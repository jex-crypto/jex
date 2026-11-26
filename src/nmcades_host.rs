// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
//! Native Messaging host for the Jex browser extension (`ru.jex.nmcades`).
//!
//! Also remains wire-compatible with CryptoPro's nmcades protocol so demos that
//! speak CAdESCOM / cadesplugin work unchanged against this host.
//!
//! Speaks stdio framing (uint32 LE length + UTF-8 JSON). Optional egui dialogs
//! (feature `nmcades-ui`) prompt for site trust and PIN.

use crate::{
    archive, cades, container, container::ClassicContainer, curves, daemon, enveloped, nmcades_ui,
    rutoken, timestamp, validation, verification, x509, xmldsig, xlong,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::{
    collections::{HashMap, HashSet},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use zeroize::Zeroize;

const PLUGIN_ROOT_ID: u32 = 0;

/// Default Rutoken CHV (user PIN). CryptoPro classic *container* password is
/// often empty and is tried separately — do not conflate the two.
const DEFAULT_PIN: &[u8] = b"12345678";

/// Reported as CAdESCOM.About.PluginVersion — must be >= CryptoPro update-server
/// channel builds (currently 2.0.15700) or demos show "есть более свежая версия".
const PLUGIN_VERSION_MAJOR: u32 = 2;
const PLUGIN_VERSION_MINOR: u32 = 0;
const PLUGIN_VERSION_BUILD: u32 = 15700;

/// Paired CSP version string (About.CSPVersion / ProviderVersion).
const CSP_VERSION_MAJOR: u32 = 5;
const CSP_VERSION_MINOR: u32 = 0;
const CSP_VERSION_BUILD: u32 = 13000;

#[derive(Debug, Clone)]
pub struct NmcadesHostOptions {
    pub config_path: PathBuf,
    /// Optional override for default TSA (else config `tsa`).
    pub tsa: Option<String>,
    /// If set, serve JSON envelopes over HTTP (Safari bridge) instead of stdio NMH.
    pub http_listen: Option<String>,
}

struct HostKey {
    id: String,
    /// Stable unique container path shown in demos (abs dir or `reader/uuid`).
    unique_container_name: String,
    /// Absolute classic-container directory when loaded from disk config.
    disk_path: Option<String>,
    cert_der: Vec<u8>,
    curve: curves::Curve,
    private_le: Vec<u8>,
    public_x_le: Vec<u8>,
    public_y_le: Vec<u8>,
    subject_name: String,
    issuer_name: String,
    serial_hex: String,
    thumbprint: String,
    not_before_unix: i64,
    not_after_unix: i64,
}

impl Drop for HostKey {
    fn drop(&mut self) {
        self.private_le.zeroize();
    }
}

/// One AuthenticatedAttributes2 entry (CADESCOM.CPAttribute snapshot).
#[derive(Debug, Clone)]
struct AttrEntry {
    name: i32,
    value: String,
    value_encoding: u32,
}

/// Certificate display fields (host key or CMS-embedded).
#[derive(Debug, Clone)]
struct CertView {
    subject_name: String,
    issuer_name: String,
    serial_hex: String,
    thumbprint: String,
    not_before_unix: i64,
    not_after_unix: i64,
    cert_der: Vec<u8>,
    /// Host key index when this is a configured container cert.
    key_index: Option<usize>,
    /// Token inventory index when this cert came from a Rutoken header.
    token_idx: Option<usize>,
}

#[derive(Debug, Clone)]
struct ReaderModeEntry {
    name: String,
    nickname: String,
    media: String,
    /// CryptoPro CARRIER_FLAG_* bitfield.
    carrier_flags: u32,
}

const READER_NAME: &str = "HDIMAGE";
const READER_NICKNAME: &str = "jex";
/// CARRIER_FLAG_REMOVABLE = 1, VIRTUAL = 128.
const CARRIER_FLAG_REMOVABLE: u32 = 1;
const CARRIER_FLAG_VIRTUAL: u32 = 128;
/// AT_SIGNATURE = 2.
const AT_SIGNATURE: u32 = 2;
const TOKEN_SCAN_TTL: Duration = Duration::from_secs(120);
const TOKEN_SCAN_DEPTH: usize = 8;
/// PC/SC can block when another CSP holds the reader — bound Store/cert listing.
const TOKEN_SCAN_TIMEOUT: Duration = Duration::from_secs(4);

const CSP_PROVIDER_NAME: &str = "Jex GOST R 34.10-2012 Cryptographic Service Provider";

fn hdimage_reader(media_path: &str) -> ReaderModeEntry {
    ReaderModeEntry {
        name: READER_NAME.into(),
        nickname: READER_NICKNAME.into(),
        media: media_path.to_string(),
        carrier_flags: CARRIER_FLAG_VIRTUAL,
    }
}

fn abs_dir_string(container_dir: &Path) -> String {
    std::fs::canonicalize(container_dir)
        .unwrap_or_else(|_| container_dir.to_path_buf())
        .display()
        .to_string()
}

fn token_unique_path(reader: &str, unique: &str) -> String {
    format!("{reader}/{unique}")
}

fn reader_nickname(pcsc_name: &str) -> String {
    pcsc_name
        .rsplit([' ', '\\', '/'])
        .find(|s| !s.is_empty())
        .unwrap_or(pcsc_name)
        .chars()
        .take(32)
        .collect()
}

fn reader_media_label(pcsc_name: &str) -> &'static str {
    let l = pcsc_name.to_ascii_lowercase();
    if l.contains("rutoken") || l.contains("aktiv") {
        "RUTOKEN"
    } else if l.contains("jacarta") || l.contains("aladdin") {
        "JACARTA"
    } else {
        "SCARD"
    }
}

/// Reference to a config HDIMAGE key or a scanned token container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContRef {
    Hdimage(usize),
    Token(usize),
}

/// Certificate from HDIMAGE key or token header (display / Find).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertRef {
    Hdimage(usize),
    Token(usize),
}

#[derive(Debug, Clone)]
struct TokenContainerEntry {
    reader_name: String,
    unique_name: String,
    fqcn: String,
    path_display: String,
    path: Vec<u16>,
    cert_der: Option<Vec<u8>>,
    view: Option<CertView>,
    public_x_prefix: Option<[u8; 8]>,
    not_after_unix: i64,
}

#[derive(Debug, Clone)]
struct TokenInventory {
    scanned_at: Instant,
    /// Physical PC/SC readers (HDIMAGE is added separately).
    readers: Vec<ReaderModeEntry>,
    containers: Vec<TokenContainerEntry>,
}

impl TokenInventory {
    fn empty() -> Self {
        Self {
            scanned_at: Instant::now()
                .checked_sub(TOKEN_SCAN_TTL * 2)
                .unwrap_or_else(Instant::now),
            readers: Vec::new(),
            containers: Vec::new(),
        }
    }

    fn is_fresh(&self) -> bool {
        self.scanned_at.elapsed() < TOKEN_SCAN_TTL
    }
}

fn scan_token_inventory() -> TokenInventory {
    let mut readers = Vec::new();
    let mut containers = Vec::new();
    let pcsc = match rutoken::list_readers() {
        Ok(r) => r,
        Err(_) => {
            return TokenInventory {
                scanned_at: Instant::now(),
                readers,
                containers,
            };
        }
    };
    for reader_name in pcsc {
        readers.push(ReaderModeEntry {
            name: reader_name.clone(),
            nickname: reader_nickname(&reader_name),
            media: reader_media_label(&reader_name).into(),
            carrier_flags: CARRIER_FLAG_REMOVABLE,
        });
        let card = match rutoken::RutokenCard::connect(Some(&reader_name)) {
            Ok(c) => c,
            Err(_) => continue, // empty slot / no card
        };
        let found = match card.discover_classic_containers(TOKEN_SCAN_DEPTH) {
            Ok(f) => f,
            Err(_) => continue,
        };
        for loc in found {
            let path_display = loc.display_path();
            let name = card
                .try_read_container_name_best_effort(&loc.path)
                .ok()
                .flatten()
                .and_then(|bytes| container::parse_name(&bytes));
            let header = card
                .try_read_container_header_best_effort(&loc.path)
                .ok()
                .flatten();
            let uuid = header
                .as_deref()
                .and_then(|h| container::resolve_uuid(name.as_deref(), h));
            let unique = uuid
                .clone()
                .or_else(|| name.clone())
                .unwrap_or_else(|| path_display.clone());
            let fqcn = token_unique_path(&reader_name, &unique);
            let mut cert_der = None;
            let mut view = None;
            let mut public_x_prefix = None;
            let mut not_after_unix = 0i64;
            if let Some(h) = header.as_deref() {
                if let Some(cert) = x509::find_certificate(h) {
                    if let Ok(v) = Host::cert_view_from_der_static(&cert) {
                        not_after_unix = v.not_after_unix;
                        if let Ok(id) = x509::identity(&cert) {
                            let mut fp = [0u8; 8];
                            if id.public_x_le.len() >= 8 {
                                fp.copy_from_slice(&id.public_x_le[..8]);
                                public_x_prefix = Some(fp);
                            }
                        }
                        view = Some(v);
                    }
                    cert_der = Some(cert);
                }
            }
            containers.push(TokenContainerEntry {
                reader_name: reader_name.clone(),
                unique_name: unique,
                fqcn,
                path_display,
                path: loc.path.clone(),
                cert_der,
                view,
                public_x_prefix,
                not_after_unix,
            });
        }
        drop(card);
    }
    TokenInventory {
        scanned_at: Instant::now(),
        readers,
        containers,
    }
}

/// Run PC/SC inventory off-thread with a deadline. On timeout returns `None`
/// so callers can keep the previous cache instead of freezing the plugin.
fn scan_token_inventory_timed() -> Option<TokenInventory> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(scan_token_inventory());
    });
    match rx.recv_timeout(TOKEN_SCAN_TIMEOUT) {
        Ok(inv) => Some(inv),
        Err(_) => {
            eprintln!(
                "jex nmcades-host: token scan timed out after {}s (PC/SC busy?)",
                TOKEN_SCAN_TIMEOUT.as_secs()
            );
            None
        }
    }
}

fn default_reader() -> ReaderModeEntry {
    hdimage_reader("HDIMAGE")
}

#[derive(Debug, Clone, Copy)]
enum EnvelopeParent {
    Cms(u32),
    Xml(u32),
}

#[derive(Debug)]
enum ObjKind {
    PluginRoot,
    About,
    /// Result of About.CSPVersion() / PluginVersion — Major/Minor/Build.
    Version {
        major: u32,
        minor: u32,
        build: u32,
    },
    Store {
        opened: bool,
        /// CAPICOM/CADESCOM store location (2=My, 100=CONTAINER_STORE, …).
        location: u32,
        /// Store name from Open(..., "My"|"AddressBook"|"ROOT"|"CA", …).
        name: String,
    },
    /// Store.CRLs collection (in-memory; empty unless Import/AddCRL).
    Crls {
        items: Vec<u32>,
    },
    /// CAdESCOM.CRL
    Crl {
        issuer_name: String,
        thumbprint: String,
        this_update: String,
        next_update: String,
        der: Vec<u8>,
    },
    Certificates {
        /// Same location filter as parent Store (ignored for now — all keys visible).
        location: u32,
        /// `None` = all visible certs; `Some` = filtered (after Find).
        indices: Option<Vec<CertRef>>,
    },
    HashedData {
        algorithm: u32,
        data_encoding: u32,
        value_hex: String,
    },
    RawSignature,
    ReaderModes {
        items: Vec<ReaderModeEntry>,
    },
    ReaderMode(ReaderModeEntry),
    /// Result of CCspInformation.EnumContainers().
    Containers {
        items: Vec<ContRef>,
    },
    /// One CryptoPro classic container (HDIMAGE config key or Rutoken).
    Container {
        source: ContRef,
        silent: bool,
    },
    ContKeys {
        source: ContRef,
    },
    ContKey {
        source: ContRef,
    },
    /// CAdESCOM.CPEnvelopedData
    CPEnvelopedData {
        algorithm: f64,
        recipient_cert_ids: Vec<u32>,
        content_b64: String,
        content_encoding: u32,
    },
    /// CAdESCOM.EnvelopedXML
    EnvelopedXml {
        content: String,
        algorithm: f64,
        recipient_cert_ids: Vec<u32>,
    },
    Recipients {
        parent: EnvelopeParent,
        cert_ids: Vec<u32>,
    },
    EnvelopeAlgorithm {
        parent: EnvelopeParent,
        name: f64,
    },
    Certificate {
        view: CertView,
    },
    /// Certificate.PrivateKey (ProviderName / UniqueContainerName).
    PrivateKey {
        key_index: usize,
        /// Short container name (folder / uuid).
        container_name: String,
        /// Absolute dir or `reader/uuid` (no Windows CSP `\\.\` prefix).
        unique_container_name: String,
    },
    /// Certificate.PublicKey() result.
    PublicKey {
        curve_bytes: usize,
    },
    /// PublicKey.Algorithm → FriendlyName / Value.
    Algorithm {
        oid: String,
        friendly: String,
    },
    /// X509Enrollment.CCspInformation stub (demo FillCertInfo try/catch).
    CspInformation {
        initialized: bool,
    },
    /// Certificate.Extensions() — empty collection (demo only checks CSP license OID).
    CertExtensions,
    /// Certificate.IsValid() → Result.
    CertStatus {
        result: bool,
    },
    /// CAdESCOM.PluginConfiguration (extension trusted-sites UI).
    PluginConfiguration,
    /// PluginConfiguration.TrustedSites — 0-based Item; Add / Remove / Save.
    TrustedSites,
    /// CADESCOM.CPAttribute (Name / Value / ValueEncoding).
    CPAttribute {
        name: i32,
        value: String,
        value_encoding: u32,
    },
    /// CPSigner.AuthenticatedAttributes2 collection.
    Attrs2 {
        signer_id: u32,
    },
    Signer {
        key_index: Option<usize>,
        /// Pending Rutoken inventory index until KeyPin unlock.
        token_idx: Option<usize>,
        key_pin: Option<String>,
        tsa: Option<String>,
        check_certificate: bool,
        options: u32,
        attrs: Vec<AttrEntry>,
    },
    SignedXml {
        content: String,
        digest_method: String,
        signature_method: String,
        signature_type: u32,
        signer_obj: Option<u32>,
    },
    CadesSignedData {
        content_b64: String,
        /// CADESCOM_STRING_TO_UCS2LE (0) or CADESCOM_BASE64_TO_BINARY (1).
        content_encoding: u32,
        /// Last SignCades/VerifyCades bDetached (CryptoPro default: attached = false).
        detached: bool,
        /// Last CMS from SignCades / VerifyCades (for EnhanceCades).
        last_signature: Option<Vec<u8>>,
        /// Populated by VerifyCades for Signers / Certificates.
        verified: Option<CadesVerifyState>,
    },
    /// CadesSignedData.Signers collection.
    Signers {
        parent: u32,
    },
    /// One SignerInfo after VerifyCades.
    VerifySigner {
        cert: CertView,
        signature_ok: bool,
        signing_time_utc: String,
    },
    /// Signer.SignatureStatus after VerifyCades.
    SignatureStatus {
        is_valid: bool,
    },
    /// CadesSignedData.Certificates (embedded chain).
    SignedDataCerts {
        parent: u32,
    },
}

#[derive(Debug, Clone)]
struct CadesVerifyState {
    signature_ok: bool,
    signing_time_utc: String,
    signer_cert: CertView,
    all_certs: Vec<CertView>,
}

struct Host {
    keys: Vec<HostKey>,
    default_tsa: Option<String>,
    tsa_timeout_secs: u64,
    tsa_policy: Option<String>,
    next_id: AtomicU32,
    objects: HashMap<u32, ObjKind>,
    /// Cached PC/SC readers + Rutoken classic containers (PIN-free header scan).
    token_inventory: TokenInventory,
    /// CAdESCOM.PluginConfiguration.TrustedSites (extension popup editor).
    trusted_sites: Vec<String>,
    /// Origins allowed for this host process only (egui "Разрешить сейчас").
    session_allowed_sites: HashSet<String>,
    /// Optional PC/SC token PIN (daemon `token_pin` / `token_pin_file`).
    token_pin: Option<Vec<u8>>,
}

impl Host {
    fn from_config(opts: &NmcadesHostOptions) -> Result<Self> {
        let cfg = daemon::load_config(&opts.config_path)?;
        let base = opts
            .config_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let mut keys = Vec::new();
        for k in &cfg.keys {
            let container_dir = resolve_path(base, &k.container_dir);
            let c = ClassicContainer::open(&container_dir)
                .with_context(|| format!("open container {:?} at {}", k.id, container_dir.display()))?;
            let cert = c
                .certificate
                .as_ref()
                .with_context(|| format!("key {:?}: no certificate in header.key", k.id))?
                .clone();
            let identity = x509::identity(&cert)?;
            let validity = x509::validity(&cert)?;
            let subject_attrs = x509::subject_name_attributes(&cert).unwrap_or_default();
            let issuer_attrs = x509::issuer_name_attributes(&cert).unwrap_or_default();
            let mut pin = if let Some(p) = &k.pin {
                p.as_bytes().to_vec()
            } else {
                let path = resolve_path(
                    base,
                    k.pin_file.as_ref().context("pin or pin_file required")?,
                );
                let mut data = std::fs::read(&path)
                    .with_context(|| format!("read pin file {}", path.display()))?;
                while data.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                    data.pop();
                }
                data
            };
            let unlocked = c.unlock(&pin);
            pin.zeroize();
            let mut unlocked = unlocked?;
            let mut hasher = Sha1::new();
            hasher.update(&cert);
            let thumbprint = hex::encode_upper(hasher.finalize());
            let serial_tlv = crate::der::parse_tlv(&identity.serial_der)?;
            let serial_hex = hex::encode_upper(serial_tlv.value);
            let disk_path = abs_dir_string(&container_dir);
            keys.push(HostKey {
                id: k.id.clone(),
                unique_container_name: disk_path.clone(),
                disk_path: Some(disk_path),
                cert_der: cert,
                curve: c.curve.clone(),
                private_le: std::mem::take(&mut unlocked.private_le),
                public_x_le: unlocked.public_x_le.clone(),
                public_y_le: unlocked.public_y_le.clone(),
                subject_name: format_dn_capicom(&subject_attrs),
                issuer_name: format_dn_capicom(&issuer_attrs),
                serial_hex,
                thumbprint,
                not_before_unix: validity.not_before_unix,
                not_after_unix: validity.not_after_unix,
            });
            unlocked.private_le.zeroize();
        }
        if keys.is_empty() {
            bail!("nmcades-host config has no keys");
        }
        let mut objects = HashMap::new();
        objects.insert(PLUGIN_ROOT_ID, ObjKind::PluginRoot);
        Ok(Self {
            keys,
            default_tsa: opts.tsa.clone().or(cfg.tsa),
            tsa_timeout_secs: cfg.tsa_timeout_secs.max(1),
            tsa_policy: cfg.tsa_policy,
            next_id: AtomicU32::new(1),
            objects,
            token_inventory: TokenInventory::empty(),
            trusted_sites: load_trusted_sites(),
            session_allowed_sites: HashSet::new(),
            token_pin: load_optional_pin(cfg.token_pin.as_deref(), cfg.token_pin_file.as_ref(), base),
        })
    }

    fn refresh_token_inventory(&mut self, force: bool) {
        if force || !self.token_inventory.is_fresh() {
            match scan_token_inventory_timed() {
                Some(inv) => self.token_inventory = inv,
                None if !self.token_inventory.containers.is_empty() || !force => {
                    // Keep last good scan; bump timestamp so we do not immediately retry.
                    self.token_inventory.scanned_at = Instant::now();
                }
                None => {
                    self.token_inventory = TokenInventory {
                        scanned_at: Instant::now(),
                        readers: Vec::new(),
                        containers: Vec::new(),
                    };
                }
            }
        }
    }

    fn all_reader_modes(&mut self) -> Vec<ReaderModeEntry> {
        self.refresh_token_inventory(false);
        let mut out = Vec::new();
        // One virtual HDIMAGE reader per distinct disk container path.
        let mut seen_paths = std::collections::BTreeSet::new();
        for k in &self.keys {
            if let Some(ref path) = k.disk_path {
                if seen_paths.insert(path.clone()) {
                    out.push(hdimage_reader(path));
                }
            }
        }
        out.extend(self.token_inventory.readers.clone());
        // Always expose a placeholder HDIMAGE carrier when nothing else is visible.
        if out.is_empty() {
            out.push(hdimage_reader("HDIMAGE"));
        }
        out
    }

    fn all_container_refs(&mut self) -> Vec<ContRef> {
        self.refresh_token_inventory(false);
        let mut out: Vec<ContRef> = (0..self.keys.len()).map(ContRef::Hdimage).collect();
        out.extend(
            (0..self.token_inventory.containers.len()).map(ContRef::Token),
        );
        out
    }

    fn all_cert_refs(&mut self) -> Vec<CertRef> {
        self.refresh_token_inventory(false);
        let mut out: Vec<CertRef> = (0..self.keys.len()).map(CertRef::Hdimage).collect();
        for (i, c) in self.token_inventory.containers.iter().enumerate() {
            if c.view.is_some() {
                out.push(CertRef::Token(i));
            }
        }
        out
    }

    fn cert_view_for_ref(&self, r: CertRef) -> Result<CertView> {
        match r {
            CertRef::Hdimage(i) => Ok(self.cert_view_from_host(i)),
            CertRef::Token(i) => {
                let mut v = self
                    .token_inventory
                    .containers
                    .get(i)
                    .and_then(|c| c.view.clone())
                    .context("token container has no certificate")?;
                v.token_idx = Some(i);
                // If already unlocked into keys (matched by thumbprint), attach key_index.
                if let Some(ki) = self
                    .keys
                    .iter()
                    .position(|k| k.thumbprint == v.thumbprint)
                {
                    v.key_index = Some(ki);
                }
                Ok(v)
            }
        }
    }

    fn alloc(&mut self, kind: ObjKind) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.objects.insert(id, kind);
        id
    }

    fn cert_view_from_host(&self, idx: usize) -> CertView {
        let k = &self.keys[idx];
        CertView {
            subject_name: k.subject_name.clone(),
            issuer_name: k.issuer_name.clone(),
            serial_hex: k.serial_hex.clone(),
            thumbprint: k.thumbprint.clone(),
            not_before_unix: k.not_before_unix,
            not_after_unix: k.not_after_unix,
            cert_der: k.cert_der.clone(),
            key_index: Some(idx),
            token_idx: None,
        }
    }

    fn cert_view_from_der(cert_der: &[u8]) -> Result<CertView> {
        Self::cert_view_from_der_static(cert_der)
    }

    fn cert_view_from_der_static(cert_der: &[u8]) -> Result<CertView> {
        // Display fields only — RSA/root CA certs (webtools "basic certificates")
        // must Import without requiring a GOST curve in SPKI.
        let names = x509::names(cert_der)?;
        let validity = x509::validity(cert_der)?;
        let subject_attrs = x509::subject_name_attributes(cert_der).unwrap_or_default();
        let issuer_attrs = x509::issuer_name_attributes(cert_der).unwrap_or_default();
        let mut hasher = Sha1::new();
        hasher.update(cert_der);
        let thumbprint = hex::encode_upper(hasher.finalize());
        let serial_tlv = crate::der::parse_tlv(&names.serial_der)?;
        let serial_hex = hex::encode_upper(serial_tlv.value);
        Ok(CertView {
            subject_name: format_dn_capicom(&subject_attrs),
            issuer_name: format_dn_capicom(&issuer_attrs),
            serial_hex,
            thumbprint,
            not_before_unix: validity.not_before_unix,
            not_after_unix: validity.not_after_unix,
            cert_der: cert_der.to_vec(),
            key_index: None,
            token_idx: None,
        })
    }

    fn curve_bytes_for_cert(view: &CertView) -> usize {
        x509::identity(&view.cert_der)
            .ok()
            .and_then(|id| curves::by_oid(&id.curve_oid))
            .map(|c| c.bytes)
            .unwrap_or(32)
    }

    fn cert_collection_refs(&self, indices: Option<&Vec<CertRef>>) -> Vec<CertRef> {
        indices.cloned().unwrap_or_else(|| {
            let mut out: Vec<CertRef> = Vec::new();
            let mut seen = std::collections::HashSet::<String>::new();
            for i in 0..self.keys.len() {
                let tp = self.keys[i].thumbprint.to_ascii_uppercase();
                if seen.insert(tp) {
                    out.push(CertRef::Hdimage(i));
                }
            }
            for (i, c) in self.token_inventory.containers.iter().enumerate() {
                let Some(view) = c.view.as_ref() else {
                    continue;
                };
                let tp = view.thumbprint.to_ascii_uppercase();
                if seen.insert(tp) {
                    out.push(CertRef::Token(i));
                }
            }
            out
        })
    }

    fn certificate_object(&mut self, view: &CertView) -> Value {
        let id = self.alloc(ObjKind::Certificate {
            view: view.clone(),
        });
        object_retval(
            id,
            &[
                "SubjectName",
                "IssuerName",
                "Thumbprint",
                "SerialNumber",
                "ValidFromDate",
                "ValidToDate",
                "PrivateKey",
                "Archived",
            ],
            &[
                "Import",
                "Export",
                "FindPrivateKey",
                "HasPrivateKey",
                "PublicKey",
                "IsValid",
                "Extensions",
            ],
        )
    }

    fn container_object(&self, id: u32) -> Value {
        object_retval(
            id,
            &[
                "Name",
                "UniqueName",
                "Media",
                "Reader",
                "FQCN",
                "Keys",
                "Silent",
            ],
            &[],
        )
    }

    fn certificate_import(&mut self, objid: u32, params: &Value) -> Result<Value> {
        let data = param_string(params, 0).context("Certificate.Import")?;
        let der = decode_cert_import(&data)?;
        let view = Self::cert_view_from_der(&der)?;
        if let Some(ObjKind::Certificate { view: slot }) = self.objects.get_mut(&objid) {
            *slot = view;
        }
        Ok(json!({"type": "OK"}))
    }

    fn crl_import(&mut self, objid: u32, params: &Value) -> Result<Value> {
        let data = param_string(params, 0).context("CRL.Import")?;
        let der = decode_cert_import(&data).or_else(|_| {
            STANDARD
                .decode(data.replace(['\n', '\r', ' '], "").as_bytes())
                .context("CRL base64")
        })?;
        let mut hasher = Sha1::new();
        hasher.update(&der);
        let thumbprint = hex::encode_upper(hasher.finalize());
        let issuer_name = x509::crl_issuer_der(&der)
            .ok()
            .map(|d| format!("DER-issuer-{}bytes", d.len()))
            .unwrap_or_else(|| "CN=Unknown CRL".into());
        if let Some(ObjKind::Crl {
            issuer_name: slot_iss,
            thumbprint: slot_tp,
            this_update,
            next_update,
            der: slot_der,
        }) = self.objects.get_mut(&objid)
        {
            *slot_iss = issuer_name;
            *slot_tp = thumbprint;
            *this_update = unix_to_cades_utc(0);
            *next_update = unix_to_cades_utc(0);
            *slot_der = der;
        }
        Ok(json!({"type": "OK"}))
    }

    fn enveloped_cms_encrypt(&mut self, objid: u32, params: &Value) -> Result<Value> {
        let (recipients, encoding, inline) = match self.objects.get(&objid) {
            Some(ObjKind::CPEnvelopedData {
                recipient_cert_ids,
                content_encoding,
                content_b64,
                ..
            }) => (
                recipient_cert_ids.clone(),
                *content_encoding,
                content_b64.clone(),
            ),
            _ => bail!("not CPEnvelopedData"),
        };
        // webtools: StreamEncrypt(btoaUnicode(text), true) — 2nd arg / BASE64_TO_BINARY
        // means the content string is base64 of the bytes to encrypt.
        let stream = param_string(params, 0);
        let force_b64 = param_bool(params, 1).unwrap_or(false) || encoding == 1;
        let raw = if let Some(s) = stream {
            if force_b64 {
                decode_enveloped_content(1, &s)?
            } else {
                decode_enveloped_content(encoding, &s)?
            }
        } else if !inline.is_empty() {
            decode_enveloped_content(if encoding == 0 && force_b64 { 1 } else { encoding }, &inline)?
        } else {
            bail!("CPEnvelopedData.Content is empty");
        };
        let mut recip_keys = Vec::new();
        for cid in recipients {
            let view = self.cert_view_from_object(cid)?;
            recip_keys.push(enveloped::RecipientKey {
                cert_der: view.cert_der,
            });
        }
        let alg_n = match self.objects.get(&objid) {
            Some(ObjKind::CPEnvelopedData { algorithm, .. }) => *algorithm as u32,
            _ => 25,
        };
        let alg = enveloped::ContentAlg::from_cadescom(alg_n)?;
        let cms = enveloped::encrypt_with(&raw, &recip_keys, alg)?;
        Ok(json!({"type": "string", "value": STANDARD.encode(&cms)}))
    }

    fn enveloped_cms_decrypt(&mut self, _objid: u32, params: &Value) -> Result<Value> {
        let msg = param_string(params, 0).context("Decrypt needs CMS")?;
        let cms = STANDARD
            .decode(msg.replace(['\n', '\r', ' '], "").as_bytes())
            .or_else(|_| {
                // Already binary-ish base64 failure → try raw if looks like DER
                if msg.as_bytes().first() == Some(&0x30) {
                    Ok(msg.into_bytes())
                } else {
                    Err(anyhow::anyhow!("CMS base64"))
                }
            })
            .context("CMS base64")?;
        // Try each host key until one unwraps.
        let mut last = anyhow::anyhow!("no host key could decrypt");
        for k in &self.keys {
            let dk = enveloped::DecryptKey {
                private_le: k.private_le.clone(),
                curve: k.curve.clone(),
                cert_der: k.cert_der.clone(),
            };
            match enveloped::decrypt(&cms, &dk) {
                Ok(pt) => {
                    return Ok(json!({
                        "type": "string",
                        "value": STANDARD.encode(&pt)
                    }));
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn enveloped_xml_encrypt(&mut self, objid: u32) -> Result<Value> {
        let (content, recipients) = match self.objects.get(&objid) {
            Some(ObjKind::EnvelopedXml {
                content,
                recipient_cert_ids,
                ..
            }) => (content.clone(), recipient_cert_ids.clone()),
            _ => bail!("not EnvelopedXML"),
        };
        let mut recip_keys = Vec::new();
        for cid in recipients {
            let view = self.cert_view_from_object(cid)?;
            recip_keys.push(enveloped::RecipientKey {
                cert_der: view.cert_der,
            });
        }
        let alg_n = match self.objects.get(&objid) {
            Some(ObjKind::EnvelopedXml { algorithm, .. }) => *algorithm as u32,
            _ => 25,
        };
        let alg = enveloped::ContentAlg::from_cadescom(alg_n)?;
        let cms = enveloped::encrypt_with(content.as_bytes(), &recip_keys, alg)?;
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <EncryptedData xmlns=\"urn:ietf:params:xml:ns:jex-enveloped\">\n\
             <CipherValue>{}</CipherValue>\n\
             </EncryptedData>\n",
            STANDARD.encode(&cms)
        );
        Ok(json!({"type": "string", "value": xml}))
    }

    fn enveloped_xml_decrypt(&mut self, objid: u32, params: &Value) -> Result<Value> {
        let msg = param_string(params, 0).context("EnvelopedXML.Decrypt")?;
        let b64 = extract_xml_cipher_value(&msg).unwrap_or(msg);
        let cms = STANDARD
            .decode(b64.replace(['\n', '\r', ' '], "").as_bytes())
            .context("CipherValue base64")?;
        let mut last = anyhow::anyhow!("no host key could decrypt");
        for k in &self.keys {
            let dk = enveloped::DecryptKey {
                private_le: k.private_le.clone(),
                curve: k.curve.clone(),
                cert_der: k.cert_der.clone(),
            };
            match enveloped::decrypt(&cms, &dk) {
                Ok(pt) => {
                    let text = String::from_utf8_lossy(&pt).into_owned();
                    if let Some(ObjKind::EnvelopedXml { content, .. }) =
                        self.objects.get_mut(&objid)
                    {
                        *content = text.clone();
                    }
                    return Ok(json!({"type": "OK"}));
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn hashed_data_hash(&mut self, objid: u32, params: &Value) -> Result<Value> {
        let data = param_string(params, 0).context("HashedData.Hash")?;
        let (algorithm, data_encoding) = match self.objects.get(&objid) {
            Some(ObjKind::HashedData {
                algorithm,
                data_encoding,
                ..
            }) => (*algorithm, *data_encoding),
            _ => bail!("not HashedData"),
        };
        let digest = nmcades_hash(algorithm, data_encoding, &data)?;
        let hex = hex::encode(&digest).to_ascii_uppercase();
        if let Some(ObjKind::HashedData { value_hex, .. }) = self.objects.get_mut(&objid) {
            *value_hex = hex.clone();
        }
        Ok(json!({"type": "string", "value": hex}))
    }

    fn raw_signature_sign_hash(&self, params: &Value) -> Result<Value> {
        let hash_hex = self.hash_from_hashed_data_param(params, 0)?;
        let cert_id = param_object_id(params, 1).context("SignHash needs certificate")?;
        let (key_index, curve) = self.resolve_signing_cert(cert_id)?;
        let digest = decode_hash_hex(&hash_hex)?;
        let key = &self.keys[key_index];
        let sig = cades::raw_sign_digest(&curve, &key.private_le, &digest)?;
        Ok(json!({"type": "string", "value": STANDARD.encode(&sig)}))
    }

    fn raw_signature_verify_hash(&self, params: &Value) -> Result<Value> {
        let hash_hex = self.hash_from_hashed_data_param(params, 0)?;
        let cert_id = param_object_id(params, 1).context("VerifyHash needs certificate")?;
        let sig_b64 = param_string(params, 2).context("VerifyHash needs signature")?;
        let view = self.cert_view_from_object(cert_id)?;
        let digest = decode_hash_hex(&hash_hex)?;
        let sig = STANDARD.decode(sig_b64.as_bytes()).context("signature base64")?;
        let identity = x509::identity(&view.cert_der)?;
        let curve = curves::by_oid(&identity.curve_oid).context("certificate curve")?;
        let ok = cades::raw_verify_digest(
            &curve,
            &identity.public_x_le,
            &identity.public_y_le,
            &digest,
            &sig,
        )?;
        if !ok {
            bail!("raw signature verification failed");
        }
        Ok(json!({"type": "OK"}))
    }

    fn hash_from_hashed_data_param(&self, params: &Value, idx: usize) -> Result<String> {
        let obj_id = param_object_id(params, idx).context("HashedData object")?;
        match self.objects.get(&obj_id) {
            Some(ObjKind::HashedData { value_hex, .. }) if !value_hex.is_empty() => {
                Ok(value_hex.clone())
            }
            _ => {
                let hex = param_string(params, idx).context("hash value")?;
                Ok(hex.replace([' ', '\t'], "").to_ascii_uppercase())
            }
        }
    }

    fn resolve_signing_cert(&self, cert_id: u32) -> Result<(usize, curves::Curve)> {
        let view = self.cert_view_from_object(cert_id)?;
        let key_index = view
            .key_index
            .or_else(|| {
                self.keys
                    .iter()
                    .position(|k| k.thumbprint.eq_ignore_ascii_case(&view.thumbprint))
            })
            .context("certificate has no private key in jex config")?;
        Ok((key_index, self.keys[key_index].curve.clone()))
    }

    /// Unlock a Rutoken classic container into `self.keys` and point the signer at it.
    fn ensure_signer_unlocked(&mut self, signer_id: u32) -> Result<()> {
        let (key_index, token_idx, key_pin) = match self.objects.get(&signer_id) {
            Some(ObjKind::Signer {
                key_index,
                token_idx,
                key_pin,
                ..
            }) => (*key_index, *token_idx, key_pin.clone()),
            _ => bail!("not CPSigner"),
        };
        if key_index.is_some() {
            return Ok(());
        }
        let token_idx = token_idx.context("CPSigner has neither HDIMAGE key nor Rutoken cert")?;
        // KeyPin is the CryptoPro *container* password (often empty). Token CHV
        // is separate (config token_pin / egui / DEFAULT_PIN) and used only for EF read.
        let mut candidates = container_pin_candidates(key_pin.as_deref(), self.token_pin.as_deref());
        if nmcades_ui::ui_enabled() && key_pin.is_none() {
            if let Some(pin) = nmcades_ui::prompt_pin(
                "Jex — пароль контейнера",
                "Пароль контейнера CryptoPro (часто пустой на Rutoken). Отмена — прервать подпись.",
            ) {
                candidates.insert(0, pin.into_bytes());
            } else {
                bail!("container PIN prompt cancelled");
            }
        }
        let ki = self.unlock_token_into_keys(token_idx, &candidates)?;
        if let Some(ObjKind::Signer {
            key_index,
            token_idx: t,
            ..
        }) = self.objects.get_mut(&signer_id)
        {
            *key_index = Some(ki);
            *t = None;
        }
        Ok(())
    }

    fn unlock_token_into_keys(
        &mut self,
        token_idx: usize,
        container_pin_candidates: &[Vec<u8>],
    ) -> Result<usize> {
        let entry = self
            .token_inventory
            .containers
            .get(token_idx)
            .cloned()
            .context("token container index out of range")?;
        // Already unlocked?
        if let Some(ref view) = entry.view {
            if let Some(i) = self
                .keys
                .iter()
                .position(|k| k.thumbprint == view.thumbprint)
            {
                return Ok(i);
            }
        }
        let card = rutoken::RutokenCard::connect(Some(&entry.reader_name))
            .with_context(|| format!("connect reader {}", entry.reader_name))?;
        let chv_pin = if let Some(ref p) = self.token_pin {
            p.clone()
        } else if nmcades_ui::ui_enabled() {
            nmcades_ui::prompt_pin(
                "Jex — PIN токена",
                "PIN карты (CHV), обычно 12345678. Нужен для чтения защищённых EF.",
            )
            .map(|s| s.into_bytes())
            .unwrap_or_else(|| DEFAULT_PIN.to_vec())
        } else {
            DEFAULT_PIN.to_vec()
        };
        let files = card
            .read_classic_container(&entry.path, Some(chv_pin.as_slice()))
            .with_context(|| format!("read token container {}", entry.path_display))?;
        drop(card);
        let c = ClassicContainer::from_files(files)
            .with_context(|| format!("parse token container {}", entry.fqcn))?;
        let cert = c
            .certificate
            .clone()
            .context("token container has no certificate")?;
        let mut last_err = anyhow::anyhow!("no container PIN candidates");
        let mut unlocked = None;
        for pin in container_pin_candidates {
            match c.unlock(pin) {
                Ok(u) => {
                    unlocked = Some(u);
                    break;
                }
                Err(e) => last_err = e,
            }
        }
        let mut unlocked = unlocked.ok_or_else(|| {
            anyhow::anyhow!(
                "unlock token container {}: {last_err}",
                entry.path_display
            )
        })?;
        let identity = x509::identity(&cert)?;
        let validity = x509::validity(&cert)?;
        let subject_attrs = x509::subject_name_attributes(&cert).unwrap_or_default();
        let issuer_attrs = x509::issuer_name_attributes(&cert).unwrap_or_default();
        let mut hasher = Sha1::new();
        hasher.update(&cert);
        let thumbprint = hex::encode_upper(hasher.finalize());
        let serial_tlv = crate::der::parse_tlv(&identity.serial_der)?;
        let serial_hex = hex::encode_upper(serial_tlv.value);
        let id = entry.unique_name.clone();
        let unique_container_name = entry.fqcn.clone();
        self.keys.push(HostKey {
            id,
            unique_container_name,
            disk_path: None,
            cert_der: cert,
            curve: c.curve.clone(),
            private_le: std::mem::take(&mut unlocked.private_le),
            public_x_le: unlocked.public_x_le.clone(),
            public_y_le: unlocked.public_y_le.clone(),
            subject_name: format_dn_capicom(&subject_attrs),
            issuer_name: format_dn_capicom(&issuer_attrs),
            serial_hex,
            thumbprint,
            not_before_unix: validity.not_before_unix,
            not_after_unix: validity.not_after_unix,
        });
        unlocked.private_le.zeroize();
        Ok(self.keys.len() - 1)
    }

    fn cert_view_from_object(&self, cert_id: u32) -> Result<CertView> {
        match self.objects.get(&cert_id) {
            Some(ObjKind::Certificate { view }) if !view.cert_der.is_empty() => Ok(view.clone()),
            _ => bail!("certificate object not initialized"),
        }
    }

    fn handle_data(&mut self, data: &Value) -> Value {
        let requestid = data.get("requestid").cloned().unwrap_or(Value::Null);
        if data.get("type").and_then(|v| v.as_str()) == Some("init") {
            if let Err(e) = self.ensure_site_allowed(data) {
                return json!({
                    "type": "error",
                    "requestid": requestid,
                    "message": format!("{e:#}"),
                });
            }
            return json!({
                "type": "result",
                "requestid": requestid,
                "value": PLUGIN_ROOT_ID,
            });
        }
        if data.get("type").and_then(|v| v.as_str()) == Some("reset") {
            self.objects.retain(|&id, _| id == PLUGIN_ROOT_ID);
            self.next_id.store(1, Ordering::Relaxed);
            return json!({ "type": "result", "requestid": requestid, "value": 0 });
        }
        match self.handle_object_call(data, &requestid) {
            Ok(v) => v,
            Err(e) => json!({
                "type": "error",
                "requestid": requestid,
                "message": format!("{e:#}"),
            }),
        }
    }

    fn ensure_site_allowed(&mut self, data: &Value) -> Result<()> {
        let url = data
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if url.is_empty() {
            return Ok(());
        }
        let origin = origin_from_url(url);
        if origin.is_empty() {
            return Ok(());
        }
        if self
            .trusted_sites
            .iter()
            .any(|s| origins_match(s, &origin))
            || self.session_allowed_sites.contains(&origin)
        {
            return Ok(());
        }
        match nmcades_ui::prompt_trust_site(&origin) {
            nmcades_ui::TrustDecision::Always => {
                if !self.trusted_sites.iter().any(|s| s == &origin) {
                    self.trusted_sites.push(origin.clone());
                    let _ = save_trusted_sites(&self.trusted_sites);
                }
                self.session_allowed_sites.insert(origin);
                Ok(())
            }
            nmcades_ui::TrustDecision::Once => {
                self.session_allowed_sites.insert(origin);
                Ok(())
            }
            nmcades_ui::TrustDecision::Deny => {
                bail!("site not trusted: {origin}")
            }
        }
    }

    fn handle_object_call(&mut self, data: &Value, requestid: &Value) -> Result<Value> {
        let objid = data
            .get("objid")
            .and_then(|v| v.as_u64())
            .context("missing objid")? as u32;

        if let Some(method) = data.get("method").and_then(|v| v.as_str()) {
            let params = data.get("params").cloned().unwrap_or_else(|| json!([]));
            let retval = self.call_method(objid, method, &params)?;
            return Ok(json!({
                "type": "result",
                "requestid": requestid,
                "retval": retval,
            }));
        }
        if let Some(prop) = data.get("get_property").and_then(|v| v.as_str()) {
            let retval = self.get_property(objid, prop)?;
            return Ok(json!({
                "type": "result",
                "requestid": requestid,
                "retval": retval,
            }));
        }
        if let Some(prop) = data.get("set_property").and_then(|v| v.as_str()) {
            let params = data.get("params").cloned().unwrap_or_else(|| json!([]));
            let retval = self.set_property(objid, prop, &params)?;
            return Ok(json!({
                "type": "result",
                "requestid": requestid,
                "retval": retval,
            }));
        }
        bail!("unsupported message shape: {data}");
    }

    fn call_method(&mut self, objid: u32, method: &str, params: &Value) -> Result<Value> {
        // CreateObject on plugin root — special-case before borrow of objects.
        if matches!(self.objects.get(&objid), Some(ObjKind::PluginRoot)) && method == "CreateObject"
        {
            let name = param_string(params, 0).context("CreateObject needs ProgID")?;
            return self.create_object(&name);
        }

        if method == "Add" {
            if let Some(ObjKind::Recipients { parent, .. }) = self.objects.get(&objid) {
                let cert_id = param_object_id(params, 0).context("Recipients.Add(cert)")?;
                let parent = *parent;
                if let Some(ObjKind::Recipients { cert_ids, .. }) = self.objects.get_mut(&objid) {
                    cert_ids.push(cert_id);
                }
                match parent {
                    EnvelopeParent::Cms(pid) => {
                        if let Some(ObjKind::CPEnvelopedData {
                            recipient_cert_ids,
                            ..
                        }) = self.objects.get_mut(&pid)
                        {
                            recipient_cert_ids.push(cert_id);
                        }
                    }
                    EnvelopeParent::Xml(pid) => {
                        if let Some(ObjKind::EnvelopedXml {
                            recipient_cert_ids,
                            ..
                        }) = self.objects.get_mut(&pid)
                        {
                            recipient_cert_ids.push(cert_id);
                        }
                    }
                }
                return Ok(json!({"type": "OK"}));
            }
        }

        match self.objects.get(&objid).context("unknown objid")? {
            ObjKind::Certificates { indices, .. } => {
                if method == "Item" {
                    let idx = param_u32(params, 0).context("Certificates.Item index")? as usize;
                    let refs = self.cert_collection_refs(indices.as_ref());
                    if idx == 0 || idx > refs.len() {
                        bail!("certificate index out of range");
                    }
                    let view = self.cert_view_for_ref(refs[idx - 1])?;
                    return Ok(self.certificate_object(&view));
                }
                if method == "Find" {
                    let find_type = param_u32(params, 0).unwrap_or(0);
                    let search = param_string(params, 1).unwrap_or_default();
                    let search = search.replace([' ', '\t'], "");
                    let all = self.cert_collection_refs(indices.as_ref());
                    let filtered: Vec<CertRef> = if find_type == 0 && !search.is_empty() {
                        all.into_iter()
                            .filter(|&r| {
                                self.cert_view_for_ref(r)
                                    .map(|v| v.thumbprint.eq_ignore_ascii_case(&search))
                                    .unwrap_or(false)
                            })
                            .collect()
                    } else {
                        all
                    };
                    let loc = match self.objects.get(&objid) {
                        Some(ObjKind::Certificates { location, .. }) => *location,
                        _ => 2,
                    };
                    let id = self.alloc(ObjKind::Certificates {
                        location: loc,
                        indices: Some(filtered),
                    });
                    return Ok(object_retval(id, &["Count"], &["Item", "Find"]));
                }
            }
            ObjKind::SignedXml { .. } => {
                if method == "Sign" {
                    return self.signed_xml_sign(objid, params);
                }
                if method == "Verify" {
                    return self.signed_xml_verify(params);
                }
            }
            ObjKind::CadesSignedData { .. } => {
                if method == "SignCades" || method == "Sign" {
                    return self.cades_sign(objid, params);
                }
                if method == "VerifyCades" || method == "Verify" {
                    return self.cades_verify(objid, params);
                }
                if method == "AdditionalStore" {
                    // verify.html attaches AddressBook; ignore for local crypto checks.
                    return Ok(json!({"type": "OK"}));
                }
                if method == "GetMsgType" {
                    return self.cades_get_msg_type(params);
                }
                if method == "EnhanceCades" {
                    return self.cades_enhance(objid, params);
                }
            }
            ObjKind::Signers { parent } => {
                let parent = *parent;
                if method == "Item" {
                    let idx = param_u32(params, 0).context("Signers.Item")? as usize;
                    let state = match self.objects.get(&parent) {
                        Some(ObjKind::CadesSignedData {
                            verified: Some(v), ..
                        }) => v.clone(),
                        _ => bail!("Signers empty — call VerifyCades first"),
                    };
                    if idx != 1 {
                        bail!("signer index out of range");
                    }
                    let id = self.alloc(ObjKind::VerifySigner {
                        cert: state.signer_cert,
                        signature_ok: state.signature_ok,
                        signing_time_utc: state.signing_time_utc,
                    });
                    return Ok(object_retval(
                        id,
                        &["Certificate", "SignatureStatus", "SigningTime"],
                        &[],
                    ));
                }
            }
            ObjKind::SignedDataCerts { parent } => {
                let parent = *parent;
                if method == "Item" {
                    let idx = param_u32(params, 0).context("Certificates.Item")? as usize;
                    let certs = match self.objects.get(&parent) {
                        Some(ObjKind::CadesSignedData {
                            verified: Some(v), ..
                        }) => v.all_certs.clone(),
                        _ => bail!("no certificates — call VerifyCades first"),
                    };
                    if idx == 0 || idx > certs.len() {
                        bail!("certificate index out of range");
                    }
                    return Ok(self.certificate_object(&certs[idx - 1]));
                }
            }
            ObjKind::HashedData { .. } => {
                if method == "Hash" {
                    return self.hashed_data_hash(objid, params);
                }
                if method == "SetHashValue" {
                    let hex = param_string(params, 0).context("SetHashValue")?;
                    if let Some(ObjKind::HashedData { value_hex, .. }) =
                        self.objects.get_mut(&objid)
                    {
                        *value_hex = hex.replace([' ', '\t'], "").to_ascii_uppercase();
                    }
                    return Ok(json!({"type": "OK"}));
                }
            }
            ObjKind::RawSignature => {
                if method == "SignHash" {
                    return self.raw_signature_sign_hash(params);
                }
                if method == "VerifyHash" {
                    return self.raw_signature_verify_hash(params);
                }
            }
            ObjKind::CPEnvelopedData { .. } => {
                if method == "StreamEncrypt" || method == "Encrypt" {
                    return self.enveloped_cms_encrypt(objid, params);
                }
                if method == "StreamDecrypt" || method == "Decrypt" {
                    return self.enveloped_cms_decrypt(objid, params);
                }
            }
            ObjKind::EnvelopedXml { .. } => {
                if method == "Encrypt" {
                    return self.enveloped_xml_encrypt(objid);
                }
                if method == "Decrypt" {
                    return self.enveloped_xml_decrypt(objid, params);
                }
            }
            ObjKind::Crl { .. } => {
                if method == "Import" {
                    return self.crl_import(objid, params);
                }
                if method == "Export" {
                    if let Some(ObjKind::Crl { der, .. }) = self.objects.get(&objid) {
                        return Ok(json!({"type": "string", "value": STANDARD.encode(der)}));
                    }
                }
            }
            ObjKind::Crls { items } => {
                if method == "Item" {
                    let idx = param_u32(params, 0).context("CRLs.Item")? as usize;
                    if idx == 0 || idx > items.len() {
                        bail!("CRL index out of range");
                    }
                    let id = items[idx - 1];
                    return Ok(object_retval(
                        id,
                        &[
                            "IssuerName",
                            "Thumbprint",
                            "ThisUpdate",
                            "NextUpdate",
                            "CRLNextPublish",
                        ],
                        &["Export"],
                    ));
                }
            }
            ObjKind::ReaderModes { .. } => {
                if method == "ItemByIndex" {
                    let idx = param_u32(params, 0).context("ItemByIndex")? as usize;
                    let entry = match self.objects.get(&objid) {
                        Some(ObjKind::ReaderModes { items }) => items.get(idx).cloned(),
                        _ => None,
                    }
                    .context("reader index out of range")?;
                    let id = self.alloc(ObjKind::ReaderMode(entry));
                    return Ok(object_retval(
                        id,
                        &["Name", "NickName", "Media", "CarrierFlags"],
                        &[],
                    ));
                }
            }
            ObjKind::Store { .. } => {
                if method == "Open" {
                    let location = param_u32(params, 0).unwrap_or(2);
                    let name = param_string(params, 1).unwrap_or_else(|| "My".into());
                    if let Some(ObjKind::Store {
                        opened,
                        location: loc,
                        name: slot_name,
                    }) = self.objects.get_mut(&objid)
                    {
                        *opened = true;
                        *loc = location;
                        *slot_name = name;
                    }
                    return Ok(json!({"type": "OK"}));
                }
                if method == "Close" {
                    if let Some(ObjKind::Store { opened, .. }) = self.objects.get_mut(&objid) {
                        *opened = false;
                    }
                    return Ok(json!({"type": "OK"}));
                }
                if method == "Add" || method == "Import" {
                    // Memory-store install flows — no persistent OS store in jex host.
                    return Ok(json!({"type": "OK"}));
                }
                if method == "AddCRL" {
                    return Ok(json!({"type": "OK"}));
                }
                if method == "RemoveCRL" {
                    return Ok(json!({"type": "OK"}));
                }
            }
            ObjKind::About => {
                if method == "CSPVersion" {
                    let id = self.alloc(ObjKind::Version {
                        major: CSP_VERSION_MAJOR,
                        minor: CSP_VERSION_MINOR,
                        build: CSP_VERSION_BUILD,
                    });
                    return Ok(object_retval(
                        id,
                        &["MajorVersion", "MinorVersion", "BuildVersion"],
                        &["toString"],
                    ));
                }
                if method == "CSPName" {
                    return Ok(json!({
                        "type": "string",
                        "value": CSP_PROVIDER_NAME
                    }));
                }
                if method == "ProviderVersion" {
                    return Ok(json!({
                        "type": "string",
                        "value": format!(
                            "{CSP_VERSION_MAJOR}.{CSP_VERSION_MINOR}.{CSP_VERSION_BUILD}"
                        )
                    }));
                }
                if method == "toString" {
                    return Ok(json!({
                        "type": "string",
                        "value": format!(
                            "{PLUGIN_VERSION_MAJOR}.{PLUGIN_VERSION_MINOR}.{PLUGIN_VERSION_BUILD}"
                        )
                    }));
                }
            }
            ObjKind::Version {
                major,
                minor,
                build,
            } => {
                if method == "toString" {
                    return Ok(json!({
                        "type": "string",
                        "value": format!("{major}.{minor}.{build}")
                    }));
                }
            }
            ObjKind::Certificate { .. } => {
                if method == "Import" {
                    return self.certificate_import(objid, params);
                }
                let view = match self.objects.get(&objid) {
                    Some(ObjKind::Certificate { view }) => view.clone(),
                    _ => bail!("not a certificate"),
                };
                if method == "Export" {
                    if view.cert_der.is_empty() {
                        bail!("certificate not imported");
                    }
                    let b64 = STANDARD.encode(&view.cert_der);
                    return Ok(json!({"type": "string", "value": b64}));
                }
                if method == "FindPrivateKey" {
                    return Ok(json!({"type": "OK"}));
                }
                // Demo FillCertInfo_Async: yield cert.HasPrivateKey() — method call.
                // Token certs carry token_idx (key not unlocked yet) — still have a private key.
                if method == "HasPrivateKey" {
                    return Ok(json!({
                        "type": "boolean",
                        "value": view.key_index.is_some() || view.token_idx.is_some()
                    }));
                }
                if method == "PublicKey" {
                    let id = self.alloc(ObjKind::PublicKey {
                        curve_bytes: Self::curve_bytes_for_cert(&view),
                    });
                    return Ok(object_retval(id, &["Algorithm", "Length"], &[]));
                }
                if method == "IsValid" {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    let ok = !view.cert_der.is_empty()
                        && now >= view.not_before_unix
                        && now <= view.not_after_unix;
                    let id = self.alloc(ObjKind::CertStatus { result: ok });
                    return Ok(object_retval(id, &["Result", "ValidationResult"], &[]));
                }
                if method == "Extensions" {
                    let id = self.alloc(ObjKind::CertExtensions);
                    return Ok(object_retval(id, &["Count"], &["Item"]));
                }
            }
            ObjKind::PrivateKey { .. } => {
                if method == "CachePin" {
                    return Ok(json!({"type": "OK"}));
                }
            }
            ObjKind::CertExtensions => {
                if method == "Item" {
                    bail!("extension index out of range");
                }
            }
            ObjKind::CspInformation { .. } => {
                if method == "InitializeFromName" {
                    if let Some(ObjKind::CspInformation { initialized }) =
                        self.objects.get_mut(&objid)
                    {
                        *initialized = true;
                    }
                    return Ok(json!({"type": "OK"}));
                }
                if method == "ContainerByName" {
                    let name = param_string(params, 0).unwrap_or_default();
                    let name = name.trim();
                    self.refresh_token_inventory(false);
                    let source = self
                        .keys
                        .iter()
                        .enumerate()
                        .find(|(_, k)| {
                            k.id.eq_ignore_ascii_case(name)
                                || k.unique_container_name.eq_ignore_ascii_case(name)
                        })
                        .map(|(i, _)| ContRef::Hdimage(i))
                        .or_else(|| {
                            self.token_inventory
                                .containers
                                .iter()
                                .enumerate()
                                .find(|(_, c)| {
                                    c.unique_name.eq_ignore_ascii_case(name)
                                        || c.fqcn.eq_ignore_ascii_case(name)
                                        || c.path_display.eq_ignore_ascii_case(name)
                                })
                                .map(|(i, _)| ContRef::Token(i))
                        });
                    let Some(source) = source else {
                        bail!("container not found");
                    };
                    let id = self.alloc(ObjKind::Container {
                        source,
                        silent: false,
                    });
                    return Ok(self.container_object(id));
                }
                if method == "EnumContainers" {
                    let items = self.all_container_refs();
                    let id = self.alloc(ObjKind::Containers { items });
                    return Ok(object_retval(id, &["Count"], &["ItemByIndex"]));
                }
                if method == "GetReaderModes" {
                    let items = self.all_reader_modes();
                    let id = self.alloc(ObjKind::ReaderModes { items });
                    return Ok(object_retval(id, &["Count"], &["ItemByIndex"]));
                }
                if method == "addEventListener" {
                    return Ok(json!({"type": "OK"}));
                }
            }
            ObjKind::Containers { .. } => {
                if method == "ItemByIndex" {
                    let idx = param_u32(params, 0).context("Containers.ItemByIndex")? as usize;
                    let source = match self.objects.get(&objid) {
                        Some(ObjKind::Containers { items }) => items.get(idx).copied(),
                        _ => None,
                    }
                    .context("container index out of range")?;
                    let id = self.alloc(ObjKind::Container {
                        source,
                        silent: false,
                    });
                    return Ok(self.container_object(id));
                }
            }
            ObjKind::ContKeys { .. } => {
                if method == "ItemByIndex" {
                    let idx = param_u32(params, 0).context("Keys.ItemByIndex")? as usize;
                    if idx != 0 {
                        bail!("key index out of range");
                    }
                    let source = match self.objects.get(&objid) {
                        Some(ObjKind::ContKeys { source }) => *source,
                        _ => bail!("not ContKeys"),
                    };
                    let id = self.alloc(ObjKind::ContKey { source });
                    return Ok(object_retval(
                        id,
                        &[
                            "IsExportable",
                            "Type",
                            "HasCertificate",
                            "ExpirationTime",
                            "KP_FP",
                            "KP_ALGID",
                            "Certificate",
                        ],
                        &[],
                    ));
                }
            }
            ObjKind::Attrs2 { signer_id } => {
                let signer_id = *signer_id;
                if method == "Add" {
                    let attr_id = param_object_id(params, 0).context("Attrs2.Add(attr)")?;
                    let entry = match self.objects.get(&attr_id) {
                        Some(ObjKind::CPAttribute {
                            name,
                            value,
                            value_encoding,
                        }) => AttrEntry {
                            name: *name,
                            value: value.clone(),
                            value_encoding: *value_encoding,
                        },
                        _ => bail!("CPAttribute expected"),
                    };
                    match self.objects.get_mut(&signer_id) {
                        Some(ObjKind::Signer { attrs, .. }) => attrs.push(entry),
                        _ => bail!("AuthenticatedAttributes2 signer missing"),
                    }
                    return Ok(json!({"type": "OK"}));
                }
                if method == "Clear" {
                    if let Some(ObjKind::Signer { attrs, .. }) = self.objects.get_mut(&signer_id) {
                        attrs.clear();
                    }
                    return Ok(json!({"type": "OK"}));
                }
                if method == "Remove" {
                    let idx = param_u32(params, 0).context("Attrs2.Remove index")? as usize;
                    if let Some(ObjKind::Signer { attrs, .. }) = self.objects.get_mut(&signer_id) {
                        if idx == 0 || idx > attrs.len() {
                            bail!("attribute index out of range");
                        }
                        attrs.remove(idx - 1);
                    }
                    return Ok(json!({"type": "OK"}));
                }
                if method == "Item" {
                    let idx = param_u32(params, 0).context("Attrs2.Item index")? as usize;
                    let entry = match self.objects.get(&signer_id) {
                        Some(ObjKind::Signer { attrs, .. }) => {
                            if idx == 0 || idx > attrs.len() {
                                bail!("attribute index out of range");
                            }
                            attrs[idx - 1].clone()
                        }
                        _ => bail!("AuthenticatedAttributes2 signer missing"),
                    };
                    let id = self.alloc(ObjKind::CPAttribute {
                        name: entry.name,
                        value: entry.value,
                        value_encoding: entry.value_encoding,
                    });
                    return Ok(object_retval(
                        id,
                        &["Name", "Value", "ValueEncoding"],
                        &[],
                    ));
                }
            }
            ObjKind::TrustedSites => {
                if method == "Item" {
                    // Extension UI uses 0-based indices (unlike CAPICOM Certificates).
                    let idx = param_u32(params, 0).context("TrustedSites.Item index")? as usize;
                    let site = self
                        .trusted_sites
                        .get(idx)
                        .cloned()
                        .context("TrustedSites index out of range")?;
                    return Ok(json!({"type": "string", "value": site}));
                }
                if method == "Add" {
                    let site = param_string(params, 0).context("TrustedSites.Add needs URL")?;
                    let site = site.trim().to_string();
                    if site.is_empty() {
                        bail!("empty trusted site");
                    }
                    if self.trusted_sites.iter().any(|s| s == &site) {
                        bail!("trusted site already exists");
                    }
                    self.trusted_sites.push(site);
                    return Ok(json!({"type": "OK"}));
                }
                if method == "Remove" {
                    let idx = param_u32(params, 0).context("TrustedSites.Remove index")? as usize;
                    if idx >= self.trusted_sites.len() {
                        bail!("TrustedSites index out of range");
                    }
                    self.trusted_sites.remove(idx);
                    return Ok(json!({"type": "OK"}));
                }
                if method == "Save" {
                    save_trusted_sites(&self.trusted_sites)?;
                    return Ok(json!({"type": "OK"}));
                }
            }
            _ => {}
        }
        bail!("method {method} not implemented on objid={objid}");
    }

    fn create_object(&mut self, name: &str) -> Result<Value> {
        // Demo / sites mix CAdESCOM.About vs CAdESCOM.about.
        let name_key = name.to_ascii_lowercase();
        let (kind, props, methods) = match name_key.as_str() {
            "cadescom.about" | "cadescom.version" => (
                ObjKind::About,
                vec![
                    "Version",
                    "PluginVersion",
                    "MajorVersion",
                    "MinorVersion",
                    "BuildVersion",
                ],
                vec!["CSPVersion", "CSPName", "ProviderVersion", "toString"],
            ),
            "cadescom.store" | "capicom.store" => (
                ObjKind::Store {
                    opened: false,
                    location: 2,
                    name: "My".into(),
                },
                vec!["Certificates", "CRLs"],
                vec!["Open", "Close", "Add", "Import", "AddCRL", "RemoveCRL"],
            ),
            "cadescom.crl" => (
                ObjKind::Crl {
                    issuer_name: String::new(),
                    thumbprint: String::new(),
                    this_update: String::new(),
                    next_update: String::new(),
                    der: Vec::new(),
                },
                vec![
                    "IssuerName",
                    "Thumbprint",
                    "ThisUpdate",
                    "NextUpdate",
                    "CRLNextPublish",
                ],
                vec!["Import", "Export"],
            ),
            "cadescom.cpsigner" => (
                ObjKind::Signer {
                    key_index: None,
                    token_idx: None,
                    key_pin: None,
                    tsa: self.default_tsa.clone(),
                    check_certificate: false,
                    options: 2,
                    attrs: Vec::new(),
                },
                vec![
                    "Certificate",
                    "KeyPin",
                    "CheckCertificate",
                    "TSAAddress",
                    "TSPAddress",
                    "Options",
                    "AuthenticatedAttributes2",
                ],
                vec![],
            ),
            "cadescom.cpattribute" | "capicom.attribute" => (
                ObjKind::CPAttribute {
                    name: 0,
                    value: String::new(),
                    value_encoding: 0,
                },
                vec!["Name", "Value", "ValueEncoding"],
                vec![],
            ),
            "cadescom.signedxml" => (
                ObjKind::SignedXml {
                    content: String::new(),
                    digest_method: xmldsig::DIGEST_METHOD_256.to_string(),
                    signature_method: xmldsig::SIGNATURE_METHOD_256.to_string(),
                    signature_type: 0,
                    signer_obj: None,
                },
                vec![
                    "Content",
                    "DigestMethod",
                    "SignatureMethod",
                    "SignatureType",
                    "Signers",
                ],
                vec!["Sign", "Verify"],
            ),
            "cadescom.cadessigneddata" => (
                ObjKind::CadesSignedData {
                    content_b64: String::new(),
                    content_encoding: CADESCOM_STRING_TO_UCS2LE,
                    detached: false,
                    last_signature: None,
                    verified: None,
                },
                vec![
                    "Content",
                    "ContentEncoding",
                    "DisplayData",
                    "Signers",
                    "Certificates",
                ],
                vec![
                    "SignCades",
                    "Sign",
                    "VerifyCades",
                    "Verify",
                    "EnhanceCades",
                    "AdditionalStore",
                    "GetMsgType",
                ],
            ),
            // Demo FillCertInfo probes this; allow create, fail later methods in try/catch.
            "x509enrollment.ccspinformation" => (
                ObjKind::CspInformation {
                    initialized: false,
                },
                vec!["ControlKeyTimeValidity"],
                vec![
                    "InitializeFromName",
                    "ContainerByName",
                    "EnumContainers",
                    "GetReaderModes",
                    "addEventListener",
                ],
            ),
            "cadescom.certificate" => (
                ObjKind::Certificate {
                    view: empty_cert_view(),
                },
                vec![
                    "SubjectName",
                    "IssuerName",
                    "Thumbprint",
                    "SerialNumber",
                    "ValidFromDate",
                    "ValidToDate",
                    "PrivateKey",
                    "Archived",
                ],
                vec![
                    "Import",
                    "Export",
                    "FindPrivateKey",
                    "HasPrivateKey",
                    "PublicKey",
                    "IsValid",
                    "Extensions",
                ],
            ),
            "cadescom.hasheddata" | "cadescom.cphasheddata" => (
                ObjKind::HashedData {
                    algorithm: 101,
                    data_encoding: 1,
                    value_hex: String::new(),
                },
                vec!["Algorithm", "DataEncoding", "Value"],
                vec!["Hash", "SetHashValue"],
            ),
            "cadescom.rawsignature" => (ObjKind::RawSignature, vec![], vec!["SignHash", "VerifyHash"]),
            "cadescom.cpenvelopeddata" => (
                ObjKind::CPEnvelopedData {
                    algorithm: 0.0,
                    recipient_cert_ids: Vec::new(),
                    content_b64: String::new(),
                    // Match webtools decrypt path (CADESCOM_BASE64_TO_BINARY).
                    content_encoding: 1,
                },
                vec!["ContentEncoding", "Content", "Recipients", "Algorithm"],
                vec!["StreamEncrypt", "StreamDecrypt", "Encrypt", "Decrypt"],
            ),
            "cadescom.envelopedxml" => (
                ObjKind::EnvelopedXml {
                    content: String::new(),
                    algorithm: 0.0,
                    recipient_cert_ids: Vec::new(),
                },
                vec!["Content", "Recipients", "Algorithm"],
                vec!["Encrypt", "Decrypt"],
            ),
            "cadescom.pluginconfiguration" => (
                ObjKind::PluginConfiguration,
                vec![
                    "TrustedSites",
                    "TrustedSitesGroupPolicy",
                    "IsUntrustedSitesDisabled",
                ],
                vec![],
            ),
            _ => bail!("Unknown object name: {name}"),
        };
        let id = self.alloc(kind);
        Ok(object_retval(id, &props, &methods))
    }

    fn get_property(&mut self, objid: u32, prop: &str) -> Result<Value> {
        match self.objects.get(&objid).context("unknown objid")? {
            ObjKind::About => match prop {
                "Version" => Ok(json!({
                    "type": "string",
                    "value": format!(
                        "{PLUGIN_VERSION_MAJOR}.{PLUGIN_VERSION_MINOR}.{PLUGIN_VERSION_BUILD}"
                    )
                })),
                "PluginVersion" => {
                    let id = self.alloc(ObjKind::Version {
                        major: PLUGIN_VERSION_MAJOR,
                        minor: PLUGIN_VERSION_MINOR,
                        build: PLUGIN_VERSION_BUILD,
                    });
                    Ok(object_retval(
                        id,
                        &["MajorVersion", "MinorVersion", "BuildVersion"],
                        &["toString"],
                    ))
                }
                "MajorVersion" => Ok(json!({"type": "number", "value": PLUGIN_VERSION_MAJOR})),
                "MinorVersion" => Ok(json!({"type": "number", "value": PLUGIN_VERSION_MINOR})),
                "BuildVersion" => Ok(json!({"type": "number", "value": PLUGIN_VERSION_BUILD})),
                _ => bail!("unknown About property {prop}"),
            },
            ObjKind::Version {
                major,
                minor,
                build,
            } => match prop {
                "MajorVersion" => Ok(json!({"type": "number", "value": major})),
                "MinorVersion" => Ok(json!({"type": "number", "value": minor})),
                "BuildVersion" => Ok(json!({"type": "number", "value": build})),
                _ => bail!("unknown Version property {prop}"),
            },
            ObjKind::Store { location, name, .. } => {
                if prop == "Certificates" {
                    let loc = *location;
                    let store_name = name.clone();
                    self.refresh_token_inventory(false);
                    // webtools FillCustomCertList opens My + AddressBook and concatenates;
                    // only "My" / container / memory stores expose personal keys.
                    let indices = if store_exposes_personal_certs(&store_name, loc) {
                        None
                    } else {
                        Some(Vec::new())
                    };
                    let id = self.alloc(ObjKind::Certificates {
                        location: loc,
                        indices,
                    });
                    return Ok(object_retval(id, &["Count"], &["Item", "Find"]));
                }
                if prop == "CRLs" {
                    let id = self.alloc(ObjKind::Crls { items: Vec::new() });
                    return Ok(object_retval(id, &["Count"], &["Item"]));
                }
                bail!("unknown Store property {prop}");
            }
            ObjKind::Crls { items } => {
                if prop == "Count" {
                    return Ok(json!({"type": "number", "value": items.len()}));
                }
                bail!("unknown CRLs property {prop}");
            }
            ObjKind::Crl { issuer_name, thumbprint, this_update, next_update, der } => {
                match prop {
                    "IssuerName" => Ok(json!({"type": "string", "value": issuer_name})),
                    "Thumbprint" => Ok(json!({"type": "string", "value": thumbprint})),
                    "ThisUpdate" => Ok(json!({"type": "string", "value": this_update})),
                    "NextUpdate" => Ok(json!({"type": "string", "value": next_update})),
                    "CRLNextPublish" => Ok(json!({"type": "string", "value": next_update})),
                    _ => {
                        let _ = der;
                        bail!("unknown CRL property {prop}")
                    }
                }
            }
            ObjKind::Certificates { indices, .. } => {
                if prop == "Count" {
                    let n = self.cert_collection_refs(indices.as_ref()).len();
                    return Ok(json!({"type": "number", "value": n}));
                }
                bail!("unknown Certificates property {prop}");
            }
            ObjKind::Certificate { view } => {
                let view = view.clone();
                if prop == "Archived" {
                    return Ok(json!({"type": "boolean", "value": false}));
                }
                if prop == "PrivateKey" {
                    let (key_index, container_name, unique_container_name) =
                        if let Some(i) = view.key_index {
                            let k = &self.keys[i];
                            (
                                i,
                                k.id.clone(),
                                k.unique_container_name.clone(),
                            )
                        } else if let Some(t) = view.token_idx {
                            let c = self
                                .token_inventory
                                .containers
                                .get(t)
                                .context("token container for PrivateKey")?;
                            let unique = if !c.fqcn.is_empty() {
                                c.fqcn.clone()
                            } else {
                                token_unique_path(&c.reader_name, &c.unique_name)
                            };
                            (0, c.unique_name.clone(), unique)
                        } else {
                            bail!("certificate has no private key");
                        };
                    let id = self.alloc(ObjKind::PrivateKey {
                        key_index,
                        container_name,
                        unique_container_name,
                    });
                    return Ok(object_retval(
                        id,
                        &["ProviderName", "UniqueContainerName", "ContainerName"],
                        &["CachePin"],
                    ));
                }
                match prop {
                    "SubjectName" => Ok(json!({"type": "string", "value": view.subject_name})),
                    "IssuerName" => Ok(json!({"type": "string", "value": view.issuer_name})),
                    "Thumbprint" => Ok(json!({"type": "string", "value": view.thumbprint})),
                    "SerialNumber" => Ok(json!({"type": "string", "value": view.serial_hex})),
                    "HasPrivateKey" => Ok(json!({
                        "type": "boolean",
                        "value": view.key_index.is_some() || view.token_idx.is_some()
                    })),
                    "ValidFromDate" => Ok(json!({
                        "type": "string",
                        "value": unix_to_cades_utc(view.not_before_unix)
                    })),
                    "ValidToDate" => Ok(json!({
                        "type": "string",
                        "value": unix_to_cades_utc(view.not_after_unix)
                    })),
                    _ => bail!("unknown Certificate property {prop}"),
                }
            }
            ObjKind::PrivateKey {
                container_name,
                unique_container_name,
                ..
            } => match prop {
                "ProviderName" => Ok(json!({
                    "type": "string",
                    "value": CSP_PROVIDER_NAME
                })),
                "UniqueContainerName" => {
                    Ok(json!({"type": "string", "value": unique_container_name}))
                }
                "ContainerName" => Ok(json!({"type": "string", "value": container_name})),
                _ => bail!("unknown PrivateKey property {prop}"),
            },
            ObjKind::PublicKey { curve_bytes } => match prop {
                "Algorithm" => {
                    let (oid, friendly) = algo_for_curve(*curve_bytes);
                    let id = self.alloc(ObjKind::Algorithm {
                        oid: oid.to_string(),
                        friendly: friendly.to_string(),
                    });
                    Ok(object_retval(id, &["Value", "FriendlyName", "Name"], &[]))
                }
                "Length" => Ok(json!({"type": "number", "value": curve_bytes * 8})),
                _ => bail!("unknown PublicKey property {prop}"),
            },
            ObjKind::Algorithm { oid, friendly } => match prop {
                "Value" | "Name" => Ok(json!({"type": "string", "value": oid})),
                "FriendlyName" => Ok(json!({"type": "string", "value": friendly})),
                _ => bail!("unknown Algorithm property {prop}"),
            },
            ObjKind::CertStatus { result } => match prop {
                "Result" | "ValidationResult" => {
                    Ok(json!({"type": "boolean", "value": result}))
                }
                _ => bail!("unknown CertStatus property {prop}"),
            },
            ObjKind::CertExtensions => {
                if prop == "Count" {
                    return Ok(json!({"type": "number", "value": 0}));
                }
                bail!("unknown Extensions property {prop}");
            },
            ObjKind::CspInformation { .. } => {
                // CONTROL_KEY_TIME_VALIDITY_ENABLED = 1 — demo skips PKUP when enabled.
                if prop == "ControlKeyTimeValidity" {
                    return Ok(json!({"type": "number", "value": 1}));
                }
                bail!("unknown CspInformation property {prop}");
            },
            ObjKind::HashedData {
                algorithm,
                data_encoding,
                value_hex,
            } => match prop {
                "Algorithm" => Ok(json!({"type": "number", "value": algorithm})),
                "DataEncoding" => Ok(json!({"type": "number", "value": data_encoding})),
                "Value" => Ok(json!({"type": "string", "value": value_hex})),
                _ => bail!("unknown HashedData property {prop}"),
            },
            ObjKind::ReaderModes { items } => {
                if prop == "Count" {
                    return Ok(json!({"type": "number", "value": items.len()}));
                }
                bail!("unknown ReaderModes property {prop}");
            }
            ObjKind::ReaderMode(entry) => match prop {
                "Name" => Ok(json!({"type": "string", "value": &entry.name})),
                "NickName" => Ok(json!({"type": "string", "value": &entry.nickname})),
                "Media" => Ok(json!({"type": "string", "value": &entry.media})),
                "CarrierFlags" => Ok(json!({"type": "number", "value": entry.carrier_flags})),
                _ => bail!("unknown ReaderMode property {prop}"),
            },
            ObjKind::Containers { items } => {
                if prop == "Count" {
                    return Ok(json!({"type": "number", "value": items.len()}));
                }
                bail!("unknown Containers property {prop}");
            }
            ObjKind::Container { source, silent } => {
                let source = *source;
                let silent = *silent;
                match prop {
                    "Name" => {
                        let name = match source {
                            ContRef::Hdimage(i) => self.keys[i].id.clone(),
                            ContRef::Token(i) => {
                                self.token_inventory.containers[i].unique_name.clone()
                            }
                        };
                        Ok(json!({"type": "string", "value": name}))
                    }
                    "UniqueName" => {
                        let name = match source {
                            ContRef::Hdimage(i) => self.keys[i].unique_container_name.clone(),
                            ContRef::Token(i) => {
                                self.token_inventory.containers[i].fqcn.clone()
                            }
                        };
                        Ok(json!({"type": "string", "value": name}))
                    }
                    "Media" => {
                        let media = match source {
                            ContRef::Hdimage(i) => self.keys[i]
                                .disk_path
                                .clone()
                                .unwrap_or_else(|| self.keys[i].unique_container_name.clone()),
                            ContRef::Token(i) => {
                                reader_media_label(&self.token_inventory.containers[i].reader_name)
                                    .to_string()
                            }
                        };
                        Ok(json!({"type": "string", "value": media}))
                    }
                    "Reader" => {
                        let reader = match source {
                            ContRef::Hdimage(_) => READER_NAME.to_string(),
                            ContRef::Token(i) => {
                                self.token_inventory.containers[i].reader_name.clone()
                            }
                        };
                        Ok(json!({"type": "string", "value": reader}))
                    }
                    "FQCN" => {
                        let fqcn = match source {
                            ContRef::Hdimage(i) => self.keys[i].unique_container_name.clone(),
                            ContRef::Token(i) => {
                                self.token_inventory.containers[i].fqcn.clone()
                            }
                        };
                        Ok(json!({"type": "string", "value": fqcn}))
                    }
                    "Silent" => Ok(json!({"type": "boolean", "value": silent})),
                    "Keys" => {
                        let id = self.alloc(ObjKind::ContKeys { source });
                        Ok(object_retval(id, &["Count"], &["ItemByIndex"]))
                    }
                    _ => bail!("unknown Container property {prop}"),
                }
            }
            ObjKind::ContKeys { .. } => {
                if prop == "Count" {
                    return Ok(json!({"type": "number", "value": 1}));
                }
                bail!("unknown ContKeys property {prop}");
            }
            ObjKind::ContKey { source } => {
                let source = *source;
                match prop {
                    "IsExportable" => Ok(json!({"type": "boolean", "value": false})),
                    "Type" => Ok(json!({"type": "number", "value": AT_SIGNATURE})),
                    "HasCertificate" => {
                        let has = match source {
                            ContRef::Hdimage(_) => true,
                            ContRef::Token(i) => {
                                self.token_inventory.containers[i].view.is_some()
                            }
                        };
                        Ok(json!({"type": "boolean", "value": has}))
                    }
                    "ExpirationTime" => {
                        let unix = match source {
                            ContRef::Hdimage(i) => self.keys[i].not_after_unix,
                            ContRef::Token(i) => {
                                self.token_inventory.containers[i].not_after_unix
                            }
                        };
                        Ok(json!({
                            "type": "string",
                            "value": unix_to_cades_utc(unix)
                        }))
                    }
                    "KP_FP" => {
                        let fp = match source {
                            ContRef::Hdimage(i) => self.keys[i]
                                .public_x_le
                                .get(..8)
                                .map(hex::encode_upper)
                                .unwrap_or_default(),
                            ContRef::Token(i) => self.token_inventory.containers[i]
                                .public_x_prefix
                                .map(hex::encode_upper)
                                .unwrap_or_default(),
                        };
                        Ok(json!({"type": "string", "value": fp}))
                    }
                    "KP_ALGID" => {
                        let alg = match source {
                            ContRef::Hdimage(i) => {
                                if self.keys[i].curve.bytes >= 64 {
                                    0x2E4Au32
                                } else {
                                    0x2E49
                                }
                            }
                            ContRef::Token(i) => {
                                let bytes = self.token_inventory.containers[i]
                                    .view
                                    .as_ref()
                                    .map(Self::curve_bytes_for_cert)
                                    .unwrap_or(32);
                                if bytes >= 64 {
                                    0x2E4Au32
                                } else {
                                    0x2E49
                                }
                            }
                        };
                        Ok(json!({"type": "number", "value": alg}))
                    }
                    "Certificate" => {
                        let view = match source {
                            ContRef::Hdimage(i) => self.cert_view_from_host(i),
                            ContRef::Token(i) => self
                                .token_inventory
                                .containers
                                .get(i)
                                .and_then(|c| c.view.clone())
                                .context("token container has no certificate")?,
                        };
                        Ok(self.certificate_object(&view))
                    }
                    _ => bail!("unknown ContKey property {prop}"),
                }
            }
            ObjKind::CPEnvelopedData {
                content_b64,
                content_encoding,
                ..
            } => {
                if prop == "Recipients" {
                    let id = self.alloc(ObjKind::Recipients {
                        parent: EnvelopeParent::Cms(objid),
                        cert_ids: Vec::new(),
                    });
                    return Ok(object_retval(id, &["Count"], &["Add"]));
                }
                if prop == "Algorithm" {
                    let name = match self.objects.get(&objid) {
                        Some(ObjKind::CPEnvelopedData { algorithm, .. }) => *algorithm,
                        _ => 0.0,
                    };
                    let id = self.alloc(ObjKind::EnvelopeAlgorithm {
                        parent: EnvelopeParent::Cms(objid),
                        name,
                    });
                    return Ok(object_retval(id, &["Name"], &[]));
                }
                if prop == "ContentEncoding" {
                    return Ok(json!({"type": "number", "value": content_encoding}));
                }
                if prop == "Content" {
                    return Ok(json!({"type": "string", "value": content_b64}));
                }
                bail!("unknown CPEnvelopedData property {prop}");
            }
            ObjKind::EnvelopedXml { content, .. } => {
                if prop == "Content" {
                    return Ok(json!({"type": "string", "value": content}));
                }
                if prop == "Recipients" {
                    let id = self.alloc(ObjKind::Recipients {
                        parent: EnvelopeParent::Xml(objid),
                        cert_ids: Vec::new(),
                    });
                    return Ok(object_retval(id, &["Count"], &["Add"]));
                }
                if prop == "Algorithm" {
                    let id = self.alloc(ObjKind::EnvelopeAlgorithm {
                        parent: EnvelopeParent::Xml(objid),
                        name: 0.0,
                    });
                    return Ok(object_retval(id, &["Name"], &[]));
                }
                bail!("unknown EnvelopedXML property {prop}");
            }
            ObjKind::Recipients { cert_ids, .. } => {
                if prop == "Count" {
                    return Ok(json!({"type": "number", "value": cert_ids.len()}));
                }
                bail!("unknown Recipients property {prop}");
            }
            ObjKind::EnvelopeAlgorithm { name, .. } => {
                if prop == "Name" {
                    return Ok(json!({"type": "number", "value": name}));
                }
                bail!("unknown Algorithm property {prop}");
            }
            ObjKind::SignedXml {
                content,
                digest_method,
                signature_method,
                signature_type,
                ..
            } => match prop {
                "Content" => Ok(json!({"type": "string", "value": content})),
                "DigestMethod" => Ok(json!({"type": "string", "value": digest_method})),
                "SignatureMethod" => Ok(json!({"type": "string", "value": signature_method})),
                "SignatureType" => Ok(json!({"type": "number", "value": signature_type})),
                _ => bail!("unknown SignedXML property {prop}"),
            },
            ObjKind::Signer { tsa, options, .. } => match prop {
                "TSAAddress" | "TSPAddress" => Ok(json!({
                    "type": "string",
                    "value": tsa.clone().unwrap_or_default()
                })),
                "CheckCertificate" => Ok(json!({"type": "boolean", "value": false})),
                "Options" => Ok(json!({"type": "number", "value": options})),
                "AuthenticatedAttributes2" => {
                    let id = self.alloc(ObjKind::Attrs2 { signer_id: objid });
                    Ok(object_retval(
                        id,
                        &["Count"],
                        &["Add", "Clear", "Remove", "Item"],
                    ))
                }
                _ => bail!("unknown CPSigner property {prop}"),
            },
            ObjKind::CPAttribute {
                name,
                value,
                value_encoding,
            } => match prop {
                "Name" => Ok(json!({"type": "number", "value": name})),
                "Value" => Ok(json!({"type": "string", "value": value})),
                "ValueEncoding" => Ok(json!({"type": "number", "value": value_encoding})),
                _ => bail!("unknown CPAttribute property {prop}"),
            },
            ObjKind::Attrs2 { signer_id } => {
                if prop == "Count" {
                    let n = match self.objects.get(signer_id) {
                        Some(ObjKind::Signer { attrs, .. }) => attrs.len(),
                        _ => 0,
                    };
                    return Ok(json!({"type": "number", "value": n}));
                }
                bail!("unknown Attrs2 property {prop}");
            },
            ObjKind::CadesSignedData { content_b64, verified, .. } => match prop {
                "Content" => Ok(json!({"type": "string", "value": content_b64})),
                "Signers" => {
                    let id = self.alloc(ObjKind::Signers { parent: objid });
                    Ok(object_retval(id, &["Count"], &["Item"]))
                }
                "Certificates" => {
                    let id = self.alloc(ObjKind::SignedDataCerts { parent: objid });
                    Ok(object_retval(id, &["Count"], &["Item"]))
                }
                _ => {
                    let _ = verified;
                    bail!("unknown CadesSignedData property {prop}")
                }
            },
            ObjKind::Signers { parent } => {
                if prop == "Count" {
                    let n = match self.objects.get(parent) {
                        Some(ObjKind::CadesSignedData {
                            verified: Some(_), ..
                        }) => 1,
                        _ => 0,
                    };
                    return Ok(json!({"type": "number", "value": n}));
                }
                bail!("unknown Signers property {prop}");
            }
            ObjKind::SignedDataCerts { parent } => {
                if prop == "Count" {
                    let n = match self.objects.get(parent) {
                        Some(ObjKind::CadesSignedData {
                            verified: Some(v), ..
                        }) => v.all_certs.len(),
                        _ => 0,
                    };
                    return Ok(json!({"type": "number", "value": n}));
                }
                bail!("unknown SignedDataCerts property {prop}");
            }
            ObjKind::VerifySigner {
                cert,
                signature_ok,
                signing_time_utc,
            } => match prop {
                "Certificate" => {
                    let id = self.alloc(ObjKind::Certificate {
                        view: cert.clone(),
                    });
                    Ok(object_retval(
                        id,
                        &[
                            "SubjectName",
                            "IssuerName",
                            "Thumbprint",
                            "SerialNumber",
                            "ValidFromDate",
                            "ValidToDate",
                            "PrivateKey",
                        ],
                        &[
                            "Export",
                            "FindPrivateKey",
                            "HasPrivateKey",
                            "PublicKey",
                            "IsValid",
                            "Extensions",
                        ],
                    ))
                }
                "SignatureStatus" => {
                    let id = self.alloc(ObjKind::SignatureStatus {
                        is_valid: *signature_ok,
                    });
                    Ok(object_retval(id, &["IsValid"], &[]))
                }
                "SigningTime" => Ok(json!({
                    "type": "string",
                    "value": signing_time_utc
                })),
                _ => bail!("unknown VerifySigner property {prop}"),
            },
            ObjKind::SignatureStatus { is_valid } => match prop {
                "IsValid" => Ok(json!({"type": "boolean", "value": is_valid})),
                _ => bail!("unknown SignatureStatus property {prop}"),
            },
            ObjKind::PluginConfiguration => match prop {
                "IsUntrustedSitesDisabled" => Ok(json!({"type": "boolean", "value": false})),
                "TrustedSitesGroupPolicy" => Ok(json!({"type": "string", "value": ""})),
                "TrustedSites" => {
                    let id = self.alloc(ObjKind::TrustedSites);
                    Ok(object_retval(id, &["Count"], &["Item", "Add", "Remove", "Save"]))
                }
                _ => bail!("unknown PluginConfiguration property {prop}"),
            },
            ObjKind::TrustedSites => {
                if prop == "Count" {
                    let n = self.trusted_sites.len();
                    return Ok(json!({"type": "number", "value": n}));
                }
                bail!("unknown TrustedSites property {prop}");
            }
            _ => bail!("get_property {prop} not supported on objid={objid}"),
        }
    }

    fn set_property(&mut self, objid: u32, prop: &str, params: &Value) -> Result<Value> {
        let val = params
            .as_array()
            .and_then(|a| a.first())
            .context("set_property needs a value")?;

        // Resolve certificate object → key_index / token_idx before mut borrow.
        let (cert_key_index, cert_token_idx) = if prop == "Certificate" {
            let cert_obj = val
                .get("value")
                .and_then(|v| v.as_u64())
                .context("Certificate expects object")? as u32;
            match self.objects.get(&cert_obj) {
                Some(ObjKind::Certificate {
                    view: CertView {
                        key_index: Some(i),
                        ..
                    },
                }) => (Some(*i), None),
                Some(ObjKind::Certificate {
                    view: CertView {
                        token_idx: Some(t),
                        key_index,
                        ..
                    },
                }) => (*key_index, Some(*t)),
                Some(ObjKind::Certificate { .. }) => {
                    bail!("Certificate has no private key (not in HDIMAGE config or Rutoken inventory)")
                }
                _ => bail!("Certificate value is not a certificate object"),
            }
        } else {
            (None, None)
        };

        match self.objects.get_mut(&objid).context("unknown objid")? {
            ObjKind::SignedXml {
                content,
                digest_method,
                signature_method,
                signature_type,
                signer_obj,
                ..
            } => match prop {
                "Content" => {
                    *content = value_as_string(val)?;
                }
                "DigestMethod" => *digest_method = value_as_string(val)?,
                "SignatureMethod" => *signature_method = value_as_string(val)?,
                "SignatureType" => {
                    *signature_type = value_as_u32(val)?;
                }
                "Signer" => {
                    *signer_obj = val.get("value").and_then(|v| v.as_u64()).map(|v| v as u32);
                }
                _ => bail!("cannot set SignedXML.{prop}"),
            },
            ObjKind::Signer {
                key_index,
                token_idx,
                key_pin,
                tsa,
                check_certificate,
                options,
                ..
            } => match prop {
                "Certificate" => {
                    *key_index = cert_key_index;
                    *token_idx = cert_token_idx;
                }
                "KeyPin" => {
                    *key_pin = Some(value_as_string(val)?);
                }
                "CheckCertificate" => {
                    *check_certificate = value_as_bool(val)?;
                }
                "TSAAddress" | "TSPAddress" => {
                    *tsa = Some(value_as_string(val)?);
                }
                "Options" => {
                    *options = value_as_u32(val)?;
                }
                _ => bail!("cannot set CPSigner.{prop}"),
            },
            ObjKind::CPAttribute {
                name,
                value,
                value_encoding,
            } => match prop {
                "Name" => *name = value_as_i32(val)?,
                "Value" => *value = value_as_attr_value(val)?,
                "ValueEncoding" => *value_encoding = value_as_u32(val)?,
                _ => bail!("cannot set CPAttribute.{prop}"),
            },
            ObjKind::PrivateKey { .. } => match prop {
                // CachePin is a write-only convenience; accept silently.
                "CachePin" => {}
                _ => bail!("cannot set PrivateKey.{prop}"),
            },
            ObjKind::CadesSignedData {
                content_b64,
                content_encoding,
                ..
            } => match prop {
                "Content" => *content_b64 = value_as_string(val)?,
                "ContentEncoding" => *content_encoding = value_as_u32(val)?,
                // DisplayData only affects UI presentation in CryptoPro; ignore.
                "DisplayData" => {}
                _ => bail!("cannot set CadesSignedData.{prop}"),
            },
            ObjKind::HashedData {
                algorithm,
                data_encoding,
                ..
            } => match prop {
                "Algorithm" => *algorithm = value_as_u32(val)?,
                "DataEncoding" => *data_encoding = value_as_u32(val)?,
                "Value" => {
                    bail!("use SetHashValue or Hash on HashedData");
                }
                _ => bail!("cannot set HashedData.{prop}"),
            },
            ObjKind::Container { silent, .. } => match prop {
                "Silent" => *silent = value_as_bool(val)?,
                _ => bail!("cannot set Container.{prop}"),
            },
            ObjKind::EnvelopedXml { content, .. } => match prop {
                "Content" => *content = value_as_string(val)?,
                _ => bail!("cannot set EnvelopedXML.{prop}"),
            },
            ObjKind::CPEnvelopedData {
                content_b64,
                content_encoding,
                ..
            } => match prop {
                "Content" => *content_b64 = value_as_string(val)?,
                "ContentEncoding" => *content_encoding = value_as_u32(val)?,
                _ => bail!("cannot set CPEnvelopedData.{prop}"),
            },
            ObjKind::EnvelopeAlgorithm { parent, name } => {
                if prop != "Name" {
                    bail!("cannot set EnvelopeAlgorithm.{prop}");
                }
                let algo = value_as_f64(val)?;
                *name = algo;
                let parent = *parent;
                match parent {
                    EnvelopeParent::Cms(pid) => {
                        if let Some(ObjKind::CPEnvelopedData { algorithm, .. }) =
                            self.objects.get_mut(&pid)
                        {
                            *algorithm = algo;
                        }
                    }
                    EnvelopeParent::Xml(pid) => {
                        if let Some(ObjKind::EnvelopedXml { algorithm, .. }) =
                            self.objects.get_mut(&pid)
                        {
                            *algorithm = algo;
                        }
                    }
                }
            }
            _ => bail!("set_property {prop} not supported on objid={objid}"),
        }
        Ok(json!({"type": "OK"}))
    }

    fn signed_xml_sign(&mut self, objid: u32, params: &Value) -> Result<Value> {
        // Sign(signer) or Sign(content, signer) — CryptoPro SignedXML.Sign(signer).
        let signer_id = param_object_id(params, 0)
            .or_else(|| param_object_id(params, 1))
            .context("SignedXML.Sign needs CPSigner")?;

        let (content, digest_method, signature_method, signature_type) =
            match self.objects.get(&objid) {
                Some(ObjKind::SignedXml {
                    content,
                    digest_method,
                    signature_method,
                    signature_type,
                    ..
                }) => (
                    content.clone(),
                    digest_method.clone(),
                    signature_method.clone(),
                    *signature_type,
                ),
                _ => bail!("not SignedXML"),
            };
        if content.is_empty() {
            bail!("SignedXML.Content is empty");
        }

        self.ensure_signer_unlocked(signer_id)?;
        let (key_index, tsa) = match self.objects.get(&signer_id) {
            Some(ObjKind::Signer {
                key_index: Some(i),
                tsa,
                ..
            }) => (*i, tsa.clone()),
            _ => bail!("CPSigner.Certificate not set / token key not unlocked"),
        };
        let key = &self.keys[key_index];

        let packaging = signature_type & 0x3;
        // Normalize legacy mistaken 0xdd0 (CAdES-A 0xdd shifted) → CADESCOM 0x7d0.
        let xades_flags = match signature_type & !0x3 {
            0x0dd0 => xmldsig::XADES_A,
            other => other,
        };
        let signature_type = match packaging {
            1 => xmldsig::XmlSignatureType::Enveloping,
            2 => xmldsig::XmlSignatureType::Template,
            _ => xmldsig::XmlSignatureType::Enveloped,
        };
        let tsa_url = tsa.as_deref().or(self.default_tsa.as_deref());
        if matches!(
            xades_flags,
            xmldsig::XADES_T | xmldsig::XADES_XLT1 | xmldsig::XADES_A
        ) && tsa_url.is_none()
        {
            bail!("XAdES-T/XLT1/A requires TSAAddress or config tsa");
        }

        let signed = xmldsig::sign_xml(&xmldsig::SignXmlParams {
            content: &content,
            cert_der: &key.cert_der,
            curve: &key.curve,
            private_le: &key.private_le,
            public_x_le: &key.public_x_le,
            public_y_le: &key.public_y_le,
            signature_type,
            digest_method: &digest_method,
            signature_method: &signature_method,
            xpath: None,
            xades_flags,
            tsa_url,
            tsa_policy: self.tsa_policy.as_deref(),
            tsa_timeout_secs: self.tsa_timeout_secs,
        })?;
        Ok(json!({"type": "string", "value": signed}))
    }

    fn signed_xml_verify(&mut self, params: &Value) -> Result<Value> {
        let signed = param_string(params, 0).context("Verify(signed_xml)")?;
        let v = xmldsig::verify_xml(&signed, None)?;
        if !v.ok {
            bail!("XML signature verification failed");
        }
        Ok(json!({"type": "OK"}))
    }

    fn cades_sign(&mut self, objid: u32, params: &Value) -> Result<Value> {
        let signer_id = param_object_id(params, 0).context("SignCades needs CPSigner")?;
        // CADES_USE_OCSP_AUTHORIZED_POLICY may be OR-ed by demo pages.
        let cades_type =
            normalize_sign_type(param_u32(params, 1).unwrap_or(CADESCOM_BES) & !CADES_OCSP_POLICY_FLAG)?;
        // SignCades(signer, type, bDetached) — third arg overrides object state.
        let is_detached_param = param_bool(params, 2);

        let (content_b64, content_encoding, object_detached) = match self.objects.get(&objid) {
            Some(ObjKind::CadesSignedData {
                content_b64,
                content_encoding,
                detached,
                ..
            }) => (content_b64.clone(), *content_encoding, *detached),
            _ => bail!("not CadesSignedData"),
        };
        let detached = is_detached_param.unwrap_or(object_detached);
        let content = decode_signed_content(&content_b64, content_encoding)?;

        self.ensure_signer_unlocked(signer_id)?;
        let (key_index, attrs, signer_tsa) = match self.objects.get(&signer_id) {
            Some(ObjKind::Signer {
                key_index: Some(i),
                attrs,
                tsa,
                ..
            }) => (*i, attrs.clone(), tsa.clone()),
            _ => bail!("CPSigner.Certificate not set / token key not unlocked"),
        };
        let key = &self.keys[key_index];
        let mut extra = Vec::new();
        for a in &attrs {
            extra.push(cades::authenticated_attr(a.name, &a.value, None)?);
        }
        let signed = cades::sign_bes_ex(&cades::SignBesParams {
            content: &content,
            content_digest: None,
            cert_der: &key.cert_der,
            curve: &key.curve,
            private_le: &key.private_le,
            expected_public_x_le: &key.public_x_le,
            expected_public_y_le: &key.public_y_le,
            detached,
            extra_signed_attrs: &extra,
        })?;

        let tsa = signer_tsa
            .as_deref()
            .or(self.default_tsa.as_deref())
            .map(|s| s.to_string());
        let der = upgrade_cades_cms(
            &signed.der,
            &signed.signature,
            key.curve.bytes,
            cades_type,
            detached,
            &content,
            tsa.as_deref(),
            self.tsa_policy.as_deref(),
            self.tsa_timeout_secs,
        )?;

        if let Some(ObjKind::CadesSignedData {
            detached: d,
            last_signature,
            ..
        }) = self.objects.get_mut(&objid)
        {
            *d = detached;
            *last_signature = Some(der.clone());
        }
        Ok(json!({"type": "string", "value": STANDARD.encode(&der)}))
    }

    fn cades_enhance(&mut self, objid: u32, params: &Value) -> Result<Value> {
        // EnhanceCades([cadesType], [tsaAddress]) — upgrades last Sign/Verify CMS.
        let target = normalize_sign_type(
            param_u32(params, 0).unwrap_or(CADESCOM_XLT1) & !CADES_OCSP_POLICY_FLAG,
        )?;
        let tsa_override = param_string(params, 1);

        let (der, content_b64, content_encoding, detached) = match self.objects.get(&objid) {
            Some(ObjKind::CadesSignedData {
                last_signature: Some(sig),
                content_b64,
                content_encoding,
                detached,
                ..
            }) => (
                sig.clone(),
                content_b64.clone(),
                *content_encoding,
                *detached,
            ),
            Some(ObjKind::CadesSignedData {
                last_signature: None,
                ..
            }) => bail!("EnhanceCades: no signature (SignCades/VerifyCades first)"),
            _ => bail!("not CadesSignedData"),
        };
        let content = if !content_b64.is_empty() {
            Some(decode_signed_content(&content_b64, content_encoding)?)
        } else {
            None
        };
        let parsed = cades::parse(&der)?;
        let tsa = tsa_override
            .or(self.default_tsa.clone())
            .context("EnhanceCades requires TSAAddress or config tsa")?;
        let curve_bytes = if parsed.signature.len() >= 128 { 64 } else { 32 };
        let out = upgrade_cades_cms(
            &der,
            &parsed.signature,
            curve_bytes,
            target,
            detached,
            content.as_deref().unwrap_or(&[]),
            Some(tsa.as_str()),
            self.tsa_policy.as_deref(),
            self.tsa_timeout_secs,
        )?;
        if let Some(ObjKind::CadesSignedData {
            last_signature, ..
        }) = self.objects.get_mut(&objid)
        {
            *last_signature = Some(out.clone());
        }
        Ok(json!({"type": "string", "value": STANDARD.encode(&out)}))
    }

    fn cades_get_msg_type(&mut self, params: &Value) -> Result<Value> {
        let b64 = param_string(params, 0).context("GetMsgType(signature)")?;
        let der = decode_cms_b64(&b64)?;
        // Attribute-only: verify.html calls GetMsgType before Content is set.
        Ok(json!({
            "type": "number",
            "value": get_msg_type_value(&der)?
        }))
    }

    fn cades_verify(&mut self, objid: u32, params: &Value) -> Result<Value> {
        let b64 = param_string(params, 0).context("VerifyCades(signature)")?;
        let der = decode_cms_b64(&b64)?;
        // CADES_USE_OCSP_AUTHORIZED_POLICY = 0x20000 is OR-ed by the demo page.
        let requested = param_u32(params, 1).unwrap_or(CADESCOM_BES) & !CADES_OCSP_POLICY_FLAG;
        let is_detached_param = param_bool(params, 2);

        let (content_b64, content_encoding, object_detached) = match self.objects.get(&objid) {
            Some(ObjKind::CadesSignedData {
                content_b64,
                content_encoding,
                detached,
                ..
            }) => (content_b64.clone(), *content_encoding, *detached),
            _ => bail!("not CadesSignedData"),
        };
        let detached = is_detached_param.unwrap_or(object_detached);
        if let Some(ObjKind::CadesSignedData { detached: d, .. }) = self.objects.get_mut(&objid) {
            *d = detached;
        }
        let content = if detached && !content_b64.is_empty() {
            Some(decode_signed_content(&content_b64, content_encoding)?)
        } else {
            None
        };
        let external = content.as_deref();

        let report = verification::analyze(&der, external)?;
        enforce_cades_type(requested, &report, &der)?;

        let parsed = cades::parse(&der)?;
        let signer_cert = Self::cert_view_from_der(&parsed.certificate)?;
        let mut all_certs = Vec::new();
        for c in cades::embedded_certificates(&der).unwrap_or_default() {
            if let Ok(view) = Self::cert_view_from_der(&c) {
                all_certs.push(view);
            }
        }
        if all_certs.is_empty() {
            all_certs.push(signer_cert.clone());
        }
        let signing_time_utc = unix_to_cades_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        );
        let signature_ok = report.is_valid();

        if let Some(ObjKind::CadesSignedData {
            verified,
            detached: det,
            last_signature,
            ..
        }) = self.objects.get_mut(&objid)
        {
            *det = parsed.detached;
            *last_signature = Some(der.clone());
            *verified = Some(CadesVerifyState {
                signature_ok,
                signing_time_utc,
                signer_cert,
                all_certs,
            });
        }
        Ok(json!({"type": "OK"}))
    }
}

/// CADESCOM_CADES_* (without CADES_USE_OCSP_AUTHORIZED_POLICY).
const CADESCOM_BES: u32 = 1;
const CADESCOM_T: u32 = 0x5;
const CADESCOM_XLT1: u32 = 0x5d;
const CADESCOM_A: u32 = 0xdd;
const CADESCOM_PKCS7: u32 = 0xffff;
const CADES_OCSP_POLICY_FLAG: u32 = 0x20000;
const CADESCOM_STRING_TO_UCS2LE: u32 = 0;
const CADESCOM_BASE64_TO_BINARY: u32 = 1;

fn store_exposes_personal_certs(name: &str, location: u32) -> bool {
    // CADESCOM_CONTAINER_STORE = 100; CADESCOM_MEMORY_STORE = 5 (typical).
    if location == 100 || location == 5 {
        return true;
    }
    let n = name.trim().to_ascii_lowercase();
    n.is_empty() || n == "my" || n == "uimy"
}

fn decode_enveloped_content(encoding: u32, content: &str) -> Result<Vec<u8>> {
    match encoding {
        0 => Ok(content.as_bytes().to_vec()),
        1 => Ok(STANDARD
            .decode(content.replace(['\n', '\r', ' '], "").as_bytes())
            .unwrap_or_else(|_| content.as_bytes().to_vec())),
        other => bail!("unsupported ContentEncoding {other}"),
    }
}

fn extract_xml_cipher_value(xml: &str) -> Option<String> {
    let start = xml.find("<CipherValue>")? + "<CipherValue>".len();
    let end = xml[start..].find("</CipherValue>")? + start;
    Some(xml[start..end].trim().to_string())
}

/// Decode CadesSignedData.Content according to ContentEncoding.
fn decode_signed_content(content: &str, encoding: u32) -> Result<Vec<u8>> {
    match encoding {
        CADESCOM_BASE64_TO_BINARY => Ok(STANDARD
            .decode(content.as_bytes())
            .unwrap_or_else(|_| content.as_bytes().to_vec())),
        CADESCOM_STRING_TO_UCS2LE => {
            // CryptoPro: Content is a string encoded as UCS-2LE (UTF-16LE without BOM).
            let mut out = Vec::with_capacity(content.len() * 2);
            for u in content.encode_utf16() {
                out.extend_from_slice(&u.to_le_bytes());
            }
            Ok(out)
        }
        other => bail!("unsupported ContentEncoding {other}"),
    }
}

fn normalize_sign_type(v: u32) -> Result<u32> {
    match v {
        0 | CADESCOM_BES | CADESCOM_PKCS7 => Ok(CADESCOM_BES),
        CADESCOM_T => Ok(CADESCOM_T),
        CADESCOM_XLT1 => Ok(CADESCOM_XLT1),
        CADESCOM_A => Ok(CADESCOM_A),
        other => bail!("unsupported CAdES type 0x{other:x}"),
    }
}

/// Upgrade CMS from BES (or higher) to the requested CADESCOM profile.
fn upgrade_cades_cms(
    der: &[u8],
    signature: &[u8],
    curve_bytes: usize,
    target: u32,
    detached: bool,
    content: &[u8],
    tsa_url: Option<&str>,
    tsa_policy: Option<&str>,
    tsa_timeout_secs: u64,
) -> Result<Vec<u8>> {
    if target == CADESCOM_BES {
        return Ok(der.to_vec());
    }

    let need_ts = matches!(target, CADESCOM_T | CADESCOM_XLT1 | CADESCOM_A);
    let tsa = if need_ts {
        tsa_url
            .map(|s| s.to_string())
            .context("CAdES-T/XLT1/A requires TSAAddress or config tsa")?
    } else {
        String::new()
    };

    let mut der = der.to_vec();
    let parsed0 = cades::parse(&der)?;
    if need_ts && parsed0.signature_timestamp_token.is_none() {
        let digest_oid = if curve_bytes == 32 {
            cades::OID_DIGEST_256
        } else {
            cades::OID_DIGEST_512
        };
        // Prefer digest OID already in CMS when enhancing an existing signature.
        let digest_oid = if !parsed0.digest_oid.is_empty() {
            parsed0.digest_oid.as_str()
        } else {
            digest_oid
        };
        let ts = timestamp::request_timestamp(
            &tsa,
            signature,
            digest_oid,
            tsa_policy,
            tsa_timeout_secs,
        )?;
        der = cades::add_signature_timestamp(&der, &ts.token)?;
    }

    if matches!(target, CADESCOM_XLT1 | CADESCOM_A) {
        let already = xlong::inspect_presence(&der)
            .map(|p| p.is_x_long_type_1())
            .unwrap_or(false);
        if !already {
            let parsed = cades::parse(&der)?;
            let inner_ts = parsed
                .signature_timestamp_token
                .as_deref()
                .context("CAdES-XLT1 requires a signature timestamp")?;
            let inner_info = timestamp::token_matches_signature(inner_ts, &parsed.signature)?;
            let inner_ts_unix = x509::generalized_time_to_unix(&inner_info.gen_time)?;
            let material = validation::collect(
                &parsed.certificate,
                Vec::new(),
                Vec::new(),
                None,
                None,
                true,
                tsa_timeout_secs.max(20),
                inner_ts_unix,
            )?;
            let enhanced = xlong::enhance_x_long_type_1(
                &der,
                &material,
                &tsa,
                tsa_policy,
                tsa_timeout_secs,
                tsa_timeout_secs.max(20),
            )?;
            der = enhanced.der;
        }
    }

    if target == CADESCOM_A {
        let parsed_for_digest = if detached && content.is_empty() {
            Some(cades::parse(&der)?)
        } else {
            None
        };
        let external = if !detached {
            None
        } else if !content.is_empty() {
            Some(archive::ExternalData::Content(content))
        } else {
            Some(archive::ExternalData::Digest(
                &parsed_for_digest
                    .as_ref()
                    .expect("digest path")
                    .message_digest,
            ))
        };
        let archived = archive::add_archive_timestamp_v3(
            &der,
            external,
            &tsa,
            tsa_policy,
            tsa_timeout_secs,
            tsa_timeout_secs.max(20),
        )?;
        der = archived.der;
    }

    Ok(der)
}

fn profile_to_cadescom(p: verification::CadesProfile) -> u32 {
    match p {
        verification::CadesProfile::Bes => CADESCOM_BES,
        verification::CadesProfile::T => CADESCOM_T,
        verification::CadesProfile::XLongType1 => CADESCOM_XLT1,
        verification::CadesProfile::A => CADESCOM_A,
    }
}

/// ETSI / CryptoPro archive timestamp attribute OIDs that mean CAdES-A.
const OID_ARCHIVE_TIMESTAMP_V2: &str = "1.2.840.113549.1.9.16.2.48";
const OID_ARCHIVE_TIMESTAMP_V1: &str = "1.2.840.113549.1.9.16.2.27";

/// CryptoPro GetMsgType: maximum CADESCOM type the CMS satisfies
/// (A → XLT1 → T → BES → PKCS7), based on unsigned/signed attribute OIDs.
fn detect_profile_from_attrs(der: &[u8]) -> Result<verification::CadesProfile> {
    // Prefer structured walk; fall back to raw OID scan if unsigned-attrs parse fails.
    let mut presence = xlong::XLongPresence::default();
    let mut archive = archive::archive_timestamp_v3_count(der).unwrap_or(0);
    match xlong::inspect_presence(der) {
        Ok(p) => presence = p,
        Err(_) => {}
    }
    let scanned = scan_cades_oids(der);
    if scanned.archive {
        archive = archive.max(1);
    }
    presence.signature_timestamp |= scanned.signature_timestamp;
    presence.certificate_refs |= scanned.certificate_refs;
    presence.revocation_refs |= scanned.revocation_refs;
    presence.certificate_values |= scanned.certificate_values;
    presence.revocation_values |= scanned.revocation_values;
    presence.esc_timestamp |= scanned.esc_timestamp;

    if archive > 0 {
        return Ok(verification::CadesProfile::A);
    }
    if presence.is_x_long_type_1() {
        return Ok(verification::CadesProfile::XLongType1);
    }
    // Partial X-Long (refs without C-timestamp) is still at least T if .14 is present.
    if presence.signature_timestamp {
        return Ok(verification::CadesProfile::T);
    }
    match cades::parse(der) {
        Ok(parsed) => {
            if parsed.signature_timestamp_token.is_some() {
                return Ok(verification::CadesProfile::T);
            }
            if parsed.signing_certificate_v2.is_some() {
                return Ok(verification::CadesProfile::Bes);
            }
            // SignedAttrs present but no ESS signing-certificate* → treat as BES if we got here
            // only when parse succeeded (parse requires signedAttrs). Still BES-shaped CMS.
            Ok(verification::CadesProfile::Bes)
        }
        Err(_) => {
            // No CAdES signedAttrs — PKCS7; caller maps via get_msg_type_value.
            bail!("pkcs7")
        }
    }
}

fn get_msg_type_value(der: &[u8]) -> Result<u32> {
    match detect_profile_from_attrs(der) {
        Ok(p) => Ok(profile_to_cadescom(p)),
        Err(e) if e.to_string() == "pkcs7" => Ok(CADESCOM_PKCS7),
        Err(e) => Err(e),
    }
}

#[derive(Default)]
struct ScannedOids {
    archive: bool,
    signature_timestamp: bool,
    certificate_refs: bool,
    revocation_refs: bool,
    certificate_values: bool,
    revocation_values: bool,
    esc_timestamp: bool,
}

fn scan_cades_oids(der: &[u8]) -> ScannedOids {
    let mut out = ScannedOids::default();
    let mut i = 0usize;
    while i + 2 < der.len() {
        if der[i] != 0x06 {
            i += 1;
            continue;
        }
        let len = der[i + 1] as usize;
        if len > 32 || i + 2 + len > der.len() {
            i += 1;
            continue;
        }
        let body = &der[i + 2..i + 2 + len];
        if let Some(oid) = crate::der::decode_oid(body) {
            match oid.as_str() {
                archive::OID_ARCHIVE_TIMESTAMP_V3
                | OID_ARCHIVE_TIMESTAMP_V2
                | OID_ARCHIVE_TIMESTAMP_V1 => out.archive = true,
                crate::timestamp::OID_SIGNATURE_TIMESTAMP => out.signature_timestamp = true,
                xlong::OID_CERT_REFS => out.certificate_refs = true,
                xlong::OID_REVOCATION_REFS => out.revocation_refs = true,
                xlong::OID_CERT_VALUES => out.certificate_values = true,
                xlong::OID_REVOCATION_VALUES => out.revocation_values = true,
                xlong::OID_ESC_TIMESTAMP => out.esc_timestamp = true,
                _ => {}
            }
        }
        i += 2 + len;
    }
    out
}

fn profile_rank(p: verification::CadesProfile) -> u8 {
    match p {
        verification::CadesProfile::Bes => 1,
        verification::CadesProfile::T => 2,
        verification::CadesProfile::XLongType1 => 3,
        verification::CadesProfile::A => 4,
    }
}

fn requested_rank(ty: u32) -> Option<u8> {
    match ty {
        0 | CADESCOM_BES | CADESCOM_PKCS7 => Some(1),
        CADESCOM_T => Some(2),
        CADESCOM_XLT1 => Some(3),
        CADESCOM_A => Some(4),
        _ => None,
    }
}

/// CryptoPro fails VerifyCades when the CMS lacks attributes required by `requested`.
/// Use CRYPT_E_ATTRIBUTES_MISSING (0x8009100F) so AUTO mode can step down the type.
fn enforce_cades_type(requested: u32, report: &verification::LocalVerification, der: &[u8]) -> Result<()> {
    if !report.base_valid() {
        bail!(
            "0x80091004 The signature did not verify (messageDigest/signature/timestamp check failed)"
        );
    }
    if report.partial_xlong {
        bail!("0x8009100F Incomplete CAdES-X Long Type 1 attribute set");
    }
    let Some(need) = requested_rank(requested) else {
        bail!("0x80070057 Unsupported CAdES type 0x{requested:x}");
    };
    // Prefer the stronger of analyze() vs attribute scan (GetMsgType rules).
    let mut have = profile_rank(report.profile);
    if let Ok(p) = detect_profile_from_attrs(der) {
        have = have.max(profile_rank(p));
    }
    if let Ok(v) = get_msg_type_value(der) {
        if v == CADESCOM_PKCS7 {
            // PKCS7 is the weakest; only matters when requested is PKCS7.
            have = have.max(1);
        }
    }

    // Verifying as a weaker profile against a stronger CMS is allowed (BES ⊂ T ⊂ XLT1 ⊂ A).
    // Verifying as a stronger profile than present must fail.
    if have < need {
        let missing = match requested {
            CADESCOM_T => "signatureTimeStampToken",
            CADESCOM_XLT1 => "CAdES-X Long Type 1 attributes (.21-.25)",
            CADESCOM_A => "archive-time-stamp-v3",
            _ => "required CAdES attributes",
        };
        bail!(
            "0x8009100F Missing {missing} for requested type 0x{requested:x} (present rank {have})"
        );
    }

    // For XLT1/A requests, also require local profile conformance when markers claim that level.
    if need >= 3 {
        if let Some(audit) = &report.xlong_audit {
            if !audit.is_conformant() {
                bail!("0x8009100F CAdES-X Long Type 1 structure is not conformant");
            }
        } else if have >= 3 && report.xlong_audit.is_none() && need >= 3 {
            // Attribute scan says XLT1+ but analyze did not build an audit — still allow
            // if base crypto is fine and markers are present (GetMsgType-compatible).
        }
    }
    if need >= 4 {
        match &report.archive_audit {
            Some(a) if a.is_conformant() => {}
            Some(_) => bail!("0x8009100F CAdES-A archive timestamp audit failed"),
            None => {
                // Attribute scan found archive OID; analyze may lack audit if only v2 OID.
                if get_msg_type_value(der)? != CADESCOM_A {
                    bail!("0x8009100F Missing archive-time-stamp-v3");
                }
            }
        }
    }
    Ok(())
}

fn decode_cms_b64(b64: &str) -> Result<Vec<u8>> {
    STANDARD.decode(b64.as_bytes()).or_else(|_| {
        let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        STANDARD
            .decode(cleaned.as_bytes())
            .context("signature base64")
    })
}

fn empty_cert_view() -> CertView {
    CertView {
        subject_name: String::new(),
        issuer_name: String::new(),
        serial_hex: String::new(),
        thumbprint: String::new(),
        not_before_unix: 0,
        not_after_unix: 0,
        cert_der: Vec::new(),
        key_index: None,
        token_idx: None,
    }
}

fn decode_cert_import(data: &str) -> Result<Vec<u8>> {
    let trimmed = data.trim();
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(der) = STANDARD.decode(compact.as_bytes()) {
        if !der.is_empty() {
            return Ok(der);
        }
    }
    if !trimmed.is_empty() {
        return Ok(trimmed.as_bytes().to_vec());
    }
    bail!("empty certificate import data");
}

fn nmcades_hash(algorithm: u32, data_encoding: u32, data: &str) -> Result<Vec<u8>> {
    let bytes = match data_encoding {
        CADESCOM_BASE64_TO_BINARY => STANDARD
            .decode(data.as_bytes())
            .unwrap_or_else(|_| data.as_bytes().to_vec()),
        CADESCOM_STRING_TO_UCS2LE => {
            let mut out = Vec::with_capacity(data.len() * 2);
            for u in data.encode_utf16() {
                out.extend_from_slice(&u.to_le_bytes());
            }
            out
        }
        other => bail!("unsupported HashedData ContentEncoding {other}"),
    };
    let digest_bytes = match algorithm {
        100 | 101 => 32,
        102 => 64,
        other => bail!("unsupported hash algorithm {other}"),
    };
    cades::digest_data(digest_bytes, &bytes)
}

fn decode_hash_hex(hex_str: &str) -> Result<Vec<u8>> {
    let cleaned = hex_str.replace([' ', '\t'], "");
    hex::decode(&cleaned).context("hash hex")
}

fn object_retval(id: u32, props: &[&str], methods: &[&str]) -> Value {
    json!({
        "type": "object",
        "value": id,
        "properties": props,
        "methods": methods,
    })
}

fn trusted_sites_path() -> Option<PathBuf> {
    let mut p = dirs::cache_dir()?;
    p.push("jex");
    p.push("trusted-sites.json");
    Some(p)
}

fn origin_from_url(url: &str) -> String {
    let url = url.trim();
    if url.is_empty() {
        return String::new();
    }
    // Prefer scheme://host[:port]
    if let Some(rest) = url.split("://").nth(1) {
        let hostport = rest.split('/').next().unwrap_or(rest);
        let scheme = url.split("://").next().unwrap_or("");
        if !scheme.is_empty() && !hostport.is_empty() {
            return format!("{scheme}://{hostport}");
        }
    }
    url.to_string()
}

fn origins_match(stored: &str, origin: &str) -> bool {
    let a = stored.trim().trim_end_matches('/');
    let b = origin.trim().trim_end_matches('/');
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    // Allow stored="https://example.com" to match, and simple "*.example.com" host suffix.
    if let Some(rest) = a.strip_prefix("https://*.") {
        return b.to_ascii_lowercase().ends_with(&format!(".{rest}"))
            || b.eq_ignore_ascii_case(&format!("https://{rest}"));
    }
    if let Some(rest) = a.strip_prefix("http://*.") {
        return b.to_ascii_lowercase().ends_with(&format!(".{rest}"))
            || b.eq_ignore_ascii_case(&format!("http://{rest}"));
    }
    false
}

fn load_optional_pin(
    pin: Option<&str>,
    pin_file: Option<&PathBuf>,
    base: &Path,
) -> Option<Vec<u8>> {
    if let Some(p) = pin {
        let b = p.as_bytes();
        return Some(if b.is_empty() {
            DEFAULT_PIN.to_vec()
        } else {
            b.to_vec()
        });
    }
    let Some(path) = pin_file else {
        return Some(DEFAULT_PIN.to_vec());
    };
    let path = if path.is_absolute() {
        path.clone()
    } else {
        base.join(path)
    };
    let mut raw = match std::fs::read(&path) {
        Ok(r) => r,
        Err(_) => return Some(DEFAULT_PIN.to_vec()),
    };
    while raw.last().copied() == Some(b'\n') || raw.last().copied() == Some(b'\r') {
        raw.pop();
    }
    if raw.is_empty() {
        Some(DEFAULT_PIN.to_vec())
    } else {
        Some(raw)
    }
}

/// CryptoPro container passwords to try for classic unlock.
///
/// Order: explicit `KeyPin` (if any), empty (common on Rutoken classic),
/// DEFAULT_PIN, then configured token CHV. Token CHV and container password
/// are different secrets; demos often pass the CHV as KeyPin by mistake.
fn container_pin_candidates(key_pin: Option<&str>, token_pin: Option<&[u8]>) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let push_unique = |out: &mut Vec<Vec<u8>>, pin: &[u8]| {
        if !out.iter().any(|e| e.as_slice() == pin) {
            out.push(pin.to_vec());
        }
    };
    if let Some(p) = key_pin {
        push_unique(&mut out, p.as_bytes());
    }
    push_unique(&mut out, b"");
    push_unique(&mut out, DEFAULT_PIN);
    if let Some(tp) = token_pin {
        push_unique(&mut out, tp);
    }
    out
}

fn load_trusted_sites() -> Vec<String> {
    let Some(path) = trusted_sites_path() else {
        return Vec::new();
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    serde_json::from_str::<Vec<String>>(&raw).unwrap_or_default()
}

fn save_trusted_sites(sites: &[String]) -> Result<()> {
    let path = trusted_sites_path().context("no cache dir for trusted sites")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create jex cache dir")?;
    }
    let raw = serde_json::to_string_pretty(sites).context("serialize trusted sites")?;
    std::fs::write(&path, raw).context("write trusted-sites.json")?;
    Ok(())
}

fn algo_for_curve(curve_bytes: usize) -> (&'static str, &'static str) {
    if curve_bytes >= 64 {
        (cades::OID_SIGN_512, "ГОСТ Р 34.10-2012 512 бит")
    } else {
        (cades::OID_SIGN_256, "ГОСТ Р 34.10-2012 256 бит")
    }
}

fn param_string(params: &Value, idx: usize) -> Option<String> {
    let a = params.as_array()?;
    let p = a.get(idx)?;
    value_as_string(p).ok()
}

fn param_u32(params: &Value, idx: usize) -> Option<u32> {
    let a = params.as_array()?;
    let p = a.get(idx)?;
    value_as_u32(p).ok()
}

fn param_bool(params: &Value, idx: usize) -> Option<bool> {
    let a = params.as_array()?;
    let p = a.get(idx)?;
    value_as_bool(p).ok()
}

fn param_object_id(params: &Value, idx: usize) -> Option<u32> {
    let a = params.as_array()?;
    let p = a.get(idx)?;
    if p.get("type").and_then(|t| t.as_str()) == Some("object") {
        return p.get("value").and_then(|v| v.as_u64()).map(|v| v as u32);
    }
    p.as_u64().map(|v| v as u32)
}

fn value_as_string(v: &Value) -> Result<String> {
    if let Some(s) = v.get("value").and_then(|x| x.as_str()) {
        return Ok(s.to_string());
    }
    if let Some(s) = v.as_str() {
        return Ok(s.to_string());
    }
    bail!("expected string param, got {v}");
}

fn value_as_attr_value(v: &Value) -> Result<String> {
    // Dates often arrive as ISO strings; unix ms as numbers.
    if let Some(n) = v.get("value").and_then(|x| x.as_u64()) {
        return Ok(n.to_string());
    }
    if let Some(n) = v.get("value").and_then(|x| x.as_i64()) {
        return Ok(n.to_string());
    }
    if let Some(n) = v.as_u64() {
        return Ok(n.to_string());
    }
    if let Some(n) = v.as_i64() {
        return Ok(n.to_string());
    }
    value_as_string(v)
}

fn value_as_i32(v: &Value) -> Result<i32> {
    if let Some(n) = v.get("value").and_then(|x| x.as_i64()) {
        return Ok(n as i32);
    }
    if let Some(n) = v.get("value").and_then(|x| x.as_u64()) {
        return Ok(n as i32);
    }
    if let Some(n) = v.as_i64() {
        return Ok(n as i32);
    }
    if let Some(n) = v.as_u64() {
        return Ok(n as i32);
    }
    if let Some(s) = v.get("value").and_then(|x| x.as_str()) {
        return Ok(s.parse()?);
    }
    bail!("expected integer param, got {v}");
}

fn value_as_u32(v: &Value) -> Result<u32> {
    if let Some(n) = v.get("value").and_then(|x| x.as_u64()) {
        return Ok(n as u32);
    }
    if let Some(n) = v.as_u64() {
        return Ok(n as u32);
    }
    if let Some(n) = v.get("value").and_then(|x| x.as_f64()) {
        return Ok(n as u32);
    }
    if let Some(n) = v.as_f64() {
        return Ok(n as u32);
    }
    if let Some(s) = v.get("value").and_then(|x| x.as_str()) {
        return Ok(s.parse()?);
    }
    bail!("expected number param, got {v}");
}

fn value_as_f64(v: &Value) -> Result<f64> {
    if let Some(n) = v.get("value").and_then(|x| x.as_f64()) {
        return Ok(n);
    }
    if let Some(n) = v.as_f64() {
        return Ok(n);
    }
    if let Some(n) = v.get("value").and_then(|x| x.as_u64()) {
        return Ok(n as f64);
    }
    if let Some(n) = v.as_u64() {
        return Ok(n as f64);
    }
    if let Some(s) = v.get("value").and_then(|x| x.as_str()) {
        return Ok(s.parse()?);
    }
    bail!("expected number param, got {v}");
}

fn value_as_bool(v: &Value) -> Result<bool> {
    if let Some(b) = v.get("value").and_then(|x| x.as_bool()) {
        return Ok(b);
    }
    if let Some(b) = v.as_bool() {
        return Ok(b);
    }
    // Chrome / plugin sometimes send 0/1.
    if let Some(n) = v.get("value").and_then(|x| x.as_u64()) {
        return Ok(n != 0);
    }
    if let Some(n) = v.as_u64() {
        return Ok(n != 0);
    }
    if let Some(s) = v.get("value").and_then(|x| x.as_str()) {
        return match s.to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => bail!("expected boolean param, got {v}"),
        };
    }
    bail!("expected boolean param, got {v}");
}

fn format_dn_capicom(attrs: &[x509::NameAttr]) -> String {
    attrs
        .iter()
        .map(|a| format!("{}={}", a.label, a.value))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Same shape as CryptoPro extension `DateToUTCStr` (parsed by `new Date(...)` in page JS).
fn unix_to_cades_utc(unix: i64) -> String {
    let secs = unix.max(0) as u64;
    let days = secs / 86_400;
    let rem = (secs % 86_400) as u32;
    let h = rem / 3600;
    let mi = (rem % 3600) / 60;
    let s = rem % 60;
    // Howard Hinnant civil_from_days
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.000Z")
}

fn resolve_path(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

fn read_message(stdin: &mut impl Read) -> Result<Option<Value>> {
    let mut header = [0u8; 4];
    match stdin.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(header) as usize;
    if len > 64 * 1024 * 1024 {
        bail!("native-messaging frame too large: {len}");
    }
    let mut buf = vec![0u8; len];
    stdin.read_exact(&mut buf)?;
    let v: Value = serde_json::from_slice(&buf).context("parse NMH JSON")?;
    Ok(Some(v))
}

fn write_message(stdout: &mut impl Write, envelope: &Value) -> Result<()> {
    let payload = serde_json::to_vec(envelope)?;
    let len = (payload.len() as u32).to_le_bytes();
    stdout.write_all(&len)?;
    stdout.write_all(&payload)?;
    stdout.flush()?;
    Ok(())
}

/// Run until stdin EOF (Chrome/Firefox NMH), or serve HTTP if `http_listen` is set.
pub fn run(opts: NmcadesHostOptions) -> Result<()> {
    if let Some(addr) = opts.http_listen.clone() {
        return run_http(opts, &addr);
    }
    let mut host = Host::from_config(&opts)?;
    eprintln!(
        "jex nmcades-host: {} key(s) from {}",
        host.keys.len(),
        opts.config_path.display()
    );

    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    while let Some(envelope) = read_message(&mut stdin)? {
        let tabid = envelope.get("tabid").cloned().unwrap_or(Value::Null);
        let data = envelope
            .get("data")
            .cloned()
            .unwrap_or(Value::Null);
        let reply_data = host.handle_data(&data);
        let out = json!({ "tabid": tabid, "data": reply_data });
        write_message(&mut stdout, &out)?;
    }
    Ok(())
}

/// Localhost HTTP bridge for Safari (avoids flaky connectNative + UUID churn).
fn run_http(opts: NmcadesHostOptions, listen: &str) -> Result<()> {
    let host = Arc::new(Mutex::new(Host::from_config(&opts)?));
    {
        let h = host.lock().unwrap();
        eprintln!(
            "jex nmcades-host HTTP on http://{} ({} key(s) from {})",
            listen,
            h.keys.len(),
            opts.config_path.display()
        );
    }
    let server = tiny_http::Server::http(listen)
        .map_err(|e| anyhow::anyhow!("bind nmcades HTTP {listen}: {e}"))?;

    for request in server.incoming_requests() {
        if let Err(e) = handle_http_request(Arc::clone(&host), request) {
            eprintln!("nmcades HTTP error: {e:#}");
        }
    }
    Ok(())
}

fn handle_http_request(host: Arc<Mutex<Host>>, mut request: tiny_http::Request) -> Result<()> {
    let cors = tiny_http::Header::from_bytes(
        &b"Access-Control-Allow-Origin"[..],
        &b"*"[..],
    )
    .unwrap();
    let cors_methods = tiny_http::Header::from_bytes(
        &b"Access-Control-Allow-Methods"[..],
        &b"POST, OPTIONS"[..],
    )
    .unwrap();
    let cors_headers = tiny_http::Header::from_bytes(
        &b"Access-Control-Allow-Headers"[..],
        &b"Content-Type"[..],
    )
    .unwrap();

    let method = request.method().clone();

    if method == tiny_http::Method::Options {
        let response = tiny_http::Response::empty(204)
            .with_header(cors)
            .with_header(cors_methods)
            .with_header(cors_headers);
        request.respond(response)?;
        return Ok(());
    }

    if method == tiny_http::Method::Get {
        let response = tiny_http::Response::from_string("jex nmcades-host ok\n")
            .with_header(cors)
            .with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/plain"[..]).unwrap(),
            );
        request.respond(response)?;
        return Ok(());
    }

    if method != tiny_http::Method::Post {
        let response = tiny_http::Response::from_string("POST JSON {tabid,data}\n")
            .with_status_code(405)
            .with_header(cors);
        request.respond(response)?;
        return Ok(());
    }

    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body)?;
    let envelope: Value = serde_json::from_slice(&body).context("parse HTTP JSON")?;
    let tabid = envelope.get("tabid").cloned().unwrap_or(Value::Null);
    let data = envelope
        .get("data")
        .cloned()
        .unwrap_or(Value::Null);
    let reply_data = host
        .lock()
        .map_err(|_| anyhow::anyhow!("host lock poisoned"))?
        .handle_data(&data);
    let out = json!({ "tabid": tabid, "data": reply_data });
    let raw = serde_json::to_vec(&out)?;
    let response = tiny_http::Response::from_data(raw)
        .with_header(cors)
        .with_header(cors_methods)
        .with_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        );
    request.respond(response)?;
    Ok(())
}
