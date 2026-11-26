// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
//! Signing daemon: unlock classic containers once and serve CAdES over HTTP.
//!
//! URL namespaces:
//! - `/api/v1/*` — first-party web API (+ `GET /jex.js`)
//! - `/v1/*` — legacy general HTTP API (do not extend)
//! - `/nmcades/*` — CryptoPro Browser plug-in shim (`cadesplugin_api.js`, frozen)
//!
//! Access is gated by API keys. Each API key whitelists which signing `key_id`s
//! it may list and use.

mod api_v1;

use crate::{
    archive, cades, container::ClassicContainer, curves, timestamp, validation, verification,
    x509, xlong, xmldsig,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use subtle::ConstantTimeEq;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use zeroize::Zeroize;

const CADESPLUGIN_API_JS: &str = include_str!("../cadesplugin_api.js");
const JEX_API_JS: &str = include_str!("../jex.js");

/// CADESCOM_CADES_* type constants from the Browser plug-in.
const CADES_BES: u32 = 1;
const CADES_T: u32 = 0x5;
const CADES_XLT1: u32 = 0x5d;
const CADES_A: u32 = 0xdd;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DaemonConfigFile {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub tsa: Option<String>,
    #[serde(default = "default_tsa_timeout")]
    pub tsa_timeout_secs: u64,
    pub tsa_policy: Option<String>,
    /// Optional PC/SC token PIN for nmcades-host Rutoken unlock.
    pub token_pin: Option<String>,
    pub token_pin_file: Option<PathBuf>,
    pub keys: Vec<KeyConfig>,
    pub api_keys: Vec<ApiKeyConfig>,
}

fn default_listen() -> String {
    "127.0.0.1:8787".to_string()
}

fn default_tsa_timeout() -> u64 {
    20
}

#[derive(Debug, Deserialize)]
pub struct KeyConfig {
    pub id: String,
    pub container_dir: PathBuf,
    pub pin_file: Option<PathBuf>,
    pub pin: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApiKeyConfig {
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
    /// Browser Origins allowed to use this API key without a Bearer token
    /// (CryptoPro plugin compatibility / CORS).
    #[serde(default)]
    pub origins: Vec<String>,
    pub allow: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DaemonOptions {
    pub config_path: PathBuf,
    pub listen_override: Option<String>,
}

pub fn load_config(path: &Path) -> Result<DaemonConfigFile> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read daemon config {}", path.display()))?;
    let cfg: DaemonConfigFile = serde_json::from_str(&raw)
        .with_context(|| format!("parse daemon config {}", path.display()))?;
    if cfg.keys.is_empty() {
        bail!("daemon config must declare at least one key under \"keys\"");
    }
    if cfg.api_keys.is_empty() {
        bail!("daemon config must declare at least one API key under \"api_keys\"");
    }
    let mut seen = HashSet::new();
    for k in &cfg.keys {
        if k.id.is_empty() {
            bail!("key id must not be empty");
        }
        if k.id == "*" {
            bail!("key id \"*\" is reserved");
        }
        if !seen.insert(k.id.clone()) {
            bail!("duplicate key id {:?}", k.id);
        }
        if k.pin.is_none() && k.pin_file.is_none() {
            bail!("key {:?} needs pin or pin_file", k.id);
        }
    }
    for (i, ak) in cfg.api_keys.iter().enumerate() {
        let has_token = ak.token.is_some() || ak.token_file.is_some();
        if !has_token && ak.origins.is_empty() {
            bail!("api_keys[{i}] needs token/token_file and/or origins");
        }
        if ak.allow.is_empty() {
            bail!("api_keys[{i}] allow list is empty");
        }
        let allow_all = ak.allow.iter().any(|a| a == "*");
        if !allow_all {
            for id in &ak.allow {
                if !seen.contains(id) {
                    bail!("api_keys[{i}] allow references unknown key id {id:?}");
                }
            }
        }
        for origin in &ak.origins {
            if origin.is_empty() {
                bail!("api_keys[{i}] has empty origin");
            }
        }
    }
    Ok(cfg)
}

fn read_secret_file(path: &Path, what: &str) -> Result<Vec<u8>> {
    let mut data = fs::read(path).with_context(|| format!("read {what} {}", path.display()))?;
    while data.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        data.pop();
    }
    Ok(data)
}

fn read_pin(cfg: &KeyConfig) -> Result<Vec<u8>> {
    if let Some(pin) = &cfg.pin {
        return Ok(pin.as_bytes().to_vec());
    }
    read_secret_file(cfg.pin_file.as_ref().expect("validated"), "container PIN")
}

fn read_api_token(cfg: &ApiKeyConfig) -> Result<Option<Vec<u8>>> {
    if let Some(token) = &cfg.token {
        return Ok(Some(token.as_bytes().to_vec()));
    }
    if let Some(path) = &cfg.token_file {
        return Ok(Some(read_secret_file(path, "API token")?));
    }
    Ok(None)
}

fn is_loopback_listen(listen: &str) -> Result<bool> {
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("parse listen address {listen:?}"))?;
    Ok(addr.ip().is_loopback())
}

// ---------------------------------------------------------------------------
// Key store + ACL
// ---------------------------------------------------------------------------

struct LoadedKey {
    id: String,
    cert_der: Vec<u8>,
    curve: curves::Curve,
    private_le: Vec<u8>,
    public_x_le: Vec<u8>,
    public_y_le: Vec<u8>,
    subject: String,
    subject_name: String,
    issuer: String,
    issuer_name: String,
    serial_hex: String,
    thumbprint: String,
    not_before: String,
    not_after: String,
    not_before_unix: i64,
    not_after_unix: i64,
}

impl Drop for LoadedKey {
    fn drop(&mut self) {
        self.private_le.zeroize();
    }
}

pub struct KeyStore {
    keys: HashMap<String, LoadedKey>,
}

impl KeyStore {
    pub fn load(cfgs: &[KeyConfig]) -> Result<Self> {
        let mut keys = HashMap::new();
        for cfg in cfgs {
            let c = ClassicContainer::open(&cfg.container_dir)
                .with_context(|| format!("open container for key {:?}", cfg.id))?;
            let cert = c.certificate.as_deref().context(format!(
                "key {:?}: header.key has no parseable X.509 certificate",
                cfg.id
            ))?;
            let validity = x509::validity(cert).context("decode signer certificate validity")?;
            let identity = x509::identity(cert).context("decode signer certificate identity")?;
            let subject_attrs = x509::subject_name_attributes(cert).unwrap_or_default();
            let issuer_attrs = x509::issuer_name_attributes(cert).unwrap_or_default();
            let subject =
                x509::display_name_from_attrs(&subject_attrs).unwrap_or_else(|| "<unknown>".into());
            let issuer =
                x509::display_name_from_attrs(&issuer_attrs).unwrap_or_else(|| "<unknown>".into());
            let subject_name = format_dn(&subject_attrs);
            let issuer_name = format_dn(&issuer_attrs);
            let serial_hex = serial_to_hex(&identity.serial_der)?;
            let thumbprint = cert_thumbprint_sha1(cert);

            let mut pin = read_pin(cfg)?;
            let unlocked = c.unlock(&pin);
            pin.zeroize();
            let mut unlocked = unlocked.with_context(|| format!("unlock key {:?}", cfg.id))?;

            let loaded = LoadedKey {
                id: cfg.id.clone(),
                cert_der: cert.to_vec(),
                curve: c.curve.clone(),
                private_le: std::mem::take(&mut unlocked.private_le),
                public_x_le: unlocked.public_x_le.clone(),
                public_y_le: unlocked.public_y_le.clone(),
                subject,
                subject_name,
                issuer,
                issuer_name,
                serial_hex,
                thumbprint,
                not_before: validity.not_before,
                not_after: validity.not_after,
                not_before_unix: validity.not_before_unix,
                not_after_unix: validity.not_after_unix,
            };
            unlocked.private_le.zeroize();
            keys.insert(cfg.id.clone(), loaded);
        }
        Ok(Self { keys })
    }

    fn get(&self, id: &str) -> Option<&LoadedKey> {
        self.keys.get(id)
    }

    fn by_thumbprint(&self, thumbprint: &str) -> Option<&LoadedKey> {
        let want = normalize_thumbprint(thumbprint);
        self.keys.values().find(|k| k.thumbprint == want)
    }

    fn ids(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(|s| s.as_str())
    }
}

struct ApiKeyEntry {
    token: Vec<u8>,
    origins: Vec<String>,
    allow_all: bool,
    allow: HashSet<String>,
}

impl Drop for ApiKeyEntry {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

pub struct ApiAcl {
    entries: Vec<ApiKeyEntry>,
}

impl ApiAcl {
    pub fn from_config(cfgs: &[ApiKeyConfig]) -> Result<Self> {
        let mut entries = Vec::with_capacity(cfgs.len());
        let mut seen_origins = HashSet::new();
        for cfg in cfgs {
            let token = match read_api_token(cfg)? {
                Some(mut t) if t.is_empty() => {
                    t.zeroize();
                    bail!("API token must not be empty");
                }
                Some(t) => t,
                None => Vec::new(),
            };
            let allow_all = cfg.allow.iter().any(|a| a == "*");
            let allow: HashSet<String> = cfg
                .allow
                .iter()
                .filter(|a| a.as_str() != "*")
                .cloned()
                .collect();
            let mut origins = Vec::new();
            for o in &cfg.origins {
                let norm = normalize_origin(o);
                if !seen_origins.insert(norm.clone()) {
                    bail!("duplicate origin {norm:?} in api_keys");
                }
                origins.push(norm);
            }
            entries.push(ApiKeyEntry {
                token,
                origins,
                allow_all,
                allow,
            });
        }
        for i in 0..entries.len() {
            if entries[i].token.is_empty() {
                continue;
            }
            for j in (i + 1)..entries.len() {
                if entries[j].token.is_empty() {
                    continue;
                }
                if token_eq(&entries[i].token, &entries[j].token) {
                    bail!("duplicate API tokens in config");
                }
            }
        }
        Ok(Self { entries })
    }

    fn resolve(&self, bearer: &[u8]) -> Option<&ApiKeyEntry> {
        self.entries
            .iter()
            .find(|e| !e.token.is_empty() && token_eq(&e.token, bearer))
    }

    fn resolve_origin(&self, origin: &str) -> Option<&ApiKeyEntry> {
        let norm = normalize_origin(origin);
        self.entries
            .iter()
            .find(|e| e.origins.iter().any(|o| o == &norm))
    }

    fn all_origins(&self) -> Vec<String> {
        let mut out = Vec::new();
        for e in &self.entries {
            out.extend(e.origins.iter().cloned());
        }
        out.sort();
        out.dedup();
        out
    }

    fn visible_ids<'a>(&'a self, entry: &'a ApiKeyEntry, store: &'a KeyStore) -> Vec<&'a str> {
        if entry.allow_all {
            let mut ids: Vec<&str> = store.ids().collect();
            ids.sort_unstable();
            ids
        } else {
            let mut ids: Vec<&str> = entry
                .allow
                .iter()
                .filter(|id| store.get(id).is_some())
                .map(|s| s.as_str())
                .collect();
            ids.sort_unstable();
            ids
        }
    }

    fn authorize_key(&self, entry: &ApiKeyEntry, key_id: &str, store: &KeyStore) -> bool {
        if store.get(key_id).is_none() {
            return false;
        }
        entry.allow_all || entry.allow.contains(key_id)
    }
}

fn token_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

fn normalize_origin(origin: &str) -> String {
    origin.trim().trim_end_matches('/').to_string()
}

fn normalize_thumbprint(tp: &str) -> String {
    tp.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn cert_thumbprint_sha1(cert_der: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let digest = Sha1::digest(cert_der);
    hex::encode(digest).to_ascii_uppercase()
}

fn format_dn(attrs: &[x509::NameAttr]) -> String {
    attrs
        .iter()
        .map(|a| format!("{}={}", a.label, a.value))
        .collect::<Vec<_>>()
        .join(", ")
}

fn serial_to_hex(serial_der: &[u8]) -> Result<String> {
    let t = crate::der::parse_tlv(serial_der).context("parse serial INTEGER")?;
    if t.tag != 0x02 {
        bail!("serial is not INTEGER");
    }
    Ok(hex::encode(t.value).to_ascii_uppercase())
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SignRequestJson {
    key_id: Option<String>,
    content_b64: String,
    #[serde(default)]
    attached: bool,
    /// Absent/null → daemon default TSA; `false` → BES only; string → TSA URL.
    #[serde(default)]
    tsa: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct SignResponseJson {
    profile: String,
    signature_b64: String,
    key_id: String,
    content_digest_hex: String,
}

#[derive(Debug, Serialize)]
struct KeyInfoJson {
    id: String,
    subject: String,
    serial_hex: String,
    not_before: String,
    not_after: String,
    curve: String,
}

#[derive(Debug, Serialize)]
struct ErrorJson {
    error: String,
}

struct Runtime {
    store: KeyStore,
    acl: ApiAcl,
    default_tsa: Option<String>,
    tsa_timeout_secs: u64,
    tsa_policy: Option<String>,
}

fn resolve_tsa(
    req: &Option<serde_json::Value>,
    default: &Option<String>,
) -> Result<Option<String>> {
    match req {
        None => Ok(default.clone()),
        Some(serde_json::Value::Null) => Ok(default.clone()),
        Some(serde_json::Value::Bool(false)) => Ok(None),
        Some(serde_json::Value::Bool(true)) => Ok(Some(
            default
                .clone()
                .context("tsa=true but daemon has no default TSA URL")?,
        )),
        Some(serde_json::Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
        Some(serde_json::Value::String(_)) => bail!("tsa URL must not be empty"),
        Some(_) => bail!("tsa must be a URL string, false, or null"),
    }
}

fn sign_with_key(
    rt: &Runtime,
    key: &LoadedKey,
    content: &[u8],
    attached: bool,
    tsa_url: Option<&str>,
) -> Result<SignResponseJson> {
    let cades_type = if tsa_url.is_some() {
        CADES_T
    } else {
        CADES_BES
    };
    sign_with_key_typed(rt, key, content, attached, tsa_url, cades_type)
}

fn sign_with_key_typed(
    rt: &Runtime,
    key: &LoadedKey,
    content: &[u8],
    attached: bool,
    tsa_url: Option<&str>,
    cades_type: u32,
) -> Result<SignResponseJson> {
    sign_with_key_full(rt, key, content, None, attached, tsa_url, cades_type, &[])
}

fn sign_with_key_full(
    rt: &Runtime,
    key: &LoadedKey,
    content: &[u8],
    content_digest: Option<&[u8]>,
    attached: bool,
    tsa_url: Option<&str>,
    cades_type: u32,
    extra_attrs: &[Vec<u8>],
) -> Result<SignResponseJson> {
    let detached = !attached || content_digest.is_some();
    let signed = cades::sign_bes_ex(&cades::SignBesParams {
        content,
        content_digest,
        cert_der: &key.cert_der,
        curve: &key.curve,
        private_le: &key.private_le,
        expected_public_x_le: &key.public_x_le,
        expected_public_y_le: &key.public_y_le,
        detached,
        extra_signed_attrs: extra_attrs,
    })?;

    let cades_type = if cades_type == 0 {
        CADES_BES
    } else {
        cades_type
    };
    if !matches!(cades_type, CADES_BES | CADES_T | CADES_XLT1 | CADES_A) {
        bail!("unsupported CAdES type 0x{cades_type:x}");
    }

    let need_ts = matches!(cades_type, CADES_T | CADES_XLT1 | CADES_A);
    // BES must never hit the TSA even if the daemon has a default `tsa` URL.
    let tsa = if need_ts {
        tsa_url
            .map(|s| s.to_string())
            .or_else(|| rt.default_tsa.clone())
            .context("CAdES-T/XLT1/A requires a TSA URL (signer TSAAddress or daemon tsa)")?
    } else {
        String::new()
    };

    let (mut output_der, mut profile) = if !tsa.is_empty() {
        let digest_oid = if key.curve.bytes == 32 {
            cades::OID_DIGEST_256
        } else {
            cades::OID_DIGEST_512
        };
        let ts = timestamp::request_timestamp(
            &tsa,
            &signed.signature,
            digest_oid,
            rt.tsa_policy.as_deref(),
            rt.tsa_timeout_secs,
        )?;
        let der = cades::add_signature_timestamp(&signed.der, &ts.token)?;
        (der, "CAdES-T".to_string())
    } else {
        (signed.der.clone(), "CAdES-BES".to_string())
    };

    if matches!(cades_type, CADES_XLT1 | CADES_A) {
        if profile != "CAdES-T" {
            bail!("CAdES-X Long Type 1 requires a signature timestamp");
        }
        let parsed = cades::parse(&output_der)?;
        let inner_ts = parsed
            .signature_timestamp_token
            .as_deref()
            .context("missing signature timestamp after T step")?;
        let inner_info = timestamp::token_matches_signature(inner_ts, &parsed.signature)?;
        let inner_ts_unix = x509::generalized_time_to_unix(&inner_info.gen_time)?;
        let material = validation::collect(
            &parsed.certificate,
            Vec::new(),
            Vec::new(),
            None,
            None,
            true,
            rt.tsa_timeout_secs.max(20),
            inner_ts_unix,
        )?;
        let enhanced = xlong::enhance_x_long_type_1(
            &output_der,
            &material,
            &tsa,
            rt.tsa_policy.as_deref(),
            rt.tsa_timeout_secs,
            rt.tsa_timeout_secs.max(20),
        )?;
        output_der = enhanced.der;
        profile = "CAdES-XLT1".to_string();
    }

    if cades_type == CADES_A {
        let external = if detached {
            // Prefer precomputed digest when signing via SignHash (content may be empty).
            if let Some(d) = content_digest {
                Some(archive::ExternalData::Digest(d))
            } else if !content.is_empty() {
                Some(archive::ExternalData::Content(content))
            } else {
                None
            }
        } else {
            None
        };
        let archived = archive::add_archive_timestamp_v3(
            &output_der,
            external,
            &tsa,
            rt.tsa_policy.as_deref(),
            rt.tsa_timeout_secs,
            rt.tsa_timeout_secs.max(20),
        )?;
        output_der = archived.der;
        profile = "CAdES-A".to_string();
    }

    Ok(SignResponseJson {
        profile,
        signature_b64: STANDARD.encode(&output_der),
        key_id: key.id.clone(),
        content_digest_hex: hex::encode(&signed.content_digest),
    })
}

fn pick_key_id(
    entry: &ApiKeyEntry,
    store: &KeyStore,
    requested: Option<&str>,
    acl: &ApiAcl,
) -> Result<String, (u16, String)> {
    let visible = acl.visible_ids(entry, store);
    match requested {
        Some(id) => {
            if !acl.authorize_key(entry, id, store) {
                return Err((403, "forbidden key_id".into()));
            }
            Ok(id.to_string())
        }
        None => match visible.as_slice() {
            [only] => Ok((*only).to_string()),
            [] => Err((403, "no signing keys available for this API key".into())),
            _ => Err((
                400,
                "key_id is required when multiple keys are allowed".into(),
            )),
        },
    }
}

#[derive(Debug, Serialize)]
struct NmcadesCertJson {
    id: String,
    subject: String,
    subject_name: String,
    issuer: String,
    issuer_name: String,
    serial_hex: String,
    thumbprint: String,
    not_before: String,
    not_after: String,
    not_before_unix: i64,
    not_after_unix: i64,
    cert_b64: String,
}

#[derive(Debug, Deserialize)]
struct NmcadesSignRequest {
    thumbprint: Option<String>,
    key_id: Option<String>,
    #[serde(default)]
    content_b64: Option<String>,
    /// Pre-computed digest (hex or base64) for SignHash.
    hash_hex: Option<String>,
    hash_b64: Option<String>,
    #[serde(default)]
    detached: bool,
    #[serde(default = "default_cades_bes")]
    cades_type: u32,
    tsa: Option<String>,
    #[serde(default)]
    attrs: Vec<NmcadesAttr>,
}

#[derive(Debug, Deserialize)]
struct NmcadesAttr {
    name: i32,
    value: String,
}

#[derive(Debug, Deserialize)]
struct NmcadesVerifyRequest {
    signature_b64: String,
    content_b64: Option<String>,
    content_hash_hex: Option<String>,
    content_hash_b64: Option<String>,
    #[serde(default)]
    detached: bool,
}

#[derive(Debug, Deserialize)]
struct NmcadesHashRequest {
    /// 101 = Streebog-256, 102 = Streebog-512 (CADESCOM_HASH_ALGORITHM_*)
    #[serde(default = "default_hash_alg")]
    algorithm: u32,
    data_b64: Option<String>,
    /// When set with CADESCOM_BASE64_TO_BINARY semantics already decoded by client as raw b64 of bytes.
    #[serde(default)]
    data_encoding: u32,
}

fn default_hash_alg() -> u32 {
    101
}

#[derive(Debug, Deserialize)]
struct NmcadesRawSignRequest {
    thumbprint: Option<String>,
    key_id: Option<String>,
    hash_hex: Option<String>,
    hash_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NmcadesRawVerifyRequest {
    thumbprint: Option<String>,
    cert_b64: Option<String>,
    hash_hex: Option<String>,
    hash_b64: Option<String>,
    signature_b64: String,
}

#[derive(Debug, Deserialize)]
struct NmcadesEnhanceRequest {
    signature_b64: String,
    content_b64: Option<String>,
    /// Digest of detached content (hex), alternative to content_b64 for CAdES-A.
    content_hash_hex: Option<String>,
    content_hash_b64: Option<String>,
    #[serde(default = "default_cades_xlt1")]
    cades_type: u32,
    tsa: Option<String>,
}

/// General `/v1/enhance` body — profile names, not CADESCOM integers.
#[derive(Debug, Deserialize)]
struct EnhanceRequest {
    signature_b64: String,
    content_b64: Option<String>,
    content_hash_hex: Option<String>,
    content_hash_b64: Option<String>,
    /// Target: `t` | `xlt1` | `a` (aliases: `cades-t`, `xlong`, `archive`, …). Default `xlt1`.
    #[serde(default = "default_enhance_profile")]
    profile: String,
    tsa: Option<String>,
}

fn default_enhance_profile() -> String {
    "xlt1".into()
}

#[derive(Debug, Deserialize)]
struct AttachRequest {
    signature_b64: String,
    content_b64: String,
}

#[derive(Debug, Deserialize)]
struct DetachRequest {
    signature_b64: String,
}

#[derive(Debug, Deserialize)]
struct NmcadesXmlSignRequest {
    content: String,
    thumbprint: Option<String>,
    key_id: Option<String>,
    /// 0 enveloped, 1 enveloping, 2 template (CADESCOM_XML_SIGNATURE_TYPE_*).
    #[serde(default)]
    signature_type: u32,
    digest_method: Option<String>,
    signature_method: Option<String>,
    xpath: Option<String>,
    /// 0 XMLDSIG, 0x20 BES, 0x50 T, 0x5d0 XLT1, 0x7d0 A (CADESCOM_XADES_*).
    #[serde(default)]
    xades_flags: Option<u32>,
    tsa: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NmcadesXmlVerifyRequest {
    signed_xml: String,
    xpath: Option<String>,
}

fn default_cades_xlt1() -> u32 {
    CADES_XLT1
}

fn default_cades_bes() -> u32 {
    CADES_BES
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

pub fn run(opts: DaemonOptions) -> Result<()> {
    let mut cfg = load_config(&opts.config_path)?;
    if let Some(listen) = opts.listen_override {
        cfg.listen = listen;
    }
    if !is_loopback_listen(&cfg.listen)? && cfg.api_keys.is_empty() {
        bail!("non-loopback listen requires api_keys");
    }

    let store = KeyStore::load(&cfg.keys)?;
    let acl = ApiAcl::from_config(&cfg.api_keys)?;
    let rt = Arc::new(Runtime {
        store,
        acl,
        default_tsa: cfg.tsa.clone(),
        tsa_timeout_secs: cfg.tsa_timeout_secs,
        tsa_policy: cfg.tsa_policy.clone(),
    });

    let server =
        Server::http(&cfg.listen).map_err(|e| anyhow::anyhow!("bind {}: {e}", cfg.listen))?;
    let workers = std::env::var("JEX_DAEMON_WORKERS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4));
    eprintln!(
        "jex daemon listening on http://{} ({} key(s), {} API key(s), {} workers); web API: http://{}/api/v1  SDK: http://{}/jex.js  (legacy plugin: /cadesplugin_api.js)",
        cfg.listen,
        rt.store.keys.len(),
        rt.acl.entries.len(),
        workers,
        cfg.listen,
        cfg.listen
    );

    let (tx, rx) = std::sync::mpsc::sync_channel::<tiny_http::Request>(workers * 8);
    let rx = Arc::new(std::sync::Mutex::new(rx));
    for _ in 0..workers {
        let rx = Arc::clone(&rx);
        let rt = Arc::clone(&rt);
        std::thread::spawn(move || loop {
            let request = {
                let guard = match rx.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };
                guard.recv()
            };
            match request {
                Ok(request) => {
                    if let Err(e) = handle_request(Arc::clone(&rt), request) {
                        eprintln!("daemon request error: {e:#}");
                    }
                }
                Err(_) => break,
            }
        });
    }

    for request in server.incoming_requests() {
        if tx.send(request).is_err() {
            break;
        }
    }
    Ok(())
}

fn handle_request(rt: Arc<Runtime>, request: Request) -> Result<()> {
    let method = request.method().clone();
    let url = request.url().to_string();
    let (path, query) = split_url(&url);
    let origin = header_value(&request, "Origin");

    if method == Method::Options {
        return respond_cors_preflight(request, origin.as_deref(), &rt.acl);
    }

    if method == Method::Get && (path == "/cadesplugin_api.js" || path == "/cadesplugin_api.js/") {
        return respond_js(request, CADESPLUGIN_API_JS, origin.as_deref(), &rt.acl);
    }
    if method == Method::Get && (path == "/jex.js" || path == "/jex.js/") {
        return respond_js(request, JEX_API_JS, origin.as_deref(), &rt.acl);
    }

    if method == Method::Get && path == "/health" {
        return respond_json_cors(
            request,
            200,
            &serde_json::json!({ "status": "ok" }),
            origin.as_deref(),
            &rt.acl,
        );
    }

    if path == "/api/v1" || path == "/api/v1/" || path.starts_with("/api/v1/") {
        return api_v1::try_handle(rt, request, &method, path, origin.as_deref());
    }

    if method == Method::Get && path == "/nmcades/about" {
        // Public probe used by the browser shim before auth-bound calls.
        return respond_json_cors(
            request,
            200,
            &serde_json::json!({
                "PluginVersion": "2.0.15512",
                "CSPVersion": "5.0.13000",
            }),
            origin.as_deref(),
            &rt.acl,
        );
    }

    if method == Method::Post && path == "/v1/sign" {
        return handle_sign(rt, request, &query, origin.as_deref());
    }
    if method == Method::Post && path == "/v1/enhance" {
        return handle_enhance(rt, request, origin.as_deref());
    }
    if method == Method::Post && path == "/v1/attach" {
        return handle_attach(rt, request, origin.as_deref());
    }
    if method == Method::Post && path == "/v1/detach" {
        return handle_detach(rt, request, origin.as_deref());
    }
    if method == Method::Post && path == "/nmcades/sign" {
        return handle_nmcades_sign(rt, request, origin.as_deref());
    }
    if method == Method::Post && path == "/nmcades/verify" {
        return handle_nmcades_verify(rt, request, origin.as_deref());
    }
    if method == Method::Post && path == "/nmcades/hash" {
        return handle_nmcades_hash(rt, request, origin.as_deref());
    }
    if method == Method::Post && path == "/nmcades/raw-sign" {
        return handle_nmcades_raw_sign(rt, request, origin.as_deref());
    }
    if method == Method::Post && path == "/nmcades/raw-verify" {
        return handle_nmcades_raw_verify(rt, request, origin.as_deref());
    }
    if method == Method::Post && path == "/nmcades/enhance" {
        return handle_nmcades_enhance(rt, request, origin.as_deref());
    }
    if method == Method::Post && path == "/nmcades/xml-sign" {
        return handle_nmcades_xml_sign(rt, request, origin.as_deref());
    }
    if method == Method::Post && path == "/nmcades/xml-verify" {
        return handle_nmcades_xml_verify(rt, request, origin.as_deref());
    }

    let entry = match authorize_request(&rt.acl, &request, origin.as_deref()) {
        Ok(e) => e,
        Err((code, msg)) => {
            return respond_json_cors(
                request,
                code,
                &ErrorJson { error: msg },
                origin.as_deref(),
                &rt.acl,
            )
        }
    };

    match (method, path) {
        (Method::Get, "/v1/keys") => {
            let infos: Vec<KeyInfoJson> = rt
                .acl
                .visible_ids(entry, &rt.store)
                .into_iter()
                .filter_map(|id| rt.store.get(id))
                .map(|k| KeyInfoJson {
                    id: k.id.clone(),
                    subject: k.subject.clone(),
                    serial_hex: k.serial_hex.clone(),
                    not_before: k.not_before.clone(),
                    not_after: k.not_after.clone(),
                    curve: k.curve.name.to_string(),
                })
                .collect();
            respond_json_cors(request, 200, &infos, origin.as_deref(), &rt.acl)
        }
        (Method::Get, "/nmcades/certificates") => {
            let certs: Vec<NmcadesCertJson> = rt
                .acl
                .visible_ids(entry, &rt.store)
                .into_iter()
                .filter_map(|id| rt.store.get(id))
                .map(nmcades_cert_json)
                .collect();
            respond_json_cors(request, 200, &certs, origin.as_deref(), &rt.acl)
        }
        _ => respond_json_cors(
            request,
            404,
            &ErrorJson {
                error: "not found".into(),
            },
            origin.as_deref(),
            &rt.acl,
        ),
    }
}

fn authorize_request<'a>(
    acl: &'a ApiAcl,
    request: &Request,
    origin: Option<&str>,
) -> Result<&'a ApiKeyEntry, (u16, String)> {
    if let Ok(bearer) = extract_bearer(request) {
        return acl.resolve(&bearer).ok_or((401, "invalid API key".into()));
    }
    if let Some(origin) = origin {
        if let Some(entry) = acl.resolve_origin(origin) {
            return Ok(entry);
        }
        return Err((401, "origin is not allowed".into()));
    }
    Err((401, "missing Authorization header".into()))
}

fn nmcades_cert_json(k: &LoadedKey) -> NmcadesCertJson {
    NmcadesCertJson {
        id: k.id.clone(),
        subject: k.subject.clone(),
        subject_name: k.subject_name.clone(),
        issuer: k.issuer.clone(),
        issuer_name: k.issuer_name.clone(),
        serial_hex: k.serial_hex.clone(),
        thumbprint: k.thumbprint.clone(),
        not_before: k.not_before.clone(),
        not_after: k.not_after.clone(),
        not_before_unix: k.not_before_unix,
        not_after_unix: k.not_after_unix,
        cert_b64: STANDARD.encode(&k.cert_der),
    }
}

fn handle_nmcades_sign(rt: Arc<Runtime>, mut request: Request, origin: Option<&str>) -> Result<()> {
    let entry = match authorize_request(&rt.acl, &request, origin) {
        Ok(e) => e,
        Err((code, msg)) => {
            return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl)
        }
    };
    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body)?;
    let parsed: NmcadesSignRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid JSON body: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };

    let digest = match decode_hash(parsed.hash_hex.as_deref(), parsed.hash_b64.as_deref()) {
        Ok(d) => d,
        Err(e) => return respond_json_cors(request, 400, &ErrorJson { error: e }, origin, &rt.acl),
    };
    let content = if let Some(b64) = parsed.content_b64.as_deref() {
        match STANDARD.decode(b64.trim()) {
            Ok(c) => c,
            Err(e) => {
                return respond_json_cors(
                    request,
                    400,
                    &ErrorJson {
                        error: format!("invalid content_b64: {e}"),
                    },
                    origin,
                    &rt.acl,
                )
            }
        }
    } else {
        Vec::new()
    };
    if digest.is_none() && content.is_empty() {
        return respond_json_cors(
            request,
            400,
            &ErrorJson {
                error: "content_b64 or hash required".into(),
            },
            origin,
            &rt.acl,
        );
    }

    let key = match resolve_signing_key(
        &rt,
        entry,
        parsed.thumbprint.as_deref(),
        parsed.key_id.as_deref(),
    ) {
        Ok(k) => k,
        Err((code, msg)) => {
            return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl)
        }
    };

    let mut extra = Vec::new();
    for a in &parsed.attrs {
        match cades::authenticated_attr(a.name, &a.value, None) {
            Ok(der) => extra.push(der),
            Err(e) => {
                return respond_json_cors(
                    request,
                    400,
                    &ErrorJson {
                        error: format!("invalid attr: {e:#}"),
                    },
                    origin,
                    &rt.acl,
                )
            }
        }
    }

    let tsa = if matches!(
        if parsed.cades_type == 0 {
            CADES_BES
        } else {
            parsed.cades_type
        },
        CADES_T | CADES_XLT1 | CADES_A
    ) {
        parsed.tsa.as_deref().or(rt.default_tsa.as_deref())
    } else {
        parsed.tsa.as_deref()
    };
    let cades_type = if parsed.cades_type == 0 {
        CADES_BES
    } else {
        parsed.cades_type
    };
    match sign_with_key_full(
        &rt,
        key,
        &content,
        digest.as_deref(),
        !parsed.detached,
        tsa,
        cades_type,
        &extra,
    ) {
        Ok(resp) => respond_json_cors(request, 200, &resp, origin, &rt.acl),
        Err(e) => respond_json_cors(
            request,
            500,
            &ErrorJson {
                error: format!("sign failed: {e:#}"),
            },
            origin,
            &rt.acl,
        ),
    }
}

fn resolve_signing_key<'a>(
    rt: &'a Runtime,
    entry: &ApiKeyEntry,
    thumbprint: Option<&str>,
    key_id: Option<&str>,
) -> Result<&'a LoadedKey, (u16, String)> {
    if let Some(tp) = thumbprint {
        return match rt.store.by_thumbprint(tp) {
            Some(k) if rt.acl.authorize_key(entry, &k.id, &rt.store) => Ok(k),
            _ => Err((403, "forbidden certificate".into())),
        };
    }
    let key_id = pick_key_id(entry, &rt.store, key_id, &rt.acl)?;
    rt.store
        .get(&key_id)
        .ok_or((403, "forbidden certificate".into()))
}

fn decode_hash(hex_v: Option<&str>, b64_v: Option<&str>) -> Result<Option<Vec<u8>>, String> {
    if let Some(h) = hex_v {
        let clean: String = h.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        return hex::decode(&clean)
            .map(Some)
            .map_err(|e| format!("invalid hash_hex: {e}"));
    }
    if let Some(b) = b64_v {
        return STANDARD
            .decode(b.trim())
            .map(Some)
            .map_err(|e| format!("invalid hash_b64: {e}"));
    }
    Ok(None)
}

fn handle_nmcades_verify(
    rt: Arc<Runtime>,
    mut request: Request,
    origin: Option<&str>,
) -> Result<()> {
    if let Err((code, msg)) = authorize_request(&rt.acl, &request, origin) {
        return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl);
    }
    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body)?;
    let parsed: NmcadesVerifyRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid JSON body: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    let sig = match STANDARD.decode(parsed.signature_b64.trim()) {
        Ok(s) => s,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid signature_b64: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    let content = match parsed.content_b64.as_deref() {
        Some(b64) => match STANDARD.decode(b64.trim()) {
            Ok(c) => Some(c),
            Err(e) => {
                return respond_json_cors(
                    request,
                    400,
                    &ErrorJson {
                        error: format!("invalid content_b64: {e}"),
                    },
                    origin,
                    &rt.acl,
                )
            }
        },
        None => None,
    };
    let content_hash = match decode_hash(
        parsed.content_hash_hex.as_deref(),
        parsed.content_hash_b64.as_deref(),
    ) {
        Ok(h) => h,
        Err(e) => {
            return respond_json_cors(request, 400, &ErrorJson { error: e }, origin, &rt.acl)
        }
    };
    if content.is_some() && content_hash.is_some() {
        return respond_json_cors(
            request,
            400,
            &ErrorJson {
                error: "pass either content_b64 or content_hash_*, not both".into(),
            },
            origin,
            &rt.acl,
        );
    }
    match cades::verify_ex(&sig, content.as_deref(), content_hash.as_deref()) {
        Ok(v) => {
            let parsed_cms = cades::parse(&sig).ok();
            let thumbprint = parsed_cms
                .as_ref()
                .map(|p| cert_thumbprint_sha1(&p.certificate));
            let subject = parsed_cms.as_ref().and_then(|p| {
                x509::subject_name_attributes(&p.certificate)
                    .ok()
                    .and_then(|a| x509::display_name_from_attrs(&a))
            });
            respond_json_cors(
                request,
                200,
                &serde_json::json!({
                    "ok": v.signature_valid && v.message_digest_valid,
                    "signature_valid": v.signature_valid,
                    "message_digest_valid": v.message_digest_valid,
                    "signing_certificate_v2_valid": v.signing_certificate_v2_valid,
                    "detached": parsed_cms.as_ref().map(|p| p.detached),
                    "thumbprint": thumbprint,
                    "subject": subject,
                    "cert_b64": parsed_cms.as_ref().map(|p| STANDARD.encode(&p.certificate)),
                }),
                origin,
                &rt.acl,
            )
        }
        Err(e) => respond_json_cors(
            request,
            400,
            &ErrorJson {
                error: format!("verify failed: {e:#}"),
            },
            origin,
            &rt.acl,
        ),
    }
}

fn handle_nmcades_hash(rt: Arc<Runtime>, mut request: Request, origin: Option<&str>) -> Result<()> {
    if let Err((code, msg)) = authorize_request(&rt.acl, &request, origin) {
        return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl);
    }
    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body)?;
    let parsed: NmcadesHashRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid JSON body: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    let raw = match parsed.data_b64.as_deref() {
        Some(b64) => match STANDARD.decode(b64.trim()) {
            Ok(c) => c,
            Err(e) => {
                return respond_json_cors(
                    request,
                    400,
                    &ErrorJson {
                        error: format!("invalid data_b64: {e}"),
                    },
                    origin,
                    &rt.acl,
                )
            }
        },
        None => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: "data_b64 required".into(),
                },
                origin,
                &rt.acl,
            )
        }
    };
    // data_encoding 1 = already binary via b64; 0 = treat b64-decoded bytes as UTF-8 string bytes (same).
    let _ = parsed.data_encoding;
    let bytes = match parsed.algorithm {
        101 | 100 => 32u8, // GOST 2012-256 / legacy 3411 mapped to 256 for plugin
        102 => 64,
        other => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("unsupported hash algorithm {other}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    match cades::digest_data(bytes as usize, &raw) {
        Ok(hash) => respond_json_cors(
            request,
            200,
            &serde_json::json!({
                "hash_hex": hex::encode(&hash).to_ascii_uppercase(),
                "hash_b64": STANDARD.encode(&hash),
            }),
            origin,
            &rt.acl,
        ),
        Err(e) => respond_json_cors(
            request,
            500,
            &ErrorJson {
                error: format!("{e:#}"),
            },
            origin,
            &rt.acl,
        ),
    }
}

fn handle_nmcades_raw_sign(
    rt: Arc<Runtime>,
    mut request: Request,
    origin: Option<&str>,
) -> Result<()> {
    let entry = match authorize_request(&rt.acl, &request, origin) {
        Ok(e) => e,
        Err((code, msg)) => {
            return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl)
        }
    };
    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body)?;
    let parsed: NmcadesRawSignRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid JSON body: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    let digest = match decode_hash(parsed.hash_hex.as_deref(), parsed.hash_b64.as_deref()) {
        Ok(Some(d)) => d,
        Ok(None) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: "hash_hex or hash_b64 required".into(),
                },
                origin,
                &rt.acl,
            )
        }
        Err(e) => return respond_json_cors(request, 400, &ErrorJson { error: e }, origin, &rt.acl),
    };
    let key = match resolve_signing_key(
        &rt,
        entry,
        parsed.thumbprint.as_deref(),
        parsed.key_id.as_deref(),
    ) {
        Ok(k) => k,
        Err((code, msg)) => {
            return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl)
        }
    };
    match cades::raw_sign_digest(&key.curve, &key.private_le, &digest) {
        Ok(sig) => respond_json_cors(
            request,
            200,
            &serde_json::json!({
                "signature_b64": STANDARD.encode(&sig),
                "signature_hex": hex::encode(&sig).to_ascii_uppercase(),
                "key_id": key.id,
            }),
            origin,
            &rt.acl,
        ),
        Err(e) => respond_json_cors(
            request,
            500,
            &ErrorJson {
                error: format!("raw sign failed: {e:#}"),
            },
            origin,
            &rt.acl,
        ),
    }
}

fn handle_nmcades_raw_verify(
    rt: Arc<Runtime>,
    mut request: Request,
    origin: Option<&str>,
) -> Result<()> {
    if let Err((code, msg)) = authorize_request(&rt.acl, &request, origin) {
        return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl);
    }
    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body)?;
    let parsed: NmcadesRawVerifyRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid JSON body: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    let digest = match decode_hash(parsed.hash_hex.as_deref(), parsed.hash_b64.as_deref()) {
        Ok(Some(d)) => d,
        Ok(None) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: "hash required".into(),
                },
                origin,
                &rt.acl,
            )
        }
        Err(e) => return respond_json_cors(request, 400, &ErrorJson { error: e }, origin, &rt.acl),
    };
    let sig = match STANDARD.decode(parsed.signature_b64.trim()) {
        Ok(s) => s,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid signature_b64: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    let (curve, x, y) = if let Some(tp) = parsed.thumbprint.as_deref() {
        match rt.store.by_thumbprint(tp) {
            Some(k) => (
                k.curve.clone(),
                k.public_x_le.clone(),
                k.public_y_le.clone(),
            ),
            None => {
                return respond_json_cors(
                    request,
                    404,
                    &ErrorJson {
                        error: "certificate not found".into(),
                    },
                    origin,
                    &rt.acl,
                )
            }
        }
    } else if let Some(b64) = parsed.cert_b64.as_deref() {
        let cert = match STANDARD.decode(b64.trim()) {
            Ok(c) => c,
            Err(e) => {
                return respond_json_cors(
                    request,
                    400,
                    &ErrorJson {
                        error: format!("invalid cert_b64: {e}"),
                    },
                    origin,
                    &rt.acl,
                )
            }
        };
        match x509::identity(&cert) {
            Ok(id) => match curves::by_oid(&id.curve_oid) {
                Some(c) => (c, id.public_x_le, id.public_y_le),
                None => {
                    return respond_json_cors(
                        request,
                        400,
                        &ErrorJson {
                            error: "unsupported certificate curve".into(),
                        },
                        origin,
                        &rt.acl,
                    )
                }
            },
            Err(e) => {
                return respond_json_cors(
                    request,
                    400,
                    &ErrorJson {
                        error: format!("{e:#}"),
                    },
                    origin,
                    &rt.acl,
                )
            }
        }
    } else {
        return respond_json_cors(
            request,
            400,
            &ErrorJson {
                error: "thumbprint or cert_b64 required".into(),
            },
            origin,
            &rt.acl,
        );
    };
    match cades::raw_verify_digest(&curve, &x, &y, &digest, &sig) {
        Ok(ok) => respond_json_cors(
            request,
            200,
            &serde_json::json!({ "ok": ok }),
            origin,
            &rt.acl,
        ),
        Err(e) => respond_json_cors(
            request,
            400,
            &ErrorJson {
                error: format!("{e:#}"),
            },
            origin,
            &rt.acl,
        ),
    }
}

fn parse_enhance_profile(s: &str) -> Result<u32> {
    match s.trim().to_ascii_lowercase().as_str() {
        "t" | "cades-t" | "cades_t" => Ok(CADES_T),
        "xlt1" | "xlong" | "x-long" | "cades-xlt1" | "cades_xlt1" => Ok(CADES_XLT1),
        "a" | "archive" | "cades-a" | "cades_a" | "atsv3" => Ok(CADES_A),
        other => bail!("unknown enhance profile '{other}' (expected t|xlt1|a)"),
    }
}

/// Upgrade CMS/CAdES toward T / XLT1 / A. Shared by `/v1/enhance` and `/nmcades/enhance`.
fn enhance_cms(
    rt: &Runtime,
    mut der: Vec<u8>,
    external: Option<archive::ExternalData<'_>>,
    tsa: Option<String>,
    target: u32,
) -> Result<(Vec<u8>, String)> {
    let mut profile = "input".to_string();
    let parsed_cms = cades::parse(&der)?;
    if matches!(target, CADES_T | CADES_XLT1 | CADES_A)
        && parsed_cms.signature_timestamp_token.is_none()
    {
        let tsa = tsa
            .clone()
            .context("enhance to T/XLT1/A requires TSA URL")?;
        let digest_oid = parsed_cms.digest_oid.as_str();
        let ts = timestamp::request_timestamp(
            &tsa,
            &parsed_cms.signature,
            digest_oid,
            rt.tsa_policy.as_deref(),
            rt.tsa_timeout_secs,
        )?;
        der = cades::add_signature_timestamp(&der, &ts.token)?;
        profile = "CAdES-T".into();
    }
    if matches!(target, CADES_XLT1 | CADES_A) {
        let tsa = tsa
            .clone()
            .context("enhance to XLT1/A requires TSA URL")?;
        let parsed_cms = cades::parse(&der)?;
        let inner_ts = parsed_cms
            .signature_timestamp_token
            .as_deref()
            .context("missing signature timestamp")?;
        let inner_info = timestamp::token_matches_signature(inner_ts, &parsed_cms.signature)?;
        let inner_ts_unix = x509::generalized_time_to_unix(&inner_info.gen_time)?;
        let material = validation::collect(
            &parsed_cms.certificate,
            Vec::new(),
            Vec::new(),
            None,
            None,
            true,
            rt.tsa_timeout_secs.max(20),
            inner_ts_unix,
        )?;
        let enhanced = xlong::enhance_x_long_type_1(
            &der,
            &material,
            &tsa,
            rt.tsa_policy.as_deref(),
            rt.tsa_timeout_secs,
            rt.tsa_timeout_secs.max(20),
        )?;
        der = enhanced.der;
        profile = "CAdES-XLT1".into();
    }
    if target == CADES_A {
        let tsa = tsa.context("enhance to A requires TSA URL")?;
        let archived = archive::add_archive_timestamp_v3(
            &der,
            external,
            &tsa,
            rt.tsa_policy.as_deref(),
            rt.tsa_timeout_secs,
            rt.tsa_timeout_secs.max(20),
        )?;
        der = archived.der;
        profile = "CAdES-A".into();
    }
    if target == CADES_T && profile == "input" {
        profile = "CAdES-T".into();
    }
    Ok((der, profile))
}

fn decode_enhance_inputs(
    signature_b64: &str,
    content_b64: Option<&str>,
    content_hash_hex: Option<&str>,
    content_hash_b64: Option<&str>,
) -> Result<(Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>), String> {
    let der = STANDARD
        .decode(signature_b64.trim())
        .map_err(|e| format!("invalid signature_b64: {e}"))?;
    let content = match content_b64 {
        Some(b64) => Some(
            STANDARD
                .decode(b64.trim())
                .map_err(|e| format!("invalid content_b64: {e}"))?,
        ),
        None => None,
    };
    let content_hash = decode_hash(content_hash_hex, content_hash_b64)?;
    Ok((der, content, content_hash))
}

fn handle_enhance(rt: Arc<Runtime>, mut request: Request, origin: Option<&str>) -> Result<()> {
    if let Err((code, msg)) = authorize_request(&rt.acl, &request, origin) {
        return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl);
    }
    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body)?;
    let parsed: EnhanceRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid JSON body: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    let (der, content, content_hash) = match decode_enhance_inputs(
        &parsed.signature_b64,
        parsed.content_b64.as_deref(),
        parsed.content_hash_hex.as_deref(),
        parsed.content_hash_b64.as_deref(),
    ) {
        Ok(v) => v,
        Err(e) => {
            return respond_json_cors(request, 400, &ErrorJson { error: e }, origin, &rt.acl)
        }
    };
    let external =
        match archive::ExternalData::from_parts(content.as_deref(), content_hash.as_deref()) {
            Ok(e) => e,
            Err(e) => {
                return respond_json_cors(
                    request,
                    400,
                    &ErrorJson {
                        error: format!("{e:#}"),
                    },
                    origin,
                    &rt.acl,
                )
            }
        };
    let target = match parse_enhance_profile(&parsed.profile) {
        Ok(t) => t,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("{e:#}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    let tsa = parsed
        .tsa
        .as_deref()
        .or(rt.default_tsa.as_deref())
        .map(|s| s.to_string());

    match enhance_cms(&rt, der, external, tsa, target) {
        Ok((der, profile)) => respond_json_cors(
            request,
            200,
            &serde_json::json!({
                "profile": profile,
                "signature_b64": STANDARD.encode(&der),
            }),
            origin,
            &rt.acl,
        ),
        Err(e) => respond_json_cors(
            request,
            500,
            &ErrorJson {
                error: format!("enhance failed: {e:#}"),
            },
            origin,
            &rt.acl,
        ),
    }
}

fn handle_nmcades_enhance(
    rt: Arc<Runtime>,
    mut request: Request,
    origin: Option<&str>,
) -> Result<()> {
    if let Err((code, msg)) = authorize_request(&rt.acl, &request, origin) {
        return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl);
    }
    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body)?;
    let parsed: NmcadesEnhanceRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid JSON body: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    let (der, content, content_hash) = match decode_enhance_inputs(
        &parsed.signature_b64,
        parsed.content_b64.as_deref(),
        parsed.content_hash_hex.as_deref(),
        parsed.content_hash_b64.as_deref(),
    ) {
        Ok(v) => v,
        Err(e) => {
            return respond_json_cors(request, 400, &ErrorJson { error: e }, origin, &rt.acl)
        }
    };
    let external =
        match archive::ExternalData::from_parts(content.as_deref(), content_hash.as_deref()) {
            Ok(e) => e,
            Err(e) => {
                return respond_json_cors(
                    request,
                    400,
                    &ErrorJson {
                        error: format!("{e:#}"),
                    },
                    origin,
                    &rt.acl,
                )
            }
        };
    let tsa = parsed
        .tsa
        .as_deref()
        .or(rt.default_tsa.as_deref())
        .map(|s| s.to_string());
    let target = if parsed.cades_type == 0 {
        CADES_XLT1
    } else {
        parsed.cades_type
    };

    match enhance_cms(&rt, der, external, tsa, target) {
        Ok((der, profile)) => respond_json_cors(
            request,
            200,
            &serde_json::json!({
                "profile": profile,
                "signature_b64": STANDARD.encode(&der),
            }),
            origin,
            &rt.acl,
        ),
        Err(e) => respond_json_cors(
            request,
            500,
            &ErrorJson {
                error: format!("enhance failed: {e:#}"),
            },
            origin,
            &rt.acl,
        ),
    }
}

fn handle_attach(
    rt: Arc<Runtime>,
    mut request: Request,
    origin: Option<&str>,
) -> Result<()> {
    if let Err((code, msg)) = authorize_request(&rt.acl, &request, origin) {
        return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl);
    }
    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body)?;
    let parsed: AttachRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid JSON body: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    let der = match STANDARD.decode(parsed.signature_b64.trim()) {
        Ok(s) => s,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid signature_b64: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    let content = match STANDARD.decode(parsed.content_b64.trim()) {
        Ok(c) => c,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid content_b64: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };

    let outcome = (|| -> Result<Vec<u8>> {
        let attached = archive::attach_original_content(&der, &content)?;
        let report = verification::analyze(&attached, None)?;
        if !report.is_valid() {
            bail!("attached CMS/CAdES failed local verification");
        }
        Ok(attached)
    })();

    match outcome {
        Ok(attached) => respond_json_cors(
            request,
            200,
            &serde_json::json!({
                "signature_b64": STANDARD.encode(&attached),
                "detached": false,
                "content_len": content.len(),
            }),
            origin,
            &rt.acl,
        ),
        Err(e) => respond_json_cors(
            request,
            500,
            &ErrorJson {
                error: format!("attach failed: {e:#}"),
            },
            origin,
            &rt.acl,
        ),
    }
}

fn handle_detach(
    rt: Arc<Runtime>,
    mut request: Request,
    origin: Option<&str>,
) -> Result<()> {
    if let Err((code, msg)) = authorize_request(&rt.acl, &request, origin) {
        return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl);
    }
    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body)?;
    let parsed: DetachRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid JSON body: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    let der = match STANDARD.decode(parsed.signature_b64.trim()) {
        Ok(s) => s,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid signature_b64: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };

    let outcome = (|| -> Result<(Vec<u8>, Vec<u8>)> {
        let (detached, content) = archive::detach_original_content(&der)?;
        let report = verification::analyze(&detached, Some(&content))?;
        if !report.is_valid() {
            bail!("detached CMS/CAdES failed local verification");
        }
        Ok((detached, content))
    })();

    match outcome {
        Ok((detached, content)) => respond_json_cors(
            request,
            200,
            &serde_json::json!({
                "signature_b64": STANDARD.encode(&detached),
                "content_b64": STANDARD.encode(&content),
                "detached": true,
                "content_len": content.len(),
            }),
            origin,
            &rt.acl,
        ),
        Err(e) => respond_json_cors(
            request,
            500,
            &ErrorJson {
                error: format!("detach failed: {e:#}"),
            },
            origin,
            &rt.acl,
        ),
    }
}

fn handle_nmcades_xml_sign(
    rt: Arc<Runtime>,
    mut request: Request,
    origin: Option<&str>,
) -> Result<()> {
    let entry = match authorize_request(&rt.acl, &request, origin) {
        Ok(e) => e,
        Err((code, msg)) => {
            return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl)
        }
    };
    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body)?;
    let parsed: NmcadesXmlSignRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid JSON body: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    if parsed.content.trim().is_empty() {
        return respond_json_cors(
            request,
            400,
            &ErrorJson {
                error: "content required".into(),
            },
            origin,
            &rt.acl,
        );
    }
    let key = match resolve_signing_key(
        &rt,
        entry,
        parsed.thumbprint.as_deref(),
        parsed.key_id.as_deref(),
    ) {
        Ok(k) => k,
        Err((code, msg)) => {
            return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl)
        }
    };

    let digest_method = match parsed.digest_method.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => match xmldsig::digest_method_uri(key.curve.bytes) {
            Ok(u) => u.to_string(),
            Err(e) => {
                return respond_json_cors(
                    request,
                    400,
                    &ErrorJson {
                        error: format!("{e:#}"),
                    },
                    origin,
                    &rt.acl,
                )
            }
        },
    };
    let signature_method = match parsed.signature_method.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => match xmldsig::signature_method_uri(key.curve.bytes) {
            Ok(u) => u.to_string(),
            Err(e) => {
                return respond_json_cors(
                    request,
                    400,
                    &ErrorJson {
                        error: format!("{e:#}"),
                    },
                    origin,
                    &rt.acl,
                )
            }
        },
    };
    let signature_type = match parsed.signature_type {
        1 => xmldsig::XmlSignatureType::Enveloping,
        2 => xmldsig::XmlSignatureType::Template,
        _ => xmldsig::XmlSignatureType::Enveloped,
    };
    let tsa_url = parsed.tsa.as_deref().or(rt.default_tsa.as_deref());
    let params = xmldsig::SignXmlParams {
        content: &parsed.content,
        cert_der: &key.cert_der,
        curve: &key.curve,
        private_le: key.private_le.as_slice(),
        public_x_le: key.public_x_le.as_slice(),
        public_y_le: key.public_y_le.as_slice(),
        signature_type,
        digest_method: &digest_method,
        signature_method: &signature_method,
        xpath: parsed.xpath.as_deref(),
        xades_flags: parsed.xades_flags.unwrap_or(0),
        tsa_url,
        tsa_policy: rt.tsa_policy.as_deref(),
        tsa_timeout_secs: rt.tsa_timeout_secs.max(1),
    };
    match xmldsig::sign_xml(&params) {
        Ok(signed_xml) => respond_json_cors(
            request,
            200,
            &serde_json::json!({ "signed_xml": signed_xml }),
            origin,
            &rt.acl,
        ),
        Err(e) => respond_json_cors(
            request,
            500,
            &ErrorJson {
                error: format!("xml-sign failed: {e:#}"),
            },
            origin,
            &rt.acl,
        ),
    }
}

fn handle_nmcades_xml_verify(
    rt: Arc<Runtime>,
    mut request: Request,
    origin: Option<&str>,
) -> Result<()> {
    if let Err((code, msg)) = authorize_request(&rt.acl, &request, origin) {
        return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl);
    }
    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body)?;
    let parsed: NmcadesXmlVerifyRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("invalid JSON body: {e}"),
                },
                origin,
                &rt.acl,
            )
        }
    };
    if parsed.signed_xml.trim().is_empty() {
        return respond_json_cors(
            request,
            400,
            &ErrorJson {
                error: "signed_xml required".into(),
            },
            origin,
            &rt.acl,
        );
    }
    match xmldsig::verify_xml(&parsed.signed_xml, parsed.xpath.as_deref()) {
        Ok(v) => {
            let (thumbprint, subject, cert_b64) = match &v.certificate_der {
                Some(cert) => {
                    let tp = cert_thumbprint_sha1(cert);
                    let subj = x509::subject_name_attributes(cert)
                        .ok()
                        .and_then(|a| x509::display_name_from_attrs(&a));
                    (Some(tp), subj, Some(STANDARD.encode(cert)))
                }
                None => (None, None, None),
            };
            respond_json_cors(
                request,
                200,
                &serde_json::json!({
                    "ok": v.ok,
                    "signature_valid": v.signature_valid,
                    "references_valid": v.references_valid,
                    "cert_b64": cert_b64,
                    "thumbprint": thumbprint,
                    "subject": subject,
                }),
                origin,
                &rt.acl,
            )
        }
        Err(e) => respond_json_cors(
            request,
            400,
            &ErrorJson {
                error: format!("xml-verify failed: {e:#}"),
            },
            origin,
            &rt.acl,
        ),
    }
}

fn handle_sign(
    rt: Arc<Runtime>,
    mut request: Request,
    query: &str,
    origin: Option<&str>,
) -> Result<()> {
    let entry = match authorize_request(&rt.acl, &request, origin) {
        Ok(e) => e,
        Err((code, msg)) => {
            return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl)
        }
    };
    let content_type = header_value(&request, "Content-Type").unwrap_or_default();
    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body)?;

    let as_json = content_type.starts_with("application/json")
        || (content_type.is_empty() && body.first().copied() == Some(b'{'));
    let as_octet = content_type.starts_with("application/octet-stream")
        || (content_type.is_empty() && !as_json);

    let (key_id_req, content, attached, tsa_val) = if as_json {
        let parsed: SignRequestJson = match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(e) => {
                return respond_json_cors(
                    request,
                    400,
                    &ErrorJson {
                        error: format!("invalid JSON body: {e}"),
                    },
                    origin,
                    &rt.acl,
                )
            }
        };
        let content = match STANDARD.decode(parsed.content_b64.trim()) {
            Ok(c) => c,
            Err(e) => {
                return respond_json_cors(
                    request,
                    400,
                    &ErrorJson {
                        error: format!("invalid content_b64: {e}"),
                    },
                    origin,
                    &rt.acl,
                )
            }
        };
        (parsed.key_id, content, parsed.attached, parsed.tsa)
    } else if as_octet {
        if body.is_empty() {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: "empty body".into(),
                },
                origin,
                &rt.acl,
            );
        }
        let key_id = header_value(&request, "X-Key-Id").or_else(|| query_param(query, "key_id"));
        let attached = query_param(query, "attached")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let tsa_val = match query_param(query, "tsa").as_deref() {
            None => None,
            Some("false") | Some("0") => Some(serde_json::Value::Bool(false)),
            Some(url) => Some(serde_json::Value::String(url.to_string())),
        };
        (key_id, body, attached, tsa_val)
    } else {
        return respond_json_cors(
            request,
            415,
            &ErrorJson {
                error: "Content-Type must be application/json or application/octet-stream".into(),
            },
            origin,
            &rt.acl,
        );
    };

    let key_id = match pick_key_id(entry, &rt.store, key_id_req.as_deref(), &rt.acl) {
        Ok(id) => id,
        Err((code, msg)) => {
            return respond_json_cors(request, code, &ErrorJson { error: msg }, origin, &rt.acl)
        }
    };

    let tsa_url = match resolve_tsa(&tsa_val, &rt.default_tsa) {
        Ok(u) => u,
        Err(e) => {
            return respond_json_cors(
                request,
                400,
                &ErrorJson {
                    error: format!("{e:#}"),
                },
                origin,
                &rt.acl,
            )
        }
    };

    let key = match rt.store.get(&key_id) {
        Some(k) => k,
        None => {
            return respond_json_cors(
                request,
                403,
                &ErrorJson {
                    error: "forbidden key_id".into(),
                },
                origin,
                &rt.acl,
            )
        }
    };
    match sign_with_key(&rt, key, &content, attached, tsa_url.as_deref()) {
        Ok(resp) => respond_json_cors(request, 200, &resp, origin, &rt.acl),
        Err(e) => respond_json_cors(
            request,
            500,
            &ErrorJson {
                error: format!("sign failed: {e:#}"),
            },
            origin,
            &rt.acl,
        ),
    }
}

fn cors_origin_allowed(origin: Option<&str>, acl: &ApiAcl) -> Option<String> {
    let origin = origin?;
    let norm = normalize_origin(origin);
    if acl.all_origins().iter().any(|o| o == &norm) {
        Some(norm)
    } else {
        None
    }
}

fn append_cors(headers: &mut Vec<Header>, origin: Option<&str>, acl: &ApiAcl) {
    if let Some(o) = cors_origin_allowed(origin, acl) {
        if let Ok(h) = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], o.as_bytes()) {
            headers.push(h);
        }
        if let Ok(h) = Header::from_bytes(
            &b"Access-Control-Allow-Headers"[..],
            &b"Authorization, Content-Type"[..],
        ) {
            headers.push(h);
        }
        if let Ok(h) = Header::from_bytes(
            &b"Access-Control-Allow-Methods"[..],
            &b"GET, POST, OPTIONS"[..],
        ) {
            headers.push(h);
        }
        if let Ok(h) = Header::from_bytes(&b"Vary"[..], &b"Origin"[..]) {
            headers.push(h);
        }
    }
}

fn respond_cors_preflight(request: Request, origin: Option<&str>, acl: &ApiAcl) -> Result<()> {
    let mut headers = Vec::new();
    append_cors(&mut headers, origin, acl);
    let mut response = Response::from_data(Vec::new()).with_status_code(StatusCode(204));
    for h in headers {
        response.add_header(h);
    }
    request.respond(response)?;
    Ok(())
}

fn respond_js(request: Request, body: &str, origin: Option<&str>, acl: &ApiAcl) -> Result<()> {
    let mut headers = Vec::new();
    if let Ok(h) = Header::from_bytes(
        &b"Content-Type"[..],
        &b"application/javascript; charset=utf-8"[..],
    ) {
        headers.push(h);
    }
    if let Ok(h) = Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]) {
        headers.push(h);
    }
    append_cors(&mut headers, origin, acl);
    let mut response = Response::from_data(body.as_bytes()).with_status_code(StatusCode(200));
    for h in headers {
        response.add_header(h);
    }
    request.respond(response)?;
    Ok(())
}

fn respond_json_cors<T: Serialize>(
    request: Request,
    code: u16,
    body: &T,
    origin: Option<&str>,
    acl: &ApiAcl,
) -> Result<()> {
    let bytes = serde_json::to_vec(body)?;
    let mut headers = Vec::new();
    if let Ok(h) = Header::from_bytes(
        &b"Content-Type"[..],
        &b"application/json; charset=utf-8"[..],
    ) {
        headers.push(h);
    }
    append_cors(&mut headers, origin, acl);
    let mut response = Response::from_data(bytes).with_status_code(StatusCode(code));
    for h in headers {
        response.add_header(h);
    }
    request.respond(response)?;
    Ok(())
}

fn extract_bearer(request: &Request) -> Result<Vec<u8>, String> {
    let Some(raw) = header_value(request, "Authorization") else {
        return Err("missing Authorization header".into());
    };
    let raw = raw.trim();
    let prefix = "Bearer ";
    if raw.len() < prefix.len() || !raw[..prefix.len()].eq_ignore_ascii_case(prefix) {
        return Err("Authorization must be Bearer <token>".into());
    }
    let token = raw[prefix.len()..].trim();
    if token.is_empty() {
        return Err("empty bearer token".into());
    }
    Ok(token.as_bytes().to_vec())
}

fn header_value(request: &Request, name: &str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| {
            let field: &str = h.field.as_str().as_ref();
            field.eq_ignore_ascii_case(name)
        })
        .map(|h| h.value.as_str().to_string())
}

fn split_url(url: &str) -> (&str, &str) {
    match url.split_once('?') {
        Some((path, query)) => (path, query),
        None => (url, ""),
    }
}

fn query_param(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => (pair, ""),
        };
        if k == name {
            return Some(urlencoding_decode(v));
        }
    }
    None
}

fn urlencoding_decode(s: &str) -> String {
    // Minimal decode for query values (percent-encoding + '+').
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let h = |c: u8| -> Option<u8> {
                    match c {
                        b'0'..=b'9' => Some(c - b'0'),
                        b'a'..=b'f' => Some(c - b'a' + 10),
                        b'A'..=b'F' => Some(c - b'A' + 10),
                        _ => None,
                    }
                };
                if let (Some(a), Some(b)) = (h(bytes[i + 1]), h(bytes[i + 2])) {
                    out.push((a << 4) | b);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_acl() -> ApiAcl {
        ApiAcl {
            entries: vec![
                ApiKeyEntry {
                    token: b"token-a".to_vec(),
                    origins: vec!["http://app-a.example".into()],
                    allow_all: false,
                    allow: HashSet::from(["alice".into()]),
                },
                ApiKeyEntry {
                    token: b"token-b".to_vec(),
                    origins: vec!["http://app-b.example".into()],
                    allow_all: false,
                    allow: HashSet::from(["alice".into(), "bob".into()]),
                },
                ApiKeyEntry {
                    token: b"token-star".to_vec(),
                    origins: Vec::new(),
                    allow_all: true,
                    allow: HashSet::new(),
                },
            ],
        }
    }

    fn empty_store_with_ids(ids: &[&str]) -> KeyStore {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.1").expect("curve");
        let mut keys = HashMap::new();
        for id in ids {
            keys.insert(
                (*id).to_string(),
                LoadedKey {
                    id: (*id).to_string(),
                    cert_der: Vec::new(),
                    curve: curve.clone(),
                    private_le: vec![0u8; 32],
                    public_x_le: vec![0u8; 32],
                    public_y_le: vec![0u8; 32],
                    subject: format!("CN={id}"),
                    subject_name: format!("CN={id}"),
                    issuer: "CN=CA".into(),
                    issuer_name: "CN=CA".into(),
                    serial_hex: "01".into(),
                    thumbprint: format!("{:040}", id.bytes().map(|b| b as u32).sum::<u32>()),
                    not_before: "2020-01-01".into(),
                    not_after: "2030-01-01".into(),
                    not_before_unix: 1577836800,
                    not_after_unix: 1893456000,
                },
            );
        }
        KeyStore { keys }
    }

    #[test]
    fn acl_filters_keys_per_api_token() {
        let acl = sample_acl();
        let store = empty_store_with_ids(&["alice", "bob"]);
        let a = acl.resolve(b"token-a").unwrap();
        assert_eq!(acl.visible_ids(a, &store), vec!["alice"]);
        assert!(acl.authorize_key(a, "alice", &store));
        assert!(!acl.authorize_key(a, "bob", &store));

        let b = acl.resolve(b"token-b").unwrap();
        assert_eq!(acl.visible_ids(b, &store), vec!["alice", "bob"]);

        let star = acl.resolve(b"token-star").unwrap();
        assert_eq!(acl.visible_ids(star, &store), vec!["alice", "bob"]);
    }

    #[test]
    fn unknown_or_forbidden_key_is_denied() {
        let acl = sample_acl();
        let store = empty_store_with_ids(&["alice", "bob"]);
        let a = acl.resolve(b"token-a").unwrap();
        assert!(!acl.authorize_key(a, "bob", &store));
        assert!(!acl.authorize_key(a, "carol", &store));
        match pick_key_id(a, &store, Some("bob"), &acl) {
            Err((403, _)) => {}
            other => panic!("expected 403, got {other:?}"),
        }
        match pick_key_id(a, &store, Some("carol"), &acl) {
            Err((403, _)) => {}
            other => panic!("expected 403, got {other:?}"),
        }
    }

    #[test]
    fn pick_key_id_defaults_when_single_allowed() {
        let acl = sample_acl();
        let store = empty_store_with_ids(&["alice", "bob"]);
        let a = acl.resolve(b"token-a").unwrap();
        assert_eq!(pick_key_id(a, &store, None, &acl).unwrap(), "alice");
        let b = acl.resolve(b"token-b").unwrap();
        match pick_key_id(b, &store, None, &acl) {
            Err((400, _)) => {}
            other => panic!("expected 400, got {other:?}"),
        }
    }

    #[test]
    fn token_eq_rejects_wrong_token() {
        assert!(token_eq(b"abc", b"abc"));
        assert!(!token_eq(b"abc", b"abd"));
        assert!(!token_eq(b"abc", b"ab"));
        assert!(sample_acl().resolve(b"nope").is_none());
    }

    #[test]
    fn resolve_tsa_modes() {
        let default = Some("https://tsa.example/tsp".into());
        assert_eq!(
            resolve_tsa(&None, &default).unwrap().as_deref(),
            Some("https://tsa.example/tsp")
        );
        assert_eq!(
            resolve_tsa(&Some(serde_json::Value::Bool(false)), &default)
                .unwrap()
                .as_deref(),
            None
        );
        assert_eq!(
            resolve_tsa(
                &Some(serde_json::Value::String("https://other/tsp".into())),
                &default
            )
            .unwrap()
            .as_deref(),
            Some("https://other/tsp")
        );
    }

    #[test]
    fn config_rejects_unknown_allow_id() {
        let dir = std::env::temp_dir().join(format!("jex-daemon-cfg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("daemon.json");
        fs::write(
            &path,
            r#"{
              "keys": [{"id":"alice","container_dir":"./x","pin":"1"}],
              "api_keys": [{"token":"t","allow":["bob"]}]
            }"#,
        )
        .unwrap();
        let err = load_config(&path).unwrap_err().to_string();
        assert!(err.contains("unknown key id"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn origin_acl_selects_api_key() {
        let acl = sample_acl();
        let store = empty_store_with_ids(&["alice", "bob"]);
        let a = acl.resolve_origin("http://app-a.example/").unwrap();
        assert_eq!(acl.visible_ids(a, &store), vec!["alice"]);
        assert!(acl.resolve_origin("http://unknown.example").is_none());
    }

    #[test]
    fn thumbprint_lookup() {
        let store = empty_store_with_ids(&["alice"]);
        let tp = store.get("alice").unwrap().thumbprint.clone();
        assert!(store.by_thumbprint(&tp).is_some());
        assert!(store.by_thumbprint(&tp.to_ascii_lowercase()).is_some());
        assert!(store.by_thumbprint("nope").is_none());
    }

    #[test]
    fn plugin_script_is_embedded() {
        assert!(CADESPLUGIN_API_JS.contains("CreateObjectAsync"));
        assert!(CADESPLUGIN_API_JS.contains("CAdESCOM.CadesSignedData"));
        assert!(CADESPLUGIN_API_JS.contains("CAdESCOM.HashedData"));
        assert!(CADESPLUGIN_API_JS.contains("CAdESCOM.RawSignature"));
        assert!(CADESPLUGIN_API_JS.contains("VerifyCades"));
        assert!(CADESPLUGIN_API_JS.contains("SignHash"));
        assert!(CADESPLUGIN_API_JS.contains("EnhanceCades"));
        assert!(CADESPLUGIN_API_JS.contains("AuthenticatedAttributes2"));
        // The only Jex branding allowed in the page shim is the CSP provider
        // name, which must match what the native host reports.
        let without_provider =
            CADESPLUGIN_API_JS.replace("Jex GOST R 34.10-2012 Cryptographic Service Provider", "");
        assert!(!without_provider.to_ascii_lowercase().contains("jex"));
    }

    #[test]
    fn query_param_parsing() {
        assert_eq!(
            query_param("key_id=alice&attached=true", "key_id").as_deref(),
            Some("alice")
        );
        assert_eq!(
            query_param("attached=true", "attached").as_deref(),
            Some("true")
        );
        assert_eq!(query_param("a=1%2F2", "a").as_deref(), Some("1/2"));
    }
}
