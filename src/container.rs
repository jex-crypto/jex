// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use crate::{cades, cms_der, cpkdf, curves, der, gost28147, gost3410, x509};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use num_bigint::BigUint;
use rand::{rngs::OsRng, RngCore};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use streebog::{Digest, Streebog256};
use zeroize::{Zeroize, Zeroizing};

/// Default classic-container curve (CryptoPro-XchA / TC26 2012-256 B), matching
/// typical CryptoPro HDIMAGE containers such as `roman/`.
pub const DEFAULT_CREATE_CURVE_OID: &str = "1.2.643.2.2.36.0";

const OID_CONTAINER_BLOB: &str = "1.2.643.2.2.37.2.1";
const OID_PRIVATE_KEY_2012_256: &str = "1.2.643.7.1.1.6.1";
const OID_ATTR_NOT_AFTER: &str = "1.2.643.2.2.37.3.10";
const MASKS_FILE_SIZE: usize = 60;
const PRIMARY_FILE_SIZE: usize = 70;
const NAME_FILE_SIZE: usize = 300;

#[derive(Clone, Debug)]
pub struct ContainerFiles {
    pub header: Vec<u8>,
    pub masks: Vec<u8>,
    pub masks2: Option<Vec<u8>>,
    pub name: Option<Vec<u8>>,
    pub primary: Vec<u8>,
    pub primary2: Option<Vec<u8>>,
}

impl Drop for ContainerFiles {
    fn drop(&mut self) {
        // masks.key holds the unencrypted mask; primary.key the masked key.
        self.masks.zeroize();
        self.primary.zeroize();
        if let Some(v) = self.masks2.as_mut() {
            v.zeroize();
        }
        if let Some(v) = self.primary2.as_mut() {
            v.zeroize();
        }
    }
}

/// Return true when `dir` contains the three required classic container EFs.
pub fn is_dump_dir(dir: &Path) -> bool {
    dir.is_dir()
        && dir.join("header.key").is_file()
        && dir.join("masks.key").is_file()
        && dir.join("primary.key").is_file()
}

/// List immediate subdirectories of `root` that look like `rutoken dump` output.
pub fn discover_dump_dirs(root: impl AsRef<Path>) -> Result<Vec<PathBuf>> {
    let root = root.as_ref();
    let mut dirs = Vec::new();
    for entry in fs::read_dir(root).with_context(|| format!("read dump root {}", root.display()))? {
        let entry =
            entry.with_context(|| format!("read dump root entry under {}", root.display()))?;
        let path = entry.path();
        if is_dump_dir(&path) {
            dirs.push(path);
        }
    }
    dirs.sort();
    Ok(dirs)
}

impl ContainerFiles {
    pub fn open_dir(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        let read_required = |name: &str| -> Result<Vec<u8>> {
            fs::read(root.join(name)).with_context(|| format!("read {}", root.join(name).display()))
        };
        let read_optional = |name: &str| -> Option<Vec<u8>> { fs::read(root.join(name)).ok() };

        Ok(Self {
            header: read_required("header.key")?,
            masks: read_required("masks.key")?,
            masks2: read_optional("masks2.key"),
            name: read_optional("name.key"),
            primary: read_required("primary.key")?,
            primary2: read_optional("primary2.key"),
        })
    }

    pub fn write_dir(&self, root: impl AsRef<Path>) -> Result<()> {
        let root = root.as_ref();
        fs::create_dir_all(root).with_context(|| format!("create {}", root.display()))?;
        fs::write(root.join("header.key"), &self.header)?;
        fs::write(root.join("masks.key"), &self.masks)?;
        fs::write(root.join("primary.key"), &self.primary)?;
        if let Some(v) = &self.masks2 {
            fs::write(root.join("masks2.key"), v)?;
        }
        if let Some(v) = &self.name {
            fs::write(root.join("name.key"), v)?;
        }
        if let Some(v) = &self.primary2 {
            fs::write(root.join("primary2.key"), v)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ClassicContainer {
    pub files: ContainerFiles,
    pub name: Option<String>,
    pub uuid: Option<String>,
    pub oids: Vec<String>,
    pub primary_fp: Option<[u8; 8]>,
    pub curve: curves::Curve,
    /// First complete X.509 certificate embedded in header.key, if present.
    pub certificate: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct UnlockedKey {
    pub private_le: Vec<u8>,
    pub public_x_le: Vec<u8>,
    pub public_y_le: Vec<u8>,
    pub used_backup: bool,
}

impl Drop for UnlockedKey {
    fn drop(&mut self) {
        self.private_le.zeroize();
    }
}

#[derive(Debug)]
struct MaskFile {
    mask: Vec<u8>,
    salt: Vec<u8>,
    _hmac: Vec<u8>,
}

impl Drop for MaskFile {
    fn drop(&mut self) {
        self.mask.zeroize();
    }
}

fn parse_mask(input: &[u8]) -> Result<MaskFile> {
    let fields = der::parse_sequence(input).context("parse masks.key")?;
    if fields.len() < 3 || fields[0].tag != 0x04 || fields[1].tag != 0x04 || fields[2].tag != 0x04 {
        bail!("unexpected masks.key ASN.1 layout");
    }
    Ok(MaskFile {
        mask: fields[0].value.to_vec(),
        salt: fields[1].value.to_vec(),
        _hmac: fields[2].value.to_vec(),
    })
}

fn parse_primary(input: &[u8]) -> Result<Vec<u8>> {
    let fields = der::parse_sequence(input).context("parse primary.key")?;
    let first = fields.first().context("empty primary.key SEQUENCE")?;
    if first.tag != 0x04 {
        bail!(
            "unexpected primary.key layout: first tag 0x{:02x}",
            first.tag
        );
    }
    Ok(first.value.to_vec())
}

fn decode_string_tlv(tlv: &der::Tlv<'_>) -> Option<String> {
    match tlv.tag {
        // PrintableString, IA5String, GeneralString
        0x13 | 0x16 | 0x1b | 0x1e => std::str::from_utf8(tlv.value).ok().map(ToOwned::to_owned),
        0x0c => String::from_utf8(tlv.value.to_vec()).ok(),
        _ => None,
    }
}

/// Decode a CryptoPro `name.key` value (bare string or SEQUENCE of strings).
/// Returns the decoded name or a diagnostic hex representation if decoding fails.
pub(crate) fn parse_name_or_hex(input: &[u8]) -> String {
    if let Some(name) = parse_name(input) {
        return name;
    }
    // If standard parsing fails, try to extract some diagnostic info
    match der::parse_tlv(input) {
        Ok(top) => {
            let tag_str = match top.tag {
                0x30 => "SEQUENCE".to_string(),
                0x16 => "IA5String".to_string(),
                0x13 => "PrintableString".to_string(),
                0x0c => "UTF8String".to_string(),
                0x1b => "GeneralString".to_string(),
                0x1e => "GeneralString".to_string(),
                t => format!("tag:0x{:02x}", t),
            };
            // Show first 32 bytes in hex as diagnostic
            let hex_preview = hex::encode(&input[..input.len().min(32)]);
            if input.len() > 32 {
                format!(
                    "<unparseable {} - {} bytes, hex: {}...>",
                    tag_str,
                    input.len(),
                    hex_preview
                )
            } else {
                format!("<unparseable {} - hex: {}>", tag_str, hex_preview)
            }
        }
        Err(_) => {
            let hex_preview = hex::encode(&input[..input.len().min(32)]);
            if input.len() > 32 {
                format!(
                    "<invalid DER - {} bytes, hex: {}...>",
                    input.len(),
                    hex_preview
                )
            } else {
                format!("<invalid DER - hex: {}>", hex_preview)
            }
        }
    }
}

/// Decode a CryptoPro `name.key` value (bare string or SEQUENCE of strings).
pub(crate) fn parse_name(input: &[u8]) -> Option<String> {
    let top = der::parse_tlv(input).ok()?;
    match top.tag {
        0x30 => der::children(top.value)
            .ok()?
            .first()
            .and_then(decode_string_tlv),
        _ => decode_string_tlv(&top),
    }
}

fn detect_curve(oids: &[String]) -> Result<curves::Curve> {
    for oid in oids.iter().filter(|x| x.starts_with("1.2.643.7.1.2.1.")) {
        if let Some(c) = curves::by_oid(oid) {
            return Ok(c);
        }
    }
    for oid in oids {
        if let Some(c) = curves::by_oid(oid) {
            return Ok(c);
        }
    }
    bail!("no supported GOST curve OID found in header.key");
}

fn is_2012(oids: &[String]) -> bool {
    oids.iter().any(|x| {
        x == "1.2.643.7.1.1.6.1"
            || x == "1.2.643.7.1.1.6.2"
            || x == "1.2.643.7.1.1.1.1"
            || x == "1.2.643.7.1.1.1.2"
    })
}

/// True when `s` has the standard 36-character UUID shape
/// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, hex digits + dashes).
fn looks_like_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-')
        && b.iter()
            .enumerate()
            .all(|(i, &c)| [8, 13, 18, 23].contains(&i) || c.is_ascii_hexdigit())
}

/// Resolve the container UUID. Rutoken-generated classic containers store
/// the CryptoPro "unique container name" (`name.key`) as the UUID itself
/// (an IA5String inside a one-element SEQUENCE); prefer that when it is
/// UUID-shaped, and fall back to the legacy header.key context-tag 0x89
/// encoding for containers that don't follow this convention.
pub(crate) fn resolve_uuid(name: Option<&str>, header: &[u8]) -> Option<String> {
    name.filter(|n| looks_like_uuid(n))
        .map(|n| n.to_ascii_lowercase())
        .or_else(|| extract_container_uuid(header))
}

/// Extract container UUID from header.key (context tag 0x89 with 16 bytes).
/// Returns UUID in standard format "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
pub(crate) fn extract_container_uuid(header: &[u8]) -> Option<String> {
    der::find_context_primitive(header, 0x89, 16).map(|uuid_bytes| {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3],
            uuid_bytes[4], uuid_bytes[5],
            uuid_bytes[6], uuid_bytes[7],
            uuid_bytes[8], uuid_bytes[9],
            uuid_bytes[10], uuid_bytes[11], uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15]
        )
    })
}

impl ClassicContainer {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::from_files(ContainerFiles::open_dir(root)?)
    }

    pub fn from_files(files: ContainerFiles) -> Result<Self> {
        // Try to parse name, but prefer standard parse_name for backward compatibility
        let name = files.name.as_deref().and_then(parse_name);
        let uuid = resolve_uuid(name.as_deref(), &files.header);
        let oids = der::collect_oids(&files.header);
        if !is_2012(&oids) {
            bail!("container does not look like a GOST-2012 classic container; GOST-2001 KDF is not implemented");
        }
        let curve = detect_curve(&oids)?;
        let primary_fp = der::find_context_primitive(&files.header, 0x8a, 8)
            .and_then(|v| <[u8; 8]>::try_from(v).ok());
        let certificate = x509::find_certificate(&files.header);
        Ok(Self {
            files,
            name,
            uuid,
            oids,
            primary_fp,
            curve,
            certificate,
        })
    }

    pub fn unlock(&self, pin: &[u8]) -> Result<UnlockedKey> {
        match self.unlock_pair(pin, false) {
            Ok(k) => Ok(k),
            Err(primary_err) => match self.unlock_pair(pin, true) {
                Ok(k) => Ok(k),
                Err(backup_err) => Err(anyhow::anyhow!(
                    "primary pair failed: {primary_err:#}; backup pair failed: {backup_err:#}"
                )),
            },
        }
    }

    fn unlock_pair(&self, pin: &[u8], backup: bool) -> Result<UnlockedKey> {
        let (masks_name, primary_name, masks_raw, primary_raw) = if backup {
            (
                "masks2.key",
                "primary2.key",
                self.files
                    .masks2
                    .as_deref()
                    .context("masks2.key is absent")?,
                self.files
                    .primary2
                    .as_deref()
                    .context("primary2.key is absent")?,
            )
        } else {
            (
                "masks.key",
                "primary.key",
                self.files.masks.as_slice(),
                self.files.primary.as_slice(),
            )
        };

        let mask = parse_mask(masks_raw)?;
        let primary = Zeroizing::new(parse_primary(primary_raw)?);

        if mask.mask.len() != self.curve.bytes {
            bail!(
                "{} mask length {}, expected {}",
                masks_name,
                mask.mask.len(),
                self.curve.bytes
            );
        }
        if primary.len() != self.curve.bytes {
            bail!(
                "{} key length {}, expected {}",
                primary_name,
                primary.len(),
                self.curve.bytes
            );
        }
        if mask.salt.len() != 12 {
            bail!(
                "{} salt length {}, expected 12",
                masks_name,
                mask.salt.len()
            );
        }

        let storage_key = Zeroizing::new(cpkdf::derive_2012(pin, &mask.salt));
        let decrypted = Zeroizing::new(gost28147::decrypt_ecb(
            &storage_key,
            &primary,
            &gost28147::SBOX_TC26_Z,
        )?);
        drop(storage_key);
        drop(primary);

        // num-bigint cannot wipe its limbs; byte buffers are zeroized instead.
        let protected = BigUint::from_bytes_le(&decrypted);
        drop(decrypted);
        let mask_n = BigUint::from_bytes_le(&mask.mask);
        let d = curves::remove_mask(&self.curve, &protected, &mask_n)?;
        drop((protected, mask_n));
        let pubkey = curves::public_key(&self.curve, &d)?;
        let x_le = curves::le_fixed(&pubkey.x, self.curve.bytes);
        let y_le = curves::le_fixed(&pubkey.y, self.curve.bytes);

        if let Some(fp) = self.primary_fp {
            if x_le.get(..8) != Some(fp.as_slice()) {
                bail!("primaryFP mismatch (wrong PIN, unsupported variant, or damaged container)");
            }
        } else {
            bail!("header.key does not contain an 8-byte primaryFP [10]; refusing unverified private key");
        }

        Ok(UnlockedKey {
            private_le: curves::le_fixed(&d, self.curve.bytes),
            public_x_le: x_le,
            public_y_le: y_le,
            used_backup: backup,
        })
    }
}

// ---------------------------------------------------------------------------
// HDIMAGE create / CSR / install-cert
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CreateContainerParams<'a> {
    pub pin: &'a [u8],
    /// UUID string for name.key; generated when None.
    pub name: Option<&'a str>,
    /// Curve OID written into header (also used for keygen).
    pub curve_oid: &'a str,
    /// Optional not-after unix time for header attribute; default ≈ now+3y.
    pub not_after_unix: Option<i64>,
}

#[derive(Debug)]
pub struct CreatedContainer {
    pub files: ContainerFiles,
    pub uuid: String,
    pub public_x_le: Vec<u8>,
    pub public_y_le: Vec<u8>,
    pub curve_oid: String,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn pad_ff(mut der: Vec<u8>, size: usize) -> Vec<u8> {
    if der.len() > size {
        der.truncate(size);
        return der;
    }
    der.resize(size, 0xff);
    der
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

fn random_uuid_string() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    // RFC 4122 version 4 / variant 1 bits.
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

fn encode_name_key(uuid: &str) -> Vec<u8> {
    let der = cms_der::sequence(&[cms_der::ia5_string(uuid)]);
    pad_ff(der, NAME_FILE_SIZE)
}

fn encode_masks_primary(
    curve: &curves::Curve,
    private_le: &[u8],
    pin: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let d = BigUint::from_bytes_le(private_le);
    let mut mask_le = gost3410::generate_private_le(curve);
    // Ensure mask is non-zero mod q (generate_private_le already ensures that).
    let mask_n = BigUint::from_bytes_le(&mask_le);
    let protected = curves::apply_mask(curve, &d, &mask_n)?;
    let protected_le = curves::le_fixed(&protected, curve.bytes);

    let salt = random_bytes(12);
    let mut storage_key = cpkdf::derive_2012(pin, &salt);
    let ciphertext =
        gost28147::encrypt_ecb(&storage_key, &protected_le, &gost28147::SBOX_TC26_Z)?;
    storage_key.zeroize();

    let mut mask_key = [0u8; 32];
    if mask_le.len() != 32 {
        bail!("masks MAC currently supports 256-bit containers only");
    }
    mask_key.copy_from_slice(&mask_le);
    let mac = gost28147::mac_imit4(&mask_key, &salt, &gost28147::SBOX_TC26_Z);
    mask_key.fill(0);

    let masks_der = cms_der::sequence(&[
        cms_der::octet_string(&mask_le),
        cms_der::octet_string(&salt),
        cms_der::octet_string(&mac),
    ]);
    mask_le.zeroize();
    let primary_der = cms_der::sequence(&[cms_der::octet_string(&ciphertext)]);
    Ok((
        pad_ff(masks_der, MASKS_FILE_SIZE),
        pad_ff(primary_der, PRIMARY_FILE_SIZE),
    ))
}

fn build_header_without_cert(
    curve_oid: &str,
    primary_fp: &[u8; 8],
    not_after_unix: i64,
) -> Result<Vec<u8>> {
    // Layout mirrored from CryptoPro classic containers (e.g. roman/header.key).
    let alg_params = cms_der::sequence(&[
        cms_der::oid(curve_oid)?,
        cms_der::oid(cades::OID_DIGEST_256)?,
    ]);
    let private_key_alg = cms_der::context_constructed(
        0,
        &cms_der::concat(&[cms_der::oid(OID_PRIVATE_KEY_2012_256)?, alg_params]),
    );
    let key_params = cms_der::sequence(&[cms_der::tlv(0x03, &[0x00]), private_key_alg]);

    let gt = cms_der::generalized_time(not_after_unix)?;
    let (_, gt_body) = cms_der::split_tlv(&gt)?;
    let stamped = cms_der::sequence(&[cms_der::tlv(0x81, gt_body)]);
    let attr = cms_der::sequence(&[
        cms_der::oid(OID_ATTR_NOT_AFTER)?,
        cms_der::octet_string(&stamped),
    ]);
    let (_, attr_body) = cms_der::split_tlv(&attr)?;

    let content = cms_der::concat(&[
        cms_der::context_constructed(0, &cms_der::oid(OID_CONTAINER_BLOB)?),
        // CryptoPro flag BIT STRING: unused_bits=6, value 0x40.
        cms_der::tlv(0x03, &[0x06, 0x40]),
        key_params,
        cms_der::context_primitive(2, &[0, 0, 0, 0]),
        cms_der::context_primitive(10, primary_fp),
        cms_der::tlv(0xac, attr_body),
    ]);
    let inner = cms_der::tlv(0x30, &content);
    let trailer = cms_der::octet_string(&[0, 0, 0, 0]);
    Ok(cms_der::sequence(&[inner, trailer]))
}

/// Create a new GOST 2012-256 classic container (HDIMAGE files in memory).
pub fn create_container(p: &CreateContainerParams<'_>) -> Result<CreatedContainer> {
    let curve = curves::by_oid(p.curve_oid)
        .with_context(|| format!("unsupported curve OID {}", p.curve_oid))?;
    if curve.bytes != 32 {
        bail!("hdimage create currently supports 256-bit curves only");
    }

    let uuid = match p.name {
        Some(n) => {
            if !looks_like_uuid(n) {
                bail!("--name must be a UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)");
            }
            n.to_ascii_lowercase()
        }
        None => random_uuid_string(),
    };

    let mut private_le = gost3410::generate_private_le(&curve);
    let d = BigUint::from_bytes_le(&private_le);
    let pubkey = curves::public_key(&curve, &d)?;
    let public_x_le = curves::le_fixed(&pubkey.x, curve.bytes);
    let public_y_le = curves::le_fixed(&pubkey.y, curve.bytes);
    let mut primary_fp = [0u8; 8];
    primary_fp.copy_from_slice(&public_x_le[..8]);

    let (masks, primary) = encode_masks_primary(&curve, &private_le, p.pin)?;
    let (masks2, primary2) = encode_masks_primary(&curve, &private_le, p.pin)?;
    private_le.zeroize();

    let not_after = p.not_after_unix.unwrap_or_else(|| unix_now() + 3 * 365 * 24 * 3600);
    // Prefer CryptoPro legacy OID in header when the logical curve is CryptoPro-A.
    let header_curve_oid = if p.curve_oid == "1.2.643.7.1.2.1.1.2" {
        "1.2.643.2.2.36.0"
    } else {
        p.curve_oid
    };
    let header = build_header_without_cert(header_curve_oid, &primary_fp, not_after)?;
    let name = encode_name_key(&uuid);

    Ok(CreatedContainer {
        files: ContainerFiles {
            header,
            masks,
            masks2: Some(masks2),
            name: Some(name),
            primary,
            primary2: Some(primary2),
        },
        uuid,
        public_x_le,
        public_y_le,
        curve_oid: header_curve_oid.to_string(),
    })
}

/// Build a PKCS#10 CertificationRequest DER for the unlocked container key.
pub fn build_certificate_request(
    curve: &curves::Curve,
    private_le: &[u8],
    public_x_le: &[u8],
    public_y_le: &[u8],
    subject_cn: &str,
) -> Result<Vec<u8>> {
    let mut xy = public_x_le.to_vec();
    xy.extend_from_slice(public_y_le);
    let digest_oid = if curve.bytes == 32 {
        cades::OID_DIGEST_256
    } else {
        cades::OID_DIGEST_512
    };
    let sign_oid = if curve.bytes == 32 {
        cades::OID_SIGN_256
    } else {
        cades::OID_SIGN_512
    };
    let public_key_alg = cms_der::sequence(&[
        cms_der::oid(sign_oid)?,
        cms_der::sequence(&[cms_der::oid(curve.oid)?, cms_der::oid(digest_oid)?]),
    ]);
    let spki = cms_der::sequence(&[
        public_key_alg,
        cms_der::bit_string(&cms_der::octet_string(&xy)),
    ]);
    let cn_atv = cms_der::sequence(&[
        cms_der::oid("2.5.4.3")?,
        cms_der::utf8_string(subject_cn),
    ]);
    let subject = cms_der::sequence(&[cms_der::set(vec![cn_atv])]);
    let cri = cms_der::sequence(&[
        cms_der::integer_u8(0),
        subject,
        spki,
        cms_der::tlv(0xa0, &[]), // attributes [0] IMPLICIT empty
    ]);

    let mut hasher = Streebog256::new();
    hasher.update(&cri);
    let digest = hasher.finalize().to_vec();
    let signature = gost3410::sign_digest(curve, private_le, &digest)?;

    // CryptoPro CSRs commonly use the signWithDigest OID for signatureAlgorithm.
    let sig_alg = if curve.bytes == 32 {
        cms_der::algorithm_identifier("1.2.643.7.1.1.3.2")?
    } else {
        cms_der::algorithm_identifier("1.2.643.7.1.1.3.3")?
    };
    Ok(cms_der::sequence(&[
        cri,
        sig_alg,
        cms_der::bit_string(&signature),
    ]))
}

fn load_cert_bytes(path: &Path) -> Result<Vec<u8>> {
    let raw = fs::read(path).with_context(|| format!("read certificate {}", path.display()))?;
    if let Some(der) = pem_to_der(&raw) {
        return Ok(der);
    }
    if x509::find_certificate(&raw).is_some() || looks_like_raw_cert(&raw) {
        return Ok(raw);
    }
    bail!("certificate file is neither PEM nor DER X.509");
}

fn looks_like_raw_cert(raw: &[u8]) -> bool {
    der::parse_tlv(raw)
        .ok()
        .map(|t| t.tag == 0x30 && t.total_len == raw.len())
        .unwrap_or(false)
}

fn pem_to_der(raw: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(raw).ok()?;
    let start = text.find("-----BEGIN CERTIFICATE-----")?;
    let end = text.find("-----END CERTIFICATE-----")?;
    let b64: String = text[start..end]
        .lines()
        .skip(1)
        .map(str::trim)
        .collect();
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

/// Embed an issued X.509 certificate into `header.key` (`[5]` / tag 0x85).
///
/// Verifies that the certificate public key matches the container `primaryFP`
/// (and, when `pin` is provided, the unlocked public key).
pub fn install_certificate(
    files: &mut ContainerFiles,
    cert_der: &[u8],
    pin: Option<&[u8]>,
) -> Result<()> {
    let identity = x509::identity(cert_der).context("parse certificate to install")?;
    let fp = der::find_context_primitive(&files.header, 0x8a, 8)
        .context("header.key missing primaryFP [10]")?;
    if identity.public_x_le.get(..8) != Some(fp) {
        bail!("certificate public key does not match container primaryFP");
    }

    if let Some(pin) = pin {
        let c = ClassicContainer::from_files(files.clone())?;
        let unlocked = c.unlock(pin)?;
        if unlocked.public_x_le != identity.public_x_le
            || unlocked.public_y_le != identity.public_y_le
        {
            bail!("certificate public key does not match unlocked container key");
        }
    }

    files.header = embed_certificate_in_header(&files.header, cert_der)?;
    Ok(())
}

fn embed_certificate_in_header(header: &[u8], cert_der: &[u8]) -> Result<Vec<u8>> {
    let outer = der::parse_tlv(header).context("parse header.key")?;
    if outer.tag != 0x30 {
        bail!("header.key is not a SEQUENCE");
    }
    let outer_children = der::children(outer.value)?;
    let inner = outer_children
        .first()
        .context("header.key missing inner SEQUENCE")?;
    if inner.tag != 0x30 {
        bail!("header.key inner value is not a SEQUENCE");
    }
    let trailer = outer_children.get(1).map(|t| {
        let mut enc = Vec::new();
        enc.push(t.tag);
        // Re-encode length+value from original slice: use raw TLV from header.
        // Safer: rebuild octet string from value.
        cms_der::tlv(t.tag, t.value)
    });

    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut inserted = false;
    for child in der::children(inner.value)? {
        if child.tag == 0x85 {
            continue; // replace existing cert
        }
        // Insert cert immediately before primaryFP [10] / 0x8a.
        if child.tag == 0x8a && !inserted {
            parts.push(cms_der::context_primitive(5, cert_der));
            inserted = true;
        }
        parts.push(cms_der::tlv(child.tag, child.value));
    }
    if !inserted {
        parts.push(cms_der::context_primitive(5, cert_der));
    }
    let new_inner = cms_der::sequence(&parts);
    let mut out_parts = vec![new_inner];
    if let Some(t) = trailer {
        out_parts.push(t);
    } else {
        out_parts.push(cms_der::octet_string(&[0, 0, 0, 0]));
    }
    Ok(cms_der::sequence(&out_parts))
}

/// Read PEM or DER certificate from `path`.
pub fn read_certificate_file(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    load_cert_bytes(path.as_ref())
}

#[cfg(test)]
fn fake_cert_for_tests(curve: &curves::Curve, x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut xy = x.to_vec();
    xy.extend_from_slice(y);
    let public_key_alg = cms_der::sequence(&[
        cms_der::oid(cades::OID_SIGN_256).unwrap(),
        cms_der::sequence(&[
            cms_der::oid(curve.oid).unwrap(),
            cms_der::oid(cades::OID_DIGEST_256).unwrap(),
        ]),
    ]);
    let spki = cms_der::sequence(&[
        public_key_alg,
        cms_der::bit_string(&cms_der::octet_string(&xy)),
    ]);
    let empty_name = cms_der::sequence(&[]);
    let tbs = cms_der::sequence(&[
        cms_der::explicit0(&cms_der::integer_u8(2)),
        cms_der::integer_u8(1),
        cms_der::algorithm_identifier(cades::OID_SIGN_256).unwrap(),
        empty_name.clone(),
        cms_der::sequence(&[]),
        empty_name,
        spki,
    ]);
    cms_der::sequence(&[
        tbs,
        cms_der::algorithm_identifier(cades::OID_SIGN_256).unwrap(),
        cms_der::bit_string(&[0u8; 64]),
    ])
}

#[cfg(test)]
mod create_tests {
    use super::*;

    #[test]
    fn create_unlock_roundtrip() {
        let created = create_container(&CreateContainerParams {
            pin: b"test-pin",
            name: None,
            curve_oid: DEFAULT_CREATE_CURVE_OID,
            not_after_unix: None,
        })
        .unwrap();
        assert!(looks_like_uuid(&created.uuid));
        let c = ClassicContainer::from_files(created.files.clone()).unwrap();
        assert!(c.certificate.is_none());
        let unlocked = c.unlock(b"test-pin").unwrap();
        assert_eq!(unlocked.public_x_le, created.public_x_le);
        assert_eq!(unlocked.public_y_le, created.public_y_le);
        assert!(!unlocked.used_backup);
    }

    #[test]
    fn install_cert_then_sign_bes() {
        let pin = b"pin";
        let mut created = create_container(&CreateContainerParams {
            pin,
            name: Some("11111111-2222-4333-8444-555555555555"),
            curve_oid: DEFAULT_CREATE_CURVE_OID,
            not_after_unix: Some(1_900_000_000),
        })
        .unwrap();
        let curve = curves::by_oid(DEFAULT_CREATE_CURVE_OID).unwrap();
        let cert = fake_cert_for_tests(&curve, &created.public_x_le, &created.public_y_le);
        install_certificate(&mut created.files, &cert, Some(pin)).unwrap();

        let c = ClassicContainer::from_files(created.files.clone()).unwrap();
        assert!(c.certificate.is_some());
        let mut key = c.unlock(pin).unwrap();

        let signed = cades::sign_bes(
            b"hdimage create smoke",
            c.certificate.as_ref().unwrap(),
            &curve,
            &key.private_le,
            &key.public_x_le,
            &key.public_y_le,
            true,
        )
        .unwrap();
        key.private_le.zeroize();
        let v = cades::verify(&signed.der, Some(b"hdimage create smoke")).unwrap();
        assert!(v.signature_valid);
        assert!(v.message_digest_valid);
    }

    #[test]
    fn certificate_request_has_signature() {
        let created = create_container(&CreateContainerParams {
            pin: b"x",
            name: None,
            curve_oid: DEFAULT_CREATE_CURVE_OID,
            not_after_unix: None,
        })
        .unwrap();
        let c = ClassicContainer::from_files(created.files).unwrap();
        let mut key = c.unlock(b"x").unwrap();
        let csr = build_certificate_request(
            &c.curve,
            &key.private_le,
            &key.public_x_le,
            &key.public_y_le,
            "Jex Test",
        )
        .unwrap();
        key.private_le.zeroize();
        let top = der::parse_tlv(&csr).unwrap();
        assert_eq!(top.tag, 0x30);
        assert!(csr.len() > 100);
        assert!(der::collect_oids(&csr)
            .iter()
            .any(|o| o == "1.2.643.7.1.1.3.2"));
    }
}

#[cfg(test)]
mod uuid_tests {
    use super::*;

    #[test]
    fn extract_uuid_from_context_tag() {
        let uuid_bytes = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let context_tag_89 = vec![0x89, 0x10]; // tag 0x89, length 16
        let mut header = context_tag_89;
        header.extend_from_slice(&uuid_bytes);

        let result = extract_container_uuid(&header);
        assert_eq!(
            result,
            Some("12345678-9abc-def0-fedc-ba9876543210".to_string())
        );
    }

    #[test]
    fn extract_uuid_returns_none_if_missing() {
        let header = vec![0x06, 0x04, 0x01, 0x02, 0x03, 0x04]; // Some other tag
        let result = extract_container_uuid(&header);
        assert_eq!(result, None);
    }

    #[test]
    fn resolve_uuid_prefers_uuid_shaped_name() {
        let name = "b35fb6a4-2d0a-432b-987d-ba142db3e574";
        let header: &[u8] = &[]; // header not consulted when name is UUID-shaped
        assert_eq!(resolve_uuid(Some(name), header), Some(name.to_string()));
    }

    #[test]
    fn resolve_uuid_falls_back_to_header_when_name_is_not_uuid_shaped() {
        let uuid_bytes = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut header = vec![0x89, 0x10];
        header.extend_from_slice(&uuid_bytes);
        assert_eq!(
            resolve_uuid(Some("Мой контейнер"), &header),
            Some("12345678-9abc-def0-fedc-ba9876543210".to_string())
        );
        assert_eq!(
            resolve_uuid(None, &header),
            Some("12345678-9abc-def0-fedc-ba9876543210".to_string())
        );
    }
}

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn parse_name_accepts_bare_ia5string() {
        let raw = [0x16, 0x04, b't', b'e', b's', b't'];
        assert_eq!(parse_name(&raw).as_deref(), Some("test"));
    }

    #[test]
    fn parse_name_accepts_sequence_of_strings() {
        // SEQUENCE { IA5String "demo" }
        let raw = [0x30, 0x06, 0x16, 0x04, b'd', b'e', b'm', b'o'];
        assert_eq!(parse_name(&raw).as_deref(), Some("demo"));
    }

    #[test]
    fn parse_name_or_hex_returns_string_on_success() {
        let raw = [0x16, 0x04, b't', b'e', b's', b't'];
        let result = parse_name_or_hex(&raw);
        assert_eq!(result, "test");
    }

    #[test]
    fn parse_name_or_hex_returns_diagnostic_on_invalid_der() {
        let raw = [0xFF, 0xFF];
        let result = parse_name_or_hex(&raw);
        assert!(result.contains("invalid DER") || result.contains("unparseable"));
        assert!(result.contains("ffff"));
    }

    #[test]
    fn parse_name_or_hex_shows_tag_name_when_possible() {
        let raw = [0x30, 0x00]; // Empty SEQUENCE
        let result = parse_name_or_hex(&raw);
        assert!(result.contains("unparseable") && result.contains("SEQUENCE"));
    }
}

#[cfg(test)]
mod dump_dir_tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn discovers_dump_subdirectories() {
        let root = std::env::temp_dir().join(format!("jex-discover-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("alpha")).unwrap();
        fs::create_dir_all(root.join("beta")).unwrap();
        fs::create_dir_all(root.join("noise")).unwrap();
        for name in ["alpha", "beta"] {
            for file in ["header.key", "masks.key", "primary.key"] {
                fs::File::create(root.join(name).join(file))
                    .unwrap()
                    .write_all(b"x")
                    .unwrap();
            }
        }

        let found = discover_dump_dirs(&root).unwrap();
        assert_eq!(found, vec![root.join("alpha"), root.join("beta")],);

        let _ = fs::remove_dir_all(&root);
    }
}
