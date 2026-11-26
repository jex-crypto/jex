// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use crate::{curves, der, gost3410};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use streebog::{Digest, Streebog256, Streebog512};

#[derive(Clone, Debug)]
pub struct CertIdentity {
    /// Complete DER Name TLV copied from TBSCertificate.issuer.
    pub issuer_der: Vec<u8>,
    /// Complete DER INTEGER TLV copied from TBSCertificate.serialNumber.
    pub serial_der: Vec<u8>,
    /// Complete DER Name TLV copied from TBSCertificate.subject.
    pub subject_der: Vec<u8>,
    /// GOST curve OID from SubjectPublicKeyInfo parameters.
    pub curve_oid: String,
    /// Subject public key coordinates in RFC 9215 wire form (little-endian).
    pub public_x_le: Vec<u8>,
    pub public_y_le: Vec<u8>,
}

/// Subject public key from an X.509 certificate (GOST, RSA, or ECDSA P-256).
#[derive(Clone, Debug)]
pub enum SubjectPublicKey {
    Gost {
        curve_oid: String,
        public_x_le: Vec<u8>,
        public_y_le: Vec<u8>,
    },
    Rsa {
        /// UNSIGNED big-endian modulus bytes (DER INTEGER content, may include leading 0x00).
        modulus: Vec<u8>,
        /// UNSIGNED big-endian public exponent bytes.
        exponent: Vec<u8>,
    },
    /// NIST P-256 / secp256r1 uncompressed SEC1 point (`0x04 || X || Y`).
    EcP256 { uncompressed: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct CertNames {
    pub issuer_der: Vec<u8>,
    pub subject_der: Vec<u8>,
    pub serial_der: Vec<u8>,
}

pub fn names(cert_der: &[u8]) -> Result<CertNames> {
    let top = der::parse_tlv(cert_der).context("parse certificate")?;
    if top.tag != 0x30 || top.total_len != cert_der.len() {
        bail!("certificate is not one complete DER SEQUENCE");
    }
    let cert_parts = raw_children(top.value)?;
    if cert_parts.len() != 3 {
        bail!(
            "unexpected Certificate layout: {} top-level fields",
            cert_parts.len()
        );
    }
    let tbs = der::parse_tlv(cert_parts[0]).context("parse TBSCertificate")?;
    if tbs.tag != 0x30 {
        bail!("TBSCertificate is not a SEQUENCE");
    }
    let tbs_parts = raw_children(tbs.value)?;
    let base = if tbs_parts.first().and_then(|r| r.first()).copied() == Some(0xA0) {
        1
    } else {
        0
    };
    if tbs_parts.len() <= base + 4 {
        bail!("truncated TBSCertificate");
    }
    if tbs_parts[base].first().copied() != Some(0x02) {
        bail!("TBSCertificate serialNumber is not INTEGER");
    }
    Ok(CertNames {
        serial_der: tbs_parts[base].to_vec(),
        issuer_der: tbs_parts[base + 2].to_vec(),
        subject_der: tbs_parts[base + 4].to_vec(),
    })
}

/// Strip leading zero bytes from a DER INTEGER value (or full INTEGER TLV).
/// Used when matching IssuerAndSerialNumber across independently encoded fields.
pub(crate) fn integer_normalized(raw: &[u8]) -> Result<Vec<u8>> {
    let t = der::parse_tlv(raw)?;
    if t.tag != 0x02 {
        bail!("expected INTEGER");
    }
    let mut v = t.value;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    Ok(v.to_vec())
}

/// Match `issuerAndSerialNumber` against an X.509 certificate.
pub(crate) fn issuer_serial_matches(
    cert_der: &[u8],
    issuer_der: &[u8],
    serial_der: &[u8],
) -> Result<bool> {
    let names = names(cert_der)?;
    Ok(names.issuer_der.as_slice() == issuer_der
        && integer_normalized(&names.serial_der)? == integer_normalized(serial_der)?)
}

pub fn find_certificate(input: &[u8]) -> Option<Vec<u8>> {
    fn walk(buf: &[u8]) -> Option<Vec<u8>> {
        let mut rest = buf;
        while !rest.is_empty() {
            let tlv = der::parse_tlv(rest).ok()?;
            let raw = &rest[..tlv.total_len];
            if tlv.tag == 0x30 && looks_like_certificate(raw) {
                return Some(raw.to_vec());
            }
            if tlv.tag & 0x20 != 0 {
                if let Some(found) = walk(tlv.value) {
                    return Some(found);
                }
            }
            rest = rest.get(tlv.total_len..)?;
        }
        None
    }

    if let Some(cert) = walk(input) {
        return Some(cert);
    }

    // CryptoPro headers can wrap a certificate inside proprietary fields.
    // A conservative byte scan lets us recover a complete DER Certificate
    // without depending on the surrounding container ASN.1 schema.
    for offset in 0..input.len() {
        if input[offset] != 0x30 {
            continue;
        }
        let Ok(tlv) = der::parse_tlv(&input[offset..]) else {
            continue;
        };
        let end = offset.checked_add(tlv.total_len)?;
        if end > input.len() {
            continue;
        }
        let raw = &input[offset..end];
        if looks_like_certificate(raw) {
            return Some(raw.to_vec());
        }
    }
    None
}

fn looks_like_certificate(raw: &[u8]) -> bool {
    let Ok(top) = der::parse_tlv(raw) else {
        return false;
    };
    if top.tag != 0x30 || top.total_len != raw.len() {
        return false;
    }
    let Ok(children) = der::children(top.value) else {
        return false;
    };
    if children.len() != 3
        || children[0].tag != 0x30
        || children[1].tag != 0x30
        || children[2].tag != 0x03
    {
        return false;
    }
    der::children(children[0].value)
        .map(|v| v.len() >= 6)
        .unwrap_or(false)
}

pub fn identity(cert_der: &[u8]) -> Result<CertIdentity> {
    let names = names(cert_der)?;
    match subject_public_key(cert_der)? {
        SubjectPublicKey::Gost {
            curve_oid,
            public_x_le,
            public_y_le,
        } => Ok(CertIdentity {
            issuer_der: names.issuer_der,
            serial_der: names.serial_der,
            subject_der: names.subject_der,
            curve_oid,
            public_x_le,
            public_y_le,
        }),
        SubjectPublicKey::Rsa { .. } => {
            bail!("certificate uses RSA; use subject_public_key() for non-GOST keys")
        }
        SubjectPublicKey::EcP256 { .. } => {
            bail!("certificate uses ECDSA P-256; use subject_public_key() for non-GOST keys")
        }
    }
}

/// Parse SubjectPublicKeyInfo from a certificate (GOST, RSA, or NIST P-256).
pub fn subject_public_key(cert_der: &[u8]) -> Result<SubjectPublicKey> {
    let top = der::parse_tlv(cert_der).context("parse certificate")?;
    if top.tag != 0x30 || top.total_len != cert_der.len() {
        bail!("certificate is not one complete DER SEQUENCE");
    }
    let cert_parts = raw_children(top.value)?;
    if cert_parts.len() != 3 {
        bail!(
            "unexpected Certificate layout: {} top-level fields",
            cert_parts.len()
        );
    }
    let tbs = der::parse_tlv(cert_parts[0]).context("parse TBSCertificate")?;
    if tbs.tag != 0x30 {
        bail!("TBSCertificate is not a SEQUENCE");
    }
    let tbs_parts = raw_children(tbs.value)?;
    let base = if tbs_parts.first().and_then(|r| r.first()).copied() == Some(0xA0) {
        1
    } else {
        0
    };
    if tbs_parts.len() <= base + 5 {
        bail!("truncated TBSCertificate");
    }
    if tbs_parts[base].first().copied() != Some(0x02) {
        bail!("TBSCertificate serialNumber is not INTEGER");
    }
    parse_spki(tbs_parts[base + 5])
}

fn parse_spki(spki_der: &[u8]) -> Result<SubjectPublicKey> {
    let spki = der::parse_tlv(spki_der).context("parse SubjectPublicKeyInfo")?;
    if spki.tag != 0x30 {
        bail!("SubjectPublicKeyInfo is not a SEQUENCE");
    }
    let parts = raw_children(spki.value)?;
    if parts.len() != 2 {
        bail!("unexpected SubjectPublicKeyInfo layout");
    }

    let alg = der::parse_tlv(parts[0]).context("parse SPKI algorithm")?;
    if alg.tag != 0x30 {
        bail!("SPKI algorithm is not AlgorithmIdentifier");
    }
    let alg_parts = raw_children(alg.value)?;
    let alg_oid_tlv = der::parse_tlv(*alg_parts.first().context("missing algorithm OID")?)?;
    if alg_oid_tlv.tag != 0x06 {
        bail!("algorithm OID is not OBJECT IDENTIFIER");
    }
    let alg_oid = der::decode_oid(alg_oid_tlv.value).context("decode algorithm OID")?;

    let bits = der::parse_tlv(parts[1]).context("parse subjectPublicKey BIT STRING")?;
    if bits.tag != 0x03 || bits.value.first().copied() != Some(0) {
        bail!("unsupported subjectPublicKey BIT STRING");
    }
    let payload = &bits.value[1..];

    // GOST R 34.10-2012: curve OID lives in parameters; key is X||Y (LE) often wrapped in OCTET STRING.
    if let Some(curve_oid) = der::collect_oids(spki_der)
        .into_iter()
        .find(|oid| curves::by_oid(oid).is_some())
    {
        let curve = curves::by_oid(&curve_oid).expect("OID was just checked");
        let (public_x_le, public_y_le) = gost_spki_coordinates(payload, curve.bytes)?;
        return Ok(SubjectPublicKey::Gost {
            curve_oid,
            public_x_le,
            public_y_le,
        });
    }

    match alg_oid.as_str() {
        "1.2.840.113549.1.1.1" => {
            let rsa = der::parse_tlv(payload).context("parse RSAPublicKey")?;
            if rsa.tag != 0x30 {
                bail!("RSAPublicKey is not a SEQUENCE");
            }
            let rf = raw_children(rsa.value)?;
            if rf.len() != 2 {
                bail!("unexpected RSAPublicKey layout");
            }
            let n = der::parse_tlv(rf[0])?;
            let e = der::parse_tlv(rf[1])?;
            if n.tag != 0x02 || e.tag != 0x02 {
                bail!("RSAPublicKey n/e are not INTEGER");
            }
            Ok(SubjectPublicKey::Rsa {
                modulus: n.value.to_vec(),
                exponent: e.value.to_vec(),
            })
        }
        "1.2.840.10045.2.1" => {
            let curve = alg_parts
                .get(1)
                .and_then(|r| der::parse_tlv(r).ok())
                .filter(|t| t.tag == 0x06)
                .and_then(|t| der::decode_oid(t.value))
                .context("EC SubjectPublicKeyInfo missing namedCurve")?;
            if curve != "1.2.840.10045.3.1.7" {
                bail!("unsupported EC curve {curve} (only NIST P-256 / secp256r1)");
            }
            if payload.len() != 65 || payload[0] != 0x04 {
                bail!(
                    "ECDSA P-256 public key must be uncompressed SEC1 (65 bytes), got {}",
                    payload.len()
                );
            }
            Ok(SubjectPublicKey::EcP256 {
                uncompressed: payload.to_vec(),
            })
        }
        other => bail!("unsupported SubjectPublicKeyInfo algorithm {other}"),
    }
}

fn gost_spki_coordinates(payload: &[u8], coordinate_bytes: usize) -> Result<(Vec<u8>, Vec<u8>)> {
    // RFC 9215 encodes GostR3410-2012-PublicKey as an OCTET STRING inside
    // subjectPublicKey. Be lenient and also accept a bare X||Y payload.
    let key = match der::parse_tlv(payload) {
        Ok(inner) if inner.tag == 0x04 && inner.total_len == payload.len() => inner.value,
        _ => payload,
    };
    if key.len() != coordinate_bytes * 2 {
        bail!(
            "GOST public key has {} bytes, expected {}",
            key.len(),
            coordinate_bytes * 2
        );
    }
    Ok((
        key[..coordinate_bytes].to_vec(),
        key[coordinate_bytes..].to_vec(),
    ))
}

pub fn raw_children(value: &[u8]) -> Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let tlv = der::parse_tlv(rest)?;
        out.push(&rest[..tlv.total_len]);
        rest = &rest[tlv.total_len..];
    }
    Ok(out)
}

#[derive(Clone, Debug)]
pub struct CertValidity {
    pub not_before: String,
    pub not_after: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
}

#[derive(Clone, Debug)]
pub struct CertCheck {
    pub validity: CertValidity,
    pub revocation_status: Option<RevocationCheckResult>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RevocationCheckResult {
    /// Certificate is not revoked (checked via OCSP)
    Good,
    /// Certificate is revoked
    Revoked { reason: Option<String> },
    /// Revocation status is unknown (CRL didn't list it or check failed)
    Unknown,
}

impl RevocationCheckResult {
    /// Short upper-case label used in table output.
    pub fn label(&self) -> String {
        match self {
            RevocationCheckResult::Good => "GOOD".to_string(),
            RevocationCheckResult::Revoked { reason: Some(r) } => format!("REVOKED ({r})"),
            RevocationCheckResult::Revoked { reason: None } => "REVOKED".to_string(),
            RevocationCheckResult::Unknown => "UNKNOWN".to_string(),
        }
    }
}

impl CertValidity {
    pub fn is_valid_at(&self, unix: i64) -> bool {
        unix >= self.not_before_unix && unix <= self.not_after_unix
    }
}

pub fn validity(cert_der: &[u8]) -> Result<CertValidity> {
    let top = der::parse_tlv(cert_der).context("parse certificate")?;
    if top.tag != 0x30 {
        bail!("certificate is not a SEQUENCE");
    }
    let cert_parts = raw_children(top.value)?;
    let tbs = der::parse_tlv(
        *cert_parts
            .first()
            .context("certificate missing TBSCertificate")?,
    )?;
    if tbs.tag != 0x30 {
        bail!("TBSCertificate is not a SEQUENCE");
    }
    let tbs_parts = raw_children(tbs.value)?;
    let base = if tbs_parts.first().and_then(|r| r.first()).copied() == Some(0xA0) {
        1
    } else {
        0
    };
    let validity_raw = *tbs_parts
        .get(base + 3)
        .context("TBSCertificate missing validity")?;
    let validity = der::parse_tlv(validity_raw)?;
    if validity.tag != 0x30 {
        bail!("Certificate.validity is not SEQUENCE");
    }
    let fields = raw_children(validity.value)?;
    if fields.len() != 2 {
        bail!("Certificate.validity must contain notBefore and notAfter");
    }
    let (not_before, not_before_unix) = parse_x509_time(fields[0])?;
    let (not_after, not_after_unix) = parse_x509_time(fields[1])?;
    Ok(CertValidity {
        not_before,
        not_after,
        not_before_unix,
        not_after_unix,
    })
}

fn parse_x509_time(raw: &[u8]) -> Result<(String, i64)> {
    let t = der::parse_tlv(raw)?;
    let s = std::str::from_utf8(t.value)
        .context("certificate time is not ASCII")?
        .to_string();
    let (year, rest) = match t.tag {
        0x17 => {
            // UTCTime YYMMDDHHMMSSZ
            if s.len() != 13 || !s.ends_with('Z') {
                bail!("unsupported UTCTime {s:?}");
            }
            let yy = parse_dec(&s[0..2])? as i32;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, &s[2..12])
        }
        0x18 => {
            // GeneralizedTime YYYYMMDDHHMMSSZ
            if s.len() != 15 || !s.ends_with('Z') {
                bail!("unsupported GeneralizedTime {s:?}");
            }
            (parse_dec(&s[0..4])? as i32, &s[4..14])
        }
        _ => bail!("unsupported certificate time tag 0x{:02X}", t.tag),
    };
    let month = parse_dec(&rest[0..2])? as u32;
    let day = parse_dec(&rest[2..4])? as u32;
    let hour = parse_dec(&rest[4..6])? as u32;
    let minute = parse_dec(&rest[6..8])? as u32;
    let second = parse_dec(&rest[8..10])? as u32;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        bail!("invalid certificate time {s:?}");
    }
    let days = days_from_civil(year, month, day);
    let unix = days * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second.min(59) as i64;
    let readable = format!("{:04}-{:02}-{:02}", year, month, day);
    Ok((readable, unix))
}

fn parse_dec(s: &str) -> Result<u32> {
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        bail!("non-decimal time component {s:?}");
    }
    s.parse::<u32>().context("parse decimal time component")
}
fn is_leap(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}
fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}
// Days since Unix epoch, Howard Hinnant's civil-date transform.
fn days_from_civil(mut y: i32, m: u32, d: u32) -> i64 {
    y -= if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146097 + doe as i64 - 719468
}

/// Return the DER payload of an X.509 extension's extnValue OCTET STRING.
pub fn extension_value<'a>(cert_der: &'a [u8], wanted_oid: &str) -> Result<Option<&'a [u8]>> {
    let top = der::parse_tlv(cert_der).context("parse certificate")?;
    if top.tag != 0x30 {
        bail!("certificate is not a SEQUENCE");
    }
    let cert_parts = raw_children(top.value)?;
    let tbs = der::parse_tlv(
        *cert_parts
            .first()
            .context("certificate missing TBSCertificate")?,
    )?;
    if tbs.tag != 0x30 {
        bail!("TBSCertificate is not a SEQUENCE");
    }
    let tbs_parts = raw_children(tbs.value)?;
    let Some(ext_wrapper_raw) = tbs_parts.iter().find(|r| r.first().copied() == Some(0xA3)) else {
        return Ok(None);
    };
    let ext_wrapper = der::parse_tlv(ext_wrapper_raw)?;
    let wrapped = raw_children(ext_wrapper.value)?;
    let extensions_raw = *wrapped.first().context("empty extensions [3] wrapper")?;
    let extensions = der::parse_tlv(extensions_raw)?;
    if extensions.tag != 0x30 {
        bail!("Extensions is not a SEQUENCE");
    }
    for ext_raw in raw_children(extensions.value)? {
        let ext = der::parse_tlv(ext_raw)?;
        if ext.tag != 0x30 {
            continue;
        }
        let f = raw_children(ext.value)?;
        if f.len() < 2 {
            continue;
        }
        let oid_tlv = der::parse_tlv(f[0])?;
        if oid_tlv.tag != 0x06 {
            continue;
        }
        let Some(oid) = der::decode_oid(oid_tlv.value) else {
            continue;
        };
        if oid != wanted_oid {
            continue;
        }
        let value_raw = *f.last().context("extension missing extnValue")?;
        let value = der::parse_tlv(value_raw)?;
        if value.tag != 0x04 {
            bail!("extension {wanted_oid} extnValue is not OCTET STRING");
        }
        return Ok(Some(value.value));
    }
    Ok(None)
}

/// RFC 6960 id-pkix-ocsp-nocheck extension. A delegated OCSP responder
/// carrying this extension does not require separate revocation evidence.
pub fn has_ocsp_nocheck(cert_der: &[u8]) -> Result<bool> {
    const OID_OCSP_NOCHECK: &str = "1.3.6.1.5.5.7.48.1.5";
    Ok(extension_value(cert_der, OID_OCSP_NOCHECK)?.is_some())
}

/// caIssuers HTTP(S) URIs from Authority Information Access.
pub fn aia_ca_issuers_urls(cert_der: &[u8]) -> Result<Vec<String>> {
    const OID_AIA: &str = "1.3.6.1.5.5.7.1.1";
    const OID_CA_ISSUERS: &str = "1.3.6.1.5.5.7.48.2";
    let Some(value) = extension_value(cert_der, OID_AIA)? else {
        return Ok(Vec::new());
    };
    let seq = der::parse_tlv(value).context("parse AuthorityInfoAccessSyntax")?;
    if seq.tag != 0x30 {
        bail!("AuthorityInfoAccessSyntax is not a SEQUENCE");
    }
    let mut out = Vec::new();
    for ad_raw in raw_children(seq.value)? {
        let ad = der::parse_tlv(ad_raw)?;
        if ad.tag != 0x30 {
            continue;
        }
        let f = raw_children(ad.value)?;
        if f.len() != 2 {
            continue;
        }
        let oid = der::parse_tlv(f[0])?;
        if oid.tag != 0x06 || der::decode_oid(oid.value).as_deref() != Some(OID_CA_ISSUERS) {
            continue;
        }
        let loc = der::parse_tlv(f[1])?;
        if loc.tag != 0x86 {
            continue;
        } // GeneralName.uniformResourceIdentifier [6] IA5String
        let Ok(url) = std::str::from_utf8(loc.value) else {
            continue;
        };
        if url.starts_with("http://") || url.starts_with("https://") {
            out.push(url.to_string());
        }
    }
    Ok(out)
}

/// HTTP(S) URIs from CRL Distribution Points. We intentionally ignore LDAP.
pub fn crl_distribution_urls(cert_der: &[u8]) -> Result<Vec<String>> {
    const OID_CRL_DP: &str = "2.5.29.31";
    let Some(value) = extension_value(cert_der, OID_CRL_DP)? else {
        return Ok(Vec::new());
    };
    fn walk(buf: &[u8], out: &mut Vec<String>) {
        let mut rest = buf;
        while !rest.is_empty() {
            let Ok(t) = der::parse_tlv(rest) else {
                break;
            };
            if t.tag == 0x86 {
                if let Ok(url) = std::str::from_utf8(t.value) {
                    if url.starts_with("http://") || url.starts_with("https://") {
                        out.push(url.to_string());
                    }
                }
            }
            if t.tag & 0x20 != 0 {
                walk(t.value, out);
            }
            if t.total_len == 0 || t.total_len > rest.len() {
                break;
            }
            rest = &rest[t.total_len..];
        }
    }
    let mut out = Vec::new();
    walk(value, &mut out);
    out.sort();
    out.dedup();
    Ok(out)
}

/// Issuer Name TLV of a DER X.509 CRL (CertificateList).
pub fn crl_issuer_der(crl_der: &[u8]) -> Result<Vec<u8>> {
    let top = der::parse_tlv(crl_der).context("parse CRL")?;
    if top.tag != 0x30 || top.total_len != crl_der.len() {
        bail!("CRL is not one complete CertificateList SEQUENCE");
    }
    let f = raw_children(top.value)?;
    let tbs_raw = *f.first().context("CRL missing tbsCertList")?;
    let tbs = der::parse_tlv(tbs_raw)?;
    if tbs.tag != 0x30 {
        bail!("TBSCertList is not a SEQUENCE");
    }
    let tf = raw_children(tbs.value)?;
    let base = if tf.first().and_then(|r| r.first()).copied() == Some(0x02) {
        1
    } else {
        0
    };
    let issuer = *tf.get(base + 1).context("TBSCertList missing issuer")?;
    if issuer.first().copied() != Some(0x30) {
        bail!("TBSCertList issuer is not Name");
    }
    Ok(issuer.to_vec())
}

/// Parse an RFC 3161 / ASN.1 GeneralizedTime of the common form
/// YYYYMMDDHHMMSS[.fraction]Z to Unix seconds.
pub fn generalized_time_to_unix(s: &str) -> Result<i64> {
    if !s.ends_with('Z') {
        bail!("unsupported GeneralizedTime without Z suffix: {s:?}");
    }
    let core = &s[..s.len() - 1];
    let main = core.split_once('.').map(|(a, _)| a).unwrap_or(core);
    if main.len() != 14 {
        bail!("unsupported GeneralizedTime {s:?}");
    }
    let year = parse_dec(&main[0..4])? as i32;
    let month = parse_dec(&main[4..6])? as u32;
    let day = parse_dec(&main[6..8])? as u32;
    let hour = parse_dec(&main[8..10])? as u32;
    let minute = parse_dec(&main[10..12])? as u32;
    let second = parse_dec(&main[12..14])? as u32;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        bail!("invalid GeneralizedTime {s:?}");
    }
    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second.min(59) as i64)
}

#[derive(Debug, Clone)]
pub struct CrlIdentifierParts {
    pub issuer_der: Vec<u8>,
    pub this_update_der: Vec<u8>,
    pub crl_number_der: Option<Vec<u8>>,
}

/// Extract the fields used by RFC 5126 CrlIdentifier. If CRLNumber is
/// present, crl_number_der is the complete INTEGER TLV from extnValue.
pub fn crl_identifier_parts(crl_der: &[u8]) -> Result<CrlIdentifierParts> {
    let top = der::parse_tlv(crl_der).context("parse CRL")?;
    if top.tag != 0x30 || top.total_len != crl_der.len() {
        bail!("CRL is not one complete CertificateList SEQUENCE");
    }
    let f = raw_children(top.value)?;
    let tbs_raw = *f.first().context("CRL missing tbsCertList")?;
    let tbs = der::parse_tlv(tbs_raw)?;
    if tbs.tag != 0x30 {
        bail!("TBSCertList is not a SEQUENCE");
    }
    let tf = raw_children(tbs.value)?;
    let base = if tf.first().and_then(|r| r.first()).copied() == Some(0x02) {
        1
    } else {
        0
    };
    let issuer = *tf.get(base + 1).context("TBSCertList missing issuer")?;
    let this_update = *tf.get(base + 2).context("TBSCertList missing thisUpdate")?;
    let time = der::parse_tlv(this_update)?;
    if time.tag != 0x17 && time.tag != 0x18 {
        bail!("TBSCertList.thisUpdate is not Time");
    }

    let mut crl_number_der = None;
    if let Some(ext_wrapper_raw) = tf.iter().find(|r| r.first().copied() == Some(0xA0)) {
        let ext_wrapper = der::parse_tlv(ext_wrapper_raw)?;
        let wrapped = raw_children(ext_wrapper.value)?;
        if let Some(exts_raw) = wrapped.first() {
            let exts = der::parse_tlv(exts_raw)?;
            if exts.tag == 0x30 {
                for ext_raw in raw_children(exts.value)? {
                    let ext = der::parse_tlv(ext_raw)?;
                    if ext.tag != 0x30 {
                        continue;
                    }
                    let ef = raw_children(ext.value)?;
                    if ef.len() < 2 {
                        continue;
                    }
                    let oid_tlv = der::parse_tlv(ef[0])?;
                    if oid_tlv.tag != 0x06
                        || der::decode_oid(oid_tlv.value).as_deref() != Some("2.5.29.20")
                    {
                        continue;
                    }
                    let value_raw = *ef.last().context("CRLNumber extension missing extnValue")?;
                    let value = der::parse_tlv(value_raw)?;
                    if value.tag != 0x04 {
                        bail!("CRLNumber extnValue is not OCTET STRING");
                    }
                    let integer = der::parse_tlv(value.value)?;
                    if integer.tag != 0x02 || integer.total_len != value.value.len() {
                        bail!("CRLNumber extnValue is not one INTEGER");
                    }
                    crl_number_der = Some(value.value.to_vec());
                    break;
                }
            }
        }
    }
    Ok(CrlIdentifierParts {
        issuer_der: issuer.to_vec(),
        this_update_der: this_update.to_vec(),
        crl_number_der,
    })
}

#[cfg(test)]
mod validity_tests {
    use super::*;

    #[test]
    fn unix_epoch_date_math() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
    }
}

/// OCSP responder HTTP(S) URIs from Authority Information Access.
pub fn aia_ocsp_urls(cert_der: &[u8]) -> Result<Vec<String>> {
    const OID_AIA: &str = "1.3.6.1.5.5.7.1.1";
    const OID_OCSP: &str = "1.3.6.1.5.5.7.48.1";
    let Some(value) = extension_value(cert_der, OID_AIA)? else {
        return Ok(Vec::new());
    };
    let seq = der::parse_tlv(value).context("parse AuthorityInfoAccessSyntax")?;
    if seq.tag != 0x30 {
        bail!("AuthorityInfoAccessSyntax is not a SEQUENCE");
    }
    let mut out = Vec::new();
    for ad_raw in raw_children(seq.value)? {
        let ad = der::parse_tlv(ad_raw)?;
        if ad.tag != 0x30 {
            continue;
        }
        let f = raw_children(ad.value)?;
        if f.len() != 2 {
            continue;
        }
        let oid = der::parse_tlv(f[0])?;
        if oid.tag != 0x06 || der::decode_oid(oid.value).as_deref() != Some(OID_OCSP) {
            continue;
        }
        let loc = der::parse_tlv(f[1])?;
        if loc.tag != 0x86 {
            continue;
        }
        let Ok(url) = std::str::from_utf8(loc.value) else {
            continue;
        };
        if url.starts_with("http://") || url.starts_with("https://") {
            out.push(url.to_string());
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// One AttributeTypeAndValue from an X.509 Name (RDNSequence).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameAttr {
    pub oid: String,
    /// Short display label (`CN`, `INN`, `OGRNIP`, …); falls back to the OID.
    pub label: String,
    pub value: String,
}

/// Extract Common Name (CN) from certificate Subject Name.
/// Returns None if not found.
pub fn extract_subject_cn(cert_der: &[u8]) -> Result<Option<String>> {
    Ok(subject_name_attributes(cert_der)?
        .into_iter()
        .find(|a| a.oid == "2.5.4.3")
        .map(|a| a.value))
}

/// Subject RDN attributes in certificate order.
pub fn subject_name_attributes(cert_der: &[u8]) -> Result<Vec<NameAttr>> {
    let n = names(cert_der)?;
    name_attributes(&n.subject_der)
}

/// Issuer RDN attributes in certificate order.
pub fn issuer_name_attributes(cert_der: &[u8]) -> Result<Vec<NameAttr>> {
    let n = names(cert_der)?;
    name_attributes(&n.issuer_der)
}

/// Parse an X.509 Name (full DER Name TLV) into ordered attribute pairs.
pub fn name_attributes(name_der: &[u8]) -> Result<Vec<NameAttr>> {
    let name = der::parse_tlv(name_der)?;
    if name.tag != 0x30 {
        bail!("RDNSequence is not a SEQUENCE");
    }
    let mut out = Vec::new();
    for rdn_raw in raw_children(name.value)? {
        let rdn = der::parse_tlv(rdn_raw)?;
        if rdn.tag != 0x31 {
            continue;
        }
        for attr_raw in raw_children(rdn.value)? {
            let attr = der::parse_tlv(attr_raw)?;
            if attr.tag != 0x30 {
                continue;
            }
            let parts = raw_children(attr.value)?;
            if parts.len() != 2 {
                continue;
            }
            let oid_tlv = der::parse_tlv(parts[0])?;
            if oid_tlv.tag != 0x06 {
                continue;
            }
            let Some(oid) = der::decode_oid(oid_tlv.value) else {
                continue;
            };
            let value_tlv = der::parse_tlv(parts[1])?;
            let Some(value) = directory_string_value(value_tlv.tag, value_tlv.value) else {
                continue;
            };
            let label = rdn_attr_label(&oid).unwrap_or(oid.as_str()).to_string();
            out.push(NameAttr { oid, label, value });
        }
    }
    Ok(out)
}

fn directory_string_value(tag: u8, value: &[u8]) -> Option<String> {
    match tag {
        // NumericString, PrintableString, TeletexString, IA5String, UTF8String
        0x12 | 0x13 | 0x14 | 0x16 | 0x0C => String::from_utf8(value.to_vec()).ok(),
        // BMPString (UTF-16BE)
        0x1E if value.len() % 2 == 0 => {
            let units: Vec<u16> = value
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

fn rdn_attr_label(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.42" => "GN",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "T",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "1.2.840.113549.1.9.1" => "email",
        "1.2.643.3.131.1.1" => "INN",
        "1.2.643.100.4" => "INNLE",
        "1.2.643.100.1" => "OGRN",
        "1.2.643.100.5" => "OGRNIP",
        "1.2.643.100.3" => "SNILS",
        _ => return None,
    })
}

/// Prefer CN; otherwise SN+GN; otherwise first attribute value.
pub fn display_name_from_attrs(attrs: &[NameAttr]) -> Option<String> {
    if let Some(cn) = attrs.iter().find(|a| a.oid == "2.5.4.3") {
        return Some(cn.value.clone());
    }
    let sn = attrs
        .iter()
        .find(|a| a.oid == "2.5.4.4")
        .map(|a| a.value.as_str());
    let gn = attrs
        .iter()
        .find(|a| a.oid == "2.5.4.42")
        .map(|a| a.value.as_str());
    match (sn, gn) {
        (Some(s), Some(g)) => Some(format!("{s} {g}")),
        (Some(s), None) => Some(s.to_string()),
        (None, Some(g)) => Some(g.to_string()),
        (None, None) => attrs.first().map(|a| a.value.clone()),
    }
}

#[cfg(test)]
mod name_attr_tests {
    use super::*;

    /// Minimal RDNSequence: CN=Test + INN=123456789012
    fn sample_name_der() -> Vec<u8> {
        // SEQUENCE {
        //   SET { SEQUENCE { OID 2.5.4.3, UTF8 "Test" } }
        //   SET { SEQUENCE { OID 1.2.643.3.131.1.1, NumericString "123456789012" } }
        // }
        vec![
            48, 43, 49, 13, 48, 11, 6, 3, 85, 4, 3, 12, 4, 84, 101, 115, 116, 49, 26, 48, 24, 6, 8,
            42, 133, 3, 3, 129, 3, 1, 1, 18, 12, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50,
        ]
    }

    #[test]
    fn parses_cn_and_inn_labels() {
        let attrs = name_attributes(&sample_name_der()).unwrap();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].label, "CN");
        assert_eq!(attrs[0].value, "Test");
        assert_eq!(attrs[1].label, "INN");
        assert_eq!(attrs[1].value, "123456789012");
        assert_eq!(display_name_from_attrs(&attrs).as_deref(), Some("Test"));
    }
}

fn certificate_parts(cert_der: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    let top = der::parse_tlv(cert_der).context("parse certificate")?;
    if top.tag != 0x30 || top.total_len != cert_der.len() {
        bail!("certificate is not one complete DER SEQUENCE");
    }
    let parts = raw_children(top.value)?;
    if parts.len() != 3 {
        bail!(
            "unexpected Certificate layout: {} top-level fields",
            parts.len()
        );
    }
    Ok((parts[0], parts[1], parts[2]))
}

fn algorithm_oid(raw: &[u8]) -> Result<String> {
    let t = der::parse_tlv(raw)?;
    if t.tag != 0x30 {
        bail!("AlgorithmIdentifier is not SEQUENCE");
    }
    let f = raw_children(t.value)?;
    let oid_tlv = der::parse_tlv(*f.first().context("empty AlgorithmIdentifier")?)?;
    if oid_tlv.tag != 0x06 {
        bail!("AlgorithmIdentifier.oid is not OBJECT IDENTIFIER");
    }
    der::decode_oid(oid_tlv.value).context("invalid certificate signatureAlgorithm OID")
}

fn signature_value(raw: &[u8]) -> Result<Vec<u8>> {
    let bits = der::parse_tlv(raw).context("parse certificate signature")?;
    if bits.tag != 0x03 || bits.value.first().copied() != Some(0) {
        bail!("certificate signature is not a BIT STRING");
    }
    Ok(bits.value[1..].to_vec())
}

fn digest_for_cert_signature(sig_alg_oid: &str, tbs_der: &[u8]) -> Result<Vec<u8>> {
    match sig_alg_oid {
        "1.2.643.7.1.1.3.2" => Ok(Streebog256::digest(tbs_der).to_vec()),
        "1.2.643.7.1.1.3.3" => Ok(Streebog512::digest(tbs_der).to_vec()),
        other => bail!("unsupported certificate signature algorithm {other}"),
    }
}

/// Verify that `cert_der` was signed by `issuer_cert_der`.
pub fn verify_issued_by(cert_der: &[u8], issuer_cert_der: &[u8]) -> Result<bool> {
    let cert_names = names(cert_der)?;
    let issuer_names = names(issuer_cert_der)?;
    if cert_names.issuer_der != issuer_names.subject_der {
        bail!("issuer certificate subject does not match certificate issuer");
    }
    certificate_parts(cert_der)?;
    verify_signed_structure(cert_der, issuer_cert_der)
}

/// Verify the GOST signature on a `SEQUENCE { tbs, AlgorithmIdentifier,
/// BIT STRING, ... }` (Certificate, CertificateList, BasicOCSPResponse) with
/// the public key of `signer_cert_der`. The tbs bytes are hashed as received.
pub fn verify_signed_structure(signed_der: &[u8], signer_cert_der: &[u8]) -> Result<bool> {
    let top = der::parse_tlv(signed_der).context("parse signed structure")?;
    if top.tag != 0x30 || top.total_len != signed_der.len() {
        bail!("signed structure is not one complete DER SEQUENCE");
    }
    let parts = raw_children(top.value)?;
    if parts.len() < 3 {
        bail!("signed structure is truncated");
    }
    let sig_alg_oid = algorithm_oid(parts[1])?;
    let digest = digest_for_cert_signature(&sig_alg_oid, parts[0])?;
    let signature = signature_value(parts[2])?;
    let signer = identity(signer_cert_der)?;
    let curve = curves::by_oid(&signer.curve_oid).context("unsupported signer certificate curve")?;
    gost3410::verify_digest(
        &curve,
        &signer.public_x_le,
        &signer.public_y_le,
        &digest,
        &signature,
    )
}

/// True if the certificate's extendedKeyUsage lists `wanted_oid`.
pub fn has_extended_key_usage(cert_der: &[u8], wanted_oid: &str) -> Result<bool> {
    const OID_EKU: &str = "2.5.29.37";
    let Some(value) = extension_value(cert_der, OID_EKU)? else {
        return Ok(false);
    };
    let seq = der::parse_tlv(value).context("parse ExtKeyUsageSyntax")?;
    if seq.tag != 0x30 {
        bail!("ExtKeyUsageSyntax is not a SEQUENCE");
    }
    for oid in der::children(seq.value)? {
        if oid.tag == 0x06 && der::decode_oid(oid.value).as_deref() == Some(wanted_oid) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Exact DER BIT STRING payload of SubjectPublicKeyInfo.subjectPublicKey,
/// excluding the initial "unused bits" count byte. RFC 6960 hashes this
/// payload for CertID.issuerKeyHash.
pub fn subject_public_key_bits(cert_der: &[u8]) -> Result<Vec<u8>> {
    let top = der::parse_tlv(cert_der).context("parse certificate")?;
    if top.tag != 0x30 || top.total_len != cert_der.len() {
        bail!("certificate is not one complete DER SEQUENCE");
    }
    let cert_parts = raw_children(top.value)?;
    let tbs = der::parse_tlv(
        *cert_parts
            .first()
            .context("certificate missing TBSCertificate")?,
    )?;
    if tbs.tag != 0x30 {
        bail!("TBSCertificate is not a SEQUENCE");
    }
    let tbs_parts = raw_children(tbs.value)?;
    let base = if tbs_parts.first().and_then(|r| r.first()).copied() == Some(0xA0) {
        1
    } else {
        0
    };
    let spki_raw = *tbs_parts
        .get(base + 5)
        .context("TBSCertificate missing SubjectPublicKeyInfo")?;
    let spki = der::parse_tlv(spki_raw)?;
    if spki.tag != 0x30 {
        bail!("SubjectPublicKeyInfo is not a SEQUENCE");
    }
    let f = raw_children(spki.value)?;
    let bits = der::parse_tlv(
        *f.get(1)
            .context("SubjectPublicKeyInfo missing subjectPublicKey")?,
    )?;
    if bits.tag != 0x03 || bits.value.first().copied() != Some(0) {
        bail!("unsupported subjectPublicKey BIT STRING");
    }
    Ok(bits.value[1..].to_vec())
}
