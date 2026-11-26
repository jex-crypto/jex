// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use crate::{cms_der, curves, der, gost3410, pkix, x509};
use anyhow::{bail, Context, Result};
use sha2::{Digest as Sha2Digest, Sha256, Sha384, Sha512};
use streebog::{Digest, Streebog256, Streebog512};

pub const OID_DATA: &str = "1.2.840.113549.1.7.1";
pub const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const OID_ATTR_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
pub const OID_ATTR_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub const OID_ATTR_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
pub const OID_ATTR_SIGNING_CERT_V2: &str = "1.2.840.113549.1.9.16.2.47";
/// CryptoPro CADESCOM document name / description authenticated attributes.
pub const OID_ATTR_DOCUMENT_NAME: &str = "1.2.643.100.111";
pub const OID_ATTR_DOCUMENT_DESCRIPTION: &str = "1.2.643.100.112";
pub const OID_DIGEST_256: &str = "1.2.643.7.1.1.2.2";
pub const OID_DIGEST_512: &str = "1.2.643.7.1.1.2.3";
pub use pkix::{OID_SHA256, OID_SHA384, OID_SHA512};
// CryptoPro CMS convention: SignerInfo.signatureAlgorithm contains the
// public-key algorithm OID. The hash algorithm is carried separately in
// SignerInfo.digestAlgorithm. CryptoPro cryptcp/CAdES expects this form.
pub const OID_SIGN_256: &str = "1.2.643.7.1.1.1.1";
pub const OID_SIGN_512: &str = "1.2.643.7.1.1.1.2";

// X.509 Certificate/CRL signatureAlgorithm OIDs combine signature + digest.
// Older versions of this project emitted these in CMS SignerInfo. Keep them
// accepted by the local verifier for backwards compatibility, but never emit
// them for new CMS signatures.
pub const OID_SIGN_WITH_DIGEST_256: &str = "1.2.643.7.1.1.3.2";
pub const OID_SIGN_WITH_DIGEST_512: &str = "1.2.643.7.1.1.3.3";

#[derive(Debug)]
pub struct SignResult {
    pub der: Vec<u8>,
    pub content_digest: Vec<u8>,
    pub attrs_digest: Vec<u8>,
    pub signature: Vec<u8>,
    pub certificate: Vec<u8>,
}

#[derive(Debug)]
pub struct ParsedCades {
    pub version: u64,
    pub detached: bool,
    pub embedded_content: Option<Vec<u8>>,
    pub digest_oid: String,
    pub signature_oid: String,
    pub certificate: Vec<u8>,
    pub signed_attrs_der: Vec<u8>,
    pub signature: Vec<u8>,
    pub message_digest: Vec<u8>,
    pub content_type_oid: String,
    pub signing_certificate_v2: Option<SigningCertV2>,
    pub signature_timestamp_token: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SigningCertV2 {
    pub hash_algorithm_oid: String,
    pub cert_hash: Vec<u8>,
}

#[derive(Debug)]
pub struct VerifyResult {
    pub signature_valid: bool,
    pub message_digest_valid: bool,
    pub signing_certificate_v2_valid: bool,
    pub signer_id_matches_certificate: bool,
    pub detached: bool,
    pub digest_oid: String,
    pub signature_oid: String,
    pub curve_oid: String,
    pub timestamp_imprint_valid: Option<bool>,
    pub timestamp_token_signature_valid: Option<bool>,
    pub timestamp_token_certificate_valid_at_gen_time: Option<bool>,
    pub timestamp_gen_time: Option<String>,
}

pub fn digest_for_curve(curve: &curves::Curve, data: &[u8]) -> Vec<u8> {
    match curve.bytes {
        32 => Streebog256::digest(data).to_vec(),
        64 => Streebog512::digest(data).to_vec(),
        _ => unreachable!("only 256/512-bit GOST curves are supported"),
    }
}

pub(crate) fn digest_by_oid(oid: &str, data: &[u8]) -> Result<Vec<u8>> {
    match oid {
        OID_DIGEST_256 => Ok(Streebog256::digest(data).to_vec()),
        OID_DIGEST_512 => Ok(Streebog512::digest(data).to_vec()),
        OID_SHA256 => Ok(Sha256::digest(data).to_vec()),
        OID_SHA384 => Ok(Sha384::digest(data).to_vec()),
        OID_SHA512 => Ok(Sha512::digest(data).to_vec()),
        _ => bail!("unsupported CMS digest algorithm {oid}"),
    }
}

fn digest_oid(curve: &curves::Curve) -> Result<&'static str> {
    match curve.bytes {
        32 => Ok(OID_DIGEST_256),
        64 => Ok(OID_DIGEST_512),
        n => bail!("unsupported GOST private-key size: {} bits", n * 8),
    }
}

fn signature_oid(curve: &curves::Curve) -> Result<&'static str> {
    match curve.bytes {
        32 => Ok(OID_SIGN_256),
        64 => Ok(OID_SIGN_512),
        n => bail!("unsupported GOST private-key size: {} bits", n * 8),
    }
}

fn attribute(oid: &str, value: Vec<u8>) -> Result<Vec<u8>> {
    Ok(cms_der::sequence(&[
        cms_der::oid(oid)?,
        cms_der::set(vec![value]),
    ]))
}

fn issuer_serial(issuer_der: &[u8], serial_der: &[u8]) -> Vec<u8> {
    // GeneralName.directoryName is [4] EXPLICIT Name.
    let general_names = cms_der::sequence(&[cms_der::tlv(0xA4, issuer_der)]);
    cms_der::sequence(&[general_names, serial_der.to_vec()])
}

fn signing_certificate_v2_value(
    cert_der: &[u8],
    issuer_der: &[u8],
    serial_der: &[u8],
    digest_oid: &str,
) -> Result<Vec<u8>> {
    let cert_hash = digest_by_oid(digest_oid, cert_der)?;
    let mut fields = Vec::with_capacity(3);
    // SHA-256 is the ASN.1 DEFAULT, so DER requires omitting it; GOST is not
    // the default and must be explicit.
    if digest_oid != OID_SHA256 {
        fields.push(cms_der::algorithm_identifier(digest_oid)?);
    }
    fields.push(cms_der::octet_string(&cert_hash));
    fields.push(issuer_serial(issuer_der, serial_der));
    let ess_cert_id = cms_der::sequence(&fields);
    let certs = cms_der::sequence(&[ess_cert_id]);
    Ok(cms_der::sequence(&[certs]))
}

pub fn sign_bes(
    content: &[u8],
    cert_der: &[u8],
    curve: &curves::Curve,
    private_le: &[u8],
    expected_public_x_le: &[u8],
    expected_public_y_le: &[u8],
    detached: bool,
) -> Result<SignResult> {
    sign_bes_ex(&SignBesParams {
        content,
        content_digest: None,
        cert_der,
        curve,
        private_le,
        expected_public_x_le,
        expected_public_y_le,
        detached,
        extra_signed_attrs: &[],
    })
}

/// Parameters for CAdES-BES creation (content or pre-computed digest + optional attrs).
pub struct SignBesParams<'a> {
    pub content: &'a [u8],
    /// When set (SignHash), used as messageDigest instead of hashing `content`.
    pub content_digest: Option<&'a [u8]>,
    pub cert_der: &'a [u8],
    pub curve: &'a curves::Curve,
    pub private_le: &'a [u8],
    pub expected_public_x_le: &'a [u8],
    pub expected_public_y_le: &'a [u8],
    pub detached: bool,
    /// Complete Attribute DER SEQUENCEs appended after the mandatory trio.
    pub extra_signed_attrs: &'a [Vec<u8>],
}

pub fn sign_bes_ex(p: &SignBesParams<'_>) -> Result<SignResult> {
    let identity = x509::identity(p.cert_der).context("decode signer certificate")?;
    if identity.curve_oid != p.curve.oid {
        let cert_curve =
            curves::by_oid(&identity.curve_oid).context("unsupported certificate curve")?;
        if &cert_curve.p != &p.curve.p
            || &cert_curve.q != &p.curve.q
            || &cert_curve.gx != &p.curve.gx
            || &cert_curve.gy != &p.curve.gy
        {
            bail!(
                "certificate curve {} does not match container curve {}",
                identity.curve_oid,
                p.curve.oid
            );
        }
    }
    if identity.public_x_le != p.expected_public_x_le
        || identity.public_y_le != p.expected_public_y_le
    {
        bail!("certificate public key does not match the unlocked private key");
    }

    let dig_oid = digest_oid(p.curve)?;
    let sig_oid = signature_oid(p.curve)?;
    let content_digest = match p.content_digest {
        Some(d) => {
            if d.len() != p.curve.bytes {
                bail!(
                    "content digest length {}, expected {} for curve",
                    d.len(),
                    p.curve.bytes
                );
            }
            d.to_vec()
        }
        None => digest_for_curve(p.curve, p.content),
    };
    let cert_v2 = signing_certificate_v2_value(
        p.cert_der,
        &identity.issuer_der,
        &identity.serial_der,
        dig_oid,
    )?;

    let mut attrs = vec![
        attribute(OID_ATTR_CONTENT_TYPE, cms_der::oid(OID_DATA)?)?,
        attribute(
            OID_ATTR_MESSAGE_DIGEST,
            cms_der::octet_string(&content_digest),
        )?,
        attribute(OID_ATTR_SIGNING_CERT_V2, cert_v2)?,
    ];
    attrs.extend(p.extra_signed_attrs.iter().cloned());
    let signed_attrs_der = cms_der::set(attrs);

    let attrs_digest = digest_for_curve(p.curve, &signed_attrs_der);
    let signature = gost3410::sign_digest(p.curve, p.private_le, &attrs_digest)?;

    let sid = cms_der::sequence(&[identity.issuer_der.clone(), identity.serial_der.clone()]);
    let signer_info = cms_der::sequence(&[
        cms_der::integer_u8(1),
        sid,
        cms_der::algorithm_identifier(dig_oid)?,
        cms_der::implicit_set0_from_der_set(&signed_attrs_der)?,
        cms_der::algorithm_identifier(sig_oid)?,
        cms_der::octet_string(&signature),
    ]);

    let encap = if p.detached || p.content_digest.is_some() {
        // SignHash / detached: EncapsulatedContentInfo without eContent.
        cms_der::sequence(&[cms_der::oid(OID_DATA)?])
    } else {
        cms_der::sequence(&[
            cms_der::oid(OID_DATA)?,
            cms_der::explicit0(&cms_der::octet_string(p.content)),
        ])
    };

    let certificates = cms_der::implicit0(p.cert_der);
    let signed_data = cms_der::sequence(&[
        cms_der::integer_u8(1),
        cms_der::set(vec![cms_der::algorithm_identifier(dig_oid)?]),
        encap,
        certificates,
        cms_der::set(vec![signer_info]),
    ]);
    let der = cms_der::sequence(&[
        cms_der::oid(OID_SIGNED_DATA)?,
        cms_der::explicit0(&signed_data),
    ]);

    Ok(SignResult {
        der,
        content_digest,
        attrs_digest,
        signature,
        certificate: p.cert_der.to_vec(),
    })
}

/// CAdES-BES with a soft RSA or ECDSA P-256 key (SHA-256), signing-time = now.
pub fn sign_bes_pkix(
    content: &[u8],
    cert_der: &[u8],
    key: &pkix::SoftPrivateKey,
    detached: bool,
) -> Result<SignResult> {
    if !key.matches_certificate(cert_der)? {
        bail!("certificate public key does not match the private key");
    }
    let names = x509::names(cert_der).context("decode signer certificate")?;
    let dig_oid = key.digest_oid();
    let sig_oid = key.signature_oid();
    let content_digest = digest_by_oid(dig_oid, content)?;
    let cert_v2 =
        signing_certificate_v2_value(cert_der, &names.issuer_der, &names.serial_der, dig_oid)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs() as i64;
    // RFC 5652 11.3: UTCTime for 1950..=2049, GeneralizedTime otherwise.
    let signing_time = cms_der::utc_time_yy(now).or_else(|_| cms_der::generalized_time(now))?;

    let attrs = vec![
        attribute(OID_ATTR_CONTENT_TYPE, cms_der::oid(OID_DATA)?)?,
        attribute(OID_ATTR_SIGNING_TIME, signing_time)?,
        attribute(
            OID_ATTR_MESSAGE_DIGEST,
            cms_der::octet_string(&content_digest),
        )?,
        attribute(OID_ATTR_SIGNING_CERT_V2, cert_v2)?,
    ];
    let signed_attrs_der = cms_der::set(attrs);
    let attrs_digest = digest_by_oid(dig_oid, &signed_attrs_der)?;
    let signature = key.sign_signed_attrs(&signed_attrs_der)?;

    let sid = cms_der::sequence(&[names.issuer_der.clone(), names.serial_der.clone()]);
    let sig_alg = match key {
        pkix::SoftPrivateKey::Rsa(_) => pkix::algorithm_identifier_null(sig_oid)?,
        pkix::SoftPrivateKey::EcdsaP256(_) => cms_der::algorithm_identifier(sig_oid)?,
    };
    let signer_info = cms_der::sequence(&[
        cms_der::integer_u8(1),
        sid,
        cms_der::algorithm_identifier(dig_oid)?,
        cms_der::implicit_set0_from_der_set(&signed_attrs_der)?,
        sig_alg,
        cms_der::octet_string(&signature),
    ]);

    let encap = if detached {
        cms_der::sequence(&[cms_der::oid(OID_DATA)?])
    } else {
        cms_der::sequence(&[
            cms_der::oid(OID_DATA)?,
            cms_der::explicit0(&cms_der::octet_string(content)),
        ])
    };

    let certificates = cms_der::implicit0(cert_der);
    let signed_data = cms_der::sequence(&[
        cms_der::integer_u8(1),
        cms_der::set(vec![cms_der::algorithm_identifier(dig_oid)?]),
        encap,
        certificates,
        cms_der::set(vec![signer_info]),
    ]);
    let der = cms_der::sequence(&[
        cms_der::oid(OID_SIGNED_DATA)?,
        cms_der::explicit0(&signed_data),
    ]);

    Ok(SignResult {
        der,
        content_digest,
        attrs_digest,
        signature,
        certificate: cert_der.to_vec(),
    })
}

/// Build a CADESCOM authenticated attribute value for the plugin attribute Name codes.
pub fn authenticated_attr(
    name: i32,
    value: &str,
    unix_signing_time: Option<i64>,
) -> Result<Vec<u8>> {
    match name {
        0 => {
            // SIGNING_TIME
            let unix = unix_signing_time.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
            });
            // If value parses as a date string, prefer it.
            let unix = parse_attr_time(value).unwrap_or(unix);
            attribute(OID_ATTR_SIGNING_TIME, cms_der::utc_time_yy(unix)?)
        }
        1 => attribute(OID_ATTR_DOCUMENT_NAME, cms_der::utf8_string(value)),
        2 => attribute(OID_ATTR_DOCUMENT_DESCRIPTION, cms_der::utf8_string(value)),
        _ => bail!("unsupported authenticated attribute name {name}"),
    }
}

fn parse_attr_time(value: &str) -> Option<i64> {
    // Accept ISO-like `YYYY-MM-DDTHH:MM:SS` or JS Date toString leftovers as unix digits.
    if let Ok(n) = value.parse::<i64>() {
        if n > 1_000_000_000 {
            return Some(if n > 10_000_000_000 { n / 1000 } else { n });
        }
    }
    None
}

pub fn digest_data(curve_bytes: usize, data: &[u8]) -> Result<Vec<u8>> {
    match curve_bytes {
        32 => Ok(Streebog256::digest(data).to_vec()),
        64 => Ok(Streebog512::digest(data).to_vec()),
        n => bail!("unsupported digest size: {n}"),
    }
}

pub fn raw_sign_digest(curve: &curves::Curve, private_le: &[u8], digest: &[u8]) -> Result<Vec<u8>> {
    gost3410::sign_digest(curve, private_le, digest)
}

pub fn raw_verify_digest(
    curve: &curves::Curve,
    public_x_le: &[u8],
    public_y_le: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<bool> {
    gost3410::verify_digest(curve, public_x_le, public_y_le, digest, signature)
}

pub fn parse(input: &[u8]) -> Result<ParsedCades> {
    let top = der::parse_tlv(input).context("parse CMS ContentInfo")?;
    if top.tag != 0x30 || top.total_len != input.len() {
        bail!("CMS ContentInfo is not one complete DER SEQUENCE");
    }
    let ci = x509::raw_children(top.value)?;
    if ci.len() != 2 || decode_oid_tlv(ci[0])?.as_str() != OID_SIGNED_DATA {
        bail!("ContentInfo is not id-signedData");
    }
    let content = der::parse_tlv(ci[1])?;
    if content.tag != 0xA0 {
        bail!("ContentInfo.content is not [0] EXPLICIT");
    }
    let sd_raw = x509::raw_children(content.value)?;
    if sd_raw.len() != 1 {
        bail!("unexpected SignedData explicit wrapper");
    }
    let sd = der::parse_tlv(sd_raw[0])?;
    if sd.tag != 0x30 {
        bail!("SignedData is not a SEQUENCE");
    }
    let fields = x509::raw_children(sd.value)?;
    if fields.len() < 4 {
        bail!("truncated SignedData");
    }
    let version = parse_small_integer(fields[0])?;

    let encap_index = 2;
    let (detached, embedded_content) = parse_encap(fields[encap_index])?;

    let mut certificates_raw = None;
    let mut signer_infos = None;
    for raw in &fields[3..] {
        match raw.first().copied() {
            Some(0xA0) if certificates_raw.is_none() => certificates_raw = Some(*raw),
            Some(0x31) => signer_infos = Some(*raw),
            _ => {}
        }
    }
    let certificates_raw = certificates_raw.context("SignedData has no certificates")?;
    let signer_infos = signer_infos.context("SignedData has no signerInfos SET")?;
    let si_set = der::parse_tlv(signer_infos)?;
    let si_items = x509::raw_children(si_set.value)?;
    let si_raw = *si_items.first().context("empty signerInfos")?;
    let si = der::parse_tlv(si_raw)?;
    if si.tag != 0x30 {
        bail!("SignerInfo is not a SEQUENCE");
    }
    let sif = x509::raw_children(si.value)?;
    if sif.len() < 6 {
        bail!("SignerInfo without signedAttrs is not CAdES-BES");
    }

    let certificate = select_signer_certificate(certificates_raw, sif[1])
        .context("resolve SignerInfo.sid to an embedded certificate")?;

    let digest_oid = algorithm_oid(sif[2])?;
    let attrs = der::parse_tlv(sif[3])?;
    if attrs.tag != 0xA0 {
        bail!("SignerInfo.signedAttrs is missing");
    }
    let signed_attrs_der = cms_der::tlv(0x31, attrs.value);
    let signature_oid = algorithm_oid(sif[4])?;
    let signature_tlv = der::parse_tlv(sif[5])?;
    if signature_tlv.tag != 0x04 {
        bail!("SignerInfo.signature is not OCTET STRING");
    }

    let (content_type_oid, message_digest, signing_certificate_v2) =
        parse_signed_attrs(attrs.value)?;
    let signature_timestamp_token = sif
        .get(6)
        .filter(|raw| raw.first().copied() == Some(0xA1))
        .map(|raw| parse_signature_timestamp_attr(raw))
        .transpose()?;

    Ok(ParsedCades {
        version,
        detached,
        embedded_content,
        digest_oid,
        signature_oid,
        certificate,
        signed_attrs_der,
        signature: signature_tlv.value.to_vec(),
        message_digest,
        content_type_oid,
        signing_certificate_v2,
        signature_timestamp_token,
    })
}

/// All X.509 certificates embedded in CMS SignedData (leaf + chain).
pub fn embedded_certificates(input: &[u8]) -> Result<Vec<Vec<u8>>> {
    let top = der::parse_tlv(input).context("parse CMS ContentInfo")?;
    if top.tag != 0x30 {
        bail!("CMS ContentInfo is not a SEQUENCE");
    }
    let ci = x509::raw_children(top.value)?;
    if ci.len() != 2 {
        bail!("unexpected ContentInfo layout");
    }
    let content = der::parse_tlv(ci[1])?;
    if content.tag != 0xA0 {
        bail!("ContentInfo content is not [0] EXPLICIT");
    }
    let sd_raw = x509::raw_children(content.value)?;
    if sd_raw.len() != 1 {
        bail!("unexpected SignedData explicit wrapper");
    }
    let sd = der::parse_tlv(sd_raw[0])?;
    if sd.tag != 0x30 {
        bail!("SignedData is not a SEQUENCE");
    }
    let fields = x509::raw_children(sd.value)?;
    if fields.len() < 4 {
        bail!("truncated SignedData");
    }
    let mut certificates_raw = None;
    for raw in &fields[3..] {
        if raw.first().copied() == Some(0xA0) {
            certificates_raw = Some(*raw);
            break;
        }
    }
    let certificates_raw = certificates_raw.context("SignedData has no certificates")?;
    let outer = der::parse_tlv(certificates_raw)?;
    if outer.tag != 0xA0 {
        bail!("SignedData.certificates is not [0] IMPLICIT");
    }
    Ok(x509::raw_children(outer.value)?
        .into_iter()
        .filter(|r| r.first().copied() == Some(0x30))
        .map(|r| r.to_vec())
        .collect())
}

/// Pick the signer certificate from CertificateSet by matching SignerInfo.sid.
/// CryptoPro (and many CAs) embed the full chain; the leaf is not always first.
fn select_signer_certificate(certificates_raw: &[u8], sid_raw: &[u8]) -> Result<Vec<u8>> {
    let outer = der::parse_tlv(certificates_raw)?;
    if outer.tag != 0xA0 {
        bail!("SignedData.certificates is not [0] IMPLICIT");
    }
    let candidates = x509::raw_children(outer.value)?;
    let sid = der::parse_tlv(sid_raw)?;
    if sid.tag == 0x30 {
        let sf = x509::raw_children(sid.value)?;
        if sf.len() != 2 {
            bail!("unsupported issuerAndSerialNumber layout");
        }
        for raw in &candidates {
            if raw.first().copied() != Some(0x30) {
                continue;
            }
            if x509::issuer_serial_matches(raw, sf[0], sf[1]).unwrap_or(false) {
                return Ok(raw.to_vec());
            }
        }
        bail!("no CertificateSet entry matches SignerInfo issuerAndSerialNumber");
    }
    if sid.tag == 0x80 {
        for raw in &candidates {
            if raw.first().copied() != Some(0x30) {
                continue;
            }
            let Some(ext) = x509::extension_value(raw, "2.5.29.14")? else {
                continue;
            };
            let ski = der::parse_tlv(ext).context("parse SubjectKeyIdentifier extension")?;
            if ski.tag == 0x04 && ski.total_len == ext.len() && ski.value == sid.value {
                return Ok(raw.to_vec());
            }
        }
        bail!("no CertificateSet entry matches SignerInfo subjectKeyIdentifier");
    }
    bail!("unsupported SignerIdentifier tag 0x{:02X}", sid.tag)
}

fn parse_encap(raw: &[u8]) -> Result<(bool, Option<Vec<u8>>)> {
    let top = der::parse_tlv(raw)?;
    if top.tag != 0x30 {
        bail!("encapContentInfo is not a SEQUENCE");
    }
    let parts = x509::raw_children(top.value)?;
    if parts.is_empty() || decode_oid_tlv(parts[0])?.as_str() != OID_DATA {
        bail!("only id-data CAdES content is supported");
    }
    if parts.len() == 1 {
        return Ok((true, None));
    }
    let wrapper = der::parse_tlv(parts[1])?;
    if wrapper.tag != 0xA0 {
        bail!("eContent is not [0] EXPLICIT");
    }
    let inner = der::parse_tlv(wrapper.value)?;
    if inner.tag != 0x04 || inner.total_len != wrapper.value.len() {
        bail!("eContent is not one OCTET STRING");
    }
    Ok((false, Some(inner.value.to_vec())))
}

fn parse_signed_attrs(value: &[u8]) -> Result<(String, Vec<u8>, Option<SigningCertV2>)> {
    let attrs = x509::raw_children(value)?;
    let mut content_type = None;
    let mut message_digest = None;
    let mut signing_cert = None;

    for raw in attrs {
        let seq = der::parse_tlv(raw)?;
        if seq.tag != 0x30 {
            bail!("signed attribute is not a SEQUENCE");
        }
        let fields = x509::raw_children(seq.value)?;
        if fields.len() != 2 {
            bail!("malformed signed attribute");
        }
        let oid = decode_oid_tlv(fields[0])?;
        let values = der::parse_tlv(fields[1])?;
        if values.tag != 0x31 {
            bail!("attribute values are not SET OF");
        }
        let vals = x509::raw_children(values.value)?;
        let first = *vals.first().context("empty signed attribute value SET")?;
        match oid.as_str() {
            OID_ATTR_CONTENT_TYPE => content_type = Some(decode_oid_tlv(first)?),
            OID_ATTR_MESSAGE_DIGEST => {
                let v = der::parse_tlv(first)?;
                if v.tag != 0x04 {
                    bail!("message-digest attribute is not OCTET STRING");
                }
                message_digest = Some(v.value.to_vec());
            }
            OID_ATTR_SIGNING_CERT_V2 => signing_cert = Some(parse_signing_cert_v2(first)?),
            _ => {}
        }
    }

    Ok((
        content_type.context("CAdES signedAttrs missing content-type")?,
        message_digest.context("CAdES signedAttrs missing message-digest")?,
        signing_cert,
    ))
}

fn parse_signing_cert_v2(raw: &[u8]) -> Result<SigningCertV2> {
    let sc = der::parse_tlv(raw)?;
    if sc.tag != 0x30 {
        bail!("SigningCertificateV2 is not a SEQUENCE");
    }
    let sc_fields = x509::raw_children(sc.value)?;
    let certs_raw = *sc_fields.first().context("empty SigningCertificateV2")?;
    let certs = der::parse_tlv(certs_raw)?;
    if certs.tag != 0x30 {
        bail!("SigningCertificateV2.certs is not a SEQUENCE");
    }
    let ids = x509::raw_children(certs.value)?;
    let id_raw = *ids.first().context("SigningCertificateV2.certs is empty")?;
    let id = der::parse_tlv(id_raw)?;
    if id.tag != 0x30 {
        bail!("ESSCertIDv2 is not a SEQUENCE");
    }
    let f = x509::raw_children(id.value)?;
    if f.is_empty() {
        bail!("empty ESSCertIDv2");
    }

    let (hash_algorithm_oid, hash_index) = if f[0].first().copied() == Some(0x30) {
        (algorithm_oid(f[0])?, 1)
    } else {
        // ASN.1 DEFAULT is SHA-256. We parse it for completeness, though this
        // project intentionally emits explicit GOST hash AlgorithmIdentifier.
        ("2.16.840.1.101.3.4.2.1".to_string(), 0)
    };
    let hash = f.get(hash_index).context("ESSCertIDv2 missing certHash")?;
    let hash = der::parse_tlv(hash)?;
    if hash.tag != 0x04 {
        bail!("ESSCertIDv2.certHash is not OCTET STRING");
    }
    Ok(SigningCertV2 {
        hash_algorithm_oid,
        cert_hash: hash.value.to_vec(),
    })
}

pub fn verify(input: &[u8], external_content: Option<&[u8]>) -> Result<VerifyResult> {
    verify_ex(input, external_content, None)
}

/// Verify CMS/CAdES. For detached signatures pass either `external_content` or
/// `external_digest` (must equal `messageDigest` under SignerInfo.digestAlgorithm).
pub fn verify_ex(
    input: &[u8],
    external_content: Option<&[u8]>,
    external_digest: Option<&[u8]>,
) -> Result<VerifyResult> {
    let parsed = parse(input)?;
    // Accept CMS-correct version 1 and the version-3 values this project
    // briefly emitted before aligning with RFC 5652 / CryptoPro.
    if parsed.version != 1 && parsed.version != 3 {
        bail!(
            "CAdES-BES SignedData version is {}, expected 1 (or legacy 3)",
            parsed.version
        );
    }
    if parsed.content_type_oid != OID_DATA {
        bail!(
            "CAdES content-type attribute is {}, expected id-data",
            parsed.content_type_oid
        );
    }

    let content: Option<&[u8]> = match (&parsed.embedded_content, external_content) {
        (Some(embedded), Some(external)) => {
            if embedded.as_slice() != external {
                bail!("external content differs from attached CMS content");
            }
            Some(embedded)
        }
        (Some(embedded), None) => Some(embedded),
        (None, Some(external)) => Some(external),
        (None, None) => None,
    };

    let message_digest_valid = if let Some(content) = content {
        let computed_content_digest = digest_by_oid(&parsed.digest_oid, content)?;
        computed_content_digest == parsed.message_digest
    } else if let Some(digest) = external_digest {
        digest == parsed.message_digest.as_slice()
    } else {
        bail!("detached CAdES requires --content FILE or --content-hash HEX for verification");
    };

    let spk = x509::subject_public_key(&parsed.certificate)?;
    let key_oid = match &spk {
        x509::SubjectPublicKey::Gost { curve_oid, .. } => curve_oid.clone(),
        x509::SubjectPublicKey::Rsa { .. } => pkix::OID_RSA_ENCRYPTION.to_string(),
        x509::SubjectPublicKey::EcP256 { .. } => pkix::OID_SECP256R1.to_string(),
    };

    let signature_valid = match &spk {
        x509::SubjectPublicKey::Gost {
            curve_oid,
            public_x_le,
            public_y_le,
        } => {
            let curve = curves::by_oid(curve_oid).context("unsupported certificate curve")?;
            let expected_sig_oid = signature_oid(&curve)?;
            let expected_digest_oid = digest_oid(&curve)?;
            let legacy_sig_oid = match curve.bytes {
                32 => OID_SIGN_WITH_DIGEST_256,
                64 => OID_SIGN_WITH_DIGEST_512,
                _ => unreachable!(),
            };
            if parsed.signature_oid != expected_sig_oid && parsed.signature_oid != legacy_sig_oid {
                bail!(
                    "signatureAlgorithm {} does not match certificate key (expected CryptoPro CMS {} or legacy {})",
                    parsed.signature_oid, expected_sig_oid, legacy_sig_oid
                );
            }
            if parsed.digest_oid != expected_digest_oid {
                bail!(
                    "digestAlgorithm {} does not match certificate key ({expected_digest_oid})",
                    parsed.digest_oid
                );
            }
            let attrs_digest = digest_by_oid(&parsed.digest_oid, &parsed.signed_attrs_der)?;
            gost3410::verify_digest(
                &curve,
                public_x_le,
                public_y_le,
                &attrs_digest,
                &parsed.signature,
            )?
        }
        x509::SubjectPublicKey::Rsa { .. } | x509::SubjectPublicKey::EcP256 { .. } => {
            pkix::verify_signed_attrs(
                &spk,
                &parsed.digest_oid,
                &parsed.signature_oid,
                &parsed.signed_attrs_der,
                &parsed.signature,
            )?
        }
    };

    let signing_certificate_v2_valid = match &parsed.signing_certificate_v2 {
        Some(sc) => {
            digest_by_oid(&sc.hash_algorithm_oid, &parsed.certificate)?.as_slice()
                == sc.cert_hash.as_slice()
        }
        None => false,
    };

    // Our parser currently supports issuerAndSerialNumber sid only. Since the
    // certificate is embedded and the SignerInfo was parsed in that form,
    // compare it against the signer certificate directly.
    let names = x509::names(&parsed.certificate)?;
    let signer_id_matches_certificate = signer_id_matches(input, &names)?;

    let (
        timestamp_imprint_valid,
        timestamp_token_signature_valid,
        timestamp_token_certificate_valid_at_gen_time,
        timestamp_gen_time,
    ) = match &parsed.signature_timestamp_token {
        Some(token) => {
            let imprint = crate::timestamp::token_matches_signature(token, &parsed.signature);
            let token_verify = crate::timestamp::verify_token_signature(token);
            let imprint_valid = imprint.is_ok();
            let gen_time = imprint.ok().map(|info| info.gen_time);
            match token_verify {
                Ok(v) => (
                    Some(imprint_valid),
                    Some(
                        v.signature_valid
                            && v.message_digest_valid
                            && v.content_type_valid
                            && v.signer_id_matches_certificate,
                    ),
                    Some(v.certificate_valid_at_gen_time),
                    gen_time.or(Some(v.info.gen_time)),
                ),
                Err(_) => (Some(imprint_valid), Some(false), Some(false), gen_time),
            }
        }
        None => (None, None, None, None),
    };

    Ok(VerifyResult {
        signature_valid,
        message_digest_valid,
        signing_certificate_v2_valid,
        signer_id_matches_certificate,
        detached: parsed.detached,
        digest_oid: parsed.digest_oid,
        signature_oid: parsed.signature_oid,
        curve_oid: key_oid,
        timestamp_imprint_valid,
        timestamp_token_signature_valid,
        timestamp_token_certificate_valid_at_gen_time,
        timestamp_gen_time,
    })
}

pub fn add_signature_timestamp(bes_der: &[u8], token: &[u8]) -> Result<Vec<u8>> {
    // Validate the TSA token cryptographically and against the exact CMS
    // signature OCTET STRING before embedding it.
    let parsed = parse(bes_der)?;
    let token_verify = crate::timestamp::verify_token_signature(token)
        .context("verify signatureTimeStampToken CMS signature")?;
    if !token_verify.is_valid() {
        bail!(
            "signatureTimeStampToken failed local cryptographic verification: signature={}, messageDigest={}, contentType={}, sid={}, certAtGenTime={}",
            token_verify.signature_valid,
            token_verify.message_digest_valid,
            token_verify.content_type_valid,
            token_verify.signer_id_matches_certificate,
            token_verify.certificate_valid_at_gen_time,
        );
    }
    crate::timestamp::token_matches_signature(token, &parsed.signature)?;
    if parsed.signature_timestamp_token.is_some() {
        bail!("CAdES already contains id-aa-signatureTimeStampToken");
    }

    let top = der::parse_tlv(bes_der)?;
    let ci_fields = x509::raw_children(top.value)?;
    if ci_fields.len() != 2 {
        bail!("unexpected ContentInfo layout");
    }
    let wrapper = der::parse_tlv(ci_fields[1])?;
    if wrapper.tag != 0xA0 {
        bail!("ContentInfo.content is not [0]");
    }
    let wrapped = x509::raw_children(wrapper.value)?;
    let sd_raw = *wrapped.first().context("missing SignedData")?;
    let sd = der::parse_tlv(sd_raw)?;
    let mut sd_fields = x509::raw_children(sd.value)?
        .into_iter()
        .map(|v| v.to_vec())
        .collect::<Vec<_>>();

    let signer_index = sd_fields
        .iter()
        .rposition(|r| r.first().copied() == Some(0x31))
        .context("SignedData signerInfos missing")?;
    let signer_set = der::parse_tlv(&sd_fields[signer_index])?;
    let mut signers = x509::raw_children(signer_set.value)?
        .into_iter()
        .map(|v| v.to_vec())
        .collect::<Vec<_>>();
    if signers.len() != 1 {
        bail!("timestamp upgrade currently supports exactly one SignerInfo");
    }
    let si = der::parse_tlv(&signers[0])?;
    if si.tag != 0x30 {
        bail!("SignerInfo is not a SEQUENCE");
    }
    let mut sif = x509::raw_children(si.value)?
        .into_iter()
        .map(|v| v.to_vec())
        .collect::<Vec<_>>();
    if sif.iter().any(|r| r.first().copied() == Some(0xA1)) {
        bail!("SignerInfo already contains unsignedAttrs");
    }

    let attr = attribute(crate::timestamp::OID_SIGNATURE_TIMESTAMP, token.to_vec())?;
    let set = cms_der::set(vec![attr]);
    sif.push(cms_der::implicit_set1_from_der_set(&set)?);
    signers[0] = cms_der::sequence(&sif);
    sd_fields[signer_index] = cms_der::set(signers);
    let new_sd = cms_der::sequence(&sd_fields);
    Ok(cms_der::sequence(&[
        ci_fields[0].to_vec(),
        cms_der::explicit0(&new_sd),
    ]))
}

fn parse_signature_timestamp_attr(raw: &[u8]) -> Result<Vec<u8>> {
    let attrs = der::parse_tlv(raw)?;
    if attrs.tag != 0xA1 {
        bail!("unsignedAttrs is not [1] IMPLICIT");
    }
    for attr_raw in x509::raw_children(attrs.value)? {
        let attr = der::parse_tlv(attr_raw)?;
        if attr.tag != 0x30 {
            continue;
        }
        let f = x509::raw_children(attr.value)?;
        if f.len() != 2 {
            continue;
        }
        if decode_oid_tlv(f[0])? != crate::timestamp::OID_SIGNATURE_TIMESTAMP {
            continue;
        }
        let values = der::parse_tlv(f[1])?;
        if values.tag != 0x31 {
            bail!("signatureTimeStampToken attribute values are not SET OF");
        }
        let vals = x509::raw_children(values.value)?;
        let token = vals
            .first()
            .context("empty signatureTimeStampToken attribute")?;
        return Ok((*token).to_vec());
    }
    bail!("unsignedAttrs present but id-aa-signatureTimeStampToken is missing")
}

pub fn signer_identifier_matches_embedded_certificate(input: &[u8]) -> Result<bool> {
    let parsed = parse(input)?;
    let names = x509::names(&parsed.certificate)?;
    signer_id_matches(input, &names)
}

fn signer_id_matches(input: &[u8], names: &x509::CertNames) -> Result<bool> {
    let top = der::parse_tlv(input)?;
    let ci = x509::raw_children(top.value)?;
    let content = der::parse_tlv(ci[1])?;
    let sd_raw = x509::raw_children(content.value)?;
    let sd = der::parse_tlv(sd_raw[0])?;
    let fields = x509::raw_children(sd.value)?;
    let signer_set_raw = *fields
        .iter()
        .rev()
        .find(|r| r.first().copied() == Some(0x31))
        .context("signerInfos missing")?;
    let signer_set = der::parse_tlv(signer_set_raw)?;
    let signers = x509::raw_children(signer_set.value)?;
    let si_raw = *signers.first().context("empty signerInfos")?;
    let si = der::parse_tlv(si_raw)?;
    let sif = x509::raw_children(si.value)?;
    let sid = der::parse_tlv(sif[1])?;
    if sid.tag != 0x30 {
        return Ok(false);
    }
    let sidf = x509::raw_children(sid.value)?;
    if sidf.len() != 2 {
        return Ok(false);
    }
    Ok(sidf[0] == names.issuer_der.as_slice()
        && x509::integer_normalized(sidf[1])? == x509::integer_normalized(&names.serial_der)?)
}

fn algorithm_oid(raw: &[u8]) -> Result<String> {
    let ai = der::parse_tlv(raw)?;
    if ai.tag != 0x30 {
        bail!("AlgorithmIdentifier is not a SEQUENCE");
    }
    let f = x509::raw_children(ai.value)?;
    let first = *f.first().context("empty AlgorithmIdentifier")?;
    decode_oid_tlv(first)
}

fn decode_oid_tlv(raw: &[u8]) -> Result<String> {
    let o = der::parse_tlv(raw)?;
    if o.tag != 0x06 {
        bail!("expected OBJECT IDENTIFIER, got tag 0x{:02x}", o.tag);
    }
    der::decode_oid(o.value).context("invalid OBJECT IDENTIFIER")
}

fn parse_small_integer(raw: &[u8]) -> Result<u64> {
    let i = der::parse_tlv(raw)?;
    if i.tag != 0x02 || i.value.is_empty() || i.value.len() > 8 {
        bail!("unsupported INTEGER encoding");
    }
    let mut v = 0u64;
    for &b in i.value {
        v = v
            .checked_mul(256)
            .and_then(|x| x.checked_add(b as u64))
            .context("INTEGER overflow")?;
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn gost_sign_verify_roundtrip() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(123456789u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let hash = digest_for_curve(&curve, b"cades self-test");
        let sig = gost3410::sign_digest(&curve, &private, &hash).unwrap();
        assert!(gost3410::verify_digest(&curve, &x, &y, &hash, &sig).unwrap());
    }

    fn fake_gost_certificate(curve: &curves::Curve, x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut xy = x.to_vec();
        xy.extend_from_slice(y);
        let public_key_alg = cms_der::sequence(&[
            cms_der::oid("1.2.643.7.1.1.1.1").unwrap(),
            cms_der::sequence(&[
                cms_der::oid(curve.oid).unwrap(),
                cms_der::oid(OID_DIGEST_256).unwrap(),
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
            cms_der::algorithm_identifier(OID_SIGN_256).unwrap(),
            empty_name.clone(),
            cms_der::sequence(&[]), // validity; sufficient for our structural test parser
            empty_name,
            spki,
        ]);
        cms_der::sequence(&[
            tbs,
            cms_der::algorithm_identifier(OID_SIGN_256).unwrap(),
            cms_der::bit_string(&[0u8; 64]),
        ])
    }

    #[test]
    fn cades_bes_detached_roundtrip() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(987654321u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let cert = fake_gost_certificate(&curve, &x, &y);
        let content = b"detached CAdES-BES test content";
        let signed = sign_bes(content, &cert, &curve, &private, &x, &y, true).unwrap();
        let parsed = parse(&signed.der).unwrap();
        assert!(parsed.detached);
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.digest_oid, OID_DIGEST_256);
        assert_eq!(parsed.signature_oid, OID_SIGN_256);
        let verified = verify(&signed.der, Some(content)).unwrap();
        assert!(verified.message_digest_valid);
        assert!(verified.signing_certificate_v2_valid);
        assert!(verified.signer_id_matches_certificate);
        assert!(verified.signature_valid);
    }

    #[test]
    fn cades_bes_legacy_signed_data_version_3_still_verifies() {
        // Brief emit of SignedData.version=3 was incorrect for IssuerAndSerialNumber
        // + id-data, but those signatures must keep verifying.
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(987654321u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let cert = fake_gost_certificate(&curve, &x, &y);
        let content = b"legacy version-3 CAdES-BES";
        let signed = sign_bes(content, &cert, &curve, &private, &x, &y, true).unwrap();

        // Patch SignedData.version INTEGER from 1 to 3 in place (same DER length).
        let mut der = signed.der;
        let mut patched = false;
        for i in 0..der.len().saturating_sub(2) {
            if der[i] == 0x02 && der[i + 1] == 0x01 && der[i + 2] == 0x01 {
                der[i + 2] = 0x03;
                patched = true;
                break;
            }
        }
        assert!(patched, "failed to locate SignedData.version INTEGER");
        let parsed = parse(&der).unwrap();
        assert_eq!(parsed.version, 3);
        let verified = verify(&der, Some(content)).unwrap();
        assert!(verified.message_digest_valid);
        assert!(verified.signing_certificate_v2_valid);
        assert!(verified.signer_id_matches_certificate);
        assert!(verified.signature_valid);
    }

    #[test]
    fn cades_bes_attached_roundtrip() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(1122334455u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let cert = fake_gost_certificate(&curve, &x, &y);
        let content = b"attached CAdES-BES test content";
        let signed = sign_bes(content, &cert, &curve, &private, &x, &y, false).unwrap();
        let verified = verify(&signed.der, None).unwrap();
        assert!(!verified.detached);
        assert!(verified.message_digest_valid);
        assert!(verified.signing_certificate_v2_valid);
        assert!(verified.signer_id_matches_certificate);
        assert!(verified.signature_valid);
    }

    #[test]
    fn cades_bes_wrong_detached_content_is_detected() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(5566778899u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let cert = fake_gost_certificate(&curve, &x, &y);
        let signed = sign_bes(b"original", &cert, &curve, &private, &x, &y, true).unwrap();
        let verified = verify(&signed.der, Some(b"tampered")).unwrap();
        assert!(!verified.message_digest_valid);
        assert!(verified.signing_certificate_v2_valid);
        assert!(verified.signer_id_matches_certificate);
        // The CMS signature covers signedAttrs, so it remains mathematically
        // valid while the signed messageDigest no longer matches the content.
        assert!(verified.signature_valid);
    }

    #[test]
    fn attach_detach_roundtrip_preserves_signerinfo() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(7788990011u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let cert = fake_gost_certificate(&curve, &x, &y);
        let content = b"attach/detach roundtrip content";
        let signed = sign_bes(content, &cert, &curve, &private, &x, &y, true).unwrap();
        assert!(parse(&signed.der).unwrap().detached);

        let attached = crate::archive::attach_original_content(&signed.der, content).unwrap();
        let attached_parsed = parse(&attached).unwrap();
        assert!(!attached_parsed.detached);
        assert_eq!(attached_parsed.embedded_content.as_deref(), Some(content.as_slice()));

        let (detached, extracted) =
            crate::archive::detach_original_content(&attached).unwrap();
        assert_eq!(extracted, content);
        let detached_parsed = parse(&detached).unwrap();
        assert!(detached_parsed.detached);
        assert_eq!(detached_parsed.signed_attrs_der, attached_parsed.signed_attrs_der);
        assert_eq!(detached_parsed.signature, attached_parsed.signature);

        let verified = verify(&detached, Some(content)).unwrap();
        assert!(verified.message_digest_valid);
        assert!(verified.signature_valid);

        assert!(crate::archive::detach_original_content(&detached).is_err());
        assert!(crate::archive::attach_original_content(&attached, content).is_err());
    }

    fn fake_rsa_certificate(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
        let rsa_pub = cms_der::sequence(&[
            cms_der::integer_unsigned(modulus),
            cms_der::integer_unsigned(exponent),
        ]);
        let spki = cms_der::sequence(&[
            crate::pkix::algorithm_identifier_null(crate::pkix::OID_RSA_ENCRYPTION).unwrap(),
            cms_der::bit_string(&rsa_pub),
        ]);
        let empty_name = cms_der::sequence(&[]);
        let tbs = cms_der::sequence(&[
            cms_der::explicit0(&cms_der::integer_u8(2)),
            cms_der::integer_u8(1),
            cms_der::algorithm_identifier(crate::pkix::OID_SHA256_WITH_RSA).unwrap(),
            empty_name.clone(),
            cms_der::sequence(&[]),
            empty_name,
            spki,
        ]);
        cms_der::sequence(&[
            tbs,
            cms_der::algorithm_identifier(crate::pkix::OID_SHA256_WITH_RSA).unwrap(),
            cms_der::bit_string(&[0u8; 256]),
        ])
    }

    fn rsa_material() -> (Vec<u8>, crate::pkix::SoftPrivateKey) {
        use rsa::traits::PublicKeyParts;
        let mut rng = rand::thread_rng();
        let sk = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA-2048");
        let pk = sk.to_public_key();
        let cert = fake_rsa_certificate(&pk.n().to_bytes_be(), &pk.e().to_bytes_be());
        (cert, crate::pkix::SoftPrivateKey::Rsa(sk))
    }

    fn rcgen_ecdsa_p256_material() -> (Vec<u8>, crate::pkix::SoftPrivateKey) {
        let params = rcgen::CertificateParams::new(vec!["ecdsa.example".into()]).unwrap();
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key = crate::pkix::SoftPrivateKey::from_pem(&key_pair.serialize_pem()).unwrap();
        (cert_der, key)
    }

    #[test]
    fn cades_bes_rsa_sha256_roundtrip() {
        let (cert, key) = rsa_material();
        let content = b"RSA CAdES-BES test content";
        let signed = sign_bes_pkix(content, &cert, &key, true).unwrap();
        let parsed = parse(&signed.der).unwrap();
        assert!(parsed.detached);
        assert_eq!(parsed.digest_oid, OID_SHA256);
        assert_eq!(parsed.signature_oid, crate::pkix::OID_RSA_ENCRYPTION);
        let verified = verify(&signed.der, Some(content)).unwrap();
        assert!(verified.message_digest_valid);
        assert!(verified.signing_certificate_v2_valid);
        assert!(verified.signer_id_matches_certificate);
        assert!(verified.signature_valid);
    }

    #[test]
    fn cades_bes_ecdsa_p256_sha256_roundtrip() {
        let (cert, key) = rcgen_ecdsa_p256_material();
        let content = b"ECDSA P-256 CAdES-BES test content";
        let signed = sign_bes_pkix(content, &cert, &key, false).unwrap();
        let parsed = parse(&signed.der).unwrap();
        assert!(!parsed.detached);
        assert_eq!(parsed.digest_oid, OID_SHA256);
        assert_eq!(parsed.signature_oid, crate::pkix::OID_ECDSA_WITH_SHA256);
        let verified = verify(&signed.der, None).unwrap();
        assert!(verified.message_digest_valid);
        assert!(verified.signing_certificate_v2_valid);
        assert!(verified.signer_id_matches_certificate);
        assert!(verified.signature_valid);
    }

    #[test]
    fn pkix_verify_signed_attrs_rsa_sha512() {
        use sha2::Sha512;
        let (cert, key) = rsa_material();
        let crate::pkix::SoftPrivateKey::Rsa(sk) = &key else {
            unreachable!()
        };
        let attrs = cms_der::set(vec![attribute(OID_ATTR_CONTENT_TYPE, cms_der::oid(OID_DATA).unwrap()).unwrap()]);
        let hashed = Sha512::digest(&attrs);
        let sig = sk
            .sign_with_rng(
                &mut rand::thread_rng(),
                rsa::Pkcs1v15Sign::new::<Sha512>(),
                &hashed,
            )
            .unwrap();
        let spk = x509::subject_public_key(&cert).unwrap();
        for sig_oid in [crate::pkix::OID_RSA_ENCRYPTION, crate::pkix::OID_SHA512_WITH_RSA] {
            assert!(
                crate::pkix::verify_signed_attrs(&spk, OID_SHA512, sig_oid, &attrs, &sig).unwrap()
            );
        }
        // Wrong digestAlgorithm with a bare rsaEncryption: signature does not verify.
        assert!(!crate::pkix::verify_signed_attrs(
            &spk,
            OID_SHA256,
            crate::pkix::OID_RSA_ENCRYPTION,
            &attrs,
            &sig
        )
        .unwrap());
        // signatureAlgorithm hash contradicting digestAlgorithm is rejected.
        assert!(crate::pkix::verify_signed_attrs(
            &spk,
            OID_SHA512,
            crate::pkix::OID_SHA256_WITH_RSA,
            &attrs,
            &sig
        )
        .is_err());
    }

    #[test]
    fn pkix_verify_signed_attrs_p256_sha384() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::Sha384;
        let (cert, key) = rcgen_ecdsa_p256_material();
        let crate::pkix::SoftPrivateKey::EcdsaP256(sk) = &key else {
            unreachable!()
        };
        let attrs = cms_der::set(vec![attribute(OID_ATTR_CONTENT_TYPE, cms_der::oid(OID_DATA).unwrap()).unwrap()]);
        let sig: p256::ecdsa::Signature = sk.sign_prehash(&Sha384::digest(&attrs)).unwrap();
        let sig = sig.to_der().as_bytes().to_vec();
        let spk = x509::subject_public_key(&cert).unwrap();
        for sig_oid in [crate::pkix::OID_EC_PUBLIC_KEY, crate::pkix::OID_ECDSA_WITH_SHA384] {
            assert!(
                crate::pkix::verify_signed_attrs(&spk, OID_SHA384, sig_oid, &attrs, &sig).unwrap()
            );
        }
        assert!(crate::pkix::verify_signed_attrs(
            &spk,
            OID_SHA384,
            crate::pkix::OID_ECDSA_WITH_SHA256,
            &attrs,
            &sig
        )
        .is_err());
    }

    #[test]
    fn ess_cert_id_v2_sha256_omits_default_hash_algorithm() {
        let (cert, key) = rcgen_ecdsa_p256_material();
        let names = x509::names(&cert).unwrap();
        let value =
            signing_certificate_v2_value(&cert, &names.issuer_der, &names.serial_der, OID_SHA256)
                .unwrap();
        let sc = der::parse_tlv(&value).unwrap();
        let certs = der::parse_tlv(x509::raw_children(sc.value).unwrap()[0]).unwrap();
        let id = der::parse_tlv(x509::raw_children(certs.value).unwrap()[0]).unwrap();
        let fields = x509::raw_children(id.value).unwrap();
        assert_eq!(fields.len(), 2, "hashAlgorithm must be omitted for SHA-256");
        assert_eq!(fields[0][0], 0x04);

        // GOST keeps the explicit AlgorithmIdentifier.
        let gost =
            signing_certificate_v2_value(&cert, &names.issuer_der, &names.serial_der, OID_DIGEST_256)
                .unwrap();
        let parsed = parse_signing_cert_v2(&gost).unwrap();
        assert_eq!(parsed.hash_algorithm_oid, OID_DIGEST_256);

        let content = b"ESSCertIDv2 default hash";
        let signed = sign_bes_pkix(content, &cert, &key, true).unwrap();
        let parsed = parse(&signed.der).unwrap();
        let sc = parsed.signing_certificate_v2.as_ref().unwrap();
        assert_eq!(sc.hash_algorithm_oid, OID_SHA256);
        assert!(der::collect_oids(&parsed.signed_attrs_der)
            .iter()
            .any(|o| o == OID_ATTR_SIGNING_TIME));
        let verified = verify(&signed.der, Some(content)).unwrap();
        assert!(verified.signing_certificate_v2_valid);
        assert!(verified.signature_valid);
    }

    #[test]
    fn x509_names_rejects_non_integer_serial_and_bad_layout() {
        let (cert, _) = rcgen_ecdsa_p256_material();
        assert!(x509::names(&cert).is_ok());
        let top = der::parse_tlv(&cert).unwrap();
        let parts = x509::raw_children(top.value).unwrap();
        let tbs = der::parse_tlv(parts[0]).unwrap();
        let mut tbs_parts: Vec<Vec<u8>> = x509::raw_children(tbs.value)
            .unwrap()
            .into_iter()
            .map(|p| p.to_vec())
            .collect();
        let serial_idx = if tbs_parts[0][0] == 0xA0 { 1 } else { 0 };
        tbs_parts[serial_idx][0] = 0x04; // INTEGER -> OCTET STRING
        let bad_tbs = cms_der::sequence(&tbs_parts);
        let bad = cms_der::sequence(&[bad_tbs, parts[1].to_vec(), parts[2].to_vec()]);
        let err = x509::names(&bad).unwrap_err().to_string();
        assert!(err.contains("serialNumber is not INTEGER"), "{err}");
        assert!(x509::subject_public_key(&bad).is_err());

        let truncated = cms_der::sequence(&[parts[0].to_vec()]);
        let err = x509::names(&truncated).unwrap_err().to_string();
        assert!(err.contains("unexpected Certificate layout: 1 top-level fields"), "{err}");
    }
}
