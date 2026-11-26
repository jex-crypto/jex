// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use crate::{cades, cms_der, curves, der, gost3410, x509};
use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use std::{io::Read, time::Duration};

pub const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
pub const OID_SIGNATURE_TIMESTAMP: &str = "1.2.840.113549.1.9.16.2.14";

#[derive(Debug, Clone)]
pub struct TimestampTokenInfo {
    pub digest_oid: String,
    pub message_imprint: Vec<u8>,
    pub gen_time: String,
    pub nonce: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct TimestampResponse {
    pub token: Vec<u8>,
    pub info: TimestampTokenInfo,
}

#[derive(Debug, Clone)]
pub struct TimestampSignerMeta {
    pub certificate: Vec<u8>,
    pub digest_oid: String,
}

#[derive(Debug, Clone)]
pub struct TimestampTokenVerifyResult {
    pub info: TimestampTokenInfo,
    pub signature_valid: bool,
    pub message_digest_valid: bool,
    pub content_type_valid: bool,
    pub signer_id_matches_certificate: bool,
    pub certificate_valid_at_gen_time: bool,
    pub digest_oid: String,
    pub signature_oid: String,
    pub curve_oid: String,
}

impl TimestampTokenVerifyResult {
    pub fn is_valid(&self) -> bool {
        self.signature_valid
            && self.message_digest_valid
            && self.content_type_valid
            && self.signer_id_matches_certificate
            && self.certificate_valid_at_gen_time
    }
}

/// Return the certificate and digest algorithm of the RFC 3161 token signer.
/// The TSA token may contain a certificate chain; select the actual signer by
/// matching SignerInfo.sid (issuerAndSerialNumber) instead of assuming that the
/// first CertificateSet entry is the signer certificate.
pub fn signer_meta(token: &[u8]) -> Result<TimestampSignerMeta> {
    let ci = der::parse_tlv(token).context("parse TimeStampToken ContentInfo")?;
    if ci.tag != 0x30 || ci.total_len != token.len() {
        bail!("TimeStampToken is not one ContentInfo SEQUENCE");
    }
    let cif = x509::raw_children(ci.value)?;
    if cif.len() != 2 || decode_oid_tlv(cif[0])? != cades::OID_SIGNED_DATA {
        bail!("TimeStampToken ContentInfo is not id-signedData");
    }
    let explicit = der::parse_tlv(cif[1])?;
    if explicit.tag != 0xA0 {
        bail!("TimeStampToken SignedData wrapper is not [0]");
    }
    let wrapped = x509::raw_children(explicit.value)?;
    let sd_raw = *wrapped.first().context("empty TimeStampToken [0]")?;
    let sd = der::parse_tlv(sd_raw)?;
    if sd.tag != 0x30 {
        bail!("TimeStampToken SignedData is not a SEQUENCE");
    }
    let fields = x509::raw_children(sd.value)?;

    let cert_set_raw = fields
        .iter()
        .find(|r| r.first().copied() == Some(0xA0))
        .context("TimeStampToken SignedData has no certificates")?;
    let cert_set = der::parse_tlv(cert_set_raw)?;
    let cert_candidates = x509::raw_children(cert_set.value)?;

    let signer_infos_raw = fields
        .iter()
        .rev()
        .find(|r| r.first().copied() == Some(0x31))
        .context("TimeStampToken SignedData has no signerInfos")?;
    let signer_infos = der::parse_tlv(signer_infos_raw)?;
    let signers = x509::raw_children(signer_infos.value)?;
    if signers.len() != 1 {
        bail!(
            "TimeStampToken must contain exactly one SignerInfo; got {}",
            signers.len()
        );
    }
    let si = der::parse_tlv(signers[0])?;
    if si.tag != 0x30 {
        bail!("TimeStampToken SignerInfo is not a SEQUENCE");
    }
    let sif = x509::raw_children(si.value)?;
    if sif.len() < 5 {
        bail!("truncated TimeStampToken SignerInfo");
    }
    let digest_oid = algorithm_oid(sif[2])?;

    let sid = der::parse_tlv(sif[1])?;
    if sid.tag == 0x30 {
        let sf = x509::raw_children(sid.value)?;
        if sf.len() != 2 {
            bail!("unsupported TimeStampToken issuerAndSerialNumber layout");
        }
        let issuer = sf[0];
        let serial = sf[1];
        for raw in &cert_candidates {
            if raw.first().copied() != Some(0x30) {
                continue;
            }
            if x509::issuer_serial_matches(raw, issuer, serial).unwrap_or(false) {
                return Ok(TimestampSignerMeta {
                    certificate: raw.to_vec(),
                    digest_oid,
                });
            }
        }
        bail!("TimeStampToken signer certificate matching issuerAndSerialNumber was not found");
    }

    // subjectKeyIdentifier is [0] IMPLICIT SubjectKeyIdentifier, i.e. tag 0x80
    // carrying the raw OCTET STRING contents. Match it against X.509 SKI
    // instead of guessing based on certificate order.
    if sid.tag == 0x80 {
        for raw in &cert_candidates {
            if raw.first().copied() != Some(0x30) {
                continue;
            }
            let Some(ext) = x509::extension_value(raw, "2.5.29.14")? else {
                continue;
            };
            let ski = der::parse_tlv(ext).context("parse SubjectKeyIdentifier extension")?;
            if ski.tag != 0x04 || ski.total_len != ext.len() {
                bail!("SubjectKeyIdentifier extension is not one OCTET STRING");
            }
            if ski.value == sid.value {
                return Ok(TimestampSignerMeta {
                    certificate: raw.to_vec(),
                    digest_oid,
                });
            }
        }
        bail!("TimeStampToken signer certificate matching subjectKeyIdentifier was not found");
    }

    bail!(
        "unsupported TimeStampToken SignerIdentifier tag 0x{:02X}",
        sid.tag
    )
}

fn signed_attribute_first_value(attrs_value: &[u8], wanted_oid: &str) -> Result<Option<Vec<u8>>> {
    let mut found = None;
    for raw in x509::raw_children(attrs_value)? {
        let attr = der::parse_tlv(raw)?;
        if attr.tag != 0x30 || attr.total_len != raw.len() {
            bail!("timestamp signed attribute is not one SEQUENCE");
        }
        let fields = x509::raw_children(attr.value)?;
        if fields.len() != 2 {
            bail!("malformed timestamp signed attribute");
        }
        if decode_oid_tlv(fields[0])? != wanted_oid {
            continue;
        }
        if found.is_some() {
            bail!("duplicate timestamp signed attribute {wanted_oid}");
        }
        let values = der::parse_tlv(fields[1])?;
        if values.tag != 0x31 {
            bail!("timestamp Attribute.attrValues is not SET OF");
        }
        let children = x509::raw_children(values.value)?;
        if children.len() != 1 {
            bail!(
                "timestamp signed attribute {wanted_oid} must contain exactly one value; got {}",
                children.len()
            );
        }
        found = Some(children[0].to_vec());
    }
    Ok(found)
}

/// Verify the CMS signature of an RFC 3161 TimeStampToken without making a
/// PKI trust decision. This validates the signer certificate selection,
/// signed-attributes messageDigest/contentType, GOST signature, and signer
/// certificate validity at TSTInfo.genTime. Chain trust and revocation policy
/// remain the responsibility of a PKI validator such as CryptoPro.
pub fn verify_token_signature(token: &[u8]) -> Result<TimestampTokenVerifyResult> {
    let info = parse_token(token)?;
    let signer = signer_meta(token)?;
    let spk = x509::subject_public_key(&signer.certificate)?;
    let key_oid = match &spk {
        x509::SubjectPublicKey::Gost { curve_oid, .. } => curve_oid.clone(),
        x509::SubjectPublicKey::Rsa { .. } => crate::pkix::OID_RSA_ENCRYPTION.to_string(),
        x509::SubjectPublicKey::EcP256 { .. } => crate::pkix::OID_SECP256R1.to_string(),
    };

    let ci = der::parse_tlv(token).context("parse TimeStampToken ContentInfo")?;
    let cif = x509::raw_children(ci.value)?;
    let explicit = der::parse_tlv(
        *cif.get(1)
            .context("TimeStampToken missing SignedData wrapper")?,
    )?;
    let wrapped = x509::raw_children(explicit.value)?;
    let sd_raw = *wrapped
        .first()
        .context("empty TimeStampToken SignedData wrapper")?;
    let sd = der::parse_tlv(sd_raw)?;
    let sdf = x509::raw_children(sd.value)?;
    if sdf.len() < 4 {
        bail!("truncated TimeStampToken SignedData");
    }

    let encap = der::parse_tlv(sdf[2])?;
    if encap.tag != 0x30 {
        bail!("TimeStampToken encapContentInfo is not SEQUENCE");
    }
    let ef = x509::raw_children(encap.value)?;
    if decode_oid_tlv(*ef.first().context("TimeStampToken missing eContentType")?)? != OID_TST_INFO
    {
        bail!("TimeStampToken eContentType is not id-ct-TSTInfo");
    }
    let wrapper = der::parse_tlv(*ef.get(1).context("TimeStampToken missing eContent")?)?;
    if wrapper.tag != 0xA0 {
        bail!("TimeStampToken eContent is not [0] EXPLICIT");
    }
    let inner = x509::raw_children(wrapper.value)?;
    let oct = der::parse_tlv(*inner.first().context("empty TimeStampToken eContent")?)?;
    if oct.tag != 0x04 || oct.total_len != inner[0].len() {
        bail!("TimeStampToken eContent is not one OCTET STRING");
    }
    let tst_info_der = oct.value;

    let signer_infos_raw = sdf
        .iter()
        .rev()
        .find(|r| r.first().copied() == Some(0x31))
        .context("TimeStampToken SignedData has no signerInfos")?;
    let signer_infos = der::parse_tlv(signer_infos_raw)?;
    let signers = x509::raw_children(signer_infos.value)?;
    if signers.len() != 1 {
        bail!(
            "TimeStampToken must contain exactly one SignerInfo; got {}",
            signers.len()
        );
    }
    let si = der::parse_tlv(signers[0])?;
    let sif = x509::raw_children(si.value)?;
    if sif.len() < 6 {
        bail!("TimeStampToken SignerInfo is truncated or has no signedAttrs");
    }

    let digest_oid = algorithm_oid(sif[2])?;
    let attrs = der::parse_tlv(sif[3])?;
    if attrs.tag != 0xA0 {
        bail!("TimeStampToken SignerInfo.signedAttrs is missing");
    }
    let signed_attrs_der = cms_der::tlv(0x31, attrs.value);
    let signature_oid = algorithm_oid(sif[4])?;
    let signature = der::parse_tlv(sif[5])?;
    if signature.tag != 0x04 {
        bail!("TimeStampToken SignerInfo.signature is not OCTET STRING");
    }

    let digest_set = der::parse_tlv(sdf[1])?;
    if digest_set.tag != 0x31 {
        bail!("TimeStampToken digestAlgorithms is not SET OF");
    }
    let mut digest_declared = false;
    for raw in x509::raw_children(digest_set.value)? {
        if let Ok(oid) = algorithm_oid(raw) {
            if oid == digest_oid {
                digest_declared = true;
                break;
            }
        }
    }
    if !digest_declared {
        bail!(
            "TimeStampToken SignerInfo digest algorithm is absent from SignedData.digestAlgorithms"
        );
    }

    match &spk {
        x509::SubjectPublicKey::Gost { curve_oid, .. } => {
            let curve = curves::by_oid(curve_oid).context("unsupported timestamp signer curve")?;
            let (expected_digest_oid, expected_signature_oid, legacy_signature_oid) =
                match curve.bytes {
                    32 => (
                        cades::OID_DIGEST_256,
                        cades::OID_SIGN_256,
                        cades::OID_SIGN_WITH_DIGEST_256,
                    ),
                    64 => (
                        cades::OID_DIGEST_512,
                        cades::OID_SIGN_512,
                        cades::OID_SIGN_WITH_DIGEST_512,
                    ),
                    n => bail!("unsupported timestamp signer key size: {} bits", n * 8),
                };
            if digest_oid != expected_digest_oid {
                bail!("TimeStampToken digestAlgorithm {digest_oid} does not match timestamp signer key ({expected_digest_oid})");
            }
            if signature_oid != expected_signature_oid && signature_oid != legacy_signature_oid {
                bail!("TimeStampToken signatureAlgorithm {signature_oid} does not match timestamp signer key (expected {expected_signature_oid} or legacy {legacy_signature_oid})");
            }
        }
        // RSA/ECDSA: digest (SHA-256/384/512) and signatureAlgorithm
        // consistency are checked in pkix::verify_signed_attrs below.
        x509::SubjectPublicKey::Rsa { .. } | x509::SubjectPublicKey::EcP256 { .. } => {}
    }

    let content_type_raw = signed_attribute_first_value(attrs.value, cades::OID_ATTR_CONTENT_TYPE)?
        .context("TimeStampToken signedAttrs missing content-type")?;
    let content_type_valid = decode_oid_tlv(&content_type_raw)? == OID_TST_INFO;

    let message_digest_raw =
        signed_attribute_first_value(attrs.value, cades::OID_ATTR_MESSAGE_DIGEST)?
            .context("TimeStampToken signedAttrs missing message-digest")?;
    let message_digest = der::parse_tlv(&message_digest_raw)?;
    if message_digest.tag != 0x04 || message_digest.total_len != message_digest_raw.len() {
        bail!("TimeStampToken message-digest attribute is not one OCTET STRING");
    }
    let expected_message_digest = cades::digest_by_oid(&digest_oid, tst_info_der)?;
    let message_digest_valid = message_digest.value == expected_message_digest.as_slice();

    let signature_valid = match &spk {
        x509::SubjectPublicKey::Gost {
            curve_oid,
            public_x_le,
            public_y_le,
        } => {
            let curve = curves::by_oid(curve_oid).expect("curve checked above");
            let attrs_digest = cades::digest_by_oid(&digest_oid, &signed_attrs_der)?;
            gost3410::verify_digest(
                &curve,
                public_x_le,
                public_y_le,
                &attrs_digest,
                signature.value,
            )?
        }
        x509::SubjectPublicKey::Rsa { .. } | x509::SubjectPublicKey::EcP256 { .. } => {
            crate::pkix::verify_signed_attrs(
                &spk,
                &digest_oid,
                &signature_oid,
                &signed_attrs_der,
                signature.value,
            )?
        }
    };

    let gen_time_unix = x509::generalized_time_to_unix(&info.gen_time)?;
    let validity = x509::validity(&signer.certificate)?;
    let certificate_valid_at_gen_time = validity.is_valid_at(gen_time_unix);

    Ok(TimestampTokenVerifyResult {
        info,
        signature_valid,
        message_digest_valid,
        content_type_valid,
        signer_id_matches_certificate: true,
        certificate_valid_at_gen_time,
        digest_oid,
        signature_oid,
        curve_oid: key_oid,
    })
}

pub fn request_timestamp(
    tsa_url: &str,
    signature_value: &[u8],
    digest_oid: &str,
    policy: Option<&str>,
    timeout_secs: u64,
) -> Result<TimestampResponse> {
    request_timestamp_over_data(tsa_url, signature_value, digest_oid, policy, timeout_secs)
}

/// Request an RFC 3161 token over arbitrary bytes. The TSA messageImprint is
/// digest(data), so callers can use this for signature timestamps and for the
/// CAdES-C/X-Type-1 timestamp input defined by RFC 5126 §6.3.5.
pub fn request_timestamp_over_data(
    tsa_url: &str,
    data: &[u8],
    digest_oid: &str,
    policy: Option<&str>,
    timeout_secs: u64,
) -> Result<TimestampResponse> {
    let imprint = cades::digest_by_oid(digest_oid, data)?;
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce[0] &= 0x7f; // positive INTEGER without semantic sign bit
    if nonce.iter().all(|b| *b == 0) {
        nonce[15] = 1;
    }

    let mut fields = vec![
        cms_der::integer_u8(1),
        cms_der::sequence(&[
            cms_der::algorithm_identifier(digest_oid)?,
            cms_der::octet_string(&imprint),
        ]),
    ];
    if let Some(policy) = policy {
        fields.push(cms_der::oid(policy)?);
    }
    fields.push(cms_der::integer_unsigned(&nonce));
    fields.push(cms_der::boolean(true)); // certReq: ask TSA to include its certificate
    let request = cms_der::sequence(&fields);

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .build();
    let response = agent
        .post(tsa_url)
        .set("Content-Type", "application/timestamp-query")
        .set("Accept", "application/timestamp-reply")
        .send_bytes(&request)
        .map_err(|e| anyhow::anyhow!("TSA HTTP request failed: {e}"))?;

    let content_type = response
        .header("Content-Type")
        .unwrap_or("")
        .to_ascii_lowercase();
    if !content_type.is_empty()
        && !content_type.starts_with("application/timestamp-reply")
        && !content_type.starts_with("application/octet-stream")
    {
        bail!("TSA returned unexpected Content-Type {content_type:?}");
    }
    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .context("read TSA response body")?;
    parse_timestamp_response(&body, digest_oid, &imprint, Some(&nonce))
}

pub fn parse_timestamp_response(
    response_der: &[u8],
    expected_digest_oid: &str,
    expected_imprint: &[u8],
    expected_nonce: Option<&[u8]>,
) -> Result<TimestampResponse> {
    let top = der::parse_tlv(response_der).context("parse TimeStampResp")?;
    if top.tag != 0x30 || top.total_len != response_der.len() {
        bail!("TSA response is not one DER TimeStampResp SEQUENCE");
    }
    let fields = x509::raw_children(top.value)?;
    let status_raw = *fields.first().context("TimeStampResp missing status")?;
    let status_seq = der::parse_tlv(status_raw)?;
    if status_seq.tag != 0x30 {
        bail!("PKIStatusInfo is not a SEQUENCE");
    }
    let status_fields = x509::raw_children(status_seq.value)?;
    let status = parse_small_integer(
        *status_fields
            .first()
            .context("PKIStatusInfo missing status INTEGER")?,
    )?;
    if status != 0 && status != 1 {
        let status_text = status_fields
            .iter()
            .find_map(|r| parse_free_text(r).ok())
            .unwrap_or_default();
        bail!(
            "TSA rejected timestamp request: PKIStatus={status}{}",
            if status_text.is_empty() {
                String::new()
            } else {
                format!(" ({status_text})")
            }
        );
    }
    let token = fields
        .get(1)
        .context("TSA granted request but returned no TimeStampToken")?
        .to_vec();
    let info = parse_token(&token)?;
    if info.digest_oid != expected_digest_oid {
        bail!(
            "TSA token messageImprint algorithm {} differs from requested {}",
            info.digest_oid,
            expected_digest_oid
        );
    }
    if info.message_imprint != expected_imprint {
        bail!("TSA token messageImprint does not match the requested data hash");
    }
    if let Some(expected) = expected_nonce {
        let got = info
            .nonce
            .as_deref()
            .context("TSA token omitted nonce present in request")?;
        if normalize_integer(got) != normalize_integer(expected) {
            bail!("TSA token nonce does not match request nonce");
        }
    }
    let verified =
        verify_token_signature(&token).context("verify TSA TimeStampToken CMS signature")?;
    if !verified.is_valid() {
        bail!(
            "TSA TimeStampToken failed local cryptographic verification: signature={}, messageDigest={}, contentType={}, sid={}, certAtGenTime={}",
            verified.signature_valid,
            verified.message_digest_valid,
            verified.content_type_valid,
            verified.signer_id_matches_certificate,
            verified.certificate_valid_at_gen_time,
        );
    }
    Ok(TimestampResponse { token, info })
}

pub fn parse_token(token: &[u8]) -> Result<TimestampTokenInfo> {
    let ci = der::parse_tlv(token).context("parse TimeStampToken ContentInfo")?;
    if ci.tag != 0x30 || ci.total_len != token.len() {
        bail!("TimeStampToken is not one ContentInfo SEQUENCE");
    }
    let cif = x509::raw_children(ci.value)?;
    if cif.len() != 2 || decode_oid_tlv(cif[0])? != cades::OID_SIGNED_DATA {
        bail!("TimeStampToken ContentInfo is not id-signedData");
    }
    let explicit = der::parse_tlv(cif[1])?;
    if explicit.tag != 0xA0 {
        bail!("TimeStampToken SignedData wrapper is not [0]");
    }
    let explicit_fields = x509::raw_children(explicit.value)?;
    let sd_raw = *explicit_fields
        .first()
        .context("empty TimeStampToken [0]")?;
    let sd = der::parse_tlv(sd_raw)?;
    if sd.tag != 0x30 {
        bail!("TimeStampToken SignedData is not a SEQUENCE");
    }
    let sdf = x509::raw_children(sd.value)?;
    let encap_raw = *sdf
        .get(2)
        .context("TimeStampToken SignedData missing encapContentInfo")?;
    let encap = der::parse_tlv(encap_raw)?;
    if encap.tag != 0x30 {
        bail!("TimeStampToken encapContentInfo is not SEQUENCE");
    }
    let ef = x509::raw_children(encap.value)?;
    if decode_oid_tlv(*ef.first().context("TimeStampToken missing eContentType")?)? != OID_TST_INFO
    {
        bail!("TimeStampToken eContentType is not id-ct-TSTInfo");
    }
    let econtent = der::parse_tlv(*ef.get(1).context("TimeStampToken missing eContent")?)?;
    if econtent.tag != 0xA0 {
        bail!("TimeStampToken eContent is not [0] EXPLICIT");
    }
    let ecf = x509::raw_children(econtent.value)?;
    let oct = der::parse_tlv(*ecf.first().context("empty TimeStampToken eContent")?)?;
    if oct.tag != 0x04 {
        bail!("TimeStampToken eContent is not OCTET STRING");
    }
    parse_tst_info(oct.value)
}

fn parse_tst_info(input: &[u8]) -> Result<TimestampTokenInfo> {
    let top = der::parse_tlv(input).context("parse TSTInfo")?;
    if top.tag != 0x30 || top.total_len != input.len() {
        bail!("TSTInfo is not one SEQUENCE");
    }
    let f = x509::raw_children(top.value)?;
    if f.len() < 5 {
        bail!("truncated TSTInfo");
    }
    let _version = parse_small_integer(f[0])?;
    let mi = der::parse_tlv(f[2])?;
    if mi.tag != 0x30 {
        bail!("TSTInfo.messageImprint is not SEQUENCE");
    }
    let mif = x509::raw_children(mi.value)?;
    let digest_oid = algorithm_oid(
        *mif.first()
            .context("messageImprint missing hashAlgorithm")?,
    )?;
    let hash = der::parse_tlv(*mif.get(1).context("messageImprint missing hashedMessage")?)?;
    if hash.tag != 0x04 {
        bail!("messageImprint.hashedMessage is not OCTET STRING");
    }
    let gt = der::parse_tlv(f[4])?;
    if gt.tag != 0x18 {
        bail!("TSTInfo.genTime is not GeneralizedTime");
    }
    let gen_time = std::str::from_utf8(gt.value)
        .context("TSTInfo.genTime is not ASCII")?
        .to_string();

    let mut nonce = None;
    for raw in &f[5..] {
        let t = der::parse_tlv(raw)?;
        if t.tag == 0x02 {
            nonce = Some(t.value.to_vec());
        }
    }
    Ok(TimestampTokenInfo {
        digest_oid,
        message_imprint: hash.value.to_vec(),
        gen_time,
        nonce,
    })
}

pub fn token_matches_signature(token: &[u8], signature_value: &[u8]) -> Result<TimestampTokenInfo> {
    let info = parse_token(token)?;
    let digest = cades::digest_by_oid(&info.digest_oid, signature_value)?;
    if digest != info.message_imprint {
        bail!("signatureTimeStampToken messageImprint does not match CMS signature value");
    }
    Ok(info)
}

fn algorithm_oid(raw: &[u8]) -> Result<String> {
    let ai = der::parse_tlv(raw)?;
    if ai.tag != 0x30 {
        bail!("AlgorithmIdentifier is not SEQUENCE");
    }
    let f = x509::raw_children(ai.value)?;
    decode_oid_tlv(*f.first().context("empty AlgorithmIdentifier")?)
}
fn decode_oid_tlv(raw: &[u8]) -> Result<String> {
    let o = der::parse_tlv(raw)?;
    if o.tag != 0x06 {
        bail!("expected OBJECT IDENTIFIER");
    }
    der::decode_oid(o.value).context("invalid OBJECT IDENTIFIER")
}
fn parse_small_integer(raw: &[u8]) -> Result<u64> {
    let t = der::parse_tlv(raw)?;
    if t.tag != 0x02 || t.value.is_empty() || t.value.len() > 8 {
        bail!("unsupported INTEGER");
    }
    let mut out = 0u64;
    for b in t.value {
        out = out
            .checked_mul(256)
            .and_then(|v| v.checked_add(*b as u64))
            .context("INTEGER overflow")?;
    }
    Ok(out)
}
fn parse_free_text(raw: &[u8]) -> Result<String> {
    let seq = der::parse_tlv(raw)?;
    if seq.tag != 0x30 {
        bail!("not PKIFreeText");
    }
    let items = x509::raw_children(seq.value)?;
    let mut texts = Vec::new();
    for item in items {
        let t = der::parse_tlv(item)?;
        if t.tag == 0x0c {
            texts.push(String::from_utf8_lossy(t.value).into_owned());
        }
    }
    Ok(texts.join("; "))
}
fn normalize_integer(bytes: &[u8]) -> &[u8] {
    let i = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    &bytes[i..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn attr(oid: &str, value: Vec<u8>) -> Vec<u8> {
        cms_der::sequence(&[cms_der::oid(oid).unwrap(), cms_der::set(vec![value])])
    }

    fn fake_gost_certificate(curve: &curves::Curve, x: &[u8], y: &[u8]) -> Vec<u8> {
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
        let validity = cms_der::sequence(&[
            cms_der::tlv(0x17, b"250101000000Z"),
            cms_der::tlv(0x17, b"491231235959Z"),
        ]);
        let tbs = cms_der::sequence(&[
            cms_der::explicit0(&cms_der::integer_u8(2)),
            cms_der::integer_u8(1),
            cms_der::algorithm_identifier(cades::OID_SIGN_256).unwrap(),
            empty_name.clone(),
            validity,
            empty_name,
            spki,
        ]);
        cms_der::sequence(&[
            tbs,
            cms_der::algorithm_identifier(cades::OID_SIGN_256).unwrap(),
            cms_der::bit_string(&[0u8; 64]),
        ])
    }

    fn synthetic_timestamp_token() -> Vec<u8> {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(123456789u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let cert = fake_gost_certificate(&curve, &x, &y);
        let identity = x509::identity(&cert).unwrap();

        let stamped_data = b"timestamp input";
        let imprint = cades::digest_by_oid(cades::OID_DIGEST_256, stamped_data).unwrap();
        let tst_info = cms_der::sequence(&[
            cms_der::integer_u8(1),
            cms_der::oid("1.2.643.100.113").unwrap(),
            cms_der::sequence(&[
                cms_der::algorithm_identifier(cades::OID_DIGEST_256).unwrap(),
                cms_der::octet_string(&imprint),
            ]),
            cms_der::integer_u8(1),
            cms_der::tlv(0x18, b"20260819184915Z"),
        ]);
        let content_digest = cades::digest_by_oid(cades::OID_DIGEST_256, &tst_info).unwrap();
        let signed_attrs = cms_der::set(vec![
            attr(
                cades::OID_ATTR_CONTENT_TYPE,
                cms_der::oid(OID_TST_INFO).unwrap(),
            ),
            attr(
                cades::OID_ATTR_MESSAGE_DIGEST,
                cms_der::octet_string(&content_digest),
            ),
        ]);
        let attrs_digest = cades::digest_by_oid(cades::OID_DIGEST_256, &signed_attrs).unwrap();
        let signature = gost3410::sign_digest(&curve, &private, &attrs_digest).unwrap();
        let sid = cms_der::sequence(&[identity.issuer_der, identity.serial_der]);
        let signer_info = cms_der::sequence(&[
            cms_der::integer_u8(1),
            sid,
            cms_der::algorithm_identifier(cades::OID_DIGEST_256).unwrap(),
            cms_der::implicit_set0_from_der_set(&signed_attrs).unwrap(),
            cms_der::algorithm_identifier(cades::OID_SIGN_256).unwrap(),
            cms_der::octet_string(&signature),
        ]);
        let encap = cms_der::sequence(&[
            cms_der::oid(OID_TST_INFO).unwrap(),
            cms_der::explicit0(&cms_der::octet_string(&tst_info)),
        ]);
        let signed_data = cms_der::sequence(&[
            cms_der::integer_u8(3),
            cms_der::set(vec![
                cms_der::algorithm_identifier(cades::OID_DIGEST_256).unwrap()
            ]),
            encap,
            cms_der::implicit0(&cert),
            cms_der::set(vec![signer_info]),
        ]);
        cms_der::sequence(&[
            cms_der::oid(cades::OID_SIGNED_DATA).unwrap(),
            cms_der::explicit0(&signed_data),
        ])
    }

    #[test]
    fn verifies_timestamp_token_cms_signature() {
        let token = synthetic_timestamp_token();
        let v = verify_token_signature(&token).unwrap();
        assert!(v.is_valid());
        assert_eq!(v.info.gen_time, "20260819184915Z");
    }

    #[test]
    fn detects_tampered_timestamp_signed_content() {
        let mut token = synthetic_timestamp_token();
        // Alter a byte in TSTInfo while preserving DER lengths. The CMS
        // messageDigest/signature must no longer validate.
        let needle = b"20260819184915Z";
        let pos = token
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap();
        token[pos + 13] ^= 1;
        let v = verify_token_signature(&token).unwrap();
        assert!(!v.is_valid());
    }

    #[test]
    fn detects_tampered_timestamp_signature_value() {
        let mut token = synthetic_timestamp_token();
        // In the synthetic token the SignerInfo.signature OCTET STRING is the
        // final payload, so the final byte is part of the GOST signature.
        *token.last_mut().unwrap() ^= 1;
        let v = verify_token_signature(&token).unwrap();
        assert!(!v.signature_valid);
        assert!(!v.is_valid());
    }
}
