// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use crate::{cms_der, der, x509};
use anyhow::{bail, Context, Result};
use sha1::{Digest, Sha1};
use std::{io::Read, time::Duration};

pub const OID_SHA1: &str = "1.3.14.3.2.26";
pub const OID_BASIC_OCSP_RESPONSE: &str = "1.3.6.1.5.5.7.48.1.1";
const OID_KP_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";

/// Allowed clock skew for a live response's thisUpdate in the future.
const MAX_FUTURE_SKEW_SECS: i64 = 10 * 60;
/// A live response without nextUpdate claims to be real-time; reject one
/// older than this as a probable replay.
const MAX_AGE_WITHOUT_NEXT_UPDATE_SECS: i64 = 60 * 60;

#[derive(Debug, Clone)]
pub struct OcspEvidence {
    /// DER BasicOCSPResponse, exactly the value embedded into CAdES
    /// RevocationValues.ocspVals.
    pub basic_response: Vec<u8>,
    /// Full RFC 6960 OCSPResponse DER (status + responseBytes). Kept for
    /// tooling and round-trip; CryptoPro libxades expects
    /// [`Self::basic_response`] inside XAdES EncapsulatedOCSPValue.
    pub full_response: Vec<u8>,
    /// Raw ResponderID TLV copied from ResponseData.
    pub responder_id_der: Vec<u8>,
    /// Raw GeneralizedTime TLV copied from ResponseData.producedAt.
    pub produced_at_der: Vec<u8>,
    pub produced_at: String,
    pub this_update: String,
    pub this_update_unix: i64,
    pub next_update: Option<String>,
    /// Certificates carried by BasicOCSPResponse.certs. CryptoPro XLT1
    /// expects the OCSP response signer certificate to be resolvable from
    /// CompleteCertificateRefs/CertificateValues.
    pub embedded_certificates: Vec<Vec<u8>>,
}

fn sha1(data: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().to_vec()
}

fn sha1_algorithm_identifier() -> Result<Vec<u8>> {
    // ETSI TS 101 733 recommends NULL parameters when generating SHA-1
    // AlgorithmIdentifier. RFC 6960 CertID permits SHA-1 and responders
    // commonly support it even when the certificate itself uses GOST.
    Ok(cms_der::sequence(&[
        cms_der::oid(OID_SHA1)?,
        cms_der::tlv(0x05, &[]),
    ]))
}

fn build_cert_id(cert_der: &[u8], issuer_der: &[u8]) -> Result<Vec<u8>> {
    let cert_names = x509::names(cert_der)?;
    let issuer_names = x509::names(issuer_der)?;
    if cert_names.issuer_der != issuer_names.subject_der {
        bail!("OCSP issuer certificate subject does not match certificate issuer");
    }
    let issuer_name_hash = sha1(&issuer_names.subject_der);
    let issuer_key_hash = sha1(&x509::subject_public_key_bits(issuer_der)?);
    Ok(cms_der::sequence(&[
        sha1_algorithm_identifier()?,
        cms_der::octet_string(&issuer_name_hash),
        cms_der::octet_string(&issuer_key_hash),
        cert_names.serial_der,
    ]))
}

pub fn build_request(cert_der: &[u8], issuer_der: &[u8]) -> Result<Vec<u8>> {
    let cert_id = build_cert_id(cert_der, issuer_der)?;
    let request = cms_der::sequence(&[cert_id]);
    let request_list = cms_der::sequence(&[request]);
    let tbs_request = cms_der::sequence(&[request_list]);
    Ok(cms_der::sequence(&[tbs_request]))
}

fn decode_oid_tlv(raw: &[u8]) -> Result<String> {
    let t = der::parse_tlv(raw)?;
    if t.tag != 0x06 {
        bail!("expected OBJECT IDENTIFIER");
    }
    der::decode_oid(t.value).context("invalid OBJECT IDENTIFIER")
}

fn algorithm_oid(raw: &[u8]) -> Result<String> {
    let t = der::parse_tlv(raw)?;
    if t.tag != 0x30 {
        bail!("AlgorithmIdentifier is not SEQUENCE");
    }
    let f = x509::raw_children(t.value)?;
    decode_oid_tlv(*f.first().context("empty AlgorithmIdentifier")?)
}

fn time_string(raw: &[u8]) -> Result<String> {
    let t = der::parse_tlv(raw)?;
    if t.tag != 0x18 {
        bail!("OCSP time is not GeneralizedTime");
    }
    Ok(std::str::from_utf8(t.value)
        .context("OCSP GeneralizedTime is not ASCII")?
        .to_string())
}

fn integer_value(raw: &[u8]) -> Result<&[u8]> {
    let t = der::parse_tlv(raw)?;
    if t.tag != 0x02 {
        bail!("expected INTEGER");
    }
    let mut v = t.value;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    Ok(v)
}

struct ParsedOcspWire {
    /// Bare BasicOCSPResponse DER.
    basic_der: Vec<u8>,
    /// Full OCSPResponse DER (original wire form, or rebuilt wrapper).
    full_der: Vec<u8>,
}

/// Wrap a BasicOCSPResponse as a successful RFC 6960 OCSPResponse.
pub fn wrap_basic_as_ocsp_response(basic_der: &[u8]) -> Result<Vec<u8>> {
    let response_bytes = cms_der::sequence(&[
        cms_der::oid(OID_BASIC_OCSP_RESPONSE)?,
        cms_der::octet_string(basic_der),
    ]);
    Ok(cms_der::sequence(&[
        cms_der::tlv(0x0A, &[0x00]), // responseStatus successful
        cms_der::tlv(0xA0, &response_bytes),
    ]))
}

fn parse_response_bytes(input: &[u8]) -> Result<ParsedOcspWire> {
    let top = der::parse_tlv(input).context("parse OCSPResponse")?;
    if top.tag != 0x30 || top.total_len != input.len() {
        bail!("OCSP response is not one DER SEQUENCE");
    }
    let f = x509::raw_children(top.value)?;

    // Accept a raw BasicOCSPResponse for --ocsp-file as well as a full
    // RFC 6960 OCSPResponse. A BasicOCSPResponse starts with ResponseData
    // (SEQUENCE), signatureAlgorithm (SEQUENCE), signature (BIT STRING).
    if f.len() >= 3
        && f[0].first().copied() == Some(0x30)
        && f[1].first().copied() == Some(0x30)
        && f[2].first().copied() == Some(0x03)
    {
        let basic = input.to_vec();
        let full = wrap_basic_as_ocsp_response(&basic)?;
        return Ok(ParsedOcspWire {
            basic_der: basic,
            full_der: full,
        });
    }

    let status_raw = *f.first().context("OCSPResponse missing responseStatus")?;
    let status = der::parse_tlv(status_raw)?;
    if status.tag != 0x0A || status.value.len() != 1 {
        bail!("invalid OCSP responseStatus");
    }
    if status.value[0] != 0 {
        bail!("OCSP responder returned responseStatus={}", status.value[0]);
    }
    let wrapper_raw = *f
        .get(1)
        .context("successful OCSPResponse has no responseBytes")?;
    let wrapper = der::parse_tlv(wrapper_raw)?;
    if wrapper.tag != 0xA0 {
        bail!("OCSPResponse.responseBytes is not [0] EXPLICIT");
    }
    let wf = x509::raw_children(wrapper.value)?;
    let rb_raw = *wf.first().context("empty OCSP responseBytes wrapper")?;
    let rb = der::parse_tlv(rb_raw)?;
    if rb.tag != 0x30 {
        bail!("ResponseBytes is not SEQUENCE");
    }
    let rbf = x509::raw_children(rb.value)?;
    if rbf.len() != 2 {
        bail!("ResponseBytes must contain responseType and response");
    }
    if decode_oid_tlv(rbf[0])? != OID_BASIC_OCSP_RESPONSE {
        bail!("OCSP responseType is not id-pkix-ocsp-basic");
    }
    let octets = der::parse_tlv(rbf[1])?;
    if octets.tag != 0x04 {
        bail!("ResponseBytes.response is not OCTET STRING");
    }
    let basic = der::parse_tlv(octets.value)?;
    if basic.tag != 0x30 || basic.total_len != octets.value.len() {
        bail!("BasicOCSPResponse is malformed");
    }
    Ok(ParsedOcspWire {
        basic_der: octets.value.to_vec(),
        full_der: input.to_vec(),
    })
}

pub(crate) fn embedded_certificates(basic_der: &[u8]) -> Result<Vec<Vec<u8>>> {
    let basic = der::parse_tlv(basic_der)?;
    if basic.tag != 0x30 || basic.total_len != basic_der.len() {
        bail!("BasicOCSPResponse is malformed");
    }
    let fields = x509::raw_children(basic.value)?;
    let Some(certs_raw) = fields.get(3) else {
        return Ok(Vec::new());
    };
    let wrapper = der::parse_tlv(certs_raw)?;
    if wrapper.tag != 0xA0 {
        // A BasicOCSPResponse may omit certs entirely; if a fourth field is
        // present, however, RFC 6960 defines it as [0] EXPLICIT.
        bail!("BasicOCSPResponse.certs is not [0] EXPLICIT");
    }
    let inner = x509::raw_children(wrapper.value)?;
    let seq_raw = *inner
        .first()
        .context("empty BasicOCSPResponse.certs wrapper")?;
    let seq = der::parse_tlv(seq_raw)?;
    if seq.tag != 0x30 || seq.total_len != seq_raw.len() {
        bail!("BasicOCSPResponse.certs does not contain SEQUENCE OF Certificate");
    }
    let mut out = Vec::new();
    for cert in x509::raw_children(seq.value)? {
        // Parse enough to reject accidental non-certificate values here.
        x509::names(cert).context("parse certificate embedded in BasicOCSPResponse")?;
        if !out.iter().any(|c: &Vec<u8>| c.as_slice() == cert) {
            out.push(cert.to_vec());
        }
    }
    Ok(out)
}

fn cert_id_matches(cert_id_raw: &[u8], cert_der: &[u8], issuer_der: &[u8]) -> Result<bool> {
    let cid = der::parse_tlv(cert_id_raw)?;
    if cid.tag != 0x30 {
        bail!("OCSP CertID is not SEQUENCE");
    }
    let f = x509::raw_children(cid.value)?;
    if f.len() != 4 {
        bail!("OCSP CertID must have four fields");
    }
    let oid = algorithm_oid(f[0])?;
    if oid != OID_SHA1 {
        return Ok(false);
    }
    let name_hash = der::parse_tlv(f[1])?;
    let key_hash = der::parse_tlv(f[2])?;
    if name_hash.tag != 0x04 || key_hash.tag != 0x04 {
        bail!("OCSP CertID hashes are not OCTET STRINGs");
    }
    let cert_names = x509::names(cert_der)?;
    let issuer_names = x509::names(issuer_der)?;
    if cert_names.issuer_der != issuer_names.subject_der {
        return Ok(false);
    }
    if name_hash.value != sha1(&issuer_names.subject_der).as_slice() {
        return Ok(false);
    }
    if key_hash.value != sha1(&x509::subject_public_key_bits(issuer_der)?).as_slice() {
        return Ok(false);
    }
    Ok(integer_value(f[3])? == integer_value(&cert_names.serial_der)?)
}

/// Outcome of a non-panicking OCSP certificate-status lookup. Unlike
/// [`parse_for_certificate`], which is used by the CryptoPro XLT1 evidence
/// pipeline and rejects anything other than "good", this preserves the
/// revoked/unknown distinction for display purposes.
pub enum CertStatusOutcome {
    Good,
    Revoked { reason: Option<String> },
    Unknown,
}

struct MatchedSingleResponse {
    basic_der: Vec<u8>,
    full_der: Vec<u8>,
    embedded_certificates: Vec<Vec<u8>>,
    responder_id_der: Vec<u8>,
    produced_at_der: Vec<u8>,
    produced_at: String,
    status_tag: u8,
    status_value: Vec<u8>,
    this_update: String,
    this_update_unix: i64,
    next_update: Option<String>,
}

/// Parse a BasicOCSPResponse and locate the SingleResponse matching
/// `cert_der`/`issuer_der`, without interpreting the certStatus CHOICE.
fn locate_single_response(
    input: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
) -> Result<MatchedSingleResponse> {
    let wire = parse_response_bytes(input)?;
    let basic_der = wire.basic_der;
    let full_der = wire.full_der;
    let basic = der::parse_tlv(&basic_der)?;
    let embedded_certificates = embedded_certificates(&basic_der)?;
    let bf = x509::raw_children(basic.value)?;
    if bf.len() < 3 {
        bail!("BasicOCSPResponse is truncated");
    }
    let response_data = der::parse_tlv(bf[0])?;
    if response_data.tag != 0x30 {
        bail!("BasicOCSPResponse.tbsResponseData is not SEQUENCE");
    }
    let rf = x509::raw_children(response_data.value)?;
    let mut pos = 0usize;
    if rf.get(pos).and_then(|r| r.first()).copied() == Some(0xA0) {
        pos += 1;
    }
    let responder_id_der = rf
        .get(pos)
        .context("OCSP ResponseData missing responderID")?
        .to_vec();
    pos += 1;
    let produced_at_der = rf
        .get(pos)
        .context("OCSP ResponseData missing producedAt")?
        .to_vec();
    pos += 1;
    let produced_at = time_string(&produced_at_der)?;
    let responses_raw = *rf.get(pos).context("OCSP ResponseData missing responses")?;
    let responses = der::parse_tlv(responses_raw)?;
    if responses.tag != 0x30 {
        bail!("OCSP ResponseData.responses is not SEQUENCE OF");
    }

    for sr_raw in x509::raw_children(responses.value)? {
        let sr = der::parse_tlv(sr_raw)?;
        if sr.tag != 0x30 {
            continue;
        }
        let sf = x509::raw_children(sr.value)?;
        if sf.len() < 3 {
            continue;
        }
        if !cert_id_matches(sf[0], cert_der, issuer_der)? {
            continue;
        }
        let status = der::parse_tlv(sf[1])?;
        let status_tag = status.tag;
        let status_value = status.value.to_vec();
        let this_update = time_string(sf[2])?;
        let this_update_unix = x509::generalized_time_to_unix(&this_update)?;
        let mut next_update = None;
        for extra in sf.iter().skip(3) {
            let t = der::parse_tlv(extra)?;
            if t.tag == 0xA0 {
                let inner = x509::raw_children(t.value)?;
                if let Some(raw) = inner.first() {
                    next_update = Some(time_string(raw)?);
                }
            }
        }
        return Ok(MatchedSingleResponse {
            basic_der,
            full_der,
            embedded_certificates,
            responder_id_der,
            produced_at_der,
            produced_at,
            status_tag,
            status_value,
            this_update,
            this_update_unix,
            next_update,
        });
    }
    bail!("OCSP response contains no SingleResponse matching signer certificate")
}

/// Human-readable CRLReason (RFC 5280 5.3.1) label for a revoked certificate.
fn crl_reason_label(code: u8) -> &'static str {
    match code {
        0 => "unspecified",
        1 => "keyCompromise",
        2 => "cACompromise",
        3 => "affiliationChanged",
        4 => "superseded",
        5 => "cessationOfOperation",
        6 => "certificateHold",
        8 => "removeFromCRL",
        9 => "privilegeWithdrawn",
        10 => "aACompromise",
        _ => "unspecified",
    }
}

/// RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime, revocationReason [0] EXPLICIT CRLReason OPTIONAL }
fn parse_revoked_reason(revoked_info: &[u8]) -> Option<String> {
    let parts = x509::raw_children(revoked_info).ok()?;
    let wrapper_raw = parts
        .iter()
        .skip(1)
        .find(|r| r.first().copied() == Some(0xA0))?;
    let wrapper = der::parse_tlv(wrapper_raw).ok()?;
    let inner = x509::raw_children(wrapper.value).ok()?;
    let enum_tlv = der::parse_tlv(inner.first()?).ok()?;
    if enum_tlv.tag != 0x0A {
        return None;
    } // ENUMERATED
    let code = *enum_tlv.value.first()?;
    Some(crl_reason_label(code).to_string())
}

/// RFC 6960 §4.2.2.2: a response is acceptable only if it is signed by the
/// CA that issued the certificate in question, or by a delegated responder
/// certificate issued directly by that CA, carrying id-kp-OCSPSigning and
/// valid at producedAt.
pub(crate) fn verify_response_signature(
    basic_der: &[u8],
    embedded_certificates: &[Vec<u8>],
    issuer_der: &[u8],
    produced_at: &str,
) -> Result<()> {
    if x509::verify_signed_structure(basic_der, issuer_der).unwrap_or(false) {
        return Ok(());
    }
    let produced_at_unix = x509::generalized_time_to_unix(produced_at)?;
    for responder in embedded_certificates {
        let authorized = x509::verify_issued_by(responder, issuer_der).unwrap_or(false)
            && x509::has_extended_key_usage(responder, OID_KP_OCSP_SIGNING).unwrap_or(false)
            && x509::validity(responder)
                .map(|v| v.is_valid_at(produced_at_unix))
                .unwrap_or(false);
        if authorized && x509::verify_signed_structure(basic_der, responder).unwrap_or(false) {
            return Ok(());
        }
    }
    bail!(
        "OCSP response signature does not verify against the issuing CA or an authorized responder certificate"
    )
}

/// Freshness for a response obtained just now from a responder.
fn check_live_freshness(this_update_unix: i64, next_update: Option<&str>, now: i64) -> Result<()> {
    if this_update_unix > now + MAX_FUTURE_SKEW_SECS {
        bail!("OCSP thisUpdate is more than {MAX_FUTURE_SKEW_SECS}s in the future");
    }
    match next_update {
        Some(nu) => {
            if x509::generalized_time_to_unix(nu)? < now {
                bail!("OCSP response expired: nextUpdate={nu}");
            }
        }
        None => {
            if this_update_unix < now - MAX_AGE_WITHOUT_NEXT_UPDATE_SECS {
                bail!(
                    "OCSP response without nextUpdate is older than {MAX_AGE_WITHOUT_NEXT_UPDATE_SECS}s; possible replay"
                );
            }
        }
    }
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parse a response obtained from a responder or a file and check that it
/// is authentic before it is trusted or embedded.
fn parse_authentic(input: &[u8], cert_der: &[u8], issuer_der: &[u8]) -> Result<OcspEvidence> {
    let e = parse_for_certificate(input, cert_der, issuer_der)?;
    verify_response_signature(
        &e.basic_response,
        &e.embedded_certificates,
        issuer_der,
        &e.produced_at,
    )?;
    Ok(e)
}

pub fn parse_for_certificate(
    input: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
) -> Result<OcspEvidence> {
    let r = locate_single_response(input, cert_der, issuer_der)?;
    if r.status_tag != 0x80 {
        match r.status_tag {
            0xA1 | 0x81 => bail!("OCSP status for signer certificate is revoked"),
            0x82 | 0xA2 => bail!("OCSP status for signer certificate is unknown"),
            _ => bail!("unexpected OCSP certStatus tag 0x{:02X}", r.status_tag),
        }
    }
    Ok(OcspEvidence {
        basic_response: r.basic_der,
        full_response: r.full_der,
        responder_id_der: r.responder_id_der,
        produced_at_der: r.produced_at_der,
        produced_at: r.produced_at,
        this_update: r.this_update,
        this_update_unix: r.this_update_unix,
        next_update: r.next_update,
        embedded_certificates: r.embedded_certificates,
    })
}

/// Like [`parse_for_certificate`], but returns revoked/unknown as data
/// instead of an error.
fn status_outcome_for_certificate(
    input: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
) -> Result<CertStatusOutcome> {
    let r = locate_single_response(input, cert_der, issuer_der)?;
    Ok(match r.status_tag {
        0x80 => CertStatusOutcome::Good,
        0xA1 | 0x81 => CertStatusOutcome::Revoked {
            reason: parse_revoked_reason(&r.status_value),
        },
        0x82 | 0xA2 => CertStatusOutcome::Unknown,
        t => bail!("unexpected OCSP certStatus tag 0x{:02X}", t),
    })
}

fn http_post_ocsp(url: &str, request: &[u8], timeout_secs: u64) -> Result<Vec<u8>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .build();
    let response = agent
        .post(url)
        .set("Content-Type", "application/ocsp-request")
        .set("Accept", "application/ocsp-response")
        .send_bytes(request)
        .map_err(|e| anyhow::anyhow!("POST {url} failed: {e}"))?;
    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .with_context(|| format!("read OCSP response from {url}"))?;
    Ok(body)
}

pub fn fetch(
    cert_der: &[u8],
    issuer_der: &[u8],
    explicit_url: Option<&str>,
    timeout_secs: u64,
) -> Result<OcspEvidence> {
    let urls = if let Some(url) = explicit_url {
        vec![url.to_string()]
    } else {
        x509::aia_ocsp_urls(cert_der)?
    };
    if urls.is_empty() {
        bail!("signer certificate has no HTTP(S) OCSP AIA URL; use --ocsp-url or --ocsp-file");
    }
    let request = build_request(cert_der, issuer_der)?;
    let mut errors = Vec::new();
    for url in urls {
        match http_post_ocsp(&url, &request, timeout_secs).and_then(|r| {
            let e = parse_authentic(&r, cert_der, issuer_der)?;
            check_live_freshness(e.this_update_unix, e.next_update.as_deref(), unix_now())?;
            Ok(e)
        }) {
            Ok(v) => return Ok(v),
            Err(e) => errors.push(format!("{url}: {e:#}")),
        }
    }
    bail!(
        "could not obtain usable OCSP response: {}",
        errors.join("; ")
    )
}

/// Query the certificate's OCSP responder(s) and classify the result as
/// Good/Revoked/Unknown without failing on a non-good status. Only network,
/// transport, or malformed-response problems produce an `Err`.
pub fn check_status(
    cert_der: &[u8],
    issuer_der: &[u8],
    explicit_url: Option<&str>,
    timeout_secs: u64,
) -> Result<CertStatusOutcome> {
    let urls = if let Some(url) = explicit_url {
        vec![url.to_string()]
    } else {
        x509::aia_ocsp_urls(cert_der)?
    };
    if urls.is_empty() {
        bail!("certificate has no HTTP(S) OCSP AIA URL; use --ocsp-url");
    }
    let request = build_request(cert_der, issuer_der)?;
    let mut errors = Vec::new();
    for url in urls {
        match http_post_ocsp(&url, &request, timeout_secs).and_then(|r| {
            let m = locate_single_response(&r, cert_der, issuer_der)?;
            verify_response_signature(
                &m.basic_der,
                &m.embedded_certificates,
                issuer_der,
                &m.produced_at,
            )?;
            check_live_freshness(m.this_update_unix, m.next_update.as_deref(), unix_now())?;
            status_outcome_for_certificate(&r, cert_der, issuer_der)
        }) {
            Ok(v) => return Ok(v),
            Err(e) => errors.push(format!("{url}: {e:#}")),
        }
    }
    bail!(
        "could not obtain usable OCSP response: {}",
        errors.join("; ")
    )
}

pub fn load(path: &std::path::Path, cert_der: &[u8], issuer_der: &[u8]) -> Result<OcspEvidence> {
    let raw =
        std::fs::read(path).with_context(|| format!("read OCSP response {}", path.display()))?;
    parse_authentic(&raw, cert_der, issuer_der)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generalized_time_tlv(s: &str) -> Vec<u8> {
        let mut out = vec![0x18, s.len() as u8];
        out.extend_from_slice(s.as_bytes());
        out
    }

    /// RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime, revocationReason [0] EXPLICIT CRLReason OPTIONAL }
    fn revoked_info_with_reason(reason_code: u8) -> Vec<u8> {
        let mut out = generalized_time_tlv("20240101000000Z");
        out.extend_from_slice(&[0xA0, 0x03, 0x0A, 0x01, reason_code]);
        out
    }

    #[test]
    fn live_freshness_rules() {
        let now = 1_800_000_000;
        // Real-time responder (no nextUpdate): fresh, slightly ahead, replayed.
        assert!(check_live_freshness(now - 5, None, now).is_ok());
        assert!(check_live_freshness(now + 60, None, now).is_ok());
        assert!(check_live_freshness(now + 3600, None, now).is_err());
        assert!(check_live_freshness(now - 2 * 3600, None, now).is_err());
        // Pre-signed responses are fine until nextUpdate.
        assert!(check_live_freshness(now - 86_400, Some("20290101000000Z"), now).is_ok());
        assert!(check_live_freshness(now - 86_400, Some("20200101000000Z"), now).is_err());
    }

    #[test]
    fn parses_revocation_reason_key_compromise() {
        let revoked_info = revoked_info_with_reason(1);
        assert_eq!(
            parse_revoked_reason(&revoked_info),
            Some("keyCompromise".to_string())
        );
    }

    #[test]
    fn parses_revocation_reason_ca_compromise() {
        let revoked_info = revoked_info_with_reason(2);
        assert_eq!(
            parse_revoked_reason(&revoked_info),
            Some("cACompromise".to_string())
        );
    }

    #[test]
    fn missing_revocation_reason_returns_none() {
        let revoked_info = generalized_time_tlv("20240101000000Z");
        assert_eq!(parse_revoked_reason(&revoked_info), None);
    }

    #[test]
    fn unrecognized_reason_code_maps_to_unspecified() {
        let revoked_info = revoked_info_with_reason(99);
        assert_eq!(
            parse_revoked_reason(&revoked_info),
            Some("unspecified".to_string())
        );
    }
}
