// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use crate::{certcache, ocsp, x509};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::{fs, io::Read, path::Path, time::Duration};

#[derive(Debug, Clone)]
pub struct ValidationMaterial {
    /// CA certificates in path order: immediate issuer first, trust anchor last.
    pub ca_chain: Vec<Vec<u8>>,
    /// CryptoPro-compatible evidence for the signer certificate.
    pub signer_ocsp: ocsp::OcspEvidence,
    /// CRLs for non-trust-anchor CA certificates in ca_chain order.
    /// For [issuer, root], this contains one CRL for `issuer`.
    pub ca_crls: Vec<Vec<u8>>,
}

pub fn load_certificate(path: &Path) -> Result<Vec<u8>> {
    normalize_pem_or_der(
        &fs::read(path).with_context(|| format!("read certificate {}", path.display()))?,
        "CERTIFICATE",
    )
}

pub fn load_crl(path: &Path) -> Result<Vec<u8>> {
    normalize_pem_or_der(
        &fs::read(path).with_context(|| format!("read CRL {}", path.display()))?,
        "X509 CRL",
    )
}

fn normalize_pem_or_der(input: &[u8], label: &str) -> Result<Vec<u8>> {
    if !input.starts_with(b"-----BEGIN ") {
        return Ok(input.to_vec());
    }
    let text = std::str::from_utf8(input).context("PEM is not UTF-8/ASCII")?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let a = text
        .find(&begin)
        .with_context(|| format!("PEM does not contain {begin}"))?
        + begin.len();
    let b = text[a..]
        .find(&end)
        .map(|n| a + n)
        .with_context(|| format!("PEM does not contain {end}"))?;
    let body: String = text[a..b]
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    STANDARD
        .decode(body.as_bytes())
        .context("decode PEM base64")
}

fn http_get(url: &str, timeout_secs: u64) -> Result<Vec<u8>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .build();
    let response = agent
        .get(url)
        .call()
        .map_err(|e| anyhow::anyhow!("GET {url} failed: {e}"))?;
    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .with_context(|| format!("read {url}"))?;
    Ok(body)
}

fn fetch_certificate(url: &str, timeout_secs: u64) -> Result<Vec<u8>> {
    let body = http_get(url, timeout_secs)?;
    normalize_pem_or_der(&body, "CERTIFICATE")
        .with_context(|| format!("decode CA certificate from {url}"))
}

fn fetch_crl(url: &str, timeout_secs: u64) -> Result<Vec<u8>> {
    let body = http_get(url, timeout_secs)?;
    normalize_pem_or_der(&body, "X509 CRL").with_context(|| format!("decode CRL from {url}"))
}

pub fn validate_chain_links(signer: &[u8], ca_chain: &[Vec<u8>]) -> Result<()> {
    let mut current = x509::names(signer)?;
    for (i, cert) in ca_chain.iter().enumerate() {
        let ca = x509::names(cert).with_context(|| format!("parse CA certificate #{i}"))?;
        if current.issuer_der != ca.subject_der {
            bail!("CA certificate #{i} subject does not match issuer of previous certificate");
        }
        current = ca;
    }
    Ok(())
}

/// Follow HTTP(S) caIssuers AIA links until a self-issued certificate is found.
pub fn fetch_ca_chain(signer: &[u8], timeout_secs: u64) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut current = signer.to_vec();
    for depth in 0..8 {
        let n = x509::names(&current)?;
        if n.issuer_der == n.subject_der {
            break;
        }
        let urls = x509::aia_ca_issuers_urls(&current)?;
        if urls.is_empty() {
            bail!("certificate path stopped at depth {depth}: no HTTP(S) caIssuers AIA URL; supply --chain-cert manually");
        }
        let mut found = None;
        let mut errors = Vec::new();
        for url in urls {
            match fetch_certificate(&url, timeout_secs).and_then(|cert| {
                let ca = x509::names(&cert)?;
                if ca.subject_der != n.issuer_der {
                    bail!("downloaded certificate subject does not match issuer");
                }
                Ok(cert)
            }) {
                Ok(cert) => {
                    found = Some(cert);
                    break;
                }
                Err(e) => errors.push(format!("{url}: {e}")),
            }
        }
        let cert = found.with_context(|| {
            format!("could not fetch issuer certificate: {}", errors.join("; "))
        })?;
        if out.iter().any(|v| v == &cert) {
            bail!("AIA certificate chain contains a loop");
        }
        current = cert.clone();
        out.push(cert);
    }
    if out.len() >= 8 {
        bail!("certificate chain exceeds safety limit of 8 CA certificates");
    }
    validate_chain_links(signer, &out)?;
    Ok(out)
}

/// Fetch CRLs only for intermediate CA certificates. CryptoPro's XLT1
/// verifier requires OCSP evidence for the signer certificate; CRLs remain
/// acceptable for intermediate CAs. The final trust anchor has no entry.
pub fn fetch_ca_crls(ca_chain: &[Vec<u8>], timeout_secs: u64) -> Result<Vec<Vec<u8>>> {
    if ca_chain.is_empty() {
        bail!("CAdES-X Long Type 1 needs a CA chain");
    }
    let mut out = Vec::new();
    for (i, cert) in ca_chain
        .iter()
        .take(ca_chain.len().saturating_sub(1))
        .enumerate()
    {
        let names = x509::names(cert)?;
        let urls = x509::crl_distribution_urls(cert)?;
        if urls.is_empty() {
            bail!(
                "CA certificate #{i} has no HTTP(S) CRL Distribution Point; supply --crl manually"
            );
        }
        let mut found = None;
        let mut errors = Vec::new();
        for url in urls {
            match fetch_crl(&url, timeout_secs).and_then(|crl| {
                let issuer = x509::crl_issuer_der(&crl)?;
                if issuer != names.issuer_der {
                    bail!("CRL issuer does not match CA certificate issuer");
                }
                Ok(crl)
            }) {
                Ok(crl) => {
                    found = Some(crl);
                    break;
                }
                Err(e) => errors.push(format!("{url}: {e}")),
            }
        }
        out.push(found.with_context(|| {
            format!(
                "could not fetch CRL for CA certificate #{i}: {}",
                errors.join("; ")
            )
        })?);
    }
    Ok(out)
}

pub fn validate_ca_crl_order(ca_chain: &[Vec<u8>], crls: &[Vec<u8>]) -> Result<()> {
    if ca_chain.is_empty() {
        bail!("CA chain is empty");
    }
    let expected = ca_chain.len().saturating_sub(1);
    if crls.len() != expected {
        bail!(
            "need exactly {expected} CA CRLs (one per non-root CA); got {}",
            crls.len()
        );
    }
    for (i, (cert, crl)) in ca_chain.iter().take(expected).zip(crls).enumerate() {
        let cert_names = x509::names(cert)?;
        let crl_issuer = x509::crl_issuer_der(crl).with_context(|| format!("parse CA CRL #{i}"))?;
        if crl_issuer != cert_names.issuer_der {
            bail!("CA CRL #{i} issuer does not match CA certificate #{i} issuer");
        }
    }
    Ok(())
}

fn validate_signer_ocsp_timing(e: &ocsp::OcspEvidence, inner_timestamp_unix: i64) -> Result<()> {
    if e.next_update.is_some() {
        bail!("CryptoPro XLT1 requires signer OCSP evidence without nextUpdate; responder returned nextUpdate={}", e.next_update.as_deref().unwrap_or("?"));
    }
    if e.this_update_unix < inner_timestamp_unix {
        bail!("signer OCSP thisUpdate={} is earlier than the signature timestamp; CryptoPro requires innerTimestamp <= thisUpdate <= outerTimestamp", e.this_update);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn collect(
    signer: &[u8],
    manual_chain: Vec<Vec<u8>>,
    manual_ca_crls: Vec<Vec<u8>>,
    manual_ocsp_file: Option<&Path>,
    ocsp_url: Option<&str>,
    allow_fetch: bool,
    timeout_secs: u64,
    inner_timestamp_unix: i64,
) -> Result<ValidationMaterial> {
    let ca_chain = if manual_chain.is_empty() {
        if !allow_fetch {
            bail!("no CA chain supplied and validation-data fetching is disabled");
        }
        fetch_ca_chain(signer, timeout_secs)?
    } else {
        validate_chain_links(signer, &manual_chain)?;
        manual_chain
    };
    if ca_chain.is_empty() {
        bail!("could not establish a CA chain");
    }

    let issuer = &ca_chain[0];
    let signer_ocsp = if let Some(path) = manual_ocsp_file {
        ocsp::load(path, signer, issuer)?
    } else {
        if !allow_fetch && ocsp_url.is_none() {
            bail!("no signer OCSP response supplied and fetching is disabled");
        }
        ocsp::fetch(signer, issuer, ocsp_url, timeout_secs)?
    };
    validate_signer_ocsp_timing(&signer_ocsp, inner_timestamp_unix)?;

    let ca_crls = if manual_ca_crls.is_empty() {
        if !allow_fetch {
            bail!("no CA CRLs supplied and validation-data fetching is disabled");
        }
        fetch_ca_crls(&ca_chain, timeout_secs)?
    } else {
        validate_ca_crl_order(&ca_chain, &manual_ca_crls)?;
        manual_ca_crls
    };
    validate_ca_crl_order(&ca_chain, &ca_crls)?;

    Ok(ValidationMaterial {
        ca_chain,
        signer_ocsp,
        ca_crls,
    })
}

/// Collect long-term validation evidence for the signer of an RFC 3161 token.
/// Unlike the CryptoPro outer-signer profile, a TSA OCSP response is allowed to
/// carry nextUpdate; the important temporal property is that its thisUpdate is
/// not earlier than the timestamp token's genTime.
pub fn collect_tsa(
    tsa_signer: &[u8],
    timeout_secs: u64,
    timestamp_gen_time_unix: i64,
) -> Result<ValidationMaterial> {
    let ca_chain = fetch_ca_chain(tsa_signer, timeout_secs)?;
    if ca_chain.is_empty() {
        bail!("could not establish TSA CA chain");
    }
    let issuer = &ca_chain[0];
    let signer_ocsp = ocsp::fetch(tsa_signer, issuer, None, timeout_secs)
        .context("obtain OCSP evidence for TSA signing certificate")?;
    if signer_ocsp.this_update_unix < timestamp_gen_time_unix {
        bail!(
            "TSA OCSP thisUpdate={} is earlier than timestamp genTime; long-term evidence must post-date the timestamp",
            signer_ocsp.this_update
        );
    }
    let ca_crls = fetch_ca_crls(&ca_chain, timeout_secs)?;
    validate_ca_crl_order(&ca_chain, &ca_crls)?;
    Ok(ValidationMaterial {
        ca_chain,
        signer_ocsp,
        ca_crls,
    })
}

/// Fetch the immediate issuer certificate via the AIA `caIssuers` extension.
/// Returns `Ok(None)` when `cert_der` is self-signed (no issuer to find) or
/// carries no HTTP(S) `caIssuers` URL at all. This intentionally resolves
/// only one level, unlike [`fetch_ca_chain`], which walks to the root.
pub fn fetch_immediate_issuer(cert_der: &[u8], timeout_secs: u64) -> Result<Option<Vec<u8>>> {
    let names = x509::names(cert_der)?;
    if names.issuer_der == names.subject_der {
        return Ok(None);
    }
    let urls = x509::aia_ca_issuers_urls(cert_der)?;
    if urls.is_empty() {
        return Ok(None);
    }
    let mut errors = Vec::new();
    for url in urls {
        match fetch_certificate(&url, timeout_secs).and_then(|cert| {
            let issuer_names = x509::names(&cert)?;
            if issuer_names.subject_der != names.issuer_der {
                bail!("downloaded certificate subject does not match issuer");
            }
            Ok(cert)
        }) {
            Ok(cert) => return Ok(Some(cert)),
            Err(e) => errors.push(format!("{url}: {e}")),
        }
    }
    bail!("could not fetch issuer certificate: {}", errors.join("; "))
}

/// Check certificate date validity and (when `allow_network`) revocation
/// status, using the on-disk certificate cache to avoid redundant OCSP
/// queries. In offline mode, only an already-fresh cached result is
/// reported; otherwise the revocation status is left unchecked (`None`).
///
/// Certificates that are already invalid at `now` (expired or not yet
/// valid) never trigger a revocation check: they cannot be used regardless
/// of revocation status, so there is no point spending a network round trip
/// (or even a cache lookup) on them.
pub fn check_certificate(
    cert_der: &[u8],
    ocsp_url: Option<&str>,
    timeout_secs: u64,
    cache: &mut certcache::CertCache,
    allow_network: bool,
    now: i64,
) -> Result<x509::CertCheck> {
    let validity = x509::validity(cert_der)?;

    let revocation_status = if !validity.is_valid_at(now) {
        None
    } else if allow_network {
        Some(cache.check_revocation(
            cert_der,
            || fetch_immediate_issuer(cert_der, timeout_secs),
            ocsp_url,
            timeout_secs,
        ))
    } else {
        cache.peek_revocation(cert_der)
    };

    Ok(x509::CertCheck {
        validity,
        revocation_status,
    })
}

#[derive(Debug)]
pub struct PkiVerification {
    pub cert_check: x509::CertCheck,
    pub chain_depth: usize,
}

impl PkiVerification {
    pub fn is_valid(&self, now: i64) -> bool {
        if !self.cert_check.validity.is_valid_at(now) {
            return false;
        }
        matches!(
            self.cert_check.revocation_status,
            Some(x509::RevocationCheckResult::Good)
        )
    }
}

/// Build a CA chain for `signer` using `pool` first, then optional AIA fetch.
pub fn build_ca_chain(
    signer: &[u8],
    pool: &[Vec<u8>],
    allow_fetch: bool,
    timeout_secs: u64,
) -> Result<Vec<Vec<u8>>> {
    let signer_names = x509::names(signer)?;
    if signer_names.issuer_der == signer_names.subject_der {
        return Ok(Vec::new());
    }

    let mut chain = Vec::new();
    let mut current = signer.to_vec();
    for _ in 0..8 {
        let current_names = x509::names(&current)?;
        if current_names.issuer_der == current_names.subject_der {
            break;
        }

        let issuer = pool
            .iter()
            .find(|c| {
                x509::names(c)
                    .map(|n| n.subject_der == current_names.issuer_der)
                    .unwrap_or(false)
            })
            .cloned();

        let issuer = match issuer {
            Some(cert) => cert,
            None if allow_fetch => {
                fetch_immediate_issuer(&current, timeout_secs)?.with_context(|| {
                    format!(
                        "issuer certificate for {} not found in signature evidence or AIA",
                        x509::extract_subject_cn(&current)
                            .ok()
                            .flatten()
                            .unwrap_or_else(|| "signer".to_string())
                    )
                })?
            }
            None => bail!("issuer certificate not found in available certificate pool"),
        };

        if chain.iter().any(|c| c == &issuer) {
            bail!("certificate chain contains a loop");
        }
        chain.push(issuer.clone());
        current = issuer;
    }

    if chain.len() >= 8 {
        bail!("certificate chain exceeds safety limit of 8 CA certificates");
    }
    validate_chain_links(signer, &chain)?;
    Ok(chain)
}

pub fn verify_ca_chain(signer: &[u8], ca_chain: &[Vec<u8>]) -> Result<()> {
    let mut subject = signer;
    for (i, issuer) in ca_chain.iter().enumerate() {
        if !x509::verify_issued_by(subject, issuer)? {
            bail!("CA certificate #{i} failed to verify the signature on the previous certificate");
        }
        subject = issuer;
    }
    Ok(())
}

/// Validate signer certificate validity, revocation status and CA chain signatures.
pub fn verify_signer_pki(
    signer: &[u8],
    embedded_certs: Option<&[Vec<u8>]>,
    cache: &mut certcache::CertCache,
    allow_network: bool,
    refresh: bool,
    timeout_secs: u64,
    now: i64,
) -> Result<PkiVerification> {
    if refresh {
        cache.invalidate_revocation(signer);
    }

    let mut pool = vec![signer.to_vec()];
    if let Some(certs) = embedded_certs {
        for cert in certs {
            if !pool.iter().any(|existing| existing == cert) {
                pool.push(cert.clone());
            }
        }
    }

    let ca_chain = build_ca_chain(signer, &pool, allow_network, timeout_secs)?;
    verify_ca_chain(signer, &ca_chain)?;
    let cert_check = check_certificate(signer, None, timeout_secs, cache, allow_network, now)?;

    Ok(PkiVerification {
        cert_check,
        chain_depth: ca_chain.len(),
    })
}

#[cfg(test)]
mod issuer_tests {
    use super::*;

    fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, value.len() as u8];
        out.extend_from_slice(value);
        out
    }

    /// Builds a minimal (non-conformant, but `x509::names`-parseable) fake
    /// certificate: SEQUENCE(TBSCertificate, signatureAlgorithm, signature),
    /// where TBSCertificate is
    /// SEQUENCE(serial, signatureAlgorithm, issuer, validity, subject).
    fn fake_certificate(issuer: &[u8], subject: &[u8]) -> Vec<u8> {
        let serial = der_tlv(0x02, &[0x01]);
        let sig_alg = der_tlv(0x30, &[]);
        let validity = der_tlv(0x30, &[]);
        let mut tbs_value = Vec::new();
        tbs_value.extend_from_slice(&serial);
        tbs_value.extend_from_slice(&sig_alg);
        tbs_value.extend_from_slice(issuer);
        tbs_value.extend_from_slice(&validity);
        tbs_value.extend_from_slice(subject);
        let mut cert_value = der_tlv(0x30, &tbs_value);
        cert_value.extend_from_slice(&sig_alg);
        cert_value.extend_from_slice(&der_tlv(0x03, &[0x00]));
        der_tlv(0x30, &cert_value)
    }

    #[test]
    fn self_signed_certificate_has_no_issuer_to_fetch() {
        let name = der_tlv(0x30, &[]);
        let cert = fake_certificate(&name, &name);
        // No network should be attempted: issuer_der == subject_der short-circuits immediately.
        let result =
            fetch_immediate_issuer(&cert, 1).expect("self-signed short-circuit must not error");
        assert!(result.is_none());
    }

    #[test]
    fn certificate_without_aia_has_no_issuer_to_fetch() {
        let issuer = der_tlv(0x30, &[0x30, 0x00]);
        let subject = der_tlv(0x30, &[]);
        let cert = fake_certificate(&issuer, &subject);
        // No AIA caIssuers extension present at all: nothing to fetch, no network attempted.
        let result =
            fetch_immediate_issuer(&cert, 1).expect("missing-AIA short-circuit must not error");
        assert!(result.is_none());
    }
}
