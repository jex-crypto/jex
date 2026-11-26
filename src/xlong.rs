// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use crate::{cades, cms_der, der, ocsp, timestamp, validation, x509};
use anyhow::{bail, Context, Result};

pub const OID_CERT_REFS: &str = "1.2.840.113549.1.9.16.2.21";
pub const OID_REVOCATION_REFS: &str = "1.2.840.113549.1.9.16.2.22";
pub const OID_CERT_VALUES: &str = "1.2.840.113549.1.9.16.2.23";
pub const OID_REVOCATION_VALUES: &str = "1.2.840.113549.1.9.16.2.24";
pub const OID_ESC_TIMESTAMP: &str = "1.2.840.113549.1.9.16.2.25";

#[derive(Debug)]
pub struct EnhanceResult {
    pub der: Vec<u8>,
    pub ca_count: usize,
    pub crl_count: usize,
    pub ocsp_count: usize,
    pub esc_timestamp: timestamp::TimestampTokenInfo,
    pub signature_tsa_evidence: TimestampEvidenceSummary,
    pub esc_tsa_evidence: TimestampEvidenceSummary,
}

#[derive(Debug, Clone)]
pub struct TimestampEvidenceSummary {
    pub ca_count: usize,
    pub crl_count: usize,
    pub ocsp_count: usize,
}

fn attribute(oid: &str, value: Vec<u8>) -> Result<Vec<u8>> {
    Ok(cms_der::sequence(&[
        cms_der::oid(oid)?,
        cms_der::set(vec![value]),
    ]))
}

fn issuer_serial(cert_der: &[u8]) -> Result<Vec<u8>> {
    let n = x509::names(cert_der)?;
    let general_names = cms_der::sequence(&[cms_der::tlv(0xA4, &n.issuer_der)]);
    Ok(cms_der::sequence(&[general_names, n.serial_der]))
}

fn other_hash(digest_oid: &str, value: &[u8]) -> Result<Vec<u8>> {
    let hash = cades::digest_by_oid(digest_oid, value)?;
    Ok(cms_der::sequence(&[
        cms_der::algorithm_identifier(digest_oid)?,
        cms_der::octet_string(&hash),
    ]))
}

fn referenced_certificates(ca_chain: &[Vec<u8>], signer_ocsp: &ocsp::OcspEvidence) -> Vec<Vec<u8>> {
    // CryptoPro-generated XLT1 includes not only the CA path but also the
    // certificate(s) carried in BasicOCSPResponse.certs (normally the OCSP
    // responder signing certificate) in CompleteCertificateRefs.
    let mut out = ca_chain.to_vec();
    for cert in &signer_ocsp.embedded_certificates {
        if !out.iter().any(|c| c == cert) {
            out.push(cert.clone());
        }
    }
    out
}

fn complete_certificate_refs(certificates: &[Vec<u8>], digest_oid: &str) -> Result<Vec<u8>> {
    let mut ids = Vec::with_capacity(certificates.len());
    for cert in certificates {
        // OtherCertID ::= SEQUENCE { otherCertHash OtherHash, issuerSerial IssuerSerial OPTIONAL }
        ids.push(cms_der::sequence(&[
            other_hash(digest_oid, cert)?,
            issuer_serial(cert)?,
        ]));
    }
    Ok(cms_der::sequence(&ids))
}

fn crl_identifier(crl: &[u8]) -> Result<Option<Vec<u8>>> {
    let p = x509::crl_identifier_parts(crl)?;
    // RFC 5126 CrlIdentifier fixes crlIssuedTime to UTCTime. For the usual
    // 2020s CRLs this is exactly the encoding used by TBSCertList.thisUpdate.
    // If a future CRL uses GeneralizedTime, omit this OPTIONAL identifier
    // rather than encode a value with the wrong ASN.1 type.
    if p.this_update_der.first().copied() != Some(0x17) {
        return Ok(None);
    }
    let mut fields = vec![p.issuer_der, p.this_update_der];
    if let Some(number) = p.crl_number_der {
        fields.push(number);
    }
    Ok(Some(cms_der::sequence(&fields)))
}

fn crl_ocsp_ref_for_crl(crl: &[u8], digest_oid: &str) -> Result<Vec<u8>> {
    // CrlValidatedID ::= SEQUENCE { crlHash OtherHash, crlIdentifier OPTIONAL }
    // ETSI recommends crlIdentifier whenever the CRL cannot otherwise be
    // inferred unambiguously. crlHash is over the *entire* DER CertificateList,
    // including its signature. `crl` is already normalized to exactly that DER.
    let mut validated_fields = vec![other_hash(digest_oid, crl)?];
    if let Some(identifier) = crl_identifier(crl)? {
        validated_fields.push(identifier);
    }
    let validated = cms_der::sequence(&validated_fields);
    // CRLListID ::= SEQUENCE { crls SEQUENCE OF CrlValidatedID }
    let crl_list = cms_der::sequence(&[cms_der::sequence(&[validated])]);
    // CrlOcspRef.crlids is [0] EXPLICIT in the RFC 5126 explicit-tag module.
    Ok(cms_der::sequence(&[cms_der::tlv(0xA0, &crl_list)]))
}

fn crl_ocsp_ref_for_ocsp(e: &ocsp::OcspEvidence, digest_oid: &str) -> Result<Vec<u8>> {
    // OcspIdentifier ::= SEQUENCE { ocspResponderID ResponderID, producedAt GeneralizedTime }
    let identifier = cms_der::sequence(&[e.responder_id_der.clone(), e.produced_at_der.clone()]);
    // Include ocspRepHash to remove ambiguity and to bind the reference to the
    // exact BasicOCSPResponse that is embedded in revocationValues.
    let response_id = cms_der::sequence(&[identifier, other_hash(digest_oid, &e.basic_response)?]);
    // OcspListID ::= SEQUENCE { ocspResponses SEQUENCE OF OcspResponsesID }
    let list = cms_der::sequence(&[cms_der::sequence(&[response_id])]);
    // CrlOcspRef.ocspids is [1] EXPLICIT in the RFC 5126 explicit-tag module.
    Ok(cms_der::sequence(&[cms_der::tlv(0xA1, &list)]))
}

fn complete_revocation_refs(
    ca_chain: &[Vec<u8>],
    signer_ocsp: &ocsp::OcspEvidence,
    ca_crls: &[Vec<u8>],
    digest_oid: &str,
) -> Result<Vec<u8>> {
    let expected_ca_crls = ca_chain.len().saturating_sub(1);
    if ca_crls.len() != expected_ca_crls {
        bail!(
            "revocation reference construction expects {expected_ca_crls} CA CRLs, got {}",
            ca_crls.len()
        );
    }
    let referenced = referenced_certificates(ca_chain, signer_ocsp);
    let extra_ocsp_certs = referenced.len().saturating_sub(ca_chain.len());
    let mut refs = Vec::with_capacity(1 + referenced.len());
    // Status of the primary signer is proven by this OCSP response.
    refs.push(crl_ocsp_ref_for_ocsp(signer_ocsp, digest_oid)?);
    // Each non-root CA uses its CRL evidence.
    for crl in ca_crls {
        refs.push(crl_ocsp_ref_for_crl(crl, digest_oid)?);
    }
    // Trust anchor needs no revocation evidence.
    refs.push(cms_der::sequence(&[]));
    // CryptoPro's own XLT1 output gives the OCSP responder certificate a
    // CompleteCertificateRef and an empty CrlOcspRef. OCSP signing certs
    // normally carry id-pkix-ocsp-nocheck, so no recursive status proof is
    // embedded here.
    for _ in 0..extra_ocsp_certs {
        refs.push(cms_der::sequence(&[]));
    }
    Ok(cms_der::sequence(&refs))
}

fn certificate_values(certificates: &[Vec<u8>]) -> Vec<u8> {
    cms_der::sequence(certificates)
}

fn certificate_values_for_signer(
    signer: &[u8],
    ca_chain: &[Vec<u8>],
    signer_ocsp: &ocsp::OcspEvidence,
) -> Vec<u8> {
    // Match CryptoPro's XLT1 layout: the primary signer certificate is kept
    // in CertificateValues too, followed by the certificates referenced by
    // CompleteCertificateRefs (CA path + OCSP responder signer certificate).
    let mut values = vec![signer.to_vec()];
    for cert in referenced_certificates(ca_chain, signer_ocsp) {
        if !values.iter().any(|c| c == &cert) {
            values.push(cert);
        }
    }
    certificate_values(&values)
}

fn revocation_values(signer_ocsp: &ocsp::OcspEvidence, ca_crls: &[Vec<u8>]) -> Vec<u8> {
    // RevocationValues ::= SEQUENCE {
    //   crlVals  [0] SEQUENCE OF CertificateList OPTIONAL,
    //   ocspVals [1] SEQUENCE OF BasicOCSPResponse OPTIONAL, ... }
    // RFC 5126's ASN.1 module uses EXPLICIT TAGS.
    let mut fields = Vec::new();
    if !ca_crls.is_empty() {
        let crl_sequence = cms_der::sequence(ca_crls);
        fields.push(cms_der::tlv(0xA0, &crl_sequence));
    }
    let ocsp_sequence = cms_der::sequence(&[signer_ocsp.basic_response.clone()]);
    fields.push(cms_der::tlv(0xA1, &ocsp_sequence));
    cms_der::sequence(&fields)
}

fn revocation_values_many(ocsps: &[ocsp::OcspEvidence], crls: &[Vec<u8>]) -> Vec<u8> {
    let mut fields = Vec::new();
    if !crls.is_empty() {
        let crl_sequence = cms_der::sequence(crls);
        fields.push(cms_der::tlv(0xA0, &crl_sequence));
    }
    if !ocsps.is_empty() {
        let values = ocsps
            .iter()
            .map(|e| e.basic_response.clone())
            .collect::<Vec<_>>();
        let ocsp_sequence = cms_der::sequence(&values);
        fields.push(cms_der::tlv(0xA1, &ocsp_sequence));
    }
    cms_der::sequence(&fields)
}

#[derive(Debug, Clone)]
enum CertStatusEvidence {
    None,
    Crl(Vec<u8>),
    Ocsp(ocsp::OcspEvidence),
}

#[derive(Debug, Clone)]
struct OuterEvidencePlan {
    /// Certificates referenced by CompleteCertificateRefs. The outer CMS signer
    /// itself is intentionally NOT present here; its revocation reference is the
    /// first CrlOcspRef in CompleteRevocationRefs.
    certs: Vec<Vec<u8>>,
    status: Vec<CertStatusEvidence>,
}

impl OuterEvidencePlan {
    fn new() -> Self {
        Self {
            certs: Vec::new(),
            status: Vec::new(),
        }
    }

    fn status_rank(s: &CertStatusEvidence) -> u8 {
        match s {
            CertStatusEvidence::None => 0,
            CertStatusEvidence::Crl(_) => 1,
            CertStatusEvidence::Ocsp(_) => 2,
        }
    }

    fn push(&mut self, cert: &[u8], evidence: CertStatusEvidence) {
        if let Some(i) = self.certs.iter().position(|c| c.as_slice() == cert) {
            if Self::status_rank(&evidence) > Self::status_rank(&self.status[i]) {
                self.status[i] = evidence;
            }
            return;
        }
        self.certs.push(cert.to_vec());
        self.status.push(evidence);
    }

    fn append_primary_chain(&mut self, material: &validation::ValidationMaterial) -> Result<()> {
        for (i, cert) in material.ca_chain.iter().enumerate() {
            let evidence = if i < material.ca_chain.len().saturating_sub(1) {
                CertStatusEvidence::Crl(
                    material
                        .ca_crls
                        .get(i)
                        .context("missing CA CRL while building outer evidence plan")?
                        .clone(),
                )
            } else {
                CertStatusEvidence::None
            };
            self.push(cert, evidence);
        }
        for cert in &material.signer_ocsp.embedded_certificates {
            self.push(cert, CertStatusEvidence::None);
        }
        Ok(())
    }

    fn append_secondary_signer(
        &mut self,
        signer_cert: &[u8],
        material: &validation::ValidationMaterial,
    ) -> Result<()> {
        // Unlike the outer CMS signer, a TSA signer is an OtherCertID and must
        // therefore have its OCSP status at the matching CompleteRevocationRefs
        // position.
        self.push(
            signer_cert,
            CertStatusEvidence::Ocsp(material.signer_ocsp.clone()),
        );
        for (i, cert) in material.ca_chain.iter().enumerate() {
            let evidence = if i < material.ca_chain.len().saturating_sub(1) {
                CertStatusEvidence::Crl(
                    material
                        .ca_crls
                        .get(i)
                        .context("missing TSA CA CRL while building outer evidence plan")?
                        .clone(),
                )
            } else {
                CertStatusEvidence::None
            };
            self.push(cert, evidence);
        }
        for cert in &material.signer_ocsp.embedded_certificates {
            self.push(cert, CertStatusEvidence::None);
        }
        Ok(())
    }
}

fn complete_revocation_refs_for_plan(
    primary_signer_ocsp: &ocsp::OcspEvidence,
    plan: &OuterEvidencePlan,
    digest_oid: &str,
) -> Result<Vec<u8>> {
    if plan.certs.len() != plan.status.len() {
        bail!("internal outer evidence plan length mismatch");
    }
    let mut refs = Vec::with_capacity(1 + plan.status.len());
    refs.push(crl_ocsp_ref_for_ocsp(primary_signer_ocsp, digest_oid)?);
    for evidence in &plan.status {
        refs.push(match evidence {
            CertStatusEvidence::None => cms_der::sequence(&[]),
            CertStatusEvidence::Crl(crl) => crl_ocsp_ref_for_crl(crl, digest_oid)?,
            CertStatusEvidence::Ocsp(ocsp) => crl_ocsp_ref_for_ocsp(ocsp, digest_oid)?,
        });
    }
    Ok(cms_der::sequence(&refs))
}

fn values_for_plan(
    primary_signer: &[u8],
    primary_signer_ocsp: &ocsp::OcspEvidence,
    plan: &OuterEvidencePlan,
) -> (Vec<u8>, Vec<u8>) {
    let mut certs = vec![primary_signer.to_vec()];
    for cert in &plan.certs {
        if !certs.iter().any(|c| c == cert) {
            certs.push(cert.clone());
        }
    }

    let mut ocsps = vec![primary_signer_ocsp.clone()];
    let mut crls: Vec<Vec<u8>> = Vec::new();
    for evidence in &plan.status {
        match evidence {
            CertStatusEvidence::None => {}
            CertStatusEvidence::Crl(crl) => {
                if !crls.iter().any(|v| v == crl) {
                    crls.push(crl.clone());
                }
            }
            CertStatusEvidence::Ocsp(e) => {
                if !ocsps.iter().any(|v| v.basic_response == e.basic_response) {
                    ocsps.push(e.clone());
                }
            }
        }
    }
    (
        certificate_values(&certs),
        revocation_values_many(&ocsps, &crls),
    )
}

fn build_x_input(
    signature: &[u8],
    sig_ts_attr: &[u8],
    cert_refs_attr: &[u8],
    rev_refs_attr: &[u8],
) -> Result<Vec<u8>> {
    let mut x_input = Vec::new();
    x_input.extend_from_slice(signature);
    x_input.extend_from_slice(&attribute_value_bytes_for_x_timestamp(sig_ts_attr)?);
    x_input.extend_from_slice(&attribute_value_bytes_for_x_timestamp(cert_refs_attr)?);
    x_input.extend_from_slice(&attribute_value_bytes_for_x_timestamp(rev_refs_attr)?);
    Ok(x_input)
}

/// Add the long-term validation evidence required to validate an RFC 3161
/// token without network access. The TSA signature itself is untouched:
/// completeCertificateRefs / completeRevocationRefs / certificateValues /
/// revocationValues are unsigned attributes of the token's SignerInfo.
fn augment_timestamp_token_with_material(
    token: &[u8],
    info: &timestamp::TimestampTokenInfo,
    signer: &timestamp::TimestampSignerMeta,
    material: &validation::ValidationMaterial,
) -> Result<(Vec<u8>, TimestampEvidenceSummary)> {
    let digest_oid = &info.digest_oid;
    let referenced = referenced_certificates(&material.ca_chain, &material.signer_ocsp);
    let cert_refs_attr = attribute(
        OID_CERT_REFS,
        complete_certificate_refs(&referenced, digest_oid)?,
    )?;
    let rev_refs_attr = attribute(
        OID_REVOCATION_REFS,
        complete_revocation_refs(
            &material.ca_chain,
            &material.signer_ocsp,
            &material.ca_crls,
            digest_oid,
        )?,
    )?;
    let cert_values_attr = attribute(
        OID_CERT_VALUES,
        certificate_values_for_signer(
            &signer.certificate,
            &material.ca_chain,
            &material.signer_ocsp,
        ),
    )?;
    let rev_values_attr = attribute(
        OID_REVOCATION_VALUES,
        revocation_values(&material.signer_ocsp, &material.ca_crls),
    )?;

    let (ci, signer_index, sd_fields, sif) = cms_single_signer_mut(token)?;
    let mut attrs = existing_unsigned_attrs(&sif)?;
    attrs.retain(|a| match attr_oid(a) {
        Ok(oid) => ![
            OID_CERT_REFS,
            OID_REVOCATION_REFS,
            OID_CERT_VALUES,
            OID_REVOCATION_VALUES,
        ]
        .contains(&oid.as_str()),
        Err(_) => true,
    });
    attrs.extend([
        cert_refs_attr,
        rev_refs_attr,
        cert_values_attr,
        rev_values_attr,
    ]);
    let der = rebuild_with_unsigned_attrs(ci, signer_index, sd_fields, sif, attrs)?;

    let after = timestamp::parse_token(&der)?;
    if after.digest_oid != info.digest_oid
        || after.message_imprint != info.message_imprint
        || after.gen_time != info.gen_time
    {
        bail!("timestamp TSTInfo changed while adding unsigned validation evidence");
    }
    let signer_after = timestamp::signer_meta(&der)
        .context("TSA SignerInfo.sid no longer resolves after adding validation evidence")?;
    if signer_after.certificate != signer.certificate
        || signer_after.digest_oid != signer.digest_oid
    {
        bail!("TSA signer certificate/digest changed while adding unsigned validation evidence");
    }

    Ok((
        der,
        TimestampEvidenceSummary {
            ca_count: material.ca_chain.len(),
            crl_count: material.ca_crls.len(),
            ocsp_count: 1,
        },
    ))
}

/// Add the long-term validation evidence required to validate an RFC 3161
/// token without network access. The TSA signature itself is untouched:
/// completeCertificateRefs / completeRevocationRefs / certificateValues /
/// revocationValues are unsigned attributes of the token's SignerInfo.
pub fn augment_timestamp_token(
    token: &[u8],
    fetch_timeout_secs: u64,
) -> Result<(Vec<u8>, TimestampEvidenceSummary)> {
    let info =
        timestamp::parse_token(token).context("parse timestamp before adding TSA evidence")?;
    let signer = timestamp::signer_meta(token).context("locate timestamp signer certificate")?;
    let gen_unix = x509::generalized_time_to_unix(&info.gen_time)?;
    let material = validation::collect_tsa(&signer.certificate, fetch_timeout_secs, gen_unix)
        .context("collect validation evidence for timestamp signer")?;
    augment_timestamp_token_with_material(token, &info, &signer, &material)
}

fn decode_oid_tlv(raw: &[u8]) -> Result<String> {
    let t = der::parse_tlv(raw)?;
    if t.tag != 0x06 {
        bail!("expected OBJECT IDENTIFIER");
    }
    der::decode_oid(t.value).context("invalid OBJECT IDENTIFIER")
}

fn attr_oid(attr_raw: &[u8]) -> Result<String> {
    let a = der::parse_tlv(attr_raw)?;
    if a.tag != 0x30 {
        bail!("attribute is not a SEQUENCE");
    }
    let f = x509::raw_children(a.value)?;
    decode_oid_tlv(*f.first().context("empty attribute")?)
}

fn algorithm_identifier_oid(raw: &[u8]) -> Result<String> {
    let ai = der::parse_tlv(raw)?;
    if ai.tag != 0x30 {
        bail!("AlgorithmIdentifier is not a SEQUENCE");
    }
    let f = x509::raw_children(ai.value)?;
    decode_oid_tlv(*f.first().context("empty AlgorithmIdentifier")?)
}

/// Normalize legacy project output to CryptoPro's CMS convention while
/// enhancing an already-created CAdES-T. This field is outside signedAttrs, so
/// changing only AlgorithmIdentifier does not invalidate the user's signature.
fn normalize_cms_signature_algorithm(sif: &mut [Vec<u8>], digest_oid: &str) -> Result<()> {
    let signature_index = sif
        .iter()
        .position(|r| r.first().copied() == Some(0x04))
        .context("SignerInfo.signature OCTET STRING missing")?;
    if signature_index == 0 {
        bail!("SignerInfo.signature has no preceding signatureAlgorithm");
    }
    let alg_index = signature_index - 1;
    let current = algorithm_identifier_oid(&sif[alg_index])?;
    let (expected, legacy) = match digest_oid {
        cades::OID_DIGEST_256 => (cades::OID_SIGN_256, cades::OID_SIGN_WITH_DIGEST_256),
        cades::OID_DIGEST_512 => (cades::OID_SIGN_512, cades::OID_SIGN_WITH_DIGEST_512),
        _ => bail!("unsupported CMS digest algorithm {digest_oid}"),
    };
    if current != expected && current != legacy {
        bail!("unsupported CMS SignerInfo.signatureAlgorithm {current}; expected {expected}");
    }
    sif[alg_index] = cms_der::algorithm_identifier(expected)?;
    Ok(())
}

fn attribute_value_bytes_for_x_timestamp(attr_raw: &[u8]) -> Result<Vec<u8>> {
    // RFC 5126 §6.3.5 NOTE 2: hash attrType and attrValues (including their
    // TLVs), but exclude the type and length of the outer Attribute SEQUENCE.
    let a = der::parse_tlv(attr_raw)?;
    if a.tag != 0x30 || a.total_len != attr_raw.len() {
        bail!("malformed Attribute");
    }
    Ok(a.value.to_vec())
}

fn cms_single_signer_mut(
    input: &[u8],
) -> Result<(Vec<Vec<u8>>, usize, Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let top = der::parse_tlv(input)?;
    if top.tag != 0x30 || top.total_len != input.len() {
        bail!("CMS is not one ContentInfo SEQUENCE");
    }
    let ci = x509::raw_children(top.value)?
        .into_iter()
        .map(|v| v.to_vec())
        .collect::<Vec<_>>();
    if ci.len() != 2 {
        bail!("unexpected ContentInfo layout");
    }
    let wrapper = der::parse_tlv(&ci[1])?;
    if wrapper.tag != 0xA0 {
        bail!("ContentInfo.content is not [0] EXPLICIT");
    }
    let w = x509::raw_children(wrapper.value)?;
    let sd_raw = *w.first().context("missing SignedData")?;
    let sd = der::parse_tlv(sd_raw)?;
    if sd.tag != 0x30 {
        bail!("SignedData is not a SEQUENCE");
    }
    let sd_fields = x509::raw_children(sd.value)?
        .into_iter()
        .map(|v| v.to_vec())
        .collect::<Vec<_>>();
    let signer_index = sd_fields
        .iter()
        .rposition(|r| r.first().copied() == Some(0x31))
        .context("SignedData signerInfos missing")?;
    let signer_set = der::parse_tlv(&sd_fields[signer_index])?;
    let signers = x509::raw_children(signer_set.value)?
        .into_iter()
        .map(|v| v.to_vec())
        .collect::<Vec<_>>();
    if signers.len() != 1 {
        bail!("CAdES-X Long Type 1 upgrade currently supports exactly one SignerInfo");
    }
    let si = der::parse_tlv(&signers[0])?;
    if si.tag != 0x30 {
        bail!("SignerInfo is not a SEQUENCE");
    }
    let sif = x509::raw_children(si.value)?
        .into_iter()
        .map(|v| v.to_vec())
        .collect::<Vec<_>>();
    Ok((ci, signer_index, sd_fields, sif))
}

fn existing_unsigned_attrs(sif: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let Some(raw) = sif.iter().find(|r| r.first().copied() == Some(0xA1)) else {
        return Ok(Vec::new());
    };
    let t = der::parse_tlv(raw)?;
    x509::raw_children(t.value).map(|v| v.into_iter().map(|x| x.to_vec()).collect())
}

fn find_attr(attrs: &[Vec<u8>], oid: &str) -> Result<Option<Vec<u8>>> {
    for a in attrs {
        if attr_oid(a)? == oid {
            return Ok(Some(a.clone()));
        }
    }
    Ok(None)
}

fn rebuild_with_unsigned_attrs(
    ci: Vec<Vec<u8>>,
    signer_index: usize,
    mut sd_fields: Vec<Vec<u8>>,
    mut sif: Vec<Vec<u8>>,
    attrs: Vec<Vec<u8>>,
) -> Result<Vec<u8>> {
    sif.retain(|r| r.first().copied() != Some(0xA1));
    let set = cms_der::set(attrs);
    sif.push(cms_der::implicit_set1_from_der_set(&set)?);
    let signer = cms_der::sequence(&sif);
    sd_fields[signer_index] = cms_der::set(vec![signer]);
    let sd = cms_der::sequence(&sd_fields);
    Ok(cms_der::sequence(&[ci[0].clone(), cms_der::explicit0(&sd)]))
}

/// Upgrade CAdES-T to CryptoPro-compatible CAdES-X Long Type 1.
///
/// The outer validation set includes evidence for the document signer, the
/// signature-timestamp TSA and the CAdES-C-timestamp TSA. CryptoPro's CAdES-A
/// verifier validates historical timestamps offline and requires these TSA
/// revocation references to be resolvable from the outer XLT1 evidence set.
///
/// Because the CAdES-C timestamp (.25) covers completeCertificateRefs (.21)
/// and completeRevocationRefs (.22), while its TSA signer is only known after
/// receiving a timestamp, enhancement is intentionally two-pass:
///
/// 1. request a provisional .25 to discover the TSA signer;
/// 2. collect that TSA's validation material and complete outer .21/.22;
/// 3. request the final .25 over the completed refs;
/// 4. embed .23/.24 plus fresh nested TSA validation evidence.
///
/// If a TSA farm rotates certificates between requests, a bounded fixed-point
/// loop rebuilds the refs until the final TSA signer stabilizes.
pub fn enhance_x_long_type_1(
    cades_t: &[u8],
    material: &validation::ValidationMaterial,
    tsa_url: &str,
    tsa_policy: Option<&str>,
    tsa_timeout_secs: u64,
    validation_fetch_timeout_secs: u64,
) -> Result<EnhanceResult> {
    let parsed = cades::parse(cades_t).context("parse input CAdES-T")?;
    let original_sig_ts = parsed.signature_timestamp_token.as_deref().context(
        "CAdES-X Long Type 1 upgrade requires an existing CAdES-T signatureTimeStampToken",
    )?;
    validation::validate_chain_links(&parsed.certificate, &material.ca_chain)?;
    validation::validate_ca_crl_order(&material.ca_chain, &material.ca_crls)?;

    timestamp::token_matches_signature(original_sig_ts, &parsed.signature)
        .context("signature timestamp does not match signature value")?;
    let sig_ts_verify = timestamp::verify_token_signature(original_sig_ts)
        .context("verify input signature timestamp CMS signature")?;
    if !sig_ts_verify.is_valid() {
        bail!(
            "input signature timestamp failed local cryptographic verification: signature={}, messageDigest={}, contentType={}, sid={}, certAtGenTime={}",
            sig_ts_verify.signature_valid,
            sig_ts_verify.message_digest_valid,
            sig_ts_verify.content_type_valid,
            sig_ts_verify.signer_id_matches_certificate,
            sig_ts_verify.certificate_valid_at_gen_time,
        );
    }
    let sig_ts_info = sig_ts_verify.info.clone();
    let sig_ts_signer =
        timestamp::signer_meta(original_sig_ts).context("locate signature timestamp TSA signer")?;
    let sig_ts_unix = x509::generalized_time_to_unix(&sig_ts_info.gen_time)?;
    let sig_ts_material = validation::collect_tsa(
        &sig_ts_signer.certificate,
        validation_fetch_timeout_secs,
        sig_ts_unix,
    )
    .context("collect validation evidence for signature timestamp TSA")?;
    let (sig_ts_token, signature_tsa_evidence) = augment_timestamp_token_with_material(
        original_sig_ts,
        &sig_ts_info,
        &sig_ts_signer,
        &sig_ts_material,
    )
    .context("embed validation evidence into signature timestamp")?;
    timestamp::token_matches_signature(&sig_ts_token, &parsed.signature)
        .context("augmented signature timestamp no longer matches signature value")?;
    let sig_ts_attr = attribute(timestamp::OID_SIGNATURE_TIMESTAMP, sig_ts_token.clone())?;

    // Base plan is deterministic: document signer CA path + OCSP responder,
    // then the signature-timestamp TSA signer/path/evidence.
    let mut base_plan = OuterEvidencePlan::new();
    base_plan.append_primary_chain(material)?;
    base_plan.append_secondary_signer(&sig_ts_signer.certificate, &sig_ts_material)?;

    // Provisional .25: its only purpose is to tell us which TSA certificate the
    // endpoint will use.  It is never embedded into the output signature.
    let provisional_cert_refs = attribute(
        OID_CERT_REFS,
        complete_certificate_refs(&base_plan.certs, &parsed.digest_oid)?,
    )?;
    let provisional_rev_refs = attribute(
        OID_REVOCATION_REFS,
        complete_revocation_refs_for_plan(&material.signer_ocsp, &base_plan, &parsed.digest_oid)?,
    )?;
    let provisional_input = build_x_input(
        &parsed.signature,
        &sig_ts_attr,
        &provisional_cert_refs,
        &provisional_rev_refs,
    )?;
    let provisional = timestamp::request_timestamp_over_data(
        tsa_url,
        &provisional_input,
        &parsed.digest_oid,
        tsa_policy,
        tsa_timeout_secs,
    )
    .context("request provisional CAdES-C timestamp")?;
    let mut planned_esc_signer = timestamp::signer_meta(&provisional.token)
        .context("locate provisional CAdES-C timestamp TSA signer")?;
    let provisional_unix = x509::generalized_time_to_unix(&provisional.info.gen_time)?;
    let mut planned_esc_material = validation::collect_tsa(
        &planned_esc_signer.certificate,
        validation_fetch_timeout_secs,
        provisional_unix,
    )
    .context("collect provisional CAdES-C TSA validation evidence")?;

    // Usually one iteration is enough.  A short fixed-point loop handles TSA
    // farms that rotate signing certificates between two consecutive requests.
    let mut final_raw = None;
    let mut final_plan = None;
    for attempt in 1..=4 {
        let mut plan = base_plan.clone();
        plan.append_secondary_signer(&planned_esc_signer.certificate, &planned_esc_material)?;

        let cert_refs_attr = attribute(
            OID_CERT_REFS,
            complete_certificate_refs(&plan.certs, &parsed.digest_oid)?,
        )?;
        let rev_refs_attr = attribute(
            OID_REVOCATION_REFS,
            complete_revocation_refs_for_plan(&material.signer_ocsp, &plan, &parsed.digest_oid)?,
        )?;
        let x_input = build_x_input(
            &parsed.signature,
            &sig_ts_attr,
            &cert_refs_attr,
            &rev_refs_attr,
        )?;
        let candidate = timestamp::request_timestamp_over_data(
            tsa_url,
            &x_input,
            &parsed.digest_oid,
            tsa_policy,
            tsa_timeout_secs,
        )
        .with_context(|| format!("request final CAdES-C timestamp attempt #{attempt}"))?;
        let expected = cades::digest_by_oid(&candidate.info.digest_oid, &x_input)?;
        if expected != candidate.info.message_imprint {
            bail!("CAdES-C timestamp token imprint mismatch on attempt #{attempt}");
        }
        let candidate_signer = timestamp::signer_meta(&candidate.token)
            .context("locate final CAdES-C timestamp TSA signer")?;

        if candidate_signer.certificate == planned_esc_signer.certificate {
            final_raw = Some(candidate);
            final_plan = Some(plan);
            break;
        }

        eprintln!(
            "WARNING: TSA signer changed during XLT1 enhancement attempt #{attempt}; rebuilding outer refs and retrying"
        );
        let candidate_unix = x509::generalized_time_to_unix(&candidate.info.gen_time)?;
        planned_esc_material = validation::collect_tsa(
            &candidate_signer.certificate,
            validation_fetch_timeout_secs,
            candidate_unix,
        )
        .context("collect validation evidence for rotated CAdES-C TSA signer")?;
        planned_esc_signer = candidate_signer;
    }

    let mut final_raw =
        final_raw.context("TSA signer did not stabilize after 4 CAdES-C timestamp attempts")?;
    let final_plan = final_plan.expect("set with final_raw");

    // CryptoPro sandwich: signatureTSP <= OCSP.thisUpdate <= CAdES-C (.25) TSP.
    // Document-signer OCSP and the CryptoPro TSA often disagree by a few seconds;
    // one-shot SignCades(XLT1) hits this most often. Refs imprint is fixed, so
    // re-request .25 until TSA genTime catches up (bounded wait).
    let mut outer_unix = x509::generalized_time_to_unix(&final_raw.info.gen_time)?;
    if outer_unix < material.signer_ocsp.this_update_unix {
        let cert_refs_attr = attribute(
            OID_CERT_REFS,
            complete_certificate_refs(&final_plan.certs, &parsed.digest_oid)?,
        )?;
        let rev_refs_attr = attribute(
            OID_REVOCATION_REFS,
            complete_revocation_refs_for_plan(
                &material.signer_ocsp,
                &final_plan,
                &parsed.digest_oid,
            )?,
        )?;
        let x_input = build_x_input(
            &parsed.signature,
            &sig_ts_attr,
            &cert_refs_attr,
            &rev_refs_attr,
        )?;
        let mut ok = false;
        for wait_attempt in 1..=10 {
            let skew_secs = (material.signer_ocsp.this_update_unix - outer_unix).max(1) as u64;
            let sleep_ms = (skew_secs * 1000).clamp(500, 3_000);
            eprintln!(
                "WARNING: CAdES-C timestamp {} < OCSP thisUpdate {} (skew {}s); waiting {sleep_ms}ms and re-requesting .25 (attempt {wait_attempt}/10)",
                final_raw.info.gen_time,
                material.signer_ocsp.this_update,
                skew_secs,
            );
            std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
            let candidate = timestamp::request_timestamp_over_data(
                tsa_url,
                &x_input,
                &parsed.digest_oid,
                tsa_policy,
                tsa_timeout_secs,
            )
            .with_context(|| {
                format!("re-request CAdES-C timestamp for OCSP sandwich attempt #{wait_attempt}")
            })?;
            let expected = cades::digest_by_oid(&candidate.info.digest_oid, &x_input)?;
            if expected != candidate.info.message_imprint {
                bail!("CAdES-C timestamp token imprint mismatch while waiting for OCSP sandwich");
            }
            let candidate_signer = timestamp::signer_meta(&candidate.token)
                .context("locate CAdES-C timestamp TSA signer during OCSP sandwich wait")?;
            if candidate_signer.certificate != planned_esc_signer.certificate {
                bail!(
                    "TSA signer changed while waiting for CAdES-C genTime >= OCSP thisUpdate; retry enhance"
                );
            }
            final_raw = candidate;
            outer_unix = x509::generalized_time_to_unix(&final_raw.info.gen_time)?;
            if outer_unix >= material.signer_ocsp.this_update_unix {
                ok = true;
                break;
            }
        }
        if !ok {
            bail!(
                "final CAdES-C timestamp {} is earlier than document-signer OCSP thisUpdate {}; CryptoPro requires innerTimestamp <= thisUpdate <= outerTimestamp",
                final_raw.info.gen_time,
                material.signer_ocsp.this_update
            );
        }
    }

    // The outer ref for the .25 TSA necessarily comes from evidence collected
    // after the provisional timestamp and before the final .25 is issued. Prefer
    // an OCSP validity interval that covers final genTime; otherwise keep the
    // warning because a strict external validator may reject the evidence.
    if planned_esc_material.signer_ocsp.this_update_unix < outer_unix {
        let covered = planned_esc_material
            .signer_ocsp
            .next_update
            .as_deref()
            .and_then(|s| x509::generalized_time_to_unix(s).ok())
            .is_some_and(|next| outer_unix <= next);
        if !covered {
            eprintln!(
                "WARNING: outer .22 OCSP for the .25 TSA has thisUpdate={} before final .25 genTime={} and no usable nextUpdate covering it; a strict external validator may reject this evidence",
                planned_esc_material.signer_ocsp.this_update,
                final_raw.info.gen_time,
            );
        }
    }

    // Fresh nested evidence is collected *after* the final timestamp.  This is
    // independent of the earlier OCSP value referenced by outer .22.
    let final_esc_signer = timestamp::signer_meta(&final_raw.token)
        .context("locate final CAdES-C timestamp TSA signer")?;
    let final_esc_material = validation::collect_tsa(
        &final_esc_signer.certificate,
        validation_fetch_timeout_secs,
        outer_unix,
    )
    .context("collect fresh validation evidence for final CAdES-C timestamp TSA")?;
    let (esc_ts_token, esc_tsa_evidence) = augment_timestamp_token_with_material(
        &final_raw.token,
        &final_raw.info,
        &final_esc_signer,
        &final_esc_material,
    )
    .context("embed fresh validation evidence into final CAdES-C timestamp")?;

    let cert_refs_attr = attribute(
        OID_CERT_REFS,
        complete_certificate_refs(&final_plan.certs, &parsed.digest_oid)?,
    )?;
    let rev_refs_attr = attribute(
        OID_REVOCATION_REFS,
        complete_revocation_refs_for_plan(&material.signer_ocsp, &final_plan, &parsed.digest_oid)?,
    )?;
    let (cert_values, rev_values) =
        values_for_plan(&parsed.certificate, &material.signer_ocsp, &final_plan);
    let cert_values_attr = attribute(OID_CERT_VALUES, cert_values)?;
    let rev_values_attr = attribute(OID_REVOCATION_VALUES, rev_values)?;
    let esc_attr = attribute(OID_ESC_TIMESTAMP, esc_ts_token.clone())?;

    let (ci, signer_index, sd_fields, mut sif) = cms_single_signer_mut(cades_t)?;
    normalize_cms_signature_algorithm(&mut sif, &parsed.digest_oid)?;
    let mut attrs = existing_unsigned_attrs(&sif)?;
    attrs.retain(|a| match attr_oid(a) {
        Ok(oid) => oid != timestamp::OID_SIGNATURE_TIMESTAMP,
        Err(_) => true,
    });
    for oid in [
        OID_CERT_REFS,
        OID_REVOCATION_REFS,
        OID_CERT_VALUES,
        OID_REVOCATION_VALUES,
        OID_ESC_TIMESTAMP,
    ] {
        if find_attr(&attrs, oid)?.is_some() {
            bail!("input already contains X-Long attribute {oid}");
        }
    }
    attrs.extend([
        sig_ts_attr,
        cert_refs_attr,
        rev_refs_attr,
        cert_values_attr,
        rev_values_attr,
        esc_attr,
    ]);
    let der = rebuild_with_unsigned_attrs(ci, signer_index, sd_fields, sif, attrs)?;

    let after_outer = cades::parse(&der).context("parse rebuilt XLT1 outer CMS")?;
    if after_outer.certificate != parsed.certificate {
        bail!("outer signer certificate changed while enhancing CAdES-T");
    }
    if after_outer.signature != parsed.signature {
        bail!("outer CMS signature value changed while enhancing CAdES-T");
    }
    if after_outer.signed_attrs_der != parsed.signed_attrs_der {
        bail!("outer CMS signedAttrs changed while enhancing CAdES-T");
    }
    let after_sig_ts = after_outer
        .signature_timestamp_token
        .as_deref()
        .context("signatureTimeStampToken disappeared after enhancement")?;
    timestamp::token_matches_signature(after_sig_ts, &parsed.signature)
        .context("enhanced signatureTimeStampToken is invalid")?;
    timestamp_validation_evidence_present(after_sig_ts)
        .context("enhanced signatureTimeStampToken lacks validation evidence")?;
    timestamp_validation_evidence_present(&esc_ts_token)
        .context("enhanced CAdES-C timestamp lacks validation evidence")?;
    if !cades::signer_identifier_matches_embedded_certificate(&der)? {
        bail!("outer SignerInfo.sid no longer resolves to the embedded signer certificate after enhancement");
    }

    Ok(EnhanceResult {
        der,
        ca_count: material.ca_chain.len(),
        crl_count: material.ca_crls.len(),
        ocsp_count: 1,
        esc_timestamp: final_raw.info,
        signature_tsa_evidence,
        esc_tsa_evidence,
    })
}

fn attribute_first_value(attr_raw: &[u8]) -> Result<Vec<u8>> {
    let a = der::parse_tlv(attr_raw)?;
    if a.tag != 0x30 {
        bail!("attribute is not a SEQUENCE");
    }
    let f = x509::raw_children(a.value)?;
    if f.len() != 2 {
        bail!("malformed Attribute");
    }
    let set = der::parse_tlv(f[1])?;
    if set.tag != 0x31 {
        bail!("Attribute.attrValues is not SET OF");
    }
    let vals = x509::raw_children(set.value)?;
    Ok((*vals.first().context("empty Attribute.attrValues")?).to_vec())
}

/// Validate only the RFC 5126 §6.3.5 CAdES-C timestamp messageImprint.
/// TSA signature/trust and PKI revocation validation remain the job of a full validator.
pub fn verify_esc_timestamp_imprint(input: &[u8]) -> Result<timestamp::TimestampTokenInfo> {
    let parsed = cades::parse(input)?;
    let (_, _, _, sif) = cms_single_signer_mut(input)?;
    let attrs = existing_unsigned_attrs(&sif)?;
    let sig_ts = find_attr(&attrs, timestamp::OID_SIGNATURE_TIMESTAMP)?
        .context("signatureTimeStampToken missing")?;
    let cert_refs = find_attr(&attrs, OID_CERT_REFS)?.context("completeCertificateRefs missing")?;
    let rev_refs =
        find_attr(&attrs, OID_REVOCATION_REFS)?.context("completeRevocationRefs missing")?;
    let esc = find_attr(&attrs, OID_ESC_TIMESTAMP)?.context("CAdES-C-time-stamp missing")?;
    let token = attribute_first_value(&esc)?;

    let mut x_input = Vec::new();
    x_input.extend_from_slice(&parsed.signature);
    x_input.extend_from_slice(&attribute_value_bytes_for_x_timestamp(&sig_ts)?);
    x_input.extend_from_slice(&attribute_value_bytes_for_x_timestamp(&cert_refs)?);
    x_input.extend_from_slice(&attribute_value_bytes_for_x_timestamp(&rev_refs)?);

    let info = timestamp::parse_token(&token)?;
    let expected = cades::digest_by_oid(&info.digest_oid, &x_input)?;
    if expected != info.message_imprint {
        bail!("CAdES-C-time-stamp messageImprint mismatch");
    }
    Ok(info)
}

#[derive(Debug, Clone)]
struct HashRef {
    oid: String,
    value: Vec<u8>,
}

#[derive(Debug, Clone)]
struct CertificateRef {
    hash: HashRef,
    issuer_der: Vec<u8>,
    serial_der: Vec<u8>,
}

#[derive(Debug, Clone)]
struct OcspRef {
    responder_id_der: Vec<u8>,
    produced_at_der: Vec<u8>,
    response_hash: Option<HashRef>,
}

#[derive(Debug, Clone)]
struct RevocationRef {
    crl_hashes: Vec<HashRef>,
    ocsp_refs: Vec<OcspRef>,
}

#[derive(Debug, Clone)]
pub struct AuditCheck {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct XLongAudit {
    pub checks: Vec<AuditCheck>,
}

impl XLongAudit {
    pub fn is_conformant(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }
}

fn check(checks: &mut Vec<AuditCheck>, name: &'static str, result: Result<String>) {
    match result {
        Ok(detail) => checks.push(AuditCheck {
            name,
            ok: true,
            detail,
        }),
        Err(e) => checks.push(AuditCheck {
            name,
            ok: false,
            detail: format!("{e:#}"),
        }),
    }
}

fn parse_other_hash(raw: &[u8]) -> Result<HashRef> {
    let t = der::parse_tlv(raw)?;
    if t.total_len != raw.len() {
        bail!("OtherHash has trailing data");
    }
    if t.tag == 0x04 {
        // OtherHash.sha1Hash choice.
        return Ok(HashRef {
            oid: "1.3.14.3.2.26".to_string(),
            value: t.value.to_vec(),
        });
    }
    if t.tag != 0x30 {
        bail!("OtherHash is neither OCTET STRING nor OtherHashAlgAndValue");
    }
    let f = x509::raw_children(t.value)?;
    if f.len() != 2 {
        bail!("OtherHashAlgAndValue must contain algorithm and hash");
    }
    let oid = algorithm_identifier_oid(f[0])?;
    let hash = der::parse_tlv(f[1])?;
    if hash.tag != 0x04 {
        bail!("OtherHash.hashValue is not OCTET STRING");
    }
    Ok(HashRef {
        oid,
        value: hash.value.to_vec(),
    })
}

fn parse_issuer_serial(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let is = der::parse_tlv(raw)?;
    if is.tag != 0x30 {
        bail!("IssuerSerial is not SEQUENCE");
    }
    let f = x509::raw_children(is.value)?;
    if f.len() < 2 {
        bail!("IssuerSerial is truncated");
    }
    let names = der::parse_tlv(f[0])?;
    if names.tag != 0x30 {
        bail!("IssuerSerial.issuer is not GeneralNames");
    }
    let mut issuer_name = None;
    for g in x509::raw_children(names.value)? {
        let gn = der::parse_tlv(g)?;
        if gn.tag == 0xA4 {
            let inner = x509::raw_children(gn.value)?;
            let name = *inner.first().context("empty directoryName")?;
            if name.first().copied() != Some(0x30) {
                bail!("directoryName does not contain Name");
            }
            issuer_name = Some(name.to_vec());
            break;
        }
    }
    let serial = der::parse_tlv(f[1])?;
    if serial.tag != 0x02 {
        bail!("IssuerSerial.serialNumber is not INTEGER");
    }
    Ok((
        issuer_name.context("IssuerSerial has no directoryName")?,
        f[1].to_vec(),
    ))
}

fn parse_certificate_refs(attr: &[u8]) -> Result<Vec<CertificateRef>> {
    let value = attribute_first_value(attr)?;
    let seq = der::parse_tlv(&value)?;
    if seq.tag != 0x30 || seq.total_len != value.len() {
        bail!("CompleteCertificateRefs is not one SEQUENCE");
    }
    let mut out = Vec::new();
    for raw in x509::raw_children(seq.value)? {
        let id = der::parse_tlv(raw)?;
        if id.tag != 0x30 {
            bail!("OtherCertID is not SEQUENCE");
        }
        let f = x509::raw_children(id.value)?;
        if f.len() < 2 {
            bail!("OtherCertID must contain issuerSerial for CAdES-C");
        }
        let hash = parse_other_hash(f[0])?;
        let (issuer_der, serial_der) = parse_issuer_serial(f[1])?;
        out.push(CertificateRef {
            hash,
            issuer_der,
            serial_der,
        });
    }
    Ok(out)
}

fn parse_certificate_values(attr: &[u8]) -> Result<Vec<Vec<u8>>> {
    let value = attribute_first_value(attr)?;
    let seq = der::parse_tlv(&value)?;
    if seq.tag != 0x30 || seq.total_len != value.len() {
        bail!("CertificateValues is not one SEQUENCE");
    }
    Ok(x509::raw_children(seq.value)?
        .into_iter()
        .map(|v| v.to_vec())
        .collect())
}

fn parse_revocation_refs(attr: &[u8]) -> Result<Vec<RevocationRef>> {
    let value = attribute_first_value(attr)?;
    let seq = der::parse_tlv(&value)?;
    if seq.tag != 0x30 || seq.total_len != value.len() {
        bail!("CompleteRevocationRefs is not one SEQUENCE");
    }
    let mut out = Vec::new();
    for raw in x509::raw_children(seq.value)? {
        let r = der::parse_tlv(raw)?;
        if r.tag != 0x30 {
            bail!("CrlOcspRef is not SEQUENCE");
        }
        let mut crl_hashes = Vec::new();
        let mut ocsp_refs = Vec::new();
        for field in x509::raw_children(r.value)? {
            let t = der::parse_tlv(field)?;
            if t.tag == 0xA0 {
                let exp = x509::raw_children(t.value)?;
                let list_raw = *exp.first().context("empty CrlOcspRef.crlids")?;
                let list = der::parse_tlv(list_raw)?;
                if list.tag != 0x30 {
                    bail!("CRLListID is not SEQUENCE");
                }
                let lf = x509::raw_children(list.value)?;
                let ids_raw = *lf.first().context("CRLListID missing crls")?;
                let ids = der::parse_tlv(ids_raw)?;
                if ids.tag != 0x30 {
                    bail!("CRLListID.crls is not SEQUENCE OF");
                }
                for vid_raw in x509::raw_children(ids.value)? {
                    let vid = der::parse_tlv(vid_raw)?;
                    if vid.tag != 0x30 {
                        bail!("CrlValidatedID is not SEQUENCE");
                    }
                    let vf = x509::raw_children(vid.value)?;
                    crl_hashes.push(parse_other_hash(
                        *vf.first().context("CrlValidatedID missing crlHash")?,
                    )?);
                }
            } else if t.tag == 0xA1 {
                let exp = x509::raw_children(t.value)?;
                let list_raw = *exp.first().context("empty CrlOcspRef.ocspids")?;
                let list = der::parse_tlv(list_raw)?;
                if list.tag != 0x30 {
                    bail!("OcspListID is not SEQUENCE");
                }
                let lf = x509::raw_children(list.value)?;
                let ids_raw = *lf.first().context("OcspListID missing ocspResponses")?;
                let ids = der::parse_tlv(ids_raw)?;
                if ids.tag != 0x30 {
                    bail!("OcspListID.ocspResponses is not SEQUENCE OF");
                }
                for id_raw in x509::raw_children(ids.value)? {
                    let id = der::parse_tlv(id_raw)?;
                    if id.tag != 0x30 {
                        bail!("OcspResponsesID is not SEQUENCE");
                    }
                    let idf = x509::raw_children(id.value)?;
                    let identifier_raw = *idf
                        .first()
                        .context("OcspResponsesID missing ocspIdentifier")?;
                    let identifier = der::parse_tlv(identifier_raw)?;
                    if identifier.tag != 0x30 {
                        bail!("OcspIdentifier is not SEQUENCE");
                    }
                    let inf = x509::raw_children(identifier.value)?;
                    if inf.len() != 2 {
                        bail!("OcspIdentifier must contain responderID and producedAt");
                    }
                    let response_hash = if let Some(h) = idf.get(1) {
                        Some(parse_other_hash(h)?)
                    } else {
                        None
                    };
                    ocsp_refs.push(OcspRef {
                        responder_id_der: inf[0].to_vec(),
                        produced_at_der: inf[1].to_vec(),
                        response_hash,
                    });
                }
            }
        }
        out.push(RevocationRef {
            crl_hashes,
            ocsp_refs,
        });
    }
    Ok(out)
}

fn parse_revocation_values(attr: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let value = attribute_first_value(attr)?;
    let seq = der::parse_tlv(&value)?;
    if seq.tag != 0x30 || seq.total_len != value.len() {
        bail!("RevocationValues is not one SEQUENCE");
    }
    let mut crls = Vec::new();
    let mut ocsps = Vec::new();
    for raw in x509::raw_children(seq.value)? {
        let t = der::parse_tlv(raw)?;
        if t.tag != 0xA0 && t.tag != 0xA1 {
            continue;
        }
        let exp = x509::raw_children(t.value)?;
        let values_raw = *exp.first().context("empty RevocationValues wrapper")?;
        let values = der::parse_tlv(values_raw)?;
        if values.tag != 0x30 {
            bail!("RevocationValues list is not SEQUENCE OF");
        }
        let dst = if t.tag == 0xA0 { &mut crls } else { &mut ocsps };
        dst.extend(
            x509::raw_children(values.value)?
                .into_iter()
                .map(|v| v.to_vec()),
        );
    }
    Ok((crls, ocsps))
}

fn cert_matches_ref(cert: &[u8], r: &CertificateRef) -> Result<bool> {
    let n = x509::names(cert)?;
    if n.issuer_der != r.issuer_der || n.serial_der != r.serial_der {
        return Ok(false);
    }
    Ok(cades::digest_by_oid(&r.hash.oid, cert)? == r.hash.value)
}

fn crl_matches_hash(crl: &[u8], h: &HashRef) -> Result<bool> {
    // ETSI EN 319 122-1: hash the entire DER encoded CRL, including signature.
    Ok(cades::digest_by_oid(&h.oid, crl)? == h.value)
}

fn verify_revocation_refs_values_for_signer(
    signer_cert: &[u8],
    cert_refs: &[CertificateRef],
    cert_values: &[Vec<u8>],
    rev_refs: &[RevocationRef],
    crls: &[Vec<u8>],
    ocsps: &[Vec<u8>],
    label: &str,
) -> Result<String> {
    let expected_refs = 1 + cert_refs.len();
    if rev_refs.len() != expected_refs {
        bail!(
            "{label} CompleteRevocationRefs has {} CrlOcspRef entries, expected {expected_refs} (signer + one per OtherCertID)",
            rev_refs.len()
        );
    }

    let mut status_certs = vec![signer_cert.to_vec()];
    for (i, r) in cert_refs.iter().enumerate() {
        let mut found = None;
        for cert in cert_values {
            if cert_matches_ref(cert, r)? {
                if found.is_some() {
                    bail!("{label} certificate ref #{i} resolves ambiguously");
                }
                found = Some(cert.clone());
            }
        }
        status_certs.push(found.with_context(|| {
            format!("{label} certificate ref #{i} has no matching certificateValue")
        })?);
    }
    if !cert_values.iter().any(|c| c.as_slice() == signer_cert) {
        bail!("{label} signer certificate is missing from certificateValues");
    }
    if status_certs.len() < 2 {
        bail!("{label} cannot validate signer OCSP without the immediate issuer certificate");
    }

    // The primary signer status is represented by OCSP in the layouts emitted
    // by this implementation and required by CryptoPro's offline validation.
    let signer_ref = &rev_refs[0];
    if !signer_ref.crl_hashes.is_empty() || signer_ref.ocsp_refs.len() != 1 {
        bail!("{label} signer CrlOcspRef must contain exactly one OCSP reference and no CRL reference");
    }
    let signer_ref_id = &signer_ref.ocsp_refs[0];
    let signer_issuer = &status_certs[1];
    let mut signer_matches = 0usize;
    for raw in ocsps {
        let Ok(e) = ocsp::parse_for_certificate(raw, signer_cert, signer_issuer) else {
            continue;
        };
        if e.responder_id_der != signer_ref_id.responder_id_der
            || e.produced_at_der != signer_ref_id.produced_at_der
        {
            continue;
        }
        if let Some(h) = &signer_ref_id.response_hash {
            if cades::digest_by_oid(&h.oid, raw)? != h.value {
                continue;
            }
        }
        signer_matches += 1;
    }
    if signer_matches != 1 {
        bail!(
            "{label} signer OCSP reference resolves to {signer_matches} embedded BasicOCSPResponse values, expected exactly 1"
        );
    }

    let mut referenced_status = 1usize;
    for i in 1..rev_refs.len() {
        let r = &rev_refs[i];
        let cert = &status_certs[i];
        let names = x509::names(cert)?;
        let self_issued = names.issuer_der == names.subject_der;

        if r.crl_hashes.is_empty() && r.ocsp_refs.is_empty() {
            if !self_issued && !x509::has_ocsp_nocheck(cert)? {
                bail!(
                    "{label} CrlOcspRef #{i} is empty for a certificate that is neither self-issued nor id-pkix-ocsp-nocheck"
                );
            }
            continue;
        }

        if !r.ocsp_refs.is_empty() {
            let issuer = cert_values
                .iter()
                .find(|candidate| {
                    x509::names(candidate)
                        .map(|n| n.subject_der == names.issuer_der)
                        .unwrap_or(false)
                })
                .with_context(|| {
                    format!("{label} cannot resolve issuer for OCSP-backed certificate ref #{i}")
                })?;
            for (j, ref_id) in r.ocsp_refs.iter().enumerate() {
                let mut matches = 0usize;
                for raw in ocsps {
                    let Ok(e) = ocsp::parse_for_certificate(raw, cert, issuer) else {
                        continue;
                    };
                    if e.responder_id_der != ref_id.responder_id_der
                        || e.produced_at_der != ref_id.produced_at_der
                    {
                        continue;
                    }
                    if let Some(h) = &ref_id.response_hash {
                        if cades::digest_by_oid(&h.oid, raw)? != h.value {
                            continue;
                        }
                    }
                    matches += 1;
                }
                if matches != 1 {
                    bail!("{label} OCSP ref #{i}.{j} resolves to {matches} embedded values, expected exactly 1");
                }
                referenced_status += 1;
            }
        }

        for (j, h) in r.crl_hashes.iter().enumerate() {
            let mut matches = 0usize;
            for crl in crls {
                if x509::crl_issuer_der(crl)? != names.issuer_der {
                    continue;
                }
                if crl_matches_hash(crl, h)? {
                    matches += 1;
                }
            }
            if matches != 1 {
                bail!("{label} CRL ref #{i}.{j} resolves to {matches} embedded CRLs, expected exactly 1");
            }
            referenced_status += 1;
        }
    }

    Ok(format!(
        "{label} refs/values resolve: {} certificate ref(s), {} revocation ref(s), {} referenced status value(s)",
        cert_refs.len(),
        rev_refs.len(),
        referenced_status,
    ))
}

fn verify_outer_tsa_ocsp_binding(
    tsa_cert: &[u8],
    label: &str,
    cert_refs: &[CertificateRef],
    cert_values: &[Vec<u8>],
    rev_refs: &[RevocationRef],
    ocsps: &[Vec<u8>],
) -> Result<String> {
    let mut ref_indices = Vec::new();
    for (i, r) in cert_refs.iter().enumerate() {
        if cert_matches_ref(tsa_cert, r)? {
            ref_indices.push(i);
        }
    }
    if ref_indices.len() != 1 {
        bail!("{label} signer certificate resolves to {} CompleteCertificateRefs entries, expected exactly 1", ref_indices.len());
    }
    if !cert_values.iter().any(|cert| cert.as_slice() == tsa_cert) {
        bail!("{label} signer certificate is missing from outer certificateValues");
    }

    // CompleteRevocationRefs starts with the outer document signer's status;
    // every OtherCertID then has the CrlOcspRef at index + 1.
    let cert_ref_index = ref_indices[0];
    let rev_ref_index = cert_ref_index + 1;
    let rev_ref = rev_refs
        .get(rev_ref_index)
        .with_context(|| format!("{label} signer has no matching outer CrlOcspRef"))?;
    if !rev_ref.crl_hashes.is_empty() {
        bail!("{label} signer outer revocation reference uses CRL; CryptoPro CAdES-A offline validation requires resolvable OCSP evidence");
    }
    if rev_ref.ocsp_refs.len() != 1 {
        bail!(
            "{label} signer outer CrlOcspRef contains {} OCSP references, expected exactly 1",
            rev_ref.ocsp_refs.len()
        );
    }

    let names = x509::names(tsa_cert)?;
    let issuer = cert_values
        .iter()
        .find(|candidate| {
            x509::names(candidate)
                .map(|n| n.subject_der == names.issuer_der)
                .unwrap_or(false)
        })
        .with_context(|| format!("cannot resolve issuer certificate for {label} signer OCSP"))?;
    let ref_id = &rev_ref.ocsp_refs[0];
    let mut matches = 0usize;
    for raw in ocsps {
        let Ok(e) = ocsp::parse_for_certificate(raw, tsa_cert, issuer) else {
            continue;
        };
        if e.responder_id_der != ref_id.responder_id_der
            || e.produced_at_der != ref_id.produced_at_der
        {
            continue;
        }
        if let Some(h) = &ref_id.response_hash {
            if cades::digest_by_oid(&h.oid, raw)? != h.value {
                continue;
            }
        }
        matches += 1;
    }
    if matches != 1 {
        bail!("{label} signer OCSP reference resolves to {matches} embedded BasicOCSPResponse values, expected exactly 1");
    }

    Ok(format!(
        "{label} signer is present in outer .21/.23 and has resolvable OCSP in matching .22/.24"
    ))
}

/// RFC 5126 long-term semantic precondition: the signature timestamp must
/// have been obtained while the signer certificate was valid. A timestamp
/// after certificate expiration has no evidentiary value for CAdES-C/XLT1.
pub fn signature_timestamp_within_signer_validity(input: &[u8]) -> Result<String> {
    let parsed = cades::parse(input)?;
    let token = parsed
        .signature_timestamp_token
        .as_deref()
        .context("signatureTimeStampToken missing")?;
    let ts = timestamp::token_matches_signature(token, &parsed.signature)?;
    let t = x509::generalized_time_to_unix(&ts.gen_time)?;
    let validity = x509::validity(&parsed.certificate)?;
    if !validity.is_valid_at(t) {
        bail!("signature timestamp {} is outside signer certificate validity {}..{}; RFC 5126 long-term evidence cannot be established", ts.gen_time, validity.not_before, validity.not_after);
    }
    Ok(format!(
        "{} within {}..{}",
        ts.gen_time, validity.not_before, validity.not_after
    ))
}

/// Audit the parts of CAdES-X Long Type 1 that can be verified locally
/// without a PKI trust engine: attribute presence, T timestamp timing,
/// certificateRefs↔certificateValues, revocationRefs↔revocationValues,
/// strict revocation-ref count/order, and the CAdES-C timestamp imprint.
fn timestamp_validation_evidence_present(token: &[u8]) -> Result<String> {
    let (_, _, _, sif) = cms_single_signer_mut(token)?;
    let attrs = existing_unsigned_attrs(&sif)?;
    for oid in [
        OID_CERT_REFS,
        OID_REVOCATION_REFS,
        OID_CERT_VALUES,
        OID_REVOCATION_VALUES,
    ] {
        if find_attr(&attrs, oid)?.is_none() {
            bail!("timestamp SignerInfo is missing validation-evidence attribute {oid}");
        }
    }

    let cert_refs = parse_certificate_refs(&find_attr(&attrs, OID_CERT_REFS)?.unwrap())?;
    let cert_values = parse_certificate_values(&find_attr(&attrs, OID_CERT_VALUES)?.unwrap())?;
    let rev_refs = parse_revocation_refs(&find_attr(&attrs, OID_REVOCATION_REFS)?.unwrap())?;
    let (crls, ocsps) =
        parse_revocation_values(&find_attr(&attrs, OID_REVOCATION_VALUES)?.unwrap())?;
    let signer = timestamp::signer_meta(token)
        .context("timestamp SignerInfo.sid has no matching embedded TSA certificate")?;

    verify_revocation_refs_values_for_signer(
        &signer.certificate,
        &cert_refs,
        &cert_values,
        &rev_refs,
        &crls,
        &ocsps,
        "timestamp TSA",
    )
}

pub fn audit_x_long_type_1(input: &[u8]) -> XLongAudit {
    let mut checks = Vec::new();
    check(
        &mut checks,
        "outer SignerIdentifier",
        (|| -> Result<String> {
            if !cades::signer_identifier_matches_embedded_certificate(input)? {
                bail!("outer SignerInfo.sid does not match the embedded signer certificate");
            }
            Ok("matches embedded signer certificate".into())
        })(),
    );
    check(
        &mut checks,
        "required attributes",
        (|| -> Result<String> {
            let p = inspect_presence(input)?;
            if !p.is_x_long_type_1() {
                bail!("one or more XLT1 attributes are missing");
            }
            Ok("all XLT1 marker attributes present".into())
        })(),
    );
    check(
        &mut checks,
        "signature timestamp vs signer certificate",
        signature_timestamp_within_signer_validity(input),
    );
    check(
        &mut checks,
        "signature timestamp CMS signature",
        (|| -> Result<String> {
            let parsed = cades::parse(input)?;
            let token = parsed
                .signature_timestamp_token
                .as_deref()
                .context("signatureTimeStampToken missing")?;
            let v = timestamp::verify_token_signature(token)?;
            if !v.is_valid() {
                bail!(
                "timestamp token verification failed: signature={}, messageDigest={}, contentType={}, sid={}, certAtGenTime={}",
                v.signature_valid,
                v.message_digest_valid,
                v.content_type_valid,
                v.signer_id_matches_certificate,
                v.certificate_valid_at_gen_time,
            );
            }
            Ok(format!(
                "valid, genTime={}, signer curve={}",
                v.info.gen_time, v.curve_oid
            ))
        })(),
    );
    check(
        &mut checks,
        "CAdES-C timestamp imprint",
        verify_esc_timestamp_imprint(input).map(|i| format!("valid, genTime={}", i.gen_time)),
    );
    check(
        &mut checks,
        "CAdES-C timestamp CMS signature",
        (|| -> Result<String> {
            let (_, _, _, sif) = cms_single_signer_mut(input)?;
            let attrs = existing_unsigned_attrs(&sif)?;
            let esc =
                find_attr(&attrs, OID_ESC_TIMESTAMP)?.context("CAdES-C-time-stamp missing")?;
            let token = attribute_first_value(&esc)?;
            let v = timestamp::verify_token_signature(&token)?;
            if !v.is_valid() {
                bail!(
                "timestamp token verification failed: signature={}, messageDigest={}, contentType={}, sid={}, certAtGenTime={}",
                v.signature_valid,
                v.message_digest_valid,
                v.content_type_valid,
                v.signer_id_matches_certificate,
                v.certificate_valid_at_gen_time,
            );
            }
            Ok(format!(
                "valid, genTime={}, signer curve={}",
                v.info.gen_time, v.curve_oid
            ))
        })(),
    );

    check(
        &mut checks,
        "signature timestamp TSA evidence",
        (|| -> Result<String> {
            let parsed = cades::parse(input)?;
            let token = parsed
                .signature_timestamp_token
                .as_deref()
                .context("signatureTimeStampToken missing")?;
            // Each RFC 3161 token remains independently self-contained. The outer
            // XLT1 evidence set additionally references TSA status material for
            // CryptoPro's offline CAdES-A historical-validation path.
            timestamp_validation_evidence_present(token)
        })(),
    );
    check(
        &mut checks,
        "CAdES-C timestamp TSA evidence",
        (|| -> Result<String> {
            let (_, _, _, sif) = cms_single_signer_mut(input)?;
            let attrs = existing_unsigned_attrs(&sif)?;
            let esc =
                find_attr(&attrs, OID_ESC_TIMESTAMP)?.context("CAdES-C-time-stamp missing")?;
            let token = attribute_first_value(&esc)?;
            timestamp_validation_evidence_present(&token)
        })(),
    );

    check(
        &mut checks,
        "outer TSA evidence for offline CAdES-A",
        (|| -> Result<String> {
            let parsed = cades::parse(input)?;
            let sig_ts = parsed
                .signature_timestamp_token
                .as_deref()
                .context("signatureTimeStampToken missing")?;
            let sig_tsa =
                timestamp::signer_meta(sig_ts).context("locate signature timestamp TSA signer")?;

            let (_, _, _, sif) = cms_single_signer_mut(input)?;
            let attrs = existing_unsigned_attrs(&sif)?;
            let esc_attr =
                find_attr(&attrs, OID_ESC_TIMESTAMP)?.context("CAdES-C-time-stamp missing")?;
            let esc_token = attribute_first_value(&esc_attr)?;
            let esc_tsa = timestamp::signer_meta(&esc_token)
                .context("locate CAdES-C timestamp TSA signer")?;

            let cert_refs_attr =
                find_attr(&attrs, OID_CERT_REFS)?.context("completeCertificateRefs missing")?;
            let cert_values_attr =
                find_attr(&attrs, OID_CERT_VALUES)?.context("certificateValues missing")?;
            let rev_refs_attr = find_attr(&attrs, OID_REVOCATION_REFS)?
                .context("completeRevocationRefs missing")?;
            let rev_values_attr =
                find_attr(&attrs, OID_REVOCATION_VALUES)?.context("revocationValues missing")?;
            let cert_refs = parse_certificate_refs(&cert_refs_attr)?;
            let cert_values = parse_certificate_values(&cert_values_attr)?;
            let rev_refs = parse_revocation_refs(&rev_refs_attr)?;
            let (_, ocsps) = parse_revocation_values(&rev_values_attr)?;
            if rev_refs.len() != 1 + cert_refs.len() {
                bail!(
                    "CompleteRevocationRefs has {} entries, expected {}",
                    rev_refs.len(),
                    1 + cert_refs.len()
                );
            }

            let sig_detail = verify_outer_tsa_ocsp_binding(
                &sig_tsa.certificate,
                "signature timestamp TSA",
                &cert_refs,
                &cert_values,
                &rev_refs,
                &ocsps,
            )?;
            let esc_detail = verify_outer_tsa_ocsp_binding(
                &esc_tsa.certificate,
                "CAdES-C timestamp TSA",
                &cert_refs,
                &cert_values,
                &rev_refs,
                &ocsps,
            )?;
            Ok(format!("{sig_detail}; {esc_detail}"))
        })(),
    );

    check(
        &mut checks,
        "certificate refs/values",
        (|| -> Result<String> {
            let (_, _, _, sif) = cms_single_signer_mut(input)?;
            let attrs = existing_unsigned_attrs(&sif)?;
            let refs_attr =
                find_attr(&attrs, OID_CERT_REFS)?.context("completeCertificateRefs missing")?;
            let values_attr =
                find_attr(&attrs, OID_CERT_VALUES)?.context("certificateValues missing")?;
            let refs = parse_certificate_refs(&refs_attr)?;
            let values = parse_certificate_values(&values_attr)?;
            if refs.is_empty() {
                bail!("CompleteCertificateRefs is empty");
            }
            for (i, r) in refs.iter().enumerate() {
                let mut matches = 0usize;
                for cert in &values {
                    if cert_matches_ref(cert, r)? {
                        matches += 1;
                    }
                }
                if matches != 1 {
                    bail!("OtherCertID #{i} matches {matches} certificateValues entries, expected exactly 1");
                }
            }
            Ok(format!(
                "{} references resolve to embedded certificate values",
                refs.len()
            ))
        })(),
    );

    check(
        &mut checks,
        "CryptoPro revocation evidence",
        (|| -> Result<String> {
            let parsed = cades::parse(input)?;
            let inner_token = parsed
                .signature_timestamp_token
                .as_deref()
                .context("signatureTimeStampToken missing")?;
            let inner_info = timestamp::token_matches_signature(inner_token, &parsed.signature)?;
            let inner_unix = x509::generalized_time_to_unix(&inner_info.gen_time)?;
            let outer_info = verify_esc_timestamp_imprint(input)?;
            let outer_unix = x509::generalized_time_to_unix(&outer_info.gen_time)?;

            let (_, _, _, sif) = cms_single_signer_mut(input)?;
            let attrs = existing_unsigned_attrs(&sif)?;
            let cert_refs_attr =
                find_attr(&attrs, OID_CERT_REFS)?.context("completeCertificateRefs missing")?;
            let cert_values_attr =
                find_attr(&attrs, OID_CERT_VALUES)?.context("certificateValues missing")?;
            let rev_refs_attr = find_attr(&attrs, OID_REVOCATION_REFS)?
                .context("completeRevocationRefs missing")?;
            let rev_values_attr =
                find_attr(&attrs, OID_REVOCATION_VALUES)?.context("revocationValues missing")?;
            let cert_refs = parse_certificate_refs(&cert_refs_attr)?;
            let cert_values = parse_certificate_values(&cert_values_attr)?;
            let refs = parse_revocation_refs(&rev_refs_attr)?;
            let (crls, ocsps) = parse_revocation_values(&rev_values_attr)?;
            let expected_refs = 1 + cert_refs.len();
            if refs.len() != expected_refs {
                bail!("CompleteRevocationRefs has {} CrlOcspRef entries, expected {} (signer + one per OtherCertID)", refs.len(), expected_refs);
            }

            // Resolve signer + CA certificates in exactly the order mandated by
            // CompleteRevocationRefs: signer first, then OtherCertID order.
            let mut status_certs = vec![parsed.certificate.clone()];
            for (i, r) in cert_refs.iter().enumerate() {
                let mut found = None;
                for cert in &cert_values {
                    if cert_matches_ref(cert, r)? {
                        if found.is_some() {
                            bail!("certificate ref #{i} resolves ambiguously");
                        }
                        found = Some(cert.clone());
                    }
                }
                status_certs.push(found.with_context(|| {
                    format!("certificate ref #{i} has no matching certificateValue")
                })?);
            }
            if status_certs.len() < 2 {
                bail!("cannot validate signer OCSP without the immediate issuer certificate");
            }

            // CryptoPro-specific XLT1 rule (confirmed by vendor): the first
            // CrlOcspRef, i.e. signer-certificate status, MUST be OCSP. A CRL is
            // not accepted for the signer even though generic RFC 5126 permits it.
            let signer_ref = &refs[0];
            if !signer_ref.crl_hashes.is_empty() {
                bail!("signer CrlOcspRef uses CRL evidence; CryptoPro XLT1 requires OCSP for the signer certificate");
            }
            if signer_ref.ocsp_refs.len() != 1 {
                bail!(
                    "signer CrlOcspRef must contain exactly one OCSP reference; got {}",
                    signer_ref.ocsp_refs.len()
                );
            }
            let signer_ref_id = &signer_ref.ocsp_refs[0];
            let issuer = &status_certs[1];
            let mut signer_matches = Vec::new();
            for raw in &ocsps {
                let Ok(e) = ocsp::parse_for_certificate(raw, &parsed.certificate, issuer) else {
                    continue;
                };
                if e.responder_id_der != signer_ref_id.responder_id_der
                    || e.produced_at_der != signer_ref_id.produced_at_der
                {
                    continue;
                }
                if let Some(h) = &signer_ref_id.response_hash {
                    if cades::digest_by_oid(&h.oid, raw)? != h.value {
                        continue;
                    }
                }
                signer_matches.push(e);
            }
            if signer_matches.len() != 1 {
                bail!("signer OCSP reference resolves to {} embedded BasicOCSPResponse values, expected exactly 1", signer_matches.len());
            }
            let signer_ocsp = &signer_matches[0];
            if signer_ocsp.next_update.is_some() {
                bail!("signer OCSP has nextUpdate={}; CryptoPro XLT1 requires nextUpdate to be absent", signer_ocsp.next_update.as_deref().unwrap_or("?"));
            }
            if signer_ocsp.this_update_unix < inner_unix
                || signer_ocsp.this_update_unix > outer_unix
            {
                bail!("signer OCSP timing violates CryptoPro rule: inner TSP {} <= OCSP thisUpdate {} <= outer TSP {}", inner_info.gen_time, signer_ocsp.this_update, outer_info.gen_time);
            }

            // Subsequent references may describe the document-signing CA path,
            // signature-TSA, CAdES-C-TSA, trust anchors and OCSP responders.
            // Validate every non-empty status reference against its paired cert.
            let mut crl_ref_count = 0usize;
            let mut extra_ocsp_ref_count = 0usize;
            for i in 1..refs.len() {
                let r = &refs[i];
                let cert = &status_certs[i];
                let names = x509::names(cert)?;
                let self_issued_root = names.issuer_der == names.subject_der;

                if r.crl_hashes.is_empty() && r.ocsp_refs.is_empty() {
                    let nocheck = x509::has_ocsp_nocheck(cert)?;
                    if !self_issued_root && !nocheck {
                        bail!("CrlOcspRef #{i} is empty for a certificate that is neither self-issued nor id-pkix-ocsp-nocheck");
                    }
                    continue;
                }

                if !r.ocsp_refs.is_empty() {
                    let issuer = cert_values.iter()
                    .find(|candidate| x509::names(candidate).map(|n| n.subject_der == names.issuer_der).unwrap_or(false))
                    .with_context(|| format!("cannot resolve issuer certificate for OCSP-backed certificate ref #{i}"))?;
                    for (j, ref_id) in r.ocsp_refs.iter().enumerate() {
                        let mut matches = 0usize;
                        for raw in &ocsps {
                            let Ok(e) = ocsp::parse_for_certificate(raw, cert, issuer) else {
                                continue;
                            };
                            if e.responder_id_der != ref_id.responder_id_der
                                || e.produced_at_der != ref_id.produced_at_der
                            {
                                continue;
                            }
                            if let Some(h) = &ref_id.response_hash {
                                if cades::digest_by_oid(&h.oid, raw)? != h.value {
                                    continue;
                                }
                            }
                            matches += 1;
                        }
                        if matches != 1 {
                            bail!("OCSP ref #{i}.{j} resolves to {matches} embedded BasicOCSPResponse values, expected exactly 1");
                        }
                        extra_ocsp_ref_count += 1;
                    }
                }

                for (j, h) in r.crl_hashes.iter().enumerate() {
                    let mut matches = 0usize;
                    for crl in &crls {
                        if x509::crl_issuer_der(crl)? != names.issuer_der {
                            continue;
                        }
                        if crl_matches_hash(crl, h)? {
                            matches += 1;
                        }
                    }
                    if matches != 1 {
                        bail!("CRL ref #{i}.{j} matches {matches} embedded CRLs by issuer+full-DER hash, expected exactly 1; oid={} hash={}", h.oid, hex::encode(&h.value));
                    }
                    crl_ref_count += 1;
                }
            }

            Ok(format!(
            "signer OCSP valid (thisUpdate={}, no nextUpdate, {}<=thisUpdate<={}); {} CRL reference(s), {} OCSP reference(s), {} embedded OCSP value(s), {} embedded CRL(s)",
            signer_ocsp.this_update, inner_info.gen_time, outer_info.gen_time, crl_ref_count, extra_ocsp_ref_count + 1, ocsps.len(), crls.len()
        ))
        })(),
    );

    XLongAudit { checks }
}

#[derive(Debug, Default)]
pub struct XLongPresence {
    pub signature_timestamp: bool,
    pub certificate_refs: bool,
    pub revocation_refs: bool,
    pub certificate_values: bool,
    pub revocation_values: bool,
    pub esc_timestamp: bool,
}

impl XLongPresence {
    pub fn is_x_long_type_1(&self) -> bool {
        self.signature_timestamp
            && self.certificate_refs
            && self.revocation_refs
            && self.certificate_values
            && self.revocation_values
            && self.esc_timestamp
    }
}

/// Return embedded `certificateValues` when present in an XLT1 signature.
pub fn extract_certificate_values(input: &[u8]) -> Result<Option<Vec<Vec<u8>>>> {
    let presence = inspect_presence(input)?;
    if !presence.certificate_values {
        return Ok(None);
    }
    let (_, _, _, sif) = cms_single_signer_mut(input)?;
    let attrs = existing_unsigned_attrs(&sif)?;
    let attr = find_attr(&attrs, OID_CERT_VALUES)?
        .context("certificateValues marker set but attribute missing")?;
    Ok(Some(parse_certificate_values(&attr)?))
}

pub fn inspect_presence(input: &[u8]) -> Result<XLongPresence> {
    let (_, _, _, sif) = cms_single_signer_mut(input)?;
    let attrs = existing_unsigned_attrs(&sif)?;
    let mut p = XLongPresence::default();
    for a in attrs {
        match attr_oid(&a)?.as_str() {
            timestamp::OID_SIGNATURE_TIMESTAMP => p.signature_timestamp = true,
            OID_CERT_REFS => p.certificate_refs = true,
            OID_REVOCATION_REFS => p.revocation_refs = true,
            OID_CERT_VALUES => p.certificate_values = true,
            OID_REVOCATION_VALUES => p.revocation_values = true,
            OID_ESC_TIMESTAMP => p.esc_timestamp = true,
            _ => {}
        }
    }
    Ok(p)
}

#[cfg(test)]
mod real_evidence_tests {
    use super::*;

    /// Run against a real XLT1/A signature (not shipped: contains personal data):
    /// JEX_XLT1_SAMPLE=path cargo test real_embedded_evidence -- --ignored
    #[test]
    #[ignore]
    fn real_embedded_evidence_signatures_verify() {
        let Ok(path) = std::env::var("JEX_XLT1_SAMPLE") else {
            return;
        };
        let raw = std::fs::read(path).unwrap();
        let (_, _, _, sif) = cms_single_signer_mut(&raw).unwrap();
        let attrs = existing_unsigned_attrs(&sif).unwrap();
        let mut pool =
            parse_certificate_values(&find_attr(&attrs, OID_CERT_VALUES).unwrap().unwrap())
                .unwrap();
        pool.push(cades::parse(&raw).unwrap().certificate);
        let (crls, ocsps) =
            parse_revocation_values(&find_attr(&attrs, OID_REVOCATION_VALUES).unwrap().unwrap())
                .unwrap();
        for (i, basic) in ocsps.iter().enumerate() {
            let embedded = ocsp::embedded_certificates(basic).unwrap();
            let produced = {
                let t = der::parse_tlv(basic).unwrap();
                let bf = x509::raw_children(t.value).unwrap();
                let rd = der::parse_tlv(bf[0]).unwrap();
                let rf = x509::raw_children(rd.value).unwrap();
                let pos = if rf[0][0] == 0xA0 { 2 } else { 1 };
                let g = der::parse_tlv(rf[pos]).unwrap();
                String::from_utf8(g.value.to_vec()).unwrap()
            };
            let ok = pool.iter().any(|issuer| {
                ocsp::verify_response_signature(basic, &embedded, issuer, &produced).is_ok()
            });
            eprintln!("OCSP #{i}: embedded certs={} authentic={ok}", embedded.len());
            assert!(ok, "OCSP #{i} not authenticated");
        }
        for (i, crl) in crls.iter().enumerate() {
            let ok = pool
                .iter()
                .any(|c| x509::verify_signed_structure(crl, c).unwrap_or(false));
            eprintln!("CRL #{i}: authentic={ok}");
            assert!(ok, "CRL #{i} not authenticated");
        }
    }
}
