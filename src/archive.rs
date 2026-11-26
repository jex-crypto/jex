// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use crate::{cades, cms_der, der, timestamp, x509, xlong};
use anyhow::{bail, Context, Result};

/// ETSI EN 319 122-1 archive-time-stamp-v3.
pub const OID_ARCHIVE_TIMESTAMP_V3: &str = "0.4.0.1733.2.4";
/// ETSI EN 319 122-1 ats-hash-index-v3, carried inside the archive timestamp token.
pub const OID_ATS_HASH_INDEX_V3: &str = "0.4.0.19122.1.5";

#[derive(Debug, Clone)]
pub struct AtsHashIndexSummary {
    pub certificates: usize,
    pub revocations: usize,
    pub unsigned_attribute_values: usize,
}

#[derive(Debug)]
pub struct ArchiveResult {
    pub der: Vec<u8>,
    /// Number of archive-time-stamp-v3 attributes present before this operation.
    pub previous_archive_count: usize,
    pub timestamp: timestamp::TimestampTokenInfo,
    pub tsa_evidence: xlong::TimestampEvidenceSummary,
    pub hash_index: AtsHashIndexSummary,
}

#[derive(Debug, Clone)]
pub struct ArchiveAuditCheck {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct ArchiveAudit {
    pub checks: Vec<ArchiveAuditCheck>,
}

impl ArchiveAudit {
    pub fn is_conformant(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }
}

fn check(checks: &mut Vec<ArchiveAuditCheck>, name: &'static str, result: Result<String>) {
    match result {
        Ok(detail) => checks.push(ArchiveAuditCheck {
            name,
            ok: true,
            detail,
        }),
        Err(e) => checks.push(ArchiveAuditCheck {
            name,
            ok: false,
            detail: format!("{e:#}"),
        }),
    }
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
    let fields = x509::raw_children(a.value)?;
    decode_oid_tlv(*fields.first().context("empty attribute")?)
}

fn attribute(oid: &str, value: Vec<u8>) -> Result<Vec<u8>> {
    Ok(cms_der::sequence(&[
        cms_der::oid(oid)?,
        cms_der::set(vec![value]),
    ]))
}

fn attribute_first_value(attr_raw: &[u8]) -> Result<Vec<u8>> {
    let a = der::parse_tlv(attr_raw)?;
    if a.tag != 0x30 {
        bail!("attribute is not a SEQUENCE");
    }
    let fields = x509::raw_children(a.value)?;
    if fields.len() != 2 {
        bail!("malformed Attribute");
    }
    let values = der::parse_tlv(fields[1])?;
    if values.tag != 0x31 {
        bail!("Attribute.attrValues is not SET OF");
    }
    let children = x509::raw_children(values.value)?;
    if children.len() != 1 {
        bail!(
            "attribute must contain exactly one AttributeValue; got {}",
            children.len()
        );
    }
    Ok(children[0].to_vec())
}

/// Return ContentInfo fields, signerInfos position inside SignedData,
/// SignedData fields and the only SignerInfo fields.
fn cms_single_signer_parts(
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
    let wrapped = x509::raw_children(wrapper.value)?;
    let sd_raw = *wrapped.first().context("missing SignedData")?;
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
    let signers = x509::raw_children(signer_set.value)?;
    if signers.len() != 1 {
        bail!("CAdES-A upgrade currently supports exactly one SignerInfo");
    }
    let si = der::parse_tlv(signers[0])?;
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

fn add_unsigned_attribute_to_single_signer(input: &[u8], attr: Vec<u8>) -> Result<Vec<u8>> {
    let (ci, signer_index, sd_fields, sif) = cms_single_signer_parts(input)?;
    let mut attrs = existing_unsigned_attrs(&sif)?;
    attrs.push(attr);
    rebuild_with_unsigned_attrs(ci, signer_index, sd_fields, sif, attrs)
}

fn root_certificate_choices(sd_fields: &[Vec<u8>], signer_index: usize) -> Result<Vec<Vec<u8>>> {
    for raw in sd_fields.iter().take(signer_index).skip(3) {
        if raw.first().copied() != Some(0xA0) {
            continue;
        }
        let set = der::parse_tlv(raw)?;
        return Ok(x509::raw_children(set.value)?
            .into_iter()
            .map(|v| v.to_vec())
            .collect());
    }
    Ok(Vec::new())
}

fn root_revocation_choices(sd_fields: &[Vec<u8>], signer_index: usize) -> Result<Vec<Vec<u8>>> {
    for raw in sd_fields.iter().take(signer_index).skip(3) {
        if raw.first().copied() != Some(0xA1) {
            continue;
        }
        let set = der::parse_tlv(raw)?;
        return Ok(x509::raw_children(set.value)?
            .into_iter()
            .map(|v| v.to_vec())
            .collect());
    }
    Ok(Vec::new())
}

fn unsigned_attribute_value_hashes(attrs: &[Vec<u8>], digest_oid: &str) -> Result<Vec<Vec<u8>>> {
    let mut hashes = Vec::new();
    for attr in attrs {
        let a = der::parse_tlv(attr)?;
        if a.tag != 0x30 || a.total_len != attr.len() {
            bail!("malformed unsigned Attribute");
        }
        let fields = x509::raw_children(a.value)?;
        if fields.len() != 2 {
            bail!("malformed unsigned Attribute fields");
        }
        let attr_type = fields[0];
        let values = der::parse_tlv(fields[1])?;
        if values.tag != 0x31 {
            bail!("unsigned Attribute.attrValues is not SET OF");
        }
        for value in x509::raw_children(values.value)? {
            let mut indexed = Vec::with_capacity(attr_type.len() + value.len());
            indexed.extend_from_slice(attr_type);
            indexed.extend_from_slice(value);
            hashes.push(cades::digest_by_oid(digest_oid, &indexed)?);
        }
    }
    Ok(hashes)
}

/// Build ATSHashIndexV3 for an explicit snapshot of SignerInfo.unsignedAttrs.
///
/// This is required for archive renewal: when validating ATS #N in a signature
/// that already contains ATS #N+1, the later archive attribute must not be
/// included in the older ATS hash index. The encoded bytes of every attribute
/// that *was* present are kept verbatim.
fn build_ats_hash_index_v3_for_attrs(
    sd_fields: &[Vec<u8>],
    signer_index: usize,
    attrs: &[Vec<u8>],
    digest_oid: &str,
) -> Result<(Vec<u8>, AtsHashIndexSummary)> {
    let certificates = root_certificate_choices(sd_fields, signer_index)?;
    let revocations = root_revocation_choices(sd_fields, signer_index)?;

    let cert_hashes = certificates
        .iter()
        .map(|raw| cades::digest_by_oid(digest_oid, raw).map(|h| cms_der::octet_string(&h)))
        .collect::<Result<Vec<_>>>()?;
    let rev_hashes = revocations
        .iter()
        .map(|raw| cades::digest_by_oid(digest_oid, raw).map(|h| cms_der::octet_string(&h)))
        .collect::<Result<Vec<_>>>()?;
    let unsigned_hashes = unsigned_attribute_value_hashes(attrs, digest_oid)?;
    let unsigned_hash_values = unsigned_hashes
        .iter()
        .map(|h| cms_der::octet_string(h))
        .collect::<Vec<_>>();

    let value = cms_der::sequence(&[
        cms_der::algorithm_identifier(digest_oid)?,
        cms_der::sequence(&cert_hashes),
        cms_der::sequence(&rev_hashes),
        cms_der::sequence(&unsigned_hash_values),
    ]);

    Ok((
        value,
        AtsHashIndexSummary {
            certificates: certificates.len(),
            revocations: revocations.len(),
            unsigned_attribute_values: unsigned_hashes.len(),
        },
    ))
}

fn encap_content_type_tlv(sd_fields: &[Vec<u8>]) -> Result<Vec<u8>> {
    let encap_raw = sd_fields
        .get(2)
        .context("SignedData.encapContentInfo missing")?;
    let encap = der::parse_tlv(encap_raw)?;
    if encap.tag != 0x30 {
        bail!("SignedData.encapContentInfo is not SEQUENCE");
    }
    let fields = x509::raw_children(encap.value)?;
    let oid = *fields
        .first()
        .context("encapContentInfo.eContentType missing")?;
    if der::parse_tlv(oid)?.tag != 0x06 {
        bail!("encapContentInfo.eContentType is not OBJECT IDENTIFIER");
    }
    Ok(oid.to_vec())
}

fn signer_core_fields(sif: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let signature_index = sif
        .iter()
        .position(|r| r.first().copied() == Some(0x04))
        .context("SignerInfo.signature OCTET STRING missing")?;
    if signature_index < 4 {
        bail!("SignerInfo is truncated before signature");
    }
    // ETSI EN 319 122-1 5.5.3: version, sid, digestAlgorithm,
    // signedAttrs, signatureAlgorithm, signature, in encoded form.
    Ok(sif[..=signature_index].to_vec())
}

/// Detached signed data for CAdES-A: full bytes, or digest under SignerInfo.digestAlgorithm.
///
/// ATSv3 messageImprint includes `H(content)` (not the content itself). When that hash
/// algorithm equals the signature digest, `H(content)` is exactly `messageDigest`, so a
/// precomputed hash is enough — no need to ship the original file.
#[derive(Debug, Clone, Copy)]
pub enum ExternalData<'a> {
    Content(&'a [u8]),
    /// Digest with signature `digestAlgorithm` (must equal `messageDigest`).
    Digest(&'a [u8]),
}

impl<'a> ExternalData<'a> {
    pub fn from_parts(
        content: Option<&'a [u8]>,
        digest: Option<&'a [u8]>,
    ) -> Result<Option<Self>> {
        match (content, digest) {
            (Some(_), Some(_)) => {
                bail!("pass either content or content-hash, not both")
            }
            (Some(c), None) => Ok(Some(Self::Content(c))),
            (None, Some(h)) => Ok(Some(Self::Digest(h))),
            (None, None) => Ok(None),
        }
    }
}

fn validate_supplied_content(parsed: &cades::ParsedCades, content: &[u8]) -> Result<()> {
    let actual = cades::digest_by_oid(&parsed.digest_oid, content)?;
    if actual != parsed.message_digest {
        bail!("content does not match the message-digest signed attribute");
    }
    Ok(())
}

fn validate_supplied_digest(parsed: &cades::ParsedCades, digest: &[u8]) -> Result<()> {
    if digest != parsed.message_digest.as_slice() {
        bail!("content-hash does not match the message-digest signed attribute");
    }
    Ok(())
}

/// Resolve `H(content)` for ATSv3 imprint step 2 (ETSI EN 319 122-1 5.5.2/5.5.3).
fn resolve_content_digest(
    parsed: &cades::ParsedCades,
    external: Option<ExternalData<'_>>,
    imprint_digest_oid: &str,
) -> Result<Vec<u8>> {
    if !parsed.detached {
        let content = parsed
            .embedded_content
            .as_deref()
            .context("attached CMS says content is present but it could not be extracted")?;
        validate_supplied_content(parsed, content)?;
        return cades::digest_by_oid(imprint_digest_oid, content);
    }
    match external {
        Some(ExternalData::Content(content)) => {
            validate_supplied_content(parsed, content)?;
            cades::digest_by_oid(imprint_digest_oid, content)
        }
        Some(ExternalData::Digest(digest)) => {
            validate_supplied_digest(parsed, digest)?;
            if imprint_digest_oid != parsed.digest_oid {
                bail!(
                    "content-hash cannot be used when archive imprint digest OID ({imprint_digest_oid}) \
                     differs from signature digest OID ({}); pass full content",
                    parsed.digest_oid
                );
            }
            Ok(digest.to_vec())
        }
        None => bail!(
            "detached CAdES-A requires the original content (--content FILE) \
             or its digest (--content-hash HEX)"
        ),
    }
}

fn archive_imprint_input(
    sd_fields: &[Vec<u8>],
    sif: &[Vec<u8>],
    content_digest: &[u8],
    ats_hash_index_v3: &[u8],
) -> Result<Vec<u8>> {
    let mut input = Vec::new();
    // ETSI EN 319 122-1 5.5.3, steps 1..4.
    input.extend_from_slice(&encap_content_type_tlv(sd_fields)?);
    input.extend_from_slice(content_digest);
    for field in signer_core_fields(sif)? {
        input.extend_from_slice(&field);
    }
    input.extend_from_slice(ats_hash_index_v3);
    Ok(input)
}

fn timestamp_hash_index_value(token: &[u8]) -> Result<Vec<u8>> {
    let (_, _, _, sif) = cms_single_signer_parts(token)?;
    let attrs = existing_unsigned_attrs(&sif)?;
    let mut found = Vec::new();
    for attr in attrs {
        if attr_oid(&attr)? == OID_ATS_HASH_INDEX_V3 {
            found.push(attribute_first_value(&attr)?);
        }
    }
    if found.len() != 1 {
        bail!(
            "archive TimeStampToken must contain exactly one ats-hash-index-v3 attribute; got {}",
            found.len()
        );
    }
    Ok(found.remove(0))
}

fn timestamp_has_xlt_evidence(token: &[u8]) -> Result<String> {
    let (_, _, _, sif) = cms_single_signer_parts(token)?;
    let attrs = existing_unsigned_attrs(&sif)?;
    let mut cert_refs = false;
    let mut rev_refs = false;
    let mut cert_values = false;
    let mut rev_values = false;
    for attr in attrs {
        match attr_oid(&attr)?.as_str() {
            xlong::OID_CERT_REFS => cert_refs = true,
            xlong::OID_REVOCATION_REFS => rev_refs = true,
            xlong::OID_CERT_VALUES => cert_values = true,
            xlong::OID_REVOCATION_VALUES => rev_values = true,
            _ => {}
        }
    }
    if !(cert_refs && rev_refs && cert_values && rev_values) {
        bail!("archive TimeStampToken lacks one or more TSA validation evidence attributes (.21/.22/.23/.24)");
    }
    Ok("complete TSA certificate/revocation refs and values are embedded".into())
}

fn outer_archive_attributes(input: &[u8]) -> Result<Vec<Vec<u8>>> {
    let (_, _, _, sif) = cms_single_signer_parts(input)?;
    let attrs = existing_unsigned_attrs(&sif)?;
    let mut out = Vec::new();
    for attr in attrs {
        if attr_oid(&attr)? == OID_ARCHIVE_TIMESTAMP_V3 {
            out.push(attr);
        }
    }
    Ok(out)
}

/// Convert a detached CMS/CAdES object to attached form by embedding the
/// original signed content into `SignedData.encapContentInfo.eContent`.
///
/// SignerInfo, signed attributes, signature bytes and all unsigned attributes
/// remain byte-for-byte unchanged. For CAdES-A, the existing ATSv3 chain is
/// re-audited after embedding the content before the result is returned.
pub fn attach_original_content(input: &[u8], content: &[u8]) -> Result<Vec<u8>> {
    let parsed = cades::parse(input)?;
    if !parsed.detached {
        bail!("input signature is already attached");
    }
    validate_supplied_content(&parsed, content)?;

    let (ci, _signer_index, mut sd_fields, sif_before) = cms_single_signer_parts(input)?;
    let encap_raw = sd_fields
        .get(2)
        .context("SignedData.encapContentInfo missing")?;
    let encap = der::parse_tlv(encap_raw)?;
    if encap.tag != 0x30 {
        bail!("SignedData.encapContentInfo is not SEQUENCE");
    }
    let encap_fields = x509::raw_children(encap.value)?;
    if encap_fields.len() != 1 {
        bail!("detached EncapsulatedContentInfo unexpectedly already contains eContent");
    }
    if der::parse_tlv(encap_fields[0])?.tag != 0x06 {
        bail!("encapContentInfo.eContentType is not OBJECT IDENTIFIER");
    }

    let econtent = cms_der::explicit0(&cms_der::octet_string(content));
    sd_fields[2] = cms_der::sequence(&[encap_fields[0].to_vec(), econtent]);
    let sd = cms_der::sequence(&sd_fields);
    let out = cms_der::sequence(&[ci[0].clone(), cms_der::explicit0(&sd)]);

    let after = cades::parse(&out)?;
    if after.detached {
        bail!("failed to embed eContent");
    }
    if after.embedded_content.as_deref() != Some(content) {
        bail!("embedded content differs from supplied content");
    }
    if after.signature != parsed.signature
        || after.signed_attrs_der != parsed.signed_attrs_der
        || after.certificate != parsed.certificate
    {
        bail!("SignerInfo signed material changed while attaching content");
    }

    let (_, _, _, sif_after) = cms_single_signer_parts(&out)?;
    if sif_after != sif_before {
        bail!("SignerInfo encoding changed while attaching content");
    }

    if archive_timestamp_v3_count(input)? > 0 {
        let audit = audit_cades_a(&out, None);
        if !audit.is_conformant() {
            let details = audit
                .checks
                .iter()
                .filter(|c| !c.ok)
                .map(|c| format!("{}: {}", c.name, c.detail))
                .collect::<Vec<_>>()
                .join("; ");
            bail!("CAdES-A audit failed after attaching content: {details}");
        }
    }

    Ok(out)
}

/// Convert an attached CMS/CAdES object to detached form by removing
/// `SignedData.encapContentInfo.eContent`.
///
/// Returns `(detached_cms, extracted_content)`. SignerInfo, signed attributes,
/// signature bytes and all unsigned attributes remain byte-for-byte unchanged.
/// For CAdES-A, the existing ATSv3 chain is re-audited against the extracted
/// content before the result is returned.
pub fn detach_original_content(input: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let parsed = cades::parse(input)?;
    if parsed.detached {
        bail!("input signature is already detached");
    }
    let content = parsed
        .embedded_content
        .clone()
        .context("attached CMS says content is present but it could not be extracted")?;
    validate_supplied_content(&parsed, &content)?;

    let (ci, _signer_index, mut sd_fields, sif_before) = cms_single_signer_parts(input)?;
    let encap_raw = sd_fields
        .get(2)
        .context("SignedData.encapContentInfo missing")?;
    let encap = der::parse_tlv(encap_raw)?;
    if encap.tag != 0x30 {
        bail!("SignedData.encapContentInfo is not SEQUENCE");
    }
    let encap_fields = x509::raw_children(encap.value)?;
    if encap_fields.len() != 2 {
        bail!("attached EncapsulatedContentInfo must contain eContentType and eContent");
    }
    if der::parse_tlv(encap_fields[0])?.tag != 0x06 {
        bail!("encapContentInfo.eContentType is not OBJECT IDENTIFIER");
    }

    sd_fields[2] = cms_der::sequence(&[encap_fields[0].to_vec()]);
    let sd = cms_der::sequence(&sd_fields);
    let out = cms_der::sequence(&[ci[0].clone(), cms_der::explicit0(&sd)]);

    let after = cades::parse(&out)?;
    if !after.detached {
        bail!("failed to remove eContent");
    }
    if after.embedded_content.is_some() {
        bail!("detached CMS still reports embedded content");
    }
    if after.signature != parsed.signature
        || after.signed_attrs_der != parsed.signed_attrs_der
        || after.certificate != parsed.certificate
        || after.message_digest != parsed.message_digest
    {
        bail!("SignerInfo signed material changed while detaching content");
    }

    let (_, _, _, sif_after) = cms_single_signer_parts(&out)?;
    if sif_after != sif_before {
        bail!("SignerInfo encoding changed while detaching content");
    }

    if archive_timestamp_v3_count(input)? > 0 {
        let audit = audit_cades_a(&out, Some(ExternalData::Content(&content)));
        if !audit.is_conformant() {
            let details = audit
                .checks
                .iter()
                .filter(|c| !c.ok)
                .map(|c| format!("{}: {}", c.name, c.detail))
                .collect::<Vec<_>>()
                .join("; ");
            bail!("CAdES-A audit failed after detaching content: {details}");
        }
    }

    Ok((out, content))
}

pub fn archive_timestamp_v3_count(input: &[u8]) -> Result<usize> {
    Ok(outer_archive_attributes(input)?.len())
}

pub fn archive_timestamp_v3_infos(input: &[u8]) -> Result<Vec<timestamp::TimestampTokenInfo>> {
    let mut infos = Vec::new();
    for attr in outer_archive_attributes(input)? {
        infos.push(timestamp::parse_token(&attribute_first_value(&attr)?)?);
    }
    infos.sort_by(|a, b| a.gen_time.cmp(&b.gen_time));
    Ok(infos)
}

/// Add one ETSI archive-time-stamp-v3 to a CryptoPro-compatible CAdES signature.
///
/// Input may be a plain XLT1 (initial CAdES-A creation) or an already archived
/// CAdES-A. In the latter case this performs archive renewal: the new
/// ATSHashIndexV3 covers every unsigned AttributeValue that was present before
/// the operation, including all previous archive-time-stamp-v3 values.
///
/// No private signing key is used. For detached signatures either the original
/// content or its digest (`ExternalData::Digest` = `messageDigest`) is required
/// because ATSv3 includes `H(content)`.
pub fn add_archive_timestamp_v3(
    input: &[u8],
    external: Option<ExternalData<'_>>,
    tsa_url: &str,
    tsa_policy: Option<&str>,
    tsa_timeout_secs: u64,
    validation_fetch_timeout_secs: u64,
) -> Result<ArchiveResult> {
    let xlt_presence = xlong::inspect_presence(input)?;
    if !xlt_presence.is_x_long_type_1() {
        bail!("CAdES-A archive timestamp requires CAdES-X Long Type 1 input");
    }
    let xlt_audit = xlong::audit_x_long_type_1(input);
    if !xlt_audit.is_conformant() {
        bail!("input CAdES-XLT1 failed local semantic audit");
    }

    let previous_archive_count = archive_timestamp_v3_count(input)?;
    if previous_archive_count > 0 {
        let previous_audit = audit_cades_a(input, external);
        if !previous_audit.is_conformant() {
            let details = previous_audit
                .checks
                .iter()
                .filter(|c| !c.ok)
                .map(|c| format!("{}: {}", c.name, c.detail))
                .collect::<Vec<_>>()
                .join("; ");
            bail!("existing CAdES-A failed local ATSv3 audit; refusing renewal: {details}");
        }
    }

    let parsed = cades::parse(input)?;
    let content_digest = resolve_content_digest(&parsed, external, &parsed.digest_oid)?;

    let (ci, signer_index, sd_fields, sif) = cms_single_signer_parts(input)?;
    let attrs_before = existing_unsigned_attrs(&sif)?;
    // At renewal time *all* currently present unsigned AttributeValue instances
    // are covered, including each previous archive-time-stamp-v3.
    let (ats_hash_index, hash_index) = build_ats_hash_index_v3_for_attrs(
        &sd_fields,
        signer_index,
        &attrs_before,
        &parsed.digest_oid,
    )?;
    let imprint_input =
        archive_imprint_input(&sd_fields, &sif, &content_digest, &ats_hash_index)?;

    let raw_ts = timestamp::request_timestamp_over_data(
        tsa_url,
        &imprint_input,
        &parsed.digest_oid,
        tsa_policy,
        tsa_timeout_secs,
    )?;

    if previous_archive_count > 0 {
        let previous = archive_timestamp_v3_infos(input)?;
        let latest = previous
            .last()
            .context("archive timestamp list unexpectedly empty")?;
        let latest_unix = x509::generalized_time_to_unix(&latest.gen_time)?;
        let new_unix = x509::generalized_time_to_unix(&raw_ts.info.gen_time)?;
        if new_unix <= latest_unix {
            bail!(
                "new archive timestamp {} is not later than previous archive timestamp {}; retry after TSA time advances",
                raw_ts.info.gen_time,
                latest.gen_time,
            );
        }
    }

    let hash_index_attr = attribute(OID_ATS_HASH_INDEX_V3, ats_hash_index.clone())?;
    let token_with_index = add_unsigned_attribute_to_single_signer(&raw_ts.token, hash_index_attr)
        .context("add ats-hash-index-v3 to archive TimeStampToken")?;
    let (archive_token, tsa_evidence) =
        xlong::augment_timestamp_token(&token_with_index, validation_fetch_timeout_secs)
            .context("embed validation evidence into archive TimeStampToken")?;

    let embedded_index = timestamp_hash_index_value(&archive_token)?;
    if embedded_index != ats_hash_index {
        bail!("ats-hash-index-v3 changed while augmenting archive TimeStampToken");
    }
    timestamp_has_xlt_evidence(&archive_token)?;

    let archive_attr = attribute(OID_ARCHIVE_TIMESTAMP_V3, archive_token)?;
    let mut attrs_after = attrs_before;
    attrs_after.push(archive_attr);
    let der = rebuild_with_unsigned_attrs(ci, signer_index, sd_fields, sif, attrs_after)?;

    let after = cades::parse(&der)?;
    if after.signature != parsed.signature
        || after.signed_attrs_der != parsed.signed_attrs_der
        || after.certificate != parsed.certificate
    {
        bail!("document SignerInfo signed material changed while adding archive timestamp");
    }

    let audit = audit_cades_a(&der, external);
    if !audit.is_conformant() {
        let details = audit
            .checks
            .iter()
            .filter(|c| !c.ok)
            .map(|c| format!("{}: {}", c.name, c.detail))
            .collect::<Vec<_>>()
            .join("; ");
        bail!("generated CAdES-A failed local ATSv3 audit: {details}");
    }

    Ok(ArchiveResult {
        der,
        previous_archive_count,
        timestamp: raw_ts.info,
        tsa_evidence,
        hash_index,
    })
}

#[derive(Debug, Clone)]
struct ArchiveRecord {
    attr: Vec<u8>,
    token: Vec<u8>,
    info: timestamp::TimestampTokenInfo,
}

fn archive_records(input: &[u8]) -> Result<Vec<ArchiveRecord>> {
    let mut records = Vec::new();
    for attr in outer_archive_attributes(input)? {
        let token = attribute_first_value(&attr)?;
        let info = timestamp::parse_token(&token)?;
        records.push(ArchiveRecord { attr, token, info });
    }
    records.sort_by(|a, b| a.info.gen_time.cmp(&b.info.gen_time));
    Ok(records)
}

fn verify_archive_timestamp_token_signatures(input: &[u8]) -> Result<String> {
    let records = archive_records(input)?;
    if records.is_empty() {
        bail!("archive-time-stamp-v3 missing");
    }
    for (i, record) in records.iter().enumerate() {
        let v = timestamp::verify_token_signature(&record.token)
            .with_context(|| format!("verify ATS #{} RFC 3161 CMS signature", i + 1))?;
        if !v.is_valid() {
            bail!(
                "ATS #{} timestamp token verification failed: signature={}, messageDigest={}, contentType={}, sid={}, certAtGenTime={}",
                i + 1,
                v.signature_valid,
                v.message_digest_valid,
                v.content_type_valid,
                v.signer_id_matches_certificate,
                v.certificate_valid_at_gen_time,
            );
        }
    }
    Ok(format!(
        "{} RFC 3161 archive timestamp token signature(s) valid",
        records.len()
    ))
}

fn verify_archive_timestamp_v3_chain(
    input: &[u8],
    external: Option<ExternalData<'_>>,
) -> Result<String> {
    let parsed = cades::parse(input)?;

    let records = archive_records(input)?;
    if records.is_empty() {
        bail!("archive-time-stamp-v3 missing");
    }

    let (_, signer_index, sd_fields, sif) = cms_single_signer_parts(input)?;
    let all_attrs = existing_unsigned_attrs(&sif)?;
    let non_archive_attrs = all_attrs
        .iter()
        .filter(|a| {
            attr_oid(a)
                .map(|oid| oid != OID_ARCHIVE_TIMESTAMP_V3)
                .unwrap_or(true)
        })
        .cloned()
        .collect::<Vec<_>>();

    // We require strictly increasing TSA times. Besides being natural for a
    // renewal chain, this gives an unambiguous historical snapshot for each
    // ATS even though SignerInfo.unsignedAttrs is a SET OF and has no semantic
    // insertion order.
    for pair in records.windows(2) {
        let a = x509::generalized_time_to_unix(&pair[0].info.gen_time)?;
        let b = x509::generalized_time_to_unix(&pair[1].info.gen_time)?;
        if b <= a {
            bail!(
                "archive timestamp chronology is not strictly increasing: {} then {}",
                pair[0].info.gen_time,
                pair[1].info.gen_time,
            );
        }
    }

    for (i, record) in records.iter().enumerate() {
        let actual_index = timestamp_hash_index_value(&record.token)?;

        // Reconstruct the unsignedAttrs snapshot from the moment ATS #i was
        // requested: every non-archive attribute plus all earlier ATSv3 values,
        // but not this ATS nor any future ATS. Sort exactly as DER SET OF would
        // have sorted the attributes at that point.
        let mut snapshot = non_archive_attrs.clone();
        snapshot.extend(records[..i].iter().map(|r| r.attr.clone()));
        snapshot.sort();

        let (expected_index, _) = build_ats_hash_index_v3_for_attrs(
            &sd_fields,
            signer_index,
            &snapshot,
            &record.info.digest_oid,
        )?;
        if actual_index != expected_index {
            bail!(
                "ATS #{} ats-hash-index-v3 does not match the historical CAdES state",
                i + 1
            );
        }

        let content_digest =
            resolve_content_digest(&parsed, external, &record.info.digest_oid)?;
        let imprint_input =
            archive_imprint_input(&sd_fields, &sif, &content_digest, &actual_index)?;
        let expected_imprint = cades::digest_by_oid(&record.info.digest_oid, &imprint_input)?;
        if expected_imprint != record.info.message_imprint {
            bail!(
                "ATS #{} archive-time-stamp-v3 messageImprint mismatch",
                i + 1
            );
        }

        timestamp_has_xlt_evidence(&record.token)
            .with_context(|| format!("ATS #{} TSA evidence", i + 1))?;
    }

    Ok(format!(
        "{} archive-time-stamp-v3 value(s) form a valid renewal chain; latest genTime={}",
        records.len(),
        records.last().unwrap().info.gen_time,
    ))
}

pub fn audit_cades_a(input: &[u8], external: Option<ExternalData<'_>>) -> ArchiveAudit {
    let mut checks = Vec::new();
    check(
        &mut checks,
        "XLT1 base",
        (|| -> Result<String> {
            let p = xlong::inspect_presence(input)?;
            if !p.is_x_long_type_1() {
                bail!("XLT1 marker attributes are incomplete");
            }
            let audit = xlong::audit_x_long_type_1(input);
            if !audit.is_conformant() {
                bail!("underlying XLT1 semantic audit failed");
            }
            Ok("underlying CAdES-XLT1 is conformant".into())
        })(),
    );
    check(
        &mut checks,
        "archive timestamp count",
        (|| -> Result<String> {
            let n = archive_timestamp_v3_count(input)?;
            if n == 0 {
                bail!("archive-time-stamp-v3 missing");
            }
            Ok(format!("{n} archive-time-stamp-v3 value(s)"))
        })(),
    );
    check(
        &mut checks,
        "archive timestamp TSA signatures",
        verify_archive_timestamp_token_signatures(input),
    );
    check(
        &mut checks,
        "archive timestamp chain imprint/index",
        verify_archive_timestamp_v3_chain(input, external),
    );
    check(
        &mut checks,
        "archive timestamp chronology",
        (|| -> Result<String> {
            let esc = xlong::verify_esc_timestamp_imprint(input)?;
            let records = archive_records(input)?;
            let first = records.first().context("archive-time-stamp-v3 missing")?;
            let esc_unix = x509::generalized_time_to_unix(&esc.gen_time)?;
            let first_unix = x509::generalized_time_to_unix(&first.info.gen_time)?;
            if first_unix < esc_unix {
                bail!(
                    "first archive timestamp {} predates CAdES-C timestamp {}",
                    first.info.gen_time,
                    esc.gen_time
                );
            }
            for pair in records.windows(2) {
                let a = x509::generalized_time_to_unix(&pair[0].info.gen_time)?;
                let b = x509::generalized_time_to_unix(&pair[1].info.gen_time)?;
                if b <= a {
                    bail!(
                        "archive timestamps are not strictly increasing: {} then {}",
                        pair[0].info.gen_time,
                        pair[1].info.gen_time
                    );
                }
            }
            Ok(format!(
                "first {} >= CAdES-C {}; {} archive timestamp(s), strictly increasing",
                first.info.gen_time,
                esc.gen_time,
                records.len(),
            ))
        })(),
    );
    ArchiveAudit { checks }
}

