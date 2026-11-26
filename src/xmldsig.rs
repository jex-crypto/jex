// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
//! XML-DSig + XAdES (BES/T/X-L/A) with CryptoPro GOST R 34.10-2012 algorithms.
//!
//! Uses Exc-C14N (`xml_c14n`), Streebog digests, and `gost3410` signatures
//! (SignatureValue = base64 of S||R big-endian fixed-width).

use crate::cms_der;
use crate::curves;
use crate::gost3410;
use crate::ocsp;
use crate::timestamp;
use crate::validation;
use crate::x509;
use crate::xml_c14n::{self, XmlDoc};
use crate::xml_util::{
    find_element_by_id, get_attr, parse_element, serialize_element, Element, Node, XMLDSIG_NS,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::time::{SystemTime, UNIX_EPOCH};

/// CryptoPro / CADESCOM digest method URIs (GOST R 34.11-2012).
pub const DIGEST_METHOD_256: &str = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
pub const DIGEST_METHOD_512: &str = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512";
/// CryptoPro / CADESCOM signature method URIs (GOST R 34.10-2012 + matching digest).
pub const SIGNATURE_METHOD_256: &str =
    "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";
pub const SIGNATURE_METHOD_512: &str =
    "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";

pub const EXC_C14N_URI: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const ENVELOPED_TRANSFORM_URI: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";
/// XAdES 1.4.1 namespace (CompleteCertificateRefsV2, SigAndRefsTimeStampV2, …).
pub const XADES_141_NS: &str = "http://uri.etsi.org/01903/v1.4.1#";
pub const XADES_SIGNED_PROPERTIES_TYPE: &str = "http://uri.etsi.org/01903#SignedProperties";
/// EncapsulatedPKIData Encoding attribute (ETSI TS 101 903 / XAdES 1.2.2 URI, still common).
pub const ENCAPSULATED_PKI_ENCODING: &str = "http://uri.etsi.org/01903/v1.2.2#DER";
/// Default CryptoPro qualified TSA used for XAdES-T / XLT1 goldens.
pub const DEFAULT_CRYPTOPRO_TSA: &str = "http://qs.cryptopro.ru/tsp/tsp.srf";

/// CADESCOM_XADES_* / XMLDSIG type flags (OR-able with signature type enum separately).
pub const XADES_NONE: u32 = 0x0000;
pub const XADES_BES: u32 = 0x0020;
pub const XADES_T: u32 = 0x0050;
pub const XADES_XLT1: u32 = 0x05d0;
/// XAdES-A (archive): XLT1 + `xades141:ArchiveTimeStamp`.
/// Matches CryptoPro `CADESCOM_XADES_A` / `XADES_A` (`0x7d0` in `xades.h`).
pub const XADES_A: u32 = 0x07d0;

const DEFAULT_TEMPLATE_XPATH: &str = "//*[local-name()='Signature' and namespace-uri()='http://www.w3.org/2000/09/xmldsig#' and (count(*[local-name()='SignatureValue'])=0 or *[local-name()='SignatureValue']='')]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum XmlSignatureType {
    Enveloped = 0,
    Enveloping = 1,
    Template = 2,
}

pub struct SignXmlParams<'a> {
    pub content: &'a str,
    pub cert_der: &'a [u8],
    pub curve: &'a curves::Curve,
    pub private_le: &'a [u8],
    pub public_x_le: &'a [u8],
    pub public_y_le: &'a [u8],
    pub signature_type: XmlSignatureType,
    pub digest_method: &'a str,
    pub signature_method: &'a str,
    pub xpath: Option<&'a str>,
    /// 0 = plain XMLDSIG, 0x20 BES, 0x50 T, 0x5d0 XLT1, 0x7d0 A (CADESCOM).
    pub xades_flags: u32,
    pub tsa_url: Option<&'a str>,
    pub tsa_policy: Option<&'a str>,
    pub tsa_timeout_secs: u64,
}

pub struct VerifyXmlResult {
    pub ok: bool,
    pub signature_valid: bool,
    pub references_valid: bool,
    pub certificate_der: Option<Vec<u8>>,
}

/// DigestMethod URI for the curve width (32 → 256-bit Streebog, 64 → 512).
pub fn digest_method_uri(curve_bytes: usize) -> Result<&'static str> {
    match curve_bytes {
        32 => Ok(DIGEST_METHOD_256),
        64 => Ok(DIGEST_METHOD_512),
        n => bail!("unsupported curve width for XML-DSig digest: {n}"),
    }
}

/// SignatureMethod URI for the curve width.
pub fn signature_method_uri(curve_bytes: usize) -> Result<&'static str> {
    match curve_bytes {
        32 => Ok(SIGNATURE_METHOD_256),
        64 => Ok(SIGNATURE_METHOD_512),
        n => bail!("unsupported curve width for XML-DSig signature: {n}"),
    }
}

pub fn sign_xml(p: &SignXmlParams<'_>) -> Result<String> {
    let identity = x509::identity(p.cert_der).context("parse signing certificate")?;
    if identity.public_x_le != p.public_x_le || identity.public_y_le != p.public_y_le {
        bail!("public key does not match certificate SubjectPublicKeyInfo");
    }
    let digest_bytes = digest_size_for_uri(p.digest_method)?;
    if digest_bytes != p.curve.bytes {
        bail!(
            "digest method {} width {} does not match curve {} bytes",
            p.digest_method,
            digest_bytes,
            p.curve.bytes
        );
    }

    let xades_bes = matches!(
        p.xades_flags,
        XADES_BES | XADES_T | XADES_XLT1 | XADES_A
    ) || p.xades_flags & XADES_BES != 0;
    let xades_t = matches!(p.xades_flags, XADES_T | XADES_XLT1 | XADES_A);
    let xades_xlt1 = matches!(p.xades_flags, XADES_XLT1 | XADES_A);
    let xades_a = p.xades_flags == XADES_A;

    match p.signature_type {
        XmlSignatureType::Enveloped => {
            sign_enveloped(p, &identity, xades_bes, xades_t, xades_xlt1, xades_a)
        }
        XmlSignatureType::Enveloping => {
            sign_enveloping(p, &identity, xades_bes, xades_t, xades_xlt1, xades_a)
        }
        XmlSignatureType::Template => {
            sign_template(p, &identity, xades_t || xades_xlt1, xades_xlt1, xades_a)
        }
    }
}

pub fn verify_xml(signed_xml: &str, xpath: Option<&str>) -> Result<VerifyXmlResult> {
    let mut root = parse_element(signed_xml).context("parse signed XML")?;
    let sig = select_signature_mut(&mut root, xpath)?.context("no ds:Signature found")?;
    // Clone signature subtree for analysis while keeping full doc for URI="".
    let sig_xml = serialize_element(sig);
    let full_xml = serialize_element(&root);

    let sig_el = parse_element(&sig_xml)?;
    let signed_info =
        find_child_ns(&sig_el, XMLDSIG_NS, "SignedInfo").context("Signature missing SignedInfo")?;
    let digest_method = reference_digest_method(signed_info).unwrap_or(DIGEST_METHOD_256);
    let digest_bytes = digest_size_for_uri(digest_method)?;

    let references_valid = verify_references(&full_xml, &sig_el, digest_bytes)?;

    let cert_der = extract_certificate(&sig_el)?;
    let (signature_valid, certificate_der) = if let Some(cert) = cert_der {
        let identity = x509::identity(&cert).context("parse KeyInfo certificate")?;
        let curve = curves::by_oid(&identity.curve_oid)
            .with_context(|| format!("unsupported curve OID {}", identity.curve_oid))?;
        let si_c14n = canonicalize_signed_info(&full_xml, &sig_el)?;
        let si_digest = crate::cades::digest_data(curve.bytes, &si_c14n)?;
        let sig_value = signature_value_bytes(&sig_el)?;
        let ok = gost3410::verify_digest(
            &curve,
            &identity.public_x_le,
            &identity.public_y_le,
            &si_digest,
            &sig_value,
        )?;
        (ok, Some(cert))
    } else {
        (false, None)
    };

    let timestamp_ok = match verify_signature_timestamp(&sig_el) {
        Ok(None) => true, // absent → unchanged
        Ok(Some(ok)) => ok,
        Err(_) => false,
    };

    // XAdES properties are bound to the Signature via its Id
    // (QualifyingProperties/@Target). Without an Id there is no XAdES-X/A
    // material to check, so treat these properties as absent.
    let (sar_ok, archive_ok) = match get_attr(&sig_el, "Id") {
        Some(sig_id) => (
            match verify_sig_and_refs_timestamp(&full_xml, sig_id) {
                Ok(None) => true,
                Ok(Some(ok)) => ok,
                Err(_) => false,
            },
            match verify_archive_timestamps(&full_xml, sig_id) {
                Ok(None) => true,
                Ok(Some(ok)) => ok,
                Err(_) => false,
            },
        ),
        None => (true, true),
    };

    Ok(VerifyXmlResult {
        ok: signature_valid && references_valid && timestamp_ok && sar_ok && archive_ok,
        signature_valid,
        references_valid,
        certificate_der,
    })
}

// ── signing modes ──────────────────────────────────────────────────────────

fn sign_enveloped(
    p: &SignXmlParams<'_>,
    identity: &x509::CertIdentity,
    xades_bes: bool,
    xades_t: bool,
    xades_xlt1: bool,
    xades_a: bool,
) -> Result<String> {
    let sig_id = "Signature-jex";
    let sp_id = "SignedProperties-jex";
    let mut root = parse_element(p.content).context("parse XML content")?;

    let signed_props = if xades_bes {
        Some(build_signed_properties(p, identity, sp_id)?)
    } else {
        None
    };

    let sig_xml = build_signature_skeleton(
        p,
        sig_id,
        signed_props.as_deref(),
        sp_id,
        /*enveloped*/ true,
        /*object_xml*/ None,
    )?;
    let sig_el = parse_element(&sig_xml)?;
    root.children.push(Node::Element(sig_el));

    let mut doc_xml = serialize_element(&root);
    fill_reference_digests(&mut doc_xml, sig_id, p.digest_method)?;
    let sig_bytes = sign_signed_info(&doc_xml, sig_id, p)?;
    set_signature_value(&mut doc_xml, sig_id, &sig_bytes)?;

    if xades_t || xades_xlt1 {
        add_unsigned_after_sign(&mut doc_xml, sig_id, p, xades_xlt1)?;
    }
    if xades_a {
        add_archive_timestamp(&mut doc_xml, sig_id, p)?;
    }
    Ok(doc_xml)
}

fn sign_enveloping(
    p: &SignXmlParams<'_>,
    identity: &x509::CertIdentity,
    xades_bes: bool,
    xades_t: bool,
    xades_xlt1: bool,
    xades_a: bool,
) -> Result<String> {
    let sig_id = "Signature-jex";
    let sp_id = "SignedProperties-jex";
    let obj_id = "Object-jex";

    let content_el = parse_element(p.content).context("parse XML content")?;
    let object_inner = serialize_element(&content_el);
    // Plain enveloping matches CryptoPro: default xmldsig xmlns, no ds: prefix.
    let object_xml = format!(r#"<Object Id="{obj_id}">{object_inner}</Object>"#);

    let signed_props = if xades_bes {
        Some(build_signed_properties(p, identity, sp_id)?)
    } else {
        None
    };

    let mut sig_xml = build_signature_skeleton(
        p,
        sig_id,
        signed_props.as_deref(),
        sp_id,
        /*enveloped*/ false,
        Some((obj_id, &object_xml)),
    )?;

    fill_reference_digests(&mut sig_xml, sig_id, p.digest_method)?;
    let sig_bytes = sign_signed_info(&sig_xml, sig_id, p)?;
    set_signature_value(&mut sig_xml, sig_id, &sig_bytes)?;

    if xades_t || xades_xlt1 {
        add_unsigned_after_sign(&mut sig_xml, sig_id, p, xades_xlt1)?;
    }
    if xades_a {
        add_archive_timestamp(&mut sig_xml, sig_id, p)?;
    }
    Ok(sig_xml)
}

fn sign_template(
    p: &SignXmlParams<'_>,
    identity: &x509::CertIdentity,
    xades_t: bool,
    xades_xlt1: bool,
    xades_a: bool,
) -> Result<String> {
    let xpath = p.xpath.unwrap_or(DEFAULT_TEMPLATE_XPATH);
    let mut root = parse_element(p.content).context("parse template XML")?;
    let targets = find_template_signatures(&root, xpath);
    if targets.is_empty() {
        bail!("template xpath matched no incomplete ds:Signature nodes");
    }
    // Sign the first match (CryptoPro SignXML typically fills one).
    let path = targets[0].clone();
    fill_template_signature(&mut root, &path, p, identity)?;
    let mut doc_xml = serialize_element(&root);

    // Locate Id for subsequent unsigned props / digest fill.
    let mut root2 = parse_element(&doc_xml)?;
    let sig = element_at_path_mut(&mut root2, &path).context("signature path lost")?;
    let sig_id = get_attr(sig, "Id").unwrap_or("Signature-jex").to_string();
    let sig_id_owned = if get_attr(sig, "Id").is_none() {
        sig.attrs.push(crate::xml_util::Attr {
            prefix: None,
            local_name: "Id".into(),
            namespace_uri: String::new(),
            value: sig_id.clone(),
        });
        sig_id
    } else {
        sig_id
    };
    doc_xml = serialize_element(&root2);

    fill_reference_digests(&mut doc_xml, &sig_id_owned, p.digest_method)?;
    let sig_bytes = sign_signed_info(&doc_xml, &sig_id_owned, p)?;
    set_signature_value(&mut doc_xml, &sig_id_owned, &sig_bytes)?;

    if xades_t || xades_xlt1 {
        add_unsigned_after_sign(&mut doc_xml, &sig_id_owned, p, xades_xlt1)?;
    }
    if xades_a {
        add_archive_timestamp(&mut doc_xml, &sig_id_owned, p)?;
    }
    Ok(doc_xml)
}

fn fill_template_signature(
    root: &mut Element,
    path: &[usize],
    p: &SignXmlParams<'_>,
    identity: &x509::CertIdentity,
) -> Result<()> {
    let sig = element_at_path_mut(root, path).context("invalid signature path")?;
    // Ensure SignatureMethod / DigestMethod match params when empty/absent.
    if let Some(si) = find_child_ns_mut(sig, XMLDSIG_NS, "SignedInfo") {
        if let Some(sm) = find_child_ns_mut(si, XMLDSIG_NS, "SignatureMethod") {
            if get_attr(sm, "Algorithm").unwrap_or("").is_empty() {
                set_attr(sm, "Algorithm", p.signature_method);
            }
        }
        for child in si.children.iter_mut() {
            if let Node::Element(r) = child {
                if r.local_name == "Reference" && r.namespace_uri == XMLDSIG_NS {
                    if let Some(dm) = find_child_ns_mut(r, XMLDSIG_NS, "DigestMethod") {
                        if get_attr(dm, "Algorithm").unwrap_or("").is_empty() {
                            set_attr(dm, "Algorithm", p.digest_method);
                        }
                    }
                }
            }
        }
    }
    // KeyInfo: fill only when empty / missing certificate.
    let key_info_empty = match find_child_ns(sig, XMLDSIG_NS, "KeyInfo") {
        None => true,
        Some(ki) => {
            element_text(ki).trim().is_empty()
                && find_desc_ns(ki, XMLDSIG_NS, "X509Certificate").is_none()
        }
    };
    if key_info_empty {
        // Remove empty KeyInfo if present, then insert filled one after SignatureValue.
        sig.children.retain(|n| {
            !matches!(n, Node::Element(e) if e.local_name == "KeyInfo" && e.namespace_uri == XMLDSIG_NS)
        });
        let ki = parse_element(&key_info_xml(p.cert_der, false)?)?;
        // Insert after SignatureValue if possible.
        let insert_at = sig
            .children
            .iter()
            .position(|n| {
                matches!(n, Node::Element(e) if e.local_name == "SignatureValue" && e.namespace_uri == XMLDSIG_NS)
            })
            .map(|i| i + 1)
            .unwrap_or(sig.children.len());
        sig.children.insert(insert_at, Node::Element(ki));
    }
    let _ = identity;
    Ok(())
}

// ── skeleton / XAdES builders ──────────────────────────────────────────────

fn build_signature_skeleton(
    p: &SignXmlParams<'_>,
    sig_id: &str,
    signed_props_xml: Option<&str>,
    sp_id: &str,
    enveloped: bool,
    content_object: Option<(&str, &str)>,
) -> Result<String> {
    // CryptoPro plain XMLDSIG uses default xmlns on Signature (no ds: prefix).
    // CryptoPro XAdES-BES uses the ds: prefix; mirror that for reverse interop.
    let xades = signed_props_xml.is_some();
    let pfx = if xades { "ds:" } else { "" };
    let sig_ns_decl = if xades {
        format!(r#"xmlns:ds="{XMLDSIG_NS}""#)
    } else {
        format!(r#"xmlns="{XMLDSIG_NS}""#)
    };

    let mut refs = String::new();
    if enveloped {
        refs.push_str(&format!(
            concat!(
                r#"<{p}Reference URI=""><{p}Transforms>"#,
                r#"<{p}Transform Algorithm="{env}"/>"#,
                r#"<{p}Transform Algorithm="{c14n}"/>"#,
                r#"</{p}Transforms><{p}DigestMethod Algorithm="{dm}"/>"#,
                r#"<{p}DigestValue></{p}DigestValue></{p}Reference>"#,
            ),
            p = pfx,
            env = ENVELOPED_TRANSFORM_URI,
            c14n = EXC_C14N_URI,
            dm = xml_escape_attr(p.digest_method),
        ));
    } else if let Some((obj_id, _)) = content_object {
        refs.push_str(&format!(
            concat!(
                "<{p}Reference URI=\"#{obj}\"><{p}Transforms>",
                "<{p}Transform Algorithm=\"{c14n}\"/></{p}Transforms>",
                "<{p}DigestMethod Algorithm=\"{dm}\"/>",
                "<{p}DigestValue></{p}DigestValue></{p}Reference>",
            ),
            p = pfx,
            obj = obj_id,
            c14n = EXC_C14N_URI,
            dm = xml_escape_attr(p.digest_method),
        ));
    }
    if signed_props_xml.is_some() {
        refs.push_str(&format!(
            concat!(
                "<{p}Reference URI=\"#{sp}\" Type=\"{ty}\"><{p}Transforms>",
                "<{p}Transform Algorithm=\"{c14n}\"/></{p}Transforms>",
                "<{p}DigestMethod Algorithm=\"{dm}\"/>",
                "<{p}DigestValue></{p}DigestValue></{p}Reference>",
            ),
            p = pfx,
            sp = sp_id,
            ty = XADES_SIGNED_PROPERTIES_TYPE,
            c14n = EXC_C14N_URI,
            dm = xml_escape_attr(p.digest_method),
        ));
    }

    let mut objects = String::new();
    if let Some((_, obj_xml)) = content_object {
        objects.push_str(obj_xml);
    }
    if let Some(sp) = signed_props_xml {
        objects.push_str(&format!(
            concat!(
                "<ds:Object><xades:QualifyingProperties xmlns:xades=\"{xades}\" ",
                "Target=\"#{sid}\">{props}</xades:QualifyingProperties></ds:Object>",
            ),
            xades = XADES_NS,
            sid = sig_id,
            props = sp,
        ));
    }

    let ki = key_info_xml(p.cert_der, xades)?;
    Ok(format!(
        concat!(
            "<{p}Signature {ns} Id=\"{sid}\">",
            "<{p}SignedInfo>",
            "<{p}CanonicalizationMethod Algorithm=\"{c14n}\"/>",
            "<{p}SignatureMethod Algorithm=\"{sm}\"/>",
            "{refs}</{p}SignedInfo>",
            "<{p}SignatureValue></{p}SignatureValue>",
            "{ki}{objects}</{p}Signature>",
        ),
        p = pfx,
        ns = sig_ns_decl,
        sid = sig_id,
        c14n = EXC_C14N_URI,
        sm = xml_escape_attr(p.signature_method),
        refs = refs,
        ki = ki,
        objects = objects,
    ))
}

fn build_signed_properties(
    p: &SignXmlParams<'_>,
    identity: &x509::CertIdentity,
    sp_id: &str,
) -> Result<String> {
    let cert_hash = crate::cades::digest_data(p.curve.bytes, p.cert_der)?;
    let cert_hash_b64 = STANDARD.encode(&cert_hash);
    let issuer_serial = issuer_serial_der(identity);
    let issuer_serial_b64 = STANDARD.encode(&issuer_serial);
    let signing_time = xs_datetime_utc_now()?;
    Ok(format!(
        r#"<xades:SignedProperties xmlns:xades="{XADES_NS}" xmlns:ds="{XMLDSIG_NS}" Id="{sp_id}"><xades:SignedSignatureProperties><xades:SigningTime>{signing_time}</xades:SigningTime><xades:SigningCertificateV2><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="{dm}"/><ds:DigestValue>{cert_hash_b64}</ds:DigestValue></xades:CertDigest><xades:IssuerSerialV2>{issuer_serial_b64}</xades:IssuerSerialV2></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties></xades:SignedProperties>"#,
        dm = xml_escape_attr(p.digest_method),
    ))
}

fn issuer_serial_der(identity: &x509::CertIdentity) -> Vec<u8> {
    let general_names = cms_der::sequence(&[cms_der::tlv(0xA4, &identity.issuer_der)]);
    cms_der::sequence(&[general_names, identity.serial_der.clone()])
}

fn key_info_xml(cert_der: &[u8], xades_ds_prefix: bool) -> Result<String> {
    let b64 = STANDARD.encode(cert_der);
    // Plain XMLDSIG: default xmlns (CryptoPro style). Explicit xmlns so the
    // fragment parses into XMLDSIG_NS even when inserted into a ds:-prefixed
    // template Signature.
    // XAdES: explicit ds: prefix like CryptoPro XAdES-BES goldens.
    if xades_ds_prefix {
        Ok(format!(
            r#"<ds:KeyInfo xmlns:ds="{XMLDSIG_NS}"><ds:X509Data><ds:X509Certificate>{b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"#
        ))
    } else {
        Ok(format!(
            r#"<KeyInfo xmlns="{XMLDSIG_NS}"><X509Data><X509Certificate>{b64}</X509Certificate></X509Data></KeyInfo>"#
        ))
    }
}

// ── digest / sign helpers ──────────────────────────────────────────────────

fn fill_reference_digests(doc_xml: &mut String, sig_id: &str, digest_method: &str) -> Result<()> {
    let digest_bytes = digest_size_for_uri(digest_method)?;
    let mut root = parse_element(doc_xml)?;
    let sig = find_signature_by_id_mut(&mut root, sig_id)
        .with_context(|| format!("Signature Id={sig_id} not found"))?;
    let si = find_child_ns_mut(sig, XMLDSIG_NS, "SignedInfo").context("SignedInfo missing")?;

    // Collect Reference URIs first (immutable borrow), then compute digests from doc snapshot.
    let mut specs: Vec<(String, Vec<String>)> = Vec::new();
    for child in &si.children {
        if let Node::Element(r) = child {
            if r.local_name == "Reference" && r.namespace_uri == XMLDSIG_NS {
                let uri = get_attr(r, "URI").unwrap_or("").to_string();
                let transforms = collect_transform_uris(r);
                specs.push((uri, transforms));
            }
        }
    }
    let snapshot = serialize_element(&root);
    let mut digests: Vec<String> = Vec::new();
    for (uri, transforms) in &specs {
        let octets = apply_reference_transforms(&snapshot, uri, transforms)?;
        let d = crate::cades::digest_data(digest_bytes, &octets)?;
        digests.push(STANDARD.encode(d));
    }

    let sig = find_signature_by_id_mut(&mut root, sig_id).unwrap();
    let si = find_child_ns_mut(sig, XMLDSIG_NS, "SignedInfo").unwrap();
    let mut i = 0;
    for child in si.children.iter_mut() {
        if let Node::Element(r) = child {
            if r.local_name == "Reference" && r.namespace_uri == XMLDSIG_NS {
                if let Some(dv) = find_child_ns_mut(r, XMLDSIG_NS, "DigestValue") {
                    set_text(dv, &digests[i]);
                }
                i += 1;
            }
        }
    }
    *doc_xml = serialize_element(&root);
    Ok(())
}

fn sign_signed_info(doc_xml: &str, sig_id: &str, p: &SignXmlParams<'_>) -> Result<Vec<u8>> {
    let doc = XmlDoc::parse(doc_xml)?;
    // Prefer SignedInfo under the named Signature (Id lookup on Signature, then child).
    let root = doc.root();
    let sig = find_element_by_id(root, sig_id)
        .or_else(|| find_desc_ns(root, XMLDSIG_NS, "Signature"))
        .context("Signature not found for SignedInfo C14N")?;
    let si = find_child_ns(sig, XMLDSIG_NS, "SignedInfo").context("SignedInfo missing")?;
    // In-place Exc-C14N keeps xmlns inherited from Signature (CryptoPro default ns).
    let c14n = xml_c14n::canonicalize_element_exc(si);
    let digest = crate::cades::digest_data(p.curve.bytes, &c14n)?;
    gost3410::sign_digest(p.curve, p.private_le, &digest)
}

fn set_signature_value(doc_xml: &mut String, sig_id: &str, sig_bytes: &[u8]) -> Result<()> {
    let mut root = parse_element(doc_xml)?;
    let sig = find_signature_by_id_mut(&mut root, sig_id)
        .with_context(|| format!("Signature Id={sig_id} not found"))?;
    let sv =
        find_child_ns_mut(sig, XMLDSIG_NS, "SignatureValue").context("SignatureValue missing")?;
    // CryptoPro wraps SignatureValue base64 at 64 columns.
    set_text(sv, &base64_wrap_64(&STANDARD.encode(sig_bytes)));
    *doc_xml = serialize_element(&root);
    Ok(())
}

fn base64_wrap_64(b64: &str) -> String {
    let mut out = String::with_capacity(b64.len() + b64.len() / 64 + 1);
    for (i, ch) in b64.chars().enumerate() {
        if i > 0 && i % 64 == 0 {
            out.push('\n');
        }
        out.push(ch);
    }
    out
}

fn add_unsigned_after_sign(
    doc_xml: &mut String,
    sig_id: &str,
    p: &SignXmlParams<'_>,
    xades_xlt1: bool,
) -> Result<()> {
    let tsa = p.tsa_url.context("XAdES-T/XLT1 requires tsa_url")?;
    let digest_oid = tsa_digest_oid(p.curve.bytes)?;
    let timeout = p.tsa_timeout_secs.max(1);

    // XAdES SignatureTimeStamp messageImprint is Exc-C14N(ds:SignatureValue),
    // not the raw CMS/GOST signature octets (those are for CAdES-T).
    let sv_c14n = signature_value_exc_c14n(doc_xml, sig_id)?;
    let sig_ts =
        timestamp::request_timestamp_over_data(tsa, &sv_c14n, digest_oid, p.tsa_policy, timeout)
            .context("request XAdES SignatureTimeStamp")?;
    let signature_ts_xml = xades_timestamp_xml("SignatureTimeStamp", &sig_ts.token);

    if !xades_xlt1 {
        set_unsigned_signature_properties(doc_xml, sig_id, &signature_ts_xml, false)?;
        return Ok(());
    }

    // CryptoPro libxades: "|TSP − OCSP| > 60 sec : TSP and OCSP time is out of
    // sync". Fetch SignatureTimeStamp TSA OCSP immediately after STS, before
    // the slower document-signer chain/CRL walk.
    let sts_meta =
        timestamp::signer_meta(&sig_ts.token).context("locate SignatureTimeStamp TSA signer")?;
    let sts_gen_unix = x509::generalized_time_to_unix(&sig_ts.info.gen_time)?;
    let sts_tsa_material = validation::collect_tsa(&sts_meta.certificate, timeout, sts_gen_unix)
        .context("collect SignatureTimeStamp TSA validation material")?;

    // Document-signer evidence: OCSP thisUpdate must be >= SignatureTimeStamp
    // (same CryptoPro XLT1 rule as CAdES inner TSP ≤ OCSP ≤ outer TSP).
    let material = validation::collect(
        p.cert_der,
        Vec::new(),
        Vec::new(),
        None,
        None,
        true,
        timeout,
        sts_gen_unix,
    )
    .context("collect XAdES-X-L validation material (chain/OCSP/CRL)")?;

    // CryptoPro libxades does not use TimeStampValidationData when validating
    // SignatureTimeStamp offline. Include the STS TSA path in Complete*Refs,
    // then use a provisional SAR to discover its TSA before finalizing them.
    let provisional_xl =
        build_xades_xl_parts(p, &[&material, &sts_tsa_material], &[&sts_meta.certificate])?;
    let provisional_refs = format!(
        "{}{}{}",
        signature_ts_xml, provisional_xl.cert_refs, provisional_xl.rev_refs
    );
    set_unsigned_signature_properties(doc_xml, sig_id, &provisional_refs, true)?;
    let provisional_imprint = sig_and_refs_imprint(doc_xml, sig_id)?;
    let provisional_sar = timestamp::request_timestamp_over_data(
        tsa,
        &provisional_imprint,
        digest_oid,
        p.tsa_policy,
        timeout,
    )
    .context("request provisional XAdES SigAndRefsTimeStampV2")?;
    let sar_meta = timestamp::signer_meta(&provisional_sar.token)
        .context("locate SigAndRefsTimeStampV2 TSA signer")?;
    let sar_unix = x509::generalized_time_to_unix(&provisional_sar.info.gen_time)?;
    let sar_tsa_material = validation::collect_tsa(&sar_meta.certificate, timeout, sar_unix)
        .context("collect SigAndRefsTimeStampV2 TSA validation material")?;
    let tsa_materials: Vec<&validation::ValidationMaterial> =
        if sts_meta.certificate == sar_meta.certificate {
            vec![&sar_tsa_material]
        } else {
            vec![&sts_tsa_material, &sar_tsa_material]
        };
    let mut all_materials = vec![&material];
    all_materials.extend(tsa_materials);
    let xl = build_xades_xl_parts(
        p,
        &all_materials,
        &[&sts_meta.certificate, &sar_meta.certificate],
    )?;

    let final_refs = format!("{}{}{}", signature_ts_xml, xl.cert_refs, xl.rev_refs);
    set_unsigned_signature_properties(doc_xml, sig_id, &final_refs, true)?;
    let sar_imprint = sig_and_refs_imprint(doc_xml, sig_id)?;
    let sar_ts = timestamp::request_timestamp_over_data(
        tsa,
        &sar_imprint,
        digest_oid,
        p.tsa_policy,
        timeout,
    )
    .context("request final XAdES SigAndRefsTimeStampV2")?;
    let final_sar_meta = timestamp::signer_meta(&sar_ts.token)
        .context("locate final SigAndRefsTimeStampV2 TSA signer")?;
    if final_sar_meta.certificate != sar_meta.certificate {
        bail!("TSA signer rotated between provisional and final SigAndRefsTimeStampV2");
    }
    let sar_xml = xades141_timestamp_xml("SigAndRefsTimeStampV2", &sar_ts.token);

    let unsigned_inner = format!(
        "{}{}{}{}{}{}",
        signature_ts_xml, xl.cert_refs, xl.rev_refs, sar_xml, xl.cert_vals, xl.rev_vals
    );
    set_unsigned_signature_properties(doc_xml, sig_id, &unsigned_inner, true)?;
    Ok(())
}

/// Add (or renew) `xades141:ArchiveTimeStamp` on an existing XAdES-XLT1/A signature.
///
/// No private key. Imprint follows ETSI EN 319 132-1 §5.5.2.3 (not-distributed /
/// implicit case) with Exc-C14N. ETSI defines the non-deprecated property in the
/// XAdES 1.4.1 namespace; the 1.3.2 property is not a substitute because current
/// CryptoPro libxades then classifies the document only as XAdES-XLT1.
pub fn add_archive_timestamp_xml(
    doc_xml: &mut String,
    sig_id: Option<&str>,
    tsa_url: &str,
    tsa_policy: Option<&str>,
    tsa_timeout_secs: u64,
    digest_oid: &str,
) -> Result<()> {
    let sid = resolve_signature_id(doc_xml, sig_id)?;
    ensure_xlt1_or_a_base(doc_xml, &sid)?;
    let timeout = tsa_timeout_secs.max(1);
    let imprint = archive_timestamp_imprint(doc_xml, &sid, None)
        .context("build XAdES ArchiveTimeStamp messageImprint")?;
    let ts = timestamp::request_timestamp_over_data(
        tsa_url,
        &imprint,
        digest_oid,
        tsa_policy,
        timeout,
    )
    .context("request XAdES ArchiveTimeStamp")?;
    // Chronology vs previous archive stamps (and vs SigAndRefs when present).
    let new_unix = x509::generalized_time_to_unix(&ts.info.gen_time)?;
    if let Some(prev) = latest_archive_timestamp_gen_unix(doc_xml, &sid)? {
        if new_unix <= prev {
            bail!(
                "new ArchiveTimeStamp {} is not later than previous archive timestamp; retry after TSA time advances",
                ts.info.gen_time
            );
        }
    }
    append_archive_timestamp_property(doc_xml, &sid, &ts.token)?;
    Ok(())
}

fn add_archive_timestamp(doc_xml: &mut String, sig_id: &str, p: &SignXmlParams<'_>) -> Result<()> {
    let tsa = p
        .tsa_url
        .context("XAdES-A requires tsa_url")?;
    let digest_oid = tsa_digest_oid(p.curve.bytes)?;
    add_archive_timestamp_xml(
        doc_xml,
        Some(sig_id),
        tsa,
        p.tsa_policy,
        p.tsa_timeout_secs,
        digest_oid,
    )
}

fn resolve_signature_id(doc_xml: &str, sig_id: Option<&str>) -> Result<String> {
    if let Some(id) = sig_id {
        return Ok(id.to_string());
    }
    let root = parse_element(doc_xml)?;
    let sig = find_first_signature(&root).context("no ds:Signature found")?;
    Ok(get_attr(sig, "Id")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Signature-jex".into()))
}

fn ensure_xlt1_or_a_base(doc_xml: &str, sig_id: &str) -> Result<()> {
    let doc = XmlDoc::parse(doc_xml)?;
    let sig = find_element_by_id(doc.root(), sig_id)
        .with_context(|| format!("Signature Id={sig_id} not found"))?;
    if find_desc_ns(sig, XADES_141_NS, "SigAndRefsTimeStampV2").is_none()
        && find_desc_ns(sig, XADES_141_NS, "CompleteCertificateRefsV2").is_none()
    {
        bail!("XAdES-A archive timestamp requires XAdES-XLT1 input (SigAndRefsTimeStampV2 / CompleteCertificateRefsV2)");
    }
    Ok(())
}

fn latest_archive_timestamp_gen_unix(doc_xml: &str, sig_id: &str) -> Result<Option<i64>> {
    let doc = XmlDoc::parse(doc_xml)?;
    let sig = find_element_by_id(doc.root(), sig_id)
        .with_context(|| format!("Signature Id={sig_id} not found"))?;
    let Some(usp) = find_unsigned_signature_properties(sig) else {
        return Ok(None);
    };
    let mut latest: Option<i64> = None;
    for child in &usp.children {
        let Node::Element(el) = child else {
            continue;
        };
        if el.local_name != "ArchiveTimeStamp" {
            continue;
        }
        let Some(encap) = find_desc_ns(el, XADES_NS, "EncapsulatedTimeStamp")
            .or_else(|| find_child_local(el, "EncapsulatedTimeStamp"))
        else {
            continue;
        };
        let compact: String = element_text(encap).split_whitespace().collect();
        let Ok(token) = STANDARD.decode(compact.as_bytes()) else {
            continue;
        };
        let Ok(info) = timestamp::parse_token(&token) else {
            continue;
        };
        let Ok(u) = x509::generalized_time_to_unix(&info.gen_time) else {
            continue;
        };
        latest = Some(latest.map_or(u, |p| p.max(u)));
    }
    Ok(latest)
}

fn append_archive_timestamp_property(
    doc_xml: &mut String,
    sig_id: &str,
    token: &[u8],
) -> Result<()> {
    let ats_xml = xades141_timestamp_xml("ArchiveTimeStamp", token);
    let mut root = parse_element(doc_xml)?;
    let sig = find_signature_by_id_mut(&mut root, sig_id)
        .with_context(|| format!("Signature Id={sig_id} not found"))?;
    let usp = find_unsigned_signature_properties_mut(sig)
        .context("UnsignedSignatureProperties missing (need XAdES-T/XLT1 first)")?;
    usp.children
        .push(Node::Element(parse_element(&ats_xml)?));
    *doc_xml = serialize_element(&root);
    Ok(())
}

fn find_unsigned_signature_properties_mut(sig: &mut Element) -> Option<&mut Element> {
    for child in &mut sig.children {
        let Node::Element(obj) = child else {
            continue;
        };
        if obj.local_name != "Object" || obj.namespace_uri != XMLDSIG_NS {
            continue;
        }
        for c2 in &mut obj.children {
            let Node::Element(qp) = c2 else {
                continue;
            };
            if qp.local_name != "QualifyingProperties" {
                continue;
            }
            for c3 in &mut qp.children {
                let Node::Element(up) = c3 else {
                    continue;
                };
                if up.local_name != "UnsignedProperties" {
                    continue;
                }
                for c4 in &mut up.children {
                    let Node::Element(usp) = c4 else {
                        continue;
                    };
                    if usp.local_name == "UnsignedSignatureProperties" {
                        return Some(usp);
                    }
                }
            }
        }
    }
    None
}

fn find_first_signature(root: &Element) -> Option<&Element> {
    if root.local_name == "Signature" && root.namespace_uri == XMLDSIG_NS {
        return Some(root);
    }
    for child in &root.children {
        if let Node::Element(el) = child {
            if let Some(s) = find_first_signature(el) {
                return Some(s);
            }
        }
    }
    None
}

/// ETSI EN 319 132-1 §5.5.2.3 (not-distributed) ArchiveTimeStamp messageImprint.
///
/// `stop_before_ats_index`: when verifying ATS #n, only unsigned properties with
/// child index `< n` are included. `None` = all current unsigned properties
/// (generation, before the new ATS exists).
fn archive_timestamp_imprint(
    doc_xml: &str,
    sig_id: &str,
    stop_before_ats_index: Option<usize>,
) -> Result<Vec<u8>> {
    let doc = XmlDoc::parse(doc_xml)?;
    let sig = find_element_by_id(doc.root(), sig_id)
        .with_context(|| format!("Signature Id={sig_id} not found for ArchiveTimeStamp imprint"))?;
    let si = find_child_ns(sig, XMLDSIG_NS, "SignedInfo")
        .context("SignedInfo missing for ArchiveTimeStamp imprint")?;

    let mut out = Vec::new();

    // Step 3: Reference data objects (already transformed), in SignedInfo order.
    for child in &si.children {
        let Node::Element(r) = child else {
            continue;
        };
        if r.local_name != "Reference" || r.namespace_uri != XMLDSIG_NS {
            continue;
        }
        let uri = get_attr(r, "URI").unwrap_or("");
        let transforms = collect_transform_uris(r);
        let octets = apply_reference_transforms(doc_xml, uri, &transforms)?;
        out.extend_from_slice(&octets);
    }

    // Step 4: SignedInfo, SignatureValue, KeyInfo (Exc-C14N).
    out.extend_from_slice(&xml_c14n::canonicalize_element_exc(si));
    let sv = find_child_ns(sig, XMLDSIG_NS, "SignatureValue")
        .context("SignatureValue missing for ArchiveTimeStamp imprint")?;
    out.extend_from_slice(&xml_c14n::canonicalize_element_exc(sv));
    if let Some(ki) = find_child_ns(sig, XMLDSIG_NS, "KeyInfo") {
        out.extend_from_slice(&xml_c14n::canonicalize_element_exc(ki));
    }

    // Step 5: UnsignedSignatureProperties children before the ATS under construction.
    if let Some(usp) = find_unsigned_signature_properties(sig) {
        let limit = stop_before_ats_index.unwrap_or(usp.children.len());
        for (i, child) in usp.children.iter().enumerate() {
            if i >= limit {
                break;
            }
            let Node::Element(el) = child else {
                continue;
            };
            out.extend_from_slice(&xml_c14n::canonicalize_element_exc(el));
        }
    }

    // Step 6: ds:Object elements except QualifyingProperties container.
    for child in &sig.children {
        let Node::Element(obj) = child else {
            continue;
        };
        if obj.local_name != "Object" || obj.namespace_uri != XMLDSIG_NS {
            continue;
        }
        let has_qp = obj.children.iter().any(|n| {
            matches!(
                n,
                Node::Element(e) if e.local_name == "QualifyingProperties"
            )
        });
        if has_qp {
            continue;
        }
        out.extend_from_slice(&xml_c14n::canonicalize_element_exc(obj));
    }

    Ok(out)
}

fn verify_archive_timestamps(doc_xml: &str, sig_id: &str) -> Result<Option<bool>> {
    let doc = XmlDoc::parse(doc_xml)?;
    let sig = find_element_by_id(doc.root(), sig_id)
        .with_context(|| format!("Signature Id={sig_id} not found"))?;
    let Some(usp) = find_unsigned_signature_properties(sig) else {
        return Ok(None);
    };
    let mut any = false;
    let mut all_ok = true;
    let mut ats_indices = Vec::new();
    for (i, child) in usp.children.iter().enumerate() {
        if let Node::Element(el) = child {
            if el.local_name == "ArchiveTimeStamp" {
                ats_indices.push(i);
            }
        }
    }
    if ats_indices.is_empty() {
        return Ok(None);
    }
    for &idx in &ats_indices {
        any = true;
        let Node::Element(ats) = &usp.children[idx] else {
            all_ok = false;
            continue;
        };
        let Some(encap) = find_desc_ns(ats, XADES_NS, "EncapsulatedTimeStamp")
            .or_else(|| find_child_local(ats, "EncapsulatedTimeStamp"))
        else {
            all_ok = false;
            continue;
        };
        let compact: String = element_text(encap).split_whitespace().collect();
        let token = match STANDARD.decode(compact.as_bytes()) {
            Ok(t) => t,
            Err(_) => {
                all_ok = false;
                continue;
            }
        };
        let info = match timestamp::parse_token(&token) {
            Ok(i) => i,
            Err(_) => {
                all_ok = false;
                continue;
            }
        };
        let imprint = match archive_timestamp_imprint(doc_xml, sig_id, Some(idx)) {
            Ok(i) => i,
            Err(_) => {
                all_ok = false;
                continue;
            }
        };
        let expected = match crate::cades::digest_by_oid(&info.digest_oid, &imprint) {
            Ok(d) => d,
            Err(_) => {
                all_ok = false;
                continue;
            }
        };
        if expected != info.message_imprint {
            all_ok = false;
            continue;
        }
        match timestamp::verify_token_signature(&token) {
            Ok(v) if v.is_valid() => {}
            _ => all_ok = false,
        }
    }
    Ok(if any { Some(all_ok) } else { None })
}

/// Replace (or create) `UnsignedProperties` under the signature's QualifyingProperties.
fn set_unsigned_signature_properties(
    doc_xml: &mut String,
    sig_id: &str,
    unsigned_inner: &str,
    xades_xlt1: bool,
) -> Result<()> {
    let mut root = parse_element(doc_xml)?;
    let sig = find_signature_by_id_mut(&mut root, sig_id)
        .with_context(|| format!("Signature Id={sig_id} not found"))?;
    let qp = ensure_qualifying_properties(sig, sig_id)?;
    qp.children.retain(|n| {
        !matches!(
            n,
            Node::Element(e) if e.local_name == "UnsignedProperties"
        )
    });
    let unsigned_xml = if xades_xlt1 {
        format!(
            r#"<xades:UnsignedProperties xmlns:xades="{XADES_NS}" xmlns:xades141="{XADES_141_NS}" xmlns:ds="{XMLDSIG_NS}"><xades:UnsignedSignatureProperties>{unsigned_inner}</xades:UnsignedSignatureProperties></xades:UnsignedProperties>"#
        )
    } else {
        format!(
            r#"<xades:UnsignedProperties xmlns:xades="{XADES_NS}" xmlns:ds="{XMLDSIG_NS}"><xades:UnsignedSignatureProperties>{unsigned_inner}</xades:UnsignedSignatureProperties></xades:UnsignedProperties>"#
        )
    };
    qp.children
        .push(Node::Element(parse_element(&unsigned_xml)?));
    *doc_xml = serialize_element(&root);
    Ok(())
}

/// Exc-C14N concatenation for SigAndRefsTimeStampV2 messageImprint, taken from
/// the live signature tree (ETSI EN 319 132-1: SignatureValue + SignatureTimeStamp
/// + CompleteCertificateRefs + CompleteRevocationRefs).
fn sig_and_refs_imprint(doc_xml: &str, sig_id: &str) -> Result<Vec<u8>> {
    let doc = XmlDoc::parse(doc_xml)?;
    let sig = find_element_by_id(doc.root(), sig_id)
        .with_context(|| format!("Signature Id={sig_id} not found for SigAndRefs imprint"))?;
    let sv = find_child_ns(sig, XMLDSIG_NS, "SignatureValue")
        .context("SignatureValue missing for SigAndRefs imprint")?;
    let usp = find_unsigned_signature_properties(sig)
        .context("UnsignedSignatureProperties missing for SigAndRefs imprint")?;
    let sts = find_child_local(usp, "SignatureTimeStamp")
        .context("SignatureTimeStamp missing for SigAndRefs imprint")?;
    let ccr = find_child_local(usp, "CompleteCertificateRefsV2")
        .context("CompleteCertificateRefsV2 missing for SigAndRefs imprint")?;
    let crr = find_child_local(usp, "CompleteRevocationRefs")
        .context("CompleteRevocationRefs missing for SigAndRefs imprint")?;
    let mut out = Vec::new();
    out.extend_from_slice(&xml_c14n::canonicalize_element_exc(sv));
    out.extend_from_slice(&xml_c14n::canonicalize_element_exc(sts));
    out.extend_from_slice(&xml_c14n::canonicalize_element_exc(ccr));
    out.extend_from_slice(&xml_c14n::canonicalize_element_exc(crr));
    Ok(out)
}

fn find_unsigned_signature_properties(sig: &Element) -> Option<&Element> {
    for child in &sig.children {
        let Node::Element(obj) = child else {
            continue;
        };
        if obj.local_name != "Object" || obj.namespace_uri != XMLDSIG_NS {
            continue;
        }
        for c2 in &obj.children {
            let Node::Element(qp) = c2 else {
                continue;
            };
            if qp.local_name != "QualifyingProperties" {
                continue;
            }
            for c3 in &qp.children {
                let Node::Element(up) = c3 else {
                    continue;
                };
                if up.local_name != "UnsignedProperties" {
                    continue;
                }
                return find_child_local(up, "UnsignedSignatureProperties");
            }
        }
    }
    None
}

fn find_child_local<'a>(el: &'a Element, local: &str) -> Option<&'a Element> {
    for child in &el.children {
        if let Node::Element(e) = child {
            if e.local_name == local {
                return Some(e);
            }
        }
    }
    None
}

fn tsa_digest_oid(curve_bytes: usize) -> Result<&'static str> {
    match curve_bytes {
        32 => Ok(crate::cades::OID_DIGEST_256),
        64 => Ok(crate::cades::OID_DIGEST_512),
        n => bail!("unsupported curve width for TSA: {n}"),
    }
}

/// Exc-C14N of the `ds:SignatureValue` element under `sig_id` (inherited ns kept).
fn signature_value_exc_c14n(doc_xml: &str, sig_id: &str) -> Result<Vec<u8>> {
    let doc = XmlDoc::parse(doc_xml)?;
    let sig = find_element_by_id(doc.root(), sig_id)
        .with_context(|| format!("Signature Id={sig_id} not found for SignatureValue C14N"))?;
    let sv = find_child_ns(sig, XMLDSIG_NS, "SignatureValue").context("SignatureValue missing")?;
    Ok(xml_c14n::canonicalize_element_exc(sv))
}

fn xades_timestamp_xml(local_name: &str, token: &[u8]) -> String {
    let b64 = base64_wrap_64(&STANDARD.encode(token));
    format!(
        r#"<xades:{local_name} xmlns:xades="{XADES_NS}" xmlns:ds="{XMLDSIG_NS}"><ds:CanonicalizationMethod Algorithm="{EXC_C14N_URI}"/><xades:EncapsulatedTimeStamp Encoding="{ENCAPSULATED_PKI_ENCODING}">{b64}</xades:EncapsulatedTimeStamp></xades:{local_name}>"#
    )
}

/// XAdES 1.4.1 timestamp property (`SigAndRefsTimeStampV2`): apex in xades141,
/// `EncapsulatedTimeStamp` stays in 1.3.2 (`xades:XAdESTimeStampType`).
fn xades141_timestamp_xml(local_name: &str, token: &[u8]) -> String {
    let b64 = base64_wrap_64(&STANDARD.encode(token));
    format!(
        r#"<xades141:{local_name} xmlns:xades141="{XADES_141_NS}" xmlns:xades="{XADES_NS}" xmlns:ds="{XMLDSIG_NS}"><ds:CanonicalizationMethod Algorithm="{EXC_C14N_URI}"/><xades:EncapsulatedTimeStamp Encoding="{ENCAPSULATED_PKI_ENCODING}">{b64}</xades:EncapsulatedTimeStamp></xades141:{local_name}>"#
    )
}

struct XadesXlParts {
    cert_refs: String,
    rev_refs: String,
    cert_vals: String,
    rev_vals: String,
}

fn build_xades_xl_parts(
    p: &SignXmlParams<'_>,
    materials: &[&validation::ValidationMaterial],
    extra_ref_certs: &[&[u8]],
) -> Result<XadesXlParts> {
    let mut seen_certs: Vec<Vec<u8>> = Vec::new();
    let mut cert_refs = String::new();
    let mut cert_vals_inner = String::new();

    let mut push_cert = |cert: &[u8], into_refs: bool| -> Result<()> {
        if seen_certs.iter().any(|c| c == cert) {
            return Ok(());
        }
        seen_certs.push(cert.to_vec());
        if into_refs {
            cert_refs.push_str(&cert_ref_xml(p, cert)?);
        }
        let b64 = STANDARD.encode(cert);
        cert_vals_inner.push_str(&format!(
            r#"<xades:EncapsulatedX509Certificate Encoding="{ENCAPSULATED_PKI_ENCODING}">{b64}</xades:EncapsulatedX509Certificate>"#
        ));
        Ok(())
    };

    // Leaf certs that must appear in CCR (TSA signers).
    for cert in extra_ref_certs {
        push_cert(cert, true)?;
    }
    for material in materials {
        for cert in &material.ca_chain {
            push_cert(cert, true)?;
        }
        // CryptoPro uses the delegated responder certificate while validating
        // BasicOCSPResponse offline and requires every such validation
        // certificate to participate in CompleteCertificateRefsV2. OCSP No
        // Check on the responder certificate avoids recursive revocation data.
        for cert in &material.signer_ocsp.embedded_certificates {
            push_cert(cert, true)?;
        }
    }

    let mut seen_ocsp: Vec<Vec<u8>> = Vec::new();
    let mut ocsp_refs = String::new();
    let mut ocsp_vals = String::new();
    for material in materials {
        // libxades parses xades:EncapsulatedOCSPValue as BasicOCSPResponse,
        // matching the CAdES revocationValues representation rather than the
        // full RFC 6960 OCSPResponse wrapper prescribed by ETSI.
        let resp = &material.signer_ocsp.basic_response;
        if seen_ocsp.iter().any(|r| r == resp) {
            continue;
        }
        seen_ocsp.push(resp.clone());
        ocsp_refs.push_str(&ocsp_ref_xml(p, &material.signer_ocsp)?);
        let b64 = STANDARD.encode(resp);
        ocsp_vals.push_str(&format!(
            r#"<xades:EncapsulatedOCSPValue Encoding="{ENCAPSULATED_PKI_ENCODING}">{b64}</xades:EncapsulatedOCSPValue>"#
        ));
    }

    let mut seen_crl: Vec<Vec<u8>> = Vec::new();
    let mut crl_refs = String::new();
    let mut crl_vals = String::new();
    for material in materials {
        for crl in &material.ca_crls {
            if seen_crl.iter().any(|c| c == crl) {
                continue;
            }
            seen_crl.push(crl.clone());
            crl_refs.push_str(&crl_ref_xml(p, crl)?);
            let b64 = STANDARD.encode(crl);
            crl_vals.push_str(&format!(
                r#"<xades:EncapsulatedCRLValue Encoding="{ENCAPSULATED_PKI_ENCODING}">{b64}</xades:EncapsulatedCRLValue>"#
            ));
        }
    }

    let mut rev_inner = String::new();
    if !crl_refs.is_empty() {
        rev_inner.push_str(&format!("<xades:CRLRefs>{crl_refs}</xades:CRLRefs>"));
    }
    if !ocsp_refs.is_empty() {
        rev_inner.push_str(&format!("<xades:OCSPRefs>{ocsp_refs}</xades:OCSPRefs>"));
    }

    Ok(XadesXlParts {
        // CryptoPro MakeXAdES_X_Long: CompleteCertificateRefsV2 + IssuerSerialV2 (xades 1.4.1).
        cert_refs: format!(
            r#"<xades141:CompleteCertificateRefsV2><xades141:CertRefs>{cert_refs}</xades141:CertRefs></xades141:CompleteCertificateRefsV2>"#
        ),
        // ETSI A.1.5.1 / libxades: CompleteRevocationRefs stays in 1.3.2 (non-V2).
        // XSD sequence: CRLRefs before OCSPRefs (omit empty wrappers).
        rev_refs: format!(
            r#"<xades:CompleteRevocationRefs>{rev_inner}</xades:CompleteRevocationRefs>"#
        ),
        cert_vals: format!(
            r#"<xades:CertificateValues>{cert_vals_inner}</xades:CertificateValues>"#
        ),
        rev_vals: {
            // XSD RevocationValuesType: CRLValues before OCSPValues.
            let mut inner = String::new();
            if !crl_vals.is_empty() {
                inner.push_str(&format!("<xades:CRLValues>{crl_vals}</xades:CRLValues>"));
            }
            if !ocsp_vals.is_empty() {
                inner.push_str(&format!("<xades:OCSPValues>{ocsp_vals}</xades:OCSPValues>"));
            }
            format!(r#"<xades:RevocationValues>{inner}</xades:RevocationValues>"#)
        },
    })
}

fn cert_ref_xml(p: &SignXmlParams<'_>, cert: &[u8]) -> Result<String> {
    let hash = crate::cades::digest_data(p.curve.bytes, cert)?;
    // CompleteCertificateRefsV2 and its locally declared CertRefs child are
    // XAdES 1.4.1. CertIDListV2Type itself is imported from XAdES 1.3.2, so
    // Cert/CertDigest/IssuerSerialV2 remain qualified in the 1.3.2 namespace.
    let issuer_serial_b64 = STANDARD.encode(issuer_serial_der_from_cert(cert)?);
    Ok(format!(
        r#"<xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="{dm}"/><ds:DigestValue>{h}</ds:DigestValue></xades:CertDigest><xades:IssuerSerialV2>{issuer_serial_b64}</xades:IssuerSerialV2></xades:Cert>"#,
        dm = xml_escape_attr(p.digest_method),
        h = STANDARD.encode(hash),
    ))
}

/// RFC 5035 `IssuerSerial` DER for any certificate (same encoding as SigningCertificateV2).
fn issuer_serial_der_from_cert(cert: &[u8]) -> Result<Vec<u8>> {
    let names = x509::names(cert)?;
    let general_names = cms_der::sequence(&[cms_der::tlv(0xA4, &names.issuer_der)]);
    Ok(cms_der::sequence(&[general_names, names.serial_der]))
}

/// DN string matching CryptoPro CSP / ocsputil display form used in XAdES
/// `OCSPIdentifier/ByName` (Cyrillic OID labels, `G=` not `GN=`, quoted STREET).
fn cryptopro_dn_from_attrs(attrs: &[x509::NameAttr]) -> String {
    let mapped: Vec<String> = attrs
        .iter()
        .map(|a| {
            let label = match a.oid.as_str() {
                "1.2.840.113549.1.9.1" => "E",
                "2.5.4.8" => "S",
                "2.5.4.9" => "STREET",
                "2.5.4.42" => "G",
                "1.2.643.100.1" => "OGRN",
                "1.2.643.100.3" => "SNILS",
                "1.2.643.100.5" => "OGRNIP",
                "1.2.643.3.131.1.1" => "INN",
                "1.2.643.100.4" => "INNLE",
                _ => a.label.as_str(),
            };
            let value = if a.oid == "2.5.4.9" && (a.value.contains(',') || a.value.contains('=')) {
                format!("\"{}\"", a.value.replace('"', r#"\""#))
            } else {
                a.value.clone()
            };
            format!("{label}={value}")
        })
        .collect();
    mapped.join(", ")
}

fn serial_decimal_from_der(serial_der: &[u8]) -> Result<String> {
    let t = crate::der::parse_tlv(serial_der).context("parse certificate serial INTEGER")?;
    if t.tag != 0x02 {
        bail!("certificate serial is not INTEGER");
    }
    let mut v = t.value;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    Ok(num_bigint::BigUint::from_bytes_be(v).to_string())
}

fn ocsp_ref_xml(p: &SignXmlParams<'_>, ev: &ocsp::OcspEvidence) -> Result<String> {
    // Digest must cover the same BasicOCSPResponse octets as the matching
    // xades:EncapsulatedOCSPValue.
    let hash = crate::cades::digest_data(p.curve.bytes, &ev.basic_response)?;
    let responder = ocsp_responder_id_xml(&ev.responder_id_der)?;
    let produced = ocsp_produced_at_xs(&ev.produced_at)?;
    Ok(format!(
        r#"<xades:OCSPRef><xades:OCSPIdentifier><xades:ResponderID>{responder}</xades:ResponderID><xades:ProducedAt>{produced}</xades:ProducedAt></xades:OCSPIdentifier><xades:DigestAlgAndValue><ds:DigestMethod Algorithm="{dm}"/><ds:DigestValue>{h}</ds:DigestValue></xades:DigestAlgAndValue></xades:OCSPRef>"#,
        dm = xml_escape_attr(p.digest_method),
        h = STANDARD.encode(hash),
    ))
}

fn ocsp_responder_id_xml(responder_id_der: &[u8]) -> Result<String> {
    let t = crate::der::parse_tlv(responder_id_der).context("parse OCSP ResponderID")?;
    match t.tag {
        0xA1 => {
            // [1] EXPLICIT Name → ByName
            let name_der = if t.value.first().copied() == Some(0x30) {
                t.value.to_vec()
            } else {
                crate::cms_der::tlv(0x30, t.value)
            };
            let attrs = x509::name_attributes(&name_der)?;
            Ok(format!(
                "<xades:ByName>{}</xades:ByName>",
                xml_escape_text(&cryptopro_dn_from_attrs(&attrs))
            ))
        }
        0xA2 => {
            // [2] EXPLICIT KeyHash → ByKey
            let inner = crate::der::parse_tlv(t.value).context("parse ResponderID KeyHash")?;
            let hash = if inner.tag == 0x04 {
                inner.value
            } else {
                t.value
            };
            Ok(format!(
                "<xades:ByKey>{}</xades:ByKey>",
                STANDARD.encode(hash)
            ))
        }
        _ => bail!("unsupported OCSP ResponderID tag 0x{:02X}", t.tag),
    }
}

fn ocsp_produced_at_xs(produced_at: &str) -> Result<String> {
    // OCSP GeneralizedTime YYYYMMDDHHMMSSZ → xs:dateTime.
    if produced_at.len() == 15 && produced_at.ends_with('Z') {
        Ok(format!(
            "{}-{}-{}T{}:{}:{}Z",
            &produced_at[0..4],
            &produced_at[4..6],
            &produced_at[6..8],
            &produced_at[8..10],
            &produced_at[10..12],
            &produced_at[12..14],
        ))
    } else {
        bail!("unsupported OCSP producedAt {produced_at:?}");
    }
}

fn crl_ref_xml(p: &SignXmlParams<'_>, crl: &[u8]) -> Result<String> {
    let hash = crate::cades::digest_data(p.curve.bytes, crl)?;
    let mut out = format!(
        r#"<xades:CRLRef><xades:DigestAlgAndValue><ds:DigestMethod Algorithm="{dm}"/><ds:DigestValue>{h}</ds:DigestValue></xades:DigestAlgAndValue>"#,
        dm = xml_escape_attr(p.digest_method),
        h = STANDARD.encode(hash),
    );
    if let Ok(ident) = crl_identifier_xml(crl) {
        out.push_str(&ident);
    }
    out.push_str("</xades:CRLRef>");
    Ok(out)
}

/// Optional `CRLIdentifier` (Issuer, IssueTime, Number) from CRL TBS fields.
fn crl_identifier_xml(crl: &[u8]) -> Result<String> {
    let parts = x509::crl_identifier_parts(crl)?;
    let attrs = x509::name_attributes(&parts.issuer_der)?;
    let issuer = cryptopro_dn_from_attrs(&attrs);
    let issue_time = asn1_time_to_xs_datetime(&parts.this_update_der)?;
    let mut inner = format!(
        "<xades:Issuer>{}</xades:Issuer><xades:IssueTime>{}</xades:IssueTime>",
        xml_escape_text(&issuer),
        xml_escape_text(&issue_time),
    );
    if let Some(num_der) = &parts.crl_number_der {
        inner.push_str(&format!(
            "<xades:Number>{}</xades:Number>",
            xml_escape_text(&serial_decimal_from_der(num_der)?)
        ));
    }
    Ok(format!(
        "<xades:CRLIdentifier>{inner}</xades:CRLIdentifier>"
    ))
}

/// UTCTime / GeneralizedTime TLV → `xs:dateTime` (`YYYY-MM-DDThh:mm:ssZ`).
fn asn1_time_to_xs_datetime(time_der: &[u8]) -> Result<String> {
    let t = crate::der::parse_tlv(time_der).context("parse ASN.1 Time")?;
    let s = std::str::from_utf8(t.value).context("ASN.1 Time is not ASCII")?;
    let (year, rest) = match t.tag {
        0x17 => {
            if s.len() != 13 || !s.ends_with('Z') {
                bail!("unsupported UTCTime {s:?}");
            }
            let yy: i32 = s[0..2].parse().context("UTCTime year")?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, &s[2..12])
        }
        0x18 => {
            if s.len() < 15 || !s.ends_with('Z') {
                bail!("unsupported GeneralizedTime {s:?}");
            }
            let year: i32 = s[0..4].parse().context("GeneralizedTime year")?;
            (year, &s[4..14])
        }
        _ => bail!("unsupported Time tag 0x{:02X}", t.tag),
    };
    Ok(format!(
        "{year:04}-{}-{}T{}:{}:{}Z",
        &rest[0..2],
        &rest[2..4],
        &rest[4..6],
        &rest[6..8],
        &rest[8..10],
    ))
}

fn xml_escape_text(s: &str) -> String {
    crate::xml_util::escape_text(s)
}

fn ensure_qualifying_properties<'a>(sig: &'a mut Element, sig_id: &str) -> Result<&'a mut Element> {
    // Locate existing Object/QualifyingProperties by path indices to avoid
    // overlapping mutable borrows.
    let mut found: Option<(usize, usize)> = None;
    for (oi, child) in sig.children.iter().enumerate() {
        if let Node::Element(obj) = child {
            if obj.local_name == "Object" && obj.namespace_uri == XMLDSIG_NS {
                for (qi, c2) in obj.children.iter().enumerate() {
                    if let Node::Element(qp) = c2 {
                        if qp.local_name == "QualifyingProperties" {
                            found = Some((oi, qi));
                            break;
                        }
                    }
                }
            }
        }
        if found.is_some() {
            break;
        }
    }
    if let Some((oi, qi)) = found {
        let Node::Element(obj) = &mut sig.children[oi] else {
            unreachable!();
        };
        let Node::Element(qp) = &mut obj.children[qi] else {
            unreachable!();
        };
        return Ok(qp);
    }

    let qp_xml = format!(
        "<ds:Object xmlns:ds=\"{ds}\"><xades:QualifyingProperties xmlns:xades=\"{xades}\" Target=\"#{sid}\"></xades:QualifyingProperties></ds:Object>",
        ds = XMLDSIG_NS,
        xades = XADES_NS,
        sid = sig_id,
    );
    let obj = parse_element(&qp_xml)?;
    sig.children.push(Node::Element(obj));
    let Node::Element(obj) = sig.children.last_mut().unwrap() else {
        unreachable!();
    };
    let Node::Element(qp) = obj.children.last_mut().unwrap() else {
        bail!("QualifyingProperties missing after insert");
    };
    Ok(qp)
}

// ── verification helpers ───────────────────────────────────────────────────

fn verify_references(full_xml: &str, sig_el: &Element, digest_bytes: usize) -> Result<bool> {
    let si = find_child_ns(sig_el, XMLDSIG_NS, "SignedInfo").context("SignedInfo missing")?;
    let mut all_ok = true;
    for child in &si.children {
        if let Node::Element(r) = child {
            if r.local_name != "Reference" || r.namespace_uri != XMLDSIG_NS {
                continue;
            }
            let uri = get_attr(r, "URI").unwrap_or("");
            let transforms = collect_transform_uris(r);
            let octets = apply_reference_transforms(full_xml, uri, &transforms)?;
            let dm = find_child_ns(r, XMLDSIG_NS, "DigestMethod")
                .and_then(|e| get_attr(e, "Algorithm"))
                .unwrap_or("");
            let width = if dm.is_empty() {
                digest_bytes
            } else {
                digest_size_for_uri(dm)?
            };
            let expected = crate::cades::digest_data(width, &octets)?;
            let dv = find_child_ns(r, XMLDSIG_NS, "DigestValue")
                .map(element_text)
                .unwrap_or_default();
            let dv = dv.split_whitespace().collect::<String>();
            let got = STANDARD
                .decode(dv.as_bytes())
                .context("decode DigestValue base64")?;
            if got != expected {
                all_ok = false;
            }
        }
    }
    Ok(all_ok)
}

fn apply_reference_transforms(full_xml: &str, uri: &str, transforms: &[String]) -> Result<Vec<u8>> {
    const INCLUSIVE_C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    let mut has_enveloped = false;
    let mut use_exclusive = false;
    let mut use_inclusive = false;
    for t in transforms {
        if t.is_empty() {
            continue;
        } else if t == ENVELOPED_TRANSFORM_URI {
            has_enveloped = true;
        } else if t == EXC_C14N_URI {
            use_exclusive = true;
        } else if t == INCLUSIVE_C14N {
            use_inclusive = true;
        } else {
            bail!("unsupported XML-DSig Transform Algorithm: {t}");
        }
    }
    // XML-DSig Core §4.3.3.2: node-set → octets defaults to Canonical XML
    // (Inclusive) when no C14N Transform is listed. CryptoPro XAdES-BES
    // SignedProperties References omit Transforms.
    if !use_exclusive && !use_inclusive {
        use_inclusive = true;
    }

    // Apply enveloped-signature first (CryptoPro order: enveloped then C14N).
    // Work in a parsed tree so Id targets keep ancestor xmlns (Signature default
    // ns, QualifyingProperties XAdES ns). serialize→reparse loses those decls.
    let working_xml;
    let xml_for_parse = if has_enveloped {
        working_xml = xml_c14n::enveloped_signature_remove(full_xml)?;
        working_xml.as_str()
    } else {
        full_xml
    };

    let doc = XmlDoc::parse(xml_for_parse)?;
    let el = if uri.is_empty() {
        doc.root()
    } else {
        let id = uri.strip_prefix('#').unwrap_or(uri);
        find_element_by_id(doc.root(), id).with_context(|| {
            format!(
                "Reference URI target #{id} not found{}",
                if has_enveloped {
                    " after enveloped-signature"
                } else {
                    ""
                }
            )
        })?
    };
    if use_exclusive {
        Ok(xml_c14n::canonicalize_element_exc(el))
    } else {
        Ok(xml_c14n::canonicalize_element_inclusive(el))
    }
}

fn canonicalize_signed_info(full_xml: &str, sig_el: &Element) -> Result<Vec<u8>> {
    let si = find_child_ns(sig_el, XMLDSIG_NS, "SignedInfo").context("SignedInfo missing")?;
    // Prefer Id-based C14N when SignedInfo carries Id.
    if let Some(id) = get_attr(si, "Id") {
        let doc = XmlDoc::parse(full_xml)?;
        return doc.canonicalize_node(Some(id));
    }
    // Prefer document-context element (inherited xmlns) over serialize→reparse.
    if let Some(sig_id) = get_attr(sig_el, "Id") {
        let doc = XmlDoc::parse(full_xml)?;
        if let Some(sig) = find_element_by_id(doc.root(), sig_id) {
            if let Some(si2) = find_child_ns(sig, XMLDSIG_NS, "SignedInfo") {
                return Ok(xml_c14n::canonicalize_element_exc(si2));
            }
        }
    }
    Ok(xml_c14n::canonicalize_element_exc(si))
}

fn signature_value_bytes(sig_el: &Element) -> Result<Vec<u8>> {
    let sv =
        find_child_ns(sig_el, XMLDSIG_NS, "SignatureValue").context("SignatureValue missing")?;
    let text = element_text(sv);
    let compact: String = text.split_whitespace().collect();
    STANDARD
        .decode(compact.as_bytes())
        .context("decode SignatureValue base64")
}

/// Verify XAdES `SignatureTimeStamp` when present.
///
/// Returns `Ok(None)` if absent, `Ok(Some(true/false))` when present.
/// messageImprint must match Exc-C14N(`ds:SignatureValue`); token CMS signature
/// is checked via [`timestamp::verify_token_signature`].
fn verify_signature_timestamp(sig_el: &Element) -> Result<Option<bool>> {
    let Some(sts) = find_desc_ns(sig_el, XADES_NS, "SignatureTimeStamp") else {
        return Ok(None);
    };
    let Some(encap) = find_desc_ns(sts, XADES_NS, "EncapsulatedTimeStamp") else {
        return Ok(Some(false));
    };
    let text = element_text(encap);
    let compact: String = text.split_whitespace().collect();
    let token = match STANDARD.decode(compact.as_bytes()) {
        Ok(t) => t,
        Err(_) => return Ok(Some(false)),
    };
    let Some(sv) = find_child_ns(sig_el, XMLDSIG_NS, "SignatureValue") else {
        return Ok(Some(false));
    };
    let c14n = xml_c14n::canonicalize_element_exc(sv);
    let info = match timestamp::parse_token(&token) {
        Ok(i) => i,
        Err(_) => return Ok(Some(false)),
    };
    let expected = match crate::cades::digest_by_oid(&info.digest_oid, &c14n) {
        Ok(d) => d,
        Err(_) => return Ok(Some(false)),
    };
    if expected != info.message_imprint {
        return Ok(Some(false));
    }
    match timestamp::verify_token_signature(&token) {
        Ok(v) => Ok(Some(v.is_valid())),
        Err(_) => Ok(Some(false)),
    }
}

fn verify_sig_and_refs_timestamp(doc_xml: &str, sig_id: &str) -> Result<Option<bool>> {
    let doc = XmlDoc::parse(doc_xml)?;
    let sig = find_element_by_id(doc.root(), sig_id)
        .with_context(|| format!("Signature Id={sig_id} not found"))?;
    let Some(sar) = find_desc_ns(sig, XADES_141_NS, "SigAndRefsTimeStampV2") else {
        return Ok(None);
    };
    let Some(encap) = find_desc_ns(sar, XADES_NS, "EncapsulatedTimeStamp") else {
        return Ok(Some(false));
    };
    let compact: String = element_text(encap).split_whitespace().collect();
    let token = match STANDARD.decode(compact.as_bytes()) {
        Ok(t) => t,
        Err(_) => return Ok(Some(false)),
    };
    let info = match timestamp::parse_token(&token) {
        Ok(i) => i,
        Err(_) => return Ok(Some(false)),
    };
    let imprint_input = sig_and_refs_imprint(doc_xml, sig_id)?;
    let expected = crate::cades::digest_by_oid(&info.digest_oid, &imprint_input)?;
    if expected != info.message_imprint {
        return Ok(Some(false));
    }
    Ok(Some(timestamp::verify_token_signature(&token)?.is_valid()))
}

fn extract_certificate(sig_el: &Element) -> Result<Option<Vec<u8>>> {
    let Some(cert_el) = find_desc_ns(sig_el, XMLDSIG_NS, "X509Certificate") else {
        return Ok(None);
    };
    let text = element_text(cert_el);
    let compact: String = text.split_whitespace().collect();
    let der = STANDARD
        .decode(compact.as_bytes())
        .context("decode X509Certificate base64")?;
    Ok(Some(der))
}

fn reference_digest_method(si: &Element) -> Option<&str> {
    for child in &si.children {
        if let Node::Element(r) = child {
            if r.local_name == "Reference" {
                if let Some(dm) = find_child_ns(r, XMLDSIG_NS, "DigestMethod") {
                    return get_attr(dm, "Algorithm");
                }
            }
        }
    }
    None
}

fn collect_transform_uris(reference: &Element) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(transforms) = find_child_ns(reference, XMLDSIG_NS, "Transforms") {
        for child in &transforms.children {
            if let Node::Element(t) = child {
                if t.local_name == "Transform" {
                    if let Some(a) = get_attr(t, "Algorithm") {
                        out.push(a.to_string());
                    }
                }
            }
        }
    }
    out
}

// ── DOM / xpath helpers ────────────────────────────────────────────────────

fn digest_size_for_uri(uri: &str) -> Result<usize> {
    if uri == DIGEST_METHOD_512
        || uri == SIGNATURE_METHOD_512
        || uri.ends_with("12012-512")
        || uri.ends_with("3411-512")
        || uri.contains("gostr34112012-512")
    {
        return Ok(64);
    }
    if uri == DIGEST_METHOD_256
        || uri == SIGNATURE_METHOD_256
        || uri.ends_with("12012-256")
        || uri.contains("gostr34112012-256")
        || uri.contains("gostr3411")
    {
        return Ok(32);
    }
    bail!("unsupported XML digest/signature method URI: {uri}");
}

fn xs_datetime_utc_now() -> Result<String> {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // Reuse civil conversion via UTCTime helper body pattern.
    let (y, mon, d, h, mi, s) = civil_from_unix(unix);
    Ok(format!("{y:04}-{mon:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z"))
}

fn civil_from_unix(unix: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = unix.div_euclid(86_400);
    let rem = unix.rem_euclid(86_400) as u32;
    let h = rem / 3600;
    let mi = (rem % 3600) / 60;
    let s = rem % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, s)
}

fn xml_escape_attr(s: &str) -> String {
    crate::xml_util::escape_attr(s)
}

fn element_text(el: &Element) -> String {
    let mut out = String::new();
    for c in &el.children {
        if let Node::Text(t) = c {
            out.push_str(t);
        }
    }
    out
}

fn set_text(el: &mut Element, text: &str) {
    el.children = vec![Node::Text(text.to_string())];
}

fn set_attr(el: &mut Element, local_name: &str, value: &str) {
    if let Some(a) = el.attrs.iter_mut().find(|a| a.local_name == local_name) {
        a.value = value.to_string();
    } else {
        el.attrs.push(crate::xml_util::Attr {
            prefix: None,
            local_name: local_name.to_string(),
            namespace_uri: String::new(),
            value: value.to_string(),
        });
    }
}

fn find_child_ns<'a>(el: &'a Element, ns: &str, local: &str) -> Option<&'a Element> {
    el.children.iter().find_map(|n| match n {
        Node::Element(e) if e.local_name == local && e.namespace_uri == ns => Some(e),
        _ => None,
    })
}

fn find_child_ns_mut<'a>(el: &'a mut Element, ns: &str, local: &str) -> Option<&'a mut Element> {
    el.children.iter_mut().find_map(|n| match n {
        Node::Element(e) if e.local_name == local && e.namespace_uri == ns => Some(e),
        _ => None,
    })
}

fn find_desc_ns<'a>(el: &'a Element, ns: &str, local: &str) -> Option<&'a Element> {
    if el.local_name == local && el.namespace_uri == ns {
        return Some(el);
    }
    for c in &el.children {
        if let Node::Element(e) = c {
            if let Some(f) = find_desc_ns(e, ns, local) {
                return Some(f);
            }
        }
    }
    None
}

fn find_signature_by_id_mut<'a>(root: &'a mut Element, id: &str) -> Option<&'a mut Element> {
    find_signature_by_id_mut_rec(root, id)
}

fn find_signature_by_id_mut_rec<'a>(el: &'a mut Element, id: &str) -> Option<&'a mut Element> {
    if el.local_name == "Signature"
        && el.namespace_uri == XMLDSIG_NS
        && get_attr(el, "Id") == Some(id)
    {
        return Some(el);
    }
    for c in el.children.iter_mut() {
        if let Node::Element(e) = c {
            if let Some(f) = find_signature_by_id_mut_rec(e, id) {
                return Some(f);
            }
        }
    }
    None
}

fn select_signature_mut<'a>(
    root: &'a mut Element,
    xpath: Option<&str>,
) -> Result<Option<&'a mut Element>> {
    let xpath = xpath.unwrap_or(
        "//*[local-name()='Signature' and namespace-uri()='http://www.w3.org/2000/09/xmldsig#']",
    );
    let paths = find_signatures_matching(root, xpath);
    if paths.is_empty() {
        return Ok(None);
    }
    let path = paths[0].clone();
    Ok(element_at_path_mut(root, &path))
}

/// Minimal XPath: `//* [local-name()='Signature' and namespace-uri()='...' and (count(*[local-name()='SignatureValue'])=0 or *[local-name()='SignatureValue']='')]`
fn find_template_signatures(root: &Element, xpath: &str) -> Vec<Vec<usize>> {
    find_signatures_matching(root, xpath)
}

fn find_signatures_matching(root: &Element, xpath: &str) -> Vec<Vec<usize>> {
    let want_empty_sv = xpath.contains("SignatureValue");
    let mut out = Vec::new();
    walk_collect_signatures(root, &mut Vec::new(), want_empty_sv, &mut out);
    out
}

fn walk_collect_signatures(
    el: &Element,
    path: &mut Vec<usize>,
    want_empty_sv: bool,
    out: &mut Vec<Vec<usize>>,
) {
    if el.local_name == "Signature" && el.namespace_uri == XMLDSIG_NS {
        let sv = find_child_ns(el, XMLDSIG_NS, "SignatureValue");
        let empty = match sv {
            None => true,
            Some(e) => element_text(e).trim().is_empty(),
        };
        if !want_empty_sv || empty {
            out.push(path.clone());
        }
    }
    for (i, c) in el.children.iter().enumerate() {
        if let Node::Element(e) = c {
            path.push(i);
            walk_collect_signatures(e, path, want_empty_sv, out);
            path.pop();
        }
    }
}

fn element_at_path_mut<'a>(root: &'a mut Element, path: &[usize]) -> Option<&'a mut Element> {
    if path.is_empty() {
        return Some(root);
    }
    let mut cur = root;
    for (depth, &idx) in path.iter().enumerate() {
        let child = cur.children.get_mut(idx)?;
        match child {
            Node::Element(e) => {
                if depth + 1 == path.len() {
                    return Some(e);
                }
                cur = e;
            }
            _ => return None,
        }
    }
    None
}

// ── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn fake_gost_certificate(curve: &curves::Curve, x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut xy = x.to_vec();
        xy.extend_from_slice(y);
        let public_key_alg = cms_der::sequence(&[
            cms_der::oid("1.2.643.7.1.1.1.1").unwrap(),
            cms_der::sequence(&[
                cms_der::oid(curve.oid).unwrap(),
                cms_der::oid(crate::cades::OID_DIGEST_256).unwrap(),
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
            cms_der::algorithm_identifier(crate::cades::OID_SIGN_256).unwrap(),
            empty_name.clone(),
            cms_der::sequence(&[]),
            empty_name,
            spki,
        ]);
        cms_der::sequence(&[
            tbs,
            cms_der::algorithm_identifier(crate::cades::OID_SIGN_256).unwrap(),
            cms_der::bit_string(&[0u8; 64]),
        ])
    }

    #[test]
    fn enveloped_sign_verify_roundtrip() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(4242424242u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let cert = fake_gost_certificate(&curve, &x, &y);
        let content = r#"<doc><body>xml-dsig gost roundtrip</body></doc>"#;
        let signed = sign_xml(&SignXmlParams {
            content,
            cert_der: &cert,
            curve: &curve,
            private_le: &private,
            public_x_le: &x,
            public_y_le: &y,
            signature_type: XmlSignatureType::Enveloped,
            digest_method: DIGEST_METHOD_256,
            signature_method: SIGNATURE_METHOD_256,
            xpath: None,
            xades_flags: XADES_NONE,
            tsa_url: None,
            tsa_policy: None,
            tsa_timeout_secs: 5,
        })
        .unwrap();
        assert!(signed.contains("SignatureValue"));
        assert!(signed.contains("gostr34102012-gostr34112012-256"));
        let v = verify_xml(&signed, None).unwrap();
        assert!(v.references_valid, "references must verify");
        assert!(v.signature_valid, "signature must verify");
        assert!(v.ok);
        assert!(v.certificate_der.is_some());
    }

    #[test]
    fn enveloped_xades_bes_roundtrip() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(135791113u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let cert = fake_gost_certificate(&curve, &x, &y);
        let content = r#"<root xmlns="urn:test"><item>bes</item></root>"#;
        let signed = sign_xml(&SignXmlParams {
            content,
            cert_der: &cert,
            curve: &curve,
            private_le: &private,
            public_x_le: &x,
            public_y_le: &y,
            signature_type: XmlSignatureType::Enveloped,
            digest_method: DIGEST_METHOD_256,
            signature_method: SIGNATURE_METHOD_256,
            xpath: None,
            xades_flags: XADES_BES,
            tsa_url: None,
            tsa_policy: None,
            tsa_timeout_secs: 5,
        })
        .unwrap();
        assert!(signed.contains("SignedProperties"));
        assert!(signed.contains("SigningCertificateV2"));
        let v = verify_xml(&signed, None).unwrap();
        assert!(v.ok, "XAdES-BES references+signature must verify");
    }

    #[test]
    fn archive_timestamp_requires_xlt1_base() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(2468101214u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let cert = fake_gost_certificate(&curve, &x, &y);
        let content = r#"<root xmlns="urn:test"><item>no-archive-yet</item></root>"#;
        let mut signed = sign_xml(&SignXmlParams {
            content,
            cert_der: &cert,
            curve: &curve,
            private_le: &private,
            public_x_le: &x,
            public_y_le: &y,
            signature_type: XmlSignatureType::Enveloped,
            digest_method: DIGEST_METHOD_256,
            signature_method: SIGNATURE_METHOD_256,
            xpath: None,
            xades_flags: XADES_BES,
            tsa_url: None,
            tsa_policy: None,
            tsa_timeout_secs: 5,
        })
        .unwrap();
        let err = add_archive_timestamp_xml(
            &mut signed,
            Some("Signature-jex"),
            "http://example.invalid/tsp",
            None,
            5,
            crate::cades::OID_DIGEST_256,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("XLT1") || msg.contains("XAdES-A"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn archive_timestamp_uses_xades_141_namespace() {
        let mut xml = format!(
            r#"<root><ds:Signature xmlns:ds="{XMLDSIG_NS}" Id="Signature-jex"><ds:Object><xades:QualifyingProperties xmlns:xades="{XADES_NS}"><xades:UnsignedProperties><xades:UnsignedSignatureProperties/></xades:UnsignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature></root>"#
        );
        append_archive_timestamp_property(&mut xml, "Signature-jex", &[1, 2, 3]).unwrap();
        let doc = XmlDoc::parse(&xml).unwrap();
        let sig = find_element_by_id(doc.root(), "Signature-jex").unwrap();
        let usp = find_unsigned_signature_properties(sig).unwrap();
        let ats = usp
            .children
            .iter()
            .find_map(|node| match node {
                Node::Element(el) if el.local_name == "ArchiveTimeStamp" => Some(el),
                _ => None,
            })
            .unwrap();
        assert_eq!(ats.namespace_uri, XADES_141_NS);
        assert!(find_desc_ns(ats, XADES_NS, "EncapsulatedTimeStamp").is_some());
    }

    #[test]
    fn archive_timestamp_imprint_is_stable_on_fixture() {
        // Minimal enveloped-like tree with XLT1 unsigned markers (no real crypto).
        let xml = r##"<?xml version="1.0"?>
<root xmlns="urn:test"><item>x</item>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-jex">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256"/>
    <ds:Reference URI="">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256"/>
      <ds:DigestValue>AA==</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>AA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  <ds:Object>
    <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" xmlns:xades141="http://uri.etsi.org/01903/v1.4.1#" Target="#Signature-jex">
      <xades:UnsignedProperties>
        <xades:UnsignedSignatureProperties>
          <xades:SignatureTimeStamp><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><xades:EncapsulatedTimeStamp Encoding="http://uri.etsi.org/01903/v1.2.2#DER">AA==</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>
          <xades141:CompleteCertificateRefsV2><xades141:CertRefs/></xades141:CompleteCertificateRefsV2>
          <xades:CompleteRevocationRefs/>
          <xades141:SigAndRefsTimeStampV2><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><xades:EncapsulatedTimeStamp Encoding="http://uri.etsi.org/01903/v1.2.2#DER">AA==</xades:EncapsulatedTimeStamp></xades141:SigAndRefsTimeStampV2>
          <xades:CertificateValues/>
          <xades:RevocationValues/>
        </xades:UnsignedSignatureProperties>
      </xades:UnsignedProperties>
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature>
</root>"##;
        let a = archive_timestamp_imprint(xml, "Signature-jex", None).unwrap();
        let b = archive_timestamp_imprint(xml, "Signature-jex", None).unwrap();
        assert_eq!(a, b);
        assert!(!a.is_empty());
        // Before first unsigned prop → shorter imprint than full USP.
        let early = archive_timestamp_imprint(xml, "Signature-jex", Some(0)).unwrap();
        assert!(early.len() < a.len());
    }

    #[test]
    fn enveloping_sign_verify_roundtrip() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(777888999u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let cert = fake_gost_certificate(&curve, &x, &y);
        let content = r#"<payload>enveloping</payload>"#;
        let signed = sign_xml(&SignXmlParams {
            content,
            cert_der: &cert,
            curve: &curve,
            private_le: &private,
            public_x_le: &x,
            public_y_le: &y,
            signature_type: XmlSignatureType::Enveloping,
            digest_method: DIGEST_METHOD_256,
            signature_method: SIGNATURE_METHOD_256,
            xpath: None,
            xades_flags: XADES_NONE,
            tsa_url: None,
            tsa_policy: None,
            tsa_timeout_secs: 5,
        })
        .unwrap();
        assert!(signed.contains("Signature") || signed.contains(":Signature"));
        assert!(signed.contains("Object-jex"));
        // CryptoPro-style plain enveloping: default xmlns, no ds: prefix.
        assert!(
            signed.contains(r#"xmlns="http://www.w3.org/2000/09/xmldsig#""#)
                || signed.contains("xmlns:ds="),
            "signature must declare xmldsig namespace"
        );
        let v = verify_xml(&signed, None).unwrap();
        assert!(v.ok);
    }

    #[test]
    fn template_sign_verify_roundtrip() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(314159265u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let cert = fake_gost_certificate(&curve, &x, &y);
        // Pre-built template with empty DigestValue/SignatureValue and no KeyInfo.
        let template = format!(
            concat!(
                "<doc><ds:Signature xmlns:ds=\"{ds}\" Id=\"Signature-jex\">",
                "<ds:SignedInfo>",
                "<ds:CanonicalizationMethod Algorithm=\"{c14n}\"/>",
                "<ds:SignatureMethod Algorithm=\"{sm}\"/>",
                "<ds:Reference URI=\"\">",
                "<ds:Transforms>",
                "<ds:Transform Algorithm=\"{env}\"/>",
                "<ds:Transform Algorithm=\"{c14n}\"/>",
                "</ds:Transforms>",
                "<ds:DigestMethod Algorithm=\"{dm}\"/>",
                "<ds:DigestValue></ds:DigestValue>",
                "</ds:Reference>",
                "</ds:SignedInfo>",
                "<ds:SignatureValue></ds:SignatureValue>",
                "</ds:Signature></doc>",
            ),
            ds = XMLDSIG_NS,
            c14n = EXC_C14N_URI,
            sm = SIGNATURE_METHOD_256,
            env = ENVELOPED_TRANSFORM_URI,
            dm = DIGEST_METHOD_256,
        );
        let signed = sign_xml(&SignXmlParams {
            content: &template,
            cert_der: &cert,
            curve: &curve,
            private_le: &private,
            public_x_le: &x,
            public_y_le: &y,
            signature_type: XmlSignatureType::Template,
            digest_method: DIGEST_METHOD_256,
            signature_method: SIGNATURE_METHOD_256,
            xpath: None,
            xades_flags: XADES_NONE,
            tsa_url: None,
            tsa_policy: None,
            tsa_timeout_secs: 5,
        })
        .unwrap();
        assert!(signed.contains("X509Certificate"));
        let v = verify_xml(&signed, None).unwrap();
        assert!(v.ok);
    }

    #[test]
    fn algorithm_uri_helpers() {
        assert_eq!(digest_method_uri(32).unwrap(), DIGEST_METHOD_256);
        assert_eq!(signature_method_uri(64).unwrap(), SIGNATURE_METHOD_512);
    }

    #[test]
    fn xlt1_references_delegated_ocsp_responder_certificate() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(2026082914u64);
        let public = curves::public_key(&curve, &d).unwrap();
        let x = curves::le_fixed(&public.x, curve.bytes);
        let y = curves::le_fixed(&public.y, curve.bytes);
        let responder_cert = fake_gost_certificate(&curve, &x, &y);
        let private = curves::le_fixed(&d, curve.bytes);
        let material = validation::ValidationMaterial {
            ca_chain: Vec::new(),
            signer_ocsp: ocsp::OcspEvidence {
                basic_response: cms_der::sequence(&[]),
                full_response: Vec::new(),
                responder_id_der: cms_der::tlv(0xA2, &cms_der::octet_string(&[0x42; 20])),
                produced_at_der: Vec::new(),
                produced_at: "20260829220000Z".to_string(),
                this_update: "20260829220000Z".to_string(),
                this_update_unix: 0,
                next_update: None,
                embedded_certificates: vec![responder_cert.clone()],
            },
            ca_crls: Vec::new(),
        };
        let params = SignXmlParams {
            content: "<Document/>",
            cert_der: &responder_cert,
            curve: &curve,
            private_le: &private,
            public_x_le: &x,
            public_y_le: &y,
            signature_type: XmlSignatureType::Enveloped,
            digest_method: DIGEST_METHOD_256,
            signature_method: SIGNATURE_METHOD_256,
            xpath: None,
            xades_flags: XADES_XLT1,
            tsa_url: None,
            tsa_policy: None,
            tsa_timeout_secs: 5,
        };

        let parts = build_xades_xl_parts(&params, &[&material], &[]).unwrap();
        let responder_digest =
            STANDARD.encode(crate::cades::digest_data(curve.bytes, &responder_cert).unwrap());
        assert!(parts.cert_refs.contains(&format!(
            "<ds:DigestValue>{responder_digest}</ds:DigestValue>"
        )));
        assert!(parts.cert_vals.contains(&STANDARD.encode(&responder_cert)));
    }

    #[test]
    fn verify_nmcades_enveloped_golden() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/xmldsig/nmcades_enveloped.xml"
        );
        // Golden files are produced with a real CryptoPro certificate and are
        // kept out of the public tree; skip when they are not present.
        let Ok(signed) = std::fs::read_to_string(path) else {
            eprintln!("skip: {path} not present");
            return;
        };
        let v = verify_xml(&signed, None).expect("verify_xml");
        assert!(
            v.references_valid,
            "nmcades golden: DigestValue / reference transforms must match (got signature_valid={})",
            v.signature_valid
        );
        assert!(
            v.signature_valid,
            "nmcades golden: SignatureValue over SignedInfo Exc-C14N must verify (got references_valid={})",
            v.references_valid
        );
        assert!(v.ok);
        assert!(v.certificate_der.is_some());
    }

    fn assert_nmcades_golden(rel: &str) {
        let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
        let Ok(signed) = std::fs::read_to_string(&path) else {
            eprintln!("skip: {path} not present");
            return;
        };
        let v = verify_xml(&signed, None).unwrap_or_else(|e| panic!("verify_xml {path}: {e}"));
        assert!(
            v.references_valid,
            "{rel}: references failed (signature_valid={})",
            v.signature_valid
        );
        assert!(
            v.signature_valid,
            "{rel}: signature failed (references_valid={})",
            v.references_valid
        );
        assert!(v.ok, "{rel}: verify not ok");
        assert!(v.certificate_der.is_some(), "{rel}: missing certificate");
    }

    #[test]
    fn verify_nmcades_enveloping_golden() {
        assert_nmcades_golden("testdata/xmldsig/nmcades_enveloping.xml");
    }

    #[test]
    fn verify_nmcades_template_golden() {
        assert_nmcades_golden("testdata/xmldsig/nmcades_template.xml");
    }

    #[test]
    fn verify_nmcades_xades_bes_golden() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/xmldsig/nmcades_xades_bes.xml"
        );
        let Ok(signed) = std::fs::read_to_string(path) else {
            eprintln!("skip: {path} not present");
            return;
        };
        assert!(
            signed.contains("SignedProperties"),
            "XAdES-BES golden must embed SignedProperties"
        );
        let v = verify_xml(&signed, None).expect("verify_xml xades-bes");
        assert!(
            v.references_valid,
            "nmcades XAdES-BES: SignedProperties/document DigestValue mismatch (signature_valid={})",
            v.signature_valid
        );
        assert!(
            v.signature_valid,
            "nmcades XAdES-BES: SignatureValue failed (references_valid={})",
            v.references_valid
        );
        assert!(v.ok);
        assert!(v.certificate_der.is_some());
    }

    /// Writes a jex-signed enveloped fixture for nmcades reverse Verify.
    /// Run: `cargo test export_jex_enveloped_for_nmcades -- --nocapture`
    #[test]
    fn export_jex_enveloped_for_nmcades() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(2026082912u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let cert = fake_gost_certificate(&curve, &x, &y);
        // Same minimal document as nmcades golden harness.
        let content = r#"<?xml version="1.0"?><Document><Body>golden</Body></Document>"#;
        let signed = sign_xml(&SignXmlParams {
            content,
            cert_der: &cert,
            curve: &curve,
            private_le: &private,
            public_x_le: &x,
            public_y_le: &y,
            signature_type: XmlSignatureType::Enveloped,
            digest_method: DIGEST_METHOD_256,
            signature_method: SIGNATURE_METHOD_256,
            xpath: None,
            xades_flags: XADES_NONE,
            tsa_url: None,
            tsa_policy: None,
            tsa_timeout_secs: 5,
        })
        .expect("sign enveloped");
        let v = verify_xml(&signed, None).expect("self-verify");
        assert!(v.ok, "jex must self-verify before exporting");
        // CryptoPro plain enveloped style: default xmlns, no ds: prefix.
        assert!(
            signed.contains(r#"xmlns="http://www.w3.org/2000/09/xmldsig#""#),
            "expected CryptoPro-style default xmldsig xmlns"
        );
        assert!(
            !signed.contains("<ds:Signature"),
            "plain XMLDSIG must not use ds: prefix"
        );
        let out = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/xmldsig/jex_enveloped_synthetic.xml"
        );
        std::fs::write(
            out,
            if signed.ends_with('\n') {
                signed.clone()
            } else {
                format!("{signed}\n")
            },
        )
        .expect("write fixture");
        eprintln!("Wrote {out} ({} bytes)", signed.len());
    }

    /// Optional: sign with dumped `roman/` container when `JEX_CONTAINER_PIN` or
    /// `JEX_CONTAINER_PIN_FILE` is set (never prints the PIN).
    #[test]
    fn export_jex_enveloped_from_roman_container() {
        use zeroize::Zeroize;
        // Allow empty PIN (var set to "") — some classic containers use blank PIN.
        let pin = match std::env::var("JEX_CONTAINER_PIN") {
            Ok(s) => Some(s),
            Err(_) => std::env::var("JEX_CONTAINER_PIN_FILE")
                .ok()
                .and_then(|path| {
                    std::fs::read_to_string(path)
                        .ok()
                        .map(|s| s.trim_end_matches('\n').to_string())
                }),
        };
        let Some(mut pin) = pin else {
            eprintln!(
                "skip: set JEX_CONTAINER_PIN or JEX_CONTAINER_PIN_FILE to export roman fixture"
            );
            return;
        };
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/roman");
        let c = crate::container::ClassicContainer::open(std::path::Path::new(dir))
            .expect("open roman container");
        let mut key = c.unlock(pin.as_bytes()).expect("unlock roman container");
        pin.zeroize();
        let cert = c.certificate.as_ref().expect("roman cert").clone();
        let identity = x509::identity(&cert).expect("parse cert");
        let curve = curves::by_oid(&identity.curve_oid).expect("curve");
        let content = r#"<?xml version="1.0"?><Document><Body>golden</Body></Document>"#;
        let signed = sign_xml(&SignXmlParams {
            content,
            cert_der: &cert,
            curve: &curve,
            private_le: &key.private_le,
            public_x_le: &key.public_x_le,
            public_y_le: &key.public_y_le,
            signature_type: XmlSignatureType::Enveloped,
            digest_method: DIGEST_METHOD_256,
            signature_method: SIGNATURE_METHOD_256,
            xpath: None,
            xades_flags: XADES_NONE,
            tsa_url: None,
            tsa_policy: None,
            tsa_timeout_secs: 5,
        })
        .expect("sign with roman key");
        key.private_le.zeroize();
        let v = verify_xml(&signed, None).expect("self-verify");
        assert!(v.ok);
        let out = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/xmldsig/jex_enveloped_roman.xml"
        );
        std::fs::write(
            out,
            if signed.ends_with('\n') {
                signed
            } else {
                format!("{signed}\n")
            },
        )
        .expect("write");
        eprintln!("Wrote {out}");
    }

    fn unlock_roman_or_skip() -> Option<(
        crate::container::ClassicContainer,
        crate::container::UnlockedKey,
    )> {
        use zeroize::Zeroize;
        let mut pin = std::env::var("JEX_CONTAINER_PIN").unwrap_or_default();
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/roman");
        let c = match crate::container::ClassicContainer::open(std::path::Path::new(dir)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skip: open roman/: {e}");
                return None;
            }
        };
        let key = match c.unlock(pin.as_bytes()) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("skip: unlock roman/ with empty/default PIN failed: {e}");
                pin.zeroize();
                return None;
            }
        };
        pin.zeroize();
        Some((c, key))
    }

    /// XAdES-T: SignatureTimeStamp over Exc-C14N(SignatureValue) via CryptoPro TSA.
    /// Writes `testdata/xmldsig/jex_xades_t.xml`.
    #[test]
    fn export_jex_xades_t_from_roman_container() {
        use zeroize::Zeroize;
        let Some((c, mut key)) = unlock_roman_or_skip() else {
            return;
        };
        let cert = c.certificate.as_ref().expect("roman cert").clone();
        let identity = x509::identity(&cert).expect("parse cert");
        let curve = curves::by_oid(&identity.curve_oid).expect("curve");
        let content = r#"<?xml version="1.0"?><Document><Body>golden</Body></Document>"#;
        let signed = sign_xml(&SignXmlParams {
            content,
            cert_der: &cert,
            curve: &curve,
            private_le: &key.private_le,
            public_x_le: &key.public_x_le,
            public_y_le: &key.public_y_le,
            signature_type: XmlSignatureType::Enveloped,
            digest_method: DIGEST_METHOD_256,
            signature_method: SIGNATURE_METHOD_256,
            xpath: None,
            xades_flags: XADES_T,
            tsa_url: Some(DEFAULT_CRYPTOPRO_TSA),
            tsa_policy: None,
            tsa_timeout_secs: 30,
        })
        .expect("sign XAdES-T with roman key + CryptoPro TSA");
        key.private_le.zeroize();

        assert!(
            signed.contains("SignatureTimeStamp"),
            "XAdES-T must embed SignatureTimeStamp"
        );
        assert!(
            signed.contains("CanonicalizationMethod"),
            "SignatureTimeStamp must include CanonicalizationMethod"
        );
        assert!(
            signed.contains("EncapsulatedTimeStamp"),
            "SignatureTimeStamp must include EncapsulatedTimeStamp"
        );

        let v = verify_xml(&signed, None).expect("self-verify XAdES-T");
        assert!(v.references_valid, "XAdES-T references");
        assert!(v.signature_valid, "XAdES-T signature");
        assert!(v.ok, "XAdES-T must verify including SignatureTimeStamp");

        let out = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/xmldsig/jex_xades_t.xml"
        );
        std::fs::write(
            out,
            if signed.ends_with('\n') {
                signed
            } else {
                format!("{signed}\n")
            },
        )
        .expect("write jex_xades_t.xml");
        eprintln!("Wrote {out}");
    }

    /// XAdES-X Long Type 1: T + V2 refs + SigAndRefsTimeStampV2.
    /// Writes `testdata/xmldsig/jex_xades_xlt1.xml` when OCSP/CRL collect succeeds.
    #[test]
    fn export_jex_xades_xlt1_from_roman_container() {
        use zeroize::Zeroize;
        let Some((c, mut key)) = unlock_roman_or_skip() else {
            return;
        };
        let cert = c.certificate.as_ref().expect("roman cert").clone();
        let identity = x509::identity(&cert).expect("parse cert");
        let curve = curves::by_oid(&identity.curve_oid).expect("curve");
        let content = r#"<?xml version="1.0"?><Document><Body>golden</Body></Document>"#;
        let signed = match sign_xml(&SignXmlParams {
            content,
            cert_der: &cert,
            curve: &curve,
            private_le: &key.private_le,
            public_x_le: &key.public_x_le,
            public_y_le: &key.public_y_le,
            signature_type: XmlSignatureType::Enveloped,
            digest_method: DIGEST_METHOD_256,
            signature_method: SIGNATURE_METHOD_256,
            xpath: None,
            xades_flags: XADES_XLT1,
            tsa_url: Some(DEFAULT_CRYPTOPRO_TSA),
            tsa_policy: None,
            tsa_timeout_secs: 60,
        }) {
            Ok(s) => s,
            Err(e) => {
                key.private_le.zeroize();
                eprintln!("skip XLT1 golden (collect/TSA failed): {e:#}");
                return;
            }
        };
        key.private_le.zeroize();

        for needle in [
            "SignatureTimeStamp",
            "CompleteCertificateRefsV2",
            "IssuerSerialV2",
            "CompleteRevocationRefs",
            "SigAndRefsTimeStampV2",
            "CertificateValues",
            "RevocationValues",
            XADES_141_NS,
        ] {
            assert!(signed.contains(needle), "XAdES-XLT1 must embed {needle}");
        }
        assert!(
            !signed.contains("<xades:CompleteCertificateRefs>")
                && !signed.contains("<xades:SigAndRefsTimeStamp>"),
            "XAdES-XLT1 must not emit obsolete V1 CompleteCertificateRefs / SigAndRefsTimeStamp"
        );

        let v = verify_xml(&signed, None).expect("self-verify XAdES-XLT1");
        assert!(v.references_valid, "XAdES-XLT1 references");
        assert!(v.signature_valid, "XAdES-XLT1 signature");
        assert!(v.ok, "XAdES-XLT1 must verify including SignatureTimeStamp");
        assert_eq!(
            verify_sig_and_refs_timestamp(&signed, "Signature-jex")
                .expect("verify SigAndRefsTimeStampV2"),
            Some(true),
            "XAdES-XLT1 SigAndRefsTimeStampV2 must verify"
        );

        let out = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/xmldsig/jex_xades_xlt1.xml"
        );
        std::fs::write(
            out,
            if signed.ends_with('\n') {
                signed
            } else {
                format!("{signed}\n")
            },
        )
        .expect("write jex_xades_xlt1.xml");
        eprintln!("Wrote {out}");
    }

    /// Synthetic-key XAdES-T: TSA imprint/token validity does not need a real cert.
    #[test]
    fn enveloped_xades_t_synthetic_with_cryptopro_tsa() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d = BigUint::from(2026082913u64);
        let p = curves::public_key(&curve, &d).unwrap();
        let private = curves::le_fixed(&d, curve.bytes);
        let x = curves::le_fixed(&p.x, curve.bytes);
        let y = curves::le_fixed(&p.y, curve.bytes);
        let cert = fake_gost_certificate(&curve, &x, &y);
        let content = r#"<?xml version="1.0"?><Document><Body>xades-t</Body></Document>"#;
        let signed = sign_xml(&SignXmlParams {
            content,
            cert_der: &cert,
            curve: &curve,
            private_le: &private,
            public_x_le: &x,
            public_y_le: &y,
            signature_type: XmlSignatureType::Enveloped,
            digest_method: DIGEST_METHOD_256,
            signature_method: SIGNATURE_METHOD_256,
            xpath: None,
            xades_flags: XADES_T,
            tsa_url: Some(DEFAULT_CRYPTOPRO_TSA),
            tsa_policy: None,
            tsa_timeout_secs: 30,
        })
        .expect("synthetic XAdES-T + CryptoPro TSA");
        assert!(signed.contains("SignatureTimeStamp"));
        let v = verify_xml(&signed, None).expect("verify synthetic XAdES-T");
        assert!(v.ok, "synthetic XAdES-T must verify (signature+refs+STS)");
    }

    #[test]
    fn verify_jex_xades_t_golden_if_present() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/xmldsig/jex_xades_t.xml"
        );
        let Ok(signed) = std::fs::read_to_string(path) else {
            eprintln!("skip: {path} not present yet");
            return;
        };
        assert!(signed.contains("SignatureTimeStamp"));
        let v = verify_xml(&signed, None).expect("verify jex_xades_t golden");
        assert!(v.ok, "jex_xades_t.xml must verify");
    }
}
