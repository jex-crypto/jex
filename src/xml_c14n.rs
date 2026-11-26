// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
//! Exclusive XML Canonicalization 1.0 without comments
//! (`http://www.w3.org/2001/10/xml-exc-c14n#`) plus Inclusive Canonical XML
//! 1.0 without comments for XML-DSig References that omit Transforms.
//!
//! Sufficient for CryptoPro XML-DSig / XAdES interop: attribute order, namespace
//! axis rules, UTF-8, empty elements as start+end tags, no comments.

use crate::xml_util::{
    escape_attr, escape_text, find_element_by_id, parse_element, remove_enveloped_signatures,
    serialize_element, Element, Node,
};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Parsed XML document (single root element).
pub struct XmlDoc {
    root: Element,
}

impl XmlDoc {
    pub fn parse(xml: &str) -> Result<Self> {
        Ok(Self {
            root: parse_element(xml).context("parse XML document")?,
        })
    }

    /// Exclusive C14N of a node.
    ///
    /// - `None` — document element
    /// - `Some(id)` — element with matching `xml:id` or `Id` (`#id` accepted)
    pub fn canonicalize_node(&self, node_id: Option<&str>) -> Result<Vec<u8>> {
        let el = match node_id {
            None => &self.root,
            Some(id) => find_element_by_id(&self.root, id)
                .with_context(|| format!("element id {id:?} not found"))?,
        };
        Ok(canonicalize_element_exc(el))
    }

    /// Exc-C14N of an already-isolated element serialization (fragment).
    pub fn canonicalize_element_xml(fragment: &str) -> Result<Vec<u8>> {
        let el = parse_element(fragment).context("parse element fragment")?;
        Ok(canonicalize_element_exc(&el))
    }

    pub fn root(&self) -> &Element {
        &self.root
    }
}

/// Convenience: parse and canonicalize.
///
/// `xpath_or_subtree`:
/// - `None` — whole document element
/// - `Some("#id")` / `Some("id")` — subtree by id
/// - `Some("<...>")` — treat as already-extracted element XML
pub fn canonicalize_exc(xml: &str, xpath_or_subtree: Option<&str>) -> Result<Vec<u8>> {
    match xpath_or_subtree {
        None => XmlDoc::parse(xml)?.canonicalize_node(None),
        Some(sel) if sel.trim_start().starts_with('<') => XmlDoc::canonicalize_element_xml(sel),
        Some(sel) => XmlDoc::parse(xml)?.canonicalize_node(Some(sel)),
    }
}

/// Strip enveloped `ds:Signature` elements, return XML suitable as C14N input.
pub fn enveloped_signature_remove(doc_xml: &str) -> Result<String> {
    let mut root = parse_element(doc_xml).context("parse document for enveloped-signature")?;
    remove_enveloped_signatures(&mut root);
    Ok(serialize_element(&root))
}

/// Exclusive C14N of an element already in a parsed tree (preserves inherited `ns_scope`).
///
/// Prefer this over serialize→reparse: CryptoPro often puts default `xmlns` on
/// `Signature`, so `SignedInfo` has no local ns decl and must inherit it.
pub fn canonicalize_element_exc(el: &Element) -> Vec<u8> {
    canonicalize_element(el, /*exclusive*/ true)
}

/// Inclusive Canonical XML 1.0 (without comments) of an in-tree element.
///
/// Used when an XML-DSig `Reference` has no Transforms (XML-DSig Core §4.3.3.2
/// defaults to Canonical XML). CryptoPro XAdES-BES SignedProperties references
/// typically omit Transforms and therefore need Inclusive, not Exclusive, C14N.
pub fn canonicalize_element_inclusive(el: &Element) -> Vec<u8> {
    canonicalize_element(el, /*exclusive*/ false)
}

fn canonicalize_element(el: &Element, exclusive: bool) -> Vec<u8> {
    let mut out = Vec::new();
    // At the apex, nothing has been rendered yet.
    let rendered = HashMap::new();
    write_c14n(el, &rendered, exclusive, &mut out);
    out
}

/// Constrained Exclusive C14N (W3C non-normative §3.1), InclusiveNamespaces empty,
/// or Inclusive Canonical XML 1.0 without comments.
fn write_c14n(
    el: &Element,
    ns_rendered: &HashMap<String, String>,
    exclusive: bool,
    out: &mut Vec<u8>,
) {
    let mut visibly: HashSet<String> = HashSet::new();
    match &el.prefix {
        Some(p) if !p.is_empty() => {
            visibly.insert(p.clone());
        }
        _ => {
            visibly.insert(String::new());
        }
    }
    for a in &el.attrs {
        if let Some(p) = &a.prefix {
            if p != "xml" {
                visibly.insert(p.clone());
            }
        }
    }

    // Namespace declarations to emit on this start tag.
    let mut ns_to_emit: BTreeMap<String, String> = BTreeMap::new();

    if exclusive {
        for prefix in &visibly {
            maybe_emit_ns(el, ns_rendered, prefix, &mut ns_to_emit);
        }
    } else {
        // Inclusive: emit every in-scope namespace (except xml) not already rendered
        // with the same URI. Default empty namespace is omitted unless an ancestor
        // rendered a non-empty default (then emit xmlns="").
        for (prefix, uri) in &el.ns_scope {
            if prefix == "xml" {
                continue;
            }
            if prefix.is_empty() && uri.is_empty() {
                if let Some(prev) = ns_rendered.get("") {
                    if !prev.is_empty() {
                        ns_to_emit.insert(String::new(), String::new());
                    }
                }
                continue;
            }
            if ns_rendered.get(prefix).map(String::as_str) != Some(uri.as_str()) {
                ns_to_emit.insert(prefix.clone(), uri.clone());
            }
        }
        // Also ensure visibly-utilized empty default is handled when absent from map.
        if visibly.contains("") && !el.ns_scope.contains_key("") {
            if let Some(prev) = ns_rendered.get("") {
                if !prev.is_empty() {
                    ns_to_emit.insert(String::new(), String::new());
                }
            }
        }
    }

    // Attributes: sort by namespace URI, then local name (C14N).
    let mut attrs: Vec<&crate::xml_util::Attr> = el.attrs.iter().collect();
    attrs.sort_by(|a, b| {
        a.namespace_uri
            .cmp(&b.namespace_uri)
            .then_with(|| a.local_name.cmp(&b.local_name))
    });

    out.push(b'<');
    push_str(out, &el.qname());

    // Namespace nodes first: default xmlns, then xmlns:prefix by prefix name.
    for (prefix, uri) in &ns_to_emit {
        out.push(b' ');
        if prefix.is_empty() {
            push_str(out, "xmlns=\"");
        } else {
            push_str(out, "xmlns:");
            push_str(out, prefix);
            push_str(out, "=\"");
        }
        push_str(out, &escape_attr(uri));
        out.push(b'"');
    }

    for a in attrs {
        out.push(b' ');
        if let Some(p) = &a.prefix {
            push_str(out, p);
            out.push(b':');
        }
        push_str(out, &a.local_name);
        out.push(b'=');
        out.push(b'"');
        push_str(out, &escape_attr(&a.value));
        out.push(b'"');
    }
    out.push(b'>');

    let mut child_rendered = ns_rendered.clone();
    for (prefix, uri) in &ns_to_emit {
        if prefix.is_empty() && uri.is_empty() {
            child_rendered.remove("");
        } else {
            child_rendered.insert(prefix.clone(), uri.clone());
        }
    }

    for child in &el.children {
        match child {
            Node::Element(e) => write_c14n(e, &child_rendered, exclusive, out),
            Node::Text(t) => push_str(out, &escape_text(t)),
            Node::Pi { target, data } => {
                // Canonical XML PI form.
                out.extend_from_slice(b"<?");
                push_str(out, target);
                if !data.is_empty() {
                    out.push(b' ');
                    // PI data: escape per C14N (#xD only in practice for PI).
                    push_str(out, &data.replace('\r', "&#xD;"));
                }
                out.extend_from_slice(b"?>");
            }
        }
    }

    out.extend_from_slice(b"</");
    push_str(out, &el.qname());
    out.push(b'>');
}

fn maybe_emit_ns(
    el: &Element,
    ns_rendered: &HashMap<String, String>,
    prefix: &str,
    ns_to_emit: &mut BTreeMap<String, String>,
) {
    if prefix == "xml" {
        return;
    }
    let in_scope = el.ns_scope.get(prefix);
    if prefix.is_empty() {
        let empty_or_absent = match in_scope {
            None => true,
            Some(u) => u.is_empty(),
        };
        if empty_or_absent {
            // Default visibly utilized, no (or empty) default in scope.
            // Emit xmlns="" iff an ancestor already rendered a non-empty default.
            if let Some(prev) = ns_rendered.get("") {
                if !prev.is_empty() {
                    ns_to_emit.insert(String::new(), String::new());
                }
            }
        } else if let Some(uri) = in_scope {
            if ns_rendered.get("").map(String::as_str) != Some(uri.as_str()) {
                ns_to_emit.insert(String::new(), uri.clone());
            }
        }
    } else if let Some(uri) = in_scope {
        if ns_rendered.get(prefix).map(String::as_str) != Some(uri.as_str()) {
            ns_to_emit.insert(prefix.to_string(), uri.clone());
        }
    }
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_element_ns_and_attrs() {
        // Attribute order in input is deliberately wrong; C14N reorders.
        let xml = r#"<n1:elem xmlns:n1="http://example.com" xmlns:n0="urn:unused" b="2" a="1"></n1:elem>"#;
        let out = canonicalize_exc(xml, None).unwrap();
        let s = String::from_utf8(out).unwrap();
        // n0 not visibly utilized → omitted; attrs sorted by local name (no ns).
        assert_eq!(
            s,
            r#"<n1:elem xmlns:n1="http://example.com" a="1" b="2"></n1:elem>"#
        );
    }

    #[test]
    fn exc_omits_unused_ancestor_namespaces() {
        let xml = r#"<n1:outer xmlns:n1="http://example.com" xmlns:n2="http://example.net">
  <n2:inner xmlns:n3="ftp://example.org">text</n2:inner>
</n1:outer>"#;
        let doc = XmlDoc::parse(xml).unwrap();
        let whole = String::from_utf8(doc.canonicalize_node(None).unwrap()).unwrap();
        assert!(whole.starts_with(r#"<n1:outer xmlns:n1="http://example.com">"#));
        assert!(whole.contains(r#"<n2:inner xmlns:n2="http://example.net">text</n2:inner>"#));
        assert!(!whole.contains("xmlns:n3"));
        assert!(!whole.contains("ftp://example.org"));
    }

    #[test]
    fn empty_element_expanded() {
        let xml = r#"<e xmlns="urn:x"/>"#;
        let s = String::from_utf8(canonicalize_exc(xml, None).unwrap()).unwrap();
        assert_eq!(s, r#"<e xmlns="urn:x"></e>"#);
    }

    #[test]
    fn fragment_and_id_selection() {
        let xml = r#"<root><child xml:id="c1" xmlns:a="urn:a" a:x="1">ok</child></root>"#;
        let by_id = String::from_utf8(canonicalize_exc(xml, Some("#c1")).unwrap()).unwrap();
        // Attrs: xml:id (XML NS) before a:x (urn:a) by namespace URI order.
        assert_eq!(
            by_id,
            r#"<child xmlns:a="urn:a" xml:id="c1" a:x="1">ok</child>"#
        );

        let frag = r#"<child xmlns:a="urn:a" a:x="1" xml:id="c1">ok</child>"#;
        let by_frag = String::from_utf8(XmlDoc::canonicalize_element_xml(frag).unwrap()).unwrap();
        assert_eq!(by_frag, by_id);
    }

    #[test]
    fn attr_order_by_namespace_uri() {
        let xml = r#"<e xmlns:b="urn:b" xmlns:a="urn:a" b:z="1" a:z="2" plain="0"/>"#;
        let s = String::from_utf8(canonicalize_exc(xml, None).unwrap()).unwrap();
        // Unprefixed first (empty ns URI), then urn:a, then urn:b.
        assert_eq!(
            s,
            r#"<e xmlns:a="urn:a" xmlns:b="urn:b" plain="0" a:z="2" b:z="1"></e>"#
        );
    }

    #[test]
    fn comments_omitted() {
        let xml = r#"<e><!--secret-->x</e>"#;
        let s = String::from_utf8(canonicalize_exc(xml, None).unwrap()).unwrap();
        assert_eq!(s, "<e>x</e>");
    }

    #[test]
    fn enveloped_signature_strip() {
        let xml = r#"<doc xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><body>hi</body><ds:Signature><ds:SignedInfo/></ds:Signature></doc>"#;
        let stripped = enveloped_signature_remove(xml).unwrap();
        assert!(!stripped.contains("Signature"));
        assert!(stripped.contains("<body>hi</body>"));
        let c14n = String::from_utf8(canonicalize_exc(&stripped, None).unwrap()).unwrap();
        assert_eq!(c14n, "<doc><body>hi</body></doc>");
    }

    #[test]
    fn w3c_style_exc_subtree_stable() {
        // Adapted from W3C Exc-C14N: unused context prefixes omitted on orphan apex.
        let inner = r#"<n1:elem2 xmlns:n1="http://example.net" xml:lang="en">
       <n3:stuff xmlns:n3="ftp://example.org"></n3:stuff>
   </n1:elem2>"#;
        let s = String::from_utf8(XmlDoc::canonicalize_element_xml(inner).unwrap()).unwrap();
        assert_eq!(
            s,
            "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">\n       <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n   </n1:elem2>"
        );
    }

    #[test]
    fn inclusive_emits_unused_in_scope_prefixes() {
        // Inclusive C14N emits xmlns:a on the apex even though only used on a child.
        let xml =
            r#"<root xmlns:a="urn:a" xmlns:b="urn:b"><child xml:id="c1"><a:x/></child></root>"#;
        let doc = XmlDoc::parse(xml).unwrap();
        let child = find_element_by_id(doc.root(), "c1").unwrap();
        let inc = String::from_utf8(canonicalize_element_inclusive(child)).unwrap();
        assert!(
            inc.starts_with(r#"<child xmlns:a="urn:a" xmlns:b="urn:b" xml:id="c1">"#),
            "inclusive should keep unused ancestor prefixes: {inc}"
        );
        let exc = String::from_utf8(canonicalize_element_exc(child)).unwrap();
        assert!(
            !exc.contains("xmlns:b"),
            "exclusive must omit unused b: {exc}"
        );
        assert!(
            exc.contains(r#"xmlns:a="urn:a""#),
            "a is used on descendant"
        );
    }
}
