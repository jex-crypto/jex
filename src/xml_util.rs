// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
//! Shared XML helpers for Exc-C14N and XML-DSig transforms.
//!
//! Minimal DOM + escaping / id lookup. Parsing uses `quick-xml` events.

use anyhow::{bail, Context, Result};
use quick_xml::escape::unescape;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::QName;
use quick_xml::reader::Reader;
use quick_xml::XmlVersion;
use std::collections::HashMap;

/// Fixed binding for the reserved `xml` prefix (never emitted as xmlns:xml).
pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
/// XML Digital Signature namespace.
pub const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

#[derive(Debug, Clone)]
pub struct Attr {
    pub prefix: Option<String>,
    pub local_name: String,
    /// Empty string = no namespace.
    pub namespace_uri: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Element {
    pub prefix: Option<String>,
    pub local_name: String,
    /// Empty string = no namespace.
    pub namespace_uri: String,
    /// Namespace declarations on this element: (prefix, uri).
    /// Empty prefix string means default `xmlns="..."`.
    pub ns_decls: Vec<(String, String)>,
    pub attrs: Vec<Attr>,
    pub children: Vec<Node>,
    /// In-scope namespace map after this element's declarations
    /// (`""` key = default namespace URI; absent = no default).
    pub ns_scope: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum Node {
    Element(Element),
    Text(String),
    /// Processing instruction: target + optional data.
    Pi {
        target: String,
        data: String,
    },
}

impl Element {
    pub fn qname(&self) -> String {
        match &self.prefix {
            Some(p) if !p.is_empty() => format!("{}:{}", p, self.local_name),
            _ => self.local_name.clone(),
        }
    }
}

/// Escape text node content per Canonical XML 1.0.
pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Escape attribute value per Canonical XML 1.0.
pub fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(ch),
        }
    }
    out
}

/// First attribute with the given local name (any namespace), or `None`.
pub fn get_attr<'a>(el: &'a Element, local_name: &str) -> Option<&'a str> {
    el.attrs
        .iter()
        .find(|a| a.local_name == local_name)
        .map(|a| a.value.as_str())
}

/// Attribute by namespace URI + local name.
pub fn get_attr_ns<'a>(el: &'a Element, ns_uri: &str, local_name: &str) -> Option<&'a str> {
    el.attrs
        .iter()
        .find(|a| a.namespace_uri == ns_uri && a.local_name == local_name)
        .map(|a| a.value.as_str())
}

/// Find element by `xml:id` (preferred) or unprefixed / any-ns `Id`.
///
/// `id` may be bare (`foo`) or URI-fragment style (`#foo`).
pub fn find_element_by_id<'a>(root: &'a Element, id: &str) -> Option<&'a Element> {
    let id = id.strip_prefix('#').unwrap_or(id);
    find_by_id_rec(root, id)
}

fn find_by_id_rec<'a>(el: &'a Element, id: &str) -> Option<&'a Element> {
    if element_id_matches(el, id) {
        return Some(el);
    }
    for child in &el.children {
        if let Node::Element(e) = child {
            if let Some(found) = find_by_id_rec(e, id) {
                return Some(found);
            }
        }
    }
    None
}

fn element_id_matches(el: &Element, id: &str) -> bool {
    if get_attr_ns(el, XML_NS, "id") == Some(id) {
        return true;
    }
    if el
        .attrs
        .iter()
        .any(|a| a.prefix.is_none() && a.local_name == "Id" && a.value == id)
    {
        return true;
    }
    el.attrs
        .iter()
        .any(|a| a.local_name == "Id" && a.value == id)
}

/// Parse a well-formed XML document or element fragment into a root [`Element`].
///
/// Skips the XML declaration; comments are dropped; the first top-level element
/// becomes the root.
pub fn parse_element(xml: &str) -> Result<Element> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    reader.config_mut().expand_empty_elements = true;

    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut scope_stack: Vec<HashMap<String, String>> =
        vec![HashMap::from([("xml".to_string(), XML_NS.to_string())])];

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let parent_scope = scope_stack.last().cloned().unwrap_or_default();
                let el = start_to_element(&e, &parent_scope)?;
                scope_stack.push(el.ns_scope.clone());
                stack.push(el);
            }
            Ok(Event::Empty(e)) => {
                let parent_scope = scope_stack.last().cloned().unwrap_or_default();
                let el = start_to_element(&e, &parent_scope)?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(Node::Element(el));
                } else if root.is_none() {
                    root = Some(el);
                } else {
                    bail!("multiple top-level elements");
                }
            }
            Ok(Event::End(_)) => {
                scope_stack.pop();
                let el = stack.pop().context("unbalanced end tag")?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(Node::Element(el));
                } else if root.is_none() {
                    root = Some(el);
                } else {
                    bail!("multiple top-level elements");
                }
            }
            Ok(Event::Text(t)) => {
                let raw = t.as_ref();
                let text = unescape(raw)
                    .map(|c| c.into_owned())
                    .unwrap_or_else(|_| raw.to_string());
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(Node::Text(text));
                }
            }
            Ok(Event::CData(c)) => {
                let text = c.as_ref().to_string();
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(Node::Text(text));
                }
            }
            Ok(Event::Comment(_)) => {}
            Ok(Event::PI(pi)) => {
                let (target, data) = split_pi(pi.as_ref());
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(Node::Pi { target, data });
                }
            }
            Ok(Event::Decl(_)) | Ok(Event::DocType(_)) => {}
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::Error::new(e)).context("parse XML"),
            _ => {}
        }
    }

    root.context("XML has no element")
}

fn split_pi(raw: &str) -> (String, String) {
    let raw = raw.trim();
    match raw.split_once(|c: char| c.is_whitespace()) {
        Some((t, rest)) => (t.to_string(), rest.trim_start().to_string()),
        None => (raw.to_string(), String::new()),
    }
}

fn start_to_element(e: &BytesStart<'_>, parent_scope: &HashMap<String, String>) -> Result<Element> {
    let (prefix, local) = split_qname(e.name());
    let mut ns_decls: Vec<(String, String)> = Vec::new();
    let mut attrs: Vec<Attr> = Vec::new();
    let mut scope = parent_scope.clone();
    scope
        .entry("xml".to_string())
        .or_insert_with(|| XML_NS.to_string());

    for attr in e.attributes().with_checks(false) {
        let attr = attr.context("XML attribute")?;
        let (ap, al) = split_qname(attr.key);
        let value = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map(|c| c.into_owned())
            .unwrap_or_else(|_| attr.value.into_owned());

        if ap.as_deref() == Some("xmlns") {
            ns_decls.push((al.clone(), value.clone()));
            scope.insert(al, value);
            continue;
        }
        if ap.is_none() && al == "xmlns" {
            ns_decls.push((String::new(), value.clone()));
            if value.is_empty() {
                scope.remove("");
            } else {
                scope.insert(String::new(), value);
            }
            continue;
        }

        let namespace_uri = match &ap {
            Some(p) => scope.get(p).cloned().unwrap_or_default(),
            None => String::new(),
        };
        attrs.push(Attr {
            prefix: ap,
            local_name: al,
            namespace_uri,
            value,
        });
    }

    let namespace_uri = match &prefix {
        Some(p) => scope.get(p).cloned().unwrap_or_default(),
        None => scope.get("").cloned().unwrap_or_default(),
    };

    Ok(Element {
        prefix,
        local_name: local,
        namespace_uri,
        ns_decls,
        attrs,
        children: Vec::new(),
        ns_scope: scope,
    })
}

fn split_qname(name: QName<'_>) -> (Option<String>, String) {
    let raw = name.as_ref();
    match raw.split_once(':') {
        Some((p, l)) => (Some(p.to_string()), l.to_string()),
        None => (None, raw.to_string()),
    }
}

/// Serialize an element tree to XML (not canonical). Suitable as C14N input.
pub fn serialize_element(el: &Element) -> String {
    let mut out = String::new();
    write_element(el, &mut out);
    out
}

fn write_element(el: &Element, out: &mut String) {
    out.push('<');
    out.push_str(&el.qname());
    for (prefix, uri) in &el.ns_decls {
        out.push(' ');
        if prefix.is_empty() {
            out.push_str("xmlns=\"");
        } else {
            out.push_str("xmlns:");
            out.push_str(prefix);
            out.push_str("=\"");
        }
        out.push_str(&escape_attr(uri));
        out.push('"');
    }
    for a in &el.attrs {
        out.push(' ');
        if let Some(p) = &a.prefix {
            out.push_str(p);
            out.push(':');
        }
        out.push_str(&a.local_name);
        out.push_str("=\"");
        out.push_str(&escape_attr(&a.value));
        out.push('"');
    }
    out.push('>');
    for child in &el.children {
        match child {
            Node::Element(e) => write_element(e, out),
            Node::Text(t) => out.push_str(&escape_text(t)),
            Node::Pi { target, data } => {
                out.push_str("<?");
                out.push_str(target);
                if !data.is_empty() {
                    out.push(' ');
                    out.push_str(data);
                }
                out.push_str("?>");
            }
        }
    }
    out.push_str("</");
    out.push_str(&el.qname());
    out.push('>');
}

/// Remove all `ds:Signature` elements (local-name `Signature` in XMLDSIG_NS).
pub fn remove_enveloped_signatures(el: &mut Element) {
    el.children.retain_mut(|node| match node {
        Node::Element(e) => {
            if e.local_name == "Signature" && e.namespace_uri == XMLDSIG_NS {
                return false;
            }
            remove_enveloped_signatures(e);
            true
        }
        _ => true,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_attr_and_text() {
        assert_eq!(escape_text("a&b<c>d\r"), "a&amp;b&lt;c&gt;d&#xD;");
        assert_eq!(
            escape_attr("a&b<c\"d\t\n\r"),
            "a&amp;b&lt;c&quot;d&#x9;&#xA;&#xD;"
        );
    }

    #[test]
    fn find_by_xml_id_and_id() {
        let doc =
            parse_element(r#"<root><a xml:id="x1"/><b Id="x2"/><c other="x3"/></root>"#).unwrap();
        let a = find_element_by_id(&doc, "x1").unwrap();
        assert_eq!(a.local_name, "a");
        assert_eq!(get_attr_ns(a, XML_NS, "id"), Some("x1"));
        let b = find_element_by_id(&doc, "#x2").unwrap();
        assert_eq!(b.local_name, "b");
        assert_eq!(get_attr(b, "Id"), Some("x2"));
        assert!(find_element_by_id(&doc, "x3").is_none());
    }
}
