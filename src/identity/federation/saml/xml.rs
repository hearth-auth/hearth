//! Minimal XML reader/writer helpers for SAML.
//!
//! Built on `quick-xml`. Deliberately narrow — only the shapes we emit
//! and consume for SAML 2.0 messages are supported. No DTDs, no entity
//! expansion, no processing instructions.
//!
//! Security posture: rejects XML external entities, DOCTYPE declarations,
//! and comments outside of the document root. These vectors have produced
//! many XXE CVEs in SAML parsers historically.

use quick_xml::escape::{resolve_predefined_entity, unescape};
use quick_xml::events::attributes::Attribute;
use quick_xml::events::{BytesRef, BytesStart, BytesText, Event};
use quick_xml::Reader;
use std::borrow::Cow;
use std::io::BufRead;

use crate::identity::error::IdentityError;
use crate::identity::federation::saml::SamlError;

/// Standard SAML namespace URIs.
pub mod ns {
    pub const SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
    pub const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
    pub const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
    pub const MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
    pub const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
    pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
}

/// XML-DSIG algorithm URIs we accept.
pub mod alg {
    pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
    pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
    pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    pub const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    pub const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
}

/// Configures a `quick_xml::Reader` with our security-conservative defaults.
pub fn make_reader<R: BufRead>(reader: R) -> Reader<R> {
    let mut r = Reader::from_reader(reader);
    let cfg = r.config_mut();
    // Rejecting DOCTYPE/XXE vectors: quick-xml skips DTDs by default but
    // emit them as Event::DocType anyway so we can reject them.
    cfg.expand_empty_elements = true;
    cfg.trim_text(false);
    r
}

/// Returns `true` iff the given [`BytesStart`] represents an element in
/// the given namespace and with the given local name.
pub fn is_element(start: &BytesStart<'_>, namespace_uri: &str, local: &str) -> bool {
    let qname = start.name();
    // Split prefix and local — we need to resolve the prefix against the
    // accumulated namespace context. `quick_xml::NsReader` handles this
    // natively; we rely on callers using it where namespace awareness is
    // required. For simple cases we accept either `{ns}local` comparison
    // or prefix:local matching when the ns is one of the well-known ones.
    let name_bytes = qname.as_ref();
    if let Some(colon) = name_bytes.iter().position(|&b| b == b':') {
        let local_bytes = &name_bytes[colon + 1..];
        local_bytes == local.as_bytes()
            && namespace_matches_prefix(&name_bytes[..colon], namespace_uri, start)
    } else {
        name_bytes == local.as_bytes() && has_default_namespace(start, namespace_uri)
    }
}

fn namespace_matches_prefix(prefix: &[u8], expected_uri: &str, start: &BytesStart<'_>) -> bool {
    let attr_name = [b"xmlns:", prefix].concat();
    for attr in start.attributes().with_checks(false).flatten() {
        if attr.key.as_ref() == attr_name {
            if let Ok(v) = unescape_attr_value(&attr) {
                return v == expected_uri;
            }
        }
    }
    // Fall back to prefix-match for the common SAML prefixes even when
    // the xmlns isn't declared on this element (it would be on an
    // ancestor in a proper parse). Accept standard prefixes.
    matches!(
        (prefix, expected_uri),
        (b"samlp" | b"saml2p", ns::SAMLP)
            | (b"saml" | b"saml2", ns::SAML)
            | (b"ds", ns::DS)
            | (b"md", ns::MD)
    )
}

fn has_default_namespace(start: &BytesStart<'_>, expected_uri: &str) -> bool {
    for attr in start.attributes().with_checks(false).flatten() {
        if attr.key.as_ref() == b"xmlns" {
            if let Ok(v) = unescape_attr_value(&attr) {
                return v == expected_uri;
            }
        }
    }
    false
}

/// Extracts the value of a specific attribute from a start tag.
pub fn attr(start: &BytesStart<'_>, name: &str) -> Option<String> {
    for a in start.attributes().with_checks(false).flatten() {
        if a.key.as_ref() == name.as_bytes() {
            if let Ok(v) = unescape_attr_value(&a) {
                return Some(v);
            }
        }
    }
    None
}

/// Decodes and entity-unescapes an XML text node.
///
/// quick-xml 0.41 removed `BytesText::unescape()`, which decoded the raw
/// bytes and resolved XML entity references (`&amp;` → `&`) in a single
/// call. This restores that behavior: XML 1.0 decode with EOL normalization,
/// then entity unescaping. Preserves the pre-upgrade parsing semantics so no
/// SAML message is decoded differently than before.
pub fn unescape_text<'a>(t: &BytesText<'a>) -> Result<Cow<'a, str>, quick_xml::Error> {
    match t.xml10_content()? {
        Cow::Borrowed(s) => Ok(unescape(s)?),
        Cow::Owned(s) => Ok(Cow::Owned(unescape(&s)?.into_owned())),
    }
}

/// Resolves an XML entity-reference event ([`Event::GeneralRef`]) to its text.
///
/// quick-xml 0.41 tokenizes every `&...;` reference — including the five
/// predefined entities — into a standalone [`Event::GeneralRef`] rather than
/// folding it into the surrounding text. Text-collecting loops must resolve
/// these so escaped characters (e.g. an `&amp;` inside an Issuer URI) are not
/// silently dropped.
///
/// Numeric character references (`&#48;`, `&#x30;`) and the five predefined
/// entities (`amp`, `lt`, `gt`, `quot`, `apos`) are resolved. Any other
/// (DTD-defined) general entity is rejected: Hearth's SAML reader forbids
/// DOCTYPE/entity expansion, so a custom entity reference is treated as an
/// XXE attempt.
pub fn resolve_entity_ref(r: &BytesRef<'_>) -> Result<String, IdentityError> {
    if let Some(c) = r
        .resolve_char_ref()
        .map_err(|e| parse_err(format!("bad character reference: {e}")))?
    {
        return Ok(c.to_string());
    }
    let name = r
        .decode()
        .map_err(|e| parse_err(format!("bad entity reference: {e}")))?;
    resolve_predefined_entity(&name)
        .map(str::to_owned)
        .ok_or_else(|| parse_err(format!("disallowed XML entity reference: &{name};")))
}

/// Decodes and entity-unescapes an attribute value.
///
/// Replaces the `Attribute::unescape_value()` method deprecated in quick-xml
/// 0.41. Deliberately preserves the pre-0.41 semantics — decode UTF-8 and
/// resolve XML entity references only — and does **not** apply the XML
/// attribute-value whitespace normalization that `normalized_value()` performs.
/// Canonicalization (`c14n`) relies on literal tab/newline/carriage-return
/// characters surviving so they can be escaped to their numeric character
/// references; normalizing them to spaces here would corrupt the canonical
/// form and break signature validation.
pub fn unescape_attr_value(a: &Attribute<'_>) -> Result<String, IdentityError> {
    let raw = std::str::from_utf8(a.value.as_ref())
        .map_err(|e| parse_err(format!("attribute value not UTF-8: {e}")))?;
    Ok(unescape(raw)
        .map_err(|e| parse_err(format!("bad attribute value: {e}")))?
        .into_owned())
}

/// Parse error helper.
pub fn parse_err(reason: impl Into<String>) -> IdentityError {
    IdentityError::Saml(SamlError::Parse {
        reason: reason.into(),
    })
}

/// Reads the textual content between the current start and its matching
/// end tag. Simplified — does not support nested elements (which the
/// SAML fields we extract with this don't contain).
pub fn read_text<R: BufRead>(reader: &mut Reader<R>) -> Result<String, IdentityError> {
    let mut buf = Vec::new();
    let mut out = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Text(t)) => {
                if let Ok(s) = unescape_text(&t) {
                    out.push_str(s.as_ref());
                }
            }
            Ok(Event::GeneralRef(r)) => {
                out.push_str(&resolve_entity_ref(&r)?);
            }
            Ok(Event::CData(c)) => {
                if let Ok(s) = std::str::from_utf8(c.as_ref()) {
                    out.push_str(s);
                }
            }
            Ok(Event::End(_)) => return Ok(out),
            Ok(Event::Eof) => return Err(parse_err("unexpected EOF in text content")),
            Ok(Event::Start(_)) => {
                return Err(parse_err("unexpected child element in text content"));
            }
            Err(e) => return Err(parse_err(format!("XML read error: {e}"))),
            _ => {}
        }
        buf.clear();
    }
}

/// XML escape for element content (`<`, `>`, `&`, and CR).
///
/// Per exclusive C14N: CR `&#x0D;` must be escaped; NL and tab are left.
pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    out
}

/// XML escape for attribute values (`<`, `&`, `"`, and whitespace chars).
pub fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    out
}

/// Locates an element by (namespace_uri, local_name) and returns the raw
/// byte range in `xml` containing that element, inclusive of its start
/// and end tags.
///
/// Used by signature verification: we need to canonicalize exactly the
/// bytes the IdP signed, not a re-serialized form. Works by tracking
/// buffer position offsets from the quick-xml reader.
///
/// Returns the first matching element at **any** depth. Callers that need a
/// structural guarantee about where the element sits — signature discovery,
/// for one — must use [`find_child_element_range`] instead.
pub fn find_element_range(
    xml: &[u8],
    namespace_uri: &str,
    local: &str,
    id_attr: Option<&str>,
) -> Result<Option<(usize, usize)>, IdentityError> {
    find_element_range_at_depth(xml, namespace_uri, local, id_attr, None)
}

/// Locates a **direct child of the document's root element** by
/// (namespace_uri, local_name), returning its raw byte range in `xml`.
///
/// XML-DSIG structure is positional: an enveloped `<ds:Signature>` is a
/// child of the element it signs, and `<ds:SignedInfo>` is a child of
/// `<ds:Signature>`. Searching at any depth lets a signature belonging to a
/// descendant be read as though it were the root's own — the digest and
/// `Reference URI` bindings then have to carry the whole defence alone.
/// Constraining discovery to the declared depth removes that class outright.
///
/// # Errors
///
/// Returns a parse error on malformed XML, on a `DOCTYPE` declaration, or
/// when the document exceeds `MAX_SAML_XML_EVENTS`.
pub fn find_child_element_range(
    xml: &[u8],
    namespace_uri: &str,
    local: &str,
) -> Result<Option<(usize, usize)>, IdentityError> {
    // Root element is depth 1, so its direct children sit at depth 2.
    find_element_range_at_depth(xml, namespace_uri, local, None, Some(2))
}

/// Shared scanner for [`find_element_range`] and [`find_child_element_range`].
///
/// `required_depth`, when set, restricts matching to elements opening at
/// exactly that depth (the document's root element is depth 1).
fn find_element_range_at_depth(
    xml: &[u8],
    namespace_uri: &str,
    local: &str,
    id_attr: Option<&str>,
    required_depth: Option<i32>,
) -> Result<Option<(usize, usize)>, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut buf = Vec::new();
    let mut depth: i32 = 0;
    // Depth at which we found the first matching Start. We emit when the
    // corresponding End closes at this depth.
    let mut target_depth: Option<i32> = None;
    let mut target_start: usize = 0;
    // A-35: cap total element events to prevent resource exhaustion.
    let mut event_count: usize = 0;

    loop {
        let pos_before = reader.buffer_position() as usize;
        event_count += 1;
        if event_count > crate::abuse::MAX_SAML_XML_EVENTS {
            return Err(parse_err("XML document exceeds maximum element limit"));
        }
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                depth += 1;
                if target_depth.is_none()
                    && required_depth.is_none_or(|want| want == depth)
                    && is_element(e, namespace_uri, local)
                    && id_match(e, id_attr)
                {
                    target_depth = Some(depth);
                    target_start = pos_before;
                }
            }
            Ok(Event::End(_)) => {
                let pos_after = reader.buffer_position() as usize;
                if target_depth == Some(depth) {
                    return Ok(Some((target_start, pos_after)));
                }
                depth -= 1;
            }
            Ok(Event::Empty(ref e)) => {
                let pos_after = reader.buffer_position() as usize;
                // An `Empty` event does not move `depth`, so the element it
                // represents sits one level below the currently-open element.
                if target_depth.is_none()
                    && required_depth.is_none_or(|want| want == depth + 1)
                    && is_element(e, namespace_uri, local)
                    && id_match(e, id_attr)
                {
                    return Ok(Some((pos_before, pos_after)));
                }
            }
            Ok(Event::DocType(_)) => {
                return Err(parse_err("DOCTYPE declarations are rejected"));
            }
            Ok(Event::Eof) => return Ok(None),
            Err(e) => return Err(parse_err(format!("XML scan error: {e}"))),
            _ => {}
        }
        buf.clear();
    }
}

/// Counts every element with the given (namespace_uri, local_name) in the
/// document, at any depth — including elements nested inside a
/// `<ds:Signature>`, which the enveloped-signature transform removes
/// before a digest is computed.
///
/// Signature-wrapping defences need this: a wrapped document is one where
/// the number of candidate elements the parser can reach differs from the
/// one element whose signature was verified.
///
/// # Errors
///
/// Returns a parse error on malformed XML, on a `DOCTYPE` declaration, or
/// when the document exceeds `MAX_SAML_XML_EVENTS`.
pub fn count_elements(
    xml: &[u8],
    namespace_uri: &str,
    local: &str,
) -> Result<usize, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut buf = Vec::new();
    let mut count: usize = 0;
    let mut event_count: usize = 0;

    loop {
        event_count += 1;
        if event_count > crate::abuse::MAX_SAML_XML_EVENTS {
            return Err(parse_err("XML document exceeds maximum element limit"));
        }
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                if is_element(e, namespace_uri, local) {
                    count += 1;
                }
            }
            Ok(Event::DocType(_)) => {
                return Err(parse_err("DOCTYPE declarations are rejected"));
            }
            Ok(Event::Eof) => return Ok(count),
            Err(e) => return Err(parse_err(format!("XML scan error: {e}"))),
            _ => {}
        }
        buf.clear();
    }
}

/// Counts the **direct children of the document's root element** with the
/// given (namespace_uri, local_name).
///
/// An XML-DSIG enveloped signature is a direct child of the element it
/// signs, and the enveloped-signature transform removes exactly that one
/// `<ds:Signature>` from the digest input. A second direct-child
/// `<ds:Signature>` is therefore a region of the signed element that no
/// verifier looks at — `verify_signed_element` uses this count to refuse it.
///
/// # Errors
///
/// Returns a parse error on malformed XML, on a `DOCTYPE` declaration, or
/// when the document exceeds `MAX_SAML_XML_EVENTS`.
pub fn count_child_elements(
    xml: &[u8],
    namespace_uri: &str,
    local: &str,
) -> Result<usize, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut buf = Vec::new();
    let mut depth: usize = 0;
    let mut count: usize = 0;
    let mut event_count: usize = 0;

    loop {
        event_count += 1;
        if event_count > crate::abuse::MAX_SAML_XML_EVENTS {
            return Err(parse_err("XML document exceeds maximum element limit"));
        }
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                depth += 1;
                if depth == 2 && is_element(e, namespace_uri, local) {
                    count += 1;
                }
            }
            // An `Empty` event does not move `depth`: the element sits one
            // level below the currently open one.
            Ok(Event::Empty(ref e)) => {
                if depth + 1 == 2 && is_element(e, namespace_uri, local) {
                    count += 1;
                }
            }
            Ok(Event::End(_)) => depth = depth.saturating_sub(1),
            Ok(Event::DocType(_)) => {
                return Err(parse_err("DOCTYPE declarations are rejected"));
            }
            Ok(Event::Eof) => return Ok(count),
            Err(e) => return Err(parse_err(format!("XML scan error: {e}"))),
            _ => {}
        }
        buf.clear();
    }
}

/// One step of [`walk_outside_signatures`].
pub enum XmlStep<'a> {
    /// An element opened. `depth` is 1 for the document's root element.
    Open {
        /// The element's start tag.
        element: &'a BytesStart<'a>,
        /// Nesting depth of the element (root = 1).
        depth: usize,
    },
    /// Character data (entity and character references resolved, CDATA
    /// included) directly inside the element open at `depth`.
    Text {
        /// The decoded text.
        text: &'a str,
        /// Depth of the innermost open element (0 outside the root).
        depth: usize,
    },
    /// The element opened at `depth` closed. A self-closing element produces
    /// an `Open` immediately followed by its `Close`.
    Close {
        /// Nesting depth of the element that closed.
        depth: usize,
    },
}

/// Walks `xml` and reports every element and text node **outside** every
/// `<ds:Signature>` subtree, at any depth.
///
/// A `<ds:Signature>` is the one region of a signed SAML element that its
/// digest does not cover: the enveloped-signature transform removes it
/// before hashing, and only its `<ds:SignedInfo>` is covered by the signature
/// value. Anything an attacker adds inside one — a `<saml:NameID>`, a
/// `<saml:Attribute>`, a `<saml:Conditions>` — leaves the signature valid. A
/// field reader that can see into it can therefore be fed unsigned values
/// (GA audit 3, G-1). Every SAML field extractor (`parse_response`,
/// `parse_authn_request`, `parse_logout_request`, `parse_logout_response`)
/// reads the document through this walker, so none of them can.
///
/// Also enforces, for every caller: no `DOCTYPE`, at most
/// `MAX_SAML_XML_EVENTS` events, and exactly one root element — a second
/// top-level element would be a second document whose fields a parser could
/// merge into the first.
///
/// # Errors
///
/// Returns a parse error on malformed XML, a `DOCTYPE` declaration, a
/// disallowed entity reference, a second root element, or when the document
/// exceeds `MAX_SAML_XML_EVENTS`; and any error `visit` returns.
pub fn walk_outside_signatures<F>(xml: &[u8], mut visit: F) -> Result<(), IdentityError>
where
    F: FnMut(XmlStep<'_>) -> Result<(), IdentityError>,
{
    let mut reader = Reader::from_reader(xml);
    let cfg = reader.config_mut();
    cfg.expand_empty_elements = false;
    cfg.trim_text(false);

    let mut buf = Vec::new();
    let mut depth: usize = 0;
    // Depth of the `<ds:Signature>` whose subtree is being skipped.
    let mut skipping: Option<usize> = None;
    let mut root_seen = false;
    let mut event_count: usize = 0;

    loop {
        event_count += 1;
        if event_count > crate::abuse::MAX_SAML_XML_EVENTS {
            return Err(parse_err("XML document exceeds maximum element limit"));
        }
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                if depth == 0 {
                    if root_seen {
                        return Err(parse_err("XML document has more than one root element"));
                    }
                    root_seen = true;
                }
                depth += 1;
                if skipping.is_none() {
                    if is_element(e, ns::DS, "Signature") {
                        skipping = Some(depth);
                    } else {
                        visit(XmlStep::Open { element: e, depth })?;
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                if depth == 0 {
                    if root_seen {
                        return Err(parse_err("XML document has more than one root element"));
                    }
                    root_seen = true;
                }
                if skipping.is_none() && !is_element(e, ns::DS, "Signature") {
                    visit(XmlStep::Open {
                        element: e,
                        depth: depth + 1,
                    })?;
                    visit(XmlStep::Close { depth: depth + 1 })?;
                }
            }
            Ok(Event::End(_)) => {
                match skipping {
                    Some(d) if d == depth => skipping = None,
                    Some(_) => {}
                    None => visit(XmlStep::Close { depth })?,
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Text(ref t)) => {
                if skipping.is_none() {
                    let text = unescape_text(t).map_err(|e| parse_err(e.to_string()))?;
                    visit(XmlStep::Text { text: &text, depth })?;
                }
            }
            Ok(Event::GeneralRef(ref r)) => {
                if skipping.is_none() {
                    let text = resolve_entity_ref(r)?;
                    visit(XmlStep::Text { text: &text, depth })?;
                }
            }
            Ok(Event::CData(ref c)) => {
                if skipping.is_none() {
                    let text = std::str::from_utf8(c.as_ref())
                        .map_err(|e| parse_err(format!("CDATA not UTF-8: {e}")))?;
                    visit(XmlStep::Text { text, depth })?;
                }
            }
            Ok(Event::DocType(_)) => {
                return Err(parse_err("DOCTYPE declarations are rejected"));
            }
            Ok(Event::Eof) => return Ok(()),
            Err(e) => return Err(parse_err(format!("XML read error: {e}"))),
            // Comments, processing instructions and the XML declaration
            // carry no SAML data (and exclusive C14N drops them too).
            Ok(_) => {}
        }
        buf.clear();
    }
}

fn id_match(e: &BytesStart<'_>, id_attr: Option<&str>) -> bool {
    match id_attr {
        None => true,
        Some(expected) => {
            attr(e, "ID").as_deref() == Some(expected) || attr(e, "Id").as_deref() == Some(expected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_text_covers_gt_lt_amp_cr() {
        assert_eq!(escape_text("a<b>&c\r"), "a&lt;b&gt;&amp;c&#xD;");
    }

    #[test]
    fn escape_attr_covers_whitespace_quote() {
        assert_eq!(escape_attr("\"\t\n\r<&"), "&quot;&#x9;&#xA;&#xD;&lt;&amp;");
    }

    const NESTED: &[u8] = br#"<Root><Mid><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">deep</ds:Signature></Mid></Root>"#;
    const DIRECT: &[u8] = br#"<Root><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">shallow</ds:Signature><Mid/></Root>"#;

    #[test]
    fn find_child_element_range_ignores_a_nested_match() {
        let found =
            find_child_element_range(NESTED, ns::DS, "Signature").expect("well-formed input");
        assert!(
            found.is_none(),
            "a grandchild must not be reported as a direct child"
        );
    }

    #[test]
    fn find_child_element_range_finds_a_direct_child() {
        let (start, end) = find_child_element_range(DIRECT, ns::DS, "Signature")
            .expect("well-formed input")
            .expect("the direct-child signature must be found");
        let slice = std::str::from_utf8(&DIRECT[start..end]).expect("utf8");
        assert!(slice.contains("shallow"), "wrong range returned: {slice}");
        assert!(
            slice.ends_with("</ds:Signature>"),
            "range not closed: {slice}"
        );
    }

    /// Collects `(kind, depth, detail)` for every step the walker reports.
    fn walk(xml: &[u8]) -> Result<Vec<(char, usize, String)>, IdentityError> {
        let mut out = Vec::new();
        walk_outside_signatures(xml, |step| {
            out.push(match step {
                XmlStep::Open { element, depth } => (
                    'o',
                    depth,
                    String::from_utf8_lossy(element.name().as_ref()).into_owned(),
                ),
                XmlStep::Text { text, depth } => ('t', depth, text.to_string()),
                XmlStep::Close { depth } => ('c', depth, String::new()),
            });
            Ok(())
        })?;
        Ok(out)
    }

    /// GA audit 3, G-1: nothing inside a `<ds:Signature>` — at any depth — is
    /// reported, and the walk resumes correctly after it.
    #[test]
    fn walk_outside_signatures_skips_every_signature_subtree() {
        let xml = br#"<R xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature><N>hidden</N></ds:Signature><A><ds:Signature><N>deep</N></ds:Signature><N>seen &amp; kept</N></A><ds:Signature/></R>"#;
        let steps = walk(xml).expect("walk");
        let names: Vec<&str> = steps
            .iter()
            .filter(|s| s.0 == 'o')
            .map(|s| s.2.as_str())
            .collect();
        assert_eq!(names, ["R", "A", "N"]);
        let text: String = steps
            .iter()
            .filter(|s| s.0 == 't')
            .map(|s| s.2.as_str())
            .collect();
        assert_eq!(text, "seen & kept");
        assert!(
            steps.contains(&('o', 3, "N".to_string())),
            "depth tracking broke after a skipped subtree: {steps:?}"
        );
    }

    #[test]
    fn walk_outside_signatures_rejects_a_second_root() {
        let err = walk(b"<A/><B/>").expect_err("two roots must be rejected");
        assert!(matches!(err, IdentityError::Saml(SamlError::Parse { .. })));
    }

    #[test]
    fn walk_outside_signatures_rejects_doctype() {
        let err = walk(b"<!DOCTYPE a []><a/>").expect_err("DOCTYPE must be rejected");
        assert!(matches!(err, IdentityError::Saml(SamlError::Parse { .. })));
    }

    /// Only the root's direct children are counted.
    #[test]
    fn count_child_elements_counts_direct_children_only() {
        let xml = br#"<Root><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/><Mid><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></Mid><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">x</ds:Signature></Root>"#;
        assert_eq!(
            count_child_elements(xml, ns::DS, "Signature").expect("count"),
            2
        );
        assert_eq!(
            count_child_elements(DIRECT, ns::DS, "Signature").expect("count"),
            1
        );
        assert_eq!(
            count_child_elements(NESTED, ns::DS, "Signature").expect("count"),
            0
        );
    }

    /// The unconstrained scanner still reaches any depth — the two functions
    /// differ only in the depth constraint, which is what `Signature`
    /// discovery relies on.
    #[test]
    fn find_element_range_still_matches_at_any_depth() {
        let found = find_element_range(NESTED, ns::DS, "Signature", None)
            .expect("well-formed input")
            .expect("the unconstrained scanner must still find a nested match");
        let slice = std::str::from_utf8(&NESTED[found.0..found.1]).expect("utf8");
        assert!(slice.contains("deep"), "wrong range returned: {slice}");
    }
}
