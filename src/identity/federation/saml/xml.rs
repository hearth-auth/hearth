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
/// Returns the first matching element. Nested recursion supported.
pub fn find_element_range(
    xml: &[u8],
    namespace_uri: &str,
    local: &str,
    id_attr: Option<&str>,
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
                if target_depth.is_none()
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
}
