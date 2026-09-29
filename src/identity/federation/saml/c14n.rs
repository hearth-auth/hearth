//! Exclusive XML canonicalization (subset of http://www.w3.org/2001/10/xml-exc-c14n#).
//!
//! This is a deliberately narrow implementation — enough for the SAML
//! 2.0 messages Hearth produces and consumes in practice. It is NOT a
//! general-purpose exc-c14n processor.
//!
//! Supported:
//! - Element sorting (attributes alphabetical by fully-qualified name).
//! - Namespace declarations emitted only when "visibly utilized" on an
//!   element or its attributes.
//! - The enveloped-signature transform: remove the ONE `<ds:Signature>`
//!   the verifier is checking (see [`EnvelopedSignature`]).
//! - Proper escape of text and attribute content per c14n rules.
//!
//! NOT supported:
//! - Processing instructions inside the canonicalized subtree.
//! - Mixed-content elements with significant whitespace from entity
//!   expansion.
//! - Inclusive namespace prefix lists (`InclusiveNamespaces`).
//! - `#WithComments` (deliberate — Hearth never emits comments).
//!
//! Any input that uses the unsupported features produces a
//! `SamlUnsupportedAlgorithm` error rather than silent misbehavior.

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::collections::BTreeMap;

use super::xml::{
    escape_attr, escape_text, ns, parse_err, resolve_entity_ref, unescape_attr_value, unescape_text,
};
use crate::identity::error::IdentityError;
use crate::identity::federation::saml::SamlError;

/// What the enveloped-signature transform removes from the canonical form.
///
/// XML-DSIG's enveloped-signature transform removes exactly one element: the
/// `<ds:Signature>` that contains the transform — the signature being
/// verified. Removing any other element hides it from the digest while every
/// parser still sees it. Hearth used to remove *every* direct-child
/// `<ds:Signature>`, so a second one appended to a signed assertion could
/// carry forged SAML elements under an unchanged digest (GA audit 3, G-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopedSignature {
    /// No transform: every node is canonicalized. Used when signing (the
    /// signature does not exist yet) and for `<ds:SignedInfo>`.
    Keep,
    /// Remove exactly one element: the `<ds:Signature>` that is a direct child
    /// of the root and whose start tag begins at this byte offset of the
    /// input. Canonicalization fails if that element is not there or is not a
    /// `<ds:Signature>`.
    RemoveAt(usize),
}

/// Canonicalizes the element subtree contained in `xml`, applying the
/// exclusive C14N 1.0 rules.
///
/// `enveloped` selects the one `<ds:Signature>` (if any) the
/// enveloped-signature transform removes. Every other `<ds:Signature>` —
/// a second direct child, or one inside a nested `<Assertion>` — is
/// canonicalized like any other element and so stays covered by the digest.
///
/// `xml` MUST contain exactly one top-level element (the signed element
/// extracted via `xml::find_element_range`).
///
/// # Errors
///
/// Returns a parse error on malformed input, `SamlError::UnsupportedAlgorithm`
/// on a `DOCTYPE`, and `SamlError::Signature` when
/// [`EnvelopedSignature::RemoveAt`] does not name a direct-child
/// `<ds:Signature>`.
pub fn canonicalize(xml: &[u8], enveloped: EnvelopedSignature) -> Result<Vec<u8>, IdentityError> {
    canonicalize_with_inherited(xml, enveloped, &BTreeMap::new())
}

/// Canonicalizes with a known "declared but not emitted" namespace context.
///
/// When we extract a subtree from a larger document for canonicalization
/// (e.g. the `<ds:SignedInfo>` inside `<ds:Signature>`), the extracted
/// bytes reference a prefix that was declared on an ancestor outside our
/// subtree. We need to:
///
/// 1. Resolve the prefix correctly (the `declared_inherited` context).
/// 2. Still emit an xmlns decl for the prefix on the subtree's root
///    because no canonical ancestor of *our* processing has emitted it.
///
/// Exclusive-C14N's emission rule is "decl emitted if visibly utilized
/// AND not already emitted on a canonical ancestor". A prefix declared
/// in source but not on a canonical ancestor of the current
/// canonicalization IS emitted.
///
/// # Errors
///
/// As [`canonicalize`].
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
pub fn canonicalize_with_inherited(
    xml: &[u8],
    enveloped: EnvelopedSignature,
    declared_inherited: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<Vec<u8>, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    let cfg = reader.config_mut();
    cfg.expand_empty_elements = false;
    cfg.trim_text(false);

    let mut out: Vec<u8> = Vec::with_capacity(xml.len());
    let mut buf = Vec::new();
    // `emitted_stack` always starts empty — from this canonicalization's
    // perspective there are no canonical ancestors. `declared_stack` is
    // seeded with the caller-supplied inherited-declaration context so
    // element-prefix resolution finds the right URI.
    let mut emitted_stack: Vec<BTreeMap<Vec<u8>, Vec<u8>>> = vec![BTreeMap::new()];
    let mut declared_stack: Vec<BTreeMap<Vec<u8>, Vec<u8>>> = vec![declared_inherited.clone()];
    let mut skip_depth: Option<i32> = None;
    let mut depth: i32 = 0;
    // The byte offset of the one `<ds:Signature>` to remove, and whether it
    // was found. A requested removal that never happens means the caller's
    // idea of "the verified signature" does not match this document.
    let remove_at = match enveloped {
        EnvelopedSignature::Keep => None,
        EnvelopedSignature::RemoveAt(offset) => Some(offset),
    };
    let mut removed = false;
    // Track the visible prefixes used on the current element so namespace
    // decls can be emitted on the output tag in exclusive form.
    loop {
        let pos_before = reader.buffer_position() as usize;
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                depth += 1;
                if let Some(d) = skip_depth {
                    // Inside a stripped subtree; keep tracking depth but
                    // emit nothing.
                    if depth > d {
                        emitted_stack.push(emitted_stack.last().cloned().unwrap_or_default());
                        declared_stack.push(declared_stack.last().cloned().unwrap_or_default());
                        buf.clear();
                        continue;
                    }
                }

                let (is_signature, rendered) =
                    process_start(&e, &mut emitted_stack, &mut declared_stack, false)?;
                if depth == 2 && remove_at == Some(pos_before) {
                    // Enveloped-signature transform: drop the verified
                    // <Signature> subtree — and only that one. depth==2
                    // because root is depth 1; Signature is a direct child.
                    if !is_signature {
                        return Err(IdentityError::Saml(SamlError::Signature));
                    }
                    skip_depth = Some(depth);
                    removed = true;
                } else {
                    out.extend_from_slice(rendered.as_bytes());
                }
            }
            Ok(Event::Empty(e)) => {
                depth += 1;
                if let Some(d) = skip_depth {
                    if depth > d {
                        buf.clear();
                        depth -= 1;
                        continue;
                    }
                }
                let (is_signature, rendered) =
                    process_start(&e, &mut emitted_stack, &mut declared_stack, true)?;
                if depth == 2 && remove_at == Some(pos_before) {
                    // The verified (empty) <Signature>: nothing to emit.
                    if !is_signature {
                        return Err(IdentityError::Saml(SamlError::Signature));
                    }
                    removed = true;
                } else {
                    out.extend_from_slice(rendered.as_bytes());
                }
                emitted_stack.pop();
                declared_stack.pop();
                depth -= 1;
            }
            Ok(Event::End(e)) => {
                if let Some(d) = skip_depth {
                    if depth == d {
                        skip_depth = None;
                        emitted_stack.pop();
                        declared_stack.pop();
                        depth -= 1;
                        buf.clear();
                        continue;
                    }
                    if depth > d {
                        emitted_stack.pop();
                        declared_stack.pop();
                        depth -= 1;
                        buf.clear();
                        continue;
                    }
                }
                out.push(b'<');
                out.push(b'/');
                out.extend_from_slice(e.name().as_ref());
                out.push(b'>');
                emitted_stack.pop();
                declared_stack.pop();
                depth -= 1;
            }
            Ok(Event::Text(t)) => {
                if skip_depth.is_some() {
                    buf.clear();
                    continue;
                }
                let raw = unescape_text(&t).map_err(|e| parse_err(e.to_string()))?;
                let escaped = escape_text(raw.as_ref());
                out.extend_from_slice(escaped.as_bytes());
            }
            Ok(Event::GeneralRef(r)) => {
                if skip_depth.is_some() {
                    buf.clear();
                    continue;
                }
                // quick-xml 0.41 emits escaped characters as standalone
                // entity-reference events. Resolve then re-escape so the
                // canonical output matches the source's textual content.
                let resolved = resolve_entity_ref(&r)?;
                let escaped = escape_text(&resolved);
                out.extend_from_slice(escaped.as_bytes());
            }
            Ok(Event::CData(c)) => {
                if skip_depth.is_some() {
                    buf.clear();
                    continue;
                }
                let s = std::str::from_utf8(c.as_ref()).map_err(|e| parse_err(e.to_string()))?;
                let escaped = escape_text(s);
                out.extend_from_slice(escaped.as_bytes());
            }
            Ok(Event::Eof) => break,
            Ok(Event::Comment(_) | Event::Decl(_) | Event::PI(_)) => {
                // Skip per c14n rules (we never emit these, and comments
                // are off per our #WithComments-free variant).
            }
            Ok(Event::DocType(_)) => {
                return Err(IdentityError::Saml(SamlError::UnsupportedAlgorithm));
            }
            Err(e) => return Err(parse_err(format!("c14n parse error: {e}"))),
        }
        buf.clear();
    }

    if remove_at.is_some() && !removed {
        return Err(IdentityError::Saml(SamlError::Signature));
    }
    Ok(out)
}

#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
fn process_start(
    start: &BytesStart<'_>,
    emitted_stack: &mut Vec<BTreeMap<Vec<u8>, Vec<u8>>>,
    declared_stack: &mut Vec<BTreeMap<Vec<u8>, Vec<u8>>>,
    self_closing: bool,
) -> Result<(bool, String), IdentityError> {
    // Two views:
    //   `emitted_parent` — decls that have been EMITTED on canonical
    //      ancestors. Used for exclusive-C14N dedup: a decl is only
    //      emitted here if the parent canonical form did not already
    //      emit the same prefix→URI binding.
    //   `declared_parent` — every decl the SOURCE XML has declared on
    //      an ancestor. Used for prefix resolution so we can identify
    //      the element namespace even when the xmlns decl was
    //      suppressed from the canonical output further up.
    let emitted_parent = emitted_stack.last().cloned().unwrap_or_default();
    let declared_parent = declared_stack.last().cloned().unwrap_or_default();

    let mut source_ns: BTreeMap<Vec<u8>, Vec<u8>> = declared_parent.clone();
    let mut regular_attrs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    for a in start.attributes().with_checks(false) {
        let a = a.map_err(|e| parse_err(format!("bad attribute: {e}")))?;
        let key = a.key.as_ref().to_vec();
        let val = unescape_attr_value(&a)?.into_bytes();
        if key == b"xmlns" || key.starts_with(b"xmlns:") {
            let prefix = if key == b"xmlns" {
                Vec::new()
            } else {
                key[6..].to_vec()
            };
            source_ns.insert(prefix, val);
        } else {
            regular_attrs.push((key, val));
        }
    }

    // Determine visibly utilized prefixes:
    // 1. The element's own prefix.
    // 2. Every prefix used in regular attribute names (excluding `xml:`
    //    which is implicit).
    let name = start.name();
    let name_bytes = name.as_ref();
    let elem_prefix: Vec<u8> = match name_bytes.iter().position(|&b| b == b':') {
        Some(i) => name_bytes[..i].to_vec(),
        None => Vec::new(),
    };

    let mut visible: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    if let Some(uri) = source_ns.get(&elem_prefix) {
        visible.insert(elem_prefix.clone(), uri.clone());
    }
    for (k, _) in &regular_attrs {
        if let Some(i) = k.iter().position(|&b| b == b':') {
            let pfx = k[..i].to_vec();
            if pfx == b"xml" {
                continue;
            }
            if let Some(uri) = source_ns.get(&pfx) {
                visible.insert(pfx, uri.clone());
            }
        }
    }

    // Exclusive dedup: emit a decl only if it wasn't already emitted on
    // a canonical ancestor with the same URI.
    let mut emitted_decls: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (pfx, uri) in &visible {
        if emitted_parent.get(pfx) != Some(uri) {
            emitted_decls.push((pfx.clone(), uri.clone()));
        }
    }

    // Push the source-declared context for children (regardless of what
    // got emitted). Needed so `<ds:Signature>` is recognized even when
    // its xmlns:ds was declared on an ancestor and suppressed from the
    // canonical output.
    declared_stack.push(source_ns.clone());

    // Build the new emitted-scope for children: parent's emitted set
    // plus the decls we just emitted on this element.
    let mut emitted_here = emitted_parent.clone();
    for (pfx, uri) in &emitted_decls {
        emitted_here.insert(pfx.clone(), uri.clone());
    }
    emitted_stack.push(emitted_here);
    // Sort decls: default first, then prefixes alphabetical.
    emitted_decls.sort_by(|a, b| match (a.0.is_empty(), b.0.is_empty()) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.0.cmp(&b.0),
    });

    // Sort regular attrs alphabetically by fully-qualified name (c14n
    // says: sort by namespace URI then local name; simplified here to
    // byte-sort on the raw attribute key which matches in practice for
    // our SAML output since we use consistent prefixes).
    regular_attrs.sort_by(|a, b| a.0.cmp(&b.0));

    // Build the rendered start tag.
    let mut out = String::new();
    out.push('<');
    out.push_str(std::str::from_utf8(name_bytes).map_err(|e| parse_err(e.to_string()))?);

    for (pfx, uri) in &emitted_decls {
        out.push(' ');
        if pfx.is_empty() {
            out.push_str("xmlns=\"");
        } else {
            out.push_str("xmlns:");
            out.push_str(std::str::from_utf8(pfx).map_err(|e| parse_err(e.to_string()))?);
            out.push_str("=\"");
        }
        out.push_str(&escape_attr(
            std::str::from_utf8(uri).map_err(|e| parse_err(e.to_string()))?,
        ));
        out.push('"');
    }
    for (k, v) in &regular_attrs {
        out.push(' ');
        out.push_str(std::str::from_utf8(k).map_err(|e| parse_err(e.to_string()))?);
        out.push_str("=\"");
        out.push_str(&escape_attr(
            std::str::from_utf8(v).map_err(|e| parse_err(e.to_string()))?,
        ));
        out.push('"');
    }

    if self_closing {
        // In c14n, empty elements are written as <tag></tag> (no
        // self-closing form in the canonical output).
        out.push('>');
        out.push_str("</");
        out.push_str(std::str::from_utf8(name_bytes).map_err(|e| parse_err(e.to_string()))?);
        out.push('>');
    } else {
        out.push('>');
    }

    // Detect whether this element is <ds:Signature> in the XMLDSIG
    // namespace.
    let is_signature = match (elem_prefix.as_slice(), source_ns.get(&elem_prefix)) {
        (p, Some(uri)) if uri.as_slice() == ns::DS.as_bytes() => {
            // local name must be "Signature"
            let local = if p.is_empty() {
                name_bytes
            } else {
                &name_bytes[p.len() + 1..]
            };
            local == b"Signature"
        }
        _ => false,
    };

    Ok((is_signature, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canon_preserves_simple_element() {
        let xml = br#"<root xmlns="http://example.com/ns">hello</root>"#;
        let out = canonicalize(xml, EnvelopedSignature::Keep).expect("canon");
        let s = std::str::from_utf8(&out).expect("utf8");
        assert_eq!(s, r#"<root xmlns="http://example.com/ns">hello</root>"#);
    }

    #[test]
    fn canon_sorts_attributes() {
        let xml = br#"<root z="1" a="2" m="3"/>"#;
        let out = canonicalize(xml, EnvelopedSignature::Keep).expect("canon");
        let s = std::str::from_utf8(&out).expect("utf8");
        assert_eq!(s, r#"<root a="2" m="3" z="1"></root>"#);
    }

    #[test]
    fn canon_escapes_text() {
        let xml = br"<root>a&amp;b&lt;c</root>";
        let out = canonicalize(xml, EnvelopedSignature::Keep).expect("canon");
        let s = std::str::from_utf8(&out).expect("utf8");
        assert_eq!(s, r"<root>a&amp;b&lt;c</root>");
    }

    /// Byte offset of the `nth` (0-based) occurrence of `needle` in `xml`.
    fn offset_of(xml: &[u8], needle: &str, nth: usize) -> usize {
        let s = std::str::from_utf8(xml).expect("utf8");
        s.match_indices(needle)
            .nth(nth)
            .unwrap_or_else(|| panic!("occurrence {nth} of {needle:?} not present"))
            .0
    }

    const ONE_SIGNATURE: &[u8] = br#"<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><Issuer>x</Issuer><ds:Signature><ds:SignedInfo></ds:SignedInfo></ds:Signature><Status/></Response>"#;

    #[test]
    fn canon_strips_envelope_signature() {
        let at = offset_of(ONE_SIGNATURE, "<ds:Signature", 0);
        let out = canonicalize(ONE_SIGNATURE, EnvelopedSignature::RemoveAt(at)).expect("canon");
        let s = std::str::from_utf8(&out).expect("utf8");
        assert!(
            !s.contains("Signature"),
            "signature should be stripped: {s}"
        );
        assert!(s.contains("Issuer"));
        assert!(s.contains("Status"));
    }

    /// `Keep` canonicalizes the signature like any other element — the
    /// signer's view, before the signature exists.
    #[test]
    fn canon_keep_leaves_a_signature_in_place() {
        let out = canonicalize(ONE_SIGNATURE, EnvelopedSignature::Keep).expect("canon");
        let s = std::str::from_utf8(&out).expect("utf8");
        assert!(s.contains("<ds:Signature"), "Keep must not strip: {s}");
    }

    /// G-1: the transform removes ONE signature — the verified one. A second
    /// direct-child `<ds:Signature>` stays in the canonical form, so anything
    /// hidden in it changes the digest.
    #[test]
    fn canon_removes_only_the_named_signature() {
        let xml = br#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="a1"><ds:Signature><ds:SignedInfo>real</ds:SignedInfo></ds:Signature><Subject>mallory</Subject><ds:Signature><Subject>ceo</Subject></ds:Signature></Assertion>"#;
        let at = offset_of(xml, "<ds:Signature", 0);
        let out = canonicalize(xml, EnvelopedSignature::RemoveAt(at)).expect("canon");
        let s = std::str::from_utf8(&out).expect("utf8");
        assert!(
            !s.contains("real"),
            "the named signature must be removed: {s}"
        );
        assert!(
            s.contains("<Subject>ceo</Subject>"),
            "a second signature must stay covered by the digest: {s}"
        );
    }

    /// The second signature can be the one named — position is irrelevant —
    /// and then the first one is the one that stays.
    #[test]
    fn canon_removal_follows_the_offset_not_the_position() {
        let xml = br#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="a1"><ds:Signature>first</ds:Signature><Subject>s</Subject><ds:Signature>second</ds:Signature></Assertion>"#;
        let at = offset_of(xml, "<ds:Signature", 1);
        let out = canonicalize(xml, EnvelopedSignature::RemoveAt(at)).expect("canon");
        let s = std::str::from_utf8(&out).expect("utf8");
        assert!(s.contains("first") && !s.contains("second"), "{s}");
    }

    /// An offset that names something other than a direct-child
    /// `<ds:Signature>` is a caller/document mismatch and fails closed.
    #[test]
    fn canon_refuses_an_offset_that_is_not_a_signature() {
        let at = offset_of(ONE_SIGNATURE, "<Issuer", 0);
        let err = canonicalize(ONE_SIGNATURE, EnvelopedSignature::RemoveAt(at))
            .expect_err("an offset naming <Issuer> must be refused");
        assert!(
            matches!(err, IdentityError::Saml(SamlError::Signature)),
            "wrong error: {err:?}"
        );
    }

    /// An offset that matches no element at all fails closed rather than
    /// silently canonicalizing with nothing removed.
    #[test]
    fn canon_refuses_an_offset_that_matches_nothing() {
        let at = offset_of(ONE_SIGNATURE, "<ds:Signature", 0) + 1;
        let err = canonicalize(ONE_SIGNATURE, EnvelopedSignature::RemoveAt(at))
            .expect_err("an offset inside a tag must be refused");
        assert!(
            matches!(err, IdentityError::Saml(SamlError::Signature)),
            "wrong error: {err:?}"
        );
    }

    /// A `<ds:Signature>` below the root's direct children is never the
    /// enveloped one, even when the offset names it.
    #[test]
    fn canon_refuses_an_offset_naming_a_nested_signature() {
        let xml = br#"<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><Wrap><ds:Signature>deep</ds:Signature></Wrap></Response>"#;
        let at = offset_of(xml, "<ds:Signature", 0);
        let err = canonicalize(xml, EnvelopedSignature::RemoveAt(at))
            .expect_err("a nested signature is not the enveloped one");
        assert!(
            matches!(err, IdentityError::Saml(SamlError::Signature)),
            "wrong error: {err:?}"
        );
    }
}
