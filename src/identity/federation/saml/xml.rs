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
use std::collections::BTreeMap;
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

/// Prefix → namespace-URI bindings in scope at some point of a document.
/// The empty prefix is the default namespace.
pub type Namespaces = BTreeMap<Vec<u8>, Vec<u8>>;

/// The namespace bindings in scope while scanning: one frame per open
/// element, each the complete scope for that element.
///
/// Element matching keys on the namespace URI a prefix is bound to here —
/// never on how the prefix is spelled. Hearth used to resolve a prefix only
/// from an `xmlns` on the element itself and otherwise accept `ds`, `saml`,
/// `samlp`, … as their conventional namespaces whatever they were bound to.
/// That both rejected legitimate IdP output (Entra ID's unprefixed
/// `<Signature xmlns="…xmldsig#">` whose children inherit the default
/// namespace) and let a scanner disagree with the canonicalizer, which does
/// resolve through ancestors (GA audit 3, round 2).
struct NsScope {
    base: Namespaces,
    frames: Vec<Namespaces>,
}

impl NsScope {
    /// Starts a scan whose first element inherits `inherited` (the bindings
    /// in scope for it in the enclosing document, if the scan is of a slice).
    fn new(inherited: &Namespaces) -> Self {
        Self {
            base: inherited.clone(),
            frames: Vec::new(),
        }
    }

    /// The bindings in scope at the current position.
    fn current(&self) -> &Namespaces {
        self.frames.last().unwrap_or(&self.base)
    }

    /// Enters `e`: its own `xmlns` declarations apply to it and to its
    /// descendants until the matching [`NsScope::leave`].
    fn enter(&mut self, e: &BytesStart<'_>) -> Result<(), IdentityError> {
        let mut scope = self.current().clone();
        for a in e.attributes().with_checks(false) {
            let a = a.map_err(|err| parse_err(format!("bad attribute: {err}")))?;
            let key = a.key.as_ref();
            let prefix = if key == b"xmlns" {
                Some(&key[..0])
            } else {
                key.strip_prefix(b"xmlns:")
            };
            if let Some(prefix) = prefix {
                scope.insert(prefix.to_vec(), unescape_attr_value(&a)?.into_bytes());
            }
        }
        self.frames.push(scope);
        Ok(())
    }

    /// Leaves the innermost entered element.
    fn leave(&mut self) {
        self.frames.pop();
    }

    /// Whether `e` — already [entered](NsScope::enter) — is `{namespace_uri}local`.
    fn is(&self, e: &BytesStart<'_>, namespace_uri: &str, local: &str) -> bool {
        e.local_name().as_ref() == local.as_bytes()
            && element_namespace(self.current(), e) == Some(namespace_uri.as_bytes())
    }
}

/// The namespace URI `e`'s prefix is bound to in `scope`, or `None` when the
/// element is in no namespace (unbound prefix, no default namespace, or the
/// default namespace undeclared with `xmlns=""`).
fn element_namespace<'s>(scope: &'s Namespaces, e: &BytesStart<'_>) -> Option<&'s [u8]> {
    let name = e.name();
    let qname = name.as_ref();
    let prefix = match qname.iter().position(|&b| b == b':') {
        Some(colon) => &qname[..colon],
        None => &[],
    };
    scope
        .get(prefix)
        .map(Vec::as_slice)
        .filter(|uri| !uri.is_empty())
}

/// An element's start tag together with the namespace URI it resolves to in
/// its document — what [`walk_outside_signatures`] reports.
#[derive(Clone, Copy)]
pub struct ElementRef<'a> {
    start: &'a BytesStart<'a>,
    namespace: Option<&'a [u8]>,
}

impl ElementRef<'_> {
    /// Whether this is the element `{namespace_uri}local`, by namespace URI.
    #[must_use]
    pub fn is(&self, namespace_uri: &str, local: &str) -> bool {
        self.start.local_name().as_ref() == local.as_bytes()
            && self.namespace == Some(namespace_uri.as_bytes())
    }

    /// The value of the unprefixed attribute `name`, if present.
    #[must_use]
    pub fn attr(&self, name: &str) -> Option<String> {
        attr(self.start, name)
    }

    /// The element's local name (without prefix).
    #[must_use]
    pub fn local_name(&self) -> &[u8] {
        self.start.local_name().into_inner()
    }
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
///
/// # Errors
///
/// Returns a parse error on malformed XML, on a `DOCTYPE` declaration, or
/// when the document exceeds `MAX_SAML_XML_EVENTS`.
pub fn find_element_range(
    xml: &[u8],
    namespace_uri: &str,
    local: &str,
    id_attr: Option<&str>,
) -> Result<Option<(usize, usize)>, IdentityError> {
    find_element_range_at_depth(xml, &Namespaces::new(), namespace_uri, local, id_attr, None)
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
/// `xml` is scanned as a whole document; for a slice of a larger document
/// use [`find_child_element_range_in`] with the slice's inherited bindings.
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
    find_child_element_range_in(xml, &Namespaces::new(), namespace_uri, local)
}

/// [`find_child_element_range`] over a slice of a larger document whose root
/// element inherits the namespace bindings `inherited` (see
/// [`in_scope_namespaces`]).
///
/// # Errors
///
/// As [`find_child_element_range`].
pub fn find_child_element_range_in(
    xml: &[u8],
    inherited: &Namespaces,
    namespace_uri: &str,
    local: &str,
) -> Result<Option<(usize, usize)>, IdentityError> {
    // Root element is depth 1, so its direct children sit at depth 2.
    find_element_range_at_depth(xml, inherited, namespace_uri, local, None, Some(2))
}

/// Shared scanner for [`find_element_range`] and [`find_child_element_range`].
///
/// `required_depth`, when set, restricts matching to elements opening at
/// exactly that depth (the document's root element is depth 1).
fn find_element_range_at_depth(
    xml: &[u8],
    inherited: &Namespaces,
    namespace_uri: &str,
    local: &str,
    id_attr: Option<&str>,
    required_depth: Option<usize>,
) -> Result<Option<(usize, usize)>, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut scope = NsScope::new(inherited);
    let mut buf = Vec::new();
    let mut depth: usize = 0;
    // Depth at which we found the first matching Start. We emit when the
    // corresponding End closes at this depth.
    let mut target_depth: Option<usize> = None;
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
                scope.enter(e)?;
                if target_depth.is_none()
                    && required_depth.is_none_or(|want| want == depth)
                    && scope.is(e, namespace_uri, local)
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
                scope.leave();
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Empty(ref e)) => {
                let pos_after = reader.buffer_position() as usize;
                // An `Empty` event does not move `depth`, so the element it
                // represents sits one level below the currently-open element.
                scope.enter(e)?;
                let hit = target_depth.is_none()
                    && required_depth.is_none_or(|want| want == depth + 1)
                    && scope.is(e, namespace_uri, local)
                    && id_match(e, id_attr);
                scope.leave();
                if hit {
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

/// The namespace bindings in scope for the element whose start tag begins at
/// byte `offset` of `xml` — its parent's scope, before its own declarations.
///
/// Pass the result as `inherited` when scanning or canonicalizing that
/// element as a slice: exclusive C14N renders a visibly used namespace
/// declaration on the apex of a canonicalized subtree even when it was
/// declared on an ancestor, and element matching must see the same bindings.
///
/// # Errors
///
/// Returns a parse error on malformed XML, a `DOCTYPE`, more than
/// `MAX_SAML_XML_EVENTS` events, or when no element starts at `offset`.
pub fn in_scope_namespaces(
    xml: &[u8],
    inherited: &Namespaces,
    offset: usize,
) -> Result<Namespaces, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut scope = NsScope::new(inherited);
    let mut buf = Vec::new();
    let mut event_count: usize = 0;
    loop {
        let pos_before = reader.buffer_position() as usize;
        event_count += 1;
        if event_count > crate::abuse::MAX_SAML_XML_EVENTS {
            return Err(parse_err("XML document exceeds maximum element limit"));
        }
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                if pos_before == offset {
                    return Ok(scope.current().clone());
                }
                scope.enter(e)?;
            }
            Ok(Event::Empty(_)) if pos_before == offset => {
                return Ok(scope.current().clone());
            }
            Ok(Event::End(_)) => scope.leave(),
            Ok(Event::DocType(_)) => {
                return Err(parse_err("DOCTYPE declarations are rejected"));
            }
            Ok(Event::Eof) => return Err(parse_err("no element starts at the given offset")),
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

    let mut scope = NsScope::new(&Namespaces::new());
    let mut buf = Vec::new();
    let mut count: usize = 0;
    let mut event_count: usize = 0;

    loop {
        event_count += 1;
        if event_count > crate::abuse::MAX_SAML_XML_EVENTS {
            return Err(parse_err("XML document exceeds maximum element limit"));
        }
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                scope.enter(e)?;
                if scope.is(e, namespace_uri, local) {
                    count += 1;
                }
            }
            Ok(Event::Empty(ref e)) => {
                scope.enter(e)?;
                if scope.is(e, namespace_uri, local) {
                    count += 1;
                }
                scope.leave();
            }
            Ok(Event::End(_)) => scope.leave(),
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

/// Refuses a `<ds:Signature>` anywhere the SAML SP profile does not put one.
///
/// A signature is allowed only as a direct child of the root
/// `<samlp:Response>` or of a `<saml:Assertion>`, and at most one per parent
/// (scope-trim-trusted-core, strict SP profile). Any other `<ds:Signature>` —
/// inside `<samlp:Status>`, `<saml:Subject>`, another signature's `<KeyInfo>`
/// or `<Object>`, or a second one under the same parent — is a region no
/// verifier looks at. The parsers already never read inside one; refusing
/// the document outright removes the region instead of trusting every reader
/// to skip it.
///
/// # Errors
///
/// Returns [`SamlError::Signature`] on a misplaced or duplicate signature, and
/// a parse error on malformed XML, a `DOCTYPE`, or more than
/// `MAX_SAML_XML_EVENTS` events.
pub fn check_signature_placement(xml: &[u8]) -> Result<(), IdentityError> {
    /// One open element: may it hold a signature, and has it got one yet?
    struct Frame {
        may_hold_signature: bool,
        has_signature: bool,
    }
    let misplaced = || IdentityError::Saml(SamlError::Signature);

    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut scope = NsScope::new(&Namespaces::new());
    let mut buf = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut event_count: usize = 0;

    loop {
        event_count += 1;
        if event_count > crate::abuse::MAX_SAML_XML_EVENTS {
            return Err(parse_err("XML document exceeds maximum element limit"));
        }
        let (start, empty) = match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => (e.into_owned(), false),
            Ok(Event::Empty(e)) => (e.into_owned(), true),
            Ok(Event::End(_)) => {
                scope.leave();
                stack.pop();
                buf.clear();
                continue;
            }
            Ok(Event::DocType(_)) => {
                return Err(parse_err("DOCTYPE declarations are rejected"));
            }
            Ok(Event::Eof) => return Ok(()),
            Err(e) => return Err(parse_err(format!("XML scan error: {e}"))),
            Ok(_) => {
                buf.clear();
                continue;
            }
        };
        scope.enter(&start)?;
        if scope.is(&start, ns::DS, "Signature") {
            match stack.last_mut() {
                Some(parent) if parent.may_hold_signature && !parent.has_signature => {
                    parent.has_signature = true;
                }
                _ => return Err(misplaced()),
            }
        }
        let is_root_response = stack.is_empty() && scope.is(&start, ns::SAMLP, "Response");
        let may_hold_signature = is_root_response || scope.is(&start, ns::SAML, "Assertion");
        if empty {
            scope.leave();
        } else {
            stack.push(Frame {
                may_hold_signature,
                has_signature: false,
            });
        }
        buf.clear();
    }
}

/// Counts the **direct children of the root element** of `xml` (a slice
/// whose root inherits `inherited`) with the given (namespace_uri,
/// local_name).
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
    inherited: &Namespaces,
    namespace_uri: &str,
    local: &str,
) -> Result<usize, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut scope = NsScope::new(inherited);
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
                scope.enter(e)?;
                if depth == 2 && scope.is(e, namespace_uri, local) {
                    count += 1;
                }
            }
            // An `Empty` event does not move `depth`: the element sits one
            // level below the currently open one.
            Ok(Event::Empty(ref e)) => {
                scope.enter(e)?;
                if depth + 1 == 2 && scope.is(e, namespace_uri, local) {
                    count += 1;
                }
                scope.leave();
            }
            Ok(Event::End(_)) => {
                scope.leave();
                depth = depth.saturating_sub(1);
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

/// A direct child of a slice's root element, as [`child_elements`] reports it.
pub struct ChildElement {
    /// The namespace URI the child's prefix is bound to, if any.
    pub namespace: Option<Vec<u8>>,
    /// The child's local name.
    pub local_name: Vec<u8>,
    /// The child's byte range in the scanned slice (start and end tags
    /// included).
    pub range: (usize, usize),
    /// The child's own text content (entity references resolved; the text of
    /// its descendants is not included).
    pub text: String,
}

/// Lists the direct children of the root element of `xml` — a slice whose
/// root inherits the bindings `inherited` — each with the namespace it
/// resolves to, in document order.
///
/// # Errors
///
/// Returns a parse error on malformed XML, a `DOCTYPE`, a disallowed entity
/// reference, or more than `MAX_SAML_XML_EVENTS` events.
pub fn child_elements(
    xml: &[u8],
    inherited: &Namespaces,
) -> Result<Vec<ChildElement>, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    let cfg = reader.config_mut();
    cfg.expand_empty_elements = false;
    cfg.trim_text(false);

    let mut scope = NsScope::new(inherited);
    let mut buf = Vec::new();
    let mut depth: usize = 0;
    let mut children: Vec<ChildElement> = Vec::new();
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
                scope.enter(e)?;
                if depth == 2 {
                    children.push(ChildElement {
                        namespace: element_namespace(scope.current(), e).map(<[u8]>::to_vec),
                        local_name: e.local_name().as_ref().to_vec(),
                        range: (pos_before, pos_before),
                        text: String::new(),
                    });
                }
            }
            Ok(Event::Empty(ref e)) => {
                scope.enter(e)?;
                if depth + 1 == 2 {
                    children.push(ChildElement {
                        namespace: element_namespace(scope.current(), e).map(<[u8]>::to_vec),
                        local_name: e.local_name().as_ref().to_vec(),
                        range: (pos_before, reader.buffer_position() as usize),
                        text: String::new(),
                    });
                }
                scope.leave();
            }
            Ok(Event::End(_)) => {
                if depth == 2 {
                    if let Some(child) = children.last_mut() {
                        child.range.1 = reader.buffer_position() as usize;
                    }
                }
                scope.leave();
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Text(ref t)) if depth == 2 => {
                let text = unescape_text(t).map_err(|e| parse_err(e.to_string()))?;
                if let Some(child) = children.last_mut() {
                    child.text.push_str(&text);
                }
            }
            Ok(Event::GeneralRef(ref r)) if depth == 2 => {
                let text = resolve_entity_ref(r)?;
                if let Some(child) = children.last_mut() {
                    child.text.push_str(&text);
                }
            }
            Ok(Event::DocType(_)) => {
                return Err(parse_err("DOCTYPE declarations are rejected"));
            }
            Ok(Event::Eof) => return Ok(children),
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
        /// The element, with the namespace it resolves to.
        element: ElementRef<'a>,
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
/// `parse_idp_metadata`) reads the document through this walker, so none of
/// them can.
///
/// Elements are identified by the namespace URI their prefix is bound to in
/// scope ([`ElementRef::is`]), so a `<Signature>` in an inherited default
/// DSIG namespace is recognised and skipped exactly like a `<ds:Signature>`.
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

    let mut scope = NsScope::new(&Namespaces::new());
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
                scope.enter(e)?;
                if skipping.is_none() {
                    if scope.is(e, ns::DS, "Signature") {
                        skipping = Some(depth);
                    } else {
                        let element = ElementRef {
                            start: e,
                            namespace: element_namespace(scope.current(), e),
                        };
                        visit(XmlStep::Open { element, depth })?;
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
                scope.enter(e)?;
                if skipping.is_none() && !scope.is(e, ns::DS, "Signature") {
                    let element = ElementRef {
                        start: e,
                        namespace: element_namespace(scope.current(), e),
                    };
                    visit(XmlStep::Open {
                        element,
                        depth: depth + 1,
                    })?;
                    visit(XmlStep::Close { depth: depth + 1 })?;
                }
                scope.leave();
            }
            Ok(Event::End(_)) => {
                match skipping {
                    Some(d) if d == depth => skipping = None,
                    Some(_) => {}
                    None => visit(XmlStep::Close { depth })?,
                }
                scope.leave();
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

    const DS_NS: &str = r#"xmlns:ds="http://www.w3.org/2000/09/xmldsig#""#;

    fn placement(xml: &str) -> Result<(), IdentityError> {
        check_signature_placement(xml.as_bytes())
    }

    #[test]
    fn signature_placement_allows_one_under_response_and_one_under_assertion() {
        let xml = format!(
            r#"<samlp:Response xmlns:samlp="{}" xmlns:saml="{}" {DS_NS}><ds:Signature/><saml:Assertion><ds:Signature><ds:SignedInfo/></ds:Signature></saml:Assertion></samlp:Response>"#,
            ns::SAMLP,
            ns::SAML
        );
        placement(&xml).expect("the two profile positions are allowed");
    }

    #[test]
    fn signature_placement_refuses_a_self_closing_stray_signature() {
        let xml = format!(
            r#"<samlp:Response xmlns:samlp="{}" {DS_NS}><samlp:Status><ds:Signature/></samlp:Status></samlp:Response>"#,
            ns::SAMLP
        );
        assert!(matches!(
            placement(&xml),
            Err(IdentityError::Saml(SamlError::Signature))
        ));
    }

    #[test]
    fn signature_placement_refuses_two_under_one_parent_and_one_inside_another() {
        let two = format!(
            r#"<samlp:Response xmlns:samlp="{}" {DS_NS}><ds:Signature/><ds:Signature/></samlp:Response>"#,
            ns::SAMLP
        );
        let nested = format!(
            r#"<samlp:Response xmlns:samlp="{}" {DS_NS}><ds:Signature><ds:KeyInfo><ds:Signature/></ds:KeyInfo></ds:Signature></samlp:Response>"#,
            ns::SAMLP
        );
        for xml in [two, nested] {
            assert!(
                matches!(
                    placement(&xml),
                    Err(IdentityError::Saml(SamlError::Signature))
                ),
                "{xml}"
            );
        }
    }

    #[test]
    fn signature_placement_refuses_a_signature_on_a_nested_response() {
        // Only the ROOT Response may hold one; a Response wrapped inside the
        // document is an XSW1/XSW2 shape.
        let xml = format!(
            r#"<samlp:Response xmlns:samlp="{}" {DS_NS}><samlp:Response><ds:Signature/></samlp:Response></samlp:Response>"#,
            ns::SAMLP
        );
        assert!(matches!(
            placement(&xml),
            Err(IdentityError::Saml(SamlError::Signature))
        ));
    }

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
                    String::from_utf8_lossy(element.local_name()).into_owned(),
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
            count_child_elements(xml, &Namespaces::new(), ns::DS, "Signature").expect("count"),
            2
        );
        assert_eq!(
            count_child_elements(DIRECT, &Namespaces::new(), ns::DS, "Signature").expect("count"),
            1
        );
        assert_eq!(
            count_child_elements(NESTED, &Namespaces::new(), ns::DS, "Signature").expect("count"),
            0
        );
    }

    // GA audit 3 round 2 — element matching keys on the namespace URI in
    // scope, never on the prefix spelling.

    /// `ds:` bound (on an ancestor) to some other namespace is not XML-DSIG.
    #[test]
    fn ds_prefix_bound_elsewhere_is_not_a_signature() {
        let xml = br#"<R xmlns:ds="urn:not-dsig"><ds:Signature/></R>"#;
        let found = find_child_element_range(xml, ns::DS, "Signature").expect("scan");
        assert!(found.is_none(), "prefix `ds` matched without the DSIG URI");
    }

    /// Any prefix bound to the DSIG URI on an ancestor is XML-DSIG.
    #[test]
    fn any_prefix_bound_to_dsig_on_an_ancestor_is_a_signature() {
        let xml = br#"<R xmlns:x="http://www.w3.org/2000/09/xmldsig#"><x:Signature/></R>"#;
        let found = find_child_element_range(xml, ns::DS, "Signature").expect("scan");
        assert!(
            found.is_some(),
            "a DSIG-bound prefix declared on an ancestor was missed"
        );
    }

    /// The Entra ID shape: an unprefixed element in an inherited default
    /// namespace.
    #[test]
    fn inherited_default_namespace_is_resolved() {
        let xml = br#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>x</SignedInfo></Signature>"#;
        let found = find_child_element_range(xml, ns::DS, "SignedInfo").expect("scan");
        assert!(
            found.is_some(),
            "an inherited default namespace was not applied"
        );
    }

    /// An unbound prefix is in no namespace — it is not guessed from its
    /// spelling.
    #[test]
    fn unbound_prefix_matches_nothing() {
        let xml = br"<R><ds:Signature>x</ds:Signature></R>";
        let found = find_child_element_range(xml, ns::DS, "Signature").expect("scan");
        assert!(
            found.is_none(),
            "an unbound `ds:` prefix was treated as DSIG"
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
