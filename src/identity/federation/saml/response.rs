//! `<Response>` and `<Assertion>` XML construction, parsing, and validation.

use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::BTreeMap;

use super::authn_request::{format_xsd_datetime, parse_xsd_datetime};
use super::xml::{
    attr, escape_attr, escape_text, is_element, ns, parse_err, resolve_entity_ref, unescape_text,
};
use crate::core::Timestamp;
use crate::identity::error::IdentityError;
use crate::identity::federation::saml::SamlError;

/// The `urn:oasis:names:tc:SAML:2.0:cm:bearer` subject-confirmation method.
const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// A `<SubjectConfirmationData>` carried by a bearer `<SubjectConfirmation>`
/// *inside* an `<Assertion>`.
///
/// These are the bindings the SAML 2.0 Web Browser SSO profile (§4.1.4.3)
/// requires an SP to check, and they live inside the element the IdP signs.
/// The `<Response>`-level `Destination` and `InResponseTo` are unsigned
/// whenever only the assertion carries a signature, so these are the copies
/// that actually bind the assertion to this SP and to this login attempt
/// (audit 2026-08-28 §4.10#5).
#[derive(Debug, Clone, Default)]
pub struct BearerConfirmation {
    /// `Recipient` — the ACS URL the IdP minted this assertion for.
    pub recipient: Option<String>,
    /// `NotOnOrAfter` — the bearer window, independent of `Conditions`.
    pub not_on_or_after: Option<Timestamp>,
    /// `InResponseTo` — the `AuthnRequest` ID this answers, absent for
    /// unsolicited (IdP-initiated) responses.
    pub in_response_to: Option<String>,
}

/// Parsed `<Assertion>` contents relevant to the consuming SP.
#[derive(Debug, Clone)]
pub struct Assertion {
    pub id: String,
    pub issuer: String,
    pub subject_name_id: Option<String>,
    pub subject_name_id_format: Option<String>,
    pub not_before: Option<Timestamp>,
    pub not_on_or_after: Option<Timestamp>,
    pub audience: Option<String>,
    pub attributes: BTreeMap<String, Vec<String>>,
    pub in_response_to: Option<String>,
    pub session_index: Option<String>,
    pub destination: Option<String>,
    /// Bearer `<SubjectConfirmationData>` elements found *within this
    /// assertion*. Never populated from a `<SubjectConfirmation>` that sits
    /// outside every `<saml:Assertion>` — the consumed bindings must come
    /// from the same element whose signature was verified.
    pub bearer_confirmations: Vec<BearerConfirmation>,
}

/// Parsed `<Response>` structure.
#[derive(Debug, Clone)]
pub struct SamlResponse {
    pub id: String,
    pub in_response_to: Option<String>,
    pub issue_instant: String,
    pub destination: Option<String>,
    pub issuer: String,
    pub status_code: String,
    pub assertions: Vec<Assertion>,
}

/// Builder for an IdP-issued `<Response>` with a single `<Assertion>`.
pub struct ResponseBuilder<'a> {
    pub response_id: &'a str,
    pub in_response_to: Option<&'a str>,
    pub issue_instant: Timestamp,
    pub destination: &'a str,
    pub issuer: &'a str,
    pub audience: &'a str,
    pub assertion_id: &'a str,
    pub subject_name_id: &'a str,
    pub subject_name_id_format: &'a str,
    pub session_index: &'a str,
    pub not_before: Timestamp,
    pub not_on_or_after: Timestamp,
    pub attributes: &'a BTreeMap<String, Vec<String>>,
}

/// Builds the XML for an IdP-issued `<Response>` with one `<Assertion>`.
/// Neither element is signed; signing is performed separately via the
/// `signature` module.
#[must_use]
pub fn build_response_xml(b: &ResponseBuilder<'_>) -> String {
    let mut attrs_xml = String::new();
    for (name, values) in b.attributes {
        attrs_xml.push_str(&format!(
            r#"<saml:Attribute Name="{n}">"#,
            n = escape_attr(name)
        ));
        for v in values {
            attrs_xml.push_str(&format!(
                r"<saml:AttributeValue>{v}</saml:AttributeValue>",
                v = escape_text(v)
            ));
        }
        attrs_xml.push_str("</saml:Attribute>");
    }
    let attrs_block = if attrs_xml.is_empty() {
        String::new()
    } else {
        format!("<saml:AttributeStatement>{attrs_xml}</saml:AttributeStatement>")
    };

    let in_response = b
        .in_response_to
        .map(|v| format!(r#" InResponseTo="{}""#, escape_attr(v)))
        .unwrap_or_default();
    let subj_in_response = b
        .in_response_to
        .map(|v| format!(r#" InResponseTo="{}""#, escape_attr(v)))
        .unwrap_or_default();

    let ts_resp = format_xsd_datetime(b.issue_instant);
    let ts_nb = format_xsd_datetime(b.not_before);
    let ts_noa = format_xsd_datetime(b.not_on_or_after);

    format!(
        r#"<samlp:Response xmlns:samlp="{samlp}" xmlns:saml="{saml}" ID="{rid}" Version="2.0" IssueInstant="{ts}" Destination="{dest}"{inrt}><saml:Issuer>{iss}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status><saml:Assertion ID="{aid}" Version="2.0" IssueInstant="{ts}"><saml:Issuer>{iss}</saml:Issuer><saml:Subject><saml:NameID Format="{nidf}">{nid}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{noa}" Recipient="{dest}"{subj_in}></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{nb}" NotOnOrAfter="{noa}"><saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{ts}" SessionIndex="{sidx}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>{attrs}</saml:Assertion></samlp:Response>"#,
        samlp = ns::SAMLP,
        saml = ns::SAML,
        rid = escape_attr(b.response_id),
        ts = escape_attr(&ts_resp),
        dest = escape_attr(b.destination),
        inrt = in_response,
        iss = escape_text(b.issuer),
        aid = escape_attr(b.assertion_id),
        nidf = escape_attr(b.subject_name_id_format),
        nid = escape_text(b.subject_name_id),
        noa = escape_attr(&ts_noa),
        nb = escape_attr(&ts_nb),
        subj_in = subj_in_response,
        aud = escape_text(b.audience),
        sidx = escape_attr(b.session_index),
        attrs = attrs_block,
    )
}

/// Parses a SAML `<Response>` and its `<Assertion>` children.
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
pub fn parse_response(xml: &[u8]) -> Result<SamlResponse, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut buf = Vec::new();
    let mut response_id: Option<String> = None;
    let mut in_response_to: Option<String> = None;
    let mut issue_instant: Option<String> = None;
    let mut destination: Option<String> = None;
    let mut response_issuer: Option<String> = None;
    let mut status_code: Option<String> = None;
    let mut assertions: Vec<Assertion> = Vec::new();

    let mut state = ParseState::Root;
    let mut current: Option<Assertion> = None;
    // True while inside a `<SubjectConfirmation Method="…:cm:bearer">`. A
    // `<SubjectConfirmationData>` is only recorded when this is set AND we are
    // inside an `<Assertion>` — see `Assertion::bearer_confirmations`.
    let mut in_bearer_confirmation = false;
    let mut attr_name: Option<String> = None;
    let mut attr_values: Vec<String> = Vec::new();
    let mut capturing_text: Option<TextTarget> = None;
    // Text content is accumulated here across `Text`/`GeneralRef` events and
    // committed to `capturing_text`'s target when the element closes. quick-xml
    // 0.41 tokenizes `&amp;`-style references into standalone `GeneralRef`
    // events, so a single value may span several events.
    let mut text_buf = String::new();

    // A-35: cap XML event count to prevent resource exhaustion from
    // crafted responses with thousands of elements (no DTD required).
    let mut event_count: usize = 0;

    loop {
        let ev = reader.read_event_into(&mut buf);
        event_count += 1;
        if event_count > crate::abuse::MAX_SAML_XML_EVENTS {
            return Err(parse_err("SAML response exceeds maximum XML event limit"));
        }
        match ev {
            Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                // A new element closes any capture window left dangling by a
                // self-closing capturing element (which emits no `End`).
                capturing_text = None;
                text_buf.clear();
                // Close the bearer-confirmation window on any element that is
                // neither the confirmation itself nor its data child. This
                // also covers a self-closing `<SubjectConfirmation/>`, which
                // emits no `End` event.
                if !is_element(e, ns::SAML, "SubjectConfirmation")
                    && !is_element(e, ns::SAML, "SubjectConfirmationData")
                {
                    in_bearer_confirmation = false;
                }
                if is_element(e, ns::SAMLP, "Response") {
                    response_id = attr(e, "ID");
                    in_response_to = attr(e, "InResponseTo");
                    issue_instant = attr(e, "IssueInstant");
                    destination = attr(e, "Destination");
                } else if is_element(e, ns::SAMLP, "StatusCode") && state == ParseState::Status {
                    status_code = attr(e, "Value");
                } else if is_element(e, ns::SAMLP, "Status") {
                    state = ParseState::Status;
                } else if is_element(e, ns::SAML, "Assertion") {
                    current = Some(Assertion {
                        id: attr(e, "ID").unwrap_or_default(),
                        issuer: String::new(),
                        subject_name_id: None,
                        subject_name_id_format: None,
                        not_before: None,
                        not_on_or_after: None,
                        audience: None,
                        attributes: BTreeMap::new(),
                        in_response_to: in_response_to.clone(),
                        session_index: None,
                        destination: destination.clone(),
                        bearer_confirmations: Vec::new(),
                    });
                    state = ParseState::Assertion;
                } else if is_element(e, ns::SAML, "SubjectConfirmation") {
                    in_bearer_confirmation =
                        attr(e, "Method").is_some_and(|m| m.trim() == CM_BEARER);
                } else if is_element(e, ns::SAML, "SubjectConfirmationData") {
                    // Only bindings inside the assertion count. A
                    // `<SubjectConfirmationData>` planted elsewhere in the
                    // document is outside the signed element and is ignored.
                    if in_bearer_confirmation {
                        if let Some(ref mut a) = current {
                            a.bearer_confirmations.push(BearerConfirmation {
                                recipient: attr(e, "Recipient"),
                                not_on_or_after: attr(e, "NotOnOrAfter")
                                    .and_then(|s| parse_xsd_datetime(&s)),
                                in_response_to: attr(e, "InResponseTo"),
                            });
                        }
                    }
                } else if is_element(e, ns::SAML, "Issuer") {
                    capturing_text = Some(if matches!(state, ParseState::Assertion) {
                        TextTarget::AssertionIssuer
                    } else {
                        TextTarget::ResponseIssuer
                    });
                } else if is_element(e, ns::SAML, "NameID") {
                    if let Some(ref mut a) = current {
                        a.subject_name_id_format = attr(e, "Format");
                    }
                    capturing_text = Some(TextTarget::SubjectNameId);
                } else if is_element(e, ns::SAML, "Conditions") {
                    if let Some(ref mut a) = current {
                        a.not_before = attr(e, "NotBefore").and_then(|s| parse_xsd_datetime(&s));
                        a.not_on_or_after =
                            attr(e, "NotOnOrAfter").and_then(|s| parse_xsd_datetime(&s));
                    }
                } else if is_element(e, ns::SAML, "Audience") {
                    capturing_text = Some(TextTarget::Audience);
                } else if is_element(e, ns::SAML, "AuthnStatement") {
                    if let Some(ref mut a) = current {
                        a.session_index = attr(e, "SessionIndex");
                    }
                } else if is_element(e, ns::SAML, "Attribute") {
                    attr_name = attr(e, "Name");
                    attr_values.clear();
                } else if is_element(e, ns::SAML, "AttributeValue") {
                    capturing_text = Some(TextTarget::AttributeValue);
                }
            }
            Ok(Event::Text(t)) if capturing_text.is_some() => {
                if let Ok(s) = unescape_text(&t) {
                    text_buf.push_str(&s);
                }
            }
            Ok(Event::GeneralRef(r)) if capturing_text.is_some() => {
                text_buf.push_str(&resolve_entity_ref(&r)?);
            }
            Ok(Event::End(e)) => {
                // Commit any captured text to its target. Empty content is not
                // committed, matching the pre-0.41 single-`Text`-event behavior.
                if let Some(target) = capturing_text.take() {
                    if !text_buf.is_empty() {
                        let val = std::mem::take(&mut text_buf);
                        match target {
                            TextTarget::ResponseIssuer => response_issuer = Some(val),
                            TextTarget::AssertionIssuer => {
                                if let Some(ref mut a) = current {
                                    a.issuer = val;
                                }
                            }
                            TextTarget::SubjectNameId => {
                                if let Some(ref mut a) = current {
                                    a.subject_name_id = Some(val);
                                }
                            }
                            TextTarget::Audience => {
                                if let Some(ref mut a) = current {
                                    a.audience = Some(val);
                                }
                            }
                            TextTarget::AttributeValue => attr_values.push(val),
                        }
                    }
                    text_buf.clear();
                }
                let nm = e.name();
                let name_bytes = nm.as_ref();
                if name_bytes.ends_with(b":Attribute") || name_bytes == b"Attribute" {
                    if let (Some(n), Some(a)) = (attr_name.take(), current.as_mut()) {
                        if !attr_values.is_empty() {
                            a.attributes.insert(n, std::mem::take(&mut attr_values));
                        }
                    }
                } else if name_bytes.ends_with(b":SubjectConfirmation")
                    || name_bytes == b"SubjectConfirmation"
                {
                    in_bearer_confirmation = false;
                } else if name_bytes.ends_with(b":Assertion") || name_bytes == b"Assertion" {
                    if let Some(a) = current.take() {
                        assertions.push(a);
                    }
                    state = ParseState::Root;
                } else if name_bytes.ends_with(b":Status") || name_bytes == b"Status" {
                    state = ParseState::Root;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(parse_err(format!("Response parse error: {e}"))),
            Ok(Event::DocType(_)) => return Err(parse_err("DOCTYPE declarations are rejected")),
            _ => {}
        }
        buf.clear();
    }

    Ok(SamlResponse {
        id: response_id.ok_or_else(|| parse_err("Response missing ID"))?,
        in_response_to,
        issue_instant: issue_instant.ok_or_else(|| parse_err("missing IssueInstant"))?,
        destination,
        issuer: response_issuer.unwrap_or_default(),
        status_code: status_code.ok_or_else(|| parse_err("missing StatusCode"))?,
        assertions,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    Root,
    Status,
    Assertion,
}

#[derive(Debug, Clone, Copy)]
enum TextTarget {
    ResponseIssuer,
    AssertionIssuer,
    SubjectNameId,
    Audience,
    AttributeValue,
}

/// Validates a SAML `<Response>` + `<Assertion>` for an SP.
///
/// Returns the assertion on success. Caller should have already verified
/// XML-DSIG signatures on the signed element before calling this.
pub struct ValidateParams<'a> {
    /// This SP's entity ID.
    pub sp_entity_id: &'a str,
    /// The ACS URL; must match `Destination`.
    pub acs_url: &'a str,
    /// Expected IdP entity ID.
    pub idp_entity_id: &'a str,
    /// Expected `InResponseTo` (the AuthnRequest ID we issued), or None
    /// for IdP-initiated SSO.
    pub expected_in_response_to: Option<&'a str>,
    /// Current time.
    pub now: Timestamp,
    /// Clock-skew tolerance in seconds.
    pub clock_skew_secs: i64,
}

/// Validates and extracts a single assertion from a parsed response.
///
/// On success returns the assertion. The caller is responsible for the
/// replay check (the assertion ID must not be reused) — this is done
/// externally against storage.
#[allow(clippy::too_many_lines)] // Each block is one normative SAML check.
pub fn extract_and_validate_assertion(
    resp: &SamlResponse,
    p: &ValidateParams<'_>,
) -> Result<Assertion, IdentityError> {
    // Status must be Success.
    if !resp.status_code.ends_with("status:Success") {
        return Err(IdentityError::Saml(SamlError::InvalidAuthnRequest {
            reason: format!("non-success status: {}", resp.status_code),
        }));
    }

    if resp.assertions.is_empty() {
        return Err(parse_err("no assertions in Response"));
    }
    if resp.assertions.len() > 1 {
        return Err(parse_err("multiple assertions not supported"));
    }
    let a = resp.assertions[0].clone();

    // Destination check (on the Response element).
    if let Some(ref d) = resp.destination {
        if d != p.acs_url {
            return Err(IdentityError::Saml(SamlError::DestinationMismatch));
        }
    }

    // Issuer check.
    if a.issuer != p.idp_entity_id && resp.issuer != p.idp_entity_id {
        return Err(IdentityError::Saml(SamlError::IssuerMismatch));
    }

    // Audience check.
    match &a.audience {
        Some(v) if v == p.sp_entity_id => {}
        _ => return Err(IdentityError::Saml(SamlError::AudienceMismatch)),
    }

    // Timestamps.
    //
    // S4 (HEA-1751): the assertion MUST carry a `Conditions/NotOnOrAfter`
    // bound. An assertion with no expiry never ages out and can be replayed
    // indefinitely, so a missing upper bound is rejected outright rather
    // than silently skipped. `NotBefore` remains optional per the SAML
    // profile (many IdPs omit it).
    let now_micros = p.now.as_micros();
    let skew = p.clock_skew_secs * 1_000_000;
    if let Some(nb) = a.not_before {
        if nb.as_micros() > now_micros + skew {
            return Err(IdentityError::Saml(SamlError::Expired));
        }
    }
    let noa = a
        .not_on_or_after
        .ok_or(IdentityError::Saml(SamlError::Expired))?;
    if noa.as_micros() <= now_micros - skew {
        return Err(IdentityError::Saml(SamlError::Expired));
    }

    // InResponseTo (Response level — unsigned when only the assertion is
    // signed, so the authoritative copy is the one checked below).
    if let Some(expected) = p.expected_in_response_to {
        match &resp.in_response_to {
            Some(got) if got == expected => {}
            _ => {
                return Err(IdentityError::Saml(SamlError::InvalidAuthnRequest {
                    reason: "InResponseTo mismatch".to_string(),
                }))
            }
        }
    }

    // The signed `<SubjectConfirmationData>` bindings (audit 2026-08-28
    // §4.10#5, SAML 2.0 profiles §4.1.4.3).
    //
    // These three attributes are what actually bind a bearer assertion to
    // *this* SP and to *this* login attempt, and — unlike their `<Response>`
    // level twins — they sit inside the element the IdP signed. They were
    // parsed nowhere and enforced nowhere: an assertion minted for another
    // service provider, or one whose bearer window had closed, was accepted
    // as long as the outer envelope looked right.
    //
    // `a` is the single assertion the caller has already tied to the verified
    // signature (`SamlSpService::complete_inner` refuses a document with more
    // than one `<saml:Assertion>` and compares the consumed ID against the
    // verified one), and `bearer_confirmations` is populated only from inside
    // an `<Assertion>` — so these bindings come from the verified element.
    let confirmation = match a.bearer_confirmations.as_slice() {
        [one] => one,
        [] => {
            return Err(IdentityError::Saml(SamlError::InvalidAuthnRequest {
                reason: "assertion carries no bearer SubjectConfirmationData".to_string(),
            }))
        }
        _ => {
            // Two bearer confirmations make "the" Recipient ambiguous, which
            // is exactly the ambiguity a wrapping attack wants. Refuse.
            return Err(IdentityError::Saml(SamlError::InvalidAuthnRequest {
                reason: "multiple bearer SubjectConfirmationData elements".to_string(),
            }));
        }
    };

    // Recipient MUST name this SP's ACS URL.
    match &confirmation.recipient {
        Some(r) if r == p.acs_url => {}
        _ => return Err(IdentityError::Saml(SamlError::DestinationMismatch)),
    }

    // The bearer NotOnOrAfter is mandatory and is its own window — it is
    // typically far tighter than `Conditions/NotOnOrAfter`.
    let bearer_noa = confirmation
        .not_on_or_after
        .ok_or(IdentityError::Saml(SamlError::Expired))?;
    if bearer_noa.as_micros() <= now_micros - skew {
        return Err(IdentityError::Saml(SamlError::Expired));
    }

    // InResponseTo MUST name the AuthnRequest we issued. When we issued none
    // (unsolicited / IdP-initiated) there is nothing to bind against and the
    // attribute is not consulted.
    if let Some(expected) = p.expected_in_response_to {
        match confirmation.in_response_to.as_deref() {
            Some(got) if got == expected => {}
            _ => {
                return Err(IdentityError::Saml(SamlError::InvalidAuthnRequest {
                    reason: "SubjectConfirmationData InResponseTo mismatch".to_string(),
                }))
            }
        }
    }

    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_builder() -> ResponseBuilder<'static> {
        static AUD: &str = "https://sp.example";
        let attrs: &'static BTreeMap<String, Vec<String>> = Box::leak(Box::default());
        ResponseBuilder {
            response_id: "_r1",
            in_response_to: Some("_req1"),
            issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
            destination: "https://sp.example/acs",
            issuer: "https://idp.example",
            audience: AUD,
            assertion_id: "_a1",
            subject_name_id: "alice@example.com",
            subject_name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            session_index: "sess1",
            not_before: Timestamp::from_micros(1_699_999_990 * 1_000_000),
            not_on_or_after: Timestamp::from_micros(1_700_000_300 * 1_000_000),
            attributes: attrs,
        }
    }

    #[test]
    fn build_parse_roundtrip() {
        let xml = build_response_xml(&sample_builder());
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        assert_eq!(parsed.id, "_r1");
        assert_eq!(parsed.assertions.len(), 1);
        let a = &parsed.assertions[0];
        assert_eq!(a.id, "_a1");
        assert_eq!(a.subject_name_id.as_deref(), Some("alice@example.com"));
        assert_eq!(a.audience.as_deref(), Some("https://sp.example"));
    }

    /// quick-xml 0.41 tokenizes `&amp;`-style references into standalone
    /// `GeneralRef` events, splitting text runs. A value like an Issuer URI or
    /// a NameID that contains an escaped character must still be parsed in full
    /// — the pre-upgrade "capture the first Text event" logic would truncate at
    /// the entity. This guards that regression.
    #[test]
    fn parse_preserves_escaped_entities_in_text() {
        let xml = concat!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" "#,
            r#"IssueInstant="2023-11-14T00:00:00Z">"#,
            r#"<saml:Issuer>https://idp.example/sso?a=1&amp;b=2</saml:Issuer>"#,
            r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
            r#"<saml:Assertion ID="_a1">"#,
            r#"<saml:Issuer>https://idp.example/sso?a=1&amp;b=2</saml:Issuer>"#,
            r#"<saml:Subject><saml:NameID "#,
            r#"Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">"#,
            r#"a&amp;b@example.com</saml:NameID></saml:Subject>"#,
            r#"<saml:Conditions NotBefore="2023-11-14T00:00:00Z" NotOnOrAfter="2023-11-14T01:00:00Z">"#,
            r#"<saml:AudienceRestriction><saml:Audience>https://sp.example/?x=1&amp;y=2</saml:Audience>"#,
            r#"</saml:AudienceRestriction></saml:Conditions>"#,
            r#"<saml:AttributeStatement><saml:Attribute Name="dept">"#,
            r#"<saml:AttributeValue>R&amp;D &lt;core&gt;</saml:AttributeValue>"#,
            r#"</saml:Attribute></saml:AttributeStatement>"#,
            r#"</saml:Assertion></samlp:Response>"#,
        );
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        assert_eq!(parsed.issuer, "https://idp.example/sso?a=1&b=2");
        let a = &parsed.assertions[0];
        assert_eq!(a.issuer, "https://idp.example/sso?a=1&b=2");
        assert_eq!(a.subject_name_id.as_deref(), Some("a&b@example.com"));
        assert_eq!(a.audience.as_deref(), Some("https://sp.example/?x=1&y=2"));
        assert_eq!(
            a.attributes.get("dept").map(Vec::as_slice),
            Some(["R&D <core>".to_string()].as_slice())
        );
    }

    #[test]
    fn validate_audience_mismatch() {
        let xml = build_response_xml(&sample_builder());
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        let res = extract_and_validate_assertion(
            &parsed,
            &ValidateParams {
                sp_entity_id: "https://OTHER.example",
                acs_url: "https://sp.example/acs",
                idp_entity_id: "https://idp.example",
                expected_in_response_to: None,
                now: Timestamp::from_micros(1_700_000_000 * 1_000_000),
                clock_skew_secs: 60,
            },
        );
        assert!(matches!(
            res,
            Err(IdentityError::Saml(SamlError::AudienceMismatch))
        ));
    }

    #[test]
    fn validate_expired_rejected() {
        let xml = build_response_xml(&sample_builder());
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        let res = extract_and_validate_assertion(
            &parsed,
            &ValidateParams {
                sp_entity_id: "https://sp.example",
                acs_url: "https://sp.example/acs",
                idp_entity_id: "https://idp.example",
                expected_in_response_to: None,
                now: Timestamp::from_micros(1_800_000_000 * 1_000_000),
                clock_skew_secs: 60,
            },
        );
        assert!(matches!(res, Err(IdentityError::Saml(SamlError::Expired))));
    }

    #[test]
    fn validate_rejects_assertion_missing_not_on_or_after() {
        // S4 (HEA-1751): an assertion whose `<Conditions>` carries an
        // AudienceRestriction but no `NotOnOrAfter` bound must be rejected —
        // otherwise it never expires and is replayable forever. The audience
        // check passes first (so we know we reach the timestamp gate), then
        // the missing upper bound trips `Expired`.
        let xml = concat!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" "#,
            r#"IssueInstant="2023-11-14T00:00:00Z">"#,
            r#"<saml:Issuer>https://idp.example</saml:Issuer>"#,
            r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
            r#"<saml:Assertion ID="_a1">"#,
            r#"<saml:Issuer>https://idp.example</saml:Issuer>"#,
            r#"<saml:Subject><saml:NameID "#,
            r#"Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">"#,
            r#"alice@example.com</saml:NameID></saml:Subject>"#,
            r#"<saml:Conditions>"#,
            r#"<saml:AudienceRestriction><saml:Audience>https://sp.example</saml:Audience>"#,
            r#"</saml:AudienceRestriction></saml:Conditions>"#,
            r#"</saml:Assertion></samlp:Response>"#,
        );
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        assert!(
            parsed.assertions[0].not_on_or_after.is_none(),
            "fixture must lack NotOnOrAfter"
        );
        let res = extract_and_validate_assertion(
            &parsed,
            &ValidateParams {
                sp_entity_id: "https://sp.example",
                acs_url: "https://sp.example/acs",
                idp_entity_id: "https://idp.example",
                expected_in_response_to: None,
                now: Timestamp::from_micros(1_700_000_000 * 1_000_000),
                clock_skew_secs: 60,
            },
        );
        assert!(
            matches!(res, Err(IdentityError::Saml(SamlError::Expired))),
            "assertion without NotOnOrAfter must be rejected, got {res:?}"
        );
    }

    #[test]
    fn parse_response_rejects_doctype() {
        let xml = b"<!DOCTYPE foo [<!ENTITY x \"x\">]><samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_r\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\"></samlp:Response>";
        let result = parse_response(xml);
        assert!(result.is_err(), "DOCTYPE in SAML Response must be rejected");
    }

    // ==================================================================
    // 19.4 (audit 2026-08-28 §4.10#5) — the signed
    // `<SubjectConfirmationData>` bindings.
    // ==================================================================

    /// Builds a `<Response>` whose bearer `<SubjectConfirmationData>` carries
    /// the supplied attribute string. Every other field is valid for
    /// `sp_entity_id = https://sp.example`, `acs_url = https://sp.example/acs`
    /// and `now = 2023-11-14T22:13:20Z` (1 700 000 000).
    fn response_with_subject_confirmation(scd_attrs: &str) -> Vec<u8> {
        format!(
            concat!(
                r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
                r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" "#,
                r#"IssueInstant="2023-11-14T00:00:00Z" InResponseTo="_req1" "#,
                r#"Destination="https://sp.example/acs">"#,
                r#"<saml:Issuer>https://idp.example</saml:Issuer>"#,
                r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
                r#"<saml:Assertion ID="_a1">"#,
                r#"<saml:Issuer>https://idp.example</saml:Issuer>"#,
                r#"<saml:Subject>"#,
                r#"<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">"#,
                r#"alice@example.com</saml:NameID>"#,
                r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">"#,
                r#"<saml:SubjectConfirmationData {scd}/>"#,
                r#"</saml:SubjectConfirmation></saml:Subject>"#,
                r#"<saml:Conditions NotBefore="2023-11-14T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">"#,
                r#"<saml:AudienceRestriction><saml:Audience>https://sp.example</saml:Audience>"#,
                r#"</saml:AudienceRestriction></saml:Conditions>"#,
                r#"</saml:Assertion></samlp:Response>"#,
            ),
            scd = scd_attrs,
        )
        .into_bytes()
    }

    fn validate_fixture(
        scd_attrs: &str,
        expected_in_response_to: Option<&str>,
    ) -> Result<Assertion, IdentityError> {
        let xml = response_with_subject_confirmation(scd_attrs);
        let parsed = parse_response(&xml).expect("parse");
        extract_and_validate_assertion(
            &parsed,
            &ValidateParams {
                sp_entity_id: "https://sp.example",
                acs_url: "https://sp.example/acs",
                idp_entity_id: "https://idp.example",
                expected_in_response_to,
                now: Timestamp::from_micros(1_700_000_000 * 1_000_000),
                clock_skew_secs: 60,
            },
        )
    }

    /// Control: a fully-bound bearer confirmation is accepted, so the three
    /// rejection tests below cannot pass vacuously.
    #[test]
    fn validate_accepts_well_formed_bearer_subject_confirmation() {
        let res = validate_fixture(
            r#"InResponseTo="_req1" Recipient="https://sp.example/acs" NotOnOrAfter="2099-01-01T00:00:00Z""#,
            Some("_req1"),
        );
        assert!(
            res.is_ok(),
            "a correctly bound bearer confirmation must be accepted, got {res:?}"
        );
    }

    /// §4.10#5: `Recipient` names a different service provider. The assertion
    /// was minted for someone else and must not be honoured here — even though
    /// the outer `Destination` is ours.
    #[test]
    fn validate_rejects_subject_confirmation_recipient_mismatch() {
        let res = validate_fixture(
            r#"InResponseTo="_req1" Recipient="https://other-sp.example/acs" NotOnOrAfter="2099-01-01T00:00:00Z""#,
            Some("_req1"),
        );
        assert!(
            matches!(
                res,
                Err(IdentityError::Saml(SamlError::DestinationMismatch))
            ),
            "SubjectConfirmationData Recipient naming another SP must be refused, got {res:?}"
        );
    }

    /// §4.10#5: the bearer `NotOnOrAfter` is a tighter bound than
    /// `Conditions/NotOnOrAfter` and must be enforced independently.
    #[test]
    fn validate_rejects_expired_bearer_subject_confirmation() {
        let res = validate_fixture(
            r#"InResponseTo="_req1" Recipient="https://sp.example/acs" NotOnOrAfter="2023-11-13T00:00:00Z""#,
            Some("_req1"),
        );
        assert!(
            matches!(res, Err(IdentityError::Saml(SamlError::Expired))),
            "an expired bearer SubjectConfirmationData must be refused, got {res:?}"
        );
    }

    /// §4.10#5: a missing bearer `NotOnOrAfter` leaves the bearer token
    /// unbounded in time.
    #[test]
    fn validate_rejects_bearer_confirmation_without_not_on_or_after() {
        let res = validate_fixture(
            r#"InResponseTo="_req1" Recipient="https://sp.example/acs""#,
            Some("_req1"),
        );
        assert!(
            matches!(res, Err(IdentityError::Saml(SamlError::Expired))),
            "a bearer confirmation with no NotOnOrAfter must be refused, got {res:?}"
        );
    }

    /// §4.10#5: `InResponseTo` inside the signed assertion must name the
    /// `AuthnRequest` this SP issued. The `<Response>`-level `InResponseTo`
    /// is unsigned when only the assertion is signed, so this is the binding
    /// that actually matters.
    #[test]
    fn validate_rejects_subject_confirmation_in_response_to_mismatch() {
        let res = validate_fixture(
            r#"InResponseTo="_attacker" Recipient="https://sp.example/acs" NotOnOrAfter="2099-01-01T00:00:00Z""#,
            Some("_req1"),
        );
        assert!(
            matches!(
                res,
                Err(IdentityError::Saml(SamlError::InvalidAuthnRequest { .. }))
            ),
            "SubjectConfirmationData InResponseTo mismatch must be refused, got {res:?}"
        );
    }

    /// §4.10#5: an assertion that carries no `InResponseTo` inside the signed
    /// element is not bound to the login attempt we started, even when the
    /// unsigned `<Response>` envelope carries the right value.
    #[test]
    fn validate_rejects_bearer_confirmation_missing_in_response_to() {
        let res = validate_fixture(
            r#"Recipient="https://sp.example/acs" NotOnOrAfter="2099-01-01T00:00:00Z""#,
            Some("_req1"),
        );
        assert!(
            matches!(
                res,
                Err(IdentityError::Saml(SamlError::InvalidAuthnRequest { .. }))
            ),
            "a bearer confirmation with no InResponseTo must be refused when a \
             request ID was expected, got {res:?}"
        );
    }

    /// §4.10#5: an assertion with no bearer `<SubjectConfirmation>` at all
    /// carries none of the three bindings, so it must not be accepted.
    #[test]
    fn validate_rejects_assertion_without_bearer_subject_confirmation() {
        let xml = concat!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" "#,
            r#"IssueInstant="2023-11-14T00:00:00Z" Destination="https://sp.example/acs">"#,
            r#"<saml:Issuer>https://idp.example</saml:Issuer>"#,
            r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
            r#"<saml:Assertion ID="_a1">"#,
            r#"<saml:Issuer>https://idp.example</saml:Issuer>"#,
            r#"<saml:Subject><saml:NameID "#,
            r#"Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">"#,
            r#"alice@example.com</saml:NameID></saml:Subject>"#,
            r#"<saml:Conditions NotBefore="2023-11-14T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">"#,
            r#"<saml:AudienceRestriction><saml:Audience>https://sp.example</saml:Audience>"#,
            r#"</saml:AudienceRestriction></saml:Conditions>"#,
            r#"</saml:Assertion></samlp:Response>"#,
        );
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        let res = extract_and_validate_assertion(
            &parsed,
            &ValidateParams {
                sp_entity_id: "https://sp.example",
                acs_url: "https://sp.example/acs",
                idp_entity_id: "https://idp.example",
                expected_in_response_to: None,
                now: Timestamp::from_micros(1_700_000_000 * 1_000_000),
                clock_skew_secs: 60,
            },
        );
        assert!(
            matches!(
                res,
                Err(IdentityError::Saml(SamlError::InvalidAuthnRequest { .. }))
            ),
            "an assertion with no bearer SubjectConfirmation must be refused, got {res:?}"
        );
    }

    /// §4.10#5 + XSW: two bearer confirmations make "the" recipient
    /// ambiguous. Refuse rather than pick one.
    #[test]
    fn validate_rejects_multiple_bearer_subject_confirmations() {
        let xml = concat!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" "#,
            r#"IssueInstant="2023-11-14T00:00:00Z" Destination="https://sp.example/acs">"#,
            r#"<saml:Issuer>https://idp.example</saml:Issuer>"#,
            r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
            r#"<saml:Assertion ID="_a1">"#,
            r#"<saml:Issuer>https://idp.example</saml:Issuer>"#,
            r#"<saml:Subject><saml:NameID "#,
            r#"Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">"#,
            r#"alice@example.com</saml:NameID>"#,
            r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">"#,
            r#"<saml:SubjectConfirmationData Recipient="https://other-sp.example/acs" "#,
            r#"NotOnOrAfter="2099-01-01T00:00:00Z"/></saml:SubjectConfirmation>"#,
            r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">"#,
            r#"<saml:SubjectConfirmationData Recipient="https://sp.example/acs" "#,
            r#"NotOnOrAfter="2099-01-01T00:00:00Z"/></saml:SubjectConfirmation>"#,
            r#"</saml:Subject>"#,
            r#"<saml:Conditions NotBefore="2023-11-14T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">"#,
            r#"<saml:AudienceRestriction><saml:Audience>https://sp.example</saml:Audience>"#,
            r#"</saml:AudienceRestriction></saml:Conditions>"#,
            r#"</saml:Assertion></samlp:Response>"#,
        );
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        let res = extract_and_validate_assertion(
            &parsed,
            &ValidateParams {
                sp_entity_id: "https://sp.example",
                acs_url: "https://sp.example/acs",
                idp_entity_id: "https://idp.example",
                expected_in_response_to: None,
                now: Timestamp::from_micros(1_700_000_000 * 1_000_000),
                clock_skew_secs: 60,
            },
        );
        assert!(
            matches!(
                res,
                Err(IdentityError::Saml(SamlError::InvalidAuthnRequest { .. }))
            ),
            "two bearer SubjectConfirmations must be refused as ambiguous, got {res:?}"
        );
    }

    /// The parser must attribute a `<SubjectConfirmationData>` to the
    /// assertion that encloses it — never to a sibling placed outside every
    /// `<saml:Assertion>`. This is the parse-side half of the
    /// signature-wrapping defence: `verify_signed_element` authenticates one
    /// element, and only bindings inside that element may be read.
    #[test]
    fn parse_ignores_subject_confirmation_outside_any_assertion() {
        let xml = concat!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" "#,
            r#"IssueInstant="2023-11-14T00:00:00Z" Destination="https://sp.example/acs">"#,
            r#"<saml:Issuer>https://idp.example</saml:Issuer>"#,
            // Decoy: a bearer confirmation that belongs to no assertion.
            r#"<saml:Subject><saml:SubjectConfirmation "#,
            r#"Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">"#,
            r#"<saml:SubjectConfirmationData Recipient="https://sp.example/acs" "#,
            r#"NotOnOrAfter="2099-01-01T00:00:00Z"/></saml:SubjectConfirmation></saml:Subject>"#,
            r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
            r#"<saml:Assertion ID="_a1">"#,
            r#"<saml:Issuer>https://idp.example</saml:Issuer>"#,
            r#"<saml:Subject><saml:NameID "#,
            r#"Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">"#,
            r#"alice@example.com</saml:NameID></saml:Subject>"#,
            r#"<saml:Conditions NotBefore="2023-11-14T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">"#,
            r#"<saml:AudienceRestriction><saml:Audience>https://sp.example</saml:Audience>"#,
            r#"</saml:AudienceRestriction></saml:Conditions>"#,
            r#"</saml:Assertion></samlp:Response>"#,
        );
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        assert!(
            parsed.assertions[0].bearer_confirmations.is_empty(),
            "a SubjectConfirmationData outside every <Assertion> must not be \
             attributed to the assertion"
        );
    }
}
