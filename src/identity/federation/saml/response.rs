//! `<Response>` and `<Assertion>` XML construction, parsing, and validation.

use std::collections::{BTreeMap, BTreeSet};

use super::authn_request::{format_xsd_datetime, parse_xsd_datetime};
use super::xml::{
    escape_attr, escape_text, ns, parse_err, walk_outside_signatures, ElementRef, XmlStep,
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
    /// One entry per `<saml:AudienceRestriction>` in `<Conditions>`, each
    /// holding that restriction's `<saml:Audience>` values in document order.
    /// SAML Core §2.5.1.4: the assertion is addressed to this SP only if EVERY
    /// restriction lists it (any position within a restriction).
    pub audience_restrictions: Vec<Vec<String>>,
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
///
/// Structural, not positional-by-name: every field is read only from the
/// place the SAML 2.0 core schema defines for it (`Response/Assertion/
/// Subject/NameID`, `Response/Assertion/Conditions`, …), decided from the
/// element's parent. An element with a SAML name anywhere else — inside an
/// `<AttributeValue>`, inside `<Advice>`, or at the wrong level — is ignored
/// rather than overwriting the real field.
///
/// Signature-wrapping hardening (GA audit 3, G-1):
/// - The document is read through [`walk_outside_signatures`], so nothing
///   inside a `<ds:Signature>` — the region the enveloped-signature transform
///   removes from the digest — is ever read.
/// - Inside one `<Assertion>`, a second `<Issuer>`, `<Subject>`, subject
///   `<NameID>`, `<Conditions>`, or a second `<Attribute>` with the same
///   `Name`, is rejected rather than resolved last-write-wins. At the
///   `<Response>` level a second `<Issuer>`, `<Status>` or top-level
///   `<StatusCode>` is rejected likewise.
///
/// # Errors
///
/// Returns [`SamlError::Parse`] on malformed XML, a `DOCTYPE`, more than
/// `MAX_SAML_XML_EVENTS` events, a duplicate field as above, or a Response
/// missing its `ID`, `IssueInstant` or `StatusCode`.
pub fn parse_response(xml: &[u8]) -> Result<SamlResponse, IdentityError> {
    let mut parser = ResponseParser::default();
    walk_outside_signatures(xml, |step| match step {
        XmlStep::Open { element, .. } => parser.open(element),
        XmlStep::Text { text, .. } => {
            parser.text(text);
            Ok(())
        }
        XmlStep::Close { .. } => {
            parser.close();
            Ok(())
        }
    })?;
    parser.finish()
}

/// Where an element sits in a `<samlp:Response>`, decided from its parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Node {
    /// The root `<samlp:Response>`.
    Response,
    /// `Response/Status`.
    Status,
    /// `Response/Status/StatusCode` (the top-level code only).
    StatusCode,
    /// `Response/Issuer`.
    ResponseIssuer,
    /// `Response/Assertion`.
    Assertion,
    /// `Assertion/Issuer`.
    AssertionIssuer,
    /// `Assertion/Subject`.
    Subject,
    /// `Assertion/Subject/NameID`.
    NameId,
    /// `Assertion/Subject/SubjectConfirmation`.
    SubjectConfirmation {
        /// `Method` is the bearer confirmation method.
        bearer: bool,
    },
    /// `Assertion/Conditions`.
    Conditions,
    /// `Assertion/Conditions/AudienceRestriction`.
    AudienceRestriction,
    /// `Assertion/Conditions/AudienceRestriction/Audience`.
    Audience,
    /// `Assertion/AttributeStatement`.
    AttributeStatement,
    /// `Assertion/AttributeStatement/Attribute`.
    Attribute,
    /// `Assertion/AttributeStatement/Attribute/AttributeValue`.
    AttributeValue,
    /// Anything else. Nothing inside it is read.
    Other,
}

impl Node {
    /// Classifies `e` given its parent node.
    fn classify(parent: Option<Node>, e: ElementRef<'_>) -> Node {
        let is = |namespace: &str, local: &str| e.is(namespace, local);
        match parent {
            None if is(ns::SAMLP, "Response") => Node::Response,
            Some(Node::Response) if is(ns::SAMLP, "Status") => Node::Status,
            Some(Node::Response) if is(ns::SAML, "Issuer") => Node::ResponseIssuer,
            Some(Node::Response) if is(ns::SAML, "Assertion") => Node::Assertion,
            Some(Node::Status) if is(ns::SAMLP, "StatusCode") => Node::StatusCode,
            Some(Node::Assertion) if is(ns::SAML, "Issuer") => Node::AssertionIssuer,
            Some(Node::Assertion) if is(ns::SAML, "Subject") => Node::Subject,
            Some(Node::Assertion) if is(ns::SAML, "Conditions") => Node::Conditions,
            Some(Node::Assertion) if is(ns::SAML, "AttributeStatement") => Node::AttributeStatement,
            Some(Node::Subject) if is(ns::SAML, "NameID") => Node::NameId,
            Some(Node::Subject) if is(ns::SAML, "SubjectConfirmation") => {
                Node::SubjectConfirmation {
                    bearer: e.attr("Method").is_some_and(|m| m.trim() == CM_BEARER),
                }
            }
            Some(Node::Conditions) if is(ns::SAML, "AudienceRestriction") => {
                Node::AudienceRestriction
            }
            Some(Node::AudienceRestriction) if is(ns::SAML, "Audience") => Node::Audience,
            Some(Node::AttributeStatement) if is(ns::SAML, "Attribute") => Node::Attribute,
            Some(Node::Attribute) if is(ns::SAML, "AttributeValue") => Node::AttributeValue,
            _ => Node::Other,
        }
    }

    /// Whether the element's text content is a field value.
    fn captures_text(self) -> bool {
        matches!(
            self,
            Node::ResponseIssuer
                | Node::AssertionIssuer
                | Node::NameId
                | Node::Audience
                | Node::AttributeValue
        )
    }
}

/// An `<Assertion>` being parsed, with the fields that may appear only once.
struct AssertionInProgress {
    assertion: Assertion,
    seen_issuer: bool,
    seen_subject: bool,
    seen_name_id: bool,
    seen_conditions: bool,
    attribute_names: BTreeSet<String>,
}

/// Rejects the second occurrence of a single-valued field.
fn once(seen: &mut bool, what: &str) -> Result<(), IdentityError> {
    if std::mem::replace(seen, true) {
        return Err(parse_err(format!("duplicate {what}")));
    }
    Ok(())
}

/// State for [`parse_response`].
#[derive(Default)]
struct ResponseParser {
    stack: Vec<Node>,
    response_id: Option<String>,
    in_response_to: Option<String>,
    issue_instant: Option<String>,
    destination: Option<String>,
    response_issuer: Option<String>,
    status_code: Option<String>,
    seen_response_issuer: bool,
    seen_status: bool,
    seen_status_code: bool,
    assertions: Vec<Assertion>,
    current: Option<AssertionInProgress>,
    // Text content is accumulated here across `Text` steps and committed to
    // the capturing element's field when it closes. quick-xml 0.41 tokenizes
    // `&amp;`-style references into standalone events, so a single value may
    // span several steps.
    text: String,
    attr_name: Option<String>,
    attr_values: Vec<String>,
}

impl ResponseParser {
    fn open(&mut self, e: ElementRef<'_>) -> Result<(), IdentityError> {
        let node = Node::classify(self.stack.last().copied(), e);
        if node.captures_text() {
            self.text.clear();
        }
        match node {
            Node::Response => {
                self.response_id = e.attr("ID");
                self.in_response_to = e.attr("InResponseTo");
                self.issue_instant = e.attr("IssueInstant");
                self.destination = e.attr("Destination");
            }
            Node::Status => once(&mut self.seen_status, "<samlp:Status> in Response")?,
            Node::StatusCode => {
                once(&mut self.seen_status_code, "<samlp:StatusCode> in Status")?;
                self.status_code = e.attr("Value");
            }
            Node::ResponseIssuer => {
                once(&mut self.seen_response_issuer, "<saml:Issuer> in Response")?;
            }
            Node::Assertion => {
                self.current = Some(AssertionInProgress {
                    assertion: Assertion {
                        id: e.attr("ID").unwrap_or_default(),
                        issuer: String::new(),
                        subject_name_id: None,
                        subject_name_id_format: None,
                        not_before: None,
                        not_on_or_after: None,
                        audience_restrictions: Vec::new(),
                        attributes: BTreeMap::new(),
                        in_response_to: self.in_response_to.clone(),
                        session_index: None,
                        destination: self.destination.clone(),
                        bearer_confirmations: Vec::new(),
                    },
                    seen_issuer: false,
                    seen_subject: false,
                    seen_name_id: false,
                    seen_conditions: false,
                    attribute_names: BTreeSet::new(),
                });
            }
            Node::Other => self.open_other(e),
            _ => self.open_in_assertion(node, e)?,
        }
        self.stack.push(node);
        Ok(())
    }

    /// Elements the parser reads for an attribute but does not descend into:
    /// `<SubjectConfirmationData>` and `<AuthnStatement>`.
    fn open_other(&mut self, e: ElementRef<'_>) {
        let parent = self.stack.last().copied();
        let Some(ref mut cur) = self.current else {
            return;
        };
        let a = &mut cur.assertion;
        match parent {
            // Only a bearer confirmation inside this assertion's `<Subject>`
            // counts — see `Assertion::bearer_confirmations`.
            Some(Node::SubjectConfirmation { bearer: true })
                if e.is(ns::SAML, "SubjectConfirmationData") =>
            {
                a.bearer_confirmations.push(BearerConfirmation {
                    recipient: e.attr("Recipient"),
                    not_on_or_after: e.attr("NotOnOrAfter").and_then(|s| parse_xsd_datetime(&s)),
                    in_response_to: e.attr("InResponseTo"),
                });
            }
            Some(Node::Assertion) if e.is(ns::SAML, "AuthnStatement") => {
                a.session_index = e.attr("SessionIndex");
            }
            _ => {}
        }
    }

    fn open_in_assertion(&mut self, node: Node, e: ElementRef<'_>) -> Result<(), IdentityError> {
        let Some(ref mut cur) = self.current else {
            return Ok(());
        };
        match node {
            Node::AssertionIssuer => once(&mut cur.seen_issuer, "<saml:Issuer> in Assertion")?,
            Node::Subject => once(&mut cur.seen_subject, "<saml:Subject> in Assertion")?,
            Node::NameId => {
                once(&mut cur.seen_name_id, "<saml:NameID> in Subject")?;
                cur.assertion.subject_name_id_format = e.attr("Format");
            }
            Node::Conditions => {
                once(&mut cur.seen_conditions, "<saml:Conditions> in Assertion")?;
                cur.assertion.not_before = e.attr("NotBefore").and_then(|s| parse_xsd_datetime(&s));
                cur.assertion.not_on_or_after =
                    e.attr("NotOnOrAfter").and_then(|s| parse_xsd_datetime(&s));
            }
            Node::AudienceRestriction => cur.assertion.audience_restrictions.push(Vec::new()),
            Node::Attribute => {
                self.attr_name = e.attr("Name");
                self.attr_values.clear();
                if let Some(ref name) = self.attr_name {
                    if !cur.attribute_names.insert(name.clone()) {
                        return Err(parse_err("duplicate <saml:Attribute> Name in Assertion"));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn text(&mut self, t: &str) {
        if self.stack.last().is_some_and(|n| n.captures_text()) {
            self.text.push_str(t);
        }
    }

    fn close(&mut self) {
        let Some(node) = self.stack.pop() else {
            return;
        };
        if node == Node::Assertion {
            if let Some(c) = self.current.take() {
                self.assertions.push(c.assertion);
            }
            return;
        }
        // Commit captured text. Empty content is not committed, matching the
        // pre-0.41 single-`Text`-event behaviour.
        let value = if node.captures_text() && !self.text.is_empty() {
            Some(std::mem::take(&mut self.text))
        } else {
            None
        };
        match (node, value, self.current.as_mut()) {
            (Node::ResponseIssuer, Some(v), _) => self.response_issuer = Some(v),
            (Node::AssertionIssuer, Some(v), Some(c)) => c.assertion.issuer = v,
            (Node::NameId, Some(v), Some(c)) => c.assertion.subject_name_id = Some(v),
            (Node::Audience, Some(v), Some(c)) => {
                if let Some(restriction) = c.assertion.audience_restrictions.last_mut() {
                    restriction.push(v);
                }
            }
            (Node::AttributeValue, Some(v), _) => self.attr_values.push(v),
            (Node::Attribute, _, Some(c)) => {
                let values = std::mem::take(&mut self.attr_values);
                if let Some(name) = self.attr_name.take() {
                    if !values.is_empty() {
                        c.assertion.attributes.insert(name, values);
                    }
                }
            }
            _ => {}
        }
    }

    fn finish(self) -> Result<SamlResponse, IdentityError> {
        Ok(SamlResponse {
            id: self
                .response_id
                .ok_or_else(|| parse_err("Response missing ID"))?,
            in_response_to: self.in_response_to,
            issue_instant: self
                .issue_instant
                .ok_or_else(|| parse_err("missing IssueInstant"))?,
            destination: self.destination,
            issuer: self.response_issuer.unwrap_or_default(),
            status_code: self
                .status_code
                .ok_or_else(|| parse_err("missing StatusCode"))?,
            assertions: self.assertions,
        })
    }
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

    // Audience check — SAML Core §2.5.1.4. Within one `<AudienceRestriction>`
    // the assertion is addressed to this SP if ANY `<Audience>` names it;
    // several restrictions are a conjunction, so EACH must name it. The Web
    // Browser SSO profile (§4.1.4.2) requires at least one restriction naming
    // the SP, so none at all is refused too.
    let addressed_to_us = !a.audience_restrictions.is_empty()
        && a.audience_restrictions
            .iter()
            .all(|restriction| restriction.iter().any(|aud| aud == p.sp_entity_id));
    if !addressed_to_us {
        return Err(IdentityError::Saml(SamlError::AudienceMismatch));
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
        assert_eq!(a.audience_restrictions, [["https://sp.example"]]);
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
        assert_eq!(a.audience_restrictions, [["https://sp.example/?x=1&y=2"]]);
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

    // ==================================================================
    // GA audit 3, G-1 — the parser never reads inside a `<ds:Signature>`
    // and refuses duplicate single-valued fields.
    // ==================================================================

    /// A Response whose single assertion carries `extra` just before
    /// `</saml:Assertion>`. Everything else matches `sample_builder`.
    fn response_with_assertion_tail(extra: &str) -> String {
        let xml = build_response_xml(&sample_builder());
        assert!(xml.contains("</saml:Assertion>"));
        xml.replacen("</saml:Assertion>", &format!("{extra}</saml:Assertion>"), 1)
    }

    /// Everything a wrapping attack would plant, inside a `<ds:Signature>`
    /// placed after the real fields (where last-write-wins used to take it).
    #[test]
    fn parse_never_reads_inside_a_signature() {
        let xml = response_with_assertion_tail(concat!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
            "<saml:Issuer>https://evil.example</saml:Issuer>",
            "<saml:Subject><saml:NameID>ceo@example.com</saml:NameID></saml:Subject>",
            r#"<saml:Conditions NotOnOrAfter="2099-01-01T00:00:00Z">"#,
            "<saml:AudienceRestriction><saml:Audience>https://evil.example</saml:Audience>",
            "</saml:AudienceRestriction></saml:Conditions>",
            r#"<saml:AuthnStatement SessionIndex="evil"/>"#,
            r#"<saml:AttributeStatement><saml:Attribute Name="mail">"#,
            "<saml:AttributeValue>ceo@example.com</saml:AttributeValue>",
            "</saml:Attribute></saml:AttributeStatement>",
            "<ds:KeyInfo><saml:Subject><saml:NameID>deeper@example.com</saml:NameID>",
            "</saml:Subject></ds:KeyInfo>",
            "</ds:Signature>",
        ));
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        let a = &parsed.assertions[0];
        assert_eq!(a.subject_name_id.as_deref(), Some("alice@example.com"));
        assert_eq!(a.issuer, "https://idp.example");
        assert_eq!(a.audience_restrictions, [["https://sp.example"]]);
        assert_eq!(
            a.not_on_or_after,
            Some(Timestamp::from_micros(1_700_000_300 * 1_000_000))
        );
        assert_eq!(a.session_index.as_deref(), Some("sess1"));
        assert!(a.attributes.is_empty(), "attributes: {:?}", a.attributes);
    }

    /// A second occurrence of a single-valued field inside one assertion is
    /// refused rather than resolved last-write-wins.
    #[test]
    fn parse_rejects_duplicate_single_valued_fields() {
        let cases = [
            (
                "second Subject",
                "<saml:Subject><saml:NameID>ceo@example.com</saml:NameID></saml:Subject>",
            ),
            (
                "second Issuer",
                "<saml:Issuer>https://idp.example</saml:Issuer>",
            ),
            (
                "second Conditions",
                r#"<saml:Conditions NotOnOrAfter="2099-01-01T00:00:00Z"></saml:Conditions>"#,
            ),
            (
                "same-name Attribute in a second statement",
                concat!(
                    r#"<saml:AttributeStatement><saml:Attribute Name="mail">"#,
                    "<saml:AttributeValue>a@example.com</saml:AttributeValue></saml:Attribute>",
                    r#"</saml:AttributeStatement><saml:AttributeStatement><saml:Attribute Name="mail">"#,
                    "<saml:AttributeValue>b@example.com</saml:AttributeValue></saml:Attribute>",
                    "</saml:AttributeStatement>",
                ),
            ),
        ];
        for (case, extra) in cases {
            let xml = response_with_assertion_tail(extra);
            let err = parse_response(xml.as_bytes())
                .err()
                .unwrap_or_else(|| panic!("{case}: must be rejected"));
            assert!(
                matches!(&err, IdentityError::Saml(SamlError::Parse { reason }) if reason.contains("duplicate")),
                "{case}: wrong error: {err:?}"
            );
        }
    }

    /// Two `<NameID>` elements inside the one `<Subject>` are refused.
    #[test]
    fn parse_rejects_duplicate_subject_name_id() {
        let xml = build_response_xml(&sample_builder()).replacen(
            "</saml:NameID>",
            "</saml:NameID><saml:NameID>ceo@example.com</saml:NameID>",
            1,
        );
        let err = parse_response(xml.as_bytes())
            .expect_err("two NameIDs in one Subject must be rejected");
        assert!(
            matches!(&err, IdentityError::Saml(SamlError::Parse { reason }) if reason.contains("NameID")),
            "wrong error: {err:?}"
        );
    }

    /// The same, one level up: a second Response-level `<Issuer>` or
    /// `<Status>`.
    #[test]
    fn parse_rejects_duplicate_response_level_fields() {
        let base = build_response_xml(&sample_builder());
        let cases = [
            (
                "second Response Issuer",
                "<samlp:Status>",
                "<saml:Issuer>https://evil.example</saml:Issuer><samlp:Status>",
            ),
            (
                "second Status",
                "<saml:Assertion ",
                concat!(
                    "<samlp:Status><samlp:StatusCode ",
                    r#"Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
                    "<saml:Assertion ",
                ),
            ),
        ];
        for (case, anchor, replacement) in cases {
            assert!(base.contains(anchor), "{case}: anchor missing");
            let xml = base.replacen(anchor, replacement, 1);
            let err = parse_response(xml.as_bytes())
                .err()
                .unwrap_or_else(|| panic!("{case}: must be rejected"));
            assert!(
                matches!(&err, IdentityError::Saml(SamlError::Parse { reason }) if reason.contains("duplicate")),
                "{case}: wrong error: {err:?}"
            );
        }
    }

    /// A `<NameID>` that is not the Subject's — here the value of an
    /// `eduPersonTargetedID`-style attribute — is not the subject. The old
    /// parser took the last `<NameID>` anywhere in the assertion.
    #[test]
    fn parse_takes_the_subject_name_id_only_from_subject() {
        let xml = response_with_assertion_tail(concat!(
            r#"<saml:AttributeStatement><saml:Attribute Name="targeted-id">"#,
            "<saml:AttributeValue><saml:NameID>opaque-123</saml:NameID></saml:AttributeValue>",
            "</saml:Attribute></saml:AttributeStatement>",
        ));
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        assert_eq!(
            parsed.assertions[0].subject_name_id.as_deref(),
            Some("alice@example.com")
        );
    }

    /// A second top-level element is a second document; its fields must not
    /// be merged into the first.
    #[test]
    fn parse_rejects_a_second_root_element() {
        let xml = format!(
            "{}{}",
            build_response_xml(&sample_builder()),
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_evil"/>"#
        );
        let err = parse_response(xml.as_bytes()).expect_err("two root elements must be rejected");
        assert!(
            matches!(&err, IdentityError::Saml(SamlError::Parse { reason }) if reason.contains("root")),
            "wrong error: {err:?}"
        );
    }

    // ==================================================================
    // GA audit 3 round 2 — `<AudienceRestriction>` semantics (SAML Core
    // §2.5.1.4): within one restriction ANY `<Audience>` may name this SP;
    // with several restrictions, EACH must name it.
    // ==================================================================

    const OTHER_SP: &str = "https://other-sp.example";
    const THIS_SP: &str = "https://sp.example";

    /// Validates a Response whose `<Conditions>` carries one
    /// `<AudienceRestriction>` per inner slice. Everything else is valid.
    fn validate_audiences(restrictions: &[&[&str]]) -> Result<Assertion, IdentityError> {
        let conditions: String = restrictions
            .iter()
            .map(|r| {
                let audiences: String = r
                    .iter()
                    .map(|a| format!("<saml:Audience>{a}</saml:Audience>"))
                    .collect();
                format!("<saml:AudienceRestriction>{audiences}</saml:AudienceRestriction>")
            })
            .collect();
        let xml = format!(
            concat!(
                r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
                r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" "#,
                r#"IssueInstant="2023-11-14T00:00:00Z" Destination="https://sp.example/acs">"#,
                r#"<saml:Issuer>https://idp.example</saml:Issuer>"#,
                r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
                r#"<saml:Assertion ID="_a1"><saml:Issuer>https://idp.example</saml:Issuer>"#,
                r#"<saml:Subject><saml:NameID>alice@example.com</saml:NameID>"#,
                r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">"#,
                r#"<saml:SubjectConfirmationData Recipient="https://sp.example/acs" "#,
                r#"NotOnOrAfter="2099-01-01T00:00:00Z"/></saml:SubjectConfirmation></saml:Subject>"#,
                r#"<saml:Conditions NotBefore="2023-11-14T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">"#,
                "{conditions}</saml:Conditions></saml:Assertion></samlp:Response>",
            ),
            conditions = conditions,
        );
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        extract_and_validate_assertion(
            &parsed,
            &ValidateParams {
                sp_entity_id: THIS_SP,
                acs_url: "https://sp.example/acs",
                idp_entity_id: "https://idp.example",
                expected_in_response_to: None,
                now: Timestamp::from_micros(1_700_000_000 * 1_000_000),
                clock_skew_secs: 60,
            },
        )
    }

    fn assert_audience_mismatch(res: Result<Assertion, IdentityError>, case: &str) {
        assert!(
            matches!(res, Err(IdentityError::Saml(SamlError::AudienceMismatch))),
            "{case}: expected AudienceMismatch, got {res:?}"
        );
    }

    /// Any audience of a restriction may be this SP — its position does not
    /// matter. The old parser kept only the LAST `<Audience>`, so `[sp, other]`
    /// was refused.
    #[test]
    fn audience_restriction_accepts_this_sp_anywhere_in_the_list() {
        validate_audiences(&[&[OTHER_SP, THIS_SP]]).expect("[other, sp] must be accepted");
        validate_audiences(&[&[THIS_SP, OTHER_SP]]).expect("[sp, other] must be accepted");
    }

    /// A restriction that does not name this SP refuses the assertion.
    #[test]
    fn audience_restriction_without_this_sp_rejected() {
        assert_audience_mismatch(validate_audiences(&[&[OTHER_SP]]), "[other]");
    }

    /// Several restrictions are a conjunction: each must name this SP. The
    /// old parser kept only the last audience, so `[other], [sp]` passed.
    #[test]
    fn every_audience_restriction_must_name_this_sp() {
        assert_audience_mismatch(
            validate_audiences(&[&[THIS_SP], &[OTHER_SP]]),
            "[sp], [other]",
        );
        assert_audience_mismatch(
            validate_audiences(&[&[OTHER_SP], &[THIS_SP]]),
            "[other], [sp]",
        );
        validate_audiences(&[&[THIS_SP], &[OTHER_SP, THIS_SP]])
            .expect("two restrictions that both name this SP must be accepted");
    }

    /// The Web Browser SSO profile (§4.1.4.2) requires a restriction naming
    /// the SP: none at all, or an empty one, is refused.
    #[test]
    fn missing_or_empty_audience_restriction_rejected() {
        assert_audience_mismatch(validate_audiences(&[]), "no restriction");
        assert_audience_mismatch(validate_audiences(&[&[]]), "empty restriction");
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
