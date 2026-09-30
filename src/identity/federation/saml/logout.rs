//! `<LogoutRequest>` and `<LogoutResponse>` construction and parsing.

use super::authn_request::format_xsd_datetime;
use super::xml::{escape_attr, escape_text, ns, parse_err, walk_outside_signatures, XmlStep};
use crate::core::Timestamp;
use crate::identity::error::IdentityError;

#[derive(Debug, Clone)]
pub struct LogoutRequest {
    pub id: String,
    pub issue_instant: String,
    pub destination: Option<String>,
    pub issuer: String,
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub session_index: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LogoutResponse {
    pub id: String,
    pub in_response_to: Option<String>,
    pub issue_instant: String,
    pub destination: Option<String>,
    pub issuer: String,
    pub status_code: String,
}

pub struct BuildLogoutRequestParams<'a> {
    pub id: &'a str,
    pub destination: &'a str,
    pub issue_instant: Timestamp,
    pub issuer: &'a str,
    pub name_id: &'a str,
    pub name_id_format: &'a str,
    pub session_index: Option<&'a str>,
}

#[must_use]
pub fn build_logout_request_xml(p: &BuildLogoutRequestParams<'_>) -> String {
    let sidx = p
        .session_index
        .map(|s| {
            format!(
                "<samlp:SessionIndex>{}</samlp:SessionIndex>",
                escape_text(s)
            )
        })
        .unwrap_or_default();
    let ts = format_xsd_datetime(p.issue_instant);
    format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{samlp}" xmlns:saml="{saml}" ID="{id}" Version="2.0" IssueInstant="{ts}" Destination="{dest}"><saml:Issuer>{iss}</saml:Issuer><saml:NameID Format="{nidf}">{nid}</saml:NameID>{sidx}</samlp:LogoutRequest>"#,
        samlp = ns::SAMLP,
        saml = ns::SAML,
        id = escape_attr(p.id),
        ts = escape_attr(&ts),
        dest = escape_attr(p.destination),
        iss = escape_text(p.issuer),
        nidf = escape_attr(p.name_id_format),
        nid = escape_text(p.name_id),
        sidx = sidx,
    )
}

pub struct BuildLogoutResponseParams<'a> {
    pub id: &'a str,
    pub in_response_to: &'a str,
    pub destination: &'a str,
    pub issue_instant: Timestamp,
    pub issuer: &'a str,
    pub success: bool,
}

#[must_use]
pub fn build_logout_response_xml(p: &BuildLogoutResponseParams<'_>) -> String {
    let ts = format_xsd_datetime(p.issue_instant);
    let code = if p.success {
        "urn:oasis:names:tc:SAML:2.0:status:Success"
    } else {
        "urn:oasis:names:tc:SAML:2.0:status:Requester"
    };
    format!(
        r#"<samlp:LogoutResponse xmlns:samlp="{samlp}" xmlns:saml="{saml}" ID="{id}" Version="2.0" IssueInstant="{ts}" Destination="{dest}" InResponseTo="{irt}"><saml:Issuer>{iss}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{code}"></samlp:StatusCode></samlp:Status></samlp:LogoutResponse>"#,
        samlp = ns::SAMLP,
        saml = ns::SAML,
        id = escape_attr(p.id),
        ts = escape_attr(&ts),
        dest = escape_attr(p.destination),
        irt = escape_attr(p.in_response_to),
        iss = escape_text(p.issuer),
        code = code,
    )
}

/// Parses a SAML `<LogoutRequest>`.
///
/// Reads the request's attributes from the root element only and `<Issuer>`,
/// `<NameID>` and `<SessionIndex>` from the root's direct children only,
/// through [`walk_outside_signatures`] — nothing inside a `<ds:Signature>` is
/// ever read (GA audit 3, G-1). A second `<Issuer>` or `<NameID>` is
/// rejected; of several `<SessionIndex>` elements (which the schema allows)
/// the first is kept.
///
/// # Errors
///
/// Returns a parse error on malformed XML, a `DOCTYPE`, a duplicate field, a
/// root that is not a `<LogoutRequest>`, or a missing `ID` / `IssueInstant` /
/// `Issuer` / `NameID`.
pub fn parse_logout_request(xml: &[u8]) -> Result<LogoutRequest, IdentityError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Capture {
        Issuer,
        NameId,
        SessionIndex,
    }

    let mut is_request = false;
    let mut id: Option<String> = None;
    let mut issue_instant: Option<String> = None;
    let mut destination: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut name_id: Option<String> = None;
    let mut name_id_format: Option<String> = None;
    let mut session_index: Option<String> = None;
    let (mut seen_issuer, mut seen_name_id, mut seen_session_index) = (false, false, false);
    let mut capture: Option<Capture> = None;

    walk_outside_signatures(xml, |step| {
        match step {
            XmlStep::Open {
                element: e,
                depth: 1,
            } => {
                if e.is(ns::SAMLP, "LogoutRequest") {
                    is_request = true;
                    id = e.attr("ID");
                    issue_instant = e.attr("IssueInstant");
                    destination = e.attr("Destination");
                }
            }
            XmlStep::Open {
                element: e,
                depth: 2,
            } if is_request => {
                if e.is(ns::SAML, "Issuer") {
                    if std::mem::replace(&mut seen_issuer, true) {
                        return Err(parse_err("duplicate <saml:Issuer> in LogoutRequest"));
                    }
                    capture = Some(Capture::Issuer);
                } else if e.is(ns::SAML, "NameID") {
                    if std::mem::replace(&mut seen_name_id, true) {
                        return Err(parse_err("duplicate <saml:NameID> in LogoutRequest"));
                    }
                    name_id_format = e.attr("Format");
                    capture = Some(Capture::NameId);
                } else if e.is(ns::SAMLP, "SessionIndex")
                    && !std::mem::replace(&mut seen_session_index, true)
                {
                    capture = Some(Capture::SessionIndex);
                }
            }
            XmlStep::Text { text, depth: 2 } => {
                // quick-xml 0.41 emits `&amp;`-style references as separate
                // events; accumulate each resolved piece into the value.
                let slot = match capture {
                    Some(Capture::Issuer) => &mut issuer,
                    Some(Capture::NameId) => &mut name_id,
                    Some(Capture::SessionIndex) => &mut session_index,
                    None => return Ok(()),
                };
                slot.get_or_insert_with(String::new).push_str(text);
            }
            XmlStep::Close { depth: 2 } => capture = None,
            _ => {}
        }
        Ok(())
    })?;

    if !is_request {
        return Err(parse_err("root element is not a LogoutRequest"));
    }
    Ok(LogoutRequest {
        id: id.ok_or_else(|| parse_err("LogoutRequest missing ID"))?,
        issue_instant: issue_instant.ok_or_else(|| parse_err("missing IssueInstant"))?,
        destination,
        issuer: issuer.ok_or_else(|| parse_err("LogoutRequest missing Issuer"))?,
        name_id: name_id.ok_or_else(|| parse_err("LogoutRequest missing NameID"))?,
        name_id_format,
        session_index,
    })
}

/// Parses a SAML `<LogoutResponse>`.
///
/// Root attributes, the root's `<Issuer>` and the top-level
/// `<Status>/<StatusCode>` only, read through [`walk_outside_signatures`]
/// (GA audit 3, G-1). A second `<Issuer>` or top-level `<StatusCode>` is
/// rejected.
///
/// # Errors
///
/// Returns a parse error on malformed XML, a `DOCTYPE`, a duplicate field, a
/// root that is not a `<LogoutResponse>`, or a missing `ID` / `IssueInstant` /
/// `StatusCode`.
pub fn parse_logout_response(xml: &[u8]) -> Result<LogoutResponse, IdentityError> {
    let mut is_response = false;
    let mut id: Option<String> = None;
    let mut in_response_to: Option<String> = None;
    let mut issue_instant: Option<String> = None;
    let mut destination: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut status_code: Option<String> = None;
    let (mut seen_issuer, mut seen_status, mut seen_status_code) = (false, false, false);
    let mut in_issuer = false;
    let mut in_status = false;

    walk_outside_signatures(xml, |step| {
        match step {
            XmlStep::Open {
                element: e,
                depth: 1,
            } => {
                if e.is(ns::SAMLP, "LogoutResponse") {
                    is_response = true;
                    id = e.attr("ID");
                    in_response_to = e.attr("InResponseTo");
                    issue_instant = e.attr("IssueInstant");
                    destination = e.attr("Destination");
                }
            }
            XmlStep::Open {
                element: e,
                depth: 2,
            } if is_response => {
                if e.is(ns::SAML, "Issuer") {
                    if std::mem::replace(&mut seen_issuer, true) {
                        return Err(parse_err("duplicate <saml:Issuer> in LogoutResponse"));
                    }
                    in_issuer = true;
                } else if e.is(ns::SAMLP, "Status") {
                    if std::mem::replace(&mut seen_status, true) {
                        return Err(parse_err("duplicate <samlp:Status> in LogoutResponse"));
                    }
                    in_status = true;
                }
            }
            XmlStep::Open {
                element: e,
                depth: 3,
            } if in_status && e.is(ns::SAMLP, "StatusCode") => {
                if std::mem::replace(&mut seen_status_code, true) {
                    return Err(parse_err("duplicate <samlp:StatusCode> in Status"));
                }
                status_code = e.attr("Value");
            }
            XmlStep::Text { text, depth: 2 } if in_issuer => {
                issuer.get_or_insert_with(String::new).push_str(text);
            }
            XmlStep::Close { depth: 2 } => {
                in_issuer = false;
                in_status = false;
            }
            _ => {}
        }
        Ok(())
    })?;

    if !is_response {
        return Err(parse_err("root element is not a LogoutResponse"));
    }
    Ok(LogoutResponse {
        id: id.ok_or_else(|| parse_err("LogoutResponse missing ID"))?,
        in_response_to,
        issue_instant: issue_instant.ok_or_else(|| parse_err("missing IssueInstant"))?,
        destination,
        issuer: issuer.unwrap_or_default(),
        status_code: status_code.ok_or_else(|| parse_err("missing StatusCode"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_request_roundtrip() {
        let xml = build_logout_request_xml(&BuildLogoutRequestParams {
            id: "_lo1",
            destination: "https://sp.example/slo",
            issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
            issuer: "https://idp.example",
            name_id: "alice@example.com",
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            session_index: Some("sess1"),
        });
        let parsed = parse_logout_request(xml.as_bytes()).expect("parse");
        assert_eq!(parsed.id, "_lo1");
        assert_eq!(parsed.name_id, "alice@example.com");
        assert_eq!(parsed.session_index.as_deref(), Some("sess1"));
    }

    fn sample_logout_request() -> String {
        build_logout_request_xml(&BuildLogoutRequestParams {
            id: "_real",
            destination: "https://idp.example/slo",
            issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
            issuer: "https://sp.example",
            name_id: "alice@example.com",
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            session_index: Some("sess1"),
        })
    }

    /// GA audit 3, G-1: a `<ds:Signature>` carrying a forged request is
    /// invisible to the parser.
    #[test]
    fn parse_logout_request_never_reads_inside_a_signature() {
        let xml = sample_logout_request().replacen(
            "</samlp:LogoutRequest>",
            concat!(
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                r#"<samlp:LogoutRequest ID="_forged" IssueInstant="2099-01-01T00:00:00Z"/>"#,
                "<saml:Issuer>https://evil.example</saml:Issuer>",
                "<saml:NameID>ceo@example.com</saml:NameID></ds:Signature>",
                "</samlp:LogoutRequest>",
            ),
            1,
        );
        let parsed = parse_logout_request(xml.as_bytes()).expect("parse");
        assert_eq!(parsed.id, "_real");
        assert_eq!(parsed.issuer, "https://sp.example");
        assert_eq!(parsed.name_id, "alice@example.com");
    }

    /// A second `<Issuer>` or `<NameID>` used to be concatenated onto the
    /// first; both are refused.
    #[test]
    fn parse_logout_request_rejects_duplicate_fields() {
        let cases = [
            (
                "</saml:Issuer>",
                "</saml:Issuer><saml:Issuer>https://evil.example</saml:Issuer>",
            ),
            (
                "</saml:NameID>",
                "</saml:NameID><saml:NameID>ceo@example.com</saml:NameID>",
            ),
        ];
        for (anchor, replacement) in cases {
            let xml = sample_logout_request().replacen(anchor, replacement, 1);
            let err = parse_logout_request(xml.as_bytes())
                .err()
                .unwrap_or_else(|| panic!("{anchor}: duplicate must be rejected"));
            assert!(
                matches!(&err, IdentityError::Saml(crate::identity::federation::saml::SamlError::Parse { reason }) if reason.contains("duplicate")),
                "{anchor}: wrong error: {err:?}"
            );
        }
    }

    /// A signature-hidden `<StatusCode>` does not replace the real one.
    #[test]
    fn parse_logout_response_never_reads_inside_a_signature() {
        let xml = build_logout_response_xml(&BuildLogoutResponseParams {
            id: "_lr1",
            in_response_to: "_lo1",
            destination: "https://idp.example/slo",
            issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
            issuer: "https://sp.example",
            success: false,
        })
        .replacen(
            "</samlp:LogoutResponse>",
            concat!(
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                r#"<samlp:Status><samlp:StatusCode "#,
                r#"Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
                "</ds:Signature></samlp:LogoutResponse>",
            ),
            1,
        );
        let parsed = parse_logout_response(xml.as_bytes()).expect("parse");
        assert!(
            !parsed.status_code.ends_with(":Success"),
            "the hidden Success status was read: {}",
            parsed.status_code
        );
    }

    #[test]
    fn logout_response_roundtrip() {
        let xml = build_logout_response_xml(&BuildLogoutResponseParams {
            id: "_lr1",
            in_response_to: "_lo1",
            destination: "https://idp.example/slo",
            issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
            issuer: "https://sp.example",
            success: true,
        });
        let parsed = parse_logout_response(xml.as_bytes()).expect("parse");
        assert_eq!(parsed.in_response_to.as_deref(), Some("_lo1"));
        assert!(parsed.status_code.ends_with("Success"));
    }

    #[test]
    fn parse_logout_request_rejects_doctype() {
        let xml = b"<!DOCTYPE foo []><samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_x\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\"></samlp:LogoutRequest>";
        let result = parse_logout_request(xml);
        assert!(result.is_err(), "DOCTYPE in LogoutRequest must be rejected");
    }

    #[test]
    fn parse_logout_response_rejects_doctype() {
        let xml = b"<!DOCTYPE foo []><samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_x\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\" InResponseTo=\"_lo\"></samlp:LogoutResponse>";
        let result = parse_logout_response(xml);
        assert!(
            result.is_err(),
            "DOCTYPE in LogoutResponse must be rejected"
        );
    }
}
