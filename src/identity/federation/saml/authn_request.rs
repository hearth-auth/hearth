//! `<AuthnRequest>` XML construction (the SP sends these upstream).

use super::xml::{escape_attr, ns};
use crate::core::Timestamp;

/// Parameters for building an AuthnRequest.
pub struct BuildAuthnRequestParams<'a> {
    /// Unique request ID (format: `_` + hex/base62). SAML requires the
    /// ID to start with a letter or `_`.
    pub id: &'a str,
    /// Destination (the IdP's SSO URL).
    pub destination: &'a str,
    /// Issuer (SP's entity ID).
    pub issuer: &'a str,
    /// The ACS URL where the response will be POSTed.
    pub acs_url: &'a str,
    /// Issue instant (serialized via `Timestamp`).
    pub issue_instant: Timestamp,
    /// Optional NameIDPolicy format hint.
    pub nameid_format: Option<&'a str>,
    /// If true, request forced re-authentication.
    pub force_authn: bool,
}

/// Builds a SAML `<AuthnRequest>` XML document.
#[must_use]
pub fn build_authn_request_xml(p: &BuildAuthnRequestParams<'_>) -> String {
    let nameid = p
        .nameid_format
        .map(|f| {
            format!(
                r#"<samlp:NameIDPolicy AllowCreate="true" Format="{f}"></samlp:NameIDPolicy>"#,
                f = escape_attr(f)
            )
        })
        .unwrap_or_default();
    let force = if p.force_authn { "true" } else { "false" };
    let iso_ts = format_xsd_datetime(p.issue_instant);
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{samlp}" xmlns:saml="{saml}" ID="{id}" Version="2.0" IssueInstant="{ts}" Destination="{dest}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{acs}" ForceAuthn="{fa}"><saml:Issuer>{iss}</saml:Issuer>{nid}</samlp:AuthnRequest>"#,
        samlp = ns::SAMLP,
        saml = ns::SAML,
        id = escape_attr(p.id),
        ts = escape_attr(&iso_ts),
        dest = escape_attr(p.destination),
        acs = escape_attr(p.acs_url),
        fa = force,
        iss = super::xml::escape_text(p.issuer),
        nid = nameid,
    )
}

/// Formats a timestamp in XSD `dateTime` format (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn format_xsd_datetime(ts: Timestamp) -> String {
    use time::format_description::well_known::Iso8601;
    let odt = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ts.as_micros()) * 1000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    odt.format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Parses an XSD `dateTime` string back to `Timestamp`.
pub fn parse_xsd_datetime(s: &str) -> Option<Timestamp> {
    use time::format_description::well_known::Iso8601;
    let odt = time::OffsetDateTime::parse(s, &Iso8601::DEFAULT).ok()?;
    let nanos = odt.unix_timestamp_nanos();
    let micros = (nanos / 1000) as i64;
    Some(Timestamp::from_micros(micros))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SP builds the request it sends upstream; the fields the IdP routes
    /// on must be present and exactly what the SP was configured with.
    #[test]
    fn built_request_carries_the_configured_fields() {
        let xml = build_authn_request_xml(&BuildAuthnRequestParams {
            id: "_abc123",
            destination: "https://idp.example/sso",
            issuer: "https://sp.example",
            acs_url: "https://sp.example/acs",
            issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
            nameid_format: Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
            force_authn: false,
        });
        for expected in [
            r#"ID="_abc123""#,
            r#"Destination="https://idp.example/sso""#,
            r#"AssertionConsumerServiceURL="https://sp.example/acs""#,
            "https://sp.example</saml:Issuer>",
            r#"IssueInstant="2023-11-14T22:13:20"#,
        ] {
            assert!(xml.contains(expected), "missing {expected} in {xml}");
        }
    }

    /// Values are attribute-escaped: a quote in a configured URL cannot
    /// close the attribute and inject a sibling.
    #[test]
    fn built_request_escapes_attribute_values() {
        let xml = build_authn_request_xml(&BuildAuthnRequestParams {
            id: "_x",
            destination: r#"https://idp.example/sso" Evil="1"#,
            issuer: "https://sp.example",
            acs_url: "https://sp.example/acs",
            issue_instant: Timestamp::from_micros(0),
            nameid_format: None,
            force_authn: false,
        });
        assert!(!xml.contains(r#"" Evil="1""#), "unescaped quote in {xml}");
    }
}
