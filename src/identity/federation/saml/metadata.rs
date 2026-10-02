//! SAML metadata `<EntityDescriptor>` generation and parsing.

use super::xml::{escape_attr, ns, parse_err, walk_outside_signatures, XmlStep};
use crate::identity::error::IdentityError;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

/// SP metadata parameters.
pub struct SpMetadataParams<'a> {
    /// SP's own entity ID (typically the realm's base URL).
    pub entity_id: &'a str,
    /// Hearth ACS URL where signed Responses are delivered.
    pub acs_url: &'a str,
    /// Hearth SLO URL (optional).
    pub slo_url: Option<&'a str>,
    /// Whether outbound AuthnRequests will be signed.
    pub sign_authn_requests: bool,
    /// Whether Hearth requires signed assertions from the IdP.
    pub want_assertions_signed: bool,
    /// Optional signing certificate DER to embed for signing requests.
    pub signing_cert_der: Option<&'a [u8]>,
}

/// Builds an `<EntityDescriptor>` XML document for an SP.
#[must_use]
pub fn build_sp_metadata(p: &SpMetadataParams<'_>) -> String {
    let key_desc = p
        .signing_cert_der
        .map(|der| {
            let b64 = B64.encode(der);
            format!(
                r#"<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="{ds}"><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#,
                ds = ns::DS,
                cert = b64,
            )
        })
        .unwrap_or_default();

    let slo = p
        .slo_url
        .map(|u| {
            format!(
                r#"<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{loc}"></md:SingleLogoutService>"#,
                loc = escape_attr(u)
            )
        })
        .unwrap_or_default();

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="{md}" entityID="{eid}"><md:SPSSODescriptor AuthnRequestsSigned="{ars}" WantAssertionsSigned="{was}" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{key}{slo}<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0" isDefault="true"></md:AssertionConsumerService></md:SPSSODescriptor></md:EntityDescriptor>"#,
        md = ns::MD,
        eid = escape_attr(p.entity_id),
        ars = p.sign_authn_requests,
        was = p.want_assertions_signed,
        key = key_desc,
        slo = slo,
        acs = escape_attr(p.acs_url),
    )
}

/// Parsed IdP metadata relevant for SP-side configuration.
#[derive(Debug, Clone)]
pub struct ParsedIdpMetadata {
    pub entity_id: String,
    pub sso_redirect_url: Option<String>,
    pub sso_post_url: Option<String>,
    pub slo_url: Option<String>,
    /// Signing certificate(s) in PEM format.
    pub signing_certs_pem: Vec<String>,
}

/// Parses an `<EntityDescriptor>` containing an `<IDPSSODescriptor>`.
pub fn parse_idp_metadata(xml: &[u8]) -> Result<ParsedIdpMetadata, IdentityError> {
    let mut entity_id: Option<String> = None;
    let mut sso_redirect: Option<String> = None;
    let mut sso_post: Option<String> = None;
    let mut slo_url: Option<String> = None;
    let mut certs: Vec<String> = Vec::new();
    // Depth of the open `<md:IDPSSODescriptor>`, and of the open
    // `<ds:X509Certificate>` whose text is being collected.
    let mut idp_depth: Option<usize> = None;
    let mut cert_depth: Option<usize> = None;
    let mut cert_text = String::new();

    // Read through the signature-blind walker, matching elements by namespace
    // URI: a certificate inside the metadata's own `<ds:Signature>` (its
    // `KeyInfo`) is not an IdP signing certificate (GA audit 3, round 2).
    walk_outside_signatures(xml, |step| {
        match step {
            XmlStep::Open { element: e, depth } => {
                if e.is(ns::MD, "EntityDescriptor") && entity_id.is_none() {
                    entity_id = e.attr("entityID");
                } else if e.is(ns::MD, "IDPSSODescriptor") {
                    idp_depth.get_or_insert(depth);
                } else if idp_depth.is_some() && e.is(ns::MD, "SingleSignOnService") {
                    let binding = e.attr("Binding").unwrap_or_default();
                    let loc = e.attr("Location");
                    if binding.ends_with("HTTP-Redirect") {
                        sso_redirect = loc;
                    } else if binding.ends_with("HTTP-POST") {
                        sso_post = loc;
                    }
                } else if idp_depth.is_some() && e.is(ns::MD, "SingleLogoutService") {
                    if slo_url.is_none() {
                        slo_url = e.attr("Location");
                    }
                } else if idp_depth.is_some() && e.is(ns::DS, "X509Certificate") {
                    cert_depth = Some(depth);
                    cert_text.clear();
                }
            }
            XmlStep::Text { text, depth } if cert_depth == Some(depth) => cert_text.push_str(text),
            XmlStep::Close { depth } => {
                if cert_depth == Some(depth) {
                    cert_depth = None;
                    let cleaned: String =
                        cert_text.chars().filter(|c| !c.is_whitespace()).collect();
                    if !cleaned.is_empty() {
                        certs.push(wrap_cert_pem(&cleaned));
                    }
                }
                if idp_depth == Some(depth) {
                    idp_depth = None;
                }
            }
            XmlStep::Text { .. } => {}
        }
        Ok(())
    })?;

    let entity_id = entity_id.ok_or_else(|| parse_err("no entityID in metadata"))?;

    Ok(ParsedIdpMetadata {
        entity_id,
        sso_redirect_url: sso_redirect,
        sso_post_url: sso_post,
        slo_url,
        signing_certs_pem: certs,
    })
}

fn wrap_cert_pem(b64: &str) -> String {
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GA audit 3 round 2: a certificate inside a `<ds:Signature>` (the
    /// metadata's own signature `KeyInfo`) is not an IdP signing
    /// certificate — only the `KeyDescriptor`'s is — and `ds:` is matched by
    /// the namespace it is bound to on the root.
    #[test]
    fn parse_idp_metadata_ignores_certificates_inside_a_signature() {
        let xml = concat!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" "#,
            r#"xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example">"#,
            r#"<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">"#,
            "<ds:Signature><ds:KeyInfo><ds:X509Data><ds:X509Certificate>U0lHTkFUVVJF",
            "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
            r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>"#,
            "<ds:X509Certificate>UkVBTA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
            "</md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>",
        );
        let parsed = parse_idp_metadata(xml.as_bytes()).expect("parse");
        assert_eq!(
            parsed.signing_certs_pem.len(),
            1,
            "{:?}",
            parsed.signing_certs_pem
        );
        assert!(parsed.signing_certs_pem[0].contains("UkVBTA=="));
    }

    #[test]
    fn sp_metadata_contains_acs() {
        let p = SpMetadataParams {
            entity_id: "https://hearth.example/acme",
            acs_url: "https://hearth.example/ui/realms/acme/federation/saml/acs",
            slo_url: None,
            sign_authn_requests: false,
            want_assertions_signed: true,
            signing_cert_der: None,
        };
        let xml = build_sp_metadata(&p);
        assert!(xml.contains("AssertionConsumerService"));
        assert!(xml.contains("https://hearth.example/ui/realms/acme/federation/saml/acs"));
    }

    /// An upstream IdP's metadata, as Okta / Entra / Shibboleth publish it.
    #[test]
    fn parses_upstream_idp_metadata() {
        let xml = br#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>AQIDBA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#;
        let parsed = parse_idp_metadata(xml).expect("parse");
        assert_eq!(parsed.entity_id, "https://idp.example");
        assert_eq!(
            parsed.sso_redirect_url.as_deref(),
            Some("https://idp.example/sso")
        );
        assert_eq!(parsed.signing_certs_pem.len(), 1);
    }

    #[test]
    fn parse_idp_metadata_rejects_doctype() {
        let xml = b"<!DOCTYPE foo []><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://idp.example\"></md:EntityDescriptor>";
        let result = parse_idp_metadata(xml);
        assert!(result.is_err(), "DOCTYPE in IdP metadata must be rejected");
    }
}
