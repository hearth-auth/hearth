//! SP-side orchestration: begin login, consume Response at ACS, SLO.
//!
//! Pure logic — no storage, no HTTP. Callers (engine, web handlers)
//! combine these primitives with their own state-stores.

use super::response::{extract_and_validate_assertion, parse_response, Assertion, ValidateParams};
use super::signature::verify_signed_element;
use super::types::{AttributeMap, SamlIdpConfig};
use super::xml::{count_elements, ns};
use crate::core::Timestamp;
use crate::identity::error::IdentityError;
use crate::identity::federation::saml::SamlError;
use crate::identity::federation::types::ExternalIdentity;

/// Outcome of a completed SP login round-trip.
pub enum SamlSpOutcome {
    /// A valid assertion was accepted. The caller should proceed to
    /// federation's normal linking / JIT provisioning path.
    Accepted {
        /// Assertion metadata translated to the federation
        /// `ExternalIdentity` shape.
        identity: ExternalIdentity,
        /// Session index from the assertion's AuthnStatement (for SLO).
        session_index: Option<String>,
        /// The raw assertion (for audit / debugging).
        assertion: Assertion,
    },
    /// The response was rejected. `reason` is one of the SAML error
    /// variants; the engine maps this to a `SamlLoginFailed` audit event.
    Rejected { error: IdentityError },
}

/// Top-level SP service.
pub struct SamlSpService;

impl SamlSpService {
    /// Completes an SP-initiated login by validating a POSTed
    /// `SAMLResponse`.
    ///
    /// `xml` is the parsed+base64-decoded Response bytes.
    pub fn complete(
        idp: &SamlIdpConfig,
        sp_entity_id: &str,
        acs_url: &str,
        expected_in_response_to: Option<&str>,
        now: Timestamp,
        xml: &[u8],
    ) -> SamlSpOutcome {
        match Self::complete_inner(
            idp,
            sp_entity_id,
            acs_url,
            expected_in_response_to,
            now,
            xml,
        ) {
            Ok((identity, session_index, assertion)) => SamlSpOutcome::Accepted {
                identity,
                session_index,
                assertion,
            },
            Err(error) => SamlSpOutcome::Rejected { error },
        }
    }

    fn complete_inner(
        idp: &SamlIdpConfig,
        sp_entity_id: &str,
        acs_url: &str,
        expected_in_response_to: Option<&str>,
        now: Timestamp,
        xml: &[u8],
    ) -> Result<(ExternalIdentity, Option<String>, Assertion), IdentityError> {
        let primary_cert = idp
            .idp_certificates_pem
            .first()
            .ok_or(IdentityError::Saml(SamlError::Signature))?;

        // XML Signature Wrapping defence, part 1 (audit 2026-08-28 B5).
        //
        // The document must carry exactly one `<saml:Assertion>`. A wrapped
        // response hides a second one where the signature cannot see it —
        // inside the `<ds:Signature>` element, which the enveloped-signature
        // transform strips before the digest is computed. Signature
        // verification then passes on the IdP's assertion while the response
        // parser, which collects every `<saml:Assertion>` at any depth,
        // consumes the attacker's. Counting the whole document closes every
        // placement, not just the one that was reproduced.
        //
        // This SP consumes a single assertion (`extract_and_validate_assertion`
        // refuses more than one), so requiring exactly one here removes no
        // supported case.
        if count_elements(xml, ns::SAML, "Assertion")? != 1 {
            return Err(IdentityError::Saml(SamlError::Signature));
        }

        // Signature verification: prefer Assertion-level signature if
        // want_assertions_signed, else accept Response-level signature.
        let verified_assertion_id = match verify_signed_element(xml, "Assertion", primary_cert) {
            Ok(verified) => Some(verified.id),
            Err(_) => {
                if idp.want_assertions_signed {
                    return Err(IdentityError::Saml(SamlError::Signature));
                }
                // Fall back to Response-level signature.
                verify_signed_element(xml, "Response", primary_cert)?;
                None
            }
        };

        let resp = parse_response(xml)?;
        let assertion = extract_and_validate_assertion(
            &resp,
            &ValidateParams {
                sp_entity_id,
                acs_url,
                idp_entity_id: &idp.entity_id,
                expected_in_response_to,
                now,
                clock_skew_secs: 60,
            },
        )?;

        // XML Signature Wrapping defence, part 2: the element whose
        // signature was verified must be the element that is consumed.
        if let Some(verified_id) = verified_assertion_id {
            if assertion.id != verified_id {
                return Err(IdentityError::Saml(SamlError::Signature));
            }
        }

        let identity =
            assertion_to_external_identity(idp.idp_id.clone(), &assertion, &idp.attribute_map)?;
        let session_index = assertion.session_index.clone();
        Ok((identity, session_index, assertion))
    }
}

/// Translates a parsed `<Assertion>` into an `ExternalIdentity` using the
/// configured attribute map.
fn assertion_to_external_identity(
    idp_id: crate::core::IdpId,
    a: &Assertion,
    map: &AttributeMap,
) -> Result<ExternalIdentity, IdentityError> {
    let nameid = a.subject_name_id.as_deref().unwrap_or("").to_string();

    let email = resolve(map, "email", a, &nameid).unwrap_or_else(|| nameid.clone());
    let display_name = resolve(map, "display_name", a, &nameid).unwrap_or_default();
    let first_name = resolve(map, "first_name", a, &nameid).unwrap_or_default();
    let last_name = resolve(map, "last_name", a, &nameid).unwrap_or_default();
    let external_sub = resolve(map, "external_sub", a, &nameid).unwrap_or_else(|| nameid.clone());

    Ok(ExternalIdentity {
        idp_id,
        external_sub,
        email,
        // SAML doesn't carry a `email_verified` signal; enterprises treat
        // SAML-asserted emails as trustworthy since they come from a
        // trusted corporate IdP. Still, default to false and require the
        // caller to opt into auto-link via YAML.
        email_verified: false,
        display_name,
        first_name,
        last_name,
        picture_url: None,
    })
}

fn resolve(map: &AttributeMap, field: &str, a: &Assertion, nameid: &str) -> Option<String> {
    let src = map.get(field)?;
    if src == "NameID" {
        return Some(nameid.to_string());
    }
    a.attributes
        .get(src)
        .and_then(|vs| vs.first())
        .map(|v| v.clone())
}

// Prevent unused-import warning on debug-only ns path.
#[allow(dead_code)]
const _SAML_NS: &str = ns::SAML;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_map_name_id_fallback() {
        use crate::core::IdpId;
        use std::collections::BTreeMap;
        let mut m = BTreeMap::new();
        m.insert("email".to_string(), "NameID".to_string());

        let a = Assertion {
            id: "a1".into(),
            issuer: "idp".into(),
            subject_name_id: Some("alice@example.com".into()),
            subject_name_id_format: None,
            not_before: None,
            not_on_or_after: None,
            audience: None,
            attributes: BTreeMap::new(),
            in_response_to: None,
            session_index: None,
            destination: None,
        };
        let ext = assertion_to_external_identity(IdpId::generate(), &a, &m).expect("map");
        assert_eq!(ext.email, "alice@example.com");
    }

    /// Test-only PEM wrapper for a DER cert (mirrors `signature::tests`).
    fn cert_der_to_pem(der: &[u8]) -> String {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let b64 = B64.encode(der);
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).expect("base64 is valid utf8"));
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }

    /// Builds a valid `<Response>` whose outer envelope is signed but whose
    /// inner `<Assertion>` is NOT individually signed. Returns `(xml, pem)`.
    fn response_signed_but_assertion_unsigned() -> (Vec<u8>, String) {
        use super::super::response::{build_response_xml, ResponseBuilder};
        use super::super::signature::sign_element;
        use crate::core::Timestamp;
        use crate::identity::tokens::RsaSigningKey;
        use std::collections::BTreeMap;

        let key = RsaSigningKey::generate("hearth-test", 365).expect("key");
        let cert_pem = cert_der_to_pem(key.cert_der());

        let attrs: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let unsigned = build_response_xml(&ResponseBuilder {
            response_id: "_r1",
            in_response_to: None,
            issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
            destination: "https://sp.example/acs",
            issuer: "https://idp.example",
            audience: "https://sp.example",
            assertion_id: "_a1",
            subject_name_id: "alice@example.com",
            subject_name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            session_index: "sess1",
            not_before: Timestamp::from_micros(1_699_999_990 * 1_000_000),
            not_on_or_after: Timestamp::from_micros(1_700_000_300 * 1_000_000),
            attributes: &attrs,
        });

        // Sign the outer Response element only — the inner Assertion carries
        // no <Signature> of its own.
        let signed = sign_element(unsigned.as_bytes(), "_r1", &key).expect("sign response");
        (signed, cert_pem)
    }

    fn idp_config(cert_pem: String, want_assertions_signed: bool) -> SamlIdpConfig {
        use crate::core::IdpId;
        use std::collections::BTreeMap;
        SamlIdpConfig {
            idp_id: IdpId::generate(),
            name: "corp".to_string(),
            entity_id: "https://idp.example".to_string(),
            sso_url: "https://idp.example/sso".to_string(),
            slo_url: None,
            idp_certificates_pem: vec![cert_pem],
            sign_authn_requests: false,
            want_assertions_signed,
            attribute_map: BTreeMap::new(),
        }
    }

    /// S4 (HEA-1751): with `want_assertions_signed = true`, a Response whose
    /// envelope is signed but whose Assertion is NOT individually signed MUST
    /// be rejected — a Response-level signature is not a substitute. This
    /// guards against re-introducing the hardcoded `want_assertions_signed =
    /// false` that let unsigned assertions through.
    #[test]
    fn want_assertions_signed_rejects_response_only_signature() {
        let (xml, cert_pem) = response_signed_but_assertion_unsigned();
        let idp = idp_config(cert_pem, /* want_assertions_signed */ true);
        let now = Timestamp::from_micros(1_700_000_100 * 1_000_000);

        let outcome = SamlSpService::complete(
            &idp,
            "https://sp.example",
            "https://sp.example/acs",
            None,
            now,
            &xml,
        );
        match outcome {
            SamlSpOutcome::Rejected { error } => assert!(
                matches!(error, IdentityError::Saml(SamlError::Signature)),
                "expected Signature rejection, got {error:?}"
            ),
            SamlSpOutcome::Accepted { .. } => {
                panic!("unsigned assertion accepted despite want_assertions_signed=true")
            }
        }
    }

    /// Companion to the above: the SAME Response-level-only signature is
    /// ACCEPTED when `want_assertions_signed = false`. Pairing the two proves
    /// the flag — not some unrelated validation error — is what gates the
    /// signature requirement.
    #[test]
    fn response_level_signature_accepted_when_assertions_not_required() {
        let (xml, cert_pem) = response_signed_but_assertion_unsigned();
        let idp = idp_config(cert_pem, /* want_assertions_signed */ false);
        let now = Timestamp::from_micros(1_700_000_100 * 1_000_000);

        let outcome = SamlSpService::complete(
            &idp,
            "https://sp.example",
            "https://sp.example/acs",
            None,
            now,
            &xml,
        );
        match outcome {
            SamlSpOutcome::Accepted { identity, .. } => {
                assert_eq!(identity.external_sub, "alice@example.com");
            }
            SamlSpOutcome::Rejected { error } => {
                panic!("response-level signature must be accepted when assertion signing is not required, got {error:?}")
            }
        }
    }
}
