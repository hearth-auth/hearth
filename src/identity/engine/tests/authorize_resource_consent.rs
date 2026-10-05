//! G6 — the consent record an authorization request is checked against is
//! keyed by the resource's canonical form (`core::Uri`), so every spelling of
//! one protected resource reads the same record.
//!
//! The key used to be built from the raw `resource` string: a spelling
//! differing only in case, default port or a trailing slash looked up a
//! different key and missed the record entirely.

use super::*;

use crate::core::Uri;

const CANONICAL: &str = "https://mcp.example.com/api";

#[test]
fn every_spelling_of_a_resource_reads_the_same_consent_record() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);
    engine
        .register_protected_resource(
            &realm,
            &crate::identity::RegisterProtectedResourceRequest {
                resource_uri: CANONICAL.to_string(),
                display_name: "MCP".to_string(),
                scopes: Vec::new(),
                required_claims: Vec::new(),
                introspection_client_id: None,
            },
        )
        .expect("register resource");
    let client = engine
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "consent-key".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                trust_level: crate::identity::ClientTrustLevel::ThirdParty,
                ..Default::default()
            },
        )
        .expect("client")
        .client_id()
        .clone();

    // Consent granted under the canonical spelling.
    engine
        .grant_consent(
            &realm,
            &crate::identity::ConsentGrant {
                key: crate::identity::ConsentKey {
                    user_id: user.id().clone(),
                    client_id: client.clone(),
                    org_id: None,
                    resource: Some(Uri::try_from(CANONICAL.to_string()).expect("uri")),
                },
                scopes: vec!["openid".to_string()],
                via: crate::identity::ConsentSurface::Web,
            },
        )
        .expect("consent");

    for spelling in [CANONICAL, "HTTPS://MCP.Example.com:443/api/"] {
        let outcome = engine
            .authorization_scopes(&realm, user.id(), &client, "openid", Some(spelling), None)
            .expect("resolve");
        assert_eq!(
            outcome.consent,
            crate::identity::ConsentState::Held,
            "resource spelled {spelling:?} did not read the resource's consent row"
        );
    }
}
