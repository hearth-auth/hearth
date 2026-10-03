//! G6 — the consent record an authorization request is checked against is
//! keyed by the resource's canonical form (`core::Uri`), so every spelling of
//! one protected resource reads the same record.
//!
//! The key used to be built from the raw `resource` string: a spelling
//! differing only in case, default port or a trailing slash looked up a
//! different key and missed the record entirely.

use super::*;

use crate::identity::oidc::CodeChallengeMethod;

const CANONICAL: &str = "https://mcp.example.com/api";

#[test]
fn every_spelling_of_a_resource_reads_the_same_consent_record() {
    use base64::Engine as _;
    let (_dir, engine, clock) = setup_engine();
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
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("client")
        .client_id()
        .clone();

    // A record for the resource whose digest no longer matches its scopes:
    // the authorize-time re-check refuses it with `ConsentRequired`, which is
    // how this test observes that the record was found.
    let mut record = ConsentRecord::new(
        user.id().clone(),
        client.clone(),
        vec!["openid".to_string()],
        clock.now(),
    );
    record.resource = Some(CANONICAL.to_string());
    record.scope_digest = vec![0u8; 32];
    engine
        .storage
        .put(
            &realm,
            &keys::encode_consent_key_extended(
                user.id(),
                &client,
                keys::CONSENT_ORG_KEY_REALM,
                CANONICAL,
            ),
            &serde_json::to_vec(&record).expect("serialize"),
        )
        .expect("put consent");

    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        ring::digest::digest(&ring::digest::SHA256, b"consent-key-verifier-0123456789ab").as_ref(),
    );
    for spelling in [CANONICAL, "HTTPS://MCP.Example.com:443/api/"] {
        let outcome = engine.authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.clone(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                scope: "openid".to_string(),
                state: "st".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(challenge.clone()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: Some(spelling.to_string()),
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
            },
        );
        assert!(
            matches!(outcome, Err(IdentityError::ConsentRequired)),
            "resource spelled {spelling:?} did not read the resource's consent record: {:?}",
            outcome.map(|r| r.code().to_string())
        );
    }
}
