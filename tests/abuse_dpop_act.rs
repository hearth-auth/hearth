//! Adversarial tests for A-38: `cnf.jkt` enforcement and RFC 8693 `act`
//! chain depth cap.
//!
//! Covers:
//! - A-38a: `client_credentials` access tokens require `dpop_jkt` for a client
//!   registered with `dpop_bound_access_tokens` (RFC 9449 §5.2); with a proof
//!   the token carries `cnf.jkt`.
//! - A-38c: `client_credentials` without `dpop_jkt` for a client without the
//!   flag succeeds.
//! - A-38d: `security.max_act_chain_depth` defaults to 3 and must be in `1`–`32`.

mod common;

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use hearth::config::Config;
use hearth::identity::oidc::{ClientCredentialsRequest, RegisterClientRequest};

// ─────────────────────────────────────────────────────────────────────────────
// A-38a — `dpop_bound_access_tokens` cnf.jkt enforcement on client_credentials
// ─────────────────────────────────────────────────────────────────────────────

/// A `dpop_bound_access_tokens` client — `client_credentials` without
/// `dpop_jkt` must be rejected with `InvalidDPopProof`.
#[tokio::test]
async fn a38a_dpop_bound_client_credentials_without_dpop_rejected() {
    let harness = common::TestHarness::in_process()
        .await
        .expect("harness setup");

    let realm_id = harness.create_realm();

    // A confidential client that must use sender-constrained tokens.
    let client = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "m2m-dpop-bound-test".to_string(),
                redirect_uris: vec![],
                client_secret: Some("super-secret-123!".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                dpop_bound_access_tokens: true,
                ..Default::default()
            },
        )
        .expect("register client");

    // Attempt client_credentials WITHOUT dpop_jkt — must be rejected.
    let err = harness
        .identity()
        .client_credentials_token(
            &realm_id,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: Some("super-secret-123!".to_string()),
                scope: Some("openid".to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
                resource: None,
            },
        )
        .expect_err("must fail without dpop_jkt for a dpop_bound_access_tokens client");

    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::InvalidDPopProof { .. }
        ),
        "expected InvalidDPopProof, got: {err:?}"
    );
}

/// A `dpop_bound_access_tokens` client — `client_credentials` WITH a dummy
/// `dpop_jkt` thumbprint must succeed (the token carries `cnf.jkt`).
#[tokio::test]
async fn a38a_dpop_bound_client_credentials_with_dpop_jkt_accepted() {
    let harness = common::TestHarness::in_process()
        .await
        .expect("harness setup");

    let realm_id = harness.create_realm();

    let client = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "m2m-with-dpop".to_string(),
                redirect_uris: vec![],
                client_secret: Some("super-secret-456!".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                dpop_bound_access_tokens: true,
                ..Default::default()
            },
        )
        .expect("register client");

    // A JWK thumbprint is a base64url-encoded SHA-256 digest of the JWK.
    // Use a fixed test thumbprint — the server only stores it in cnf.jkt.
    const DUMMY_JKT: &str = "OKVsYiUkGsOrgWxWpGpzDRzZpISBgekj0RvDqxNYors";

    let resp = harness
        .identity()
        .client_credentials_token(
            &realm_id,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: Some("super-secret-456!".to_string()),
                scope: Some("openid".to_string()),
                dpop_jkt: Some(DUMMY_JKT.to_string()),
                client_assertion_type: None,
                client_assertion: None,
                resource: None,
            },
        )
        .expect(
            "client_credentials with dpop_jkt must succeed for a dpop_bound_access_tokens client",
        );

    assert!(
        !resp.access_token().is_empty(),
        "access token must be non-empty"
    );

    // The docstring claims the token carries `cnf.jkt`; decode the JWT payload
    // and assert the confirmation claim actually binds the supplied thumbprint.
    // Without decoding, a token with no `cnf` would pass the non-empty check
    // vacuously.
    let parts: Vec<&str> = resp.access_token().split('.').collect();
    assert_eq!(parts.len(), 3, "access token must be a 3-part JWS");
    let claims_json = BASE64_URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64 decode claims");
    let claims: serde_json::Value =
        serde_json::from_slice(&claims_json).expect("parse claims JSON");
    assert_eq!(
        claims["cnf"]["jkt"].as_str(),
        Some(DUMMY_JKT),
        "token must carry cnf.jkt binding the supplied thumbprint; got: {claims}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-38c — Client without `dpop_bound_access_tokens`: no dpop_jkt enforcement
// ─────────────────────────────────────────────────────────────────────────────

/// A client without `dpop_bound_access_tokens` — `client_credentials` without
/// `dpop_jkt` must succeed (DPoP is optional for it).
#[tokio::test]
async fn a38c_unbound_client_credentials_without_dpop_ok() {
    let harness = common::TestHarness::in_process()
        .await
        .expect("harness setup");

    let realm_id = harness.create_realm();

    let client = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "unbound-m2m".to_string(),
                redirect_uris: vec![],
                client_secret: Some("super-secret-000!".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    let resp = harness
        .identity()
        .client_credentials_token(
            &realm_id,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: Some("super-secret-000!".to_string()),
                scope: Some("openid".to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
                resource: None,
            },
        )
        .expect("client_credentials without dpop_jkt must succeed for an unbound client");

    assert!(
        !resp.access_token().is_empty(),
        "access token must be non-empty"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-38d — `security.max_act_chain_depth`
// ─────────────────────────────────────────────────────────────────────────────

/// A production config with `security_extra` inside the `security:` block.
fn prod_yaml(security_extra: &str) -> String {
    format!(
        "server:\n  trust_forwarded_proto: true\n  trusted_proxies: [\"127.0.0.1\"]\n\
         storage:\n  data_dir: \"/tmp/hearth-a38d\"\n\
         security:\n  key_encryption_key: \"\
         1111111111111111111111111111111111111111111111111111111111111111\"\n{security_extra}\
         oidc:\n  issuer: \"https://auth.example.test\"\n\
         email:\n  allow_log_transport_in_production: true\n"
    )
}

/// Scenario "The default delegation chain depth ceiling is 3".
#[test]
fn a38d_the_default_ceiling_is_3() {
    let config = Config::from_yaml_str(&prod_yaml("")).expect("config without the key loads");
    assert_eq!(config.security.max_act_chain_depth, 3);
}

/// Scenario "A ceiling out of range": `0` and `33` fail and name the key;
/// the bounds `1` and `32` load.
#[test]
fn a38d_a_ceiling_out_of_range_is_refused() {
    for bad in [0, 33] {
        let err = Config::from_yaml_str(&prod_yaml(&format!("  max_act_chain_depth: {bad}\n")))
            .expect_err("a ceiling outside 1..=32 is refused");
        assert!(
            err.to_string().contains("security.max_act_chain_depth"),
            "value {bad}: the error must name the key; got: {err}"
        );
    }
    for good in [1_u8, 32] {
        let config = Config::from_yaml_str(&prod_yaml(&format!("  max_act_chain_depth: {good}\n")))
            .expect("a ceiling inside 1..=32 loads");
        assert_eq!(config.security.max_act_chain_depth, good);
    }
}
