//! Adversarial tests for A-38: `cnf.jkt` enforcement and RFC 8693 `act`
//! chain depth cap.
//!
//! Covers:
//! - A-38a: `client_credentials` access tokens require `dpop_jkt` for a client
//!   registered with `dpop_bound_access_tokens` (RFC 9449 §5.2); with a proof
//!   the token carries `cnf.jkt`.
//! - A-38c: `client_credentials` without `dpop_jkt` for a client without the
//!   flag succeeds.
//! - A-38d: `MAX_ACT_CHAIN_DEPTH` is the documented sentinel value of 3.

mod common;

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use hearth::abuse::MAX_ACT_CHAIN_DEPTH;
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
            },
        )
        .expect("client_credentials without dpop_jkt must succeed for an unbound client");

    assert!(
        !resp.access_token().is_empty(),
        "access token must be non-empty"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-38d — MAX_ACT_CHAIN_DEPTH sentinel
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the constant equals the documented default so spec and code
/// stay in sync. Raised from 3 → 10 in HEA-1406 (M2 Phase B: delegation chains
/// need deeper `max_delegation_depth` per AGENT_AUTH.md §3.4).
#[test]
fn a38d_max_act_chain_depth_is_10() {
    assert_eq!(
        MAX_ACT_CHAIN_DEPTH, 10,
        "constant changed — update docs/specs/AGENT_AUTH.md and CHANGELOG"
    );
}
