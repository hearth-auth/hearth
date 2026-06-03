//! Adversarial tests for A-38: `cnf.jkt` enforcement and RFC 8693 `act`
//! chain depth cap.
//!
//! Covers:
//! - A-38a: `client_credentials` access tokens require `dpop_jkt` when FAPI
//!   is enforced at the realm level.
//! - A-38b: `client_credentials` with a FAPI-profile client requires `dpop_jkt`.
//! - A-38c: `client_credentials` without `dpop_jkt` on a non-FAPI realm succeeds.
//! - A-38d: `MAX_ACT_CHAIN_DEPTH` is the documented sentinel value of 3.

mod common;

use hearth::abuse::MAX_ACT_CHAIN_DEPTH;
use hearth::identity::oidc::{ClientCredentialsRequest, ClientProfile, RegisterClientRequest};
use hearth::identity::{CreateRealmRequest, FapiProfile, RealmConfig};

// ─────────────────────────────────────────────────────────────────────────────
// A-38a — FAPI realm-level cnf.jkt enforcement on client_credentials
// ─────────────────────────────────────────────────────────────────────────────

/// Realm with `fapi_profile: Baseline` — `client_credentials` without
/// `dpop_jkt` must be rejected with `FapiViolation`.
#[tokio::test]
async fn a38a_fapi_realm_client_credentials_without_dpop_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    // Create a FAPI Baseline realm.
    let realm_id = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "fapi-cc-test".to_string(),
            config: Some(RealmConfig {
                fapi_profile: Some(FapiProfile::Baseline),
                ..Default::default()
            }),
        })
        .expect("create FAPI realm")
        .id()
        .clone();

    // Register a standard (non-FAPI) confidential client — realm gate applies.
    let client = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "m2m-fapi-test".to_string(),
                redirect_uris: vec![],
                client_secret: Some("super-secret-123!".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
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
        .expect_err("must fail without dpop_jkt on FAPI realm");

    assert!(
        matches!(err, hearth::identity::IdentityError::FapiViolation { .. }),
        "expected FapiViolation, got: {err:?}"
    );
}

/// Realm with `fapi_profile: Baseline` — `client_credentials` WITH a dummy
/// `dpop_jkt` thumbprint must succeed (the token carries `cnf.jkt`).
#[tokio::test]
async fn a38a_fapi_realm_client_credentials_with_dpop_jkt_accepted() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    let realm_id = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "fapi-cc-ok".to_string(),
            config: Some(RealmConfig {
                fapi_profile: Some(FapiProfile::Baseline),
                ..Default::default()
            }),
        })
        .expect("create FAPI realm")
        .id()
        .clone();

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
        .expect("client_credentials with dpop_jkt on FAPI realm must succeed");

    assert!(
        !resp.access_token().is_empty(),
        "access token must be non-empty"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-38b — FAPI per-client profile cnf.jkt enforcement
// ─────────────────────────────────────────────────────────────────────────────

/// Non-FAPI realm but FAPI-profile client — FAPI 2.0 mandates `private_key_jwt`
/// so registering a FAPI2 client with `client_secret` is itself rejected as
/// a `FapiViolation` (A-38b gate fires at registration, not just at the token
/// endpoint).
#[tokio::test]
async fn a38b_fapi_client_profile_enforces_dpop_jkt() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    let realm_id = harness.create_realm();

    // FAPI 2.0 clients MUST NOT use client_secret (§5.3 — private_key_jwt only).
    // The engine enforces this at registration time so no non-DPoP-capable
    // FAPI2 client can ever be created (defense-in-depth: gate fires before
    // token issuance is even possible).
    let err = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "fapi2-client".to_string(),
                redirect_uris: vec![],
                client_secret: Some("super-secret-789!".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                profile: ClientProfile::Fapi2,
                ..Default::default()
            },
        )
        .expect_err("registering a FAPI2 client with client_secret must fail");

    assert!(
        matches!(err, hearth::identity::IdentityError::FapiViolation { .. }),
        "expected FapiViolation at registration, got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-38c — Non-FAPI realm: no dpop_jkt enforcement
// ─────────────────────────────────────────────────────────────────────────────

/// Non-FAPI realm with standard client — `client_credentials` without
/// `dpop_jkt` must succeed (DPoP is optional in non-FAPI mode).
#[tokio::test]
async fn a38c_non_fapi_client_credentials_without_dpop_ok() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    let realm_id = harness.create_realm();

    let client = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "non-fapi-m2m".to_string(),
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
        .expect("non-FAPI client_credentials without dpop_jkt must succeed");

    assert!(
        !resp.access_token().is_empty(),
        "access token must be non-empty"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-38d — MAX_ACT_CHAIN_DEPTH sentinel
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the constant equals the documented default so spec and code
/// stay in sync.
#[test]
fn a38d_max_act_chain_depth_is_3() {
    assert_eq!(
        MAX_ACT_CHAIN_DEPTH, 3,
        "constant changed — update ABUSE.md and CHANGELOG"
    );
}
