//! Realm status must be enforced on the machine-to-machine plane
//! (audit 2026-08-28 §4.19#6).
//!
//! Suspending a realm revokes user sessions, but sessionless tokens have no
//! session to revoke. Before the fix, the two sessionless grants
//! (`client_credentials` and `jwt-bearer`) kept minting fresh tokens, and
//! neither `introspect` nor `decide` consulted realm status — a suspended
//! tenant's M2M plane kept working.

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    ClientCredentialsRequest, CreateRealmRequest, DecidePermissionRequest, IdentityError,
    JwtBearerRequest, RealmStatus, RegisterClientRequest, TokenIntrospectionRequest,
    UpdateRealmRequest,
};

const CLIENT_SECRET: &str = "m2m-suspend-secret-123!";

fn create_realm(harness: &common::TestHarness) -> RealmId {
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("m2m-suspend-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    realm.id().clone()
}

/// Registers a confidential `client_credentials` client and returns its ID.
fn register_m2m_client(harness: &common::TestHarness, realm: &RealmId) -> hearth::core::ClientId {
    harness
        .identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "Suspension M2M Client".to_string(),
                redirect_uris: vec![],
                client_secret: Some(CLIENT_SECRET.to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register confidential client")
        .client_id()
        .clone()
}

fn cc_request(client_id: &hearth::core::ClientId) -> ClientCredentialsRequest {
    ClientCredentialsRequest {
        client_id: client_id.clone(),
        client_secret: Some(CLIENT_SECRET.to_string()),
        scope: Some("read".to_string()),
        dpop_jkt: None,
        client_assertion_type: None,
        client_assertion: None,
    }
}

fn suspend_realm(harness: &common::TestHarness, realm: &RealmId) {
    harness
        .identity()
        .update_realm(
            realm,
            &UpdateRealmRequest {
                name: None,
                status: Some(RealmStatus::Suspended),
                config: None,
            },
        )
        .expect("suspend realm");
}

/// A suspended realm must not mint fresh client-credentials tokens.
#[tokio::test]
async fn suspended_realm_refuses_client_credentials_grant() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&harness);
    let client_id = register_m2m_client(&harness, &realm);

    // Sanity: the grant works while the realm is active.
    harness
        .identity()
        .client_credentials_token(&realm, &cc_request(&client_id))
        .expect("grant works while active");

    suspend_realm(&harness, &realm);

    let err = harness
        .identity()
        .client_credentials_token(&realm, &cc_request(&client_id))
        .expect_err("a suspended realm must not mint tokens (audit §4.19#6)");
    assert!(
        matches!(err, IdentityError::RealmSuspended),
        "expected RealmSuspended, got {err:?}"
    );
}

/// The jwt-bearer grant must check realm status before anything else, so a
/// suspended realm answers `RealmSuspended` — not an assertion error.
#[tokio::test]
async fn suspended_realm_refuses_jwt_bearer_grant() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&harness);
    let client_id = register_m2m_client(&harness, &realm);

    suspend_realm(&harness, &realm);

    let err = harness
        .identity()
        .jwt_bearer_token(
            &realm,
            &JwtBearerRequest {
                client_id,
                assertion: "not-a-real-assertion".to_string(),
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("a suspended realm must not mint tokens (audit §4.19#6)");
    assert!(
        matches!(err, IdentityError::RealmSuspended),
        "the realm-status gate must fire before assertion parsing, got {err:?}"
    );
}

/// A token minted before suspension must introspect as inactive and must not
/// authorize through `decide` while the realm is suspended.
#[tokio::test]
async fn suspended_realm_token_is_inactive_on_introspect_and_decide() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&harness);
    let client_id = register_m2m_client(&harness, &realm);

    let token = harness
        .identity()
        .client_credentials_token(&realm, &cc_request(&client_id))
        .expect("mint while active")
        .access_token()
        .to_string();

    // Sanity: active before suspension.
    let before = harness
        .identity()
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: token.clone(),
                token_type_hint: None,
                introspecting_client_id: None,
            },
        )
        .expect("introspect while active");
    assert!(
        before.active,
        "precondition: token active before suspension"
    );

    suspend_realm(&harness, &realm);

    let after = harness
        .identity()
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: token.clone(),
                token_type_hint: None,
                introspecting_client_id: None,
            },
        )
        .expect("introspect must answer, not error (RFC 7662)");
    assert!(
        !after.active,
        "a suspended realm's token must introspect inactive (audit §4.19#6)"
    );

    let decision = harness
        .identity()
        .decide_token_permission(
            &realm,
            &DecidePermissionRequest {
                token,
                permission: "docs.read".to_string(),
                organization_id: None,
                resource: None,
            },
        )
        .expect("decide must answer fail-closed, not error");
    assert!(
        !decision.allowed,
        "a suspended realm's token must not authorize (audit §4.19#6)"
    );
}
