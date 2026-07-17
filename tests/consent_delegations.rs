//! Integration tests for the consent delegation management (AGENT_AUTH.md §3.5).
//!
//! TDD — tests written before implementation. Covers:
//! - §3.5: Delegation grant persisted after RFC 8693 token exchange
//! - §3.5: list_delegation_grants returns active grants for the user
//! - §3.5: revoke_delegation_grant immediately invalidates the grant
//! - §3.5: revoked delegation does not appear in listing
//! - §3.5: revocation of another user's grant returns DelegationGrantNotFound

mod common;

use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::{
    AccessTokenAuthorization, ClientCredentialsRequest, ClientTrustLevel, CreateRealmRequest,
    CreateUserRequest, IdentityEngine, IdentityError, RegisterClientRequest, Rfc8693Request,
    SessionContext, TokenIssuanceContext,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_realm(identity: &dyn IdentityEngine) -> RealmId {
    identity
        .create_realm(&CreateRealmRequest {
            name: format!("cd-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn make_user(identity: &dyn IdentityEngine, realm_id: &RealmId) -> UserId {
    identity
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: format!("cd-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "CD User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone()
}

/// Register an OAuth client and issue a real `client_credentials` access token.
///
/// Returns `(client_id, access_token)`. The `client_id` MUST be used as
/// `Rfc8693Request.client_id` so that the `actor_token.sub == client_id` assertion passes
/// (F3 / HEA-1466).
fn make_actor_token(
    identity: &dyn IdentityEngine,
    realm_id: &RealmId,
    scope: &str,
) -> (ClientId, String) {
    const SECRET: &str = "actor-test-secret!";
    let declared: Vec<String> = scope.split_whitespace().map(String::from).collect();
    let client = identity
        .register_client(
            realm_id,
            &RegisterClientRequest {
                client_name: format!("cd-actor-{}", uuid::Uuid::new_v4()),
                client_secret: Some(SECRET.to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                declared_scopes: declared,
                access_token_authorization: AccessTokenAuthorization::Embedded,
                ..Default::default()
            },
        )
        .expect("register actor client");
    let client_id = client.client_id().clone();
    let resp = identity
        .client_credentials_token(
            realm_id,
            &ClientCredentialsRequest {
                client_id: client_id.clone(),
                client_secret: Some(SECRET.to_string()),
                scope: if scope.is_empty() {
                    None
                } else {
                    Some(scope.to_string())
                },
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("issue actor access token");
    (client_id, resp.access_token().to_string())
}

/// Issue a real Ed25519-signed access token for `user_id` with explicit `scope`.
///
/// After HEA-1470, `rfc8693_token_exchange` calls `validate_token`, so subject
/// tokens must be cryptographically valid.
fn build_subject_jwt(
    identity: &dyn IdentityEngine,
    user_id: &UserId,
    realm_id: &RealmId,
    scope: &str,
) -> String {
    use std::collections::BTreeSet;

    let session = identity
        .create_session(realm_id, user_id, &SessionContext::default())
        .expect("create session for subject token");
    let granted_scopes: BTreeSet<String> = scope.split_whitespace().map(String::from).collect();
    identity
        .issue_tokens_with_context(
            realm_id,
            user_id,
            session.id(),
            &TokenIssuanceContext {
                client_id: None,
                granted_scopes,
                oid: None,
                resource: None,
            },
        )
        .expect("issue subject token")
        .access_token()
        .to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// §3.5 Delegation persistence
// ─────────────────────────────────────────────────────────────────────────────

/// RFC 8693 token exchange → delegation grant appears in list.
#[tokio::test]
async fn delegation_grant_persisted_after_exchange() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    let subject_token = build_subject_jwt(identity, &user_id, &realm_id, "mcp:tools:invoke");

    // F3 (HEA-1466): use a Hearth-signed actor token; client_id must match actor_token.sub.
    let (actor_client_id, actor_token) = make_actor_token(identity, &realm_id, "mcp:tools:invoke");

    let request = Rfc8693Request {
        client_id: actor_client_id.clone(),
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: Some(actor_token),
        actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
        requested_token_type: None,
        scope: Some("mcp:tools:invoke".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect("token exchange should succeed");

    let user_sub = user_id.to_string();
    let grants = identity
        .list_delegation_grants(&realm_id, &user_sub)
        .expect("list should succeed");

    assert_eq!(grants.len(), 1, "exactly one delegation grant expected");
    let g = &grants[0];
    assert_eq!(
        g.actor_sub,
        actor_client_id.to_string(),
        "actor_sub must equal the actor's client_id"
    );
    assert!(
        g.granted_scopes.contains(&"mcp:tools:invoke".to_string()),
        "granted_scopes should contain the requested scope"
    );
    assert!(!g.delegation_id.is_empty(), "delegation_id must be set");
}

/// G1 regression (HEA-1753): revoking a delegation consent must immediately
/// invalidate the previously-issued, **session-bound** OBO access token — not
/// merely drop it from the listing. The prior test only asserted the listing no
/// longer showed the grant (false confidence): it never re-validated the issued
/// token, so the broken session-path revocation check went undetected. The OBO
/// token issued by `rfc8693_token_exchange` inherits the subject's `sid`
/// (session-bound), and revocation projects its `jti` into the revocation
/// cache; `validate_token` must reject it on the session path.
#[tokio::test]
async fn revoked_delegation_rejects_previously_issued_obo_token() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    let subject_token = build_subject_jwt(identity, &user_id, &realm_id, "mcp:tools:invoke");
    let (actor_client_id, actor_token) = make_actor_token(identity, &realm_id, "mcp:tools:invoke");

    let request = Rfc8693Request {
        client_id: actor_client_id,
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: Some(actor_token),
        actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
        requested_token_type: None,
        scope: Some("mcp:tools:invoke".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    let exchange = identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect("exchange should succeed");
    let obo_token = exchange.access_token.clone();

    // Sanity: the freshly-issued OBO token validates before revocation.
    identity
        .validate_token(&realm_id, &obo_token)
        .expect("OBO token must be valid before consent revocation");

    let user_sub = user_id.to_string();
    let grants = identity
        .list_delegation_grants(&realm_id, &user_sub)
        .expect("list should succeed");
    assert_eq!(grants.len(), 1, "setup: one delegation expected");
    let delegation_id = grants[0].delegation_id.clone();

    // Revoke the delegation consent.
    identity
        .revoke_delegation_grant(&realm_id, &delegation_id, &user_sub)
        .expect("revoke should succeed");

    // The previously-issued session-bound OBO token must now be rejected.
    let after = identity.validate_token(&realm_id, &obo_token);
    assert!(
        after.is_err(),
        "revoked delegation must invalidate the previously-issued OBO token, got: {after:?}"
    );

    // And it must no longer appear in the listing (retains prior coverage).
    let grants_after = identity
        .list_delegation_grants(&realm_id, &user_sub)
        .expect("list after revoke should succeed");
    assert!(
        grants_after.is_empty(),
        "revoked delegation must not appear in listing"
    );
}

/// Revocation of another user's grant returns DelegationGrantNotFound.
#[tokio::test]
async fn revoke_other_users_delegation_is_not_found() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_a = make_user(identity, &realm_id);
    let user_b = make_user(identity, &realm_id);

    let subject_token = build_subject_jwt(identity, &user_a, &realm_id, "mcp:tools:invoke");
    let (actor_client_id, actor_token) = make_actor_token(identity, &realm_id, "mcp:tools:invoke");

    let request = Rfc8693Request {
        client_id: actor_client_id,
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: Some(actor_token),
        actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
        requested_token_type: None,
        scope: Some("mcp:tools:invoke".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect("exchange should succeed");

    // user_a's delegation_id
    let sub_a = user_a.to_string();
    let grants = identity
        .list_delegation_grants(&realm_id, &sub_a)
        .expect("list should succeed");
    assert_eq!(grants.len(), 1);
    let delegation_id = grants[0].delegation_id.clone();

    // user_b tries to revoke user_a's delegation — must fail
    let sub_b = user_b.to_string();
    let err = identity
        .revoke_delegation_grant(&realm_id, &delegation_id, &sub_b)
        .expect_err("cross-user revoke should be rejected");

    assert!(
        matches!(err, IdentityError::DelegationGrantNotFound),
        "expected DelegationGrantNotFound for cross-user revoke, got: {err}"
    );
}

/// Revocation idempotency — revoking twice is safe.
#[tokio::test]
async fn revoke_delegation_is_idempotent() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    let subject_token = build_subject_jwt(identity, &user_id, &realm_id, "mcp:tools:invoke");
    let (actor_client_id, actor_token) = make_actor_token(identity, &realm_id, "mcp:tools:invoke");

    let request = Rfc8693Request {
        client_id: actor_client_id,
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: Some(actor_token),
        actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
        requested_token_type: None,
        scope: Some("mcp:tools:invoke".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect("exchange should succeed");

    let user_sub = user_id.to_string();
    let grants = identity
        .list_delegation_grants(&realm_id, &user_sub)
        .expect("list should succeed");
    let delegation_id = grants[0].delegation_id.clone();

    identity
        .revoke_delegation_grant(&realm_id, &delegation_id, &user_sub)
        .expect("first revoke should succeed");

    // Second revoke — idempotent
    identity
        .revoke_delegation_grant(&realm_id, &delegation_id, &user_sub)
        .expect("second revoke should be idempotent");
}

/// Empty sub returns empty list without error.
#[tokio::test]
async fn list_delegation_grants_empty_for_new_user() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    let user_sub = user_id.to_string();
    let grants = identity
        .list_delegation_grants(&realm_id, &user_sub)
        .expect("list should succeed for user with no delegations");

    assert!(
        grants.is_empty(),
        "new user should have no delegation grants"
    );
}
