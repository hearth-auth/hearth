//! Integration tests for the consent delegation management (AGENT_AUTH.md §3.5).
//!
//! TDD — tests written before implementation. Covers:
//! - §3.5: Delegation grant persisted after RFC 8693 token exchange
//! - §3.5: list_delegation_grants returns active grants for the user
//! - §3.5: revoke_delegation_grant immediately invalidates the grant
//! - §3.5: revoked delegation does not appear in listing
//! - §3.5: revocation of another user's grant returns DelegationGrantNotFound

mod common;

use hearth::core::{AgentId, RealmId, UserId};
use hearth::identity::{
    AgentOwner, CreateAgentRequest, CreateRealmRequest, CreateUserRequest, IdentityEngine,
    IdentityError, Rfc8693Request,
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

fn make_agent(identity: &dyn IdentityEngine, realm_id: &RealmId, owner_id: &UserId) -> AgentId {
    identity
        .create_agent(
            realm_id,
            &CreateAgentRequest {
                display_name: format!("CD agent {}", uuid::Uuid::new_v4()),
                description: None,
                owner: AgentOwner::User(owner_id.clone()),
                capabilities: vec![],
                max_delegation_depth: 3,
            },
            None,
        )
        .expect("create agent")
        .id()
        .clone()
}

/// Build a mock subject token JWT (user access token).
///
/// Uses `user_id.to_string()` (prefixed) for the `sub` claim, matching what
/// the real token issuance path produces.
fn build_subject_jwt(
    user_id: &UserId,
    realm_id: &RealmId,
    scope: &str,
    exp: i64,
    iat: i64,
) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT","kid":"test"}"#);
    let payload_json = serde_json::json!({
        "sub": user_id.to_string(),
        "iss": "hearth",
        "aud": "hearth",
        "exp": exp,
        "iat": iat,
        "sid": "sid-test",
        "tid": realm_id.to_string(),
        "token_type": "access",
        "jti": uuid::Uuid::new_v4().to_string(),
        "scope": scope,
        "roles": [],
        "groups": [],
        "permissions": [],
        "required_actions": [],
    });
    let payload = URL_SAFE_NO_PAD.encode(payload_json.to_string());
    let sig = URL_SAFE_NO_PAD.encode("fakesig");
    format!("{header}.{payload}.{sig}")
}

/// Build a mock actor-token JWT (agent assertion).
fn build_actor_jwt(actor_sub: &str, exp: i64, iat: i64, jti: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT","kid":"agent-key"}"#);
    let payload_json = serde_json::json!({
        "iss": actor_sub,
        "sub": actor_sub,
        "aud": "hearth",
        "exp": exp,
        "iat": iat,
        "jti": jti,
    });
    let payload = URL_SAFE_NO_PAD.encode(payload_json.to_string());
    let sig = URL_SAFE_NO_PAD.encode("fakesig");
    format!("{header}.{payload}.{sig}")
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs() as i64
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
    let owner_id = make_user(identity, &realm_id);
    let agent_id = make_agent(identity, &realm_id, &owner_id);

    let now = now_secs();
    let actor_sub = format!("agt_{}", agent_id.as_uuid());
    let subject_token = build_subject_jwt(&user_id, &realm_id, "mcp:tools:invoke", now + 900, now);
    let actor_jti = uuid::Uuid::new_v4().to_string();
    let actor_token = build_actor_jwt(&actor_sub, now + 60, now, &actor_jti);

    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());
    let request = Rfc8693Request {
        client_id,
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
        g.actor_sub, actor_sub,
        "actor_sub should match agent identifier"
    );
    assert!(
        g.granted_scopes.contains(&"mcp:tools:invoke".to_string()),
        "granted_scopes should contain the requested scope"
    );
    assert!(!g.delegation_id.is_empty(), "delegation_id must be set");
}

/// After revocation, the delegation no longer appears in the listing.
#[tokio::test]
async fn revoked_delegation_not_in_listing() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let owner_id = make_user(identity, &realm_id);
    let agent_id = make_agent(identity, &realm_id, &owner_id);

    let now = now_secs();
    let actor_sub = format!("agt_{}", agent_id.as_uuid());
    let subject_token = build_subject_jwt(&user_id, &realm_id, "mcp:tools:invoke", now + 900, now);
    let actor_jti = uuid::Uuid::new_v4().to_string();
    let actor_token = build_actor_jwt(&actor_sub, now + 60, now, &actor_jti);

    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());
    let request = Rfc8693Request {
        client_id,
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
    assert_eq!(grants.len(), 1, "setup: one delegation expected");

    let delegation_id = grants[0].delegation_id.clone();

    identity
        .revoke_delegation_grant(&realm_id, &delegation_id, &user_sub)
        .expect("revoke should succeed");

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
    let owner_id = make_user(identity, &realm_id);
    let agent_id = make_agent(identity, &realm_id, &owner_id);

    let now = now_secs();
    let actor_sub = format!("agt_{}", agent_id.as_uuid());
    let subject_token = build_subject_jwt(&user_a, &realm_id, "mcp:tools:invoke", now + 900, now);
    let actor_jti = uuid::Uuid::new_v4().to_string();
    let actor_token = build_actor_jwt(&actor_sub, now + 60, now, &actor_jti);

    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());
    let request = Rfc8693Request {
        client_id,
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
    let owner_id = make_user(identity, &realm_id);
    let agent_id = make_agent(identity, &realm_id, &owner_id);

    let now = now_secs();
    let actor_sub = format!("agt_{}", agent_id.as_uuid());
    let subject_token = build_subject_jwt(&user_id, &realm_id, "mcp:tools:invoke", now + 900, now);
    let actor_jti = uuid::Uuid::new_v4().to_string();
    let actor_token = build_actor_jwt(&actor_sub, now + 60, now, &actor_jti);

    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());
    let request = Rfc8693Request {
        client_id,
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: Some(actor_token),
        actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
        requested_token_type: None,
        scope: None,
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
