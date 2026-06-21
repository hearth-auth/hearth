//! Integration tests for RFC 8693 token exchange (AGENT_AUTH.md §3.3 / B.4).
//!
//! TDD — tests written before implementation. Covers:
//! - B.4: Full token-exchange happy path (valid subject + actor tokens)
//! - B.4: Scope intersection enforcement
//! - B.4: Lifetime ≤ subject token remaining lifetime
//! - B.4: Delegation depth enforcement (agent max_delegation_depth)
//! - B.5: Actor token JTI replay prevention
//! - B.7: Scope-only-narrows property (child scope ⊆ parent scope)
//! - MCP scope validator unit tests (§2.6)

mod common;

use hearth::core::{AgentId, RealmId, UserId};
use hearth::identity::{
    mcp::{intersect_scopes, intersect_three, is_mcp_scope, validate_mcp_scope_string},
    tokens::{decode_claims_unverified, ActClaim},
    AgentOwner, CreateAgentRequest, CreateRealmRequest, CreateUserRequest, IdentityEngine,
    IdentityError, Rfc8693Request,
};

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn make_realm(identity: &dyn IdentityEngine) -> RealmId {
    identity
        .create_realm(&CreateRealmRequest {
            name: format!("te-test-{}", uuid::Uuid::new_v4()),
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
                email: format!("te-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "TE User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone()
}

fn make_agent(
    identity: &dyn IdentityEngine,
    realm_id: &RealmId,
    owner_id: &UserId,
    max_depth: u8,
) -> AgentId {
    identity
        .create_agent(
            realm_id,
            &CreateAgentRequest {
                display_name: format!("TE agent {}", uuid::Uuid::new_v4()),
                description: None,
                owner: AgentOwner::User(owner_id.clone()),
                capabilities: vec![],
                max_delegation_depth: max_depth,
            },
            None,
        )
        .expect("create agent")
        .id()
        .clone()
}

/// Build a minimal JWT with a known payload and a fake signature.
///
/// Only valid for use with `decode_claims_unverified` paths — not for
/// production use. The signature segment is a placeholder and will not
/// pass cryptographic verification.
fn build_mock_jwt(sub: &str, aud: &str, scope: &str, exp: i64, iat: i64) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT","kid":"test"}"#);
    let payload_json = serde_json::json!({
        "sub": sub,
        "iss": "hearth",
        "aud": aud,
        "exp": exp,
        "iat": iat,
        "sid": "sid-test",
        "tid": "00000000-0000-0000-0000-000000000000",
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
///
/// `scope` is included as the `scope` claim when provided. RFC 8693 §4.4 enforcement
/// requires actors to carry a scope claim — the token exchange engine uses it as the ceiling.
fn build_actor_jwt(sub: &str, aud: &str, exp: i64, iat: i64, jti: &str, scope: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT","kid":"agent-key"}"#);
    let payload_json = serde_json::json!({
        "iss": sub,
        "sub": sub,
        "aud": aud,
        "exp": exp,
        "iat": iat,
        "jti": jti,
        "scope": scope,
    });
    let payload = URL_SAFE_NO_PAD.encode(payload_json.to_string());
    let sig = URL_SAFE_NO_PAD.encode("fakesig");
    format!("{header}.{payload}.{sig}")
}

// ──────────────────────────────────────────────────────────────────────────────
// § MCP Scope Validator (§2.6)
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn mcp_scope_valid_three_part() {
    validate_mcp_scope_string("mcp:tools:invoke").expect("mcp:tools:invoke is a valid scope");
    validate_mcp_scope_string("mcp:resources:read").expect("mcp:resources:read is valid");
    validate_mcp_scope_string("mcp:resources:write").expect("mcp:resources:write is valid");
    validate_mcp_scope_string("mcp:prompts:read").expect("mcp:prompts:read is valid");
    validate_mcp_scope_string("custom:ns:action").expect("custom:ns:action is valid");
}

#[test]
fn mcp_scope_rejects_two_parts() {
    let msg = validate_mcp_scope_string("mcp:tools")
        .expect_err("two-part scope mcp:tools should be rejected");
    assert!(
        msg.contains("three components"),
        "error message should mention three-component requirement: {msg}"
    );
}

#[test]
fn mcp_scope_rejects_empty_component() {
    for bad in [":tools:invoke", "mcp::invoke", "mcp:tools:"] {
        let msg = validate_mcp_scope_string(bad).expect_err(&format!(
            "scope with empty component '{bad}' should be rejected"
        ));
        assert!(
            msg.contains("empty"),
            "error for '{bad}' should mention empty component: {msg}"
        );
    }
}

#[test]
fn mcp_scope_rejects_invalid_chars() {
    let msg = validate_mcp_scope_string("mcp:tools:invoke me")
        .expect_err("scope with space should be rejected");
    assert!(
        msg.contains("invalid characters"),
        "error should mention invalid chars: {msg}"
    );
    let msg2 = validate_mcp_scope_string("mcp.tools.invoke")
        .expect_err("dot-separated scope should be rejected");
    assert!(
        msg2.contains("three components"),
        "error should mention three-component requirement: {msg2}"
    );
}

#[test]
fn is_mcp_scope_check() {
    assert!(
        is_mcp_scope("mcp:tools:invoke"),
        "mcp:tools:invoke starts with mcp:"
    );
    assert!(!is_mcp_scope("openid"), "openid is not an MCP scope");
}

// ──────────────────────────────────────────────────────────────────────────────
// § Scope Intersection
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn scope_intersection_basic() {
    let a = "openid profile mcp:tools:invoke";
    let b = "mcp:tools:invoke mcp:resources:read";
    assert_eq!(intersect_scopes(a, b), "mcp:tools:invoke");
}

#[test]
fn scope_intersection_empty_on_no_overlap() {
    assert!(intersect_scopes("openid", "mcp:tools:invoke").is_empty());
}

#[test]
fn three_way_intersection_narrows_to_requested() {
    // subject has broad scopes, actor has broad scopes, requested is narrow
    let result = intersect_three(
        "mcp:tools:invoke mcp:resources:read openid",
        "mcp:tools:invoke mcp:resources:read",
        Some("mcp:tools:invoke"),
    );
    assert_eq!(result, "mcp:tools:invoke");
}

#[test]
fn three_way_intersection_empty_when_no_overlap() {
    // subject has no MCP scopes → intersection is empty regardless of actor
    let result = intersect_three(
        "openid profile",
        "mcp:tools:invoke",
        Some("mcp:tools:invoke"),
    );
    assert!(result.is_empty(), "expected empty scope intersection");
}

// ──────────────────────────────────────────────────────────────────────────────
// § Act Chain Depth
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn act_claim_depth_counts_chain() {
    let depth_1 = ActClaim {
        sub: "agent:A".to_string(),
        act: None,
    };
    assert_eq!(depth_1.depth(), 1);

    let depth_2 = ActClaim {
        sub: "agent:B".to_string(),
        act: Some(Box::new(ActClaim {
            sub: "agent:A".to_string(),
            act: None,
        })),
    };
    assert_eq!(depth_2.depth(), 2);

    let depth_3 = ActClaim {
        sub: "agent:C".to_string(),
        act: Some(Box::new(ActClaim {
            sub: "agent:B".to_string(),
            act: Some(Box::new(ActClaim {
                sub: "agent:A".to_string(),
                act: None,
            })),
        })),
    };
    assert_eq!(depth_3.depth(), 3);
}

// ──────────────────────────────────────────────────────────────────────────────
// § RFC 8693 Token Exchange — Integration tests
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn token_exchange_requires_access_token_type() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());

    let subject_token = build_mock_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "mcp:tools:invoke",
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test setup failed")
            .as_secs() as i64)
            + 900,
        0,
    );

    let request = Rfc8693Request {
        client_id,
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(), // wrong type
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        scope: None,
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    let err = identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect_err("expected error");
    assert!(
        matches!(
            err,
            IdentityError::TokenExchangeRejected {
                oauth_error: "invalid_request",
                ..
            }
        ),
        "expected invalid_request for wrong subject_token_type, got: {err}"
    );
}

#[tokio::test]
async fn token_exchange_rejects_expired_subject_token() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());

    // Token expired 60 seconds ago
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test setup failed")
        .as_secs() as i64;
    let subject_token = build_mock_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "mcp:tools:invoke",
        now - 60,
        0,
    );

    let request = Rfc8693Request {
        client_id,
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        scope: None,
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    let err = identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect_err("expected error");
    assert!(
        matches!(err, IdentityError::TokenExpired),
        "expected TokenExpired, got: {err}"
    );
}

#[tokio::test]
async fn token_exchange_empty_scope_intersection_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test setup failed")
        .as_secs() as i64;

    // subject has only "openid", but we request "mcp:tools:invoke"
    let subject_token = build_mock_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "openid",
        now + 900,
        now,
    );

    let request = Rfc8693Request {
        client_id,
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        scope: Some("mcp:tools:invoke".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    let err = identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect_err("expected error");
    assert!(
        matches!(err, IdentityError::EmptyScopeIntersection),
        "expected EmptyScopeIntersection, got: {err}"
    );
}

#[tokio::test]
async fn token_exchange_produces_act_claim() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let owner_id = make_user(identity, &realm_id);
    let agent_id = make_agent(identity, &realm_id, &owner_id, 3);
    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test setup failed")
        .as_secs() as i64;

    let subject_token = build_mock_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "mcp:tools:invoke mcp:resources:read",
        now + 900,
        now,
    );

    let actor_jti = uuid::Uuid::new_v4().to_string();
    let actor_sub = format!("agt_{}", agent_id.as_uuid());
    let actor_token = build_actor_jwt(
        &actor_sub,
        "hearth",
        now + 60,
        now,
        &actor_jti,
        "mcp:tools:invoke mcp:resources:read",
    );

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

    let response = identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect("exchange should succeed");

    assert_eq!(
        response.issued_token_type,
        "urn:ietf:params:oauth:token-type:access_token"
    );
    assert_eq!(response.scope, "mcp:tools:invoke");
    assert!(response.expires_in > 0 && response.expires_in <= 900);

    // Verify the issued token has an act claim
    let claims = decode_claims_unverified(&response.access_token).expect("decode token");
    let act = claims.act.expect("expected act claim in issued token");
    assert_eq!(act.sub, actor_sub, "act.sub should be the agent");
    assert!(act.act.is_none(), "single-hop: no nested act");
}

#[tokio::test]
async fn token_exchange_actor_jti_replay_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let owner_id = make_user(identity, &realm_id);
    let agent_id = make_agent(identity, &realm_id, &owner_id, 3);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test setup failed")
        .as_secs() as i64;

    let actor_jti = uuid::Uuid::new_v4().to_string();
    let actor_sub = format!("agt_{}", agent_id.as_uuid());

    let make_request = |subject_token: String| Rfc8693Request {
        client_id: hearth::core::ClientId::new(uuid::Uuid::new_v4()),
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: Some(build_actor_jwt(
            &actor_sub,
            "hearth",
            now + 60,
            now,
            &actor_jti,
            "mcp:tools:invoke",
        )),
        actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
        requested_token_type: None,
        scope: Some("mcp:tools:invoke".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    let subject_token_1 = build_mock_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "mcp:tools:invoke",
        now + 900,
        now,
    );
    let subject_token_2 = build_mock_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "mcp:tools:invoke",
        now + 900,
        now,
    );

    // First exchange should succeed.
    identity
        .rfc8693_token_exchange(&realm_id, &make_request(subject_token_1))
        .expect("first exchange should succeed");

    // Second exchange with same actor jti should be rejected.
    let err = identity
        .rfc8693_token_exchange(&realm_id, &make_request(subject_token_2))
        .expect_err("replay should be rejected");

    assert!(
        matches!(err, IdentityError::ActorTokenReplayed),
        "expected ActorTokenReplayed, got: {err}"
    );
}

#[tokio::test]
async fn token_exchange_delegation_depth_enforced() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let owner_id = make_user(identity, &realm_id);
    // Agent with max_delegation_depth = 1 — only one hop allowed.
    let agent_id = make_agent(identity, &realm_id, &owner_id, 1);
    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test setup failed")
        .as_secs() as i64;

    // Subject token already has an `act` chain of depth 1 — adding this
    // agent would make depth 2, exceeding max_delegation_depth = 1.
    let subject_with_existing_act = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let payload = serde_json::json!({
            "sub": user_id.as_uuid().to_string(),
            "iss": "hearth",
            "aud": "hearth",
            "exp": now + 900,
            "iat": now,
            "sid": "sid-test",
            "tid": "00000000-0000-0000-0000-000000000000",
            "token_type": "access",
            "jti": uuid::Uuid::new_v4().to_string(),
            "scope": "mcp:tools:invoke",
            "roles": [],
            "groups": [],
            "permissions": [],
            "required_actions": [],
            // Already delegated once
            "act": { "sub": "agt_some-other-agent" },
        });
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT","kid":"test"}"#);
        let p = URL_SAFE_NO_PAD.encode(payload.to_string());
        format!("{header}.{p}.fakesig")
    };

    let actor_sub = format!("agt_{}", agent_id.as_uuid());
    let request = Rfc8693Request {
        client_id,
        subject_token: subject_with_existing_act,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: Some(build_actor_jwt(
            &actor_sub,
            "hearth",
            now + 60,
            now,
            &uuid::Uuid::new_v4().to_string(),
            "mcp:tools:invoke",
        )),
        actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
        requested_token_type: None,
        scope: Some("mcp:tools:invoke".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    let err = identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect_err("depth exceeded should be rejected");

    assert!(
        matches!(err, IdentityError::DelegationDepthExceeded { max: 1, .. }),
        "expected DelegationDepthExceeded with max=1, got: {err}"
    );
}

#[tokio::test]
async fn token_exchange_lifetime_bounded_by_subject() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test setup failed")
        .as_secs() as i64;

    // Subject token expires in just 30 seconds — well below normal 15-minute TTL.
    let short_exp = now + 30;
    let subject_token = build_mock_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "mcp:tools:invoke",
        short_exp,
        now,
    );

    let request = Rfc8693Request {
        client_id,
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        scope: None,
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    let response = identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect("exchange should succeed");

    // The resulting token MUST NOT have a longer lifetime than the subject's remaining.
    assert!(
        response.expires_in <= 30,
        "issued token TTL {} should be ≤ 30s (subject remaining)",
        response.expires_in
    );
}

#[tokio::test]
async fn token_exchange_nested_act_chain_two_hops() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let owner_id = make_user(identity, &realm_id);
    // Agent with max_delegation_depth = 3 — allows multi-hop.
    let agent_b_id = make_agent(identity, &realm_id, &owner_id, 3);
    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test setup failed")
        .as_secs() as i64;

    // Subject token that was already delegated once (user → agent A).
    let subject_with_act_a = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let payload = serde_json::json!({
            "sub": user_id.as_uuid().to_string(),
            "iss": "hearth",
            "aud": "hearth",
            "exp": now + 900,
            "iat": now,
            "sid": "sid-test",
            "tid": "00000000-0000-0000-0000-000000000000",
            "token_type": "access",
            "jti": uuid::Uuid::new_v4().to_string(),
            "scope": "mcp:tools:invoke",
            "roles": [],
            "groups": [],
            "permissions": [],
            "required_actions": [],
            "act": { "sub": "agt_agent-a" },
        });
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT","kid":"test"}"#);
        let p = URL_SAFE_NO_PAD.encode(payload.to_string());
        format!("{header}.{p}.fakesig")
    };

    let actor_b_sub = format!("agt_{}", agent_b_id.as_uuid());
    let request = Rfc8693Request {
        client_id,
        subject_token: subject_with_act_a,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: Some(build_actor_jwt(
            &actor_b_sub,
            "hearth",
            now + 60,
            now,
            &uuid::Uuid::new_v4().to_string(),
            "mcp:tools:invoke",
        )),
        actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
        requested_token_type: None,
        scope: Some("mcp:tools:invoke".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    let response = identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect("two-hop exchange should succeed");

    let claims = decode_claims_unverified(&response.access_token).expect("decode");
    let act = claims.act.expect("act claim present");

    // Outer act is agent B
    assert_eq!(act.sub, actor_b_sub);
    // Inner act is agent A (preserved from subject)
    let inner = act.act.expect("inner act present for 2-hop chain");
    assert_eq!(inner.sub, "agt_agent-a");
}

// ──────────────────────────────────────────────────────────────────────────────
// § B.7 Property: scope only narrows (child scope ⊆ parent scope)
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn property_scope_only_narrows() {
    // For any subject scope S and requested scope R,
    // effective = intersect(S, R) must be a subset of S.
    let test_cases = [
        ("mcp:tools:invoke mcp:resources:read", "mcp:tools:invoke"),
        ("mcp:tools:invoke", "mcp:tools:invoke mcp:resources:read"),
        ("openid profile email mcp:tools:invoke", "mcp:tools:invoke"),
        ("mcp:tools:invoke", "openid"), // disjoint → empty
    ];
    for (subject, requested) in &test_cases {
        let effective = intersect_scopes(subject, requested);
        let subject_set: std::collections::HashSet<&str> = subject.split_whitespace().collect();
        let effective_set: std::collections::HashSet<&str> = effective.split_whitespace().collect();
        // effective must be a subset of subject
        for s in &effective_set {
            assert!(
                subject_set.contains(s),
                "scope '{s}' in effective but not in subject '{subject}'"
            );
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// § RFC 8693 §4.4 Actor scope enforcement (HEA-1429)
// ──────────────────────────────────────────────────────────────────────────────

/// Actor with a narrow scope must not obtain broader scope from the subject.
///
/// Subject has `mcp:tools:invoke mcp:tools:list`; actor only holds `mcp:tools:list`.
/// The resulting token MUST contain only `mcp:tools:list`.
#[tokio::test]
async fn token_exchange_actor_scope_limits_result() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let owner_id = make_user(identity, &realm_id);
    let agent_id = make_agent(identity, &realm_id, &owner_id, 3);
    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test setup failed")
        .as_secs() as i64;

    // Subject holds two scopes; actor only holds the narrower one.
    let subject_token = build_mock_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "mcp:tools:invoke mcp:tools:list",
        now + 900,
        now,
    );

    let actor_sub = format!("agt_{}", agent_id.as_uuid());
    let actor_token = build_actor_jwt(
        &actor_sub,
        "hearth",
        now + 60,
        now,
        &uuid::Uuid::new_v4().to_string(),
        "mcp:tools:list", // actor only has list, not invoke
    );

    let request = Rfc8693Request {
        client_id,
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: Some(actor_token),
        actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
        requested_token_type: None,
        scope: None, // no narrowing requested — actor scope is the only constraint
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    let response = identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect("exchange should succeed — actor and subject share mcp:tools:list");

    assert_eq!(
        response.scope, "mcp:tools:list",
        "result scope must be limited to actor's scope (mcp:tools:list), not subject's full scope"
    );

    let claims = decode_claims_unverified(&response.access_token).expect("decode token");
    let scope_claim = claims.scope.expect("issued token must carry scope claim");
    assert!(
        !scope_claim.contains("mcp:tools:invoke"),
        "issued token must NOT contain mcp:tools:invoke — actor never held that scope"
    );
}

/// Zero-scope actor cannot escalate to subject's high-privilege scopes.
///
/// An actor presenting a token with an empty scope must be rejected with
/// `EmptyScopeIntersection` even if the subject holds highly privileged scopes.
#[tokio::test]
async fn token_exchange_zero_scope_actor_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let owner_id = make_user(identity, &realm_id);
    let agent_id = make_agent(identity, &realm_id, &owner_id, 3);
    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test setup failed")
        .as_secs() as i64;

    // Subject holds a highly privileged scope.
    let subject_token = build_mock_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "tool:delete-db:invoke",
        now + 900,
        now,
    );

    // Actor presents itself with an empty scope — zero permissions.
    let actor_sub = format!("agt_{}", agent_id.as_uuid());
    let actor_token = build_actor_jwt(
        &actor_sub,
        "hearth",
        now + 60,
        now,
        &uuid::Uuid::new_v4().to_string(),
        "", // zero scope
    );

    let request = Rfc8693Request {
        client_id,
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: Some(actor_token),
        actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
        requested_token_type: None,
        scope: Some("tool:delete-db:invoke".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    let err = identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect_err("zero-scope actor must be rejected");

    assert!(
        matches!(err, IdentityError::EmptyScopeIntersection),
        "expected EmptyScopeIntersection for zero-scope actor, got: {err}"
    );
}
