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

use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::{
    mcp::{intersect_scopes, intersect_three, is_mcp_scope, validate_mcp_scope_string},
    tokens::{decode_claims_unverified, ActClaim},
    AccessTokenAuthorization, ClientCredentialsRequest, ClientTrustLevel, CreateRealmRequest,
    CreateUserRequest, IdentityEngine, IdentityError, RegisterClientRequest, Rfc8693Request,
    SessionContext, TokenIssuanceContext,
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

/// Register a confidential OAuth client and issue a real `client_credentials` access token.
///
/// Returns `(client_id, access_token)`. The `client_id` MUST be used as `Rfc8693Request.client_id`
/// so that the `actor_token.sub == client_id` assertion passes (F3 / HEA-1466).
///
/// `scope` is the space-delimited scope to declare and request.  Pass `Some("")` to issue a
/// token with an explicitly-empty scope, which causes `EmptyScopeIntersection` in the exchange.
fn make_actor_token(
    identity: &dyn IdentityEngine,
    realm_id: &RealmId,
    scope: Option<&str>,
) -> (ClientId, String) {
    const SECRET: &str = "actor-test-secret!";
    let declared: Vec<String> = scope
        .unwrap_or("")
        .split_whitespace()
        .map(String::from)
        .collect();
    let client = identity
        .register_client(
            realm_id,
            &RegisterClientRequest {
                client_name: format!("actor-client-{}", uuid::Uuid::new_v4()),
                client_secret: Some(SECRET.to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                declared_scopes: declared,
                access_token_authorization: AccessTokenAuthorization::Embedded,
                ..Default::default()
            },
        )
        .expect("register actor OAuth client");
    let client_id = client.client_id().clone();
    let resp = identity
        .client_credentials_token(
            realm_id,
            &ClientCredentialsRequest {
                client_id: client_id.clone(),
                client_secret: Some(SECRET.to_string()),
                scope: scope.map(str::to_string),
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
/// After HEA-1470, `rfc8693_token_exchange` calls `validate_token` (signature
/// verification), so subject tokens must be cryptographically valid. Use this
/// helper instead of `build_mock_jwt` wherever the exchange is expected to
/// succeed or fail for a reason other than signature invalidity.
fn make_subject_token(
    identity: &dyn IdentityEngine,
    realm_id: &RealmId,
    user_id: &UserId,
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

/// Build a minimal JWT with a known payload and a **bogus** signature.
///
/// Use only for tests that specifically verify signature-rejection behaviour
/// (HEA-1470 regression). For exchange tests that should succeed or fail for
/// any other reason, use `make_subject_token` instead.
fn build_mock_jwt(sub: &str, aud: &str, scope: &str, exp: i64, iat: i64, tid: &str) -> String {
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
        "tid": tid,
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
        &realm_id.to_string(),
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
        &realm_id.to_string(),
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
    // After HEA-1470: validate_token checks signature first, so an expired
    // subject_token (with invalid signature) maps to invalid_grant, not TokenExpired.
    assert!(
        matches!(
            err,
            IdentityError::TokenExchangeRejected {
                oauth_error: "invalid_grant",
                ..
            }
        ),
        "expected invalid_grant for expired/invalid subject_token, got: {err}"
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

    // subject has only "openid", but we request "mcp:tools:invoke"
    let subject_token = make_subject_token(identity, &realm_id, &user_id, "openid");

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

    let subject_token = make_subject_token(
        identity,
        &realm_id,
        &user_id,
        "mcp:tools:invoke mcp:resources:read",
    );

    // F3 (HEA-1466): actor_token must be a Hearth-issued, realm-key-signed access token
    // whose sub matches the client_id in the exchange request.
    let (actor_client_id, actor_token) = make_actor_token(
        identity,
        &realm_id,
        Some("mcp:tools:invoke mcp:resources:read"),
    );

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

    let response = identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect("exchange should succeed");

    assert_eq!(
        response.issued_token_type,
        "urn:ietf:params:oauth:token-type:access_token"
    );
    assert_eq!(response.scope, "mcp:tools:invoke");
    assert!(response.expires_in > 0 && response.expires_in <= 900);

    // Verify the issued token has an act claim whose sub is the actor's client_id.
    let claims = decode_claims_unverified(&response.access_token).expect("decode token");
    let act = claims.act.expect("expected act claim in issued token");
    assert_eq!(
        act.sub,
        actor_client_id.to_string(),
        "act.sub must equal the actor's client_id"
    );
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

    // Issue a single real actor token — the same JWT (same JTI) will be used twice.
    let (actor_client_id, actor_token) =
        make_actor_token(identity, &realm_id, Some("mcp:tools:invoke"));

    let make_request = |subject_token: String| Rfc8693Request {
        client_id: actor_client_id.clone(),
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: Some(actor_token.clone()),
        actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
        requested_token_type: None,
        scope: Some("mcp:tools:invoke".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    // Two separate real subject tokens — both cryptographically valid.
    let subject_token_1 = make_subject_token(identity, &realm_id, &user_id, "mcp:tools:invoke");
    // set_password was called in subject_token_1; re-issue with same credentials by calling
    // make_subject_token again (sets a new password each time, independent of the first call).
    let user_id_2 = make_user(identity, &realm_id);
    let subject_token_2 = make_subject_token(identity, &realm_id, &user_id_2, "mcp:tools:invoke");

    // First exchange should succeed — JTI is recorded.
    identity
        .rfc8693_token_exchange(&realm_id, &make_request(subject_token_1))
        .expect("first exchange should succeed");

    // Second exchange with the identical actor_token (same JTI) must be rejected.
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

    let max_depth = hearth::abuse::MAX_ACT_CHAIN_DEPTH;

    // Build a real subject token at depth `max_depth` by running `max_depth` sequential
    // token exchanges. Each exchange appends one act-chain hop. Because each hop requires a
    // fresh actor token (JTI replay guard), we create a new actor per iteration.
    let mut current_subject = make_subject_token(identity, &realm_id, &user_id, "mcp:tools:invoke");

    for i in 0..max_depth {
        let (hop_actor_id, hop_actor_token) =
            make_actor_token(identity, &realm_id, Some("mcp:tools:invoke"));
        current_subject = identity
            .rfc8693_token_exchange(
                &realm_id,
                &Rfc8693Request {
                    client_id: hop_actor_id,
                    subject_token: current_subject,
                    subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
                    actor_token: Some(hop_actor_token),
                    actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
                    requested_token_type: None,
                    scope: Some("mcp:tools:invoke".to_string()),
                    resource: None,
                    audience: None,
                    dpop_jkt: None,
                },
            )
            .unwrap_or_else(|e| panic!("hop {i} of {max_depth} failed: {e}"))
            .access_token;
    }

    // One more hop must be rejected — subject is already at the global ceiling.
    let (final_actor_id, final_actor_token) =
        make_actor_token(identity, &realm_id, Some("mcp:tools:invoke"));

    let err = identity
        .rfc8693_token_exchange(
            &realm_id,
            &Rfc8693Request {
                client_id: final_actor_id,
                subject_token: current_subject,
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
                actor_token: Some(final_actor_token),
                actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
                requested_token_type: None,
                scope: Some("mcp:tools:invoke".to_string()),
                resource: None,
                audience: None,
                dpop_jkt: None,
            },
        )
        .expect_err("depth at global ceiling + 1 must be rejected");

    assert!(
        matches!(
            err,
            IdentityError::DelegationDepthExceeded {
                max: 10,
                attempted: 11
            }
        ),
        "expected DelegationDepthExceeded {{ max: 10, attempted: 11 }}, got: {err}"
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

    // Issue a real signed subject token, then immediately measure its remaining lifetime.
    let subject_token = make_subject_token(identity, &realm_id, &user_id, "mcp:tools:invoke");
    let subject_claims = decode_claims_unverified(&subject_token).expect("decode subject claims");
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test setup failed")
        .as_secs() as i64;
    let subject_remaining = subject_claims.exp - now_secs;

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
        response.expires_in > 0,
        "issued token must have a positive TTL"
    );
    assert!(
        response.expires_in <= subject_remaining,
        "issued token TTL {} must be ≤ subject remaining {} s",
        response.expires_in,
        subject_remaining
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

    // Build a real depth-1 subject (user → first_actor) via a first exchange.
    let user_token = make_subject_token(identity, &realm_id, &user_id, "mcp:tools:invoke");
    let (first_actor_id, first_actor_token) =
        make_actor_token(identity, &realm_id, Some("mcp:tools:invoke"));

    let subject_with_first_hop = identity
        .rfc8693_token_exchange(
            &realm_id,
            &Rfc8693Request {
                client_id: first_actor_id.clone(),
                subject_token: user_token,
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
                actor_token: Some(first_actor_token),
                actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
                requested_token_type: None,
                scope: Some("mcp:tools:invoke".to_string()),
                resource: None,
                audience: None,
                dpop_jkt: None,
            },
        )
        .expect("first hop should succeed")
        .access_token;

    // Second actor adds the second hop (F3).
    let (second_actor_id, second_actor_token) =
        make_actor_token(identity, &realm_id, Some("mcp:tools:invoke"));

    let response = identity
        .rfc8693_token_exchange(
            &realm_id,
            &Rfc8693Request {
                client_id: second_actor_id.clone(),
                subject_token: subject_with_first_hop,
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
                actor_token: Some(second_actor_token),
                actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
                requested_token_type: None,
                scope: Some("mcp:tools:invoke".to_string()),
                resource: None,
                audience: None,
                dpop_jkt: None,
            },
        )
        .expect("two-hop exchange should succeed");

    let claims = decode_claims_unverified(&response.access_token).expect("decode");
    let act = claims.act.expect("act claim present");

    // Outer act is second_actor — identified by its client_id string.
    assert_eq!(act.sub, second_actor_id.to_string());
    // Inner act is first_actor (preserved from the first exchange).
    let inner = act.act.expect("inner act present for 2-hop chain");
    assert_eq!(inner.sub, first_actor_id.to_string());
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

    // Subject holds two scopes; actor only holds the narrower one.
    let subject_token = make_subject_token(
        identity,
        &realm_id,
        &user_id,
        "mcp:tools:invoke mcp:tools:list",
    );

    // Actor registered and issued a token with only mcp:tools:list (F3).
    let (actor_client_id, actor_token) =
        make_actor_token(identity, &realm_id, Some("mcp:tools:list"));

    let request = Rfc8693Request {
        client_id: actor_client_id,
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

/// Actor with no scope overlap with the subject must be rejected with EmptyScopeIntersection.
///
/// An actor presenting a token with an empty scope string must be rejected even if the
/// subject holds highly privileged scopes.  The engine treats `scope = ""` as an explicit
/// zero-permission assertion — it does not fall back to the subject's scope.
#[tokio::test]
async fn token_exchange_zero_scope_actor_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    // Subject holds a highly privileged scope.
    let subject_token = make_subject_token(identity, &realm_id, &user_id, "tool:delete-db:invoke");

    // Actor token issued with an explicit empty scope string — zero permissions (F3).
    // make_actor_token with Some("") passes scope="" to client_credentials_token which
    // stores scope=Some("") in the issued JWT; the engine treats this as zero permissions.
    let (actor_client_id, actor_token) = make_actor_token(identity, &realm_id, Some(""));

    let request = Rfc8693Request {
        client_id: actor_client_id,
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

/// HEA-1467 / F4: subject token with a `tid` from a different realm must be rejected.
///
/// Token exchange in Realm B must not accept a subject token that was issued for Realm A.
/// Without this guard an attacker could present a Realm A token to Realm B's exchange
/// endpoint and launder the identity across trust boundaries.
#[tokio::test]
async fn token_exchange_rejects_cross_realm_subject_tid() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    // Two separate realms — the subject token belongs to realm_a but is presented to realm_b.
    let realm_a = make_realm(identity);
    let realm_b = make_realm(identity);
    let user_id = make_user(identity, &realm_a);
    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());

    // Subject token is a real realm_a-signed token — presented to realm_b's exchange.
    // validate_token(realm_b, token) fails because the token was signed by realm_a's key.
    let subject_token = make_subject_token(identity, &realm_a, &user_id, "mcp:tools:invoke");

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

    // Exchange is performed against realm_b — must be rejected.
    let err = identity
        .rfc8693_token_exchange(&realm_b, &request)
        .expect_err("cross-realm subject token must be rejected");

    assert!(
        matches!(
            err,
            IdentityError::TokenExchangeRejected {
                oauth_error: "invalid_grant",
                ..
            }
        ),
        "expected invalid_grant for cross-realm subject tid, got: {err}"
    );
}

/// HEA-1466 / F3 regression: forged actor_token with valid JTI but mismatched sub must be rejected.
///
/// An attacker holds a valid Hearth token for client A.  They present it as `actor_token` in an
/// exchange request that claims `client_id` = client B.  The `actor_token.sub` check must catch
/// this confused-deputy attempt before the JTI replay guard would even fire.
#[tokio::test]
async fn token_exchange_actor_sub_mismatch_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    let subject_token = make_subject_token(identity, &realm_id, &user_id, "mcp:tools:invoke");

    // Issue a real actor token for client A.
    let (client_a, actor_token_a) = make_actor_token(identity, &realm_id, Some("mcp:tools:invoke"));
    // Register a completely separate client B.
    let (client_b, _) = make_actor_token(identity, &realm_id, Some("mcp:tools:invoke"));
    // Sanity-check that A and B really are different clients.
    assert_ne!(client_a, client_b);

    // Forge: present client A's token but claim to be client B in the exchange request.
    let request = Rfc8693Request {
        client_id: client_b, // claims to be B
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: Some(actor_token_a), // token belongs to A (sub = "client_<A_UUID>")
        actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
        requested_token_type: None,
        scope: Some("mcp:tools:invoke".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    let err = identity
        .rfc8693_token_exchange(&realm_id, &request)
        .expect_err("sub mismatch must be rejected");

    assert!(
        matches!(
            err,
            IdentityError::TokenExchangeRejected {
                oauth_error: "invalid_grant",
                ..
            }
        ),
        "expected TokenExchangeRejected(invalid_grant) for mismatched sub, got: {err}"
    );
}

/// HEA-1467 / F4: the issued token's `iss` and `tid` must reflect the serving realm,
/// not the subject token's original claims.
#[tokio::test]
async fn token_exchange_overrides_iss_and_tid_to_serving_realm() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let client_id = hearth::core::ClientId::new(uuid::Uuid::new_v4());

    // Issue a real signed subject token — the exchange must override its iss/tid.
    let subject_token = make_subject_token(identity, &realm_id, &user_id, "mcp:tools:invoke");

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
        .expect("same-realm exchange should succeed");

    let claims = decode_claims_unverified(&response.access_token).expect("decode issued token");

    // tid MUST be overridden to the serving realm.
    assert_eq!(
        claims.tid,
        realm_id.to_string(),
        "issued token tid must equal the serving realm, not the subject's original tid"
    );

    // iss must never be empty (it is pinned to config.token.issuer).
    assert!(!claims.iss.is_empty(), "issued token iss must be non-empty");
}

// ──────────────────────────────────────────────────────────────────────────────
// § HEA-1470 regression: forged subject_token with bogus signature
// ──────────────────────────────────────────────────────────────────────────────

/// A JWT with correct tid/iss/exp claims but a forged signature must be rejected.
///
/// Before HEA-1470, `decode_claims_unverified` was used at step 2 of
/// `rfc8693_token_exchange`. An attacker could craft a JWT with:
///   - `tid` = serving realm UUID  (passes the old tid guard)
///   - `sub` = any victim user ID
///   - arbitrary `permissions`/`scope`
///   - signature = anything (was never verified)
/// and obtain a server-signed token with those claims.  This test pins the fix.
#[tokio::test]
async fn token_exchange_rejects_forged_subject_token_bogus_signature() {
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

    // Forged token: correct tid/iss/exp, valid-looking structure, but signature = "fakesig".
    let forged = build_mock_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "mcp:tools:invoke",
        now + 900,
        now,
        &realm_id.to_string(),
    );

    let err = identity
        .rfc8693_token_exchange(
            &realm_id,
            &Rfc8693Request {
                client_id,
                subject_token: forged,
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
                actor_token: None,
                actor_token_type: None,
                requested_token_type: None,
                scope: None,
                resource: None,
                audience: None,
                dpop_jkt: None,
            },
        )
        .expect_err("forged subject_token must be rejected");

    assert!(
        matches!(
            err,
            IdentityError::TokenExchangeRejected {
                oauth_error: "invalid_grant",
                ..
            }
        ),
        "expected invalid_grant for forged subject_token, got: {err}"
    );
}
