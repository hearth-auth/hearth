//! RFC 8693 OAuth 2.0 Token Exchange — conformance fixtures.
//!
//! Validates wire-format shapes from `tests/fixtures/rfc8693/conformance_vectors.json`.
//!
//! Coverage:
//! - ACT-01..03: `act` claim JSON round-trip at depth 1, 2, and 3 (RFC 8693 §4.1)
//! - Response required fields: `access_token`, `issued_token_type`, `token_type`
//! - `issued_token_type` is always `urn:ietf:params:oauth:token-type:access_token`
//! - ERR-01: wrong `subject_token_type` → `invalid_request` OAuth error code
//! - ERR-02: expired subject token → error
//! - ERR-03: requested scope wider than subject scope → `invalid_scope`
//!
//! Spec refs: RFC 8693, RFC 6749 §5.2
//! Test vectors: tests/fixtures/rfc8693/conformance_vectors.json

#![allow(clippy::unwrap_used)]

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    tokens::ActClaim, CreateRealmRequest, CreateUserRequest, IdentityEngine, IdentityError,
    Rfc8693Request,
};
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/rfc8693/conformance_vectors.json");

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64
}

fn make_realm(identity: &dyn IdentityEngine) -> RealmId {
    identity
        .create_realm(&CreateRealmRequest {
            name: format!("rfc8693-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

/// Build a minimal mock subject-token JWT for use with `decode_claims_unverified`.
fn mock_subject_jwt(sub: &str, aud: &str, scope: &str, exp: i64) -> String {
    use base64::Engine as _;
    let hdr = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(r#"{"alg":"EdDSA","typ":"JWT","kid":"test"}"#);
    let now = now_secs();
    let payload = serde_json::json!({
        "sub": sub, "iss": "hearth", "aud": aud,
        "exp": exp, "iat": now, "sid": "sid-test",
        "tid": "00000000-0000-0000-0000-000000000000",
        "token_type": "access",
        "jti": uuid::Uuid::new_v4().to_string(),
        "scope": scope, "roles": [], "groups": [],
        "permissions": [], "required_actions": [],
    });
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string());
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("fakesig");
    format!("{hdr}.{body}.{sig}")
}

// ── ACT chain round-trip ──────────────────────────────────────────────────────

/// ACT-01..03: parse each `act_chain_vectors` entry from the fixture JSON,
/// verify depth, and assert JSON round-trip fidelity.
#[test]
fn act_chain_round_trip_from_fixture() {
    let doc: Value = serde_json::from_str(VECTORS).expect("parse rfc8693 fixture JSON");
    let vectors = doc["act_chain_vectors"]
        .as_array()
        .expect("act_chain_vectors array");

    for v in vectors {
        let id = v["id"].as_str().unwrap_or("?");
        let json_val = &v["json"];
        let expected_depth = v["expected_depth"].as_u64().unwrap() as usize;

        let claim: ActClaim = serde_json::from_value(json_val.clone())
            .unwrap_or_else(|e| panic!("{id}: deserialization failed: {e}"));

        assert_eq!(
            claim.depth(),
            expected_depth,
            "{id}: expected act chain depth {expected_depth}, got {}",
            claim.depth()
        );

        // Round-trip: serialize then deserialize and compare.
        let serialized =
            serde_json::to_value(&claim).unwrap_or_else(|e| panic!("{id}: serialize failed: {e}"));
        let re_parsed: ActClaim = serde_json::from_value(serialized)
            .unwrap_or_else(|e| panic!("{id}: re-deserialize failed: {e}"));
        assert_eq!(re_parsed, claim, "{id}: round-trip mismatch");
    }
}

/// ACT-01: depth-1 `act` claim contains only `sub`, no nested `act` key.
#[test]
fn act_chain_depth1_no_inner_act() {
    let claim = ActClaim {
        sub: "agt_agent-a".to_string(),
        act: None,
    };
    let val = serde_json::to_value(&claim).expect("serialize");
    assert!(
        val.get("act").is_none(),
        "depth-1 claim must omit the 'act' key"
    );
    assert_eq!(claim.depth(), 1);
}

/// ACT-02: depth-2 `act` claim has exactly one level of nesting.
#[test]
fn act_chain_depth2_one_hop() {
    let claim = ActClaim {
        sub: "agt_agent-b".to_string(),
        act: Some(Box::new(ActClaim {
            sub: "agt_agent-a".to_string(),
            act: None,
        })),
    };
    let val = serde_json::to_value(&claim).expect("serialize");
    let inner = val["act"].as_object().expect("inner act object");
    assert_eq!(inner["sub"].as_str().unwrap(), "agt_agent-a");
    assert!(
        inner.get("act").is_none(),
        "inner should not have a nested act"
    );
    assert_eq!(claim.depth(), 2);
}

// ── Response required-field assertions ────────────────────────────────────────

/// Response always carries the required RFC 8693 §2.2.1 fields.
#[tokio::test]
async fn rfc8693_response_required_fields() {
    let doc: Value = serde_json::from_str(VECTORS).expect("parse fixture");
    let required: Vec<&str> = doc["response_required_fields"]
        .as_array()
        .expect("response_required_fields")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    let harness = common::TestHarness::embedded().await.expect("test setup");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    let user_id = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RFC8693 User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();

    let subject_token = mock_subject_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "mcp:tools:invoke",
        now_secs() + 900,
    );

    let response = identity
        .rfc8693_token_exchange(
            &realm_id,
            &Rfc8693Request {
                client_id: hearth::core::ClientId::new(uuid::Uuid::new_v4()),
                subject_token,
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
        .expect("rfc8693_token_exchange");

    // Validate each field listed in the fixture's required-fields list.
    let response_val = serde_json::json!({
        "access_token": response.access_token,
        "issued_token_type": response.issued_token_type,
        "token_type": response.token_type,
        "expires_in": response.expires_in,
        "scope": response.scope,
    });

    for field in &required {
        let val = response_val.get(field).unwrap_or(&Value::Null);
        assert!(
            !val.is_null() && val.as_str().map_or(true, |s| !s.is_empty()),
            "RFC 8693 required field '{field}' must be present and non-empty"
        );
    }

    // Validate the issued_token_type value is exactly what the spec demands.
    let expected_type = doc["issued_token_type_value"].as_str().unwrap();
    assert_eq!(
        response.issued_token_type, expected_type,
        "issued_token_type must be '{expected_type}'"
    );
}

// ── Error code vectors ────────────────────────────────────────────────────────

/// ERR-01: wrong `subject_token_type` → `invalid_request` (RFC 8693 §2.2.2).
#[tokio::test]
async fn rfc8693_err01_wrong_subject_token_type() {
    let harness = common::TestHarness::embedded().await.expect("test setup");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RFC8693 User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();

    let subject_token = mock_subject_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "mcp:tools:invoke",
        now_secs() + 900,
    );

    let err = identity
        .rfc8693_token_exchange(
            &realm_id,
            &Rfc8693Request {
                client_id: hearth::core::ClientId::new(uuid::Uuid::new_v4()),
                subject_token,
                // Wrong type — must be access_token, not jwt
                subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
                actor_token: None,
                actor_token_type: None,
                requested_token_type: None,
                scope: None,
                resource: None,
                audience: None,
                dpop_jkt: None,
            },
        )
        .expect_err("must reject wrong subject_token_type");

    assert!(
        matches!(
            err,
            IdentityError::TokenExchangeRejected {
                oauth_error: "invalid_request",
                ..
            }
        ),
        "ERR-01: expected invalid_request, got: {err}"
    );
}

/// ERR-02: expired subject token → token-expired error.
#[tokio::test]
async fn rfc8693_err02_expired_subject_token() {
    let harness = common::TestHarness::embedded().await.expect("test setup");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RFC8693 User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();

    // Token expired 60 seconds ago.
    let subject_token = mock_subject_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "mcp:tools:invoke",
        now_secs() - 60,
    );

    let err = identity
        .rfc8693_token_exchange(
            &realm_id,
            &Rfc8693Request {
                client_id: hearth::core::ClientId::new(uuid::Uuid::new_v4()),
                subject_token,
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
        .expect_err("must reject expired subject token");

    assert!(
        matches!(err, IdentityError::TokenExpired),
        "ERR-02: expected TokenExpired, got: {err}"
    );
}

/// ERR-03: requested scope wider than subject token scope → `EmptyScopeIntersection`
/// (maps to the RFC 8693 `invalid_scope` OAuth error code at the HTTP layer).
#[tokio::test]
async fn rfc8693_err03_scope_wider_than_subject() {
    let harness = common::TestHarness::embedded().await.expect("test setup");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RFC8693 User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();

    // Subject has only "openid"; we request "mcp:tools:invoke" which is wider.
    let subject_token = mock_subject_jwt(
        &user_id.as_uuid().to_string(),
        "hearth",
        "openid",
        now_secs() + 900,
    );

    let err = identity
        .rfc8693_token_exchange(
            &realm_id,
            &Rfc8693Request {
                client_id: hearth::core::ClientId::new(uuid::Uuid::new_v4()),
                subject_token,
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
                actor_token: None,
                actor_token_type: None,
                requested_token_type: None,
                scope: Some("mcp:tools:invoke".to_string()),
                resource: None,
                audience: None,
                dpop_jkt: None,
            },
        )
        .expect_err("must reject scope wider than subject");

    // EmptyScopeIntersection is the engine-layer variant for the RFC 8693
    // invalid_scope condition: the requested scope and subject scope have no
    // overlap, so no valid narrowed token can be issued.
    assert!(
        matches!(err, IdentityError::EmptyScopeIntersection),
        "ERR-03: expected EmptyScopeIntersection (maps to invalid_scope), got: {err}"
    );
}

/// Fixture JSON contains the three documented error codes, cross-checked against
/// the variants exercised above.
#[test]
fn error_vector_codes_are_documented_in_fixture() {
    let doc: Value = serde_json::from_str(VECTORS).expect("parse fixture");
    let errors: Vec<&str> = doc["error_vectors"]
        .as_array()
        .expect("error_vectors")
        .iter()
        .map(|v| v["error"].as_str().unwrap())
        .collect();

    for expected in &["invalid_request", "invalid_grant", "invalid_scope"] {
        assert!(
            errors.contains(expected),
            "fixture must document error code '{expected}'"
        );
    }
}
