//! RFC 7009 revocation must not persist the presented bearer token.
//!
//! Audit 2026-08-28 §4.16#9 (MEDIUM): `revoke_token` recorded the raw token
//! string as the audit event's `resource_id`. The audit log is durable, is
//! exported to CSV from the admin console, and is readable by every realm
//! admin — so a still-valid access token sat there as a replayable credential
//! at rest. The event must reference the token by a non-reversible
//! identifier instead (its `jti`, else a truncated SHA-256 digest).

mod common;

use common::TestHarness;
use hearth::audit::{AuditAction, AuditQuery};
use hearth::core::RealmId;
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, SessionContext, TokenRevocationRequest,
};

async fn create_test_realm(harness: &TestHarness) -> RealmId {
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("revoke-audit-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    realm.id().clone()
}

/// The `SessionRevoked` event written by `POST /revoke` must not contain the
/// token string anywhere in the persisted record.
#[tokio::test]
async fn revoke_audit_record_never_contains_the_raw_token() {
    let harness = TestHarness::embedded().await.expect("harness");
    let realm_id = create_test_realm(&harness).await;

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "revoke-audit@test.com".to_string(),
                display_name: "Revoke Audit".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let session = harness
        .identity()
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("create session");
    let tokens = harness
        .identity()
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens");
    let access_token = tokens.access_token().to_string();

    harness
        .identity()
        .revoke_token(
            &realm_id,
            &TokenRevocationRequest {
                token: access_token.clone(),
                token_type_hint: Some("access_token".to_string()),
            },
        )
        .expect("revoke");

    let events = harness
        .audit()
        .query(&AuditQuery::for_realm(realm_id.clone()))
        .expect("query audit");

    let revoked: Vec<_> = events
        .iter()
        .filter(|e| e.action == AuditAction::SessionRevoked && e.resource_type == "token")
        .collect();
    assert!(
        !revoked.is_empty(),
        "revocation must still write a SessionRevoked audit event for resource_type=token"
    );

    // The token has three dot-separated JWT segments; the signature segment
    // alone is enough to replay it, so assert on the whole string *and* on
    // the payload/signature segments individually.
    let segments: Vec<&str> = access_token.split('.').collect();
    assert_eq!(segments.len(), 3, "access token must be a compact JWT");

    for event in &revoked {
        let serialized = serde_json::to_string(event).expect("serialize audit event");
        assert!(
            !serialized.contains(&access_token),
            "audit event must not persist the raw token: {serialized}"
        );
        assert!(
            !serialized.contains(segments[1]),
            "audit event must not persist the token payload segment: {serialized}"
        );
        assert!(
            !serialized.contains(segments[2]),
            "audit event must not persist the token signature segment: {serialized}"
        );
        assert!(
            !event.resource_id.is_empty(),
            "the event must still reference the revoked token by an opaque id"
        );
    }
}

/// The replacement identifier must be *stable* — revoking the same token
/// twice references it the same way, so operators can still correlate.
#[tokio::test]
async fn revoke_audit_reference_is_stable_and_opaque() {
    let harness = TestHarness::embedded().await.expect("harness");
    let realm_id = create_test_realm(&harness).await;

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "revoke-audit-stable@test.com".to_string(),
                display_name: "Revoke Audit Stable".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let session = harness
        .identity()
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("create session");
    let tokens = harness
        .identity()
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens");
    let access_token = tokens.access_token().to_string();

    for _ in 0..2 {
        harness
            .identity()
            .revoke_token(
                &realm_id,
                &TokenRevocationRequest {
                    token: access_token.clone(),
                    token_type_hint: None,
                },
            )
            .expect("revoke");
    }

    let events = harness
        .audit()
        .query(&AuditQuery::for_realm(realm_id.clone()))
        .expect("query audit");
    let refs: Vec<&str> = events
        .iter()
        .filter(|e| e.action == AuditAction::SessionRevoked && e.resource_type == "token")
        .map(|e| e.resource_id.as_str())
        .collect();

    assert!(
        refs.len() >= 2,
        "expected two revocation events, got {refs:?}"
    );
    assert!(
        refs.windows(2).all(|w| w[0] == w[1]),
        "the opaque token reference must be stable across revocations: {refs:?}"
    );
    for r in &refs {
        assert!(
            !access_token.contains(r),
            "the reference must not be a substring of the token itself: {r}"
        );
    }
}
