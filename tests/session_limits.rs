//! Integration tests for per-realm concurrent session limits.
//!
//! Tests the `max_concurrent_sessions` + `session_over_limit_policy` controls
//! added to `RealmConfig`. These are black box tests via the embedded engine.

mod common;

use hearth::audit::{AuditAction, AuditQuery};
use hearth::core::RealmId;
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, IdentityError, RealmConfig, SessionContext,
    SessionLimitPolicy,
};

// ===== SEC-2: Default policy is RejectNew =====

/// Verify the in-memory default; operators must explicitly opt in to eviction.
#[test]
fn default_policy_is_reject_new() {
    assert_eq!(
        SessionLimitPolicy::default(),
        SessionLimitPolicy::RejectNew,
        "default must be RejectNew so an attacker cannot silently evict victim sessions"
    );
}

// ===== SEC-3: Unrecognized policy string is a hard error =====

#[test]
fn unrecognized_policy_string_returns_error() {
    use hearth::config::{AuthConfig, RealmYamlConfig};
    use hearth::rbac::registry::RegistryError;

    let yaml_config = RealmYamlConfig {
        session_over_limit_policy: Some("banish_oldest".to_string()),
        ..Default::default()
    };
    let result = yaml_config.to_realm_config(&AuthConfig::default(), None);
    assert!(
        result.is_err(),
        "unrecognized session_over_limit_policy must be a hard error, not a silent fallback"
    );
    let errors = result.expect_err("expected config error");
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, RegistryError::InvalidRealmConfigField { .. })),
        "expected InvalidRealmConfigField error, got: {errors:?}"
    );
}

fn create_user_in(harness: &common::TestHarness, realm: &RealmId) -> hearth::identity::User {
    harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
}

fn create_realm_with_limit(
    harness: &common::TestHarness,
    limit: u32,
    policy: SessionLimitPolicy,
) -> RealmId {
    let config = RealmConfig {
        max_concurrent_sessions: Some(limit),
        session_over_limit_policy: policy,
        ..RealmConfig::default()
    };

    harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("session-limit-realm-{}", uuid::Uuid::new_v4()),
            config: Some(config),
        })
        .expect("create realm")
        .id()
        .clone()
}

// ===== RejectNew policy =====

#[tokio::test]
async fn reject_new_policy_blocks_4th_session() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_limit(&harness, 3, SessionLimitPolicy::RejectNew);
    let user = create_user_in(&harness, &realm);

    for i in 1..=3 {
        harness
            .identity()
            .create_session(&realm, user.id(), &SessionContext::default())
            .unwrap_or_else(|e| panic!("session {i} should succeed: {e}"));
    }

    let err = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect_err("4th session must be rejected");

    assert!(
        matches!(
            err,
            IdentityError::SessionLimitExceeded {
                limit: 3,
                active: 3
            }
        ),
        "expected SessionLimitExceeded(limit=3, active=3), got: {err:?}"
    );
}

#[tokio::test]
async fn reject_new_policy_audit_event_written() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_limit(&harness, 1, SessionLimitPolicy::RejectNew);
    let user = create_user_in(&harness, &realm);

    harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("first session");

    let _ = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default());

    let mut q = AuditQuery::for_realm(realm.clone());
    q.action = Some(AuditAction::SessionLimitEnforced);
    q.limit = Some(10);
    let events = harness.audit().query(&q).expect("audit query");

    assert!(
        !events.is_empty(),
        "SessionLimitEnforced audit event should be written"
    );
}

// ===== EvictOldest policy =====

#[tokio::test]
async fn evict_oldest_policy_evicts_session_1() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_limit(&harness, 3, SessionLimitPolicy::EvictOldest);
    let user = create_user_in(&harness, &realm);

    let s1 = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session 1");
    for i in 2..=3 {
        harness
            .identity()
            .create_session(&realm, user.id(), &SessionContext::default())
            .unwrap_or_else(|e| panic!("session {i} should succeed: {e}"));
    }

    // 4th session — should succeed by evicting s1
    harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("4th session should succeed under EvictOldest");

    // s1 should now be revoked (get_session returns None for revoked sessions)
    let looked_up = harness
        .identity()
        .get_session(&realm, s1.id())
        .expect("get_session must not error");
    assert!(
        looked_up.is_none(),
        "session 1 should be revoked/expired after eviction"
    );
}

#[tokio::test]
async fn evict_oldest_audit_event_written() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_limit(&harness, 1, SessionLimitPolicy::EvictOldest);
    let user = create_user_in(&harness, &realm);

    harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("first session");

    // Second session should evict first
    harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("second session should succeed under EvictOldest");

    let mut q = AuditQuery::for_realm(realm.clone());
    q.action = Some(AuditAction::SessionLimitEnforced);
    q.limit = Some(10);
    let events = harness.audit().query(&q).expect("audit query");

    assert!(
        !events.is_empty(),
        "SessionLimitEnforced audit event should be written"
    );
}

// ===== None limit (default) =====

#[tokio::test]
async fn no_limit_allows_many_sessions() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness.create_realm(); // no limit
    let user = create_user_in(&harness, &realm);

    for i in 1..=100 {
        harness
            .identity()
            .create_session(&realm, user.id(), &SessionContext::default())
            .unwrap_or_else(|e| panic!("session {i} should succeed without limit: {e}"));
    }
}

// ===== Revoked sessions don't count =====

#[tokio::test]
async fn revoked_sessions_do_not_count_toward_limit() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_limit(&harness, 2, SessionLimitPolicy::RejectNew);
    let user = create_user_in(&harness, &realm);

    let s1 = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session 1");
    harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session 2");

    // Revoke session 1 — now only 1 active
    harness
        .identity()
        .revoke_session(&realm, s1.id())
        .expect("revoke");

    // Should be able to create one more (1 active < limit of 2)
    harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session 3 should succeed after revoking s1");
}
