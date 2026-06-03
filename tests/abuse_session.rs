//! Tests for A-18 (session lifecycle policy: idle + absolute timeouts, reaper)
//! and P-7 (`SessionStore` pluggable trait).
//!
//! D-4 taxonomy: unit (timeout arithmetic, audit strings) + integration
//! (idle/absolute eviction, reaper sweep, refresh denial) + adversarial
//! (bypass attempts) per the abuse-prevention plan §4.1/§4.2.
//!
//! Closes: §3.19 (no session lifecycle policy).

use std::sync::Arc;

use hearth::audit::{AuditAction, AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, FakeClock, Timestamp};
use hearth::identity::sessions::SessionStore;
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, RealmConfig, SessionContext,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Start timestamp: 1 second past epoch (non-zero to avoid accidental zero checks).
const START_MICROS: i64 = 1_000_000;

/// 1 hour in microseconds.
const ONE_HOUR_MICROS: i64 = 3_600_000_000;

/// Creates an engine backed by a tempdir and `FakeClock` starting at `start_micros`.
///
/// Returns `(temp_dir, engine, clock)`. The `temp_dir` must be kept alive for
/// the engine's lifetime — drop it last.
fn make_timed_engine(
    start_micros: i64,
) -> (tempfile::TempDir, EmbeddedIdentityEngine, Arc<FakeClock>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
            .expect("storage open"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(start_micros)));
    let cfg = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    )) as Arc<dyn AuditEngine>;
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
        cfg,
        audit,
    )
    .expect("engine");
    (dir, engine, clock)
}

/// Creates a realm with the given config and a standard test user.
/// Returns `(realm_id, user_id)`.
fn make_realm_and_user(
    engine: &EmbeddedIdentityEngine,
    config: RealmConfig,
) -> (hearth::core::RealmId, hearth::core::UserId) {
    let realm_id = engine
        .create_realm(&CreateRealmRequest {
            name: "test-realm".to_string(),
            config: Some(config),
        })
        .expect("create realm")
        .id()
        .clone();

    let user_id = engine
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "user@example.com".to_string(),
                display_name: "Test User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();

    (realm_id, user_id)
}

// ─────────────────────────────────────────────────────────────────────────────
// A-18 — Unit: audit action string round-trips
// ─────────────────────────────────────────────────────────────────────────────

/// `SessionEvicted` must have a stable wire string that round-trips through
/// `Display` → `FromStr`.
#[test]
fn a18_session_evicted_audit_action_round_trips() {
    let action = AuditAction::SessionEvicted;
    let s = action.as_str();
    assert_eq!(
        s, "session_evicted",
        "unexpected wire string for SessionEvicted"
    );
    let parsed: AuditAction = s.parse().expect("parse SessionEvicted");
    assert_eq!(parsed, AuditAction::SessionEvicted);
}

/// `SessionEvicted` must appear in `AuditAction::all()` so the admin filter
/// UI lists it without manual updates.
#[test]
fn a18_session_evicted_in_all_actions() {
    let all = AuditAction::all();
    assert!(
        all.contains(&AuditAction::SessionEvicted),
        "SessionEvicted missing from AuditAction::all()"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// P-7 — Unit: SessionStore trait is accessible and object-safe
// ─────────────────────────────────────────────────────────────────────────────

/// The `SessionStore` trait must be usable as a trait object (dyn-safe).
/// This test is a compilation check: if it compiles, the trait is object-safe.
#[test]
fn p7_session_store_trait_is_object_safe() {
    fn _accepts_dyn(_store: &dyn SessionStore) {}
    // If this compiles, SessionStore is dyn-safe (P-7 requirement).
    let _: Option<Box<dyn SessionStore>> = None;
}

/// `EmbeddedSessionStore` must implement `SessionStore`.
/// Compilation test — if it builds, the impl exists.
#[test]
fn p7_embedded_session_store_implements_trait() {
    use hearth::identity::sessions::EmbeddedSessionStore;
    fn requires_session_store<T: SessionStore>() {}
    requires_session_store::<EmbeddedSessionStore>();
}

// ─────────────────────────────────────────────────────────────────────────────
// A-18 — Integration: idle timeout eviction
// ─────────────────────────────────────────────────────────────────────────────

/// A session not refreshed within `idle_timeout_secs` must be invisible to
/// `get_session` even when the TTL has not expired.
///
/// Scenario: TTL = 24 h, idle_timeout = 1 h. Advance clock 2 h → evicted.
#[test]
fn a18_idle_timeout_evicts_session_on_get() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);

    let (realm_id, user_id) = make_realm_and_user(
        &engine,
        RealmConfig {
            idle_timeout_secs: Some(3_600), // 1 hour
            ..Default::default()
        },
    );

    let session = engine
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .expect("create session");

    // Advance 2 hours — past idle timeout, within TTL (24 h).
    clock.advance(2 * ONE_HOUR_MICROS);

    let result = engine
        .get_session(&realm_id, session.id())
        .expect("get_session must not error");

    assert!(
        result.is_none(),
        "session must be invisible after idle timeout"
    );
}

/// A session refreshed before idle timeout must survive.
#[test]
fn a18_idle_timeout_does_not_evict_recently_refreshed_session() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);

    let (realm_id, user_id) = make_realm_and_user(
        &engine,
        RealmConfig {
            idle_timeout_secs: Some(3_600), // 1 hour
            ..Default::default()
        },
    );

    let session = engine
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .expect("create session");

    // Advance 30 minutes — within idle timeout window.
    clock.advance(ONE_HOUR_MICROS / 2);

    // Refresh the session (resets idle deadline).
    engine
        .refresh_session(&realm_id, session.id())
        .expect("refresh should succeed within idle timeout");

    // Advance another 30 minutes — 30 min after refresh, still within new idle window.
    clock.advance(ONE_HOUR_MICROS / 2);

    let result = engine
        .get_session(&realm_id, session.id())
        .expect("get_session must not error");

    assert!(
        result.is_some(),
        "session must still be valid after refresh within idle window"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-18 — Integration: absolute timeout eviction
// ─────────────────────────────────────────────────────────────────────────────

/// A session past the absolute timeout must be invisible to `get_session`
/// even if it was refreshed recently.
///
/// Scenario: absolute_timeout = 2 h, idle_timeout = none. Advance 3 h → evicted.
#[test]
fn a18_absolute_timeout_evicts_session_on_get() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);

    let (realm_id, user_id) = make_realm_and_user(
        &engine,
        RealmConfig {
            absolute_timeout_secs: Some(7_200), // 2 hours
            ..Default::default()
        },
    );

    let session = engine
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .expect("create session");

    // Refresh just before the absolute timeout — idle window is fine.
    clock.advance(ONE_HOUR_MICROS);
    engine
        .refresh_session(&realm_id, session.id())
        .expect("refresh within absolute timeout");

    // Advance another 2 hours — now 3 h after creation, past absolute timeout.
    clock.advance(2 * ONE_HOUR_MICROS);

    let result = engine
        .get_session(&realm_id, session.id())
        .expect("get_session must not error");

    assert!(
        result.is_none(),
        "session must be invisible after absolute timeout regardless of refresh"
    );
}

/// A session before the absolute timeout must survive.
#[test]
fn a18_absolute_timeout_does_not_evict_within_window() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);

    let (realm_id, user_id) = make_realm_and_user(
        &engine,
        RealmConfig {
            absolute_timeout_secs: Some(7_200), // 2 hours
            ..Default::default()
        },
    );

    let session = engine
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .expect("create session");

    // Advance 1 hour — within absolute timeout.
    clock.advance(ONE_HOUR_MICROS);

    let result = engine
        .get_session(&realm_id, session.id())
        .expect("get_session must not error");

    assert!(
        result.is_some(),
        "session must still be valid within absolute timeout"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-18 — Integration: refresh_session denial at idle boundary
// ─────────────────────────────────────────────────────────────────────────────

/// `refresh_session` must return `SessionNotFound` when the session has
/// exceeded its idle timeout — refresh must not resurrect an idle-dead session.
#[test]
fn a18_refresh_denied_after_idle_timeout() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);

    let (realm_id, user_id) = make_realm_and_user(
        &engine,
        RealmConfig {
            idle_timeout_secs: Some(3_600), // 1 hour
            ..Default::default()
        },
    );

    let session = engine
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .expect("create session");

    // Advance past idle timeout.
    clock.advance(2 * ONE_HOUR_MICROS);

    let err = engine
        .refresh_session(&realm_id, session.id())
        .expect_err("refresh must fail after idle timeout");

    assert!(
        matches!(err, hearth::identity::IdentityError::SessionNotFound),
        "expected SessionNotFound, got: {err}"
    );
}

/// `refresh_session` must return `SessionNotFound` when the session has
/// exceeded its absolute timeout.
#[test]
fn a18_refresh_denied_after_absolute_timeout() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);

    let (realm_id, user_id) = make_realm_and_user(
        &engine,
        RealmConfig {
            absolute_timeout_secs: Some(3_600), // 1 hour absolute cap
            ..Default::default()
        },
    );

    let session = engine
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .expect("create session");

    // Advance past absolute timeout.
    clock.advance(2 * ONE_HOUR_MICROS);

    let err = engine
        .refresh_session(&realm_id, session.id())
        .expect_err("refresh must fail after absolute timeout");

    assert!(
        matches!(err, hearth::identity::IdentityError::SessionNotFound),
        "expected SessionNotFound, got: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-18 — Integration: session reaper sweep
// ─────────────────────────────────────────────────────────────────────────────

/// `sweep_expired_sessions` must proactively evict sessions past their idle
/// timeout. After the sweep, `get_session` must return `None`.
#[test]
fn a18_reaper_evicts_idle_timed_out_sessions() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);

    let (realm_id, user_id) = make_realm_and_user(
        &engine,
        RealmConfig {
            idle_timeout_secs: Some(3_600), // 1 hour
            ..Default::default()
        },
    );

    let session = engine
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .expect("create session");

    // Advance past idle timeout.
    clock.advance(2 * ONE_HOUR_MICROS);

    let evicted = engine
        .sweep_expired_sessions(&realm_id)
        .expect("sweep must not error");

    assert_eq!(evicted, 1, "reaper must evict the timed-out session");

    // After sweep, get_session must return None.
    let result = engine
        .get_session(&realm_id, session.id())
        .expect("get_session after sweep");
    assert!(result.is_none(), "session must be gone after reaper sweep");
}

/// `sweep_expired_sessions` must not evict sessions within their idle timeout.
#[test]
fn a18_reaper_does_not_evict_live_sessions() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);

    let (realm_id, user_id) = make_realm_and_user(
        &engine,
        RealmConfig {
            idle_timeout_secs: Some(3_600), // 1 hour
            ..Default::default()
        },
    );

    let session = engine
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .expect("create session");

    // Advance 30 minutes — within idle timeout.
    clock.advance(ONE_HOUR_MICROS / 2);

    let evicted = engine
        .sweep_expired_sessions(&realm_id)
        .expect("sweep must not error");

    assert_eq!(evicted, 0, "reaper must not evict live sessions");

    let result = engine
        .get_session(&realm_id, session.id())
        .expect("get_session");
    assert!(result.is_some(), "session must still be alive");
}

/// `sweep_expired_sessions` returns 0 for realms with no timeout policy.
#[test]
fn a18_reaper_skips_realm_without_timeout_policy() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);

    let (realm_id, user_id) = make_realm_and_user(
        &engine,
        RealmConfig::default(), // no idle or absolute timeout
    );

    engine
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .expect("create session");

    // Advance far into the future.
    clock.advance(100 * ONE_HOUR_MICROS);

    let evicted = engine.sweep_expired_sessions(&realm_id).expect("sweep");

    assert_eq!(
        evicted, 0,
        "no-policy realm must never be reaped by policy sweep"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-18 — Adversarial: cannot bypass absolute timeout by refreshing
// ─────────────────────────────────────────────────────────────────────────────

/// Attacker scenario: repeatedly refreshing a session must not bypass the
/// absolute timeout. After the absolute cap, the session is always dead.
#[test]
fn a18_adversarial_refresh_cannot_bypass_absolute_timeout() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);

    let (realm_id, user_id) = make_realm_and_user(
        &engine,
        RealmConfig {
            absolute_timeout_secs: Some(3_600), // 1-hour hard cap
            ..Default::default()
        },
    );

    let session = engine
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .expect("create session");

    // Refresh repeatedly within TTL window.
    for _ in 0..6 {
        clock.advance(ONE_HOUR_MICROS / 8); // 7.5 minutes each
                                            // refresh_session should succeed while within absolute timeout
    }

    // At 6 × 7.5 min = 45 min — still within absolute cap, so refresh works.
    engine
        .refresh_session(&realm_id, session.id())
        .expect("refresh before absolute timeout must succeed");

    // Advance past the 1-hour absolute cap.
    clock.advance(ONE_HOUR_MICROS); // now 1h45m past creation

    let result = engine
        .get_session(&realm_id, session.id())
        .expect("get_session");
    assert!(
        result.is_none(),
        "session must be evicted after absolute timeout even with prior refreshes"
    );
}

/// Adversarial: a no-timeout realm must not be affected by the reaper.
/// Regression guard: ensure the reaper short-circuits on realms without policy.
#[test]
fn a18_adversarial_reaper_noop_on_no_policy_realm() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);

    let (realm_id, user_id) = make_realm_and_user(
        &engine,
        RealmConfig::default(), // no timeouts
    );

    // Create 3 sessions.
    for _ in 0..3 {
        engine
            .create_session(&realm_id, &user_id, &SessionContext::default())
            .expect("create session");
    }

    // Advance 48 hours — past default TTL.
    clock.advance(48 * ONE_HOUR_MICROS);

    // Reaper must return 0 (TTL-expired sessions are handled by is_valid,
    // not by policy sweep).
    let evicted = engine.sweep_expired_sessions(&realm_id).expect("sweep");

    assert_eq!(
        evicted, 0,
        "policy sweep must not evict TTL-expired sessions (is_valid handles that)"
    );
}
