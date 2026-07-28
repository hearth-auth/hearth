//! Tests for A-37 (`prompt=none` per-(realm, subject) probe limit).
//!
//! D-4 taxonomy:
//! - Unit: audit action round-trip, error display.
//! - Integration: probe counter increments, rate limit enforced after cap.
//! - Adversarial: limit resets after window expiry; different subjects
//!   have independent counters.
//!
//! Closes: §3.38 (`prompt=none` silent-auth probing).

use std::sync::Arc;

use hearth::audit::{AuditAction, AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, FakeClock, RealmId, Timestamp, UserId};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const START_MICROS: i64 = 1_000_000;
const ONE_HOUR_MICROS: i64 = 3_600_000_000_i64;

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

fn make_realm_and_user(engine: &EmbeddedIdentityEngine, email: &str) -> (RealmId, UserId) {
    let realm_id = engine
        .create_realm(&CreateRealmRequest {
            name: "test-realm".to_string(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    let user_id = engine
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: email.to_string(),
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
// Unit: audit action round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a37_oidc_silent_auth_probed_audit_round_trips() {
    let action = AuditAction::OidcSilentAuthProbed;
    assert_eq!(action.as_str(), "oidc_silent_auth_probed");
    let parsed: AuditAction = "oidc_silent_auth_probed"
        .parse()
        .expect("parse OidcSilentAuthProbed");
    assert_eq!(parsed, AuditAction::OidcSilentAuthProbed);
}

#[test]
fn a37_oidc_silent_auth_probed_in_all_actions() {
    let all = AuditAction::all();
    assert!(
        all.contains(&AuditAction::OidcSilentAuthProbed),
        "OidcSilentAuthProbed missing from AuditAction::all()"
    );
}

#[test]
fn a37_silent_auth_rate_limited_error_has_wire_code() {
    use hearth::identity::IdentityError;
    let code = IdentityError::SilentAuthRateLimited.wire_error_code();
    assert_eq!(code, Some("HEARTH_SILENT_AUTH_RATE_LIMITED"));
}

// ─────────────────────────────────────────────────────────────────────────────
// A-37 Integration: rate-limit enforcement
// ─────────────────────────────────────────────────────────────────────────────

/// First 50 probes must succeed; the 51st must be rate-limited.
#[test]
fn a37_probe_limit_enforced_at_cap() {
    let (_dir, engine, _clock) = make_timed_engine(START_MICROS);
    let (realm_id, user_id) = make_realm_and_user(&engine, "probe@example.com");

    // First 50 probes: all must succeed.
    for i in 0..50_u32 {
        engine
            .check_silent_auth_probe(&realm_id, &user_id, "client-123", "code_issued")
            .unwrap_or_else(|e| panic!("probe {i} should succeed, got {e}"));
    }

    // 51st probe must be rate-limited.
    let err = engine
        .check_silent_auth_probe(&realm_id, &user_id, "client-123", "code_issued")
        .expect_err("51st probe must be rate-limited");
    assert!(
        matches!(err, hearth::identity::IdentityError::SilentAuthRateLimited),
        "expected SilentAuthRateLimited, got {err}"
    );
}

/// After the 1-hour window expires the counter resets and probes succeed again.
#[test]
fn a37_probe_limit_resets_after_window() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);
    let (realm_id, user_id) = make_realm_and_user(&engine, "reset@example.com");

    // Exhaust the limit.
    for _ in 0..51_u32 {
        let _ =
            engine.check_silent_auth_probe(&realm_id, &user_id, "client-456", "consent_required");
    }

    // Advance past the 1-hour window.
    clock.advance(ONE_HOUR_MICROS + 1);

    // The counter must have FULLY reset, not merely "not immediately fail":
    // a whole fresh budget of 50 probes succeeds, and only the 51st in the new
    // window trips again. A single success would not distinguish a real reset
    // from an off-by-one carry-over.
    for i in 0..50_u32 {
        engine
            .check_silent_auth_probe(&realm_id, &user_id, "client-456", "code_issued")
            .unwrap_or_else(|e| panic!("probe {i} after reset should succeed, got {e}"));
    }
    let err = engine
        .check_silent_auth_probe(&realm_id, &user_id, "client-456", "code_issued")
        .expect_err("51st probe in the reset window must be rate-limited again");
    assert!(
        matches!(err, hearth::identity::IdentityError::SilentAuthRateLimited),
        "expected SilentAuthRateLimited after window reset, got {err}"
    );
}

/// Each subject has an independent counter — exhausting one must not affect another.
#[test]
fn a37_different_subjects_have_independent_counters() {
    let (_dir, engine, _clock) = make_timed_engine(START_MICROS);
    let realm_id = engine
        .create_realm(&CreateRealmRequest {
            name: "shared-realm".to_string(),
            config: None,
        })
        .expect("realm")
        .id()
        .clone();

    let user_a = engine
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "user-a@example.com".to_string(),
                display_name: "A".to_string(),
                ..Default::default()
            },
        )
        .expect("user A")
        .id()
        .clone();

    let user_b = engine
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "user-b@example.com".to_string(),
                display_name: "B".to_string(),
                ..Default::default()
            },
        )
        .expect("user B")
        .id()
        .clone();

    // Exhaust user A's limit.
    for _ in 0..51_u32 {
        let _ = engine.check_silent_auth_probe(&realm_id, &user_a, "c", "code_issued");
    }

    // User B must have its OWN full, independent budget: 50 successes then a
    // rate-limit on the 51st — even though user A is already exhausted. A single
    // success would not prove B's counter is independent rather than shared with
    // A (which would already be over the shared limit).
    for i in 0..50_u32 {
        engine
            .check_silent_auth_probe(&realm_id, &user_b, "c", "code_issued")
            .unwrap_or_else(|e| panic!("user B probe {i} should succeed, got {e}"));
    }
    let err = engine
        .check_silent_auth_probe(&realm_id, &user_b, "c", "code_issued")
        .expect_err("user B's own 51st probe must be rate-limited");
    assert!(
        matches!(err, hearth::identity::IdentityError::SilentAuthRateLimited),
        "expected SilentAuthRateLimited for user B's independent counter, got {err}"
    );
}
