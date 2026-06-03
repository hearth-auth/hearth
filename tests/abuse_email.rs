//! Tests for A-19 (email-change re-verification) and A-20 (deleted-email
//! 90-day reservation cooldown).
//!
//! D-4 taxonomy:
//! - Unit: audit action string round-trips, error display.
//! - Integration: full initiate→confirm flow, cooldown enforcement on
//!   re-registration, token expiry, duplicate-new-email guard.
//! - Adversarial: attempt re-registration during cooldown, replayed
//!   confirm token, email-change to reserved address.
//!
//! Closes: §3.20 (email-change re-verification), §3.21 (deleted-email
//! reuse cooldown).

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
const DAY_MICROS: i64 = 86_400_000_000_i64;
const NINETY_DAYS_MICROS: i64 = 90 * DAY_MICROS;

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

fn make_realm(engine: &EmbeddedIdentityEngine) -> RealmId {
    engine
        .create_realm(&CreateRealmRequest {
            name: "test-realm".to_string(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn make_user(engine: &EmbeddedIdentityEngine, realm_id: &RealmId, email: &str) -> UserId {
    engine
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Test User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone()
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: audit action string round-trips
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a19_email_change_initiated_audit_round_trips() {
    let action = AuditAction::EmailChangeInitiated;
    assert_eq!(action.as_str(), "email_change_initiated");
    let parsed: AuditAction = "email_change_initiated"
        .parse()
        .expect("parse EmailChangeInitiated");
    assert_eq!(parsed, AuditAction::EmailChangeInitiated);
}

#[test]
fn a19_email_change_confirmed_audit_round_trips() {
    let action = AuditAction::EmailChangeConfirmed;
    assert_eq!(action.as_str(), "email_change_confirmed");
    let parsed: AuditAction = "email_change_confirmed"
        .parse()
        .expect("parse EmailChangeConfirmed");
    assert_eq!(parsed, AuditAction::EmailChangeConfirmed);
}

#[test]
fn a19_email_change_actions_in_all() {
    let all = AuditAction::all();
    assert!(
        all.contains(&AuditAction::EmailChangeInitiated),
        "EmailChangeInitiated missing from AuditAction::all()"
    );
    assert!(
        all.contains(&AuditAction::EmailChangeConfirmed),
        "EmailChangeConfirmed missing from AuditAction::all()"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-19 Integration: happy-path initiate → confirm
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a19_initiate_returns_token_and_confirm_swaps_email() {
    let (_dir, engine, _clock) = make_timed_engine(START_MICROS);
    let realm_id = make_realm(&engine);
    let user_id = make_user(&engine, &realm_id, "old@example.com");

    // Initiate: returns a plaintext token.
    let token = engine
        .initiate_email_change(&realm_id, &user_id, "new@example.com")
        .expect("initiate_email_change");
    assert!(!token.is_empty(), "token must be non-empty");

    // User record unchanged before confirm.
    let user_before = engine
        .get_user(&realm_id, &user_id)
        .expect("get_user")
        .expect("user exists");
    assert_eq!(user_before.email(), "old@example.com");

    // Confirm: swaps the email.
    let updated = engine
        .confirm_email_change(&realm_id, &token)
        .expect("confirm_email_change");
    assert_eq!(updated.email(), "new@example.com");
    assert!(updated.email_verified(), "email_verified must be set");

    // Old address is now free; new address is indexed.
    let by_new = engine
        .get_user_by_email(&realm_id, "new@example.com")
        .expect("lookup by new email")
        .expect("user found by new email");
    assert_eq!(by_new.id(), &user_id);

    let by_old = engine
        .get_user_by_email(&realm_id, "old@example.com")
        .expect("lookup by old email");
    assert!(by_old.is_none(), "old email index must be removed");
}

#[test]
fn a19_confirm_is_single_use() {
    let (_dir, engine, _clock) = make_timed_engine(START_MICROS);
    let realm_id = make_realm(&engine);
    let user_id = make_user(&engine, &realm_id, "alice@example.com");

    let token = engine
        .initiate_email_change(&realm_id, &user_id, "alice2@example.com")
        .expect("initiate");
    engine
        .confirm_email_change(&realm_id, &token)
        .expect("first confirm");

    // Second confirm must fail.
    let err = engine
        .confirm_email_change(&realm_id, &token)
        .expect_err("second confirm must fail");
    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::EmailChangeTokenInvalid
        ),
        "expected EmailChangeTokenInvalid, got {err}"
    );
}

#[test]
fn a19_confirm_fails_on_expired_token() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);
    let realm_id = make_realm(&engine);
    let user_id = make_user(&engine, &realm_id, "bob@example.com");

    let token = engine
        .initiate_email_change(&realm_id, &user_id, "bob2@example.com")
        .expect("initiate");

    // Advance clock by 25 hours (past the 24-hour expiry).
    clock.advance(25 * 3_600_000_000_i64);

    let err = engine
        .confirm_email_change(&realm_id, &token)
        .expect_err("expired token must fail");
    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::EmailChangeTokenInvalid
        ),
        "expected EmailChangeTokenInvalid, got {err}"
    );
}

#[test]
fn a19_initiate_rejects_duplicate_email() {
    let (_dir, engine, _clock) = make_timed_engine(START_MICROS);
    let realm_id = make_realm(&engine);
    let user_id = make_user(&engine, &realm_id, "carol@example.com");
    let _other_user_id = make_user(&engine, &realm_id, "taken@example.com");

    let err = engine
        .initiate_email_change(&realm_id, &user_id, "taken@example.com")
        .expect_err("should fail on taken email");
    assert!(
        matches!(err, hearth::identity::IdentityError::DuplicateEmail),
        "expected DuplicateEmail, got {err}"
    );
}

#[test]
fn a19_initiate_rejects_same_email() {
    let (_dir, engine, _clock) = make_timed_engine(START_MICROS);
    let realm_id = make_realm(&engine);
    let user_id = make_user(&engine, &realm_id, "dave@example.com");

    let err = engine
        .initiate_email_change(&realm_id, &user_id, "dave@example.com")
        .expect_err("same email should fail");
    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidInput { .. }),
        "expected InvalidInput, got {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-20 Integration: deleted-email cooldown
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a20_deleted_email_blocks_re_registration_within_90_days() {
    let (_dir, engine, _clock) = make_timed_engine(START_MICROS);
    let realm_id = make_realm(&engine);
    let user_id = make_user(&engine, &realm_id, "squatter@example.com");

    engine
        .delete_user(&realm_id, &user_id)
        .expect("delete_user");

    // Immediate re-registration must be blocked.
    let err = engine
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "squatter@example.com".to_string(),
                display_name: "New User".to_string(),
                ..Default::default()
            },
        )
        .expect_err("re-registration must fail within 90 days");

    assert!(
        matches!(err, hearth::identity::IdentityError::EmailReserved),
        "expected EmailReserved, got {err}"
    );
}

#[test]
fn a20_re_registration_allowed_after_90_days() {
    let (_dir, engine, clock) = make_timed_engine(START_MICROS);
    let realm_id = make_realm(&engine);
    let user_id = make_user(&engine, &realm_id, "old-user@example.com");

    engine
        .delete_user(&realm_id, &user_id)
        .expect("delete_user");

    // Advance past the 90-day window.
    clock.advance(NINETY_DAYS_MICROS + DAY_MICROS);

    let new_user = engine
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "old-user@example.com".to_string(),
                display_name: "New Person".to_string(),
                ..Default::default()
            },
        )
        .expect("re-registration after 90 days must succeed");

    assert_ne!(
        new_user.id(),
        &user_id,
        "new registration must get a fresh identity"
    );
}

#[test]
fn a20_email_change_to_reserved_address_blocked() {
    let (_dir, engine, _clock) = make_timed_engine(START_MICROS);
    let realm_id = make_realm(&engine);
    let deleted_user = make_user(&engine, &realm_id, "ex-user@example.com");
    let active_user = make_user(&engine, &realm_id, "active@example.com");

    engine
        .delete_user(&realm_id, &deleted_user)
        .expect("delete_user");

    // Initiating an email change TO the reserved address must be blocked.
    let err = engine
        .initiate_email_change(&realm_id, &active_user, "ex-user@example.com")
        .expect_err("email change to reserved address must fail");

    assert!(
        matches!(err, hearth::identity::IdentityError::EmailReserved),
        "expected EmailReserved, got {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial
// ─────────────────────────────────────────────────────────────────────────────

/// EmailReserved must have the same wire error code as DuplicateEmail so
/// callers cannot distinguish "email in use" from "email reserved".
#[test]
fn a20_email_reserved_matches_duplicate_email_wire_code() {
    let reserved_code = hearth::identity::IdentityError::EmailReserved.wire_error_code();
    let duplicate_code = hearth::identity::IdentityError::DuplicateEmail.wire_error_code();
    assert_eq!(
        reserved_code, duplicate_code,
        "EmailReserved and DuplicateEmail must share the same wire error code"
    );
}

/// A random string must not be accepted as a valid email-change token.
#[test]
fn a19_random_token_rejected() {
    let (_dir, engine, _clock) = make_timed_engine(START_MICROS);
    let realm_id = make_realm(&engine);

    let err = engine
        .confirm_email_change(&realm_id, "this-is-not-a-valid-token")
        .expect_err("random token must fail");
    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::EmailChangeTokenInvalid
        ),
        "expected EmailChangeTokenInvalid, got {err}"
    );
}

/// Sessions must be revoked after a confirmed email change.
#[test]
fn a19_confirm_revokes_sessions() {
    use hearth::identity::SessionContext;

    let (_dir, engine, _clock) = make_timed_engine(START_MICROS);
    let realm_id = make_realm(&engine);
    let user_id = make_user(&engine, &realm_id, "eve@example.com");

    engine
        .set_password(
            &realm_id,
            &user_id,
            &hearth::identity::CleartextPassword::from_string("Password123!".to_string()),
        )
        .expect("set_password");

    let session_id = engine
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .expect("create_session")
        .id()
        .clone();

    // Session must be valid before email change.
    assert!(
        engine
            .get_session(&realm_id, &session_id)
            .expect("get_session")
            .is_some(),
        "session must exist before email change"
    );

    let token = engine
        .initiate_email_change(&realm_id, &user_id, "eve2@example.com")
        .expect("initiate");
    engine
        .confirm_email_change(&realm_id, &token)
        .expect("confirm");

    // Session must be revoked after email change.
    let session = engine
        .get_session(&realm_id, &session_id)
        .expect("get_session after change");
    assert!(
        session.is_none(),
        "session must be revoked after email change"
    );
}
