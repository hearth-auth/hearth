//! Integration tests for HIBP k-anonymity breach-check (HEA-834 / HEA-830).
//!
//! AC-1: Compromised password rejected with `IdentityError::PasswordCompromised`.
//! AC-2: Only 5-char SHA-1 prefix sent (verified in `src/identity/hibp.rs` unit tests).
//! AC-3: Fail-open on HIBP unavailable — password accepted, audit event emitted.
//! AC-4: Breach-check disabled when `realm.config.breach_check.enabled = false`.

use std::sync::Arc;

use hearth::audit::{AuditEngine, AuditQuery, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId};
use hearth::identity::hibp::{HibpError, HibpTransport};
use hearth::identity::{
    BreachCheckConfig, CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, IdentityError, RealmConfig,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Stub transports ──────────────────────────────────────────────────────────

/// Stub that always reports the password as compromised.
struct AlwaysPwnedTransport;

impl HibpTransport for AlwaysPwnedTransport {
    fn get_range(&self, _prefix: &str, _api_key: Option<&str>) -> Result<String, HibpError> {
        // Return the suffix for "password" (SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8).
        // The prefix is "5BAA6", so the suffix is "1E4C9B93F3F0682250B6CF8331B7EE68FD8".
        Ok("1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824".to_string())
    }
}

/// Stub that never finds the password in HIBP (safe password).
struct NeverPwnedTransport;

impl HibpTransport for NeverPwnedTransport {
    fn get_range(&self, _prefix: &str, _api_key: Option<&str>) -> Result<String, HibpError> {
        Ok("ABCDE00000000000000000000000000000:1".to_string())
    }
}

/// Stub that simulates HIBP being unreachable.
struct UnreachableTransport;

impl HibpTransport for UnreachableTransport {
    fn get_range(&self, _prefix: &str, _api_key: Option<&str>) -> Result<String, HibpError> {
        Err(HibpError::Unreachable {
            reason: "simulated timeout".to_string(),
        })
    }
}

// ── Test helpers ─────────────────────────────────────────────────────────────

fn build_engine_with_transport(
    transport: Arc<dyn HibpTransport>,
) -> (EmbeddedIdentityEngine, Arc<EmbeddedAuditEngine>) {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(temp_dir.path().to_path_buf()))
            .expect("storage"),
    );
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));
    let engine = EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        Arc::clone(&rbac) as Arc<dyn RbacEngine>,
        Arc::clone(&audit) as Arc<dyn hearth::audit::AuditEngine>,
    )
    .expect("engine")
    .with_hibp_transport(transport);

    (engine, audit)
}

fn create_realm_with_breach_check(
    engine: &EmbeddedIdentityEngine,
    enabled: bool,
) -> hearth::identity::Realm {
    engine
        .create_realm(&CreateRealmRequest {
            name: format!("breach-check-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                breach_check: BreachCheckConfig {
                    enabled,
                    mode: hearth::identity::BreachCheckMode::Online,
                    timeout_ms: 3000,
                    hibp_api_key: String::new(),
                },
                ..RealmConfig::default()
            }),
        })
        .expect("create realm")
}

fn make_user(
    engine: &EmbeddedIdentityEngine,
    realm_id: &RealmId,
    tag: &str,
) -> hearth::identity::User {
    engine
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: format!("{tag}-{}@example.com", uuid::Uuid::new_v4()),
                display_name: format!("{tag} User"),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
}

// ── AC-1: Compromised password rejected ──────────────────────────────────────

#[test]
fn compromised_password_rejected_with_correct_error() {
    let (engine, _audit) = build_engine_with_transport(Arc::new(AlwaysPwnedTransport));
    let realm = create_realm_with_breach_check(&engine, true);
    let user = make_user(&engine, realm.id(), "ac1");

    // "password" is known to be in HIBP; the stub returns its suffix.
    let pw = CleartextPassword::from_string("password".to_string());
    let err = engine
        .set_password(realm.id(), user.id(), &pw)
        .expect_err("should reject compromised password");

    assert!(
        matches!(err, IdentityError::PasswordCompromised),
        "expected PasswordCompromised, got: {err:?}"
    );
}

// ── AC-1 + audit: PasswordCompromisedRejected event emitted ──────────────────

#[test]
fn compromised_password_emits_rejected_audit_event() {
    let (engine, audit) = build_engine_with_transport(Arc::new(AlwaysPwnedTransport));
    let realm = create_realm_with_breach_check(&engine, true);
    let user = make_user(&engine, realm.id(), "ac1-audit");

    let pw = CleartextPassword::from_string("password".to_string());
    let _ = engine.set_password(realm.id(), user.id(), &pw);

    let events = audit
        .query(&AuditQuery::for_realm(realm.id().clone()))
        .expect("audit query");

    let has_rejected = events
        .iter()
        .any(|e| e.action == hearth::audit::AuditAction::PasswordCompromisedRejected);
    assert!(
        has_rejected,
        "expected PasswordCompromisedRejected audit event"
    );
}

// ── AC-3: Fail-open on HIBP timeout ──────────────────────────────────────────

#[test]
fn fail_open_when_hibp_unreachable() {
    let (engine, _audit) = build_engine_with_transport(Arc::new(UnreachableTransport));
    let realm = create_realm_with_breach_check(&engine, true);
    let user = make_user(&engine, realm.id(), "ac3");

    // Password should be accepted (fail-open) even though HIBP is unreachable.
    let pw = CleartextPassword::from_string("some-unique-pw-ac3".to_string());
    engine
        .set_password(realm.id(), user.id(), &pw)
        .expect("should accept password when HIBP unreachable (fail-open)");
}

// ── AC-3 + audit: BreachCheckUnavailable event emitted on fail-open ───────────

#[test]
fn fail_open_emits_breach_check_unavailable_event() {
    let (engine, audit) = build_engine_with_transport(Arc::new(UnreachableTransport));
    let realm = create_realm_with_breach_check(&engine, true);
    let user = make_user(&engine, realm.id(), "ac3-audit");

    let pw = CleartextPassword::from_string("some-unique-pw-ac3-audit".to_string());
    engine
        .set_password(realm.id(), user.id(), &pw)
        .expect("fail-open");

    let events = audit
        .query(&AuditQuery::for_realm(realm.id().clone()))
        .expect("audit query");

    let has_unavailable = events
        .iter()
        .any(|e| e.action == hearth::audit::AuditAction::BreachCheckUnavailable);
    assert!(
        has_unavailable,
        "expected BreachCheckUnavailable audit event"
    );
}

// ── AC-4: Breach-check disabled — password always accepted ───────────────────

#[test]
fn disabled_breach_check_skips_hibp_entirely() {
    // Use AlwaysPwned transport — if HIBP was consulted, this would reject the password.
    let (engine, _audit) = build_engine_with_transport(Arc::new(AlwaysPwnedTransport));
    // Create realm with breach_check.enabled = false.
    let realm = create_realm_with_breach_check(&engine, false);
    let user = make_user(&engine, realm.id(), "ac4");

    // "password" would be rejected if HIBP was consulted.
    // Since breach_check.enabled=false, it should be accepted.
    let pw = CleartextPassword::from_string("password".to_string());
    engine
        .set_password(realm.id(), user.id(), &pw)
        .expect("should accept when breach check is disabled");
}

// ── AC-4 + audit: No HIBP events when disabled ───────────────────────────────

#[test]
fn disabled_breach_check_emits_no_hibp_audit_events() {
    let (engine, audit) = build_engine_with_transport(Arc::new(AlwaysPwnedTransport));
    let realm = create_realm_with_breach_check(&engine, false);
    let user = make_user(&engine, realm.id(), "ac4-noaudit");

    let pw = CleartextPassword::from_string("password".to_string());
    engine
        .set_password(realm.id(), user.id(), &pw)
        .expect("accepted");

    let events = audit
        .query(&AuditQuery::for_realm(realm.id().clone()))
        .expect("audit query");

    let no_hibp_events = !events.iter().any(|e| {
        e.action == hearth::audit::AuditAction::PasswordCompromisedRejected
            || e.action == hearth::audit::AuditAction::BreachCheckUnavailable
    });
    assert!(
        no_hibp_events,
        "expected no HIBP audit events when breach check is disabled"
    );
}

// ── Non-compromised password passes check ─────────────────────────────────────

#[test]
fn safe_password_accepted_when_breach_check_enabled() {
    let (engine, _audit) = build_engine_with_transport(Arc::new(NeverPwnedTransport));
    let realm = create_realm_with_breach_check(&engine, true);
    let user = make_user(&engine, realm.id(), "safe");

    let pw = CleartextPassword::from_string("not-in-hibp-uniqueXYZ".to_string());
    engine
        .set_password(realm.id(), user.id(), &pw)
        .expect("should accept safe password");
}
