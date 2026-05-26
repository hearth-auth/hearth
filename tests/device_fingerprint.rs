//! Integration tests for device fingerprint storage and adaptive-MFA step-up.
//!
//! Tests correspond to HEA-839 acceptance criteria AC-6 through AC-11.
//! HEA-875 adds GDPR Art.17 regression tests (cascade + admin erasure endpoint).

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{
    device_fp::{DeviceFingerprintOutcome, DeviceFingerprintStore, FingerprintResult},
    AdaptiveMfaConfig, CreateRealmRequest, CreateUserRequest, RealmConfig, SessionContext,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use secrecy::SecretString;
use tower::ServiceExt as _;

// ===================================================================
// AC-11: GDPR — only HMAC bytes stored, not raw IP / UA
// ===================================================================

/// HMAC derivation is deterministic for the same inputs.
/// Hosts in the same /24 produce the same HMAC; different /24 produce different.
#[tokio::test]
async fn hmac_derivation_deterministic_and_subnet_sensitive() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "fp-hmac-test".to_string(),
            config: None,
        })
        .expect("create realm");
    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "hmac@example.com".to_string(),
                display_name: "HMAC Test".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let secret = "test-hmac-secret-at-least-32-bytes!";
    let h1 = DeviceFingerprintStore::derive_hmac(secret, user.id(), "192.168.1.42", "Mozilla/5.0");
    let h2 = DeviceFingerprintStore::derive_hmac(secret, user.id(), "192.168.1.99", "Mozilla/5.0");
    let h3 = DeviceFingerprintStore::derive_hmac(secret, user.id(), "192.168.2.10", "Mozilla/5.0");
    let h4 = DeviceFingerprintStore::derive_hmac(secret, user.id(), "192.168.1.42", "Mozilla/5.0");

    // Same /24 subnet → same HMAC (subnet normalisation)
    assert_eq!(h1, h2, "same /24 must produce same HMAC");
    // Different /24 → different HMAC
    assert_ne!(h1, h3, "different /24 must produce different HMAC");
    // Deterministic
    assert_eq!(h1, h4, "HMAC must be deterministic");
}

/// IPv6 addresses in the same /48 produce the same HMAC.
#[tokio::test]
async fn hmac_ipv6_subnet_normalisation() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "fp-ipv6-test".to_string(),
            config: None,
        })
        .expect("create realm");
    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "ipv6@example.com".to_string(),
                display_name: "IPv6 Test".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let secret = "test-hmac-secret-at-least-32-bytes!";
    // Same first 48 bits, different suffix
    let h1 = DeviceFingerprintStore::derive_hmac(
        secret,
        user.id(),
        "2001:db8:85a3::8a2e:370:7334",
        "curl/7",
    );
    let h2 = DeviceFingerprintStore::derive_hmac(
        secret,
        user.id(),
        "2001:db8:85a3::dead:beef:cafe",
        "curl/7",
    );
    assert_eq!(h1, h2, "same /48 must produce same HMAC");

    // Different /48
    let h3 = DeviceFingerprintStore::derive_hmac(
        secret,
        user.id(),
        "2001:db8:1234::8a2e:370:7334",
        "curl/7",
    );
    assert_ne!(h1, h3, "different /48 must produce different HMAC");
}

// ===================================================================
// AC-6 / AC-7: Unrecognised → step-up; recognised → skip
// ===================================================================

/// A brand-new fingerprint is unrecognised.
#[tokio::test]
async fn unrecognised_device_returns_unrecognised() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "fp-unrec-test".to_string(),
            config: None,
        })
        .expect("create realm");
    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "unrec@example.com".to_string(),
                display_name: "Unrecognised".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let store = harness.device_fp_store();
    let hmac =
        DeviceFingerprintStore::derive_hmac("secret-value", user.id(), "10.0.0.1", "TestAgent");
    let result = store
        .check_and_refresh(realm.id(), user.id(), &hmac, 30)
        .expect("check");
    assert_eq!(result, FingerprintResult::Unrecognised);
}

/// After recording, the fingerprint is recognised.
#[tokio::test]
async fn recognised_after_record() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "fp-rec-test".to_string(),
            config: None,
        })
        .expect("create realm");
    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "rec@example.com".to_string(),
                display_name: "Recognised".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let store = harness.device_fp_store();
    let hmac =
        DeviceFingerprintStore::derive_hmac("secret-value", user.id(), "10.0.0.2", "TestAgent");

    // First: unrecognised
    assert_eq!(
        store
            .check_and_refresh(realm.id(), user.id(), &hmac, 30)
            .expect("check 1"),
        FingerprintResult::Unrecognised
    );

    // Record
    store
        .record(realm.id(), user.id(), &hmac, 30)
        .expect("record");

    // Second: recognised
    assert_eq!(
        store
            .check_and_refresh(realm.id(), user.id(), &hmac, 30)
            .expect("check 2"),
        FingerprintResult::Recognised
    );
}

// ===================================================================
// AC-9: Rolling TTL refresh on recognised-device login
// ===================================================================

/// `check_and_refresh` extends the expiry on an existing entry.
#[tokio::test]
async fn ttl_is_refreshed_on_recognised_login() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "fp-ttl-test".to_string(),
            config: None,
        })
        .expect("create realm");
    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "ttl@example.com".to_string(),
                display_name: "TTL Test".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let store = harness.device_fp_store();
    let hmac =
        DeviceFingerprintStore::derive_hmac("secret-value", user.id(), "10.0.0.3", "TestAgent");

    // Record with 1-day window
    store
        .record(realm.id(), user.id(), &hmac, 1)
        .expect("record short");
    let expiry_before = store
        .get_expiry(realm.id(), user.id(), &hmac)
        .expect("expiry before")
        .expect("should exist");

    // Refresh with 30-day window
    let r = store
        .check_and_refresh(realm.id(), user.id(), &hmac, 30)
        .expect("refresh");
    assert_eq!(r, FingerprintResult::Recognised);

    let expiry_after = store
        .get_expiry(realm.id(), user.id(), &hmac)
        .expect("expiry after")
        .expect("should still exist");

    assert!(
        expiry_after > expiry_before,
        "expiry must be extended after check_and_refresh"
    );

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs() as i64;
    assert!(
        expiry_after >= now_secs + 29 * 86400,
        "expiry must be ~30 days out"
    );
}

// ===================================================================
// AC-10: Feature disabled → Skipped
// ===================================================================

/// When adaptive_mfa.enabled = false the engine must return Skipped.
#[tokio::test]
async fn adaptive_mfa_disabled_returns_skipped() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "fp-disabled-test".to_string(),
            config: Some(RealmConfig {
                adaptive_mfa: AdaptiveMfaConfig {
                    enabled: false,
                    recognition_window_days: 30,
                    fingerprint_hmac_secret: SecretString::new("some-secret-value-here".into()),
                },
                ..Default::default()
            }),
        })
        .expect("create realm");
    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "disabled@example.com".to_string(),
                display_name: "Disabled".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let outcome = harness
        .identity()
        .check_device_fingerprint(realm.id(), user.id(), "10.0.0.4", "TestAgent")
        .expect("check");
    assert_eq!(outcome, DeviceFingerprintOutcome::Skipped);
}

/// Empty HMAC secret with adaptive_mfa enabled must return a hard Internal error
/// (BLK-2: fail-secure, not fail-open). Silently skipping would allow tokens
/// to be issued without the intended fingerprint gate.
#[tokio::test]
async fn empty_hmac_secret_returns_skipped() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "fp-empty-secret-test".to_string(),
            config: Some(RealmConfig {
                adaptive_mfa: AdaptiveMfaConfig {
                    enabled: true,
                    recognition_window_days: 30,
                    fingerprint_hmac_secret: SecretString::new(String::new()), // intentionally empty
                },
                ..Default::default()
            }),
        })
        .expect("create realm");
    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "empty@example.com".to_string(),
                display_name: "Empty Secret".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let err = harness
        .identity()
        .check_device_fingerprint(realm.id(), user.id(), "10.0.0.5", "TestAgent")
        .expect_err("empty secret with enabled=true must return Internal error");
    assert!(
        matches!(err, hearth::identity::IdentityError::Internal { .. }),
        "expected Internal config error, got: {err:?}"
    );
}

// ===================================================================
// AC-8: User with no MFA → EnrollMfaRequired
// ===================================================================

/// Unrecognised device + user has no MFA factor → EnrollMfaRequired.
#[tokio::test]
async fn unrecognised_no_mfa_returns_enroll_required() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "fp-enroll-test".to_string(),
            config: Some(RealmConfig {
                adaptive_mfa: AdaptiveMfaConfig {
                    enabled: true,
                    recognition_window_days: 30,
                    fingerprint_hmac_secret: SecretString::new(
                        "test-secret-at-least-32-bytes-ok".into(),
                    ),
                },
                ..Default::default()
            }),
        })
        .expect("create realm");
    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "enroll@example.com".to_string(),
                display_name: "Enroll Required".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let outcome = harness
        .identity()
        .check_device_fingerprint(realm.id(), user.id(), "10.0.0.6", "TestAgent")
        .expect("check");
    assert_eq!(outcome, DeviceFingerprintOutcome::EnrollMfaRequired);
}

// ===================================================================
// AC-6: User with MFA enrolled + unrecognised → StepUpRequired
// ===================================================================

/// Unrecognised device + user has TOTP enrolled → StepUpRequired.
#[tokio::test]
async fn unrecognised_with_mfa_returns_step_up_required() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "fp-stepup-test".to_string(),
            config: Some(RealmConfig {
                adaptive_mfa: AdaptiveMfaConfig {
                    enabled: true,
                    recognition_window_days: 30,
                    fingerprint_hmac_secret: SecretString::new(
                        "test-secret-at-least-32-bytes-ok".into(),
                    ),
                },
                ..Default::default()
            }),
        })
        .expect("create realm");
    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "stepup@example.com".to_string(),
                display_name: "Step Up".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    // Enroll TOTP
    let enrollment = harness
        .identity()
        .enroll_totp(realm.id(), user.id())
        .expect("enroll totp");
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    harness
        .identity()
        .verify_totp_enrollment(realm.id(), user.id(), &code)
        .expect("verify enrollment");

    let outcome = harness
        .identity()
        .check_device_fingerprint(realm.id(), user.id(), "10.0.0.7", "TestAgent")
        .expect("check");
    assert_eq!(outcome, DeviceFingerprintOutcome::StepUpRequired);
}

/// After recording fingerprint, recognised device skips step-up (AC-7).
#[tokio::test]
async fn recognised_device_skips_step_up() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "fp-skip-test".to_string(),
            config: Some(RealmConfig {
                adaptive_mfa: AdaptiveMfaConfig {
                    enabled: true,
                    recognition_window_days: 30,
                    fingerprint_hmac_secret: SecretString::new(
                        "test-secret-at-least-32-bytes-ok".into(),
                    ),
                },
                ..Default::default()
            }),
        })
        .expect("create realm");
    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "skip@example.com".to_string(),
                display_name: "Skip Step-Up".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    // Enroll TOTP
    let enrollment = harness
        .identity()
        .enroll_totp(realm.id(), user.id())
        .expect("enroll totp");
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    harness
        .identity()
        .verify_totp_enrollment(realm.id(), user.id(), &code)
        .expect("verify enrollment");

    // First check → StepUpRequired (unrecognised)
    assert_eq!(
        harness
            .identity()
            .check_device_fingerprint(realm.id(), user.id(), "10.0.0.8", "TestAgent")
            .expect("first check"),
        DeviceFingerprintOutcome::StepUpRequired
    );

    // Record the fingerprint (simulates completed step-up)
    harness
        .identity()
        .record_device_fingerprint(realm.id(), user.id(), "10.0.0.8", "TestAgent")
        .expect("record fp");

    // Second check → Recognised (AC-7)
    assert_eq!(
        harness
            .identity()
            .check_device_fingerprint(realm.id(), user.id(), "10.0.0.8", "TestAgent")
            .expect("second check"),
        DeviceFingerprintOutcome::Recognised
    );
}

// ===================================================================
// Helpers
// ===================================================================

// ===================================================================
// CWE-532 regression: Debug output must not contain the secret value
// ===================================================================

/// `AdaptiveMfaConfig` `Debug` must redact `fingerprint_hmac_secret`.
///
/// Regression for HEA-869: the field must never appear in log output.
#[test]
fn adaptive_mfa_config_debug_redacts_secret() {
    let sentinel = "super-secret-hmac-sentinel-value";
    let cfg = AdaptiveMfaConfig {
        enabled: true,
        recognition_window_days: 30,
        fingerprint_hmac_secret: SecretString::new(sentinel.into()),
    };
    let debug_output = format!("{cfg:?}");
    assert!(
        !debug_output.contains(sentinel),
        "Debug output must not contain the HMAC secret; got: {debug_output}"
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug output should contain [REDACTED]; got: {debug_output}"
    );
}

/// `BreachCheckConfig` `Debug` must redact `hibp_api_key`.
///
/// Regression for HEA-869: the API key must never appear in log output.
#[test]
fn breach_check_config_debug_redacts_api_key() {
    use hearth::identity::BreachCheckConfig;
    let sentinel = "hibp-api-key-sentinel-value-12345";
    let cfg = BreachCheckConfig {
        enabled: true,
        timeout_ms: 3000,
        hibp_api_key: SecretString::new(sentinel.into()),
    };
    let debug_output = format!("{cfg:?}");
    assert!(
        !debug_output.contains(sentinel),
        "Debug output must not contain the HIBP API key; got: {debug_output}"
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug output should contain [REDACTED]; got: {debug_output}"
    );
}

// ===================================================================
// HEA-875: GDPR Art.17 — Gap A cascade + Gap B admin erasure API
// ===================================================================

async fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

async fn admin_token_for(harness: &common::TestHarness, realm: &RealmId) -> String {
    let user = harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("admin-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "Admin".into(),
                first_name: "Admin".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create admin user");
    let role = harness
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    harness
        .rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign");
    let session = harness
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    harness
        .identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("tokens")
        .access_token()
        .to_string()
}

/// Gap A regression: `delete_user` must erase all device fingerprints so
/// GDPR Art.17 erasure is complete without a separate API call.
#[tokio::test]
async fn delete_user_erases_device_fingerprints() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "gdpr-cascade-test".into(),
            config: None,
        })
        .expect("realm");
    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "eraseme@example.com".into(),
                display_name: "Erase Me".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("user");

    let store = harness.device_fp_store();
    let secret = "test-secret-gdpr-cascade-32-bytes!";
    let hmac = DeviceFingerprintStore::derive_hmac(secret, user.id(), "10.1.2.3", "TestUA/1");
    store
        .record(realm.id(), user.id(), &hmac, 30)
        .expect("record");

    // Pre-condition: fingerprint exists.
    assert_eq!(
        store
            .check_and_refresh(realm.id(), user.id(), &hmac, 30)
            .expect("pre-check"),
        FingerprintResult::Recognised
    );

    // Delete the user.
    harness
        .identity()
        .delete_user(realm.id(), user.id())
        .expect("delete");

    // Post-condition: fingerprint gone.
    assert_eq!(
        store
            .check_and_refresh(realm.id(), user.id(), &hmac, 30)
            .expect("post-check"),
        FingerprintResult::Unrecognised,
        "fingerprint must be erased when user is deleted"
    );
}

/// Gap B: `DELETE /admin/users/{id}/device-fingerprints` returns 200 with
/// `{"erased": N}` and the fingerprints are gone from storage.
#[tokio::test]
async fn admin_delete_device_fingerprints_erases_and_returns_count() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness.create_realm();
    harness.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token_for(&harness, &realm).await;

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "fp-erase@example.com".into(),
                display_name: "FP Target".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("user");

    let store = harness.device_fp_store();
    let secret = "test-secret-admin-erasure-32-bytes!";
    for ip in &["10.2.0.1", "10.3.0.1"] {
        let hmac = DeviceFingerprintStore::derive_hmac(secret, user.id(), ip, "AdminUA/1");
        store.record(&realm, user.id(), &hmac, 30).expect("record");
    }

    let app = build_app(&harness).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/admin/users/{}/device-fingerprints",
                    user.id().as_uuid()
                ))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body["erased"], 2, "must report 2 erased records");

    // Verify storage is actually empty.
    let hmac = DeviceFingerprintStore::derive_hmac(secret, user.id(), "10.2.0.1", "AdminUA/1");
    assert_eq!(
        store
            .check_and_refresh(&realm, user.id(), &hmac, 30)
            .expect("post-check"),
        FingerprintResult::Unrecognised,
        "fingerprint must be gone after admin erasure"
    );
}

/// Computes a TOTP code using the same algorithm as the engine.
fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let step = unix_secs / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let msg = step.to_be_bytes();
    let tag = ring::hmac::sign(&key, &msg);
    let hash = tag.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    format!("{:06}", binary % 1_000_000)
}
