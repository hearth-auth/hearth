//! Integration tests for Email OTP MFA (HEA-1329).
//!
//! Covers:
//! - `issue_email_otp` → `verify_email_otp` round-trip with correct code succeeds.
//! - Wrong code returns `InvalidEmailOtp`.
//! - Expired OTP returns `InvalidEmailOtp`.
//! - Replay after successful verify returns `InvalidEmailOtp` (single-use).
//! - Attempt exhaustion returns `InvalidEmailOtp`.
//! - `email_otp_expiry_seconds` realm config overrides the module default.
//! - `RequiredAction::EnrollEmailOtp` serializes/deserializes correctly.
//! - `User.email_otp_enabled()` starts `false`; after successful enrollment it is `true`.

mod common;

use std::sync::{Arc, Mutex};

use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, EmailBranding, EmailError, EmailMessage, EmailSender,
    RealmConfig, RequiredAction, UpdateUserRequest,
};

// ---------------------------------------------------------------------------
// Test-only capturing email sender
// ---------------------------------------------------------------------------

/// An [`EmailSender`] that records every outgoing message.
/// Used to extract the OTP code from the email body.
struct CapturingEmailSender {
    messages: Mutex<Vec<EmailMessage>>,
}

impl CapturingEmailSender {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            messages: Mutex::new(Vec::new()),
        })
    }

    /// Extracts the 6-digit OTP code from the last sent email body.
    ///
    /// Looks for a 6-digit sequence in the text body.
    fn last_otp_code(&self) -> Option<String> {
        #[allow(clippy::unwrap_used)]
        let guard = self.messages.lock().unwrap();
        let body = guard.last()?.text_body.clone();
        // Find the 6-digit code — the format is "Your ... code is: NNNNNN"
        body.rsplit_once(": ")
            .map(|(_, rest)| rest.trim().chars().take(6).collect())
    }
}

impl EmailSender for CapturingEmailSender {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        #[allow(clippy::unwrap_used)]
        self.messages.lock().unwrap().push(message.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const HMAC_KEY: &[u8] = b"test-email-otp-hmac-key-not-for-prod";

fn now_unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn make_email_service(sender: Arc<CapturingEmailSender>) -> hearth::identity::EmailService {
    hearth::identity::EmailService::new(
        sender,
        "Hearth Test".to_string(),
        None,
        EmailBranding::default(),
        String::new(),
        None,
    )
    .expect("EmailService::new")
}

// ---------------------------------------------------------------------------
// AC-1: issue_email_otp → verify_email_otp round-trip succeeds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn email_otp_issue_verify_round_trip() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("email-otp-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let sender = CapturingEmailSender::new();
    let svc = make_email_service(sender.clone());
    let now = now_unix_ts();

    let nonce = harness
        .identity()
        .issue_email_otp(realm.id(), "alice@example.com", HMAC_KEY, &svc, None, now)
        .expect("issue_email_otp should succeed");

    assert!(!nonce.is_empty(), "nonce must be non-empty");

    let code = sender
        .last_otp_code()
        .expect("capturing sender must have a code");
    assert_eq!(code.len(), 6, "OTP code must be 6 digits");
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "OTP must be numeric"
    );

    harness
        .identity()
        .verify_email_otp(realm.id(), &nonce, &code, HMAC_KEY, now)
        .expect("verify_email_otp with correct code must succeed");
}

// ---------------------------------------------------------------------------
// AC-2: Wrong code returns InvalidEmailOtp
// ---------------------------------------------------------------------------

#[tokio::test]
async fn email_otp_wrong_code_returns_invalid() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("email-otp-wrong-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let sender = CapturingEmailSender::new();
    let svc = make_email_service(sender.clone());
    let now = now_unix_ts();

    let nonce = harness
        .identity()
        .issue_email_otp(realm.id(), "bob@example.com", HMAC_KEY, &svc, None, now)
        .expect("issue_email_otp");

    let code = sender.last_otp_code().expect("code");
    let wrong = if code == "000000" { "000001" } else { "000000" };

    let err = harness
        .identity()
        .verify_email_otp(realm.id(), &nonce, wrong, HMAC_KEY, now)
        .expect_err("wrong code must fail");

    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidEmailOtp),
        "expected InvalidEmailOtp, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// AC-3: Expired OTP returns InvalidEmailOtp
// ---------------------------------------------------------------------------

#[tokio::test]
async fn email_otp_expired_returns_invalid() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("email-otp-exp-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let sender = CapturingEmailSender::new();
    let svc = make_email_service(sender.clone());
    // Issue at t=0, but verify at t >> expiry
    let issue_ts = 100u64;

    let nonce = harness
        .identity()
        .issue_email_otp(
            realm.id(),
            "carol@example.com",
            HMAC_KEY,
            &svc,
            None,
            issue_ts,
        )
        .expect("issue_email_otp");

    let code = sender.last_otp_code().expect("code");

    // 10 minutes + 1 second past issue time — well beyond the 10-minute TTL.
    let verify_ts = issue_ts + 10 * 60 + 1;

    let err = harness
        .identity()
        .verify_email_otp(realm.id(), &nonce, &code, HMAC_KEY, verify_ts)
        .expect_err("expired OTP must fail");

    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidEmailOtp),
        "expected InvalidEmailOtp for expired OTP, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// AC-4: Replay returns InvalidEmailOtp (single-use)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn email_otp_replay_fails() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("email-otp-replay-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let sender = CapturingEmailSender::new();
    let svc = make_email_service(sender.clone());
    let now = now_unix_ts();

    let nonce = harness
        .identity()
        .issue_email_otp(realm.id(), "dave@example.com", HMAC_KEY, &svc, None, now)
        .expect("issue_email_otp");

    let code = sender.last_otp_code().expect("code");

    // First verify succeeds.
    harness
        .identity()
        .verify_email_otp(realm.id(), &nonce, &code, HMAC_KEY, now)
        .expect("first verify must succeed");

    // Second verify with same nonce+code must fail (record deleted on success).
    let err = harness
        .identity()
        .verify_email_otp(realm.id(), &nonce, &code, HMAC_KEY, now)
        .expect_err("replay must fail");

    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidEmailOtp),
        "expected InvalidEmailOtp for replay, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// AC-5: Attempt exhaustion returns InvalidEmailOtp
// ---------------------------------------------------------------------------

#[tokio::test]
async fn email_otp_attempt_exhaustion_returns_invalid() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("email-otp-exhaust-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let sender = CapturingEmailSender::new();
    let svc = make_email_service(sender.clone());
    let now = now_unix_ts();

    let nonce = harness
        .identity()
        .issue_email_otp(realm.id(), "eve@example.com", HMAC_KEY, &svc, None, now)
        .expect("issue_email_otp");

    let code = sender.last_otp_code().expect("code");
    let wrong = if code == "000000" {
        "000001".to_string()
    } else {
        "000000".to_string()
    };

    // Exhaust all 5 attempts with wrong codes.
    for _ in 0..5 {
        let _ = harness
            .identity()
            .verify_email_otp(realm.id(), &nonce, &wrong, HMAC_KEY, now);
    }

    // A subsequent attempt (even with the correct code) must fail.
    let err = harness
        .identity()
        .verify_email_otp(realm.id(), &nonce, &code, HMAC_KEY, now)
        .expect_err("exhausted OTP must fail even with correct code");

    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidEmailOtp),
        "expected InvalidEmailOtp after exhaustion, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// AC-6: email_otp_expiry_seconds realm config overrides module default
// ---------------------------------------------------------------------------

#[tokio::test]
async fn email_otp_realm_expiry_override() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    // Set 60-second expiry (below the 10-minute module default).
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("email-otp-cfg-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                email_otp_expiry_seconds: Some(60),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    let sender = CapturingEmailSender::new();
    let svc = make_email_service(sender.clone());
    let issue_ts = 1_000u64;

    let nonce = harness
        .identity()
        .issue_email_otp(
            realm.id(),
            "frank@example.com",
            HMAC_KEY,
            &svc,
            None,
            issue_ts,
        )
        .expect("issue_email_otp");

    let code = sender.last_otp_code().expect("code");

    // 61 seconds past issue time — expired under the realm override.
    let err = harness
        .identity()
        .verify_email_otp(realm.id(), &nonce, &code, HMAC_KEY, issue_ts + 61)
        .expect_err("OTP must expire after realm-configured 60 s");

    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidEmailOtp),
        "expected InvalidEmailOtp after realm-level expiry, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// AC-7: RequiredAction::EnrollEmailOtp serialization round-trip
// ---------------------------------------------------------------------------

#[test]
fn required_action_enroll_email_otp_serde_round_trip() {
    let action = RequiredAction::EnrollEmailOtp;
    let json = serde_json::to_string(&action).expect("serialize");
    assert_eq!(
        json, "\"ENROLL_EMAIL_OTP\"",
        "EnrollEmailOtp must serialize to ENROLL_EMAIL_OTP"
    );
    let back: RequiredAction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, RequiredAction::EnrollEmailOtp);
}

#[test]
fn required_action_enroll_email_otp_path_segment() {
    assert_eq!(
        RequiredAction::EnrollEmailOtp.as_path_segment(),
        "ENROLL_EMAIL_OTP"
    );
    assert_eq!(
        RequiredAction::from_path_segment("ENROLL_EMAIL_OTP"),
        Some(RequiredAction::EnrollEmailOtp)
    );
}

// ---------------------------------------------------------------------------
// AC-8: User.email_otp_enabled() starts false; enrollment sets it true
// ---------------------------------------------------------------------------

#[tokio::test]
async fn user_email_otp_enabled_starts_false_and_set_on_enrollment() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("email-otp-flag-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("grace-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Grace".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    assert!(
        !user.email_otp_enabled(),
        "email_otp_enabled must be false on a fresh user"
    );

    // Simulate enrollment completing: update the user's email_otp_enabled flag.
    let updated = harness
        .identity()
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                email_otp_enabled: Some(true),
                ..UpdateUserRequest::default()
            },
        )
        .expect("update_user");

    assert!(
        updated.email_otp_enabled(),
        "email_otp_enabled must be true after enrollment"
    );
}
