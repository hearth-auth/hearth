//! Concurrency guards for one-time codes (audit 2026-08-28 §4.18#4).
//!
//! A TOTP, recovery or email-OTP code MUST be redeemable exactly
//! once, including when two submissions of the same code race.
//!
//! Every verifier is an unsynchronised read-modify-write on storage: load the
//! record, check it, write it back. Without a lock, two concurrent callers
//! both load the not-yet-consumed record and both succeed. Each test below
//! fires `CONCURRENCY` submissions of one code through a barrier and asserts
//! that exactly one of them returns `Ok`.

mod common;

use std::sync::{Arc, Barrier, Mutex};

use hearth::core::{RealmId, UserId};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, EmailBranding, EmailError, EmailMessage, EmailSender,
    IdentityEngine, RealmConfig,
};

/// Number of racing submissions of the same code.
const CONCURRENCY: usize = 6;

const EMAIL_HMAC_KEY: &[u8] = b"test-email-otp-hmac-key-not-for-prod";

// ---------------------------------------------------------------------------
// Test-only capturing senders
// ---------------------------------------------------------------------------

struct CapturingEmailSender {
    messages: Mutex<Vec<EmailMessage>>,
}

impl CapturingEmailSender {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            messages: Mutex::new(Vec::new()),
        })
    }

    fn last_otp_code(&self) -> Option<String> {
        #[allow(clippy::unwrap_used)]
        let guard = self.messages.lock().unwrap();
        let body = guard.last()?.text_body.clone();
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
// Helpers
// ---------------------------------------------------------------------------

fn now_unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn create_realm(harness: &common::TestHarness, prefix: &str) -> RealmId {
    harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("{prefix}-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                // Canonical names per VALID_MFA_METHODS; "email" is not one of
                // them, and task 19.15 made the gate actually enforce the list.
                mfa_methods: Some(vec!["totp".to_string(), "email_otp".to_string()]),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm")
        .id()
        .clone()
}

fn create_user(harness: &common::TestHarness, realm: &RealmId) -> UserId {
    harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("otp-race-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "OTP Race User".to_string(),
                ..CreateUserRequest::default()
            },
        )
        .expect("create user")
        .id()
        .clone()
}

/// Computes a TOTP code from a base32 secret — same algorithm as the engine.
fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let step = unix_secs / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let tag = ring::hmac::sign(&key, &step.to_be_bytes());
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

/// Runs `f` on `CONCURRENCY` blocking threads released by one barrier, and
/// returns how many of them returned `Ok`.
async fn count_concurrent_successes<F>(engine: &Arc<dyn IdentityEngine>, f: F) -> usize
where
    F: Fn(&Arc<dyn IdentityEngine>) -> Result<(), hearth::identity::IdentityError>
        + Send
        + Sync
        + Clone
        + 'static,
{
    let barrier = Arc::new(Barrier::new(CONCURRENCY));
    let mut handles = Vec::with_capacity(CONCURRENCY);

    for _ in 0..CONCURRENCY {
        let engine = Arc::clone(engine);
        let barrier = Arc::clone(&barrier);
        let f = f.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            barrier.wait();
            f(&engine).is_ok()
        }));
    }

    let mut successes = 0;
    for handle in handles {
        if handle.await.expect("join blocking task") {
            successes += 1;
        }
    }
    successes
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn totp_code_is_redeemable_once_under_concurrency() {
    let harness = common::TestHarness::in_process().await.expect("harness");
    let realm = create_realm(&harness, "totp-race");
    let user = create_user(&harness, &realm);

    let enrollment = harness
        .identity()
        .enroll_totp(&realm, &user)
        .expect("enroll_totp");
    let now = now_unix_ts();
    let code = compute_totp_code(&enrollment.secret_base32, now);
    harness
        .identity()
        .verify_totp_enrollment(&realm, &user, &code)
        .expect("verify enrollment");

    // The enrolment consumed this step, so race the next step's code.
    let next_code = compute_totp_code(&enrollment.secret_base32, now + 30);
    let engine = harness.identity_arc();
    let successes =
        count_concurrent_successes(&engine, move |e| e.verify_totp(&realm, &user, &next_code))
            .await;

    assert_eq!(
        successes, 1,
        "one TOTP code must be redeemable exactly once, got {successes} successes"
    );
}

// ---------------------------------------------------------------------------
// Recovery code
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_code_is_redeemable_once_under_concurrency() {
    let harness = common::TestHarness::in_process().await.expect("harness");
    let realm = create_realm(&harness, "recovery-race");
    let user = create_user(&harness, &realm);

    let enrollment = harness
        .identity()
        .enroll_totp(&realm, &user)
        .expect("enroll_totp");
    let now = now_unix_ts();
    let code = compute_totp_code(&enrollment.secret_base32, now);
    harness
        .identity()
        .verify_totp_enrollment(&realm, &user, &code)
        .expect("verify enrollment");

    let recovery_code = enrollment.recovery_codes.as_slice()[0].clone();
    let engine = harness.identity_arc();
    let successes = count_concurrent_successes(&engine, move |e| {
        e.verify_recovery_code(&realm, &user, &recovery_code)
    })
    .await;

    assert_eq!(
        successes, 1,
        "one recovery code must be redeemable exactly once, got {successes} successes"
    );
}

// ---------------------------------------------------------------------------
// Email OTP
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn email_otp_is_redeemable_once_under_concurrency() {
    let harness = common::TestHarness::in_process().await.expect("harness");
    let realm = create_realm(&harness, "email-race");

    let sender = CapturingEmailSender::new();
    let service = hearth::identity::EmailService::new(
        sender.clone(),
        "Hearth Test".to_string(),
        None,
        EmailBranding::default(),
        String::new(),
        None,
    )
    .expect("EmailService::new");
    let now = now_unix_ts();

    let nonce = harness
        .identity()
        .issue_email_otp(
            &realm,
            "race@example.com",
            EMAIL_HMAC_KEY,
            &service,
            None,
            now,
        )
        .expect("issue_email_otp");
    let code = sender.last_otp_code().expect("OTP sent");

    let engine = harness.identity_arc();
    let successes = count_concurrent_successes(&engine, move |e| {
        e.verify_email_otp(
            &realm,
            &nonce,
            "race@example.com",
            &code,
            EMAIL_HMAC_KEY,
            now,
        )
    })
    .await;

    assert_eq!(
        successes, 1,
        "one email OTP must be redeemable exactly once, got {successes} successes"
    );
}
