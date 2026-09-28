//! A recovery code is checked against up to eight Argon2id hashes, so the
//! browser MFA challenge must run that check inside the shared KDF admission
//! gate, like every other pre-session hash (GA audit 2026-09-28, L16). It ran
//! on the async worker, outside the gate: with the gate saturated, a recovery
//! code submission still paid for eight hashes.
//!
//! With the gate's only permit held, `POST /ui/mfa-challenge` with a recovery
//! code must be shed with `503 + Retry-After`; once the permit frees, the same
//! submission is no longer shed.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, KdfGateConfig, RealmConfig,
    UpdateUserRequest, UserStatus,
};
use tower::ServiceExt as _;

fn password() -> String {
    ["recovery", "gate", "horse", "staple"].join("-")
}

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

fn build_web_app(h: &common::TestHarness) -> axum::Router {
    use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
    use hearth::identity::onboarding::OnboardingService;
    use hearth::protocol::web::{self, CookieSecret, WebState};

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
    let email = Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    let onboarding = Arc::new(OnboardingService::new(
        h.identity_arc(),
        h.rbac_arc(),
        email,
        data_dir,
    ));
    let state = WebState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        onboarding,
        CookieSecret::from_bytes([3u8; 32]),
        None,
    )
    .with_dev_mode(true);
    web::router(state)
}

async fn submit_recovery_code(app: &axum::Router, pending: &str, code: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/mfa-challenge")
                .header(header::COOKIE, pending)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("code={code}")))
                .expect("build POST"),
        )
        .await
        .expect("oneshot")
        .status()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // one linear browser flow; splitting it hides the sequence
async fn recovery_codes_are_checked_inside_the_kdf_gate() {
    // First call wins the process-global OnceLock; nextest runs this test in
    // its own process, so the one-permit bound is deterministic.
    assert!(
        hearth::identity::init_gate(KdfGateConfig {
            max_in_flight: 1,
            max_queue_wait: Duration::from_millis(40),
            retry_after: Duration::from_secs(2),
        }),
        "init_gate must win the OnceLock"
    );

    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("rc-{}", uuid::Uuid::new_v4().simple()),
            config: Some(RealmConfig::default()),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("rc-{}@example.com", uuid::Uuid::new_v4().simple()),
                display_name: "Recovery".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");
    h.identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string(password()),
        )
        .expect("set password");
    h.identity()
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate");
    let enrollment = h
        .identity()
        .enroll_totp(realm.id(), user.id())
        .expect("enroll totp");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("epoch")
        .as_secs();
    h.identity()
        .verify_totp_enrollment(
            realm.id(),
            user.id(),
            &compute_totp_code(&enrollment.secret_base32, now),
        )
        .expect("verify enrollment");

    let app = build_web_app(&h);
    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/realms/{}/login", realm.name()))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "email={}&password={}",
                    user.email().replace('@', "%40"),
                    password()
                )))
                .expect("build login"),
        )
        .await
        .expect("login");
    let pending = login
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("hearth_ui_mfa_pending="))
        .and_then(|c| c.split(';').next())
        .expect("pending cookie")
        .to_string();

    // Hold the only permit; the signal fires from inside the gated closure.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let holder = tokio::spawn(async move {
        let _ = hearth::identity::gate()
            .run(move || {
                let _ = tx.send(());
                std::thread::sleep(Duration::from_millis(1500)); // AUDIT: justified-sleep: holds the only KDF permit so the test can verify shedding while it is occupied
            })
            .await;
    });
    rx.await.expect("holder acquired the only permit");

    let status = submit_recovery_code(&app, &pending, "NOT-A-REAL-RECOVERY-CODE").await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a recovery-code check must wait for a KDF permit and be shed, not hash ungated"
    );

    holder.await.expect("holder joins");
    let status_free = submit_recovery_code(&app, &pending, "NOT-A-REAL-RECOVERY-CODE").await;
    assert_eq!(
        status_free,
        StatusCode::UNAUTHORIZED,
        "with a free permit the wrong code is simply refused"
    );
}
