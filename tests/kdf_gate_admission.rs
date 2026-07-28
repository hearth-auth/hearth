//! Regression test for HEA-1891 / HEA-1889 Finding 3.
//!
//! R1 (HEA-1887) introduced a bounded KDF admission gate but wired it to only
//! the three login handlers. Every *other* Argon2id caller — self-service
//! registration, password-reset confirm, account change-password, MFA step-up,
//! and the REST `create_user` paths — stayed ungated, so a flood on the
//! unauthenticated `/ui/register` (or `/ui/reset-password`) endpoint could
//! independently oversubscribe the blocking pool and re-introduce the
//! `offered × 19 MiB` memory blowup the gate exists to prevent.
//!
//! This test pins the fix: with the shared process-global gate saturated,
//! a registration and a reset-confirm submission are **shed** with
//! `503 + Retry-After` — proving those paths now share the one permit pool with
//! login. It also proves the shed is gate-specific: once the permit frees, the
//! same registration submission is no longer a 503.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use hearth::core::{Clock, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    KdfGateConfig, RealmConfig, RegistrationPolicy,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [9u8; 32];

fn null_email_service() -> Arc<EmailService> {
    Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    )
}

fn build_rig() -> axum::Router {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    identity
        .create_realm(&CreateRealmRequest {
            name: "solo".to_string(),
            config: Some(RealmConfig {
                registration_policy: Some(RegistrationPolicy::Open),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        None,
    )
    .with_dev_mode(true);
    web::router(state)
}

async fn post_form(app: &axum::Router, path: &str, body: &str) -> (StatusCode, HeaderMap) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .expect("build POST request"),
        )
        .await
        .expect("send request");
    (resp.status(), resp.headers().clone())
}

/// Saturating the shared KDF gate sheds registration and reset-confirm
/// submissions with `503 + Retry-After`, and the shed lifts once the permit
/// frees — proving both paths route through the same admission bound as login.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_and_reset_are_shed_when_kdf_gate_is_saturated() {
    // Install a 1-permit gate BEFORE anything touches `gate()`. First call wins
    // the process-global OnceLock; nextest isolates this test in its own process
    // so the tiny bound is deterministic.
    let installed = hearth::identity::init_gate(KdfGateConfig {
        max_in_flight: 1,
        max_queue_wait: Duration::from_millis(40),
        retry_after: Duration::from_secs(2),
    });
    assert!(
        installed,
        "init_gate must win the OnceLock — no earlier gate() call in this process"
    );

    let app = build_rig();

    // Hold the sole permit for the duration of the probes. The signal fires from
    // *inside* the gated closure, i.e. after the permit is already acquired, so
    // once we receive it the gate is provably saturated.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let holder = tokio::spawn(async move {
        let _ = hearth::identity::gate()
            .run(move || {
                let _ = tx.send(());
                std::thread::sleep(Duration::from_millis(1500));
            })
            .await;
    });
    rx.await.expect("holder acquired the only permit");

    // Registration submission (unauthenticated, the priority hole) must shed.
    let reg_body =
        "email=flood@example.test&password=correcthorsebattery&password_confirm=correcthorsebattery";
    let (reg_status, reg_headers) = post_form(&app, "/ui/register", reg_body).await;
    assert_eq!(
        reg_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "registration must be shed by the saturated KDF gate, not run ungated"
    );
    assert!(
        reg_headers.contains_key(axum::http::header::RETRY_AFTER),
        "shed registration must carry a Retry-After header"
    );

    // Reset-confirm submission must also shed through the same gate.
    let reset_body =
        "token=whatever-token&password=correcthorsebattery&password_confirm=correcthorsebattery";
    let (reset_status, _reset_headers) = post_form(&app, "/ui/reset-password", reset_body).await;
    assert_eq!(
        reset_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "reset-confirm must be shed by the saturated KDF gate"
    );

    // Release the permit and confirm the shed was gate-specific: the *same*
    // registration submission is no longer a 503 once capacity is available.
    holder.await.expect("holder task joins");
    let (reg_status_free, _) = post_form(&app, "/ui/register", reg_body).await;
    assert_ne!(
        reg_status_free,
        StatusCode::SERVICE_UNAVAILABLE,
        "with a free permit the registration path must not 503 — the shed came from the gate, \
         not an unrelated failure"
    );
}
