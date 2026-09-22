//! §4.17#2 (audit 2026-08-28): the browser login form must be rate-shaped so a
//! flood of password submissions cannot drive unbounded pre-auth Argon2id work.
//!
//! The form runs its Argon2id verify inside the shared process-global KDF
//! admission gate. This test pins that wiring: with the gate saturated (its
//! sole permit held), a `POST /ui/login` is **shed** with `503 + Retry-After`
//! rather than running an ungated hash — and the shed lifts once the permit
//! frees, proving the 503 came from the gate and not an unrelated failure.
//!
//! Red against a login handler that runs `verify_password` outside the gate.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use hearth::core::{Clock, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    KdfGateConfig, RealmConfig,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [7u8; 32];

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
            config: Some(RealmConfig::default()),
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

async fn post_login(app: &axum::Router, body: &str) -> (StatusCode, HeaderMap) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .expect("build POST request"),
        )
        .await
        .expect("send request");
    (resp.status(), resp.headers().clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_form_is_shed_when_kdf_gate_is_saturated() {
    // Install a 1-permit gate before anything touches `gate()`. First call wins
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

    // Hold the sole permit. The signal fires from inside the gated closure —
    // after the permit is acquired — so once received the gate is saturated.
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

    // A login submission (dev-mode CSRF bypass; single request so the per-IP
    // limiter, which runs pre-gate, does not trip) must be shed by the gate.
    let body = "email=victim@example.test&password=correcthorsebattery";
    let (status, headers) = post_login(&app, body).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the login form must be shed by the saturated KDF gate, not run ungated Argon2id \
         (§4.17#2)"
    );
    assert!(
        headers.contains_key(axum::http::header::RETRY_AFTER),
        "a shed login must carry a Retry-After header"
    );

    // Release the permit; the same submission must no longer 503 — proving the
    // shed came from the gate, not an unrelated failure.
    holder.await.expect("holder task joins");
    let (status_free, _) = post_login(&app, body).await;
    assert_ne!(
        status_free,
        StatusCode::SERVICE_UNAVAILABLE,
        "with a free permit the login path must not 503"
    );
}
