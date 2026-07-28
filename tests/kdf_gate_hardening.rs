//! Regression tests for HEA-1892 (SecurityAuditor review HEA-1889 F1/F2).
//!
//! R1 (HEA-1887) added a bounded KDF admission gate, but the SecurityAuditor
//! review found two abuse-resistance gaps:
//!
//! * **F1** — the allocation-free abuse fast-rejects (CSRF double-submit,
//!   cross-origin POST, per-IP rate limit) ran *inside* the gate, so a
//!   distributed sub-threshold flood of soon-to-be-rejected requests could
//!   still saturate the Argon2id admission pool. The fix hoists those rejects
//!   *before* the gate in `login_prepare`, so rejected traffic never consumes a
//!   permit.
//! * **F2** — a single process-global gate was shared by every realm login AND
//!   admin login, so one realm's flood could lock the operator out of the admin
//!   console. The fix gives admin login a separate reserved gate.
//!
//! Both properties are pinned here as black-box tests: with the shared realm
//! gate saturated to zero free permits, (F1) a bad-CSRF login is still rejected
//! with `422` — proving the CSRF check ran *before* the gate, not after — and
//! (F2) admin login is NOT shed, proving it draws from a separate pool.

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

/// Builds a single-realm rig. `dev_mode` toggles the CSRF fail-closed behaviour:
/// `false` enforces the CSRF double-submit check (needed for the F1 probe);
/// `true` bypasses it so a probe can reach the gate stage (needed for F2).
fn build_rig(dev_mode: bool) -> axum::Router {
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
    .with_dev_mode(dev_mode);
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

/// Installs a 1-permit shared gate and holds its only permit, returning the
/// holder task. Once this returns, the shared gate is provably saturated: any
/// further `gate().run(..)` must shed. The signal fires from *inside* the gated
/// closure, so receiving it proves the permit was acquired.
async fn saturate_shared_gate() -> tokio::task::JoinHandle<()> {
    let installed = hearth::identity::init_gate(KdfGateConfig {
        max_in_flight: 1,
        max_queue_wait: Duration::from_millis(40),
        retry_after: Duration::from_secs(2),
    });
    assert!(
        installed,
        "init_gate must win the OnceLock — no earlier gate() call in this process"
    );

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
    holder
}

/// F1: a bad-CSRF login submission is rejected with `422` *before* it can
/// consume a KDF permit. With the shared gate saturated, the OLD ordering
/// (CSRF check inside the gate) would have shed this request with `503`; the
/// hoisted check returns the CSRF `422` regardless of gate pressure — proof the
/// reject happened pre-gate and never touched the permit pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_csrf_login_rejected_before_consuming_a_kdf_permit() {
    // dev_mode=false → CSRF double-submit is fail-closed. No `hearth_ui_csrf`
    // cookie is sent, so the check must reject.
    let app = build_rig(false);
    let holder = saturate_shared_gate().await;

    let body = "email=victim@example.test&password=correcthorsebattery&_csrf=forged-token";
    let (status, headers) = post_form(&app, "/ui/login", body).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad-CSRF login must be rejected with 422 by the pre-gate check, NOT shed with 503 by the \
         saturated gate — the reject must not depend on (or consume) admission capacity"
    );
    assert!(
        !headers.contains_key(axum::http::header::RETRY_AFTER),
        "a pre-gate CSRF reject must not carry the gate's Retry-After shed header"
    );

    // Control: even after the permit frees, the same request is still a 422 —
    // confirming the 422 comes from CSRF, independent of gate state.
    holder.await.expect("holder task joins");
    let (status_free, _) = post_form(&app, "/ui/login", body).await;
    assert_eq!(
        status_free,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the CSRF reject is gate-independent"
    );
}

/// F2: admin login draws from a separate reserved gate. With the shared realm
/// gate saturated, a realm login is shed (`503`) but an admin login is NOT —
/// proving one realm's flood cannot lock the operator out of the admin console.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_login_survives_a_saturated_shared_realm_gate() {
    // dev_mode=true → CSRF bypassed, so both probes reach their respective
    // gate stages instead of being rejected at the CSRF check.
    let app = build_rig(true);
    let holder = saturate_shared_gate().await;

    // A realm login draws from the saturated shared gate → shed with 503.
    let realm_body = "email=nobody@example.test&password=correcthorsebattery";
    let (realm_status, realm_headers) = post_form(&app, "/ui/login", realm_body).await;
    assert_eq!(
        realm_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "realm login must be shed by the saturated shared gate"
    );
    assert!(
        realm_headers.contains_key(axum::http::header::RETRY_AFTER),
        "shed realm login must carry Retry-After"
    );

    // The admin login draws from the *separate* admin gate → NOT shed. The
    // system realm is auto-seeded at engine construction, so this reaches the
    // Argon2id verify and returns the generic 401 (no admin credential), never
    // a 503.
    let admin_body = "email=admin@hearth.test&password=correcthorsebattery";
    let (admin_status, _) = post_form(&app, "/ui/admin/login", admin_body).await;
    assert_ne!(
        admin_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "admin login must NOT be shed by a saturated tenant-realm gate — it uses the reserved \
         admin pool (HEA-1892 / F2)"
    );

    holder.await.expect("holder task joins");
}
