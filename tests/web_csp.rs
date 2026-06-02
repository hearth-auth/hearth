//! CSP hardening acceptance tests (HEA-630).
//!
//! Verifies that the Content-Security-Policy header on `/ui/**` routes:
//! - contains no `'unsafe-inline'`
//! - contains no third-party origins (cdn.jsdelivr.net, fonts.googleapis.com, etc.)
//! - restricts `base-uri` to `'self'`
//!
//! Also verifies that the self-hosted assets (admin.js, components.js, fonts) are served
//! with the correct Content-Type, and that alpine.min.js and hyperscript.min.js are no
//! longer served (HEA-850, HEA-1049).

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::audit::EmbeddedAuditEngine;
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt;

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

fn make_web_state() -> WebState {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::rbac::RbacEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity"),
    ) as Arc<dyn hearth::identity::IdentityEngine>;
    identity
        .create_realm(&CreateRealmRequest {
            name: "default".to_string(),
            config: None,
        })
        .expect("seed realm");
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        null_email_service(),
        data_dir,
    ));
    WebState::new(
        identity,
        rbac,
        audit,
        onboarding,
        CookieSecret::random(),
        None,
    )
}

// ---------------------------------------------------------------------------
// CSP header assertions
// ---------------------------------------------------------------------------

/// Fetches the CSP header value from the given URI.
async fn get_csp(state: WebState, uri: &str) -> String {
    let app = web::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    resp.headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn csp_script_src_no_unsafe_inline_on_login() {
    let csp = get_csp(make_web_state(), "/ui/login").await;
    assert!(!csp.is_empty(), "CSP header must be present");
    // Alpine removed (HEA-850): neither unsafe-eval nor unsafe-inline should appear.
    assert!(
        !csp.contains("'unsafe-eval'"),
        "CSP must not allow unsafe-eval: {csp}"
    );
    assert!(
        !csp.contains("'unsafe-inline'"),
        "CSP must not allow unsafe-inline: {csp}"
    );
}

#[tokio::test]
async fn csp_no_third_party_origins() {
    let csp = get_csp(make_web_state(), "/ui/login").await;
    assert!(
        !csp.contains("cdn.jsdelivr.net"),
        "CSP must not reference cdn.jsdelivr.net: {csp}"
    );
    assert!(
        !csp.contains("fonts.googleapis.com"),
        "CSP must not reference fonts.googleapis.com: {csp}"
    );
    assert!(
        !csp.contains("fonts.gstatic.com"),
        "CSP must not reference fonts.gstatic.com: {csp}"
    );
}

#[tokio::test]
async fn csp_base_uri_restricted() {
    let csp = get_csp(make_web_state(), "/ui/login").await;
    assert!(
        csp.contains("base-uri 'self'"),
        "CSP must restrict base-uri to self: {csp}"
    );
}

#[tokio::test]
async fn csp_frame_ancestors_none() {
    let csp = get_csp(make_web_state(), "/ui/login").await;
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP must set frame-ancestors none: {csp}"
    );
}

// ---------------------------------------------------------------------------
// Self-hosted asset serving
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alpine_js_not_served() {
    // Alpine removed in HEA-850 — the route should now 404.
    let app = web::router(make_web_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ui/static/alpine.min.js")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "alpine.min.js must return 404 after removal"
    );
}

#[tokio::test]
async fn hyperscript_js_not_served() {
    // Hyperscript removed in HEA-1049 — the route must now return 404.
    let app = web::router(make_web_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ui/static/hyperscript.min.js")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "hyperscript.min.js must return 404 after removal"
    );
}

#[tokio::test]
async fn components_js_served() {
    // components.js backs data-component attributes (HEA-1049).
    let app = web::router(make_web_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ui/static/components.js")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "components.js must be served"
    );
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/javascript; charset=utf-8"),
        "components.js content-type must be application/javascript; charset=utf-8"
    );
}

#[tokio::test]
async fn admin_js_served_from_self() {
    let app = web::router(make_web_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ui/static/admin.js")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK, "admin.js must be served");
    let body = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    assert!(!body.is_empty(), "admin.js body must not be empty");
    assert!(
        body.windows(b"SidebarManager".len())
            .any(|w| w == b"SidebarManager"),
        "admin.js must contain vanilla JS layout managers (not Alpine)"
    );
}

#[tokio::test]
async fn font_files_served_with_woff2_content_type() {
    let fonts = [
        "fonts/fraunces-latin.woff2",
        "fonts/fraunces-italic-latin.woff2",
        "fonts/manrope-latin.woff2",
        "fonts/jetbrains-mono-latin.woff2",
    ];
    for font in fonts {
        let app = web::router(make_web_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/ui/static/{font}"))
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{font} must be served with 200"
        );
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(ct, "font/woff2", "{font} must have font/woff2 content-type");
    }
}
