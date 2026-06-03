//! Adversarial + unit tests for A-26 (`/metrics` auth) and A-27
//! (tracing PII / token redaction).
//!
//! Covers (D-4 taxonomy):
//! - A-26 `/metrics` Bearer auth — unauthenticated access rejected when
//!   bearer_token configured; correct token accepted; no-token config allows.
//! - A-26 `Server:` header stripped from all responses.
//! - A-27 `Redact<T>` newtype — `Display`/`Debug` never expose inner value.

use std::sync::Arc;

use axum::http::StatusCode;
use tower::ServiceExt as _;

use hearth::audit::EmbeddedAuditEngine;
use hearth::core::SystemClock;
use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig};
use hearth::protocol::http::{router, AppState};
use hearth::protocol::redact::Redact;
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn build_state(bearer_token: Option<&str>) -> Arc<AppState> {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage_cfg = StorageConfig::dev(dir.keep());
    let engine = Arc::new(EmbeddedStorageEngine::open(storage_cfg).expect("open storage"));
    let clock = Arc::new(SystemClock) as Arc<dyn hearth::core::Clock>;
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let rbac: Arc<dyn hearth::rbac::RbacEngine> = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));
    let identity = EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
        identity_config,
        Arc::clone(&rbac),
        Arc::clone(&audit) as Arc<dyn hearth::audit::AuditEngine>,
    )
    .expect("identity engine");

    Arc::new(
        AppState::new(
            Arc::new(identity),
            rbac,
            audit as Arc<dyn hearth::audit::AuditEngine>,
        )
        .with_metrics_bearer_token(bearer_token.map(str::to_owned)),
    )
}

async fn get_metrics(app: axum::Router, auth: Option<&str>) -> axum::response::Response {
    let mut req = axum::http::Request::builder().method("GET").uri("/metrics");
    if let Some(token) = auth {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    app.oneshot(req.body(axum::body::Body::empty()).expect("build request"))
        .await
        .expect("response")
}

// ─────────────────────────────────────────────────────────────────────────────
// A-27 — Redact newtype unit tests
// ─────────────────────────────────────────────────────────────────────────────

/// Display emits `[REDACTED]` regardless of the inner value.
#[test]
fn a27_redact_display_hides_value() {
    let r = Redact("super-secret-token");
    assert_eq!(r.to_string(), "[REDACTED]", "Display must emit [REDACTED]");
}

/// Debug emits `[REDACTED]` and never exposes the inner value.
#[test]
fn a27_redact_debug_hides_value() {
    let r = Redact("super-secret-token");
    let s = format!("{r:?}");
    assert_eq!(s, "[REDACTED]", "Debug must emit [REDACTED]");
    assert!(
        !s.contains("super-secret-token"),
        "Debug must not contain the original value; got: {s}"
    );
}

/// Redact works over any type, not just strings.
#[test]
fn a27_redact_works_over_non_string() {
    let r = Redact(12345_u64);
    assert_eq!(r.to_string(), "[REDACTED]");
    assert_eq!(format!("{r:?}"), "[REDACTED]");
}

/// An email address wrapped in Redact is never logged.
#[test]
fn a27_redact_email_not_exposed() {
    let r = Redact("user@example.com");
    let display = format!("{r}");
    let debug = format!("{r:?}");
    assert!(!display.contains('@'), "email must not appear in Display");
    assert!(!debug.contains('@'), "email must not appear in Debug");
}

// ─────────────────────────────────────────────────────────────────────────────
// A-26 — /metrics Bearer auth integration tests
// ─────────────────────────────────────────────────────────────────────────────

/// Without a bearer_token config, `/metrics` is accessible with no auth.
#[tokio::test]
async fn a26_metrics_open_when_no_token_configured() {
    let state = build_state(None);
    let app = router(state);
    let resp = get_metrics(app, None).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "/metrics must be open when no bearer_token is configured"
    );
}

/// When bearer_token is configured, a request with no auth gets 401.
#[tokio::test]
async fn a26_metrics_401_without_auth() {
    let state = build_state(Some("secret-scrape-token"));
    let app = router(state);
    let resp = get_metrics(app, None).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "/metrics must return 401 when no auth and token is configured"
    );
    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        www_auth.contains("Bearer"),
        "WWW-Authenticate must indicate Bearer scheme; got: {www_auth}"
    );
}

/// Adversarial: wrong Bearer token gets 401.
#[tokio::test]
async fn a26_metrics_401_wrong_token() {
    let state = build_state(Some("correct-token"));
    let app = router(state);
    let resp = get_metrics(app, Some("wrong-token")).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "/metrics must return 401 for an incorrect token"
    );
}

/// Correct Bearer token grants access (200).
#[tokio::test]
async fn a26_metrics_200_correct_token() {
    let state = build_state(Some("correct-token"));
    let app = router(state);
    let resp = get_metrics(app, Some("correct-token")).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "/metrics must return 200 for the correct token"
    );
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/plain"),
        "Content-Type must be text/plain; got: {ct}"
    );
}

/// Adversarial: prefix-match attack — "correct-tokenEXTRA" must not pass.
#[tokio::test]
async fn a26_metrics_401_prefix_extension_attack() {
    let state = build_state(Some("correct-token"));
    let app = router(state);
    let resp = get_metrics(app, Some("correct-tokenEXTRA")).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Prefixed extension of correct token must not pass"
    );
}

/// A-26: `Server:` header must be absent on all responses (including /health).
#[tokio::test]
async fn a26_server_header_stripped() {
    let state = build_state(None);
    let app = router(state);
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/health")
                .body(axum::body::Body::empty())
                .expect("build request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("server").is_none(),
        "Server: header must be absent; headers: {:?}",
        resp.headers()
    );
}
