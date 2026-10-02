//! Route-absence assertions for removed features (scope-trim-trusted-core).
//!
//! A removed route must answer exactly like a path that never existed. The
//! check drives the *composed* tree — the API router with the browser router
//! nested under it, as `main.rs` builds it — because `TestHarness::server()`
//! mounts only the API router and would 404 every `/ui/*` path vacuously.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use hearth::audit::EmbeddedAuditEngine;
use hearth::core::SystemClock;
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig,
};
use hearth::protocol::http::{router_with, AppState};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt as _;

/// Realm seeded by [`composed_app`], so realm-scoped routes reach their
/// handler instead of failing realm lookup.
pub const SEEDED_REALM: &str = "acme";

/// Builds the composed API + browser router over fresh engines, with the
/// `default` realm and [`SEEDED_REALM`] created.
pub fn composed_app() -> axum::Router {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    // Held for the lifetime of the test process.
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    ) as Arc<dyn hearth::storage::StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity"),
    ) as Arc<dyn hearth::identity::IdentityEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn hearth::rbac::RbacEngine>;

    for name in ["default", SEEDED_REALM] {
        identity
            .create_realm(&CreateRealmRequest {
                name: name.to_string(),
                config: None,
            })
            .expect("seed realm");
    }

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
        Arc::clone(&identity),
        Arc::clone(&rbac),
        email,
        data_dir,
    ));
    let web_state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        Arc::clone(&audit),
        onboarding,
        CookieSecret::random(),
        None,
    )
    .with_dev_mode(true);
    let app_state = AppState::new(identity, rbac, audit);

    router_with(Arc::new(app_state), web::router(web_state))
}

async fn send(app: &axum::Router, method: &Method, path: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method(method.clone())
        .uri(path)
        .header("host", "localhost")
        .body(Body::empty())
        .expect("build request");
    let response = app.clone().oneshot(request).await.expect("oneshot");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body");
    let body = String::from_utf8_lossy(&bytes).replace(path, "<PATH>");
    (status, body)
}

/// Asserts that `method path` answers exactly like an unknown sibling path:
/// status `404` and the same body (with the request path normalised out).
///
/// # Panics
/// Panics when the route is still served, or when it answers differently
/// from a path that never existed.
pub async fn assert_route_absent(app: &axum::Router, method: Method, path: &str) {
    let control = match path.rsplit_once('/') {
        Some((parent, _)) => format!("{parent}/__route_absent_control__"),
        None => "/__route_absent_control__".to_string(),
    };
    let (control_status, control_body) = send(app, &method, &control).await;
    assert_eq!(
        control_status,
        StatusCode::NOT_FOUND,
        "control path {control} must be unknown"
    );
    let (status, body) = send(app, &method, path).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "{method} {path} is still served (status {status})"
    );
    assert_eq!(
        body, control_body,
        "{method} {path} answers 404 differently from an unknown path"
    );
}
