#![cfg(feature = "dev-endpoints")]
//! The dev console (`/dev`): one page that sets up the dev accounts and signs
//! a developer in with one click (`docs/dev/DEVELOPMENT.md`).
//!
//! Gates: mounted only under `--dev`, answered only for a loopback peer, and a
//! cross-site form post cannot sign the browser in.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::RealmId;
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const LOOPBACK: ([u8; 4], u16) = ([127, 0, 0, 1], 50_000);

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
}

fn build_rig(dev_mode: bool) -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
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
    ) as Arc<dyn IdentityEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;
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
    let state = WebState::new(
        Arc::clone(&identity),
        rbac,
        audit,
        onboarding,
        CookieSecret::from_bytes([7u8; 32]),
        None,
    )
    .with_dev_mode(dev_mode);
    Rig {
        app: web::router(state),
        identity,
    }
}

fn request(method: &str, uri: &str, peer: SocketAddr) -> axum::http::request::Builder {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "127.0.0.1:8420");
    builder
        .extensions_mut()
        .expect("extensions")
        .insert(ConnectInfo(peer));
    builder
}

async fn send(rig: &Rig, req: Request<Body>) -> axum::response::Response {
    rig.app.clone().oneshot(req).await.expect("oneshot")
}

async fn body_text(resp: axum::response::Response) -> String {
    String::from_utf8(
        to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("utf8")
}

/// The `name=value` pairs of every `Set-Cookie`, joined for a `Cookie` header.
fn cookies_of(resp: &axum::response::Response) -> String {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .collect::<Vec<_>>()
        .join("; ")
}

#[tokio::test]
async fn the_console_sets_up_the_dev_accounts_and_lists_them() {
    let rig = build_rig(true);
    let resp = send(
        &rig,
        request("GET", "/dev", LOOPBACK.into())
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "a page with passwords and tokens is never cached"
    );
    let body = body_text(resp).await;
    for expected in [
        "admin@hearth.test",
        "HearthTest123!",
        "admin@dev.local",
        "HearthDev123!",
        "/dev/sign-in/console",
        "/dev/sign-in/realm",
        "<svg",
    ] {
        assert!(body.contains(expected), "the page shows {expected}");
    }

    let system = RealmId::new(uuid::Uuid::nil());
    assert!(rig
        .identity
        .get_user_by_email(&system, "admin@hearth.test")
        .expect("lookup")
        .is_some());
    let realm = rig
        .identity
        .get_realm_by_name("dev-realm")
        .expect("lookup")
        .expect("dev-realm exists");
    assert!(rig
        .identity
        .get_user_by_email(realm.id(), "admin@dev.local")
        .expect("lookup")
        .is_some());

    // A second visit keeps the same accounts.
    let again = send(
        &rig,
        request("GET", "/dev", LOOPBACK.into())
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(again.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_current_codes_are_six_digits() {
    let rig = build_rig(true);
    let resp = send(
        &rig,
        request("GET", "/dev/codes", LOOPBACK.into())
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_text(resp).await).expect("json");
    for key in ["console", "realm"] {
        let code = body[key].as_str().unwrap_or_default();
        assert!(
            code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()),
            "{key} has a six-digit code"
        );
    }
    let left = body["seconds_left"].as_u64().unwrap_or_default();
    assert!((1..=30).contains(&left));
}

#[tokio::test]
async fn the_credentials_twin_has_the_bootstrap_shape() {
    // The UI test harness reads it when the accounts were set up from /dev
    // and a token-less re-bootstrap answers 401.
    let rig = build_rig(true);
    let resp = send(
        &rig,
        request("GET", "/dev/credentials", LOOPBACK.into())
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_text(resp).await).expect("json");
    for key in [
        "realm_id",
        "user_id",
        "access_token",
        "refresh_token",
        "totp_secret",
        "admin_totp_secret",
        "system_access_token",
        "system_realm_id",
    ] {
        assert!(
            body[key].as_str().is_some_and(|v| !v.is_empty()),
            "{key} is present"
        );
    }
    let realm = rig
        .identity
        .get_realm_by_name("dev-realm")
        .expect("lookup")
        .expect("dev-realm exists");
    assert_eq!(body["realm_id"], realm.id().as_uuid().to_string());

    let remote = send(
        &rig,
        request("GET", "/dev/credentials", ([10, 0, 0, 5], 50_000).into())
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(remote.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn one_click_opens_the_admin_console() {
    let rig = build_rig(true);
    let resp = send(
        &rig,
        request("POST", "/dev/sign-in/console", LOOPBACK.into())
            .header(header::ORIGIN, "http://127.0.0.1:8420")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert!(resp.status().is_redirection(), "{}", resp.status());
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/admin")
    );
    let cookies = cookies_of(&resp);
    assert!(cookies.contains("hearth_ui_session="));

    // The session counts as having proved a second factor, so the console
    // (system realm: MFA always required) opens without a code.
    let console = send(
        &rig,
        request("GET", "/ui/admin/realms", LOOPBACK.into())
            .header(header::COOKIE, &cookies)
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(console.status(), StatusCode::OK);
    assert!(body_text(console).await.contains("dev-realm"));
}

#[tokio::test]
async fn one_click_signs_in_the_realm_admin() {
    let rig = build_rig(true);
    let resp = send(
        &rig,
        request("POST", "/dev/sign-in/realm", LOOPBACK.into())
            .header(header::ORIGIN, "http://127.0.0.1:8420")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert!(resp.status().is_redirection(), "{}", resp.status());
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui")
    );
    assert!(cookies_of(&resp).contains("hearth_ui_session="));
}

#[tokio::test]
async fn a_cross_site_post_cannot_sign_in() {
    let rig = build_rig(true);
    let resp = send(
        &rig,
        request("POST", "/dev/sign-in/console", LOOPBACK.into())
            .header(header::ORIGIN, "https://evil.example")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(!cookies_of(&resp).contains("hearth_ui_session="));
}

#[tokio::test]
async fn a_remote_peer_gets_not_found() {
    let rig = build_rig(true);
    let remote: SocketAddr = ([10, 0, 0, 5], 50_000).into();
    for (method, uri) in [
        ("GET", "/dev"),
        ("GET", "/dev/codes"),
        ("POST", "/dev/sign-in/console"),
    ] {
        let resp = send(
            &rig,
            request(method, uri, remote)
                .body(Body::empty())
                .expect("req"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{method} {uri}");
    }
    assert!(
        rig.identity
            .get_realm_by_name("dev-realm")
            .expect("lookup")
            .is_none(),
        "a refused request sets nothing up"
    );
}

#[tokio::test]
async fn the_console_is_absent_without_dev_mode() {
    let rig = build_rig(false);
    let resp = send(
        &rig,
        request("GET", "/dev", LOOPBACK.into())
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let post = send(
        &rig,
        request("POST", "/dev/sign-in/console", LOOPBACK.into())
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(post.status(), StatusCode::NOT_FOUND);
}
