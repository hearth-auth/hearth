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
    let _ = temp.keep();

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
    .with_dev_mode(true)
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

/// M1 (HEA-1757): the CSP must pin `object-src` to `'none'` (blocks plugin/embed
/// vectors) and `form-action` to `'self'` (blocks exfiltration via attacker-set
/// form targets). Regression guard — fails against the pre-HEA-1757 directive set.
#[tokio::test]
async fn csp_object_src_and_form_action_hardened() {
    let csp = get_csp(make_web_state(), "/ui/login").await;
    assert!(
        csp.contains("object-src 'none'"),
        "CSP must set object-src 'none': {csp}"
    );
    assert!(
        csp.contains("form-action 'self'"),
        "CSP must set form-action 'self': {csp}"
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

// ---------------------------------------------------------------------------
// #820: no inline event handlers in templates
// ---------------------------------------------------------------------------

/// Every `.html` file under `dir` and its subdirectories.
fn html_files_under(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            html_files_under(&path, out);
        } else if path.extension().is_some_and(|e| e == "html") {
            out.push(path);
        }
    }
}

/// The inline event handler attributes (`onclick=`, `onsubmit=`, ...) in
/// `text`, as `line: attribute` strings.
fn inline_handlers(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let bytes = line.as_bytes();
        for i in 0..bytes.len() {
            let after_space = i == 0 || bytes[i - 1].is_ascii_whitespace();
            if !after_space || !line[i..].starts_with("on") {
                continue;
            }
            let name_len = line[i + 2..]
                .bytes()
                .take_while(u8::is_ascii_lowercase)
                .count();
            if name_len > 0 && line[i + 2 + name_len..].starts_with('=') {
                found.push(format!("{}: {}", n + 1, &line[i..i + 2 + name_len]));
            }
        }
    }
    found
}

/// The CSP (`script-src 'self'`) blocks an inline event handler, so the
/// browser never runs it. Before #820, the session revoke form had an
/// `onsubmit=` confirm and the raw config editor had an `onclick=` reset.
#[test]
fn no_template_has_an_inline_event_handler() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
    let mut files = Vec::new();
    html_files_under(&root, &mut files);
    assert!(!files.is_empty(), "templates found");
    let mut offenders = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read template");
        for hit in inline_handlers(&text) {
            offenders.push(format!("{}:{hit}", file.display()));
        }
    }
    assert_eq!(
        offenders,
        Vec::<String>::new(),
        "inline event handlers (blocked by the CSP)"
    );
}

#[test]
fn the_inline_handler_scan_finds_a_handler() {
    assert_eq!(
        inline_handlers("<form\n   onsubmit=\"x\" data-on=\"y\">"),
        vec!["2: onsubmit".to_string()]
    );
    assert_eq!(
        inline_handlers("<p>Turn it on = off</p>"),
        Vec::<String>::new()
    );
}

/// The raw config editor's reset button gets its listener from
/// `admin.js`, which calls `resetRawEditor`.
#[test]
fn the_raw_editor_reset_button_has_a_listener() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let template =
        std::fs::read_to_string(root.join("templates/ui/admin/settings/_raw_editor.html"))
            .expect("raw editor template");
    let script =
        std::fs::read_to_string(root.join("src/protocol/web/assets/admin.js")).expect("admin.js");
    assert!(
        template.contains("id=\"raw-reset-bottom\""),
        "the reset button has the id raw-reset-bottom"
    );
    assert!(
        script.contains("getElementById('raw-reset-bottom')?.addEventListener('click', () => this.resetRawEditor())"),
        "admin.js wires the reset button to resetRawEditor"
    );
}
