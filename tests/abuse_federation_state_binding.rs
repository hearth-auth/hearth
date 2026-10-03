#![allow(clippy::unwrap_used)]
//! Adversarial tests for A-48 (OAuth state↔session binding).
//!
//! D-4 taxonomy:
//! - **A-48 adversarial (HTTP)**: three attack scenarios against the
//!   `hearth_fed_bind` cookie guard — missing cookie, wrong state,
//!   garbled cookie — all must redirect to the login-error page.
//!
//! Closes: HEA-1200 §A-48.
//!
//! Origin: split out of the former `tests/abuse_a48_a49.rs` when the A-49
//! refresh-context drift scoring was removed in Hearth 3.0.0. Its removal is
//! covered by `tests/abuse_risk_and_sms_removed.rs`.

// ─────────────────────────────────────────────────────────────────────────────
// A-48 — OAuth state↔session binding (adversarial HTTP tests)
// ─────────────────────────────────────────────────────────────────────────────
//
// These tests spin up a full axum router (embedded engines + stubbed
// federation transport) and issue raw HTTP requests to exercise the
// `hearth_fed_bind` cookie guard in `callback_impl`.
//
// The guard is fail-closed: any deviation from a valid cookie → 303 to
// `/ui/login?error=federation_failed`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::audit::AuditEngine;
use hearth::core::{Clock, IdpId, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::federation::{
    compute_federation_state_mac, FederationSecret, IdpConfig, IdpKind, StubFederationTransport,
};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    RealmConfig,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

/// Server-side cookie secret used in all rig instances.
const COOKIE_SECRET: [u8; 32] = [13u8; 32];

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

struct Rig {
    app: axum::Router,
}

fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let stub = Arc::new(StubFederationTransport::new());
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
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

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "demo".to_string(),
            config: Some(RealmConfig::default()),
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let idp_id = IdpId::generate();
    identity
        .register_idp(&IdpConfig {
            id: idp_id,
            realm_id: realm_id.clone(),
            name: "upstream".to_string(),
            kind: IdpKind::Oidc,
            display_name: "Upstream".to_string(),
            issuer: "https://idp.example".to_string(),
            authorization_endpoint: "https://idp.example/auth".to_string(),
            token_endpoint: "https://idp.example/token".to_string(),
            userinfo_endpoint: None,
            jwks_uri: Some("https://idp.example/jwks".to_string()),
            scopes: vec!["openid".to_string(), "email".to_string()],
            client_id: "demo-client".to_string(),
            client_secret: FederationSecret::new("demo-secret".to_string()),
            claim_mappings: BTreeMap::new(),
            leeway_seconds: IdpConfig::default_leeway_seconds(),
            want_assertions_signed: false,
            trust_asserted_email: false,
            apple: None,
            created_at: hearth::core::Timestamp::from_micros(0),
            updated_at: hearth::core::Timestamp::from_micros(0),
        })
        .expect("register idp");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir,
    ));

    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        Arc::clone(&audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(null_email_service()),
    )
    .with_dev_mode(true)
    .with_federation_http(stub as Arc<dyn hearth::identity::federation::FederationHttpTransport>);

    Rig {
        app: web::router(state),
    }
}

fn send(app: &axum::Router, req: Request<Body>) -> axum::http::Response<Body> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(app.clone().oneshot(req))
        .expect("router response")
}

/// Helper: produce a valid `hearth_fed_bind` cookie value for the given state.
fn valid_bind_cookie(state_token: &str) -> String {
    let mac = compute_federation_state_mac(&COOKIE_SECRET, state_token);
    format!("hearth_fed_bind={mac}")
}

// ─────────────────────────────────────────────────────────────────────────────
// A-48: adversarial — missing cookie
// ─────────────────────────────────────────────────────────────────────────────

/// An attacker who can intercept or predict the `state` token but does NOT
/// control the victim's browser cannot replay the callback because the
/// `hearth_fed_bind` cookie is absent.
///
/// Expected: 303 → `/ui/login?error=federation_failed` (fail-closed).
#[test]
fn a48_callback_without_any_cookie_is_rejected() {
    let rig = build_rig();
    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/federation/callback?state=any-state&code=anycode")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "missing cookie must produce a redirect"
    );
    let location = resp
        .headers()
        .get("location")
        .expect("must have Location")
        .to_str()
        .unwrap();
    assert_eq!(
        location, "/ui/login?error=federation_failed",
        "missing cookie must redirect to federation_failed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-48: adversarial — cookie bound to a different state token
// ─────────────────────────────────────────────────────────────────────────────

/// An attacker who steals another user's valid `state` token cannot pair it
/// with their own browser's cookie, because the MAC is bound to a SPECIFIC
/// state token.  Mismatching cookie-state and URL-state must be rejected.
///
/// Expected: 303 → `/ui/login?error=federation_failed` (fail-closed).
#[test]
fn a48_callback_with_cookie_for_different_state_is_rejected() {
    let rig = build_rig();
    // Attacker's browser initiated a flow with "attacker-state".
    // Victim's flow produced "victim-state".
    // The attacker tries to replay the victim's state with their own cookie.
    let attacker_cookie = valid_bind_cookie("attacker-state");
    let resp = send(
        &rig.app,
        Request::builder()
            .header("cookie", attacker_cookie)
            .uri("/ui/realms/demo/federation/callback?state=victim-state&code=stolen-code")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(
        location, "/ui/login?error=federation_failed",
        "cross-state cookie must be rejected"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-48: adversarial — garbled / forged cookie value
// ─────────────────────────────────────────────────────────────────────────────

/// An attacker who fabricates a `hearth_fed_bind` cookie with an arbitrary
/// value (or with a MAC computed from a DIFFERENT secret) must be rejected.
///
/// Expected: 303 → `/ui/login?error=federation_failed` (fail-closed).
#[test]
fn a48_callback_with_forged_cookie_mac_is_rejected() {
    let rig = build_rig();
    // Attacker guesses or constructs an invalid MAC.
    let forged_cookie = "hearth_fed_bind=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let resp = send(
        &rig.app,
        Request::builder()
            .header("cookie", forged_cookie)
            .uri("/ui/realms/demo/federation/callback?state=some-state&code=anycode")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(
        location, "/ui/login?error=federation_failed",
        "forged MAC must be rejected"
    );
}

/// A valid MAC computed with the WRONG server secret must be rejected — the
/// server's `cookie_secret` is required.
#[test]
fn a48_callback_with_cookie_signed_by_wrong_secret_is_rejected() {
    let rig = build_rig();
    // Compute a valid-looking MAC but with a different 32-byte secret.
    let wrong_secret = [99u8; 32];
    let wrong_mac = compute_federation_state_mac(&wrong_secret, "state-token-x");
    let cookie = format!("hearth_fed_bind={wrong_mac}");
    let resp = send(
        &rig.app,
        Request::builder()
            .header("cookie", cookie)
            .uri("/ui/realms/demo/federation/callback?state=state-token-x&code=anycode")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(
        location, "/ui/login?error=federation_failed",
        "cookie signed with wrong secret must be rejected"
    );
}
