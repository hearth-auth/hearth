#![allow(clippy::unwrap_used)]
//! HTTP-level regression tests for SAML web-handler hardening (HEA-1751).
//!
//! S1: the IdP-side SSO endpoints (`/saml/sso`, `/saml/sso/init`) mint
//! signed assertions and are therefore *signing oracles*. They MUST reject
//! unauthenticated callers — an anonymous request must never receive a
//! signed `SAMLResponse`. These tests boot the real web router and confirm
//! that, with no session cookie, the endpoints redirect to login rather than
//! emitting an assertion.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::Request;
use hearth::audit::AuditEngine;
use hearth::core::{Clock, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::federation::saml::{SamlNameIdFormat, SamlServiceProvider};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    RealmConfig,
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

fn build_app() -> axum::Router {
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

    // Register a SAML SP so `/saml/sso/init` would have a valid target *if*
    // the caller were authenticated — proving the rejection is due to the
    // auth gate, not a missing SP.
    identity
        .register_saml_sp(
            realm.id(),
            &SamlServiceProvider {
                sp_key: "crm".to_string(),
                entity_id: "https://crm.example".to_string(),
                acs_url: "https://crm.example/acs".to_string(),
                slo_url: None,
                sp_certificate_pem: None,
                sign_assertions: true,
                sign_responses: true,
                want_authn_requests_signed: false,
                nameid_format: SamlNameIdFormat::EmailAddress,
                attribute_map: BTreeMap::new(),
            },
        )
        .expect("register sp");

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
    .with_dev_mode(true);

    web::router(state)
}

fn send(app: &axum::Router, req: Request<Body>) -> axum::http::Response<Body> {
    let fut = app.clone().oneshot(req);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
        .expect("router response")
}

fn body_string(resp: axum::http::Response<Body>) -> String {
    let bytes = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(to_bytes(resp.into_body(), 1024 * 1024))
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// A tiny well-formed (base64) SAML `AuthnRequest`. Its content is
/// irrelevant: the auth gate runs during extraction, before the body is
/// ever parsed, so an anonymous request never reaches the parser.
fn sample_authn_request_b64() -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    B64.encode(
        br#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://crm.example</saml:Issuer></samlp:AuthnRequest>"#,
    )
}

fn assert_redirect_to_login(resp: axum::http::Response<Body>) {
    let status = resp.status();
    assert!(
        status.is_redirection(),
        "unauthenticated SSO must redirect, got {status}"
    );
    let location = resp
        .headers()
        .get("location")
        .expect("redirect location")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        location.contains("/login"),
        "expected redirect to login, got {location}"
    );
    // Crucially: no signed assertion was minted.
    let body = body_string(resp);
    assert!(
        !body.contains("SAMLResponse"),
        "no signed SAMLResponse may be emitted to an anonymous caller"
    );
}

#[test]
fn idp_sso_get_unauthenticated_redirects_to_login() {
    let app = build_app();
    let resp = send(
        &app,
        Request::builder()
            .uri(format!(
                "/ui/realms/demo/saml/sso?SAMLRequest={}",
                urlencoding_lite(&sample_authn_request_b64())
            ))
            .body(Body::empty())
            .unwrap(),
    );
    assert_redirect_to_login(resp);
}

#[test]
fn idp_sso_post_unauthenticated_redirects_to_login() {
    let app = build_app();
    let form = format!(
        "SAMLRequest={}",
        urlencoding_lite(&sample_authn_request_b64())
    );
    let resp = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/ui/realms/demo/saml/sso")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form))
            .unwrap(),
    );
    assert_redirect_to_login(resp);
}

#[test]
fn idp_sso_init_unauthenticated_redirects_to_login() {
    let app = build_app();
    let resp = send(
        &app,
        Request::builder()
            .uri("/ui/realms/demo/saml/sso/init?sp=crm")
            .body(Body::empty())
            .unwrap(),
    );
    assert_redirect_to_login(resp);
}

/// Minimal percent-encoding for the base64 alphabet's `+`, `/`, and `=`.
fn urlencoding_lite(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '+' => out.push_str("%2B"),
            '/' => out.push_str("%2F"),
            '=' => out.push_str("%3D"),
            other => out.push(other),
        }
    }
    out
}
