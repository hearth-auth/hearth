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
    build_app_full().0
}

/// Like [`build_app`] but also returns the shared identity engine and realm id
/// so a test can register additional SPs (with known certs) against the same
/// storage the router reads.
fn build_app_full() -> (axum::Router, Arc<dyn IdentityEngine>, hearth::core::RealmId) {
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

    // An SP with an SLO URL registered — the IdP-side SLO endpoint mints a
    // realm-key-signed LogoutResponse for this SP, so it must authenticate
    // the inbound LogoutRequest (audit 2026-08-28 §4.10#2).
    identity
        .register_saml_sp(
            realm.id(),
            &SamlServiceProvider {
                sp_key: "logout-sp".to_string(),
                entity_id: "https://sp.example".to_string(),
                acs_url: "https://sp.example/acs".to_string(),
                slo_url: Some("https://sp.example/slo".to_string()),
                sp_certificate_pem: None,
                sign_assertions: true,
                sign_responses: true,
                want_authn_requests_signed: false,
                nameid_format: SamlNameIdFormat::EmailAddress,
                attribute_map: BTreeMap::new(),
            },
        )
        .expect("register slo sp");

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

    (
        web::router(state),
        Arc::clone(&identity),
        realm.id().clone(),
    )
}

/// Encodes a DER certificate as PEM (mirrors the helper in `tests/saml.rs`).
fn cert_der_to_pem(der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let b64 = B64.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is valid utf8"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
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

/// An unsigned but well-formed SAML `LogoutRequest` from `https://sp.example`,
/// base64-encoded for the HTTP-POST binding.
fn unsigned_logout_request_b64() -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    B64.encode(
        br#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lo1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="https://hearth.example/ui/realms/demo/saml/slo-idp"><saml:Issuer>https://sp.example</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">victim@sp.example</saml:NameID></samlp:LogoutRequest>"#,
    )
}

/// §4.10#2 (audit 2026-08-28): the IdP-side SLO endpoint is an unauthenticated
/// realm-key signing oracle. An anonymous caller posts a `LogoutRequest` for a
/// registered SP and gets back a realm-signed `LogoutResponse`, because the
/// inbound request's signature is never verified. The endpoint MUST refuse to
/// sign for an unauthenticated (unsigned / unverifiable) LogoutRequest.
#[test]
fn idp_slo_post_unsigned_request_is_not_a_signing_oracle() {
    let app = build_app();
    let form = format!(
        "SAMLRequest={}",
        urlencoding_lite(&unsigned_logout_request_b64())
    );
    let resp = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/ui/realms/demo/saml/slo-idp")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form))
            .unwrap(),
    );
    let status = resp.status();
    let body = body_string(resp);
    assert!(
        !body.contains("SAMLResponse"),
        "no realm-signed SAMLResponse may be minted for an unauthenticated \
         LogoutRequest (§4.10#2); got status {status}, body: {body}"
    );
    assert!(
        status == axum::http::StatusCode::FORBIDDEN
            || status == axum::http::StatusCode::BAD_REQUEST,
        "an unsigned LogoutRequest must be refused (403/400), got {status}"
    );
}

/// A LogoutRequest signed by the SP's registered certificate must still be
/// honored — the §4.10#2 fix must authenticate the request, not refuse all of
/// them. Proves the gate is a real signature check, not a blanket denial.
#[test]
fn idp_slo_post_signed_request_is_honored() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use hearth::core::Timestamp;
    use hearth::identity::federation::saml::{
        build_logout_request_xml, sign_element, BuildLogoutRequestParams, SamlNameIdFormat,
        SamlServiceProvider,
    };
    use hearth::identity::tokens::RsaSigningKey;

    let (app, identity, realm_id) = build_app_full();

    // SP keypair; register the SP with its cert so Hearth can authenticate it.
    let sp_key = RsaSigningKey::generate("test-sp", 365).expect("sp key");
    let sp_cert_pem = cert_der_to_pem(sp_key.cert_der());
    identity
        .register_saml_sp(
            &realm_id,
            &SamlServiceProvider {
                sp_key: "signed-sp".to_string(),
                entity_id: "https://signed-sp.example".to_string(),
                acs_url: "https://signed-sp.example/acs".to_string(),
                slo_url: Some("https://signed-sp.example/slo".to_string()),
                sp_certificate_pem: Some(sp_cert_pem),
                sign_assertions: true,
                sign_responses: true,
                want_authn_requests_signed: true,
                nameid_format: SamlNameIdFormat::EmailAddress,
                attribute_map: BTreeMap::new(),
            },
        )
        .expect("register signed sp");

    let req_xml = build_logout_request_xml(&BuildLogoutRequestParams {
        id: "_lo_signed_1",
        destination: "https://hearth.example/ui/realms/demo/saml/slo-idp",
        issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
        issuer: "https://signed-sp.example",
        name_id: "victim@signed-sp.example",
        name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: None,
    });
    let signed = sign_element(req_xml.as_bytes(), "_lo_signed_1", &sp_key).expect("sign request");
    let form = format!("SAMLRequest={}", urlencoding_lite(&B64.encode(&signed)));

    let resp = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/ui/realms/demo/saml/slo-idp")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form))
            .unwrap(),
    );
    let status = resp.status();
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "a signature-verified LogoutRequest must be honored, got {status}"
    );
    let body = body_string(resp);
    assert!(
        body.contains("SAMLResponse"),
        "a signature-verified LogoutRequest must receive a signed SAMLResponse"
    );
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

// ============================================================================
// §4.10#4 — `want_authn_requests_signed` must not be a silent no-op.
//
// The flag parsed, reached the SP record, and changed nothing: an SP that
// asked Hearth to require signed `<AuthnRequest>`s got the same unverified
// signing oracle as an SP that did not. These tests pin the enforcement in
// both directions — an unsigned request is refused, a signed one is honored.
// ============================================================================

/// Seeds an active user and returns a cookie header that authenticates it.
fn authenticated_cookie(
    identity: &dyn IdentityEngine,
    realm_id: &hearth::core::RealmId,
    email: &str,
) -> String {
    use hearth::identity::{CreateUserRequest, SessionContext, UpdateUserRequest, UserStatus};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let user = identity
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "SSO User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    identity
        .update_user(
            realm_id,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate user");
    let session = identity
        .create_session(realm_id, user.id(), &SessionContext::default())
        .expect("create session");

    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("hmac key");
    mac.update(session.id().as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}",
        session.id().as_uuid(),
        realm_id.as_uuid(),
        tag,
    )
}

/// Registers an SP that demands signed AuthnRequests, with `cert_pem` as the
/// registered verification certificate.
fn register_signing_sp(
    identity: &dyn IdentityEngine,
    realm_id: &hearth::core::RealmId,
    sp_key: &str,
    entity_id: &str,
    cert_pem: Option<String>,
) {
    identity
        .register_saml_sp(
            realm_id,
            &SamlServiceProvider {
                sp_key: sp_key.to_string(),
                entity_id: entity_id.to_string(),
                acs_url: format!("{entity_id}/acs"),
                slo_url: None,
                sp_certificate_pem: cert_pem,
                sign_assertions: true,
                sign_responses: true,
                want_authn_requests_signed: true,
                nameid_format: SamlNameIdFormat::EmailAddress,
                attribute_map: BTreeMap::new(),
            },
        )
        .expect("register sp");
}

fn authn_request_xml(id: &str, issuer: &str) -> String {
    use hearth::core::Timestamp;
    use hearth::identity::federation::saml::{build_authn_request_xml, BuildAuthnRequestParams};
    build_authn_request_xml(&BuildAuthnRequestParams {
        id,
        destination: "https://hearth.example/ui/realms/demo/saml/sso",
        issuer,
        acs_url: &format!("{issuer}/acs"),
        issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
        nameid_format: None,
        force_authn: false,
    })
}

fn post_sso(app: &axum::Router, cookie: &str, saml_request_b64: &str) -> (u16, String) {
    let form = format!("SAMLRequest={}", urlencoding_lite(saml_request_b64));
    let resp = send(
        app,
        Request::builder()
            .method("POST")
            .uri("/ui/realms/demo/saml/sso")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", cookie)
            .body(Body::from(form))
            .unwrap(),
    );
    let status = resp.status().as_u16();
    (status, body_string(resp))
}

/// An SP with `want_authn_requests_signed: true` must not receive an
/// assertion for an *unsigned* AuthnRequest.
#[test]
fn idp_sso_refuses_unsigned_request_when_sp_wants_signed() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use hearth::identity::tokens::RsaSigningKey;

    let (app, identity, realm_id) = build_app_full();
    let sp_key = RsaSigningKey::generate("wants-signed-sp", 365).expect("sp key");
    register_signing_sp(
        identity.as_ref(),
        &realm_id,
        "wants-signed",
        "https://wants-signed.example",
        Some(cert_der_to_pem(sp_key.cert_der())),
    );
    let cookie = authenticated_cookie(identity.as_ref(), &realm_id, "sso-a@demo.test");

    let xml = authn_request_xml("_ar_unsigned", "https://wants-signed.example");
    let (status, body) = post_sso(&app, &cookie, &B64.encode(xml.as_bytes()));

    assert!(
        !body.contains("SAMLResponse"),
        "an unsigned AuthnRequest must not mint an assertion for an SP that \
         requires signing (§4.10#4); got status {status}, body: {body}"
    );
    assert_eq!(
        status, 403,
        "an unsigned AuthnRequest must be refused with 403, got {status}"
    );
}

/// The same SP, sending a *signed* AuthnRequest, must still be served —
/// the gate is a signature check, not a blanket denial.
#[test]
fn idp_sso_honors_signed_request_when_sp_wants_signed() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use hearth::identity::federation::saml::sign_element;
    use hearth::identity::tokens::RsaSigningKey;

    let (app, identity, realm_id) = build_app_full();
    let sp_key = RsaSigningKey::generate("wants-signed-sp", 365).expect("sp key");
    register_signing_sp(
        identity.as_ref(),
        &realm_id,
        "wants-signed",
        "https://wants-signed.example",
        Some(cert_der_to_pem(sp_key.cert_der())),
    );
    let cookie = authenticated_cookie(identity.as_ref(), &realm_id, "sso-b@demo.test");

    let xml = authn_request_xml("_ar_signed", "https://wants-signed.example");
    let signed = sign_element(xml.as_bytes(), "_ar_signed", &sp_key).expect("sign request");
    let (status, body) = post_sso(&app, &cookie, &B64.encode(&signed));

    assert_eq!(
        status, 200,
        "a signature-verified AuthnRequest must be honored, got {status}: {body}"
    );
    assert!(
        body.contains("SAMLResponse"),
        "a signature-verified AuthnRequest must receive a signed SAMLResponse"
    );
}

/// `want_authn_requests_signed: true` with no registered certificate has
/// nothing to verify against. It must fail closed, not fall through to the
/// unverified path.
#[test]
fn idp_sso_fails_closed_when_sp_wants_signed_without_certificate() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    let (app, identity, realm_id) = build_app_full();
    register_signing_sp(
        identity.as_ref(),
        &realm_id,
        "no-cert",
        "https://no-cert.example",
        None,
    );
    let cookie = authenticated_cookie(identity.as_ref(), &realm_id, "sso-c@demo.test");

    let xml = authn_request_xml("_ar_nocert", "https://no-cert.example");
    let (status, body) = post_sso(&app, &cookie, &B64.encode(xml.as_bytes()));

    assert!(
        !body.contains("SAMLResponse"),
        "an SP that requires signing but registered no certificate must not \
         receive an assertion; got status {status}, body: {body}"
    );
    assert_eq!(status, 403, "expected 403, got {status}");
}

/// An SP that leaves the flag at its `false` default keeps working — the
/// enforcement must be scoped to the SPs that asked for it.
#[test]
fn idp_sso_still_serves_sp_that_does_not_want_signed_requests() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    let (app, identity, realm_id) = build_app_full();
    let cookie = authenticated_cookie(identity.as_ref(), &realm_id, "sso-d@demo.test");

    // `crm` is registered by `build_app_full` with the flag left false.
    let xml = authn_request_xml("_ar_plain", "https://crm.example");
    let (status, body) = post_sso(&app, &cookie, &B64.encode(xml.as_bytes()));

    assert_eq!(
        status, 200,
        "an SP with want_authn_requests_signed: false must still be served, got {status}: {body}"
    );
    assert!(body.contains("SAMLResponse"));
}

/// The IdP metadata must tell SPs what the server actually enforces. With a
/// realm SP requiring signed AuthnRequests, `WantAuthnRequestsSigned` must
/// read `true` — otherwise an SP configures itself from metadata, does not
/// sign, and is refused.
#[test]
fn idp_metadata_advertises_want_authn_requests_signed() {
    let (app, identity, realm_id) = build_app_full();

    let resp = send(
        &app,
        Request::builder()
            .uri("/ui/realms/demo/saml/metadata")
            .body(Body::empty())
            .unwrap(),
    );
    let body = body_string(resp);
    assert!(
        body.contains(r#"WantAuthnRequestsSigned="false""#),
        "with no SP requiring signing, metadata must advertise false: {body}"
    );

    register_signing_sp(
        identity.as_ref(),
        &realm_id,
        "wants-signed",
        "https://wants-signed.example",
        Some("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".to_string()),
    );

    let resp = send(
        &app,
        Request::builder()
            .uri("/ui/realms/demo/saml/metadata")
            .body(Body::empty())
            .unwrap(),
    );
    let body = body_string(resp);
    assert!(
        body.contains(r#"WantAuthnRequestsSigned="true""#),
        "once an SP requires signed AuthnRequests the metadata must say so: {body}"
    );
}

// ============================================================================
// 19.5 (audit 2026-08-28 §4.10#6, §4.22#4) — the SP assertion consumer must
// create a session.
//
// It validated the assertion, wrote a `saml_login_completed` audit event and
// then 302'd the browser to `return_to` with no cookie and no user. Every
// downstream page treated the caller as anonymous, while the audit log said a
// login had completed.
//
// 19.6 (§4.10#7) — and the SP entity ID / ACS URL those assertions are
// validated against must never come from `X-Forwarded-Host`.
// ============================================================================

/// Registers a SAML-kind IdP connector whose `client_secret` carries the IdP's
/// signing certificate (the shape `sp_acs` reads).
fn register_saml_idp(
    identity: &dyn IdentityEngine,
    realm_id: &hearth::core::RealmId,
    name: &str,
    entity_id: &str,
    cert_pem: String,
) -> hearth::core::IdpId {
    use hearth::identity::federation::{FederationSecret, IdpConfig, IdpKind};
    let now = SystemClock.now();
    let id = hearth::core::IdpId::generate();
    let mut claim_mappings = BTreeMap::new();
    claim_mappings.insert("email".to_string(), "NameID".to_string());
    identity
        .register_idp(&IdpConfig {
            id: id.clone(),
            realm_id: realm_id.clone(),
            name: name.to_string(),
            kind: IdpKind::Saml,
            display_name: "Corp SAML".to_string(),
            issuer: entity_id.to_string(),
            authorization_endpoint: format!("{entity_id}/sso"),
            token_endpoint: String::new(),
            userinfo_endpoint: None,
            jwks_uri: None,
            scopes: Vec::new(),
            client_id: String::new(),
            client_secret: FederationSecret::new(cert_pem),
            claim_mappings,
            leeway_seconds: 60,
            want_assertions_signed: false,
            apple: None,
            created_at: now,
            updated_at: now,
        })
        .expect("register saml idp");
    id
}

/// Builds, signs and base64-encodes a `<Response>` for the ACS.
fn signed_saml_response_b64(
    key: &hearth::identity::tokens::RsaSigningKey,
    request_id: &str,
    acs_url: &str,
    sp_entity_id: &str,
    idp_entity_id: &str,
    email: &str,
) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use hearth::identity::federation::saml::{build_response_xml, sign_element, ResponseBuilder};

    let now = SystemClock.now();
    let attrs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let xml = build_response_xml(&ResponseBuilder {
        response_id: "_resp_19_5",
        in_response_to: Some(request_id),
        issue_instant: now,
        destination: acs_url,
        issuer: idp_entity_id,
        audience: sp_entity_id,
        assertion_id: "_assert_19_5",
        subject_name_id: email,
        subject_name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: "sess-19-5",
        not_before: hearth::core::Timestamp::from_micros(now.as_micros() - 60_000_000),
        not_on_or_after: hearth::core::Timestamp::from_micros(now.as_micros() + 600_000_000),
        attributes: &attrs,
    });
    let signed = sign_element(xml.as_bytes(), "_resp_19_5", key).expect("sign response");
    B64.encode(signed)
}

/// Seeds the in-flight state bag the ACS consumes as `RelayState`.
fn seed_saml_state(
    identity: &dyn IdentityEngine,
    realm_id: &hearth::core::RealmId,
    idp_id: &hearth::core::IdpId,
    token: &str,
    request_id: &str,
) {
    use hearth::identity::federation::saml::SamlStateBag;
    identity
        .put_saml_state(&SamlStateBag {
            token: token.to_string(),
            request_id: request_id.to_string(),
            realm_id: realm_id.clone(),
            idp_id: idp_id.clone(),
            return_to: Some("/ui/account".to_string()),
            created_at: SystemClock.now(),
        })
        .expect("put saml state");
}

fn post_acs(
    app: &axum::Router,
    saml_response_b64: &str,
    relay_state: &str,
    extra_headers: &[(&str, &str)],
) -> axum::http::Response<Body> {
    let body = format!(
        "SAMLResponse={}&RelayState={}",
        urlencoding_lite(saml_response_b64),
        urlencoding_lite(relay_state)
    );
    let mut builder = Request::builder()
        .method("POST")
        .uri("/ui/realms/demo/federation/saml/acs")
        .header("content-type", "application/x-www-form-urlencoded");
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    send(app, builder.body(Body::from(body)).unwrap())
}

/// 19.5: a valid assertion must produce a Hearth session — a `Set-Cookie`
/// carrying the session cookie — and must JIT-provision the asserted user.
#[test]
fn sp_acs_valid_assertion_creates_a_session() {
    let (app, identity, realm_id) = build_app_full();
    let idp_key = hearth::identity::tokens::RsaSigningKey::generate("corp-idp", 365).expect("key");
    let idp_id = register_saml_idp(
        identity.as_ref(),
        &realm_id,
        "corp",
        "https://corp-idp.example",
        cert_der_to_pem(idp_key.cert_der()),
    );
    seed_saml_state(
        identity.as_ref(),
        &realm_id,
        &idp_id,
        "relay-19-5",
        "_req_19_5",
    );

    // The router test client sends no Host header, so the SP origin is the
    // loopback default.
    let sp_entity_id = "http://localhost:8420/ui/realms/demo";
    let acs_url = format!("{sp_entity_id}/federation/saml/acs");
    let b64 = signed_saml_response_b64(
        &idp_key,
        "_req_19_5",
        &acs_url,
        sp_entity_id,
        "https://corp-idp.example",
        "saml-user@corp.example",
    );

    let resp = post_acs(&app, &b64, "relay-19-5", &[]);
    let status = resp.status().as_u16();
    let cookies: Vec<String> = resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .collect();

    assert_eq!(
        status, 303,
        "a validated assertion must redirect the browser"
    );
    assert!(
        cookies.iter().any(|c| c.starts_with("hearth_ui_session=")),
        "the SP assertion consumer must issue a Hearth session cookie; got {cookies:?}"
    );
    assert!(
        identity
            .get_user_by_email(&realm_id, "saml-user@corp.example")
            .expect("lookup")
            .is_some(),
        "the asserted subject must be provisioned as a real user"
    );
}

/// 19.6: `X-Forwarded-Host` must not steer the SP entity ID / ACS URL the
/// assertion is validated against. An assertion minted for the attacker's
/// origin must be refused even when the attacker sets the header to match.
#[test]
fn sp_acs_ignores_x_forwarded_host_when_choosing_the_audience() {
    let (app, identity, realm_id) = build_app_full();
    let idp_key = hearth::identity::tokens::RsaSigningKey::generate("corp-idp", 365).expect("key");
    let idp_id = register_saml_idp(
        identity.as_ref(),
        &realm_id,
        "corp",
        "https://corp-idp.example",
        cert_der_to_pem(idp_key.cert_der()),
    );
    seed_saml_state(
        identity.as_ref(),
        &realm_id,
        &idp_id,
        "relay-19-6",
        "_req_19_6",
    );

    // Assertion minted for an origin the attacker chose via X-Forwarded-Host.
    let evil_entity_id = "https://evil.attacker.example/ui/realms/demo";
    let acs_url = format!("{evil_entity_id}/federation/saml/acs");
    let b64 = signed_saml_response_b64(
        &idp_key,
        "_req_19_6",
        &acs_url,
        evil_entity_id,
        "https://corp-idp.example",
        "victim@corp.example",
    );

    let resp = post_acs(
        &app,
        &b64,
        "relay-19-6",
        &[
            ("x-forwarded-host", "evil.attacker.example"),
            ("x-forwarded-proto", "https"),
        ],
    );
    assert_eq!(
        resp.status().as_u16(),
        400,
        "an assertion bound to an X-Forwarded-Host origin must be rejected"
    );
    assert!(
        identity
            .get_user_by_email(&realm_id, "victim@corp.example")
            .expect("lookup")
            .is_none(),
        "a rejected assertion must not provision a user"
    );
}
