#![allow(clippy::unwrap_used)]
//! HTTP-level regression tests for the SAML service-provider web handlers
//! (HEA-1751 and later audits): the Assertion Consumer Service, its audit
//! trail, its audience anchoring, and IdP signing-certificate rollover.
//! Hearth no longer acts as a SAML IdP (removed in 3.0.0).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use hearth::audit::AuditEngine;
use hearth::core::{Clock, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
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
    let (app, identity, realm_id, _audit) = build_app_audited();
    (app, identity, realm_id)
}

/// Like [`build_app_full`] but also hands back the audit engine, so a test can
/// assert on what the handlers recorded (19.5).
fn build_app_audited() -> (
    axum::Router,
    Arc<dyn IdentityEngine>,
    hearth::core::RealmId,
    Arc<dyn AuditEngine>,
) {
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
        Arc::clone(&audit),
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
///
/// The connector trusts the asserted address (`trust_asserted_email`), so a
/// JIT-provisioned user is active at once; see
/// [`register_saml_idp_trusting`] for one that does not.
fn register_saml_idp(
    identity: &dyn IdentityEngine,
    realm_id: &hearth::core::RealmId,
    name: &str,
    entity_id: &str,
    cert_pem: String,
) -> hearth::core::IdpId {
    register_saml_idp_trusting(identity, realm_id, name, entity_id, cert_pem, true)
}

/// [`register_saml_idp`] with `trust_asserted_email` spelled out.
fn register_saml_idp_trusting(
    identity: &dyn IdentityEngine,
    realm_id: &hearth::core::RealmId,
    name: &str,
    entity_id: &str,
    cert_pem: String,
    trust_asserted_email: bool,
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
            trust_asserted_email,
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
        subject_name_id_format: hearth::identity::federation::saml::SamlNameIdFormat::EmailAddress
            .as_uri(),
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

/// GA audit round 3, G-3: SAML carries no `email_verified`, so a connector
/// that does not trust the asserted address (`trust_asserted_email: false`,
/// the default) provisions an account that waits for the address owner to
/// verify it — no session on an address nobody proved.
#[test]
fn sp_acs_untrusted_email_provisions_an_account_pending_verification() {
    let (app, identity, realm_id) = build_app_full();
    let idp_key = hearth::identity::tokens::RsaSigningKey::generate("corp-idp", 365).expect("key");
    let idp_id = register_saml_idp_trusting(
        identity.as_ref(),
        &realm_id,
        "corp",
        "https://corp-idp.example",
        cert_der_to_pem(idp_key.cert_der()),
        false,
    );
    seed_saml_state(identity.as_ref(), &realm_id, &idp_id, "relay-g3", "_req_g3");
    let sp_entity_id = "http://localhost:8420/ui/realms/demo";
    let acs_url = format!("{sp_entity_id}/federation/saml/acs");
    let b64 = signed_saml_response_b64(
        &idp_key,
        "_req_g3",
        &acs_url,
        sp_entity_id,
        "https://corp-idp.example",
        "unproven@corp.example",
    );

    let resp = post_acs(&app, &b64, "relay-g3", &[]);
    let cookies: Vec<String> = resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        !cookies.iter().any(|c| c.starts_with("hearth_ui_session=")),
        "no session on an unproven address; got {cookies:?}"
    );
    let user = identity
        .get_user_by_email(&realm_id, "unproven@corp.example")
        .expect("lookup")
        .expect("the asserted subject is provisioned");
    assert_eq!(
        user.status(),
        hearth::identity::UserStatus::PendingVerification
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

/// Counts the realm's audit events with the given action.
fn count_audit(
    audit: &dyn AuditEngine,
    realm_id: &hearth::core::RealmId,
    action: hearth::audit::AuditAction,
) -> usize {
    let mut q = hearth::audit::AuditQuery::for_realm(realm_id.clone());
    q.action = Some(action);
    audit.query(&q).expect("audit query").len()
}

/// 19.5 (§4.22#4): the audit log must not claim a login that did not happen.
///
/// The ACS wrote `saml_login_completed` unconditionally on the accept path,
/// while issuing no cookie and authenticating nobody. The event is now gated on
/// a session cookie actually being set, so a *rejected* assertion must leave the
/// completed count untouched and record a failure instead.
#[test]
fn sp_acs_audits_completed_only_for_a_login_that_happened() {
    use hearth::audit::AuditAction;

    let (app, identity, realm_id, audit) = build_app_audited();
    let idp_key = hearth::identity::tokens::RsaSigningKey::generate("corp-idp", 365).expect("key");
    let idp_id = register_saml_idp(
        identity.as_ref(),
        &realm_id,
        "corp",
        "https://corp-idp.example",
        cert_der_to_pem(idp_key.cert_der()),
    );

    let sp_entity_id = "http://localhost:8420/ui/realms/demo";
    let acs_url = format!("{sp_entity_id}/federation/saml/acs");

    // A rejected assertion first: minted for another SP's audience, so
    // validation fails before anything downstream runs.
    seed_saml_state(
        identity.as_ref(),
        &realm_id,
        &idp_id,
        "relay-bad",
        "_req_bad",
    );
    let bad = signed_saml_response_b64(
        &idp_key,
        "_req_bad",
        &acs_url,
        "https://other-sp.example/ui/realms/demo",
        "https://corp-idp.example",
        "nobody@corp.example",
    );
    let resp = post_acs(&app, &bad, "relay-bad", &[]);
    assert_eq!(
        resp.status().as_u16(),
        400,
        "an assertion minted for another SP must be refused"
    );
    assert_eq!(
        count_audit(audit.as_ref(), &realm_id, AuditAction::SamlLoginCompleted),
        0,
        "a refused assertion must never be audited as a completed login"
    );
    assert_eq!(
        count_audit(audit.as_ref(), &realm_id, AuditAction::SamlLoginFailed),
        1,
        "a refused assertion must be audited as a failure"
    );

    // Now the accepted one, which does issue a session cookie.
    seed_saml_state(identity.as_ref(), &realm_id, &idp_id, "relay-ok", "_req_ok");
    let good = signed_saml_response_b64(
        &idp_key,
        "_req_ok",
        &acs_url,
        sp_entity_id,
        "https://corp-idp.example",
        "audited@corp.example",
    );
    let resp = post_acs(&app, &good, "relay-ok", &[]);
    assert_eq!(resp.status().as_u16(), 303);

    let mut q = hearth::audit::AuditQuery::for_realm(realm_id.clone());
    q.action = Some(AuditAction::SamlLoginCompleted);
    let completed = audit.query(&q).expect("audit query");
    assert_eq!(
        completed.len(),
        1,
        "the accepted assertion must be audited as exactly one completed login"
    );
    assert_eq!(
        completed[0].actor, "audited@corp.example",
        "the completed-login event must name the asserted subject"
    );
}

// ============================================================================
// The shared `/ui` CSP (task 21.8 / audit §4.23#7).
//
// The per-response POST-binding policy this section used to cover belonged to
// the SAML IdP side, removed in 3.0.0. The shared layer must still apply its
// strict policy to every ordinary `/ui` page.
// ============================================================================

fn csp_of(resp: &axum::http::Response<Body>) -> String {
    resp.headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// Regression guard for the shared layer: it must not stomp the handler's
/// policy, but it must still apply its own to every other `/ui` response.
#[test]
fn shared_ui_csp_still_applies_to_ordinary_pages() {
    let app = build_app();
    let resp = send(
        &app,
        Request::builder()
            .method("GET")
            .uri("/ui/realms/demo/login")
            .body(Body::empty())
            .unwrap(),
    );
    let csp = csp_of(&resp);
    assert!(
        csp.contains("form-action 'self'"),
        "a page with no policy of its own must still get the shared strict CSP, got: {csp}"
    );
}

// ============================================================================
// GA sweep 3, round 2 — IdP signing-certificate rollover through the ACS.
//
// The connector's `idp_certificate_pem` may hold a bundle — the outgoing and
// the incoming certificate concatenated — while an IdP rolls its key. The
// ACS used to hand the whole bundle to the verifier as one certificate, which
// read only the first block, so every assertion signed with the new key was
// refused until the operator swapped the PEM at exactly the right moment.
// ============================================================================

#[test]
fn sp_acs_accepts_an_assertion_signed_by_the_second_certificate_of_a_bundle() {
    let (app, identity, realm_id) = build_app_full();
    let old_key = hearth::identity::tokens::RsaSigningKey::generate("corp-old", 365).expect("key");
    let new_key = hearth::identity::tokens::RsaSigningKey::generate("corp-new", 365).expect("key");
    let bundle = format!(
        "{}{}",
        cert_der_to_pem(old_key.cert_der()),
        cert_der_to_pem(new_key.cert_der())
    );
    let idp_id = register_saml_idp(
        identity.as_ref(),
        &realm_id,
        "corp",
        "https://corp-idp.example",
        bundle,
    );
    seed_saml_state(
        identity.as_ref(),
        &realm_id,
        &idp_id,
        "relay-roll",
        "_req_roll",
    );

    let sp_entity_id = "http://localhost:8420/ui/realms/demo";
    let acs_url = format!("{sp_entity_id}/federation/saml/acs");
    let b64 = signed_saml_response_b64(
        &new_key,
        "_req_roll",
        &acs_url,
        sp_entity_id,
        "https://corp-idp.example",
        "rollover-user@corp.example",
    );

    let resp = post_acs(&app, &b64, "relay-roll", &[]);
    let status = resp.status().as_u16();
    let cookies: Vec<String> = resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        status, 303,
        "an assertion signed by the bundle's second certificate must be accepted"
    );
    assert!(
        cookies.iter().any(|c| c.starts_with("hearth_ui_session=")),
        "the accepted assertion must produce a session; got {cookies:?}"
    );
}
