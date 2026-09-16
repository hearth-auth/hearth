#![allow(clippy::unwrap_used)]
//! HTTP-level integration tests for the `/ui/federation/*` handlers.
//!
//! Boots a full axum router with a real `EmbeddedIdentityEngine`, a
//! real `EmbeddedAuditEngine`, and a stubbed `FederationHttpTransport`
//! — issues HTTP requests through the router and asserts on redirect
//! targets, cookies, and audit rows.
//!
//! Complements the engine-level tests in `tests/federation.rs` and
//! the connector unit tests in `src/identity/federation/oidc.rs` by
//! exercising the Web adapter end-to-end.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hearth::audit::{AuditEngine, AuditQuery};
use hearth::core::{Clock, IdpId, SystemClock, Timestamp};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::federation::{
    compute_federation_state_mac, FederationSecret, IdpConfig, IdpKind, LinkMode, StateBag,
    StubFederationTransport,
};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::tokens::RsaSigningKey;
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, RealmConfig, UpdateRealmRequest,
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

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    audit: Arc<dyn AuditEngine>,
    realm_id: hearth::core::RealmId,
    idp_id: IdpId,
}

fn build_rig(stub: Arc<StubFederationTransport>) -> Rig {
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

    // Create the demo realm with default LinkMode::Confirm (None ≡
    // Confirm in RealmConfig).
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "demo".to_string(),
            config: Some(RealmConfig::default()),
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    // Register a connector. URLs point at idp.example; the stub will
    // intercept `/token`, `/jwks`, etc.
    let idp_id = IdpId::generate();
    identity
        .register_idp(&IdpConfig {
            id: idp_id.clone(),
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

    let app = web::router(state);

    Rig {
        app,
        identity,
        audit,
        realm_id,
        idp_id,
    }
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

fn set_link_mode(rig: &Rig, mode: LinkMode) {
    rig.identity
        .update_realm(
            &rig.realm_id,
            &UpdateRealmRequest {
                name: None,
                status: None,
                config: Some(RealmConfig {
                    federation_link_mode: Some(mode),
                    ..RealmConfig::default()
                }),
            },
        )
        .expect("update realm");
}

/// Returns the `Cookie` header value containing the A-48 state-binding MAC.
fn fed_bind_cookie(state_token: &str) -> String {
    let mac = compute_federation_state_mac(&COOKIE_SECRET, state_token);
    format!("hearth_fed_bind={mac}")
}

fn seed_state(rig: &Rig, state_token: &str, nonce: &str) {
    rig.identity
        .put_federation_state(&StateBag {
            state_token: state_token.to_string(),
            realm_id: rig.realm_id.clone(),
            idp_id: rig.idp_id.clone(),
            nonce: nonce.to_string(),
            pkce_verifier: "verifier-123".to_string(),
            return_to: "/ui/account".to_string(),
            expires_at: Timestamp::from_micros(i64::MAX),
            apple_user_json: None,
        })
        .expect("seed federation state");
}

fn stub_successful_oidc_callback(
    transport: &StubFederationTransport,
    _code: &str,
    nonce: &str,
    sub: &str,
    email: &str,
    email_verified: bool,
) {
    let kid = "test-key-1";
    let signing_key = RsaSigningKey::generate("web-ui-fed", 1).expect("generate rsa key");
    let pub_jwk = signing_key.to_jwk().expect("jwk");
    let n_b64 = pub_jwk.n.expect("modulus");
    let e_b64 = pub_jwk.e.expect("exponent");

    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": kid,
    });
    let payload = serde_json::json!({
        "iss": "https://idp.example",
        "sub": sub,
        "aud": "demo-client",
        "exp": 4_102_444_800i64,
        "iat": 4_102_444_200i64,
        "nonce": nonce,
        "email": email,
        "email_verified": email_verified,
        "name": "Alice Federated",
    });
    let header_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("serialize jwt header"));
    let payload_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("serialize jwt payload"));
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signature = signing_key
        .sign(signing_input.as_bytes())
        .expect("sign jwt");
    let jwt = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));

    transport.stub(
        "POST",
        "https://idp.example/token",
        200,
        serde_json::json!({ "id_token": jwt }).to_string(),
    );
    transport.stub(
        "GET",
        "https://idp.example/jwks",
        200,
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "kid": kid,
                "n": n_b64,
                "e": e_b64,
            }]
        })
        .to_string(),
    );
}

#[test]
fn begin_unknown_connector_returns_404() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(stub);
    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/federation/begin?idp=does-not-exist")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test]
fn begin_known_connector_302s_to_upstream_and_persists_state() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/federation/begin?idp=upstream")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get("location")
        .expect("redirect")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        location.starts_with("https://idp.example/auth?"),
        "got: {location}"
    );
    assert!(location.contains("client_id=demo-client"));
    assert!(location.contains("state="));
    assert!(location.contains("code_challenge="));

    // Pull the state token out of the URL and confirm the engine has
    // a persisted bag for it.
    let state_tok = location
        .split('&')
        .find_map(|p| p.strip_prefix("state="))
        .expect("state param");
    // `take` consumes, so calling it here ends the bag — that's fine
    // for this test.
    rig.identity
        .take_federation_state(&rig.realm_id, state_tok)
        .expect("state persisted");

    // Audit: FederationLoginStarted emitted.
    let events = rig
        .audit
        .query(&AuditQuery {
            realm_id: rig.realm_id.clone(),
            actor: None,
            action: Some(hearth::audit::AuditAction::FederationLoginStarted),
            start_time: None,
            end_time: None,
            limit: Some(10),
            agent_id: None,
            tool: None,
        })
        .expect("audit query");
    assert!(!events.is_empty(), "expected audit event");
}

#[test]
fn callback_with_error_redirects_to_login_denied() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(stub);
    let resp = send(
        &rig.app,
        Request::builder()
            .header("cookie", fed_bind_cookie("whatever"))
            .uri("/ui/realms/demo/federation/callback?state=whatever&error=access_denied")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "/ui/login?error=federation_denied");
}

#[test]
fn callback_with_unknown_state_redirects_to_login_failed() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(stub);
    let resp = send(
        &rig.app,
        Request::builder()
            .header("cookie", fed_bind_cookie("unknown"))
            .uri("/ui/realms/demo/federation/callback?state=unknown&code=xyz")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "/ui/login?error=federation_failed");
}

#[test]
fn login_page_renders_federation_buttons_when_connectors_exist() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(stub);
    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/login")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(to_bytes(resp.into_body(), 1024 * 1024))
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);
    // The button row is present.
    assert!(
        body.contains("data-testid=\"federation-button\""),
        "body missing federation button marker"
    );
    assert!(
        body.contains("Sign in with Upstream"),
        "body missing button label"
    );
    // The URL points at the scoped begin endpoint.
    assert!(
        body.contains("/ui/realms/demo/federation/begin?idp=upstream"),
        "button URL missing or unscoped"
    );
}

#[test]
fn login_page_omits_federation_section_when_no_connectors() {
    // Build a rig, then delete the connector so the login page has
    // no federation options to render. The section should disappear
    // entirely — no empty "or continue with" divider.
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(stub);
    rig.identity
        .delete_idp(&rig.realm_id, &rig.idp_id)
        .expect("delete idp");
    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/login")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(to_bytes(resp.into_body(), 1024 * 1024))
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);
    assert!(!body.contains("federation-button"));
    assert!(!body.contains("or continue with"));
}

#[test]
fn callback_auto_links_existing_user_on_verified_email() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    set_link_mode(&rig, LinkMode::Auto);
    let existing = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice Local".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create local user");
    seed_state(&rig, "state-auto", "nonce-auto");
    stub_successful_oidc_callback(
        &stub,
        "code-auto",
        "nonce-auto",
        "ext-auto-1",
        "alice@example.com",
        true,
    );

    let resp = send(
        &rig.app,
        Request::builder()
            .header("cookie", fed_bind_cookie("state-auto"))
            .uri("/ui/realms/demo/federation/callback?state=state-auto&code=code-auto")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/ui/account"
    );
    assert_eq!(
        rig.identity
            .find_user_by_external_identity(&rig.realm_id, &rig.idp_id, "ext-auto-1")
            .expect("lookup link"),
        Some(existing.id().clone())
    );
}

/// A realm that sets `mfa_required` demands a second factor on the federation
/// path too (audit 2026-08-28 §4.18#3, task 9.6). The upstream IdP asserts a
/// first factor only, so the callback must hand the browser to Hearth's own
/// MFA step instead of issuing a session cookie.
#[test]
fn callback_demands_mfa_when_the_realm_requires_it() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    set_link_mode(&rig, LinkMode::Auto);
    rig.identity
        .update_realm(
            &rig.realm_id,
            &UpdateRealmRequest {
                name: None,
                status: None,
                config: Some(RealmConfig {
                    federation_link_mode: Some(LinkMode::Auto),
                    mfa_required: Some(true),
                    ..RealmConfig::default()
                }),
            },
        )
        .expect("update realm");
    rig.identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice Local".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create local user");
    seed_state(&rig, "state-mfa", "nonce-mfa");
    stub_successful_oidc_callback(
        &stub,
        "code-mfa",
        "nonce-mfa",
        "ext-mfa-1",
        "alice@example.com",
        true,
    );

    let resp = send(
        &rig.app,
        Request::builder()
            .header("cookie", fed_bind_cookie("state-mfa"))
            .uri("/ui/realms/demo/federation/callback?state=state-mfa&code=code-mfa")
            .body(Body::empty())
            .unwrap(),
    );

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // No TOTP is enrolled, so the user is sent to forced enrolment.
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/ui/mfa-enroll-required"
    );
    let cookies: Vec<&str> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        !cookies.iter().any(|c| c.starts_with("hearth_ui_session=")),
        "no session cookie may be issued before the second factor: {cookies:?}"
    );
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("hearth_ui_mfa_pending=")),
        "the MFA pending cookie must carry the proven identity: {cookies:?}"
    );
}

#[test]
fn callback_confirm_mode_redirects_to_confirm_link_for_existing_user() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    set_link_mode(&rig, LinkMode::Confirm);
    let existing = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice Local".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create local user");
    seed_state(&rig, "state-confirm", "nonce-confirm");
    stub_successful_oidc_callback(
        &stub,
        "code-confirm",
        "nonce-confirm",
        "ext-confirm-1",
        "alice@example.com",
        true,
    );

    let resp = send(
        &rig.app,
        Request::builder()
            .header("cookie", fed_bind_cookie("state-confirm"))
            .uri("/ui/realms/demo/federation/callback?state=state-confirm&code=code-confirm")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        // 22.19: the redirect names the realm the login started in.
        location.starts_with("/ui/realms/demo/federation/confirm-link?ticket="),
        "unexpected confirm redirect: {location}"
    );
    assert_eq!(
        rig.identity
            .find_user_by_external_identity(&rig.realm_id, &rig.idp_id, "ext-confirm-1")
            .expect("link lookup"),
        None
    );
    let ticket = location
        .split("ticket=")
        .nth(1)
        .expect("confirm-link ticket");
    let pending = rig
        .identity
        .take_confirm_link_ticket(&rig.realm_id, ticket)
        .expect("load confirm-link ticket");
    assert_eq!(pending.user_id, *existing.id());
}

#[test]
fn callback_disabled_mode_creates_separate_user_on_email_collision() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    set_link_mode(&rig, LinkMode::Disabled);
    let existing = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice Local".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create local user");
    seed_state(&rig, "state-disabled", "nonce-disabled");
    stub_successful_oidc_callback(
        &stub,
        "code-disabled",
        "nonce-disabled",
        "ext-disabled-1",
        "alice@example.com",
        true,
    );

    let resp = send(
        &rig.app,
        Request::builder()
            .header("cookie", fed_bind_cookie("state-disabled"))
            .uri("/ui/realms/demo/federation/callback?state=state-disabled&code=code-disabled")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/ui/account"
    );
    let linked_user = rig
        .identity
        .find_user_by_external_identity(&rig.realm_id, &rig.idp_id, "ext-disabled-1")
        .expect("lookup link")
        .expect("linked user");
    assert_ne!(linked_user, *existing.id());
    let created = rig
        .identity
        .get_user(&rig.realm_id, &linked_user)
        .expect("get linked user")
        .expect("linked user exists");
    assert_eq!(
        created.email(),
        format!("ext-disabled-1@fed.{}.local", rig.idp_id.as_uuid())
    );
}

// ---------------------------------------------------------------------------
// 22.19 — confirm-to-link must resolve the realm the login started in
// ---------------------------------------------------------------------------

/// Creates a second realm so the bare (unscoped) resolver can no longer fall
/// back to `demo` via the sole-realm shortcut.
///
/// `realm_resolver::resolve(state, None)` returns `Resolved::Realm` only when
/// storage holds exactly one realm (or a `default_realm_name` is configured).
/// With two realms and no declared default it returns `MustChoose`, which is
/// the shape every real multi-realm deployment has.
fn add_second_realm(rig: &Rig) {
    rig.identity
        .create_realm(&CreateRealmRequest {
            name: "other".to_string(),
            config: Some(RealmConfig::default()),
        })
        .expect("create second realm");
}

/// Pulls the `hearth_ui_fed_confirm` cookie out of a response's `Set-Cookie`.
fn confirm_cookie_from(resp: &axum::http::Response<Body>) -> String {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("hearth_ui_fed_confirm="))
        .map(|v| v.split(';').next().unwrap_or("").to_string())
        .expect("confirm-link cookie must be set")
}

/// Drives a Confirm-mode federation callback and returns
/// `(confirm_redirect_location, confirm_cookie, local_user_id)`.
fn start_confirm_link_flow(
    rig: &Rig,
    stub: &StubFederationTransport,
) -> (String, String, hearth::core::UserId) {
    set_link_mode(rig, LinkMode::Confirm);
    let existing = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: "scoped@example.com".to_string(),
                display_name: "Scoped Local".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create local user");
    seed_state(rig, "state-scoped", "nonce-scoped");
    stub_successful_oidc_callback(
        stub,
        "code-scoped",
        "nonce-scoped",
        "ext-scoped-1",
        "scoped@example.com",
        true,
    );

    let resp = send(
        &rig.app,
        Request::builder()
            .header("cookie", fed_bind_cookie("state-scoped"))
            .uri("/ui/realms/demo/federation/callback?state=state-scoped&code=code-scoped")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let cookie = confirm_cookie_from(&resp);
    (location, cookie, existing.id().clone())
}

/// The callback must send the browser to the realm-scoped confirm page.
///
/// Audit 2026-08-28 §4.22#11: it redirected to the bare
/// `/ui/federation/confirm-link`, whose handler resolves the *default* realm.
/// The ticket lives under the realm the login started in, so on any
/// multi-realm deployment the lookup missed and the user was bounced to
/// `/ui/login` with no way to finish linking.
#[test]
fn confirm_link_redirect_is_realm_scoped() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    add_second_realm(&rig);

    let (location, _cookie, _user) = start_confirm_link_flow(&rig, &stub);
    assert!(
        location.starts_with("/ui/realms/demo/federation/confirm-link?ticket="),
        "confirm redirect must name the originating realm, got: {location}"
    );
}

/// Following that redirect renders the confirm page; the bare route — which
/// cannot resolve a realm here — does not.
#[test]
fn scoped_confirm_page_renders_where_the_bare_route_cannot() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    add_second_realm(&rig);

    let (location, cookie, _user) = start_confirm_link_flow(&rig, &stub);
    let ticket = location
        .split("ticket=")
        .nth(1)
        .expect("ticket")
        .to_string();

    // The scoped route resolves `demo` from the path and finds the ticket.
    let scoped = send(
        &rig.app,
        Request::builder()
            .header("cookie", cookie.clone())
            .uri(&location)
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(
        scoped.status(),
        StatusCode::OK,
        "the scoped confirm page must render"
    );
    let body = to_bytes(scoped.into_body(), usize::MAX);
    let body = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(body)
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        text.contains("/ui/realms/demo/federation/confirm-link"),
        "the confirm form must POST back to the realm-scoped route"
    );

    // The bare route is what the old redirect used. It cannot resolve a realm
    // on a multi-realm deployment, so it bounces — this is the failure users saw.
    let bare = send(
        &rig.app,
        Request::builder()
            .header("cookie", cookie)
            .uri(format!("/ui/federation/confirm-link?ticket={ticket}"))
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(bare.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        bare.headers().get("location").unwrap().to_str().unwrap(),
        "/ui/login",
        "the bare route cannot resolve the realm — which is why the callback \
         must not send the user there"
    );
}

/// The whole round trip completes: POST to the scoped route with the correct
/// local password links the external identity.
#[test]
fn scoped_confirm_submit_links_the_external_identity() {
    use hearth::identity::{CleartextPassword, UpdateUserRequest, UserStatus};

    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    add_second_realm(&rig);

    let (location, cookie, user_id) = start_confirm_link_flow(&rig, &stub);
    let ticket = location
        .split("ticket=")
        .nth(1)
        .expect("ticket")
        .to_string();

    // Task 21.14 made the POST handler actually read the `_csrf` field it had
    // been parsing and ignoring, so the round trip must now fetch the confirm
    // page first and submit the token it carries alongside its cookie.
    let page = send(
        &rig.app,
        Request::builder()
            .header("cookie", cookie.clone())
            .uri(&location)
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(page.status(), StatusCode::OK);
    let csrf_cookie = csrf_cookie_from(&page);
    let csrf_field = csrf_field_from(&body_text(page));
    let cookie = format!("{cookie}; {csrf_cookie}");

    rig.identity
        .set_password(
            &rig.realm_id,
            &user_id,
            &CleartextPassword::from_string("correct-horse-battery".to_string()),
        )
        .expect("set password");
    rig.identity
        .update_user(
            &rig.realm_id,
            &user_id,
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate");

    let body = format!("ticket={ticket}&password=correct-horse-battery&_csrf={csrf_field}");
    let resp = send(
        &rig.app,
        Request::builder()
            .method("POST")
            .header("cookie", cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .uri("/ui/realms/demo/federation/confirm-link")
            .body(Body::from(body))
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        rig.identity
            .find_user_by_external_identity(&rig.realm_id, &rig.idp_id, "ext-scoped-1")
            .expect("link lookup"),
        Some(user_id),
        "the confirm submit must persist the external-identity link"
    );
}

// ---------------------------------------------------------------------------
// 22.23 — Apple `form_post` callbacks must be able to authenticate
// ---------------------------------------------------------------------------

/// A syntactically valid P-256 PKCS#8 PEM. `AppleConnector::new` only needs
/// the config to be present; the key is exercised at token-exchange time.
const APPLE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----";

/// Registers an Apple Sign In connector named `apple` in the rig's realm.
fn register_apple_idp(rig: &Rig) {
    use hearth::identity::federation::AppleConfig;

    rig.identity
        .register_idp(&IdpConfig {
            id: IdpId::generate(),
            realm_id: rig.realm_id.clone(),
            name: "apple".to_string(),
            kind: IdpKind::Apple,
            display_name: "Apple".to_string(),
            issuer: "https://appleid.apple.com".to_string(),
            authorization_endpoint: "https://appleid.apple.com/auth/authorize".to_string(),
            token_endpoint: "https://appleid.apple.com/auth/token".to_string(),
            userinfo_endpoint: None,
            jwks_uri: Some("https://appleid.apple.com/auth/keys".to_string()),
            scopes: vec!["name".to_string(), "email".to_string()],
            client_id: "com.example.service".to_string(),
            client_secret: FederationSecret::new(String::new()),
            claim_mappings: BTreeMap::new(),
            leeway_seconds: IdpConfig::default_leeway_seconds(),
            want_assertions_signed: false,
            apple: Some(AppleConfig {
                team_id: "A1B2C3D4E5".to_string(),
                key_id: "ABCDE12345".to_string(),
                private_key_pem: FederationSecret::new(APPLE_KEY_PEM.to_string()),
            }),
            created_at: Timestamp::from_micros(0),
            updated_at: Timestamp::from_micros(0),
        })
        .expect("register apple idp");
}

/// Returns the `hearth_fed_bind` `Set-Cookie` line from a response.
fn bind_cookie_header(resp: &axum::http::Response<Body>) -> String {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("hearth_fed_bind="))
        .map(str::to_string)
        .expect("begin must plant the A-48 binding cookie")
}

/// 22.23 (audit 2026-08-28 §4.22#15): `callback_post` / `callback_scoped_post`
/// could never succeed from a browser.
///
/// Apple answers with `response_mode=form_post`, i.e. a cross-site **POST**
/// back to Hearth. A `SameSite=Lax` cookie is sent on a cross-site top-level
/// GET but *not* on a cross-site POST, so the A-48 binding cookie never
/// arrived and the handler always redirected to
/// `/ui/login?error=federation_failed`. `SameSite=None; Secure` is the only
/// setting a browser will send on that request.
#[test]
fn apple_begin_plants_a_cookie_a_browser_will_send_on_a_cross_site_post() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    register_apple_idp(&rig);

    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/federation/begin?idp=apple")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = bind_cookie_header(&resp);

    assert!(
        cookie.contains("SameSite=None"),
        "a form_post connector needs SameSite=None or its callback can never \
         authenticate; got: {cookie}"
    );
    assert!(
        cookie.contains("Secure"),
        "SameSite=None without Secure is rejected outright by browsers; got: {cookie}"
    );
    assert!(cookie.contains("HttpOnly"), "got: {cookie}");
}

/// Redirect-mode connectors keep `SameSite=Lax` — the change is scoped to the
/// connectors that actually need the relaxation.
#[test]
fn redirect_mode_connectors_keep_samesite_lax() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));

    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/federation/begin?idp=upstream")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = bind_cookie_header(&resp);
    assert!(cookie.contains("SameSite=Lax"), "got: {cookie}");
    assert!(
        !cookie.contains("SameSite=None"),
        "only form_post connectors get the relaxation; got: {cookie}"
    );
}

/// The POST callback route reaches the same handler as the GET one: with a
/// valid binding cookie it gets past A-48 and fails on the upstream exchange,
/// not on the cookie check.
#[test]
fn form_post_callback_passes_the_binding_check_with_the_cookie_present() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    seed_state(&rig, "state-formpost", "nonce-formpost");

    // Without the cookie the handler rejects before touching storage.
    let no_cookie = send(
        &rig.app,
        Request::builder()
            .method("POST")
            .header("content-type", "application/x-www-form-urlencoded")
            .uri("/ui/realms/demo/federation/callback")
            .body(Body::from("state=state-formpost&code=c"))
            .unwrap(),
    );
    assert_eq!(no_cookie.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        no_cookie
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap(),
        "/ui/login?error=federation_failed"
    );

    // With the cookie the state bag is consumed, proving the POST route runs
    // the same pipeline as the GET one once the cookie is actually delivered.
    let with_cookie = send(
        &rig.app,
        Request::builder()
            .method("POST")
            .header("cookie", fed_bind_cookie("state-formpost"))
            .header("content-type", "application/x-www-form-urlencoded")
            .uri("/ui/realms/demo/federation/callback")
            .body(Body::from("state=state-formpost&code=c"))
            .unwrap(),
    );
    assert_eq!(with_cookie.status(), StatusCode::SEE_OTHER);
    assert!(
        rig.identity
            .take_federation_state(&rig.realm_id, "state-formpost")
            .is_err(),
        "the POST callback must have consumed the state bag — i.e. it got past \
         the A-48 binding check rather than bouncing on it"
    );
}

// ---------------------------------------------------------------------------
// 21.14 (audit 2026-08-28 §4.22#12) — the `_csrf` field on
// `POST /ui/federation/confirm-link` was parsed and ignored
// ---------------------------------------------------------------------------

/// Reads a response body to a `String`, blocking on the shared helper runtime.
fn body_text(resp: axum::http::Response<Body>) -> String {
    let fut = to_bytes(resp.into_body(), usize::MAX);
    let bytes = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Pulls the `hearth_ui_csrf` cookie out of a response's `Set-Cookie` headers.
fn csrf_cookie_from(resp: &axum::http::Response<Body>) -> String {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("hearth_ui_csrf="))
        .map(|v| v.split(';').next().unwrap_or("").to_string())
        .expect("the confirm-link page must issue a CSRF cookie")
}

/// Extracts the hidden `_csrf` value the confirm-link form carries.
fn csrf_field_from(html: &str) -> String {
    let marker = r#"name="_csrf" value=""#;
    let start = html
        .find(marker)
        .map(|i| i + marker.len())
        .expect("the confirm-link form must carry a hidden _csrf field");
    let end = start + html[start..].find('"').expect("unterminated _csrf value");
    html[start..end].to_string()
}

/// Drives the flow up to a rendered confirm page and returns
/// `(post_uri, cookie_header, csrf_field, ticket)`.
fn confirm_page_context(
    rig: &Rig,
    stub: &StubFederationTransport,
) -> (String, String, String, String) {
    let (location, confirm_cookie, _user) = start_confirm_link_flow(rig, stub);
    let ticket = location
        .split("ticket=")
        .nth(1)
        .expect("ticket")
        .to_string();

    let page = send(
        &rig.app,
        Request::builder()
            .header("cookie", confirm_cookie.clone())
            .uri(&location)
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(page.status(), StatusCode::OK);
    let csrf_cookie = csrf_cookie_from(&page);
    let csrf_field = csrf_field_from(&body_text(page));
    let cookie_header = format!("{confirm_cookie}; {csrf_cookie}");
    (
        "/ui/realms/demo/federation/confirm-link".to_string(),
        cookie_header,
        csrf_field,
        ticket,
    )
}

/// The page must both mint a CSRF cookie and echo the token into the form.
/// Without one of the two there is nothing for the POST handler to compare.
#[test]
fn confirm_link_page_issues_a_csrf_token() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    add_second_realm(&rig);

    let (_uri, cookie_header, csrf_field, _ticket) = confirm_page_context(&rig, &stub);
    assert!(!csrf_field.is_empty(), "_csrf field must not be empty");
    assert!(
        cookie_header.contains(&format!("hearth_ui_csrf={csrf_field}")),
        "the hidden _csrf field must equal the cookie the page set"
    );
}

/// A POST with no `_csrf` — what a cross-origin form can send, since it
/// cannot read the cookie — must be refused, and must NOT burn the ticket.
#[test]
fn confirm_link_submit_without_csrf_is_refused() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    add_second_realm(&rig);

    let (uri, cookie_header, _csrf, ticket) = confirm_page_context(&rig, &stub);
    let resp = send(
        &rig.app,
        Request::builder()
            .method("POST")
            .header("cookie", cookie_header)
            .header("content-type", "application/x-www-form-urlencoded")
            .uri(&uri)
            .body(Body::from(format!("ticket={ticket}&password=irrelevant")))
            .unwrap(),
    );
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a tokenless confirm-link POST must be refused"
    );
    assert!(
        rig.identity
            .take_confirm_link_ticket(&rig.realm_id, &ticket)
            .is_ok(),
        "a CSRF failure must not consume the ticket"
    );
}

/// A forged token must not pass either — the check has to compare values, not
/// merely notice that the field is present.
#[test]
fn confirm_link_submit_with_a_wrong_csrf_is_refused() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    add_second_realm(&rig);

    let (uri, cookie_header, csrf, ticket) = confirm_page_context(&rig, &stub);
    // Flip the last character to something it is not, keeping the length so
    // the constant-time compare reaches the byte loop rather than short-
    // circuiting on a length mismatch.
    let last = csrf.chars().last().expect("non-empty token");
    let flipped = if last == 'A' { 'B' } else { 'A' };
    let forged = format!("{}{flipped}", &csrf[..csrf.len() - 1]);
    assert_ne!(forged, csrf);
    let resp = send(
        &rig.app,
        Request::builder()
            .method("POST")
            .header("cookie", cookie_header)
            .header("content-type", "application/x-www-form-urlencoded")
            .uri(&uri)
            .body(Body::from(format!(
                "ticket={ticket}&password=irrelevant&_csrf={forged}"
            )))
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// The matching token still gets through, so the check is not a blanket deny.
/// The password is wrong, so the handler bounces to the login page — that is
/// the far side of the CSRF gate, which is what this pins.
#[test]
fn confirm_link_submit_with_the_matching_csrf_passes_the_gate() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    add_second_realm(&rig);

    let (uri, cookie_header, csrf, ticket) = confirm_page_context(&rig, &stub);
    let resp = send(
        &rig.app,
        Request::builder()
            .method("POST")
            .header("cookie", cookie_header)
            .header("content-type", "application/x-www-form-urlencoded")
            .uri(&uri)
            .body(Body::from(format!(
                "ticket={ticket}&password=not-the-password&_csrf={csrf}"
            )))
            .unwrap(),
    );
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a matching token must not be refused by the CSRF gate"
    );
    assert!(
        rig.identity
            .take_confirm_link_ticket(&rig.realm_id, &ticket)
            .is_err(),
        "passing the gate must reach the handler, which consumes the ticket"
    );
}

/// 22.16 (audit 2026-08-28 §4.22#8): the `redirect_uri` actually transmitted
/// upstream must be the absolute, realm-scoped callback URL — the same string
/// the admin Identity Provider detail page publishes for the operator to
/// register with the provider.
///
/// `tests/web_ui_idp_admin.rs` covers the published half; this covers the
/// transmitted half, so the two ends of the claim are pinned independently and
/// a future divergence cannot pass both. The old value was
/// `/realms/{realm}/federation/callback` — relative, and missing the `/ui`
/// prefix — so upstream IdPs answered `redirect_uri_mismatch`.
#[test]
fn begin_transmits_the_absolute_realm_scoped_callback_as_redirect_uri() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/federation/begin?idp=upstream")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get("location")
        .expect("redirect")
        .to_str()
        .unwrap()
        .to_string();

    let redirect_uri = location
        .split("redirect_uri=")
        .nth(1)
        .map(|rest| {
            let end = rest.find('&').unwrap_or(rest.len());
            rest[..end].to_string()
        })
        .expect("the authorize URL must carry a redirect_uri");
    // The parameter is percent-encoded in the query string.
    let decoded = redirect_uri.replace("%3A", ":").replace("%2F", "/");

    assert_eq!(
        decoded, "http://localhost/ui/realms/demo/federation/callback",
        "the transmitted redirect_uri must be the absolute, realm-scoped \
         callback URL the admin page publishes"
    );
    assert!(
        !decoded.starts_with("/realms/"),
        "a relative redirect_uri is not a routable callback: {decoded}"
    );
}
