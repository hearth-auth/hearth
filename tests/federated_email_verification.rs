#![allow(clippy::unwrap_used)]
//! An email address is attested as verified only when it is (GA audit
//! round 3, G-3 and B-8).
//!
//! * Federated just-in-time provisioning created an `Active` account on
//!   whatever address the upstream named, whether or not the upstream said it
//!   verified it. Behind an IdP that lets a user claim any address, an attacker
//!   pre-created the victim's account (and, through Hearth's SAML IdP, had
//!   Hearth assert the victim's address to every registered SP). Such an
//!   account is now created `PendingVerification`, like self-registration, and
//!   the address owner gets the verification mail.
//! * `/userinfo` answered `email_verified: true` for every token carrying the
//!   `email` scope. It now reports the account's own state.

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hearth::core::{ClientId, Clock, IdpId, RealmId, SystemClock, Timestamp, UserId};
use hearth::identity::email::{EmailBranding, EmailError, EmailMessage, EmailSender, EmailService};
use hearth::identity::federation::{
    compute_federation_state_mac, FederationSecret, IdpConfig, IdpKind, StateBag,
    StubFederationTransport,
};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::tokens::RsaSigningKey;
use hearth::identity::{
    AuthorizationRequest, ClientTrustLevel, CodeChallengeMethod, CreateRealmRequest,
    CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    RealmConfig, RegisterClientRequest, TokenExchangeRequest, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [53u8; 32];

// ── Federation rig ───────────────────────────────────────────────────────────

/// Every message the realm sent: (recipient, text body).
#[derive(Default)]
struct Outbox(Mutex<Vec<(String, String)>>);

struct CapturingMail(Arc<Outbox>);
impl EmailSender for CapturingMail {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        self.0
             .0
            .lock()
            .unwrap()
            .push((message.to.clone(), message.text_body.clone()));
        Ok(())
    }
}

struct FedRig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    idp_id: IdpId,
    outbox: Arc<Outbox>,
}

fn build_fed_rig(stub: Arc<StubFederationTransport>) -> FedRig {
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
    )) as Arc<dyn hearth::audit::AuditEngine>;
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
    let rbac = Arc::new(EmbeddedRbacEngine::new(
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
            trust_asserted_email: false,
            apple: None,
            created_at: Timestamp::from_micros(0),
            updated_at: Timestamp::from_micros(0),
        })
        .expect("register idp");
    let outbox = Arc::new(Outbox::default());
    let email = Arc::new(
        EmailService::new(
            Arc::new(CapturingMail(Arc::clone(&outbox))),
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
        Arc::clone(&email),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        rbac,
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(email),
    )
    .with_dev_mode(true)
    .with_federation_http(stub as Arc<dyn hearth::identity::federation::FederationHttpTransport>);
    FedRig {
        app: web::router(state),
        identity,
        realm_id,
        idp_id,
        outbox,
    }
}

/// Runs one request on a runtime of its own. Dropping the runtime waits for
/// the blocking tasks the handler spawned (the verification mail is sent off
/// the request path), so the outbox is complete when this returns.
fn send(app: &axum::Router, req: Request<Body>) -> axum::http::Response<Body> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let resp = rt
        .block_on(app.clone().oneshot(req))
        .expect("router response");
    drop(rt);
    resp
}

fn body_text(resp: axum::http::Response<Body>) -> String {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let bytes = rt
        .block_on(to_bytes(resp.into_body(), 1 << 20))
        .expect("body");
    String::from_utf8_lossy(&bytes).into_owned()
}

fn set_cookies(resp: &axum::http::Response<Body>) -> Vec<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect()
}

fn issues_a_session(resp: &axum::http::Response<Body>) -> bool {
    set_cookies(resp)
        .iter()
        .any(|c| c.starts_with("hearth_ui_session=") && !c.starts_with("hearth_ui_session=;"))
}

/// Seeds the state bag and stubs the upstream so that the callback for
/// `state` resolves to an ID token naming `sub` / `email` / `email_verified`.
/// The stub answers every later token request with the same ID token (its
/// first matching stub wins), so a later login reuses it via [`seed_state`].
fn stub_upstream_login(
    rig: &FedRig,
    stub: &StubFederationTransport,
    state: &str,
    sub: &str,
    email: &str,
    email_verified: bool,
) {
    let nonce = format!("nonce-{state}");
    seed_state(rig, state, &nonce);
    stub_id_token(stub, &nonce, sub, email, email_verified);
}

/// Seeds the federation state bag for `state`, expecting `nonce`.
fn seed_state(rig: &FedRig, state: &str, nonce: &str) {
    rig.identity
        .put_federation_state(&StateBag {
            state_token: state.to_string(),
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

/// Stubs the upstream token and JWKS endpoints with an ID token for `nonce`.
fn stub_id_token(
    stub: &StubFederationTransport,
    nonce: &str,
    sub: &str,
    email: &str,
    email_verified: bool,
) {
    let kid = "test-key-1";
    let signing_key = RsaSigningKey::generate("fed-email", 1).expect("generate rsa key");
    let jwk = signing_key.to_jwk().expect("jwk");
    let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": kid });
    let payload = serde_json::json!({
        "iss": "https://idp.example",
        "sub": sub,
        "aud": "demo-client",
        "exp": 4_102_444_800i64,
        "iat": 4_102_444_200i64,
        "nonce": nonce,
        "email": email,
        "email_verified": email_verified,
        "name": "Federated User",
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
    );
    let signature = signing_key.sign(signing_input.as_bytes()).expect("sign");
    let jwt = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));
    stub.stub(
        "POST",
        "https://idp.example/token",
        200,
        serde_json::json!({ "id_token": jwt }).to_string(),
    );
    stub.stub(
        "GET",
        "https://idp.example/jwks",
        200,
        serde_json::json!({ "keys": [{
            "kty": "RSA", "alg": "RS256", "kid": kid,
            "n": jwk.n.expect("n"), "e": jwk.e.expect("e"),
        }]})
        .to_string(),
    );
}

fn callback(rig: &FedRig, state: &str) -> axum::http::Response<Body> {
    let mac = compute_federation_state_mac(&COOKIE_SECRET, state);
    send(
        &rig.app,
        Request::builder()
            .header("cookie", format!("hearth_fed_bind={mac}"))
            .uri(format!(
                "/ui/realms/demo/federation/callback?state={state}&code=code-{state}"
            ))
            .body(Body::empty())
            .unwrap(),
    )
}

fn linked_user(rig: &FedRig, sub: &str) -> hearth::identity::User {
    let user_id = rig
        .identity
        .find_user_by_external_identity(&rig.realm_id, &rig.idp_id, sub)
        .expect("lookup link")
        .expect("the external identity is linked");
    rig.identity
        .get_user(&rig.realm_id, &user_id)
        .expect("get user")
        .expect("user exists")
}

/// The verification token in the last message sent to `recipient`.
fn verification_token_sent_to(rig: &FedRig, recipient: &str) -> Option<String> {
    let outbox = rig.outbox.0.lock().unwrap();
    outbox
        .iter()
        .rev()
        .find(|(to, _)| to == recipient)
        .and_then(|(_, body)| body.split("verify-email?token=").nth(1))
        .map(|rest| {
            rest.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect()
        })
}

/// G-3: an upstream that did NOT assert the address verified gets an account
/// that waits for the address owner, not a session on that address.
#[test]
fn jit_with_an_unverified_upstream_email_waits_for_the_address_owner() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_fed_rig(Arc::clone(&stub));
    stub_upstream_login(
        &rig,
        &stub,
        "st-unverified",
        "ext-1",
        "victim@corp.example",
        false,
    );

    let resp = callback(&rig, "st-unverified");
    assert!(
        !issues_a_session(&resp),
        "no session on an address nobody proved (status {}, location {:?})",
        resp.status(),
        resp.headers().get("location")
    );
    let user = linked_user(&rig, "ext-1");
    assert_eq!(user.email(), "victim@corp.example");
    assert_eq!(
        user.status(),
        UserStatus::PendingVerification,
        "the account waits for its address to be verified"
    );
    assert!(!user.email_verified());
    let token = verification_token_sent_to(&rig, "victim@corp.example")
        .expect("the address owner is sent the verification link");

    // The address owner verifies; from then on the federated login works.
    rig.identity
        .verify_email_token(&rig.realm_id, &token)
        .expect("verify");
    seed_state(&rig, "st-again", "nonce-st-unverified");
    let resp = callback(&rig, "st-again");
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        issues_a_session(&resp),
        "a verified account signs in through its link (location {:?})",
        resp.headers().get("location")
    );
}

/// Control: an upstream that asserted the address verified gets an active
/// account whose address is recorded as verified, and a session.
#[test]
fn jit_with_a_verified_upstream_email_is_active_and_verified() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_fed_rig(Arc::clone(&stub));
    stub_upstream_login(
        &rig,
        &stub,
        "st-verified",
        "ext-2",
        "alice@corp.example",
        true,
    );

    let resp = callback(&rig, "st-verified");
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{}", body_text(resp));
    let user = linked_user(&rig, "ext-2");
    assert_eq!(user.status(), UserStatus::Active);
    assert!(
        user.email_verified(),
        "the upstream vouched for the address"
    );
}

// ── /userinfo (B-8) ──────────────────────────────────────────────────────────

const REDIRECT_URI: &str = "https://rp.example.com/cb";
const VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

fn email_scope_token(h: &common::TestHarness, realm: &RealmId, user: &UserId) -> String {
    let client: ClientId = h
        .identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "rp".into(),
                redirect_uris: vec![REDIRECT_URI.into()],
                grant_types: vec!["authorization_code".into()],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register")
        .client_id()
        .clone();
    let challenge = URL_SAFE_NO_PAD
        .encode(ring::digest::digest(&ring::digest::SHA256, VERIFIER.as_bytes()).as_ref());
    let code = h
        .identity()
        .authorize(
            realm,
            &AuthorizationRequest {
                client_id: client.clone(),
                redirect_uri: REDIRECT_URI.into(),
                scope: "openid email".into(),
                state: "s".into(),
                response_type: "code".into(),
                user_id: user.clone(),
                code_challenge: Some(challenge),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize")
        .code()
        .to_string();
    h.identity()
        .exchange_authorization_code(
            realm,
            &TokenExchangeRequest {
                client_id: client,
                code,
                redirect_uri: REDIRECT_URI.into(),
                code_verifier: Some(VERIFIER.into()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange")
        .access_token()
        .to_string()
}

fn userinfo_setup(h: &common::TestHarness) -> (RealmId, UserId) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("userinfo-ev-{}", uuid::Uuid::new_v4().simple()),
            config: Some(RealmConfig::default()),
        })
        .expect("create realm")
        .id()
        .clone();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@userinfo.test", uuid::Uuid::new_v4().simple()),
                display_name: "Userinfo".into(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    (realm, user)
}

/// B-8: an operator-created account has not proved its address; `/userinfo`
/// must say so, and say `true` once the address is verified.
#[tokio::test]
async fn userinfo_reports_the_accounts_own_email_verification_state() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, user) = userinfo_setup(&h);

    let token = email_scope_token(&h, &realm, &user);
    let info = h.identity().userinfo(&realm, &token).expect("userinfo");
    assert!(
        info.email.is_some(),
        "control: the email scope releases the address"
    );
    assert_eq!(
        info.email_verified,
        Some(false),
        "an address nobody proved is not attested as verified"
    );

    let verify = h
        .identity()
        .issue_email_verification_token(&realm, &user)
        .expect("issue token");
    h.identity()
        .verify_email_token(&realm, &verify)
        .expect("verify");
    let token = email_scope_token(&h, &realm, &user);
    let info = h.identity().userinfo(&realm, &token).expect("userinfo");
    assert_eq!(info.email_verified, Some(true));
}

/// B-8 sibling: an operator changing a verified account's address leaves
/// the NEW address unproven.
#[tokio::test]
async fn changing_the_address_clears_its_verification() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, user) = userinfo_setup(&h);
    let verify = h
        .identity()
        .issue_email_verification_token(&realm, &user)
        .expect("issue token");
    h.identity()
        .verify_email_token(&realm, &verify)
        .expect("verify");
    assert!(
        h.identity()
            .get_user(&realm, &user)
            .unwrap()
            .unwrap()
            .email_verified(),
        "control: the address is verified"
    );

    let updated = h
        .identity()
        .update_user(
            &realm,
            &user,
            &UpdateUserRequest {
                email: Some(format!(
                    "moved-{}@userinfo.test",
                    uuid::Uuid::new_v4().simple()
                )),
                ..Default::default()
            },
        )
        .expect("update");
    assert!(
        !updated.email_verified(),
        "the new address has not been proved"
    );
}
