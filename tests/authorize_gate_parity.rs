//! Every browser authorization branch runs the same gates.
//!
//! `GET /ui/oauth/authorize` has four ways to reach code issuance: a plain
//! request, a signed request object (JAR, RFC 9101), a pushed request
//! (`request_uri`, RFC 9126) and the resumes at the end of the
//! required-action and SMS-challenge interstitials. Only the plain branch
//! used to run the consent interstitial and honour `prompt`; the others
//! issued a code straight away — a third-party client got a code without
//! the user ever approving it. The PAR branch and the SMS resume also
//! dropped the requested `response_mode`, so a `fragment` / JARM request
//! got a plain query-string redirect.
//!
//! And the required-action intercept read a user-lookup *error* as "no
//! required actions", so a storage fault skipped a forced password change —
//! one call deeper, a client or RBAC lookup error skipped the MFA enrolment a
//! client or role mandates. A `prompt=none` request was redirected into the
//! required-action and SMS interstitials instead of being refused.
//!
//! Each branch is driven through the public web router.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, Response, StatusCode};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock, Timestamp, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, OAuthClient, RealmConfig,
    RegisterClientRequest, RequiredAction, SessionContext, SmsError, SmsMessage, SmsSender,
    UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{
    EmbeddedStorageEngine, ScanEntry, StorageConfig, StorageEngine, StorageError,
};
use tower::ServiceExt as _;

const COOKIE_SECRET: [u8; 32] = [73u8; 32];
const CSRF: &str = "authorize-gate-parity-csrf";
const USER_EMAIL: &str = "gate-user@parity.test";
const PHONE: &str = "+15555550163";
const REDIRECT: &str = "https://app.example.com/cb";
const SMS_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
const PKCE_VERIFIER: &str = "verifier-verifier-verifier-verifier-7";
const JAR_KID: &str = "gate-parity-jar-key";
const RESOURCE: &str = "https://api.example.com/v1";

fn password() -> String {
    ["gate", "parity", "pass", "phrase"].join("-")
}

fn pkce_challenge() -> String {
    data_encoding::BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes()).as_ref())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Rig
// ---------------------------------------------------------------------------

struct CapturingSms {
    messages: Mutex<Vec<SmsMessage>>,
}

impl CapturingSms {
    fn last_code(&self) -> String {
        #[allow(clippy::unwrap_used)]
        let guard = self.messages.lock().unwrap();
        let body = guard.last().expect("an SMS was sent").body.clone();
        let (_, code) = body.rsplit_once(": ").expect("code in body");
        code.trim().to_string()
    }
}

impl SmsSender for CapturingSms {
    fn send(&self, message: &SmsMessage) -> Result<(), SmsError> {
        #[allow(clippy::unwrap_used)]
        self.messages.lock().unwrap().push(message.clone());
        Ok(())
    }
}

fn null_email() -> Arc<EmailService> {
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

fn web_state(
    identity: Arc<dyn IdentityEngine>,
    rbac: Arc<dyn RbacEngine>,
    audit: Arc<dyn AuditEngine>,
    data_dir: std::path::PathBuf,
) -> WebState {
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        null_email(),
        data_dir,
    ));
    WebState::new(
        identity,
        rbac,
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(null_email()),
    )
}

struct Rig {
    _harness: common::TestHarness,
    _data_dir: tempfile::TempDir,
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    user_id: UserId,
    sms: Arc<CapturingSms>,
}

/// A realm, an active user with a verified phone, and the web router.
/// `sms_realm` makes the realm require the SMS factor (with a working
/// transport and OTP key wired).
async fn rig(sms_realm: bool) -> Rig {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity_arc();
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("gate-parity-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_methods: sms_realm.then(|| vec!["sms".to_string()]),
                ..RealmConfig::default()
            }),
        })
        .expect("realm");
    // RFC 8707: a `resource` must name a protected resource of the realm.
    identity
        .register_protected_resource(
            realm.id(),
            &hearth::identity::RegisterProtectedResourceRequest {
                resource_uri: RESOURCE.to_string(),
                display_name: "Gate parity API".to_string(),
                scopes: Vec::new(),
                required_claims: Vec::new(),
                introspection_client_id: None,
            },
        )
        .expect("register the protected resource");
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: USER_EMAIL.to_string(),
                display_name: "Gate".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("user");
    identity
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string(password()),
        )
        .expect("password");
    identity
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                phone_number: Some(Some(PHONE.to_string())),
                phone_verified: Some(true),
                ..Default::default()
            },
        )
        .expect("activate");

    let data_dir = tempfile::tempdir().expect("tempdir");
    let sms = Arc::new(CapturingSms {
        messages: Mutex::new(Vec::new()),
    });
    let state = web_state(
        Arc::clone(&identity),
        harness.rbac_arc(),
        harness.audit_arc(),
        data_dir.path().to_path_buf(),
    )
    .with_sms(Arc::clone(&sms) as _, Some(SMS_KEY.to_vec()))
    .with_default_realm(Some(realm.name().to_string()));
    Rig {
        app: web::router(state),
        _harness: harness,
        _data_dir: data_dir,
        identity,
        realm_id: realm.id().clone(),
        user_id: user.id().clone(),
        sms,
    }
}

fn register(rig: &Rig, require_consent: bool, jwks: Option<String>) -> OAuthClient {
    rig.identity
        .register_client(
            &rig.realm_id,
            &RegisterClientRequest {
                client_name: "Gate parity app".to_string(),
                redirect_uris: vec![REDIRECT.to_string()],
                require_consent,
                grant_types: vec!["authorization_code".to_string()],
                // The consent gate is driven by the trust level (AUTHZ_EXPANSION):
                // registration derives `require_consent` from it.
                trust_level: if require_consent {
                    hearth::identity::ClientTrustLevel::ThirdParty
                } else {
                    hearth::identity::ClientTrustLevel::FirstParty
                },
                jwks,
                ..Default::default()
            },
        )
        .expect("register client")
}

fn grant_consent(rig: &Rig, client: &OAuthClient) {
    rig.identity
        .grant_consent(
            &rig.realm_id,
            &rig.user_id,
            client.client_id(),
            &["openid".to_string()],
        )
        .expect("grant consent");
}

fn require_password_update(rig: &Rig) {
    rig.identity
        .update_user(
            &rig.realm_id,
            &rig.user_id,
            &UpdateUserRequest {
                required_actions: Some(vec![RequiredAction::UpdatePassword]),
                ..Default::default()
            },
        )
        .expect("require a password update");
}

/// A signed UI session cookie (plus the CSRF cookie) for the rig's user.
fn session_cookie(rig: &Rig) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let session = rig
        .identity
        .create_session(
            &rig.realm_id,
            &rig.user_id,
            &SessionContext {
                // The user may hold a second factor, and a session must say it
                // proved one (GA audit B4/B5): this stands for a completed login.
                mfa_proof: hearth::identity::MfaProof::Proved,
                ..SessionContext::default()
            },
        )
        .expect("session");
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("key");
    mac.update(session.id().as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={CSRF}",
        session.id().as_uuid(),
        rig.realm_id.as_uuid(),
        tag,
    )
}

async fn get(rig: &Rig, uri: &str, cookies: &str) -> Response<Body> {
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, cookies)
                .body(Body::empty())
                .expect("build GET"),
        )
        .await
        .expect("GET")
}

async fn post_form(rig: &Rig, uri: &str, cookies: &str, body: String) -> Response<Body> {
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookies)
                .body(Body::from(body))
                .expect("build POST"),
        )
        .await
        .expect("POST")
}

fn location(resp: &Response<Body>) -> String {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn cookie_pair(resp: &Response<Body>, name: &str) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")) && !v.contains("Max-Age=0"))
        .map(|v| v.split(';').next().unwrap_or("").to_string())
}

/// Parameters of a redirect `location`, from its query or its fragment.
fn redirect_param(location: &str, name: &str, in_fragment: bool) -> Option<String> {
    let part = if in_fragment {
        location.split_once('#')?.1
    } else {
        location.split('#').next()?.split_once('?')?.1
    };
    form_urlencoded::parse(part.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// The response must be the consent interstitial, not a code.
fn assert_consent_prompt(resp: &Response<Body>, what: &str) {
    assert_eq!(
        location(resp),
        "/ui/oauth/consent",
        "{what}: a client that requires consent must get the consent prompt, not a code \
         (status {})",
        resp.status()
    );
    assert!(
        cookie_pair(resp, "hearth_ui_oauth_ticket").is_some(),
        "{what}: the consent ticket cookie must be set"
    );
}

/// Approves the pending consent ticket in `authorize_resp` and returns the
/// consent POST's response.
async fn approve_consent(
    rig: &Rig,
    cookies: &str,
    authorize_resp: &Response<Body>,
) -> Response<Body> {
    decide_consent(rig, cookies, authorize_resp, "approve").await
}

/// Submits `decision` for the pending consent ticket in `authorize_resp`.
async fn decide_consent(
    rig: &Rig,
    cookies: &str,
    authorize_resp: &Response<Body>,
    decision: &str,
) -> Response<Body> {
    let ticket_pair =
        cookie_pair(authorize_resp, "hearth_ui_oauth_ticket").expect("consent ticket cookie");
    let ticket = ticket_pair
        .strip_prefix("hearth_ui_oauth_ticket=")
        .and_then(|v| v.split('.').next())
        .expect("ticket value")
        .to_string();
    post_form(
        rig,
        "/ui/oauth/consent",
        &format!("{cookies}; {ticket_pair}"),
        format!("ticket={ticket}&decision={decision}&scope=openid&_csrf={CSRF}"),
    )
    .await
}

/// The claims of a JWT, unverified (the signature is the engine's concern;
/// these tests only check which values travelled where).
fn jwt_claims(jwt: &str) -> serde_json::Value {
    let payload = jwt.split('.').nth(1).expect("JWT payload");
    serde_json::from_slice(
        &data_encoding::BASE64URL_NOPAD
            .decode(payload.as_bytes())
            .expect("base64url payload"),
    )
    .expect("claims json")
}

/// A `private_key_jwt` assertion signed with the client's JWKS key: a
/// client that registered a JWKS is confidential and authenticates with it.
fn client_assertion(
    rig: &Rig,
    client: &OAuthClient,
    pair: &ring::signature::Ed25519KeyPair,
) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let cid = client.client_id().to_string();
    let realm_name = rig
        .identity
        .get_realm(&rig.realm_id)
        .expect("get_realm")
        .expect("realm")
        .name()
        .to_string();
    let now = i64::try_from(now_secs()).expect("now");
    let h = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({ "alg": "EdDSA", "kid": JAR_KID })).expect("header"),
    );
    let c = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "iss": cid, "sub": cid,
            "aud": format!("https://hearth.local/realms/{realm_name}"),
            "exp": now + 60, "iat": now, "jti": uuid::Uuid::new_v4().to_string(),
        }))
        .expect("claims"),
    );
    let input = format!("{h}.{c}");
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(pair.sign(input.as_bytes()).as_ref())
    )
}

/// Exchanges `code` and returns the access token's `aud`. A client that
/// registered a JWKS (`pair`) authenticates with an assertion signed by it; a
/// public client (`None`) authenticates by PKCE alone.
fn exchanged_audience(
    rig: &Rig,
    client: &OAuthClient,
    pair: Option<&ring::signature::Ed25519KeyPair>,
    code: String,
) -> Vec<String> {
    let tokens = rig
        .identity
        .exchange_authorization_code(
            &rig.realm_id,
            &hearth::identity::TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code,
                redirect_uri: REDIRECT.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: pair
                    .map(|_| "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string()),
                client_assertion: pair.map(|pair| client_assertion(rig, client, pair)),
            },
        )
        .expect("exchange the code");
    let payload = tokens
        .access_token()
        .split('.')
        .nth(1)
        .expect("JWT payload");
    let claims: serde_json::Value = serde_json::from_slice(
        &data_encoding::BASE64URL_NOPAD
            .decode(payload.as_bytes())
            .expect("base64url payload"),
    )
    .expect("claims json");
    match &claims["aud"] {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        other => panic!("unexpected aud {other}"),
    }
}

// ---------------------------------------------------------------------------
// Request builders, one per branch
// ---------------------------------------------------------------------------

/// A plain authorize URI with `extra` query parameters appended.
fn plain_uri(client: &OAuthClient, extra: &str) -> String {
    format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb\
         &response_type=code&scope=openid&state=plain-state&code_challenge={}\
         &code_challenge_method=S256{extra}",
        client.client_id().as_uuid(),
        pkce_challenge()
    )
}

/// Registers a JWKS client and returns it with a signing key pair.
fn jar_client(rig: &Rig, require_consent: bool) -> (OAuthClient, ring::signature::Ed25519KeyPair) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("pair");
    let x = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    let jwks = format!(
        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"{JAR_KID}","x":"{x}"}}]}}"#
    );
    (register(rig, require_consent, Some(jwks)), pair)
}

/// A JAR authorize URI signed by `pair`, with `overrides` merged into the
/// request object's claims and `outer` appended to the query string.
fn jar_uri(
    rig: &Rig,
    client: &OAuthClient,
    pair: &ring::signature::Ed25519KeyPair,
    overrides: &serde_json::Value,
    outer: &str,
) -> String {
    format!(
        "/ui/oauth/authorize?client_id={}&request={}{outer}",
        client.client_id().as_uuid(),
        jar_jwt(rig, client, pair, overrides)
    )
}

/// A request object signed by `pair`, with `overrides` merged into its claims.
fn jar_jwt(
    rig: &Rig,
    client: &OAuthClient,
    pair: &ring::signature::Ed25519KeyPair,
    overrides: &serde_json::Value,
) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let cid = client.client_id().to_string();
    let realm_name = rig
        .identity
        .get_realm(&rig.realm_id)
        .expect("get_realm")
        .expect("realm")
        .name()
        .to_string();
    let now = i64::try_from(now_secs()).expect("now");
    let header = serde_json::json!({ "alg": "EdDSA", "kid": JAR_KID });
    let mut claims = serde_json::json!({
        "iss": cid,
        "aud": format!("https://hearth.local/realms/{realm_name}"),
        "exp": now + 600,
        "iat": now,
        "jti": uuid::Uuid::new_v4().to_string(),
        "client_id": cid,
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "scope": "openid",
        "state": "jar-state",
        "code_challenge": pkce_challenge(),
        "code_challenge_method": "S256",
    });
    if let (Some(claims), Some(overrides)) = (claims.as_object_mut(), overrides.as_object()) {
        for (k, v) in overrides {
            claims.insert(k.clone(), v.clone());
        }
    }
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
    let input = format!("{h}.{c}");
    let sig = URL_SAFE_NO_PAD.encode(pair.sign(input.as_bytes()).as_ref());
    format!("{input}.{sig}")
}

/// A pushed authorization request with the rig's defaults and no prompt,
/// response mode, resource or request object.
fn par_request(client: &OAuthClient) -> hearth::identity::PushedAuthorizationRequest {
    hearth::identity::PushedAuthorizationRequest {
        client_id: client.client_id().clone(),
        redirect_uri: REDIRECT.to_string(),
        scope: "openid".to_string(),
        state: "par-state".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: Some(pkce_challenge()),
        code_challenge_method: Some(hearth::identity::CodeChallengeMethod::S256),
        nonce: None,
        request: None,
        response_mode: None,
        prompt: None,
    }
}

/// Pushes `request` and returns the `request_uri` authorize URI.
fn push(rig: &Rig, request: &hearth::identity::PushedAuthorizationRequest) -> String {
    let pushed = rig
        .identity
        .push_authorization_request(&rig.realm_id, request)
        .expect("push");
    format!(
        "/ui/oauth/authorize?client_id={}&request_uri={}",
        request.client_id.as_uuid(),
        form_urlencoded::byte_serialize(pushed.request_uri.as_bytes()).collect::<String>()
    )
}

/// Pushes an authorization request and returns the `request_uri` authorize URI.
fn par_uri(
    rig: &Rig,
    client: &OAuthClient,
    response_mode: Option<&str>,
    resource: Option<&str>,
) -> String {
    let mut request = par_request(client);
    request.response_mode = response_mode.map(str::to_string);
    request.resource = resource.map(str::to_string);
    push(rig, &request)
}

/// Completes the pending UPDATE_PASSWORD action started by `authorize_resp`.
async fn complete_password_update(rig: &Rig, authorize_resp: &Response<Body>) -> Response<Body> {
    let ra = cookie_pair(authorize_resp, "hearth_ra_session").expect("RA cookie");
    let new_password = ["a", "fresh", "gate", "parity", "phrase", "3"].join("-");
    // The form token is bound to the RA session cookie; a `/ui` CSRF cookie
    // never reaches `/required-action/*` in a browser.
    let ra_value = ra
        .strip_prefix("hearth_ra_session=")
        .expect("RA cookie pair");
    let form_token = hearth::protocol::web::required_action::ra_form_token_for(
        &CookieSecret::from_bytes(COOKIE_SECRET),
        ra_value,
    );
    post_form(
        rig,
        "/required-action/UPDATE_PASSWORD",
        &ra,
        format!(
            "current_password={}&new_password={new_password}&confirm_password={new_password}\
             &_csrf={form_token}",
            password()
        ),
    )
    .await
}

/// Submits the SMS code for the challenge started by `authorize_resp`.
async fn pass_sms_challenge(
    rig: &Rig,
    cookies: &str,
    authorize_resp: &Response<Body>,
) -> Response<Body> {
    assert_eq!(location(authorize_resp), "/ui/sms-challenge");
    let sms_cookie = cookie_pair(authorize_resp, "hearth_ui_sms_mfa").expect("SMS cookie");
    let code = rig.sms.last_code();
    post_form(
        rig,
        "/ui/sms-challenge",
        &format!("{cookies}; {sms_cookie}"),
        format!("code={code}&_csrf={CSRF}"),
    )
    .await
}

// ===========================================================================
// Control: the plain branch (the reference behaviour)
// ===========================================================================

#[tokio::test]
async fn plain_authorize_for_a_consent_client_shows_the_consent_prompt() {
    let rig = rig(false).await;
    let client = register(&rig, true, None);
    let resp = get(&rig, &plain_uri(&client, ""), &session_cookie(&rig)).await;
    assert_consent_prompt(&resp, "plain");
}

// ===========================================================================
// JAR branch
// ===========================================================================

#[tokio::test]
async fn jar_authorize_for_a_consent_client_shows_the_consent_prompt() {
    let rig = rig(false).await;
    let (client, pair) = jar_client(&rig, true);
    let uri = jar_uri(&rig, &client, &pair, &serde_json::json!({}), "");
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    assert_consent_prompt(&resp, "JAR");
}

#[tokio::test]
async fn jar_authorize_with_prompt_none_and_no_consent_returns_consent_required() {
    let rig = rig(false).await;
    let (client, pair) = jar_client(&rig, true);
    let uri = jar_uri(&rig, &client, &pair, &serde_json::json!({}), "&prompt=none");
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    let loc = location(&resp);
    assert!(
        loc.starts_with(REDIRECT),
        "prompt=none must redirect back; got {loc}"
    );
    assert_eq!(
        redirect_param(&loc, "error", false).as_deref(),
        Some("consent_required"),
        "got {loc}"
    );
    assert!(
        redirect_param(&loc, "code", false).is_none(),
        "no code; got {loc}"
    );
    assert_eq!(
        redirect_param(&loc, "state", false).as_deref(),
        Some("jar-state")
    );
}

#[tokio::test]
async fn jar_request_object_prompt_none_is_honoured() {
    let rig = rig(false).await;
    let (client, pair) = jar_client(&rig, true);
    let uri = jar_uri(
        &rig,
        &client,
        &pair,
        &serde_json::json!({ "prompt": "none" }),
        "",
    );
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    let loc = location(&resp);
    assert_eq!(
        redirect_param(&loc, "error", false).as_deref(),
        Some("consent_required"),
        "a prompt=none request object must never show UI; got {loc}"
    );
}

#[tokio::test]
async fn jar_authorize_with_prompt_consent_reprompts_despite_a_recorded_consent() {
    let rig = rig(false).await;
    let (client, pair) = jar_client(&rig, true);
    grant_consent(&rig, &client);
    let uri = jar_uri(
        &rig,
        &client,
        &pair,
        &serde_json::json!({}),
        "&prompt=consent",
    );
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    assert_consent_prompt(&resp, "JAR prompt=consent");
}

/// Control: a recorded consent covering the scopes lets the JAR through.
#[tokio::test]
async fn jar_authorize_with_a_recorded_consent_issues_the_code() {
    let rig = rig(false).await;
    let (client, pair) = jar_client(&rig, true);
    grant_consent(&rig, &client);
    let uri = jar_uri(&rig, &client, &pair, &serde_json::json!({}), "");
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    let loc = location(&resp);
    assert!(redirect_param(&loc, "code", false).is_some(), "got {loc}");
    assert_eq!(
        redirect_param(&loc, "state", false).as_deref(),
        Some("jar-state")
    );
}

/// Approving the JAR's consent prompt issues the code with every JAR value:
/// its state, its `response_mode` and its RFC 8707 resource.
#[tokio::test]
async fn jar_consent_approval_keeps_the_jar_response_mode_and_resource() {
    let rig = rig(false).await;
    let (client, pair) = jar_client(&rig, true);
    let uri = jar_uri(
        &rig,
        &client,
        &pair,
        &serde_json::json!({ "response_mode": "fragment", "resource": RESOURCE }),
        "",
    );
    let cookies = session_cookie(&rig);
    let resp = get(&rig, &uri, &cookies).await;
    assert_consent_prompt(&resp, "JAR with resource");
    let resp = approve_consent(&rig, &cookies, &resp).await;
    let loc = location(&resp);
    let code = redirect_param(&loc, "code", true)
        .unwrap_or_else(|| panic!("fragment response_mode must deliver #code=; got {loc}"));
    assert_eq!(
        redirect_param(&loc, "state", true).as_deref(),
        Some("jar-state")
    );
    let aud = exchanged_audience(&rig, &client, Some(&pair), code);
    assert!(aud.iter().any(|a| a == RESOURCE), "aud = {aud:?}");
}

/// The request object's own `response_mode` claim wins over the outer query.
#[tokio::test]
async fn jar_request_object_response_mode_is_honoured() {
    let rig = rig(false).await;
    let (client, pair) = jar_client(&rig, false);
    let uri = jar_uri(
        &rig,
        &client,
        &pair,
        &serde_json::json!({ "response_mode": "fragment" }),
        "",
    );
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    let loc = location(&resp);
    assert!(
        redirect_param(&loc, "code", true).is_some(),
        "the JAR's response_mode=fragment must deliver #code=; got {loc}"
    );
}

// ===========================================================================
// PAR branch
// ===========================================================================

#[tokio::test]
async fn par_authorize_for_a_consent_client_shows_the_consent_prompt() {
    let rig = rig(false).await;
    let client = register(&rig, true, None);
    let uri = par_uri(&rig, &client, None, None);
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    assert_consent_prompt(&resp, "PAR");
}

#[tokio::test]
async fn par_stored_response_mode_is_honoured() {
    let rig = rig(false).await;
    let client = register(&rig, false, None);
    let uri = par_uri(&rig, &client, Some("fragment"), None);
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    let loc = location(&resp);
    assert!(
        redirect_param(&loc, "code", true).is_some(),
        "the pushed response_mode=fragment must deliver #code=; got {loc}"
    );
    assert_eq!(
        redirect_param(&loc, "state", true).as_deref(),
        Some("par-state")
    );
}

/// Consent approval for a pushed request keeps its resource, response mode
/// and PAR origin.
#[tokio::test]
async fn par_consent_approval_keeps_the_pushed_response_mode_and_resource() {
    let rig = rig(false).await;
    let client = register(&rig, true, None);
    let uri = par_uri(&rig, &client, Some("fragment"), Some(RESOURCE));
    let cookies = session_cookie(&rig);
    let resp = get(&rig, &uri, &cookies).await;
    assert_consent_prompt(&resp, "PAR with resource");
    let resp = approve_consent(&rig, &cookies, &resp).await;
    let loc = location(&resp);
    let code = redirect_param(&loc, "code", true)
        .unwrap_or_else(|| panic!("fragment response_mode must deliver #code=; got {loc}"));
    let aud = exchanged_audience(&rig, &client, None, code);
    assert!(aud.iter().any(|a| a == RESOURCE), "aud = {aud:?}");
}

// ---------------------------------------------------------------------------
// PAR: `prompt` is pushed like every other parameter
//
// A pushed request had no way to carry `prompt`: the PAR endpoint had no
// field for it, the stored entry had none, a JAR pushed through PAR lost its
// `prompt` claim, and the authorize branch hard-coded it empty. On a FAPI 2.0
// realm, where PAR is mandatory, `prompt` could never take effect.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn par_authorize_with_prompt_none_and_no_consent_returns_consent_required() {
    let rig = rig(false).await;
    let client = register(&rig, true, None);
    let mut request = par_request(&client);
    request.prompt = Some("none".to_string());
    let resp = get(&rig, &push(&rig, &request), &session_cookie(&rig)).await;
    let loc = location(&resp);
    assert!(
        loc.starts_with(REDIRECT),
        "a pushed prompt=none must redirect back, never show the consent page; got {loc}"
    );
    assert_eq!(
        redirect_param(&loc, "error", false).as_deref(),
        Some("consent_required"),
        "got {loc}"
    );
    assert_eq!(
        redirect_param(&loc, "state", false).as_deref(),
        Some("par-state")
    );
    assert!(redirect_param(&loc, "code", false).is_none(), "got {loc}");
}

#[tokio::test]
async fn par_authorize_with_prompt_consent_reprompts_despite_a_recorded_consent() {
    let rig = rig(false).await;
    let client = register(&rig, true, None);
    grant_consent(&rig, &client);
    let mut request = par_request(&client);
    request.prompt = Some("consent".to_string());
    let resp = get(&rig, &push(&rig, &request), &session_cookie(&rig)).await;
    assert_consent_prompt(&resp, "PAR prompt=consent");
}

/// Control: without a pushed prompt a recorded consent lets the request through.
#[tokio::test]
async fn par_authorize_with_a_recorded_consent_issues_the_code() {
    let rig = rig(false).await;
    let client = register(&rig, true, None);
    grant_consent(&rig, &client);
    let resp = get(
        &rig,
        &push(&rig, &par_request(&client)),
        &session_cookie(&rig),
    )
    .await;
    let loc = location(&resp);
    assert!(redirect_param(&loc, "code", false).is_some(), "got {loc}");
}

/// A request object pushed through PAR keeps its `prompt` claim.
#[tokio::test]
async fn par_pushed_request_object_prompt_none_is_honoured() {
    let rig = rig(false).await;
    let (client, pair) = jar_client(&rig, true);
    let mut request = par_request(&client);
    request.request = Some(jar_jwt(
        &rig,
        &client,
        &pair,
        &serde_json::json!({ "prompt": "none" }),
    ));
    let resp = get(&rig, &push(&rig, &request), &session_cookie(&rig)).await;
    let loc = location(&resp);
    assert_eq!(
        redirect_param(&loc, "error", false).as_deref(),
        Some("consent_required"),
        "the pushed request object's prompt=none must never show UI; got {loc}"
    );
    assert_eq!(
        redirect_param(&loc, "state", false).as_deref(),
        Some("jar-state")
    );
}

/// RFC 9101 §4: the request object's `prompt` claim wins over the pushed
/// outer value.
#[tokio::test]
async fn par_pushed_request_object_prompt_wins_over_the_outer_prompt() {
    let rig = rig(false).await;
    let (client, pair) = jar_client(&rig, true);
    grant_consent(&rig, &client);
    let mut request = par_request(&client);
    request.prompt = Some("consent".to_string());
    request.request = Some(jar_jwt(
        &rig,
        &client,
        &pair,
        &serde_json::json!({ "prompt": "none" }),
    ));
    let resp = get(&rig, &push(&rig, &request), &session_cookie(&rig)).await;
    let loc = location(&resp);
    assert!(
        redirect_param(&loc, "code", false).is_some(),
        "prompt=none (claim) over prompt=consent (outer) with a recorded consent issues \
         the code silently; got {loc} ({})",
        resp.status()
    );
}

/// RFC 9126 §4: only the pushed values count — a `prompt` added to the
/// authorize query next to `request_uri` is ignored, so it cannot strip a
/// pushed `prompt=consent` or add a `prompt=none` the client never pushed.
#[tokio::test]
async fn par_authorize_ignores_a_prompt_on_the_authorize_query() {
    let rig = rig(false).await;
    let client = register(&rig, true, None);
    let uri = format!("{}&prompt=none", push(&rig, &par_request(&client)));
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    assert_consent_prompt(&resp, "PAR with an outer prompt=none");
}

/// The engine itself must honour a plain `fragment` response mode: discovery
/// advertises it, but the code response always came back as `query`.
#[tokio::test]
async fn engine_authorize_honours_the_fragment_response_mode() {
    let rig = rig(false).await;
    let client = register(&rig, false, None);
    let resp = rig
        .identity
        .authorize(
            &rig.realm_id,
            &hearth::identity::AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: REDIRECT.to_string(),
                scope: "openid".to_string(),
                state: "engine-state".to_string(),
                resource: None,
                response_type: "code".to_string(),
                user_id: rig.user_id.clone(),
                code_challenge: Some(pkce_challenge()),
                code_challenge_method: Some(hearth::identity::CodeChallengeMethod::S256),
                nonce: None,
                amr_values: Vec::new(),
                response_mode: Some(hearth::identity::ResponseMode::Fragment),
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");
    assert_eq!(
        resp.response_mode(),
        &hearth::identity::ResponseMode::Fragment
    );
}

// ===========================================================================
// Error responses use the request's response mode
//
// OAuth Multiple Response Types §2.1 and JARM §2.3: the response mode governs
// the error response too. Errors used to go to the query string, unsigned
// unless the client had a registered signing alg, whatever mode was asked for
// — so a silent-auth SPA using `fragment` got its code in the fragment but
// `consent_required` in the query, and a `query.jwt` request got an unsigned
// error.
// ===========================================================================

/// The error must be in the fragment, not the query, and carry the state.
fn assert_fragment_error(loc: &str, error: &str, state: &str) {
    assert!(loc.starts_with(REDIRECT), "got {loc}");
    assert_eq!(
        redirect_param(loc, "error", true).as_deref(),
        Some(error),
        "the error must travel in the fragment; got {loc}"
    );
    assert_eq!(redirect_param(loc, "state", true).as_deref(), Some(state));
    assert!(
        redirect_param(loc, "error", false).is_none(),
        "no error in the query string; got {loc}"
    );
}

#[tokio::test]
async fn plain_prompt_none_error_uses_the_fragment_response_mode() {
    let rig = rig(false).await;
    let client = register(&rig, true, None);
    let uri = plain_uri(&client, "&prompt=none&response_mode=fragment");
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    assert_fragment_error(&location(&resp), "consent_required", "plain-state");
}

#[tokio::test]
async fn jar_prompt_none_error_uses_the_fragment_response_mode() {
    let rig = rig(false).await;
    let (client, pair) = jar_client(&rig, true);
    let uri = jar_uri(
        &rig,
        &client,
        &pair,
        &serde_json::json!({ "prompt": "none", "response_mode": "fragment" }),
        "",
    );
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    assert_fragment_error(&location(&resp), "consent_required", "jar-state");
}

#[tokio::test]
async fn par_prompt_none_error_uses_the_fragment_response_mode() {
    let rig = rig(false).await;
    let client = register(&rig, true, None);
    let mut request = par_request(&client);
    request.prompt = Some("none".to_string());
    request.response_mode = Some("fragment".to_string());
    let resp = get(&rig, &push(&rig, &request), &session_cookie(&rig)).await;
    assert_fragment_error(&location(&resp), "consent_required", "par-state");
}

#[tokio::test]
async fn consent_denial_uses_the_fragment_response_mode() {
    let rig = rig(false).await;
    let client = register(&rig, true, None);
    let uri = par_uri(&rig, &client, Some("fragment"), None);
    let cookies = session_cookie(&rig);
    let resp = get(&rig, &uri, &cookies).await;
    assert_consent_prompt(&resp, "PAR fragment");
    let resp = decide_consent(&rig, &cookies, &resp, "deny").await;
    assert_fragment_error(&location(&resp), "access_denied", "par-state");
}

/// A request validation error on the plain branch, once the redirect URI is
/// confirmed, also goes where the request asked.
#[tokio::test]
async fn plain_request_error_uses_the_fragment_response_mode() {
    let rig = rig(false).await;
    let client = register(&rig, false, None);
    let uri = format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb\
         &response_type=code&scope=openid&state=plain-state&code_challenge={}\
         &code_challenge_method=plain&response_mode=fragment",
        client.client_id().as_uuid(),
        pkce_challenge()
    );
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    assert_fragment_error(&location(&resp), "invalid_request", "plain-state");
}

/// `query.jwt` asked by a client with no registered signing alg: the error
/// is a signed `?response=` JWT, as the code would have been.
#[tokio::test]
async fn jar_prompt_none_error_uses_the_query_jwt_response_mode() {
    let rig = rig(false).await;
    let (client, pair) = jar_client(&rig, true);
    assert!(client.authorization_signed_response_alg().is_none());
    let uri = jar_uri(
        &rig,
        &client,
        &pair,
        &serde_json::json!({ "prompt": "none", "response_mode": "query.jwt" }),
        "",
    );
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    let loc = location(&resp);
    assert!(
        redirect_param(&loc, "error", false).is_none(),
        "a JARM request must not get a plain error; got {loc}"
    );
    let jwt = redirect_param(&loc, "response", false)
        .unwrap_or_else(|| panic!("query.jwt must deliver ?response=<jwt>; got {loc}"));
    let claims = jwt_claims(&jwt);
    assert_eq!(claims["error"], "consent_required", "claims {claims}");
    assert_eq!(claims["state"], "jar-state", "claims {claims}");
}

#[tokio::test]
async fn par_prompt_none_error_uses_the_fragment_jwt_response_mode() {
    let rig = rig(false).await;
    let client = register(&rig, true, None);
    let mut request = par_request(&client);
    request.prompt = Some("none".to_string());
    request.response_mode = Some("fragment.jwt".to_string());
    let resp = get(&rig, &push(&rig, &request), &session_cookie(&rig)).await;
    let loc = location(&resp);
    assert!(
        redirect_param(&loc, "response", false).is_none()
            && redirect_param(&loc, "error", false).is_none(),
        "nothing in the query string; got {loc}"
    );
    let jwt = redirect_param(&loc, "response", true)
        .unwrap_or_else(|| panic!("fragment.jwt must deliver #response=<jwt>; got {loc}"));
    let claims = jwt_claims(&jwt);
    assert_eq!(claims["error"], "consent_required", "claims {claims}");
    assert_eq!(claims["state"], "par-state", "claims {claims}");
}

// ===========================================================================
// SMS challenge resume
// ===========================================================================

#[tokio::test]
async fn sms_resume_for_a_consent_client_shows_the_consent_prompt() {
    let rig = rig(true).await;
    let client = register(&rig, true, None);
    let cookies = session_cookie(&rig);
    let resp = get(&rig, &plain_uri(&client, ""), &cookies).await;
    let resp = pass_sms_challenge(&rig, &cookies, &resp).await;
    assert_consent_prompt(&resp, "after the SMS challenge");
}

#[tokio::test]
async fn sms_resume_keeps_the_requested_response_mode() {
    let rig = rig(true).await;
    let client = register(&rig, false, None);
    let cookies = session_cookie(&rig);
    let resp = get(
        &rig,
        &plain_uri(&client, "&response_mode=fragment"),
        &cookies,
    )
    .await;
    let resp = pass_sms_challenge(&rig, &cookies, &resp).await;
    let loc = location(&resp);
    assert!(
        redirect_param(&loc, "code", true).is_some(),
        "response_mode=fragment must survive the SMS challenge; got {loc}"
    );
}

/// JAR + SMS + consent: the JAR's resource and response mode survive both
/// interstitials, and the consent ticket carries them to the code.
#[tokio::test]
async fn jar_through_sms_and_consent_keeps_resource_and_response_mode() {
    let rig = rig(true).await;
    let (client, pair) = jar_client(&rig, true);
    let uri = jar_uri(
        &rig,
        &client,
        &pair,
        &serde_json::json!({ "response_mode": "fragment", "resource": RESOURCE }),
        "",
    );
    let cookies = session_cookie(&rig);
    let resp = get(&rig, &uri, &cookies).await;
    let resp = pass_sms_challenge(&rig, &cookies, &resp).await;
    assert_consent_prompt(&resp, "JAR after SMS");
    let resp = approve_consent(&rig, &cookies, &resp).await;
    let loc = location(&resp);
    let code = redirect_param(&loc, "code", true)
        .unwrap_or_else(|| panic!("fragment response_mode must deliver #code=; got {loc}"));
    let aud = exchanged_audience(&rig, &client, Some(&pair), code);
    assert!(aud.iter().any(|a| a == RESOURCE), "aud = {aud:?}");
}

// ===========================================================================
// Required-action resume
// ===========================================================================

#[tokio::test]
async fn required_action_resume_for_a_consent_client_shows_the_consent_prompt() {
    let rig = rig(false).await;
    require_password_update(&rig);
    let client = register(&rig, true, None);
    let resp = get(&rig, &plain_uri(&client, ""), &session_cookie(&rig)).await;
    let resp = complete_password_update(&rig, &resp).await;
    assert_consent_prompt(&resp, "after a required action");
}

#[tokio::test]
async fn required_action_resume_keeps_prompt_consent() {
    let rig = rig(false).await;
    require_password_update(&rig);
    let client = register(&rig, true, None);
    grant_consent(&rig, &client);
    let resp = get(
        &rig,
        &plain_uri(&client, "&prompt=consent"),
        &session_cookie(&rig),
    )
    .await;
    let resp = complete_password_update(&rig, &resp).await;
    assert_consent_prompt(&resp, "prompt=consent after a required action");
}

#[tokio::test]
async fn required_action_resume_on_a_par_request_keeps_the_response_mode() {
    let rig = rig(false).await;
    require_password_update(&rig);
    let client = register(&rig, false, None);
    let uri = par_uri(&rig, &client, Some("fragment"), None);
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    let resp = complete_password_update(&rig, &resp).await;
    let loc = location(&resp);
    assert!(
        redirect_param(&loc, "code", true).is_some(),
        "the pushed response_mode must survive the required action; got {loc} ({})",
        resp.status()
    );
}

// ===========================================================================
// prompt=none never reaches an interstitial
//
// OIDC Core §3.1.2.1: with `prompt=none` the server MUST NOT display any
// authentication or consent UI. The gate sequence honoured it only at the
// consent gate; the required-action intercept and the SMS challenge ran
// first and suspended the flow into an interactive page — and the SMS gate
// texted the user a code on every silent renew.
// ===========================================================================

/// A silent refusal: back to the client with `error`, no code, no
/// interstitial cookie.
fn assert_silent_refusal(resp: &Response<Body>, error: &str, state: &str, what: &str) {
    let loc = location(resp);
    assert!(
        loc.starts_with(REDIRECT),
        "{what}: prompt=none must redirect back to the client, never to an interstitial; \
         got {loc} ({})",
        resp.status()
    );
    assert_eq!(
        redirect_param(&loc, "error", false).as_deref(),
        Some(error),
        "{what}: got {loc}"
    );
    assert_eq!(
        redirect_param(&loc, "state", false).as_deref(),
        Some(state),
        "{what}: got {loc}"
    );
    assert!(
        redirect_param(&loc, "code", false).is_none(),
        "{what}: no code; got {loc}"
    );
    assert!(
        cookie_pair(resp, "hearth_ra_session").is_none(),
        "{what}: no required-action session may be started"
    );
    assert!(
        cookie_pair(resp, "hearth_ui_sms_mfa").is_none(),
        "{what}: no SMS challenge may be started"
    );
}

fn sms_sent(rig: &Rig) -> usize {
    #[allow(clippy::unwrap_used)]
    rig.sms.messages.lock().unwrap().len()
}

#[tokio::test]
async fn plain_prompt_none_with_a_pending_required_action_is_interaction_required() {
    let rig = rig(false).await;
    require_password_update(&rig);
    let client = register(&rig, false, None);
    let resp = get(
        &rig,
        &plain_uri(&client, "&prompt=none"),
        &session_cookie(&rig),
    )
    .await;
    assert_silent_refusal(&resp, "interaction_required", "plain-state", "plain");
}

#[tokio::test]
async fn jar_prompt_none_with_a_pending_required_action_is_interaction_required() {
    let rig = rig(false).await;
    require_password_update(&rig);
    let (client, pair) = jar_client(&rig, false);
    let uri = jar_uri(
        &rig,
        &client,
        &pair,
        &serde_json::json!({ "prompt": "none" }),
        "",
    );
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    assert_silent_refusal(&resp, "interaction_required", "jar-state", "JAR");
}

#[tokio::test]
async fn par_prompt_none_with_a_pending_required_action_is_interaction_required() {
    let rig = rig(false).await;
    require_password_update(&rig);
    let client = register(&rig, false, None);
    let mut request = par_request(&client);
    request.prompt = Some("none".to_string());
    let resp = get(&rig, &push(&rig, &request), &session_cookie(&rig)).await;
    assert_silent_refusal(&resp, "interaction_required", "par-state", "PAR");
}

#[tokio::test]
async fn plain_prompt_none_on_an_sms_realm_is_login_required_and_sends_no_text() {
    let rig = rig(true).await;
    let client = register(&rig, false, None);
    let resp = get(
        &rig,
        &plain_uri(&client, "&prompt=none"),
        &session_cookie(&rig),
    )
    .await;
    assert_silent_refusal(&resp, "login_required", "plain-state", "plain SMS");
    assert_eq!(sms_sent(&rig), 0, "a silent request must not text the user");
}

#[tokio::test]
async fn jar_prompt_none_on_an_sms_realm_is_login_required_and_sends_no_text() {
    let rig = rig(true).await;
    let (client, pair) = jar_client(&rig, false);
    let uri = jar_uri(
        &rig,
        &client,
        &pair,
        &serde_json::json!({ "prompt": "none" }),
        "",
    );
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    assert_silent_refusal(&resp, "login_required", "jar-state", "JAR SMS");
    assert_eq!(sms_sent(&rig), 0, "a silent request must not text the user");
}

#[tokio::test]
async fn par_prompt_none_on_an_sms_realm_is_login_required_and_sends_no_text() {
    let rig = rig(true).await;
    let client = register(&rig, false, None);
    let mut request = par_request(&client);
    request.prompt = Some("none".to_string());
    let resp = get(&rig, &push(&rig, &request), &session_cookie(&rig)).await;
    assert_silent_refusal(&resp, "login_required", "par-state", "PAR SMS");
    assert_eq!(sms_sent(&rig), 0, "a silent request must not text the user");
}

/// The silent refusal travels in the request's response mode like any other
/// authorization error.
#[tokio::test]
async fn prompt_none_interstitial_refusal_uses_the_fragment_response_mode() {
    let rig = rig(false).await;
    require_password_update(&rig);
    let client = register(&rig, false, None);
    let resp = get(
        &rig,
        &plain_uri(&client, "&prompt=none&response_mode=fragment"),
        &session_cookie(&rig),
    )
    .await;
    assert_fragment_error(&location(&resp), "interaction_required", "plain-state");
}

/// Control: the same SMS-realm request without `prompt=none` is challenged.
#[tokio::test]
async fn interactive_request_on_an_sms_realm_is_still_challenged() {
    let rig = rig(true).await;
    let client = register(&rig, false, None);
    let resp = get(&rig, &plain_uri(&client, ""), &session_cookie(&rig)).await;
    assert_eq!(location(&resp), "/ui/sms-challenge");
    assert_eq!(sms_sent(&rig), 1);
}

// ===========================================================================
// Required-action lookup errors fail closed
// ===========================================================================

/// `usr:id:` — the user-record key family (crate-private, restated here).
const USER_ID_PREFIX: &[u8] = b"usr:id:";
/// `oauth:client:` — the OAuth client key family.
const OAUTH_CLIENT_PREFIX: &[u8] = b"oauth:client:";
/// `realm:id:` — the realm-record key family.
const REALM_ID_PREFIX: &[u8] = b"realm:id:";

/// Fails user-record reads while `armed`, and arms itself once the OAuth
/// client record has been read (`arm_on_client_read`) — which on the
/// authorize path happens after the session extractor loaded the user and
/// before the required-action intercept does.
struct UserReadFault {
    inner: Arc<EmbeddedStorageEngine>,
    armed: Arc<AtomicBool>,
    arm_on_client_read: Arc<AtomicBool>,
    /// Fails realm-record reads instead, independently of `armed`.
    realm_armed: Arc<AtomicBool>,
    /// A one-shot fault: once `one_shot` holds a key prefix, the first user
    /// read after an OAuth client read (the required-action intercept's own
    /// user lookup, after the authorize branch loaded the client) makes the
    /// next `get` or `scan` under that prefix fail — exactly once, so a later
    /// read of the same record (the consent gate's) succeeds.
    one_shot: Arc<Mutex<Option<Vec<u8>>>>,
    client_seen: AtomicBool,
    one_shot_live: AtomicBool,
    one_shot_fired: Arc<AtomicBool>,
}

impl UserReadFault {
    /// Tracks the arming sequence and reports whether a read of `key`
    /// must fail now.
    fn one_shot_fault(&self, key: &[u8]) -> bool {
        #[allow(clippy::unwrap_used)]
        let target = self.one_shot.lock().unwrap().clone();
        let Some(target) = target else {
            return false;
        };
        if self.one_shot_fired.load(Ordering::SeqCst) {
            return false;
        }
        if self.one_shot_live.load(Ordering::SeqCst) && key.starts_with(&target) {
            self.one_shot_fired.store(true, Ordering::SeqCst);
            return true;
        }
        if key.starts_with(OAUTH_CLIENT_PREFIX) {
            self.client_seen.store(true, Ordering::SeqCst);
        } else if key.starts_with(USER_ID_PREFIX) && self.client_seen.load(Ordering::SeqCst) {
            self.one_shot_live.store(true, Ordering::SeqCst);
        }
        false
    }
}

impl StorageEngine for UserReadFault {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        if self.one_shot_fault(key) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected one-shot read fault",
            )));
        }
        if key.starts_with(OAUTH_CLIENT_PREFIX) && self.arm_on_client_read.load(Ordering::SeqCst) {
            self.armed.store(true, Ordering::SeqCst);
        }
        if self.armed.load(Ordering::SeqCst) && key.starts_with(USER_ID_PREFIX) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected user-record read fault",
            )));
        }
        if self.realm_armed.load(Ordering::SeqCst) && key.starts_with(REALM_ID_PREFIX) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected realm-record read fault",
            )));
        }
        self.inner.get(realm_id, key)
    }

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.inner.put(realm_id, key, value)
    }

    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(realm_id, key)
    }

    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        if self.one_shot_fault(start) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected one-shot scan fault",
            )));
        }
        self.inner.scan(realm_id, start, end)
    }

    fn list_realms(&self) -> Result<Vec<RealmId>, StorageError> {
        self.inner.list_realms()
    }

    fn begin_snapshot_restore(&self, snapshot_id: &str) -> Result<(), StorageError> {
        self.inner.begin_snapshot_restore(snapshot_id)
    }

    fn complete_snapshot_restore(&self) -> Result<(), StorageError> {
        self.inner.complete_snapshot_restore()
    }
}

struct FaultRig {
    _temp: tempfile::TempDir,
    state: Arc<WebState>,
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    user_id: UserId,
    armed: Arc<AtomicBool>,
    arm_on_client_read: Arc<AtomicBool>,
    realm_armed: Arc<AtomicBool>,
    rbac: Arc<dyn RbacEngine>,
    one_shot: Arc<Mutex<Option<Vec<u8>>>>,
    one_shot_fired: Arc<AtomicBool>,
}

fn fault_rig() -> FaultRig {
    fault_rig_with(None, vec![RequiredAction::UpdatePassword])
}

/// The fault rig with a realm `config` and the user's stored `pending` actions.
fn fault_rig_with(config: Option<RealmConfig>, pending: Vec<RequiredAction>) -> FaultRig {
    let temp = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(temp.path().join("data")))
            .expect("open storage"),
    );
    let armed = Arc::new(AtomicBool::new(false));
    let arm_on_client_read = Arc::new(AtomicBool::new(false));
    let realm_armed = Arc::new(AtomicBool::new(false));
    let one_shot = Arc::new(Mutex::new(None));
    let one_shot_fired = Arc::new(AtomicBool::new(false));
    let storage: Arc<dyn StorageEngine> = Arc::new(UserReadFault {
        inner,
        armed: Arc::clone(&armed),
        arm_on_client_read: Arc::clone(&arm_on_client_read),
        realm_armed: Arc::clone(&realm_armed),
        one_shot: Arc::clone(&one_shot),
        client_seen: AtomicBool::new(false),
        one_shot_live: AtomicBool::new(false),
        one_shot_fired: Arc::clone(&one_shot_fired),
    });
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let rbac: Arc<dyn RbacEngine> = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let audit: Arc<dyn AuditEngine> = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let identity: Arc<dyn IdentityEngine> = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&storage),
            clock,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&rbac),
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    );
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("gate-fault-{}", uuid::Uuid::new_v4()),
            config,
        })
        .expect("realm");
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: USER_EMAIL.to_string(),
                display_name: "Fault".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("user");
    identity
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                required_actions: Some(pending),
                ..Default::default()
            },
        )
        .expect("activate with the pending actions");
    let state = web_state(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        audit,
        temp.path().join("onboarding"),
    )
    .with_default_realm(Some(realm.name().to_string()));
    FaultRig {
        app: web::router(state.clone()),
        state: Arc::new(state),
        _temp: temp,
        identity,
        realm_id: realm.id().clone(),
        user_id: user.id().clone(),
        armed,
        arm_on_client_read,
        realm_armed,
        rbac,
        one_shot,
        one_shot_fired,
    }
}

/// A signed UI session cookie (plus the CSRF cookie) for the fault rig's user.
fn fault_session_cookie(rig: &FaultRig) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let session = rig
        .identity
        .create_session(
            &rig.realm_id,
            &rig.user_id,
            &SessionContext {
                // The user may hold a second factor, and a session must say it
                // proved one (GA audit B4/B5): this stands for a completed login.
                mfa_proof: hearth::identity::MfaProof::Proved,
                ..SessionContext::default()
            },
        )
        .expect("session");
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("key");
    mac.update(session.id().as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{tag}; hearth_ui_csrf={CSRF}",
        session.id().as_uuid(),
        rig.realm_id.as_uuid(),
    )
}

async fn fault_get(rig: &FaultRig, uri: &str, cookies: &str) -> Response<Body> {
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, cookies)
                .body(Body::empty())
                .expect("build GET"),
        )
        .await
        .expect("GET")
}

/// A first-party client (no consent), optionally requiring MFA.
fn fault_client(rig: &FaultRig, mfa_required: bool) -> OAuthClient {
    rig.identity
        .register_client(
            &rig.realm_id,
            &RegisterClientRequest {
                client_name: "Fault MFA app".to_string(),
                redirect_uris: vec![REDIRECT.to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                mfa_required: mfa_required.then_some(true),
                trust_level: hearth::identity::ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("client")
}

// ===========================================================================
// The MFA-enrolment requirement fails closed too
//
// `inject_enroll_mfa_if_needed` read a client or RBAC lookup error as "MFA
// not required": EnrollMfa was skipped and — with the consent gate's own
// client read succeeding — the code was issued without the enrolment the
// client or the user's role mandates.
// ===========================================================================

const RBAC_USER_ASSIGNMENT_PREFIX: &[u8] = b"rba:assign:user:";

/// A realm whose `admin` role mandates MFA, and a user holding it with no
/// enrolled factor.
fn role_mfa_rig() -> FaultRig {
    let rig = fault_rig_with(
        Some(RealmConfig {
            mfa_required_roles: Some(vec!["gate-admin".to_string()]),
            ..RealmConfig::default()
        }),
        Vec::new(),
    );
    let role = rig
        .rbac
        .create_role(
            &rig.realm_id,
            &hearth::rbac::CreateRoleRequest {
                name: "gate-admin".to_string(),
                description: None,
                permissions: vec![hearth::rbac::Permission::new("docs.read").expect("perm")],
                parent_roles: vec![],
                scope_kind: hearth::rbac::RoleScopeKind::Realm,
                allow_reserved_permissions: false,
            },
        )
        .expect("role");
    rig.rbac
        .assign_role(
            &rig.realm_id,
            &hearth::rbac::AssignRoleRequest {
                subject: hearth::rbac::Subject::User(rig.user_id.clone()),
                role_id: role.id.clone(),
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign");
    rig
}

/// Control: a client with `mfa_required` routes an unenrolled user to
/// enrolment.
#[tokio::test]
async fn client_mfa_requirement_routes_to_enrolment() {
    let rig = fault_rig_with(None, Vec::new());
    let client = fault_client(&rig, true);
    let resp = fault_get(&rig, &plain_uri(&client, ""), &fault_session_cookie(&rig)).await;
    assert_eq!(
        location(&resp),
        "/required-action/enroll-mfa",
        "status {}",
        resp.status()
    );
}

#[tokio::test]
async fn authorize_fails_closed_when_the_client_mfa_lookup_errors() {
    let rig = fault_rig_with(None, Vec::new());
    let client = fault_client(&rig, true);
    let cookies = fault_session_cookie(&rig);
    #[allow(clippy::unwrap_used)]
    {
        *rig.one_shot.lock().unwrap() = Some(OAUTH_CLIENT_PREFIX.to_vec());
    }
    let resp = fault_get(&rig, &plain_uri(&client, ""), &cookies).await;
    assert!(
        rig.one_shot_fired.load(Ordering::SeqCst),
        "rig sanity: the one-shot client-read fault must have fired"
    );
    let loc = location(&resp);
    assert!(
        !loc.starts_with(REDIRECT),
        "a client lookup error must not skip the client's MFA requirement; got {loc}"
    );
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "got {loc}"
    );
}

/// Control: a role in `mfa_required_roles` routes an unenrolled user to
/// enrolment.
#[tokio::test]
async fn role_mfa_requirement_routes_to_enrolment() {
    let rig = role_mfa_rig();
    let client = fault_client(&rig, false);
    let resp = fault_get(&rig, &plain_uri(&client, ""), &fault_session_cookie(&rig)).await;
    assert_eq!(
        location(&resp),
        "/required-action/enroll-mfa",
        "status {}",
        resp.status()
    );
}

#[tokio::test]
async fn authorize_fails_closed_when_the_role_mfa_lookup_errors() {
    let rig = role_mfa_rig();
    let client = fault_client(&rig, false);
    let cookies = fault_session_cookie(&rig);
    #[allow(clippy::unwrap_used)]
    {
        *rig.one_shot.lock().unwrap() = Some(RBAC_USER_ASSIGNMENT_PREFIX.to_vec());
    }
    let resp = fault_get(&rig, &plain_uri(&client, ""), &cookies).await;
    assert!(
        rig.one_shot_fired.load(Ordering::SeqCst),
        "rig sanity: the one-shot RBAC-read fault must have fired"
    );
    let loc = location(&resp);
    assert!(
        !loc.starts_with(REDIRECT),
        "an RBAC lookup error must not skip the role's MFA requirement; got {loc}"
    );
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "got {loc}"
    );
}

/// The OIDC intercept: a user-lookup error must not read as "no required
/// actions" and issue the code past a pending forced password change.
#[tokio::test]
async fn authorize_fails_closed_when_the_required_action_lookup_errors() {
    let rig = fault_rig();
    let client = rig
        .identity
        .register_client(
            &rig.realm_id,
            &RegisterClientRequest {
                client_name: "Fault app".to_string(),
                redirect_uris: vec![REDIRECT.to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                ..Default::default()
            },
        )
        .expect("client");
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let session = rig
        .identity
        .create_session(
            &rig.realm_id,
            &rig.user_id,
            &SessionContext {
                // The user may hold a second factor, and a session must say it
                // proved one (GA audit B4/B5): this stands for a completed login.
                mfa_proof: hearth::identity::MfaProof::Proved,
                ..SessionContext::default()
            },
        )
        .expect("session");
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("key");
    mac.update(session.id().as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    let cookies = format!(
        "hearth_ui_session={}.{}.{tag}; hearth_ui_csrf={CSRF}",
        session.id().as_uuid(),
        rig.realm_id.as_uuid(),
    );

    rig.arm_on_client_read.store(true, Ordering::SeqCst);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(plain_uri(&client, ""))
                .header(header::COOKIE, cookies)
                .body(Body::empty())
                .expect("build authorize"),
        )
        .await
        .expect("authorize");
    assert!(
        rig.armed.load(Ordering::SeqCst),
        "rig sanity: the fault must have been armed by the client read"
    );
    let loc = location(&resp);
    assert!(
        !loc.starts_with(REDIRECT),
        "a user-lookup error must not issue a code past a pending action; got {loc}"
    );
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "got {loc}"
    );
}

/// The browser-login intercept: same rule.
#[tokio::test]
async fn browser_required_action_check_fails_closed_on_a_lookup_error() {
    let rig = fault_rig();
    rig.armed.store(true, Ordering::SeqCst);
    let resp = web::required_action::required_action_check_browser(
        &rig.state,
        &rig.realm_id,
        &rig.user_id,
        None,
        &axum::http::HeaderMap::new(),
        Timestamp::from_micros(0),
    );
    let resp = resp.expect("a lookup error must be refused, not read as \"no actions\"");
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// The realm-driven enrolment requirements (SMS / email OTP / passkey) are
/// read from the realm record; a lookup error there must not read as "the
/// realm requires nothing" either.
#[tokio::test]
async fn browser_required_action_check_fails_closed_on_a_realm_lookup_error() {
    let rig = fault_rig();
    rig.identity
        .update_user(
            &rig.realm_id,
            &rig.user_id,
            &UpdateUserRequest {
                required_actions: Some(Vec::new()),
                ..Default::default()
            },
        )
        .expect("clear the stored actions");
    rig.realm_armed.store(true, Ordering::SeqCst);
    let resp = web::required_action::required_action_check_browser(
        &rig.state,
        &rig.realm_id,
        &rig.user_id,
        None,
        &axum::http::HeaderMap::new(),
        Timestamp::from_micros(0),
    );
    let resp =
        resp.expect("a realm lookup error must be refused, not read as \"nothing required\"");
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// Control: without the fault the same user is routed into the action.
#[tokio::test]
async fn browser_required_action_check_routes_a_pending_action() {
    let rig = fault_rig();
    let resp = web::required_action::required_action_check_browser(
        &rig.state,
        &rig.realm_id,
        &rig.user_id,
        None,
        &axum::http::HeaderMap::new(),
        Timestamp::from_micros(0),
    )
    .expect("a pending action intercepts");
    assert_eq!(
        location_of(&resp),
        "/required-action/UPDATE_PASSWORD",
        "status {}",
        resp.status()
    );
}

/// "User not found" keeps its meaning — nothing is pending for a record that
/// does not exist; the step that mints the session or code is what refuses a
/// missing user (`create_session` / the code exchange return `UserNotFound`).
#[tokio::test]
async fn browser_required_action_check_treats_a_missing_user_as_nothing_pending() {
    let rig = fault_rig();
    let resp = web::required_action::required_action_check_browser(
        &rig.state,
        &rig.realm_id,
        &UserId::new(uuid::Uuid::new_v4()),
        None,
        &axum::http::HeaderMap::new(),
        Timestamp::from_micros(0),
    );
    assert!(
        resp.is_none(),
        "a missing user has no stored actions; got status {:?}",
        resp.map(|r| r.status())
    );
}

fn location_of(resp: &axum::response::Response) -> String {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

// ---------------------------------------------------------------------------
// G6: `resource` must name a registered protected resource (RFC 8707)
// ---------------------------------------------------------------------------

const UNDECLARED: &str = "https%3A%2F%2Fundeclared.example.com%2Fv1";

/// A plain request naming a resource the realm never declared is refused with
/// `invalid_target` at the (registered) redirect URI — not issued a code.
#[tokio::test]
async fn plain_authorize_refuses_an_unregistered_resource() {
    let rig = rig(false).await;
    let client = register(&rig, false, None);
    let uri = plain_uri(&client, &format!("&resource={UNDECLARED}"));
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    let loc = location(&resp);
    assert_eq!(
        (
            redirect_param(&loc, "error", false).as_deref(),
            redirect_param(&loc, "code", false),
        ),
        (Some("invalid_target"), None),
        "an undeclared resource must answer invalid_target; got {} {loc}",
        resp.status()
    );
}

/// A plain request naming any spelling of a registered resource gets a code
/// whose token carries the resource's canonical form in `aud`.
#[tokio::test]
async fn plain_authorize_carries_a_registered_resource_in_canonical_form() {
    let rig = rig(false).await;
    let client = register(&rig, false, None);
    let uri = plain_uri(
        &client,
        "&resource=HTTPS%3A%2F%2FAPI.Example.com%3A443%2Fv1%2F",
    );
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    let loc = location(&resp);
    let code = redirect_param(&loc, "code", false)
        .unwrap_or_else(|| panic!("a registered resource gets a code; got {loc}"));
    let aud = exchanged_audience(&rig, &client, None, code);
    assert!(aud.iter().any(|a| a == RESOURCE), "aud = {aud:?}");
}

/// A request object naming an undeclared resource is refused (400, as every
/// JAR error on this entry point), not issued a code.
#[tokio::test]
async fn jar_authorize_refuses_an_unregistered_resource() {
    let rig = rig(false).await;
    let (client, pair) = jar_client(&rig, false);
    let uri = jar_uri(
        &rig,
        &client,
        &pair,
        &serde_json::json!({ "resource": "https://undeclared.example.com/v1" }),
        "",
    );
    let resp = get(&rig, &uri, &session_cookie(&rig)).await;
    assert_eq!(
        (resp.status(), location(&resp)),
        (StatusCode::BAD_REQUEST, String::new()),
        "a request object naming an undeclared resource must be refused"
    );
}
