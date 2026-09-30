//! The SMS challenge on `/authorize` and on device approval records the
//! factor it proved (GA sweep 4, authn follow-up 1).
//!
//! Every other second-factor challenge — TOTP / recovery code, SMS or email
//! OTP at login, the passkey second factor — records `MfaProof::Proved` for
//! what it verified. The SMS interstitial that a realm with
//! `mfa_methods: ["sms"]` puts in front of code issuance and device approval
//! verified a live OTP too, but the code (and the device approval) carried
//! only the browser session's own proof. A session that proved nothing at
//! sign-in — the phone was verified after it — got a code whose token
//! session proved nothing either, although the user had just proved the SMS
//! factor for exactly this authorization. A client or role that demands a
//! second factor then refused that token through the JSON / gRPC
//! `Authorize`.
//!
//! The challenge now raises the carried proof to `Proved`; a session that
//! already proved more (a user-verifying passkey) keeps its proof.

mod common;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, Response};
use hearth::core::{ClientId, RealmId, SessionId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    ClientTrustLevel, CreateRealmRequest, CreateUserRequest, DeviceAuthorizationRequest,
    IdentityEngine, MfaProof, RealmConfig, RegisterClientRequest, SessionContext, SmsError,
    SmsMessage, SmsSender, TokenExchangeRequest, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use tower::ServiceExt as _;

const COOKIE_SECRET: [u8; 32] = [89u8; 32];
const CSRF: &str = "sms-challenge-proof-csrf";
const PHONE: &str = "+15555550177";
const REDIRECT: &str = "https://app.example.com/cb";
const SMS_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
const PKCE_VERIFIER: &str = "verifier-verifier-verifier-verifier-sms-proof";

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

struct Rig {
    _harness: common::TestHarness,
    _data_dir: tempfile::TempDir,
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    sms: Arc<CapturingSms>,
    /// Browser cookies of a UI session that proved `proof` at sign-in.
    cookies: String,
}

/// An SMS realm and a user whose browser session proved `proof` at sign-in;
/// the phone is verified only after that sign-in, so the session could
/// prove less than the factor the realm now challenges.
async fn rig(proof: MfaProof) -> Rig {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity_arc();
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("sms-proof-{}", uuid::Uuid::new_v4().simple()),
            config: Some(RealmConfig {
                mfa_methods: Some(vec!["sms".to_string(), "webauthn".to_string()]),
                ..RealmConfig::default()
            }),
        })
        .expect("realm");
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("u-{}@sms-proof.test", uuid::Uuid::new_v4().simple()),
                display_name: "Sms".to_string(),
                ..Default::default()
            },
        )
        .expect("user");
    identity
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate");
    let session = identity
        .create_session(
            realm.id(),
            user.id(),
            &SessionContext {
                mfa_proof: proof,
                ..SessionContext::default()
            },
        )
        .expect("browser session");
    identity
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                phone_number: Some(Some(PHONE.to_string())),
                phone_verified: Some(true),
                ..Default::default()
            },
        )
        .expect("verify the phone after sign-in");
    let issued = web::auth::issue_auth_cookies(
        &CookieSecret::from_bytes(COOKIE_SECRET),
        realm.id(),
        session.id(),
        false,
    );
    let session_pair = issued
        .session_cookie
        .split(';')
        .next()
        .expect("session cookie pair")
        .to_string();
    let cookies = format!("{session_pair}; hearth_ui_csrf={CSRF}");

    let data_dir = tempfile::tempdir().expect("tempdir");
    let sms = Arc::new(CapturingSms {
        messages: Mutex::new(Vec::new()),
    });
    let rbac = harness.rbac_arc();
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        null_email(),
        data_dir.path().to_path_buf(),
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        rbac,
        harness.audit_arc(),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(null_email()),
    )
    .with_sms(Arc::clone(&sms) as _, Some(SMS_KEY.to_vec()));
    Rig {
        app: web::router(state),
        _harness: harness,
        _data_dir: data_dir,
        identity,
        realm_id: realm.id().clone(),
        sms,
        cookies,
    }
}

async fn send(rig: &Rig, req: Request<Body>) -> Response<Body> {
    rig.app.clone().oneshot(req).await.expect("request")
}

async fn get(rig: &Rig, uri: &str) -> Response<Body> {
    send(
        rig,
        Request::builder()
            .uri(uri)
            .header(header::COOKIE, &rig.cookies)
            .body(Body::empty())
            .expect("build GET"),
    )
    .await
}

async fn post_form(rig: &Rig, uri: &str, cookies: &str, body: String) -> Response<Body> {
    send(
        rig,
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, cookies)
            .body(Body::from(body))
            .expect("build POST"),
    )
    .await
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

/// Submits the SMS code for the challenge `challenge_resp` started.
async fn pass_sms_challenge(rig: &Rig, challenge_resp: &Response<Body>) -> Response<Body> {
    assert_eq!(
        location(challenge_resp),
        "/ui/sms-challenge",
        "the SMS realm challenges the factor"
    );
    let sms_cookie = cookie_pair(challenge_resp, "hearth_ui_sms_mfa").expect("SMS cookie");
    let code = rig.sms.last_code();
    post_form(
        rig,
        "/ui/sms-challenge",
        &format!("{}; {sms_cookie}", rig.cookies),
        format!("code={code}&_csrf={CSRF}"),
    )
    .await
}

/// The `mfa_proof` of the session an access token names.
fn token_session_proof(rig: &Rig, token: &str) -> MfaProof {
    let claims = rig
        .identity
        .validate_token(&rig.realm_id, token)
        .expect("valid token");
    let sid = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
    rig.identity
        .get_session(
            &rig.realm_id,
            &SessionId::new(sid.parse().expect("session uuid")),
        )
        .expect("lookup")
        .expect("token session")
        .mfa_proof()
}

/// Runs the browser authorization through the SMS challenge, exchanges the
/// code and returns the proof its token session records.
async fn code_flow_proof_after_sms(rig: &Rig) -> MfaProof {
    let client = rig
        .identity
        .register_client(
            &rig.realm_id,
            &RegisterClientRequest {
                client_name: "Sms proof app".to_string(),
                redirect_uris: vec![REDIRECT.to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");
    let challenge = data_encoding::BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes()).as_ref());
    let uri = format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb\
         &response_type=code&scope=openid&state=s&code_challenge={challenge}\
         &code_challenge_method=S256",
        client.client_id().as_uuid(),
    );
    let resp = get(rig, &uri).await;
    let resp = pass_sms_challenge(rig, &resp).await;
    let next = location(&resp);
    assert!(next.starts_with(REDIRECT), "a code is issued: {next}");
    let code = next
        .split("code=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("code parameter")
        .to_string();
    let tokens = rig
        .identity
        .exchange_authorization_code(
            &rig.realm_id,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code,
                redirect_uri: REDIRECT.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange");
    token_session_proof(rig, tokens.access_token())
}

/// Approves a device code through `/ui/device` and the SMS challenge, polls
/// the device's tokens and returns the proof their session records.
async fn device_proof_after_sms(rig: &Rig) -> MfaProof {
    let client = rig
        .identity
        .register_client(
            &rig.realm_id,
            &RegisterClientRequest {
                client_name: "Sms proof device".to_string(),
                redirect_uris: vec![],
                grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register device client");
    let client_id: ClientId = client.client_id().clone();
    let started = rig
        .identity
        .device_authorize(
            &rig.realm_id,
            &DeviceAuthorizationRequest {
                client_id: client_id.clone(),
                scope: Some("openid".to_string()),
            },
        )
        .expect("device authorize");
    let resp = post_form(
        rig,
        "/ui/device",
        &rig.cookies,
        format!(
            "user_code={}&decision=approve&csrf_token={CSRF}",
            started.user_code
        ),
    )
    .await;
    let resp = pass_sms_challenge(rig, &resp).await;
    assert_eq!(
        location(&resp),
        "/ui/device?flash=approved",
        "the verified code approves the device"
    );
    let tokens = rig
        .identity
        .poll_device_token(&rig.realm_id, &started.device_code, &client_id)
        .expect("the device collects its tokens");
    token_session_proof(rig, tokens.access_token())
}

#[tokio::test]
async fn a_code_issued_after_the_sms_challenge_carries_the_proved_factor() {
    let rig = rig(MfaProof::None).await;
    assert_eq!(code_flow_proof_after_sms(&rig).await, MfaProof::Proved);
}

#[tokio::test]
async fn a_uv_less_passkey_session_plus_the_sms_challenge_is_a_proved_code() {
    let rig = rig(MfaProof::PasskeyPossession).await;
    assert_eq!(code_flow_proof_after_sms(&rig).await, MfaProof::Proved);
}

#[tokio::test]
async fn the_sms_challenge_does_not_lower_a_passkey_sessions_proof() {
    let rig = rig(MfaProof::ProvedWebAuthn).await;
    assert_eq!(
        code_flow_proof_after_sms(&rig).await,
        MfaProof::ProvedWebAuthn,
        "an OTP is not phishing-resistant, so it must not replace a UV passkey's proof"
    );
}

#[tokio::test]
async fn a_device_approved_after_the_sms_challenge_carries_the_proved_factor() {
    let rig = rig(MfaProof::None).await;
    assert_eq!(device_proof_after_sms(&rig).await, MfaProof::Proved);
}

#[tokio::test]
async fn a_device_approval_keeps_a_passkey_sessions_proof_through_the_sms_challenge() {
    let rig = rig(MfaProof::ProvedWebAuthn).await;
    assert_eq!(device_proof_after_sms(&rig).await, MfaProof::ProvedWebAuthn);
}
