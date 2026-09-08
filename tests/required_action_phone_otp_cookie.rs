//! The phone-OTP enrolment surface must verify its RA session cookie
//! (audit 2026-08-28 §4.19#7).
//!
//! `enroll_phone_otp_send` only checked that the cookie was *present*, then
//! read the realm out of the unverified payload and issued an SMS OTP against
//! it. Anyone could therefore mint a cookie naming any realm and make Hearth
//! send SMS on that realm's account. Its email twin
//! (`enroll_email_otp_send`) has always verified the token signature first;
//! these tests hold the phone surface to the same rule.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use data_encoding::BASE64URL_NOPAD;
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SessionId, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, ClientTrustLevel, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, OAuthClient, RealmConfig,
    RegisterClientRequest, RequiredAction, SessionContext, SmsError, SmsMessage, SmsSender,
    UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [23u8; 32];
const PASSWORD: &str = "test-password-hearth-ra-phone";
const PKCE_VERIFIER: &str = "dGVzdC12ZXJpZmllci10aGlzLWlzLTQzLWNoYXJhY3RlcnM";
const TEST_PHONE: &str = "+15555550188";

// ---------------------------------------------------------------------------
// Test-only capturing SMS sender
// ---------------------------------------------------------------------------

struct CapturingSmsSender {
    messages: Mutex<Vec<SmsMessage>>,
}

impl CapturingSmsSender {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            messages: Mutex::new(Vec::new()),
        })
    }

    fn sent_count(&self) -> usize {
        #[allow(clippy::unwrap_used)]
        self.messages.lock().unwrap().len()
    }
}

impl SmsSender for CapturingSmsSender {
    fn send(&self, message: &SmsMessage) -> Result<(), SmsError> {
        #[allow(clippy::unwrap_used)]
        self.messages.lock().unwrap().push(message.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Rig
// ---------------------------------------------------------------------------

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    client: OAuthClient,
    sms: Arc<CapturingSmsSender>,
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

fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit: Arc<dyn AuditEngine> = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as _,
        Arc::clone(&clock),
    ));
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as _,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit) as _,
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as _,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("ra-phone-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_methods: Some(vec!["sms".to_string()]),
                ..Default::default()
            }),
        })
        .expect("create realm");

    let client = identity
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "RA Phone Test App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        null_email(),
        data_dir,
    ));

    let sms = CapturingSmsSender::new();
    let state = WebState::new(
        Arc::clone(&identity),
        rbac,
        Arc::clone(&audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(null_email()),
    )
    .with_dev_mode(true)
    .with_sms(Arc::clone(&sms) as _, Some(b"test-sms-hmac-key".to_vec()));

    Rig {
        app: web::router(state),
        identity,
        realm_id: realm.id().clone(),
        client,
        sms,
    }
}

fn create_user_needing_phone_enrolment(rig: &Rig, email: &str) -> String {
    let user = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Test".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    rig.identity
        .set_password(
            &rig.realm_id,
            user.id(),
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("set password");

    rig.identity
        .update_user(
            &rig.realm_id,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                required_actions: Some(vec![RequiredAction::EnrollPhoneOtp]),
                ..Default::default()
            },
        )
        .expect("update user");

    let session = rig
        .identity
        .create_session(&rig.realm_id, user.id(), &SessionContext::default())
        .expect("session");

    session_cookie(&rig.realm_id, session.id(), "csrf-tok")
}

fn session_cookie(realm_id: &RealmId, session_id: &SessionId, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("hmac");
    mac.update(session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(realm_id.as_uuid().as_bytes());
    let tag = BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        session_id.as_uuid(),
        realm_id.as_uuid(),
        tag,
        csrf,
    )
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

fn authorize_uri(client: &OAuthClient) -> String {
    let challenge = BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes()).as_ref());
    format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid&state=csrf-state&code_challenge={}&code_challenge_method=S256",
        client.client_id().as_uuid(),
        urlencode("https://app.example.com/cb"),
        urlencode(&challenge),
    )
}

fn ra_cookie_value(resp: &axum::response::Response) -> Option<String> {
    for v in resp.headers().get_all(header::SET_COOKIE) {
        if let Ok(s) = v.to_str() {
            if let Some(rest) = s.strip_prefix("hearth_ra_session=") {
                return rest.split(';').next().map(str::to_string);
            }
        }
    }
    None
}

/// Mints an RA-shaped JWT that names `realm` but carries a bogus signature.
fn forged_ra_token(realm: &RealmId) -> String {
    let header = BASE64URL_NOPAD.encode(br#"{"alg":"EdDSA","typ":"ra+jwt"}"#);
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + 900;
    let claims = serde_json::json!({
        "sub": uuid::Uuid::new_v4().to_string(),
        "realm": realm.as_uuid().to_string(),
        "pending_actions": ["ENROLL_PHONE_OTP"],
        "iat": exp - 900,
        "exp": exp,
    });
    let payload = BASE64URL_NOPAD.encode(&serde_json::to_vec(&claims).expect("encode claims"));
    let signature = BASE64URL_NOPAD.encode(&[0u8; 64]);
    format!("{header}.{payload}.{signature}")
}

// ---------------------------------------------------------------------------
// A forged cookie must not drive an SMS send
// ---------------------------------------------------------------------------

#[tokio::test]
async fn phone_otp_send_refuses_a_forged_ra_cookie() {
    let rig = build_rig();
    let token = forged_ra_token(&rig.realm_id);

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/ENROLL_PHONE_OTP/send")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ra_session={token}"))
                .body(Body::from(format!("phone={}", urlencode(TEST_PHONE))))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "a forged RA cookie must not reach the code-entry page"
    );
    assert_eq!(
        rig.sms.sent_count(),
        0,
        "a forged RA cookie must not spend the named realm's SMS budget"
    );
}

#[tokio::test]
async fn phone_otp_page_refuses_a_forged_ra_cookie() {
    let rig = build_rig();
    let token = forged_ra_token(&rig.realm_id);

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/required-action/ENROLL_PHONE_OTP")
                .header(header::COOKIE, format!("hearth_ra_session={token}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "a forged RA cookie must not render the enrolment form"
    );
}

// ---------------------------------------------------------------------------
// The genuine flow still works
// ---------------------------------------------------------------------------

#[tokio::test]
async fn phone_otp_send_still_works_with_a_genuine_ra_cookie() {
    let rig = build_rig();
    let ui_cookie = create_user_needing_phone_enrolment(&rig, "phone-enrol@example.com");

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_uri(&rig.client))
                .header(header::COOKIE, &ui_cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    let ra_token = ra_cookie_value(&resp).expect("RA token from intercept");

    let resp2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/ENROLL_PHONE_OTP/send")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::from(format!("phone={}", urlencode(TEST_PHONE))))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "a genuine RA cookie must still reach the code-entry page"
    );
    assert_eq!(
        rig.sms.sent_count(),
        1,
        "the genuine flow must still send exactly one SMS"
    );
}
