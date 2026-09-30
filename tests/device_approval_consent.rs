#![allow(clippy::unwrap_used)]
//! GA audit 2026-09-28 B3 — the device approval page approved a device on the
//! strength of the user code alone.
//!
//! `/ui/device` rendered a code box and nothing else: no client name, no
//! logo, no scopes. Submitting a code approved it at once and ran no consent.
//! An attacker who started a device flow for any client could send a victim
//! the user code ("enter this at /ui/device") and collect the victim's tokens.
//!
//! Entering a code now shows which application is asking and for which
//! scopes; the device is approved only on an explicit Approve, which records
//! the user's consent for a client that requires it (the same record the
//! browser consent screen writes). Deny approves nothing.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    ClientTrustLevel, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    DeviceAuthorizationRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityError, MfaProof,
    RegisterClientRequest, SessionContext,
};
use hearth::protocol::web::auth::{issue_auth_cookies, CookieSecret, CSRF_COOKIE};
use hearth::protocol::web::{self, WebState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt;

const CSRF: &str = "device-consent-csrf-token";
const CLIENT_NAME: &str = "Living Room TV";
const LOGO: &str = "https://tv.example.com/logo.png";

struct Rig {
    state: WebState,
    realm: RealmId,
    user: UserId,
    cookies: String,
}

fn rig() -> Rig {
    rig_with_proof(MfaProof::None)
}

/// A rig whose UI session recorded `mfa_proof` at sign-in.
fn rig_with_proof(mfa_proof: MfaProof) -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
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
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::rbac::RbacEngine>;

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "default".to_string(),
            config: None,
        })
        .expect("realm")
        .id()
        .clone();
    let user = identity
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "device-consent@hearth.test".into(),
                display_name: "Device".into(),
                ..Default::default()
            },
        )
        .expect("user")
        .id()
        .clone();
    let session = identity
        .create_session(
            &realm,
            &user,
            &SessionContext {
                mfa_proof,
                ..SessionContext::default()
            },
        )
        .expect("session");

    let email = Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
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
        Arc::clone(&authz),
        email,
        data_dir,
    ));
    let secret = CookieSecret::random();
    let cookies = issue_auth_cookies(&secret, &realm, session.id(), false);
    let session_pair = cookies.session_cookie.split(';').next().unwrap_or("");
    let cookies = format!("{session_pair}; {CSRF_COOKIE}={CSRF}");
    let state =
        WebState::new(identity, authz, audit, onboarding, secret, None).with_dev_mode(false);
    Rig {
        state,
        realm,
        user,
        cookies,
    }
}

impl Rig {
    /// Registers a third-party device client and starts a flow for
    /// `openid profile`; returns `(client, device_code, user_code)`.
    fn start(&self) -> (ClientId, String, String) {
        self.start_for(None)
    }

    /// [`Self::start`] with the client's `mfa_required` set.
    fn start_for(&self, mfa_required: Option<bool>) -> (ClientId, String, String) {
        let client = self
            .state
            .identity
            .register_client(
                &self.realm,
                &RegisterClientRequest {
                    client_name: CLIENT_NAME.into(),
                    redirect_uris: vec![],
                    grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".into()],
                    require_consent: true,
                    trust_level: ClientTrustLevel::ThirdParty,
                    declared_scopes: vec!["openid".into(), "profile".into()],
                    client_logo_url: Some(LOGO.into()),
                    mfa_required,
                    ..Default::default()
                },
            )
            .expect("register device client");
        let started = self
            .state
            .identity
            .device_authorize(
                &self.realm,
                &DeviceAuthorizationRequest {
                    client_id: client.client_id().clone(),
                    scope: Some("openid profile".into()),
                },
            )
            .expect("device authorize");
        (
            client.client_id().clone(),
            started.device_code,
            started.user_code,
        )
    }

    async fn post(&self, form: &str) -> (StatusCode, Option<String>, String) {
        let resp = web::router(self.state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ui/device")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, &self.cookies)
                    .body(Body::from(format!("{form}&csrf_token={CSRF}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let location = resp
            .headers()
            .get(header::LOCATION)
            .map(|v| v.to_str().unwrap().to_string());
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, location, String::from_utf8_lossy(&body).to_string())
    }

    /// Whether the device may now collect tokens.
    fn poll(&self, client: &ClientId, device_code: &str) -> Result<(), IdentityError> {
        self.state
            .identity
            .poll_device_token(&self.realm, device_code, client, None)
            .map(|_| ())
    }
}

#[tokio::test]
async fn entering_a_device_code_shows_the_client_and_scopes_and_approves_nothing() {
    let rig = rig();
    let (client, device_code, user_code) = rig.start();

    let (status, _, html) = rig.post(&format!("user_code={user_code}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "entering a code must render a confirmation page, not approve at once"
    );
    for (what, needle) in [
        ("client name", CLIENT_NAME),
        ("client logo", LOGO),
        ("openid scope", "openid"),
        ("profile scope", "profile"),
        ("user code carried to the decision", user_code.as_str()),
    ] {
        assert!(
            html.contains(needle),
            "the confirmation page must show the {what} (`{needle}`)"
        );
    }
    assert!(
        matches!(
            rig.poll(&client, &device_code),
            Err(IdentityError::AuthorizationPending)
        ),
        "the device must not be approved before the user confirms"
    );
}

#[tokio::test]
async fn approving_a_device_records_consent_for_a_client_that_requires_it() {
    let rig = rig();
    let (client, device_code, user_code) = rig.start();

    let (status, location, _) = rig
        .post(&format!("user_code={user_code}&decision=approve"))
        .await;
    assert!(status.is_redirection(), "approve redirects; got {status}");
    assert_eq!(location.as_deref(), Some("/ui/device?flash=approved"));
    rig.poll(&client, &device_code)
        .expect("the approved device collects its tokens");

    let consent = rig
        .state
        .identity
        .get_consent(&rig.realm, &rig.user, &client)
        .expect("consent lookup")
        .expect("approving a consent-requiring client must record the user's consent");
    assert!(
        consent.covers(&["openid".to_string(), "profile".to_string()]),
        "the consent must cover the scopes the device requested; got {:?}",
        consent.granted_scopes
    );
}

#[tokio::test]
async fn denying_a_device_approves_nothing() {
    let rig = rig();
    let (client, device_code, user_code) = rig.start();

    let (status, _, _) = rig
        .post(&format!("user_code={user_code}&decision=deny"))
        .await;
    assert!(status.is_redirection(), "deny redirects; got {status}");
    assert!(
        rig.poll(&client, &device_code).is_err(),
        "a denied device must not receive tokens"
    );
    assert!(
        rig.state
            .identity
            .get_consent(&rig.realm, &rig.user, &client)
            .expect("consent lookup")
            .is_none(),
        "deny records no consent"
    );
}

// ─── GA audit B5 on the device path: the factor the session PROVED ──────────

fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let tag = ring::hmac::sign(&key, &(unix_secs / 30).to_be_bytes());
    let hash = tag.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    format!("{:06}", binary % 1_000_000)
}

/// Enrols TOTP for the rig's user AFTER its session was opened, so the
/// session proves nothing while the account now holds a factor.
fn enrol_totp_after_sign_in(rig: &Rig) {
    let enrollment = rig
        .state
        .identity
        .enroll_totp(&rig.realm, &rig.user)
        .expect("enroll_totp");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("epoch")
        .as_secs();
    rig.state
        .identity
        .verify_totp_enrollment(
            &rig.realm,
            &rig.user,
            &compute_totp_code(&enrollment.secret_base32, now),
        )
        .expect("verify_totp_enrollment");
}

/// A device client that sets `mfa_required` must not be approved from a
/// session that proved no factor, the rule the browser authorize path
/// applies (`authorize_gate::mfa_use_gate`): the session is ended so the
/// user signs in again with the factor.
#[tokio::test]
async fn an_mfa_required_device_client_is_not_approved_from_an_unproved_session() {
    let rig = rig_with_proof(MfaProof::None);
    enrol_totp_after_sign_in(&rig);
    let (client, device_code, user_code) = rig.start_for(Some(true));

    let (status, location, _) = rig
        .post(&format!("user_code={user_code}&decision=approve"))
        .await;
    assert!(status.is_redirection(), "refusal redirects; got {status}");
    assert_ne!(
        location.as_deref(),
        Some("/ui/device?flash=approved"),
        "an unproved session must not approve an MFA-required client"
    );
    assert!(
        rig.poll(&client, &device_code).is_err(),
        "the device must not receive tokens"
    );
}

/// The control: a session that proved a factor approves the same client.
#[tokio::test]
async fn an_mfa_required_device_client_is_approved_from_a_proved_session() {
    let rig = rig_with_proof(MfaProof::Proved);
    enrol_totp_after_sign_in(&rig);
    let (client, device_code, user_code) = rig.start_for(Some(true));

    let (_, location, _) = rig
        .post(&format!("user_code={user_code}&decision=approve"))
        .await;
    assert_eq!(location.as_deref(), Some("/ui/device?flash=approved"));
    rig.poll(&client, &device_code)
        .expect("a proved session approves the MFA-required client");
}

// ── GA audit round 3, D-7: the device token session records the approving
// session's proof, not `Inherited` ─────────────────────────────────────────

impl Rig {
    /// Approves `user_code` through `/ui/device` and polls the device's
    /// tokens; returns the `mfa_proof` of the session the tokens name.
    async fn approved_device_session_proof(
        &self,
        client: &ClientId,
        device_code: &str,
        user_code: &str,
    ) -> MfaProof {
        let (_, location, _) = self
            .post(&format!("user_code={user_code}&decision=approve"))
            .await;
        assert_eq!(location.as_deref(), Some("/ui/device?flash=approved"));
        let tokens = self
            .state
            .identity
            .poll_device_token(&self.realm, device_code, client, None)
            .expect("the device collects its tokens");
        let claims = self
            .state
            .identity
            .validate_token(&self.realm, tokens.access_token())
            .expect("valid token");
        let sid = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
        self.state
            .identity
            .get_session(
                &self.realm,
                &hearth::core::SessionId::new(sid.parse().expect("session uuid")),
            )
            .expect("lookup")
            .expect("token session")
            .mfa_proof()
    }
}

#[tokio::test]
async fn a_device_token_session_records_the_approving_sessions_proof() {
    let rig = rig_with_proof(MfaProof::Proved);
    let (client, device_code, user_code) = rig.start();
    assert_eq!(
        rig.approved_device_session_proof(&client, &device_code, &user_code)
            .await,
        MfaProof::Proved
    );
}

#[tokio::test]
async fn a_device_approved_from_an_unproved_session_gets_an_unproved_session() {
    let rig = rig();
    let (client, device_code, user_code) = rig.start();
    assert_eq!(
        rig.approved_device_session_proof(&client, &device_code, &user_code)
            .await,
        MfaProof::None,
        "the device proved nothing the approving session did not"
    );
}
