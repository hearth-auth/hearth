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
    DeviceAuthorizationRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityError,
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
        .create_session(&realm, &user, &SessionContext::default())
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
            .poll_device_token(&self.realm, device_code, client)
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
