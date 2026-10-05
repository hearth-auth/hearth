//! A web + REST rig with the login abuse guards configured, shared by the A-3
//! and A-16 challenge tests. Include it with
//! `#[path = "common/abuse_rig.rs"] mod abuse_rig;` next to `mod common;`.
//!
//! Every request carries no `ConnectInfo`, so every request comes from the
//! same loopback client.
#![allow(dead_code)]

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, Request, StatusCode};
use hearth::abuse::challenge::CaptchaProvider;
use hearth::abuse::runtime::AbuseGuards;
use hearth::audit::{AuditAction, AuditQuery};
use hearth::config::SecurityYaml;
use hearth::core::RealmId;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, RealmConfig, UpdateUserRequest,
    UserStatus,
};
use tower::ServiceExt as _;

/// The token [`FakeCaptcha`] accepts.
pub const SOLVED: &str = "solved-token";

/// Marker the fake widget renders, so a test can find it on a page.
pub const WIDGET: &str = "data-test-captcha-widget";

/// A CAPTCHA provider that accepts [`SOLVED`] and nothing else.
pub struct FakeCaptcha;

impl CaptchaProvider for FakeCaptcha {
    fn widget_html(&self) -> &str {
        "<div data-test-captcha-widget></div>"
    }

    fn verify(&self, token: &str, _ip: IpAddr) -> bool {
        token == SOLVED
    }
}

/// The password every rig user has.
pub fn password() -> String {
    ["abuse", "rig", "correct", "staple"].join("-")
}

/// A-3: one distinct username per client is the most allowed.
pub const A3_ONE_USERNAME: &str = "distributed_attack_detector:\n  enabled: true\n  \
     window: 300s\n  username_per_ip_threshold: 1\n  ip_per_username_threshold: 1000\n";

/// A-16 with `threshold` failures per window, plus A-3 when `with_a3`.
pub fn a16(threshold: u32, with_a3: bool) -> String {
    let mut yaml = format!(
        "captcha:\n  provider: turnstile\n  challenge_threshold: {threshold}\n  \
         window_secs: 60\n  challenge_ttl_secs: 1800\n"
    );
    if with_a3 {
        yaml.push_str(A3_ONE_USERNAME);
    }
    yaml
}

/// The rig: one realm, a web router and a REST router sharing one guard set.
pub struct Rig {
    pub h: crate::common::TestHarness,
    pub realm: RealmId,
    pub realm_name: String,
    pub web: axum::Router,
    pub api: axum::Router,
}

impl Rig {
    /// Builds the rig from a `security:` block, with the fake CAPTCHA
    /// provider installed when `provider` is set.
    pub async fn new(security: &str, provider: bool) -> Self {
        let h = crate::common::TestHarness::in_process()
            .await
            .expect("harness");
        let yaml: SecurityYaml = serde_norway::from_str(security).expect("security block");
        let mut guards = AbuseGuards::from_security(&yaml);
        if provider {
            guards = guards.with_captcha_provider(Arc::new(FakeCaptcha));
        }
        let guards = Arc::new(guards);
        let realm = h
            .identity()
            .create_realm(&CreateRealmRequest {
                name: format!("abuse-{}", uuid::Uuid::new_v4().simple()),
                config: Some(RealmConfig {
                    registration_policy: Some(hearth::identity::RegistrationPolicy::Open),
                    ..RealmConfig::default()
                }),
            })
            .expect("create realm");
        let web = build_web(&h, Arc::clone(&guards));
        let api = hearth::protocol::http::router(Arc::new(
            hearth::protocol::http::AppState::new_dev(
                h.identity_arc(),
                h.rbac_arc(),
                h.audit_arc(),
            )
            .with_abuse_guards(guards),
        ));
        Self {
            realm: realm.id().clone(),
            realm_name: realm.name().to_string(),
            h,
            web,
            api,
        }
    }

    /// Creates an active user with [`password`] and returns the address.
    pub fn create_user(&self) -> String {
        let email = format!("u-{}@example.com", uuid::Uuid::new_v4().simple());
        let user = self
            .h
            .identity()
            .create_user(
                &self.realm,
                &CreateUserRequest {
                    email: email.clone(),
                    display_name: "Abuse Rig".to_string(),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )
            .expect("create user");
        self.h
            .identity()
            .set_password(
                &self.realm,
                user.id(),
                &CleartextPassword::from_string(password()),
            )
            .expect("set password");
        self.h
            .identity()
            .update_user(
                &self.realm,
                user.id(),
                &UpdateUserRequest {
                    status: Some(UserStatus::Active),
                    ..Default::default()
                },
            )
            .expect("activate user");
        email
    }

    /// `POST /ui/realms/<realm>/login`.
    pub async fn ui_login(
        &self,
        email: &str,
        password: &str,
        captcha_token: Option<&str>,
    ) -> (StatusCode, String) {
        let mut body = format!(
            "email={}&password={}",
            urlencode(email),
            urlencode(password)
        );
        if let Some(token) = captcha_token {
            body.push_str(&format!("&captcha_token={}", urlencode(token)));
        }
        let response = self
            .web
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/ui/realms/{}/login", self.realm_name))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .expect("build POST"),
            )
            .await
            .expect("oneshot");
        let status = response.status();
        (status, body_text(response).await)
    }

    /// `GET /ui/realms/<realm>/login`.
    pub async fn ui_login_page(&self) -> (StatusCode, HeaderMap, String) {
        let response = self
            .web
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/ui/realms/{}/login", self.realm_name))
                    .body(Body::empty())
                    .expect("build GET"),
            )
            .await
            .expect("oneshot");
        let status = response.status();
        let headers = response.headers().clone();
        (status, headers, body_text(response).await)
    }

    /// `POST /v1/<realm>/auth/magic-link`.
    pub async fn magic_link(
        &self,
        email: &str,
        captcha_token: Option<&str>,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let mut body = serde_json::json!({ "email": email });
        if let Some(token) = captcha_token {
            body["captcha_token"] = serde_json::Value::from(token);
        }
        self.api_json(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/{}/auth/magic-link", self.realm_name))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("build POST"),
        )
        .await
    }

    /// `POST /webauthn/auth/complete` with a well-formed assertion for a
    /// credential that does not exist, so the assertion check fails.
    pub async fn api_passkey_complete(
        &self,
        captcha_token: Option<&str>,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let mut body = bogus_assertion();
        body["origin"] = serde_json::Value::from("http://localhost");
        if let Some(token) = captcha_token {
            body["captcha_token"] = serde_json::Value::from(token);
        }
        self.api_json(
            Request::builder()
                .method("POST")
                .uri("/webauthn/auth/complete")
                .header("X-Realm-ID", self.realm.as_uuid().to_string())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("build POST"),
        )
        .await
    }

    /// The login page's `POST /ui/realms/<realm>/login/passkey-complete` with
    /// a well-formed assertion that cannot verify.
    pub async fn ui_passkey_complete(&self) -> (StatusCode, HeaderMap, String) {
        let response = self
            .web
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/ui/realms/{}/login/passkey-complete",
                        self.realm_name
                    ))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(bogus_assertion().to_string()))
                    .expect("build POST"),
            )
            .await
            .expect("oneshot");
        let status = response.status();
        let headers = response.headers().clone();
        (status, headers, body_text(response).await)
    }

    async fn api_json(&self, request: Request<Body>) -> (StatusCode, HeaderMap, serde_json::Value) {
        let response = self.api.clone().oneshot(request).await.expect("oneshot");
        let status = response.status();
        let headers = response.headers().clone();
        let text = body_text(response).await;
        let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
        (status, headers, json)
    }

    /// Metadata of every `AbuseDetected` event in the rig's realm.
    pub fn abuse_events(&self) -> Vec<serde_json::Value> {
        let mut query = AuditQuery::for_realm(self.realm.clone());
        query.action = Some(AuditAction::AbuseDetected);
        self.h
            .audit()
            .query(&query)
            .expect("query audit log")
            .into_iter()
            .map(|e| e.metadata.unwrap_or(serde_json::Value::Null))
            .collect()
    }
}

/// An assertion with valid base64url fields and a user handle that names no
/// user: every check after decoding fails.
fn bogus_assertion() -> serde_json::Value {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    serde_json::json!({
        "credential_id": URL_SAFE_NO_PAD.encode([7u8; 16]),
        "client_data_json": URL_SAFE_NO_PAD.encode(b"{}"),
        "authenticator_data": URL_SAFE_NO_PAD.encode([0u8; 37]),
        "signature": URL_SAFE_NO_PAD.encode([1u8; 64]),
        "user_handle": URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().to_string().as_bytes()),
    })
}

fn build_web(h: &crate::common::TestHarness, guards: Arc<AbuseGuards>) -> axum::Router {
    use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
    use hearth::identity::onboarding::OnboardingService;
    use hearth::protocol::web::{self, CookieSecret, WebState};

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
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
        h.identity_arc(),
        h.rbac_arc(),
        email,
        data_dir,
    ));
    let state = WebState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        onboarding,
        CookieSecret::from_bytes([5u8; 32]),
        None,
    )
    .with_abuse_guards(guards)
    .with_dev_mode(true);
    web::router(state)
}

fn urlencode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn body_text(response: axum::response::Response) -> String {
    String::from_utf8_lossy(&to_bytes(response.into_body(), 1 << 20).await.expect("body"))
        .into_owned()
}
