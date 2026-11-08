//! The world every invariant driver runs in, and the violations it can apply.
//!
//! One fixture per run: a fresh in-process harness, one tenant realm, one
//! active user with a password and no second factor, the clients the drivers
//! need, an organization the user belongs to, and the web and REST routers.
//! The realm always has a fail-closed pre-token webhook. Its transport allows
//! until [`Violation::WebhookDenies`] switches it to fail.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{header, Request};
use axum::response::Response;
use hearth::audit::{Actor, AuditContext};
use hearth::core::{ClientId, OrganizationId, RealmId, UserId};
use hearth::identity::email::{EmailBranding, EmailError, EmailMessage, EmailSender, EmailService};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::pre_token_webhook::{
    PreTokenWebhookError, PreTokenWebhookResponse, PreTokenWebhookTransport,
};
use hearth::identity::{
    ApplicationStatus, CleartextPassword, ClientTrustLevel, CreateOrganizationRequest,
    CreateRealmRequest, CreateUserRequest, OAuthClient, OrganizationRole, OrganizationStatus,
    PreTokenWebhookConfig, PreTokenWebhookErrorPolicy, RealmConfig, RegisterClientRequest,
    SessionContext, SigningKey, UpdateClientRequest, UpdateOrganizationRequest, UpdateRealmRequest,
    UpdateUserRequest, User, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use tower::ServiceExt as _;

use super::browser::Browser;
use super::common;

/// The password of every fixture user.
pub const PASSWORD: &str = "invariant-registry-password-1";
/// The redirect URI of the browser clients.
pub const CALLBACK: &str = "https://app.example.com/cb";
/// The secret of the confidential client.
pub const CLIENT_SECRET: &str = "invariant-client-secret-value-1";
/// The PKCE verifier every authorization request uses.
pub const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// `S256(PKCE_VERIFIER)`.
pub const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// The WebAuthn relying party (the `Host` the passkey drivers send).
pub const RP_ID: &str = "example.com";
/// The WebAuthn origin.
pub const ORIGIN: &str = "http://example.com";
/// The slug of the organization the user belongs to.
pub const ORG_SLUG: &str = "acme";

const COOKIE_SECRET: [u8; 32] = [77u8; 32];
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// One condition that must stop an entry point from issuing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    /// The realm is suspended.
    RealmSuspended,
    /// The organization of an org-context flow is suspended.
    OrgSuspended,
    /// The user is disabled.
    UserDisabled,
    /// The user's password login is locked after failed attempts.
    UserLocked,
    /// The client is archived.
    ClientArchived,
    /// The realm starts to require MFA; the user has no second factor.
    MfaRequired,
    /// The pre-token webhook fails and the realm's policy is fail-closed.
    WebhookDenies,
}

/// A webhook transport that allows until it is told to fail.
#[derive(Default)]
pub struct SwitchHook {
    fail: AtomicBool,
}

impl PreTokenWebhookTransport for SwitchHook {
    fn fire(
        &self,
        _url: &str,
        _timeout_ms: u64,
        _body: &[u8],
        _hmac_sig: Option<&str>,
    ) -> Result<PreTokenWebhookResponse, PreTokenWebhookError> {
        if self.fail.load(Ordering::SeqCst) {
            Err(PreTokenWebhookError::TransportError {
                reason: "the test webhook denies".to_string(),
            })
        } else {
            Ok(PreTokenWebhookResponse {
                extra_claims: BTreeMap::new(),
            })
        }
    }
}

/// Every mail the web layer sends.
#[derive(Default)]
pub struct Outbox {
    mail: Mutex<Vec<String>>,
}

impl Outbox {
    /// The text and HTML of the last mail.
    pub fn last(&self) -> String {
        self.mail
            .lock()
            .expect("outbox lock")
            .last()
            .cloned()
            .expect("a mail was sent")
    }
}

struct CapturingMail(Arc<Outbox>);

impl EmailSender for CapturingMail {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        self.0
            .mail
            .lock()
            .expect("outbox lock")
            .push(format!("{}\n{}", message.text_body, message.html_body));
        Ok(())
    }
}

/// The world of one driver run.
pub struct Fx {
    /// The harness.
    pub h: common::TestHarness,
    /// The tenant realm.
    pub realm: RealmId,
    /// Its name.
    pub realm_name: String,
    /// The active user: a password, no second factor.
    pub user: User,
    /// A confidential first-party client with every user and machine grant.
    pub app: OAuthClient,
    /// A third-party client that requires consent.
    pub consent: OAuthClient,
    /// A public client that authenticates with a signed assertion.
    pub jwt_client: ClientId,
    /// The assertion key of `jwt_client`.
    pub jwt_key: SigningKey,
    /// An organization the user is a member of.
    pub org: OrganizationId,
    /// The web router's cookie secret.
    pub secret: CookieSecret,
    /// The hosted UI router.
    pub web: axum::Router,
    /// The REST router.
    pub rest: axum::Router,
    /// Mail the web layer sent.
    pub outbox: Arc<Outbox>,
    /// The pre-token webhook.
    pub hook: Arc<SwitchHook>,
}

/// Builds a fresh fixture.
// A flat list of setup steps; splitting it would only scatter them.
#[allow(clippy::too_many_lines)]
pub async fn fixture() -> Fx {
    let hook = Arc::new(SwitchHook::default());
    let h = common::TestHarness::in_process_with_pre_token_transport(
        Arc::clone(&hook) as Arc<dyn PreTokenWebhookTransport>
    )
    .await
    .expect("harness");
    let realm_name = format!("inv-{}", uuid::Uuid::new_v4().simple());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: Some(RealmConfig {
                mfa_required: Some(false),
                max_failed_logins: Some(3),
                pre_token_webhook: Some(PreTokenWebhookConfig {
                    url: "https://hooks.example.com/pre-token".to_string(),
                    timeout_ms: 1000,
                    on_error: PreTokenWebhookErrorPolicy::FailClosed,
                    hmac_secret: Some("invariant-webhook-secret".to_string()),
                }),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm")
        .id()
        .clone();
    h.declare_scopes(&realm, &["read"]);
    let user = create_user(
        &h,
        &realm,
        &format!("u-{}@inv.test", uuid::Uuid::new_v4().simple()),
    );

    let app = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Invariant App".to_string(),
                redirect_uris: vec![CALLBACK.to_string()],
                client_secret: Some(CLIENT_SECRET.to_string()),
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                    "client_credentials".to_string(),
                    DEVICE_GRANT.to_string(),
                    TOKEN_EXCHANGE_GRANT.to_string(),
                ],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                declared_scopes: vec!["openid".to_string(), "profile".to_string()],
                ..Default::default()
            },
        )
        .expect("register the app client");
    let consent = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Invariant Third Party".to_string(),
                redirect_uris: vec![CALLBACK.to_string()],
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                trust_level: ClientTrustLevel::ThirdParty,
                declared_scopes: vec!["openid".to_string(), "profile".to_string()],
                ..Default::default()
            },
        )
        .expect("register the consent client");
    let jwt_key = SigningKey::generate().expect("assertion key");
    let jwt_client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Invariant Assertion Client".to_string(),
                grant_types: vec![JWT_BEARER_GRANT.to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register the assertion client")
        .client_id()
        .clone();
    {
        use base64::Engine as _;
        h.identity()
            .update_client(
                &realm,
                &jwt_client,
                &UpdateClientRequest {
                    assertion_public_key: Some(Some(
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(jwt_key.public_key_bytes()),
                    )),
                    ..Default::default()
                },
            )
            .expect("set the assertion key");
    }

    let org = h
        .identity()
        .create_organization(
            &realm,
            &CreateOrganizationRequest {
                name: ORG_SLUG.to_string(),
                slug: ORG_SLUG.to_string(),
                description: None,
                config: None,
                attributes: Default::default(),
            },
        )
        .expect("create organization")
        .id()
        .clone();
    h.identity()
        .add_member(&realm, &org, user.id(), OrganizationRole::Member)
        .expect("add member");

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
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    let _ = temp.keep();
    let onboarding = Arc::new(OnboardingService::new(
        h.identity_arc(),
        h.rbac_arc(),
        Arc::clone(&email),
        data_dir,
    ));
    let secret = CookieSecret::from_bytes(COOKIE_SECRET);
    let web = web::router(
        WebState::new(
            h.identity_arc(),
            h.rbac_arc(),
            h.audit_arc(),
            onboarding,
            CookieSecret::from_bytes(COOKIE_SECRET),
            Some(email),
        )
        .with_dev_mode(false),
    );
    let rest = hearth::protocol::http::router(Arc::new(hearth::protocol::http::AppState::new_dev(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )));
    Fx {
        h,
        realm,
        realm_name,
        user,
        app,
        consent,
        jwt_client,
        jwt_key,
        org,
        secret,
        web,
        rest,
        outbox,
        hook,
    }
}

/// Creates an active user with [`PASSWORD`].
pub fn create_user(h: &common::TestHarness, realm: &RealmId, email: &str) -> User {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Invariant User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    h.identity()
        .set_password(
            realm,
            user.id(),
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("set password");
    h.identity()
        .update_user(
            realm,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate user");
    h.identity()
        .get_user(realm, user.id())
        .expect("get user")
        .expect("user exists")
}

impl Fx {
    /// The user's id.
    pub fn uid(&self) -> &UserId {
        self.user.id()
    }

    /// The app client's id.
    pub fn app_id(&self) -> &ClientId {
        self.app.client_id()
    }

    /// Changes the realm config with `edit`.
    pub fn edit_realm(&self, edit: impl FnOnce(&mut RealmConfig)) {
        let mut config = self
            .h
            .identity()
            .get_realm(&self.realm)
            .expect("get realm")
            .expect("realm exists")
            .config()
            .clone();
        edit(&mut config);
        self.h
            .identity()
            .update_realm(
                &self.realm,
                &UpdateRealmRequest {
                    config: Some(config),
                    ..Default::default()
                },
            )
            .expect("update realm config");
    }

    /// Applies `v` (when given) to this fixture. `client` is the client the
    /// entry point acts for, `user` the user it signs in.
    pub fn violate(&self, v: Option<Violation>, client: Option<&ClientId>, user: &UserId) {
        let Some(v) = v else { return };
        let id = self.h.identity();
        match v {
            Violation::RealmSuspended => {
                id.set_realm_suspended(
                    &self.realm,
                    true,
                    &AuditContext {
                        actor: Actor::System,
                        metadata: None,
                    },
                )
                .expect("suspend realm");
            }
            Violation::OrgSuspended => {
                id.update_organization(
                    &self.realm,
                    &self.org,
                    &UpdateOrganizationRequest {
                        status: Some(OrganizationStatus::Suspended),
                        ..Default::default()
                    },
                )
                .expect("suspend organization");
            }
            Violation::UserDisabled => {
                id.update_user(
                    &self.realm,
                    user,
                    &UpdateUserRequest {
                        status: Some(UserStatus::Disabled),
                        ..Default::default()
                    },
                )
                .expect("disable user");
            }
            Violation::UserLocked => {
                let wrong = CleartextPassword::from_string("not-the-password-0".to_string());
                for _ in 0..3 {
                    let _ = id.verify_password(&self.realm, user, &wrong);
                }
                assert!(
                    id.login_lockout_remaining(&self.realm, user).is_some(),
                    "three failed attempts must lock the login"
                );
            }
            Violation::ClientArchived => {
                id.update_client(
                    &self.realm,
                    client.expect("a client-status violation needs the entry point's client"),
                    &UpdateClientRequest {
                        status: Some(ApplicationStatus::Archived),
                        ..Default::default()
                    },
                )
                .expect("archive client");
            }
            Violation::MfaRequired => self.edit_realm(|c| c.mfa_required = Some(true)),
            Violation::WebhookDenies => self.hook.fail.store(true, Ordering::SeqCst),
        }
    }

    /// A browser holding a signed-in session (no second factor proved) for
    /// `user`, plus its CSRF cookie.
    pub fn signed_in(&self, user: &UserId, host: Option<&str>) -> Browser {
        let session = self
            .h
            .identity()
            .create_session(&self.realm, user, &SessionContext::default())
            .expect("create session");
        let cookies = web::auth::issue_auth_cookies(&self.secret, &self.realm, session.id(), false);
        let mut browser = self.browser(host);
        browser.accept_set_cookie(&cookies.session_cookie, "/ui/login");
        browser.accept_set_cookie(&cookies.csrf_cookie, "/ui/login");
        browser
    }

    /// An empty browser for the web router.
    pub fn browser(&self, host: Option<&str>) -> Browser {
        let mut browser = Browser::new(self.web.clone());
        if let Some(host) = host {
            browser.set_header("host", host);
        }
        browser
    }

    /// Sends one request to `app` and returns the response.
    pub async fn send(
        app: &axum::Router,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: Body,
    ) -> Response {
        let mut req = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        app.clone()
            .oneshot(req.body(body).expect("build request"))
            .await
            .expect("oneshot")
    }

    /// POSTs a JSON body to the REST router with the realm header.
    pub async fn rest_json(
        &self,
        uri: &str,
        bearer: Option<&str>,
        body: &serde_json::Value,
    ) -> (u16, serde_json::Value) {
        let realm = self.realm.as_uuid().to_string();
        let auth = bearer.map(|t| format!("Bearer {t}"));
        let mut headers = vec![
            ("X-Realm-ID", realm.as_str()),
            (header::CONTENT_TYPE.as_str(), "application/json"),
        ];
        if let Some(a) = auth.as_deref() {
            headers.push(("authorization", a));
        }
        let resp = Self::send(
            &self.rest,
            "POST",
            uri,
            &headers,
            Body::from(body.to_string()),
        )
        .await;
        let status = resp.status().as_u16();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }
}

/// Whether a `Set-Cookie` of `resp` sets a live UI session.
pub fn sets_session(resp: &Response) -> bool {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|c| c.starts_with("hearth_ui_session=") && !c.contains("Max-Age=0"))
}

/// The TOTP code of `secret` at `unix_secs`.
pub fn totp(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let step = unix_secs / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let tag = ring::hmac::sign(&key, &step.to_be_bytes());
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

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("epoch")
        .as_secs()
}

/// The first six-digit run in `text`.
pub fn six_digit_code(text: &str) -> String {
    let bytes = text.as_bytes();
    (0..bytes.len().saturating_sub(5))
        .find(|&i| {
            bytes[i..i + 6].iter().all(u8::is_ascii_digit)
                && (i == 0 || !bytes[i - 1].is_ascii_digit())
                && bytes.get(i + 6).is_none_or(|b| !b.is_ascii_digit())
        })
        .map(|i| text[i..i + 6].to_string())
        .expect("a six-digit code in the mail")
}
