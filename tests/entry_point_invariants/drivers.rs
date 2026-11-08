//! One driver per registered entry point.
//!
//! A driver runs the steps that lead to its entry point, applies the
//! violation (if any) immediately before the request to the entry point, and
//! returns whether that request issued what the entry point issues. A step
//! before the entry point that fails is a broken driver, so it panics.

use std::collections::BTreeSet;
use std::fmt;

use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::ClientId;
use hearth::identity::tokens::{Audience, JwtAssertionClaims};
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, DeviceAuthorizationRequest, MfaProof,
    RegistrationOptions, SessionContext, TokenExchangeRequest, TokenIssuanceContext,
    UpdateUserRequest,
};

use super::browser::{body_text, hidden_fields, location, Browser};
use super::fixture::{
    now_secs, sets_session, six_digit_code, totp, Fx, Violation, CALLBACK, CLIENT_SECRET, ORG_SLUG,
    ORIGIN, PASSWORD, PKCE_CHALLENGE, PKCE_VERIFIER, RP_ID,
};
use super::webauthn_helper::TestAuthenticator;

/// The variant of an entry point a case drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// The entry point in realm context.
    Plain,
    /// The entry point for an organization (`organization` parameter).
    Org,
    /// One grant of the token endpoint.
    Grant(&'static str),
    /// One grant of the token endpoint for an organization.
    OrgGrant(&'static str),
}

/// One run target: an entry point id from `ENTRY_POINTS` and its variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Case {
    /// The `ENTRY_POINTS` id.
    pub entry: &'static str,
    /// Which variant.
    pub variant: Variant,
}

impl Case {
    /// Whether the case runs in an organization context.
    pub fn org(self) -> bool {
        matches!(self.variant, Variant::Org | Variant::OrgGrant(_))
    }

    /// The token grant, for a token-endpoint case.
    pub fn grant(self) -> Option<&'static str> {
        match self.variant {
            Variant::Grant(g) | Variant::OrgGrant(g) => Some(g),
            Variant::Plain | Variant::Org => None,
        }
    }
}

impl fmt::Display for Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.variant {
            Variant::Plain => write!(f, "{}", self.entry),
            Variant::Org => write!(f, "{}[org]", self.entry),
            Variant::Grant(g) => write!(f, "{}[{g}]", self.entry),
            Variant::OrgGrant(g) => write!(f, "{}[{g}, org]", self.entry),
        }
    }
}

/// The token grants a token-endpoint case can drive.
pub const GRANTS: &[&str] = &[
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "urn:hearth:grant-type:magic-link",
];

/// The token grants that can carry an organization context.
pub const ORG_GRANTS: &[&str] = &["authorization_code", "refresh_token"];

/// Runs `case` in `fx`, with `v` applied just before the entry point.
/// Returns whether the entry point issued.
pub async fn run(fx: &Fx, case: Case, v: Option<Violation>) -> bool {
    let realm_ui = format!("/ui/realms/{}", fx.realm_name);
    match case.entry {
        "password-login" => password_login(fx, "/ui/login", v).await,
        "password-login-realm" => password_login(fx, &format!("{realm_ui}/login"), v).await,
        "passkey-login" => passkey_login(fx, "/ui/login", v).await,
        "passkey-login-realm" => passkey_login(fx, &format!("{realm_ui}/login"), v).await,
        "magic-link" => magic_link(fx, "/ui/magic-link", v).await,
        "magic-link-realm" => magic_link(fx, &format!("{realm_ui}/magic-link"), v).await,
        "totp-step" => totp_step(fx, v).await,
        "email-otp-step" => email_otp_step(fx, v).await,
        "passkey-step" => passkey_step(fx, v).await,
        "mfa-enroll-required" => enroll_required(fx, v).await,
        "authorize-browser" => authorize_browser(fx, "/ui/oauth/authorize", case.org(), v).await,
        "authorize-browser-realm" => {
            authorize_browser(fx, &format!("{realm_ui}/oauth/authorize"), case.org(), v).await
        }
        "consent" => consent(fx, case.org(), v).await,
        "authorize-api" => authorize_api(fx, "/authorize", case.org(), v).await,
        "authorize-api-realm" => {
            let path = format!("/realms/{}/authorize", fx.realm_name);
            authorize_api(fx, &path, case.org(), v).await
        }
        "device-approval" => device_approval(fx, v).await,
        "token" => token(fx, "/token", case, v).await,
        "token-realm" => token(fx, &format!("/realms/{}/token", fx.realm_name), case, v).await,
        other => panic!("no driver for entry point {other}"),
    }
}

// ── shared steps ────────────────────────────────────────────────────────────

/// Follows same-origin redirects and continue pages from `resp` until a page
/// renders. Returns the page's path and HTML.
async fn follow(b: &mut Browser, mut resp: Response, mut path: String) -> (String, String) {
    for _ in 0..10 {
        match location(&resp) {
            Some(next) if next.starts_with('/') => {
                resp = b.get(&next).await;
                path = next;
            }
            _ => {
                assert_eq!(resp.status(), StatusCode::OK, "page at {path}");
                return (path, body_text(resp).await);
            }
        }
    }
    panic!("redirect loop at {path}");
}

/// Opens the realm's login page and submits the password. Returns the POST
/// response.
async fn submit_password(fx: &Fx, b: &mut Browser, login_path: &str) -> Response {
    let page = b.get(login_path).await;
    assert_eq!(page.status(), StatusCode::OK, "login page {login_path}");
    let html = body_text(page).await;
    let mut fields = hidden_fields(&html, login_path);
    fields.push(("email".to_string(), fx.user.email().to_string()));
    fields.push(("password".to_string(), PASSWORD.to_string()));
    b.post_form(login_path, &fields).await
}

/// Signs in with the password and follows the flow to the second-factor
/// page. Returns the page's path and HTML.
async fn password_to_second_factor(fx: &Fx, b: &mut Browser) -> (String, String) {
    let login_path = format!("/ui/realms/{}/login", fx.realm_name);
    let resp = submit_password(fx, b, &login_path).await;
    assert!(
        !sets_session(&resp),
        "a user with a second factor must not get a session from the password alone"
    );
    follow(b, resp, login_path).await
}

/// Enrols a TOTP factor for the user and returns its secret.
fn enrol_totp(fx: &Fx) -> String {
    let id = fx.h.identity();
    let enrolment = id.enroll_totp(&fx.realm, fx.uid()).expect("enroll_totp");
    id.verify_totp_enrollment(
        &fx.realm,
        fx.uid(),
        &totp(&enrolment.secret_base32, now_secs()),
    )
    .expect("verify_totp_enrollment");
    enrolment.secret_base32.clone()
}

/// Enrols a discoverable, user-verifying passkey for the user.
fn enrol_passkey(fx: &Fx) -> TestAuthenticator {
    let authenticator = TestAuthenticator::new(RP_ID);
    let id = fx.h.identity();
    let challenge = id
        .start_webauthn_registration(
            &fx.realm,
            fx.uid(),
            &RegistrationOptions {
                rp_id: RP_ID.to_string(),
                discoverable: true,
            },
        )
        .expect("start registration");
    let (cdj, att) = authenticator.build_verified_registration_response(&challenge, ORIGIN);
    id.complete_webauthn_registration(
        &fx.realm,
        fx.uid(),
        &cdj,
        &att,
        ORIGIN,
        true,
        &Default::default(),
    )
    .expect("complete registration");
    authenticator
}

/// The assertion JSON a browser posts for `challenge`.
fn assertion_json(
    authenticator: &TestAuthenticator,
    challenge_b64: &str,
    user_handle: Option<&str>,
) -> serde_json::Value {
    let challenge = URL_SAFE_NO_PAD
        .decode(challenge_b64)
        .expect("challenge is base64url");
    let (cdj, auth_data, sig, _) =
        authenticator.build_verified_authentication_response(&challenge, ORIGIN, 1, user_handle);
    let mut body = serde_json::json!({
        "credential_id": URL_SAFE_NO_PAD.encode(&authenticator.credential_id),
        "client_data_json": URL_SAFE_NO_PAD.encode(&cdj),
        "authenticator_data": URL_SAFE_NO_PAD.encode(&auth_data),
        "signature": URL_SAFE_NO_PAD.encode(&sig),
    });
    if let Some(handle) = user_handle {
        body["user_handle"] = URL_SAFE_NO_PAD.encode(handle.as_bytes()).into();
    }
    body
}

/// The query of an authorization request from `client`.
fn authorize_query(client: &ClientId, org: bool) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("client_id", &client.as_uuid().to_string())
        .append_pair("redirect_uri", CALLBACK)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid")
        .append_pair("state", "inv-state")
        .append_pair("code_challenge", PKCE_CHALLENGE)
        .append_pair("code_challenge_method", "S256");
    if org {
        query.append_pair("organization", ORG_SLUG);
    }
    query.finish()
}

/// Whether `target` hands the client an authorization code.
fn has_code(target: Option<&str>) -> bool {
    target.is_some_and(|t| t.starts_with(&format!("{CALLBACK}?")) && t.contains("code="))
}

/// An authorization code for the app client, minted through the engine.
fn mint_code(fx: &Fx, org: bool) -> String {
    fx.h.identity()
        .authorize(
            &fx.realm,
            &AuthorizationRequest {
                organization: org.then(|| ORG_SLUG.to_string()),
                client_id: fx.app_id().clone(),
                redirect_uri: CALLBACK.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "inv-state".to_string(),
                nonce: None,
                code_challenge: Some(PKCE_CHALLENGE.to_string()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id: fx.uid().clone(),
                amr_values: vec![],
                response_mode: None,
                request: None,
            },
        )
        .expect("authorize")
        .code()
        .to_string()
}

// ── sessions ────────────────────────────────────────────────────────────────

async fn password_login(fx: &Fx, login_path: &str, v: Option<Violation>) -> bool {
    let mut b = fx.browser(None);
    let page = b.get(login_path).await;
    assert_eq!(page.status(), StatusCode::OK, "login page {login_path}");
    let html = body_text(page).await;
    let mut fields = hidden_fields(&html, login_path);
    fields.push(("email".to_string(), fx.user.email().to_string()));
    fields.push(("password".to_string(), PASSWORD.to_string()));
    fx.violate(v, None, fx.uid());
    let resp = b.post_form(login_path, &fields).await;
    sets_session(&resp)
}

async fn passkey_login(fx: &Fx, login_base: &str, v: Option<Violation>) -> bool {
    let authenticator = enrol_passkey(fx);
    let begin = Fx::send(
        &fx.web,
        "GET",
        &format!("{login_base}/passkey-begin"),
        &[("host", RP_ID)],
        Body::empty(),
    )
    .await;
    assert_eq!(begin.status(), StatusCode::OK, "passkey begin");
    let begin: serde_json::Value =
        serde_json::from_str(&body_text(begin).await).expect("begin JSON");
    let handle = fx.uid().as_uuid().to_string();
    let body = assertion_json(
        &authenticator,
        begin["challenge"].as_str().expect("challenge"),
        Some(&handle),
    );
    fx.violate(v, None, fx.uid());
    let resp = Fx::send(
        &fx.web,
        "POST",
        &format!("{login_base}/passkey-complete"),
        &[
            ("host", RP_ID),
            (header::CONTENT_TYPE.as_str(), "application/json"),
        ],
        Body::from(body.to_string()),
    )
    .await;
    sets_session(&resp)
}

async fn magic_link(fx: &Fx, path: &str, v: Option<Violation>) -> bool {
    let minted =
        fx.h.identity()
            .request_magic_link(&fx.realm, fx.user.email())
            .expect("mint magic link");
    // The link's GET moves the token into a cookie and renders the
    // confirmation form; its POST redeems the link.
    let mut b = fx.browser(None);
    let link = format!("{path}?token={}", minted.token());
    let first = b.get(&link).await;
    let (_, html) = follow(&mut b, first, link).await;
    let fields = hidden_fields(&html, path);
    fx.violate(v, None, fx.uid());
    let resp = b.post_form(path, &fields).await;
    sets_session(&resp)
}

async fn totp_step(fx: &Fx, v: Option<Violation>) -> bool {
    let secret = enrol_totp(fx);
    let mut b = fx.browser(None);
    let (_, html) = password_to_second_factor(fx, &mut b).await;
    let mut fields = hidden_fields(&html, "/ui/mfa-challenge");
    fields.push(("code".to_string(), totp(&secret, now_secs() + 30)));
    fx.violate(v, None, fx.uid());
    b.post_form("/ui/mfa-challenge", &fields).await;
    b.has_cookie("hearth_ui_session")
}

async fn email_otp_step(fx: &Fx, v: Option<Violation>) -> bool {
    fx.edit_realm(|c| c.mfa_methods = Some(vec!["totp".to_string(), "email_otp".to_string()]));
    fx.h.identity()
        .update_user(
            &fx.realm,
            fx.uid(),
            &UpdateUserRequest {
                email_otp_enabled: Some(true),
                ..Default::default()
            },
        )
        .expect("enable email OTP");
    let mut b = fx.browser(None);
    let (path, html) = password_to_second_factor(fx, &mut b).await;
    assert!(
        path.starts_with("/ui/mfa-otp-challenge"),
        "OTP page: {path}"
    );
    let mut fields = hidden_fields(&html, "/ui/mfa-otp-challenge");
    fields.push(("code".to_string(), six_digit_code(&fx.outbox.last())));
    fx.violate(v, None, fx.uid());
    b.post_form("/ui/mfa-otp-challenge", &fields).await;
    b.has_cookie("hearth_ui_session")
}

async fn passkey_step(fx: &Fx, v: Option<Violation>) -> bool {
    let authenticator = enrol_passkey(fx);
    let mut b = fx.browser(Some(RP_ID));
    let (path, _) = password_to_second_factor(fx, &mut b).await;
    assert!(
        path.starts_with("/ui/mfa-passkey-challenge"),
        "passkey page: {path}"
    );
    let csrf = b
        .cookie("hearth_ui_csrf")
        .expect("the challenge page sets a CSRF cookie");
    let begin = b
        .post_json(
            "/ui/mfa-passkey-challenge/begin",
            &serde_json::json!({}),
            &[("x-csrf-token", &csrf)],
        )
        .await;
    assert_eq!(begin.status(), StatusCode::OK, "passkey challenge begin");
    let begin: serde_json::Value =
        serde_json::from_str(&body_text(begin).await).expect("begin JSON");
    let body = assertion_json(
        &authenticator,
        begin["challenge"].as_str().expect("challenge"),
        None,
    );
    fx.violate(v, None, fx.uid());
    b.post_json(
        "/ui/mfa-passkey-challenge/complete",
        &body,
        &[("x-csrf-token", &csrf)],
    )
    .await;
    b.has_cookie("hearth_ui_session")
}

async fn enroll_required(fx: &Fx, v: Option<Violation>) -> bool {
    fx.edit_realm(|c| c.mfa_required = Some(true));
    let mut b = fx.browser(None);
    let (path, html) = password_to_second_factor(fx, &mut b).await;
    assert_eq!(path, "/ui/mfa-enroll-required", "forced enrolment");
    let secret =
        fx.h.identity()
            .enroll_totp(&fx.realm, fx.uid())
            .expect("pending TOTP secret")
            .secret_base32
            .clone();
    let mut fields = hidden_fields(&html, "/ui/mfa-enroll-required/activate");
    fields.push(("code".to_string(), totp(&secret, now_secs())));
    fx.violate(v, None, fx.uid());
    b.post_form("/ui/mfa-enroll-required/activate", &fields)
        .await;
    b.has_cookie("hearth_ui_session")
}

// ── authorization codes and device approval ─────────────────────────────────

async fn authorize_browser(fx: &Fx, base: &str, org: bool, v: Option<Violation>) -> bool {
    let mut b = fx.signed_in(fx.uid(), None);
    let url = format!("{base}?{}", authorize_query(fx.app_id(), org));
    fx.violate(v, Some(fx.app_id()), fx.uid());
    let resp = b.get(&url).await;
    has_code(location(&resp).as_deref())
}

async fn consent(fx: &Fx, org: bool, v: Option<Violation>) -> bool {
    let mut b = fx.signed_in(fx.uid(), None);
    let url = format!(
        "/ui/realms/{}/oauth/authorize?{}",
        fx.realm_name,
        authorize_query(fx.consent.client_id(), org)
    );
    let resp = b.get(&url).await;
    let consent_url = location(&resp).expect("authorize redirects to consent");
    assert!(
        consent_url.starts_with("/ui/oauth/consent"),
        "consent: {consent_url}"
    );
    let page = b.get(&consent_url).await;
    assert_eq!(page.status(), StatusCode::OK, "consent page");
    let mut fields = hidden_fields(&body_text(page).await, "/ui/oauth/consent");
    fields.push(("scope".to_string(), "openid".to_string()));
    fields.push(("decision".to_string(), "approve".to_string()));
    fx.violate(v, Some(fx.consent.client_id()), fx.uid());
    let resp = b.post_form("/ui/oauth/consent", &fields).await;
    has_code(location(&resp).as_deref())
}

async fn authorize_api(fx: &Fx, path: &str, org: bool, v: Option<Violation>) -> bool {
    let id = fx.h.identity();
    let session = id
        .create_session(&fx.realm, fx.uid(), &SessionContext::default())
        .expect("session");
    let bearer = id
        .issue_tokens(&fx.realm, fx.uid(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();
    let mut body = serde_json::json!({
        "client_id": fx.app_id().as_uuid().to_string(),
        "redirect_uri": CALLBACK,
        "response_type": "code",
        "scope": "openid",
        "state": "inv-state",
        "code_challenge": PKCE_CHALLENGE,
        "code_challenge_method": "S256",
    });
    if org {
        body["organization"] = ORG_SLUG.into();
    }
    fx.violate(v, Some(fx.app_id()), fx.uid());
    let (status, json) = fx.rest_json(path, Some(&bearer), &body).await;
    status == 200 && json["code"].as_str().is_some_and(|c| !c.is_empty())
}

async fn device_approval(fx: &Fx, v: Option<Violation>) -> bool {
    let mut b = fx.signed_in(fx.uid(), None);
    let started =
        fx.h.identity()
            .device_authorize(
                &fx.realm,
                &DeviceAuthorizationRequest {
                    client_id: fx.app_id().clone(),
                    scope: Some("openid".to_string()),
                },
            )
            .expect("device authorize");
    let csrf = b.cookie("hearth_ui_csrf").expect("CSRF cookie");
    let fields = vec![
        ("user_code".to_string(), started.user_code.clone()),
        ("decision".to_string(), "approve".to_string()),
        ("csrf_token".to_string(), csrf),
    ];
    fx.violate(v, Some(fx.app_id()), fx.uid());
    let resp = b.post_form("/ui/device", &fields).await;
    location(&resp).as_deref() == Some("/ui/device?flash=approved")
}

// ── the token endpoint ──────────────────────────────────────────────────────

// One arm per grant; splitting them apart would only scatter the table.
#[allow(clippy::too_many_lines)]
async fn token(fx: &Fx, path: &str, case: Case, v: Option<Violation>) -> bool {
    let grant = case.grant().expect("a token case names its grant");
    let app = fx.app_id().as_uuid().to_string();
    let id = fx.h.identity();
    let (client, body) = match grant {
        "authorization_code" => (
            Some(fx.app_id()),
            serde_json::json!({
                "grant_type": grant,
                "client_id": app,
                "client_secret": CLIENT_SECRET,
                "code": mint_code(fx, case.org()),
                "redirect_uri": CALLBACK,
                "code_verifier": PKCE_VERIFIER,
            }),
        ),
        "refresh_token" => {
            let tokens = id
                .exchange_authorization_code(
                    &fx.realm,
                    &TokenExchangeRequest {
                        client_id: fx.app_id().clone(),
                        code: mint_code(fx, case.org()),
                        redirect_uri: CALLBACK.to_string(),
                        code_verifier: Some(PKCE_VERIFIER.to_string()),
                        dpop_jkt: None,
                        client_assertion_type: None,
                        client_assertion: None,
                        resource: None,
                    },
                )
                .expect("exchange code");
            (
                Some(fx.app_id()),
                serde_json::json!({
                    "grant_type": grant,
                    "client_id": app,
                    "client_secret": CLIENT_SECRET,
                    "refresh_token": tokens.refresh_token(),
                }),
            )
        }
        "client_credentials" => (
            Some(fx.app_id()),
            serde_json::json!({
                "grant_type": grant,
                "client_id": app,
                "client_secret": CLIENT_SECRET,
            }),
        ),
        "urn:ietf:params:oauth:grant-type:device_code" => {
            let started = id
                .device_authorize(
                    &fx.realm,
                    &DeviceAuthorizationRequest {
                        client_id: fx.app_id().clone(),
                        scope: Some("openid".to_string()),
                    },
                )
                .expect("device authorize");
            id.approve_device_from_session(&fx.realm, &started.user_code, fx.uid(), MfaProof::None)
                .expect("approve device");
            (
                Some(fx.app_id()),
                serde_json::json!({
                    "grant_type": grant,
                    "client_id": app,
                    "client_secret": CLIENT_SECRET,
                    "device_code": started.device_code,
                }),
            )
        }
        "urn:ietf:params:oauth:grant-type:jwt-bearer" => {
            let issuer = format!("{}/realms/{}", id.oidc_discovery().issuer, fx.realm_name);
            #[allow(clippy::cast_possible_wrap)]
            let now = now_secs() as i64;
            let jwt = fx.jwt_client.as_uuid().to_string();
            let assertion = fx
                .jwt_key
                .issue_assertion_jwt(&JwtAssertionClaims {
                    iss: jwt.clone(),
                    sub: jwt.clone(),
                    aud: Audience::single(issuer),
                    exp: now + 60,
                    jti: Some(uuid::Uuid::new_v4().to_string()),
                    iat: Some(now),
                })
                .expect("sign assertion");
            (
                Some(&fx.jwt_client),
                serde_json::json!({
                    "grant_type": grant,
                    "client_id": jwt,
                    "assertion": assertion,
                    "scope": "read",
                }),
            )
        }
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            let session = id
                .create_session(&fx.realm, fx.uid(), &SessionContext::default())
                .expect("session");
            let subject = id
                .issue_tokens_with_context(
                    &fx.realm,
                    fx.uid(),
                    session.id(),
                    &TokenIssuanceContext {
                        client_id: None,
                        granted_scopes: BTreeSet::from(["openid".to_string()]),
                        oid: None,
                        resource: None,
                        dpop_jkt: None,
                    },
                )
                .expect("subject token")
                .access_token()
                .to_string();
            (
                Some(fx.app_id()),
                serde_json::json!({
                    "grant_type": grant,
                    "client_id": app,
                    "client_secret": CLIENT_SECRET,
                    "subject_token": subject,
                    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                }),
            )
        }
        "urn:hearth:grant-type:magic-link" => {
            let minted = id
                .request_magic_link(&fx.realm, fx.user.email())
                .expect("mint magic link");
            (
                None,
                serde_json::json!({ "grant_type": grant, "token": minted.token() }),
            )
        }
        other => panic!("no token driver for grant {other}"),
    };
    fx.violate(v, client, fx.uid());
    let (status, json) = fx.rest_json(path, None, &body).await;
    status == 200 && json["access_token"].as_str().is_some_and(|t| !t.is_empty())
}
