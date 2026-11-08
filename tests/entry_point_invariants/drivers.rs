//! One driver per registered entry point.
//!
//! A driver runs the steps that lead to its entry point, applies the
//! violation (if any) immediately before the request to the entry point, and
//! returns whether that request issued what the entry point issues. A step
//! before the entry point that fails is a broken driver, so it panics.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{AgentId, ClientId, IdpId, RealmId, Timestamp, UserId};
use hearth::identity::federation::{
    compute_federation_state_mac, FederationSecret, IdpConfig, IdpKind, StateBag,
};
use hearth::identity::tokens::RsaSigningKey;
use hearth::identity::tokens::{Audience, JwtAssertionClaims};
use hearth::identity::{
    AgentOwner, AuthorizationRequest, CodeChallengeMethod, CreateAgentRequest,
    DeviceAuthorizationRequest, MfaProof, RegistrationOptions, RequiredAction, SessionContext,
    TokenExchangeRequest, TokenIssuanceContext, UpdateUserRequest,
};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};

use super::browser::{body_text, hidden_fields, location, Browser};
use super::fixture::{
    now_secs, sets_session, six_digit_code, system_realm, totp, Fx, Violation, CALLBACK,
    CLIENT_SECRET, COOKIE_SECRET, ORG_SLUG, ORIGIN, PASSWORD, PKCE_CHALLENGE, PKCE_VERIFIER, RP_ID,
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
        "password-login-admin" => admin_password_login(fx, v).await,
        "passkey-login-admin" => admin_passkey_login(fx, v).await,
        "magic-link" => magic_link(fx, "/ui/magic-link", v).await,
        "magic-link-realm" => magic_link(fx, &format!("{realm_ui}/magic-link"), v).await,
        "totp-step" => totp_step(fx, v).await,
        "email-otp-step" => email_otp_step(fx, v).await,
        "passkey-step" => passkey_step(fx, v).await,
        "mfa-enroll-required" => enroll_required(fx, v).await,
        "ra-verify-email-page" => ra_verify_email_page(fx, v).await,
        "ra-verify-email-confirm" => ra_verify_email_confirm(fx, v).await,
        "ra-update-password" => ra_update_password(fx, v).await,
        "ra-email-otp-page" => ra_email_otp_page(fx, v).await,
        "ra-email-otp-verify" => ra_email_otp_verify(fx, v).await,
        "ra-enroll-mfa-page" => ra_enroll_mfa_page(fx, v).await,
        "ra-enroll-mfa" => ra_enroll_mfa(fx, v).await,
        "ra-enroll-passkey" => ra_enroll_passkey(fx, v).await,
        "social-callback" => social_callback(fx, "/ui/federation/callback", false, v).await,
        "social-callback-post" => social_callback(fx, "/ui/federation/callback", true, v).await,
        "social-callback-realm" => {
            social_callback(fx, &format!("{realm_ui}/federation/callback"), false, v).await
        }
        "social-callback-realm-post" => {
            social_callback(fx, &format!("{realm_ui}/federation/callback"), true, v).await
        }
        "social-confirm-link" => social_confirm_link(fx, "/ui/federation/confirm-link", v).await,
        "social-confirm-link-realm" => {
            social_confirm_link(fx, &format!("{realm_ui}/federation/confirm-link"), v).await
        }
        "saml-acs" => saml_acs(fx, v).await,
        "aat-issue" => aat_issue(fx, v).await,
        "aat-derive" => aat_derive(fx, v).await,
        "transaction-token" => transaction_token(fx, v).await,
        "agent-api-key" => agent_api_key(fx, v).await,
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
        "admin-api-token" => admin_api_token(fx, v).await,
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
                assert_eq!(resp.status(), StatusCode::OK, "a redirect ends on a page");
                return (path, body_text(resp).await);
            }
        }
    }
    panic!("the redirects do not end");
}

/// Opens the realm's login page and submits the password. Returns the POST
/// response.
async fn submit_password(fx: &Fx, b: &mut Browser, login_path: &str) -> Response {
    let fields = login_fields(b, login_path, fx.user.email()).await;
    b.post_form(login_path, &fields).await
}

/// Opens the login page at `login_path` and returns its form fields, filled
/// in for `email` and [`PASSWORD`].
async fn login_fields(b: &mut Browser, login_path: &str, email: &str) -> Vec<(String, String)> {
    let page = b.get(login_path).await;
    assert_eq!(page.status(), StatusCode::OK, "login page {login_path}");
    let html = body_text(page).await;
    let mut fields = hidden_fields(&html, login_path);
    fields.push(("email".to_string(), email.to_string()));
    fields.push(("password".to_string(), PASSWORD.to_string()));
    fields
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
    enrol_totp_in(fx, &fx.realm, fx.uid())
}

/// Enrols a TOTP factor for `user` of `realm` and returns its secret. The
/// enrolment uses the previous time step, so a later step can use the
/// current one without a replay refusal.
fn enrol_totp_in(fx: &Fx, realm: &RealmId, user: &UserId) -> String {
    let id = fx.h.identity();
    let enrolment = id.enroll_totp(realm, user).expect("enroll_totp");
    id.verify_totp_enrollment(
        realm,
        user,
        &totp(&enrolment.secret_base32, now_secs() - 30),
    )
    .expect("verify_totp_enrollment");
    enrolment.secret_base32.clone()
}

/// Enrols a discoverable, user-verifying passkey for the user.
fn enrol_passkey(fx: &Fx) -> TestAuthenticator {
    enrol_passkey_in(fx, &fx.realm, fx.uid())
}

/// Enrols a discoverable, user-verifying passkey for `user` of `realm`.
fn enrol_passkey_in(fx: &Fx, realm: &RealmId, user: &UserId) -> TestAuthenticator {
    let authenticator = TestAuthenticator::new(RP_ID);
    let id = fx.h.identity();
    let challenge = id
        .start_webauthn_registration(
            realm,
            user,
            &RegistrationOptions {
                rp_id: RP_ID.to_string(),
                discoverable: true,
            },
        )
        .expect("start registration");
    let (cdj, att) = authenticator.build_verified_registration_response(&challenge, ORIGIN);
    id.complete_webauthn_registration(realm, user, &cdj, &att, ORIGIN, true, &Default::default())
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
    passkey_login_as(fx, login_base, &fx.realm, fx.uid(), v).await
}

async fn passkey_login_as(
    fx: &Fx,
    login_base: &str,
    realm: &RealmId,
    user: &UserId,
    v: Option<Violation>,
) -> bool {
    let authenticator = enrol_passkey_in(fx, realm, user);
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
    let handle = user.as_uuid().to_string();
    let body = assertion_json(
        &authenticator,
        begin["challenge"].as_str().expect("challenge"),
        Some(&handle),
    );
    fx.violate_in(realm, v, None, user);
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
        "the login asks for the email OTP"
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
        "the login asks for the passkey"
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

// ── operator console ────────────────────────────────────────────────────────

/// The system realm always requires MFA, so the operator console sign-in
/// issues a session only after the second factor. The driver applies the
/// violation before the password POST and reports whether the sign-in ends
/// with a session. Under [`Violation::MfaRequired`] the operator holds no
/// second factor (the system realm cannot turn MFA off).
async fn admin_password_login(fx: &Fx, v: Option<Violation>) -> bool {
    let sys = system_realm();
    let op = fx.operator();
    let no_factor = v == Some(Violation::MfaRequired);
    let secret = (!no_factor).then(|| enrol_totp_in(fx, &sys, op.id()));
    let login_path = "/ui/admin/login";
    let mut b = fx.browser(None);
    let fields = login_fields(&mut b, login_path, op.email()).await;
    fx.violate_in(&sys, v.filter(|_| !no_factor), None, op.id());
    let resp = b.post_form(login_path, &fields).await;
    let Some(secret) = secret else {
        return b.has_cookie("hearth_ui_session");
    };
    if b.has_cookie("hearth_ui_session") || resp.status() != StatusCode::OK {
        return b.has_cookie("hearth_ui_session");
    }
    // The password POST renders the TOTP form in place.
    let (_, html) = follow(&mut b, resp, login_path.to_string()).await;
    let mut fields = hidden_fields(&html, "/ui/mfa-challenge");
    fields.push(("code".to_string(), totp(&secret, now_secs() + 30)));
    b.post_form("/ui/mfa-challenge", &fields).await;
    b.has_cookie("hearth_ui_session")
}

async fn admin_passkey_login(fx: &Fx, v: Option<Violation>) -> bool {
    let op = fx.operator();
    passkey_login_as(fx, "/ui/admin/login", &system_realm(), op.id(), v).await
}

/// The operator token: a console session that proved a passkey, then the
/// form with the password and a TOTP code (step-up).
async fn admin_api_token(fx: &Fx, v: Option<Violation>) -> bool {
    const PAGE: &str = "/ui/admin/api-tokens";
    let sys = system_realm();
    let op = fx.operator();
    let secret = enrol_totp_in(fx, &sys, op.id());
    let context = SessionContext {
        mfa_proof: MfaProof::ProvedWebAuthn,
        ..SessionContext::default()
    };
    let mut b = fx.signed_in_with(&sys, op.id(), context, None);
    let page = b.get(PAGE).await;
    assert_eq!(page.status(), StatusCode::OK, "operator token page");
    let html = body_text(page).await;
    let mut fields = hidden_fields(&html, PAGE);
    fields.push(("ttl_minutes".to_string(), "15".to_string()));
    fields.push(("password".to_string(), PASSWORD.to_string()));
    fields.push(("totp_code".to_string(), totp(&secret, now_secs())));
    fx.violate_in(&sys, v, None, op.id());
    let resp = b.post_form(PAGE, &fields).await;
    body_text(resp).await.contains("id=\"api-token\"")
}

// ── required actions ────────────────────────────────────────────────────────

/// Gives the user `actions`, signs in with the password and returns the
/// browser and the target of the continue page the login answers.
async fn login_with_actions(
    fx: &Fx,
    actions: Vec<RequiredAction>,
    host: Option<&str>,
) -> (Browser, String) {
    set_actions(fx, actions);
    let mut b = fx.browser(host);
    let login_path = format!("/ui/realms/{}/login", fx.realm_name);
    let resp = submit_password(fx, &mut b, &login_path).await;
    let next = location(&resp).expect("the login continues");
    (b, next)
}

fn set_actions(fx: &Fx, actions: Vec<RequiredAction>) {
    fx.h.identity()
        .update_user(
            &fx.realm,
            fx.uid(),
            &UpdateUserRequest {
                required_actions: Some(actions),
                ..Default::default()
            },
        )
        .expect("set required actions");
}

/// GETs `page` and returns its HTML.
async fn open(b: &mut Browser, page: &str) -> String {
    let resp = b.get(page).await;
    assert_eq!(resp.status(), StatusCode::OK, "the page opens");
    body_text(resp).await
}

/// The login reaches the action page; the GET of the page completes the
/// action because the email is verified already.
async fn ra_verify_email_page(fx: &Fx, v: Option<Violation>) -> bool {
    let id = fx.h.identity();
    let token = id
        .issue_email_verification_token(&fx.realm, fx.uid())
        .expect("verification token");
    id.verify_email_token(&fx.realm, &token)
        .expect("verify email");
    let (mut b, page) = login_with_actions(fx, vec![RequiredAction::VerifyEmail], None).await;
    assert_eq!(page, "/required-action/VERIFY_EMAIL");
    fx.violate(v, None, fx.uid());
    b.get(&page).await;
    b.has_cookie("hearth_ui_session")
}

async fn ra_verify_email_confirm(fx: &Fx, v: Option<Violation>) -> bool {
    const CONFIRM: &str = "/required-action/VERIFY_EMAIL/confirm";
    let (mut b, page) = login_with_actions(fx, vec![RequiredAction::VerifyEmail], None).await;
    assert_eq!(page, "/required-action/VERIFY_EMAIL");
    open(&mut b, &page).await;
    let mail = fx.outbox.last();
    let start = mail
        .find(&format!("{CONFIRM}?token="))
        .expect("a confirm link in the email");
    let link: String = mail[start..]
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '<')
        .collect();
    // The link's GET moves the token into a cookie.
    let hop = b.get(&link).await;
    let confirm = location(&hop).expect("the link redirects to the confirm page");
    let html = open(&mut b, &confirm).await;
    let fields = hidden_fields(&html, CONFIRM);
    fx.violate(v, None, fx.uid());
    b.post_form(CONFIRM, &fields).await;
    b.has_cookie("hearth_ui_session")
}

async fn ra_update_password(fx: &Fx, v: Option<Violation>) -> bool {
    let (mut b, page) = login_with_actions(fx, vec![RequiredAction::UpdatePassword], None).await;
    assert_eq!(page, "/required-action/UPDATE_PASSWORD");
    let html = open(&mut b, &page).await;
    let new = "invariant-registry-password-2";
    let mut fields = hidden_fields(&html, &page);
    fields.push(("current_password".to_string(), PASSWORD.to_string()));
    fields.push(("new_password".to_string(), new.to_string()));
    fields.push(("confirm_password".to_string(), new.to_string()));
    fx.violate(v, None, fx.uid());
    b.post_form(&page, &fields).await;
    b.has_cookie("hearth_ui_session")
}

/// The user holds email OTP and proves it at the login; the GET of the
/// action page completes the action because the factor is held.
async fn ra_email_otp_page(fx: &Fx, v: Option<Violation>) -> bool {
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
    set_actions(fx, vec![RequiredAction::EnrollEmailOtp]);
    let mut b = fx.browser(None);
    let (path, html) = password_to_second_factor(fx, &mut b).await;
    assert!(
        path.starts_with("/ui/mfa-otp-challenge"),
        "the login asks for the email OTP"
    );
    let mut fields = hidden_fields(&html, "/ui/mfa-otp-challenge");
    fields.push(("code".to_string(), six_digit_code(&fx.outbox.last())));
    let resp = b.post_form("/ui/mfa-otp-challenge", &fields).await;
    let page = location(&resp).expect("the second factor continues");
    assert_eq!(page, "/required-action/ENROLL_EMAIL_OTP");
    fx.violate(v, None, fx.uid());
    b.get(&page).await;
    b.has_cookie("hearth_ui_session")
}

async fn ra_email_otp_verify(fx: &Fx, v: Option<Violation>) -> bool {
    const VERIFY: &str = "/required-action/ENROLL_EMAIL_OTP/verify";
    fx.edit_realm(|c| c.mfa_methods = Some(vec!["totp".to_string(), "email_otp".to_string()]));
    let (mut b, page) = login_with_actions(fx, vec![RequiredAction::EnrollEmailOtp], None).await;
    assert_eq!(page, "/required-action/ENROLL_EMAIL_OTP");
    let html = open(&mut b, &page).await;
    let send = "/required-action/ENROLL_EMAIL_OTP/send";
    let fields = hidden_fields(&html, send);
    let resp = b.post_form(send, &fields).await;
    assert_eq!(resp.status(), StatusCode::OK, "the send step");
    let html = body_text(resp).await;
    let mut fields = hidden_fields(&html, VERIFY);
    fields.push(("code".to_string(), six_digit_code(&fx.outbox.last())));
    fx.violate(v, None, fx.uid());
    b.post_form(VERIFY, &fields).await;
    b.has_cookie("hearth_ui_session")
}

/// The user holds TOTP and proves it at the login; the GET of the action
/// page completes the action because the factor is held.
async fn ra_enroll_mfa_page(fx: &Fx, v: Option<Violation>) -> bool {
    fx.edit_realm(|c| c.mfa_methods = Some(vec!["totp".to_string()]));
    let secret = enrol_totp(fx);
    set_actions(fx, vec![RequiredAction::EnrollMfa]);
    let mut b = fx.browser(None);
    let (_, html) = password_to_second_factor(fx, &mut b).await;
    let mut fields = hidden_fields(&html, "/ui/mfa-challenge");
    fields.push(("code".to_string(), totp(&secret, now_secs() + 30)));
    let resp = b.post_form("/ui/mfa-challenge", &fields).await;
    let page = location(&resp).expect("the second factor continues");
    assert_eq!(page, "/required-action/enroll-mfa");
    fx.violate(v, None, fx.uid());
    b.get(&page).await;
    b.has_cookie("hearth_ui_session")
}

async fn ra_enroll_mfa(fx: &Fx, v: Option<Violation>) -> bool {
    fx.edit_realm(|c| c.mfa_methods = Some(vec!["totp".to_string()]));
    let (mut b, page) = login_with_actions(fx, vec![RequiredAction::EnrollMfa], None).await;
    assert_eq!(page, "/required-action/enroll-mfa");
    let html = open(&mut b, &page).await;
    let secret =
        fx.h.identity()
            .load_pending_totp_secret(&fx.realm, fx.uid())
            .expect("load pending secret")
            .expect("a pending enrolment");
    let mut fields = hidden_fields(&html, &page);
    fields.push(("code".to_string(), totp(&secret, now_secs())));
    fx.violate(v, None, fx.uid());
    b.post_form(&page, &fields).await;
    b.has_cookie("hearth_ui_session")
}

/// A realm that requires a passkey: the login of a password-only user
/// registers one.
async fn ra_enroll_passkey(fx: &Fx, v: Option<Violation>) -> bool {
    fx.edit_realm(|c| {
        c.webauthn_required = Some(true);
        c.mfa_methods = Some(vec!["webauthn".to_string()]);
    });
    let (mut b, page) = login_with_actions(fx, vec![], Some(RP_ID)).await;
    assert_eq!(page, "/required-action/enroll-mfa");
    let html = open(&mut b, &page).await;
    let csrf = html
        .split("<meta name=\"csrf\" content=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the page carries a CSRF token for its script")
        .to_string();
    let begin = b
        .post_json(
            "/required-action/enroll-mfa/passkey/begin",
            &serde_json::json!({}),
            &[("x-csrf-token", &csrf)],
        )
        .await;
    assert_eq!(begin.status(), StatusCode::OK, "registration begin");
    let opts: serde_json::Value =
        serde_json::from_str(&body_text(begin).await).expect("options JSON");
    let challenge = URL_SAFE_NO_PAD
        .decode(opts["challenge"].as_str().expect("challenge"))
        .expect("challenge is base64url");
    let (cdj, att) =
        TestAuthenticator::new(RP_ID).build_verified_registration_response(&challenge, ORIGIN);
    fx.violate(v, None, fx.uid());
    b.post_json(
        "/required-action/enroll-mfa/passkey/complete",
        &serde_json::json!({
            "client_data_json": URL_SAFE_NO_PAD.encode(&cdj),
            "attestation_object": URL_SAFE_NO_PAD.encode(&att),
        }),
        &[("x-csrf-token", &csrf)],
    )
    .await;
    b.has_cookie("hearth_ui_session")
}

// ── federation ──────────────────────────────────────────────────────────────

const UPSTREAM: &str = "https://idp.example";
const UPSTREAM_CLIENT: &str = "inv-client";
const EXTERNAL_SUB: &str = "inv-external-sub";
const FED_STATE: &str = "inv-fed-state";
const FED_NONCE: &str = "inv-fed-nonce";

/// One RSA key for every upstream ID token and SAML response: a key takes
/// long to generate in a debug build.
fn upstream_key() -> &'static RsaSigningKey {
    static KEY: OnceLock<RsaSigningKey> = OnceLock::new();
    KEY.get_or_init(|| RsaSigningKey::generate("inv-upstream", 365).expect("RSA key"))
}

/// Registers an identity provider of `kind` in the fixture realm.
fn register_upstream(fx: &Fx, kind: IdpKind, trust_asserted_email: bool) -> IdpId {
    let id = IdpId::generate();
    let saml = kind == IdpKind::Saml;
    let mut claim_mappings = BTreeMap::new();
    if saml {
        claim_mappings.insert("email".to_string(), "NameID".to_string());
    }
    fx.h.identity()
        .register_idp(&IdpConfig {
            id: id.clone(),
            realm_id: fx.realm.clone(),
            name: format!("inv-{}", uuid::Uuid::new_v4().simple()),
            kind,
            display_name: "Upstream".to_string(),
            issuer: UPSTREAM.to_string(),
            authorization_endpoint: format!("{UPSTREAM}/auth"),
            token_endpoint: if saml {
                String::new()
            } else {
                format!("{UPSTREAM}/token")
            },
            userinfo_endpoint: None,
            jwks_uri: (!saml).then(|| format!("{UPSTREAM}/jwks")),
            scopes: if saml {
                vec![]
            } else {
                vec!["openid".to_string(), "email".to_string()]
            },
            client_id: if saml {
                String::new()
            } else {
                UPSTREAM_CLIENT.to_string()
            },
            // A SAML connector keeps the IdP certificate here.
            client_secret: FederationSecret::new(if saml {
                cert_pem(upstream_key().cert_der())
            } else {
                "inv-upstream-secret".to_string()
            }),
            claim_mappings,
            leeway_seconds: IdpConfig::default_leeway_seconds(),
            want_assertions_signed: false,
            trust_asserted_email,
            apple: None,
            created_at: Timestamp::from_micros(0),
            updated_at: Timestamp::from_micros(0),
        })
        .expect("register identity provider");
    id
}

fn cert_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is UTF-8"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Seeds the state of a login at `idp` and makes the upstream answer the
/// code exchange with an ID token for [`EXTERNAL_SUB`] and the user's email.
/// Returns a browser that holds the state's binding cookie.
fn upstream_login(fx: &Fx, idp: &IdpId) -> Browser {
    fx.h.identity()
        .put_federation_state(&StateBag {
            state_token: FED_STATE.to_string(),
            realm_id: fx.realm.clone(),
            idp_id: idp.clone(),
            nonce: FED_NONCE.to_string(),
            pkce_verifier: "inv-fed-verifier".to_string(),
            return_to: "/ui/account".to_string(),
            expires_at: Timestamp::from_micros(i64::MAX),
            apple_user_json: None,
        })
        .expect("seed federation state");
    let key = upstream_key();
    let jwk = key.to_jwk().expect("JWK");
    let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": "inv-kid" });
    let now = i64::try_from(now_secs()).expect("time fits i64");
    let claims = serde_json::json!({
        "iss": UPSTREAM,
        "sub": EXTERNAL_SUB,
        "aud": UPSTREAM_CLIENT,
        "exp": now + 600,
        "iat": now,
        "nonce": FED_NONCE,
        "email": fx.user.email(),
        "email_verified": true,
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = key.sign(input.as_bytes()).expect("sign ID token");
    let id_token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
    fx.upstream.stub(
        "POST",
        format!("{UPSTREAM}/token"),
        200,
        serde_json::json!({ "id_token": id_token }).to_string(),
    );
    fx.upstream.stub(
        "GET",
        format!("{UPSTREAM}/jwks"),
        200,
        serde_json::json!({ "keys": [{
            "kty": "RSA", "alg": "RS256", "kid": "inv-kid",
            "n": jwk.n.expect("n"), "e": jwk.e.expect("e"),
        }]})
        .to_string(),
    );
    let mut b = fx.browser(None);
    let bind = compute_federation_state_mac(&COOKIE_SECRET, FED_STATE);
    b.accept_set_cookie(&format!("hearth_fed_bind={bind}; Path=/"), "/");
    b
}

/// The callback of a login by a user whose external identity is linked.
async fn social_callback(fx: &Fx, path: &str, post: bool, v: Option<Violation>) -> bool {
    let idp = register_upstream(fx, IdpKind::Oidc, false);
    fx.h.identity()
        .link_external_identity(&fx.realm, fx.uid(), &idp, EXTERNAL_SUB)
        .expect("link external identity");
    let mut b = upstream_login(fx, &idp);
    fx.violate(v, None, fx.uid());
    if post {
        let fields = [
            ("state".to_string(), FED_STATE.to_string()),
            ("code".to_string(), "inv-code".to_string()),
        ];
        b.post_form(path, &fields).await;
    } else {
        b.get(&format!("{path}?state={FED_STATE}&code=inv-code"))
            .await;
    }
    b.has_cookie("hearth_ui_session")
}

/// The first login with an upstream identity that names the email of a
/// local account: the user confirms the link with the local password.
async fn social_confirm_link(fx: &Fx, path: &str, v: Option<Violation>) -> bool {
    let idp = register_upstream(fx, IdpKind::Oidc, false);
    let mut b = upstream_login(fx, &idp);
    let resp = b
        .get(&format!(
            "/ui/realms/{}/federation/callback?state={FED_STATE}&code=inv-code",
            fx.realm_name
        ))
        .await;
    let target = location(&resp).expect("the callback redirects");
    assert!(
        target.ends_with("/federation/confirm-link"),
        "the callback asks to confirm the link"
    );
    let html = open(&mut b, path).await;
    let mut fields = hidden_fields(&html, path);
    fields.push(("password".to_string(), PASSWORD.to_string()));
    fx.violate(v, None, fx.uid());
    b.post_form(path, &fields).await;
    b.has_cookie("hearth_ui_session")
}

/// A signed SAML response for the user's email (the NameID), linked to the
/// user, posted to the realm's assertion consumer.
async fn saml_acs(fx: &Fx, v: Option<Violation>) -> bool {
    use hearth::identity::federation::saml::{
        build_response_xml, sign_element, ResponseBuilder, SamlNameIdFormat, SamlStateBag,
    };
    let idp = register_upstream(fx, IdpKind::Saml, true);
    let email = fx.user.email().to_string();
    fx.h.identity()
        .link_external_identity(&fx.realm, fx.uid(), &idp, &email)
        .expect("link external identity");
    let request_id = "_inv_req";
    fx.h.identity()
        .put_saml_state(&SamlStateBag {
            token: "inv-relay".to_string(),
            request_id: request_id.to_string(),
            realm_id: fx.realm.clone(),
            idp_id: idp.clone(),
            return_to: Some("/ui/account".to_string()),
            created_at: Timestamp::now(),
        })
        .expect("seed SAML state");
    // With no Host header the SP origin is the loopback default.
    let sp = format!("http://localhost:8420/ui/realms/{}", fx.realm_name);
    let acs = format!("{sp}/federation/saml/acs");
    let now = Timestamp::now();
    let attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let xml = build_response_xml(&ResponseBuilder {
        response_id: "_inv_resp",
        in_response_to: Some(request_id),
        issue_instant: now,
        destination: &acs,
        issuer: UPSTREAM,
        audience: &sp,
        assertion_id: "_inv_assert",
        subject_name_id: &email,
        subject_name_id_format: SamlNameIdFormat::EmailAddress.as_uri(),
        session_index: "inv-session",
        not_before: Timestamp::from_micros(now.as_micros() - 60_000_000),
        not_on_or_after: Timestamp::from_micros(now.as_micros() + 600_000_000),
        attributes: &attributes,
    });
    let signed = sign_element(xml.as_bytes(), "_inv_resp", upstream_key()).expect("sign");
    let fields = [
        (
            "SAMLResponse".to_string(),
            base64::engine::general_purpose::STANDARD.encode(signed),
        ),
        ("RelayState".to_string(), "inv-relay".to_string()),
    ];
    let mut b = fx.browser(None);
    fx.violate(v, None, fx.uid());
    b.post_form(
        &format!("/ui/realms/{}/federation/saml/acs", fx.realm_name),
        &fields,
    )
    .await;
    b.has_cookie("hearth_ui_session")
}

// ── agent tokens ────────────────────────────────────────────────────────────

/// An admin of the fixture realm with `hearth.agents.admin`, and its access
/// token. The admin is not the fixture user: the user owns the agents.
fn agents_admin(fx: &Fx) -> String {
    let rbac = fx.h.rbac();
    rbac.seed_realm(&fx.realm).expect("seed the realm roles");
    let admin = super::fixture::create_user(
        &fx.h,
        &fx.realm,
        &format!("agents-admin-{}@inv.test", uuid::Uuid::new_v4().simple()),
    );
    let role = rbac
        .get_role_by_name(&fx.realm, "hearth.agents.admin")
        .expect("role lookup")
        .expect("the realm has hearth.agents.admin");
    rbac.assign_role(
        &fx.realm,
        &AssignRoleRequest {
            subject: Subject::User(admin.id().clone()),
            role_id: role.id,
            scope: Scope::Realm,
            assigned_by: None,
        },
    )
    .expect("grant hearth.agents.admin");
    let id = fx.h.identity();
    let session = id
        .create_session(&fx.realm, admin.id(), &SessionContext::default())
        .expect("admin session");
    id.issue_tokens(&fx.realm, admin.id(), session.id())
        .expect("admin token")
        .access_token()
        .to_string()
}

/// An agent owned by the fixture user.
fn agent(fx: &Fx) -> AgentId {
    fx.h.identity()
        .create_agent(
            &fx.realm,
            &CreateAgentRequest {
                display_name: "inv-agent".to_string(),
                description: None,
                owner: AgentOwner::User(fx.uid().clone()),
                capabilities: vec![],
                max_delegation_depth: 3,
                endpoint_url: None,
            },
            None,
        )
        .expect("create agent")
        .id()
        .clone()
}

fn aat_body(agent: &AgentId) -> serde_json::Value {
    serde_json::json!({
        "agent_id": agent.as_uuid().to_string(),
        "tools": [{ "tool": "search", "actions": ["read"], "constraints": null }],
        "scope": ["read"],
    })
}

async fn aat_issue(fx: &Fx, v: Option<Violation>) -> bool {
    let admin = agents_admin(fx);
    let agent = agent(fx);
    fx.violate(v, None, fx.uid());
    let (status, body) = fx
        .rest_json("/v1/aats", Some(&admin), &aat_body(&agent))
        .await;
    status == 201 && body["aat"].is_string()
}

async fn aat_derive(fx: &Fx, v: Option<Violation>) -> bool {
    let admin = agents_admin(fx);
    let agent = agent(fx);
    let (status, parent) = fx
        .rest_json("/v1/aats", Some(&admin), &aat_body(&agent))
        .await;
    assert_eq!(status, 201, "the parent AAT");
    let body = serde_json::json!({
        "parent_aat": parent["aat"].as_str().expect("parent AAT"),
        "tools": [{ "tool": "search", "actions": ["read"], "constraints": null }],
        "scope": ["read"],
    });
    fx.violate(v, None, fx.uid());
    let (status, body) = fx.rest_json("/v1/aats/derive", Some(&admin), &body).await;
    status == 200 && body["aat"].is_string()
}

async fn transaction_token(fx: &Fx, v: Option<Violation>) -> bool {
    let admin = agents_admin(fx);
    let (requesting, target) = (agent(fx), agent(fx));
    let body = serde_json::json!({
        "requesting_agent_id": requesting.as_uuid().to_string(),
        "target_agent_id": target.as_uuid().to_string(),
        "txn_id": format!("inv-{}", uuid::Uuid::new_v4().simple()),
    });
    fx.violate(v, None, fx.uid());
    let (status, body) = fx
        .rest_json("/v1/transaction-tokens", Some(&admin), &body)
        .await;
    status == 201 && body["token"].is_string()
}

async fn agent_api_key(fx: &Fx, v: Option<Violation>) -> bool {
    let admin = agents_admin(fx);
    let agent = agent(fx);
    let uri = format!("/v1/agents/{}/credentials/keys", agent.as_uuid());
    fx.violate(v, None, fx.uid());
    let (status, _) = fx
        .rest_json(&uri, Some(&admin), &serde_json::json!({ "label": "inv" }))
        .await;
    (200..300).contains(&status)
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
