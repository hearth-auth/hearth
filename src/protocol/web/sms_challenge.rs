//! SMS MFA challenge interstitial for the OIDC authorization code flow.
//!
//! When a realm has `mfa_methods: ["sms"]` and the authenticating user has a
//! verified phone number, this interceptor fires between the
//! required-action check and the consent check in `authorize_get_impl`.
//!
//! | Route | Method | Purpose |
//! |-------|--------|---------|
//! | `/ui/sms-challenge` | GET  | Render the OTP entry form |
//! | `/ui/sms-challenge` | POST | Verify OTP → issue auth code with `amr=["sms"]` |
//!
//! The same challenge also guards device approval (`POST /ui/device`,
//! RFC 8628): there the verified OTP approves the pending user code instead
//! of issuing an authorization code.
//!
//! # State management
//!
//! Challenge state (OIDC params + OTP nonce + masked phone) is stored in
//! an HMAC-signed cookie:
//!   `{base64url(json)}.{base64url(hmac-sha256(user_id_bytes|base64url(json)))}`
//!
//! The cookie is scoped to `SameSite=Lax; Path=/ui` and expires in
//! [`SMS_MFA_TTL_SECS`] seconds. Because the OTP nonce is the server-side
//! record, there is no extra storage entry — the cookie is the entire pending
//! state.
//!
//! # Security notes
//!
//! * Cookie payload is HMAC-signed with [`CookieSecret`] and bound to
//!   `user_id`, making cross-user replay detectable.
//! * OTP verification is delegated to the identity engine which enforces
//!   expiry, max-attempts, and replay prevention.
//! * On verification failure the form is re-rendered; the `otp_nonce` stays
//!   valid until it is consumed or expires.

use std::sync::Arc;

use askama::Template;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{ClientId, RealmId, Timestamp, UserId};
use crate::identity::IdentityError;

use super::auth::{CookieSecret, UiSession};
use super::authorize_gate::{
    method_wire, parse_method, parse_response_mode, run_authorize_gates, AuthorizeParams, Gate,
};
use super::handlers::append_cookie;
use super::handlers_common;
use super::oauth_consent::{append_query, redirect_with_oauth_error, AuthorizeQuery};
use super::templates::render;
use super::WebState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Cookie name for the SMS MFA pending state.
pub const SMS_MFA_COOKIE: &str = "hearth_ui_sms_mfa";

/// TTL for the SMS MFA challenge cookie in seconds (10 minutes).
pub const SMS_MFA_TTL_SECS: i64 = 600;

// ---------------------------------------------------------------------------
// Cookie state
// ---------------------------------------------------------------------------

/// All state needed to resume the OAuth flow after a successful SMS OTP
/// verification. Serialized as JSON and stored in the HMAC-signed cookie.
#[derive(Debug, Serialize, Deserialize)]
struct SmsMfaState {
    /// Realm UUID string.
    realm_id: String,
    /// User UUID string.
    user_id: String,
    /// Nonce returned by `issue_sms_otp` — used to verify the OTP.
    otp_nonce: String,
    /// Masked phone number displayed in the UI (e.g. `+1***-***-1234`).
    masked_phone: String,
    // -- OIDC flow params (reconstructed after OTP success) --
    client_id: String,
    redirect_uri: String,
    scope: String,
    /// OAuth 2.0 `state` parameter for CSRF protection.
    oauth_state: String,
    code_challenge: String,
    code_challenge_method: String,
    /// OIDC nonce echoed into the ID token.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    nonce: String,
    response_type: String,
    /// Whether the originating request went through PAR (RFC 9126).
    ///
    /// Restored in `sms_challenge_post` so `issue_code_and_redirect` can
    /// pass `via_par = true` to the engine — FAPI Baseline/Advanced realms
    /// reject code issuance when this flag is `false`.
    #[serde(default)]
    via_par: bool,
    /// RFC 8707 resource indicator from a verified JAR or PAR entry, bound
    /// into the code issued once the OTP verifies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    /// Requested response mode wire string (`fragment`, `query.jwt`, …).
    /// Dropping it redirected a `fragment` / JARM request as plain `query`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_mode: Option<String>,
    /// OIDC `prompt` of the original request, applied by the consent gate
    /// that runs after the OTP verifies.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    prompt: String,
    /// Set when the challenge guards a device approval (`/ui/device`) rather
    /// than an authorization code: the RFC 8628 user code to approve once
    /// the OTP verifies. The OIDC fields are then empty and unused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_user_code: Option<String>,
}

/// What a verified SMS OTP unlocks.
#[derive(Clone, Copy)]
enum SmsResume<'a> {
    /// Resume this (already validated) authorization request.
    Authorize { params: &'a AuthorizeParams },
    /// Approve this device authorization user code (RFC 8628).
    Device { user_code: &'a str },
}

impl SmsMfaState {
    /// The pending state for `resume`, keyed to the issued OTP `otp_nonce`.
    fn pending(
        realm: &RealmId,
        user_id: &UserId,
        otp_nonce: String,
        masked_phone: String,
        resume: SmsResume<'_>,
    ) -> Self {
        let mut s = Self {
            realm_id: realm.as_uuid().to_string(),
            user_id: user_id.as_uuid().to_string(),
            otp_nonce,
            masked_phone,
            client_id: String::new(),
            redirect_uri: String::new(),
            scope: String::new(),
            oauth_state: String::new(),
            code_challenge: String::new(),
            code_challenge_method: String::new(),
            nonce: String::new(),
            response_type: String::new(),
            via_par: false,
            resource: None,
            response_mode: None,
            prompt: String::new(),
            device_user_code: None,
        };
        match resume {
            SmsResume::Authorize { params } => {
                s.client_id = params.client_id.as_uuid().to_string();
                s.redirect_uri.clone_from(&params.redirect_uri);
                s.scope.clone_from(&params.scope);
                s.oauth_state.clone_from(&params.state);
                s.code_challenge = params.code_challenge.clone().unwrap_or_default();
                s.code_challenge_method = method_wire(params.code_challenge_method.as_ref());
                s.nonce = params.nonce.clone().unwrap_or_default();
                s.response_type = "code".to_string();
                s.via_par = params.via_par;
                s.resource.clone_from(&params.resource);
                s.response_mode = params
                    .response_mode
                    .as_ref()
                    .map(|m| m.as_str().to_string());
                s.prompt.clone_from(&params.prompt);
            }
            SmsResume::Device { user_code } => {
                s.device_user_code = Some(user_code.to_string());
            }
        }
        s
    }

    /// The authorization request to resume, restored from this state.
    ///
    /// `None` when a value does not parse: the cookie is MAC'd and was built
    /// from validated parameters, so that is refused rather than defaulted.
    fn authorize_params(&self) -> Option<AuthorizeParams> {
        Some(AuthorizeParams {
            client_id: ClientId::new(uuid::Uuid::parse_str(&self.client_id).ok()?),
            redirect_uri: self.redirect_uri.clone(),
            scope: self.scope.clone(),
            state: self.oauth_state.clone(),
            code_challenge: Some(self.code_challenge.clone()).filter(|c| !c.is_empty()),
            code_challenge_method: parse_method(&self.code_challenge_method)?,
            nonce: Some(self.nonce.clone()).filter(|n| !n.is_empty()),
            prompt: self.prompt.clone(),
            response_mode: parse_response_mode(self.response_mode.as_deref())?,
            resource: self.resource.clone(),
            via_par: self.via_par,
        })
    }
}

/// Issues an HMAC-signed SMS MFA pending cookie value.
///
/// Cookie value: `{b64_payload}.{b64_mac}` where the MAC covers
/// `{user_id_bytes}|{b64_payload}`.
///
/// `secure` adds the `Secure` attribute — pass
/// [`crate::protocol::web::WebState::is_secure_request`], the same predicate
/// the session and CSRF cookies use. It was missing entirely before task 21.6
/// (audit §4.23#5), so the MAC-signed pending-MFA state of a
/// half-authenticated user was sent over plaintext on a downgrade.
fn issue_sms_mfa_cookie(
    secret: &CookieSecret,
    user_id: &UserId,
    s: &SmsMfaState,
    secure: bool,
) -> Option<String> {
    let json = serde_json::to_string(s).ok()?;
    let b64 = BASE64URL_NOPAD.encode(json.as_bytes());
    let mac = compute_sms_mac(secret, user_id, &b64);
    let value = format!("{b64}.{mac}");
    let secure_attr = if secure { "; Secure" } else { "" };
    Some(format!(
        "{SMS_MFA_COOKIE}={value}; HttpOnly; Path=/ui; SameSite=Lax; Max-Age={SMS_MFA_TTL_SECS}{secure_attr}"
    ))
}

/// Reads and validates the SMS MFA cookie. Returns the decoded [`SmsMfaState`]
/// on success; `None` on missing, malformed, or MAC-invalid cookie.
fn read_sms_mfa_cookie(
    secret: &CookieSecret,
    user_id: &UserId,
    headers: &axum::http::HeaderMap,
) -> Option<SmsMfaState> {
    let raw = super::auth::cookie_value_from_headers(headers, SMS_MFA_COOKIE)?;
    let (b64, mac_str) = raw.rsplit_once('.')?;
    let expected = compute_sms_mac(secret, user_id, b64);
    let ok: bool = expected.as_bytes().ct_eq(mac_str.as_bytes()).into();
    if !ok {
        return None;
    }
    let json_bytes = BASE64URL_NOPAD.decode(b64.as_bytes()).ok()?;
    serde_json::from_slice(&json_bytes).ok()
}

fn compute_sms_mac(secret: &CookieSecret, user_id: &UserId, payload: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(super::auth::cookie_secret_bytes(secret))
        .expect("HMAC-SHA256 accepts any 32-byte key");
    mac.update(user_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(payload.as_bytes());
    BASE64URL_NOPAD.encode(&mac.finalize().into_bytes())
}

/// Builds the `Set-Cookie` header that clears the SMS MFA cookie.
///
/// `secure` must match what [`issue_sms_mfa_cookie`] used, or the browser keeps
/// a second copy of the cookie under the other security scope.
fn clear_sms_mfa_cookie(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{SMS_MFA_COOKIE}=; HttpOnly; Path=/ui; SameSite=Lax; Max-Age=0{secure_attr}")
}

// ---------------------------------------------------------------------------
// SMS MFA challenge intercept (called from authorize_get_impl)
// ---------------------------------------------------------------------------

/// Checks whether an SMS MFA challenge is required for this authorization
/// attempt and, if so, issues the OTP and returns a redirect `Response`.
///
/// Returns `Some(response)` when the flow should be intercepted (caller must
/// return the response immediately). Returns `None` when the flow should
/// continue normally.
///
/// Intercept conditions (all must hold):
/// 1. Realm has `mfa_methods` containing `"sms"`.
/// 2. User has a verified phone number.
///
/// When both hold but the factor cannot be challenged — no SMS sender or no
/// OTP HMAC key on `WebState`, or a realm/user lookup fails — the returned
/// response is an error: the authorization is refused, never waved through.
pub fn sms_mfa_challenge_check(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    q: &AuthorizeQuery,
    headers: &axum::http::HeaderMap,
    _now: Timestamp,
    via_par: bool,
) -> Option<Response> {
    // Task 21.6: the pending-MFA cookie must carry `Secure` on a TLS request,
    // like every other `/ui` cookie. `headers` was previously unused.
    let secure = state.is_secure_request(headers);
    let Ok(client_uuid) = uuid::Uuid::parse_str(&q.client_id) else {
        return Some(handlers_common::bad_request("invalid client_id"));
    };
    let (Some(code_challenge_method), Some(response_mode)) = (
        parse_method(&q.code_challenge_method),
        parse_response_mode(q.response_mode.as_deref()),
    ) else {
        return Some(handlers_common::bad_request(
            "invalid authorization request",
        ));
    };
    let params = AuthorizeParams {
        client_id: ClientId::new(client_uuid),
        redirect_uri: q.redirect_uri.clone(),
        scope: q.scope.clone(),
        state: q.state.clone(),
        code_challenge: Some(q.code_challenge.clone()).filter(|c| !c.is_empty()),
        code_challenge_method,
        nonce: Some(q.nonce.clone()).filter(|n| !n.is_empty()),
        prompt: q.prompt.clone(),
        response_mode,
        resource: q.resource.clone(),
        via_par,
    };
    sms_mfa_challenge_gate(state, realm, user_id, &params, secure)
}

/// The SMS MFA gate of the authorization flow (see `authorize_gate`), for a
/// request the caller has already validated. Same conditions and refusals as
/// [`sms_mfa_challenge_check`]; on success `POST /ui/sms-challenge` resumes
/// the flow at the consent gate.
pub(super) fn sms_mfa_challenge_gate(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    params: &AuthorizeParams,
    secure: bool,
) -> Option<Response> {
    sms_gate(
        state,
        realm,
        user_id,
        secure,
        SmsResume::Authorize { params },
    )
}

/// The SMS MFA gate for a device approval (`POST /ui/device`).
///
/// Approving a device code hands the device client tokens for the session
/// user, so it needs the same second factor as issuing an authorization
/// code: without this a session created without the SMS factor (passkey,
/// magic link, federation) could approve a device on a realm that requires
/// it. Same conditions and same fail-closed refusals as
/// [`sms_mfa_challenge_check`]; on success `POST /ui/sms-challenge`
/// approves `user_code` instead of issuing a code.
pub(super) fn sms_mfa_device_gate(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    user_code: &str,
    secure: bool,
) -> Option<Response> {
    sms_gate(
        state,
        realm,
        user_id,
        secure,
        SmsResume::Device { user_code },
    )
}

#[allow(clippy::too_many_lines)]
fn sms_gate(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    secure: bool,
    resume: SmsResume<'_>,
) -> Option<Response> {
    // 1. Is SMS MFA required for this realm?
    // A lookup failure must not read as "SMS not required": that would skip
    // the factor on a storage error. Refuse instead.
    let realm_obj = match state.identity.get_realm(realm) {
        Ok(Some(r)) => r,
        Ok(None) | Err(_) => {
            tracing::warn!(
                realm_id = %realm.as_uuid(),
                "sms_mfa_challenge_check: realm lookup failed; refusing the authorization"
            );
            return Some(handlers_common::server_error());
        }
    };
    let sms_required = realm_obj
        .config()
        .mfa_methods
        .as_ref()
        .map(|m| m.iter().any(|s| s == "sms"))
        .unwrap_or(false);
    if !sms_required {
        return None;
    }

    // 2. Does this user have a verified phone?
    let user = match state.identity.get_user(realm, user_id) {
        Ok(Some(u)) => u,
        Ok(None) | Err(_) => {
            tracing::warn!(
                realm_id = %realm.as_uuid(),
                "sms_mfa_challenge_check: user lookup failed; refusing the authorization"
            );
            return Some(handlers_common::server_error());
        }
    };
    if !user.phone_verified() {
        // No phone enrolled — RA interceptor should have handled enrollment.
        // Allow the flow to continue; phone is not a hard requirement here.
        return None;
    }
    // Verified but no number is an inconsistent record; there is nowhere to
    // send the code, so the factor cannot be proved.
    let Some(phone) = user.phone_number() else {
        return Some(handlers_common::server_error());
    };
    let masked_phone = user
        .masked_phone_number()
        .unwrap_or_else(|| "****".to_string());

    // 3. SMS sender and HMAC key must be configured. Either missing means the
    //    factor cannot be challenged, so the authorization is refused. These
    //    branches used to `return None` — "no challenge needed" — so the code
    //    was issued without the realm's SMS factor (or, with no key, the OTP
    //    was HMAC'd under an all-zero key).
    let Some(sms_sender) = state.sms.as_ref() else {
        tracing::warn!(
            realm_id = %realm.as_uuid(),
            "sms_mfa_challenge_check: realm requires SMS MFA but no SMS transport is \
             configured; refusing the authorization"
        );
        return Some(handlers_common::server_error());
    };
    let Some(hmac_key) = super::required_action::sms_otp_hmac_key_bytes(state) else {
        tracing::warn!(
            realm_id = %realm.as_uuid(),
            "sms_mfa_challenge_check: no SMS OTP HMAC key is loaded; refusing the authorization"
        );
        return Some(handlers_common::server_error());
    };

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let otp_nonce =
        match state
            .identity
            .issue_sms_otp(realm, phone, &hmac_key, sms_sender.as_ref(), now_ts)
        {
            Ok(n) => n,
            Err(IdentityError::SmsResendLimitExceeded) => {
                // A code was sent recently — redirect to challenge page anyway;
                // the user can enter the previous code or wait.
                tracing::debug!(
                    user_id = %user_id.as_uuid(),
                    "sms_mfa_challenge_check: resend throttled, using existing OTP"
                );
                // We can't get the existing nonce back from the engine, so we
                // need to redirect to the challenge page with an error redirect.
                // Return a redirect to the challenge page; the user must wait or
                // reload the authorize flow to get a fresh code.
                // No valid nonce: the POST re-renders "wait and retry".
                let state_cookie =
                    SmsMfaState::pending(realm, user_id, String::new(), masked_phone, resume);
                if let Some(cookie) =
                    issue_sms_mfa_cookie(&state.cookie_secret, user_id, &state_cookie, secure)
                {
                    let mut resp = Redirect::to("/ui/sms-challenge").into_response();
                    append_cookie(&mut resp, &cookie);
                    return Some(resp);
                }
                return Some(handlers_common::server_error());
            }
            Err(e) => {
                tracing::warn!(error = %e, "sms_mfa_challenge_check: issue_sms_otp failed");
                return Some(handlers_common::server_error());
            }
        };

    let state_cookie = SmsMfaState::pending(realm, user_id, otp_nonce, masked_phone, resume);

    let Some(cookie) = issue_sms_mfa_cookie(&state.cookie_secret, user_id, &state_cookie, secure)
    else {
        return Some(handlers_common::server_error());
    };

    let mut resp = Redirect::to("/ui/sms-challenge").into_response();
    append_cookie(&mut resp, &cookie);
    Some(resp)
}

// ---------------------------------------------------------------------------
// Template
// ---------------------------------------------------------------------------

/// Template rendered by `GET /ui/sms-challenge`.
#[derive(Template)]
#[template(path = "ui/sms_challenge.html")]
struct SmsChallengeTemplate {
    /// Masked phone number shown on the challenge page.
    masked_phone: String,
    /// Error message to display, if any.
    error: Option<String>,
    /// CSRF double-submit token.
    csrf: Option<String>,
    // Layout chrome.
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    narrow: bool,
    flash: Option<super::templates::Flash>,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

// ---------------------------------------------------------------------------
// GET /ui/sms-challenge
// ---------------------------------------------------------------------------

/// Renders the SMS OTP challenge form.
pub async fn sms_challenge_get(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(sms_state) = read_sms_mfa_cookie(&state.cookie_secret, &session.user_id, &headers)
    else {
        return handlers_common::bad_request("No SMS MFA challenge in progress");
    };

    // Basic sanity: cookie user must match session user.
    if sms_state.user_id != session.user_id.as_uuid().to_string() {
        return handlers_common::bad_request("SMS MFA challenge mismatch");
    }

    let admin = super::handlers::is_admin(state.as_ref(), &session);
    render(&SmsChallengeTemplate {
        masked_phone: sms_state.masked_phone,
        error: None,
        csrf: session.csrf.clone(),
        chrome: true,
        active: "account",
        user_email: Some(session.user_email.clone()),
        is_admin: admin,
        narrow: true,
        flash: None,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    })
}

// ---------------------------------------------------------------------------
// POST /ui/sms-challenge
// ---------------------------------------------------------------------------

/// Handles OTP submission: verifies the code and, on success, issues the
/// authorization code with `amr=["sms"]` and redirects to `redirect_uri`.
#[allow(clippy::too_many_lines)]
pub async fn sms_challenge_post(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    // Parse form body.
    let (mut code, mut csrf) = (String::new(), String::new());
    for (k, v) in form_urlencoded::parse(&body) {
        match k.as_ref() {
            "code" => code = v.into_owned(),
            "_csrf" => csrf = v.into_owned(),
            _ => {}
        }
    }

    // CSRF check.
    if let Err(resp) = super::auth::verify_csrf_form_field(&session, &csrf) {
        return resp;
    }

    // Read and validate cookie.
    let Some(sms_state) = read_sms_mfa_cookie(&state.cookie_secret, &session.user_id, &headers)
    else {
        return handlers_common::bad_request("No SMS MFA challenge in progress");
    };

    if sms_state.user_id != session.user_id.as_uuid().to_string() {
        return handlers_common::bad_request("SMS MFA challenge mismatch");
    }

    // Parse realm/user IDs from cookie state.
    let realm_uuid = match uuid::Uuid::parse_str(&sms_state.realm_id) {
        Ok(u) => u,
        Err(_) => return handlers_common::server_error(),
    };
    let realm = RealmId::new(realm_uuid);

    let user_uuid = match uuid::Uuid::parse_str(&sms_state.user_id) {
        Ok(u) => u,
        Err(_) => return handlers_common::server_error(),
    };
    let user_id = UserId::new(user_uuid);

    // Handle the "resend throttled" case (empty nonce was stored).
    if sms_state.otp_nonce.is_empty() {
        let admin = super::handlers::is_admin(state.as_ref(), &session);
        return render(&SmsChallengeTemplate {
            masked_phone: sms_state.masked_phone,
            error: Some(
                "A code was recently sent. Please wait a few minutes and try your authorization \
                 request again."
                    .to_string(),
            ),
            csrf: session.csrf.clone(),
            chrome: true,
            active: "account",
            user_email: Some(session.user_email.clone()),
            is_admin: admin,
            narrow: true,
            flash: None,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            realm_theme_url: state.realm_theme_url(),
            inline_theme_css: state.inline_theme_css(),
        });
    }

    // No key: nothing can verify, so refuse rather than HMAC under a
    // guessable key.
    let Some(hmac_key) = super::required_action::sms_otp_hmac_key_bytes(&state) else {
        return handlers_common::server_error();
    };

    // The code must have been sent to THIS user's verified number; the OTP
    // record names no one, so the expected recipient comes from the user.
    let phone = match state.identity.get_user(&realm, &user_id) {
        Ok(Some(u)) if u.phone_verified() => match u.phone_number() {
            Some(p) => p.to_string(),
            None => return handlers_common::server_error(),
        },
        _ => return handlers_common::server_error(),
    };

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    match state.identity.verify_sms_otp(
        &realm,
        &sms_state.otp_nonce,
        &phone,
        &code,
        &hmac_key,
        now_ts,
    ) {
        Ok(()) => {
            // Emit success audit event.
            emit_audit(
                &state,
                &realm,
                &user_id,
                AuditAction::SmsMfaChallengeSucceeded,
                None,
            );

            // Clear the SMS challenge cookie.
            let clear = clear_sms_mfa_cookie(state.is_secure_request(&headers));

            // A device approval: the factor is proved, approve the code.
            if let Some(user_code) = sms_state.device_user_code.as_deref() {
                let mut response =
                    super::handlers::finish_device_approval(&state, &realm, &user_id, user_code);
                append_cookie(&mut response, &clear);
                return response;
            }

            // The factor is proved: resume the authorization at the gate
            // after this one — consent / `prompt`, then issuance with the
            // request's response mode. This used to issue the code directly,
            // skipping the consent prompt and dropping `response_mode`.
            let Some(params) = sms_state.authorize_params() else {
                tracing::warn!("sms_challenge_post: challenge state carries unparseable params");
                return handlers_common::server_error();
            };
            let now = Timestamp::from_micros(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .and_then(|d| i64::try_from(d.as_micros()).ok())
                    .unwrap_or(0),
            );
            let mut response = run_authorize_gates(
                &state,
                &realm,
                &user_id,
                &params,
                Gate::Consent,
                vec!["sms".to_string()],
                state.is_secure_request(&headers),
                now,
            );
            append_cookie(&mut response, &clear);
            response
        }
        Err(_) => {
            // Emit failure audit event.
            emit_audit(
                &state,
                &realm,
                &user_id,
                AuditAction::SmsMfaChallengeFailed,
                Some(serde_json::json!({ "client_id": sms_state.client_id })),
            );

            let admin = super::handlers::is_admin(state.as_ref(), &session);
            render(&SmsChallengeTemplate {
                masked_phone: sms_state.masked_phone,
                error: Some("Incorrect or expired code. Please try again.".to_string()),
                csrf: session.csrf.clone(),
                chrome: true,
                active: "account",
                user_email: Some(session.user_email.clone()),
                is_admin: admin,
                narrow: true,
                flash: None,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                realm_theme_url: state.realm_theme_url(),
                inline_theme_css: state.inline_theme_css(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn emit_audit(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    action: AuditAction,
    metadata: Option<serde_json::Value>,
) {
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: user_id.as_uuid().to_string(),
        action,
        resource_type: "user".to_string(),
        resource_id: user_id.as_uuid().to_string(),
        metadata,
    }) {
        tracing::warn!(error = %e, "sms_challenge: audit append failed");
    }
}

#[allow(dead_code)]
fn optional_query_build(base: &str, params: &[(&str, &str)]) -> String {
    append_query(base, params)
}

#[allow(dead_code)]
fn build_oauth_error_redirect(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state_param: &str,
) -> Response {
    redirect_with_oauth_error(redirect_uri, error, description, state_param)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_secure(cookie: &str) -> bool {
        cookie
            .split(';')
            .any(|a| a.trim().eq_ignore_ascii_case("Secure"))
    }

    fn sample_state() -> SmsMfaState {
        SmsMfaState {
            realm_id: "00000000-0000-0000-0000-000000000001".to_string(),
            user_id: "00000000-0000-0000-0000-000000000003".to_string(),
            otp_nonce: "n".to_string(),
            masked_phone: "+1***-***-1234".to_string(),
            client_id: "00000000-0000-0000-0000-000000000002".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            scope: "openid".to_string(),
            oauth_state: String::new(),
            code_challenge: String::new(),
            code_challenge_method: String::new(),
            nonce: String::new(),
            response_type: "code".to_string(),
            via_par: false,
            resource: None,
            response_mode: None,
            prompt: String::new(),
            device_user_code: None,
        }
    }

    /// Task 21.6 / audit §4.23#5: `hearth_ui_sms_mfa` had no `Secure`
    /// attribute on any code path. `issue_sms_mfa_cookie` and
    /// `clear_sms_mfa_cookie` are the only two places it is ever written, so
    /// these two cases are the whole surface. The value is the MAC-signed
    /// pending-MFA state of a half-authenticated user.
    #[test]
    fn sms_mfa_cookie_carries_secure_over_tls() {
        let secret = CookieSecret::from_bytes([42u8; 32]);
        let user_id = UserId::generate();
        let issued =
            issue_sms_mfa_cookie(&secret, &user_id, &sample_state(), true).expect("cookie issued");
        assert!(
            has_secure(&issued),
            "issued cookie omitted Secure: {issued}"
        );
        let cleared = clear_sms_mfa_cookie(true);
        assert!(
            has_secure(&cleared),
            "cleared cookie omitted Secure: {cleared}"
        );
        assert!(
            cleared.contains("Max-Age=0"),
            "clearing cookie must still expire the value: {cleared}"
        );
    }

    /// A plaintext deployment must NOT get `Secure`, or the browser drops the
    /// cookie and the SMS challenge can never be completed.
    #[test]
    fn sms_mfa_cookie_omits_secure_over_plaintext() {
        let secret = CookieSecret::from_bytes([42u8; 32]);
        let user_id = UserId::generate();
        let issued =
            issue_sms_mfa_cookie(&secret, &user_id, &sample_state(), false).expect("cookie issued");
        assert!(!has_secure(&issued), "issued cookie set Secure: {issued}");
        let cleared = clear_sms_mfa_cookie(false);
        assert!(
            !has_secure(&cleared),
            "cleared cookie set Secure: {cleared}"
        );
    }

    #[test]
    fn sms_mfa_cookie_roundtrip() {
        let secret = CookieSecret::from_bytes([42u8; 32]);
        let user_id = UserId::generate();

        let s = SmsMfaState {
            realm_id: "00000000-0000-0000-0000-000000000001".to_string(),
            user_id: user_id.as_uuid().to_string(),
            otp_nonce: "test-nonce-abc".to_string(),
            masked_phone: "+1***-***-1234".to_string(),
            client_id: "00000000-0000-0000-0000-000000000002".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            scope: "openid profile".to_string(),
            oauth_state: "state123".to_string(),
            code_challenge: "abc123".to_string(),
            code_challenge_method: "S256".to_string(),
            nonce: "nonce456".to_string(),
            response_type: "code".to_string(),
            via_par: false,
            resource: None,
            response_mode: None,
            prompt: String::new(),
            device_user_code: None,
        };

        let cookie_header = issue_sms_mfa_cookie(&secret, &user_id, &s, false)
            .expect("issue_sms_mfa_cookie should succeed");
        // Extract the cookie value from the Set-Cookie header string.
        let value = cookie_header
            .strip_prefix(&format!("{SMS_MFA_COOKIE}="))
            .expect("cookie header should start with cookie name")
            .split(';')
            .next()
            .expect("split should yield at least one segment")
            .to_string();

        // Build a fake header map with the cookie.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(&format!("{SMS_MFA_COOKIE}={value}"))
                .expect("cookie value should be a valid header value"),
        );

        let decoded = read_sms_mfa_cookie(&secret, &user_id, &headers)
            .expect("read_sms_mfa_cookie should succeed");
        assert_eq!(decoded.otp_nonce, "test-nonce-abc");
        assert_eq!(decoded.masked_phone, "+1***-***-1234");
        assert_eq!(decoded.scope, "openid profile");
    }

    #[test]
    fn sms_mfa_cookie_rejects_wrong_user() {
        let secret = CookieSecret::from_bytes([7u8; 32]);
        let user_a = UserId::generate();
        let user_b = UserId::generate();

        let s = SmsMfaState {
            realm_id: "00000000-0000-0000-0000-000000000001".to_string(),
            user_id: user_a.as_uuid().to_string(),
            otp_nonce: "nonce".to_string(),
            masked_phone: "****".to_string(),
            client_id: "00000000-0000-0000-0000-000000000002".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            scope: "openid".to_string(),
            oauth_state: "s".to_string(),
            code_challenge: String::new(),
            code_challenge_method: String::new(),
            nonce: String::new(),
            response_type: "code".to_string(),
            via_par: false,
            resource: None,
            response_mode: None,
            prompt: String::new(),
            device_user_code: None,
        };

        let cookie_header = issue_sms_mfa_cookie(&secret, &user_a, &s, false)
            .expect("issue_sms_mfa_cookie should succeed");
        let value = cookie_header
            .strip_prefix(&format!("{SMS_MFA_COOKIE}="))
            .expect("cookie header should start with cookie name")
            .split(';')
            .next()
            .expect("split should yield at least one segment")
            .to_string();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(&format!("{SMS_MFA_COOKIE}={value}"))
                .expect("cookie value should be a valid header value"),
        );

        // user_a's cookie must not validate under user_b.
        assert!(read_sms_mfa_cookie(&secret, &user_b, &headers).is_none());
    }
}
