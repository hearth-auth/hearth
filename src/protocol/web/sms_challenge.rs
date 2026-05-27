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
use crate::identity::{CodeChallengeMethod, IdentityError};

use super::auth::{CookieSecret, UiSession};
use super::handlers::append_cookie;
use super::handlers_common;
use super::oauth_consent::{
    append_query, issue_code_and_redirect, redirect_with_oauth_error, AuthorizeQuery,
};
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
}

/// Issues an HMAC-signed SMS MFA pending cookie value.
///
/// Cookie value: `{b64_payload}.{b64_mac}` where the MAC covers
/// `{user_id_bytes}|{b64_payload}`.
fn issue_sms_mfa_cookie(
    secret: &CookieSecret,
    user_id: &UserId,
    s: &SmsMfaState,
) -> Option<String> {
    let json = serde_json::to_string(s).ok()?;
    let b64 = BASE64URL_NOPAD.encode(json.as_bytes());
    let mac = compute_sms_mac(secret, user_id, &b64);
    let value = format!("{b64}.{mac}");
    Some(format!(
        "{SMS_MFA_COOKIE}={value}; HttpOnly; Path=/ui; SameSite=Lax; Max-Age={SMS_MFA_TTL_SECS}"
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
fn clear_sms_mfa_cookie() -> String {
    format!("{SMS_MFA_COOKIE}=; HttpOnly; Path=/ui; SameSite=Lax; Max-Age=0")
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
/// 3. The SMS sender and HMAC key are configured on `WebState`.
#[allow(clippy::too_many_lines)]
pub fn sms_mfa_challenge_check(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    q: &AuthorizeQuery,
    _headers: &axum::http::HeaderMap,
    _now: Timestamp,
) -> Option<Response> {
    // 1. Is SMS MFA required for this realm?
    let realm_obj = state.identity.get_realm(realm).ok().flatten()?;
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
    let user = state.identity.get_user(realm, user_id).ok().flatten()?;
    if !user.phone_verified() {
        // No phone enrolled — RA interceptor should have handled enrollment.
        // Allow the flow to continue; phone is not a hard requirement here.
        return None;
    }
    let phone = user.phone_number()?;
    let masked_phone = user
        .masked_phone_number()
        .unwrap_or_else(|| "****".to_string());

    // 3. SMS sender and HMAC key must be configured.
    let sms_sender = match state.sms.as_ref() {
        Some(s) => s,
        None => {
            tracing::warn!(
                realm_id = %realm.as_uuid(),
                "sms_mfa_challenge_check: realm requires SMS MFA but no SMS transport is configured"
            );
            return None;
        }
    };
    let hmac_key: Vec<u8> = state
        .sms_otp_hmac_key
        .clone()
        .unwrap_or_else(|| b"hearth-dev-sms-otp-key-not-for-production".to_vec());

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
                let state_cookie = SmsMfaState {
                    realm_id: realm.as_uuid().to_string(),
                    user_id: user_id.as_uuid().to_string(),
                    otp_nonce: String::new(), // no valid nonce
                    masked_phone,
                    client_id: q.client_id.clone(),
                    redirect_uri: q.redirect_uri.clone(),
                    scope: q.scope.clone(),
                    oauth_state: q.state.clone(),
                    code_challenge: q.code_challenge.clone(),
                    code_challenge_method: q.code_challenge_method.clone(),
                    nonce: q.nonce.clone(),
                    response_type: q.response_type.clone(),
                };
                if let Some(cookie) =
                    issue_sms_mfa_cookie(&state.cookie_secret, user_id, &state_cookie)
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

    let state_cookie = SmsMfaState {
        realm_id: realm.as_uuid().to_string(),
        user_id: user_id.as_uuid().to_string(),
        otp_nonce,
        masked_phone,
        client_id: q.client_id.clone(),
        redirect_uri: q.redirect_uri.clone(),
        scope: q.scope.clone(),
        oauth_state: q.state.clone(),
        code_challenge: q.code_challenge.clone(),
        code_challenge_method: q.code_challenge_method.clone(),
        nonce: q.nonce.clone(),
        response_type: q.response_type.clone(),
    };

    let Some(cookie) = issue_sms_mfa_cookie(&state.cookie_secret, user_id, &state_cookie) else {
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

    let client_uuid = match uuid::Uuid::parse_str(&sms_state.client_id) {
        Ok(u) => u,
        Err(_) => return handlers_common::server_error(),
    };
    let client_id = ClientId::new(client_uuid);

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
        });
    }

    let hmac_key: Vec<u8> = state
        .sms_otp_hmac_key
        .clone()
        .unwrap_or_else(|| b"hearth-dev-sms-otp-key-not-for-production".to_vec());

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    match state
        .identity
        .verify_sms_otp(&realm, &sms_state.otp_nonce, &code, &hmac_key, now_ts)
    {
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
            let clear = clear_sms_mfa_cookie();

            // Reconstruct PKCE and nonce params.
            let code_challenge = if sms_state.code_challenge.is_empty() {
                None
            } else {
                Some(sms_state.code_challenge.clone())
            };
            let code_challenge_method = match sms_state.code_challenge_method.as_str() {
                "S256" => Some(CodeChallengeMethod::S256),
                _ => None,
            };
            let nonce = if sms_state.nonce.is_empty() {
                None
            } else {
                Some(sms_state.nonce.clone())
            };

            let mut response = issue_code_and_redirect(
                &state,
                &realm,
                &user_id,
                &client_id,
                &sms_state.redirect_uri,
                &sms_state.scope,
                &sms_state.oauth_state,
                code_challenge,
                code_challenge_method,
                nonce,
                vec!["sms".to_string()],
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
        };

        let cookie_header = issue_sms_mfa_cookie(&secret, &user_id, &s)
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
        };

        let cookie_header = issue_sms_mfa_cookie(&secret, &user_a, &s)
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
