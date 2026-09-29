//! Admin console: short-lived system-realm API tokens (GA audit 3 DOC-2).
//!
//! `GET /ui/admin/api-tokens` shows the form; `POST` verifies a fresh
//! two-factor step-up ([`crate::identity::verify_operator_step_up`]) and mints
//! the token through [`IdentityEngine::issue_operator_token`], which writes
//! through the normal storage path — Raft in cluster mode. This is the source
//! of the `$SYSTEM_TOKEN` the realm and cluster runbooks need on a running
//! server.
//!
//! The token appears exactly once, in the body of the `POST` response, which
//! carries `Cache-Control: no-store`. It is never put in a URL, a redirect, a
//! log line or the audit record.

use std::time::Duration;

use axum::http::{header, HeaderMap, HeaderValue};
use base64::Engine as _;

use super::*;
use crate::core::FormSecret;
use crate::identity::{
    verify_operator_step_up, OperatorToken, OperatorTokenIssuer, SecondFactorProof,
    StepUpAssertion, StepUpError, OPERATOR_TOKEN_DEFAULT_TTL, OPERATOR_TOKEN_MAX_TTL,
    OPERATOR_TOKEN_MIN_TTL,
};

const fn minutes(d: Duration) -> u64 {
    d.as_secs() / 60
}

#[derive(Template)]
#[template(path = "ui/admin/api_tokens/new.html")]
struct ApiTokenFormTemplate {
    error: Option<String>,
    ttl_minutes: u64,
    min_minutes: u64,
    max_minutes: u64,
    has_totp: bool,
    has_passkey: bool,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

#[derive(Template)]
#[template(path = "ui/admin/api_tokens/issued.html")]
struct ApiTokenIssuedTemplate<'a> {
    token: &'a str,
    jti: &'a str,
    session_id: String,
    expires_at: String,
    ttl_minutes: u64,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// The fields of the token form.
///
/// Implements neither `Debug` nor `Serialize`: `password` and the assertion
/// are live credentials.
#[derive(Deserialize)]
pub struct ApiTokenForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    ttl_minutes: Option<String>,
    #[serde(default)]
    password: Option<FormSecret>,
    #[serde(default)]
    totp_code: Option<String>,
    #[serde(default)]
    assertion_credential_id: Option<String>,
    #[serde(default)]
    assertion_client_data_json: Option<String>,
    #[serde(default)]
    assertion_authenticator_data: Option<String>,
    #[serde(default)]
    assertion_signature: Option<String>,
    #[serde(default)]
    assertion_user_handle: Option<String>,
}

fn non_blank(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

fn decode_b64url(value: &str) -> Vec<u8> {
    // A field that does not decode becomes empty bytes, which the ceremony
    // refuses: a malformed proof is a failed proof, never an absent one.
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim())
        .unwrap_or_default()
}

impl ApiTokenForm {
    /// The second factor the form carries. A TOTP code wins over an
    /// assertion; `origin` is the server-pinned expected origin.
    fn second_factor(&mut self, origin: &str) -> SecondFactorProof {
        if let Some(code) = non_blank(self.totp_code.take()) {
            return SecondFactorProof::TotpCode(code.trim().to_string());
        }
        let Some(credential_id) = non_blank(self.assertion_credential_id.take()) else {
            return SecondFactorProof::None;
        };
        let field = |v: &mut Option<String>| decode_b64url(v.take().as_deref().unwrap_or(""));
        SecondFactorProof::WebAuthnAssertion(Box::new(StepUpAssertion {
            credential_id: decode_b64url(&credential_id),
            client_data_json: field(&mut self.assertion_client_data_json),
            authenticator_data: field(&mut self.assertion_authenticator_data),
            signature: field(&mut self.assertion_signature),
            user_handle: non_blank(self.assertion_user_handle.take()).map(|h| decode_b64url(&h)),
            origin: origin.to_string(),
        }))
    }
}

/// Parses the lifetime field (whole minutes). Absent means the default.
fn parse_ttl(raw: Option<&str>) -> Result<Duration, String> {
    let (min, max) = (
        minutes(OPERATOR_TOKEN_MIN_TTL),
        minutes(OPERATOR_TOKEN_MAX_TTL),
    );
    let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(OPERATOR_TOKEN_DEFAULT_TTL);
    };
    match raw.parse::<u64>() {
        Ok(m) if (min..=max).contains(&m) => Ok(Duration::from_secs(m * 60)),
        _ => Err(format!(
            "The lifetime must be a whole number of minutes from {min} to {max}."
        )),
    }
}

/// Renders the form with `status`, an optional error and the account's
/// factors (which inputs to show).
fn form_page(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    status: StatusCode,
    error: Option<String>,
    ttl: Duration,
) -> Response {
    let has_totp = state
        .identity
        .mfa_enabled(&session.realm_id, &session.user_id)
        .unwrap_or(false);
    let has_passkey = state
        .identity
        .list_webauthn_credentials(&session.realm_id, &session.user_id)
        .is_ok_and(|creds| !creds.is_empty());
    super::templates::render_status(
        &ApiTokenFormTemplate {
            error,
            ttl_minutes: minutes(ttl),
            min_minutes: minutes(OPERATOR_TOKEN_MIN_TTL),
            max_minutes: minutes(OPERATOR_TOKEN_MAX_TTL),
            has_totp,
            has_passkey,
            chrome: true,
            active: "api-tokens",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            realm_theme_url: state.realm_theme_url(),
            inline_theme_css: state.inline_theme_css(),
        },
        status,
    )
}

/// `GET /ui/admin/api-tokens` — the token form.
pub async fn admin_api_token_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
) -> Response {
    form_page(
        &state,
        &session,
        StatusCode::OK,
        None,
        OPERATOR_TOKEN_DEFAULT_TTL,
    )
}

/// Verifies the form's fresh two-factor step-up for the signed-in operator.
/// On refusal, returns the page to send instead (the form with an error).
async fn check_step_up(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    headers: &HeaderMap,
    form: &mut ApiTokenForm,
    ttl: Duration,
) -> Result<(), Response> {
    let origin = state.public_origin_str(headers);
    let password = form
        .password
        .take()
        .filter(|p| !p.trim().is_empty())
        .map(|p| crate::identity::CleartextPassword::new(p.as_bytes().to_vec()));
    let second = form.second_factor(&origin);
    let msg = match verify_operator_step_up(
        &state.identity,
        &session.realm_id,
        &session.user_id,
        password,
        second,
    )
    .await
    {
        Ok(()) => return Ok(()),
        Err(StepUpError::Overloaded { retry_after }) => {
            let mut resp = form_page(
                state,
                session,
                StatusCode::SERVICE_UNAVAILABLE,
                Some("Verification is busy. Try again in a few seconds.".to_string()),
                ttl,
            );
            if let Ok(v) = HeaderValue::from_str(&retry_after.as_secs().max(1).to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
            return Err(resp);
        }
        Err(StepUpError::SecondFactorNotEnrolled) => {
            "Your account has no second factor. Enrol an authenticator app or a passkey on \
             your account page, then create the token."
        }
        Err(_) => {
            "Your password and a second factor (an authenticator code, or a passkey that \
             verifies you) are both required, and both must be correct."
        }
    };
    Err(form_page(
        state,
        session,
        StatusCode::FORBIDDEN,
        Some(msg.to_string()),
        ttl,
    ))
}

/// The one page the token is ever shown on: `no-store`, `no-referrer`.
fn issued_page(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    token: &OperatorToken,
    ttl: Duration,
) -> Response {
    let mut resp = render(&ApiTokenIssuedTemplate {
        token: token.access_token(),
        jti: token.jti().unwrap_or("—"),
        session_id: token.session_id().as_uuid().to_string(),
        expires_at: format_ts(token.expires_at()),
        ttl_minutes: minutes(ttl),
        chrome: true,
        active: "api-tokens",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    });
    // The page holds a bearer credential: never cache it, never leak the
    // URL it was shown on.
    let headers = resp.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}

/// `POST /ui/admin/api-tokens` — verifies the step-up and shows a new
/// system-realm token once.
pub async fn admin_api_token_issue(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    headers: HeaderMap,
    FriendlyForm(mut form): FriendlyForm<ApiTokenForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let ttl = match parse_ttl(form.ttl_minutes.as_deref()) {
        Ok(ttl) => ttl,
        Err(msg) => {
            return form_page(
                &state,
                &session,
                StatusCode::BAD_REQUEST,
                Some(msg),
                OPERATOR_TOKEN_DEFAULT_TTL,
            )
        }
    };
    if let Err(resp) = check_step_up(&state, &session, &headers, &mut form, ttl).await {
        return resp;
    }

    let issuer = OperatorTokenIssuer::Console {
        console_session_id: session.session_id.clone(),
    };
    match state
        .identity
        .issue_operator_token(&session.user_id, ttl, &issuer)
    {
        Ok(token) => issued_page(&state, &session, &token, ttl),
        Err(IdentityError::Unauthorized) => form_page(
            &state,
            &session,
            StatusCode::FORBIDDEN,
            Some("Your account's token would not carry hearth.admin.".to_string()),
            ttl,
        ),
        Err(e) => {
            tracing::warn!(error = %e, "operator token issuance failed");
            super::handlers_common::server_error()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lifetime_is_whole_minutes_within_bounds() {
        assert_eq!(parse_ttl(None), Ok(OPERATOR_TOKEN_DEFAULT_TTL));
        assert_eq!(parse_ttl(Some("  ")), Ok(OPERATOR_TOKEN_DEFAULT_TTL));
        assert_eq!(parse_ttl(Some("1")), Ok(Duration::from_secs(60)));
        assert_eq!(parse_ttl(Some("60")), Ok(Duration::from_secs(3600)));
        for bad in ["0", "61", "-5", "1.5", "15m", "abc"] {
            assert!(parse_ttl(Some(bad)).is_err(), "{bad}");
        }
    }
}
