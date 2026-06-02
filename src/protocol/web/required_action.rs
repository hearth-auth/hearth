//! Required-Action OIDC interceptor.
//!
//! After a user authenticates, the authorize route checks for pending required
//! actions before issuing an authorization code.  When actions are present the
//! flow is:
//!
//! 1. `required_action_check` intercepts the authorize request, sorts actions
//!    by priority, generates an RA session JWT (via the identity engine), sets
//!    an HttpOnly cookie, and redirects to `/required-action/{first_action}`.
//! 2. `/required-action/{action}` renders the action page (GET) or marks the
//!    action complete (POST).
//! 3. On POST the handler calls `next_required_action` (more actions remain)
//!    or `resume_oidc_flow` (all actions done).
//! 4. `resume_oidc_flow` clears the RA cookie, issues the authorization code,
//!    and redirects to `redirect_uri?code=…&state=…`.
//!
//! | Route | Method | Purpose |
//! |-------|--------|---------|
//! | `/required-action/{action}` | GET  | Render the action page |
//! | `/required-action/{action}` | POST | Mark action complete |
//!
//! # Cookie security
//!
//! The RA session cookie is `HttpOnly; Path=/required-action; SameSite=Strict`.
//! It is scoped to `/required-action` only, preventing the RA JWT from being
//! sent to the main UI paths.  `Secure` is added when the server is TLS-enabled
//! or a trusted proxy signals `X-Forwarded-Proto: https`.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{ClientId, RealmId, Timestamp, UserId};
use crate::identity::error::IdentityError;
use crate::identity::ra_token::{self, OidcParams};
use crate::identity::CodeChallengeMethod;
use crate::identity::RequiredAction;
use crate::identity::{CleartextPassword, SessionContext, UpdateUserRequest};
use crate::protocol::web::auth::{issue_auth_cookies, IssuedCookies};
use crate::protocol::web::oauth_consent::{build_authorization_redirect, AuthorizeQuery};

use super::handlers::append_cookie;
use super::handlers_common;
use super::templates::render;
use super::WebState;

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// Rendered by `GET /required-action/{action}`.
#[derive(Template)]
#[template(path = "ui/required_action/action.html")]
struct ActionPageTemplate {
    /// SCREAMING_SNAKE_CASE action name (e.g. `"VERIFY_EMAIL"`).
    action: String,
    /// Human-readable action description for the page heading.
    action_label: &'static str,
    // Layout chrome.
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    narrow: bool,
    flash: Option<super::templates::Flash>,
    csrf: Option<String>,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// Rendered by `GET /required-action/UPDATE_PASSWORD` (and re-rendered on validation failure).
#[derive(Template)]
#[template(path = "ui/required_action/update_password.html")]
struct UpdatePasswordPageTemplate {
    /// Inline error message shown above the form on validation failure.
    error: Option<String>,
    // Layout chrome.
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    narrow: bool,
    flash: Option<super::templates::Flash>,
    csrf: Option<String>,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// `application/x-www-form-urlencoded` body for `POST /required-action/UPDATE_PASSWORD`.
#[derive(Debug, Deserialize)]
pub struct UpdatePasswordForm {
    #[serde(default)]
    pub new_password: String,
    #[serde(default)]
    pub confirm_password: String,
}

fn action_label(action: &str) -> &'static str {
    match action {
        "VERIFY_EMAIL" => "Verify your email address",
        "UPDATE_PASSWORD" => "Update your password",
        "ENROLL_PHONE_OTP" => "Enroll your phone number",
        _ => "Complete required action",
    }
}

// ---------------------------------------------------------------------------
// Public entry point: called from oauth_consent::authorize_get_impl  (AC-1)
// ---------------------------------------------------------------------------

/// Checks whether the authenticated user has pending required actions.
///
/// Returns `Some(redirect_response)` when actions are present — the caller
/// MUST return this response immediately.  Returns `None` to indicate the
/// normal flow should continue (AC-5: no-op path).
///
/// The OIDC params are embedded in the signed RA session JWT so the flow can
/// be resumed by [`resume_oidc_flow`] once all actions are complete.
pub fn required_action_check(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    q: &AuthorizeQuery,
    headers: &HeaderMap,
    now: Timestamp,
    via_par: bool,
) -> Option<Response> {
    let user = state.identity.get_user(realm, user_id).ok().flatten()?;

    let mut actions: Vec<RequiredAction> = user.required_actions().to_vec();

    // Dynamic injection: if the realm requires SMS MFA and the user has no
    // verified phone, ensure ENROLL_PHONE_OTP is in the pending actions list.
    inject_enroll_phone_otp_if_needed(state, realm, user_id, &user, &mut actions);

    if actions.is_empty() {
        return None;
    }

    // Sort by canonical priority so execution order is deterministic regardless
    // of how actions were stored.
    actions.sort_by_key(|a| a.priority());
    let first = actions[0];

    let oidc_params = OidcParams {
        client_id: q.client_id.clone(),
        redirect_uri: q.redirect_uri.clone(),
        scope: q.scope.clone(),
        code_challenge: q.code_challenge.clone(),
        code_challenge_method: q.code_challenge_method.clone(),
        nonce: if q.nonce.is_empty() {
            None
        } else {
            Some(q.nonce.clone())
        },
        state: if q.state.is_empty() {
            None
        } else {
            Some(q.state.clone())
        },
        response_type: q.response_type.clone(),
        response_mode: q.response_mode.clone().filter(|m| !m.is_empty()),
        via_par,
    };

    let token = match state
        .identity
        .generate_ra_token(realm, user_id, actions, oidc_params, now)
    {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "required_action_check: generate_ra_token failed");
            return Some(handlers_common::server_error());
        }
    };

    let secure = state.is_secure_request(headers);
    let cookie = ra_token::ra_session_cookie(&token, secure);
    let path = format!("/required-action/{}", first.as_path_segment());
    let mut response = Redirect::to(&path).into_response();
    append_cookie(&mut response, &cookie);
    Some(response)
}

/// Checks whether the authenticating user has pending required actions for
/// the **direct browser login path** (not OIDC).
///
/// Returns `Some(redirect_response)` when actions are pending — the caller
/// MUST return this response immediately instead of creating a session.
/// Returns `None` when no actions are pending and the login can proceed.
///
/// Unlike [`required_action_check`], this generates an RA token without
/// OIDC params; flow resumption creates a session cookie and redirects to
/// `return_to` once all actions are complete.
pub fn required_action_check_browser(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    return_to: Option<&str>,
    headers: &HeaderMap,
    now: Timestamp,
) -> Option<Response> {
    let user = state.identity.get_user(realm, user_id).ok().flatten()?;

    let mut actions: Vec<RequiredAction> = user.required_actions().to_vec();

    // Dynamic injection: if the realm requires SMS MFA and the user has no
    // verified phone, ensure ENROLL_PHONE_OTP is in the pending actions list.
    inject_enroll_phone_otp_if_needed(state, realm, user_id, &user, &mut actions);

    if actions.is_empty() {
        return None;
    }

    actions.sort_by_key(|a| a.priority());
    let first = actions[0];

    let token = match state.identity.generate_browser_ra_token(
        realm,
        user_id,
        actions,
        return_to.map(str::to_string),
        now,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "required_action_check_browser: generate_browser_ra_token failed");
            return Some(handlers_common::server_error());
        }
    };

    let secure = state.is_secure_request(headers);
    let cookie = ra_token::ra_session_cookie(&token, secure);
    let path = format!("/required-action/{}", first.as_path_segment());
    let mut response = Redirect::to(&path).into_response();
    append_cookie(&mut response, &cookie);
    Some(response)
}

/// Clears the RA cookie, creates a session, and redirects to the original
/// destination for the **direct browser login path**.
///
/// Called when all required actions have been completed on the browser path.
pub fn resume_browser_flow(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_sub: &str,
    return_to: Option<String>,
    secure: bool,
) -> Response {
    let clear_cookie = ra_token::clear_ra_session_cookie(secure);

    let Ok(user_uuid) = uuid::Uuid::parse_str(user_sub) else {
        return handlers_common::server_error();
    };
    let user_id = UserId::new(user_uuid);

    let session = match state
        .identity
        .create_session(realm, &user_id, &SessionContext::default())
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "resume_browser_flow: create_session failed");
            return handlers_common::server_error();
        }
    };

    let IssuedCookies {
        session_cookie,
        csrf_cookie,
    } = issue_auth_cookies(&state.cookie_secret, realm, session.id(), secure);

    let last_realm_cookie = super::auth::last_realm_cookie(
        &super::auth::last_realm_value(state.identity.as_ref(), realm),
        secure,
    );

    let location = return_to
        .as_deref()
        .and_then(super::auth::sanitize_return_to)
        .unwrap_or_else(|| "/ui".to_string());

    let mut response = Redirect::to(&location).into_response();
    append_cookie(&mut response, &clear_cookie);
    append_cookie(&mut response, &session_cookie);
    append_cookie(&mut response, &csrf_cookie);
    append_cookie(&mut response, &last_realm_cookie);
    response
}

// ---------------------------------------------------------------------------
// GET /required-action/{action}
// ---------------------------------------------------------------------------

/// Renders the action-specific page stub.
pub async fn action_page(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Path(action): Path<String>,
) -> Response {
    if RequiredAction::from_path_segment(&action).is_none() {
        return handlers_common::not_found("Unknown required action");
    }
    // Require a syntactically present RA cookie before rendering so orphaned
    // page loads (no active intercept) get a clear error rather than a form
    // the user cannot submit successfully.
    if read_ra_cookie(&headers).is_none() {
        return handlers_common::bad_request("No active required-action session");
    }

    let tmpl = ActionPageTemplate {
        action_label: action_label(&action),
        action: action.clone(),
        chrome: false,
        active: "",
        user_email: None,
        is_admin: false,
        narrow: true,
        flash: None,
        csrf: None,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    };
    render(&tmpl)
}

// ---------------------------------------------------------------------------
// POST /required-action/{action}  (AC-3: sequential completion)
// ---------------------------------------------------------------------------

/// Marks the current required action complete and advances the flow.
///
/// Reads the RA session cookie, validates the JWT, removes `action` from
/// `pending_actions`, then either:
/// - Calls [`next_required_action`] (more actions remain), or
/// - Calls [`resume_oidc_flow`] (all actions done — issues the auth code).
pub async fn action_complete(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Path(action): Path<String>,
) -> Response {
    let Some(completed) = RequiredAction::from_path_segment(&action) else {
        return handlers_common::not_found("Unknown required action");
    };

    let Some(token) = read_ra_cookie(&headers) else {
        return handlers_common::bad_request("No active required-action session");
    };

    // Bootstrap realm lookup from the unsigned payload before verifying.
    let Some(realm_str) = ra_token::extract_realm_unchecked(&token) else {
        return handlers_common::bad_request("Malformed RA session token");
    };
    let Ok(realm_uuid) = uuid::Uuid::parse_str(&realm_str) else {
        return handlers_common::bad_request("Malformed realm in RA session token");
    };
    let realm = RealmId::new(realm_uuid);

    let now = Timestamp::from_micros(now_micros());
    let claims = match state.identity.validate_ra_token(&realm, &token, now) {
        Ok(c) => c,
        Err(ra_token::RaTokenError::Expired) => {
            return handlers_common::bad_request("Required-action session has expired");
        }
        Err(_) => {
            return handlers_common::bad_request("Invalid required-action session token");
        }
    };

    let secure = state.is_secure_request(&headers);

    // Remove the just-completed action from the pending list.
    let remaining: Vec<RequiredAction> = claims
        .pending_actions
        .into_iter()
        .filter(|a| *a != completed)
        .collect();

    if remaining.is_empty() {
        if claims.browser_return_to.is_some() {
            resume_browser_flow(
                &state,
                &realm,
                &claims.sub,
                claims.browser_return_to,
                secure,
            )
        } else if let Some(oidc_params) = claims.oidc_params {
            resume_oidc_flow(&state, &realm, &claims.sub, oidc_params, secure)
        } else {
            resume_browser_flow(&state, &realm, &claims.sub, None, secure)
        }
    } else {
        next_required_action(
            &state,
            &realm,
            &claims.sub,
            remaining,
            claims.oidc_params,
            claims.browser_return_to,
            secure,
            now,
        )
    }
}

// ---------------------------------------------------------------------------
// Flow helpers (also used in tests)
// ---------------------------------------------------------------------------

/// Clears the RA cookie and issues the authorization code.
///
/// Called when all required actions have been completed.  Reconstructs the
/// original OIDC authorize request from `RaClaims` and calls
/// `identity.issue_authorization_code`.
pub fn resume_oidc_flow(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_sub: &str,
    oidc_params: OidcParams,
    secure: bool,
) -> Response {
    let clear_cookie = ra_token::clear_ra_session_cookie(secure);

    let Ok(user_uuid) = uuid::Uuid::parse_str(user_sub) else {
        return handlers_common::server_error();
    };
    let Ok(client_uuid) = uuid::Uuid::parse_str(&oidc_params.client_id) else {
        return handlers_common::server_error();
    };

    let user_id = UserId::new(user_uuid);
    let client_id = ClientId::new(client_uuid);

    let code_challenge_method = match oidc_params.code_challenge_method.as_str() {
        "S256" => Some(CodeChallengeMethod::S256),
        _ => None,
    };
    let state_param = oidc_params.state.as_deref().unwrap_or("");
    let code_challenge = if oidc_params.code_challenge.is_empty() {
        None
    } else {
        Some(oidc_params.code_challenge.clone())
    };

    let response_mode = oidc_params
        .response_mode
        .as_deref()
        .and_then(|m| m.parse::<crate::identity::ResponseMode>().ok());

    match state.identity.issue_authorization_code(
        realm,
        &user_id,
        &client_id,
        &oidc_params.redirect_uri,
        &oidc_params.scope,
        state_param,
        code_challenge,
        code_challenge_method,
        oidc_params.nonce.clone(),
        Vec::new(),
        response_mode,
        None,                // jar_request — RA resume restores pre-validated params
        oidc_params.via_par, // propagated from the original authorize request
    ) {
        Ok(resp) => {
            let location = build_authorization_redirect(&oidc_params.redirect_uri, &resp);
            let mut response = Redirect::to(&location).into_response();
            append_cookie(&mut response, &clear_cookie);
            response
        }
        Err(e) => {
            tracing::warn!(error = %e, "resume_oidc_flow: issue_authorization_code failed");
            handlers_common::server_error()
        }
    }
}

/// Generates a fresh RA session JWT for the remaining actions and redirects
/// to the next action page.  (AC-3: sequential multi-action flow)
///
/// Exactly one of `oidc_params` or `browser_return_to` should be `Some` —
/// whichever was set when the RA flow was originally initiated.
pub fn next_required_action(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_sub: &str,
    mut remaining: Vec<RequiredAction>,
    oidc_params: Option<OidcParams>,
    browser_return_to: Option<String>,
    secure: bool,
    now: Timestamp,
) -> Response {
    remaining.sort_by_key(|a| a.priority());
    let next = remaining[0];

    let Ok(user_uuid) = uuid::Uuid::parse_str(user_sub) else {
        return handlers_common::server_error();
    };
    let user_id = UserId::new(user_uuid);

    let token = if let Some(oidc) = oidc_params {
        match state
            .identity
            .generate_ra_token(realm, &user_id, remaining, oidc, now)
        {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "next_required_action: generate_ra_token failed");
                return handlers_common::server_error();
            }
        }
    } else {
        match state.identity.generate_browser_ra_token(
            realm,
            &user_id,
            remaining,
            browser_return_to,
            now,
        ) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "next_required_action: generate_browser_ra_token failed");
                return handlers_common::server_error();
            }
        }
    };

    let cookie = ra_token::ra_session_cookie(&token, secure);
    let path = format!("/required-action/{}", next.as_path_segment());
    let mut response = Redirect::to(&path).into_response();
    append_cookie(&mut response, &cookie);
    response
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Dynamically injects `ENROLL_PHONE_OTP` when a realm requires SMS MFA and
/// the user has no verified phone number.
///
/// Persists the action to the user record so subsequent `required_actions()`
/// reads see it. Idempotent: no-op if already present or not applicable.
fn inject_enroll_phone_otp_if_needed(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    user: &crate::identity::User,
    actions: &mut Vec<RequiredAction>,
) {
    if user.phone_verified() {
        return;
    }
    if actions.contains(&RequiredAction::EnrollPhoneOtp) {
        return;
    }
    let sms_required = state
        .identity
        .get_realm(realm)
        .ok()
        .flatten()
        .and_then(|r| r.config().mfa_methods.clone())
        .map(|methods| methods.iter().any(|m| m == "sms"))
        .unwrap_or(false);

    if !sms_required {
        return;
    }

    actions.push(RequiredAction::EnrollPhoneOtp);

    // Persist so the RA-JWT and future checks agree on the list.
    let mut persisted = user.required_actions().to_vec();
    if !persisted.contains(&RequiredAction::EnrollPhoneOtp) {
        persisted.push(RequiredAction::EnrollPhoneOtp);
        if let Err(e) = state.identity.update_user(
            realm,
            user_id,
            &UpdateUserRequest {
                required_actions: Some(persisted),
                ..Default::default()
            },
        ) {
            tracing::warn!(
                error = %e,
                "inject_enroll_phone_otp_if_needed: failed to persist ENROLL_PHONE_OTP"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// GET /required-action/VERIFY_EMAIL
// ---------------------------------------------------------------------------

/// Rendered by `GET /required-action/VERIFY_EMAIL`.
#[derive(Template)]
#[template(path = "ui/required_action/verify_email.html")]
struct VerifyEmailPageTemplate {
    /// Masked/full email address shown on the "check your email" page.
    user_email: Option<String>,
    // Layout chrome.
    chrome: bool,
    active: &'static str,
    is_admin: bool,
    narrow: bool,
    flash: Option<super::templates::Flash>,
    csrf: Option<String>,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// Rendered by `GET /required-action/VERIFY_EMAIL/confirm` when the token is
/// expired or invalid.
#[derive(Template)]
#[template(path = "ui/required_action/verify_email_expired.html")]
struct VerifyEmailExpiredTemplate {
    // Layout chrome.
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    narrow: bool,
    flash: Option<super::templates::Flash>,
    csrf: Option<String>,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// Query parameters for `GET /required-action/VERIFY_EMAIL/confirm`.
#[derive(Debug, Deserialize)]
pub struct VerifyEmailConfirmQuery {
    /// The plaintext verification token from the emailed link.
    #[serde(default)]
    pub token: String,
}

/// Renders the "check your email" page for the VERIFY_EMAIL required action.
///
/// Before sending the verification email, checks if the user's email is already
/// verified in storage (auto-clear scenario for migration artifacts). If so,
/// clears the VERIFY_EMAIL action and advances the OIDC flow without sending
/// another email (AC-8 / OQ-3 resolution).
#[allow(clippy::too_many_lines)] // TODO: split this function
pub async fn verify_email_page(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    let Some(token) = read_ra_cookie(&headers) else {
        return handlers_common::bad_request("No active required-action session");
    };

    let Some(realm_str) = ra_token::extract_realm_unchecked(&token) else {
        return handlers_common::bad_request("Malformed RA session token");
    };
    let Ok(realm_uuid) = uuid::Uuid::parse_str(&realm_str) else {
        return handlers_common::bad_request("Malformed realm in RA session token");
    };
    let realm = RealmId::new(realm_uuid);

    let now = Timestamp::from_micros(now_micros());
    let claims = match state.identity.validate_ra_token(&realm, &token, now) {
        Ok(c) => c,
        Err(ra_token::RaTokenError::Expired) => {
            return Redirect::to("/").into_response();
        }
        Err(_) => {
            return handlers_common::bad_request("Invalid required-action session token");
        }
    };

    let Ok(user_uuid) = uuid::Uuid::parse_str(&claims.sub) else {
        return handlers_common::server_error();
    };
    let user_id = UserId::new(user_uuid);
    let secure = state.is_secure_request(&headers);

    // Look up the user to get email and email_verified status.
    let Ok(Some(user)) = state.identity.get_user(&realm, &user_id) else {
        return handlers_common::server_error();
    };

    // Auto-clear: if the email is already verified in storage, skip sending
    // another email and advance the OIDC flow directly (OQ-3 / AC-8).
    if user.email_verified() {
        if let Err(e) = state.identity.update_user(
            &realm,
            &user_id,
            &UpdateUserRequest {
                required_actions: Some(
                    user.required_actions()
                        .iter()
                        .filter(|&&a| a != RequiredAction::VerifyEmail)
                        .copied()
                        .collect(),
                ),
                ..Default::default()
            },
        ) {
            tracing::warn!(
                error = %e,
                "verify_email_page: auto-clear failed to update required_actions"
            );
        }

        if let Err(e) = state.audit.append(&CreateAuditEvent {
            realm_id: realm.clone(),
            actor: user_id.as_uuid().to_string(),
            action: AuditAction::RequiredActionAutoCleared,
            resource_type: "user".to_string(),
            resource_id: user_id.as_uuid().to_string(),
            metadata: Some(serde_json::json!({
                "action_type": "VERIFY_EMAIL",
                "reason": "email_already_verified"
            })),
        }) {
            tracing::warn!(error = %e, "verify_email_page: auto-clear audit append failed");
        }

        let remaining: Vec<RequiredAction> = claims
            .pending_actions
            .into_iter()
            .filter(|a| *a != RequiredAction::VerifyEmail)
            .collect();

        return if remaining.is_empty() {
            if claims.browser_return_to.is_some() {
                resume_browser_flow(
                    &state,
                    &realm,
                    &claims.sub,
                    claims.browser_return_to,
                    secure,
                )
            } else if let Some(oidc_params) = claims.oidc_params {
                resume_oidc_flow(&state, &realm, &claims.sub, oidc_params, secure)
            } else {
                resume_browser_flow(&state, &realm, &claims.sub, None, secure)
            }
        } else {
            next_required_action(
                &state,
                &realm,
                &claims.sub,
                remaining,
                claims.oidc_params,
                claims.browser_return_to,
                secure,
                now,
            )
        };
    }

    // Issue a new verification token and send the email (best-effort).
    match state
        .identity
        .issue_email_verification_token(&realm, &user_id)
    {
        Ok(verify_token) => {
            if let Some(email_svc) = state.email.as_ref() {
                let base = state
                    .config
                    .as_ref()
                    .and_then(|c| c.onboarding.base_url.as_deref())
                    .unwrap_or("http://localhost")
                    .trim_end_matches('/');
                let verify_url = format!(
                    "{base}/required-action/VERIFY_EMAIL/confirm?token={}",
                    percent_encode_string(&verify_token)
                );
                if let Err(e) =
                    email_svc.send_verification_email(user.email(), &verify_url, None, None, None)
                {
                    tracing::warn!(error = %e, "verify_email_page: failed to send verification email");
                }
            } else {
                tracing::warn!("verify_email_page: no email transport configured");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "verify_email_page: issue_email_verification_token failed");
        }
    }

    let tmpl = VerifyEmailPageTemplate {
        user_email: Some(user.email().to_string()),
        chrome: false,
        active: "",
        is_admin: false,
        narrow: true,
        flash: None,
        csrf: None,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    };
    render(&tmpl)
}

/// Validates a clicked verification token and advances the OIDC flow.
///
/// Requires the RA session cookie (400 if absent). On success, removes
/// VERIFY_EMAIL from the RA pending list and calls
/// [`resume_oidc_flow`] or [`next_required_action`]. On failure, renders an
/// error page with a link to resend the verification email.
#[allow(clippy::too_many_lines)] // TODO: split this function
pub async fn verify_email_confirm(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Query(q): Query<VerifyEmailConfirmQuery>,
) -> Response {
    let Some(ra_cookie) = read_ra_cookie(&headers) else {
        return handlers_common::bad_request("No active required-action session");
    };

    let Some(realm_str) = ra_token::extract_realm_unchecked(&ra_cookie) else {
        return handlers_common::bad_request("Malformed RA session token");
    };
    let Ok(realm_uuid) = uuid::Uuid::parse_str(&realm_str) else {
        return handlers_common::bad_request("Malformed realm in RA session token");
    };
    let realm = RealmId::new(realm_uuid);

    let now = Timestamp::from_micros(now_micros());
    let claims = match state.identity.validate_ra_token(&realm, &ra_cookie, now) {
        Ok(c) => c,
        Err(ra_token::RaTokenError::Expired) => {
            return Redirect::to("/").into_response();
        }
        Err(_) => {
            return handlers_common::bad_request("Invalid required-action session token");
        }
    };

    let Ok(user_uuid) = uuid::Uuid::parse_str(&claims.sub) else {
        return handlers_common::server_error();
    };
    let user_id = UserId::new(user_uuid);
    let secure = state.is_secure_request(&headers);

    // Validate and consume the email verification token.
    if q.token.is_empty() {
        return render_verify_email_expired(&state);
    }

    match state.identity.verify_email_token(&realm, &q.token) {
        Ok(verified_user_id) => {
            if verified_user_id != user_id {
                return handlers_common::bad_request("Verification token does not match session");
            }
            // Remove VERIFY_EMAIL from the user's persistent required_actions.
            if let Ok(Some(user)) = state.identity.get_user(&realm, &user_id) {
                let updated: Vec<RequiredAction> = user
                    .required_actions()
                    .iter()
                    .filter(|&&a| a != RequiredAction::VerifyEmail)
                    .copied()
                    .collect();
                if let Err(e) = state.identity.update_user(
                    &realm,
                    &user_id,
                    &UpdateUserRequest {
                        required_actions: Some(updated),
                        ..Default::default()
                    },
                ) {
                    tracing::warn!(
                        error = %e,
                        "verify_email_confirm: failed to clear VERIFY_EMAIL from user record"
                    );
                }
            }

            // Audit: RequiredActionCompleted.
            if let Err(e) = state.audit.append(&CreateAuditEvent {
                realm_id: realm.clone(),
                actor: user_id.as_uuid().to_string(),
                action: AuditAction::RequiredActionCompleted,
                resource_type: "user".to_string(),
                resource_id: user_id.as_uuid().to_string(),
                metadata: Some(serde_json::json!({ "action_type": "VERIFY_EMAIL" })),
            }) {
                tracing::warn!(error = %e, "verify_email_confirm: audit append failed");
            }

            // Advance flow (OIDC or browser).
            let remaining: Vec<RequiredAction> = claims
                .pending_actions
                .into_iter()
                .filter(|a| *a != RequiredAction::VerifyEmail)
                .collect();

            if remaining.is_empty() {
                if claims.browser_return_to.is_some() {
                    resume_browser_flow(
                        &state,
                        &realm,
                        &claims.sub,
                        claims.browser_return_to,
                        secure,
                    )
                } else if let Some(oidc_params) = claims.oidc_params {
                    resume_oidc_flow(&state, &realm, &claims.sub, oidc_params, secure)
                } else {
                    resume_browser_flow(&state, &realm, &claims.sub, None, secure)
                }
            } else {
                next_required_action(
                    &state,
                    &realm,
                    &claims.sub,
                    remaining,
                    claims.oidc_params,
                    claims.browser_return_to,
                    secure,
                    now,
                )
            }
        }
        Err(IdentityError::VerificationTokenInvalid) => render_verify_email_expired(&state),
        Err(e) => {
            tracing::warn!(error = %e, "verify_email_confirm: unexpected error");
            handlers_common::server_error()
        }
    }
}

fn render_verify_email_expired(state: &Arc<WebState>) -> Response {
    let tmpl = VerifyEmailExpiredTemplate {
        chrome: false,
        active: "",
        user_email: None,
        is_admin: false,
        narrow: true,
        flash: None,
        csrf: None,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    };
    render(&tmpl)
}

/// Percent-encodes a string for safe inclusion in a URL query parameter.
fn percent_encode_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    percent_encode_into(value, &mut out);
    out
}

// ---------------------------------------------------------------------------
// GET /required-action/UPDATE_PASSWORD
// ---------------------------------------------------------------------------

/// Renders the update-password form.
pub async fn update_password_page(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    if read_ra_cookie(&headers).is_none() {
        return handlers_common::bad_request("No active required-action session");
    }
    render_update_password_form(&state, None)
}

// ---------------------------------------------------------------------------
// POST /required-action/UPDATE_PASSWORD
// ---------------------------------------------------------------------------

/// Processes the new-password submission for the UPDATE_PASSWORD required action.
///
/// On validation failure the form is re-rendered with an inline error and the
/// RA cookie is left intact (the token remains valid for the remaining TTL).
/// On success the password credential is replaced, the action is removed from
/// the user record, and the OIDC flow resumes.
#[allow(clippy::too_many_lines)] // TODO: split this function
pub async fn update_password_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<UpdatePasswordForm>,
) -> Response {
    let Some(token) = read_ra_cookie(&headers) else {
        return handlers_common::bad_request("No active required-action session");
    };

    let Some(realm_str) = ra_token::extract_realm_unchecked(&token) else {
        return handlers_common::bad_request("Malformed RA session token");
    };
    let Ok(realm_uuid) = uuid::Uuid::parse_str(&realm_str) else {
        return handlers_common::bad_request("Malformed realm in RA session token");
    };
    let realm = RealmId::new(realm_uuid);

    let now = Timestamp::from_micros(now_micros());
    let claims = match state.identity.validate_ra_token(&realm, &token, now) {
        Ok(c) => c,
        Err(ra_token::RaTokenError::Expired) => {
            // RA session expired — redirect to root so user can restart the login flow.
            return Redirect::to("/").into_response();
        }
        Err(_) => {
            return handlers_common::bad_request("Invalid required-action session token");
        }
    };

    let Ok(user_uuid) = uuid::Uuid::parse_str(&claims.sub) else {
        return handlers_common::server_error();
    };
    let user_id = UserId::new(user_uuid);
    let secure = state.is_secure_request(&headers);

    if form.new_password != form.confirm_password {
        return render_update_password_form(
            &state,
            Some("New password and confirmation do not match."),
        );
    }

    let new_pw = CleartextPassword::from_string(form.new_password);
    match state.identity.set_password(&realm, &user_id, &new_pw) {
        Ok(()) => {}
        Err(IdentityError::InvalidInput { reason }) => {
            return render_update_password_form(&state, Some(&reason));
        }
        Err(IdentityError::PasswordReused) => {
            return render_update_password_form(
                &state,
                Some("That password was used recently — choose a different one."),
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "update_password_submit: set_password failed");
            return render_update_password_form(
                &state,
                Some("Unable to update password. Please try again."),
            );
        }
    }

    // Remove UPDATE_PASSWORD from the user's persistent required_actions so
    // future logins are not intercepted again for this action.
    if let Ok(Some(user)) = state.identity.get_user(&realm, &user_id) {
        let updated_actions: Vec<RequiredAction> = user
            .required_actions()
            .iter()
            .filter(|&&a| a != RequiredAction::UpdatePassword)
            .copied()
            .collect();
        if let Err(e) = state.identity.update_user(
            &realm,
            &user_id,
            &UpdateUserRequest {
                required_actions: Some(updated_actions),
                ..Default::default()
            },
        ) {
            tracing::warn!(
                error = %e,
                "update_password_submit: failed to clear UPDATE_PASSWORD from user record"
            );
        }
    }

    // Emit audit event (best-effort — never blocks the response).
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: user_id.as_uuid().to_string(),
        action: AuditAction::RequiredActionCompleted,
        resource_type: "user".to_string(),
        resource_id: user_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "action_type": "UPDATE_PASSWORD" })),
    }) {
        tracing::warn!(error = %e, "update_password_submit: audit append failed");
    }

    // Advance the OIDC flow: remove UPDATE_PASSWORD from the RA JWT pending list.
    let remaining: Vec<RequiredAction> = claims
        .pending_actions
        .into_iter()
        .filter(|a| *a != RequiredAction::UpdatePassword)
        .collect();

    if remaining.is_empty() {
        if claims.browser_return_to.is_some() {
            resume_browser_flow(
                &state,
                &realm,
                &claims.sub,
                claims.browser_return_to,
                secure,
            )
        } else if let Some(oidc_params) = claims.oidc_params {
            resume_oidc_flow(&state, &realm, &claims.sub, oidc_params, secure)
        } else {
            resume_browser_flow(&state, &realm, &claims.sub, None, secure)
        }
    } else {
        next_required_action(
            &state,
            &realm,
            &claims.sub,
            remaining,
            claims.oidc_params,
            claims.browser_return_to,
            secure,
            now,
        )
    }
}

// ---------------------------------------------------------------------------
// UPDATE_PASSWORD helpers
// ---------------------------------------------------------------------------

fn render_update_password_form(state: &Arc<WebState>, error: Option<&str>) -> Response {
    let tmpl = UpdatePasswordPageTemplate {
        error: error.map(str::to_string),
        chrome: false,
        active: "",
        user_email: None,
        is_admin: false,
        narrow: true,
        flash: None,
        csrf: None,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    };
    render(&tmpl)
}

// ---------------------------------------------------------------------------
// GET /required-action/ENROLL_PHONE_OTP
// ---------------------------------------------------------------------------

/// Rendered by `GET /required-action/ENROLL_PHONE_OTP`.
#[derive(Template)]
#[template(path = "ui/required_action/enroll_phone_otp.html")]
struct EnrollPhoneOtpPageTemplate {
    error: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    narrow: bool,
    flash: Option<super::templates::Flash>,
    csrf: Option<String>,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// Rendered by `POST /required-action/ENROLL_PHONE_OTP/send` on success.
#[derive(Template)]
#[template(path = "ui/required_action/enroll_phone_otp_verify.html")]
struct EnrollPhoneOtpVerifyTemplate {
    /// Masked display of the phone (e.g. `+1•••••0100`).
    masked_phone: String,
    /// Raw phone (for hidden form fields).
    phone: String,
    /// Opaque nonce returned by `issue_sms_otp`; `None` in rate-limited renders.
    nonce: Option<String>,
    error: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    narrow: bool,
    flash: Option<super::templates::Flash>,
    csrf: Option<String>,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// `application/x-www-form-urlencoded` body for `POST /required-action/ENROLL_PHONE_OTP/send`.
#[derive(Debug, Deserialize)]
pub struct EnrollPhoneOtpSendForm {
    #[serde(default)]
    pub phone: String,
}

/// `application/x-www-form-urlencoded` body for `POST /required-action/ENROLL_PHONE_OTP/verify`.
#[derive(Debug, Deserialize)]
pub struct EnrollPhoneOtpVerifyForm {
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub code: String,
}

/// Renders the phone-number input form.
pub async fn enroll_phone_otp_page(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    if read_ra_cookie(&headers).is_none() {
        return handlers_common::bad_request("No active required-action session");
    }
    render_enroll_phone_page(&state, None)
}

/// Sends an SMS OTP to the supplied E.164 phone number and renders the
/// code-entry form.
///
/// Enumeration resistance (AC 3.5.3): always returns 200 with the code-entry
/// form regardless of whether the phone is already registered to another user.
/// The OTP simply won't verify on the complete step, yielding a generic error.
pub async fn enroll_phone_otp_send(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<EnrollPhoneOtpSendForm>,
) -> Response {
    if read_ra_cookie(&headers).is_none() {
        return handlers_common::bad_request("No active required-action session");
    }

    let phone = form.phone.trim().to_string();

    // Basic E.164 validation: must start with '+' and contain 7-15 digits.
    if !is_e164(&phone) {
        return render_enroll_phone_page(
            &state,
            Some("Enter a valid international phone number (e.g. +15555550100)."),
        );
    }

    let Some(sms_sender) = state.sms.as_ref() else {
        tracing::warn!("enroll_phone_otp_send: SMS transport not configured");
        return render_enroll_phone_page(
            &state,
            Some("SMS delivery is not configured. Contact your administrator."),
        );
    };

    let hmac_key = sms_otp_hmac_key_bytes(&state);
    let now_ts = now_unix_ts();

    let nonce = match state.identity.issue_sms_otp(
        &extract_realm_from_ra_cookie(&headers),
        &phone,
        &hmac_key,
        sms_sender.as_ref(),
        now_ts,
    ) {
        Ok(n) => n,
        Err(crate::identity::IdentityError::SmsResendLimitExceeded) => {
            return render_enroll_phone_verify(
                &state,
                // Return the verify page with a warning rather than blocking —
                // the real OTP was already sent recently (rate limit window).
                &phone,
                None,
                Some("A code was recently sent to this number. Please wait before requesting another."),
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "enroll_phone_otp_send: issue_sms_otp failed");
            return render_enroll_phone_page(
                &state,
                Some("Failed to send verification code. Please try again."),
            );
        }
    };

    render_enroll_phone_verify(&state, &phone, Some(&nonce), None)
}

/// Verifies the submitted OTP code, stores the phone as verified, clears
/// `ENROLL_PHONE_OTP` from the user's required actions, and advances the flow.
#[allow(clippy::too_many_lines)] // TODO: split this function
pub async fn enroll_phone_otp_verify_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<EnrollPhoneOtpVerifyForm>,
) -> Response {
    let Some(token) = read_ra_cookie(&headers) else {
        return handlers_common::bad_request("No active required-action session");
    };

    let Some(realm_str) = ra_token::extract_realm_unchecked(&token) else {
        return handlers_common::bad_request("Malformed RA session token");
    };
    let Ok(realm_uuid) = uuid::Uuid::parse_str(&realm_str) else {
        return handlers_common::bad_request("Malformed realm in RA session token");
    };
    let realm = RealmId::new(realm_uuid);

    let now = Timestamp::from_micros(now_micros());
    let claims = match state.identity.validate_ra_token(&realm, &token, now) {
        Ok(c) => c,
        Err(ra_token::RaTokenError::Expired) => {
            return Redirect::to("/").into_response();
        }
        Err(_) => {
            return handlers_common::bad_request("Invalid required-action session token");
        }
    };

    let Ok(user_uuid) = uuid::Uuid::parse_str(&claims.sub) else {
        return handlers_common::server_error();
    };
    let user_id = UserId::new(user_uuid);
    let secure = state.is_secure_request(&headers);

    let phone = form.phone.trim().to_string();
    if !is_e164(&phone) || form.nonce.is_empty() || form.code.is_empty() {
        return render_enroll_phone_verify(
            &state,
            &phone,
            Some(&form.nonce),
            Some("Invalid submission."),
        );
    }

    let hmac_key = sms_otp_hmac_key_bytes(&state);
    let now_ts = now_unix_ts();

    match state
        .identity
        .verify_sms_otp(&realm, &form.nonce, &form.code, &hmac_key, now_ts)
    {
        Ok(()) => {}
        Err(_) => {
            return render_enroll_phone_verify(
                &state,
                &phone,
                Some(&form.nonce),
                Some("That code is incorrect or has expired. Try again or request a new code."),
            );
        }
    }

    // OTP verified — store phone number as verified and clear ENROLL_PHONE_OTP.
    let updated_actions: Vec<RequiredAction> = claims
        .pending_actions
        .iter()
        .filter(|&&a| a != RequiredAction::EnrollPhoneOtp)
        .copied()
        .collect();

    if let Err(e) = state.identity.update_user(
        &realm,
        &user_id,
        &UpdateUserRequest {
            phone_number: Some(Some(phone.clone())),
            phone_verified: Some(true),
            required_actions: Some(updated_actions.clone()),
            ..Default::default()
        },
    ) {
        tracing::warn!(error = %e, "enroll_phone_otp_verify_submit: update_user failed");
        return handlers_common::server_error();
    }

    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: user_id.as_uuid().to_string(),
        action: AuditAction::RequiredActionCompleted,
        resource_type: "user".to_string(),
        resource_id: user_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "action_type": "ENROLL_PHONE_OTP" })),
    }) {
        tracing::warn!(error = %e, "enroll_phone_otp_verify_submit: audit append failed");
    }

    if updated_actions.is_empty() {
        if claims.browser_return_to.is_some() {
            resume_browser_flow(
                &state,
                &realm,
                &claims.sub,
                claims.browser_return_to,
                secure,
            )
        } else if let Some(oidc_params) = claims.oidc_params {
            resume_oidc_flow(&state, &realm, &claims.sub, oidc_params, secure)
        } else {
            resume_browser_flow(&state, &realm, &claims.sub, None, secure)
        }
    } else {
        next_required_action(
            &state,
            &realm,
            &claims.sub,
            updated_actions,
            claims.oidc_params,
            claims.browser_return_to,
            secure,
            now,
        )
    }
}

// ---------------------------------------------------------------------------
// ENROLL_PHONE_OTP helpers
// ---------------------------------------------------------------------------

fn render_enroll_phone_page(state: &Arc<WebState>, error: Option<&str>) -> Response {
    let tmpl = EnrollPhoneOtpPageTemplate {
        error: error.map(str::to_string),
        chrome: false,
        active: "",
        user_email: None,
        is_admin: false,
        narrow: true,
        flash: None,
        csrf: None,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    };
    render(&tmpl)
}

fn render_enroll_phone_verify(
    state: &Arc<WebState>,
    phone: &str,
    nonce: Option<&str>,
    error: Option<&str>,
) -> Response {
    let tmpl = EnrollPhoneOtpVerifyTemplate {
        masked_phone: mask_phone(phone),
        phone: phone.to_string(),
        nonce: nonce.map(str::to_string),
        error: error.map(str::to_string),
        chrome: false,
        active: "",
        user_email: None,
        is_admin: false,
        narrow: true,
        flash: None,
        csrf: None,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    };
    render(&tmpl)
}

/// Masks a phone number for display: keeps the country code and last 4 digits.
/// E.g. `"+15555550100"` → `"+1•••••0100"`.
fn mask_phone(phone: &str) -> String {
    if phone.len() <= 5 {
        return phone.to_string();
    }
    let visible_suffix = &phone[phone.len() - 4..];
    let prefix_end = phone.find(|c: char| c.is_ascii_digit()).unwrap_or(1) + 1;
    let country_code = &phone[..prefix_end];
    let dots = "•".repeat(phone.len() - prefix_end - 4);
    format!("{country_code}{dots}{visible_suffix}")
}

/// Returns true when `s` is a syntactically valid E.164 number:
/// starts with '+', followed by 7–15 ASCII digits, no spaces.
fn is_e164(s: &str) -> bool {
    if !s.starts_with('+') {
        return false;
    }
    let digits = &s[1..];
    digits.len() >= 7 && digits.len() <= 15 && digits.chars().all(|c| c.is_ascii_digit())
}

/// Returns the HMAC key bytes to use for OTP operations.
///
/// Falls back to a deterministic dev key when the key is not configured
/// (Log transport, dev mode only).
fn sms_otp_hmac_key_bytes(state: &Arc<WebState>) -> Vec<u8> {
    state
        .sms_otp_hmac_key
        .clone()
        .unwrap_or_else(|| b"hearth-dev-sms-otp-key-not-for-production".to_vec())
}

/// Extracts the realm from the RA session cookie without full JWT verification
/// (used to provide a `RealmId` to `issue_sms_otp` before full token validation).
fn extract_realm_from_ra_cookie(headers: &HeaderMap) -> RealmId {
    read_ra_cookie(headers)
        .as_deref()
        .and_then(ra_token::extract_realm_unchecked)
        .and_then(|s| uuid::Uuid::parse_str(&s).ok())
        .map(RealmId::new)
        .unwrap_or_else(|| {
            // Should not happen; caller already verified the cookie exists.
            tracing::warn!("extract_realm_from_ra_cookie: falling back to nil realm");
            RealmId::new(uuid::Uuid::nil())
        })
}

fn now_unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_ra_cookie(headers: &HeaderMap) -> Option<String> {
    super::auth::cookie_value_from_headers(headers, ra_token::RA_SESSION_COOKIE).map(str::to_string)
}

fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

fn percent_encode_into(value: &str, out: &mut String) {
    use std::fmt::Write as _;
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_redirect_location(base: &str, params: &[(&str, &str)]) -> String {
        use std::fmt::Write as _;
        let mut out = base.to_string();
        let mut first = true;
        for (k, v) in params {
            if v.is_empty() {
                continue;
            }
            out.push(if first { '?' } else { '&' });
            first = false;
            for b in k.bytes() {
                match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        out.push(b as char);
                    }
                    _ => {
                        let _ = write!(out, "%{b:02X}");
                    }
                }
            }
            out.push('=');
            for b in v.bytes() {
                match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        out.push(b as char);
                    }
                    _ => {
                        let _ = write!(out, "%{b:02X}");
                    }
                }
            }
        }
        out
    }

    #[test]
    fn build_redirect_location_appends_params() {
        let loc = build_redirect_location(
            "https://app/cb",
            &[("code", "abc"), ("state", "xyz"), ("iss", "https://hearth")],
        );
        assert!(loc.starts_with("https://app/cb?code=abc&state=xyz&iss="));
    }

    #[test]
    fn build_redirect_location_skips_empty_values() {
        let loc = build_redirect_location("https://app/cb", &[("code", "abc"), ("state", "")]);
        assert_eq!(loc, "https://app/cb?code=abc");
    }

    #[test]
    fn action_label_maps_known_actions() {
        assert_eq!(action_label("VERIFY_EMAIL"), "Verify your email address");
        assert_eq!(action_label("UPDATE_PASSWORD"), "Update your password");
        assert_eq!(action_label("UNKNOWN"), "Complete required action");
    }
}
