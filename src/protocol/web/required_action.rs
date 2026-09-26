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
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{ClientId, RealmId, Timestamp, UserId};
use crate::identity::error::IdentityError;
use crate::identity::ra_token::{self, OidcParams};
use crate::identity::RequiredAction;
use crate::identity::{CleartextPassword, SessionContext, UpdateUserRequest};
use crate::protocol::web::auth::{issue_auth_cookies, IssuedCookies};

use super::authorize_gate::{refuse_if_silent, run_authorize_gates, AuthorizeParams, Gate};
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
    /// The password currently on the account. Verified before the replacement
    /// is applied (audit §4.23#2, task 21.3) so that possession of the RA
    /// cookie alone is not enough to take over the account.
    #[serde(default)]
    pub current_password: String,
    #[serde(default)]
    pub new_password: String,
    #[serde(default)]
    pub confirm_password: String,
    /// CSRF double-submit token, matched against the `hearth_ui_csrf` cookie.
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
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

/// The required-action gate of the authorization flow (see
/// `authorize_gate`): checks whether the authenticated user has pending
/// required actions before a code is issued.
///
/// Returns `Some(response)` when the flow must stop here — a redirect into
/// the first action, or an error — and the caller MUST return it. Returns
/// `None` when nothing is pending (AC-5: no-op path).
///
/// A lookup *error* is `Some(error)`, never `None`: reading a storage fault
/// as "no required actions" issued the code past a pending forced password
/// change or enrolment. A user that does not exist has no stored actions
/// (`None`); the code exchange refuses a missing user (`UserNotFound`).
///
/// A `prompt=none` request with pending actions is answered
/// `interaction_required` (OIDC Core §3.1.2.1) instead of being redirected
/// into an action page.
///
/// The parameters are embedded in the signed RA session JWT so the flow can
/// be resumed by [`resume_oidc_flow`] once all actions are complete.
pub(super) fn required_action_intercept(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    params: &AuthorizeParams,
    secure: bool,
    now: Timestamp,
) -> Option<Response> {
    let client_id = params.client_id.as_uuid().to_string();
    let mut actions = match pending_required_actions(state, realm, user_id, Some(&client_id)) {
        Ok(Some(actions)) => actions,
        Ok(None) => return None,
        Err(resp) => return Some(resp),
    };
    if actions.is_empty() {
        return None;
    }
    // `prompt=none`: the actions need the user, and no UI may be shown.
    if let Some(refusal) = refuse_if_silent(
        state,
        realm,
        user_id,
        params,
        "interaction_required",
        "user interaction required",
    ) {
        return Some(refusal);
    }

    // Sort by canonical priority so execution order is deterministic regardless
    // of how actions were stored.
    actions.sort_by_key(|a| a.priority());
    let first = actions[0];

    let token = match state.identity.generate_ra_token(
        realm,
        user_id,
        actions,
        params.to_oidc_params(),
        now,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "required_action_intercept: generate_ra_token failed");
            return Some(handlers_common::server_error());
        }
    };

    let cookie = ra_token::ra_session_cookie(&token, secure);
    let path = format!("/required-action/{}", first.as_path_segment());
    let mut response = Redirect::to(&path).into_response();
    append_cookie(&mut response, &cookie);
    Some(response)
}

/// The user's pending required actions: the stored list plus the
/// dynamically injected enrolment requirements.
///
/// * `Ok(None)` — the user does not exist, so nothing is stored for them.
///   Every caller's next step (session creation, code exchange) refuses a
///   missing user, so this is not the place to decide it.
/// * `Err(response)` — a lookup failed. The actions (or the realm's
///   enrolment requirements) are unknown, so the caller must refuse: reading
///   the fault as "nothing pending" skipped the actions.
fn pending_required_actions(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    client_id: Option<&str>,
) -> Result<Option<Vec<RequiredAction>>, Response> {
    let user = match state.identity.get_user(realm, user_id) {
        Ok(Some(u)) => u,
        Ok(None) => return Ok(None),
        Err(e) => {
            tracing::warn!(
                error = %e,
                realm_id = %realm.as_uuid(),
                "required actions: user lookup failed; refusing"
            );
            return Err(handlers_common::server_error());
        }
    };
    // The realm's enrolment requirements (SMS / email OTP / passkey) are read
    // from the realm record; an error there is equally unknown.
    let realm_config = match state.identity.get_realm(realm) {
        Ok(r) => r.map(|r| r.config().clone()),
        Err(e) => {
            tracing::warn!(
                error = %e,
                realm_id = %realm.as_uuid(),
                "required actions: realm lookup failed; refusing"
            );
            return Err(handlers_common::server_error());
        }
    };

    let mut actions: Vec<RequiredAction> = user.required_actions().to_vec();
    // Dynamic injection: SMS MFA enrollment if realm requires it.
    inject_enroll_phone_otp_if_needed(
        state,
        realm,
        user_id,
        &user,
        realm_config.as_ref(),
        &mut actions,
    );
    // Dynamic injection: Email OTP enrollment if realm requires it.
    inject_enroll_email_otp_if_needed(
        state,
        realm,
        user_id,
        &user,
        realm_config.as_ref(),
        &mut actions,
    );
    // Dynamic injection: TOTP/MFA enrollment if the client (OIDC only) or a
    // role requires it.
    // An unknown requirement refuses, like the lookups above.
    inject_enroll_mfa_if_needed(
        state,
        realm,
        user_id,
        realm_config.as_ref(),
        client_id,
        &mut actions,
    )
    .map_err(|()| handlers_common::server_error())?;
    Ok(Some(actions))
}

/// Checks whether the authenticating user has pending required actions for
/// the **direct browser login path** (not OIDC).
///
/// Returns `Some(redirect_response)` when actions are pending — the caller
/// MUST return this response immediately instead of creating a session.
/// Returns `None` when no actions are pending and the login can proceed.
/// A user or realm lookup error returns `Some(error)`: it is never read as
/// "nothing pending". A user that does not exist returns `None`;
/// `create_session` refuses it (`UserNotFound`).
///
/// Unlike the OIDC intercept, this generates an RA token without
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
    // No client on the direct browser login path; client-level MFA
    // enforcement is OIDC-only. A lookup error refuses (see
    // `pending_required_actions`).
    let mut actions = match pending_required_actions(state, realm, user_id, None) {
        Ok(Some(actions)) => actions,
        Ok(None) => return None,
        Err(resp) => return Some(resp),
    };

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

    // The MFA proof is inherited: the RA session cookie backing this call is
    // only minted by `required_action_check_browser`, which the login and MFA
    // challenge handlers call *after* the realm's `mfa_required` gate has been
    // satisfied (audit 2026-08-28 §4.18#3).
    let ctx = SessionContext {
        mfa_proof: crate::identity::MfaProof::Inherited,
        ..SessionContext::default()
    };
    let session = match state.identity.create_session(realm, &user_id, &ctx) {
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

/// Clears the RA cookie and resumes the authorization after the last
/// required action.
///
/// Reconstructs the original request from the signed `RaClaims` and
/// re-enters the shared gate sequence (`authorize_gate`) at the gate after
/// this one: the SMS MFA challenge, then consent / `prompt`, then issuance.
/// This used to issue the code directly — skipping the SMS factor (fixed
/// earlier) and the consent prompt, so any request that detoured through a
/// required action got a code for a client the user never approved.
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
    let user_id = UserId::new(user_uuid);
    // Server-signed state built from validated parameters: a value that does
    // not parse is an internal fault, refused rather than defaulted.
    let Some(params) = AuthorizeParams::from_oidc_params(&oidc_params) else {
        tracing::warn!("resume_oidc_flow: RA session carries unparseable OIDC params");
        return handlers_common::server_error();
    };

    let mut response = run_authorize_gates(
        state,
        realm,
        &user_id,
        &params,
        Gate::SmsMfa,
        Vec::new(),
        secure,
        Timestamp::from_micros(now_micros()),
    );
    append_cookie(&mut response, &clear_cookie);
    response
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
    realm_config: Option<&crate::identity::RealmConfig>,
    actions: &mut Vec<RequiredAction>,
) {
    if user.phone_verified() {
        return;
    }
    if actions.contains(&RequiredAction::EnrollPhoneOtp) {
        return;
    }
    let sms_required = realm_config
        .and_then(|c| c.mfa_methods.as_ref())
        .is_some_and(|methods| methods.iter().any(|m| m == "sms"));

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

/// Dynamically injects `ENROLL_EMAIL_OTP` when a realm requires email OTP MFA
/// and the user has not yet enrolled email OTP.
///
/// Persists the action to the user record. Idempotent: no-op if already present
/// or not applicable.
fn inject_enroll_email_otp_if_needed(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    user: &crate::identity::User,
    realm_config: Option<&crate::identity::RealmConfig>,
    actions: &mut Vec<RequiredAction>,
) {
    if user.email_otp_enabled() {
        return;
    }
    if actions.contains(&RequiredAction::EnrollEmailOtp) {
        return;
    }
    let email_otp_required = realm_config
        .and_then(|c| c.mfa_methods.as_ref())
        .is_some_and(|methods| methods.iter().any(|m| m == "email_otp"));

    if !email_otp_required {
        return;
    }

    actions.push(RequiredAction::EnrollEmailOtp);

    let mut persisted = user.required_actions().to_vec();
    if !persisted.contains(&RequiredAction::EnrollEmailOtp) {
        persisted.push(RequiredAction::EnrollEmailOtp);
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
                "inject_enroll_email_otp_if_needed: failed to persist ENROLL_EMAIL_OTP"
            );
        }
    }
}

/// Whether a realm-level passkey requirement is unmet for this user.
///
/// Split out from [`inject_enroll_mfa_if_needed`] so the rule is testable
/// without a live `WebState`. A TOTP secret deliberately does **not** satisfy
/// `webauthn_required`: the key names a passkey, and an operator who sets it
/// after a phishing incident is asking for a phishing-resistant factor
/// specifically (audit §4.18#9).
const fn enroll_mfa_needed(realm_requires_passkey: bool, has_passkeys: bool) -> bool {
    realm_requires_passkey && !has_passkeys
}

/// Dynamically injects `ENROLL_MFA` when a client-level or role-level MFA
/// requirement is in effect and the user has no enrolled MFA factor.
///
/// Idempotent: no-op if the user already has TOTP enabled, a registered
/// passkey, or if `EnrollMfa` is already in the pending actions list.
/// Does NOT persist the injected action — it is re-evaluated on every
/// authorize request because the condition is external (client config / roles).
///
/// `Err(())` when a lookup the decision depends on fails (the factor list,
/// the client record, the user's role assignments or a role): the
/// requirement is then unknown and the caller refuses. Each of these used to
/// read an error as "no requirement", so a transient client-store or RBAC
/// fault issued the code without the enrolment the client or the user's
/// role mandates. A client or role that does not exist imposes nothing.
fn inject_enroll_mfa_if_needed(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    realm_config: Option<&crate::identity::RealmConfig>,
    client_id_str: Option<&str>,
    actions: &mut Vec<RequiredAction>,
) -> Result<(), ()> {
    if actions.contains(&RequiredAction::EnrollMfa) {
        return Ok(());
    }
    let refuse = |what: &str, e: &dyn std::fmt::Display| {
        tracing::warn!(
            error = %e,
            realm_id = %realm.as_uuid(),
            lookup = what,
            "required actions: MFA-requirement lookup failed; refusing"
        );
    };

    // User with TOTP or passkeys already satisfies any MFA requirement.
    let has_totp = state
        .identity
        .mfa_enabled(realm, user_id)
        .map_err(|e| refuse("totp", &e))?;
    let has_passkeys = !state
        .identity
        .list_webauthn_credentials(realm, user_id)
        .map_err(|e| refuse("passkeys", &e))?
        .is_empty();

    // §4.18#9: `realms.<name>.auth.webauthn_required` was dead code — the
    // field existed on `RealmConfig`, was hard-coded to `None` by
    // `to_realm_config`, and nothing read it. It is a *passkey* requirement,
    // so TOTP does not satisfy it and it must be evaluated before the
    // "any factor will do" short-circuit below.
    let realm_requires_passkey = realm_config
        .and_then(|c| c.webauthn_required)
        .unwrap_or(false);
    if enroll_mfa_needed(realm_requires_passkey, has_passkeys) {
        actions.push(RequiredAction::EnrollMfa);
        return Ok(());
    }

    if has_totp || has_passkeys {
        return Ok(());
    }

    // Per-client requirement.
    let client_requires_mfa = match client_id_str
        .and_then(|cid| uuid::Uuid::parse_str(cid).ok())
        .map(ClientId::new)
    {
        Some(cid) => state
            .identity
            .get_client(realm, &cid)
            .map_err(|e| refuse("client", &e))?
            .and_then(|c| c.mfa_required())
            .unwrap_or(false),
        None => false,
    };

    // Per-role requirement: any role the user holds that appears in
    // `realm.config.mfa_required_roles` triggers enforcement.
    let required_roles = realm_config
        .and_then(|c| c.mfa_required_roles.as_deref())
        .unwrap_or_default();
    let mut role_requires_mfa = false;
    if !client_requires_mfa && !required_roles.is_empty() {
        let assignments = state
            .rbac
            .list_user_assignments(realm, user_id)
            .map_err(|e| refuse("role assignments", &e))?;
        for assignment in &assignments {
            let role = state
                .rbac
                .get_role(realm, &assignment.role_id)
                .map_err(|e| refuse("role", &e))?;
            if role.is_some_and(|r| required_roles.iter().any(|req| req == &r.name)) {
                role_requires_mfa = true;
                break;
            }
        }
    }

    if client_requires_mfa || role_requires_mfa {
        actions.push(RequiredAction::EnrollMfa);
    }
    Ok(())
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
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
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
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
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
///
/// Issues (or re-uses) the `hearth_ui_csrf` double-submit cookie and embeds its
/// value as the form's `_csrf` field, so the POST handler can verify it
/// (task 21.3). Mirrors the pre-auth login form, which is the other `/ui` form
/// rendered without a `UiSession`.
pub async fn update_password_page(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    if read_ra_cookie(&headers).is_none() {
        return handlers_common::bad_request("No active required-action session");
    }
    let secure = state.is_secure_request(&headers);
    let (csrf_value, fresh_cookie) = match super::auth::csrf_cookie_value_from_headers(&headers) {
        Some(existing) => (existing.to_string(), None),
        None => {
            let (val, cookie) = super::auth::fresh_csrf_cookie(secure);
            (val, Some(cookie))
        }
    };
    let mut resp = render_update_password_form(&state, None, Some(csrf_value));
    if let Some(cookie) = fresh_cookie {
        append_cookie(&mut resp, &cookie);
    }
    resp
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
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
pub async fn update_password_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<UpdatePasswordForm>,
) -> Response {
    // CSRF double-submit (audit §4.23#2, task 21.3). The RA cookie is
    // `SameSite=Strict`, but `SameSite` is a browser-version-dependent
    // mitigation, not a control — a cross-site POST that rides an existing RA
    // session must be refused on its own merits. Fail-closed in production;
    // `--dev` keeps the bypass so direct-POST tooling still works, exactly as
    // `login_submit_impl` does.
    let secure = state.is_secure_request(&headers);
    let csrf_ok = match super::auth::csrf_cookie_value_from_headers(&headers) {
        Some(cookie_val) => super::auth::csrf_token_eq(cookie_val, &form.csrf),
        None => state.dev_mode,
    };
    if !csrf_ok {
        return update_password_csrf_failure(&state, secure);
    }

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
    let csrf_echo = Some(form.csrf.clone());

    if form.new_password != form.confirm_password {
        return render_update_password_form(
            &state,
            Some("New password and confirmation do not match."),
            csrf_echo,
        );
    }

    // Prove possession of the *current* password before replacing it
    // (audit §4.23#2). Without this, anyone who can drive one POST with the RA
    // cookie attached owns the account. `change_password` verifies the old
    // credential and applies the new one; both are Argon2id operations, so the
    // pair runs through the shared KDF admission gate rather than inline on the
    // async worker.
    let current = CleartextPassword::from_string(form.current_password);
    let new_pw = CleartextPassword::from_string(form.new_password);
    let identity = state.identity.clone();
    let realm_for_kdf = realm.clone();
    let user_for_kdf = user_id.clone();
    let change_result = match crate::identity::gate()
        .run(move || {
            match identity.change_password(&realm_for_kdf, &user_for_kdf, &current, &new_pw) {
                // A user with no password credential at all (federated or
                // passkey-only, forced to set one) has no "current password"
                // to prove. There is nothing to bypass in that case, so fall
                // through to a plain set.
                Err(IdentityError::CredentialNotFound) => {
                    identity.set_password(&realm_for_kdf, &user_for_kdf, &new_pw)
                }
                other => other,
            }
        })
        .await
    {
        Ok(r) => r,
        Err(crate::identity::KdfGateError::Overloaded { retry_after }) => {
            return super::handlers::kdf_shed_html_response(
                &state,
                &headers,
                retry_after,
                None,
                None,
                None,
            );
        }
        Err(crate::identity::KdfGateError::Join(e)) => {
            tracing::warn!(error = %e, "update_password_submit: KDF task panicked");
            return render_update_password_form(
                &state,
                Some("Unable to update password. Please try again."),
                csrf_echo,
            );
        }
    };

    match change_result {
        Ok(()) => {}
        Err(IdentityError::InvalidCredential { .. }) => {
            return render_update_password_form(
                &state,
                Some("Current password is incorrect."),
                csrf_echo,
            );
        }
        Err(IdentityError::InvalidInput { reason }) => {
            return render_update_password_form(&state, Some(&reason), csrf_echo);
        }
        Err(IdentityError::PasswordReused) => {
            return render_update_password_form(
                &state,
                Some("That password was used recently — choose a different one."),
                csrf_echo,
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "update_password_submit: change_password failed");
            return render_update_password_form(
                &state,
                Some("Unable to update password. Please try again."),
                csrf_echo,
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

fn update_password_template(
    state: &Arc<WebState>,
    error: Option<&str>,
    csrf: Option<String>,
) -> UpdatePasswordPageTemplate {
    UpdatePasswordPageTemplate {
        error: error.map(str::to_string),
        chrome: false,
        active: "",
        user_email: None,
        is_admin: false,
        narrow: true,
        flash: None,
        csrf,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    }
}

fn render_update_password_form(
    state: &Arc<WebState>,
    error: Option<&str>,
    csrf: Option<String>,
) -> Response {
    render(&update_password_template(state, error, csrf))
}

/// 403 response for a failed CSRF double-submit on the update-password form.
///
/// Re-renders the form (with a fresh token the browser can actually use) rather
/// than a bare error page, so a user whose token expired mid-flow can retry.
fn update_password_csrf_failure(state: &Arc<WebState>, secure: bool) -> Response {
    let (csrf_value, cookie) = super::auth::fresh_csrf_cookie(secure);
    let tmpl = update_password_template(
        state,
        Some("Your session expired. Please try again."),
        Some(csrf_value),
    );
    let mut resp = super::templates::render_status(&tmpl, StatusCode::FORBIDDEN);
    append_cookie(&mut resp, &cookie);
    resp
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
    // Verify the RA session token, exactly as the email twin does — cookie
    // presence alone proves nothing (audit 2026-08-28 §4.19#7).
    if let Err(response) = validated_ra_session(&state, &headers) {
        return response;
    }
    render_enroll_phone_page(&state, None)
}

/// Verifies the RA session cookie and returns its realm and claims.
///
/// The realm is read from the payload only to select the verification key; the
/// signature is checked under that realm's key immediately afterwards, so a
/// caller cannot name a realm it does not hold a token for
/// (audit 2026-08-28 §4.19#7).
fn validated_ra_session(
    state: &Arc<WebState>,
    headers: &HeaderMap,
) -> Result<(RealmId, ra_token::RaClaims), Response> {
    let Some(token) = read_ra_cookie(headers) else {
        return Err(handlers_common::bad_request(
            "No active required-action session",
        ));
    };
    let Some(realm_str) = ra_token::extract_realm_unchecked(&token) else {
        return Err(handlers_common::bad_request("Malformed RA session token"));
    };
    let Ok(realm_uuid) = uuid::Uuid::parse_str(&realm_str) else {
        return Err(handlers_common::bad_request(
            "Malformed realm in RA session token",
        ));
    };
    let realm = RealmId::new(realm_uuid);
    let now = Timestamp::from_micros(now_micros());
    match state.identity.validate_ra_token(&realm, &token, now) {
        Ok(claims) => Ok((realm, claims)),
        Err(ra_token::RaTokenError::Expired) => Err(Redirect::to("/").into_response()),
        Err(_) => Err(handlers_common::bad_request(
            "Invalid required-action session token",
        )),
    }
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
    // Verify the RA session token before doing anything that costs the realm
    // money: the realm below comes from the verified token, not from the
    // unauthenticated payload (audit 2026-08-28 §4.19#7).
    let realm = match validated_ra_session(&state, &headers) {
        Ok((realm, _claims)) => realm,
        Err(response) => return response,
    };

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

    let Some(hmac_key) = sms_otp_hmac_key_bytes(&state) else {
        return render_enroll_phone_page(
            &state,
            Some("SMS delivery is not configured. Contact your administrator."),
        );
    };
    let now_ts = now_unix_ts();

    let nonce = match state.identity.issue_sms_otp(
        &realm,
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
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
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
    // 22.4 (audit 2026-08-28 §4.4#2): a phone that fails E.164 validation must
    // not be echoed back into the verify page — that page masks it, and the
    // masking used to index raw bytes. `mask_phone` is total now, but this
    // layer still validates its own input rather than trusting the form: an
    // unparsed number has nothing to mask, so send the user back to the entry
    // page instead of rendering a masked view of junk.
    if !is_e164(&phone) {
        return render_enroll_phone_page(&state, Some("Invalid submission."));
    }
    if form.nonce.is_empty() || form.code.is_empty() {
        return render_enroll_phone_verify(
            &state,
            &phone,
            Some(&form.nonce),
            Some("Invalid submission."),
        );
    }

    let Some(hmac_key) = sms_otp_hmac_key_bytes(&state) else {
        return render_enroll_phone_page(
            &state,
            Some("SMS delivery is not configured. Contact your administrator."),
        );
    };
    let now_ts = now_unix_ts();

    match state
        .identity
        // Bound to the submitted number: a code sent to one phone must not
        // mark a different one verified.
        .verify_sms_otp(&realm, &form.nonce, &phone, &form.code, &hmac_key, now_ts)
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
/// E.g. `"+15555550100"` → `"+1••••••0100"`.
///
/// 22.4 (audit 2026-08-28 §4.4#2): this used to index `phone` by **byte**
/// offset in three places — `phone[phone.len() - 4..]`, `phone[..prefix_end]`,
/// and a `phone.len() - prefix_end - 4` width that could underflow. Any of the
/// three panicked the handler on input that was not pure ASCII (a multi-byte
/// character landing across a slice boundary) or that had no digit in the first
/// few characters. The function is now total for every `&str`: it works on
/// `char`s and clamps the prefix so the dot count can never go negative.
fn mask_phone(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    if chars.len() <= 5 {
        return phone.to_string();
    }
    let suffix_start = chars.len() - 4;
    // Country code = everything up to and including the first ASCII digit
    // (e.g. "+1"), clamped so it can never overlap the visible suffix.
    let prefix_end = chars
        .iter()
        .position(char::is_ascii_digit)
        .unwrap_or(1)
        .saturating_add(1)
        .min(suffix_start);
    let country_code: String = chars[..prefix_end].iter().collect();
    let visible_suffix: String = chars[suffix_start..].iter().collect();
    let dots = "•".repeat(suffix_start - prefix_end);
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

/// Returns the HMAC key bytes to use for SMS OTP operations, or `None` when
/// no key is loaded.
///
/// There is deliberately no fallback. This used to substitute an all-zero
/// 32-byte key whenever `HEARTH_SMS_OTP_HMAC_KEY` was unset (the `log`
/// transport), which made every stored OTP digest brute-forceable by anyone
/// who could read storage. Every caller now treats `None` as "SMS OTP is
/// unavailable" and fails closed: no code is issued and nothing verifies.
///
/// Startup always loads a key for a real SMS transport, and generates a random
/// per-process key in dev mode, so `None` means a production `log` transport.
pub(super) fn sms_otp_hmac_key_bytes(state: &Arc<WebState>) -> Option<Vec<u8>> {
    let key = state.sms_otp_hmac_key.clone();
    if key.is_none() {
        tracing::warn!(
            "SMS OTP refused: no HEARTH_SMS_OTP_HMAC_KEY is loaded, so no code can be \
             issued or verified (configure a real sms.transport and the key)"
        );
    }
    key
}

/// Returns the current Unix timestamp in whole seconds.
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

// ---------------------------------------------------------------------------
// GET/POST /required-action/ENROLL_EMAIL_OTP
// ---------------------------------------------------------------------------

/// Rendered by `GET /required-action/ENROLL_EMAIL_OTP`.
#[derive(Template)]
#[template(path = "ui/required_action/enroll_email_otp.html")]
struct EnrollEmailOtpPageTemplate {
    /// Masked display of the user's email (e.g. `a***@example.com`).
    masked_email: String,
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

/// Rendered by `POST /required-action/ENROLL_EMAIL_OTP/send` on success.
#[derive(Template)]
#[template(path = "ui/required_action/enroll_email_otp_verify.html")]
struct EnrollEmailOtpVerifyTemplate {
    /// Masked display of the email.
    masked_email: String,
    /// Opaque nonce returned by `issue_email_otp`; `None` in rate-limited renders.
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

/// `application/x-www-form-urlencoded` body for `POST /required-action/ENROLL_EMAIL_OTP/verify`.
#[derive(Debug, Deserialize)]
pub struct EnrollEmailOtpVerifyForm {
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub code: String,
}

/// Renders the landing page for email OTP enrollment. Loads the user's email
/// from the RA token subject and shows a "Send code to my email" button.
pub async fn enroll_email_otp_page(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
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
    let Ok(claims) = state.identity.validate_ra_token(&realm, &token, now) else {
        return Redirect::to("/").into_response();
    };
    let Ok(user_uuid) = uuid::Uuid::parse_str(&claims.sub) else {
        return handlers_common::server_error();
    };
    let user_id = UserId::new(user_uuid);
    let email = state
        .identity
        .get_user(&realm, &user_id)
        .ok()
        .flatten()
        .map(|u| u.email().to_string())
        .unwrap_or_default();
    render_enroll_email_otp_page(&state, &email, None)
}

/// Sends an email OTP to the user's registered email address and renders
/// the code-entry form.
pub async fn enroll_email_otp_send(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
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
    let Ok(claims) = state.identity.validate_ra_token(&realm, &token, now) else {
        return Redirect::to("/").into_response();
    };
    let Ok(user_uuid) = uuid::Uuid::parse_str(&claims.sub) else {
        return handlers_common::server_error();
    };
    let user_id = UserId::new(user_uuid);

    let email = match state.identity.get_user(&realm, &user_id) {
        Ok(Some(u)) => u.email().to_string(),
        _ => {
            return handlers_common::server_error();
        }
    };

    let Some(email_service) = state.email.as_ref() else {
        tracing::warn!("enroll_email_otp_send: email transport not configured");
        return render_enroll_email_otp_page(
            &state,
            &email,
            Some("Email delivery is not configured. Contact your administrator."),
        );
    };

    let hmac_key = email_otp_hmac_key_bytes(&state);
    let now_ts = now_unix_ts();

    match state
        .identity
        .issue_email_otp(&realm, &email, &hmac_key, email_service, None, now_ts)
    {
        Ok(nonce) => render_enroll_email_otp_verify(&state, &email, Some(&nonce), None),
        Err(e) => {
            tracing::warn!(error = %e, "enroll_email_otp_send: issue_email_otp failed");
            render_enroll_email_otp_page(
                &state,
                &email,
                Some("Failed to send verification code. Please try again."),
            )
        }
    }
}

/// Verifies the submitted OTP code, sets `email_otp_enabled = true`, clears
/// `ENROLL_EMAIL_OTP` from the user's required actions, and advances the flow.
#[allow(clippy::too_many_lines)]
pub async fn enroll_email_otp_verify_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<EnrollEmailOtpVerifyForm>,
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

    let email = match state.identity.get_user(&realm, &user_id) {
        Ok(Some(u)) => u.email().to_string(),
        _ => return handlers_common::server_error(),
    };

    if form.nonce.is_empty() || form.code.is_empty() {
        return render_enroll_email_otp_verify(
            &state,
            &email,
            Some(&form.nonce),
            Some("Invalid submission."),
        );
    }

    let hmac_key = email_otp_hmac_key_bytes(&state);
    let now_ts = now_unix_ts();

    match state.identity.verify_email_otp(
        &realm,
        &form.nonce,
        &email,
        &form.code,
        &hmac_key,
        now_ts,
    ) {
        Ok(()) => {}
        Err(_) => {
            return render_enroll_email_otp_verify(
                &state,
                &email,
                Some(&form.nonce),
                Some("That code is incorrect or has expired. Try again or request a new code."),
            );
        }
    }

    // OTP verified — set email_otp_enabled and clear ENROLL_EMAIL_OTP.
    let updated_actions: Vec<RequiredAction> = claims
        .pending_actions
        .iter()
        .filter(|&&a| a != RequiredAction::EnrollEmailOtp)
        .copied()
        .collect();

    if let Err(e) = state.identity.update_user(
        &realm,
        &user_id,
        &UpdateUserRequest {
            email_otp_enabled: Some(true),
            required_actions: Some(updated_actions.clone()),
            ..Default::default()
        },
    ) {
        tracing::warn!(error = %e, "enroll_email_otp_verify_submit: update_user failed");
        return handlers_common::server_error();
    }

    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: user_id.as_uuid().to_string(),
        action: AuditAction::RequiredActionCompleted,
        resource_type: "user".to_string(),
        resource_id: user_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "action_type": "ENROLL_EMAIL_OTP" })),
    }) {
        tracing::warn!(error = %e, "enroll_email_otp_verify_submit: audit append failed");
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

fn render_enroll_email_otp_page(
    state: &Arc<WebState>,
    email: &str,
    error: Option<&str>,
) -> Response {
    let tmpl = EnrollEmailOtpPageTemplate {
        masked_email: mask_email(email),
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

fn render_enroll_email_otp_verify(
    state: &Arc<WebState>,
    email: &str,
    nonce: Option<&str>,
    error: Option<&str>,
) -> Response {
    let tmpl = EnrollEmailOtpVerifyTemplate {
        masked_email: mask_email(email),
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

/// Masks an email address for display: shows the first character, then
/// `***`, then the domain. E.g. `alice@example.com` → `a***@example.com`.
fn mask_email(email: &str) -> String {
    if let Some((local, domain)) = email.split_once('@') {
        let first = local.chars().next().unwrap_or('*');
        format!("{first}***@{domain}")
    } else {
        "***".to_string()
    }
}

/// Returns the HMAC key bytes to use for email OTP operations.
///
/// Always a secret key — see [`derive_email_otp_hmac_key`]. This used to fall
/// back to the public constant `hearth-dev-email-otp-key-not-for-production`
/// whenever no SMS OTP key was loaded, which is every production deployment
/// on the `log` SMS transport: each stored email OTP digest was then keyed
/// with a value anyone could read in the source, and so brute-forceable
/// offline in about 10^6 HMACs.
pub(super) fn email_otp_hmac_key_bytes(state: &Arc<WebState>) -> Vec<u8> {
    derive_email_otp_hmac_key(
        state.sms_otp_hmac_key.as_deref(),
        super::auth::cookie_secret_bytes(&state.cookie_secret),
    )
}

/// Domain-separation label for [`derive_email_otp_hmac_key`].
const EMAIL_OTP_KEY_LABEL: &[u8] = b"hearth/email-otp-hmac-key/v1";

/// Derives the email OTP HMAC key: `HMAC-SHA256(base, label)`.
///
/// `base` is the operator's `HEARTH_SMS_OTP_HMAC_KEY` when one is loaded (it is
/// stable across restarts and shared by every node), otherwise the process's
/// random cookie secret. The cookie secret already bounds the email OTP login
/// flow — the MFA pending cookie is MAC'd with it — so a code issued under it
/// lives exactly as long, and on exactly the node, as the login it belongs to.
/// The label keeps the derived key distinct from the key it came from.
fn derive_email_otp_hmac_key(sms_key: Option<&[u8]>, cookie_secret: &[u8]) -> Vec<u8> {
    let base = sms_key.unwrap_or(cookie_secret);
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, base);
    ring::hmac::sign(&key, EMAIL_OTP_KEY_LABEL)
        .as_ref()
        .to_vec()
}

// ---------------------------------------------------------------------------
// GET + POST /required-action/enroll-mfa
// ---------------------------------------------------------------------------

/// Rendered by `GET /required-action/enroll-mfa`.
#[derive(Template)]
#[template(path = "ui/required_action/enroll_mfa.html")]
struct EnrollMfaPageTemplate {
    error: Option<String>,
    secret_base32: String,
    provisioning_uri: String,
    qr_svg: String,
    recovery_codes: Vec<String>,
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

/// `application/x-www-form-urlencoded` body for `POST /required-action/enroll-mfa`.
#[derive(Debug, Deserialize)]
pub struct EnrollMfaForm {
    #[serde(default)]
    pub code: String,
}

/// Initiates TOTP enrollment for the `EnrollMfa` required action.
///
/// Reads the RA session cookie to identify the user, calls `enroll_totp` to
/// generate a fresh TOTP secret, and renders the QR code + recovery codes.
/// Each GET generates a new pending enrollment (idempotent from the user's
/// perspective; the previous pending secret is overwritten).
pub async fn enroll_mfa_page(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    let Some(token_str) = read_ra_cookie(&headers) else {
        return handlers_common::bad_request("No active required-action session");
    };

    let Some(realm_str) = ra_token::extract_realm_unchecked(&token_str) else {
        return handlers_common::bad_request("Malformed RA session token");
    };
    let Ok(realm_uuid) = uuid::Uuid::parse_str(&realm_str) else {
        return handlers_common::bad_request("Malformed realm in RA session token");
    };
    let realm = RealmId::new(realm_uuid);

    let now = Timestamp::from_micros(now_micros());
    let claims = match state.identity.validate_ra_token(&realm, &token_str, now) {
        Ok(c) => c,
        Err(ra_token::RaTokenError::Expired) => {
            return handlers_common::bad_request("Required-action session has expired");
        }
        Err(_) => {
            return handlers_common::bad_request("Invalid required-action session token");
        }
    };

    let Ok(user_uuid) = uuid::Uuid::parse_str(&claims.sub) else {
        return handlers_common::server_error();
    };
    let user_id = UserId::new(user_uuid);
    let identity = state.identity.clone();

    let enroll_result = tokio::task::spawn_blocking(move || identity.enroll_totp(&realm, &user_id))
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "enroll_mfa_page: enroll_totp panicked");
            Err(IdentityError::Storage(Box::new(e)))
        });

    match enroll_result {
        Ok(enrollment) => {
            let qr_svg = super::account::generate_qr_svg(&enrollment.provisioning_uri);
            let tmpl = EnrollMfaPageTemplate {
                error: None,
                secret_base32: enrollment.secret_base32,
                provisioning_uri: enrollment.provisioning_uri,
                qr_svg,
                recovery_codes: enrollment.recovery_codes.as_slice().to_vec(),
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
            super::templates::render(&tmpl)
        }
        Err(IdentityError::MfaAlreadyEnabled) => {
            // Already enrolled — skip this action automatically by redirecting
            // to the generic action_complete path.
            Redirect::to("/required-action/enroll-mfa").into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "enroll_mfa_page: enroll_totp failed");
            let tmpl = EnrollMfaPageTemplate {
                error: Some("Unable to start MFA enrollment. Please try again.".to_string()),
                secret_base32: String::new(),
                provisioning_uri: String::new(),
                qr_svg: String::new(),
                recovery_codes: Vec::new(),
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
            super::templates::render_status(&tmpl, StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Verifies the TOTP code from the enrollment form and advances the RA flow.
///
/// On success the `EnrollMfa` action is removed from the RA token and the flow
/// either advances to the next action or resumes OIDC / browser flow.
#[allow(clippy::too_many_lines)]
pub async fn enroll_mfa_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<EnrollMfaForm>,
) -> Response {
    let Some(token_str) = read_ra_cookie(&headers) else {
        return handlers_common::bad_request("No active required-action session");
    };

    let Some(realm_str) = ra_token::extract_realm_unchecked(&token_str) else {
        return handlers_common::bad_request("Malformed RA session token");
    };
    let Ok(realm_uuid) = uuid::Uuid::parse_str(&realm_str) else {
        return handlers_common::bad_request("Malformed realm in RA session token");
    };
    let realm = RealmId::new(realm_uuid);

    let now = Timestamp::from_micros(now_micros());
    let claims = match state.identity.validate_ra_token(&realm, &token_str, now) {
        Ok(c) => c,
        Err(ra_token::RaTokenError::Expired) => {
            return handlers_common::bad_request("Required-action session has expired");
        }
        Err(_) => {
            return handlers_common::bad_request("Invalid required-action session token");
        }
    };

    let Ok(user_uuid) = uuid::Uuid::parse_str(&claims.sub) else {
        return handlers_common::server_error();
    };
    let user_id = UserId::new(user_uuid);
    let realm_clone = realm.clone();
    let user_id_clone = user_id.clone();
    let code = form.code.trim().to_string();
    let identity = state.identity.clone();

    let verify_result = tokio::task::spawn_blocking(move || {
        identity.verify_totp_enrollment(&realm_clone, &user_id_clone, &code)
    })
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, "enroll_mfa_submit: verify_totp_enrollment panicked");
        Err(IdentityError::Storage(Box::new(e)))
    });

    let render_error = |msg: &str| {
        let tmpl = EnrollMfaPageTemplate {
            error: Some(msg.to_string()),
            secret_base32: String::new(),
            provisioning_uri: String::new(),
            qr_svg: String::new(),
            recovery_codes: Vec::new(),
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
        super::templates::render_status(&tmpl, StatusCode::UNPROCESSABLE_ENTITY)
    };

    match verify_result {
        Err(IdentityError::InvalidMfaCode) => {
            return render_error("Invalid code. Please re-scan the QR code and try again.");
        }
        Err(IdentityError::MfaNotEnabled) => {
            return Redirect::to("/required-action/enroll-mfa").into_response();
        }
        Err(e) => {
            tracing::warn!(error = %e, "enroll_mfa_submit: verify_totp_enrollment failed");
            return render_error("Unable to verify the code. Please try again.");
        }
        Ok(()) => {}
    }

    // Enrollment confirmed — advance the RA flow (remove EnrollMfa from pending).
    let secure = state.is_secure_request(&headers);
    let remaining: Vec<RequiredAction> = claims
        .pending_actions
        .into_iter()
        .filter(|a| *a != RequiredAction::EnrollMfa)
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

    // ===== realms.<name>.auth.webauthn_required (audit §4.18#9) =====

    /// A realm that requires a passkey must intercept a user who has none.
    #[test]
    fn webauthn_required_realm_injects_enroll_mfa_when_no_passkey() {
        assert!(
            enroll_mfa_needed(true, false),
            "webauthn_required with no registered passkey must force enrolment"
        );
    }

    /// Once the passkey exists the requirement is satisfied and the user is
    /// not intercepted again.
    #[test]
    fn webauthn_required_realm_is_satisfied_by_a_passkey() {
        assert!(!enroll_mfa_needed(true, true));
    }

    /// A realm that does not set the key keeps the previous behaviour: the
    /// client-level and role-level rules below decide, not this one.
    #[test]
    fn webauthn_not_required_never_forces_enrolment_on_its_own() {
        assert!(!enroll_mfa_needed(false, false));
        assert!(!enroll_mfa_needed(false, true));
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

#[cfg(test)]
mod mask_phone_tests {
    use super::{is_e164, mask_phone};

    /// The documented happy path still masks exactly as before.
    #[test]
    fn masks_an_e164_number_keeping_country_code_and_last_four() {
        assert_eq!(mask_phone("+15555550100"), "+1••••••0100");
        assert_eq!(mask_phone("+442071838750"), "+4•••••••8750");
    }

    /// Short inputs pass through untouched (no suffix to preserve).
    #[test]
    fn short_input_passes_through() {
        assert_eq!(mask_phone(""), "");
        assert_eq!(mask_phone("+1234"), "+1234");
        assert_eq!(mask_phone("+1"), "+1");
    }

    /// 22.4 (§4.4#2): the three byte-slicing panics.
    ///
    /// Each of these strings made the old implementation abort the handler:
    /// a multi-byte char across the `len() - 4` suffix boundary, a multi-byte
    /// char under the `[..prefix_end]` country-code slice, and a digit far
    /// enough in that `len() - prefix_end - 4` underflowed.
    #[test]
    fn multibyte_and_digitless_input_does_not_panic() {
        for input in [
            "+1555555€",       // multi-byte char inside the 4-char suffix
            "€€€€€€€€",        // every char multi-byte, no ASCII digit at all
            "++++++9",         // first digit at index 6 ⇒ prefix_end 7 > len - 4
            "+🔥🔥🔥🔥🔥1234", // emoji (4-byte) before the digits
            "ありがとう1234",  // no leading '+', multi-byte prefix
            "+++++++++",       // no digit anywhere, all ASCII
        ] {
            let masked = mask_phone(input);
            // Total, and it never invents characters it was not given.
            assert!(
                !masked.is_empty(),
                "mask_phone({input:?}) returned empty string"
            );
        }
    }

    /// The masked form never leaks more than the last four characters.
    #[test]
    fn masked_form_hides_the_middle() {
        let masked = mask_phone("+15555550100");
        assert!(!masked.contains("555555"), "middle digits leaked: {masked}");
        assert!(masked.ends_with("0100"), "suffix missing: {masked}");
    }

    /// The entry-point guard that keeps unvalidated input away from the
    /// masking view in the first place (22.4, second half).
    #[test]
    fn e164_validator_rejects_the_panic_inputs() {
        for input in ["+1555555€", "€€€€€€€€", "++++++9", "ありがとう1234"] {
            assert!(!is_e164(input), "is_e164 accepted {input:?}");
        }
        assert!(is_e164("+15555550100"));
    }
}

#[cfg(test)]
mod email_otp_key_tests {
    use super::derive_email_otp_hmac_key;

    /// The constant this used to fall back to whenever no SMS OTP key was
    /// loaded — i.e. every production deployment on the `log` SMS transport.
    /// It is in the public source, so every digest keyed with it could be
    /// brute-forced offline (10^6 HMACs) by anyone who could read storage.
    const OLD_PUBLIC_KEY: &[u8] = b"hearth-dev-email-otp-key-not-for-production";

    #[test]
    fn no_sms_key_derives_from_the_process_secret_not_a_public_constant() {
        let a = derive_email_otp_hmac_key(None, &[1u8; 32]);
        let b = derive_email_otp_hmac_key(None, &[2u8; 32]);
        assert_ne!(a.as_slice(), OLD_PUBLIC_KEY);
        assert_eq!(a.len(), 32, "a full HMAC-SHA256 key");
        assert_ne!(a, b, "the key must depend on the secret, not be a constant");
        assert_eq!(
            a,
            derive_email_otp_hmac_key(None, &[1u8; 32]),
            "deterministic for one secret, so issue and verify agree"
        );
    }

    #[test]
    fn an_sms_key_is_preferred_but_never_reused_verbatim() {
        let sms = b"0123456789abcdef0123456789abcdef";
        let k = derive_email_otp_hmac_key(Some(sms), &[1u8; 32]);
        assert_ne!(
            k.as_slice(),
            sms.as_slice(),
            "domain-separated from the SMS key"
        );
        assert_eq!(
            k,
            derive_email_otp_hmac_key(Some(sms), &[9u8; 32]),
            "the operator's cluster-shared key wins over the per-process secret"
        );
        assert_ne!(k.as_slice(), OLD_PUBLIC_KEY);
    }
}
