//! Required-Action OIDC interceptor.
//!
//! After a user authenticates, the authorize route checks for pending required
//! actions before issuing an authorization code.  When actions are present the
//! flow is:
//!
//! 1. `required_action_check` intercepts the authorize request, sorts actions
//!    by priority, generates an RA session JWT (via the identity engine), sets
//!    an HttpOnly cookie, and redirects to `/required-action/{first_action}`.
//! 2. Each action has its own page, `GET /required-action/{ACTION}`, whose
//!    form POSTs to that action's handler (`UPDATE_PASSWORD`,
//!    `VERIFY_EMAIL/confirm`, `ENROLL_PHONE_OTP/{send,verify}`,
//!    `ENROLL_EMAIL_OTP/{send,verify}`, `enroll-mfa`). There is no generic
//!    "mark complete" POST: an action is only done when its handler has done
//!    it.
//! 3. On success the handler calls `next_required_action` (more actions
//!    remain) or `resume_oidc_flow` (all actions done).
//! 4. `resume_oidc_flow` clears the RA cookie, issues the authorization code,
//!    and redirects to `redirect_uri?code=…&state=…`.
//!
//! # CSRF
//!
//! Every form here carries `_csrf` = [`ra_form_token`], an HMAC of the RA
//! session cookie. The `/ui` pages' `hearth_ui_csrf` double-submit cookie is
//! `Path=/ui` and never reaches these routes in a browser.
//!
//! # Cookie security
//!
//! The RA session cookie is `HttpOnly; Path=/required-action; SameSite=Strict`.
//! It is scoped to `/required-action` only, preventing the RA JWT from being
//! sent to the main UI paths.  `Secure` is added when the server is TLS-enabled
//! or a trusted proxy signals `X-Forwarded-Proto: https`.

mod passkey;

use passkey::render_enroll_passkey_page;
pub use passkey::{passkey_begin, passkey_complete, PasskeyRegistrationBody};

use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{ClientId, FormSecret, RealmId, Timestamp, UserId};
use crate::identity::error::IdentityError;
use crate::identity::ra_token::{self, OidcParams};
use crate::identity::RequiredAction;
use crate::identity::{CleartextPassword, MfaProof, SessionContext, UpdateUserRequest};
use crate::protocol::client_info::PeerAddr;
use crate::protocol::web::auth::{issue_auth_cookies, FirstFactor, IssuedCookies};

use super::authorize_gate::{refuse_if_silent, run_authorize_gates, AuthorizeParams, Gate};
use super::handlers::append_cookie;
use super::handlers_common;
use super::templates::render;
use super::WebState;

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

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
    pub current_password: FormSecret,
    #[serde(default)]
    pub new_password: FormSecret,
    #[serde(default)]
    pub confirm_password: FormSecret,
    /// The page's [`ra_form_token`].
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
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
        None,
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
/// * `Ok(None)` — the user does not exist, or cannot sign in (disabled, or
///   still waiting for email verification). No required-action session is
///   minted for such an account (GA audit round 3, D-11): it let a disabled
///   or unverified account holder who knew the password change it, bind a
///   phone and send SMS. Every caller's next step (session creation, code
///   exchange) refuses the account with its usual answer.
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
        Ok(Some(u)) if u.status() == crate::identity::UserStatus::Active => u,
        Ok(_) => return Ok(None),
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
/// `ctx` is the context of the login that reached this gate, built from its
/// request. Its `mfa_proof` — what that authentication proved — is carried
/// in the RA session token, and the session created when the flow ends
/// records it ([`resume_browser_flow`]). A flow that cannot end in a session
/// is not started (GA audit round 3, D-1): starting it let whoever relayed a
/// password and a TOTP code enrol a phone of their own on the account before
/// the login was refused.
///
/// * The realm's `cidr_policy` refuses the client address (`403`). The
///   session the flow ends in is created without one, which the policy
///   reads as "nothing to refuse", so the flow must not start from a network
///   the policy turns away.
/// * The proof does not meet the realm's `mfa_required` / `webauthn_required`
///   policy and no pending action can raise it: the login is sent to the
///   passkey it owes, or refused.
///
/// Unlike the OIDC intercept, this generates an RA token without
/// OIDC params; flow resumption creates a session cookie and redirects to
/// `return_to` once all actions are complete.
///
/// `first_factor` is what proved the login's first factor. After a magic
/// link ([`FirstFactor::Inbox`]) an email OTP enrolled in the flow proves
/// the same inbox and does not raise the proof
/// ([`ra_token::RaClaims::inbox_first_factor`], GA sweep 4 round 2).
#[allow(clippy::too_many_arguments)]
pub fn required_action_check_browser(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    return_to: Option<&str>,
    ctx: &SessionContext,
    first_factor: FirstFactor,
    headers: &HeaderMap,
    now: Timestamp,
) -> Option<Response> {
    let inbox_first_factor = !first_factor.allows_email_otp();
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

    let secure = state.is_secure_request(headers);
    if let Err(e) = state
        .identity
        .check_realm_network_policy(realm, ctx.ip_address.as_deref())
    {
        tracing::info!(
            error = %e,
            realm_id = %realm.as_uuid(),
            "required actions: the realm's network policy refuses this login"
        );
        return Some(forbidden_page());
    }
    let mfa_proof = ctx.mfa_proof;
    let realm_config = match state.identity.get_realm(realm) {
        Ok(r) => r.map(|r| r.config().clone()),
        Err(e) => {
            tracing::warn!(error = %e, "required_action_check_browser: realm lookup failed");
            return Some(handlers_common::server_error());
        }
    };
    if let Some(config) = realm_config.as_ref() {
        let reachable = best_reachable_proof(mfa_proof, &actions, config, inbox_first_factor);
        if !realm_policy_admits(config, reachable) {
            tracing::info!(
                realm_id = %realm.as_uuid(),
                "required actions: this login cannot meet the realm's second-factor policy; \
                 not starting the flow"
            );
            return Some(owed_factor_or_refusal(
                state, realm, user_id, return_to, secure,
            ));
        }
    }

    actions.sort_by_key(|a| a.priority());
    let first = actions[0];

    let token = match state.identity.generate_browser_ra_token(
        realm,
        user_id,
        actions,
        return_to.map(str::to_string),
        mfa_proof,
        inbox_first_factor,
        None,
        now,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "required_action_check_browser: generate_browser_ra_token failed");
            return Some(handlers_common::server_error());
        }
    };

    let cookie = ra_token::ra_session_cookie(&token, secure);
    let path = format!("/required-action/{}", first.as_path_segment());
    let mut response = Redirect::to(&path).into_response();
    append_cookie(&mut response, &cookie);
    Some(response)
}

/// The strongest proof a browser required-action flow that starts from
/// `proof` with `actions` pending can end with: a passkey registration (the
/// `ENROLL_MFA` page registers one in a realm that offers passkeys) records
/// [`MfaProof::ProvedWebAuthn`]; any enrolment raises a login that proved
/// nothing to [`MfaProof::Proved`] (see [`ra_token::RaClaims`]) — except an
/// email-OTP enrolment after a magic link (`inbox_first_factor`), which proves
/// the inbox the login already proved. An upper bound — an action can be
/// skipped as already satisfied — so the session the flow ends in is still
/// checked by the engine.
fn best_reachable_proof(
    proof: MfaProof,
    actions: &[RequiredAction],
    config: &crate::identity::RealmConfig,
    inbox_first_factor: bool,
) -> MfaProof {
    let offers_passkeys = config
        .mfa_methods
        .as_ref()
        .is_none_or(|m| m.iter().any(|x| x == "webauthn"));
    if offers_passkeys && actions.contains(&RequiredAction::EnrollMfa) {
        return MfaProof::ProvedWebAuthn;
    }
    let enrols_a_factor = actions.iter().any(|a| match a {
        RequiredAction::EnrollMfa | RequiredAction::EnrollPhoneOtp => true,
        RequiredAction::EnrollEmailOtp => !inbox_first_factor,
        _ => false,
    });
    if enrols_a_factor && proof == MfaProof::None {
        return MfaProof::Proved;
    }
    proof
}

/// Whether the realm's second-factor policy admits a session with `proof` —
/// the same two predicates `create_session` applies.
fn realm_policy_admits(config: &crate::identity::RealmConfig, proof: MfaProof) -> bool {
    let mfa_ok = !config.mfa_required.unwrap_or(false) || proof.satisfies_mfa_required();
    let webauthn_ok =
        !config.webauthn_required.unwrap_or(false) || proof.satisfies_webauthn_required();
    mfa_ok && webauthn_ok
}

/// The answer to a browser login whose proof the realm's policy refuses:
/// the passkey challenge when the user holds a passkey that can meet it
/// (with a fresh MFA pending cookie — the RA token or the spent pending
/// cookie behind this call proved the first factor), otherwise `403`.
///
/// Only the passkey is offered: it is the one factor that can raise a proof
/// to what `webauthn_required` asks for, and any other factor the user holds
/// was already routed to before the flow started.
fn owed_factor_or_refusal(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    return_to: Option<&str>,
    secure: bool,
) -> Response {
    let (Ok(Some(realm_record)), Ok(Some(user))) = (
        state.identity.get_realm(realm),
        state.identity.get_user(realm, user_id),
    ) else {
        return handlers_common::server_error();
    };
    // Only the passkey is routed to, and the passkey proves nothing an
    // earlier factor proved, so what proved this login's first factor does
    // not change the answer; recording it as an inbox keeps the email OTP
    // out of reach of the pending cookie issued here all the same.
    let first = super::auth::FirstFactor::Inbox;
    match super::second_factor::second_factor_step(state, &realm_record, &user, first) {
        Ok(Some(step @ super::second_factor::SecondFactorStep::Passkey)) => {
            super::second_factor::redirect_to_second_factor(
                state, realm, user_id, step, first, return_to, secure,
            )
        }
        Ok(_) => forbidden_page(),
        Err(e) => {
            tracing::warn!(error = %e, "required actions: second-factor lookup failed");
            handlers_common::server_error()
        }
    }
}

/// The client context of a required-action request (address, user agent),
/// recorded on the session the flow may end in.
pub(super) fn client_context(
    state: &WebState,
    headers: &HeaderMap,
    peer_addr: std::net::SocketAddr,
) -> SessionContext {
    crate::protocol::client_info::build_session_context(headers, peer_addr, &state.trusted_proxies)
}

/// The bare `403` page for a login this flow refuses.
fn forbidden_page() -> Response {
    let mut page = handlers_common::ForbiddenTemplate::new(None);
    page.chrome = false;
    super::templates::render_status(&page, StatusCode::FORBIDDEN)
}

/// Clears the RA cookie, creates a session, and redirects to the original
/// destination for the **direct browser login path**.
///
/// Called when all required actions have been completed on the browser path.
/// The session records `mfa_proof` — what the login proved, as carried in
/// the RA token — so the engine's `mfa_required` / `webauthn_required` gates
/// judge the login by the factor it actually proved. A proof they refuse
/// sends the login to the passkey it owes, or refuses it.
pub fn resume_browser_flow(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_sub: &str,
    return_to: Option<String>,
    mfa_proof: MfaProof,
    client: &SessionContext,
    secure: bool,
) -> Response {
    let clear_cookie = ra_token::clear_ra_session_cookie(secure);

    let Ok(user_uuid) = uuid::Uuid::parse_str(user_sub) else {
        return handlers_common::server_error();
    };
    let user_id = UserId::new(user_uuid);

    // Never `Inherited`: the RA token records what the authentication that
    // started this flow proved, raised only by a factor the flow proved
    // itself (a user-verified passkey registration, or a first factor
    // enrolled by a user who held none). The flow used to resume with
    // `Inherited`, which satisfies `webauthn_required`, so a TOTP code plus
    // any pending action opened a session on a passkey-only realm (GA audit
    // round 3, D-1).
    // The client completing the flow — its address, which the realm's
    // network policy is checked against, and its user agent, shown in the
    // user's session list. The session used to record neither.
    let ctx = SessionContext {
        mfa_proof,
        ..client.clone()
    };
    let session = match state.identity.create_session(realm, &user_id, &ctx) {
        Ok(s) => s,
        Err(IdentityError::MfaRequired) => {
            let mut response =
                owed_factor_or_refusal(state, realm, &user_id, return_to.as_deref(), secure);
            append_cookie(&mut response, &clear_cookie);
            return response;
        }
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
/// whichever was set when the RA flow was originally initiated. `flow` is
/// the flow's id ([`ra_token::RaClaims::flow`]), which the new token keeps.
#[allow(clippy::too_many_arguments)]
pub fn next_required_action(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_sub: &str,
    mut remaining: Vec<RequiredAction>,
    oidc_params: Option<OidcParams>,
    browser_return_to: Option<String>,
    mfa_proof: MfaProof,
    inbox_first_factor: bool,
    flow: &str,
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
            .generate_ra_token(realm, &user_id, remaining, oidc, Some(flow), now)
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
            mfa_proof,
            inbox_first_factor,
            Some(flow),
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

    if client_or_role_requires_mfa(state, realm, user_id, realm_config, client_id_str)? {
        actions.push(RequiredAction::EnrollMfa);
    }
    Ok(())
}

/// Whether the client (its `mfa_required`) or one of the user's roles (listed
/// in the realm's `mfa_required_roles`) demands a second factor for this
/// authorization.
///
/// `Err(())` when a lookup the answer depends on fails: the requirement is
/// then unknown and the caller refuses. A client or role that does not exist
/// imposes nothing.
pub(super) fn client_or_role_requires_mfa(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    realm_config: Option<&crate::identity::RealmConfig>,
    client_id_str: Option<&str>,
) -> Result<bool, ()> {
    let refuse = |what: &str, e: &dyn std::fmt::Display| {
        tracing::warn!(
            error = %e,
            realm_id = %realm.as_uuid(),
            lookup = what,
            "required actions: MFA-requirement lookup failed; refusing"
        );
    };

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
    if client_requires_mfa {
        return Ok(true);
    }

    // Per-role requirement: any role the user holds that appears in
    // `realm.config.mfa_required_roles` triggers enforcement.
    let required_roles = realm_config
        .and_then(|c| c.mfa_required_roles.as_deref())
        .unwrap_or_default();
    if required_roles.is_empty() {
        return Ok(false);
    }
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
            return Ok(true);
        }
    }
    Ok(false)
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

/// Renders the "check your email" page for the VERIFY_EMAIL required action.
///
/// Before sending the verification email, checks if the user's email is already
/// verified in storage (auto-clear scenario for migration artifacts). If so,
/// clears the VERIFY_EMAIL action and advances the OIDC flow without sending
/// another email (AC-8 / OQ-3 resolution).
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
pub async fn verify_email_page(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
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

        return advance_flow(
            &state,
            &realm,
            claims,
            RequiredAction::VerifyEmail,
            &client_context(&state, &headers, peer_addr),
            secure,
            now,
        );
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
                    tracing::warn!(
                        error = %crate::protocol::redact::sanitize_log_text(&e.to_string()),
                        "verify_email_page: failed to send verification email"
                    );
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

/// `GET /required-action/VERIFY_EMAIL/confirm` — the confirmation page for
/// the emailed verification link.
///
/// The link's `?token=` was moved into the link-token cookie by the route's
/// middleware, and nothing is verified here: a mail scanner or link preview
/// that fetches the URL must not complete the action (GA audit L18). The
/// page's `POST` ([`verify_email_confirm_submit`]) verifies.
///
/// The RA session cookie is not required here: it is `SameSite=Strict`, so a
/// browser arriving from a mail client does not send it on this cross-site
/// navigation, but it does send it on the page's same-site `POST`.
pub async fn verify_email_confirm(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = super::link_token::read(&headers) else {
        return render_verify_email_expired(&state);
    };
    // The `hearth_ui_csrf` cookie is scoped to `/ui` and never reaches this
    // path; the link binding plus the `SameSite=Strict` RA session cookie
    // carry the `POST`'s cross-site protection.
    super::handlers::render_link_confirm(
        &state,
        &headers,
        &token,
        super::handlers::LinkConfirmCopy {
            heading: "Confirm your email address",
            message: "Confirm that this address is yours to continue signing in.",
            button_label: "Verify email",
        },
        "/required-action/VERIFY_EMAIL/confirm".to_string(),
        state.realm_theme_url(),
        false,
    )
}

/// `POST /required-action/VERIFY_EMAIL/confirm` — validates the stashed
/// verification token and advances the OIDC flow.
///
/// No redirect below ever carries the token (GA audit L18).
///
/// Requires the RA session cookie (400 if absent). On success, removes
/// VERIFY_EMAIL from the RA pending list and calls
/// [`resume_oidc_flow`] or [`next_required_action`]. On failure, renders an
/// error page with a link to resend the verification email.
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
pub async fn verify_email_confirm_submit(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<super::handlers::LinkConfirmForm>,
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

    // Validate and consume the email verification token. A POST without the
    // link cookie or with the wrong binding is refused and keeps the link.
    let Some(verify_token) =
        super::link_token::confirmed_token(&state, &headers, &form.link_binding, "", false)
    else {
        return render_verify_email_expired(&state);
    };

    super::link_token::mark_spent(
        match state.identity.verify_email_token(&realm, &verify_token) {
            Ok(verified_user_id) => {
                if verified_user_id != user_id {
                    return handlers_common::bad_request(
                        "Verification token does not match session",
                    );
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
                advance_flow(
                    &state,
                    &realm,
                    claims,
                    RequiredAction::VerifyEmail,
                    &client_context(&state, &headers, peer_addr),
                    secure,
                    now,
                )
            }
            Err(IdentityError::VerificationTokenInvalid) => render_verify_email_expired(&state),
            Err(e) => {
                tracing::warn!(error = %e, "verify_email_confirm: unexpected error");
                handlers_common::server_error()
            }
        },
    )
}

/// Continues the flow once `done` is off the pending list: the next pending
/// action's page, or — when none remain — back to the client with a code or
/// to the browser login's destination.
#[allow(clippy::needless_pass_by_value)]
fn advance_flow(
    state: &Arc<WebState>,
    realm: &RealmId,
    claims: ra_token::RaClaims,
    done: RequiredAction,
    client: &SessionContext,
    secure: bool,
    now: Timestamp,
) -> Response {
    let remaining: Vec<RequiredAction> = claims
        .pending_actions
        .iter()
        .copied()
        .filter(|a| *a != done)
        .collect();
    if !remaining.is_empty() {
        return next_required_action(
            state,
            realm,
            &claims.sub,
            remaining,
            claims.oidc_params,
            claims.browser_return_to,
            claims.mfa_proof,
            claims.inbox_first_factor,
            &claims.flow,
            secure,
            now,
        );
    }
    // The flow ends here — in a session or an authorization code — and it
    // ends once. A copy of any of its RA cookies used to end it again: the
    // "already satisfied" pages lead straight here, and every replay minted
    // another session (GA audit round 3, D-2).
    if let Err(e) = state.identity.consume_required_action_flow(realm, &claims) {
        tracing::info!(error = %e, "required actions: this flow has already ended");
        let mut response = forbidden_page();
        append_cookie(&mut response, &ra_token::clear_ra_session_cookie(secure));
        return response;
    }
    if claims.browser_return_to.is_some() {
        resume_browser_flow(
            state,
            realm,
            &claims.sub,
            claims.browser_return_to,
            claims.mfa_proof,
            client,
            secure,
        )
    } else if let Some(oidc_params) = claims.oidc_params {
        resume_oidc_flow(state, realm, &claims.sub, oidc_params, secure)
    } else {
        resume_browser_flow(
            state,
            realm,
            &claims.sub,
            None,
            claims.mfa_proof,
            client,
            secure,
        )
    }
}

/// Removes `action` from the account's persisted pending actions, so the
/// next login does not ask for it again. Best effort: a failure is logged,
/// and the flow still advances (the next login re-evaluates).
fn clear_persisted_action(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    action: RequiredAction,
) {
    let Ok(Some(user)) = state.identity.get_user(realm, user_id) else {
        tracing::warn!("clear_persisted_action: user lookup failed");
        return;
    };
    if !user.required_actions().contains(&action) {
        return;
    }
    let remaining: Vec<RequiredAction> = user
        .required_actions()
        .iter()
        .copied()
        .filter(|a| *a != action)
        .collect();
    if let Err(e) = state.identity.update_user(
        realm,
        user_id,
        &UpdateUserRequest {
            required_actions: Some(remaining),
            ..Default::default()
        },
    ) {
        tracing::warn!(error = %e, "clear_persisted_action: update_user failed");
    }
}

/// An action the user had already satisfied when its page was reached — an
/// operator put it on an account that holds the factor, or the user finished
/// it elsewhere. Records it as completed (`RequiredActionAutoCleared`),
/// clears it from the account and continues the flow, so the page never
/// redirects to itself.
#[allow(clippy::too_many_arguments)]
fn skip_satisfied_action(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    claims: ra_token::RaClaims,
    action: RequiredAction,
    reason: &'static str,
    client: &SessionContext,
    secure: bool,
    now: Timestamp,
) -> Response {
    clear_persisted_action(state, realm, user_id, action);
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: user_id.as_uuid().to_string(),
        action: AuditAction::RequiredActionAutoCleared,
        resource_type: "user".to_string(),
        resource_id: user_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({
            "action_type": crate::protocol::convert::identity::required_action_to_wire(action),
            "reason": reason,
        })),
    }) {
        tracing::warn!(error = %e, "skip_satisfied_action: audit append failed");
    }
    advance_flow(state, realm, claims, action, client, secure, now)
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
/// Embeds the page's [`ra_form_token`] as the form's `_csrf` field, so the
/// POST handler can verify it (task 21.3).
pub async fn update_password_page(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    if read_ra_cookie(&headers).is_none() {
        return handlers_common::bad_request("No active required-action session");
    }
    render_update_password_form(&state, None, ra_form_token(&state, &headers))
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
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<UpdatePasswordForm>,
) -> Response {
    // CSRF (audit §4.23#2, task 21.3). The RA cookie is `SameSite=Strict`,
    // but `SameSite` is a browser-version-dependent mitigation, not a control
    // — a cross-site POST that rides an existing RA session must be refused on
    // its own merits. The form carries a token bound to the RA session cookie
    // (`ra_form_token`); the `/ui`-scoped `hearth_ui_csrf` cookie this used to
    // check never reaches `/required-action/*` in a real browser, so the form
    // could not be submitted outside `--dev`.
    if read_ra_cookie(&headers).is_some() && !ra_form_ok(&state, &headers, &form.csrf) {
        return update_password_csrf_failure(&state, &headers);
    }
    let secure = state.is_secure_request(&headers);

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
    let csrf_echo = ra_form_token(&state, &headers);

    if *form.new_password != *form.confirm_password {
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
    //
    // The RA session cookie is single-use for this action: the engine claims
    // it cluster-wide before writing, so a replay within its 900 s life can
    // neither set the password again nor resume the flow again. A refused
    // submission (wrong current password, policy, reuse) releases the claim.
    // A user with no password credential yet (federated or passkey-only,
    // forced to set one) has no current password to prove; the engine sets
    // the password directly in that case.
    let current = CleartextPassword::new(form.current_password.as_bytes().to_vec());
    let new_pw = CleartextPassword::new(form.new_password.as_bytes().to_vec());
    let identity = state.identity.clone();
    let realm_for_kdf = realm.clone();
    let user_for_kdf = user_id.clone();
    let ra_session_token = token.clone();
    let ra_expires_at = Timestamp::from_micros(claims.exp.saturating_mul(1_000_000));
    let change_result = match crate::identity::gate()
        .run(move || {
            identity.complete_required_password_update(
                &realm_for_kdf,
                &user_for_kdf,
                &ra_session_token,
                ra_expires_at,
                &current,
                &new_pw,
            )
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
        Err(IdentityError::InvalidToken) => {
            return handlers_common::bad_request(
                "This required-action session was already used. Sign in again.",
            );
        }
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
    advance_flow(
        &state,
        &realm,
        claims,
        RequiredAction::UpdatePassword,
        &client_context(&state, &headers, peer_addr),
        secure,
        now,
    )
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

/// 403 response for an update-password POST without the page's form token.
///
/// Re-renders the form (with the token the browser can actually use) rather
/// than a bare error page, so a user whose page went stale can retry.
fn update_password_csrf_failure(state: &Arc<WebState>, headers: &HeaderMap) -> Response {
    let tmpl = update_password_template(
        state,
        Some("Your session expired. Please try again."),
        ra_form_token(state, headers),
    );
    super::templates::render_status(&tmpl, StatusCode::FORBIDDEN)
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
    /// The page's [`ra_form_token`].
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    #[serde(default)]
    pub phone: String,
}

/// `application/x-www-form-urlencoded` body for `POST /required-action/ENROLL_PHONE_OTP/verify`.
#[derive(Debug, Deserialize)]
pub struct EnrollPhoneOtpVerifyForm {
    /// The page's [`ra_form_token`].
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
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
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
) -> Response {
    // Verify the RA session token, exactly as the email twin does — cookie
    // presence alone proves nothing (audit 2026-08-28 §4.19#7).
    let (realm, claims) = match validated_ra_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    // A user who already holds a verified phone has nothing to enrol here.
    let Ok(user_uuid) = uuid::Uuid::parse_str(&claims.sub) else {
        return handlers_common::server_error();
    };
    let user_id = UserId::new(user_uuid);
    match state.identity.get_user(&realm, &user_id) {
        Ok(Some(user)) if user.phone_verified() => {
            let secure = state.is_secure_request(&headers);
            let now = Timestamp::from_micros(now_micros());
            return skip_satisfied_action(
                &state,
                &realm,
                &user_id,
                claims,
                RequiredAction::EnrollPhoneOtp,
                "phone_already_verified",
                &client_context(&state, &headers, peer_addr),
                secure,
                now,
            );
        }
        Ok(Some(_)) => {}
        _ => return handlers_common::server_error(),
    }
    render_enroll_phone_page(&state, &headers, None)
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
    if read_ra_cookie(&headers).is_some() && !ra_form_ok(&state, &headers, &form.csrf) {
        return ra_form_refused();
    }
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
            &headers,
            Some("Enter a valid international phone number (e.g. +15555550100)."),
        );
    }

    let Some(sms_sender) = state.sms.as_ref() else {
        tracing::warn!("enroll_phone_otp_send: SMS transport not configured");
        return render_enroll_phone_page(
            &state,
            &headers,
            Some("SMS delivery is not configured. Contact your administrator."),
        );
    };

    let Some(hmac_key) = sms_otp_hmac_key_bytes(&state) else {
        return render_enroll_phone_page(
            &state,
            &headers,
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
                &headers,
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
                &headers,
                Some("Failed to send verification code. Please try again."),
            );
        }
    };

    render_enroll_phone_verify(&state, &headers, &phone, Some(&nonce), None)
}

/// Verifies the submitted OTP code, stores the phone as verified, clears
/// `ENROLL_PHONE_OTP` from the user's required actions, and advances the flow.
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
pub async fn enroll_phone_otp_verify_submit(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<EnrollPhoneOtpVerifyForm>,
) -> Response {
    if read_ra_cookie(&headers).is_some() && !ra_form_ok(&state, &headers, &form.csrf) {
        return ra_form_refused();
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
        return render_enroll_phone_page(&state, &headers, Some("Invalid submission."));
    }
    if form.nonce.is_empty() || form.code.is_empty() {
        return render_enroll_phone_verify(
            &state,
            &headers,
            &phone,
            Some(&form.nonce),
            Some("Invalid submission."),
        );
    }

    let Some(hmac_key) = sms_otp_hmac_key_bytes(&state) else {
        return render_enroll_phone_page(
            &state,
            &headers,
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
                &headers,
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

    // The user proved the phone just enrolled; see `record_enrolled_factor`.
    let mut claims = claims;
    claims.record_enrolled_factor();
    advance_flow(
        &state,
        &realm,
        claims,
        RequiredAction::EnrollPhoneOtp,
        &client_context(&state, &headers, peer_addr),
        secure,
        now,
    )
}

// ---------------------------------------------------------------------------
// ENROLL_PHONE_OTP helpers
// ---------------------------------------------------------------------------

fn render_enroll_phone_page(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    error: Option<&str>,
) -> Response {
    let tmpl = EnrollPhoneOtpPageTemplate {
        error: error.map(str::to_string),
        chrome: false,
        active: "",
        user_email: None,
        is_admin: false,
        narrow: true,
        flash: None,
        csrf: ra_form_token(state, headers),
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    };
    render(&tmpl)
}

fn render_enroll_phone_verify(
    state: &Arc<WebState>,
    headers: &HeaderMap,
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
        csrf: ra_form_token(state, headers),
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

/// Purpose tag of the per-page form token every `/required-action/*` form
/// carries.
const RA_FORM_PURPOSE: &str = "hearth-ra-form";

/// The `_csrf` value every `/required-action/*` form carries: an HMAC of the
/// required-action session cookie under the cookie secret.
///
/// The `/ui` pages use the `hearth_ui_csrf` double-submit cookie, but that
/// cookie is scoped to `Path=/ui` and a browser never sends it to
/// `/required-action/*`, so these forms bind to the RA session cookie
/// instead — the same shape as the emailed-link `link_binding`. The page can
/// embed the token; a cross-site attacker, who can neither read the HttpOnly
/// cookie nor compute the MAC, cannot. `None` without an RA cookie.
fn ra_form_token(state: &WebState, headers: &HeaderMap) -> Option<String> {
    read_ra_cookie(headers).map(|token| ra_form_token_for(&state.cookie_secret, &token))
}

/// The [`ra_form_token`] for the RA session cookie value `ra_session_token`
/// under `secret`.
#[must_use]
pub fn ra_form_token_for(secret: &super::auth::CookieSecret, ra_session_token: &str) -> String {
    super::link_token::keyed_binding(secret, RA_FORM_PURPOSE, ra_session_token)
}

/// Whether `submitted` is the form token for the request's RA session
/// cookie, compared in constant time. There is no `--dev` bypass: the page
/// always embeds the token, so a genuine submission always carries it.
fn ra_form_ok(state: &WebState, headers: &HeaderMap, submitted: &str) -> bool {
    ra_form_token(state, headers)
        .is_some_and(|expected| crate::core::ct_eq_secret_str(&expected, submitted))
}

/// `403` for a `/required-action/*` POST that lacks the page's form token.
fn ra_form_refused() -> Response {
    (
        StatusCode::FORBIDDEN,
        "This form has expired. Go back, reload the page and try again.",
    )
        .into_response()
}

/// The only field the send-code forms post besides the form token.
#[derive(Debug, Deserialize)]
pub struct RaFormToken {
    /// The page's [`ra_form_token`].
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
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
    /// The page's [`ra_form_token`].
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub code: String,
}

/// Renders the landing page for email OTP enrollment. Loads the user's email
/// from the RA token subject and shows a "Send code to my email" button.
pub async fn enroll_email_otp_page(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
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
    let user = match state.identity.get_user(&realm, &user_id) {
        Ok(Some(user)) => user,
        _ => return handlers_common::server_error(),
    };
    // A user who already has email OTP has nothing to enrol here, and must
    // not be sent another code.
    if user.email_otp_enabled() {
        let secure = state.is_secure_request(&headers);
        return skip_satisfied_action(
            &state,
            &realm,
            &user_id,
            claims,
            RequiredAction::EnrollEmailOtp,
            "email_otp_already_enabled",
            &client_context(&state, &headers, peer_addr),
            secure,
            now,
        );
    }
    render_enroll_email_otp_page(&state, &headers, user.email(), None)
}

/// Sends an email OTP to the user's registered email address and renders
/// the code-entry form.
pub async fn enroll_email_otp_send(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<RaFormToken>,
) -> Response {
    if read_ra_cookie(&headers).is_some() && !ra_form_ok(&state, &headers, &form.csrf) {
        return ra_form_refused();
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
            &headers,
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
        Ok(nonce) => render_enroll_email_otp_verify(&state, &headers, &email, Some(&nonce), None),
        Err(e) => {
            tracing::warn!(
                error = %crate::protocol::redact::sanitize_log_text(&e.to_string()),
                "enroll_email_otp_send: issue_email_otp failed"
            );
            render_enroll_email_otp_page(
                &state,
                &headers,
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
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<EnrollEmailOtpVerifyForm>,
) -> Response {
    if read_ra_cookie(&headers).is_some() && !ra_form_ok(&state, &headers, &form.csrf) {
        return ra_form_refused();
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
            &headers,
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
                &headers,
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

    // The user proved the inbox just enrolled; after a magic link that is
    // the inbox the login already proved (see `record_enrolled_email_otp`).
    let mut claims = claims;
    claims.record_enrolled_email_otp();
    advance_flow(
        &state,
        &realm,
        claims,
        RequiredAction::EnrollEmailOtp,
        &client_context(&state, &headers, peer_addr),
        secure,
        now,
    )
}

fn render_enroll_email_otp_page(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    email: &str,
    error: Option<&str>,
) -> Response {
    let tmpl = EnrollEmailOtpPageTemplate {
        masked_email: crate::identity::email::mask_email_address(email),
        error: error.map(str::to_string),
        chrome: false,
        active: "",
        user_email: None,
        is_admin: false,
        narrow: true,
        flash: None,
        csrf: ra_form_token(state, headers),
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    };
    render(&tmpl)
}

fn render_enroll_email_otp_verify(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    email: &str,
    nonce: Option<&str>,
    error: Option<&str>,
) -> Response {
    let tmpl = EnrollEmailOtpVerifyTemplate {
        masked_email: crate::identity::email::mask_email_address(email),
        nonce: nonce.map(str::to_string),
        error: error.map(str::to_string),
        chrome: false,
        active: "",
        user_email: None,
        is_admin: false,
        narrow: true,
        flash: None,
        csrf: ra_form_token(state, headers),
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    };
    render(&tmpl)
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
    /// The page's [`ra_form_token`].
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    #[serde(default)]
    pub code: String,
}

/// Where a user stands against a pending `EnrollMfa`.
enum EnrollMfaStatus {
    /// Already satisfied: a passkey, or TOTP where the realm does not
    /// require a passkey specifically.
    Satisfied,
    /// The realm requires a passkey (TOTP does not count — audit §4.18#9),
    /// which this page cannot register.
    NeedsPasskey,
    /// TOTP enrolment on this page satisfies it.
    NeedsTotp,
}

/// Evaluates `EnrollMfa` for `user_id` exactly as
/// `inject_enroll_mfa_if_needed` decides to add it. `Err(())` when a lookup
/// fails (logged): the answer is then unknown.
fn enroll_mfa_status(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
) -> Result<EnrollMfaStatus, ()> {
    let log = |what: &str, e: &dyn std::fmt::Display| {
        tracing::warn!(error = %e, lookup = what, "enroll_mfa_status: lookup failed");
    };
    let has_totp = state
        .identity
        .mfa_enabled(realm, user_id)
        .map_err(|e| log("totp", &e))?;
    let has_passkeys = !state
        .identity
        .list_webauthn_credentials(realm, user_id)
        .map_err(|e| log("passkeys", &e))?
        .is_empty();
    let realm_requires_passkey = state
        .identity
        .get_realm(realm)
        .map_err(|e| log("realm", &e))?
        .and_then(|r| r.config().webauthn_required)
        .unwrap_or(false);
    Ok(if has_passkeys || (has_totp && !realm_requires_passkey) {
        EnrollMfaStatus::Satisfied
    } else if realm_requires_passkey {
        EnrollMfaStatus::NeedsPasskey
    } else {
        EnrollMfaStatus::NeedsTotp
    })
}

/// `409` for a passkey requirement this page cannot meet: it can only enrol
/// TOTP, which would not count. Says so instead of enrolling a factor that
/// does not satisfy the realm, or looping.
fn passkey_required_page(state: &Arc<WebState>, headers: &HeaderMap) -> Response {
    enroll_mfa_error_page(
        state,
        headers,
        "This sign-in requires a passkey, but this realm does not offer passkey \
         registration. Ask your administrator to enable passkeys for the realm.",
        StatusCode::CONFLICT,
    )
}

/// Whether the realm lets users register passkeys (`mfa_methods` absent, or
/// listing `webauthn` — the gate `start_webauthn_registration` applies).
fn realm_offers_passkeys(state: &Arc<WebState>, realm: &RealmId) -> bool {
    match state.identity.get_realm(realm) {
        Ok(Some(r)) => r
            .config()
            .mfa_methods
            .as_ref()
            .is_none_or(|m| m.iter().any(|x| x == "webauthn")),
        _ => false,
    }
}

/// The enrol-MFA page showing only `message`, answered with `status`.
fn enroll_mfa_error_page(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    message: &str,
    status: StatusCode,
) -> Response {
    let tmpl = EnrollMfaPageTemplate {
        error: Some(message.to_string()),
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
        csrf: ra_form_token(state, headers),
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    };
    super::templates::render_status(&tmpl, status)
}

/// What `GET /required-action/enroll-mfa` answers before any TOTP
/// enrolment: `Some` when the action is already satisfied (skipped), when
/// only a passkey will do (the registration page, or a 409 in a realm that
/// does not offer passkeys), or when the factor lookup failed; `None` when
/// TOTP enrolment on this page satisfies the action.
fn enroll_mfa_gate(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    claims: ra_token::RaClaims,
    headers: &HeaderMap,
    client: &SessionContext,
    now: Timestamp,
) -> Option<Response> {
    match enroll_mfa_status(state, realm, user_id) {
        Err(()) => Some(handlers_common::server_error()),
        Ok(EnrollMfaStatus::Satisfied) => Some(skip_satisfied_action(
            state,
            realm,
            user_id,
            claims,
            RequiredAction::EnrollMfa,
            "mfa_already_enrolled",
            client,
            state.is_secure_request(headers),
            now,
        )),
        Ok(EnrollMfaStatus::NeedsPasskey) => Some(if realm_offers_passkeys(state, realm) {
            render_enroll_passkey_page(state, headers)
        } else {
            passkey_required_page(state, headers)
        }),
        Ok(EnrollMfaStatus::NeedsTotp) => None,
    }
}

/// Initiates TOTP enrollment for the `EnrollMfa` required action.
///
/// Reads the RA session cookie to identify the user, calls `enroll_totp` to
/// generate a fresh TOTP secret, and renders the QR code + recovery codes.
/// Each GET generates a new pending enrollment (idempotent from the user's
/// perspective; the previous pending secret is overwritten).
pub async fn enroll_mfa_page(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
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

    let client = client_context(&state, &headers, peer_addr);
    if let Some(resp) = enroll_mfa_gate(
        &state,
        &realm,
        &user_id,
        claims.clone(),
        &headers,
        &client,
        now,
    ) {
        return resp;
    }

    let identity = state.identity.clone();
    let enroll_realm = realm.clone();
    let enroll_user = user_id.clone();
    let enroll_result =
        tokio::task::spawn_blocking(move || identity.enroll_totp(&enroll_realm, &enroll_user))
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
                csrf: ra_form_token(&state, &headers),
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                realm_theme_url: state.realm_theme_url(),
                inline_theme_css: state.inline_theme_css(),
            };
            super::templates::render(&tmpl)
        }
        Err(IdentityError::MfaAlreadyEnabled) => {
            // TOTP was enabled between the check above and now (another tab):
            // the action is satisfied — never redirect back to this page.
            let secure = state.is_secure_request(&headers);
            skip_satisfied_action(
                &state,
                &realm,
                &user_id,
                claims,
                RequiredAction::EnrollMfa,
                "mfa_already_enrolled",
                &client_context(&state, &headers, peer_addr),
                secure,
                now,
            )
        }
        Err(e) => {
            tracing::warn!(error = %e, "enroll_mfa_page: enroll_totp failed");
            enroll_mfa_error_page(
                &state,
                &headers,
                "Unable to start MFA enrollment. Please try again.",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
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
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<EnrollMfaForm>,
) -> Response {
    if read_ra_cookie(&headers).is_some() && !ra_form_ok(&state, &headers, &form.csrf) {
        return ra_form_refused();
    }
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
            csrf: ra_form_token(&state, &headers),
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

    // Enrollment confirmed. Clear the action from the account too: an
    // operator-set `EnrollMfa` left on it would send the user back here on
    // every later login.
    clear_persisted_action(&state, &realm, &user_id, RequiredAction::EnrollMfa);
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: user_id.as_uuid().to_string(),
        action: AuditAction::RequiredActionCompleted,
        resource_type: "user".to_string(),
        resource_id: user_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "action_type": "ENROLL_MFA" })),
    }) {
        tracing::warn!(error = %e, "enroll_mfa_submit: audit append failed");
    }
    // The user proved the TOTP just enrolled; see `record_enrolled_factor`.
    let mut claims = claims;
    claims.record_enrolled_factor();
    let secure = state.is_secure_request(&headers);
    advance_flow(
        &state,
        &realm,
        claims,
        RequiredAction::EnrollMfa,
        &client_context(&state, &headers, peer_addr),
        secure,
        now,
    )
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

/// Password fields are wiped on drop and never printed by `Debug`
/// (GA audit L20).
#[cfg(test)]
mod secret_field_tests {
    use super::*;
    use crate::core::secrets::assert_zeroize_on_drop;

    #[test]
    fn update_password_form_is_zeroized_and_redacted() {
        let form: UpdatePasswordForm = serde_urlencoded::from_str(
            "current_password=CANARY-cur&new_password=CANARY-new&confirm_password=CANARY-cfm",
        )
        .expect("form parses");
        assert_zeroize_on_drop(&form.current_password);
        assert_zeroize_on_drop(&form.new_password);
        assert_zeroize_on_drop(&form.confirm_password);
        assert_eq!(form.confirm_password.expose(), "CANARY-cfm");
        let dbg = format!("{form:?}");
        assert!(!dbg.contains("CANARY"), "Debug leaked a secret: {dbg}");
    }
}
