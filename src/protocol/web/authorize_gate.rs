//! The one gate sequence every browser authorization branch runs.
//!
//! `GET /ui/oauth/authorize` reaches code issuance by several routes: a plain
//! request, a signed request object (JAR, RFC 9101), a pushed request
//! (`request_uri`, RFC 9126), and the resumes at the end of the
//! required-action and SMS-challenge interstitials. Each branch used to call
//! the gates it remembered: only the plain branch ran the consent
//! interstitial and honoured `prompt`, so a JAR or PAR request — or any
//! request that detoured through a required action or the SMS challenge —
//! was issued a code for a third-party client the user never approved, and
//! the PAR branch and the SMS resume dropped the requested `response_mode`.
//!
//! Every branch now builds one [`AuthorizeParams`] from its authoritative
//! source and hands it to [`run_authorize_gates`], which runs, in order:
//!
//! 1. the required-action intercept,
//! 2. the SMS MFA challenge,
//! 3. consent and OIDC `prompt` handling,
//! 4. code issuance with the request's `response_mode`, `resource` and PAR
//!    origin.
//!
//! An interstitial that suspends the flow stores the parameters and, when it
//! completes, re-enters here at the [`Gate`] after its own — so no branch can
//! skip a later gate by returning early.
//!
//! `prompt=none` (OIDC Core §3.1.2.1) forbids any UI, so every gate that
//! would suspend the flow asks [`refuse_if_silent`] first and, for a silent
//! request, answers the client with an error instead: `interaction_required`
//! for a pending required action, `consent_required` for consent. The
//! required-action gate used to redirect a silent request into its
//! interactive page.

use std::sync::Arc;

use axum::response::{IntoResponse, Redirect, Response};

use crate::core::{ClientId, RealmId, Timestamp, UserId};
use crate::identity::ra_token::OidcParams;
use crate::identity::{
    canonicalize_scopes, AuthorizationRequest, CodeChallengeMethod, MfaProof,
    PendingAuthorizationRequest, ResponseMode,
};

use super::handlers::append_cookie;
use super::handlers_common;
use super::oauth_consent::{
    authorization_error_redirect, build_authorization_redirect, issue_ticket_cookie, ErrorReturn,
    CONSENT_TICKET_TTL_SECS,
};
use super::WebState;

/// A validated authorization request, every value authoritative.
///
/// Built by each `/authorize` branch from its own source — the query string,
/// a verified request object, a stored PAR entry — or restored from an
/// interstitial's signed resume state. The gates never re-read the query.
#[derive(Debug, Clone)]
pub(super) struct AuthorizeParams {
    /// The requesting client.
    pub client_id: ClientId,
    /// Redirect URI, already checked against the client's registration.
    pub redirect_uri: String,
    /// Space-delimited requested scopes.
    pub scope: String,
    /// OAuth `state`, echoed to the client.
    pub state: String,
    /// PKCE challenge.
    pub code_challenge: Option<String>,
    /// PKCE method (`S256` only).
    pub code_challenge_method: Option<CodeChallengeMethod>,
    /// OIDC nonce.
    pub nonce: Option<String>,
    /// OIDC `prompt` (`none`, `consent`, or empty).
    pub prompt: String,
    /// Requested response mode; `None` is the default `query`.
    pub response_mode: Option<ResponseMode>,
    /// RFC 8707 resource indicator, from a verified JAR or PAR entry only.
    pub resource: Option<String>,
    /// What the browser session authorizing the request proved about a
    /// second factor. The code records it, and the token session its exchange
    /// opens proves exactly that (GA audit round 3, D-7). Set from the
    /// session at every entry point; `None` otherwise.
    pub mfa_proof: MfaProof,
}

impl AuthorizeParams {
    /// The wire form carried in the required-action session JWT.
    pub(super) fn to_oidc_params(&self) -> OidcParams {
        OidcParams {
            // The bare UUID: `ClientId`'s `Display` is prefixed.
            client_id: self.client_id.as_uuid().to_string(),
            redirect_uri: self.redirect_uri.clone(),
            scope: self.scope.clone(),
            code_challenge: self.code_challenge.clone().unwrap_or_default(),
            code_challenge_method: method_wire(self.code_challenge_method.as_ref()),
            nonce: self.nonce.clone(),
            state: Some(self.state.clone()).filter(|s| !s.is_empty()),
            response_type: "code".to_string(),
            response_mode: self.response_mode.as_ref().map(|m| m.as_str().to_string()),
            prompt: self.prompt.clone(),
            mfa_proof: self.mfa_proof,
            resource: self.resource.clone(),
        }
    }

    /// Restores the parameters from a required-action session JWT.
    ///
    /// `None` when a value does not parse: the JWT is server-signed and was
    /// built by [`Self::to_oidc_params`], so that is an internal fault and
    /// the caller refuses the authorization.
    pub(super) fn from_oidc_params(p: &OidcParams) -> Option<Self> {
        Some(Self {
            client_id: ClientId::new(uuid::Uuid::parse_str(&p.client_id).ok()?),
            redirect_uri: p.redirect_uri.clone(),
            scope: p.scope.clone(),
            state: p.state.clone().unwrap_or_default(),
            code_challenge: Some(p.code_challenge.clone()).filter(|c| !c.is_empty()),
            code_challenge_method: parse_method(&p.code_challenge_method)?,
            nonce: p.nonce.clone(),
            prompt: p.prompt.clone(),
            response_mode: parse_response_mode(p.response_mode.as_deref())?,
            resource: p.resource.clone(),
            mfa_proof: p.mfa_proof,
        })
    }
}

/// The wire string for a PKCE method (`""` when absent).
pub(super) fn method_wire(method: Option<&CodeChallengeMethod>) -> String {
    match method {
        Some(CodeChallengeMethod::S256) => "S256".to_string(),
        None => String::new(),
    }
}

/// Parses a stored PKCE method: `Some(None)` for absent, `None` for invalid.
pub(super) fn parse_method(wire: &str) -> Option<Option<CodeChallengeMethod>> {
    match wire {
        "" => Some(None),
        "S256" => Some(Some(CodeChallengeMethod::S256)),
        _ => None,
    }
}

/// Parses a stored response mode: `Some(None)` for absent, `None` for invalid.
pub(super) fn parse_response_mode(wire: Option<&str>) -> Option<Option<ResponseMode>> {
    match wire.filter(|m| !m.is_empty()) {
        None => Some(None),
        Some(m) => m.parse::<ResponseMode>().ok().map(Some),
    }
}

/// Where a (re-)entry into the gate sequence starts.
///
/// A fresh request starts at [`Gate::RequiredActions`]; an interstitial that
/// completes resumes at the gate after its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Gate {
    /// Pending required actions (password change, enrolment, …).
    RequiredActions,
    /// Consent and OIDC `prompt` handling, then code issuance.
    Consent,
}

/// Runs every gate from `from` onward and returns the response: an
/// interstitial redirect, an error, or the code redirect.
///
/// `amr_values` are the factors proved on the way here; they are bound into
/// the issued code.
#[allow(clippy::too_many_arguments)]
pub(super) fn run_authorize_gates(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    params: &AuthorizeParams,
    from: Gate,
    amr_values: Vec<String>,
    secure: bool,
    now: Timestamp,
) -> Response {
    if from <= Gate::RequiredActions {
        if let Some(resp) = super::required_action::required_action_intercept(
            state, realm, user_id, params, secure, now,
        ) {
            return resp;
        }
    }
    consent_gate(state, realm, user_id, params, amr_values, secure, now)
}

/// Refuses an authorization for a client or role that demands a second
/// factor when the SESSION proved none (GA audit B5).
///
/// Client `mfa_required` and realm `mfa_required_roles` used to be enforced
/// only at enrolment: the required-action gate asked whether the account
/// *held* a factor and, once it did, issued the code. A session that never
/// proved one — a password-only login from before the factor was enrolled, a
/// magic-link session, a session from before sessions recorded their proof —
/// was issued codes for exactly the clients the operator had marked
/// sensitive.
///
/// A user who holds no factor at all is left to the required-action gate,
/// which injects `EnrollMfa`. A user who holds one must prove it, which
/// means signing in again: the session is revoked and the client is told
/// `login_required`, so its next request lands on the login page and the
/// second-factor challenge. Runs on fresh entry only; an interstitial resume
/// continues a request this gate already admitted.
pub(super) fn mfa_use_gate(
    state: &Arc<WebState>,
    realm: &RealmId,
    session: &super::auth::UiSession,
    params: &AuthorizeParams,
) -> Option<Response> {
    if session.mfa_proof.satisfies_mfa_required() {
        return None;
    }
    let client_id = params.client_id.as_uuid().to_string();
    match super::required_action::mfa_requirement_for(
        state,
        realm,
        &session.user_id,
        Some(&client_id),
    ) {
        Ok(false) => return None,
        Ok(true) => {}
        Err(()) => return Some(handlers_common::server_error()),
    }
    match state.identity.has_second_factor(realm, &session.user_id) {
        // Nothing to prove yet: the required-action gate enrols a factor.
        Ok(false) => return None,
        Ok(true) => {}
        Err(e) => {
            tracing::warn!(error = %e, "authorize: factor lookup failed at the MFA-use gate");
            return Some(handlers_common::server_error());
        }
    }

    match state.identity.get_client(realm, &params.client_id) {
        Ok(Some(_)) => {}
        Ok(None) => return Some(handlers_common::bad_request("unknown client")),
        Err(e) => {
            tracing::warn!(error = %e, "authorize: get_client failed at the MFA-use gate");
            return Some(handlers_common::server_error());
        }
    }
    // The unproved session must not be reused for this client: revoke it so
    // the client's retry reaches the login page and its factor challenge.
    if let Err(e) = state.identity.revoke_session(realm, &session.session_id) {
        tracing::warn!(error = %e, "authorize: revoking an unproved session failed");
        return Some(handlers_common::server_error());
    }
    let error_return = ErrorReturn {
        redirect_uri: &params.redirect_uri,
        state: &params.state,
        response_mode: params.response_mode.as_ref(),
    };
    Some(authorization_error_redirect(
        state,
        realm,
        &error_return,
        "login_required",
        "this application requires a second factor; sign in again",
    ))
}

/// `Some(error redirect)` when `params` is a `prompt=none` request, which a
/// gate about to show UI must return instead (OIDC Core §3.1.2.1); `None`
/// for an interactive request, which the gate may suspend.
///
/// `error` is the OIDC error the gate's interaction maps to
/// (`interaction_required`, `login_required`). The refusal travels in the
/// request's response mode like any other authorization error, and counts
/// as a silent-auth probe (A-37) like the consent gate's own outcomes.
pub(super) fn refuse_if_silent(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    params: &AuthorizeParams,
    error: &str,
    description: &str,
) -> Option<Response> {
    if params.prompt != "none" {
        return None;
    }
    match state.identity.get_client(realm, &params.client_id) {
        Ok(Some(_)) => {}
        Ok(None) => return Some(handlers_common::bad_request("unknown client")),
        Err(e) => {
            tracing::warn!(error = %e, "authorize: get_client failed refusing a silent request");
            return Some(handlers_common::server_error());
        }
    }
    let error_return = ErrorReturn {
        redirect_uri: &params.redirect_uri,
        state: &params.state,
        response_mode: params.response_mode.as_ref(),
    };
    let client_id_str = params.client_id.to_string();
    if let Err(crate::identity::IdentityError::SilentAuthRateLimited) = state
        .identity
        .check_silent_auth_probe(realm, user_id, &client_id_str, error)
    {
        return Some(authorization_error_redirect(
            state,
            realm,
            &error_return,
            "login_required",
            "silent auth rate limit exceeded",
        ));
    }
    Some(authorization_error_redirect(
        state,
        realm,
        &error_return,
        error,
        description,
    ))
}

/// Consent + OIDC `prompt` handling (OIDC Core §3.1.2.1), then issuance.
///
/// * No consent needed (`require_consent=false`, or a recorded consent covers
///   the scopes and `prompt` is not `consent`) → issue the code.
/// * `prompt=none` otherwise → `error=consent_required`.
/// * Otherwise → store a pending request under a ticket and redirect to the
///   consent page, which issues the code on approval.
#[allow(clippy::too_many_lines)]
fn consent_gate(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    params: &AuthorizeParams,
    amr_values: Vec<String>,
    secure: bool,
    now: Timestamp,
) -> Response {
    let client = match state.identity.get_client(realm, &params.client_id) {
        Ok(Some(c)) => c,
        Ok(None) => return handlers_common::bad_request("unknown client"),
        Err(e) => {
            tracing::warn!(error = %e, "authorize: get_client failed at the consent gate");
            return handlers_common::server_error();
        }
    };
    let client_id_str = params.client_id.to_string();
    // Errors go back the way the code would have: in the request's
    // response mode.
    let error_return = ErrorReturn {
        redirect_uri: &params.redirect_uri,
        state: &params.state,
        response_mode: params.response_mode.as_ref(),
    };

    // Resolve the scopes first (scope-consent-integrity design §2): the
    // consent check, the consent screen and the code see only what can be
    // granted.
    let granted = match state.identity.authorization_scopes(
        realm,
        user_id,
        &params.client_id,
        &params.scope,
        params.resource.as_deref(),
    ) {
        Ok(granted) => granted,
        Err(crate::identity::IdentityError::InvalidScope { .. }) => {
            return authorization_error_redirect(
                state,
                realm,
                &error_return,
                "invalid_scope",
                "a requested scope is not available",
            );
        }
        Err(crate::identity::IdentityError::InvalidTarget { .. }) => {
            return handlers_common::bad_request(
                "invalid_target: resource is not a registered protected resource",
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "authorize: scope resolution failed");
            return handlers_common::server_error();
        }
    };
    let mut granted_params = params.clone();
    granted_params.scope = granted.join(" ");
    let params = &granted_params;

    let requested_scopes = canonicalize_scopes(granted);

    let existing = match state
        .identity
        .get_consent(realm, user_id, &params.client_id)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "authorize: get_consent failed");
            return handlers_common::server_error();
        }
    };
    let covered = existing
        .as_ref()
        .is_some_and(|r| r.covers(&requested_scopes));

    let force_prompt = params.prompt == "consent";
    let silent_only = params.prompt == "none";

    // A-37: every `prompt=none` request is counted per (realm, sub) and rate
    // limited; a limited probe answers `login_required` (OIDC Core §3.1.2.6).
    if silent_only {
        let outcome = if !client.require_consent() || covered {
            "code_issued"
        } else {
            "consent_required"
        };
        if let Err(crate::identity::IdentityError::SilentAuthRateLimited) = state
            .identity
            .check_silent_auth_probe(realm, user_id, &client_id_str, outcome)
        {
            return authorization_error_redirect(
                state,
                realm,
                &error_return,
                "login_required",
                "silent auth rate limit exceeded",
            );
        }
    }

    let bypass = !client.require_consent() || (covered && !force_prompt);
    if bypass {
        return issue_code(
            state,
            realm,
            user_id,
            params,
            &requested_scopes.join(" "),
            amr_values,
        );
    }

    if silent_only {
        return authorization_error_redirect(
            state,
            realm,
            &error_return,
            "consent_required",
            "user consent required",
        );
    }

    let pending = PendingAuthorizationRequest {
        realm_id: realm.clone(),
        user_id: user_id.clone(),
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        requested_scopes,
        state: params.state.clone(),
        response_type: "code".to_string(),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: Some(method_wire(params.code_challenge_method.as_ref()))
            .filter(|m| !m.is_empty()),
        nonce: params.nonce.clone(),
        response_mode: params
            .response_mode
            .as_ref()
            .map(|m| m.as_str().to_string()),
        resource: params.resource.clone(),
        amr_values,
        created_at: now,
        expires_at: now.add_micros(CONSENT_TICKET_TTL_SECS * 1_000_000),
    };
    let ticket = match state.identity.put_pending_authorization(realm, &pending) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "put_pending_authorization failed");
            return handlers_common::server_error();
        }
    };
    let cookie = issue_ticket_cookie(&state.cookie_secret, user_id, &ticket, secure);
    let mut response = Redirect::to("/ui/oauth/consent").into_response();
    append_cookie(&mut response, &cookie);
    response
}

/// Issues the authorization code for `params` (with the consented `scope`)
/// and redirects the user-agent to the engine-validated redirect URI in the
/// request's response mode.
///
/// Only the consent gate and the consent approval call this: every other
/// path reaches issuance through [`run_authorize_gates`].
pub(super) fn issue_code(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    params: &AuthorizeParams,
    scope: &str,
    amr_values: Vec<String>,
) -> Response {
    let request = AuthorizationRequest {
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        scope: scope.to_string(),
        state: params.state.clone(),
        resource: params.resource.clone(),
        response_type: "code".to_string(),
        user_id: user_id.clone(),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
        nonce: params.nonce.clone(),
        amr_values,
        response_mode: params.response_mode.clone(),
        request: None,
    };
    match state
        .identity
        .authorize_from_session(realm, &request, params.mfa_proof)
    {
        Ok(resp) => {
            // 22.3 (audit 2026-08-28 §4.3#5): redirect to the URI the engine
            // validated and bound the code to, never to a caller-held copy.
            let location = build_authorization_redirect(resp.redirect_uri(), &resp);
            Redirect::to(&location).into_response()
        }
        // The resource was removed from the registry after the entry point
        // checked it (G6).
        Err(crate::identity::IdentityError::InvalidTarget { .. }) => handlers_common::bad_request(
            "invalid_target: resource is not a registered protected resource",
        ),
        Err(e) => {
            tracing::warn!(error = %e, "authorize: code issuance failed");
            handlers_common::server_error()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuthorizeParams {
        AuthorizeParams {
            client_id: ClientId::new(uuid::Uuid::new_v4()),
            redirect_uri: "https://app.example.com/cb".to_string(),
            scope: "openid profile".to_string(),
            state: "st".to_string(),
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            nonce: Some("n".to_string()),
            prompt: "consent".to_string(),
            response_mode: Some(ResponseMode::Fragment),
            resource: Some("https://api.example.com".to_string()),
            mfa_proof: MfaProof::Proved,
        }
    }

    #[test]
    fn oidc_params_round_trip_keeps_every_value() {
        let p = sample();
        let back = AuthorizeParams::from_oidc_params(&p.to_oidc_params()).expect("round trip");
        assert_eq!(back.client_id, p.client_id);
        assert_eq!(back.redirect_uri, p.redirect_uri);
        assert_eq!(back.scope, p.scope);
        assert_eq!(back.state, p.state);
        assert_eq!(back.code_challenge, p.code_challenge);
        assert_eq!(back.code_challenge_method, p.code_challenge_method);
        assert_eq!(back.nonce, p.nonce);
        assert_eq!(back.prompt, p.prompt);
        assert_eq!(back.response_mode, p.response_mode);
        assert_eq!(back.resource, p.resource);
    }

    #[test]
    fn a_malformed_stored_value_is_refused_not_defaulted() {
        let mut o = sample().to_oidc_params();
        o.response_mode = Some("form_post".to_string());
        assert!(AuthorizeParams::from_oidc_params(&o).is_none());
        let mut o = sample().to_oidc_params();
        o.code_challenge_method = "plain".to_string();
        assert!(AuthorizeParams::from_oidc_params(&o).is_none());
        let mut o = sample().to_oidc_params();
        o.client_id = "not-a-uuid".to_string();
        assert!(AuthorizeParams::from_oidc_params(&o).is_none());
    }
}
