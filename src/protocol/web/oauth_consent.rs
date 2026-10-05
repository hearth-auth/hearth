//! Browser-facing OAuth authorization endpoint + consent interstitial.
//!
//! RFC 6749 §4.1 requires a browser-redirect `GET /authorize` endpoint
//! where the user interactively approves the authorization request. The
//! existing JSON `POST /authorize` at `src/protocol/http.rs` is for
//! machine clients and SDKs and bypasses consent.
//!
//! This module adds:
//!
//! | Route | Method | Purpose |
//! |-------|--------|---------|
//! | `/ui/oauth/authorize` | GET | RFC 6749 redirect entry point |
//! | `/ui/realms/{realm}/oauth/authorize` | GET | Realm-scoped variant |
//! | `/ui/oauth/consent` | GET | Render consent prompt |
//! | `/ui/oauth/consent` | POST | Approve / deny submit |
//!
//! Flow:
//!
//! 1. `GET /ui/oauth/authorize` — validate the request (plain query, JAR or
//!    PAR) against the registered `OAuthClient`, require a valid
//!    `UiSession`, then run the shared gates in `authorize_gate`: required
//!    actions and consent — the engine resolves the scopes and checks the
//!    consent row for the request's organization and resource. If the row
//!    covers what the grant discloses (or the client has no consent step),
//!    skip straight to code issuance and
//!    302 back to `redirect_uri`. Otherwise stash a
//!    [`PendingAuthorizationRequest`] under an opaque ticket and
//!    redirect to the consent page.
//! 2. `GET /ui/oauth/consent` — render the interstitial showing client
//!    name, logo (if set), and per-scope checkboxes.
//! 3. `POST /ui/oauth/consent` — validate CSRF + ticket, either:
//!    - `decision=approve` → verify approved scopes are a subset of the
//!      originally requested set, persist consent, emit
//!      [`AuditAction::ConsentGranted`], issue code, 302 to redirect URI.
//!    - `decision=deny` → emit [`AuditAction::ConsentDenied`], 302 to
//!      `redirect_uri?error=access_denied&state=...` per RFC 6749 §4.1.2.1.
//!
//! # Security notes
//!
//! * Ticket cookie is HMAC-signed with [`CookieSecret`] and bound to the
//!   current `UiSession`'s `user_id` so cross-user replay is detectable.
//! * The engine's pending-auth record independently re-checks the `user_id`
//!   before issuing a code — cookie compromise alone is not sufficient.
//! * POST-submitted `approved_scopes` must be a subset of the original
//!   request's scope list. Tampering returns
//!   [`IdentityError::ConsentScopeNotRequested`].
//! * `prompt=none` with no sufficient existing consent returns
//!   `error=consent_required` per OIDC Core §3.1.2.1.
//! * `prompt=consent` forces re-prompting even if a matching consent
//!   record exists — per OIDC Core §3.1.2.1.

use std::collections::BTreeSet;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{ClientId, RealmId, Timestamp, UserId};
use crate::identity::{
    canonicalize_scopes, CodeChallengeMethod, IdentityError, MfaProof, PendingAuthorizationRequest,
    ResponseMode,
};

use super::auth::{CookieSecret, UiSession};
use super::authorize_gate::{
    issue_code, parse_method, parse_response_mode, run_authorize_gates, AuthorizeParams, Gate,
};
use super::handlers::append_cookie;
use super::handlers_common;
use super::templates::render;
use super::WebState;

/// Ticket cookie name. Short-lived, signed, bound to the `UiSession` user id.
pub const CONSENT_TICKET_COOKIE: &str = "hearth_ui_oauth_ticket";

/// TTL for a pending-authorization ticket in seconds (10 minutes — same
/// ballpark as the OAuth authorization code TTL).
pub const CONSENT_TICKET_TTL_SECS: i64 = 600;

// ---------------------------------------------------------------------------
// Query parameters (RFC 6749 §4.1.1 + OIDC Core §3.1.2.1)
// ---------------------------------------------------------------------------

/// Query parameters accepted by `GET /ui/oauth/authorize`.
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    /// OAuth client id (UUID string).
    #[serde(default)]
    pub client_id: String,
    /// Registered redirect URI the user agent is returned to.
    #[serde(default)]
    pub redirect_uri: String,
    /// Must be `"code"` — implicit and hybrid flows are not supported.
    #[serde(default)]
    pub response_type: String,
    /// Space-delimited scope string. May be empty.
    #[serde(default)]
    pub scope: String,
    /// CSRF-protecting opaque value echoed back to the client.
    #[serde(default)]
    pub state: String,
    /// PKCE challenge.
    #[serde(default)]
    pub code_challenge: String,
    /// PKCE challenge method. Only `S256` is accepted.
    #[serde(default)]
    pub code_challenge_method: String,
    /// OIDC nonce — echoed into the ID token.
    #[serde(default)]
    pub nonce: String,
    /// OIDC `prompt` parameter. Supported: `none`, `consent`, or empty.
    #[serde(default)]
    pub prompt: String,
    /// Response mode (`query` or `fragment`).
    ///
    /// Absent means default `query` mode (plain code redirect).
    #[serde(default)]
    pub response_mode: Option<String>,
    /// Signed JAR JWT (RFC 9101). When present, all authorization parameters
    /// are taken from the JWT payload; other query params (except `client_id`)
    /// serve only as defaults.
    #[serde(default)]
    pub request: Option<String>,
    /// PAR `request_uri` (RFC 9126). When present, this handler calls
    /// `consume_par` to expand the pre-validated stored parameters.
    #[serde(default)]
    pub request_uri: Option<String>,
    /// The `organization` parameter: an organization ID or slug of the realm
    /// (`scope-consent-integrity` design §1). A JAR's claim takes precedence.
    #[serde(default)]
    pub organization: Option<String>,
    /// RFC 8707 resource indicator (plain requests; a JAR or PAR request
    /// takes it from the request object or the stored entry instead).
    ///
    /// Every branch holds it to the realm's protected-resource registry
    /// before anything else happens: an undeclared resource is refused with
    /// `invalid_target`, and a registered one travels in canonical form (G6).
    /// The required-action intercept carries it to the code they
    /// eventually issue — dropping it issued a code, and a token, without
    /// the audience the client asked for.
    #[serde(default)]
    pub resource: Option<String>,
}

// ---------------------------------------------------------------------------
// Template
// ---------------------------------------------------------------------------

/// A single scope row on the consent prompt.
struct ConsentScopeRow {
    /// Raw scope value (e.g. `"profile"`).
    name: String,
    /// Whether the user has already granted this scope previously.
    /// Pre-checked in the UI for convenience but explicitly re-submitted.
    already_granted: bool,
}

/// Template rendered by `GET /ui/oauth/consent`.
#[derive(Template)]
#[template(path = "ui/oauth/consent.html")]
struct ConsentTemplate {
    /// Client display name for the "{app} wants to access..." header.
    client_name: String,
    /// Optional client logo URL. `None` renders a generic icon.
    client_logo_url: Option<String>,
    /// Requested scopes + pre-granted state.
    scopes: Vec<ConsentScopeRow>,
    /// Opaque ticket — submitted back with the decision.
    ticket: String,
    /// CSRF double-submit token (`hearth_ui_csrf` cookie value).
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
// Entry point: GET /ui/oauth/authorize
// ---------------------------------------------------------------------------

/// Bare `GET /ui/oauth/authorize` — uses the current UI session's realm.
pub async fn authorize_get(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    headers: axum::http::HeaderMap,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    let realm = session.realm_id.clone();
    authorize_get_impl(&state, &session, &realm, &q, &headers).await
}

/// Realm-scoped variant at `GET /ui/realms/{realm}/oauth/authorize`.
///
/// The path-scoped realm MUST match the signed-in session's realm; a
/// mismatch returns 404 (not a bypass surface).
pub async fn authorize_get_scoped(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    let Ok(Some(realm)) = state.identity.get_realm_by_name(&realm_name) else {
        return handlers_common::not_found("Realm not found");
    };
    if realm.id() != &session.realm_id {
        return handlers_common::not_found("Realm not found");
    }
    authorize_get_impl(&state, &session, realm.id(), &q, &headers).await
}

#[allow(clippy::unused_async)]
async fn authorize_get_impl(
    state: &Arc<WebState>,
    session: &UiSession,
    realm: &RealmId,
    q: &AuthorizeQuery,
    headers: &axum::http::HeaderMap,
) -> Response {
    let now = Timestamp::from_micros(now_micros());
    let mut params = match authorize_params(state, realm, q) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    // The code carries what this session proved into the token session
    // (GA audit round 3, D-7).
    params.mfa_proof = session.mfa_proof;
    // A client or role that demands a second factor needs a session that
    // PROVED one (GA audit B5). Fresh entry only: the interstitial resumes
    // continue a request this check already admitted.
    if let Some(refusal) = super::authorize_gate::mfa_use_gate(state, realm, session, &params) {
        return refusal;
    }
    // Every branch — plain, JAR, PAR — runs the same gates in the same order:
    // required actions, consent / `prompt`, then issuance. The
    // interstitials resume into the same sequence after their own gate.
    run_authorize_gates(
        state,
        realm,
        &session.user_id,
        &params,
        Gate::RequiredActions,
        Vec::new(),
        state.is_secure_request(headers),
        now,
    )
}

/// Builds the validated [`AuthorizeParams`] from whichever source the
/// request names: a pushed request (`request_uri`), a signed request object
/// (`request`), or the plain query string. `Err` is the response to return.
fn authorize_params(
    state: &Arc<WebState>,
    realm: &RealmId,
    q: &AuthorizeQuery,
) -> Result<AuthorizeParams, Response> {
    // PAR first: a PAR submission may itself have carried a JAR, and the
    // stored parameters are already the effective values.
    if let Some(ref request_uri) = q.request_uri {
        return par_params(state, realm, q, request_uri);
    }

    // client_id is always required (JAR and non-JAR alike).
    let Ok(client_uuid) = uuid::Uuid::parse_str(&q.client_id) else {
        return Err(handlers_common::bad_request("invalid client_id"));
    };
    let client_id = ClientId::new(client_uuid);
    let client = match state.identity.get_client(realm, &client_id) {
        Ok(Some(c)) => c,
        Ok(None) => return Err(handlers_common::bad_request("unknown client")),
        Err(e) => {
            tracing::warn!(error = %e, "authorize_get: get_client failed");
            return Err(handlers_common::server_error());
        }
    };

    // When a signed request object (JAR) is present, outer params other than
    // `client_id` are only fallbacks — the verified claims are authoritative.
    // Never redirect for JAR errors (open-redirect risk).
    if let Some(ref request_jwt) = q.request {
        return jar_params(state, realm, &client, q, request_jwt);
    }
    plain_params(state, realm, &client, q)
}

/// The plain branch: validate the query string itself.
fn plain_params(
    state: &Arc<WebState>,
    realm: &RealmId,
    client: &crate::identity::OAuthClient,
    q: &AuthorizeQuery,
) -> Result<AuthorizeParams, Response> {
    let client_id = client.client_id();
    if q.response_type != "code" {
        return Err(handlers_common::bad_request("response_type must be 'code'"));
    }
    if q.state.is_empty() {
        return Err(handlers_common::bad_request(
            "state parameter is required for CSRF protection",
        ));
    }
    // The redirect_uri is validated BEFORE any error redirect — per RFC 6749
    // §4.1.2.1, errors are only redirected to a confirmed-registered URI.
    if !client.redirect_uris().iter().any(|u| u == &q.redirect_uri) {
        return Err(handlers_common::bad_request("invalid redirect_uri"));
    }

    // The response mode is read first: every later error goes back in the
    // mode the request asked for. An unsupported mode is itself reported in
    // the default mode.
    let Some(response_mode) = parse_response_mode(q.response_mode.as_deref()) else {
        return Err(authorization_error_redirect(
            state,
            realm,
            &ErrorReturn {
                redirect_uri: &q.redirect_uri,
                state: &q.state,
                response_mode: None,
            },
            "invalid_request",
            "unsupported_response_mode",
        ));
    };
    let error_return = ErrorReturn {
        redirect_uri: &q.redirect_uri,
        state: &q.state,
        response_mode: response_mode.as_ref(),
    };

    let Some(code_challenge_method) = parse_method(&q.code_challenge_method) else {
        return Err(authorization_error_redirect(
            state,
            realm,
            &error_return,
            "invalid_request",
            "unsupported code_challenge_method",
        ));
    };

    // Public clients MUST supply PKCE S256 (RFC 9700 / HEA-501 F-01).
    if !client.is_confidential() && q.code_challenge.is_empty() {
        return Err(authorization_error_redirect(
            state,
            realm,
            &error_return,
            "invalid_request",
            "public clients must use PKCE with code_challenge_method=S256",
        ));
    }

    // RFC 8707 §2: a resource the realm does not declare is `invalid_target`.
    let resource = match q.resource.as_deref().filter(|r| !r.is_empty()) {
        None => None,
        Some(r) => match state.identity.canonical_protected_resource(realm, r) {
            Ok(canonical) => Some(canonical),
            Err(IdentityError::InvalidTarget { .. }) => {
                return Err(authorization_error_redirect(
                    state,
                    realm,
                    &error_return,
                    "invalid_target",
                    "resource is not a registered protected resource",
                ));
            }
            Err(e) => {
                tracing::warn!(error = %e, "authorize_get: resource lookup failed");
                return Err(handlers_common::server_error());
            }
        },
    };

    Ok(AuthorizeParams {
        client_id: client_id.clone(),
        redirect_uri: q.redirect_uri.clone(),
        scope: q.scope.clone(),
        state: q.state.clone(),
        code_challenge: optional(&q.code_challenge),
        code_challenge_method,
        nonce: optional(&q.nonce),
        prompt: q.prompt.clone(),
        response_mode,
        resource,
        organization: q.organization.clone().filter(|o| !o.is_empty()),
        // Set from the session by `authorize_get_impl`.
        mfa_proof: MfaProof::None,
    })
}

/// The PAR (RFC 9126) branch: consume the stored entry.
///
/// Everything comes from the stored request — including its
/// `response_mode` and `prompt`, which this branch used to drop. Outer query
/// parameters other than `client_id` are ignored (RFC 9126 §4): a `prompt`
/// beside `request_uri` can neither strip a pushed `prompt=consent` nor add
/// a `prompt=none` the client never pushed.
fn par_params(
    state: &Arc<WebState>,
    realm: &RealmId,
    q: &AuthorizeQuery,
    request_uri: &str,
) -> Result<AuthorizeParams, Response> {
    let stored = match state.identity.consume_par(realm, request_uri) {
        Ok(s) => s,
        Err(IdentityError::InvalidPushedAuthorizationRequest) => {
            return Err(handlers_common::bad_request(
                "invalid or expired request_uri",
            ));
        }
        Err(e) => {
            tracing::warn!(error = %e, "consume_par failed in authorize_get_impl");
            return Err(handlers_common::server_error());
        }
    };

    // RFC 9126 §4: a client_id in the query string MUST match the stored one.
    if !q.client_id.is_empty() {
        let Ok(q_client) = uuid::Uuid::parse_str(&q.client_id).map(ClientId::new) else {
            return Err(handlers_common::bad_request("invalid client_id"));
        };
        if q_client != stored.client_id {
            return Err(handlers_common::bad_request(
                "client_id mismatch with pushed authorization request",
            ));
        }
    }

    // The PAR endpoint stores `response_mode` unparsed. Never redirect for
    // a malformed stored request.
    let Some(response_mode) = parse_response_mode(stored.response_mode.as_deref()) else {
        return Err(handlers_common::bad_request("unsupported response_mode"));
    };

    // The entry was checked against the registry when it was pushed; the
    // resource may have been removed since (G6).
    let resource = match stored.resource.as_deref() {
        None => None,
        Some(r) => Some(registered_resource_or_refusal(state, realm, r)?),
    };

    Ok(AuthorizeParams {
        client_id: stored.client_id,
        redirect_uri: stored.redirect_uri,
        scope: stored.scope,
        state: stored.state,
        code_challenge: stored.code_challenge,
        code_challenge_method: stored.code_challenge_method,
        nonce: stored.nonce,
        prompt: stored.prompt.unwrap_or_default(),
        response_mode,
        resource,
        organization: stored.organization,
        // Set from the session by `authorize_get_impl`.
        mfa_proof: MfaProof::None,
    })
}

/// The consent row a pending request is decided under: its user, client,
/// organization (stored by the gate as an ID) and canonical resource.
///
/// `None` when a stored value does not parse. The gate wrote it, so that is
/// an internal fault and the caller refuses the ticket.
fn pending_consent_key(
    pending: &PendingAuthorizationRequest,
) -> Option<crate::identity::ConsentKey> {
    let org_id = match pending.organization.as_deref() {
        None => None,
        Some(o) => Some(o.parse::<crate::core::OrganizationId>().ok()?),
    };
    let resource = match pending.resource.as_deref() {
        None => None,
        Some(r) => Some(crate::core::Uri::try_from(r.to_string()).ok()?),
    };
    Some(crate::identity::ConsentKey {
        user_id: pending.user_id.clone(),
        client_id: pending.client_id.clone(),
        org_id,
        resource,
    })
}

// ---------------------------------------------------------------------------
// GET /ui/oauth/consent
// ---------------------------------------------------------------------------

/// Renders the consent interstitial for a pending authorization request.
pub async fn consent_page(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(ticket_value) = read_ticket_cookie(&headers) else {
        return handlers_common::bad_request("no pending authorization");
    };
    let Some(ticket) =
        validate_ticket_cookie(&state.cookie_secret, &session.user_id, &ticket_value)
    else {
        return handlers_common::bad_request("consent ticket invalid");
    };

    // Peek the pending request without consuming the ticket — we do a
    // real take on the POST path. This peek uses get_consent of a sibling
    // nature: we need to scan the ticket-keyed entry. Since
    // `take_pending_authorization` consumes, we instead fetch via a
    // lightweight path: re-issuing would require a lookup-only engine
    // method. For simplicity we read via `get_pending_authorization`
    // helper added below.
    let pending = match peek_pending(&state, &session.realm_id, &ticket) {
        Ok(p) => p,
        Err(PeekErr::NotFound | PeekErr::Expired) => {
            return handlers_common::bad_request("consent ticket invalid")
        }
        Err(PeekErr::Storage) => return handlers_common::server_error(),
    };

    // Cross-user guard: the pending record embeds the user_id. Tampered
    // cookies that happen to MAC-validate still don't grant consent for
    // another user.
    if pending.user_id != session.user_id {
        return handlers_common::bad_request("consent ticket invalid");
    }

    // A-34: Cross-realm guard. The pending request embeds the realm it was
    // issued in; a mismatch means the user switched realms after initiating
    // the consent flow. Reject rather than silently issue a code in the
    // wrong realm.
    if pending.realm_id != session.realm_id {
        return handlers_common::bad_request("consent ticket invalid");
    }

    // Load the client for display fields + determine pre-granted scopes.
    let client = match state
        .identity
        .get_client(&session.realm_id, &pending.client_id)
    {
        Ok(Some(c)) => c,
        Ok(None) => return handlers_common::bad_request("unknown client"),
        Err(_) => return handlers_common::server_error(),
    };
    let Some(key) = pending_consent_key(&pending) else {
        return handlers_common::bad_request("consent ticket invalid");
    };
    let existing = state
        .identity
        .get_consent(&session.realm_id, &key)
        .ok()
        .flatten();

    let scopes: Vec<ConsentScopeRow> = pending
        .requested_scopes
        .iter()
        .map(|s| ConsentScopeRow {
            name: s.clone(),
            already_granted: existing
                .as_ref()
                .is_some_and(|r| r.granted_scopes.iter().any(|g| g == s)),
        })
        .collect();

    let admin = super::handlers::is_admin(state.as_ref(), &session);
    let tmpl = ConsentTemplate {
        client_name: client.client_name().to_string(),
        client_logo_url: client.client_logo_url().map(str::to_string),
        scopes,
        ticket,
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
    };
    // A-34: Prevent clickjacking of the consent prompt. The page must never
    // be rendered inside an iframe — an attacker-controlled frame could layer
    // invisible UI over the approve/deny buttons (UI redressing / clickjack).
    let mut resp = render(&tmpl);
    resp.headers_mut().insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static("frame-ancestors 'none'"),
    );
    resp
}

// ---------------------------------------------------------------------------
// POST /ui/oauth/consent
// ---------------------------------------------------------------------------

/// Parsed consent-submit form. Built via [`parse_consent_form`] from the
/// raw body because `serde_urlencoded` (axum's default) does not collect
/// repeated `scope=` fields into a `Vec<String>`.
struct ConsentSubmitForm {
    /// Opaque ticket (single-use).
    pub ticket: String,
    /// `"approve"` or `"deny"`.
    pub decision: String,
    /// Scopes the user approved (repeated `scope=` fields).
    pub scopes: Vec<String>,
    /// CSRF double-submit token.
    pub csrf: String,
}

/// Parses an `application/x-www-form-urlencoded` body into a
/// [`ConsentSubmitForm`], collecting repeated `scope=` keys into a
/// `Vec<String>`.
fn parse_consent_form(body: &[u8]) -> ConsentSubmitForm {
    let mut ticket = String::new();
    let mut decision = String::new();
    let mut scopes: Vec<String> = Vec::new();
    let mut csrf = String::new();
    for (k, v) in form_urlencoded::parse(body) {
        match k.as_ref() {
            "ticket" => ticket = v.into_owned(),
            "decision" => decision = v.into_owned(),
            "scope" => scopes.push(v.into_owned()),
            "_csrf" => csrf = v.into_owned(),
            _ => {}
        }
    }
    ConsentSubmitForm {
        ticket,
        decision,
        scopes,
        csrf,
    }
}

/// Handles `POST /ui/oauth/consent`.
#[allow(clippy::too_many_lines)]
pub async fn consent_submit(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let form = parse_consent_form(&body);
    if let Err(resp) = super::auth::verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    // Validate ticket cookie matches the form-posted ticket and is
    // MAC-bound to the current user.
    let Some(cookie_value) = read_ticket_cookie(&headers) else {
        return handlers_common::bad_request("consent ticket invalid");
    };
    let Some(ticket_from_cookie) =
        validate_ticket_cookie(&state.cookie_secret, &session.user_id, &cookie_value)
    else {
        return handlers_common::bad_request("consent ticket invalid");
    };
    if !cookie_ticket_matches(&ticket_from_cookie, &form.ticket) {
        return handlers_common::bad_request("consent ticket invalid");
    }

    // Consume the ticket — single-use, regardless of decision.
    let pending = match state
        .identity
        .take_pending_authorization(&session.realm_id, &form.ticket)
    {
        Ok(p) => p,
        Err(IdentityError::ConsentTicketNotFound | IdentityError::ConsentTicketExpired) => {
            return handlers_common::bad_request("consent ticket invalid");
        }
        Err(e) => {
            tracing::warn!(error = %e, "take_pending_authorization failed");
            return handlers_common::server_error();
        }
    };

    // Ownership guard redundant with the cookie MAC check, but cheap.
    if pending.user_id != session.user_id {
        return handlers_common::bad_request("consent ticket invalid");
    }

    // A-34: Cross-realm guard on submit path.
    if pending.realm_id != session.realm_id {
        return handlers_common::bad_request("consent ticket invalid");
    }

    // Clear the ticket cookie regardless of outcome.
    let clear_cookie =
        format!("{CONSENT_TICKET_COOKIE}=; HttpOnly; Path=/ui; SameSite=Lax; Max-Age=0");

    #[allow(clippy::single_match_else, clippy::match_same_arms)]
    match form.decision.as_str() {
        "approve" => {
            // Validate approved scopes are a subset of requested.
            let requested: BTreeSet<&String> = pending.requested_scopes.iter().collect();
            let approved = canonicalize_scopes(form.scopes.clone());
            for s in &approved {
                if !requested.contains(&s) {
                    return handlers_common::bad_request("scope not in original request");
                }
            }

            // Persist consent (even if approved is empty — the user
            // chose "approve no scopes", which still satisfies the
            // request for an authorization code).
            // The row is bound to the organization and the resource of the
            // request (`scope-consent-integrity` design §5).
            let Some(key) = pending_consent_key(&pending) else {
                return handlers_common::bad_request("consent ticket invalid");
            };
            let grant = crate::identity::ConsentGrant {
                key,
                scopes: approved.clone(),
                via: crate::identity::ConsentSurface::Web,
            };
            if let Err(e) = state.identity.grant_consent(&session.realm_id, &grant) {
                tracing::warn!(error = %e, "grant_consent failed");
                return handlers_common::server_error();
            }
            // Engine now emits ConsentGranted internally; metadata-threading
            // for via/scopes context tracked in follow-up.

            // The pending record is ours (written by the consent gate), so a
            // value that no longer parses is refused rather than defaulted.
            let method = parse_method(pending.code_challenge_method.as_deref().unwrap_or(""));
            let response_mode = parse_response_mode(pending.response_mode.as_deref());
            let (Some(code_challenge_method), Some(response_mode)) = (method, response_mode) else {
                let mut err_response = authorization_error_redirect(
                    &state,
                    &session.realm_id,
                    &ErrorReturn {
                        redirect_uri: &pending.redirect_uri,
                        state: &pending.state,
                        response_mode: None,
                    },
                    "invalid_request",
                    "unsupported_response_mode",
                );
                append_cookie(&mut err_response, &clear_cookie);
                return err_response;
            };
            // Everything the request carried to the consent gate — its
            // response mode, RFC 8707 resource and the factors already
            // proved — reaches the code. This used to issue with no resource
            // and no `amr`.
            let params = AuthorizeParams {
                client_id: pending.client_id.clone(),
                redirect_uri: pending.redirect_uri.clone(),
                scope: approved.join(" "),
                state: pending.state.clone(),
                code_challenge: pending.code_challenge.clone(),
                code_challenge_method,
                nonce: pending.nonce.clone(),
                prompt: String::new(),
                response_mode,
                resource: pending.resource.clone(),
                organization: pending.organization.clone(),
                // The approving session's proof (GA audit round 3, D-7).
                mfa_proof: session.mfa_proof,
            };
            let mut response = issue_code(
                &state,
                &session.realm_id,
                &session.user_id,
                &params,
                &params.scope,
                pending.amr_values.clone(),
            );
            append_cookie(&mut response, &clear_cookie);
            response
        }
        _ => {
            audit_consent_event(
                &state,
                &session.realm_id,
                &session.user_id,
                &pending.client_id,
                AuditAction::ConsentDenied,
                &pending.requested_scopes,
                "self",
            );
            // The denial goes back in the request's response mode, like the
            // code would have. The pending record is ours; a mode that no
            // longer parses falls back to the default.
            let response_mode = parse_response_mode(pending.response_mode.as_deref()).flatten();
            let mut response = authorization_error_redirect(
                &state,
                &session.realm_id,
                &ErrorReturn {
                    redirect_uri: &pending.redirect_uri,
                    state: &pending.state,
                    response_mode: response_mode.as_ref(),
                },
                "access_denied",
                "user denied authorization",
            );
            append_cookie(&mut response, &clear_cookie);
            response
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn optional(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Wall-clock "now" in Unix microseconds. `Timestamp` uses the engine
/// `Clock`; for pending-auth TTLs we just need a coarse wall value since
/// the engine itself re-checks expiry at take-time using its own clock.
fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

/// Builds a signed ticket cookie value: `{ticket}.{mac}` where the MAC
/// covers `user_id|ticket` with [`CookieSecret`]. Binding to the user id
/// makes cross-user replay detectable even if the cookie is copied.
pub(super) fn issue_ticket_cookie(
    secret: &CookieSecret,
    user_id: &UserId,
    ticket: &str,
    secure: bool,
) -> String {
    let mac = compute_ticket_mac(secret, user_id, ticket);
    let value = format!("{ticket}.{mac}");
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{CONSENT_TICKET_COOKIE}={value}; HttpOnly; Path=/ui; SameSite=Lax; Max-Age={CONSENT_TICKET_TTL_SECS}{secure_flag}"
    )
}

fn compute_ticket_mac(secret: &CookieSecret, user_id: &UserId, ticket: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret_as_bytes(secret))
        .expect("HMAC-SHA256 accepts any 32-byte key");
    mac.update(user_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(ticket.as_bytes());
    BASE64URL_NOPAD.encode(&mac.finalize().into_bytes())
}

/// Exposes the `[u8; 32]` inside [`CookieSecret`] without adding a public
/// accessor. This is a read-only borrow — if the representation of
/// `CookieSecret` changes, update this one place.
fn secret_as_bytes(secret: &CookieSecret) -> &[u8] {
    // Use a tiny hack to borrow via the Debug path: `CookieSecret` is
    // `Arc<[u8; 32]>`. We `clone()` to bump the Arc refcount, then keep
    // the Arc alive by returning a static-lifetime reference derived
    // from a `Box::leak` pattern is overkill. Instead we serialize via
    // the public signing path: re-implement inline.
    //
    // NB: the auth module owns `CookieSecret::as_bytes` (pub(super)).
    // Here we re-use the same trick via the `Mac::new_from_slice` →
    // `compute_mac` path already present. Simpler: call through a
    // helper defined in `auth`.
    //
    // Pragmatic path: we expose `CookieSecret::as_bytes_public` via a
    // newtype shim in `auth.rs` so this module can read it.
    // Implemented below via a re-export — see `super::auth::cookie_secret_bytes`.
    super::auth::cookie_secret_bytes(secret)
}

/// Reads the raw ticket cookie value from request headers. Returns
/// `None` when absent.
fn read_ticket_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    super::auth::cookie_value_from_headers(headers, CONSENT_TICKET_COOKIE).map(str::to_string)
}

/// Parses and MAC-validates a ticket cookie value. Returns the inner
/// ticket on success.
fn validate_ticket_cookie(secret: &CookieSecret, user_id: &UserId, value: &str) -> Option<String> {
    let (ticket, mac_str) = value.rsplit_once('.')?;
    let expected = compute_ticket_mac(secret, user_id, ticket);
    let ok: bool = expected.as_bytes().ct_eq(mac_str.as_bytes()).into();
    if ok {
        Some(ticket.to_string())
    } else {
        None
    }
}

/// Returns `true` when the ticket submitted with the consent form equals the
/// one bound into the MAC-verified consent cookie.
///
/// Constant-time and length-blind ([`crate::core::ct_eq_secret_str`]); a
/// plain `!=` would return at the first differing byte.
fn cookie_ticket_matches(from_cookie: &str, submitted: &str) -> bool {
    crate::core::ct_eq_secret_str(from_cookie, submitted)
}

/// Lightweight non-consuming peek at a pending authorization ticket.
///
/// The engine's [`take_pending_authorization`] is single-use. For the
/// consent page render we want to read without consuming. We do that by
/// issuing a direct storage read through the engine's
/// `get_pending_authorization` extension defined below.
enum PeekErr {
    NotFound,
    Expired,
    Storage,
}

fn peek_pending(
    state: &Arc<WebState>,
    realm: &RealmId,
    ticket: &str,
) -> Result<PendingAuthorizationRequest, PeekErr> {
    state
        .identity
        .get_pending_authorization(realm, ticket)
        .map_err(|e| match e {
            IdentityError::ConsentTicketNotFound => PeekErr::NotFound,
            IdentityError::ConsentTicketExpired => PeekErr::Expired,
            _ => PeekErr::Storage,
        })
        .and_then(|opt| opt.ok_or(PeekErr::NotFound))
}

/// The JAR (RFC 9101) branch: verify the signed request object here —
/// consuming its `jti` — and take its claims as authoritative.
///
/// The merge is claim-wins, outer-value-fallback for `redirect_uri`,
/// `response_type`, `scope`, `state`, `code_challenge`, `nonce`,
/// `response_mode` and `prompt` (RFC 9101 §4); `code_challenge_method` and
/// the RFC 8707 `resource` come from the claims only (the outer query never
/// supplies either on this entry point). The merged request is then held to
/// the plain branch's rules: `response_type=code`, non-empty `state`, PKCE
/// `S256`, a registered `redirect_uri`, a supported `response_mode`.
///
/// This branch used to issue the code itself, skipping the consent prompt
/// and `prompt` handling; now it only builds the parameters and the shared
/// gates do the rest. JAR errors are never redirected (open-redirect risk):
/// each is a 400.
fn jar_params(
    state: &Arc<WebState>,
    realm: &RealmId,
    client: &crate::identity::OAuthClient,
    q: &AuthorizeQuery,
    request_jwt: &str,
) -> Result<AuthorizeParams, Response> {
    let client_id = client.client_id();
    let jar = match state.identity.verify_jar(realm, client_id, request_jwt) {
        Ok(jar) => jar,
        Err(e) => {
            tracing::warn!(error = %e, "authorize_get(JAR): request object rejected");
            return Err(handlers_common::bad_request("invalid request object"));
        }
    };
    // `verify_jar` checked the JAR's `iss` and `client_id` claims against the
    // client (RFC 9101 §4), in the client_id form the client was issued.

    let redirect_uri = jar.redirect_uri.unwrap_or_else(|| q.redirect_uri.clone());
    let response_type = jar.response_type.unwrap_or_else(|| q.response_type.clone());
    let state_param = jar.state.unwrap_or_else(|| q.state.clone());
    let code_challenge = jar
        .code_challenge
        .unwrap_or_else(|| q.code_challenge.clone());

    if response_type != "code" {
        return Err(handlers_common::bad_request("response_type must be 'code'"));
    }
    if state_param.is_empty() {
        return Err(handlers_common::bad_request(
            "state parameter is required for CSRF protection",
        ));
    }
    if !client.redirect_uris().iter().any(|u| u == &redirect_uri) {
        return Err(handlers_common::bad_request("invalid redirect_uri"));
    }
    let code_challenge_method = match jar.code_challenge_method.as_deref() {
        Some("S256") => Some(CodeChallengeMethod::S256),
        _ => None,
    };
    if code_challenge.is_empty() || code_challenge_method.is_none() {
        return Err(handlers_common::bad_request(
            "PKCE is required (code_challenge with code_challenge_method=S256)",
        ));
    }
    let Some(response_mode) =
        parse_response_mode(jar.response_mode.as_deref().or(q.response_mode.as_deref()))
    else {
        return Err(handlers_common::bad_request("unsupported response_mode"));
    };
    let resource = match jar.resource.as_deref() {
        None => None,
        Some(r) => Some(registered_resource_or_refusal(state, realm, r)?),
    };

    Ok(AuthorizeParams {
        client_id: client_id.clone(),
        redirect_uri,
        scope: jar.scope.unwrap_or_else(|| q.scope.clone()),
        state: state_param,
        code_challenge: Some(code_challenge),
        code_challenge_method,
        nonce: optional(&jar.nonce.unwrap_or_else(|| q.nonce.clone())),
        prompt: jar.prompt.unwrap_or_else(|| q.prompt.clone()),
        response_mode,
        resource,
        organization: jar
            .organization
            .or_else(|| q.organization.clone())
            .filter(|o| !o.is_empty()),
        // Set from the session by `authorize_get_impl`.
        mfa_proof: MfaProof::None,
    })
}

/// The canonical form of `resource` when it is a protected resource of the
/// realm; otherwise the 400 `invalid_target` a JAR or PAR request is refused
/// with (those branches never redirect an error).
fn registered_resource_or_refusal(
    state: &Arc<WebState>,
    realm: &RealmId,
    resource: &str,
) -> Result<String, Response> {
    match state.identity.canonical_protected_resource(realm, resource) {
        Ok(canonical) => Ok(canonical),
        Err(IdentityError::InvalidTarget { .. }) => Err(handlers_common::bad_request(
            "invalid_target: resource is not a registered protected resource",
        )),
        Err(e) => {
            tracing::warn!(error = %e, "authorize_get: resource lookup failed");
            Err(handlers_common::server_error())
        }
    }
}

/// Builds the redirect location string from an `AuthorizationResponse`.
///
/// Parameters travel per RFC 6749 §4.1.2 + RFC 9207 §4.1:
/// * `fragment` → hash-fragment delivery of `code`, `state`, `iss`
/// * `query` (default) → query-string delivery of `code`, `state`, `iss`
pub(super) fn build_authorization_redirect(
    redirect_uri: &str,
    resp: &crate::identity::AuthorizationResponse,
) -> String {
    match resp.response_mode() {
        ResponseMode::Fragment => append_fragment(
            redirect_uri,
            &[
                ("code", resp.code()),
                ("state", resp.state()),
                ("iss", resp.iss()),
            ],
        ),
        ResponseMode::Query => append_query(
            redirect_uri,
            &[
                ("code", resp.code()),
                ("state", resp.state()),
                ("iss", resp.iss()),
            ],
        ),
    }
}

/// Where an authorization error response goes, and in which mode.
///
/// Only ever built from a redirect URI already confirmed against the
/// client's registration (RFC 6749 §4.1.2.1).
pub(super) struct ErrorReturn<'a> {
    /// The registration-checked redirect URI.
    pub redirect_uri: &'a str,
    /// The request's `state`, echoed back.
    pub state: &'a str,
    /// The request's `response_mode` (`None` = default).
    pub response_mode: Option<&'a ResponseMode>,
}

/// Redirects an authorization error to the client in the mode its code
/// would have been delivered in ([`ResponseMode::effective`]): `fragment`
/// errors travel in the fragment.
///
/// OAuth Multiple Response Types §2.1 makes the response mode govern error
/// responses too. This used to put every error in the query string — so a
/// `fragment` request got its code in the fragment but `consent_required`
/// in the query.
///
/// RFC 9207 §2: an error carries the realm issuer as `iss`, exactly as a
/// successful response does, whenever the realm's discovery document
/// advertises `authorization_response_iss_parameter_supported`.
pub(super) fn authorization_error_redirect(
    state: &Arc<WebState>,
    realm: &RealmId,
    to: &ErrorReturn<'_>,
    error: &str,
    description: &str,
) -> Response {
    let mode = ResponseMode::effective(to.response_mode);
    let place: fn(&str, &[(&str, &str)]) -> String = if mode.uses_fragment() {
        append_fragment
    } else {
        append_query
    };
    // The issuer the realm's discovery document names — the value the
    // success path sends. A realm whose document cannot be built gets no
    // `iss` rather than a wrong one.
    let iss = match state.identity.realm_oidc_discovery(realm) {
        Ok(doc) if doc.authorization_response_iss_parameter_supported => doc.issuer,
        Ok(_) => String::new(),
        Err(e) => {
            tracing::warn!(error = %e, "authorization error: realm issuer unavailable");
            String::new()
        }
    };
    let location = place(
        to.redirect_uri,
        &[
            ("error", error),
            ("error_description", description),
            ("state", to.state),
            // Empty values are skipped by `append_query`/`append_fragment`.
            ("iss", &iss),
        ],
    );
    Redirect::to(&location).into_response()
}

/// Appends query parameters to a URI, choosing `?` vs `&` based on
/// whether the base already has a query string.
pub(super) fn append_query(base: &str, params: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(base.len() + 64);
    out.push_str(base);
    let mut first = !base.contains('?');
    for (k, v) in params {
        if v.is_empty() {
            continue;
        }
        out.push(if first { '?' } else { '&' });
        first = false;
        percent_encode_into(k, &mut out);
        out.push('=');
        percent_encode_into(v, &mut out);
    }
    out
}

/// Appends parameters to the fragment (hash) portion of a URI.
///
/// Used for `response_mode=fragment`. The
/// fragment is always appended after any existing query string, using `#`
/// as separator.  Per RFC 3986, the fragment is the last component and a URI
/// may have at most one `#`, so we always use `#` then `&` for subsequent params.
pub(super) fn append_fragment(base: &str, params: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(base.len() + 64);
    out.push_str(base);
    let mut first = true;
    for (k, v) in params {
        if v.is_empty() {
            continue;
        }
        out.push(if first { '#' } else { '&' });
        first = false;
        percent_encode_into(k, &mut out);
        out.push('=');
        percent_encode_into(v, &mut out);
    }
    out
}

/// Minimal percent-encoder for OAuth redirect parameters.
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

/// Appends a single consent audit event. Best-effort.
fn audit_consent_event(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    client_id: &ClientId,
    action: AuditAction,
    scopes: &[String],
    via: &'static str,
) {
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: user_id.as_uuid().to_string(),
        action,
        resource_type: "oauth_client".to_string(),
        resource_id: client_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({
            "via": via,
            "scopes": scopes,
            "client_id": client_id.as_uuid().to_string(),
        })),
    }) {
        tracing::warn!(error = %e, "consent audit append failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_cookie_detects_user_substitution() {
        let secret = CookieSecret::from_bytes([1u8; 32]);
        let u1 = UserId::generate();
        let u2 = UserId::generate();
        let ticket = "abc-123";
        let cookie_full = issue_ticket_cookie(&secret, &u1, ticket, false);
        // Extract raw value (strip the "name=" prefix and attributes).
        let raw = cookie_full
            .strip_prefix(&format!("{CONSENT_TICKET_COOKIE}="))
            .expect("prefix")
            .split(';')
            .next()
            .expect("value");
        assert_eq!(
            validate_ticket_cookie(&secret, &u1, raw).as_deref(),
            Some(ticket)
        );
        assert!(validate_ticket_cookie(&secret, &u2, raw).is_none());
    }

    #[test]
    fn submitted_ticket_matching_the_cookie_is_accepted() {
        assert!(cookie_ticket_matches("ticket-0123", "ticket-0123"));
    }

    #[test]
    fn submitted_ticket_same_length_mismatch_is_rejected() {
        assert!(!cookie_ticket_matches("ticket-0123", "ticket-0124"));
    }

    #[test]
    fn submitted_ticket_different_length_is_rejected() {
        assert!(!cookie_ticket_matches("ticket-0123", "ticket-012"));
        assert!(!cookie_ticket_matches("ticket-0123", "ticket-01234"));
        assert!(!cookie_ticket_matches("ticket-0123", ""));
    }

    #[test]
    fn ticket_cookie_detects_malformed() {
        let secret = CookieSecret::from_bytes([2u8; 32]);
        let u = UserId::generate();
        assert!(validate_ticket_cookie(&secret, &u, "").is_none());
        assert!(validate_ticket_cookie(&secret, &u, "no-dot").is_none());
        assert!(validate_ticket_cookie(&secret, &u, "ticket.badmac").is_none());
    }

    #[test]
    fn append_query_handles_existing_queries() {
        assert_eq!(
            append_query("https://app/cb", &[("code", "abc"), ("state", "xyz")]),
            "https://app/cb?code=abc&state=xyz"
        );
        assert_eq!(
            append_query(
                "https://app/cb?foo=bar",
                &[("code", "abc"), ("state", "xyz")]
            ),
            "https://app/cb?foo=bar&code=abc&state=xyz"
        );
    }

    #[test]
    fn append_query_skips_empty_values() {
        assert_eq!(
            append_query(
                "https://app/cb",
                &[("code", "abc"), ("state", ""), ("other", "v")]
            ),
            "https://app/cb?code=abc&other=v"
        );
    }

    #[test]
    fn append_query_percent_encodes_reserved() {
        let out = append_query("https://app/cb", &[("state", "a b&c=d")]);
        assert!(out.contains("state=a%20b%26c%3Dd"), "got: {out}");
    }

    #[test]
    fn append_fragment_uses_hash() {
        let out = append_fragment("https://app/cb", &[("code", "abc"), ("state", "xyz")]);
        assert_eq!(out, "https://app/cb#code=abc&state=xyz");
    }

    #[test]
    fn append_fragment_skips_empty_values() {
        let out = append_fragment("https://app/cb", &[("response", "jwt123"), ("extra", "")]);
        assert_eq!(out, "https://app/cb#response=jwt123");
    }

    #[test]
    fn build_redirect_plain_query_has_code_state_iss() {
        use crate::identity::oidc::AuthorizationResponse;
        let resp = AuthorizationResponse::new(
            "authcode".to_string(),
            "mystate".to_string(),
            "https://as.example.com".to_string(),
            "https://app/cb".to_string(),
        );
        let location = build_authorization_redirect("https://app/cb", &resp);
        assert!(location.contains("code=authcode"), "got: {location}");
        assert!(location.contains("state=mystate"), "got: {location}");
        assert!(location.contains("iss="), "got: {location}");
        assert!(!location.contains("response="), "got: {location}");
        assert!(
            location.contains('?'),
            "must use query string, got: {location}"
        );
    }
}
