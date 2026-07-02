//! Federation login handlers.
//!
//! * `GET  /ui/realms/{realm}/federation/begin?idp={name}` — builds an
//!   upstream authorize URL and 302s the browser to it.
//! * `GET  /ui/realms/{realm}/federation/callback?state=&code=` —
//!   completes the round-trip. Outcome decides what happens next:
//!   existing-link → new Hearth session; JIT → new user + session;
//!   ConfirmLink → HMAC-bound cookie + redirect to confirm page.
//! * `GET  /ui/federation/confirm-link?ticket={t}` — renders a page
//!   asking the user to enter their local password.
//! * `POST /ui/federation/confirm-link` — verifies the local password
//!   and persists the link.
//!
//! Audit events are emitted on every state-changing path — login
//! started, completed, account linked/unlinked, JIT provisioned.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{IdpId, RealmId, Timestamp, UserId};
use crate::identity::federation::{
    compute_confirm_ticket_mac, compute_federation_state_mac, verify_confirm_ticket_mac,
    verify_federation_state_mac, FederationOutcome, FederationService,
};
use crate::identity::SessionContext;
use crate::identity::{CreateUserRequest, IdentityError};

use super::auth;
use super::handlers_common;
use super::realm_resolver::{self, Resolved};
use super::templates::render;
use super::WebState;
use crate::abuse::redirect::validate_return_to;

/// Cookie carrying the confirm-link ticket to `/ui/federation/confirm-link`.
const CONFIRM_LINK_COOKIE: &str = "hearth_ui_fed_confirm";

/// Short-lived HttpOnly cookie binding the federation `state` to the originating
/// browser (A-48).  Planted at `begin`, verified and cleared at `callback`.
const FED_BIND_COOKIE: &str = "hearth_fed_bind";

/// Query-string parameters for `begin`.
#[derive(Debug, Deserialize)]
pub struct BeginQuery {
    /// Operator-assigned connector name (e.g., `"google"`).
    pub idp: String,
    /// Optional post-login return path inside the UI.
    #[serde(default)]
    pub return_to: Option<String>,
}

/// Query-string parameters for `callback` (GET, standard OIDC / GitHub).
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    /// The `state` Hearth generated on `begin`.
    pub state: String,
    /// The authorization code returned by the upstream.
    #[serde(default)]
    pub code: Option<String>,
    /// Error code returned by the upstream when the user denied the
    /// consent prompt (e.g., `access_denied`).
    #[serde(default)]
    pub error: Option<String>,
    /// RFC 9207 `iss` parameter — the issuer URL of the authorization server
    /// that produced this callback.  When present, validated against the
    /// expected issuer for the IdP connector (A-29 IdP-mixup defense).
    #[serde(default)]
    pub iss: Option<String>,
}

/// Form body for Apple Sign In `form_post` callback (POST).
///
/// Apple POSTs the authorization response instead of encoding it as query
/// params.  The optional `user` field is a JSON string present only on the
/// user's very first login; it contains the given/family name Apple sends
/// exactly once.
#[derive(Debug, Deserialize)]
pub struct CallbackForm {
    /// The `state` Hearth generated on `begin`.
    pub state: String,
    /// The authorization code.
    #[serde(default)]
    pub code: Option<String>,
    /// Upstream error code when the user denied consent.
    #[serde(default)]
    pub error: Option<String>,
    /// First-login-only user JSON: `{"name":{"firstName":"...","lastName":"..."}}`.
    /// Absent on all subsequent logins.
    #[serde(default)]
    pub user: Option<String>,
}

/// `GET /ui/realms/{realm}/federation/begin?idp=...`
pub async fn begin_scoped(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Path(realm_name): Path<String>,
    Query(q): Query<BeginQuery>,
) -> Response {
    let realm_id = match realm_resolver::resolve(state.as_ref(), Some(&realm_name)) {
        Resolved::Realm(r) => r.id().clone(),
        Resolved::NotFound => return handlers_common::not_found("Realm not found"),
        Resolved::MustChoose(_) => return handlers_common::bad_request("Realm not specified"),
        Resolved::Storage => return handlers_common::server_error(),
    };
    begin_impl(state, &headers, realm_id, q).await
}

/// `GET /ui/federation/begin?idp=...` (bare — resolves default realm).
pub async fn begin(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Query(q): Query<BeginQuery>,
) -> Response {
    let realm_id = match realm_resolver::resolve(state.as_ref(), None) {
        Resolved::Realm(r) => r.id().clone(),
        Resolved::NotFound => return handlers_common::not_found("Realm not found"),
        Resolved::MustChoose(_) => return handlers_common::bad_request("Realm not specified"),
        Resolved::Storage => return handlers_common::server_error(),
    };
    begin_impl(state, &headers, realm_id, q).await
}

async fn begin_impl(
    state: Arc<WebState>,
    headers: &HeaderMap,
    realm_id: RealmId,
    q: BeginQuery,
) -> Response {
    let service = match build_service(&state) {
        Some(s) => s,
        None => return handlers_common::server_error(),
    };
    // A-52: validate return_to before storing in federation state bag.
    let return_to_raw = q.return_to.as_deref().unwrap_or("/ui/account");
    let return_to =
        validate_return_to(return_to_raw, &[]).unwrap_or_else(|| "/ui/account".to_string());
    let now = Timestamp::from_micros(now_micros());
    match service.begin(&realm_id, &q.idp, &return_to, now) {
        Ok((url, state_token)) => {
            audit_federation_started(&state, &realm_id, &q.idp);
            // A-48: plant session-binding cookie.  SameSite=Lax is required
            // because the IdP redirect is a top-level cross-origin navigation.
            let bind_mac = compute_federation_state_mac(cookie_secret_32(&state), &state_token);
            let secure = state.is_secure_request(headers);
            let secure_flag = if secure { "; Secure" } else { "" };
            let bind_cookie = format!(
                "{FED_BIND_COOKIE}={bind_mac}; HttpOnly; Path=/; SameSite=Lax; Max-Age=600{secure_flag}"
            );
            let mut resp = Redirect::to(url.as_str()).into_response();
            resp.headers_mut().insert(
                header::SET_COOKIE,
                header::HeaderValue::from_str(&bind_cookie)
                    .unwrap_or_else(|_| header::HeaderValue::from_static("")),
            );
            resp
        }
        Err(IdentityError::FederationUnknownConnector) => {
            handlers_common::not_found("Connector not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "federation begin failed");
            handlers_common::server_error()
        }
    }
}

/// `GET /ui/realms/{realm}/federation/callback?state=&code=`
pub async fn callback_scoped(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Path(realm_name): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let realm_id = match realm_resolver::resolve(state.as_ref(), Some(&realm_name)) {
        Resolved::Realm(r) => r.id().clone(),
        Resolved::NotFound => return handlers_common::not_found("Realm not found"),
        Resolved::MustChoose(_) => return handlers_common::bad_request("Realm not specified"),
        Resolved::Storage => return handlers_common::server_error(),
    };
    callback_impl(
        state, headers, realm_id, q.state, q.code, q.error, q.iss, None,
    )
    .await
}

/// `GET /ui/federation/callback`
pub async fn callback(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let realm_id = match realm_resolver::resolve(state.as_ref(), None) {
        Resolved::Realm(r) => r.id().clone(),
        Resolved::NotFound => return handlers_common::not_found("Realm not found"),
        Resolved::MustChoose(_) => return handlers_common::bad_request("Realm not specified"),
        Resolved::Storage => return handlers_common::server_error(),
    };
    callback_impl(
        state, headers, realm_id, q.state, q.code, q.error, q.iss, None,
    )
    .await
}

/// `POST /ui/realms/{realm}/federation/callback` — Apple Sign In `form_post`.
pub async fn callback_scoped_post(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Path(realm_name): Path<String>,
    Form(f): Form<CallbackForm>,
) -> Response {
    let realm_id = match realm_resolver::resolve(state.as_ref(), Some(&realm_name)) {
        Resolved::Realm(r) => r.id().clone(),
        Resolved::NotFound => return handlers_common::not_found("Realm not found"),
        Resolved::MustChoose(_) => return handlers_common::bad_request("Realm not specified"),
        Resolved::Storage => return handlers_common::server_error(),
    };
    callback_impl(
        state, headers, realm_id, f.state, f.code, f.error, None, f.user,
    )
    .await
}

/// `POST /ui/federation/callback` — Apple Sign In `form_post` (bare realm).
pub async fn callback_post(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(f): Form<CallbackForm>,
) -> Response {
    let realm_id = match realm_resolver::resolve(state.as_ref(), None) {
        Resolved::Realm(r) => r.id().clone(),
        Resolved::NotFound => return handlers_common::not_found("Realm not found"),
        Resolved::MustChoose(_) => return handlers_common::bad_request("Realm not specified"),
        Resolved::Storage => return handlers_common::server_error(),
    };
    callback_impl(
        state, headers, realm_id, f.state, f.code, f.error, None, f.user,
    )
    .await
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
async fn callback_impl(
    state: Arc<WebState>,
    headers: HeaderMap,
    realm_id: RealmId,
    state_token: String,
    code: Option<String>,
    error: Option<String>,
    iss: Option<String>,
    user_json: Option<String>,
) -> Response {
    if error.is_some() {
        // User denied consent at the upstream — quietly land on login.
        return Redirect::to("/ui/login?error=federation_denied").into_response();
    }

    let secure = state.is_secure_request(&headers);

    // A-48: verify session-binding cookie before touching storage.
    // Fail-closed: a missing or invalid cookie rejects the callback.
    {
        let cookie_hdr = headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let bind_mac = cookie_hdr.split(';').find_map(|part| {
            let part = part.trim();
            part.strip_prefix(&format!("{FED_BIND_COOKIE}="))
        });
        match bind_mac {
            Some(mac)
                if verify_federation_state_mac(cookie_secret_32(&state), &state_token, mac) => {}
            _ => {
                tracing::warn!(
                    "federation callback: missing or invalid state-binding cookie (A-48)"
                );
                return Redirect::to("/ui/login?error=federation_failed").into_response();
            }
        }
    }
    let Some(code) = code else {
        return handlers_common::bad_request("Missing code");
    };
    let service = match build_service(&state) {
        Some(s) => s,
        None => return handlers_common::server_error(),
    };
    // Look up the realm's LinkMode once. `federation_link_mode = None`
    // ≡ `LinkMode::Confirm` (Keycloak-equivalent safety default).
    let link_mode = match state.identity.get_realm(&realm_id) {
        Ok(Some(r)) => r
            .config()
            .federation_link_mode
            .unwrap_or(crate::identity::federation::LinkMode::Confirm),
        _ => crate::identity::federation::LinkMode::Confirm,
    };
    let now = Timestamp::from_micros(now_micros());
    let (bag, outcome) = match service
        .callback(
            &realm_id,
            &state_token,
            &code,
            iss.as_deref(),
            link_mode,
            now,
            user_json.as_deref(),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "federation callback failed");
            return Redirect::to("/ui/login?error=federation_failed").into_response();
        }
    };

    match outcome {
        FederationOutcome::ExistingUser(user_id) => {
            audit_federation_completed(&state, &realm_id, &bag.idp_id, &user_id, false);
            complete_login(&state, &headers, &realm_id, &user_id, &bag.return_to)
        }
        FederationOutcome::AutoLinked(user_id) => {
            audit_federation_linked(&state, &realm_id, &bag.idp_id, &user_id, "auto");
            audit_federation_completed(&state, &realm_id, &bag.idp_id, &user_id, true);
            complete_login(&state, &headers, &realm_id, &user_id, &bag.return_to)
        }
        FederationOutcome::JitProvision(identity) => {
            // Create a fresh user for this external identity.
            //
            // Fallback chain for display_name: upstreams that omit the
            // `profile` scope (or `name` claim entirely — e.g., Apple
            // Sign-In after the first consent, or any bare-minimum
            // `openid email` grant) leave `identity.display_name`
            // empty. The engine validator rejects an empty display
            // name, so synthesize one from the email local-part and
            // fall through to the external sub as the last resort.
            let email_taken = if identity.email.is_empty() {
                false
            } else {
                match state.identity.get_user_by_email(&realm_id, &identity.email) {
                    Ok(Some(_)) => true,
                    Ok(None) => false,
                    Err(e) => {
                        tracing::warn!(error = %e, "federation email collision lookup failed");
                        return handlers_common::server_error();
                    }
                }
            };
            let email = if identity.email.is_empty() || email_taken {
                // Synthesized email for providers that don't expose
                // one (GitHub private-email users, or minimal-scope
                // flows), and for "treat as separate" cases where the
                // upstream email collides with an existing local user.
                synthetic_federation_email(&bag.idp_id, &identity.external_sub)
            } else {
                identity.email.clone()
            };
            let display_name = if !identity.display_name.is_empty() {
                identity.display_name.clone()
            } else if let Some((local, _)) = email.split_once('@') {
                if local.is_empty() {
                    identity.external_sub.clone()
                } else {
                    local.to_string()
                }
            } else {
                identity.external_sub.clone()
            };
            let req = CreateUserRequest {
                email,
                display_name,
                first_name: identity.first_name.clone(),
                last_name: identity.last_name.clone(),
                attributes: Default::default(),
            };
            let new_user = match state.identity.create_user(&realm_id, &req) {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(error = %e, "JIT user create failed");
                    return handlers_common::server_error();
                }
            };
            if let Err(e) = service.after_jit_provision(
                &realm_id,
                new_user.id(),
                &identity.idp_id,
                &identity.external_sub,
            ) {
                tracing::warn!(error = %e, "JIT link failed");
                return handlers_common::server_error();
            }
            audit_federation_jit(&state, &realm_id, &identity.idp_id, new_user.id());
            audit_federation_linked(
                &state,
                &realm_id,
                &identity.idp_id,
                new_user.id(),
                "initial",
            );
            audit_federation_completed(&state, &realm_id, &identity.idp_id, new_user.id(), true);
            complete_login(&state, &headers, &realm_id, new_user.id(), &bag.return_to)
        }
        FederationOutcome::ConfirmLinkRequired(ticket) => {
            // Persist the HMAC-bound cookie and redirect.
            let tag = compute_confirm_ticket_mac(
                cookie_secret_32(&state),
                &ticket.user_id,
                &ticket.ticket,
            );
            let secure_flag = if secure { "; Secure" } else { "" };
            let cookie = format!(
                "{CONFIRM_LINK_COOKIE}={}.{tag}; HttpOnly; Path=/ui; SameSite=Lax; Max-Age=600{secure_flag}",
                ticket.ticket
            );
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert(
                header::SET_COOKIE,
                header::HeaderValue::from_str(&cookie)
                    .unwrap_or_else(|_| header::HeaderValue::from_static("")),
            );
            (
                resp_headers,
                Redirect::to(&format!(
                    "/ui/federation/confirm-link?ticket={}",
                    ticket.ticket
                )),
            )
                .into_response()
        }
    }
}

// ------ confirm-link flow ------

#[derive(Debug, Deserialize)]
pub struct ConfirmLinkQuery {
    pub ticket: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmLinkForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    pub ticket: String,
    pub password: String,
}

#[derive(Template)]
#[template(path = "ui/federation/confirm_link.html")]
#[allow(clippy::struct_excessive_bools)]
struct ConfirmLinkPage {
    ticket: String,
    external_email: String,
    idp_display_name: String,
    // Layout fields required by ui/_layout.html.
    chrome: bool,
    active: &'static str,
    narrow: bool,
    is_admin: bool,
    user_email: Option<String>,
    flash: Option<super::templates::Flash>,
    csrf: Option<String>,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// `GET /ui/federation/confirm-link?ticket=...`
pub async fn confirm_link_page(
    State(state): State<Arc<WebState>>,
    Query(q): Query<ConfirmLinkQuery>,
    headers: HeaderMap,
) -> Response {
    // Non-destructive read + cookie MAC check.
    let Some(cookie_val) = auth::cookie_value_from_headers(&headers, CONFIRM_LINK_COOKIE) else {
        return Redirect::to("/ui/login").into_response();
    };
    let Some((ticket_cookie, mac)) = cookie_val.rsplit_once('.') else {
        return Redirect::to("/ui/login").into_response();
    };
    if ticket_cookie != q.ticket {
        return Redirect::to("/ui/login").into_response();
    }
    // We don't know user_id yet (peek without consuming the engine
    // ticket). Peek by scanning — we want the user_id for MAC
    // verification, so read-through the engine.
    let realm_id = match realm_resolver::resolve(state.as_ref(), None) {
        Resolved::Realm(r) => r.id().clone(),
        _ => return Redirect::to("/ui/login").into_response(),
    };
    // Peek: get_pending isn't ideal (ticket is unrelated storage); we
    // do a second-path take-and-resave via a transient round-trip.
    // Simpler: call take, re-put immediately (idempotent write).
    let ticket_rec = match state
        .identity
        .take_confirm_link_ticket(&realm_id, &q.ticket)
    {
        Ok(r) => r,
        Err(_) => return Redirect::to("/ui/login").into_response(),
    };
    if !verify_confirm_ticket_mac(
        cookie_secret_32(&state),
        &ticket_rec.user_id,
        &ticket_rec.ticket,
        mac,
    ) {
        return Redirect::to("/ui/login").into_response();
    }
    // Re-put the ticket for the POST step.
    if state.identity.put_confirm_link_ticket(&ticket_rec).is_err() {
        return handlers_common::server_error();
    }
    let idp = state
        .identity
        .get_idp(&realm_id, &ticket_rec.identity.idp_id)
        .ok()
        .flatten();
    let tmpl = ConfirmLinkPage {
        ticket: ticket_rec.ticket.clone(),
        external_email: ticket_rec.identity.email.clone(),
        idp_display_name: idp
            .map(|c| c.display_name)
            .unwrap_or_else(|| "external IdP".to_string()),
        chrome: false,
        active: "login",
        narrow: true,
        is_admin: false,
        user_email: None,
        flash: None,
        csrf: None,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    };
    render(&tmpl)
}

/// `POST /ui/federation/confirm-link`
pub async fn confirm_link_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<ConfirmLinkForm>,
) -> Response {
    // Cookie + MAC check.
    let Some(cookie_val) = auth::cookie_value_from_headers(&headers, CONFIRM_LINK_COOKIE) else {
        return Redirect::to("/ui/login").into_response();
    };
    let Some((ticket_cookie, mac)) = cookie_val.rsplit_once('.') else {
        return Redirect::to("/ui/login").into_response();
    };
    if ticket_cookie != form.ticket {
        return Redirect::to("/ui/login").into_response();
    }
    let realm_id = match realm_resolver::resolve(state.as_ref(), None) {
        Resolved::Realm(r) => r.id().clone(),
        _ => return Redirect::to("/ui/login").into_response(),
    };
    let ticket_rec = match state
        .identity
        .take_confirm_link_ticket(&realm_id, &form.ticket)
    {
        Ok(r) => r,
        Err(_) => return Redirect::to("/ui/login").into_response(),
    };
    if !verify_confirm_ticket_mac(
        cookie_secret_32(&state),
        &ticket_rec.user_id,
        &ticket_rec.ticket,
        mac,
    ) {
        return Redirect::to("/ui/login").into_response();
    }
    // Verify local password.
    let cleartext = crate::identity::CleartextPassword::from_string(form.password);
    let ok = state
        .identity
        .verify_password(&realm_id, &ticket_rec.user_id, &cleartext)
        .unwrap_or(false);
    if !ok {
        // Redirect to login rather than back to the confirm-link page.
        // Returning to confirm-link with the ticket reveals that the ticket
        // was valid (enumeration resistance). The ticket was consumed by
        // take_confirm_link_ticket above, so the user must restart the
        // federation flow to try again.
        return Redirect::to("/ui/login?error=fed_link_failed").into_response();
    }
    // Link and complete.
    if let Err(e) = state.identity.link_external_identity(
        &realm_id,
        &ticket_rec.user_id,
        &ticket_rec.identity.idp_id,
        &ticket_rec.identity.external_sub,
    ) {
        tracing::warn!(error = %e, "link_external_identity failed");
        return handlers_common::server_error();
    }
    audit_federation_linked(
        &state,
        &realm_id,
        &ticket_rec.identity.idp_id,
        &ticket_rec.user_id,
        "confirm",
    );
    audit_federation_completed(
        &state,
        &realm_id,
        &ticket_rec.identity.idp_id,
        &ticket_rec.user_id,
        true,
    );
    complete_login(
        &state,
        &headers,
        &realm_id,
        &ticket_rec.user_id,
        "/ui/account",
    )
}

// ------ helpers ------

fn build_service(state: &WebState) -> Option<FederationService> {
    // Tests inject a stub transport via `WebState::with_federation_http`.
    // Production builds leave it `None` and fall through to the ureq-
    // backed implementation.
    let http: Arc<dyn crate::identity::federation::FederationHttpTransport> = state
        .federation_http
        .clone()
        .unwrap_or_else(|| Arc::new(crate::identity::federation::UreqFederationTransport));
    // Reuse the onboarding base_url — the same "public URL of this
    // Hearth server" that verification emails use. Federation callback
    // URLs have the same requirement (must match exactly what's
    // registered at the upstream IdP).
    let redirect_uri = state
        .config
        .as_ref()
        .and_then(|c| c.onboarding.base_url.clone())
        .unwrap_or_else(|| "http://localhost:8080".to_string())
        .trim_end_matches('/')
        .to_string()
        + "/ui/federation/callback";
    Some(FederationService::new(
        state.identity.clone(),
        http,
        redirect_uri,
    ))
}

fn complete_login(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    realm_id: &RealmId,
    user_id: &UserId,
    return_to: &str,
) -> Response {
    // Build a minimal session. The browser context is populated from
    // request headers in the standard login flow; for federation we
    // record what we can.
    let ctx = SessionContext::default();
    let session = match state.identity.create_session(realm_id, user_id, &ctx) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "create_session after federation failed");
            return handlers_common::server_error();
        }
    };
    let secure = state.is_secure_request(headers);
    let auth::IssuedCookies {
        session_cookie,
        csrf_cookie,
    } = auth::issue_auth_cookies(&state.cookie_secret, realm_id, session.id(), secure);
    state.set_current_realm(realm_id.clone());
    let mut response = Redirect::to(return_to).into_response();
    super::handlers::append_cookie(&mut response, &session_cookie);
    super::handlers::append_cookie(&mut response, &csrf_cookie);
    // A-48: clear the binding cookie — flow is complete.
    super::handlers::append_cookie(
        &mut response,
        &format!("{FED_BIND_COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0"),
    );
    response
}

fn now_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

fn synthetic_federation_email(idp_id: &IdpId, external_sub: &str) -> String {
    format!("{external_sub}@fed.{}.local", idp_id.as_uuid())
}

fn audit_federation_started(state: &Arc<WebState>, realm: &RealmId, idp_name: &str) {
    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: "anonymous".to_string(),
        action: AuditAction::FederationLoginStarted,
        resource_type: "federation_idp".to_string(),
        resource_id: idp_name.to_string(),
        metadata: None,
    });
}

fn audit_federation_completed(
    state: &Arc<WebState>,
    realm: &RealmId,
    idp: &IdpId,
    user: &UserId,
    linked_this_request: bool,
) {
    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: user.as_uuid().to_string(),
        action: AuditAction::FederationLoginCompleted,
        resource_type: "federation_idp".to_string(),
        resource_id: idp.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "linked_this_request": linked_this_request })),
    });
}

fn audit_federation_linked(
    state: &Arc<WebState>,
    realm: &RealmId,
    idp: &IdpId,
    user: &UserId,
    mode: &str,
) {
    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: user.as_uuid().to_string(),
        action: AuditAction::FederationAccountLinked,
        resource_type: "federation_idp".to_string(),
        resource_id: idp.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "mode": mode })),
    });
}

fn audit_federation_jit(state: &Arc<WebState>, realm: &RealmId, idp: &IdpId, user: &UserId) {
    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: user.as_uuid().to_string(),
        action: AuditAction::FederationJitProvisioned,
        resource_type: "federation_idp".to_string(),
        resource_id: idp.as_uuid().to_string(),
        metadata: None,
    });
}

/// Emits the unlink audit event — called from `account_linked.rs`.
pub(crate) fn audit_federation_unlinked(
    state: &Arc<WebState>,
    realm: &RealmId,
    idp: &IdpId,
    user: &UserId,
    via: &str,
) {
    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: user.as_uuid().to_string(),
        action: AuditAction::FederationAccountUnlinked,
        resource_type: "federation_idp".to_string(),
        resource_id: idp.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": via })),
    });
}

// Helper: pull the 32-byte cookie secret out of WebState. We can't add
// an inherent `fn` to `WebState` from a sibling module, so work via the
// `pub(super)` accessor exposed by `auth.rs`.
fn cookie_secret_32(state: &WebState) -> &[u8; 32] {
    auth::cookie_secret_bytes_32(&state.cookie_secret)
}
