//! Federation login handlers.
//!
//! * `GET  /ui/realms/{realm}/federation/begin?idp={name}` — builds an
//!   upstream authorize URL and 302s the browser to it.
//! * `GET  /ui/realms/{realm}/federation/callback?state=&code=` —
//!   completes the round-trip. Outcome decides what happens next:
//!   existing-link → new Hearth session; JIT → new user + session;
//!   ConfirmLink → HMAC-bound cookie + redirect to confirm page.
//! * `GET  /ui/realms/{realm}/federation/confirm-link` — renders a
//!   page asking the user to enter their local password. The unscoped
//!   `/ui/federation/confirm-link` twin resolves the default realm and exists
//!   only for single-realm deployments (22.19).
//! * `POST /ui/realms/{realm}/federation/confirm-link` — verifies the local
//!   password and persists the link.
//!
//! Audit events are emitted on every state-changing path — login
//! started, completed, account linked/unlinked, JIT provisioned.

use std::net::SocketAddr;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{FormSecret, IdpId, RealmId, Timestamp, UserId};
use crate::identity::federation::{
    compute_confirm_ticket_mac, compute_federation_state_mac, verify_confirm_ticket_mac,
    verify_federation_state_mac, FederationOutcome, FederationService,
};
use crate::identity::SessionContext;
use crate::identity::{CreateUserRequest, IdentityError, UserStatus};
use crate::protocol::client_info::{build_session_context, PeerAddr};

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
    let (realm_id, realm_name) = match realm_resolver::resolve(state.as_ref(), Some(&realm_name)) {
        Resolved::Realm(r) => (r.id().clone(), r.name().to_string()),
        Resolved::NotFound => return handlers_common::not_found("Realm not found"),
        Resolved::MustChoose(_) => return handlers_common::bad_request("Realm not specified"),
        Resolved::Storage => return handlers_common::server_error(),
    };
    begin_impl(state, &headers, realm_id, &realm_name, q).await
}

/// `GET /ui/federation/begin?idp=...` (bare — resolves default realm).
pub async fn begin(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Query(q): Query<BeginQuery>,
) -> Response {
    let (realm_id, realm_name) = match realm_resolver::resolve(state.as_ref(), None) {
        Resolved::Realm(r) => (r.id().clone(), r.name().to_string()),
        Resolved::NotFound => return handlers_common::not_found("Realm not found"),
        Resolved::MustChoose(_) => return handlers_common::bad_request("Realm not specified"),
        Resolved::Storage => return handlers_common::server_error(),
    };
    begin_impl(state, &headers, realm_id, &realm_name, q).await
}

async fn begin_impl(
    state: Arc<WebState>,
    headers: &HeaderMap,
    realm_id: RealmId,
    realm_name: &str,
    q: BeginQuery,
) -> Response {
    let service = match build_service(&state, realm_name) {
        Some(s) => s,
        None => return handlers_common::server_error(),
    };
    // A-52: validate return_to before storing in federation state bag.
    let return_to_raw = q.return_to.as_deref().unwrap_or("/ui/account");
    let return_to = validate_return_to(return_to_raw, state.allowed_return_to_origins())
        .unwrap_or_else(|| "/ui/account".to_string());
    let now = Timestamp::from_micros(now_micros());
    match service.begin(&realm_id, &q.idp, &return_to, now) {
        Ok((url, state_token)) => {
            audit_federation_started(&state, &realm_id, &q.idp);
            // A-48: plant session-binding cookie.  SameSite=Lax is required
            // because the IdP redirect is a top-level cross-origin navigation.
            //
            // 22.23 (audit 2026-08-28 §4.22#15): connectors that answer with
            // `response_mode=form_post` (Apple Sign In) come back as a
            // cross-site **POST**, and a SameSite=Lax cookie is NOT sent on a
            // cross-site POST — only on a top-level GET. With Lax the A-48
            // check below could never pass, so `callback_post` /
            // `callback_scoped_post` always bounced to
            // `/ui/login?error=federation_failed`. Those connectors get
            // `SameSite=None; Secure`, which browsers do send on a cross-site
            // POST. `None` without `Secure` is rejected outright by every
            // modern browser, so the flag is unconditional here — Apple
            // mandates an HTTPS redirect URI anyway.
            let bind_mac = compute_federation_state_mac(cookie_secret_32(&state), &state_token);
            let secure = state.is_secure_request(headers);
            let same_site = if uses_form_post_callback(&state, &realm_id, &q.idp) {
                "None; Secure"
            } else if secure {
                "Lax; Secure"
            } else {
                "Lax"
            };
            let bind_cookie = format!(
                "{FED_BIND_COOKIE}={bind_mac}; HttpOnly; Path=/; SameSite={same_site}; Max-Age=600"
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
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Path(realm_name): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let (realm_id, realm_name) = match realm_resolver::resolve(state.as_ref(), Some(&realm_name)) {
        Resolved::Realm(r) => (r.id().clone(), r.name().to_string()),
        Resolved::NotFound => return handlers_common::not_found("Realm not found"),
        Resolved::MustChoose(_) => return handlers_common::bad_request("Realm not specified"),
        Resolved::Storage => return handlers_common::server_error(),
    };
    callback_impl(
        state,
        headers,
        peer_addr,
        realm_id,
        &realm_name,
        q.state,
        q.code,
        q.error,
        q.iss,
        None,
    )
    .await
}

/// `GET /ui/federation/callback`
pub async fn callback(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let (realm_id, realm_name) = match realm_resolver::resolve(state.as_ref(), None) {
        Resolved::Realm(r) => (r.id().clone(), r.name().to_string()),
        Resolved::NotFound => return handlers_common::not_found("Realm not found"),
        Resolved::MustChoose(_) => return handlers_common::bad_request("Realm not specified"),
        Resolved::Storage => return handlers_common::server_error(),
    };
    callback_impl(
        state,
        headers,
        peer_addr,
        realm_id,
        &realm_name,
        q.state,
        q.code,
        q.error,
        q.iss,
        None,
    )
    .await
}

/// `POST /ui/realms/{realm}/federation/callback` — Apple Sign In `form_post`.
pub async fn callback_scoped_post(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Path(realm_name): Path<String>,
    Form(f): Form<CallbackForm>,
) -> Response {
    let (realm_id, realm_name) = match realm_resolver::resolve(state.as_ref(), Some(&realm_name)) {
        Resolved::Realm(r) => (r.id().clone(), r.name().to_string()),
        Resolved::NotFound => return handlers_common::not_found("Realm not found"),
        Resolved::MustChoose(_) => return handlers_common::bad_request("Realm not specified"),
        Resolved::Storage => return handlers_common::server_error(),
    };
    callback_impl(
        state,
        headers,
        peer_addr,
        realm_id,
        &realm_name,
        f.state,
        f.code,
        f.error,
        None,
        f.user,
    )
    .await
}

/// `POST /ui/federation/callback` — Apple Sign In `form_post` (bare realm).
pub async fn callback_post(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(f): Form<CallbackForm>,
) -> Response {
    let (realm_id, realm_name) = match realm_resolver::resolve(state.as_ref(), None) {
        Resolved::Realm(r) => (r.id().clone(), r.name().to_string()),
        Resolved::NotFound => return handlers_common::not_found("Realm not found"),
        Resolved::MustChoose(_) => return handlers_common::bad_request("Realm not specified"),
        Resolved::Storage => return handlers_common::server_error(),
    };
    callback_impl(
        state,
        headers,
        peer_addr,
        realm_id,
        &realm_name,
        f.state,
        f.code,
        f.error,
        None,
        f.user,
    )
    .await
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
async fn callback_impl(
    state: Arc<WebState>,
    headers: HeaderMap,
    peer_addr: SocketAddr,
    realm_id: RealmId,
    realm_name: &str,
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
    let service = match build_service(&state, realm_name) {
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

    complete_federation_outcome(
        &state,
        &headers,
        peer_addr,
        &realm_id,
        realm_name,
        &bag.idp_id,
        outcome,
        &bag.return_to,
        secure,
    )
}

/// Turns a [`FederationOutcome`] into the browser response that finishes the
/// login: a Hearth session for an existing or auto-linked user, JIT
/// provisioning followed by a session, or the confirm-to-link hop.
///
/// Shared with the SAML assertion consumer (`super::saml::sp_acs`, audit
/// 2026-08-28 §4.10#6 / §4.22#4). SAML asserts the identity through
/// `SamlSpService` instead of an OAuth code exchange, but everything from the
/// resolved outcome onward — linking policy, JIT user shape, audit events and
/// the session cookie — must be the same code, or the two protocols drift.
#[allow(clippy::too_many_lines)]
pub(super) fn complete_federation_outcome(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    peer_addr: SocketAddr,
    realm_id: &RealmId,
    realm_name: &str,
    bag_idp_id: &IdpId,
    outcome: FederationOutcome,
    return_to: &str,
    secure: bool,
) -> Response {
    // The realm's `cidr_policy` ("CIDRs permitted to authenticate") binds
    // federated logins too (GA audit M13). Checked before anything is
    // provisioned or linked, so a denied network cannot JIT-create an account.
    let client_ip = build_session_context(headers, peer_addr, &state.trusted_proxies).ip_address;
    if let Err(e) = state
        .identity
        .check_realm_network_policy(realm_id, client_ip.as_deref())
    {
        tracing::warn!(error = %e, "federation: refused by the realm's network policy");
        return Redirect::to("/ui/login?error=fed_link_failed").into_response();
    }
    match outcome {
        FederationOutcome::ExistingUser(user_id) => {
            audit_federation_completed(state, realm_id, bag_idp_id, &user_id, false);
            complete_login(state, headers, peer_addr, realm_id, &user_id, return_to)
        }
        FederationOutcome::AutoLinked(user_id) => {
            audit_federation_linked(state, realm_id, bag_idp_id, &user_id, "auto");
            audit_federation_completed(state, realm_id, bag_idp_id, &user_id, true);
            complete_login(state, headers, peer_addr, realm_id, &user_id, return_to)
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
                match state.identity.get_user_by_email(realm_id, &identity.email) {
                    Ok(Some(_)) => true,
                    Ok(None) => false,
                    Err(e) => {
                        tracing::warn!(error = %e, "federation email collision lookup failed");
                        return handlers_common::server_error();
                    }
                }
            };
            let synthetic = identity.email.is_empty() || email_taken;
            let email = if synthetic {
                // Synthesized email for providers that don't expose
                // one (GitHub private-email users, or minimal-scope
                // flows), and for "treat as separate" cases where the
                // upstream email collides with an existing local user.
                synthetic_federation_email(bag_idp_id, &identity.external_sub)
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
            // An upstream address is recorded as the account's only if the
            // upstream said it verified it; otherwise the account waits for
            // the address owner, as a self-registered one does (GA audit
            // round 3, G-3). It used to be created `Active` on whatever the
            // upstream named — an attacker's IdP could name the victim's
            // address and pre-create (and, through Hearth's SAML IdP,
            // assert) the victim's account. A synthesized address names
            // no mailbox and nobody, so that account is active, unverified.
            let created = if synthetic {
                state.identity.create_user(realm_id, &req)
            } else {
                state
                    .identity
                    .provision_federated_user(realm_id, &req, identity.email_verified)
            };
            let new_user = match created {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(error = %e, "JIT user create failed");
                    return handlers_common::server_error();
                }
            };
            if let Err(e) = state.identity.link_external_identity(
                realm_id,
                new_user.id(),
                &identity.idp_id,
                &identity.external_sub,
            ) {
                tracing::warn!(error = %e, "JIT link failed");
                return handlers_common::server_error();
            }
            audit_federation_jit(state, realm_id, &identity.idp_id, new_user.id());
            audit_federation_linked(state, realm_id, &identity.idp_id, new_user.id(), "initial");
            if new_user.status() == UserStatus::PendingVerification {
                return await_email_verification(state, headers, realm_id, realm_name, &new_user);
            }
            audit_federation_completed(state, realm_id, &identity.idp_id, new_user.id(), true);
            complete_login(
                state,
                headers,
                peer_addr,
                realm_id,
                new_user.id(),
                return_to,
            )
        }
        FederationOutcome::ConfirmLinkRequired(ticket) => {
            // Persist the HMAC-bound cookie and redirect.
            let tag = compute_confirm_ticket_mac(
                cookie_secret_32(state),
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
            // The ticket travels only in the cookie above, never in the
            // redirect URL, where history, `Referer` and proxy logs keep it
            // (GA audit L18).
            (
                resp_headers,
                Redirect::to(&format!("/ui/realms/{realm_name}/federation/confirm-link")),
            )
                .into_response()
        }
    }
}

// ------ confirm-link flow ------

#[derive(Debug, Deserialize)]
pub struct ConfirmLinkForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    pub ticket: String,
    pub password: FormSecret,
}

#[derive(Template)]
#[template(path = "ui/federation/confirm_link.html")]
#[allow(clippy::struct_excessive_bools)]
struct ConfirmLinkPage {
    ticket: String,
    /// Absolute path the confirm form POSTs to. Realm-scoped when the page was
    /// reached through `/ui/realms/{realm}/...` so the submit resolves the same
    /// realm the ticket lives in (22.19).
    form_action: String,
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

/// `GET /ui/realms/{realm}/federation/confirm-link`
///
/// The ticket is read from the HMAC-bound confirm cookie the callback set;
/// the redirect that lands here carries none (GA audit L18).
///
/// 22.19 (audit 2026-08-28 §4.22#11): the confirm-to-link ticket is stored
/// under the realm the federated login **started** in. The bare route below
/// resolves the *default* realm, so on a multi-realm deployment the ticket
/// lookup missed and every confirm-to-link hop bounced to `/ui/login`. The
/// federation callback now redirects here, carrying the originating realm in
/// the path.
pub async fn confirm_link_page_scoped(
    State(state): State<Arc<WebState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
) -> Response {
    confirm_link_page_impl(state, Some(realm_name), headers).await
}

/// `GET /ui/federation/confirm-link` (bare — resolves default realm).
pub async fn confirm_link_page(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    confirm_link_page_impl(state, None, headers).await
}

async fn confirm_link_page_impl(
    state: Arc<WebState>,
    realm_name: Option<String>,
    headers: HeaderMap,
) -> Response {
    // Non-destructive read + cookie MAC check. The cookie is
    // `{ticket}.{mac}`; the MAC binds the ticket to its user and is verified
    // below once the ticket record names that user.
    let Some(cookie_val) = auth::cookie_value_from_headers(&headers, CONFIRM_LINK_COOKIE) else {
        return Redirect::to("/ui/login").into_response();
    };
    let Some((ticket, mac)) = cookie_val.rsplit_once('.') else {
        return Redirect::to("/ui/login").into_response();
    };
    if ticket.is_empty() || mac.is_empty() {
        return Redirect::to("/ui/login").into_response();
    }
    // We don't know user_id yet (peek without consuming the engine
    // ticket). Peek by scanning — we want the user_id for MAC
    // verification, so read-through the engine.
    let realm_id = match realm_resolver::resolve(state.as_ref(), realm_name.as_deref()) {
        Resolved::Realm(r) => r.id().clone(),
        _ => return Redirect::to("/ui/login").into_response(),
    };
    // Peek without consuming: the POST step takes the ticket. (This used to
    // take it and re-put it, which a replicated single-use claim — G4 —
    // rightly refuses to take a second time.) The ticket comes from the
    // confirm cookie, never the URL (GA audit L18).
    let ticket_rec = match state.identity.get_confirm_link_ticket(&realm_id, ticket) {
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
    let idp = state
        .identity
        .get_idp(&realm_id, &ticket_rec.identity.idp_id)
        .ok()
        .flatten();
    let form_action = match realm_name.as_deref() {
        Some(name) => format!("/ui/realms/{name}/federation/confirm-link"),
        None => "/ui/federation/confirm-link".to_string(),
    };
    // 21.14 (audit 2026-08-28 §4.22#12): `ConfirmLinkForm` has always declared
    // a `_csrf` field, but the page never filled it in and the POST handler
    // never read it — the field parsed and was discarded. Mint a pre-auth CSRF
    // cookie here, the same way the login and reset-password forms do, so
    // `confirm_link_submit_impl` has something to compare against.
    let (csrf_value, csrf_cookie) = auth::fresh_csrf_cookie(state.is_secure_request(&headers));
    let tmpl = ConfirmLinkPage {
        ticket: ticket_rec.ticket.clone(),
        form_action,
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
        csrf: Some(csrf_value),
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    };
    let mut resp = render(&tmpl);
    if let Ok(v) = header::HeaderValue::from_str(&csrf_cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

/// `POST /ui/realms/{realm}/federation/confirm-link` (22.19).
pub async fn confirm_link_submit_scoped(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ConfirmLinkForm>,
) -> Response {
    confirm_link_submit_impl(state, Some(realm_name), headers, peer_addr, form).await
}

/// `POST /ui/federation/confirm-link` (bare — resolves default realm).
pub async fn confirm_link_submit(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Form(form): Form<ConfirmLinkForm>,
) -> Response {
    confirm_link_submit_impl(state, None, headers, peer_addr, form).await
}

/// Checks the local account's password before a confirm-link; `Err` is the
/// answer to send instead of linking.
///
/// This is an Argon2id op, so it runs on the shared KDF admission gate —
/// every pre-auth hash MUST join the one permit pool that bounds total
/// hashing work and sheds 503 on overload (audit 2026-08-28 §4.17#2 class;
/// HEA-1891/F3). A wrong password redirects to the login page rather than
/// back to the confirm-link page, which would reveal that the ticket was
/// valid (enumeration resistance); the ticket is already consumed, so the
/// user restarts the federation flow. A locked account is told it is locked
/// (GA sweep 4 round 2).
async fn verify_link_password(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    realm_id: &RealmId,
    user_id: &UserId,
    password: &FormSecret,
) -> Result<(), Response> {
    let cleartext = crate::identity::CleartextPassword::new(password.as_bytes().to_vec());
    let (identity, realm, user) = (state.identity.clone(), realm_id.clone(), user_id.clone());
    match crate::identity::gate()
        .run(move || identity.verify_password(&realm, &user, &cleartext))
        .await
    {
        Ok(Ok(true)) => Ok(()),
        Ok(Err(crate::identity::IdentityError::RateLimited)) => {
            Err(locked_account_response(state, realm_id, user_id))
        }
        Err(crate::identity::KdfGateError::Overloaded { retry_after }) => Err(
            super::handlers::kdf_shed_html_response(state, headers, retry_after, None, None, None),
        ),
        other => {
            if let Err(crate::identity::KdfGateError::Join(e)) = other {
                tracing::warn!(error = %e, "confirm-link verify_password KDF task panicked");
            }
            Err(Redirect::to("/ui/login?error=fed_link_failed").into_response())
        }
    }
}

/// The confirm-link answer for an account whose login lockout refused the
/// password: `429` with `Retry-After` and a lockout message (GA sweep 4
/// round 2). It used to read as a wrong password.
fn locked_account_response(state: &WebState, realm_id: &RealmId, user_id: &UserId) -> Response {
    let retry_after =
        crate::identity::password_retry_after(state.identity.as_ref(), realm_id, user_id);
    let mut resp = handlers_common::too_many_requests(
        state,
        "Too many failed sign-in attempts for this account. Wait a few minutes, then sign in \
         with your identity provider again.",
    );
    crate::protocol::step_up::set_retry_after(&mut resp, retry_after);
    resp
}

async fn confirm_link_submit_impl(
    state: Arc<WebState>,
    realm_name: Option<String>,
    headers: HeaderMap,
    peer_addr: SocketAddr,
    form: ConfirmLinkForm,
) -> Response {
    // 21.14 (audit §4.22#12): double-submit CSRF check, before the ticket is
    // consumed. The `_csrf` form field is compared in constant time against the
    // `hearth_ui_csrf` cookie the GET page set. Until this existed the field
    // deserialized and was thrown away, so a cross-origin form POST that
    // replayed a ticket needed nothing but the cookie the browser sends
    // anyway. Failing here does NOT burn the ticket — the user can reload the
    // confirm page and resubmit.
    match auth::csrf_cookie_value_from_headers(&headers) {
        Some(cookie) if auth::csrf_token_eq(cookie, form.csrf.as_str()) => {}
        _ => return auth::csrf_failure_response(),
    }

    // Cookie + MAC check.
    let Some(cookie_val) = auth::cookie_value_from_headers(&headers, CONFIRM_LINK_COOKIE) else {
        return Redirect::to("/ui/login").into_response();
    };
    let Some(mac) = confirm_cookie_mac_for(cookie_val, &form.ticket) else {
        return Redirect::to("/ui/login").into_response();
    };
    let realm_id = match realm_resolver::resolve(state.as_ref(), realm_name.as_deref()) {
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
    // The realm's network policy binds this login path too (GA audit M13).
    let client_ip = build_session_context(&headers, peer_addr, &state.trusted_proxies).ip_address;
    if state
        .identity
        .check_realm_network_policy(&realm_id, client_ip.as_deref())
        .is_err()
    {
        return Redirect::to("/ui/login?error=fed_link_failed").into_response();
    }
    if let Err(refusal) = verify_link_password(
        &state,
        &headers,
        &realm_id,
        &ticket_rec.user_id,
        &form.password,
    )
    .await
    {
        return refusal;
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
        peer_addr,
        &realm_id,
        &ticket_rec.user_id,
        "/ui/account",
    )
}

// ------ helpers ------

pub(super) fn build_service(state: &WebState, realm_name: &str) -> Option<FederationService> {
    // Tests inject a stub transport via `WebState::with_federation_http`.
    // Production builds leave it `None` and fall through to the ureq-
    // backed implementation.
    let http: Arc<dyn crate::identity::federation::FederationHttpTransport> = state
        .federation_http
        .clone()
        .unwrap_or_else(|| Arc::new(crate::identity::federation::UreqFederationTransport));
    // 22.16 (audit 2026-08-28 §4.22#8): the `redirect_uri` sent upstream is
    // realm-scoped and comes from the same seam the admin Identity Provider
    // page publishes, so the two strings cannot drift. Upstream IdPs compare
    // `redirect_uri` byte-for-byte against the registered value.
    let redirect_uri = state.federation_callback_url(realm_name);
    Some(FederationService::new(
        state.identity.clone(),
        http,
        redirect_uri,
    ))
}

/// Whether the named connector answers the authorization request with
/// `response_mode=form_post` (a cross-site POST back to Hearth) rather than a
/// redirect. Apple Sign In is the only such connector today.
///
/// Drives the `SameSite` attribute of the A-48 state-binding cookie: `Lax` is
/// not sent on a cross-site POST, so a form_post connector needs
/// `SameSite=None; Secure` or its callback can never authenticate (22.23).
/// A lookup failure answers `false` — the stricter cookie.
fn uses_form_post_callback(state: &WebState, realm_id: &RealmId, idp_name: &str) -> bool {
    matches!(
        state.identity.get_idp_by_name(realm_id, idp_name),
        Ok(Some(cfg)) if cfg.kind == crate::identity::federation::IdpKind::Apple
    )
}

fn complete_login(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    peer_addr: SocketAddr,
    realm_id: &RealmId,
    user_id: &UserId,
    return_to: &str,
) -> Response {
    let secure = state.is_secure_request(headers);
    // A-48: the binding cookie is cleared on every exit — the federation hop
    // is complete whether it ends in a session or in a challenge.
    let clear_bind = format!("{FED_BIND_COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0");

    let (Ok(Some(realm)), Ok(Some(user))) = (
        state.identity.get_realm(realm_id),
        state.identity.get_user(realm_id, user_id),
    ) else {
        tracing::warn!("federation: realm or user lookup failed after the upstream login");
        return handlers_common::server_error();
    };

    // The upstream IdP asserts ONE factor. The user's own second factor binds
    // exactly as after a password (GA audit B5): a TOTP, OTP or passkey the
    // user holds is challenged on every realm, not only on `mfa_required`
    // realms, and forced enrolment is offered only to a user who holds no
    // factor — this used to send every non-TOTP user on an `mfa_required`
    // realm to TOTP enrolment. The MFA pending cookie carries the proven
    // identity across the hop, exactly as the direct login does.
    let first = auth::FirstFactor::Credential;
    match super::second_factor::second_factor_step(state, &realm, &user, first) {
        Ok(Some(step)) => {
            let mut response = super::second_factor::redirect_to_second_factor(
                state,
                realm_id,
                user_id,
                step,
                first,
                Some(return_to),
                secure,
            );
            super::handlers::append_cookie(&mut response, &clear_bind);
            return response;
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(error = %e, "federation: second-factor lookup failed");
            return handlers_common::server_error();
        }
    }

    // Pending required actions bind a federated login too (GA audit M11).
    let now = Timestamp::from_micros(now_micros());
    if let Some(mut ra) = super::required_action::required_action_check_browser(
        state,
        realm_id,
        user_id,
        Some(return_to),
        // The upstream login is one factor; nothing was owed above.
        &build_session_context(headers, peer_addr, &state.trusted_proxies),
        auth::FirstFactor::Credential,
        headers,
        now,
    ) {
        state.set_current_realm(realm_id.clone());
        super::handlers::append_cookie(&mut ra, &clear_bind);
        return ra;
    }

    // Nothing owed: the realm asks for no second factor and the user holds
    // none, so the default (unproven) MFA context is correct. The engine
    // refuses it if either is untrue. The peer address feeds the realm's
    // network policy (GA audit M13).
    let ctx: SessionContext = build_session_context(headers, peer_addr, &state.trusted_proxies);
    // A-41: a federated login rotates the session like a password login —
    // any session the browser already holds is revoked before the new one.
    auth::revoke_prior_session_cookie(state.identity.as_ref(), headers, &state.cookie_secret);
    let session = match state.identity.create_session(realm_id, user_id, &ctx) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "create_session after federation failed");
            return handlers_common::server_error();
        }
    };
    let auth::IssuedCookies {
        session_cookie,
        csrf_cookie,
    } = auth::issue_auth_cookies(&state.cookie_secret, realm_id, session.id(), secure);
    state.set_current_realm(realm_id.clone());
    let mut response = Redirect::to(return_to).into_response();
    super::handlers::append_cookie(&mut response, &session_cookie);
    super::handlers::append_cookie(&mut response, &csrf_cookie);
    super::handlers::append_cookie(&mut response, &clear_bind);
    response
}

/// Sends a just-provisioned federated account whose address the upstream did
/// not verify the verification link, and shows the "check your email" page.
/// The account signs in through its link once the address owner has
/// verified it (GA audit round 3, G-3).
fn await_email_verification(
    state: &Arc<WebState>,
    headers: &HeaderMap,
    realm_id: &RealmId,
    realm_name: &str,
    user: &crate::identity::User,
) -> Response {
    let clear_bind = format!("{FED_BIND_COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0");
    let realm = match state.identity.get_realm(realm_id) {
        Ok(Some(r)) => r,
        Ok(None) | Err(_) => {
            tracing::warn!("federation: realm lookup failed after JIT provisioning");
            return handlers_common::server_error();
        }
    };
    let token = match state
        .identity
        .issue_email_verification_token(realm_id, user.id())
    {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "federation: verification token issue failed");
            return handlers_common::server_error();
        }
    };
    let action_prefix = format!("/ui/realms/{realm_name}");
    super::handlers::send_verification_email_off_path(
        state,
        &realm,
        user.email().to_string(),
        &token,
        &action_prefix,
        headers,
    );
    let mut response = Redirect::to(&format!("{action_prefix}/register/sent")).into_response();
    super::handlers::append_cookie(&mut response, &clear_bind);
    // This browser performed the federated login: a verification completed
    // here keeps the account's federated link; one completed anywhere else
    // activates the account without it (GA audit round 3, G-3).
    super::handlers::append_cookie(
        &mut response,
        &super::link_token::federated_origin_cookie(
            &state.cookie_secret,
            &token,
            state.is_secure_request(headers),
        ),
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
    crate::protocol::audit_log::record(
        state.audit.as_ref(),
        &CreateAuditEvent {
            realm_id: realm.clone(),
            actor: "anonymous".to_string(),
            action: AuditAction::FederationLoginStarted,
            resource_type: "federation_idp".to_string(),
            resource_id: idp_name.to_string(),
            metadata: None,
        },
    );
}

fn audit_federation_completed(
    state: &Arc<WebState>,
    realm: &RealmId,
    idp: &IdpId,
    user: &UserId,
    linked_this_request: bool,
) {
    crate::protocol::audit_log::record(
        state.audit.as_ref(),
        &CreateAuditEvent {
            realm_id: realm.clone(),
            actor: user.as_uuid().to_string(),
            action: AuditAction::FederationLoginCompleted,
            resource_type: "federation_idp".to_string(),
            resource_id: idp.as_uuid().to_string(),
            metadata: Some(serde_json::json!({ "linked_this_request": linked_this_request })),
        },
    );
}

fn audit_federation_linked(
    state: &Arc<WebState>,
    realm: &RealmId,
    idp: &IdpId,
    user: &UserId,
    mode: &str,
) {
    crate::protocol::audit_log::record(
        state.audit.as_ref(),
        &CreateAuditEvent {
            realm_id: realm.clone(),
            actor: user.as_uuid().to_string(),
            action: AuditAction::FederationAccountLinked,
            resource_type: "federation_idp".to_string(),
            resource_id: idp.as_uuid().to_string(),
            metadata: Some(serde_json::json!({ "mode": mode })),
        },
    );
}

fn audit_federation_jit(state: &Arc<WebState>, realm: &RealmId, idp: &IdpId, user: &UserId) {
    crate::protocol::audit_log::record(
        state.audit.as_ref(),
        &CreateAuditEvent {
            realm_id: realm.clone(),
            actor: user.as_uuid().to_string(),
            action: AuditAction::FederationJitProvisioned,
            resource_type: "federation_idp".to_string(),
            resource_id: idp.as_uuid().to_string(),
            metadata: None,
        },
    );
}

/// Emits the unlink audit event — called from `account_linked.rs`.
pub(crate) fn audit_federation_unlinked(
    state: &Arc<WebState>,
    realm: &RealmId,
    idp: &IdpId,
    user: &UserId,
    via: &str,
) {
    crate::protocol::audit_log::record(
        state.audit.as_ref(),
        &CreateAuditEvent {
            realm_id: realm.clone(),
            actor: user.as_uuid().to_string(),
            action: AuditAction::FederationAccountUnlinked,
            resource_type: "federation_idp".to_string(),
            resource_id: idp.as_uuid().to_string(),
            metadata: Some(serde_json::json!({ "via": via })),
        },
    );
}

// Helper: pull the 32-byte cookie secret out of WebState. We can't add
// an inherent `fn` to `WebState` from a sibling module, so work via the
// `pub(super)` accessor exposed by `auth.rs`.
fn cookie_secret_32(state: &WebState) -> &[u8; 32] {
    auth::cookie_secret_bytes_32(&state.cookie_secret)
}

/// Splits a `{ticket}.{mac}` confirm-link cookie and returns the MAC part when
/// the cookie's ticket equals the `supplied` one, `None` otherwise.
///
/// The ticket comparison is constant-time and length-blind
/// ([`crate::core::ct_eq_secret_str`]), so a probe cannot learn the cookie's
/// ticket byte by byte from response timing.
fn confirm_cookie_mac_for<'a>(cookie_val: &'a str, supplied: &str) -> Option<&'a str> {
    let (ticket_cookie, mac) = cookie_val.rsplit_once('.')?;
    crate::core::ct_eq_secret_str(ticket_cookie, supplied).then_some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TICKET: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn confirm_cookie_mac_is_returned_when_the_ticket_matches() {
        let cookie = format!("{TICKET}.the-mac");
        assert_eq!(confirm_cookie_mac_for(&cookie, TICKET), Some("the-mac"));
    }

    #[test]
    fn confirm_cookie_same_length_ticket_mismatch_is_rejected() {
        let cookie = format!("{TICKET}.the-mac");
        let forged = format!("{}0", &TICKET[..TICKET.len() - 1]);
        assert_eq!(forged.len(), TICKET.len());
        assert_ne!(forged, TICKET);
        assert_eq!(confirm_cookie_mac_for(&cookie, &forged), None);
    }

    #[test]
    fn confirm_cookie_different_length_ticket_is_rejected() {
        let cookie = format!("{TICKET}.the-mac");
        assert_eq!(
            confirm_cookie_mac_for(&cookie, &TICKET[..TICKET.len() - 1]),
            None
        );
        assert_eq!(confirm_cookie_mac_for(&cookie, &format!("{TICKET}0")), None);
        assert_eq!(confirm_cookie_mac_for(&cookie, ""), None);
    }

    #[test]
    fn confirm_cookie_without_a_mac_separator_is_rejected() {
        assert_eq!(confirm_cookie_mac_for(TICKET, TICKET), None);
    }

    /// The link-confirmation password is wiped on drop and never printed by
    /// `Debug` (GA audit L20).
    #[test]
    fn confirm_link_form_password_is_zeroized_and_redacted() {
        let form: ConfirmLinkForm =
            serde_urlencoded::from_str("ticket=t&password=CANARY-pw").expect("form parses");
        crate::core::secrets::assert_zeroize_on_drop(&form.password);
        assert_eq!(form.password.expose(), "CANARY-pw");
        let dbg = format!("{form:?}");
        assert!(!dbg.contains("CANARY"), "Debug leaked a secret: {dbg}");
    }
}
