//! The dev console (`/dev`): one page that signs a developer in.
//!
//! `make dev` logs its URL. The first visit creates the dev accounts
//! ([`crate::protocol::dev_accounts`]), so a fresh data directory needs no
//! bootstrap call. The page lists each account with:
//!
//! - a **Sign in** button that opens a browser session counted as having
//!   proved a second factor, so no TOTP code is typed;
//! - its password, TOTP secret (text and QR code) and the current code, for
//!   testing the real sign-in path;
//! - a fresh API access token and the realm ID for the admin API.
//!
//! `GET /dev/credentials` returns the same data in the `POST /admin/bootstrap`
//! response shape, for scripts and the UI test harness.
//!
//! Three gates, as for every dev endpoint (`protocol::http`): the routes are
//! compiled only into `dev-endpoints` builds, mounted only under `--dev`, and
//! answer only a loopback peer. A cross-site form post cannot sign the browser
//! in: [`sign_in`] refuses a request whose `Origin` names another site.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Router;

use crate::core::{RealmId, UserId};
use crate::identity::MfaProof;
use crate::protocol::client_info::{build_session_context, PeerAddr};
use crate::protocol::dev_accounts::{self, DevAccounts};

use super::auth::{issue_auth_cookies, revoke_prior_session_cookie, IssuedCookies};
use super::handlers::append_cookie;
use super::templates::render;
use super::WebState;

/// One dev account as the page shows it.
struct AccountView {
    /// Path segment of its sign-in route.
    key: &'static str,
    title: &'static str,
    email: &'static str,
    password: &'static str,
    realm_id: String,
    /// Where the account signs in with a password.
    login_url: String,
    totp_secret: String,
    totp_code: String,
    /// Inline SVG of the `otpauth://` URI; empty when there is no factor.
    totp_qr_svg: String,
    access_token: String,
}

#[derive(Template)]
#[template(path = "dev/console.html")]
struct ConsoleTemplate {
    accounts: Vec<AccountView>,
    seconds_left: u64,
    error: Option<String>,
}

/// The `/dev` routes, behind the loopback guard. Mounted only under `--dev`.
pub(super) fn routes() -> Router<Arc<WebState>> {
    Router::new()
        .route("/dev", axum::routing::get(console))
        .route("/dev/codes", axum::routing::get(codes))
        .route("/dev/credentials", axum::routing::get(credentials))
        .route("/dev/sign-in/{account}", axum::routing::post(sign_in))
        .route_layer(axum::middleware::from_fn(
            crate::protocol::http::dev_loopback_only,
        ))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Seconds until the current 30-second TOTP step ends.
fn seconds_left(now: u64) -> u64 {
    30 - now % 30
}

/// The account behind a sign-in route segment: its realm and user.
fn account_target(accounts: &DevAccounts, key: &str) -> Option<(RealmId, UserId)> {
    match key {
        "console" => Some((
            crate::identity::keys::system_realm_id(),
            accounts.system_admin.clone(),
        )),
        "realm" => Some((accounts.realm_id.clone(), accounts.realm_admin.clone())),
        _ => None,
    }
}

/// A fresh `(access, refresh)` token pair for the account, from a session
/// that proved its second factor. Empty on failure; the page still works
/// without it.
fn token_pair(state: &WebState, realm_id: &RealmId, user_id: &UserId) -> (String, String) {
    let ctx = crate::identity::SessionContext {
        mfa_proof: MfaProof::Proved,
        ..Default::default()
    };
    state
        .identity
        .create_session(realm_id, user_id, &ctx)
        .and_then(|session| state.identity.issue_tokens(realm_id, user_id, session.id()))
        .map(|tokens| {
            (
                tokens.access_token().to_string(),
                tokens.refresh_token().to_string(),
            )
        })
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "dev console: token issuance failed");
            (String::new(), String::new())
        })
}

/// The account's TOTP secret, or empty.
fn totp_secret(state: &WebState, realm_id: &RealmId, user_id: &UserId) -> String {
    state
        .identity
        .dev_totp_secret(realm_id, user_id)
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "dev console: TOTP secret lookup failed");
            None
        })
        .unwrap_or_default()
}

fn account_view(
    state: &WebState,
    key: &'static str,
    accounts: &DevAccounts,
    now: u64,
) -> Option<AccountView> {
    let (realm_id, user_id) = account_target(accounts, key)?;
    let (title, email, password, login_url) = if key == "console" {
        (
            "Admin console",
            dev_accounts::SYSTEM_ADMIN_EMAIL,
            dev_accounts::SYSTEM_ADMIN_PASSWORD,
            "/ui/admin/login".to_string(),
        )
    } else {
        (
            "Realm admin (dev-realm)",
            dev_accounts::DEV_REALM_ADMIN_EMAIL,
            dev_accounts::DEV_REALM_ADMIN_PASSWORD,
            format!("/ui/realms/{}/login", dev_accounts::DEV_REALM_NAME),
        )
    };
    let totp_secret = totp_secret(state, &realm_id, &user_id);
    let totp_code = crate::identity::totp::code_at(&totp_secret, now).unwrap_or_default();
    let totp_qr_svg = if totp_secret.is_empty() {
        String::new()
    } else {
        super::account::generate_qr_svg(&crate::identity::totp::generate_provisioning_uri(
            &totp_secret,
            email,
            "Hearth (dev)",
        ))
    };
    Some(AccountView {
        key,
        title,
        email,
        password,
        realm_id: realm_id.as_uuid().to_string(),
        login_url,
        totp_secret,
        totp_code,
        totp_qr_svg,
        access_token: token_pair(state, &realm_id, &user_id).0,
    })
}

/// `GET /dev` — creates the dev accounts when missing, then lists them.
async fn console(State(state): State<Arc<WebState>>) -> Response {
    let now = unix_now();
    let (accounts, error) = match dev_accounts::ensure(state.identity.as_ref(), state.rbac.as_ref())
    {
        Ok(accounts) => (
            ["console", "realm"]
                .into_iter()
                .filter_map(|key| account_view(&state, key, &accounts, now))
                .collect(),
            None,
        ),
        Err(e) => {
            tracing::warn!(error = %e, "dev console: account setup failed");
            (
                Vec::new(),
                Some(format!(
                    "The dev accounts could not be set up: {e}. If this data directory \
                         predates the current code, run `make dev-reset` and reload."
                )),
            )
        }
    };
    let mut response = render(&ConsoleTemplate {
        accounts,
        seconds_left: seconds_left(now),
        error,
    });
    // Passwords and tokens: never cached.
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `GET /dev/codes` — the current TOTP codes, for the page's live refresh.
async fn codes(State(state): State<Arc<WebState>>) -> Response {
    let now = unix_now();
    let Ok(accounts) = dev_accounts::ensure(state.identity.as_ref(), state.rbac.as_ref()) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let code = |key: &str| {
        account_target(&accounts, key)
            .and_then(|(realm, user)| state.identity.dev_totp_secret(&realm, &user).ok().flatten())
            .and_then(|secret| crate::identity::totp::code_at(&secret, now))
            .unwrap_or_default()
    };
    let mut response = axum::Json(serde_json::json!({
        "console": code("console"),
        "realm": code("realm"),
        "seconds_left": seconds_left(now),
    }))
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `GET /dev/credentials` — the page's data in the `POST /admin/bootstrap`
/// response shape, for scripts and test harnesses. A token-less re-bootstrap
/// answers `401` once the accounts exist; this is how a harness gets tokens and
/// TOTP secrets for accounts that a visit to `/dev` set up.
async fn credentials(State(state): State<Arc<WebState>>) -> Response {
    let accounts = match dev_accounts::ensure(state.identity.as_ref(), state.rbac.as_ref()) {
        Ok(accounts) => accounts,
        Err(e) => {
            tracing::warn!(error = %e, "dev console: account setup failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let system = crate::identity::keys::system_realm_id();
    let (access_token, refresh_token) =
        token_pair(&state, &accounts.realm_id, &accounts.realm_admin);
    let (system_access_token, _) = token_pair(&state, &system, &accounts.system_admin);
    let mut response = axum::Json(serde_json::json!({
        "realm_id": accounts.realm_id.as_uuid().to_string(),
        "user_id": accounts.realm_admin.as_uuid().to_string(),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "admin_password": dev_accounts::SYSTEM_ADMIN_PASSWORD,
        "system_access_token": system_access_token,
        "system_realm_id": system.as_uuid().to_string(),
        "totp_secret": totp_secret(&state, &accounts.realm_id, &accounts.realm_admin),
        "admin_totp_secret": totp_secret(&state, &system, &accounts.system_admin),
    }))
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Whether the request's `Origin` is this server. A browser sends `Origin` on
/// every form post; one that names another site is a cross-site post that
/// would sign the victim's browser in as the dev admin.
fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        // Not a browser form post (curl, a test client).
        return true;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    origin == format!("http://{host}") || origin == format!("https://{host}")
}

/// `POST /dev/sign-in/{account}` — signs the browser in as a dev account
/// (`console` or `realm`), with the second factor counted as proved, and
/// redirects to where that account lands after a normal sign-in.
async fn sign_in(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer): PeerAddr,
    Path(account): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let accounts = match dev_accounts::ensure(state.identity.as_ref(), state.rbac.as_ref()) {
        Ok(accounts) => accounts,
        Err(e) => {
            tracing::warn!(error = %e, "dev console: account setup failed");
            return Redirect::to("/dev").into_response();
        }
    };
    let Some((realm_id, user_id)) = account_target(&accounts, &account) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let mut ctx = build_session_context(&headers, peer, &state.trusted_proxies);
    ctx.mfa_proof = MfaProof::Proved;
    // A-41: end the browser's previous session before issuing a new one.
    revoke_prior_session_cookie(state.identity.as_ref(), &headers, &state.cookie_secret);
    let session = match state.identity.create_session(&realm_id, &user_id, &ctx) {
        Ok(session) => session,
        Err(e) => {
            tracing::warn!(error = %e, "dev console: session creation failed");
            return Redirect::to("/dev").into_response();
        }
    };
    let secure = state.is_secure_request(&headers);
    let IssuedCookies {
        session_cookie,
        csrf_cookie,
    } = issue_auth_cookies(&state.cookie_secret, &realm_id, session.id(), secure);
    state.set_current_realm(realm_id.clone());

    let target = if account == "console" {
        "/ui/admin"
    } else {
        "/ui"
    };
    let mut response = Redirect::to(target).into_response();
    append_cookie(&mut response, &session_cookie);
    append_cookie(&mut response, &csrf_cookie);
    append_cookie(
        &mut response,
        &super::auth::last_realm_cookie(
            &super::auth::last_realm_value(state.identity.as_ref(), &realm_id),
            secure,
        ),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cross_site_origin_is_refused() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "127.0.0.1:8420".parse().expect("header"));
        assert!(same_origin(&h), "no Origin: not a browser form post");
        h.insert(
            header::ORIGIN,
            "http://127.0.0.1:8420".parse().expect("header"),
        );
        assert!(same_origin(&h));
        h.insert(
            header::ORIGIN,
            "https://evil.example".parse().expect("header"),
        );
        assert!(!same_origin(&h));
        h.remove(header::HOST);
        h.insert(
            header::ORIGIN,
            "http://127.0.0.1:8420".parse().expect("header"),
        );
        assert!(
            !same_origin(&h),
            "an Origin with no Host to match is refused"
        );
    }

    #[test]
    fn the_step_countdown_runs_from_30_to_1() {
        assert_eq!(seconds_left(60), 30);
        assert_eq!(seconds_left(61), 29);
        assert_eq!(seconds_left(89), 1);
    }
}
