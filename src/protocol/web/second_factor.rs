//! Second-factor routing after a first factor, and the passkey second-factor
//! challenge (GA audit 2026-09-28, findings B4 and B5).
//!
//! Every browser path that proves a first factor — the password form, a magic
//! link, a federated login, a passkey that proved possession only — asks
//! [`second_factor_step`] what the user still owes, and hands the browser to
//! that factor's challenge with the MFA pending cookie. Each path used to
//! decide this for itself, and each decided differently: the magic link asked
//! nothing, federation asked only on `mfa_required` realms and only about
//! TOTP, and none of them counted a passkey. A passkey-only user was therefore
//! treated as holding no factor: signed in on the password alone, or — on an
//! `mfa_required` realm — sent to forced TOTP enrolment, where whoever held
//! the password enrolled a TOTP of their own.
//!
//! The engine's `create_session` is the backstop: it refuses a session whose
//! `mfa_proof` proves nothing for a user who holds a factor. This module is
//! what turns that refusal into a challenge the user can answer.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;

use crate::core::{RealmId, UserId};
use crate::identity::{
    AuthenticationOptions, CompleteAuthenticationParams, IdentityError, MfaProof, Realm,
    SessionContext, User,
};
use crate::protocol::client_info::{build_session_context, PeerAddr};

use super::auth::{
    clear_mfa_pending_cookie, cookie_value_from_headers, issue_auth_cookies,
    issue_mfa_pending_cookie_after, parse_mfa_pending_cookie, revoke_prior_session_cookie,
    FirstFactor, IssuedCookies, MfaPending, MFA_PENDING_COOKIE,
};
use super::handlers::{append_cookie, otp_factor_for, OtpFactor, PasskeyLoginCompleteBody};
use super::templates::{render, Flash};
use super::WebState;

/// The second factor a login must clear after proving a first factor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SecondFactorStep {
    /// Challenge the enrolled TOTP (or a recovery code).
    Totp,
    /// Challenge an SMS or email OTP.
    Otp(OtpFactor),
    /// Challenge an enrolled passkey.
    Passkey,
    /// The realm mandates a second factor and the user holds none: force
    /// TOTP enrolment. Never chosen for a user who holds any factor.
    EnrolTotp,
}

impl SecondFactorStep {
    /// The page that runs this step.
    pub(super) fn path(self) -> &'static str {
        match self {
            Self::Totp => "/ui/mfa-challenge",
            Self::Otp(_) => "/ui/mfa-otp-challenge",
            Self::Passkey => "/ui/mfa-passkey-challenge",
            Self::EnrolTotp => "/ui/mfa-enroll-required",
        }
    }
}

/// The factor a login that ALREADY used a passkey still owes: TOTP, then an
/// OTP. The passkey itself is not offered again — proving the same
/// credential twice is still one factor. For the same reason an email OTP is
/// never the second factor of a login whose first was a magic link
/// (`first`, GA audit round 3, D-4): both prove the same inbox.
///
/// # Errors
///
/// A factor lookup failed; the caller must refuse rather than skip the factor.
pub(super) fn non_passkey_factor_step(
    state: &Arc<WebState>,
    realm: &Realm,
    user: &User,
    first: FirstFactor,
) -> Result<Option<SecondFactorStep>, IdentityError> {
    if state.identity.mfa_enabled(realm.id(), user.id())? {
        return Ok(Some(SecondFactorStep::Totp));
    }
    Ok(otp_factor_for(state, realm, user, first).map(SecondFactorStep::Otp))
}

/// Decides what `user` owes after a first factor that is not a passkey — a
/// password, a magic link, a federated login. `first` says which: after a
/// magic link an email OTP does not count (see [`non_passkey_factor_step`]).
/// A user whose only factor is then out of reach owes nothing here, and the
/// engine refuses the session (the factor they hold was not proved).
///
/// `Ok(None)` means nothing is owed here. A realm that requires MFA but does
/// not offer TOTP also answers `None`: the required-action gate injects the
/// OTP enrolment such a realm offers, and the engine's `mfa_required` gate
/// refuses the session if neither fires.
///
/// Order: a passkey first when the realm sets `webauthn_required` (no other
/// factor satisfies it), then TOTP, then an OTP, then a passkey. Forced
/// enrolment only when the user holds no factor at all.
///
/// # Errors
///
/// A factor lookup failed; the caller must refuse rather than skip the factor.
pub(super) fn second_factor_step(
    state: &Arc<WebState>,
    realm: &Realm,
    user: &User,
    first: FirstFactor,
) -> Result<Option<SecondFactorStep>, IdentityError> {
    let holds_passkey = state.identity.has_passkey_factor(realm.id(), user.id())?;
    if holds_passkey && realm.config().webauthn_required.unwrap_or(false) {
        return Ok(Some(SecondFactorStep::Passkey));
    }
    if let Some(step) = non_passkey_factor_step(state, realm, user, first)? {
        return Ok(Some(step));
    }
    if holds_passkey {
        return Ok(Some(SecondFactorStep::Passkey));
    }
    let realm_requires_mfa = realm.config().mfa_required.unwrap_or(false);
    // An absent `mfa_methods` restricts nothing, so TOTP is on offer.
    let realm_offers_totp = realm
        .config()
        .mfa_methods
        .as_ref()
        .is_none_or(|m| m.iter().any(|x| x == "totp"));
    if realm_requires_mfa
        && realm_offers_totp
        && !state.identity.has_second_factor(realm.id(), user.id())?
    {
        return Ok(Some(SecondFactorStep::EnrolTotp));
    }
    Ok(None)
}

/// Issues the MFA pending cookie for `user_id` (recording what proved its
/// first factor) and redirects to `step`.
pub(super) fn redirect_to_second_factor(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    user_id: &UserId,
    step: SecondFactorStep,
    first: FirstFactor,
    return_to: Option<&str>,
    secure: bool,
) -> Response {
    let cookie = issue_mfa_pending_cookie_after(
        &state.cookie_secret,
        realm_id,
        user_id,
        return_to,
        first,
        secure,
    );
    state.set_current_realm(realm_id.clone());
    tracing::debug!(
        step = step.path(),
        "login: routing to the user's second factor"
    );
    let mut response = Redirect::to(step.path()).into_response();
    append_cookie(&mut response, &cookie);
    response
}

/// Loads the realm and user a pending cookie names, and confirms the passkey
/// is the factor this login owes. `Err` is the response to return.
fn pending_passkey_login(
    state: &Arc<WebState>,
    pending: &MfaPending,
) -> Result<(Realm, User), Response> {
    let (Ok(Some(realm)), Ok(Some(user))) = (
        state.identity.get_realm(&pending.realm_id),
        state.identity.get_user(&pending.realm_id, &pending.user_id),
    ) else {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "Your sign-in has expired.",
        ));
    };
    // The pending cookie does not say which first factor minted it. A login
    // that already used this passkey (possession only) owes a DIFFERENT
    // factor and is routed there by `non_passkey_factor_step`; accepting the
    // same passkey again here would count one factor twice. So the passkey is
    // accepted only when it is the step this user owes after a first factor
    // that is not a passkey.
    match second_factor_step(state, &realm, &user, pending.first_factor) {
        Ok(Some(SecondFactorStep::Passkey)) => Ok((realm, user)),
        Ok(_) => Err(json_error(
            StatusCode::FORBIDDEN,
            "A passkey cannot complete this sign-in.",
        )),
        Err(e) => {
            tracing::warn!(error = %e, "mfa-passkey-challenge: factor lookup failed");
            Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Sign-in is unavailable right now.",
            ))
        }
    }
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

/// Reads and verifies the MFA pending cookie. `Err` is a 401 JSON response.
fn pending_from_headers(
    state: &Arc<WebState>,
    headers: &HeaderMap,
) -> Result<MfaPending, Response> {
    cookie_value_from_headers(headers, MFA_PENDING_COOKIE)
        .and_then(|raw| parse_mfa_pending_cookie(&state.cookie_secret, raw))
        .ok_or_else(|| json_error(StatusCode::UNAUTHORIZED, "Your sign-in has expired."))
}

/// Double-submit CSRF for the JSON endpoints: the `X-CSRF-Token` header must
/// match the `hearth_ui_csrf` cookie. Fail-closed outside dev mode, like the
/// sibling challenge forms.
fn csrf_ok(state: &Arc<WebState>, headers: &HeaderMap) -> bool {
    let submitted = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    match super::auth::csrf_cookie_value_from_headers(headers) {
        Some(cookie) => super::auth::csrf_token_eq(cookie, submitted),
        None => state.dev_mode,
    }
}

/// The RP ID for the configured public origin (scheme and port stripped).
fn rp_id_for(origin: &str) -> String {
    origin
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string()
}

/// Passkey second-factor challenge page.
#[derive(Template)]
#[template(path = "ui/mfa_passkey_challenge.html")]
struct MfaPasskeyChallengeTemplate {
    error: Option<String>,
    begin_url: &'static str,
    complete_url: &'static str,
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

/// `GET /ui/mfa-passkey-challenge` — the page that asks for the passkey.
///
/// Requires the MFA pending cookie. Mints a CSRF cookie when the visitor has
/// none, because the ceremony's two JSON calls carry it back as a header.
pub async fn mfa_passkey_challenge_form(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    let Some(pending) = cookie_value_from_headers(&headers, MFA_PENDING_COOKIE)
        .and_then(|raw| parse_mfa_pending_cookie(&state.cookie_secret, raw))
    else {
        return Redirect::to("/ui/login").into_response();
    };
    let secure = state.is_secure_request(&headers);
    let (csrf_value, fresh_cookie) = match super::auth::csrf_cookie_value_from_headers(&headers) {
        Some(existing) => (existing.to_string(), None),
        None => {
            let (val, cookie) = super::auth::fresh_csrf_cookie(secure);
            (val, Some(cookie))
        }
    };
    let tmpl = MfaPasskeyChallengeTemplate {
        error: None,
        begin_url: "/ui/mfa-passkey-challenge/begin",
        complete_url: "/ui/mfa-passkey-challenge/complete",
        chrome: false,
        active: "",
        user_email: None,
        is_admin: false,
        flash: None,
        csrf: Some(csrf_value),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url_for(&pending.realm_id),
        inline_theme_css: state.inline_theme_css(),
    };
    let mut response = render(&tmpl);
    if let Some(cookie) = fresh_cookie {
        append_cookie(&mut response, &cookie);
    }
    response
}

/// `POST /ui/mfa-passkey-challenge/begin` — mints an authentication challenge
/// bound to the pending user and lists that user's credentials.
pub async fn mfa_passkey_challenge_begin(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    use base64::Engine as _;

    let pending = match pending_from_headers(&state, &headers) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    if !csrf_ok(&state, &headers) {
        return json_error(StatusCode::FORBIDDEN, "Reload the page and try again.");
    }
    let (realm, user) = match pending_passkey_login(&state, &pending) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let rp_id = rp_id_for(&state.public_origin_str(&headers));
    let challenge = match state.identity.start_webauthn_authentication(
        realm.id(),
        Some(user.id()),
        &AuthenticationOptions {
            rp_id: rp_id.clone(),
        },
    ) {
        Ok(c) => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&c),
        Err(e) => {
            tracing::warn!(error = %e, "mfa-passkey-challenge: begin failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not start the passkey check.",
            );
        }
    };
    let allow_credentials: Vec<serde_json::Value> = match state
        .identity
        .list_webauthn_credentials(realm.id(), user.id())
    {
        Ok(creds) => creds
            .iter()
            .map(|c| serde_json::json!({ "type": "public-key", "id": c.credential_id_b64url() }))
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "mfa-passkey-challenge: credential listing failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not start the passkey check.",
            );
        }
    };
    let user_verification = realm
        .config()
        .webauthn_user_verification
        .clone()
        .unwrap_or_else(|| "preferred".to_string());
    Json(serde_json::json!({
        "challenge": challenge,
        "rpId": rp_id,
        "allowCredentials": allow_credentials,
        "userVerification": user_verification,
        "timeout": 300_000,
    }))
    .into_response()
}

/// Turns a redirect response (the required-action gate's) into the JSON
/// `{"redirect": ...}` shape the passkey script follows, keeping its cookies.
pub(super) fn redirect_as_json(redirect: &Response) -> Response {
    let location = redirect
        .headers()
        .get(axum::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("/ui/login")
        .to_string();
    let mut response = Json(serde_json::json!({ "redirect": location })).into_response();
    for cookie in redirect
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        append_cookie(&mut response, cookie);
    }
    response
}

/// Whether `response` sets the cookie `name` (to any value).
fn sets_cookie(response: &Response, name: &str) -> bool {
    response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|line| {
            line.split_once('=')
                .is_some_and(|(cookie_name, _)| cookie_name.trim() == name)
        })
}

/// `POST /ui/mfa-passkey-challenge/complete` — verifies the assertion against
/// the pending user's own credentials and completes the login.
#[allow(clippy::too_many_lines)] // one linear verification sequence
pub async fn mfa_passkey_challenge_complete(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Json(body): Json<PasskeyLoginCompleteBody>,
) -> Response {
    use base64::Engine as _;

    let pending = match pending_from_headers(&state, &headers) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    if !csrf_ok(&state, &headers) {
        return json_error(StatusCode::FORBIDDEN, "Reload the page and try again.");
    }
    let (realm, user) = match pending_passkey_login(&state, &pending) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (Ok(credential_id), Ok(client_data_json), Ok(authenticator_data), Ok(signature)) = (
        b64.decode(&body.credential_id),
        b64.decode(&body.client_data_json),
        b64.decode(&body.authenticator_data),
        b64.decode(&body.signature),
    ) else {
        return json_error(StatusCode::BAD_REQUEST, "Malformed passkey response.");
    };
    let user_handle = body.user_handle.as_deref().and_then(|h| b64.decode(h).ok());
    let origin = state.public_origin_str(&headers);
    let params = CompleteAuthenticationParams {
        credential_id: &credential_id,
        client_data_json: &client_data_json,
        authenticator_data: &authenticator_data,
        signature: &signature,
        user_handle: user_handle.as_deref(),
        origin: &origin,
    };
    let result = match state
        .identity
        .complete_webauthn_authentication(realm.id(), &params)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "mfa-passkey-challenge: assertion rejected");
            return json_error(StatusCode::UNAUTHORIZED, "Passkey check failed.");
        }
    };
    // The assertion must come from the PENDING user's own credential. The
    // challenge was minted for that user, and the engine checks the owner;
    // this check makes the binding explicit at the one place a session is
    // about to be issued.
    if result.user_id() != user.id() {
        tracing::warn!("mfa-passkey-challenge: assertion from another account's passkey");
        return json_error(StatusCode::UNAUTHORIZED, "Passkey check failed.");
    }

    // Single-use pending cookie, exactly as the TOTP and OTP challenges do.
    let exp_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_add(super::auth::MFA_PENDING_TTL_SECS);
    match state
        .identity
        .redeem_mfa_nonce(&pending.realm_id, &pending.nonce, exp_secs)
    {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            return json_error(StatusCode::UNAUTHORIZED, "Your sign-in has expired.");
        }
    }

    let secure = state.is_secure_request(&headers);
    let now = crate::core::Timestamp::from_micros(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_micros()).ok())
            .unwrap_or(0),
    );
    // A first factor (password, magic link, federated login) plus this
    // passkey is two factors. It is `ProvedWebAuthn` only when the
    // authenticator also proved user verification — the one proof a realm
    // with `webauthn_required` accepts (audit 2026-08-28 §4.18#3, B10).
    let session_ctx = SessionContext {
        mfa_proof: if result.user_verified() {
            MfaProof::ProvedWebAuthn
        } else {
            MfaProof::Proved
        },
        ..build_session_context(&headers, peer_addr, &state.trusted_proxies)
    };
    if let Some(ra) = super::required_action::required_action_check_browser(
        &state,
        realm.id(),
        user.id(),
        pending.return_to.as_deref(),
        &session_ctx,
        pending.first_factor,
        &headers,
        now,
    ) {
        state.set_current_realm(realm.id().clone());
        let mut response = redirect_as_json(&ra);
        // The pending cookie is spent — unless the answer routes this login
        // back to the passkey with a fresh one (a UV-less assertion on a
        // realm that requires user verification), which must survive.
        if !sets_cookie(&ra, MFA_PENDING_COOKIE) {
            append_cookie(&mut response, &clear_mfa_pending_cookie(secure));
        }
        return response;
    }

    revoke_prior_session_cookie(state.identity.as_ref(), &headers, &state.cookie_secret);
    match state
        .identity
        .create_session(realm.id(), user.id(), &session_ctx)
    {
        Ok(session) => {
            let IssuedCookies {
                session_cookie,
                csrf_cookie,
            } = issue_auth_cookies(&state.cookie_secret, realm.id(), session.id(), secure);
            state.set_current_realm(realm.id().clone());
            let location = pending.return_to.as_deref().unwrap_or("/ui");
            let mut response = Json(serde_json::json!({ "redirect": location })).into_response();
            append_cookie(&mut response, &session_cookie);
            append_cookie(&mut response, &csrf_cookie);
            append_cookie(&mut response, &clear_mfa_pending_cookie(secure));
            append_cookie(
                &mut response,
                &super::auth::last_realm_cookie(
                    &super::auth::last_realm_value(state.identity.as_ref(), realm.id()),
                    secure,
                ),
            );
            response
        }
        Err(e) => {
            tracing::warn!(error = %e, "mfa-passkey-challenge: create_session failed");
            json_error(StatusCode::UNAUTHORIZED, "Sign-in failed.")
        }
    }
}
