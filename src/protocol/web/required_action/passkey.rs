//! Login-time passkey enrolment for a realm that requires a passkey
//! (`webauthn_required`).
//!
//! A user without a passkey reaches `GET /required-action/enroll-mfa` after
//! the password (and any second factor they already hold). The page runs a
//! WebAuthn registration against the two JSON endpoints here:
//!
//! | Route | Method | Purpose |
//! |-------|--------|---------|
//! | `/required-action/enroll-mfa/passkey/begin` | POST | Mint the registration challenge |
//! | `/required-action/enroll-mfa/passkey/complete` | POST | Verify and store the credential, then continue the login |
//!
//! Both require the RA session cookie and an `X-CSRF-Token` header equal to
//! the page's [`super::ra_form_token`] — the same RA-session-bound token
//! every `/required-action/*` form carries. User verification is required
//! whatever the realm's `webauthn_user_verification` policy: the credential
//! registered here is the factor a `webauthn_required` realm accepts, so a
//! touch-only one would never satisfy it. The RP ID and origin are pinned to
//! the configured public origin exactly as on the account page.
//!
//! The challenge is single-use (the engine's challenge store removes it on
//! redemption), bound to the user it was minted for (the engine refuses it
//! for anyone else), and bound to this RA session: `begin` sets
//! `hearth_ra_webauthn` = an HMAC of the RA session cookie and the
//! challenge, and `complete` refuses a challenge without the matching
//! cookie. On success the action is cleared and recorded completed, and the
//! RA flow continues with its proof raised to `MfaProof::ProvedWebAuthn`
//! (`RaClaims::record_verified_passkey`), which the browser-login session
//! created at the end records.

use std::sync::Arc;

use crate::protocol::client_info::PeerAddr;

use askama::Template;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::Deserialize;

use super::super::handlers_common;
use super::super::link_token::keyed_binding;
use super::super::templates::render;
use super::super::WebState;
use super::{
    advance_flow, clear_persisted_action, client_context, enroll_mfa_status, ra_form_token,
    read_ra_cookie, validated_ra_session, EnrollMfaStatus,
};
use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{Timestamp, UserId};
use crate::identity::{RegistrationOptions, RequiredAction};

/// Endpoint the page's script calls to start the registration.
const BEGIN_URL: &str = "/required-action/enroll-mfa/passkey/begin";
/// Endpoint the page's script posts the new credential to.
const COMPLETE_URL: &str = "/required-action/enroll-mfa/passkey/complete";
/// Cookie binding an issued challenge to the RA session that asked for it.
const BINDING_COOKIE: &str = "hearth_ra_webauthn";
/// Path [`BINDING_COOKIE`] is scoped to (both endpoints live under it).
const BINDING_PATH: &str = "/required-action/enroll-mfa/passkey";
/// HMAC purpose tag of [`BINDING_COOKIE`].
const BINDING_PURPOSE: &str = "hearth-ra-webauthn";
/// Lifetime of [`BINDING_COOKIE`]: the engine's challenge lifetime.
const BINDING_TTL_SECS: u32 = 300;

/// Rendered by `GET /required-action/enroll-mfa` when the realm requires a
/// passkey the user does not hold.
#[derive(Template)]
#[template(path = "ui/required_action/enroll_passkey.html")]
struct EnrollPasskeyTemplate {
    begin_url: &'static str,
    complete_url: &'static str,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    narrow: bool,
    flash: Option<super::super::templates::Flash>,
    /// The page's [`ra_form_token`], exposed to the script as the layout's
    /// `<meta name="csrf">`.
    csrf: Option<String>,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// Renders the passkey registration page.
pub(super) fn render_enroll_passkey_page(state: &Arc<WebState>, headers: &HeaderMap) -> Response {
    render(&EnrollPasskeyTemplate {
        begin_url: BEGIN_URL,
        complete_url: COMPLETE_URL,
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
    })
}

/// Whether the request's `X-CSRF-Token` is the page's [`ra_form_token`].
fn header_token_ok(state: &WebState, headers: &HeaderMap) -> bool {
    let submitted = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    ra_form_token(state, headers)
        .is_some_and(|expected| crate::core::ct_eq_secret_str(&expected, submitted))
}

/// The origin and RP ID pinned to the configured public origin — the same
/// derivation the account page's registration uses.
fn origin_and_rp_id(state: &WebState, headers: &HeaderMap) -> (String, String) {
    let origin = state.public_origin_str(headers);
    let rp_id = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string();
    (origin, rp_id)
}

/// [`BINDING_COOKIE`]'s value for `challenge_b64` issued in the RA session
/// `ra_token`.
fn binding_for(state: &WebState, ra_token: &str, challenge_b64: &str) -> String {
    keyed_binding(
        &state.cookie_secret,
        BINDING_PURPOSE,
        &format!("{ra_token}|{challenge_b64}"),
    )
}

fn binding_cookie(value: &str, max_age: u32, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{BINDING_COOKIE}={value}; HttpOnly; Path={BINDING_PATH}; SameSite=Strict; \
         Max-Age={max_age}{secure_attr}"
    )
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        "This page has expired. Reload it and try again.",
    )
        .into_response()
}

fn nothing_to_register() -> Response {
    (
        StatusCode::CONFLICT,
        "No passkey registration is pending for this sign-in.",
    )
        .into_response()
}

/// The pending user, when a passkey is what this RA session still owes.
fn pending_passkey_user(
    state: &Arc<WebState>,
    headers: &HeaderMap,
) -> Result<
    (
        crate::core::RealmId,
        crate::identity::ra_token::RaClaims,
        UserId,
    ),
    Response,
> {
    if read_ra_cookie(headers).is_none() {
        return Err(handlers_common::bad_request(
            "No active required-action session",
        ));
    }
    if !header_token_ok(state, headers) {
        return Err(forbidden());
    }
    let (realm, claims) = validated_ra_session(state, headers)?;
    if !claims.pending_actions.contains(&RequiredAction::EnrollMfa) {
        return Err(nothing_to_register());
    }
    let Ok(user_uuid) = uuid::Uuid::parse_str(&claims.sub) else {
        return Err(handlers_common::server_error());
    };
    let user_id = UserId::new(user_uuid);
    match enroll_mfa_status(state, &realm, &user_id) {
        Ok(EnrollMfaStatus::NeedsPasskey) => Ok((realm, claims, user_id)),
        Ok(_) => Err(nothing_to_register()),
        Err(()) => Err(handlers_common::server_error()),
    }
}

/// `POST /required-action/enroll-mfa/passkey/begin` — mints the registration
/// challenge and answers the `PublicKeyCredentialCreationOptions`.
pub async fn passkey_begin(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    let (realm, _claims, user_id) = match pending_passkey_user(&state, &headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let (_origin, rp_id) = origin_and_rp_id(&state, &headers);
    let resident_key = state
        .identity
        .get_realm(&realm)
        .ok()
        .flatten()
        .and_then(|r| r.config().webauthn_resident_key.clone())
        .unwrap_or_else(|| "preferred".to_string());
    let Ok(Some(user)) = state.identity.get_user(&realm, &user_id) else {
        return handlers_common::server_error();
    };
    let options = RegistrationOptions {
        rp_id: rp_id.clone(),
        discoverable: resident_key != "discouraged",
    };
    let challenge = match state
        .identity
        .start_webauthn_registration(&realm, &user_id, &options)
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "ra passkey_begin: start_webauthn_registration failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Registration unavailable",
            )
                .into_response();
        }
    };
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let challenge_b64 = b64.encode(&challenge);
    let body = serde_json::json!({
        "challenge": challenge_b64,
        "rp": { "id": rp_id, "name": state.product_name },
        "user": {
            "id": b64.encode(user_id.as_uuid().as_bytes()),
            "name": user.email(),
            "displayName": user.email(),
        },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },   // ES256
            { "type": "public-key", "alg": -257 }, // RS256
        ],
        "authenticatorSelection": {
            "residentKey": resident_key,
            "userVerification": "required",
        },
        "attestation": "none",
    });
    // INVARIANT: `pending_passkey_user` proved the RA cookie is present.
    let ra_token = read_ra_cookie(&headers).unwrap_or_default();
    let secure = state.is_secure_request(&headers);
    let mut resp = Json(body).into_response();
    append(
        &mut resp,
        &binding_cookie(
            &binding_for(&state, &ra_token, &challenge_b64),
            BINDING_TTL_SECS,
            secure,
        ),
    );
    resp
}

/// JSON body of `POST /required-action/enroll-mfa/passkey/complete`.
#[derive(Debug, Deserialize)]
pub struct PasskeyRegistrationBody {
    /// Base64url `clientDataJSON` from the authenticator.
    pub client_data_json: String,
    /// Base64url `attestationObject` from the authenticator.
    pub attestation_object: String,
    /// The credential's `getClientExtensionResults()`; the realm's
    /// attestation policy reads `largeBlob.supported` from it.
    #[serde(default)]
    pub client_extension_results: crate::identity::ClientExtensionResults,
}

/// `POST /required-action/enroll-mfa/passkey/complete` — verifies and stores
/// the credential (user verification required), clears the action, and
/// continues the login. Answers `{"next": "<url>"}` with the continuation's
/// cookies, for the page's script to navigate to.
pub async fn passkey_complete(
    State(state): State<Arc<WebState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Json(body): Json<PasskeyRegistrationBody>,
) -> Response {
    let (realm, mut claims, user_id) = match pending_passkey_user(&state, &headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (Ok(client_data_json), Ok(attestation_object)) = (
        b64.decode(&body.client_data_json),
        b64.decode(&body.attestation_object),
    ) else {
        return (StatusCode::BAD_REQUEST, "Malformed registration").into_response();
    };
    let Some(challenge_b64) = serde_json::from_slice::<serde_json::Value>(&client_data_json)
        .ok()
        .and_then(|v| {
            v.get("challenge")
                .and_then(|c| c.as_str())
                .map(str::to_string)
        })
    else {
        return (StatusCode::BAD_REQUEST, "Malformed registration").into_response();
    };

    // The challenge must have been issued to this RA session.
    let ra_token = read_ra_cookie(&headers).unwrap_or_default();
    let bound = super::super::auth::cookie_value_from_headers(&headers, BINDING_COOKIE)
        .is_some_and(|v| {
            crate::core::ct_eq_secret_str(v, &binding_for(&state, &ra_token, &challenge_b64))
        });
    if !bound {
        return forbidden();
    }

    let (origin, _rp_id) = origin_and_rp_id(&state, &headers);
    if let Err(e) = state.identity.complete_webauthn_registration_user_verified(
        &realm,
        &user_id,
        &client_data_json,
        &attestation_object,
        &origin,
        true,
        &body.client_extension_results,
    ) {
        tracing::warn!(error = %e, "ra passkey_complete: registration refused");
        return (StatusCode::BAD_REQUEST, "Registration failed").into_response();
    }

    clear_persisted_action(&state, &realm, &user_id, RequiredAction::EnrollMfa);
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: user_id.as_uuid().to_string(),
        action: AuditAction::RequiredActionCompleted,
        resource_type: "user".to_string(),
        resource_id: user_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "action_type": "ENROLL_MFA", "factor": "passkey" })),
    }) {
        tracing::warn!(error = %e, "ra passkey_complete: audit append failed");
    }

    let secure = state.is_secure_request(&headers);
    claims.record_verified_passkey();
    let now = Timestamp::from_micros(super::now_micros());
    let next = advance_flow(
        &state,
        &realm,
        claims,
        RequiredAction::EnrollMfa,
        &client_context(&state, &headers, peer_addr),
        secure,
        now,
    );
    as_json_continuation(&next, secure)
}

/// Re-expresses the continuation redirect `next` as `200 {"next": url}`
/// carrying the same cookies, since the page's `fetch` cannot surface a
/// redirect's `Location`.
fn as_json_continuation(next: &Response, secure: bool) -> Response {
    let Some(location) = next
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
    else {
        tracing::warn!(status = %next.status(), "ra passkey_complete: continuation did not redirect");
        return handlers_common::server_error();
    };
    let mut resp = Json(serde_json::json!({ "next": location })).into_response();
    for cookie in next.headers().get_all(header::SET_COOKIE) {
        resp.headers_mut()
            .append(header::SET_COOKIE, cookie.clone());
    }
    append(&mut resp, &binding_cookie("", 0, secure));
    resp
}

fn append(resp: &mut Response, set_cookie: &str) {
    if let Ok(v) = HeaderValue::from_str(set_cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
}
