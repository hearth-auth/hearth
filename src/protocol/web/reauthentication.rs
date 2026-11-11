//! Forced sign-in for `prompt=login` and `max_age` (OIDC Core §3.1.2.1, #782).
//!
//! A browser authorization request with `prompt=login`, or with a `max_age`
//! shorter than the time since the session's last completed interactive
//! sign-in, sends the user to the sign-in page before the code is issued.
//! With `prompt=none` such a request gets `login_required` instead.
//!
//! The forced sign-in is a normal sign-in: it opens a new session and revokes
//! the old one (session-id rotation, task 24.1). The sign-in page then returns
//! the browser to the same authorize request with a `hearth_reauth` marker.
//! The marker lets that one request through without a second forced sign-in.
//! It is:
//!
//! * signed with the cookie secret (HMAC-SHA256);
//! * bound to the realm and to every other parameter of the authorize request;
//! * short-lived ([`MARKER_TTL_SECS`]);
//! * accepted only when the session's sign-in completed after the marker was
//!   issued;
//! * single-use: its nonce is burned in durable storage when it is accepted,
//!   so a replay forces a sign-in again.

use std::sync::Arc;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::core::{RealmId, Timestamp};

use super::auth::{cookie_secret_bytes, login_url_for_realm, CookieSecret, UiSession};
use super::authorize_gate::{refuse_if_silent, AuthorizeParams};
use super::oauth_consent::{authorization_error_redirect, ErrorReturn};
use super::{handlers_common, WebState};

/// The query parameter that carries the marker back to the authorize request.
pub(super) const MARKER_PARAM: &str = "hearth_reauth";

/// How long a marker stays valid: the time the user has to sign in again.
pub(super) const MARKER_TTL_SECS: i64 = 600;

/// The prefix of a burned marker nonce in the single-use nonce store. It
/// keeps the marker nonces apart from the MFA pending-cookie nonces that
/// share the store.
const BURN_PREFIX: &str = "reauth:";

/// What the authorize request asks about the age of the sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SignInFreshness {
    /// `prompt` contains `login`.
    pub prompt_login: bool,
    /// The `max_age` parameter, in seconds.
    pub max_age: Option<i64>,
}

impl SignInFreshness {
    /// Reads `prompt` and the raw `max_age` value. `Err` when `max_age` is
    /// not a non-negative integer (OIDC Core §3.1.2.1).
    pub(super) fn parse(prompt: &str, max_age: Option<&str>) -> Result<Self, ()> {
        let max_age = match max_age.map(str::trim).filter(|v| !v.is_empty()) {
            None => None,
            Some(v) => Some(v.parse::<u32>().map_err(|_| ())?.into()),
        };
        Ok(Self {
            prompt_login: prompt.split_whitespace().any(|p| p == "login"),
            max_age,
        })
    }

    /// `true` when a session whose last sign-in completed at `authenticated_at`
    /// must sign in again before a code is issued at `now`.
    fn needs_sign_in(self, authenticated_at: Timestamp, now: Timestamp) -> bool {
        self.prompt_login
            || self.max_age.is_some_and(|secs| {
                now.as_micros().saturating_sub(authenticated_at.as_micros())
                    > secs.saturating_mul(1_000_000)
            })
    }
}

/// The fresh-entry sign-in freshness gate. `None` lets the request go on to
/// the other gates. `Some` is the response: `login_required` for a silent
/// request, else a `303` to the sign-in page.
///
/// `raw_query` is the authorize request's query string, the marker included.
pub(super) fn reauthentication_gate(
    state: &Arc<WebState>,
    realm: &RealmId,
    session: &UiSession,
    params: &AuthorizeParams,
    freshness: SignInFreshness,
    raw_query: &str,
    now: Timestamp,
) -> Option<Response> {
    if !freshness.needs_sign_in(session.authenticated_at, now) {
        return None;
    }
    let (binding, marker) = split_marker(raw_query);
    if let Some(marker) = marker {
        match admit_marker(state, realm, session, &binding, &marker, now) {
            Ok(true) => return None,
            Ok(false) => {}
            Err(()) => return Some(handlers_common::server_error()),
        }
    }
    if let Some(refusal) = refuse_if_silent(
        state,
        realm,
        &session.user_id,
        params,
        "login_required",
        "the request needs a new sign-in",
    ) {
        return Some(refusal);
    }
    Some(sign_in_redirect(state, realm, &binding, now))
}

/// Splits the marker out of `raw_query`. Returns the other parameters,
/// encoded again in their order (the value the marker is bound to), and the
/// marker.
fn split_marker(raw_query: &str) -> (String, Option<String>) {
    let mut marker = None;
    let mut rest = form_urlencoded::Serializer::new(String::new());
    for (k, v) in form_urlencoded::parse(raw_query.as_bytes()) {
        if k == MARKER_PARAM {
            marker = Some(v.into_owned());
        } else {
            rest.append_pair(&k, &v);
        }
    }
    (rest.finish(), marker)
}

/// The marker's MAC over the realm, its nonce, its issue time and the
/// request it is bound to. `None` only if HMAC refuses the key, which
/// HMAC-SHA256 never does for a 32-byte key.
fn marker_mac(
    secret: &CookieSecret,
    realm: &RealmId,
    nonce: &str,
    issued: i64,
    binding: &str,
) -> Option<String> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(cookie_secret_bytes(secret)).ok()?;
    mac.update(b"hearth-reauth|");
    mac.update(realm.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(nonce.as_bytes());
    mac.update(b"|");
    mac.update(issued.to_string().as_bytes());
    mac.update(b"|");
    mac.update(binding.as_bytes());
    Some(BASE64URL_NOPAD.encode(&mac.finalize().into_bytes()))
}

/// A new marker `{nonce}.{issued_micros}.{mac}` for the request `binding`.
fn issue_marker(
    secret: &CookieSecret,
    realm: &RealmId,
    binding: &str,
    now: Timestamp,
) -> Option<String> {
    let nonce = crate::core::random_secret_hex();
    let issued = now.as_micros();
    let mac = marker_mac(secret, realm, &nonce, issued, binding)?;
    Some(format!("{nonce}.{issued}.{mac}"))
}

/// `Ok(true)` when `marker` lets this request through: a valid signature
/// for this realm and request, not expired, issued before the session's last
/// sign-in completed, and not used before (the nonce is burned here).
/// `Ok(false)` for any other marker. `Err` when the nonce store fails.
fn admit_marker(
    state: &Arc<WebState>,
    realm: &RealmId,
    session: &UiSession,
    binding: &str,
    marker: &str,
    now: Timestamp,
) -> Result<bool, ()> {
    let mut parts = marker.splitn(3, '.');
    let (Some(nonce), Some(issued), Some(mac)) = (parts.next(), parts.next(), parts.next()) else {
        return Ok(false);
    };
    let Ok(issued) = issued.parse::<i64>() else {
        return Ok(false);
    };
    if nonce.len() != 32 || HEXLOWER.decode(nonce.as_bytes()).is_err() {
        return Ok(false);
    }
    let expected = marker_mac(&state.cookie_secret, realm, nonce, issued, binding).ok_or(())?;
    if !bool::from(expected.as_bytes().ct_eq(mac.as_bytes())) {
        return Ok(false);
    }
    let expires = issued.saturating_add(MARKER_TTL_SECS * 1_000_000);
    if now.as_micros() > expires || issued > now.as_micros() {
        return Ok(false);
    }
    // The user must have signed in after the marker was issued.
    if session.authenticated_at.as_micros() < issued {
        return Ok(false);
    }
    let expires_secs = u64::try_from(expires / 1_000_000).unwrap_or(0);
    match state
        .identity
        .redeem_mfa_nonce(realm, &format!("{BURN_PREFIX}{nonce}"), expires_secs)
    {
        Ok(first_use) => Ok(first_use),
        Err(e) => {
            tracing::warn!(error = %e, "authorize: burning a sign-in marker failed");
            Err(())
        }
    }
}

/// `303` to the realm's sign-in page. After the sign-in the page returns the
/// browser to the realm-scoped authorize request `binding` with a new marker.
fn sign_in_redirect(
    state: &Arc<WebState>,
    realm: &RealmId,
    binding: &str,
    now: Timestamp,
) -> Response {
    let realm_name = match state.identity.get_realm(realm) {
        Ok(Some(r)) => r.name().to_string(),
        Ok(None) => return handlers_common::not_found("Realm not found"),
        Err(e) => {
            tracing::warn!(error = %e, "authorize: realm lookup failed before a forced sign-in");
            return handlers_common::server_error();
        }
    };
    let Some(marker) = issue_marker(&state.cookie_secret, realm, binding, now) else {
        tracing::warn!("authorize: the re-authentication marker MAC failed");
        return handlers_common::server_error();
    };
    let mut resume = form_urlencoded::Serializer::new(binding.to_string());
    resume.append_pair(MARKER_PARAM, &marker);
    let return_to = format!(
        "/ui/realms/{realm_name}/oauth/authorize?{}",
        resume.finish()
    );
    let location = format!(
        "{}?{}",
        login_url_for_realm(Some(&realm_name)),
        form_urlencoded::Serializer::new(String::new())
            .append_pair("return_to", &return_to)
            .finish()
    );
    let Ok(location) = HeaderValue::try_from(location) else {
        return handlers_common::bad_request("invalid authorization request");
    };
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, location),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
    )
        .into_response()
}

/// The `invalid_request` error redirect for a `max_age` that is not a
/// non-negative integer.
pub(super) fn invalid_max_age(
    state: &Arc<WebState>,
    realm: &RealmId,
    params: &AuthorizeParams,
) -> Response {
    authorization_error_redirect(
        state,
        realm,
        &ErrorReturn {
            redirect_uri: &params.redirect_uri,
            state: &params.state,
            response_mode: params.response_mode.as_ref(),
        },
        "invalid_request",
        "max_age must be a non-negative integer",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_micros(secs * 1_000_000)
    }

    #[test]
    fn prompt_login_always_needs_a_sign_in() {
        let f = SignInFreshness::parse("login consent", None).expect("parse");
        assert!(f.needs_sign_in(at(100), at(100)));
    }

    #[test]
    fn max_age_counts_from_the_last_sign_in() {
        let f = SignInFreshness::parse("", Some("10")).expect("parse");
        assert!(
            !f.needs_sign_in(at(100), at(110)),
            "10 s old meets max_age=10"
        );
        assert!(f.needs_sign_in(at(100), at(111)), "11 s old does not");
    }

    #[test]
    fn max_age_zero_needs_a_sign_in_after_any_time() {
        let f = SignInFreshness::parse("", Some("0")).expect("parse");
        assert!(f.needs_sign_in(at(100), Timestamp::from_micros(100_000_001)));
    }

    #[test]
    fn no_prompt_and_no_max_age_needs_nothing() {
        let f = SignInFreshness::parse("consent", None).expect("parse");
        assert!(!f.needs_sign_in(at(0), at(1_000_000)));
    }

    #[test]
    fn a_bad_max_age_is_refused() {
        for bad in ["-1", "abc", "1.5"] {
            assert!(SignInFreshness::parse("", Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_marker_is_split_from_the_other_parameters() {
        let (binding, marker) = split_marker("a=1&hearth_reauth=m.1.x&b=two+words");
        assert_eq!(binding, "a=1&b=two+words");
        assert_eq!(marker.as_deref(), Some("m.1.x"));
    }

    #[test]
    fn the_marker_mac_binds_the_request_and_the_realm() {
        let secret = CookieSecret::from_bytes([7u8; 32]);
        let realm = RealmId::new(uuid::Uuid::new_v4());
        let other = RealmId::new(uuid::Uuid::new_v4());
        let mac = marker_mac(&secret, &realm, "n", 1, "a=1");
        assert_eq!(
            mac.as_deref().map(str::len),
            Some(43),
            "a 32-byte MAC, base64url"
        );
        assert_ne!(mac, marker_mac(&secret, &realm, "n", 1, "a=2"));
        assert_ne!(mac, marker_mac(&secret, &other, "n", 1, "a=1"));
        assert_ne!(mac, marker_mac(&secret, &realm, "n", 2, "a=1"));
    }
}
