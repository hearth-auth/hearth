//! One-time link tokens kept out of URLs (GA audit L18).
//!
//! Setup, email-verification, password-reset, magic-link, invitation and
//! required-action verification tokens reach the user in an emailed link, so
//! the first request has to carry them in the query string. Left there, the
//! token lands in browser history, in the `Referer` of anything the page
//! loads or links to, in every proxy's access log and — before PR #372 — in
//! Hearth's own request span, and the reset form echoed it into a hidden
//! field.
//!
//! [`stash`] is a per-route middleware for those routes. On a `GET` whose
//! query carries the token it answers at once — before the handler runs —
//! with `303 See Other` to the same path minus the token, and moves the token
//! into [`LINK_TOKEN_COOKIE`]: `HttpOnly`, `SameSite=Lax`, `Secure` over
//! TLS, scoped to exactly that path, and gone after
//! [`LINK_TOKEN_TTL_SECS`]. Handlers read the token only from the cookie,
//! via [`read`]; nothing reads it from the query any more.
//!
//! `SameSite=Lax`, not `Strict`: the first hop is a cross-site navigation
//! from a mail client, and browsers treat the redirect chain it starts as
//! cross-site, so a `Strict` cookie set on the first response would be
//! withheld on the second. `Lax` still withholds the cookie from every
//! cross-site `POST`, and the forms that spend a token additionally carry a
//! `link_binding` field — [`link_binding`], an HMAC of the token under the
//! cookie secret — so a forged `POST` cannot supply it even where `SameSite`
//! is not honoured.
//!
//! No `GET` on these routes spends a token. A mail scanner or link preview
//! fetches every URL in a message; a `GET` that verified the address, signed
//! the user in or joined the organization did so before the user clicked.
//! Verification, magic-link, invitation and required-action confirmation
//! pages therefore render a confirmation form, and the token is spent by its
//! `POST`, which must carry the binding and — on `/ui` routes — the CSRF
//! double-submit token ([`confirmed_token`]). Once a handler has spent the
//! token it marks the response with [`mark_spent`] and the middleware clears
//! the cookie. Every response on these routes carries
//! `Referrer-Policy: no-referrer`.

use std::sync::Arc;

use axum::extract::{OriginalUri, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::auth::{cookie_secret_bytes, cookie_value_from_headers, CookieSecret};
use super::WebState;
use crate::core::{ct_eq_secret_str, FormSecret};

/// Cookie that holds an emailed link's token after the first request.
pub const LINK_TOKEN_COOKIE: &str = "hearth_link_token";

/// Lifetime of [`LINK_TOKEN_COOKIE`]: long enough to fill in a form, short
/// enough that a forgotten tab does not keep a credential around.
pub const LINK_TOKEN_TTL_SECS: u64 = 900;

/// Longest value accepted as a token. Every token Hearth mints is far
/// shorter; the cap only keeps an absurd value out of a `Set-Cookie` header.
const MAX_TOKEN_LEN: usize = 2048;

/// Response marker a handler sets once it has spent (or definitively
/// rejected) the stashed token, so [`stash`] clears the cookie.
#[derive(Clone, Copy, Debug)]
pub struct LinkTokenSpent;

/// Marks `resp` so the link-token middleware clears the cookie.
#[must_use]
pub fn mark_spent(mut resp: Response) -> Response {
    resp.extensions_mut().insert(LinkTokenSpent);
    resp
}

/// Reads the stashed link token, if the browser sent one.
#[must_use]
pub fn read(headers: &HeaderMap) -> Option<FormSecret> {
    cookie_value_from_headers(headers, LINK_TOKEN_COOKIE)
        .filter(|v| !v.is_empty())
        .map(|v| FormSecret::new(v.to_string()))
}

/// The value a token-spending form carries in its `link_binding` field: a
/// base64url HMAC-SHA256 of `token` under the cookie secret.
///
/// A page served to the holder of the cookie can embed it; a cross-site
/// attacker, who can neither read the cookie nor compute the MAC, cannot.
#[must_use]
pub fn link_binding(secret: &CookieSecret, token: &str) -> String {
    // INVARIANT: HMAC-SHA256 accepts a key of any length.
    #[allow(clippy::unwrap_used)]
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(cookie_secret_bytes(secret)).unwrap();
    mac.update(b"hearth-link-binding|");
    mac.update(token.as_bytes());
    BASE64URL_NOPAD.encode(&mac.finalize().into_bytes())
}

/// Whether `submitted` is the binding for `token`, compared in constant time.
#[must_use]
pub fn binding_matches(secret: &CookieSecret, token: &str, submitted: &str) -> bool {
    ct_eq_secret_str(&link_binding(secret, token), submitted)
}

/// The stashed token behind a token-spending `POST`, or `None` when the
/// `POST` must be refused.
///
/// Requires the link cookie and a `link_binding` that matches it. With
/// `check_csrf`, the `_csrf` field must also match the `hearth_ui_csrf`
/// double-submit cookie; as on the login form, only `--dev` accepts a
/// request that sent no CSRF cookie at all. A refusal leaves the cookie in
/// place, so the genuine page still works.
#[must_use]
pub fn confirmed_token(
    state: &WebState,
    headers: &HeaderMap,
    link_binding: &str,
    csrf: &str,
    check_csrf: bool,
) -> Option<FormSecret> {
    if check_csrf {
        let csrf_ok = match super::auth::csrf_cookie_value_from_headers(headers) {
            Some(cookie) => super::auth::csrf_token_eq(cookie, csrf),
            None => state.dev_mode,
        };
        if !csrf_ok {
            return None;
        }
    }
    read(headers).filter(|t| binding_matches(&state.cookie_secret, t, link_binding))
}

/// Middleware for a route an emailed link lands on. See the module docs.
pub async fn stash(State(state): State<Arc<WebState>>, req: Request, next: Next) -> Response {
    // Nested routers strip their prefix from `req.uri()`; the cookie path and
    // the redirect need the path the browser actually requested.
    let path = req
        .extensions()
        .get::<OriginalUri>()
        .map_or_else(|| req.uri().path().to_string(), |u| u.0.path().to_string());
    let secure = state.is_secure_request(req.headers());
    let cookie_path_ok = is_cookie_safe_path(&path);

    if req.method() == Method::GET && cookie_path_ok {
        if let Some((token, other_params)) = req.uri().query().and_then(split_token) {
            return stash_redirect(&path, &other_params, &token, secure);
        }
    }

    let mut resp = next.run(req).await;
    if resp.extensions().get::<LinkTokenSpent>().is_some() && cookie_path_ok {
        append_header(&mut resp, header::SET_COOKIE, &clear_cookie(&path, secure));
    }
    resp.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}

/// Builds the first-hop answer: `303` to `path` (plus any other query
/// parameters) with the token moved into the cookie.
fn stash_redirect(path: &str, other_params: &str, token: &FormSecret, secure: bool) -> Response {
    let location = if other_params.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{other_params}")
    };
    let cookie = if is_cookie_safe_token(token) {
        set_cookie(path, token, secure)
    } else {
        // Not something Hearth minted. Clear any earlier stash so a stale
        // token is not spent on this click; the handler shows "invalid link".
        clear_cookie(path, secure)
    };
    let mut resp = StatusCode::SEE_OTHER.into_response();
    append_header(&mut resp, header::LOCATION, &location);
    append_header(&mut resp, header::SET_COOKIE, &cookie);
    let h = resp.headers_mut();
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Splits `token` out of a raw query string. Returns the (decoded) token and
/// the remaining parameters re-encoded, or `None` when there is no `token`.
fn split_token(query: &str) -> Option<(FormSecret, String)> {
    let mut token = None;
    let mut rest = form_urlencoded::Serializer::new(String::new());
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        if name == "token" {
            token.get_or_insert_with(|| FormSecret::new(value.into_owned()));
        } else {
            rest.append_pair(&name, &value);
        }
    }
    token.map(|t| (t, rest.finish()))
}

/// Characters a Hearth-minted token can contain (base64url, hex, base64 and
/// JWT alphabets). Anything else is not one of ours and would need escaping
/// inside a cookie.
fn is_cookie_safe_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
}

/// Whether `path` can be used verbatim as a cookie `Path` attribute and a
/// `Location` target.
fn is_cookie_safe_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-._~%".contains(&b))
}

/// `Set-Cookie` value that stashes `token` for `path`.
fn set_cookie(path: &str, token: &str, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{LINK_TOKEN_COOKIE}={token}; HttpOnly; Path={path}; SameSite=Lax; \
         Max-Age={LINK_TOKEN_TTL_SECS}{secure_attr}"
    )
}

/// `Set-Cookie` value that clears the stash for `path`.
fn clear_cookie(path: &str, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{LINK_TOKEN_COOKIE}=; HttpOnly; Path={path}; SameSite=Lax; Max-Age=0{secure_attr}")
}

fn append_header(resp: &mut Response, name: header::HeaderName, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        resp.headers_mut().append(name, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_token_decodes_the_token_and_keeps_the_rest() {
        let (token, rest) = split_token("a=1&token=ab%2Bc%3D&next=%2Fhome").expect("has token");
        assert_eq!(token.expose(), "ab+c=");
        assert_eq!(rest, "a=1&next=%2Fhome");
    }

    #[test]
    fn split_token_without_a_token_is_none() {
        assert!(split_token("next=%2Fhome&tokens=x").is_none());
    }

    #[test]
    fn split_token_drops_every_repeated_token() {
        let (token, rest) = split_token("token=first&token=second&x=1").expect("has token");
        assert_eq!(token.expose(), "first", "the first occurrence wins");
        assert_eq!(rest, "x=1", "no copy of the token survives in the redirect");
    }

    #[test]
    fn cookie_safe_tokens_are_the_minted_alphabets() {
        assert!(is_cookie_safe_token("aGVsbG8_d29ybGQ-"));
        assert!(is_cookie_safe_token(
            "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln"
        ));
        assert!(is_cookie_safe_token("0123abcdef"));
        assert!(!is_cookie_safe_token(""));
        assert!(!is_cookie_safe_token("has space"));
        assert!(!is_cookie_safe_token("semi;colon"));
        assert!(!is_cookie_safe_token("quote\""));
        assert!(!is_cookie_safe_token(&"a".repeat(MAX_TOKEN_LEN + 1)));
    }

    #[test]
    fn cookie_safe_paths_reject_header_breaking_characters() {
        assert!(is_cookie_safe_path("/ui/realms/acme/reset-password"));
        assert!(is_cookie_safe_path("/required-action/VERIFY_EMAIL/confirm"));
        assert!(!is_cookie_safe_path("//evil.test/ui"));
        assert!(!is_cookie_safe_path("/ui/realms/a;b/reset-password"));
        assert!(!is_cookie_safe_path("ui/relative"));
    }

    #[test]
    fn stash_and_clear_cookies_are_scoped_and_hardened() {
        let set = set_cookie("/ui/magic-link", "tok", true);
        assert_eq!(
            set,
            "hearth_link_token=tok; HttpOnly; Path=/ui/magic-link; SameSite=Lax; \
             Max-Age=900; Secure"
        );
        let clear = clear_cookie("/ui/magic-link", false);
        assert_eq!(
            clear,
            "hearth_link_token=; HttpOnly; Path=/ui/magic-link; SameSite=Lax; Max-Age=0"
        );
    }

    #[test]
    fn binding_is_keyed_and_token_specific() {
        let a = CookieSecret::from_bytes([1u8; 32]);
        let b = CookieSecret::from_bytes([2u8; 32]);
        let bind = link_binding(&a, "token-1");
        assert!(binding_matches(&a, "token-1", &bind));
        assert!(!binding_matches(&a, "token-2", &bind), "another token");
        assert!(!binding_matches(&b, "token-1", &bind), "another secret");
        assert!(!binding_matches(&a, "token-1", ""), "empty submission");
        assert!(
            !bind.contains("token-1"),
            "the binding does not reveal the token"
        );
    }

    #[test]
    fn read_ignores_an_empty_cookie() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("hearth_link_token=; other=1"),
        );
        assert!(read(&h).is_none());
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("other=1; hearth_link_token=abc"),
        );
        assert_eq!(read(&h).as_deref(), Some("abc"));
    }
}
