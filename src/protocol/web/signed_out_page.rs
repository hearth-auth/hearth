//! The page a browser lands on after RP-initiated logout when there is no
//! post-logout redirect to follow (`rp-initiated-logout`). A browser used to
//! end on the API's `{"message":"logged out"}`.

use askama::Template;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use tracing::error;

/// The signed-out page. It has no inputs.
#[derive(Template)]
#[template(path = "ui/signed_out.html")]
struct SignedOutTemplate;

/// Returns `true` when the request's `Accept` header lists `text/html`, as a
/// browser navigation does.
pub(crate) fn accepts_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| {
            accept.split(',').any(|range| {
                range
                    .split(';')
                    .next()
                    .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/html"))
            })
        })
}

/// Renders the signed-out page as a `200`. A render failure answers the
/// JSON body the endpoint used to send: the logout itself has succeeded.
pub(crate) fn signed_out_page() -> Response {
    match SignedOutTemplate.render() {
        Ok(html) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "signed-out page render failed");
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({"message": "logged out"})),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accept(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT, value.parse().expect("header value"));
        h
    }

    #[test]
    fn a_browser_navigation_accepts_html() {
        assert!(accepts_html(&accept(
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )));
        assert!(accepts_html(&accept("TEXT/HTML; q=0.5")));
    }

    #[test]
    fn a_machine_client_does_not() {
        assert!(!accepts_html(&HeaderMap::new()));
        assert!(!accepts_html(&accept("application/json")));
        assert!(!accepts_html(&accept("*/*")));
        assert!(!accepts_html(&accept("text/html-fragment")));
    }
}
