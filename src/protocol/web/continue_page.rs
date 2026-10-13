//! Ends a hosted form navigation on a Hearth page (`form-action-safe-sign-in`).
//!
//! The UI sends `Content-Security-Policy: form-action 'self'`. Browsers check
//! `form-action` against every URL of a navigation that a form submission
//! starts, redirects included. The sign-in, second-factor, required-action and
//! consent forms post to Hearth, and Hearth answers with a `303` chain that
//! ends on the client's `redirect_uri` — on another origin, so Chrome blocks
//! it. Any redirect the application makes after its callback is blocked too.
//!
//! [`end_form_navigation`] is a per-route layer for those POSTs. It replaces a
//! `303 See Other` with a `200` page that navigates to the same target through
//! a `Refresh: 0;url=…` header and a matching `<meta http-equiv="refresh">`,
//! and shows a link to it. The form navigation ends on that page; the refresh
//! is a new navigation that no form starts, so `form-action` no longer applies
//! to it or to anything after it. A document runs only its first declarative
//! refresh, so the header and the meta tag never navigate twice.
//!
//! The layer works on the outer response only. The handlers keep answering
//! `303`, because the passkey `fetch()` wrappers read the inner `Location`.

use askama::Template;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tracing::error;

/// The continue page: a refresh to `target` and a link to it.
#[derive(Template)]
#[template(path = "ui/continue.html")]
struct ContinueTemplate<'a> {
    /// The redirect target the page navigates to. Askama HTML-escapes it.
    target: &'a str,
}

/// Replaces the `303 See Other` of a hosted form `POST` with a `200` continue
/// page that navigates to the same target.
///
/// Every header of the redirect except `Location` is kept, so the cookies a
/// sign-in step sets or clears survive. A `GET`, and any status other than
/// `303`, passes through unchanged.
pub(crate) async fn end_form_navigation(req: Request, next: Next) -> Response {
    let is_post = req.method() == Method::POST;
    let resp = next.run(req).await;
    if !is_post || resp.status() != StatusCode::SEE_OTHER {
        return resp;
    }
    let Some(location) = resp.headers().get(header::LOCATION).cloned() else {
        return resp;
    };
    let Ok(target) = location.to_str() else {
        return resp;
    };
    let html = match (ContinueTemplate { target }).render() {
        Ok(html) => html,
        Err(err) => {
            // The redirect still works outside Chrome; keep it rather than
            // turn a sign-in into a 500.
            error!(error = %err, "continue page render failed");
            return resp;
        }
    };
    let mut refresh = Vec::with_capacity(6 + location.len());
    refresh.extend_from_slice(b"0;url=");
    refresh.extend_from_slice(location.as_bytes());
    let Ok(refresh) = HeaderValue::from_bytes(&refresh) else {
        return resp;
    };

    let (mut parts, _body) = resp.into_parts();
    parts.status = StatusCode::OK;
    parts.headers.remove(header::LOCATION);
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.insert(header::REFRESH, refresh);
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    Response::from_parts(parts, Body::from(html))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Method, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::Router;
    use tower::ServiceExt as _;

    fn redirect(location: &'static str) -> Response {
        let mut resp = (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response();
        let headers = resp.headers_mut();
        headers.append(
            header::SET_COOKIE,
            header::HeaderValue::from_static("hearth_session=s1; Path=/ui; HttpOnly"),
        );
        headers.append(
            header::SET_COOKIE,
            header::HeaderValue::from_static("hearth_csrf=c1; Path=/ui"),
        );
        resp
    }

    fn app() -> Router {
        Router::new()
            .route(
                "/form",
                get(|| async { redirect("/ui/login") })
                    .post(|| async { redirect("https://app.example/cb?code=a&state=b") }),
            )
            .route(
                "/quote",
                post(|| async { redirect("https://app.example/cb?x=\"><script>") }),
            )
            .route(
                "/found",
                post(|| async {
                    (
                        StatusCode::FOUND,
                        [(header::LOCATION, "https://app.example/")],
                    )
                }),
            )
            .route("/ok", post(|| async { "plain" }))
            .route_layer(axum::middleware::from_fn(end_form_navigation))
    }

    async fn call(method: Method, uri: &str) -> Response {
        app()
            .oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("oneshot")
    }

    async fn body(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        String::from_utf8(bytes.to_vec()).expect("utf-8")
    }

    #[tokio::test]
    async fn post_303_becomes_a_continue_page() {
        let resp = call(Method::POST, "/form").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::LOCATION).is_none());
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(ct.starts_with("text/html"), "content-type: {ct}");
        assert_eq!(
            resp.headers()
                .get(header::REFRESH)
                .and_then(|v| v.to_str().ok()),
            Some("0;url=https://app.example/cb?code=a&state=b")
        );
        let html = body(resp).await;
        assert!(
            html.contains(
                r#"<meta http-equiv="refresh" content="0;url=https://app.example/cb?code=a&amp;state=b">"#
            ),
            "meta refresh missing: {html}"
        );
        assert!(
            html.contains(r#"href="https://app.example/cb?code=a&amp;state=b""#),
            "continue link missing: {html}"
        );
    }

    #[tokio::test]
    async fn every_set_cookie_header_is_kept() {
        let resp = call(Method::POST, "/form").await;
        let cookies: Vec<_> = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().expect("ascii").to_owned())
            .collect();
        assert_eq!(
            cookies,
            vec![
                "hearth_session=s1; Path=/ui; HttpOnly".to_owned(),
                "hearth_csrf=c1; Path=/ui".to_owned(),
            ]
        );
    }

    #[tokio::test]
    async fn the_target_is_html_escaped() {
        let html = body(call(Method::POST, "/quote").await).await;
        assert!(!html.contains("\"><script>"), "unescaped target: {html}");
        assert!(
            html.contains("&quot;&gt;&lt;script&gt;"),
            "escaped target missing: {html}"
        );
    }

    #[tokio::test]
    async fn get_redirect_is_unchanged() {
        let resp = call(Method::GET, "/form").await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/ui/login")
        );
    }

    #[tokio::test]
    async fn other_statuses_are_unchanged() {
        let found = call(Method::POST, "/found").await;
        assert_eq!(found.status(), StatusCode::FOUND);
        assert_eq!(
            found
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://app.example/")
        );
        let ok = call(Method::POST, "/ok").await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(body(ok).await, "plain");
    }
}
