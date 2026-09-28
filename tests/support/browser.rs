//! A minimal browser for black-box web tests: a cookie jar that honours
//! `Path` and `Max-Age=0` the way RFC 6265 user agents do, plus HTML form
//! scraping.
//!
//! Hand-built `Cookie:` headers hid a production bug: the UPDATE_PASSWORD form
//! checked a CSRF cookie scoped to `/ui`, which a real browser never sends to
//! `/required-action/*`. Driving a flow through this jar means a test only
//! ever sends the cookies a browser would.
//!
//! Included with `#[path = "support/browser.rs"] mod browser;`.

#![allow(dead_code)]

use axum::body::{to_bytes, Body};
use axum::http::{header, Request};
use axum::response::Response;
use tower::ServiceExt;

/// One stored cookie.
#[derive(Clone, Debug)]
struct Cookie {
    name: String,
    value: String,
    path: String,
}

/// A cookie jar plus the router it talks to.
pub struct Browser {
    app: axum::Router,
    jar: Vec<Cookie>,
}

impl Browser {
    /// A browser with an empty jar.
    pub fn new(app: axum::Router) -> Self {
        Self {
            app,
            jar: Vec::new(),
        }
    }

    /// Stores a `Set-Cookie` line as if `request_path` had returned it.
    pub fn accept_set_cookie(&mut self, line: &str, request_path: &str) {
        let mut parts = line.split(';');
        let Some((name, value)) = parts.next().and_then(|p| p.trim().split_once('=')) else {
            return;
        };
        let mut path = default_path(request_path);
        let mut delete = false;
        for attr in parts {
            let attr = attr.trim();
            let (key, val) = attr.split_once('=').unwrap_or((attr, ""));
            if key.eq_ignore_ascii_case("path") && val.starts_with('/') {
                path = val.to_string();
            } else if key.eq_ignore_ascii_case("max-age") && val.trim() == "0" {
                delete = true;
            }
        }
        self.jar.retain(|c| !(c.name == name && c.path == path));
        if !delete {
            self.jar.push(Cookie {
                name: name.to_string(),
                value: value.to_string(),
                path,
            });
        }
    }

    /// The `Cookie:` header a browser would send to `request_path`: every
    /// cookie whose `Path` path-matches it, longest path first.
    pub fn cookie_header(&self, request_path: &str) -> Option<String> {
        let mut matching: Vec<&Cookie> = self
            .jar
            .iter()
            .filter(|c| path_matches(request_path, &c.path))
            .collect();
        if matching.is_empty() {
            return None;
        }
        matching.sort_by_key(|c| std::cmp::Reverse(c.path.len()));
        Some(
            matching
                .iter()
                .map(|c| format!("{}={}", c.name, c.value))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// Whether the jar holds a cookie named `name` (for any path).
    pub fn has_cookie(&self, name: &str) -> bool {
        self.jar.iter().any(|c| c.name == name)
    }

    /// GETs `uri`, sending and storing cookies like a browser.
    pub async fn get(&mut self, uri: &str) -> Response {
        let req = Request::builder().method("GET").uri(uri);
        self.send(uri, req, Body::empty()).await
    }

    /// POSTs `fields` as `application/x-www-form-urlencoded` to `uri`.
    pub async fn post_form(&mut self, uri: &str, fields: &[(String, String)]) -> Response {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish();
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        self.send(uri, req, Body::from(body)).await
    }

    async fn send(
        &mut self,
        uri: &str,
        mut req: axum::http::request::Builder,
        body: Body,
    ) -> Response {
        let path = uri.split('?').next().unwrap_or(uri).to_string();
        if let Some(cookies) = self.cookie_header(&path) {
            req = req.header(header::COOKIE, cookies);
        }
        let resp = self
            .app
            .clone()
            .oneshot(req.body(body).expect("build request"))
            .await
            .expect("oneshot");
        let lines: Vec<String> = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(str::to_string)
            .collect();
        for line in lines {
            self.accept_set_cookie(&line, &path);
        }
        resp
    }
}

/// The response's `Location` header.
pub fn location(resp: &Response) -> Option<String> {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// The response body as text.
pub async fn body_text(resp: Response) -> String {
    let bytes = to_bytes(resp.into_body(), 4 << 20).await.expect("body");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The `name`/`value` of every `<input type="hidden">` inside the first
/// `<form>` whose `action` is `action` — exactly what a browser submits for
/// that form besides the fields the user types.
pub fn hidden_fields(html: &str, action: &str) -> Vec<(String, String)> {
    let marker = format!("action=\"{action}\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("no form posting to {action} in:\n{html}"));
    let form = &html[start..];
    let form = &form[..form.find("</form>").unwrap_or(form.len())];
    let mut fields = Vec::new();
    for input in form.split("<input").skip(1) {
        let tag = &input[..input.find('>').unwrap_or(input.len())];
        if !tag.contains("type=\"hidden\"") {
            continue;
        }
        let attr = |name: &str| {
            let key = format!("{name}=\"");
            tag.find(&key).map(|i| {
                let rest = &tag[i + key.len()..];
                unescape(&rest[..rest.find('"').unwrap_or(rest.len())])
            })
        };
        if let Some(name) = attr("name") {
            fields.push((name, attr("value").unwrap_or_default()));
        }
    }
    fields
}

/// Undoes the HTML escaping askama applies to attribute values.
fn unescape(s: &str) -> String {
    s.replace("&#x2F;", "/")
        .replace("&#x27;", "'")
        .replace("&#39;", "'")
        .replace("&quot;", "\"")
        .replace("&#34;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// RFC 6265 §5.1.4 default-path.
fn default_path(request_path: &str) -> String {
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => request_path[..i].to_string(),
    }
}

/// RFC 6265 §5.1.4 path-match.
fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    request_path == cookie_path
        || (request_path.starts_with(cookie_path)
            && (cookie_path.ends_with('/')
                || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')))
}
