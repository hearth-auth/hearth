//! Integration and adversarial tests for the Mailcatcher transport (HEA-574).
//!
//! Exercises the HTTP routes directly via `tower::ServiceExt::oneshot` —
//! no TCP socket required — plus the `MailcatcherSender` unit contract.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt as _;

use hearth::identity::email::mailcatcher::{MailcatcherSender, MailcatcherState};
use hearth::identity::email::{EmailMessage, EmailSender};
use hearth::protocol::web::mailcatcher::mailcatcher_router;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_state(password: &str) -> Arc<MailcatcherState> {
    Arc::new(MailcatcherState::new(password.to_string()))
}

fn auth_cookie(state: &MailcatcherState) -> String {
    format!("mcauth={}", state.session_cookie_value())
}

async fn send_request(
    state: Arc<MailcatcherState>,
    req: Request<Body>,
) -> axum::response::Response {
    mailcatcher_router(state)
        .oneshot(req)
        .await
        .expect("router oneshot should not fail")
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Body::empty())
        .expect("request builder should not fail")
}

fn get_authed(path: &str, state: &MailcatcherState) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::COOKIE, auth_cookie(state))
        .body(Body::empty())
        .expect("request builder should not fail")
}

fn post_form(path: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .expect("request builder should not fail")
}

fn delete_authed(path: &str, state: &MailcatcherState) -> Request<Body> {
    Request::builder()
        .method(Method::DELETE)
        .uri(path)
        .header(header::COOKIE, auth_cookie(state))
        .body(Body::empty())
        .expect("request builder should not fail")
}

fn extract_set_cookie(response: &axum::response::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            let (k, after_eq) = s.split_once('=')?;
            (k.trim() == name).then(|| after_eq.split(';').next().unwrap_or("").trim().to_string())
        })
}

fn send_test_email(state: &Arc<MailcatcherState>, subject: &str, to: &str) {
    MailcatcherSender::new(Arc::clone(state))
        .send(&EmailMessage {
            to: to.to_string(),
            subject: subject.to_string(),
            html_body: format!("<p>Body for {subject}</p>"),
            text_body: format!("Body for {subject}"),
        })
        .expect("send should succeed");
}

// ── Integration: unauthenticated GET /dev/mail → redirects to login ───────────

#[tokio::test]
async fn unauthed_inbox_redirects_to_login() {
    let state = make_state("pw");
    let resp = send_request(Arc::clone(&state), get("/dev/mail")).await;
    assert!(
        resp.status().is_redirection(),
        "expected redirect, got {}",
        resp.status()
    );
    let location = resp
        .headers()
        .get(header::LOCATION)
        .expect("LOCATION header must be present")
        .to_str()
        .expect("LOCATION must be valid UTF-8");
    assert_eq!(location, "/dev/mail/login");
}

// ── Integration: correct password → cookie → inbox 200 ───────────────────────

#[tokio::test]
async fn correct_password_issues_cookie_and_redirects() {
    let state = make_state("correct-password");
    let req = post_form("/dev/mail/login", "password=correct-password");
    let resp = send_request(Arc::clone(&state), req).await;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .expect("LOCATION header must be present")
        .to_str()
        .expect("LOCATION must be valid UTF-8");
    assert_eq!(location, "/dev/mail");

    let cookie = extract_set_cookie(&resp, "mcauth");
    assert!(cookie.is_some(), "SET-COOKIE mcauth must be present");
    assert_eq!(
        cookie.expect("cookie must be present"),
        state.session_cookie_value(),
        "cookie value must match expected session token"
    );
}

#[tokio::test]
async fn authenticated_inbox_returns_200() {
    let state = make_state("test-pw");
    let resp = send_request(Arc::clone(&state), get_authed("/dev/mail", &state)).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── Integration: wrong password → login page with error ──────────────────────

#[tokio::test]
async fn wrong_password_returns_login_with_error() {
    let state = make_state("right");
    let req = post_form("/dev/mail/login", "password=wrong");
    let resp = send_request(Arc::clone(&state), req).await;

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "should re-render login (200)"
    );
    let cookie = extract_set_cookie(&resp, "mcauth");
    assert!(cookie.is_none(), "wrong password must NOT issue a cookie");

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body read should not fail");
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("Incorrect password"),
        "error message must appear in response"
    );
}

// ── Integration: send email → list → detail → delete ─────────────────────────

#[tokio::test]
async fn email_lifecycle_list_detail_delete() {
    let state = make_state("lifecycle-pw");

    // 1. Send an email through the sender
    send_test_email(&state, "Welcome to Hearth", "alice@example.com");

    // 2. List — email appears in inbox
    let resp = send_request(Arc::clone(&state), get_authed("/dev/mail", &state)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body read should not fail");
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("Welcome to Hearth"),
        "subject must appear in inbox list"
    );
    assert!(
        html.contains("alice@example.com"),
        "recipient must appear in inbox list"
    );

    // 3. Detail — navigate to the email
    let email_id = {
        let inbox = state
            .inbox
            .lock()
            .expect("inbox lock should not be poisoned");
        inbox[0].id.to_string()
    };
    let resp = send_request(
        Arc::clone(&state),
        get_authed(&format!("/dev/mail/{email_id}"), &state),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body read should not fail");
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("Welcome to Hearth"),
        "subject must appear in detail view"
    );
    assert!(
        html.contains("alice@example.com"),
        "recipient must appear in detail view"
    );

    // 4. Delete — email is removed from inbox
    let resp = send_request(
        Arc::clone(&state),
        delete_authed(&format!("/dev/mail/{email_id}"), &state),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let inbox_len = state
        .inbox
        .lock()
        .expect("inbox lock should not be poisoned")
        .len();
    assert_eq!(inbox_len, 0, "inbox must be empty after delete");
}

// ── Adversarial: cookie with wrong HMAC → rejected → redirect to login ────────

#[tokio::test]
async fn tampered_cookie_is_rejected() {
    let state = make_state("real-pw");
    let req = Request::builder()
        .method(Method::GET)
        .uri("/dev/mail")
        .header(
            header::COOKIE,
            "mcauth=00000000000000000000000000000000deadbeef",
        )
        .body(Body::empty())
        .expect("request builder should not fail");
    let resp = send_request(Arc::clone(&state), req).await;
    assert!(
        resp.status().is_redirection(),
        "expected redirect, got {}",
        resp.status()
    );
    let location = resp
        .headers()
        .get(header::LOCATION)
        .expect("LOCATION header must be present")
        .to_str()
        .expect("LOCATION must be valid UTF-8");
    assert_eq!(
        location, "/dev/mail/login",
        "tampered cookie must redirect to login"
    );
}

// ── Adversarial: /dev/mail exists ONLY because mailcatcher_router mounts it ────
//
// In production (`src/main.rs`) the `/dev/mail*` routes are merged into the app
// router *only* when the mailcatcher transport is active. When it is not, the
// merge is skipped and those paths are unregistered. The previous version of
// this test asserted that a hand-built router with an explicit `404` fallback
// returns 404 — a tautology that never touched Hearth code.
//
// This version pins the real invariant on both sides:
//   * Positive control — the REAL product `mailcatcher_router` serves
//     `GET /dev/mail` (an unauthenticated request redirects to the login page,
//     which is decidedly *not* a 404). This proves the route is real.
//   * Negative control — a router that did NOT merge `mailcatcher_router` has no
//     such route, so axum's own default handling (not a fabricated fallback)
//     returns 404. This is exactly the "transport ≠ mailcatcher" case.
#[tokio::test]
async fn dev_mail_absent_without_mailcatcher_transport() {
    // Negative control: no mailcatcher merge → axum's default 404 for /dev/mail.
    let without = axum::Router::new()
        .oneshot(get("/dev/mail"))
        .await
        .expect("router oneshot should not fail");
    assert_eq!(
        without.status(),
        StatusCode::NOT_FOUND,
        "without the mailcatcher merge, /dev/mail must not be routed"
    );

    // Positive control: the real product router does register /dev/mail. An
    // unauthenticated GET is redirected to the login form — proving the route
    // exists and is handled by Hearth code, not by a 404 fallback.
    let state = make_state("route-presence-pw");
    let with = send_request(state, get("/dev/mail")).await;
    assert_ne!(
        with.status(),
        StatusCode::NOT_FOUND,
        "with the mailcatcher merge, /dev/mail must be routed"
    );
    assert!(
        with.status().is_redirection(),
        "unauthenticated /dev/mail must redirect to login, got {}",
        with.status()
    );
    assert_eq!(
        with.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/dev/mail/login"),
        "unauthenticated /dev/mail must redirect to the mailcatcher login"
    );
}

// ── Integration: clear all emails ─────────────────────────────────────────────

#[tokio::test]
async fn clear_all_empties_inbox() {
    let state = make_state("clear-pw");

    for i in 0..3u32 {
        send_test_email(&state, &format!("Email {i}"), "user@example.com");
    }
    assert_eq!(
        state
            .inbox
            .lock()
            .expect("inbox lock should not be poisoned")
            .len(),
        3
    );

    let resp = send_request(Arc::clone(&state), delete_authed("/dev/mail", &state)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        state
            .inbox
            .lock()
            .expect("inbox lock should not be poisoned")
            .len(),
        0,
        "inbox must be empty after clear all"
    );
}
