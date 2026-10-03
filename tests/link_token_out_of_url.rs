//! One-time link tokens leave the URL on the first request (GA audit L18).
//!
//! Setup, verify-email, reset-password, magic-link, invitation and
//! required-action verification tokens arrive in emailed links, so the first
//! GET has to carry them. They used to stay in the URL for the whole flow —
//! the reset form even echoed the token into a hidden field — which put a live
//! credential into browser history, `Referer` headers and every proxy access
//! log on the way. Now the first GET moves the token into a short-lived,
//! HttpOnly, path-scoped cookie and answers `303` to the same path without it;
//! every later request, and the form, works from the cookie. No GET spends a
//! token: verification, magic-link and invitation links render a
//! confirmation page whose POST (link binding + CSRF) spends it, so a mail
//! scanner or link preview fetching the URL changes nothing.
//!
//! The server-internal `/ui/required-actions/*` flow, which redirected with
//! `?ra_token=<jwt>`, is removed: nothing outside the identity engine could
//! mint its first token. The reachable required-action flow lives under
//! `/required-action/*` and always carried its JWT in a cookie.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::response::Response;
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RealmConfig, UpdateUserRequest,
    UserStatus,
};
use hearth::protocol::web::link_token::{link_binding, LINK_TOKEN_COOKIE};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET_BYTES: [u8; 32] = [23u8; 32];
const OLD_PASSWORD: &str = "correct-horse-battery-staple";
const NEW_PASSWORD: &str = "a-perfectly-fine-passphrase";

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    data_dir: std::path::PathBuf,
}

/// Builds the web router. With `with_realm` a realm `acme` exists; without it
/// the instance is fresh, which is what the first-run setup page needs.
fn build_rig(with_realm: bool) -> Rig {
    build_rig_with(with_realm, false)
}

fn build_rig_with(with_realm: bool, tls: bool) -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    let realm_id = if with_realm {
        identity
            .create_realm(&CreateRealmRequest {
                name: "acme".to_string(),
                config: Some(RealmConfig {
                    allowed_auth_methods: Some(vec![
                        "password".to_string(),
                        "magic_link".to_string(),
                    ]),
                    ..RealmConfig::default()
                }),
            })
            .expect("create realm")
            .id()
            .clone()
    } else {
        RealmId::new(uuid::Uuid::nil())
    };

    let email = Arc::new(
        hearth::identity::email::EmailService::new(
            Arc::new(hearth::identity::email::LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            hearth::identity::email::EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        Arc::clone(&email),
        data_dir.clone(),
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
        Some(email),
    )
    .with_dev_mode(true)
    .with_tls_enabled(tls)
    .with_default_realm(with_realm.then(|| "acme".to_string()));

    Rig {
        app: web::router(state),
        identity,
        realm_id,
        data_dir,
    }
}

fn make_active_user(rig: &Rig, email: &str) -> UserId {
    let user = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    rig.identity
        .set_password(
            &rig.realm_id,
            user.id(),
            &CleartextPassword::from_string(OLD_PASSWORD.to_string()),
        )
        .expect("set password");
    rig.identity
        .update_user(
            &rig.realm_id,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate");
    user.id().clone()
}

fn binding(token: &str) -> String {
    link_binding(&CookieSecret::from_bytes(COOKIE_SECRET_BYTES), token)
}

async fn send(app: &axum::Router, req: Request<Body>) -> Response {
    app.clone().oneshot(req).await.expect("oneshot")
}

async fn get(app: &axum::Router, uri: &str, cookie: Option<&str>) -> Response {
    let mut req = Request::builder().uri(uri);
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    send(app, req.body(Body::empty()).expect("build GET")).await
}

async fn post_form(app: &axum::Router, uri: &str, cookie: Option<&str>, body: &str) -> Response {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    send(
        app,
        req.body(Body::from(body.to_string())).expect("build POST"),
    )
    .await
}

async fn body_text(resp: Response) -> String {
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    String::from_utf8_lossy(&bytes).to_string()
}

fn set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect()
}

/// The `Set-Cookie` line for the link-token cookie, if the response set one.
fn link_cookie_line(headers: &HeaderMap) -> Option<String> {
    set_cookies(headers)
        .into_iter()
        .find(|c| c.starts_with(&format!("{LINK_TOKEN_COOKIE}=")))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
}

/// Follows an emailed link's first hop and returns the `Cookie` header value
/// the browser would send next.
async fn stash(app: &axum::Router, path: &str, token: &str) -> String {
    let resp = get(app, &format!("{path}?token={token}"), None).await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "{path}: first GET stashes"
    );
    assert_eq!(header_str(resp.headers(), "location"), path);
    let line = link_cookie_line(resp.headers()).expect("link cookie set");
    let pair = line.split(';').next().expect("cookie pair").to_string();
    assert_eq!(pair, format!("{LINK_TOKEN_COOKIE}={token}"));
    pair
}

// ── The first GET: token out of the URL ─────────────────────────────────────

/// Every route an emailed link lands on.
const LINK_ROUTES: &[&str] = &[
    "/ui/setup",
    "/ui/verify-email",
    "/ui/realms/acme/verify-email",
    "/ui/admin/verify-email",
    "/ui/reset-password",
    "/ui/realms/acme/reset-password",
    "/ui/admin/reset-password",
    "/ui/magic-link",
    "/ui/realms/acme/magic-link",
    "/ui/accept-invitation",
    "/ui/realms/acme/accept-invitation",
    "/required-action/VERIFY_EMAIL/confirm",
];

#[tokio::test]
async fn every_emailed_link_route_moves_the_token_into_a_cookie() {
    let rig = build_rig(true);
    let token = "Tok3n_value-with.dots~";
    for path in LINK_ROUTES {
        let resp = get(&rig.app, &format!("{path}?token={token}&keep=1"), None).await;
        let h = resp.headers();
        assert_eq!(
            resp.status(),
            StatusCode::SEE_OTHER,
            "{path}: must redirect"
        );
        let location = header_str(h, "location");
        assert_eq!(
            location,
            format!("{path}?keep=1"),
            "{path}: the redirect drops the token and keeps every other parameter"
        );
        assert!(
            !location.contains(token),
            "{path}: Location leaks the token"
        );
        let cookie = link_cookie_line(h).unwrap_or_else(|| panic!("{path}: no link cookie"));
        assert!(
            cookie.starts_with(&format!("{LINK_TOKEN_COOKIE}={token};")),
            "{path}: cookie carries the token: {cookie}"
        );
        for attr in [
            "HttpOnly",
            "SameSite=Lax",
            &format!("Path={path}"),
            "Max-Age=900",
        ] {
            assert!(
                cookie.contains(attr),
                "{path}: cookie lacks {attr}: {cookie}"
            );
        }
        assert!(
            !cookie.contains("Secure"),
            "{path}: plain-HTTP request must not get a Secure cookie: {cookie}"
        );
        assert_eq!(header_str(h, "referrer-policy"), "no-referrer", "{path}");
        assert_eq!(header_str(h, "cache-control"), "no-store", "{path}");
    }
}

#[tokio::test]
async fn a_token_over_tls_gets_a_secure_cookie() {
    let rig = build_rig_with(true, true);
    let resp = get(&rig.app, "/ui/magic-link?token=abc", None).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = link_cookie_line(resp.headers()).expect("link cookie");
    assert!(
        cookie.ends_with("; Secure"),
        "a TLS request needs Secure: {cookie}"
    );
    assert!(cookie.contains("HttpOnly"), "{cookie}");
}

#[tokio::test]
async fn a_malformed_token_clears_the_cookie_instead_of_stashing_it() {
    let rig = build_rig(true);
    let resp = get(&rig.app, "/ui/magic-link?token=has%20a%3Bspace", None).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(header_str(resp.headers(), "location"), "/ui/magic-link");
    let cookie = link_cookie_line(resp.headers()).expect("clearing cookie");
    assert!(
        cookie.starts_with(&format!("{LINK_TOKEN_COOKIE}=;")) && cookie.contains("Max-Age=0"),
        "a value that cannot be a token must clear, not stash: {cookie}"
    );
}

// ── Reset password: form from the cookie, single use ───────────────────────

#[tokio::test]
async fn reset_link_completes_from_the_cookie_and_only_once() {
    let rig = build_rig(true);
    let user = make_active_user(&rig, "reset@acme.test");
    let token = rig
        .identity
        .request_password_reset(&rig.realm_id, "reset@acme.test")
        .expect("request reset")
        .expect("token for a known address");
    let path = "/ui/realms/acme/reset-password";
    let cookie = stash(&rig.app, path, &token).await;

    // The page renders from the cookie and never puts the token in a URL or
    // the form.
    let page = get(&rig.app, path, Some(&cookie)).await;
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(header_str(page.headers(), "referrer-policy"), "no-referrer");
    let html = body_text(page).await;
    assert!(!html.contains(&token), "the page must not render the token");
    assert!(
        html.contains(&binding(&token)),
        "the form carries the binding, not the token: {html}"
    );

    // The POST carries no token: the cookie supplies it.
    let body = format!(
        "link_binding={}&password={NEW_PASSWORD}&password_confirm={NEW_PASSWORD}",
        binding(&token)
    );
    let done = post_form(&rig.app, path, Some(&cookie), &body).await;
    assert_eq!(done.status(), StatusCode::OK);
    let cleared = link_cookie_line(done.headers()).expect("spent link clears its cookie");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    assert!(cleared.contains(&format!("Path={path}")), "{cleared}");
    let html = body_text(done).await;
    assert!(!html.contains("invalid or has expired"), "{html}");
    assert!(
        rig.identity
            .verify_password(
                &rig.realm_id,
                &user,
                &CleartextPassword::from_string(NEW_PASSWORD.to_string()),
            )
            .expect("verify"),
        "the reset took effect"
    );

    // Single use: replaying the same cookie + binding does nothing.
    let again = post_form(&rig.app, path, Some(&cookie), &body).await;
    let html = body_text(again).await;
    assert!(
        html.contains("invalid or has expired"),
        "a spent reset link must be refused: {html}"
    );
}

#[tokio::test]
async fn reset_post_with_a_wrong_binding_is_refused_and_keeps_the_link() {
    let rig = build_rig(true);
    let user = make_active_user(&rig, "csrf@acme.test");
    let token = rig
        .identity
        .request_password_reset(&rig.realm_id, "csrf@acme.test")
        .expect("request reset")
        .expect("token");
    let path = "/ui/realms/acme/reset-password";
    let cookie = stash(&rig.app, path, &token).await;

    // A cross-site POST that somehow carried the cookie cannot know the binding.
    let forged =
        format!("link_binding=forged&password={NEW_PASSWORD}&password_confirm={NEW_PASSWORD}");
    let refused = post_form(&rig.app, path, Some(&cookie), &forged).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(
        link_cookie_line(refused.headers()).is_none(),
        "a refused POST must not clear the legitimate user's link"
    );
    assert!(
        rig.identity
            .verify_password(
                &rig.realm_id,
                &user,
                &CleartextPassword::from_string(OLD_PASSWORD.to_string()),
            )
            .expect("verify"),
        "the forged POST changed nothing"
    );

    let body = format!(
        "link_binding={}&password={NEW_PASSWORD}&password_confirm={NEW_PASSWORD}",
        binding(&token)
    );
    let done = post_form(&rig.app, path, Some(&cookie), &body).await;
    let html = body_text(done).await;
    assert!(
        !html.contains("invalid or has expired"),
        "link still live: {html}"
    );
}

#[tokio::test]
async fn the_old_token_in_the_form_shape_no_longer_resets() {
    let rig = build_rig(true);
    let user = make_active_user(&rig, "legacy@acme.test");
    let token = rig
        .identity
        .request_password_reset(&rig.realm_id, "legacy@acme.test")
        .expect("request reset")
        .expect("token");
    let body = format!("token={token}&password={NEW_PASSWORD}&password_confirm={NEW_PASSWORD}");
    let resp = post_form(&rig.app, "/ui/realms/acme/reset-password", None, &body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        rig.identity
            .verify_password(
                &rig.realm_id,
                &user,
                &CleartextPassword::from_string(OLD_PASSWORD.to_string()),
            )
            .expect("verify"),
        "a token in the form body is no longer read"
    );
}

// ── Redeeming links: GET only confirms, POST spends ─────────────────────────
//
// A mail scanner or link preview fetches every URL in a message. A GET that
// spent the token let it sign the user in, verify the address or join the
// organization before the user ever clicked. Now the GET (after the stash
// hop) renders a confirmation page, and only its POST — carrying the link
// binding and the CSRF double-submit token — spends the token.

/// What a confirmation page hands the browser for its POST.
struct ConfirmPage {
    /// `Cookie` header value for the POST: link cookie plus CSRF cookie.
    cookie: String,
    /// Form body for the POST.
    body: String,
}

/// GETs a confirmation page and checks it spends nothing and shows nothing
/// secret; returns what the POST needs.
async fn confirm_page(
    app: &axum::Router,
    path: &str,
    link_cookie: &str,
    token: &str,
) -> ConfirmPage {
    let resp = get(app, path, Some(link_cookie)).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "{path}: GET renders the confirmation"
    );
    assert_eq!(header_str(resp.headers(), "referrer-policy"), "no-referrer");
    assert!(
        !set_cookies(resp.headers())
            .iter()
            .any(|c| c.starts_with("hearth_ui_session=")),
        "{path}: a GET must not sign anyone in"
    );
    assert!(
        link_cookie_line(resp.headers()).is_none(),
        "{path}: a GET must not clear (spend) the link"
    );
    let csrf_pair = set_cookies(resp.headers())
        .into_iter()
        .find(|c| c.starts_with("hearth_ui_csrf="))
        .and_then(|c| c.split(';').next().map(str::to_string))
        .expect("the confirmation page issues a CSRF cookie");
    let csrf_value = csrf_pair
        .strip_prefix("hearth_ui_csrf=")
        .expect("csrf pair")
        .to_string();
    let html = body_text(resp).await;
    assert!(
        !html.contains(token),
        "{path}: the page must not render the token"
    );
    assert!(
        html.contains(&binding(token)),
        "{path}: the form carries the binding"
    );
    assert!(
        html.contains(&format!("value=\"{csrf_value}\"")),
        "{path}: the form carries the CSRF token"
    );
    assert!(
        html.contains(&format!("action=\"{path}\"")),
        "{path}: the form posts back to the route the cookie is scoped to"
    );
    ConfirmPage {
        cookie: format!("{link_cookie}; {csrf_pair}"),
        body: format!("link_binding={}&_csrf={csrf_value}", binding(token)),
    }
}

#[tokio::test]
async fn magic_link_get_confirms_and_post_signs_in_once() {
    let rig = build_rig(true);
    make_active_user(&rig, "wanderer@acme.test");
    let minted = rig
        .identity
        .request_magic_link(&rig.realm_id, "wanderer@acme.test")
        .expect("mint magic link");
    let path = "/ui/realms/acme/magic-link";
    let link = stash(&rig.app, path, minted.token()).await;

    // A scanner may fetch it any number of times.
    confirm_page(&rig.app, path, &link, minted.token()).await;
    let page = confirm_page(&rig.app, path, &link, minted.token()).await;

    let resp = post_form(&rig.app, path, Some(&page.cookie), &page.body).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "the POST signs in");
    let cookies = set_cookies(resp.headers());
    assert!(
        cookies.iter().any(|c| c.starts_with("hearth_ui_session=")),
        "a session is issued: {cookies:?}"
    );
    let cleared = link_cookie_line(resp.headers()).expect("the link cookie is cleared");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    assert!(
        !header_str(resp.headers(), "location").contains(minted.token()),
        "no redirect carries the token"
    );

    let replay = post_form(&rig.app, path, Some(&page.cookie), &page.body).await;
    assert_ne!(
        replay.status(),
        StatusCode::SEE_OTHER,
        "a magic link is single-use"
    );
    assert!(
        !set_cookies(replay.headers())
            .iter()
            .any(|c| c.starts_with("hearth_ui_session=")),
        "a replay mints no session"
    );
}

#[tokio::test]
async fn verify_email_get_confirms_and_post_verifies_once() {
    let rig = build_rig(true);
    let user = make_active_user(&rig, "verify@acme.test");
    let token = rig
        .identity
        .issue_email_verification_token(&rig.realm_id, &user)
        .expect("issue verification token");
    let path = "/ui/realms/acme/verify-email";
    let link = stash(&rig.app, path, &token).await;

    confirm_page(&rig.app, path, &link, &token).await;
    let page = confirm_page(&rig.app, path, &link, &token).await;

    let ok = post_form(&rig.app, path, Some(&page.cookie), &page.body).await;
    assert_eq!(ok.status(), StatusCode::OK, "verification succeeds on POST");
    assert!(link_cookie_line(ok.headers()).is_some_and(|c| c.contains("Max-Age=0")));
    assert!(!body_text(ok).await.contains(&token));

    let replay = post_form(&rig.app, path, Some(&page.cookie), &page.body).await;
    assert_eq!(
        replay.status(),
        StatusCode::GONE,
        "the token works only once"
    );
}

#[tokio::test]
async fn invitation_get_confirms_and_post_accepts_once() {
    use hearth::identity::{
        CreateInvitationRequest, CreateOrganizationRequest, OrganizationConfig, OrganizationRole,
    };
    let rig = build_rig(true);
    let inviter = make_active_user(&rig, "inviter@acme.test");
    let org = rig
        .identity
        .create_organization(
            &rig.realm_id,
            &CreateOrganizationRequest {
                name: "acme-org".to_string(),
                slug: "acme-org".to_string(),
                description: None,
                config: Some(OrganizationConfig::default()),
                ..Default::default()
            },
        )
        .expect("create org");
    let (_invitation, token) = rig
        .identity
        .create_invitation(
            &rig.realm_id,
            &CreateInvitationRequest {
                org_id: org.id().clone(),
                email: "invitee@acme.test".to_string(),
                role: OrganizationRole::Member,
                invited_by: inviter,
            },
        )
        .expect("create invitation");
    let path = "/ui/realms/acme/accept-invitation";
    let link = stash(&rig.app, path, &token).await;

    confirm_page(&rig.app, path, &link, &token).await;
    let page = confirm_page(&rig.app, path, &link, &token).await;

    let ok = post_form(&rig.app, path, Some(&page.cookie), &page.body).await;
    assert_eq!(ok.status(), StatusCode::OK);
    assert!(link_cookie_line(ok.headers()).is_some_and(|c| c.contains("Max-Age=0")));
    let html = body_text(ok).await;
    assert!(html.contains("joined acme-org"), "the POST accepts: {html}");

    let replay = post_form(&rig.app, path, Some(&page.cookie), &page.body).await;
    let html = body_text(replay).await;
    assert!(
        html.contains("expired or is invalid"),
        "an invitation is accepted only once: {html}"
    );
}

#[tokio::test]
async fn a_redeem_post_without_binding_or_csrf_is_refused_and_keeps_the_link() {
    let rig = build_rig(true);
    make_active_user(&rig, "forged@acme.test");
    let minted = rig
        .identity
        .request_magic_link(&rig.realm_id, "forged@acme.test")
        .expect("mint magic link");
    let path = "/ui/realms/acme/magic-link";
    let link = stash(&rig.app, path, minted.token()).await;
    let page = confirm_page(&rig.app, path, &link, minted.token()).await;

    // Wrong binding, right CSRF.
    let csrf_only = page.body.replace(&binding(minted.token()), "forged");
    let resp = post_form(&rig.app, path, Some(&page.cookie), &csrf_only).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        link_cookie_line(resp.headers()).is_none(),
        "the link is kept"
    );

    // Right binding, CSRF field that does not match the cookie.
    let (binding_part, _) = page.body.split_once("&_csrf=").expect("body shape");
    let resp = post_form(
        &rig.app,
        path,
        Some(&page.cookie),
        &format!("{binding_part}&_csrf=forged"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // The link is still live for the real user.
    let resp = post_form(&rig.app, path, Some(&page.cookie), &page.body).await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "the genuine POST still works"
    );
}

#[tokio::test]
async fn setup_and_reset_gets_do_not_spend_their_tokens() {
    // Reset: two GETs, then the POST still resets.
    let rig = build_rig(true);
    make_active_user(&rig, "twice@acme.test");
    let token = rig
        .identity
        .request_password_reset(&rig.realm_id, "twice@acme.test")
        .expect("request reset")
        .expect("token");
    let path = "/ui/realms/acme/reset-password";
    let link = stash(&rig.app, path, &token).await;
    for _ in 0..2 {
        let page = get(&rig.app, path, Some(&link)).await;
        assert_eq!(page.status(), StatusCode::OK);
        assert!(
            link_cookie_line(page.headers()).is_none(),
            "GET keeps the link"
        );
    }
    let body = format!(
        "link_binding={}&password={NEW_PASSWORD}&password_confirm={NEW_PASSWORD}",
        binding(&token)
    );
    let done = body_text(post_form(&rig.app, path, Some(&link), &body).await).await;
    assert!(!done.contains("invalid or has expired"), "{done}");

    // Setup: the page can be loaded repeatedly.
    let fresh = build_rig(false);
    let token = hearth::identity::onboarding::ensure_setup_token(
        fresh.identity.as_ref(),
        &fresh.data_dir,
        None,
        None,
        None,
        true,
    )
    .expect("setup token")
    .expect("fresh instance issues one");
    let link = stash(&fresh.app, "/ui/setup", &token).await;
    for _ in 0..2 {
        let page = get(&fresh.app, "/ui/setup", Some(&link)).await;
        assert_eq!(
            page.status(),
            StatusCode::OK,
            "the setup GET spends nothing"
        );
    }
}

#[tokio::test]
async fn a_link_route_without_the_cookie_is_an_invalid_link() {
    let rig = build_rig(true);
    let resp = get(&rig.app, "/ui/realms/acme/verify-email", None).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── First-run setup ─────────────────────────────────────────────────────────

#[tokio::test]
async fn setup_page_reads_the_stashed_token() {
    let rig = build_rig(false);
    let token = hearth::identity::onboarding::ensure_setup_token(
        rig.identity.as_ref(),
        &rig.data_dir,
        None,
        None,
        None,
        true,
    )
    .expect("setup token")
    .expect("fresh instance issues one");
    let cookie = stash(&rig.app, "/ui/setup", &token).await;

    let page = get(&rig.app, "/ui/setup", Some(&cookie)).await;
    assert_eq!(page.status(), StatusCode::OK);
    let html = body_text(page).await;
    assert!(
        !html.contains(&token),
        "the setup page must not render the token"
    );
    assert!(
        html.contains(&binding(&token)),
        "the form carries the binding"
    );

    let no_cookie = get(&rig.app, "/ui/setup", None).await;
    assert_eq!(no_cookie.status(), StatusCode::NOT_FOUND);

    let forged = post_form(
        &rig.app,
        "/ui/setup",
        Some(&cookie),
        "link_binding=forged&admin_email=a%40b.test&admin_display_name=A\
         &admin_password=long-enough-password",
    )
    .await;
    assert_eq!(
        forged.status(),
        StatusCode::NOT_FOUND,
        "a setup POST without the binding is refused"
    );
}

// ── The server-internal flow is gone ───────────────────────────────────────

#[tokio::test]
async fn the_ra_token_query_pages_are_removed() {
    let rig = build_rig(true);
    for path in [
        "/ui/required-actions/update-password?ra_token=x",
        "/ui/required-actions/verify-email?ra_token=x",
    ] {
        let resp = get(&rig.app, path, None).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
}
