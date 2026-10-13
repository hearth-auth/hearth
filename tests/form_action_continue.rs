//! `form-action-safe-sign-in`: a hosted form submission never ends in a
//! redirect off Hearth's origin.
//!
//! Browsers apply CSP `form-action 'self'` to every redirect that follows a
//! form POST, so the sign-in, consent and required-action POSTs answer `200`
//! with a continue page (a `Refresh` header plus a meta refresh) instead of a
//! `303`. These tests drive the flows through the production-mode web router
//! with a cookie jar, the way a browser does.

#[path = "support/browser.rs"]
mod browser;

use std::sync::Arc;

use axum::http::{header, StatusCode};
use axum::response::Response;
use browser::{body_text, hidden_fields, location, Browser};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, ClientTrustLevel, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, OAuthClient, RegisterClientRequest,
    RequiredAction, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};

const COOKIE_SECRET: [u8; 32] = [57u8; 32];
const PASSWORD: &str = "continue-page-password-1";
const NEW_PASSWORD: &str = "continue-page-password-2";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const FIRST_PARTY_CB: &str = "https://app.example.com/cb";
const THIRD_PARTY_CB: &str = "https://third.example.net/cb";

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    realm_name: String,
    first_party: OAuthClient,
    third_party: OAuthClient,
}

fn build_rig() -> Rig {
    build_rig_with(false)
}

fn build_rig_with(dev_mode: bool) -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit: Arc<dyn AuditEngine> = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as _,
        Arc::clone(&clock),
    ));
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as _,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit) as _,
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as _,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;
    let realm_name = format!("continue-{}", uuid::Uuid::new_v4().simple());
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .expect("create realm");
    let first_party = identity
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "First Party".to_string(),
                redirect_uris: vec![FIRST_PARTY_CB.to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register first-party client");
    let third_party = identity
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "Third Party".to_string(),
                redirect_uris: vec![THIRD_PARTY_CB.to_string()],
                require_consent: true,
                grant_types: vec!["authorization_code".to_string()],
                ..Default::default()
            },
        )
        .expect("register third-party client");
    let email = Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        email,
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        rbac,
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        None,
    )
    .with_dev_mode(dev_mode);
    Rig {
        app: web::router(state),
        identity,
        realm_id: realm.id().clone(),
        realm_name,
        first_party,
        third_party,
    }
}

fn seed_user(rig: &Rig, email: &str, actions: Vec<RequiredAction>) {
    let user = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Continue User".to_string(),
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
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("set password");
    rig.identity
        .update_user(
            &rig.realm_id,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                required_actions: Some(actions),
                ..Default::default()
            },
        )
        .expect("activate");
}

fn authorize_path(rig: &Rig, client: &OAuthClient) -> String {
    let redirect = &client.redirect_uris()[0];
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &client.client_id().as_uuid().to_string())
        .append_pair("redirect_uri", redirect)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid")
        .append_pair("state", "st-1")
        .append_pair("code_challenge", PKCE_CHALLENGE)
        .append_pair("code_challenge_method", "S256")
        .finish();
    format!("/ui/realms/{}/oauth/authorize?{query}", rig.realm_name)
}

/// Asserts `resp` is a continue page and returns its target.
async fn continue_target(resp: Response) -> String {
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected a continue page, got {} to {:?}",
        resp.status(),
        resp.headers().get(header::LOCATION)
    );
    assert!(
        resp.headers().get(header::LOCATION).is_none(),
        "a continue page carries no Location"
    );
    let target = location(&resp).expect("continue page Refresh target");
    let html = body_text(resp).await;
    assert!(
        html.contains(r#"<meta http-equiv="refresh" content="0;url="#),
        "continue page has no meta refresh: {html}"
    );
    target
}

/// Path and query of `url`, for a same-origin `Browser::get`.
fn path_of(url: &str) -> String {
    url.strip_prefix("http://localhost")
        .unwrap_or(url)
        .to_string()
}

/// Opens the authorize URL signed out, follows it to the login form and
/// submits the password. Returns the login POST response.
async fn sign_in(rig: &Rig, browser: &mut Browser, client: &OAuthClient, email: &str) -> Response {
    let authorize = browser.get(&authorize_path(rig, client)).await;
    assert_eq!(
        authorize.status(),
        StatusCode::SEE_OTHER,
        "authorize redirects to login"
    );
    let login_url = location(&authorize).expect("login redirect");
    let login_page = browser.get(&path_of(&login_url)).await;
    assert_eq!(login_page.status(), StatusCode::OK);
    let action = format!("/ui/realms/{}/login", rig.realm_name);
    let mut fields = hidden_fields(&body_text(login_page).await, &action);
    fields.push(("email".to_string(), email.to_string()));
    fields.push(("password".to_string(), PASSWORD.to_string()));
    browser.post_form(&action, &fields).await
}

#[tokio::test]
async fn sign_in_for_a_client_on_another_origin_ends_on_a_continue_page() {
    let rig = build_rig();
    seed_user(&rig, "fp@continue.test", Vec::new());
    let mut browser = Browser::new(rig.app.clone());

    let login = sign_in(&rig, &mut browser, &rig.first_party, "fp@continue.test").await;
    assert!(
        browser.has_cookie("hearth_ui_session"),
        "the continue page must keep the session cookie"
    );
    assert!(browser.has_cookie("hearth_ui_csrf"), "and the CSRF cookie");
    let target = continue_target(login).await;
    assert!(
        target.starts_with(&format!("/ui/realms/{}/oauth/authorize?", rig.realm_name)),
        "target is the UI authorize URL: {target}"
    );

    // The refresh is a plain navigation: the authorize page redirects to the
    // client, off Hearth's origin, with a code.
    let authorize = browser.get(&target).await;
    assert_eq!(authorize.status(), StatusCode::SEE_OTHER);
    let callback = location(&authorize).expect("callback redirect");
    assert!(
        callback.starts_with(&format!("{FIRST_PARTY_CB}?code=")) && callback.contains("state=st-1"),
        "callback: {callback}"
    );
}

/// Signs in for the consent-requiring client and opens the consent form.
async fn consent_form(rig: &Rig, browser: &mut Browser, email: &str) -> Vec<(String, String)> {
    let login = sign_in(rig, browser, &rig.third_party, email).await;
    let authorize = browser.get(&continue_target(login).await).await;
    assert_eq!(authorize.status(), StatusCode::SEE_OTHER);
    let consent_url = location(&authorize).expect("consent redirect");
    assert!(
        consent_url.starts_with("/ui/oauth/consent"),
        "consent: {consent_url}"
    );
    let page = browser.get(&consent_url).await;
    assert_eq!(page.status(), StatusCode::OK);
    hidden_fields(&body_text(page).await, "/ui/oauth/consent")
}

#[tokio::test]
async fn approved_consent_ends_on_a_continue_page_to_the_client() {
    let rig = build_rig();
    seed_user(&rig, "approve@continue.test", Vec::new());
    let mut browser = Browser::new(rig.app.clone());
    let mut fields = consent_form(&rig, &mut browser, "approve@continue.test").await;
    fields.push(("scope".to_string(), "openid".to_string()));
    fields.push(("decision".to_string(), "approve".to_string()));

    let resp = browser.post_form("/ui/oauth/consent", &fields).await;
    let target = continue_target(resp).await;
    assert!(
        target.starts_with(&format!("{THIRD_PARTY_CB}?code=")) && target.contains("state=st-1"),
        "target: {target}"
    );
}

#[tokio::test]
async fn denied_consent_ends_on_a_continue_page_with_access_denied() {
    let rig = build_rig();
    seed_user(&rig, "deny@continue.test", Vec::new());
    let mut browser = Browser::new(rig.app.clone());
    let mut fields = consent_form(&rig, &mut browser, "deny@continue.test").await;
    fields.push(("decision".to_string(), "deny".to_string()));

    let resp = browser.post_form("/ui/oauth/consent", &fields).await;
    let target = continue_target(resp).await;
    assert!(
        target.starts_with(THIRD_PARTY_CB) && target.contains("error=access_denied"),
        "target: {target}"
    );
}

#[tokio::test]
async fn a_required_action_ends_on_a_continue_page_to_the_client() {
    let rig = build_rig();
    seed_user(
        &rig,
        "ra@continue.test",
        vec![RequiredAction::UpdatePassword],
    );
    let mut browser = Browser::new(rig.app.clone());

    // Sign-in hands over to the required action, still through a continue page.
    let login = sign_in(&rig, &mut browser, &rig.first_party, "ra@continue.test").await;
    let mut next = continue_target(login).await;
    // Follow plain redirects until the UPDATE_PASSWORD form renders.
    let page = loop {
        let resp = browser.get(&path_of(&next)).await;
        if resp.status() != StatusCode::SEE_OTHER {
            break resp;
        }
        next = location(&resp).expect("redirect");
    };
    assert_eq!(page.status(), StatusCode::OK, "update-password page");
    let action = "/required-action/UPDATE_PASSWORD";
    let mut fields = hidden_fields(&body_text(page).await, action);
    fields.push(("current_password".to_string(), PASSWORD.to_string()));
    fields.push(("new_password".to_string(), NEW_PASSWORD.to_string()));
    fields.push(("confirm_password".to_string(), NEW_PASSWORD.to_string()));

    let resp = browser.post_form(action, &fields).await;
    let mut target = continue_target(resp).await;
    // The action resumes the authorization request: the chain that follows
    // the continue page ends on the client with a code.
    while !target.starts_with(FIRST_PARTY_CB) {
        let resp = browser.get(&path_of(&target)).await;
        assert_eq!(
            resp.status(),
            StatusCode::SEE_OTHER,
            "resume chain at {target}"
        );
        target = location(&resp).expect("redirect");
    }
    assert!(target.contains("code="), "callback: {target}");
}

#[tokio::test]
async fn dev_mode_keeps_the_strict_form_action_directive() {
    let rig = build_rig_with(true);
    let mut browser = Browser::new(rig.app.clone());
    let resp = browser
        .get(&format!("/ui/realms/{}/login", rig.realm_name))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let csp = resp
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .expect("CSP header")
        .to_string();
    assert!(
        csp.contains("form-action 'self';"),
        "form-action must be exactly 'self' under --dev: {csp}"
    );
    assert!(
        !csp.contains("localhost"),
        "no extra origins under --dev: {csp}"
    );
}
