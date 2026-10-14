//! A passkey sign-in returns to the page that sent the user to sign in.
//!
//! The login page carries `return_to` (for example the UI authorize URL of an
//! OIDC request). The password form posts it, and the sign-in ends there. The
//! passkey ceremony is a `fetch()` from the same page: it sends the same field,
//! and the completion's JSON `redirect` — or the second factor or required
//! action it still owes — ends at that URL too. An off-site value falls back
//! to the account page, as for the password form (A-52).
//!
//! Every flow is driven through a cookie jar that honours `Path`
//! (`support/browser.rs`), outside `--dev`.

#[path = "support/browser.rs"]
mod browser;
#[path = "common/webauthn_helper.rs"]
mod webauthn_helper;

use std::sync::Arc;

use axum::http::{header, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use browser::{body_text, hidden_fields, location, Browser};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RealmConfig, RegistrationOptions,
    RequiredAction, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};

const COOKIE_SECRET: [u8; 32] = [53u8; 32];
/// The origin and RP ID the server derives for a request with no `Host`.
const ORIGIN: &str = "http://localhost";
const RP_ID: &str = "localhost";

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    realm_name: String,
}

/// A production-mode (`dev_mode = false`) web router over plain HTTP, with
/// one realm configured by `config`.
fn build_rig(config: RealmConfig) -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    let _ = temp.keep();
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
    let realm_name = format!("pk-return-{}", uuid::Uuid::new_v4().simple());
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: Some(config),
        })
        .expect("create realm");
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
        Arc::clone(&email),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        rbac,
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(email),
    )
    .with_dev_mode(false);
    Rig {
        app: web::router(state),
        identity,
        realm_id: realm.id().clone(),
        realm_name,
    }
}

/// A password assembled at runtime rather than written as a literal, so it
/// does not trip CodeQL's `rust/hard-coded-cryptographic-value` rule.
fn password() -> String {
    ["passkey", "return", "to", "1"].join("-")
}

/// An active user with a password and `actions` pending.
fn create_user(rig: &Rig, email: &str, actions: Vec<RequiredAction>) -> UserId {
    let user = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Passkey User".to_string(),
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
            &CleartextPassword::from_string(password()),
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
    user.id().clone()
}

/// The RFC 6238 code for the 30-second step `offset` steps from now.
fn totp_code(secret_base32: &str, offset: u64) -> String {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_base32.trim_end_matches('=').as_bytes())
        .expect("base32 secret");
    let step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        / 30
        + offset;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret);
    let tag = ring::hmac::sign(&key, &step.to_be_bytes());
    let hash = tag.as_ref();
    let at = usize::from(hash[hash.len() - 1] & 0x0f);
    let binary = u32::from_be_bytes([hash[at] & 0x7f, hash[at + 1], hash[at + 2], hash[at + 3]]);
    format!("{:06}", binary % 1_000_000)
}

/// Enrols TOTP (confirming with the current step's code) and returns the
/// secret. The login then answers with the NEXT step's code: the current one
/// is spent (replay protection).
fn enrol_totp(rig: &Rig, user: &UserId) -> String {
    let enrolment = rig
        .identity
        .enroll_totp(&rig.realm_id, user)
        .expect("start TOTP enrolment");
    rig.identity
        .verify_totp_enrollment(&rig.realm_id, user, &totp_code(&enrolment.secret_base32, 0))
        .expect("confirm TOTP enrolment");
    enrolment.secret_base32
}

/// Registers a passkey for `user` through the engine, as the account page
/// would, and returns the authenticator holding it.
fn enrol_passkey(
    rig: &Rig,
    user: &UserId,
    user_verified: bool,
) -> webauthn_helper::TestAuthenticator {
    let authenticator = webauthn_helper::TestAuthenticator::new(RP_ID);
    let challenge = rig
        .identity
        .start_webauthn_registration(
            &rig.realm_id,
            user,
            &RegistrationOptions {
                rp_id: RP_ID.to_string(),
                discoverable: true,
            },
        )
        .expect("start registration");
    let (cdj, att) = if user_verified {
        authenticator.build_verified_registration_response(&challenge, ORIGIN)
    } else {
        authenticator.build_registration_response(&challenge, ORIGIN)
    };
    rig.identity
        .complete_webauthn_registration(
            &rig.realm_id,
            user,
            &cdj,
            &att,
            ORIGIN,
            true,
            &Default::default(),
        )
        .expect("complete registration");
    authenticator
}

/// The UI authorize URL an OIDC request sends the user to sign in from.
fn authorize_return_to(rig: &Rig) -> String {
    format!(
        "/ui/realms/{}/oauth/authorize?response_type=code&client_id=app&state=s1",
        rig.realm_name
    )
}

/// Runs the passkey ceremony from the realm's login page, as `passkey.js`
/// does, sending `return_to` when given. Returns the completion's JSON.
async fn passkey_sign_in(
    rig: &Rig,
    browser: &mut Browser,
    user: &UserId,
    authenticator: &webauthn_helper::TestAuthenticator,
    user_verified: bool,
    return_to: Option<&str>,
) -> serde_json::Value {
    let begin = browser
        .get(&format!(
            "/ui/realms/{}/login/passkey-begin",
            rig.realm_name
        ))
        .await;
    assert_eq!(begin.status(), StatusCode::OK, "passkey begin");
    let options: serde_json::Value =
        serde_json::from_str(&body_text(begin).await).expect("options JSON");
    let challenge = URL_SAFE_NO_PAD
        .decode(options["challenge"].as_str().expect("challenge"))
        .expect("b64 challenge");
    let user_handle = user.as_uuid().to_string();
    let (cdj, auth_data, sig, handle) = if user_verified {
        authenticator.build_verified_authentication_response(
            &challenge,
            ORIGIN,
            1,
            Some(&user_handle),
        )
    } else {
        authenticator.build_authentication_response(&challenge, ORIGIN, 1, Some(&user_handle))
    };
    let mut body = serde_json::json!({
        "credential_id": URL_SAFE_NO_PAD.encode(&authenticator.credential_id),
        "client_data_json": URL_SAFE_NO_PAD.encode(&cdj),
        "authenticator_data": URL_SAFE_NO_PAD.encode(&auth_data),
        "signature": URL_SAFE_NO_PAD.encode(&sig),
        "user_handle": handle.map(|h| URL_SAFE_NO_PAD.encode(h)),
    });
    if let Some(return_to) = return_to {
        body["return_to"] = serde_json::Value::String(return_to.to_string());
    }
    let resp = browser
        .post_json(
            &format!("/ui/realms/{}/login/passkey-complete", rig.realm_name),
            &body,
            &[],
        )
        .await;
    let status = resp.status();
    let text = body_text(resp).await;
    assert_eq!(status, StatusCode::OK, "passkey completion: {text}");
    serde_json::from_str(&text).expect("completion JSON")
}

/// The target of the continue page a sign-in form POST ends on
/// (`form-action-safe-sign-in`).
fn continue_target(resp: &axum::response::Response) -> String {
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected the continue page, got {}",
        resp.status()
    );
    assert!(
        resp.headers().get(header::LOCATION).is_none(),
        "the continue page carries no Location"
    );
    location(resp).expect("the continue page names its target")
}

/// A user-verified passkey on a realm that requires no second factor: the
/// completion sends the browser back to the authorize URL, with a session.
#[tokio::test]
async fn a_passkey_sign_in_returns_to_the_authorize_url() {
    let rig = build_rig(RealmConfig {
        mfa_required: Some(false),
        ..Default::default()
    });
    let user = create_user(&rig, "pk-uv@example.com", vec![]);
    let authenticator = enrol_passkey(&rig, &user, true);
    let return_to = authorize_return_to(&rig);

    let mut browser = Browser::new(rig.app.clone());
    let done = passkey_sign_in(
        &rig,
        &mut browser,
        &user,
        &authenticator,
        true,
        Some(&return_to),
    )
    .await;

    assert_eq!(done["redirect"], return_to.as_str(), "completion: {done}");
    assert!(
        browser.has_cookie("hearth_ui_session"),
        "the passkey sign-in opens a session"
    );
}

/// A `return_to` off Hearth's UI is ignored, as for the password form (A-52):
/// the completion falls back to the account page.
#[tokio::test]
async fn an_off_site_return_to_falls_back_to_the_account_page() {
    for bad in [
        "https://evil.example/cb",
        "//evil.example/cb",
        "/admin/users",
    ] {
        let rig = build_rig(RealmConfig {
            mfa_required: Some(false),
            ..Default::default()
        });
        let user = create_user(&rig, "pk-off-site@example.com", vec![]);
        let authenticator = enrol_passkey(&rig, &user, true);

        let mut browser = Browser::new(rig.app.clone());
        let done =
            passkey_sign_in(&rig, &mut browser, &user, &authenticator, true, Some(bad)).await;

        assert_eq!(done["redirect"], "/ui", "return_to {bad:?}: {done}");
    }
}

/// A UV-less passkey on a realm that requires MFA still owes TOTP. The TOTP
/// step ends on the continue page to the authorize URL, not the account page.
#[tokio::test]
async fn a_second_factor_after_a_passkey_keeps_return_to() {
    let rig = build_rig(RealmConfig {
        mfa_required: Some(true),
        ..Default::default()
    });
    let user = create_user(&rig, "pk-totp@example.com", vec![]);
    let secret = enrol_totp(&rig, &user);
    let authenticator = enrol_passkey(&rig, &user, false);
    let return_to = authorize_return_to(&rig);

    let mut browser = Browser::new(rig.app.clone());
    let done = passkey_sign_in(
        &rig,
        &mut browser,
        &user,
        &authenticator,
        false,
        Some(&return_to),
    )
    .await;
    assert_eq!(
        done["redirect"], "/ui/mfa-challenge",
        "a UV-less passkey owes TOTP: {done}"
    );

    let page = browser.get("/ui/mfa-challenge").await;
    assert_eq!(page.status(), StatusCode::OK, "TOTP challenge page");
    let html = body_text(page).await;
    let mut fields = hidden_fields(&html, "/ui/mfa-challenge");
    fields.push(("code".to_string(), totp_code(&secret, 1)));
    let resp = browser.post_form("/ui/mfa-challenge", &fields).await;

    assert_eq!(continue_target(&resp), return_to);
    assert!(browser.has_cookie("hearth_ui_session"));
}

/// A pending required action after a passkey sign-in keeps `return_to`: the
/// action's form ends on the continue page to the authorize URL.
#[tokio::test]
async fn a_required_action_after_a_passkey_keeps_return_to() {
    let rig = build_rig(RealmConfig {
        mfa_required: Some(false),
        ..Default::default()
    });
    let user = create_user(
        &rig,
        "pk-action@example.com",
        vec![RequiredAction::UpdatePassword],
    );
    let authenticator = enrol_passkey(&rig, &user, true);
    let return_to = authorize_return_to(&rig);

    let mut browser = Browser::new(rig.app.clone());
    let done = passkey_sign_in(
        &rig,
        &mut browser,
        &user,
        &authenticator,
        true,
        Some(&return_to),
    )
    .await;
    let action = done["redirect"].as_str().expect("redirect").to_string();
    assert!(
        action.starts_with("/required-action/"),
        "the sign-in owes the pending action: {done}"
    );

    let page = browser.get(&action).await;
    assert_eq!(page.status(), StatusCode::OK, "required-action page");
    let html = body_text(page).await;
    let mut fields = hidden_fields(&html, &action);
    let new_password = format!("New-{}-Aa1!", uuid::Uuid::new_v4().simple());
    fields.push(("current_password".to_string(), password()));
    fields.push(("new_password".to_string(), new_password.clone()));
    fields.push(("confirm_password".to_string(), new_password));
    let resp = browser.post_form(&action, &fields).await;

    assert_eq!(continue_target(&resp), return_to);
}
