//! The browser session a required-action detour ends in records the second
//! factor the login actually proved (GA audit round 3, D-1 / I-2).
//!
//! A login that hit a pending required action used to resume with
//! `MfaProof::Inherited`, which satisfies both `mfa_required` and
//! `webauthn_required`. So password + TOTP (or a UV-less passkey, or the
//! password alone) plus ANY pending action — and a realm listing `sms` in
//! `mfa_methods` makes `ENROLL_PHONE_OTP` pending for every user without a
//! verified phone — opened a session the same login was refused without the
//! detour. The detour now carries what the login proved, raised only by a
//! factor the flow itself proves, and a flow that cannot end in a session is
//! not started at all.
//!
//! Every flow is driven through a cookie jar that honours `Path`
//! (`support/browser.rs`), outside `--dev`.

#[path = "support/browser.rs"]
mod browser;
#[path = "common/webauthn_helper.rs"]
mod webauthn_helper;

use std::sync::Arc;

use axum::http::StatusCode;
use browser::{body_text, hidden_fields, location, Browser};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, MfaProof, RealmConfig,
    RegistrationOptions, RequiredAction, SmsError, SmsMessage, SmsSender, UpdateUserRequest,
    UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};

const COOKIE_SECRET: [u8; 32] = [47u8; 32];
const PASSWORD: &str = "ra-proof-password-1";
/// The origin and RP ID the server derives for a request with no `Host`.
const ORIGIN: &str = "http://localhost";
const RP_ID: &str = "localhost";
const PASSKEY_CHALLENGE: &str = "/ui/mfa-passkey-challenge";

/// An SMS transport that delivers nothing: these flows never get as far as
/// sending one once the fix is in place, and must not need to.
struct DroppedSms;
impl SmsSender for DroppedSms {
    fn send(&self, _message: &SmsMessage) -> Result<(), SmsError> {
        Ok(())
    }
}

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
    let realm_name = format!("ra-proof-{}", uuid::Uuid::new_v4().simple());
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
    .with_dev_mode(false)
    .with_sms(
        Arc::new(DroppedSms) as _,
        Some(b"ra-proof-sms-key".to_vec()),
    );
    Rig {
        app: web::router(state),
        identity,
        realm_id: realm.id().clone(),
        realm_name,
    }
}

fn methods(list: &[&str]) -> Option<Vec<String>> {
    Some(list.iter().map(|m| (*m).to_string()).collect())
}

/// An active user with a password and `actions` pending.
fn create_user(rig: &Rig, email: &str, actions: Vec<RequiredAction>) -> UserId {
    let user = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Proof User".to_string(),
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
        .complete_webauthn_registration(&rig.realm_id, user, &cdj, &att, ORIGIN, true)
        .expect("complete registration");
    authenticator
}

/// Posts the realm's password form and returns the browser and the response.
async fn post_password(rig: &Rig, email: &str) -> (Browser, axum::response::Response) {
    let mut browser = Browser::new(rig.app.clone());
    let login = format!("/ui/realms/{}/login", rig.realm_name);
    let resp = browser.get(&login).await;
    assert_eq!(resp.status(), StatusCode::OK, "login page");
    let html = body_text(resp).await;
    let mut fields = hidden_fields(&html, &login);
    fields.push(("email".to_string(), email.to_string()));
    fields.push(("password".to_string(), PASSWORD.to_string()));
    let resp = browser.post_form(&login, &fields).await;
    (browser, resp)
}

/// Opens the TOTP challenge page under the jar's pending cookie and submits
/// `code` through its form.
async fn submit_totp(browser: &mut Browser, code: &str) -> axum::response::Response {
    let page = browser.get("/ui/mfa-challenge").await;
    assert_eq!(page.status(), StatusCode::OK, "TOTP challenge page");
    let html = body_text(page).await;
    let mut fields = hidden_fields(&html, "/ui/mfa-challenge");
    fields.push(("code".to_string(), code.to_string()));
    browser.post_form("/ui/mfa-challenge", &fields).await
}

/// The `mfa_proof` of the browser session the jar now holds.
fn session_proof(rig: &Rig, browser: &Browser) -> MfaProof {
    let cookie = browser
        .cookie("hearth_ui_session")
        .expect("a session cookie");
    let session_id = cookie.split('.').next().expect("session id");
    let session_id = hearth::core::SessionId::new(session_id.parse().expect("uuid"));
    rig.identity
        .get_session(&rig.realm_id, &session_id)
        .expect("lookup")
        .expect("session")
        .mfa_proof()
}

fn phone_verified(rig: &Rig, user: &UserId) -> bool {
    rig.identity
        .get_user(&rig.realm_id, user)
        .expect("lookup")
        .expect("user")
        .phone_verified()
}

/// D-1: a passkey realm, a user holding a passkey AND TOTP, and `sms` offered
/// (so `ENROLL_PHONE_OTP` is pending for this phone-less user). The password
/// login owes the passkey; whoever relays the password and one TOTP code must
/// not reach a session — nor enrol a phone of their own on the way — by
/// answering the TOTP challenge instead.
#[tokio::test]
async fn a_totp_code_cannot_detour_a_passkey_login_through_a_required_action() {
    let rig = build_rig(RealmConfig {
        mfa_methods: methods(&["webauthn", "totp", "sms"]),
        webauthn_required: Some(true),
        ..Default::default()
    });
    let user = create_user(&rig, "d1-victim@example.com", vec![]);
    let secret = enrol_totp(&rig, &user);
    enrol_passkey(&rig, &user, true);

    let (mut browser, login) = post_password(&rig, "d1-victim@example.com").await;
    assert_eq!(
        location(&login).as_deref(),
        Some(PASSKEY_CHALLENGE),
        "control: the password login owes the passkey"
    );

    let resp = submit_totp(&mut browser, &totp_code(&secret, 1)).await;
    assert_eq!(
        location(&resp).as_deref(),
        Some(PASSKEY_CHALLENGE),
        "a TOTP code cannot finish a login that owes a passkey; it is sent back to the \
         passkey (status {})",
        resp.status()
    );
    assert!(
        !browser.has_cookie("hearth_ra_session"),
        "no required-action flow is started for a login that cannot end in a session"
    );
    assert!(
        !browser.has_cookie("hearth_ui_session"),
        "no session is issued"
    );
    assert!(
        !phone_verified(&rig, &user),
        "and no phone is enrolled on the account"
    );
}

/// I-2 (A): a UV-less passkey proves possession only. On a passkey realm it
/// is refused outright without a pending action; with one it must not come
/// out of the required-action flow as a full session either.
#[tokio::test]
async fn a_uv_less_passkey_cannot_detour_a_login_through_a_required_action() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let rig = build_rig(RealmConfig {
        mfa_methods: methods(&["webauthn", "sms"]),
        webauthn_required: Some(true),
        ..Default::default()
    });
    let user = create_user(&rig, "i2-uvless@example.com", vec![]);
    let authenticator = enrol_passkey(&rig, &user, false);

    let mut browser = Browser::new(rig.app.clone());
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
    let (cdj, auth_data, sig, handle) =
        authenticator.build_authentication_response(&challenge, ORIGIN, 1, Some(&user_handle));
    let resp = browser
        .post_json(
            &format!("/ui/realms/{}/login/passkey-complete", rig.realm_name),
            &serde_json::json!({
                "credential_id": URL_SAFE_NO_PAD.encode(&authenticator.credential_id),
                "client_data_json": URL_SAFE_NO_PAD.encode(&cdj),
                "authenticator_data": URL_SAFE_NO_PAD.encode(&auth_data),
                "signature": URL_SAFE_NO_PAD.encode(&sig),
                "user_handle": handle.map(|h| URL_SAFE_NO_PAD.encode(h)),
            }),
            &[],
        )
        .await;
    let status = resp.status();
    let body = body_text(resp).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let body: serde_json::Value = serde_json::from_str(&body).expect("completion JSON");
    assert_eq!(
        body["redirect"], PASSKEY_CHALLENGE,
        "the login owes a user-verified passkey, not a required-action detour: {body}"
    );
    assert!(!browser.has_cookie("hearth_ra_session"));
    assert!(!browser.has_cookie("hearth_ui_session"));
    assert!(!phone_verified(&rig, &user));
}

/// I-2 (B): an `mfa_required` realm whose only method is a passkey, and a
/// password-only user with an operator-forced password change. Without the
/// pending action the password alone is refused; with it, completing the
/// action must not open a session either.
#[tokio::test]
async fn a_required_action_does_not_stand_in_for_the_second_factor_a_realm_requires() {
    let rig = build_rig(RealmConfig {
        mfa_required: Some(true),
        mfa_methods: methods(&["webauthn"]),
        ..Default::default()
    });
    create_user(
        &rig,
        "i2-pw-only@example.com",
        vec![RequiredAction::UpdatePassword],
    );

    let (browser, resp) = post_password(&rig, "i2-pw-only@example.com").await;
    let status = resp.status();
    let next = location(&resp);
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the login proved no second factor and no pending action can prove one \
         (redirected to {next:?})"
    );
    assert!(!browser.has_cookie("hearth_ra_session"));
    assert!(!browser.has_cookie("hearth_ui_session"));
}

/// The session a completed detour opens records the factor the login
/// proved — `Proved` for a TOTP code — never `Inherited`.
#[tokio::test]
async fn the_session_after_a_required_action_records_the_factor_the_login_proved() {
    let rig = build_rig(RealmConfig {
        mfa_methods: methods(&["totp"]),
        ..Default::default()
    });
    let user = create_user(
        &rig,
        "ra-proof-totp@example.com",
        vec![RequiredAction::UpdatePassword],
    );
    let secret = enrol_totp(&rig, &user);

    let (mut browser, login) = post_password(&rig, "ra-proof-totp@example.com").await;
    assert_eq!(
        login.status(),
        StatusCode::OK,
        "the TOTP step renders inline"
    );
    let resp = submit_totp(&mut browser, &totp_code(&secret, 1)).await;
    assert_eq!(
        location(&resp).as_deref(),
        Some("/required-action/UPDATE_PASSWORD"),
        "the proved login detours through the pending action"
    );

    let page = browser.get("/required-action/UPDATE_PASSWORD").await;
    assert_eq!(page.status(), StatusCode::OK);
    let html = body_text(page).await;
    let mut fields = hidden_fields(&html, "/required-action/UPDATE_PASSWORD");
    let new = "ra-proof-password-2";
    fields.push(("current_password".to_string(), PASSWORD.to_string()));
    fields.push(("new_password".to_string(), new.to_string()));
    fields.push(("confirm_password".to_string(), new.to_string()));
    let resp = browser
        .post_form("/required-action/UPDATE_PASSWORD", &fields)
        .await;
    assert_eq!(location(&resp).as_deref(), Some("/ui"), "the login lands");
    assert_eq!(
        session_proof(&rig, &browser),
        MfaProof::Proved,
        "the session records the TOTP the login proved"
    );
}

/// The resume itself re-checks the proof: a TOTP login on a passkey realm
/// detours to register a passkey, the user registers one elsewhere meanwhile,
/// and the action is skipped as satisfied. The login still proved only TOTP,
/// so it is sent to the passkey rather than into a session.
#[tokio::test]
async fn a_skipped_passkey_enrolment_does_not_turn_a_totp_login_into_a_passkey_login() {
    let rig = build_rig(RealmConfig {
        mfa_methods: methods(&["webauthn", "totp"]),
        webauthn_required: Some(true),
        ..Default::default()
    });
    let user = create_user(&rig, "ra-proof-skip@example.com", vec![]);
    let secret = enrol_totp(&rig, &user);

    let (mut browser, login) = post_password(&rig, "ra-proof-skip@example.com").await;
    assert_eq!(
        login.status(),
        StatusCode::OK,
        "the TOTP step renders inline"
    );
    let resp = submit_totp(&mut browser, &totp_code(&secret, 1)).await;
    assert_eq!(
        location(&resp).as_deref(),
        Some("/required-action/enroll-mfa"),
        "the realm requires a passkey the user does not hold yet"
    );

    // Registered from another device while this login waits.
    enrol_passkey(&rig, &user, true);

    let resp = browser.get("/required-action/enroll-mfa").await;
    assert_eq!(
        location(&resp).as_deref(),
        Some(PASSKEY_CHALLENGE),
        "the satisfied action is skipped, and the login still owes the passkey (status {})",
        resp.status()
    );
    assert!(!browser.has_cookie("hearth_ui_session"), "no session");
}

/// Same class, network policy: a passkey login (which leaves the realm's
/// `cidr_policy` to `create_session`) from a refused network must not start a
/// required-action flow. The flow's session used to be created with no client
/// address at all, which the policy check reads as "nothing to refuse".
#[tokio::test]
async fn a_refused_network_cannot_detour_a_login_through_a_required_action() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let rig = build_rig(RealmConfig {
        mfa_methods: methods(&["webauthn"]),
        // The test client's peer address is loopback.
        cidr_policy: Some(hearth::identity::CidrPolicy {
            allow: Vec::new(),
            deny: vec!["127.0.0.0/8".to_string()],
        }),
        ..Default::default()
    });
    let user = create_user(
        &rig,
        "cidr-detour@example.com",
        vec![RequiredAction::UpdatePassword],
    );
    let authenticator = enrol_passkey(&rig, &user, true);

    let mut browser = Browser::new(rig.app.clone());
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
    let (cdj, auth_data, sig, handle) = authenticator.build_verified_authentication_response(
        &challenge,
        ORIGIN,
        1,
        Some(&user_handle),
    );
    let resp = browser
        .post_json(
            &format!("/ui/realms/{}/login/passkey-complete", rig.realm_name),
            &serde_json::json!({
                "credential_id": URL_SAFE_NO_PAD.encode(&authenticator.credential_id),
                "client_data_json": URL_SAFE_NO_PAD.encode(&cdj),
                "authenticator_data": URL_SAFE_NO_PAD.encode(&auth_data),
                "signature": URL_SAFE_NO_PAD.encode(&sig),
                "user_handle": handle.map(|h| URL_SAFE_NO_PAD.encode(h)),
            }),
            &[],
        )
        .await;
    let status = resp.status();
    let body = body_text(resp).await;
    assert!(
        !body.contains("/required-action/"),
        "a login from a refused network must not start a required-action flow: {status} {body}"
    );
    assert!(!browser.has_cookie("hearth_ra_session"));
    assert!(!browser.has_cookie("hearth_ui_session"));
}

// ── D-11: no required-action session for an account that cannot sign in ─────

async fn assert_no_required_action_flow(rig: &Rig, email: &str) {
    let (browser, resp) = post_password(rig, email).await;
    let next = location(&resp);
    assert!(
        !next
            .as_deref()
            .is_some_and(|l| l.starts_with("/required-action/")),
        "an account that cannot sign in must not be handed a required-action flow \
         (status {}, location {next:?})",
        resp.status()
    );
    assert!(!browser.has_cookie("hearth_ra_session"));
    assert!(!browser.has_cookie("hearth_ui_session"));
}

/// GA audit round 3, D-11: a disabled account holder who knows the password
/// could still run required actions (change the password, bind a phone).
#[tokio::test]
async fn a_disabled_account_is_not_handed_a_required_action_flow() {
    let rig = build_rig(RealmConfig::default());
    let user = create_user(
        &rig,
        "d11-disabled@example.com",
        vec![RequiredAction::UpdatePassword],
    );
    rig.identity
        .update_user(
            &rig.realm_id,
            &user,
            &UpdateUserRequest {
                status: Some(UserStatus::Disabled),
                ..Default::default()
            },
        )
        .expect("disable");
    assert_no_required_action_flow(&rig, "d11-disabled@example.com").await;
}

/// D-11: nor an account still waiting for its email to be verified.
#[tokio::test]
async fn an_unverified_account_is_not_handed_a_required_action_flow() {
    let rig = build_rig(RealmConfig::default());
    let user = create_user(
        &rig,
        "d11-unverified@example.com",
        vec![RequiredAction::UpdatePassword],
    );
    rig.identity
        .update_user(
            &rig.realm_id,
            &user,
            &UpdateUserRequest {
                status: Some(UserStatus::PendingVerification),
                ..Default::default()
            },
        )
        .expect("mark unverified");
    assert_no_required_action_flow(&rig, "d11-unverified@example.com").await;
}

// ── D-2: a required-action session ends in at most one session, and dies with
// the user's sessions ─────────────────────────────────────────────────────────

/// An active user whose address is verified, with `VERIFY_EMAIL` still
/// pending — the action's page clears it as already satisfied and ends the
/// flow, which is exactly the page a replayed RA cookie used to reuse.
fn verified_user_with_pending_verification(rig: &Rig, email: &str) -> UserId {
    let user = create_user(rig, email, vec![RequiredAction::VerifyEmail]);
    let token = rig
        .identity
        .issue_email_verification_token(&rig.realm_id, &user)
        .expect("issue verification token");
    rig.identity
        .verify_email_token(&rig.realm_id, &token)
        .expect("verify");
    user
}

/// A browser that holds only `ra_cookie` (the value of `hearth_ra_session`).
fn browser_with_ra_cookie(rig: &Rig, ra_cookie: &str) -> Browser {
    let mut browser = Browser::new(rig.app.clone());
    browser.accept_set_cookie(
        &format!("hearth_ra_session={ra_cookie}; HttpOnly; Path=/required-action"),
        "/required-action/VERIFY_EMAIL",
    );
    browser
}

/// Starts the password login and returns the RA cookie value it was handed.
async fn start_verify_email_flow(rig: &Rig, email: &str) -> (Browser, String) {
    let (browser, resp) = post_password(rig, email).await;
    assert_eq!(
        location(&resp).as_deref(),
        Some("/required-action/VERIFY_EMAIL"),
        "control: the login detours through the pending action"
    );
    let ra = browser
        .cookie("hearth_ra_session")
        .expect("the login set the RA cookie");
    (browser, ra)
}

/// GA audit round 3, D-2: replaying the RA cookie after the flow ended
/// minted a fresh browser session on every replay (the already-satisfied
/// page ends the flow again). Only UPDATE_PASSWORD was single-use.
#[tokio::test]
async fn a_required_action_session_opens_at_most_one_session() {
    let rig = build_rig(RealmConfig::default());
    verified_user_with_pending_verification(&rig, "d2-replay@example.com");
    let (mut browser, ra) = start_verify_email_flow(&rig, "d2-replay@example.com").await;
    let resp = browser.get("/required-action/VERIFY_EMAIL").await;
    assert_eq!(
        location(&resp).as_deref(),
        Some("/ui"),
        "the flow completes"
    );
    assert!(
        browser.has_cookie("hearth_ui_session"),
        "control: one session"
    );

    let mut replay = browser_with_ra_cookie(&rig, &ra);
    let resp = replay.get("/required-action/VERIFY_EMAIL").await;
    assert!(
        !replay.has_cookie("hearth_ui_session"),
        "a replayed RA cookie must not open another session (status {}, location {:?})",
        resp.status(),
        location(&resp)
    );
}

/// D-2: signing the user out everywhere ends a flow that was under way.
#[tokio::test]
async fn revoking_the_users_sessions_ends_a_required_action_flow() {
    let rig = build_rig(RealmConfig::default());
    let user = verified_user_with_pending_verification(&rig, "d2-revoke@example.com");
    let (_, ra) = start_verify_email_flow(&rig, "d2-revoke@example.com").await;

    rig.identity
        .revoke_all_user_sessions(&rig.realm_id, &user, None)
        .expect("revoke all");

    let mut browser = browser_with_ra_cookie(&rig, &ra);
    let resp = browser.get("/required-action/VERIFY_EMAIL").await;
    assert!(
        !browser.has_cookie("hearth_ui_session"),
        "the RA session must die with the user's sessions (status {}, location {:?})",
        resp.status(),
        location(&resp)
    );
}

/// D-2: so does signing out of any of the user's sessions.
#[tokio::test]
async fn logging_out_ends_a_required_action_flow() {
    let rig = build_rig(RealmConfig::default());
    let user = verified_user_with_pending_verification(&rig, "d2-logout@example.com");
    let session = rig
        .identity
        .create_session(
            &rig.realm_id,
            &user,
            &hearth::identity::SessionContext::default(),
        )
        .expect("an existing session");
    let (_, ra) = start_verify_email_flow(&rig, "d2-logout@example.com").await;

    // The user signs out of the existing session in another browser.
    let issued = web::auth::issue_auth_cookies(
        &CookieSecret::from_bytes(COOKIE_SECRET),
        &rig.realm_id,
        session.id(),
        false,
    );
    let mut other = Browser::new(rig.app.clone());
    other.accept_set_cookie(&issued.session_cookie, "/ui/login");
    other.accept_set_cookie(&issued.csrf_cookie, "/ui/login");
    let csrf = other.cookie("hearth_ui_csrf").expect("csrf cookie");
    let resp = other
        .post_form("/ui/logout", &[("_csrf".to_string(), csrf)])
        .await;
    assert!(resp.status().is_redirection(), "logout: {}", resp.status());

    let mut browser = browser_with_ra_cookie(&rig, &ra);
    let resp = browser.get("/required-action/VERIFY_EMAIL").await;
    assert!(
        !browser.has_cookie("hearth_ui_session"),
        "the RA session must not outlive a sign-out (status {}, location {:?})",
        resp.status(),
        location(&resp)
    );
}

/// The session a required-action flow ends in records the client like any
/// other login — its address (which the realm's network policy is checked
/// against) and its user agent (shown in the user's session list). It used
/// to record neither.
#[tokio::test]
async fn the_session_after_a_required_action_records_the_client() {
    let rig = build_rig(RealmConfig::default());
    verified_user_with_pending_verification(&rig, "ra-client@example.com");
    let mut browser = Browser::new(rig.app.clone());
    browser.set_header("user-agent", "RaProofAgent/1.0");
    let login = format!("/ui/realms/{}/login", rig.realm_name);
    let html = body_text(browser.get(&login).await).await;
    let mut fields = hidden_fields(&html, &login);
    fields.push(("email".to_string(), "ra-client@example.com".to_string()));
    fields.push(("password".to_string(), PASSWORD.to_string()));
    let resp = browser.post_form(&login, &fields).await;
    assert_eq!(
        location(&resp).as_deref(),
        Some("/required-action/VERIFY_EMAIL")
    );
    let resp = browser.get("/required-action/VERIFY_EMAIL").await;
    assert_eq!(location(&resp).as_deref(), Some("/ui"));

    let cookie = browser.cookie("hearth_ui_session").expect("session");
    let session_id =
        hearth::core::SessionId::new(cookie.split('.').next().expect("id").parse().expect("uuid"));
    let session = rig
        .identity
        .get_session(&rig.realm_id, &session_id)
        .expect("lookup")
        .expect("session");
    assert_eq!(session.ip_address(), Some("127.0.0.1"));
    assert_eq!(session.user_agent_raw(), Some("RaProofAgent/1.0"));
}
