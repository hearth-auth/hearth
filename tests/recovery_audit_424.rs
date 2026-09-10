//! Regression tests for the audit-2026-08-28 §4.24 browser recovery and
//! self-registration findings.
//!
//! | Finding | Test |
//! |---|---|
//! | #10 — admin reset actions mint a token, discard it, report "sent" | `admin_send_reset_actually_delivers_email`, `admin_bulk_send_invite_actually_delivers_email` |
//! | #7  — admin reset link points at a route that does not exist | `admin_reset_password_route_exists`, `admin_forgot_password_emails_a_resolvable_link` |
//! | #5  — a short password destroys the link while the page says "try again" | `short_password_does_not_burn_the_reset_link` |
//! | #3  — `POST /ui/forgot-password` leaks existence via the in-request send | `forgot_password_send_is_off_the_request_path` |
//! | #4  — the duplicate-email register arm skips Argon2id | `register_duplicate_email_does_the_same_kdf_work` |
//! | #6  — magic-link login cannot complete | `magic_link_redemption_route_creates_a_session` |

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::core::{Clock, RealmId, SessionId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailError, EmailMessage, EmailSender, EmailService};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RealmConfig, RegisterUserRequest,
    RegistrationPolicy, SessionContext, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET_BYTES: [u8; 32] = [11u8; 32];

// ── A recording email transport ──────────────────────────────────────────────

/// Captures every message handed to the transport, and optionally blocks
/// inside `send` until the test releases it. The block is what makes the
/// "off the request path" property observable without a wall-clock sleep.
struct RecordingSender {
    inbox: Arc<Mutex<Vec<EmailMessage>>>,
    /// When set, `send` blocks on this receiver before recording.
    gate: Option<Mutex<mpsc::Receiver<()>>>,
    /// Incremented the moment `send` is entered, before any blocking.
    entered: Arc<AtomicUsize>,
}

impl EmailSender for RecordingSender {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.gate {
            // INVARIANT: the receiver mutex is only contended by concurrent
            // sends inside a single test; a poisoned lock is a test bug.
            #[allow(clippy::unwrap_used)]
            let rx = gate.lock().unwrap();
            let _ = rx.recv();
        }
        #[allow(clippy::unwrap_used)]
        self.inbox.lock().unwrap().push(message.clone());
        Ok(())
    }
}

#[derive(Clone)]
struct Inbox {
    messages: Arc<Mutex<Vec<EmailMessage>>>,
    entered: Arc<AtomicUsize>,
}

impl Inbox {
    fn len(&self) -> usize {
        #[allow(clippy::unwrap_used)]
        self.messages.lock().unwrap().len()
    }

    fn entered(&self) -> usize {
        self.entered.load(Ordering::SeqCst)
    }

    fn last_body(&self) -> String {
        #[allow(clippy::unwrap_used)]
        let guard = self.messages.lock().unwrap();
        guard
            .last()
            .map(|m| format!("{}\n{}", m.text_body, m.html_body))
            .unwrap_or_default()
    }

    fn recipients(&self) -> Vec<String> {
        #[allow(clippy::unwrap_used)]
        let guard = self.messages.lock().unwrap();
        guard.iter().map(|m| m.to.clone()).collect()
    }
}

fn recording_email_service(gate: Option<mpsc::Receiver<()>>) -> (Arc<EmailService>, Inbox) {
    let messages: Arc<Mutex<Vec<EmailMessage>>> = Arc::new(Mutex::new(Vec::new()));
    let entered = Arc::new(AtomicUsize::new(0));
    let sender = Arc::new(RecordingSender {
        inbox: Arc::clone(&messages),
        gate: gate.map(Mutex::new),
        entered: Arc::clone(&entered),
    });
    let service = Arc::new(
        EmailService::new(
            sender,
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    (service, Inbox { messages, entered })
}

// ── Rig ──────────────────────────────────────────────────────────────────────

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    inbox: Inbox,
    admin_session_id: SessionId,
}

#[allow(clippy::too_many_lines)]
fn build_rig(gate: Option<mpsc::Receiver<()>>) -> Rig {
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

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "acme".to_string(),
            config: Some(RealmConfig {
                registration_policy: Some(RegistrationPolicy::Open),
                allowed_auth_methods: Some(vec!["password".to_string(), "magic_link".to_string()]),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    // Admin identity lives in the system realm (nil UUID).
    let admin_realm_id = RealmId::new(uuid::Uuid::nil());
    let admin_user = identity
        .create_admin_user(&CreateUserRequest {
            email: "admin@acme.test".to_string(),
            display_name: "Admin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create admin user");
    identity
        .set_password(
            &admin_realm_id,
            admin_user.id(),
            &CleartextPassword::from_string("correct-horse-battery-staple".to_string()),
        )
        .expect("set admin password");
    identity
        .update_user(
            &admin_realm_id,
            admin_user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate admin");
    let admin_session = identity
        .create_session(&admin_realm_id, admin_user.id(), &SessionContext::default())
        .expect("admin session");
    authz
        .seed_realm(&admin_realm_id)
        .expect("seed system realm");
    let admin_role = authz
        .get_role_by_name(&admin_realm_id, "realm.admin")
        .expect("lookup role")
        .expect("seed role present");
    authz
        .assign_role(
            &admin_realm_id,
            &hearth::rbac::AssignRoleRequest {
                subject: hearth::rbac::Subject::User(admin_user.id().clone()),
                role_id: admin_role.id.clone(),
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");

    let (email, inbox) = recording_email_service(gate);
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        Arc::clone(&email),
        data_dir,
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
    .with_default_realm(Some("acme".to_string()));
    let app = web::router(state);

    Rig {
        app,
        identity,
        realm_id: realm.id().clone(),
        inbox,
        admin_session_id: admin_session.id().clone(),
    }
}

fn admin_cookie(rig: &Rig, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let admin_realm = RealmId::new(uuid::Uuid::nil());
    #[allow(clippy::unwrap_used)]
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET_BYTES).unwrap();
    mac.update(rig.admin_session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(admin_realm.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        rig.admin_session_id.as_uuid(),
        admin_realm.as_uuid(),
        tag,
        csrf,
    )
}

async fn post_form(app: &axum::Router, uri: &str, body: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .expect("build POST"),
        )
        .await
        .expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn post_form_authed(
    app: &axum::Router,
    uri: &str,
    cookie: &str,
    body: &str,
) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .expect("build POST"),
        )
        .await
        .expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// Waits for `n` messages to reach the recording transport.
///
/// Pre-auth handlers hand the send to the blocking pool so SMTP latency
/// cannot distinguish a known address from an unknown one
/// (audit 2026-08-28 §4.24#3), so delivery is observed after the response.
async fn await_inbox(inbox: &Inbox, n: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while inbox.len() < n && std::time::Instant::now() < deadline {
        tokio::task::yield_now().await;
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
            &CleartextPassword::from_string("correct-horse-battery-staple".to_string()),
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

// ── §4.24#10 — the admin reset actions must actually send ────────────────────

#[tokio::test]
async fn admin_send_reset_actually_delivers_email() {
    let rig = build_rig(None);
    let user_id = make_active_user(&rig, "victim@acme.test");
    let cookie = admin_cookie(&rig, "csrf-admin");

    let (status, _body) = post_form_authed(
        &rig.app,
        &format!(
            "/ui/admin/realms/acme/users/{}/reset-password",
            user_id.as_uuid()
        ),
        &cookie,
        "_csrf=csrf-admin",
    )
    .await;
    assert!(
        status.is_success() || status.is_redirection(),
        "admin reset-password action must succeed; got {status}"
    );

    assert_eq!(
        rig.inbox.len(),
        1,
        "the admin reset action reports 'Reset email sent' — it must actually send one \
         (audit §4.24#10); recipients so far: {:?}",
        rig.inbox.recipients()
    );
    assert_eq!(
        rig.inbox.recipients(),
        vec!["victim@acme.test".to_string()],
        "the reset email must go to the target user"
    );
    assert!(
        rig.inbox.last_body().contains("reset-password?token="),
        "the reset email must carry a reset link; body was: {}",
        rig.inbox.last_body()
    );
}

#[tokio::test]
async fn admin_bulk_send_invite_actually_delivers_email() {
    let rig = build_rig(None);
    let a = make_active_user(&rig, "one@acme.test");
    let b = make_active_user(&rig, "two@acme.test");
    let cookie = admin_cookie(&rig, "csrf-admin");

    let body = format!(
        "_csrf=csrf-admin&bulk_action=send_invite&ids={},{}",
        a.as_uuid(),
        b.as_uuid()
    );
    let (status, _) = post_form_authed(
        &rig.app,
        "/ui/admin/realms/acme/users/bulk-action",
        &cookie,
        &body,
    )
    .await;
    assert!(
        status.is_success() || status.is_redirection(),
        "bulk send_invite must succeed; got {status}"
    );

    let mut recipients = rig.inbox.recipients();
    recipients.sort();
    assert_eq!(
        recipients,
        vec!["one@acme.test".to_string(), "two@acme.test".to_string()],
        "bulk send_invite reports 'invited' — it must actually send (audit §4.24#10)"
    );
}

// ── §4.24#7 — the admin reset link must point at a live route ────────────────

#[tokio::test]
async fn admin_reset_password_route_exists() {
    let rig = build_rig(None);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/admin/reset-password?token=whatever")
                .body(Body::empty())
                .expect("build GET"),
        )
        .await
        .expect("oneshot");
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "GET /ui/admin/reset-password must exist — the admin forgot-password mail links to it \
         (audit §4.24#7)"
    );
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn admin_forgot_password_emails_a_resolvable_link() {
    let rig = build_rig(None);
    // The admin account lives in the system realm.
    let (status, _) = post_form(
        &rig.app,
        "/ui/admin/forgot-password",
        "email=admin%40acme.test",
    )
    .await;
    assert!(
        status.is_redirection(),
        "admin forgot-password must redirect to the sent page; got {status}"
    );
    await_inbox(&rig.inbox, 1).await;
    assert_eq!(rig.inbox.len(), 1, "an admin reset email must be sent");

    let body = rig.inbox.last_body();
    let token = body
        .split("/ui/admin/reset-password?token=")
        .nth(1)
        .map(|rest| {
            rest.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect::<String>()
        })
        .expect("admin reset mail must link to /ui/admin/reset-password (audit §4.24#7)");
    assert!(!token.is_empty(), "the emailed link must carry a token");

    // The emailed link must complete a reset, not 404.
    let (status, body) = post_form(
        &rig.app,
        "/ui/admin/reset-password",
        &format!(
            "token={token}&password=brand-new-passphrase&password_confirm=brand-new-passphrase"
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "POST /ui/admin/reset-password must complete the reset; body: {body}"
    );
    let admin_realm = RealmId::new(uuid::Uuid::nil());
    let admin = rig
        .identity
        .get_user_by_email(&admin_realm, "admin@acme.test")
        .expect("lookup admin")
        .expect("admin exists");
    assert!(
        rig.identity
            .verify_password(
                &admin_realm,
                admin.id(),
                &CleartextPassword::from_string("brand-new-passphrase".to_string()),
            )
            .expect("verify"),
        "the reset must have taken effect"
    );
}

// ── §4.24#5 — a rejected password must not burn the link ─────────────────────

#[tokio::test]
async fn short_password_does_not_burn_the_reset_link() {
    let rig = build_rig(None);
    make_active_user(&rig, "shorty@acme.test");
    let token = rig
        .identity
        .request_password_reset(&rig.realm_id, "shorty@acme.test")
        .expect("request reset")
        .expect("token for a known address");

    // 11 characters: above the handler's old 8-char pre-gate, below the
    // 12-character policy floor.
    let (status, body) = post_form(
        &rig.app,
        "/ui/reset-password",
        &format!("token={token}&password=elevenchar&password_confirm=elevenchar"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the form must re-render, not error");
    assert!(
        body.contains("12 characters"),
        "the page must name the real requirement, not a generic 'try again' \
         (audit §4.24#5); body: {body}"
    );

    // The link must still work with a compliant password.
    let (status, body) = post_form(
        &rig.app,
        "/ui/reset-password",
        &format!(
            "token={token}&password=a-perfectly-fine-passphrase\
             &password_confirm=a-perfectly-fine-passphrase"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("invalid or has expired"),
        "the rejected attempt must not have consumed the token (audit §4.24#5); body: {body}"
    );
    let shorty = rig
        .identity
        .get_user_by_email(&rig.realm_id, "shorty@acme.test")
        .expect("lookup")
        .expect("exists");
    assert!(
        rig.identity
            .verify_password(
                &rig.realm_id,
                shorty.id(),
                &CleartextPassword::from_string("a-perfectly-fine-passphrase".to_string()),
            )
            .expect("verify"),
        "the second attempt must succeed on the same link"
    );
}

// ── §4.24#3 — the SMTP send must not sit on the request path ─────────────────

#[tokio::test]
async fn forgot_password_send_is_off_the_request_path() {
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let rig = build_rig(Some(release_rx));
    make_active_user(&rig, "known@acme.test");

    // Watchdog: if the send is still on the request path the handler would
    // block forever, so release the transport after a bounded wait. The
    // assertions below then fail (the message landed before the response),
    // rather than the test hanging.
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        let _ = done_rx.recv_timeout(std::time::Duration::from_secs(5));
        let _ = release_tx.send(());
        release_tx
    });

    let (status, _) = post_form(&rig.app, "/ui/forgot-password", "email=known%40acme.test").await;
    let delivered_before_response = rig.inbox.len();
    // Wait for the deferred send to at least *enter* the transport, so the
    // assertion below cannot pass vacuously by no mail being attempted.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while rig.inbox.entered() == 0 && std::time::Instant::now() < deadline {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        rig.inbox.entered(),
        1,
        "the transport must have been called — otherwise 'nothing delivered before the \
         response' proves nothing"
    );
    let _ = done_tx.send(());
    let release_tx = watchdog.join().expect("watchdog thread");

    assert!(status.is_redirection(), "must redirect to the sent page");
    assert_eq!(
        delivered_before_response, 0,
        "the SMTP send must not sit on the request path — a slow transport is an \
         account-existence oracle (audit §4.24#3)"
    );

    // Release and confirm the mail is still genuinely sent.
    let _ = release_tx.send(());
    await_inbox(&rig.inbox, 1).await;
    assert_eq!(
        rig.inbox.len(),
        1,
        "deferring the send must not drop it — the reset mail must still be delivered"
    );
}

// ── §4.24#4 — the duplicate-email register arm must do equal work ────────────

#[tokio::test]
async fn register_duplicate_email_does_the_same_kdf_work() {
    // Real (not `fast_for_testing`) Argon2id parameters so the skipped work is
    // measurable. The assertion is a lower bound on the duplicate arm, which
    // is robust: it cannot fail by the machine being slow.
    let temp = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(temp.path().to_path_buf()))
            .expect("storage"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let identity = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
        IdentityConfig::default(),
        audit,
    )
    .expect("identity engine");
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "dup".to_string(),
            config: Some(RealmConfig {
                registration_policy: Some(RegistrationPolicy::Open),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    let req = |email: &str| RegisterUserRequest {
        email: email.to_string(),
        display_name: "N".to_string(),
        first_name: String::new(),
        last_name: String::new(),
        password: CleartextPassword::from_string("correct-horse-battery-staple".to_string()),
        client_ip: None,
        invitation_token: None,
    };

    // Arm A: a fresh address — pays for Argon2id.
    let t0 = std::time::Instant::now();
    identity
        .register_user(realm.id(), &req("fresh@dup.test"))
        .expect("first registration");
    let fresh_cost = t0.elapsed();

    // Arm B: the same address again — must pay the same.
    let t1 = std::time::Instant::now();
    identity
        .register_user(realm.id(), &req("fresh@dup.test"))
        .expect("duplicate registration must still look like success");
    let duplicate_cost = t1.elapsed();

    // Guard against a degenerate measurement: if the fresh arm were itself
    // ~free the ratio assertion below would pass vacuously.
    assert!(
        fresh_cost.as_millis() >= 5,
        "the fresh arm must actually pay for Argon2id for this comparison to mean \
         anything; measured {fresh_cost:?}"
    );
    assert!(
        duplicate_cost.as_micros() * 4 >= fresh_cost.as_micros(),
        "the duplicate-email arm must do comparable work to the fresh arm — skipping \
         Argon2id makes a registered address measurably faster (audit §4.24#4). \
         fresh={fresh_cost:?} duplicate={duplicate_cost:?}"
    );
}

// ── §4.24#6 — magic-link login must be able to complete ──────────────────────

#[tokio::test]
async fn magic_link_redemption_route_creates_a_session() {
    let rig = build_rig(None);
    make_active_user(&rig, "wanderer@acme.test");

    let response = rig
        .identity
        .request_magic_link(&rig.realm_id, "wanderer@acme.test")
        .expect("mint a magic link");

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/magic-link?token={}", response.token()))
                .body(Body::empty())
                .expect("build GET"),
        )
        .await
        .expect("oneshot");

    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "a magic-link redemption route must exist — without it the flow cannot complete \
         (audit §4.24#6)"
    );
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "redeeming a valid magic link must redirect into the signed-in UI"
    );
    let cookies: Vec<String> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect();
    assert!(
        cookies.iter().any(|c| c.starts_with("hearth_ui_session=")),
        "redeeming a magic link must issue a browser session cookie; got {cookies:?}"
    );

    // Single use: the second redemption must not mint another session.
    let resp2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/magic-link?token={}", response.token()))
                .body(Body::empty())
                .expect("build GET"),
        )
        .await
        .expect("oneshot");
    assert_ne!(
        resp2.status(),
        StatusCode::SEE_OTHER,
        "a magic link must be single-use"
    );
}
