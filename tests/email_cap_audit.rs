//! A send that an outbound email cap stops or flags is audited (#622).
//!
//! The A-4 per-realm shield and the A-50 cross-realm cap only logged a
//! warning. The `abuse-prevention` spec requires an `AbuseDetected` audit
//! event and the A-7 security webhook, so the operator sees email abuse (a
//! flood of reset or verification emails) in the audit log and the SIEM.
//!
//! The rig's audit engine is wrapped exactly as `serve` wraps it, so an event
//! that arrives on the broadcast channel is an event the webhook dispatcher
//! receives.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::abuse::runtime::AbuseGuards;
use hearth::audit::{AuditAction, AuditEngine, AuditEvent, AuditQuery};
use hearth::config::SecurityYaml;
use hearth::core::{RealmId, UserId};
use hearth::identity::email::{EmailBranding, EmailError, EmailMessage, EmailSender, EmailService};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, SessionContext, UpdateUserRequest,
    UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use hearth::webhook::dispatcher::{audit_event_channel, AuditEventReceiver};
use hearth::webhook::NotifyingAuditEngine;
use tower::ServiceExt as _;

/// A-4 stops every send: the first recipient is over a hard cap of 0.
const A4_HARD: &str =
    "outbound_volume_shield:\n  enabled: true\n  email_soft_cap: 0\n  email_hard_cap: 0\n";

/// A-4 flags every send and stops none.
const A4_SOFT: &str =
    "outbound_volume_shield:\n  enabled: true\n  email_soft_cap: 0\n  email_hard_cap: 1000\n";

/// A-50 stops every send: one realm is over a hard cap of 0.
const A50_HARD: &str = "cross_realm_aggregation_cap:\n  enabled: true\n  alert_threshold: 0\n  \
     email_realm_soft_cap: 0\n  email_realm_hard_cap: 0\n";

/// Counts the messages handed to the transport.
struct CountingSender(Arc<AtomicUsize>);

impl EmailSender for CountingSender {
    fn send(&self, _message: &EmailMessage) -> Result<(), EmailError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct Rig {
    h: common::TestHarness,
    realm: RealmId,
    realm_name: String,
    web: axum::Router,
    api: axum::Router,
    /// What the webhook dispatcher receives.
    webhook_feed: AuditEventReceiver,
    sent: Arc<AtomicUsize>,
}

impl Rig {
    async fn new(security: &str) -> Self {
        let h = common::TestHarness::in_process().await.expect("harness");
        let yaml: SecurityYaml = serde_norway::from_str(security).expect("security block");
        let guards = Arc::new(AbuseGuards::from_security(&yaml));
        let (tx, webhook_feed) = audit_event_channel();
        let audit = Arc::new(NotifyingAuditEngine::new(h.audit_arc(), tx)) as Arc<dyn AuditEngine>;
        let sent = Arc::new(AtomicUsize::new(0));
        let email = Arc::new(
            EmailService::new(
                Arc::new(CountingSender(Arc::clone(&sent))),
                "Hearth".to_string(),
                None,
                EmailBranding::default(),
                String::new(),
                None,
            )
            .expect("email service"),
        );
        let realm = h
            .identity()
            .create_realm(&CreateRealmRequest {
                name: format!("capped-{}", uuid::Uuid::new_v4().simple()),
                config: None,
            })
            .expect("create realm");
        h.rbac().seed_realm(realm.id()).expect("seed realm");

        let temp = tempfile::tempdir().expect("tempdir");
        let data_dir = temp.path().to_path_buf();
        let _ = temp.keep();
        let onboarding = Arc::new(OnboardingService::new(
            h.identity_arc(),
            h.rbac_arc(),
            Arc::clone(&email),
            data_dir,
        ));
        let web = web::router(
            WebState::new(
                h.identity_arc(),
                h.rbac_arc(),
                Arc::clone(&audit),
                onboarding,
                CookieSecret::from_bytes([6u8; 32]),
                Some(Arc::clone(&email)),
            )
            .with_abuse_guards(Arc::clone(&guards))
            .with_dev_mode(true),
        );
        let api = hearth::protocol::http::router(Arc::new(
            hearth::protocol::http::AppState::new(h.identity_arc(), h.rbac_arc(), audit)
                .with_abuse_guards(guards)
                .with_email(Some(email)),
        ));
        Self {
            realm: realm.id().clone(),
            realm_name: realm.name().to_string(),
            h,
            web,
            api,
            webhook_feed,
            sent,
        }
    }

    /// An active user with a password. Returns the ID and the address.
    fn user(&self) -> (UserId, String) {
        let email = format!("u-{}@capped.test", uuid::Uuid::new_v4().simple());
        let user = self
            .h
            .identity()
            .create_user(
                &self.realm,
                &CreateUserRequest {
                    email: email.clone(),
                    display_name: "Capped".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user");
        self.h
            .identity()
            .set_password(
                &self.realm,
                user.id(),
                &CleartextPassword::from_string("capped-correct-horse-staple".to_string()),
            )
            .expect("set password");
        self.h
            .identity()
            .update_user(
                &self.realm,
                user.id(),
                &UpdateUserRequest {
                    status: Some(UserStatus::Active),
                    ..Default::default()
                },
            )
            .expect("activate user");
        (user.id().clone(), email)
    }

    /// A bearer token for a user who holds `realm.admin`.
    fn admin_token(&self) -> String {
        let (admin, _) = self.user();
        let role = self
            .h
            .rbac()
            .get_role_by_name(&self.realm, "realm.admin")
            .expect("lookup")
            .expect("seeded role")
            .id;
        self.h
            .rbac()
            .assign_role(
                &self.realm,
                &AssignRoleRequest {
                    subject: Subject::User(admin.clone()),
                    role_id: role,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign role");
        let session = self
            .h
            .identity()
            .create_session(&self.realm, &admin, &SessionContext::default())
            .expect("session");
        self.h
            .identity()
            .issue_tokens(&self.realm, &admin, session.id())
            .expect("tokens")
            .access_token()
            .to_string()
    }

    /// `POST /ui/realms/<realm>/forgot-password`.
    async fn forgot_password(&self, email: &str) -> StatusCode {
        let body = format!(
            "email={}",
            form_urlencoded::byte_serialize(email.as_bytes()).collect::<String>()
        );
        let response = self
            .web
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/ui/realms/{}/forgot-password", self.realm_name))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .expect("build POST"),
            )
            .await
            .expect("oneshot");
        response.status()
    }

    /// `POST /admin/users/{id}/password-email`.
    async fn admin_password_email(&self, token: &str, user: &UserId) -> StatusCode {
        let response = self
            .api
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/users/{}/password-email", user.as_uuid()))
                    .header("x-realm-id", self.realm.as_uuid().to_string())
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("build POST"),
            )
            .await
            .expect("oneshot");
        let status = response.status();
        let _ = to_bytes(response.into_body(), 1 << 20).await;
        status
    }

    /// The next `AbuseDetected` event the webhook dispatcher receives. The
    /// capped send runs off the request path, so it lands after the response.
    async fn next_abuse_event(&mut self) -> AuditEvent {
        let wait = async {
            loop {
                match self.webhook_feed.recv().await {
                    Ok(event) if event.action == AuditAction::AbuseDetected => return event,
                    Ok(_) => {}
                    Err(e) => panic!("webhook feed closed: {e}"),
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), wait)
            .await
            .expect("no AbuseDetected event reached the webhook dispatcher")
    }

    fn abuse_events(&self) -> Vec<AuditEvent> {
        let mut query = AuditQuery::for_realm(self.realm.clone());
        query.action = Some(AuditAction::AbuseDetected);
        self.h.audit().query(&query).expect("query audit log")
    }

    /// Waits until the transport has received `n` messages.
    async fn await_sent(&self, n: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while self.sent.load(Ordering::SeqCst) < n && std::time::Instant::now() < deadline {
            tokio::task::yield_now().await;
        }
    }
}

fn meta<'a>(event: &'a AuditEvent, key: &str) -> Option<&'a serde_json::Value> {
    event.metadata.as_ref()?.get(key)
}

#[tokio::test]
async fn a_reset_email_over_the_realm_hard_cap_is_audited_and_not_sent() {
    let mut rig = Rig::new(A4_HARD).await;
    let (_, email) = rig.user();

    assert!(rig.forgot_password(&email).await.is_redirection());

    let event = rig.next_abuse_event().await;
    assert_eq!(event.realm_id, rig.realm);
    assert_eq!(
        meta(&event, "guard").and_then(serde_json::Value::as_str),
        Some("a4_email_hard_cap")
    );
    assert_eq!(
        meta(&event, "flow").and_then(serde_json::Value::as_str),
        Some("password_reset")
    );
    assert_eq!(
        meta(&event, "sent").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        rig.sent.load(Ordering::SeqCst),
        0,
        "a capped send is abandoned"
    );
}

#[tokio::test]
async fn a_reset_email_over_the_realm_soft_cap_is_audited_and_sent() {
    let mut rig = Rig::new(A4_SOFT).await;
    let (_, email) = rig.user();

    assert!(rig.forgot_password(&email).await.is_redirection());

    let event = rig.next_abuse_event().await;
    assert_eq!(
        meta(&event, "guard").and_then(serde_json::Value::as_str),
        Some("a4_email_soft_cap")
    );
    assert_eq!(
        meta(&event, "sent").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    rig.await_sent(1).await;
    assert_eq!(rig.sent.load(Ordering::SeqCst), 1, "a soft cap still sends");
}

/// Two refused sends in one window write one event, and the event names
/// neither the recipient nor how many realms targeted it (A-50).
#[tokio::test]
async fn admin_password_emails_over_the_cross_realm_cap_are_audited_once() {
    let rig = Rig::new(A50_HARD).await;
    let token = rig.admin_token();
    let (user, email) = rig.user();

    for _ in 0..2 {
        assert_eq!(
            rig.admin_password_email(&token, &user).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    let events = rig.abuse_events();
    assert_eq!(events.len(), 1, "one event per guard and realm per window");
    let event = &events[0];
    assert_eq!(
        meta(event, "guard").and_then(serde_json::Value::as_str),
        Some("a50_email_hard_cap")
    );
    assert_eq!(
        meta(event, "flow").and_then(serde_json::Value::as_str),
        Some("password_email")
    );
    let metadata = event.metadata.as_ref().expect("metadata").to_string();
    assert!(!metadata.contains(&email), "the recipient is not recorded");
    assert!(
        meta(event, "realm_count").is_none(),
        "the realm count stays private"
    );
    assert_eq!(rig.sent.load(Ordering::SeqCst), 0);
}

/// Every capped send goes through the one check that audits it, so a new
/// email flow cannot skip the audit event.
#[test]
fn every_outbound_email_check_is_the_audited_one() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let allowed = root.join("src/protocol/outbound_email.rs");
    let mut stack = vec![root.join("src/protocol")];
    let mut offenders = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") && path != allowed {
                let text = std::fs::read_to_string(&path).expect("read source");
                if text.contains(".check_outbound_email(") {
                    offenders.push(
                        path.strip_prefix(root)
                            .expect("in root")
                            .display()
                            .to_string(),
                    );
                }
            }
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "call `outbound_email::admit` instead of `AbuseGuards::check_outbound_email`: {offenders:?}"
    );
}
