#![allow(clippy::unwrap_used)]
//! `POST /admin/users/{id}/password-email` (OpenSpec change
//! `admin-password-email`).
//!
//! An application that provisions users had no API to let a new user choose
//! a password: the console's reset email needs an operator, and its link
//! lives 30 minutes. The admin API now sends a user with no password the
//! `welcome` email with a set-password link, and a user with a password the
//! reset email.

mod common;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::{RealmId, UserId};
use hearth::identity::email::{EmailBranding, EmailError, EmailMessage, EmailSender, EmailService};
use hearth::identity::{CleartextPassword, CreateRealmRequest, CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

const BASE_URL: &str = "https://id.example.com";

/// Records every message handed to the transport.
struct Recorder(Arc<Mutex<Vec<EmailMessage>>>);

impl EmailSender for Recorder {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        self.0.lock().unwrap().push(message.clone());
        Ok(())
    }
}

struct Rig {
    h: common::TestHarness,
    realm: RealmId,
    inbox: Arc<Mutex<Vec<EmailMessage>>>,
}

impl Rig {
    async fn new() -> Self {
        let h = common::TestHarness::in_process().await.expect("harness");
        let realm = h
            .identity()
            .create_realm(&CreateRealmRequest {
                name: format!("pwmail-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
                config: None,
            })
            .expect("create realm")
            .id()
            .clone();
        h.rbac().seed_realm(&realm).expect("seed realm");
        Self {
            h,
            realm,
            inbox: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn app(&self, with_email: bool) -> axum::Router {
        let email = with_email.then(|| {
            Arc::new(
                EmailService::new(
                    Arc::new(Recorder(Arc::clone(&self.inbox))),
                    "Hearth".to_string(),
                    None,
                    EmailBranding::default(),
                    String::new(),
                    None,
                )
                .expect("email service"),
            )
        });
        router(Arc::new(
            AppState::new(self.h.identity_arc(), self.h.rbac_arc(), self.h.audit_arc())
                .with_email(email)
                .with_public_base_url(BASE_URL),
        ))
    }

    fn user(&self, label: &str) -> UserId {
        self.h
            .identity()
            .create_user(
                &self.realm,
                &CreateUserRequest {
                    email: format!("{label}-{}@pwmail.example", uuid::Uuid::new_v4()),
                    display_name: label.to_string(),
                    ..CreateUserRequest::default()
                },
            )
            .expect("create user")
            .id()
            .clone()
    }

    fn user_with_role(&self, label: &str, role: &str) -> UserId {
        let user = self.user(label);
        let role = self
            .h
            .rbac()
            .get_role_by_name(&self.realm, role)
            .expect("lookup role")
            .unwrap_or_else(|| panic!("seeded role {role} missing"));
        self.h
            .rbac()
            .assign_role(
                &self.realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: role.id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign role");
        user
    }

    fn token_for(&self, user: &UserId) -> String {
        let session = self
            .h
            .identity()
            .create_session(&self.realm, user, &SessionContext::default())
            .expect("session");
        self.h
            .identity()
            .issue_tokens(&self.realm, user, session.id())
            .expect("issue")
            .access_token()
            .to_string()
    }

    fn admin_token(&self) -> String {
        let admin = self.user_with_role("admin", "realm.admin");
        self.token_for(&admin)
    }

    async fn send(
        &self,
        app: &axum::Router,
        token: &str,
        user: &UserId,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri(format!("/admin/users/{}/password-email", user.as_uuid()))
            .header("authorization", format!("Bearer {token}"))
            .header("x-realm-id", self.realm.as_uuid().to_string())
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn sent(&self) -> Vec<EmailMessage> {
        self.inbox.lock().unwrap().clone()
    }

    fn email_of(&self, user: &UserId) -> String {
        self.h
            .identity()
            .get_user(&self.realm, user)
            .expect("lookup")
            .expect("user")
            .email()
            .to_string()
    }
}

/// The link token in a sent message's text body.
fn link_token(message: &EmailMessage) -> String {
    let body = &message.text_body;
    let start = body
        .find("reset-password?token=")
        .unwrap_or_else(|| panic!("no reset-password link in: {body}"))
        + "reset-password?token=".len();
    body[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

#[tokio::test]
async fn a_user_without_a_password_gets_the_welcome_email() {
    let rig = Rig::new().await;
    let app = rig.app(true);
    let token = rig.admin_token();
    let user = rig.user("newcomer");

    let (status, body) = rig.send(&app, &token, &user).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["kind"], "PASSWORD_EMAIL_KIND_SETUP", "{body}");

    let sent = rig.sent();
    assert_eq!(sent.len(), 1, "one email");
    let mail = &sent[0];
    assert_eq!(mail.to, rig.email_of(&user));
    assert!(
        mail.subject.to_lowercase().contains("welcome"),
        "a welcome subject, got {:?}",
        mail.subject
    );
    assert!(
        mail.text_body.contains(BASE_URL),
        "the link uses the public base URL: {}",
        mail.text_body
    );

    // The link sets the user's first password.
    let link = link_token(mail);
    rig.h
        .identity()
        .reset_password_with_token(
            &rig.realm,
            &link,
            &CleartextPassword::from_string("FirstPassword1!".to_string()),
        )
        .expect("the welcome link sets a password");
    assert!(rig
        .h
        .identity()
        .verify_password(
            &rig.realm,
            &user,
            &CleartextPassword::from_string("FirstPassword1!".to_string())
        )
        .expect("verify"));
}

#[tokio::test]
async fn a_user_with_a_password_gets_the_reset_email() {
    let rig = Rig::new().await;
    let app = rig.app(true);
    let token = rig.admin_token();
    let user = rig.user("member");
    rig.h
        .identity()
        .set_password(
            &rig.realm,
            &user,
            &CleartextPassword::from_string("ValidPassword1!".to_string()),
        )
        .expect("set password");

    let (status, body) = rig.send(&app, &token, &user).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["kind"], "PASSWORD_EMAIL_KIND_RESET", "{body}");
    let sent = rig.sent();
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0].subject.to_lowercase().contains("reset"),
        "{:?}",
        sent[0].subject
    );
}

#[tokio::test]
async fn refusals() {
    let rig = Rig::new().await;
    let app = rig.app(true);
    let token = rig.admin_token();

    // An unknown user.
    let (status, body) = rig.send(&app, &token, &UserId::generate()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // The sub-admin ceiling: a user admin cannot email a realm admin.
    let sub_admin = rig.user_with_role("sub-admin", "hearth.users.admin");
    let senior = rig.user_with_role("senior", "realm.admin");
    let (status, body) = rig.send(&app, &rig.token_for(&sub_admin), &senior).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // The fourth request for one address within the window.
    let user = rig.user("limited");
    for _ in 0..3 {
        let (status, body) = rig.send(&app, &token, &user).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, body) = rig.send(&app, &token, &user).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");

    assert_eq!(
        rig.sent().len(),
        3,
        "no email for a refused request: {:?}",
        rig.sent().iter().map(|m| &m.to).collect::<Vec<_>>()
    );

    // No email transport.
    let (status, body) = rig.send(&rig.app(false), &token, &rig.user("unsent")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
}
