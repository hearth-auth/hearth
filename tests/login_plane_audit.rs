//! §4.14#7 (audit 2026-08-28), task 19.2: the login plane must audit the two
//! failures it silently swallowed.
//!
//! 1. **A failed login for an unknown address.** `LoginFailed` is emitted by
//!    `verify_password`, which the browser login handler never reaches when
//!    `get_user_by_email` returns `None`. A credential-stuffing run against a
//!    realm's whole address space therefore ticked an in-memory per-IP counter
//!    and left the audit trail — the one log an operator reads — completely
//!    empty.
//!
//! 2. **A failed second-factor verification.** Covered by unit tests next to
//!    the engine; this file pins the browser-facing half.
//!
//! The audit log is a keyed-HMAC chain, so both tests also assert the chain
//! still verifies after the new write: an event appended on a conditional path
//! must not skip or reorder a chain link.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::audit::{AuditAction, AuditEngine, AuditQuery, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, RealmConfig,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [9u8; 32];

struct Rig {
    app: axum::Router,
    audit: Arc<dyn AuditEngine>,
    realm_id: RealmId,
}

fn null_email_service() -> Arc<EmailService> {
    Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    )
}

fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
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
            name: "solo".to_string(),
            config: Some(RealmConfig::default()),
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    // A real account, so the "unknown address" case is distinguishable from
    // "this realm has no users at all".
    identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "real@example.com".to_string(),
                display_name: "Real".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        Arc::clone(&audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        None,
    )
    .with_dev_mode(true);

    Rig {
        app: web::router(state),
        audit,
        realm_id,
    }
}

async fn post_login(app: &axum::Router, body: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .expect("build POST request"),
        )
        .await
        .expect("send request")
        .status()
}

fn login_failures(rig: &Rig) -> Vec<serde_json::Value> {
    let mut query = AuditQuery::for_realm(rig.realm_id.clone());
    query.action = Some(AuditAction::LoginFailed);
    rig.audit
        .query(&query)
        .expect("query audit log")
        .into_iter()
        .map(|e| e.metadata.unwrap_or(serde_json::Value::Null))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_login_for_an_unknown_address_is_audited() {
    let rig = build_rig();
    assert!(
        login_failures(&rig).is_empty(),
        "the rig must start with an empty LoginFailed trail"
    );

    let status = post_login(&rig.app, "email=nobody@example.com&password=hunter2hunter2").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unknown address must still get the generic failure page"
    );

    let events = login_failures(&rig);
    assert_eq!(
        events.len(),
        1,
        "exactly one LoginFailed must be recorded, got: {events:?}"
    );
    assert_eq!(
        events[0].get("reason").and_then(serde_json::Value::as_str),
        Some("unknown_account"),
        "the event must say why the login failed, got: {:?}",
        events[0]
    );

    // The audit log is a keyed-HMAC chain; a write on a conditional path must
    // not skip or reorder a link.
    assert!(
        rig.audit
            .verify_integrity(&rig.realm_id, None, None)
            .expect("verify integrity"),
        "the HMAC chain must still verify after the new conditional write"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_audited_address_is_not_echoed_into_the_trail() {
    // The realm audit log is readable by realm admins. Echoing an arbitrary
    // attacker-supplied address into it would turn the log into a reflected
    // store of third-party email addresses, so the submitted address must not
    // appear anywhere in the event.
    let rig = build_rig();
    let victim = "victim-should-not-appear@example.com";
    post_login(&rig.app, &format!("email={victim}&password=hunter2hunter2")).await;

    let events = login_failures(&rig);
    assert_eq!(events.len(), 1, "got: {events:?}");
    let rendered = serde_json::to_string(&events[0]).expect("serialize metadata");
    assert!(
        !rendered.contains("victim-should-not-appear"),
        "the submitted address must not be stored in the audit metadata: {rendered}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_unknown_address_attempts_each_leave_a_record() {
    let rig = build_rig();
    for i in 0..3 {
        post_login(
            &rig.app,
            &format!("email=nobody{i}@example.com&password=hunter2hunter2"),
        )
        .await;
    }
    assert_eq!(
        login_failures(&rig).len(),
        3,
        "a stuffing run must be countable from the audit log alone"
    );
}
