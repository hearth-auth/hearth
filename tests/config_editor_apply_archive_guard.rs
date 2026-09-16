//! `POST /ui/admin/settings/editor/visual/apply` must not answer `{"ok":true}`
//! for a document whose reconcile silently archives live realms
//! (production-readiness task 21.5, audit §4.23#4).
//!
//! The visual editor is a raw JSON→YAML passthrough over the whole config
//! document. `reconcile_declared_realms` archives every storage realm whose
//! name is absent from `realms:`. So a browser tab that never loaded the
//! `realms:` section — or one opened before a realm was created — wipes every
//! realm the operator did not re-list. The handler returned `ok:true` the
//! moment the file hit disk, because the archiving happens afterwards in the
//! hot-reload with no channel back to the caller.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{RealmId, SessionId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope, Subject};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [88u8; 32];
const CSRF: &str = "config-editor-csrf-token";

struct Rig {
    app: axum::Router,
    admin_session_id: SessionId,
    system_realm_id: RealmId,
    config_path: std::path::PathBuf,
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

#[allow(clippy::too_many_lines)] // mirrors the shared admin-UI rig
fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let config_path = data_dir.join("hearth.yaml");
    std::fs::write(&config_path, "# original\nserver:\n  port: 8420\n").expect("seed config");

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn hearth::core::Clock>;
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
        .expect("identity"),
    ) as Arc<dyn IdentityEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    let system_realm_id = RealmId::new(uuid::Uuid::nil());
    rbac.seed_realm(&system_realm_id).expect("seed system");

    let admin_user = identity
        .create_admin_user(&CreateUserRequest {
            email: "cfg-admin@test.example".to_string(),
            display_name: "CfgAdmin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create admin");
    identity
        .set_password(
            &system_realm_id,
            admin_user.id(),
            &CleartextPassword::from_string("s3cr3t1!-p@ss".to_string()),
        )
        .expect("password");
    identity
        .update_user(
            &system_realm_id,
            admin_user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate");
    let admin_role = rbac
        .get_role_by_name(&system_realm_id, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    rbac.assign_role(
        &system_realm_id,
        &AssignRoleRequest {
            subject: Subject::User(admin_user.id().clone()),
            role_id: admin_role.id,
            scope: Scope::Realm,
            assigned_by: None,
        },
    )
    .expect("assign");
    let admin_session = identity
        .create_session(
            &system_realm_id,
            admin_user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("session");

    // Two live realms the operator's editor tab does not know about.
    for name in ["alpha", "bravo"] {
        identity
            .create_realm(&CreateRealmRequest {
                name: name.to_string(),
                config: None,
            })
            .expect("realm");
    }

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        Arc::clone(&audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        None,
    )
    .with_dev_mode(true)
    .with_config_path(config_path.clone());

    Rig {
        app: web::router(state),
        admin_session_id: admin_session.id().clone(),
        system_realm_id,
        config_path,
    }
}

fn admin_cookie(rig: &Rig) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("key");
    mac.update(rig.admin_session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.system_realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={CSRF}",
        rig.admin_session_id.as_uuid(),
        rig.system_realm_id.as_uuid(),
        tag,
    )
}

/// A config document that passes the *full* production validation pipeline, so
/// the apply reaches the archive gate rather than stopping at `validate_all()`.
///
/// The editor refuses `dev_mode`, so every submitted document is validated as a
/// production one: it needs a KEK, a TLS story (here, a trusted proxy that
/// attests HTTPS) and an issuer. Mirrors the in-repo fixture in
/// `src/config/validate.rs`'s own tests.
fn document(realms_json: Option<&str>) -> String {
    let realms = match realms_json {
        Some(r) => format!(r#","realms":{r}"#),
        None => String::new(),
    };
    format!(
        // A real email transport is required: the realms below enable password
        // authentication, and task 19.21 refuses `transport: log` for such a
        // realm in production because every reset mail would be discarded.
        r#"{{"oidc":{{"issuer":"https://auth.example.com"}},"server":{{"trust_forwarded_proto":true,"trusted_proxies":["127.0.0.1"]}},"email":{{"transport":"smtp","from":"noreply@example.com","smtp":{{"host":"smtp.example.com","port":587}}}},"security":{{"key_encryption_key":"1111111111111111111111111111111111111111111111111111111111111111"}}{realms}}}"#
    )
}

async fn apply(rig: &Rig, query: &str, body: &str) -> (StatusCode, serde_json::Value) {
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/settings/editor/visual/apply{query}"))
                .header(header::COOKIE, admin_cookie(rig))
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-csrf-token", CSRF)
                .body(Body::from(body.to_string()))
                .expect("test invariant"),
        )
        .await
        .expect("test invariant");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("test invariant");
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// The defect: a document listing only `alpha` archives `bravo` on reload, but
/// the endpoint answered `{"ok":true}` and wrote the file anyway.
#[tokio::test]
async fn apply_that_would_archive_a_live_realm_is_refused() {
    let rig = build_rig();
    let before = std::fs::read_to_string(&rig.config_path).expect("read config");

    let (status, body) = apply(&rig, "", &document(Some(r#"{"alpha":{}}"#))).await;

    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "partial realms document was accepted: {body}"
    );
    assert_eq!(
        body.get("ok").and_then(serde_json::Value::as_bool),
        Some(false),
        "response claimed success for a destructive apply: {body}"
    );
    let doomed = body
        .get("would_archive")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        doomed
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>(),
        vec!["bravo"],
        "the refusal must name exactly the realms at risk: {body}"
    );

    let after = std::fs::read_to_string(&rig.config_path).expect("read config");
    assert_eq!(
        before, after,
        "hearth.yaml was rewritten despite the refusal"
    );
}

/// A document that drops every realm is the worst case and must be refused too.
#[tokio::test]
async fn apply_that_would_archive_every_realm_is_refused() {
    let rig = build_rig();
    let (status, body) = apply(&rig, "", &document(Some("{}"))).await;
    assert_eq!(status, StatusCode::CONFLICT, "got: {body}");
    let doomed: Vec<&str> = body
        .get("would_archive")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
        .unwrap_or_default();
    assert_eq!(doomed, vec!["alpha", "bravo"], "got: {body}");
}

/// An explicit acknowledgement lets the operator through — and the success
/// body still names what is about to be archived, instead of a bare `ok:true`.
#[tokio::test]
async fn confirmed_apply_succeeds_and_reports_what_it_archives() {
    let rig = build_rig();
    let (status, body) = apply(
        &rig,
        "?confirm_archive=true",
        &document(Some(r#"{"alpha":{}}"#)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert_eq!(
        body.get("ok").and_then(serde_json::Value::as_bool),
        Some(true),
        "got: {body}"
    );
    let doomed: Vec<&str> = body
        .get("archived_realms")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
        .unwrap_or_default();
    assert_eq!(
        doomed,
        vec!["bravo"],
        "a confirmed destructive apply must still report the casualties: {body}"
    );
    let after = std::fs::read_to_string(&rig.config_path).expect("read config");
    assert!(
        after.contains("alpha"),
        "confirmed apply did not write the document: {after}"
    );
}

/// A document that omits `realms:` entirely archives nothing — `reconcile_realms`
/// skips realm reconciliation when the key is absent — so it must NOT be gated.
#[tokio::test]
async fn apply_without_a_realms_section_is_not_gated() {
    let rig = build_rig();
    let (status, body) = apply(&rig, "", &document(None)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a document with no realms: section must not be treated as destructive: {body}"
    );
    assert_eq!(
        body.get("ok").and_then(serde_json::Value::as_bool),
        Some(true),
        "got: {body}"
    );
}

/// A document that re-lists every live realm archives nothing and applies clean.
#[tokio::test]
async fn apply_listing_every_realm_is_not_gated() {
    let rig = build_rig();
    let (status, body) = apply(&rig, "", &document(Some(r#"{"alpha":{},"bravo":{}}"#))).await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert_eq!(
        body.get("ok").and_then(serde_json::Value::as_bool),
        Some(true),
        "got: {body}"
    );
}
