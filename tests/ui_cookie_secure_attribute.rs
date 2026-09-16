//! `hearth_ui_flash` must carry `Secure` when the request arrived over TLS
//! (production-readiness task 21.6, audit §4.23#5).
//!
//! The session, CSRF, MFA-pending and required-action cookies already took a
//! `secure: bool` and appended `; Secure`. Two did not: `hearth_ui_flash`
//! (`templates.rs`) and `hearth_ui_sms_mfa` (`sms_challenge.rs`) hard-coded
//! their attribute list with no `Secure` on *any* path — neither when set nor
//! when cleared. A cookie without `Secure` is sent over plaintext, so a
//! downgrade or a mixed-content sub-resource leaks it.
//!
//! Both producers of each cookie (set + clear) are covered by in-crate unit
//! tests next to the code (`templates.rs`, `sms_challenge.rs`); those two pairs
//! are the *only* places either cookie is written. This file proves the wiring
//! end-to-end: a TLS-served `/ui` response that really sets `hearth_ui_flash`
//! carries `Secure` on the wire.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request};
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

const COOKIE_SECRET: [u8; 32] = [63u8; 32];
const CSRF: &str = "secure-cookie-csrf-token";

struct Rig {
    app: axum::Router,
    admin_session_id: SessionId,
    system_realm_id: RealmId,
    tenant_realm_name: String,
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

/// Boots the `/ui` router with `tls_enabled`, which is what makes
/// `WebState::is_secure_request` true for every request.
#[allow(clippy::too_many_lines)] // mirrors the shared admin-UI rig
fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

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
            email: "secure-cookie-admin@test.example".to_string(),
            display_name: "SecureCookieAdmin".to_string(),
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

    identity
        .create_realm(&CreateRealmRequest {
            name: "securecookie".to_string(),
            config: None,
        })
        .expect("realm");

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
    .with_tls_enabled(true);

    Rig {
        app: web::router(state),
        admin_session_id: admin_session.id().clone(),
        system_realm_id,
        tenant_realm_name: "securecookie".to_string(),
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

/// A TLS-served `/ui` response that sets `hearth_ui_flash` must carry `Secure`.
///
/// `POST .../groups/{gid}/roles/assign` with an unparseable `role_id` takes the
/// shortest branch to `redirect_with_flash` and needs no pre-existing group.
#[tokio::test]
async fn flash_cookie_on_the_wire_carries_secure() {
    let rig = build_rig();
    let realm = &rig.tenant_realm_name;
    let gid = uuid::Uuid::new_v4();
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/ui/admin/realms/{realm}/groups/{gid}/roles/assign"
                ))
                .header(header::COOKIE, admin_cookie(&rig))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "_csrf={CSRF}&role_id=not-a-uuid&scope=realm"
                )))
                .expect("test invariant"),
        )
        .await
        .expect("test invariant");

    let lines: Vec<String> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(ToString::to_string))
        .collect();
    let flash: Vec<&String> = lines
        .iter()
        .filter(|l| l.starts_with("hearth_ui_flash="))
        .collect();
    assert!(
        !flash.is_empty(),
        "no hearth_ui_flash Set-Cookie on the response (status {}): {lines:?}",
        resp.status()
    );
    for line in flash {
        assert!(
            line.split(';')
                .any(|a| a.trim().eq_ignore_ascii_case("Secure")),
            "hearth_ui_flash Set-Cookie is missing Secure over TLS: {line}"
        );
    }
}
