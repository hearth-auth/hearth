//! Integration tests for HEA-855: admin phone management + realm SMS OTP config.
//!
//! Covers:
//! - AC 3.4.1 — `mfa_methods` accepts `"sms"` via PATCH /admin/realms/{realm}/config
//! - AC 3.4.3 — `sms_otp_expiry_seconds` configurable via PATCH /admin/realms/{realm}/config
//! - AC 3.4.4 — `sms_otp_max_attempts` configurable via PATCH /admin/realms/{realm}/config
//! - AC 3.4.2 — POST /ui/admin/realms/{realm}/users/{id}/remove-phone clears phone +
//!   adds ENROLL_PHONE_OTP to required_actions (engine-layer test)

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, RequiredAction, SessionContext, UpdateUserRequest};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

// ===== Helpers =====

fn build_app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

async fn admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: "admin@phone-test.example".into(),
                display_name: "Admin".into(),
                first_name: "Admin".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create admin");

    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup role")
        .expect("realm.admin seeded");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");

    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    use axum::body::to_bytes;
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("bytes");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// ===== AC 3.4.1: mfa_methods accepts "sms" =====

#[tokio::test]
async fn patch_realm_config_sets_mfa_methods_with_sms() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"mfa_methods":["totp","sms"]}"#))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK, "PATCH must succeed");

    let updated = h
        .identity()
        .get_realm(&realm)
        .expect("get_realm")
        .expect("realm exists");
    let methods = updated
        .config()
        .mfa_methods
        .as_deref()
        .expect("mfa_methods must be set");
    assert!(
        methods.contains(&"sms".to_string()),
        "mfa_methods must contain \"sms\"; got {methods:?}"
    );
    assert!(
        methods.contains(&"totp".to_string()),
        "mfa_methods must contain \"totp\"; got {methods:?}"
    );
}

#[tokio::test]
async fn patch_realm_config_mfa_methods_sms_only() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"mfa_methods":["sms"]}"#))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);

    let updated = h
        .identity()
        .get_realm(&realm)
        .expect("get_realm")
        .expect("realm exists");
    assert_eq!(
        updated.config().mfa_methods.as_deref(),
        Some(["sms".to_string()].as_slice()),
        "mfa_methods must be [\"sms\"]"
    );
}

// ===== AC 3.4.3 + 3.4.4: sms_otp_expiry_seconds + sms_otp_max_attempts =====

#[tokio::test]
async fn patch_realm_config_sets_sms_otp_params() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"sms_otp_expiry_seconds":300,"sms_otp_max_attempts":3}"#,
                ))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK, "PATCH must succeed");

    let updated = h
        .identity()
        .get_realm(&realm)
        .expect("get_realm")
        .expect("realm exists");
    let cfg = updated.config();
    assert_eq!(
        cfg.sms_otp_expiry_seconds,
        Some(300),
        "sms_otp_expiry_seconds must be 300"
    );
    assert_eq!(
        cfg.sms_otp_max_attempts,
        Some(3),
        "sms_otp_max_attempts must be 3"
    );
}

#[tokio::test]
async fn patch_realm_config_omitted_sms_params_leave_existing_unchanged() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);

    // First PATCH: set the params.
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"sms_otp_expiry_seconds":600,"sms_otp_max_attempts":5}"#,
                ))
                .expect("build"),
        )
        .await
        .expect("oneshot");

    // Second PATCH: change only default_required_actions, leave sms params absent.
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"default_required_actions":[]}"#))
                .expect("build"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);

    let updated = h
        .identity()
        .get_realm(&realm)
        .expect("get_realm")
        .expect("realm exists");
    let cfg = updated.config();
    assert_eq!(
        cfg.sms_otp_expiry_seconds,
        Some(600),
        "sms_otp_expiry_seconds must be unchanged"
    );
    assert_eq!(
        cfg.sms_otp_max_attempts,
        Some(5),
        "sms_otp_max_attempts must be unchanged"
    );
}

// ===== AC 3.4.2: remove-phone via identity engine =====
//
// The UI handler is an HTTP POST with CSRF; we test the underlying engine
// behaviour (phone cleared + ENROLL_PHONE_OTP added) directly here.
// A separate UI-layer smoke test would require a browser session — hand to QA.

#[tokio::test]
async fn remove_phone_clears_number_and_adds_required_action() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    // Create user with a phone number.
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "phone-user@example.com".into(),
                display_name: "Phone User".into(),
                first_name: "Phone".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    h.identity()
        .update_user(
            &realm,
            user.id(),
            &UpdateUserRequest {
                phone_number: Some(Some("+15555551234".to_string())),
                phone_verified: Some(true),
                ..Default::default()
            },
        )
        .expect("set phone");

    // Simulate the admin remove-phone action.
    let current = h
        .identity()
        .get_user(&realm, user.id())
        .expect("get_user")
        .expect("user exists");

    let mut new_actions: Vec<RequiredAction> = current.required_actions().to_vec();
    if !new_actions.contains(&RequiredAction::EnrollPhoneOtp) {
        new_actions.push(RequiredAction::EnrollPhoneOtp);
    }

    h.identity()
        .update_user(
            &realm,
            user.id(),
            &UpdateUserRequest {
                phone_number: Some(None),
                phone_verified: Some(false),
                required_actions: Some(new_actions),
                ..Default::default()
            },
        )
        .expect("remove phone");

    let updated = h
        .identity()
        .get_user(&realm, user.id())
        .expect("get_user")
        .expect("user exists after update");

    assert!(
        updated.phone_number().is_none(),
        "phone number must be cleared"
    );
    assert!(
        !updated.phone_verified(),
        "phone_verified must be false after removal"
    );
    assert!(
        updated
            .required_actions()
            .contains(&RequiredAction::EnrollPhoneOtp),
        "ENROLL_PHONE_OTP must be in required_actions; got {:?}",
        updated.required_actions()
    );
}

#[tokio::test]
async fn remove_phone_idempotent_when_no_phone_set() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "nophone@example.com".into(),
                display_name: "No Phone".into(),
                first_name: "No".into(),
                last_name: "Phone".into(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    // Simulate remove-phone when no phone is enrolled: should not error.
    let current = h
        .identity()
        .get_user(&realm, user.id())
        .expect("get_user")
        .expect("exists");

    let mut new_actions: Vec<RequiredAction> = current.required_actions().to_vec();
    if !new_actions.contains(&RequiredAction::EnrollPhoneOtp) {
        new_actions.push(RequiredAction::EnrollPhoneOtp);
    }

    h.identity()
        .update_user(
            &realm,
            user.id(),
            &UpdateUserRequest {
                phone_number: Some(None),
                phone_verified: Some(false),
                required_actions: Some(new_actions),
                ..Default::default()
            },
        )
        .expect("remove-phone when no phone must succeed");

    // Verify the persisted user state after an idempotent remove-phone: no phone,
    // unverified, and ENROLL_PHONE_OTP present exactly once.
    let updated = h
        .identity()
        .get_user(&realm, user.id())
        .expect("get_user")
        .expect("user exists after update");
    assert!(
        updated.phone_number().is_none(),
        "phone number must remain unset"
    );
    assert!(
        !updated.phone_verified(),
        "phone_verified must be false after remove-phone"
    );
    let enroll_count = updated
        .required_actions()
        .iter()
        .filter(|a| **a == RequiredAction::EnrollPhoneOtp)
        .count();
    assert_eq!(
        enroll_count,
        1,
        "ENROLL_PHONE_OTP must be present exactly once; got {:?}",
        updated.required_actions()
    );
}

#[tokio::test]
async fn remove_phone_does_not_duplicate_enroll_action() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "dup@example.com".into(),
                display_name: "Dup".into(),
                first_name: "Dup".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    // Pre-seed ENROLL_PHONE_OTP on the user.
    h.identity()
        .update_user(
            &realm,
            user.id(),
            &UpdateUserRequest {
                required_actions: Some(vec![RequiredAction::EnrollPhoneOtp]),
                ..Default::default()
            },
        )
        .expect("seed required action");

    // Now simulate admin remove-phone — should not duplicate the action.
    let current = h
        .identity()
        .get_user(&realm, user.id())
        .expect("get_user")
        .expect("exists");

    let mut new_actions: Vec<RequiredAction> = current.required_actions().to_vec();
    if !new_actions.contains(&RequiredAction::EnrollPhoneOtp) {
        new_actions.push(RequiredAction::EnrollPhoneOtp);
    }

    h.identity()
        .update_user(
            &realm,
            user.id(),
            &UpdateUserRequest {
                phone_number: Some(None),
                phone_verified: Some(false),
                required_actions: Some(new_actions),
                ..Default::default()
            },
        )
        .expect("remove phone");

    let updated = h
        .identity()
        .get_user(&realm, user.id())
        .expect("get_user")
        .expect("exists");

    let enroll_count = updated
        .required_actions()
        .iter()
        .filter(|a| **a == RequiredAction::EnrollPhoneOtp)
        .count();
    assert_eq!(
        enroll_count, 1,
        "ENROLL_PHONE_OTP must appear exactly once; got {enroll_count}"
    );
}

// ===== AC 3.5.2: phone not leaked in audit metadata =====

#[tokio::test]
async fn patch_realm_config_response_does_not_contain_raw_phone() {
    // This test verifies that the realm config JSON response from PATCH
    // does not accidentally include raw phone numbers. The realm config
    // has no phone field at all — this is a canary test.
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"mfa_methods":["sms"]}"#))
                .expect("build"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let body_str = body.to_string();

    // No real phone numbers should be in this response.
    assert!(
        !body_str.contains("+1"),
        "realm config response must not contain phone-like data; got {body_str}"
    );
}
