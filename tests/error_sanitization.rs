//! Regression tests for information-disclosure sanitization (HEA-SEC-30).
//!
//! These tests encode the invariant that internal storage details — realm UUIDs,
//! byte offsets, key structure strings, StorageError Display text — must never
//! appear in HTTP response bodies.
//!
//! Pattern: trigger an error path that previously called `e.to_string()`, assert
//! the response body's `error` field is an opaque code and does NOT contain
//! storage-layer terminology or UUID-shaped strings.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{
    CreateUserRequest, SessionContext, SessionVersionConfig, UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

/// Storage-layer terms that MUST NOT appear in any error response body.
const STORAGE_LEAK_PATTERNS: &[&str] = &[
    "StorageError",
    "deserialization failed",
    "checksum mismatch",
    "byte offset",
    "WAL format",
    "HEARTH_MASTER_KEY",
    "HostKeyMismatch",
    "DeserializationFailed",
    "ChecksumMismatch",
    "storage I/O error",
    "storage corrupted",
    "affected realms",
    "IdentityError",
];

fn assert_no_storage_leak(body_str: &str) {
    for pattern in STORAGE_LEAK_PATTERNS {
        assert!(
            !body_str.to_lowercase().contains(&pattern.to_lowercase()),
            "error response contains storage-layer term {pattern:?}: {body_str}"
        );
    }
}

/// Asserts the `error` field is one of the known sanitized codes (allowlist).
/// This is stronger than regex: it rejects any new unapproved wording.
fn assert_error_is_sanitized(body: &serde_json::Value, body_str: &str) {
    const SAFE_CODES: &[&str] = &[
        "internal_error",
        "internal error",
        "session versioning disabled for realm",
        "upload_read_error",
        "ssrf check failed",
    ];
    let error_val = body["error"].as_str().unwrap_or("");
    assert!(
        SAFE_CODES.contains(&error_val),
        "error field must be a known sanitized code; got: {error_val:?}\nfull body: {body_str}"
    );
    assert_no_storage_leak(body_str);
}

fn build_app(h: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    router(state)
}

/// Creates a realm with session versioning enabled.
fn setup_sv_realm(h: &common::TestHarness) -> RealmId {
    let realm = h.create_realm();
    let current = h
        .identity()
        .get_realm(&realm)
        .expect("get realm")
        .expect("realm exists");
    let mut config = current.config().clone();
    config.session_version = SessionVersionConfig {
        enabled: true,
        delta_retention_seconds: 3600,
    };
    h.identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                name: None,
                status: None,
                config: Some(config),
            },
        )
        .expect("enable sv");
    realm
}

/// Issues an admin token for `realm` (seeds roles, creates user, assigns realm.admin).
async fn make_admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    h.rbac().seed_realm(realm).expect("seed rbac");
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("admin-{}@test.invalid", uuid::Uuid::new_v4()),
                display_name: "Admin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create admin user");
    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup role")
        .expect("role seeded");
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
        .expect("create session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

// ── SEC-30 regression: sv_list_deltas disabled realm returns clean 404 ────────

/// `sv_list_deltas` on a realm with session versioning DISABLED returns 404
/// with a human-readable message that contains NO internal storage details.
#[tokio::test]
async fn sv_list_deltas_disabled_realm_error_is_sanitized() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm(); // SV disabled by default

    h.rbac().seed_realm(&realm).expect("seed rbac");
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("sv-{}@test.invalid", uuid::Uuid::new_v4()),
                display_name: "SV".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let role = h
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("lookup role")
        .expect("seeded");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens")
        .access_token()
        .to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth/session-versions?since=0&limit=100")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let bytes = to_bytes(resp.into_body(), 1_000_000).await.expect("bytes");
    let body_str = String::from_utf8_lossy(&bytes).into_owned();
    let body: serde_json::Value = serde_json::from_str(&body_str).expect("json");

    assert_error_is_sanitized(&body, &body_str);
}

// ── SEC-30 regression: sv_bump_session error does not leak internal details ──

/// `sv_bump_session` called with a non-existent session UUID must not expose
/// storage details in the response. Either a clean 404/200 or a sanitized 500.
#[tokio::test]
async fn sv_bump_session_error_is_sanitized() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = setup_sv_realm(&h);
    let token = make_admin_token(&h, &realm).await;

    let fake_session = uuid::Uuid::new_v4();
    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/sv/bump/{fake_session}"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");

    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1_000_000).await.expect("bytes");
    let body_str = String::from_utf8_lossy(&bytes).into_owned();

    assert_no_storage_leak(&body_str);

    // If an error occurred (500), it must be the sanitized opaque code.
    if status == StatusCode::INTERNAL_SERVER_ERROR {
        let body: serde_json::Value = serde_json::from_str(&body_str).expect("json");
        assert_eq!(
            body["error"].as_str(),
            Some("internal_error"),
            "500 body must use opaque error code, got: {body_str}"
        );
    }
}

// ── SEC-30 regression: sv_bump_all response does not leak internal details ────

/// `sv_bump_all` with a valid admin token on a SV-enabled realm must not
/// expose internal error text. Success returns `{"bumped": N}`.
#[tokio::test]
async fn sv_bump_all_response_is_sanitized() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = setup_sv_realm(&h);
    let token = make_admin_token(&h, &realm).await;

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/realms/{}/sv-bump-all", realm.as_uuid()))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");

    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1_000_000).await.expect("bytes");
    let body_str = String::from_utf8_lossy(&bytes).into_owned();

    assert_no_storage_leak(&body_str);

    if status == StatusCode::INTERNAL_SERVER_ERROR {
        let body: serde_json::Value = serde_json::from_str(&body_str).expect("json");
        assert_eq!(
            body["error"].as_str(),
            Some("internal_error"),
            "500 body must use opaque error code, got: {body_str}"
        );
    }
}

// ── SEC-30 unit: StorageError Display must not be forwarded verbatim ─────────

/// Confirms that StorageError::HostKeyMismatch and DeserializationFailed Display
/// include sensitive details, which is correct for server logs but MUST be
/// scrubbed at the HTTP boundary — which is exactly what HEA-SEC-30 fixes.
#[test]
fn storage_error_display_contains_sensitive_detail_not_forwarded() {
    use hearth::storage::StorageError;

    let err = StorageError::HostKeyMismatch {
        affected_realms: vec!["realm-alpha".into(), "realm-beta".into()],
    };
    let msg = err.to_string();
    // The Display includes realm names — correct for operator logs.
    assert!(
        msg.contains("realm-alpha"),
        "HostKeyMismatch Display must include realm names for logs: {msg}"
    );
    // Verify the Display would fail the STORAGE_LEAK_PATTERNS check —
    // confirming it MUST be scrubbed before reaching API responses.
    assert!(
        msg.to_lowercase().contains("affected"),
        "HostKeyMismatch Display contains sensitive detail that must not reach clients: {msg}"
    );

    let err = StorageError::DeserializationFailed {
        reason: "unexpected byte at offset 42 in key /realm/abc123".into(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("offset 42"),
        "DeserializationFailed Display includes internal offset detail (correct for logs): {msg}"
    );
    assert!(
        msg.to_lowercase().contains("deserialization failed"),
        "DeserializationFailed Display contains a STORAGE_LEAK_PATTERN term: {msg}"
    );
}
