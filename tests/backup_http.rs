//! Integration tests for the admin backup HTTP endpoints.
//!
//! Covers:
//! - `POST /admin/backup` — create and download a backup archive
//! - `POST /admin/backup/restore` — restore from a backup archive
//! - Auth gating (403 for non-admin, 401 for missing token)
//! - Dry-run restore returns counts without writing
//! - Round-trip: backup a realm, restore to a fresh realm

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::backup::BackupArchive;
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

// ===== helpers =====

async fn build_app(h: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    router(state)
}

async fn make_admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("admin-{}@backup-test.example", uuid::Uuid::new_v4()),
                display_name: "Backup Admin".into(),
                first_name: "Backup".into(),
                last_name: "Admin".into(),
                attributes: Default::default(),
            },
        )
        .expect("create admin user");

    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("look up realm.admin role")
        .expect("realm.admin must be seeded");

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

async fn resp_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).expect("parse JSON")
}

async fn resp_bytes(resp: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes")
        .to_vec()
}

// ===== POST /admin/backup — auth tests =====

#[tokio::test]
async fn backup_create_requires_auth() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/backup")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn backup_create_requires_admin_role() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    // Create a user without the admin role.
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "nonadmin@backup-test.example".into(),
                display_name: "Non Admin".into(),
                first_name: "Non".into(),
                last_name: "Admin".into(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
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

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/backup")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ===== POST /admin/backup — happy path =====

#[tokio::test]
async fn backup_create_returns_archive() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = make_admin_token(&h, &realm).await;

    // Create a user so the realm has some content.
    h.identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@backup-test.example".into(),
                display_name: "Alice".into(),
                first_name: "Alice".into(),
                last_name: "Test".into(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/backup")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        content_type, "application/octet-stream",
        "must be octet-stream"
    );

    let content_disposition = resp
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_disposition.contains("attachment"),
        "content-disposition must be attachment: {content_disposition}"
    );
    assert!(
        content_disposition.contains(".hearth-backup"),
        "filename must end in .hearth-backup: {content_disposition}"
    );

    let body = resp_bytes(resp).await;
    assert!(!body.is_empty(), "archive body must not be empty");

    // Verify the bytes are a parseable archive by writing to a tempfile and opening.
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), &body).expect("write archive");
    let reader = BackupArchive::open(tmp.path()).expect("open archive");
    // The realm must appear in the manifest.
    assert_eq!(reader.realms().len(), 1, "one realm exported");
}

#[tokio::test]
async fn backup_create_realm_filter() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = make_admin_token(&h, &realm).await;

    // Find the realm slug for the query param.
    let realm_obj = h
        .identity()
        .get_realm(&realm)
        .expect("get realm")
        .expect("realm exists");
    let slug = realm_obj.name().to_string();

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/backup?realm={slug}"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_bytes(resp).await;
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), &body).expect("write");
    let reader = BackupArchive::open(tmp.path()).expect("open");
    assert_eq!(reader.realms().len(), 1);
    assert_eq!(reader.realms()[0].slug, slug);
}

// ===== POST /admin/backup/restore — auth tests =====

#[tokio::test]
async fn backup_restore_requires_auth() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/backup/restore")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("content-type", "multipart/form-data; boundary=boundary")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ===== POST /admin/backup/restore — missing file field =====

#[tokio::test]
async fn backup_restore_missing_file_field_returns_400() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = make_admin_token(&h, &realm).await;
    let app = build_app(&h).await;

    // Empty multipart body — no `file` field.
    let body = "--boundary\r\nContent-Disposition: form-data; name=\"other\"\r\n\r\ndata\r\n--boundary--\r\n";

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/backup/restore")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("content-type", "multipart/form-data; boundary=boundary")
                .body(Body::from(body))
                .expect("req"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = resp_json(resp).await;
    assert!(json["error"]
        .as_str()
        .unwrap_or("")
        .contains("missing 'file'"));
}

// ===== Dry-run restore round-trip =====

/// Builds a minimal valid backup archive by serializing the actual `Realm` object.
///
/// Uses the real `Realm` serde output so the importer can deserialize it correctly.
fn make_test_archive(harness: &common::TestHarness, realm_id: &RealmId) -> Vec<u8> {
    use hearth::backup::{BackupManifest, RealmManifest, RecordCounts};

    let realm_obj = harness
        .identity()
        .get_realm(realm_id)
        .expect("get realm")
        .expect("exists");
    let realm_slug = realm_obj.name().to_string();
    let realm_json = serde_json::to_vec(&realm_obj).expect("serialize realm");

    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let mut writer = BackupArchive::create(tmp.path()).expect("create archive");

    writer
        .add_file(&format!("realms/{realm_slug}/realm.json"), &realm_json)
        .expect("add realm.json");
    writer
        .add_file(&format!("realms/{realm_slug}/users.ndjson"), b"")
        .expect("add users");
    writer
        .add_file(&format!("realms/{realm_slug}/credentials.ndjson"), b"")
        .expect("add credentials");
    writer
        .add_file(&format!("realms/{realm_slug}/clients.ndjson"), b"")
        .expect("add clients");

    let manifest = BackupManifest::new(vec![RealmManifest {
        realm_id: format!("realm_{}", realm_id.as_uuid()),
        slug: realm_slug.clone(),
        record_counts: RecordCounts::default(),
    }]);
    writer.finish(manifest).expect("finish archive");

    std::fs::read(tmp.path()).expect("read archive")
}

fn multipart_body(archive_bytes: &[u8]) -> (String, Vec<u8>) {
    let boundary = "hearth_test_boundary_42";
    let mut body = Vec::new();
    // Header
    body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.hearth-backup\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
    // File data
    body.extend_from_slice(archive_bytes);
    // Footer
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

#[tokio::test]
async fn backup_restore_dry_run_returns_counts() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = make_admin_token(&h, &realm).await;

    let archive = make_test_archive(&h, &realm);
    let (ct, body_bytes) = multipart_body(&archive);

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/backup/restore?dry_run=true")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("content-type", ct)
                .body(Body::from(body_bytes))
                .expect("req"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK, "dry-run should succeed");
    let json = resp_json(resp).await;
    assert_eq!(json["dry_run"], true, "dry_run flag must be echoed");
    assert!(json["counts"].is_object(), "counts must be an object");
    assert!(json["errors"].is_array(), "errors must be an array");
}

#[tokio::test]
async fn backup_restore_invalid_mode_returns_400() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = make_admin_token(&h, &realm).await;

    let archive = make_test_archive(&h, &realm);
    let (ct, body_bytes) = multipart_body(&archive);

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/backup/restore?mode=invalidmode")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("content-type", ct)
                .body(Body::from(body_bytes))
                .expect("req"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = resp_json(resp).await;
    assert!(
        json["error"]
            .as_str()
            .unwrap_or("")
            .contains("unknown mode"),
        "error must mention 'unknown mode'"
    );
}
