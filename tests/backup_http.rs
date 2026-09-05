//! Integration tests for the admin backup HTTP endpoints.
//!
//! Covers:
//! - `POST /admin/backup` — create and download a backup archive
//! - `POST /admin/backup/restore` — restore from a backup archive
//! - Auth gating (403 for non-admin, 401 for missing token)
//! - SEC-14: restore requires `hearth.export` capability (403 without it)
//! - SEC-14: pre-restore audit event recorded before destructive write
//! - Dry-run restore returns counts without writing
//! - Round-trip: backup a realm, restore to a fresh realm

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::audit::{AuditAction, AuditQuery};
use hearth::backup::BackupArchive;
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState, BACKUP_RESTORE_BODY_LIMIT};
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
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var(
            "HEARTH_MASTER_KEY",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        );
    }
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
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var(
            "HEARTH_MASTER_KEY",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        );
    }
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

// ===== POST /admin/backup/restore — SEC-14: export capability gate =====

/// Creates a user with only the `hearth.realm.admin` role, which does NOT
/// include `hearth.export`. The token passes `extract_admin_auth` (has
/// `hearth.realm.admin` permission) but fails `check_export_capability`.
async fn make_realm_admin_token_no_export(h: &common::TestHarness, realm: &RealmId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("realm-admin-{}@backup-test.example", uuid::Uuid::new_v4()),
                display_name: "Realm Admin".into(),
                first_name: "Realm".into(),
                last_name: "Admin".into(),
                attributes: Default::default(),
            },
        )
        .expect("create realm admin user");

    let role = h
        .rbac()
        .get_role_by_name(realm, "hearth.realm.admin")
        .expect("look up hearth.realm.admin role")
        .expect("hearth.realm.admin must be seeded");

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
        .expect("assign hearth.realm.admin role");

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

/// A token with `hearth.realm.admin` (sub-admin) but without `hearth.export`
/// must receive 403 from the restore endpoint (SEC-14).
///
/// The capability check runs before multipart streaming, so no valid archive is
/// required — the response must be 403 regardless of the request body.
#[tokio::test]
async fn backup_restore_requires_export_capability() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    let token = make_realm_admin_token_no_export(&h, &realm).await;
    let app = build_app(&h).await;

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

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "restore must be 403 for a token without hearth.export"
    );
    let json = resp_json(resp).await;
    assert!(
        json["error_description"]
            .as_str()
            .unwrap_or("")
            .contains("hearth.export"),
        "error_description must mention hearth.export: {json}"
    );
}

/// The restore endpoint emits a `BackupRestored` audit event BEFORE the
/// destructive import begins (SEC-14). We verify this with a dry-run: even
/// though no data is written, the audit record must be present.
#[tokio::test]
async fn backup_restore_emits_pre_restore_audit_event() {
    set_master_key();
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = make_admin_token(&h, &realm).await;

    let archive = export_archive(&h, &realm, &token).await;
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

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "dry-run with valid admin token must succeed"
    );

    // The audit event must be present regardless of dry_run status — it is
    // emitted before the import runs, not inside the success branch.
    let events = h
        .audit()
        .query(&AuditQuery {
            action: Some(AuditAction::BackupRestored),
            ..AuditQuery::for_realm(realm.clone())
        })
        .expect("audit query");

    assert!(
        !events.is_empty(),
        "BackupRestored audit event must be recorded before restore completes"
    );
    let ev = &events[0];
    assert_eq!(ev.resource_type, "backup");
    let meta = ev.metadata.as_ref().expect("metadata must be present");
    assert_eq!(
        meta.get("dry_run").and_then(|v| v.as_bool()),
        Some(true),
        "audit metadata must reflect dry_run=true"
    );
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

/// Test master key for the wrapped DEK. Export encrypts every section with a
/// DEK wrapped by this key; restore unwraps it from the same variable.
const TEST_MASTER_KEY: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

/// Sets `HEARTH_MASTER_KEY` for this test process. `nextest` runs each test in
/// its own process, so this cannot race a sibling test.
fn set_master_key() {
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("HEARTH_MASTER_KEY", TEST_MASTER_KEY);
    }
}

/// Exports a real archive through `POST /admin/backup` and returns its bytes.
///
/// Restore fails closed when an archive carries no restorable signing key
/// (HEA-2168), and the HTTP handler never sets `allow_missing_signing_key`.
/// A hand-built archive therefore cannot reach the restore path at all, so any
/// test of restore behaviour must start from an archive the exporter produced.
///
/// The caller MUST have called [`set_master_key`] before building the harness.
async fn export_archive(harness: &common::TestHarness, realm: &RealmId, token: &str) -> Vec<u8> {
    let app = build_app(harness).await;
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
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "export must succeed before a restore can be tested"
    );
    let bytes = resp_bytes(resp).await;
    assert!(!bytes.is_empty(), "exported archive must not be empty");
    bytes
}

/// Builds a minimal backup archive by serializing the actual `Realm` object.
///
/// The archive is unencrypted and carries no `signing_key.json`, so restore
/// REFUSES it by design (HEA-2168). Use it only for tests that fail before the
/// signing-key gate — the mode parser, the body limit, the auth checks. For a
/// restore that must reach the importer, use [`export_archive`].
#[allow(dead_code)]
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
    set_master_key();
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = make_admin_token(&h, &realm).await;

    let archive = export_archive(&h, &realm, &token).await;
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

// ===== POST /admin/backup/restore — body size limit =====

/// Verifies that `BACKUP_RESTORE_BODY_LIMIT` is a finite, sane value so the
/// restore endpoint cannot be used for an OOM DoS (HEA-1130).
///
/// Also verifies that axum's `DefaultBodyLimit::max` middleware correctly
/// returns 413 when the body exceeds the configured cap, using a minimal
/// in-test router with a small limit (to avoid sending gigabytes in CI).
#[tokio::test]
async fn backup_restore_body_limit_is_enforced() {
    use axum::extract::DefaultBodyLimit;
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::Router;

    // The production constant must be positive and ≤ 8 GiB — evaluated at
    // compile time so this is a hard guarantee, not a runtime check.
    const _: () = assert!(BACKUP_RESTORE_BODY_LIMIT > 0);
    const _: () = assert!(BACKUP_RESTORE_BODY_LIMIT <= 8 * 1024 * 1024 * 1024);

    // Build a minimal test router using the same DefaultBodyLimit::max wiring
    // as the production route (just with a small cap to avoid sending GiB).
    // This proves the middleware returns 413 for oversized bodies.
    //
    // Note: `Multipart` is lazy — it only reads the body when fields are iterated,
    // so the limit isn't enforced until actual field reads. `Bytes` reads the
    // entire body eagerly, making the 413 deterministic at extraction time.
    // The production handler's `Multipart` hits the same limited body stream
    // when it iterates fields; the 413 manifests there instead of at creation.
    const TEST_LIMIT: usize = 512;

    async fn noop(_body: axum::body::Bytes) -> impl IntoResponse {
        StatusCode::OK
    }

    let app = Router::new().route(
        "/restore",
        post(noop).route_layer(DefaultBodyLimit::max(TEST_LIMIT)),
    );

    // Body of TEST_LIMIT + 1 bytes exceeds the cap → expect 413.
    let oversized_body = vec![b'x'; TEST_LIMIT + 1];
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/restore")
                .body(Body::from(oversized_body))
                .expect("req"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "restore endpoint must return 413 when body exceeds the configured limit"
    );
}

// ===== B3: a restore completes or refuses; it never destroys the target =====
//
// Audit 2026-08-28 §3 B3, §4.9#2 (P12, BLOCKER). `mode=overwrite` deleted the
// target realm and then failed to restore it: of 1,160 CLI runs none completed,
// 975 left the realm destroyed or truncated, and one reported exit 0.
//
// The cause is a race with the deletion itself. `delete_realm` marks the realm
// `DeletingInProgress` and, for a realm above `cascade_background_threshold`,
// spawns the cascade on a background task and returns `Ok` while it is still
// running (`src/identity/engine/mod.rs`). The importer then re-creates the
// realm, and the cascade deletes the realm record, the name index, the signing
// key and the freshly restored user, credential and session keys underneath it.
//
// A restore therefore never deletes a live realm. Restoring into an instance
// where the realm is absent — the disaster-recovery case — is unaffected: the
// first `import_realm` succeeds and the overwrite branch is never reached.

/// Overwrite-restoring over a live realm must refuse and leave it intact.
#[tokio::test]
async fn backup_restore_overwrite_refuses_over_a_live_realm() {
    set_master_key();
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = make_admin_token(&h, &realm).await;

    // Give the realm content, so a truncating restore is visible.
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "victim@backup-test.example".into(),
                display_name: "Victim".into(),
                first_name: "Victim".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let archive = export_archive(&h, &realm, &token).await;
    let (ct, body_bytes) = multipart_body(&archive);

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/backup/restore?mode=overwrite")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("content-type", ct)
                .body(Body::from(body_bytes))
                .expect("req"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "overwrite over a live realm must be refused, not half-executed"
    );

    // Left untouched: the realm and its content must both survive.
    assert!(
        h.identity().get_realm(&realm).expect("get realm").is_some(),
        "a refused overwrite must leave the realm in place"
    );
    assert!(
        h.identity()
            .get_user(&realm, user.id())
            .expect("get user")
            .is_some(),
        "a refused overwrite must leave the realm's users in place"
    );
}

// ===== B1: the realm acted on comes from the caller's identity =====
//
// Audit 2026-08-28 §3 B1, §4.1#1 (P13, BLOCKER). Both backup routes took the
// realm from a `?realm=<slug>` query parameter and resolved it against every
// realm in the deployment, with no check that the caller owned it. With no
// parameter at all, export covered every tenant and restore wrote every realm
// the archive named. A tenant admin could export a peer tenant in full and
// overwrite-restore it.

/// Reads a realm's slug (its `name`).
fn realm_slug(harness: &common::TestHarness, realm: &RealmId) -> String {
    harness
        .identity()
        .get_realm(realm)
        .expect("get realm")
        .expect("realm exists")
        .name()
        .to_string()
}

/// Naming a peer tenant's slug on export must be refused, not served.
#[tokio::test]
async fn backup_create_refuses_peer_realm_slug() {
    set_master_key();
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm_a = h.create_realm();
    h.rbac().seed_realm(&realm_a).expect("seed a");
    let token_a = make_admin_token(&h, &realm_a).await;

    let realm_b = h.create_realm();
    h.rbac().seed_realm(&realm_b).expect("seed b");
    let slug_b = realm_slug(&h, &realm_b);

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/backup?realm={slug_b}"))
                .header("Authorization", format!("Bearer {token_a}"))
                .header("X-Realm-ID", realm_a.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a realm admin must not export a peer tenant by naming its slug"
    );
}

/// Omitting the parameter must export the caller's realm, not every realm.
#[tokio::test]
async fn backup_create_without_realm_param_exports_only_caller_realm() {
    set_master_key();
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm_a = h.create_realm();
    h.rbac().seed_realm(&realm_a).expect("seed a");
    let token_a = make_admin_token(&h, &realm_a).await;
    let slug_a = realm_slug(&h, &realm_a);

    // A second tenant that must not appear in realm A's archive.
    let realm_b = h.create_realm();
    h.rbac().seed_realm(&realm_b).expect("seed b");

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/backup")
                .header("Authorization", format!("Bearer {token_a}"))
                .header("X-Realm-ID", realm_a.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "own-realm export must succeed"
    );

    let body = resp_bytes(resp).await;
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), &body).expect("write archive");
    let reader = BackupArchive::open(tmp.path()).expect("open archive");

    let slugs: Vec<&str> = reader.realms().iter().map(|r| r.slug.as_str()).collect();
    assert_eq!(
        slugs,
        vec![slug_a.as_str()],
        "an export with no realm parameter must carry the caller's realm only"
    );
}

/// Restoring an archive that names a peer tenant must be refused before any
/// write. `mode=overwrite` is used because it is the destructive path: if the
/// check does not fire, the peer realm is deleted.
#[tokio::test]
async fn backup_restore_refuses_archive_naming_a_peer_realm() {
    set_master_key();
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm_a = h.create_realm();
    h.rbac().seed_realm(&realm_a).expect("seed a");
    let token_a = make_admin_token(&h, &realm_a).await;

    let realm_b = h.create_realm();
    h.rbac().seed_realm(&realm_b).expect("seed b");
    let token_b = make_admin_token(&h, &realm_b).await;

    // Realm B's own admin exports realm B — that part is legitimate.
    let archive_b = export_archive(&h, &realm_b, &token_b).await;
    let (ct, body_bytes) = multipart_body(&archive_b);

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/backup/restore?mode=overwrite")
                .header("Authorization", format!("Bearer {token_a}"))
                .header("X-Realm-ID", realm_a.as_uuid().to_string())
                .header("content-type", ct)
                .body(Body::from(body_bytes))
                .expect("req"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a realm admin must not restore over a peer tenant"
    );

    // Fail closed: realm B must be untouched.
    assert!(
        h.identity()
            .get_realm(&realm_b)
            .expect("get realm b")
            .is_some(),
        "the refused restore must not have deleted the peer realm"
    );
}
