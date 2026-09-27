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
use hearth::backup::{BackupArchive, BackupSigningKey};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState, BACKUP_RESTORE_BODY_LIMIT};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

// ===== helpers =====

/// Test-only Ed25519 backup signing key (PKCS#8 v1, as `openssl genpkey
/// -algorithm ed25519` writes it). Its public half is [`TEST_VERIFY_KEY_B64`].
const TEST_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBJga6BJyucFOXunA+oAB3JEXBR0Q+ZWepPJ0QZdsprJ
-----END PRIVATE KEY-----
";
const TEST_VERIFY_KEY_B64: &str = "5settUVm3ZDqg9RWtbbLjmbA1RK2KOvVu_PmihsFk-8";

fn test_signing_key() -> BackupSigningKey {
    BackupSigningKey::from_pem(TEST_SIGNING_KEY_PEM).expect("test signing key")
}

fn test_verify_key() -> [u8; 32] {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD
        .decode(TEST_VERIFY_KEY_B64)
        .expect("base64url")
        .try_into()
        .expect("32 bytes")
}

/// A production-mode app (not dev) with `security.backup.verify_key` set to
/// [`TEST_VERIFY_KEY_B64`] — the configuration restore requires outside dev
/// mode.
async fn build_app(h: &common::TestHarness) -> axum::Router {
    build_app_with(h, Some(test_verify_key()), false)
}

fn build_app_with(
    h: &common::TestHarness,
    verify_key: Option<[u8; 32]>,
    dev_mode: bool,
) -> axum::Router {
    let state = if dev_mode {
        AppState::new_dev(h.identity_arc(), h.rbac_arc(), h.audit_arc())
    } else {
        AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())
    };
    router(Arc::new(state.with_backup_verify_key(verify_key)))
}

/// Signs archive bytes with `key`, as `hearth backup sign` would.
fn sign_bytes(archive: &[u8], key: &BackupSigningKey) -> Vec<u8> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("a.hearth-backup");
    std::fs::write(&path, archive).expect("write");
    hearth::backup::sign_archive(&path, &path, key).expect("sign");
    std::fs::read(&path).expect("read")
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
/// The archive is signed with [`test_signing_key`], so it verifies against the
/// key [`build_app`] configures. Use [`export_unsigned_archive`] for the raw
/// export.
///
/// The caller MUST have called [`set_master_key`] before building the harness.
async fn export_archive(harness: &common::TestHarness, realm: &RealmId, token: &str) -> Vec<u8> {
    sign_bytes(
        &export_unsigned_archive(harness, realm, token).await,
        &test_signing_key(),
    )
}

/// Exports an archive through `POST /admin/backup` exactly as the server
/// produced it: the server holds no signing key, so it is unsigned.
async fn export_unsigned_archive(
    harness: &common::TestHarness,
    realm: &RealmId,
    token: &str,
) -> Vec<u8> {
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
        audit_chain_included: false,
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

// ===== POST /admin/backup/restore — integrity (task 26.42) =====

/// Rewrites a `.hearth-backup` blob with one member deleted, leaving
/// `manifest.json` — and therefore that member's checksum — untouched.
fn archive_without_member(archive: &[u8], drop_member: &str) -> Vec<u8> {
    use std::io::Read as _;

    let src = tempfile::NamedTempFile::new().expect("src tempfile");
    std::fs::write(src.path(), archive).expect("write src");
    let dst = tempfile::NamedTempFile::new().expect("dst tempfile");

    let decoder =
        zstd::Decoder::new(std::fs::File::open(src.path()).expect("open src")).expect("dec");
    let mut tar_in = tar::Archive::new(decoder);
    let encoder =
        zstd::Encoder::new(std::fs::File::create(dst.path()).expect("create dst"), 0).expect("enc");
    let mut builder = tar::Builder::new(encoder);
    let mut dropped = false;
    for entry in tar_in.entries().expect("entries") {
        let mut entry = entry.expect("entry");
        let path = entry.path().expect("path").to_string_lossy().into_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).expect("read");
        if path.ends_with(drop_member) {
            dropped = true;
            continue;
        }
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, &path, bytes.as_slice())
            .expect("append");
    }
    builder
        .into_inner()
        .expect("into_inner")
        .finish()
        .expect("finish");
    assert!(
        dropped,
        "'{drop_member}' was not in the archive — the mutation this helper exists \
         to make did not happen"
    );
    std::fs::read(dst.path()).expect("read dst")
}

/// The HTTP restore must verify the archive before importing anything.
///
/// It opened the archive and imported. Nothing called `verify_checksums`, so an
/// archive with a member deleted from it — which `hearth backup verify` also
/// called "OK", because verification walked the tar rather than the manifest —
/// imported a realm with zero users and answered 200 (audit re-run 23.5, B-3
/// and B-7). Unlike the CLI this route has no opt-out.
#[tokio::test]
async fn backup_restore_refuses_an_archive_that_fails_verification() {
    set_master_key();
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = make_admin_token(&h, &realm).await;

    h.identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "integrity@backup-test.example".into(),
                display_name: "Integrity".into(),
                first_name: "In".into(),
                last_name: "Tegrity".into(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let archive = export_archive(&h, &realm, &token).await;

    // Control: the unmodified archive is accepted, so the refusal below is
    // attributable to the elision and not to the export or the multipart body.
    let (ct, body_bytes) = multipart_body(&archive);
    let ok = build_app(&h)
        .await
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
        ok.status(),
        StatusCode::OK,
        "control: an untouched archive must restore"
    );

    let elided = archive_without_member(&archive, "users.ndjson");
    let (ct, body_bytes) = multipart_body(&elided);
    let resp = build_app(&h)
        .await
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
        StatusCode::BAD_REQUEST,
        "an archive missing a member the manifest checksums must be refused"
    );
    let body = String::from_utf8_lossy(&resp_bytes(resp).await).into_owned();
    assert!(
        body.contains("integrity") && body.contains("users.ndjson"),
        "the refusal must say what is wrong and name the missing member; got: {body}"
    );
}

// ===== A-30: restore refuses archives it cannot authenticate =====
//
// An archive is encrypted and checksummed, but the checksums sit in the
// manifest an attacker would rewrite and the passphrase is shared by every
// operator who can restore. The detached manifest signature is the only proof
// of origin, and the restore used to skip it whenever
// `security.backup.verify_key` was unset — the default. Outside dev mode a
// restore now requires a key and a valid signature.

async fn dry_run_restore(
    app: axum::Router,
    realm: &RealmId,
    token: &str,
    archive: &[u8],
) -> (StatusCode, String) {
    let (ct, body_bytes) = multipart_body(archive);
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
    let status = resp.status();
    (
        status,
        String::from_utf8_lossy(&resp_bytes(resp).await).into_owned(),
    )
}

#[tokio::test]
async fn restore_without_a_verify_key_is_refused_outside_dev_mode() {
    set_master_key();
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = make_admin_token(&h, &realm).await;
    let archive = export_archive(&h, &realm, &token).await;

    // Control: the same archive restores once a key is configured.
    let (ok, body) = dry_run_restore(build_app(&h).await, &realm, &token, &archive).await;
    assert_eq!(ok, StatusCode::OK, "control must restore; got {body}");

    let (status, body) =
        dry_run_restore(build_app_with(&h, None, false), &realm, &token, &archive).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "no verify key in production must refuse; got {body}"
    );
    assert!(
        body.contains("security.backup.verify_key"),
        "the refusal must say how to configure the key; got {body}"
    );
    assert!(
        body.contains("backup_verify_key_not_configured"),
        "the refusal must carry a stable machine-readable code; got {body}"
    );
}

#[tokio::test]
async fn restore_without_a_verify_key_is_allowed_in_dev_mode() {
    set_master_key();
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = make_admin_token(&h, &realm).await;
    let archive = export_unsigned_archive(&h, &realm, &token).await;

    let (status, body) =
        dry_run_restore(build_app_with(&h, None, true), &realm, &token, &archive).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "dev mode keeps unsigned restores; got {body}"
    );
}

#[tokio::test]
async fn unsigned_archive_is_refused_when_a_verify_key_is_configured() {
    set_master_key();
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = make_admin_token(&h, &realm).await;
    let archive = export_unsigned_archive(&h, &realm, &token).await;

    // Dev mode does not relax a configured key.
    for dev in [false, true] {
        let (status, body) = dry_run_restore(
            build_app_with(&h, Some(test_verify_key()), dev),
            &realm,
            &token,
            &archive,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "dev={dev}: {body}");
        assert!(body.contains("unsigned"), "dev={dev}: {body}");
        // The documented contract token (CHANGELOG, HEA-1206) survives.
        assert!(
            body.contains("missing_manifest_signature"),
            "dev={dev}: {body}"
        );
    }
}

#[tokio::test]
async fn archive_signed_by_another_key_is_refused() {
    set_master_key();
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = make_admin_token(&h, &realm).await;
    let (other, _pem) = BackupSigningKey::generate().expect("generate");
    let archive = sign_bytes(&export_unsigned_archive(&h, &realm, &token).await, &other);

    let (status, body) = dry_run_restore(build_app(&h).await, &realm, &token, &archive).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("signature is invalid"), "{body}");
    assert!(body.contains("invalid_manifest_signature"), "{body}");
}

// ===== The system realm over HTTP (operator-console recovery) =====
//
// `POST /admin/backup` enumerated realms through `list_realms`, which hides
// the system realm, so no HTTP export ever carried an operator account. It now
// does — for a system-realm caller only. A tenant-scoped caller never exports
// it and can never restore it.

fn system_realm() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

/// Creates an operator in the system realm (as first-run setup does) and
/// returns a system-realm access token for it.
fn make_system_token(h: &common::TestHarness, email: &str) -> String {
    let sys = system_realm();
    let user = h
        .identity()
        .create_admin_user(&CreateUserRequest {
            email: email.to_string(),
            display_name: "Operator".into(),
            ..Default::default()
        })
        .expect("operator");
    h.rbac().seed_realm(&sys).expect("seed system roles");
    let role = h
        .rbac()
        .get_role_by_name(&sys, "realm.admin")
        .expect("role")
        .expect("seeded");
    h.rbac()
        .assign_role(
            &sys,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("grant realm.admin");
    let session = h
        .identity()
        .create_session(&sys, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(&sys, user.id(), session.id())
        .expect("tokens")
        .access_token()
        .to_string()
}

async fn post_backup(h: &common::TestHarness, uri: &str, token: &str, realm: &RealmId) -> Vec<u8> {
    let resp = build_app(h)
        .await
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "export {uri} must succeed");
    resp_bytes(resp).await
}

fn archive_realm_ids(bytes: &[u8]) -> Vec<String> {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), bytes).expect("write");
    let reader = BackupArchive::open(tmp.path()).expect("open archive");
    reader.realms().iter().map(|r| r.realm_id.clone()).collect()
}

fn nil_realm_id_string() -> String {
    format!("realm_{}", uuid::Uuid::nil())
}

#[tokio::test]
async fn a_system_realm_export_carries_the_system_realm_and_a_tenant_export_never_does() {
    set_master_key();
    let h = common::TestHarness::embedded().await.expect("harness");
    let tenant = h.create_realm();
    h.rbac().seed_realm(&tenant).expect("seed");
    let tenant_token = make_admin_token(&h, &tenant).await;
    let system_token = make_system_token(&h, "operator@hearth.test");

    // Full export by a system-realm caller: every tenant AND the system realm.
    let ids =
        archive_realm_ids(&post_backup(&h, "/admin/backup", &system_token, &system_realm()).await);
    assert!(
        ids.contains(&nil_realm_id_string()),
        "a system-realm caller's full export must carry the system realm: {ids:?}"
    );
    assert!(
        ids.contains(&format!("realm_{}", tenant.as_uuid())),
        "and every tenant realm: {ids:?}"
    );

    // Named explicitly.
    let ids = archive_realm_ids(
        &post_backup(
            &h,
            "/admin/backup?realm=system",
            &system_token,
            &system_realm(),
        )
        .await,
    );
    assert_eq!(
        ids,
        vec![nil_realm_id_string()],
        "?realm=system exports the system realm only"
    );

    // A tenant-scoped caller: never the system realm, with or without naming it.
    let ids = archive_realm_ids(&post_backup(&h, "/admin/backup", &tenant_token, &tenant).await);
    assert!(
        !ids.contains(&nil_realm_id_string()),
        "a tenant export must never carry the system realm: {ids:?}"
    );
    let resp = build_app(&h)
        .await
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/backup?realm=system")
                .header("Authorization", format!("Bearer {tenant_token}"))
                .header("X-Realm-ID", tenant.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a tenant caller naming the system realm is refused"
    );
}

async fn post_restore(
    h: &common::TestHarness,
    uri: &str,
    token: &str,
    realm: &RealmId,
    archive: &[u8],
) -> (StatusCode, serde_json::Value) {
    let (ct, body) = multipart_body(archive);
    let resp = build_app(h)
        .await
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("content-type", ct)
                .body(Body::from(body))
                .expect("req"),
        )
        .await
        .expect("response");
    let status = resp.status();
    (status, resp_json(resp).await)
}

#[tokio::test]
async fn only_a_system_realm_caller_restores_the_system_realm_over_http() {
    set_master_key();
    // Source: an operator to recover, exported by a system-realm caller.
    let src = common::TestHarness::embedded().await.expect("src");
    let src_token = make_system_token(&src, "recovered@hearth.test");
    let archive = sign_bytes(
        &post_backup(
            &src,
            "/admin/backup?realm=system",
            &src_token,
            &system_realm(),
        )
        .await,
        &test_signing_key(),
    );

    let dst = common::TestHarness::embedded().await.expect("dst");
    let tenant = dst.create_realm();
    dst.rbac().seed_realm(&tenant).expect("seed");
    let tenant_token = make_admin_token(&dst, &tenant).await;

    // A tenant-scoped caller — even in overwrite mode — is refused, and no
    // system-realm principal is created.
    for uri in [
        "/admin/backup/restore",
        "/admin/backup/restore?mode=overwrite",
        "/admin/backup/restore?realm=system",
    ] {
        let (status, body) = post_restore(&dst, uri, &tenant_token, &tenant, &archive).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
    }
    assert!(
        dst.identity()
            .get_user_by_email(&system_realm(), "recovered@hearth.test")
            .expect("lookup")
            .is_none(),
        "a tenant-scoped restore must never create a system-realm principal"
    );

    // A system-realm caller restores it.
    let dst_token = make_system_token(&dst, "live@hearth.test");
    let (status, body) = post_restore(
        &dst,
        "/admin/backup/restore",
        &dst_token,
        &system_realm(),
        &archive,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "system-realm restore: {body}");
    assert_eq!(body["counts"]["system"]["users"]["created"], 1, "{body}");
    assert!(
        dst.identity()
            .get_user_by_email(&system_realm(), "recovered@hearth.test")
            .expect("lookup")
            .is_some(),
        "the archived operator is restored"
    );
    assert!(
        dst.identity()
            .get_user_by_email(&system_realm(), "live@hearth.test")
            .expect("lookup")
            .is_some(),
        "the live operator is untouched"
    );
}

/// Creates an operator in the system realm holding exactly `permissions`
/// (through one custom role) and returns a system-realm access token for it.
fn make_system_token_with(h: &common::TestHarness, email: &str, permissions: &[&str]) -> String {
    use hearth::rbac::{CreateRoleRequest, Permission};
    let sys = system_realm();
    let user = h
        .identity()
        .create_admin_user(&CreateUserRequest {
            email: email.to_string(),
            display_name: "Delegated operator".into(),
            ..Default::default()
        })
        .expect("operator");
    h.rbac().seed_realm(&sys).expect("seed system roles");
    let role = h
        .rbac()
        .create_role(
            &sys,
            &CreateRoleRequest {
                name: format!("delegated-{}", uuid::Uuid::new_v4()),
                description: None,
                permissions: permissions
                    .iter()
                    .map(|p| Permission::new(*p).expect("permission"))
                    .collect(),
                parent_roles: vec![],
                scope_kind: hearth::rbac::RoleScopeKind::Realm,
                allow_reserved_permissions: true,
            },
        )
        .expect("role");
    h.rbac()
        .assign_role(
            &sys,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("grant role");
    let session = h
        .identity()
        .create_session(&sys, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(&sys, user.id(), session.id())
        .expect("tokens")
        .access_token()
        .to_string()
}

async fn post_backup_status(
    h: &common::TestHarness,
    uri: &str,
    token: &str,
    realm: &RealmId,
) -> StatusCode {
    build_app(h)
        .await
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("response")
        .status()
}

/// A system-realm caller's backup reaches every realm — the system realm's
/// operators and signing key included — so it needs `hearth.admin`, not just
/// a sub-admin permission plus `hearth.export`. A delegated operator holding
/// `hearth.users.admin` + `hearth.export` could otherwise resurrect deleted
/// operators, overwrite every operator's password hash, or reinstall a rotated
/// system signing key with a signed archive.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one scenario: four sub-admins refused, then the superuser
async fn a_system_realm_backup_or_restore_needs_hearth_admin_not_a_sub_admin() {
    set_master_key();
    let src = common::TestHarness::embedded().await.expect("src");
    let src_token = make_system_token(&src, "recovered@hearth.test");
    let archive = sign_bytes(
        &post_backup(
            &src,
            "/admin/backup?realm=system",
            &src_token,
            &system_realm(),
        )
        .await,
        &test_signing_key(),
    );

    let dst = common::TestHarness::embedded().await.expect("dst");
    let tenant = dst.create_realm();
    dst.rbac().seed_realm(&tenant).expect("seed");
    let tenant_archive = {
        let tenant_token = make_admin_token(&dst, &tenant).await;
        export_archive(&dst, &tenant, &tenant_token).await
    };
    let key_before = dst
        .identity()
        .export_realm_signing_key_pkcs8(&system_realm())
        .expect("system key");

    for sub_admin in [
        "hearth.users.admin",
        "hearth.realm.admin",
        "hearth.clients.admin",
        "hearth.agents.admin",
    ] {
        let token = make_system_token_with(
            &dst,
            &format!("{sub_admin}@hearth.test"),
            &[sub_admin, "hearth.export"],
        );
        for uri in ["/admin/backup", "/admin/backup?realm=system"] {
            assert_eq!(
                post_backup_status(&dst, uri, &token, &system_realm()).await,
                StatusCode::FORBIDDEN,
                "{sub_admin} + hearth.export must not export {uri}"
            );
        }
        for uri in [
            "/admin/backup/restore",
            "/admin/backup/restore?mode=merge",
            "/admin/backup/restore?mode=overwrite",
            "/admin/backup/restore?dry_run=true",
        ] {
            let (status, body) = post_restore(&dst, uri, &token, &system_realm(), &archive).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{sub_admin} + hearth.export must not restore the system realm ({uri}): {body}"
            );
            let (status, body) =
                post_restore(&dst, uri, &token, &system_realm(), &tenant_archive).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{sub_admin} + hearth.export must not restore a tenant realm from the \
                 system realm ({uri}): {body}"
            );
        }
    }

    // Nothing was written by any refused restore.
    assert!(
        dst.identity()
            .get_user_by_email(&system_realm(), "recovered@hearth.test")
            .expect("lookup")
            .is_none(),
        "a refused restore must not create the archived operator"
    );
    assert_eq!(
        dst.identity()
            .export_realm_signing_key_pkcs8(&system_realm())
            .expect("system key"),
        key_before,
        "a refused restore must not touch the system signing key"
    );
    let restored_events = dst
        .audit()
        .query(&AuditQuery {
            action: Some(AuditAction::BackupRestored),
            ..AuditQuery::for_realm(system_realm())
        })
        .expect("audit query");
    assert!(
        restored_events.is_empty(),
        "a refused restore records no BackupRestored event: {restored_events:?}"
    );

    // hearth.admin + hearth.export (and nothing else) is enough.
    let admin = make_system_token_with(
        &dst,
        "superuser@hearth.test",
        &["hearth.admin", "hearth.export"],
    );
    assert_eq!(
        post_backup_status(&dst, "/admin/backup?realm=system", &admin, &system_realm()).await,
        StatusCode::OK,
        "hearth.admin + hearth.export exports the system realm"
    );
    let (status, body) = post_restore(
        &dst,
        "/admin/backup/restore",
        &admin,
        &system_realm(),
        &archive,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "hearth.admin restores: {body}");
    assert!(
        dst.identity()
            .get_user_by_email(&system_realm(), "recovered@hearth.test")
            .expect("lookup")
            .is_some(),
        "the archived operator is restored"
    );
}
