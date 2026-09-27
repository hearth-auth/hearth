//! Operator-console recovery through the real CLI: `hearth backup create` of a
//! store, `hearth backup restore` into an EMPTY data directory, then an
//! operator signs in to `/ui/admin/login` on the restored store with the
//! original credentials.
//!
//! Before the system realm was restorable this sequence ended at the restore:
//! it exited 2 with `operation not permitted on the system realm:
//! import_realm`, and a restore narrowed to the tenant realms left nobody able
//! to sign in to the console.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::rbac::{AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope, Subject};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

const MASTER_KEY: &str = "5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e";
const OPERATOR_EMAIL: &str = "operator@hearth.test";
const OPERATOR_PASSWORD: &str = "Operat0r-Recovery-Pa55!";

struct Engines {
    identity: Arc<dyn IdentityEngine>,
    rbac: Arc<dyn RbacEngine>,
    audit: Arc<dyn AuditEngine>,
}

/// Opens the engines on `dir` without a KEK — what the CLI does with neither
/// `HEARTH_KEK` nor a `--config` that sets one.
fn open(dir: &Path) -> Engines {
    // The storage layer seals each realm's data key under HEARTH_MASTER_KEY;
    // the CLI child processes run with the same one. nextest runs each test in
    // its own process, so this cannot race a sibling test.
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("HEARTH_MASTER_KEY", MASTER_KEY);
    }
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.to_path_buf())).expect("storage"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&storage),
            clock,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&rbac),
            Arc::clone(&audit),
        )
        .expect("identity"),
    ) as Arc<dyn IdentityEngine>;
    Engines {
        identity,
        rbac,
        audit,
    }
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("mkdir");
    for entry in std::fs::read_dir(src).expect("read_dir") {
        let entry = entry.expect("entry");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).expect("copy");
        }
    }
}

fn hearth(args: &[&std::ffi::OsStr]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hearth"))
        .args(args)
        .env_remove("HEARTH_KEK")
        .env("HEARTH_MASTER_KEY", MASTER_KEY)
        .output()
        .expect("run hearth");
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn os(s: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(s)
}

/// Seeds `dir` with a tenant realm and one operator (active, password,
/// `realm.admin`), exactly the state first-run setup leaves behind.
fn seed_source_store(dir: &Path) {
    let e = open(dir);
    e.identity
        .create_realm(&CreateRealmRequest {
            name: "tenant".to_string(),
            config: None,
        })
        .expect("tenant realm");
    let sys = RealmId::new(uuid::Uuid::nil());
    let op = e
        .identity
        .create_admin_user(&CreateUserRequest {
            email: OPERATOR_EMAIL.to_string(),
            display_name: "Operator".to_string(),
            ..Default::default()
        })
        .expect("operator");
    e.identity
        .set_password(
            &sys,
            op.id(),
            &CleartextPassword::from_string(OPERATOR_PASSWORD.to_string()),
        )
        .expect("password");
    e.rbac.seed_realm(&sys).expect("seed system roles");
    let role = e
        .rbac
        .get_role_by_name(&sys, "realm.admin")
        .expect("role")
        .expect("seeded");
    e.rbac
        .assign_role(
            &sys,
            &AssignRoleRequest {
                subject: Subject::User(op.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("grant realm.admin");
}

async fn admin_login(e: &Engines, data_dir: &Path, password: &str) -> StatusCode {
    let email = Arc::new(
        hearth::identity::email::EmailService::new(
            Arc::new(hearth::identity::email::LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            hearth::identity::email::EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email"),
    );
    let onboarding = Arc::new(hearth::identity::onboarding::OnboardingService::new(
        Arc::clone(&e.identity),
        Arc::clone(&e.rbac),
        email,
        data_dir.to_path_buf(),
    ));
    let state = hearth::protocol::web::WebState::new(
        Arc::clone(&e.identity),
        Arc::clone(&e.rbac),
        Arc::clone(&e.audit),
        onboarding,
        hearth::protocol::web::CookieSecret::from_bytes([7u8; 32]),
        None,
    )
    .with_dev_mode(true);
    let body = format!(
        "email={}&password={}",
        OPERATOR_EMAIL.replace('@', "%40"),
        password
    );
    let resp = hearth::protocol::web::router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    if status.is_redirection() {
        assert!(
            resp.headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .any(|c| c.starts_with("hearth_ui_session=")),
            "a successful console login sets the session cookie"
        );
    }
    status
}

#[tokio::test]
async fn cli_export_and_offline_restore_bring_back_operator_console_access() {
    let dir = tempfile::tempdir().expect("tempdir");
    let origin = dir.path().join("origin");
    seed_source_store(&origin);
    // The origin's engines are dropped, but its storage lock is per-process;
    // the child process reads a copy.
    let source = dir.path().join("source");
    copy_dir(&origin, &source);

    // A production-shaped archive: signed, audit included.
    let key_file = dir.path().join("backup-signing.pem");
    let (code, out) = hearth(&[
        os("backup"),
        os("keygen"),
        os("--output"),
        key_file.as_os_str(),
    ]);
    assert_eq!(code, Some(0), "keygen: {out}");
    let verify_key = hearth::backup::BackupSigningKey::from_pem(
        &std::fs::read_to_string(&key_file).expect("key"),
    )
    .expect("key parses")
    .verify_key_b64();

    let archive = dir.path().join("full.hearth-backup");
    let (code, out) = hearth(&[
        os("backup"),
        os("create"),
        os("--data-dir"),
        source.as_os_str(),
        os("--output"),
        archive.as_os_str(),
        os("--include-audit"),
        os("--sign-key"),
        key_file.as_os_str(),
    ]);
    assert_eq!(code, Some(0), "backup create: {out}");

    // Rebuilt node: an empty data directory.
    let restored = dir.path().join("restored");
    let (code, out) = hearth(&[
        os("backup"),
        os("restore"),
        os("--input"),
        archive.as_os_str(),
        os("--data-dir"),
        restored.as_os_str(),
        os("--verify-key"),
        os(&verify_key),
    ]);
    assert_eq!(
        code,
        Some(0),
        "a full archive — system realm included — must restore cleanly: {out}"
    );
    assert!(
        out.contains("operator-console") && out.contains("/ui/admin/login"),
        "the restore must say the operator console was restored and where to sign in: {out}"
    );

    // Start on the restored store and sign in with the ORIGINAL credentials.
    let e = open(&restored);
    assert!(
        e.identity
            .get_realm_by_name("tenant")
            .expect("lookup")
            .is_some(),
        "the tenant realm is restored beside the system realm"
    );
    assert!(
        admin_login(&e, &restored, OPERATOR_PASSWORD)
            .await
            .is_redirection(),
        "the operator must sign in to the console with the original password"
    );
    // Control: the form really checks the password.
    assert!(
        !admin_login(&e, &restored, "wrong-password-123")
            .await
            .is_redirection(),
        "a wrong password must not sign in"
    );
}

/// An archive without the system realm (`--realm tenant`, or a v1.6.11 HTTP
/// export) still restores without error, and the restore does not claim the
/// operator console came back.
#[tokio::test]
async fn an_archive_without_the_system_realm_restores_and_says_so() {
    let dir = tempfile::tempdir().expect("tempdir");
    let origin = dir.path().join("origin");
    seed_source_store(&origin);
    let source = dir.path().join("source");
    copy_dir(&origin, &source);

    let archive = dir.path().join("tenant.hearth-backup");
    let (code, out) = hearth(&[
        os("backup"),
        os("create"),
        os("--data-dir"),
        source.as_os_str(),
        os("--output"),
        archive.as_os_str(),
        os("--realm"),
        os("tenant"),
    ]);
    assert_eq!(code, Some(0), "backup create: {out}");

    let restored = dir.path().join("restored");
    let (code, out) = hearth(&[
        os("backup"),
        os("restore"),
        os("--input"),
        archive.as_os_str(),
        os("--data-dir"),
        restored.as_os_str(),
        os("--allow-unsigned"),
    ]);
    assert_eq!(code, Some(0), "tenant-only restore: {out}");
    assert!(
        out.contains("does not contain the system realm"),
        "the restore must warn that no operator account came back: {out}"
    );
    let e = open(&restored);
    assert!(
        !admin_login(&e, &restored, OPERATOR_PASSWORD)
            .await
            .is_redirection(),
        "no operator exists after a tenant-only restore"
    );
}
