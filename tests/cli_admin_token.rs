//! `hearth admin token` — a short-lived system-realm operator token minted on
//! the host, against a stopped node's data directory (GA audit 3 DOC-2).
//!
//! Every production runbook that needs `$SYSTEM_TOKEN` (upgrading, disaster
//! recovery, clustering, the realm admin API) had no production source for it:
//! the only minting path was `POST /admin/bootstrap`, which exists only in a
//! `dev-endpoints` build running `--dev`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use hearth::audit::{AuditAction, AuditEngine, AuditQuery, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::key_encryption::StorageKek;
use hearth::identity::{
    CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::rbac::{AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope, Subject};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Host key the production store is opened with, here and by the CLI.
const MASTER_KEY: &str = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
/// Key-encryption key sealing the realm signing keys, given to the CLI through
/// `security.key_encryption_key` in the config file.
const KEK_HEX: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const OPERATOR: &str = "ops@hearth.example";
const NOT_AN_OPERATOR: &str = "viewer@hearth.example";

fn system_realm() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

fn kek() -> StorageKek {
    let bytes: [u8; 32] = hex::decode(KEK_HEX)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    StorageKek::new(bytes)
}

struct Engines {
    identity: Arc<EmbeddedIdentityEngine>,
    rbac: Arc<EmbeddedRbacEngine>,
    audit: Arc<EmbeddedAuditEngine>,
}

/// Opens the store the way `serve` and every one-shot command do: the
/// production config, sealed under `HEARTH_MASTER_KEY`, keys under the KEK.
fn open(data_dir: &Path) -> Engines {
    // nextest runs each test in its own process, so this cannot leak.
    std::env::set_var("HEARTH_MASTER_KEY", MASTER_KEY);
    std::env::remove_var("HEARTH_KEK");
    let storage: Arc<dyn StorageEngine> = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::production(
            data_dir.to_path_buf(),
            64 * 1024 * 1024,
            4 * 1024 * 1024,
            10_000,
        ))
        .expect("open the production store"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let audit = Arc::new(
        EmbeddedAuditEngine::new(Arc::clone(&storage), Arc::clone(&clock))
            .with_kek(Some(*kek().as_bytes())),
    );
    let identity = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            storage,
            clock,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                key_encryption_key: Some(kek()),
                ..IdentityConfig::default()
            },
            Arc::clone(&rbac) as Arc<dyn RbacEngine>,
            Arc::clone(&audit) as Arc<dyn AuditEngine>,
        )
        .expect("identity engine"),
    );
    Engines {
        identity,
        rbac,
        audit,
    }
}

/// A stopped node's data directory: the system realm holds one operator
/// account (`realm.admin`, so `hearth.admin`) and one account without it.
/// Every engine is dropped on return, which releases the data-dir lock.
fn seed_store(data_dir: &Path) {
    let e = open(data_dir);
    let sys = system_realm();
    e.rbac.seed_realm(&sys).expect("seed system realm roles");
    let role = e
        .rbac
        .get_role_by_name(&sys, "realm.admin")
        .expect("look up realm.admin")
        .expect("realm.admin seeded");
    for email in [OPERATOR, NOT_AN_OPERATOR] {
        let user = e
            .identity
            .create_admin_user(&CreateUserRequest {
                email: email.to_string(),
                display_name: "Operator".into(),
                ..Default::default()
            })
            .expect("account in the system realm");
        if email == OPERATOR {
            e.rbac
                .assign_role(
                    &sys,
                    &AssignRoleRequest {
                        subject: Subject::User(user.id().clone()),
                        role_id: role.id.clone(),
                        scope: Scope::Realm,
                        assigned_by: None,
                    },
                )
                .expect("grant realm.admin");
        }
    }
}

fn write_config(dir: &Path, data_dir: &Path) -> PathBuf {
    let path = dir.join("hearth.yaml");
    std::fs::write(
        &path,
        format!(
            "storage:\n  data_dir: \"{}\"\nsecurity:\n  key_encryption_key: \"{KEK_HEX}\"\n",
            data_dir.display()
        ),
    )
    .expect("write config");
    path
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn hearth(args: &[&std::ffi::OsStr]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_hearth"))
        .args(args)
        .env_remove("HEARTH_KEK")
        .env("HEARTH_MASTER_KEY", MASTER_KEY)
        .output()
        .expect("run hearth");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn os(s: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(s)
}

/// Sends `GET /admin/realms` to an in-process router over the same store, as
/// the runbooks do with `$SYSTEM_TOKEN`.
fn admin_realms_status(e: &Engines, token: &str) -> StatusCode {
    let state = Arc::new(hearth::protocol::http::AppState::new_dev(
        Arc::clone(&e.identity) as Arc<dyn IdentityEngine>,
        Arc::clone(&e.rbac) as Arc<dyn RbacEngine>,
        Arc::clone(&e.audit) as Arc<dyn AuditEngine>,
    ));
    let app = hearth::protocol::http::router(state);
    let mut req = Request::builder()
        .uri("/admin/realms")
        .header("authorization", format!("Bearer {token}"))
        .header("x-realm-id", uuid::Uuid::nil().to_string())
        .body(Body::empty())
        .expect("request");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            40_000,
        ))));
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(app.oneshot(req))
        .expect("router response")
        .status()
}

/// The command prints one token, and nothing else, on stdout; the server
/// accepts it as a system-realm admin on the realm admin API; it carries
/// `hearth.admin`, lives exactly `--ttl`, and its issuance is in the system
/// realm's audit trail — without the token itself anywhere but stdout.
#[test]
fn admin_token_mints_a_short_lived_system_admin_token_the_admin_api_accepts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    seed_store(&data_dir);
    let config = write_config(dir.path(), &data_dir);

    let run = hearth(&[
        os("admin"),
        os("token"),
        os("--config"),
        config.as_os_str(),
        os("--user"),
        os(OPERATOR),
        os("--ttl"),
        os("10m"),
    ]);
    assert_eq!(
        run.code,
        Some(0),
        "stdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "stdout must carry the token alone, so `SYSTEM_TOKEN=$(hearth admin token …)` \
         works: {:?}",
        run.stdout
    );
    let token = lines[0].trim().to_string();
    assert_eq!(token.split('.').count(), 3, "a JWT: {token}");
    assert!(
        !run.stderr.contains(&token),
        "the token must never be logged: {}",
        run.stderr
    );

    let e = open(&data_dir);
    let sys = system_realm();
    let claims = e
        .identity
        .validate_token(&sys, &token)
        .expect("the token validates in the system realm");
    assert!(
        claims.permissions.iter().any(|p| p == "hearth.admin"),
        "the token must carry hearth.admin: {:?}",
        claims.permissions
    );
    assert_eq!(
        claims.exp - claims.iat,
        600,
        "the token lives exactly --ttl"
    );

    assert_eq!(
        admin_realms_status(&e, &token),
        StatusCode::OK,
        "the realm admin API must accept the token as a system-realm admin"
    );

    let events = e
        .audit
        .query(&AuditQuery {
            action: Some(AuditAction::TokenIssued),
            ..AuditQuery::for_realm(sys)
        })
        .expect("query the system realm's audit trail");
    let issued: Vec<_> = events
        .iter()
        .filter(|ev| {
            ev.metadata
                .as_ref()
                .and_then(|m| m.get("issued_via"))
                .and_then(serde_json::Value::as_str)
                == Some("hearth admin token")
        })
        .collect();
    assert_eq!(
        issued.len(),
        1,
        "exactly one audit record for the issuance: {events:?}"
    );
    let record = serde_json::to_string(issued[0]).expect("serialise the audit record");
    assert!(
        !record.contains(&token),
        "the audit record must not carry the token"
    );
    assert_eq!(
        issued[0]
            .metadata
            .as_ref()
            .and_then(|m| m.get("ttl_secs"))
            .and_then(serde_json::Value::as_u64),
        Some(600)
    );
}

/// The command opens the store directly, so it refuses while `hearth serve`
/// holds the data directory — and says to stop the server.
#[test]
fn admin_token_refuses_a_data_directory_a_running_server_holds() {
    use fs2::FileExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    seed_store(&data_dir);
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(data_dir.join("LOCK"))
        .expect("open LOCK");
    lock.try_lock_exclusive().expect("hold the lock");

    let run = hearth(&[
        os("admin"),
        os("token"),
        os("--data-dir"),
        data_dir.as_os_str(),
        os("--config"),
        write_config(dir.path(), &data_dir).as_os_str(),
        os("--user"),
        os(OPERATOR),
    ]);
    assert_ne!(run.code, Some(0), "must refuse while the store is held");
    assert!(run.stdout.trim().is_empty(), "no token: {}", run.stdout);
    let all = format!("{}{}", run.stdout, run.stderr);
    assert!(
        all.contains("locked") && all.contains("stop"),
        "the refusal must name the lock and say to stop the server: {all}"
    );
}

/// A cluster node's store is refused: the session and audit record the command
/// writes would exist on that node only, outside Raft, and fork the replicated
/// system-realm audit chain. `--sole-cluster-node` accepts it for the one case
/// where that cannot happen — the node restarts as its cluster's only member
/// and every other node rejoins empty from its snapshot (disaster recovery).
#[test]
fn admin_token_refuses_a_cluster_node_data_directory_unless_it_will_run_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    seed_store(&data_dir);
    std::fs::write(data_dir.join("raft.db"), b"").expect("mark as a cluster node");
    let config = write_config(dir.path(), &data_dir);

    let run = hearth(&[
        os("admin"),
        os("token"),
        os("--config"),
        config.as_os_str(),
        os("--user"),
        os(OPERATOR),
    ]);
    assert_ne!(run.code, Some(0), "must refuse a cluster node's store");
    assert!(run.stdout.trim().is_empty(), "no token: {}", run.stdout);
    let all = format!("{}{}", run.stdout, run.stderr);
    assert!(
        all.contains("cluster") && all.contains("--sole-cluster-node"),
        "the refusal must say why, and name the override: {all}"
    );

    let run = hearth(&[
        os("admin"),
        os("token"),
        os("--config"),
        config.as_os_str(),
        os("--user"),
        os(OPERATOR),
        os("--sole-cluster-node"),
    ]);
    assert_eq!(
        run.code,
        Some(0),
        "stdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
    let token = run.stdout.trim();
    let e = open(&data_dir);
    e.identity
        .validate_token(&system_realm(), token)
        .expect("the token minted for the sole node validates");
}

/// Only an operator account holding `hearth.admin` gets a token, and only a
/// short-lived one.
#[test]
fn admin_token_refuses_a_non_operator_and_a_long_ttl() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    seed_store(&data_dir);
    let config = write_config(dir.path(), &data_dir);

    for (user, ttl, why) in [
        (NOT_AN_OPERATOR, "15m", "an account without hearth.admin"),
        ("nobody@hearth.example", "15m", "an unknown account"),
        (OPERATOR, "2h", "a TTL over one hour"),
        (OPERATOR, "30s", "a TTL under one minute"),
    ] {
        let run = hearth(&[
            os("admin"),
            os("token"),
            os("--config"),
            config.as_os_str(),
            os("--user"),
            os(user),
            os("--ttl"),
            os(ttl),
        ]);
        assert_ne!(run.code, Some(0), "{why} must be refused");
        assert!(
            run.stdout.trim().is_empty(),
            "{why}: no token may be printed: {}",
            run.stdout
        );
    }

    // Nothing above minted anything.
    let e = open(&data_dir);
    let issued = e
        .audit
        .query(&AuditQuery {
            action: Some(AuditAction::TokenIssued),
            ..AuditQuery::for_realm(system_realm())
        })
        .expect("query the audit trail");
    assert!(
        issued.is_empty(),
        "a refusal records no issuance: {issued:?}"
    );
}
