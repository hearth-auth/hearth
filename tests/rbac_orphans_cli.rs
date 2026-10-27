//! `hearth rbac orphans list` and `purge` through the real CLI (#618).
//!
//! An orphan is a stored reference to a registry entry that `hearth.yaml` no
//! longer declares: here, a user's extra grant of a permission whose record
//! is archived (custom-permissions spec, "Maintenance commands manage the
//! registry and its orphans"). The commands scanned every extra grant in the
//! system realm, whatever `--realm` said, and the purge deleted each one
//! without an audit event.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use hearth::audit::{AuditAction, AuditEngine, AuditQuery, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock, Timestamp, UserId};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine,
};
use hearth::rbac::{EmbeddedRbacEngine, Permission, RbacEngine, Scope, UserPermissionGrant};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

const MASTER_KEY: &str = "a11ce0dea11ce0dea11ce0dea11ce0dea11ce0dea11ce0dea11ce0dea11ce0de";

struct Engines {
    identity: Arc<dyn IdentityEngine>,
    rbac: Arc<dyn RbacEngine>,
    audit: Arc<dyn AuditEngine>,
}

/// Opens the engines on `dir`, as the CLI does.
fn open(dir: &Path) -> Engines {
    // The storage layer seals each realm's data key under HEARTH_MASTER_KEY;
    // the CLI child process runs with the same one. nextest runs each test in
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

/// Runs the `hearth` binary; returns its exit code and its whole output.
fn hearth(args: &[&str]) -> (Option<i32>, String) {
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

fn perm(name: &str) -> Permission {
    Permission::new(name).expect("valid permission")
}

struct Seeded {
    realm: RealmId,
    user: UserId,
}

/// Realm `orphanco` declares `docs.read`. It declared `docs.archive` too,
/// until `hearth.yaml` dropped it, so that record is archived. One user
/// holds both as extra grants.
fn seed(dir: &Path) -> Seeded {
    let e = open(dir);
    let realm = e
        .identity
        .create_realm(&CreateRealmRequest {
            name: "orphanco".to_string(),
            config: None,
        })
        .expect("realm");
    let realm_id = realm.id().clone();
    let user = e
        .identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "holder@orphanco.test".to_string(),
                display_name: "Holder".to_string(),
                ..Default::default()
            },
        )
        .expect("user");
    e.rbac
        .reconcile_permissions(
            &realm_id,
            &["docs.read".to_string(), "docs.archive".to_string()],
        )
        .expect("declare permissions");
    for name in ["docs.read", "docs.archive"] {
        e.rbac
            .grant_user_permission(
                &realm_id,
                &UserPermissionGrant {
                    realm_id: realm_id.clone(),
                    user_id: user.id().clone(),
                    permission: perm(name),
                    scope: Scope::Realm,
                    granted_at: Timestamp::now(),
                    granted_by: None,
                },
            )
            .expect("grant extra permission");
    }
    e.rbac
        .archive_removed_permissions(&realm_id, &HashSet::from(["docs.read".to_string()]))
        .expect("archive docs.archive");
    Seeded {
        realm: realm_id,
        user: user.id().clone(),
    }
}

/// The user's extra permissions, sorted.
fn extra_permissions(e: &Engines, s: &Seeded) -> Vec<String> {
    let mut names: Vec<String> = e
        .rbac
        .list_user_permissions(&s.realm, &s.user)
        .expect("list extra permissions")
        .iter()
        .map(|g| g.permission.as_str().to_string())
        .collect();
    names.sort();
    names
}

#[test]
fn list_names_the_orphaned_grant_of_the_realm() {
    let dir = tempfile::tempdir().expect("tempdir");
    let seeded = seed(dir.path());
    let realm = seeded.realm.as_uuid().to_string();
    let data_dir = dir.path().to_str().expect("utf-8 path");

    let (code, out) = hearth(&[
        "rbac",
        "orphans",
        "list",
        "--realm",
        &realm,
        "--data-dir",
        data_dir,
    ]);

    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.contains("docs.archive"),
        "the list must name the orphaned grant: {out}"
    );
    assert!(
        !out.contains("docs.read"),
        "a grant of a declared permission is not an orphan: {out}"
    );
}

#[test]
fn purge_deletes_only_the_grant_of_a_permission_hearth_yaml_no_longer_declares() {
    let dir = tempfile::tempdir().expect("tempdir");
    let seeded = seed(dir.path());
    let realm = seeded.realm.as_uuid().to_string();
    let data_dir = dir.path().to_str().expect("utf-8 path");

    let (code, out) = hearth(&[
        "rbac",
        "orphans",
        "purge",
        "--realm",
        &realm,
        "--data-dir",
        data_dir,
    ]);
    assert_eq!(code, Some(0), "{out}");

    let e = open(dir.path());
    assert_eq!(
        extra_permissions(&e, &seeded),
        vec!["docs.read".to_string()],
        "the purge must delete the orphaned grant and keep the declared one: {out}"
    );
    let mut query = AuditQuery::for_realm(seeded.realm.clone());
    query.action = Some(AuditAction::UserPermissionRevoked);
    let revoked = e.audit.query(&query).expect("audit query");
    assert_eq!(
        revoked.len(),
        1,
        "the purge must write one audit event per deleted grant: {revoked:?}"
    );
    assert_eq!(revoked[0].resource_id, seeded.user.as_uuid().to_string());
    assert_eq!(
        revoked[0]
            .metadata
            .as_ref()
            .and_then(|m| m.get("permission"))
            .and_then(|p| p.as_str()),
        Some("docs.archive"),
        "the audit event must name the deleted grant: {revoked:?}"
    );
}

#[test]
fn a_dry_run_purge_reports_the_orphan_and_deletes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let seeded = seed(dir.path());
    let realm = seeded.realm.as_uuid().to_string();
    let data_dir = dir.path().to_str().expect("utf-8 path");

    let (code, out) = hearth(&[
        "rbac",
        "orphans",
        "purge",
        "--realm",
        &realm,
        "--data-dir",
        data_dir,
        "--dry-run",
    ]);

    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.contains("docs.archive"),
        "a dry run must report what it would delete: {out}"
    );
    let e = open(dir.path());
    assert_eq!(
        extra_permissions(&e, &seeded),
        vec!["docs.archive".to_string(), "docs.read".to_string()],
        "a dry run must delete nothing: {out}"
    );
}
