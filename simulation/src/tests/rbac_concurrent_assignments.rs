//! Concurrent role-assignment writes.
//!
//! Oracle invariant: concurrent role-assignment writes produce no data
//! corruption — after quiescence, `resolve_permissions` returns a set
//! consistent with some serializable order of the ops, with no partial
//! index writes or dangling assignments.
//!
//! Uses `std::thread::spawn` (like `realm_concurrent_io.rs`) to avoid
//! pulling tokio into the simulation crate's dependency footprint.

use std::sync::Arc;

use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::rbac::{
    AssignRoleRequest, AssignmentId, CreateRoleRequest, EmbeddedRbacEngine, Permission, RbacEngine,
    RoleId, Scope, Subject,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

fn perms(list: &[&str]) -> Vec<Permission> {
    list.iter()
        .map(|p| Permission::new(*p).expect("valid"))
        .collect()
}

fn open() -> (Arc<dyn RbacEngine>, RealmId) {
    let dir = tempfile::tempdir().expect("tmp");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage =
        Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let rbac =
        Arc::new(EmbeddedRbacEngine::new(Arc::clone(&storage), clock)) as Arc<dyn RbacEngine>;
    let realm = RealmId::generate();
    // Leak tempdir so storage handles stay valid beyond the caller.
    std::mem::forget(dir);
    (rbac, realm)
}

#[test]
fn concurrent_assign_unassign_converge_to_consistent_set() {
    let (rbac, realm) = open();

    // Pre-seed 4 distinct roles (serial).
    let mut roles: Vec<RoleId> = Vec::new();
    for i in 0..4 {
        let r = rbac
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: format!("r{i}"),
                    description: None,
                    permissions: perms(&[&format!("p.r{i}")]),
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("create role");
        roles.push(r.id);
    }

    let user = UserId::generate();

    // Concurrent assigns.
    let mut assign_handles = Vec::new();
    for role_id in roles.iter().cloned() {
        let rbac = Arc::clone(&rbac);
        let realm = realm.clone();
        let user = user.clone();
        assign_handles.push(std::thread::spawn(move || {
            rbac.assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user),
                    role_id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign ok")
        }));
    }

    // Concurrent resolves alongside the writes — must not panic or tear. Each
    // resolve returns its observed permission names so we can assert (post-join)
    // that every in-race snapshot was a *consistent subset* of the legal set
    // {p.r0..p.r3} — never a torn/dangling permission from a half-applied index
    // write. The previous `let _ = ...` discarded these, so the in-race resolve
    // was a no-op that only checked "did not panic".
    let mut resolve_handles = Vec::new();
    for _ in 0..8 {
        let rbac = Arc::clone(&rbac);
        let realm = realm.clone();
        let user = user.clone();
        resolve_handles.push(std::thread::spawn(move || {
            rbac.resolve_permissions(&user, &realm, None, None)
                .expect("resolve ok")
                .permissions
                .iter()
                .map(|p| p.as_str().to_string())
                .collect::<Vec<_>>()
        }));
    }

    let assigned: Vec<_> = assign_handles
        .into_iter()
        .map(|h| h.join().expect("thread join"))
        .collect();
    let legal: std::collections::HashSet<String> = (0..4).map(|i| format!("p.r{i}")).collect();
    for h in resolve_handles {
        let observed = h.join().expect("thread join");
        for name in &observed {
            assert!(
                legal.contains(name),
                "in-race resolve returned an illegal/torn permission {name:?}; \
                 legal set is {legal:?}"
            );
        }
    }

    // Post-quiescence: all four permissions visible.
    let resolved = rbac
        .resolve_permissions(&user, &realm, None, None)
        .expect("final resolve");
    let names: Vec<&str> = resolved
        .permissions
        .iter()
        .map(Permission::as_str)
        .collect();
    assert_eq!(names.len(), 4, "expected 4 perms; got {names:?}");
    for i in 0..4 {
        let want = format!("p.r{i}");
        assert!(names.contains(&want.as_str()), "missing {want}");
    }

    // Concurrent unassign — converge to empty.
    let mut unassign_handles = Vec::new();
    for a in assigned {
        let rbac = Arc::clone(&rbac);
        let realm = realm.clone();
        let id: AssignmentId = a.id;
        unassign_handles.push(std::thread::spawn(move || {
            rbac.unassign_role(&realm, &id).expect("unassign ok");
        }));
    }
    for h in unassign_handles {
        h.join().expect("thread join");
    }

    let resolved = rbac
        .resolve_permissions(&user, &realm, None, None)
        .expect("final resolve after unassign");
    assert!(
        resolved.permissions.is_empty(),
        "expected empty post-unassign set; got {resolved:?}"
    );
    assert!(
        resolved.roles.is_empty(),
        "no dangling roles should remain after unassign"
    );
}

/// Same-key contention. The test above races assigns over four *distinct*
/// roles, so no two writers touch the same assignment key — the A-28 write-lock
/// + idempotency path (`engine.rs`: "if this exact (subject, role, scope)
/// already exists, return it without creating a duplicate") is never exercised.
/// Here eight threads race to assign the *same* role to the *same* user at the
/// same scope; the invariant is that exactly one assignment record survives (no
/// lost update, no duplicate index entries, no torn resolve).
#[test]
fn concurrent_same_role_assign_is_idempotent() {
    let (rbac, realm) = open();

    let role = rbac
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "shared".to_string(),
                description: None,
                permissions: perms(&["p.shared"]),
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role");

    let user = UserId::generate();

    let mut handles = Vec::new();
    for _ in 0..8 {
        let rbac = Arc::clone(&rbac);
        let realm = realm.clone();
        let user = user.clone();
        let role_id = role.id.clone();
        handles.push(std::thread::spawn(move || {
            rbac.assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user),
                    role_id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("idempotent assign must succeed under contention")
        }));
    }

    // Every winner must observe the *same* assignment id — idempotency collapses
    // all eight racers onto one record rather than minting eight.
    let ids: std::collections::HashSet<AssignmentId> = handles
        .into_iter()
        .map(|h| h.join().expect("thread join").id)
        .collect();
    assert_eq!(
        ids.len(),
        1,
        "concurrent same-(subject,role,scope) assigns must yield exactly one \
         assignment record, got {} distinct ids",
        ids.len()
    );

    // Resolve must show the single permission exactly once and one effective role.
    let resolved = rbac
        .resolve_permissions(&user, &realm, None, None)
        .expect("resolve");
    let names: Vec<&str> = resolved
        .permissions
        .iter()
        .map(Permission::as_str)
        .collect();
    assert_eq!(
        names,
        ["p.shared"],
        "same-role contention must resolve to exactly one permission, got {names:?}"
    );
    assert_eq!(
        resolved.roles.len(),
        1,
        "same-role contention must leave exactly one effective role, got {:?}",
        resolved.roles
    );
}
