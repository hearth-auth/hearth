//! Registry hygiene (`scope-consent-integrity` design §4).
//!
//! Effective-permission resolution is the single enforcement point for a
//! registry entry that YAML no longer defines: a permission or role removed
//! from `hearth.yaml` is archived, and resolution skips it and reports it as
//! an orphan. A bundle removed from YAML is deleted. Scenarios from
//! `custom-permissions` "Registry reload is lazy and non-destructive".

mod common;

use std::collections::{BTreeSet, HashSet};

use hearth::audit::{AuditAction, AuditQuery};
use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::identity::{
    CreateOrganizationRequest, CreateUserRequest, OrganizationConfig, OrganizationRole,
    SessionContext, TokenIssuanceContext,
};
use hearth::rbac::{
    AssignRoleRequest, CreateRoleRequest, OrphanKind, Permission, RoleScopeKind, RoleSpec, Scope,
    ScopeSpec, Subject, UserPermissionGrant,
};

fn perm(name: &str) -> Permission {
    Permission::new(name).expect("valid permission")
}

fn names(set: &[Permission]) -> Vec<&str> {
    set.iter().map(Permission::as_str).collect()
}

fn make_user(h: &common::TestHarness, realm: &RealmId) -> UserId {
    h.identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Registry User".into(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone()
}

fn yaml_names(list: &[&str]) -> HashSet<String> {
    list.iter().map(|s| (*s).to_string()).collect()
}

/// A realm whose YAML declares `docs.read` and `docs.archive`.
fn realm_with_docs_permissions(h: &common::TestHarness) -> RealmId {
    let realm = h.create_realm();
    h.rbac()
        .reconcile_permissions(&realm, &["docs.read".into(), "docs.archive".into()])
        .expect("reconcile permissions");
    realm
}

#[tokio::test]
async fn a_permission_removed_from_yaml_leaves_role_grants() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm_with_docs_permissions(&h);
    let user = make_user(&h, &realm);
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "docs-keeper".into(),
                description: None,
                permissions: vec![perm("docs.read"), perm("docs.archive")],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");

    h.rbac()
        .archive_removed_permissions(&realm, &yaml_names(&["docs.read"]))
        .expect("archive");

    let resolved = h
        .rbac()
        .resolve_permissions(&user, &realm, None, None)
        .expect("resolve");
    assert_eq!(names(&resolved.permissions), vec!["docs.read"]);
    assert!(
        resolved
            .orphans
            .iter()
            .any(|o| o.kind == OrphanKind::Permission && o.reference == "docs.archive"),
        "the skipped permission is reported as an orphan: {:?}",
        resolved.orphans
    );
}

#[tokio::test]
async fn an_extra_permission_ends_with_its_registry_entry() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm_with_docs_permissions(&h);
    let user = make_user(&h, &realm);
    h.rbac()
        .grant_user_permission(
            &realm,
            &UserPermissionGrant {
                realm_id: realm.clone(),
                user_id: user.clone(),
                permission: perm("docs.archive"),
                scope: Scope::Realm,
                granted_at: hearth::core::Timestamp::now(),
                granted_by: None,
            },
        )
        .expect("grant extra");

    h.rbac()
        .archive_removed_permissions(&realm, &yaml_names(&["docs.read"]))
        .expect("archive");

    let resolved = h
        .rbac()
        .resolve_permissions(&user, &realm, None, None)
        .expect("resolve");
    assert!(
        !names(&resolved.permissions).contains(&"docs.archive"),
        "an archived extra permission is not granted: {:?}",
        resolved.permissions
    );
}

#[tokio::test]
async fn a_permission_never_registered_is_still_granted() {
    // A realm created at runtime has no YAML vocabulary. Its roles name
    // permissions that have no registry record, and those stay granted.
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    let user = make_user(&h, &realm);
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "runtime-role".into(),
                description: None,
                permissions: vec![perm("ledger.read")],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");

    let resolved = h
        .rbac()
        .resolve_permissions(&user, &realm, None, None)
        .expect("resolve");
    assert_eq!(names(&resolved.permissions), vec!["ledger.read"]);
    assert!(resolved.orphans.is_empty(), "{:?}", resolved.orphans);
}

#[tokio::test]
async fn an_archived_role_grants_nothing() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm_with_docs_permissions(&h);
    let user = make_user(&h, &realm);
    h.rbac()
        .reconcile_roles(
            &realm,
            &[RoleSpec {
                name: "docs-reader".into(),
                description: None,
                permissions: vec!["docs.read".into()],
                parent_names: vec![],
                scope_kind: RoleScopeKind::Realm,
            }],
        )
        .expect("reconcile roles");
    let role = h
        .rbac()
        .get_role_by_name(&realm, "docs-reader")
        .expect("lookup")
        .expect("role exists");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");

    h.rbac()
        .archive_removed_roles(&realm, &HashSet::new())
        .expect("archive roles");

    let resolved = h
        .rbac()
        .resolve_permissions(&user, &realm, None, None)
        .expect("resolve");
    assert!(
        resolved.permissions.is_empty(),
        "an archived role grants nothing: {:?}",
        resolved.permissions
    );
    assert!(
        resolved
            .orphans
            .iter()
            .any(|o| o.kind == OrphanKind::Role && o.reference == "docs-reader"),
        "{:?}",
        resolved.orphans
    );
}

fn scope_names(h: &common::TestHarness, realm: &RealmId) -> HashSet<String> {
    h.rbac()
        .export_all_scopes(realm)
        .expect("export scopes")
        .into_iter()
        .map(|s| s.name)
        .collect()
}

#[tokio::test]
async fn a_bundle_removed_from_yaml_is_deleted() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm_with_docs_permissions(&h);
    h.rbac().seed_realm(&realm).expect("seed");
    h.rbac()
        .reconcile_scopes(
            &realm,
            &[ScopeSpec {
                name: "read:docs".into(),
                permissions: Some(vec!["docs.read".into()]),
            }],
        )
        .expect("reconcile scopes");
    assert!(scope_names(&h, &realm).contains("read:docs"));

    h.rbac()
        .reconcile_scopes(&realm, &[])
        .expect("reconcile without the bundle");

    let left = scope_names(&h, &realm);
    assert!(
        !left.contains("read:docs"),
        "a bundle removed from YAML is deleted: {left:?}"
    );
    assert!(
        left.contains("admin"),
        "a seeded bare-word scope is not a YAML bundle and stays: {left:?}"
    );
}

fn make_org(h: &common::TestHarness, realm: &RealmId) -> OrganizationId {
    h.identity()
        .create_organization(
            realm,
            &CreateOrganizationRequest {
                name: "acme".into(),
                slug: "acme".into(),
                description: None,
                config: Some(OrganizationConfig::default()),
                ..Default::default()
            },
        )
        .expect("create org")
        .id()
        .clone()
}

#[tokio::test]
async fn a_skipped_orphan_reference_is_audited() {
    // Scenario "A skipped orphan reference is audited".
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    let org = make_org(&h, &realm);
    let user = make_user(&h, &realm);
    // The role comes from YAML; the operator later removes it, so it is
    // archived while the membership still names it.
    h.rbac()
        .reconcile_permissions(&realm, &["billing.write".into()])
        .expect("reconcile permissions");
    h.rbac()
        .reconcile_roles(
            &realm,
            &[RoleSpec {
                name: "billing-admin".into(),
                description: None,
                permissions: vec!["billing.write".into()],
                parent_names: vec![],
                scope_kind: RoleScopeKind::Organization,
            }],
        )
        .expect("reconcile roles");
    h.identity()
        .add_member(&realm, &org, &user, OrganizationRole::Member)
        .expect("add member");
    h.rbac()
        .add_additional_role(&realm, &org, &user, "billing-admin", None)
        .expect("grant extra role");
    h.rbac()
        .archive_removed_roles(&realm, &HashSet::new())
        .expect("archive roles");

    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let ctx = TokenIssuanceContext {
        oid: Some(org.to_string()),
        granted_scopes: BTreeSet::new(),
        ..Default::default()
    };
    for _ in 0..2 {
        h.identity()
            .issue_tokens_with_context(&realm, &user, session.id(), &ctx)
            .expect("issue in org");
    }

    let events = h
        .audit()
        .query(&AuditQuery::for_realm(realm.clone()))
        .expect("audit query");
    let orphan_events = events
        .iter()
        .filter(|e| e.action == AuditAction::OrphanedReferenceSkipped)
        .count();
    assert_eq!(
        orphan_events, 1,
        "two issuances within the hour record one OrphanedReferenceSkipped"
    );
}

#[tokio::test]
async fn the_orphan_summary_lists_every_skipped_reference() {
    // Startup logs a summary of these (custom-permissions "Registry reload is
    // lazy and non-destructive").
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm_with_docs_permissions(&h);
    let user = make_user(&h, &realm);
    h.rbac()
        .reconcile_roles(
            &realm,
            &[RoleSpec {
                name: "docs-reader".into(),
                description: None,
                permissions: vec!["docs.read".into()],
                parent_names: vec![],
                scope_kind: RoleScopeKind::Realm,
            }],
        )
        .expect("reconcile roles");
    let role = h
        .rbac()
        .get_role_by_name(&realm, "docs-reader")
        .expect("lookup")
        .expect("role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign");
    h.rbac()
        .grant_user_permission(
            &realm,
            &UserPermissionGrant {
                realm_id: realm.clone(),
                user_id: user.clone(),
                permission: perm("docs.archive"),
                scope: Scope::Realm,
                granted_at: hearth::core::Timestamp::now(),
                granted_by: None,
            },
        )
        .expect("grant extra");

    h.rbac()
        .archive_removed_roles(&realm, &HashSet::new())
        .expect("archive roles");
    h.rbac()
        .archive_removed_permissions(&realm, &yaml_names(&["docs.read"]))
        .expect("archive permissions");

    let orphans = h.rbac().orphaned_references(&realm).expect("summary");
    let has = |kind: OrphanKind, reference: &str| {
        orphans
            .iter()
            .any(|o| o.kind == kind && o.reference == reference)
    };
    assert!(has(OrphanKind::Role, "docs-reader"), "{orphans:?}");
    assert!(has(OrphanKind::Permission, "docs.archive"), "{orphans:?}");
}
