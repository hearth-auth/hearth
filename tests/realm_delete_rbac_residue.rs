//! Audit 2026-08-28 §4.20#4: RBAC rows outliving the realm that owned them.
//!
//! The audit found three families surviving `delete_realm` — direct permission
//! grants, org extra roles, and every group-subject assignment — and reported
//! that they were silently reactivated when the same `UserId` was re-imported.
//!
//! The cascade now sweeps the realm's entire key space rather than a
//! hand-written prefix allowlist, and every RBAC write is partitioned under the
//! realm it belongs to, so all three families should go with the realm. These
//! tests hold that: they build each family, delete the realm, and then rebuild
//! the realm and the user under their original IDs to check nothing came back.

#![allow(clippy::unwrap_used)]

mod common;

use std::collections::BTreeMap;

use hearth::core::{RealmId, UserId};
use hearth::identity::{
    CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest, ImportUserRequest,
    OrganizationRole, UserStatus,
};
use hearth::rbac::{
    AssignRoleRequest, CreateGroupRequest, GroupMember, Permission, Scope, Subject,
    UserPermissionGrant,
};

/// Everything the three named families need, all under one realm.
struct RealmFixture {
    realm_id: RealmId,
    user_id: UserId,
    permission: Permission,
}

/// Builds a realm holding one direct permission grant, one org extra role, and
/// one group-subject role assignment.
fn build_realm_with_every_rbac_family(h: &common::TestHarness, slug: &str) -> RealmFixture {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: slug.to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    h.rbac().seed_realm(&realm_id).expect("seed rbac");

    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("member@{slug}.test"),
                display_name: "Member".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");
    let user_id = user.id().clone();

    // 1. A direct permission grant, held outside any role.
    let permission = Permission::new("hearth.user.read").expect("build permission");
    h.rbac()
        .grant_user_permission(
            &realm_id,
            &UserPermissionGrant {
                realm_id: realm_id.clone(),
                user_id: user_id.clone(),
                permission: permission.clone(),
                scope: Scope::Realm,
                granted_at: hearth::core::Timestamp::from_micros(1_000_000),
                granted_by: None,
            },
        )
        .expect("grant direct permission");

    // 2. An org membership carrying an extra role beyond the membership role.
    let org = h
        .identity()
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Residue Org".to_string(),
                slug: format!("{slug}-org"),
                description: None,
                config: None,
                attributes: BTreeMap::new(),
            },
        )
        .expect("create organization");
    h.identity()
        .add_member(&realm_id, org.id(), &user_id, OrganizationRole::Member)
        .expect("add org member");
    h.rbac()
        .add_additional_role(&realm_id, org.id(), &user_id, "realm.admin", None)
        .expect("add org extra role");

    // 3. A group holding the user, with a role assigned to the group itself.
    let group = h
        .rbac()
        .create_group(
            &realm_id,
            &CreateGroupRequest {
                name: "Residue Group".to_string(),
                slug: format!("{slug}-group"),
                description: None,
            },
        )
        .expect("create group");
    h.rbac()
        .add_group_member(&realm_id, &group.id, &GroupMember::User(user_id.clone()))
        .expect("add group member");
    let role = h
        .rbac()
        .get_role_by_name(&realm_id, "realm.admin")
        .expect("lookup role")
        .expect("realm.admin exists after seed");
    h.rbac()
        .assign_role(
            &realm_id,
            &AssignRoleRequest {
                subject: Subject::Group(group.id),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role to group");

    RealmFixture {
        realm_id,
        user_id,
        permission,
    }
}

/// Every `rba:` key the realm still holds, as readable strings.
fn surviving_rbac_keys(h: &common::TestHarness, realm_id: &RealmId) -> Vec<String> {
    h.storage()
        .scan(realm_id, b"rba:", b"rba;")
        .expect("scan rba: key space")
        .iter()
        .map(|e| String::from_utf8_lossy(&e.key).into_owned())
        .collect()
}

/// The three families the audit named must go with the realm's key space.
#[tokio::test]
async fn realm_deletion_removes_every_rbac_family() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let fixture = build_realm_with_every_rbac_family(&h, "residue");

    // Precondition: all three families really exist before the delete.
    let before = surviving_rbac_keys(&h, &fixture.realm_id);
    for family in ["rba:user_perm:", "rba:org_role:", "rba:assign:group:"] {
        assert!(
            before.iter().any(|k| k.starts_with(family)),
            "precondition: {family} must exist before the delete, saw {before:?}"
        );
    }

    h.archive_realm(&fixture.realm_id);
    h.identity()
        .delete_realm(&fixture.realm_id)
        .expect("delete realm");

    let after = surviving_rbac_keys(&h, &fixture.realm_id);
    assert!(
        after.is_empty(),
        "{} RBAC key(s) survived realm deletion: {after:?}",
        after.len()
    );
}

/// Re-creating the realm under its old ID and re-importing the user under its
/// old `UserId` must not resurrect anything the delete removed.
#[tokio::test]
async fn a_reimported_user_inherits_no_grant_from_the_deleted_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let fixture = build_realm_with_every_rbac_family(&h, "reimport");

    h.archive_realm(&fixture.realm_id);
    h.identity()
        .delete_realm(&fixture.realm_id)
        .expect("delete realm");

    // Rebuild the realm under its original ID, as a backup restore would.
    h.identity()
        .import_realm(
            &CreateRealmRequest {
                name: "reimport-restored".to_string(),
                config: None,
            },
            Some(fixture.realm_id.clone()),
            None,
        )
        .expect("re-import realm under its old ID");

    h.identity()
        .import_user(
            &fixture.realm_id,
            &ImportUserRequest {
                id: Some(fixture.user_id.clone()),
                email: "member@reimport.test".to_string(),
                display_name: "Member".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                status: UserStatus::Active,
                credential: None,
                attributes: BTreeMap::new(),
            },
        )
        .expect("re-import user under its old ID");

    let grants = h
        .rbac()
        .list_user_permissions(&fixture.realm_id, &fixture.user_id)
        .expect("list direct permission grants");
    assert!(
        grants.is_empty(),
        "a re-imported user must inherit no direct permission grant from the \
         deleted realm, found {grants:?}"
    );

    let resolved = h
        .rbac()
        .resolve_permissions(&fixture.user_id, &fixture.realm_id, None, None)
        .expect("resolve permissions");
    assert!(
        !resolved.permissions.contains(&fixture.permission),
        "a re-imported user must hold none of the deleted realm's permissions, \
         resolved {:?}",
        resolved.permissions
    );

    let survivors = surviving_rbac_keys(&h, &fixture.realm_id);
    let reactivated: Vec<&String> = survivors
        .iter()
        .filter(|k| {
            k.starts_with("rba:user_perm:")
                || k.starts_with("rba:org_role:")
                || k.starts_with("rba:assign:group:")
        })
        .collect();
    assert!(
        reactivated.is_empty(),
        "no RBAC row from the deleted realm may reappear: {reactivated:?}"
    );
}
