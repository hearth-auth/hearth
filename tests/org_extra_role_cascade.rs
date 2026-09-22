//! Task 26.15 (subsystem audit 2026-09-21, finding O-1) — `rba:org_role:` rows
//! must not outlive the membership, the organisation, or the user they were
//! granted against.
//!
//! The defect: `add_additional_role` writes
//! `rba:org_role:{realm}:{org}:{user}:{role}`, `resolve_full` expands every
//! such row it finds for `(realm, org, user)` with no membership check, and
//! **no** cleanup path deleted them — not `remove_member`, not
//! `delete_organization`, not `purge_user_from_realm` (and therefore not
//! `delete_user` or realm deletion). Re-adding an offboarded contractor
//! silently restored every extra role they had held.

mod common;

use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::identity::{
    CreateOrganizationRequest, CreateUserRequest, OrganizationConfig, OrganizationRole,
};
use hearth::rbac::{CreateRoleRequest, Permission};

fn perms(list: &[&str]) -> Vec<Permission> {
    list.iter()
        .map(|p| Permission::new(*p).expect("valid perm"))
        .collect()
}

/// Creates a realm-level role the extra-role rows can reference.
fn make_role(h: &common::TestHarness, realm: &RealmId, name: &str, perm_names: &[&str]) {
    h.rbac()
        .create_role(
            realm,
            &CreateRoleRequest {
                name: name.to_string(),
                description: None,
                permissions: perms(perm_names),
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role");
}

fn make_org(h: &common::TestHarness, realm: &RealmId, slug: &str) -> OrganizationId {
    h.identity()
        .create_organization(
            realm,
            &CreateOrganizationRequest {
                name: slug.to_string(),
                slug: slug.to_string(),
                description: None,
                config: Some(OrganizationConfig { max_members: None }),
                ..Default::default()
            },
        )
        .expect("create org")
        .id()
        .clone()
}

fn make_user(h: &common::TestHarness, realm: &RealmId) -> UserId {
    h.identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("member-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Contractor".into(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone()
}

// ---------------------------------------------------------------------------
// remove_member
// ---------------------------------------------------------------------------

#[tokio::test]
async fn remove_member_purges_org_extra_roles() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let org = make_org(&h, &realm, "acme-remove");
    let a = make_user(&h, &realm);
    let b = make_user(&h, &realm);
    make_role(&h, &realm, "billing-admin", &["billing.write"]);

    for u in [&a, &b] {
        h.identity()
            .add_member(&realm, &org, u, OrganizationRole::Owner)
            .expect("add member");
        h.rbac()
            .add_additional_role(&realm, &org, u, "billing-admin", None)
            .expect("grant extra role");
    }

    h.identity()
        .remove_member(&realm, &org, &a)
        .expect("remove member");

    assert!(
        h.rbac()
            .list_additional_roles(&realm, &org, &a)
            .expect("list")
            .is_empty(),
        "removed member must not keep org extra roles"
    );
    // The *other* member's rows must survive: the purge is scoped to one user.
    assert_eq!(
        h.rbac()
            .list_additional_roles(&realm, &org, &b)
            .expect("list"),
        vec!["billing-admin".to_string()],
        "purge must not touch a different member's extra roles"
    );
}

#[tokio::test]
async fn re_added_member_does_not_regain_removed_org_extra_roles() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let org = make_org(&h, &realm, "acme-readd");
    let user = make_user(&h, &realm);
    make_role(&h, &realm, "billing-admin", &["billing.write"]);

    h.identity()
        .add_member(&realm, &org, &user, OrganizationRole::Member)
        .expect("add member");
    h.rbac()
        .add_additional_role(&realm, &org, &user, "billing-admin", None)
        .expect("grant extra role");

    let billing = Permission::new("billing.write").expect("perm");
    let before = h
        .rbac()
        .resolve_permissions(&user, &realm, Some(&org), None)
        .expect("resolve");
    assert!(
        before.permissions.contains(&billing),
        "precondition: the extra role must grant billing.write while a member"
    );

    // Offboard, then re-hire as a plain Member months later.
    h.identity()
        .remove_member(&realm, &org, &user)
        .expect("remove member");
    h.identity()
        .add_member(&realm, &org, &user, OrganizationRole::Member)
        .expect("re-add member");

    let after = h
        .rbac()
        .resolve_permissions(&user, &realm, Some(&org), None)
        .expect("resolve");
    assert!(
        !after.permissions.contains(&billing),
        "a re-added member must not silently regain billing.write; got {:?}",
        after.permissions
    );
}

// ---------------------------------------------------------------------------
// delete_organization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_organization_purges_org_extra_roles() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let org = make_org(&h, &realm, "acme-delete");
    let member = make_user(&h, &realm);
    let stranger = make_user(&h, &realm);
    make_role(&h, &realm, "billing-admin", &["billing.write"]);

    h.identity()
        .add_member(&realm, &org, &member, OrganizationRole::Owner)
        .expect("add member");
    h.rbac()
        .add_additional_role(&realm, &org, &member, "billing-admin", None)
        .expect("grant extra role");
    // An orphan row for a non-member: the cascade must sweep the whole org,
    // not just the users it finds in the membership index.
    h.rbac()
        .add_additional_role(&realm, &org, &stranger, "billing-admin", None)
        .expect("grant orphan extra role");

    h.identity()
        .delete_organization(&realm, &org)
        .expect("delete org");

    for u in [&member, &stranger] {
        assert!(
            h.rbac()
                .list_additional_roles(&realm, &org, u)
                .expect("list")
                .is_empty(),
            "deleting an organisation must sweep every org extra role row"
        );
    }
}

// ---------------------------------------------------------------------------
// delete_user / purge_user_from_realm
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_user_purges_org_extra_roles_in_every_org() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let org_a = make_org(&h, &realm, "acme-a");
    let org_b = make_org(&h, &realm, "acme-b");
    let user = make_user(&h, &realm);
    let survivor = make_user(&h, &realm);
    make_role(&h, &realm, "billing-admin", &["billing.write"]);

    for org in [&org_a, &org_b] {
        h.identity()
            .add_member(&realm, org, &user, OrganizationRole::Owner)
            .expect("add member");
        h.identity()
            .add_member(&realm, org, &survivor, OrganizationRole::Owner)
            .expect("add survivor");
        h.rbac()
            .add_additional_role(&realm, org, &user, "billing-admin", None)
            .expect("grant extra role");
        h.rbac()
            .add_additional_role(&realm, org, &survivor, "billing-admin", None)
            .expect("grant survivor extra role");
    }

    h.identity()
        .delete_user(&realm, &user)
        .expect("delete user");

    for org in [&org_a, &org_b] {
        assert!(
            h.rbac()
                .list_additional_roles(&realm, org, &user)
                .expect("list")
                .is_empty(),
            "deleting a user must sweep their org extra roles in every org"
        );
        assert_eq!(
            h.rbac()
                .list_additional_roles(&realm, org, &survivor)
                .expect("list"),
            vec!["billing-admin".to_string()],
            "the realm-wide sweep must not touch another user's rows"
        );
    }
}
