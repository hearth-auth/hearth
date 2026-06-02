//! Integration tests for HEA-909: org-scoped group paths in OIDC token claims.
//!
//! Verifies that tokens issued in an organization context carry both:
//! - `groups`: flat RBAC group slugs (backward compat)
//! - `org_groups`: `/org-slug/group-name` paths for multi-org tenancy

mod common;

use hearth::identity::{
    CreateOrganizationRequest, CreateUserRequest, OrganizationConfig, SessionContext,
    TokenIssuanceContext,
};
use hearth::rbac::{
    AssignRoleRequest, CreateGroupRequest, CreateRoleRequest, GroupMember, Scope, Subject,
};
use std::collections::BTreeSet;

// ===== Integration Scenario: tokens in org context carry org-scoped group paths =====

#[tokio::test]
async fn org_context_token_emits_org_groups_paths() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    // Create an organization with a known slug.
    let org = h
        .identity()
        .create_organization(
            &realm,
            &CreateOrganizationRequest {
                name: "Acme Corp".to_string(),
                slug: "acme-corp".to_string(),
                description: None,
                config: Some(OrganizationConfig { max_members: None }),
                ..Default::default()
            },
        )
        .expect("create org");

    // Create a user and put them in two RBAC groups.
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Alice".into(),
                first_name: "Alice".into(),
                last_name: "Smith".into(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let group_admins = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "Admins".into(),
                slug: "admins".into(),
                description: None,
            },
        )
        .expect("create admins group");

    let group_devs = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "Developers".into(),
                slug: "developers".into(),
                description: None,
            },
        )
        .expect("create developers group");

    h.rbac()
        .add_group_member(
            &realm,
            &group_admins.id,
            &GroupMember::User(user.id().clone()),
        )
        .expect("add to admins");
    h.rbac()
        .add_group_member(
            &realm,
            &group_devs.id,
            &GroupMember::User(user.id().clone()),
        )
        .expect("add to devs");

    // Attach a role so permissions resolve (not strictly required for this test,
    // but makes the group membership show up in resolved.groups).
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "viewer".into(),
                description: None,
                permissions: vec![],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::Group(group_admins.id.clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");

    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");

    // Issue token WITHOUT org context — org_groups must be absent.
    let pair_no_org = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            user.id(),
            session.id(),
            &TokenIssuanceContext::default(),
        )
        .expect("issue tokens no org");

    let claims_no_org = h
        .identity()
        .validate_token(&realm, pair_no_org.access_token())
        .expect("validate no-org token");

    assert!(
        claims_no_org.org_groups.is_empty(),
        "no org_groups without org context; got: {:?}",
        claims_no_org.org_groups
    );
    assert!(
        !claims_no_org.groups.is_empty(),
        "flat groups must still be present without org context"
    );

    // Issue token WITH org context — org_groups must carry /org-slug/group-name paths.
    let pair_with_org = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            user.id(),
            session.id(),
            &TokenIssuanceContext {
                oid: Some(org.id().to_string()),
                granted_scopes: BTreeSet::new(),
                client_id: None,
                resource: None,
            },
        )
        .expect("issue tokens with org");

    let claims = h
        .identity()
        .validate_token(&realm, pair_with_org.access_token())
        .expect("validate org token");

    // Flat groups unchanged (backward compat).
    assert!(
        claims.groups.contains(&"admins".to_string()),
        "flat groups must still contain 'admins'; got: {:?}",
        claims.groups
    );
    assert!(
        claims.groups.contains(&"developers".to_string()),
        "flat groups must still contain 'developers'; got: {:?}",
        claims.groups
    );

    // Org-scoped paths present.
    assert!(
        claims.org_groups.contains(&"/acme-corp/admins".to_string()),
        "org_groups must contain '/acme-corp/admins'; got: {:?}",
        claims.org_groups
    );
    assert!(
        claims
            .org_groups
            .contains(&"/acme-corp/developers".to_string()),
        "org_groups must contain '/acme-corp/developers'; got: {:?}",
        claims.org_groups
    );

    // org_groups count matches groups count.
    assert_eq!(
        claims.groups.len(),
        claims.org_groups.len(),
        "org_groups and groups must have the same cardinality"
    );
}

// ===== Flat groups preserved for non-org tokens (backward compat) =====

#[tokio::test]
async fn non_org_token_has_no_org_groups() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("user2-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Bob".into(),
                first_name: "Bob".into(),
                last_name: "Jones".into(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");

    let pair = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    let claims = h
        .identity()
        .validate_token(&realm, pair.access_token())
        .expect("validate");

    assert!(
        claims.org_groups.is_empty(),
        "org_groups must be absent on non-org token"
    );
}
