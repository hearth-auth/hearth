//! Task 26.16 (subsystem audit 2026-09-21, finding O-2) — suspending an
//! organisation must be a kill switch, not a hiring freeze.
//!
//! `templates/ui/admin/organizations/edit.html` told the operator that
//! `Suspended` means "members are blocked from signing in via this org" — the
//! only written statement of what the status does anywhere in the repo. At
//! HEAD `OrganizationStatus` was consulted in exactly two engine functions —
//! `add_member` and `create_invitation` — so a suspended organisation kept
//! minting org-context tokens and kept answering `allowed: true` for its
//! org-scoped permissions. Everything a member already had continued to work;
//! only *new* members and *new* invitations were stopped.
//!
//! The rule these tests pin:
//!   * token issuance in a non-Active org context is refused outright;
//!   * live RBAC resolution in a non-Active org context drops the org
//!     context, so org-scoped authority evaporates while realm-scoped
//!     authority is untouched;
//!   * realm-scoped issuance is never affected by an org's status.

mod common;

use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::identity::{
    CreateOrganizationRequest, CreateUserRequest, DecidePermissionRequest, IdentityError,
    OrganizationConfig, OrganizationRole, OrganizationStatus, SessionContext, TokenIssuanceContext,
    UpdateOrganizationRequest,
};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

fn perms(list: &[&str]) -> Vec<Permission> {
    list.iter()
        .map(|p| Permission::new(*p).expect("valid perm"))
        .collect()
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
                display_name: "Member".into(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone()
}

fn set_status(
    h: &common::TestHarness,
    realm: &RealmId,
    org: &OrganizationId,
    status: OrganizationStatus,
) {
    h.identity()
        .update_organization(
            realm,
            org,
            &UpdateOrganizationRequest {
                status: Some(status),
                ..Default::default()
            },
        )
        .expect("update org status");
}

// ---------------------------------------------------------------------------
// Token issuance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn suspended_org_blocks_token_issuance_in_that_org_context() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let org = make_org(&h, &realm, "acme-suspend-token");
    let user = make_user(&h, &realm);
    h.identity()
        .add_member(&realm, &org, &user, OrganizationRole::Member)
        .expect("add member");
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("create session")
        .id()
        .clone();

    // Precondition: the org context issues fine while Active.
    h.identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            &session,
            &TokenIssuanceContext {
                oid: Some(org.to_string()),
                ..Default::default()
            },
        )
        .expect("active org issues");

    set_status(&h, &realm, &org, OrganizationStatus::Suspended);

    let err = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            &session,
            &TokenIssuanceContext {
                oid: Some(org.to_string()),
                ..Default::default()
            },
        )
        .expect_err("suspended org must not mint an org-context token");
    assert!(
        matches!(err, IdentityError::OrganizationSuspended),
        "expected OrganizationSuspended, got {err}"
    );
}

#[tokio::test]
async fn archived_org_blocks_token_issuance_in_that_org_context() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let org = make_org(&h, &realm, "acme-archived-token");
    let user = make_user(&h, &realm);
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("create session")
        .id()
        .clone();

    set_status(&h, &realm, &org, OrganizationStatus::Archived);

    let err = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            &session,
            &TokenIssuanceContext {
                oid: Some(org.to_string()),
                ..Default::default()
            },
        )
        .expect_err("archived org must not mint an org-context token");
    assert!(
        matches!(err, IdentityError::OrganizationSuspended),
        "expected OrganizationSuspended, got {err}"
    );
}

#[tokio::test]
async fn suspended_org_does_not_block_realm_scoped_token_issuance() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let org = make_org(&h, &realm, "acme-suspend-realm-scope");
    let user = make_user(&h, &realm);
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("create session")
        .id()
        .clone();

    set_status(&h, &realm, &org, OrganizationStatus::Suspended);

    // No `oid` — nothing about this token is org-scoped, so the suspension
    // must not reach it. A kill switch that logs everyone out of the realm
    // would be a different (and wrong) control.
    h.identity()
        .issue_tokens_with_context(&realm, &user, &session, &TokenIssuanceContext::default())
        .expect("realm-scoped issuance must be unaffected by an org suspension");
}

// ---------------------------------------------------------------------------
// Live RBAC decisions
// ---------------------------------------------------------------------------

/// Grants `user` a realm-wide role and an org-scoped extra role, then returns
/// an access token with no org context (so the decision endpoint's org
/// parameter is the only thing under test).
fn seed_decision_fixture(
    h: &common::TestHarness,
    realm: &RealmId,
    org: &OrganizationId,
    user: &UserId,
) -> String {
    h.rbac()
        .create_role(
            realm,
            &CreateRoleRequest {
                name: "realm-reader".into(),
                description: None,
                permissions: perms(&["docs.read"]),
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create realm role");
    let org_role = h
        .rbac()
        .create_role(
            realm,
            &CreateRoleRequest {
                name: "org-writer".into(),
                description: None,
                permissions: perms(&["docs.write"]),
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create org role");
    let _ = org_role;
    let realm_role = h
        .rbac()
        .get_role_by_name(realm, "realm-reader")
        .expect("get role")
        .expect("role exists");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: realm_role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign realm role");
    h.identity()
        .add_member(realm, org, user, OrganizationRole::Member)
        .expect("add member");
    h.rbac()
        .add_additional_role(realm, org, user, "org-writer", None)
        .expect("grant org extra role");

    let session = h
        .identity()
        .create_session(realm, user, &SessionContext::default())
        .expect("create session")
        .id()
        .clone();
    h.identity()
        .issue_tokens_with_context(realm, user, &session, &TokenIssuanceContext::default())
        .expect("issue token")
        .access_token()
        .to_string()
}

fn decide(h: &common::TestHarness, realm: &RealmId, token: &str, perm: &str, org: &str) -> bool {
    h.identity()
        .decide_token_permission(
            realm,
            &DecidePermissionRequest {
                token: token.to_string(),
                permission: perm.to_string(),
                organization_id: Some(org.to_string()),
                resource: None,
            },
        )
        .expect("decide")
        .allowed
}

#[tokio::test]
async fn suspended_org_strips_org_scoped_authority_from_the_decision_endpoint() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let org = make_org(&h, &realm, "acme-decide");
    let user = make_user(&h, &realm);
    let token = seed_decision_fixture(&h, &realm, &org, &user);
    let org_str = org.to_string();

    // Precondition: while Active the org-scoped role decides true.
    assert!(
        decide(&h, &realm, &token, "docs.write", &org_str),
        "precondition: an active org must grant its org-scoped permission"
    );

    set_status(&h, &realm, &org, OrganizationStatus::Suspended);

    assert!(
        !decide(&h, &realm, &token, "docs.write", &org_str),
        "a suspended org must not keep granting its org-scoped permission"
    );
    // Realm-scoped authority is untouched: suspension kills the org, not the
    // member's account.
    assert!(
        decide(&h, &realm, &token, "docs.read", &org_str),
        "realm-scoped permissions must survive an org suspension"
    );
}

// ---------------------------------------------------------------------------
// Membership mutations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn suspended_org_blocks_member_role_changes() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let org = make_org(&h, &realm, "acme-role-change");
    let user = make_user(&h, &realm);
    h.identity()
        .add_member(&realm, &org, &user, OrganizationRole::Member)
        .expect("add member");

    set_status(&h, &realm, &org, OrganizationStatus::Suspended);

    let err = h
        .identity()
        .update_member_role(&realm, &org, &user, OrganizationRole::Owner)
        .expect_err("promoting inside a suspended org must be refused");
    assert!(
        matches!(err, IdentityError::OrganizationSuspended),
        "expected OrganizationSuspended, got {err}"
    );

    // Removing a member stays possible: an operator must still be able to
    // offboard people from a frozen tenant.
    h.identity()
        .remove_member(&realm, &org, &user)
        .expect("remove_member must remain available while suspended");
}
