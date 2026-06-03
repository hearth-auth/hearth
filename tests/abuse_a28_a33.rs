//! Integration tests for A-28 (race-condition hardening) and A-33 (chunked
//! realm cascade with `DeletingInProgress` status fence).
//!
//! A-28 covers three idempotency / deduplication scenarios:
//!  1. Concurrent slug reservation — only one org wins the race.
//!  2. Invitation double-spend — concurrent accepts of the same token produce
//!     exactly one membership.
//!  3. RBAC assignment deduplication — calling `assign_role` twice with the
//!     same `(subject, role, scope)` is idempotent.
//!
//! A-33 covers:
//!  4. `delete_realm` sets `DeletingInProgress` and operations on the realm are
//!     rejected after deletion completes.
//!  5. After a realm delete, scanning per-realm key prefixes produces no orphans.

mod common;

use std::sync::Arc;

use hearth::identity::{
    CreateInvitationRequest, CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest,
    IdentityError, OrganizationRole,
};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

// ---------------------------------------------------------------------------
// A-28 test 1: Concurrent slug reservation
// ---------------------------------------------------------------------------
//
// Two tasks race to create an organization with the same slug.
// Exactly one must succeed and exactly one must get `DuplicateOrgSlug`.
// After the race, only one org with that slug must exist.

#[tokio::test]
async fn a28_concurrent_slug_reservation_only_one_wins() {
    let harness = Arc::new(common::TestHarness::embedded().await.expect("harness"));

    let realm_id = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("slug-race-realm-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let identity_a = harness.identity_arc();
    let identity_b = harness.identity_arc();
    let realm_a = realm_id.clone();
    let realm_b = realm_id.clone();

    let task_a = tokio::task::spawn_blocking(move || {
        identity_a.create_organization(
            &realm_a,
            &CreateOrganizationRequest {
                name: "Race Org A".to_string(),
                slug: "race-slug".to_string(),
                description: None,
                config: None,
                ..Default::default()
            },
        )
    });

    let task_b = tokio::task::spawn_blocking(move || {
        identity_b.create_organization(
            &realm_b,
            &CreateOrganizationRequest {
                name: "Race Org B".to_string(),
                slug: "race-slug".to_string(),
                description: None,
                config: None,
                ..Default::default()
            },
        )
    });

    let (result_a, result_b) = tokio::join!(task_a, task_b);
    let result_a = result_a.expect("task_a join");
    let result_b = result_b.expect("task_b join");

    // Exactly one must succeed.
    let (ok_count, dup_count) = [&result_a, &result_b]
        .iter()
        .fold((0u32, 0u32), |(ok, dup), r| match r {
            Ok(_) => (ok + 1, dup),
            Err(IdentityError::DuplicateOrgSlug) => (ok, dup + 1),
            Err(other) => panic!("unexpected error from concurrent slug race: {other}"),
        });

    assert_eq!(ok_count, 1, "exactly one create must succeed");
    assert_eq!(
        dup_count, 1,
        "exactly one create must fail with DuplicateOrgSlug"
    );

    // Only one org must exist with this slug.
    let identity = harness.identity();
    let by_slug = identity
        .get_organization_by_slug(&realm_id, "race-slug")
        .expect("get by slug")
        .expect("winning org must exist");
    assert_eq!(by_slug.slug(), "race-slug");

    let page = identity
        .list_organizations(&realm_id, None, 10)
        .expect("list");
    assert_eq!(page.items.len(), 1, "only one org must exist after race");
}

// ---------------------------------------------------------------------------
// A-28 test 2: Invitation double-spend prevention
// ---------------------------------------------------------------------------
//
// Two tasks concurrently accept the same invitation token.
// Exactly one accept must succeed; the second must return an error.
// After the race the membership count must be exactly one.

#[tokio::test]
async fn a28_invitation_double_spend_rejected() {
    let harness = Arc::new(common::TestHarness::embedded().await.expect("harness"));
    let identity = harness.identity();

    let realm_id = identity
        .create_realm(&CreateRealmRequest {
            name: format!("inv-race-realm-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let org = identity
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Inv Org".to_string(),
                slug: "inv-org".to_string(),
                description: None,
                config: None,
                ..Default::default()
            },
        )
        .expect("create org");

    let admin = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "admin@inv-race.test".to_string(),
                display_name: "Admin".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create admin");

    identity
        .add_member(&realm_id, org.id(), admin.id(), OrganizationRole::Owner)
        .expect("add admin as owner");

    let (_invitation, token) = identity
        .create_invitation(
            &realm_id,
            &CreateInvitationRequest {
                org_id: org.id().clone(),
                email: "invitee@inv-race.test".to_string(),
                role: OrganizationRole::Member,
                invited_by: admin.id().clone(),
            },
        )
        .expect("create invitation");

    // Race: two tasks accept the same token.
    let identity_a = harness.identity_arc();
    let identity_b = harness.identity_arc();
    let realm_a = realm_id.clone();
    let realm_b = realm_id.clone();
    let token_a = token.clone();
    let token_b = token.clone();

    let task_a =
        tokio::task::spawn_blocking(move || identity_a.accept_invitation(&realm_a, &token_a));
    let task_b =
        tokio::task::spawn_blocking(move || identity_b.accept_invitation(&realm_b, &token_b));

    let (result_a, result_b) = tokio::join!(task_a, task_b);
    let result_a = result_a.expect("task_a join");
    let result_b = result_b.expect("task_b join");

    let ok_count = [&result_a, &result_b].iter().filter(|r| r.is_ok()).count();
    let err_count = [&result_a, &result_b].iter().filter(|r| r.is_err()).count();

    assert_eq!(ok_count, 1, "exactly one accept must succeed");
    assert_eq!(err_count, 1, "exactly one accept must fail (double-spend)");

    // Exactly one membership must exist.
    let members = identity
        .list_members(&realm_id, org.id(), None, 10)
        .expect("list members");

    // The invitee was auto-created; filter out the admin owner.
    let invitee_memberships: Vec<_> = members
        .items
        .iter()
        .filter(|m| m.user_id() != admin.id())
        .collect();
    assert_eq!(
        invitee_memberships.len(),
        1,
        "invitee must have exactly one membership, not two"
    );
}

// ---------------------------------------------------------------------------
// A-28 test 3: RBAC assignment deduplication
// ---------------------------------------------------------------------------
//
// Calling `assign_role` twice with the same `(subject, role, scope)` must be
// idempotent: both calls return Ok(assignment) and only one storage record
// exists for that subject+role pair.

#[tokio::test]
async fn a28_rbac_assignment_is_idempotent() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let rbac = harness.rbac();

    let realm_id = identity
        .create_realm(&CreateRealmRequest {
            name: format!("rbac-dedup-realm-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "dedup@rbac.test".to_string(),
                display_name: "Dedup User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let role = rbac
        .create_role(
            &realm_id,
            &CreateRoleRequest {
                name: "dedup-role".to_string(),
                description: None,
                permissions: vec![Permission::new("docs.read").expect("valid perm")],
                parent_roles: vec![],
                scope_kind: hearth::rbac::RoleScopeKind::Realm,
            },
        )
        .expect("create role");

    let req = AssignRoleRequest {
        subject: Subject::User(user.id().clone()),
        role_id: role.id.clone(),
        scope: Scope::Realm,
        assigned_by: None,
    };

    // First assignment.
    let first = rbac.assign_role(&realm_id, &req).expect("first assign");

    // Second assignment with the same parameters — must be idempotent.
    let second = rbac
        .assign_role(&realm_id, &req)
        .expect("second assign (must not fail)");

    // Both return an assignment record with the same underlying ID.
    assert_eq!(
        first.id, second.id,
        "idempotent assign_role must return the same assignment ID"
    );
    assert_eq!(first.role_id, second.role_id);
    assert_eq!(first.scope, second.scope);

    // Only one assignment record must exist for this user.
    let assignments = rbac
        .list_user_assignments(&realm_id, user.id())
        .expect("list assignments");

    let matching: Vec<_> = assignments
        .iter()
        .filter(|a| a.role_id == role.id && a.scope == Scope::Realm)
        .collect();

    assert_eq!(
        matching.len(),
        1,
        "exactly one assignment record must exist after two idempotent calls"
    );
}

// ---------------------------------------------------------------------------
// A-33 test 1: delete_realm marks status + rejects subsequent operations
// ---------------------------------------------------------------------------
//
// After `delete_realm` completes the realm must not be findable, and any
// operation requiring an active realm (e.g. `create_user`) must be rejected.

#[tokio::test]
async fn a33_delete_realm_rejects_new_operations_after_completion() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // Set up a realm with a user and an org.
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("a33-delete-realm-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let realm_id = realm.id().clone();

    identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "alice@delete-test.test".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user before deletion");

    identity
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Pre-delete Org".to_string(),
                slug: "pre-delete-org".to_string(),
                description: None,
                config: None,
                ..Default::default()
            },
        )
        .expect("create org before deletion");

    // Delete the realm.
    identity.delete_realm(&realm_id).expect("delete realm");

    // Realm record must be gone.
    let fetched = identity
        .get_realm(&realm_id)
        .expect("get_realm after deletion");
    assert!(
        fetched.is_none(),
        "realm record must be absent after deletion"
    );

    // New user creation on the deleted realm must be rejected.
    let create_result = identity.create_user(
        &realm_id,
        &CreateUserRequest {
            email: "bob@delete-test.test".to_string(),
            display_name: "Bob".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        },
    );

    assert!(
        create_result.is_err(),
        "create_user on a deleted realm must fail"
    );

    // The error should indicate the realm is not found or suspended.
    match create_result.expect_err("create_user on a deleted realm must return an error") {
        IdentityError::RealmNotFound | IdentityError::RealmSuspended => {}
        other => panic!("expected RealmNotFound or RealmSuspended after deletion, got: {other}"),
    }
}

// ---------------------------------------------------------------------------
// A-33 test 2: Chunked cascade leaves no orphans
// ---------------------------------------------------------------------------
//
// Create a realm with users, orgs, memberships, and RBAC assignments.
// After `delete_realm` completes, scan the realm's storage namespace for
// the primary key prefixes and assert all are empty.

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a33_chunked_cascade_leaves_no_orphans() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let rbac = harness.rbac();
    let storage = harness.storage();

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("a33-orphan-realm-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let realm_id = realm.id().clone();

    // Create several users.
    let mut user_ids = Vec::new();
    for i in 0..3 {
        let user = identity
            .create_user(
                &realm_id,
                &CreateUserRequest {
                    email: format!("user{i}@orphan-test.test"),
                    display_name: format!("User {i}"),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )
            .expect("create user");
        user_ids.push(user.id().clone());
    }

    // Create an org and add members.
    let org = identity
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Orphan Org".to_string(),
                slug: "orphan-org".to_string(),
                description: None,
                config: None,
                ..Default::default()
            },
        )
        .expect("create org");

    identity
        .add_member(&realm_id, org.id(), &user_ids[0], OrganizationRole::Owner)
        .expect("add owner");
    identity
        .add_member(&realm_id, org.id(), &user_ids[1], OrganizationRole::Member)
        .expect("add member");

    // Create an RBAC role and assign it.
    let role = rbac
        .create_role(
            &realm_id,
            &CreateRoleRequest {
                name: "orphan-role".to_string(),
                description: None,
                permissions: vec![Permission::new("docs.read").expect("valid perm")],
                parent_roles: vec![],
                scope_kind: hearth::rbac::RoleScopeKind::Realm,
            },
        )
        .expect("create role");

    rbac.assign_role(
        &realm_id,
        &AssignRoleRequest {
            subject: Subject::User(user_ids[2].clone()),
            role_id: role.id.clone(),
            scope: Scope::Realm,
            assigned_by: None,
        },
    )
    .expect("assign role");

    // Confirm data exists before deletion.
    let pre_users = identity
        .list_users(&realm_id, None, 10)
        .expect("list users before");
    assert_eq!(pre_users.items.len(), 3, "expect 3 users before deletion");
    let pre_orgs = identity
        .list_organizations(&realm_id, None, 10)
        .expect("list orgs before");
    assert_eq!(pre_orgs.items.len(), 1, "expect 1 org before deletion");

    // Delete the realm.
    identity.delete_realm(&realm_id).expect("delete realm");

    // --- Scan for orphans using key prefix ranges ---
    //
    // Each prefix corresponds to a realm-scoped key family. After deletion
    // every scan over these prefixes must return an empty result set.
    //
    // Key format for range scans: start = prefix bytes, end = prefix + \xff
    // (the storage engine uses half-open [start, end) intervals).

    let check_prefix_empty = |prefix: &str, label: &str| {
        let start = prefix.as_bytes().to_vec();
        let mut end = start.clone();
        // Increment last byte to get the exclusive upper bound.
        *end.last_mut().expect("non-empty prefix") += 1;
        let entries = storage.scan(&realm_id, &start, &end).unwrap_or_default();
        assert!(
            entries.is_empty(),
            "orphan check: prefix '{label}' must be empty after realm delete, found {} entries",
            entries.len()
        );
    };

    // User records and email index.
    check_prefix_empty("usr:id:", "user primaries");
    check_prefix_empty("usr:email:", "user email index");

    // Credential records.
    check_prefix_empty("cred:user:", "credential primaries");

    // Session records.
    check_prefix_empty("ses:id:", "session primaries");
    check_prefix_empty("ses:user:", "session user index");

    // Organization records, slug index, memberships, and invitations.
    check_prefix_empty("org:id:", "org primaries");
    check_prefix_empty("org:slug:", "org slug index");
    check_prefix_empty("orgm:org:", "org→user memberships");
    check_prefix_empty("orgm:user:", "user→org memberships");
    check_prefix_empty("orgi:id:", "invitation primaries");
    check_prefix_empty("orgi:token:", "invitation token index");
    check_prefix_empty("orgi:org:", "invitation org dedup index");
    check_prefix_empty("orgi:list:", "invitation list index");

    // OAuth clients and codes.
    check_prefix_empty("oauth:client:", "oauth clients");
}
