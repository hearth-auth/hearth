//! Engine unit tests for `PageRequest` + `PagedResult` pagination (HEA-1617).
//!
//! Verifies that each list/search engine method returns:
//! - correct `total` count
//! - correct `items` window for first, last, and beyond-last pages
//! - correct `offset` + `limit` echoes

mod common;

use hearth::core::{PageRequest, MAX_PAGE_LIMIT};
use hearth::identity::{
    CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest, IdentityEngine,
};
use hearth::rbac::CreateGroupRequest;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn realm(identity: &dyn IdentityEngine) -> hearth::core::RealmId {
    identity
        .create_realm(&CreateRealmRequest {
            name: format!("pag-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn user(n: usize) -> CreateUserRequest {
    CreateUserRequest {
        email: format!("user{n}@pag.test"),
        display_name: format!("User {n}"),
        first_name: String::new(),
        last_name: String::new(),
        attributes: Default::default(),
    }
}

fn seed_users(identity: &dyn IdentityEngine, rid: &hearth::core::RealmId, count: usize) {
    for i in 0..count {
        identity.create_user(rid, &user(i)).expect("create user");
    }
}

// ---------------------------------------------------------------------------
// list_users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_users_empty_returns_zero_total() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    let r = id.list_users(&rid, &PageRequest::default()).expect("list");
    assert_eq!(r.total, 0, "empty realm: total must be 0");
    assert!(r.items.is_empty());
}

#[tokio::test]
async fn list_users_total_matches_count() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);
    seed_users(id, &rid, 7);

    let r = id
        .list_users(&rid, &PageRequest::new(0, MAX_PAGE_LIMIT))
        .expect("list all");
    assert_eq!(r.total, 7);
    assert_eq!(r.items.len(), 7);
}

#[tokio::test]
async fn list_users_first_page_correct_window() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);
    seed_users(id, &rid, 10);

    let r = id
        .list_users(&rid, &PageRequest::new(0, 4))
        .expect("page 1");
    assert_eq!(r.total, 10);
    assert_eq!(r.items.len(), 4);
    assert_eq!(r.offset, 0);
    assert_eq!(r.limit, 4);
}

#[tokio::test]
async fn list_users_last_page_returns_remainder() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);
    seed_users(id, &rid, 10);

    let r = id
        .list_users(&rid, &PageRequest::new(8, 4))
        .expect("last page");
    assert_eq!(r.total, 10);
    assert_eq!(r.items.len(), 2, "only 2 items remain at offset 8 of 10");
}

#[tokio::test]
async fn list_users_beyond_last_page_returns_empty() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);
    seed_users(id, &rid, 3);

    let r = id
        .list_users(&rid, &PageRequest::new(100, 10))
        .expect("beyond");
    assert_eq!(
        r.total, 3,
        "total must still be 3 even though window is empty"
    );
    assert!(r.items.is_empty());
}

// ---------------------------------------------------------------------------
// search_users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn search_users_returns_total_and_first_page() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    // 8 users with "user" in email, 1 admin that won't match
    seed_users(id, &rid, 8);
    id.create_user(
        &rid,
        &CreateUserRequest {
            email: "admin@pag.test".to_string(),
            display_name: "Admin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        },
    )
    .expect("create admin");

    let r = id
        .search_users(&rid, "user", &PageRequest::new(0, 4))
        .expect("search p1");
    assert_eq!(r.total, 8, "8 users match 'user'");
    assert_eq!(r.items.len(), 4);

    let r2 = id
        .search_users(&rid, "user", &PageRequest::new(4, 4))
        .expect("search p2");
    assert_eq!(r2.total, 8);
    assert_eq!(r2.items.len(), 4);
}

#[tokio::test]
async fn search_users_empty_query_returns_zero_total() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);
    seed_users(id, &rid, 3);

    let r = id
        .search_users(&rid, "", &PageRequest::default())
        .expect("empty");
    assert_eq!(r.total, 0);
    assert!(r.items.is_empty());
}

#[tokio::test]
async fn search_users_no_matches_returns_zero_total() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);
    seed_users(id, &rid, 3);

    let r = id
        .search_users(&rid, "zzzzz", &PageRequest::default())
        .expect("no match");
    assert_eq!(r.total, 0);
    assert!(r.items.is_empty());
}

#[tokio::test]
async fn search_users_beyond_last_returns_empty_items_correct_total() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);
    seed_users(id, &rid, 3);

    let r = id
        .search_users(&rid, "user", &PageRequest::new(100, 10))
        .expect("beyond");
    assert_eq!(r.total, 3);
    assert!(r.items.is_empty());
}

// ---------------------------------------------------------------------------
// list_realms
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_realms_total_and_first_page() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();

    // seed 5 extra realms
    for _ in 0..5 {
        id.create_realm(&CreateRealmRequest {
            name: format!("pag-realm-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    }

    let r_all = id
        .list_realms(&PageRequest::new(0, MAX_PAGE_LIMIT))
        .expect("all");
    let total = r_all.total;
    assert!(total >= 5, "at least 5 realms created");

    let r = id.list_realms(&PageRequest::new(0, 3)).expect("page");
    assert_eq!(r.total, total);
    assert_eq!(r.items.len(), 3);
}

#[tokio::test]
async fn list_realms_beyond_last_returns_empty() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();

    let r_all = id
        .list_realms(&PageRequest::new(0, MAX_PAGE_LIMIT))
        .expect("all");
    let total = r_all.total;

    let r = id
        .list_realms(&PageRequest::new(total + 100, 10))
        .expect("beyond");
    assert_eq!(r.total, total);
    assert!(r.items.is_empty());
}

// ---------------------------------------------------------------------------
// list_organizations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_organizations_total_and_window() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    for i in 0..5u32 {
        id.create_organization(
            &rid,
            &CreateOrganizationRequest {
                name: format!("Org {i}"),
                slug: format!("org-pag-{i}"),
                description: None,
                config: None,
                attributes: Default::default(),
            },
        )
        .expect("create org");
    }

    let r = id
        .list_organizations(&rid, &PageRequest::new(0, 3))
        .expect("list");
    assert_eq!(r.total, 5);
    assert_eq!(r.items.len(), 3);
}

#[tokio::test]
async fn list_organizations_beyond_last_returns_empty() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    let r = id
        .list_organizations(&rid, &PageRequest::new(100, 10))
        .expect("beyond");
    assert_eq!(r.total, 0);
    assert!(r.items.is_empty());
}

// ---------------------------------------------------------------------------
// list_groups (RBAC)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_groups_total_and_windowed_pages() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rbac = h.rbac_arc();
    let rid = realm(id);

    for i in 0..7u32 {
        rbac.create_group(
            &rid,
            &CreateGroupRequest {
                name: format!("Group {i}"),
                slug: format!("group-pag-{i}"),
                description: None,
            },
        )
        .expect("create group");
    }

    let p1 = rbac
        .list_groups(&rid, &PageRequest::new(0, 4))
        .expect("page 1");
    assert_eq!(p1.total, 7);
    assert_eq!(p1.items.len(), 4);

    let p2 = rbac
        .list_groups(&rid, &PageRequest::new(4, 4))
        .expect("page 2");
    assert_eq!(p2.total, 7);
    assert_eq!(p2.items.len(), 3, "last 3 groups on second page");
}

#[tokio::test]
async fn list_groups_empty_returns_zero_total() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rbac = h.rbac_arc();
    let rid = realm(id);

    let r = rbac
        .list_groups(&rid, &PageRequest::default())
        .expect("list");
    assert_eq!(r.total, 0);
    assert!(r.items.is_empty());
}
