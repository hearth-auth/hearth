//! Integration tests for the users list search grammar + sort feature (HEA-1633).
//!
//! Covers: wildcard, exact, substring, sort asc/desc, sort+search+page
//! interaction, exact-total pagination, and injection-safe inputs.
#![allow(clippy::unwrap_used)]

mod common;

use hearth::core::{PageRequest, RealmId};
use hearth::identity::{
    search::{SortDir, UserSortField},
    CreateRealmRequest, CreateUserRequest, IdentityEngine,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn realm(identity: &dyn IdentityEngine) -> RealmId {
    identity
        .create_realm(&CreateRealmRequest {
            name: format!("sort-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn make_user(email: &str, display_name: &str) -> CreateUserRequest {
    CreateUserRequest {
        email: email.to_string(),
        display_name: display_name.to_string(),
        first_name: String::new(),
        last_name: String::new(),
        attributes: Default::default(),
    }
}

// ---------------------------------------------------------------------------
// Search — wildcard
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wildcard_suffix_matches_domain() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    id.create_user(&rid, &make_user("alice@acme.com", "Alice A"))
        .expect("create alice");
    id.create_user(&rid, &make_user("bob@acme.com", "Bob B"))
        .expect("create bob");
    id.create_user(&rid, &make_user("carol@other.com", "Carol C"))
        .expect("create carol");

    let r = id
        .search_users(
            &rid,
            "*@acme.com",
            &PageRequest::new(0, 50),
            None,
            SortDir::default(),
        )
        .expect("wildcard search");
    assert_eq!(r.total, 2, "only 2 users at acme.com");
    let emails: Vec<&str> = r.items.iter().map(|u| u.email()).collect();
    assert!(emails.contains(&"alice@acme.com"));
    assert!(emails.contains(&"bob@acme.com"));
}

#[tokio::test]
async fn wildcard_prefix_matches_start_of_email() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    id.create_user(&rid, &make_user("alice@test.com", "Alice"))
        .unwrap();
    id.create_user(&rid, &make_user("alice2@test.com", "Alice Two"))
        .unwrap();
    id.create_user(&rid, &make_user("bob@test.com", "Bob"))
        .unwrap();

    let r = id
        .search_users(
            &rid,
            "alice*",
            &PageRequest::new(0, 50),
            None,
            SortDir::default(),
        )
        .expect("prefix glob");
    assert_eq!(r.total, 2);
}

#[tokio::test]
async fn wildcard_question_matches_single_char() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    id.create_user(&rid, &make_user("john@test.com", "John"))
        .unwrap();
    id.create_user(&rid, &make_user("joan@test.com", "Joan"))
        .unwrap();
    id.create_user(&rid, &make_user("jan@test.com", "Jan"))
        .unwrap();

    // j?an matches "joan" (j-o-a-n) and "jan" is j-a-n which is only 3 chars
    // and j?an needs exactly 4. So only "joan" should match.
    let r = id
        .search_users(
            &rid,
            "j?an@test.com",
            &PageRequest::new(0, 50),
            None,
            SortDir::default(),
        )
        .expect("question glob");
    assert_eq!(r.total, 1);
    assert_eq!(r.items[0].email(), "joan@test.com");
}

// ---------------------------------------------------------------------------
// Search — exact
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exact_query_matches_only_whole_field() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    id.create_user(&rid, &make_user("alice@test.com", "Alice"))
        .unwrap();
    id.create_user(&rid, &make_user("alice2@test.com", "Alice2"))
        .unwrap();

    let r = id
        .search_users(
            &rid,
            r#""alice@test.com""#,
            &PageRequest::new(0, 50),
            None,
            SortDir::default(),
        )
        .expect("exact match");
    assert_eq!(r.total, 1, "exact must not match alice2@test.com");
    assert_eq!(r.items[0].email(), "alice@test.com");
}

#[tokio::test]
async fn exact_query_case_insensitive() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    id.create_user(&rid, &make_user("alice@test.com", "Alice"))
        .unwrap();

    let r = id
        .search_users(
            &rid,
            r#""ALICE@TEST.COM""#,
            &PageRequest::new(0, 50),
            None,
            SortDir::default(),
        )
        .expect("case exact");
    assert_eq!(r.total, 1);
}

// ---------------------------------------------------------------------------
// Search — substring (default)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn substring_search_matches_email_and_name() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    id.create_user(&rid, &make_user("alice@test.com", "Alice Smith"))
        .unwrap();
    id.create_user(&rid, &make_user("bob@test.com", "Bob Smith"))
        .unwrap();
    id.create_user(&rid, &make_user("carol@test.com", "Carol Jones"))
        .unwrap();

    // "smith" matches Alice and Bob by display_name
    let r = id
        .search_users(
            &rid,
            "smith",
            &PageRequest::new(0, 50),
            None,
            SortDir::default(),
        )
        .expect("substring");
    assert_eq!(r.total, 2);
}

// ---------------------------------------------------------------------------
// Sort — asc / desc
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sort_by_email_asc_orders_alphabetically() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    id.create_user(&rid, &make_user("charlie@test.com", "Charlie"))
        .unwrap();
    id.create_user(&rid, &make_user("alice@test.com", "Alice"))
        .unwrap();
    id.create_user(&rid, &make_user("bob@test.com", "Bob"))
        .unwrap();

    let r = id
        .search_users(
            &rid,
            "",
            &PageRequest::new(0, 50),
            Some(UserSortField::Email),
            SortDir::Asc,
        )
        .expect("sort email asc");
    assert_eq!(r.total, 3);
    let emails: Vec<&str> = r.items.iter().map(|u| u.email()).collect();
    assert_eq!(
        emails,
        ["alice@test.com", "bob@test.com", "charlie@test.com"]
    );
}

#[tokio::test]
async fn sort_by_email_desc_reverses_order() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    id.create_user(&rid, &make_user("charlie@test.com", "Charlie"))
        .unwrap();
    id.create_user(&rid, &make_user("alice@test.com", "Alice"))
        .unwrap();
    id.create_user(&rid, &make_user("bob@test.com", "Bob"))
        .unwrap();

    let r = id
        .search_users(
            &rid,
            "",
            &PageRequest::new(0, 50),
            Some(UserSortField::Email),
            SortDir::Desc,
        )
        .expect("sort email desc");
    assert_eq!(r.total, 3);
    let emails: Vec<&str> = r.items.iter().map(|u| u.email()).collect();
    assert_eq!(
        emails,
        ["charlie@test.com", "bob@test.com", "alice@test.com"]
    );
}

#[tokio::test]
async fn sort_by_name_asc_orders_by_display_name() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    id.create_user(&rid, &make_user("x@test.com", "Zara"))
        .unwrap();
    id.create_user(&rid, &make_user("y@test.com", "Alice"))
        .unwrap();
    id.create_user(&rid, &make_user("z@test.com", "Mike"))
        .unwrap();

    let r = id
        .search_users(
            &rid,
            "",
            &PageRequest::new(0, 50),
            Some(UserSortField::Name),
            SortDir::Asc,
        )
        .expect("sort name asc");
    let names: Vec<&str> = r.items.iter().map(|u| u.display_name()).collect();
    assert_eq!(names, ["Alice", "Mike", "Zara"]);
}

#[tokio::test]
async fn sort_by_created_desc_newest_first() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    // Creation order: a → b → c; desc means c is first.
    id.create_user(&rid, &make_user("a@test.com", "A")).unwrap();
    id.create_user(&rid, &make_user("b@test.com", "B")).unwrap();
    id.create_user(&rid, &make_user("c@test.com", "C")).unwrap();

    let r = id
        .search_users(
            &rid,
            "",
            &PageRequest::new(0, 50),
            Some(UserSortField::Created),
            SortDir::Desc,
        )
        .expect("sort created desc");
    assert_eq!(r.total, 3);
    // The most-recently-created user (c) must appear before a.
    let emails: Vec<&str> = r.items.iter().map(|u| u.email()).collect();
    let idx_a = emails.iter().position(|&e| e == "a@test.com").unwrap();
    let idx_c = emails.iter().position(|&e| e == "c@test.com").unwrap();
    assert!(
        idx_c < idx_a,
        "c (newest) must precede a (oldest) in desc order"
    );
}

// ---------------------------------------------------------------------------
// Sort + search interaction
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sort_and_search_combined_applies_filter_before_sort() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    id.create_user(&rid, &make_user("charlie@acme.com", "Charlie"))
        .unwrap();
    id.create_user(&rid, &make_user("alice@acme.com", "Alice"))
        .unwrap();
    id.create_user(&rid, &make_user("zara@other.com", "Zara"))
        .unwrap(); // won't match

    let r = id
        .search_users(
            &rid,
            "*@acme.com",
            &PageRequest::new(0, 50),
            Some(UserSortField::Email),
            SortDir::Asc,
        )
        .expect("search + sort");
    assert_eq!(r.total, 2, "non-acme user filtered out");
    let emails: Vec<&str> = r.items.iter().map(|u| u.email()).collect();
    assert_eq!(emails, ["alice@acme.com", "charlie@acme.com"]);
}

// ---------------------------------------------------------------------------
// Exact-total pagination — sort MUST apply to full set before slice
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sort_pagination_stable_across_pages() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    // 6 users: emails e0..e5, intentionally out of alphabetical order at creation.
    for i in [3usize, 1, 5, 0, 4, 2] {
        id.create_user(
            &rid,
            &make_user(&format!("e{i}@test.com"), &format!("E{i}")),
        )
        .unwrap();
    }

    // Page 1 (email asc): e0, e1, e2
    let p1 = id
        .search_users(
            &rid,
            "",
            &PageRequest::new(0, 3),
            Some(UserSortField::Email),
            SortDir::Asc,
        )
        .expect("p1");
    assert_eq!(p1.total, 6, "exact total must be 6");
    let p1_emails: Vec<&str> = p1.items.iter().map(|u| u.email()).collect();
    assert_eq!(p1_emails, ["e0@test.com", "e1@test.com", "e2@test.com"]);

    // Page 2 (email asc): e3, e4, e5
    let p2 = id
        .search_users(
            &rid,
            "",
            &PageRequest::new(3, 3),
            Some(UserSortField::Email),
            SortDir::Asc,
        )
        .expect("p2");
    assert_eq!(p2.total, 6);
    let p2_emails: Vec<&str> = p2.items.iter().map(|u| u.email()).collect();
    assert_eq!(p2_emails, ["e3@test.com", "e4@test.com", "e5@test.com"]);
}

#[tokio::test]
async fn sort_pagination_no_overlap_no_gap() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    for i in 0..10usize {
        id.create_user(
            &rid,
            &make_user(&format!("user{i:02}@test.com"), &format!("User {i:02}")),
        )
        .unwrap();
    }

    let mut all_emails: Vec<String> = Vec::new();
    for page in 0..5u64 {
        let r = id
            .search_users(
                &rid,
                "",
                &PageRequest::new(page * 2, 2),
                Some(UserSortField::Email),
                SortDir::Asc,
            )
            .expect("page");
        assert_eq!(r.total, 10);
        for u in &r.items {
            all_emails.push(u.email().to_string());
        }
    }

    assert_eq!(all_emails.len(), 10, "all 10 users covered exactly once");
    // No duplicates.
    let mut deduped = all_emails.clone();
    deduped.dedup();
    assert_eq!(deduped.len(), 10);
    // Monotonically ascending.
    for w in all_emails.windows(2) {
        assert!(
            w[0] < w[1],
            "sorted order must be monotonic: {} < {}",
            w[0],
            w[1]
        );
    }
}

// ---------------------------------------------------------------------------
// Injection-safe inputs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bare_star_glob_matches_all() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    id.create_user(&rid, &make_user("alice@test.com", "Alice"))
        .unwrap();
    id.create_user(&rid, &make_user("bob@test.com", "Bob"))
        .unwrap();

    let r = id
        .search_users(
            &rid,
            "*",
            &PageRequest::new(0, 50),
            None,
            SortDir::default(),
        )
        .expect("bare star");
    // bare `*` is a valid glob (MatchAll via glob), not an injection
    assert_eq!(r.total, 2, "bare star must match all users");
}

#[tokio::test]
async fn exact_empty_inner_matches_empty_fields_only() {
    // `""` (two quotes) = Exact("") which matches only fields equal to "".
    // No user should have an empty email, so result must be empty.
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    id.create_user(&rid, &make_user("alice@test.com", "Alice"))
        .unwrap();

    let r = id
        .search_users(
            &rid,
            r#""""#,
            &PageRequest::new(0, 50),
            None,
            SortDir::default(),
        )
        .expect("empty exact");
    assert_eq!(r.total, 0, "no user has empty email");
}

#[tokio::test]
async fn unicode_query_matches_correctly() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let id = h.identity();
    let rid = realm(id);

    id.create_user(&rid, &make_user("hans@test.com", "Häns Müller"))
        .unwrap();
    id.create_user(&rid, &make_user("jane@test.com", "Jane Smith"))
        .unwrap();

    let r = id
        .search_users(
            &rid,
            "müller",
            &PageRequest::new(0, 50),
            None,
            SortDir::default(),
        )
        .expect("unicode");
    assert_eq!(r.total, 1);
    assert_eq!(r.items[0].email(), "hans@test.com");
}

// ---------------------------------------------------------------------------
// UserSortField / SortDir parsing
// ---------------------------------------------------------------------------

#[test]
fn sort_field_from_param_unknown_falls_back_to_email() {
    use hearth::identity::search::UserSortField;
    assert_eq!(UserSortField::from_param("unknown"), UserSortField::Email);
    assert_eq!(UserSortField::from_param(""), UserSortField::Email);
    assert_eq!(UserSortField::from_param("name"), UserSortField::Name);
    assert_eq!(UserSortField::from_param("NAME"), UserSortField::Name);
    assert_eq!(UserSortField::from_param("status"), UserSortField::Status);
    assert_eq!(UserSortField::from_param("created"), UserSortField::Created);
}

#[test]
fn sort_dir_from_param_unknown_falls_back_to_asc() {
    assert_eq!(SortDir::from_param(""), SortDir::Asc);
    assert_eq!(SortDir::from_param("invalid"), SortDir::Asc);
    assert_eq!(SortDir::from_param("asc"), SortDir::Asc);
    assert_eq!(SortDir::from_param("desc"), SortDir::Desc);
    assert_eq!(SortDir::from_param("DESC"), SortDir::Desc);
}
