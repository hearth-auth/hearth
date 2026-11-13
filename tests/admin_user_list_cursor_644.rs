#![allow(clippy::unwrap_used)]
//! #644: `GET /admin/users` pages with a key cursor, and its field filters
//! read the whole realm.
//!
//! Before, `next_cursor` was a decimal offset: a user deleted during a walk
//! moved the next user onto the page the client already had, so the client
//! never saw it. A field filter (`status`, `username`, `attr`) read only the
//! first 10,000 users of the realm and always answered `next_cursor: null`,
//! so it showed one page of the matches among those users.

mod common;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::{RealmId, UserId};
use hearth::identity::{
    CreateUserRequest, ImportUserRequest, SessionContext, UpdateUserRequest, UserStatus,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

/// The last possible user id in key order: a user with it is the last one
/// a walk of the realm reaches.
const LAST_ID: &str = "ffffffff-ffff-4fff-bfff-ffffffffffff";

fn build_app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

/// Creates a realm admin and returns its bearer token and user id.
fn admin(h: &common::TestHarness, realm: &RealmId) -> (String, UserId) {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: "admin@cursor.test".into(),
                display_name: "Admin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create admin");
    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup role")
        .expect("realm.admin seeded");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();
    (token, user.id().clone())
}

fn create_users(h: &common::TestHarness, realm: &RealmId, prefix: &str, n: u32) -> Vec<UserId> {
    (0..n)
        .map(|i| {
            h.identity()
                .create_user(
                    realm,
                    &CreateUserRequest {
                        email: format!("{prefix}{i}@cursor.test"),
                        display_name: format!("{prefix} {i}"),
                        first_name: String::new(),
                        last_name: String::new(),
                        attributes: Default::default(),
                    },
                )
                .expect("create user")
                .id()
                .clone()
        })
        .collect()
}

fn disable(h: &common::TestHarness, realm: &RealmId, user: &UserId) {
    h.identity()
        .update_user(
            realm,
            user,
            &UpdateUserRequest {
                status: Some(UserStatus::Disabled),
                ..UpdateUserRequest::default()
            },
        )
        .expect("disable user");
}

async fn get(
    app: &axum::Router,
    realm: &RealmId,
    token: &str,
    query: &str,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/users?{query}"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, serde_json::from_slice(&bytes).expect("json"))
}

fn ids_of(body: &serde_json::Value) -> Vec<String> {
    body["items"]
        .as_array()
        .expect("items array")
        .iter()
        .map(|u| u["id"].as_str().expect("id").to_string())
        .collect()
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Follows `next_cursor` from the first page until it is absent, and returns
/// the id of every item with how many times it came back. `between` runs
/// after the first page.
async fn walk(
    app: &axum::Router,
    realm: &RealmId,
    token: &str,
    query: &str,
    mut between: impl FnMut(&[String]),
) -> HashMap<String, usize> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut cursor: Option<String> = None;
    for request in 0.. {
        assert!(request < 10_000, "the walk does not end");
        let q = match &cursor {
            Some(c) => format!("{query}&cursor={}", encode(c)),
            None => query.to_string(),
        };
        let (status, body) = get(app, realm, token, &q).await;
        assert_eq!(status, StatusCode::OK, "{q}: {body}");
        let ids = ids_of(&body);
        for id in &ids {
            *seen.entry(id.clone()).or_default() += 1;
        }
        if request == 0 {
            between(&ids);
        }
        match body["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_string()),
            None => break,
        }
    }
    seen
}

#[tokio::test]
async fn following_next_cursor_reads_every_user_once_when_a_user_is_deleted() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let (token, admin_id) = admin(&h, &realm);
    let users = create_users(&h, &realm, "walker", 30);
    let app = build_app(&h);

    let mut deleted: Option<String> = None;
    let seen = walk(&app, &realm, &token, "limit=10", |first_page| {
        // Delete a user of the page the client already holds.
        let victim = first_page
            .iter()
            .find(|id| **id != admin_id.as_uuid().to_string())
            .expect("a user on the first page")
            .clone();
        let victim_id = UserId::new(victim.parse().expect("uuid"));
        h.identity()
            .delete_user(&realm, &victim_id)
            .expect("delete user");
        deleted = Some(victim);
    })
    .await;

    let deleted = deleted.expect("a user was deleted");
    let mut expected: HashSet<String> = users.iter().map(|u| u.as_uuid().to_string()).collect();
    expected.insert(admin_id.as_uuid().to_string());
    for id in &expected {
        if *id == deleted {
            continue;
        }
        assert_eq!(
            seen.get(id),
            Some(&1),
            "user {id} must come back exactly once"
        );
    }
}

#[tokio::test]
async fn a_status_filter_pages_through_every_match() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let (token, _) = admin(&h, &realm);
    let disabled = create_users(&h, &realm, "off", 25);
    for user in &disabled {
        disable(&h, &realm, user);
    }
    create_users(&h, &realm, "on", 5);
    let app = build_app(&h);

    let seen = walk(&app, &realm, &token, "status=disabled&limit=10", |_| {}).await;

    let expected: HashSet<String> = disabled.iter().map(|u| u.as_uuid().to_string()).collect();
    let got: HashSet<String> = seen.keys().cloned().collect();
    assert_eq!(
        got, expected,
        "the status filter must return every disabled user"
    );
    assert!(seen.values().all(|n| *n == 1), "each match comes back once");
}

#[tokio::test]
async fn field_filters_find_a_user_past_the_first_10000_users() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let (token, _) = admin(&h, &realm);
    create_users(&h, &realm, "crowd", 10_000);
    let needle = h
        .identity()
        .import_user(
            &realm,
            &ImportUserRequest {
                id: Some(UserId::new(LAST_ID.parse().expect("uuid"))),
                email: "needle@cursor.test".into(),
                display_name: "Needle Person".into(),
                first_name: String::new(),
                last_name: String::new(),
                status: UserStatus::Disabled,
                credential: None,
                attributes: [("tier".to_string(), "gold".to_string())].into(),
                restored: None,
            },
        )
        .expect("import the last user");
    let needle = needle.id().as_uuid().to_string();
    let app = build_app(&h);

    for query in ["status=disabled", "username=needle", "attr=tier:gold"] {
        let seen = walk(&app, &realm, &token, &format!("{query}&limit=100"), |_| {}).await;
        assert_eq!(
            seen.keys().cloned().collect::<Vec<_>>(),
            vec![needle.clone()],
            "{query} must find the one matching user, the last in key order"
        );
    }
}

#[tokio::test]
async fn an_invalid_cursor_is_refused() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let (token, _) = admin(&h, &realm);
    let app = build_app(&h);

    for query in ["cursor=not-a-cursor", "status=active&cursor=not-a-cursor"] {
        let (status, body) = get(&app, &realm, &token, query).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
    }
}
