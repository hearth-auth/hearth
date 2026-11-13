#![allow(clippy::unwrap_used)]
//! #644: SCIM `GET /Users` reads the realm, not only its first 1,000 users.
//!
//! Before, the list read at most `SCIM_MAX_SCAN_LIMIT` (1,000) users and
//! filtered and paged them in memory. In a bigger realm a provisioning client
//! did not see the other users, `totalResults` stopped at 1,000, and an
//! `eq` filter did not find a user past the cap.

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::{PageRequest, RealmId, UserId};
use hearth::identity::{CreateRealmRequest, CreateUserRequest, RealmConfig, UpdateRealmRequest};
use hearth::protocol::http::{router, AppState};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

/// More users than the old scan cap (1,000).
const USERS: u32 = 1_005;

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn build_app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

/// Creates a realm with a SCIM bearer token and `users` users.
fn setup(h: &common::TestHarness, suffix: &str, users: u32) -> (RealmId, String) {
    let token = format!("scim-paging-644-token-{suffix}");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("scim-paging-644-{suffix}"),
            config: None,
        })
        .expect("create realm");
    h.identity()
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    scim_bearer_token_hash: Some(sha256_hex(&token)),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("set scim token");
    for i in 0..users {
        h.identity()
            .create_user(
                realm.id(),
                &CreateUserRequest {
                    email: format!("user{i}@{suffix}.test"),
                    display_name: format!("User {i}"),
                    first_name: format!("User{i}"),
                    last_name: "Paging".into(),
                    attributes: Default::default(),
                },
            )
            .expect("create user");
    }
    (realm.id().clone(), format!("Bearer {token}"))
}

async fn get_users(app: &axum::Router, realm_id: &RealmId, auth: &str, query: &str) -> Value {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/scim/v2/Users?{query}"))
        .header("x-realm-id", realm_id.as_uuid().to_string())
        .header("authorization", auth)
        .body(Body::empty())
        .expect("build list request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let val: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(status, StatusCode::OK, "GET /Users?{query}: {val}");
    val
}

fn ids(val: &Value) -> Vec<String> {
    val["Resources"]
        .as_array()
        .expect("Resources array")
        .iter()
        .map(|r| r["id"].as_str().expect("id").to_string())
        .collect()
}

/// The users at positions `offset..offset + n` in the order that SCIM pages.
fn users_at(h: &common::TestHarness, realm_id: &RealmId, offset: u64, n: u32) -> Vec<UserId> {
    h.identity()
        .list_users(realm_id, &PageRequest::new(offset, n))
        .expect("list users")
        .items
        .iter()
        .map(|u| u.id().clone())
        .collect()
}

#[tokio::test]
async fn startindex_pages_reach_every_user_past_the_old_scan_cap() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm_id, auth) = setup(&h, "every", USERS);
    let app = build_app(&h);

    let mut seen: HashSet<String> = HashSet::new();
    let mut start = 1u32;
    loop {
        let page = get_users(
            &app,
            &realm_id,
            &auth,
            &format!("startIndex={start}&count=200"),
        )
        .await;
        assert_eq!(
            page["totalResults"].as_u64(),
            Some(u64::from(USERS)),
            "totalResults at startIndex={start}"
        );
        let page_ids = ids(&page);
        if page_ids.is_empty() {
            break;
        }
        for id in &page_ids {
            assert!(seen.insert(id.clone()), "user {id} on two pages");
        }
        start += u32::try_from(page_ids.len()).unwrap();
    }
    assert_eq!(seen.len(), USERS as usize, "every user on exactly one page");
}

#[tokio::test]
async fn a_user_name_eq_filter_finds_a_user_past_the_old_scan_cap() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm_id, auth) = setup(&h, "username", USERS);
    let app = build_app(&h);

    let last = users_at(&h, &realm_id, u64::from(USERS) - 1, 1).remove(0);
    let email = h
        .identity()
        .get_user(&realm_id, &last)
        .expect("get user")
        .expect("user exists")
        .email()
        .to_string();

    let filter = format!("filter=userName%20eq%20%22{email}%22");
    let page = get_users(&app, &realm_id, &auth, &filter).await;
    assert_eq!(page["totalResults"].as_u64(), Some(1), "{page}");
    assert_eq!(ids(&page), vec![last.as_uuid().to_string()]);
}

#[tokio::test]
async fn an_external_id_eq_filter_finds_a_user_past_the_old_scan_cap() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm_id, auth) = setup(&h, "externalid", USERS);
    let app = build_app(&h);

    let last = users_at(&h, &realm_id, u64::from(USERS) - 1, 1).remove(0);
    h.identity()
        .set_scim_external_id(&realm_id, &last, "idp-0042")
        .expect("set external id");

    let page = get_users(
        &app,
        &realm_id,
        &auth,
        "filter=externalId%20eq%20%22idp-0042%22",
    )
    .await;
    assert_eq!(page["totalResults"].as_u64(), Some(1), "{page}");
    assert_eq!(ids(&page), vec![last.as_uuid().to_string()]);
}

/// A client that pages in sequence gets the next users after the last page,
/// even when a user of an earlier page was deleted between the requests.
/// A plain offset would skip one user.
#[tokio::test]
async fn the_next_page_in_sequence_starts_after_the_last_page_when_a_user_is_deleted() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm_id, auth) = setup(&h, "sequence", 10);
    let app = build_app(&h);
    let order = users_at(&h, &realm_id, 0, 10);

    let first = get_users(&app, &realm_id, &auth, "startIndex=1&count=5").await;
    let first_ids = ids(&first);
    let expected_first: Vec<String> = order[..5].iter().map(|u| u.as_uuid().to_string()).collect();
    assert_eq!(first_ids, expected_first);

    h.identity()
        .delete_user(&realm_id, &order[0])
        .expect("delete user");

    let second = get_users(&app, &realm_id, &auth, "startIndex=6&count=5").await;
    let expected_second: Vec<String> = order[5..].iter().map(|u| u.as_uuid().to_string()).collect();
    assert_eq!(
        ids(&second),
        expected_second,
        "the page after the last one must not skip a user"
    );
    assert_eq!(second["totalResults"].as_u64(), Some(9));
}

/// A filter that no index serves reads every user of a realm up to the
/// filter scan limit, so it finds a user past the old cap.
#[tokio::test]
async fn an_unindexed_filter_finds_a_user_past_the_old_scan_cap() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm_id, auth) = setup(&h, "unindexed", USERS);
    let app = build_app(&h);

    let last = users_at(&h, &realm_id, u64::from(USERS) - 1, 1).remove(0);
    let name = h
        .identity()
        .get_user(&realm_id, &last)
        .expect("get user")
        .expect("user exists")
        .display_name()
        .to_string();

    let filter = format!(
        "filter=displayName%20eq%20%22{}%22",
        name.replace(' ', "%20")
    );
    let page = get_users(&app, &realm_id, &auth, &filter).await;
    assert_eq!(page["totalResults"].as_u64(), Some(1), "{page}");
    assert_eq!(ids(&page), vec![last.as_uuid().to_string()]);
}

/// Above the filter scan limit, a filter that no index serves gets `400`
/// with `scimType` `tooMany` (RFC 7644 §3.12), not the matches of part of
/// the realm. An indexed `eq` filter still works.
#[tokio::test]
async fn an_unindexed_filter_above_the_scan_limit_is_too_many() {
    let limit = u32::try_from(hearth::abuse::SCIM_FILTER_SCAN_LIMIT).unwrap();
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm_id, auth) = setup(&h, "toomany", limit + 1);
    let app = build_app(&h);

    let req = Request::builder()
        .method("GET")
        .uri("/scim/v2/Users?filter=displayName%20co%20%22User%22")
        .header("x-realm-id", realm_id.as_uuid().to_string())
        .header("authorization", &auth)
        .body(Body::empty())
        .expect("build list request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let val: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(val["scimType"], "tooMany", "{val}");

    let page = get_users(
        &app,
        &realm_id,
        &auth,
        "filter=userName%20eq%20%22user7@toomany.test%22",
    )
    .await;
    assert_eq!(page["totalResults"].as_u64(), Some(1), "{page}");
}
