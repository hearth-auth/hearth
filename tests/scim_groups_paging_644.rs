#![allow(clippy::unwrap_used)]
//! #644: SCIM `GET /Groups` reads the realm, not only its first 1,000 groups.
//!
//! Before, the list read at most `SCIM_MAX_SCAN_LIMIT` (1,000) organizations
//! and filtered and paged them in memory. In a bigger realm a provisioning
//! client did not see the other groups, `totalResults` stopped at 1,000, and
//! a filter did not find a group past the cap.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::{PageRequest, RealmId};
use hearth::identity::{
    CreateOrganizationRequest, CreateRealmRequest, RealmConfig, UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

/// More groups than the old scan cap (1,000).
const GROUPS: u32 = 1_005;

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

/// Creates a realm with a SCIM bearer token and `groups` organizations.
fn setup(h: &common::TestHarness, suffix: &str, groups: u32) -> (RealmId, String) {
    let token = format!("scim-groups-644-token-{suffix}");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("scim-groups-644-{suffix}"),
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
    for i in 0..groups {
        h.identity()
            .create_organization(
                realm.id(),
                &CreateOrganizationRequest {
                    name: format!("Group {i}"),
                    slug: format!("group-{i}"),
                    ..CreateOrganizationRequest::default()
                },
            )
            .expect("create organization");
    }
    (realm.id().clone(), format!("Bearer {token}"))
}

async fn get_groups(
    app: &axum::Router,
    realm_id: &RealmId,
    auth: &str,
    query: &str,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/scim/v2/Groups?{query}"))
        .header("x-realm-id", realm_id.as_uuid().to_string())
        .header("authorization", auth)
        .body(Body::empty())
        .expect("build list request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    (status, serde_json::from_slice(&bytes).expect("json"))
}

fn ids(val: &Value) -> Vec<String> {
    val["Resources"]
        .as_array()
        .expect("Resources array")
        .iter()
        .map(|r| r["id"].as_str().expect("id").to_string())
        .collect()
}

#[tokio::test]
async fn startindex_pages_reach_every_group_past_the_old_scan_cap() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm_id, auth) = setup(&h, "pages", GROUPS);
    let app = build_app(&h);

    let (status, page) = get_groups(&app, &realm_id, &auth, "startIndex=1001&count=10").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        page["totalResults"].as_u64(),
        Some(u64::from(GROUPS)),
        "{page}"
    );
    let expected: Vec<String> = h
        .identity()
        .list_organizations(&realm_id, &PageRequest::new(1_000, 10))
        .expect("list organizations")
        .items
        .iter()
        .map(|o| o.id().as_uuid().to_string())
        .collect();
    assert_eq!(expected.len(), 5);
    assert_eq!(ids(&page), expected);
}

#[tokio::test]
async fn a_filter_finds_every_matching_group_past_the_old_scan_cap() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm_id, auth) = setup(&h, "filter", GROUPS);
    let app = build_app(&h);

    // Every group matches: the total counts all of them, not the first 1,000.
    let (status, page) = get_groups(
        &app,
        &realm_id,
        &auth,
        "filter=displayName%20sw%20%22Group%22&count=1",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        page["totalResults"].as_u64(),
        Some(u64::from(GROUPS)),
        "{page}"
    );

    // The last group in ID order is past the old scan cap.
    let last = h
        .identity()
        .list_organizations(&realm_id, &PageRequest::new(u64::from(GROUPS) - 1, 1))
        .expect("list organizations")
        .items
        .pop()
        .expect("last organization");
    let name = last.name().replace(' ', "%20");
    let (status, page) = get_groups(
        &app,
        &realm_id,
        &auth,
        &format!("filter=displayName%20eq%20%22{name}%22"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["totalResults"].as_u64(), Some(1), "{page}");
    assert_eq!(ids(&page), vec![last.id().as_uuid().to_string()]);
}

#[tokio::test]
async fn a_filter_above_the_scan_limit_is_too_many() {
    let limit = u32::try_from(hearth::abuse::SCIM_FILTER_SCAN_LIMIT).unwrap();
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm_id, auth) = setup(&h, "toomany", limit + 1);
    let app = build_app(&h);

    let (status, val) = get_groups(
        &app,
        &realm_id,
        &auth,
        "filter=displayName%20eq%20%22Group%207%22",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{val}");
    assert_eq!(val["scimType"], "tooMany", "{val}");

    // With no filter, the list still pages the whole realm.
    let (status, page) = get_groups(&app, &realm_id, &auth, "count=1").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["totalResults"].as_u64(), Some(u64::from(limit + 1)));
}
