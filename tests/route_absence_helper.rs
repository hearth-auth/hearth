//! Self-tests for `common::routes::assert_route_absent`. A helper that
//! passes on a live route would make every removal test vacuous.

mod common;

use axum::http::Method;
use common::routes::{assert_route_absent, composed_app, SEEDED_REALM};

#[tokio::test]
async fn never_existing_route_is_absent() {
    let app = composed_app();
    assert_route_absent(&app, Method::GET, "/ui/realms/acme/no-such-feature").await;
    assert_route_absent(&app, Method::POST, "/admin/no-such-feature").await;
}

#[tokio::test]
#[should_panic(expected = "is still served")]
async fn live_api_route_is_not_absent() {
    let app = composed_app();
    assert_route_absent(&app, Method::GET, "/health").await;
}

#[tokio::test]
#[should_panic(expected = "is still served")]
async fn live_realm_scoped_ui_route_is_not_absent() {
    let app = composed_app();
    let path = format!("/ui/realms/{SEEDED_REALM}/login");
    assert_route_absent(&app, Method::GET, &path).await;
}
