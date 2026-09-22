//! `POST /token` must be rate-limited even when the request carries no
//! `client_id`.
//!
//! Audit 2026-08-28 §4.16#8 (MEDIUM): the token-endpoint limiter buckets on
//! `(realm, client_id)` and the handler only consulted it when the body's
//! `client_id` parsed as a UUID. Hearth's clientless session-refresh flow
//! (`grant_type=refresh_token` with no `client_id` and no Basic auth) is
//! therefore invisible to the limiter — an unauthenticated attacker could
//! flood the endpoint with refresh-token guesses forever. The client IP is
//! the only identity such a request has, so it must supply the bucket.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::audit::EmbeddedAuditEngine;
use hearth::core::RealmId;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig,
};
use hearth::protocol::http::{router as http_router, AppState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt;
use uuid::Uuid;

/// Token-endpoint cap used by these tests. Small so the test does not have to
/// issue 200 requests to reach the ceiling.
const LIMIT: u32 = 4;

fn make_app_state(token_per_minute: Option<u32>) -> (Arc<AppState>, RealmId, String) {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage =
        Arc::new(EmbeddedStorageEngine::open(StorageConfig::dev(data_dir)).expect("storage"));
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::rbac::RbacEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&rbac),
            Arc::clone(&audit),
        )
        .expect("identity"),
    ) as Arc<dyn hearth::identity::IdentityEngine>;

    let realm_name = format!("anon-rl-{}", Uuid::new_v4());
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let state = Arc::new(AppState::new(identity, rbac, audit).with_rate_limits(
        None,
        token_per_minute,
        None,
    ));
    (state, realm_id, realm_name)
}

fn clientless_refresh_request(uri: &str, realm_id: &RealmId) -> Request<Body> {
    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": "not.a.real-token",
    });
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-realm-id", realm_id.as_uuid().to_string())
        .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
        .expect("build request")
}

/// The header-routed `/token` endpoint refuses the `LIMIT + 1`-th clientless
/// refresh from the same peer with 429 + `Retry-After`.
#[tokio::test]
async fn clientless_refresh_flood_is_rate_limited_on_token_endpoint() {
    let (state, realm_id, _realm_name) = make_app_state(Some(LIMIT));

    for i in 0..LIMIT {
        let app = http_router(Arc::clone(&state));
        let resp = app
            .oneshot(clientless_refresh_request("/token", &realm_id))
            .await
            .expect("oneshot");
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "request {i} is inside the window and must not be throttled"
        );
    }

    let app = http_router(Arc::clone(&state));
    let resp = app
        .oneshot(clientless_refresh_request("/token", &realm_id))
        .await
        .expect("oneshot");
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a clientless refresh_token grant must still be bucketed — by client IP"
    );
    assert!(
        resp.headers().contains_key("retry-after"),
        "429 must carry Retry-After"
    );
}

/// The realm-scoped twin `/realms/{realm}/token` has the same hole and the
/// same fix.
#[tokio::test]
async fn clientless_refresh_flood_is_rate_limited_on_realm_token_endpoint() {
    let (state, realm_id, realm_name) = make_app_state(Some(LIMIT));
    let uri = format!("/realms/{realm_name}/token");

    for i in 0..LIMIT {
        let app = http_router(Arc::clone(&state));
        let resp = app
            .oneshot(clientless_refresh_request(&uri, &realm_id))
            .await
            .expect("oneshot");
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "request {i} is inside the window and must not be throttled"
        );
    }

    let app = http_router(Arc::clone(&state));
    let resp = app
        .oneshot(clientless_refresh_request(&uri, &realm_id))
        .await
        .expect("oneshot");
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the realm-scoped token endpoint must bucket clientless refreshes too"
    );
}

/// `0` is the "unlimited" sentinel for this limiter (`TokenRateLimiter::
/// disabled()` / `security.load_test_unthrottled`). The IP fallback must
/// honour it rather than reading `0` as "deny everything".
#[tokio::test]
async fn zero_limit_still_means_unlimited_for_the_ip_bucket() {
    let (state, realm_id, _realm_name) = make_app_state(Some(0));

    for i in 0..(LIMIT * 4) {
        let app = http_router(Arc::clone(&state));
        let resp = app
            .oneshot(clientless_refresh_request("/token", &realm_id))
            .await
            .expect("oneshot");
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "limit=0 means unlimited; request {i} must not be throttled"
        );
    }
}
