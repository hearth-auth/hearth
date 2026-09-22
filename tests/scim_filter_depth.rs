#![allow(clippy::unwrap_used)]
//! Audit §4.6#1 regression: a deeply nested SCIM filter used to overflow the
//! stack and abort the whole multi-tenant process.
//!
//! `parse_factor` recursed into `parse_or` once per `(` with no bound, so a
//! single ~6 KB authenticated request took the server down on both `/Users`
//! and `/Groups`. The parser now refuses a filter longer than
//! `MAX_FILTER_LEN` and parentheses nested deeper than `MAX_FILTER_DEPTH`.
//!
//! Each test also issues a plain request afterwards, so a pass proves the
//! server survived rather than that the request merely failed.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    RealmConfig, UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::protocol::scim::filter::{MAX_FILTER_DEPTH, MAX_FILTER_LEN};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const SCIM_TOKEN: &str = "super-secret-scim-service-account-token-32chars";

struct Rig {
    app: axum::Router,
    realm_id: RealmId,
    _storage: Arc<EmbeddedStorageEngine>,
    _dir: tempfile::TempDir,
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn build_rig() -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open"));
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    );
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "scim-filter-depth".to_string(),
            config: None,
        })
        .expect("create realm");
    identity
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    scim_bearer_token_hash: Some(sha256_hex(SCIM_TOKEN)),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("configure scim token");

    let realm_id = realm.id().clone();
    let state = Arc::new(AppState::new(identity, authz, audit));
    Rig {
        app: router(state),
        realm_id,
        _storage: engine,
        _dir: dir,
    }
}

/// `GET` a SCIM collection with the given raw filter string.
async fn get_with_filter(rig: &Rig, collection: &str, filter: &str) -> (StatusCode, Value) {
    let encoded: String = filter
        .chars()
        .map(|c| match c {
            '(' => "%28".to_string(),
            ')' => "%29".to_string(),
            ' ' => "%20".to_string(),
            '"' => "%22".to_string(),
            other => other.to_string(),
        })
        .collect();
    let req = Request::builder()
        .method("GET")
        .uri(format!("/scim/v2/{collection}?filter={encoded}"))
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .header("authorization", format!("Bearer {SCIM_TOKEN}"))
        .body(Body::empty())
        .expect("build request");

    let resp = rig.app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

/// A plain unfiltered list, used to prove the server is still serving.
async fn assert_still_serving(rig: &Rig, collection: &str) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/scim/v2/{collection}"))
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .header("authorization", format!("Bearer {SCIM_TOKEN}"))
        .body(Body::empty())
        .expect("build request");
    let resp = rig.app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "{collection} stopped serving"
    );
}

async fn deep_filter_is_refused(collection: &str) {
    let rig = build_rig();

    // Under MAX_FILTER_LEN, so the depth guard is what refuses it.
    let nested = "(".repeat(MAX_FILTER_LEN - 1);
    let (status, body) = get_with_filter(&rig, collection, &nested).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["scimType"], "invalidFilter");
    assert_still_serving(&rig, collection).await;

    // The audit's own ~6 KB shape, refused by the length guard.
    let long = "(".repeat(6 * 1024);
    let (status, body) = get_with_filter(&rig, collection, &long).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["scimType"], "invalidFilter");
    assert_still_serving(&rig, collection).await;
}

#[tokio::test]
async fn deep_filter_on_users_is_refused_and_the_server_survives() {
    deep_filter_is_refused("Users").await;
}

#[tokio::test]
async fn deep_filter_on_groups_is_refused_and_the_server_survives() {
    deep_filter_is_refused("Groups").await;
}

/// The bound is on nesting, not on filtering: a filter at the permitted depth
/// is still served.
#[tokio::test]
async fn a_filter_at_the_permitted_depth_is_served() {
    let rig = build_rig();
    let filter = format!(
        "{}userName pr{}",
        "(".repeat(MAX_FILTER_DEPTH),
        ")".repeat(MAX_FILTER_DEPTH)
    );
    let (status, _) = get_with_filter(&rig, "Users", &filter).await;
    assert_eq!(status, StatusCode::OK);
}
