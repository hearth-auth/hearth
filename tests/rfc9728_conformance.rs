//! RFC 9728 Protected Resource Metadata — conformance fixtures.
//!
//! Validates the `/.well-known/oauth-protected-resource` document shape
//! against `tests/fixtures/rfc9728/conformance_vectors.json`.
//!
//! Coverage:
//! - Endpoint returns HTTP 200 with `Content-Type: application/json`
//! - Required fields present: `resource`, `authorization_servers` (RFC 9728 §3)
//! - Recommended fields present: `jwks_uri`, `scopes_supported`,
//!   `bearer_methods_supported`, `resource_signing_alg_values_supported`
//! - All MCP scopes from fixture are listed in `scopes_supported`
//! - `authorization_servers` is a non-empty JSON array
//! - `bearer_methods_supported` contains only RFC-allowed values
//!
//! Spec refs: RFC 9728 §3
//! Test vectors: tests/fixtures/rfc9728/conformance_vectors.json

#![allow(clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt as _;

use hearth::audit::EmbeddedAuditEngine;
use hearth::core::SystemClock;
use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine};
use hearth::protocol::http::{router as http_router, AppState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine, SvBumper};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

const VECTORS: &str = include_str!("fixtures/rfc9728/conformance_vectors.json");

/// Build a minimal AppState (no realm, no config needed for the PRM endpoint).
fn make_app_state() -> Arc<AppState> {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage =
        Arc::new(EmbeddedStorageEngine::open(StorageConfig::dev(data_dir)).expect("storage"));
    let clock = Arc::new(SystemClock) as Arc<dyn hearth::core::Clock>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let identity_concrete = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&rbac) as Arc<dyn RbacEngine>,
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    );

    rbac.init_sv_bumper(Arc::clone(&identity_concrete) as Arc<dyn SvBumper>);

    let identity = Arc::clone(&identity_concrete) as Arc<dyn IdentityEngine>;
    Arc::new(AppState::new_dev(identity, rbac, audit))
}

// ── Fixture structure ─────────────────────────────────────────────────────────

/// Fixture JSON parses and lists required + recommended field names.
#[test]
fn fixture_parses_and_lists_fields() {
    let doc: Value = serde_json::from_str(VECTORS).expect("parse rfc9728 fixture JSON");
    let required = doc["required_fields"].as_array().expect("required_fields");
    let recommended = doc["recommended_fields"]
        .as_array()
        .expect("recommended_fields");

    // Spot-check the two normative required fields from RFC 9728 §3.
    let required_names: Vec<&str> = required
        .iter()
        .map(|v| v["field"].as_str().unwrap())
        .collect();
    assert!(
        required_names.contains(&"resource"),
        "fixture must list 'resource' as required"
    );
    assert!(
        required_names.contains(&"authorization_servers"),
        "fixture must list 'authorization_servers' as required"
    );

    // All recommended fields should be named.
    assert!(
        !recommended.is_empty(),
        "fixture should document recommended fields"
    );
}

// ── HTTP response shape ───────────────────────────────────────────────────────

/// PRM endpoint returns HTTP 200 with application/json Content-Type.
#[tokio::test]
async fn prm_endpoint_returns_200_json() {
    let app = http_router(make_app_state());

    let resp = app
        .oneshot(
            Request::get("/.well-known/oauth-protected-resource")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PRM endpoint must return 200 OK"
    );

    let ct = resp
        .headers()
        .get("content-type")
        .expect("Content-Type header missing")
        .to_str()
        .expect("Content-Type not UTF-8");
    assert!(
        ct.contains("application/json"),
        "Content-Type must be application/json; got '{ct}'"
    );
}

/// RFC 9728 §3 REQUIRED fields are all present in the response.
#[tokio::test]
async fn prm_required_fields_present() {
    let doc: Value = serde_json::from_str(VECTORS).expect("parse fixture");
    let required_fields: Vec<&str> = doc["required_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["field"].as_str().unwrap())
        .collect();

    let app = http_router(make_app_state());
    let resp = app
        .oneshot(
            Request::get("/.well-known/oauth-protected-resource")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 64)
        .await
        .expect("read body");
    let prm: Value = serde_json::from_slice(&body_bytes).expect("parse PRM JSON");

    for field in &required_fields {
        let val = prm.get(*field).unwrap_or(&Value::Null);
        assert!(
            !val.is_null(),
            "RFC 9728 REQUIRED field '{field}' missing from PRM document"
        );
    }

    // `authorization_servers` must be a non-empty array.
    let as_arr = prm["authorization_servers"]
        .as_array()
        .expect("authorization_servers must be an array");
    assert!(
        !as_arr.is_empty(),
        "authorization_servers must contain at least one entry"
    );
}

/// RFC 9728 §3 RECOMMENDED fields are present in the Hearth PRM document.
#[tokio::test]
async fn prm_recommended_fields_present() {
    let doc: Value = serde_json::from_str(VECTORS).expect("parse fixture");
    let recommended_fields: Vec<&str> = doc["recommended_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["field"].as_str().unwrap())
        .collect();

    let app = http_router(make_app_state());
    let resp = app
        .oneshot(
            Request::get("/.well-known/oauth-protected-resource")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 64)
        .await
        .expect("read body");
    let prm: Value = serde_json::from_slice(&body_bytes).expect("parse PRM JSON");

    for field in &recommended_fields {
        let val = prm.get(*field).unwrap_or(&Value::Null);
        assert!(
            !val.is_null(),
            "RFC 9728 RECOMMENDED field '{field}' should be present in Hearth's PRM document"
        );
    }
}

/// All MCP scopes listed in the fixture appear in `scopes_supported`.
#[tokio::test]
async fn prm_mcp_scopes_all_present_in_scopes_supported() {
    let doc: Value = serde_json::from_str(VECTORS).expect("parse fixture");
    let expected_scopes: Vec<&str> = doc["mcp_scopes_required_in_response"]
        .as_array()
        .expect("mcp_scopes_required_in_response")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    let app = http_router(make_app_state());
    let resp = app
        .oneshot(
            Request::get("/.well-known/oauth-protected-resource")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 64)
        .await
        .expect("read body");
    let prm: Value = serde_json::from_slice(&body_bytes).expect("parse PRM JSON");

    let scopes_supported: Vec<&str> = prm["scopes_supported"]
        .as_array()
        .expect("scopes_supported must be an array")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    for scope in expected_scopes {
        assert!(
            scopes_supported.contains(&scope),
            "MCP scope '{scope}' must be in scopes_supported; got: {scopes_supported:?}"
        );
    }
}

/// `bearer_methods_supported` only contains RFC-valid values (header, form, query).
#[tokio::test]
async fn prm_bearer_methods_are_rfc_valid() {
    let doc: Value = serde_json::from_str(VECTORS).expect("parse fixture");
    let valid_methods: Vec<&str> = doc["bearer_methods_valid_values"]
        .as_array()
        .expect("bearer_methods_valid_values")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    let app = http_router(make_app_state());
    let resp = app
        .oneshot(
            Request::get("/.well-known/oauth-protected-resource")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 64)
        .await
        .expect("read body");
    let prm: Value = serde_json::from_slice(&body_bytes).expect("parse PRM JSON");

    let methods = prm["bearer_methods_supported"]
        .as_array()
        .expect("bearer_methods_supported must be an array");

    for method in methods {
        let m = method.as_str().unwrap();
        assert!(
            valid_methods.contains(&m),
            "bearer method '{m}' is not a valid RFC value; allowed: {valid_methods:?}"
        );
    }
}
