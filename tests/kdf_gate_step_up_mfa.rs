//! Regression test for HEA-1910.
//!
//! The `step-up-mfa` grant (`urn:hearth:params:grant-type:step-up-mfa`) called
//! `state.identity.step_up_mfa_grant_token(...)` directly in the async handler —
//! neither gated through the shared KDF admission pool nor dispatched via
//! `spawn_blocking`. This meant:
//!
//! 1. A concurrent flood of step-up requests could independently oversubscribe
//!    the blocking pool, falsifying the `permits × 19 MiB` memory ceiling that
//!    the R1 gate (HEA-1889 F3) is meant to enforce server-wide.
//! 2. Argon2id ran on Tokio worker threads directly, degrading the async
//!    runtime including the `validate_token` hot path.
//!
//! This test pins the fix: with the shared process-global gate saturated,
//! a step-up MFA token request at `/token` is **shed** with `503 + Retry-After`
//! — proving the path now routes through the shared admit pool. It also proves
//! the shed is gate-specific: once the permit frees, the same request is no
//! longer a 503 (it fails with a credential error instead, not an admission
//! shed).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    KdfGateConfig,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

/// Builds a REST HTTP rig backed by in-process engines. Returns the axum router
/// and the ID of a pre-created realm to use in `X-Realm-ID` request headers.
fn build_rest_rig() -> (axum::Router, RealmId) {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp); // keep the dir alive for the duration of the test

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "test-realm".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let state = Arc::new(AppState::new_dev(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        Arc::clone(&audit),
    ));
    (router(state), realm_id)
}

async fn post_json(
    app: &axum::Router,
    path: &str,
    realm_id: &RealmId,
    body: serde_json::Value,
) -> (StatusCode, HeaderMap) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("x-realm-id", realm_id.as_uuid().to_string())
                .body(Body::from(
                    serde_json::to_string(&body).expect("serialize body"),
                ))
                .expect("build request"),
        )
        .await
        .expect("send request");
    (resp.status(), resp.headers().clone())
}

/// Saturating the shared KDF gate sheds a step-up MFA `/token` request with
/// `503 + Retry-After`, and the shed lifts once the permit frees — proving the
/// path now routes through the shared admission pool (HEA-1910 fix).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn step_up_mfa_grant_is_shed_when_kdf_gate_is_saturated() {
    // Install a 1-permit gate BEFORE anything touches `gate()`. First call wins
    // the process-global OnceLock; nextest isolates this test in its own process
    // so the tiny bound is deterministic.
    let installed = hearth::identity::init_gate(KdfGateConfig {
        max_in_flight: 1,
        max_queue_wait: Duration::from_millis(40),
        retry_after: Duration::from_secs(2),
    });
    assert!(
        installed,
        "init_gate must win the OnceLock — no earlier gate() call in this process"
    );

    let (app, realm_id) = build_rest_rig();

    // Hold the sole permit for the duration of the probes. The signal fires
    // from *inside* the gated closure, so receiving it proves the permit is
    // already acquired and the gate is provably saturated.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let holder = tokio::spawn(async move {
        let _ = hearth::identity::gate()
            .run(move || {
                let _ = tx.send(());
                // AUDIT: justified-sleep: holds the only KDF permit so the
                // test can verify step-up shedding while the permit is occupied
                std::thread::sleep(Duration::from_millis(1500));
            })
            .await;
    });
    rx.await.expect("holder acquired the only permit");

    // Step-up MFA grant must be shed — it now routes through the shared pool.
    let body = serde_json::json!({
        "client_id": uuid::Uuid::new_v4().to_string(),
        "grant_type": "urn:hearth:params:grant-type:step-up-mfa",
        "username": "flood@example.test",
        "password": "somepassword",
        "mfa_code": "123456"
    });
    let (status, headers) = post_json(&app, "/token", &realm_id, body.clone()).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "step-up MFA grant must be shed with 503 by the saturated KDF gate, \
         not run ungated and block a Tokio worker"
    );
    assert!(
        headers.contains_key(axum::http::header::RETRY_AFTER),
        "shed step-up MFA grant must carry a Retry-After header"
    );

    // Release the permit and confirm the shed was gate-specific: the same
    // request is no longer a 503 once capacity is available. It will fail
    // with a credential error (401/400 — the user doesn't exist), never 503.
    holder.await.expect("holder task joins");
    let (status_free, _) = post_json(&app, "/token", &realm_id, body).await;
    assert_ne!(
        status_free,
        StatusCode::SERVICE_UNAVAILABLE,
        "with a free permit the step-up grant must not 503 — the shed came \
         from the gate, not an unrelated failure"
    );
}
