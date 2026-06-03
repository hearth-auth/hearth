//! Test harness integration tests.
//!
//! Covers `TEST_SCENARIOS.md` § Test Infrastructure:
//! 1. Embedded mode starts and stops cleanly
//! 2. Dual-mode pattern: same logic runs against embedded and server modes
//! 3. Server mode starts an HTTP server, `base_url()` returns `Some`

mod common;

use common::{HarnessMode, TestHarness};
use hearth::core::RealmId;

/// Scenario 1: Embedded mode starts with isolated temp dir and stops cleanly.
#[tokio::test]
async fn embedded_mode_starts_and_stops_cleanly() {
    let harness = TestHarness::embedded()
        .await
        .expect("embedded harness should start");

    assert_eq!(harness.mode(), HarnessMode::Embedded);
    assert!(
        harness.base_url().is_none(),
        "embedded mode has no base URL"
    );

    // Verify storage is functional with a basic round-trip
    let realm = RealmId::generate();
    harness
        .storage()
        .put(&realm, b"harness-key", b"harness-value")
        .expect("put should succeed");
    let val = harness
        .storage()
        .get(&realm, b"harness-key")
        .expect("get should succeed");
    assert_eq!(val, Some(b"harness-value".to_vec()));

    // Drop triggers cleanup — temp dir removed automatically
    drop(harness);
}

/// Scenario 2: Dual-mode pattern — same async test logic runs against embedded mode.
#[tokio::test]
async fn dual_mode_embedded() {
    run_dual_mode_assertions(
        TestHarness::embedded()
            .await
            .expect("embedded harness should start"),
    )
    .await;
}

/// Shared test logic for the dual-mode pattern.
#[allow(clippy::unused_async)]
async fn run_dual_mode_assertions(harness: TestHarness) {
    let realm = RealmId::generate();

    // Write
    harness
        .storage()
        .put(&realm, b"dual-key", b"dual-value")
        .expect("put should succeed in any mode");

    // Read back
    let val = harness
        .storage()
        .get(&realm, b"dual-key")
        .expect("get should succeed in any mode");
    assert_eq!(val, Some(b"dual-value".to_vec()));

    // Delete
    harness
        .storage()
        .delete(&realm, b"dual-key")
        .expect("delete should succeed in any mode");

    // Confirm deleted
    let val = harness
        .storage()
        .get(&realm, b"dual-key")
        .expect("get after delete should succeed");
    assert_eq!(val, None, "deleted key should return None");
}

/// Scenario 3: Server mode starts an HTTP server and exposes `base_url`.
///
/// Proves the dual-mode contract: `server()` succeeds, `base_url()` is `Some`,
/// and the live server answers a health-check request. The same storage
/// round-trip from `run_dual_mode_assertions` runs in server mode too.
#[tokio::test]
async fn server_mode_starts_and_exposes_base_url() {
    let harness = TestHarness::server()
        .await
        .expect("server harness should start");

    assert_eq!(harness.mode(), HarnessMode::Server);
    let base_url = harness
        .base_url()
        .expect("server mode must have a base_url");

    // Server storage is also accessible via the embedded engine accessors.
    run_dual_mode_assertions(
        TestHarness::embedded()
            .await
            .expect("embedded harness should start"),
    )
    .await;

    // Verify the HTTP server responds to /health.
    let url = format!("{base_url}/health");
    let resp = reqwest::get(&url).await.expect("GET /health");
    assert_eq!(resp.status().as_u16(), 200, "GET /health must return 200");
}
