//! Black-box security-property tests for the admin REST boundary (HEA-1834).
//!
//! Covers Phase 2 matrix (HEA-1818) ranked gaps 1 & 5:
//!
//! | Security claim | Test |
//! |---|---|
//! | Admin resource lookup does not leak existence to unauthenticated callers (enumeration timing, TEST_SCENARIOS §674) | `admin_user_lookup_does_not_leak_existence_unauthenticated` |
//! | The global HTTP rate limiter also guards `/admin/*` routes (§673) | `admin_route_enforces_rate_limit_429` |
//!
//! ## Timing methodology
//!
//! The repository's established stance (see `tests/adversarial.rs` and
//! `tests/security_f10_f17.rs`) is that fine-grained side-channel timing cannot
//! be proven in an in-process unit test — jitter dominates. Enumeration
//! resistance is therefore asserted **behaviorally**: the existing-id and
//! nonexistent-id paths must return the *identical* status and body, so there is
//! no observable oracle. An `Instant`/`elapsed` measurement is added as a
//! *coarse* gross-oracle guard (generous ratio bound) to catch a regression
//! that short-circuits auth work on a miss — it is intentionally loose, not a
//! constant-time proof.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::abuse::shaper::{RequestShaper, ShaperConfig};
use hearth::core::RealmId;
use hearth::identity::{CreateRealmRequest, CreateUserRequest};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

async fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

fn create_realm(harness: &common::TestHarness) -> RealmId {
    harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("admin-sec-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    String::from_utf8_lossy(&bytes).into_owned()
}

// ===== Gap 1: admin lookup enumeration resistance (TEST_SCENARIOS §674) =====

/// An unauthenticated GET of an admin user resource must be indistinguishable
/// between an id that exists and one that does not — same status, same body —
/// so an attacker cannot enumerate valid user ids through the admin API.
#[tokio::test]
async fn admin_user_lookup_does_not_leak_existence_unauthenticated() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&harness);

    let existing = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("victim-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Victim".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
        .id()
        .clone();
    let existing_path = format!("/admin/users/{}", existing.as_uuid());
    let missing_path = format!("/admin/users/{}", uuid::Uuid::new_v4());

    // Behavioral oracle check: existing vs nonexistent must be identical.
    let hit = build_app(&harness)
        .await
        .oneshot(
            Request::builder()
                .uri(&existing_path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let miss = build_app(&harness)
        .await
        .oneshot(
            Request::builder()
                .uri(&missing_path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let hit_status = hit.status();
    let miss_status = miss.status();
    assert_eq!(
        hit_status, miss_status,
        "existing and nonexistent user ids must return the same status to an \
         unauthenticated caller (enumeration oracle)"
    );
    // Must be a client-error rejection that runs before the existence check.
    // A 200 (found) or 404 (not-found) would itself be the enumeration oracle.
    assert!(
        hit_status.is_client_error()
            && hit_status != StatusCode::NOT_FOUND
            && hit_status != StatusCode::OK,
        "unauthenticated admin lookup must be rejected before existence check \
         (not a 200/404 that reveals existence), got {hit_status}"
    );
    let hit_body = body_string(hit).await;
    let miss_body = body_string(miss).await;
    assert_eq!(
        hit_body, miss_body,
        "response body must not reveal whether the user id exists"
    );

    // Coarse gross-oracle timing guard (see module docs — intentionally loose).
    let median_hit = median_latency(&harness, &existing_path).await;
    let median_miss = median_latency(&harness, &missing_path).await;
    let (lo, hi) = if median_hit <= median_miss {
        (median_hit, median_miss)
    } else {
        (median_miss, median_hit)
    };
    // Guard only against an order-of-magnitude oracle; jitter forbids a tight bound.
    if lo > Duration::from_micros(1) {
        let ratio = hi.as_secs_f64() / lo.as_secs_f64();
        assert!(
            ratio < 20.0,
            "hit/miss admin-lookup latency differs by {ratio:.1}× (hit={median_hit:?}, \
             miss={median_miss:?}) — possible enumeration timing oracle"
        );
    }
}

/// Median wall-clock latency of an unauthenticated GET over `iters` samples.
async fn median_latency(harness: &common::TestHarness, path: &str) -> Duration {
    const ITERS: usize = 41;
    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let app = build_app(harness).await;
        let start = Instant::now();
        let _ = app
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        samples.push(start.elapsed());
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

// ===== Gap 4: admin routes are covered by the global rate limiter (§673) =====

/// The per-IP HTTP rate limiter is a `route_layer` on every matched route,
/// including `/admin/*`. Exceeding the limit on an admin route must return
/// HTTP 429 — the limiter runs before auth, so this holds even for an
/// unauthenticated caller (a matched admin route still consumes shaper budget).
#[tokio::test]
async fn admin_route_enforces_rate_limit_429() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let shaper = Arc::new(RequestShaper::with_config(ShaperConfig {
        ip_rps: Some(1),
        realm_rps: None,
    }));
    let state = Arc::new(
        AppState::new(
            harness.identity_arc(),
            harness.rbac_arc(),
            harness.audit_arc(),
        )
        .with_request_shaper(Arc::clone(&shaper)),
    );

    // First admin request is within the limit — rejected by auth (not the limiter).
    let first = router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .uri("/admin/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        first.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "first admin request must pass the rate limiter"
    );

    // Second admin request from the same IP exceeds the 1 rps limit.
    let second = router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .uri("/admin/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "admin route must be rate-limited with HTTP 429 once the per-IP limit is exceeded"
    );
    assert_eq!(
        second
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok()),
        Some("1"),
        "429 on admin route must carry Retry-After: 1"
    );
}
