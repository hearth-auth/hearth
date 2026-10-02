#![allow(clippy::unwrap_used)]
//! GA sweep 3, review E — network-edge limiter findings.
//!
//! * E-1: the HTTP request shaper's "per-realm" bucket was one server-wide
//!   bucket (`""`), so ~10 addresses at the per-IP cap starved every tenant.
//! * E-2: every limiter map grew without bound. (Its gRPC realm-key half
//!   went with the public gRPC API; the HTTP half is pinned by
//!   `e1_admin_realm_bucket_is_keyed_by_a_uuid_x_realm_id`.)
//! * E-3: every per-IP limiter keyed on the full IPv6 address, so one host
//!   with a routed `/64` had 2^64 fresh budgets.
//! * E-6: the raw request method was a Prometheus label, so every invented
//!   method added a series for the life of the process.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::abuse::shaper::{RequestShaper, ShaperConfig};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

/// A `oneshot` request from an explicit peer, so the shaper sees a real
/// `ConnectInfo` rather than the loopback fallback.
fn request_from(method: &str, uri: &str, peer: &str, realm_header: Option<&str>) -> Request<Body> {
    let peer: SocketAddr = peer.parse().expect("peer");
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(realm) = realm_header {
        builder = builder.header("x-realm-id", realm);
    }
    let mut req = builder.body(Body::empty()).expect("request");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    req
}

async fn state_with(shaper: ShaperConfig) -> Arc<AppState> {
    let h = common::TestHarness::embedded().await.unwrap();
    Arc::new(
        AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())
            .with_request_shaper(Arc::new(RequestShaper::with_config(shaper))),
    )
}

async fn status_of(state: &Arc<AppState>, req: Request<Body>) -> StatusCode {
    router(Arc::clone(state))
        .oneshot(req)
        .await
        .unwrap()
        .status()
}

// ── E-1: the realm dimension is keyed by the resolved realm, never shared ────

/// Requests that name no realm (`/health`, discovery at the root) must not be
/// counted in one shared bucket: with `realm_rps = 2`, a third caller from a
/// different address was answered 429 by a bucket nobody could name.
#[tokio::test]
async fn e1_unknown_realm_requests_do_not_share_one_server_wide_bucket() {
    let state = state_with(ShaperConfig {
        ip_rps: None,
        realm_rps: Some(2),
    })
    .await;

    for i in 0..3 {
        let status = status_of(
            &state,
            request_from("GET", "/health", "203.0.113.1:4000", None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "request {i} from peer A must pass");
    }
    let status = status_of(
        &state,
        request_from("GET", "/health", "203.0.113.2:4000", None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a realm-less request from another peer must not be shed by a shared bucket"
    );
}

/// On a `/realms/{name}` route the bucket is that realm's, so one realm's
/// budget is spent only by calls to that realm.
#[tokio::test]
async fn e1_realm_bucket_is_keyed_by_the_path_realm() {
    let state = state_with(ShaperConfig {
        ip_rps: None,
        realm_rps: Some(1),
    })
    .await;
    let alpha = "/realms/alpha/.well-known/openid-configuration";
    let beta = "/realms/beta/.well-known/openid-configuration";

    let first = status_of(&state, request_from("GET", alpha, "203.0.113.1:4000", None)).await;
    assert_ne!(
        first,
        StatusCode::TOO_MANY_REQUESTS,
        "alpha's first call is in budget"
    );
    let second = status_of(&state, request_from("GET", alpha, "203.0.113.2:4000", None)).await;
    assert_eq!(
        second,
        StatusCode::TOO_MANY_REQUESTS,
        "alpha's second call (from any peer) exceeds alpha's 1 rps budget"
    );
    let other = status_of(&state, request_from("GET", beta, "203.0.113.3:4000", None)).await;
    assert_ne!(
        other,
        StatusCode::TOO_MANY_REQUESTS,
        "beta has its own budget — alpha's callers must not spend it"
    );
    let root = status_of(
        &state,
        request_from("GET", "/health", "203.0.113.4:4000", None),
    )
    .await;
    assert_eq!(
        root,
        StatusCode::OK,
        "a realm-less route is outside every realm bucket"
    );
}

/// On the admin API the realm is the `X-Realm-ID` header; a value that is not
/// a UUID names no realm and opens no bucket.
#[tokio::test]
async fn e1_admin_realm_bucket_is_keyed_by_a_uuid_x_realm_id() {
    let state = state_with(ShaperConfig {
        ip_rps: None,
        realm_rps: Some(1),
    })
    .await;
    let realm_a = "11111111-1111-1111-1111-111111111111";
    let realm_b = "22222222-2222-2222-2222-222222222222";

    let first = status_of(
        &state,
        request_from("GET", "/admin/realms", "203.0.113.1:4000", Some(realm_a)),
    )
    .await;
    assert_ne!(first, StatusCode::TOO_MANY_REQUESTS);
    let second = status_of(
        &state,
        request_from("GET", "/admin/realms", "203.0.113.2:4000", Some(realm_a)),
    )
    .await;
    assert_eq!(
        second,
        StatusCode::TOO_MANY_REQUESTS,
        "realm A's budget is spent"
    );
    let other = status_of(
        &state,
        request_from("GET", "/admin/realms", "203.0.113.3:4000", Some(realm_b)),
    )
    .await;
    assert_ne!(
        other,
        StatusCode::TOO_MANY_REQUESTS,
        "realm B has its own budget"
    );

    // A garbage header is not a realm: three calls, none shed, no bucket.
    for _ in 0..3 {
        let status = status_of(
            &state,
            request_from(
                "GET",
                "/admin/realms",
                "203.0.113.4:4000",
                Some("not-a-realm"),
            ),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "an unparseable X-Realm-ID must not open (or share) a realm bucket"
        );
    }
    assert_eq!(
        state.request_shaper.realm_bucket_count(),
        2,
        "only the two real realm ids may hold a bucket"
    );
}

// ── E-3: IPv6 peers are bucketed per /64 ────────────────────────────────────

/// Two addresses inside one `/64` are one host and share one per-IP bucket; an
/// address in another `/64` does not.
#[tokio::test]
async fn e3_two_ipv6_peers_in_one_slash64_share_the_per_ip_bucket() {
    let state = state_with(ShaperConfig {
        ip_rps: Some(1),
        realm_rps: None,
    })
    .await;

    let first = status_of(
        &state,
        request_from("GET", "/health", "[2001:db8::1]:4000", None),
    )
    .await;
    assert_eq!(first, StatusCode::OK);
    let sibling = status_of(
        &state,
        request_from("GET", "/health", "[2001:db8::2]:4000", None),
    )
    .await;
    assert_eq!(
        sibling,
        StatusCode::TOO_MANY_REQUESTS,
        "a second address in the same /64 must share the first one's budget"
    );
    let other_host = status_of(
        &state,
        request_from("GET", "/health", "[2001:db8:0:1::1]:4000", None),
    )
    .await;
    assert_eq!(
        other_host,
        StatusCode::OK,
        "an address in a different /64 is a different host"
    );
}

/// The per-IP login limit (hosted login, `/token` password grant, the
/// magic-link request) keyed on the full address: fifty addresses in one `/64`
/// were fifty budgets. They are one client.
#[tokio::test]
async fn e3_login_per_ip_limit_counts_an_ipv6_slash64_as_one_client() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    let identity = h.identity_arc();

    for i in 1..=50u16 {
        identity.record_ip_login_attempt(&realm, &format!("2001:db8:77:1::{i:x}"));
    }
    assert!(
        matches!(
            identity.check_ip_login_rate_limit(&realm, "2001:db8:77:1:ffff::1"),
            Err(hearth::identity::IdentityError::RateLimited)
        ),
        "fifty failures from one /64 must trip the per-IP login limit"
    );
    assert!(
        matches!(
            identity.check_ip_login_rate_limit(&realm, "2001:db8:77:2::1"),
            Ok(())
        ),
        "a different /64 is a different client"
    );
}

// ── E-6: the method label is a closed set ───────────────────────────────────

/// An invented method reaches the 405 fallback through the metrics
/// `route_layer`, so the raw method became a label value and a new series.
#[tokio::test]
async fn e6_an_unknown_http_method_does_not_create_a_metric_series() {
    let state = state_with(ShaperConfig {
        ip_rps: None,
        realm_rps: None,
    })
    .await;

    for i in 0..3 {
        let method = format!("GA3PROBE{i}");
        let status = status_of(
            &state,
            request_from(&method, "/health", "203.0.113.1:4000", None),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "an unknown method is a 405"
        );
    }
    let ok = status_of(
        &state,
        request_from("GET", "/health", "203.0.113.1:4000", None),
    )
    .await;
    assert_eq!(ok, StatusCode::OK);

    // Render, never `get_metric_with_label_values` — that would create the
    // series this test asserts is absent.
    let rendered = hearth::metrics::metrics().render();
    assert!(
        !rendered.contains("method=\"GA3PROBE"),
        "a request-controlled method must never become a label value"
    );
    assert!(
        rendered.contains("method=\"OTHER\""),
        "unknown methods are folded into the fixed OTHER label"
    );
    assert!(
        rendered.contains("method=\"GET\",route=\"/health\""),
        "known methods keep their own label"
    );
}
