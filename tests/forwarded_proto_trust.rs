//! GA audit 2026-09-28 L4 — `X-Forwarded-Proto` was trusted from any peer.
//!
//! With `server.trust_forwarded_proto: true`, `WebState::is_secure_request`
//! (the `Secure` cookie attribute, the login Origin check) and the HSTS layer
//! read the header whatever TCP peer sent it. `server.trusted_proxies` was
//! consulted only for `X-Forwarded-For`, so a client that reached the listener
//! directly — around the proxy — chose for itself whether its responses were
//! treated as HTTPS. The comments claiming the header "came through a proxy
//! the operator named" were false at runtime.
//!
//! The header is now honoured only when the connection's peer is listed in
//! `server.trusted_proxies`.

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use hearth::core::TrustedProxies;
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::protocol::http::{router_with, AppState};
use hearth::protocol::web::{self, CookieSecret, WebState};
use tower::ServiceExt;

const PROXY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
const DIRECT_CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

async fn app(h: &common::TestHarness) -> axum::Router {
    app_trusting(h, &["10.0.0.7"]).await
}

/// The app with `server.trusted_proxies` set to `trusted`.
async fn app_trusting(h: &common::TestHarness, trusted: &[&str]) -> axum::Router {
    let trusted = TrustedProxies::parse(trusted).expect("valid trusted_proxies");
    let email = Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    let data_dir = tempfile::tempdir().expect("tempdir").keep();
    let onboarding = Arc::new(OnboardingService::new(
        h.identity_arc(),
        h.rbac_arc(),
        email,
        data_dir,
    ));
    let web_state = WebState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        onboarding,
        CookieSecret::random(),
        None,
    )
    .with_trust_forwarded_proto(true)
    .with_trusted_proxies(trusted.clone());
    let app_state =
        AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()).with_trusted_proxies(trusted);
    router_with(Arc::new(app_state), web::router(web_state))
}

/// Requests the admin login page from `peer` claiming HTTPS, and reports
/// whether the response treated the request as secure (HSTS emitted).
async fn hsts_for(app: axum::Router, peer: IpAddr) -> bool {
    let request = Request::builder()
        .uri("/ui/admin/login")
        .header("host", "localhost")
        .header("x-forwarded-proto", "https")
        .extension(ConnectInfo(SocketAddr::new(peer, 40000)))
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    response.headers().contains_key("strict-transport-security")
}

#[tokio::test]
async fn forwarded_proto_from_a_peer_that_is_not_a_trusted_proxy_is_ignored() {
    let h = common::TestHarness::embedded().await.expect("harness");
    assert!(
        !hsts_for(app(&h).await, DIRECT_CLIENT).await,
        "a client that is not a trusted proxy set X-Forwarded-Proto: https and got HSTS — \
         it decided for itself that its request arrived over HTTPS"
    );
}

/// The control: the same header from the named proxy is honoured, so the test
/// above cannot pass merely because HSTS is never emitted.
#[tokio::test]
async fn forwarded_proto_from_a_trusted_proxy_is_honoured() {
    let h = common::TestHarness::embedded().await.expect("harness");
    assert!(
        hsts_for(app(&h).await, PROXY).await,
        "X-Forwarded-Proto: https from a trusted proxy must still be honoured"
    );
}

// ── CIDR trusted_proxies (G3) ───────────────────────────────────────────────
//
// Ingress-controller pod IPs change on reschedule, so operators list a range.
// The header check must use the same range match as the X-Forwarded-For walk.

/// A peer anywhere inside a trusted CIDR is a proxy: its header is honoured.
#[tokio::test]
async fn forwarded_proto_from_a_peer_inside_a_trusted_cidr_is_honoured() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = app_trusting(&h, &["10.42.0.0/16"]).await;
    assert!(
        hsts_for(app, IpAddr::V4(Ipv4Addr::new(10, 42, 200, 3))).await,
        "a peer inside server.trusted_proxies' CIDR range is a trusted proxy"
    );
}

/// One address past the range is an ordinary client: its header is removed.
#[tokio::test]
async fn forwarded_proto_from_a_peer_outside_a_trusted_cidr_is_ignored() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = app_trusting(&h, &["10.42.0.0/16"]).await;
    assert!(
        !hsts_for(app, IpAddr::V4(Ipv4Addr::new(10, 43, 0, 0))).await,
        "a peer outside the trusted range set X-Forwarded-Proto: https and got HSTS"
    );
}

/// IPv6 ranges and dual-stack (`::ffff:a.b.c.d`) peers use the same match.
#[tokio::test]
async fn forwarded_proto_honours_ipv6_and_v4_mapped_peers_by_range() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let trusted = ["2001:db8:42::/48", "10.42.0.0/16"];
    let v6_in: IpAddr = "2001:db8:42::9".parse().expect("ip");
    let v6_out: IpAddr = "2001:db8:43::9".parse().expect("ip");
    let mapped_in: IpAddr = "::ffff:10.42.0.9".parse().expect("ip");
    assert!(hsts_for(app_trusting(&h, &trusted).await, v6_in).await);
    assert!(!hsts_for(app_trusting(&h, &trusted).await, v6_out).await);
    assert!(hsts_for(app_trusting(&h, &trusted).await, mapped_in).await);
}
