//! Client information extraction from HTTP requests.
//!
//! Extracts the client IP address (with trusted proxy support) and parses
//! the `User-Agent` header into a human-readable device label for session
//! metadata display.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::HeaderMap;

use crate::identity::SessionContext;

/// Fallback peer address when [`ConnectInfo`] is not available — e.g. tests
/// that exercise handlers via `tower::oneshot` without
/// `into_make_service_with_connect_info`.
pub const FALLBACK_PEER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

/// Axum extractor that resolves the real peer [`SocketAddr`].
///
/// Reads the connection address from `ConnectInfo<SocketAddr>` when available
/// (production and full-server integration tests), and silently falls back to
/// [`FALLBACK_PEER`] when the extension is absent (unit tests using
/// `tower::oneshot`). Always infallible — never returns an extraction error.
pub struct PeerAddr(pub SocketAddr);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerAddr {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Infallible> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0)
            .unwrap_or(FALLBACK_PEER);
        Ok(PeerAddr(peer))
    }
}

/// Extracts the client's IP address from the request.
///
/// `X-Forwarded-For` is honored **only** when the immediate peer is listed in
/// `trusted_proxies` — from any other peer the header is attacker-controlled
/// and is ignored entirely (HEA-2165). An empty `trusted_proxies` list
/// therefore fails closed: the peer (socket) IP is always used.
///
/// When the peer is a trusted proxy, walks the `X-Forwarded-For` header
/// right-to-left and returns the first IP that is NOT in the trusted set
/// ("rightmost non-trusted", per OWASP). An unparseable hop stops the walk
/// and falls back to the peer, since everything to its left is unverifiable.
///
/// All returned addresses are canonicalized (`::ffff:a.b.c.d` → `a.b.c.d`) so
/// the same client cannot occupy two per-IP rate-limit buckets.
pub fn extract_client_ip(
    headers: &HeaderMap,
    peer: SocketAddr,
    trusted_proxies: &[IpAddr],
) -> String {
    // Fail closed: XFF is only meaningful when the immediate peer is a
    // reverse proxy we explicitly trust.
    if !is_trusted(peer.ip(), trusted_proxies) {
        return peer.ip().to_canonical().to_string();
    }

    // Parse X-Forwarded-For (comma-separated, rightmost = closest proxy)
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Walk right-to-left, find the first non-trusted hop
    for ip_str in xff.rsplit(',').map(str::trim).filter(|s| !s.is_empty()) {
        match ip_str.parse::<IpAddr>() {
            Ok(ip) if is_trusted(ip, trusted_proxies) => {}
            Ok(ip) => return ip.to_canonical().to_string(),
            // Everything left of an unparseable hop is unverifiable — stop
            // the walk and fail closed to the peer.
            Err(_) => return peer.ip().to_canonical().to_string(),
        }
    }

    // All IPs in XFF are trusted (or XFF is empty) — fall back to peer
    peer.ip().to_canonical().to_string()
}

/// Compares canonicalized so a v4-mapped v6 peer (`::ffff:10.0.0.1` on a
/// dual-stack listener) matches a `10.0.0.1` trusted-proxy entry.
fn is_trusted(ip: IpAddr, trusted_proxies: &[IpAddr]) -> bool {
    let ip = ip.to_canonical();
    trusted_proxies.iter().any(|t| t.to_canonical() == ip)
}

/// Parses a `User-Agent` string into a human-readable device label.
///
/// Returns `Some("Browser, OS")` on success, or `None` for empty/unrecognizable UAs.
pub fn parse_device_label(ua: Option<&str>) -> Option<String> {
    let ua_str = ua?;
    if ua_str.is_empty() {
        return None;
    }

    let parser = woothee::parser::Parser::new();
    let result = parser.parse(ua_str)?;

    // woothee returns "UNKNOWN" for unrecognized fields
    let browser = if result.name == "UNKNOWN" {
        return None;
    } else {
        result.name
    };

    let os = if result.os == "UNKNOWN" {
        "Unknown OS"
    } else {
        result.os
    };

    Some(format!("{browser}, {os}"))
}

/// Builds a complete [`SessionContext`] from HTTP request metadata.
///
/// Combines IP extraction and UA parsing into a single struct ready for
/// passing to `create_session()`.
pub fn build_session_context(
    headers: &HeaderMap,
    peer: SocketAddr,
    trusted_proxies: &[IpAddr],
) -> SessionContext {
    let ip_address = Some(extract_client_ip(headers, peer, trusted_proxies));

    let ua_raw = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let device_label = parse_device_label(ua_raw.as_deref());

    SessionContext {
        ip_address,
        user_agent_raw: ua_raw,
        device_label,
        satisfies_mfa_via_passkey: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::FromRequestParts;
    use axum::http::HeaderValue;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn peer_addr() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345))
    }

    fn peer_a() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 1024))
    }

    fn peer_b() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 2048))
    }

    // ===== PeerAddr extractor tests =====

    #[tokio::test]
    async fn peer_addr_reads_connect_info_when_present() {
        let mut parts = axum::http::Request::new(()).into_parts().0;
        parts.extensions.insert(ConnectInfo::<SocketAddr>(peer_a()));
        let PeerAddr(got) = PeerAddr::from_request_parts(&mut parts, &())
            .await
            .expect("infallible");
        assert_eq!(got, peer_a(), "extractor must return the real socket peer");
    }

    #[tokio::test]
    async fn peer_addr_falls_back_when_connect_info_absent() {
        let mut parts = axum::http::Request::new(()).into_parts().0;
        let PeerAddr(got) = PeerAddr::from_request_parts(&mut parts, &())
            .await
            .expect("infallible");
        assert_eq!(
            got, FALLBACK_PEER,
            "extractor must fall back to FALLBACK_PEER in test environments"
        );
    }

    #[tokio::test]
    async fn two_distinct_peers_produce_distinct_rate_limit_keys() {
        // Regression test for HEA-2027: with trusted_proxies empty, two
        // connections from different peer IPs must map to different IP strings
        // rather than both collapsing to 127.0.0.1.
        let headers = HeaderMap::new();
        let ip_a = extract_client_ip(&headers, peer_a(), &[]);
        let ip_b = extract_client_ip(&headers, peer_b(), &[]);
        assert_ne!(
            ip_a, ip_b,
            "distinct peers must produce distinct rate-limit keys"
        );
        assert_eq!(ip_a, "203.0.113.1");
        assert_eq!(ip_b, "203.0.113.2");
    }

    // ===== IP extraction tests =====

    #[test]
    fn no_trusted_proxies_returns_peer_ip() {
        let headers = HeaderMap::new();
        let result = extract_client_ip(&headers, peer_addr(), &[]);
        assert_eq!(result, "192.168.1.100");
    }

    #[test]
    fn xff_ignored_when_no_trusted_proxies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1, 172.16.0.1"),
        );
        let result = extract_client_ip(&headers, peer_addr(), &[]);
        assert_eq!(result, "192.168.1.100");
    }

    #[test]
    fn xff_right_to_left_with_trusted_proxy() {
        // HEA-2165: the request must arrive FROM a trusted proxy for the
        // XFF walk to run at all.
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.50, 10.0.0.1"),
        );
        let trusted: Vec<IpAddr> = vec!["10.0.0.1".parse().expect("valid IP")];
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4433));
        let result = extract_client_ip(&headers, peer, &trusted);
        assert_eq!(result, "203.0.113.50");
    }

    #[test]
    fn all_trusted_fallback_to_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1, 10.0.0.2"),
        );
        let trusted: Vec<IpAddr> = vec![
            "10.0.0.1".parse().expect("valid"),
            "10.0.0.2".parse().expect("valid"),
        ];
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 4433));
        let result = extract_client_ip(&headers, peer, &trusted);
        assert_eq!(result, "10.0.0.2");
    }

    // ===== HEA-2165: XFF honored only from a trusted peer =====

    fn trusted_peer() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4433))
    }

    #[test]
    fn xff_from_untrusted_peer_is_ignored() {
        // peer_addr() (192.168.1.100) is NOT in trusted_proxies, so XFF is
        // attacker-controlled and must be ignored entirely.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.50"));
        let trusted: Vec<IpAddr> = vec!["10.0.0.1".parse().expect("valid IP")];
        let result = extract_client_ip(&headers, peer_addr(), &trusted);
        assert_eq!(
            result, "192.168.1.100",
            "XFF from an untrusted peer must be ignored (per-request IP spoofing)"
        );
    }

    #[test]
    fn xff_from_trusted_peer_is_honored() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.50"));
        let trusted: Vec<IpAddr> = vec!["10.0.0.1".parse().expect("valid IP")];
        let result = extract_client_ip(&headers, trusted_peer(), &trusted);
        assert_eq!(result, "203.0.113.50");
    }

    #[test]
    fn walk_returns_first_untrusted_hop_not_leftmost() {
        // Client-prepended garbage on the left must not win: the first
        // untrusted hop from the right is the real client.
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("6.6.6.6, 203.0.113.50, 10.0.0.2"),
        );
        let trusted: Vec<IpAddr> = vec![
            "10.0.0.1".parse().expect("valid"),
            "10.0.0.2".parse().expect("valid"),
        ];
        let result = extract_client_ip(&headers, trusted_peer(), &trusted);
        assert_eq!(result, "203.0.113.50");
    }

    #[test]
    fn unparseable_hop_stops_walk_fail_closed() {
        // An unparseable hop makes everything to its left unverifiable —
        // the walk must stop and fall back to the peer, not skip past it
        // and trust a client-supplied value.
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("6.6.6.6, not-an-ip, 10.0.0.2"),
        );
        let trusted: Vec<IpAddr> = vec![
            "10.0.0.1".parse().expect("valid"),
            "10.0.0.2".parse().expect("valid"),
        ];
        let result = extract_client_ip(&headers, trusted_peer(), &trusted);
        assert_eq!(
            result, "10.0.0.1",
            "unparseable hop must fail closed to the peer, not trust 6.6.6.6"
        );
    }

    #[test]
    fn v4_mapped_v6_peer_matches_v4_trusted_entry() {
        // Dual-stack listeners report v4 peers as ::ffff:a.b.c.d — canonical
        // comparison must still recognize the configured v4 proxy.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.50"));
        let trusted: Vec<IpAddr> = vec!["10.0.0.1".parse().expect("valid IP")];
        let peer: SocketAddr = "[::ffff:10.0.0.1]:4433".parse().expect("valid addr");
        let result = extract_client_ip(&headers, peer, &trusted);
        assert_eq!(result, "203.0.113.50");
    }

    #[test]
    fn v4_mapped_xff_entry_is_canonicalized() {
        // ::ffff:203.0.113.50 and 203.0.113.50 must map to the SAME rate-limit
        // key, otherwise an attacker splits per-IP buckets by alternating forms.
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("::ffff:203.0.113.50"),
        );
        let trusted: Vec<IpAddr> = vec!["10.0.0.1".parse().expect("valid IP")];
        let result = extract_client_ip(&headers, trusted_peer(), &trusted);
        assert_eq!(result, "203.0.113.50");
    }

    // ===== UA parsing tests =====

    #[test]
    fn chrome_macos_ua() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let label = parse_device_label(Some(ua));
        assert!(label.is_some());
        let label = label.expect("should parse");
        assert!(label.contains("Chrome"), "expected Chrome in '{label}'");
        assert!(
            label.contains("Mac") || label.contains("OS X"),
            "expected Mac in '{label}'"
        );
    }

    #[test]
    fn firefox_windows_ua() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0";
        let label = parse_device_label(Some(ua));
        assert!(label.is_some());
        let label = label.expect("should parse");
        assert!(label.contains("Firefox"), "expected Firefox in '{label}'");
        assert!(label.contains("Windows"), "expected Windows in '{label}'");
    }

    #[test]
    fn empty_ua_returns_none() {
        assert_eq!(parse_device_label(Some("")), None);
    }

    #[test]
    fn none_ua_returns_none() {
        assert_eq!(parse_device_label(None), None);
    }

    #[test]
    fn garbage_ua_returns_none() {
        assert_eq!(parse_device_label(Some("not-a-real-user-agent")), None);
    }
}
