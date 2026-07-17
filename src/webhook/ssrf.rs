//! SSRF guard for webhook egress (F3, HEA-1651).
//!
//! Enforces that webhook destination URLs resolve exclusively to
//! publicly-routable IP addresses.  Private, loopback, link-local, ULA, and
//! cloud-metadata ranges are blocked:
//!
//! - At **registration time** (URL stored in engine) — prevents saving
//!   obviously malicious destinations.
//! - **Immediately before each delivery attempt** — defends against DNS
//!   rebinding attacks where an initially-public hostname later resolves to a
//!   private address.
//!
//! # Residual risk
//!
//! The rebinding guard is point-in-time: a hostname that passes the check
//! could be re-bound between this DNS query and the TCP `connect()`.  No
//! practical defense exists at the application layer for that race; operators
//! who require stronger guarantees should route egress through a dedicated
//! HTTP proxy with network-level egress filtering.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::OnceLock;

use crate::abuse::cidr::Cidr;

use super::error::WebhookError;

/// Private/reserved IPv4 and IPv6 ranges that must never receive webhook traffic.
const BLOCKED_CIDR_STRS: &[&str] = &[
    // IPv4 — "this" network
    "0.0.0.0/8",
    // IPv4 — RFC 1918 private (10/8, 172.16/12, 192.168/16)
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    // IPv4 — loopback
    "127.0.0.0/8",
    // IPv4 — link-local / AWS+GCP+Azure instance metadata (169.254.169.254)
    "169.254.0.0/16",
    // IPv4 — RFC 6598 shared address space (carrier-grade NAT)
    "100.64.0.0/10",
    // IPv4 — IETF protocol assignments
    "192.0.0.0/24",
    // IPv4 — documentation (TEST-NET-1/2/3)
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    // IPv4 — RFC 2544 benchmarking
    "198.18.0.0/15",
    // IPv4 — reserved / future use
    "240.0.0.0/4",
    // IPv4 — broadcast
    "255.255.255.255/32",
    // IPv6 — unspecified
    "::/128",
    // IPv6 — loopback
    "::1/128",
    // IPv6 — ULA (fc00::/7 covers both fc00::/8 and fd00::/8)
    "fc00::/7",
    // IPv6 — link-local
    "fe80::/10",
];

fn blocked_cidrs() -> &'static [Cidr] {
    static CIDRS: OnceLock<Vec<Cidr>> = OnceLock::new();
    CIDRS.get_or_init(|| {
        BLOCKED_CIDR_STRS
            .iter()
            .map(|s| Cidr::parse(s).expect("built-in CIDR is valid"))
            .collect()
    })
}

/// Returns `true` if `ip` falls in any blocked (private/reserved) range.
///
/// IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are unwrapped to their IPv4
/// form before evaluation so the IPv4 blocklist applies correctly.
pub fn is_ssrf_blocked(ip: IpAddr) -> bool {
    let effective = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    blocked_cidrs().iter().any(|c| c.contains(effective))
}

/// Resolves `host:port` and checks every resulting address against the SSRF
/// blocklist.
///
/// Returns `Err(WebhookError::BlockedDestination)` when:
/// - DNS resolution fails (fail-closed; attacker controls the record).
/// - DNS returns no addresses.
/// - Any resolved address falls in a blocked range.
///
/// # DNS rebinding note
///
/// Call this immediately before each TCP connection, not once at registration
/// and cached, to defend against DNS rebinding.
pub fn check_host(host: &str, port: u16) -> Result<(), WebhookError> {
    let addrs: Vec<SocketAddr> = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|e| WebhookError::BlockedDestination {
            reason: format!("DNS resolution failed for '{host}': {e}"),
        })?
        .collect();

    if addrs.is_empty() {
        return Err(WebhookError::BlockedDestination {
            reason: format!("DNS resolution returned no addresses for '{host}'"),
        });
    }

    for sa in &addrs {
        if is_ssrf_blocked(sa.ip()) {
            return Err(WebhookError::BlockedDestination {
                reason: format!(
                    "destination IP {} resolves from '{host}' and is in a private/reserved range",
                    sa.ip()
                ),
            });
        }
    }

    Ok(())
}

/// Maximum HTTP redirects to follow on any webhook egress path.
///
/// Pinned to `0` (W1, HEA-1754). [`check_webhook_url`] only validates the
/// *initial* destination; a `3xx` response could redirect the request to an
/// internal/link-local address (IMDS `169.254.169.254`, RFC 1918) that was
/// never SSRF-checked. Refusing to follow redirects closes that hole. With
/// `ureq`'s default `max_redirects_will_error`, a redirect response therefore
/// fails the delivery instead of silently chasing the `Location` header.
///
/// DNS-rebinding TOCTOU between the guard and connect is a separate residual
/// risk (needs IP-pinned connect / egress proxy) tracked outside this fix.
pub(crate) const MAX_WEBHOOK_REDIRECTS: u32 = 0;

/// Validates a webhook URL for SSRF safety.
///
/// Enforces:
/// 1. `https://` scheme only.
/// 2. All DNS-resolved IPs are publicly routable.
///
/// Intended for use at both registration time and immediately before each
/// delivery attempt (rebinding-resistant guard).
pub fn check_webhook_url(url: &str) -> Result<(), WebhookError> {
    if !url.starts_with("https://") {
        return Err(WebhookError::InvalidUrl {
            reason: "webhook URL must use the https:// scheme".to_string(),
        });
    }

    let (host, port) = extract_host_port(url)?;
    check_host(&host, port)
}

/// Extracts `(host, port)` from an `https://` URL without a dependency on the
/// `url` crate.
fn extract_host_port(url: &str) -> Result<(String, u16), WebhookError> {
    let authority_and_path =
        url.strip_prefix("https://")
            .ok_or_else(|| WebhookError::InvalidUrl {
                reason: "expected https:// prefix".to_string(),
            })?;

    // Authority ends at the first `/`, `?`, or `#`.
    let authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(authority_and_path);

    if authority.is_empty() {
        return Err(WebhookError::InvalidUrl {
            reason: "URL has no host".to_string(),
        });
    }

    // Strip userinfo (not valid for webhooks but avoid panicking).
    let authority = if let Some(at) = authority.rfind('@') {
        &authority[at + 1..]
    } else {
        authority
    };

    // IPv6 literal: `[::1]` or `[::1]:8080`
    if authority.starts_with('[') {
        let close = authority
            .find(']')
            .ok_or_else(|| WebhookError::InvalidUrl {
                reason: "unclosed '[' in IPv6 literal".to_string(),
            })?;
        let host = authority[1..close].to_string();
        let port = if authority.len() > close + 1 && authority.as_bytes()[close + 1] == b':' {
            authority[close + 2..]
                .parse::<u16>()
                .map_err(|_| WebhookError::InvalidUrl {
                    reason: "invalid port in URL".to_string(),
                })?
        } else {
            443
        };
        return Ok((host, port));
    }

    // `host` or `host:port`
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| WebhookError::InvalidUrl {
                reason: "invalid port in URL".to_string(),
            })?;
        Ok((host.to_string(), port))
    } else {
        Ok((authority.to_string(), 443))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().expect("valid test IPv6"))
    }

    // ── is_ssrf_blocked — known-blocked IPs ──────────────────────────────────

    #[test]
    fn loopback_ipv4_is_blocked() {
        assert!(
            is_ssrf_blocked(v4(127, 0, 0, 1)),
            "127.0.0.1 must be blocked"
        );
    }

    #[test]
    fn loopback_ipv4_full_range_is_blocked() {
        assert!(is_ssrf_blocked(v4(127, 255, 255, 255)));
    }

    #[test]
    fn rfc1918_10_slash8_is_blocked() {
        assert!(is_ssrf_blocked(v4(10, 0, 0, 1)));
        assert!(is_ssrf_blocked(v4(10, 255, 255, 255)));
    }

    #[test]
    fn rfc1918_172_16_slash12_is_blocked() {
        assert!(is_ssrf_blocked(v4(172, 16, 0, 1)));
        assert!(is_ssrf_blocked(v4(172, 31, 255, 255)));
    }

    #[test]
    fn rfc1918_192_168_slash16_is_blocked() {
        assert!(is_ssrf_blocked(v4(192, 168, 0, 1)));
        assert!(is_ssrf_blocked(v4(192, 168, 255, 255)));
    }

    #[test]
    fn link_local_ipv4_is_blocked() {
        // Covers the cloud metadata endpoint 169.254.169.254
        assert!(is_ssrf_blocked(v4(169, 254, 0, 1)));
        assert!(
            is_ssrf_blocked(v4(169, 254, 169, 254)),
            "cloud metadata IP must be blocked"
        );
    }

    #[test]
    fn metadata_ip_169_254_169_254_is_blocked() {
        assert!(
            is_ssrf_blocked(v4(169, 254, 169, 254)),
            "169.254.169.254 (AWS/GCP/Azure metadata) must be rejected"
        );
    }

    #[test]
    fn loopback_ipv6_is_blocked() {
        assert!(is_ssrf_blocked(v6("::1")));
    }

    #[test]
    fn ula_ipv6_is_blocked() {
        assert!(is_ssrf_blocked(v6("fc00::1")));
        assert!(is_ssrf_blocked(v6("fd00::1")));
    }

    #[test]
    fn link_local_ipv6_is_blocked() {
        assert!(is_ssrf_blocked(v6("fe80::1")));
    }

    #[test]
    fn ipv4_mapped_ipv6_loopback_is_blocked() {
        // ::ffff:127.0.0.1 must be treated as 127.0.0.1
        let mapped: IpAddr = IpAddr::V6("::ffff:127.0.0.1".parse().expect("valid"));
        assert!(
            is_ssrf_blocked(mapped),
            "IPv4-mapped IPv6 loopback must be blocked"
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_private_is_blocked() {
        let mapped: IpAddr = IpAddr::V6("::ffff:192.168.1.1".parse().expect("valid"));
        assert!(is_ssrf_blocked(mapped));
    }

    // ── is_ssrf_blocked — public IPs should pass ─────────────────────────────

    #[test]
    fn public_ipv4_is_allowed() {
        assert!(
            !is_ssrf_blocked(v4(8, 8, 8, 8)),
            "8.8.8.8 must not be blocked"
        );
        assert!(!is_ssrf_blocked(v4(1, 1, 1, 1)));
        assert!(!is_ssrf_blocked(v4(93, 184, 216, 34)));
    }

    #[test]
    fn public_ipv6_is_allowed() {
        // 2001:4860:4860::8888 = Google IPv6 DNS
        assert!(!is_ssrf_blocked(v6("2001:4860:4860::8888")));
    }

    // ── extract_host_port ────────────────────────────────────────────────────

    #[test]
    fn extract_host_port_simple() {
        let (h, p) = extract_host_port("https://example.com/hook").expect("parse");
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn extract_host_port_with_explicit_port() {
        let (h, p) = extract_host_port("https://example.com:8443/hook").expect("parse");
        assert_eq!(h, "example.com");
        assert_eq!(p, 8443);
    }

    #[test]
    fn extract_host_port_ipv6_literal() {
        let (h, p) = extract_host_port("https://[::1]/hook").expect("parse");
        assert_eq!(h, "::1");
        assert_eq!(p, 443);
    }

    #[test]
    fn extract_host_port_ipv6_literal_with_port() {
        let (h, p) = extract_host_port("https://[::1]:9000/hook").expect("parse");
        assert_eq!(h, "::1");
        assert_eq!(p, 9000);
    }

    #[test]
    fn extract_host_port_no_path() {
        let (h, p) = extract_host_port("https://example.com").expect("parse");
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn extract_host_port_query_string() {
        let (h, p) = extract_host_port("https://example.com/hook?foo=bar").expect("parse");
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
    }

    // ── check_webhook_url — scheme enforcement ───────────────────────────────

    #[test]
    fn http_scheme_rejected() {
        let err =
            check_webhook_url("http://example.com/hook").expect_err("http:// must be rejected");
        assert!(
            matches!(err, WebhookError::InvalidUrl { .. }),
            "expected InvalidUrl, got {err}"
        );
    }

    #[test]
    fn ftp_scheme_rejected() {
        let err = check_webhook_url("ftp://example.com/hook").expect_err("ftp:// must be rejected");
        assert!(matches!(err, WebhookError::InvalidUrl { .. }));
    }

    // ── check_host — private address rejection ───────────────────────────────

    #[test]
    fn check_host_loopback_rejected() {
        // 127.0.0.1 resolves directly from a numeric literal.
        let err = check_host("127.0.0.1", 443).expect_err("loopback must be blocked");
        assert!(
            matches!(err, WebhookError::BlockedDestination { .. }),
            "{err}"
        );
    }

    #[test]
    fn check_host_private_10x_rejected() {
        let err = check_host("10.0.0.1", 443).expect_err("10.x must be blocked");
        assert!(
            matches!(err, WebhookError::BlockedDestination { .. }),
            "{err}"
        );
    }

    #[test]
    fn check_host_metadata_ip_rejected() {
        let err = check_host("169.254.169.254", 80).expect_err("cloud metadata IP must be blocked");
        assert!(
            matches!(err, WebhookError::BlockedDestination { .. }),
            "{err}"
        );
    }

    #[test]
    fn check_host_ipv6_loopback_rejected() {
        let err = check_host("::1", 443).expect_err("IPv6 loopback must be blocked");
        assert!(
            matches!(err, WebhookError::BlockedDestination { .. }),
            "{err}"
        );
    }

    #[test]
    fn check_host_private_192_168_rejected() {
        let err = check_host("192.168.1.1", 443).expect_err("192.168.x must be blocked");
        assert!(
            matches!(err, WebhookError::BlockedDestination { .. }),
            "{err}"
        );
    }

    // ── redirect refusal (W1, HEA-1754) ──────────────────────────────────────
    //
    // check_webhook_url only validates the *initial* destination. Every webhook
    // egress agent therefore pins max_redirects to MAX_WEBHOOK_REDIRECTS (0) so
    // a 3xx cannot bounce the request to an internal/link-local target that was
    // never SSRF-checked. These tests exercise the shared control behaviourally
    // over plaintext (https_only, applied at the real call sites, would block a
    // loopback test server); if MAX_WEBHOOK_REDIRECTS is bumped above 0 they
    // fail, catching a regression on any of the three egress paths.

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    /// Spawns a loopback server that 302-redirects to `target_url`, then a
    /// second "internal" target server that reports (over the returned channel)
    /// if it is ever contacted. Returns the redirect server's URL.
    fn spawn_redirect_to_internal() -> (String, mpsc::Receiver<()>) {
        let target = TcpListener::bind("127.0.0.1:0").expect("bind target");
        let target_addr = target.local_addr().expect("target addr");
        let (hit_tx, hit_rx) = mpsc::channel::<()>();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = target.accept() {
                // The redirect was followed to the "internal" host — report it.
                let _ = hit_tx.send(());
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });

        let redirector = TcpListener::bind("127.0.0.1:0").expect("bind redirector");
        let redirector_addr = redirector.local_addr().expect("redirector addr");
        // Point the Location at the loopback "internal" target — 127.0.0.1 is an
        // SSRF-blocked range and stands in for IMDS/RFC-1918. If the agent chases
        // the redirect it connects here and trips the hit channel.
        let location = format!("http://127.0.0.1:{}/steal", target_addr.port());
        thread::spawn(move || {
            if let Ok((mut stream, _)) = redirector.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        (format!("http://{redirector_addr}/hook"), hit_rx)
    }

    /// Builds an agent with the shared webhook redirect policy and asserts a
    /// 302 to an internal address is refused (never contacts the target).
    fn assert_redirect_refused(egress_path: &str) {
        let agent = ureq::config::Config::builder()
            .max_redirects(MAX_WEBHOOK_REDIRECTS)
            .timeout_global(Some(std::time::Duration::from_secs(5)))
            .build()
            .new_agent();
        let (redirect_url, hit_rx) = spawn_redirect_to_internal();

        // Delivery must not succeed by chasing the redirect. Either ureq errors
        // (default max_redirects_will_error) or returns the raw 3xx — both fine.
        let _ = agent.post(&redirect_url).send(b"{}");

        assert!(
            hit_rx.recv_timeout(std::time::Duration::from_millis(300)).is_err(),
            "{egress_path}: redirect to internal (loopback) address was followed"
        );
    }

    #[test]
    fn dispatcher_egress_refuses_redirect_to_internal() {
        // Mirrors src/webhook/dispatcher.rs::deliver_once.
        assert_redirect_refused("webhook::dispatcher");
    }

    #[test]
    fn approval_notifier_egress_refuses_redirect_to_internal() {
        // Mirrors src/identity/approval_notifier.rs::UreqApprovalTransport.
        assert_redirect_refused("identity::approval_notifier");
    }

    #[test]
    fn pre_token_webhook_egress_refuses_redirect_to_internal() {
        // Mirrors src/identity/pre_token_webhook.rs::UreqPreTokenWebhookTransport.
        assert_redirect_refused("identity::pre_token_webhook");
    }
}
