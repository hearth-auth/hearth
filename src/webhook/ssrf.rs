//! SSRF protection: hostname resolution and private-IP rejection for webhook URLs.
//!
//! Applied at both webhook registration time and at each delivery attempt
//! (defeating DNS-rebinding attacks where a hostname resolves to a different
//! IP after initial validation).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use super::error::WebhookError;

/// Returns `true` if `addr` falls into a range that must never be reachable
/// via outbound webhook delivery: loopback, RFC 1918 private, link-local
/// (169.254.0.0/16 — cloud metadata such as AWS IMDSv1), CGNAT, or IPv6 ULA.
pub(super) fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => is_private_ipv4(ip),
        IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    // 0.0.0.0/8 — "this" network
    if a == 0 {
        return true;
    }
    // 10.0.0.0/8 — RFC 1918
    if a == 10 {
        return true;
    }
    // 100.64.0.0/10 — shared address / CGNAT (RFC 6598)
    if a == 100 && (64..=127).contains(&b) {
        return true;
    }
    // 127.0.0.0/8 — loopback
    if a == 127 {
        return true;
    }
    // 169.254.0.0/16 — link-local / cloud metadata (AWS IMDSv1)
    if a == 169 && b == 254 {
        return true;
    }
    // 172.16.0.0/12 — RFC 1918
    if a == 172 && (16..=31).contains(&b) {
        return true;
    }
    // 192.168.0.0/16 — RFC 1918
    if a == 192 && b == 168 {
        return true;
    }
    false
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    // ::1 — loopback
    if ip == Ipv6Addr::LOCALHOST {
        return true;
    }
    // :: — unspecified
    if ip == Ipv6Addr::UNSPECIFIED {
        return true;
    }
    let s = ip.segments();
    // fe80::/10 — link-local
    if (s[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // fc00::/7 — Unique Local Address / ULA (covers fd00::/8)
    if (s[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    false
}

/// Extracts `(hostname, port)` from a URL that has already been validated to
/// start with `http://` or `https://`.
///
/// Returns `None` if the URL is malformed (e.g. empty host).
pub(super) fn extract_host_port(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        return None;
    };
    let default_port: u16 = if scheme == "https" { 443 } else { 80 };

    // Drop path, query, and fragment — keep only the authority component.
    let authority = rest.split('/').next().unwrap_or(rest);
    // Drop any userinfo (user:pass@host) — rare but valid in URLs.
    let authority = authority.split('@').last().unwrap_or(authority);

    if authority.is_empty() {
        return None;
    }

    // IPv6 literal: [::1] or [::1]:8080
    if let Some(bracket_end) = authority.find(']') {
        let ipv6_host = &authority[1..bracket_end]; // strip brackets
        let port = authority
            .get(bracket_end + 1..)
            .and_then(|s| s.strip_prefix(':'))
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return Some((ipv6_host.to_string(), port));
    }

    // Regular host or host:port.
    match authority.rfind(':') {
        Some(colon) => {
            let host = &authority[..colon];
            let port = authority[colon + 1..].parse().unwrap_or(default_port);
            if host.is_empty() {
                None
            } else {
                Some((host.to_string(), port))
            }
        }
        None => Some((authority.to_string(), default_port)),
    }
}

/// Resolves `host` to IP addresses and rejects any that fall in a
/// private/reserved range.
///
/// If `allowed_url_prefixes` is non-empty and `full_url` starts with any of
/// those prefixes, the check is bypassed — this lets operators allowlist
/// internal receivers (e.g. `https://internal.corp/`).
///
/// `port` is used only to satisfy `ToSocketAddrs`; no connection is made.
pub(super) fn check_host_for_ssrf(
    host: &str,
    port: u16,
    full_url: &str,
    allowed_url_prefixes: &[String],
) -> Result<(), WebhookError> {
    if !allowed_url_prefixes.is_empty()
        && allowed_url_prefixes
            .iter()
            .any(|p| full_url.starts_with(p.as_str()))
    {
        return Ok(());
    }

    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| WebhookError::InvalidUrl {
            reason: format!("could not resolve hostname '{host}': {e}"),
        })?;

    let mut resolved_any = false;
    for addr in addrs {
        resolved_any = true;
        let ip = addr.ip();
        if is_private_ip(ip) {
            return Err(WebhookError::InvalidUrl {
                reason: format!(
                    "webhook URL resolves to a private/reserved IP ({ip}); \
                     SSRF protection rejects internal destinations"
                ),
            });
        }
    }

    if !resolved_any {
        return Err(WebhookError::InvalidUrl {
            reason: format!("hostname '{host}' resolved to no addresses"),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_private_ip ────────────────────────────────────────────────────────

    #[test]
    fn loopback_ipv4_is_private() {
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("127.1.2.3".parse().unwrap()));
    }

    #[test]
    fn rfc1918_is_private() {
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("10.255.255.255".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("172.31.255.255".parse().unwrap()));
        assert!(is_private_ip("192.168.0.1".parse().unwrap()));
        assert!(is_private_ip("192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn link_local_ipv4_is_private() {
        assert!(is_private_ip("169.254.169.254".parse().unwrap())); // AWS IMDSv1
        assert!(is_private_ip("169.254.0.1".parse().unwrap()));
    }

    #[test]
    fn cgnat_is_private() {
        assert!(is_private_ip("100.64.0.1".parse().unwrap()));
        assert!(is_private_ip("100.127.255.255".parse().unwrap()));
    }

    #[test]
    fn public_ipv4_is_not_private() {
        assert!(!is_private_ip("1.1.1.1".parse().unwrap())); // Cloudflare
        assert!(!is_private_ip("8.8.8.8".parse().unwrap())); // Google
        assert!(!is_private_ip("93.184.216.34".parse().unwrap())); // example.com
    }

    #[test]
    fn loopback_ipv6_is_private() {
        assert!(is_private_ip("::1".parse().unwrap()));
    }

    #[test]
    fn ula_ipv6_is_private() {
        assert!(is_private_ip("fd00::1".parse().unwrap()));
        assert!(is_private_ip("fc00::1".parse().unwrap()));
    }

    #[test]
    fn link_local_ipv6_is_private() {
        assert!(is_private_ip("fe80::1".parse().unwrap()));
    }

    #[test]
    fn public_ipv6_is_not_private() {
        assert!(!is_private_ip("2606:4700::1111".parse().unwrap())); // Cloudflare
    }

    // ── extract_host_port ────────────────────────────────────────────────────

    #[test]
    fn extract_host_port_https_default() {
        assert_eq!(
            extract_host_port("https://example.com/hook"),
            Some(("example.com".to_string(), 443))
        );
    }

    #[test]
    fn extract_host_port_http_default() {
        assert_eq!(
            extract_host_port("http://example.com/hook"),
            Some(("example.com".to_string(), 80))
        );
    }

    #[test]
    fn extract_host_port_explicit() {
        assert_eq!(
            extract_host_port("http://example.com:8080/hook"),
            Some(("example.com".to_string(), 8080))
        );
    }

    #[test]
    fn extract_host_port_ipv6() {
        assert_eq!(
            extract_host_port("http://[::1]:9000/hook"),
            Some(("::1".to_string(), 9000))
        );
    }

    #[test]
    fn extract_host_port_ipv4_literal() {
        assert_eq!(
            extract_host_port("http://127.0.0.1:8080/hook"),
            Some(("127.0.0.1".to_string(), 8080))
        );
    }

    // ── check_host_for_ssrf (IP literal — no real DNS needed) ───────────────

    #[test]
    fn rejects_loopback_ip_literal() {
        let err = check_host_for_ssrf("127.0.0.1", 8080, "http://127.0.0.1:8080/hook", &[])
            .unwrap_err();
        assert!(matches!(err, WebhookError::InvalidUrl { .. }));
    }

    #[test]
    fn rejects_rfc1918_ip_literal() {
        let err = check_host_for_ssrf("10.0.0.1", 80, "http://10.0.0.1/hook", &[]).unwrap_err();
        assert!(matches!(err, WebhookError::InvalidUrl { .. }));
    }

    #[test]
    fn rejects_link_local_ip_literal() {
        let err =
            check_host_for_ssrf("169.254.169.254", 80, "http://169.254.169.254/", &[]).unwrap_err();
        assert!(matches!(err, WebhookError::InvalidUrl { .. }));
    }

    #[test]
    fn rejects_ipv6_loopback_literal() {
        let err = check_host_for_ssrf("::1", 80, "http://[::1]/hook", &[]).unwrap_err();
        assert!(matches!(err, WebhookError::InvalidUrl { .. }));
    }

    #[test]
    fn allowlist_bypasses_private_check() {
        // An operator who deliberately allowlists an internal URL should get through.
        let result = check_host_for_ssrf(
            "10.0.0.1",
            80,
            "http://10.0.0.1/hook",
            &["http://10.0.0.1/".to_string()],
        );
        assert!(result.is_ok());
    }
}
