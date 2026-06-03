//! Integration tests for A-9 tenant-managed CIDR allow/deny lists.
//!
//! D-4 taxonomy:
//! - **Unit**: CIDR parsing correctness for IPv4 and IPv6.
//! - **Unit**: Filter evaluation — allow list, deny list, combined semantics.
//! - **Adversarial**: boundary cases, mixed address families, host-bit masking.
//!
//! Closes: HEA-1191 §A-9 (Tenant-managed allow/deny CIDR).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hearth::abuse::cidr::{Cidr, CidrFilter, CidrOutcome, CidrParseError};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().expect("valid IPv6 address"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Cidr parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Valid IPv4 host route parses without error.
#[test]
fn a9_parse_ipv4_host_route() {
    let c = Cidr::parse("203.0.113.42/32").expect("valid test CIDR");
    assert!(c.contains(v4(203, 0, 113, 42)));
    assert!(!c.contains(v4(203, 0, 113, 43)));
}

/// Valid IPv4 network with host bits set is accepted (host bits masked).
#[test]
fn a9_parse_ipv4_host_bits_masked() {
    let c = Cidr::parse("10.1.2.255/24").expect("valid test CIDR");
    // Network should be 10.1.2.0/24 after masking.
    assert!(c.contains(v4(10, 1, 2, 100)));
    assert!(!c.contains(v4(10, 1, 3, 100)));
}

/// /0 prefix matches every IPv4 address.
#[test]
fn a9_parse_ipv4_slash0_matches_all() {
    let c = Cidr::parse("0.0.0.0/0").expect("valid test CIDR");
    assert!(c.contains(v4(1, 2, 3, 4)));
    assert!(c.contains(v4(255, 255, 255, 255)));
}

/// IPv6 CIDR parses and contains correctly.
#[test]
fn a9_parse_ipv6_cidr_contains() {
    let c = Cidr::parse("2001:db8::/32").expect("valid test CIDR");
    assert!(c.contains(v6("2001:db8::1")));
    assert!(!c.contains(v6("2001:db9::1")));
}

/// IPv6 loopback /128 is a host route.
#[test]
fn a9_parse_ipv6_loopback_host_route() {
    let c = Cidr::parse("::1/128").expect("valid test CIDR");
    assert!(c.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(!c.contains(v6("::2")));
}

/// Missing slash returns MissingSeparator error.
#[test]
fn a9_parse_error_missing_slash() {
    assert!(matches!(
        Cidr::parse("192.168.0.0"),
        Err(CidrParseError::MissingSeparator(_))
    ));
}

/// Prefix length exceeding address family maximum returns PrefixLenTooLong.
#[test]
fn a9_parse_error_prefix_too_long_ipv4() {
    assert!(matches!(
        Cidr::parse("10.0.0.0/33"),
        Err(CidrParseError::PrefixLenTooLong(_, 33))
    ));
}

/// IPv6 prefix > 128 returns PrefixLenTooLong.
#[test]
fn a9_parse_error_prefix_too_long_ipv6() {
    assert!(matches!(
        Cidr::parse("::1/129"),
        Err(CidrParseError::PrefixLenTooLong(_, 129))
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// CidrFilter — empty (fail-open)
// ─────────────────────────────────────────────────────────────────────────────

/// Empty filter allows every IP (fail-open per §6.1).
#[test]
fn a9_empty_filter_allows_any_ip() {
    let f = CidrFilter::empty();
    assert_eq!(f.check(v4(1, 2, 3, 4)), CidrOutcome::Allow);
    assert_eq!(f.check(IpAddr::V6(Ipv6Addr::LOCALHOST)), CidrOutcome::Allow);
}

/// Empty filter `is_empty()` returns true.
#[test]
fn a9_empty_filter_is_empty() {
    assert!(CidrFilter::empty().is_empty());
    assert!(!CidrFilter::from_strs(["1.2.3.4/32"], [] as [&str; 0])
        .expect("valid test CIDR")
        .is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// CidrFilter — deny list only
// ─────────────────────────────────────────────────────────────────────────────

/// IP inside deny CIDR is blocked.
#[test]
fn a9_deny_list_blocks_matching_ip() {
    let f = CidrFilter::from_strs([] as [&str; 0], ["198.51.100.0/24"]).expect("valid test CIDR");
    assert_eq!(f.check(v4(198, 51, 100, 7)), CidrOutcome::Deny);
}

/// IP outside deny CIDR is allowed.
#[test]
fn a9_deny_list_allows_non_matching_ip() {
    let f = CidrFilter::from_strs([] as [&str; 0], ["198.51.100.0/24"]).expect("valid test CIDR");
    assert_eq!(f.check(v4(198, 51, 101, 7)), CidrOutcome::Allow);
}

/// Multiple deny CIDRs — any match blocks.
#[test]
fn a9_multiple_deny_cidrs_any_match_blocks() {
    let f = CidrFilter::from_strs(
        [] as [&str; 0],
        ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    )
    .expect("valid test CIDR");
    assert_eq!(f.check(v4(172, 20, 0, 1)), CidrOutcome::Deny);
    assert_eq!(f.check(v4(8, 8, 8, 8)), CidrOutcome::Allow);
}

// ─────────────────────────────────────────────────────────────────────────────
// CidrFilter — allow list only (strict whitelist mode)
// ─────────────────────────────────────────────────────────────────────────────

/// IP inside allow CIDR is permitted.
#[test]
fn a9_allow_list_permits_matching_ip() {
    let f = CidrFilter::from_strs(["203.0.113.0/24"], [] as [&str; 0]).expect("valid test CIDR");
    assert_eq!(f.check(v4(203, 0, 113, 10)), CidrOutcome::Allow);
}

/// IP NOT in allow CIDR is denied (strict whitelist mode).
#[test]
fn a9_allow_list_denies_non_matching_ip() {
    let f = CidrFilter::from_strs(["203.0.113.0/24"], [] as [&str; 0]).expect("valid test CIDR");
    assert_eq!(
        f.check(v4(1, 2, 3, 4)),
        CidrOutcome::Deny,
        "strict allowlist mode: IP outside allow list must be denied"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// CidrFilter — combined allow + deny
// ─────────────────────────────────────────────────────────────────────────────

/// IP in both allow and deny → allow wins (explicit trust).
#[test]
fn a9_allow_overrides_deny() {
    let f = CidrFilter::from_strs(["10.0.0.0/8"], ["10.1.2.3/32"]).expect("valid test CIDR");
    assert_eq!(
        f.check(v4(10, 1, 2, 3)),
        CidrOutcome::Allow,
        "allow list must override deny list for the same IP"
    );
}

/// IP outside allow list is denied even though deny list is empty.
#[test]
fn a9_allow_non_empty_denies_outside_ip() {
    let f = CidrFilter::from_strs(["10.0.0.0/8"], [] as [&str; 0]).expect("valid test CIDR");
    assert_eq!(f.check(v4(192, 168, 1, 1)), CidrOutcome::Deny);
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial
// ─────────────────────────────────────────────────────────────────────────────

/// IPv4 address does not match an IPv6 deny CIDR.
#[test]
fn a9_adversarial_ipv4_vs_ipv6_cidr_no_match() {
    let f = CidrFilter::from_strs([] as [&str; 0], ["::1/128"]).expect("valid test CIDR");
    // IPv4 loopback is a different address family — must not match ::1/128.
    assert_eq!(f.check(v4(127, 0, 0, 1)), CidrOutcome::Allow);
}

/// Exact boundary: last IP in the /24 network is inside.
#[test]
fn a9_adversarial_last_ip_in_network_is_inside() {
    let f = CidrFilter::from_strs([] as [&str; 0], ["192.0.2.0/24"]).expect("valid test CIDR");
    assert_eq!(f.check(v4(192, 0, 2, 255)), CidrOutcome::Deny);
}

/// Exact boundary: first IP of the next /24 is outside.
#[test]
fn a9_adversarial_first_ip_next_network_is_outside() {
    let f = CidrFilter::from_strs([] as [&str; 0], ["192.0.2.0/24"]).expect("valid test CIDR");
    assert_eq!(f.check(v4(192, 0, 3, 0)), CidrOutcome::Allow);
}

/// from_strs returns parse error on malformed entry.
#[test]
fn a9_from_strs_propagates_parse_error() {
    let result = CidrFilter::from_strs([] as [&str; 0], ["not-a-cidr"]);
    assert!(result.is_err(), "malformed CIDR must produce an error");
}
