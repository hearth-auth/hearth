//! Integration tests for A-9 tenant-managed CIDR allow/deny lists.
//!
//! D-4 taxonomy:
//! - **Unit**: CIDR parsing correctness for IPv4 and IPv6.
//! - **Unit**: Filter evaluation — allow list, deny list, combined semantics.
//! - **Adversarial**: boundary cases, mixed address families, strict parsing.
//!
//! Closes: HEA-1191 §A-9 (Tenant-managed allow/deny CIDR).
//!
//! Entries are parsed by `hearth::core::IpRange` — the same strict grammar as
//! `server.trusted_proxies`, but without its breadth rules: a policy may deny
//! or allow `0.0.0.0/0`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hearth::abuse::cidr::{CidrFilter, CidrOutcome};
use hearth::core::{IpRange, IpRangeError};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().expect("valid IPv6 address"))
}

fn range(s: &str) -> IpRange {
    s.parse()
        .unwrap_or_else(|e| panic!("'{s}' must parse: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Valid IPv4 host route parses without error.
#[test]
fn a9_parse_ipv4_host_route() {
    let c = range("203.0.113.42/32");
    assert!(c.contains(v4(203, 0, 113, 42)));
    assert!(!c.contains(v4(203, 0, 113, 43)));
}

/// A bare address is a host route — the same entry as `/32`.
#[test]
fn a9_parse_bare_address_is_a_host_route() {
    assert_eq!(range("192.0.2.7"), range("192.0.2.7/32"));
    assert!(range("192.0.2.7").contains(v4(192, 0, 2, 7)));
    assert!(!range("192.0.2.7").contains(v4(192, 0, 2, 8)));
}

/// Host bits set is refused, not silently masked: `10.1.2.255/24` may mean the
/// host or the /24, and a deny/allow list must not guess. The error names the
/// network form.
#[test]
fn a9_parse_refuses_host_bits_and_names_the_network() {
    let err = "10.1.2.255/24".parse::<IpRange>().expect_err("host bits");
    assert_eq!(
        err,
        IpRangeError::HostBitsSet {
            network: v4(10, 1, 2, 0),
            prefix: 24
        }
    );
    assert!(err.to_string().contains("10.1.2.0/24"), "got: {err}");
}

/// Decorations the old parser accepted, or that no tool prints, are refused.
#[test]
fn a9_parse_refuses_non_canonical_spellings() {
    for bad in [
        "10.0.0.0/+8",
        "10.0.0.0/08",
        "fe80::1%eth0",
        "fe80::%eth0/64",
        "[2001:db8::]/32",
        "[2001:db8::1]",
        "192.0.2.7:443",
        "192.0.2.0:443/24",
        " 192.0.2.0/24",
        "192.0.2.0/24 ",
        "192.0.2.0/24/24",
        "not-a-cidr",
    ] {
        assert_eq!(
            bad.parse::<IpRange>().expect_err(bad),
            IpRangeError::Malformed,
            "'{bad}'"
        );
    }
}

/// /0 prefix matches every IPv4 address — broad ranges stay legal in policies.
#[test]
fn a9_parse_ipv4_slash0_matches_all() {
    let c = range("0.0.0.0/0");
    assert!(c.contains(v4(1, 2, 3, 4)));
    assert!(c.contains(v4(255, 255, 255, 255)));
    assert!(range("::/0").contains(v6("2001:db8::1")));
}

/// IPv6 CIDR parses and contains correctly.
#[test]
fn a9_parse_ipv6_cidr_contains() {
    let c = range("2001:db8::/32");
    assert!(c.contains(v6("2001:db8::1")));
    assert!(!c.contains(v6("2001:db9::1")));
}

/// IPv6 loopback /128 is a host route.
#[test]
fn a9_parse_ipv6_loopback_host_route() {
    let c = range("::1/128");
    assert!(c.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(!c.contains(v6("::2")));
}

/// Prefix length exceeding the address family maximum is refused.
#[test]
fn a9_parse_error_prefix_too_long() {
    assert_eq!(
        "10.0.0.0/33".parse::<IpRange>().expect_err("/33"),
        IpRangeError::PrefixOutOfRange { max: 32 }
    );
    assert_eq!(
        "::1/129".parse::<IpRange>().expect_err("/129"),
        IpRangeError::PrefixOutOfRange { max: 128 }
    );
}

/// Every well-formed policy entry matches exactly the addresses it matched
/// before the strict parser: the change refuses bad spellings, it does not
/// move any valid range.
#[test]
fn a9_existing_valid_policies_match_the_same_addresses() {
    let cases: &[(&str, &[&str], &[&str])] = &[
        (
            "10.0.0.0/8",
            &["10.0.0.0", "10.255.255.255"],
            &["11.0.0.0", "9.255.255.255"],
        ),
        (
            "172.16.0.0/12",
            &["172.16.0.1", "172.31.255.255"],
            &["172.32.0.0", "172.15.255.255"],
        ),
        (
            "192.0.2.0/24",
            &["192.0.2.0", "192.0.2.255"],
            &["192.0.3.0", "192.0.1.255"],
        ),
        ("198.51.100.0/24", &["198.51.100.7"], &["198.51.101.7"]),
        ("203.0.113.42/32", &["203.0.113.42"], &["203.0.113.43"]),
        ("0.0.0.0/0", &["0.0.0.0", "255.255.255.255"], &["::1"]),
        (
            "2001:db8::/32",
            &["2001:db8::", "2001:db8:ffff::1"],
            &["2001:db9::", "10.0.0.1"],
        ),
        ("::1/128", &["::1"], &["::2", "127.0.0.1"]),
        ("::/0", &["::", "2001:db8::1"], &["10.0.0.1"]),
    ];
    for (entry, inside, outside) in cases {
        let f = CidrFilter::from_strs([] as [&str; 0], [*entry]).expect(entry);
        for ip in *inside {
            let ip: IpAddr = ip.parse().expect("ip");
            assert_eq!(f.check(ip), CidrOutcome::Deny, "{entry} must contain {ip}");
        }
        for ip in *outside {
            let ip: IpAddr = ip.parse().expect("ip");
            assert_eq!(
                f.check(ip),
                CidrOutcome::Allow,
                "{entry} must not contain {ip}"
            );
        }
    }
}

/// A dual-stack listener reports IPv4 clients as `::ffff:a.b.c.d`; the policy
/// must see them as the IPv4 address they are, in both lists.
#[test]
fn a9_v4_mapped_client_is_matched_as_ipv4() {
    let deny = CidrFilter::from_strs([] as [&str; 0], ["198.51.100.0/24"]).expect("valid");
    assert_eq!(deny.check(v6("::ffff:198.51.100.9")), CidrOutcome::Deny);
    let allow = CidrFilter::from_strs(["192.0.2.0/24"], [] as [&str; 0]).expect("valid");
    assert_eq!(allow.check(v6("::ffff:192.0.2.9")), CidrOutcome::Allow);
    assert_eq!(allow.check(v6("::ffff:192.0.3.9")), CidrOutcome::Deny);
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

/// from_strs refuses the whole filter at the first bad entry, and names it.
#[test]
fn a9_from_strs_propagates_parse_error() {
    let err = CidrFilter::from_strs(["10.0.0.0/8"], ["198.51.100.0/24", "10.1.2.255/24"])
        .expect_err("host bits must refuse the filter");
    assert_eq!(err.entry, "10.1.2.255/24");
    assert!(
        matches!(err.reason, IpRangeError::HostBitsSet { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("'10.1.2.255/24'"), "{err}");
}
