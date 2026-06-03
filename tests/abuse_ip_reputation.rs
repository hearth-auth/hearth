//! Integration tests for P-2 IP reputation: Spamhaus DROP + MaxMind ASN/GeoIP2.
//!
//! D-4 taxonomy:
//! - **Unit**: Noop provider always returns clean verdict.
//! - **Unit**: `IpReputationVerdict::is_clean` reflects `is_blocklisted`.
//! - **Unit**: DROP list parser skips comment and blank lines.
//! - **Unit**: DROP list parser skips malformed CIDR lines without panicking.
//! - **Unit**: Known DROP-listed IPv4 address is flagged as blocklisted.
//! - **Unit**: IP just outside the DROP CIDR boundary returns clean.
//! - **Unit**: IPv6 DROP-listed address is flagged as blocklisted.
//! - **Unit**: Empty filter (initial state before first refresh) fails open.
//! - **Unit**: `from_text` with both DROP and EDROP lists merges correctly.
//! - **Unit**: MaxMind provider with missing DB file fails open.
//! - **Adversarial**: DROP list text containing only comments → empty filter, no panic.
//! - **Adversarial**: DROP list with garbage/binary lines → no panic, empty filter.
//! - **Adversarial**: IP at the exact start of a blocked /24 is flagged.
//! - **Adversarial**: IP at the last address of a blocked /24 is flagged.
//!
//! Closes: HEA-1203 (P-2 IP reputation).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hearth::abuse::ip_reputation::{
    maxmind::{MaxMindAsnConfig, MaxMindAsnProvider},
    spamhaus::SpamhausDropProvider,
    IpReputationPolicy, IpReputationProvider, NoopIpReputation,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// Sample Spamhaus DROP list text (IPv4).
///
/// Contains two synthetic CIDR entries used across tests.  Uses the real
/// Spamhaus DROP list format: comment lines start with `;`, data lines are
/// `CIDR ; SBLnnnnn`.
const SAMPLE_DROP: &str = "\
; Spamhaus DROP List 2024/01/01 - (c) 2024 The Spamhaus Project
; http://www.spamhaus.org/drop/drop.txt
; Last-Modified: Mon,  1 Jan 2024 00:00:01 GMT
; Expires: Tue,  2 Jan 2024 12:00:01 GMT
1.10.16.0/20 ; SBL000001
192.0.2.0/24 ; SBL000002
; End of DROP list
";

/// Sample Spamhaus EDROP list text (IPv6).
const SAMPLE_DROPV6: &str = "\
; Spamhaus EDROP List 2024/01/01 - (c) 2024 The Spamhaus Project
2001:db8::/32 ; SBL000003
";

// ─────────────────────────────────────────────────────────────────────────────
// NoopIpReputation
// ─────────────────────────────────────────────────────────────────────────────

/// Noop provider always returns a clean verdict regardless of the IP.
#[test]
fn p2_noop_always_clean() {
    let p = NoopIpReputation;
    let v = p.check(ipv4(1, 2, 3, 4));
    assert!(v.is_clean(), "noop must return clean verdict");
    assert!(!v.is_blocklisted);
    assert!(v.asn.is_none());
    assert!(v.asn_org.is_none());
}

/// Noop returns clean even for well-known abusive ranges.
#[test]
fn p2_noop_ignores_spamhaus_ranges() {
    let p = NoopIpReputation;
    // 1.10.16.1 would be in the DROP list — noop must still allow it.
    assert!(p.check(ipv4(1, 10, 16, 1)).is_clean());
}

// ─────────────────────────────────────────────────────────────────────────────
// IpReputationVerdict helpers
// ─────────────────────────────────────────────────────────────────────────────

/// `is_clean` returns false when `is_blocklisted` is set.
#[test]
fn p2_verdict_is_clean_reflects_blocklisted() {
    use hearth::abuse::ip_reputation::IpReputationVerdict;
    let blocked = IpReputationVerdict {
        is_blocklisted: true,
        ..Default::default()
    };
    assert!(!blocked.is_clean());

    let clean = IpReputationVerdict::default();
    assert!(clean.is_clean());
}

// ─────────────────────────────────────────────────────────────────────────────
// SpamhausDropProvider — parser
// ─────────────────────────────────────────────────────────────────────────────

/// Comment lines (starting with `;`) and blank lines are skipped; no panics.
#[test]
fn p2_drop_parser_skips_comments_and_blanks() {
    let only_comments = "\
; comment 1
; comment 2

; another comment
";
    let p = SpamhausDropProvider::from_text(only_comments, "");
    // An all-comment list produces an empty filter → fail-open.
    assert!(p.check(ipv4(1, 2, 3, 4)).is_clean());
}

/// Malformed CIDR lines (e.g. missing `/`) are silently skipped.
#[test]
fn p2_drop_parser_skips_malformed_lines() {
    let bad_list = "\
this is not a cidr ; SBL000001
also-bad
1.2.3.4  ; missing slash
1.10.16.0/20 ; SBL000002
";
    let p = SpamhausDropProvider::from_text(bad_list, "");
    // The one valid entry (1.10.16.0/20) must still be loaded.
    assert!(p.check(ipv4(1, 10, 16, 1)).is_blocklisted);
    // Skipping bad entries must not cause a panic.
    assert!(p.check(ipv4(8, 8, 8, 8)).is_clean());
}

/// A fully garbage (binary-like) list produces an empty filter and no panic.
#[test]
fn p2_drop_parser_garbage_input_no_panic() {
    let garbage = "\x00\x01\x02\u{ff}\u{fe}\r\ngarbage\nnot a cidr\n";
    let p = SpamhausDropProvider::from_text(garbage, "");
    // Fail-open: garbage input → empty filter → clean for all IPs.
    assert!(p.check(ipv4(1, 2, 3, 4)).is_clean());
}

// ─────────────────────────────────────────────────────────────────────────────
// SpamhausDropProvider — lookup correctness
// ─────────────────────────────────────────────────────────────────────────────

/// IP inside a DROP-listed /20 is flagged.
#[test]
fn p2_drop_ip_inside_drop_cidr_is_blocklisted() {
    let p = SpamhausDropProvider::from_text(SAMPLE_DROP, "");
    // 1.10.16.0/20 covers 1.10.16.0 – 1.10.31.255
    assert!(
        p.check(ipv4(1, 10, 16, 1)).is_blocklisted,
        "1.10.16.1 must be blocklisted"
    );
}

/// First address of a DROP-listed /20 is flagged.
#[test]
fn p2_drop_first_address_of_cidr_is_blocklisted() {
    let p = SpamhausDropProvider::from_text(SAMPLE_DROP, "");
    assert!(
        p.check(ipv4(1, 10, 16, 0)).is_blocklisted,
        "first address of /20 must be blocklisted"
    );
}

/// Last address of a DROP-listed /20 is flagged.
#[test]
fn p2_drop_last_address_of_cidr_is_blocklisted() {
    let p = SpamhausDropProvider::from_text(SAMPLE_DROP, "");
    // 1.10.16.0/20 → last address = 1.10.31.255
    assert!(
        p.check(ipv4(1, 10, 31, 255)).is_blocklisted,
        "last address of /20 must be blocklisted"
    );
}

/// IP just outside the DROP-listed /20 boundary is clean.
#[test]
fn p2_drop_address_just_outside_cidr_is_clean() {
    let p = SpamhausDropProvider::from_text(SAMPLE_DROP, "");
    // 1.10.32.0 is one address past the end of 1.10.16.0/20
    assert!(
        p.check(ipv4(1, 10, 32, 0)).is_clean(),
        "1.10.32.0 must be clean (outside /20)"
    );
}

/// Second DROP CIDR (192.0.2.0/24) is also correctly loaded.
#[test]
fn p2_drop_second_cidr_is_blocklisted() {
    let p = SpamhausDropProvider::from_text(SAMPLE_DROP, "");
    assert!(
        p.check(ipv4(192, 0, 2, 1)).is_blocklisted,
        "192.0.2.1 must be blocklisted"
    );
}

/// Google DNS (8.8.8.8) is not in any DROP list.
#[test]
fn p2_drop_google_dns_is_clean() {
    let p = SpamhausDropProvider::from_text(SAMPLE_DROP, "");
    assert!(p.check(ipv4(8, 8, 8, 8)).is_clean());
}

/// Localhost (127.0.0.1) is never in the DROP list.
#[test]
fn p2_drop_localhost_is_clean() {
    let p = SpamhausDropProvider::from_text(SAMPLE_DROP, "");
    assert!(p.check(ipv4(127, 0, 0, 1)).is_clean());
}

/// Empty filter (no DROP list loaded) fails open — every IP is clean.
#[test]
fn p2_drop_empty_filter_fails_open() {
    let p = SpamhausDropProvider::from_text("", "");
    assert!(p.check(ipv4(1, 10, 16, 1)).is_clean());
    assert!(p.check(ipv4(0, 0, 0, 0)).is_clean());
}

// ─────────────────────────────────────────────────────────────────────────────
// SpamhausDropProvider — IPv6 EDROP
// ─────────────────────────────────────────────────────────────────────────────

/// IPv6 address inside EDROP-listed /32 is flagged.
#[test]
fn p2_edrop_ipv6_inside_cidr_is_blocklisted() {
    let p = SpamhausDropProvider::from_text("", SAMPLE_DROPV6);
    // 2001:db8::/32 — any address inside it should be blocked
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
    assert!(
        p.check(ip).is_blocklisted,
        "2001:db8::1 must be blocklisted"
    );
}

/// IPv6 address outside EDROP-listed /32 is clean.
#[test]
fn p2_edrop_ipv6_outside_cidr_is_clean() {
    let p = SpamhausDropProvider::from_text("", SAMPLE_DROPV6);
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0dc0, 0, 0, 0, 0, 0, 1));
    assert!(p.check(ip).is_clean());
}

/// IPv4 address is not flagged by IPv6-only EDROP list.
#[test]
fn p2_edrop_ipv4_not_flagged_by_ipv6_list() {
    let p = SpamhausDropProvider::from_text("", SAMPLE_DROPV6);
    assert!(p.check(ipv4(1, 2, 3, 4)).is_clean());
}

// ─────────────────────────────────────────────────────────────────────────────
// SpamhausDropProvider — from_text merges both lists
// ─────────────────────────────────────────────────────────────────────────────

/// `from_text` with both DROP (v4) and EDROP (v6) lists correctly loads both.
#[test]
fn p2_from_text_merges_v4_and_v6_lists() {
    let p = SpamhausDropProvider::from_text(SAMPLE_DROP, SAMPLE_DROPV6);

    // IPv4 entry from DROP list.
    assert!(p.check(ipv4(1, 10, 16, 1)).is_blocklisted);
    // IPv6 entry from EDROP list.
    let ip6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
    assert!(p.check(ip6).is_blocklisted);
    // Unrelated addresses are clean.
    assert!(p.check(ipv4(8, 8, 8, 8)).is_clean());
}

// ─────────────────────────────────────────────────────────────────────────────
// SpamhausDropProvider — reload
// ─────────────────────────────────────────────────────────────────────────────

/// Reloading with a new list atomically replaces the old one.
#[test]
fn p2_drop_reload_replaces_filter_atomically() {
    let p = SpamhausDropProvider::from_text(SAMPLE_DROP, "");
    // Initially, 192.0.2.1 is blocklisted.
    assert!(p.check(ipv4(192, 0, 2, 1)).is_blocklisted);

    // Reload with an empty list.
    p.reload("", "");

    // After reload, 192.0.2.1 is clean (fail-open on empty list).
    assert!(p.check(ipv4(192, 0, 2, 1)).is_clean());
}

/// Reloading with a new CIDR replaces the old one.
#[test]
fn p2_drop_reload_with_new_cidrs() {
    let p = SpamhausDropProvider::from_text(SAMPLE_DROP, "");
    // Replace with a different list that blocks 8.8.8.0/24 instead.
    let new_list = "8.8.8.0/24 ; SBL999999\n";
    p.reload(new_list, "");

    assert!(
        p.check(ipv4(8, 8, 8, 8)).is_blocklisted,
        "8.8.8.8 must now be blocked"
    );
    assert!(
        p.check(ipv4(1, 10, 16, 1)).is_clean(),
        "1.10.16.1 must now be clean"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// MaxMindAsnProvider — fail-open
// ─────────────────────────────────────────────────────────────────────────────

/// MaxMind provider with a non-existent DB path fails open (clean verdict).
#[test]
fn p2_maxmind_missing_db_fails_open() {
    let config = MaxMindAsnConfig {
        db_path: "/nonexistent/does-not-exist/GeoLite2-ASN.mmdb".into(),
    };
    let provider = MaxMindAsnProvider::open(config);
    // Must not return Err — the provider is created in a failed/noop state.
    let v = provider.check(ipv4(8, 8, 8, 8));
    // Fail-open: missing DB → clean verdict.
    assert!(v.is_clean());
    assert!(v.asn.is_none());
    assert!(v.asn_org.is_none());
}

/// MaxMind provider with a path pointing to a non-MMDB file fails open.
#[test]
fn p2_maxmind_invalid_db_file_fails_open() {
    use std::io::Write;
    let mut tmp = tempfile::NamedTempFile::new().expect("temp file");
    write!(tmp, "this is not an mmdb file").expect("write");
    let config = MaxMindAsnConfig {
        db_path: tmp.path().to_path_buf(),
    };
    let provider = MaxMindAsnProvider::open(config);
    let v = provider.check(ipv4(1, 2, 3, 4));
    assert!(v.is_clean());
}

// ─────────────────────────────────────────────────────────────────────────────
// IpReputationPolicy
// ─────────────────────────────────────────────────────────────────────────────

/// Default policy is disabled (fail-open: checks are skipped).
#[test]
fn p2_default_policy_is_disabled() {
    let policy = IpReputationPolicy::default();
    assert!(!policy.enabled, "default policy must be disabled");
}

/// Policy with `enabled = true` is correctly read back.
#[test]
fn p2_policy_enabled_flag_roundtrip() {
    use hearth::abuse::ip_reputation::IpReputationAction;
    let policy = IpReputationPolicy {
        enabled: true,
        action: IpReputationAction::Block,
    };
    assert!(policy.enabled);
    assert_eq!(policy.action, IpReputationAction::Block);
}
