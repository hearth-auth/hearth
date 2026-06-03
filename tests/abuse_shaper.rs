//! Adversarial tests for the global request shaper (A-2) and gRPC
//! rate-limit interceptor (A-15).
//!
//! D-4 taxonomy: negative-scenario (adversarial) per §3.41.

use std::net::{IpAddr, Ipv4Addr};

use hearth::abuse::shaper::{RequestShaper, ShaperConfig, ShaperOutcome};

fn ip(b: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, b))
}

// ─────────────────────────────────────────────────────────────────────────────
// A-2 — Global request shaper
// ─────────────────────────────────────────────────────────────────────────────

/// Adversarial: IP that exceeds per-IP rate limit is throttled.
#[test]
fn a2_ip_rate_limit_enforced() {
    let shaper = RequestShaper::with_config(ShaperConfig {
        ip_rps: Some(5),
        realm_rps: None,
    });
    for i in 0..5 {
        assert_eq!(
            shaper.check(ip(1), ""),
            ShaperOutcome::Allow,
            "request {i} must be allowed"
        );
    }
    assert_eq!(
        shaper.check(ip(1), ""),
        ShaperOutcome::IpLimited,
        "6th request from same IP must be rate-limited"
    );
}

/// Adversarial: realm that exceeds per-realm rate limit is throttled.
#[test]
fn a2_realm_rate_limit_enforced() {
    let shaper = RequestShaper::with_config(ShaperConfig {
        ip_rps: None,
        realm_rps: Some(3),
    });
    for _ in 0..3 {
        assert_eq!(shaper.check(ip(1), "my-realm"), ShaperOutcome::Allow);
    }
    assert_eq!(
        shaper.check(ip(2), "my-realm"),
        ShaperOutcome::RealmLimited,
        "4th request to same realm from different IP must still be realm-limited"
    );
}

/// Negative: different IPs do not share per-IP counters.
#[test]
fn a2_different_ips_independent() {
    let shaper = RequestShaper::with_config(ShaperConfig {
        ip_rps: Some(2),
        realm_rps: None,
    });
    // Exhaust IP 1.
    for _ in 0..2 {
        assert_eq!(shaper.check(ip(1), ""), ShaperOutcome::Allow);
    }
    assert_eq!(shaper.check(ip(1), ""), ShaperOutcome::IpLimited);
    // IP 2 is unaffected.
    assert_eq!(
        shaper.check(ip(2), ""),
        ShaperOutcome::Allow,
        "different IP must not share rate-limit counter"
    );
}

/// Negative: disabled shaper always allows all requests.
#[test]
fn a2_disabled_shaper_allows_all() {
    let shaper = RequestShaper::disabled();
    for _ in 0..100_000 {
        assert_eq!(shaper.check(ip(1), "any-realm"), ShaperOutcome::Allow);
    }
}

/// Negative: different realms do not share per-realm counters.
#[test]
fn a2_different_realms_independent() {
    let shaper = RequestShaper::with_config(ShaperConfig {
        ip_rps: None,
        realm_rps: Some(1),
    });
    assert_eq!(shaper.check(ip(1), "realm-a"), ShaperOutcome::Allow);
    assert_eq!(shaper.check(ip(1), "realm-a"), ShaperOutcome::RealmLimited);
    assert_eq!(
        shaper.check(ip(1), "realm-b"),
        ShaperOutcome::Allow,
        "realm-b must be independent of realm-a"
    );
}
