//! Integration tests for A-17 login-event tarpit.
//!
//! D-4 taxonomy:
//! - **Unit**: Below threshold — no delay; at/above threshold — delay returned.
//! - **Unit**: Delay duration matches configuration.
//! - **Unit**: Clear resets tarpit state.
//! - **Adversarial**: threshold=1 triggers immediately; check before record
//!   never delays; IP isolation.
//!
//! Closes: HEA-1191 §A-17 (Login-event tarpit).

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use hearth::abuse::tarpit::{TarpitConfig, TarpitOutcome, TarpitStore};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn ip(b: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, b))
}

fn store_with(threshold: u32, delay_ms: u64) -> TarpitStore {
    TarpitStore::with_config(TarpitConfig {
        threshold: Some(threshold),
        window_secs: 60,
        delay_ms,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Disabled store
// ─────────────────────────────────────────────────────────────────────────────

/// Disabled tarpit always allows regardless of how many failures are recorded.
#[test]
fn a17_disabled_always_allows() {
    let s = TarpitStore::disabled();
    for _ in 0..1_000 {
        s.record_failure(ip(1));
    }
    assert_eq!(s.check(ip(1)), TarpitOutcome::Allow);
}

/// Disabled tarpit: record_failure is a no-op.
#[test]
fn a17_disabled_record_failure_noop() {
    let s = TarpitStore::disabled();
    s.record_failure(ip(2)); // must not panic
    assert_eq!(s.check(ip(2)), TarpitOutcome::Allow);
}

// ─────────────────────────────────────────────────────────────────────────────
// Below threshold
// ─────────────────────────────────────────────────────────────────────────────

/// Failures below threshold do not trigger tarpit.
#[test]
fn a17_below_threshold_allows() {
    let s = store_with(5, 200);
    for _ in 0..4 {
        s.record_failure(ip(3));
    }
    assert_eq!(
        s.check(ip(3)),
        TarpitOutcome::Allow,
        "4 failures below threshold of 5 must not trigger tarpit"
    );
}

/// Exactly one below the threshold still allows.
#[test]
fn a17_one_below_threshold_allows() {
    let s = store_with(10, 200);
    for _ in 0..9 {
        s.record_failure(ip(4));
    }
    assert_eq!(s.check(ip(4)), TarpitOutcome::Allow);
}

// ─────────────────────────────────────────────────────────────────────────────
// At and above threshold
// ─────────────────────────────────────────────────────────────────────────────

/// At threshold a Delay outcome is returned.
#[test]
fn a17_at_threshold_triggers_delay() {
    let s = store_with(3, 200);
    for _ in 0..3 {
        s.record_failure(ip(5));
    }
    assert_eq!(
        s.check(ip(5)),
        TarpitOutcome::Delay(Duration::from_millis(200)),
        "reaching threshold must trigger tarpit delay"
    );
}

/// Above threshold delay persists.
#[test]
fn a17_above_threshold_delay_persists() {
    let s = store_with(2, 150);
    for _ in 0..10 {
        s.record_failure(ip(6));
    }
    assert_eq!(
        s.check(ip(6)),
        TarpitOutcome::Delay(Duration::from_millis(150))
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Configured delay
// ─────────────────────────────────────────────────────────────────────────────

/// Delay duration matches what was configured (100 ms boundary).
#[test]
fn a17_delay_100ms_returned() {
    let s = store_with(1, 100);
    s.record_failure(ip(7));
    assert_eq!(
        s.check(ip(7)),
        TarpitOutcome::Delay(Duration::from_millis(100))
    );
}

/// Delay duration matches what was configured (500 ms boundary).
#[test]
fn a17_delay_500ms_returned() {
    let s = store_with(1, 500);
    s.record_failure(ip(8));
    assert_eq!(
        s.check(ip(8)),
        TarpitOutcome::Delay(Duration::from_millis(500))
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Clear
// ─────────────────────────────────────────────────────────────────────────────

/// clear() resets tarpit state; subsequent check() returns Allow.
#[test]
fn a17_clear_resets_tarpit() {
    let s = store_with(2, 200);
    s.record_failure(ip(9));
    s.record_failure(ip(9));
    assert_eq!(
        s.check(ip(9)),
        TarpitOutcome::Delay(Duration::from_millis(200))
    );
    s.clear(ip(9));
    assert_eq!(
        s.check(ip(9)),
        TarpitOutcome::Allow,
        "clear must reset tarpit state"
    );
}

/// clear() on an unknown IP is a no-op.
#[test]
fn a17_clear_unknown_ip_noop() {
    let s = store_with(2, 200);
    s.clear(ip(99)); // must not panic
    assert_eq!(s.check(ip(99)), TarpitOutcome::Allow);
}

// ─────────────────────────────────────────────────────────────────────────────
// IP isolation
// ─────────────────────────────────────────────────────────────────────────────

/// Failures on one IP do not affect another.
#[test]
fn a17_ip_isolation() {
    let s = store_with(1, 200);
    s.record_failure(ip(10));
    assert_eq!(
        s.check(ip(10)),
        TarpitOutcome::Delay(Duration::from_millis(200))
    );
    assert_eq!(
        s.check(ip(11)),
        TarpitOutcome::Allow,
        "failures on ip(10) must not tarpit ip(11)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial
// ─────────────────────────────────────────────────────────────────────────────

/// threshold=1: first recorded failure immediately triggers tarpit on next check.
#[test]
fn a17_adversarial_threshold_one_triggers_immediately() {
    let s = store_with(1, 200);
    s.record_failure(ip(20));
    assert_eq!(
        s.check(ip(20)),
        TarpitOutcome::Delay(Duration::from_millis(200)),
        "threshold=1: one failure must trigger tarpit"
    );
}

/// check before any record_failure never triggers.
#[test]
fn a17_adversarial_check_before_failures_never_delays() {
    let s = store_with(1, 200);
    // Check without recording any failure — must always allow.
    assert_eq!(
        s.check(ip(30)),
        TarpitOutcome::Allow,
        "check with no prior failures must not delay"
    );
}

/// Applying the tarpit delay asynchronously does not change check() result.
///
/// This test confirms the design contract: the Delay decision is idempotent
/// and repeated check() calls return the same outcome.  The actual sleep is
/// the caller's responsibility.
#[test]
fn a17_delay_outcome_is_idempotent() {
    let s = store_with(2, 200);
    s.record_failure(ip(40));
    s.record_failure(ip(40));
    let first = s.check(ip(40));
    let second = s.check(ip(40));
    assert_eq!(
        first, second,
        "repeated check() calls must return the same outcome"
    );
    assert_eq!(first, TarpitOutcome::Delay(Duration::from_millis(200)));
}
