//! Integration and adversarial tests for A-50 — cross-realm aggregation cap.
//!
//! Tests are standalone (no server needed) and exercise
//! [`CrossRealmAggregationCap`] directly to verify the §3.53 bypass is closed.

use hearth::abuse::detector::{
    CrossRealmAggCapConfig, CrossRealmAggregationCap, CrossRealmOutcome,
};
use std::time::{Duration, Instant};

fn realm(n: u32) -> String {
    format!("realm-{n:04}")
}

// ── Integration: basic lifecycle ──────────────────────────────────────────────

#[test]
fn integration_under_thresholds_sends_allowed() {
    let cap = CrossRealmAggregationCap::new(CrossRealmAggCapConfig {
        alert_threshold: 5,
        email_realm_soft_cap: 10,
        email_realm_hard_cap: 20,
        ..CrossRealmAggCapConfig::default()
    });
    let now = Instant::now();
    for i in 0..4u32 {
        assert_eq!(
            cap.check_email_with_time(&realm(i), "user@example.com", now),
            CrossRealmOutcome::Allow,
            "realm {i} must be below alert threshold"
        );
    }
}

#[test]
fn integration_alert_then_soft_then_hard_cap_escalation() {
    let cap = CrossRealmAggregationCap::new(CrossRealmAggCapConfig {
        alert_threshold: 2,
        email_realm_soft_cap: 4,
        email_realm_hard_cap: 6,
        ..CrossRealmAggCapConfig::default()
    });
    let now = Instant::now();
    let target = "victim@example.com";

    // Below alert
    assert_eq!(
        cap.check_email_with_time(&realm(0), target, now),
        CrossRealmOutcome::Allow
    );
    assert_eq!(
        cap.check_email_with_time(&realm(1), target, now),
        CrossRealmOutcome::Allow
    );

    // Cross alert threshold (realm_count = 3 > alert_threshold = 2)
    let out = cap.check_email_with_time(&realm(2), target, now);
    assert!(
        matches!(out, CrossRealmOutcome::MultiRealmAlert { .. }),
        "expected MultiRealmAlert at realm 3, got {out:?}"
    );

    // Cross soft cap (realm_count = 5 > soft_cap = 4)
    let _ = cap.check_email_with_time(&realm(3), target, now);
    let out = cap.check_email_with_time(&realm(4), target, now);
    assert!(
        matches!(out, CrossRealmOutcome::SoftCap { .. }),
        "expected SoftCap at realm 5, got {out:?}"
    );

    // Cross hard cap (realm_count = 7 > hard_cap = 6)
    let _ = cap.check_email_with_time(&realm(5), target, now);
    let out = cap.check_email_with_time(&realm(6), target, now);
    assert!(
        matches!(out, CrossRealmOutcome::HardCap { .. }),
        "expected HardCap at realm 7, got {out:?}"
    );
}

#[test]
fn integration_phone_and_email_counters_independent() {
    let cap = CrossRealmAggregationCap::new(CrossRealmAggCapConfig {
        alert_threshold: 2,
        email_realm_soft_cap: 3,
        email_realm_hard_cap: 5,
        sms_realm_soft_cap: 3,
        sms_realm_hard_cap: 5,
        ..CrossRealmAggCapConfig::default()
    });
    let now = Instant::now();
    // Exhaust email cap
    for i in 0..5u32 {
        let _ = cap.check_email_with_time(&realm(i), "user@example.com", now);
    }
    // SMS cap for a different target must be unaffected
    let out = cap.check_sms_with_time(&realm(0), "+12025550100", now);
    assert_eq!(
        out,
        CrossRealmOutcome::Allow,
        "email cap exhaustion must not bleed into SMS counter"
    );
}

#[test]
fn integration_window_rotation_resets_cap() {
    let cap = CrossRealmAggregationCap::new(CrossRealmAggCapConfig {
        alert_threshold: 2,
        email_realm_soft_cap: 3,
        email_realm_hard_cap: 4,
        window: Duration::from_millis(200),
        ..CrossRealmAggCapConfig::default()
    });
    let t0 = Instant::now();
    let target = "user@example.com";

    // Fill to hard cap
    for i in 0..4u32 {
        let _ = cap.check_email_with_time(&realm(i), target, t0);
    }
    assert!(matches!(
        cap.check_email_with_time(&realm(4), target, t0),
        CrossRealmOutcome::HardCap { .. }
    ));

    // Advance past full window + half window to push old data out
    let t1 = t0 + Duration::from_millis(350);
    // Record one entry to trigger full rotation
    let _ = cap.check_email_with_time("probe", target, t1);
    let t2 = t1 + Duration::from_millis(120);
    // After second half-period rotation, only "probe" remains in prev
    let out = cap.check_email_with_time("fresh-realm", target, t2);
    // 2 realms in window ("probe" + "fresh-realm") — should be at or below soft cap
    assert!(
        !matches!(out, CrossRealmOutcome::HardCap { .. }),
        "hard cap must clear after window rotation, got {out:?}"
    );
}

// ── Adversarial: §3.53 — 50-realm bypass attempt ─────────────────────────────

#[test]
fn adversarial_fifty_realm_bypass_blocked() {
    // §3.53: an attacker splits sends across 50 distinct realms to slip past
    // A-4's per-realm budget.  A-50 must detect and block this pattern.
    let cap = CrossRealmAggregationCap::new(CrossRealmAggCapConfig {
        alert_threshold: 3,
        email_realm_soft_cap: 5,
        email_realm_hard_cap: 10,
        ..CrossRealmAggCapConfig::default()
    });
    let now = Instant::now();
    let target = "victim@example.com";

    let mut last = CrossRealmOutcome::Allow;
    for i in 0..50u32 {
        last = cap.check_email_with_time(&realm(i), target, now);
    }
    assert!(
        matches!(last, CrossRealmOutcome::HardCap { .. }),
        "50-realm bypass must trigger HardCap, got {last:?}"
    );
}

#[test]
fn adversarial_sms_cross_realm_attack_blocked() {
    let cap = CrossRealmAggregationCap::new(CrossRealmAggCapConfig {
        sms_realm_soft_cap: 3,
        sms_realm_hard_cap: 5,
        ..CrossRealmAggCapConfig::default()
    });
    let now = Instant::now();
    let phone = "+12025550199";

    let mut last = CrossRealmOutcome::Allow;
    for i in 0..20u32 {
        last = cap.check_sms_with_time(&realm(i), phone, now);
    }
    assert!(
        matches!(last, CrossRealmOutcome::HardCap { .. }),
        "SMS cross-realm attack must trigger HardCap, got {last:?}"
    );
}

// ── Adversarial: single-realm high volume must not trigger cross-realm cap ────

#[test]
fn adversarial_single_realm_high_volume_not_penalised() {
    // A legitimate high-volume sender from one realm must never be penalized by
    // the cross-realm cap (A-4 per-realm cap handles that use-case).
    let cap = CrossRealmAggregationCap::new(CrossRealmAggCapConfig {
        alert_threshold: 3,
        email_realm_soft_cap: 5,
        email_realm_hard_cap: 10,
        ..CrossRealmAggCapConfig::default()
    });
    let now = Instant::now();
    for _ in 0..50_000 {
        let out = cap.check_email_with_time("single-realm", "user@example.com", now);
        assert_eq!(
            out,
            CrossRealmOutcome::Allow,
            "single-realm high-volume must not trigger cross-realm cap"
        );
    }
}

// ── Adversarial: realm_count in outcome is plausible ─────────────────────────

#[test]
fn adversarial_realm_count_in_hard_cap_is_plausible() {
    let cap = CrossRealmAggregationCap::new(CrossRealmAggCapConfig {
        alert_threshold: 2,
        email_realm_soft_cap: 3,
        email_realm_hard_cap: 5,
        ..CrossRealmAggCapConfig::default()
    });
    let now = Instant::now();
    let target = "x@example.com";
    for i in 0..5u32 {
        let _ = cap.check_email_with_time(&realm(i), target, now);
    }
    let out = cap.check_email_with_time(&realm(5), target, now);
    if let CrossRealmOutcome::HardCap { realm_count } = out {
        assert!(
            realm_count >= 5,
            "realm_count in HardCap must be >= hard_cap (5), got {realm_count}"
        );
    } else {
        panic!("expected HardCap, got {out:?}");
    }
}
