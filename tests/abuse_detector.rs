//! A-3 Distributed-attack detector + A-4 outbound volume shield — integration tests.
//!
//! D-4 taxonomy:
//! - **Unit**: rolling-window cardinality, threshold crossing, bucket rotation.
//! - **Integration**: username-per-IP and IP-per-username detector, volume shield
//!   per-realm isolation.
//! - **Adversarial**: repeated same-item, exact-threshold boundary, hard vs soft cap.
//!
//! Closes: HEA-1189 §A-3 (distributed-attack detector) + §A-4 (outbound volume shield).

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use hearth::abuse::detector::{
    DetectorConfig, DetectorOutcome, DistributedAttackDetector, OutboundVolumeShield,
    VolumeShieldConfig, VolumeShieldOutcome,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn ip(last_octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet))
}

fn username(n: u32) -> String {
    format!("user{n}@example.com")
}

// ─────────────────────────────────────────────────────────────────────────────
// A-3 — DistributedAttackDetector: username-per-IP dimension
// ─────────────────────────────────────────────────────────────────────────────

/// Under the threshold, checking a single IP with few usernames is allowed.
#[test]
fn a3_unit_under_username_threshold_allows() {
    let cfg = DetectorConfig {
        username_per_ip_threshold: 5,
        ip_per_username_threshold: 100,
        ..DetectorConfig::default()
    };
    let det = DistributedAttackDetector::new(cfg);
    let now = Instant::now();
    let attacker = ip(1);

    // 5 distinct usernames — exactly at threshold, should still allow.
    for i in 0..5 {
        let outcome = det.check_with_time(attacker, &username(i), now);
        assert!(
            matches!(outcome, DetectorOutcome::Allow),
            "expected Allow for username {i}, got {outcome:?}",
        );
    }
}

/// Crossing the username-per-IP threshold trips Challenge.
#[test]
fn a3_unit_over_username_threshold_challenges() {
    let cfg = DetectorConfig {
        username_per_ip_threshold: 3,
        ip_per_username_threshold: 100,
        ..DetectorConfig::default()
    };
    let det = DistributedAttackDetector::new(cfg);
    let now = Instant::now();
    let attacker = ip(1);

    for i in 0..3 {
        let _ = det.check_with_time(attacker, &username(i), now);
    }
    // 4th distinct username crosses threshold.
    let outcome = det.check_with_time(attacker, &username(3), now);
    assert!(
        matches!(outcome, DetectorOutcome::Challenge { .. }),
        "expected Challenge after threshold crossing, got {outcome:?}",
    );
}

/// Repeated same username from the same IP does not inflate the count.
#[test]
fn a3_unit_repeated_username_not_inflated() {
    let cfg = DetectorConfig {
        username_per_ip_threshold: 3,
        ip_per_username_threshold: 100,
        ..DetectorConfig::default()
    };
    let det = DistributedAttackDetector::new(cfg);
    let now = Instant::now();
    let attacker = ip(1);

    // Same username 100 times.
    for _ in 0..100 {
        let outcome = det.check_with_time(attacker, "alice@example.com", now);
        assert!(
            matches!(outcome, DetectorOutcome::Allow),
            "repeated same username must not trip detector",
        );
    }
}

/// Different IPs are tracked independently on the username-per-IP dimension.
#[test]
fn a3_unit_different_ips_independent() {
    let cfg = DetectorConfig {
        username_per_ip_threshold: 3,
        ip_per_username_threshold: 100,
        ..DetectorConfig::default()
    };
    let det = DistributedAttackDetector::new(cfg);
    let now = Instant::now();

    // Each IP gets its own counter; 3 usernames each — none crosses threshold.
    for ip_octet in 1..=10 {
        for user_i in 0..3 {
            let outcome = det.check_with_time(ip(ip_octet), &username(user_i), now);
            assert!(
                matches!(outcome, DetectorOutcome::Allow),
                "IP {ip_octet} username {user_i}: expected Allow",
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A-3 — DistributedAttackDetector: IP-per-username dimension
// ─────────────────────────────────────────────────────────────────────────────

/// Crossing the IP-per-username threshold trips Challenge.
#[test]
fn a3_unit_over_ip_per_username_challenges() {
    let cfg = DetectorConfig {
        username_per_ip_threshold: 100,
        ip_per_username_threshold: 4,
        ..DetectorConfig::default()
    };
    let det = DistributedAttackDetector::new(cfg);
    let now = Instant::now();
    let victim = "alice@example.com";

    for i in 0..4 {
        let _ = det.check_with_time(ip(i), victim, now);
    }
    // 5th distinct IP targeting alice crosses threshold.
    let outcome = det.check_with_time(ip(4), victim, now);
    assert!(
        matches!(outcome, DetectorOutcome::Challenge { .. }),
        "expected Challenge from IP-per-username crossing, got {outcome:?}",
    );
}

/// Repeated same IP targeting one username does not inflate the count.
#[test]
fn a3_unit_repeated_ip_not_inflated() {
    let cfg = DetectorConfig {
        username_per_ip_threshold: 100,
        ip_per_username_threshold: 3,
        ..DetectorConfig::default()
    };
    let det = DistributedAttackDetector::new(cfg);
    let now = Instant::now();
    let victim = "alice@example.com";

    for _ in 0..100 {
        let outcome = det.check_with_time(ip(1), victim, now);
        assert!(
            matches!(outcome, DetectorOutcome::Allow),
            "repeated same IP must not trip IP-per-username detector",
        );
    }
}

/// Different usernames are tracked independently on the IP-per-username dimension.
#[test]
fn a3_unit_different_usernames_independent() {
    let cfg = DetectorConfig {
        username_per_ip_threshold: 100,
        ip_per_username_threshold: 3,
        ..DetectorConfig::default()
    };
    let det = DistributedAttackDetector::new(cfg);
    let now = Instant::now();

    // 3 IPs each target 10 different usernames — none crosses threshold.
    for user_i in 0..10 {
        let victim = username(user_i);
        for ip_octet in 1..=3 {
            let outcome = det.check_with_time(ip(ip_octet), &victim, now);
            assert!(
                matches!(outcome, DetectorOutcome::Allow),
                "username {user_i} IP {ip_octet}: expected Allow",
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A-3 — Window rotation (time-based)
// ─────────────────────────────────────────────────────────────────────────────

/// After the window expires, counts reset and the detector allows again.
#[test]
fn a3_window_rotation_resets_count() {
    let window = Duration::from_millis(200);
    let cfg = DetectorConfig {
        window,
        username_per_ip_threshold: 3,
        ip_per_username_threshold: 100,
    };
    let det = DistributedAttackDetector::new(cfg);
    let attacker = ip(1);
    let t0 = Instant::now();

    // Exceed the threshold at t0.
    for i in 0..4 {
        let _ = det.check_with_time(attacker, &username(i), t0);
    }
    let over = det.check_with_time(attacker, &username(4), t0);
    assert!(
        matches!(over, DetectorOutcome::Challenge { .. }),
        "should be in Challenge at t0",
    );

    // After more than the window has elapsed, the window rotates.
    let t_after = t0 + window + Duration::from_millis(10);
    // Send just 1 username after rotation — should be allowed.
    let after = det.check_with_time(attacker, &username(99), t_after);
    assert!(
        matches!(after, DetectorOutcome::Allow),
        "expected Allow after window rotation, got {after:?}",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-3 — Disabled detector always allows
// ─────────────────────────────────────────────────────────────────────────────

/// `DistributedAttackDetector::disabled()` always returns Allow regardless of volume.
#[test]
fn a3_disabled_always_allows() {
    let det = DistributedAttackDetector::disabled();
    let attacker = ip(1);
    let now = Instant::now();

    // Hammer 1000 distinct usernames from one IP — must always be Allow.
    for i in 0..1000 {
        let outcome = det.check_with_time(attacker, &username(i), now);
        assert!(
            matches!(outcome, DetectorOutcome::Allow),
            "disabled detector must always allow",
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A-3 — Adversarial: distributed spray
// ─────────────────────────────────────────────────────────────────────────────

/// Credential stuffing pattern: 1 attempt per IP, many IPs, 1 username.
/// The IP-per-username dimension should trigger.
#[test]
fn a3_adversarial_distributed_spray_trips_ip_per_username() {
    let cfg = DetectorConfig {
        username_per_ip_threshold: 100,
        ip_per_username_threshold: 10,
        ..DetectorConfig::default()
    };
    let det = DistributedAttackDetector::new(cfg);
    let victim = "alice@example.com";
    let now = Instant::now();

    let mut last_outcome = DetectorOutcome::Allow;
    for octet in 1..=20 {
        last_outcome = det.check_with_time(ip(octet), victim, now);
    }
    // After 20 distinct IPs (> threshold of 10), must be Challenge.
    assert!(
        matches!(last_outcome, DetectorOutcome::Challenge { .. }),
        "distributed spray must trip IP-per-username detector",
    );
}

/// Password spray: one IP, many distinct usernames.
/// The username-per-IP dimension should trigger.
#[test]
fn a3_adversarial_password_spray_trips_username_per_ip() {
    let cfg = DetectorConfig {
        username_per_ip_threshold: 10,
        ip_per_username_threshold: 100,
        ..DetectorConfig::default()
    };
    let det = DistributedAttackDetector::new(cfg);
    let attacker = ip(1);
    let now = Instant::now();

    let mut last_outcome = DetectorOutcome::Allow;
    for i in 0..20 {
        last_outcome = det.check_with_time(attacker, &username(i), now);
    }
    assert!(
        matches!(last_outcome, DetectorOutcome::Challenge { .. }),
        "password spray must trip username-per-IP detector",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-4 — OutboundVolumeShield: soft and hard caps
// ─────────────────────────────────────────────────────────────────────────────

/// Under the soft cap, all sends are allowed.
#[test]
fn a4_unit_under_soft_cap_allows() {
    let cfg = VolumeShieldConfig {
        email_soft_cap: 10,
        email_hard_cap: 20,
        ..VolumeShieldConfig::default()
    };
    let shield = OutboundVolumeShield::new(cfg);
    let now = Instant::now();
    let realm = "realm1";

    for i in 0..10u32 {
        let recipient = format!("user{i}@example.com");
        let outcome = shield.check_email_with_time(realm, &recipient, now);
        assert!(
            matches!(outcome, VolumeShieldOutcome::Allow),
            "expected Allow for recipient {i}",
        );
    }
}

/// Crossing the soft cap returns SoftCap outcome.
#[test]
fn a4_unit_soft_cap_triggers() {
    let cfg = VolumeShieldConfig {
        email_soft_cap: 5,
        email_hard_cap: 20,
        ..VolumeShieldConfig::default()
    };
    let shield = OutboundVolumeShield::new(cfg);
    let now = Instant::now();
    let realm = "realm1";

    // Reach the soft cap.
    for i in 0..5u32 {
        let _ = shield.check_email_with_time(realm, &format!("user{i}@example.com"), now);
    }
    // 6th distinct recipient crosses soft cap.
    let outcome = shield.check_email_with_time(realm, "user5@example.com", now);
    assert!(
        matches!(outcome, VolumeShieldOutcome::SoftCap),
        "expected SoftCap at 6th recipient, got {outcome:?}",
    );
}

/// Crossing the hard cap returns HardCap outcome.
#[test]
fn a4_unit_hard_cap_triggers() {
    let cfg = VolumeShieldConfig {
        email_soft_cap: 2,
        email_hard_cap: 5,
        ..VolumeShieldConfig::default()
    };
    let shield = OutboundVolumeShield::new(cfg);
    let now = Instant::now();
    let realm = "realm1";

    for i in 0..5u32 {
        let _ = shield.check_email_with_time(realm, &format!("user{i}@example.com"), now);
    }
    // 6th distinct recipient crosses hard cap.
    let outcome = shield.check_email_with_time(realm, "user5@example.com", now);
    assert!(
        matches!(outcome, VolumeShieldOutcome::HardCap),
        "expected HardCap at 6th recipient, got {outcome:?}",
    );
}

/// Repeated sends to the same recipient are not double-counted.
#[test]
fn a4_unit_repeated_recipient_not_double_counted() {
    let cfg = VolumeShieldConfig {
        email_soft_cap: 5,
        email_hard_cap: 10,
        ..VolumeShieldConfig::default()
    };
    let shield = OutboundVolumeShield::new(cfg);
    let now = Instant::now();
    let realm = "realm1";

    // 100 sends to the same address.
    for _ in 0..100 {
        let outcome = shield.check_email_with_time(realm, "alice@example.com", now);
        assert!(
            matches!(outcome, VolumeShieldOutcome::Allow),
            "repeated recipient must not inflate distinct count",
        );
    }
}

/// Per-realm isolation: one realm crossing its cap does not affect another realm.
#[test]
fn a4_unit_per_realm_isolation() {
    let cfg = VolumeShieldConfig {
        email_soft_cap: 3,
        email_hard_cap: 5,
        ..VolumeShieldConfig::default()
    };
    let shield = OutboundVolumeShield::new(cfg);
    let now = Instant::now();

    // Realm A exhausts its soft cap.
    for i in 0..5u32 {
        let _ = shield.check_email_with_time("realm_a", &format!("user{i}@example.com"), now);
    }

    // Realm B should still be at zero.
    let outcome = shield.check_email_with_time("realm_b", "user0@example.com", now);
    assert!(
        matches!(outcome, VolumeShieldOutcome::Allow),
        "realm_b must be unaffected by realm_a's volume",
    );
}

/// After the window expires, distinct-recipient count resets.
#[test]
fn a4_window_rotation_resets_count() {
    let window = Duration::from_millis(200);
    let cfg = VolumeShieldConfig {
        window,
        email_soft_cap: 3,
        email_hard_cap: 10,
        ..VolumeShieldConfig::default()
    };
    let shield = OutboundVolumeShield::new(cfg);
    let realm = "realm1";
    let t0 = Instant::now();

    // Cross the soft cap.
    for i in 0..4u32 {
        let _ = shield.check_email_with_time(realm, &format!("user{i}@example.com"), t0);
    }
    let at_cap = shield.check_email_with_time(realm, "new@example.com", t0);
    assert!(
        matches!(at_cap, VolumeShieldOutcome::SoftCap),
        "should be SoftCap before rotation",
    );

    // After more than a full window, counts reset.
    let t_after = t0 + window + Duration::from_millis(10);
    let after = shield.check_email_with_time(realm, "fresh@example.com", t_after);
    assert!(
        matches!(after, VolumeShieldOutcome::Allow),
        "expected Allow after window rotation, got {after:?}",
    );
}

/// Disabled shield always allows.
#[test]
fn a4_disabled_always_allows() {
    let shield = OutboundVolumeShield::disabled();
    let now = Instant::now();

    for i in 0..10_000u32 {
        let outcome = shield.check_email_with_time("realm", &format!("user{i}@example.com"), now);
        assert!(
            matches!(outcome, VolumeShieldOutcome::Allow),
            "disabled shield must always allow",
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A-4 — Adversarial: email pumping scenario
// ─────────────────────────────────────────────────────────────────────────────

/// Email pumping: one tenant sends to 10k distinct recipients in one window.
/// Hard cap must block once exceeded.
#[test]
fn a4_adversarial_email_pumping_hard_cap() {
    let cfg = VolumeShieldConfig {
        email_soft_cap: 100,
        email_hard_cap: 200,
        ..VolumeShieldConfig::default()
    };
    let shield = OutboundVolumeShield::new(cfg);
    let realm = "attacker_realm";
    let now = Instant::now();

    let mut saw_hard_cap = false;
    for i in 0..500u32 {
        let outcome = shield.check_email_with_time(realm, &format!("victim{i}@example.com"), now);
        if matches!(outcome, VolumeShieldOutcome::HardCap) {
            saw_hard_cap = true;
            break;
        }
    }
    assert!(
        saw_hard_cap,
        "hard cap must trigger during email pumping attack"
    );
}
