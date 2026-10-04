//! Integration tests for A-12 adaptive exponential lockout backoff.
//!
//! D-4 taxonomy:
//! - **Unit**: Escalation through all offense levels.
//! - **Unit**: Check reflects active lockout; check before lockout allows.
//! - **Unit**: Clear removes lockout and resets offense history.
//! - **Adversarial**: Saturation at max offense level; key isolation.
//!
//! Closes: HEA-1191 §A-12 (Adaptive lockout backoff).

use std::time::Duration;

use hearth::abuse::backoff::{AdaptiveBackoffStore, BackoffConfig, BackoffOutcome};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn store_4level() -> AdaptiveBackoffStore {
    AdaptiveBackoffStore::with_config(BackoffConfig {
        durations: vec![
            Duration::from_secs(60),
            Duration::from_secs(300),
            Duration::from_secs(1_800),
            Duration::from_secs(86_400),
        ],
        offense_cooldown: Duration::from_secs(7 * 24 * 3600),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Disabled store
// ─────────────────────────────────────────────────────────────────────────────

/// Disabled store always allows regardless of how many lockouts are recorded.
#[test]
fn a12_disabled_store_always_allows() {
    let s = AdaptiveBackoffStore::disabled();
    for _ in 0..100 {
        assert_eq!(s.record_lockout("ip:1.2.3.4"), BackoffOutcome::Allow);
        assert_eq!(s.check("ip:1.2.3.4"), BackoffOutcome::Allow);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Escalation
// ─────────────────────────────────────────────────────────────────────────────

/// First lockout is at offense level 1 with the first duration (~1 min).
#[test]
fn a12_first_lockout_is_level_one() {
    let s = store_4level();
    let outcome = s.record_lockout("ip:1.1.1.1");
    assert!(
        matches!(
            outcome,
            BackoffOutcome::Locked {
                offense_level: 1,
                ..
            }
        ),
        "first lockout must be offense level 1, got {outcome:?}"
    );
}

/// First lockout duration is approximately 60 seconds.
#[test]
fn a12_first_lockout_duration_is_one_minute() {
    use std::time::Instant;
    let s = store_4level();
    if let BackoffOutcome::Locked { until, .. } = s.record_lockout("ip:1.1.1.2") {
        let remaining = until.duration_since(Instant::now());
        assert!(
            remaining > Duration::from_secs(58) && remaining <= Duration::from_secs(60),
            "first lockout duration must be ~60 s, got {remaining:?}"
        );
    } else {
        panic!("expected Locked outcome");
    }
}

/// Each successive lockout call on the same key escalates the offense level.
#[test]
fn a12_successive_lockouts_escalate_offense_level() {
    let s = store_4level();
    for expected_level in 1u32..=4 {
        match s.record_lockout("ip:escalate") {
            BackoffOutcome::Locked { offense_level, .. } => {
                assert_eq!(
                    offense_level, expected_level,
                    "lockout #{expected_level} must be at offense level {expected_level}"
                );
            }
            BackoffOutcome::Allow => panic!("expected Locked at level {expected_level}"),
        }
    }
}

/// Beyond the maximum level the duration saturates at the last configured value.
#[test]
fn a12_beyond_max_level_saturates_at_last_duration() {
    use std::time::Instant;
    let s = store_4level();
    for _ in 0..6 {
        s.record_lockout("ip:sat");
    }
    if let BackoffOutcome::Locked { until, .. } = s.record_lockout("ip:sat") {
        let remaining = until.duration_since(Instant::now());
        assert!(
            remaining > Duration::from_secs(86_390),
            "saturated lockout must be ~24 h, got {remaining:?}"
        );
    } else {
        panic!("expected Locked");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Check
// ─────────────────────────────────────────────────────────────────────────────

/// check() returns Allow before any lockout is recorded.
#[test]
fn a12_check_before_lockout_allows() {
    let s = store_4level();
    assert_eq!(s.check("ip:fresh"), BackoffOutcome::Allow);
}

/// check() returns Locked immediately after record_lockout().
#[test]
fn a12_check_after_lockout_returns_locked() {
    let s = store_4level();
    s.record_lockout("ip:locked");
    assert!(
        matches!(s.check("ip:locked"), BackoffOutcome::Locked { .. }),
        "check must reflect active lockout state"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Clear
// ─────────────────────────────────────────────────────────────────────────────

/// clear() removes lockout state; subsequent check() returns Allow.
#[test]
fn a12_clear_removes_lockout() {
    let s = store_4level();
    s.record_lockout("u:alice");
    assert!(matches!(s.check("u:alice"), BackoffOutcome::Locked { .. }));
    s.clear("u:alice");
    assert_eq!(
        s.check("u:alice"),
        BackoffOutcome::Allow,
        "clear must remove lockout"
    );
}

/// clear() on an unknown key is a no-op (must not panic).
#[test]
fn a12_clear_unknown_key_noop() {
    let s = store_4level();
    s.clear("does:not:exist");
    assert_eq!(s.check("does:not:exist"), BackoffOutcome::Allow);
}

// ─────────────────────────────────────────────────────────────────────────────
// Peek
// ─────────────────────────────────────────────────────────────────────────────

/// peek_next_duration returns first-level duration for a fresh key.
#[test]
fn a12_peek_next_duration_fresh_key() {
    let s = store_4level();
    assert_eq!(s.peek_next_duration("new"), Duration::from_secs(60));
}

/// peek_next_duration returns second-level duration after one lockout.
#[test]
fn a12_peek_next_duration_after_one_lockout() {
    let s = store_4level();
    s.record_lockout("k");
    assert_eq!(s.peek_next_duration("k"), Duration::from_secs(300));
}

// ─────────────────────────────────────────────────────────────────────────────
// Key isolation
// ─────────────────────────────────────────────────────────────────────────────

/// Lockout on one key does not affect another key.
#[test]
fn a12_key_isolation() {
    let s = store_4level();
    s.record_lockout("ip:a");
    assert!(matches!(s.check("ip:a"), BackoffOutcome::Locked { .. }));
    assert_eq!(
        s.check("ip:b"),
        BackoffOutcome::Allow,
        "lockout on ip:a must not affect ip:b"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial: single-duration config
// ─────────────────────────────────────────────────────────────────────────────

/// Single-duration config saturates immediately and stays there.
#[test]
fn a12_single_duration_always_same_lockout() {
    let s = AdaptiveBackoffStore::with_config(BackoffConfig {
        durations: vec![Duration::from_secs(3600)],
        offense_cooldown: Duration::from_secs(86_400),
    });
    use std::time::Instant;
    for _ in 0..5 {
        if let BackoffOutcome::Locked { until, .. } = s.record_lockout("ip:single") {
            let remaining = until.duration_since(Instant::now());
            assert!(
                remaining > Duration::from_secs(3590),
                "single-duration config must always produce ~1 h lockout, got {remaining:?}"
            );
        } else {
            panic!("expected Locked");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Configured schedule reaches the `POST /ui/device` guard
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the device-approval guard the server builds from `security:` YAML.
fn device_guard_from_yaml(yaml: &str) -> hearth::abuse::device_approval::DeviceApprovalGuard {
    let config = hearth::config::Config::from_yaml_str_unchecked(yaml).expect("config parses");
    hearth::abuse::runtime::build_device_approval_guard(&config.security)
}

/// Records wrong codes for `key` until the guard locks it, and returns how
/// long the lockout lasts, measured from just before the tripping attempt.
fn device_lockout_length(
    guard: &hearth::abuse::device_approval::DeviceApprovalGuard,
    key: &str,
) -> Duration {
    use hearth::abuse::device_approval::DeviceApprovalDecision;
    for _ in 0..4 {
        assert_eq!(guard.record_failure(key), DeviceApprovalDecision::Allow);
    }
    let before = std::time::Instant::now();
    match guard.record_failure(key) {
        DeviceApprovalDecision::LockedOut { until, .. } => until.duration_since(before),
        other => panic!("the fifth wrong code must lock the key, got {other:?}"),
    }
}

/// `security.adaptive_backoff.durations: ["2m"]` sets the `/ui/device` lockout
/// to two minutes instead of the compiled one-minute first step.
#[test]
fn a12_configured_schedule_reaches_device_approval_guard() {
    let guard = device_guard_from_yaml("security:\n  adaptive_backoff:\n    durations: [\"2m\"]\n");
    let lockout = device_lockout_length(&guard, "realm:user");
    assert!(
        lockout >= Duration::from_secs(120) && lockout < Duration::from_secs(121),
        "the configured 2m step must govern the device lockout, got {lockout:?}"
    );
}

/// `durations: []` turns off escalation but keeps a flat lockout on
/// `/ui/device`: a repeat offence locks the key for the same one minute.
#[test]
fn a12_empty_schedule_keeps_flat_device_lockout() {
    let guard = device_guard_from_yaml("security:\n  adaptive_backoff:\n    durations: []\n");
    for offence in 1..=3 {
        let lockout = device_lockout_length(&guard, "realm:user");
        assert!(
            lockout >= Duration::from_secs(60) && lockout < Duration::from_secs(61),
            "offence {offence}: an empty schedule must keep a flat 1m lockout, got {lockout:?}"
        );
    }
}
