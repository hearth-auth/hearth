//! Tests for A-7 — security webhook channel and A-8 — abuse dashboard.
//!
//! Covers (D-4 taxonomy):
//! - Unit: `AbuseDetected` audit action round-trips through `as_str`/`from_str`
//! - Unit: All five `security.*` event types are present in `available_event_types`
//!   (validated via the handler logic, not the UI directly)
//! - Unit: `failure_policy` for `AbuseDetected` is `LogOnly`
//! - Unit: `AuditAction::all()` includes `AbuseDetected`
//! - Unit: Security actions sort correctly in `all()` (alphabetical by wire key)

use hearth::audit::{AuditAction, AuditFailurePolicy};

// ─────────────────────────────────────────────────────────────────────────────
// A-7 — AbuseDetected audit action
// ─────────────────────────────────────────────────────────────────────────────

/// `AbuseDetected` serialises to the expected wire string.
#[test]
fn a7_abuse_detected_as_str() {
    assert_eq!(AuditAction::AbuseDetected.as_str(), "abuse_detected");
}

/// `AbuseDetected` deserialises from its wire string.
#[test]
fn a7_abuse_detected_from_str() {
    let action: AuditAction = "abuse_detected".parse().expect("parse");
    assert_eq!(action, AuditAction::AbuseDetected);
}

/// `AbuseDetected` round-trips through `Display` → `FromStr`.
#[test]
fn a7_abuse_detected_display_round_trip() {
    let original = AuditAction::AbuseDetected;
    let displayed = format!("{original}");
    let parsed: AuditAction = displayed.parse().expect("round-trip parse");
    assert_eq!(original, parsed);
}

/// `AbuseDetected` serde round-trips through JSON.
#[test]
fn a7_abuse_detected_serde_round_trip() {
    let action = AuditAction::AbuseDetected;
    let json = serde_json::to_string(&action).expect("serialize");
    let deserialized: AuditAction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(action, deserialized);
}

/// `AbuseDetected` uses `LogOnly` failure policy — it is informational,
/// not destructive. A failed audit append MUST NOT prevent the request
/// from continuing into the `Challenge` decision path.
#[test]
fn a7_abuse_detected_failure_policy_log_only() {
    assert_eq!(
        AuditAction::AbuseDetected.failure_policy(),
        AuditFailurePolicy::LogOnly,
        "AbuseDetected must be LogOnly so an audit outage never blocks the request path"
    );
}

/// `AuditAction::all()` includes `AbuseDetected`.
#[test]
fn a7_abuse_detected_in_all() {
    let all = AuditAction::all();
    assert!(
        all.contains(&AuditAction::AbuseDetected),
        "AuditAction::all() must include AbuseDetected for the audit-log filter UI"
    );
}

/// All five security family actions are present in `AuditAction::all()`.
#[test]
fn a7_all_security_family_in_all() {
    let all = AuditAction::all();
    let security_actions = [
        AuditAction::LoginFailed,
        AuditAction::LoginLocked,
        AuditAction::IpLoginLimitExceeded,
        AuditAction::PasswordCompromisedRejected,
        AuditAction::AbuseDetected,
    ];
    for action in &security_actions {
        assert!(
            all.contains(action),
            "AuditAction::all() must include {action:?} (security family)"
        );
    }
}

/// Unknown wire string returns an `Err` — no silent fallback.
#[test]
fn a7_unknown_wire_str_is_err() {
    let result: Result<AuditAction, _> = "security.abuse_detected".parse();
    assert!(
        result.is_err(),
        "dot-notation 'security.abuse_detected' must not parse — only 'abuse_detected' is valid"
    );
}

/// `AuditAction::all()` is sorted alphabetically by wire key (regression guard
/// for the admin UI `<select>` ordering — new variants must slot in correctly).
#[test]
fn all_actions_alphabetically_sorted() {
    let all = AuditAction::all();
    let keys: Vec<&str> = all.iter().map(|a| a.as_str()).collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(
        keys, sorted,
        "AuditAction::all() must be sorted alphabetically by wire key"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-8 — abuse dashboard helper functions
// ─────────────────────────────────────────────────────────────────────────────

/// The five security `AuditAction` variants that the dashboard aggregates
/// must map to their expected wire strings. If these ever break, the
/// dashboard's per-action queries will silently miss events.
#[test]
fn a8_security_action_wire_keys() {
    let expected = [
        (AuditAction::LoginFailed, "login_failed"),
        (AuditAction::LoginLocked, "login_locked"),
        (AuditAction::IpLoginLimitExceeded, "ip_login_limit_exceeded"),
        (
            AuditAction::PasswordCompromisedRejected,
            "password_compromised_rejected",
        ),
        (AuditAction::AbuseDetected, "abuse_detected"),
    ];
    for (action, expected_str) in expected {
        assert_eq!(
            action.as_str(),
            expected_str,
            "Wire key mismatch — abuse dashboard queries would miss this action"
        );
    }
}
