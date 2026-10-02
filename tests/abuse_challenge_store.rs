//! Tests for the A-16 CAPTCHA challenge plumbing and the A-48 federation
//! state↔session MAC primitive.
//!
//! D-4 taxonomy: unit + adversarial (challenge isolation, threshold edge
//! cases, MAC tampering) per the abuse prevention plan §4.1.
//!
//! Closes: §3.18 (no CAPTCHA-of-last-resort).
//!
//! Origin: split out of the former `tests/abuse_risk.rs` when the A-11 risk
//! scorer and the A-49 refresh-context drift scoring were removed in Hearth
//! 3.0.0. Their removal is covered by `tests/abuse_risk_and_sms_removed.rs`.

use std::net::{IpAddr, Ipv4Addr};

use hearth::abuse::challenge::{
    CaptchaProvider, ChallengeConfig, ChallengeOutcome, IpChallengeStore, NoopCaptchaProvider,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

fn store(threshold: u32) -> IpChallengeStore {
    IpChallengeStore::with_config(ChallengeConfig {
        threshold: Some(threshold),
        ..ChallengeConfig::default()
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// A-16 — Challenge store: unit tests
// ─────────────────────────────────────────────────────────────────────────────

// Unit: disabled store

/// Disabled store must always allow, never challenge.
#[test]
fn a16_disabled_store_always_allows() {
    let s = IpChallengeStore::disabled();
    for i in 0u8..=255 {
        assert_eq!(
            s.record_failure(ip(i)),
            ChallengeOutcome::Allow,
            "disabled store must allow failure from ip({})",
            i
        );
        assert_eq!(s.check(ip(i)), ChallengeOutcome::Allow);
    }
}

// Unit: threshold crossing

/// IP must remain in Allow until threshold is reached.
#[test]
fn a16_under_threshold_allows() {
    let s = store(5);
    for i in 0..4 {
        assert_eq!(
            s.record_failure(ip(1)),
            ChallengeOutcome::Allow,
            "failure {} of 4 must allow",
            i
        );
    }
    assert_eq!(
        s.check(ip(1)),
        ChallengeOutcome::Allow,
        "before threshold must still allow"
    );
}

/// Exactly at threshold: that failure's `record_failure` returns `ChallengeRequired`.
#[test]
fn a16_threshold_triggers_challenge_on_crossing() {
    let s = store(3);
    s.record_failure(ip(2));
    s.record_failure(ip(2));
    let outcome = s.record_failure(ip(2));
    assert_eq!(
        outcome,
        ChallengeOutcome::ChallengeRequired,
        "3rd failure must return ChallengeRequired"
    );
}

/// After threshold crossed, `check()` must return `ChallengeRequired`.
#[test]
fn a16_check_reflects_challenge_state() {
    let s = store(2);
    s.record_failure(ip(3));
    s.record_failure(ip(3));
    assert_eq!(
        s.check(ip(3)),
        ChallengeOutcome::ChallengeRequired,
        "check() must reflect challenge state"
    );
}

// Unit: clear

/// `clear()` must reset challenge state.
#[test]
fn a16_clear_resets_challenge_state() {
    let s = store(2);
    s.record_failure(ip(4));
    s.record_failure(ip(4));
    assert_eq!(s.check(ip(4)), ChallengeOutcome::ChallengeRequired);
    s.clear(ip(4));
    assert_eq!(
        s.check(ip(4)),
        ChallengeOutcome::Allow,
        "after clear() IP must allow again"
    );
}

/// `clear()` on an unknown IP must not panic.
#[test]
fn a16_clear_unknown_ip_is_noop() {
    let s = store(5);
    s.clear(ip(200)); // never seen IP — must not panic
    assert_eq!(s.check(ip(200)), ChallengeOutcome::Allow);
}

// Unit: IP isolation

/// Challenges on one IP must not affect other IPs.
#[test]
fn a16_ip_isolation() {
    let s = store(1);
    s.record_failure(ip(10));
    assert_eq!(s.check(ip(10)), ChallengeOutcome::ChallengeRequired);
    assert_eq!(
        s.check(ip(11)),
        ChallengeOutcome::Allow,
        "ip(11) must not be affected by ip(10) failures"
    );
}

// Unit: noop provider

/// `NoopCaptchaProvider::widget_html` must return an empty string.
#[test]
fn a16_noop_provider_empty_widget() {
    assert_eq!(NoopCaptchaProvider.widget_html(), "");
}

/// `NoopCaptchaProvider::verify` must always return `true` (fail-open).
#[test]
fn a16_noop_provider_always_verifies() {
    let p = NoopCaptchaProvider;
    assert!(p.verify("", ip(1)));
    assert!(p.verify("any-token", ip(1)));
    assert!(p.verify("garbage-xyz-123", ip(2)));
}

// ─────────────────────────────────────────────────────────────────────────────
// A-16 — Adversarial: challenge store edge cases
// ─────────────────────────────────────────────────────────────────────────────

/// Adversarial: threshold = 1 means the first failure triggers a challenge.
#[test]
fn a16_adversarial_threshold_one_immediate_challenge() {
    let s = store(1);
    assert_eq!(
        s.record_failure(ip(20)),
        ChallengeOutcome::ChallengeRequired,
        "threshold=1: first failure must immediately challenge"
    );
    assert_eq!(s.check(ip(20)), ChallengeOutcome::ChallengeRequired);
}

/// Adversarial: subsequent failures after threshold keep IP in challenge.
#[test]
fn a16_adversarial_additional_failures_keep_challenge() {
    let s = store(2);
    s.record_failure(ip(30));
    s.record_failure(ip(30)); // threshold reached
    s.record_failure(ip(30)); // additional failure
    assert_eq!(
        s.check(ip(30)),
        ChallengeOutcome::ChallengeRequired,
        "additional failures must keep IP in challenge state"
    );
}

/// Adversarial: clearing then failing again re-enters challenge at threshold.
#[test]
fn a16_adversarial_reenter_challenge_after_clear() {
    let s = store(2);
    s.record_failure(ip(40));
    s.record_failure(ip(40)); // enter challenge
    s.clear(ip(40)); // exit challenge
    s.record_failure(ip(40));
    assert_eq!(
        s.check(ip(40)),
        ChallengeOutcome::Allow,
        "one failure after clear must allow"
    );
    s.record_failure(ip(40)); // second failure
    assert_eq!(
        s.check(ip(40)),
        ChallengeOutcome::ChallengeRequired,
        "threshold crossed again must re-enter challenge"
    );
}

/// Adversarial: many different IPs do not interfere.
#[test]
fn a16_adversarial_many_ips_independent() {
    let s = store(3);
    // Exhaust threshold for every even IP.
    for i in (0u8..20).step_by(2) {
        s.record_failure(ip(i));
        s.record_failure(ip(i));
        s.record_failure(ip(i));
        assert_eq!(s.check(ip(i)), ChallengeOutcome::ChallengeRequired);
    }
    // Odd IPs must be unaffected.
    for i in (1u8..20).step_by(2) {
        assert_eq!(
            s.check(ip(i)),
            ChallengeOutcome::Allow,
            "ip({}) must not be in challenge",
            i
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A-16: error code contract
// ─────────────────────────────────────────────────────────────────────────────

/// `IdentityError::StepUpChallengeRequired` must have a wire error code
/// that API callers can inspect to gate CAPTCHA / MFA prompts (A-16).
#[test]
fn a16_abuse_challenge_required_error_code() {
    use hearth::identity::IdentityError;
    let err = IdentityError::StepUpChallengeRequired;
    let code = err.wire_error_code();
    assert!(
        code.is_some(),
        "StepUpChallengeRequired must carry a wire error code"
    );
    let code_str = code.expect("wire error code must be Some");
    assert!(
        code_str.contains("CHALLENGE") || code_str.contains("STEP_UP") || code_str.contains("MFA"),
        "wire error code must be challenge/step-up/mfa related: {code_str:?}"
    );
}

/// `IdentityError::StepUpChallengeRequired` must have a non-empty Display.
#[test]
fn a16_abuse_challenge_required_display() {
    use hearth::identity::IdentityError;
    let display = format!("{}", IdentityError::StepUpChallengeRequired);
    assert!(
        !display.is_empty(),
        "AbuseChallengeRequired must have a non-empty Display"
    );
    assert!(
        display.to_lowercase().contains("challenge"),
        "Display must mention 'challenge': {display}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-48 — Federation state↔session binding (MAC primitive tests)
// ─────────────────────────────────────────────────────────────────────────────

/// The federation state MAC must be deterministic for the same inputs.
#[test]
fn a48_federation_state_mac_is_deterministic() {
    use hearth::identity::federation::compute_federation_state_mac;
    let secret = [42u8; 32];
    let token = "test-state-token";
    let mac1 = compute_federation_state_mac(&secret, token);
    let mac2 = compute_federation_state_mac(&secret, token);
    assert_eq!(mac1, mac2, "MAC must be deterministic");
    assert!(!mac1.is_empty(), "MAC must be non-empty");
}

/// The federation state MAC verifier must accept the correct MAC.
#[test]
fn a48_federation_state_mac_roundtrip() {
    use hearth::identity::federation::{compute_federation_state_mac, verify_federation_state_mac};
    let secret = [7u8; 32];
    let token = "abc-state-123";
    let mac = compute_federation_state_mac(&secret, token);
    assert!(
        verify_federation_state_mac(&secret, token, &mac),
        "correct MAC must verify"
    );
}

/// A wrong MAC must fail verification.
#[test]
fn a48_federation_state_mac_rejects_wrong_mac() {
    use hearth::identity::federation::{compute_federation_state_mac, verify_federation_state_mac};
    let secret = [7u8; 32];
    let mac = compute_federation_state_mac(&secret, "token-a");
    assert!(
        !verify_federation_state_mac(&secret, "token-b", &mac),
        "wrong state token must fail"
    );
}

/// A wrong secret must fail verification.
#[test]
fn a48_federation_state_mac_rejects_wrong_secret() {
    use hearth::identity::federation::{compute_federation_state_mac, verify_federation_state_mac};
    let token = "abc";
    let mac = compute_federation_state_mac(&[1u8; 32], token);
    assert!(
        !verify_federation_state_mac(&[2u8; 32], token, &mac),
        "wrong secret must fail"
    );
}

/// The federation state MAC must be domain-separated from the confirm-ticket MAC.
#[test]
fn a48_federation_state_mac_domain_separated() {
    use hearth::core::UserId;
    use hearth::identity::federation::{compute_confirm_ticket_mac, compute_federation_state_mac};
    let secret = [9u8; 32];
    let token = "shared-value";
    let user = UserId::generate();
    let state_mac = compute_federation_state_mac(&secret, token);
    let ticket_mac = compute_confirm_ticket_mac(&secret, &user, token);
    assert_ne!(
        state_mac, ticket_mac,
        "state MAC and ticket MAC must differ (domain separation)"
    );
}
