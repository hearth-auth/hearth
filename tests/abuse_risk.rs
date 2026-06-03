//! Tests for the A-11 step-up MFA risk scorer and the A-16 CAPTCHA challenge
//! plumbing.
//!
//! D-4 taxonomy: unit (scorer rules, signal weights) + adversarial (threshold
//! bypass attempts, forced step-up, challenge isolation) per the abuse
//! prevention plan §4.1.
//!
//! Closes: §3.7 (no anomaly/risk scoring on login), §3.18 (no CAPTCHA-of-last-resort).

// Risk scores of 0.0 (sum of nothing) and 1.0 (result of .min(1.0) clamp) are
// guaranteed exact by the arithmetic, so float equality is appropriate in tests.
#![allow(clippy::float_cmp)]

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};

use hearth::abuse::challenge::{
    CaptchaProvider, ChallengeConfig, ChallengeOutcome, IpChallengeStore, NoopCaptchaProvider,
};
use hearth::identity::risk::{
    build_risk_context, DefaultRiskScorer, RiskContext, RiskScorer, RiskScorerConfig, RiskSignal,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

fn enabled_scorer() -> DefaultRiskScorer {
    DefaultRiskScorer::new(RiskScorerConfig {
        enabled: true,
        ..RiskScorerConfig::default()
    })
}

fn enabled_scorer_with_threshold(threshold: f32) -> DefaultRiskScorer {
    DefaultRiskScorer::new(RiskScorerConfig {
        enabled: true,
        step_up_threshold: threshold,
        ..RiskScorerConfig::default()
    })
}

fn store(threshold: u32) -> IpChallengeStore {
    IpChallengeStore::with_config(ChallengeConfig {
        threshold: Some(threshold),
        ..ChallengeConfig::default()
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// A-11 — Risk scorer: unit tests
// ─────────────────────────────────────────────────────────────────────────────

// Unit: disabled scorer

/// Disabled scorer must never block login regardless of signals.
#[test]
fn a11_disabled_scorer_does_not_trigger_step_up() {
    let scorer = DefaultRiskScorer::disabled();
    let ctx = RiskContext {
        signals: vec![
            RiskSignal::NewDevice,
            RiskSignal::NewCountry,
            RiskSignal::BreachCorpusHit,
            RiskSignal::PasswordAge { days: 1000 },
        ],
    };
    let result = scorer.score(&ctx);
    assert_eq!(result.score, 0.0, "disabled scorer must score 0.0");
    assert!(
        !result.step_up_required,
        "disabled scorer must not require step-up"
    );
}

// Unit: individual signal weights

/// NewDevice alone must NOT trigger step-up with default threshold (0.3 < 0.5).
#[test]
fn a11_new_device_alone_does_not_trigger_step_up() {
    let scorer = enabled_scorer();
    let ctx = RiskContext {
        signals: vec![RiskSignal::NewDevice],
    };
    let result = scorer.score(&ctx);
    assert!(
        (result.score - 0.3).abs() < 1e-5,
        "NewDevice must score 0.3"
    );
    assert!(
        !result.step_up_required,
        "NewDevice alone must not trigger step-up at default threshold"
    );
}

/// NewCountry alone must NOT trigger step-up with default threshold (0.4 < 0.5).
#[test]
fn a11_new_country_alone_does_not_trigger_step_up() {
    let scorer = enabled_scorer();
    let ctx = RiskContext {
        signals: vec![RiskSignal::NewCountry],
    };
    let result = scorer.score(&ctx);
    assert!(
        (result.score - 0.4).abs() < 1e-5,
        "NewCountry must score 0.4"
    );
    assert!(
        !result.step_up_required,
        "NewCountry alone must not trigger step-up at default threshold"
    );
}

/// BreachCorpusHit must always trigger step-up (weight = 1.0 >= 0.5 threshold).
#[test]
fn a11_breach_corpus_hit_forces_step_up() {
    let scorer = enabled_scorer();
    let ctx = RiskContext {
        signals: vec![RiskSignal::BreachCorpusHit],
    };
    let result = scorer.score(&ctx);
    assert_eq!(result.score, 1.0, "BreachCorpusHit must score 1.0");
    assert!(
        result.step_up_required,
        "BreachCorpusHit must always force step-up"
    );
}

/// PasswordAge below threshold must score 0.0.
#[test]
fn a11_password_age_below_threshold_does_not_score() {
    let scorer = enabled_scorer();
    let ctx = RiskContext {
        signals: vec![RiskSignal::PasswordAge { days: 100 }],
    };
    let result = scorer.score(&ctx);
    assert_eq!(result.score, 0.0, "PasswordAge < 365 must score 0.0");
}

/// PasswordAge at or above threshold must score password_age_weight.
#[test]
fn a11_password_age_at_threshold_scores() {
    let scorer = enabled_scorer();
    let ctx = RiskContext {
        signals: vec![RiskSignal::PasswordAge { days: 365 }],
    };
    let result = scorer.score(&ctx);
    assert!(
        (result.score - 0.2).abs() < 1e-5,
        "PasswordAge = 365 must score 0.2"
    );
}

// Unit: signal combinations

/// NewDevice + NewCountry must trigger step-up (0.3 + 0.4 = 0.7 >= 0.5).
#[test]
fn a11_new_device_plus_new_country_triggers_step_up() {
    let scorer = enabled_scorer();
    let ctx = RiskContext {
        signals: vec![RiskSignal::NewDevice, RiskSignal::NewCountry],
    };
    let result = scorer.score(&ctx);
    assert!(
        result.score >= 0.5,
        "NewDevice + NewCountry must cross threshold"
    );
    assert!(result.step_up_required);
}

/// Score is capped at 1.0 regardless of how many signals fire.
#[test]
fn a11_score_is_capped_at_one() {
    let scorer = enabled_scorer();
    let ctx = RiskContext {
        signals: vec![
            RiskSignal::NewDevice,
            RiskSignal::NewCountry,
            RiskSignal::BreachCorpusHit,
            RiskSignal::PasswordAge { days: 999 },
        ],
    };
    let result = scorer.score(&ctx);
    assert_eq!(result.score, 1.0, "score must be capped at 1.0");
}

// Unit: build_risk_context helper

/// Recognised device must not emit NewDevice signal.
#[test]
fn a11_recognised_device_no_new_device_signal() {
    let ctx = build_risk_context(true, false, None, false);
    assert!(
        !ctx.signals.contains(&RiskSignal::NewDevice),
        "recognised device must produce no NewDevice signal"
    );
}

/// Unrecognised device must emit NewDevice signal.
#[test]
fn a11_unrecognised_device_emits_new_device_signal() {
    let ctx = build_risk_context(false, false, None, false);
    assert!(
        ctx.signals.contains(&RiskSignal::NewDevice),
        "unrecognised device must emit NewDevice signal"
    );
}

/// Old credential (> 365 days) must produce PasswordAge >= 365 signal.
#[test]
fn a11_old_credential_emits_password_age_signal() {
    let old = SystemTime::now() - Duration::from_secs(500 * 86_400);
    let ctx = build_risk_context(true, false, Some(old), false);
    let has_age = ctx
        .signals
        .iter()
        .any(|s| matches!(s, RiskSignal::PasswordAge { days } if *days >= 365));
    assert!(
        has_age,
        "500-day credential must produce PasswordAge >= 365"
    );
}

/// Breach corpus hit must be reflected in context.
#[test]
fn a11_breach_corpus_hit_in_context() {
    let ctx = build_risk_context(true, false, None, true);
    assert!(ctx.signals.contains(&RiskSignal::BreachCorpusHit));
}

// Unit: configurable thresholds

/// Low threshold (0.1) makes NewDevice alone trigger step-up.
#[test]
fn a11_custom_low_threshold_triggers_on_new_device() {
    let scorer = enabled_scorer_with_threshold(0.1);
    let ctx = RiskContext {
        signals: vec![RiskSignal::NewDevice], // weight 0.3 > 0.1
    };
    let result = scorer.score(&ctx);
    assert!(
        result.step_up_required,
        "0.3 >= 0.1 custom threshold must trigger step-up"
    );
}

/// High threshold (0.9) prevents step-up from NewDevice + NewCountry alone.
#[test]
fn a11_custom_high_threshold_prevents_step_up_on_combined_signals() {
    let scorer = enabled_scorer_with_threshold(0.9);
    let ctx = RiskContext {
        signals: vec![RiskSignal::NewDevice, RiskSignal::NewCountry], // 0.3 + 0.4 = 0.7 < 0.9
    };
    let result = scorer.score(&ctx);
    assert!(
        !result.step_up_required,
        "0.7 < 0.9 threshold must not trigger step-up"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-11 — Adversarial: score manipulation attempts
// ─────────────────────────────────────────────────────────────────────────────

/// Adversarial: duplicate signals must not bypass cap.
#[test]
fn a11_adversarial_duplicate_signals_do_not_bypass_cap() {
    let scorer = enabled_scorer();
    // Inject 100 NewDevice signals — should still cap at 1.0.
    let signals = vec![RiskSignal::NewDevice; 100];
    let ctx = RiskContext { signals };
    let result = scorer.score(&ctx);
    assert!(
        result.score <= 1.0,
        "score must not exceed 1.0 with duplicate signals"
    );
}

/// Adversarial: zero-day password (PasswordAge { days: 0 }) must score 0.
#[test]
fn a11_adversarial_zero_day_password_no_age_score() {
    let scorer = enabled_scorer();
    let ctx = RiskContext {
        signals: vec![RiskSignal::PasswordAge { days: 0 }],
    };
    let result = scorer.score(&ctx);
    assert_eq!(
        result.score, 0.0,
        "PasswordAge {{ days: 0 }} must score 0.0"
    );
    assert!(!result.step_up_required);
}

/// Adversarial: PasswordAge just below threshold must not score.
#[test]
fn a11_adversarial_password_age_just_below_threshold_no_score() {
    let scorer = enabled_scorer();
    let ctx = RiskContext {
        signals: vec![RiskSignal::PasswordAge { days: 364 }],
    };
    let result = scorer.score(&ctx);
    assert_eq!(
        result.score, 0.0,
        "PasswordAge {{ days: 364 }} must not score"
    );
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
// A-11 + A-16 combined: error code contract
// ─────────────────────────────────────────────────────────────────────────────

/// `IdentityError::StepUpChallengeRequired` must have a wire error code
/// that API callers can inspect to gate CAPTCHA / MFA prompts (A-11 / A-16).
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

// ─────────────────────────────────────────────────────────────────────────────
// A-49 — Refresh context delta risk signal
// ─────────────────────────────────────────────────────────────────────────────

/// Disabled scorer must not block refresh even if UA changed.
#[test]
fn a49_disabled_scorer_does_not_block_refresh_context_delta() {
    use hearth::identity::risk::{DefaultRiskScorer, RiskContext, RiskScorer, RiskSignal};
    let scorer = DefaultRiskScorer::disabled();
    let ctx = RiskContext {
        signals: vec![RiskSignal::RefreshContextDelta {
            ua_changed: true,
            asn_changed: true,
        }],
    };
    let result = scorer.score(&ctx);
    assert_eq!(result.score, 0.0, "disabled scorer must score 0.0");
    assert!(
        !result.step_up_required,
        "disabled scorer must not require step-up"
    );
}

/// UA change alone must trigger step-up when scorer is enabled with low threshold.
#[test]
fn a49_ua_change_triggers_step_up_at_low_threshold() {
    use hearth::identity::risk::{
        DefaultRiskScorer, RiskContext, RiskScorer, RiskScorerConfig, RiskSignal,
    };
    let scorer = DefaultRiskScorer::new(RiskScorerConfig {
        enabled: true,
        step_up_threshold: 0.3,
        ..RiskScorerConfig::default()
    });
    let ctx = RiskContext {
        signals: vec![RiskSignal::RefreshContextDelta {
            ua_changed: true,
            asn_changed: false,
        }],
    };
    let result = scorer.score(&ctx);
    assert!(result.score > 0.0, "UA change must contribute to score");
    assert!(
        result.step_up_required,
        "UA change must trigger step-up at low threshold"
    );
}

/// Both UA and ASN changing adds 2× the weight.
#[test]
fn a49_both_changed_scores_two_dimensions() {
    use hearth::identity::risk::{
        DefaultRiskScorer, RiskContext, RiskScorer, RiskScorerConfig, RiskSignal,
    };
    let scorer = DefaultRiskScorer::new(RiskScorerConfig {
        enabled: true,
        refresh_context_delta_weight: 0.3,
        step_up_threshold: 0.9,
        ..RiskScorerConfig::default()
    });
    // Both changed → 0.3 + 0.3 = 0.6, but threshold is 0.9 → no step-up
    let both = RiskContext {
        signals: vec![RiskSignal::RefreshContextDelta {
            ua_changed: true,
            asn_changed: true,
        }],
    };
    let one = RiskContext {
        signals: vec![RiskSignal::RefreshContextDelta {
            ua_changed: true,
            asn_changed: false,
        }],
    };
    let score_both = scorer.score(&both).score;
    let score_one = scorer.score(&one).score;
    assert!(
        score_both > score_one,
        "both dimensions changing must score higher than one: {score_both} vs {score_one}"
    );
}

/// No change must score 0.0 (neither ua_changed nor asn_changed).
#[test]
fn a49_no_change_scores_zero() {
    use hearth::identity::risk::{
        DefaultRiskScorer, RiskContext, RiskScorer, RiskScorerConfig, RiskSignal,
    };
    let scorer = DefaultRiskScorer::new(RiskScorerConfig {
        enabled: true,
        ..RiskScorerConfig::default()
    });
    let ctx = RiskContext {
        signals: vec![RiskSignal::RefreshContextDelta {
            ua_changed: false,
            asn_changed: false,
        }],
    };
    let result = scorer.score(&ctx);
    assert_eq!(result.score, 0.0, "no-change delta must score 0.0");
    assert!(
        !result.step_up_required,
        "no-change delta must not trigger step-up"
    );
}
