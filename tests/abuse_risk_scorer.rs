//! Tests for P-4 RiskScorer pluggable trait + rule-based reference engine.
//!
//! D-4 taxonomy:
//! - **Unit**: signal weight correctness, noop provider, disabled scorer.
//! - **Integration**: scorer wired as a dyn trait; full signal pipeline.
//! - **Adversarial**: boundary games, zero-weight bypass, weight saturation,
//!   custom-provider substitution without re-compile.
//!
//! Closes: HEA-1205 §P-4 (RiskScorer trait + reference rule engine).

// Score boundary assertions use exact 0.0/1.0 comparisons intentionally.
#![allow(clippy::float_cmp)]

use hearth::abuse::risk_scorer::{
    build_risk_context, NoopRiskScorer, RiskContext, RiskScore, RiskScorer, RiskScorerConfig,
    RiskSignal, RuleBasedRiskScorer,
};
use std::time::{Duration, SystemTime};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn enabled() -> RuleBasedRiskScorer {
    RuleBasedRiskScorer::new(RiskScorerConfig {
        enabled: true,
        ..RiskScorerConfig::default()
    })
}

fn ctx(signals: Vec<RiskSignal>) -> RiskContext {
    RiskContext { signals }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: NoopRiskScorer
// ─────────────────────────────────────────────────────────────────────────────

/// Noop always scores zero even when signals are present — no false positives.
#[test]
fn p4_noop_zero_no_signals() {
    let result = NoopRiskScorer.score(&RiskContext::default());
    assert_eq!(result.score, 0.0_f32);
    assert!(!result.step_up_required);
}

/// Noop zero even with a breach-corpus hit — never blocks login.
#[test]
fn p4_noop_zero_breach_hit() {
    let result = NoopRiskScorer.score(&ctx(vec![RiskSignal::BreachCorpusHit]));
    assert_eq!(result.score, 0.0_f32);
    assert!(!result.step_up_required);
}

/// Noop propagates signals into the output for observability.
#[test]
fn p4_noop_propagates_signals() {
    let signals = vec![RiskSignal::NewDevice, RiskSignal::NewCountry];
    let result = NoopRiskScorer.score(&ctx(signals.clone()));
    assert_eq!(result.signals, signals);
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: disabled scorer (fail-open gate)
// ─────────────────────────────────────────────────────────────────────────────

/// Disabled scorer returns 0.0 regardless of signals (fail-open mandate).
#[test]
fn p4_disabled_always_zero() {
    let scorer = RuleBasedRiskScorer::disabled();
    let result = scorer.score(&ctx(vec![
        RiskSignal::BreachCorpusHit,
        RiskSignal::NewDevice,
        RiskSignal::NewCountry,
    ]));
    assert_eq!(result.score, 0.0_f32);
    assert!(!result.step_up_required);
}

/// Disabled scorer also propagates signals for downstream logging.
#[test]
fn p4_disabled_propagates_signals() {
    let scorer = RuleBasedRiskScorer::disabled();
    let signals = vec![RiskSignal::NewDevice];
    let result = scorer.score(&ctx(signals.clone()));
    assert_eq!(result.signals, signals);
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: individual signal weights
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn p4_new_device_weight_0_3() {
    let result = enabled().score(&ctx(vec![RiskSignal::NewDevice]));
    assert!(
        (result.score - 0.3).abs() < f32::EPSILON,
        "NewDevice score = {}",
        result.score
    );
    // 0.3 < 0.5 default threshold → no step-up
    assert!(!result.step_up_required);
}

#[test]
fn p4_new_country_weight_0_4() {
    let result = enabled().score(&ctx(vec![RiskSignal::NewCountry]));
    assert!(
        (result.score - 0.4).abs() < f32::EPSILON,
        "NewCountry score = {}",
        result.score
    );
    assert!(!result.step_up_required);
}

#[test]
fn p4_device_plus_country_triggers_step_up() {
    // 0.3 + 0.4 = 0.7 >= 0.5 threshold
    let result = enabled().score(&ctx(vec![RiskSignal::NewDevice, RiskSignal::NewCountry]));
    assert!(result.score >= 0.5, "combined score = {}", result.score);
    assert!(result.step_up_required);
}

#[test]
fn p4_breach_corpus_hit_scores_1_0() {
    let result = enabled().score(&ctx(vec![RiskSignal::BreachCorpusHit]));
    assert_eq!(result.score, 1.0_f32, "breach must score 1.0");
    assert!(result.step_up_required);
}

#[test]
fn p4_password_age_fresh_scores_zero() {
    let result = enabled().score(&ctx(vec![RiskSignal::PasswordAge { days: 30 }]));
    assert_eq!(result.score, 0.0_f32, "fresh password must score 0.0");
    assert!(!result.step_up_required);
}

#[test]
fn p4_password_age_exactly_at_threshold_scores() {
    let result = enabled().score(&ctx(vec![RiskSignal::PasswordAge { days: 365 }]));
    assert!(
        (result.score - 0.2).abs() < f32::EPSILON,
        "score = {}",
        result.score
    );
}

#[test]
fn p4_refresh_ua_only_one_dim() {
    let result = enabled().score(&ctx(vec![RiskSignal::RefreshContextDelta {
        ua_changed: true,
        asn_changed: false,
    }]));
    let expected = 0.35_f32;
    assert!(
        (result.score - expected).abs() < f32::EPSILON,
        "score = {}, expected {expected}",
        result.score
    );
}

#[test]
fn p4_refresh_both_dims_doubles_weight() {
    let result = enabled().score(&ctx(vec![RiskSignal::RefreshContextDelta {
        ua_changed: true,
        asn_changed: true,
    }]));
    let expected = 0.70_f32;
    assert!(
        (result.score - expected).abs() < f32::EPSILON,
        "score = {}, expected {expected}",
        result.score
    );
    assert!(result.step_up_required, "0.7 >= 0.5 threshold");
}

#[test]
fn p4_refresh_no_dims_scores_zero() {
    let result = enabled().score(&ctx(vec![RiskSignal::RefreshContextDelta {
        ua_changed: false,
        asn_changed: false,
    }]));
    assert_eq!(result.score, 0.0_f32);
    assert!(!result.step_up_required);
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: score capping
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn p4_score_capped_at_1_0() {
    let result = enabled().score(&ctx(vec![
        RiskSignal::NewDevice,
        RiskSignal::NewCountry,
        RiskSignal::BreachCorpusHit,
        RiskSignal::PasswordAge { days: 500 },
    ]));
    assert!(result.score <= 1.0_f32, "score must not exceed 1.0");
    assert_eq!(result.score, 1.0_f32);
}

#[test]
fn p4_empty_context_scores_zero() {
    let result = enabled().score(&RiskContext::default());
    assert_eq!(result.score, 0.0_f32);
    assert!(!result.step_up_required);
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: configurable threshold / weights
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn p4_custom_threshold_lower_triggers_on_new_device() {
    let scorer = RuleBasedRiskScorer::new(RiskScorerConfig {
        enabled: true,
        step_up_threshold: 0.25, // lower than default 0.5
        ..RiskScorerConfig::default()
    });
    let result = scorer.score(&ctx(vec![RiskSignal::NewDevice])); // weight 0.3
    assert!(result.step_up_required, "0.3 >= 0.25 must trigger step-up");
}

#[test]
fn p4_custom_threshold_higher_ignores_both_signals() {
    let scorer = RuleBasedRiskScorer::new(RiskScorerConfig {
        enabled: true,
        step_up_threshold: 0.9, // very high
        ..RiskScorerConfig::default()
    });
    let result = scorer.score(&ctx(vec![RiskSignal::NewDevice, RiskSignal::NewCountry]));
    // 0.7 < 0.9 → no step-up
    assert!(
        !result.step_up_required,
        "0.7 < 0.9 must not trigger step-up"
    );
}

#[test]
fn p4_custom_new_device_weight() {
    let scorer = RuleBasedRiskScorer::new(RiskScorerConfig {
        enabled: true,
        new_device_weight: 0.8,
        step_up_threshold: 0.5,
        ..RiskScorerConfig::default()
    });
    let result = scorer.score(&ctx(vec![RiskSignal::NewDevice]));
    assert!(
        (result.score - 0.8).abs() < f32::EPSILON,
        "score = {}",
        result.score
    );
    assert!(result.step_up_required, "0.8 >= 0.5 must trigger step-up");
}

#[test]
fn p4_custom_password_age_days_threshold() {
    // Operator sets 180-day threshold instead of default 365.
    let scorer = RuleBasedRiskScorer::new(RiskScorerConfig {
        enabled: true,
        password_age_days_threshold: 180,
        step_up_threshold: 0.1,
        ..RiskScorerConfig::default()
    });
    let result = scorer.score(&ctx(vec![RiskSignal::PasswordAge { days: 200 }]));
    assert!(
        result.step_up_required,
        "200 days >= 180 day threshold must score"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: trait-object dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Demonstrates plug-and-play: the caller holds `Box<dyn RiskScorer>` and
/// can swap implementations without any type change.
#[test]
fn p4_dyn_scorer_rule_based() {
    let scorer: Box<dyn RiskScorer> = Box::new(enabled());
    let result = scorer.score(&ctx(vec![RiskSignal::NewDevice, RiskSignal::NewCountry]));
    assert!(result.step_up_required);
}

#[test]
fn p4_dyn_scorer_noop() {
    let scorer: Box<dyn RiskScorer> = Box::new(NoopRiskScorer);
    let result = scorer.score(&ctx(vec![RiskSignal::BreachCorpusHit]));
    assert!(
        !result.step_up_required,
        "noop must never block via dyn dispatch"
    );
}

/// Custom scorer that always returns 1.0 — shows extensibility.
struct AlwaysMaxScorer;
impl RiskScorer for AlwaysMaxScorer {
    fn score(&self, context: &RiskContext) -> RiskScore {
        RiskScore {
            score: 1.0,
            signals: context.signals.clone(),
            step_up_required: true,
        }
    }
}

#[test]
fn p4_custom_scorer_wired_as_dyn_trait() {
    let scorer: Box<dyn RiskScorer> = Box::new(AlwaysMaxScorer);
    let result = scorer.score(&RiskContext::default());
    assert_eq!(result.score, 1.0_f32);
    assert!(result.step_up_required);
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: build_risk_context pipeline
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn p4_build_context_then_score_clean_login() {
    let scorer = enabled();
    let ctx = build_risk_context(true, false, None, false);
    let result = scorer.score(&ctx);
    assert_eq!(result.score, 0.0_f32, "clean login must score zero");
    assert!(!result.step_up_required);
}

#[test]
fn p4_build_context_new_device_scored() {
    let scorer = enabled();
    let ctx = build_risk_context(false, false, None, false);
    let result = scorer.score(&ctx);
    assert!(
        (result.score - 0.3).abs() < f32::EPSILON,
        "score = {}",
        result.score
    );
}

#[test]
fn p4_build_context_breach_corpus_hit_forces_step_up() {
    let scorer = enabled();
    let ctx = build_risk_context(true, false, None, true);
    let result = scorer.score(&ctx);
    assert_eq!(result.score, 1.0_f32);
    assert!(result.step_up_required);
}

#[test]
fn p4_build_context_old_password_and_new_device() {
    let scorer = enabled();
    let old = SystemTime::now() - Duration::from_secs(400 * 86_400);
    let ctx = build_risk_context(false, false, Some(old), false);
    // NewDevice 0.3 + PasswordAge 0.2 = 0.5 >= 0.5 threshold
    let result = scorer.score(&ctx);
    assert!(result.score >= 0.5, "score = {}", result.score);
    assert!(result.step_up_required);
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial: boundary and weight-game scenarios
// ─────────────────────────────────────────────────────────────────────────────

/// Attacker who knows default weights sends NewDevice (0.3) alone — stays
/// below 0.5 threshold.  The scorer must NOT step up.
#[test]
fn p4_adversarial_single_signal_stays_below_default_threshold() {
    let result = enabled().score(&ctx(vec![RiskSignal::NewDevice]));
    assert!(
        !result.step_up_required,
        "single NewDevice must not trigger step-up at default weights"
    );
}

/// Attacker who knows NewCountry (0.4) alone also stays below 0.5.
#[test]
fn p4_adversarial_new_country_alone_stays_below_threshold() {
    let result = enabled().score(&ctx(vec![RiskSignal::NewCountry]));
    assert!(
        !result.step_up_required,
        "single NewCountry must not trigger step-up at default weights"
    );
}

/// Adding a RefreshContextDelta (single dim = 0.35) to NewDevice (0.3)
/// produces 0.65 ≥ 0.5 → operator catches multi-signal attacks.
#[test]
fn p4_adversarial_refresh_plus_new_device_triggers_step_up() {
    let result = enabled().score(&ctx(vec![
        RiskSignal::NewDevice,
        RiskSignal::RefreshContextDelta {
            ua_changed: true,
            asn_changed: false,
        },
    ]));
    // 0.3 + 0.35 = 0.65 ≥ 0.5
    assert!(
        result.step_up_required,
        "score = {} must trigger step-up",
        result.score
    );
}

/// Duplicate signals should not bypass the cap — injecting BreachCorpusHit
/// twice still clamps to 1.0.
#[test]
fn p4_adversarial_duplicate_signals_capped() {
    let result = enabled().score(&ctx(vec![
        RiskSignal::BreachCorpusHit,
        RiskSignal::BreachCorpusHit,
    ]));
    assert!(
        result.score <= 1.0_f32,
        "duplicate signals must not exceed 1.0"
    );
    assert_eq!(result.score, 1.0_f32);
}

/// Zero-weight breach-corpus — operator sets breach weight to 0.0.  Should
/// NOT trigger step-up (operator made an explicit choice; scorer honours it).
#[test]
fn p4_adversarial_zero_weight_breach_no_step_up() {
    let scorer = RuleBasedRiskScorer::new(RiskScorerConfig {
        enabled: true,
        breach_corpus_weight: 0.0,
        step_up_threshold: 0.5,
        ..RiskScorerConfig::default()
    });
    let result = scorer.score(&ctx(vec![RiskSignal::BreachCorpusHit]));
    assert_eq!(result.score, 0.0_f32, "zero-weight breach must score 0.0");
    assert!(!result.step_up_required);
}

/// Score at exactly the threshold boundary must trigger step-up (inclusive).
#[test]
fn p4_adversarial_threshold_boundary_inclusive() {
    // NewDevice default 0.3; set threshold to exactly 0.3.
    let scorer = RuleBasedRiskScorer::new(RiskScorerConfig {
        enabled: true,
        step_up_threshold: 0.3,
        ..RiskScorerConfig::default()
    });
    let result = scorer.score(&ctx(vec![RiskSignal::NewDevice]));
    assert!(
        result.step_up_required,
        "score == threshold must trigger step-up (inclusive comparison)"
    );
}

/// Score just below the threshold (0.2999…) must NOT trigger step-up.
#[test]
fn p4_adversarial_just_below_threshold_no_step_up() {
    let scorer = RuleBasedRiskScorer::new(RiskScorerConfig {
        enabled: true,
        step_up_threshold: 0.5,
        new_device_weight: 0.499, // just below 0.5
        ..RiskScorerConfig::default()
    });
    let result = scorer.score(&ctx(vec![RiskSignal::NewDevice]));
    assert!(
        !result.step_up_required,
        "0.499 < 0.5 must not trigger step-up"
    );
}
