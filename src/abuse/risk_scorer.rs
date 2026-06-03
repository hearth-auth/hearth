//! P-4 RiskScorer — pluggable risk-scoring trait + rule-based reference engine.
//!
//! # Design
//!
//! [`RiskScorer`] is the trait that every pluggable risk-scoring backend must
//! implement.  The built-in [`RuleBasedRiskScorer`] ships with Hearth and
//! implements the A-11 rule engine: it aggregates configurable signals
//! (new-country, new-device, password-age, breach-corpus history) and
//! computes a score in `[0.0, 1.0]`.  When the score meets or exceeds the
//! configured threshold, [`RiskScore::step_up_required`] is `true` and the
//! caller must enforce MFA before issuing tokens.
//!
//! ## Extensibility
//!
//! Implement [`RiskScorer`] to plug in a vendor ML-risk engine or a custom
//! HTTP endpoint.  All adapters are configured under
//! `security.risk_scorer` in `hearth.yaml`.
//!
//! ## Failure mode: fail-open
//!
//! Per §6.1 of the abuse-prevention plan: `RiskScorer` is **fail-open**.
//! Implementations MUST return `step_up_required = false` on any transient
//! error so that legitimate logins are never blocked by a scorer outage.
//! [`NoopRiskScorer`] and the disabled variant of [`RuleBasedRiskScorer`]
//! both embody this posture.
//!
//! ## Off hot-path
//!
//! The scorer is consulted only at login time — not during token validation
//! or session lookup (`validate_token`, `lookup_session`), which are on the
//! latency-critical hot path.  External adapters that require network calls
//! should cache results and refresh asynchronously.
//!
//! ## Built-in signal weights (defaults)
//!
//! | Signal | Default weight | Source |
//! |--------|---------------|--------|
//! | `NewDevice` | 0.3 | Device-fingerprint miss |
//! | `NewCountry` | 0.4 | GeoIP (stub; absent until P-2 ships) |
//! | `PasswordAge` | 0.2 | Credential `created_at` (approximation) |
//! | `BreachCorpusHit` | 1.0 | HIBP / offline corpus |
//! | `RefreshContextDelta` | 0.35 per dim | UA-hash or ASN change (A-49) |

use std::time::{Duration, SystemTime};

// ─────────────────────────────────────────────────────────────────────────────
// Risk signals
// ─────────────────────────────────────────────────────────────────────────────

/// A single observable risk signal gathered at login time.
///
/// Signals are aggregated into a [`RiskContext`] before being passed to the
/// [`RiskScorer`].  The rule engine assigns each signal a configurable weight.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum RiskSignal {
    /// Login from an unrecognised device (device-fingerprint miss).
    ///
    /// Populated when the adaptive-MFA device-fingerprint store returns
    /// `Unrecognised` for the `(user_id, ip/24, user_agent)` tuple.
    NewDevice,

    /// Login from a country not previously seen for this user.
    ///
    /// Requires a GeoIP provider (P-2 — pluggable); always absent until one
    /// is configured.  The slot is here so the rule engine can score it
    /// without a code change once a provider is wired.
    NewCountry,

    /// The user's password has not been changed in over the configured
    /// threshold (default: 365 days).
    ///
    /// Approximation: uses the credential's `created_at` timestamp when no
    /// explicit `password_changed_at` field is available.
    PasswordAge {
        /// Approximate age of the credential in whole days.
        days: u32,
    },

    /// The user's current password appears in a known breach corpus.
    ///
    /// Populated by the HIBP k-anonymity client or the offline breach corpus
    /// checker.  When present the score is forced to `1.0` regardless of
    /// other signals (weight defaults to `1.0`).
    BreachCorpusHit,

    /// The refresh token was exchanged from a different context than when it
    /// was issued (A-49).
    ///
    /// Populated when the User-Agent hash or ASN changes between the original
    /// token issuance and the refresh exchange.  The scorer applies
    /// `refresh_context_delta_weight` for each changed dimension.
    RefreshContextDelta {
        /// The User-Agent hash changed between issuance and refresh.
        ua_changed: bool,
        /// The originating ASN changed between issuance and refresh.
        ///
        /// `false` when no ASN is available (GeoIP stub — P-2/P-4).
        asn_changed: bool,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Output types
// ─────────────────────────────────────────────────────────────────────────────

/// Composite risk score for a single login event.
#[derive(Debug, Clone)]
pub struct RiskScore {
    /// Normalised score in `[0.0, 1.0]`; `1.0` is maximum risk.
    pub score: f32,
    /// Signals that contributed to this score (may be empty).
    pub signals: Vec<RiskSignal>,
    /// `true` when `score >= step_up_threshold` and the caller must enforce
    /// MFA before issuing tokens.
    pub step_up_required: bool,
}

/// Login context supplied to the risk scorer.
///
/// Build with [`build_risk_context`] or assemble manually in tests.
#[derive(Debug, Clone, Default)]
pub struct RiskContext {
    /// Signals already gathered by the login handler.
    pub signals: Vec<RiskSignal>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Pluggable risk-scorer trait (P-4 extension point).
///
/// Implement this trait to replace the built-in rule engine with a vendor
/// risk API or a custom ML model.  The reference implementation is
/// [`RuleBasedRiskScorer`].
///
/// # Contract
///
/// - `score()` MUST be synchronous.  External adapters that require network
///   calls should cache results and refresh asynchronously via a background
///   task.
/// - `score()` MUST fail-open: return `step_up_required = false` on any
///   transient error so that legitimate logins are never blocked.
/// - `score()` MUST NOT log passwords, session tokens, or PII.
pub trait RiskScorer: Send + Sync {
    /// Scores the login context and returns a composite [`RiskScore`].
    ///
    /// Implementations MUST NOT panic.
    fn score(&self, context: &RiskContext) -> RiskScore;
}

// ─────────────────────────────────────────────────────────────────────────────
// No-op provider (fail-open default)
// ─────────────────────────────────────────────────────────────────────────────

/// No-op risk scorer.
///
/// Always returns score = `0.0` and `step_up_required = false`.  This is the
/// safe default for deployments that have not yet configured risk scoring; no
/// login is ever blocked by this implementation.
pub struct NoopRiskScorer;

impl RiskScorer for NoopRiskScorer {
    fn score(&self, context: &RiskContext) -> RiskScore {
        RiskScore {
            score: 0.0,
            signals: context.signals.clone(),
            step_up_required: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the built-in rule-based risk scorer.
///
/// All weights are in `[0.0, 1.0]`.  The sum of active signals is clamped to
/// `1.0` before comparing to `step_up_threshold`.
///
/// Serialised under `security.risk_scorer` in `hearth.yaml`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RiskScorerConfig {
    /// Whether risk scoring is active.  `false` = always score 0.0 (fail-open).
    pub enabled: bool,

    /// Score at or above which step-up MFA is required.
    ///
    /// Range `[0.0, 1.0]`.  Default: `0.5`.
    pub step_up_threshold: f32,

    /// Score contribution for [`RiskSignal::NewDevice`].  Default: `0.3`.
    pub new_device_weight: f32,

    /// Score contribution for [`RiskSignal::NewCountry`].  Default: `0.4`.
    pub new_country_weight: f32,

    /// Score contribution for [`RiskSignal::PasswordAge`] when age exceeds
    /// `password_age_days_threshold`.  Default: `0.2`.
    pub password_age_weight: f32,

    /// Minimum password age (in days) before `password_age_weight` applies.
    /// Default: `365`.
    pub password_age_days_threshold: u32,

    /// Score contribution for [`RiskSignal::BreachCorpusHit`].
    ///
    /// Defaults to `1.0` so any confirmed breach forces step-up regardless
    /// of other signals.
    pub breach_corpus_weight: f32,

    /// Score contribution per changed dimension in
    /// [`RiskSignal::RefreshContextDelta`] (A-49).
    ///
    /// Applied once for each of `ua_changed` and `asn_changed` that is
    /// `true`, so both changing adds `2 × weight`.  Default: `0.35`.
    pub refresh_context_delta_weight: f32,
}

impl Default for RiskScorerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            step_up_threshold: 0.5,
            new_device_weight: 0.3,
            new_country_weight: 0.4,
            password_age_weight: 0.2,
            password_age_days_threshold: 365,
            breach_corpus_weight: 1.0,
            refresh_context_delta_weight: 0.35,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule-based reference adapter
// ─────────────────────────────────────────────────────────────────────────────

/// Rule-based risk scorer — A-11 reference implementation (P-4).
///
/// Assigns each [`RiskSignal`] a configurable weight, sums the contributions
/// (clamped to `1.0`), and compares to `step_up_threshold`.  No I/O —
/// appropriate for direct use in the login path without async overhead.
///
/// Configuration: `security.risk_scorer` in `hearth.yaml`.
///
/// ## Fail-open guarantee
///
/// When `security.risk_scorer.enabled = false` (the default), the scorer
/// always returns score = `0.0` and `step_up_required = false`.  Existing
/// deployments are unaffected until an operator opts in.
#[derive(Debug)]
pub struct RuleBasedRiskScorer {
    config: RiskScorerConfig,
}

impl RuleBasedRiskScorer {
    /// Creates a scorer with the given configuration.
    #[must_use]
    pub fn new(config: RiskScorerConfig) -> Self {
        Self { config }
    }

    /// Creates a scorer that always returns score = 0.0 (fail-open default).
    ///
    /// Used when `security.risk_scorer.enabled = false` (the default) so
    /// existing deployments are unaffected by this feature shipping.
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(RiskScorerConfig::default())
    }
}

impl RiskScorer for RuleBasedRiskScorer {
    fn score(&self, context: &RiskContext) -> RiskScore {
        if !self.config.enabled {
            return RiskScore {
                score: 0.0,
                signals: context.signals.clone(),
                step_up_required: false,
            };
        }

        let mut total: f32 = 0.0;

        for signal in &context.signals {
            let contribution: f32 = match signal {
                RiskSignal::NewDevice => self.config.new_device_weight,
                RiskSignal::NewCountry => self.config.new_country_weight,
                RiskSignal::PasswordAge { days } => {
                    if *days >= self.config.password_age_days_threshold {
                        self.config.password_age_weight
                    } else {
                        0.0
                    }
                }
                RiskSignal::BreachCorpusHit => self.config.breach_corpus_weight,
                RiskSignal::RefreshContextDelta {
                    ua_changed,
                    asn_changed,
                } => {
                    let dims = (*ua_changed as u8) + (*asn_changed as u8);
                    f32::from(dims) * self.config.refresh_context_delta_weight
                }
            };
            total = (total + contribution).min(1.0);
        }

        let step_up_required = total >= self.config.step_up_threshold;

        RiskScore {
            score: total,
            signals: context.signals.clone(),
            step_up_required,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Context builder helper
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a [`RiskContext`] from the signals available at login time.
///
/// # Arguments
///
/// * `device_recognised` — `true` when the device-fingerprint store returned
///   `Recognised` for this `(user_id, ip/24, user_agent)`.  When `false`,
///   a [`RiskSignal::NewDevice`] is appended.
/// * `country_changed` — `true` when the login IP resolves to a country not
///   previously seen for this user.  Pass `false` when no GeoIP is available
///   (stub until P-2 ships).
/// * `credential_created_at` — timestamp used to approximate password age
///   (typically `user.created_at()`).  `None` = no age signal.
/// * `breach_corpus_hit` — `true` when the password was found in the HIBP
///   or offline breach corpus during this login attempt.
#[must_use]
pub fn build_risk_context(
    device_recognised: bool,
    country_changed: bool,
    credential_created_at: Option<SystemTime>,
    breach_corpus_hit: bool,
) -> RiskContext {
    let mut signals: Vec<RiskSignal> = Vec::new();

    if !device_recognised {
        signals.push(RiskSignal::NewDevice);
    }
    if country_changed {
        signals.push(RiskSignal::NewCountry);
    }
    if let Some(created_at) = credential_created_at {
        let age = SystemTime::now()
            .duration_since(created_at)
            .unwrap_or(Duration::ZERO);
        // Saturating cast: u32::MAX days > 11 million years; sufficient for any
        // real credential age.
        let days = u32::try_from(age.as_secs() / 86_400).unwrap_or(u32::MAX);
        signals.push(RiskSignal::PasswordAge { days });
    }
    if breach_corpus_hit {
        signals.push(RiskSignal::BreachCorpusHit);
    }

    RiskContext { signals }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    fn enabled_config() -> RiskScorerConfig {
        RiskScorerConfig {
            enabled: true,
            ..RiskScorerConfig::default()
        }
    }

    fn enabled_scorer() -> RuleBasedRiskScorer {
        RuleBasedRiskScorer::new(enabled_config())
    }

    // ── NoopRiskScorer ───────────────────────────────────────────────────────

    #[test]
    fn noop_scores_zero_no_signals() {
        let s = NoopRiskScorer;
        let result = s.score(&RiskContext::default());
        assert_eq!(result.score, 0.0);
        assert!(!result.step_up_required);
    }

    #[test]
    fn noop_scores_zero_with_signals() {
        let s = NoopRiskScorer;
        let ctx = RiskContext {
            signals: vec![RiskSignal::NewDevice, RiskSignal::BreachCorpusHit],
        };
        let result = s.score(&ctx);
        assert_eq!(result.score, 0.0);
        assert!(!result.step_up_required);
    }

    #[test]
    fn noop_preserves_signals_in_output() {
        let s = NoopRiskScorer;
        let ctx = RiskContext {
            signals: vec![RiskSignal::NewDevice],
        };
        let result = s.score(&ctx);
        assert_eq!(result.signals, ctx.signals);
    }

    // ── Disabled scorer (fail-open default) ──────────────────────────────────

    #[test]
    fn disabled_scorer_always_zero() {
        let scorer = RuleBasedRiskScorer::disabled();
        let ctx = RiskContext {
            signals: vec![RiskSignal::NewDevice, RiskSignal::BreachCorpusHit],
        };
        let result = scorer.score(&ctx);
        assert_eq!(result.score, 0.0);
        assert!(!result.step_up_required);
    }

    #[test]
    fn disabled_scorer_preserves_signals() {
        let scorer = RuleBasedRiskScorer::disabled();
        let ctx = RiskContext {
            signals: vec![RiskSignal::NewDevice],
        };
        let result = scorer.score(&ctx);
        assert_eq!(result.signals, ctx.signals);
    }

    // ── Signal weights ───────────────────────────────────────────────────────

    #[test]
    fn new_device_alone_below_threshold() {
        let scorer = enabled_scorer();
        let ctx = RiskContext {
            signals: vec![RiskSignal::NewDevice],
        };
        let result = scorer.score(&ctx);
        // 0.3 < 0.5 default threshold
        assert!(
            (result.score - 0.3).abs() < f32::EPSILON,
            "score = {}",
            result.score
        );
        assert!(
            !result.step_up_required,
            "new device alone must not trigger step-up"
        );
    }

    #[test]
    fn new_country_alone_below_threshold() {
        let scorer = enabled_scorer();
        let ctx = RiskContext {
            signals: vec![RiskSignal::NewCountry],
        };
        let result = scorer.score(&ctx);
        // 0.4 < 0.5 default threshold
        assert!(
            (result.score - 0.4).abs() < f32::EPSILON,
            "score = {}",
            result.score
        );
        assert!(!result.step_up_required);
    }

    #[test]
    fn new_device_plus_new_country_triggers_step_up() {
        let scorer = enabled_scorer();
        let ctx = RiskContext {
            signals: vec![RiskSignal::NewDevice, RiskSignal::NewCountry],
        };
        let result = scorer.score(&ctx);
        // 0.3 + 0.4 = 0.7 >= 0.5 threshold
        assert!(result.score >= 0.5, "score = {}", result.score);
        assert!(
            result.step_up_required,
            "new device + new country must trigger step-up"
        );
    }

    #[test]
    fn breach_corpus_hit_forces_step_up() {
        let scorer = enabled_scorer();
        let ctx = RiskContext {
            signals: vec![RiskSignal::BreachCorpusHit],
        };
        let result = scorer.score(&ctx);
        assert_eq!(result.score, 1.0, "breach hit must score 1.0");
        assert!(result.step_up_required);
    }

    #[test]
    fn password_age_below_threshold_scores_zero() {
        let scorer = enabled_scorer();
        let ctx = RiskContext {
            signals: vec![RiskSignal::PasswordAge { days: 30 }],
        };
        let result = scorer.score(&ctx);
        assert_eq!(result.score, 0.0, "young password must score 0.0");
        assert!(!result.step_up_required);
    }

    #[test]
    fn password_age_at_threshold_scores() {
        let scorer = enabled_scorer();
        let ctx = RiskContext {
            signals: vec![RiskSignal::PasswordAge { days: 365 }],
        };
        let result = scorer.score(&ctx);
        assert!(
            (result.score - 0.2).abs() < f32::EPSILON,
            "score = {}",
            result.score
        );
    }

    #[test]
    fn password_age_above_threshold_scores_same() {
        let scorer = enabled_scorer();
        let ctx = RiskContext {
            signals: vec![RiskSignal::PasswordAge { days: 730 }],
        };
        let result = scorer.score(&ctx);
        assert!(
            (result.score - 0.2).abs() < f32::EPSILON,
            "score = {}",
            result.score
        );
    }

    // ── RefreshContextDelta (A-49) ───────────────────────────────────────────

    #[test]
    fn refresh_ua_only_scores_one_weight() {
        let scorer = enabled_scorer();
        let ctx = RiskContext {
            signals: vec![RiskSignal::RefreshContextDelta {
                ua_changed: true,
                asn_changed: false,
            }],
        };
        let result = scorer.score(&ctx);
        let expected = 0.35_f32;
        assert!(
            (result.score - expected).abs() < f32::EPSILON,
            "score = {}, expected {expected}",
            result.score
        );
    }

    #[test]
    fn refresh_both_dims_scores_double_weight() {
        let scorer = enabled_scorer();
        let ctx = RiskContext {
            signals: vec![RiskSignal::RefreshContextDelta {
                ua_changed: true,
                asn_changed: true,
            }],
        };
        let result = scorer.score(&ctx);
        let expected = 0.70_f32;
        assert!(
            (result.score - expected).abs() < f32::EPSILON,
            "score = {}, expected {expected}",
            result.score
        );
    }

    #[test]
    fn refresh_no_change_scores_zero() {
        let scorer = enabled_scorer();
        let ctx = RiskContext {
            signals: vec![RiskSignal::RefreshContextDelta {
                ua_changed: false,
                asn_changed: false,
            }],
        };
        let result = scorer.score(&ctx);
        assert_eq!(result.score, 0.0);
        assert!(!result.step_up_required);
    }

    // ── Score capping ────────────────────────────────────────────────────────

    #[test]
    fn score_capped_at_one() {
        let scorer = enabled_scorer();
        let ctx = RiskContext {
            signals: vec![
                RiskSignal::NewDevice,
                RiskSignal::NewCountry,
                RiskSignal::BreachCorpusHit,
                RiskSignal::PasswordAge { days: 500 },
            ],
        };
        let result = scorer.score(&ctx);
        assert!(result.score <= 1.0, "score must not exceed 1.0");
        assert_eq!(result.score, 1.0);
    }

    #[test]
    fn empty_signals_scores_zero() {
        let scorer = enabled_scorer();
        let ctx = RiskContext { signals: vec![] };
        let result = scorer.score(&ctx);
        assert_eq!(result.score, 0.0);
        assert!(!result.step_up_required);
    }

    // ── Configurable threshold and weights ───────────────────────────────────

    #[test]
    fn custom_threshold_changes_step_up_decision() {
        let scorer = RuleBasedRiskScorer::new(RiskScorerConfig {
            enabled: true,
            step_up_threshold: 0.25,
            ..RiskScorerConfig::default()
        });
        let ctx = RiskContext {
            signals: vec![RiskSignal::NewDevice], // weight 0.3 > 0.25
        };
        let result = scorer.score(&ctx);
        assert!(result.step_up_required, "0.3 >= 0.25 must trigger step-up");
    }

    #[test]
    fn custom_new_device_weight_applied() {
        let scorer = RuleBasedRiskScorer::new(RiskScorerConfig {
            enabled: true,
            new_device_weight: 0.6,
            step_up_threshold: 0.5,
            ..RiskScorerConfig::default()
        });
        let ctx = RiskContext {
            signals: vec![RiskSignal::NewDevice],
        };
        let result = scorer.score(&ctx);
        assert!(
            (result.score - 0.6).abs() < f32::EPSILON,
            "score = {}",
            result.score
        );
        assert!(result.step_up_required);
    }

    // ── build_risk_context helper ────────────────────────────────────────────

    #[test]
    fn build_context_new_device_signal() {
        let ctx = build_risk_context(false, false, None, false);
        assert!(
            ctx.signals.contains(&RiskSignal::NewDevice),
            "unrecognised device must produce NewDevice signal"
        );
    }

    #[test]
    fn build_context_recognised_device_no_signal() {
        let ctx = build_risk_context(true, false, None, false);
        assert!(
            !ctx.signals.contains(&RiskSignal::NewDevice),
            "recognised device must not produce NewDevice signal"
        );
    }

    #[test]
    fn build_context_new_country_signal() {
        let ctx = build_risk_context(true, true, None, false);
        assert!(ctx.signals.contains(&RiskSignal::NewCountry));
    }

    #[test]
    fn build_context_breach_signal() {
        let ctx = build_risk_context(true, false, None, true);
        assert!(ctx.signals.contains(&RiskSignal::BreachCorpusHit));
    }

    #[test]
    fn build_context_old_password_signal() {
        let old = SystemTime::now() - Duration::from_secs(500 * 86_400);
        let ctx = build_risk_context(true, false, Some(old), false);
        let has_age = ctx
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::PasswordAge { days } if *days >= 365));
        assert!(
            has_age,
            "500-day credential must produce PasswordAge >= 365 signal"
        );
    }

    #[test]
    fn build_context_fresh_password_no_age_signal() {
        let fresh = SystemTime::now() - Duration::from_secs(10 * 86_400);
        let ctx = build_risk_context(true, false, Some(fresh), false);
        let has_old_age = ctx
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::PasswordAge { days } if *days >= 365));
        assert!(
            !has_old_age,
            "10-day credential must not produce PasswordAge >= 365 signal"
        );
    }

    #[test]
    fn build_context_all_signals() {
        let old = SystemTime::now() - Duration::from_secs(400 * 86_400);
        let ctx = build_risk_context(false, true, Some(old), true);
        assert!(ctx.signals.contains(&RiskSignal::NewDevice));
        assert!(ctx.signals.contains(&RiskSignal::NewCountry));
        assert!(ctx.signals.contains(&RiskSignal::BreachCorpusHit));
        assert!(ctx
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::PasswordAge { days } if *days >= 365)));
    }

    #[test]
    fn build_context_no_signals_when_clean() {
        let ctx = build_risk_context(true, false, None, false);
        assert!(
            ctx.signals.is_empty(),
            "no signals expected for a clean login"
        );
    }
}
