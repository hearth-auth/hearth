//! Step-up MFA risk scorer (A-11).
//!
//! Aggregates risk signals from a login event and computes a composite
//! score in `[0.0, 1.0]`.  When the score meets or exceeds the configured
//! threshold, `RiskScore::step_up_required` is `true` and the caller must
//! return `IdentityError::StepUpChallengeRequired`.
//!
//! # Built-in signals
//!
//! | Signal | Weight (default) | Source |
//! |--------|-----------------|--------|
//! | `NewDevice` | 0.3 | Device-fingerprint miss |
//! | `NewCountry` | 0.4 | GeoIP lookup (stub — P-4 required) |
//! | `PasswordAge` | 0.2 | Credential `created_at` (approximation) |
//! | `BreachCorpusHit` | 1.0 | HIBP/offline corpus check |
//!
//! # Pluggable scorer (P-4 extension point)
//!
//! The [`RiskScorer`] trait is the P-4 hook (HEA-1205).  The built-in
//! [`DefaultRiskScorer`] runs a deterministic rule engine with configurable
//! weights.  Operators can replace it with a vendor ML model or a remote
//! risk API once HEA-1205 ships.
//!
//! # Failure mode: fail-open
//!
//! Per §6.1 of the abuse-prevention plan: when the risk scorer is disabled
//! (the default) or encounters a configuration error it MUST NOT block login.
//! `DefaultRiskScorer::disabled()` always returns score = 0.0 and
//! `step_up_required = false`.

use std::time::{Duration, SystemTime};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// A single observable risk signal gathered at login time.
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
    /// Requires a GeoIP provider; always absent until one is configured
    /// (pluggable via P-2/P-4 in HEA-1205).  The slot is here so the
    /// `DefaultRiskScorer` can score it without a code change.
    NewCountry,

    /// The user's password has not been changed in over the configured
    /// threshold (default: 365 days).
    ///
    /// Approximation: uses the credential's `created_at` timestamp when
    /// no explicit `password_changed_at` field is available (HEA-1192 scope).
    PasswordAge {
        /// Approximate age of the credential in whole days.
        days: u32,
    },

    /// The user's current password appears in a known breach corpus.
    ///
    /// This signal is populated by the HIBP k-anonymity client or the
    /// offline breach corpus checker.  When present the score is forced
    /// to `1.0` regardless of other signals (weight defaults to `1.0`).
    BreachCorpusHit,

    /// The refresh token was exchanged from a different context than when
    /// it was issued (A-49).
    ///
    /// Populated when the User-Agent hash or ASN changes between the
    /// original token issuance and the refresh exchange.  The scorer
    /// applies `refresh_context_delta_weight` for each changed dimension.
    RefreshContextDelta {
        /// The User-Agent hash changed between issuance and refresh.
        ua_changed: bool,
        /// The originating ASN changed between issuance and refresh.
        ///
        /// `false` when no ASN is available (GeoIP stub — P-4).
        asn_changed: bool,
    },
}

/// Composite risk score for a single login event.
#[derive(Debug, Clone)]
pub struct RiskScore {
    /// Normalised score in `[0.0, 1.0]`; `1.0` is maximum risk.
    pub score: f32,
    /// Signals that contributed to this score (may be empty).
    pub signals: Vec<RiskSignal>,
    /// `true` when `score >= step_up_threshold` and the caller must
    /// enforce MFA before issuing tokens.
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

/// Pluggable risk-scorer trait (P-4 extension point — HEA-1205).
///
/// Implement this trait to replace the built-in rule engine with a vendor
/// risk API or a custom ML model.  The reference implementation is
/// [`DefaultRiskScorer`].
pub trait RiskScorer: Send + Sync {
    /// Scores the login context and returns a composite [`RiskScore`].
    ///
    /// Implementations MUST NOT block indefinitely and MUST NOT panic.
    /// On transient error, return `step_up_required = false` (fail-open).
    fn score(&self, context: &RiskContext) -> RiskScore;
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the built-in rule-based risk scorer.
///
/// All weights are in `[0.0, 1.0]`.  The sum of active signals is clamped
/// to `1.0` before comparing to `step_up_threshold`.
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

    /// Score contribution for [`RiskSignal::PasswordAge`] when the age
    /// exceeds `password_age_days_threshold`.  Default: `0.2`.
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
// Built-in scorer
// ─────────────────────────────────────────────────────────────────────────────

/// Rule-based risk scorer (A-11 built-in).
///
/// Assigns each [`RiskSignal`] a configurable weight, sums the contributions
/// (clamped to `1.0`), and compares to `step_up_threshold`.  No I/O.
#[derive(Debug)]
pub struct DefaultRiskScorer {
    config: RiskScorerConfig,
}

impl DefaultRiskScorer {
    /// Creates a scorer with the given configuration.
    #[must_use]
    pub fn new(config: RiskScorerConfig) -> Self {
        Self { config }
    }

    /// Creates a scorer that always returns score = 0.0 (fail-open default).
    ///
    /// Used when `security.risk_scorer.enabled = false` (the default) so
    /// existing deployments are unaffected.
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(RiskScorerConfig::default())
    }
}

impl RiskScorer for DefaultRiskScorer {
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
// Context builder
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a [`RiskContext`] from the signals available at login time.
///
/// # Arguments
///
/// * `device_recognised` — `true` when the device-fingerprint store returned
///   `Recognised` for this `(user_id, ip/24, user_agent)`.  When `false`,
///   a [`RiskSignal::NewDevice`] is added.
/// * `country_changed` — `true` when the login IP resolves to a country not
///   previously seen for this user.  Pass `false` when no GeoIP is available
///   (stub until P-4 ships).
/// * `credential_created_at` — the timestamp from which password age is
///   approximated (typically `user.created_at()`).  `None` = no age signal.
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
        // Saturating cast: u32::MAX days > 11 million years, enough for any
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
#[allow(clippy::float_cmp)] // risk score boundary assertions use exact 0.0/1.0
mod tests {
    use super::*;

    fn enabled_config() -> RiskScorerConfig {
        RiskScorerConfig {
            enabled: true,
            ..RiskScorerConfig::default()
        }
    }

    // ── Unit: disabled scorer ────────────────────────────────────────────────

    #[test]
    fn disabled_scorer_always_zero() {
        let scorer = DefaultRiskScorer::disabled();
        let ctx = RiskContext {
            signals: vec![RiskSignal::NewDevice, RiskSignal::BreachCorpusHit],
        };
        let result = scorer.score(&ctx);
        assert_eq!(result.score, 0.0);
        assert!(!result.step_up_required);
    }

    #[test]
    fn disabled_scorer_preserves_signals_in_output() {
        let scorer = DefaultRiskScorer::disabled();
        let ctx = RiskContext {
            signals: vec![RiskSignal::NewDevice],
        };
        let result = scorer.score(&ctx);
        assert_eq!(result.signals, ctx.signals);
    }

    // ── Unit: signal weights ─────────────────────────────────────────────────

    #[test]
    fn new_device_alone_below_threshold() {
        let scorer = DefaultRiskScorer::new(enabled_config());
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
            "new device alone should not require step-up"
        );
    }

    #[test]
    fn new_country_alone_below_threshold() {
        let scorer = DefaultRiskScorer::new(enabled_config());
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
        let scorer = DefaultRiskScorer::new(enabled_config());
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
        let scorer = DefaultRiskScorer::new(enabled_config());
        let ctx = RiskContext {
            signals: vec![RiskSignal::BreachCorpusHit],
        };
        let result = scorer.score(&ctx);
        assert_eq!(result.score, 1.0, "breach hit must score 1.0");
        assert!(result.step_up_required);
    }

    #[test]
    fn password_age_below_threshold_scores_zero() {
        let scorer = DefaultRiskScorer::new(enabled_config());
        let ctx = RiskContext {
            signals: vec![RiskSignal::PasswordAge { days: 30 }],
        };
        let result = scorer.score(&ctx);
        assert_eq!(result.score, 0.0, "young password must score 0.0");
        assert!(!result.step_up_required);
    }

    #[test]
    fn password_age_at_threshold_scores() {
        let scorer = DefaultRiskScorer::new(enabled_config());
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
    fn password_age_above_threshold_scores() {
        let scorer = DefaultRiskScorer::new(enabled_config());
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

    #[test]
    fn score_capped_at_one() {
        let scorer = DefaultRiskScorer::new(enabled_config());
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
        let scorer = DefaultRiskScorer::new(enabled_config());
        let ctx = RiskContext { signals: vec![] };
        let result = scorer.score(&ctx);
        assert_eq!(result.score, 0.0);
        assert!(!result.step_up_required);
    }

    // ── Unit: configurable threshold ─────────────────────────────────────────

    #[test]
    fn custom_threshold_changes_step_up_decision() {
        let scorer = DefaultRiskScorer::new(RiskScorerConfig {
            enabled: true,
            step_up_threshold: 0.25, // lower threshold
            ..RiskScorerConfig::default()
        });
        let ctx = RiskContext {
            signals: vec![RiskSignal::NewDevice], // weight 0.3 > 0.25
        };
        let result = scorer.score(&ctx);
        assert!(result.step_up_required, "0.3 >= 0.25 must trigger step-up");
    }

    #[test]
    fn custom_weights_applied_correctly() {
        let scorer = DefaultRiskScorer::new(RiskScorerConfig {
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

    // ── Unit: build_risk_context ─────────────────────────────────────────────

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
        // Credential created 500 days ago.
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
    fn build_context_fresh_password_signal() {
        // Credential created 10 days ago.
        let fresh = SystemTime::now() - Duration::from_secs(10 * 86_400);
        let ctx = build_risk_context(true, false, Some(fresh), false);
        let has_age = ctx
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::PasswordAge { days } if *days >= 365));
        assert!(
            !has_age,
            "10-day credential must produce PasswordAge < 365 signal"
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
    fn build_context_no_signals() {
        let ctx = build_risk_context(true, false, None, false);
        assert!(ctx.signals.is_empty(), "no signals expected");
    }
}
