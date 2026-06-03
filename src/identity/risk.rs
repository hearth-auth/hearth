//! Step-up MFA risk scorer (A-11) — canonical types in [`crate::abuse::risk_scorer`].
//!
//! This module re-exports the P-4 types so that call sites within the
//! `identity` layer do not need to be updated when the canonical location
//! moved to `src/abuse/risk_scorer.rs` (HEA-1205).
//!
//! New code should import directly from [`crate::abuse::risk_scorer`].
pub use crate::abuse::risk_scorer::{
    build_risk_context, NoopRiskScorer, RiskContext, RiskScore, RiskScorer, RiskScorerConfig,
    RiskSignal, RuleBasedRiskScorer,
};

/// Backward-compatible alias for [`RuleBasedRiskScorer`].
///
/// Existing callers within the identity engine import `DefaultRiskScorer`;
/// this alias preserves those imports without a mechanical rename.
pub use RuleBasedRiskScorer as DefaultRiskScorer;
