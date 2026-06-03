use thiserror::Error;

/// Errors produced by the abuse-prevention subsystem.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AbuseError {
    /// Policy configuration is invalid or inconsistent.
    #[error("invalid abuse policy configuration: {0}")]
    ConfigInvalid(String),

    /// An internal error occurred while evaluating the policy.
    #[error("abuse policy evaluation error: {0}")]
    Internal(String),
}
