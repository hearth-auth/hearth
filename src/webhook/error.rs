//! Error types for the webhook engine.

use crate::core::WebhookId;

/// Errors that can occur in the webhook engine.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// A storage I/O error occurred.
    #[error("storage error: {reason}")]
    Storage { reason: String },

    /// Serialization or deserialization failed.
    #[error("serialization error: {reason}")]
    Serialization { reason: String },

    /// The requested webhook subscription was not found.
    #[error("webhook not found: {id}")]
    NotFound { id: WebhookId },

    /// The provided URL is not valid.
    #[error("invalid URL: {reason}")]
    InvalidUrl { reason: String },

    /// The signing secret is too short.
    #[error("secret too short: minimum 16 bytes")]
    SecretTooShort,

    /// The webhook destination resolves to a private/reserved IP address.
    ///
    /// Raised by the SSRF guard (F3/HEA-1651) when the target hostname
    /// resolves to loopback, RFC 1918, link-local, ULA, or cloud metadata
    /// ranges, or when DNS resolution itself fails.
    #[error("blocked destination: {reason}")]
    BlockedDestination { reason: String },
}

impl From<crate::storage::StorageError> for WebhookError {
    fn from(e: crate::storage::StorageError) -> Self {
        Self::Storage {
            reason: e.to_string(),
        }
    }
}
