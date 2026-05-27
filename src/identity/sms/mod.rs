//! Outbound SMS delivery.
//!
//! Defines the [`SmsSender`] trait with concrete implementations:
//!
//! - [`LoggingSmsSender`] — writes SMS body to the `tracing` log at WARN
//!   level. The default for local development.
//! - [`TwilioSmsSender`] — delivers via the Twilio Messaging REST API.
//! - [`SnsSmsSender`] — delivers via AWS SNS Transactional SMS with
//!   Signature Version 4 authentication.
//!
//! Off the hot path. Senders are invoked from MFA and OTP flows, never
//! from token validation.

pub mod http;
mod log;
pub(crate) mod otp;
mod sns;
mod twilio;

use std::fmt;
use std::sync::Arc;

use zeroize::Zeroize;

pub use self::http::StubSmsHttpTransport;
pub use self::log::LoggingSmsSender;
pub use self::sns::SnsSmsSender;
pub use self::twilio::TwilioSmsSender;

/// Errors returned from an SMS send attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum SmsError {
    /// The configured transport failed to deliver the message.
    Transport {
        /// Sanitized description of the failure (no secrets).
        reason: String,
    },
    /// The caller passed invalid input — e.g. a phone number with CR/LF.
    InvalidInput {
        /// What was wrong with the input.
        reason: String,
    },
}

impl fmt::Display for SmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { reason } => write!(f, "SMS transport error: {reason}"),
            Self::InvalidInput { reason } => write!(f, "invalid SMS input: {reason}"),
        }
    }
}

impl std::error::Error for SmsError {}

/// A fully-rendered SMS message ready for delivery.
///
/// Transport adapters only need to deliver this — they are not
/// responsible for content decisions.
#[derive(Clone, Debug)]
pub struct SmsMessage {
    /// Recipient phone number in E.164 format (e.g. `+15551234567`).
    pub to: String,
    /// SMS text body.
    pub body: String,
}

/// Wraps an SMS credential (auth token, secret access key) and prevents
/// it from leaking via [`fmt::Debug`] or [`fmt::Display`].
#[derive(Clone, Zeroize)]
pub struct SmsSecret {
    secret: String,
}

impl SmsSecret {
    /// Creates a new `SmsSecret`.
    pub fn new(secret: String) -> Self {
        Self { secret }
    }

    /// Returns the secret value for use in API calls.
    pub(crate) fn expose_secret(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for SmsSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SmsSecret([redacted])")
    }
}

/// Trait for outbound SMS delivery adapters.
///
/// Implementations are synchronous. Callers in async contexts must wrap
/// invocations in `tokio::task::spawn_blocking`.
pub trait SmsSender: Send + Sync {
    /// Sends an SMS message. Returns `Ok(())` on success.
    fn send(&self, message: &SmsMessage) -> Result<(), SmsError>;
}

/// Convenience alias for a shared dynamic [`SmsSender`].
pub type SharedSmsSender = Arc<dyn SmsSender>;

/// Returns the masked form of an E.164 phone number for safe use in
/// observability output (AC 3.5.2).
///
/// Keeps the `+` prefix (if any) and the last four decimal digits visible;
/// replaces everything in between with `***`. For example:
/// `+15551234567` → `+***4567`, `07911123456` → `***3456`.
pub(crate) fn mask_phone(phone: &str) -> String {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    let last4 = if digits.len() > 4 {
        &digits[digits.len() - 4..]
    } else {
        &digits
    };
    if phone.starts_with('+') {
        format!("+***{last4}")
    } else {
        format!("***{last4}")
    }
}

/// Rejects a field value that contains CR or LF — prevents header/body injection.
pub(crate) fn reject_crlf(field: &str, value: &str) -> Result<(), SmsError> {
    if value.contains('\r') || value.contains('\n') {
        return Err(SmsError::InvalidInput {
            reason: format!("{field} must not contain CR or LF"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sms_error_display_transport() {
        let err = SmsError::Transport {
            reason: "connection refused".to_string(),
        };
        assert!(
            err.to_string().contains("transport error"),
            "display: {err}"
        );
    }

    #[test]
    fn sms_error_display_invalid_input() {
        let err = SmsError::InvalidInput {
            reason: "contains CR".to_string(),
        };
        assert!(err.to_string().contains("invalid"), "display: {err}");
    }

    #[test]
    fn sms_secret_debug_is_redacted() {
        let secret = SmsSecret::new("supersecret".to_string());
        let debug = format!("{secret:?}");
        assert!(!debug.contains("supersecret"), "debug: {debug}");
        assert!(debug.contains("redacted"), "debug: {debug}");
    }

    #[test]
    fn sms_secret_expose_secret() {
        let secret = SmsSecret::new("mytoken".to_string());
        assert_eq!(secret.expose_secret(), "mytoken");
    }

    #[test]
    fn reject_crlf_rejects_cr() {
        assert!(reject_crlf("field", "value\rmore").is_err());
    }

    #[test]
    fn reject_crlf_rejects_lf() {
        assert!(reject_crlf("field", "value\nmore").is_err());
    }

    #[test]
    fn reject_crlf_passes_clean_input() {
        assert!(reject_crlf("field", "+15551234567").is_ok());
    }

    #[test]
    fn mask_phone_e164_us() {
        assert_eq!(mask_phone("+15551234567"), "+***4567");
    }

    #[test]
    fn mask_phone_no_plus_prefix() {
        assert_eq!(mask_phone("07911123456"), "***3456");
    }

    #[test]
    fn mask_phone_short_number() {
        // Fewer than 4 digits — show all digits, still safe.
        assert_eq!(mask_phone("+123"), "+***123");
    }

    #[test]
    fn mask_phone_hides_middle_digits() {
        let masked = mask_phone("+447700900123");
        assert!(!masked.contains("7700900"), "middle digits must not appear");
        assert!(masked.ends_with("0123"), "last 4 must be visible");
    }
}
