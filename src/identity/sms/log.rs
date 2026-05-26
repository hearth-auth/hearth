//! Logging SMS sender — writes messages to the `tracing` log.
//!
//! Default transport when no external SMS provider is configured. Each
//! message is emitted at WARN level so it stands out in normal INFO-level
//! logs. No PII beyond the recipient phone number (already known to the caller).

use super::{reject_crlf, SmsError, SmsMessage, SmsSender};

/// An [`SmsSender`] that writes messages to the `tracing` log.
///
/// Default transport when no external SMS provider is configured.
#[derive(Debug, Default)]
pub struct LoggingSmsSender;

impl LoggingSmsSender {
    /// Creates a new logging SMS sender.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SmsSender for LoggingSmsSender {
    fn send(&self, message: &SmsMessage) -> Result<(), SmsError> {
        reject_crlf("recipient", &message.to)?;
        tracing::warn!(
            recipient = %super::mask_phone(&message.to),
            body      = %message.body,
            "sms.send (log transport): message logged instead of delivered"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_message() -> SmsMessage {
        SmsMessage {
            to: "+15551234567".to_string(),
            body: "Your code is 123456".to_string(),
        }
    }

    #[test]
    fn log_sender_succeeds() {
        let sender = LoggingSmsSender::new();
        let result = sender.send(&test_message());
        assert!(
            result.is_ok(),
            "log sender should always succeed: {result:?}"
        );
    }

    #[test]
    fn log_sender_rejects_crlf_in_recipient() {
        let sender = LoggingSmsSender::new();
        let msg = SmsMessage {
            to: "+15551234567\r\nX-Injected: yes".to_string(),
            body: "code".to_string(),
        };
        assert!(
            matches!(sender.send(&msg), Err(SmsError::InvalidInput { .. })),
            "should reject CRLF in recipient"
        );
    }

    #[test]
    fn log_sender_default_constructs() {
        let sender = LoggingSmsSender::default();
        assert!(sender.send(&test_message()).is_ok());
    }

    #[test]
    fn log_sender_is_object_safe_and_send_sync() {
        fn assert_object_safe(_: &dyn SmsSender) {}
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        let sender = LoggingSmsSender::new();
        assert_object_safe(&sender);
        assert_send_sync(&sender);
    }
}
