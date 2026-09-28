//! Logging SMS sender — writes a line to the `tracing` log instead of
//! delivering the message.
//!
//! Default transport when no external SMS provider is configured. Each
//! message is emitted at WARN level so it stands out in normal INFO-level
//! logs. The recipient is always masked.
//!
//! The message body carries the one-time code, so it is only logged by the
//! dev-mode sender ([`LoggingSmsSender::new_dev`]). The production sender
//! ([`LoggingSmsSender::new`], also the `Default`) records that a message was
//! dropped and nothing else — mirroring `LoggingEmailSender`.

use super::{reject_crlf, SmsError, SmsMessage, SmsSender};

/// An [`SmsSender`] that writes messages to the `tracing` log.
///
/// Default transport when no external SMS provider is configured.
#[derive(Debug, Default)]
pub struct LoggingSmsSender {
    /// When `true`, the full message body — which carries the OTP — is
    /// logged. Only ever `true` in dev mode. In production the body is a live
    /// authentication code and MUST NOT reach the operator log.
    log_body: bool,
}

impl LoggingSmsSender {
    /// Creates a production-safe logging sender.
    ///
    /// Logs only that a message was produced (and its masked recipient) —
    /// never the body, which carries the one-time code.
    #[must_use]
    pub fn new() -> Self {
        Self { log_body: false }
    }

    /// Creates a dev-only logging sender that writes the full message body to
    /// the log so an engineer can read the code from the terminal.
    ///
    /// MUST NOT be constructed in production — the body is a live OTP.
    #[must_use]
    pub fn new_dev() -> Self {
        Self { log_body: true }
    }
}

impl SmsSender for LoggingSmsSender {
    fn send(&self, message: &SmsMessage) -> Result<(), SmsError> {
        reject_crlf("recipient", &message.to)?;
        if self.log_body {
            tracing::warn!(
                recipient = %super::mask_phone(&message.to),
                body      = %message.body,
                "sms.send (log transport, dev): message logged instead of delivered"
            );
        } else {
            tracing::warn!(
                recipient = %super::mask_phone(&message.to),
                "sms.send (log transport): message not delivered and its body (which \
                 carries a one-time code) is suppressed from the log — configure a real \
                 sms.transport to deliver SMS"
            );
        }
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

    #[derive(Clone, Default)]
    struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("capture mutex").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for CaptureWriter {
        type Writer = Self;

        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// Runs `f` with every event at TRACE and above captured.
    fn capture_logs(f: impl FnOnce()) -> String {
        let writer = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = writer.0.lock().expect("capture mutex").clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// The body carries the OTP. Outside dev mode it must never reach the
    /// operator log — it used to be written in full at WARN.
    #[test]
    fn production_sender_does_not_log_the_otp() {
        let sender = LoggingSmsSender::new();
        let logs = capture_logs(|| {
            sender.send(&test_message()).expect("send");
        });
        assert!(
            !logs.contains("123456"),
            "the production log transport leaked the OTP: {logs}"
        );
        assert!(
            logs.contains("sms.send"),
            "the redacted line must still record that a message was dropped: {logs}"
        );
    }

    /// Dev mode keeps the full body so a developer can read the code from the
    /// terminal — the only way the log transport "delivers" anything.
    #[test]
    fn dev_sender_logs_the_body() {
        let sender = LoggingSmsSender::new_dev();
        let logs = capture_logs(|| {
            sender.send(&test_message()).expect("send");
        });
        assert!(logs.contains("123456"), "dev must log the code: {logs}");
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
        // `Default` is the production-safe (body-suppressing) sender.
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
