//! Logging email sender — writes messages to the `tracing` log.
//!
//! Default transport when no external mail server is configured. In
//! production the message *body* is never logged: it carries password-reset,
//! verification, and invitation links (recovery credentials), and
//! `CLAUDE.md` forbids logging tokens or PII (audit 2026-08-28 §4.14#2,
//! §4.24#2). Only a dev-mode sender logs the full body so an engineer can
//! click the link from the terminal.

use super::{reject_crlf, EmailError, EmailMessage, EmailSender};

/// An [`EmailSender`] that writes messages to the `tracing` log.
///
/// Default transport when no external mail server is configured.
#[derive(Debug, Default)]
pub struct LoggingEmailSender {
    /// When `true`, the full message body — which carries reset/verification
    /// links — is logged. Only ever `true` in dev mode. In production the
    /// body is a recovery credential and MUST NOT reach the operator log.
    log_body: bool,
}

impl LoggingEmailSender {
    /// Creates a production-safe logging sender.
    ///
    /// Logs only that a message was produced (and its recipient) — never the
    /// subject or body, both of which may carry a recovery link.
    #[must_use]
    pub fn new() -> Self {
        Self { log_body: false }
    }

    /// Creates a dev-only logging sender that writes the full message body to
    /// the log so an engineer can follow the link from the terminal.
    ///
    /// MUST NOT be constructed in production — the body is a recovery
    /// credential (audit 2026-08-28 §4.14#2, §4.24#2).
    #[must_use]
    pub fn new_dev() -> Self {
        Self { log_body: true }
    }

    /// Returns the message body to log, or `None` when the body must be
    /// suppressed (production). Pure seam so the redaction policy is testable
    /// without capturing a `tracing` subscriber.
    fn loggable_body<'a>(&self, message: &'a EmailMessage) -> Option<&'a str> {
        if self.log_body {
            Some(message.text_body.as_str())
        } else {
            None
        }
    }
}

impl EmailSender for LoggingEmailSender {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        reject_crlf("recipient", &message.to)?;
        match self.loggable_body(message) {
            Some(body) => tracing::warn!(
                recipient = %message.to,
                subject = %message.subject,
                body = %body,
                "email.send (log transport, dev): message logged instead of delivered"
            ),
            None => tracing::warn!(
                recipient = %message.to,
                "email.send (log transport): message not delivered and its body \
                 (which carries recovery links) is suppressed from the log — configure a \
                 real email.transport to deliver recovery mail"
            ),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg() -> EmailMessage {
        EmailMessage {
            to: "alice@example.com".to_string(),
            subject: "Reset your password".to_string(),
            text_body: "Open https://auth.example.com/reset?token=SECRET-abc123".to_string(),
            html_body: String::new(),
        }
    }

    #[test]
    fn production_sender_suppresses_the_body() {
        // The default (production) sender must never expose the body, which
        // carries the reset token (audit 2026-08-28 §4.14#2, §4.24#2).
        let sender = LoggingEmailSender::new();
        assert!(
            sender.loggable_body(&msg()).is_none(),
            "production log transport must not log the message body"
        );
    }

    #[test]
    fn dev_sender_logs_the_body() {
        let sender = LoggingEmailSender::new_dev();
        assert_eq!(
            sender.loggable_body(&msg()),
            Some("Open https://auth.example.com/reset?token=SECRET-abc123"),
            "dev log transport must log the full body so the link is clickable"
        );
    }
}
