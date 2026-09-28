//! Outbound email delivery.
//!
//! Defines the [`EmailSender`] trait with concrete implementations:
//!
//! - [`LoggingEmailSender`] — writes verification URLs to the `tracing`
//!   log at WARN level. The default for local development.
//! - [`SmtpEmailSender`] — delivers via SMTP (with or without TLS /
//!   STARTTLS) using the `lettre` crate. Production transport.
//! - [`SendgridEmailSender`], [`PostmarkEmailSender`], [`MailgunEmailSender`],
//!   [`MailtrapEmailSender`] — HTTP API adapters for cloud email providers.
//!
//! Off the hot path. Senders are invoked from onboarding and (later)
//! password-reset flows, never from authentication.

mod branding;
pub mod http;
mod log;
pub mod mailcatcher;
pub mod mailgun;
mod mailtrap;
pub(crate) mod placeholder;
mod postmark;
mod sendgrid;
pub(crate) mod service;
mod smtp;
pub(crate) mod stored_templates;
pub(crate) mod templates;

use std::fmt;
use std::sync::Arc;

use zeroize::Zeroize;

pub use self::http::StubHttpTransport;
pub use self::log::LoggingEmailSender;
pub use self::mailcatcher::{MailcatcherSender, MailcatcherState};
pub use self::mailgun::MailgunEmailSender;
pub use self::mailtrap::MailtrapEmailSender;
pub use self::postmark::PostmarkEmailSender;
pub use self::sendgrid::SendgridEmailSender;
pub use self::service::EmailService;
pub use self::smtp::{smtp_sender_from_config, SmtpEmailSender};
pub use branding::EmailBranding;
pub use placeholder::{
    allowed_placeholders, render as render_email_template, validate as validate_email_template,
};
pub use stored_templates::{EmailTemplateBody, LocalizedEmailTemplate};

/// Errors returned from an email send attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum EmailError {
    /// The configured transport failed to deliver the message (network,
    /// auth, rejection). Contains a human-readable reason without secrets.
    Transport {
        /// Sanitized description of the failure.
        reason: String,
    },
    /// The caller passed an invalid recipient or body — e.g. an address
    /// containing CR/LF that would enable header injection.
    InvalidInput {
        /// What was wrong with the input.
        reason: String,
    },
    /// A template rendering error occurred.
    Template {
        /// Description of the template error.
        reason: String,
    },
}

impl fmt::Display for EmailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { reason } => write!(f, "email transport error: {reason}"),
            Self::InvalidInput { reason } => write!(f, "invalid email input: {reason}"),
            Self::Template { reason } => write!(f, "email template error: {reason}"),
        }
    }
}

impl std::error::Error for EmailError {}

/// A fully-rendered email message ready for delivery.
///
/// Transport adapters only need to deliver this — they are not
/// responsible for content decisions (branding, templates, etc.).
#[derive(Clone, Debug)]
pub struct EmailMessage {
    /// Recipient email address.
    pub to: String,
    /// Email subject line.
    pub subject: String,
    /// Plain text body (for clients that do not render HTML).
    pub text_body: String,
    /// HTML body (primary content).
    pub html_body: String,
}

/// Trait for outbound email delivery.
///
/// Implementations MUST be `Send + Sync` so the sender can be held in an
/// `Arc` and called from any task. The single `send` method delivers a
/// fully-rendered [`EmailMessage`].
pub trait EmailSender: Send + Sync {
    /// Sends a fully-rendered email message.
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError>;
}

/// Validates that an input string contains no CR/LF characters.
///
/// Email headers use CR/LF as separators; allowing untrusted input to
/// contain these characters enables header injection (e.g. adding a
/// `Bcc:` to exfiltrate mail to an attacker).
pub(crate) fn reject_crlf(field: &str, value: &str) -> Result<(), EmailError> {
    if value.contains('\r') || value.contains('\n') {
        return Err(EmailError::InvalidInput {
            reason: format!("{field} must not contain CR/LF"),
        });
    }
    Ok(())
}

/// Masks an email address for logs and display: the first character of the
/// local part, then `***`, then the domain — `alice@example.com` becomes
/// `a***@example.com`. Anything that is not `local@domain` becomes `***`.
///
/// Logs MUST NOT carry PII (CLAUDE.md), so every transport logs the recipient
/// through this.
pub(crate) fn mask_email_address(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let first = local.chars().next().unwrap_or('*');
            format!("{first}***@{domain}")
        }
        None => "***".to_string(),
    }
}

/// Convenience alias for a shared dynamic [`EmailSender`].
pub type SharedEmailSender = Arc<dyn EmailSender>;

/// A zeroize-on-drop wrapper for API keys.
///
/// Prevents accidental leakage via `Debug` or `Display`. API keys for
/// email providers (`SendGrid`, `Postmark`, `Mailgun`) MUST be wrapped in
/// this type.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ApiKey {
    inner: String,
}

impl ApiKey {
    /// Creates a new API key from a string.
    pub fn new(key: String) -> Self {
        Self { inner: key }
    }

    /// Returns the key value. Callers MUST NOT log the return value.
    pub(crate) fn expose_secret(&self) -> &str {
        &self.inner
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_email_address_keeps_only_the_first_character_and_the_domain() {
        assert_eq!(mask_email_address("alice@example.com"), "a***@example.com");
        assert_eq!(
            mask_email_address("bob.smith+otp@corp.example.org"),
            "b***@corp.example.org"
        );
        assert_eq!(mask_email_address("not-an-address"), "***");
        assert_eq!(mask_email_address("@example.com"), "****@example.com");
        assert_eq!(mask_email_address(""), "***");
    }

    #[test]
    fn logging_sender_accepts_plain_values() {
        let sender = LoggingEmailSender::new();
        let msg = EmailMessage {
            to: "alice@example.com".to_string(),
            subject: "Test".to_string(),
            text_body: "Hello".to_string(),
            html_body: "<p>Hello</p>".to_string(),
        };
        let result = sender.send(&msg);
        assert!(result.is_ok(), "clean inputs should succeed: {result:?}");
    }

    #[test]
    fn rejects_header_injection_in_recipient() {
        let sender = LoggingEmailSender::new();
        let msg = EmailMessage {
            to: "alice@x.com\r\nBcc: evil@x.com".to_string(),
            subject: "Test".to_string(),
            text_body: "Hello".to_string(),
            html_body: "<p>Hello</p>".to_string(),
        };
        let result = sender.send(&msg);
        assert!(matches!(result, Err(EmailError::InvalidInput { .. })));
    }

    #[test]
    fn error_display_does_not_leak_secrets() {
        let err = EmailError::Transport {
            reason: "connection refused".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("email transport error"), "got: {display}");
        assert!(display.contains("connection refused"), "got: {display}");
    }

    #[test]
    fn template_error_display() {
        let err = EmailError::Template {
            reason: "missing variable".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("email template error"), "got: {display}");
    }

    #[test]
    fn email_sender_is_object_safe() {
        fn assert_object_safe(_: &dyn EmailSender) {}
        let sender = LoggingEmailSender::new();
        assert_object_safe(&sender);
    }

    #[test]
    fn api_key_zeroize_and_redacted_debug() {
        let raw = format!("sg-test-{}", uuid::Uuid::new_v4());
        let key = ApiKey::new(raw.clone());
        let debug = format!("{key:?}");
        assert_eq!(debug, "ApiKey(***)");
        assert!(!debug.contains(&raw));
        assert_eq!(key.expose_secret(), &raw);
    }

    #[test]
    fn api_key_clone_works() {
        let key = ApiKey::new("test-key".to_string());
        let cloned = key.clone();
        assert_eq!(cloned.expose_secret(), "test-key");
    }
}
