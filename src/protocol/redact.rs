//! PII / token redaction for `tracing` span fields (A-27).
//!
//! Wrap any sensitive value in [`Redact`] before passing it to a tracing
//! macro. Both `Display` and `Debug` emit the literal string `[REDACTED]`
//! so the inner value is never formatted into a log record or span field.
//!
//! # Default-redacted field names
//!
//! Per §3.28 of the abuse-prevention plan the following span-field names
//! MUST always be wrapped in [`Redact`] (or dropped entirely):
//!
//! - `reset_url` — one-shot password-reset URLs carry a bearer-equivalent token.
//! - `magic_link_url` — same token-in-URL risk.
//! - `password` — plaintext credential.
//! - `token` — opaque bearer token.
//! - `cookie` — session cookie value.
//! - raw email addresses — PII under most data-protection regulations.
//!
//! Per-deployment overrides are not yet wired (Phase 0 ships the newtype only).
//! Future work: `HEARTH_LOG_INCLUDE_PII=1` env toggle and per-realm config.
//!
//! # Example
//!
//! ```rust,ignore
//! use crate::protocol::redact::Redact;
//!
//! tracing::warn!(
//!     reset_url = %Redact(&url),
//!     "password reset URL (no email transport configured)"
//! );
//! ```

use std::fmt;

/// Wraps a value so that both `Display` and `Debug` emit `[REDACTED]`.
///
/// The inner value is never accessed by either formatter and therefore never
/// written into any tracing subscriber, span exporter, or log record.
///
/// The wrapper is zero-cost: no heap allocation, no cloning.
pub struct Redact<T>(pub T);

impl<T> fmt::Display for Redact<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> fmt::Debug for Redact<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
