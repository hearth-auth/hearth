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

/// Longest message [`sanitize_log_text`] keeps, in characters, so one error
/// cannot flood the log.
const MAX_LOGGED_CHARS: usize = 1024;

/// Shortest run of token-alphabet characters treated as a possible secret
/// (an API key, a JWT segment, a hex or base64 key).
const MIN_OPAQUE_RUN: usize = 24;

/// Keys whose value, after `=` or `:`, is masked.
const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "bearer",
    "basic",
    "dpop",
];

/// HTTP authorization schemes: followed by whitespace, then the credential.
const AUTH_SCHEMES: &[&str] = &["bearer", "basic", "dpop"];

/// A PII-safe rendering of an [`IdentityError`](crate::identity::IdentityError)
/// for an ERROR log line: the error's kind (its variant name) and its message
/// passed through [`sanitize_log_text`].
///
/// An error's `Display` text is not safe to log as-is: an internal error can
/// wrap text Hearth did not write — an SMTP server's rejection names the
/// recipient's address, an upstream's body can echo a credential.
pub(crate) struct LogSafeError<'a>(pub &'a crate::identity::IdentityError);

impl fmt::Display for LogSafeError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The derived `Debug` starts with the variant name; nothing else of it
        // is written.
        let debug = format!("{:?}", self.0);
        let kind = debug
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .unwrap_or_default();
        write!(f, "{kind}: {}", sanitize_log_text(&self.0.to_string()))
    }
}

/// Masks what a log line must not carry (CLAUDE.md: no passwords, tokens,
/// keys or PII) in free text: e-mail addresses become `[email]`; the value
/// after a secret-looking key (`password=`, `token:`, `Bearer `, …) and any
/// run of at least 24 token-alphabet characters that is not a UUID become
/// `[REDACTED]`. The result is capped at 1024 characters.
pub(crate) fn sanitize_log_text(text: &str) -> String {
    let masked = mask_opaque_runs(&mask_secret_values(&mask_emails(text)));
    if masked.chars().count() <= MAX_LOGGED_CHARS {
        return masked;
    }
    let mut capped: String = masked.chars().take(MAX_LOGGED_CHARS).collect();
    capped.push('…');
    capped
}

fn is_email_local(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-')
}

fn is_email_domain(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-')
}

/// Replaces every `local@domain.tld` with `[email]`.
fn mask_emails(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '@' {
            let local_len = out.chars().rev().take_while(|c| is_email_local(*c)).count();
            let domain: String = chars[i + 1..]
                .iter()
                .take_while(|c| is_email_domain(**c))
                .collect();
            let domain = domain.trim_end_matches('.');
            if local_len > 0 && domain.contains('.') && !domain.starts_with('.') {
                for _ in 0..local_len {
                    out.pop();
                }
                out.push_str("[email]");
                i += 1 + domain.chars().count();
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Replaces the value after a [`SECRET_KEYS`] key followed by `=`, `:` or
/// (for `bearer`) whitespace.
fn mask_secret_values(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    'scan: while i < text.len() {
        for key in SECRET_KEYS {
            if lower[i..].starts_with(key)
                && !lower[..i]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_ascii_alphanumeric())
            {
                let after_key = i + key.len();
                let rest = &text[after_key..];
                let gap = rest.len() - rest.trim_start_matches([' ', '"', '\'']).len();
                let sep = rest[gap..].chars().next();
                let value_start = match sep {
                    Some('=' | ':') => {
                        let after_sep = &rest[gap + 1..];
                        after_key
                            + gap
                            + 1
                            + (after_sep.len()
                                - after_sep.trim_start_matches([' ', '"', '\'']).len())
                    }
                    Some(_) if AUTH_SCHEMES.contains(key) && gap > 0 => after_key + gap,
                    _ => continue,
                };
                let value_len = text[value_start..]
                    .find(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '&' | '"' | '\''))
                    .unwrap_or(text.len() - value_start);
                if value_len == 0 {
                    continue;
                }
                // `Authorization: Bearer <credential>`: the scheme is not the
                // secret — resume at it, so its own rule masks the credential.
                let value = lower[value_start..value_start + value_len].to_string();
                if AUTH_SCHEMES.contains(&value.as_str()) {
                    out.push_str(&text[i..value_start]);
                    i = value_start;
                    continue 'scan;
                }
                out.push_str(&text[i..value_start]);
                out.push_str("[REDACTED]");
                i = value_start + value_len;
                continue 'scan;
            }
        }
        let c = text[i..].chars().next().unwrap_or_default();
        out.push(c);
        i += c.len_utf8().max(1);
    }
    out
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '=' | '_' | '-')
}

fn is_uuid(run: &str) -> bool {
    run.len() == 36
        && run.char_indices().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// Replaces every run of at least [`MIN_OPAQUE_RUN`] token-alphabet characters
/// that is not a UUID with `[REDACTED]`.
fn mask_opaque_runs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= MIN_OPAQUE_RUN && !is_uuid(run) {
            out.push_str("[REDACTED]");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if is_token_char(c) {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

#[cfg(test)]
mod sanitize_tests {
    use super::sanitize_log_text;

    #[test]
    fn email_addresses_are_masked() {
        assert_eq!(
            sanitize_log_text("550 5.1.1 <a.b+c@mail.example.co.uk>: rejected; cc x_y@z.io."),
            "550 5.1.1 <[email]>: rejected; cc [email]."
        );
    }

    #[test]
    fn an_at_sign_without_an_address_is_kept() {
        assert_eq!(
            sanitize_log_text("user@ host @localhost"),
            "user@ host @localhost"
        );
    }

    #[test]
    fn secret_values_are_masked() {
        assert_eq!(
            sanitize_log_text("password=hunter2, Token: abc; Authorization: Bearer xyz"),
            "password=[REDACTED], Token: [REDACTED]; Authorization: Bearer [REDACTED]"
        );
    }

    #[test]
    fn opaque_runs_are_masked_but_uuids_and_paths_are_kept() {
        let text = "realm 3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b key \
                    q83vEjRWeJC7ze8BI0VniavN7wEjRWeJ at /var/lib/hearth/data/000007.sst";
        assert_eq!(
            sanitize_log_text(text),
            "realm 3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b key [REDACTED] at \
             /var/lib/hearth/data/000007.sst"
        );
    }

    #[test]
    fn a_long_message_is_capped() {
        let long = "word ".repeat(1_000);
        assert_eq!(sanitize_log_text(&long).chars().count(), 1_025);
    }
}
