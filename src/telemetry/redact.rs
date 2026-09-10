//! Redaction helpers for anything that renders an HTTP header into a log line.
//!
//! Hearth makes outbound requests to federation providers, SMS gateways, email
//! providers and operator-registered webhook endpoints. Those requests carry
//! provider credentials in their headers. The project rule is absolute: a
//! password, token, key or piece of personally identifying data must never
//! reach a log line, at any level.
//!
//! Two things enforce that rule. [`crate::telemetry::build_env_filter`] caps the
//! dependency targets that hex-dump a serialized request head, so no log level
//! and no `RUST_LOG` value can turn them on. This module covers the other half:
//! when Hearth's own code renders a header, it renders it through here.
//!
//! The matcher is deliberately generous. A header wrongly treated as sensitive
//! costs one unreadable diagnostic line. A header wrongly treated as benign
//! costs a credential.

/// What replaces the value of a sensitive header.
pub const REDACTED: &str = "[redacted]";

/// Header names that are sensitive in full, compared case-insensitively.
const SENSITIVE_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "dpop",
    "www-authenticate",
    "proxy-authenticate",
];

/// Substrings that make a header name sensitive wherever they appear.
///
/// These catch the vendor-specific header names Hearth's egress paths use —
/// `X-Api-Key`, `X-Postmark-Server-Token`, `X-Amz-Security-Token`,
/// `X-Goog-Api-Key` and the webhook signature header among them — without
/// needing an exhaustive list of every provider Hearth may ever talk to.
const SENSITIVE_MARKERS: &[&str] = &[
    "api-key",
    "apikey",
    "auth",
    "credential",
    "password",
    "private",
    "secret",
    "signature",
    "token",
];

/// Returns `true` when a header of this name must never have its value logged.
///
/// The comparison is case-insensitive, because HTTP header names are.
#[must_use]
pub fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if SENSITIVE_NAMES.iter().any(|n| *n == lower) {
        return true;
    }
    SENSITIVE_MARKERS.iter().any(|m| lower.contains(m))
}

/// Returns the value to log for `name`, replacing it when the header is
/// sensitive.
///
/// A benign header keeps its value, because the whole point of logging a
/// request head is to be able to read it.
#[must_use]
pub fn redact_header_value(name: &str, value: &str) -> String {
    if is_sensitive_header(name) {
        REDACTED.to_string()
    } else {
        value.to_string()
    }
}

/// Renders a header list as one log-safe line.
///
/// Header *names* are kept — knowing that an `Authorization` header was present
/// is useful and discloses nothing. Only the values of sensitive headers are
/// replaced.
#[must_use]
pub fn redacted_headers<N, V>(headers: &[(N, V)]) -> String
where
    N: AsRef<str>,
    V: AsRef<str>,
{
    let mut out = String::new();
    for (name, value) in headers {
        if !out.is_empty() {
            out.push_str("; ");
        }
        let name = name.as_ref();
        out.push_str(name);
        out.push_str(": ");
        out.push_str(&redact_header_value(name, value.as_ref()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{is_sensitive_header, redact_header_value, redacted_headers};

    #[test]
    fn benign_headers_are_not_treated_as_sensitive() {
        for name in [
            "Content-Type",
            "Content-Length",
            "Accept",
            "User-Agent",
            "Host",
            "Date",
            "Keep-Alive",
        ] {
            assert!(
                !is_sensitive_header(name),
                "{name} must keep its value in a log line"
            );
        }
    }

    #[test]
    fn matching_ignores_header_name_case() {
        assert!(is_sensitive_header("AUTHORIZATION"));
        assert!(is_sensitive_header("authorization"));
        assert!(is_sensitive_header("Authorization"));
    }

    #[test]
    fn an_empty_header_list_renders_empty() {
        let headers: Vec<(String, String)> = Vec::new();
        assert_eq!(redacted_headers(&headers), "");
    }

    #[test]
    fn a_sensitive_value_never_survives_rendering() {
        let secret = "sk-live-0123456789";
        assert_eq!(redact_header_value("X-Api-Key", secret), "[redacted]");
        let rendered = redacted_headers(&[("X-Api-Key", secret)]);
        assert!(!rendered.contains(secret), "leaked: {rendered}");
    }
}
