//! HIBP k-anonymity breach-check client.
//!
//! Uses the HaveIBeenPwned Pwned Passwords Range API: only the first 5 characters of the
//! SHA-1 hex digest are transmitted, so no password or full hash leaves the process
//! (k-anonymity model).

use std::sync::Arc;

use ring::digest;
use thiserror::Error;

/// Error returned by the HIBP breach-check client.
#[derive(Debug, Error)]
pub enum HibpError {
    /// The HIBP API was unreachable (network error, timeout, or non-2xx response).
    ///
    /// Callers MUST fail-open on this variant: accept the password and emit a
    /// `BreachCheckUnavailable` audit event.
    #[error("HIBP API unreachable: {reason}")]
    Unreachable { reason: String },
}

/// HTTP transport for the HIBP Range API.
///
/// Trait-based so tests can inject a stub without network I/O.
pub trait HibpTransport: Send + Sync {
    /// Calls `GET https://api.pwnedpasswords.com/range/{prefix}`.
    ///
    /// Returns the raw response body (newline-separated `SUFFIX:COUNT` pairs).
    /// `prefix` is the first 5 uppercase hex characters of the SHA-1 hash.
    fn get_range(&self, prefix: &str, api_key: Option<&str>) -> Result<String, HibpError>;
}

/// Production `ureq`-backed transport.
///
/// Runs the blocking ureq call inside `block_in_place` when invoked from a
/// multi-thread Tokio runtime, matching the pattern used by
/// `src/identity/email/http.rs`.
pub(crate) struct UreqHibpTransport;

impl HibpTransport for UreqHibpTransport {
    fn get_range(&self, prefix: &str, api_key: Option<&str>) -> Result<String, HibpError> {
        let url = format!(
            "https://api.pwnedpasswords.com/range/{}",
            prefix.to_uppercase()
        );

        let do_request = || -> Result<String, HibpError> {
            let mut req = ureq::get(&url).header("Add-Padding", "true");
            if let Some(key) = api_key {
                if !key.is_empty() {
                    req = req.header("hibp-api-key", key);
                }
            }
            let resp = req.call().map_err(|e| HibpError::Unreachable {
                reason: e.to_string(),
            })?;

            let status: u16 = resp.status().into();
            if status != 200 {
                return Err(HibpError::Unreachable {
                    reason: format!("HTTP {status}"),
                });
            }

            resp.into_body()
                .read_to_string()
                .map_err(|e| HibpError::Unreachable {
                    reason: e.to_string(),
                })
        };

        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(do_request)
            }
            _ => do_request(),
        }
    }
}

/// HIBP k-anonymity breach-check client.
///
/// Holds a shared transport (connection pool in production). The transport is
/// injectable via [`HibpClient::with_transport`] for tests.
pub struct HibpClient {
    transport: Arc<dyn HibpTransport>,
}

impl HibpClient {
    /// Creates a production client backed by [`UreqHibpTransport`].
    pub fn new() -> Self {
        Self {
            transport: Arc::new(UreqHibpTransport),
        }
    }

    /// Creates a client with an injected transport.
    ///
    /// Used in integration tests to inject a stub without network calls.
    /// Follows the same pattern as `StubHttpTransport` in the email module.
    pub fn with_transport(transport: Arc<dyn HibpTransport>) -> Self {
        Self { transport }
    }

    /// Returns `true` if `password` has appeared in a known data breach.
    ///
    /// Computes SHA-1 of the password; sends only the first 5 hex characters
    /// to the HIBP Range API — the full hash never leaves the process.
    ///
    /// # Errors
    /// Returns [`HibpError::Unreachable`] on network failure or a non-2xx response.
    /// Callers must fail-open: accept the password and emit a `BreachCheckUnavailable`
    /// audit event instead of rejecting the user.
    pub fn is_pwned(&self, password: &[u8], api_key: Option<&str>) -> Result<bool, HibpError> {
        let (prefix, suffix) = sha1_prefix_suffix(password);
        let body = self.transport.get_range(&prefix, api_key)?;
        Ok(response_contains_suffix(&body, &suffix))
    }
}

/// Computes the SHA-1 hash of `data` and splits it into the k-anonymity
/// prefix (first 5 uppercase hex chars) and suffix (remaining 35 chars).
pub(crate) fn sha1_prefix_suffix(data: &[u8]) -> (String, String) {
    let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    let hex = hex::encode(hash.as_ref()).to_uppercase();
    let prefix = hex[..5].to_string();
    let suffix = hex[5..].to_string();
    (prefix, suffix)
}

/// Returns `true` if `suffix` (uppercase, without colon) appears in a HIBP range body.
fn response_contains_suffix(body: &str, suffix: &str) -> bool {
    for line in body.lines() {
        if let Some((candidate, _count)) = line.split_once(':') {
            if candidate.trim().eq_ignore_ascii_case(suffix) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SHA-1 helpers ─────────────────────────────────────────────────────────

    #[test]
    fn sha1_prefix_suffix_known_vector() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = sha1_prefix_suffix(b"password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn sha1_prefix_length_is_five() {
        let (prefix, _) = sha1_prefix_suffix(b"hunter2");
        assert_eq!(prefix.len(), 5);
    }

    #[test]
    fn sha1_suffix_length_is_35() {
        let (_, suffix) = sha1_prefix_suffix(b"some-unique-passphrase");
        assert_eq!(suffix.len(), 35);
    }

    #[test]
    fn sha1_output_is_uppercase_hex() {
        let (prefix, suffix) = sha1_prefix_suffix(b"abc");
        let full = format!("{prefix}{suffix}");
        assert!(full
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
    }

    // ── response_contains_suffix ──────────────────────────────────────────────

    #[test]
    fn response_contains_suffix_found() {
        let body =
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\nABCDE00000000000000000000000000000:1";
        assert!(response_contains_suffix(
            body,
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        ));
    }

    #[test]
    fn response_contains_suffix_not_found() {
        let body = "ABCDE00000000000000000000000000000:1\nFFFFF00000000000000000000000000000:2";
        assert!(!response_contains_suffix(
            body,
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        ));
    }

    #[test]
    fn response_contains_suffix_case_insensitive() {
        let body = "1e4c9b93f3f0682250b6cf8331b7ee68fd8:1";
        assert!(response_contains_suffix(
            body,
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        ));
    }

    // ── HibpClient with stub transport ────────────────────────────────────────

    struct StubTransport {
        body: &'static str,
    }

    impl HibpTransport for StubTransport {
        fn get_range(&self, _prefix: &str, _api_key: Option<&str>) -> Result<String, HibpError> {
            Ok(self.body.to_string())
        }
    }

    struct FailingTransport;

    impl HibpTransport for FailingTransport {
        fn get_range(&self, _prefix: &str, _api_key: Option<&str>) -> Result<String, HibpError> {
            Err(HibpError::Unreachable {
                reason: "simulated timeout".to_string(),
            })
        }
    }

    #[test]
    fn is_pwned_returns_true_when_suffix_in_body() {
        // "password" suffix (after first 5 chars of SHA-1)
        let client = HibpClient::with_transport(Arc::new(StubTransport {
            body: "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824",
        }));
        assert!(client.is_pwned(b"password", None).unwrap());
    }

    #[test]
    fn is_pwned_returns_false_when_suffix_absent() {
        let client = HibpClient::with_transport(Arc::new(StubTransport {
            body: "ABCDE00000000000000000000000000000:1",
        }));
        assert!(!client.is_pwned(b"password", None).unwrap());
    }

    #[test]
    fn is_pwned_propagates_unreachable_error() {
        let client = HibpClient::with_transport(Arc::new(FailingTransport));
        assert!(matches!(
            client.is_pwned(b"any-password", None),
            Err(HibpError::Unreachable { .. })
        ));
    }

    #[test]
    fn is_pwned_only_sends_5_char_prefix() {
        // Verify the prefix sent is exactly 5 chars (k-anonymity AC-2).
        struct PrefixCapture(std::sync::Mutex<String>);
        impl HibpTransport for PrefixCapture {
            fn get_range(&self, prefix: &str, _api_key: Option<&str>) -> Result<String, HibpError> {
                *self.0.lock().unwrap() = prefix.to_string();
                Ok(String::new())
            }
        }
        let captured = Arc::new(PrefixCapture(std::sync::Mutex::new(String::new())));
        let client = HibpClient::with_transport(Arc::clone(&captured) as Arc<dyn HibpTransport>);
        let _ = client.is_pwned(b"password", None);
        assert_eq!(captured.0.lock().unwrap().len(), 5);
    }
}
