//! Unified `return_to` / federation-redirect allowlist validator (A-52).
//!
//! Every `return_to`, `RelayState`-embedded URL, and federation `bag.return_to`
//! MUST flow through [`validate_return_to`] before being used as a `Location`
//! header or Redirect target.
//!
//! # Rejected inputs
//!
//! - Scheme-relative (`//evil.com/…`)
//! - Backslash-relative (`\evil`)
//! - Absolute URLs whose origin is not in `allowed_origins`
//! - `data:` and `javascript:` URLs
//! - Newline / CR characters (header-injection guard)
//! - Empty string
//!
//! # Accepted inputs
//!
//! - Absolute-path URLs (`/ui/…`, `/admin/…`, `/`) — always accepted when they
//!   pass the injection checks.
//! - Absolute URLs whose origin exactly matches one of `allowed_origins`.

/// Validates a `return_to` value and returns the sanitized form, or `None`
/// if the value is unsafe.
///
/// `allowed_origins` is the operator-configured list from
/// `security.allowed_return_to_origins` in `hearth.yaml`.  Pass an empty slice
/// to permit only same-origin relative paths.
#[must_use]
pub fn validate_return_to(value: &str, allowed_origins: &[String]) -> Option<String> {
    let s = value.trim();

    if s.is_empty() {
        return None;
    }

    // Header-injection guard.
    if s.contains('\n') || s.contains('\r') || s.contains('\0') {
        return None;
    }

    // Reject scheme-relative and backslash-relative.
    if s.starts_with("//") || s.starts_with('\\') {
        return None;
    }

    // Reject data: and javascript: (case-insensitive prefix check).
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("javascript:") || lower.starts_with("data:") {
        return None;
    }

    // Absolute URL — only allowed if origin is whitelisted.
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let origin = extract_origin(s)?;
        if allowed_origins.iter().any(|o| o == &origin) {
            return Some(s.to_string());
        }
        return None;
    }

    // Relative-path URL: must start with '/'.
    if !s.starts_with('/') {
        return None;
    }

    Some(s.to_string())
}

/// Extracts the `scheme://host[:port]` origin from an absolute URL.
fn extract_origin(url: &str) -> Option<String> {
    // Find "://"
    let after_scheme = url.find("://")?;
    let host_start = after_scheme + 3;
    let host_end = url[host_start..]
        .find('/')
        .map_or(url.len(), |i| host_start + i);
    if host_end <= host_start {
        return None;
    }
    // scheme
    let scheme = &url[..after_scheme];
    let host = &url[host_start..host_end];
    Some(format!("{scheme}://{host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_origins() -> Vec<String> {
        vec![]
    }

    fn with_origin(o: &str) -> Vec<String> {
        vec![o.to_string()]
    }

    #[test]
    fn accepts_relative_paths() {
        assert_eq!(
            validate_return_to("/ui/account", &no_origins()),
            Some("/ui/account".to_string())
        );
        assert_eq!(
            validate_return_to("/admin/dashboard", &no_origins()),
            Some("/admin/dashboard".to_string())
        );
        assert_eq!(
            validate_return_to("/", &no_origins()),
            Some("/".to_string())
        );
    }

    #[test]
    fn accepts_path_with_query() {
        let val = "/ui/login?next=overview";
        assert_eq!(
            validate_return_to(val, &no_origins()),
            Some(val.to_string())
        );
    }

    #[test]
    fn rejects_scheme_relative() {
        assert!(validate_return_to("//evil.com/steal", &no_origins()).is_none());
    }

    #[test]
    fn rejects_backslash() {
        assert!(validate_return_to("\\evil.com", &no_origins()).is_none());
    }

    #[test]
    fn rejects_javascript_scheme() {
        assert!(validate_return_to("javascript:alert(1)", &no_origins()).is_none());
        assert!(validate_return_to("JAVASCRIPT:alert(1)", &no_origins()).is_none());
    }

    #[test]
    fn rejects_data_scheme() {
        assert!(validate_return_to("data:text/html,<h1>x</h1>", &no_origins()).is_none());
    }

    #[test]
    fn rejects_absolute_without_allowlist() {
        assert!(validate_return_to("https://evil.com/", &no_origins()).is_none());
    }

    #[test]
    fn accepts_absolute_when_origin_whitelisted() {
        let origins = with_origin("https://app.example.com");
        assert!(validate_return_to("https://app.example.com/path", &origins).is_some());
    }

    #[test]
    fn rejects_absolute_different_origin() {
        let origins = with_origin("https://app.example.com");
        assert!(validate_return_to("https://evil.example.com/path", &origins).is_none());
    }

    #[test]
    fn rejects_newline_injection() {
        assert!(validate_return_to("/ui/account\nSet-Cookie: bad=1", &no_origins()).is_none());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_return_to("", &no_origins()).is_none());
        assert!(validate_return_to("   ", &no_origins()).is_none());
    }
}
