//! SCIM optimistic-concurrency support: `If-Match` precondition checking
//! and ETag-bearing resource responses (RFC 7644 §3.14, RFC 7232 §3.1).
//!
//! Hearth emits weak ETags of the form `W/"<updated_at-micros>"`. A SCIM
//! client (Okta, Azure AD) echoes the exact validator it last received in
//! an `If-Match` header on a subsequent `PUT`/`PATCH`/`DELETE`. If the
//! resource has since changed, its current validator differs and the write
//! is rejected with `412 Precondition Failed` — so a concurrent update
//! made against a stale copy fails loudly instead of silently clobbering
//! the newer state.

use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::protocol::scim::error::ScimError;

/// Reduces an ETag to its opaque tag, stripping the optional weak-validator
/// prefix (`W/`) and the surrounding double quotes. This lets a weak ETag
/// compare equal to the same tag echoed back by a client regardless of
/// quoting, which is the pragmatic comparison SCIM deployments rely on.
fn normalize(tag: &str) -> &str {
    let t = tag.trim();
    let t = t.strip_prefix("W/").unwrap_or(t);
    let t = t.strip_prefix('"').unwrap_or(t);
    t.strip_suffix('"').unwrap_or(t)
}

/// Enforces an inbound `If-Match` precondition against a resource's current
/// version.
///
/// * No `If-Match` header → `Ok(())` (the client did not request a
///   precondition; the write proceeds unconditionally).
/// * `If-Match: *` → matches any existing resource → `Ok(())`. Callers
///   MUST have already confirmed the resource exists.
/// * Any comma-separated validator equal to `current_version` (ignoring the
///   weak-validator prefix and quoting) → `Ok(())`.
/// * Otherwise → `Err` with `412 Precondition Failed`.
pub fn check_if_match(headers: &HeaderMap, current_version: &str) -> Result<(), ScimError> {
    let Some(raw) = headers.get(header::IF_MATCH) else {
        return Ok(());
    };
    let value = raw
        .to_str()
        .map_err(|_| ScimError::invalid_value("If-Match header is not valid text"))?;

    let current = normalize(current_version);
    for candidate in value.split(',') {
        let candidate = candidate.trim();
        if candidate == "*" || normalize(candidate) == current {
            return Ok(());
        }
    }
    Err(ScimError::precondition_failed(
        "resource has been modified since the version in If-Match",
    ))
}

/// Builds a `200 OK` SCIM resource response carrying the resource's ETag
/// header and the `application/scim+json` content type. Every single-
/// resource read/update response goes through here so the ETag a client
/// needs for its next conditional write is always present.
pub fn resource_response<T: Serialize>(body: &T, version: &str) -> Response {
    let mut resp = Json(body).into_response();
    if let Ok(v) = HeaderValue::from_str(version) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/scim+json"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdrs(if_match: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = if_match {
            h.insert(
                header::IF_MATCH,
                HeaderValue::from_str(v).expect("test If-Match value must be a valid header value"),
            );
        }
        h
    }

    #[test]
    fn absent_if_match_passes() {
        assert!(check_if_match(&hdrs(None), "W/\"42\"").is_ok());
    }

    #[test]
    fn matching_weak_etag_passes() {
        assert!(check_if_match(&hdrs(Some("W/\"42\"")), "W/\"42\"").is_ok());
    }

    #[test]
    fn strong_form_of_weak_etag_passes() {
        // Client dropped the `W/` prefix; the opaque tag still matches.
        assert!(check_if_match(&hdrs(Some("\"42\"")), "W/\"42\"").is_ok());
    }

    #[test]
    fn wildcard_passes() {
        assert!(check_if_match(&hdrs(Some("*")), "W/\"42\"").is_ok());
    }

    #[test]
    fn stale_etag_is_precondition_failed() {
        let err = check_if_match(&hdrs(Some("W/\"41\"")), "W/\"42\"")
            .expect_err("stale validator must fail");
        assert_eq!(err.status, axum::http::StatusCode::PRECONDITION_FAILED);
    }

    #[test]
    fn one_matching_validator_in_a_list_passes() {
        assert!(check_if_match(&hdrs(Some("W/\"1\", W/\"42\"")), "W/\"42\"").is_ok());
    }
}
