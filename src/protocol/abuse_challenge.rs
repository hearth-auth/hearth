//! How a sign-in endpoint answers a challenge from the A-3 detector or the
//! A-16 challenge state, shared by the login form and the JSON endpoints.
//!
//! | CAPTCHA provider | Login page (UI) | API sign-in endpoint |
//! |---|---|---|
//! | Configured | the login page again, with the widget | `403` `HEARTH_ABUSE_CHALLENGE_REQUIRED` |
//! | Not configured | the generic sign-in failure page | `429` `HEARTH_RATE_LIMITED` + `Retry-After` |
//!
//! Every challenge is audited as `AbuseDetected`, at most once per guard,
//! client and username per window. No response names the guard that fired.

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::abuse::runtime::{AbuseGuards, Challenge, PreAuthVerdict};
use crate::audit::{AuditAction, AuditEngine, CreateAuditEvent};
use crate::core::RealmId;

/// Where a challenged sign-in arrived, for the audit metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Surface {
    /// The browser login page and its passkey endpoint.
    Ui,
    /// A JSON sign-in endpoint.
    Api,
}

impl Surface {
    /// The `surface` value written to the audit metadata.
    fn as_str(self) -> &'static str {
        match self {
            Self::Ui => "ui",
            Self::Api => "api",
        }
    }
}

/// One challenged sign-in attempt, as the endpoint saw it.
pub(crate) struct ChallengedAttempt<'a> {
    /// The realm the attempt targets; the audit event lands there.
    pub realm_id: &'a RealmId,
    /// The client address the guards counted.
    pub ip: Option<IpAddr>,
    /// The submitted username, when the endpoint has one.
    pub username: Option<&'a str>,
    /// Which endpoint family the attempt arrived on.
    pub surface: Surface,
}

/// Logs the challenge and writes its `AbuseDetected` event, unless one was
/// written for the same guard, client and username inside the window.
pub(crate) fn audit_challenge(
    guards: &AbuseGuards,
    audit: &dyn AuditEngine,
    attempt: &ChallengedAttempt<'_>,
    challenge: &Challenge,
) {
    tracing::warn!(
        guard = challenge.guard.as_str(),
        reason = challenge.reason,
        surface = attempt.surface.as_str(),
        "sign-in challenged by an abuse guard"
    );
    let Some(ip) = attempt.ip else {
        return;
    };
    if !guards.should_audit_challenge(challenge, ip, attempt.username) {
        return;
    }
    let mut metadata = serde_json::json!({
        "ip": ip.to_string(),
        "guard": challenge.guard.as_str(),
        "surface": attempt.surface.as_str(),
    });
    if let Some(username) = attempt.username {
        metadata["username"] = serde_json::Value::from(bounded_username(username));
    }
    crate::protocol::audit_log::record(
        audit,
        &CreateAuditEvent {
            realm_id: attempt.realm_id.clone(),
            actor: "anonymous".to_string(),
            action: AuditAction::AbuseDetected,
            resource_type: "credential".to_string(),
            resource_id: "unknown".to_string(),
            metadata: Some(metadata),
        },
    );
}

/// The JSON answer to a challenge the caller did not solve: `403` with the
/// challenge code when a provider is configured, otherwise a `429` lockout
/// until the guard's window ends.
pub(crate) fn api_challenge_response(guards: &AbuseGuards, challenge: &Challenge) -> Response {
    if guards.captcha_provider().is_some() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "challenge required",
                "error_code": crate::protocol::error_codes::ABUSE_CHALLENGE_REQUIRED,
            })),
        )
            .into_response();
    }
    lockout_response(challenge)
}

/// `429` with `HEARTH_RATE_LIMITED` and the whole seconds left in the
/// guard's window, at least `1`. The body is the per-IP login limiter's, so
/// it does not say which limit fired.
fn lockout_response(challenge: &Challenge) -> Response {
    let secs = challenge
        .retry_after
        .as_secs()
        .saturating_add(u64::from(challenge.retry_after.subsec_nanos() > 0))
        .max(1);
    crate::protocol::http::make_ip_rate_limit_response(u32::try_from(secs).unwrap_or(u32::MAX))
}

/// Verifies `token` on the blocking pool. A worker that panics counts as
/// an unsolved challenge.
pub(crate) async fn verify_captcha(
    guards: &Arc<AbuseGuards>,
    ip: Option<IpAddr>,
    token: &str,
) -> bool {
    if guards.captcha_provider().is_none() || token.is_empty() {
        return false;
    }
    let guards = Arc::clone(guards);
    let token = token.to_string();
    tokio::task::spawn_blocking(move || guards.verify_captcha(ip, &token))
        .await
        .unwrap_or(false)
}

/// Runs a JSON sign-in endpoint's guard verdict to its end: `Ok(())` lets
/// the attempt continue, `Err` is the response to return.
///
/// A challenge is audited, then solved by a verified `captcha_token`, or
/// answered with [`api_challenge_response`]. A refusal (`Deny`) is answered
/// like an unsolved challenge, so it reveals nothing more.
pub(crate) async fn gate_api_sign_in(
    guards: &Arc<AbuseGuards>,
    audit: &dyn AuditEngine,
    attempt: &ChallengedAttempt<'_>,
    verdict: PreAuthVerdict,
    captcha_token: Option<&str>,
) -> Result<(), Response> {
    let challenge = match verdict {
        PreAuthVerdict::Allow => return Ok(()),
        PreAuthVerdict::Deny { reason } => {
            tracing::warn!(guard = reason, "sign-in refused by an abuse guard");
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": "forbidden" })),
            )
                .into_response());
        }
        PreAuthVerdict::Challenge(challenge) => challenge,
    };
    audit_challenge(guards, audit, attempt, &challenge);
    if verify_captcha(guards, attempt.ip, captcha_token.unwrap_or_default()).await {
        return Ok(());
    }
    Err(api_challenge_response(guards, &challenge))
}

/// The longest username written to the audit metadata, in bytes: the
/// longest valid email address (RFC 5321).
const MAX_AUDITED_USERNAME: usize = 254;

/// `username` cut to [`MAX_AUDITED_USERNAME`] bytes on a character boundary.
/// The value is caller-supplied, so its size in the audit log is bounded.
fn bounded_username(username: &str) -> &str {
    if username.len() <= MAX_AUDITED_USERNAME {
        return username;
    }
    let mut end = MAX_AUDITED_USERNAME;
    while !username.is_char_boundary(end) {
        end -= 1;
    }
    &username[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_normal_username_is_audited_whole() {
        assert_eq!(bounded_username("a@example.com"), "a@example.com");
    }

    #[test]
    fn an_oversized_username_is_cut_on_a_character_boundary() {
        let long = "é".repeat(200);
        let cut = bounded_username(&long);
        assert!(cut.len() <= MAX_AUDITED_USERNAME, "{} bytes", cut.len());
        assert!(long.starts_with(cut));
        assert_eq!(cut.chars().count(), MAX_AUDITED_USERNAME / 2);
    }
}
