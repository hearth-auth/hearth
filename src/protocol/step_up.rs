//! Shared wire shape for the step-up proof that credential-enrolment requests
//! carry (audit 2026-08-28 §4.18#2).
//!
//! Both enrolment surfaces — the browser account page and the REST
//! `/webauthn/register/begin` endpoint — accept the same three optional
//! fields, so one guard and one contract cover both:
//!
//! ```text
//! { "password": "…" }
//! { "totp_code": "123456" }
//! { "assertion": { "credential_id": "…", "client_data_json": "…",
//!                  "authenticator_data": "…", "signature": "…",
//!                  "user_handle": "…" } }
//! ```
//!
//! Assertion fields are base64url, no padding. A field that does not decode is
//! kept as empty bytes so the ceremony refuses it — a malformed proof is a
//! failed proof, never an absent one.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;

use crate::core::FormSecret;
use crate::identity::{CleartextPassword, StepUpAssertion, StepUpProof};

/// The step-up proof fields of an enrolment request body.
///
/// Deliberately implements neither `Debug` nor `Serialize`: `password` holds a
/// live credential.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpProofBody {
    /// The account's current password.
    #[serde(default)]
    pub password: Option<FormSecret>,
    /// A current code from the account's enrolled TOTP factor.
    #[serde(default)]
    pub totp_code: Option<String>,
    /// An assertion from an already-enrolled passkey.
    #[serde(default)]
    pub assertion: Option<StepUpAssertionBody>,
}

/// Base64url-encoded assertion offered as a step-up proof.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpAssertionBody {
    /// Credential ID the assertion was produced with.
    pub credential_id: String,
    /// `clientDataJSON` from the authenticator.
    pub client_data_json: String,
    /// Authenticator data bytes.
    pub authenticator_data: String,
    /// Signature bytes.
    pub signature: String,
    /// User handle, for discoverable credentials.
    #[serde(default)]
    pub user_handle: Option<String>,
}

fn decode(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value).unwrap_or_default()
}

impl StepUpProofBody {
    /// Converts the body into the proof the identity layer verifies.
    ///
    /// `origin` is the server-pinned expected origin for an assertion proof —
    /// never a client-supplied value (HEA-2025). Precedence is password, then
    /// TOTP code, then assertion. A blank field counts as absent.
    #[must_use]
    pub fn into_proof(self, origin: &str) -> StepUpProof {
        if let Some(password) = self.password.filter(|p| !p.trim().is_empty()) {
            return StepUpProof::Password(CleartextPassword::new(password.as_bytes().to_vec()));
        }
        if let Some(code) = self.totp_code.filter(|c| !c.trim().is_empty()) {
            return StepUpProof::TotpCode(code.trim().to_string());
        }
        if let Some(assertion) = self.assertion {
            return StepUpProof::WebAuthnAssertion(Box::new(StepUpAssertion {
                credential_id: decode(&assertion.credential_id),
                client_data_json: decode(&assertion.client_data_json),
                authenticator_data: decode(&assertion.authenticator_data),
                signature: decode(&assertion.signature),
                user_handle: assertion.user_handle.as_deref().map(decode),
                origin: origin.to_string(),
            }));
        }
        StepUpProof::None
    }
}

/// The step-up password is wiped on drop (GA audit L20). The body implements
/// no `Debug`, so there is nothing to redact.
#[cfg(test)]
mod secret_field_tests {
    use super::*;

    #[test]
    fn step_up_proof_password_is_zeroized() {
        let body: StepUpProofBody =
            serde_json::from_str(r#"{"password":"CANARY-pw"}"#).expect("json parses");
        crate::core::secrets::assert_zeroize_on_drop(&body.password);
        assert_eq!(
            body.password.as_ref().map(crate::core::FormSecret::expose),
            Some("CANARY-pw")
        );
    }
}

/// The `error` every JSON step-up surface answers a locked account with
/// (GA sweep 4). The body's `error_code` is
/// [`crate::protocol::error_codes::RATE_LIMITED`], as on every other
/// rate-limit or lockout refusal.
pub const STEP_UP_LOCKED_ERROR: &str = "too_many_attempts";

/// Sets `Retry-After` on `response`: `retry_after` in whole seconds, rounded
/// up, at least one.
pub(crate) fn set_retry_after(
    response: &mut axum::response::Response,
    retry_after: std::time::Duration,
) {
    let secs = retry_after
        .as_secs()
        .saturating_add(u64::from(retry_after.subsec_nanos() > 0))
        .max(1);
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from(secs),
    );
}

/// The one response every JSON step-up surface answers a locked account
/// with: `429 Too Many Requests`, `Retry-After`, and
/// `{"error": "too_many_attempts", "error_code": "HEARTH_RATE_LIMITED"}`.
///
/// A locked account's proof is never checked, so the answer must not read as
/// "wrong proof" (`403 step_up_required`): that tells the client to try
/// another credential, and every try is refused until the window passes.
pub(crate) fn locked_json_response(retry_after: std::time::Duration) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let mut response = (
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({
            "error": STEP_UP_LOCKED_ERROR,
            "error_description":
                "too many failed attempts; the account is locked — retry after the \
                 Retry-After interval",
            "error_code": crate::protocol::error_codes::RATE_LIMITED,
        })),
    )
        .into_response();
    set_retry_after(&mut response, retry_after);
    response
}

#[cfg(test)]
mod locked_response_tests {
    use super::*;

    #[test]
    fn retry_after_rounds_up_to_whole_seconds_and_is_never_zero() {
        for (given, expected) in [
            (std::time::Duration::from_millis(1), "1"),
            (std::time::Duration::ZERO, "1"),
            (std::time::Duration::from_millis(1_500), "2"),
            (std::time::Duration::from_secs(300), "300"),
        ] {
            let response = locked_json_response(given);
            assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                response
                    .headers()
                    .get(axum::http::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
                Some(expected),
                "from {given:?}"
            );
        }
    }
}
