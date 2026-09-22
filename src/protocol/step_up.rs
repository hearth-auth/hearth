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

use crate::identity::{CleartextPassword, StepUpAssertion, StepUpProof};

/// The step-up proof fields of an enrolment request body.
///
/// Deliberately implements neither `Debug` nor `Serialize`: `password` holds a
/// live credential.
#[derive(Default, Deserialize)]
pub struct StepUpProofBody {
    /// The account's current password.
    #[serde(default)]
    pub password: Option<String>,
    /// A current code from the account's enrolled TOTP factor.
    #[serde(default)]
    pub totp_code: Option<String>,
    /// An assertion from an already-enrolled passkey.
    #[serde(default)]
    pub assertion: Option<StepUpAssertionBody>,
}

/// Base64url-encoded assertion offered as a step-up proof.
#[derive(Debug, Deserialize)]
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
            return StepUpProof::Password(CleartextPassword::from_string(password));
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
