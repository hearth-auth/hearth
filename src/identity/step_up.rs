//! Step-up verification for credential enrolment (audit 2026-08-28 §4.18#2)
//! and for privileged operator actions ([`verify_operator_step_up`]).
//!
//! A session, or an access token, is one factor. Enrolling a new passkey from
//! that alone turns a stolen session into a permanent credential the account
//! owner never sees and cannot easily notice. Every enrolment surface therefore
//! calls [`verify_step_up`] before it mints a ceremony challenge.
//!
//! Three proofs are accepted, and each one proves possession of a credential
//! the account already holds:
//!
//! * the account password,
//! * a current TOTP code,
//! * an assertion from an already-enrolled passkey.
//!
//! An account that holds none of the three has nothing to prove. For that case
//! [`verify_step_up`] passes: demanding a credential the user does not have
//! would lock the account out of enrolment for good. The probe fails closed —
//! any storage error is read as "the credential exists", so the enrolment is
//! refused rather than waved through.

use std::sync::Arc;

use crate::core::{RealmId, UserId};
use crate::identity::webauthn::CompleteAuthenticationParams;
use crate::identity::{CleartextPassword, IdentityEngine, IdentityError, KdfGateError};

/// An assertion from an already-enrolled passkey, offered as a step-up proof.
#[derive(Debug)]
pub struct StepUpAssertion {
    /// Raw credential ID the assertion was produced with.
    pub credential_id: Vec<u8>,
    /// Raw `clientDataJSON` from the authenticator.
    pub client_data_json: Vec<u8>,
    /// Raw authenticator data bytes.
    pub authenticator_data: Vec<u8>,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
    /// Optional user handle, for discoverable credentials.
    pub user_handle: Option<Vec<u8>>,
    /// Server-pinned expected origin for the ceremony.
    pub origin: String,
}

/// Proof that the caller holds a credential the account already has.
#[non_exhaustive]
pub enum StepUpProof {
    /// The account's current password.
    Password(CleartextPassword),
    /// A current code from the account's enrolled TOTP factor.
    TotpCode(String),
    /// An assertion from an already-enrolled passkey.
    WebAuthnAssertion(Box<StepUpAssertion>),
    /// No proof was supplied.
    None,
}

impl std::fmt::Debug for StepUpProof {
    /// Names the variant only. A step-up proof carries a live credential, so
    /// the value MUST NOT reach a log or an error string.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Password(_) => "Password",
            Self::TotpCode(_) => "TotpCode",
            Self::WebAuthnAssertion(_) => "WebAuthnAssertion",
            Self::None => "None",
        };
        f.write_str(name)
    }
}

/// Why a step-up was not granted.
#[derive(Debug)]
#[non_exhaustive]
pub enum StepUpError {
    /// No proof was supplied, or the supplied proof did not verify.
    Required,
    /// The KDF admission gate shed the password verification. The caller
    /// SHOULD answer `503` with the carried `Retry-After` hint.
    Overloaded {
        /// Suggested `Retry-After` duration for the client.
        retry_after: std::time::Duration,
    },
    /// An operator step-up needs a second factor and the account holds none
    /// (no TOTP factor, no passkey). Enrolling one is the only way forward.
    SecondFactorNotEnrolled,
    /// The account's login lockout, or its TOTP guess budget, is spent: too
    /// many wrong passwords or codes. No proof is checked until the window
    /// passes, however correct. Every caller answers `429 Too Many Requests`
    /// with the carried `Retry-After` hint (GA sweep 4).
    Locked {
        /// How long until the lockout that refused the proof ends (at least
        /// one second).
        retry_after: std::time::Duration,
    },
}

impl std::fmt::Display for StepUpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Required => f.write_str("step-up authentication required"),
            Self::Overloaded { .. } => f.write_str("step-up verification shed — overloaded"),
            Self::SecondFactorNotEnrolled => {
                f.write_str("step-up needs a second factor and the account holds none")
            }
            Self::Locked { .. } => f.write_str("step-up refused — too many failed attempts"),
        }
    }
}

impl std::error::Error for StepUpError {}

/// The smallest `Retry-After` a locked step-up answers with.
const MIN_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(1);

/// The `Retry-After` for a password refused by the account's login lockout:
/// the lockout's remaining time, at least one second (the lockout may have
/// ended between the refusal and this read).
pub fn password_retry_after(
    identity: &dyn IdentityEngine,
    realm_id: &RealmId,
    user_id: &UserId,
) -> std::time::Duration {
    identity
        .login_lockout_remaining(realm_id, user_id)
        .map_or(MIN_RETRY_AFTER, |d| d.max(MIN_RETRY_AFTER))
}

/// The `Retry-After` for a TOTP code refused because the account's TOTP
/// guess budget is spent, at least one second.
pub fn totp_retry_after(
    identity: &dyn IdentityEngine,
    realm_id: &RealmId,
    user_id: &UserId,
) -> std::time::Duration {
    identity
        .mfa_lockout_remaining(realm_id, user_id)
        .max(MIN_RETRY_AFTER)
}

/// Verifies a step-up proof before a credential enrolment.
///
/// Fails closed: an absent proof, a wrong proof, and every underlying error
/// all resolve to [`StepUpError::Required`]. The only pass without a proof is
/// an account that holds no step-up credential at all.
///
/// # Errors
///
/// - [`StepUpError::Required`] when the step-up was not proven.
/// - [`StepUpError::Locked`] when the account's login lockout (password) or
///   TOTP guess budget (code) is spent. Wrong proofs spend the same budgets a
///   login does, so a stolen session cannot guess faster here than at the
///   login form.
/// - [`StepUpError::Overloaded`] when the KDF gate shed a password verify.
pub async fn verify_step_up(
    identity: &Arc<dyn IdentityEngine>,
    realm_id: &RealmId,
    user_id: &UserId,
    proof: StepUpProof,
) -> Result<(), StepUpError> {
    match proof {
        StepUpProof::Password(password) => {
            // Argon2id — route through the KDF admission gate rather than an
            // ungated `spawn_blocking` (HEA-1891 / F3), and through the same
            // gate the account's login uses: a system-realm operator's verify
            // draws from the admin-reserved pool, so a tenant-login flood
            // that fills the shared gate cannot shed it (HEA-1892 / F2).
            //
            // `verify_password` applies the account's login lockout itself:
            // a wrong password here counts as a failed login, and a locked
            // account is refused before its credential is checked.
            let kdf_gate = crate::identity::gate_for_realm(realm_id);
            let engine = Arc::clone(identity);
            let realm = realm_id.clone();
            let user = user_id.clone();
            match kdf_gate
                .run(move || engine.verify_password(&realm, &user, &password))
                .await
            {
                Ok(Ok(true)) => Ok(()),
                Ok(Err(IdentityError::RateLimited)) => Err(StepUpError::Locked {
                    retry_after: password_retry_after(identity.as_ref(), realm_id, user_id),
                }),
                Ok(Ok(false) | Err(_)) => Err(StepUpError::Required),
                Err(KdfGateError::Overloaded { retry_after }) => {
                    Err(StepUpError::Overloaded { retry_after })
                }
                Err(KdfGateError::Join(e)) => {
                    tracing::warn!(error = %e, "step-up password verify task failed");
                    Err(StepUpError::Required)
                }
            }
        }
        // `verify_totp` spends the account's TOTP guess budget — the one its
        // login's second factor draws from — and refuses once it is spent.
        StepUpProof::TotpCode(code) => match identity.verify_totp(realm_id, user_id, &code) {
            Ok(()) => Ok(()),
            Err(IdentityError::RateLimited) => Err(StepUpError::Locked {
                retry_after: totp_retry_after(identity.as_ref(), realm_id, user_id),
            }),
            Err(_) => Err(StepUpError::Required),
        },
        StepUpProof::WebAuthnAssertion(assertion) => {
            let params = CompleteAuthenticationParams {
                credential_id: &assertion.credential_id,
                client_data_json: &assertion.client_data_json,
                authenticator_data: &assertion.authenticator_data,
                signature: &assertion.signature,
                user_handle: assertion.user_handle.as_deref(),
                origin: &assertion.origin,
            };
            match identity.complete_webauthn_authentication(realm_id, &params) {
                // The assertion must belong to the enrolling account — a valid
                // assertion for a different user is not a step-up for this one.
                Ok(result) if result.user_id() == user_id => Ok(()),
                _ => Err(StepUpError::Required),
            }
        }
        StepUpProof::None => {
            if has_step_up_credential(identity.as_ref(), realm_id, user_id) {
                Err(StepUpError::Required)
            } else {
                Ok(())
            }
        }
    }
}

/// The second factor offered with an operator step-up.
#[non_exhaustive]
pub enum SecondFactorProof {
    /// A current code from the account's enrolled TOTP factor.
    TotpCode(String),
    /// An assertion from an enrolled passkey. It counts only when the
    /// authenticator proved user verification (the UV flag).
    WebAuthnAssertion(Box<StepUpAssertion>),
    /// No second factor was offered.
    None,
}

impl std::fmt::Debug for SecondFactorProof {
    /// Names the variant only: the value is a live credential.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TotpCode(_) => "TotpCode",
            Self::WebAuthnAssertion(_) => "WebAuthnAssertion",
            Self::None => "None",
        })
    }
}

/// Verifies a fresh two-factor step-up before a privileged operator action:
/// minting a system-realm API token in the admin console (GA audit 3 DOC-2).
///
/// Stricter than [`verify_step_up`], which accepts any one proof:
///
/// * the account's password is required whenever the account has one;
/// * a second factor the account holds is always required — a current TOTP
///   code, or a passkey assertion that proved user verification (a touch
///   alone is possession, one factor);
/// * an account that holds no second factor is refused with
///   [`StepUpError::SecondFactorNotEnrolled`], never waved through.
///
/// The password is checked first, so a wrong password does not spend a TOTP
/// code. Every probe fails closed: an unreadable credential counts as held,
/// so its proof is demanded.
///
/// # Errors
///
/// - [`StepUpError::SecondFactorNotEnrolled`] — no TOTP factor and no passkey.
/// - [`StepUpError::Required`] — a required proof is missing or does not
///   verify.
/// - [`StepUpError::Locked`] — the account's login lockout or TOTP guess
///   budget is spent (see [`verify_step_up`]).
/// - [`StepUpError::Overloaded`] — the KDF gate shed the password verify.
pub async fn verify_operator_step_up(
    identity: &Arc<dyn IdentityEngine>,
    realm_id: &RealmId,
    user_id: &UserId,
    password: Option<CleartextPassword>,
    second: SecondFactorProof,
) -> Result<(), StepUpError> {
    let has_password = identity
        .has_password_credential(realm_id, user_id)
        .unwrap_or(true);
    let has_totp = identity.mfa_enabled(realm_id, user_id).unwrap_or(true);
    let has_passkey = identity
        .list_webauthn_credentials(realm_id, user_id)
        .map_or(true, |creds| !creds.is_empty());
    if !has_totp && !has_passkey {
        return Err(StepUpError::SecondFactorNotEnrolled);
    }
    if has_password {
        let Some(password) = password else {
            return Err(StepUpError::Required);
        };
        verify_step_up(identity, realm_id, user_id, StepUpProof::Password(password)).await?;
    }
    match second {
        SecondFactorProof::TotpCode(code) if has_totp => {
            verify_step_up(identity, realm_id, user_id, StepUpProof::TotpCode(code)).await
        }
        SecondFactorProof::WebAuthnAssertion(assertion) if has_passkey => {
            let params = CompleteAuthenticationParams {
                credential_id: &assertion.credential_id,
                client_data_json: &assertion.client_data_json,
                authenticator_data: &assertion.authenticator_data,
                signature: &assertion.signature,
                user_handle: assertion.user_handle.as_deref(),
                origin: &assertion.origin,
            };
            match identity.complete_webauthn_authentication(realm_id, &params) {
                Ok(result) if result.user_id() == user_id && result.user_verified() => Ok(()),
                _ => Err(StepUpError::Required),
            }
        }
        _ => Err(StepUpError::Required),
    }
}

/// Returns whether the account holds any credential that a step-up can be
/// proven with.
///
/// Fails closed on every read error: an unreadable probe counts as "the
/// credential exists", so an unproven enrolment is refused.
#[must_use]
pub fn has_step_up_credential(
    identity: &dyn IdentityEngine,
    realm_id: &RealmId,
    user_id: &UserId,
) -> bool {
    let has_password = identity
        .has_password_credential(realm_id, user_id)
        .unwrap_or(true);
    let has_totp = identity.mfa_enabled(realm_id, user_id).unwrap_or(true);
    let has_passkey = identity
        .list_webauthn_credentials(realm_id, user_id)
        .map_or(true, |creds| !creds.is_empty());
    has_password || has_totp || has_passkey
}
