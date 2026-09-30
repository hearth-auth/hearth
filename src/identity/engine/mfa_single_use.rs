//! Cluster-wide single use and guess budgets for TOTP and recovery codes (G6).
//!
//! The MFA state record (`mfa:totp:{user}`) holds the TOTP secret, the last
//! accepted step and the recovery-code hashes, and every verification writes
//! the whole record back. In cluster mode reads are local, so a record-borne
//! decision is only as good as the freshest read: a node that had not applied
//! another node's verification accepted the same TOTP code again (about 90 s
//! of window), spent a recovery code a second time, and — writing its stale
//! copy back — even restored a recovery code already spent. The node-local
//! failure tracker also gave every node its own five guesses.
//!
//! Each decision is therefore one replicated `put_if_absent` (see
//! `single_use`), made before the record is written:
//!
//! * a TOTP code claims `consumed:totp:{user}:{step}`, dated to the end of the
//!   step's acceptance window;
//! * a recovery code claims `consumed:recovery:{user}:{digest of its stored
//!   hash}`, never swept — a stale record write can bring the hash back, and
//!   the marker is what keeps the code spent (at most one marker per code a
//!   user ever spends);
//! * every guess — TOTP, activation or recovery code — first claims a slot
//!   of a per-user budget of [`EmbeddedIdentityEngine::MFA_MAX_ATTEMPTS`]
//!   guesses per [`EmbeddedIdentityEngine::MFA_LOCKOUT_MICROS`] window,
//!   shared by every node. A correct guess returns the window's slots.

use crate::core::{RealmId, Timestamp, UserId};
use crate::identity::error::IdentityError;
use crate::identity::keys;

use super::EmbeddedIdentityEngine;

impl EmbeddedIdentityEngine {
    /// Length of one cluster-wide MFA guess-budget window, in seconds.
    const MFA_GUESS_WINDOW_SECS: i64 = Self::MFA_LOCKOUT_MICROS / 1_000_000;

    /// The slot prefix of `user_id`'s guess budget for the current window,
    /// and when that window ends.
    pub(super) fn mfa_guess_window(&self, user_id: &UserId) -> (Vec<u8>, Timestamp) {
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        let window = now_secs.div_euclid(Self::MFA_GUESS_WINDOW_SECS);
        let prefix =
            keys::encode_guess_slot_prefix("mfa", &format!("{}:{window}", user_id.as_uuid()));
        let ends_at = (window + 1).saturating_mul(Self::MFA_GUESS_WINDOW_SECS);
        (
            prefix,
            Timestamp::from_micros(ends_at.saturating_mul(1_000_000)),
        )
    }

    /// Spends one guess of `user_id`'s cluster-wide MFA budget, or refuses
    /// with [`IdentityError::RateLimited`] when the window's budget is spent.
    ///
    /// Call after the node-local tracker check (which costs no write) and
    /// before the guess is checked.
    pub(super) fn claim_mfa_guess(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        let (prefix, ends_at) = self.mfa_guess_window(user_id);
        match self.claim_guess_slot(realm_id, &prefix, Self::MFA_MAX_ATTEMPTS, ends_at)? {
            Some(_) => Ok(()),
            None => Err(IdentityError::RateLimited),
        }
    }

    /// Returns the current window's MFA guesses after a correct guess.
    pub(super) fn release_mfa_guesses(&self, realm_id: &RealmId, user_id: &UserId) {
        let (prefix, _) = self.mfa_guess_window(user_id);
        self.release_guess_slots(realm_id, &prefix);
    }

    /// Claims the single use of `user_id`'s TOTP code for `step`. `false`
    /// means another verification — on any node — already accepted it.
    pub(super) fn claim_totp_step(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        step: u64,
    ) -> Result<bool, IdentityError> {
        let ends_at = i64::try_from(crate::identity::totp::step_acceptance_ends_at(step))
            .unwrap_or(i64::MAX / 1_000_000);
        self.claim_single_use(
            realm_id,
            &keys::encode_consumed_totp_step(user_id, step),
            Timestamp::from_micros(ends_at.saturating_mul(1_000_000)),
        )
    }

    /// Claims the single use of the recovery code whose stored hash is
    /// `stored_hash`. `false` means it was already spent, on any node — even
    /// if a stale write has put its hash back into the MFA record.
    pub(super) fn claim_recovery_code(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        stored_hash: &str,
    ) -> Result<bool, IdentityError> {
        let digest = Self::sha256_hex(stored_hash.as_bytes());
        // Never swept: a recovery code does not expire.
        self.claim_single_use(
            realm_id,
            &keys::encode_consumed_recovery_code(user_id, &digest),
            Timestamp::from_micros(i64::MAX),
        )
    }
}
