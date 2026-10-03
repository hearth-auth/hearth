//! Cluster-wide single-use claims (G4).
//!
//! Every redeem-once artifact Hearth issues — a PAR `request_uri`, an
//! authorization code, a device code, a magic link, a password-reset link, an
//! email-verification link, a refresh token — is spent by claiming a marker
//! under the `consumed:` key space with one `put_if_absent`.
//!
//! In cluster mode that call is a `PutIfAbsent` Raft command whose presence
//! check the state machine evaluates at apply time, so exactly one claim wins
//! across every node. A per-node advisory lock around a read and a later write
//! cannot give that: reads are local, so a redemption that read the artifact
//! before another node spent it can write after leadership moves to its own
//! node. The advisory locks stay, but only so same-node racers queue instead
//! of each proposing a Raft write.

use crate::core::{RealmId, Timestamp};
use crate::identity::error::IdentityError;

use super::EmbeddedIdentityEngine;
use super::CLOCK_SKEW_SECS;

/// How long a single-use marker outlives the artifact it guards.
///
/// The marker is swept on the sweeping node's clock while the artifact's own
/// expiry is checked on the redeeming node's clock. Without a margin, a node
/// whose clock runs behind the sweeper's could still see the artifact as live
/// after its marker was reclaimed, and redeem it again. The engine's clock
/// skew tolerance bounds that difference.
pub(super) const CONSUMED_MARKER_GRACE_SECS: i64 = CLOCK_SKEW_SECS;

impl EmbeddedIdentityEngine {
    /// Claims the single use of a redeemable artifact across the whole
    /// deployment.
    ///
    /// Returns `true` for exactly one caller per `marker_key`, on any node,
    /// and `false` for every other. The marker is dated
    /// `artifact_expires_at` + [`CONSUMED_MARKER_GRACE_SECS`]; the periodic
    /// cleanup sweep reclaims it after that, when the artifact's own expiry
    /// check refuses it anyway.
    pub(super) fn claim_single_use(
        &self,
        realm_id: &RealmId,
        marker_key: &[u8],
        artifact_expires_at: Timestamp,
    ) -> Result<bool, IdentityError> {
        let marker_expires_at =
            artifact_expires_at.as_micros() / 1_000_000 + CONSUMED_MARKER_GRACE_SECS;
        self.storage
            .put_if_absent(realm_id, marker_key, &marker_expires_at.to_le_bytes())
            .map_err(Self::storage_err)
    }

    /// Claims one guess from a cluster-wide budget of `max` guesses (G6).
    ///
    /// The budget is `max` slots under `slot_prefix`
    /// ([`keys::encode_guess_slot_prefix`](crate::identity::keys::encode_guess_slot_prefix)).
    /// A guess claims the first free slot with one replicated
    /// `put_if_absent` BEFORE the guess is checked, so every node draws from
    /// the same budget: a counter kept in a record the verifier rewrites is
    /// reset by any node whose read of it is stale, which multiplied the
    /// budget by the number of nodes.
    ///
    /// Slots this node already sees taken are skipped without a write; a
    /// stale read can only show a taken slot as free, and that slot's claim
    /// then fails and the next is tried. Returns the claimed slot (1-based),
    /// or `None` when all `max` are spent. Each slot is dated `expires_at`
    /// and reclaimed by the `consumed:` sweep, so the budget is bounded and
    /// needs no other cleanup.
    pub(super) fn claim_guess_slot(
        &self,
        realm_id: &RealmId,
        slot_prefix: &[u8],
        max: u32,
        expires_at: Timestamp,
    ) -> Result<Option<u32>, IdentityError> {
        for slot in 1..=max {
            let mut key = slot_prefix.to_vec();
            key.extend_from_slice(slot.to_string().as_bytes());
            if self
                .storage
                .get(realm_id, &key)
                .map_err(Self::storage_err)?
                .is_some()
            {
                continue;
            }
            if self.claim_single_use(realm_id, &key, expires_at)? {
                return Ok(Some(slot));
            }
        }
        Ok(None)
    }

    /// Returns every guess under `slot_prefix` to the budget — a correct
    /// guess ends the run of failures it counts, as the node-local tracker's
    /// reset does. Best-effort: a slot this node does not see yet stays
    /// claimed until the sweep reclaims it, which only makes the budget
    /// stricter.
    pub(super) fn release_guess_slots(&self, realm_id: &RealmId, slot_prefix: &[u8]) {
        let end = crate::identity::keys::prefix_end(slot_prefix);
        let released = self
            .storage
            .scan(realm_id, slot_prefix, &end)
            .and_then(|slots| {
                slots
                    .iter()
                    .try_for_each(|slot| self.storage.delete(realm_id, &slot.key))
            });
        if let Err(e) = released {
            tracing::warn!(error = %e, "guess slots not released after a correct guess");
        }
    }

    /// A pending OTP's expiry as a [`Timestamp`], for dating its marker.
    pub(super) fn otp_expiry(stored: &crate::identity::otp::StoredOtp) -> Timestamp {
        let secs = i64::try_from(stored.expiry_unix_ts).unwrap_or(i64::MAX / 1_000_000);
        Timestamp::from_micros(secs.saturating_mul(1_000_000))
    }

    /// Takes a redeem-once row: reads it, claims its single use under
    /// `marker_key` (dated by `expires_at`), then deletes it.
    ///
    /// For the "get, then delete" tickets and state bags. The delete cannot
    /// decide the single use across a cluster — deleting an absent key
    /// succeeds — so a take that read the row before another node took it was
    /// served too. `missing` is the error for an absent row, and for a row
    /// another caller already took. The caller still checks expiry.
    pub(super) fn take_single_use_row<T: serde::de::DeserializeOwned>(
        &self,
        realm_id: &RealmId,
        row_key: &[u8],
        marker_key: &[u8],
        missing: fn() -> IdentityError,
        expires_at: impl FnOnce(&T) -> Timestamp,
    ) -> Result<T, IdentityError> {
        let bytes = self
            .storage
            .get(realm_id, row_key)
            .map_err(Self::storage_err)?
            .ok_or_else(missing)?;
        let row: T = serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        if !self.claim_single_use(realm_id, marker_key, expires_at(&row))? {
            return Err(missing());
        }
        self.storage
            .delete(realm_id, row_key)
            .map_err(Self::storage_err)?;
        Ok(row)
    }
}
