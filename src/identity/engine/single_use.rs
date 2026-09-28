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
}
