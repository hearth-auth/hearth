//! Monotonic grant-family revocation (G6).
//!
//! A grant family's `revoked` flag lives in the same row a refresh rotation
//! rewrites in full. The per-family lock serializes a revocation with a
//! rotation on one node, but in cluster mode reads are local: a rotation that
//! read the row before another node revoked the family, and wrote after
//! leadership moved to its own node, wrote `revoked = false` back — the family
//! stayed live after consent was withdrawn.
//!
//! Revocation is therefore recorded twice, in two writes a rotation never
//! makes:
//!
//! 1. a write-once tombstone (`oauth:family-revoked:{fid}`) that every family
//!    reader consults, so a stale write-back of the row cannot un-revoke it;
//! 2. a claim on the family's current refresh token (`consumed:refresh:`,
//!    the marker a rotation claims before it persists). A rotation that read
//!    the family before the revocation and has not claimed yet loses that
//!    replicated `put_if_absent` and is refused, so it cannot mint a pair
//!    after the revocation either.

use crate::core::RealmId;
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::oidc::StoredGrantFamily;

use super::EmbeddedIdentityEngine;

impl EmbeddedIdentityEngine {
    /// Records that `family` is revoked, in writes no rotation makes.
    ///
    /// Call before writing the row with `revoked = true` (the row flag stays
    /// for readers of the row alone, such as the admin views). Idempotent.
    pub(super) fn mark_grant_family_revoked(
        &self,
        realm_id: &RealmId,
        family: &StoredGrantFamily,
    ) -> Result<(), IdentityError> {
        self.storage
            .put_if_absent(
                realm_id,
                &keys::encode_grant_family_revoked(&family.family_id),
                &[],
            )
            .map_err(Self::storage_err)?;
        // Spend the family's current refresh token so an in-flight rotation
        // that already passed its hash check loses its claim. Losing this
        // claim ourselves only means that token was already rotated; the
        // tombstone above is what keeps the family dead either way.
        self.claim_single_use(
            realm_id,
            &keys::encode_consumed_refresh(&family.current_refresh_hash),
            family.expires_at,
        )?;
        Ok(())
    }

    /// Whether `family` is revoked: its row says so, or its tombstone exists.
    ///
    /// Every decision that a family is live goes through here, never through
    /// `family.revoked` alone.
    pub(super) fn grant_family_is_revoked(
        &self,
        realm_id: &RealmId,
        family: &StoredGrantFamily,
    ) -> Result<bool, IdentityError> {
        if family.revoked {
            return Ok(true);
        }
        Ok(self
            .storage
            .get(
                realm_id,
                &keys::encode_grant_family_revoked(&family.family_id),
            )
            .map_err(Self::storage_err)?
            .is_some())
    }
}
