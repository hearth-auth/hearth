//! Retired signing-key records: which key ids each realm rotated away from.
//!
//! A backup archive carries the realm's active signing key and every retiring
//! key still inside its grace window. Restored into a realm that has since
//! rotated — above all a revoking rotation (grace 0), the remedy for a leaked
//! key — those keys would verify tokens again. So every rotation records, per
//! realm and per key family, the key it retires and every retiring key it
//! purges (`realm:retired:{uuid}:{family}:{kid}`, in the same atomic batch as
//! the rotation itself), a restore that displaces a live key records the key
//! it displaces, and every restore path refuses archived key material whose
//! kid is recorded. The records hold no key material and are never deleted,
//! not even with the realm: a realm deleted and restored from an old archive
//! must not get a revoked key back either.

use crate::core::RealmId;
use crate::identity::error::IdentityError;
use crate::identity::keys;

use super::EmbeddedIdentityEngine;

/// One of a realm's two signing-key families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KeyFamily {
    /// The Ed25519 key that signs access, refresh and (for EdDSA clients) ID
    /// tokens.
    Ed25519,
    /// The RSA key that signs RS256 ID tokens (task 26.55).
    IdTokenRs256,
}

impl KeyFamily {
    /// Storage key of the retired record for `kid`.
    fn retired_record(self, realm_id: &RealmId, kid: &str) -> Vec<u8> {
        match self {
            Self::Ed25519 => keys::encode_realm_retired_signing_kid(realm_id, kid),
            Self::IdTokenRs256 => keys::encode_realm_retired_id_token_rsa_kid(realm_id, kid),
        }
    }

    /// Scan prefix of the family's retiring-key rows for `realm_id`.
    fn retiring_prefix(self, realm_id: &RealmId) -> Vec<u8> {
        match self {
            Self::Ed25519 => keys::realm_retiring_key_scan_prefix(realm_id),
            Self::IdTokenRs256 => keys::realm_id_token_rsa_retiring_scan_prefix(realm_id),
        }
    }

    /// The kid a retiring-key row names.
    fn retiring_kid(self, row: &[u8]) -> Option<String> {
        match self {
            Self::Ed25519 => keys::parse_retiring_key_id(row),
            Self::IdTokenRs256 => keys::parse_id_token_rsa_retiring_key_id(row),
        }
    }

    /// The grace deadline a retiring-key row carries.
    fn retiring_deadline(self, row: &[u8]) -> Option<u64> {
        match self {
            Self::Ed25519 => keys::parse_retiring_key_deadline(row),
            Self::IdTokenRs256 => keys::parse_id_token_rsa_retiring_deadline(row),
        }
    }

    /// How a refusal names the key.
    fn describe(self) -> &'static str {
        match self {
            Self::Ed25519 => "signing key",
            Self::IdTokenRs256 => "RS256 ID-token signing key",
        }
    }
}

/// The retiring-key rows a rotation removes, with the kid each names.
pub(super) struct RetiringPurge {
    /// Storage keys to delete, under the system realm.
    pub(super) rows: Vec<Vec<u8>>,
    /// The kids of those rows, for the retired record.
    pub(super) kids: Vec<String>,
}

impl EmbeddedIdentityEngine {
    /// Batch entries recording every kid in `kids` as retired by `realm_id`,
    /// stamped `now_secs`. Written in the same batch as the change that
    /// retires them, so the record exists exactly when the change does.
    pub(super) fn retired_record_puts(
        realm_id: &RealmId,
        family: KeyFamily,
        kids: &[String],
        now_secs: u64,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let stamp = now_secs.to_string().into_bytes();
        kids.iter()
            .map(|kid| (family.retired_record(realm_id, kid), stamp.clone()))
            .collect()
    }

    /// The retiring-key rows of `family` a rotation removes: those whose grace
    /// window closed by `cutoff_secs`, or every one for `None` (a revoking
    /// rotation). An unparseable deadline counts as closed — such a row can
    /// never verify anything.
    pub(super) fn retiring_rows_to_purge(
        &self,
        realm_id: &RealmId,
        family: KeyFamily,
        cutoff_secs: Option<u64>,
    ) -> Result<RetiringPurge, IdentityError> {
        let sys_realm = keys::system_realm_id();
        let prefix = family.retiring_prefix(realm_id);
        let end = keys::prefix_end(&prefix);
        let mut purge = RetiringPurge {
            rows: Vec::new(),
            kids: Vec::new(),
        };
        for entry in self
            .storage
            .scan(&sys_realm, &prefix, &end)
            .map_err(Self::storage_err)?
        {
            if let Some(now_secs) = cutoff_secs {
                if family
                    .retiring_deadline(&entry.key)
                    .is_some_and(|deadline| deadline > now_secs)
                {
                    continue;
                }
            }
            if let Some(kid) = family.retiring_kid(&entry.key) {
                purge.kids.push(kid);
            }
            purge.rows.push(entry.key);
        }
        Ok(purge)
    }

    /// Whether `realm_id` still holds a retiring row of `family` for `kid`
    /// (any deadline).
    pub(super) fn retiring_key_is_live(
        &self,
        realm_id: &RealmId,
        family: KeyFamily,
        kid: &str,
    ) -> Result<bool, IdentityError> {
        let sys_realm = keys::system_realm_id();
        let prefix = family.retiring_prefix(realm_id);
        let end = keys::prefix_end(&prefix);
        Ok(self
            .storage
            .scan(&sys_realm, &prefix, &end)
            .map_err(Self::storage_err)?
            .iter()
            .any(|e| family.retiring_kid(&e.key).as_deref() == Some(kid)))
    }

    /// Whether a rotation (or a restore that displaced it) recorded `kid` as
    /// retired by `realm_id`.
    pub(super) fn key_is_recorded_retired(
        &self,
        realm_id: &RealmId,
        family: KeyFamily,
        kid: &str,
    ) -> Result<bool, IdentityError> {
        Ok(self
            .storage
            .get(
                &keys::system_realm_id(),
                &family.retired_record(realm_id, kid),
            )
            .map_err(Self::storage_err)?
            .is_some())
    }

    /// Refuses to install `kid` as the ACTIVE key of `family` in `realm_id`
    /// when the realm rotated away from it: a record names it, or it is one of
    /// the realm's retiring keys (still trusted for its window, but no longer
    /// the key the realm signs with).
    pub(super) fn refuse_rotated_away_active_key(
        &self,
        realm_id: &RealmId,
        family: KeyFamily,
        kid: &str,
    ) -> Result<(), IdentityError> {
        if self.key_is_recorded_retired(realm_id, family, kid)?
            || self.retiring_key_is_live(realm_id, family, kid)?
        {
            return Err(Self::rotated_away(family, kid));
        }
        Ok(())
    }

    /// Refuses to reinstate `kid` as a RETIRING key of `family` when the realm
    /// recorded it retired and no longer holds its retiring row: the row was
    /// purged — by a revoking rotation, the remedy for a leaked key, or at the
    /// end of its window. A key whose row is still there is left to the
    /// caller's usual exists-check.
    pub(super) fn refuse_purged_retiring_key(
        &self,
        realm_id: &RealmId,
        family: KeyFamily,
        kid: &str,
    ) -> Result<(), IdentityError> {
        if self.key_is_recorded_retired(realm_id, family, kid)?
            && !self.retiring_key_is_live(realm_id, family, kid)?
        {
            return Err(Self::rotated_away(family, kid));
        }
        Ok(())
    }

    fn rotated_away(family: KeyFamily, kid: &str) -> IdentityError {
        IdentityError::InvalidInput {
            reason: format!(
                "the archived {} {kid} is one this realm rotated away from; a restore never \
                 reinstalls a retired or revoked key (restore a backup made after the rotation)",
                family.describe()
            ),
        }
    }
}
