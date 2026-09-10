//! Periodic cleanup of expired OAuth entities.
//!
//! Sweeps expired authorization codes, device codes, pending
//! authorization tickets, and grant families from storage. Called by a
//! background task at a configurable interval.
//!
//! # Race semantics
//!
//! The sweeper may delete a code between issue and redemption.
//! `exchange_authorization_code()` returns `InvalidAuthorizationCode`
//! for missing keys — identical error to a legitimate double-submit.
//! OAuth clients must already handle `invalid_grant` responses.
//!
//! Device code polling returns `DeviceCodeExpired` (`expired_token`)
//! for missing keys, so a swept device code surfaces as a clean expiry.

use crate::core::{Clock, RealmId, Timestamp};
use crate::identity::federation::saml::SAML_STATE_TTL_SECS;
use crate::identity::keys;
use crate::identity::oidc::{
    StoredDeviceCode, StoredGrantFamily, StoredPushedAuthorizationRequest,
};
use crate::identity::types::PendingAuthorizationRequest;
use crate::storage::StorageEngine;

/// Configuration for the periodic cleanup sweeper.
#[derive(Debug, Clone)]
pub struct CleanupConfig {
    /// Whether periodic cleanup is enabled.
    pub enabled: bool,
    /// Interval in seconds between OAuth entity cleanup sweeps. 0 disables
    /// the background task even when `enabled` is true.
    pub interval_secs: u64,
    /// Maximum entities to delete per type per sweep. Bounds worst-case
    /// sweep latency on the first run after feature enablement.
    pub max_per_type: usize,
    /// Interval in seconds between device-fingerprint TTL sweeps.
    ///
    /// Default: 21 600 (6 hours). 0 disables the dfp sweeper even when
    /// `enabled` is true.
    pub dfp_sweeper_interval_secs: u64,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 300,
            max_per_type: 1000,
            dfp_sweeper_interval_secs: 21_600,
        }
    }
}

/// Deletion counts from a single sweep pass.
#[derive(Debug, Default, Clone)]
pub struct CleanupStats {
    /// Authorization codes swept.
    pub auth_codes_deleted: u64,
    /// Device codes swept.
    pub device_codes_deleted: u64,
    /// Pending authorization tickets swept.
    pub pending_tickets_deleted: u64,
    /// Grant families swept.
    pub grant_families_deleted: u64,
    /// Pushed authorization requests swept.
    pub par_requests_deleted: u64,
    /// JAR (RFC 9101) JTI replay-store entries swept.
    pub jar_jtis_deleted: u64,
    /// DPoP proof JTI replay-cache entries swept.
    pub dpop_jtis_deleted: u64,
    /// Actor token JTI replay-cache entries swept (RFC 8693 B.5).
    pub actor_jtis_deleted: u64,
    /// SAML SP-side request-state bags swept (`saml:state:`).
    ///
    /// This key space is written by an unauthenticated GET
    /// (`…/federation/saml/begin`) and, before 22.11, was only ever removed
    /// by a matching ACS POST — an abandoned login leaked a row forever.
    pub saml_states_deleted: u64,
    /// SAML assertion replay sentinels swept (`saml:asn:`).
    ///
    /// Each sentinel only needs to outlive the assertion it guards; past that
    /// point the assertion's own `NotOnOrAfter` rejects any replay.
    pub saml_assertions_deleted: u64,
    /// Revoked-JTI blocklist entries (`oauth:revjti:`) swept (22.13).
    ///
    /// A blocklist entry only has to outlive the revoked token it names: once
    /// the token's own `exp` has passed, validation rejects it on the expiry
    /// check and the row is dead weight. Legacy rows that carry no expiry are
    /// never swept — deleting one would silently un-revoke a live token.
    pub revoked_jtis_deleted: u64,
    /// Session → grant-family index rows (`oauth:session_fam:`) reclaimed (22.13).
    ///
    /// A row is written when a grant family is created and removed when the
    /// session is revoked. A family that merely *expires* is reclaimed by
    /// `sweep_grant_families` and used to leave its index row behind forever.
    pub session_family_rows_deleted: u64,
    /// A-18 idle/absolute-timeout sessions evicted by the background sweep.
    ///
    /// Policy-expired sessions are rejected fail-closed on the read path with
    /// zero storage writes (C-5); the actual eviction (revoke + audit + SV
    /// bump) is performed here on the periodic sweep.
    pub sessions_evicted: u64,
    /// In-memory rate-tracker entries pruned across all five maps.
    ///
    /// Rate tracker `HashMap`s are not backed by storage; they are pruned
    /// in the engine's `sweep_expired` after the storage sweep completes.
    pub rate_trackers_pruned: u64,
    /// Number of entity-type sweeps that encountered an error.
    pub errors: u64,
}

impl CleanupStats {
    /// Total entities deleted across all types.
    pub fn total_deleted(&self) -> u64 {
        self.auth_codes_deleted
            + self.device_codes_deleted
            + self.pending_tickets_deleted
            + self.grant_families_deleted
            + self.par_requests_deleted
            + self.jar_jtis_deleted
            + self.dpop_jtis_deleted
            + self.actor_jtis_deleted
            + self.saml_states_deleted
            + self.saml_assertions_deleted
            + self.revoked_jtis_deleted
            + self.session_family_rows_deleted
            + self.rate_trackers_pruned
            + self.sessions_evicted
    }
}

/// Runs all entity-type sweeps for a single realm.
///
/// Errors from individual sweeps are logged and counted in
/// [`CleanupStats::errors`]; the function always returns `CleanupStats`
/// (best-effort). The next tick retries any failed sweeps.
/// Records one sweep's outcome into `slot`, counting and logging a failure.
///
/// Every sweep in [`sweep_expired`] has the same shape: on success record the
/// count, on failure count an error and warn. Keeping that shape in one place
/// means a sweep added later cannot quietly drop its error — the class of
/// defect the audit found across the protocol layer's audit writes.
fn record<E: std::fmt::Display>(
    realm_id: &RealmId,
    slot: &mut u64,
    errors: &mut u64,
    what: &str,
    result: Result<u64, E>,
) {
    match result {
        Ok(n) => *slot = n,
        Err(e) => {
            *errors += 1;
            tracing::warn!(
                realm = %realm_id,
                error = %e,
                sweep = what,
                "cleanup: sweep failed"
            );
        }
    }
}

pub(crate) fn sweep_expired(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    clock: &dyn Clock,
    config: &CleanupConfig,
) -> CleanupStats {
    let mut stats = CleanupStats::default();
    let now = clock.now();
    let mut errors = 0_u64;

    record(
        realm_id,
        &mut stats.auth_codes_deleted,
        &mut errors,
        "auth code",
        sweep_auth_codes(realm_id, storage, now, config.max_per_type),
    );
    record(
        realm_id,
        &mut stats.device_codes_deleted,
        &mut errors,
        "device code",
        sweep_device_codes(realm_id, storage, now, config.max_per_type),
    );
    record(
        realm_id,
        &mut stats.pending_tickets_deleted,
        &mut errors,
        "pending ticket",
        sweep_pending_tickets(realm_id, storage, now, config.max_per_type),
    );
    record(
        realm_id,
        &mut stats.grant_families_deleted,
        &mut errors,
        "grant family",
        sweep_grant_families(realm_id, storage, now, config.max_per_type),
    );
    record(
        realm_id,
        &mut stats.par_requests_deleted,
        &mut errors,
        "PAR request",
        sweep_par_requests(realm_id, storage, now, config.max_per_type),
    );

    let now_secs = now.as_micros() / 1_000_000;
    record(
        realm_id,
        &mut stats.jar_jtis_deleted,
        &mut errors,
        "JAR JTI",
        sweep_jar_jtis(realm_id, storage, now_secs),
    );
    record(
        realm_id,
        &mut stats.dpop_jtis_deleted,
        &mut errors,
        "DPoP JTI",
        sweep_dpop_jtis(realm_id, storage, now_secs),
    );
    record(
        realm_id,
        &mut stats.actor_jtis_deleted,
        &mut errors,
        "actor JTI",
        sweep_actor_jtis(realm_id, storage, now_secs),
    );
    record(
        realm_id,
        &mut stats.saml_states_deleted,
        &mut errors,
        "SAML request-state",
        sweep_saml_states(realm_id, storage, now_secs),
    );
    record(
        realm_id,
        &mut stats.saml_assertions_deleted,
        &mut errors,
        "SAML replay-sentinel",
        sweep_saml_assertions(realm_id, storage, now_secs),
    );
    record(
        realm_id,
        &mut stats.revoked_jtis_deleted,
        &mut errors,
        "revoked-JTI blocklist",
        sweep_revoked_jtis(realm_id, storage, now_secs),
    );

    // Ordered after `sweep_grant_families`: that sweep is what turns a live
    // index row into an orphan, so running it first lets the same tick reclaim
    // both halves instead of leaving the index a tick behind.
    record(
        realm_id,
        &mut stats.session_family_rows_deleted,
        &mut errors,
        "session grant-family index",
        sweep_session_family_index(realm_id, storage, config.max_per_type),
    );

    stats.errors = errors;
    stats
}

/// Eviction counts from a single device-fingerprint sweep of one realm.
#[derive(Debug, Default, Clone)]
pub struct FingerprintSweepStats {
    /// Expired fingerprint entries deleted.
    pub evicted: u64,
    /// Active (non-expired) fingerprint entries observed after the sweep.
    pub active: u64,
}

/// Scans all `dfp:user:*` keys in `realm_id` and deletes entries whose
/// 8-byte little-endian i64 expiry (Unix seconds) is <= `now_secs`.
///
/// Returns [`FingerprintSweepStats`] on success. The caller should log any
/// returned error at WARN level and continue — partial sweeps are safe
/// because lazy expiry on the read path still handles stragglers.
pub(crate) fn sweep_fingerprints(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now_secs: i64,
) -> Result<FingerprintSweepStats, crate::storage::StorageError> {
    let prefix = keys::device_fp_global_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut stats = FingerprintSweepStats::default();
    for entry in &entries {
        let Ok(bytes) = entry.value.as_slice().try_into() else {
            tracing::warn!(key = ?entry.key, "cleanup: malformed fingerprint expiry entry, skipping");
            continue;
        };
        let expires_at = i64::from_le_bytes(bytes);
        if expires_at <= now_secs {
            storage.delete(realm_id, &entry.key)?;
            stats.evicted += 1;
        } else {
            stats.active += 1;
        }
    }
    Ok(stats)
}

// --- per-entity sweep helpers ---

fn sweep_auth_codes(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now: Timestamp,
    max_per_type: usize,
) -> Result<u64, crate::storage::StorageError> {
    #[derive(serde::Deserialize)]
    struct Expiry {
        expires_at: Timestamp,
    }

    let prefix = keys::oauth_code_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        if deleted >= max_per_type as u64 {
            break;
        }

        let exp: Expiry = serde_json::from_slice(&entry.value).map_err(|e| {
            crate::storage::StorageError::DeserializationFailed {
                reason: format!("cleanup: failed to deserialize auth code: {e}"),
            }
        })?;

        if now >= exp.expires_at {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }

    Ok(deleted)
}

fn sweep_device_codes(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now: Timestamp,
    max_per_type: usize,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::device_code_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        if deleted >= max_per_type as u64 {
            break;
        }
        let stored: StoredDeviceCode = serde_json::from_slice(&entry.value).map_err(|e| {
            crate::storage::StorageError::DeserializationFailed {
                reason: format!("cleanup: failed to deserialize device code: {e}"),
            }
        })?;

        if now >= stored.expires_at {
            storage.delete(realm_id, &entry.key)?;
            // Also clean up the user_code → device_code index.
            // An orphaned index is benign garbage, but we make a
            // best-effort attempt to remove it.
            let uc_key = keys::encode_user_code(&stored.user_code);
            if let Err(e) = storage.delete(realm_id, &uc_key) {
                tracing::warn!(
                    realm = %realm_id,
                    user_code = %stored.user_code,
                    error = %e,
                    "cleanup: failed to delete user_code index for expired device code",
                );
            }
            deleted += 1;
        }
    }

    Ok(deleted)
}

fn sweep_pending_tickets(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now: Timestamp,
    max_per_type: usize,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::oauth_pending_auth_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        if deleted >= max_per_type as u64 {
            break;
        }
        let ticket: PendingAuthorizationRequest =
            serde_json::from_slice(&entry.value).map_err(|e| {
                crate::storage::StorageError::DeserializationFailed {
                    reason: format!("cleanup: failed to deserialize pending ticket: {e}"),
                }
            })?;

        if now >= ticket.expires_at {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }

    Ok(deleted)
}

fn sweep_grant_families(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now: Timestamp,
    max_per_type: usize,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::grant_family_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        if deleted >= max_per_type as u64 {
            break;
        }
        let family: StoredGrantFamily = serde_json::from_slice(&entry.value).map_err(|e| {
            crate::storage::StorageError::DeserializationFailed {
                reason: format!("cleanup: failed to deserialize grant family: {e}"),
            }
        })?;

        if now >= family.expires_at {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }

    Ok(deleted)
}

fn sweep_par_requests(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now: Timestamp,
    max_per_type: usize,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::par_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        if deleted >= max_per_type as u64 {
            break;
        }
        let par: StoredPushedAuthorizationRequest =
            serde_json::from_slice(&entry.value).map_err(|e| {
                crate::storage::StorageError::DeserializationFailed {
                    reason: format!("cleanup: failed to deserialize PAR request: {e}"),
                }
            })?;

        if now >= par.expires_at {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }

    Ok(deleted)
}

/// Scans all `oauth:jar-jti:*` keys in `realm_id` and deletes entries whose
/// 8-byte little-endian i64 expiry (Unix seconds) is <= `now_secs`.
///
/// Returns the number of evicted entries. Errors are propagated to the caller,
/// which should log at WARN level and continue — partial sweeps are safe because
/// replay prevention still fires on the read path for any entry still present.
pub(crate) fn sweep_jar_jtis(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now_secs: i64,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::jar_jti_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        // Legacy b"1" entries and genuinely malformed entries both fail this conversion;
        // legacy entries are left for cascade realm deletion and do not warrant a warning.
        let Ok(bytes) = entry.value.as_slice().try_into() else {
            continue;
        };
        let expires_at = i64::from_le_bytes(bytes);
        if expires_at <= now_secs {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Scans all `agt:dpop:jti:*` keys in `realm_id` and deletes entries whose
/// 8-byte little-endian i64 expiry (Unix seconds) is <= `now_secs`.
///
/// Returns the number of evicted entries. Partial sweeps are safe because
/// replay prevention fires on the storage read path for any entry still
/// present.
pub(crate) fn sweep_dpop_jtis(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now_secs: i64,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::dpop_jti_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        let Ok(bytes) = entry.value.as_slice().try_into() else {
            continue;
        };
        let expires_at = i64::from_le_bytes(bytes);
        if expires_at <= now_secs {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Evicts expired actor-token JTI entries (RFC 8693 §3.3 replay prevention).
///
/// Each entry stores an 8-byte little-endian `i64` Unix-seconds expiry.
/// Entries are deleted once `expires_at <= now_secs`.
pub(crate) fn sweep_actor_jtis(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now_secs: i64,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::actor_jti_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        let Ok(bytes) = entry.value.as_slice().try_into() else {
            continue;
        };
        let expires_at = i64::from_le_bytes(bytes);
        if expires_at <= now_secs {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Reclaims expired SAML SP-side request state (`saml:state:` — audit
/// 2026-08-28 §4.10#9).
///
/// Every `GET …/federation/saml/begin` writes one bag. Only a matching ACS
/// POST removed it, so every abandoned or attacker-issued login leaked a row
/// permanently — and the writer is unauthenticated. Entries older than
/// [`SAML_STATE_TTL_SECS`] are already refused on the read path; this deletes
/// them.
///
/// A bag whose JSON no longer deserializes is left in place for realm-cascade
/// deletion rather than silently dropped.
pub(crate) fn sweep_saml_states(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now_secs: i64,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::saml_state_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        let Ok(bag) =
            serde_json::from_slice::<crate::identity::federation::saml::SamlStateBag>(&entry.value)
        else {
            continue;
        };
        let created_secs = bag.created_at.as_micros() / 1_000_000;
        if now_secs.saturating_sub(created_secs) > SAML_STATE_TTL_SECS {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Reclaims expired SAML assertion replay sentinels (`saml:asn:` — audit
/// 2026-08-28 §4.10#9).
///
/// Each sentinel stores an 8-byte little-endian `i64` Unix-seconds expiry
/// derived from the assertion's own `NotOnOrAfter` plus the SP clock skew.
/// Once that moment passes the assertion cannot be replayed anyway — its
/// validity window closed — so the sentinel has no further work to do.
///
/// Sentinels written before 22.11 stored an empty value. Those fail the
/// 8-byte conversion and are left for realm-cascade deletion, exactly as the
/// JAR/DPoP JTI sweeps treat their own legacy entries.
pub(crate) fn sweep_saml_assertions(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now_secs: i64,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::saml_assertion_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        let Ok(bytes) = entry.value.as_slice().try_into() else {
            continue;
        };
        let expires_at = i64::from_le_bytes(bytes);
        if expires_at <= now_secs {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Reclaims expired entries from the sessionless-token revocation blocklist.
///
/// `oauth:revjti:{jti}` rows are written by RFC 7009 revocation and by agent
/// token revocation. The value is an 8-byte little-endian `i64` holding the
/// revoked token's own `exp` in Unix seconds; once that instant has passed the
/// token is rejected on the ordinary expiry check and the row serves no
/// purpose. Nothing ever deleted these rows, so the blocklist grew for the
/// life of the realm (audit 2026-08-28 §4.16#13).
///
/// Rows whose value is not exactly 8 bytes are the legacy `b"1"` encoding,
/// which carries no expiry. They are left in place: the hot-path projection
/// treats them as `i64::MAX`, so deleting one would un-revoke a live token.
///
/// Deleting an expired row cannot resurrect a token. The hot-path
/// revoked-JTI projection self-evicts on the same `exp`, so the cache and the
/// key space agree without any cross-layer invalidation.
pub(crate) fn sweep_revoked_jtis(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now_secs: i64,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::revoked_jti_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        let Ok(bytes) = entry.value.as_slice().try_into() else {
            // Legacy `b"1"` (no expiry) or a malformed row: never reclaimed.
            continue;
        };
        let expires_at = i64::from_le_bytes(bytes);
        if expires_at <= now_secs {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Reclaims `oauth:session_fam:` index rows whose grant family is gone.
///
/// The row exists so that revoking a session can cascade into every refresh
/// token family the session issued. It is written at family creation (after
/// the family record itself) and deleted on session revocation — but a family
/// that simply expires is reclaimed by [`sweep_grant_families`], which leaves
/// the index row behind with nothing to point at. Those rows accumulated
/// forever (audit 2026-08-28 §4.16#13).
///
/// A row is reclaimed only when its family record is absent, which is exact
/// rather than time-based: the family record is always written before the
/// index row, so "family missing" can only mean the family has been deleted,
/// never that it is about to be created.
pub(crate) fn sweep_session_family_index(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    max_per_type: usize,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::session_grant_family_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        if deleted >= max_per_type as u64 {
            break;
        }
        // A row we cannot parse is left alone rather than guessed at.
        let Some(family_id) = keys::decode_session_grant_family_id(&entry.key) else {
            continue;
        };
        let family_key = keys::encode_grant_family(family_id);
        if storage.get(realm_id, &family_key)?.is_none() {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FakeClock, Timestamp};
    use crate::identity::keys;
    use crate::identity::oidc::{DeviceCodeStatus, StoredAuthorizationCode, StoredDeviceCode};
    use crate::identity::types::PendingAuthorizationRequest;
    use crate::storage::EmbeddedStorageEngine;

    fn storage() -> (EmbeddedStorageEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = EmbeddedStorageEngine::open(crate::storage::StorageConfig::dev(
            dir.path().to_path_buf(),
        ))
        .expect("open storage");
        (engine, dir)
    }

    fn fake_clock(micros: i64) -> FakeClock {
        FakeClock::new(Timestamp::from_micros(micros))
    }

    const T0: i64 = 1_700_000_000_000_000; // base timestamp in micros
    const ONE_HOUR: i64 = 3_600_000_000;
    const TEN_MINUTES: i64 = 600_000_000;

    // --- auth codes ---

    #[test]
    fn sweep_auth_codes_deletes_expired() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + 2 * ONE_HOUR);

        let code = StoredAuthorizationCode {
            code_hash: "hash1".into(),
            client_id: crate::core::ClientId::generate(),
            user_id: crate::core::UserId::generate(),
            redirect_uri: "https://ex.com/cb".into(),
            scope: "openid".into(),
            code_challenge: None,
            code_challenge_method: None,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
            nonce: None,
            resource: None,
            amr_values: Vec::new(),
        };
        let key = keys::encode_oauth_code("hash1");
        s.put(&realm, &key, &serde_json::to_vec(&code).expect("serialize"))
            .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.auth_codes_deleted, 1);
        assert!(s.get(&realm, &key).expect("get").is_none());
    }

    #[test]
    fn sweep_auth_codes_keeps_valid() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + TEN_MINUTES / 2);

        let code = StoredAuthorizationCode {
            code_hash: "hash2".into(),
            client_id: crate::core::ClientId::generate(),
            user_id: crate::core::UserId::generate(),
            redirect_uri: "https://ex.com/cb".into(),
            scope: "openid".into(),
            code_challenge: None,
            code_challenge_method: None,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
            nonce: None,
            resource: None,
            amr_values: Vec::new(),
        };
        let key = keys::encode_oauth_code("hash2");
        s.put(&realm, &key, &serde_json::to_vec(&code).expect("serialize"))
            .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.auth_codes_deleted, 0);
        assert!(s.get(&realm, &key).expect("get").is_some());
    }

    // --- device codes ---

    #[test]
    fn sweep_device_codes_deletes_expired() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + 2 * ONE_HOUR);

        let dc = StoredDeviceCode {
            device_code_hash: "dch1".into(),
            user_code: "BDFGJKMN".into(),
            client_id: crate::core::ClientId::generate(),
            realm_id: realm.clone(),
            scope: Some("openid".into()),
            status: DeviceCodeStatus::Pending,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
            interval: 5,
            last_polled_at: None,
        };

        let dc_key = keys::encode_device_code("dch1");
        s.put(
            &realm,
            &dc_key,
            &serde_json::to_vec(&dc).expect("serialize"),
        )
        .expect("put");
        let uc_key = keys::encode_user_code("BDFGJKMN");
        s.put(&realm, &uc_key, b"dch1").expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.device_codes_deleted, 1);
        assert!(s.get(&realm, &dc_key).expect("get").is_none());
        assert!(s.get(&realm, &uc_key).expect("get").is_none());
    }

    #[test]
    fn sweep_device_codes_keeps_valid() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + TEN_MINUTES / 2);

        let dc = StoredDeviceCode {
            device_code_hash: "dch2".into(),
            user_code: "BCDFGHJK".into(),
            client_id: crate::core::ClientId::generate(),
            realm_id: realm.clone(),
            scope: None,
            status: DeviceCodeStatus::Pending,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + ONE_HOUR),
            interval: 5,
            last_polled_at: None,
        };

        let dc_key = keys::encode_device_code("dch2");
        s.put(
            &realm,
            &dc_key,
            &serde_json::to_vec(&dc).expect("serialize"),
        )
        .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.device_codes_deleted, 0);
        assert!(s.get(&realm, &dc_key).expect("get").is_some());
    }

    // --- pending tickets ---

    #[test]
    fn sweep_pending_tickets_deletes_expired() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + 2 * ONE_HOUR);

        let ticket = PendingAuthorizationRequest {
            realm_id: realm.clone(),
            user_id: crate::core::UserId::generate(),
            client_id: crate::core::ClientId::generate(),
            redirect_uri: "https://ex.com/cb".into(),
            requested_scopes: vec!["openid".into()],
            state: "state1".into(),
            response_type: "code".into(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            response_mode: None,
            authorization_signed_response_alg: None,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
        };

        let ticket_id = uuid::Uuid::new_v4().to_string();
        let key = keys::encode_pending_auth_key(&ticket_id);
        s.put(
            &realm,
            &key,
            &serde_json::to_vec(&ticket).expect("serialize"),
        )
        .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.pending_tickets_deleted, 1);
        assert!(s.get(&realm, &key).expect("get").is_none());
    }

    #[test]
    fn sweep_pending_tickets_keeps_valid() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + TEN_MINUTES / 2);

        let ticket = PendingAuthorizationRequest {
            realm_id: realm.clone(),
            user_id: crate::core::UserId::generate(),
            client_id: crate::core::ClientId::generate(),
            redirect_uri: "https://ex.com/cb".into(),
            requested_scopes: vec!["openid".into()],
            state: "state2".into(),
            response_type: "code".into(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            response_mode: None,
            authorization_signed_response_alg: None,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + ONE_HOUR),
        };

        let ticket_id = uuid::Uuid::new_v4().to_string();
        let key = keys::encode_pending_auth_key(&ticket_id);
        s.put(
            &realm,
            &key,
            &serde_json::to_vec(&ticket).expect("serialize"),
        )
        .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.pending_tickets_deleted, 0);
        assert!(s.get(&realm, &key).expect("get").is_some());
    }

    // --- grant families ---

    #[test]
    fn sweep_grant_families_deletes_expired() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + 2 * ONE_HOUR);

        let family = StoredGrantFamily {
            family_id: "fid1".into(),
            current_refresh_hash: "hash".into(),
            session_id: crate::core::SessionId::generate(),
            realm_id: realm.clone(),
            revoked: false,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
            client_id: None,
            resources: Vec::new(),
            amr_values: Vec::new(),
            bound_asn: None,
            ua_hash: None,
            bound_jkt: None,
        };

        let key = keys::encode_grant_family("fid1");
        s.put(
            &realm,
            &key,
            &serde_json::to_vec(&family).expect("serialize"),
        )
        .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.grant_families_deleted, 1);
        assert!(s.get(&realm, &key).expect("get").is_none());
    }

    #[test]
    fn sweep_grant_families_deletes_revoked_when_expired() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + 2 * ONE_HOUR);

        let family = StoredGrantFamily {
            family_id: "fid2".into(),
            current_refresh_hash: "hash".into(),
            session_id: crate::core::SessionId::generate(),
            realm_id: realm.clone(),
            revoked: true,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
            client_id: None,
            resources: Vec::new(),
            amr_values: Vec::new(),
            bound_asn: None,
            ua_hash: None,
            bound_jkt: None,
        };

        let key = keys::encode_grant_family("fid2");
        s.put(
            &realm,
            &key,
            &serde_json::to_vec(&family).expect("serialize"),
        )
        .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.grant_families_deleted, 1);
        assert!(s.get(&realm, &key).expect("get").is_none());
    }

    #[test]
    fn sweep_grant_families_keeps_valid() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + TEN_MINUTES / 2);

        let family = StoredGrantFamily {
            family_id: "fid3".into(),
            current_refresh_hash: "hash".into(),
            session_id: crate::core::SessionId::generate(),
            realm_id: realm.clone(),
            revoked: false,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + ONE_HOUR),
            client_id: None,
            resources: Vec::new(),
            amr_values: Vec::new(),
            bound_asn: None,
            ua_hash: None,
            bound_jkt: None,
        };

        let key = keys::encode_grant_family("fid3");
        s.put(
            &realm,
            &key,
            &serde_json::to_vec(&family).expect("serialize"),
        )
        .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.grant_families_deleted, 0);
        assert!(s.get(&realm, &key).expect("get").is_some());
    }

    // --- max_per_type ---

    #[test]
    fn sweep_respects_max_per_type() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + 2 * ONE_HOUR);

        for i in 0..5 {
            let code = StoredAuthorizationCode {
                code_hash: format!("expired_hash_{i}"),
                client_id: crate::core::ClientId::generate(),
                user_id: crate::core::UserId::generate(),
                redirect_uri: "https://ex.com/cb".into(),
                scope: "openid".into(),
                code_challenge: None,
                code_challenge_method: None,
                created_at: Timestamp::from_micros(T0),
                expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
            };
            let key = keys::encode_oauth_code(&format!("expired_hash_{i}"));
            s.put(&realm, &key, &serde_json::to_vec(&code).expect("serialize"))
                .expect("put");
        }

        let config = CleanupConfig {
            max_per_type: 3,
            ..Default::default()
        };
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.auth_codes_deleted, 3);
    }

    // --- total deleted ---

    #[test]
    fn total_deleted_sums_all_types() {
        let stats = CleanupStats {
            auth_codes_deleted: 1,
            device_codes_deleted: 2,
            pending_tickets_deleted: 3,
            grant_families_deleted: 4,
            par_requests_deleted: 5,
            ..Default::default()
        };
        assert_eq!(stats.total_deleted(), 15);
    }

    // --- device fingerprint sweep ---

    const NOW_SECS: i64 = 1_700_000_000; // fixed base time in Unix seconds

    /// Seed a fingerprint entry with the given expiry directly into storage.
    fn seed_fingerprint(
        s: &EmbeddedStorageEngine,
        realm: &RealmId,
        user_id: &crate::core::UserId,
        tag: u8,
        expires_at: i64,
    ) {
        let hmac_hex = format!("{tag:0>64x}");
        let key = keys::encode_device_fp(user_id, &hmac_hex);
        s.put(realm, &key, &expires_at.to_le_bytes())
            .expect("put fingerprint");
    }

    #[test]
    fn sweep_fingerprints_deletes_expired_keeps_active() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let user_a = crate::core::UserId::generate();
        let user_b = crate::core::UserId::generate();

        // Seed 3 expired entries (for two different users)
        seed_fingerprint(&s, &realm, &user_a, 1, NOW_SECS - 1);
        seed_fingerprint(&s, &realm, &user_a, 2, NOW_SECS - 3600);
        seed_fingerprint(&s, &realm, &user_b, 3, NOW_SECS - 86400);

        // Seed 2 live entries
        seed_fingerprint(&s, &realm, &user_a, 4, NOW_SECS + 86400);
        seed_fingerprint(&s, &realm, &user_b, 5, NOW_SECS + 7 * 86400);

        let stats = sweep_fingerprints(&realm, &s, NOW_SECS).expect("sweep");
        assert_eq!(stats.evicted, 3, "should delete 3 expired entries");
        assert_eq!(stats.active, 2, "should observe 2 live entries");

        // Verify exactly 2 entries remain in storage.
        let prefix = keys::device_fp_global_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let remaining = s.scan(&realm, &prefix, &end).expect("scan after sweep");
        assert_eq!(remaining.len(), 2, "only active entries must survive");
    }

    #[test]
    fn sweep_fingerprints_empty_realm_is_ok() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let stats = sweep_fingerprints(&realm, &s, NOW_SECS).expect("sweep empty realm");
        assert_eq!(stats.evicted, 0);
        assert_eq!(stats.active, 0);
    }

    #[test]
    fn sweep_fingerprints_all_active_nothing_deleted() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let user = crate::core::UserId::generate();

        for tag in 0u8..4 {
            seed_fingerprint(&s, &realm, &user, tag, NOW_SECS + 86400);
        }

        let stats = sweep_fingerprints(&realm, &s, NOW_SECS).expect("sweep");
        assert_eq!(stats.evicted, 0);
        assert_eq!(stats.active, 4);
    }

    #[test]
    fn sweep_fingerprints_boundary_at_exactly_now_is_expired() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let user = crate::core::UserId::generate();

        // Entry whose expiry == now (not strictly in the future) must be evicted.
        seed_fingerprint(&s, &realm, &user, 1, NOW_SECS);

        let stats = sweep_fingerprints(&realm, &s, NOW_SECS).expect("sweep");
        assert_eq!(
            stats.evicted, 1,
            "entry expiring exactly at now must be evicted"
        );
        assert_eq!(stats.active, 0);
    }

    #[test]
    fn sweep_fingerprints_isolated_across_realms() {
        let (s, _dir) = storage();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();
        let user = crate::core::UserId::generate();

        // Seed expired in realm_a, live in realm_b.
        seed_fingerprint(&s, &realm_a, &user, 1, NOW_SECS - 1);
        seed_fingerprint(&s, &realm_b, &user, 2, NOW_SECS + 86400);

        let stats_a = sweep_fingerprints(&realm_a, &s, NOW_SECS).expect("sweep realm_a");
        assert_eq!(stats_a.evicted, 1);
        assert_eq!(stats_a.active, 0);

        let stats_b = sweep_fingerprints(&realm_b, &s, NOW_SECS).expect("sweep realm_b");
        assert_eq!(stats_b.evicted, 0);
        assert_eq!(stats_b.active, 1, "realm_b entry must be untouched");
    }

    // --- JAR JTI sweep ---

    /// Seed a JAR JTI entry with the given expiry (Unix seconds) directly into storage.
    fn seed_jar_jti(s: &EmbeddedStorageEngine, realm: &RealmId, jti: &str, expires_at: i64) {
        let key = keys::encode_jar_jti(jti);
        s.put(realm, &key, &expires_at.to_le_bytes())
            .expect("put jar jti");
    }

    #[test]
    fn sweep_jar_jtis_deletes_expired_keeps_active() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();

        seed_jar_jti(&s, &realm, "expired-1", NOW_SECS - 1);
        seed_jar_jti(&s, &realm, "expired-2", NOW_SECS - 3600);
        seed_jar_jti(&s, &realm, "active-1", NOW_SECS + 300);

        let deleted = sweep_jar_jtis(&realm, &s, NOW_SECS).expect("sweep");
        assert_eq!(deleted, 2, "both expired entries must be removed");

        assert!(
            s.get(&realm, &keys::encode_jar_jti("expired-1"))
                .expect("get")
                .is_none(),
            "expired-1 must be gone"
        );
        assert!(
            s.get(&realm, &keys::encode_jar_jti("active-1"))
                .expect("get")
                .is_some(),
            "active-1 must survive"
        );
    }

    #[test]
    fn sweep_jar_jtis_boundary_at_exactly_now_is_expired() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();

        seed_jar_jti(&s, &realm, "boundary", NOW_SECS);

        let deleted = sweep_jar_jtis(&realm, &s, NOW_SECS).expect("sweep boundary");
        assert_eq!(deleted, 1, "entry expiring exactly at now must be evicted");
    }

    #[test]
    fn sweep_jar_jtis_empty_realm_is_ok() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let deleted = sweep_jar_jtis(&realm, &s, NOW_SECS).expect("sweep empty");
        assert_eq!(deleted, 0);
    }

    #[test]
    fn sweep_jar_jtis_isolated_across_realms() {
        let (s, _dir) = storage();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        seed_jar_jti(&s, &realm_a, "jti-expired", NOW_SECS - 1);
        seed_jar_jti(&s, &realm_b, "jti-active", NOW_SECS + 86400);

        let deleted_a = sweep_jar_jtis(&realm_a, &s, NOW_SECS).expect("sweep realm_a");
        assert_eq!(deleted_a, 1);

        let deleted_b = sweep_jar_jtis(&realm_b, &s, NOW_SECS).expect("sweep realm_b");
        assert_eq!(deleted_b, 0, "realm_b entry must be untouched");
        assert!(s
            .get(&realm_b, &keys::encode_jar_jti("jti-active"))
            .expect("get")
            .is_some());
    }

    #[test]
    fn sweep_expired_includes_jar_jtis() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + ONE_HOUR);

        // Store an expired JAR JTI (expiry 30 min before "now").
        let expires_at_secs = (T0 + ONE_HOUR) / 1_000_000 - 1800;
        seed_jar_jti(&s, &realm, "jar-expired", expires_at_secs);

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(
            stats.jar_jtis_deleted, 1,
            "sweep_expired must include JAR JTI sweep"
        );
    }

    #[test]
    fn sweep_fingerprints_malformed_entry_is_skipped() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let user = crate::core::UserId::generate();

        // Seed a valid expired entry alongside a malformed one (wrong byte length).
        seed_fingerprint(&s, &realm, &user, 1, NOW_SECS - 1);
        let bad_key = keys::encode_device_fp(&user, &format!("{:0>64x}", 99u8));
        s.put(&realm, &bad_key, b"bad").expect("put malformed");

        // Must not panic; valid expired entry is deleted, malformed entry is left in place.
        let stats = sweep_fingerprints(&realm, &s, NOW_SECS).expect("sweep with malformed entry");
        assert_eq!(
            stats.evicted, 1,
            "only the valid expired entry should be evicted"
        );
        assert!(
            s.get(&realm, &bad_key).expect("get").is_some(),
            "malformed entry must be skipped, not deleted"
        );
    }

    // --- DPoP JTI sweep ---

    fn seed_dpop_jti(s: &EmbeddedStorageEngine, realm: &RealmId, jti: &str, expires_at: i64) {
        let key = keys::encode_dpop_jti(jti);
        s.put(realm, &key, &expires_at.to_le_bytes())
            .expect("put dpop jti");
    }

    #[test]
    fn sweep_dpop_jtis_deletes_expired_keeps_active() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();

        seed_dpop_jti(&s, &realm, "dpop-expired-1", NOW_SECS - 1);
        seed_dpop_jti(&s, &realm, "dpop-expired-2", NOW_SECS - 3600);
        seed_dpop_jti(&s, &realm, "dpop-active-1", NOW_SECS + 120);

        let deleted = sweep_dpop_jtis(&realm, &s, NOW_SECS).expect("sweep");
        assert_eq!(deleted, 2, "both expired entries must be removed");

        assert!(
            s.get(&realm, &keys::encode_dpop_jti("dpop-expired-1"))
                .expect("get")
                .is_none(),
            "dpop-expired-1 must be gone"
        );
        assert!(
            s.get(&realm, &keys::encode_dpop_jti("dpop-active-1"))
                .expect("get")
                .is_some(),
            "dpop-active-1 must survive"
        );
    }

    #[test]
    fn sweep_dpop_jtis_boundary_at_exactly_now_is_expired() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();

        seed_dpop_jti(&s, &realm, "dpop-boundary", NOW_SECS);

        let deleted = sweep_dpop_jtis(&realm, &s, NOW_SECS).expect("sweep boundary");
        assert_eq!(deleted, 1, "entry expiring exactly at now must be evicted");
    }

    #[test]
    fn sweep_dpop_jtis_empty_realm_is_ok() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let deleted = sweep_dpop_jtis(&realm, &s, NOW_SECS).expect("sweep empty");
        assert_eq!(deleted, 0);
    }

    #[test]
    fn sweep_dpop_jtis_isolated_across_realms() {
        let (s, _dir) = storage();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        seed_dpop_jti(&s, &realm_a, "jti-expired", NOW_SECS - 1);
        seed_dpop_jti(&s, &realm_b, "jti-active", NOW_SECS + 86400);

        let deleted_a = sweep_dpop_jtis(&realm_a, &s, NOW_SECS).expect("sweep realm_a");
        assert_eq!(deleted_a, 1);

        let deleted_b = sweep_dpop_jtis(&realm_b, &s, NOW_SECS).expect("sweep realm_b");
        assert_eq!(deleted_b, 0, "realm_b entry must be untouched");
    }

    #[test]
    fn sweep_expired_includes_dpop_jtis() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + ONE_HOUR);

        let expires_at_secs = (T0 + ONE_HOUR) / 1_000_000 - 60;
        seed_dpop_jti(&s, &realm, "dpop-expired", expires_at_secs);

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(
            stats.dpop_jtis_deleted, 1,
            "sweep_expired must include DPoP JTI sweep"
        );
    }

    #[test]
    fn sweep_jar_jtis_malformed_and_legacy_entries_are_skipped() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();

        // Seed a valid expired entry, a legacy b"1" entry, and a malformed entry.
        seed_jar_jti(&s, &realm, "expired-ok", NOW_SECS - 1);
        let legacy_key = keys::encode_jar_jti("legacy-jti");
        s.put(&realm, &legacy_key, b"1").expect("put legacy");
        let bad_key = keys::encode_jar_jti("malformed-jti");
        s.put(&realm, &bad_key, b"bad").expect("put malformed");

        // Must not panic; only the valid expired entry is deleted.
        let deleted = sweep_jar_jtis(&realm, &s, NOW_SECS).expect("sweep with legacy/malformed");
        assert_eq!(deleted, 1, "only the valid expired entry should be deleted");
        assert!(
            s.get(&realm, &legacy_key).expect("get").is_some(),
            "legacy b\"1\" entry must survive"
        );
        assert!(
            s.get(&realm, &bad_key).expect("get").is_some(),
            "malformed entry must survive"
        );
    }

    // ==================================================================
    // 22.11 (audit 2026-08-28 §4.10#9) — the two unbounded SAML key
    // spaces. `saml:state:` is written by an unauthenticated GET; both
    // grew forever because nothing ever reclaimed them.
    // ==================================================================

    fn seed_saml_state(
        s: &EmbeddedStorageEngine,
        realm: &RealmId,
        token: &str,
        created_at_secs: i64,
    ) {
        let bag = crate::identity::federation::saml::SamlStateBag {
            token: token.to_string(),
            request_id: format!("_req-{token}"),
            realm_id: realm.clone(),
            idp_id: crate::core::IdpId::generate(),
            return_to: None,
            created_at: Timestamp::from_micros(created_at_secs * 1_000_000),
        };
        let key = keys::encode_saml_state_key(token);
        s.put(
            realm,
            &key,
            &serde_json::to_vec(&bag).expect("serialize bag"),
        )
        .expect("put saml state");
    }

    fn seed_saml_assertion(
        s: &EmbeddedStorageEngine,
        realm: &RealmId,
        idp_id: &crate::core::IdpId,
        assertion_id: &str,
        expires_at_secs: i64,
    ) {
        let key = keys::encode_saml_assertion_id(idp_id, assertion_id);
        s.put(realm, &key, &expires_at_secs.to_le_bytes())
            .expect("put saml assertion sentinel");
    }

    #[test]
    fn sweep_saml_states_deletes_expired_keeps_active() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();

        // TTL is 600 s, so anything created more than 600 s ago is expired.
        seed_saml_state(&s, &realm, "stale-1", NOW_SECS - 601);
        seed_saml_state(&s, &realm, "stale-2", NOW_SECS - 7200);
        seed_saml_state(&s, &realm, "fresh-1", NOW_SECS - 30);

        let deleted = sweep_saml_states(&realm, &s, NOW_SECS).expect("sweep");
        assert_eq!(deleted, 2, "both expired state bags must be removed");
        assert!(
            s.get(&realm, &keys::encode_saml_state_key("stale-1"))
                .expect("get")
                .is_none(),
            "stale-1 must be gone"
        );
        assert!(
            s.get(&realm, &keys::encode_saml_state_key("fresh-1"))
                .expect("get")
                .is_some(),
            "an in-flight login must survive the sweep"
        );
    }

    #[test]
    fn sweep_saml_assertions_deletes_expired_keeps_active() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let idp = crate::core::IdpId::generate();

        seed_saml_assertion(&s, &realm, &idp, "_a-expired", NOW_SECS - 1);
        seed_saml_assertion(&s, &realm, &idp, "_a-active", NOW_SECS + 300);

        let deleted = sweep_saml_assertions(&realm, &s, NOW_SECS).expect("sweep");
        assert_eq!(deleted, 1, "only the expired replay sentinel is reclaimed");
        assert!(
            s.get(&realm, &keys::encode_saml_assertion_id(&idp, "_a-active"))
                .expect("get")
                .is_some(),
            "a sentinel whose assertion can still be replayed must survive"
        );
    }

    #[test]
    fn sweep_saml_key_spaces_are_isolated_across_realms() {
        let (s, _dir) = storage();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();
        let idp = crate::core::IdpId::generate();

        seed_saml_state(&s, &realm_b, "other-realm", NOW_SECS - 7200);
        seed_saml_assertion(&s, &realm_b, &idp, "_a-other", NOW_SECS - 1);

        assert_eq!(
            sweep_saml_states(&realm_a, &s, NOW_SECS).expect("sweep states"),
            0
        );
        assert_eq!(
            sweep_saml_assertions(&realm_a, &s, NOW_SECS).expect("sweep assertions"),
            0
        );
        assert!(
            s.get(&realm_b, &keys::encode_saml_state_key("other-realm"))
                .expect("get")
                .is_some(),
            "realm_b entries must be untouched by a realm_a sweep"
        );
    }

    #[test]
    fn sweep_expired_includes_saml_key_spaces() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + ONE_HOUR);
        let now_secs = (T0 + ONE_HOUR) / 1_000_000;
        let idp = crate::core::IdpId::generate();

        seed_saml_state(&s, &realm, "stale", now_secs - 7200);
        seed_saml_assertion(&s, &realm, &idp, "_a-expired", now_secs - 60);

        let stats = sweep_expired(&realm, &s, &clock, &CleanupConfig::default());
        assert_eq!(
            stats.saml_states_deleted, 1,
            "sweep_expired must reclaim expired SAML request state"
        );
        assert_eq!(
            stats.saml_assertions_deleted, 1,
            "sweep_expired must reclaim expired SAML replay sentinels"
        );
    }

    // --- 22.13: revoked-JTI blocklist + session→grant-family index ---

    /// `oauth:revjti:` is written on every sessionless-token revocation and,
    /// before this sweep, was never deleted: the blocklist grew for the life of
    /// the realm even though an entry is only load-bearing until the revoked
    /// token's own `exp` passes (audit 2026-08-28 §4.16#13).
    #[test]
    fn sweep_expired_reclaims_expired_revoked_jtis() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + ONE_HOUR);
        let now_secs = (T0 + ONE_HOUR) / 1_000_000;

        let stale = keys::encode_revoked_jti("jti-stale");
        s.put(&realm, &stale, &(now_secs - 1).to_le_bytes())
            .expect("put stale");
        let live = keys::encode_revoked_jti("jti-live");
        s.put(&realm, &live, &(now_secs + 3600).to_le_bytes())
            .expect("put live");
        // Legacy entries carry no expiry and must be left alone: deleting one
        // would un-revoke a token that is still valid.
        let legacy = keys::encode_revoked_jti("jti-legacy");
        s.put(&realm, &legacy, b"1").expect("put legacy");

        let stats = sweep_expired(&realm, &s, &clock, &CleanupConfig::default());

        assert_eq!(
            stats.revoked_jtis_deleted, 1,
            "only the entry whose own exp has passed may be reclaimed"
        );
        assert!(
            s.get(&realm, &stale).expect("get").is_none(),
            "an expired blocklist entry must be reclaimed"
        );
        assert!(
            s.get(&realm, &live).expect("get").is_some(),
            "a blocklist entry for a still-valid token must survive"
        );
        assert!(
            s.get(&realm, &legacy).expect("get").is_some(),
            "a legacy no-expiry blocklist entry must survive"
        );
    }

    /// `oauth:session_fam:` rows are written at grant-family creation and only
    /// removed when the session is revoked. A family that simply expires (swept
    /// by `sweep_grant_families`) left its index row behind forever.
    #[test]
    fn sweep_expired_reclaims_orphaned_session_family_index_rows() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + ONE_HOUR);
        let session_id = crate::core::SessionId::generate();

        // Family A is still live — its index row must survive.
        let live_family = StoredGrantFamily {
            family_id: "fam-live".into(),
            current_refresh_hash: "h".into(),
            session_id: session_id.clone(),
            realm_id: realm.clone(),
            revoked: false,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + 10 * ONE_HOUR),
            client_id: None,
            resources: Vec::new(),
            amr_values: Vec::new(),
            ua_hash: None,
            bound_asn: None,
            bound_jkt: None,
        };
        s.put(
            &realm,
            &keys::encode_grant_family("fam-live"),
            &serde_json::to_vec(&live_family).expect("serialize"),
        )
        .expect("put family");
        let live_row = keys::encode_session_grant_family(&session_id, "fam-live");
        s.put(&realm, &live_row, &[]).expect("put live row");

        // Family B no longer exists — its index row is unreachable garbage.
        let orphan_row = keys::encode_session_grant_family(&session_id, "fam-gone");
        s.put(&realm, &orphan_row, &[]).expect("put orphan row");

        let stats = sweep_expired(&realm, &s, &clock, &CleanupConfig::default());

        assert_eq!(
            stats.session_family_rows_deleted, 1,
            "only the index row whose grant family is gone may be reclaimed"
        );
        assert!(
            s.get(&realm, &orphan_row).expect("get").is_none(),
            "an index row pointing at a deleted grant family must be reclaimed"
        );
        assert!(
            s.get(&realm, &live_row).expect("get").is_some(),
            "an index row for a live grant family must survive: it is what \
             cascades refresh-token revocation when the session ends"
        );
    }
}
