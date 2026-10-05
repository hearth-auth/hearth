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
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 300,
            max_per_type: 1000,
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
    /// `private_key_jwt` client-assertion JTI replay markers (`oauth:ca-jti:`)
    /// swept (RFC 7523 §2.2).
    ///
    /// One marker is written per assertion-authenticated request at the token
    /// endpoint, `/introspect` and `/revoke`. It only has to outlive the
    /// assertion it guards; past `exp` + clock skew the assertion fails its own
    /// expiry check and the marker is dead weight.
    pub client_assertion_jtis_deleted: u64,
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
    /// OIDC `nonce` replay sentinels (`oauth:nonce:`) swept (22.21).
    ///
    /// A sentinel only has to outlive the authorization code it guards: once
    /// the code's TTL has passed, a replayed `/authorize` carrying the same
    /// nonce cannot yield a usable code anyway. Before 22.21 the replay set
    /// was an in-process `HashMap` swept on every `/authorize`; it is now
    /// replicated storage swept here, once per cleanup pass.
    pub oidc_nonces_deleted: u64,
    /// Single-use redemption markers (`consumed:`) swept (G4).
    ///
    /// One marker is claimed per redeemed PAR `request_uri`, authorization
    /// code and device code. It only has to outlive the artifact it guards
    /// (plus the clock-skew grace); past that the artifact's own expiry check
    /// refuses any second redemption.
    pub consumed_markers_deleted: u64,
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
    /// Delegation parent-index rows (`dgrant:parent:`) swept.
    ///
    /// A row links an exchange's subject token to the grant it created, so a
    /// revoke can reach onward exchanges. Once the child token has expired
    /// there is nothing left to revoke, and the row is dead weight.
    pub delegation_parent_rows_deleted: u64,
    /// Records of minted AATs (`aat:rec:`) swept once the AAT has expired.
    ///
    /// AAT validation reads the record of every chain link. An expired AAT
    /// fails its own `exp` check first, so its record is dead weight.
    pub aat_records_deleted: u64,
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
            + self.client_assertion_jtis_deleted
            + self.saml_states_deleted
            + self.saml_assertions_deleted
            + self.oidc_nonces_deleted
            + self.consumed_markers_deleted
            + self.revoked_jtis_deleted
            + self.session_family_rows_deleted
            + self.delegation_parent_rows_deleted
            + self.aat_records_deleted
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

// One `record` call per key space; splitting it would only scatter the list.
#[allow(clippy::too_many_lines)]
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
        &mut stats.client_assertion_jtis_deleted,
        &mut errors,
        "client-assertion JTI",
        sweep_client_assertion_jtis(realm_id, storage, now_secs),
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
        &mut stats.oidc_nonces_deleted,
        &mut errors,
        "OIDC nonce replay-sentinel",
        sweep_oidc_nonces(realm_id, storage, now_secs),
    );
    record(
        realm_id,
        &mut stats.consumed_markers_deleted,
        &mut errors,
        "single-use redemption marker",
        sweep_consumed_markers(realm_id, storage, now_secs),
    );
    record(
        realm_id,
        &mut stats.delegation_parent_rows_deleted,
        &mut errors,
        "delegation parent index",
        sweep_delegation_parent_index(realm_id, storage, now_secs),
    );
    record(
        realm_id,
        &mut stats.aat_records_deleted,
        &mut errors,
        "AAT record",
        sweep_aat_records(realm_id, storage, now_secs),
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
            // The revocation tombstone lives exactly as long as the row it
            // guards; nothing else removes it (G6).
            storage.delete(
                realm_id,
                &keys::encode_grant_family_revoked(&family.family_id),
            )?;
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

/// Evicts delegation parent-index rows (`dgrant:parent:`) whose child token
/// has expired.
///
/// Each row stores the child token's `exp` as an 8-byte little-endian `i64`
/// (Unix seconds). A row of another size is left for realm-cascade deletion.
pub(crate) fn sweep_delegation_parent_index(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now_secs: i64,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::delegation_grant_parent_scan_prefix();
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

/// Evicts the records of expired AATs (`aat:rec:`).
///
/// A record is the minted claims as JSON; only its `exp` (Unix seconds) is
/// read. A record that does not parse is left for realm-cascade deletion.
pub(crate) fn sweep_aat_records(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now_secs: i64,
) -> Result<u64, crate::storage::StorageError> {
    #[derive(serde::Deserialize)]
    struct Expiry {
        exp: i64,
    }
    let prefix = keys::aat_record_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        let Ok(Expiry { exp }) = serde_json::from_slice(&entry.value) else {
            continue;
        };
        if exp <= now_secs {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Evicts expired `private_key_jwt` client-assertion JTI markers
/// (`oauth:ca-jti:`, RFC 7523 §2.2 replay prevention).
///
/// `verify_client_assertion` writes one marker per assertion-authenticated
/// request at the token endpoint, `/introspect` and `/revoke`. Each stores an
/// 8-byte little-endian `i64`: the assertion's `exp` plus clock skew, in Unix
/// seconds. Past that instant the assertion fails its own expiry check on every
/// node, so the marker no longer prevents anything and is deleted here.
///
/// Rows that are not exactly 8 bytes are the legacy `b"1"` encoding, which
/// records no expiry; they are left for realm-cascade deletion rather than
/// guessed at.
pub(crate) fn sweep_client_assertion_jtis(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now_secs: i64,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::client_assertion_jti_scan_prefix();
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

/// Reclaims expired OIDC `nonce` replay sentinels (`oauth:nonce:` — 22.21).
///
/// Each sentinel stores an 8-byte little-endian `i64` Unix-seconds expiry: the
/// instant the authorization code the nonce guards would itself have expired.
/// Past that point a replayed nonce buys the attacker nothing, so the sentinel
/// is dead weight.
///
/// This replaces a full `retain` over an in-process map that ran on **every**
/// `/authorize` call while holding a global mutex — the reclamation work is
/// the same, but it now happens once per sweep instead of once per request,
/// and off the request path entirely.
pub(crate) fn sweep_oidc_nonces(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now_secs: i64,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::oidc_nonce_scan_prefix();
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

/// Reclaims expired single-use redemption markers (`consumed:` — G4).
///
/// The value is an 8-byte little-endian `i64` expiry in Unix seconds: the
/// guarded artifact's own expiry plus the clock-skew grace. A marker whose
/// value is anything else cannot be dated and is kept — deleting it could make
/// a still-live artifact redeemable again, so the sweep fails closed.
pub(crate) fn sweep_consumed_markers(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now_secs: i64,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::consumed_marker_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        let Ok(bytes) = entry.value.as_slice().try_into() else {
            tracing::warn!(
                realm = %realm_id,
                "cleanup: single-use marker with an unreadable expiry kept"
            );
            continue;
        };
        if i64::from_le_bytes(bytes) <= now_secs {
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
            org_id: None,
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
            mfa_proof: crate::identity::MfaProof::None,
            scope_narrowed: false,
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
            org_id: None,
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
            mfa_proof: crate::identity::MfaProof::None,
            scope_narrowed: false,
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
            mfa_proof: crate::identity::MfaProof::None,
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
            mfa_proof: crate::identity::MfaProof::None,
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
            organization: None,
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
            resource: None,
            amr_values: Vec::new(),
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
            organization: None,
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
            resource: None,
            amr_values: Vec::new(),
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
            bound_jkt: None,
            scope_narrowed: false,
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
            bound_jkt: None,
            scope_narrowed: false,
        };

        let key = keys::encode_grant_family("fid2");
        s.put(
            &realm,
            &key,
            &serde_json::to_vec(&family).expect("serialize"),
        )
        .expect("put");
        let tombstone = keys::encode_grant_family_revoked("fid2");
        s.put(&realm, &tombstone, &[]).expect("put tombstone");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.grant_families_deleted, 1);
        assert!(s.get(&realm, &key).expect("get").is_none());
        assert!(
            s.get(&realm, &tombstone).expect("get tombstone").is_none(),
            "the revocation tombstone outlived the family row it guards"
        );
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
            bound_jkt: None,
            scope_narrowed: false,
        };

        let key = keys::encode_grant_family("fid3");
        s.put(
            &realm,
            &key,
            &serde_json::to_vec(&family).expect("serialize"),
        )
        .expect("put");
        let tombstone = keys::encode_grant_family_revoked("fid3");
        s.put(&realm, &tombstone, &[]).expect("put tombstone");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.grant_families_deleted, 0);
        assert!(s.get(&realm, &key).expect("get").is_some());
        assert!(
            s.get(&realm, &tombstone).expect("get tombstone").is_some(),
            "a live family's revocation tombstone was swept"
        );
    }

    // --- max_per_type ---

    #[test]
    fn sweep_respects_max_per_type() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + 2 * ONE_HOUR);

        for i in 0..5 {
            let code = StoredAuthorizationCode {
                org_id: None,
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
                mfa_proof: crate::identity::MfaProof::None,
                scope_narrowed: false,
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

    const NOW_SECS: i64 = 1_700_000_000; // fixed base time in Unix seconds

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
    fn sweep_delegation_parent_index_deletes_rows_of_expired_children() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let expired = keys::encode_delegation_grant_parent_index("parent", "expired-child");
        let live = keys::encode_delegation_grant_parent_index("parent", "live-child");
        s.put(&realm, &expired, &(NOW_SECS - 1).to_le_bytes())
            .expect("put expired");
        s.put(&realm, &live, &(NOW_SECS + 300).to_le_bytes())
            .expect("put live");

        let deleted = sweep_delegation_parent_index(&realm, &s, NOW_SECS).expect("sweep");
        assert_eq!(deleted, 1, "only the expired child's row is removed");
        assert!(s.get(&realm, &expired).expect("get").is_none());
        assert!(s.get(&realm, &live).expect("get").is_some());
    }

    #[test]
    fn sweep_aat_records_deletes_records_of_expired_aats() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let expired = keys::encode_aat_record("expired");
        let live = keys::encode_aat_record("live");
        s.put(
            &realm,
            &expired,
            format!(r#"{{"exp":{}}}"#, NOW_SECS - 1).as_bytes(),
        )
        .expect("put expired");
        s.put(
            &realm,
            &live,
            format!(r#"{{"exp":{}}}"#, NOW_SECS + 300).as_bytes(),
        )
        .expect("put live");

        let deleted = sweep_aat_records(&realm, &s, NOW_SECS).expect("sweep");
        assert_eq!(deleted, 1, "only the expired AAT's record is removed");
        assert!(s.get(&realm, &expired).expect("get").is_none());
        assert!(s.get(&realm, &live).expect("get").is_some());
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

    // ── single-use redemption markers (`consumed:`) ─────────────────────

    fn seed_marker(s: &EmbeddedStorageEngine, realm: &RealmId, key: &[u8], expires_at: i64) {
        s.put(realm, key, &expires_at.to_le_bytes())
            .expect("put consumed marker");
    }

    #[test]
    fn sweep_consumed_markers_deletes_expired_keeps_active_for_every_kind() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let expired = [
            keys::encode_consumed_par("par-old"),
            keys::encode_consumed_code("code-old"),
            keys::encode_consumed_device_code("device-old"),
            keys::encode_consumed_magic_link("magic-old"),
            keys::encode_consumed_password_reset("reset-old"),
            keys::encode_consumed_email_verify("verify-old"),
            keys::encode_consumed_refresh("refresh-old"),
        ];
        let live = [
            keys::encode_consumed_par("par-live"),
            keys::encode_consumed_code("code-live"),
            keys::encode_consumed_device_code("device-live"),
            keys::encode_consumed_magic_link("magic-live"),
            keys::encode_consumed_password_reset("reset-live"),
            keys::encode_consumed_email_verify("verify-live"),
            keys::encode_consumed_refresh("refresh-live"),
        ];
        for key in &expired {
            seed_marker(&s, &realm, key, NOW_SECS);
        }
        for key in &live {
            seed_marker(&s, &realm, key, NOW_SECS + 1);
        }

        let deleted = sweep_consumed_markers(&realm, &s, NOW_SECS).expect("sweep");
        assert_eq!(deleted, 7, "exactly the markers at or past expiry go");
        for key in &expired {
            assert!(s.get(&realm, key).expect("get").is_none(), "{key:?} kept");
        }
        for key in &live {
            assert!(s.get(&realm, key).expect("get").is_some(), "{key:?} swept");
        }
    }

    /// A marker whose expiry cannot be read is kept: deleting it could make a
    /// still-live artifact redeemable again, so the sweep fails closed.
    #[test]
    fn sweep_consumed_markers_keeps_a_marker_it_cannot_date() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let key = keys::encode_consumed_par("undatable");
        s.put(&realm, &key, b"1").expect("put");

        let deleted = sweep_consumed_markers(&realm, &s, NOW_SECS).expect("sweep");
        assert_eq!(deleted, 0);
        assert!(s.get(&realm, &key).expect("get").is_some());
    }

    #[test]
    fn sweep_consumed_markers_is_realm_scoped() {
        let (s, _dir) = storage();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();
        let key = keys::encode_consumed_code("shared-hash");
        seed_marker(&s, &realm_a, &key, NOW_SECS - 1);
        seed_marker(&s, &realm_b, &key, NOW_SECS - 1);

        assert_eq!(
            sweep_consumed_markers(&realm_a, &s, NOW_SECS).expect("sweep a"),
            1
        );
        assert!(
            s.get(&realm_b, &key).expect("get").is_some(),
            "realm_b's marker must be untouched by realm_a's sweep"
        );
    }

    #[test]
    fn sweep_expired_includes_consumed_markers() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + ONE_HOUR);
        let now_secs = (T0 + ONE_HOUR) / 1_000_000;
        seed_marker(&s, &realm, &keys::encode_consumed_par("gone"), now_secs - 1);
        seed_marker(
            &s,
            &realm,
            &keys::encode_consumed_par("kept"),
            now_secs + 60,
        );

        let stats = sweep_expired(&realm, &s, &clock, &CleanupConfig::default());
        assert_eq!(stats.consumed_markers_deleted, 1);
        assert_eq!(stats.errors, 0);
        assert!(stats.total_deleted() >= 1);
    }

    // --- private_key_jwt client-assertion JTI sweep ---

    fn seed_ca_jti(s: &EmbeddedStorageEngine, realm: &RealmId, jti: &str, expires_at: i64) {
        s.put(
            realm,
            &keys::encode_client_assertion_jti(jti),
            &expires_at.to_le_bytes(),
        )
        .expect("put client-assertion jti");
    }

    #[test]
    fn sweep_client_assertion_jtis_deletes_expired_keeps_active() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();

        seed_ca_jti(&s, &realm, "ca-expired", NOW_SECS - 1);
        seed_ca_jti(&s, &realm, "ca-boundary", NOW_SECS);
        seed_ca_jti(&s, &realm, "ca-active", NOW_SECS + 1);

        let deleted = sweep_client_assertion_jtis(&realm, &s, NOW_SECS).expect("sweep");
        assert_eq!(
            deleted, 2,
            "expired and exactly-now entries must be removed"
        );
        for (jti, present) in [
            ("ca-expired", false),
            ("ca-boundary", false),
            ("ca-active", true),
        ] {
            assert_eq!(
                s.get(&realm, &keys::encode_client_assertion_jti(jti))
                    .expect("get")
                    .is_some(),
                present,
                "{jti}: expected present={present}"
            );
        }
    }

    #[test]
    fn sweep_client_assertion_jtis_leaves_legacy_and_malformed_rows() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();

        seed_ca_jti(&s, &realm, "ca-expired", NOW_SECS - 1);
        let legacy = keys::encode_client_assertion_jti("ca-legacy");
        s.put(&realm, &legacy, b"1").expect("put legacy");

        let deleted = sweep_client_assertion_jtis(&realm, &s, NOW_SECS).expect("sweep");
        assert_eq!(deleted, 1, "only the expiry-carrying row is reclaimable");
        assert!(
            s.get(&realm, &legacy).expect("get").is_some(),
            "a legacy b\"1\" row carries no expiry and must not be deleted"
        );
    }

    #[test]
    fn sweep_client_assertion_jtis_isolated_across_realms() {
        let (s, _dir) = storage();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        seed_ca_jti(&s, &realm_a, "ca-a", NOW_SECS - 1);
        seed_ca_jti(&s, &realm_b, "ca-b", NOW_SECS - 1);

        assert_eq!(
            sweep_client_assertion_jtis(&realm_a, &s, NOW_SECS).expect("sweep a"),
            1
        );
        assert!(
            s.get(&realm_b, &keys::encode_client_assertion_jti("ca-b"))
                .expect("get")
                .is_some(),
            "sweeping realm_a must not touch realm_b"
        );
    }

    #[test]
    fn sweep_expired_includes_client_assertion_jtis() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + ONE_HOUR);
        let now_secs = (T0 + ONE_HOUR) / 1_000_000;

        seed_ca_jti(&s, &realm, "ca-expired", now_secs - 60);
        seed_ca_jti(&s, &realm, "ca-live", now_secs + 60);

        let stats = sweep_expired(&realm, &s, &clock, &CleanupConfig::default());
        assert_eq!(
            stats.client_assertion_jtis_deleted, 1,
            "sweep_expired must include the client-assertion JTI sweep"
        );
        assert_eq!(stats.errors, 0);
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
            bound_jkt: None,
            scope_narrowed: false,
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
