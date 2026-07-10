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
            + self.rate_trackers_pruned
    }
}

/// Runs all entity-type sweeps for a single realm.
///
/// Errors from individual sweeps are logged and counted in
/// [`CleanupStats::errors`]; the function always returns `CleanupStats`
/// (best-effort). The next tick retries any failed sweeps.
pub(crate) fn sweep_expired(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    clock: &dyn Clock,
    config: &CleanupConfig,
) -> CleanupStats {
    let mut stats = CleanupStats::default();
    let now = clock.now();

    match sweep_auth_codes(realm_id, storage, now, config.max_per_type) {
        Ok(n) => stats.auth_codes_deleted = n,
        Err(e) => {
            stats.errors += 1;
            tracing::warn!(
                realm = %realm_id,
                error = %e,
                "cleanup: auth code sweep failed"
            );
        }
    }

    match sweep_device_codes(realm_id, storage, now, config.max_per_type) {
        Ok(n) => stats.device_codes_deleted = n,
        Err(e) => {
            stats.errors += 1;
            tracing::warn!(
                realm = %realm_id,
                error = %e,
                "cleanup: device code sweep failed"
            );
        }
    }

    match sweep_pending_tickets(realm_id, storage, now, config.max_per_type) {
        Ok(n) => stats.pending_tickets_deleted = n,
        Err(e) => {
            stats.errors += 1;
            tracing::warn!(
                realm = %realm_id,
                error = %e,
                "cleanup: pending ticket sweep failed"
            );
        }
    }

    match sweep_grant_families(realm_id, storage, now, config.max_per_type) {
        Ok(n) => stats.grant_families_deleted = n,
        Err(e) => {
            stats.errors += 1;
            tracing::warn!(
                realm = %realm_id,
                error = %e,
                "cleanup: grant family sweep failed"
            );
        }
    }

    match sweep_par_requests(realm_id, storage, now, config.max_per_type) {
        Ok(n) => stats.par_requests_deleted = n,
        Err(e) => {
            stats.errors += 1;
            tracing::warn!(
                realm = %realm_id,
                error = %e,
                "cleanup: PAR request sweep failed"
            );
        }
    }

    let now_secs = now.as_micros() / 1_000_000;
    match sweep_jar_jtis(realm_id, storage, now_secs) {
        Ok(n) => stats.jar_jtis_deleted = n,
        Err(e) => {
            stats.errors += 1;
            tracing::warn!(
                realm = %realm_id,
                error = %e,
                "cleanup: JAR JTI sweep failed"
            );
        }
    }

    match sweep_dpop_jtis(realm_id, storage, now_secs) {
        Ok(n) => stats.dpop_jtis_deleted = n,
        Err(e) => {
            stats.errors += 1;
            tracing::warn!(
                realm = %realm_id,
                error = %e,
                "cleanup: DPoP JTI sweep failed"
            );
        }
    }

    match sweep_actor_jtis(realm_id, storage, now_secs) {
        Ok(n) => stats.actor_jtis_deleted = n,
        Err(e) => {
            stats.errors += 1;
            tracing::warn!(
                realm = %realm_id,
                error = %e,
                "cleanup: actor JTI sweep failed"
            );
        }
    }

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
}
