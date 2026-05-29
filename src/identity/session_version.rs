//! Session-version (`sv`) bump, delta log, and snapshot operations.
//!
//! Implements the server side of HEA-930: per-session monotonic version
//! counters stored at `ssv:sid:{session_id}`, a realm-scoped sequence
//! at `ssv:seq`, and an append-only delta log at `ssv:delta:{seq:020}`.
//!
//! All operations are realm-scoped (storage already enforces this) and
//! WAL-backed via the storage engine's `put` / `put_batch` primitives.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::core::{Clock, RealmId, SessionId, Timestamp, UserId};
use crate::identity::keys;
use crate::storage::StorageEngine;

use super::error::IdentityError;

/// A single entry in the delta log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SvDeltaEntry {
    /// Global bump sequence number for this realm.
    pub seq: u64,
    /// The session whose version was bumped.
    pub session_id: String,
    /// The new minimum acceptable `sv` for `session_id`.
    ///
    /// Resource servers must reject tokens where `sv < min_sv`.
    pub min_sv: u64,
    /// Unix timestamp (seconds) when the bump was recorded.
    pub bumped_at: i64,
}

/// Response from a delta-feed query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SvDeltaResponse {
    pub realm: String,
    /// Use this as `since` on the next poll.
    pub next_seq: u64,
    pub deltas: Vec<SvDeltaEntry>,
}

/// Response from the snapshot endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SvSnapshotResponse {
    pub realm: String,
    /// Current sequence; use as `since` for the first poll after snapshot.
    pub current_seq: u64,
    /// Map of `session_id → min_sv` for all tracked sessions.
    pub versions: HashMap<String, u64>,
}

/// Low-level session-version operations backed by a `StorageEngine`.
///
/// All methods take a realm-scoped storage reference; callers are responsible
/// for passing the correct realm.
pub struct SessionVersionStore {
    storage: Arc<dyn StorageEngine>,
    clock: Arc<dyn Clock>,
}

impl SessionVersionStore {
    pub fn new(storage: Arc<dyn StorageEngine>, clock: Arc<dyn Clock>) -> Self {
        Self { storage, clock }
    }

    /// Returns the current version for `session_id`, or `1` if not yet tracked.
    pub fn get_version(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<u64, IdentityError> {
        let key = keys::encode_ssv_session(session_id);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        {
            Some(bytes) if bytes.len() == 8 => Ok(u64::from_le_bytes(
                bytes[..8].try_into().unwrap_or([0u8; 8]),
            )),
            _ => Ok(1), // initial version for untracked sessions
        }
    }

    /// Increments the session version and appends a delta entry.
    ///
    /// Returns the new version (= new `min_sv` resource servers should reject below).
    pub fn bump(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
        retention_secs: u64,
    ) -> Result<u64, IdentityError> {
        let now: Timestamp = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;

        // Load + increment session version.
        let old_version = self.get_version(realm_id, session_id)?;
        let new_version = old_version + 1;

        // Load + increment global sequence.
        let seq = self.next_seq(realm_id)?;

        // Expire old deltas beyond retention window.
        self.expire_old_deltas(realm_id, now_secs, retention_secs)?;

        let delta = SvDeltaEntry {
            seq,
            session_id: session_id.as_uuid().to_string(),
            min_sv: new_version,
            bumped_at: now_secs,
        };
        let delta_bytes = serde_json::to_vec(&delta).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;

        self.storage
            .put_batch(
                realm_id,
                &[
                    (
                        keys::encode_ssv_session(session_id),
                        new_version.to_le_bytes().to_vec(),
                    ),
                    (keys::encode_ssv_delta(seq), delta_bytes),
                    // seq counter is updated last so readers never see a delta
                    // without the seq counter reflecting it.
                    (keys::ssv_seq_key(), seq.to_le_bytes().to_vec()),
                ],
            )
            .map_err(Self::storage_err)?;

        Ok(new_version)
    }

    /// Bumps the version for every active session owned by `user_id`.
    ///
    /// Scans the `ses:user:{user_id}:` session index, reads each session_id,
    /// then bumps each one. Best-effort: individual bump failures are logged
    /// but do not abort the whole operation.
    pub fn bump_user_sessions(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        retention_secs: u64,
    ) -> Result<usize, IdentityError> {
        let prefix = keys::encode_user_sessions_prefix(user_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;

        let mut bumped = 0usize;
        for entry in &entries {
            // Key format: `ses:user:{user_uuid}:{session_uuid}`
            if let Some(suffix) = entry.key.strip_prefix(prefix.as_slice()) {
                let session_uuid_str = std::str::from_utf8(suffix).unwrap_or("");
                if let Ok(uuid) = uuid::Uuid::parse_str(session_uuid_str) {
                    let sid = SessionId::new(uuid);
                    if let Err(e) = self.bump(realm_id, &sid, retention_secs) {
                        tracing::warn!(
                            realm = %realm_id,
                            session = %sid.as_uuid(),
                            error = %e,
                            "sv bump failed for session"
                        );
                    } else {
                        bumped += 1;
                    }
                }
            }
        }
        Ok(bumped)
    }

    /// Lists delta entries with `seq > since`, up to `limit` entries.
    ///
    /// Returns `None` when `since` is older than the retention window (caller
    /// should fall back to the snapshot endpoint).
    pub fn list_deltas(
        &self,
        realm_id: &RealmId,
        since: u64,
        limit: usize,
    ) -> Result<Option<SvDeltaResponse>, IdentityError> {
        let current_seq = self.current_seq(realm_id)?;

        if since >= current_seq {
            // No new deltas.
            return Ok(Some(SvDeltaResponse {
                realm: realm_id.as_uuid().to_string(),
                next_seq: current_seq,
                deltas: Vec::new(),
            }));
        }

        // Check whether the oldest available delta covers `since`.
        // If the first delta in storage has seq > since+1, the caller has
        // fallen behind the retention window.
        let all_prefix = keys::ssv_delta_scan_prefix();
        let all_end = keys::prefix_end(&all_prefix);
        let first_entries = self
            .storage
            .scan(realm_id, &all_prefix, &all_end)
            .map_err(Self::storage_err)?;
        if !first_entries.is_empty() {
            // decode the first entry's seq
            if let Ok(first_delta) = serde_json::from_slice::<SvDeltaEntry>(&first_entries[0].value)
            {
                if first_delta.seq > since + 1 {
                    // Gap: since is before the oldest retained delta.
                    return Ok(None);
                }
            }
        }

        // Scan from seq = since+1 onward.
        let start_key = keys::encode_ssv_delta(since + 1);
        let end_key = keys::prefix_end(&keys::ssv_delta_scan_prefix());
        let entries = self
            .storage
            .scan(realm_id, &start_key, &end_key)
            .map_err(Self::storage_err)?;

        let mut deltas = Vec::with_capacity(entries.len().min(limit));
        let mut next_seq = current_seq;
        for entry in entries.iter().take(limit) {
            match serde_json::from_slice::<SvDeltaEntry>(&entry.value) {
                Ok(d) => {
                    next_seq = d.seq;
                    deltas.push(d);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to decode sv delta entry");
                }
            }
        }

        Ok(Some(SvDeltaResponse {
            realm: realm_id.as_uuid().to_string(),
            next_seq,
            deltas,
        }))
    }

    /// Returns the full `{session_id → current_version}` map for the realm.
    pub fn snapshot(&self, realm_id: &RealmId) -> Result<SvSnapshotResponse, IdentityError> {
        let current_seq = self.current_seq(realm_id)?;

        let prefix = keys::encode_ssv_session_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;

        let mut versions = HashMap::new();
        for entry in &entries {
            if let Some(suffix) = entry.key.strip_prefix(prefix.as_slice()) {
                let session_uuid_str = std::str::from_utf8(suffix).unwrap_or("");
                if !session_uuid_str.is_empty() {
                    if entry.value.len() == 8 {
                        let v = u64::from_le_bytes(entry.value[..8].try_into().unwrap_or([0u8; 8]));
                        versions.insert(session_uuid_str.to_string(), v);
                    }
                }
            }
        }

        Ok(SvSnapshotResponse {
            realm: realm_id.as_uuid().to_string(),
            current_seq,
            versions,
        })
    }

    /// Bumps all sessions across the entire realm.
    ///
    /// Scans every `ssv:sid:*` key and bumps each one. Heavy operation;
    /// generates O(active_sessions) delta entries.
    pub fn bump_all(
        &self,
        realm_id: &RealmId,
        retention_secs: u64,
    ) -> Result<usize, IdentityError> {
        let prefix = keys::encode_ssv_session_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;

        let mut bumped = 0usize;
        for entry in &entries {
            if let Some(suffix) = entry.key.strip_prefix(prefix.as_slice()) {
                let session_uuid_str = std::str::from_utf8(suffix).unwrap_or("");
                if let Ok(uuid) = uuid::Uuid::parse_str(session_uuid_str) {
                    let sid = SessionId::new(uuid);
                    if let Err(e) = self.bump(realm_id, &sid, retention_secs) {
                        tracing::warn!(
                            realm = %realm_id,
                            session = %sid.as_uuid(),
                            error = %e,
                            "sv bump_all: failed"
                        );
                    } else {
                        bumped += 1;
                    }
                }
            }
        }
        Ok(bumped)
    }

    // ── private helpers ──────────────────────────────────────────────────────

    fn current_seq(&self, realm_id: &RealmId) -> Result<u64, IdentityError> {
        match self
            .storage
            .get(realm_id, &keys::ssv_seq_key())
            .map_err(Self::storage_err)?
        {
            Some(bytes) if bytes.len() == 8 => Ok(u64::from_le_bytes(
                bytes[..8].try_into().unwrap_or([0u8; 8]),
            )),
            _ => Ok(0),
        }
    }

    fn next_seq(&self, realm_id: &RealmId) -> Result<u64, IdentityError> {
        Ok(self.current_seq(realm_id)? + 1)
    }

    /// Deletes delta entries older than `retention_secs`.
    fn expire_old_deltas(
        &self,
        realm_id: &RealmId,
        now_secs: i64,
        retention_secs: u64,
    ) -> Result<(), IdentityError> {
        let cutoff = now_secs.saturating_sub(retention_secs as i64);
        let prefix = keys::ssv_delta_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        for entry in &entries {
            if let Ok(delta) = serde_json::from_slice::<SvDeltaEntry>(&entry.value) {
                if delta.bumped_at < cutoff {
                    let _ = self.storage.delete(realm_id, &entry.key);
                } else {
                    // Entries are ordered by seq (time-monotonic), so we can stop.
                    break;
                }
            }
        }
        Ok(())
    }

    fn storage_err(e: crate::storage::StorageError) -> IdentityError {
        IdentityError::Storage(Box::new(e))
    }
}
