//! Embedded audit engine implementation.
//!
//! Stores audit events in the storage engine with hash chain integrity.
//! Events are append-only: no update or delete operations exist.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ring::hmac;
use ring::rand::SecureRandom as _;

use crate::codec;
use crate::core::{AuditEventId, Clock, RealmId, Timestamp};
use crate::storage::StorageEngine;

use super::error::AuditError;
use super::keys;
use super::types::{AuditAction, AuditEvent, AuditQuery, AuditRetentionConfig, CreateAuditEvent};
use super::AuditEngine;

/// The genesis hash used as the "previous hash" for the first event in a realm.
const GENESIS_HASH: &str = "genesis";

/// Compact binary storage record for an audit event (HEA-1899).
///
/// Fields mirror [`AuditEvent`] except:
/// - `integrity_hash` is 32 raw HMAC-SHA256 bytes instead of 64-char hex (saves 32 B).
/// - `metadata` is raw JSON bytes instead of `serde_json::Value` (avoids the
///   postcard-encoding a recursive JSON enum, keeps the exact JSON bytes needed
///   for HMAC verification on re-read).
///
/// Serialised with `postcard` via [`crate::codec`].  The format is NOT
/// self-describing; field order matches declaration order and must not change
/// without a storage-format migration note (greenfield = no compat required).
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredAuditEvent {
    id: AuditEventId,
    realm_id: RealmId,
    actor: String,
    action: AuditAction,
    resource_type: String,
    resource_id: String,
    timestamp: Timestamp,
    /// Raw JSON bytes of the metadata object, or `None`.
    metadata_json: Option<Vec<u8>>,
    /// HMAC-SHA256 integrity hash as 32 raw bytes.
    integrity_hash: [u8; 32],
}

impl StoredAuditEvent {
    fn from_event(event: &AuditEvent) -> Result<Self, AuditError> {
        let hash_bytes: [u8; 32] = hex_decode(&event.integrity_hash)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| AuditError::Serialization {
                reason: "integrity_hash must be 64-char lowercase hex (HMAC-SHA256)".into(),
            })?;

        let metadata_json = event
            .metadata
            .as_ref()
            .map(|m| serde_json::to_vec(m))
            .transpose()
            .map_err(|e| AuditError::Serialization {
                reason: e.to_string(),
            })?;

        Ok(Self {
            id: event.id.clone(),
            realm_id: event.realm_id.clone(),
            actor: event.actor.clone(),
            action: event.action.clone(),
            resource_type: event.resource_type.clone(),
            resource_id: event.resource_id.clone(),
            timestamp: event.timestamp,
            metadata_json,
            integrity_hash: hash_bytes,
        })
    }

    fn into_event(self) -> Result<AuditEvent, AuditError> {
        let metadata = self
            .metadata_json
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(|e| AuditError::Serialization {
                reason: e.to_string(),
            })?;

        Ok(AuditEvent {
            id: self.id,
            realm_id: self.realm_id,
            actor: self.actor,
            action: self.action,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            timestamp: self.timestamp,
            metadata,
            integrity_hash: hex_encode(&self.integrity_hash),
        })
    }
}

/// Serialises an audit event for storage using compact binary encoding.
fn encode_event(event: &AuditEvent) -> Result<Vec<u8>, AuditError> {
    let record = StoredAuditEvent::from_event(event)?;
    codec::encode(&record).map_err(|e| AuditError::Serialization { reason: e })
}

/// Deserialises an audit event from its compact binary storage representation.
fn decode_event(bytes: &[u8]) -> Result<AuditEvent, AuditError> {
    let record: StoredAuditEvent =
        codec::decode(bytes).map_err(|e| AuditError::Serialization { reason: e })?;
    record.into_event()
}

/// Persisted, HMAC-signed summary of a realm's audit chain (HEA-1756).
///
/// Per-event hashing alone cannot detect two attacks:
///
/// * **Tail truncation (U3):** deleting the newest events leaves a chain that
///   is still internally consistent. `count` and `last_hash` pin the expected
///   end of the chain, so a shortened log is detected.
/// * **Prune invalidation (U2):** retention pruning removes the events that
///   later events chain from. `anchor` records the `prev_hash` that the first
///   *surviving* event chains from, so verification re-anchors instead of
///   failing.
///
/// The `mac` is `HMAC-SHA256(realm_key, canonical_fields)`, so a storage-layer
/// attacker who cannot recover the per-realm key cannot forge a head to match a
/// truncated or reordered log.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ChainHead {
    /// The `prev_hash` the first live event chains from: `GENESIS_HASH` for an
    /// un-pruned chain, or the last-pruned event's hash after a prune.
    anchor: String,
    /// Integrity hash of the most recent live event, or `anchor` when the chain
    /// currently holds no events.
    last_hash: String,
    /// Monotonic per-realm sequence: the value assigned to the most recent
    /// append. Never decreases, even across prunes; the next append uses
    /// `seq + 1`. Embedded in each event's primary key to force deterministic
    /// scan order (U1).
    seq: u64,
    /// Number of live events currently retained in the chain.
    count: u64,
    /// HMAC-SHA256 tag (hex) over `anchor|last_hash|seq|count`.
    mac: String,
}

/// Embedded audit engine backed by the storage layer.
///
/// Thread-safe via the underlying `StorageEngine`. Hash-chain correctness
/// requires that appends within a single realm be serialized; a per-realm
/// mutex ensures each `append` observes the previous event's hash before
/// computing its own. The hash chain is inherently sequential, so this is
/// correctness, not just a performance cache.
///
/// Each realm gets a unique 32-byte HMAC-SHA256 key stored under
/// `audit:hmac:key` (KEK-wrapped when a key-encryption key is configured).
/// This prevents a storage-layer attacker from recomputing a valid chain
/// without knowledge of the key.
pub struct EmbeddedAuditEngine {
    /// Storage backend.
    storage: Arc<dyn StorageEngine>,
    /// Clock for timestamps.
    clock: Arc<dyn Clock>,
    /// Per-realm serialization of the hash-chain read-modify-write cycle,
    /// with an optional cached [`ChainHead`] to avoid re-reading the persisted
    /// head (and the `O(n)` scan) on every append after the first.
    chain_locks: Mutex<HashMap<RealmId, Arc<Mutex<Option<ChainHead>>>>>,
    /// Optional key-encryption key; when set, per-realm HMAC keys are
    /// AES-256-GCM-wrapped at rest.
    kek: Option<[u8; 32]>,
    /// Cached per-realm HMAC key material (32 bytes each). Lazy-initialized
    /// on first access per realm; never evicted (realm IDs are stable).
    hmac_key_cache: Mutex<HashMap<RealmId, [u8; 32]>>,
}

impl EmbeddedAuditEngine {
    /// Creates a new audit engine.
    pub fn new(storage: Arc<dyn StorageEngine>, clock: Arc<dyn Clock>) -> Self {
        Self {
            storage,
            clock,
            chain_locks: Mutex::new(HashMap::new()),
            kek: None,
            hmac_key_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Configures a KEK so that per-realm audit HMAC keys are wrapped at rest.
    ///
    /// Must be called before any `append` or `verify_integrity` — keys are
    /// generated on first use and the wrapping applied at generation time.
    #[must_use]
    pub fn with_kek(mut self, kek: Option<[u8; 32]>) -> Self {
        self.kek = kek;
        self
    }

    /// Returns (or lazily creates) the per-realm HMAC key.
    fn get_realm_hmac_key(&self, realm_id: &RealmId) -> Result<[u8; 32], AuditError> {
        {
            let cache = self.hmac_key_cache.lock().expect("hmac_key_cache poisoned");
            if let Some(k) = cache.get(realm_id) {
                return Ok(*k);
            }
        }

        let storage_key = keys::audit_hmac_key();
        let key_bytes: [u8; 32] = match self.storage.get(realm_id, &storage_key)? {
            Some(raw) => {
                let plaintext =
                    crate::identity::key_encryption::unwrap_key(&raw, self.kek.as_ref()).map_err(
                        |e| AuditError::Serialization {
                            reason: format!("audit HMAC key unwrap failed: {e}"),
                        },
                    )?;
                if plaintext.len() != 32 {
                    return Err(AuditError::Serialization {
                        reason: format!(
                            "audit HMAC key has wrong length: {} (expected 32)",
                            plaintext.len()
                        ),
                    });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&plaintext);
                arr
            }
            None => {
                let rng = ring::rand::SystemRandom::new();
                let mut key = [0u8; 32];
                rng.fill(&mut key).map_err(|_| AuditError::Serialization {
                    reason: "failed to generate audit HMAC key".into(),
                })?;
                let wrapped = crate::identity::key_encryption::wrap_key(&key, self.kek.as_ref())
                    .map_err(|e| AuditError::Serialization {
                        reason: format!("audit HMAC key wrap failed: {e}"),
                    })?;
                self.storage.put(realm_id, &storage_key, &wrapped)?;
                key
            }
        };

        let mut cache = self.hmac_key_cache.lock().expect("hmac_key_cache poisoned");
        cache.insert(realm_id.clone(), key_bytes);
        Ok(key_bytes)
    }

    /// Returns the per-realm chain lock, creating it on first access.
    fn realm_chain_lock(&self, realm_id: &RealmId) -> Arc<Mutex<Option<ChainHead>>> {
        let mut map = self.chain_locks.lock().expect("chain_locks mutex poisoned");
        if let Some(lock) = map.get(realm_id) {
            Arc::clone(lock)
        } else {
            let lock = Arc::new(Mutex::new(None));
            map.insert(realm_id.clone(), Arc::clone(&lock));
            lock
        }
    }

    /// Computes the HMAC-SHA256 integrity hash for an event.
    ///
    /// `Hash = HMAC-SHA256(realm_hmac_key, prev_hash || event_data_json)`
    ///
    /// The keyed MAC prevents a storage-layer attacker from recomputing a valid
    /// chain after deleting or modifying events — they would need the per-realm
    /// HMAC key (KEK-protected when configured) to forge a tag.
    fn compute_hmac_hash(hmac_key_bytes: &[u8], prev_hash: &str, event: &AuditEvent) -> String {
        let hashable = serde_json::json!({
            "id": event.id,
            "realm_id": event.realm_id,
            "actor": event.actor,
            "action": event.action,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "timestamp": event.timestamp,
            "metadata": event.metadata,
        });

        let event_bytes = hashable.to_string();
        let mut data = Vec::with_capacity(prev_hash.len() + event_bytes.len());
        data.extend_from_slice(prev_hash.as_bytes());
        data.extend_from_slice(event_bytes.as_bytes());

        let key = hmac::Key::new(hmac::HMAC_SHA256, hmac_key_bytes);
        let tag = hmac::sign(&key, &data);
        hex_encode(tag.as_ref())
    }

    /// Computes the HMAC-SHA256 tag (hex) over the chain-head fields.
    ///
    /// The canonical input `anchor|last_hash|seq|count` binds every field that
    /// verification relies on, so a storage-layer attacker cannot alter the
    /// recorded end-of-chain, re-anchor value, or event count without the
    /// per-realm key.
    fn compute_head_mac(
        hmac_key: &[u8],
        anchor: &str,
        last_hash: &str,
        seq: u64,
        count: u64,
    ) -> String {
        let input = Self::head_mac_input(anchor, last_hash, seq, count);
        let key = hmac::Key::new(hmac::HMAC_SHA256, hmac_key);
        let tag = hmac::sign(&key, input.as_bytes());
        hex_encode(tag.as_ref())
    }

    /// Canonical byte-string fed to the chain-head MAC.
    fn head_mac_input(anchor: &str, last_hash: &str, seq: u64, count: u64) -> String {
        format!("{anchor}|{last_hash}|{seq}|{count}")
    }

    /// Builds a [`ChainHead`] with a freshly computed MAC.
    fn signed_head(
        hmac_key: &[u8],
        anchor: String,
        last_hash: String,
        seq: u64,
        count: u64,
    ) -> ChainHead {
        let mac = Self::compute_head_mac(hmac_key, &anchor, &last_hash, seq, count);
        ChainHead {
            anchor,
            last_hash,
            seq,
            count,
            mac,
        }
    }

    /// Serializes a chain head for storage.
    fn head_bytes(head: &ChainHead) -> Result<Vec<u8>, AuditError> {
        serde_json::to_vec(head).map_err(|e| AuditError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Loads and MAC-verifies the persisted chain head, if any.
    ///
    /// Returns `Ok(None)` when no head has been persisted yet, and
    /// [`AuditError::IntegrityViolation`] when a head exists but its MAC does
    /// not match — i.e. the head record itself was tampered.
    fn load_head(
        &self,
        realm_id: &RealmId,
        hmac_key: &[u8],
    ) -> Result<Option<ChainHead>, AuditError> {
        let key = keys::chain_head_key();
        match self.storage.get(realm_id, &key)? {
            Some(bytes) => {
                let head: ChainHead =
                    serde_json::from_slice(&bytes).map_err(|e| AuditError::Serialization {
                        reason: e.to_string(),
                    })?;
                // Constant-time verification via `hmac::verify`: recompute the
                // tag over the canonical fields and compare against the stored
                // (hex-decoded) tag. A malformed or non-matching tag means the
                // head record was tampered.
                let input =
                    Self::head_mac_input(&head.anchor, &head.last_hash, head.seq, head.count);
                let stored_tag =
                    hex_decode(&head.mac).ok_or_else(|| AuditError::IntegrityViolation {
                        reason: "audit chain head MAC is not valid hex".to_string(),
                    })?;
                let key = hmac::Key::new(hmac::HMAC_SHA256, hmac_key);
                if hmac::verify(&key, input.as_bytes(), &stored_tag).is_err() {
                    return Err(AuditError::IntegrityViolation {
                        reason: "audit chain head MAC mismatch".to_string(),
                    });
                }
                Ok(Some(head))
            }
            None => Ok(None),
        }
    }

    /// Loads the chain head, bootstrapping one from existing events when no head
    /// has been persisted yet (fresh realm or a log written before the head was
    /// introduced).
    fn load_or_init_head(
        &self,
        realm_id: &RealmId,
        hmac_key: &[u8],
    ) -> Result<ChainHead, AuditError> {
        if let Some(head) = self.load_head(realm_id, hmac_key)? {
            return Ok(head);
        }

        let prefix = keys::event_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;
        let count = entries.len() as u64;
        let last_hash = if let Some(last) = entries.last() {
            decode_event(&last.value)?.integrity_hash
        } else {
            GENESIS_HASH.to_string()
        };
        Ok(Self::signed_head(
            hmac_key,
            GENESIS_HASH.to_string(),
            last_hash,
            count,
            count,
        ))
    }

    /// Plans a prune of a chronological prefix of events.
    ///
    /// Given the entries to remove (in ascending key order), returns the
    /// re-anchored [`ChainHead`], the flat list of keys to delete (primary plus
    /// both secondary indexes per event), and the number of events pruned.
    ///
    /// The new `anchor` is the integrity hash of the newest pruned event — i.e.
    /// the `prev_hash` that the first surviving event chains from — so the
    /// retained window still verifies (HEA-1756 U2). When every event is pruned
    /// the head's `last_hash` collapses onto the anchor so the next append
    /// continues the chain unbroken.
    fn plan_prune<'a, I>(
        &self,
        hmac_key: &[u8],
        head: &ChainHead,
        entries: I,
    ) -> Result<(ChainHead, Vec<Vec<u8>>, u64), AuditError>
    where
        I: Iterator<Item = &'a crate::storage::ScanEntry>,
    {
        let mut delete_keys: Vec<Vec<u8>> = Vec::new();
        let mut anchor = head.anchor.clone();
        let mut deleted: u64 = 0;

        for entry in entries {
            let event = decode_event(&entry.value)?;
            let actor_key = keys::encode_actor_index(&event.actor, event.timestamp, &event.id);
            let action_key =
                keys::encode_action_index(event.action.as_str(), event.timestamp, &event.id);
            delete_keys.push(entry.key.clone());
            delete_keys.push(actor_key);
            delete_keys.push(action_key);
            // Entries are ascending, so the last iteration leaves `anchor` at
            // the newest pruned event's hash.
            anchor = event.integrity_hash;
            deleted += 1;
        }

        let new_count = head.count.saturating_sub(deleted);
        let last_hash = if new_count == 0 {
            anchor.clone()
        } else {
            head.last_hash.clone()
        };
        let new_head = Self::signed_head(hmac_key, anchor, last_hash, head.seq, new_count);
        Ok((new_head, delete_keys, deleted))
    }
}

impl AuditEngine for EmbeddedAuditEngine {
    fn append(&self, request: &CreateAuditEvent) -> Result<AuditEvent, AuditError> {
        // Acquire the per-realm chain lock BEFORE reading the last hash. The
        // chain's integrity guarantee ("every event's prev_hash is the
        // previous event's integrity_hash") is only preserved if no other
        // append can interleave between our read of last_hash and our
        // storage write. The lock doubles as a cache for the last hash
        // to avoid a full O(n) scan per append after the first.
        let chain_lock = self.realm_chain_lock(&request.realm_id);
        let mut cached = chain_lock.lock().expect("realm chain lock poisoned");

        let hmac_key = self.get_realm_hmac_key(&request.realm_id)?;

        // The signed head is the source of truth for the previous hash and the
        // monotonic sequence. Prefer the cache; otherwise load (and MAC-verify)
        // the persisted head so tampering with it fails the append fast.
        let head = match cached.as_ref() {
            Some(h) => h.clone(),
            None => self.load_or_init_head(&request.realm_id, &hmac_key)?,
        };
        let prev_hash = head.last_hash.clone();
        let seq = head.seq + 1;

        let event_id = AuditEventId::generate();
        let timestamp = self.clock.now();

        // Build the event (integrity_hash will be filled after computation)
        let mut event = AuditEvent {
            id: event_id,
            realm_id: request.realm_id.clone(),
            actor: request.actor.clone(),
            action: request.action.clone(),
            resource_type: request.resource_type.clone(),
            resource_id: request.resource_id.clone(),
            timestamp,
            metadata: request.metadata.clone(),
            integrity_hash: String::new(),
        };

        // Compute and set HMAC-SHA256 integrity hash.
        event.integrity_hash = Self::compute_hmac_hash(&hmac_key, &prev_hash, &event);

        // Serialise the complete event using compact binary encoding (HEA-1899).
        let value = encode_event(&event)?;

        // Single atomic write: primary + actor index + action index + the
        // updated signed head all land together, or not at all. `put_batch`
        // guarantees that a crash mid-write can never leave a "half-indexed"
        // event or a head that disagrees with the persisted events. This is
        // what makes the hash chain recoverable and tail-truncation-detectable:
        // every persisted event is fully observable through every query path,
        // and the head always reflects exactly the events on disk.
        let primary_key = keys::encode_event_key(timestamp, seq, &event.id);
        let actor_key = keys::encode_actor_index(&request.actor, timestamp, &event.id);
        let action_key = keys::encode_action_index(request.action.as_str(), timestamp, &event.id);

        let new_head = Self::signed_head(
            &hmac_key,
            head.anchor.clone(),
            event.integrity_hash.clone(),
            seq,
            head.count + 1,
        );
        let head_value = Self::head_bytes(&new_head)?;

        self.storage.put_batch(
            &request.realm_id,
            &[
                (primary_key.clone(), value),
                (actor_key, primary_key.clone()),
                (action_key, primary_key),
                (keys::chain_head_key(), head_value),
            ],
        )?;

        // Only advance the cached head after the storage write succeeds. On
        // error we leave the cache unchanged so the next append will re-read
        // the persisted head and recover from whatever state actually landed.
        *cached = Some(new_head);

        Ok(event)
    }

    fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, AuditError> {
        // Determine if we're scanning by actor, action, or just time range
        if let Some(ref actor) = query.actor {
            let mut events = self.query_by_actor(query, actor)?;
            events = Self::apply_metadata_filters(events, query);
            return Ok(events);
        }
        if let Some(ref action) = query.action {
            let mut events = self.query_by_action(query, action)?;
            events = Self::apply_metadata_filters(events, query);
            return Ok(events);
        }

        // Default: scan primary event keys by time range
        let start = match query.start_time {
            Some(ts) => keys::event_scan_start(ts),
            None => keys::event_scan_prefix(),
        };
        let end = match query.end_time {
            Some(ts) => keys::event_scan_end(ts),
            None => keys::prefix_end(&keys::event_scan_prefix()),
        };

        let entries = self.storage.scan(&query.realm_id, &start, &end)?;
        let mut events = Vec::new();

        for entry in entries {
            let event = decode_event(&entry.value)?;

            // Apply agent_id / tool metadata filters before counting toward limit.
            if !Self::event_matches_metadata_filters(&event, query) {
                continue;
            }

            events.push(event);

            if let Some(limit) = query.limit {
                if events.len() >= limit {
                    break;
                }
            }
        }

        Ok(events)
    }

    fn verify_integrity(
        &self,
        realm_id: &RealmId,
        start: Option<Timestamp>,
        end: Option<Timestamp>,
    ) -> Result<bool, AuditError> {
        let scan_start = match start {
            Some(ts) => keys::event_scan_start(ts),
            None => keys::event_scan_prefix(),
        };
        let scan_end = match end {
            Some(ts) => keys::event_scan_end(ts),
            None => keys::prefix_end(&keys::event_scan_prefix()),
        };

        let entries = self.storage.scan(realm_id, &scan_start, &scan_end)?;

        let hmac_key = self.get_realm_hmac_key(realm_id)?;

        // A tampered head (bad MAC) is itself a tamper signal.
        let head = match self.load_head(realm_id, &hmac_key) {
            Ok(h) => h,
            Err(AuditError::IntegrityViolation { .. }) => {
                crate::metrics::metrics()
                    .audit_integrity_failures_total
                    .inc();
                return Ok(false);
            }
            Err(e) => return Err(e),
        };

        let full_range = start.is_none() && end.is_none();

        // Determine the starting `prev_hash`. When verifying from the beginning
        // we chain from the persisted anchor — `GENESIS_HASH` for an un-pruned
        // chain, or the last-pruned event's hash after a retention prune
        // (HEA-1756 U2). Sub-range verification chains from the event
        // immediately before `start`.
        let mut prev_hash = if start.is_none() {
            head.as_ref()
                .map_or_else(|| GENESIS_HASH.to_string(), |h| h.anchor.clone())
        } else {
            let all_start = keys::event_scan_prefix();
            let all_entries = self.storage.scan(realm_id, &all_start, &scan_start)?;
            if let Some(last) = all_entries.last() {
                decode_event(&last.value)?.integrity_hash
            } else {
                GENESIS_HASH.to_string()
            }
        };

        let mut count: u64 = 0;
        for entry in entries {
            let event = decode_event(&entry.value)?;

            let expected_hash = Self::compute_hmac_hash(&hmac_key, &prev_hash, &event);
            if event.integrity_hash != expected_hash {
                crate::metrics::metrics()
                    .audit_integrity_failures_total
                    .inc();
                return Ok(false);
            }
            prev_hash = event.integrity_hash;
            count += 1;
        }

        // Tail-truncation detection (HEA-1756 U3): on a full-range verification
        // the walked chain must end exactly where the signed head says it does.
        // Deleting the newest events leaves an internally consistent chain, but
        // the event count and final hash will no longer match the head.
        if full_range {
            if let Some(head) = head {
                if count != head.count || prev_hash != head.last_hash {
                    crate::metrics::metrics()
                        .audit_integrity_failures_total
                        .inc();
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    fn get_retention_config(&self, realm_id: &RealmId) -> Result<AuditRetentionConfig, AuditError> {
        let key = keys::retention_config_key();
        match self.storage.get(realm_id, &key)? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| AuditError::Serialization {
                reason: e.to_string(),
            }),
            None => Ok(AuditRetentionConfig::default()),
        }
    }

    fn set_retention_config(
        &self,
        realm_id: &RealmId,
        config: &AuditRetentionConfig,
    ) -> Result<(), AuditError> {
        let key = keys::retention_config_key();
        let value = serde_json::to_vec(config).map_err(|e| AuditError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage.put(realm_id, &key, &value)?;
        Ok(())
    }

    fn prune_before(&self, realm_id: &RealmId, cutoff: Timestamp) -> Result<u64, AuditError> {
        // Serialize against appends so the head read-modify-write is coherent.
        let chain_lock = self.realm_chain_lock(realm_id);
        let mut cached = chain_lock.lock().expect("realm chain lock poisoned");

        let start = keys::event_scan_prefix();
        let end = keys::event_scan_end(cutoff);
        let entries = self.storage.scan(realm_id, &start, &end)?;
        if entries.is_empty() {
            return Ok(0);
        }

        let hmac_key = self.get_realm_hmac_key(realm_id)?;
        let head = match cached.as_ref() {
            Some(h) => h.clone(),
            None => self.load_or_init_head(realm_id, &hmac_key)?,
        };

        let (new_head, delete_keys, deleted) = self.plan_prune(&hmac_key, &head, entries.iter())?;
        let head_value = Self::head_bytes(&new_head)?;

        // One atomic WAL record: every pruned key removed and the re-anchored
        // head written together (HEA-1756 U2). A crash can never leave the head
        // and the surviving events inconsistent, so verification never raises a
        // false tamper alarm after a prune.
        self.storage.write_batch(
            realm_id,
            &[(keys::chain_head_key(), head_value)],
            &delete_keys,
        )?;

        *cached = Some(new_head);
        Ok(deleted)
    }

    fn count_events(&self, realm_id: &RealmId) -> Result<u64, AuditError> {
        let prefix = keys::event_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;
        Ok(entries.len() as u64)
    }

    fn prune_oldest(&self, realm_id: &RealmId, n: u64) -> Result<u64, AuditError> {
        // Serialize against appends so the head read-modify-write is coherent.
        let chain_lock = self.realm_chain_lock(realm_id);
        let mut cached = chain_lock.lock().expect("realm chain lock poisoned");

        // Scan all primary event keys in chronological order (keys encode the
        // timestamp then the monotonic sequence, so lexicographic order equals
        // append order).
        let prefix = keys::event_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;

        let to_delete = (n as usize).min(entries.len());
        if to_delete == 0 {
            return Ok(0);
        }

        let hmac_key = self.get_realm_hmac_key(realm_id)?;
        let head = match cached.as_ref() {
            Some(h) => h.clone(),
            None => self.load_or_init_head(realm_id, &hmac_key)?,
        };

        let (new_head, delete_keys, deleted) =
            self.plan_prune(&hmac_key, &head, entries.iter().take(to_delete))?;
        let head_value = Self::head_bytes(&new_head)?;

        // One atomic WAL record — see `prune_before` (HEA-1756 U2).
        self.storage.write_batch(
            realm_id,
            &[(keys::chain_head_key(), head_value)],
            &delete_keys,
        )?;

        *cached = Some(new_head);
        Ok(deleted)
    }
}

impl EmbeddedAuditEngine {
    /// Applies `agent_id` and `tool` post-scan filters (§12.4 MUST).
    ///
    /// These filters match against the JSON `metadata` object attached to
    /// each audit event, which is cheaper to scan post-hoc than maintaining
    /// additional secondary indexes for every metadata key.
    fn apply_metadata_filters(events: Vec<AuditEvent>, query: &AuditQuery) -> Vec<AuditEvent> {
        if query.agent_id.is_none() && query.tool.is_none() {
            return events;
        }
        events
            .into_iter()
            .filter(|e| Self::event_matches_metadata_filters(e, query))
            .collect()
    }

    fn event_matches_metadata_filters(event: &AuditEvent, query: &AuditQuery) -> bool {
        if let Some(ref agent_id) = query.agent_id {
            let found = event
                .metadata
                .as_ref()
                .and_then(|m| m.get("agent_id"))
                .and_then(|v| v.as_str())
                .map(|s| s == agent_id)
                .unwrap_or(false);
            if !found {
                return false;
            }
        }
        if let Some(ref tool) = query.tool {
            let found = event
                .metadata
                .as_ref()
                .and_then(|m| m.get("tool"))
                .and_then(|v| v.as_str())
                .map(|s| s == tool)
                .unwrap_or(false);
            if !found {
                return false;
            }
        }
        true
    }

    /// Queries events by actor using the actor index.
    fn query_by_actor(
        &self,
        query: &AuditQuery,
        actor: &str,
    ) -> Result<Vec<AuditEvent>, AuditError> {
        let prefix = keys::actor_scan_prefix(actor);
        let end = keys::prefix_end(&prefix);
        let index_entries = self.storage.scan(&query.realm_id, &prefix, &end)?;

        let mut events = Vec::new();
        for index_entry in index_entries {
            // The index value is the primary event key
            let event_value = self.storage.get(&query.realm_id, &index_entry.value)?;

            if let Some(value) = event_value {
                let event = decode_event(&value)?;

                // Apply time range filter
                if let Some(start) = query.start_time {
                    if event.timestamp < start {
                        continue;
                    }
                }
                if let Some(end_time) = query.end_time {
                    if event.timestamp >= end_time {
                        continue;
                    }
                }

                events.push(event);

                if let Some(limit) = query.limit {
                    if events.len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(events)
    }

    /// Queries events by action type using the action index.
    fn query_by_action(
        &self,
        query: &AuditQuery,
        action: &AuditAction,
    ) -> Result<Vec<AuditEvent>, AuditError> {
        let prefix = keys::action_scan_prefix(action.as_str());
        let end = keys::prefix_end(&prefix);
        let index_entries = self.storage.scan(&query.realm_id, &prefix, &end)?;

        let mut events = Vec::new();
        for index_entry in index_entries {
            let event_value = self.storage.get(&query.realm_id, &index_entry.value)?;

            if let Some(value) = event_value {
                let event = decode_event(&value)?;

                // Apply time range filter
                if let Some(start) = query.start_time {
                    if event.timestamp < start {
                        continue;
                    }
                }
                if let Some(end_time) = query.end_time {
                    if event.timestamp >= end_time {
                        continue;
                    }
                }

                events.push(event);

                if let Some(limit) = query.limit {
                    if events.len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(events)
    }
}

/// Encodes bytes as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decodes a lowercase/uppercase hex string, returning `None` on any invalid
/// input (odd length or non-hex digit).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = u8::try_from(char::from(bytes[i]).to_digit(16)?).ok()?;
        let lo = u8::try_from(char::from(bytes[i + 1]).to_digit(16)?).ok()?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FakeClock, RealmId, Timestamp};
    use crate::storage::{EmbeddedStorageEngine, StorageConfig};
    use std::sync::Arc;

    fn setup() -> (EmbeddedAuditEngine, RealmId) {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));

        let engine =
            EmbeddedAuditEngine::new(storage as Arc<dyn StorageEngine>, clock as Arc<dyn Clock>);
        let realm_id = RealmId::generate();
        (engine, realm_id)
    }

    fn setup_with_clock() -> (EmbeddedAuditEngine, RealmId, Arc<FakeClock>) {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));

        let engine = EmbeddedAuditEngine::new(
            storage as Arc<dyn StorageEngine>,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        let realm_id = RealmId::generate();
        (engine, realm_id, clock)
    }

    // === Scenario: Security-critical mutations emit structured audit events ===

    #[test]
    fn append_event_returns_correct_fields() {
        let (engine, realm_id) = setup();

        let request = CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: "user_abc".to_string(),
            action: AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "user_xyz".to_string(),
            metadata: Some(serde_json::json!({"ip": "10.0.0.1"})),
        };

        let event = engine.append(&request).expect("append");

        // Verify all required fields are present and correct
        assert_eq!(event.realm_id, realm_id);
        assert_eq!(event.actor, "user_abc");
        assert_eq!(event.action, AuditAction::UserCreated);
        assert_eq!(event.resource_type, "user");
        assert_eq!(event.resource_id, "user_xyz");
        assert_eq!(event.timestamp, Timestamp::from_micros(1_000_000));
        assert!(event.metadata.is_some(), "metadata should be preserved");
        assert!(
            !event.integrity_hash.is_empty(),
            "integrity hash must be set"
        );
        // ID should be non-nil
        assert_ne!(*event.id.as_uuid(), uuid::Uuid::nil());
    }

    #[test]
    fn append_multiple_events_returns_ordered_by_time() {
        let (engine, realm_id, clock) = setup_with_clock();

        let r1 = CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: "user_a".to_string(),
            action: AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "u1".to_string(),
            metadata: None,
        };
        let e1 = engine.append(&r1).expect("append 1");

        clock.advance(1_000_000); // +1 second

        let r2 = CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: "user_b".to_string(),
            action: AuditAction::SessionCreated,
            resource_type: "session".to_string(),
            resource_id: "s1".to_string(),
            metadata: None,
        };
        let e2 = engine.append(&r2).expect("append 2");

        assert!(e2.timestamp > e1.timestamp, "second event should be later");
    }

    // === Scenario: Append-only — no update or delete API ===
    // This is enforced at the type level: AuditEngine trait has no
    // update/delete methods. The test verifies that appended events
    // persist and cannot be removed through the engine's API.

    #[test]
    fn events_are_persistent_and_immutable() {
        let (engine, realm_id) = setup();

        let request = CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: "admin".to_string(),
            action: AuditAction::RealmCreated,
            resource_type: "realm".to_string(),
            resource_id: "t1".to_string(),
            metadata: None,
        };
        let event = engine.append(&request).expect("append");

        // Query back — the event should still be there
        let query = AuditQuery {
            realm_id: realm_id.clone(),
            ..AuditQuery::for_realm(realm_id.clone())
        };
        let events = engine.query(&query).expect("query");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
    }

    // === Scenario: Query by time range, actor, action type ===

    #[test]
    fn query_by_time_range() {
        let (engine, realm_id, clock) = setup_with_clock();

        // Event at t=1s
        engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "a".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u1".to_string(),
                metadata: None,
            })
            .expect("append");

        clock.advance(2_000_000); // t=3s

        // Event at t=3s
        let e2 = engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "b".to_string(),
                action: AuditAction::SessionCreated,
                resource_type: "session".to_string(),
                resource_id: "s1".to_string(),
                metadata: None,
            })
            .expect("append");

        clock.advance(2_000_000); // t=5s

        // Event at t=5s
        engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "c".to_string(),
                action: AuditAction::TokenIssued,
                resource_type: "token".to_string(),
                resource_id: "t1".to_string(),
                metadata: None,
            })
            .expect("append");

        // Query: events between t=2s and t=4s (should only get e2)
        let query = AuditQuery {
            realm_id: realm_id.clone(),
            start_time: Some(Timestamp::from_micros(2_000_000)),
            end_time: Some(Timestamp::from_micros(4_000_000)),
            ..AuditQuery::for_realm(realm_id.clone())
        };
        let results = engine.query(&query).expect("query");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, e2.id);
    }

    #[test]
    fn query_by_actor() {
        let (engine, realm_id, clock) = setup_with_clock();

        engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "alice".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u1".to_string(),
                metadata: None,
            })
            .expect("append");

        clock.advance(1_000_000);

        engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "bob".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u2".to_string(),
                metadata: None,
            })
            .expect("append");

        clock.advance(1_000_000);

        engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "alice".to_string(),
                action: AuditAction::SessionCreated,
                resource_type: "session".to_string(),
                resource_id: "s1".to_string(),
                metadata: None,
            })
            .expect("append");

        // Query for alice only
        let query = AuditQuery {
            realm_id: realm_id.clone(),
            actor: Some("alice".to_string()),
            ..AuditQuery::for_realm(realm_id.clone())
        };
        let results = engine.query(&query).expect("query");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.actor == "alice"));
    }

    #[test]
    fn query_by_action_type() {
        let (engine, realm_id, clock) = setup_with_clock();

        engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "a".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u1".to_string(),
                metadata: None,
            })
            .expect("append");

        clock.advance(1_000_000);

        engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "b".to_string(),
                action: AuditAction::SessionCreated,
                resource_type: "session".to_string(),
                resource_id: "s1".to_string(),
                metadata: None,
            })
            .expect("append");

        clock.advance(1_000_000);

        engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "c".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u2".to_string(),
                metadata: None,
            })
            .expect("append");

        // Query for UserCreated only
        let query = AuditQuery {
            realm_id: realm_id.clone(),
            action: Some(AuditAction::UserCreated),
            ..AuditQuery::for_realm(realm_id.clone())
        };
        let results = engine.query(&query).expect("query");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.action == AuditAction::UserCreated));
    }

    #[test]
    fn query_with_limit() {
        let (engine, realm_id, clock) = setup_with_clock();

        for i in 0..5 {
            engine
                .append(&CreateAuditEvent {
                    realm_id: realm_id.clone(),
                    actor: "a".to_string(),
                    action: AuditAction::UserCreated,
                    resource_type: "user".to_string(),
                    resource_id: format!("u{i}"),
                    metadata: None,
                })
                .expect("append");
            clock.advance(1_000_000);
        }

        let query = AuditQuery {
            realm_id: realm_id.clone(),
            limit: Some(3),
            ..AuditQuery::for_realm(realm_id.clone())
        };
        let results = engine.query(&query).expect("query");
        assert_eq!(results.len(), 3);
    }

    // === Scenario: Realm-scoped events ===

    #[test]
    fn events_scoped_to_realm() {
        let (engine, realm_a) = setup();
        let realm_b = RealmId::generate();

        // Append to realm A
        engine
            .append(&CreateAuditEvent {
                realm_id: realm_a.clone(),
                actor: "a".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u1".to_string(),
                metadata: None,
            })
            .expect("append to A");

        // Append to realm B
        engine
            .append(&CreateAuditEvent {
                realm_id: realm_b.clone(),
                actor: "b".to_string(),
                action: AuditAction::SessionCreated,
                resource_type: "session".to_string(),
                resource_id: "s1".to_string(),
                metadata: None,
            })
            .expect("append to B");

        // Query realm A — should only see realm A's event
        let results_a = engine
            .query(&AuditQuery::for_realm(realm_a.clone()))
            .expect("query A");
        assert_eq!(results_a.len(), 1);
        assert_eq!(results_a[0].realm_id, realm_a);
        assert_eq!(results_a[0].actor, "a");

        // Query realm B — should only see realm B's event
        let results_b = engine
            .query(&AuditQuery::for_realm(realm_b.clone()))
            .expect("query B");
        assert_eq!(results_b.len(), 1);
        assert_eq!(results_b[0].realm_id, realm_b);
        assert_eq!(results_b[0].actor, "b");
    }

    // === Integrity hash chain ===

    #[test]
    fn integrity_hash_chain_is_valid() {
        let (engine, realm_id, clock) = setup_with_clock();

        for i in 0..5 {
            engine
                .append(&CreateAuditEvent {
                    realm_id: realm_id.clone(),
                    actor: format!("actor_{i}"),
                    action: AuditAction::UserCreated,
                    resource_type: "user".to_string(),
                    resource_id: format!("u{i}"),
                    metadata: None,
                })
                .expect("append");
            clock.advance(1_000_000);
        }

        let valid = engine
            .verify_integrity(&realm_id, None, None)
            .expect("verify");
        assert!(valid, "hash chain should be valid");
    }

    #[test]
    fn different_events_produce_different_hashes() {
        let (engine, realm_id, clock) = setup_with_clock();

        let e1 = engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "alice".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u1".to_string(),
                metadata: None,
            })
            .expect("append 1");

        clock.advance(1_000_000);

        let e2 = engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "bob".to_string(),
                action: AuditAction::SessionCreated,
                resource_type: "session".to_string(),
                resource_id: "s1".to_string(),
                metadata: None,
            })
            .expect("append 2");

        assert_ne!(
            e1.integrity_hash, e2.integrity_hash,
            "different events should have different hashes"
        );
    }

    #[test]
    fn hash_chain_survives_restart() {
        // Phase 1: write events with the first engine instance.
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let realm_id = RealmId::generate();

        {
            let config = StorageConfig::dev(temp_dir.path().to_path_buf());
            let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
            let engine = EmbeddedAuditEngine::new(
                Arc::clone(&storage) as Arc<dyn StorageEngine>,
                Arc::clone(&clock) as Arc<dyn Clock>,
            );

            for i in 0..3_u32 {
                engine
                    .append(&CreateAuditEvent {
                        realm_id: realm_id.clone(),
                        actor: format!("actor_{i}"),
                        action: AuditAction::UserCreated,
                        resource_type: "user".to_string(),
                        resource_id: format!("u{i}"),
                        metadata: None,
                    })
                    .expect("append before restart");
                clock.advance(1_000_000);
            }
        } // engine + storage dropped — simulates server restart; temp_dir stays alive

        // Phase 2: reopen the same storage directory with a fresh engine.
        let config2 = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage2 = Arc::new(EmbeddedStorageEngine::open(config2).expect("storage2"));
        let engine2 = EmbeddedAuditEngine::new(
            Arc::clone(&storage2) as Arc<dyn StorageEngine>,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );

        for i in 3..6_u32 {
            engine2
                .append(&CreateAuditEvent {
                    realm_id: realm_id.clone(),
                    actor: format!("actor_{i}"),
                    action: AuditAction::UserCreated,
                    resource_type: "user".to_string(),
                    resource_id: format!("u{i}"),
                    metadata: None,
                })
                .expect("append after restart");
            clock.advance(1_000_000);
        }

        // The full chain (pre-restart events + post-restart events) must be valid.
        let valid = engine2
            .verify_integrity(&realm_id, None, None)
            .expect("verify");
        assert!(valid, "hash chain must survive a server restart");
    }

    // === HEA-1756 R7: audit hash-chain integrity ===

    /// U1: a burst of events sharing the same microsecond timestamp must verify
    /// cleanly. Before the monotonic sequence was embedded in the primary key,
    /// the storage scan order (by random UUID) diverged from the append order,
    /// so the chain verified in the wrong order and raised a false tamper alarm.
    #[test]
    fn same_microsecond_burst_verifies_clean() {
        let (engine, realm_id) = setup(); // FakeClock is fixed — no advance()

        for i in 0..40_u32 {
            engine
                .append(&CreateAuditEvent {
                    realm_id: realm_id.clone(),
                    actor: format!("actor_{i}"),
                    action: AuditAction::UserCreated,
                    resource_type: "user".to_string(),
                    resource_id: format!("u{i}"),
                    metadata: None,
                })
                .expect("append");
            // Deliberately do NOT advance the clock: every event lands in the
            // same microsecond.
        }

        // All 40 events share one timestamp; the chain must still be valid.
        let valid = engine
            .verify_integrity(&realm_id, None, None)
            .expect("verify");
        assert!(
            valid,
            "same-microsecond burst must verify cleanly (deterministic order)"
        );

        // And the scan/query order must be stable across calls.
        let q1 = engine
            .query(&AuditQuery::for_realm(realm_id.clone()))
            .expect("query 1");
        assert_eq!(q1.len(), 40);
    }

    /// U2: the chain must still verify after a retention prune removes the
    /// oldest events. The prune re-anchors the chain head to the last-pruned
    /// event's hash so the surviving suffix chains from a known-good anchor.
    #[test]
    fn chain_verifies_after_retention_prune() {
        let (engine, realm_id, clock) = setup_with_clock();

        let mut timestamps = Vec::new();
        for i in 0..6_u32 {
            let e = engine
                .append(&CreateAuditEvent {
                    realm_id: realm_id.clone(),
                    actor: format!("actor_{i}"),
                    action: AuditAction::UserCreated,
                    resource_type: "user".to_string(),
                    resource_id: format!("u{i}"),
                    metadata: None,
                })
                .expect("append");
            timestamps.push(e.timestamp);
            clock.advance(1_000_000);
        }

        // Prune the three oldest events (cutoff strictly after the 3rd event).
        let cutoff = Timestamp::from_micros(timestamps[3].as_micros());
        let pruned = engine.prune_before(&realm_id, cutoff).expect("prune");
        assert_eq!(pruned, 3, "three oldest events should be pruned");

        // The surviving window must verify against the re-anchored head.
        let valid = engine
            .verify_integrity(&realm_id, None, None)
            .expect("verify");
        assert!(valid, "chain must re-anchor and verify after a prune");

        // Sanity: exactly the surviving events remain.
        let remaining = engine
            .query(&AuditQuery::for_realm(realm_id.clone()))
            .expect("query");
        assert_eq!(remaining.len(), 3);

        // Appending after a prune keeps the chain valid.
        engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "post_prune".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u_new".to_string(),
                metadata: None,
            })
            .expect("append after prune");
        let valid_after = engine
            .verify_integrity(&realm_id, None, None)
            .expect("verify");
        assert!(valid_after, "chain must stay valid appending after a prune");
    }

    /// U3: deleting the newest events from storage (tail truncation) leaves an
    /// internally consistent chain, but the persisted signed head still records
    /// the original count and final hash, so verification must reject it.
    #[test]
    fn tail_truncation_detected_against_persisted_head() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let engine = EmbeddedAuditEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        let realm_id = RealmId::generate();

        for i in 0..5_u32 {
            engine
                .append(&CreateAuditEvent {
                    realm_id: realm_id.clone(),
                    actor: format!("actor_{i}"),
                    action: AuditAction::UserCreated,
                    resource_type: "user".to_string(),
                    resource_id: format!("u{i}"),
                    metadata: None,
                })
                .expect("append");
            clock.advance(1_000_000);
        }

        // Baseline: the untouched chain verifies.
        assert!(engine
            .verify_integrity(&realm_id, None, None)
            .expect("verify"));

        // Simulate an attacker truncating the tail: delete the newest primary
        // event key directly through storage, bypassing the append-only engine.
        let prefix = keys::event_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = storage.scan(&realm_id, &prefix, &end).expect("scan");
        let newest_key = entries.last().expect("at least one event").key.clone();
        storage
            .delete(&realm_id, &newest_key)
            .expect("delete newest event");

        // The remaining events still chain internally, but the signed head
        // records 5 events ending at the deleted hash — truncation is detected.
        let valid = engine
            .verify_integrity(&realm_id, None, None)
            .expect("verify");
        assert!(!valid, "tail truncation must be detected against the head");
    }

    /// U3 corollary: tampering with the persisted head itself (bad MAC) is a
    /// tamper signal — verification must fail rather than trusting the forged
    /// head.
    #[test]
    fn forged_chain_head_is_rejected() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let engine = EmbeddedAuditEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        let realm_id = RealmId::generate();

        for i in 0..3_u32 {
            engine
                .append(&CreateAuditEvent {
                    realm_id: realm_id.clone(),
                    actor: format!("actor_{i}"),
                    action: AuditAction::UserCreated,
                    resource_type: "user".to_string(),
                    resource_id: format!("u{i}"),
                    metadata: None,
                })
                .expect("append");
            clock.advance(1_000_000);
        }

        // Overwrite the head with a syntactically valid but unsigned record.
        let forged = serde_json::json!({
            "anchor": GENESIS_HASH,
            "last_hash": "deadbeef",
            "seq": 99_u64,
            "count": 99_u64,
            "mac": "00",
        });
        let forged_bytes = serde_json::to_vec(&forged).expect("serialize forged head");
        storage
            .put(&realm_id, &keys::chain_head_key(), &forged_bytes)
            .expect("overwrite head");

        let valid = engine
            .verify_integrity(&realm_id, None, None)
            .expect("verify");
        assert!(!valid, "a head with an invalid MAC must be rejected");
    }

    /// HEA-1899: a stored event whose value has been silently mutated (e.g. actor
    /// field overwritten) must be caught by the hash-chain HMAC even after the
    /// compact binary key encoding change.
    #[test]
    fn tampered_event_value_detected_by_hash_chain() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let engine = EmbeddedAuditEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        let realm_id = RealmId::generate();

        for i in 0..3_u32 {
            engine
                .append(&CreateAuditEvent {
                    realm_id: realm_id.clone(),
                    actor: format!("actor_{i}"),
                    action: AuditAction::UserCreated,
                    resource_type: "user".to_string(),
                    resource_id: format!("u{i}"),
                    metadata: None,
                })
                .expect("append");
            clock.advance(1_000_000);
        }

        // Baseline: the untouched chain verifies.
        assert!(
            engine
                .verify_integrity(&realm_id, None, None)
                .expect("verify"),
            "baseline chain must be valid"
        );

        // Simulate an attacker overwriting the first event's actor field in
        // storage directly, bypassing the append-only engine.
        let prefix = keys::event_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = storage.scan(&realm_id, &prefix, &end).expect("scan");
        let first_key = entries.first().expect("at least one event").key.clone();

        let original_bytes = storage
            .get(&realm_id, &first_key)
            .expect("get")
            .expect("event exists");

        // Parse and mutate the actor field (must use binary codec — events are no longer JSON).
        let mut event: AuditEvent = decode_event(&original_bytes).expect("deserialize event");
        event.actor = "attacker".to_string();
        let tampered_bytes = encode_event(&event).expect("serialize tampered event");

        // Write the tampered value back under the same key.
        storage
            .put(&realm_id, &first_key, &tampered_bytes)
            .expect("overwrite event");

        // The chain HMAC must catch the mutation.
        let valid = engine
            .verify_integrity(&realm_id, None, None)
            .expect("verify");
        assert!(
            !valid,
            "tampered event value must be detected by the hash chain"
        );
    }

    #[test]
    fn genesis_hash_for_empty_realm() {
        let (engine, realm_id) = setup();

        // First event should chain from genesis
        let event = engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "a".to_string(),
                action: AuditAction::RealmCreated,
                resource_type: "realm".to_string(),
                resource_id: "t1".to_string(),
                metadata: None,
            })
            .expect("append");

        // Verify the hash was computed using genesis
        assert!(!event.integrity_hash.is_empty());
        // Integrity check should pass
        let valid = engine
            .verify_integrity(&realm_id, None, None)
            .expect("verify");
        assert!(valid);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use crate::core::{Clock, FakeClock, RealmId, Timestamp};
    use crate::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
    use proptest::prelude::*;
    use std::sync::Arc;

    /// Strategy for generating a random `AuditAction`.
    fn arb_action() -> impl Strategy<Value = AuditAction> {
        prop_oneof![
            Just(AuditAction::UserCreated),
            Just(AuditAction::UserUpdated),
            Just(AuditAction::UserDeleted),
            Just(AuditAction::CredentialSet),
            Just(AuditAction::CredentialChanged),
            Just(AuditAction::CredentialVerified),
            Just(AuditAction::SessionCreated),
            Just(AuditAction::SessionRevoked),
            Just(AuditAction::TokenIssued),
            Just(AuditAction::TokenRefreshed),
            Just(AuditAction::RealmCreated),
            Just(AuditAction::RealmUpdated),
            Just(AuditAction::RealmDeleted),
            Just(AuditAction::ClientRegistered),
            Just(AuditAction::AuthorizationCodeIssued),
            Just(AuditAction::AuthorizationCodeExchanged),
            Just(AuditAction::TupleWritten),
            Just(AuditAction::TupleDeleted),
            Just(AuditAction::Cleanup),
        ]
    }

    /// Strategy for a random audit event request.
    #[allow(dead_code)]
    fn arb_create_event(realm_id: RealmId) -> impl Strategy<Value = CreateAuditEvent> {
        (
            "[a-z]{3,8}", // actor
            arb_action(),
            "[a-z]{3,8}",      // resource_type
            "[a-z0-9_]{3,12}", // resource_id
        )
            .prop_map(move |(actor, action, resource_type, resource_id)| {
                CreateAuditEvent {
                    realm_id: realm_id.clone(),
                    actor,
                    action,
                    resource_type,
                    resource_id,
                    metadata: None,
                }
            })
    }

    // Property: event count equals mutation count
    proptest! {
        #[test]
        fn event_count_matches_mutation_count(
            count in 1_usize..50,
        ) {
            let temp_dir = tempfile::tempdir().expect("temp dir");
            let config = StorageConfig::dev(temp_dir.path().to_path_buf());
            let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
            let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
            let engine = EmbeddedAuditEngine::new(
                storage as Arc<dyn StorageEngine>,
                Arc::clone(&clock) as Arc<dyn Clock>,
            );
            let realm_id = RealmId::generate();

            for i in 0..count {
                engine
                    .append(&CreateAuditEvent {
                        realm_id: realm_id.clone(),
                        actor: format!("actor_{i}"),
                        action: AuditAction::UserCreated,
                        resource_type: "user".to_string(),
                        resource_id: format!("u{i}"),
                        metadata: None,
                    })
                    .expect("append");
                clock.advance(1_000_000);
            }

            let events = engine
                .query(&AuditQuery::for_realm(realm_id))
                .expect("query");
            prop_assert_eq!(events.len(), count);
        }
    }

    // Property: events are strictly ordered by timestamp
    proptest! {
        #[test]
        fn events_strictly_ordered_by_timestamp(
            actions in prop::collection::vec(arb_action(), 2..30),
        ) {
            let temp_dir = tempfile::tempdir().expect("temp dir");
            let config = StorageConfig::dev(temp_dir.path().to_path_buf());
            let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
            let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
            let engine = EmbeddedAuditEngine::new(
                storage as Arc<dyn StorageEngine>,
                Arc::clone(&clock) as Arc<dyn Clock>,
            );
            let realm_id = RealmId::generate();

            for (i, action) in actions.iter().enumerate() {
                engine
                    .append(&CreateAuditEvent {
                        realm_id: realm_id.clone(),
                        actor: format!("actor_{i}"),
                        action: action.clone(),
                        resource_type: "resource".to_string(),
                        resource_id: format!("r{i}"),
                        metadata: None,
                    })
                    .expect("append");
                // Advance clock between events to ensure distinct timestamps
                clock.advance(1_000);
            }

            let events = engine
                .query(&AuditQuery::for_realm(realm_id))
                .expect("query");

            // Verify strict ordering
            for i in 1..events.len() {
                prop_assert!(
                    events[i].timestamp > events[i - 1].timestamp,
                    "event {} ({:?}) should have timestamp > event {} ({:?})",
                    i, events[i].timestamp,
                    i - 1, events[i - 1].timestamp,
                );
            }
        }
    }
}
