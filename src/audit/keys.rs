//! Storage key encoding for audit log records.
//!
//! Audit events are stored with time-ordered keys for efficient range scans.
//! All keys are realm-scoped via the `StorageEngine`'s `RealmId` requirement.
//!
//! ## Key format (HEA-1899 — compact binary encoding)
//!
//! | Index | Format | Size |
//! |-------|--------|------|
//! | Event primary | `audit:evt:{ts_8be}{seq_8be}{uuid_16raw}` | 42 bytes |
//! | Actor index | `audit:actor:{actor}:{ts_8be}{uuid_16raw}` | 37 + len(actor) bytes |
//! | Action index | `audit:action:{action}:{ts_8be}{uuid_16raw}` | 38 + len(action) bytes |
//!
//! Timestamps and sequence numbers are 8-byte big-endian `u64` values. Big-endian
//! integers compare lexicographically in the same order as numerically, so the
//! existing range-scan semantics are preserved without any padding or separators.
//! UUIDs are stored as 16 raw bytes (not the 36-character hyphenated string).
//!
//! The primary key embeds a per-realm monotonic sequence number between the timestamp
//! and the UUID so that same-microsecond events sort in append order — `verify_integrity`
//! walks the chain in exactly the order it was written (HEA-1756 U1).
//!
//! ## Scan-bound semantics
//!
//! `event_scan_start(ts)` / `event_scan_end(ts)` both return the 18-byte prefix
//! `audit:evt:{ts_8be}`. An actual event key at that timestamp is 42 bytes; because
//! any 42-byte key whose first 18 bytes equal the prefix sorts *after* the 18-byte
//! value in lexicographic comparison, the prefix acts as a correct exclusive upper
//! bound for events strictly before `ts` and a correct inclusive lower bound for
//! events at-or-after `ts`.

use crate::core::{AuditEventId, Timestamp};

/// Prefix for audit event primary keys.
const EVENT_PREFIX: &str = "audit:evt:";

/// Prefix for audit actor index keys.
const ACTOR_PREFIX: &str = "audit:actor:";

/// Prefix for audit action index keys.
const ACTION_PREFIX: &str = "audit:action:";

/// Key for the per-realm audit retention configuration.
const RETENTION_CONFIG_KEY: &str = "audit:config:retention";

/// Key for the per-realm HMAC-SHA256 chain signing key.
///
/// Stores 32 raw bytes (wrapped with the KEK when one is configured).
/// Generated once per realm on first audit append.
const AUDIT_HMAC_KEY: &str = "audit:hmac:key";

/// Key for the per-realm signed audit chain head.
///
/// Stores a JSON [`super::engine::ChainHead`]: the last event's integrity hash,
/// the re-anchor value, the monotonic sequence, the live-event count, and an
/// HMAC-SHA256 tag over those fields. Persisting this lets verification detect
/// tail truncation and survive retention pruning (HEA-1756 U2/U3).
const AUDIT_CHAIN_HEAD_KEY: &str = "audit:chain:head";

/// Encodes a timestamp as 8 big-endian bytes.
///
/// Real timestamps are microseconds since the Unix epoch (always non-negative),
/// so casting `i64` to `u64` preserves chronological ordering in byte comparison.
fn timestamp_bytes(ts: Timestamp) -> [u8; 8] {
    #[allow(clippy::cast_sign_loss)]
    (ts.as_micros() as u64).to_be_bytes()
}

/// Encodes a sequence number as 8 big-endian bytes.
fn seq_bytes(seq: u64) -> [u8; 8] {
    seq.to_be_bytes()
}

/// Encodes the primary key for an audit event.
///
/// Format: `audit:evt:{ts_8be}{seq_8be}{uuid_16raw}` (42 bytes total)
///
/// The monotonic `seq` guarantees same-microsecond events sort in append order,
/// so `verify_integrity` walks the chain in exactly the order it was written
/// (HEA-1756 U1).
pub(crate) fn encode_event_key(timestamp: Timestamp, seq: u64, event_id: &AuditEventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(42);
    key.extend_from_slice(EVENT_PREFIX.as_bytes());
    key.extend_from_slice(&timestamp_bytes(timestamp));
    key.extend_from_slice(&seq_bytes(seq));
    key.extend_from_slice(event_id.as_uuid().as_bytes());
    key
}

/// Returns the scan prefix for all audit events.
///
/// Format: `audit:evt:`
pub(crate) fn event_scan_prefix() -> Vec<u8> {
    EVENT_PREFIX.as_bytes().to_vec()
}

/// Returns the scan start key for events at or after a given timestamp.
///
/// Format: `audit:evt:{ts_8be}` (18 bytes)
pub(crate) fn event_scan_start(timestamp: Timestamp) -> Vec<u8> {
    let mut key = Vec::with_capacity(18);
    key.extend_from_slice(EVENT_PREFIX.as_bytes());
    key.extend_from_slice(&timestamp_bytes(timestamp));
    key
}

/// Returns the scan end key for events strictly before a given timestamp (exclusive).
///
/// Format: `audit:evt:{ts_8be}` (18 bytes) — identical to `event_scan_start`.
///
/// The 18-byte prefix is an exclusive upper bound for events before `ts` because any
/// actual event key at `ts` is 42 bytes long and sorts *after* the 18-byte prefix in
/// lexicographic byte comparison.
pub(crate) fn event_scan_end(timestamp: Timestamp) -> Vec<u8> {
    event_scan_start(timestamp)
}

/// Encodes the actor index key for an audit event.
///
/// Format: `audit:actor:{actor}:{ts_8be}{uuid_16raw}`
pub(crate) fn encode_actor_index(
    actor: &str,
    timestamp: Timestamp,
    event_id: &AuditEventId,
) -> Vec<u8> {
    let prefix = actor_scan_prefix(actor);
    let mut key = Vec::with_capacity(prefix.len() + 8 + 16);
    key.extend_from_slice(&prefix);
    key.extend_from_slice(&timestamp_bytes(timestamp));
    key.extend_from_slice(event_id.as_uuid().as_bytes());
    key
}

/// Returns the scan prefix for all events by a given actor.
///
/// Format: `audit:actor:{actor}:`
pub(crate) fn actor_scan_prefix(actor: &str) -> Vec<u8> {
    format!("{ACTOR_PREFIX}{actor}:").into_bytes()
}

/// Encodes the action index key for an audit event.
///
/// Format: `audit:action:{action}:{ts_8be}{uuid_16raw}`
pub(crate) fn encode_action_index(
    action: &str,
    timestamp: Timestamp,
    event_id: &AuditEventId,
) -> Vec<u8> {
    let prefix = action_scan_prefix(action);
    let mut key = Vec::with_capacity(prefix.len() + 8 + 16);
    key.extend_from_slice(&prefix);
    key.extend_from_slice(&timestamp_bytes(timestamp));
    key.extend_from_slice(event_id.as_uuid().as_bytes());
    key
}

/// Returns the scan prefix for all events of a given action type.
///
/// Format: `audit:action:{action}:`
pub(crate) fn action_scan_prefix(action: &str) -> Vec<u8> {
    format!("{ACTION_PREFIX}{action}:").into_bytes()
}

/// Returns the storage key for the realm's audit retention configuration.
pub(crate) fn retention_config_key() -> Vec<u8> {
    RETENTION_CONFIG_KEY.as_bytes().to_vec()
}

/// Returns the storage key for the realm's per-realm audit HMAC chain key.
pub(crate) fn audit_hmac_key() -> Vec<u8> {
    AUDIT_HMAC_KEY.as_bytes().to_vec()
}

/// Returns the storage key for the realm's signed audit chain head.
pub(crate) fn chain_head_key() -> Vec<u8> {
    AUDIT_CHAIN_HEAD_KEY.as_bytes().to_vec()
}

/// Computes the exclusive end bound for a prefix scan.
///
/// Increments the last byte of the prefix.
pub(crate) fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::AuditEventId;

    // --- HEA-1899: compact binary key format ---

    #[test]
    fn timestamp_bytes_order_preserving() {
        let earlier = timestamp_bytes(Timestamp::from_micros(100));
        let later = timestamp_bytes(Timestamp::from_micros(200));
        assert!(
            earlier < later,
            "earlier timestamp must sort first as BE bytes"
        );
    }

    #[test]
    fn seq_bytes_order_preserving() {
        assert!(seq_bytes(0) < seq_bytes(1));
        assert!(seq_bytes(1) < seq_bytes(u64::MAX));
    }

    #[test]
    fn encode_event_key_binary_layout() {
        // Primary key: 10-byte prefix + 8-byte ts + 8-byte seq + 16-byte UUID = 42 bytes
        let ts = Timestamp::from_micros(1_700_000_000_000_000);
        let id = AuditEventId::generate();
        let key = encode_event_key(ts, 7, &id);

        assert_eq!(key.len(), 42, "primary key must be exactly 42 bytes");
        assert_eq!(&key[..10], b"audit:evt:", "ASCII prefix must be intact");

        let expected_ts: [u8; 8] = (1_700_000_000_000_000u64).to_be_bytes();
        assert_eq!(&key[10..18], expected_ts, "timestamp must be 8-byte BE u64");

        let expected_seq: [u8; 8] = 7u64.to_be_bytes();
        assert_eq!(&key[18..26], expected_seq, "sequence must be 8-byte BE u64");

        assert_eq!(
            &key[26..42],
            id.as_uuid().as_bytes().as_slice(),
            "UUID must be 16 raw bytes"
        );
    }

    #[test]
    fn event_keys_ordered_by_timestamp() {
        let id1 = AuditEventId::generate();
        let id2 = AuditEventId::generate();
        let key1 = encode_event_key(Timestamp::from_micros(100), 0, &id1);
        let key2 = encode_event_key(Timestamp::from_micros(200), 1, &id2);
        assert!(key1 < key2, "earlier timestamp should sort first");
    }

    #[test]
    fn event_keys_same_timestamp_ordered_by_seq() {
        // Two events sharing the same microsecond must sort by sequence, in
        // append order, regardless of their (random) UUIDs (HEA-1756 U1).
        let id_high = AuditEventId::generate();
        let id_low = AuditEventId::generate();
        let ts = Timestamp::from_micros(1_000_000);
        let key_seq0 = encode_event_key(ts, 0, &id_high);
        let key_seq1 = encode_event_key(ts, 1, &id_low);
        assert!(
            key_seq0 < key_seq1,
            "lower sequence must sort first even when UUIDs would order differently"
        );
    }

    #[test]
    fn event_scan_prefix_is_ascii() {
        let prefix = event_scan_prefix();
        assert_eq!(prefix, b"audit:evt:");
    }

    #[test]
    fn event_key_starts_with_scan_prefix() {
        let ts = Timestamp::from_micros(1000);
        let id = AuditEventId::generate();
        let key = encode_event_key(ts, 3, &id);
        let prefix = event_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn event_key_within_time_range_bounds() {
        // A key at exactly `ts` with the maximum seq must still fall within
        // [event_scan_start(ts), event_scan_end(ts+1)).
        //
        // With 8-byte BE encoding, event_scan_start(ts) is an 18-byte prefix.
        // An event key is 42 bytes; because the first 18 bytes equal the prefix
        // and the key is longer, the key sorts *after* the 18-byte bound in
        // lexicographic comparison — i.e. key >= start.
        let ts = Timestamp::from_micros(1000);
        let id = AuditEventId::generate();
        let key = encode_event_key(ts, u64::MAX, &id);
        let start = event_scan_start(ts);
        let end = event_scan_end(Timestamp::from_micros(1001));
        assert!(key >= start, "key must be >= scan start for its timestamp");
        assert!(key < end, "key must be < scan end for a later timestamp");
    }

    #[test]
    fn event_scan_end_excludes_events_at_bound() {
        // event_scan_end(ts) must be strictly less than any actual event at ts.
        let ts = Timestamp::from_micros(5000);
        let id = AuditEventId::generate();
        let event_key = encode_event_key(ts, 0, &id);
        let bound = event_scan_end(ts);
        assert!(
            event_key > bound,
            "event at ts must sort AFTER event_scan_end(ts) so it is excluded from [start, end)"
        );
    }

    #[test]
    fn encode_actor_index_binary_layout() {
        // Actor key: actor_scan_prefix + 8-byte ts + 16-byte UUID
        let ts = Timestamp::from_micros(1000);
        let id = AuditEventId::generate();
        let actor = "user_123";
        let key = encode_actor_index(actor, ts, &id);
        let prefix = actor_scan_prefix(actor);

        assert!(
            key.starts_with(&prefix),
            "actor key must start with actor prefix"
        );

        let ts_offset = prefix.len();
        let expected_ts: [u8; 8] = (1000u64).to_be_bytes();
        assert_eq!(
            &key[ts_offset..ts_offset + 8],
            expected_ts,
            "8-byte BE timestamp after prefix"
        );
        assert_eq!(
            &key[ts_offset + 8..],
            id.as_uuid().as_bytes().as_slice(),
            "16-byte raw UUID at end"
        );
        assert_eq!(key.len(), prefix.len() + 8 + 16);
    }

    #[test]
    fn actor_index_starts_with_actor_prefix() {
        let ts = Timestamp::from_micros(1000);
        let id = AuditEventId::generate();
        let key = encode_actor_index("user_123", ts, &id);
        let prefix = actor_scan_prefix("user_123");
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_action_index_starts_with_action_prefix() {
        let ts = Timestamp::from_micros(1000);
        let id = AuditEventId::generate();
        let key = encode_action_index("user_created", ts, &id);
        let prefix = action_scan_prefix("user_created");
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn action_index_binary_layout() {
        let ts = Timestamp::from_micros(2000);
        let id = AuditEventId::generate();
        let action = "session_created";
        let key = encode_action_index(action, ts, &id);
        let prefix = action_scan_prefix(action);
        assert_eq!(key.len(), prefix.len() + 8 + 16);

        let expected_ts: [u8; 8] = (2000u64).to_be_bytes();
        assert_eq!(&key[prefix.len()..prefix.len() + 8], expected_ts);
        assert_eq!(&key[prefix.len() + 8..], id.as_uuid().as_bytes().as_slice());
    }

    #[test]
    fn prefix_end_increments() {
        let prefix = event_scan_prefix();
        let end = prefix_end(&prefix);
        assert!(end > prefix);
    }

    #[test]
    fn different_actors_different_prefixes() {
        let p1 = actor_scan_prefix("alice");
        let p2 = actor_scan_prefix("bob");
        assert_ne!(p1, p2);
    }

    #[test]
    fn actor_keys_sort_chronologically_within_actor() {
        let actor = "alice";
        let id1 = AuditEventId::generate();
        let id2 = AuditEventId::generate();
        let k1 = encode_actor_index(actor, Timestamp::from_micros(100), &id1);
        let k2 = encode_actor_index(actor, Timestamp::from_micros(200), &id2);
        assert!(k1 < k2, "actor index entries must sort chronologically");
    }
}
