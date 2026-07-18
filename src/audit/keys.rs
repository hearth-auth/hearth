//! Storage key encoding for audit log records.
//!
//! Audit events are stored with time-ordered keys for efficient range scans.
//! All keys are realm-scoped via the `StorageEngine`'s `RealmId` requirement.
//!
//! Indexes maintained:
//!
//! - **Event primary**: `audit:evt:{timestamp_19d}:{seq_20d}:{uuid}` → JSON-serialized `AuditEvent`
//! - **Actor index**: `audit:actor:{actor}:{timestamp_19d}:{uuid}` → event primary key
//! - **Action index**: `audit:action:{action}:{timestamp_19d}:{uuid}` → event primary key
//!
//! Timestamps are zero-padded to 19 digits for correct lexicographic ordering.
//! The primary key additionally embeds a per-realm monotonic sequence number
//! (zero-padded to 20 digits) between the timestamp and the UUID. This makes
//! the storage scan order deterministic and identical to append order even for
//! events that share the same microsecond timestamp, so the hash chain verifies
//! in exactly the order it was written (HEA-1756 U1).

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

/// Formats a timestamp as a 19-digit zero-padded string.
///
/// This ensures lexicographic ordering matches chronological ordering
/// for all positive timestamp values.
fn pad_timestamp(ts: Timestamp) -> String {
    format!("{:019}", ts.as_micros())
}

/// Formats a per-realm sequence number as a 20-digit zero-padded string.
///
/// 20 digits accommodate the full `u64` range so that lexicographic ordering
/// of the encoded sequence always matches numeric ordering.
fn pad_seq(seq: u64) -> String {
    format!("{seq:020}")
}

/// Encodes the primary key for an audit event.
///
/// Format: `audit:evt:{timestamp_19d}:{seq_20d}:{uuid}`
///
/// The monotonic `seq` guarantees that same-microsecond events sort in append
/// order, so `verify_integrity` walks the chain in the exact order it was
/// written (HEA-1756 U1).
pub(crate) fn encode_event_key(timestamp: Timestamp, seq: u64, event_id: &AuditEventId) -> Vec<u8> {
    format!(
        "{EVENT_PREFIX}{}:{}:{}",
        pad_timestamp(timestamp),
        pad_seq(seq),
        event_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all audit events (used with time-range filtering).
///
/// Format: `audit:evt:`
pub(crate) fn event_scan_prefix() -> Vec<u8> {
    EVENT_PREFIX.as_bytes().to_vec()
}

/// Returns the scan start key for events at or after a given timestamp.
///
/// Format: `audit:evt:{timestamp_19d}`
pub(crate) fn event_scan_start(timestamp: Timestamp) -> Vec<u8> {
    format!("{EVENT_PREFIX}{}", pad_timestamp(timestamp)).into_bytes()
}

/// Returns the scan end key for events before a given timestamp (exclusive).
///
/// Format: `audit:evt:{timestamp_19d}`
pub(crate) fn event_scan_end(timestamp: Timestamp) -> Vec<u8> {
    format!("{EVENT_PREFIX}{}", pad_timestamp(timestamp)).into_bytes()
}

/// Encodes the actor index key for an audit event.
///
/// Format: `audit:actor:{actor}:{timestamp_19d}:{uuid}`
pub(crate) fn encode_actor_index(
    actor: &str,
    timestamp: Timestamp,
    event_id: &AuditEventId,
) -> Vec<u8> {
    format!(
        "{ACTOR_PREFIX}{actor}:{}:{}",
        pad_timestamp(timestamp),
        event_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all events by a given actor.
///
/// Format: `audit:actor:{actor}:`
pub(crate) fn actor_scan_prefix(actor: &str) -> Vec<u8> {
    format!("{ACTOR_PREFIX}{actor}:").into_bytes()
}

/// Encodes the action index key for an audit event.
///
/// Format: `audit:action:{action}:{timestamp_19d}:{uuid}`
pub(crate) fn encode_action_index(
    action: &str,
    timestamp: Timestamp,
    event_id: &AuditEventId,
) -> Vec<u8> {
    format!(
        "{ACTION_PREFIX}{action}:{}:{}",
        pad_timestamp(timestamp),
        event_id.as_uuid()
    )
    .into_bytes()
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

    #[test]
    fn pad_timestamp_19_digits() {
        let ts = Timestamp::from_micros(1_700_000_000_000_000);
        let padded = pad_timestamp(ts);
        assert_eq!(padded.len(), 19);
        assert_eq!(padded, "0001700000000000000");
    }

    #[test]
    fn pad_timestamp_small_value() {
        let ts = Timestamp::from_micros(42);
        let padded = pad_timestamp(ts);
        assert_eq!(padded.len(), 19);
        assert_eq!(padded, "0000000000000000042");
    }

    #[test]
    fn encode_event_key_format() {
        let ts = Timestamp::from_micros(1_700_000_000_000_000);
        let id = AuditEventId::generate();
        let key = encode_event_key(ts, 7, &id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert!(key_str.starts_with("audit:evt:0001700000000000000:00000000000000000007:"));
        assert!(key_str.contains(&id.as_uuid().to_string()));
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
    fn event_scan_prefix_format() {
        let prefix = event_scan_prefix();
        let prefix_str = std::str::from_utf8(&prefix).expect("utf8");
        assert_eq!(prefix_str, "audit:evt:");
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
        // A key at exactly `ts` must fall within [event_scan_start(ts),
        // event_scan_end(ts+1)) so seq-suffixed keys still satisfy range scans.
        let ts = Timestamp::from_micros(1000);
        let id = AuditEventId::generate();
        let key = encode_event_key(ts, u64::MAX, &id);
        let start = event_scan_start(ts);
        let end = event_scan_end(Timestamp::from_micros(1001));
        assert!(key >= start, "key must be >= scan start for its timestamp");
        assert!(key < end, "key must be < scan end for a later timestamp");
    }

    #[test]
    fn encode_actor_index_format() {
        let ts = Timestamp::from_micros(1000);
        let id = AuditEventId::generate();
        let key = encode_actor_index("user_123", ts, &id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert!(key_str.starts_with("audit:actor:user_123:"));
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
    fn encode_action_index_format() {
        let ts = Timestamp::from_micros(1000);
        let id = AuditEventId::generate();
        let key = encode_action_index("user_created", ts, &id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert!(key_str.starts_with("audit:action:user_created:"));
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
}
