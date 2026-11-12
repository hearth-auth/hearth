//! Key prefixes that more than one layer must agree on.
//!
//! The storage engine keeps an exact count of the keys under each prefix in
//! [`COUNTED_KEY_PREFIXES`] (#644). The identity layer writes the keys under
//! those prefixes. The storage layer cannot import identity, so the prefixes
//! live here.

/// The prefix of a user's primary record key: `usr:id:{uuid}`.
pub const USER_RECORD_KEY_PREFIX: &[u8] = b"usr:id:";

/// The key prefixes whose per-realm key count the storage engine keeps.
///
/// `count_prefix` with no cap reads such a count in O(1) instead of a walk of
/// every key. Each entry costs one point lookup per write to a key under it.
pub const COUNTED_KEY_PREFIXES: &[&[u8]] = &[USER_RECORD_KEY_PREFIX];
