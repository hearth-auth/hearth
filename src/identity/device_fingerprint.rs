//! Device-fingerprint helpers for adaptive step-up MFA (HEA-836).
//!
//! This module re-exports the storage-backed [`device_fp`] implementation and
//! provides the public `derive_fingerprint_key` convenience function used by
//! tests and integration callers.
//!
//! The canonical storage is in [`crate::identity::device_fp`].

pub use crate::identity::device_fp::{DeviceFingerprintOutcome, DeviceFingerprintStore};

use crate::core::UserId;
use crate::identity::keys;

/// Derive a stable storage key for a `(user, ip, user_agent)` triple.
///
/// Normalises the IP to its /24 subnet and the User-Agent to its major-version
/// before hashing. Only the HMAC output is stored — no raw PII.
///
/// Delegates to [`DeviceFingerprintStore::derive_hmac`].
#[must_use]
pub fn derive_fingerprint_key(
    user_id: &UserId,
    ip_prefix: &str,
    user_agent_normalized: &str,
    secret: &str,
) -> String {
    let hmac =
        DeviceFingerprintStore::derive_hmac(secret, user_id, ip_prefix, user_agent_normalized);
    let hmac_hex = hex::encode(hmac);
    // INVARIANT: encode_device_fp produces ASCII-only bytes (uuid + hex chars).
    #[allow(clippy::unwrap_used)]
    String::from_utf8(keys::encode_device_fp(user_id, &hmac_hex)).unwrap()
}
