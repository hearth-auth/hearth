//! Device-fingerprint helpers for adaptive step-up MFA (HEA-836).
//!
//! This module re-exports the storage-backed [`device_fp`] implementation and
//! provides the public `derive_fingerprint_key` convenience function used by
//! tests and integration callers.
//!
//! The canonical storage is in [`crate::identity::device_fp`].

pub use crate::identity::device_fp::{DeviceFingerprintOutcome, DeviceFingerprintStore};

use crate::core::UserId;

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
    secret: &[u8],
) -> String {
    let secret_str = std::str::from_utf8(secret).unwrap_or("");
    let hmac =
        DeviceFingerprintStore::derive_hmac(secret_str, user_id, ip_prefix, user_agent_normalized);
    format!("dev:fp:{}:{}", user_id.as_uuid(), hex::encode(hmac))
}
