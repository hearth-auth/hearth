//! Device fingerprint storage for adaptive (risk-based) MFA.
//!
//! Stores HMAC-SHA256 digests of `(user_id, ip /24 or /48, user_agent)` with an
//! expiry timestamp. Only the HMAC output is persisted — never raw IP addresses or
//! User-Agent strings (GDPR / AC-11).
//!
//! # Storage layout
//!
//! Key:   `dfp:user:{user_uuid}:{hmac_hex}` (realm-scoped via `StorageEngine`)
//! Value: 8-byte little-endian `i64` Unix-seconds expiry

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::hmac;

use crate::core::{RealmId, UserId};
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::storage::StorageEngine;

/// Result of a fingerprint existence check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintResult {
    /// Fingerprint found and not expired; TTL has been refreshed in place.
    Recognised,
    /// Fingerprint not present (or expired).
    Unrecognised,
}

/// High-level outcome returned by the identity engine's adaptive-MFA gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceFingerprintOutcome {
    /// Feature disabled (`adaptive_mfa.enabled = false`) or HMAC secret empty.
    Skipped,
    /// Device recognised within the rolling window. Proceed normally.
    Recognised,
    /// Device unrecognised; user has an enrolled MFA factor. Inject step-up.
    StepUpRequired,
    /// Device unrecognised; user has no enrolled MFA factor.
    /// Append `RequiredAction::EnrollMfa` and issue an RA token.
    EnrollMfaRequired,
}

/// Thin storage wrapper for device fingerprint records.
///
/// One instance is shared across all realms inside `EmbeddedIdentityEngine`.
/// All operations are realm-scoped via the underlying `StorageEngine`.
pub struct DeviceFingerprintStore {
    storage: Arc<dyn StorageEngine>,
}

impl std::fmt::Debug for DeviceFingerprintStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceFingerprintStore")
            .finish_non_exhaustive()
    }
}

impl DeviceFingerprintStore {
    /// Creates a new store backed by `storage`.
    pub fn new(storage: Arc<dyn StorageEngine>) -> Self {
        Self { storage }
    }

    /// Derives the HMAC-SHA256 fingerprint for a `(user_id, ip, user_agent)` triple.
    ///
    /// The IP address is normalised to its /24 subnet (IPv4) or /48 prefix (IPv6)
    /// and the User-Agent is normalised to major-version tokens only (e.g.
    /// `Chrome/125.0.6422.112` → `Chrome/125`) before hashing.  Raw values are
    /// never stored.
    ///
    /// HMAC input: `user_id_bytes \x00 ip_subnet \x00 ua_normalized`
    pub fn derive_hmac(secret: &str, user_id: &UserId, ip: &str, user_agent: &str) -> [u8; 32] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let subnet = ip_subnet(ip);
        let ua_norm = normalize_user_agent(user_agent);
        let mut msg: Vec<u8> = Vec::with_capacity(16 + 1 + subnet.len() + 1 + ua_norm.len());
        msg.extend_from_slice(user_id.as_uuid().as_bytes());
        msg.push(0u8);
        msg.extend_from_slice(subnet.as_bytes());
        msg.push(0u8);
        msg.extend_from_slice(ua_norm.as_bytes());
        let tag = hmac::sign(&key, &msg);
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        out
    }

    /// Checks whether `hmac_bytes` is a recognised (non-expired) fingerprint for
    /// this user in this realm. If it is, the TTL is refreshed to
    /// `now + window_days * 86400` seconds before returning.
    pub fn check_and_refresh(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        hmac_bytes: &[u8; 32],
        window_days: u32,
    ) -> Result<FingerprintResult, IdentityError> {
        let hmac_hex = hex::encode(hmac_bytes);
        let key = keys::encode_device_fp(user_id, &hmac_hex);
        let now_secs = unix_now_secs();

        match self
            .storage
            .get(realm_id, &key)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?
        {
            Some(bytes) if bytes.len() == 8 => {
                let expires_at = i64::from_le_bytes(bytes.try_into().expect("8 bytes"));
                if expires_at <= now_secs {
                    // Expired — treat as unrecognised; lazy cleanup.
                    self.storage
                        .delete(realm_id, &key)
                        .map_err(|e| IdentityError::Storage(Box::new(e)))?;
                    return Ok(FingerprintResult::Unrecognised);
                }
                // Refresh TTL (AC-9 rolling window).
                let new_expiry = now_secs + i64::from(window_days) * 86400;
                self.storage
                    .put(realm_id, &key, &new_expiry.to_le_bytes())
                    .map_err(|e| IdentityError::Storage(Box::new(e)))?;
                Ok(FingerprintResult::Recognised)
            }
            _ => Ok(FingerprintResult::Unrecognised),
        }
    }

    /// Upserts a fingerprint with `expires_at = now + window_days * 86400`.
    ///
    /// Call this after a successful step-up MFA challenge to mark the device
    /// as trusted for the configured recognition window.
    pub fn record(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        hmac_bytes: &[u8; 32],
        window_days: u32,
    ) -> Result<(), IdentityError> {
        let hmac_hex = hex::encode(hmac_bytes);
        let key = keys::encode_device_fp(user_id, &hmac_hex);
        let expires_at = unix_now_secs() + i64::from(window_days) * 86400;
        self.storage
            .put(realm_id, &key, &expires_at.to_le_bytes())
            .map_err(|e| IdentityError::Storage(Box::new(e)))
    }

    /// Reads the raw expiry (Unix seconds) for a fingerprint without modifying it.
    ///
    /// Returns `None` when the key is absent. Used by tests to verify TTL refresh.
    pub fn get_expiry(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        hmac_bytes: &[u8; 32],
    ) -> Result<Option<i64>, IdentityError> {
        let hmac_hex = hex::encode(hmac_bytes);
        let key = keys::encode_device_fp(user_id, &hmac_hex);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?
        {
            Some(bytes) if bytes.len() == 8 => {
                Ok(Some(i64::from_le_bytes(bytes.try_into().expect("8 bytes"))))
            }
            _ => Ok(None),
        }
    }

    /// Deletes every fingerprint stored for `user_id` in this realm.
    ///
    /// Used during `delete_user` (GDPR Art. 17 right-to-erasure cascade) and by
    /// the admin erasure API (`DELETE /admin/users/{id}/device-fingerprints`).
    /// Returns the number of keys removed.
    pub fn delete_all_for_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<usize, IdentityError> {
        let prefix = keys::device_fp_scan_prefix(user_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?;
        let count = entries.len();
        for entry in entries {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(|e| IdentityError::Storage(Box::new(e)))?;
        }
        Ok(count)
    }

    /// Removes all fingerprints whose expiry is in the past.
    ///
    /// Intended for periodic background sweeping. The hot path uses lazy expiry
    /// on read, so this is optional but keeps storage bounded.
    pub fn sweep_expired(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<usize, IdentityError> {
        let prefix = keys::device_fp_scan_prefix(user_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?;

        let now_secs = unix_now_secs();
        let mut removed = 0usize;
        for entry in entries {
            if entry.value.len() == 8 {
                let expires_at = i64::from_le_bytes(entry.value.try_into().expect("8 bytes"));
                if expires_at <= now_secs {
                    self.storage
                        .delete(realm_id, &entry.key)
                        .map_err(|e| IdentityError::Storage(Box::new(e)))?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the /24 subnet string for IPv4 or /48 prefix for IPv6.
///
/// Falls back to the raw string if the input cannot be parsed (e.g. empty string,
/// Unix socket address). This is a best-effort normalisation; if the IP is truly
/// unknown the fingerprint will just be unique per login, which is conservative.
fn ip_subnet(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let o = v4.octets();
            format!("{}.{}.{}", o[0], o[1], o[2])
        }
        Ok(IpAddr::V6(v6)) => {
            let segs = v6.segments();
            // First 48 bits = first 3 × 16-bit groups.
            format!("{:x}:{:x}:{:x}", segs[0], segs[1], segs[2])
        }
        Err(_) => ip.to_string(),
    }
}

/// Normalise a User-Agent string to major-version tokens only.
///
/// Each `Name/M.minor.patch` token is reduced to `Name/M` so that minor
/// browser updates do not produce a new fingerprint and trigger an unwanted
/// step-up challenge.
fn normalize_user_agent(ua: &str) -> String {
    let mut out = String::with_capacity(ua.len());
    for (i, token) in ua.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if let Some(slash_pos) = token.find('/') {
            let name = &token[..slash_pos];
            let ver = &token[slash_pos + 1..];
            let major = ver.split('.').next().unwrap_or(ver);
            out.push_str(name);
            out.push('/');
            out.push_str(major);
        } else {
            out.push_str(token);
        }
    }
    out
}

/// Returns the current time as Unix seconds (`i64`).
fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::UserId;

    fn dummy_user_id() -> UserId {
        UserId::new(uuid::Uuid::new_v4())
    }

    #[test]
    fn derive_hmac_is_deterministic() {
        let uid = dummy_user_id();
        let h1 = DeviceFingerprintStore::derive_hmac("secret", &uid, "1.2.3.4", "ua");
        let h2 = DeviceFingerprintStore::derive_hmac("secret", &uid, "1.2.3.4", "ua");
        assert_eq!(h1, h2);
    }

    #[test]
    fn derive_hmac_same_subnet_same_hash() {
        let uid = dummy_user_id();
        let h1 = DeviceFingerprintStore::derive_hmac("secret", &uid, "192.168.1.1", "ua");
        let h2 = DeviceFingerprintStore::derive_hmac("secret", &uid, "192.168.1.200", "ua");
        assert_eq!(h1, h2, "/24 hosts must produce same HMAC");
    }

    #[test]
    fn derive_hmac_different_subnet_different_hash() {
        let uid = dummy_user_id();
        let h1 = DeviceFingerprintStore::derive_hmac("secret", &uid, "192.168.1.1", "ua");
        let h2 = DeviceFingerprintStore::derive_hmac("secret", &uid, "192.168.2.1", "ua");
        assert_ne!(h1, h2);
    }

    #[test]
    fn derive_hmac_different_user_different_hash() {
        let u1 = dummy_user_id();
        let u2 = dummy_user_id();
        let h1 = DeviceFingerprintStore::derive_hmac("secret", &u1, "1.2.3.4", "ua");
        let h2 = DeviceFingerprintStore::derive_hmac("secret", &u2, "1.2.3.4", "ua");
        assert_ne!(h1, h2);
    }

    #[test]
    fn ip_subnet_ipv4_normalisation() {
        assert_eq!(ip_subnet("10.0.0.42"), "10.0.0");
        assert_eq!(ip_subnet("192.168.1.1"), "192.168.1");
        assert_eq!(ip_subnet("255.255.255.254"), "255.255.255");
    }

    #[test]
    fn ip_subnet_ipv6_normalisation() {
        // Same /48, different suffix
        assert_eq!(
            ip_subnet("2001:db8:85a3::8a2e:370:7334"),
            ip_subnet("2001:db8:85a3::dead:beef:cafe")
        );
        // Different /48
        assert_ne!(ip_subnet("2001:db8:85a3::1"), ip_subnet("2001:db8:1234::1"));
    }

    #[test]
    fn ip_subnet_unknown_fallback() {
        // Non-IP strings pass through unchanged so the HMAC still works.
        assert_eq!(ip_subnet(""), "");
        assert_eq!(ip_subnet("unknown"), "unknown");
    }
}
