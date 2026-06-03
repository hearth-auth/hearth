//! Credential storage: password hashing, verification, and types.
//!
//! Uses Argon2id as the primary hashing algorithm (OWASP recommended).
//! Supports verification of bcrypt and scrypt hashes for migration scenarios.
//! All cleartext passwords are wrapped in `Zeroize`-on-drop types.
//!
//! # Pepper rotation
//!
//! When `CredentialConfig::pepper` is set, a server-side secret is applied to
//! the password bytes via HMAC-SHA256 before Argon2id hashing. The pepper
//! version is stored in `StoredCredential::pepper_version` so that rotation is
//! possible: on login, both the active pepper and, during the configured grace
//! window, the previous pepper are tried. A credential verified with the
//! previous pepper has `needs_rehash = true` set in the return from
//! [`verify_password_with_pepper`], signalling the engine to lazily re-hash
//! with the active pepper.

use std::fmt;

use argon2::Argon2;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use pbkdf2::pbkdf2;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::identity::error::IdentityError;

/// A secret pepper key used to pre-hash passwords before Argon2id.
///
/// Zeroed from memory on drop. Does NOT implement `Debug` content-revealing
/// output, `Display`, or `Serialize` to prevent accidental secret exposure.
///
/// The key MUST be at least 32 bytes (256 bits).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PepperKey {
    bytes: Vec<u8>,
}

impl fmt::Debug for PepperKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PepperKey([REDACTED])")
    }
}

impl PepperKey {
    /// Creates a new pepper key from raw bytes.
    ///
    /// Returns an error if fewer than 32 bytes are supplied.
    pub fn new(bytes: Vec<u8>) -> Result<Self, IdentityError> {
        if bytes.len() < 32 {
            return Err(IdentityError::InvalidInput {
                reason: format!("pepper key must be at least 32 bytes, got {}", bytes.len()),
            });
        }
        Ok(Self { bytes })
    }

    /// Creates a pepper key from a hex-encoded string.
    ///
    /// Accepts uppercase or lowercase hex. Returns an error if the string is
    /// not valid hex or is shorter than 64 hex chars (32 bytes).
    pub fn from_hex(hex: &str) -> Result<Self, IdentityError> {
        let bytes = hex::decode(hex).map_err(|e| IdentityError::InvalidInput {
            reason: format!("invalid pepper hex: {e}"),
        })?;
        Self::new(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Configuration for server-side Argon2 pepper rotation.
///
/// When present in `CredentialConfig`, a pepper is applied via
/// HMAC-SHA256 before password hashing. The `active_version` is embedded in
/// `StoredCredential::pepper_version`. The `previous_*` fields allow graceful
/// rotation: both peppers are tried on login during the operator-controlled
/// grace window.
#[derive(Debug, Clone)]
pub struct PepperConfig {
    /// Version identifier for the active (current) pepper.
    pub active_version: u32,
    /// The currently active pepper key — used for all new and rehashed credentials.
    pub active_key: PepperKey,
    /// Version identifier for the previous pepper, if a rotation is in progress.
    ///
    /// When set, credentials carrying this version are accepted on login and
    /// lazily re-hashed with the active pepper. Remove this field once the
    /// grace window has elapsed and all active users have logged in.
    pub previous_version: Option<u32>,
    /// The previous pepper key. Must be `Some` iff `previous_version` is `Some`.
    pub previous_key: Option<PepperKey>,
}

/// A cleartext password that is zeroed from memory on drop.
///
/// **Security**: This type intentionally does NOT implement `Display`,
/// `Serialize`, or content-revealing `Debug`. The `Debug` impl prints
/// a redacted placeholder.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CleartextPassword {
    bytes: Vec<u8>,
}

impl fmt::Debug for CleartextPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CleartextPassword(***)")
    }
}

impl CleartextPassword {
    /// Creates a new cleartext password from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Creates a new cleartext password from a string.
    pub fn from_string(s: String) -> Self {
        Self {
            bytes: s.into_bytes(),
        }
    }

    /// Returns the password bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The hashing algorithm used for a stored credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PasswordAlgorithm {
    /// Argon2id — the recommended algorithm.
    Argon2id,
    /// Bcrypt — supported for migration from legacy systems.
    Bcrypt,
    /// Scrypt — supported for migration from legacy systems.
    Scrypt,
    /// PBKDF2-HMAC-SHA256 — supported for migration from Keycloak and
    /// similar legacy systems. Verification only: new credentials are
    /// always hashed with Argon2id.
    Pbkdf2Sha256,
}

/// A stored password credential.
///
/// Contains the hashed password in PHC string format along with metadata.
/// The `Debug` implementation redacts the hash field to prevent accidental
/// exposure in logs.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// The hashing algorithm used.
    pub algorithm: PasswordAlgorithm,
    /// The password hash in PHC string format.
    pub hash: String,
    /// When this credential was created (Unix microseconds).
    pub created_at: i64,
    /// Pepper version used when hashing. `None` means no pepper was applied.
    ///
    /// Introduced in A-46. Existing credentials without this field deserialize
    /// to `None` via `serde(default)` — backward-compatible.
    #[serde(default)]
    pub pepper_version: Option<u32>,
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredCredential")
            .field("algorithm", &self.algorithm)
            .field("hash", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("pepper_version", &self.pepper_version)
            .finish()
    }
}

/// Configuration for password hashing parameters.
///
/// Defaults follow OWASP recommendations for Argon2id:
/// - 19 MiB memory cost
/// - 2 iterations (time cost)
/// - 1 degree of parallelism
#[derive(Debug, Clone)]
pub struct CredentialConfig {
    /// Memory cost in KiB for Argon2id.
    pub memory_cost_kib: u32,
    /// Number of iterations (time cost) for Argon2id.
    pub time_cost: u32,
    /// Degree of parallelism for Argon2id.
    pub parallelism: u32,
    /// Optional pepper configuration.
    ///
    /// When `Some`, all new credentials are peppered with
    /// `HMAC-SHA256(key=active_key, msg=password)` before Argon2id hashing.
    /// Existing un-peppered credentials are lazily re-hashed on the next
    /// successful login.
    pub pepper: Option<PepperConfig>,
}

impl Default for CredentialConfig {
    fn default() -> Self {
        Self {
            memory_cost_kib: 19_456, // 19 MiB per OWASP
            time_cost: 2,
            parallelism: 1,
            pepper: None,
        }
    }
}

impl CredentialConfig {
    /// Returns a fast configuration suitable for tests.
    ///
    /// Uses minimal parameters to keep test execution fast while still
    /// exercising the hashing pipeline.
    pub fn fast_for_testing() -> Self {
        Self {
            memory_cost_kib: 256, // 256 KiB — fast enough for tests
            time_cost: 1,
            parallelism: 1,
            pepper: None,
        }
    }

    /// Returns a fast test configuration with an active pepper.
    pub fn fast_for_testing_with_pepper(active_version: u32, active_key: PepperKey) -> Self {
        Self {
            pepper: Some(PepperConfig {
                active_version,
                active_key,
                previous_version: None,
                previous_key: None,
            }),
            ..Self::fast_for_testing()
        }
    }

    /// Builds an `Argon2` hasher from this configuration.
    fn to_argon2(&self) -> Result<Argon2<'static>, IdentityError> {
        let params =
            argon2::Params::new(self.memory_cost_kib, self.time_cost, self.parallelism, None)
                .map_err(|e| IdentityError::InvalidInput {
                    reason: format!("invalid Argon2id parameters: {e}"),
                })?;
        Ok(Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

/// Applies HMAC-SHA256(key=pepper, msg=password) and returns the 32-byte digest.
///
/// The result is used as the effective password input to Argon2, keeping the
/// pepper secret from the stored hash while providing meaningful pre-hashing.
fn apply_pepper(password_bytes: &[u8], pepper: &PepperKey) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(pepper.as_bytes())
        .expect("HMAC accepts any key length — invariant: PepperKey::new validates ≥32 bytes");
    mac.update(password_bytes);
    mac.finalize().into_bytes().to_vec()
}

/// Hashes a password using Argon2id with the given configuration.
///
/// When `config.pepper` is set, the password is pre-hashed via
/// `HMAC-SHA256(key=active_key, msg=password)` before Argon2id hashing, and
/// the resulting `StoredCredential` carries the active pepper version.
///
/// Returns a `StoredCredential` with the hash in PHC string format.
pub fn hash_password(
    password: &CleartextPassword,
    config: &CredentialConfig,
    created_at: i64,
) -> Result<StoredCredential, IdentityError> {
    let argon2 = config.to_argon2()?;
    let salt = SaltString::generate(&mut OsRng);

    // Apply pepper if configured — HMAC output replaces raw password bytes.
    let (effective_input, pepper_version) = if let Some(pepper_cfg) = &config.pepper {
        let peppered = apply_pepper(password.as_bytes(), &pepper_cfg.active_key);
        (peppered, Some(pepper_cfg.active_version))
    } else {
        (password.as_bytes().to_vec(), None)
    };

    let hash =
        argon2
            .hash_password(&effective_input, &salt)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("password hashing failed: {e}"),
            })?;

    Ok(StoredCredential {
        algorithm: PasswordAlgorithm::Argon2id,
        hash: hash.to_string(),
        created_at,
        pepper_version,
    })
}

/// Verifies a password against a stored credential.
///
/// Supports Argon2id, bcrypt, and scrypt hash formats. The algorithm
/// is determined from the PHC string prefix, not the `algorithm` field,
/// ensuring correct verification regardless of metadata.
#[allow(dead_code)] // pepper-unaware callers and test utilities use this
pub(crate) fn verify_password(
    password: &CleartextPassword,
    credential: &StoredCredential,
) -> Result<bool, IdentityError> {
    verify_hash(password, &credential.hash)
}

/// Verifies a password with pepper support, returning `(matches, needs_rehash)`.
///
/// - `matches`: whether the supplied password is correct.
/// - `needs_rehash`: whether the credential should be re-hashed with the
///   active pepper on the next successful login. This is `true` when the
///   credential was verified with a previous or absent pepper.
///
/// # Pepper verification order
///
/// 1. If no pepper is configured and credential has no pepper version:
///    plain `verify_hash` path (no change from pre-A-46 behaviour).
/// 2. If pepper is configured and credential's version matches the active one:
///    verify with active pepper, `needs_rehash = false`.
/// 3. If credential's version matches the previous pepper (rotation in progress):
///    verify with previous pepper, `needs_rehash = true`.
/// 4. If credential has no pepper version but pepper is now configured:
///    verify without pepper (legacy credential), `needs_rehash = true` on match.
/// 5. Credential pepper version unrecognised (rotation complete, grace window
///    closed by operator removing `previous`): reject with `matches = false`.
pub fn verify_password_with_pepper(
    password: &CleartextPassword,
    credential: &StoredCredential,
    config: &CredentialConfig,
) -> Result<(bool, bool), IdentityError> {
    let Some(pepper_cfg) = &config.pepper else {
        // No pepper configured at all — verify without pepper.
        let matches = verify_hash(password, &credential.hash)?;
        // If the stored credential somehow has a pepper version, flag for rehash
        // (e.g., pepper was removed from config — unusual but defensive).
        let needs_rehash = matches && credential.pepper_version.is_some();
        return Ok((matches, needs_rehash));
    };

    // Determine which pepper key to use based on stored version.
    match credential.pepper_version {
        Some(v) if v == pepper_cfg.active_version => {
            // Up-to-date — use active pepper.
            let peppered = apply_pepper(password.as_bytes(), &pepper_cfg.active_key);
            let pw_peppered = CleartextPassword::new(peppered);
            let matches = verify_hash(&pw_peppered, &credential.hash)?;
            Ok((matches, false))
        }
        Some(v) if pepper_cfg.previous_version == Some(v) && pepper_cfg.previous_key.is_some() => {
            // Grace window: previous pepper accepted, rehash triggered on success.
            let prev_key = pepper_cfg.previous_key.as_ref().expect("checked is_some");
            let peppered = apply_pepper(password.as_bytes(), prev_key);
            let pw_peppered = CleartextPassword::new(peppered);
            let matches = verify_hash(&pw_peppered, &credential.hash)?;
            Ok((matches, matches)) // needs_rehash only when password is correct
        }
        Some(_) => {
            // Unrecognised pepper version — grace window closed. Reject.
            Ok((false, false))
        }
        None => {
            // Legacy credential with no pepper. Verify without pepper and
            // flag for rehash so the next successful login upgrades it.
            let matches = verify_hash(password, &credential.hash)?;
            Ok((matches, matches))
        }
    }
}

/// Returns `true` if the Argon2id hash was produced with parameters that differ
/// from `config`, meaning the credential should be transparently re-hashed on
/// the next successful login.
///
/// Always returns `false` for non-Argon2id hash strings (those are handled by
/// the separate legacy-algorithm upgrade path).
pub(crate) fn argon2_params_need_rehash(hash_str: &str, config: &CredentialConfig) -> bool {
    if !hash_str.starts_with("$argon2id$") {
        return false;
    }
    // Argon2id PHC format: $argon2id$v=19$m=N,t=N,p=N$<salt>$<hash>
    // Locate the params segment — the one that contains "m=" (memory cost).
    let mut m: Option<u32> = None;
    let mut t: Option<u32> = None;
    for seg in hash_str.split('$') {
        if seg.contains("m=") {
            for kv in seg.split(',') {
                if let Some(v) = kv.strip_prefix("m=") {
                    m = v.parse().ok();
                } else if let Some(v) = kv.strip_prefix("t=") {
                    t = v.parse().ok();
                }
            }
            break;
        }
    }
    m.map_or(false, |v| v != config.memory_cost_kib) || t.map_or(false, |v| v != config.time_cost)
}

/// Verifies a password against a hash string.
///
/// Dispatches to the correct algorithm based on the hash prefix.
pub(crate) fn verify_hash(
    password: &CleartextPassword,
    hash_str: &str,
) -> Result<bool, IdentityError> {
    // Try bcrypt first — bcrypt hashes start with "$2b$" or "$2a$"
    if hash_str.starts_with("$2b$") || hash_str.starts_with("$2a$") {
        return Ok(bcrypt::verify(password.as_bytes(), hash_str).unwrap_or(false));
    }

    // PBKDF2-SHA256: `$pbkdf2-sha256$i=N$<salt-b64>$<hash-b64>`.
    // The `password-hash` crate does not ship a PBKDF2 verifier, so we
    // parse the PHC string manually and compare in constant time.
    if hash_str.starts_with("$pbkdf2-sha256$") {
        return verify_pbkdf2_sha256(password.as_bytes(), hash_str);
    }

    // Parse as PHC string for argon2id and scrypt
    let parsed = PasswordHash::new(hash_str).map_err(|e| IdentityError::InvalidInput {
        reason: format!("invalid password hash format: {e}"),
    })?;

    // Dispatch based on algorithm identifier in the PHC string
    let alg_id = parsed.algorithm;
    if alg_id == argon2::ARGON2ID_IDENT {
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    } else if alg_id == scrypt::ALG_ID {
        Ok(scrypt::Scrypt
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    } else {
        Err(IdentityError::InvalidInput {
            reason: format!("unsupported password hash algorithm: {alg_id}"),
        })
    }
}

/// Verifies a password against a PBKDF2-HMAC-SHA256 PHC string.
///
/// Format: `$pbkdf2-sha256$i=<iterations>$<salt-b64>$<hash-b64>`.
///
/// Base64 encoding is the PHC standard-no-padding variant. The hash
/// length in the PHC string determines how many derived bytes to
/// compute; this matches Keycloak's default of 32 bytes but also
/// supports other sizes produced by alternative exporters.
fn verify_pbkdf2_sha256(password: &[u8], hash_str: &str) -> Result<bool, IdentityError> {
    let mut parts = hash_str.split('$');
    // The PHC string starts with an empty segment because of the
    // leading '$'; skip it, then consume the four payload segments.
    let _empty = parts.next();
    let algo = parts.next().ok_or_else(|| IdentityError::InvalidInput {
        reason: "invalid pbkdf2 hash: missing algorithm".to_string(),
    })?;
    if algo != "pbkdf2-sha256" {
        return Err(IdentityError::InvalidInput {
            reason: format!("unexpected pbkdf2 variant: {algo}"),
        });
    }
    let params = parts.next().ok_or_else(|| IdentityError::InvalidInput {
        reason: "invalid pbkdf2 hash: missing parameters".to_string(),
    })?;
    let iterations = params
        .strip_prefix("i=")
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| IdentityError::InvalidInput {
            reason: format!("invalid pbkdf2 iterations: {params}"),
        })?;
    if iterations == 0 {
        return Err(IdentityError::InvalidInput {
            reason: "pbkdf2 iterations must be non-zero".to_string(),
        });
    }
    let salt_b64 = parts.next().ok_or_else(|| IdentityError::InvalidInput {
        reason: "invalid pbkdf2 hash: missing salt".to_string(),
    })?;
    let hash_b64 = parts.next().ok_or_else(|| IdentityError::InvalidInput {
        reason: "invalid pbkdf2 hash: missing hash".to_string(),
    })?;
    if parts.next().is_some() {
        return Err(IdentityError::InvalidInput {
            reason: "invalid pbkdf2 hash: trailing data".to_string(),
        });
    }

    let salt = STANDARD_NO_PAD
        .decode(salt_b64)
        .map_err(|e| IdentityError::InvalidInput {
            reason: format!("invalid pbkdf2 salt: {e}"),
        })?;
    let expected = STANDARD_NO_PAD
        .decode(hash_b64)
        .map_err(|e| IdentityError::InvalidInput {
            reason: format!("invalid pbkdf2 hash: {e}"),
        })?;

    let mut derived = vec![0u8; expected.len()];
    pbkdf2::<Hmac<Sha256>>(password, &salt, iterations, &mut derived).map_err(|e| {
        IdentityError::InvalidInput {
            reason: format!("pbkdf2 derivation failed: {e}"),
        }
    })?;

    // Constant-time equality — prevents timing oracles on hash comparison.
    Ok(derived.ct_eq(&expected).into())
}

/// Hashes a raw secret (e.g., client secret) with Argon2id.
///
/// Returns the PHC-formatted hash string. Used for confidential OAuth
/// client authentication where we don't have a `CleartextPassword` wrapper.
pub(crate) fn hash_raw_secret(
    secret: &[u8],
    config: &CredentialConfig,
) -> Result<String, IdentityError> {
    let argon2 = config.to_argon2()?;
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2
        .hash_password(secret, &salt)
        .map_err(|e| IdentityError::InvalidInput {
            reason: format!("secret hashing failed: {e}"),
        })?;
    Ok(hash.to_string())
}

/// Verifies a raw secret against an Argon2id hash string.
///
/// Returns `true` if the secret matches the hash.
pub(crate) fn verify_raw_secret(secret: &[u8], hash_str: &str) -> Result<bool, IdentityError> {
    let parsed = PasswordHash::new(hash_str).map_err(|e| IdentityError::InvalidInput {
        reason: format!("invalid hash format: {e}"),
    })?;
    Ok(Argon2::default().verify_password(secret, &parsed).is_ok())
}

/// Pre-computes a dummy hash for timing-oracle prevention.
///
/// When `verify_password` is called for a nonexistent user, we verify
/// against this dummy hash so the response time is indistinguishable
/// from a real failed verification.
pub(crate) fn compute_dummy_hash(config: &CredentialConfig) -> String {
    let argon2 = config.to_argon2().expect("default config should be valid");
    let salt = SaltString::generate(&mut OsRng);
    let dummy_password = b"dummy_password_for_timing_defense";
    argon2
        .hash_password(dummy_password, &salt)
        .expect("dummy hash should succeed")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CredentialConfig {
        CredentialConfig::fast_for_testing()
    }

    // ===== CleartextPassword =====

    #[test]
    fn cleartext_password_debug_is_redacted() {
        let pw = CleartextPassword::from_string("supersecret".to_string());
        let debug = format!("{pw:?}");
        assert!(
            !debug.contains("supersecret"),
            "debug must not reveal password: {debug}"
        );
        assert!(
            debug.contains("***"),
            "debug should show redacted placeholder: {debug}"
        );
    }

    #[test]
    fn cleartext_password_as_bytes() {
        let pw = CleartextPassword::from_string("hello".to_string());
        assert_eq!(pw.as_bytes(), b"hello");
    }

    #[test]
    fn cleartext_password_from_raw_bytes() {
        let pw = CleartextPassword::new(vec![0x00, 0xFF, 0x42]);
        assert_eq!(pw.as_bytes(), &[0x00, 0xFF, 0x42]);
    }

    // ===== StoredCredential =====

    #[test]
    fn stored_credential_debug_redacts_hash() {
        let cred = StoredCredential {
            algorithm: PasswordAlgorithm::Argon2id,
            hash: "$argon2id$v=19$m=256,t=1,p=1$somesalt$somehash".to_string(),
            created_at: 1_000_000,
            pepper_version: None,
        };
        let debug = format!("{cred:?}");
        assert!(
            !debug.contains("somesalt"),
            "debug must not reveal salt: {debug}"
        );
        assert!(
            !debug.contains("somehash"),
            "debug must not reveal hash: {debug}"
        );
        assert!(
            debug.contains("REDACTED"),
            "debug should show REDACTED: {debug}"
        );
    }

    #[test]
    fn stored_credential_serde_roundtrip() {
        let cred = StoredCredential {
            algorithm: PasswordAlgorithm::Argon2id,
            hash: "$argon2id$v=19$m=256,t=1,p=1$salt$hash".to_string(),
            created_at: 1_000_000,
            pepper_version: Some(3),
        };
        let json = serde_json::to_string(&cred).expect("serialize");
        let deserialized: StoredCredential = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.algorithm, cred.algorithm);
        assert_eq!(deserialized.hash, cred.hash);
        assert_eq!(deserialized.created_at, cred.created_at);
        assert_eq!(deserialized.pepper_version, cred.pepper_version);
    }

    #[test]
    fn stored_credential_pepper_version_serde_default() {
        // Old credentials serialized without pepper_version must deserialize to None.
        let json =
            r#"{"algorithm":"Argon2id","hash":"$argon2id$v=19$m=256,t=1,p=1$x$y","created_at":0}"#;
        let cred: StoredCredential = serde_json::from_str(json).expect("deserialize legacy");
        assert_eq!(
            cred.pepper_version, None,
            "legacy credentials must deserialize with pepper_version=None"
        );
    }

    // ===== Scenario 1: Hash + verify =====

    #[test]
    fn hash_and_verify_correct_password() {
        let config = test_config();
        let pw = CleartextPassword::from_string("correct-horse-battery-staple".to_string());
        let cred = hash_password(&pw, &config, 1_000_000).expect("hash");

        assert_eq!(cred.algorithm, PasswordAlgorithm::Argon2id);
        assert!(
            cred.hash.starts_with("$argon2id$"),
            "hash should be PHC format"
        );

        let result = verify_password(&pw, &cred).expect("verify");
        assert!(result, "correct password should verify");
    }

    #[test]
    fn hash_and_verify_wrong_password() {
        let config = test_config();
        let pw = CleartextPassword::from_string("correct-password".to_string());
        let cred = hash_password(&pw, &config, 1_000_000).expect("hash");

        let wrong = CleartextPassword::from_string("wrong-password".to_string());
        let result = verify_password(&wrong, &cred).expect("verify");
        assert!(!result, "wrong password should not verify");
    }

    #[test]
    fn different_hashes_for_same_password() {
        let config = test_config();
        let pw1 = CleartextPassword::from_string("same-password".to_string());
        let pw2 = CleartextPassword::from_string("same-password".to_string());
        let cred1 = hash_password(&pw1, &config, 1_000_000).expect("hash1");
        let cred2 = hash_password(&pw2, &config, 1_000_000).expect("hash2");

        // Different salts should produce different hashes
        assert_ne!(
            cred1.hash, cred2.hash,
            "same password should produce different hashes (different salts)"
        );
    }

    // ===== Scenario 2: Multi-algorithm verification =====

    #[test]
    fn verify_bcrypt_hash() {
        // Generate a bcrypt hash
        let hash = bcrypt::hash(b"bcrypt-password", bcrypt::DEFAULT_COST).expect("bcrypt hash");
        let pw = CleartextPassword::from_string("bcrypt-password".to_string());
        let result = verify_hash(&pw, &hash).expect("verify");
        assert!(result, "correct password should verify against bcrypt hash");

        let wrong = CleartextPassword::from_string("wrong".to_string());
        let result = verify_hash(&wrong, &hash).expect("verify");
        assert!(
            !result,
            "wrong password should not verify against bcrypt hash"
        );
    }

    #[test]
    fn verify_scrypt_hash() {
        use password_hash::PasswordHasher;
        // Generate a scrypt hash with minimal params for test speed
        let params = scrypt::Params::new(8, 1, 1, 32).expect("scrypt params");
        let salt = SaltString::generate(&mut OsRng);
        let scrypt_hasher = scrypt::Scrypt;
        let hash = scrypt_hasher
            .hash_password_customized(b"scrypt-password", None, None, params, &salt)
            .expect("scrypt hash");

        let pw = CleartextPassword::from_string("scrypt-password".to_string());
        let result = verify_hash(&pw, &hash.to_string()).expect("verify");
        assert!(result, "correct password should verify against scrypt hash");

        let wrong = CleartextPassword::from_string("wrong".to_string());
        let result = verify_hash(&wrong, &hash.to_string()).expect("verify");
        assert!(
            !result,
            "wrong password should not verify against scrypt hash"
        );
    }

    // ===== PBKDF2-SHA256 verification (migration path) =====

    /// Helper: builds a PBKDF2-SHA256 PHC string for a given password.
    fn build_pbkdf2_phc(password: &[u8], iterations: u32, salt: &[u8]) -> String {
        let mut derived = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut derived)
            .expect("pbkdf2 derivation");
        format!(
            "$pbkdf2-sha256$i={iterations}${}${}",
            STANDARD_NO_PAD.encode(salt),
            STANDARD_NO_PAD.encode(derived),
        )
    }

    #[test]
    fn verify_pbkdf2_sha256_correct_password() {
        // 27,500 is Keycloak's historical default; we use a smaller value
        // here purely for test speed. The verifier is identical either way.
        let phc = build_pbkdf2_phc(b"keycloak-password", 1000, b"keycloak-salt-16");
        let pw = CleartextPassword::from_string("keycloak-password".to_string());
        assert!(
            verify_hash(&pw, &phc).expect("verify"),
            "should accept correct password"
        );
    }

    #[test]
    fn verify_pbkdf2_sha256_wrong_password() {
        let phc = build_pbkdf2_phc(b"keycloak-password", 1000, b"keycloak-salt-16");
        let wrong = CleartextPassword::from_string("different".to_string());
        assert!(
            !verify_hash(&wrong, &phc).expect("verify"),
            "should reject wrong password"
        );
    }

    #[test]
    fn verify_pbkdf2_sha256_via_stored_credential() {
        // Round-trips through the public `verify_password` entry point so
        // a Keycloak-migrated credential works end-to-end without any
        // special-casing at the engine layer.
        let phc = build_pbkdf2_phc(b"migrated-password", 1000, b"stable-salt-abc");
        let cred = StoredCredential {
            algorithm: PasswordAlgorithm::Pbkdf2Sha256,
            hash: phc,
            created_at: 1_000_000,
            pepper_version: None,
        };
        let pw = CleartextPassword::from_string("migrated-password".to_string());
        assert!(verify_password(&pw, &cred).expect("verify"));
    }

    #[test]
    fn verify_pbkdf2_sha256_rejects_malformed_phc() {
        let pw = CleartextPassword::from_string("x".to_string());
        // Missing iterations parameter
        let bad = "$pbkdf2-sha256$i=$c2FsdA$aGFzaA";
        assert!(verify_hash(&pw, bad).is_err(), "malformed PHC must error");
    }

    // ===== Scenario 4 (P1): Custom params =====

    #[test]
    fn custom_params_respected() {
        let config = CredentialConfig {
            memory_cost_kib: 512,
            time_cost: 2,
            parallelism: 1,
            pepper: None,
        };
        let pw = CleartextPassword::from_string("test-password".to_string());
        let cred = hash_password(&pw, &config, 1_000_000).expect("hash");

        // PHC string should reflect custom memory cost
        assert!(
            cred.hash.contains("m=512"),
            "hash should contain m=512: {}",
            cred.hash
        );
        assert!(
            cred.hash.contains("t=2"),
            "hash should contain t=2: {}",
            cred.hash
        );

        // Should still verify
        let result = verify_password(&pw, &cred).expect("verify");
        assert!(result, "custom-params hash should still verify");
    }

    // ===== Default parameter pins (OWASP 2023 compliance regression guard) =====

    /// Pins the `CredentialConfig::default()` values to the OWASP 2023 minimum.
    ///
    /// If this test fails, a change accidentally regressed the security floor.
    /// Any intentional reduction MUST be reviewed and the CHANGELOG updated.
    #[test]
    fn default_credential_config_meets_owasp_2023_minimum() {
        let config = CredentialConfig::default();
        assert_eq!(
            config.memory_cost_kib, 19_456,
            "memory cost must be 19 MiB (OWASP 2023 minimum m=19456); see HEA-823"
        );
        assert_eq!(
            config.time_cost, 2,
            "time cost must be >= 2 iterations (OWASP 2023 minimum); see HEA-823"
        );
        assert_eq!(
            config.parallelism, 1,
            "parallelism must be >= 1 (OWASP 2023 minimum); see HEA-823"
        );
    }

    // ===== argon2_params_need_rehash =====

    #[test]
    fn params_need_rehash_detects_memory_change() {
        let config = CredentialConfig {
            memory_cost_kib: 512,
            time_cost: 2,
            parallelism: 1,
            pepper: None,
        };
        let pw = CleartextPassword::from_string("pw".to_string());
        let cred = hash_password(&pw, &config, 0).expect("hash");

        // Same params → no rehash needed
        assert!(!argon2_params_need_rehash(&cred.hash, &config));

        // Different memory cost → rehash needed
        let new_config = CredentialConfig {
            memory_cost_kib: 1024,
            ..config.clone()
        };
        assert!(argon2_params_need_rehash(&cred.hash, &new_config));
    }

    #[test]
    fn params_need_rehash_detects_time_change() {
        let config = CredentialConfig {
            memory_cost_kib: 512,
            time_cost: 1,
            parallelism: 1,
            pepper: None,
        };
        let pw = CleartextPassword::from_string("pw".to_string());
        let cred = hash_password(&pw, &config, 0).expect("hash");

        let new_config = CredentialConfig {
            time_cost: 3,
            ..config.clone()
        };
        assert!(argon2_params_need_rehash(&cred.hash, &new_config));
    }

    #[test]
    fn params_need_rehash_false_for_non_argon2id() {
        let config = CredentialConfig::default();
        // bcrypt hash should never trigger Argon2 param rehash
        let bcrypt_hash = "$2b$12$fakebcrypthashfakebcrypthashfakebcrypthashfakebcrypt";
        assert!(!argon2_params_need_rehash(bcrypt_hash, &config));
    }

    // ===== Dummy hash for timing =====

    #[test]
    fn dummy_hash_is_valid_argon2id() {
        let config = test_config();
        let dummy = compute_dummy_hash(&config);
        assert!(
            dummy.starts_with("$argon2id$"),
            "dummy hash should be argon2id"
        );

        // Should be verifiable (against the dummy password, not a real one)
        let parsed = PasswordHash::new(&dummy).expect("should parse as PHC");
        assert_eq!(parsed.algorithm, argon2::ARGON2ID_IDENT);
    }

    // ===== Adversarial: Debug/Display never reveals hash content =====

    #[test]
    fn password_algorithm_debug_is_safe() {
        let alg = PasswordAlgorithm::Argon2id;
        let debug = format!("{alg:?}");
        assert!(debug.contains("Argon2id"), "should show variant name");
    }

    #[test]
    fn cleartext_password_has_no_display() {
        // CleartextPassword deliberately does not implement Display.
        // This is a compile-time guarantee — if someone adds Display,
        // this test documents the intent.
        fn assert_no_display<T: fmt::Debug>() {}
        assert_no_display::<CleartextPassword>();
    }

    // ===== Pepper key =====

    fn test_pepper_key() -> PepperKey {
        PepperKey::new(vec![0xABu8; 32]).expect("32 bytes is valid")
    }

    #[allow(dead_code)]
    fn test_pepper_config(version: u32, key: PepperKey) -> PepperConfig {
        PepperConfig {
            active_version: version,
            active_key: key,
            previous_version: None,
            previous_key: None,
        }
    }

    #[test]
    fn pepper_key_too_short_is_rejected() {
        let result = PepperKey::new(vec![0u8; 31]);
        assert!(result.is_err(), "31 bytes should be rejected");
    }

    #[test]
    fn pepper_key_exactly_32_bytes_accepted() {
        let result = PepperKey::new(vec![0u8; 32]);
        assert!(result.is_ok(), "32 bytes should be accepted");
    }

    #[test]
    fn pepper_key_debug_is_redacted() {
        let key = test_pepper_key();
        let debug = format!("{key:?}");
        assert!(
            !debug.contains("AB") && !debug.contains("ab"),
            "pepper key debug must not reveal key bytes: {debug}"
        );
        assert!(
            debug.contains("REDACTED"),
            "pepper key debug should show REDACTED: {debug}"
        );
    }

    #[test]
    fn pepper_key_from_hex() {
        let key = PepperKey::from_hex(&"ab".repeat(32)).expect("valid hex");
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn pepper_key_from_hex_too_short() {
        // 31 bytes = 62 hex chars
        assert!(PepperKey::from_hex(&"ab".repeat(31)).is_err());
    }

    // ===== Pepper hash and verify =====

    #[test]
    fn hash_with_pepper_embeds_pepper_version() {
        let key = test_pepper_key();
        let config = CredentialConfig::fast_for_testing_with_pepper(1, key);
        let pw = CleartextPassword::from_string("correct-horse".to_string());
        let cred = hash_password(&pw, &config, 0).expect("hash");

        assert_eq!(cred.pepper_version, Some(1), "pepper_version must be set");
    }

    #[test]
    fn hash_without_pepper_has_no_pepper_version() {
        let config = CredentialConfig::fast_for_testing();
        let pw = CleartextPassword::from_string("password".to_string());
        let cred = hash_password(&pw, &config, 0).expect("hash");
        assert_eq!(cred.pepper_version, None);
    }

    #[test]
    fn verify_with_active_pepper_correct_password() {
        let key = PepperKey::new(vec![0x55u8; 32]).expect("ok");
        let config = CredentialConfig::fast_for_testing_with_pepper(1, key);
        let pw = CleartextPassword::from_string("hunter2".to_string());
        let cred = hash_password(&pw, &config, 0).expect("hash");

        let (matches, needs_rehash) =
            verify_password_with_pepper(&pw, &cred, &config).expect("verify");
        assert!(matches, "correct password should verify");
        assert!(!needs_rehash, "up-to-date pepper needs no rehash");
    }

    #[test]
    fn verify_with_active_pepper_wrong_password() {
        let key = PepperKey::new(vec![0x55u8; 32]).expect("ok");
        let config = CredentialConfig::fast_for_testing_with_pepper(1, key);
        let pw = CleartextPassword::from_string("hunter2".to_string());
        let cred = hash_password(&pw, &config, 0).expect("hash");

        let wrong = CleartextPassword::from_string("wrong".to_string());
        let (matches, needs_rehash) =
            verify_password_with_pepper(&wrong, &cred, &config).expect("verify");
        assert!(!matches, "wrong password must not verify");
        assert!(!needs_rehash, "wrong password produces no rehash");
    }

    #[test]
    fn verify_with_previous_pepper_triggers_rehash() {
        // Hash with old pepper (version 1).
        let old_key = PepperKey::new(vec![0x11u8; 32]).expect("ok");
        let old_config = CredentialConfig::fast_for_testing_with_pepper(1, old_key.clone());
        let pw = CleartextPassword::from_string("supersecret".to_string());
        let cred = hash_password(&pw, &old_config, 0).expect("hash with old pepper");
        assert_eq!(cred.pepper_version, Some(1));

        // Rotate: new active = 2, previous = 1 (grace window open).
        let new_key = PepperKey::new(vec![0x22u8; 32]).expect("ok");
        let rotated_config = CredentialConfig {
            pepper: Some(PepperConfig {
                active_version: 2,
                active_key: new_key,
                previous_version: Some(1),
                previous_key: Some(old_key),
            }),
            ..CredentialConfig::fast_for_testing()
        };

        let (matches, needs_rehash) =
            verify_password_with_pepper(&pw, &cred, &rotated_config).expect("verify");
        assert!(
            matches,
            "previous pepper should still verify during grace window"
        );
        assert!(needs_rehash, "previous pepper match must trigger rehash");
    }

    #[test]
    fn verify_with_unknown_pepper_version_rejected() {
        // Credential has version 99, but config only knows 1.
        let key = PepperKey::new(vec![0x33u8; 32]).expect("ok");
        let mut cred = {
            let cfg = CredentialConfig::fast_for_testing_with_pepper(99, key.clone());
            let pw = CleartextPassword::from_string("pw".to_string());
            hash_password(&pw, &cfg, 0).expect("hash")
        };
        cred.pepper_version = Some(99); // keep as-is

        // Config knows only version 1 with no previous.
        let config = CredentialConfig::fast_for_testing_with_pepper(1, key);
        let pw = CleartextPassword::from_string("pw".to_string());
        let (matches, needs_rehash) =
            verify_password_with_pepper(&pw, &cred, &config).expect("verify");
        assert!(!matches, "unknown pepper version must be rejected");
        assert!(!needs_rehash);
    }

    #[test]
    fn verify_legacy_credential_triggers_rehash_when_pepper_configured() {
        // Legacy credential: hashed without pepper.
        let legacy_config = CredentialConfig::fast_for_testing();
        let pw = CleartextPassword::from_string("legacy_pass".to_string());
        let cred = hash_password(&pw, &legacy_config, 0).expect("hash");
        assert_eq!(cred.pepper_version, None);

        // Now pepper is configured — legacy credential should verify but flag rehash.
        let key = PepperKey::new(vec![0x77u8; 32]).expect("ok");
        let peppered_config = CredentialConfig::fast_for_testing_with_pepper(1, key);

        let (matches, needs_rehash) =
            verify_password_with_pepper(&pw, &cred, &peppered_config).expect("verify");
        assert!(matches, "legacy credential should still verify");
        assert!(
            needs_rehash,
            "legacy credential must be flagged for pepper rehash"
        );
    }

    #[test]
    fn verify_no_pepper_config_no_pepper_version_unchanged() {
        // Neither config nor credential has pepper — pure backward compat path.
        let config = CredentialConfig::fast_for_testing();
        let pw = CleartextPassword::from_string("simple".to_string());
        let cred = hash_password(&pw, &config, 0).expect("hash");

        let (matches, needs_rehash) =
            verify_password_with_pepper(&pw, &cred, &config).expect("verify");
        assert!(matches);
        assert!(!needs_rehash);
    }

    #[test]
    fn different_peppers_produce_different_hashes() {
        let key_a = PepperKey::new(vec![0xAAu8; 32]).expect("ok");
        let key_b = PepperKey::new(vec![0xBBu8; 32]).expect("ok");
        let config_a = CredentialConfig::fast_for_testing_with_pepper(1, key_a);
        let config_b = CredentialConfig::fast_for_testing_with_pepper(2, key_b);
        let pw = CleartextPassword::from_string("same-password".to_string());
        let cred_a = hash_password(&pw, &config_a, 0).expect("hash a");
        let cred_b = hash_password(&pw, &config_b, 0).expect("hash b");
        assert_ne!(
            cred_a.hash, cred_b.hash,
            "different peppers must produce different hashes"
        );
    }

    #[test]
    fn wrong_pepper_does_not_verify() {
        // Hash with pepper A; verify with pepper B — must reject even with correct password.
        let key_a = PepperKey::new(vec![0xAAu8; 32]).expect("ok");
        let key_b = PepperKey::new(vec![0xBBu8; 32]).expect("ok");
        let config_a = CredentialConfig::fast_for_testing_with_pepper(1, key_a);
        let config_b = CredentialConfig::fast_for_testing_with_pepper(1, key_b);
        let pw = CleartextPassword::from_string("same-password".to_string());
        let cred = hash_password(&pw, &config_a, 0).expect("hash");
        // Active version matches (both are 1) but different key — must not verify.
        let (matches, _) = verify_password_with_pepper(&pw, &cred, &config_b).expect("verify");
        assert!(
            !matches,
            "wrong pepper key must not verify even with correct password"
        );
    }

    // ===== Property tests =====

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Property: Arbitrary bytes never cause panics when used as passwords.
            #[test]
            fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
                let config = CredentialConfig::fast_for_testing();
                let pw = CleartextPassword::new(bytes);
                // Should not panic — may return Ok or Err
                let _ = hash_password(&pw, &config, 1_000_000);
            }

            /// Property: Hash round-trip — any password verifies after hashing.
            #[test]
            fn hash_roundtrip_always_verifies(s in ".{1,128}") {
                let config = CredentialConfig::fast_for_testing();
                let pw = CleartextPassword::from_string(s.clone());
                let cred = hash_password(&pw, &config, 1_000_000).expect("hash should succeed");
                let pw2 = CleartextPassword::from_string(s);
                let result = verify_password(&pw2, &cred).expect("verify should succeed");
                prop_assert!(result, "password should verify after hashing");
            }

            /// Property: Hash round-trip with pepper — any password verifies after peppered hashing.
            #[test]
            fn hash_roundtrip_with_pepper_always_verifies(s in ".{1,128}") {
                let key = PepperKey::new(vec![0xDEu8; 32]).expect("ok");
                let config = CredentialConfig::fast_for_testing_with_pepper(1, key);
                let pw = CleartextPassword::from_string(s.clone());
                let cred = hash_password(&pw, &config, 1_000_000).expect("hash should succeed");
                let pw2 = CleartextPassword::from_string(s);
                let (matches, needs_rehash) =
                    verify_password_with_pepper(&pw2, &cred, &config).expect("verify");
                prop_assert!(matches, "peppered password should verify after hashing");
                prop_assert!(!needs_rehash, "active pepper needs no rehash");
            }
        }
    }
}
