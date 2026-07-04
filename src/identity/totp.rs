//! TOTP (Time-based One-Time Password) implementation per RFC 6238.
//!
//! Provides TOTP secret generation, code computation/validation with ±1
//! window tolerance, provisioning URI generation (for authenticator apps),
//! and single-use recovery code generation with Argon2id hashing.

use std::fmt;

use base64::Engine as _;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::hkdf;
use ring::hmac;
use ring::rand::{generate, SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::identity::credentials::{self, CredentialConfig};
use crate::identity::error::IdentityError;

/// TOTP period in seconds (RFC 6238 default).
const TOTP_PERIOD: u64 = 30;

/// Number of digits in a TOTP code (RFC 6238 default).
const TOTP_DIGITS: u32 = 6;

/// Validation window: accept codes for T-1 and T+1 in addition to T.
const TOTP_WINDOW: u64 = 1;

/// Number of recovery codes generated during MFA enrollment.
const RECOVERY_CODE_COUNT: usize = 8;

/// Length of each recovery code (characters).
///
/// 16 chars × 5 bits/char (32-symbol alphabet) = 80-bit entropy, which is
/// brute-force-proof for single-use codes even offline.
const RECOVERY_CODE_LENGTH: usize = 16;

/// Character set for recovery codes — excludes confusable characters (0, O, 1, I).
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// A 20-byte TOTP secret that is zeroed from memory on drop.
///
/// **Security**: Intentionally does NOT implement `Display` or content-revealing
/// `Debug`. The `Debug` impl prints a redacted placeholder.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct TotpSecret {
    bytes: [u8; 20],
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSecret(***)")
    }
}

impl TotpSecret {
    /// Generates a new random 20-byte TOTP secret.
    pub(crate) fn generate() -> Result<Self, IdentityError> {
        let rng = ring::rand::SystemRandom::new();
        let mut bytes = [0u8; 20];
        rng.fill(&mut bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "failed to generate TOTP secret".to_string(),
            })?;
        Ok(Self { bytes })
    }

    /// Creates a `TotpSecret` from a base32-encoded string (for testing/restore).
    pub(crate) fn from_base32(encoded: &str) -> Result<Self, IdentityError> {
        let decoded = data_encoding::BASE32_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid base32 TOTP secret: {e}"),
            })?;
        if decoded.len() != 20 {
            return Err(IdentityError::InvalidInput {
                reason: format!("TOTP secret must be 20 bytes, got {}", decoded.len()),
            });
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&decoded);
        Ok(Self { bytes })
    }

    /// Returns the secret as a base32-encoded string (no padding).
    pub(crate) fn to_base32(&self) -> String {
        data_encoding::BASE32_NOPAD.encode(&self.bytes)
    }

    /// Returns the raw secret bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Persisted MFA state for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredMfaState {
    /// Base32-encoded TOTP secret.
    pub secret_base32: String,
    /// Whether MFA has been verified and is active.
    pub enabled: bool,
    /// Argon2id hashes of recovery codes (empty slots = `None`).
    pub recovery_code_hashes: Vec<Option<String>>,
    /// The last TOTP time step that was successfully used (replay protection).
    pub last_used_step: Option<u64>,
    /// When MFA was enabled (Unix microseconds), if enabled.
    pub enabled_at: Option<i64>,
    /// Plaintext recovery codes held during the pending enrollment window.
    ///
    /// Present only while `enabled == false`. Hashed and moved to
    /// `recovery_code_hashes` when the user confirms enrollment via
    /// `verify_totp_enrollment()`, then cleared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_recovery_codes: Option<Vec<String>>,
}

/// Plaintext recovery codes returned once at enrollment.
///
/// **Security**: Each code's memory is zeroed on drop. Does NOT implement
/// `Debug`, `Display`, `Serialize`, or `Clone` — the only way to observe
/// the codes is to call `iter()` or `as_slice()`, which forces callers to
/// render them at a single, auditable site.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCodes {
    codes: Vec<String>,
}

impl RecoveryCodes {
    /// Wraps a vector of plaintext recovery codes.
    pub(crate) fn new(codes: Vec<String>) -> Self {
        Self { codes }
    }

    /// Returns the codes as a slice for iteration.
    pub fn as_slice(&self) -> &[String] {
        &self.codes
    }

    /// Returns the number of recovery codes.
    pub fn len(&self) -> usize {
        self.codes.len()
    }

    /// Returns `true` if there are no recovery codes.
    pub fn is_empty(&self) -> bool {
        self.codes.is_empty()
    }

    /// Iterates over the plaintext recovery codes.
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.codes.iter()
    }
}

impl<'a> IntoIterator for &'a RecoveryCodes {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.codes.iter()
    }
}

impl fmt::Debug for RecoveryCodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryCodes")
            .field("count", &self.codes.len())
            .field("codes", &"[REDACTED]")
            .finish()
    }
}

/// Returned once during MFA enrollment — contains the plaintext recovery codes.
///
/// **Security**: Recovery codes are shown exactly once. After enrollment,
/// only their Argon2id hashes are stored. The `recovery_codes` field is
/// wrapped in [`RecoveryCodes`] to zero the plaintext on drop.
pub struct TotpEnrollment {
    /// Base32-encoded TOTP secret for manual entry.
    pub secret_base32: String,
    /// `otpauth://` URI for QR code scanning.
    pub provisioning_uri: String,
    /// Plaintext recovery codes (shown once).
    pub recovery_codes: RecoveryCodes,
}

impl fmt::Debug for TotpEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpEnrollment")
            .field("secret_base32", &"[REDACTED]")
            .field("provisioning_uri", &"[REDACTED]")
            .field("recovery_codes", &"[REDACTED]")
            .finish()
    }
}

/// Generates a provisioning URI for authenticator apps.
///
/// Format: `otpauth://totp/{issuer}:{account}?secret={base32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30`
pub(crate) fn generate_provisioning_uri(
    secret_base32: &str,
    account: &str,
    issuer: &str,
) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret_base32}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
    )
}

/// Computes a TOTP code for the given secret and time step.
///
/// Implements RFC 4226 dynamic truncation on HMAC-SHA1 output.
pub(crate) fn compute_totp(secret: &[u8], time_step: u64) -> String {
    // HMAC-SHA1(secret, time_step as 8-byte big-endian)
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let msg = time_step.to_be_bytes();
    let tag = hmac::sign(&key, &msg);
    let hash = tag.as_ref();

    // Dynamic truncation (RFC 4226 §5.4)
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);

    let otp = binary % 10u32.pow(TOTP_DIGITS);
    format!("{otp:0>width$}", width = TOTP_DIGITS as usize)
}

/// Validates a TOTP code against a secret at the given Unix timestamp.
///
/// Checks the current time step and ±`TOTP_WINDOW` adjacent steps.
/// Returns `Some(matching_step)` if valid, `None` if no match.
pub(crate) fn validate_totp(
    secret: &[u8],
    code: &str,
    unix_secs: u64,
    last_used_step: Option<u64>,
) -> Option<u64> {
    let current_step = unix_secs / TOTP_PERIOD;

    // Check T-window through T+window
    let start = current_step.saturating_sub(TOTP_WINDOW);
    let end = current_step + TOTP_WINDOW;

    for step in start..=end {
        // Replay protection: reject steps already used
        if let Some(last) = last_used_step {
            if step <= last {
                continue;
            }
        }
        if compute_totp(secret, step)
            .as_bytes()
            .ct_eq(code.as_bytes())
            .into()
        {
            return Some(step);
        }
    }
    None
}

/// Generates `RECOVERY_CODE_COUNT` unique recovery codes.
///
/// Each code is `RECOVERY_CODE_LENGTH` characters from `RECOVERY_ALPHABET`
/// (28 chars: A-Z minus I/O, 2-9 minus 0/1).
pub(crate) fn generate_recovery_codes() -> Result<Vec<String>, IdentityError> {
    let rng = ring::rand::SystemRandom::new();
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);

    for _ in 0..RECOVERY_CODE_COUNT {
        let mut buf = [0u8; RECOVERY_CODE_LENGTH];
        rng.fill(&mut buf)
            .map_err(|_| IdentityError::SigningError {
                reason: "failed to generate recovery code entropy".to_string(),
            })?;

        let code: String = buf
            .iter()
            .map(|&b| {
                let idx = (b as usize) % RECOVERY_ALPHABET.len();
                RECOVERY_ALPHABET[idx] as char
            })
            .collect();
        codes.push(code);
    }

    Ok(codes)
}

/// Hashes recovery codes using Argon2id in parallel.
///
/// Spawns one thread per code inside `std::thread::scope` so all hashes
/// run concurrently. Because each Argon2id invocation is memory-bound
/// (~19 MiB), parallel instances don't contend on CPU cores, reducing
/// wall-clock time from N × ~1s to ~1s regardless of code count.
///
/// # Panics
///
/// Propagates any panic from a spawned hashing thread.
pub(crate) fn hash_recovery_codes(
    codes: &[String],
    config: &CredentialConfig,
) -> Result<Vec<Option<String>>, IdentityError> {
    std::thread::scope(|s| {
        let handles: Vec<_> = codes
            .iter()
            .map(|code| {
                s.spawn(|| {
                    let hash = credentials::hash_raw_secret(code.as_bytes(), config)?;
                    Ok(Some(hash))
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|h| h.join().expect("recovery code hash thread panicked"))
            .collect()
    })
}

/// Verifies a recovery code against stored hashes, returning the index if found.
///
/// On success, the caller should set that index to `None` to mark it used.
pub(crate) fn verify_recovery_code(
    code: &str,
    hashes: &[Option<String>],
) -> Result<Option<usize>, IdentityError> {
    for (i, slot) in hashes.iter().enumerate() {
        if let Some(hash) = slot {
            if credentials::verify_raw_secret(code.as_bytes(), hash)? {
                return Ok(Some(i));
            }
        }
    }
    Ok(None)
}

// ===== At-rest encryption for MFA state (CRYPTO-001, CRYPTO-002) =====

/// Encrypted on-disk representation of [`StoredMfaState`].
///
/// Sensitive fields (`secret_enc`, `pending_codes_enc`) are AES-256-GCM
/// ciphertexts. Non-sensitive fields (`enabled`, `recovery_code_hashes`, …)
/// are stored plaintext so they can be updated without a full decrypt cycle.
///
/// Wire format for encrypted fields: `base64std(nonce[12] || ciphertext || GCM-tag[16])`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StoredMfaOnDisk {
    /// AES-256-GCM encrypted base32-encoded TOTP secret.
    pub secret_enc: String,
    pub enabled: bool,
    /// Argon2id hashes of recovery codes — already one-way, stored plaintext.
    pub recovery_code_hashes: Vec<Option<String>>,
    pub last_used_step: Option<u64>,
    pub enabled_at: Option<i64>,
    /// AES-256-GCM encrypted JSON-serialized `Vec<String>` of pending plaintext codes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_codes_enc: Option<String>,
}

/// Derives a 32-byte AES-256-GCM key from a realm signing key via HKDF-SHA256.
///
/// The domain label `b"hearth-totp-at-rest-v1"` scopes this DEK to TOTP
/// secret storage and prevents cross-purpose key reuse.
pub(crate) fn derive_totp_dek(signing_key_pkcs8: &[u8]) -> Result<[u8; 32], IdentityError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"hearth-totp-at-rest-v1");
    let prk = salt.extract(signing_key_pkcs8);
    let mut key = [0u8; 32];
    prk.expand(&[b"aes-256-gcm"], hkdf::HKDF_SHA256)
        .and_then(|okm| okm.fill(&mut key))
        .map_err(|_| IdentityError::SigningError {
            reason: "TOTP DEK HKDF expansion failed".to_string(),
        })?;
    Ok(key)
}

/// AES-256-GCM encrypts `plaintext`.
///
/// Returns `base64std(nonce[12] || ciphertext || GCM-tag[16])`.
pub(crate) fn encrypt_totp_field(
    plaintext: &[u8],
    key_bytes: &[u8; 32],
) -> Result<String, IdentityError> {
    let rng = SystemRandom::new();
    let nonce_bytes = generate::<[u8; 12]>(&rng)
        .map_err(|_| IdentityError::SigningError {
            reason: "TOTP nonce generation failed".to_string(),
        })?
        .expose();

    let unbound =
        UnboundKey::new(&AES_256_GCM, key_bytes).map_err(|_| IdentityError::SigningError {
            reason: "TOTP AES key init failed".to_string(),
        })?;
    let aes_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = plaintext.to_vec();
    aes_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| IdentityError::SigningError {
            reason: "TOTP field encryption failed".to_string(),
        })?;

    let mut combined = Vec::with_capacity(12 + buf.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&buf);
    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// Decrypts a blob produced by [`encrypt_totp_field`].
///
/// Returns the original plaintext bytes on success, or an error if the
/// data is truncated, the base64 is invalid, or GCM authentication fails.
pub(crate) fn decrypt_totp_field(
    encoded: &str,
    key_bytes: &[u8; 32],
) -> Result<Vec<u8>, IdentityError> {
    use base64::Engine as _;
    let combined = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|e| IdentityError::Serialization {
            reason: format!("TOTP field base64 decode failed: {e}"),
        })?;

    // nonce (12) + at least GCM tag (16)
    if combined.len() < 28 {
        return Err(IdentityError::Serialization {
            reason: "TOTP encrypted field too short (expected ≥28 bytes)".to_string(),
        });
    }
    let nonce_bytes: [u8; 12] = combined[..12].try_into().expect("12-byte slice");
    let mut buf = combined[12..].to_vec();

    let unbound =
        UnboundKey::new(&AES_256_GCM, key_bytes).map_err(|_| IdentityError::SigningError {
            reason: "TOTP AES key init failed".to_string(),
        })?;
    let aes_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let plaintext = aes_key
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| IdentityError::SigningError {
            reason: "TOTP field decryption failed — corrupted data or wrong key".to_string(),
        })?;
    Ok(plaintext.to_vec())
}

/// Serializes `state` to AES-256-GCM-encrypted JSON bytes for WAL storage.
///
/// `secret_base32` and `pending_recovery_codes` are encrypted under `dek`.
/// All other fields are stored in the clear (they are non-sensitive).
pub(crate) fn serialize_mfa_state(
    state: &StoredMfaState,
    dek: &[u8; 32],
) -> Result<Vec<u8>, IdentityError> {
    let secret_enc = encrypt_totp_field(state.secret_base32.as_bytes(), dek)?;

    let pending_codes_enc = state
        .pending_recovery_codes
        .as_ref()
        .map(|codes| -> Result<String, IdentityError> {
            let json = serde_json::to_string(codes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
            encrypt_totp_field(json.as_bytes(), dek)
        })
        .transpose()?;

    let on_disk = StoredMfaOnDisk {
        secret_enc,
        enabled: state.enabled,
        recovery_code_hashes: state.recovery_code_hashes.clone(),
        last_used_step: state.last_used_step,
        enabled_at: state.enabled_at,
        pending_codes_enc,
    };

    serde_json::to_vec(&on_disk).map_err(|e| IdentityError::Serialization {
        reason: e.to_string(),
    })
}

/// Deserializes WAL bytes into a [`StoredMfaState`], decrypting sensitive fields.
///
/// Handles both v2 (encrypted `StoredMfaOnDisk`) and v1 (legacy plaintext
/// `StoredMfaState`) formats transparently.  On a legacy record a warning is
/// emitted; the next `save_mfa_state` call will upgrade the record to v2.
pub(crate) fn deserialize_mfa_state(
    bytes: &[u8],
    dek: &[u8; 32],
) -> Result<StoredMfaState, IdentityError> {
    // v2: `secret_enc` is a required field — present only in encrypted records.
    match serde_json::from_slice::<StoredMfaOnDisk>(bytes) {
        Ok(on_disk) => {
            let secret_bytes = decrypt_totp_field(&on_disk.secret_enc, dek)?;
            let secret_base32 =
                String::from_utf8(secret_bytes).map_err(|_| IdentityError::Serialization {
                    reason: "TOTP secret UTF-8 decode failed".to_string(),
                })?;

            let pending_recovery_codes = on_disk
                .pending_codes_enc
                .as_ref()
                .map(|enc| -> Result<Vec<String>, IdentityError> {
                    let json_bytes = decrypt_totp_field(enc, dek)?;
                    serde_json::from_slice(&json_bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })
                })
                .transpose()?;

            Ok(StoredMfaState {
                secret_base32,
                enabled: on_disk.enabled,
                recovery_code_hashes: on_disk.recovery_code_hashes,
                last_used_step: on_disk.last_used_step,
                enabled_at: on_disk.enabled_at,
                pending_recovery_codes,
            })
        }
        // v1 legacy plaintext — migrate transparently on next write.
        Err(_) => {
            tracing::warn!("loaded legacy plaintext MFA state — will be re-encrypted on next save");
            serde_json::from_slice::<StoredMfaState>(bytes).map_err(|e| {
                IdentityError::Serialization {
                    reason: e.to_string(),
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Scenario A1: Provisioning URI generation =====

    #[test]
    fn generate_totp_secret_with_correct_provisioning_uri() {
        let secret = TotpSecret::generate().expect("generate");
        let base32 = secret.to_base32();

        // Base32 of 20 bytes = 32 chars (no padding)
        assert_eq!(
            base32.len(),
            32,
            "base32 encoding of 20 bytes should be 32 chars"
        );

        // Roundtrip
        let restored = TotpSecret::from_base32(&base32).expect("from_base32");
        assert_eq!(restored.as_bytes(), secret.as_bytes());

        // Provisioning URI format
        let uri = generate_provisioning_uri(&base32, "user@example.com", "Hearth");
        assert!(
            uri.starts_with("otpauth://totp/Hearth:user@example.com?"),
            "URI should start with otpauth://totp/issuer:account, got: {uri}"
        );
        assert!(
            uri.contains(&format!("secret={base32}")),
            "URI must contain secret"
        );
        assert!(uri.contains("issuer=Hearth"), "URI must contain issuer");
        assert!(uri.contains("algorithm=SHA1"), "URI must specify SHA1");
        assert!(uri.contains("digits=6"), "URI must specify 6 digits");
        assert!(uri.contains("period=30"), "URI must specify 30s period");
    }

    // ===== Scenario A2: TOTP code validation (known test vector) =====

    #[test]
    fn validate_totp_code_for_current_time_window_succeeds() {
        // RFC 6238 test vector: secret = "12345678901234567890" (ASCII)
        // Time = 59 → step = 1
        // deepcode ignore HardcodedNonCryptoSecret: RFC 6238 §B.1 mandatory test vector
        let secret = b"12345678901234567890";
        let code = compute_totp(secret, 1); // step 1 = time 30..59

        // The code should be a 6-digit string
        assert_eq!(code.len(), 6, "TOTP code should be 6 digits");
        assert!(
            code.chars().all(|c| c.is_ascii_digit()),
            "TOTP code should be all digits: {code}"
        );

        // Known value: RFC 6238 Appendix B, T=1 → 287082
        assert_eq!(code, "287082", "RFC 6238 test vector for step 1");

        // Validate at exact time (step=1 corresponds to 30..59)
        let matched = validate_totp(secret, &code, 59, None);
        assert_eq!(matched, Some(1), "should match step 1 at time=59");
    }

    // ===== Scenario A3: Time window tolerance =====

    #[test]
    fn totp_time_window_tolerance_t_minus1_and_t_plus1_accepted() {
        let secret = b"12345678901234567890";
        let current_time = 90; // step = 3

        // Code for step 3 (current)
        let code_current = compute_totp(secret, 3);
        let matched = validate_totp(secret, &code_current, current_time, None);
        assert!(matched.is_some(), "current step code should validate");

        // Code for step 2 (T-1) — should be accepted within window
        let code_prev = compute_totp(secret, 2);
        let matched = validate_totp(secret, &code_prev, current_time, None);
        assert_eq!(matched, Some(2), "T-1 code should be accepted");

        // Code for step 4 (T+1) — should be accepted within window
        let code_next = compute_totp(secret, 4);
        let matched = validate_totp(secret, &code_next, current_time, None);
        assert_eq!(matched, Some(4), "T+1 code should be accepted");

        // Code for step 1 (T-2) — should be rejected
        let code_old = compute_totp(secret, 1);
        let matched = validate_totp(secret, &code_old, current_time, None);
        assert!(matched.is_none(), "T-2 code should be rejected");

        // Code for step 5 (T+2) — should be rejected
        let code_far = compute_totp(secret, 5);
        let matched = validate_totp(secret, &code_far, current_time, None);
        assert!(matched.is_none(), "T+2 code should be rejected");
    }

    // ===== Scenario B1: Recovery code generation =====

    #[test]
    fn generate_recovery_codes_correct_count_entropy_uniqueness() {
        let codes = generate_recovery_codes().expect("generate");

        // 8 codes
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT, "should generate 8 codes");

        for code in &codes {
            // Each 8 chars
            assert_eq!(
                code.len(),
                RECOVERY_CODE_LENGTH,
                "each code should be {RECOVERY_CODE_LENGTH} chars"
            );

            // All chars from RECOVERY_ALPHABET (no confusable 0, O, 1, I)
            for ch in code.chars() {
                assert!(
                    RECOVERY_ALPHABET.contains(&(ch as u8)),
                    "char '{ch}' should be in recovery alphabet"
                );
            }

            // No confusable characters
            assert!(!code.contains('0'), "must not contain 0");
            assert!(!code.contains('O'), "must not contain O");
            assert!(!code.contains('1'), "must not contain 1");
            assert!(!code.contains('I'), "must not contain I");
        }

        // All unique
        let unique: std::collections::HashSet<&String> = codes.iter().collect();
        assert_eq!(
            unique.len(),
            codes.len(),
            "all recovery codes should be unique"
        );
    }

    // ===== Scenario B2: Recovery code redemption =====

    #[test]
    fn recovery_code_redemption_valid_succeeds_reused_rejected() {
        let codes = generate_recovery_codes().expect("generate");
        let config = CredentialConfig::fast_for_testing();

        // Hash all codes
        let mut hashes = hash_recovery_codes(&codes, &config).expect("hash");

        // Verify first code succeeds
        let idx = verify_recovery_code(&codes[0], &hashes).expect("verify");
        assert_eq!(idx, Some(0), "first code should match index 0");

        // Mark as used (set slot to None)
        hashes[0] = None;

        // Same code should now fail
        let idx = verify_recovery_code(&codes[0], &hashes).expect("verify");
        assert!(idx.is_none(), "used code should not match");

        // Different code still works
        let idx = verify_recovery_code(&codes[1], &hashes).expect("verify");
        assert_eq!(idx, Some(1), "second code should still match");
    }

    // ===== Scenario E: Property test — TOTP time tolerance =====

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Property: TOTP code computed within ±30s validates,
            /// code computed at |offset| > 60s does not.
            #[test]
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
            fn totp_time_window_property(
                // Use a reasonable time range (year 2020 to 2030)
                base_time in 1_577_836_800u64..1_893_456_000u64,
                // Offset within one period (should validate)
                near_offset in 0u64..30u64,
                // Offset beyond two periods (should NOT validate)
                far_offset in 61u64..120u64,
            ) {
                let secret = b"12345678901234567890";

                // Near: code at base_time + near_offset should validate at base_time
                let near_time = base_time + near_offset;
                let code = compute_totp(secret, near_time / TOTP_PERIOD);
                let result = validate_totp(secret, &code, base_time, None);
                prop_assert!(result.is_some(), "near code should validate: base={base_time}, offset={near_offset}");

                // Far: code at base_time + far_offset should NOT validate at base_time
                let far_time = base_time + far_offset;
                let far_code = compute_totp(secret, far_time / TOTP_PERIOD);
                // Only assert rejection if the far code is actually for a different step range
                let far_step = far_time / TOTP_PERIOD;
                let current_step = base_time / TOTP_PERIOD;
                if far_step > current_step + TOTP_WINDOW {
                    let result = validate_totp(secret, &far_code, base_time, None);
                    prop_assert!(result.is_none(), "far code should NOT validate: base={base_time}, offset={far_offset}");
                }
            }
        }
    }

    // ===== TotpSecret Debug is redacted =====

    #[test]
    fn totp_secret_debug_is_redacted() {
        let secret = TotpSecret::generate().expect("generate");
        let debug = format!("{secret:?}");
        assert!(debug.contains("***"), "debug should be redacted: {debug}");
        assert!(
            !debug.contains(&secret.to_base32()),
            "debug must not reveal secret"
        );
    }

    // ===== CRYPTO-001: secret not in plaintext in storage =====

    #[test]
    fn serialize_mfa_state_secret_not_plaintext_in_wal() {
        let secret = TotpSecret::generate().expect("generate");
        let secret_base32 = secret.to_base32();
        let state = StoredMfaState {
            secret_base32: secret_base32.clone(),
            enabled: false,
            recovery_code_hashes: Vec::new(),
            last_used_step: None,
            enabled_at: None,
            pending_recovery_codes: None,
        };
        let dek = [42u8; 32];
        let bytes = serialize_mfa_state(&state, &dek).expect("serialize");
        let serialized_str = String::from_utf8_lossy(&bytes);
        assert!(
            !serialized_str.contains(&secret_base32),
            "plaintext TOTP secret must not appear in WAL bytes; got: {serialized_str}"
        );
        // Must also not contain the field name from the legacy format.
        assert!(
            !serialized_str.contains("secret_base32"),
            "legacy field name 'secret_base32' must not appear in WAL bytes"
        );
    }

    // ===== CRYPTO-002: pending recovery codes not in plaintext in storage =====

    #[test]
    fn serialize_mfa_state_pending_codes_not_plaintext_in_wal() {
        let codes = vec![
            "ABCDEFGHABCDEFGH".to_string(),
            "XYZXYZXYZXYZXYZX".to_string(),
        ];
        let state = StoredMfaState {
            secret_base32: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string(),
            enabled: false,
            recovery_code_hashes: Vec::new(),
            last_used_step: None,
            enabled_at: None,
            pending_recovery_codes: Some(codes.clone()),
        };
        let dek = [7u8; 32];
        let bytes = serialize_mfa_state(&state, &dek).expect("serialize");
        let serialized_str = String::from_utf8_lossy(&bytes);
        for code in &codes {
            assert!(
                !serialized_str.contains(code.as_str()),
                "plaintext recovery code '{code}' must not appear in WAL bytes"
            );
        }
        assert!(
            !serialized_str.contains("pending_recovery_codes"),
            "legacy field name must not appear in WAL bytes"
        );
    }

    // ===== Encrypt/decrypt roundtrip =====

    #[test]
    fn serialize_deserialize_mfa_state_roundtrip() {
        let codes = generate_recovery_codes().expect("generate");
        let state = StoredMfaState {
            secret_base32: TotpSecret::generate().expect("gen").to_base32(),
            enabled: false,
            recovery_code_hashes: Vec::new(),
            last_used_step: None,
            enabled_at: None,
            pending_recovery_codes: Some(codes),
        };
        let dek = [99u8; 32];
        let bytes = serialize_mfa_state(&state, &dek).expect("serialize");
        let restored = deserialize_mfa_state(&bytes, &dek).expect("deserialize");
        assert_eq!(restored.secret_base32, state.secret_base32);
        assert_eq!(
            restored.pending_recovery_codes,
            state.pending_recovery_codes
        );
        assert_eq!(restored.enabled, state.enabled);
    }

    // ===== Wrong key fails decryption =====

    #[test]
    fn deserialize_mfa_state_wrong_key_returns_error() {
        let state = StoredMfaState {
            secret_base32: TotpSecret::generate().expect("gen").to_base32(),
            enabled: false,
            recovery_code_hashes: Vec::new(),
            last_used_step: None,
            enabled_at: None,
            pending_recovery_codes: None,
        };
        let dek_correct = [1u8; 32];
        let dek_wrong = [2u8; 32];
        let bytes = serialize_mfa_state(&state, &dek_correct).expect("serialize");
        let result = deserialize_mfa_state(&bytes, &dek_wrong);
        assert!(
            result.is_err(),
            "decryption with wrong key must fail, not silently return garbage"
        );
    }

    // ===== CRYPTO-003: recovery codes are 16 chars (80-bit entropy) =====

    #[test]
    fn recovery_codes_have_16_char_80_bit_entropy() {
        let codes = generate_recovery_codes().expect("generate");
        assert_eq!(
            codes.len(),
            RECOVERY_CODE_COUNT,
            "must generate {RECOVERY_CODE_COUNT} codes"
        );
        for code in &codes {
            assert_eq!(
                code.len(),
                16,
                "each code must be 16 chars (80-bit entropy); got {} chars",
                code.len()
            );
        }
        // All codes are unique
        let unique: std::collections::HashSet<&String> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len(), "all codes must be unique");
    }

    // ===== TotpEnrollment Debug is redacted =====

    #[test]
    fn totp_enrollment_debug_is_redacted() {
        let enrollment = TotpEnrollment {
            secret_base32: "JBSWY3DPEHPK3PXP".to_string(),
            provisioning_uri: "otpauth://totp/test".to_string(),
            recovery_codes: RecoveryCodes::new(vec!["ABC123XY".to_string()]),
        };
        let debug = format!("{enrollment:?}");
        assert!(
            debug.contains("REDACTED"),
            "debug should show REDACTED: {debug}"
        );
        assert!(
            !debug.contains("JBSWY3DPEHPK3PXP"),
            "must not reveal secret"
        );
        assert!(
            !debug.contains("ABC123XY"),
            "must not reveal recovery codes"
        );
    }
}
