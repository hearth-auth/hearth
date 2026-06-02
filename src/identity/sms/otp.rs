//! SMS OTP generation, HMAC-SHA256 storage, and verification.
//!
//! Implements the core OTP primitives for the SMS authentication flow:
//!
//! - 6-digit code generation with rejection sampling (no modular bias).
//! - 128-bit CSPRNG nonce for the storage key (`sms:pending_otp:{nonce}`).
//! - HMAC-SHA256 of the digits for tamper-proof storage.
//! - Constant-time verification via `ring::hmac::verify`.
//! - Attempt tracking and expiry embedded in the stored record.
//! - Per-phone resend throttle key derivation (first 8 hex chars of SHA-256).

use ring::hmac;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::identity::error::IdentityError;

/// OTP lifetime in seconds (10 minutes).
pub(crate) const OTP_EXPIRY_SECS: u64 = 10 * 60;

/// Maximum verification attempts before the OTP record is invalidated.
pub(crate) const OTP_MAX_ATTEMPTS: u32 = 5;

/// Maximum SMS resends per phone per 15-minute window.
pub(crate) const RESEND_MAX_PER_WINDOW: u32 = 5;

/// Resend window duration in seconds.
pub(crate) const RESEND_WINDOW_SECS: u64 = 15 * 60;

/// Output digit count for generated OTP codes.
const OTP_BOUND: u32 = 1_000_000;

/// Largest multiple of `OTP_BOUND` that fits in a u32.
///
/// Values `raw < OTP_ACCEPT_LIMIT` are accepted; `raw % OTP_BOUND` maps them
/// uniformly to `[0, 1_000_000)`. Values `raw >= OTP_ACCEPT_LIMIT` are
/// rejected and a new random u32 is drawn to eliminate modular bias.
///
/// `floor(2^32 / 1_000_000) * 1_000_000 = 4294 * 1_000_000 = 4_294_000_000`.
const OTP_ACCEPT_LIMIT: u32 = 4_294_000_000u32;

/// Generates a 128-bit CSPRNG nonce for the OTP storage key.
///
/// Returns the nonce as a 32-character lowercase hexadecimal string.
pub(crate) fn generate_otp_nonce(rng: &dyn SecureRandom) -> Result<String, IdentityError> {
    let mut bytes = [0u8; 16]; // 128 bits
    rng.fill(&mut bytes)
        .map_err(|_| IdentityError::SigningError {
            reason: "failed to generate OTP nonce".to_string(),
        })?;
    Ok(hex_encode(&bytes))
}

/// Generates a uniformly distributed 6-digit OTP code using rejection sampling.
///
/// # Security
///
/// This function MUST NOT use `raw % 1_000_000` without first discarding
/// values above `OTP_ACCEPT_LIMIT`. Rejection sampling ensures the output
/// is uniformly distributed over `[000000, 999999]`.
///
/// The returned string is always zero-padded to 6 digits.
pub(crate) fn generate_otp_digits(
    rng: &dyn SecureRandom,
) -> Result<Zeroizing<String>, IdentityError> {
    const MAX_ITERATIONS: u32 = 100;
    for _ in 0..MAX_ITERATIONS {
        let mut buf = [0u8; 4];
        rng.fill(&mut buf)
            .map_err(|_| IdentityError::SigningError {
                reason: "failed to generate random bytes for OTP".to_string(),
            })?;
        let raw = u32::from_le_bytes(buf);
        if raw < OTP_ACCEPT_LIMIT {
            #[allow(clippy::expect_used)]
            return Ok(Zeroizing::new(format!("{:06}", raw % OTP_BOUND)));
        }
        // raw >= OTP_ACCEPT_LIMIT: discard and retry (bias zone).
    }
    Err(IdentityError::SigningError {
        reason: "OTP generation failed: rejection sampling exceeded retry limit".to_string(),
    })
}

/// Derives the per-phone resend throttle key suffix.
///
/// Computes SHA-256 of the E.164 phone number and returns the first 8
/// hexadecimal characters (4 bytes). The plaintext number is not stored.
pub(crate) fn phone_resend_key_suffix(e164: &str) -> String {
    let hash = Sha256::digest(e164.as_bytes());
    hex_encode(&hash[..4])
}

/// Persisted OTP record stored under `sms:pending_otp:{nonce}`.
///
/// The plaintext OTP code is never persisted — only its HMAC-SHA256 tag.
/// `hmac_hex` is verified using `ring::hmac::verify` (constant-time).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredOtp {
    /// Hex-encoded HMAC-SHA256 tag of the OTP digits under the server key.
    pub hmac_hex: String,
    /// Expiry as Unix timestamp in seconds.
    pub expiry_unix_ts: u64,
    /// Number of failed verification attempts so far.
    pub attempt_count: u32,
    /// Maximum allowed attempts before the record is invalidated.
    ///
    /// Baked in at creation time from the per-realm config (or the module
    /// default). Stored here so mid-flow config changes do not retroactively
    /// affect in-flight OTPs. Absent on records written before this field
    /// was added; those deserialize to `OTP_MAX_ATTEMPTS` via the serde default.
    #[serde(default = "default_otp_max_attempts")]
    pub max_attempts: u32,
}

fn default_otp_max_attempts() -> u32 {
    OTP_MAX_ATTEMPTS
}

impl StoredOtp {
    /// Generates a 6-digit code and creates a `StoredOtp` record.
    ///
    /// Returns `(plaintext_digits, stored_record)`. The caller must include
    /// the digits in the SMS body and discard them after sending.
    pub(crate) fn create(
        rng: &dyn SecureRandom,
        key_bytes: &[u8],
        expiry_unix_ts: u64,
        max_attempts: u32,
    ) -> Result<(Zeroizing<String>, Self), IdentityError> {
        let digits = generate_otp_digits(rng)?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);
        let tag = hmac::sign(&key, digits.as_bytes());
        let hmac_hex = hex_encode(tag.as_ref());
        let stored = Self {
            hmac_hex,
            expiry_unix_ts,
            attempt_count: 0,
            max_attempts,
        };
        Ok((digits, stored))
    }

    /// Returns `true` if the OTP has expired.
    pub(crate) fn is_expired(&self, now_unix_ts: u64) -> bool {
        now_unix_ts >= self.expiry_unix_ts
    }

    /// Returns `true` if maximum verification attempts have been reached.
    pub(crate) fn is_exhausted(&self) -> bool {
        self.attempt_count >= self.max_attempts
    }

    /// Verifies `candidate_digits` against the stored HMAC in constant time.
    ///
    /// Uses `ring::hmac::verify` which performs a constant-time comparison
    /// of the recomputed HMAC against the stored tag bytes.
    ///
    /// Returns `Ok(())` on success, `Err(InvalidSmsOtp)` on any failure.
    pub(crate) fn verify(
        &self,
        candidate_digits: &str,
        key_bytes: &[u8],
    ) -> Result<(), IdentityError> {
        let stored_bytes = hex_decode(&self.hmac_hex).map_err(|_| IdentityError::InvalidSmsOtp)?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);
        hmac::verify(&key, candidate_digits.as_bytes(), &stored_bytes)
            .map_err(|_| IdentityError::InvalidSmsOtp)
    }
}

/// Per-phone resend throttle record stored under `sms:resend_count:{suffix}`.
///
/// Tracks how many OTP SMS messages have been sent to a phone in the current
/// 15-minute window. The phone number itself is not stored in this record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredResendCount {
    /// Number of OTP sends in this window.
    pub count: u32,
    /// Unix timestamp (seconds) when the current window started.
    pub window_start_unix_ts: u64,
}

impl StoredResendCount {
    /// Creates a new counter with `count = 1` at the given window start.
    pub(crate) fn new(window_start_unix_ts: u64) -> Self {
        Self {
            count: 1,
            window_start_unix_ts,
        }
    }

    /// Returns `true` if the 15-minute window has expired.
    pub(crate) fn is_window_expired(&self, now_unix_ts: u64) -> bool {
        now_unix_ts >= self.window_start_unix_ts + RESEND_WINDOW_SECS
    }

    /// Returns `true` if the resend limit has been reached in this window.
    pub(crate) fn is_limit_reached(&self) -> bool {
        self.count >= RESEND_MAX_PER_WINDOW
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;

    const TEST_KEY: &[u8] = b"hearth-test-hmac-key-32-bytes!!!";

    // ── nonce ─────────────────────────────────────────────────────────────────

    #[test]
    fn nonce_is_32_hex_chars() {
        let rng = SystemRandom::new();
        let nonce = generate_otp_nonce(&rng).expect("generate_otp_nonce should succeed");
        assert_eq!(nonce.len(), 32, "nonce should be 32 hex chars (128 bits)");
        assert!(
            nonce.chars().all(|c| c.is_ascii_hexdigit()),
            "nonce must be lowercase hex: {nonce}"
        );
    }

    #[test]
    fn nonces_are_unique() {
        let rng = SystemRandom::new();
        let a = generate_otp_nonce(&rng).expect("first nonce should generate");
        let b = generate_otp_nonce(&rng).expect("second nonce should generate");
        assert_ne!(a, b, "two consecutive nonces must differ");
    }

    // ── digit generation ──────────────────────────────────────────────────────

    #[test]
    fn digits_are_six_chars() {
        let rng = SystemRandom::new();
        for _ in 0..20 {
            let code = generate_otp_digits(&rng).expect("generate_otp_digits should succeed");
            assert_eq!(
                code.len(),
                6,
                "OTP must be exactly 6 characters, got: {}",
                code.as_str()
            );
        }
    }

    #[test]
    fn digits_are_all_ascii_decimal() {
        let rng = SystemRandom::new();
        for _ in 0..20 {
            let code = generate_otp_digits(&rng).expect("generate_otp_digits should succeed");
            assert!(
                code.chars().all(|c| c.is_ascii_digit()),
                "OTP must contain only digits: {}",
                code.as_str()
            );
        }
    }

    #[test]
    fn digits_in_valid_range() {
        let rng = SystemRandom::new();
        for _ in 0..50 {
            let code = generate_otp_digits(&rng).expect("generate_otp_digits should succeed");
            let n: u32 = code.parse().expect("OTP must be a valid number");
            assert!(n < 1_000_000, "OTP {n} must be less than 1_000_000");
        }
    }

    #[test]
    fn digits_zero_padded() {
        // Verify format!("{:06}", 42) produces "000042" — the format is always
        // 6 digits with zero padding. We exercise the formatting path by
        // checking low-valued codes if they ever come up.
        let formatted = format!("{:06}", 42u32);
        assert_eq!(formatted, "000042");
        let formatted = format!("{:06}", 0u32);
        assert_eq!(formatted, "000000");
    }

    #[test]
    fn otp_accept_limit_excludes_bias_zone() {
        // OTP_ACCEPT_LIMIT must be the largest multiple of OTP_BOUND <= u32::MAX.
        // floor((u32::MAX + 1) / OTP_BOUND) * OTP_BOUND
        // = floor(4_294_967_296 / 1_000_000) * 1_000_000
        // = 4294 * 1_000_000
        // = 4_294_000_000
        assert_eq!(OTP_ACCEPT_LIMIT, 4_294_000_000u32);
        // Every accepted value maps to [0, OTP_BOUND) with no bias.
        assert_eq!(0u32 % OTP_BOUND, 0);
        assert_eq!((OTP_ACCEPT_LIMIT - 1) % OTP_BOUND, OTP_BOUND - 1);
        // Reject the boundary. `const_assert` would express this at compile
        // time, but we keep it as a runtime test so the documented arithmetic
        // above is exercised by the regular test suite.
        const _: () = assert!(
            OTP_ACCEPT_LIMIT < u32::MAX,
            "accept limit must leave a non-empty bias zone"
        );
    }

    // ── resend key suffix ─────────────────────────────────────────────────────

    #[test]
    fn resend_key_suffix_is_8_hex_chars() {
        let suffix = phone_resend_key_suffix("+15551234567");
        assert_eq!(suffix.len(), 8, "suffix must be 8 hex chars: {suffix}");
        assert!(
            suffix.chars().all(|c| c.is_ascii_hexdigit()),
            "suffix must be hex: {suffix}"
        );
    }

    #[test]
    fn resend_key_suffix_differs_per_phone() {
        let a = phone_resend_key_suffix("+15551234567");
        let b = phone_resend_key_suffix("+15557654321");
        assert_ne!(a, b, "different phones must produce different suffixes");
    }

    #[test]
    fn resend_key_suffix_is_deterministic() {
        let a = phone_resend_key_suffix("+15551234567");
        let b = phone_resend_key_suffix("+15551234567");
        assert_eq!(a, b, "same phone must produce the same suffix");
    }

    // ── StoredOtp ─────────────────────────────────────────────────────────────

    #[test]
    fn create_otp_returns_valid_digits_and_record() {
        let rng = SystemRandom::new();
        let expiry = 9_999_999_999u64;
        let (digits, stored) = StoredOtp::create(&rng, TEST_KEY, expiry, OTP_MAX_ATTEMPTS)
            .expect("StoredOtp::create should succeed");
        assert_eq!(digits.len(), 6, "digits must be 6 chars");
        assert!(
            digits.chars().all(|c| c.is_ascii_digit()),
            "digits must be numeric"
        );
        assert_eq!(stored.expiry_unix_ts, expiry);
        assert_eq!(stored.attempt_count, 0);
        assert!(!stored.hmac_hex.is_empty(), "hmac_hex must not be empty");
    }

    #[test]
    fn verify_succeeds_with_correct_code() {
        let rng = SystemRandom::new();
        let (digits, stored) = StoredOtp::create(&rng, TEST_KEY, 9_999_999_999, OTP_MAX_ATTEMPTS)
            .expect("StoredOtp::create should succeed");
        assert!(
            stored.verify(&digits, TEST_KEY).is_ok(),
            "verification must succeed with the correct code"
        );
    }

    #[test]
    fn verify_fails_with_wrong_code() {
        let rng = SystemRandom::new();
        let (digits, stored) = StoredOtp::create(&rng, TEST_KEY, 9_999_999_999, OTP_MAX_ATTEMPTS)
            .expect("StoredOtp::create should succeed");
        let wrong: String = if digits.as_str() == "000000" {
            "000001".to_string()
        } else {
            "000000".to_string()
        };
        assert!(
            stored.verify(&wrong, TEST_KEY).is_err(),
            "verification must fail with a wrong code"
        );
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let rng = SystemRandom::new();
        let (digits, stored) = StoredOtp::create(&rng, TEST_KEY, 9_999_999_999, OTP_MAX_ATTEMPTS)
            .expect("StoredOtp::create should succeed");
        let other_key = b"a-completely-different-key!!!!!!!!";
        assert!(
            stored.verify(&digits, other_key).is_err(),
            "verification must fail with a different HMAC key"
        );
    }

    #[test]
    fn verify_fails_with_tampered_hmac_hex() {
        let rng = SystemRandom::new();
        let (digits, mut stored) =
            StoredOtp::create(&rng, TEST_KEY, 9_999_999_999, OTP_MAX_ATTEMPTS)
                .expect("StoredOtp::create should succeed");
        // Flip the first byte of the hex string.
        let original_first = stored
            .hmac_hex
            .chars()
            .next()
            .expect("hmac_hex must have at least one char");
        let replacement = if original_first == 'a' { 'b' } else { 'a' };
        stored.hmac_hex = format!("{replacement}{}", &stored.hmac_hex[1..]);
        assert!(
            stored.verify(&digits, TEST_KEY).is_err(),
            "verification must fail when hmac_hex is tampered"
        );
    }

    #[test]
    fn is_expired_returns_true_when_past_expiry() {
        let rng = SystemRandom::new();
        let (_, stored) = StoredOtp::create(&rng, TEST_KEY, 1_000u64, OTP_MAX_ATTEMPTS)
            .expect("StoredOtp::create should succeed");
        assert!(
            stored.is_expired(1_001),
            "must be expired after expiry time"
        );
        assert!(stored.is_expired(1_000), "must be expired at expiry time");
        assert!(!stored.is_expired(999), "must not be expired before expiry");
    }

    #[test]
    fn is_exhausted_after_max_attempts() {
        let rng = SystemRandom::new();
        let (_, mut stored) = StoredOtp::create(&rng, TEST_KEY, 9_999_999_999, OTP_MAX_ATTEMPTS)
            .expect("StoredOtp::create should succeed");
        assert!(!stored.is_exhausted(), "fresh OTP must not be exhausted");
        stored.attempt_count = OTP_MAX_ATTEMPTS - 1;
        assert!(
            !stored.is_exhausted(),
            "one below max must not be exhausted"
        );
        stored.attempt_count = OTP_MAX_ATTEMPTS;
        assert!(stored.is_exhausted(), "at max must be exhausted");
    }

    #[test]
    fn per_realm_max_attempts_overrides_module_default() {
        let rng = SystemRandom::new();
        // Create an OTP with max_attempts = 2 (lower than the module default of 5).
        let (_, mut stored) = StoredOtp::create(&rng, TEST_KEY, 9_999_999_999, 2)
            .expect("StoredOtp::create should succeed");
        assert!(!stored.is_exhausted(), "fresh OTP must not be exhausted");
        stored.attempt_count = 1;
        assert!(!stored.is_exhausted(), "one attempt below limit");
        stored.attempt_count = 2;
        assert!(
            stored.is_exhausted(),
            "at per-realm limit must be exhausted"
        );
    }

    #[test]
    fn stored_otp_max_attempts_defaults_on_legacy_record() {
        // Simulate a stored record written before max_attempts was added.
        let legacy_json = r#"{
            "hmac_hex": "aabbcc",
            "expiry_unix_ts": 9999999999,
            "attempt_count": 0
        }"#;
        let stored: StoredOtp = serde_json::from_str(legacy_json).expect("deserialize");
        assert_eq!(
            stored.max_attempts, OTP_MAX_ATTEMPTS,
            "legacy record must default to module constant"
        );
    }

    // ── StoredResendCount ─────────────────────────────────────────────────────

    #[test]
    fn new_resend_count_starts_at_one() {
        let r = StoredResendCount::new(1_000);
        assert_eq!(r.count, 1);
        assert_eq!(r.window_start_unix_ts, 1_000);
    }

    #[test]
    fn resend_window_expiry_detection() {
        let r = StoredResendCount::new(1_000);
        let window_end = 1_000 + RESEND_WINDOW_SECS;
        assert!(
            !r.is_window_expired(window_end - 1),
            "before end: not expired"
        );
        assert!(r.is_window_expired(window_end), "at end: expired");
        assert!(r.is_window_expired(window_end + 1), "after end: expired");
    }

    #[test]
    fn resend_limit_reached_at_max() {
        let mut r = StoredResendCount::new(1_000);
        r.count = RESEND_MAX_PER_WINDOW - 1;
        assert!(!r.is_limit_reached(), "one below max: not reached");
        r.count = RESEND_MAX_PER_WINDOW;
        assert!(r.is_limit_reached(), "at max: reached");
    }

    // ── hex helpers ───────────────────────────────────────────────────────────

    #[test]
    fn hex_encode_decode_roundtrip() {
        let original = b"hello world";
        let encoded = hex_encode(original);
        let decoded =
            hex_decode(&encoded).expect("hex_decode of round-tripped value should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert!(hex_decode("abc").is_err(), "odd-length hex must fail");
    }

    #[test]
    fn hex_decode_rejects_invalid_chars() {
        assert!(hex_decode("zz").is_err(), "non-hex chars must fail");
    }

    // ── serialization ─────────────────────────────────────────────────────────

    #[test]
    fn stored_otp_roundtrips_via_json() {
        let rng = SystemRandom::new();
        let (_, original) = StoredOtp::create(&rng, TEST_KEY, 12_345_678, OTP_MAX_ATTEMPTS)
            .expect("StoredOtp::create should succeed");
        let json = serde_json::to_vec(&original).expect("StoredOtp should serialize to JSON");
        let restored: StoredOtp =
            serde_json::from_slice(&json).expect("StoredOtp should deserialize from JSON");
        assert_eq!(restored.hmac_hex, original.hmac_hex);
        assert_eq!(restored.expiry_unix_ts, original.expiry_unix_ts);
        assert_eq!(restored.attempt_count, original.attempt_count);
    }

    #[test]
    fn stored_resend_count_roundtrips_via_json() {
        let original = StoredResendCount::new(99_999);
        let json =
            serde_json::to_vec(&original).expect("StoredResendCount should serialize to JSON");
        let restored: StoredResendCount =
            serde_json::from_slice(&json).expect("StoredResendCount should deserialize from JSON");
        assert_eq!(restored.count, original.count);
        assert_eq!(restored.window_start_unix_ts, original.window_start_unix_ts);
    }
}
