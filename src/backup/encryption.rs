//! Passphrase-based envelope encryption for full backup archives.
//!
//! # Encrypted archive layout
//!
//! ```text
//! HEARTH-BAK-ENC          (14 bytes, magic)
//! m_cost                  ( 4 bytes, little-endian u32 — Argon2id memory KiB)
//! t_cost                  ( 4 bytes, little-endian u32 — Argon2id iterations)
//! p_cost                  ( 4 bytes, little-endian u32 — Argon2id parallelism)
//! salt                    (16 bytes, random)
//! nonce                   (12 bytes, random)
//! ciphertext || GCM-tag   (variable — inner tar.zstd archive + 16-byte auth tag)
//! ```
//!
//! The passphrase is derived to a 32-byte AES-256 key via Argon2id using
//! OWASP-recommended parameters (m=65536, t=3, p=4).  The derived key is
//! zeroized immediately after the AES context consumes it.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

use super::BackupError;

/// Magic header that identifies an encrypted `.hearth-backup` envelope.
const MAGIC: &[u8; 14] = b"HEARTH-BAK-ENC";

/// Argon2id memory cost in KiB (OWASP recommendation).
const M_COST: u32 = 65_536;
/// Argon2id time cost (iterations).
const T_COST: u32 = 3;
/// Argon2id parallelism factor.
const P_COST: u32 = 4;

/// Byte length of the fixed envelope header (magic + params + salt + nonce).
const HEADER_LEN: usize = 14 + 4 + 4 + 4 + 16 + 12;

/// AES-256-GCM encrypts `input` (a raw `.hearth-backup` archive) under a key
/// derived from `passphrase`.
///
/// Returns the full encrypted envelope including the magic header, KDF
/// parameters, random salt, random nonce, and the authenticated ciphertext
/// (inner archive + 16-byte GCM tag).
///
/// The derived AES key is zeroized immediately after the encryption context
/// is constructed.  The passphrase bytes are never logged or stored.
///
/// # Errors
///
/// Returns [`BackupError::Crypto`] if random number generation fails or if the
/// AES-GCM operation fails.
pub fn encrypt_archive(passphrase: &SecretString, input: &[u8]) -> Result<Vec<u8>, BackupError> {
    let rng = SystemRandom::new();
    let salt = random_bytes::<16>(&rng)?;
    let nonce_bytes = random_bytes::<12>(&rng)?;

    let mut key_bytes = derive_key(passphrase.expose_secret().as_bytes(), &salt)?;

    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| BackupError::Crypto("AES key initialisation failed".into()))?;
    key_bytes.zeroize();

    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut ciphertext = input.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| BackupError::Crypto("encryption failed".into()))?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&M_COST.to_le_bytes());
    out.extend_from_slice(&T_COST.to_le_bytes());
    out.extend_from_slice(&P_COST.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts an envelope produced by [`encrypt_archive`].
///
/// Returns the original plaintext archive bytes on success.
///
/// # Errors
///
/// Returns [`BackupError::Crypto`] when:
/// - `data` is shorter than the minimum envelope header,
/// - the magic bytes are absent,
/// - the passphrase is wrong (GCM authentication failure), or
/// - the ciphertext is truncated or corrupted.
pub fn decrypt_archive(passphrase: &SecretString, data: &[u8]) -> Result<Vec<u8>, BackupError> {
    if data.len() < HEADER_LEN {
        return Err(BackupError::Crypto(
            "data too short to be a valid encrypted archive".into(),
        ));
    }

    if &data[..14] != MAGIC {
        return Err(BackupError::Crypto(
            "missing HEARTH-BAK-ENC magic bytes".into(),
        ));
    }

    // Parse KDF parameters stored in the envelope (may differ from build-time
    // constants if an older/newer writer used different params).
    let m_cost = u32::from_le_bytes(data[14..18].try_into().expect("4-byte slice"));
    let t_cost = u32::from_le_bytes(data[18..22].try_into().expect("4-byte slice"));
    let p_cost = u32::from_le_bytes(data[22..26].try_into().expect("4-byte slice"));

    let salt: [u8; 16] = data[26..42].try_into().expect("16-byte slice");
    let nonce_bytes: [u8; 12] = data[42..54].try_into().expect("12-byte slice");
    let ciphertext_and_tag = &data[HEADER_LEN..];

    // ring needs at least 16 bytes (the GCM tag) to open the seal.
    if ciphertext_and_tag.len() < 16 {
        return Err(BackupError::Crypto(
            "ciphertext too short — archive is truncated or corrupted".into(),
        ));
    }

    let mut key_bytes = derive_key_with_params(
        passphrase.expose_secret().as_bytes(),
        &salt,
        m_cost,
        t_cost,
        p_cost,
    )?;

    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| BackupError::Crypto("AES key initialisation failed".into()))?;
    key_bytes.zeroize();

    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = ciphertext_and_tag.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| {
            BackupError::Crypto("decryption failed — wrong passphrase or corrupted archive".into())
        })?;
    Ok(plaintext.to_vec())
}

/// Derives a 32-byte AES key using the default OWASP Argon2id parameters.
fn derive_key(password: &[u8], salt: &[u8; 16]) -> Result<[u8; 32], BackupError> {
    derive_key_with_params(password, salt, M_COST, T_COST, P_COST)
}

/// Derives a 32-byte AES key using caller-supplied Argon2id parameters.
///
/// Accepts arbitrary params so that archives written by future versions with
/// updated parameters can still be decrypted.
fn derive_key_with_params(
    password: &[u8],
    salt: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], BackupError> {
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| BackupError::Crypto(format!("argon2 params: {e}")))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| BackupError::Crypto(format!("argon2 derivation: {e}")))?;
    Ok(key)
}

/// Fills a stack-allocated `[u8; N]` with cryptographically random bytes.
fn random_bytes<const N: usize>(rng: &impl SecureRandom) -> Result<[u8; N], BackupError> {
    let mut buf = [0u8; N];
    rng.fill(&mut buf)
        .map_err(|_| BackupError::Crypto("random byte generation failed".into()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pp(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"fake tar.zstd archive bytes for roundtrip test";
        let encrypted =
            encrypt_archive(&pp("correct-horse-battery-staple"), plaintext).expect("encrypt");
        let decrypted =
            decrypt_archive(&pp("correct-horse-battery-staple"), &encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_passphrase_returns_crypto_error() {
        let plaintext = b"some archive data here";
        let encrypted = encrypt_archive(&pp("the-right-passphrase"), plaintext).expect("encrypt");
        let err = decrypt_archive(&pp("the-wrong-passphrase"), &encrypted)
            .expect_err("should fail with wrong passphrase");
        assert!(
            matches!(err, BackupError::Crypto(_)),
            "expected Crypto error, got {err}"
        );
    }

    #[test]
    fn truncated_ciphertext_returns_crypto_error() {
        let plaintext = b"archive data that will be truncated";
        let mut encrypted = encrypt_archive(&pp("passphrase"), plaintext).expect("encrypt");
        // Keep only the header + a few ciphertext bytes (not enough for the 16-byte GCM tag).
        encrypted.truncate(HEADER_LEN + 4);
        let err = decrypt_archive(&pp("passphrase"), &encrypted)
            .expect_err("should fail on truncated ciphertext");
        assert!(
            matches!(err, BackupError::Crypto(_)),
            "expected Crypto error, got {err}"
        );
    }

    #[test]
    fn data_too_short_returns_crypto_error() {
        let err =
            decrypt_archive(&pp("any"), b"too-short").expect_err("should fail on too-short input");
        assert!(matches!(err, BackupError::Crypto(_)));
    }

    #[test]
    fn wrong_magic_returns_crypto_error() {
        let mut data = vec![0u8; HEADER_LEN + 20];
        data[..14].copy_from_slice(b"NOT-THE-MAGIC!");
        let err = decrypt_archive(&pp("any"), &data).expect_err("should fail with wrong magic");
        assert!(matches!(err, BackupError::Crypto(_)));
    }

    #[test]
    fn encrypted_envelope_has_correct_structure() {
        let plaintext = b"test";
        let encrypted = encrypt_archive(&pp("pw"), plaintext).expect("encrypt");
        // Magic
        assert_eq!(&encrypted[..14], MAGIC);
        // Params (little-endian)
        assert_eq!(
            u32::from_le_bytes(encrypted[14..18].try_into().expect("4 bytes")),
            M_COST
        );
        assert_eq!(
            u32::from_le_bytes(encrypted[18..22].try_into().expect("4 bytes")),
            T_COST
        );
        assert_eq!(
            u32::from_le_bytes(encrypted[22..26].try_into().expect("4 bytes")),
            P_COST
        );
        // Total length: header + plaintext + 16-byte GCM tag
        assert_eq!(encrypted.len(), HEADER_LEN + plaintext.len() + 16);
    }
}
