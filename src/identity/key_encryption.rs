//! AES-256-GCM envelope encryption for cryptographic key material stored in the WAL.
//!
//! # Format
//!
//! Encrypted blobs written by this module begin with the `HKEY` magic tag and
//! have the following layout:
//!
//! ```text
//! HKEY          (4 bytes, magic)
//! version       (1 byte,  always 0x01 for this layout)
//! nonce         (12 bytes, random, unique per write)
//! ciphertext || GCM-tag  (variable — plaintext + 16-byte auth tag)
//! ```
//!
//! Total overhead over the plaintext: 33 bytes (4+1+12+16).
//!
//! # Backward compatibility
//!
//! Legacy blobs (stored before key-encryption was enabled) do **not** start
//! with `HKEY` — Ed25519 PKCS#8 starts with `0x30`, RSA JSON starts with
//! `{`, and DPoP nonce secrets are raw 32-byte arrays.  [`unwrap_key`] checks
//! the magic and passes non-`HKEY` blobs through unchanged so existing WALs
//! remain readable when a KEK is later added.  A `WARN` trace event is emitted
//! so operators know which keys are still in plaintext and will be re-encrypted
//! on the next rotation.

// Items are used by TOTP engine code staged separately; suppress dead_code until
// the calling code is committed.
#![allow(dead_code)]

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{generate, SystemRandom};
use zeroize::Zeroizing;

use crate::identity::IdentityError;

/// Magic tag at the start of every HKEY-encrypted blob.
const MAGIC: &[u8; 4] = b"HKEY";
/// Version byte for the v1 envelope (magic + version + nonce + ciphertext+tag).
const VERSION_V1: u8 = 1;
/// AES-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;
/// Total envelope header length: MAGIC(4) + VERSION(1) + NONCE(12) = 17.
const HEADER_LEN: usize = 4 + 1 + NONCE_LEN;

/// Opaque 32-byte key-encryption key (KEK).
///
/// Wraps a `Zeroizing<[u8; 32]>` so that the key bytes are actively overwritten
/// on drop.  `Debug` is manually implemented to never reveal key material.
pub struct StorageKek(pub(crate) Zeroizing<[u8; 32]>);

impl StorageKek {
    /// Constructs a new `StorageKek` from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Returns a reference to the inner 32-byte key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for StorageKek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StorageKek([REDACTED])")
    }
}

impl Clone for StorageKek {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(*self.0))
    }
}

/// Wraps `plaintext` for WAL storage using AES-256-GCM.
///
/// When `kek` is `Some`, encrypts the plaintext and prepends the HKEY envelope
/// header.  When `kek` is `None`, returns the plaintext bytes unchanged so
/// operators who have not configured a KEK are unaffected.
///
/// # Errors
///
/// Returns [`IdentityError::SigningError`] if nonce generation or AES-GCM
/// initialisation fails.
pub(crate) fn wrap_key(plaintext: &[u8], kek: Option<&[u8; 32]>) -> Result<Vec<u8>, IdentityError> {
    let Some(kek) = kek else {
        return Ok(plaintext.to_vec());
    };

    let rng = SystemRandom::new();
    let nonce_bytes: [u8; NONCE_LEN] = generate::<[u8; NONCE_LEN]>(&rng)
        .map_err(|_| IdentityError::SigningError {
            reason: "key envelope: nonce generation failed".into(),
        })?
        .expose();

    let unbound =
        UnboundKey::new(&AES_256_GCM, kek.as_ref()).map_err(|_| IdentityError::SigningError {
            reason: "key envelope: AES-256-GCM init failed".into(),
        })?;
    let aes_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut ciphertext = plaintext.to_vec();
    aes_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| IdentityError::SigningError {
            reason: "key envelope: encryption failed".into(),
        })?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION_V1);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Reads stored key material, decrypting if the HKEY envelope is present.
///
/// - If `bytes` starts with `HKEY`, decrypts with `kek` (returns an error if
///   no KEK is configured — this prevents silently reading encrypted keys as
///   garbage).
/// - Otherwise treats `bytes` as legacy plaintext and returns a copy.  When a
///   KEK *is* configured a `WARN` trace event is emitted so operators know the
///   key was stored before encryption was enabled and will be re-encrypted on
///   the next rotation.
///
/// # Errors
///
/// Returns [`IdentityError::SigningError`] on decryption failure (wrong KEK,
/// corrupted ciphertext, or unsupported version).
pub(crate) fn unwrap_key(
    bytes: &[u8],
    kek: Option<&[u8; 32]>,
) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    // Not an HKEY envelope — legacy plaintext path.
    if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
        if kek.is_some() {
            tracing::warn!(
                "key material read from WAL without HKEY envelope while \
                 key_encryption_key is configured; this key predates \
                 at-rest encryption and will be re-encrypted on next rotation"
            );
        }
        return Ok(Zeroizing::new(bytes.to_vec()));
    }

    let kek = kek.ok_or_else(|| IdentityError::SigningError {
        reason: "key material has HKEY envelope but no key_encryption_key is \
                 configured — set security.key_encryption_key in hearth.yaml \
                 or the HEARTH_KEK environment variable"
            .into(),
    })?;

    if bytes.len() < HEADER_LEN + 16 {
        return Err(IdentityError::SigningError {
            reason: "HKEY envelope is too short — WAL entry may be corrupted".into(),
        });
    }

    let version = bytes[MAGIC.len()];
    if version != VERSION_V1 {
        return Err(IdentityError::SigningError {
            reason: format!("unsupported HKEY envelope version {version}"),
        });
    }

    // SAFETY: slice bounds guaranteed by HEADER_LEN check above.
    let nonce_bytes: [u8; NONCE_LEN] = bytes[5..HEADER_LEN]
        .try_into()
        .expect("12-byte slice guaranteed by HEADER_LEN constant");
    let ciphertext = &bytes[HEADER_LEN..];

    let unbound =
        UnboundKey::new(&AES_256_GCM, kek.as_ref()).map_err(|_| IdentityError::SigningError {
            reason: "key envelope: AES-256-GCM init failed".into(),
        })?;
    let aes_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = ciphertext.to_vec();
    let plaintext_len = aes_key
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| IdentityError::SigningError {
            reason: "HKEY decryption failed — wrong key_encryption_key or corrupted WAL entry"
                .into(),
        })?
        .len();
    buf.truncate(plaintext_len);

    Ok(Zeroizing::new(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_kek() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn roundtrip_with_kek() {
        let plaintext = b"ed25519-pkcs8-material-here-1234";
        let wrapped = wrap_key(plaintext, Some(&fixed_kek())).expect("wrap");
        assert_ne!(
            wrapped.as_slice(),
            plaintext,
            "wrapped must differ from plaintext"
        );
        assert_eq!(&wrapped[..4], b"HKEY", "must start with HKEY magic");
        assert_eq!(wrapped[4], VERSION_V1, "version byte must be 1");
        let unwrapped = unwrap_key(&wrapped, Some(&fixed_kek())).expect("unwrap");
        assert_eq!(unwrapped.as_slice(), plaintext);
    }

    #[test]
    fn passthrough_without_kek() {
        // Raw PKCS#8 starts with 0x30; must round-trip unchanged.
        let plaintext = b"\x30\x26raw-pkcs8-bytes-here";
        let wrapped = wrap_key(plaintext, None).expect("wrap no-kek");
        assert_eq!(wrapped.as_slice(), plaintext);
        let unwrapped = unwrap_key(&wrapped, None).expect("unwrap no-kek");
        assert_eq!(unwrapped.as_slice(), plaintext);
    }

    #[test]
    fn plaintext_readable_when_kek_added_later() {
        // Simulates adding KEK to an existing deployment with plaintext keys.
        let plaintext = b"\x30\x26legacy-pkcs8";
        let unwrapped = unwrap_key(plaintext, Some(&fixed_kek())).expect("unwrap legacy");
        assert_eq!(unwrapped.as_slice(), plaintext);
    }

    #[test]
    fn encrypted_requires_kek_to_read() {
        let wrapped = wrap_key(b"secret", Some(&fixed_kek())).expect("wrap");
        let err = unwrap_key(&wrapped, None).expect_err("should fail without KEK");
        assert!(matches!(err, IdentityError::SigningError { .. }));
    }

    #[test]
    fn wrong_kek_returns_error() {
        let wrapped = wrap_key(b"secret", Some(&fixed_kek())).expect("wrap");
        let bad_kek = [0xCC; 32];
        let err = unwrap_key(&wrapped, Some(&bad_kek)).expect_err("wrong KEK");
        assert!(matches!(err, IdentityError::SigningError { .. }));
    }

    #[test]
    fn encrypted_bytes_do_not_contain_plaintext() {
        let plaintext = b"super-secret-signing-key-material";
        let wrapped = wrap_key(plaintext, Some(&fixed_kek())).expect("wrap");
        assert!(
            !wrapped.windows(plaintext.len()).any(|w| w == plaintext),
            "plaintext must not appear verbatim in wrapped bytes"
        );
    }

    #[test]
    fn different_nonces_produce_different_ciphertexts() {
        let plaintext = b"same-key-different-nonce";
        let w1 = wrap_key(plaintext, Some(&fixed_kek())).expect("wrap 1");
        let w2 = wrap_key(plaintext, Some(&fixed_kek())).expect("wrap 2");
        // Nonces are random; successive wraps must produce different output.
        assert_ne!(w1, w2, "each wrap call must use a fresh nonce");
    }

    #[test]
    fn truncated_envelope_returns_error() {
        let wrapped = wrap_key(b"data", Some(&fixed_kek())).expect("wrap");
        let truncated = &wrapped[..HEADER_LEN]; // no ciphertext+tag
        let err = unwrap_key(truncated, Some(&fixed_kek())).expect_err("too short");
        assert!(matches!(err, IdentityError::SigningError { .. }));
    }
}
