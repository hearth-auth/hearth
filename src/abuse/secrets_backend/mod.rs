//! P-8: Pluggable secrets backend trait for signing keys, encryption-at-rest
//! keys, and Argon2 pepper.
//!
//! | Adapter | Description |
//! |---------|-------------|
//! | [`StorageSecretsBackend`] | Default — stores keys in the embedded WAL (system realm). |
//! | [`FileSecretsBackend`] | Reads key material from a directory on disk. |
//! | [`KmsSecretsBackend`] | Stub — returns [`SecretsError::NotConfigured`]. |
//! | [`HsmSecretsBackend`] | Stub — returns [`SecretsError::NotConfigured`]. |

use std::path::PathBuf;
use std::sync::Arc;

use crate::core::RealmId;
use crate::storage::{StorageEngine, StorageError};

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors returned by [`SecretsBackend`] operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretsError {
    /// The requested secret was not found for the given key.
    #[error("secret not found: {key}")]
    NotFound {
        /// Description of the key that was not found.
        key: String,
    },
    /// The backend is not configured for this operation.
    #[error("secrets backend not configured for this operation")]
    NotConfigured,
    /// An I/O error occurred while reading or writing key material.
    #[error("secrets backend I/O error: {reason}")]
    Io {
        /// Human-readable description of the I/O failure.
        reason: String,
    },
    /// A backend-specific error occurred.
    #[error("secrets backend error: {reason}")]
    Backend {
        /// Human-readable description of the backend failure.
        reason: String,
    },
}

impl From<StorageError> for SecretsError {
    fn from(e: StorageError) -> Self {
        Self::Backend {
            reason: e.to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Pluggable secrets backend (P-8).
///
/// Abstracts where Hearth reads cryptographic key material from. The identity
/// layer interprets the raw bytes returned by this trait as `SigningKey`,
/// pepper, encryption keys, etc.
///
/// All implementations MUST NOT log key material at any log level.
/// Implementors should wrap secrets in `zeroize`-on-drop types when caching.
pub trait SecretsBackend: Send + Sync {
    /// Returns the raw PKCS#8 DER bytes for the Ed25519 signing key for `realm_id`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsError::NotFound`] when no key is stored for this realm.
    fn signing_key_der(&self, realm_id: &RealmId) -> Result<Vec<u8>, SecretsError>;

    /// Stores the raw PKCS#8 DER bytes for the Ed25519 signing key for `realm_id`.
    ///
    /// Overwrites any existing key. The caller is responsible for ensuring this
    /// is an intentional key rotation or creation.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsError::Io`] or [`SecretsError::Backend`] on write failure.
    fn store_signing_key_der(&self, realm_id: &RealmId, der: &[u8]) -> Result<(), SecretsError>;

    /// Returns the 32-byte encryption-at-rest key for `realm_id`.
    ///
    /// Implementations MUST return the same key for the same realm ID on every
    /// call. Explicit rotation tooling is required to change the key.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsError::NotFound`] when no key is configured for this realm.
    fn encryption_key(&self, realm_id: &RealmId) -> Result<[u8; 32], SecretsError>;

    /// Returns the 32-byte Argon2 pepper used when hashing passwords.
    ///
    /// The pepper is a single global secret shared across all realms.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsError::NotConfigured`] when the backend does not manage
    /// a pepper. Callers should fall back to a locally-configured pepper value.
    fn pepper(&self) -> Result<[u8; 32], SecretsError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// StorageSecretsBackend — reference implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Storage key prefix for realm signing keys (PKCS#8 DER).
const STORAGE_SIGNING_KEY_PREFIX: &str = "realm:key:";
/// Storage key prefix for realm encryption-at-rest keys (32 raw bytes).
const STORAGE_EAR_KEY_PREFIX: &str = "realm:ear:";
/// Storage key for the global Argon2 pepper (32 raw bytes).
const STORAGE_PEPPER_KEY: &[u8] = b"sys:secrets:pepper";

/// Reference [`SecretsBackend`] backed by the embedded WAL (P-8).
///
/// Keys are stored under the system realm namespace using these prefixes:
/// - `realm:key:{realm_uuid}` — PKCS#8 DER Ed25519 signing key
/// - `realm:ear:{realm_uuid}` — 32-byte encryption-at-rest key
/// - `sys:secrets:pepper`     — 32-byte Argon2 pepper
///
/// The `realm:key:` prefix matches the layout already used by the identity
/// engine, so no migration is required when adopting this backend.
pub struct StorageSecretsBackend {
    storage: Arc<dyn StorageEngine>,
    system_realm: RealmId,
}

impl std::fmt::Debug for StorageSecretsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageSecretsBackend")
            .field("system_realm", &self.system_realm)
            .finish_non_exhaustive()
    }
}

impl StorageSecretsBackend {
    /// Constructs a backend backed by `storage`.
    ///
    /// `system_realm` is the nil-UUID realm used as the key namespace.
    pub fn new(storage: Arc<dyn StorageEngine>, system_realm: RealmId) -> Self {
        Self {
            storage,
            system_realm,
        }
    }
}

impl SecretsBackend for StorageSecretsBackend {
    fn signing_key_der(&self, realm_id: &RealmId) -> Result<Vec<u8>, SecretsError> {
        let key = format!("{STORAGE_SIGNING_KEY_PREFIX}{}", realm_id.as_uuid()).into_bytes();
        self.storage
            .get(&self.system_realm, &key)
            .map_err(SecretsError::from)?
            .ok_or_else(|| SecretsError::NotFound {
                key: format!("signing key for realm {}", realm_id.as_uuid()),
            })
    }

    fn store_signing_key_der(&self, realm_id: &RealmId, der: &[u8]) -> Result<(), SecretsError> {
        let key = format!("{STORAGE_SIGNING_KEY_PREFIX}{}", realm_id.as_uuid()).into_bytes();
        self.storage
            .put(&self.system_realm, &key, der)
            .map_err(SecretsError::from)
    }

    fn encryption_key(&self, realm_id: &RealmId) -> Result<[u8; 32], SecretsError> {
        let key = format!("{STORAGE_EAR_KEY_PREFIX}{}", realm_id.as_uuid()).into_bytes();
        let bytes = self
            .storage
            .get(&self.system_realm, &key)
            .map_err(SecretsError::from)?
            .ok_or_else(|| SecretsError::NotFound {
                key: format!("encryption key for realm {}", realm_id.as_uuid()),
            })?;
        let len = bytes.len();
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| SecretsError::Backend {
                reason: format!(
                    "encryption key for realm {} is {len} bytes, expected 32",
                    realm_id.as_uuid(),
                ),
            })
    }

    fn pepper(&self) -> Result<[u8; 32], SecretsError> {
        let bytes = self
            .storage
            .get(&self.system_realm, STORAGE_PEPPER_KEY)
            .map_err(SecretsError::from)?
            .ok_or(SecretsError::NotConfigured)?;
        let len = bytes.len();
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| SecretsError::Backend {
                reason: format!("pepper is {len} bytes, expected 32"),
            })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FileSecretsBackend
// ─────────────────────────────────────────────────────────────────────────────

/// [`SecretsBackend`] implementation that reads key material from the filesystem.
///
/// Directory layout:
///
/// ```text
/// {root}/
///   signing/{realm_uuid}.der   — raw PKCS#8 DER (Ed25519 signing key)
///   ear/{realm_uuid}.bin       — 32 raw bytes (encryption-at-rest key)
///   pepper.bin                 — 32 raw bytes (Argon2 pepper)
/// ```
///
/// Keys are read on every call; `store_signing_key_der` writes atomically via
/// a `.tmp` rename so a partial write never corrupts the live key.
pub struct FileSecretsBackend {
    root: PathBuf,
}

impl std::fmt::Debug for FileSecretsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSecretsBackend")
            .field("root", &self.root)
            .finish()
    }
}

impl FileSecretsBackend {
    /// Constructs a backend rooted at `root`.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Creates `{root}/signing/` and `{root}/ear/` if they do not exist.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any directory creation fails.
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(self.root.join("signing"))?;
        std::fs::create_dir_all(self.root.join("ear"))?;
        Ok(())
    }

    fn signing_key_path(&self, realm_id: &RealmId) -> PathBuf {
        self.root
            .join("signing")
            .join(format!("{}.der", realm_id.as_uuid()))
    }

    fn ear_key_path(&self, realm_id: &RealmId) -> PathBuf {
        self.root
            .join("ear")
            .join(format!("{}.bin", realm_id.as_uuid()))
    }

    fn pepper_path(&self) -> PathBuf {
        self.root.join("pepper.bin")
    }
}

impl SecretsBackend for FileSecretsBackend {
    fn signing_key_der(&self, realm_id: &RealmId) -> Result<Vec<u8>, SecretsError> {
        let path = self.signing_key_path(realm_id);
        std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SecretsError::NotFound {
                    key: format!("signing key for realm {}", realm_id.as_uuid()),
                }
            } else {
                SecretsError::Io {
                    reason: e.to_string(),
                }
            }
        })
    }

    fn store_signing_key_der(&self, realm_id: &RealmId, der: &[u8]) -> Result<(), SecretsError> {
        let path = self.signing_key_path(realm_id);
        let tmp = path.with_extension("der.tmp");
        std::fs::write(&tmp, der).map_err(|e| SecretsError::Io {
            reason: e.to_string(),
        })?;
        std::fs::rename(&tmp, &path).map_err(|e| SecretsError::Io {
            reason: e.to_string(),
        })
    }

    fn encryption_key(&self, realm_id: &RealmId) -> Result<[u8; 32], SecretsError> {
        let path = self.ear_key_path(realm_id);
        let bytes = std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SecretsError::NotFound {
                    key: format!("encryption key for realm {}", realm_id.as_uuid()),
                }
            } else {
                SecretsError::Io {
                    reason: e.to_string(),
                }
            }
        })?;
        let len = bytes.len();
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| SecretsError::Backend {
                reason: format!("ear key at {} is {len} bytes, expected 32", path.display()),
            })
    }

    fn pepper(&self) -> Result<[u8; 32], SecretsError> {
        let path = self.pepper_path();
        let bytes = std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SecretsError::NotConfigured
            } else {
                SecretsError::Io {
                    reason: e.to_string(),
                }
            }
        })?;
        let len = bytes.len();
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| SecretsError::Backend {
                reason: format!("pepper at {} is {len} bytes, expected 32", path.display()),
            })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KmsSecretsBackend (stub)
// ─────────────────────────────────────────────────────────────────────────────

/// Stub [`SecretsBackend`] for KMS integration (AWS KMS, GCP Cloud KMS, etc.).
///
/// All methods return [`SecretsError::NotConfigured`]. Replace with a concrete
/// KMS SDK adapter for production HSM/KMS integration.
#[derive(Debug, Default)]
pub struct KmsSecretsBackend;

impl SecretsBackend for KmsSecretsBackend {
    fn signing_key_der(&self, _realm_id: &RealmId) -> Result<Vec<u8>, SecretsError> {
        Err(SecretsError::NotConfigured)
    }

    fn store_signing_key_der(&self, _realm_id: &RealmId, _der: &[u8]) -> Result<(), SecretsError> {
        Err(SecretsError::NotConfigured)
    }

    fn encryption_key(&self, _realm_id: &RealmId) -> Result<[u8; 32], SecretsError> {
        Err(SecretsError::NotConfigured)
    }

    fn pepper(&self) -> Result<[u8; 32], SecretsError> {
        Err(SecretsError::NotConfigured)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HsmSecretsBackend (stub)
// ─────────────────────────────────────────────────────────────────────────────

/// Stub [`SecretsBackend`] for HSM integration (PKCS#11 / SoftHSM2).
///
/// All methods return [`SecretsError::NotConfigured`]. Replace with a concrete
/// PKCS#11 adapter for production HSM integration.
#[derive(Debug, Default)]
pub struct HsmSecretsBackend;

impl SecretsBackend for HsmSecretsBackend {
    fn signing_key_der(&self, _realm_id: &RealmId) -> Result<Vec<u8>, SecretsError> {
        Err(SecretsError::NotConfigured)
    }

    fn store_signing_key_der(&self, _realm_id: &RealmId, _der: &[u8]) -> Result<(), SecretsError> {
        Err(SecretsError::NotConfigured)
    }

    fn encryption_key(&self, _realm_id: &RealmId) -> Result<[u8; 32], SecretsError> {
        Err(SecretsError::NotConfigured)
    }

    fn pepper(&self) -> Result<[u8; 32], SecretsError> {
        Err(SecretsError::NotConfigured)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use uuid::Uuid;

    use super::*;
    use crate::core::RealmId;
    use crate::storage::{EmbeddedStorageEngine, StorageConfig};

    fn random_realm() -> RealmId {
        RealmId::new(Uuid::new_v4())
    }

    fn open_storage() -> (EmbeddedStorageEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("open storage");
        (engine, dir)
    }

    // ─────── StorageSecretsBackend ───────

    /// Round-trip a signing key DER through the storage backend.
    #[test]
    fn storage_backend_round_trips_signing_key_der() {
        let (storage, _dir) = open_storage();
        let storage = Arc::new(storage);
        let sys = RealmId::new(Uuid::nil());
        let backend =
            StorageSecretsBackend::new(Arc::clone(&storage) as Arc<dyn StorageEngine>, sys);

        let realm = random_realm();
        let der = vec![1u8; 64];

        assert!(
            matches!(
                backend.signing_key_der(&realm),
                Err(SecretsError::NotFound { .. })
            ),
            "absent key must return NotFound"
        );
        backend.store_signing_key_der(&realm, &der).expect("store");
        let got = backend.signing_key_der(&realm).expect("retrieve");
        assert_eq!(got, der, "stored DER must round-trip exactly");
    }

    /// Overwriting a signing key with a new DER is idempotent (last write wins).
    #[test]
    fn storage_backend_overwrite_signing_key() {
        let (storage, _dir) = open_storage();
        let storage = Arc::new(storage) as Arc<dyn StorageEngine>;
        let sys = RealmId::new(Uuid::nil());
        let backend = StorageSecretsBackend::new(Arc::clone(&storage), sys);

        let realm = random_realm();
        let der1 = vec![0xAAu8; 48];
        let der2 = vec![0xBBu8; 48];
        backend
            .store_signing_key_der(&realm, &der1)
            .expect("store v1");
        backend
            .store_signing_key_der(&realm, &der2)
            .expect("store v2");
        let got = backend.signing_key_der(&realm).expect("retrieve");
        assert_eq!(got, der2, "overwrite must return the latest DER");
    }

    /// A pepper is absent by default, returning `NotConfigured`.
    #[test]
    fn storage_backend_pepper_not_configured_by_default() {
        let (storage, _dir) = open_storage();
        let storage: Arc<dyn StorageEngine> = Arc::new(storage);
        let sys = RealmId::new(Uuid::nil());
        // Keep a clone for direct storage access after backend construction.
        let storage_ref = Arc::clone(&storage);
        let backend = StorageSecretsBackend::new(storage, sys.clone());

        assert!(
            matches!(backend.pepper(), Err(SecretsError::NotConfigured)),
            "pepper must be absent until stored"
        );

        // Store a valid 32-byte pepper and verify it round-trips.
        let pepper: [u8; 32] = [0x42u8; 32];
        storage_ref
            .put(&sys, STORAGE_PEPPER_KEY, &pepper)
            .expect("store pepper");
        let got = backend.pepper().expect("read pepper");
        assert_eq!(got, pepper, "pepper must round-trip exactly");
    }

    /// An absent encryption key returns `NotFound`.
    #[test]
    fn storage_backend_encryption_key_not_found_until_stored() {
        let (storage, _dir) = open_storage();
        let storage = Arc::new(storage) as Arc<dyn StorageEngine>;
        let sys = RealmId::new(Uuid::nil());
        let backend = StorageSecretsBackend::new(Arc::clone(&storage), sys.clone());

        let realm = random_realm();
        assert!(
            matches!(
                backend.encryption_key(&realm),
                Err(SecretsError::NotFound { .. })
            ),
            "encryption key must be absent until stored"
        );

        // Store and verify.
        let key: [u8; 32] = [0x77u8; 32];
        let storage_key = format!("{STORAGE_EAR_KEY_PREFIX}{}", realm.as_uuid()).into_bytes();
        storage
            .put(&sys, &storage_key, &key)
            .expect("store ear key");
        let got = backend.encryption_key(&realm).expect("read ear key");
        assert_eq!(got, key);
    }

    // ─────── FileSecretsBackend ───────

    /// Round-trip a signing key DER through the file backend.
    #[test]
    fn file_backend_round_trips_signing_key_der() {
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = FileSecretsBackend::new(dir.path().to_path_buf());
        backend.ensure_dirs().expect("ensure_dirs");

        let realm = random_realm();
        let key_der = vec![0xABu8; 48];

        assert!(
            matches!(
                backend.signing_key_der(&realm),
                Err(SecretsError::NotFound { .. })
            ),
            "absent key must return NotFound"
        );
        backend
            .store_signing_key_der(&realm, &key_der)
            .expect("store");
        let got = backend.signing_key_der(&realm).expect("retrieve");
        assert_eq!(got, key_der, "stored DER must round-trip exactly");
    }

    /// Absence of `pepper.bin` returns `NotConfigured`.
    #[test]
    fn file_backend_pepper_not_configured_when_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = FileSecretsBackend::new(dir.path().to_path_buf());
        backend.ensure_dirs().expect("ensure_dirs");
        assert!(
            matches!(backend.pepper(), Err(SecretsError::NotConfigured)),
            "missing pepper.bin must return NotConfigured"
        );
    }

    /// A 32-byte `pepper.bin` round-trips correctly.
    #[test]
    fn file_backend_pepper_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = FileSecretsBackend::new(dir.path().to_path_buf());
        let pepper: [u8; 32] = [0x42u8; 32];
        std::fs::write(dir.path().join("pepper.bin"), pepper).expect("write pepper");
        let got = backend.pepper().expect("read pepper");
        assert_eq!(got, pepper, "pepper must round-trip exactly");
    }

    /// A `pepper.bin` with a wrong byte count returns `Backend` error.
    #[test]
    fn file_backend_wrong_size_pepper_is_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = FileSecretsBackend::new(dir.path().to_path_buf());
        std::fs::write(dir.path().join("pepper.bin"), b"too_short").expect("write");
        assert!(
            matches!(backend.pepper(), Err(SecretsError::Backend { .. })),
            "wrong-size pepper must return Backend error"
        );
    }

    /// `store_signing_key_der` writes atomically (last write survives).
    #[test]
    fn file_backend_atomic_overwrite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = FileSecretsBackend::new(dir.path().to_path_buf());
        backend.ensure_dirs().expect("ensure_dirs");

        let realm = random_realm();
        let v1 = vec![0x11u8; 32];
        let v2 = vec![0x22u8; 32];
        backend
            .store_signing_key_der(&realm, &v1)
            .expect("store v1");
        backend
            .store_signing_key_der(&realm, &v2)
            .expect("store v2");
        assert_eq!(
            backend.signing_key_der(&realm).expect("read"),
            v2,
            "overwrite must return latest version"
        );
    }

    // ─────── KmsSecretsBackend stub ───────

    /// All operations on the KMS stub return `NotConfigured`.
    #[test]
    fn kms_stub_returns_not_configured() {
        let backend = KmsSecretsBackend;
        let realm = random_realm();
        assert!(matches!(
            backend.signing_key_der(&realm),
            Err(SecretsError::NotConfigured)
        ));
        assert!(matches!(
            backend.store_signing_key_der(&realm, &[]),
            Err(SecretsError::NotConfigured)
        ));
        assert!(matches!(
            backend.encryption_key(&realm),
            Err(SecretsError::NotConfigured)
        ));
        assert!(matches!(backend.pepper(), Err(SecretsError::NotConfigured)));
    }

    // ─────── HsmSecretsBackend stub ───────

    /// All operations on the HSM stub return `NotConfigured`.
    #[test]
    fn hsm_stub_returns_not_configured() {
        let backend = HsmSecretsBackend;
        let realm = random_realm();
        assert!(matches!(
            backend.signing_key_der(&realm),
            Err(SecretsError::NotConfigured)
        ));
        assert!(matches!(
            backend.store_signing_key_der(&realm, &[]),
            Err(SecretsError::NotConfigured)
        ));
        assert!(matches!(
            backend.encryption_key(&realm),
            Err(SecretsError::NotConfigured)
        ));
        assert!(matches!(backend.pepper(), Err(SecretsError::NotConfigured)));
    }
}
