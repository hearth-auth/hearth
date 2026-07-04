//! Key registry for per-realm Key Encryption Keys (KEKs).
//!
//! Manages the two-level envelope encryption hierarchy:
//!
//! ```text
//! Host Key (from HEARTH_MASTER_KEY env var or auto-generated file)
//!   └── Realm KEKs (stored encrypted in hearth.keys)
//!         └── File DEKs (stored wrapped in SST/WAL headers)
//!               └── File data (encrypted with DEK)
//! ```
//!
//! KEKs are persisted in `{data_dir}/hearth.keys` with integrity framing:
//!
//! ```text
//! [2B]  Version (0x0001, u16 LE)
//! Per-entry:
//!   [16B] RealmId UUID bytes
//!   [4B]  Encrypted KEK length (u32 LE)
//!   [NB]  Encrypted KEK (nonce + ciphertext + tag from encrypt_kek)
//!   [4B]  CRC32 of preceding entry bytes (UUID + length + encrypted KEK)
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::core::RealmId;
use crate::storage::encryption::{
    decrypt_kek, encrypt_kek, generate_host_key, generate_kek, HostKey, KekId, KeyEncryptionKey,
    KEK_ID_SIZE,
};
use crate::storage::error::StorageError;
use crate::storage::fs::{Fs, RealFs};

/// File version: 2 bytes, u16 LE.
const KEY_FILE_VERSION: u16 = 0x0001;
const KEY_FILE_VERSION_SIZE: usize = 2;

// ── Host key file format ─────────────────────────────────────────────────────
//
// Layout: [8B magic][32B key][32B HMAC-SHA256] = 72 bytes total
//
// The HMAC covers the magic and key bytes (magic || key).
// HOST_KEY_HMAC_CONTEXT is the HMAC key — a domain-separation constant, not a
// secret. Its role is detecting accidental file corruption, not third-party
// authentication.
const HOST_KEY_MAGIC: &[u8; 8] = b"HRTHHKY1";
const HOST_KEY_FILE_SIZE: usize = 8 + 32 + 32; // magic + key + HMAC
const HOST_KEY_HMAC_CONTEXT: &[u8] = b"hearth:host-key-file:integrity:v1";

/// Maps realm IDs to their decrypted KEKs.
type KekMap = HashMap<RealmId, KeyEncryptionKey>;

/// Manages per-realm Key Encryption Keys.
///
/// Thread-safe via a `std::sync::Mutex`. KEK operations are off the hot path
/// (only during startup, realm creation, and key rotation).
pub(crate) struct KeyRegistry {
    /// Host key loaded from environment or auto-generated.
    host_key: HostKey,
    /// In-memory map of realm ID → decrypted KEK.
    keks: Mutex<KekMap>,
    /// Path to the `hearth.keys` persistence file.
    key_file_path: PathBuf,
    /// File handle for appending KEK entries (fsync'd on write).
    key_file: Mutex<Option<Box<dyn crate::storage::fs::FsFile>>>,
    /// Filesystem abstraction.
    fs: Arc<dyn Fs>,
}

impl KeyRegistry {
    /// Loads or creates the key registry.
    ///
    /// `dev_mode: true` permits auto-generating the host key when
    /// `HEARTH_MASTER_KEY` is unset. `false` fails closed (production).
    pub(crate) fn load(data_dir: &Path, dev_mode: bool) -> Result<Self, StorageError> {
        Self::load_with_fs(data_dir, Arc::new(RealFs), dev_mode)
    }

    /// Loads the key registry with a custom filesystem.
    pub(crate) fn load_with_fs(
        data_dir: &Path,
        fs: Arc<dyn Fs>,
        dev_mode: bool,
    ) -> Result<Self, StorageError> {
        fs.create_dir_all(data_dir)?;
        let host_key = load_or_create_host_key(data_dir, &*fs, dev_mode)?;
        let prev_host_key = load_previous_host_key()?;
        Self::load_with_keys(data_dir, fs, host_key, prev_host_key)
    }

    /// Loads the key registry with explicit host keys (used directly in tests).
    pub(crate) fn load_with_keys(
        data_dir: &Path,
        fs: Arc<dyn Fs>,
        host_key: HostKey,
        prev_host_key: Option<HostKey>,
    ) -> Result<Self, StorageError> {
        let key_file_path = data_dir.join("hearth.keys");

        let load_result = if key_file_path.exists() {
            load_keks_from_file(&key_file_path, &host_key, prev_host_key.as_ref(), &*fs)?
        } else {
            LoadKeksResult::empty()
        };

        // Block startup when any KEK entry has CRC corruption — silent realm
        // unavailability is worse than a loud startup refusal (fail-closed).
        if !load_result.corrupted.is_empty() {
            let affected_realms = load_result
                .corrupted
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>();
            return Err(StorageError::CorruptedKeks { affected_realms });
        }

        // Block startup when any KEK cannot be decrypted with either key.
        if !load_result.failed.is_empty() {
            let affected_realms = load_result
                .failed
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>();
            return Err(StorageError::HostKeyMismatch { affected_realms });
        }

        let keks = load_result.keks;

        // Re-encrypt KEKs that were decrypted with the previous host key, then
        // rewrite hearth.keys atomically so the old key is no longer needed.
        let key_file: Option<Box<dyn crate::storage::fs::FsFile>> =
            if !load_result.needs_reencrypt.is_empty() {
                tracing::info!(
                    count = load_result.needs_reencrypt.len(),
                    "HEARTH_PREVIOUS_MASTER_KEY: re-encrypting realm KEKs under new master key"
                );
                Some(rewrite_keys_file(&key_file_path, &keks, &host_key, &*fs)?)
            } else if key_file_path.exists() {
                Some(fs.open_append(&key_file_path)?)
            } else {
                None
            };

        Ok(Self {
            host_key,
            keks: Mutex::new(keks),
            key_file_path,
            key_file: Mutex::new(key_file),
            fs,
        })
    }

    /// Returns the KEK identifier for a realm (its UUID bytes).
    pub(crate) fn kek_id_for_realm(&self, realm_id: &RealmId) -> KekId {
        let mut id = [0u8; KEK_ID_SIZE];
        let uuid_bytes = realm_id.as_uuid().as_bytes();
        id.copy_from_slice(uuid_bytes);
        id
    }

    /// Returns the decrypted KEK for a realm, if it exists.
    pub(crate) fn get_kek_for_realm(&self, realm_id: &RealmId) -> Option<KeyEncryptionKey> {
        let keks = self.keks.lock().ok()?;
        keks.get(realm_id).map(|k| k.clone_key())
    }

    /// Returns true if a KEK exists for the given realm.
    #[allow(dead_code)]
    pub(crate) fn has_kek_for_realm(&self, realm_id: &RealmId) -> bool {
        self.keks
            .lock()
            .map(|k| k.contains_key(realm_id))
            .unwrap_or(false)
    }

    /// Ensures a realm has a KEK, generating one if it doesn't exist.
    ///
    /// Returns the KEK. On first creation for a realm, the KEK is persisted
    /// to `hearth.keys` immediately with fsync.
    pub(crate) fn ensure_kek_for_realm(
        &self,
        realm_id: &RealmId,
    ) -> Result<KeyEncryptionKey, StorageError> {
        {
            let keks = self.keks.lock().map_err(|_| StorageError::Crypto {
                reason: "KEK map mutex poisoned".to_string(),
            })?;
            if let Some(kek) = keks.get(realm_id) {
                return Ok(kek.clone_key());
            }
        }

        // Generate new KEK
        let new_kek = generate_kek()?;
        let kek_id = self.kek_id_for_realm(realm_id);
        let encrypted = encrypt_kek(&new_kek, &self.host_key, kek_id)?;

        // Persist to hearth.keys with fsync
        self.append_kek_entry(realm_id, &encrypted)?;

        // Store in memory
        {
            let mut keks = self.keks.lock().map_err(|_| StorageError::Crypto {
                reason: "KEK map mutex poisoned".to_string(),
            })?;
            keks.insert(realm_id.clone(), new_kek.clone_key());
        }

        Ok(new_kek)
    }

    /// Rotates the KEK for a realm: generates a new KEK and persists it.
    ///
    /// Returns `(old_kek, new_kek)`. The caller is responsible for re-wrapping
    /// all DEKs in SST/WAL files with the new KEK.
    #[allow(dead_code)]
    pub(crate) fn rotate_kek(
        &self,
        realm_id: &RealmId,
    ) -> Result<(KeyEncryptionKey, KeyEncryptionKey), StorageError> {
        let old_kek = {
            let keks = self.keks.lock().map_err(|_| StorageError::Crypto {
                reason: "KEK map mutex poisoned".to_string(),
            })?;
            keks.get(realm_id)
                .map(|k| k.clone_key())
                .ok_or_else(|| StorageError::Crypto {
                    reason: format!("no KEK for realm {realm_id}"),
                })?
        };

        let new_kek = generate_kek()?;
        let kek_id = self.kek_id_for_realm(realm_id);
        let encrypted = encrypt_kek(&new_kek, &self.host_key, kek_id)?;

        // Persist new KEK with fsync
        self.append_kek_entry(realm_id, &encrypted)?;

        // Update in memory
        {
            let mut keks = self.keks.lock().map_err(|_| StorageError::Crypto {
                reason: "KEK map mutex poisoned".to_string(),
            })?;
            keks.insert(realm_id.clone(), new_kek.clone_key());
        }

        Ok((old_kek, new_kek))
    }

    /// Appends a KEK entry to `hearth.keys` with CRC32 framing and fsync.
    fn append_kek_entry(
        &self,
        realm_id: &RealmId,
        encrypted_kek: &[u8],
    ) -> Result<(), StorageError> {
        #[allow(clippy::cast_possible_truncation)]
        let entry_len = encrypted_kek.len() as u32;

        // Build entry: [uuid(16)][length(4)][encrypted(N)][crc32(4)]
        let mut entry = Vec::with_capacity(16 + 4 + encrypted_kek.len() + 4);
        entry.extend_from_slice(realm_id.as_uuid().as_bytes());
        entry.extend_from_slice(&entry_len.to_le_bytes());
        entry.extend_from_slice(encrypted_kek);

        // Compute CRC32 over preceding bytes
        let crc = crc32fast::hash(&entry);
        entry.extend_from_slice(&crc.to_le_bytes());

        let mut file_guard = self.key_file.lock().map_err(|_| StorageError::Crypto {
            reason: "key file mutex poisoned".to_string(),
        })?;

        if file_guard.is_none() {
            // Create key file with version header
            *file_guard = Some(self.fs.create(&self.key_file_path)?);
            let version_bytes = KEY_FILE_VERSION.to_le_bytes();
            file_guard
                .as_mut()
                .ok_or_else(|| StorageError::Crypto {
                    reason: "failed to create key file".to_string(),
                })?
                .write_all(&version_bytes)?;
        }

        let f = file_guard.as_mut().ok_or_else(|| StorageError::Crypto {
            reason: "key file handle lost".to_string(),
        })?;
        f.write_all(&entry)?;
        f.sync_all()?;

        Ok(())
    }
}

impl std::fmt::Debug for KeyRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.keks.lock().map(|k| k.len()).unwrap_or(0);
        f.debug_struct("KeyRegistry")
            .field("key_file_path", &self.key_file_path)
            .field("loaded_realms", &count)
            .finish_non_exhaustive()
    }
}

/// Result of loading KEKs from `hearth.keys`.
struct LoadKeksResult {
    keks: KekMap,
    /// Realms whose KEK was decrypted with the *previous* host key; need re-encryption.
    needs_reencrypt: Vec<RealmId>,
    /// Realms whose KEK passed CRC but could not be decrypted with either key.
    failed: Vec<RealmId>,
    /// Realms whose KEK entry failed CRC verification — data integrity compromise.
    corrupted: Vec<RealmId>,
}

impl LoadKeksResult {
    fn empty() -> Self {
        Self {
            keks: KekMap::new(),
            needs_reencrypt: Vec::new(),
            failed: Vec::new(),
            corrupted: Vec::new(),
        }
    }
}

/// Loads or creates the host key.
///
/// Priority:
/// 1. `HEARTH_MASTER_KEY` environment variable (hex-encoded 32-byte key)
/// 2. `{data_dir}/hearth.host_key` file (32 raw bytes)
/// 3. Auto-generate and persist to `{data_dir}/hearth.host_key`
fn load_or_create_host_key(
    data_dir: &Path,
    fs: &dyn Fs,
    dev_mode: bool,
) -> Result<HostKey, StorageError> {
    // 1. Check environment variable
    if let Ok(env_val) = std::env::var("HEARTH_MASTER_KEY") {
        let env_val = env_val.trim();
        if env_val.len() == 64 {
            let bytes = decode_hex(env_val).map_err(|_| StorageError::Crypto {
                reason: "HEARTH_MASTER_KEY is not valid hex".to_string(),
            })?;
            return Ok(HostKey::from_bytes(bytes));
        }
        return Err(StorageError::Crypto {
            reason: "HEARTH_MASTER_KEY must be 64 hex chars".to_string(),
        });
    }

    // 2. Check file
    let host_key_path = data_dir.join("hearth.host_key");
    if host_key_path.exists() {
        // Warn on non-Unix platforms where OS file ACLs cannot be enforced.
        // On Unix the file is written with mode 0o600 (owner read/write only).
        #[cfg(not(unix))]
        tracing::warn!(
            path = %host_key_path.display(),
            "hearth.host_key file permissions cannot be enforced on this platform; \
             use the HEARTH_MASTER_KEY environment variable to protect the host key"
        );

        let data = fs.read(&host_key_path)?;

        // Verify file length: [8B magic][32B key][32B HMAC] = 72 bytes.
        if data.len() != HOST_KEY_FILE_SIZE {
            return Err(StorageError::Crypto {
                reason: format!(
                    "hearth.host_key has unexpected length: {} bytes \
                     (expected {HOST_KEY_FILE_SIZE} for magic+key+HMAC framing)",
                    data.len()
                ),
            });
        }

        // Verify magic header.
        if &data[..8] != HOST_KEY_MAGIC {
            return Err(StorageError::Crypto {
                reason: "hearth.host_key has invalid magic header; \
                         file may be corrupted or is from an incompatible version"
                    .to_string(),
            });
        }

        // Extract key bytes.
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&data[8..40]);

        // Verify HMAC-SHA256 integrity tag (constant-time comparison).
        if !verify_host_key_file_hmac(&key_bytes, &data[40..72]) {
            return Err(StorageError::Crypto {
                reason: "hearth.host_key: HMAC integrity check failed; \
                         file is corrupted — restore from backup or delete and restart"
                    .to_string(),
            });
        }

        return Ok(HostKey::from_bytes(key_bytes));
    }

    // 3. Auto-generate — only allowed in dev mode
    if !dev_mode {
        return Err(StorageError::Crypto {
            reason: "HEARTH_MASTER_KEY is not set and auto-generation is disabled in \
                     production mode; set HEARTH_MASTER_KEY to a 64-hex-char random key \
                     (e.g. openssl rand -hex 32)"
                .to_string(),
        });
    }

    tracing::warn!(
        path = %host_key_path.display(),
        "auto-generating host key and persisting to disk — \
         set HEARTH_MASTER_KEY for production deployments"
    );

    let host_key = generate_host_key()?;
    write_host_key_private(&host_key_path, &host_key)?;

    Ok(host_key)
}

/// Writes the host key file with HMAC-SHA256 integrity framing and mode `0o600`.
///
/// File layout: `[8B magic][32B key][32B HMAC-SHA256]` = 72 bytes total.
/// Uses `create_new` semantics to prevent silently overwriting an existing key.
///
/// On non-Unix platforms the mode flag is a no-op; callers should use
/// `HEARTH_MASTER_KEY` instead of the file to maintain access control.
fn write_host_key_private(path: &Path, key: &HostKey) -> Result<(), StorageError> {
    let hmac_tag = host_key_file_hmac(key.as_bytes());
    let mut content = Vec::with_capacity(HOST_KEY_FILE_SIZE);
    content.extend_from_slice(HOST_KEY_MAGIC);
    content.extend_from_slice(key.as_bytes());
    content.extend_from_slice(&hmac_tag);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    std::io::Write::write_all(&mut file, &content)?;
    Ok(())
}

/// Computes the HMAC-SHA256 integrity tag for a host key file.
///
/// Covers `HOST_KEY_MAGIC || key_bytes` so that both magic and key must be
/// intact for the tag to verify. The HMAC key is a compile-time
/// domain-separation constant, not a runtime secret.
fn host_key_file_hmac(key_bytes: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(HOST_KEY_HMAC_CONTEXT)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(HOST_KEY_MAGIC);
    mac.update(key_bytes);
    mac.finalize().into_bytes().into()
}

/// Verifies the HMAC-SHA256 integrity tag of a host key file (constant-time).
fn verify_host_key_file_hmac(key_bytes: &[u8; 32], stored_tag: &[u8]) -> bool {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(HOST_KEY_HMAC_CONTEXT)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(HOST_KEY_MAGIC);
    mac.update(key_bytes);
    mac.verify_slice(stored_tag).is_ok()
}

/// Loads the previous host key from `HEARTH_PREVIOUS_MASTER_KEY`, if set.
fn load_previous_host_key() -> Result<Option<HostKey>, StorageError> {
    let Ok(env_val) = std::env::var("HEARTH_PREVIOUS_MASTER_KEY") else {
        return Ok(None);
    };
    let env_val = env_val.trim().to_owned();
    if env_val.len() == 64 {
        let bytes = decode_hex(&env_val).map_err(|_| StorageError::Crypto {
            reason: "HEARTH_PREVIOUS_MASTER_KEY is not valid hex".to_string(),
        })?;
        return Ok(Some(HostKey::from_bytes(bytes)));
    }
    Err(StorageError::Crypto {
        reason: "HEARTH_PREVIOUS_MASTER_KEY must be 64 hex chars".to_string(),
    })
}

/// Rewrites `hearth.keys` atomically with all KEKs encrypted under `host_key`.
///
/// Uses write-to-tmp → fsync → rename to guarantee crash safety.
/// Returns an open append handle to the rewritten file.
fn rewrite_keys_file(
    path: &Path,
    keks: &KekMap,
    host_key: &HostKey,
    fs: &dyn Fs,
) -> Result<Box<dyn crate::storage::fs::FsFile>, StorageError> {
    let mut content = Vec::new();
    content.extend_from_slice(&KEY_FILE_VERSION.to_le_bytes());

    for (realm_id, kek) in keks {
        let kek_id: KekId = {
            let mut id = [0u8; KEK_ID_SIZE];
            id.copy_from_slice(realm_id.as_uuid().as_bytes());
            id
        };
        let encrypted = encrypt_kek(kek, host_key, kek_id)?;
        #[allow(clippy::cast_possible_truncation)]
        let entry_len = encrypted.len() as u32;

        let mut entry = Vec::with_capacity(16 + 4 + encrypted.len() + 4);
        entry.extend_from_slice(realm_id.as_uuid().as_bytes());
        entry.extend_from_slice(&entry_len.to_le_bytes());
        entry.extend_from_slice(&encrypted);
        let crc = crc32fast::hash(&entry);
        entry.extend_from_slice(&crc.to_le_bytes());
        content.extend_from_slice(&entry);
    }

    let parent = path.parent().unwrap_or(Path::new("."));
    let tmp_path = parent.join("hearth.keys.tmp");

    {
        let mut tmp_file = fs.create(&tmp_path)?;
        tmp_file.write_all(&content)?;
        tmp_file.sync_all()?;
    }

    fs.rename(&tmp_path, path)?;
    Ok(fs.open_append(path)?)
}

/// Loads realm KEKs from `hearth.keys` with CRC32 integrity verification.
///
/// If decryption fails with `host_key` and `prev_host_key` is provided,
/// falls back to the previous key. Realms decrypted via the fallback are
/// recorded in `needs_reencrypt`; realms that fail both keys go to `failed`.
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
fn load_keks_from_file(
    path: &Path,
    host_key: &HostKey,
    prev_host_key: Option<&HostKey>,
    fs: &dyn Fs,
) -> Result<LoadKeksResult, StorageError> {
    let data = fs.read(path)?;

    // File must have at least version header + one entry
    if data.len() < KEY_FILE_VERSION_SIZE {
        return Ok(LoadKeksResult::empty());
    }

    let version = u16::from_le_bytes(data[..KEY_FILE_VERSION_SIZE].try_into().map_err(|_| {
        StorageError::Crypto {
            reason: "truncated version in hearth.keys".to_string(),
        }
    })?);
    if version != KEY_FILE_VERSION {
        return Err(StorageError::Crypto {
            reason: format!("unsupported hearth.keys version: {version}"),
        });
    }

    let mut result = LoadKeksResult::empty();
    let mut pos = KEY_FILE_VERSION_SIZE;

    while pos + 20 + 4 <= data.len() {
        let entry_start = pos;

        // Read realm UUID (16 bytes)
        let uuid_bytes: [u8; 16] =
            data[pos..pos + 16]
                .try_into()
                .map_err(|_| StorageError::Crypto {
                    reason: "truncated realm UUID in hearth.keys".to_string(),
                })?;
        let realm_id = RealmId::new(uuid::Uuid::from_bytes(uuid_bytes));
        pos += 16;

        // Read entry length (4 bytes, u32 LE)
        if pos + 4 > data.len() {
            break;
        }
        let entry_len =
            u32::from_le_bytes(
                data[pos..pos + 4]
                    .try_into()
                    .map_err(|_| StorageError::Crypto {
                        reason: "invalid entry length in hearth.keys".to_string(),
                    })?,
            ) as usize;
        pos += 4;

        // Read encrypted KEK
        if pos + entry_len > data.len() {
            break;
        }
        pos += entry_len; // bytes consumed (we reference the slice below)

        // Read CRC32 (4 bytes)
        if pos + 4 > data.len() {
            break;
        }
        let stored_crc = u32::from_le_bytes(data[pos..pos + 4].try_into().map_err(|_| {
            StorageError::Crypto {
                reason: "truncated CRC in hearth.keys".to_string(),
            }
        })?);
        pos += 4;

        // Verify CRC32 over [UUID(16)][length(4)][encrypted(N)]
        let entry_bytes = &data[entry_start..pos - 4];
        let computed_crc = crc32fast::hash(entry_bytes);
        if stored_crc != computed_crc {
            // Promote to corrupted — do NOT silently skip. Startup will be blocked
            // so the operator knows this realm's SSTs are unreadable, not just
            // mysteriously absent. (STOR-004 / HEA-SEC-26)
            tracing::error!(
                realm_id = %realm_id,
                "hearth.keys: CRC mismatch for entry; data integrity compromised — \
                 startup will be blocked; restore hearth.keys from backup"
            );
            result.corrupted.push(realm_id);
            continue;
        }

        // Try current host key first; fall back to previous host key on failure.
        let encrypted_kek = &data[entry_start + 16 + 4..entry_start + 16 + 4 + entry_len];
        let kek_id: KekId = {
            let mut id = [0u8; KEK_ID_SIZE];
            id.copy_from_slice(realm_id.as_uuid().as_bytes());
            id
        };
        match decrypt_kek(encrypted_kek, host_key, kek_id) {
            Ok(kek) => {
                // Last entry for a realm wins (supports rotation).
                result.keks.insert(realm_id, kek);
            }
            Err(_) => {
                // Current key failed — try previous key if provided.
                if let Some(prev_key) = prev_host_key {
                    match decrypt_kek(encrypted_kek, prev_key, kek_id) {
                        Ok(kek) => {
                            tracing::info!(
                                realm_id = %realm_id,
                                "decrypted KEK with previous host key; will re-encrypt"
                            );
                            result.needs_reencrypt.push(realm_id.clone());
                            result.keks.insert(realm_id, kek);
                        }
                        Err(_) => {
                            tracing::error!(
                                realm_id = %realm_id,
                                "hearth.keys: KEK cannot be decrypted with current or previous key"
                            );
                            result.failed.push(realm_id);
                        }
                    }
                } else {
                    tracing::error!(
                        realm_id = %realm_id,
                        "hearth.keys: KEK cannot be decrypted with current key; \
                         set HEARTH_PREVIOUS_MASTER_KEY if you rotated the master key"
                    );
                    result.failed.push(realm_id);
                }
            }
        }
    }

    Ok(result)
}

/// Decodes a hex string into a 32-byte array.
fn decode_hex(s: &str) -> Result<[u8; 32], ()> {
    if s.len() != 64 {
        return Err(());
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(chunk.first().copied().unwrap_or(b'0'))?;
        let lo = hex_val(chunk.get(1).copied().unwrap_or(b'0'))?;
        bytes[i] = (hi << 4) | lo;
    }
    Ok(bytes)
}

fn hex_val(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::RealmId;

    #[test]
    fn key_registry_ensure_kek_creates_and_retrieves() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = KeyRegistry::load(dir.path(), true).expect("load");

        let realm = RealmId::generate();
        let kek = registry.ensure_kek_for_realm(&realm).expect("ensure kek");

        let retrieved = registry.get_kek_for_realm(&realm).expect("get kek");
        assert_eq!(kek.as_bytes(), retrieved.as_bytes());
    }

    #[test]
    fn key_registry_persists_across_reload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Create realm KEK
        {
            let registry = KeyRegistry::load(dir.path(), true).expect("load");
            let kek = registry.ensure_kek_for_realm(&realm).expect("ensure kek");
            let retrieved = registry.get_kek_for_realm(&realm).expect("get kek");
            assert_eq!(kek.as_bytes(), retrieved.as_bytes());
        }

        // Re-load and verify KEK survives
        {
            let registry = KeyRegistry::load(dir.path(), true).expect("reload");
            let kek = registry
                .get_kek_for_realm(&realm)
                .expect("should have kek after reload");
            assert_eq!(kek.as_bytes().len(), 32);
        }
    }

    #[test]
    fn key_registry_rotate_kek_produces_new_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = KeyRegistry::load(dir.path(), true).expect("load");
        let realm = RealmId::generate();

        let kek1 = registry.ensure_kek_for_realm(&realm).expect("ensure");

        let (old_kek, new_kek) = registry.rotate_kek(&realm).expect("rotate");

        assert_eq!(old_kek.as_bytes(), kek1.as_bytes());
        assert_ne!(new_kek.as_bytes(), kek1.as_bytes());

        let retrieved = registry
            .get_kek_for_realm(&realm)
            .expect("get after rotate");
        assert_eq!(retrieved.as_bytes(), new_kek.as_bytes());
    }

    #[test]
    fn key_registry_different_realms_have_different_keks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = KeyRegistry::load(dir.path(), true).expect("load");

        let realm1 = RealmId::generate();
        let realm2 = RealmId::generate();

        let kek1 = registry.ensure_kek_for_realm(&realm1).expect("ensure 1");
        let kek2 = registry.ensure_kek_for_realm(&realm2).expect("ensure 2");

        assert_ne!(kek1.as_bytes(), kek2.as_bytes());
    }

    #[test]
    fn key_registry_kek_id_matches_realm_uuid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = KeyRegistry::load(dir.path(), true).expect("load");
        let realm = RealmId::generate();

        let expected_kek_id: KekId = {
            let mut id = [0u8; KEK_ID_SIZE];
            id.copy_from_slice(realm.as_uuid().as_bytes());
            id
        };
        let actual_kek_id = registry.kek_id_for_realm(&realm);

        assert_eq!(expected_kek_id, actual_kek_id);
    }

    #[test]
    fn key_registry_crc_corruption_blocks_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Create a valid KEK
        {
            let registry = KeyRegistry::load(dir.path(), true).expect("load");
            registry.ensure_kek_for_realm(&realm).expect("ensure");
        }

        // Corrupt the CRC of the last entry
        {
            let key_file = dir.path().join("hearth.keys");
            let mut data = std::fs::read(&key_file).expect("read keys");
            // Corrupt last 4 bytes (CRC)
            let len = data.len();
            data[len - 1] ^= 0xFF;
            data[len - 2] ^= 0xFF;
            std::fs::write(&key_file, &data).expect("write corrupt");
        }

        // Re-load: CRC corruption MUST block startup (not silently skip).
        let err = KeyRegistry::load(dir.path(), true)
            .expect_err("CRC-corrupt KEK entry must block startup");
        match err {
            StorageError::CorruptedKeks { affected_realms } => {
                assert!(
                    !affected_realms.is_empty(),
                    "affected_realms must name at least one realm"
                );
            }
            other => panic!("expected StorageError::CorruptedKeks, got: {other:?}"),
        }
    }

    #[test]
    fn key_registry_partial_write_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Create a valid KEK
        {
            let registry = KeyRegistry::load(dir.path(), true).expect("load");
            registry.ensure_kek_for_realm(&realm).expect("ensure");
        }

        // Truncate the file to simulate partial write (cut CRC in half)
        {
            let key_file = dir.path().join("hearth.keys");
            let data = std::fs::read(&key_file).expect("read keys");
            // Truncate last 2 bytes
            let truncated = &data[..data.len() - 2];
            std::fs::write(&key_file, truncated).expect("write truncated");
        }

        // Re-load: truncated entry should be skipped (incomplete CRC)
        {
            let registry = KeyRegistry::load(dir.path(), true).expect("reload");
            assert!(
                registry.get_kek_for_realm(&realm).is_none(),
                "truncated entry should be skipped"
            );
        }
    }

    // ── Host key rotation tests ───────────────────────────────────────────────

    fn make_test_key_bytes() -> [u8; 32] {
        use crate::storage::encryption::generate_host_key;
        *generate_host_key().expect("generate host key").as_bytes()
    }

    fn mk(bytes: [u8; 32]) -> HostKey {
        HostKey::from_bytes(bytes)
    }

    fn load_with_two_keys(
        dir: &std::path::Path,
        current: [u8; 32],
        previous: Option<[u8; 32]>,
    ) -> Result<KeyRegistry, StorageError> {
        KeyRegistry::load_with_keys(
            dir,
            Arc::new(crate::storage::fs::RealFs),
            mk(current),
            previous.map(mk),
        )
    }

    #[test]
    fn host_key_rotation_re_encrypts_keks_and_new_key_works_standalone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let key1 = make_test_key_bytes();
        let key2 = make_test_key_bytes();

        // Record the KEK value under key1 so we can compare after rotation.
        let original_kek_bytes = {
            let registry = load_with_two_keys(dir.path(), key1, None).expect("load1");
            let kek = registry.ensure_kek_for_realm(&realm).expect("ensure");
            kek.as_bytes().to_vec()
        };

        // Load with key2 (current) + key1 (previous) → auto re-encrypts.
        {
            let registry =
                load_with_two_keys(dir.path(), key2, Some(key1)).expect("load with rotation");
            let kek = registry
                .get_kek_for_realm(&realm)
                .expect("kek accessible during rotation");
            assert_eq!(
                kek.as_bytes(),
                original_kek_bytes.as_slice(),
                "KEK value unchanged after re-encryption"
            );
        }

        // Load with key2 alone (no previous) → succeeds because file was rewritten.
        {
            let registry = load_with_two_keys(dir.path(), key2, None).expect("load after rewrite");
            let kek = registry
                .get_kek_for_realm(&realm)
                .expect("kek accessible after re-encryption");
            assert_eq!(
                kek.as_bytes(),
                original_kek_bytes.as_slice(),
                "KEK value unchanged after standalone reload"
            );
        }
    }

    #[test]
    fn host_key_rotation_missing_previous_key_blocks_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let key1 = make_test_key_bytes();
        let key2 = make_test_key_bytes();

        // Create realm KEK under key1.
        {
            let registry = load_with_two_keys(dir.path(), key1, None).expect("load1");
            registry.ensure_kek_for_realm(&realm).expect("ensure");
        }

        // Load with key2 but no previous key → must fail with HostKeyMismatch.
        let err = load_with_two_keys(dir.path(), key2, None)
            .expect_err("should block startup when previous key is missing");
        match err {
            StorageError::HostKeyMismatch { affected_realms } => {
                assert!(
                    !affected_realms.is_empty(),
                    "affected_realms must name at least one realm"
                );
            }
            other => panic!("expected HostKeyMismatch, got: {other:?}"),
        }
    }

    #[test]
    fn host_key_rotation_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let key1 = make_test_key_bytes();
        let key2 = make_test_key_bytes();

        // Create KEK under key1.
        {
            let registry = load_with_two_keys(dir.path(), key1, None).expect("load1");
            registry.ensure_kek_for_realm(&realm).expect("ensure");
        }

        // First rotation: key2 + key1 as previous.
        let kek_after_first = {
            let registry = load_with_two_keys(dir.path(), key2, Some(key1)).expect("rotation 1");
            registry
                .get_kek_for_realm(&realm)
                .expect("kek after rotation 1")
                .as_bytes()
                .to_vec()
        };

        // Second load with same key2, no previous → idempotent (file already rewritten).
        {
            let registry = load_with_two_keys(dir.path(), key2, None).expect("idempotent reload");
            let kek = registry
                .get_kek_for_realm(&realm)
                .expect("kek on second load");
            assert_eq!(
                kek.as_bytes(),
                kek_after_first.as_slice(),
                "KEK unchanged on second load"
            );
        }
    }

    #[test]
    fn host_key_rotation_crc_corrupt_entries_block_startup_not_host_key_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let key1 = make_test_key_bytes();
        let key2 = make_test_key_bytes();

        // Create KEK under key1.
        {
            let registry = load_with_two_keys(dir.path(), key1, None).expect("load");
            registry.ensure_kek_for_realm(&realm).expect("ensure");
        }

        // Corrupt the CRC of the entry.
        {
            let key_file = dir.path().join("hearth.keys");
            let mut data = std::fs::read(&key_file).expect("read");
            let len = data.len();
            data[len - 1] ^= 0xFF;
            std::fs::write(&key_file, &data).expect("write corrupt");
        }

        // CRC-corrupt entry must produce CorruptedKeks, NOT HostKeyMismatch
        // (the entry is corrupt before decryption is even attempted).
        let err = load_with_two_keys(dir.path(), key2, None)
            .expect_err("CRC-corrupt entry must block startup");
        match err {
            StorageError::CorruptedKeks { affected_realms } => {
                assert!(
                    !affected_realms.is_empty(),
                    "affected_realms must name at least one realm"
                );
            }
            StorageError::HostKeyMismatch { .. } => {
                panic!("CRC-corrupt entries must not be misreported as HostKeyMismatch")
            }
            other => panic!("expected StorageError::CorruptedKeks, got: {other:?}"),
        }
    }

    #[test]
    fn host_key_rotation_multi_realm_partial_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();
        let key1 = make_test_key_bytes();
        let key2 = make_test_key_bytes();
        let key3 = make_test_key_bytes();

        // realm_a under key1.
        {
            let registry = load_with_two_keys(dir.path(), key1, None).expect("a");
            registry.ensure_kek_for_realm(&realm_a).expect("ensure a");
        }
        // Rotate key1→key2; add realm_b under key2.
        {
            let registry = load_with_two_keys(dir.path(), key2, Some(key1)).expect("b");
            registry.ensure_kek_for_realm(&realm_b).expect("ensure b");
        }

        // Now load with key3 + no previous: both realms fail → HostKeyMismatch.
        let err = load_with_two_keys(dir.path(), key3, None).expect_err("both realms should fail");
        match err {
            StorageError::HostKeyMismatch { affected_realms } => {
                assert_eq!(affected_realms.len(), 2, "both realms should be reported");
            }
            other => panic!("expected HostKeyMismatch, got: {other:?}"),
        }
    }

    // ── HEA-SEC-26 security regression tests ─────────────────────────────────

    #[test]
    fn host_key_file_truncated_to_32_bytes_is_rejected() {
        // STOR-003: a legacy 32-byte raw key file must be rejected at startup;
        // only the [magic][key][HMAC] = 72-byte format is accepted.
        let dir = tempfile::tempdir().expect("tempdir");

        // Generate a valid registry (creates the 72-byte framed host key file).
        {
            let _r = KeyRegistry::load(dir.path(), true).expect("initial load");
        }

        // Overwrite with a 32-byte raw key (the old format / accidental truncation).
        {
            let hk_path = dir.path().join("hearth.host_key");
            let raw = [0xABu8; 32];
            // write_host_key_private uses create_new, so remove first.
            std::fs::remove_file(&hk_path).expect("remove");
            std::fs::write(&hk_path, raw).expect("write truncated");
        }

        let err =
            KeyRegistry::load(dir.path(), true).expect_err("32-byte raw host key must be rejected");
        match err {
            StorageError::Crypto { reason } => {
                assert!(
                    reason.contains("unexpected length") || reason.contains("magic"),
                    "error should mention length or magic, got: {reason}"
                );
            }
            other => panic!("expected StorageError::Crypto, got: {other:?}"),
        }
    }

    #[test]
    fn host_key_file_corrupt_bytes_rejected_via_hmac() {
        // STOR-003: flipping any byte within the key region must invalidate the HMAC.
        let dir = tempfile::tempdir().expect("tempdir");

        {
            let _r = KeyRegistry::load(dir.path(), true).expect("initial load");
        }

        {
            let hk_path = dir.path().join("hearth.host_key");
            let mut data = std::fs::read(&hk_path).expect("read");
            data[10] ^= 0xFF; // corrupt a key byte (positions 8..40)
            std::fs::write(&hk_path, &data).expect("write corrupt");
        }

        let err =
            KeyRegistry::load(dir.path(), true).expect_err("corrupted host key must be rejected");
        match err {
            StorageError::Crypto { reason } => {
                assert!(
                    reason.contains("HMAC"),
                    "error must mention HMAC integrity, got: {reason}"
                );
            }
            other => panic!("expected StorageError::Crypto, got: {other:?}"),
        }
    }

    #[test]
    fn host_key_file_wrong_magic_rejected() {
        // STOR-003: wrong magic header must be caught before HMAC check.
        let dir = tempfile::tempdir().expect("tempdir");

        {
            let _r = KeyRegistry::load(dir.path(), true).expect("initial load");
        }

        {
            let hk_path = dir.path().join("hearth.host_key");
            let mut data = std::fs::read(&hk_path).expect("read");
            data[0] ^= 0xFF; // corrupt the magic header
            std::fs::write(&hk_path, &data).expect("write corrupt");
        }

        let err = KeyRegistry::load(dir.path(), true).expect_err("wrong magic must be rejected");
        match err {
            StorageError::Crypto { reason } => {
                assert!(
                    reason.contains("magic"),
                    "error must mention magic header, got: {reason}"
                );
            }
            other => panic!("expected StorageError::Crypto, got: {other:?}"),
        }
    }

    #[test]
    fn crc_corrupt_kek_entry_blocks_startup_with_named_realm() {
        // STOR-004: a CRC-corrupt KEK entry must block startup and name the realm,
        // not cause silent availability degradation.
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        {
            let registry = KeyRegistry::load(dir.path(), true).expect("load");
            registry.ensure_kek_for_realm(&realm).expect("ensure");
        }

        // Corrupt the CRC of the KEK entry (last 4 bytes of the file).
        {
            let key_file = dir.path().join("hearth.keys");
            let mut data = std::fs::read(&key_file).expect("read keys");
            let len = data.len();
            data[len - 1] ^= 0xFF;
            std::fs::write(&key_file, &data).expect("write corrupt");
        }

        let err =
            KeyRegistry::load(dir.path(), true).expect_err("CRC-corrupt KEK must block startup");
        match err {
            StorageError::CorruptedKeks { affected_realms } => {
                assert_eq!(affected_realms.len(), 1, "exactly one realm is corrupt");
                // The realm ID string must appear so operators can identify affected data.
                assert!(
                    !affected_realms[0].is_empty(),
                    "affected realm must be identified"
                );
            }
            other => panic!("expected StorageError::CorruptedKeks, got: {other:?}"),
        }
    }

    // ── F7 security regression tests ─────────────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn host_key_file_written_with_0o600_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let _registry = KeyRegistry::load(dir.path(), true).expect("load in dev mode");
        let key_path = dir.path().join("hearth.host_key");
        assert!(
            key_path.exists(),
            "hearth.host_key must be created on auto-gen"
        );
        let mode = std::fs::metadata(&key_path)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "hearth.host_key must be 0o600, got 0o{mode:o}");
    }

    #[test]
    fn production_mode_refuses_autogenerated_host_key() {
        if std::env::var("HEARTH_MASTER_KEY").is_ok() {
            return; // skip when env var is already set
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let err = KeyRegistry::load(dir.path(), false)
            .expect_err("production mode must refuse without HEARTH_MASTER_KEY");
        match err {
            StorageError::Crypto { reason } => {
                assert!(
                    reason.contains("HEARTH_MASTER_KEY"),
                    "error must mention HEARTH_MASTER_KEY, got: {reason}"
                );
            }
            other => panic!("expected StorageError::Crypto, got: {other:?}"),
        }
        assert!(
            !dir.path().join("hearth.host_key").exists(),
            "host_key file must NOT be written on refused production start-up"
        );
    }
}
