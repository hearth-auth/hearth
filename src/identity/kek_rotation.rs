//! Rotation of the key-encryption key (`HEARTH_KEK`) at a restart (#649).
//!
//! The KEK wraps every stored key (signing keys, SAML and ID-token keys, the
//! MFA data key, the DPoP nonce secret and the audit chain key) in the HKEY
//! envelope. To rotate it, an operator stops the server and starts it with
//! the new value in `HEARTH_KEK` and the old value in `HEARTH_PREVIOUS_KEK`.
//! Before any engine opens the store, [`rotate_key_encryption_key`] wraps
//! again under the new KEK every stored key that does not open under it.
//!
//! The rotation is idempotent: a key that opens under the new KEK is left as
//! it is. A crash part way through leaves some keys under each KEK, and the
//! next start with both values finishes the work.

use std::sync::Arc;

use crate::core::RealmId;
use crate::identity::key_encryption::{is_enveloped, unwrap_key, wrap_key, StorageKek};
use crate::identity::{keys, IdentityError};
use crate::storage::{StorageEngine, StorageError};

/// The environment variable that holds the previous KEK during a rotation.
pub const PREVIOUS_KEK_ENV: &str = "HEARTH_PREVIOUS_KEK";

/// One stored key that the KEK wraps: where it lives and its stored bytes.
pub(crate) struct StoredKey {
    /// The realm namespace of the storage key.
    pub(crate) realm: RealmId,
    /// The storage key.
    pub(crate) key: Vec<u8>,
    /// The stored bytes (HKEY envelope, or plaintext before enrollment).
    pub(crate) value: Vec<u8>,
}

/// Every stored key of every family that the KEK wraps.
///
/// - System-realm keys: `sys:global:key`, `realm:key:*`, `realm:retiring:*`,
///   `realm:saml_key:*`, `realm:idtoken_rsa:*` and
///   `realm:idtoken_rsa_retiring:*`.
/// - Per-realm keys, in each realm's own namespace: the DPoP nonce secret,
///   the MFA data key and the audit chain key. Three point reads per realm.
///
/// The KEK enrollment pass and the rotation both use this list, so a new
/// family of stored key goes here once.
pub(crate) fn stored_keys(storage: &dyn StorageEngine) -> Result<Vec<StoredKey>, StorageError> {
    let sys_realm = keys::system_realm_id();
    let mut found = Vec::new();

    let global = keys::encode_global_signing_key();
    if let Some(value) = storage.get(&sys_realm, &global)? {
        found.push(StoredKey {
            realm: sys_realm.clone(),
            key: global,
            value,
        });
    }
    for prefix in [
        keys::realm_signing_key_scan_prefix(),
        keys::realm_retiring_key_all_scan_prefix(),
        keys::realm_saml_key_scan_prefix(),
        keys::realm_id_token_rsa_key_scan_prefix(),
        keys::realm_id_token_rsa_retiring_all_scan_prefix(),
    ] {
        let end = keys::prefix_end(&prefix);
        for entry in storage.scan(&sys_realm, &prefix, &end)? {
            found.push(StoredKey {
                realm: sys_realm.clone(),
                key: entry.key,
                value: entry.value,
            });
        }
    }

    let per_realm_keys = [
        keys::dpop_nonce_secret_key(),
        keys::mfa_dek_key(),
        crate::audit::keys::audit_hmac_key(),
    ];
    for realm in storage.list_realms()? {
        for key in &per_realm_keys {
            if let Some(value) = storage.get(&realm, key)? {
                found.push(StoredKey {
                    realm: realm.clone(),
                    key: key.clone(),
                    value,
                });
            }
        }
    }
    Ok(found)
}

/// Wraps every stored key again under `kek`, when it opens only under
/// `previous`. Returns the number of keys written.
///
/// It decrypts every key that needs it before it writes one, so a refusal
/// writes nothing. Plaintext keys (a store not yet enrolled) are left to the
/// enrollment pass of the identity engine.
///
/// # Errors
///
/// Returns [`IdentityError::Internal`], which names [`PREVIOUS_KEK_ENV`],
/// when a stored key does not open under `kek` and `previous` is `None` or
/// does not open it either. Returns [`IdentityError::Storage`] on a storage
/// error.
pub fn rotate_key_encryption_key(
    storage: &Arc<dyn StorageEngine>,
    kek: &StorageKek,
    previous: Option<&StorageKek>,
) -> Result<usize, IdentityError> {
    let storage_err = |e: StorageError| IdentityError::Storage(Box::new(e));
    let mut writes: Vec<(RealmId, Vec<u8>, Vec<u8>)> = Vec::new();
    for stored in stored_keys(storage.as_ref()).map_err(storage_err)? {
        if !is_enveloped(&stored.value) || unwrap_key(&stored.value, Some(kek.as_bytes())).is_ok() {
            continue;
        }
        let Some(previous) = previous else {
            return Err(IdentityError::Internal {
                reason: format!(
                    "a stored key does not open under HEARTH_KEK. If you changed HEARTH_KEK, \
                     start once with the old value in {PREVIOUS_KEK_ENV} to rotate the store \
                     (docs/guides/config-migration.md)"
                ),
            });
        };
        let plaintext = unwrap_key(&stored.value, Some(previous.as_bytes())).map_err(|_| {
            IdentityError::Internal {
                reason: format!(
                    "a stored key opens under neither HEARTH_KEK nor {PREVIOUS_KEK_ENV}; \
                         nothing was rotated. Check that {PREVIOUS_KEK_ENV} holds the value \
                         that HEARTH_KEK had before"
                ),
            }
        })?;
        let wrapped = wrap_key(&plaintext, Some(kek.as_bytes()))?;
        writes.push((stored.realm, stored.key, wrapped));
    }

    for (realm, key, value) in &writes {
        storage.put(realm, key, value).map_err(storage_err)?;
    }
    if writes.is_empty() {
        if previous.is_some() {
            tracing::warn!(
                "{PREVIOUS_KEK_ENV} is set, but every stored key opens under HEARTH_KEK; \
                 remove {PREVIOUS_KEK_ENV}"
            );
        }
    } else {
        tracing::info!(
            rewrapped = writes.len(),
            "key_encryption_key rotated: every stored key is wrapped under HEARTH_KEK; remove \
             {PREVIOUS_KEK_ENV}"
        );
    }
    Ok(writes.len())
}
