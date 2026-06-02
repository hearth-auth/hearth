//! Backup export engine — [`BackupExporter`].
//!
//! Walks all realm entities through the identity, audit, and RBAC engine
//! interfaces and serialises them to NDJSON streams inside a
//! [`BackupArchive`](super::BackupArchive).
//!
//! # Usage
//!
//! ```no_run
//! use std::path::Path;
//! use std::sync::Arc;
//! use hearth::backup::{BackupArchive, BackupManifest, BackupExporter, ExportOptions};
//! use hearth::core::RealmId;
//! use hearth::identity::IdentityEngine;
//! use hearth::audit::AuditEngine;
//! use hearth::rbac::RbacEngine;
//!
//! fn run(
//!     identity: Arc<dyn IdentityEngine>,
//!     audit: Arc<dyn AuditEngine>,
//!     rbac: Arc<dyn RbacEngine>,
//!     realm_id: &RealmId,
//! ) {
//!     let path = Path::new("backup.hearth-backup");
//!     let mut writer = BackupArchive::create(path).unwrap();
//!     let exporter = BackupExporter::new(identity, audit, rbac);
//!     let dek = BackupExporter::generate_dek().unwrap();
//!     let opts = ExportOptions::default();
//!     let realm_manifest = exporter.export_realm(realm_id, &mut writer, &opts, &dek).unwrap();
//!     let mut manifest = BackupManifest::new(vec![realm_manifest]);
//!     manifest.signing_key_dek_b64 = Some(base64::engine::general_purpose::STANDARD.encode(dek));
//!     writer.finish(manifest).unwrap();
//! }
//! ```

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use tracing::instrument;
use zeroize::Zeroizing;

use crate::audit::{AuditEngine, AuditQuery};
use crate::core::RealmId;
use crate::identity::IdentityEngine;
use crate::rbac::RbacEngine;

use super::{ArchiveWriter, BackupError, RealmManifest, RecordCounts};

/// Options controlling what gets included in a realm export.
#[derive(Clone, Debug, Default)]
pub struct ExportOptions {
    /// Include audit events in the export. Audit logs can be very large; omit
    /// for routine operational backups and include only for compliance exports.
    pub include_audit: bool,
    /// Restrict export to these realm IDs. When `None`, all realms are included.
    /// Currently used by callers to filter the realm list before calling
    /// [`BackupExporter::export_realm`].
    pub realm_filter: Option<Vec<RealmId>>,
}

/// Walks realm entities through engine interfaces and serialises them to
/// NDJSON streams inside a [`BackupArchive`](super::BackupArchive).
///
/// Construct with [`new`](Self::new), then call [`export_realm`](Self::export_realm)
/// once per realm. Generate a single DEK with [`generate_dek`](Self::generate_dek)
/// and reuse it for all `export_realm` calls in the same archive; store it
/// (base64-encoded) in [`BackupManifest::signing_key_dek_b64`].
pub struct BackupExporter {
    identity: Arc<dyn IdentityEngine>,
    audit: Arc<dyn AuditEngine>,
    rbac: Arc<dyn RbacEngine>,
}

impl BackupExporter {
    /// Constructs a new exporter backed by the given engine references.
    pub fn new(
        identity: Arc<dyn IdentityEngine>,
        audit: Arc<dyn AuditEngine>,
        rbac: Arc<dyn RbacEngine>,
    ) -> Self {
        Self {
            identity,
            audit,
            rbac,
        }
    }

    /// Generates a fresh random 32-byte Data Encryption Key.
    ///
    /// Generate once per archive and pass the same key to every
    /// [`export_realm`](Self::export_realm) call. Store the base64-encoded
    /// result in [`BackupManifest::signing_key_dek_b64`].
    pub fn generate_dek() -> Result<[u8; 32], BackupError> {
        let mut bytes = [0u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| BackupError::Crypto("DEK generation failed".into()))?;
        Ok(bytes)
    }

    /// Exports all entities for `realm_id` into `writer`.
    ///
    /// Writes one NDJSON file per entity type (users, credentials, clients,
    /// roles, groups, permissions, scopes, assignments, organizations) plus an
    /// AES-256-GCM encrypted `signing_key.json` and, when `opts.include_audit`
    /// is true, an `audit.ndjson` file.
    ///
    /// `signing_key_dek` is a 32-byte key used to encrypt the realm's PKCS#8
    /// signing key. Reuse the same key (produced by [`generate_dek`](Self::generate_dek))
    /// across all realms in one archive.
    ///
    /// Returns a [`RealmManifest`] with record counts that the caller embeds
    /// into [`BackupManifest::realms`].
    #[instrument(skip(self, writer, opts, signing_key_dek), fields(realm = %realm_id))]
    #[allow(clippy::too_many_lines)] // TODO: split this function
    pub fn export_realm(
        &self,
        realm_id: &RealmId,
        writer: &mut ArchiveWriter,
        opts: &ExportOptions,
        signing_key_dek: &[u8; 32],
    ) -> Result<RealmManifest, BackupError> {
        let realm = self
            .identity
            .get_realm(realm_id)
            .map_err(|e| BackupError::Engine(e.to_string()))?;
        let slug = realm
            .as_ref()
            .map(|r| slugify(r.name()))
            .unwrap_or_else(|| realm_id.as_uuid().to_string());
        let prefix = format!("realms/{slug}");
        let mut counts = RecordCounts::default();

        // realm.json
        if let Some(ref r) = realm {
            let data = serde_json::to_vec_pretty(r)?;
            writer.add_file(&format!("{prefix}/realm.json"), &data)?;
        }

        // users.ndjson
        let users = self.export_paginated(|cursor| {
            self.identity
                .list_users(realm_id, cursor, 500)
                .map(|p| (p.items, p.next_cursor))
                .map_err(|e| BackupError::Engine(e.to_string()))
        })?;
        counts.users = users.len() as u64;
        if !users.is_empty() {
            let data = to_ndjson(&users)?;
            writer.add_file(&format!("{prefix}/users.ndjson"), &data)?;
        }

        // credentials.ndjson
        let credentials = self
            .identity
            .export_all_credentials(realm_id)
            .map_err(|e| BackupError::Engine(e.to_string()))?;
        counts.credentials = credentials.len() as u64;
        if !credentials.is_empty() {
            let data = to_ndjson(&credentials)?;
            writer.add_file(&format!("{prefix}/credentials.ndjson"), &data)?;
        }

        // clients.ndjson
        let clients = self.export_paginated(|cursor| {
            self.identity
                .list_clients(realm_id, cursor, 500)
                .map(|p| (p.items, p.next_cursor))
                .map_err(|e| BackupError::Engine(e.to_string()))
        })?;
        counts.clients = clients.len() as u64;
        if !clients.is_empty() {
            let data = to_ndjson(&clients)?;
            writer.add_file(&format!("{prefix}/clients.ndjson"), &data)?;
        }

        // roles.ndjson
        let roles = self.export_paginated(|cursor| {
            self.rbac
                .list_roles(realm_id, cursor, 500)
                .map(|p| (p.items, p.next_cursor))
                .map_err(|e| BackupError::Engine(e.to_string()))
        })?;
        counts.roles = roles.len() as u64;
        if !roles.is_empty() {
            let data = to_ndjson(&roles)?;
            writer.add_file(&format!("{prefix}/roles.ndjson"), &data)?;
        }

        // permissions.ndjson
        let permissions = self
            .rbac
            .export_all_permissions(realm_id)
            .map_err(|e| BackupError::Engine(e.to_string()))?;
        counts.permissions = permissions.len() as u64;
        if !permissions.is_empty() {
            let data = to_ndjson(&permissions)?;
            writer.add_file(&format!("{prefix}/permissions.ndjson"), &data)?;
        }

        // groups.ndjson
        let groups = self.export_paginated(|cursor| {
            self.rbac
                .list_groups(realm_id, cursor, 500)
                .map(|p| (p.items, p.next_cursor))
                .map_err(|e| BackupError::Engine(e.to_string()))
        })?;
        counts.groups = groups.len() as u64;
        if !groups.is_empty() {
            let data = to_ndjson(&groups)?;
            writer.add_file(&format!("{prefix}/groups.ndjson"), &data)?;
        }

        // assignments.ndjson
        let assignments = self
            .rbac
            .export_all_assignments(realm_id)
            .map_err(|e| BackupError::Engine(e.to_string()))?;
        counts.assignments = assignments.len() as u64;
        if !assignments.is_empty() {
            let data = to_ndjson(&assignments)?;
            writer.add_file(&format!("{prefix}/assignments.ndjson"), &data)?;
        }

        // scopes.ndjson
        let scopes = self
            .rbac
            .export_all_scopes(realm_id)
            .map_err(|e| BackupError::Engine(e.to_string()))?;
        counts.scopes = scopes.len() as u64;
        if !scopes.is_empty() {
            let data = to_ndjson(&scopes)?;
            writer.add_file(&format!("{prefix}/scopes.ndjson"), &data)?;
        }

        // organizations.ndjson
        let organizations = self.export_paginated(|cursor| {
            self.identity
                .list_organizations(realm_id, cursor, 500)
                .map(|p| (p.items, p.next_cursor))
                .map_err(|e| BackupError::Engine(e.to_string()))
        })?;
        counts.organizations = organizations.len() as u64;
        if !organizations.is_empty() {
            let data = to_ndjson(&organizations)?;
            writer.add_file(&format!("{prefix}/organizations.ndjson"), &data)?;
        }

        // signing_key.json (AES-256-GCM encrypted PKCS#8 bytes)
        let pkcs8 = self
            .identity
            .export_realm_signing_key_pkcs8(realm_id)
            .map_err(|e| BackupError::Engine(e.to_string()))?;
        let encrypted = encrypt_bytes(&pkcs8, signing_key_dek)?;
        writer.add_file(&format!("{prefix}/signing_key.json"), &encrypted)?;

        // audit.ndjson (optional)
        if opts.include_audit {
            let events = self
                .audit
                .query(&AuditQuery::for_realm(realm_id.clone()))
                .map_err(|e| BackupError::Engine(e.to_string()))?;
            counts.audit_events = events.len() as u64;
            if !events.is_empty() {
                let data = to_ndjson(&events)?;
                writer.add_file(&format!("{prefix}/audit.ndjson"), &data)?;
            }
        }

        Ok(RealmManifest {
            realm_id: format!("realm_{}", realm_id.as_uuid()),
            slug,
            record_counts: counts,
        })
    }

    /// Exhausts all pages from a paginated engine call, collecting every item.
    ///
    /// The closure returns `(items, next_cursor)` — this avoids a type conflict
    /// between `identity::types::Page<T>` and `rbac::types::Page<T>`, which are
    /// structurally identical but distinct types.
    fn export_paginated<T, F>(&self, fetch: F) -> Result<Vec<T>, BackupError>
    where
        F: Fn(Option<&str>) -> Result<(Vec<T>, Option<String>), BackupError>,
    {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let (items, next_cursor) = fetch(cursor.as_deref())?;
            all.extend(items);
            match next_cursor {
                None => break,
                Some(c) => cursor = Some(c),
            }
        }
        Ok(all)
    }
}

/// Converts a realm display name to a URL-safe archive slug.
///
/// Lowercases and replaces any run of non-alphanumeric characters with a
/// single hyphen. Trailing hyphens are stripped.
fn slugify(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut prev_hyphen = false;
    for c in name.chars() {
        if c.is_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            prev_hyphen = false;
        } else if !prev_hyphen && !slug.is_empty() {
            slug.push('-');
            prev_hyphen = true;
        }
    }
    slug.trim_end_matches('-').to_string()
}

/// Serialises a slice of records as NDJSON (one JSON object per line).
fn to_ndjson<T: Serialize>(items: &[T]) -> Result<Vec<u8>, BackupError> {
    let mut out = Vec::new();
    for item in items {
        serde_json::to_writer(&mut out, item)?;
        out.push(b'\n');
    }
    Ok(out)
}

/// AES-256-GCM encrypts `plaintext` using `dek`.
///
/// Output is a JSON object:
/// ```text
/// {"nonce_b64":"<12B base64>","ciphertext_b64":"<ciphertext+tag base64>"}
/// ```
fn encrypt_bytes(plaintext: &[u8], dek: &[u8; 32]) -> Result<Vec<u8>, BackupError> {
    let mut nonce_bytes = [0u8; 12];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| BackupError::Crypto("nonce generation failed".into()))?;

    let unbound = UnboundKey::new(&AES_256_GCM, dek)
        .map_err(|_| BackupError::Crypto("key initialisation failed".into()))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut ciphertext = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| BackupError::Crypto("encryption failed".into()))?;

    let payload = serde_json::json!({
        "nonce_b64": BASE64.encode(nonce_bytes),
        "ciphertext_b64": BASE64.encode(&ciphertext),
    });
    Ok(serde_json::to_vec(&payload)?)
}

/// AES-256-GCM decrypts a blob produced by [`encrypt_bytes`].
///
/// Returns a [`Zeroizing`] wrapper so the plaintext key material is actively
/// overwritten when the returned value is dropped (HEA-750 M1).
pub fn decrypt_bytes(
    encrypted_json: &[u8],
    dek: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    #[derive(serde::Deserialize)]
    struct Payload {
        nonce_b64: String,
        ciphertext_b64: String,
    }
    let payload: Payload = serde_json::from_slice(encrypted_json)?;
    let nonce_bytes = BASE64
        .decode(&payload.nonce_b64)
        .map_err(|e| BackupError::Crypto(format!("nonce decode: {e}")))?;
    if nonce_bytes.len() != 12 {
        return Err(BackupError::Crypto("nonce must be 12 bytes".into()));
    }
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce_bytes);

    let unbound = UnboundKey::new(&AES_256_GCM, dek)
        .map_err(|_| BackupError::Crypto("key initialisation failed".into()))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_arr);

    let mut ciphertext = BASE64
        .decode(&payload.ciphertext_b64)
        .map_err(|e| BackupError::Crypto(format!("ciphertext decode: {e}")))?;
    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| {
            BackupError::Crypto("decryption failed — wrong DEK or corrupted data".into())
        })?;
    Ok(Zeroizing::new(plaintext.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_ndjson_line_count_matches_input() {
        let items = vec![
            serde_json::json!({"id": "a", "name": "Alice"}),
            serde_json::json!({"id": "b", "name": "Bob"}),
            serde_json::json!({"id": "c", "name": "Carol"}),
        ];
        let ndjson = to_ndjson(&items).expect("serialize");
        // Split on newlines; NDJSON ends with a trailing '\n', so split produces
        // one extra empty element which we subtract.
        let line_count = ndjson.split(|&b| b == b'\n').count().saturating_sub(1);
        assert_eq!(
            line_count,
            items.len(),
            "each item must produce exactly one line"
        );
    }

    #[test]
    fn to_ndjson_each_line_is_valid_json() {
        let items = vec![serde_json::json!({"x": 1}), serde_json::json!({"x": 2})];
        let ndjson = to_ndjson(&items).expect("serialize");
        for line in ndjson.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            let parsed: serde_json::Value =
                serde_json::from_slice(line).expect("valid JSON per line");
            assert!(parsed.is_object());
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dek = BackupExporter::generate_dek().expect("generate DEK");
        let plaintext = b"this is my PKCS#8 signing key";
        let encrypted = encrypt_bytes(plaintext, &dek).expect("encrypt");
        let decrypted = decrypt_bytes(&encrypted, &dek).expect("decrypt");
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_dek_fails() {
        let dek = BackupExporter::generate_dek().expect("generate DEK");
        let wrong_dek = BackupExporter::generate_dek().expect("generate DEK");
        let encrypted = encrypt_bytes(b"secret", &dek).expect("encrypt");
        let result = decrypt_bytes(&encrypted, &wrong_dek);
        assert!(result.is_err(), "decryption with wrong DEK must fail");
    }

    #[test]
    fn generate_dek_produces_distinct_keys() {
        let a = BackupExporter::generate_dek().expect("dek a");
        let b = BackupExporter::generate_dek().expect("dek b");
        assert_ne!(a, b, "each generated DEK must be unique");
    }

    #[test]
    fn decrypt_bytes_returns_zeroizing() {
        // Type-level assertion: decrypt_bytes must return Zeroizing<Vec<u8>> so
        // that the plaintext key material is actively overwritten when dropped,
        // rather than relying on the OS to zero freed heap pages (HEA-750 M1).
        use zeroize::Zeroizing;
        let dek = BackupExporter::generate_dek().expect("generate DEK");
        let enc = encrypt_bytes(b"pkcs8-key-material", &dek).expect("encrypt");
        let result: Zeroizing<Vec<u8>> = decrypt_bytes(&enc, &dek).expect("decrypt");
        assert_eq!(&*result, b"pkcs8-key-material");
    }
}
