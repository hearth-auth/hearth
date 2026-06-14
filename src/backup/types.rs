//! Core types for the backup archive manifest and entity records.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::core::Timestamp;

/// Current archive format version. Increment on incompatible layout changes.
///
/// v2: all bulk data sections are AES-256-GCM encrypted under a single DEK
/// that is always Argon2id-wrapped before being stored in the manifest.
/// Previously (v1) only `signing_key.json` was encrypted; credentials and
/// other sections were plaintext NDJSON.
pub const MANIFEST_VERSION: u32 = 2;

/// Per-entity-type record counts for a single realm in the backup.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordCounts {
    /// Number of user records.
    pub users: u64,
    /// Number of credential records (passwords, TOTP, passkeys, etc.).
    pub credentials: u64,
    /// Number of OAuth 2.0 client registrations.
    pub clients: u64,
    /// Number of RBAC role definitions.
    pub roles: u64,
    /// Number of permission records.
    pub permissions: u64,
    /// Number of RBAC group records.
    pub groups: u64,
    /// Number of role-assignment records.
    pub assignments: u64,
    /// Number of organization records.
    pub organizations: u64,
    /// Number of OAuth scope definitions.
    pub scopes: u64,
    /// Number of audit events exported (0 when audit export was omitted).
    pub audit_events: u64,
}

/// Per-realm entry in the backup manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmManifest {
    /// Prefixed realm identifier (e.g. `realm_<uuid>`).
    pub realm_id: String,
    /// Realm slug — used as the directory name inside the archive.
    pub slug: String,
    /// Record counts per entity type for this realm.
    pub record_counts: RecordCounts,
}

/// Argon2id parameters used to derive a passphrase-based wrapping key for the DEK.
///
/// When present in [`BackupManifest`], the `wrapped_dek_b64` field stores the
/// DEK encrypted (AES-256-GCM) with a key derived from a passphrase using these
/// parameters. The nonce is prepended to the ciphertext (12 bytes || ciphertext+tag).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DekWrappingParams {
    /// Base64-encoded 16-byte Argon2id salt.
    pub salt_b64: String,
    /// Argon2id memory cost in KiB.
    pub m_cost: u32,
    /// Argon2id time cost (iterations).
    pub t_cost: u32,
    /// Argon2id parallelism factor.
    pub p_cost: u32,
}

/// Root manifest written as `manifest.json` inside the archive.
///
/// SHA-256 checksums (lowercase hex) are keyed by archive-relative path
/// (e.g. `realms/my-realm/users.ndjson`). The manifest itself is not
/// checksummed. [`super::ArchiveWriter::finish`] fills the `checksums` map
/// from the files added during the write phase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Archive format version; validated by [`super::BackupArchive::open`].
    pub format_version: u32,
    /// Hearth server version that produced this backup.
    pub hearth_version: String,
    /// UTC timestamp when the backup was created.
    pub created_at: Timestamp,
    /// One entry per realm included in the backup.
    pub realms: Vec<RealmManifest>,
    /// Lowercase-hex SHA-256 checksums keyed by archive-relative path.
    pub checksums: HashMap<String, String>,
    /// When `true`, all bulk data sections are AES-256-GCM encrypted with the DEK in
    /// [`wrapped_dek_b64`](Self::wrapped_dek_b64). Always `true` for format v2+ archives.
    #[serde(default)]
    pub sections_encrypted: bool,
    /// AES-256-GCM-encrypted 32-byte DEK: `nonce (12B) || ciphertext+tag`, base64-encoded.
    /// Encrypted under Argon2id-derived wrapping key. Always set when `sections_encrypted=true`.
    /// Use [`super::unwrap_dek`] to recover the DEK.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub wrapped_dek_b64: Option<String>,
    /// Argon2id parameters for the wrapping key. Always present with `wrapped_dek_b64`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dek_wrapping_params: Option<DekWrappingParams>,
    /// Detached Ed25519 signature over the canonical manifest bytes (A-30).
    ///
    /// When `Some`, the restore handler verifies this signature against the
    /// operator public key configured in `security.backup_verify_key` before
    /// applying the archive. If the key is configured and the signature is
    /// absent or invalid, the restore is rejected (fail-closed).
    ///
    /// The signature covers the manifest JSON serialized with this field set to
    /// `null` (i.e. the serialization produced by `canonical_bytes()`).
    ///
    /// Archives produced without operator signing omit this field entirely.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detached_signature_b64: Option<String>,
    /// v1 per-realm signing-key DEK, base64-encoded (legacy, present in v1 archives only).
    ///
    /// v2+ archives use a global `wrapped_dek_b64` for all sections. This field
    /// is retained for backward-compatible deserialization of v1 archives.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signing_key_dek_b64: Option<String>,
}

impl BackupManifest {
    /// Constructs a manifest with the running server version and current timestamp.
    ///
    /// The `checksums` field starts empty; [`super::ArchiveWriter::finish`]
    /// populates it from the files written during the archive build phase.
    pub fn new(realms: Vec<RealmManifest>) -> Self {
        Self {
            format_version: MANIFEST_VERSION,
            hearth_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: Timestamp::now(),
            realms,
            checksums: HashMap::new(),
            sections_encrypted: false,
            wrapped_dek_b64: None,
            dek_wrapping_params: None,
            detached_signature_b64: None,
            signing_key_dek_b64: None,
        }
    }

    /// Returns the canonical JSON bytes that the detached signature covers.
    ///
    /// Serializes this manifest with `detached_signature_b64 = null`. Both the
    /// signer and verifier MUST use this method to obtain the signed payload.
    ///
    /// # Errors
    ///
    /// Returns `Err` if JSON serialization fails (should not happen in practice).
    pub fn canonical_bytes(&self) -> serde_json::Result<Vec<u8>> {
        let mut clone = self.clone();
        clone.detached_signature_b64 = None;
        serde_json::to_vec(&clone)
    }
}

/// Typed wrapper for a single serialized entity record.
///
/// The inner [`serde_json::Value`] carries the raw JSON representation of the
/// entity. Conversion to and from concrete identity types is handled by the
/// backup engine layer (follow-up issue). NDJSON files in the archive contain
/// one JSON object per line, not `BackupRecord` wrappers — this enum is used
/// for in-process record routing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
pub enum BackupRecord {
    /// Realm configuration.
    Realm(serde_json::Value),
    /// User account.
    User(serde_json::Value),
    /// Credential (password hash, TOTP secret, passkey descriptor, etc.).
    Credential(serde_json::Value),
    /// OAuth 2.0 client registration.
    Client(serde_json::Value),
    /// RBAC role definition.
    Role(serde_json::Value),
    /// Permission definition.
    Permission(serde_json::Value),
    /// RBAC group.
    Group(serde_json::Value),
    /// Role-assignment record.
    Assignment(serde_json::Value),
    /// Organization.
    Organization(serde_json::Value),
    /// OAuth scope definition.
    Scope(serde_json::Value),
    /// Per-realm signing key (AES-256-GCM encrypted when stored in the archive).
    SigningKey(serde_json::Value),
    /// Audit event (present only when audit export is included).
    AuditEvent(serde_json::Value),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_counts_default_is_zero() {
        let counts = RecordCounts::default();
        assert_eq!(counts.users, 0);
        assert_eq!(counts.credentials, 0);
        assert_eq!(counts.audit_events, 0);
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let manifest = BackupManifest {
            format_version: MANIFEST_VERSION,
            hearth_version: "0.1.0-test".to_string(),
            created_at: Timestamp::from_micros(1_700_000_000_000_000),
            realms: vec![RealmManifest {
                realm_id: "realm_00000000-0000-0000-0000-000000000001".to_string(),
                slug: "acme".to_string(),
                record_counts: RecordCounts {
                    users: 5,
                    ..Default::default()
                },
            }],
            checksums: [("realms/acme/users.ndjson".to_string(), "abc123".to_string())]
                .into_iter()
                .collect(),
            sections_encrypted: false,
            wrapped_dek_b64: None,
            dek_wrapping_params: None,
            detached_signature_b64: None,
            signing_key_dek_b64: None,
        };

        let json = serde_json::to_string(&manifest).expect("serialize");
        let deserialized: BackupManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(manifest, deserialized);
    }

    /// `canonical_bytes` serializes the manifest with `detached_signature_b64 = null`
    /// so the signature covers a stable payload regardless of the field value.
    #[test]
    fn canonical_bytes_strips_signature_field() {
        let mut manifest = BackupManifest::new(vec![]);
        manifest.detached_signature_b64 = Some("some_sig".to_string());
        let bytes = manifest.canonical_bytes().expect("canonical_bytes");
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).expect("parse canonical bytes");
        assert!(
            value.get("detached_signature_b64").is_none(),
            "detached_signature_b64 must be absent in canonical bytes"
        );
    }

    /// A manifest with a signature round-trips through serde correctly.
    #[test]
    fn manifest_with_signature_serde_roundtrip() {
        let mut manifest = BackupManifest::new(vec![]);
        manifest.detached_signature_b64 = Some("AAEC".to_string());
        let json = serde_json::to_string(&manifest).expect("serialize");
        let back: BackupManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            back.detached_signature_b64.as_deref(),
            Some("AAEC"),
            "signature field must survive serde round-trip"
        );
    }

    #[test]
    fn backup_record_serde_roundtrip() {
        let record = BackupRecord::User(serde_json::json!({"id": "user_abc", "email": "a@b.com"}));
        let json = serde_json::to_string(&record).expect("serialize");
        let deserialized: BackupRecord = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(deserialized, BackupRecord::User(_)));
    }
}
