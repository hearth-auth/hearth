//! Core types for the backup archive manifest and entity records.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::core::Timestamp;

/// Current archive format version. Increment on incompatible layout changes.
pub const MANIFEST_VERSION: u32 = 1;

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
/// When present in [`BackupManifest`], the `signing_key_dek_b64` field stores the
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
    /// Base64-encoded 32-byte DEK used to AES-256-GCM-encrypt the realm signing
    /// keys stored in this archive. `None` for archives without signing key export.
    /// When [`dek_wrapping_params`](Self::dek_wrapping_params) is set, this field
    /// holds the passphrase-wrapped DEK (nonce || ciphertext+tag, base64-encoded).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signing_key_dek_b64: Option<String>,
    /// When set, the DEK in `signing_key_dek_b64` is protected with a passphrase.
    /// Derive the unwrapping key with Argon2id using these parameters, then
    /// AES-256-GCM-decrypt `signing_key_dek_b64` (nonce || ciphertext+tag) to
    /// recover the 32-byte DEK.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dek_wrapping_params: Option<DekWrappingParams>,
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
            signing_key_dek_b64: None,
            dek_wrapping_params: None,
        }
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
            signing_key_dek_b64: None,
            dek_wrapping_params: None,
        };

        let json = serde_json::to_string(&manifest).expect("serialize");
        let deserialized: BackupManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(manifest, deserialized);
    }

    #[test]
    fn backup_record_serde_roundtrip() {
        let record = BackupRecord::User(serde_json::json!({"id": "user_abc", "email": "a@b.com"}));
        let json = serde_json::to_string(&record).expect("serialize");
        let deserialized: BackupRecord = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(deserialized, BackupRecord::User(_)));
    }
}
