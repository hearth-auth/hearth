//! Error types for backup creation and restoration.

use thiserror::Error;

/// Errors that can occur during backup archive creation or opening.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BackupError {
    /// I/O error reading or writing the archive.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization or deserialization failure.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// A file's actual SHA-256 checksum does not match the manifest value.
    #[error("checksum mismatch for {path}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        /// Archive-relative file path.
        path: String,
        /// Hex SHA-256 stored in the manifest.
        expected: String,
        /// Hex SHA-256 computed from the file content.
        actual: String,
    },

    /// No `manifest.json` entry found in the archive.
    #[error("manifest.json not found in archive")]
    ManifestNotFound,

    /// The archive was produced by a newer, incompatible format version.
    #[error("unsupported archive format version: {0}")]
    UnsupportedVersion(u32),

    /// An identity, RBAC, or audit engine returned an error during export.
    #[error("export engine error: {0}")]
    Engine(String),

    /// A cryptographic operation failed (key generation, encryption, decryption).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// The archive contained a member the importer does not know how to
    /// restore. Restore is fail-closed: rather than silently dropping the
    /// member (and reporting success), the whole restore aborts so the
    /// operator does not end up with a partially-restored realm (HEA-2160).
    #[error(
        "unrecognized archive member '{path}' — this Hearth version cannot fully \
         restore this backup; refusing to proceed rather than silently drop data"
    )]
    UnrecognizedMember {
        /// Archive-relative path of the member that could not be restored.
        path: String,
    },

    /// The archive carries no restorable signing key for the realm (the archive
    /// is unencrypted, predates signing-key export, or was opened without the
    /// DEK). Restoring anyway would generate a fresh key and invalidate every
    /// JWT and session issued before the backup, so restore fails closed rather
    /// than silently degrading — a `warn` on the default path is not enough
    /// (HEA-2168).
    #[error(
        "backup archive has no restorable signing key for realm '{slug}' — restoring \
         would generate a NEW key and invalidate every JWT and session issued before \
         the backup. Re-export the realm with encryption enabled (set HEARTH_MASTER_KEY \
         or pass `--encrypt` to `hearth backup create`) so the signing key round-trips, \
         or pass `--allow-missing-signing-key` to `hearth backup restore` to proceed \
         anyway with a freshly generated key."
    )]
    SigningKeyMissing {
        /// Archive slug of the realm whose signing key could not be restored.
        slug: String,
    },
}
