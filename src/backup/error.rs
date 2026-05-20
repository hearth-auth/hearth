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
}
