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

    /// `manifest.json` lists a checksum for a file the archive does not carry.
    ///
    /// `verify_checksums` used to walk the entries **present in the tar** and
    /// check the ones that also appeared in the manifest's checksum map. A file
    /// that was not there was never iterated, so its absence was not an error:
    /// deleting `users.ndjson` from an archive left `backup verify` answering
    /// *"OK — all checksums match"* and `backup restore` exiting 0 over a realm
    /// with every client, role and group intact and zero users (audit re-run
    /// 23.5, B-3). The manifest is now the authority on what the archive must
    /// contain.
    #[error(
        "archive is incomplete: {count} file(s) listed in manifest.json are missing from the \
         archive ({paths}). The archive has been truncated, edited, or repacked since it was \
         written; it cannot be restored without silently losing the data those files held."
    )]
    MissingMembers {
        /// How many checksummed paths were absent.
        count: usize,
        /// The absent paths, comma-separated and sorted.
        paths: String,
    },

    /// The archive carries a file `manifest.json` does not checksum.
    ///
    /// The writer records a checksum for every member it appends, so an
    /// unlisted member was added after the archive was sealed. Verifying it is
    /// impossible, and the importer would read it as though the producer had
    /// written it (audit re-run 23.5, B-3).
    #[error(
        "archive member '{path}' is not listed in manifest.json — its contents cannot be \
         verified against anything. The archive was modified after it was written."
    )]
    UnchecksummedMember {
        /// Archive-relative path of the unlisted member.
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

    /// The archive carries a realm the caller is not authorized to restore.
    ///
    /// A restore takes the realm it may write from the caller's identity. An
    /// archive naming any other realm is refused before anything is written,
    /// so a tenant admin cannot overwrite a peer tenant by uploading that
    /// tenant's archive (audit 2026-08-28 §3 B1, §4.1#1).
    #[error(
        "backup archive contains realm '{slug}', which is outside the caller's realm — \
         a restore may only write the realm the caller is authenticated for"
    )]
    RealmNotPermitted {
        /// Archive slug of the realm the caller may not restore.
        slug: String,
    },

    /// `mode=overwrite` was asked to replace a realm that is still live.
    ///
    /// Overwrite used to delete the realm and then re-import it. `delete_realm`
    /// backgrounds its cascade for a realm above `cascade_background_threshold`
    /// and returns `Ok` while the cascade is still running, so the re-import
    /// raced its own deletion and usually lost: the realm was left destroyed,
    /// truncated, or without its signing key. Of 1,160 recorded CLI runs none
    /// completed and 975 destroyed or truncated the realm. Restore now refuses
    /// with nothing deleted (audit 2026-08-28 §3 B3, §4.9#2).
    #[error(
        "realm '{slug}' already exists — `mode=overwrite` will not replace a live realm. \
         Overwriting required deleting it first, and a deletion that is still running races \
         the restore and destroys the realm. Delete the realm explicitly, wait for the \
         deletion to finish, then restore with the default `skip` mode; or restore into an \
         instance where this realm is absent."
    )]
    RealmExists {
        /// Name of the realm that is already present on the target.
        slug: String,
    },
}
