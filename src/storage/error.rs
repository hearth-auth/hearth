//! Storage engine error types.

use std::fmt;
use std::path::PathBuf;

/// Errors originating from the storage engine.
#[derive(Debug)]
#[non_exhaustive]
pub enum StorageError {
    /// An I/O error occurred during a storage operation.
    Io(std::io::Error),
    /// A CRC checksum did not match the expected value.
    ChecksumMismatch {
        /// Byte offset in the WAL where the mismatch was detected.
        offset: u64,
    },
    /// A record could not be deserialized from its binary representation.
    DeserializationFailed {
        /// Description of what went wrong.
        reason: String,
    },
    /// The storage file is corrupted at the given offset.
    Corrupted {
        /// Byte offset where corruption was detected.
        offset: u64,
    },
    /// An SST file has an invalid format or structure.
    InvalidSstFormat {
        /// Description of what was invalid.
        reason: String,
    },
    /// The hot tier is full and eviction could not free space.
    HotTierFull,
    /// A cryptographic operation failed (encryption, decryption, or key
    /// generation).
    Crypto {
        /// Description of what went wrong. MUST NOT contain key material.
        reason: String,
    },
    /// The WAL file uses a format version newer than this binary supports.
    ///
    /// The file was likely written by a newer version of Hearth. Downgrading
    /// is not supported — upgrade the binary or restore from backup.
    UnsupportedWalVersion {
        /// The version number found in the file.
        found: u16,
    },
    /// Realm KEKs cannot be decrypted with the current (or previous) host key.
    ///
    /// Startup is blocked. The operator must either set `HEARTH_PREVIOUS_MASTER_KEY`
    /// to the old value or restore from backup.
    HostKeyMismatch {
        /// Display names of the realms whose KEKs could not be decrypted.
        affected_realms: Vec<String>,
    },
    /// Another process (or engine instance) already holds the exclusive lock on
    /// this data directory.
    ///
    /// Only one `hearth serve` process may open a given `storage.data_dir` at a
    /// time. Stop the existing instance before starting a new one.
    AlreadyLocked {
        /// The data directory that is already locked.
        data_dir: PathBuf,
    },
    /// One or more realm KEK entries in `hearth.keys` have CRC corruption.
    ///
    /// Startup is blocked to prevent silent realm unavailability. The operator
    /// must restore `hearth.keys` from backup or remove the corrupted entries.
    /// Individual realm data encrypted under the corrupted KEK is unrecoverable
    /// without backup.
    CorruptedKeks {
        /// Display names of the realms whose KEK entries failed CRC verification.
        affected_realms: Vec<String>,
    },
    /// A Raft snapshot restore was interrupted mid-way (torn restore).
    ///
    /// The data directory contains a marker file left by the two-phase snapshot
    /// install; the node was killed between Phase 1 (delete all keys) and Phase 2
    /// (replay snapshot data). Serving reads from this state risks silently returning
    /// mixed data from two different snapshots.
    ///
    /// **Recovery**: delete the marker file named in `marker_path` and restart —
    /// the node will re-request the snapshot from the leader. Alternatively, wipe
    /// the data directory entirely.
    TornSnapshotRestore {
        /// Path to the `SNAPSHOT_RESTORE_IN_PROGRESS` marker file.
        marker_path: PathBuf,
        /// The snapshot ID from the interrupted install (from the marker file).
        snapshot_id: String,
    },
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "storage I/O error: {err}"),
            Self::ChecksumMismatch { offset } => {
                write!(f, "checksum mismatch at byte offset {offset}")
            }
            Self::DeserializationFailed { reason } => {
                write!(f, "deserialization failed: {reason}")
            }
            Self::Corrupted { offset } => {
                write!(f, "storage corrupted at byte offset {offset}")
            }
            Self::InvalidSstFormat { reason } => {
                write!(f, "invalid SST format: {reason}")
            }
            Self::HotTierFull => write!(f, "hot tier is full and eviction could not free space"),
            Self::Crypto { reason } => {
                write!(f, "cryptographic operation failed: {reason}")
            }
            Self::UnsupportedWalVersion { found } => {
                write!(
                    f,
                    "WAL format version {found} is not supported by this binary; \
                     upgrade Hearth or restore from backup"
                )
            }
            Self::HostKeyMismatch { affected_realms } => {
                let realms = affected_realms.join(", ");
                write!(
                    f,
                    "realm KEKs could not be decrypted with the current HEARTH_MASTER_KEY; \
                     affected realms: {realms}"
                )
            }
            Self::AlreadyLocked { data_dir } => {
                write!(
                    f,
                    "data directory '{}' is already locked by another process; \
                     stop the running Hearth instance before starting a new one",
                    data_dir.display()
                )
            }
            Self::CorruptedKeks { affected_realms } => {
                let realms = affected_realms.join(", ");
                write!(
                    f,
                    "CRC corruption detected in hearth.keys; startup blocked to prevent \
                     silent realm unavailability; restore from backup; affected realms: {realms}"
                )
            }
            Self::TornSnapshotRestore {
                marker_path,
                snapshot_id,
            } => {
                write!(
                    f,
                    "torn Raft snapshot restore detected: marker file '{}' (snapshot {snapshot_id}) \
                     was left by a process killed between Phase 1 (delete) and Phase 2 (replay); \
                     delete the marker file and restart so the node can re-request the snapshot \
                     from the leader, or wipe the data directory entirely",
                    marker_path.display()
                )
            }
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::ChecksumMismatch { .. }
            | Self::DeserializationFailed { .. }
            | Self::Corrupted { .. }
            | Self::InvalidSstFormat { .. }
            | Self::HotTierFull
            | Self::Crypto { .. }
            | Self::UnsupportedWalVersion { .. }
            | Self::HostKeyMismatch { .. }
            | Self::CorruptedKeks { .. }
            | Self::AlreadyLocked { .. }
            | Self::TornSnapshotRestore { .. } => None,
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_error_display() {
        let err = StorageError::ChecksumMismatch { offset: 42 };
        let display = format!("{err}");
        assert!(display.contains("checksum"), "got: {display}");
        assert!(display.contains("42"), "got: {display}");

        let io_err = StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file missing",
        ));
        let display = format!("{io_err}");
        assert!(display.contains("I/O"), "got: {display}");

        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err;
    }
}
