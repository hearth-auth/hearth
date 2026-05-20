//! Backup and restore: archive format, manifest, and typed record wrappers.
//!
//! # Archive layout
//!
//! Archives use the `.hearth-backup` extension. Each archive is a
//! zstd-compressed tar containing:
//!
//! ```text
//! manifest.json
//! realms/<realm-slug>/realm.json
//! realms/<realm-slug>/users.ndjson
//! realms/<realm-slug>/credentials.ndjson
//! realms/<realm-slug>/clients.ndjson
//! realms/<realm-slug>/roles.ndjson
//! realms/<realm-slug>/permissions.ndjson
//! realms/<realm-slug>/groups.ndjson
//! realms/<realm-slug>/assignments.ndjson
//! realms/<realm-slug>/organizations.ndjson
//! realms/<realm-slug>/scopes.ndjson
//! realms/<realm-slug>/signing_key.json   (AES-256-GCM encrypted)
//! realms/<realm-slug>/audit.ndjson       (optional)
//! ```
//!
//! The manifest is always the **last** entry so that checksums for all
//! preceding files can be included in it.
//!
//! # Usage
//!
//! ```no_run
//! use std::path::Path;
//! use hearth::backup::{BackupArchive, BackupManifest, RealmManifest};
//!
//! let path = Path::new("snapshot.hearth-backup");
//!
//! // Write
//! let mut writer = BackupArchive::create(path).unwrap();
//! writer.add_file("realms/acme/users.ndjson", b"{\"id\":\"user_1\"}\n").unwrap();
//! let manifest = BackupManifest::new(vec![]);
//! writer.finish(manifest).unwrap();
//!
//! // Read
//! let reader = BackupArchive::open(path).unwrap();
//! println!("{} realms", reader.realms().len());
//! ```

mod encryption;
mod error;
mod export;
mod import;
mod types;

pub use encryption::{decrypt_archive, encrypt_archive};
pub use error::BackupError;
pub use export::{decrypt_bytes, BackupExporter, ExportOptions};
pub use import::{BackupImporter, Conflict, EntityCounts, ImportOptions, ImportReport, RestoreMode};
pub use types::{
    BackupManifest, BackupRecord, DekWrappingParams, RecordCounts, RealmManifest, MANIFEST_VERSION,
};

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use hex::encode as hex_encode;
use sha2::{Digest, Sha256};

/// Entry point for creating and opening `.hearth-backup` archives.
///
/// Archives are zstd-compressed tarballs. Use [`create`](Self::create) to
/// build a new archive and [`open`](Self::open) to inspect an existing one.
pub struct BackupArchive;

impl BackupArchive {
    /// Creates a new archive at `path` and returns a streaming [`ArchiveWriter`].
    ///
    /// The caller adds realm data files with [`ArchiveWriter::add_file`], then
    /// calls [`ArchiveWriter::finish`] to write `manifest.json` (including the
    /// computed checksums) as the final tar entry and close the zstd stream.
    pub fn create(path: &Path) -> Result<ArchiveWriter, BackupError> {
        let file = std::fs::File::create(path)?;
        let encoder = zstd::Encoder::new(file, 0)?;
        let builder = tar::Builder::new(encoder);
        Ok(ArchiveWriter { builder, checksums: HashMap::new() })
    }

    /// Opens an existing archive at `path` and reads its `manifest.json`.
    ///
    /// Returns an [`ArchiveReader`] whose [`manifest`](ArchiveReader::manifest)
    /// field is populated. Use [`ArchiveReader::verify_checksums`] to validate
    /// file integrity.
    ///
    /// Returns [`BackupError::UnsupportedVersion`] when the archive was
    /// created by a newer, incompatible version of Hearth.
    pub fn open(path: &Path) -> Result<ArchiveReader, BackupError> {
        let manifest = read_manifest(path)?;
        if manifest.format_version != MANIFEST_VERSION {
            return Err(BackupError::UnsupportedVersion(manifest.format_version));
        }
        Ok(ArchiveReader { manifest, path: path.to_path_buf() })
    }
}

/// Streaming writer for a `.hearth-backup` archive.
///
/// Obtained via [`BackupArchive::create`]. Add realm data files with
/// [`add_file`](Self::add_file), then call [`finish`](Self::finish) to
/// write the manifest and seal the archive.
pub struct ArchiveWriter {
    builder: tar::Builder<zstd::Encoder<'static, std::fs::File>>,
    checksums: HashMap<String, String>,
}

impl ArchiveWriter {
    /// Appends `data` at `archive_path` inside the archive.
    ///
    /// The SHA-256 checksum of `data` is recorded and later written into
    /// `manifest.json` by [`finish`](Self::finish).
    ///
    /// `archive_path` must be an archive-relative POSIX path, e.g.
    /// `realms/my-realm/users.ndjson`.
    pub fn add_file(&mut self, archive_path: &str, data: &[u8]) -> Result<(), BackupError> {
        let checksum = sha256_hex(data);
        self.checksums.insert(archive_path.to_string(), checksum);

        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();

        self.builder.append_data(&mut header, archive_path, data)?;
        Ok(())
    }

    /// Writes `manifest.json` with accumulated checksums and finalises the archive.
    ///
    /// The `manifest`'s `checksums` field is replaced with the checksums
    /// accumulated from all prior [`add_file`](Self::add_file) calls, so
    /// the caller need not populate it manually.
    pub fn finish(mut self, mut manifest: BackupManifest) -> Result<(), BackupError> {
        manifest.checksums = self.checksums;

        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;

        let mut header = tar::Header::new_gnu();
        header.set_size(manifest_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();

        self.builder.append_data(&mut header, "manifest.json", manifest_bytes.as_slice())?;

        // Finalise tar (writes EOF blocks), then flush the zstd frame.
        let encoder = self.builder.into_inner()?;
        encoder.finish()?;
        Ok(())
    }
}

/// Reader for an existing `.hearth-backup` archive.
///
/// Obtained via [`BackupArchive::open`]. The `manifest` field is populated
/// on construction from the embedded `manifest.json`.
#[derive(Debug)]
pub struct ArchiveReader {
    /// The parsed manifest from `manifest.json`.
    pub manifest: BackupManifest,
    path: PathBuf,
}

impl ArchiveReader {
    /// Returns the realm entries from the manifest.
    pub fn realms(&self) -> &[RealmManifest] {
        &self.manifest.realms
    }

    /// Reads the raw bytes of a single file from the archive by its archive-relative path.
    ///
    /// Returns `None` when no entry with that path exists. Opens a fresh
    /// decoder on every call — use [`read_all_realm_files`](Self::read_all_realm_files)
    /// when reading multiple files for the same realm.
    pub fn read_file(&self, archive_path: &str) -> Result<Option<Vec<u8>>, BackupError> {
        let file = std::fs::File::open(&self.path)?;
        let decoder = zstd::Decoder::new(file)?;
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_path = entry.path()?.to_string_lossy().into_owned();
            if entry_path == archive_path {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    /// Reads all files for a realm in a single archive pass.
    ///
    /// Returns a map from archive-relative path to raw bytes for every entry
    /// under `realms/<slug>/`. More efficient than calling [`read_file`](Self::read_file)
    /// multiple times when restoring a full realm.
    pub fn read_all_realm_files(
        &self,
        slug: &str,
    ) -> Result<HashMap<String, Vec<u8>>, BackupError> {
        let prefix = format!("realms/{slug}/");
        let file = std::fs::File::open(&self.path)?;
        let decoder = zstd::Decoder::new(file)?;
        let mut archive = tar::Archive::new(decoder);
        let mut out = HashMap::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_path = entry.path()?.to_string_lossy().into_owned();
            if entry_path.starts_with(&prefix) {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                out.insert(entry_path, bytes);
            }
        }
        Ok(out)
    }

    /// Reads every non-manifest entry from the archive and validates its
    /// SHA-256 checksum against the manifest.
    ///
    /// Returns `Ok(())` if all checksummed files match. Returns
    /// [`BackupError::ChecksumMismatch`] on the first mismatch detected.
    pub fn verify_checksums(&self) -> Result<(), BackupError> {
        let file = std::fs::File::open(&self.path)?;
        let decoder = zstd::Decoder::new(file)?;
        let mut archive = tar::Archive::new(decoder);

        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_path = entry.path()?.to_string_lossy().into_owned();

            if entry_path == "manifest.json" {
                continue;
            }

            if let Some(expected) = self.manifest.checksums.get(&entry_path) {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                let actual = sha256_hex(&bytes);
                if actual != *expected {
                    return Err(BackupError::ChecksumMismatch {
                        path: entry_path,
                        expected: expected.clone(),
                        actual,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Extracts and parses `manifest.json` from the archive at `path`.
fn read_manifest(path: &Path) -> Result<BackupManifest, BackupError> {
    let file = std::fs::File::open(path)?;
    let decoder = zstd::Decoder::new(file)?;
    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?.to_string_lossy().into_owned();
        if entry_path == "manifest.json" {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let manifest: BackupManifest = serde_json::from_slice(&bytes)?;
            return Ok(manifest);
        }
    }
    Err(BackupError::ManifestNotFound)
}

/// Returns the lowercase hex-encoded SHA-256 digest of `data`.
fn sha256_hex(data: &[u8]) -> String {
    hex_encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn sample_manifest() -> BackupManifest {
        BackupManifest {
            format_version: MANIFEST_VERSION,
            hearth_version: "0.1.0-test".to_string(),
            created_at: crate::core::Timestamp::from_micros(1_700_000_000_000_000),
            realms: vec![RealmManifest {
                realm_id: "realm_00000000-0000-0000-0000-000000000001".to_string(),
                slug: "test-realm".to_string(),
                record_counts: RecordCounts { users: 2, ..Default::default() },
            }],
            checksums: HashMap::new(),
            signing_key_dek_b64: None,
            dek_wrapping_params: None,
        }
    }

    #[test]
    fn archive_write_read_roundtrip() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let path = tmp.path();

        let realm_json = br#"{"realm_id":"realm_001","slug":"test-realm"}"#;
        let users_ndjson = b"{\"id\":\"user_1\"}\n{\"id\":\"user_2\"}\n";

        let mut writer = BackupArchive::create(path).expect("create");
        writer.add_file("realms/test-realm/realm.json", realm_json).expect("add realm");
        writer.add_file("realms/test-realm/users.ndjson", users_ndjson).expect("add users");
        writer.finish(sample_manifest()).expect("finish");

        let reader = BackupArchive::open(path).expect("open");
        assert_eq!(reader.manifest.format_version, MANIFEST_VERSION);
        assert_eq!(reader.realms().len(), 1);
        assert_eq!(reader.realms()[0].slug, "test-realm");
        assert_eq!(reader.manifest.checksums.len(), 2);
        assert!(reader.manifest.checksums.contains_key("realms/test-realm/realm.json"));
        assert!(reader.manifest.checksums.contains_key("realms/test-realm/users.ndjson"));
    }

    #[test]
    fn archive_checksum_verification_passes() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let path = tmp.path();

        let mut writer = BackupArchive::create(path).expect("create");
        writer.add_file("realms/test-realm/users.ndjson", b"hello\n").expect("add");
        writer.finish(sample_manifest()).expect("finish");

        let reader = BackupArchive::open(path).expect("open");
        reader.verify_checksums().expect("checksums valid");
    }

    #[test]
    fn sha256_hex_is_stable() {
        // SHA-256 of the empty string is well-known.
        let digest = sha256_hex(b"");
        assert_eq!(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn open_empty_archive_returns_manifest_not_found() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let path = tmp.path();

        // Write an archive with no manifest.json entry.
        let file = std::fs::File::create(path).expect("create");
        let encoder = zstd::Encoder::new(file, 0).expect("encoder");
        let builder = tar::Builder::new(encoder);
        let enc = builder.into_inner().expect("into_inner");
        enc.finish().expect("finish encoder");

        let err = BackupArchive::open(path).expect_err("should fail");
        assert!(matches!(err, BackupError::ManifestNotFound));
    }
}
