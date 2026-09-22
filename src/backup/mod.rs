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
//! realms/<realm-slug>/mfa_factors.ndjson
//! realms/<realm-slug>/clients.ndjson
//! realms/<realm-slug>/roles.ndjson
//! realms/<realm-slug>/permissions.ndjson
//! realms/<realm-slug>/groups.ndjson
//! realms/<realm-slug>/group_memberships.ndjson
//! realms/<realm-slug>/assignments.ndjson
//! realms/<realm-slug>/organizations.ndjson
//! realms/<realm-slug>/organization_memberships.ndjson
//! realms/<realm-slug>/consents.ndjson
//! realms/<realm-slug>/scopes.ndjson
//! realms/<realm-slug>/agents.ndjson
//! realms/<realm-slug>/identity_providers.ndjson
//! realms/<realm-slug>/federation_links.ndjson
//! realms/<realm-slug>/webhooks.ndjson
//! realms/<realm-slug>/saml_service_providers.ndjson
//! realms/<realm-slug>/saml_signing_key.json     (AES-256-GCM encrypted)
//! realms/<realm-slug>/scim_mappings.ndjson
//! realms/<realm-slug>/invitations.ndjson
//! realms/<realm-slug>/retiring_signing_keys.json (AES-256-GCM encrypted)
//! realms/<realm-slug>/signing_key.json   (AES-256-GCM encrypted)
//! realms/<realm-slug>/audit.ndjson       (optional)
//! realms/<realm-slug>/audit_chain.json   (optional, with audit.ndjson)
//! ```
//!
//! Empty sections are omitted, so an absent member means "none of these
//! existed". See [`UNEXPORTED_FAMILIES`] for the entity families this list
//! deliberately or accidentally leaves out.
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
pub use export::{decrypt_bytes, unwrap_dek, wrap_dek, BackupExporter, ExportOptions};
pub use import::{
    BackupImporter, Conflict, EntityCounts, ImportOptions, ImportReport, RestoreMode,
};
pub use types::{
    BackupManifest, BackupRecord, DekWrappingParams, RealmManifest, RecordCounts, MANIFEST_VERSION,
};

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use hex::encode as hex_encode;
use sha2::{Digest, Sha256};

/// One entity family a `.hearth-backup` archive does **not** carry.
///
/// See [`UNEXPORTED_FAMILIES`].
#[derive(Clone, Copy, Debug)]
pub struct UnexportedFamily {
    /// Human name of the family, as an operator would say it.
    pub family: &'static str,
    /// The archive member it would occupy if it were exported. Nothing writes
    /// this member today; the name is what the liveness test in this module
    /// checks against the importer's allowlist.
    pub member: &'static str,
    /// What a restore loses because the family is absent.
    pub consequence: &'static str,
}

/// Every entity family an archive does not carry, and what a restore loses.
///
/// The importer fails closed on an *unrecognized* member but has nothing to say
/// about a *missing category*: its allowlist is the union of what the exporter
/// writes, so a family nobody exports is a family nobody misses (audit re-run
/// 23.5). Until each family round-trips, `backup create` and `backup restore`
/// print this list, so an operator is told what the archive does not hold at
/// the moment it matters rather than discovering it after a disaster.
///
/// This is a *disclosure*, not a fix. Closing a family means adding an export
/// and an import for it; when that happens, delete its row here and the
/// liveness test `unexported_families_are_really_unexported` will confirm the
/// list and the archive still agree.
pub const UNEXPORTED_FAMILIES: &[UnexportedFamily] = &[UnexportedFamily {
    family: "sessions",
    member: "sessions.ndjson",
    consequence: "every access and refresh token issued before the backup is dead after the \
                      restore, even though the signing key survives. DELIBERATE, and reaffirmed \
                      by OpenSpec 26.40: a session is per-node live state carrying a session \
                      version and a device binding, and a revocation recorded after the backup \
                      is not in the archive — so restoring sessions would resurrect exactly the \
                      sessions an operator revoked. The right fix is documentation, not export: \
                      a restore is a re-authentication event.",
}];

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
        Ok(ArchiveWriter {
            builder,
            checksums: HashMap::new(),
        })
    }

    /// Opens an existing archive at `path` and reads its `manifest.json`.
    ///
    /// Returns an [`ArchiveReader`] whose [`manifest`](ArchiveReader::manifest)
    /// field is populated. Use [`ArchiveReader::verify_checksums`] to validate
    /// file integrity.
    ///
    /// Returns [`BackupError::UnsupportedVersion`] when the archive's
    /// `format_version` is not exactly [`MANIFEST_VERSION`] — an *older*
    /// archive is rejected by the same branch as a newer one.
    pub fn open(path: &Path) -> Result<ArchiveReader, BackupError> {
        let manifest = read_manifest(path)?;
        if manifest.format_version != MANIFEST_VERSION {
            return Err(BackupError::UnsupportedVersion(manifest.format_version));
        }
        Ok(ArchiveReader {
            manifest,
            path: path.to_path_buf(),
        })
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
    ///
    /// Returns [`BackupError::Crypto`] when `sections_encrypted=true` but the
    /// required DEK fields are absent or inconsistent.
    pub fn finish(mut self, mut manifest: BackupManifest) -> Result<(), BackupError> {
        if manifest.sections_encrypted
            && (manifest.wrapped_dek_b64.is_none() || manifest.dek_wrapping_params.is_none())
        {
            return Err(BackupError::Crypto(
                "sections_encrypted=true but wrapped_dek_b64 or dek_wrapping_params absent".into(),
            ));
        }
        if manifest.wrapped_dek_b64.is_some() && manifest.dek_wrapping_params.is_none() {
            return Err(BackupError::Crypto(
                "wrapped_dek_b64 set but dek_wrapping_params absent".into(),
            ));
        }
        manifest.checksums = self.checksums;

        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;

        let mut header = tar::Header::new_gnu();
        header.set_size(manifest_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();

        self.builder
            .append_data(&mut header, "manifest.json", manifest_bytes.as_slice())?;

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

    /// Reads every non-manifest entry from the archive, validates its SHA-256
    /// checksum against the manifest, and reconciles the manifest's file list
    /// with the archive's contents **in both directions**.
    ///
    /// Returns the number of files actually read and verified — not the size of
    /// the manifest's checksum map, which is what the CLI used to print.
    ///
    /// # Errors
    ///
    /// - [`BackupError::ChecksumMismatch`] — a file's content changed.
    /// - [`BackupError::MissingMembers`] — the manifest checksums a file the
    ///   archive does not carry. This walked past silently before: the loop
    ///   iterated the tar, so a *deleted* member was never visited and never
    ///   missed. `hearth backup verify` answered "OK — all checksums match"
    ///   over an archive whose `users.ndjson` had been removed, and `restore`
    ///   then exited 0 having created zero users (audit re-run 23.5, B-3).
    /// - [`BackupError::UnchecksummedMember`] — the archive carries a file the
    ///   manifest does not list. [`ArchiveWriter::add_file`] checksums every
    ///   member it appends, so an unlisted one was added after sealing.
    pub fn verify_checksums(&self) -> Result<usize, BackupError> {
        let file = std::fs::File::open(&self.path)?;
        let decoder = zstd::Decoder::new(file)?;
        let mut archive = tar::Archive::new(decoder);

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_path = entry.path()?.to_string_lossy().into_owned();

            if entry_path == "manifest.json" {
                continue;
            }

            let Some(expected) = self.manifest.checksums.get(&entry_path) else {
                return Err(BackupError::UnchecksummedMember { path: entry_path });
            };
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
            seen.insert(entry_path);
        }

        let mut missing: Vec<&str> = self
            .manifest
            .checksums
            .keys()
            .filter(|path| !seen.contains(path.as_str()))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            missing.sort_unstable();
            return Err(BackupError::MissingMembers {
                count: missing.len(),
                paths: missing.join(", "),
            });
        }

        Ok(seen.len())
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
                record_counts: RecordCounts {
                    users: 2,
                    ..Default::default()
                },
                audit_chain_included: false,
            }],
            checksums: HashMap::new(),
            sections_encrypted: false,
            wrapped_dek_b64: None,
            dek_wrapping_params: None,
            detached_signature_b64: None,
            signing_key_dek_b64: None,
        }
    }

    #[test]
    fn archive_write_read_roundtrip() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let path = tmp.path();

        let realm_json = br#"{"realm_id":"realm_001","slug":"test-realm"}"#;
        let users_ndjson = b"{\"id\":\"user_1\"}\n{\"id\":\"user_2\"}\n";

        let mut writer = BackupArchive::create(path).expect("create");
        writer
            .add_file("realms/test-realm/realm.json", realm_json)
            .expect("add realm");
        writer
            .add_file("realms/test-realm/users.ndjson", users_ndjson)
            .expect("add users");
        writer.finish(sample_manifest()).expect("finish");

        let reader = BackupArchive::open(path).expect("open");
        assert_eq!(reader.manifest.format_version, MANIFEST_VERSION);
        assert_eq!(reader.realms().len(), 1);
        assert_eq!(reader.realms()[0].slug, "test-realm");
        assert_eq!(reader.manifest.checksums.len(), 2);
        assert!(reader
            .manifest
            .checksums
            .contains_key("realms/test-realm/realm.json"));
        assert!(reader
            .manifest
            .checksums
            .contains_key("realms/test-realm/users.ndjson"));
    }

    #[test]
    fn archive_checksum_verification_passes() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let path = tmp.path();

        let mut writer = BackupArchive::create(path).expect("create");
        writer
            .add_file("realms/test-realm/users.ndjson", b"hello\n")
            .expect("add");
        writer.finish(sample_manifest()).expect("finish");

        let reader = BackupArchive::open(path).expect("open");
        reader.verify_checksums().expect("checksums valid");
    }

    /// Rewrites the archive at `src` into `dst`, passing every member through
    /// `transform`. Returning `None` drops that member. `manifest.json` is
    /// passed through like any other entry, so a caller can leave it stale on
    /// purpose — which is exactly what an archive tamperer does.
    fn repack<F>(src: &Path, dst: &Path, transform: F)
    where
        F: Fn(&str, Vec<u8>) -> Option<Vec<u8>>,
    {
        let decoder = zstd::Decoder::new(std::fs::File::open(src).expect("open src")).expect("dec");
        let mut archive = tar::Archive::new(decoder);
        let encoder =
            zstd::Encoder::new(std::fs::File::create(dst).expect("create dst"), 0).expect("enc");
        let mut builder = tar::Builder::new(encoder);
        for entry in archive.entries().expect("entries") {
            let mut entry = entry.expect("entry");
            let path = entry.path().expect("path").to_string_lossy().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).expect("read");
            let Some(bytes) = transform(&path, bytes) else {
                continue;
            };
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            builder
                .append_data(&mut header, &path, bytes.as_slice())
                .expect("append");
        }
        builder
            .into_inner()
            .expect("into_inner")
            .finish()
            .expect("finish");
    }

    /// Rewrites the archive at `path` in place with `name` appended, leaving
    /// `manifest.json` untouched.
    fn append_member(path: &Path, name: &str, bytes: &[u8]) {
        let mut all: Vec<(String, Vec<u8>)> = Vec::new();
        let decoder = zstd::Decoder::new(std::fs::File::open(path).expect("open")).expect("dec");
        for entry in tar::Archive::new(decoder).entries().expect("entries") {
            let mut entry = entry.expect("entry");
            let p = entry.path().expect("path").to_string_lossy().into_owned();
            let mut b = Vec::new();
            entry.read_to_end(&mut b).expect("read");
            all.push((p, b));
        }
        all.push((name.to_string(), bytes.to_vec()));

        let encoder =
            zstd::Encoder::new(std::fs::File::create(path).expect("create"), 0).expect("enc");
        let mut builder = tar::Builder::new(encoder);
        for (p, b) in all {
            let mut header = tar::Header::new_gnu();
            header.set_size(b.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            builder
                .append_data(&mut header, &p, b.as_slice())
                .expect("append");
        }
        builder
            .into_inner()
            .expect("into_inner")
            .finish()
            .expect("finish");
    }

    /// Writes a two-member archive at `path` and returns it sealed.
    fn two_member_archive(path: &Path) {
        let mut writer = BackupArchive::create(path).expect("create");
        writer
            .add_file("realms/test-realm/realm.json", b"{\"slug\":\"test-realm\"}")
            .expect("add realm");
        writer
            .add_file("realms/test-realm/users.ndjson", b"{\"id\":\"user_1\"}\n")
            .expect("add users");
        writer.finish(sample_manifest()).expect("finish");
    }

    /// A member deleted from the archive must be an integrity failure.
    ///
    /// `verify_checksums` walked the entries *present in the tar*, so a file
    /// that was not there was never iterated and its absence was not an error.
    /// Removing `users.ndjson` from a real archive left `hearth backup verify`
    /// printing `OK — all checksums match (15 files verified)` and `restore`
    /// exiting 0 with `users — created: 0`: two commands in a row reporting
    /// success over a realm nobody can log in to (audit re-run 23.5, B-3).
    #[test]
    fn verify_rejects_an_archive_missing_a_file_the_manifest_lists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("good.hearth-backup");
        let elided = dir.path().join("elided.hearth-backup");
        two_member_archive(&good);

        // Control: the unmodified archive verifies, so any failure below is
        // attributable to the elision and not to the repack.
        let verified = BackupArchive::open(&good)
            .expect("open good")
            .verify_checksums()
            .expect("the control archive must verify");
        assert_eq!(verified, 2, "both members must be read and verified");

        repack(&good, &elided, |path, bytes| {
            if path == "realms/test-realm/users.ndjson" {
                None
            } else {
                Some(bytes)
            }
        });

        let err = BackupArchive::open(&elided)
            .expect("open elided")
            .verify_checksums()
            .expect_err("a deleted member must be an integrity failure");
        let msg = err.to_string();
        assert!(
            msg.contains("users.ndjson"),
            "the error must name the missing file; got: {msg}"
        );
        assert!(
            matches!(err, BackupError::MissingMembers { count: 1, .. }),
            "got: {err:?}"
        );
    }

    /// An archive member the manifest does not checksum must be refused.
    ///
    /// `add_file` records a checksum for every member it appends, so an
    /// unlisted member was added after the archive was sealed. The old loop
    /// silently ignored it: `if let Some(expected) = …` simply fell through.
    #[test]
    fn verify_rejects_an_archive_member_the_manifest_does_not_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("good.hearth-backup");
        let padded = dir.path().join("padded.hearth-backup");
        two_member_archive(&good);

        // Smuggle a member in without touching the manifest, exactly as an
        // editor of a sealed archive would.
        std::fs::copy(&good, &padded).expect("copy");
        append_member(
            &padded,
            "realms/test-realm/smuggled.ndjson",
            b"{\"id\":\"user_evil\"}\n",
        );

        let err = BackupArchive::open(&padded)
            .expect("open padded")
            .verify_checksums()
            .expect_err("an unlisted member must be an integrity failure");
        assert!(
            matches!(err, BackupError::UnchecksummedMember { ref path } if path.contains("smuggled")),
            "got: {err:?}"
        );
    }

    /// Every family [`UNEXPORTED_FAMILIES`] warns about must still be absent.
    ///
    /// The list is a promise to operators about what their archive does not
    /// hold. When someone teaches the exporter to write one of these members,
    /// the warning becomes a lie — so the member names are checked against the
    /// importer's allowlist, which is kept in step with what the exporter
    /// writes. A failure here means: delete that row from
    /// `UNEXPORTED_FAMILIES`, because the family now round-trips.
    #[test]
    fn unexported_families_are_really_unexported() {
        for family in UNEXPORTED_FAMILIES {
            assert!(
                !import::RECOGNIZED_MEMBERS.contains(&family.member),
                "'{}' is now an archive member, so `{}` no longer belongs in \
                 UNEXPORTED_FAMILIES — the CLI is warning operators about data the \
                 archive does carry",
                family.member,
                family.family
            );
            assert!(
                !family.consequence.is_empty() && !family.family.is_empty(),
                "every row must say what a restore loses"
            );
        }
        assert!(
            !UNEXPORTED_FAMILIES.is_empty(),
            "an empty list must mean every family round-trips, not that the list was \
             quietly emptied"
        );
    }

    #[test]
    fn sha256_hex_is_stable() {
        // SHA-256 of the empty string is well-known.
        let digest = sha256_hex(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
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
