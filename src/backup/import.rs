//! Backup restore engine — `BackupImporter`.
//!
//! Reads a [`BackupArchive`] and drives the existing `import_*` engine
//! methods to restore realm entities. All writes go through the engine
//! trait; no raw storage access.

use std::sync::Arc;

use serde::Deserialize;
use tracing::{debug, warn};

use crate::core::{ClientId, RealmId};
use crate::identity::{
    ClientTrustLevel, CreateRealmRequest, IdentityEngine, IdentityError, ImportClientRequest,
    ImportUserRequest, RawCredential, Realm, User,
};
use crate::rbac::RbacEngine;

use super::{ArchiveReader, BackupError};

// ── Public types ─────────────────────────────────────────────────────────────

/// What to do when a record already exists in the target.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RestoreMode {
    /// Skip records that already exist (default). The originals are untouched.
    #[default]
    Skip,
    /// Delete the existing record then re-import from the archive.
    Overwrite,
    /// Add new records; skip on conflict. Alias for `Skip` in this version.
    Merge,
}

/// Controls how `BackupImporter::import_realm` behaves.
#[derive(Clone, Debug, Default)]
pub struct ImportOptions {
    /// Conflict resolution strategy (default: `Skip`).
    pub mode: RestoreMode,
    /// When `true`, parse and validate all records but write nothing.
    pub dry_run: bool,
    /// Remap the realm to a different slug/name on restore.
    ///
    /// When set, the restored realm is created with this name instead of the
    /// one stored in the archive. Has no effect if the realm already exists.
    pub realm_target: Option<String>,
}

/// Per-entity-type outcome counts for a single realm restore operation.
#[derive(Clone, Debug, Default)]
pub struct EntityCounts {
    /// Records written successfully.
    pub created: u64,
    /// Records skipped because they already existed (Skip / Merge mode).
    pub skipped: u64,
    /// Records that replaced an existing entry (Overwrite mode).
    pub overwritten: u64,
    /// Records that could not be imported due to an error.
    pub errored: u64,
}

/// A conflict observed during restore.
#[derive(Clone, Debug)]
pub struct Conflict {
    /// Entity type — e.g. `"user"`, `"client"`, `"realm"`.
    pub entity_type: String,
    /// Human-readable identifier (email, slug, etc.).
    pub identifier: String,
    /// Why the conflict occurred.
    pub reason: String,
}

/// Full outcome report for a realm import operation.
#[derive(Clone, Debug, Default)]
pub struct ImportReport {
    /// Outcome counts for realm records (0 or 1 per call).
    pub realms: EntityCounts,
    /// Outcome counts for user records.
    pub users: EntityCounts,
    /// Outcome counts for OAuth client records.
    pub clients: EntityCounts,
    /// Conflicts encountered — populated in Skip / Merge mode only.
    pub conflicts: Vec<Conflict>,
}

// ── Internal archive record types ────────────────────────────────────────────
//
// These match the NDJSON line format written by `BackupExporter` (HEA-619).
// They use the exact serde field names emitted by the domain types so the
// exporter can serialize `User`, `Realm`, and `OAuthClient` directly.

/// A credential record from `credentials.ndjson`.
///
/// Each line binds a PHC-formatted hash to the owning user.
#[derive(Deserialize)]
struct BackupCredential {
    /// Prefixed user ID string (e.g. `"user_<uuid>"`).
    user_id: String,
    /// PHC-formatted password hash.
    phc_string: String,
    /// Original creation timestamp in Unix microseconds, if known.
    #[serde(default)]
    created_at_micros: Option<i64>,
}

/// Minimal client fields extracted from an `OAuthClient` JSON line
/// (`clients.ndjson`). Field names match `OAuthClient`'s serde output.
#[derive(Deserialize)]
struct BackupClient {
    client_id: String,
    client_name: String,
    #[serde(default)]
    slug: String,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    grant_types: Vec<String>,
    #[serde(default)]
    trust_level: ClientTrustLevel,
    #[serde(default)]
    declared_scopes: Vec<String>,
    #[serde(default)]
    consent_spans_orgs: bool,
}

// ── BackupImporter ────────────────────────────────────────────────────────────

/// Restores realm data from a [`BackupArchive`](super::BackupArchive) using
/// the existing engine `import_*` methods.
///
/// All writes are mediated through [`IdentityEngine`] and [`RbacEngine`]
/// traits — no raw storage is accessed.
pub struct BackupImporter {
    identity: Arc<dyn IdentityEngine>,
    #[allow(dead_code)] // RBAC import reserved for future use (roles, groups)
    rbac: Arc<dyn RbacEngine>,
}

impl BackupImporter {
    /// Creates a new importer backed by the given engine instances.
    pub fn new(identity: Arc<dyn IdentityEngine>, rbac: Arc<dyn RbacEngine>) -> Self {
        Self { identity, rbac }
    }

    /// Restores one realm from `reader` using the archive slug `realm_slug`.
    ///
    /// The realm slug identifies which directory inside the archive to read
    /// (e.g. `realms/<realm_slug>/`). `opts.realm_target` can remap it to a
    /// different name in the target system.
    ///
    /// Returns an [`ImportReport`] with counts and any conflicts encountered.
    pub fn import_realm(
        &self,
        realm_slug: &str,
        reader: &ArchiveReader,
        opts: &ImportOptions,
    ) -> Result<ImportReport, BackupError> {
        let mut report = ImportReport::default();

        // Load all files for this realm in a single archive pass.
        let files = reader.read_all_realm_files(realm_slug)?;

        // Parse realm.json — required.
        let realm_key = format!("realms/{realm_slug}/realm.json");
        let realm_bytes = files.get(&realm_key).ok_or_else(|| {
            BackupError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("realm.json not found for slug '{realm_slug}'"),
            ))
        })?;
        let realm: Realm = serde_json::from_slice(realm_bytes)?;

        // Parse credentials.ndjson — optional (users may have no passwords).
        let cred_key = format!("realms/{realm_slug}/credentials.ndjson");
        let credential_map = if let Some(bytes) = files.get(&cred_key) {
            parse_credentials(bytes)?
        } else {
            std::collections::HashMap::new()
        };

        // ── Realm ──────────────────────────────────────────────────────────
        let target_name = opts
            .realm_target
            .as_deref()
            .unwrap_or_else(|| realm.name());

        let realm_id = realm.id().clone();
        let create_req = CreateRealmRequest {
            name: target_name.to_string(),
            config: Some(realm.config().clone()),
        };

        let restored_realm_id = if opts.dry_run {
            report.realms.created += 1;
            realm_id.clone()
        } else {
            self.import_realm_record(&create_req, realm_id, opts, &mut report)?
        };

        // ── Users ──────────────────────────────────────────────────────────
        let users_key = format!("realms/{realm_slug}/users.ndjson");
        if let Some(bytes) = files.get(&users_key) {
            self.import_users(
                bytes,
                &credential_map,
                &restored_realm_id,
                opts,
                &mut report,
            )?;
        }

        // ── Clients ────────────────────────────────────────────────────────
        let clients_key = format!("realms/{realm_slug}/clients.ndjson");
        if let Some(bytes) = files.get(&clients_key) {
            self.import_clients(bytes, &restored_realm_id, opts, &mut report)?;
        }

        // Signing key restore requires a dedicated engine method not yet
        // available (`import_realm` always generates a fresh key). Skipped.
        let sk_key = format!("realms/{realm_slug}/signing_key.json");
        if files.contains_key(&sk_key) {
            debug!(slug = realm_slug, "signing_key.json present but skipped (engine always generates a fresh key on import_realm)");
        }

        Ok(report)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn import_realm_record(
        &self,
        req: &CreateRealmRequest,
        realm_id: RealmId,
        opts: &ImportOptions,
        report: &mut ImportReport,
    ) -> Result<RealmId, BackupError> {
        match self.identity.import_realm(req, Some(realm_id.clone())) {
            Ok(r) => {
                report.realms.created += 1;
                Ok(r.id().clone())
            }
            Err(IdentityError::DuplicateRealmName) => {
                match opts.mode {
                    RestoreMode::Skip | RestoreMode::Merge => {
                        report.realms.skipped += 1;
                        report.conflicts.push(Conflict {
                            entity_type: "realm".to_string(),
                            identifier: req.name.clone(),
                            reason: "realm with this id already exists".to_string(),
                        });
                        // Return the original ID so child entities are still imported.
                        Ok(realm_id)
                    }
                    RestoreMode::Overwrite => {
                        self.identity
                            .delete_realm(&realm_id)
                            .map_err(identity_to_backup_err)?;
                        let r = self
                            .identity
                            .import_realm(req, Some(realm_id))
                            .map_err(identity_to_backup_err)?;
                        report.realms.overwritten += 1;
                        Ok(r.id().clone())
                    }
                }
            }
            Err(e) => {
                report.realms.errored += 1;
                Err(identity_to_backup_err(e))
            }
        }
    }

    fn import_users(
        &self,
        ndjson: &[u8],
        credential_map: &std::collections::HashMap<String, RawCredential>,
        realm_id: &RealmId,
        opts: &ImportOptions,
        report: &mut ImportReport,
    ) -> Result<(), BackupError> {
        for line in ndjson.split(|&b| b == b'\n') {
            let line = trim_bytes(line);
            if line.is_empty() {
                continue;
            }
            let user: User = serde_json::from_slice(line)?;
            let user_id_str = user.id().as_uuid().to_string();
            let credential = credential_map.get(&user_id_str).cloned();

            let req = ImportUserRequest {
                id: Some(user.id().clone()),
                email: user.email().to_string(),
                display_name: user.display_name().to_string(),
                first_name: user.first_name().to_string(),
                last_name: user.last_name().to_string(),
                status: user.status(),
                credential,
                attributes: user.attributes().clone(),
            };

            if opts.dry_run {
                report.users.created += 1;
                continue;
            }

            match self.identity.import_user(realm_id, &req) {
                Ok(_) => report.users.created += 1,
                Err(IdentityError::DuplicateEmail) => {
                    match opts.mode {
                        RestoreMode::Skip | RestoreMode::Merge => {
                            report.users.skipped += 1;
                            report.conflicts.push(Conflict {
                                entity_type: "user".to_string(),
                                identifier: req.email.clone(),
                                reason: "email already exists".to_string(),
                            });
                        }
                        RestoreMode::Overwrite => {
                            // Look up existing user by email to get their ID.
                            match self.identity.get_user_by_email(realm_id, &req.email) {
                                Ok(Some(existing)) => {
                                    self.identity
                                        .delete_user(realm_id, existing.id())
                                        .map_err(identity_to_backup_err)?;
                                    self.identity
                                        .import_user(realm_id, &req)
                                        .map_err(identity_to_backup_err)?;
                                    report.users.overwritten += 1;
                                }
                                Ok(None) => {
                                    warn!(email = %req.email, "overwrite: user not found by email after DuplicateEmail");
                                    report.users.errored += 1;
                                }
                                Err(e) => {
                                    warn!(email = %req.email, err = %e, "overwrite: could not look up existing user");
                                    report.users.errored += 1;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(email = %req.email, err = %e, "import_user failed");
                    report.users.errored += 1;
                }
            }
        }
        Ok(())
    }

    fn import_clients(
        &self,
        ndjson: &[u8],
        realm_id: &RealmId,
        opts: &ImportOptions,
        report: &mut ImportReport,
    ) -> Result<(), BackupError> {
        for line in ndjson.split(|&b| b == b'\n') {
            let line = trim_bytes(line);
            if line.is_empty() {
                continue;
            }
            let client: BackupClient = serde_json::from_slice(line)?;
            let client_id_str = client.client_id.clone();

            // Parse the prefixed client ID into a `ClientId`.
            let parsed_id: Option<ClientId> = client.client_id.parse().ok();

            let req = ImportClientRequest {
                id: parsed_id,
                client_name: client.client_name.clone(),
                redirect_uris: client.redirect_uris,
                client_secret: None, // secrets are not restored (hashed in archive)
                grant_types: client.grant_types,
                slug: if client.slug.is_empty() { None } else { Some(client.slug) },
                trust_level: client.trust_level,
                declared_scopes: client.declared_scopes,
                consent_spans_orgs: client.consent_spans_orgs,
            };

            if opts.dry_run {
                report.clients.created += 1;
                continue;
            }

            match self.identity.import_client(realm_id, &req) {
                Ok(_) => report.clients.created += 1,
                Err(IdentityError::InvalidInput { reason }) if reason.contains("already exists") => {
                    match opts.mode {
                        RestoreMode::Skip | RestoreMode::Merge => {
                            report.clients.skipped += 1;
                            report.conflicts.push(Conflict {
                                entity_type: "client".to_string(),
                                identifier: client_id_str,
                                reason,
                            });
                        }
                        RestoreMode::Overwrite => {
                            // Delete by client_id then re-import.
                            if let Some(ref cid) = req.id {
                                if let Ok(()) = self.identity.delete_client(realm_id, cid) {
                                    match self.identity.import_client(realm_id, &req) {
                                        Ok(_) => report.clients.overwritten += 1,
                                        Err(e) => {
                                            warn!(client_id = %client_id_str, err = %e, "import_client retry failed");
                                            report.clients.errored += 1;
                                        }
                                    }
                                } else {
                                    report.clients.errored += 1;
                                }
                            } else {
                                report.clients.errored += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(client_id = %client_id_str, err = %e, "import_client failed");
                    report.clients.errored += 1;
                }
            }
        }
        Ok(())
    }
}

// ── Free helpers ─────────────────────────────────────────────────────────────

/// Parses `credentials.ndjson` bytes into a map from raw user UUID string to
/// [`RawCredential`].
fn parse_credentials(
    ndjson: &[u8],
) -> Result<std::collections::HashMap<String, RawCredential>, BackupError> {
    let mut map = std::collections::HashMap::new();
    for line in ndjson.split(|&b| b == b'\n') {
        let line = trim_bytes(line);
        if line.is_empty() {
            continue;
        }
        let cred: BackupCredential = serde_json::from_slice(line)?;
        // Strip the "user_" prefix to get the bare UUID used as the map key.
        let uuid_str = cred
            .user_id
            .strip_prefix("user_")
            .unwrap_or(&cred.user_id)
            .to_string();
        map.insert(
            uuid_str,
            RawCredential {
                phc_string: cred.phc_string,
                created_at_micros: cred.created_at_micros,
            },
        );
    }
    Ok(map)
}

/// Converts an [`IdentityError`] into a [`BackupError::Io`] for propagation.
fn identity_to_backup_err(e: IdentityError) -> BackupError {
    BackupError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}

/// Trims leading/trailing ASCII whitespace from a byte slice.
fn trim_bytes(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&b| !b.is_ascii_whitespace()).unwrap_or(s.len());
    let end = s.iter().rposition(|&b| !b.is_ascii_whitespace()).map(|i| i + 1).unwrap_or(0);
    if start >= end { &[] } else { &s[start..end] }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    use crate::audit::EmbeddedAuditEngine;
    use crate::backup::{BackupArchive, BackupManifest, RecordCounts, RealmManifest};
    use crate::core::{Clock, FakeClock, Timestamp};
    use crate::identity::{EmbeddedIdentityEngine, IdentityConfig};
    use crate::rbac::EmbeddedRbacEngine;
    use crate::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

    // ── Test harness ──────────────────────────────────────────────────────────

    struct TestRig {
        identity: Arc<dyn IdentityEngine>,
        rbac: Arc<dyn RbacEngine>,
        // Held to keep the temp directory alive for the duration of the test.
        _dir: TempDir,
    }

    fn make_rig() -> TestRig {
        let dir = TempDir::new().expect("tmpdir");
        let storage = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
                .expect("storage"),
        ) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)))
            as Arc<dyn Clock>;
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
        ));
        let identity = Arc::new(
            EmbeddedIdentityEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock),
                IdentityConfig::default(),
                audit as Arc<dyn crate::audit::AuditEngine>,
            )
            .expect("identity engine"),
        ) as Arc<dyn IdentityEngine>;
        let rbac = Arc::new(EmbeddedRbacEngine::new(Arc::clone(&storage), Arc::clone(&clock)))
            as Arc<dyn RbacEngine>;
        TestRig { identity, rbac, _dir: dir }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_test_archive(tmp: &TempDir, slug: &str, realm_uuid: &str) -> std::path::PathBuf {
        let archive_path = tmp.path().join("test.hearth-backup");

        // Realm's serde Deserialize goes through the inner Uuid, so IDs must be
        // bare UUIDs here (no "realm_" / "user_" prefix). The prefixed form only
        // appears in Display/FromStr — not in serde JSON round-trips.
        let realm_json = serde_json::json!({
            "id": realm_uuid,
            "name": slug,
            "status": "Active",
            "config": {},
            "created_at": 0,
            "updated_at": 0
        });

        // Two test users — bare UUIDs for serde.
        let user1_json = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "email": "alice@example.com",
            "display_name": "Alice",
            "first_name": "Alice",
            "last_name": "",
            "status": "Active",
            "created_at": 0,
            "updated_at": 0
        });
        let user2_json = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000002",
            "email": "bob@example.com",
            "display_name": "Bob",
            "first_name": "Bob",
            "last_name": "",
            "status": "Active",
            "created_at": 0,
            "updated_at": 0
        });
        let users_ndjson = format!(
            "{}\n{}\n",
            serde_json::to_string(&user1_json).unwrap(),
            serde_json::to_string(&user2_json).unwrap()
        );

        let realm_bytes = serde_json::to_vec(&realm_json).unwrap();
        let users_bytes = users_ndjson.into_bytes();

        // RealmManifest.realm_id is a plain String, so the prefixed form is fine.
        let realm_id_str = format!("realm_{realm_uuid}");
        let manifest = BackupManifest {
            format_version: crate::backup::MANIFEST_VERSION,
            hearth_version: "0.0.0-test".to_string(),
            created_at: Timestamp::from_micros(0),
            realms: vec![RealmManifest {
                realm_id: realm_id_str,
                slug: slug.to_string(),
                record_counts: RecordCounts { users: 2, ..Default::default() },
            }],
            checksums: std::collections::HashMap::new(),
            signing_key_dek_b64: None,
            dek_wrapping_params: None,
        };

        let mut writer = BackupArchive::create(&archive_path).expect("create archive");
        writer
            .add_file(&format!("realms/{slug}/realm.json"), &realm_bytes)
            .expect("add realm.json");
        writer
            .add_file(&format!("realms/{slug}/users.ndjson"), &users_bytes)
            .expect("add users.ndjson");
        writer.finish(manifest).expect("finish archive");
        archive_path
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn roundtrip_import_creates_realm_and_users() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();

        let realm_uuid = "00000000-0000-0000-0000-000000000010";
        let slug = "test-realm";
        let archive_path = make_test_archive(&archive_dir, slug, realm_uuid);

        let reader = BackupArchive::open(&archive_path).expect("open");
        let importer = BackupImporter::new(Arc::clone(&rig.identity), Arc::clone(&rig.rbac));

        let report = importer
            .import_realm(slug, &reader, &ImportOptions::default())
            .expect("import");

        assert_eq!(report.realms.created, 1, "realm should be created");
        assert_eq!(report.users.created, 2, "two users should be created");
        assert_eq!(report.realms.errored, 0);
        assert_eq!(report.users.errored, 0);
        assert!(report.conflicts.is_empty());
    }

    #[test]
    fn skip_mode_is_idempotent() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();

        let realm_uuid = "00000000-0000-0000-0000-000000000020";
        let slug = "idempotent-realm";
        let archive_path = make_test_archive(&archive_dir, slug, realm_uuid);

        let reader = BackupArchive::open(&archive_path).expect("open");
        let importer = BackupImporter::new(Arc::clone(&rig.identity), Arc::clone(&rig.rbac));
        let opts = ImportOptions { mode: RestoreMode::Skip, ..Default::default() };

        // First import — everything should be created.
        let r1 = importer.import_realm(slug, &reader, &opts).expect("first import");
        assert_eq!(r1.realms.created, 1);
        assert_eq!(r1.users.created, 2);

        // Second import with same archive — realm and users already exist.
        let r2 = importer.import_realm(slug, &reader, &opts).expect("second import");
        assert_eq!(r2.realms.skipped, 1, "realm should be skipped");
        // Users may be skipped (DuplicateEmail) or re-imported under a new realm.
        // Because the realm was skipped, the same realm_id is used → duplicate emails.
        assert_eq!(r2.users.skipped, 2, "users should be skipped on second run");
        assert_eq!(r2.conflicts.len(), 3, "1 realm + 2 user conflicts");
    }

    #[test]
    fn overwrite_mode_replaces_users() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();

        let realm_uuid = "00000000-0000-0000-0000-000000000030";
        let slug = "overwrite-realm";
        let archive_path = make_test_archive(&archive_dir, slug, realm_uuid);

        let reader = BackupArchive::open(&archive_path).expect("open");
        let importer = BackupImporter::new(Arc::clone(&rig.identity), Arc::clone(&rig.rbac));

        // First import with Skip.
        importer
            .import_realm(slug, &reader, &ImportOptions::default())
            .expect("first import");

        // Second import with Overwrite.
        let opts = ImportOptions { mode: RestoreMode::Overwrite, ..Default::default() };
        let r2 = importer.import_realm(slug, &reader, &opts).expect("overwrite import");
        assert_eq!(r2.realms.overwritten, 1, "realm should be overwritten");
        // Realm overwrite cascades: delete_realm removes all child users, so
        // users are then imported fresh (created) rather than individually overwritten.
        assert_eq!(r2.users.created, 2, "users re-created after realm cascade delete");
        assert_eq!(r2.users.overwritten, 0);
        assert_eq!(r2.users.errored, 0);
    }

    #[test]
    fn dry_run_writes_nothing() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();

        let realm_uuid = "00000000-0000-0000-0000-000000000040";
        let slug = "dry-run-realm";
        let archive_path = make_test_archive(&archive_dir, slug, realm_uuid);

        let reader = BackupArchive::open(&archive_path).expect("open");
        let importer = BackupImporter::new(Arc::clone(&rig.identity), Arc::clone(&rig.rbac));
        let opts = ImportOptions { dry_run: true, ..Default::default() };

        let report = importer.import_realm(slug, &reader, &opts).expect("dry run");
        assert_eq!(report.realms.created, 1);
        assert_eq!(report.users.created, 2);

        // Now do a real import — should succeed (nothing was written by dry run).
        let r2 = importer
            .import_realm(slug, &reader, &ImportOptions::default())
            .expect("real import after dry run");
        assert_eq!(r2.realms.created, 1, "dry run must not have written the realm");
        assert_eq!(r2.users.created, 2, "dry run must not have written users");
    }
}
