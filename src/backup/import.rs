//! Backup restore engine — `BackupImporter`.
//!
//! Reads a [`BackupArchive`] and drives the existing `import_*` engine
//! methods to restore realm entities. All writes go through the engine
//! trait; no raw storage access.

use std::sync::Arc;

use secrecy::SecretString;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::audit::{AuditEngine, AuditEvent};
use crate::core::{ClientId, ImportOutcome, RealmId};
use crate::identity::{
    ClientTrustLevel, CreateRealmRequest, IdentityEngine, IdentityError, ImportClientRequest,
    ImportUserRequest, MfaFactorExport, Organization, RawCredential, Realm, User,
};
use crate::rbac::{Group, PermissionRecord, RbacEngine, Role, RoleAssignment, ScopeExport};

use zeroize::Zeroizing;

use super::{decrypt_bytes, unwrap_dek, ArchiveReader, BackupError};

/// Every archive member (relative to `realms/<slug>/`) the importer knows how
/// to restore. A member NOT in this list is a hard error — see the fail-closed
/// check in [`BackupImporter::import_realm`] (HEA-2160).
///
/// Keep in sync with the members written by
/// [`BackupExporter::export_realm`](super::BackupExporter::export_realm).
const RECOGNIZED_MEMBERS: &[&str] = &[
    "realm.json",
    "users.ndjson",
    "credentials.ndjson",
    "mfa_factors.ndjson",
    "clients.ndjson",
    "roles.ndjson",
    "permissions.ndjson",
    "groups.ndjson",
    "assignments.ndjson",
    "scopes.ndjson",
    "organizations.ndjson",
    "signing_key.json",
    "audit.ndjson",
];

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
    /// Passphrase used to unwrap the DEK when `manifest.sections_encrypted = true`.
    ///
    /// Must be `Some` for any archive produced by format v2+.
    pub dek_passphrase: Option<SecretString>,
    /// Allow restore to proceed when the archive carries no restorable signing
    /// key (unencrypted archive, pre-signing-key export, or opened without the
    /// DEK). Defaults to `false`: restore fails closed with
    /// [`BackupError::SigningKeyMissing`] rather than silently generating a
    /// fresh key that invalidates every pre-restore JWT and session (HEA-2168).
    ///
    /// When `true`, the operator has explicitly accepted that a new signing key
    /// will be generated and all previously issued tokens will stop validating.
    pub allow_missing_signing_key: bool,
    /// Restrict the restore to a single realm.
    ///
    /// When `Some`, an archive whose `realm.json` carries any other realm ID is
    /// refused with [`BackupError::RealmNotPermitted`] before anything is
    /// written. `None` means the caller may restore every realm the archive
    /// contains — the system realm and the CLI, which run with full operator
    /// authority.
    ///
    /// The check reads the decrypted `realm.json`, not the manifest: the
    /// manifest is caller-supplied and may name one realm while the archive
    /// carries another (audit 2026-08-28 §3 B1, §4.1#1).
    pub allowed_realm: Option<RealmId>,
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
///
/// Every archive member has its own [`EntityCounts`] field so an operator can
/// see per-member results (created / skipped / overwritten / errored) rather
/// than a single boolean. Prior to HEA-2160 only `realms`, `users`, and
/// `clients` were populated — the RBAC and organization members were dropped
/// silently while restore reported success.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ImportReport {
    /// Outcome counts for realm records (0 or 1 per call).
    pub realms: EntityCounts,
    /// Outcome counts for user records.
    pub users: EntityCounts,
    /// Outcome counts for second-factor records — TOTP state and `WebAuthn`
    /// passkeys (audit 2026-08-28 §4.18#5).
    pub mfa_factors: EntityCounts,
    /// Outcome counts for OAuth client records.
    pub clients: EntityCounts,
    /// Outcome counts for RBAC role records.
    pub roles: EntityCounts,
    /// Outcome counts for permission-registry records.
    pub permissions: EntityCounts,
    /// Outcome counts for RBAC group records.
    pub groups: EntityCounts,
    /// Outcome counts for role-assignment records.
    pub assignments: EntityCounts,
    /// Outcome counts for OAuth scope records.
    pub scopes: EntityCounts,
    /// Outcome counts for organization records.
    pub organizations: EntityCounts,
    /// Outcome counts for restored audit events.
    pub audit_events: EntityCounts,
    /// Conflicts encountered — populated in Skip / Merge mode only.
    pub conflicts: Vec<Conflict>,
}

/// Records the outcome of a single record import into the matching
/// [`EntityCounts`] bucket.
fn tally(counts: &mut EntityCounts, outcome: ImportOutcome) {
    match outcome {
        ImportOutcome::Created => counts.created += 1,
        ImportOutcome::Skipped => counts.skipped += 1,
        ImportOutcome::Overwritten => counts.overwritten += 1,
    }
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
    rbac: Arc<dyn RbacEngine>,
    audit: Arc<dyn AuditEngine>,
}

impl BackupImporter {
    /// Creates a new importer backed by the given engine instances.
    pub fn new(
        identity: Arc<dyn IdentityEngine>,
        rbac: Arc<dyn RbacEngine>,
        audit: Arc<dyn AuditEngine>,
    ) -> Self {
        Self {
            identity,
            rbac,
            audit,
        }
    }

    /// Restores one realm from `reader` using the archive slug `realm_slug`.
    ///
    /// The realm slug identifies which directory inside the archive to read
    /// (e.g. `realms/<realm_slug>/`). `opts.realm_target` can remap it to a
    /// different name in the target system.
    ///
    /// For v2+ archives (`manifest.sections_encrypted = true`), `opts.dek_passphrase`
    /// must be set so the DEK can be unwrapped before decrypting sections.
    ///
    /// Returns an [`ImportReport`] with counts and any conflicts encountered.
    #[allow(clippy::too_many_lines)]
    pub fn import_realm(
        &self,
        realm_slug: &str,
        reader: &ArchiveReader,
        opts: &ImportOptions,
    ) -> Result<ImportReport, BackupError> {
        let mut report = ImportReport::default();

        // ── Unwrap DEK (v2+ archives) ─────────────────────────────────────
        let dek: Option<Zeroizing<[u8; 32]>> = if reader.manifest.sections_encrypted {
            let passphrase = opts.dek_passphrase.as_ref().ok_or_else(|| {
                BackupError::Crypto(
                    "archive has sections_encrypted=true but no dek_passphrase was provided".into(),
                )
            })?;
            let wrapped_b64 = reader.manifest.wrapped_dek_b64.as_deref().ok_or_else(|| {
                BackupError::Crypto("sections_encrypted=true but wrapped_dek_b64 is absent".into())
            })?;
            let params = reader
                .manifest
                .dek_wrapping_params
                .as_ref()
                .ok_or_else(|| {
                    BackupError::Crypto(
                        "sections_encrypted=true but dek_wrapping_params is absent".into(),
                    )
                })?;
            Some(unwrap_dek(wrapped_b64, params, passphrase)?)
        } else {
            None
        };

        // Convenience closure: decrypt a section if the archive is encrypted.
        let try_decrypt = |raw: &[u8]| -> Result<Zeroizing<Vec<u8>>, BackupError> {
            if let Some(ref d) = dek {
                decrypt_bytes(raw, d)
            } else {
                Ok(Zeroizing::new(raw.to_vec()))
            }
        };

        // Load all files for this realm in a single archive pass.
        let files = reader.read_all_realm_files(realm_slug)?;

        // ── Fail closed on any unrecognized member (HEA-2160) ──────────────
        //
        // Before writing anything, verify every member of this realm is one we
        // know how to restore. A member this version cannot handle is a HARD
        // ERROR, not a silent skip: an operator recovering from an incident
        // must never be told a restore "succeeded" while it quietly dropped
        // data it did not understand.
        let member_prefix = format!("realms/{realm_slug}/");
        for key in files.keys() {
            let member = key.strip_prefix(&member_prefix).unwrap_or(key);
            if !RECOGNIZED_MEMBERS.contains(&member) {
                return Err(BackupError::UnrecognizedMember { path: key.clone() });
            }
        }

        // ── Signing key (decrypted, optional) ──────────────────────────────
        //
        // Decrypt the archive's signing_key.json *before* creating the realm
        // so that `import_realm` can install the original key atomically with
        // the realm record (preserving the create_realm invariant that a
        // realm always has a usable key). A decrypt failure here is fatal:
        // silently generating a fresh key would invalidate every JWT issued
        // under this realm prior to backup (the bug HEA-745 fixes).
        //
        // The load + fail-closed check runs BEFORE any writes (audit events,
        // realm record, users, …) so a refusal leaves the target untouched —
        // no partial restore (HEA-2168).
        let signing_key_pkcs8 = self.load_signing_key(realm_slug, &files, dek.as_deref())?;
        if signing_key_pkcs8.is_none() && !opts.allow_missing_signing_key {
            // Fail closed. The archive is unencrypted, predates signing-key
            // export, or was opened without the DEK — restoring anyway would
            // mint a fresh key and invalidate every pre-restore token. Refuse
            // with an actionable error rather than a `warn` on the default path
            // (HEA-2168). Nothing has been written yet.
            return Err(BackupError::SigningKeyMissing {
                slug: realm_slug.to_string(),
            });
        }
        if signing_key_pkcs8.is_none() {
            // Operator explicitly opted in via `allow_missing_signing_key`. A
            // fresh key will be generated; pre-restore JWTs will fail to
            // validate — log loudly so this shows up in restore audit trails.
            warn!(
                slug = realm_slug,
                "signing_key not restored — archive missing signing_key.json or wrapped_dek_b64; \
                 proceeding under allow_missing_signing_key: pre-restore JWTs will fail to \
                 validate against the freshly generated key"
            );
        }

        // Parse realm.json — required.
        //
        // This runs BEFORE any write so the realm-authorization check below can
        // refuse with nothing written. The realm ID is taken from the decrypted
        // `realm.json`, never from the manifest: the manifest is caller-supplied
        // and an archive may name one realm in its manifest and carry another
        // (audit 2026-08-28 §3 B1, §4.1#1).
        let realm_key = format!("realms/{realm_slug}/realm.json");
        let realm_raw = files.get(&realm_key).ok_or_else(|| {
            BackupError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("realm.json not found for slug '{realm_slug}'"),
            ))
        })?;
        let realm_bytes = try_decrypt(realm_raw)?;
        let realm: Realm = serde_json::from_slice(&realm_bytes)?;

        // ── Realm authorization (fail closed, before any write) ─────────────
        //
        // When the caller is scoped to a single realm, the archive may only
        // restore that realm. Nothing has been written at this point, so a
        // refusal leaves the target untouched.
        if let Some(allowed) = &opts.allowed_realm {
            if realm.id() != allowed {
                return Err(BackupError::RealmNotPermitted {
                    slug: realm_slug.to_string(),
                });
            }
        }

        // ── Audit events (restored FIRST) ───────────────────────────────────
        //
        // Audit events are re-chained under the destination realm's HMAC key
        // (the source key is not portable), so the integrity hash changes but
        // the event content is preserved. They MUST be restored before any
        // other member: the identity/RBAC `import_*` calls below emit their own
        // fresh audit events with current timestamps, so replaying the older
        // historical events afterwards would interleave newer-then-older records
        // and break the tamper-evident chain (verification walks events in
        // timestamp order, which must equal insertion order). The exporter
        // writes events in ascending-timestamp scan order, so NDJSON line order
        // is already chronological. Each event carries its own realm ID, which
        // equals the restored realm ID (restore never remaps realm IDs).
        let audit_key = format!("realms/{realm_slug}/audit.ndjson");
        if let Some(raw) = files.get(&audit_key) {
            let decrypted = try_decrypt(raw)?;
            for line in decrypted.split(|&b| b == b'\n') {
                let line = trim_bytes(line);
                if line.is_empty() {
                    continue;
                }
                let event: AuditEvent = serde_json::from_slice(line)?;
                if opts.dry_run {
                    report.audit_events.created += 1;
                    continue;
                }
                match self.audit.import_event(&event) {
                    Ok(()) => report.audit_events.created += 1,
                    Err(e) => {
                        warn!(err = %e, "import audit event failed");
                        report.audit_events.errored += 1;
                    }
                }
            }
        }

        // Parse credentials.ndjson — optional (users may have no passwords).
        let cred_key = format!("realms/{realm_slug}/credentials.ndjson");
        let credential_map = if let Some(raw) = files.get(&cred_key) {
            let decrypted = try_decrypt(raw)?;
            parse_credentials(&decrypted)?
        } else {
            std::collections::HashMap::new()
        };

        // ── Realm ──────────────────────────────────────────────────────────
        let target_name = opts.realm_target.as_deref().unwrap_or_else(|| realm.name());

        let realm_id = realm.id().clone();
        let create_req = CreateRealmRequest {
            name: target_name.to_string(),
            config: Some(realm.config().clone()),
        };

        let restored_realm_id = if opts.dry_run {
            // A dry run reports what the real restore would do. An overwrite
            // over a live realm is refused (B3), so the dry run must refuse
            // too rather than report a success the restore would not deliver
            // (audit 2026-08-28 §9 item 1).
            if matches!(opts.mode, RestoreMode::Overwrite)
                && self
                    .identity
                    .get_realm(&realm_id)
                    .map_err(identity_to_backup_err)?
                    .is_some()
            {
                return Err(BackupError::RealmExists {
                    slug: target_name.to_string(),
                });
            }
            report.realms.created += 1;
            realm_id.clone()
        } else {
            self.import_realm_record(
                &create_req,
                realm_id,
                signing_key_pkcs8.as_ref().map(|z| z.as_slice()),
                opts,
                &mut report,
            )?
        };

        // ── Users ──────────────────────────────────────────────────────────
        let users_key = format!("realms/{realm_slug}/users.ndjson");
        if let Some(raw) = files.get(&users_key) {
            let decrypted = try_decrypt(raw)?;
            self.import_users(
                &decrypted,
                &credential_map,
                &restored_realm_id,
                opts,
                &mut report,
            )?;
        }

        // ── MFA factors (audit 2026-08-28 §4.18#5) ─────────────────────────
        //
        // After users so the owning records exist. TOTP state is re-encrypted
        // under the destination realm's MFA DEK inside `import_mfa_factor`.
        let overwrite_mfa = opts.mode == RestoreMode::Overwrite;
        self.restore_member_ndjson(
            &files,
            &format!("realms/{realm_slug}/mfa_factors.ndjson"),
            &try_decrypt,
            opts,
            &mut report.mfa_factors,
            |this, factor: &MfaFactorExport| {
                this.identity
                    .import_mfa_factor(&restored_realm_id, factor, overwrite_mfa)
                    .map_err(|e| BackupError::Engine(e.to_string()))
            },
        )?;

        // ── Clients ────────────────────────────────────────────────────────
        let clients_key = format!("realms/{realm_slug}/clients.ndjson");
        if let Some(raw) = files.get(&clients_key) {
            let decrypted = try_decrypt(raw)?;
            self.import_clients(&decrypted, &restored_realm_id, opts, &mut report)?;
        }

        // ── Authorization model (HEA-2160) ─────────────────────────────────
        //
        // Restore the RBAC + organization members that were previously dropped.
        // Order is chosen so referenced records exist first (permissions →
        // roles → groups → assignments), though the engine `import_*` methods
        // write verbatim and do not re-validate references.
        let overwrite = opts.mode == RestoreMode::Overwrite;

        self.restore_member_ndjson(
            &files,
            &format!("realms/{realm_slug}/permissions.ndjson"),
            &try_decrypt,
            opts,
            &mut report.permissions,
            |this, record: &PermissionRecord| {
                this.rbac
                    .import_permission(&restored_realm_id, record, overwrite)
                    .map_err(|e| BackupError::Engine(e.to_string()))
            },
        )?;

        self.restore_member_ndjson(
            &files,
            &format!("realms/{realm_slug}/roles.ndjson"),
            &try_decrypt,
            opts,
            &mut report.roles,
            |this, role: &Role| {
                this.rbac
                    .import_role(&restored_realm_id, role, overwrite)
                    .map_err(|e| BackupError::Engine(e.to_string()))
            },
        )?;

        self.restore_member_ndjson(
            &files,
            &format!("realms/{realm_slug}/groups.ndjson"),
            &try_decrypt,
            opts,
            &mut report.groups,
            |this, group: &Group| {
                this.rbac
                    .import_group(&restored_realm_id, group, overwrite)
                    .map_err(|e| BackupError::Engine(e.to_string()))
            },
        )?;

        self.restore_member_ndjson(
            &files,
            &format!("realms/{realm_slug}/organizations.ndjson"),
            &try_decrypt,
            opts,
            &mut report.organizations,
            |this, org: &Organization| {
                this.identity
                    .import_organization(&restored_realm_id, org, overwrite)
                    .map_err(|e| BackupError::Engine(e.to_string()))
            },
        )?;

        self.restore_member_ndjson(
            &files,
            &format!("realms/{realm_slug}/assignments.ndjson"),
            &try_decrypt,
            opts,
            &mut report.assignments,
            |this, assignment: &RoleAssignment| {
                this.rbac
                    .import_assignment(&restored_realm_id, assignment, overwrite)
                    .map_err(|e| BackupError::Engine(e.to_string()))
            },
        )?;

        self.restore_member_ndjson(
            &files,
            &format!("realms/{realm_slug}/scopes.ndjson"),
            &try_decrypt,
            opts,
            &mut report.scopes,
            |this, scope: &ScopeExport| {
                this.rbac
                    .import_scope(&restored_realm_id, scope, overwrite)
                    .map_err(|e| BackupError::Engine(e.to_string()))
            },
        )?;

        Ok(report)
    }

    /// Restores every NDJSON record in `key` (if present) by deserializing each
    /// line into `T` and applying `import_one`, tallying outcomes into `counts`.
    ///
    /// A malformed line is a hard error (propagated); a per-record engine error
    /// is counted in `counts.errored` and logged, matching the user/client
    /// import behavior. Absent members are a no-op.
    fn restore_member_ndjson<T, F>(
        &self,
        files: &std::collections::HashMap<String, Vec<u8>>,
        key: &str,
        try_decrypt: &impl Fn(&[u8]) -> Result<Zeroizing<Vec<u8>>, BackupError>,
        opts: &ImportOptions,
        counts: &mut EntityCounts,
        import_one: F,
    ) -> Result<(), BackupError>
    where
        T: serde::de::DeserializeOwned,
        F: Fn(&Self, &T) -> Result<ImportOutcome, BackupError>,
    {
        let Some(raw) = files.get(key) else {
            return Ok(());
        };
        let decrypted = try_decrypt(raw)?;
        for line in decrypted.split(|&b| b == b'\n') {
            let line = trim_bytes(line);
            if line.is_empty() {
                continue;
            }
            let record: T = serde_json::from_slice(line)?;
            if opts.dry_run {
                counts.created += 1;
                continue;
            }
            match import_one(self, &record) {
                Ok(outcome) => tally(counts, outcome),
                Err(e) => {
                    warn!(member = key, err = %e, "import record failed");
                    counts.errored += 1;
                }
            }
        }
        Ok(())
    }

    /// Decrypts `realms/<slug>/signing_key.json` using the provided DEK.
    ///
    /// Returns `Ok(None)` when the encrypted blob is absent (older archives
    /// without a signing key export). Returns a hard error when the blob is
    /// present but cannot be decrypted (corruption or wrong DEK).
    ///
    /// Returns [`Zeroizing<Vec<u8>>`] so the plaintext PKCS#8 bytes are
    /// actively overwritten on drop (HEA-750 M1).
    fn load_signing_key(
        &self,
        realm_slug: &str,
        files: &std::collections::HashMap<String, Vec<u8>>,
        dek: Option<&[u8; 32]>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, BackupError> {
        let sk_key = format!("realms/{realm_slug}/signing_key.json");
        let Some(encrypted) = files.get(&sk_key) else {
            return Ok(None);
        };
        let Some(d) = dek else {
            // No DEK available — archive predates v2 or was opened without passphrase.
            return Ok(None);
        };
        let pkcs8 = decrypt_bytes(encrypted, d)?;
        debug!(slug = realm_slug, "signing_key restored from archive");
        Ok(Some(pkcs8))
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn import_realm_record(
        &self,
        req: &CreateRealmRequest,
        realm_id: RealmId,
        signing_key_pkcs8: Option<&[u8]>,
        opts: &ImportOptions,
        report: &mut ImportReport,
    ) -> Result<RealmId, BackupError> {
        match self
            .identity
            .import_realm(req, Some(realm_id.clone()), signing_key_pkcs8)
        {
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
                        // B3: refuse rather than half-execute. This arm used to
                        // `delete_realm` and then re-import. `delete_realm`
                        // backgrounds its cascade for a realm above
                        // `cascade_background_threshold` and returns `Ok` while
                        // it is still running, so the re-import raced its own
                        // deletion: the cascade then removed the realm record,
                        // the name index, the signing key and the freshly
                        // written user, credential and session keys underneath
                        // it (audit 2026-08-28 §3 B3, §4.9#2).
                        //
                        // Nothing has been deleted at this point, so the target
                        // is untouched. Restoring into an instance where the
                        // realm is absent is unaffected — the `import_realm`
                        // above succeeds and this arm is never reached.
                        Err(BackupError::RealmExists {
                            slug: req.name.clone(),
                        })
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
                slug: if client.slug.is_empty() {
                    None
                } else {
                    Some(client.slug)
                },
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
                Err(IdentityError::InvalidInput { reason })
                    if reason.contains("already exists") =>
                {
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
    BackupError::Io(std::io::Error::other(e.to_string()))
}

/// Trims leading/trailing ASCII whitespace from a byte slice.
fn trim_bytes(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|&b| !b.is_ascii_whitespace())
        .unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(0);
    if start >= end {
        &[]
    } else {
        &s[start..end]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    use crate::audit::EmbeddedAuditEngine;
    use crate::backup::export::encrypt_bytes;
    use crate::backup::{
        wrap_dek, BackupArchive, BackupExporter, BackupManifest, RealmManifest, RecordCounts,
    };
    use crate::core::{Clock, FakeClock, Timestamp};
    use crate::identity::{EmbeddedIdentityEngine, IdentityConfig};
    use crate::rbac::EmbeddedRbacEngine;
    use crate::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

    // ── Test harness ──────────────────────────────────────────────────────────

    struct TestRig {
        identity: Arc<dyn IdentityEngine>,
        rbac: Arc<dyn RbacEngine>,
        audit: Arc<dyn AuditEngine>,
        // Held to keep the temp directory alive for the duration of the test.
        _dir: TempDir,
    }

    fn make_rig() -> TestRig {
        let dir = TempDir::new().expect("tmpdir");
        let storage = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
                .expect("storage"),
        ) as Arc<dyn StorageEngine>;
        let clock =
            Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000))) as Arc<dyn Clock>;
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
        )) as Arc<dyn AuditEngine>;
        let identity = Arc::new(
            EmbeddedIdentityEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock),
                IdentityConfig::default(),
                Arc::clone(&audit),
            )
            .expect("identity engine"),
        ) as Arc<dyn IdentityEngine>;
        let rbac = Arc::new(EmbeddedRbacEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
        )) as Arc<dyn RbacEngine>;
        TestRig {
            identity,
            rbac,
            audit,
            _dir: dir,
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Returns the shared test passphrase used by all test archives.
    fn test_passphrase() -> SecretString {
        SecretString::new("hearth-import-test-passphrase".into())
    }

    /// Returns `ImportOptions` with the test passphrase pre-filled.
    ///
    /// `allow_missing_signing_key` is set because the shared `make_test_archive`
    /// helper writes keyless archives; the dedicated signing-key tests build
    /// their own options to exercise the fail-closed default (HEA-2168).
    fn opts_with_passphrase() -> ImportOptions {
        ImportOptions {
            dek_passphrase: Some(test_passphrase()),
            allow_missing_signing_key: true,
            ..Default::default()
        }
    }

    /// Creates a v2 encrypted test archive with two users.
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
            serde_json::to_string(&user1_json).expect("serialize user1"),
            serde_json::to_string(&user2_json).expect("serialize user2")
        );

        let realm_bytes = serde_json::to_vec(&realm_json).expect("serialize realm");
        let users_bytes = users_ndjson.into_bytes();

        // Generate a DEK and wrap it with the test passphrase.
        let dek = BackupExporter::generate_dek().expect("generate DEK");
        let passphrase = test_passphrase();
        let (wrapped_dek_b64, dek_wrapping_params) = wrap_dek(&dek, &passphrase).expect("wrap DEK");

        let realm_encrypted = encrypt_bytes(&realm_bytes, &dek).expect("encrypt realm");
        let users_encrypted = encrypt_bytes(&users_bytes, &dek).expect("encrypt users");

        // RealmManifest.realm_id is a plain String, so the prefixed form is fine.
        let realm_id_str = format!("realm_{realm_uuid}");
        let mut manifest = BackupManifest {
            format_version: crate::backup::MANIFEST_VERSION,
            hearth_version: "0.0.0-test".to_string(),
            created_at: Timestamp::from_micros(0),
            realms: vec![RealmManifest {
                realm_id: realm_id_str,
                slug: slug.to_string(),
                record_counts: RecordCounts {
                    users: 2,
                    ..Default::default()
                },
            }],
            checksums: std::collections::HashMap::new(),
            sections_encrypted: true,
            wrapped_dek_b64: Some(wrapped_dek_b64),
            signing_key_dek_b64: None,
            dek_wrapping_params: Some(dek_wrapping_params),
            detached_signature_b64: None,
        };

        let mut writer = BackupArchive::create(&archive_path).expect("create archive");
        writer
            .add_file(&format!("realms/{slug}/realm.json"), &realm_encrypted)
            .expect("add realm.json");
        writer
            .add_file(&format!("realms/{slug}/users.ndjson"), &users_encrypted)
            .expect("add users.ndjson");
        // Manually set checksums (finish guard requires sections_encrypted fields to be set)
        manifest.checksums = std::collections::HashMap::new();
        // Use a raw finish path that bypasses the guard by finishing directly.
        // The manifest already has sections_encrypted=true + wrapped_dek_b64 set.
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
        let importer = BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
        );

        let report = importer
            .import_realm(slug, &reader, &opts_with_passphrase())
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
        let importer = BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
        );
        let opts = ImportOptions {
            mode: RestoreMode::Skip,
            dek_passphrase: Some(test_passphrase()),
            allow_missing_signing_key: true,
            ..Default::default()
        };

        // First import — everything should be created.
        let r1 = importer
            .import_realm(slug, &reader, &opts)
            .expect("first import");
        assert_eq!(r1.realms.created, 1);
        assert_eq!(r1.users.created, 2);

        // Second import with same archive — realm and users already exist.
        let r2 = importer
            .import_realm(slug, &reader, &opts)
            .expect("second import");
        assert_eq!(r2.realms.skipped, 1, "realm should be skipped");
        // Users may be skipped (DuplicateEmail) or re-imported under a new realm.
        // Because the realm was skipped, the same realm_id is used → duplicate emails.
        assert_eq!(r2.users.skipped, 2, "users should be skipped on second run");
        assert_eq!(r2.conflicts.len(), 3, "1 realm + 2 user conflicts");
    }

    /// B3 (audit 2026-08-28 §3 B3, §4.9#2): `RestoreMode::Overwrite` over a
    /// realm that is already present is refused, and nothing is deleted.
    ///
    /// This test previously asserted that overwrite cascaded a realm delete and
    /// re-created the users. That is the behaviour that destroyed the realm:
    /// `delete_realm` backgrounds its cascade above
    /// `cascade_background_threshold` and returns while it is still running, so
    /// the re-import raced its own deletion. Of 1,160 recorded CLI runs none
    /// completed and 975 left the realm destroyed or truncated.
    #[test]
    fn overwrite_mode_refuses_over_a_live_realm() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();

        let realm_uuid = "00000000-0000-0000-0000-000000000030";
        let slug = "overwrite-realm";
        let archive_path = make_test_archive(&archive_dir, slug, realm_uuid);

        let reader = BackupArchive::open(&archive_path).expect("open");
        let importer = BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
        );

        // First import with Skip.
        importer
            .import_realm(slug, &reader, &opts_with_passphrase())
            .expect("first import");

        // Second import with Overwrite.
        let opts = ImportOptions {
            mode: RestoreMode::Overwrite,
            dek_passphrase: Some(test_passphrase()),
            allow_missing_signing_key: true,
            ..Default::default()
        };
        let err = importer
            .import_realm(slug, &reader, &opts)
            .expect_err("overwrite over a live realm must be refused");
        assert!(
            matches!(err, BackupError::RealmExists { slug: ref s } if s == slug),
            "expected RealmExists, got: {err:?}"
        );

        // Fail closed: the realm and its users must all survive the refusal.
        let realm_id = RealmId::new(uuid::Uuid::parse_str(realm_uuid).expect("parse uuid"));
        assert!(
            rig.identity
                .get_realm(&realm_id)
                .expect("get realm")
                .is_some(),
            "a refused overwrite must leave the realm in place"
        );
    }

    /// A dry run reports what the real restore would do. An overwrite over a
    /// live realm is refused, so the dry run must refuse too rather than report
    /// a success the restore would not deliver (audit 2026-08-28 §9 item 1).
    #[test]
    fn dry_run_overwrite_over_a_live_realm_predicts_the_refusal() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();

        let realm_uuid = "00000000-0000-0000-0000-000000000031";
        let slug = "dry-run-overwrite-realm";
        let archive_path = make_test_archive(&archive_dir, slug, realm_uuid);

        let reader = BackupArchive::open(&archive_path).expect("open");
        let importer = BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
        );

        importer
            .import_realm(slug, &reader, &opts_with_passphrase())
            .expect("first import");

        let opts = ImportOptions {
            mode: RestoreMode::Overwrite,
            dry_run: true,
            dek_passphrase: Some(test_passphrase()),
            allow_missing_signing_key: true,
            ..Default::default()
        };
        let err = importer
            .import_realm(slug, &reader, &opts)
            .expect_err("a dry-run overwrite over a live realm must predict the refusal");
        assert!(
            matches!(err, BackupError::RealmExists { .. }),
            "expected RealmExists, got: {err:?}"
        );
    }

    #[test]
    fn dry_run_writes_nothing() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();

        let realm_uuid = "00000000-0000-0000-0000-000000000040";
        let slug = "dry-run-realm";
        let archive_path = make_test_archive(&archive_dir, slug, realm_uuid);

        let reader = BackupArchive::open(&archive_path).expect("open");
        let importer = BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
        );
        let opts = ImportOptions {
            dry_run: true,
            dek_passphrase: Some(test_passphrase()),
            allow_missing_signing_key: true,
            ..Default::default()
        };

        let report = importer
            .import_realm(slug, &reader, &opts)
            .expect("dry run");
        assert_eq!(report.realms.created, 1);
        assert_eq!(report.users.created, 2);

        // Now do a real import — should succeed (nothing was written by dry run).
        let r2 = importer
            .import_realm(slug, &reader, &opts_with_passphrase())
            .expect("real import after dry run");
        assert_eq!(
            r2.realms.created, 1,
            "dry run must not have written the realm"
        );
        assert_eq!(r2.users.created, 2, "dry run must not have written users");
    }

    #[test]
    fn missing_passphrase_for_encrypted_archive_returns_error() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();

        let realm_uuid = "00000000-0000-0000-0000-000000000050";
        let slug = "encrypted-realm";
        let archive_path = make_test_archive(&archive_dir, slug, realm_uuid);

        let reader = BackupArchive::open(&archive_path).expect("open");
        let importer = BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
        );

        // No passphrase — must fail with a clear error.
        let result = importer.import_realm(slug, &reader, &ImportOptions::default());
        result.expect_err("import of encrypted archive without passphrase must fail");
    }

    #[test]
    fn wrong_passphrase_returns_error() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();

        let realm_uuid = "00000000-0000-0000-0000-000000000060";
        let slug = "wrong-pass-realm";
        let archive_path = make_test_archive(&archive_dir, slug, realm_uuid);

        let reader = BackupArchive::open(&archive_path).expect("open");
        let importer = BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
        );

        let wrong_opts = ImportOptions {
            dek_passphrase: Some(SecretString::new("definitely-wrong-passphrase".into())),
            ..Default::default()
        };
        let result = importer.import_realm(slug, &reader, &wrong_opts);
        result.expect_err("import with wrong passphrase must fail");
    }

    /// Fail-closed (HEA-2160): an archive containing a member this version does
    /// not recognize must abort the restore with a hard error — never a silent
    /// skip — and must not create the realm (no partial restore).
    #[test]
    fn unrecognized_member_is_hard_error() {
        let dir = TempDir::new().expect("tmpdir");
        let archive_path = dir.path().join("surprise.hearth-backup");
        let slug = "surprise-realm";
        let realm_uuid = "00000000-0000-0000-0000-0000000000aa";

        let realm_json = serde_json::json!({
            "id": realm_uuid,
            "name": slug,
            "status": "Active",
            "config": {},
            "created_at": 0,
            "updated_at": 0
        });

        let dek = BackupExporter::generate_dek().expect("dek");
        let (wrapped_dek_b64, dek_wrapping_params) =
            wrap_dek(&dek, &test_passphrase()).expect("wrap dek");
        let realm_enc =
            encrypt_bytes(&serde_json::to_vec(&realm_json).expect("ser"), &dek).expect("enc realm");
        // A member with a name the importer has never heard of.
        let surprise_enc = encrypt_bytes(b"{}\n", &dek).expect("enc surprise");

        let manifest = BackupManifest {
            format_version: crate::backup::MANIFEST_VERSION,
            hearth_version: "0.0.0-test".to_string(),
            created_at: Timestamp::from_micros(0),
            realms: vec![RealmManifest {
                realm_id: format!("realm_{realm_uuid}"),
                slug: slug.to_string(),
                record_counts: RecordCounts::default(),
            }],
            checksums: std::collections::HashMap::new(),
            sections_encrypted: true,
            wrapped_dek_b64: Some(wrapped_dek_b64),
            signing_key_dek_b64: None,
            dek_wrapping_params: Some(dek_wrapping_params),
            detached_signature_b64: None,
        };

        let mut writer = BackupArchive::create(&archive_path).expect("create archive");
        writer
            .add_file(&format!("realms/{slug}/realm.json"), &realm_enc)
            .expect("add realm.json");
        writer
            .add_file(
                &format!("realms/{slug}/future_feature.ndjson"),
                &surprise_enc,
            )
            .expect("add unknown member");
        writer.finish(manifest).expect("finish");

        let rig = make_rig();
        let reader = BackupArchive::open(&archive_path).expect("open");
        let importer = BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
        );

        let err = importer
            .import_realm(slug, &reader, &opts_with_passphrase())
            .expect_err("restore must fail closed on an unrecognized member");
        assert!(
            matches!(err, BackupError::UnrecognizedMember { ref path } if path.contains("future_feature.ndjson")),
            "expected UnrecognizedMember, got: {err:?}"
        );

        // Fail-closed: no realm may have been created.
        let realm_id = RealmId::new(uuid::Uuid::parse_str(realm_uuid).expect("parse uuid"));
        assert!(
            rig.identity
                .get_realm(&realm_id)
                .expect("get realm")
                .is_none(),
            "no realm must be created when the restore fails closed"
        );
    }

    /// Builds a v2 encrypted archive containing `realm.json` and an encrypted
    /// `signing_key.json` carrying `signing_key_pkcs8`. Used to prove the
    /// signing key round-trips on restore (HEA-2168).
    fn make_archive_with_signing_key(
        tmp: &TempDir,
        slug: &str,
        realm_uuid: &str,
        signing_key_pkcs8: &[u8],
    ) -> std::path::PathBuf {
        let archive_path = tmp.path().join("with-key.hearth-backup");

        let realm_json = serde_json::json!({
            "id": realm_uuid,
            "name": slug,
            "status": "Active",
            "config": {},
            "created_at": 0,
            "updated_at": 0
        });

        let dek = BackupExporter::generate_dek().expect("generate DEK");
        let passphrase = test_passphrase();
        let (wrapped_dek_b64, dek_wrapping_params) = wrap_dek(&dek, &passphrase).expect("wrap DEK");

        let realm_encrypted =
            encrypt_bytes(&serde_json::to_vec(&realm_json).expect("ser realm"), &dek)
                .expect("encrypt realm");
        let sk_encrypted = encrypt_bytes(signing_key_pkcs8, &dek).expect("encrypt signing key");

        let manifest = BackupManifest {
            format_version: crate::backup::MANIFEST_VERSION,
            hearth_version: "0.0.0-test".to_string(),
            created_at: Timestamp::from_micros(0),
            realms: vec![RealmManifest {
                realm_id: format!("realm_{realm_uuid}"),
                slug: slug.to_string(),
                record_counts: RecordCounts::default(),
            }],
            checksums: std::collections::HashMap::new(),
            sections_encrypted: true,
            wrapped_dek_b64: Some(wrapped_dek_b64),
            signing_key_dek_b64: None,
            dek_wrapping_params: Some(dek_wrapping_params),
            detached_signature_b64: None,
        };

        let mut writer = BackupArchive::create(&archive_path).expect("create archive");
        writer
            .add_file(&format!("realms/{slug}/realm.json"), &realm_encrypted)
            .expect("add realm.json");
        writer
            .add_file(&format!("realms/{slug}/signing_key.json"), &sk_encrypted)
            .expect("add signing_key.json");
        writer.finish(manifest).expect("finish archive");
        archive_path
    }

    /// HEA-2168 (red at af4edb59): an archive with no restorable signing key
    /// must be REFUSED by default — not silently restored with a fresh key that
    /// invalidates every pre-restore JWT. The refusal must also be fail-closed:
    /// no realm may be created.
    #[test]
    fn missing_signing_key_refused_by_default() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();

        let realm_uuid = "00000000-0000-0000-0000-0000000000b1";
        let slug = "no-key-realm";
        let archive_path = make_test_archive(&archive_dir, slug, realm_uuid);

        let reader = BackupArchive::open(&archive_path).expect("open");
        let importer = BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
        );

        // Default options: allow_missing_signing_key = false.
        let opts = ImportOptions {
            dek_passphrase: Some(test_passphrase()),
            ..Default::default()
        };

        let err = importer
            .import_realm(slug, &reader, &opts)
            .expect_err("restore must refuse an archive with no restorable signing key");
        assert!(
            matches!(err, BackupError::SigningKeyMissing { slug: ref s } if s == slug),
            "expected SigningKeyMissing, got: {err:?}"
        );

        // Fail-closed: nothing may have been written.
        let realm_id = RealmId::new(uuid::Uuid::parse_str(realm_uuid).expect("parse uuid"));
        assert!(
            rig.identity
                .get_realm(&realm_id)
                .expect("get realm")
                .is_none(),
            "no realm must be created when restore refuses on a missing signing key"
        );
    }

    /// The explicit `allow_missing_signing_key` override lets an operator
    /// restore a keyless archive anyway, accepting a freshly generated key.
    #[test]
    fn missing_signing_key_allowed_with_override() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();

        let realm_uuid = "00000000-0000-0000-0000-0000000000b2";
        let slug = "override-realm";
        let archive_path = make_test_archive(&archive_dir, slug, realm_uuid);

        let reader = BackupArchive::open(&archive_path).expect("open");
        let importer = BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
        );

        let opts = ImportOptions {
            dek_passphrase: Some(test_passphrase()),
            allow_missing_signing_key: true,
            ..Default::default()
        };

        let report = importer
            .import_realm(slug, &reader, &opts)
            .expect("override restore must succeed");
        assert_eq!(report.realms.created, 1, "realm should be created");
        assert_eq!(report.users.created, 2, "two users should be created");
    }

    /// The signing key round-trips when the archive carries it: the restored
    /// realm's PKCS#8 signing key must byte-for-byte equal the original, so
    /// every pre-backup JWT keeps validating (HEA-2168, HEA-745).
    #[test]
    fn signing_key_round_trips_when_present() {
        let realm_uuid = "00000000-0000-0000-0000-0000000000c3";
        let slug = "key-roundtrip-realm";
        let realm_id = RealmId::new(uuid::Uuid::parse_str(realm_uuid).expect("parse uuid"));

        // Produce a valid PKCS#8 signing key by creating a realm in a source
        // engine and exporting its key.
        let source = make_rig();
        let create_req = CreateRealmRequest {
            name: slug.to_string(),
            config: None,
        };
        source
            .identity
            .import_realm(&create_req, Some(realm_id.clone()), None)
            .expect("source realm");
        let original_pkcs8 = source
            .identity
            .export_realm_signing_key_pkcs8(&realm_id)
            .expect("export source signing key");

        // Bake it into an archive and restore into a fresh engine.
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let archive_path =
            make_archive_with_signing_key(&archive_dir, slug, realm_uuid, &original_pkcs8);

        let dest = make_rig();
        let reader = BackupArchive::open(&archive_path).expect("open");
        let importer = BackupImporter::new(
            Arc::clone(&dest.identity),
            Arc::clone(&dest.rbac),
            Arc::clone(&dest.audit),
        );

        // Default options (allow_missing_signing_key = false) must succeed here
        // because the key is present — the fail-closed guard must not fire.
        let opts = ImportOptions {
            dek_passphrase: Some(test_passphrase()),
            ..Default::default()
        };
        let report = importer
            .import_realm(slug, &reader, &opts)
            .expect("restore with signing key present must succeed");
        assert_eq!(report.realms.created, 1, "realm should be created");

        let restored_pkcs8 = dest
            .identity
            .export_realm_signing_key_pkcs8(&realm_id)
            .expect("export restored signing key");
        assert_eq!(
            restored_pkcs8, original_pkcs8,
            "restored signing key must byte-for-byte equal the original"
        );
    }
}
