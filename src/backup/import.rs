//! Backup restore engine — `BackupImporter`.
//!
//! Reads a [`BackupArchive`] and drives the existing `import_*` engine
//! methods to restore realm entities. All writes go through the engine
//! trait; no raw storage access.

use std::io::{BufRead, Read};
use std::sync::Arc;

use secrecy::SecretString;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::audit::{AuditEngine, AuditEvent, AuditImportPlan, ChainVerifier};
use crate::core::{ClientId, ImportOutcome, RealmId};
use crate::identity::federation::IdpConfig;
use crate::identity::{
    AccessTokenAuthorization, AgentExport, ApplicationStatus, ClientTrustLevel, ConsentExport,
    CreateRealmRequest, FederationLinkExport, IdentityEngine, IdentityError, ImportClientRequest,
    ImportUserRequest, MfaFactorExport, Organization, OrganizationInvitation,
    OrganizationMembership, RawCredential, Realm, RestoredUserState, RetiringSigningKeyExport,
    RevocationExport, ScimMappingExport, User,
};
use crate::rbac::{
    Group, GroupMembershipEdge, PermissionRecord, RbacEngine, Role, RoleAssignment, ScopeExport,
};
use crate::webhook::{WebhookEngine, WebhookSubscription};

use zeroize::{Zeroize, Zeroizing};

use super::{decrypt_member, unwrap_dek, ArchiveReader, BackupError, DecryptReader};

/// Every archive member (relative to `realms/<slug>/`) the importer knows how
/// to restore. A member NOT in this list is a hard error — see the fail-closed
/// check in [`BackupImporter::import_realm`] (HEA-2160).
///
/// Keep in sync with the members written by
/// [`BackupExporter::export_realm`](super::BackupExporter::export_realm).
pub(crate) const RECOGNIZED_MEMBERS: &[&str] = &[
    "realm.json",
    "users.ndjson",
    "mfa_factors.ndjson",
    "clients.ndjson",
    "roles.ndjson",
    "permissions.ndjson",
    "groups.ndjson",
    "group_memberships.ndjson",
    "assignments.ndjson",
    "scopes.ndjson",
    "organizations.ndjson",
    "organization_memberships.ndjson",
    "consents.ndjson",
    "agents.ndjson",
    "identity_providers.ndjson",
    "federation_links.ndjson",
    // Older archives only: the identity engine's webhook store, which never
    // delivered (#617). Recognised so that the restore can skip and count it.
    "webhooks.ndjson",
    "webhook_subscriptions.ndjson",
    "saml_signing_key.json",
    "scim_mappings.ndjson",
    "invitations.ndjson",
    "revocations.ndjson",
    "retiring_signing_keys.json",
    "signing_key.json",
    "id_token_signing_key.json",
    "retiring_id_token_signing_keys.json",
    "audit.ndjson",
    "audit_chain.json",
];

/// The members of `realms/<slug>/` that the import pass of a restore reads,
/// in the order it imports them (#867). It is the order the exporter writes
/// them, so the import pass reads the archive once.
///
/// The audit events come first: into an EMPTY realm they keep their original
/// timestamps ahead of the fresh events the other imports emit. Records come
/// after the records they reference. `realm.json`, `signing_key.json`,
/// `id_token_signing_key.json` and `audit_chain.json` are not in this list:
/// the check pass keeps them.
const RESTORE_ORDER: &[&str] = &[
    "audit.ndjson",
    "users.ndjson",
    "mfa_factors.ndjson",
    "clients.ndjson",
    "permissions.ndjson",
    "roles.ndjson",
    "groups.ndjson",
    "organizations.ndjson",
    "assignments.ndjson",
    "group_memberships.ndjson",
    "organization_memberships.ndjson",
    "consents.ndjson",
    "agents.ndjson",
    "identity_providers.ndjson",
    "federation_links.ndjson",
    "webhooks.ndjson",
    "webhook_subscriptions.ndjson",
    "saml_signing_key.json",
    "scim_mappings.ndjson",
    "invitations.ndjson",
    "revocations.ndjson",
    "retiring_signing_keys.json",
    "retiring_id_token_signing_keys.json",
    "scopes.ndjson",
];

/// The members the check pass keeps instead of the import pass reading them.
#[cfg(test)]
const CHECKED_MEMBERS: &[&str] = &[
    "realm.json",
    "signing_key.json",
    "id_token_signing_key.json",
    "audit_chain.json",
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
    /// Allow an `Overwrite` restore of the system realm to replace a **live**
    /// system signing key — the key every live operator token is signed with.
    ///
    /// `Overwrite` alone replaces the system realm's operators but keeps its
    /// live key; replacing it too takes this explicit opt-in (the CLI's
    /// `--replace-system-signing-key`; the HTTP route never sets it). A seeded
    /// system realm with no operator (a rebuilt data directory) takes the
    /// archived key regardless: its key has signed nothing. Either way, a key
    /// the target's system realm has rotated away from is never reinstalled.
    pub replace_live_system_signing_key: bool,
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
    /// Outcome counts for group-membership edges (OpenSpec 26.40). Before
    /// this member existed, groups restored empty and every permission a user
    /// held *through* a group silently vanished.
    pub group_memberships: EntityCounts,
    /// Outcome counts for role-assignment records.
    pub assignments: EntityCounts,
    /// Outcome counts for OAuth scope records.
    pub scopes: EntityCounts,
    /// Outcome counts for organization records.
    pub organizations: EntityCounts,
    /// Outcome counts for organization-membership records (OpenSpec 26.40).
    pub organization_memberships: EntityCounts,
    /// Outcome counts for OAuth consent records (OpenSpec 26.40).
    pub consents: EntityCounts,
    /// Outcome counts for agents, credentials included (OpenSpec 26.40).
    pub agents: EntityCounts,
    /// Outcome counts for external IdP connectors (OpenSpec 26.40).
    pub identity_providers: EntityCounts,
    /// Outcome counts for federation account links (OpenSpec 26.40).
    pub federation_links: EntityCounts,
    /// Webhooks from the identity engine's old webhook store, in archives
    /// written before #654. Those webhooks never delivered (#617), so every
    /// one is counted as skipped and none is restored.
    pub webhooks: EntityCounts,
    /// Outcome counts for webhook subscriptions, with their signing
    /// secrets (#654).
    pub webhook_subscriptions: EntityCounts,
    /// Outcome counts for SCIM `externalId` mappings (OpenSpec 26.40).
    pub scim_mappings: EntityCounts,
    /// Outcome counts for organization invitations (OpenSpec 26.40).
    pub invitations: EntityCounts,
    /// Outcome counts for token revocations: revoked JTIs, blocked DPoP keys
    /// and revoked AAT JTIs. `skipped` includes JTIs whose token had already
    /// expired by the time of the restore (audit GA 2026-09-28 M3).
    pub revocations: EntityCounts,
    /// Outcome counts for retiring signing keys. `skipped` counts keys whose
    /// grace window had already closed by the time of the restore
    /// (OpenSpec 26.40).
    pub retiring_signing_keys: EntityCounts,
    /// Outcome for the realm's RS256 ID-token signing key (0 or 1), task 26.55.
    pub id_token_signing_key: EntityCounts,
    /// Outcome counts for retiring RS256 ID-token signing keys (task 26.55).
    pub retiring_id_token_signing_keys: EntityCounts,
    /// Outcome counts for restored audit events.
    pub audit_events: EntityCounts,
    /// Whether the archive's audit hashes were checked against the source
    /// chain before being re-signed under the destination realm's key.
    ///
    /// `false` when the realm carried no audit events, or when the archive
    /// predates `audit_chain.json` — in which case the restore logs a warning
    /// and the restored chain attests only to the restore, not to the source
    /// (audit 2026-08-28 §4.14#5).
    pub audit_chain_verified: bool,
    /// Conflicts encountered in Skip / Merge mode, and every client that was
    /// refused rather than restored weaker than its source (a missing or
    /// unverifiable credential), each with its reason.
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

/// One line of `users.ndjson` (format v4, #867): the user record, with its
/// password credential in the field `credential` when it has one.
#[derive(Deserialize)]
struct BackupUserLine {
    #[serde(flatten)]
    user: User,
    #[serde(default)]
    credential: Option<BackupCredential>,
}

impl BackupUserLine {
    /// The import request that restores this line.
    ///
    /// # Errors
    ///
    /// [`BackupError::Engine`] when the credential names another user.
    fn into_request(self) -> Result<ImportUserRequest, BackupError> {
        let BackupUserLine { user, credential } = self;
        let credential = credential.map(|c| c.into_raw(&user)).transpose()?;
        Ok(ImportUserRequest {
            id: Some(user.id().clone()),
            email: user.email().to_string(),
            display_name: user.display_name().to_string(),
            first_name: user.first_name().to_string(),
            last_name: user.last_name().to_string(),
            status: user.status(),
            credential,
            attributes: user.attributes().clone(),
            restored: Some(RestoredUserState {
                required_actions: user.required_actions().to_vec(),
                email_verified: user.email_verified(),
                email_otp_enabled: user.email_otp_enabled(),
                created_at: user.created_at(),
                updated_at: user.updated_at(),
            }),
        })
    }
}

/// Most lines of `users.ndjson` a restore reads before it imports them
/// together (#887).
///
/// [`IdentityEngine::import_users`] shares each fsync among the users of a
/// batch. The batch also bounds the users the import pass holds: the restore
/// streams the archive (#867), so its memory must not grow with the realm.
const RESTORE_USER_BATCH: usize = 512;

/// The password credential on a line of `users.ndjson`.
#[derive(Deserialize)]
struct BackupCredential {
    /// The user ID, bare or prefixed (`"user_<uuid>"`). It must be the ID of
    /// the user on the same line.
    user_id: String,
    /// PHC-formatted password hash.
    phc_string: String,
    /// Original creation timestamp in Unix microseconds, if known.
    #[serde(default)]
    created_at_micros: Option<i64>,
}

impl BackupCredential {
    /// Refuses a credential that names a user other than `user`.
    ///
    /// # Errors
    ///
    /// [`BackupError::Engine`] when the credential names another user.
    fn check_owner(&self, user: &User) -> Result<(), BackupError> {
        let owner = self.user_id.strip_prefix("user_").unwrap_or(&self.user_id);
        if owner != user.id().as_uuid().to_string() {
            return Err(BackupError::Engine(
                "a line of users.ndjson carries the credential of another user".to_string(),
            ));
        }
        Ok(())
    }

    /// The credential to restore for `user`.
    ///
    /// # Errors
    ///
    /// [`BackupError::Engine`] when the credential names another user: the
    /// line is not one an export writes.
    fn into_raw(self, user: &User) -> Result<RawCredential, BackupError> {
        self.check_owner(user)?;
        Ok(RawCredential {
            phc_string: self.phc_string,
            created_at_micros: self.created_at_micros,
        })
    }
}

/// The client fields a restore carries, read from an `OAuthClient` JSON line
/// (`clients.ndjson`). Field names match `OAuthClient`'s serde output.
///
/// Every credential and security field is read: the stored secret hash, the
/// assertion key, the JWKS / `jwks_uri`, the DPoP requirement. A restore that dropped
/// them re-created every confidential and `private_key_jwt` client as a
/// PUBLIC client — one anyone knowing its `client_id` could act as.
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
    /// `false` on a record written before `grant_types` governed the
    /// refresh-token grant (GA audit M7): such a client received refresh
    /// tokens whatever it listed, and is restored with `refresh_token` added
    /// so the restore does not silently take them away.
    #[serde(default)]
    grant_types_enforced: bool,
    #[serde(default)]
    trust_level: ClientTrustLevel,
    #[serde(default)]
    declared_scopes: Vec<String>,
    #[serde(default)]
    consent_spans_orgs: bool,
    /// `"RS256"` / `"EdDSA"`; absent in archives written before task 26.55
    /// (and on legacy client records), which restore as EdDSA.
    #[serde(default)]
    id_token_signed_response_alg: Option<String>,
    /// The stored hash (`$argon2id$…` or `$hearth-sha256$v=1$…`), restored
    /// verbatim.
    #[serde(default)]
    client_secret_hash: Option<String>,
    #[serde(default = "default_true")]
    require_consent: bool,
    #[serde(default)]
    client_logo_url: Option<String>,
    #[serde(default)]
    status: ApplicationStatus,
    #[serde(default)]
    backchannel_logout_uri: Option<String>,
    #[serde(default)]
    frontchannel_logout_uri: Option<String>,
    #[serde(default)]
    post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    cors_origins: Vec<String>,
    #[serde(default)]
    assertion_public_key: Option<String>,
    #[serde(default)]
    access_token_authorization: AccessTokenAuthorization,
    #[serde(default)]
    jwks: Option<String>,
    #[serde(default)]
    jwks_uri: Option<String>,
    #[serde(default)]
    dpop_bound_access_tokens: bool,
    #[serde(default)]
    mfa_required: Option<bool>,
    /// When the client was registered (#675). `None` only for a line that
    /// has no `created_at`; the restore then stamps the restore time.
    #[serde(default)]
    created_at: Option<crate::core::Timestamp>,
    /// #780. Absent in archives written before the field, which restore as
    /// `true`.
    #[serde(default = "default_true")]
    require_pkce: bool,
}

fn default_true() -> bool {
    true
}

/// Grants only ever issued to a client that authenticates.
const AUTHENTICATED_ONLY_GRANTS: [&str; 2] = [
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
];

impl BackupClient {
    /// Whether the record holds any client credential.
    fn holds_a_credential(&self) -> bool {
        self.client_secret_hash.is_some()
            || self.assertion_public_key.is_some()
            || self.jwks.is_some()
            || self.jwks_uri.is_some()
    }

    /// Why this record must not be restored, if it cannot be restored as
    /// strong as its source.
    ///
    /// A record with no credential whose grants are only issued to an
    /// authenticating client is one whose credential the archive did not
    /// carry (a hand-built or pre-release archive; every 1.x export writes the
    /// full record). Restoring it would create a PUBLIC client in place of a
    /// confidential one, so it is refused and reported instead.
    fn missing_credential(&self) -> Option<String> {
        if self.holds_a_credential() {
            return None;
        }
        let grant = self
            .grant_types
            .iter()
            .find(|g| AUTHENTICATED_ONLY_GRANTS.contains(&g.as_str()))?;
        Some(format!(
            "the archived client record carries no credential (no client_secret_hash, \
             assertion key or JWKS), yet its '{grant}' grant is only issued to a client that \
             authenticates; restoring it would create a public client. Register the client \
             again (or restore from an archive that carries its credential)"
        ))
    }
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
    webhooks: Arc<dyn WebhookEngine>,
}

impl BackupImporter {
    /// Creates a new importer backed by the given engine instances.
    ///
    /// `webhooks` must be the engine that the dispatcher reads, so that the
    /// restored subscriptions deliver events (#654).
    pub fn new(
        identity: Arc<dyn IdentityEngine>,
        rbac: Arc<dyn RbacEngine>,
        audit: Arc<dyn AuditEngine>,
        webhooks: Arc<dyn WebhookEngine>,
    ) -> Self {
        Self {
            identity,
            rbac,
            audit,
            webhooks,
        }
    }

    /// Refuses, before anything is written, an archive that carries a realm
    /// outside `opts.allowed_realm` among the realms `slugs` names.
    ///
    /// [`import_realm`](Self::import_realm) makes the same check for its own
    /// realm, but a caller restoring several realms one `import_realm` at a
    /// time would have written every realm listed before the refused one.
    /// Call this first with every slug the restore will import. Each realm's
    /// ID is read from its decrypted `realm.json`, never from the
    /// caller-supplied manifest. A no-op when `opts.allowed_realm` is `None`.
    pub fn authorize_realms(
        &self,
        slugs: &[String],
        reader: &ArchiveReader,
        opts: &ImportOptions,
    ) -> Result<(), BackupError> {
        let Some(allowed) = &opts.allowed_realm else {
            return Ok(());
        };
        let dek = Self::archive_dek(reader, opts)?;
        for slug in slugs {
            let member = format!("realms/{slug}/realm.json");
            let raw = reader.read_file(&member)?.ok_or_else(|| {
                BackupError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("realm.json not found for slug '{slug}'"),
                ))
            })?;
            let bytes = match &dek {
                Some(d) => decrypt_member(&member, &raw, d)?,
                None => Zeroizing::new(raw),
            };
            let realm: Realm = serde_json::from_slice(&bytes)?;
            if realm.id() != allowed {
                return Err(BackupError::RealmNotPermitted { slug: slug.clone() });
            }
        }
        Ok(())
    }

    /// Unwraps the archive's data-encryption key, or `None` for an archive
    /// whose sections are not encrypted.
    fn archive_dek(
        reader: &ArchiveReader,
        opts: &ImportOptions,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, BackupError> {
        if !reader.manifest.sections_encrypted {
            return Ok(None);
        }
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
        Ok(Some(unwrap_dek(wrapped_b64, params, passphrase)?))
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
    /// The restore streams the archive (#867): it holds one decrypted chunk
    /// and one record at a time, whatever the size of the realm. It reads the
    /// archive twice. The first pass checks every member before anything is
    /// written (see [`check_realm`](Self::check_realm)); the second imports the
    /// members in [`RESTORE_ORDER`], which is the order the exporter writes
    /// them, so the second pass also reads the archive once.
    ///
    /// The two passes must read the same bytes: give a reader on a private
    /// copy of the archive (the CLI copies the file, the HTTP route spools
    /// the upload to an anonymous temporary file). An encrypted member is
    /// authenticated again in the second pass, but an unencrypted archive
    /// that changes between the passes is imported as it is then.
    ///
    /// The extra memory does not grow with the archive. It grows with the
    /// target realm in two places: the ids of the audit events that the
    /// realm already holds (for the deduplication), and the conflicts of
    /// the report.
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
        let dek = Self::archive_dek(reader, opts)?;
        let dek = dek.as_deref();

        // ── Check pass: every member, before any write ─────────────────────
        //
        // Fail closed on any unrecognized member (HEA-2160), authenticate
        // every chunk of every member, keep the small members the checks
        // below need, find RS256 clients and check the audit chain. Nothing
        // is written until the whole archive passed, so a changed, cut or
        // unknown member leaves the target untouched.
        let chain_declared = reader
            .realms()
            .iter()
            .find(|r| r.slug == realm_slug)
            .is_some_and(|r| r.audit_chain_included);
        let checked = Self::check_realm(realm_slug, reader, dek, chain_declared)?;

        // ── Signing key (decrypted, optional) ──────────────────────────────
        //
        // The archive's signing_key.json is decrypted *before* creating the
        // realm so that `import_realm` can install the original key atomically
        // with the realm record (preserving the create_realm invariant that a
        // realm always has a usable key). A decrypt failure is fatal: silently
        // generating a fresh key would invalidate every JWT issued under this
        // realm prior to backup (the bug HEA-745 fixes).
        //
        // The fail-closed check runs BEFORE any writes (audit events, realm
        // record, users, …) so a refusal leaves the target untouched — no
        // partial restore (HEA-2168).
        let signing_key_pkcs8 = checked.signing_key.as_ref();
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
        } else {
            debug!(slug = realm_slug, "signing_key restored from archive");
        }

        // ── RS256 ID-token key (task 26.55), same fail-closed rule ──────────
        //
        // An archive whose clients receive RS256 ID tokens must carry the key
        // that signed them. Restoring without it would provision a fresh RSA
        // key on the first RS256 client import, and every ID token issued
        // before the backup would stop verifying. Checked before any write.
        let id_token_rsa_pkcs8 = checked.id_token_key.as_ref();
        if id_token_rsa_pkcs8.is_none() && checked.has_rs256_clients {
            if !opts.allow_missing_signing_key {
                return Err(BackupError::IdTokenSigningKeyMissing {
                    slug: realm_slug.to_string(),
                });
            }
            warn!(
                slug = realm_slug,
                "RS256 ID-token key not restored — proceeding under allow_missing_signing_key: \
                 ID tokens issued before the backup will not verify against the freshly \
                 generated key"
            );
        }

        // Parse realm.json — required.
        //
        // This runs BEFORE any write so the realm-authorization check below can
        // refuse with nothing written. The realm ID is taken from the decrypted
        // `realm.json`, never from the manifest: the manifest is caller-supplied
        // and an archive may name one realm in its manifest and carry another
        // (audit 2026-08-28 §3 B1, §4.1#1).
        let realm_bytes = checked.realm_json.as_ref().ok_or_else(|| {
            BackupError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("realm.json not found for slug '{realm_slug}'"),
            ))
        })?;
        let realm: Realm = serde_json::from_slice(realm_bytes)?;

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

        // ── Keys the realm rotated away from (before any write) ─────────────
        //
        // A realm restored as new (absent here, or deleted since the archive
        // was made) takes the archive's active keys. The target may have
        // rotated away from them — above all by a revoking rotation after a
        // leak — and its record of that outlives the realm, so a refusal here
        // leaves the target untouched instead of failing half-way through.
        // A realm that exists keeps its own active keys (skip/merge) or is
        // refused (overwrite); the retiring-key importers below check theirs.
        if !realm.id().as_uuid().is_nil()
            && self
                .identity
                .get_realm(realm.id())
                .map_err(identity_to_backup_err)?
                .is_none()
        {
            self.identity
                .check_archived_realm_keys(
                    realm.id(),
                    signing_key_pkcs8.map(|z| z.as_slice()),
                    id_token_rsa_pkcs8.map(|z| z.as_slice()),
                )
                .map_err(identity_to_backup_err)?;
        }

        // ── System realm signing key (before any other write) ───────────────
        //
        // The system realm (operator-console accounts) exists in every store —
        // engine construction seeds it — so there is no realm record to
        // create; its contents are imported into it below, with the same
        // member importers and validation as any other realm. Only its signing
        // key needs its own path, and it runs first so that a key the engine
        // refuses (one the target rotated away from) fails the restore with
        // nothing written. Reaching this point already required system-realm
        // authority: a caller scoped to a tenant realm was refused just above.
        if realm.id().as_uuid().is_nil() {
            self.restore_system_realm_key(
                signing_key_pkcs8.map(|z| z.as_slice()),
                opts,
                &mut report,
            )?;
        }

        if let Some(audit) = &checked.audit {
            report.audit_chain_verified = audit.chain_verified;
            if opts.dry_run {
                report.audit_events.created += audit.events;
            }
        }

        // ── Import pass ─────────────────────────────────────────────────────
        let target_name = opts.realm_target.as_deref().unwrap_or_else(|| realm.name());
        let mut restore = RealmRestore {
            importer: self,
            opts,
            dek,
            realm_slug,
            realm: &realm,
            create_req: CreateRealmRequest {
                name: target_name.to_string(),
                config: Some(realm.config().clone()),
            },
            signing_key_pkcs8: signing_key_pkcs8.map(|z| z.as_slice()),
            id_token_rsa_pkcs8: id_token_rsa_pkcs8.map(|z| z.as_slice()),
            audit: checked.audit,
            restored_realm_id: None,
            report,
        };
        let prefix = format!("realms/{realm_slug}/");
        let paths: Vec<String> = RESTORE_ORDER
            .iter()
            .filter(|member| checked.present.contains(*member))
            // A dry run counted the audit events in the check pass.
            .filter(|member| !(opts.dry_run && **member == "audit.ndjson"))
            .map(|member| format!("{prefix}{member}"))
            .collect();
        reader.visit_members_in_order(&paths, &mut |path, raw| {
            let name = path.strip_prefix(&prefix).unwrap_or(path);
            restore.member(name, path, raw)
        })?;
        // A realm with no member after its audit events.
        restore.restored_realm()?;
        Ok(restore.report)
    }

    /// The check pass of [`import_realm`](Self::import_realm): one pass over
    /// every member of the realm, before anything is written (#867).
    ///
    /// - A member this version does not know, or a member that is in the
    ///   archive twice, is refused (HEA-2160).
    /// - Every chunk of every member is decrypted and authenticated, so a
    ///   changed, reordered or cut chunk is refused before any record of the
    ///   archive is written. (A restore that decrypted each member whole had
    ///   that promise for one member at a time.)
    /// - `realm.json`, the signing keys and the audit chain material are kept:
    ///   they are small, and the checks before the first write need them.
    /// - Every client line is parsed, to find clients that receive RS256 ID
    ///   tokens.
    /// - Every audit event is checked against the archive's chain material,
    ///   one at a time (audit 2026-08-28 §4.14#5), and counted.
    fn check_realm(
        realm_slug: &str,
        reader: &ArchiveReader,
        dek: Option<&[u8; 32]>,
        chain_declared: bool,
    ) -> Result<CheckedRealm, BackupError> {
        let prefix = format!("realms/{realm_slug}/");
        let mut checked = CheckedRealm::default();
        let mut chain: Option<AuditChainCheck> = None;
        // The audit events came before the chain material: check them again.
        let mut recheck_audit = false;
        reader.visit_realm_members(realm_slug, &mut |path, raw| {
            let name = path.strip_prefix(&prefix).unwrap_or(path);
            let Some(name) = RECOGNIZED_MEMBERS.iter().copied().find(|m| *m == name) else {
                return Err(BackupError::UnrecognizedMember {
                    path: path.to_string(),
                });
            };
            if !checked.present.insert(name) {
                return Err(BackupError::Engine(format!(
                    "archive member {path} is in the archive twice; refusing to restore an \
                     archive that was changed after it was written"
                )));
            }
            let mut member = open_member(path, raw, dek)?;
            match name {
                "realm.json" => checked.realm_json = Some(read_small(&mut *member, path)?),
                // Without the DEK the keys cannot be read (HEA-2168).
                "signing_key.json" => {
                    let key = read_small(&mut *member, path)?;
                    checked.signing_key = dek.map(|_| key);
                }
                "id_token_signing_key.json" => {
                    let key = read_small(&mut *member, path)?;
                    checked.id_token_key = dek.map(|_| key);
                }
                "audit_chain.json" => {
                    let material: crate::audit::AuditChainMaterial =
                        serde_json::from_slice(&read_small(&mut *member, path)?)?;
                    chain = Some(AuditChainCheck::new(&material)?);
                    recheck_audit = checked.audit.is_some();
                }
                "clients.ndjson" => {
                    for client in NdjsonRecords::<BackupClient>::new(&mut *member) {
                        if client?.id_token_signed_response_alg.as_deref() == Some("RS256") {
                            checked.has_rs256_clients = true;
                        }
                    }
                }
                "audit.ndjson" => {
                    let mut verifier = chain.as_ref().map(AuditChainCheck::verifier);
                    let audit = check_audit_events(&mut *member, verifier.as_mut())?;
                    checked.audit = Some(CheckedAudit {
                        chain_verified: verifier.is_some(),
                        ..audit
                    });
                }
                _ => check_records(name, &mut *member)?,
            }
            Ok(())
        })?;

        if let Some(audit) = checked.audit.as_mut() {
            match &chain {
                Some(chain) if recheck_audit => {
                    // A hand-built archive with audit_chain.json after
                    // audit.ndjson: one more pass, over the events only.
                    let path = format!("{prefix}audit.ndjson");
                    reader.visit_members_in_order(
                        std::slice::from_ref(&path),
                        &mut |path, raw| {
                            let mut member = open_member(path, raw, dek)?;
                            check_audit_events(&mut *member, Some(&mut chain.verifier()))?;
                            Ok(())
                        },
                    )?;
                    audit.chain_verified = true;
                }
                Some(_) => {}
                None if chain_declared => {
                    // The manifest says the file was written. Its absence is
                    // tampering, not an old archive.
                    return Err(BackupError::Engine(format!(
                        "manifest declares audit chain material for realm '{realm_slug}' but \
                         audit_chain.json is missing from the archive"
                    )));
                }
                None => {
                    warn!(
                        realm = %realm_slug,
                        events = audit.events,
                        "archive carries audit events with no chain material; their source \
                         hashes cannot be checked. Re-export with a current Hearth to get a \
                         verifiable audit section."
                    );
                }
            }
        }
        Ok(checked)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Restores the system realm's signing key, reported in `report.realms`
    /// (the system realm's record is implicit, so its key IS its realm-level
    /// outcome).
    ///
    /// The engine replaces the key only when the target's system realm holds
    /// no operator account (the freshly seeded state of a rebuilt data
    /// directory), or when `opts.mode` is `Overwrite` **and**
    /// `opts.replace_live_system_signing_key` is set; otherwise the live key is
    /// kept and the conflict reported. A key the target rotated away from is
    /// refused outright (an error: nothing has been written yet). With no
    /// archived key (possible only under `allow_missing_signing_key`, checked
    /// by the caller) the target's key is kept.
    fn restore_system_realm_key(
        &self,
        pkcs8: Option<&[u8]>,
        opts: &ImportOptions,
        report: &mut ImportReport,
    ) -> Result<(), BackupError> {
        let Some(pkcs8) = pkcs8 else {
            report.realms.skipped += 1;
            report.conflicts.push(Conflict {
                entity_type: "realm".to_string(),
                identifier: crate::identity::keys::SYSTEM_REALM_NAME.to_string(),
                reason: "the archive carries no system signing key; the target's system \
                         signing key was kept (allow_missing_signing_key)"
                    .to_string(),
            });
            return Ok(());
        };
        let replace_live =
            opts.mode == RestoreMode::Overwrite && opts.replace_live_system_signing_key;
        // A dry run reports what the real run would do — the same outcome, or
        // the same refusal — without writing.
        let outcome = if opts.dry_run {
            self.identity
                .preview_system_realm_signing_key(pkcs8, replace_live)
        } else {
            self.identity
                .import_system_realm_signing_key(pkcs8, replace_live)
        };
        match outcome {
            Ok(ImportOutcome::Skipped) => {
                report.realms.skipped += 1;
                report.conflicts.push(Conflict {
                    entity_type: "realm".to_string(),
                    identifier: crate::identity::keys::SYSTEM_REALM_NAME.to_string(),
                    reason: "the target's system signing key was kept: it is already the \
                             archived key, or the system realm holds operator accounts (to \
                             replace a live key, restore from the CLI in overwrite mode with \
                             --replace-system-signing-key)"
                        .to_string(),
                });
                Ok(())
            }
            Ok(outcome) => {
                tally(&mut report.realms, outcome);
                Ok(())
            }
            Err(e) => {
                report.realms.errored += 1;
                Err(BackupError::Engine(format!(
                    "system realm signing key not restored: {e}"
                )))
            }
        }
    }

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

    /// Restores a batch of lines of `users.ndjson`: the users and their
    /// password credentials (#867).
    ///
    /// A tenant realm's batch goes to [`IdentityEngine::import_users`], which
    /// shares each fsync among many users: one user per durable write took
    /// about 18 hours for 10M users (#887). Operator accounts go through
    /// `import_admin_user` one by one — the only import path into the system
    /// realm, with `import_user`'s validation.
    fn import_user_batch(
        &self,
        requests: &[ImportUserRequest],
        realm_id: &RealmId,
        opts: &ImportOptions,
        report: &mut ImportReport,
    ) -> Result<(), BackupError> {
        if opts.dry_run {
            report.users.created += requests.len() as u64;
            return Ok(());
        }
        if realm_id.as_uuid().is_nil() {
            for req in requests {
                let result = self.identity.import_admin_user(req);
                self.settle_user_import(req, result, realm_id, opts, report)?;
            }
            return Ok(());
        }
        if requests.is_empty() {
            return Ok(());
        }
        let results = self.identity.import_users(realm_id, requests);
        if results.len() != requests.len() {
            return Err(BackupError::Engine(format!(
                "the identity engine returned {} results for {} imported users",
                results.len(),
                requests.len()
            )));
        }
        for (req, result) in requests.iter().zip(results) {
            self.settle_user_import(req, result, realm_id, opts, report)?;
        }
        Ok(())
    }

    /// Counts the outcome of one user import into `report`. A user whose
    /// email is already stored is skipped and reported, or in overwrite mode
    /// replaces the stored user.
    fn settle_user_import(
        &self,
        req: &ImportUserRequest,
        result: Result<User, IdentityError>,
        realm_id: &RealmId,
        opts: &ImportOptions,
        report: &mut ImportReport,
    ) -> Result<(), BackupError> {
        match result {
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
                                let again = if realm_id.as_uuid().is_nil() {
                                    self.identity.import_admin_user(req)
                                } else {
                                    self.identity.import_user(realm_id, req)
                                };
                                again.map_err(identity_to_backup_err)?;
                                report.users.overwritten += 1;
                            }
                            Ok(None) => {
                                warn!(email = %crate::identity::email::mask_email_address(&req.email), "overwrite: user not found by email after DuplicateEmail");
                                report.users.errored += 1;
                            }
                            Err(e) => {
                                warn!(email = %crate::identity::email::mask_email_address(&req.email), err = %e, "overwrite: could not look up existing user");
                                report.users.errored += 1;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(email = %crate::identity::email::mask_email_address(&req.email), err = %e, "import_user failed");
                report.users.errored += 1;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // one field mapping per archived client field
    /// Restores one line of `clients.ndjson`.
    fn import_client_line(
        &self,
        client: BackupClient,
        realm_id: &RealmId,
        opts: &ImportOptions,
        report: &mut ImportReport,
    ) -> Result<(), BackupError> {
        let client_id_str = client.client_id.clone();

        if let Some(reason) = client.missing_credential() {
            warn!(client_id = %client_id_str, "refusing to restore client: {reason}");
            report.clients.errored += 1;
            report.conflicts.push(Conflict {
                entity_type: "client".to_string(),
                identifier: client_id_str,
                reason,
            });
            return Ok(());
        }

        // Parse the prefixed client ID into a `ClientId`.
        let parsed_id: Option<ClientId> = client.client_id.parse().ok();

        let req = ImportClientRequest {
            id: parsed_id,
            client_name: client.client_name.clone(),
            redirect_uris: client.redirect_uris,
            // No plaintext exists; the stored hash is restored verbatim.
            client_secret: None,
            client_secret_hash: client.client_secret_hash,
            grant_types: {
                let mut grants = client.grant_types;
                // Only the grants that ever minted refresh tokens.
                let minted_refresh = grants.iter().any(|g| {
                    g == crate::identity::oidc::GRANT_AUTHORIZATION_CODE
                        || g == crate::identity::oidc::GRANT_DEVICE_CODE
                });
                if !client.grant_types_enforced
                    && minted_refresh
                    && !grants
                        .iter()
                        .any(|g| g == crate::identity::oidc::GRANT_REFRESH_TOKEN)
                {
                    grants.push(crate::identity::oidc::GRANT_REFRESH_TOKEN.to_string());
                }
                grants
            },
            slug: if client.slug.is_empty() {
                None
            } else {
                Some(client.slug)
            },
            trust_level: client.trust_level,
            declared_scopes: client.declared_scopes,
            consent_spans_orgs: client.consent_spans_orgs,
            id_token_signed_response_alg: client.id_token_signed_response_alg,
            require_consent: Some(client.require_consent),
            client_logo_url: client.client_logo_url,
            status: client.status,
            backchannel_logout_uri: client.backchannel_logout_uri,
            frontchannel_logout_uri: client.frontchannel_logout_uri,
            post_logout_redirect_uris: client.post_logout_redirect_uris,
            cors_origins: client.cors_origins,
            assertion_public_key: client.assertion_public_key,
            access_token_authorization: client.access_token_authorization,
            jwks: client.jwks,
            jwks_uri: client.jwks_uri,
            dpop_bound_access_tokens: client.dpop_bound_access_tokens,
            mfa_required: client.mfa_required,
            created_at: client.created_at,
            require_pkce: Some(client.require_pkce),
        };

        // Validate before anything is written or deleted — with exactly
        // the rules `import_client` applies. A dry run reports what the
        // real restore would refuse, and an overwrite never deletes a live
        // client for a record that cannot replace it.
        if let Err(e) = self.identity.validate_import_client(realm_id, &req) {
            warn!(client_id = %client_id_str, err = %e, "refusing to restore client");
            report.clients.errored += 1;
            report.conflicts.push(Conflict {
                entity_type: "client".to_string(),
                identifier: client_id_str,
                reason: format!("client not restored: {e}"),
            });
            return Ok(());
        }

        if opts.dry_run {
            report.clients.created += 1;
            return Ok(());
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
                        // Delete by client_id then re-import. The record
                        // was validated above — its fields, and for an
                        // RS256 client that the realm's RSA key loads — so
                        // the re-import can fail only on storage, or on
                        // provisioning a realm RSA key that did not exist
                        // yet (the restore imports the archived key before
                        // any client), not on a rule that would have
                        // refused it before the live client was deleted.
                        if let Some(ref cid) = req.id {
                            if let Ok(()) = self.identity.delete_client(realm_id, cid) {
                                match self.identity.import_client(realm_id, &req) {
                                    Ok(_) => report.clients.overwritten += 1,
                                    Err(e) => {
                                        warn!(client_id = %client_id_str, err = %e, "import_client retry failed");
                                        report.clients.errored += 1;
                                        report.conflicts.push(Conflict {
                                            entity_type: "client".to_string(),
                                            identifier: client_id_str,
                                            reason: format!("client not restored: {e}"),
                                        });
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
                // A client whose credential or profile does not validate
                // is refused rather than restored without it; the
                // operator sees why.
                warn!(client_id = %client_id_str, err = %e, "import_client failed");
                report.clients.errored += 1;
                report.conflicts.push(Conflict {
                    entity_type: "client".to_string(),
                    identifier: client_id_str,
                    reason: format!("client not restored: {e}"),
                });
            }
        }
        Ok(())
    }
}

// ── Free helpers ─────────────────────────────────────────────────────────────

// ── Streaming restore (#867) ─────────────────────────────────────────────────

/// What the check pass of a restore learned about the members of a realm.
#[derive(Default)]
struct CheckedRealm {
    /// The members the archive carries, by name.
    present: std::collections::HashSet<&'static str>,
    /// The plaintext of `realm.json`.
    realm_json: Option<Zeroizing<Vec<u8>>>,
    /// The archived signing key (PKCS#8), when the archive carries one and
    /// the DEK is known.
    signing_key: Option<Zeroizing<Vec<u8>>>,
    /// The archived RS256 ID-token key (PKCS#8), under the same conditions.
    id_token_key: Option<Zeroizing<Vec<u8>>>,
    /// A client receives RS256 ID tokens.
    has_rs256_clients: bool,
    /// The audit events, when the archive carries them.
    audit: Option<CheckedAudit>,
}

/// What the check pass learned about `audit.ndjson`.
#[derive(Clone, Copy, Default)]
struct CheckedAudit {
    /// The number of events.
    events: u64,
    /// What the audit import must know about the whole run.
    plan: AuditImportPlan,
    /// The events were checked against the archive's chain material.
    chain_verified: bool,
}

/// The chain material of `audit_chain.json`, decoded.
struct AuditChainCheck {
    key: Zeroizing<Vec<u8>>,
    anchor: String,
}

impl AuditChainCheck {
    fn new(material: &crate::audit::AuditChainMaterial) -> Result<Self, BackupError> {
        use base64::Engine as _;
        let key = base64::engine::general_purpose::STANDARD
            .decode(&material.chain_key_b64)
            .map_err(|e| BackupError::Crypto(format!("audit chain key is not base64: {e}")))?;
        Ok(Self {
            key: Zeroizing::new(key),
            anchor: material.anchor.clone(),
        })
    }

    fn verifier(&self) -> ChainVerifier {
        ChainVerifier::new(&self.key, &self.anchor)
    }
}

/// Reads every event of `audit.ndjson`, checks each against `verifier` (when
/// there is chain material), and returns their count and import plan.
///
/// # Errors
///
/// [`BackupError::Engine`] at the first event that breaks the chain, or the
/// error of a line that does not parse.
fn check_audit_events(
    member: &mut dyn BufRead,
    mut verifier: Option<&mut ChainVerifier>,
) -> Result<CheckedAudit, BackupError> {
    let mut audit = CheckedAudit::default();
    for event in NdjsonRecords::<AuditEvent>::new(member) {
        let event = event?;
        audit.events += 1;
        // Check the source hashes BEFORE re-signing them. Re-chaining under
        // the destination key discards whatever the archive said, so a
        // tampered audit log used to restore into a chain that verifies clean
        // — a false attestation (audit 2026-08-28 §4.14#5).
        if let Some(verifier) = verifier.as_deref_mut() {
            if !verifier.check(&event) {
                return Err(BackupError::Engine(format!(
                    "audit chain in archive is broken at event {}; refusing to restore an \
                     audit log that does not match its own hashes",
                    audit.events
                )));
            }
        }
        audit.plan.observe(&event);
    }
    Ok(audit)
}

/// The import pass of one realm: imports each member as
/// [`ArchiveReader::visit_members_in_order`] passes it.
struct RealmRestore<'a> {
    importer: &'a BackupImporter,
    opts: &'a ImportOptions,
    dek: Option<&'a [u8; 32]>,
    realm_slug: &'a str,
    /// The archived realm record.
    realm: &'a Realm,
    create_req: CreateRealmRequest,
    signing_key_pkcs8: Option<&'a [u8]>,
    id_token_rsa_pkcs8: Option<&'a [u8]>,
    audit: Option<CheckedAudit>,
    /// The ID of the realm the records go to, once its record is restored.
    restored_realm_id: Option<RealmId>,
    report: ImportReport,
}

impl RealmRestore<'_> {
    /// Restores the realm record and its RS256 ID-token key the first time
    /// it is called, and returns the ID of the realm the records go to.
    ///
    /// Called before the first member after the audit events: the audit
    /// events are restored before any other write, so that, into an EMPTY
    /// realm, they keep their original timestamps ahead of the fresh events
    /// the identity/RBAC `import_*` calls emit.
    fn restored_realm(&mut self) -> Result<RealmId, BackupError> {
        if let Some(id) = &self.restored_realm_id {
            return Ok(id.clone());
        }
        let importer = self.importer;
        let opts = self.opts;
        let realm_id = self.realm.id().clone();
        let restored_realm_id = if realm_id.as_uuid().is_nil() {
            // Its signing key was restored before any other write; there is
            // no record to create.
            realm_id
        } else if opts.dry_run {
            // A dry run reports what the real restore would do. An overwrite
            // over a live realm is refused (B3), so the dry run must refuse
            // too rather than report a success the restore would not deliver
            // (audit 2026-08-28 §9 item 1).
            if matches!(opts.mode, RestoreMode::Overwrite)
                && importer
                    .identity
                    .get_realm(&realm_id)
                    .map_err(identity_to_backup_err)?
                    .is_some()
            {
                return Err(BackupError::RealmExists {
                    slug: self.create_req.name.clone(),
                });
            }
            self.report.realms.created += 1;
            realm_id
        } else {
            importer.import_realm_record(
                &self.create_req,
                realm_id,
                self.signing_key_pkcs8,
                opts,
                &mut self.report,
            )?
        };

        // ── RS256 ID-token signing key (task 26.55) ─────────────────────────
        //
        // Restored BEFORE the clients: importing an RS256 client provisions the
        // realm's RSA key when none exists, so the archived key must already be
        // in place or a freshly generated one would take its slot.
        if let Some(pkcs8) = self.id_token_rsa_pkcs8 {
            if opts.dry_run {
                self.report.id_token_signing_key.created += 1;
            } else {
                match importer.identity.import_realm_id_token_rsa_key(
                    &restored_realm_id,
                    pkcs8,
                    opts.mode == RestoreMode::Overwrite,
                ) {
                    Ok(outcome) => tally(&mut self.report.id_token_signing_key, outcome),
                    // Reported, not fatal: the system realm never holds one.
                    Err(e @ IdentityError::SystemRealmProtected { .. }) => {
                        warn!(realm = %self.realm_slug, err = %e, "RS256 ID-token key refused");
                        self.report.id_token_signing_key.errored += 1;
                        self.report.conflicts.push(Conflict {
                            entity_type: "id_token_signing_key".to_string(),
                            identifier: self.realm_slug.to_string(),
                            reason: e.to_string(),
                        });
                    }
                    Err(e) => return Err(BackupError::Engine(e.to_string())),
                }
            }
        }
        self.restored_realm_id = Some(restored_realm_id.clone());
        Ok(restored_realm_id)
    }

    /// Restores the member `name` (at archive path `path`) from its raw bytes.
    #[allow(clippy::too_many_lines)] // one arm per member
    fn member(&mut self, name: &str, path: &str, raw: &mut dyn Read) -> Result<(), BackupError> {
        let mut member = open_member(path, raw, self.dek)?;
        let member = &mut *member;
        if name == "audit.ndjson" {
            return self.audit_events(member);
        }
        let realm_id = self.restored_realm()?;
        let importer = self.importer;
        let opts = self.opts;
        let overwrite = opts.mode == RestoreMode::Overwrite;
        let report = &mut self.report;
        match name {
            "users.ndjson" => {
                let mut batch = Vec::new();
                for line in NdjsonRecords::<BackupUserLine>::new(member) {
                    batch.push(line?.into_request()?);
                    if batch.len() == RESTORE_USER_BATCH {
                        importer.import_user_batch(&batch, &realm_id, opts, report)?;
                        batch.clear();
                    }
                }
                importer.import_user_batch(&batch, &realm_id, opts, report)?;
            }
            // After users so the owning records exist. TOTP state is
            // re-encrypted under the destination realm's MFA DEK inside
            // `import_mfa_factor` (audit 2026-08-28 §4.18#5).
            "mfa_factors.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.mfa_factors,
                |factor: &MfaFactorExport| {
                    importer
                        .identity
                        .import_mfa_factor(&realm_id, factor, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            "clients.ndjson" => {
                for client in NdjsonRecords::<BackupClient>::new(member) {
                    importer.import_client_line(client?, &realm_id, opts, report)?;
                }
            }
            // ── Authorization model (HEA-2160) ─────────────────────────────
            //
            // Order is chosen so referenced records exist first (permissions →
            // roles → groups → assignments), though the engine `import_*`
            // methods write verbatim and do not re-validate references.
            "permissions.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.permissions,
                |record: &PermissionRecord| {
                    importer
                        .rbac
                        .import_permission(&realm_id, record, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            "roles.ndjson" => {
                restore_records(member, path, opts, &mut report.roles, |role: &Role| {
                    importer
                        .rbac
                        .import_role(&realm_id, role, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                })?;
            }
            "groups.ndjson" => {
                restore_records(member, path, opts, &mut report.groups, |group: &Group| {
                    importer
                        .rbac
                        .import_group(&realm_id, group, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                })?;
            }
            "organizations.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.organizations,
                |org: &Organization| {
                    importer
                        .identity
                        .import_organization(&realm_id, org, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            "assignments.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.assignments,
                |assignment: &RoleAssignment| {
                    importer
                        .rbac
                        .import_assignment(&realm_id, assignment, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            // Group memberships come AFTER groups and users so the records they
            // reference already exist. `import_group_membership` writes both the
            // forward and the reverse index; the reverse one is what permission
            // resolution scans (OpenSpec 26.40).
            "group_memberships.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.group_memberships,
                |edge: &GroupMembershipEdge| {
                    importer
                        .rbac
                        .import_group_membership(&realm_id, edge, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            "organization_memberships.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.organization_memberships,
                |membership: &OrganizationMembership| {
                    importer
                        .identity
                        .import_organization_membership(&realm_id, membership, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            "consents.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.consents,
                |consent: &ConsentExport| {
                    importer
                        .identity
                        .import_consent(&realm_id, consent, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            // Agents come after users and organizations so their owner exists.
            // `import_agent` writes the agent, its owner index and every
            // credential in one batch: an agent whose credentials did not come
            // back has lost the only way to exercise the authority it describes
            // (OpenSpec 26.40).
            "agents.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.agents,
                |export: &AgentExport| {
                    importer
                        .identity
                        .import_agent(&realm_id, export, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            // IdP connectors BEFORE federation links: a link is keyed by the
            // connector's id, so the connector must be back under that same id.
            "identity_providers.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.identity_providers,
                |idp: &IdpConfig| {
                    importer
                        .identity
                        .import_identity_provider(&realm_id, idp, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            "federation_links.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.federation_links,
                |link: &FederationLinkExport| {
                    importer
                        .identity
                        .import_federation_link(&realm_id, link, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            // An older archive's webhooks.ndjson holds the identity engine's
            // webhook store, which the dispatcher never read (#617): those
            // webhooks never delivered. Count them as skipped instead of
            // bringing them back as if they worked (#654).
            "webhooks.ndjson" => {
                let mut skipped = 0u64;
                for record in NdjsonRecords::<serde::de::IgnoredAny>::new(member) {
                    record?;
                    skipped += 1;
                }
                report.webhooks.skipped += skipped;
                if skipped > 0 {
                    warn!(
                        realm = self.realm_slug,
                        count = skipped,
                        "archive webhooks from the old identity store never delivered and are \
                         not restored; create them again under /admin/webhooks"
                    );
                }
            }
            "webhook_subscriptions.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.webhook_subscriptions,
                |sub: &WebhookSubscription| {
                    importer
                        .webhooks
                        .import(&realm_id, sub, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            // The SAML signing key is restored BEFORE the SPs it authenticates
            // to, and is re-sealed under THIS node's KEK inside
            // `import_realm_saml_key` — the archive carries the unsealed form
            // precisely because the destination's KEK is a different key
            // (OpenSpec 26.40).
            "saml_signing_key.json" => {
                let plaintext = read_small(member, path)?;
                if !opts.dry_run {
                    match importer
                        .identity
                        .import_realm_saml_key(&realm_id, &plaintext)
                    {
                        Ok(()) => {}
                        // Reported, not fatal: the rest of the realm still comes
                        // back (the system realm never holds a SAML key).
                        Err(e @ IdentityError::SystemRealmProtected { .. }) => {
                            warn!(member = %path, err = %e, "record refused");
                            report.conflicts.push(Conflict {
                                entity_type: "saml_signing_key".to_string(),
                                identifier: path.to_string(),
                                reason: e.to_string(),
                            });
                        }
                        Err(e) => return Err(BackupError::Engine(e.to_string())),
                    }
                }
            }
            "scim_mappings.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.scim_mappings,
                |mapping: &ScimMappingExport| {
                    importer
                        .identity
                        .import_scim_mapping(&realm_id, mapping, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            "invitations.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.invitations,
                |invitation: &OrganizationInvitation| {
                    importer
                        .identity
                        .import_invitation(&realm_id, invitation, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            "revocations.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.revocations,
                |revocation: &RevocationExport| {
                    importer
                        .identity
                        .import_revocation(&realm_id, revocation, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            "retiring_signing_keys.json" => restore_records(
                member,
                path,
                opts,
                &mut report.retiring_signing_keys,
                |key: &RetiringSigningKeyExport| {
                    importer
                        .identity
                        .import_retiring_signing_key(&realm_id, key, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            "retiring_id_token_signing_keys.json" => restore_records(
                member,
                path,
                opts,
                &mut report.retiring_id_token_signing_keys,
                |key: &RetiringSigningKeyExport| {
                    importer
                        .identity
                        .import_retiring_id_token_rsa_key(&realm_id, key, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            "scopes.ndjson" => restore_records(
                member,
                path,
                opts,
                &mut report.scopes,
                |scope: &ScopeExport| {
                    importer
                        .rbac
                        .import_scope(&realm_id, scope, overwrite)
                        .map_err(|e| BackupError::Engine(e.to_string()))
                },
            )?,
            // Every name in RESTORE_ORDER has an arm above.
            other => {
                return Err(BackupError::UnrecognizedMember {
                    path: format!("realms/{}/{other}", self.realm_slug),
                })
            }
        }
        Ok(())
    }

    /// Restores the audit events of `audit.ndjson`, one import chunk at a
    /// time.
    ///
    /// Audit events are re-chained under the destination realm's HMAC key
    /// (the source key is not portable), so the integrity hash changes but
    /// the event content is preserved and each event is marked as restored.
    /// `import_event_stream` appends them at the END of the destination chain:
    /// a realm that already holds events (a live system realm, a tenant
    /// merged into itself) gets them stamped with the import time, the
    /// original kept in the marker, so storage order stays chain order. The
    /// exporter writes events in ascending-timestamp scan order, so NDJSON
    /// line order is the source chain order.
    fn audit_events(&mut self, member: &mut dyn BufRead) -> Result<(), BackupError> {
        let Some(audit) = self.audit else {
            return Ok(());
        };
        let mut failure = None;
        let mut events = NdjsonRecords::<AuditEvent>::new(member).map_while(|event| match event {
            Ok(event) => Some(event),
            Err(e) => {
                failure = Some(e);
                None
            }
        });
        // Appended at the END of the target realm's chain, marked as
        // restored, deduplicated by event id — so a live realm keeps a
        // verifiable chain and a repeated restore adds nothing.
        let outcome =
            self.importer
                .audit
                .import_event_stream(self.realm.id(), &audit.plan, &mut events);
        drop(events);
        match (outcome, failure) {
            (Ok(outcome), None) => {
                self.report.audit_events.created += outcome.imported;
                self.report.audit_events.skipped += outcome.duplicates;
                Ok(())
            }
            // The check pass parsed every line of this member, from the same
            // private copy; a line that does not parse now is an I/O fault.
            (_, Some(e)) => Err(e),
            (Err(e), None) => {
                // Chunks written before the failure are durable and chained;
                // the count cannot tell which, so every event is reported as
                // not restored.
                warn!(err = %e, "import audit events failed");
                self.report.audit_events.errored += audit.events;
                Ok(())
            }
        }
    }
}

/// Parses every record of the record member `name` into the type that the
/// import pass reads, and drops it (#867). The check pass calls it, so a
/// malformed line stops the restore before the first write. A member that
/// is not a record member (the SAML key) is only read to its end, which
/// authenticates it.
///
/// # Errors
///
/// The first read, authentication or parse error, or a user line whose
/// credential names another user.
fn check_records(name: &str, member: &mut dyn BufRead) -> Result<(), BackupError> {
    fn parse_all<T: serde::de::DeserializeOwned>(
        member: &mut dyn BufRead,
    ) -> Result<(), BackupError> {
        for record in NdjsonRecords::<T>::new(member) {
            record?;
        }
        Ok(())
    }
    match name {
        "users.ndjson" => {
            for line in NdjsonRecords::<BackupUserLine>::new(member) {
                let line = line?;
                if let Some(credential) = &line.credential {
                    credential.check_owner(&line.user)?;
                }
            }
            Ok(())
        }
        "mfa_factors.ndjson" => parse_all::<MfaFactorExport>(member),
        "permissions.ndjson" => parse_all::<PermissionRecord>(member),
        "roles.ndjson" => parse_all::<Role>(member),
        "groups.ndjson" => parse_all::<Group>(member),
        "organizations.ndjson" => parse_all::<Organization>(member),
        "assignments.ndjson" => parse_all::<RoleAssignment>(member),
        "group_memberships.ndjson" => parse_all::<GroupMembershipEdge>(member),
        "organization_memberships.ndjson" => parse_all::<OrganizationMembership>(member),
        "consents.ndjson" => parse_all::<ConsentExport>(member),
        "agents.ndjson" => parse_all::<AgentExport>(member),
        "identity_providers.ndjson" => parse_all::<IdpConfig>(member),
        "federation_links.ndjson" => parse_all::<FederationLinkExport>(member),
        "webhooks.ndjson" => parse_all::<serde::de::IgnoredAny>(member),
        "webhook_subscriptions.ndjson" => parse_all::<WebhookSubscription>(member),
        "scim_mappings.ndjson" => parse_all::<ScimMappingExport>(member),
        "invitations.ndjson" => parse_all::<OrganizationInvitation>(member),
        "revocations.ndjson" => parse_all::<RevocationExport>(member),
        "retiring_signing_keys.json" | "retiring_id_token_signing_keys.json" => {
            parse_all::<RetiringSigningKeyExport>(member)
        }
        "scopes.ndjson" => parse_all::<ScopeExport>(member),
        _ => drain(member),
    }
}

/// Restores every record of the NDJSON `member` by deserializing each line
/// into `T` and applying `import_one`, tallying outcomes into `counts`.
///
/// A malformed line is a hard error (propagated); a per-record engine error
/// is counted in `counts.errored` and logged, matching the user/client
/// import behavior.
fn restore_records<T, F>(
    member: &mut dyn BufRead,
    path: &str,
    opts: &ImportOptions,
    counts: &mut EntityCounts,
    import_one: F,
) -> Result<(), BackupError>
where
    T: serde::de::DeserializeOwned,
    F: Fn(&T) -> Result<ImportOutcome, BackupError>,
{
    for record in NdjsonRecords::<T>::new(member) {
        let record = record?;
        if opts.dry_run {
            counts.created += 1;
            continue;
        }
        match import_one(&record) {
            Ok(outcome) => tally(counts, outcome),
            Err(e) => {
                warn!(member = path, err = %e, "import record failed");
                counts.errored += 1;
            }
        }
    }
    Ok(())
}

/// The records of an NDJSON member, read and parsed one line at a time.
///
/// Blank lines are skipped. The first error (reading or parsing) is the last
/// item.
struct NdjsonRecords<'a, T> {
    member: &'a mut dyn BufRead,
    /// The current line. Members carry credentials and key material, so it
    /// is zeroed when dropped.
    line: Zeroizing<Vec<u8>>,
    done: bool,
    _record: std::marker::PhantomData<fn() -> T>,
}

impl<'a, T> NdjsonRecords<'a, T> {
    fn new(member: &'a mut dyn BufRead) -> Self {
        Self {
            member,
            line: Zeroizing::new(Vec::new()),
            done: false,
            _record: std::marker::PhantomData,
        }
    }
}

impl<T: serde::de::DeserializeOwned> Iterator for NdjsonRecords<'_, T> {
    type Item = Result<T, BackupError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            self.line.zeroize();
            match self.member.read_until(b'\n', &mut self.line) {
                Ok(0) => self.done = true,
                Ok(_) => {
                    let line = trim_bytes(&self.line);
                    if line.is_empty() {
                        continue;
                    }
                    let record = serde_json::from_slice(line).map_err(BackupError::from);
                    self.done = record.is_err();
                    return Some(record);
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(BackupError::from_read(e)));
                }
            }
        }
        None
    }
}

/// The largest member a restore reads whole: `realm.json` and the key
/// members. They do not grow with the records of a realm.
const SMALL_MEMBER_LIMIT: u64 = 16 * 1024 * 1024;

/// Opens the plaintext of the member at `path` over its raw bytes:
/// decrypted chunk by chunk with `dek`, or as it is in an archive whose
/// sections are not encrypted.
fn open_member<'r>(
    path: &str,
    raw: &'r mut dyn Read,
    dek: Option<&[u8; 32]>,
) -> Result<Box<dyn BufRead + 'r>, BackupError> {
    match dek {
        Some(dek) => Ok(Box::new(DecryptReader::new(raw, dek, path)?)),
        None => Ok(Box::new(std::io::BufReader::new(raw))),
    }
}

/// Reads the whole small member `member` at `path`.
///
/// # Errors
///
/// [`BackupError::Engine`] when the member is larger than
/// [`SMALL_MEMBER_LIMIT`], or the error of the read.
fn read_small(member: &mut dyn BufRead, path: &str) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    let mut out = Zeroizing::new(Vec::new());
    member
        .take(SMALL_MEMBER_LIMIT + 1)
        .read_to_end(&mut out)
        .map_err(BackupError::from_read)?;
    if out.len() as u64 > SMALL_MEMBER_LIMIT {
        return Err(BackupError::Engine(format!(
            "archive member {path} is larger than {SMALL_MEMBER_LIMIT} bytes"
        )));
    }
    Ok(out)
}

/// Reads `member` to its end without keeping it: for a member that the
/// check pass only authenticates.
fn drain(member: &mut dyn BufRead) -> Result<(), BackupError> {
    loop {
        let n = member.fill_buf().map_err(BackupError::from_read)?.len();
        if n == 0 {
            return Ok(());
        }
        member.consume(n);
    }
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
    use crate::backup::encrypt_member;
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
        webhooks: Arc<dyn WebhookEngine>,
        /// The store under the engines: its WAL sync count is the number of
        /// durable writes.
        storage: Arc<EmbeddedStorageEngine>,
        // Held to keep the temp directory alive for the duration of the test.
        _dir: TempDir,
    }

    fn make_rig() -> TestRig {
        make_rig_with(crate::storage::wal::SyncMode::None)
    }

    /// A rig on storage that fsyncs every durable write, as in production.
    fn make_durable_rig() -> TestRig {
        make_rig_with(crate::storage::wal::SyncMode::EveryWrite)
    }

    fn make_rig_with(sync_mode: crate::storage::wal::SyncMode) -> TestRig {
        let dir = TempDir::new().expect("tmpdir");
        let mut config = StorageConfig::dev(dir.path().to_path_buf());
        config.wal_config.sync_mode = sync_mode;
        let embedded = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
        let storage = Arc::clone(&embedded) as Arc<dyn StorageEngine>;
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
        let webhooks = Arc::new(crate::webhook::EmbeddedWebhookEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
        )) as Arc<dyn WebhookEngine>;
        TestRig {
            identity,
            rbac,
            audit,
            webhooks,
            storage: embedded,
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
        make_test_archive_with(tmp, slug, realm_uuid, &[])
    }

    /// [`make_test_archive`], plus `extra` members (name under the realm,
    /// plaintext) encrypted under the same DEK.
    fn make_test_archive_with(
        tmp: &TempDir,
        slug: &str,
        realm_uuid: &str,
        extra: &[(&str, &str)],
    ) -> std::path::PathBuf {
        make_test_archive_raw(tmp, slug, realm_uuid, extra, &[])
    }

    /// [`make_test_archive_with`], plus `raw` members (name under the realm,
    /// bytes) written as they are, after the encrypted ones.
    fn make_test_archive_raw(
        tmp: &TempDir,
        slug: &str,
        realm_uuid: &str,
        extra: &[(&str, &str)],
        raw: &[(&str, &[u8])],
    ) -> std::path::PathBuf {
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
        make_archive(tmp, slug, realm_uuid, &users_ndjson, extra, raw)
    }

    /// A user line of `users.ndjson` for user number `i` of a test archive.
    fn numbered_user_line(i: u32) -> String {
        let user = serde_json::json!({
            "id": format!("00000000-0000-0000-0001-{i:012}"),
            "email": format!("user{i:05}@example.com"),
            "display_name": format!("User {i}"),
            "first_name": "User",
            "last_name": "",
            "status": "Active",
            "created_at": 0,
            "updated_at": 0
        });
        serde_json::to_string(&user).expect("serialize user")
    }

    /// An archive of one realm whose `users.ndjson` is `users_ndjson`, plus
    /// `extra` members (plaintext, encrypted under the archive DEK) and `raw`
    /// members (written as they are).
    fn make_archive(
        tmp: &TempDir,
        slug: &str,
        realm_uuid: &str,
        users_ndjson: &str,
        extra: &[(&str, &str)],
        raw: &[(&str, &[u8])],
    ) -> std::path::PathBuf {
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

        let realm_bytes = serde_json::to_vec(&realm_json).expect("serialize realm");
        let users_bytes = users_ndjson.as_bytes();

        // Generate a DEK and wrap it with the test passphrase.
        let dek = BackupExporter::generate_dek().expect("generate DEK");
        let passphrase = test_passphrase();
        let (wrapped_dek_b64, dek_wrapping_params) = wrap_dek(&dek, &passphrase).expect("wrap DEK");

        let realm_encrypted =
            encrypt_member(&format!("realms/{slug}/realm.json"), &realm_bytes, &dek)
                .expect("encrypt realm");
        let users_encrypted =
            encrypt_member(&format!("realms/{slug}/users.ndjson"), users_bytes, &dek)
                .expect("encrypt users");

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
                    users: users_ndjson
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .count() as u64,
                    ..Default::default()
                },
                audit_chain_included: false,
            }],
            checksums: std::collections::BTreeMap::new(),
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
        for (member, plaintext) in extra {
            let path = format!("realms/{slug}/{member}");
            let encrypted =
                encrypt_member(&path, plaintext.as_bytes(), &dek).expect("encrypt member");
            writer.add_file(&path, &encrypted).expect("add member");
        }
        for (member, bytes) in raw {
            writer
                .add_file(&format!("realms/{slug}/{member}"), bytes)
                .expect("add raw member");
        }
        // Manually set checksums (finish guard requires sections_encrypted fields to be set)
        manifest.checksums = std::collections::BTreeMap::new();
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
            Arc::clone(&rig.webhooks),
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

    /// Restores `users_ndjson` into a new realm with `mode`, and returns the
    /// report, the realm and the number of WAL fsyncs of the restore.
    fn restore_users(
        rig: &TestRig,
        users_ndjson: &str,
        mode: RestoreMode,
    ) -> (ImportReport, RealmId, u64) {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let realm_uuid = "00000000-0000-0000-0000-000000000887";
        let slug = "batched-restore";
        let archive_path = make_archive(&archive_dir, slug, realm_uuid, users_ndjson, &[], &[]);
        let reader = BackupArchive::open(&archive_path).expect("open");
        let opts = ImportOptions {
            mode,
            ..opts_with_passphrase()
        };
        let before = rig.storage.wal_sync_count();
        let report = importer(rig)
            .import_realm(slug, &reader, &opts)
            .expect("import");
        let syncs = rig.storage.wal_sync_count() - before;
        let realm = RealmId::new(uuid::Uuid::parse_str(realm_uuid).expect("uuid"));
        (report, realm, syncs)
    }

    /// A restore wrote one user per durable write, and each user waited for
    /// two fsyncs: one for its rows, one for its audit event. On a cloud disk
    /// that is about 175 users/s: a restore of 10M users took about 18 hours
    /// (#887). A restore must share each fsync among many users.
    #[test]
    fn a_restore_shares_each_durable_write_among_many_users() {
        let rig = make_durable_rig();
        // More than one chunk of users, and a partial last chunk.
        let n: u32 = 600;
        let users: String = (0..n).map(|i| numbered_user_line(i) + "\n").collect();

        let (report, realm, syncs) = restore_users(&rig, &users, RestoreMode::Skip);

        assert_eq!(report.users.created, u64::from(n), "every user is restored");
        assert_eq!(report.users.errored, 0);
        assert_eq!(report.users.skipped, 0);
        for i in 0..n {
            let email = format!("user{i:05}@example.com");
            let user = rig
                .identity
                .get_user_by_email(&realm, &email)
                .expect("get")
                .unwrap_or_else(|| panic!("{email} is not restored"));
            assert_eq!(
                user.id().as_uuid().to_string(),
                format!("00000000-0000-0000-0001-{i:012}"),
                "{email} keeps its archived id"
            );
        }
        assert!(
            syncs <= u64::from(n) / 10,
            "{syncs} durable writes to restore {n} users"
        );
    }

    /// A user line whose email an earlier line of the archive already holds
    /// is skipped and reported, also when both lines go in the same batch.
    #[test]
    fn a_repeated_email_in_the_archive_is_skipped_and_reported() {
        let rig = make_rig();
        let mut lines: Vec<String> = (0..5).map(numbered_user_line).collect();
        let mut repeat: serde_json::Value =
            serde_json::from_str(&numbered_user_line(9)).expect("json");
        repeat["email"] = serde_json::json!("user00002@example.com");
        lines.insert(3, repeat.to_string());
        let users: String = lines.iter().map(|l| format!("{l}\n")).collect();

        let (report, realm, _) = restore_users(&rig, &users, RestoreMode::Skip);

        assert_eq!(report.users.created, 5);
        assert_eq!(report.users.skipped, 1);
        assert_eq!(report.users.errored, 0);
        assert_eq!(report.conflicts.len(), 1, "{:?}", report.conflicts);
        assert_eq!(report.conflicts[0].entity_type, "user");
        assert_eq!(report.conflicts[0].identifier, "user00002@example.com");
        assert_eq!(report.conflicts[0].reason, "email already exists");
        let kept = rig
            .identity
            .get_user_by_email(&realm, "user00002@example.com")
            .expect("get")
            .expect("stored");
        assert_eq!(
            kept.id().as_uuid().to_string(),
            "00000000-0000-0000-0001-000000000002",
            "the first line with the email is kept"
        );
    }

    /// In overwrite mode a repeated email replaces the user of the earlier
    /// line, as the lines come one after the other in the archive.
    #[test]
    fn a_repeated_email_in_the_archive_is_overwritten_in_overwrite_mode() {
        let rig = make_rig();
        let mut lines: Vec<String> = (0..5).map(numbered_user_line).collect();
        for later in [9, 10] {
            let mut repeat: serde_json::Value =
                serde_json::from_str(&numbered_user_line(later)).expect("json");
            repeat["email"] = serde_json::json!("user00002@example.com");
            lines.push(repeat.to_string());
        }
        let users: String = lines.iter().map(|l| format!("{l}\n")).collect();

        let (report, realm, _) = restore_users(&rig, &users, RestoreMode::Overwrite);

        assert_eq!(report.users.created, 5);
        assert_eq!(report.users.overwritten, 2);
        assert_eq!(report.users.errored, 0);
        let kept = rig
            .identity
            .get_user_by_email(&realm, "user00002@example.com")
            .expect("get")
            .expect("stored");
        assert_eq!(
            kept.id().as_uuid().to_string(),
            "00000000-0000-0000-0001-000000000010",
            "the last line with the email wins"
        );
        let replaced = crate::core::UserId::new(
            uuid::Uuid::parse_str("00000000-0000-0000-0001-000000000002").expect("uuid"),
        );
        assert!(
            rig.identity
                .get_user(&realm, &replaced)
                .expect("get")
                .is_none(),
            "the overwritten user is gone"
        );
    }

    /// A user line that fails validation is counted as errored; the other
    /// users of its batch are restored.
    #[test]
    fn an_invalid_user_line_is_counted_and_the_rest_of_its_batch_restored() {
        let rig = make_rig();
        let mut lines: Vec<String> = (0..4).map(numbered_user_line).collect();
        let mut invalid: serde_json::Value =
            serde_json::from_str(&numbered_user_line(7)).expect("json");
        invalid["email"] = serde_json::json!("not-an-email");
        lines.insert(2, invalid.to_string());
        let users: String = lines.iter().map(|l| format!("{l}\n")).collect();

        let (report, realm, _) = restore_users(&rig, &users, RestoreMode::Skip);

        assert_eq!(report.users.created, 4);
        assert_eq!(report.users.errored, 1);
        for i in 0..4 {
            let email = format!("user{i:05}@example.com");
            assert!(
                rig.identity
                    .get_user_by_email(&realm, &email)
                    .expect("get")
                    .is_some(),
                "{email} is restored"
            );
        }
    }

    /// A `webhooks.ndjson` member holds the identity engine's webhook store,
    /// which the dispatcher never read (#617): those webhooks never delivered.
    /// A restore skips and counts them instead of bringing them back as if
    /// they worked (#654).
    #[test]
    fn identity_store_webhooks_from_an_older_archive_are_skipped_and_counted() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();
        let realm_uuid = "00000000-0000-0000-0000-000000000654";
        let slug = "legacy-webhooks";
        let webhook = serde_json::json!({
            "id": "00000000-0000-0000-0000-0000000006a1",
            "realm_id": realm_uuid,
            "url": "https://ops.example/hearth-events",
            "secret": "hmac-signing-secret-value",
            "events": ["user.created"],
            "enabled": true,
            "created_at": 0,
            "updated_at": 0
        });
        let member = format!("{webhook}\n");
        let archive_path = make_test_archive_with(
            &archive_dir,
            slug,
            realm_uuid,
            &[("webhooks.ndjson", member.as_str())],
        );

        let reader = BackupArchive::open(&archive_path).expect("open");
        let report = BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
            Arc::clone(&rig.webhooks),
        )
        .import_realm(slug, &reader, &opts_with_passphrase())
        .expect("import");

        assert_eq!(report.webhooks.skipped, 1, "the old webhook is counted");
        assert_eq!(report.webhooks.created, 0);
        let realm_id = RealmId::new(uuid::Uuid::parse_str(realm_uuid).expect("uuid"));
        let listed = rig
            .identity
            .list_webhooks(&realm_id, &crate::core::PageRequest::default())
            .expect("list");
        assert!(listed.items.is_empty(), "the old webhook is not restored");
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
            Arc::clone(&rig.webhooks),
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
            Arc::clone(&rig.webhooks),
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
            Arc::clone(&rig.webhooks),
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
            Arc::clone(&rig.webhooks),
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
            Arc::clone(&rig.webhooks),
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
            Arc::clone(&rig.webhooks),
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
        let realm_enc = encrypt_member(
            &format!("realms/{slug}/realm.json"),
            &serde_json::to_vec(&realm_json).expect("ser"),
            &dek,
        )
        .expect("enc realm");
        // A member with a name the importer has never heard of.
        let surprise_enc = encrypt_member(
            &format!("realms/{slug}/future_feature.ndjson"),
            b"{}\n",
            &dek,
        )
        .expect("enc surprise");

        let manifest = BackupManifest {
            format_version: crate::backup::MANIFEST_VERSION,
            hearth_version: "0.0.0-test".to_string(),
            created_at: Timestamp::from_micros(0),
            realms: vec![RealmManifest {
                realm_id: format!("realm_{realm_uuid}"),
                slug: slug.to_string(),
                record_counts: RecordCounts::default(),
                audit_chain_included: false,
            }],
            checksums: std::collections::BTreeMap::new(),
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
            Arc::clone(&rig.webhooks),
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

        let realm_encrypted = encrypt_member(
            &format!("realms/{slug}/realm.json"),
            &serde_json::to_vec(&realm_json).expect("ser realm"),
            &dek,
        )
        .expect("encrypt realm");
        let sk_encrypted = encrypt_member(
            &format!("realms/{slug}/signing_key.json"),
            signing_key_pkcs8,
            &dek,
        )
        .expect("encrypt signing key");

        let manifest = BackupManifest {
            format_version: crate::backup::MANIFEST_VERSION,
            hearth_version: "0.0.0-test".to_string(),
            created_at: Timestamp::from_micros(0),
            realms: vec![RealmManifest {
                realm_id: format!("realm_{realm_uuid}"),
                slug: slug.to_string(),
                record_counts: RecordCounts::default(),
                audit_chain_included: false,
            }],
            checksums: std::collections::BTreeMap::new(),
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
            Arc::clone(&rig.webhooks),
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
            Arc::clone(&rig.webhooks),
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
            Arc::clone(&dest.webhooks),
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

    // ── Client credentials (a restore never yields a weaker client) ──────────

    /// Restores one `clients.ndjson` line into a fresh realm and returns the
    /// report, the realm, and the client id the line named.
    fn restore_client_line(line: &serde_json::Value) -> (TestRig, RealmId, ClientId, ImportReport) {
        let rig = make_rig();
        let realm = rig
            .identity
            .create_realm(&crate::identity::CreateRealmRequest {
                name: format!("client-restore-{}", uuid::Uuid::new_v4()),
                config: None,
            })
            .expect("create realm")
            .id()
            .clone();
        let cid: ClientId = serde_json::from_value(line["client_id"].clone()).expect("client id");
        let importer = BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
            Arc::clone(&rig.webhooks),
        );
        let mut report = ImportReport::default();
        let client = serde_json::from_value(line.clone()).expect("parse client line");
        importer
            .import_client_line(client, &realm, &opts_with_passphrase(), &mut report)
            .expect("import_client_line");
        (rig, realm, cid, report)
    }

    fn client_line(extra: &serde_json::Value) -> serde_json::Value {
        let mut line = serde_json::json!({
            "client_id": ClientId::generate(),
            "client_name": "Nightly M2M",
            "redirect_uris": [],
            "created_at": 0,
            "grant_types": ["client_credentials"],
        });
        for (k, v) in extra.as_object().expect("object") {
            line[k] = v.clone();
        }
        line
    }

    /// An archived client record that carries no credential although its
    /// grants need one — `client_credentials` is only ever issued to a client
    /// that authenticates — is what an archive that lost the credential looks
    /// like. Restoring it would create a PUBLIC client for a confidential
    /// one, so it is refused and reported, never restored.
    #[test]
    fn a_client_record_missing_the_credential_its_grants_need_is_refused() {
        let (rig, realm, cid, report) = restore_client_line(&client_line(&serde_json::json!({})));
        assert!(
            rig.identity
                .get_client(&realm, &cid)
                .expect("get")
                .is_none(),
            "the client must not be restored as a public client"
        );
        assert_eq!(report.clients.errored, 1);
        assert_eq!(report.clients.created, 0);
        let conflict = report
            .conflicts
            .iter()
            .find(|c| c.entity_type == "client")
            .expect("the refusal must be reported");
        assert!(
            conflict.reason.contains("credential"),
            "the report must say the credential is missing: {}",
            conflict.reason
        );
    }

    /// A stored hash in a format Hearth cannot verify is refused rather than
    /// stored (it could never authenticate) or dropped (that would make the
    /// client public).
    #[test]
    fn a_client_record_with_an_unknown_secret_hash_format_is_refused() {
        for bad in [
            "plaintext-secret",
            "$pbkdf2-sha256$i=1000$c2FsdA$aGFzaA",
            "$hearth-sha256$v=1$tooshort",
            "$hearth-sha256$v=2$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$argon2i$v=19$m=256,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
        ] {
            let (rig, realm, cid, report) = restore_client_line(&client_line(
                &serde_json::json!({"client_secret_hash": bad}),
            ));
            assert!(
                rig.identity
                    .get_client(&realm, &cid)
                    .expect("get")
                    .is_none(),
                "{bad}: must not be restored"
            );
            assert_eq!(report.clients.errored, 1, "{bad}");
            assert!(
                report.conflicts.iter().any(|c| c.entity_type == "client"),
                "{bad}: the refusal must be reported"
            );
        }
    }

    /// A stored Argon2id hash chooses its own cost. One above the password
    /// verifier's ceilings (a four-terabyte `m`, four billion passes) would
    /// make every authentication attempt for the client an allocation request
    /// the attacker sized, so the restore refuses it and reports why.
    #[test]
    fn a_client_record_with_an_extreme_argon2_cost_is_refused() {
        let hash = "$argon2id$v=19$m=4294967295,t=4294967295,p=1\
                    $c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";
        let (rig, realm, cid, report) = restore_client_line(&client_line(
            &serde_json::json!({"client_secret_hash": hash}),
        ));
        assert!(
            rig.identity
                .get_client(&realm, &cid)
                .expect("get")
                .is_none(),
            "a client whose hash sets an extreme cost must not be restored"
        );
        assert_eq!(report.clients.errored, 1);
        let conflict = report
            .conflicts
            .iter()
            .find(|c| c.entity_type == "client")
            .expect("the refusal must be reported");
        assert!(
            conflict.reason.contains("argon2 parameter"),
            "the report must name the cost parameter: {}",
            conflict.reason
        );
    }

    /// Restores one `clients.ndjson` line into an existing realm with `opts`.
    fn restore_client_line_into(
        rig: &TestRig,
        realm: &RealmId,
        line: &serde_json::Value,
        opts: &ImportOptions,
    ) -> ImportReport {
        let importer = BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
            Arc::clone(&rig.webhooks),
        );
        let mut report = ImportReport::default();
        let client = serde_json::from_value(line.clone()).expect("parse client line");
        importer
            .import_client_line(client, realm, opts, &mut report)
            .expect("import_client_line");
        report
    }

    /// A realm holding one live confidential client whose secret is
    /// `live-secret`; returns the rig, the realm and the client's id.
    fn realm_with_live_client() -> (TestRig, RealmId, ClientId) {
        let rig = make_rig();
        let realm = rig
            .identity
            .create_realm(&crate::identity::CreateRealmRequest {
                name: format!("client-overwrite-{}", uuid::Uuid::new_v4()),
                config: None,
            })
            .expect("create realm")
            .id()
            .clone();
        let cid = ClientId::generate();
        rig.identity
            .import_client(
                &realm,
                &crate::identity::ImportClientRequest {
                    id: Some(cid.clone()),
                    client_name: "Live M2M".to_string(),
                    client_secret: Some("live-secret".to_string()),
                    grant_types: vec!["client_credentials".to_string()],
                    ..Default::default()
                },
            )
            .expect("live client");
        rig.identity
            .authenticate_confidential_client(&realm, &cid, Some("live-secret"))
            .expect("control: the live client authenticates before the restore");
        (rig, realm, cid)
    }

    /// An archived record for `cid` that validates in every respect but its
    /// JWKS, which is not a JWK set.
    fn invalid_jwks_line(cid: &ClientId) -> serde_json::Value {
        let mut line = client_line(&serde_json::json!({
            "client_secret_hash": "$hearth-sha256$v=1$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "jwks": "this is not a JWK set",
        }));
        line["client_id"] = serde_json::to_value(cid).expect("client id");
        line
    }

    /// Overwrite mode used to delete the live client and only then try to
    /// import the archived record, so a record that failed validation left
    /// the realm with neither. The record is now validated first: the live
    /// client survives, still authenticates, and the report says why the
    /// archived record was refused.
    #[test]
    fn overwrite_keeps_the_live_client_when_the_archived_record_is_refused() {
        let (rig, realm, cid) = realm_with_live_client();
        let opts = ImportOptions {
            mode: RestoreMode::Overwrite,
            ..opts_with_passphrase()
        };
        let report = restore_client_line_into(&rig, &realm, &invalid_jwks_line(&cid), &opts);

        let live = rig
            .identity
            .get_client(&realm, &cid)
            .expect("get")
            .expect("the live client must survive a refused overwrite");
        assert_eq!(live.client_name(), "Live M2M", "and stay the live record");
        rig.identity
            .authenticate_confidential_client(&realm, &cid, Some("live-secret"))
            .expect("the live client must still authenticate with its own secret");
        assert_eq!(report.clients.overwritten, 0);
        assert_eq!(report.clients.errored, 1);
        let conflict = report
            .conflicts
            .iter()
            .find(|c| c.entity_type == "client")
            .expect("the refusal must be reported");
        assert!(
            conflict.reason.contains("not restored") && conflict.reason.contains("jwks"),
            "the report must say why: {}",
            conflict.reason
        );
    }

    /// Control for the test above: a VALID archived record does replace the
    /// live one in overwrite mode.
    #[test]
    fn overwrite_replaces_the_live_client_with_a_valid_archived_record() {
        let (rig, realm, cid) = realm_with_live_client();
        let mut line = client_line(&serde_json::json!({
            "client_secret_hash": "$hearth-sha256$v=1$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        }));
        line["client_id"] = serde_json::to_value(&cid).expect("client id");
        let opts = ImportOptions {
            mode: RestoreMode::Overwrite,
            ..opts_with_passphrase()
        };
        let report = restore_client_line_into(&rig, &realm, &line, &opts);
        assert_eq!(report.clients.overwritten, 1, "{:?}", report.conflicts);
        let restored = rig
            .identity
            .get_client(&realm, &cid)
            .expect("get")
            .expect("restored");
        assert_eq!(restored.client_name(), "Nightly M2M");
    }

    /// A dry run used to count every client as created before validating it,
    /// so it promised a restore the real run would refuse. It now runs the
    /// same validation, reports the refusal, and still writes nothing.
    #[test]
    fn dry_run_reports_a_client_the_real_restore_would_refuse() {
        let rig = make_rig();
        let realm = rig
            .identity
            .create_realm(&crate::identity::CreateRealmRequest {
                name: format!("client-dry-run-{}", uuid::Uuid::new_v4()),
                config: None,
            })
            .expect("create realm")
            .id()
            .clone();
        let opts = ImportOptions {
            dry_run: true,
            ..opts_with_passphrase()
        };

        let bad_id = ClientId::generate();
        let report = restore_client_line_into(&rig, &realm, &invalid_jwks_line(&bad_id), &opts);
        assert_eq!(
            report.clients.created, 0,
            "a refused client is not 'created'"
        );
        assert_eq!(report.clients.errored, 1);
        assert!(
            report
                .conflicts
                .iter()
                .any(|c| c.entity_type == "client" && c.reason.contains("jwks")),
            "the dry run must report the refusal: {:?}",
            report.conflicts
        );

        // Control: a valid record is still counted, and nothing is written.
        let good = client_line(&serde_json::json!({
            "client_secret_hash": "$hearth-sha256$v=1$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        }));
        let good_id: ClientId = serde_json::from_value(good["client_id"].clone()).expect("id");
        let report = restore_client_line_into(&rig, &realm, &good, &opts);
        assert_eq!(report.clients.created, 1, "{:?}", report.conflicts);
        for cid in [&bad_id, &good_id] {
            assert!(
                rig.identity.get_client(&realm, cid).expect("get").is_none(),
                "a dry run writes nothing"
            );
        }
    }

    /// Both stored formats come back verbatim; the client is not public.
    #[test]
    fn a_client_record_with_a_supported_hash_is_restored_verbatim() {
        for hash in [
            "$hearth-sha256$v=1$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$m=256,t=1,p=1$48W7IQncfP/IRd+UEMNchQ$RVK0enJVqYZ2Ro4u93PK5B9jFWPeS0jq9iTiOAaI1uI",
        ] {
            let (rig, realm, cid, report) = restore_client_line(&client_line(
                &serde_json::json!({"client_secret_hash": hash}),
            ));
            assert_eq!(report.clients.created, 1, "{hash}: {:?}", report.conflicts);
            let client = rig
                .identity
                .get_client(&realm, &cid)
                .expect("get")
                .expect("restored");
            assert_eq!(client.client_secret_hash(), Some(hash));
            assert!(!client.is_public());
        }
    }

    /// An archived (soft-deleted) client stays archived.
    #[test]
    fn an_archived_client_record_is_restored_archived() {
        let (rig, realm, cid, _report) = restore_client_line(&client_line(&serde_json::json!({
            "client_secret_hash": "$hearth-sha256$v=1$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "status": "archived",
        })));
        let client = rig
            .identity
            .get_client(&realm, &cid)
            .expect("get")
            .expect("restored");
        assert_eq!(
            client.status(),
            crate::identity::ApplicationStatus::Archived
        );
    }

    // ── Streaming restore (#867) ──────────────────────────────────────────────

    /// The import pass reads every recognized member the check pass does not
    /// keep, and the two lists do not overlap: a member in neither would be
    /// accepted by the check pass and then never restored.
    #[test]
    fn every_recognized_member_is_kept_or_imported_once() {
        let mut covered: Vec<&str> = RESTORE_ORDER
            .iter()
            .chain(CHECKED_MEMBERS.iter())
            .copied()
            .collect();
        covered.sort_unstable();
        let before = covered.len();
        covered.dedup();
        assert_eq!(covered.len(), before, "a member is in both lists");
        let mut recognized = RECOGNIZED_MEMBERS.to_vec();
        recognized.sort_unstable();
        assert_eq!(covered, recognized);
    }

    fn importer(rig: &TestRig) -> BackupImporter {
        BackupImporter::new(
            Arc::clone(&rig.identity),
            Arc::clone(&rig.rbac),
            Arc::clone(&rig.audit),
            Arc::clone(&rig.webhooks),
        )
    }

    /// A member whose chunk does not authenticate is refused before anything
    /// is written, even when it comes after the members that would be
    /// restored first. A restore that decrypted one member at a time had
    /// written the realm and its users by then.
    #[test]
    fn a_member_that_does_not_authenticate_is_refused_before_any_write() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();
        let realm_uuid = "00000000-0000-0000-0000-000000000867";
        let slug = "cut-scopes";
        let archive_path = make_test_archive_raw(
            &archive_dir,
            slug,
            realm_uuid,
            &[],
            &[("scopes.ndjson", b"not a sealed member".as_slice())],
        );
        let reader = BackupArchive::open(&archive_path).expect("open");

        let err = importer(&rig)
            .import_realm(slug, &reader, &opts_with_passphrase())
            .expect_err("a member that does not authenticate must be refused");

        assert!(matches!(err, BackupError::Crypto(_)), "got {err:?}");
        let realm_id = RealmId::new(uuid::Uuid::parse_str(realm_uuid).expect("uuid"));
        assert!(
            rig.identity
                .get_realm(&realm_id)
                .expect("get realm")
                .is_none(),
            "nothing may be written before the whole archive authenticated"
        );
    }

    /// A member that is in the archive twice is refused: an export writes
    /// each member once, so the second copy was added afterwards.
    #[test]
    fn a_member_in_the_archive_twice_is_refused_before_any_write() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();
        let realm_uuid = "00000000-0000-0000-0000-000000000868";
        let slug = "twice";
        let mallory = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000003",
            "email": "mallory@example.com",
            "display_name": "Mallory",
            "first_name": "Mallory",
            "last_name": "",
            "status": "Active",
            "created_at": 0,
            "updated_at": 0
        });
        let member = format!("{mallory}\n");
        let archive_path = make_test_archive_with(
            &archive_dir,
            slug,
            realm_uuid,
            &[("users.ndjson", member.as_str())],
        );
        let reader = BackupArchive::open(&archive_path).expect("open");

        let err = importer(&rig)
            .import_realm(slug, &reader, &opts_with_passphrase())
            .expect_err("a member in the archive twice must be refused");

        assert!(err.to_string().contains("twice"), "got {err}");
        let realm_id = RealmId::new(uuid::Uuid::parse_str(realm_uuid).expect("uuid"));
        assert!(rig
            .identity
            .get_realm(&realm_id)
            .expect("get realm")
            .is_none());
    }

    /// The check pass parses every record member that the import pass
    /// reads. A member that only drained would let a malformed line through
    /// to the import pass, after the first write.
    #[test]
    fn the_check_pass_parses_every_record_member() {
        // Checked by their own arms of the check pass.
        let own_arm = ["audit.ndjson", "clients.ndjson"];
        // Raw key bytes: the identity layer validates them.
        let not_records = ["saml_signing_key.json"];
        for name in RESTORE_ORDER {
            if own_arm.contains(name) || not_records.contains(name) {
                continue;
            }
            let mut line: &[u8] = b"{\"id\": [\n";
            assert!(
                check_records(name, &mut line).is_err(),
                "the check pass accepts a broken line in {name}"
            );
        }
    }

    /// A malformed line in a record member is refused before anything is
    /// written, even when the member comes after the realm and its users in
    /// the restore order. A check pass that only authenticated the members
    /// let the import pass write the realm and its users first.
    #[test]
    fn a_malformed_record_line_is_refused_before_any_write() {
        let archive_dir = TempDir::new().expect("archive tmpdir");
        let rig = make_rig();
        let realm_uuid = "00000000-0000-0000-0000-000000000869";
        let slug = "bad-scope-line";
        let archive_path = make_test_archive_with(
            &archive_dir,
            slug,
            realm_uuid,
            &[("scopes.ndjson", "{\"bogus\": true}\n")],
        );
        let reader = BackupArchive::open(&archive_path).expect("open");

        let err = importer(&rig)
            .import_realm(slug, &reader, &opts_with_passphrase())
            .expect_err("a malformed record line must be refused");

        assert!(matches!(err, BackupError::Serialization(_)), "got {err:?}");
        let realm_id = RealmId::new(uuid::Uuid::parse_str(realm_uuid).expect("uuid"));
        assert!(
            rig.identity
                .get_realm(&realm_id)
                .expect("get realm")
                .is_none(),
            "nothing may be written before every record line parsed"
        );
    }

    /// The password credential travels on the line of its user. A line whose
    /// credential names another user is not one an export writes, and is
    /// refused rather than giving that hash to the user on the line.
    #[test]
    fn a_user_line_with_the_credential_of_another_user_is_refused() {
        let line: BackupUserLine = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "email": "alice@example.com",
            "display_name": "Alice",
            "first_name": "Alice",
            "last_name": "",
            "status": "Active",
            "created_at": 0,
            "updated_at": 0,
            "credential": {
                "user_id": "user_00000000-0000-0000-0000-000000000002",
                "phc_string": "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"
            }
        }))
        .expect("parse line");
        let credential = line.credential.expect("credential parsed");

        let err = credential
            .into_raw(&line.user)
            .expect_err("the credential of another user must be refused");

        assert!(err.to_string().contains("another user"), "got {err}");
    }

    /// A line whose credential names its own user, bare or prefixed, keeps
    /// the hash.
    #[test]
    fn a_user_line_keeps_its_own_credential() {
        for owner in [
            "00000000-0000-0000-0000-000000000001",
            "user_00000000-0000-0000-0000-000000000001",
        ] {
            let line: BackupUserLine = serde_json::from_value(serde_json::json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "email": "alice@example.com",
                "display_name": "Alice",
                "first_name": "Alice",
                "last_name": "",
                "status": "Active",
                "created_at": 0,
                "updated_at": 0,
                "credential": { "user_id": owner, "phc_string": "$argon2id$x", "created_at_micros": 7 }
            }))
            .expect("parse line");
            let credential = line.credential.expect("credential parsed");

            let raw = credential.into_raw(&line.user).expect("own credential");

            assert_eq!(raw.phc_string, "$argon2id$x");
            assert_eq!(raw.created_at_micros, Some(7));
        }
    }
}
