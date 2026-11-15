//! Backup export engine — [`BackupExporter`].
//!
//! Walks all realm entities through the identity, audit, RBAC and webhook
//! engine interfaces and serialises them to NDJSON streams inside a
//! [`BackupArchive`](super::BackupArchive).
//!
//! # Usage
//!
//! ```no_run
//! use std::path::Path;
//! use std::sync::Arc;
//! use hearth::backup::{BackupArchive, BackupManifest, BackupExporter, ExportOptions};
//! use hearth::core::RealmId;
//! use hearth::identity::IdentityEngine;
//! use hearth::audit::AuditEngine;
//! use hearth::rbac::RbacEngine;
//! use hearth::webhook::WebhookEngine;
//!
//! fn run(
//!     identity: Arc<dyn IdentityEngine>,
//!     audit: Arc<dyn AuditEngine>,
//!     rbac: Arc<dyn RbacEngine>,
//!     webhooks: Arc<dyn WebhookEngine>,
//!     realm_id: &RealmId,
//! ) {
//!     let path = Path::new("backup.hearth-backup");
//!     let mut writer = BackupArchive::create(path).unwrap();
//!     let exporter = BackupExporter::new(identity, audit, rbac, webhooks);
//!     // One storage snapshot for the whole backup.
//!     let exporter = exporter.snapshot().unwrap();
//!     let dek = BackupExporter::generate_dek().unwrap();
//!     let opts = ExportOptions::default();
//!     let realm_manifest = exporter.export_realm(realm_id, &mut writer, &opts, &dek).unwrap();
//!     // Wrap the DEK and set manifest fields before finishing.
//!     writer.finish(BackupManifest::new(vec![realm_manifest])).unwrap();
//! }
//! ```

use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::ops::ControlFlow;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{generate, SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use tracing::instrument;
use zeroize::{Zeroize, Zeroizing};

use crate::audit::AuditEngine;
use crate::core::{ExportVisitor, RealmId};
use crate::identity::IdentityEngine;
use crate::rbac::RbacEngine;
use crate::webhook::{WebhookEngine, WebhookQuery};

use super::stream::EncryptWriter;
use super::{ArchiveWriter, BackupError, DekWrappingParams, RealmManifest, RecordCounts};

const DEK_WRAP_M_COST: u32 = 65_536;
const DEK_WRAP_T_COST: u32 = 3;
const DEK_WRAP_P_COST: u32 = 4;

/// Options controlling what gets included in a realm export.
#[derive(Clone, Debug, Default)]
pub struct ExportOptions {
    /// Include audit events in the export. Audit logs can be very large; omit
    /// for routine operational backups and include only for compliance exports.
    pub include_audit: bool,
    /// Restrict export to these realm IDs. When `None`, all realms are included.
    /// Currently used by callers to filter the realm list before calling
    /// [`BackupExporter::export_realm`].
    pub realm_filter: Option<Vec<RealmId>>,
}

/// Walks realm entities through engine interfaces and serialises them to
/// NDJSON streams inside a [`BackupArchive`](super::BackupArchive).
///
/// Construct with [`new`](Self::new), then call [`export_realm`](Self::export_realm)
/// once per realm. Generate a single DEK with [`generate_dek`](Self::generate_dek)
/// and reuse it for all `export_realm` calls in the same archive; wrap and store
/// it (via [`wrap_dek`](Self::wrap_dek)) in [`BackupManifest::wrapped_dek_b64`].
pub struct BackupExporter {
    identity: Arc<dyn IdentityEngine>,
    audit: Arc<dyn AuditEngine>,
    rbac: Arc<dyn RbacEngine>,
    webhooks: Arc<dyn WebhookEngine>,
}

/// A [`BackupExporter`] that reads one storage snapshot, from
/// [`BackupExporter::snapshot`] (#643).
///
/// Only this type exports a realm, so no export reads the live engines while
/// writes change them.
pub struct SnapshotExporter(BackupExporter);

impl SnapshotExporter {
    /// Exports all entities for `realm_id` into `writer`.
    ///
    /// Writes one encrypted JSON/NDJSON file per entity type (users,
    /// credentials, MFA factors, clients, roles, groups, group memberships,
    /// permissions, scopes, assignments, organizations, organization
    /// memberships, consents) plus an AES-256-GCM encrypted
    /// `signing_key.json` and, when `opts.include_audit` is true, an
    /// encrypted `audit.ndjson` file.
    ///
    /// ALL sections are encrypted with `dek`. The DEK itself must be wrapped
    /// (via [`BackupExporter::wrap_dek`]) and stored in the manifest before
    /// calling [`ArchiveWriter::finish`].
    ///
    /// Returns a [`RealmManifest`] with record counts that the caller embeds
    /// into [`BackupManifest::realms`].
    ///
    /// # Errors
    ///
    /// Any engine, serialisation, encryption or archive error.
    pub fn export_realm(
        &self,
        realm_id: &RealmId,
        writer: &mut ArchiveWriter,
        opts: &ExportOptions,
        dek: &[u8; 32],
    ) -> Result<RealmManifest, BackupError> {
        self.0.export_realm(realm_id, writer, opts, dek)
    }
}

impl BackupExporter {
    /// Constructs a new exporter backed by the given engine references.
    ///
    /// `webhooks` must be the engine that the dispatcher reads, so that the
    /// archive carries the subscriptions that deliver events (#654).
    pub fn new(
        identity: Arc<dyn IdentityEngine>,
        audit: Arc<dyn AuditEngine>,
        rbac: Arc<dyn RbacEngine>,
        webhooks: Arc<dyn WebhookEngine>,
    ) -> Self {
        Self {
            identity,
            audit,
            rbac,
            webhooks,
        }
    }

    /// Generates a fresh random 32-byte Data Encryption Key.
    ///
    /// Generate once per archive and pass the same key to every
    /// [`export_realm`](Self::export_realm) call. Wrap with
    /// [`wrap_dek`](Self::wrap_dek) and store in
    /// [`BackupManifest::wrapped_dek_b64`].
    pub fn generate_dek() -> Result<[u8; 32], BackupError> {
        let mut bytes = [0u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| BackupError::Crypto("DEK generation failed".into()))?;
        Ok(bytes)
    }

    /// Wraps `dek` with an Argon2id-derived key from `passphrase`.
    ///
    /// Returns the base64-encoded wrapped blob and the [`DekWrappingParams`]
    /// that must be stored alongside it in the manifest.
    ///
    /// # Errors
    ///
    /// Returns `Err` if salt or nonce generation or AES-GCM sealing fails.
    pub fn wrap_dek(
        dek: &[u8; 32],
        passphrase: &SecretString,
    ) -> Result<(String, DekWrappingParams), BackupError> {
        let rng = SystemRandom::new();
        let salt = generate::<[u8; 16]>(&rng)
            .map_err(|_| BackupError::Crypto("salt generation failed".into()))?
            .expose();
        let nonce_bytes = generate::<[u8; 12]>(&rng)
            .map_err(|_| BackupError::Crypto("nonce generation failed".into()))?
            .expose();
        let mut wk = derive_dek_wrapping_key(passphrase.expose_secret().as_bytes(), &salt)?;
        let unbound = UnboundKey::new(&AES_256_GCM, &wk)
            .map_err(|_| BackupError::Crypto("AES key init failed".into()))?;
        wk.zeroize();
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut blob = dek.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut blob)
            .map_err(|_| BackupError::Crypto("DEK wrap failed".into()))?;
        let mut full = Vec::with_capacity(12 + blob.len());
        full.extend_from_slice(&nonce_bytes);
        full.extend_from_slice(&blob);
        Ok((
            BASE64.encode(full),
            DekWrappingParams {
                salt_b64: BASE64.encode(salt),
                m_cost: DEK_WRAP_M_COST,
                t_cost: DEK_WRAP_T_COST,
                p_cost: DEK_WRAP_P_COST,
            },
        ))
    }

    /// Unwraps a DEK previously wrapped by [`wrap_dek`].
    ///
    /// Returns the plaintext 32-byte DEK in a [`Zeroizing`] wrapper so the
    /// key material is actively overwritten when dropped.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the blob is malformed, the passphrase is wrong,
    /// or the ciphertext is corrupted.
    pub fn unwrap_dek(
        wrapped_b64: &str,
        params: &DekWrappingParams,
        passphrase: &SecretString,
    ) -> Result<Zeroizing<[u8; 32]>, BackupError> {
        let blob = BASE64
            .decode(wrapped_b64)
            .map_err(|e| BackupError::Crypto(format!("wrapped DEK decode: {e}")))?;
        if blob.len() < 60 {
            return Err(BackupError::Crypto("wrapped DEK blob too short".into()));
        }
        let (nonce_bytes, ciphertext_tag) = blob.split_at(12);
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce_bytes);
        let salt_bytes = BASE64
            .decode(&params.salt_b64)
            .map_err(|e| BackupError::Crypto(format!("salt decode: {e}")))?;
        let salt: [u8; 16] = salt_bytes
            .try_into()
            .map_err(|_| BackupError::Crypto("salt must be 16 bytes".into()))?;
        let mut wk = derive_dek_wrapping_key_with_params(
            passphrase.expose_secret().as_bytes(),
            &salt,
            params.m_cost,
            params.t_cost,
            params.p_cost,
        )?;
        let unbound = UnboundKey::new(&AES_256_GCM, &wk)
            .map_err(|_| BackupError::Crypto("AES key init failed".into()))?;
        wk.zeroize();
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(nonce_arr);
        let mut buf = ciphertext_tag.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut buf)
            .map_err(|_| {
                BackupError::Crypto(
                    "DEK unwrap failed — wrong passphrase or corrupted archive".into(),
                )
            })?;
        if plaintext.len() != 32 {
            return Err(BackupError::Crypto(format!(
                "DEK must be 32 bytes, got {}",
                plaintext.len()
            )));
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(plaintext);
        Ok(Zeroizing::new(dek))
    }

    /// Returns an exporter that reads one storage snapshot of this moment
    /// (#643).
    ///
    /// Call it once per backup and export every realm through the result: the
    /// archive is then one point in time across all its realms, and no write
    /// waits for the export. The snapshot holds the disk space of SST files
    /// that compaction replaces until the returned exporter is dropped.
    ///
    /// When the storage cannot make a snapshot (test doubles), the result
    /// reads the live engines, and a write during the export can tear the
    /// archive.
    ///
    /// # Errors
    ///
    /// [`BackupError::Engine`] when the snapshot cannot be made, or when an
    /// engine cannot read it.
    pub fn snapshot(&self) -> Result<SnapshotExporter, BackupError> {
        let Some(storage) = self
            .identity
            .read_snapshot()
            .map_err(|e| BackupError::Engine(e.to_string()))?
        else {
            tracing::warn!("storage makes no snapshot; the export reads the live engines");
            return Ok(SnapshotExporter(Self {
                identity: Arc::clone(&self.identity),
                audit: Arc::clone(&self.audit),
                rbac: Arc::clone(&self.rbac),
                webhooks: Arc::clone(&self.webhooks),
            }));
        };
        let unsupported = |engine: &str| {
            BackupError::Engine(format!("the {engine} engine cannot read a snapshot"))
        };
        let rbac = self
            .rbac
            .read_view(Arc::clone(&storage))
            .ok_or_else(|| unsupported("RBAC"))?;
        let audit = self
            .audit
            .read_view(Arc::clone(&storage))
            .ok_or_else(|| unsupported("audit"))?;
        let webhooks = self
            .webhooks
            .read_view(Arc::clone(&storage))
            .ok_or_else(|| unsupported("webhook"))?;
        let identity = self
            .identity
            .read_view(storage, Arc::clone(&rbac), Arc::clone(&audit))
            .map_err(|e| BackupError::Engine(e.to_string()))?
            .ok_or_else(|| unsupported("identity"))?;
        Ok(SnapshotExporter(Self {
            identity,
            audit,
            rbac,
            webhooks,
        }))
    }

    /// Exports all entities for `realm_id` into `writer`.
    ///
    /// Writes one encrypted JSON/NDJSON file per entity type (users, credentials,
    /// MFA factors, clients, roles, groups, group memberships, permissions,
    /// scopes, assignments, organizations, organization memberships, consents)
    /// plus an AES-256-GCM encrypted `signing_key.json` and, when
    /// `opts.include_audit` is true, an encrypted `audit.ndjson` file.
    ///
    /// ALL sections are encrypted with `dek`. The DEK itself must be wrapped
    /// (via [`wrap_dek`](Self::wrap_dek)) and stored in the manifest before
    /// calling [`ArchiveWriter::finish`].
    ///
    /// Returns a [`RealmManifest`] with record counts that the caller embeds
    /// into [`BackupManifest::realms`].
    #[instrument(skip(self, writer, opts, dek), fields(realm = %realm_id))]
    #[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
    fn export_realm(
        &self,
        realm_id: &RealmId,
        writer: &mut ArchiveWriter,
        opts: &ExportOptions,
        dek: &[u8; 32],
    ) -> Result<RealmManifest, BackupError> {
        // An exporter from `snapshot()` reads one storage snapshot, so every
        // read below sees the same point in time (no group membership names a
        // user the archive omits) and no write waits for the export (#643).
        //
        // Each member is streamed (#866): the engines pass the records one at
        // a time, each record is serialised into a chunked encryptor, and the
        // encrypted member is spooled to an anonymous temporary file and then
        // copied into the archive. The export holds one chunk and one record
        // at a time, whatever the size of the realm.
        let engine = |e: &dyn std::fmt::Display| BackupError::Engine(e.to_string());

        let realm = self.identity.get_realm(realm_id).map_err(|e| engine(&e))?;
        let slug = realm
            .as_ref()
            .map(|r| slugify(r.name()))
            .unwrap_or_else(|| realm_id.as_uuid().to_string());
        let prefix = format!("realms/{slug}");
        let mut counts = RecordCounts::default();
        let mut out = MemberOutput {
            writer,
            dek,
            prefix: &prefix,
        };

        // realm.json
        if let Some(ref r) = realm {
            out.bytes("realm.json", &Zeroizing::new(serde_json::to_vec_pretty(r)?))?;
        }

        // users.ndjson — one walk of the user keys. Pages of `list_users` each
        // walk every user key to count the total.
        counts.users = out.ndjson("users.ndjson", |visit| {
            self.identity.export_all_users(realm_id, visit)
        })?;

        // credentials.ndjson
        counts.credentials = out.ndjson("credentials.ndjson", |visit| {
            self.identity.export_all_credentials(realm_id, visit)
        })?;

        // mfa_factors.ndjson — TOTP/recovery-code state (decrypted; every
        // archive section is itself AES-256-GCM encrypted) and WebAuthn
        // passkeys. Without this an operator who restores a realm silently
        // loses every second factor (audit 2026-08-28 §4.18#5).
        counts.mfa_factors = out.ndjson("mfa_factors.ndjson", |visit| {
            self.identity.export_all_mfa_factors(realm_id, visit)
        })?;

        // clients.ndjson
        counts.clients = out.ndjson("clients.ndjson", |visit| {
            visit_offset_pages(visit, |page| {
                self.identity
                    .list_clients(realm_id, &page)
                    .map_err(|e| engine(&e))
            })
        })?;

        // roles.ndjson
        counts.roles = out.ndjson("roles.ndjson", |visit| {
            visit_cursor_pages(visit, |cursor| {
                self.rbac
                    .list_roles(realm_id, cursor, 500)
                    .map(|p| (p.items, p.next_cursor))
                    .map_err(|e| engine(&e))
            })
        })?;

        // permissions.ndjson
        counts.permissions = out.ndjson("permissions.ndjson", |visit| {
            visit_vec(visit, self.rbac.export_all_permissions(realm_id))
        })?;

        // groups.ndjson
        counts.groups = out.ndjson("groups.ndjson", |visit| {
            visit_offset_pages(visit, |page| {
                self.rbac
                    .list_groups(realm_id, &page)
                    .map_err(|e| engine(&e))
            })
        })?;

        // assignments.ndjson
        counts.assignments = out.ndjson("assignments.ndjson", |visit| {
            self.rbac.visit_all_assignments(realm_id, visit)
        })?;

        // scopes.ndjson
        counts.scopes = out.ndjson("scopes.ndjson", |visit| {
            visit_vec(visit, self.rbac.export_all_scopes(realm_id))
        })?;

        // organizations.ndjson
        counts.organizations = out.ndjson("organizations.ndjson", |visit| {
            visit_offset_pages(visit, |page| {
                self.identity
                    .list_organizations(realm_id, &page)
                    .map_err(|e| engine(&e))
            })
        })?;

        // group_memberships.ndjson — the edges between a group and its
        // members. Without this, groups restore EMPTY: the group record and
        // the role-to-group assignment both come back, so every count matches
        // while the permissions the group granted silently vanish
        // (OpenSpec 26.40).
        counts.group_memberships = out.ndjson("group_memberships.ndjson", |visit| {
            self.rbac.export_all_group_memberships(realm_id, visit)
        })?;

        // organization_memberships.ndjson — same shape as group memberships:
        // organizations used to restore with nobody in them.
        counts.organization_memberships =
            out.ndjson("organization_memberships.ndjson", |visit| {
                self.identity
                    .export_all_organization_memberships(realm_id, visit)
            })?;

        // consents.ndjson — a restored user must not be re-prompted for
        // consent they already granted.
        counts.consents = out.ndjson("consents.ndjson", |visit| {
            self.identity.export_all_consents(realm_id, visit)
        })?;

        // agents.ndjson — the agent record AND its credentials. An agent that
        // vanishes on restore takes its credentials and its authority with it
        // (OpenSpec 26.40).
        counts.agents = out.ndjson("agents.ndjson", |visit| {
            visit_vec(visit, self.identity.export_all_agents(realm_id))
        })?;

        // identity_providers.ndjson — the connector configs. The IdpId must
        // survive because every federation link is keyed by it.
        counts.identity_providers = out.ndjson("identity_providers.ndjson", |visit| {
            visit_vec(visit, self.identity.export_all_identity_providers(realm_id))
        })?;

        // federation_links.ndjson — the user-to-IdP bindings. Without them a
        // user who only ever signed in through an external IdP cannot get back
        // in, even with the connector restored.
        counts.federation_links = out.ndjson("federation_links.ndjson", |visit| {
            self.identity.export_all_federation_links(realm_id, visit)
        })?;

        // webhook_subscriptions.ndjson — the subscriptions that the dispatcher
        // delivers to (#654): silent loss of an integration nobody notices
        // until it is needed. The signing secret rides along so the
        // receiver's signature check keeps passing. The identity engine's
        // own webhook store (`webhooks.ndjson` in older archives) never
        // delivered (#617) and is not exported.
        counts.webhook_subscriptions = out.ndjson("webhook_subscriptions.ndjson", |visit| {
            visit_vec(
                visit,
                self.webhooks.list(&WebhookQuery {
                    realm_id: realm_id.clone(),
                    enabled_only: false,
                }),
            )
        })?;

        // saml_signing_key.json — the realm's SAML key, whose certificate the
        // SP metadata publishes to upstream IdPs.
        if let Some(saml_key) = self
            .identity
            .export_realm_saml_key(realm_id)
            .map_err(|e| engine(&e))?
        {
            // Unsealed on the way out, resealed under the destination's KEK on
            // the way in. The archive member itself is DEK-encrypted.
            out.bytes("saml_signing_key.json", &saml_key)?;
        }

        // scim_mappings.ndjson — without them the next SCIM sync re-creates
        // every user it provisioned instead of updating it.
        counts.scim_mappings = out.ndjson("scim_mappings.ndjson", |visit| {
            self.identity.export_all_scim_mappings(realm_id, visit)
        })?;

        // invitations.ndjson — an outstanding invitation link must still
        // redeem after the restore.
        counts.invitations = out.ndjson("invitations.ndjson", |visit| {
            self.identity.export_all_invitations(realm_id, visit)
        })?;

        // revocations.ndjson — revoked access-token JTIs, blocked DPoP keys and
        // revoked AAT JTIs. A sessionless token (`client_credentials`, an
        // agent's) verifies against the restored signing key, so without these
        // a token revoked before the backup validates again after a restore
        // (audit GA 2026-09-28 M3). Expired JTIs are omitted. Each user's
        // required-action generation travels here too: a restore that reset it
        // to 0 revived RA tokens a revocation had ended (GA sweep 4) — and so
        // do the spent markers of flows that already ended, which could
        // otherwise end again (GA sweep 4 round 2).
        counts.revocations = out.ndjson("revocations.ndjson", |visit| {
            self.identity.export_revocations(realm_id, visit)
        })?;

        // retiring_signing_keys.json — a restore taken mid-rotation is exactly
        // when the outgoing key matters. Deadlines are absolute, so the window
        // resumes rather than restarting, and keys already past theirs are not
        // exported at all.
        counts.retiring_signing_keys = out.ndjson("retiring_signing_keys.json", |visit| {
            visit_vec(visit, self.identity.export_retiring_signing_keys(realm_id))
        })?;

        // signing_key.json (AES-256-GCM encrypted PKCS#8 bytes)
        let pkcs8 = Zeroizing::new(
            self.identity
                .export_realm_signing_key_pkcs8(realm_id)
                .map_err(|e| engine(&e))?,
        );
        out.bytes("signing_key.json", &pkcs8)?;

        // id_token_signing_key.json — the realm's RS256 ID-token key, present
        // once any client in the realm selected RS256 (task 26.55). Without it
        // a restore would provision a new RSA key and every ID token issued
        // before the backup would stop verifying. Unsealed by the engine,
        // DEK-encrypted here, re-sealed under the destination's KEK on import.
        if let Some(rsa_pkcs8) = self
            .identity
            .export_realm_id_token_rsa_key(realm_id)
            .map_err(|e| engine(&e))?
        {
            out.bytes("id_token_signing_key.json", &rsa_pkcs8)?;
        }

        // retiring_id_token_signing_keys.json — the RS256 twin of
        // retiring_signing_keys.json: absolute deadlines, expired keys omitted.
        counts.retiring_id_token_signing_keys =
            out.ndjson("retiring_id_token_signing_keys.json", |visit| {
                visit_vec(
                    visit,
                    self.identity.export_retiring_id_token_rsa_keys(realm_id),
                )
            })?;

        // audit.ndjson (optional), plus the chain material a restore needs to
        // check the exported hashes instead of discarding them (§4.14#5).
        let mut audit_chain_included = false;
        if opts.include_audit {
            counts.audit_events = out.ndjson("audit.ndjson", |visit| {
                self.audit.export_events(realm_id, visit)
            })?;
            if counts.audit_events > 0 {
                let material = self
                    .audit
                    .export_chain_material(realm_id)
                    .map_err(|e| engine(&e))?
                    .ok_or_else(|| {
                        BackupError::Engine(
                            "realm has audit events but no chain material; refusing to write an \
                             archive whose audit log cannot be verified on restore"
                                .to_string(),
                        )
                    })?;
                out.bytes(
                    "audit_chain.json",
                    &Zeroizing::new(serde_json::to_vec(&material)?),
                )?;
                audit_chain_included = true;
            }
        }

        Ok(RealmManifest {
            realm_id: realm_id.as_uuid().to_string(),
            slug,
            record_counts: counts,
            audit_chain_included,
        })
    }
}

/// Writes the encrypted members of one realm into the archive.
struct MemberOutput<'a> {
    writer: &'a mut ArchiveWriter,
    dek: &'a [u8; 32],
    /// `realms/<slug>`.
    prefix: &'a str,
}

impl MemberOutput<'_> {
    /// Writes `data` as the member `name`.
    fn bytes(&mut self, name: &str, data: &[u8]) -> Result<(), BackupError> {
        let mut member = MemberWriter::new(format!("{}/{name}", self.prefix), self.dek)?;
        member.out.write_all(data)?;
        member.finish_into(self.writer)
    }

    /// Writes the NDJSON member `name` from the records that `walk` passes
    /// to its visitor, one line per record, and returns the number of
    /// records. A member with no record is left out of the archive.
    ///
    /// # Errors
    ///
    /// The error of `walk` as [`BackupError::Engine`], or the first error
    /// serialising, encrypting or writing a record.
    fn ndjson<T, E, F>(&mut self, name: &str, walk: F) -> Result<u64, BackupError>
    where
        T: Serialize,
        E: std::fmt::Display,
        F: FnOnce(&mut ExportVisitor<'_, T>) -> Result<(), E>,
    {
        let mut member = MemberWriter::new(format!("{}/{name}", self.prefix), self.dek)?;
        let mut failure = None;
        walk(&mut |record: T| match member.record(&record) {
            Ok(()) => ControlFlow::Continue(()),
            Err(e) => {
                failure = Some(e);
                ControlFlow::Break(())
            }
        })
        .map_err(|e| BackupError::Engine(e.to_string()))?;
        if let Some(e) = failure {
            return Err(e);
        }
        let records = member.records;
        if records > 0 {
            member.finish_into(self.writer)?;
        }
        Ok(records)
    }
}

/// Bytes of the write buffer in front of a member's spool file.
const SPOOL_BUFFER_LEN: usize = 64 * 1024;

/// One archive member while it is written (#866).
///
/// The records are serialised into a chunked encryptor, and the encrypted
/// member goes to an anonymous temporary file (the spool): a tar entry needs
/// its size before its bytes. [`finish_into`](Self::finish_into) then copies
/// the spool into the archive. The spool holds only ciphertext, and it is
/// unlinked from the moment it is made, so it is gone when it is dropped.
struct MemberWriter {
    path: String,
    out: EncryptWriter<BufWriter<std::fs::File>>,
    records: u64,
}

impl MemberWriter {
    fn new(path: String, dek: &[u8; 32]) -> Result<Self, BackupError> {
        let spool = BufWriter::with_capacity(SPOOL_BUFFER_LEN, tempfile::tempfile()?);
        let out = EncryptWriter::new(spool, dek, &path)?;
        Ok(Self {
            path,
            out,
            records: 0,
        })
    }

    /// Writes `record` as one NDJSON line.
    fn record<T: Serialize>(&mut self, record: &T) -> Result<(), BackupError> {
        serde_json::to_writer(&mut self.out, record)?;
        self.out.write_all(b"\n")?;
        self.records += 1;
        Ok(())
    }

    /// Seals the member and copies it from the spool into `writer`.
    fn finish_into(self, writer: &mut ArchiveWriter) -> Result<(), BackupError> {
        let mut spool = self
            .out
            .finish()?
            .into_inner()
            .map_err(|e| BackupError::Io(e.into_error()))?;
        let len = spool.stream_position()?;
        spool.seek(SeekFrom::Start(0))?;
        writer.add_reader(&self.path, len, spool)
    }
}

/// Passes every item of `items` to `visit`, for an engine call that returns a
/// small family as one `Vec`.
fn visit_vec<T, E: std::fmt::Display>(
    visit: &mut ExportVisitor<'_, T>,
    items: Result<Vec<T>, E>,
) -> Result<(), BackupError> {
    let items = items.map_err(|e| BackupError::Engine(e.to_string()))?;
    for item in items {
        if visit(item).is_break() {
            break;
        }
    }
    Ok(())
}

/// Passes every item of a cursor-paginated engine call to `visit`, one page
/// at a time.
///
/// The closure returns `(items, next_cursor)` — this avoids a type conflict
/// between `identity::types::Page<T>` and `rbac::types::Page<T>`, which are
/// structurally identical but distinct types.
fn visit_cursor_pages<T, F>(visit: &mut ExportVisitor<'_, T>, fetch: F) -> Result<(), BackupError>
where
    F: Fn(Option<&str>) -> Result<(Vec<T>, Option<String>), BackupError>,
{
    let mut cursor: Option<String> = None;
    loop {
        let (items, next_cursor) = fetch(cursor.as_deref())?;
        for item in items {
            if visit(item).is_break() {
                return Ok(());
            }
        }
        match next_cursor {
            None => return Ok(()),
            Some(c) => cursor = Some(c),
        }
    }
}

/// Passes every item of an offset-paginated engine call (`PageRequest` /
/// `PagedResult`) to `visit`, one page at a time.
fn visit_offset_pages<T, F>(visit: &mut ExportVisitor<'_, T>, fetch: F) -> Result<(), BackupError>
where
    F: Fn(crate::core::PageRequest) -> Result<crate::core::PagedResult<T>, BackupError>,
{
    let batch = crate::core::MAX_PAGE_LIMIT;
    let mut offset = 0u64;
    loop {
        let result = fetch(crate::core::PageRequest::new(offset, batch))?;
        let n = result.items.len() as u64;
        let total = result.total;
        for item in result.items {
            if visit(item).is_break() {
                return Ok(());
            }
        }
        if n == 0 || offset + n >= total {
            return Ok(());
        }
        offset += n;
    }
}

/// Converts a realm display name to a URL-safe archive slug.
///
/// Lowercases and replaces any run of non-alphanumeric characters with a
/// single hyphen. Trailing hyphens are stripped.
fn slugify(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut prev_hyphen = false;
    for c in name.chars() {
        if c.is_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            prev_hyphen = false;
        } else if !prev_hyphen && !slug.is_empty() {
            slug.push('-');
            prev_hyphen = true;
        }
    }
    slug.trim_end_matches('-').to_string()
}

/// Derives a 32-byte AES wrapping key using Argon2id with default DEK-wrapping parameters.
fn derive_dek_wrapping_key(password: &[u8], salt: &[u8; 16]) -> Result<[u8; 32], BackupError> {
    derive_dek_wrapping_key_with_params(
        password,
        salt,
        DEK_WRAP_M_COST,
        DEK_WRAP_T_COST,
        DEK_WRAP_P_COST,
    )
}

/// Derives a 32-byte AES wrapping key using Argon2id with explicit parameters.
fn derive_dek_wrapping_key_with_params(
    password: &[u8],
    salt: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], BackupError> {
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| BackupError::Crypto(format!("argon2 params: {e}")))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| BackupError::Crypto(format!("argon2 derivation: {e}")))?;
    Ok(key)
}

/// Wraps a 32-byte DEK with an Argon2id-derived key from `passphrase`.
///
/// Delegates to [`BackupExporter::wrap_dek`].
pub fn wrap_dek(
    dek: &[u8; 32],
    passphrase: &SecretString,
) -> Result<(String, DekWrappingParams), BackupError> {
    BackupExporter::wrap_dek(dek, passphrase)
}

/// Unwraps a DEK previously wrapped by [`wrap_dek`].
///
/// Delegates to [`BackupExporter::unwrap_dek`].
pub fn unwrap_dek(
    wrapped_b64: &str,
    params: &DekWrappingParams,
    passphrase: &SecretString,
) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    BackupExporter::unwrap_dek(wrapped_b64, params, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{
        EmbeddedStorageEngine, EntryVisitor, ScanEntry, StorageEngine, StorageError,
    };

    #[test]
    fn generate_dek_produces_distinct_keys() {
        let a = BackupExporter::generate_dek().expect("dek a");
        let b = BackupExporter::generate_dek().expect("dek b");
        assert_ne!(a, b, "each generated DEK must be unique");
    }

    #[test]
    fn wrap_unwrap_dek_roundtrip() {
        let dek = BackupExporter::generate_dek().expect("generate DEK");
        let passphrase = secrecy::SecretString::new("test-passphrase-12345".into());
        let (wrapped_b64, params) = BackupExporter::wrap_dek(&dek, &passphrase).expect("wrap DEK");
        let recovered =
            BackupExporter::unwrap_dek(&wrapped_b64, &params, &passphrase).expect("unwrap DEK");
        assert_eq!(*recovered, dek, "unwrapped DEK must equal the original DEK");
    }

    #[test]
    fn unwrap_dek_with_wrong_passphrase_fails() {
        let dek = BackupExporter::generate_dek().expect("generate DEK");
        let correct = secrecy::SecretString::new("correct-passphrase".into());
        let wrong = secrecy::SecretString::new("wrong-passphrase".into());
        let (wrapped_b64, params) = BackupExporter::wrap_dek(&dek, &correct).expect("wrap DEK");
        let result = BackupExporter::unwrap_dek(&wrapped_b64, &params, &wrong);
        result.expect_err("unwrap with wrong passphrase must fail");
    }

    #[test]
    fn unwrap_dek_with_truncated_blob_fails() {
        let passphrase = secrecy::SecretString::new("passphrase".into());
        let params = DekWrappingParams {
            salt_b64: base64::engine::general_purpose::STANDARD.encode([0u8; 16]),
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        // A blob that is too short (< 60 bytes) must be rejected immediately.
        let short_blob = base64::engine::general_purpose::STANDARD.encode([0u8; 10]);
        let result = BackupExporter::unwrap_dek(&short_blob, &params, &passphrase);
        result.expect_err("truncated blob must be rejected");
    }

    #[test]
    fn wrap_dek_produces_distinct_outputs() {
        let dek = BackupExporter::generate_dek().expect("generate DEK");
        let passphrase = secrecy::SecretString::new("same-passphrase".into());
        let (b1, _) = BackupExporter::wrap_dek(&dek, &passphrase).expect("wrap 1");
        let (b2, _) = BackupExporter::wrap_dek(&dek, &passphrase).expect("wrap 2");
        assert_ne!(
            b1, b2,
            "each wrap must produce a distinct ciphertext (random nonce+salt)"
        );
    }

    /// Storage that counts the user records (`usr:id:` keys) that reads walk or
    /// return. Every call goes through to the real engine.
    struct UserReadCountingStorage {
        inner: Arc<EmbeddedStorageEngine>,
        user_reads: std::sync::atomic::AtomicUsize,
    }

    impl UserReadCountingStorage {
        fn count(&self, key: &[u8]) {
            if key.starts_with(&crate::identity::keys::user_id_scan_prefix()) {
                self.user_reads
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        fn take(&self) -> usize {
            self.user_reads.swap(0, std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl StorageEngine for UserReadCountingStorage {
        fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(realm_id, key)
        }

        fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            self.inner.put(realm_id, key, value)
        }

        fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
            self.inner.delete(realm_id, key)
        }

        fn scan(
            &self,
            realm_id: &RealmId,
            start: &[u8],
            end: &[u8],
        ) -> Result<Vec<ScanEntry>, StorageError> {
            let entries = self.inner.scan(realm_id, start, end)?;
            for entry in &entries {
                self.count(&entry.key);
            }
            Ok(entries)
        }

        fn scan_keys(
            &self,
            realm_id: &RealmId,
            start: &[u8],
            end: &[u8],
        ) -> Result<Vec<Vec<u8>>, StorageError> {
            let keys = self.inner.scan_keys(realm_id, start, end)?;
            for key in &keys {
                self.count(key);
            }
            Ok(keys)
        }

        fn visit_keys(
            &self,
            realm_id: &RealmId,
            start: &[u8],
            end: &[u8],
            visit: &mut dyn FnMut(&[u8]) -> std::ops::ControlFlow<()>,
        ) -> Result<(), StorageError> {
            self.inner.visit_keys(realm_id, start, end, &mut |key| {
                self.count(key);
                visit(key)
            })
        }

        fn visit_entries(
            &self,
            realm_id: &RealmId,
            start: &[u8],
            end: &[u8],
            visit: &mut EntryVisitor<'_>,
        ) -> Result<(), StorageError> {
            self.inner
                .visit_entries(realm_id, start, end, &mut |key, value| {
                    self.count(key);
                    visit(key, value)
                })
        }

        fn list_realms(&self) -> Result<Vec<RealmId>, StorageError> {
            self.inner.list_realms()
        }

        fn begin_snapshot_restore(&self, snapshot_id: &str) -> Result<(), StorageError> {
            self.inner.begin_snapshot_restore(snapshot_id)
        }

        fn complete_snapshot_restore(&self) -> Result<(), StorageError> {
            self.inner.complete_snapshot_restore()
        }
    }

    /// A backup reads each user record a bounded number of times. The export
    /// read users a page of 200 at a time, and each page walked every user key
    /// in the realm to count them. At 1,000,000 users that is 5,000 walks of
    /// 1,000,000 keys: 36 minutes in the restore drill, while a write barrier
    /// held every write on the node (#695).
    #[test]
    fn export_reads_each_user_record_a_bounded_number_of_times() {
        use crate::audit::EmbeddedAuditEngine;
        use crate::core::{Clock, SystemClock};
        use crate::identity::{
            CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
            IdentityConfig,
        };
        use crate::rbac::EmbeddedRbacEngine;
        use crate::storage::StorageConfig;
        use crate::webhook::EmbeddedWebhookEngine;

        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(UserReadCountingStorage {
            inner: Arc::new(
                EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
                    .expect("open storage"),
            ),
            user_reads: std::sync::atomic::AtomicUsize::new(0),
        });
        let shared = Arc::clone(&storage) as Arc<dyn StorageEngine>;
        let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
        let rbac = Arc::new(EmbeddedRbacEngine::new(
            Arc::clone(&shared),
            Arc::clone(&clock),
        ));
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&shared),
            Arc::clone(&clock),
        ));
        let identity = Arc::new(
            EmbeddedIdentityEngine::with_rbac(
                Arc::clone(&shared),
                Arc::clone(&clock),
                IdentityConfig {
                    credential: CredentialConfig::fast_for_testing(),
                    ..IdentityConfig::default()
                },
                Arc::clone(&rbac) as Arc<dyn RbacEngine>,
                Arc::clone(&audit) as Arc<dyn AuditEngine>,
            )
            .expect("identity engine"),
        );
        let webhooks = Arc::new(EmbeddedWebhookEngine::new(
            Arc::clone(&shared),
            Arc::clone(&clock),
        ));

        let realm = identity
            .create_realm(&CreateRealmRequest {
                name: "user-read-count".into(),
                config: None,
            })
            .expect("create realm")
            .id()
            .clone();
        // Three full pages and one more user.
        let users = 3 * crate::core::MAX_PAGE_LIMIT as usize + 1;
        for i in 0..users {
            identity
                .create_user(
                    &realm,
                    &CreateUserRequest {
                        email: format!("user-{i}@user-read-count.example"),
                        display_name: format!("User {i}"),
                        first_name: "User".into(),
                        last_name: "Count".into(),
                        attributes: Default::default(),
                    },
                )
                .expect("create user");
        }

        let exporter = BackupExporter::new(identity, audit, rbac, webhooks)
            .snapshot()
            .expect("snapshot");
        let archive = tempfile::NamedTempFile::new().expect("tempfile");
        let mut writer = crate::backup::BackupArchive::create(archive.path()).expect("archive");
        let dek = BackupExporter::generate_dek().expect("generate DEK");
        storage.take();
        let manifest = exporter
            .export_realm(&realm, &mut writer, &ExportOptions::default(), &dek)
            .expect("export realm");

        let reads = storage.take();
        assert_eq!(
            manifest.record_counts.users, users as u64,
            "every user is in the archive"
        );
        assert!(
            reads <= 2 * users,
            "the export read {reads} user records for {users} users"
        );
    }
}
