//! Restores the records of a backup member in batches (#896).
//!
//! Each record is validated and turned into the rows it writes by one
//! `stage_*` function, the same for one record (`import_consent`, ...) and
//! for a batch ([`IdentityEngine::import_records`]). A
//! [`WritePipeline`] then writes each record as one atomic batch, and many
//! records share each fsync: one by one, a restore wrote 175–300 records/s on
//! a cloud disk, and 10M records took 10–16 hours.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::core::{ImportOutcome, OrganizationId, RealmId, UserId};
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::totp::{self, StoredMfaState};
use crate::identity::types::{
    AgentExport, ConsentExport, FederationLinkExport, ImportRecords, MfaFactorExport, Organization,
    OrganizationInvitation, OrganizationMembership, RevocationExport, ScimMappingExport,
    ScimMappingKind,
};
use crate::storage::write_pipeline::WritePipeline;

use super::control::{self, ControlOp};
use super::EmbeddedIdentityEngine;

/// The pipeline the records of a batch are written through.
type ImportPipeline<'s> = WritePipeline<'s, ImportOutcome, IdentityError>;

/// What one validated record writes.
enum Staged {
    /// Nothing: the record is skipped.
    Skipped,
    /// `rows`, as one atomic batch. The record's outcome is `outcome` once
    /// the batch is durable, and `control` is then applied to the control
    /// caches.
    Rows {
        rows: Vec<(Vec<u8>, Vec<u8>)>,
        outcome: ImportOutcome,
        control: Option<ControlOp>,
    },
    /// `key` = `value` when `key` is absent: `Created`, or `Skipped` when it
    /// is there.
    IfAbsent { key: Vec<u8>, value: Vec<u8> },
    /// The stage function enqueued the record itself.
    Enqueued,
}

impl Staged {
    /// `rows` of a record that exists already (`exists`) or not.
    fn rows(rows: Vec<(Vec<u8>, Vec<u8>)>, exists: bool) -> Self {
        Staged::Rows {
            rows,
            outcome: if exists {
                ImportOutcome::Overwritten
            } else {
                ImportOutcome::Created
            },
            control: None,
        }
    }
}

fn serialization(e: &serde_json::Error) -> IdentityError {
    IdentityError::Serialization {
        reason: e.to_string(),
    }
}

impl EmbeddedIdentityEngine {
    /// [`IdentityEngine::import_records`](crate::identity::IdentityEngine::import_records).
    pub(super) fn import_records_batch(
        &self,
        realm_id: &RealmId,
        records: ImportRecords<'_>,
        overwrite: bool,
    ) -> Vec<Result<ImportOutcome, IdentityError>> {
        match records {
            ImportRecords::Organizations(orgs) => self.import_staged(realm_id, orgs, |_, org| {
                self.stage_organization(realm_id, org, overwrite)
            }),
            ImportRecords::MfaFactors(factors) => {
                self.import_staged(realm_id, factors, |pipeline, factor| {
                    self.stage_mfa_factor(pipeline, realm_id, factor, overwrite)
                })
            }
            ImportRecords::OrganizationMemberships(memberships) => {
                self.import_staged(realm_id, memberships, |_, membership| {
                    self.stage_organization_membership(realm_id, membership, overwrite)
                })
            }
            ImportRecords::Consents(consents) => {
                self.import_staged(realm_id, consents, |_, consent| {
                    self.stage_consent(realm_id, consent, overwrite)
                })
            }
            ImportRecords::Agents(agents) => self.import_staged(realm_id, agents, |_, export| {
                self.stage_agent(realm_id, export, overwrite)
            }),
            ImportRecords::FederationLinks(links) => {
                self.import_staged(realm_id, links, |_, link| {
                    self.stage_federation_link(realm_id, link, overwrite)
                })
            }
            ImportRecords::ScimMappings(mappings) => {
                self.import_staged(realm_id, mappings, |_, mapping| {
                    self.stage_scim_mapping(realm_id, mapping, overwrite)
                })
            }
            ImportRecords::Invitations(invitations) => {
                self.import_staged(realm_id, invitations, |_, invitation| {
                    self.stage_invitation(realm_id, invitation, overwrite)
                })
            }
            ImportRecords::Revocations(revocations) => {
                self.import_staged(realm_id, revocations, |pipeline, revocation| {
                    self.stage_revocation(pipeline, realm_id, revocation, overwrite)
                })
            }
        }
    }

    /// Restores one record through [`Self::import_records_batch`].
    pub(super) fn import_one_record(
        &self,
        realm_id: &RealmId,
        record: ImportRecords<'_>,
        overwrite: bool,
    ) -> Result<ImportOutcome, IdentityError> {
        self.import_records_batch(realm_id, record, overwrite)
            .pop()
            .unwrap_or_else(|| {
                Err(IdentityError::Internal {
                    reason: "a one-record import returned no result".to_string(),
                })
            })
    }

    /// Stages each of `records` with `stage` and writes them through one
    /// pipeline. Returns one result per record, in order.
    ///
    /// `stage` gets the pipeline to settle it before anything that can wait
    /// for a commit, or to enqueue its record itself under a lock
    /// ([`Staged::Enqueued`]). The control changes of the records that are
    /// durable are applied together, with one epoch bump.
    fn import_staged<T>(
        &self,
        realm_id: &RealmId,
        records: &[T],
        mut stage: impl FnMut(&mut ImportPipeline<'_>, &T) -> Result<Staged, IdentityError>,
    ) -> Vec<Result<ImportOutcome, IdentityError>> {
        let mut pipeline = WritePipeline::new(&*self.storage, realm_id, Self::storage_err);
        let mut controls = Vec::new();
        for (i, record) in records.iter().enumerate() {
            match stage(&mut pipeline, record) {
                Ok(Staged::Skipped) => pipeline.push_result(Ok(ImportOutcome::Skipped)),
                Ok(Staged::Rows {
                    rows,
                    outcome,
                    control,
                }) => {
                    pipeline.push_rows(&rows, outcome);
                    if let Some(op) = control {
                        controls.push((i, op));
                    }
                }
                Ok(Staged::IfAbsent { key, value }) => pipeline.push_if_absent(
                    &key,
                    &value,
                    ImportOutcome::Created,
                    ImportOutcome::Skipped,
                ),
                Ok(Staged::Enqueued) => {}
                Err(e) => pipeline.push_result(Err(e)),
            }
            if pipeline.is_full() {
                pipeline.settle();
            }
        }
        let results = pipeline.finish();
        let ops: Vec<ControlOp> = controls
            .into_iter()
            .filter(|(i, _)| results.get(*i).is_some_and(Result::is_ok))
            .map(|(_, op)| op)
            .collect();
        self.publish_controls(ops);
        results
    }

    /// [`Self::publish_control`] for many controls, with ONE bump of the
    /// persisted control epoch: a bump is a durable write, and one per
    /// revocation made a restore one fsync per revoked token again.
    fn publish_controls(&self, ops: Vec<ControlOp>) {
        if ops.is_empty() {
            return;
        }
        let _in_flight = self.control.begin_local_bump();
        let epoch = self.persist_control_epoch_bump();
        for op in ops {
            self.control.apply(Some(op), None);
        }
        self.control.apply(None, epoch);
        if epoch.is_none() {
            // Other nodes learn of the controls only through the epoch: the
            // reloader retries the bump until it succeeds.
            self.control.owe_bump();
        }
    }

    /// Whether this engine holds the MFA DEK of `realm_id` in memory, so
    /// that [`Self::get_or_create_realm_mfa_dek`] writes nothing.
    fn mfa_dek_is_cached(&self, realm_id: &RealmId) -> bool {
        self.mfa_dek_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(realm_id)
    }

    /// Whether `key` is stored in `realm_id`.
    fn row_exists(&self, realm_id: &RealmId, key: &[u8]) -> Result<bool, IdentityError> {
        Ok(self
            .storage
            .get(realm_id, key)
            .map_err(Self::storage_err)?
            .is_some())
    }

    /// Refuses `operation` in the system realm: the live API never creates
    /// these records there, so a restore must not either.
    fn refuse_system_realm(
        realm_id: &RealmId,
        operation: &'static str,
    ) -> Result<(), IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected { operation });
        }
        Ok(())
    }

    /// Mirrors `create_organization`'s persisted layout (primary record +
    /// raw-UUID slug index) but preserves the org's own ID and every field.
    fn stage_organization(
        &self,
        realm_id: &RealmId,
        org: &Organization,
        overwrite: bool,
    ) -> Result<Staged, IdentityError> {
        Self::refuse_system_realm(realm_id, "import_organization")?;
        let id_key = keys::encode_org_id(org.id());
        let exists = self.row_exists(realm_id, &id_key)?;
        if exists && !overwrite {
            return Ok(Staged::Skipped);
        }
        let org_bytes = serde_json::to_vec(org).map_err(|e| serialization(&e))?;
        let slug_key = keys::encode_org_slug(org.slug());
        Ok(Staged::rows(
            vec![
                (id_key, org_bytes),
                (slug_key, org.id().as_uuid().as_bytes().to_vec()),
            ],
            exists,
        ))
    }

    /// A TOTP state, re-encrypted under THIS realm's MFA DEK so the restore
    /// does not depend on the source deployment's keys, or a passkey with its
    /// discoverable index, as one write.
    fn stage_mfa_factor(
        &self,
        pipeline: &mut ImportPipeline<'_>,
        realm_id: &RealmId,
        factor: &MfaFactorExport,
        overwrite: bool,
    ) -> Result<Staged, IdentityError> {
        match factor {
            MfaFactorExport::Totp { user_id, state } => {
                let key = keys::encode_mfa_totp_key(user_id);
                let exists = self.row_exists(realm_id, &key)?;
                if exists && !overwrite {
                    return Ok(Staged::Skipped);
                }
                let state: StoredMfaState =
                    serde_json::from_value(state.clone()).map_err(|e| serialization(&e))?;
                if !self.mfa_dek_is_cached(realm_id) {
                    // The realm's first DEK is a durable write of its own.
                    pipeline.settle();
                }
                let dek = self.get_or_create_realm_mfa_dek(realm_id)?;
                let bytes = totp::serialize_mfa_state(&state, &dek)?;
                Ok(Staged::rows(vec![(key, bytes)], exists))
            }
            MfaFactorExport::Passkey {
                user_id,
                credential,
            } => {
                let stored: crate::identity::webauthn::StoredWebAuthnCredential =
                    serde_json::from_value(credential.clone()).map_err(|e| serialization(&e))?;
                // The credential ID becomes part of a storage key — refuse
                // anything that is not clean base64url (no separators).
                if URL_SAFE_NO_PAD
                    .decode(stored.credential_id_b64.as_bytes())
                    .is_err()
                {
                    return Err(IdentityError::InvalidInput {
                        reason: "passkey credential_id_b64 is not valid base64url".into(),
                    });
                }
                let key = keys::encode_webauthn_credential(user_id, &stored.credential_id_b64);
                let exists = self.row_exists(realm_id, &key)?;
                if exists && !overwrite {
                    return Ok(Staged::Skipped);
                }
                let bytes = serde_json::to_vec(&stored).map_err(|e| serialization(&e))?;
                let mut rows = vec![(key, bytes)];
                if stored.discoverable {
                    rows.push((
                        keys::encode_webauthn_discoverable(&stored.credential_id_b64),
                        user_id.as_uuid().to_string().into_bytes(),
                    ));
                }
                Ok(Staged::rows(rows, exists))
            }
        }
    }

    /// Both index entries (org->user and user->org), as `add_member` writes
    /// them.
    fn stage_organization_membership(
        &self,
        realm_id: &RealmId,
        membership: &OrganizationMembership,
        overwrite: bool,
    ) -> Result<Staged, IdentityError> {
        Self::refuse_system_realm(realm_id, "import_organization_membership")?;
        let fwd_key = keys::encode_membership_by_org(membership.org_id(), membership.user_id());
        let exists = self.row_exists(realm_id, &fwd_key)?;
        if exists && !overwrite {
            return Ok(Staged::Skipped);
        }
        let bytes = serde_json::to_vec(membership).map_err(|e| serialization(&e))?;
        let rev_key = keys::encode_membership_by_user(membership.user_id(), membership.org_id());
        Ok(Staged::rows(
            vec![(fwd_key, bytes.clone()), (rev_key, bytes)],
            exists,
        ))
    }

    /// The consent record at its original storage key, which must be inside
    /// the consent key space.
    fn stage_consent(
        &self,
        realm_id: &RealmId,
        consent: &ConsentExport,
        overwrite: bool,
    ) -> Result<Staged, IdentityError> {
        // A consent names a client, and the system realm refuses clients
        // (`register_client`, `import_client`).
        Self::refuse_system_realm(realm_id, "import_consent")?;
        if !keys::is_oauth_consent_key(&consent.storage_key) {
            return Err(IdentityError::Serialization {
                reason: "consent record carries a storage key outside the consent key space"
                    .to_string(),
            });
        }
        let key = consent.storage_key.as_bytes().to_vec();
        let exists = self.row_exists(realm_id, &key)?;
        if exists && !overwrite {
            return Ok(Staged::Skipped);
        }
        let bytes = serde_json::to_vec(&consent.record).map_err(|e| serialization(&e))?;
        Ok(Staged::rows(vec![(key, bytes)], exists))
    }

    /// The agent, its owner index and every credential, as one write: an
    /// agent whose credentials did not come back has lost the only way to
    /// exercise the authority it describes.
    fn stage_agent(
        &self,
        realm_id: &RealmId,
        export: &AgentExport,
        overwrite: bool,
    ) -> Result<Staged, IdentityError> {
        Self::refuse_system_realm(realm_id, "import_agent")?;
        let agent = &export.agent;
        let id_key = keys::encode_agent_id(agent.id());
        let exists = self.row_exists(realm_id, &id_key)?;
        if exists && !overwrite {
            return Ok(Staged::Skipped);
        }
        let agent_bytes = serde_json::to_vec(agent).map_err(|e| serialization(&e))?;
        // The owner index is what `list_agents` scans. An agent restored
        // without it is invisible to every listing while still authenticating,
        // which is the worst of both outcomes.
        let owner_index_key = keys::encode_agent_owner_index(
            agent.owner().storage_tag(),
            &agent.owner().uuid_str(),
            agent.id(),
        );
        let mut rows = vec![(id_key, agent_bytes), (owner_index_key, Vec::new())];
        for cred in &export.credentials {
            let cred_key = keys::encode_agent_credential(agent.id(), cred.id());
            let cred_bytes = serde_json::to_vec(cred).map_err(|e| serialization(&e))?;
            rows.push((cred_key, cred_bytes));
        }
        Ok(Staged::rows(rows, exists))
    }

    /// Both entries of a federation link: the reverse one every federated
    /// login reads, and the forward one the account page and the delete
    /// cascade read. One without the other yields a link that either cannot
    /// log in or cannot be revoked.
    fn stage_federation_link(
        &self,
        realm_id: &RealmId,
        link: &FederationLinkExport,
        overwrite: bool,
    ) -> Result<Staged, IdentityError> {
        Self::refuse_system_realm(realm_id, "import_federation_link")?;
        let reverse_key = keys::encode_federation_ext_key(&link.idp_id, &link.external_sub);
        let forward_key = keys::encode_federation_ext_fwd_key(&link.user_id, &link.idp_id);
        let exists = self.row_exists(realm_id, &reverse_key)?;
        if exists && !overwrite {
            return Ok(Staged::Skipped);
        }
        Ok(Staged::rows(
            vec![
                (reverse_key, link.user_id.as_uuid().as_bytes().to_vec()),
                (forward_key, link.external_sub.as_bytes().to_vec()),
            ],
            exists,
        ))
    }

    /// Both entries of a SCIM `externalId` mapping.
    fn stage_scim_mapping(
        &self,
        realm_id: &RealmId,
        mapping: &ScimMappingExport,
        overwrite: bool,
    ) -> Result<Staged, IdentityError> {
        // SCIM provisions users and organizations, and the system realm
        // refuses both (`create_user`, `create_organization`).
        Self::refuse_system_realm(realm_id, "import_scim_mapping")?;
        let (reverse_key, forward_key) = match mapping.kind {
            ScimMappingKind::User => (
                keys::encode_scim_ext_user_key(&mapping.external_id),
                keys::encode_scim_ext_user_fwd_key(&UserId::new(mapping.subject_id)),
            ),
            ScimMappingKind::Group => (
                keys::encode_scim_ext_group_key(&mapping.external_id),
                keys::encode_scim_ext_group_fwd_key(&OrganizationId::new(mapping.subject_id)),
            ),
        };
        let exists = self.row_exists(realm_id, &reverse_key)?;
        if exists && !overwrite {
            return Ok(Staged::Skipped);
        }
        Ok(Staged::rows(
            vec![
                (reverse_key, mapping.subject_id.as_bytes().to_vec()),
                (forward_key, mapping.external_id.as_bytes().to_vec()),
            ],
            exists,
        ))
    }

    /// All four entries `create_invitation` writes. The token index is the
    /// one an outstanding invitation LINK resolves through: without it the
    /// record restores and the link 404s.
    fn stage_invitation(
        &self,
        realm_id: &RealmId,
        invitation: &OrganizationInvitation,
        overwrite: bool,
    ) -> Result<Staged, IdentityError> {
        Self::refuse_system_realm(realm_id, "import_invitation")?;
        let id_key = keys::encode_invitation_id(invitation.id());
        let exists = self.row_exists(realm_id, &id_key)?;
        if exists && !overwrite {
            return Ok(Staged::Skipped);
        }
        let bytes = serde_json::to_vec(invitation).map_err(|e| serialization(&e))?;
        let id_bytes = invitation.id().as_uuid().as_bytes().to_vec();
        let token_key = keys::encode_invitation_token(invitation.token_hash());
        let dedup_key = keys::encode_invitation_org_email(invitation.org_id(), invitation.email());
        let list_key = keys::encode_invitation_list(invitation.org_id(), invitation.id());
        Ok(Staged::rows(
            vec![
                (id_key, bytes),
                (token_key, id_bytes.clone()),
                (dedup_key, id_bytes),
                (list_key, Vec::new()),
            ],
            exists,
        ))
    }

    /// A revocation row, written exactly as the live revocation path writes
    /// it, and applied to this node's control caches (and, through the
    /// control epoch, every other node's) once it is durable.
    fn stage_revocation(
        &self,
        pipeline: &mut ImportPipeline<'_>,
        realm_id: &RealmId,
        revocation: &RevocationExport,
        overwrite: bool,
    ) -> Result<Staged, IdentityError> {
        /// A JTI or thumbprint longer than this is not one Hearth wrote.
        const MAX_ID_LEN: usize = 512;
        let (key, id) = match revocation {
            RevocationExport::Jti { jti, .. } => (keys::encode_revoked_jti(jti), jti),
            RevocationExport::DpopJkt { jkt } => (keys::encode_blocked_dpop_jkt(jkt), jkt),
            RevocationExport::AatJti { jti } => (keys::encode_aat_revoked_jti(jti), jti),
            RevocationExport::RaGeneration {
                user_id,
                generation,
            } => return self.stage_ra_generation(pipeline, realm_id, user_id, *generation),
            RevocationExport::RaConsumed {
                marker,
                hash,
                expires_at,
            } => return self.stage_ra_consumed(marker, hash, *expires_at),
        };
        if id.is_empty() || id.len() > MAX_ID_LEN {
            return Err(IdentityError::InvalidInput {
                reason: "revocation identifier is empty or too long".to_string(),
            });
        }
        if let RevocationExport::Jti { exp: Some(exp), .. } = revocation {
            if self.clock.now().as_micros() / 1_000_000 >= *exp {
                // The token it names has expired; the row would be swept.
                return Ok(Staged::Skipped);
            }
        }
        let exists = self.row_exists(realm_id, &key)?;
        if exists && !overwrite {
            return Ok(Staged::Skipped);
        }
        let (value, control) = match revocation {
            RevocationExport::Jti { jti, exp } => (
                exp.map_or_else(|| b"1".to_vec(), |e| e.to_le_bytes().to_vec()),
                Some(ControlOp::RevokeJti {
                    key: control::revoked_jti_cache_key(realm_id, jti),
                    exp: exp.unwrap_or(i64::MAX),
                }),
            ),
            RevocationExport::DpopJkt { jkt } => {
                (Vec::new(), Some(ControlOp::BlockJkt(jkt.clone())))
            }
            // AAT revocations are read from storage at validation time.
            RevocationExport::AatJti { .. } => (b"1".to_vec(), None),
            // Staged above.
            RevocationExport::RaGeneration { .. } | RevocationExport::RaConsumed { .. } => {
                return Err(IdentityError::Internal {
                    reason: "required-action revocation staged twice".to_string(),
                })
            }
        };
        Ok(Staged::Rows {
            rows: vec![(key, value)],
            outcome: if exists {
                ImportOutcome::Overwritten
            } else {
                ImportOutcome::Created
            },
            control,
        })
    }

    /// A spent required-action marker (GA sweep 4 round 2), so a flow — or a
    /// token's forced password update — that ended before the backup cannot
    /// end again on the restored store.
    ///
    /// Only the two required-action kinds are accepted and the hash must be
    /// a SHA-256 hex digest, so an archive cannot use this member to write
    /// any other key. An expired marker, or one already present, is skipped;
    /// a present marker is the fact itself, so there is nothing to overwrite.
    fn stage_ra_consumed(
        &self,
        kind: &str,
        hash: &str,
        expires_at: i64,
    ) -> Result<Staged, IdentityError> {
        let hex_digest = hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !keys::RA_CONSUMED_KINDS.contains(&kind) || !hex_digest {
            return Err(IdentityError::InvalidInput {
                reason: "required-action marker is not one Hearth wrote".to_string(),
            });
        }
        if self.clock.now().as_micros() / 1_000_000 >= expires_at {
            return Ok(Staged::Skipped);
        }
        Ok(Staged::IfAbsent {
            key: keys::encode_consumed_ra(kind, hash),
            value: expires_at.to_le_bytes().to_vec(),
        })
    }

    /// A user's required-action generation (GA sweep 4).
    ///
    /// The generation is a revocation counter, so the restore only ever
    /// raises it: a node that has revoked the user's sessions since (a
    /// second restore of the same archive) keeps its higher counter, in
    /// either restore mode — lowering it would revive the RA tokens those
    /// revocations ended. Serialised with [`Self::bump_ra_generation`]: the
    /// record is enqueued under the user's lock, which a bump takes for its
    /// read and its write.
    fn stage_ra_generation(
        &self,
        pipeline: &mut ImportPipeline<'_>,
        realm_id: &RealmId,
        user_id: &str,
        generation: u64,
    ) -> Result<Staged, IdentityError> {
        let user_id = uuid::Uuid::parse_str(user_id)
            .map(UserId::new)
            .map_err(|_| IdentityError::InvalidInput {
                reason: "required-action generation names no user id".to_string(),
            })?;
        let lock = self.token_redemption_lock(&format!(
            "ra-gen:{}:{}",
            realm_id.as_uuid(),
            user_id.as_uuid()
        ));
        let _guard = match lock.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                // The holder's write may wait for a commit that this thread
                // leads: settle before waiting for the lock.
                pipeline.settle();
                lock.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            }
        };
        let key = keys::encode_ra_generation(&user_id);
        let exists = self.row_exists(realm_id, &key)?;
        // Read through the same decoding the RA-token check uses.
        if self.ra_generation(realm_id, &user_id)? >= generation {
            return Ok(Staged::Skipped);
        }
        pipeline.push_rows(
            &[(key, generation.to_le_bytes().to_vec())],
            if exists {
                ImportOutcome::Overwritten
            } else {
                ImportOutcome::Created
            },
        );
        Ok(Staged::Enqueued)
    }
}
