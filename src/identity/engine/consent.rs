//! Consent rows (`scope-consent-integrity` design §5).
//!
//! One row per user, client, organization context and RFC 8707 resource
//! ([`ConsentKey`]). A row holds the scopes as granted and their
//! [`ConsentDisclosure`]: the permissions the scopes stand for, the OIDC
//! scopes, and the `claim@target` pairs the claim profile releases to the
//! client. A row covers a request while the request's current disclosure is a
//! subset of the stored one, so a new mapper or a broadened bundle asks again
//! and a removed mapper or a narrowed bundle does not.
//!
//! Only a client with a consent step ([`OAuthClient::has_consent_step`]) has
//! rows. One lookup serves the browser gate, the non-interactive `/authorize`
//! and refresh: the exact row, then the realm-context row when the request is
//! in an organization and the client sets `consent_spans_orgs`. A row never
//! covers another resource.

use std::collections::{BTreeMap, BTreeSet};

use crate::audit::{Actor, AuditAction, AuditContext};
use crate::core::{ClientId, RealmId, UserId};
use crate::identity::claims_config::released_claim_targets;
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::oidc::{OAuthClient, StoredGrantFamily};
use crate::identity::types::{
    canonicalize_scopes, ConsentDisclosure, ConsentGrant, ConsentKey, ConsentListEntry,
    ConsentRecord, ConsentState,
};
use crate::identity::IdentityEngine as _;

use super::EmbeddedIdentityEngine;

impl EmbeddedIdentityEngine {
    /// Reads the row stored under `key`.
    pub(super) fn get_consent_inner(
        &self,
        realm_id: &RealmId,
        key: &ConsentKey,
    ) -> Result<Option<ConsentRecord>, IdentityError> {
        self.storage
            .get(realm_id, &keys::encode_consent_key(key))
            .map_err(Self::storage_err)?
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })
            })
            .transpose()
    }

    /// The one consent lookup: the row under `key`, else — in an
    /// organization, for a client that sets `consent_spans_orgs` — the
    /// realm-context row for the same resource.
    fn find_consent(
        &self,
        realm_id: &RealmId,
        client: &OAuthClient,
        key: &ConsentKey,
    ) -> Result<Option<ConsentRecord>, IdentityError> {
        if let Some(row) = self.get_consent_inner(realm_id, key)? {
            return Ok(Some(row));
        }
        if key.org_id.is_some() && client.consent_spans_orgs() {
            let realm_row = ConsentKey {
                org_id: None,
                ..key.clone()
            };
            return self.get_consent_inner(realm_id, &realm_row);
        }
        Ok(None)
    }

    /// What `scopes` disclose to `client` under `resource`, from the current
    /// registry and claim profile. Independent of the user.
    pub(super) fn consent_disclosure(
        &self,
        realm_id: &RealmId,
        client: &OAuthClient,
        scopes: &[String],
        resource: Option<&crate::core::Uri>,
    ) -> Result<ConsentDisclosure, IdentityError> {
        let permissions = self
            .rbac
            .scope_definitions(realm_id, scopes, resource)
            .map_err(|e| IdentityError::Internal {
                reason: format!("scope definitions: {e}"),
            })?;
        let oidc_scopes: BTreeSet<String> = scopes
            .iter()
            .filter(|s| crate::rbac::registry::is_oidc_standard_scope(s))
            .cloned()
            .collect();
        let granted: BTreeSet<String> = scopes.iter().cloned().collect();
        let overrides = self.claim_profile_overrides(realm_id);
        let claims: BTreeSet<String> = released_claim_targets(&overrides, client, &granted)
            .into_iter()
            .map(|(claim, target)| format!("{claim}@{}", target.as_str()))
            .collect();
        Ok(ConsentDisclosure {
            permissions,
            oidc_scopes: oidc_scopes.into_iter().collect(),
            claims: claims.into_iter().collect(),
        })
    }

    /// The consent decision for granting `scopes` to `client` under `key`.
    pub(super) fn consent_state(
        &self,
        realm_id: &RealmId,
        client: &OAuthClient,
        key: &ConsentKey,
        scopes: &[String],
    ) -> Result<ConsentState, IdentityError> {
        if !client.has_consent_step() {
            return Ok(ConsentState::NotRequired);
        }
        let Some(row) = self.find_consent(realm_id, client, key)? else {
            return Ok(ConsentState::Missing);
        };
        let current = self.consent_disclosure(realm_id, client, scopes, key.resource.as_ref())?;
        Ok(if current.is_subset_of(&row.disclosure) {
            ConsentState::Held
        } else {
            ConsentState::Missing
        })
    }

    /// The consent check of a `refresh_token` grant (`scope-consent-integrity`
    /// design §5, "Refresh (third-party)"), run before re-resolution.
    ///
    /// A granted scope the registry no longer defines ends the consent: the
    /// row is deleted and the refresh fails with `consent_required`. The
    /// disclosure check runs after re-resolution, in
    /// [`Self::require_refresh_disclosure`].
    pub(super) fn require_refresh_scopes_defined(
        &self,
        realm_id: &RealmId,
        client: &OAuthClient,
        key: &ConsentKey,
        scopes: &[String],
    ) -> Result<(), IdentityError> {
        if !client.has_consent_step() {
            return Ok(());
        }
        let mut undefined = false;
        for scope in scopes {
            if crate::rbac::registry::is_oidc_standard_scope(scope) {
                continue;
            }
            let defined = self
                .rbac
                .scope_definitions(realm_id, std::slice::from_ref(scope), key.resource.as_ref())
                .map_err(|e| IdentityError::Internal {
                    reason: format!("scope definitions: {e}"),
                })?;
            if defined.is_empty() {
                undefined = true;
                break;
            }
        }
        if !undefined {
            return Ok(());
        }
        // Delete the row the grant was decided under: the exact row, else the
        // realm-context row that `consent_spans_orgs` let cover it.
        let row_key = if self.get_consent_inner(realm_id, key)?.is_some() {
            Some(key.clone())
        } else if key.org_id.is_some() && client.consent_spans_orgs() {
            Some(ConsentKey {
                org_id: None,
                ..key.clone()
            })
        } else {
            None
        };
        if let Some(row_key) = row_key {
            self.storage
                .delete(realm_id, &keys::encode_consent_key(&row_key))
                .map_err(Self::storage_err)?;
        }
        self.refuse_refresh_for_consent(realm_id, key)
    }

    /// The disclosure half of the refresh consent check: the stored row must
    /// still cover what the re-resolved `scopes` disclose.
    pub(super) fn require_refresh_disclosure(
        &self,
        realm_id: &RealmId,
        client: &OAuthClient,
        key: &ConsentKey,
        scopes: &[String],
    ) -> Result<(), IdentityError> {
        match self.consent_state(realm_id, client, key, scopes)? {
            ConsentState::NotRequired | ConsentState::Held => Ok(()),
            ConsentState::Missing => self.refuse_refresh_for_consent(realm_id, key),
        }
    }

    /// Writes `ConsentRequiredOnRefresh` and returns the refusal.
    fn refuse_refresh_for_consent(
        &self,
        realm_id: &RealmId,
        key: &ConsentKey,
    ) -> Result<(), IdentityError> {
        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::Client(key.client_id.clone()),
                metadata: Some(consent_row_metadata(key)),
            }),
            AuditAction::ConsentRequiredOnRefresh,
            "consent",
            &key.client_id.as_uuid().to_string(),
        )?;
        Err(IdentityError::RefreshConsentRequired)
    }

    pub(super) fn grant_consent_inner(
        &self,
        realm_id: &RealmId,
        grant: &ConsentGrant,
    ) -> Result<ConsentRecord, IdentityError> {
        let key = &grant.key;
        // The client must exist — avoids orphan consents.
        let client = self
            .get_client(realm_id, &key.client_id)?
            .ok_or(IdentityError::ClientNotFound)?;
        let disclosure =
            self.consent_disclosure(realm_id, &client, &grant.scopes, key.resource.as_ref())?;
        let now = self.clock.now();
        let record = match self.get_consent_inner(realm_id, key)? {
            Some(mut rec) => {
                let mut all = rec.granted_scopes.clone();
                all.extend(grant.scopes.iter().cloned());
                rec.granted_scopes = canonicalize_scopes(all);
                rec.disclosure.merge(&disclosure);
                rec.updated_at = now;
                rec.granted_by = key.user_id.clone();
                rec.granted_via = grant.via;
                rec
            }
            None => ConsentRecord {
                user_id: key.user_id.clone(),
                client_id: key.client_id.clone(),
                context_oid: key.org_id.clone(),
                resource: key.resource.as_ref().map(|r| r.as_str().to_string()),
                granted_scopes: canonicalize_scopes(grant.scopes.clone()),
                disclosure,
                granted_at: now,
                updated_at: now,
                granted_by: key.user_id.clone(),
                granted_via: grant.via,
            },
        };
        let bytes = serde_json::to_vec(&record).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &keys::encode_consent_key(key), &bytes)
            .map_err(Self::storage_err)?;
        let mut metadata = consent_row_metadata(key);
        metadata["granted_via"] = serde_json::json!(grant.via);
        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(key.user_id.clone()),
                metadata: Some(metadata),
            }),
            AuditAction::ConsentGranted,
            "consent",
            &key.client_id.as_uuid().to_string(),
        )?;
        Ok(record)
    }

    /// Lists the user's consents, one entry per client. A client with rows in
    /// several organizations or for several resources is one entry: its
    /// `record` is the most recently updated row, carrying the union of the
    /// rows' scopes and the earliest `granted_at`.
    pub(super) fn list_consents_by_user_inner(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<ConsentListEntry>, IdentityError> {
        let prefix = keys::encode_consent_prefix_for_user(user_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let mut by_client: BTreeMap<ClientId, ConsentRecord> = BTreeMap::new();
        for entry in &entries {
            let rec: ConsentRecord =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            match by_client.remove(&rec.client_id) {
                None => {
                    by_client.insert(rec.client_id.clone(), rec);
                }
                Some(seen) => {
                    let (mut newer, older) = if rec.updated_at >= seen.updated_at {
                        (rec, seen)
                    } else {
                        (seen, rec)
                    };
                    let mut all = newer.granted_scopes.clone();
                    all.extend(older.granted_scopes);
                    newer.granted_scopes = canonicalize_scopes(all);
                    newer.granted_at = newer.granted_at.min(older.granted_at);
                    by_client.insert(newer.client_id.clone(), newer);
                }
            }
        }
        let mut out = Vec::with_capacity(by_client.len());
        for rec in by_client.into_values() {
            // Join with the current client. Orphaned consents (client
            // deleted) are filtered out — callers see only actionable entries.
            let Some(client) = self.get_client(realm_id, &rec.client_id)? else {
                continue;
            };
            out.push(ConsentListEntry {
                client_name: client.client_name().to_string(),
                client_logo_url: client.client_logo_url().map(str::to_string),
                record: rec,
            });
        }
        Ok(out)
    }

    /// Revokes every outstanding refresh-token grant family this user holds for
    /// `client_id`.
    ///
    /// Consent is the authority the grant was issued under. Deleting the
    /// consent record alone left the families live, and
    /// `rotate_grant_family`'s consent check then compared scope digests only
    /// *when a record existed* — so deleting the record removed the only thing
    /// that check could fail on and the application refreshed forever
    /// (audit 2026-08-28 §4.16#11).
    ///
    /// Returns the number of families revoked. Errors reading an individual row
    /// are fatal: a consent revocation that silently skipped a family would
    /// reintroduce the defect.
    fn revoke_grant_families_for_consent(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: Option<&ClientId>,
    ) -> Result<usize, IdentityError> {
        let prefix = keys::grant_family_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let mut revoked = 0usize;
        for entry in &entries {
            let listed: StoredGrantFamily =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            let Some(ref family_client) = listed.client_id else {
                // A clientless (session) grant carries no consent to revoke.
                continue;
            };
            if client_id.is_some_and(|wanted| family_client != wanted) {
                continue;
            }
            // The family records the session, not the subject; resolve the
            // owner so one user's revocation cannot revoke another's grant.
            // `load_session_raw` so an already-revoked session still resolves.
            let owner = self.load_session_raw(realm_id, &listed.session_id)?;
            if owner.as_ref().map(crate::identity::types::Session::user_id) != Some(user_id) {
                continue;
            }
            // Serialize with any in-flight rotation, then re-read under the
            // lock so this revocation is not a lost update (§4.16#2).
            let lock = self.grant_family_lock(realm_id, &listed.family_id);
            // INVARIANT: guard held only across the sync re-read + revoke-write; no .await in scope.
            let _guard = lock.lock().map_err(|_| IdentityError::Internal {
                reason: "grant family lock poisoned".to_string(),
            })?;
            let Some(bytes) = self
                .storage
                .get(realm_id, &entry.key)
                .map_err(Self::storage_err)?
            else {
                continue;
            };
            let mut family: StoredGrantFamily =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if self.grant_family_is_revoked(realm_id, &family)? {
                continue;
            }
            self.mark_grant_family_revoked(realm_id, &family)?;
            family.revoked = true;
            let updated =
                serde_json::to_vec(&family).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            self.storage
                .put(realm_id, &entry.key, &updated)
                .map_err(Self::storage_err)?;
            revoked += 1;
        }
        Ok(revoked)
    }

    /// Deletes every consent row under `prefix` and writes one
    /// `ClientConsentRevoked` per row, naming `actor`. Returns the rows
    /// deleted.
    fn delete_consent_rows(
        &self,
        realm_id: &RealmId,
        prefix: &[u8],
        actor: &Actor,
    ) -> Result<usize, IdentityError> {
        let end = keys::prefix_end(prefix);
        let entries = self
            .storage
            .scan(realm_id, prefix, &end)
            .map_err(Self::storage_err)?;
        for entry in &entries {
            let rec: ConsentRecord =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
            self.record_audit(
                realm_id,
                Some(&AuditContext {
                    actor: actor.clone(),
                    metadata: Some(serde_json::json!({
                        "client_id": rec.client_id.as_uuid().to_string(),
                        "target_user": rec.user_id.as_uuid().to_string(),
                        "context_oid": rec.context_oid.as_ref().map(|o| o.as_uuid().to_string()),
                        "resource_uri": rec.resource,
                    })),
                }),
                AuditAction::ClientConsentRevoked,
                "consent",
                &rec.client_id.as_uuid().to_string(),
            )?;
        }
        Ok(entries.len())
    }

    /// Revokes the application: every row under `(user, client)`, every
    /// organization and resource, and the grant families issued under them.
    pub(super) fn revoke_consent_inner(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
        actor: &Actor,
    ) -> Result<usize, IdentityError> {
        let prefix = keys::encode_consent_prefix_for_client(user_id, client_id);
        let deleted = self.delete_consent_rows(realm_id, &prefix, actor)?;
        if deleted == 0 {
            return Err(IdentityError::ConsentNotFound);
        }
        // The grant families issued under this consent are dead with it
        // (audit 2026-08-28 §4.16#11).
        self.revoke_grant_families_for_consent(realm_id, user_id, Some(client_id))?;
        Ok(deleted)
    }

    pub(super) fn revoke_all_consents_for_user_inner(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<usize, IdentityError> {
        let prefix = keys::encode_consent_prefix_for_user(user_id);
        let deleted = self.delete_consent_rows(realm_id, &prefix, &Actor::User(user_id.clone()))?;
        // Every grant family this user holds against any client was issued
        // under one of the consents just deleted (audit 2026-08-28 §4.16#11).
        self.revoke_grant_families_for_consent(realm_id, user_id, None)?;
        Ok(deleted)
    }
}

/// The audit metadata naming one consent row.
fn consent_row_metadata(key: &ConsentKey) -> serde_json::Value {
    serde_json::json!({
        "client_id": key.client_id.as_uuid().to_string(),
        "context_oid": key.org_id.as_ref().map(|o| o.as_uuid().to_string()),
        "resource_uri": key.resource.as_ref().map(crate::core::Uri::as_str),
    })
}
