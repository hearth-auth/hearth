//! Phase D.4 — Cross-realm trust policy engine methods.
//!
//! Implements CRUD for `CrossRealmTrustPolicy` records, which allow agents
//! from a source realm to present tokens to resources in the target realm,
//! restricted to a set of declared capabilities.
//!
//! Storage layout (all keys realm-prefixed):
//!   `xrealm:pol:{policy_id}` — JSON-serialized `CrossRealmTrustPolicy`
//!   `xrealm:from:{source_uuid}:{policy_id}` — empty; index for listing

use crate::audit::AuditAction;
use crate::core::RealmId;
use crate::identity::types::{CreateCrossRealmPolicyRequest, CrossRealmTrustPolicy};
use crate::identity::{keys, IdentityError};

use super::EmbeddedIdentityEngine;

impl EmbeddedIdentityEngine {
    /// Creates a cross-realm trust policy in `realm_id` (the trusting realm).
    pub(super) fn create_cross_realm_policy_inner(
        &self,
        realm_id: &RealmId,
        request: &CreateCrossRealmPolicyRequest,
    ) -> Result<CrossRealmTrustPolicy, IdentityError> {
        let now = self.clock.now();
        let expires_at = request.expires_in_secs.map(|secs| {
            let exp_micros = now.as_micros() + secs * 1_000_000;
            crate::core::Timestamp::from_micros(exp_micros)
        });

        let policy_id = uuid::Uuid::new_v4().to_string();

        let policy = CrossRealmTrustPolicy {
            policy_id: policy_id.clone(),
            target_realm_id: realm_id.clone(),
            source_realm_id: request.source_realm_id.clone(),
            allowed_capabilities: request.allowed_capabilities.clone(),
            expires_at,
            created_at: now,
        };

        let primary_key = keys::encode_cross_realm_policy(&policy_id);
        let from_index_key =
            keys::encode_cross_realm_from_index(&request.source_realm_id, &policy_id);
        let bytes = serde_json::to_vec(&policy).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;

        self.storage
            .put_batch(
                realm_id,
                &[(primary_key, bytes), (from_index_key, b"1".to_vec())],
            )
            .map_err(Self::storage_err)?;

        let _ = self.record_audit(
            realm_id,
            None,
            AuditAction::CrossRealmTrustCreated,
            "cross_realm_policy",
            &policy_id,
        );

        Ok(policy)
    }

    /// Retrieves a cross-realm trust policy by ID.
    pub(super) fn get_cross_realm_policy_inner(
        &self,
        realm_id: &RealmId,
        policy_id: &str,
    ) -> Result<Option<CrossRealmTrustPolicy>, IdentityError> {
        let key = keys::encode_cross_realm_policy(policy_id);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        {
            None => Ok(None),
            Some(bytes) => {
                let policy: CrossRealmTrustPolicy =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(policy))
            }
        }
    }

    /// Lists all cross-realm trust policies in the given realm.
    pub(super) fn list_cross_realm_policies_inner(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<CrossRealmTrustPolicy>, IdentityError> {
        let prefix = keys::cross_realm_policy_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;

        entries
            .into_iter()
            .map(|entry| {
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })
            })
            .collect()
    }

    /// Deletes a cross-realm trust policy and its index entry.
    pub(super) fn delete_cross_realm_policy_inner(
        &self,
        realm_id: &RealmId,
        policy_id: &str,
    ) -> Result<(), IdentityError> {
        let policy = self
            .get_cross_realm_policy_inner(realm_id, policy_id)?
            .ok_or(IdentityError::CrossRealmPolicyNotFound)?;

        let primary_key = keys::encode_cross_realm_policy(policy_id);
        let from_index_key =
            keys::encode_cross_realm_from_index(&policy.source_realm_id, policy_id);

        self.storage
            .delete(realm_id, &primary_key)
            .map_err(Self::storage_err)?;
        // Best-effort index cleanup (ignore error if already absent).
        let _ = self.storage.delete(realm_id, &from_index_key);

        let _ = self.record_audit(
            realm_id,
            None,
            AuditAction::CrossRealmTrustRevoked,
            "cross_realm_policy",
            policy_id,
        );

        Ok(())
    }

    /// Checks whether `capability` is allowed by the cross-realm trust policies
    /// between `source_realm` (origin) and `target_realm` (this realm).
    ///
    /// Returns `Ok(true)` when at least one active, non-expired policy permits it.
    pub(super) fn check_cross_realm_policy_inner(
        &self,
        target_realm: &RealmId,
        source_realm: &RealmId,
        capability: &str,
    ) -> Result<bool, IdentityError> {
        let prefix = keys::cross_realm_from_scan_prefix(source_realm);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(target_realm, &prefix, &end)
            .map_err(Self::storage_err)?;

        let now = self.clock.now();

        for entry in entries {
            // The key is `xrealm:from:{source_uuid}:{policy_id}` — extract policy_id.
            let key_str = std::str::from_utf8(&entry.key).unwrap_or("");
            let policy_id = key_str.rsplit(':').next().unwrap_or(key_str);

            if let Ok(Some(policy)) = self.get_cross_realm_policy_inner(target_realm, policy_id) {
                // Check expiry.
                if let Some(exp) = policy.expires_at {
                    if now >= exp {
                        continue;
                    }
                }
                if policy
                    .allowed_capabilities
                    .iter()
                    .any(|c| c == capability || c == "*")
                {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

// ── Task 25.15 — legacy system-sourced policies, reported at start-up ────────

/// A stored cross-realm trust policy that names the **system realm** as its
/// source while living in a realm that is not the system realm.
///
/// Task 25.11 refuses to *author* one of these unless a system-realm actor
/// writes it, because a tenant admin who could would be declaring what the
/// platform operator is allowed to do inside their own realm. That guard is
/// write-side only: a policy written before 25.11 shipped is still stored, is
/// still consulted by `check_cross_realm_policy`, and still silently narrows —
/// or removes — the operator's reach into that realm. Nothing announced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemSourcedPolicy {
    /// The realm that stores the policy (the trusting realm).
    pub target_realm_id: RealmId,
    /// That realm's name, for an operator-legible log line.
    pub target_realm_name: String,
    /// The policy's own identifier, so the operator can delete it by id.
    pub policy_id: String,
    /// The capabilities the policy grants the system realm. An operator
    /// locked out of a realm is usually looking at a short list here.
    pub allowed_capabilities: Vec<String>,
}

/// Finds every stored cross-realm policy whose source is the system realm in a
/// realm that is not the system realm.
///
/// Walks every realm, so it runs once at start-up and never on a request path.
/// Read-only and non-fatal by design: a legacy policy may well be deliberate,
/// and refusing to boot over one would strand an operator who cannot reach the
/// server to remove it. The recovery valve is task 25.14's
/// `DELETE /admin/realms/{id}/cross-realm-policies/{policy_id}`.
///
/// A realm whose policies cannot be listed is skipped rather than reported: a
/// storage error is not evidence of a policy, and inventing one would send the
/// operator hunting for a record that does not exist.
pub fn find_system_sourced_cross_realm_policies(
    identity: &dyn crate::identity::IdentityEngine,
) -> Vec<SystemSourcedPolicy> {
    const PAGE: u32 = 200;

    let mut found = Vec::new();
    let mut offset = 0u64;
    loop {
        let Ok(page) = identity.list_realms(&crate::core::PageRequest::new(offset, PAGE)) else {
            break;
        };
        let batch = u32::try_from(page.items.len()).unwrap_or(0);
        for realm in &page.items {
            if realm.id().as_uuid().is_nil() {
                // The system realm trusting itself is not the shape in question.
                continue;
            }
            let Ok(policies) = identity.list_cross_realm_policies(realm.id()) else {
                continue;
            };
            for policy in policies {
                if policy.source_realm_id.as_uuid().is_nil() {
                    found.push(SystemSourcedPolicy {
                        target_realm_id: realm.id().clone(),
                        target_realm_name: realm.name().to_string(),
                        policy_id: policy.policy_id.clone(),
                        allowed_capabilities: policy.allowed_capabilities.clone(),
                    });
                }
            }
        }
        if batch < PAGE {
            break;
        }
        offset = offset.saturating_add(u64::from(batch));
    }
    found
}
