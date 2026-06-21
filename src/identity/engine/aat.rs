//! Phase D.1 — Attenuating Authorization Token (AAT) engine methods.
//!
//! Implements `issue_aat`, `derive_aat`, `validate_aat`, and `revoke_aat`.
//!
//! Security invariants:
//! - Hearth is the sole signer of all AATs (realm Ed25519 key).
//! - Derivation enforces strict scope narrowing: child ⊆ parent.
//! - Revocation is by JTI: any ancestor revocation invalidates descendants.
//! - Chain depth is capped at 5 to limit validation cost.

use crate::audit::AuditAction;
use crate::core::RealmId;
use crate::identity::tokens::verify_jwt_typed;
use crate::identity::types::{
    AatClaims, AatResponse, AatToolPermission, DeriveAatRequest, IssueAatRequest,
};
use crate::identity::{keys, IdentityEngine, IdentityError};

use super::EmbeddedIdentityEngine;

/// Maximum AAT lifetime: 1 hour.
const MAX_AAT_TTL_SECS: i64 = 3_600;
/// Maximum attenuation chain depth (not counting root).
const MAX_AAT_CHAIN_DEPTH: usize = 5;
/// JWT `typ` for AATs.
const AAT_TYP: &str = "aat+jwt";

impl EmbeddedIdentityEngine {
    /// Issues a root AAT for an agent.
    pub(super) fn issue_aat_inner(
        &self,
        realm_id: &RealmId,
        request: &IssueAatRequest,
    ) -> Result<AatResponse, IdentityError> {
        // Verify agent exists and is Active.
        let agent = IdentityEngine::get_agent(self, realm_id, &request.agent_id)?
            .ok_or(IdentityError::AgentNotFound)?;
        if agent.status() != crate::identity::AgentStatus::Active {
            return Err(IdentityError::AgentRevoked);
        }

        // Reject non-null, non-object constraint types at issuance.
        for tool_perm in &request.tools {
            validate_constraint_type(&tool_perm.constraints)?;
        }

        let now = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;
        let ttl = request
            .expires_in_secs
            .unwrap_or(MAX_AAT_TTL_SECS)
            .clamp(1, MAX_AAT_TTL_SECS);
        let exp = now_secs + ttl;

        let jti = uuid::Uuid::new_v4().to_string();
        let issuer = IdentityEngine::realm_oidc_discovery(self, realm_id)
            .map(|d| d.issuer)
            .unwrap_or_else(|_| format!("hearth:{}", realm_id.as_uuid()));

        let sub = format!("agt_{}", request.agent_id.as_uuid());

        let claims = AatClaims {
            jti: jti.clone(),
            iss: issuer,
            sub,
            aud: request.aud.clone(),
            exp,
            iat: now_secs,
            tools: request.tools.clone(),
            scope: request.scope.clone(),
            aat_parent: None,
            aat_chain: vec![jti.clone()],
        };

        let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
        let aat = signing_key.sign_jwt(&claims, AAT_TYP)?;

        let _ = self.record_audit(realm_id, None, AuditAction::AatIssued, "aat", &jti);

        Ok(AatResponse {
            aat,
            expires_in_secs: ttl,
        })
    }

    /// Derives a child AAT by narrowing the parent's permissions.
    pub(super) fn derive_aat_inner(
        &self,
        realm_id: &RealmId,
        request: &DeriveAatRequest,
    ) -> Result<AatResponse, IdentityError> {
        // Parse and validate the parent AAT.
        let parent = self.parse_and_validate_aat(realm_id, &request.parent_aat)?;

        // Enforce chain depth cap.
        if parent.aat_chain.len() >= MAX_AAT_CHAIN_DEPTH {
            return Err(IdentityError::AatChainBroken {
                reason: format!(
                    "chain depth {} would exceed maximum {}",
                    parent.aat_chain.len(),
                    MAX_AAT_CHAIN_DEPTH
                ),
            });
        }

        // Validate scope narrowing: child scopes ⊆ parent scopes.
        for scope in &request.scope {
            if !parent.scope.contains(scope) {
                return Err(IdentityError::AatScopeEscalation);
            }
        }

        // Validate tool narrowing.
        validate_tools_subset(&request.tools, &parent.tools)?;

        let now = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;

        // Child exp must not exceed parent exp.
        let parent_remaining = parent.exp.saturating_sub(now_secs).max(0);
        let ttl = request
            .expires_in_secs
            .unwrap_or(parent_remaining)
            .clamp(1, parent_remaining);
        let exp = now_secs + ttl;

        let jti = uuid::Uuid::new_v4().to_string();
        let mut chain = parent.aat_chain.clone();
        chain.push(jti.clone());

        let claims = AatClaims {
            jti: jti.clone(),
            iss: parent.iss.clone(),
            sub: parent.sub.clone(),
            aud: request.aud.clone().or(parent.aud.clone()),
            exp,
            iat: now_secs,
            tools: request.tools.clone(),
            scope: request.scope.clone(),
            aat_parent: Some(parent.jti.clone()),
            aat_chain: chain,
        };

        let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
        let aat = signing_key.sign_jwt(&claims, AAT_TYP)?;

        let _ = self.record_audit(realm_id, None, AuditAction::AatIssued, "aat", &jti);

        Ok(AatResponse {
            aat,
            expires_in_secs: ttl,
        })
    }

    /// Parses and validates an AAT JWT, checking signature, expiry, and revocation.
    pub(super) fn parse_and_validate_aat(
        &self,
        realm_id: &RealmId,
        aat: &str,
    ) -> Result<AatClaims, IdentityError> {
        let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
        let public_key_bytes = signing_key.public_key_bytes().to_vec();

        let claims: AatClaims = verify_jwt_typed(aat, &public_key_bytes, Some(AAT_TYP))?;

        // Check expiry.
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        if now_secs >= claims.exp {
            return Err(IdentityError::AatExpired);
        }

        // Check revocation of this JTI and all ancestors in the chain.
        for jti in &claims.aat_chain {
            let rev_key = keys::encode_aat_revoked_jti(jti);
            if let Ok(Some(_)) = self.storage.get(realm_id, &rev_key) {
                return Err(IdentityError::AatRevoked);
            }
        }

        Ok(claims)
    }

    /// Marks an AAT JTI as revoked.
    pub(super) fn revoke_aat_inner(
        &self,
        realm_id: &RealmId,
        jti: &str,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_aat_revoked_jti(jti);
        self.storage
            .put(realm_id, &key, b"1")
            .map_err(Self::storage_err)?;

        let _ = self.record_audit(realm_id, None, AuditAction::AatRevoked, "aat", jti);
        Ok(())
    }
}

/// Returns `AatScopeEscalation` if `v` is neither `null` nor a JSON object.
///
/// Only `null` (unconstrained) and `{...}` (structured key/value bounds) carry
/// defined narrowing semantics.  Accepting arbitrary JSON types would create a
/// type-confusion bypass path in `validate_tools_subset`.
fn validate_constraint_type(v: &serde_json::Value) -> Result<(), IdentityError> {
    if !v.is_null() && !v.is_object() {
        return Err(IdentityError::AatScopeEscalation);
    }
    Ok(())
}

/// Returns `AatScopeEscalation` if `child_tools` is not a subset of `parent_tools`.
fn validate_tools_subset(
    child_tools: &[AatToolPermission],
    parent_tools: &[AatToolPermission],
) -> Result<(), IdentityError> {
    for child_perm in child_tools {
        // Find the matching tool in the parent.
        let parent_perm = parent_tools
            .iter()
            .find(|p| p.tool == child_perm.tool)
            .ok_or(IdentityError::AatScopeEscalation)?;

        // Child actions must be a subset of parent actions.
        for action in &child_perm.actions {
            if !parent_perm.actions.contains(action) {
                return Err(IdentityError::AatScopeEscalation);
            }
        }

        // Reject non-null, non-object constraint types on both sides.  Strings,
        // arrays, booleans, and numbers have no defined narrowing semantics, so
        // accepting them would allow a type-confusion bypass (D.1-SECURITY).
        validate_constraint_type(&child_perm.constraints)?;
        validate_constraint_type(&parent_perm.constraints)?;

        // Child constraints must not introduce keys absent in the parent.
        // For numeric values, child value must be ≤ parent value.
        if let (serde_json::Value::Object(child_obj), serde_json::Value::Object(parent_obj)) =
            (&child_perm.constraints, &parent_perm.constraints)
        {
            for (k, child_val) in child_obj {
                let parent_val = parent_obj.get(k).ok_or(IdentityError::AatScopeEscalation)?;
                // If both are numbers, child must be ≤ parent.
                if let (Some(cv), Some(pv)) = (child_val.as_f64(), parent_val.as_f64()) {
                    if cv > pv {
                        return Err(IdentityError::AatScopeEscalation);
                    }
                }
            }
        } else if !child_perm.constraints.is_null() && parent_perm.constraints.is_null() {
            // Child has constraints but parent doesn't — escalation.
            return Err(IdentityError::AatScopeEscalation);
        }
    }
    Ok(())
}
