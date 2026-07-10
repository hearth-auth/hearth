//! Approval request lifecycle engine methods (AGENT_AUTH.md §9 / Phase C.4–C.5).
//!
//! Implements: create, get, approve (→ capability token), deny, list,
//! and durable webhook notification (C.5).
//!
//! Status transitions are CAS-enforced: only Pending→Approved/Denied is legal.

use crate::audit::AuditAction;
use crate::core::AgentId;
use crate::identity::approval_notifier;
use crate::identity::types::{
    ApprovalRequest, ApprovalRequestResponse, ApprovalRequestStatus, ApprovalWebhookPayload,
    CapabilityTokenInfo, CreateApprovalRequestInput, Page,
};
use crate::identity::IdentityEngine as _;
use crate::identity::{keys, IdentityError};

use super::EmbeddedIdentityEngine;
use crate::core::RealmId;

/// Default capability token TTL: 5 minutes.
const DEFAULT_CAPABILITY_TTL_SECS: i64 = 300;
/// Maximum capability token TTL: 1 hour.
const MAX_CAPABILITY_TTL_SECS: i64 = 3600;
/// Default approval request expiry: 1 hour.
const DEFAULT_APPROVAL_EXPIRY_SECS: i64 = 3600;

impl EmbeddedIdentityEngine {
    /// Creates an approval request and writes it to storage atomically.
    pub(super) fn create_approval_request_inner(
        &self,
        realm_id: &RealmId,
        request: &CreateApprovalRequestInput,
    ) -> Result<ApprovalRequest, IdentityError> {
        let now = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;
        let expires_in = request
            .expires_in_secs
            .unwrap_or(DEFAULT_APPROVAL_EXPIRY_SECS);
        let expires_in = expires_in.clamp(1, DEFAULT_APPROVAL_EXPIRY_SECS);
        let exp_secs = now_secs + expires_in;

        let request_id = uuid::Uuid::new_v4().to_string();

        let record = ApprovalRequest {
            request_id: request_id.clone(),
            agent_id: request.agent_id.clone(),
            tool: request.tool.clone(),
            action: request.action.clone(),
            context: request.context.clone(),
            delegation_chain: request.delegation_chain.clone(),
            status: ApprovalRequestStatus::Pending,
            requested_at: now,
            expires_at: crate::core::Timestamp::from_micros(exp_secs * 1_000_000),
            resolved_at: None,
            denial_reason: None,
        };

        let primary_key = keys::encode_approval_request_id(&request_id);
        let list_key = keys::encode_approval_request_list(&request_id);
        let pending_key = keys::encode_approval_request_pending(&request_id);
        let outbox_key = keys::encode_approval_webhook_outbox(&request_id);
        let bytes = serde_json::to_vec(&record).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;

        // Build outbox payload now so it is written atomically with the record.
        // The outbox is a WAL-durable marker; if delivery succeeds immediately
        // the key is deleted, otherwise it survives for the recovery scanner.
        let outbox_bytes = serde_json::to_vec(&serde_json::json!({"request_id": request_id}))
            .unwrap_or_else(|_| b"1".to_vec());

        // Atomic batch write: primary + listing index + pending index + outbox
        self.storage
            .put_batch(
                realm_id,
                &[
                    (primary_key, bytes),
                    (list_key, b"1".to_vec()),
                    (pending_key, b"1".to_vec()),
                    (outbox_key, outbox_bytes),
                ],
            )
            .map_err(Self::storage_err)?;

        // Audit: ApprovalRequested
        let _ = self.record_audit(
            realm_id,
            None,
            AuditAction::ApprovalRequested,
            "approval_request",
            &request_id,
        );

        Ok(record)
    }

    /// Retrieves an approval request by ID.
    pub(super) fn get_approval_request_inner(
        &self,
        realm_id: &RealmId,
        request_id: &str,
    ) -> Result<ApprovalRequest, IdentityError> {
        let key = keys::encode_approval_request_id(request_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ApprovalRequestNotFound)?;
        serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Approves a pending approval request and mints a capability token.
    pub(super) fn approve_approval_request_inner(
        &self,
        realm_id: &RealmId,
        request_id: &str,
        capability_ttl_secs: Option<i64>,
    ) -> Result<ApprovalRequestResponse, IdentityError> {
        // Serialize concurrent transitions for this request. Without this lock,
        // two racing `approve` calls can both read `Pending`, both pass the
        // status check, both mint tokens with distinct JTIs, and both write
        // `Approved` — issuing two valid capability tokens for one approval.
        let lock = self.approval_request_lock(request_id);
        let _guard = lock
            .lock()
            .expect("approval_locks per-request mutex poisoned");

        let key = keys::encode_approval_request_id(request_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ApprovalRequestNotFound)?;
        let mut record: ApprovalRequest =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // CAS: only Pending → Approved is legal.
        if record.status != ApprovalRequestStatus::Pending {
            return Err(IdentityError::ApprovalRequestNotPending {
                current_status: format!("{:?}", record.status).to_lowercase(),
            });
        }

        // Check expiry.
        let now = self.clock.now();
        if record.expires_at <= now {
            return Err(IdentityError::ApprovalRequestExpired);
        }

        let now_secs = now.as_micros() / 1_000_000;
        let ttl = capability_ttl_secs
            .unwrap_or(DEFAULT_CAPABILITY_TTL_SECS)
            .clamp(1, MAX_CAPABILITY_TTL_SECS);

        // Mint capability token (JWT scoped to tool+action).
        let cap_token = self.mint_capability_token(realm_id, &record, now_secs, ttl)?;

        // Transition status.
        record.status = ApprovalRequestStatus::Approved;
        record.resolved_at = Some(now);

        let updated_bytes =
            serde_json::to_vec(&record).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Remove from pending index; update primary record.
        let pending_key = keys::encode_approval_request_pending(request_id);
        self.storage
            .delete(realm_id, &pending_key)
            .map_err(Self::storage_err)?;
        self.storage
            .put(realm_id, &key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // Audit: ApprovalGranted
        let _ = self.record_audit(
            realm_id,
            None,
            AuditAction::ApprovalGranted,
            "approval_request",
            request_id,
        );

        Ok(ApprovalRequestResponse {
            request_id: request_id.to_string(),
            status: ApprovalRequestStatus::Approved,
            capability_token: Some(CapabilityTokenInfo {
                token: cap_token,
                expires_in_secs: ttl,
            }),
        })
    }

    /// Denies a pending approval request.
    pub(super) fn deny_approval_request_inner(
        &self,
        realm_id: &RealmId,
        request_id: &str,
        reason: Option<String>,
    ) -> Result<ApprovalRequestResponse, IdentityError> {
        // Same TOCTOU guard as approve: two concurrent deny calls must not
        // both pass the Pending check and write duplicate Denied records.
        let lock = self.approval_request_lock(request_id);
        let _guard = lock
            .lock()
            .expect("approval_locks per-request mutex poisoned");

        let key = keys::encode_approval_request_id(request_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ApprovalRequestNotFound)?;
        let mut record: ApprovalRequest =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        if record.status != ApprovalRequestStatus::Pending {
            return Err(IdentityError::ApprovalRequestNotPending {
                current_status: format!("{:?}", record.status).to_lowercase(),
            });
        }

        let now = self.clock.now();
        record.status = ApprovalRequestStatus::Denied;
        record.resolved_at = Some(now);
        record.denial_reason = reason;

        let updated_bytes =
            serde_json::to_vec(&record).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        let pending_key = keys::encode_approval_request_pending(request_id);
        self.storage
            .delete(realm_id, &pending_key)
            .map_err(Self::storage_err)?;
        self.storage
            .put(realm_id, &key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // Audit: ApprovalDenied
        let _ = self.record_audit(
            realm_id,
            None,
            AuditAction::ApprovalDenied,
            "approval_request",
            request_id,
        );

        Ok(ApprovalRequestResponse {
            request_id: request_id.to_string(),
            status: ApprovalRequestStatus::Denied,
            capability_token: None,
        })
    }

    /// Lists approval requests with optional status filter.
    pub(super) fn list_approval_requests_inner(
        &self,
        realm_id: &RealmId,
        status_filter: Option<ApprovalRequestStatus>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<ApprovalRequest>, IdentityError> {
        // For pending-only queries, use the efficient pending index.
        let use_pending_index = matches!(status_filter, Some(ApprovalRequestStatus::Pending));

        let prefix = if use_pending_index {
            keys::approval_request_pending_scan_prefix()
        } else {
            keys::approval_request_list_scan_prefix()
        };
        let end = keys::prefix_end(&prefix);

        let index_entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;

        // Extract request IDs from index keys.
        let mut request_ids: Vec<String> = index_entries
            .iter()
            .filter_map(|e| {
                let s = String::from_utf8_lossy(&e.key);
                s.rsplit(':').next().map(str::to_string)
            })
            .collect();

        // Cursor-based pagination (cursor is the last seen request_id).
        if let Some(c) = cursor {
            if let Some(pos) = request_ids.iter().position(|id| id == c) {
                request_ids = request_ids.into_iter().skip(pos + 1).collect();
            }
        }

        let has_more = request_ids.len() > limit;
        request_ids.truncate(limit);

        let mut items = Vec::with_capacity(request_ids.len());
        for rid in &request_ids {
            let pk = keys::encode_approval_request_id(rid);
            let Some(bytes) = self.storage.get(realm_id, &pk).map_err(Self::storage_err)? else {
                continue;
            };
            let record: ApprovalRequest =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;

            // Apply status filter for non-pending queries.
            if let Some(ref sf) = status_filter {
                if &record.status != sf {
                    continue;
                }
            }

            items.push(record);
        }

        let next_cursor = if has_more {
            items.last().map(|r| r.request_id.clone())
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    /// Mints a capability JWT scoped to the approved tool and action.
    ///
    /// The token carries:
    /// - `sub`: the requesting agent's `AgentId` as a string
    /// - `tool`: the approved tool name
    /// - `action`: the approved action
    /// - `approval_id`: the request_id for audit linkage
    /// - Standard `exp`, `iat`, `jti`
    fn mint_capability_token(
        &self,
        realm_id: &RealmId,
        request: &ApprovalRequest,
        now_secs: i64,
        ttl: i64,
    ) -> Result<String, IdentityError> {
        use crate::identity::tokens::TokenClaims;
        use std::collections::BTreeMap;

        let signing_key = self.get_signing_key_or_default(realm_id);
        let jti = uuid::Uuid::new_v4().to_string();
        let exp = now_secs + ttl;
        let sub = request.agent_id.as_uuid().to_string();

        let mut custom = BTreeMap::new();
        custom.insert(
            "approval_id".to_string(),
            serde_json::Value::String(request.request_id.clone()),
        );
        custom.insert(
            "tool".to_string(),
            serde_json::Value::String(request.tool.clone()),
        );
        custom.insert(
            "action".to_string(),
            serde_json::Value::String(request.action.clone()),
        );

        // Capability tokens use a distinct token_type so protocol layer can
        // distinguish them from regular access tokens.
        let claims = TokenClaims {
            sub,
            iss: self.config.token.issuer.clone(),
            aud: crate::identity::tokens::Audience::Single("hearth:capability".to_string()),
            exp,
            iat: now_secs,
            nbf: None,
            sid: String::new(),
            tid: realm_id.as_uuid().to_string(),
            oid: None,
            token_type: "capability".to_string(),
            jti: Some(jti),
            fid: None,
            scope: Some(format!("tool.{}.{}", request.tool, request.action)),
            nonce: None,
            azp: None,
            cnf: None,
            roles: Vec::new(),
            groups: Vec::new(),
            org_groups: Vec::new(),
            permissions: vec![
                format!("tool.{}.{}", request.tool, request.action),
                format!("approval.{}.approved", request.request_id),
            ],
            required_actions: Vec::new(),
            act: None,
            amr: Vec::new(),
            sv: None,
            custom,
        };

        signing_key
            .issue_token(&claims)
            .map_err(|e| IdentityError::SigningError {
                reason: e.to_string(),
            })
    }

    /// Fires the approval webhook notification for a newly created request (C.5).
    ///
    /// Reads the realm's `approval_webhook` config, builds the payload, and
    /// attempts immediate delivery. On success, removes the outbox record.
    /// On failure, logs and leaves the outbox record for the recovery scanner.
    pub(super) fn notify_approval_webhook_inner(
        &self,
        realm_id: &RealmId,
        request: &ApprovalRequest,
    ) {
        let cfg = match self
            .get_realm(realm_id)
            .ok()
            .flatten()
            .and_then(|r| r.config().approval_webhook.clone())
        {
            Some(c) => c,
            None => return, // no webhook configured for this realm
        };

        // Stable delivery ID — same across all retry attempts for this request.
        let delivery_id = format!("approval:{}", request.request_id);

        let payload = ApprovalWebhookPayload {
            delivery_id: delivery_id.clone(),
            request_id: request.request_id.clone(),
            agent_id: request.agent_id.as_uuid().to_string(),
            tool: request.tool.clone(),
            action: request.action.clone(),
            context: request.context.clone(),
            delegation_chain: request.delegation_chain.clone(),
            approve_url: format!(
                "{}/v1/approval-requests/{}/approve",
                self.config.token.issuer.trim_end_matches('/'),
                request.request_id
            ),
            deny_url: format!(
                "{}/v1/approval-requests/{}/deny",
                self.config.token.issuer.trim_end_matches('/'),
                request.request_id
            ),
            expires_at_secs: request.expires_at.as_micros() / 1_000_000,
        };

        match self.approval_client.deliver(&cfg, &payload) {
            Ok(()) => {
                approval_notifier::log_delivery_success(&request.request_id, &cfg.url);
                // Remove the outbox entry — delivery confirmed.
                let outbox_key = keys::encode_approval_webhook_outbox(&request.request_id);
                if let Err(e) = self.storage.delete(realm_id, &outbox_key) {
                    tracing::warn!(
                        request_id = %request.request_id,
                        error = %e,
                        "delivered approval webhook but failed to remove outbox entry"
                    );
                }
            }
            Err(reason) => {
                approval_notifier::log_delivery_failure(&request.request_id, &reason);
                // Outbox entry stays; background scanner will retry.
            }
        }
    }

    /// Scans this realm's approval webhook outbox and redelivers any entries
    /// that survived a previous failed delivery or server crash.
    ///
    /// Called by the startup recovery scan and the periodic background task.
    #[allow(dead_code)]
    pub(super) fn flush_approval_webhook_outbox_inner(&self, realm_id: &RealmId) {
        // Guard: only proceed if this realm has a webhook configured.
        if self
            .get_realm(realm_id)
            .ok()
            .flatten()
            .and_then(|r| r.config().approval_webhook.clone())
            .is_none()
        {
            return;
        }

        let prefix = keys::approval_webhook_outbox_scan_prefix();
        let end = keys::prefix_end(&prefix);

        let entries = match self.storage.scan(realm_id, &prefix, &end) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    realm_id = %realm_id,
                    error = %e,
                    "failed to scan approval webhook outbox"
                );
                return;
            }
        };

        for entry in entries {
            // Extract request_id from key suffix.
            let key_str = String::from_utf8_lossy(&entry.key);
            let Some(request_id) = key_str.strip_prefix("appreq:outbox:") else {
                continue;
            };

            let Ok(request) = self.get_approval_request_inner(realm_id, request_id) else {
                continue;
            };

            // Deliver and clean up on success.
            self.notify_approval_webhook_inner(realm_id, &request);
            // Throttle to avoid hammering a flaky endpoint.
            // Safety: this is called from a background scan, not the hot path.
            #[allow(clippy::disallowed_methods)]
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// Validates a capability token for a tool invocation (Phase C — Complete Mediation).
    ///
    /// Enforces:
    /// - Signature valid for this realm
    /// - `token_type == "capability"` and `aud` contains `"hearth:capability"`
    /// - Token not expired
    /// - `tool` and `action` custom claims match `tool_name` / `action`
    /// - JTI has not been used before (single-use; writes JTI to blocklist on success)
    /// - `sub` of the capability token matches `caller_sub` (M5 — caller binding)
    ///
    /// Returns the `AgentId` embedded in the token's `sub` claim on success.
    /// All failure modes return `ToolApprovalRequired { tool }` to avoid leaking
    /// which specific check failed.
    pub(super) fn validate_capability_token_inner(
        &self,
        realm_id: &RealmId,
        token: &str,
        tool_name: &str,
        action: &str,
        caller_sub: &str,
    ) -> Result<AgentId, IdentityError> {
        let deny = || IdentityError::ToolApprovalRequired {
            tool: tool_name.to_string(),
        };

        // Verify JWT signature against the realm key (with global fallback).
        let claims = self
            .verify_token_signature_for_realm(realm_id, token)
            .map_err(|_| deny())?;

        // Assert token type.
        if claims.token_type != "capability" {
            return Err(deny());
        }

        // Assert audience.
        if !claims.aud.contains("hearth:capability") {
            return Err(deny());
        }

        // Assert not expired.
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        if claims.exp <= now_secs {
            return Err(deny());
        }

        // Assert tool and action match.
        let token_tool = claims
            .custom
            .get("tool")
            .and_then(|v| v.as_str())
            .ok_or_else(deny)?;
        let token_action = claims
            .custom
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(deny)?;
        if token_tool != tool_name || token_action != action {
            return Err(deny());
        }

        // Single-use enforcement: check JTI blocklist.
        let jti = claims.jti.as_deref().ok_or_else(deny)?;
        let jti_key = keys::encode_capability_jti(jti);
        if self
            .storage
            .get(realm_id, &jti_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            // Token already used — treat as requiring fresh approval.
            return Err(deny());
        }

        // Record JTI as spent (single-use).
        self.storage
            .put(realm_id, &jti_key, b"1")
            .map_err(Self::storage_err)?;

        // M5 — caller binding: capability token must have been minted for the caller.
        // Prevents agent A from consuming an approval that was issued for agent B.
        if claims.sub != caller_sub {
            return Err(deny());
        }

        // Parse agent ID from `sub`.
        let agent_uuid = uuid::Uuid::parse_str(&claims.sub).map_err(|_| deny())?;
        let agent_id = AgentId::new(agent_uuid);

        // Emit audit event for the authorized invocation.
        let _ = self.record_audit(
            realm_id,
            None,
            AuditAction::AgentToolInvocation,
            "tool",
            &format!("{}.{}", token_tool, token_action),
        );

        Ok(agent_id)
    }
}
