//! [`IdentityEngine::issue_operator_token`] for [`EmbeddedIdentityEngine`]
//! (GA audit 3 DOC-2). The types and the two calling surfaces are described
//! in [`crate::identity::operator_token`].
//!
//! The engine performs no interactive gate here (password, second factor,
//! network policy, session quota): each surface proves the caller first. The
//! console demands a fresh two-factor step-up
//! ([`crate::identity::verify_operator_step_up`]); the CLI's caller already
//! holds the data directory, `HEARTH_MASTER_KEY` and the key-encryption key.
//! The engine still refuses an account whose token would not carry
//! `hearth.admin`, bounds the lifetime, and audits the issuance before the
//! token is returned.
//!
//! Every write goes through `self.storage` — the cluster adapter in `serve` —
//! so in cluster mode the session and the audit record are Raft proposals and
//! reach every node.

use std::collections::BTreeSet;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::audit::{Actor, CreateAuditEvent};
use crate::core::{ClientId, SessionId, UserId};
use crate::identity::claims_config::ClaimTarget;
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::oidc::OAuthClient;
use crate::identity::operator_token::{
    OperatorToken, OperatorTokenIssuer, OPERATOR_TOKEN_MAX_TTL, OPERATOR_TOKEN_MIN_TTL,
};
use crate::identity::tokens::{IssueTokenRequest, TokenConfig};
use crate::identity::types::{Session, SessionContext, UserStatus};
use crate::identity::IdentityEngine;

use super::{validate_claim_payload, EmbeddedIdentityEngine};

impl EmbeddedIdentityEngine {
    /// Implements [`IdentityEngine::issue_operator_token`].
    #[allow(clippy::too_many_lines)] // one linear issuance; splitting hides the order
    pub(super) fn issue_operator_token_impl(
        &self,
        user_id: &UserId,
        ttl: Duration,
        issuer: &OperatorTokenIssuer,
    ) -> Result<OperatorToken, IdentityError> {
        if !(OPERATOR_TOKEN_MIN_TTL..=OPERATOR_TOKEN_MAX_TTL).contains(&ttl) {
            return Err(IdentityError::InvalidInput {
                reason: format!(
                    "the token lifetime must be between {} and {} seconds",
                    OPERATOR_TOKEN_MIN_TTL.as_secs(),
                    OPERATOR_TOKEN_MAX_TTL.as_secs()
                ),
            });
        }
        // Bounded by OPERATOR_TOKEN_MAX_TTL above, so this cannot truncate.
        let ttl_secs = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);

        let realm_id = keys::system_realm_id();
        self.require_active_realm(&realm_id)?;
        let user = self
            .get_user(&realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;
        match user.status() {
            UserStatus::Active => {}
            UserStatus::PendingVerification => return Err(IdentityError::UserNotVerified),
            UserStatus::Disabled => return Err(IdentityError::Unauthorized),
        }

        let now = self.clock.now();
        let resolved = self
            .rbac
            .resolve_permissions(user_id, &realm_id, None, None)
            .map_err(|e| IdentityError::Internal {
                reason: format!("rbac resolve failed: {e}"),
            })?;
        // The same first-party sentinel `issue_tokens` uses, so the claims have
        // exactly the shape a console session's token has.
        let sentinel_client =
            OAuthClient::new(ClientId::generate(), "session".to_string(), Vec::new(), now);
        let (roles, groups, permissions, custom) = self.apply_claim_profile(
            &realm_id,
            &user,
            &sentinel_client,
            &resolved,
            &BTreeSet::new(),
            None,
            ClaimTarget::AccessToken,
        );
        validate_claim_payload(ClaimTarget::AccessToken, &roles, &groups, &permissions)?;
        // Checked on the claims the token will carry, not on the resolved set:
        // a claim profile may withhold a permission, and a token without
        // `hearth.admin` is refused by every admin route it exists for.
        if !permissions.iter().any(|p| p == "hearth.admin") {
            return Err(IdentityError::Unauthorized);
        }

        let session_id = SessionId::new(crate::core::random_secret_uuid());
        let expires_at = now.add_micros(ttl_secs * 1_000_000);
        let session = Session::new(
            session_id.clone(),
            user_id.clone(),
            now,
            expires_at,
            &SessionContext {
                user_agent_raw: Some(issuer.issued_via().to_string()),
                ..SessionContext::default()
            },
            None,
            None,
        );

        // Sign before anything is written: a signing failure leaves no trace.
        // The pair's refresh token is dropped unused — it names no grant
        // family, so `refresh_tokens` refuses it anyway.
        let token_config = TokenConfig {
            access_token_ttl_secs: ttl_secs,
            refresh_token_ttl_secs: ttl_secs,
            ..self.config.token.clone()
        };
        let sv_claim = self.get_realm(&realm_id).ok().flatten().and_then(|realm| {
            realm
                .config()
                .session_version
                .enabled
                .then(|| self.get_session_sv(&realm_id, &session_id))
        });
        let pair = self
            .get_signing_key_or_default(&realm_id)
            .issue_token_pair(&IssueTokenRequest {
                sub: &user_id.to_string(),
                sid: &session_id.to_string(),
                tid: &realm_id.to_string(),
                oid: None,
                now,
                config: &token_config,
                issuer_override: Some(self.realm_issuer_url(&realm_id)),
                roles: &roles,
                groups: &groups,
                org_slug: None,
                permissions: &permissions,
                custom,
                resource: None,
                dpop_jkt: None,
                sv: sv_claim,
                scope: None,
                fid: None,
            })?;
        let access_token = Zeroizing::new(pair.access_token().to_string());
        drop(pair);
        // Our own token, signed a moment ago: reading its jti needs no check.
        let jti = crate::identity::tokens::decode_claims_unverified(&access_token)?.jti;

        let user_session_key = keys::encode_user_session(user_id, &session_id);
        self.persist_session_with(&realm_id, &session, vec![(user_session_key, Vec::new())])?;

        // The audit record is a precondition, not a best effort: an operator
        // token nobody can trace is worse than no token. `record_audit` treats
        // `TokenIssued` as log-only, so append directly and undo on failure.
        let (actor, mut metadata) = match issuer {
            OperatorTokenIssuer::HostCli => (Actor::System.label(), serde_json::json!({})),
            OperatorTokenIssuer::Console { console_session_id } => (
                Actor::User(user_id.clone()).label(),
                serde_json::json!({
                    "console_session_id": console_session_id.as_uuid().to_string(),
                }),
            ),
        };
        metadata["issued_via"] = serde_json::json!(issuer.issued_via());
        metadata["operator_user_id"] = serde_json::json!(user_id.as_uuid().to_string());
        metadata["ttl_secs"] = serde_json::json!(ttl.as_secs());
        metadata["jti"] = serde_json::json!(jti);
        let event = CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor,
            action: crate::audit::AuditAction::TokenIssued,
            resource_type: "token".to_string(),
            resource_id: session_id.as_uuid().to_string(),
            metadata: Some(metadata),
        };
        if let Err(e) = self.audit.append(&event) {
            let undo = self.storage.write_batch(
                &realm_id,
                &[],
                &[
                    keys::encode_session_id(&session_id),
                    keys::encode_user_session(user_id, &session_id),
                ],
            );
            self.session_cache_invalidate(&realm_id, &session_id);
            if let Err(undo_err) = undo {
                tracing::error!(
                    error = %undo_err,
                    session_id = %session_id.as_uuid(),
                    "could not remove the session of an operator token whose issuance \
                     was not audited; revoke it"
                );
            }
            return Err(IdentityError::AuditFailure {
                action: event.action.as_str().to_string(),
                reason: e.to_string(),
            });
        }

        tracing::info!(
            operator_user_id = %user_id.as_uuid(),
            session_id = %session_id.as_uuid(),
            issued_via = issuer.issued_via(),
            ttl_secs,
            "issued a system-realm operator token"
        );
        Ok(OperatorToken::new(
            access_token,
            jti,
            user_id.clone(),
            session_id,
            expires_at,
        ))
    }
}
