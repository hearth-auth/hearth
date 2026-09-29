//! Host-side issuance of a short-lived system-realm operator token
//! (`hearth admin token`, GA audit 3 DOC-2).
//!
//! Runbooks that call `/admin/realms` or `/admin/cluster/*` need a token for
//! the system realm (the nil UUID). The only way to mint one was
//! `POST /admin/bootstrap`, which exists only in a `dev-endpoints` build
//! running `--dev`. This module is the production source: a one-shot CLI opens
//! a stopped node's store and asks for a token for a named operator account.
//!
//! Whoever can run it already holds the data directory, `HEARTH_MASTER_KEY`
//! and the key-encryption key — every secret the server itself trusts — so it
//! does not run the interactive gates a login does (password, second factor,
//! network policy, session quota). It still refuses an account that does not
//! hold `hearth.admin`, bounds the lifetime, and records the issuance in the
//! system realm's audit trail before the token exists anywhere else.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::audit::{Actor, CreateAuditEvent};
use crate::core::{ClientId, SessionId, Timestamp, UserId};
use crate::identity::claims_config::ClaimTarget;
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::oidc::OAuthClient;
use crate::identity::tokens::{IssueTokenRequest, TokenConfig};
use crate::identity::types::{Session, SessionContext, UserStatus};
use crate::identity::IdentityEngine;

use super::{validate_claim_payload, EmbeddedIdentityEngine};

/// Shortest lifetime [`EmbeddedIdentityEngine::issue_host_admin_token`] grants.
pub const HOST_ADMIN_TOKEN_MIN_TTL: Duration = Duration::from_secs(60);

/// Longest lifetime [`EmbeddedIdentityEngine::issue_host_admin_token`] grants.
pub const HOST_ADMIN_TOKEN_MAX_TTL: Duration = Duration::from_secs(60 * 60);

/// The `issued_via` value in the issuance's audit metadata.
pub const HOST_ADMIN_TOKEN_ISSUER: &str = "hearth admin token";

/// A system-realm access token minted on the host.
///
/// The token is a bearer credential: it is zeroed on drop and `Debug` does
/// not print it.
pub struct HostAdminToken {
    access_token: Zeroizing<String>,
    user_id: UserId,
    session_id: SessionId,
    expires_at: Timestamp,
}

impl HostAdminToken {
    /// The signed access token (a JWT) — print it once, never log it.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The operator account the token was issued to.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The session the token is bound to. Revoking it revokes the token.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// When the token (and its session) stop validating.
    #[must_use]
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

impl fmt::Debug for HostAdminToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostAdminToken")
            .field("access_token", &"<redacted>")
            .field("user_id", &self.user_id)
            .field("session_id", &self.session_id)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl EmbeddedIdentityEngine {
    /// Mints a short-lived access token for a system-realm operator account.
    ///
    /// The token is bound to a new session that expires with it, carries the
    /// account's resolved RBAC claims (which must include `hearth.admin`), and
    /// comes with no usable refresh token. The issuance is written to the
    /// system realm's audit trail before the token is returned; if that write
    /// fails, the session is removed and no token is returned.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::InvalidInput`] — `ttl` is outside
    ///   [`HOST_ADMIN_TOKEN_MIN_TTL`]..=[`HOST_ADMIN_TOKEN_MAX_TTL`].
    /// - [`IdentityError::UserNotFound`] — no such account in the system realm.
    /// - [`IdentityError::UserNotVerified`] / [`IdentityError::Unauthorized`] —
    ///   the account is pending verification or disabled.
    /// - [`IdentityError::Unauthorized`] — the account's token would not carry
    ///   `hearth.admin`.
    /// - [`IdentityError::AuditFailure`] — the issuance could not be audited.
    /// - Storage and signing errors.
    #[allow(clippy::too_many_lines)] // one linear issuance; splitting hides the order
    pub fn issue_host_admin_token(
        &self,
        user_id: &UserId,
        ttl: Duration,
    ) -> Result<HostAdminToken, IdentityError> {
        if !(HOST_ADMIN_TOKEN_MIN_TTL..=HOST_ADMIN_TOKEN_MAX_TTL).contains(&ttl) {
            return Err(IdentityError::InvalidInput {
                reason: format!(
                    "the token lifetime must be between {} and {} seconds",
                    HOST_ADMIN_TOKEN_MIN_TTL.as_secs(),
                    HOST_ADMIN_TOKEN_MAX_TTL.as_secs()
                ),
            });
        }
        // Bounded by HOST_ADMIN_TOKEN_MAX_TTL above, so this cannot truncate.
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
                user_agent_raw: Some(HOST_ADMIN_TOKEN_ISSUER.to_string()),
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

        let user_session_key = keys::encode_user_session(user_id, &session_id);
        self.persist_session_with(&realm_id, &session, vec![(user_session_key, Vec::new())])?;

        // The audit record is a precondition, not a best effort: an operator
        // token nobody can trace is worse than no token. `record_audit` treats
        // `TokenIssued` as log-only, so append directly and undo on failure.
        let event = CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: Actor::System.label(),
            action: crate::audit::AuditAction::TokenIssued,
            resource_type: "token".to_string(),
            resource_id: session_id.as_uuid().to_string(),
            metadata: Some(serde_json::json!({
                "issued_via": HOST_ADMIN_TOKEN_ISSUER,
                "operator_user_id": user_id.as_uuid().to_string(),
                "ttl_secs": ttl.as_secs(),
            })),
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
            ttl_secs,
            "issued a host operator token for the system realm"
        );
        Ok(HostAdminToken {
            access_token,
            user_id: user_id.clone(),
            session_id,
            expires_at,
        })
    }
}
