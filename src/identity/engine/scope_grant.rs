//! The identity engine's one scope-resolution entry point
//! (`scope-consent-integrity` design §2).
//!
//! Every issuance path resolves its scopes here: `/authorize` and the device
//! grant in [`ScopeMode::Request`], the code exchange, refresh and live
//! resolution in [`ScopeMode::Reissue`]. The rules live in
//! `rbac::resolve::resolve_with_scopes`; this layer picks the client's trust
//! level and declared scopes, maps the errors and audits orphans.

use crate::core::{OrganizationId, RealmId, Uri, UserId};
use crate::identity::oidc::OAuthClient;
use crate::identity::{ClientTrustLevel, IdentityEngine as _, IdentityError};
use crate::rbac::{RbacError, ResolvedPermissions, ScopeMode, ScopeRequest};

use super::EmbeddedIdentityEngine;

/// One scope resolution, as an issuance path sees it.
pub(super) struct ScopeGrant<'a> {
    /// The user, or `None` for a grant with no user (`client_credentials`,
    /// or a device code not yet approved).
    pub(super) user_id: Option<&'a UserId>,
    /// The client, or `None` for a Hearth session token (first-party).
    pub(super) client: Option<&'a OAuthClient>,
    /// The scopes asked for, or granted earlier when `mode` is `Reissue`.
    pub(super) requested: &'a [String],
    /// The canonical RFC 8707 resource.
    pub(super) resource: Option<&'a Uri>,
    /// The organization context.
    pub(super) org_id: Option<&'a OrganizationId>,
    /// Request or re-issue rules.
    pub(super) mode: ScopeMode,
    /// The grant's recorded narrowing (`ScopeRequest::narrowed`); `false` for
    /// a new request.
    pub(super) narrowed: bool,
    /// Whether a token is minted from the result: the per-token size caps
    /// apply then. `/authorize` only decides what is grantable.
    pub(super) issuing: bool,
}

/// Splits a space-delimited scope string (RFC 6749 §3.3).
pub(super) fn scope_list(scope: Option<&str>) -> Vec<String> {
    scope
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

impl EmbeddedIdentityEngine {
    /// Resolves `grant` against the current registry.
    ///
    /// A refusal is `InvalidScope` for a request and `InvalidGrant` for a
    /// re-issue: a grant that can no longer be honoured as issued.
    pub(super) fn grant_scopes(
        &self,
        realm_id: &RealmId,
        grant: &ScopeGrant<'_>,
    ) -> Result<ResolvedPermissions, IdentityError> {
        let (trust_level, declared) = grant
            .client
            .map_or((ClientTrustLevel::FirstParty, &[][..]), |c| {
                (c.trust_level(), c.declared_scopes())
            });
        let resolved = self
            .rbac
            .resolve_with_scopes(
                realm_id,
                &ScopeRequest {
                    user_id: grant.user_id,
                    org_id: grant.org_id,
                    requested: grant.requested,
                    trust_level,
                    declared,
                    resource: grant.resource,
                    mode: grant.mode,
                    narrowed: grant.narrowed,
                },
            )
            .map_err(|e| match e {
                RbacError::InvalidScope { reason } => match grant.mode {
                    ScopeMode::Request => IdentityError::InvalidScope { reason },
                    ScopeMode::Reissue => IdentityError::InvalidGrant { reason },
                },
                RbacError::TokenSizeExceeded {
                    limit,
                    limit_value,
                    actual,
                } => IdentityError::TokenTooLarge {
                    limit: format!("access_token_{limit}"),
                    limit_value,
                    actual,
                },
                e => IdentityError::Internal {
                    reason: format!("rbac resolve failed: {e}"),
                },
            })?;
        self.audit_orphans(realm_id, &resolved.orphans);
        if grant.issuing {
            crate::rbac::enforce_token_caps(
                &resolved.permissions,
                &resolved.roles,
                &resolved.groups,
            )
            .map_err(|e| match e {
                RbacError::TokenSizeExceeded {
                    limit,
                    limit_value,
                    actual,
                } => IdentityError::TokenTooLarge {
                    limit: format!("access_token_{limit}"),
                    limit_value,
                    actual,
                },
                e => IdentityError::Internal {
                    reason: format!("rbac caps failed: {e}"),
                },
            })?;
        }
        Ok(resolved)
    }
}

impl EmbeddedIdentityEngine {
    /// The recorded narrowing of the grant family `fid` names. A token that
    /// names a family this node cannot read is treated as narrowed, so live
    /// resolution fails toward fewer permissions.
    pub(super) fn grant_family_narrowed(&self, realm_id: &RealmId, fid: Option<&str>) -> bool {
        let Some(fid) = fid else {
            return false;
        };
        self.storage
            .get(realm_id, &crate::identity::keys::encode_grant_family(fid))
            .ok()
            .flatten()
            .and_then(|bytes| {
                serde_json::from_slice::<crate::identity::oidc::StoredGrantFamily>(&bytes).ok()
            })
            .map_or(true, |family| family.scope_narrowed)
    }
}

impl EmbeddedIdentityEngine {
    /// Engine half of [`crate::identity::IdentityEngine::authorization_scopes`].
    pub(super) fn authorization_scopes_inner(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &crate::core::ClientId,
        scope: &str,
        resource: Option<&str>,
    ) -> Result<Vec<String>, IdentityError> {
        let client = self
            .get_client(realm_id, client_id)?
            .ok_or(IdentityError::InvalidClient)?;
        self.validate_client_scope_request(&client, scope)?;
        let resource = resource
            .map(|r| self.resolve_authorization_resource(realm_id, r))
            .transpose()?;
        let requested = scope_list(Some(scope));
        let granted = self.grant_scopes(
            realm_id,
            &ScopeGrant {
                user_id: Some(user_id),
                client: Some(&client),
                requested: &requested,
                resource: resource.as_ref(),
                org_id: None,
                mode: ScopeMode::Request,
                narrowed: false,
                issuing: false,
            },
        )?;
        Ok(granted.granted_scopes)
    }
}
