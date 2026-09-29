//! OAuth 2.0 / OIDC method implementations for [`EmbeddedIdentityEngine`].
//!
//! Extracted from `mod.rs` for navigability. Public API is unchanged —
//! `mod.rs` delegates to these `pub(super)` methods via thin wrappers in
//! `impl IdentityEngine for EmbeddedIdentityEngine`.

use std::collections::BTreeSet;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SecureRandom;

use crate::audit::{Actor, AuditAction, AuditContext};
use crate::core::{ClientId, RealmId, SessionId, Uri, UserId};
use crate::identity::claims_config::ClaimTarget;
use crate::identity::credentials::{self, CleartextPassword};
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::oidc::{
    ApplicationStatus, AuthorizationRequest, AuthorizationResponse, BackchannelTarget,
    ClientProfile, CodeChallengeMethod, FrontchannelTarget, OAuthClient, OidcDiscoveryDocument,
    OidcTokenResponse, RegisterClientRequest, ResponseMode, RpLogoutRequest, RpLogoutResult,
    StoredAuthorizationCode, StoredDeviceCode, StoredGrantFamily, TokenExchangeRequest,
};
use crate::identity::tokens::{self, Audience, LogoutTokenClaims, TokenClaims};
use crate::identity::types::{
    BulkResult, ConsentListEntry, ConsentRecord, CreateUserRequest, DelegationGrantEntry,
    PendingAuthorizationRequest, StoredDelegationGrant, UpdateUserRequest, User, UserStatus,
};
use crate::identity::validation;
use crate::identity::IdentityEngine;
use crate::rbac::error::RbacError;

use super::validate_claim_payload;
use super::EmbeddedIdentityEngine;
use super::CLIENT_TOKEN_CUTOFF_PREFIX;
use super::CLOCK_SKEW_SECS;
use super::{audience_cutoff_hash_hex, AUDIENCE_CUTOFF_HASH_HEX_LEN, AUDIENCE_TOKEN_CUTOFF_PREFIX};

/// The `client_id` exactly as the client knows it: the bare UUID that
/// registration returns and the client sends as its `client_id` parameter.
///
/// A client-authored JWT names the client by this value — a client
/// assertion's `iss` and `sub` (RFC 7523 §3, OIDC Core §9), a request
/// object's `iss` and `client_id` (RFC 9101 §4). [`ClientId`]'s `Display`
/// form (`client_<uuid>`) is Hearth's internal subject form and is never
/// accepted there (GA audit 3 round 4). The comparison is exact: no other
/// spelling of the same UUID (upper case, braces, `urn:uuid:`) matches.
fn issued_client_id(client_id: &ClientId) -> String {
    client_id.as_uuid().to_string()
}

impl EmbeddedIdentityEngine {
    // ===== Legacy OIDC RSA key material =====

    /// Deletes every `sys:oidc:rsa:*` row left by an older build.
    ///
    /// That family held a server-wide RSA-2048 keypair serialised as plain
    /// JSON — PKCS#8 **private** key included, with no HKEY envelope, while
    /// every other key family was wrapped (audit 2026-08-28 §4.15#4). Its only
    /// consumer was the `RS256` entry in the global JWKS, and Hearth never
    /// signed anything with it, so the JWKS now publishes Ed25519 only
    /// (§4.2#4, §4.15#5).
    ///
    /// Wrapping a key nothing uses would keep an unnecessary private key at
    /// rest; the row is removed instead. Called once per process from the
    /// constructor. Best-effort: a storage failure here is logged, never
    /// fatal, and the sweep retries on the next start.
    pub(super) fn purge_legacy_oidc_rsa_keys(&self) {
        let sys = keys::system_realm_id();
        let prefix = keys::legacy_oidc_rsa_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = match self.storage.scan(&sys, &prefix, &end) {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(error = %err, "could not scan for legacy OIDC RSA key rows");
                return;
            }
        };
        let mut removed = 0_usize;
        for entry in entries {
            match self.storage.delete(&sys, &entry.key) {
                Ok(()) => removed += 1,
                Err(err) => {
                    tracing::warn!(error = %err, "could not delete a legacy OIDC RSA key row");
                }
            }
        }
        if removed > 0 {
            tracing::info!(
                removed,
                "removed unencrypted legacy OIDC RSA key rows; the JWKS publishes Ed25519 only"
            );
        }
    }
}

#[allow(clippy::too_many_lines)]
impl EmbeddedIdentityEngine {
    // ===== OAuth / OIDC trait method implementations =====

    /// Narrows a caller-supplied org context to `None` unless the
    /// organisation exists and is `Active`.
    ///
    /// Suspension is a kill switch, not a label: a frozen organisation must
    /// stop granting its org-scoped assignments and extra roles through the
    /// live-RBAC paths (`/introspect`, `POST /oauth/authorize`), exactly as
    /// it stops minting org-context tokens. Realm-scoped authority is
    /// untouched — the control kills the organisation, not the member's
    /// account. Fails closed on an unknown org or a storage error
    /// (subsystem audit 2026-09-21, finding O-2).
    pub(crate) fn active_org_context(
        &self,
        realm_id: &RealmId,
        org_id: Option<crate::core::OrganizationId>,
    ) -> Option<crate::core::OrganizationId> {
        let org_id = org_id?;
        match self.get_organization(realm_id, &org_id) {
            Ok(Some(org)) if org.status() == crate::identity::OrganizationStatus::Active => {
                Some(org_id)
            }
            _ => None,
        }
    }

    // ===== OIDC / OAuth 2.0 =====

    pub(super) fn register_client_inner(
        &self,
        realm_id: &RealmId,
        request: &RegisterClientRequest,
    ) -> Result<OAuthClient, IdentityError> {
        // OAuth clients never target the admin realm. This is the
        // strongest structural guarantee that the admin surface and
        // application auth surfaces cannot be conflated.
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "register_client",
            });
        }
        // A-24: enforce per-realm client quota before writing.
        if let Ok(Some(realm)) = self.get_realm(realm_id) {
            if let Some(quotas) = &realm.config().quotas {
                if let Some(max) = quotas.max_clients {
                    let prefix = keys::oauth_client_scan_prefix();
                    self.check_resource_quota(realm_id, "clients", &prefix, max)?;
                }
            }
        }
        // Validate client name (non-empty, length limit)
        let client_name = validation::validate_client_name(&request.client_name)?;

        // Redirect URIs are optional for M2M grants (client_credentials, device_code,
        // jwt-bearer). For all other grant types, at least one is required.
        let has_client_credentials = request
            .grant_types
            .contains(&"client_credentials".to_string());
        let has_device_code = request
            .grant_types
            .contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string());
        let has_jwt_bearer = request
            .grant_types
            .contains(&"urn:ietf:params:oauth:grant-type:jwt-bearer".to_string());
        if request.redirect_uris.is_empty()
            && !has_client_credentials
            && !has_device_code
            && !has_jwt_bearer
        {
            return Err(IdentityError::InvalidInput {
                reason: "at least one redirect URI is required".to_string(),
            });
        }
        for uri in &request.redirect_uris {
            if uri.trim().is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "redirect URIs must not be empty".to_string(),
                });
            }
            validation::validate_redirect_uri(uri)?;
        }

        let client_id = ClientId::generate();
        let now = self.clock.now();

        let grant_types = if request.grant_types.is_empty() {
            crate::identity::oidc::default_grant_types()
        } else {
            request.grant_types.clone()
        };

        let secret_hash = match (&request.client_secret, &request.generated_client_secret) {
            (Some(_), Some(_)) => {
                return Err(IdentityError::InvalidInput {
                    reason: "client_secret and generated_client_secret are mutually exclusive"
                        .to_string(),
                });
            }
            // A caller-chosen secret has unknown entropy: Argon2id.
            (Some(secret), None) => Some(credentials::hash_raw_secret(
                secret.as_bytes(),
                &self.config.credential,
            )?),
            // A Hearth-generated secret carries 256 CSPRNG bits: fast SHA-256.
            (None, Some(generated)) => Some(credentials::hash_generated_client_secret(generated)),
            (None, None) => None,
        };
        let mut client = if let Some(secret_hash) = secret_hash {
            OAuthClient::new_confidential(
                client_id.clone(),
                client_name,
                request.redirect_uris.clone(),
                now,
                secret_hash,
                grant_types,
            )
        } else {
            let mut c = OAuthClient::new(
                client_id.clone(),
                client_name,
                request.redirect_uris.clone(),
                now,
            );
            // Override grant_types from request
            c.set_grant_types(grant_types);
            c
        };

        // Consent is trust-level-driven under the expanded authz model.
        client.set_require_consent(
            request.trust_level == crate::identity::ClientTrustLevel::ThirdParty,
        );
        client.set_client_logo_url(request.client_logo_url.clone());
        client.set_slug(
            request
                .slug
                .clone()
                .unwrap_or_else(|| client.client_name().to_lowercase().replace(' ', "-")),
        );
        client.set_trust_level(request.trust_level);
        client.set_declared_scopes(request.declared_scopes.clone());
        client.set_consent_spans_orgs(request.consent_spans_orgs);
        client.set_access_token_authorization(request.access_token_authorization);
        if let Some(jwks) = request.jwks.as_deref() {
            Self::check_client_jwks(jwks)?;
        }
        client.set_jwks(request.jwks.clone());
        client.set_jwks_uri(request.jwks_uri.clone());
        if let Some(ref alg) = request.authorization_signed_response_alg {
            if alg != "EdDSA" {
                return Err(IdentityError::InvalidInput {
                    reason: format!(
                        "unsupported authorization_signed_response_alg '{alg}'; supported: EdDSA"
                    ),
                });
            }
            client.set_authorization_signed_response_alg(Some(alg.clone()));
        }
        client.set_profile(request.profile);
        // FAPI 2.0 registration constraints: private_key_jwt only, with keys
        // Hearth can verify (FAPI 2.0 Security Profile §5.3.2.1).
        Self::check_fapi2_client_keys(&client)?;
        if request.mfa_required.is_some() {
            client.set_mfa_required(request.mfa_required);
        }
        if !request.cors_origins.is_empty() {
            client.set_cors_origins(request.cors_origins.clone());
        }

        // ID-token signing algorithm (task 26.55). `None` is the administrative
        // default, EdDSA; both Dynamic Client Registration handlers resolve an
        // omitted value to RS256 (OIDC Registration §2) — EdDSA in a FAPI
        // realm — before reaching here. Resolved last among the validations and
        // persisted explicitly; RS256 is refused under FAPI 2.0 (§5.4.1) and
        // otherwise provisions the realm's RSA key before the client exists.
        let fapi = request.profile.is_fapi2() || self.realm_enforces_fapi(realm_id)?;
        client.set_id_token_signed_response_alg(self.resolve_client_id_token_alg(
            realm_id,
            request.id_token_signed_response_alg.as_deref(),
            fapi,
        )?);

        // Serialize and persist
        let client_bytes =
            serde_json::to_vec(&client).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let key = keys::encode_oauth_client(&client_id);
        self.storage
            .put(realm_id, &key, &client_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::ClientRegistered,
            "client",
            &client_id.as_uuid().to_string(),
        )?;

        Ok(client)
    }

    /// Ties a non-interactive authorization request to the caller's bearer
    /// token (GA audit 3 B-1) and returns the token's session.
    ///
    /// The token must belong to the requesting user and name a session. A
    /// token issued to a client (RFC 9068 `client_id`) may authorize that
    /// client only; a token that names no client is a first-party session
    /// token, and [`Self::authorize_inner`] allows it a first-party client
    /// only, once the client is loaded. An unparseable claim fails closed.
    fn bearer_session_for(
        claims: &TokenClaims,
        request: &AuthorizationRequest,
    ) -> Result<SessionId, IdentityError> {
        if Self::parse_user_id_claim(claims)? != request.user_id {
            return Err(IdentityError::InvalidToken);
        }
        if let Some(raw) = claims.client_id() {
            if raw.parse::<ClientId>().ok().as_ref() != Some(&request.client_id) {
                return Err(IdentityError::ClientMismatch);
            }
        }
        claims
            .sid
            .parse::<SessionId>()
            .map_err(|_| IdentityError::InvalidToken)
    }

    /// Issues an authorization code.
    ///
    /// `bearer` is set by the non-interactive surfaces (JSON and gRPC
    /// `Authorize`) to the validated claims of the caller's bearer token.
    /// They cannot show a consent screen or a factor challenge, so they may
    /// issue only for the client the token was issued to — or, for a
    /// first-party session token, a first-party client (GA audit 3 B-1) —
    /// only when the client does not require consent or a recorded consent
    /// covers the requested scopes (GA audit B2), and — for a client or role
    /// that demands a second factor — only when the token's session proved
    /// one (GA audit B5). The browser flow passes `None`: its gates
    /// (`authorize_gate::mfa_use_gate`, `consent_gate`) have already run.
    #[allow(clippy::too_many_lines)]
    pub(super) fn authorize_inner(
        &self,
        realm_id: &RealmId,
        request: &AuthorizationRequest,
        bearer: Option<&TokenClaims>,
        browser_proof: crate::identity::MfaProof,
    ) -> Result<AuthorizationResponse, IdentityError> {
        use crate::identity::oidc::{CodeChallengeMethod as CCM, JarmClaims};
        use crate::identity::types::FapiProfile;

        // Retained for potential future use; FAPI Advanced JAR enforcement
        // moved to push_authorization_request where the JTI is not yet consumed.
        let _jar_was_present = request.request.is_some();

        // 0a. The bearer token of a non-interactive request (GA audit 3 B-1):
        //     it must be the requesting user's, and a token issued to a client
        //     may mint a code for that client only. Without this a third-party
        //     app's token minted a code for any first-party public client —
        //     no consent needed — and redeemed it for that client's tokens
        //     carrying the user's full permissions. Checked before JAR, the
        //     nonce sentinel or any other side effect.
        let bearer_session = bearer
            .map(|claims| Self::bearer_session_for(claims, request))
            .transpose()?;

        // 0. JAR (RFC 9101): if a signed request object is present, verify it
        //    and use its claims to override the outer query parameters. This must
        //    happen before any other validation so that JAR-supplied values
        //    (state, redirect_uri, scope, …) are used for subsequent checks.
        let jar_override;
        let request = if let Some(ref jar_jwt) = request.request {
            let jar = self.verify_jar(realm_id, &request.client_id, jar_jwt)?;

            // `verify_jar` checked the JAR's `iss` and `client_id` (RFC 9101 §4).

            let ccm = jar.code_challenge_method.as_deref().and_then(|m| {
                if m == "S256" {
                    Some(CCM::S256)
                } else {
                    None
                }
            });

            jar_override = AuthorizationRequest {
                client_id: request.client_id.clone(),
                redirect_uri: jar
                    .redirect_uri
                    .unwrap_or_else(|| request.redirect_uri.clone()),
                scope: jar.scope.unwrap_or_else(|| request.scope.clone()),
                state: jar.state.unwrap_or_else(|| request.state.clone()),
                resource: jar.resource.or_else(|| request.resource.clone()),
                response_type: jar
                    .response_type
                    .unwrap_or_else(|| request.response_type.clone()),
                user_id: request.user_id.clone(),
                code_challenge: jar
                    .code_challenge
                    .or_else(|| request.code_challenge.clone()),
                code_challenge_method: ccm.or_else(|| request.code_challenge_method.clone()),
                nonce: jar.nonce.or_else(|| request.nonce.clone()),
                amr_values: request.amr_values.clone(),
                response_mode: request.response_mode.clone(),
                request: None, // consumed — prevent re-entry
                via_par: request.via_par,
            };
            &jar_override
        } else {
            request
        };

        // 1. Validate response_type
        if request.response_type != "code" {
            return Err(IdentityError::InvalidInput {
                reason: "response_type must be 'code'".to_string(),
            });
        }

        // 1b. Validate response_mode (if provided)
        if let Some(mode) = &request.response_mode {
            let supported = [
                ResponseMode::Query,
                ResponseMode::Fragment,
                ResponseMode::QueryJwt,
                ResponseMode::FragmentJwt,
                ResponseMode::Jwt,
            ];
            if !supported.contains(mode) {
                return Err(IdentityError::InvalidInput {
                    reason: format!(
                        "unsupported response_mode '{}'; supported: query, fragment, query.jwt, fragment.jwt, jwt",
                        mode.as_str()
                    ),
                });
            }
        }

        // 2. Validate state is non-empty (CSRF protection)
        if request.state.is_empty() {
            return Err(IdentityError::InvalidGrant {
                reason: "state parameter is required for CSRF protection".to_string(),
            });
        }

        // 2a. Realm lifecycle guard — suspended/archived realms must not issue codes.
        let realm = self
            .get_realm(realm_id)?
            .ok_or(IdentityError::RealmNotFound)?;
        if realm.status() != crate::identity::types::RealmStatus::Active {
            return Err(IdentityError::RealmSuspended);
        }

        // 3. Load and validate client
        let client_key = keys::encode_oauth_client(&request.client_id);
        let client_bytes = self
            .storage
            .get(realm_id, &client_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidClient)?;
        let client: OAuthClient =
            serde_json::from_slice(&client_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        if client.status() != ApplicationStatus::Active {
            return Err(IdentityError::InvalidClient);
        }
        // 3a. The client must be registered for the grant (GA audit M7).
        if !client.allows_grant_type(crate::identity::oidc::GRANT_AUTHORIZATION_CODE) {
            return Err(IdentityError::UnsupportedGrantType);
        }
        // 3a'. A first-party session token names no client; it may authorize a
        //      first-party client only (GA audit 3 B-1). A code for a
        //      third-party client comes from that client's own token or the
        //      browser consent flow, never from whichever token leaked.
        if bearer.is_some_and(|claims| claims.client_id().is_none())
            && client.trust_level() != crate::identity::oidc::ClientTrustLevel::FirstParty
        {
            return Err(IdentityError::ClientMismatch);
        }

        // 3b. FAPI 2.0: PAR is mandatory for FAPI2 clients (RFC 9126 §2.4).
        if client.profile().is_fapi2() && !request.via_par {
            return Err(IdentityError::FapiViolation {
                reason: "FAPI 2.0 clients must use Pushed Authorization Requests (PAR); \
                         obtain a request_uri via POST /as/par before calling /authorize"
                    .to_string(),
            });
        }

        // 3c. Realm-level FAPI 2.0 enforcement gate.
        //
        // When a realm has `fapi_profile` configured, ALL clients in the realm
        // must comply with the corresponding profile constraints. This is additive
        // to the per-client `ClientProfile::Fapi2` check above.
        if let Some(profile) = realm.config().fapi_profile {
            // Baseline + Advanced: PAR required.
            if !request.via_par {
                return Err(IdentityError::FapiViolation {
                    reason: "FAPI 2.0 Baseline requires all authorization requests to go through \
                             PAR (RFC 9126); use POST /as/par to obtain a request_uri"
                        .to_string(),
                });
            }
            // Baseline + Advanced: PKCE (S256) is always required.
            if request.code_challenge.is_none() {
                return Err(IdentityError::FapiViolation {
                    reason: "FAPI 2.0 Baseline requires PKCE (code_challenge with S256)"
                        .to_string(),
                });
            }
            if profile == FapiProfile::Advanced {
                // JAR is enforced at PAR time (push_authorization_request).
                // When via_par = true the JAR was already validated there; no re-check here.
                // Advanced: client must be configured for JARM
                // (authorization_signed_response_alg must be set).
                if client.authorization_signed_response_alg().is_none()
                    && !request
                        .response_mode
                        .as_ref()
                        .map_or(false, |m| m.is_jarm())
                {
                    return Err(IdentityError::FapiViolation {
                        reason: "FAPI 2.0 Advanced requires JARM; register the client with \
                                 `authorization_signed_response_alg` or pass a JWT response_mode"
                            .to_string(),
                    });
                }
                // Advanced: client must have a JWKS registered (required for
                // private_key_jwt token endpoint authentication).
                if client.jwks().is_none() {
                    return Err(IdentityError::FapiViolation {
                        reason: "FAPI 2.0 Advanced requires private_key_jwt client \
                                 authentication; register a JWKS with the client"
                            .to_string(),
                    });
                }
            }
        }

        // 4. Validate redirect_uri matches a registered URI
        if !client.redirect_uris().contains(&request.redirect_uri) {
            return Err(IdentityError::InvalidRedirectUri);
        }

        // 4a. Nonce replay protection (OIDC Core §3.1.2.1 — unconditional)
        //
        // O3 (HEA-1757): detection is scoped to a single client within a single
        // realm. A global key would let one client's nonce usage collide with —
        // and spuriously reject — an identical nonce chosen independently by a
        // client in another realm, which is a cross-tenant availability leak.
        //
        // 22.21 (audit 2026-08-28 §4.22#14) — this used to be a process-local
        // `Mutex<HashMap>`, which was wrong twice over:
        //
        //  * **It did not replicate.** A nonce burned on one node was unknown
        //    to every other node and to the same node after a restart, so the
        //    replay guard was defeated by simply retrying against a different
        //    node. The sentinel now goes through `self.storage`, which `serve`
        //    always wraps in a `ClusterStorageAdapter`, so the write is a Raft
        //    command and every node sees it.
        //  * **It swept the entire set on every `/authorize`.** A `retain` over
        //    the whole map, holding one global `std::sync::Mutex`, ran on every
        //    authorization request in the process — O(n) work and a hard
        //    serialisation point on a request path. Reclamation is now the
        //    periodic cleanup sweep's job (`sweep_oidc_nonces`), exactly like
        //    the JAR/DPoP JTI and SAML assertion sentinels.
        //
        // `put_if_absent` is atomic through the cluster adapter, so the
        // check-and-burn has no TOCTOU window between nodes either.
        //
        // Placed *after* the client and redirect_uri checks rather than
        // before them (where the in-memory version sat): the sentinel is now
        // a durable, fsynced write, so burning one for a request that is
        // about to be rejected for an unknown client or an unregistered
        // redirect_uri would turn a doomed request into storage traffic. A
        // replayed nonce on an otherwise-invalid request now reports the
        // invalid request, which is also one oracle fewer.
        if let Some(ref nonce) = request.nonce {
            let now = self.clock.now();
            let expires_at_secs =
                now.as_micros() / 1_000_000 + self.config.oidc.authorization_code_ttl_secs;
            let key = keys::encode_oidc_nonce(&request.client_id, nonce);
            let fresh = self
                .storage
                .put_if_absent(realm_id, &key, &expires_at_secs.to_le_bytes())
                .map_err(Self::storage_err)?;
            if !fresh {
                // Lazy expiry on the read path. Reclamation is the periodic
                // sweep's job, but a sentinel must not outlive the
                // authorization code it guards: between the code expiring and
                // the next sweep tick, the nonce would still be refused even
                // though replaying it can no longer buy the attacker anything.
                // The JAR and DPoP JTI sentinels expire lazily for the same
                // reason. A malformed or unreadable value fails CLOSED.
                let stored_expiry = self
                    .storage
                    .get(realm_id, &key)
                    .map_err(Self::storage_err)?
                    .and_then(|v| v.as_slice().try_into().ok().map(i64::from_le_bytes));
                let expired = stored_expiry
                    .is_some_and(|expires_at| now.as_micros() / 1_000_000 >= expires_at);
                if !expired {
                    return Err(IdentityError::InvalidGrant {
                        reason: "nonce has already been used".to_string(),
                    });
                }
                self.storage
                    .put(realm_id, &key, &expires_at_secs.to_le_bytes())
                    .map_err(Self::storage_err)?;
            }
        }

        self.validate_client_scope_request(&client, &request.scope)?;

        // 4a. Consent on the non-interactive surfaces (GA audit B2): the same
        //     rule as the browser `consent_gate` — issue only when the client
        //     does not require consent or a recorded consent covers every
        //     requested scope. Checked after JAR has settled the scopes.
        if bearer_session.is_some() && client.require_consent() {
            let requested = crate::identity::types::canonicalize_scopes(
                request
                    .scope
                    .split_whitespace()
                    .map(str::to_string)
                    .collect(),
            );
            let covered = self
                .get_consent_inner(realm_id, &request.user_id, &request.client_id)?
                .is_some_and(|record| record.covers(&requested));
            if !covered {
                return Err(IdentityError::ConsentRequired);
            }
        }

        // 4a'. Factor USE on the non-interactive surfaces (GA audit B5, the
        //      browser `mfa_use_gate`'s rule): a client or role that demands a
        //      second factor needs a bearer session that proved one. There is
        //      no challenge to offer here, so an unproved session is refused.
        //      The code records what the authorizing session proved — the
        //      bearer token's session here, the browser session otherwise —
        //      and the exchange opens a session that proved exactly that
        //      (GA audit round 3, D-7).
        let code_proof = if let Some(session_id) = bearer_session.as_ref() {
            let proof = self
                .get_session(realm_id, session_id)?
                .filter(|s| s.user_id() == &request.user_id)
                .map_or(crate::identity::MfaProof::None, |s| s.mfa_proof());
            if !proof.satisfies_mfa_required()
                && self.client_or_role_requires_mfa(realm_id, &request.user_id, &client)?
            {
                return Err(IdentityError::MfaRequired);
            }
            proof
        } else {
            browser_proof
        };

        // 4b. Consent scope-digest re-check.
        //
        // When a consent record exists for this (user, client) and it carries
        // a non-empty `scope_digest`, re-compute the digest from the requested
        // scopes. A mismatch means the scope surface has changed since the
        // user last consented (e.g. YAML bundles reloaded) — require fresh
        // consent rather than silently issuing a stale grant.
        //
        // Records with an empty digest (written before this feature) are
        // treated as valid to preserve backward compatibility.
        //
        // The RFC 8707 resource is resolved first: it must be a registered
        // protected resource (else `invalid_target`), and its canonical form
        // keys the consent record and becomes the code's audience, so every
        // spelling of one resource is the same resource here (G6).
        let resource = request
            .resource
            .as_deref()
            .map(|r| self.resolve_authorization_resource(realm_id, r))
            .transpose()?;
        let resource_key = resource
            .as_ref()
            .map_or(keys::CONSENT_RESOURCE_KEY_DEFAULT, Uri::as_str);
        if let Some(existing_consent) = self.get_consent_extended(
            realm_id,
            &request.user_id,
            &request.client_id,
            keys::CONSENT_ORG_KEY_REALM,
            resource_key,
            client.consent_spans_orgs(),
        )? {
            // Digest re-check: verify the granted scopes are still self-consistent.
            // Compares the re-computed digest of the stored granted_scopes against
            // what was stored at consent time. A mismatch indicates external tampering
            // or structural corruption; a fresh consent is required.
            // Note: true YAML-bundle-change detection requires resolving scope names
            // to their current permission set and comparing; that is deferred to a
            // future improvement. For now we validate internal record consistency only.
            if !existing_consent.scope_digest.is_empty() {
                let current_digest = Self::compute_scope_digest(&existing_consent.granted_scopes);
                if current_digest != existing_consent.scope_digest {
                    return Err(IdentityError::ConsentRequired);
                }
            }
        }

        // 5. PKCE enforcement (RFC 9700 §2.1.1 — unconditional for all clients)
        if request.code_challenge.is_none() {
            return Err(IdentityError::InvalidInput {
                reason: "PKCE is required (code_challenge with S256 must be supplied)".to_string(),
            });
        }
        // When a challenge is present, only S256 is permitted (plain is rejected per RFC 9700).
        if request.code_challenge.is_some()
            && !matches!(
                request.code_challenge_method,
                Some(CodeChallengeMethod::S256)
            )
        {
            return Err(IdentityError::InvalidInput {
                reason: "code_challenge requires code_challenge_method=S256".to_string(),
            });
        }
        // code_challenge_method without a challenge is an error
        if request.code_challenge.is_none() && request.code_challenge_method.is_some() {
            return Err(IdentityError::InvalidInput {
                reason: "code_challenge_method requires code_challenge to be present".to_string(),
            });
        }

        // 6. Generate cryptographically random authorization code (32 bytes)
        let rng = ring::rand::SystemRandom::new();
        let mut code_bytes = [0u8; 32];
        rng.fill(&mut code_bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "failed to generate random bytes for authorization code".to_string(),
            })?;
        let raw_code = URL_SAFE_NO_PAD.encode(code_bytes);

        // 7. Hash the code for storage
        let code_hash = Self::sha256_hex(raw_code.as_bytes());

        // 8. Build stored authorization code
        let now = self.clock.now();
        let ttl_micros = self.config.oidc.authorization_code_ttl_secs * 1_000_000;
        let expires_at = now.add_micros(ttl_micros);

        let stored_code = StoredAuthorizationCode {
            code_hash: code_hash.clone(),
            client_id: request.client_id.clone(),
            user_id: request.user_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            scope: request.scope.clone(),
            code_challenge: request.code_challenge.clone(),
            code_challenge_method: request.code_challenge_method.clone(),
            created_at: now,
            expires_at,
            nonce: request.nonce.clone(),
            resource: resource.as_ref().map(|r| r.as_str().to_string()),
            amr_values: request.amr_values.clone(),
            mfa_proof: code_proof,
        };

        // 9. Persist the code
        let code_key = keys::encode_oauth_code(&code_hash);
        let code_bytes =
            serde_json::to_vec(&stored_code).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &code_key, &code_bytes)
            .map_err(Self::storage_err)?;

        let issuer = self.config.oidc.issuer.clone();

        // 10. JARM — if a JWT response mode was requested OR the client enforces JARM,
        //     sign the response. When the client has `authorization_signed_response_alg`
        //     set, any plain response_mode is upgraded to query.jwt (JARM §4).
        //     The web layer's error redirects use the same rule.
        let response_mode = ResponseMode::effective(
            request.response_mode.as_ref(),
            client.authorization_signed_response_alg().is_some(),
        );
        if response_mode.is_jarm() {
            let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
            let now_secs = self.clock.now().as_micros() / 1_000_000;
            // FAPI 2.0 §5.3.2.3: include s_hash when state is non-empty.
            // s_hash = BASE64URL(LEFT(SHA-256(ASCII(state)), 16))
            let s_hash = if client.profile().is_fapi2() && !request.state.is_empty() {
                use data_encoding::BASE64URL_NOPAD;
                use ring::digest;
                let digest = digest::digest(&digest::SHA256, request.state.as_bytes());
                Some(BASE64URL_NOPAD.encode(&digest.as_ref()[..16]))
            } else {
                None
            };
            let jarm_claims = JarmClaims {
                iss: issuer.clone(),
                aud: request.client_id.to_string(),
                // FAPI 2.0 §5.3.2.2 requires JARM JWT lifetime ≤ 5 minutes.
                exp: now_secs + 300,
                iat: now_secs,
                jti: uuid::Uuid::new_v4().to_string(),
                code: raw_code.clone(),
                state: request.state.clone(),
                s_hash,
            };
            // JARM spec §4.1 requires typ=oauth-authz-resp+jwt (RFC 9101 §2).
            let jarm_jwt = signing_key.sign_jwt(&jarm_claims, "oauth-authz-resp+jwt")?;
            return Ok(AuthorizationResponse::new_jarm(
                raw_code,
                request.state.clone(),
                issuer,
                jarm_jwt,
                response_mode,
                // 22.3: the JAR-effective, registration-validated URI.
                request.redirect_uri.clone(),
            ));
        }

        // A plain mode is `query` or `fragment`. `fragment` is advertised in
        // discovery and accepted above, but the response used to be built as
        // `query` regardless, so the code always travelled in the query string.
        Ok(AuthorizationResponse::new(
            raw_code,
            request.state.clone(),
            issuer,
            // 22.3: the JAR-effective, registration-validated URI — never the
            // caller's outer `redirect_uri`, which a JAR may have overridden.
            request.redirect_uri.clone(),
        )
        .with_plain_response_mode(response_mode))
    }

    #[allow(clippy::too_many_lines)]
    #[tracing::instrument(
        level = "info",
        skip(self, request),
        fields(
            hearth_realm_id = %realm_id,
            hearth_oauth_client_id = %request.client_id,
            hearth_oauth_grant_type = "authorization_code",
        )
    )]
    pub(super) fn exchange_authorization_code_inner(
        &self,
        realm_id: &RealmId,
        request: &TokenExchangeRequest,
    ) -> Result<OidcTokenResponse, IdentityError> {
        // 1. Hash the incoming code to find it in storage
        let code_hash = Self::sha256_hex(request.code.as_bytes());
        let code_key = keys::encode_oauth_code(&code_hash);

        // 2. Acquire per-code advisory lock and load+consume under it.
        //
        // TOCTOU fix (OAUTH-06 / HEA-SEC-22): two concurrent requests with the same
        // code would both see the key present if we only relied on an unconditional
        // delete. The per-code lock serializes the get → delete window so the second
        // request finds the key absent after the first has consumed it.
        //
        // INVARIANT: outer map guard is released inside `code_exchange_lock()`;
        // the inner per-code guard is held only across this sync block (no .await).
        let stored_code: StoredAuthorizationCode = {
            let lock = self.code_exchange_lock(&code_hash);
            let _guard = lock.lock().expect("code_exchange_lock poisoned");

            let code_bytes = self
                .storage
                .get(realm_id, &code_key)
                .map_err(Self::storage_err)?
                .ok_or(IdentityError::InvalidAuthorizationCode)?;

            let code: StoredAuthorizationCode =
                serde_json::from_slice(&code_bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;

            // The single use is decided HERE, as the first write: one
            // replicated put-if-absent the Raft state machine evaluates (G4).
            // The delete below cannot decide it across nodes — a delete of an
            // absent key succeeds, so a redemption that read the code before
            // another node spent it, and wrote after leadership moved to its
            // own node, used to be served too. The lock above still queues
            // same-node racers so they do not each propose a Raft write.
            if !self.claim_single_use(
                realm_id,
                &keys::encode_consumed_code(&code_hash),
                code.expires_at,
            )? {
                return Err(IdentityError::InvalidAuthorizationCode);
            }

            // The code row itself goes too; its sweep would reclaim it anyway.
            self.storage
                .delete(realm_id, &code_key)
                .map_err(Self::storage_err)?;

            code
        }; // inner per-code lock released here

        // 4. Check expiration
        let now = self.clock.now();
        if now >= stored_code.expires_at {
            return Err(IdentityError::InvalidAuthorizationCode);
        }

        // 5. Verify client_id matches
        if stored_code.client_id != request.client_id {
            return Err(IdentityError::InvalidAuthorizationCode);
        }

        // 6. Verify redirect_uri matches
        if stored_code.redirect_uri != request.redirect_uri {
            return Err(IdentityError::InvalidAuthorizationCode);
        }

        // 6b. Authenticate the client if a private_key_jwt assertion was provided.
        // A request carrying EITHER assertion field attempted private_key_jwt: a
        // wrong or missing type, or a type with no assertion, is refused here
        // rather than read as "no assertion" (which let a secret-holding client
        // redeem its code with a junk assertion and no secret). If no assertion
        // is supplied, we must still block private_key_jwt-only clients
        // (those with an assertion_public_key but no client_secret_hash) from
        // silently bypassing client authentication.
        if let Some(assertion) = crate::identity::client_auth::presented_client_assertion(
            request.client_assertion_type.as_deref(),
            request.client_assertion.as_deref(),
        )? {
            self.verify_client_assertion(realm_id, &request.client_id, assertion)?;
        } else {
            // No assertion presented — reject if the client is registered for private_key_jwt
            // (has an assertion_public_key but no client_secret_hash). Such clients have no
            // other authentication channel and must present an assertion on every request.
            let client_key = keys::encode_oauth_client(&request.client_id);
            if let Some(client_bytes) = self
                .storage
                .get(realm_id, &client_key)
                .map_err(Self::storage_err)?
            {
                if let Ok(client) = serde_json::from_slice::<OAuthClient>(&client_bytes) {
                    if client.requires_client_assertion() {
                        return Err(IdentityError::InvalidClientAssertion {
                            reason: "client_assertion is required for private_key_jwt clients"
                                .to_string(),
                        });
                    }
                }
            }
        }

        // 7. Validate PKCE if code_challenge was present
        if let Some(ref challenge) = stored_code.code_challenge {
            let verifier = request
                .code_verifier
                .as_ref()
                .ok_or(IdentityError::InvalidGrant {
                    reason: "code_verifier is required when code_challenge was used".to_string(),
                })?;

            // Compute S256: BASE64URL(SHA256(code_verifier)) and compare in
            // constant time.
            if !Self::pkce_s256_verifier_matches(verifier, challenge) {
                return Err(IdentityError::InvalidGrant {
                    reason: "PKCE code_verifier does not match code_challenge".to_string(),
                });
            }
        }

        // 8. Resolve claims and validate size caps before consuming side effects.
        let user = self
            .get_user(realm_id, &stored_code.user_id)?
            .ok_or(IdentityError::UserNotFound)?;
        let client = self
            .get_client(realm_id, &request.client_id)?
            .ok_or(IdentityError::ClientNotFound)?;
        // B9: a code minted before the client was archived is not redeemable.
        Self::refuse_inactive_client(&client)?;
        // 8a. The grant may have been withdrawn since the code was issued
        //     (GA audit M7).
        if !client.allows_grant_type(crate::identity::oidc::GRANT_AUTHORIZATION_CODE) {
            return Err(IdentityError::UnsupportedGrantType);
        }

        // 8b. FAPI 2.0: DPoP sender-constrained tokens are mandatory.
        // Check both per-client profile flag AND realm-level fapi_profile so that
        // clients registered without `profile: fapi2` cannot bypass the realm gate.
        // Use `.is_some()` (not a variant match) so both Baseline and Advanced are
        // covered — FAPI 2.0 Baseline §5.3.3 requires sender-constrained tokens too.
        let realm_fapi = self
            .get_realm(realm_id)?
            .ok_or(IdentityError::RealmNotFound)?
            .config()
            .fapi_profile;
        let fapi_enforced = client.profile().is_fapi2() || realm_fapi.is_some();
        if fapi_enforced && request.dpop_jkt.is_none() {
            return Err(IdentityError::FapiViolation {
                reason: "FAPI 2.0 requires sender-constrained tokens; \
                         include a DPoP proof and dpop_jkt in the token request"
                    .to_string(),
            });
        }

        let scope_value = stored_code.scope.trim().to_string();
        // Every permission-bearing scope of the grant narrows — the rule the
        // refresh and device grants and live resolution apply too (GA audit 3
        // B-4). Only a single-scope grant used to be narrowed, so
        // `openid docs:read` resolved the user's full set.
        let grant_scopes: Vec<String> =
            scope_value.split_whitespace().map(str::to_string).collect();
        let resolved = self
            .rbac
            .resolve_for_granted_scopes(&stored_code.user_id, realm_id, None, &grant_scopes)
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
                    reason: format!("rbac resolve failed: {e}"),
                },
            })?;
        let granted_scopes: BTreeSet<String> = grant_scopes.into_iter().collect();

        // For non-Embedded modes, strip RBAC claims from the access token.
        use crate::identity::oidc::AccessTokenAuthorization;
        let authz_mode = client.access_token_authorization();
        let empty_resolved = crate::rbac::ResolvedPermissions::default();
        let access_resolved = if authz_mode == AccessTokenAuthorization::Embedded {
            &resolved
        } else {
            &empty_resolved
        };

        let (access_roles, access_groups, access_permissions, access_custom) = self
            .apply_claim_profile(
                realm_id,
                &user,
                &client,
                access_resolved,
                &granted_scopes,
                None,
                ClaimTarget::AccessToken,
            );
        validate_claim_payload(
            ClaimTarget::AccessToken,
            &access_roles,
            &access_groups,
            &access_permissions,
        )?;
        let (id_roles, id_groups, id_permissions, id_custom) = self.apply_claim_profile(
            realm_id,
            &user,
            &client,
            &resolved,
            &granted_scopes,
            None,
            ClaimTarget::IdToken,
        );
        validate_claim_payload(ClaimTarget::IdToken, &id_roles, &id_groups, &id_permissions)?;

        // 8c. Pre-token enrichment webhook: fire before signing, merge extra claims
        //     into the access token's custom map.
        let webhook_extra = self.fire_pre_token_webhook(
            realm_id,
            &stored_code.user_id.to_string(),
            &request.client_id.to_string(),
            "authorization_code",
            (!scope_value.is_empty()).then_some(scope_value.as_str()),
            None, // session created below — not yet available
            &access_roles,
            &access_groups,
            &access_permissions,
            &access_custom,
        )?;
        let mut access_custom =
            crate::identity::pre_token_webhook::merge_extra_claims(access_custom, webhook_extra);
        // RFC 9068 §2.2: name the client this token is issued to, so a
        // resource (the admin API, userinfo) can tell a third-party client's
        // token from a first-party one (GA audit B1).
        TokenClaims::insert_client_id(&mut access_custom, &request.client_id);

        // 9. (Code already consumed atomically in step 3 — no further write needed.)

        // 9b. Resolve the key this client's ID token is signed with — Ed25519,
        //     or the realm's RSA key for a client that registered RS256 (task
        //     26.55) — before any side effect, so a key failure refuses the
        //     grant rather than leaving a session behind it.
        let signing_key = self.get_signing_key_or_default(realm_id);
        let id_token_signer =
            self.id_token_signer(realm_id, Some(&client), std::sync::Arc::clone(&signing_key))?;

        // 10. Create a session for the user (OAuth code exchange — no browser context).
        //     A derived session: an authorization code is minted only for a
        //     principal holding a live session — the browser `/authorize`
        //     requires a UI session, and the non-interactive surfaces (JSON and
        //     gRPC `Authorize`) require a bearer token that `validate_token`
        //     accepts only while its session is still active — and that
        //     session cleared the realm's second-factor gates when it was
        //     created (GA audit B2), so a realm that turns `mfa_required` on is
        //     enforced from each session's next sign-in. The token session
        //     records the proof the authorizing session made, which the code
        //     carries; it used to record `Inherited`, which every later gate
        //     read as a proved factor (GA audit round 3, D-7).
        let session =
            self.create_derived_session(realm_id, &stored_code.user_id, stored_code.mfa_proof)?;

        // 11. Create grant family for refresh token rotation
        let family_id = uuid::Uuid::new_v4().to_string();

        // 12. Issue tokens with family ID. Access and refresh tokens are always
        //     Ed25519, whatever the client's ID-token algorithm.
        let iat = now.as_micros() / 1_000_000;

        // Apply per-realm token TTL overrides.
        let (access_ttl_secs, refresh_ttl_secs) = self.effective_token_ttl_secs(realm_id);

        let resource_uri = stored_code
            .resource
            .as_ref()
            .map(|s| {
                Uri::try_from(s.clone()).map_err(|e| IdentityError::InvalidGrant {
                    reason: format!("authorization code has invalid resource URI: {e}"),
                })
            })
            .transpose()?;
        let aud = match &resource_uri {
            Some(r) => Audience::with_resource(self.config.token.audience.clone(), r),
            None => Audience::single(self.config.token.audience.clone()),
        };

        let sv_claim = {
            let enabled = self
                .get_realm(realm_id)
                .ok()
                .flatten()
                .map(|r| r.config().session_version.enabled)
                .unwrap_or(false);
            if enabled {
                Some(self.get_session_sv(realm_id, session.id()))
            } else {
                None
            }
        };
        let access_claims = TokenClaims {
            sub: stored_code.user_id.to_string(),
            iss: self.realm_issuer_url(realm_id),
            aud: aud.clone(),
            exp: iat + access_ttl_secs,
            iat,
            nbf: None,
            sid: session.id().to_string(),
            tid: realm_id.to_string(),
            oid: None,
            token_type: "access".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: Some(family_id.clone()),
            scope: (!scope_value.is_empty()).then(|| scope_value.clone()),
            nonce: None,
            azp: None,
            roles: access_roles,
            groups: access_groups,
            org_groups: Vec::new(),
            permissions: access_permissions,
            act: None,
            amr: stored_code.amr_values.clone(),
            cnf: request
                .dpop_jkt
                .as_deref()
                .map(|jkt| crate::identity::tokens::CnfClaim {
                    jkt: jkt.to_string(),
                }),
            custom: access_custom,
            sv: sv_claim,
        };
        let refresh_claims = TokenClaims {
            sub: stored_code.user_id.to_string(),
            iss: self.realm_issuer_url(realm_id),
            aud,
            exp: iat + refresh_ttl_secs,
            iat,
            nbf: None,
            sid: session.id().to_string(),
            tid: realm_id.to_string(),
            oid: None,
            token_type: "refresh".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: Some(family_id.clone()),
            scope: (!scope_value.is_empty()).then(|| scope_value.clone()),
            nonce: None,
            azp: None,
            roles: access_claims.roles.clone(),
            groups: access_claims.groups.clone(),
            org_groups: Vec::new(),
            permissions: access_claims.permissions.clone(),
            act: None,
            amr: Vec::new(),
            // M1 (RFC 9449 §5): bind refresh token to the DPoP key presented at exchange.
            cnf: request
                .dpop_jkt
                .as_deref()
                .map(|jkt| crate::identity::tokens::CnfClaim {
                    jkt: jkt.to_string(),
                }),
            custom: access_claims.custom.clone(),
            sv: None,
        };

        let access_token =
            signing_key
                .issue_token(&access_claims)
                .map_err(|e| IdentityError::SigningError {
                    reason: format!("failed to issue access token: {e}"),
                })?;
        let refresh_token =
            signing_key
                .issue_token(&refresh_claims)
                .map_err(|e| IdentityError::SigningError {
                    reason: format!("failed to issue refresh token: {e}"),
                })?;

        // 12. Store grant family with refresh token hash
        let refresh_hash = Self::sha256_hex(refresh_token.as_bytes());
        let family = StoredGrantFamily {
            family_id: family_id.clone(),
            current_refresh_hash: refresh_hash,
            session_id: session.id().clone(),
            realm_id: realm_id.clone(),
            revoked: false,
            created_at: now,
            expires_at: crate::core::Timestamp::from_micros(
                now.as_micros() + refresh_ttl_secs * 1_000_000,
            ),
            client_id: Some(request.client_id.clone()),
            resources: resource_uri.iter().cloned().collect(),
            amr_values: stored_code.amr_values.clone(),
            // UA/ASN binding context (A-49) recorded on first refresh exchange.
            ua_hash: None,
            bound_asn: None,
            // M1 (RFC 9449 §5): persist the DPoP key thumbprint for sender-constraint enforcement.
            bound_jkt: request.dpop_jkt.clone(),
        };
        let family_bytes =
            serde_json::to_vec(&family).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let family_key = keys::encode_grant_family(&family_id);
        self.storage
            .put(realm_id, &family_key, &family_bytes)
            .map_err(Self::storage_err)?;
        // Index session → family for cascade revocation on session termination.
        let sfam_key = keys::encode_session_grant_family(&family.session_id, &family_id);
        self.storage
            .put(realm_id, &sfam_key, &[])
            .map_err(Self::storage_err)?;

        // 13. Issue ID token (OIDC-specific, nonce echoed per OIDC Core §2)
        // iss MUST match the discovery document's issuer (OIDC Core §2)
        let id_token_claims = TokenClaims {
            sub: stored_code.user_id.to_string(),
            iss: self.config.oidc.issuer.clone(),
            aud: Audience::single(request.client_id.to_string()),
            exp: iat + access_ttl_secs,
            iat,
            nbf: None,
            sid: session.id().to_string(),
            tid: realm_id.to_string(),
            oid: None,
            token_type: "id_token".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: None,
            scope: (!scope_value.is_empty()).then(|| scope_value.clone()),
            nonce: stored_code.nonce.clone(),
            azp: Some(request.client_id.to_string()),
            roles: id_roles,
            groups: id_groups,
            org_groups: Vec::new(),
            permissions: id_permissions,
            act: None,
            amr: stored_code.amr_values.clone(),
            cnf: None,
            custom: id_custom,
            sv: None,
        };
        let id_token =
            id_token_signer
                .sign(&id_token_claims)
                .map_err(|e| IdentityError::SigningError {
                    reason: format!("failed to issue ID token: {e}"),
                })?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::AuthorizationCodeExchanged,
            "authz_code",
            &request.code,
        )?;

        // A client not registered for the refresh-token grant receives no
        // refresh token (GA audit M7). The grant family is still written: it
        // records who owns the access token for revocation and session
        // cascade, and the hash it stores matches a token nobody holds.
        let refresh_token = if client.allows_refresh_token() {
            refresh_token
        } else {
            String::new()
        };

        Ok(OidcTokenResponse::new(
            access_token,
            id_token,
            "Bearer".to_string(),
            access_ttl_secs,
            refresh_token,
        ))
    }

    pub(super) fn oidc_discovery_inner(&self) -> OidcDiscoveryDocument {
        self.build_discovery_document(&self.config.oidc.issuer.clone(), None)
    }

    pub(super) fn realm_oidc_discovery_inner(
        &self,
        realm_id: &RealmId,
    ) -> Result<OidcDiscoveryDocument, IdentityError> {
        let realm = self
            .get_realm(realm_id)?
            .ok_or(IdentityError::RealmNotFound)?;
        let issuer = format!("{}/realms/{}", self.config.oidc.issuer, realm.name());
        Ok(self.build_discovery_document(&issuer, Some(realm.config())))
    }

    // ===== OAuth 2.0 Extended (Step 22) =====

    pub(super) fn password_grant_token_inner(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::PasswordGrantRequest,
    ) -> Result<crate::identity::oidc::PasswordGrantResponse, IdentityError> {
        // 1. Look up user by email (timing-safe: dummy-hash on miss). The
        //    dummy verify runs under the REALM's Argon2 parameters: the global
        //    dummy is cheaper than a realm with a raised cost, so an unknown
        //    address answered measurably faster (GA audit L14).
        let user = match self.get_user_by_email(realm_id, &request.email)? {
            Some(u) => u,
            None => {
                let dummy_pw = CleartextPassword::from_string(request.password.clone());
                self.dummy_verify_for_realm(realm_id, &dummy_pw);
                return Err(IdentityError::InvalidCredential {
                    reason: "verification failed".to_string(),
                });
            }
        };

        // 2. Verify password (also enforces per-account rate limiting)
        let pw = CleartextPassword::from_string(request.password.clone());
        let matches = self.verify_password(realm_id, user.id(), &pw)?;
        if !matches {
            return Err(IdentityError::InvalidCredential {
                reason: "verification failed".to_string(),
            });
        }

        // 3a. Block token issuance when required actions are pending (HEA-905).
        //     Checked after password verification so the error is only reachable
        //     by a caller who knows the password — no enumeration risk.
        if !user.required_actions().is_empty() {
            return Err(IdentityError::RequiredActionsBlocking {
                actions: user.required_actions().to_vec(),
            });
        }

        // 3a-bis. Realm-wide `mfa_required` (audit 2026-08-28 §4.18#3).
        //    ROPC proves the password and nothing else, so it can never satisfy
        //    a second-factor policy on its own. Send the caller to the step-up
        //    MFA grant when a factor exists, and to enrolment when none does.
        //    Without this the request would reach `create_session` and fail with
        //    a bare `MfaRequired`, which tells the client nothing about what to
        //    do next.
        if self
            .get_realm(realm_id)?
            .is_some_and(|r| r.config().mfa_required.unwrap_or(false))
        {
            return if self.has_second_factor(realm_id, user.id())? {
                Err(IdentityError::StepUpChallengeRequired)
            } else {
                Err(IdentityError::EnrollMfaRequired)
            };
        }

        // 3b. Adaptive step-up MFA check (HEA-836).
        //    Only runs when the request carries IP/UA context (ROPC via HTTP).
        if let (Some(ip), Some(ua)) = (&request.client_ip, &request.user_agent) {
            use crate::identity::device_fp::DeviceFingerprintOutcome;
            use crate::identity::types::RequiredAction;

            let outcome = self.check_device_fingerprint(realm_id, user.id(), ip, ua)?;

            match outcome {
                DeviceFingerprintOutcome::Skipped | DeviceFingerprintOutcome::Recognised => {
                    // Device is trusted or feature disabled — proceed normally.
                    // check_and_refresh already refreshed the TTL on a recognised hit;
                    // step-5 below handles recording on a first-seen device path.
                }
                DeviceFingerprintOutcome::StepUpRequired => {
                    // User has an enrolled factor — require MFA challenge.
                    return Err(IdentityError::StepUpChallengeRequired);
                }
                DeviceFingerprintOutcome::EnrollMfaRequired => {
                    // No factor enrolled — inject EnrollMfa required action via
                    // update_user() so the write goes through the full audit +
                    // validation pipeline and avoids a TOCTOU race on storage.put().
                    let current_user = self
                        .get_user(realm_id, user.id())?
                        .ok_or(IdentityError::UserNotFound)?;
                    let actions: Vec<RequiredAction> = current_user.required_actions().to_vec();
                    if !actions.contains(&RequiredAction::EnrollMfa) {
                        let mut new_actions = actions;
                        new_actions.push(RequiredAction::EnrollMfa);
                        self.update_user(
                            realm_id,
                            user.id(),
                            &UpdateUserRequest {
                                required_actions: Some(new_actions),
                                ..Default::default()
                            },
                        )?;
                    }
                    return Err(IdentityError::EnrollMfaRequired);
                }
            }
        }

        // 3c. A second factor the user holds binds here too (GA audit B4/B5).
        //     A recognised device is not a second factor: the fingerprint is an
        //     HMAC of the client's network and user agent, both of which the
        //     caller supplies. So a user who holds a factor is sent to the
        //     step-up grant, which proves it; the engine's session gate would
        //     refuse the unproved session anyway, with an error that tells the
        //     client nothing about what to do next.
        if self.has_second_factor(realm_id, user.id())? {
            return Err(IdentityError::StepUpChallengeRequired);
        }

        // 4. Create session and issue token pair. Steps 3a-bis and 3c have
        //    refused every user who owes a second factor, so the default
        //    (unproven) context is correct here.
        let session = self.create_session(
            realm_id,
            user.id(),
            &crate::identity::SessionContext::default(),
        )?;
        let token_pair = self.issue_tokens(realm_id, user.id(), session.id())?;

        // 5. Record device fingerprint on first successful login from this device.
        if let (Some(ip), Some(ua)) = (&request.client_ip, &request.user_agent) {
            let _ = self.record_device_fingerprint(realm_id, user.id(), ip, ua);
        }

        Ok(crate::identity::oidc::PasswordGrantResponse {
            access_token: token_pair.access_token().to_string(),
            refresh_token: token_pair.refresh_token().to_string(),
            token_type: "Bearer".to_string(),
            expires_in: self.config.token.access_token_ttl_secs,
        })
    }

    pub(super) fn step_up_mfa_grant_token_inner(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::StepUpMfaGrantRequest,
    ) -> Result<crate::identity::oidc::PasswordGrantResponse, IdentityError> {
        // 1. Look up user by email (timing-safe: dummy-hash on miss). The
        //    dummy verify runs under the REALM's Argon2 parameters: the global
        //    dummy is cheaper than a realm with a raised cost, so an unknown
        //    address answered measurably faster (GA audit L14).
        let user = match self.get_user_by_email(realm_id, &request.email)? {
            Some(u) => u,
            None => {
                let dummy_pw = CleartextPassword::from_string(request.password.clone());
                self.dummy_verify_for_realm(realm_id, &dummy_pw);
                return Err(IdentityError::InvalidCredential {
                    reason: "verification failed".to_string(),
                });
            }
        };

        // 2. Re-verify password to prevent session fixation.
        let pw = CleartextPassword::from_string(request.password.clone());
        let matches = self.verify_password(realm_id, user.id(), &pw)?;
        if !matches {
            return Err(IdentityError::InvalidCredential {
                reason: "verification failed".to_string(),
            });
        }

        // 3. Verify MFA code (TOTP first; fall through to recovery code on mismatch).
        let mfa_result = match self.verify_totp(realm_id, user.id(), &request.mfa_code) {
            Ok(()) => Ok(()),
            Err(IdentityError::InvalidMfaCode) => {
                // TOTP code didn't match — try as a recovery code.
                self.verify_recovery_code(realm_id, user.id(), &request.mfa_code)
            }
            Err(e) => return Err(e),
        };
        if let Err(e) = mfa_result {
            // MFA failure counts as a login failure for IP-level rate limiting.
            if let Some(ip) = &request.client_ip {
                self.record_ip_login_attempt(realm_id, ip);
            }
            return Err(e);
        }

        // 3a. Pending required actions block token issuance, exactly as they
        //     do for the password grant (HEA-905). This grant skipped them, so
        //     an operator-forced password change or enrolment could be walked
        //     around by asking for tokens here (GA audit M11). Checked after
        //     both factors, so only a caller who holds them learns of it.
        if !user.required_actions().is_empty() {
            return Err(IdentityError::RequiredActionsBlocking {
                actions: user.required_actions().to_vec(),
            });
        }

        // 4. Create session and issue token pair. Step 3 verified a TOTP or a
        //    recovery code, so this ceremony proved a second factor. The
        //    client address feeds the realm's `cidr_policy` (GA audit M13).
        let session = self.create_session(
            realm_id,
            user.id(),
            &crate::identity::SessionContext {
                mfa_proof: crate::identity::MfaProof::Proved,
                ip_address: request.client_ip.clone(),
                user_agent_raw: request.user_agent.clone(),
                ..Default::default()
            },
        )?;
        let token_pair = self.issue_tokens(realm_id, user.id(), session.id())?;

        // 5. Record device fingerprint — this device is now trusted.
        if let (Some(ip), Some(ua)) = (&request.client_ip, &request.user_agent) {
            let _ = self.record_device_fingerprint(realm_id, user.id(), ip, ua);
        }

        // 6. Emit StepUpMfaCompleted so incident responders can correlate trigger → resolution.
        let audit_ctx = AuditContext {
            actor: Actor::User(user.id().clone()),
            metadata: Some(serde_json::json!({
                "user_id": user.id().as_uuid().to_string()
            })),
        };
        if let Err(e) = self.record_audit(
            realm_id,
            Some(&audit_ctx),
            AuditAction::StepUpMfaCompleted,
            "user",
            &user.id().as_uuid().to_string(),
        ) {
            tracing::warn!(error = %e, "StepUpMfaCompleted audit write failed — event lost");
        }

        Ok(crate::identity::oidc::PasswordGrantResponse {
            access_token: token_pair.access_token().to_string(),
            refresh_token: token_pair.refresh_token().to_string(),
            token_type: "Bearer".to_string(),
            expires_in: self.config.token.access_token_ttl_secs,
        })
    }

    #[tracing::instrument(
        level = "info",
        skip(self, request),
        fields(
            hearth_realm_id = %realm_id,
            hearth_oauth_client_id = %request.client_id,
            hearth_oauth_grant_type = "client_credentials",
        )
    )]
    pub(super) fn client_credentials_token_inner(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::ClientCredentialsRequest,
    ) -> Result<crate::identity::oidc::ClientCredentialsResponse, IdentityError> {
        // 1. Load the client — absence is not reported yet.
        let client_key = keys::encode_oauth_client(&request.client_id);
        let existing: Option<OAuthClient> = self
            .storage
            .get(realm_id, &client_key)
            .map_err(Self::storage_err)?
            .map(|bytes| {
                serde_json::from_slice::<OAuthClient>(&bytes).map_err(|e| {
                    IdentityError::Serialization {
                        reason: e.to_string(),
                    }
                })
            })
            .transpose()?;

        // 2. Authenticate the client BEFORE saying anything about it. An
        // unknown client and a client without this grant used to be refused
        // (`InvalidClient`, `UnsupportedGrantType`) before any secret check,
        // which told an unauthenticated caller whether a client id exists and
        // which grants it has. Every arm now does the same work — one
        // verification of the presented secret, against a dummy when there is
        // no stored hash (22.25) — and gets one answer until it proves the
        // secret. A presented assertion field means private_key_jwt: it is
        // verified — or, malformed, refused — and never falls through to the
        // secret check.
        if let Some(assertion) = crate::identity::client_auth::presented_client_assertion(
            request.client_assertion_type.as_deref(),
            request.client_assertion.as_deref(),
        )? {
            self.verify_client_assertion(realm_id, &request.client_id, assertion)?;
        } else {
            self.refuse_secrets_in_fapi_advanced_realm(realm_id)?;
            let secret = request
                .client_secret
                .as_deref()
                .ok_or(IdentityError::InvalidClientSecret)?;
            let stored_hash = existing.as_ref().and_then(OAuthClient::client_secret_hash);
            if !Self::verify_presented_client_secret(stored_hash, secret)? {
                return Err(IdentityError::InvalidClientSecret);
            }
            if let Some(client) = existing.as_ref() {
                Self::refuse_secret_for_fapi2_client(client)?;
            }
        }
        // A verified assertion or secret implies the client exists; the check
        // stays for the type system and costs nothing.
        let Some(client) = existing else {
            return Err(IdentityError::InvalidClientSecret);
        };
        // B9: an archived client's credentials authenticate nothing; refused
        // with the same answer as a wrong secret.
        if Self::refuse_inactive_client(&client).is_err() {
            return Err(IdentityError::InvalidClientSecret);
        }

        // 3. Only an authenticated client learns that it lacks the grant.
        if !client
            .grant_types()
            .contains(&"client_credentials".to_string())
        {
            return Err(IdentityError::UnsupportedGrantType);
        }

        self.validate_client_scope_request(&client, request.scope.as_deref().unwrap_or(""))?;

        // 3b. FAPI enforcement: realm-level AND per-client profile both gate DPoP (A-38).
        {
            let realm_fapi = self
                .get_realm(realm_id)?
                .ok_or(IdentityError::RealmNotFound)?
                .config()
                .fapi_profile;
            let fapi_enforced = client.profile().is_fapi2() || realm_fapi.is_some();
            if fapi_enforced && request.dpop_jkt.is_none() {
                return Err(IdentityError::FapiViolation {
                    reason: "FAPI 2.0 requires sender-constrained tokens; \
                             include a DPoP proof and dpop_jkt in the token request"
                        .to_string(),
                });
            }
        }

        // 4. Issue access token (no session, no refresh token per RFC 6749 §4.4.3)
        let now = self.clock.now();
        let iat = now.as_micros() / 1_000_000;
        let signing_key = self.get_or_load_realm_signing_key(realm_id)?;

        let scope = request.scope.clone();
        let access_claims = TokenClaims {
            sub: request.client_id.to_string(),
            iss: self.realm_issuer_url(realm_id),
            aud: Audience::single(self.config.token.audience.clone()),
            exp: iat + self.config.token.access_token_ttl_secs,
            iat,
            nbf: None,
            sid: "none".to_string(), // No session for client credentials
            tid: realm_id.to_string(),
            oid: None,
            token_type: "access".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: None,
            scope: scope.clone(),
            nonce: None,
            azp: None,
            roles: Vec::new(),
            groups: Vec::new(),
            org_groups: Vec::new(),
            permissions: Vec::new(),
            act: None,
            amr: Vec::new(),
            cnf: request
                .dpop_jkt
                .as_deref()
                .map(|jkt| crate::identity::tokens::CnfClaim {
                    jkt: jkt.to_string(),
                }),
            custom: std::collections::BTreeMap::new(),
            sv: None, // sessionless — no sv
        };

        let access_token =
            signing_key
                .issue_token(&access_claims)
                .map_err(|e| IdentityError::SigningError {
                    reason: format!("failed to issue access token: {e}"),
                })?;

        Ok(crate::identity::oidc::ClientCredentialsResponse::new(
            access_token,
            "Bearer".to_string(),
            self.config.token.access_token_ttl_secs,
            scope,
        ))
    }

    #[tracing::instrument(
        level = "info",
        skip(self, request),
        fields(
            hearth_realm_id = %realm_id,
            hearth_oauth_client_id = %request.client_id,
            hearth_oauth_grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer",
        )
    )]
    pub(super) fn jwt_bearer_token_inner(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::JwtBearerRequest,
    ) -> Result<crate::identity::oidc::ClientCredentialsResponse, IdentityError> {
        // 1. Load client
        let client_key = keys::encode_oauth_client(&request.client_id);
        let client_bytes = self
            .storage
            .get(realm_id, &client_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidClient)?;
        let client: OAuthClient =
            serde_json::from_slice(&client_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        Self::refuse_inactive_client(&client)?;

        // 2. Verify grant type is allowed for this client
        if !client
            .grant_types()
            .contains(&"urn:ietf:params:oauth:grant-type:jwt-bearer".to_string())
        {
            return Err(IdentityError::UnsupportedGrantType);
        }

        // 3. Resolve the registered assertion public key (base64url raw 32-byte Ed25519)
        let pk_b64 = client.assertion_public_key().ok_or_else(|| {
            IdentityError::JwtBearerAssertionInvalid {
                reason: "no assertion public key registered for this client".to_string(),
            }
        })?;
        let pk_bytes = URL_SAFE_NO_PAD.decode(pk_b64).map_err(|_| {
            IdentityError::JwtBearerAssertionInvalid {
                reason: "client has an invalid assertion public key".to_string(),
            }
        })?;

        // 4. Verify assertion JWT signature (EdDSA only, rejects alg:none, HMAC, etc.)
        let assertion_claims = tokens::verify_assertion_signature(&request.assertion, &pk_bytes)
            .map_err(|_| IdentityError::JwtBearerAssertionInvalid {
                reason: "assertion signature verification failed".to_string(),
            })?;

        // 5. Validate RFC 7523 §3 required claims
        let now = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;

        // iss MUST equal the client_id (RFC 7523 §3 requirement)
        if assertion_claims.iss != issued_client_id(&request.client_id) {
            return Err(IdentityError::JwtBearerAssertionInvalid {
                reason: "iss claim must equal the client_id".to_string(),
            });
        }

        // sub MUST equal client_id (RFC 7523 §3 / OIDC Core §9)
        if assertion_claims.sub != issued_client_id(&request.client_id) {
            return Err(IdentityError::JwtBearerAssertionInvalid {
                reason: "sub claim must equal the client_id".to_string(),
            });
        }

        // exp MUST be in the future
        if now_secs >= assertion_claims.exp {
            return Err(IdentityError::JwtBearerAssertionInvalid {
                reason: "assertion has expired".to_string(),
            });
        }

        // exp MUST NOT be more than 10 minutes in the future.
        // Unbounded lifetimes defeat replay protection when jti recycling windows are large.
        const MAX_ASSERTION_LIFETIME_SECS: i64 = 600;
        if assertion_claims.exp - now_secs > MAX_ASSERTION_LIFETIME_SECS {
            return Err(IdentityError::JwtBearerAssertionInvalid {
                reason: "assertion lifetime exceeds maximum allowed duration".to_string(),
            });
        }

        // aud MUST contain this realm's issuer URL (the token endpoint base)
        let expected_aud = self.realm_issuer_url(realm_id);
        if !assertion_claims.aud.contains(&expected_aud) {
            return Err(IdentityError::JwtBearerAssertionInvalid {
                reason: "aud claim does not match the token endpoint issuer".to_string(),
            });
        }

        // 6. jti is mandatory — without it any intercepted assertion is replayable
        // for its full validity window.
        let jti = assertion_claims.jti.as_ref().ok_or_else(|| {
            IdentityError::JwtBearerAssertionInvalid {
                reason: "jti claim is required".to_string(),
            }
        })?;

        // 6b. Atomic JTI check-and-consume with exp-bounded lazy expiry (HIGH-1/CRIT-2)
        self.check_and_consume_jwt_bearer_jti(realm_id, jti, assertion_claims.exp)?;

        // 7. Validate requested scope against the client's declared scopes
        self.validate_client_scope_request(&client, request.scope.as_deref().unwrap_or(""))?;

        // 8. Issue sessionless access token (same pattern as client_credentials)
        let iat = now_secs;
        let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
        let scope = request.scope.clone();
        let access_claims = TokenClaims {
            // Hearth's own subject form for a client, as client_credentials
            // mints it — not the assertion's `sub`, which is the issued
            // client_id (the bare UUID).
            sub: request.client_id.to_string(),
            iss: self.realm_issuer_url(realm_id),
            aud: Audience::single(self.config.token.audience.clone()),
            exp: iat + self.config.token.access_token_ttl_secs,
            iat,
            nbf: None,
            sid: "none".to_string(),
            tid: realm_id.to_string(),
            oid: None,
            token_type: "access".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: None,
            scope: scope.clone(),
            nonce: None,
            azp: None,
            roles: Vec::new(),
            groups: Vec::new(),
            org_groups: Vec::new(),
            permissions: Vec::new(),
            act: None,
            amr: vec!["jwtbearer".to_string()],
            cnf: request
                .dpop_jkt
                .as_deref()
                .map(|jkt| crate::identity::tokens::CnfClaim {
                    jkt: jkt.to_string(),
                }),
            custom: std::collections::BTreeMap::new(),
            sv: None, // JWT bearer — sessionless
        };

        let access_token =
            signing_key
                .issue_token(&access_claims)
                .map_err(|e| IdentityError::SigningError {
                    reason: format!("failed to issue access token: {e}"),
                })?;

        Ok(crate::identity::oidc::ClientCredentialsResponse::new(
            access_token,
            "Bearer".to_string(),
            self.config.token.access_token_ttl_secs,
            scope,
        ))
    }

    /// Verifies a `private_key_jwt` client assertion per RFC 7523 §2.2.
    ///
    /// Validates signature, `iss == client_id`, `sub == client_id`, `exp`, `aud`,
    /// and JTI replay protection. Returns `Ok(())` on success; returns
    /// `InvalidClientAssertion` on any failure so callers cannot distinguish
    /// individual check failures (enumeration resistance).
    pub(super) fn verify_client_assertion_inner(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        assertion: &str,
    ) -> Result<(), IdentityError> {
        // Load client to retrieve the registered public key.
        let client_key = keys::encode_oauth_client(client_id);
        let client_bytes = self
            .storage
            .get(realm_id, &client_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidClient)?;
        let client: OAuthClient =
            serde_json::from_slice(&client_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        Self::refuse_inactive_client(&client)?;

        let claims = Self::verify_client_assertion_signature(&client, assertion)?;

        // iss MUST equal client_id (RFC 7523 §3)
        if claims.iss != issued_client_id(client_id) {
            return Err(IdentityError::InvalidClientAssertion {
                reason: "iss claim must equal the client_id".to_string(),
            });
        }

        // sub MUST equal client_id (RFC 7523 §3 / OIDC Core §9)
        if claims.sub != issued_client_id(client_id) {
            return Err(IdentityError::InvalidClientAssertion {
                reason: "sub claim must equal the client_id".to_string(),
            });
        }

        // exp MUST be in the future
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        if now_secs >= claims.exp {
            return Err(IdentityError::InvalidClientAssertion {
                reason: "assertion has expired".to_string(),
            });
        }

        // exp MUST NOT be more than 5 minutes in the future (FAPI / RFC 7523 best practice).
        // Unbounded lifetimes defeat replay protection when jti is absent.
        const MAX_ASSERTION_LIFETIME_SECS: i64 = 300;
        if claims.exp - now_secs > MAX_ASSERTION_LIFETIME_SECS {
            return Err(IdentityError::InvalidClientAssertion {
                reason: "assertion lifetime exceeds 5 minutes".to_string(),
            });
        }

        // aud MUST name this realm's issuer. Under FAPI 2.0 — a FAPI 2.0
        // client, or any client of a realm with a `fapi_profile` — it must BE
        // the issuer, as a single string (FAPI 2.0 Security Profile
        // §5.3.2.1); elsewhere RFC 7523 §3 lets the issuer be one value of an
        // array.
        let expected_aud = self.realm_issuer_url(realm_id);
        let aud_ok = match &claims.aud {
            crate::identity::tokens::Audience::Single(aud) => *aud == expected_aud,
            multi @ crate::identity::tokens::Audience::Multi(_) => {
                !(client.profile().is_fapi2() || self.realm_enforces_fapi(realm_id)?)
                    && multi.contains(&expected_aud)
            }
        };
        if !aud_ok {
            return Err(IdentityError::InvalidClientAssertion {
                reason: "aud claim does not match the token endpoint issuer".to_string(),
            });
        }

        // jti MUST be present — RFC 7523 §3 SHOULD, upgraded to MUST here for replay
        // prevention. Without jti, any intercepted assertion is replayable for its full
        // validity window.
        let jti = claims
            .jti
            .as_ref()
            .ok_or_else(|| IdentityError::InvalidClientAssertion {
                reason: "jti claim is required for private_key_jwt assertions".to_string(),
            })?;

        // JTI replay protection — each JTI may only be used once per realm.
        //
        // The marker stores the instant after which the assertion can no
        // longer verify anywhere (`exp` + clock skew, 8-byte LE i64 Unix
        // seconds) so `cleanup::sweep_client_assertion_jtis` can reclaim it,
        // exactly like the JAR, DPoP and nonce sentinels. This runs once per
        // assertion-authenticated request at `/token`, `/introspect` and
        // `/revoke`; a marker with no expiry leaked one row per request for
        // the life of the realm. `exp` is already capped at
        // `MAX_ASSERTION_LIFETIME_SECS` above, so no marker outlives
        // now + 5 min + skew.
        //
        // `put_if_absent` is atomic (Raft-routed in cluster mode), so two
        // concurrent presentations of one assertion cannot both pass. Any
        // existing marker refuses — including one past its expiry that the
        // sweep has not reached yet, which only ever refuses a *new*
        // assertion reusing an old `jti`.
        let jti_key = keys::encode_client_assertion_jti(jti);
        let marker_expires_at = claims.exp.saturating_add(CLOCK_SKEW_SECS);
        let fresh = self
            .storage
            .put_if_absent(realm_id, &jti_key, &marker_expires_at.to_le_bytes())
            .map_err(Self::storage_err)?;
        if !fresh {
            return Err(IdentityError::InvalidClientAssertion {
                reason: "assertion jti has already been used (replay)".to_string(),
            });
        }

        Ok(())
    }

    /// Verifies a `private_key_jwt` assertion's signature with the keys the
    /// client registered and returns its claims (not yet validated).
    ///
    /// Two key sources, tried in order:
    ///
    /// 1. the dedicated `assertion_public_key` (raw Ed25519, `alg` EdDSA);
    /// 2. the client's registered `jwks` — the keys FAPI 2.0 registration
    ///    requires — with the key chosen by the JWS `kid` (or the only key) and
    ///    `alg` one of PS256, ES256, EdDSA (FAPI 2.0 Security Profile §5.4).
    ///
    /// A client registered with only a `jwks_uri` cannot be verified: Hearth
    /// does not fetch client key sets, so such a client must register its keys
    /// inline.
    fn verify_client_assertion_signature(
        client: &OAuthClient,
        assertion: &str,
    ) -> Result<crate::identity::tokens::JwtAssertionClaims, IdentityError> {
        let refused = |reason: &str| IdentityError::InvalidClientAssertion {
            reason: reason.to_string(),
        };
        if client.assertion_public_key().is_none() && client.jwks().is_none() {
            return Err(refused(if client.jwks_uri().is_some() {
                "the client registered only a jwks_uri, which is not fetched; register its keys \
                 inline as jwks"
            } else {
                "no assertion public key or jwks registered for this client"
            }));
        }

        if let Some(pk_b64) = client.assertion_public_key() {
            let pk_bytes = URL_SAFE_NO_PAD
                .decode(pk_b64)
                .map_err(|_| refused("client has an invalid assertion public key"))?;
            // EdDSA only — rejects alg:none, HMAC, RSA, etc.
            if let Ok(claims) = tokens::verify_assertion_signature(assertion, &pk_bytes) {
                return Ok(claims);
            }
            if client.jwks().is_none() {
                return Err(refused("assertion signature verification failed"));
            }
        }

        let Some(jwks) = client.jwks() else {
            return Err(refused("assertion signature verification failed"));
        };
        #[derive(serde::Deserialize)]
        struct AssertionHeader {
            alg: String,
            #[serde(default)]
            kid: Option<String>,
        }
        let parts: Vec<&str> = assertion.split('.').collect();
        let [header_b64, payload_b64, signature_b64] = parts.as_slice() else {
            return Err(refused("malformed assertion"));
        };
        let header: AssertionHeader = URL_SAFE_NO_PAD
            .decode(header_b64)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| refused("invalid assertion header"))?;
        super::client_jwks::verify_with_client_jwks(
            [header_b64, payload_b64, signature_b64],
            &header.alg,
            header.kid.as_deref(),
            jwks,
            super::client_jwks::CLIENT_ASSERTION_ALGS,
        )
        .map_err(|_| refused("assertion signature verification failed"))?;
        URL_SAFE_NO_PAD
            .decode(payload_b64)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| refused("invalid assertion claims"))
    }

    pub(super) fn verify_jar_inner(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        request_jwt: &str,
    ) -> Result<crate::identity::oidc::JarClaims, IdentityError> {
        use crate::identity::oidc::JarClaims;

        #[derive(serde::Deserialize)]
        struct JarHeader {
            alg: String,
            #[serde(default)]
            kid: Option<String>,
        }

        // 1. Parse JWT structure
        let parts: Vec<&str> = request_jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(IdentityError::InvalidJar {
                reason: "malformed JWT".to_string(),
            });
        }

        // 2. Decode and parse header — reject alg:none immediately.
        let header_bytes =
            URL_SAFE_NO_PAD
                .decode(parts[0])
                .map_err(|_| IdentityError::InvalidJar {
                    reason: "invalid JWT header encoding".to_string(),
                })?;
        let header: JarHeader =
            serde_json::from_slice(&header_bytes).map_err(|_| IdentityError::InvalidJar {
                reason: "invalid JWT header".to_string(),
            })?;
        let alg = header.alg.as_str();
        if alg.eq_ignore_ascii_case("none") {
            return Err(IdentityError::InvalidJar {
                reason: "alg:none is not permitted in signed request objects".to_string(),
            });
        }
        if alg != "EdDSA" && alg != "RS256" && alg != "ES256" && alg != "PS256" {
            return Err(IdentityError::InvalidJar {
                reason: format!(
                    "unsupported algorithm '{alg}'; supported: RS256, PS256, ES256, EdDSA"
                ),
            });
        }

        // 3. Load client and resolve registered JWKS.
        let client_key = keys::encode_oauth_client(client_id);
        let client_bytes = self
            .storage
            .get(realm_id, &client_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidClient)?;
        let client: OAuthClient =
            serde_json::from_slice(&client_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        let jwks_json = client.jwks().ok_or_else(|| IdentityError::InvalidJar {
            reason: "client has no registered jwks for JAR verification".to_string(),
        })?;

        // 4–5. Select the key by `kid` and verify the signature (shared with
        // `private_key_jwt` assertions verified against the client's JWKS).
        super::client_jwks::verify_with_client_jwks(
            [parts[0], parts[1], parts[2]],
            alg,
            header.kid.as_deref(),
            jwks_json,
            super::client_jwks::JAR_ALGS,
        )
        .map_err(|reason| IdentityError::InvalidJar { reason })?;

        // 6. Decode claims.
        let claims_bytes =
            URL_SAFE_NO_PAD
                .decode(parts[1])
                .map_err(|_| IdentityError::InvalidJar {
                    reason: "invalid claims encoding".to_string(),
                })?;
        let claims: JarClaims =
            serde_json::from_slice(&claims_bytes).map_err(|_| IdentityError::InvalidJar {
                reason: "invalid claims payload".to_string(),
            })?;

        // 7. Validate iss == client_id, and a `client_id` claim, when present,
        //    names the same client (RFC 9101 §4). Both in the issued form.
        //    Every consumer of a request object (authorize, PAR, the browser
        //    /authorize) relies on this one check.
        let issued = issued_client_id(client_id);
        if claims.iss != issued {
            return Err(IdentityError::InvalidJar {
                reason: "iss claim must equal the client_id".to_string(),
            });
        }
        if claims.client_id.as_deref().is_some_and(|cid| cid != issued) {
            return Err(IdentityError::InvalidJar {
                reason: "client_id in JAR claims does not match the request".to_string(),
            });
        }

        // 8. Validate aud contains the realm issuer URL — exact match required (RFC 9101 §4).
        let expected_aud = self.realm_issuer_url(realm_id);
        let aud_ok = match &claims.aud {
            crate::identity::tokens::Audience::Single(s) => s == &expected_aud,
            crate::identity::tokens::Audience::Multi(v) => v.iter().any(|a| a == &expected_aud),
        };
        if !aud_ok {
            return Err(IdentityError::InvalidJar {
                reason: "aud claim does not include the authorization server issuer".to_string(),
            });
        }

        // 9. Validate exp is in the future.
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        if now_secs >= claims.exp {
            return Err(IdentityError::InvalidJar {
                reason: "request object has expired".to_string(),
            });
        }

        // 10. Validate nbf is not in the future if present (RFC 7519 §4.1.5).
        if let Some(nbf) = claims.nbf {
            if now_secs < nbf {
                return Err(IdentityError::InvalidJar {
                    reason: "request object is not yet valid (nbf)".to_string(),
                });
            }
        }

        // 11. JTI replay prevention — RFC 9101 §4 requires jti.
        let jti = claims
            .jti
            .as_deref()
            .ok_or_else(|| IdentityError::InvalidJar {
                reason: "jti claim is required in signed request objects".to_string(),
            })?;
        let jti_key = keys::encode_jar_jti(jti);
        // Store expiry as 8-byte little-endian i64 (Unix seconds) so the
        // background sweeper in cleanup::sweep_jar_jtis() can purge entries
        // once they can no longer represent a valid JWT (exp + clock skew).
        //
        // One atomic step (GA audit L9): the old read-then-write let
        // concurrent requests carrying the same request object all pass.
        // `put_if_absent` is atomic here and Raft-routed in cluster mode.
        let jar_jti_expires_at = claims.exp.saturating_add(CLOCK_SKEW_SECS);
        let fresh = self
            .storage
            .put_if_absent(realm_id, &jti_key, &jar_jti_expires_at.to_le_bytes())
            .map_err(Self::storage_err)?;
        if !fresh {
            return Err(IdentityError::InvalidJar {
                reason: "jti has already been used (replay)".to_string(),
            });
        }

        Ok(claims)
    }

    pub(super) fn device_authorize_inner(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::DeviceAuthorizationRequest,
    ) -> Result<crate::identity::oidc::DeviceAuthorizationResponse, IdentityError> {
        use crate::identity::oidc::{DeviceCodeStatus, StoredDeviceCode};

        // 1. Verify client exists
        let client_key = keys::encode_oauth_client(&request.client_id);
        let client_bytes = self
            .storage
            .get(realm_id, &client_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidClient)?;
        let client: OAuthClient =
            serde_json::from_slice(&client_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        Self::refuse_inactive_client(&client)?;

        // 1b. Only a client registered for the device grant may start one
        //     (GA audit M7): otherwise any client — a third-party app — could
        //     phish a user code for its own flow.
        if !client.allows_grant_type(crate::identity::oidc::GRANT_DEVICE_CODE) {
            return Err(IdentityError::UnsupportedGrantType);
        }

        self.validate_client_scope_request(&client, request.scope.as_deref().unwrap_or(""))?;

        // 2. Generate device code (32 random bytes → base64url)
        let rng = ring::rand::SystemRandom::new();
        let mut device_code_bytes = [0u8; 32];
        rng.fill(&mut device_code_bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "random generation failed".to_string(),
            })?;
        let device_code = URL_SAFE_NO_PAD.encode(device_code_bytes);

        // 3. Generate user code (8 chars from unambiguous alphabet)
        let user_code = Self::generate_user_code(&rng)?;

        let now = self.clock.now();
        // HSEC-008: prefer per-realm TTL from config; fall back to 600 s (10 min).
        let expires_in = self
            .get_realm(realm_id)?
            .and_then(|r| r.config().device_code_ttl_secs)
            .unwrap_or(600_i64);
        let interval = 5_i64;
        let device_code_hash = Self::sha256_hex(device_code.as_bytes());

        // 4. Store device code
        let stored = StoredDeviceCode {
            device_code_hash: device_code_hash.clone(),
            user_code: user_code.clone(),
            client_id: request.client_id.clone(),
            realm_id: realm_id.clone(),
            scope: request.scope.clone(),
            status: DeviceCodeStatus::Pending,
            created_at: now,
            expires_at: crate::core::Timestamp::from_micros(
                now.as_micros() + expires_in * 1_000_000,
            ),
            interval,
            last_polled_at: None,
            mfa_proof: crate::identity::MfaProof::None,
        };
        let stored_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        let dc_key = keys::encode_device_code(&device_code_hash);
        self.storage
            .put(realm_id, &dc_key, &stored_bytes)
            .map_err(Self::storage_err)?;

        // 5. Store user code → device code hash mapping
        let uc_key = keys::encode_user_code(&user_code);
        self.storage
            .put(realm_id, &uc_key, device_code_hash.as_bytes())
            .map_err(Self::storage_err)?;

        Ok(crate::identity::oidc::DeviceAuthorizationResponse {
            device_code,
            user_code,
            // The end-user verification page is `handlers::device_approve_form`,
            // registered on the web router, which `router_with` mounts under the
            // `/ui` nest. Advertising `{issuer}/device` therefore handed every
            // RFC 8628 client a URL that answers 404 — the user-facing half of
            // the device grant was unreachable at the URI the server itself
            // printed (audit re-run 23.7).
            verification_uri: format!("{}/ui/device", self.config.oidc.issuer),
            expires_in,
            interval,
        })
    }

    pub(super) fn approve_device_inner(
        &self,
        realm_id: &RealmId,
        user_code: &str,
        user_id: &UserId,
        mfa_proof: crate::identity::MfaProof,
    ) -> Result<(), IdentityError> {
        use crate::identity::oidc::DeviceCodeStatus;

        // 1. Look up user code → device code hash
        let uc_key = keys::encode_user_code(user_code);
        let dc_hash_bytes = self
            .storage
            .get(realm_id, &uc_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::DeviceCodeExpired)?;
        let dc_hash = String::from_utf8(dc_hash_bytes)
            .map_err(|_| IdentityError::InvalidAuthorizationCode)?;

        // The poll takes this lock across its read-modify-write of the row;
        // without it a poll on this node could write back the `Pending` it
        // read over this approval.
        let lock = self.code_exchange_lock(&dc_hash);
        // INVARIANT: sync window only — no `.await` between here and return.
        let _decision_guard = lock.lock().expect("code_exchange_lock poisoned");

        // 2. Load device code
        let dc_key = keys::encode_device_code(&dc_hash);
        let dc_bytes = self
            .storage
            .get(realm_id, &dc_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::DeviceCodeExpired)?;
        let mut stored: StoredDeviceCode =
            serde_json::from_slice(&dc_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // 3. Check expiration
        let now = self.clock.now();
        if now >= stored.expires_at {
            return Err(IdentityError::DeviceCodeExpired);
        }

        // 4. Must be pending
        if stored.status != DeviceCodeStatus::Pending {
            return Err(IdentityError::InvalidAuthorizationCode);
        }

        // 5. Claim the decision, then approve (G6). The status check above is
        //    a local read: an approval on a node that had not applied another
        //    node's denial (or approval) overwrote it. Approve and deny claim
        //    the same replicated marker, so exactly one decides.
        if !self.claim_single_use(
            realm_id,
            &keys::encode_consumed_device_decision(&dc_hash),
            stored.expires_at,
        )? {
            return Err(IdentityError::InvalidAuthorizationCode);
        }
        stored.status = DeviceCodeStatus::Approved {
            user_id: user_id.clone(),
        };
        stored.mfa_proof = mfa_proof;
        let updated_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &dc_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::AuthorizationCodeExchanged,
            "device",
            user_code,
        )?;

        Ok(())
    }

    /// The device-code hash and row key `user_code` points at, without
    /// loading the row. `Ok(None)` when no device code carries that user code.
    fn device_code_key_for_user_code(
        &self,
        realm_id: &RealmId,
        user_code: &str,
    ) -> Result<Option<(String, Vec<u8>)>, IdentityError> {
        let Some(dc_hash_bytes) = self
            .storage
            .get(realm_id, &keys::encode_user_code(user_code))
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        let Ok(dc_hash) = String::from_utf8(dc_hash_bytes) else {
            return Ok(None);
        };
        let dc_key = keys::encode_device_code(&dc_hash);
        Ok(Some((dc_hash, dc_key)))
    }

    /// Loads the still-pending device code `user_code` names, with its
    /// storage key. `Ok(None)` when no device code carries that user code;
    /// `DeviceCodeExpired` when it has expired; `InvalidAuthorizationCode`
    /// when it was already approved or denied.
    fn load_pending_device_code(
        &self,
        realm_id: &RealmId,
        user_code: &str,
    ) -> Result<Option<(Vec<u8>, StoredDeviceCode)>, IdentityError> {
        use crate::identity::oidc::DeviceCodeStatus;

        let Some((_, dc_key)) = self.device_code_key_for_user_code(realm_id, user_code)? else {
            return Ok(None);
        };
        let Some(dc_bytes) = self
            .storage
            .get(realm_id, &dc_key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        let stored: StoredDeviceCode =
            serde_json::from_slice(&dc_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        if self.clock.now() >= stored.expires_at {
            return Err(IdentityError::DeviceCodeExpired);
        }
        if stored.status != DeviceCodeStatus::Pending {
            return Err(IdentityError::InvalidAuthorizationCode);
        }
        Ok(Some((dc_key, stored)))
    }

    /// Returns which client a pending user code belongs to and the scope it
    /// requested, so the approval page can show them (GA audit B3).
    pub(super) fn pending_device_authorization_inner(
        &self,
        realm_id: &RealmId,
        user_code: &str,
    ) -> Result<Option<crate::identity::oidc::PendingDeviceAuthorization>, IdentityError> {
        Ok(self
            .load_pending_device_code(realm_id, user_code)?
            .map(
                |(_, stored)| crate::identity::oidc::PendingDeviceAuthorization {
                    client_id: stored.client_id,
                    scope: stored.scope,
                },
            ))
    }

    /// Records the user's refusal of a pending device code, so the polling
    /// device receives `access_denied` (RFC 8628 §3.5) instead of waiting
    /// out the code's lifetime.
    pub(super) fn deny_device_inner(
        &self,
        realm_id: &RealmId,
        user_code: &str,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        use crate::identity::oidc::DeviceCodeStatus;

        let (dc_hash, dc_key) = self
            .device_code_key_for_user_code(realm_id, user_code)?
            .ok_or(IdentityError::DeviceCodeExpired)?;
        // Same lock and the same decision marker as `approve_device_inner`.
        let lock = self.code_exchange_lock(&dc_hash);
        // INVARIANT: sync window only — no `.await` between here and return.
        let _decision_guard = lock.lock().expect("code_exchange_lock poisoned");
        let (dc_key_loaded, mut stored) = self
            .load_pending_device_code(realm_id, user_code)?
            .ok_or(IdentityError::DeviceCodeExpired)?;
        if dc_key_loaded != dc_key {
            // The user code was re-pointed between the two reads.
            return Err(IdentityError::DeviceCodeExpired);
        }
        if !self.claim_single_use(
            realm_id,
            &keys::encode_consumed_device_decision(&dc_hash),
            stored.expires_at,
        )? {
            return Err(IdentityError::InvalidAuthorizationCode);
        }
        stored.status = DeviceCodeStatus::Denied;
        let updated_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &dc_key, &updated_bytes)
            .map_err(Self::storage_err)?;
        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::ConsentDenied,
            "device",
            user_code,
        )?;
        Ok(())
    }

    pub(super) fn poll_device_token_inner(
        &self,
        realm_id: &RealmId,
        device_code: &str,
        client_id: &ClientId,
    ) -> Result<OidcTokenResponse, IdentityError> {
        use crate::identity::oidc::DeviceCodeStatus;

        // 1. Look up device code by hash, under the same per-code advisory lock
        //    the authorization-code exchange uses (task 26.44).
        //
        // Device-code redemption was the one single-use path with no lock at
        // all. `exchange_authorization_code` takes `code_exchange_lock` and
        // deletes as its FIRST write, so a second concurrent caller finds the
        // key gone; refresh-token redemption takes `token_redemption_lock`.
        // This path read the code, checked its status, created a session,
        // issued a token pair, and only then deleted — so two concurrent polls
        // of an approved code could both pass the status check and both be
        // served, each with its own session.
        //
        // The lock is held across the read, the poll-rate update and, on the
        // approved arm, the delete. Everything expensive — session creation and
        // token issuance — happens after it is released.
        //
        // INVARIANT: outer map guard is released inside `code_exchange_lock()`;
        // the inner per-code guard is held only across this sync block (no .await).
        let dc_hash = Self::sha256_hex(device_code.as_bytes());
        let dc_key = keys::encode_device_code(&dc_hash);
        let lock = self.code_exchange_lock(&dc_hash);
        let poll_guard = lock.lock().expect("code_exchange_lock poisoned");
        let dc_bytes = self
            .storage
            .get(realm_id, &dc_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::DeviceCodeExpired)?;
        let mut stored: StoredDeviceCode =
            serde_json::from_slice(&dc_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // 2. Verify client matches
        if stored.client_id != *client_id {
            return Err(IdentityError::InvalidClient);
        }
        // B9: a client archived (or deleted) since it started the flow gets no
        // tokens. Checked before the code is consumed, so a restore lets a
        // still-live code complete.
        match self.get_client(realm_id, client_id)? {
            Some(c) => Self::refuse_inactive_client(&c)?,
            None => return Err(IdentityError::InvalidClient),
        }

        let now = self.clock.now();

        // 3. Check expiration
        if now >= stored.expires_at {
            return Err(IdentityError::DeviceCodeExpired);
        }

        // 4. Rate limit polling
        if let Some(last_polled) = stored.last_polled_at {
            let elapsed_secs = (now.as_micros() - last_polled.as_micros()) / 1_000_000;
            if elapsed_secs < stored.interval {
                return Err(IdentityError::SlowDown);
            }
        }

        // 5. Update last_polled_at — except on the approved arm, which
        //    consumes the code below. Writing the row back there bought
        //    nothing (it is deleted next) and, for a poll that read the code
        //    before another node redeemed it, re-created a row that node had
        //    already deleted (G4).
        if !matches!(stored.status, DeviceCodeStatus::Approved { .. }) {
            // A row read as `Pending` after the user decided (on another
            // node, not yet applied here) must not be written back: that
            // would put `Pending` over the decision, and the decision marker
            // then refuses a second one, stranding the device until expiry
            // (G6). The next poll reads the decision.
            if stored.status == DeviceCodeStatus::Pending
                && self
                    .storage
                    .get(realm_id, &keys::encode_consumed_device_decision(&dc_hash))
                    .map_err(Self::storage_err)?
                    .is_some()
            {
                return Err(IdentityError::AuthorizationPending);
            }
            stored.last_polled_at = Some(now);
            let updated_bytes =
                serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            self.storage
                .put(realm_id, &dc_key, &updated_bytes)
                .map_err(Self::storage_err)?;
        }

        // 6. Check status
        match &stored.status {
            DeviceCodeStatus::Pending => Err(IdentityError::AuthorizationPending),
            DeviceCodeStatus::Denied => Err(IdentityError::DeviceCodeDenied),
            DeviceCodeStatus::Expired => Err(IdentityError::DeviceCodeExpired),
            DeviceCodeStatus::Approved { user_id } => {
                // Consume as the FIRST write, exactly as the authorization-code
                // exchange does, and still under the lock — a second concurrent
                // poll then finds nothing (task 26.44).
                //
                // The delete is PROPAGATED, not discarded. It used to be
                // `let _ = self.storage.delete(..)` after the tokens had
                // already been minted, so a failed delete returned a live token
                // pair over a device code that stayed redeemable: the caller
                // was told the flow completed, and the code could be redeemed
                // again, and again.
                //
                // The consume that DECIDES the single use is the claim, not
                // the delete (G4): a delete of an absent key succeeds, so a
                // poll that read the approved code before another node
                // redeemed it, and wrote after leadership moved to its own
                // node, used to be served too. The claim is one replicated
                // put-if-absent the Raft state machine evaluates.
                if !self.claim_single_use(
                    realm_id,
                    &keys::encode_consumed_device_code(&dc_hash),
                    stored.expires_at,
                )? {
                    return Err(IdentityError::DeviceCodeExpired);
                }
                self.storage
                    .delete(realm_id, &dc_key)
                    .map_err(Self::storage_err)?;
                let uc_key = keys::encode_user_code(&stored.user_code);
                // The user-code index is a secondary pointer to the device code
                // that has just gone. A stale entry resolves to nothing, so it
                // cannot grant anything; log rather than fail a completed
                // authorization over it.
                if let Err(e) = self.storage.delete(realm_id, &uc_key) {
                    tracing::warn!(
                        error = %e,
                        "device code consumed but its user-code index entry was not removed"
                    );
                }
                drop(poll_guard);

                // A client deleted since it started the flow gets nothing: its
                // claim profile could no longer be evaluated, and the
                // clientless fallback is the first-party sentinel, which would
                // release the user's permissions to it (GA audit B1). A client
                // whose device grant was withdrawn gets nothing either (M7).
                let device_client = self
                    .get_client(realm_id, client_id)?
                    .ok_or(IdentityError::InvalidClient)?;
                if !device_client.allows_grant_type(crate::identity::oidc::GRANT_DEVICE_CODE) {
                    return Err(IdentityError::UnsupportedGrantType);
                }
                // Resolve the client's ID-token signer (task 26.55) before the
                // session exists, so a key failure leaves nothing behind.
                let id_token_signer = self.id_token_signer(
                    realm_id,
                    Some(&device_client),
                    self.get_or_load_realm_signing_key(realm_id)?,
                )?;

                // Issue tokens like exchange_authorization_code (device flow — no browser context).
                // A derived session: the device code reached `Approved` only
                // because a browser user approved it from a live session, and
                // that session passed the same second-factor gates at login.
                // It records the proof that approving session made (GA audit
                // round 3, D-7).
                let session = self.create_derived_session(realm_id, user_id, stored.mfa_proof)?;
                // The grant is issued TO the polling client: record it on the
                // grant family, as the authorization-code grant does. Minting
                // with the default (clientless) context left the family with
                // no owner, so RFC 7009 ownership resolved to no client and
                // the device client's own `/revoke` answered 200 while its
                // refresh token and session stayed live. It also skipped the
                // client's claim profile and the refresh-time client binding.
                let token_pair = self.issue_tokens_with_context(
                    realm_id,
                    user_id,
                    session.id(),
                    &super::TokenIssuanceContext {
                        client_id: Some(client_id.clone()),
                        // The scope the device requested and the user approved:
                        // it narrows the permissions and is carried as the
                        // token's `scope` (GA audit 3 B-4; B-6's scope half).
                        granted_scopes: stored
                            .scope
                            .as_deref()
                            .map(|s| s.split_whitespace().map(str::to_string).collect())
                            .unwrap_or_default(),
                        ..Default::default()
                    },
                )?;

                // Issue ID token
                // iss MUST match the discovery document's issuer (OIDC Core §2)
                let iat = now.as_micros() / 1_000_000;
                let id_token_claims = TokenClaims {
                    sub: user_id.to_string(),
                    iss: self.config.oidc.issuer.clone(),
                    aud: Audience::single(client_id.to_string()),
                    exp: iat + self.config.token.access_token_ttl_secs,
                    iat,
                    nbf: None,
                    sid: session.id().to_string(),
                    tid: realm_id.to_string(),
                    oid: None,
                    token_type: "id_token".to_string(),
                    jti: Some(uuid::Uuid::new_v4().to_string()),
                    fid: None,
                    scope: stored.scope.clone(),
                    nonce: None,
                    azp: Some(client_id.to_string()),
                    roles: Vec::new(),
                    groups: Vec::new(),
                    org_groups: Vec::new(),
                    permissions: Vec::new(),
                    act: None,
                    amr: Vec::new(),
                    cnf: None,
                    custom: std::collections::BTreeMap::new(),
                    sv: None,
                };
                let id_token = id_token_signer.sign(&id_token_claims).map_err(|e| {
                    IdentityError::SigningError {
                        reason: format!("failed to issue ID token: {e}"),
                    }
                })?;

                // No refresh token for a client without the refresh-token
                // grant (GA audit M7); see the authorization-code exchange.
                let refresh_token = if device_client.allows_refresh_token() {
                    token_pair.refresh_token().to_string()
                } else {
                    String::new()
                };
                Ok(OidcTokenResponse::new(
                    token_pair.access_token().to_string(),
                    id_token,
                    "Bearer".to_string(),
                    self.config.token.access_token_ttl_secs,
                    refresh_token,
                ))
            }
        }
    }

    pub(super) fn push_authorization_request_inner(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::PushedAuthorizationRequest,
    ) -> Result<crate::identity::oidc::PushedAuthorizationResponse, IdentityError> {
        use crate::identity::keys;
        use crate::identity::oidc::{CodeChallengeMethod, StoredPushedAuthorizationRequest};
        use crate::identity::types::FapiProfile;

        let realm = self
            .get_realm(realm_id)?
            .ok_or(IdentityError::RealmNotFound)?;
        if realm.status() != crate::identity::types::RealmStatus::Active {
            return Err(IdentityError::RealmSuspended);
        }

        // FAPI 2.0 pre-JAR gate: only the JAR-required check can safely fire here,
        // because the PKCE check must use `effective_code_challenge` (which may come
        // from inside the signed JAR per RFC 9101 §6.1).
        if let Some(profile) = realm.config().fapi_profile {
            // Advanced: JAR (signed request object) is mandatory.
            if profile == FapiProfile::Advanced && request.request.is_none() {
                return Err(IdentityError::FapiViolation {
                    reason: "FAPI 2.0 Advanced requires a signed request object (JAR, RFC 9101)"
                        .to_string(),
                });
            }
        }

        // JAR (RFC 9101): if a signed request object is present, verify it and
        // use its claims to override the plain-text request parameters.
        let (
            effective_redirect_uri,
            effective_scope,
            effective_state,
            effective_resource,
            effective_response_type,
            effective_code_challenge,
            effective_code_challenge_method,
            effective_nonce,
            effective_response_mode,
            effective_prompt,
        ) = if let Some(ref jar_jwt) = request.request {
            let jar = self.verify_jar(realm_id, &request.client_id, jar_jwt)?;
            // JAR client_id claim must match the outer client_id.
            // `verify_jar` checked the JAR's `iss` and `client_id` (RFC 9101 §4).
            let ccm = jar.code_challenge_method.as_deref().and_then(|m| {
                if m == "S256" {
                    Some(CodeChallengeMethod::S256)
                } else {
                    None
                }
            });
            (
                jar.redirect_uri
                    .unwrap_or_else(|| request.redirect_uri.clone()),
                jar.scope.unwrap_or_else(|| request.scope.clone()),
                jar.state.unwrap_or_else(|| request.state.clone()),
                jar.resource.or_else(|| request.resource.clone()),
                jar.response_type
                    .unwrap_or_else(|| request.response_type.clone()),
                jar.code_challenge
                    .or_else(|| request.code_challenge.clone()),
                ccm.or_else(|| request.code_challenge_method.clone()),
                jar.nonce.or_else(|| request.nonce.clone()),
                // JAR response_mode takes precedence over the outer param (RFC 9101 §4).
                jar.response_mode.or_else(|| request.response_mode.clone()),
                // So does its `prompt`. Dropping the claim here left a pushed
                // request object's `prompt=none` showing the consent page.
                jar.prompt.or_else(|| request.prompt.clone()),
            )
        } else {
            (
                request.redirect_uri.clone(),
                request.scope.clone(),
                request.state.clone(),
                request.resource.clone(),
                request.response_type.clone(),
                request.code_challenge.clone(),
                request.code_challenge_method.clone(),
                request.nonce.clone(),
                request.response_mode.clone(),
                request.prompt.clone(),
            )
        };

        // FAPI 2.0 post-JAR gate: PKCE must be checked against `effective_code_challenge`
        // so that clients who supply it only inside the JAR (RFC 9101 §6.1) are accepted.
        if realm.config().fapi_profile.is_some() {
            // Baseline + Advanced: PKCE (S256) is always required.
            if effective_code_challenge.is_none() {
                return Err(IdentityError::FapiViolation {
                    reason: "FAPI 2.0 Baseline requires PKCE (code_challenge with S256)"
                        .to_string(),
                });
            }
        }

        if effective_response_type != "code" {
            return Err(IdentityError::InvalidInput {
                reason: "response_type must be 'code'".to_string(),
            });
        }
        if effective_state.is_empty() {
            return Err(IdentityError::InvalidInput {
                reason: "state must not be empty".to_string(),
            });
        }

        let client = self
            .get_client(realm_id, &request.client_id)?
            .ok_or(IdentityError::ClientNotFound)?;
        Self::refuse_inactive_client(&client)?;

        if !client.redirect_uris().contains(&effective_redirect_uri) {
            return Err(IdentityError::InvalidRedirectUri);
        }

        // PKCE unconditional for all clients (RFC 9700 §2.1.1)
        if effective_code_challenge.is_none() {
            return Err(IdentityError::InvalidInput {
                reason: "PKCE is required (code_challenge with S256 must be supplied)".to_string(),
            });
        }
        if effective_code_challenge.is_some()
            && !matches!(
                effective_code_challenge_method,
                Some(CodeChallengeMethod::S256)
            )
        {
            return Err(IdentityError::InvalidInput {
                reason: "code_challenge requires code_challenge_method=S256".to_string(),
            });
        }

        // RFC 8707: the resource must be a registered protected resource; it
        // is stored in canonical form (G6).
        let effective_resource = effective_resource
            .as_deref()
            .map(|r| self.resolve_authorization_resource(realm_id, r))
            .transpose()?
            .map(|r| r.as_str().to_string());

        let now = self.clock.now();
        let ttl_secs: i64 = 90;
        let expires_at = now.add_micros(ttl_secs * 1_000_000);
        // 22.27 (audit 2026-08-28 §4.25#5): RFC 9126 §7.1 makes 128 bits the
        // normative floor for a `request_uri`. A UUID v4 carries only 122.
        let request_uri_id = crate::core::random_secret_hex();

        let stored = StoredPushedAuthorizationRequest {
            request_uri_id: request_uri_id.clone(),
            client_id: request.client_id.clone(),
            redirect_uri: effective_redirect_uri,
            scope: effective_scope,
            state: effective_state,
            resource: effective_resource,
            response_type: effective_response_type,
            code_challenge: effective_code_challenge,
            code_challenge_method: effective_code_challenge_method,
            nonce: effective_nonce,
            response_mode: effective_response_mode,
            prompt: effective_prompt.filter(|p| !p.is_empty()),
            created_at: now,
            expires_at,
        };

        let key = keys::encode_par_request(&request_uri_id);
        let value = serde_json::to_vec(&stored).map_err(|e| IdentityError::Internal {
            reason: format!("failed to serialize PAR request: {e}"),
        })?;
        self.storage
            .put(realm_id, &key, &value)
            .map_err(Self::storage_err)?;

        Ok(crate::identity::oidc::PushedAuthorizationResponse {
            request_uri: format!("urn:ietf:params:oauth:request_uri:{request_uri_id}"),
            expires_in: ttl_secs,
        })
    }

    pub(super) fn consume_par_inner(
        &self,
        realm_id: &RealmId,
        request_uri: &str,
    ) -> Result<crate::identity::oidc::StoredPushedAuthorizationRequest, IdentityError> {
        use crate::identity::keys;

        const URN_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";
        let request_uri_id = request_uri
            .strip_prefix(URN_PREFIX)
            .ok_or(IdentityError::InvalidPushedAuthorizationRequest)?;

        let key = keys::encode_par_request(request_uri_id);
        // GA audit L9 made read → check `used` → write back one step on this
        // node with the per-key advisory lock; it still is, so same-node
        // racers queue here instead of each proposing a Raft write. The lock
        // is node-local, though, and the flag was a read-then-write: a
        // redemption that read the entry before another node consumed it and
        // wrote after leadership moved to its own node consumed it again (G4).
        // The single use is now decided by `claim_single_use` — one replicated
        // put-if-absent the Raft state machine evaluates — and the entry
        // itself is never rewritten; the PAR sweep reclaims it at expiry.
        let lock = self.code_exchange_lock(&format!("par:{request_uri_id}"));
        // INVARIANT: guard held only across the sync read-check-claim below; no .await in scope.
        let _consume_guard = lock.lock().expect("code_exchange_lock poisoned");
        let raw = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidPushedAuthorizationRequest)?;

        let stored: crate::identity::oidc::StoredPushedAuthorizationRequest =
            serde_json::from_slice(&raw).map_err(|e| IdentityError::Internal {
                reason: format!("failed to deserialize PAR request: {e}"),
            })?;

        // Expiry first: an expired `request_uri` is refused without a write.
        let now = self.clock.now();
        if now >= stored.expires_at {
            return Err(IdentityError::InvalidPushedAuthorizationRequest);
        }
        if !self.claim_single_use(
            realm_id,
            &keys::encode_consumed_par(request_uri_id),
            stored.expires_at,
        )? {
            return Err(IdentityError::InvalidPushedAuthorizationRequest);
        }

        Ok(stored)
    }

    /// Builds a non-reversible audit reference for a revoked token.
    ///
    /// The audit log is durable, CSV-exportable from the admin console, and
    /// readable by every realm admin, so it MUST NOT carry credential
    /// material (audit 2026-08-28 §4.16#9). Prefers the token's own `jti` —
    /// a public identifier that is already recorded in the JTI blocklist —
    /// and otherwise falls back to a truncated SHA-256 digest of the token,
    /// which correlates repeated revocations of the same token without being
    /// reversible. The raw token is never returned.
    fn audit_token_reference(claims: &TokenClaims, token: &str) -> String {
        if let Some(jti) = claims.jti.as_deref().filter(|j| !j.is_empty()) {
            return format!("jti:{jti}");
        }
        use sha2::{Digest, Sha256};
        let digest = hex::encode(Sha256::digest(token.as_bytes()));
        // A hex SHA-256 is always 64 chars; `get` keeps this panic-free.
        format!("sha256:{}", digest.get(..16).unwrap_or(digest.as_str()))
    }

    /// Whether `claims` belong to a token issued to `client` (RFC 7009 §2.1).
    ///
    /// The issuing client is, in order:
    /// 1. the outermost `act.sub` — an RFC 8693 exchanged (delegated) token is
    ///    issued to the client that performed the exchange, which Hearth
    ///    records as the current actor (RFC 8693 §4.1; the exchange enforces
    ///    `act.sub` == the authenticated client). It inherits the subject
    ///    token's `fid`, `sid` and `sub`, so reading those would hand it to
    ///    the SUBJECT's client. `act.sub` is either `client_<uuid>` (from an
    ///    `actor_token`) or the bare UUID; both parse as a `ClientId`, and
    ///    anything else owns nothing;
    /// 2. `azp` — set on ID tokens and any token bound to an authorized party;
    /// 3. the grant family's `client_id` — every user access and refresh token
    ///    minted by a grant carries its family id in `fid`;
    /// 4. `sub` — for a sessionless `client_credentials` token, whose subject
    ///    is the client itself.
    ///
    /// Audience membership deliberately does NOT count: a resource server
    /// named in `aud` received the token, it was not issued it, and it must
    /// not be able to end the user's session. A token no client was issued —
    /// a Hearth first-party session token, or a family whose owning client is
    /// unrecorded or already swept — belongs to no client and yields `false`
    /// (fail closed).
    fn token_issued_to_client(
        &self,
        realm_id: &RealmId,
        claims: &TokenClaims,
        client: &crate::core::ClientId,
    ) -> Result<bool, IdentityError> {
        if let Some(act) = claims.act.as_ref() {
            return Ok(act.sub.parse::<crate::core::ClientId>().ok().as_ref() == Some(client));
        }
        let client_str = client.to_string();
        if let Some(azp) = claims.azp.as_deref() {
            return Ok(azp == client_str);
        }
        if let Some(ref fid) = claims.fid {
            let family_key = keys::encode_grant_family(fid);
            let Some(bytes) = self
                .storage
                .get(realm_id, &family_key)
                .map_err(Self::storage_err)?
            else {
                return Ok(false);
            };
            let family: StoredGrantFamily =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            return Ok(family.client_id.as_ref() == Some(client));
        }
        if claims.sid == "none" {
            return Ok(claims.sub == client_str);
        }
        Ok(false)
    }

    pub(super) fn revoke_token_inner(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::TokenRevocationRequest,
    ) -> Result<(), IdentityError> {
        // RFC 7009: invalid tokens → 200 OK (no error). Signature
        // verification prevents forged tokens from targeting real sessions
        // or grant families for revocation.
        //
        // An RS256 ID token (task 26.55) is verified too, so a client that
        // selected RS256 can still end a session with its ID token, exactly as
        // an EdDSA client can. The RS256 path yields only `id_token` claims.
        let Ok(claims) = self.verify_realm_issued_id_token(realm_id, &request.token) else {
            return Ok(());
        };

        // Verify realm matches
        if claims.tid.parse::<RealmId>().ok().as_ref() != Some(realm_id) {
            return Ok(()); // Silent success per RFC 7009
        }

        // RFC 7009 §2.1: the server "verifies whether the token was issued to
        // the client making the revocation request". Without this, any
        // authenticated client — and a public client authenticates on its
        // `client_id` alone — could end the session or grant family behind
        // any token it held: a resource server that legitimately received a
        // user's token, or anyone holding a leaked one. A foreign token is a
        // silent no-op (RFC 7009 §2.2), exactly like an invalid one.
        if let Some(revoking) = request.revoking_client_id.as_ref() {
            if !self.token_issued_to_client(realm_id, &claims, revoking)? {
                tracing::debug!(
                    realm_id = %realm_id,
                    "revocation ignored: token was not issued to the revoking client"
                );
                return Ok(());
            }
        }

        match claims.token_type.as_str() {
            // A delegated (RFC 8693 exchanged) token carries the subject
            // token's `sid`, but it was issued to the exchanging client, not
            // to the subject's. Ending that shared session would revoke the
            // subject client's own tokens — the cross-client revocation the
            // ownership check above exists to prevent — so it falls through
            // to the JTI blocklist arm below and dies alone.
            "access" | "id_token" => {
                if claims.sid != "none" && claims.act.is_none() {
                    // Session-bound token: revoke via session.
                    //
                    // The outcome is PROPAGATED, not discarded. RFC 7009 §2.2
                    // lets a client read `200 OK` as "the token is now
                    // invalid", so answering 200 after a failed revoke tells
                    // the client a live credential is dead — the same
                    // "reports success it never achieved" class as the failed
                    // session write in `update_user` (audit §4.16#10) and the
                    // reset mails that were minted and dropped (§4.24#10).
                    // An ALREADY-absent session is not a failure: RFC 7009
                    // requires 200 for a token that is already invalid.
                    let sid_str = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
                    if let Ok(uuid) = uuid::Uuid::parse_str(sid_str) {
                        let session_id = SessionId::new(uuid);
                        match self.revoke_session(realm_id, &session_id) {
                            Ok(()) | Err(IdentityError::SessionNotFound) => {}
                            Err(e) => return Err(e),
                        }
                    }
                } else if let Some(ref jti) = claims.jti {
                    // Sessionless token (e.g., client_credentials) or a
                    // delegated token: revoke via JTI blocklist.
                    // Store the token's exp so the hot-path projection can self-evict expired entries.
                    // Propagated for the same reason as the session arm above:
                    // the cache insert below would otherwise mask a failed
                    // durable write, so the blocklist entry would vanish on
                    // restart while the client believed the token was dead.
                    let jti_key = keys::encode_revoked_jti(jti);
                    self.storage
                        .put(realm_id, &jti_key, &claims.exp.to_le_bytes())
                        .map_err(Self::storage_err)?;
                    self.insert_revoked_jti_cache(realm_id, jti, claims.exp);
                }
            }
            "refresh" => {
                // Revoke via grant family.
                //
                // The load → set revoked → write sequence must hold the same
                // per-family advisory lock `rotate_grant_family` holds, or it
                // is a lost update: a rotation that has already read the family
                // and is working through RBAC resolution and the pre-token
                // webhook writes it back un-revoked afterwards. RFC 7009 §2.2
                // lets the client read the resulting `200 OK` as "the token is
                // now invalid" while the grant is still live
                // (audit 2026-08-28 §4.16#7).
                //
                // The guard is scoped to this block: `revoke_session` below
                // re-takes the same lock for its own cascade, and
                // `std::sync::Mutex` is not reentrant.
                if let Some(ref fid) = claims.fid {
                    let family_key = keys::encode_grant_family(fid);
                    let lock = self.grant_family_lock(realm_id, fid);
                    // INVARIANT: guard held only across the sync re-read + revoke-write; no .await in scope.
                    let _guard = lock.lock().map_err(|_| IdentityError::Internal {
                        reason: "grant family lock poisoned".to_string(),
                    })?;
                    if let Some(family_bytes) = self
                        .storage
                        .get(realm_id, &family_key)
                        .map_err(Self::storage_err)?
                    {
                        let mut family: StoredGrantFamily = serde_json::from_slice(&family_bytes)
                            .map_err(|e| {
                            IdentityError::Serialization {
                                reason: e.to_string(),
                            }
                        })?;
                        self.mark_grant_family_revoked(realm_id, &family)?;
                        family.revoked = true;
                        let updated = serde_json::to_vec(&family).map_err(|e| {
                            IdentityError::Serialization {
                                reason: e.to_string(),
                            }
                        })?;
                        self.storage
                            .put(realm_id, &family_key, &updated)
                            .map_err(Self::storage_err)?;
                    }
                }
                // Also revoke the session if present.
                //
                // Task 24.1: this used to discard the result, so `POST /revoke`
                // answered 200 while the session behind the refresh token
                // stayed live. It is the same defect the access-token arm above
                // carried, and RFC 7009's "silent success" applies to an
                // *unknown* token, not to a revocation the server failed to
                // perform. `SessionNotFound` is still success — the session is
                // gone, which is what the caller asked for.
                if claims.sid != "none" {
                    let sid_str = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
                    if let Ok(uuid) = uuid::Uuid::parse_str(sid_str) {
                        let session_id = SessionId::new(uuid);
                        match self.revoke_session(realm_id, &session_id) {
                            Ok(()) | Err(IdentityError::SessionNotFound) => {}
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
            _ => {} // Unknown token type → silent success
        }

        // Never persist the presented bearer token: `resource_id` is written
        // verbatim to the append-only log (audit 2026-08-28 §4.16#9).
        let token_ref = Self::audit_token_reference(&claims, &request.token);
        self.record_audit(
            realm_id,
            None,
            AuditAction::SessionRevoked,
            "token",
            &token_ref,
        )?;

        Ok(())
    }

    pub(super) fn introspect_token_inner(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::TokenIntrospectionRequest,
    ) -> Result<crate::identity::oidc::IntrospectionResponse, IdentityError> {
        use crate::identity::oidc::IntrospectionResponse;

        // 1. Verify the Ed25519 signature against the realm's own key (and any
        // in-grace retiring key). There is no global-key fallback — a realm
        // with no key of its own fails closed. Forged or tampered tokens are
        // cryptographically rejected; RFC 7662 semantics: return inactive.
        let Ok(claims) = self.verify_token_signature_for_realm(realm_id, &request.token) else {
            return Ok(IntrospectionResponse::inactive());
        };

        // 2. Verify realm matches
        if claims.tid.parse::<RealmId>().ok().as_ref() != Some(realm_id) {
            return Ok(IntrospectionResponse::inactive());
        }

        // 2a. Token-type guard: introspection is defined for access tokens only
        // (RFC 7662 §2.1). Returning `active: true` for ID tokens or refresh tokens
        // would allow token substitution — a resource server accepting any valid
        // Hearth-signed token as an access token (OAUTH-08 / HEA-SEC-22).
        if claims.token_type != "access" {
            return Ok(IntrospectionResponse::inactive());
        }

        // The protected resource(s) in `aud` whose resource server introspects
        // as the calling client (`introspection_client_id`). Such a caller is
        // an audience member for every rule below (G6).
        let caller_is_resource_server = match request.introspecting_client_id {
            Some(ref cid) => self.is_resource_server_for_audience(realm_id, cid, &claims)?,
            None => false,
        };

        // 2b. RFC 7519 §4.1.3 — audience must include the configured value,
        // unless the caller is the resource server a token exchanged with
        // `audience=` only was minted for: it carries no Hearth audience, and
        // introspection is how that server learns the token is still live
        // (AGENT_AUTH.md §2.5).
        if !claims.aud.contains(&self.config.token.audience) && !caller_is_resource_server {
            return Ok(IntrospectionResponse::inactive());
        }

        // 2c. L7: RFC 7662 §2 — restrict introspection to the token's intended
        // audience. A client may only inspect a token that is explicitly bound
        // to it via `azp` or `aud`. This prevents resource server A from
        // introspecting a token issued exclusively for resource server B.
        //
        // Three cases:
        // - `azp` set (delegated/bound token): only azp-match or aud-match allowed.
        // - `azp` absent, `sid == "none"` (M2M/client_credentials): only the
        //   owning client (`sub == cid`) or an audience member may self-introspect.
        // - `azp` absent, `sid != "none"` (unbound user session token): an
        //   audience member, the client the token's grant family was issued
        //   to, or a declared resource server (GA audit L11 — it used to be
        //   any authenticated client, which then received live RBAC data).
        if let Some(ref cid) = request
            .introspecting_client_id
            .as_ref()
            .filter(|_| !caller_is_resource_server)
        {
            let cid_str = cid.to_string();
            if let Some(token_azp) = claims.azp.as_deref() {
                if token_azp != cid_str && !claims.aud.contains(cid_str.as_str()) {
                    return Ok(IntrospectionResponse::inactive());
                }
            } else if claims.sid == "none" {
                // M2M token: only the issuing client or an explicit audience member
                // may introspect it.
                if claims.sub != cid_str && !claims.aud.contains(cid_str.as_str()) {
                    return Ok(IntrospectionResponse::inactive());
                }
            } else if !claims.aud.contains(cid_str.as_str())
                && !self.may_introspect_unbound_user_token(realm_id, cid, &claims)?
            {
                return Ok(IntrospectionResponse::inactive());
            }
        }

        // 3. Check expiration and iat sanity
        let now = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;
        if now_secs >= claims.exp {
            return Ok(IntrospectionResponse::inactive());
        }
        if claims.iat > now_secs + CLOCK_SKEW_SECS {
            return Ok(IntrospectionResponse::inactive());
        }
        if claims.iat > claims.exp {
            return Ok(IntrospectionResponse::inactive());
        }
        // RFC 7519 §4.1.5 — a token that is not yet valid is not active
        // (audit 2026-08-28 §4.2#6, §4.19#10).
        if let Some(nbf) = claims.nbf {
            if now_secs < nbf - CLOCK_SKEW_SECS {
                return Ok(IntrospectionResponse::inactive());
            }
        }

        // 4. Consult the JTI revocation blocklist on BOTH branches. A
        // session-bound OBO/delegation token carries a `jti` that delegation
        // revocation projects into the blocklist; checking it only in the
        // `sid == "none"` branch left a revoked delegation `active: true` with
        // live permissions (audit 2026-08-28 §4.19#5). Mirrors the same guard
        // in `validate_token` (G1).
        if self.is_token_jti_revoked(realm_id, &claims) {
            return Ok(IntrospectionResponse::inactive());
        }
        // A token for a protected resource removed since it was minted is
        // inactive (AGENT_AUTH.md §2.5), as in `validate_token`.
        if self.is_audience_cut_off(realm_id, &claims) {
            return Ok(IntrospectionResponse::inactive());
        }
        if claims.sid != "none" {
            let sid_str = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
            if let Ok(uuid) = uuid::Uuid::parse_str(sid_str) {
                let session_id = SessionId::new(uuid);
                if self.get_session(realm_id, &session_id)?.is_none() {
                    return Ok(IntrospectionResponse::inactive());
                }
            }
        }

        // 5. Check grant family (if refresh token with fid)
        if claims.token_type == "refresh" {
            if let Some(ref fid) = claims.fid {
                let family_key = keys::encode_grant_family(fid);
                if let Some(family_bytes) = self
                    .storage
                    .get(realm_id, &family_key)
                    .map_err(Self::storage_err)?
                {
                    let family: StoredGrantFamily =
                        serde_json::from_slice(&family_bytes).map_err(|e| {
                            IdentityError::Serialization {
                                reason: e.to_string(),
                            }
                        })?;
                    if self.grant_family_is_revoked(realm_id, &family)? {
                        return Ok(IntrospectionResponse::inactive());
                    }
                }
            }
        }

        // 6. Look up the introspecting client's authorization mode and, for
        // Introspection/Decision clients, emit live RBAC data so resource
        // servers have a single authoritative source for permissions.
        use crate::identity::oidc::AccessTokenAuthorization;
        let authz_mode = request
            .introspecting_client_id
            .as_ref()
            .and_then(|cid| self.get_client(realm_id, cid).ok().flatten())
            .map(|c| c.access_token_authorization())
            .unwrap_or(AccessTokenAuthorization::Embedded);

        // The live data is the TOKEN's authority, not the user's (GA audit 3
        // B-2 / C-8): the claim profile of the client the token was issued
        // to (a third-party client's token gets no roles, groups or
        // permissions by default), narrowed by every permission-bearing scope
        // and, for a delegated token, capped at what was delegated. A
        // client-credentials token has no user and gets nothing; a resolution
        // error releases nothing.
        let live = if authz_mode == AccessTokenAuthorization::Embedded {
            crate::identity::oidc::LiveTokenAuthority::default()
        } else {
            let org_id: Option<crate::core::OrganizationId> = self.active_org_context(
                realm_id,
                claims.oid.as_deref().and_then(|o| {
                    uuid::Uuid::parse_str(o.strip_prefix("org_").unwrap_or(o))
                        .ok()
                        .map(crate::core::OrganizationId::new)
                }),
            );
            self.live_token_authority_inner(realm_id, &claims, org_id.as_ref(), None)
                .unwrap_or_default()
        };

        // 7. Active — return metadata
        Ok(IntrospectionResponse {
            active: true,
            scope: claims.scope,
            client_id: None, // Not stored in claims for session-bound tokens
            sub: Some(claims.sub),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            nbf: claims.nbf,
            token_type: Some(claims.token_type),
            iss: Some(claims.iss),
            aud: Some(claims.aud.base().to_string()),
            mode: Some(authz_mode),
            permissions: live.permissions,
            roles: live.roles,
            groups: live.groups,
        })
    }

    /// Whether `caller` may introspect a session-bound access token that
    /// carries no `azp` (GA audit L11): only the client the token's grant
    /// family was issued to, the client that obtained it by token exchange
    /// (its `act.sub`), or a declared resource server — a client whose
    /// `access_token_authorization` is `Introspection` or `Decision`, which
    /// only an administrator can set (dynamic registration always yields
    /// `Embedded`). An unknown or archived caller is neither.
    /// Whether `caller` is the client the resource server of a protected
    /// resource named in the token's `aud` introspects as
    /// ([`ProtectedResource::introspection_client_id`]). Hearth's own
    /// audience is skipped; every other value is looked up by its canonical
    /// form in the realm's registry.
    ///
    /// [`ProtectedResource::introspection_client_id`]: crate::identity::ProtectedResource
    fn is_resource_server_for_audience(
        &self,
        realm_id: &RealmId,
        caller: &ClientId,
        claims: &TokenClaims,
    ) -> Result<bool, IdentityError> {
        let named: &[String] = match &claims.aud {
            Audience::Single(a) => std::slice::from_ref(a),
            Audience::Multi(list) => list,
        };
        for aud in named {
            if *aud == self.config.token.audience {
                continue;
            }
            let Ok(canonical) = Uri::try_from(aud.clone()) else {
                continue;
            };
            let Some(id_bytes) = self
                .storage
                .get(
                    realm_id,
                    &keys::encode_resource_server_uri_index(canonical.as_str()),
                )
                .map_err(Self::storage_err)?
            else {
                continue;
            };
            let Ok(id) = uuid::Uuid::from_slice(&id_bytes) else {
                continue;
            };
            let Some(bytes) = self
                .storage
                .get(
                    realm_id,
                    &keys::encode_resource_server_id(&crate::core::ResourceServerId::new(id)),
                )
                .map_err(Self::storage_err)?
            else {
                continue;
            };
            let resource: crate::identity::ProtectedResource = serde_json::from_slice(&bytes)
                .map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if resource.introspection_client_id.as_ref() == Some(caller) {
                // The resource server must still be a live client.
                return Ok(self
                    .get_client(realm_id, caller)?
                    .is_some_and(|c| Self::refuse_inactive_client(&c).is_ok()));
            }
        }
        Ok(false)
    }

    fn may_introspect_unbound_user_token(
        &self,
        realm_id: &RealmId,
        caller: &ClientId,
        claims: &TokenClaims,
    ) -> Result<bool, IdentityError> {
        use crate::identity::oidc::AccessTokenAuthorization;
        let Some(client) = self.get_client(realm_id, caller)? else {
            return Ok(false);
        };
        if Self::refuse_inactive_client(&client).is_err() {
            return Ok(false);
        }
        if client.access_token_authorization() != AccessTokenAuthorization::Embedded {
            return Ok(true);
        }
        // An RFC 8693 exchanged token was issued to the exchanging client,
        // which its outermost `act.sub` records (as the bare UUID, or as the
        // `client_…` subject of an actor token).
        if let Some(act) = claims.act.as_ref() {
            if act.sub == caller.to_string() || act.sub == caller.as_uuid().to_string() {
                return Ok(true);
            }
        }
        let Some(fid) = claims.fid.as_deref() else {
            return Ok(false);
        };
        let Some(bytes) = self
            .storage
            .get(realm_id, &keys::encode_grant_family(fid))
            .map_err(Self::storage_err)?
        else {
            return Ok(false);
        };
        let family: StoredGrantFamily =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        Ok(family.client_id.as_ref() == Some(caller))
    }

    pub(super) fn decide_token_permission_inner(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::DecidePermissionRequest,
    ) -> Result<crate::identity::oidc::DecidePermissionResponse, IdentityError> {
        use crate::identity::oidc::DecidePermissionResponse;
        const DENY: DecidePermissionResponse = DecidePermissionResponse { allowed: false };

        // The token must pass everything `validate_token` checks — signature,
        // realm, audience, species, expiry and `nbf`, JTI revocation, session
        // and its owner — including the two it used to skip here: the
        // audience cutoff of a removed protected resource and the DPoP key
        // blocklist (GA audit 3 C-9). A decision is an acceptance of the
        // token; it must never accept one that `validate_token` refuses.
        let Ok(claims) = self.validate_token(realm_id, &request.token) else {
            return Ok(DENY);
        };

        // RFC 8707 audience check (AUTHORIZATION.md §7.4.3): a resource
        // server that names itself is answered only for a token minted for
        // it. Dropping `resource` let a token for server A be replayed at
        // server B (GA audit 3 C-8).
        if let Some(resource) = request.resource.as_deref() {
            let Ok(resource) = Uri::try_from(resource.to_string()) else {
                return Ok(DENY);
            };
            if !claims.aud.contains(resource.as_str()) {
                return Ok(DENY);
            }
        }

        // Validate requested permission string.
        let Ok(permission) = crate::rbac::Permission::new(&request.permission) else {
            return Ok(DENY);
        };

        // The organisation context is the token's own `oid`, never the
        // caller's choice: a token minted in organisation A was answered with
        // the user's authority in B, and a realm-level token with any
        // organisation's. `organization_id` may only restate the token's
        // organisation; anything else is denied (GA audit 3, round 2).
        let parse_org = |o: &str| {
            uuid::Uuid::parse_str(o.strip_prefix("org_").unwrap_or(o))
                .ok()
                .map(crate::core::OrganizationId::new)
        };
        let token_org = claims.oid.as_deref().and_then(parse_org);
        if let Some(requested) = request.organization_id.as_deref() {
            let requested = parse_org(requested);
            if requested.is_none() || requested != token_org {
                return Ok(DENY);
            }
        }
        let org_id = self.active_org_context(realm_id, token_org);

        // The TOKEN's live authority, not the user's (GA audit 3 B-2 / C-8):
        // the token client's claim profile, every permission-bearing scope,
        // and the delegated cap of an `act` token. A client-credentials token
        // has no user and resolves to nothing. Any resolution error denies.
        let Ok(authority) =
            self.live_token_authority_inner(realm_id, &claims, org_id.as_ref(), None)
        else {
            return Ok(DENY);
        };
        Ok(DecidePermissionResponse {
            allowed: authority
                .permissions
                .iter()
                .any(|p| p.as_str() == permission.as_str()),
        })
    }

    /// Engine half of [`IdentityEngine::live_token_authority`] (GA audit 3
    /// B-2 / C-8): what an `Embedded` token issued to the same client for the
    /// same grant would carry, resolved now. `claims` are already validated.
    pub(super) fn live_token_authority_inner(
        &self,
        realm_id: &RealmId,
        claims: &TokenClaims,
        org_id: Option<&crate::core::OrganizationId>,
        narrow_scope: Option<&str>,
    ) -> Result<crate::identity::oidc::LiveTokenAuthority, IdentityError> {
        use crate::identity::oidc::LiveTokenAuthority;

        let rbac_err = |e: RbacError| match e {
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
        };

        // A token whose subject is not a user of this realm — a
        // client-credentials token, or a user deleted since — holds no user
        // authority.
        let Ok(user_id) = Self::parse_user_id_claim(claims) else {
            return Ok(LiveTokenAuthority::default());
        };
        let Some(user) = self.get_user(realm_id, &user_id)? else {
            return Ok(LiveTokenAuthority::default());
        };

        // The client the token was issued to selects the claim profile, as it
        // did at issuance. A token that names none is a first-party session
        // token, judged as the issuing path's first-party sentinel. A claim
        // naming an unparseable or unknown client fails closed.
        let issued_to = match claims.client_id() {
            None => None,
            Some(raw) => {
                let Ok(client_id) = raw.parse::<ClientId>() else {
                    return Ok(LiveTokenAuthority::default());
                };
                match self.get_client(realm_id, &client_id)? {
                    Some(client) => Some(client),
                    None => return Ok(LiveTokenAuthority::default()),
                }
            }
        };
        let sentinel = OAuthClient::new(
            ClientId::generate(),
            "session".to_string(),
            Vec::new(),
            self.clock.now(),
        );
        let client = issued_to.as_ref().unwrap_or(&sentinel);

        // Every permission-bearing scope of the token narrows (OIDC scopes and
        // scopes the realm registry does not know neither narrow nor widen);
        // the caller's own filter (`/v1/me/permissions?scope=`) can only
        // narrow further.
        let token_scopes: Vec<String> = claims
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();
        let mut resolved = self
            .rbac
            .resolve_for_granted_scopes(&user_id, realm_id, org_id, &token_scopes)
            .map_err(rbac_err)?;
        if let Some(narrow) = narrow_scope {
            let admitted: BTreeSet<crate::rbac::Permission> = self
                .rbac
                .resolve_permissions(&user_id, realm_id, org_id, Some(narrow))
                .map_err(rbac_err)?
                .permissions
                .into_iter()
                .collect();
            resolved.permissions.retain(|p| admitted.contains(p));
        }

        let granted_scopes: BTreeSet<String> = token_scopes.into_iter().collect();
        let (mut roles, mut groups, mut permissions, _custom) = self.apply_claim_profile(
            realm_id,
            &user,
            client,
            &resolved,
            &granted_scopes,
            claims.oid.as_deref(),
            ClaimTarget::AccessToken,
        );

        // A delegated token (RFC 8693 `act`) carries the intersection fixed
        // at exchange (AUTHORIZATION.md §16): the actor never gains more than
        // it was delegated, and roles/groups describe the subject, not the
        // delegation — exactly as the exchanged token itself is minted.
        if claims.act.is_some() {
            permissions.retain(|p| claims.permissions.contains(p));
            roles.clear();
            groups.clear();
        }

        Ok(LiveTokenAuthority {
            roles,
            groups,
            permissions,
        })
    }

    /// Whether `client` (its `mfa_required`) or one of `user_id`'s roles
    /// (listed in the realm's `mfa_required_roles`) demands a second factor —
    /// the engine twin of the web layer's `client_or_role_requires_mfa`.
    /// A lookup failure is returned, so the caller refuses.
    fn client_or_role_requires_mfa(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client: &OAuthClient,
    ) -> Result<bool, IdentityError> {
        if client.mfa_required() == Some(true) {
            return Ok(true);
        }
        let required_roles = self
            .get_realm(realm_id)?
            .and_then(|realm| realm.config().mfa_required_roles.clone())
            .unwrap_or_default();
        if required_roles.is_empty() {
            return Ok(false);
        }
        let rbac_err = |e: RbacError| IdentityError::Internal {
            reason: format!("rbac lookup failed: {e}"),
        };
        for assignment in self
            .rbac
            .list_user_assignments(realm_id, user_id)
            .map_err(rbac_err)?
        {
            let role = self
                .rbac
                .get_role(realm_id, &assignment.role_id)
                .map_err(rbac_err)?;
            if role.is_some_and(|r| required_roles.iter().any(|req| req == &r.name)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ===== UserInfo (OIDC Core §5.3) =====

    /// Resolves the client an access token was issued to, for claim-release
    /// gate evaluation on `/userinfo` (GA audit M10).
    ///
    /// Reads the RFC 9068 `client_id` claim, falling back to the grant
    /// family's owner for a token minted before that claim existed. `None`
    /// means no client was issued the token — a first-party session token.
    /// A token naming a client that no longer exists is judged as a
    /// third-party client, never as first-party.
    fn userinfo_client(
        &self,
        realm_id: &RealmId,
        claims: &TokenClaims,
    ) -> Result<Option<OAuthClient>, IdentityError> {
        let named: Option<ClientId> = if let Some(raw) = claims.client_id() {
            Some(
                raw.parse::<ClientId>()
                    .map_err(|_| IdentityError::InvalidToken)?,
            )
        } else if let Some(fid) = claims.fid.as_deref() {
            self.storage
                .get(realm_id, &keys::encode_grant_family(fid))
                .map_err(Self::storage_err)?
                .and_then(|bytes| serde_json::from_slice::<StoredGrantFamily>(&bytes).ok())
                .and_then(|family| family.client_id)
        } else {
            None
        };
        let Some(client_id) = named else {
            return Ok(None);
        };
        if let Some(client) = self.get_client(realm_id, &client_id)? {
            return Ok(Some(client));
        }
        let mut orphan = OAuthClient::new(
            client_id,
            "unknown".to_string(),
            Vec::new(),
            self.clock.now(),
        );
        orphan.set_trust_level(crate::identity::ClientTrustLevel::ThirdParty);
        Ok(Some(orphan))
    }

    pub(super) fn userinfo_inner(
        &self,
        realm_id: &RealmId,
        access_token: &str,
    ) -> Result<crate::identity::oidc::UserInfoResponse, IdentityError> {
        // 1. Validate the access token
        let claims = self.validate_token(realm_id, access_token)?;

        // 2. Ensure it's an access token
        if claims.token_type != "access" {
            return Err(IdentityError::InvalidToken);
        }

        // 3. Parse user_id from sub claim
        let user_id_str = claims
            .sub
            .strip_prefix("user_")
            .ok_or(IdentityError::InvalidToken)?;
        let user_uuid =
            uuid::Uuid::parse_str(user_id_str).map_err(|_| IdentityError::InvalidToken)?;
        let user_id = crate::core::UserId::new(user_uuid);

        // 4. Look up the user
        let user = self
            .get_user(realm_id, &user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        let scope_set: BTreeSet<String> = claims
            .scope
            .as_deref()
            .unwrap_or("openid")
            .split_whitespace()
            .map(str::to_string)
            .collect();
        // Evaluate the claim-release gates against the client the token was
        // issued to (GA audit M10). The old lookup read `aud` with a `client_`
        // prefix that access tokens never carry, so every caller was judged
        // as the first-party sentinel and `first_party_only` claims reached
        // third-party clients.
        let client = self.userinfo_client(realm_id, &claims)?;
        let empty_client = OAuthClient::new(
            ClientId::generate(),
            "userinfo".to_string(),
            Vec::new(),
            self.clock.now(),
        );
        let resolved = self
            .rbac
            .resolve_permissions(&user_id, realm_id, None, None)
            .map_err(|e| match e {
                RbacError::TokenSizeExceeded {
                    limit,
                    limit_value,
                    actual,
                } => IdentityError::TokenTooLarge {
                    limit: format!("userinfo_{limit}"),
                    limit_value,
                    actual,
                },
                e => IdentityError::Internal {
                    reason: format!("rbac resolve failed: {e}"),
                },
            })?;
        let (_roles, _groups, _permissions, custom) = self.apply_claim_profile(
            realm_id,
            &user,
            client.as_ref().unwrap_or(&empty_client),
            &resolved,
            &scope_set,
            claims.oid.as_deref(),
            ClaimTarget::UserInfo,
        );

        let email = custom
            .get("email")
            .and_then(|value| value.as_str().map(str::to_string));
        // The account's own verification state, released with the address it
        // describes (AUTHZ_EXPANSION "Verification attestation": always
        // sourced from canonical user state). This asserted `true` for every
        // token carrying the `email` scope, so an operator-created, SCIM or
        // federated account's unproven address reached relying parties as
        // verified (GA audit round 3, B-8).
        let email_verified = email.as_ref().map(|_| user.email_verified());
        Ok(crate::identity::oidc::UserInfoResponse {
            // `claims` is an `Arc<TokenClaims>` (HEA-1771); clone the owned field.
            sub: claims.sub.clone(),
            email,
            email_verified,
            name: custom
                .get("name")
                .and_then(|value| value.as_str().map(str::to_string)),
            custom: custom
                .into_iter()
                .filter(|(key, _)| key != "email" && key != "name")
                .collect(),
        })
    }

    pub(super) fn authenticate_oauth_client_inner(
        &self,
        realm_id: &RealmId,
        client_id: &ClientId,
        client_secret: &str,
    ) -> Result<(), IdentityError> {
        self.refuse_secrets_in_fapi_advanced_realm(realm_id)?;
        let client_key = keys::encode_oauth_client(client_id);
        let client_bytes = self
            .storage
            .get(realm_id, &client_key)
            .map_err(Self::storage_err)?;
        // 22.25 (audit 2026-08-28 §4.25#3): this used to `?`-return on the
        // missing client and again on the missing hash, both before any
        // hashing. An unregistered `client_id` therefore answered in
        // microseconds while a registered confidential one answered in
        // Argon2id-milliseconds — a clean existence-and-type oracle over an
        // unauthenticated endpoint. A secret was presented, so one
        // verification runs on every arm before the answer is decided.
        let existing: Option<OAuthClient> = client_bytes
            .map(|bytes| {
                serde_json::from_slice::<OAuthClient>(&bytes).map_err(|e| {
                    IdentityError::Serialization {
                        reason: e.to_string(),
                    }
                })
            })
            .transpose()?;
        let stored_hash = existing.as_ref().and_then(OAuthClient::client_secret_hash);
        let matched = Self::verify_presented_client_secret(stored_hash, client_secret)?;
        // Only now is the outcome decided — every arm has already paid for the
        // same single verification.
        let Some(client) = existing.as_ref() else {
            return Err(IdentityError::InvalidClient);
        };
        if client.client_secret_hash().is_none() || !matched {
            return Err(IdentityError::InvalidClientSecret);
        }
        Self::refuse_secret_for_fapi2_client(client)
    }

    /// Refuses secret-based and public (`none`) client authentication in a
    /// realm whose FAPI profile is Advanced (`docs/specs/OIDC.md` §2.1.2 item
    /// 6: only `private_key_jwt`). Runs before any secret is hashed, on every
    /// arm alike: the answer depends on the realm, never on the client.
    pub(super) fn refuse_secrets_in_fapi_advanced_realm(
        &self,
        realm_id: &RealmId,
    ) -> Result<(), IdentityError> {
        use crate::identity::types::FapiProfile;
        let advanced = self
            .get_realm(realm_id)?
            .is_some_and(|realm| realm.config().fapi_profile == Some(FapiProfile::Advanced));
        if advanced {
            return Err(IdentityError::PrivateKeyJwtRequired);
        }
        Ok(())
    }

    /// Refuses a FAPI 2.0 client that authenticated with a secret (it may hold
    /// none — registration refuses one — but a secret set by any other route
    /// must not authenticate it). Called only AFTER the secret verified, so
    /// the refusal tells nothing to a caller who does not hold it.
    fn refuse_secret_for_fapi2_client(client: &OAuthClient) -> Result<(), IdentityError> {
        if client.profile().is_fapi2() {
            return Err(IdentityError::PrivateKeyJwtRequired);
        }
        Ok(())
    }

    /// Verifies a **presented** client secret, doing the same amount of
    /// work whether or not `stored_hash` exists (22.25).
    ///
    /// A stored hash is verified by its format
    /// ([`credentials::verify_client_secret`]): a Hearth-generated secret is
    /// one SHA-256, a caller-chosen or legacy one is Argon2id. When the client
    /// is unknown, or is a public client with no stored secret, the presented
    /// secret costs one FAST verification against a dummy — the cost of the
    /// common, generated-secret arm — and the answer is `false`.
    ///
    /// The dummy is deliberately not Argon2id (26.43 follow-up). Every
    /// server-issued secret is now on the fast format, so an Argon2id dummy
    /// would make an unknown `client_id` measurably SLOWER than a real one
    /// (the existence oracle 22.25 closed, inverted) and let anyone burn an
    /// Argon2id run per request with random client ids. The residual: a
    /// client still holding an Argon2id hash (caller-chosen via gRPC,
    /// `hearth.yaml`, a migration import, or created before this change) is
    /// slower to verify than the other arms, which reveals that such a client
    /// exists. Rotating its secret moves it onto the fast format.
    ///
    /// Callers must decide the outcome *after* this returns; returning early
    /// on a missing client or missing hash is exactly the bug this closes.
    ///
    /// An Argon2id verification runs behind the process-wide KDF admission
    /// gate: the client ids of `hearth.yaml` applications are UUID v5 values
    /// anyone can compute, so without the gate an unauthenticated caller could
    /// force one Argon2id run per request. The protocol layer reaches this
    /// through the async entry points in [`crate::identity::client_auth`],
    /// which verify the secret inside the gate (waiting for a permit
    /// asynchronously) and run the engine call in a scope carrying the result:
    /// here that result is used, and a hash the scope has no result for (a
    /// secret rotated between the entry point's lookup and this call) is NOT
    /// hashed on the caller's thread — the call fails and the entry point
    /// re-dispatches it through the gate. A direct synchronous call outside any
    /// scope (a test, a caller that bypassed the entry points) takes a permit
    /// only if one is free right now and otherwise sheds — it never waits,
    /// because waiting from synchronous code on a runtime is what deadlocked
    /// the runtime. When the gate sheds, this returns
    /// [`IdentityError::KdfOverloaded`] and the protocol layer answers `503`
    /// with `Retry-After`. The fast format never touches the gate.
    pub(super) fn verify_presented_client_secret(
        stored_hash: Option<&str>,
        presented: &str,
    ) -> Result<bool, IdentityError> {
        match stored_hash {
            Some(hash) if credentials::is_fast_client_secret_hash(hash) => {
                credentials::verify_client_secret(presented.as_bytes(), hash)
            }
            Some(hash) => {
                match crate::identity::client_auth::scoped_argon2_verification(
                    hash,
                    presented.as_bytes(),
                ) {
                    crate::identity::client_auth::ScopedArgon2::Verified(matched) => {
                        return Ok(matched)
                    }
                    // Never hash on the entry point's (worker) thread: fail
                    // the call; the entry point verifies against this hash
                    // through the gate and runs the call again. The error is
                    // discarded there.
                    crate::identity::client_auth::ScopedArgon2::Redispatch => {
                        return Err(IdentityError::KdfOverloaded {
                            retry_after: std::time::Duration::from_secs(1),
                        })
                    }
                    crate::identity::client_auth::ScopedArgon2::NotScoped => {}
                }
                let secret = zeroize::Zeroizing::new(presented.as_bytes().to_vec());
                let hash = hash.to_string();
                match crate::identity::gate()
                    .try_run_inline(move || credentials::verify_raw_secret(&secret, &hash))
                {
                    Ok(verified) => verified,
                    Err(crate::identity::KdfGateError::Overloaded { retry_after }) => {
                        Err(IdentityError::KdfOverloaded { retry_after })
                    }
                    Err(e) => Err(IdentityError::Internal {
                        reason: format!("client secret verification failed: {e}"),
                    }),
                }
            }
            None => {
                credentials::verify_dummy_client_secret(presented.as_bytes());
                Ok(false)
            }
        }
    }

    pub(super) fn list_clients_inner(
        &self,
        realm_id: &RealmId,
        page: &crate::core::PageRequest,
    ) -> Result<crate::core::PagedResult<OAuthClient>, IdentityError> {
        let prefix = keys::oauth_client_scan_prefix();
        let (entries, total) = self
            .storage
            .scan_prefix_paged(realm_id, &prefix, page.offset, page.limit, 0)
            .map_err(Self::storage_err)?;

        let mut items = Vec::with_capacity(entries.len());
        for entry in &entries {
            let client: OAuthClient =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            items.push(client);
        }

        Ok(crate::core::PagedResult::new(
            items,
            total,
            page.offset,
            page.limit,
        ))
    }

    pub(super) fn get_client_inner(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<Option<OAuthClient>, IdentityError> {
        let key = keys::encode_oauth_client(client_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?;

        match bytes {
            Some(data) => {
                let client: OAuthClient =
                    serde_json::from_slice(&data).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }

    /// Refuses a client that is not [`ApplicationStatus::Active`] with
    /// [`IdentityError::InvalidClient`].
    ///
    /// GA audit B9: a client archived by removal from `hearth.yaml` must stop
    /// working on every grant, not only `/authorize`. Every path that loads a
    /// client to act for it calls this (or refuses an archived client in its
    /// own uniform error), so an archived client is indistinguishable from an
    /// unknown one.
    pub(super) fn refuse_inactive_client(client: &OAuthClient) -> Result<(), IdentityError> {
        if client.status() == ApplicationStatus::Active {
            Ok(())
        } else {
            Err(IdentityError::InvalidClient)
        }
    }

    /// RFC 8693 per-client policy (GA audit M8): the exchanging client must be
    /// a registered [`ApplicationStatus::Active`] client (else
    /// `invalid_client`), must list the token-exchange grant in its
    /// `grant_types`, and must be confidential (else `unauthorized_client`).
    ///
    /// A public client "authenticates" by its `client_id` alone, which is
    /// public by construction, so letting one exchange let anyone holding a
    /// subject token re-mint it under that client's name.
    pub(super) fn require_token_exchange_client(
        &self,
        realm_id: &RealmId,
        client_id: &ClientId,
    ) -> Result<(), IdentityError> {
        const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
        let client = self
            .get_client(realm_id, client_id)?
            .ok_or(IdentityError::InvalidClient)?;
        Self::refuse_inactive_client(&client)?;
        if client.is_public() {
            return Err(IdentityError::TokenExchangeRejected {
                reason: "token exchange requires a confidential client".to_string(),
                oauth_error: "unauthorized_client",
            });
        }
        if !client
            .grant_types()
            .iter()
            .any(|g| g == TOKEN_EXCHANGE_GRANT)
        {
            return Err(IdentityError::TokenExchangeRejected {
                reason: "client is not registered for the token-exchange grant".to_string(),
                oauth_error: "unauthorized_client",
            });
        }
        Ok(())
    }

    /// Validates one protected-resource registration and returns its
    /// canonical `resource_uri`: shared by the single register call and the
    /// YAML reconcile so both accept, and store, the same thing.
    ///
    /// `resource_uri` must be a valid RFC 8707 resource indicator (see
    /// [`Uri`]: absolute, scheme and host, no userinfo or fragment) with no
    /// surrounding whitespace. The registry keys and stores the canonical
    /// form, which is what exchange `audience` / `resource` values are
    /// canonicalized to before the lookup. Every `mcp:`-prefixed scope must be
    /// `{namespace}:{category}:{action}` (AGENT_AUTH.md §2.6, A-10).
    pub(super) fn validate_protected_resource_request(
        request: &crate::identity::types::RegisterProtectedResourceRequest,
    ) -> Result<Uri, IdentityError> {
        if request.resource_uri.is_empty() {
            return Err(IdentityError::InvalidInput {
                reason: "resource_uri must not be empty".to_string(),
            });
        }
        let canonical = Uri::try_from(request.resource_uri.clone())
            .ok()
            .filter(|_| request.resource_uri == request.resource_uri.trim())
            .ok_or_else(|| IdentityError::InvalidInput {
                reason: "resource_uri must be an absolute URI with a scheme and host, no \
                         userinfo, no fragment and no surrounding whitespace"
                    .to_string(),
            })?;
        crate::identity::mcp::validate_mcp_scope_vocabulary(&request.scopes)
            .map_err(|reason| IdentityError::InvalidInput { reason })?;
        Ok(canonical)
    }

    /// Resolves one RFC 8693 `audience` or `resource` value to the audience
    /// the exchanged token will carry (GA audit M8), or refuses it with RFC
    /// 8693 §2.2.2 `invalid_target`:
    ///
    /// - a value the subject token already carries in `aud` is narrowing and
    ///   is kept verbatim;
    /// - otherwise it must parse as a resource indicator whose canonical form
    ///   ([`Uri`]) is either already in the subject's `aud` or the
    ///   `resource_uri` of a protected resource registered in the realm, and
    ///   the canonical form is returned — every spelling of a registered URI
    ///   is accepted and minted identically, matching RBAC's resource scope
    ///   lookup.
    /// Resolves an authorization request's RFC 8707 `resource` (at
    /// `/authorize`, over JAR, or pushed with PAR) to the canonical URI of a
    /// protected resource registered in the realm, or refuses it with
    /// [`IdentityError::InvalidTarget`] (RFC 8707 §2 `invalid_target`).
    ///
    /// The resource becomes the `aud` of the code's access token, so an
    /// undeclared value would let a client mint a Hearth-signed token for a
    /// resource server the realm never declared. Every spelling of a
    /// registered URI resolves to its one canonical form (G6).
    pub(super) fn resolve_authorization_resource(
        &self,
        realm_id: &RealmId,
        resource: &str,
    ) -> Result<Uri, IdentityError> {
        let canonical =
            Uri::try_from(resource.to_string()).map_err(|reason| IdentityError::InvalidTarget {
                reason: format!("not a resource indicator: {reason}"),
            })?;
        let registered = self
            .storage
            .get(
                realm_id,
                &keys::encode_resource_server_uri_index(canonical.as_str()),
            )
            .map_err(Self::storage_err)?
            .is_some();
        if registered {
            Ok(canonical)
        } else {
            Err(IdentityError::InvalidTarget {
                reason: "not a registered protected resource".to_string(),
            })
        }
    }

    pub(super) fn resolve_exchange_target(
        &self,
        realm_id: &RealmId,
        subject_aud: &Audience,
        target: &str,
    ) -> Result<String, IdentityError> {
        let rejected = || IdentityError::TokenExchangeRejected {
            reason: "audience/resource is not a registered protected resource".to_string(),
            oauth_error: "invalid_target",
        };
        if subject_aud.contains(target) {
            return Ok(target.to_string());
        }
        let canonical = Uri::try_from(target.to_string()).map_err(|_| rejected())?;
        if subject_aud.contains(canonical.as_str()) {
            return Ok(canonical.as_str().to_string());
        }
        let registered = self
            .storage
            .get(
                realm_id,
                &keys::encode_resource_server_uri_index(canonical.as_str()),
            )
            .map_err(Self::storage_err)?
            .is_some();
        if registered {
            Ok(canonical.as_str().to_string())
        } else {
            Err(rejected())
        }
    }

    pub(super) fn authenticate_client_inner(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        client_secret: Option<&str>,
    ) -> Result<(), IdentityError> {
        // Return InvalidClientSecret (not ClientNotFound) on any failure to
        // prevent client enumeration via error differentiation.
        //
        // 22.25 (audit 2026-08-28 §4.25#3): error *shape* was already uniform,
        // but the amount of work was not. An unknown `client_id` and a public
        // client both returned without hashing, while a registered confidential
        // client paid for one Argon2id verification — so response time revealed
        // both existence and type. The rule below is that hashing work is a
        // function of the caller's own input (did it present a secret?) and
        // never of what the lookup found:
        //
        //   * a secret was presented  → exactly one verification on every arm,
        //     against the stored hash when there is one and against a fast
        //     dummy when there is not (see `verify_presented_client_secret`);
        //   * no secret was presented → no verification on any arm.
        //
        // Costing the no-secret case nothing keeps the public-client token path
        // — the common browser flow, which legitimately authenticates by
        // `client_id` alone — off every hash entirely.
        //
        // A FAPI 2.0 Advanced realm accepts neither a secret nor `none`: this
        // path only ever authenticates one of the two, so it refuses first.
        self.refuse_secrets_in_fapi_advanced_realm(realm_id)?;
        let client = self.get_client(realm_id, client_id)?;

        // B9: an archived client authenticates as nothing. The flag is read
        // here but acted on only after the (input-determined) hashing work,
        // so the refusal costs what any other refusal costs.
        let archived = client
            .as_ref()
            .is_some_and(|c| Self::refuse_inactive_client(c).is_err());

        let Some(secret) = client_secret else {
            return match client.as_ref() {
                // Public client: no secret needed, client_id alone suffices.
                // A secretless client with an assertion key or a JWKS is not
                // public — it authenticates with `private_key_jwt` only.
                Some(c) if c.is_public() && !archived => Ok(()),
                _ => Err(IdentityError::InvalidClientSecret),
            };
        };

        let stored_hash = client.as_ref().and_then(OAuthClient::client_secret_hash);
        let is_public = client.as_ref().is_some_and(OAuthClient::is_public);
        let matched = Self::verify_presented_client_secret(stored_hash, secret)?;
        if archived {
            return Err(IdentityError::InvalidClientSecret);
        }
        if is_public {
            // A stray secret on a public client is ignored, as before.
            return Ok(());
        }
        if !matched {
            return Err(IdentityError::InvalidClientSecret);
        }
        client
            .as_ref()
            .map_or(Ok(()), Self::refuse_secret_for_fapi2_client)
    }

    /// Confidential-only twin of [`Self::authenticate_client_inner`] for the
    /// introspection endpoint (RFC 7662 §2.1, task 26.43).
    ///
    /// Keeps the 22.25 cost rule — hashing work is a function of whether the
    /// caller presented a secret, never of what the lookup found — and differs
    /// only in the decision: a client with no stored hash (public, or
    /// `private_key_jwt`-only) is refused rather than accepted, AFTER the one
    /// verification a presented secret always costs.
    pub(super) fn authenticate_confidential_client_inner(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        client_secret: Option<&str>,
    ) -> Result<(), IdentityError> {
        self.refuse_secrets_in_fapi_advanced_realm(realm_id)?;
        let client = self.get_client(realm_id, client_id)?;
        // No secret: refuse on every arm without hashing. A public client has
        // nothing else to prove, so it cannot pass here.
        let Some(secret) = client_secret else {
            return Err(IdentityError::InvalidClientSecret);
        };
        let stored_hash = client.as_ref().and_then(OAuthClient::client_secret_hash);
        let matched = Self::verify_presented_client_secret(stored_hash, secret)?;
        // `matched` is false whenever there is no stored hash (the dummy never
        // matches), so an unknown or public client is refused here too. An
        // archived client (B9) is refused like an unknown one.
        let archived = client
            .as_ref()
            .is_some_and(|c| Self::refuse_inactive_client(c).is_err());
        if stored_hash.is_none() || !matched || archived {
            return Err(IdentityError::InvalidClientSecret);
        }
        client
            .as_ref()
            .map_or(Ok(()), Self::refuse_secret_for_fapi2_client)
    }

    /// Refuses a client JWKS that is not a bounded set of public signing keys
    /// ([`super::client_jwks::validate_client_jwks`]).
    pub(super) fn check_client_jwks(jwks: &str) -> Result<(), IdentityError> {
        super::client_jwks::validate_client_jwks(jwks).map_err(|reason| {
            IdentityError::InvalidInput {
                reason: format!("invalid jwks: {reason}"),
            }
        })
    }

    /// Refuses an assertion key that is not a base64url-encoded 32-byte
    /// Ed25519 public key.
    pub(super) fn check_assertion_public_key(key: &str) -> Result<(), IdentityError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(key)
            .map_err(|_| IdentityError::InvalidInput {
                reason: "assertion_public_key must be base64url-encoded".to_string(),
            })?;
        if decoded.len() != 32 {
            return Err(IdentityError::InvalidInput {
                reason: "assertion_public_key must be a 32-byte Ed25519 public key".to_string(),
            });
        }
        Ok(())
    }

    /// FAPI 2.0 clients authenticate with `private_key_jwt` only, so a FAPI
    /// 2.0 client must hold no secret and must hold a key Hearth can verify
    /// an assertion with — an inline `jwks` or an assertion key; a `jwks_uri`
    /// is never fetched. A no-op for any other profile.
    pub(super) fn check_fapi2_client_keys(client: &OAuthClient) -> Result<(), IdentityError> {
        if !client.profile().is_fapi2() {
            return Ok(());
        }
        if client.client_secret_hash().is_some() {
            return Err(IdentityError::FapiViolation {
                reason: "FAPI 2.0 clients must not use a client secret; they authenticate with \
                         private_key_jwt"
                    .to_string(),
            });
        }
        if !client.has_verifiable_assertion_keys() {
            return Err(IdentityError::FapiViolation {
                reason: "FAPI 2.0 clients authenticate with private_key_jwt and must register \
                         their public keys inline (jwks); a jwks_uri is not fetched"
                    .to_string(),
            });
        }
        Ok(())
    }

    pub(super) fn update_client_inner(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        request: &crate::identity::oidc::UpdateClientRequest,
    ) -> Result<OAuthClient, IdentityError> {
        let key = keys::encode_oauth_client(client_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ClientNotFound)?;

        let mut client: OAuthClient =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        if let Some(name) = &request.client_name {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "client_name cannot be empty".to_string(),
                });
            }
            client.set_client_name(trimmed.to_string());
        }
        if let Some(uris) = &request.redirect_uris {
            if uris.is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "redirect_uris cannot be empty".to_string(),
                });
            }
            // Audit §4.3#3: re-run the register-time rules. `register_client_inner`
            // routes every redirect URI through `validation::validate_redirect_uri`
            // (no fragment, no wildcard, no dangerous scheme, http only for a
            // loopback host). Applying them only at registration made all four
            // bypassable by register-then-PATCH.
            for uri in uris {
                if uri.trim().is_empty() {
                    return Err(IdentityError::InvalidInput {
                        reason: "redirect URIs must not be empty".to_string(),
                    });
                }
                validation::validate_redirect_uri(uri)?;
            }
            client.set_redirect_uris(uris.clone());
        }
        if let Some(grant_types) = &request.grant_types {
            if grant_types.is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "grant_types cannot be empty".to_string(),
                });
            }
            client.set_grant_types(grant_types.clone());
        }
        if let Some(require) = request.require_consent {
            client.set_require_consent(require);
        }
        if let Some(logo) = &request.client_logo_url {
            client.set_client_logo_url(logo.clone());
        }
        if let Some(slug) = &request.slug {
            client.set_slug(slug.clone());
        }
        if let Some(trust_level) = request.trust_level {
            client.set_trust_level(trust_level);
            client
                .set_require_consent(trust_level == crate::identity::ClientTrustLevel::ThirdParty);
        }
        if let Some(declared_scopes) = &request.declared_scopes {
            client.set_declared_scopes(declared_scopes.clone());
        }
        if let Some(consent_spans_orgs) = request.consent_spans_orgs {
            client.set_consent_spans_orgs(consent_spans_orgs);
        }
        if let Some(uri) = &request.backchannel_logout_uri {
            if let Some(value) = uri {
                validation::validate_logout_uri("backchannel_logout_uri", value, false)?;
            }
            client.set_backchannel_logout_uri(uri.clone());
        }
        if let Some(uri) = &request.frontchannel_logout_uri {
            if let Some(value) = uri {
                validation::validate_logout_uri("frontchannel_logout_uri", value, true)?;
            }
            client.set_frontchannel_logout_uri(uri.clone());
        }
        if let Some(uris) = &request.post_logout_redirect_uris {
            client.set_post_logout_redirect_uris(uris.clone());
        }
        // B9 / L5: the transition into `Archived` revokes what the client
        // holds. Judged before the status is overwritten; acted on after the
        // record is written, so a rotation racing this sees the new status.
        let archiving = request
            .status
            .is_some_and(|s| s != ApplicationStatus::Active)
            && client.status() == ApplicationStatus::Active;
        if let Some(status) = request.status {
            client.set_status(status);
        }
        if let Some(pk) = &request.assertion_public_key {
            // Validate base64url decodes to exactly 32 bytes (Ed25519 public key)
            if let Some(key_str) = pk {
                Self::check_assertion_public_key(key_str)?;
            }
            client.set_assertion_public_key(pk.clone());
        }
        if let Some(mode) = request.access_token_authorization {
            client.set_access_token_authorization(mode);
        }
        if let Some(alg_opt) = &request.authorization_signed_response_alg {
            if let Some(alg) = alg_opt {
                if alg != "EdDSA" {
                    return Err(IdentityError::InvalidInput {
                        reason: format!(
                            "unsupported authorization_signed_response_alg '{alg}'; supported: EdDSA"
                        ),
                    });
                }
            }
            client.set_authorization_signed_response_alg(alg_opt.clone());
        }
        if let Some(jwks) = &request.jwks {
            if let Some(jwks) = jwks.as_deref() {
                Self::check_client_jwks(jwks)?;
            }
            client.set_jwks(jwks.clone());
        }
        if let Some(profile) = request.profile {
            client.set_profile(profile);
        }
        // Judged on the client as it will be written: turning FAPI 2.0 on for
        // a client without keys (what `hearth.yaml` reconcile did for
        // `profile: fapi2`), or removing a FAPI 2.0 client's last key, would
        // leave a client that cannot authenticate. Only a change to the
        // profile or the keys is judged, so an unrelated update (a rename) of
        // a client stored before this rule still succeeds — and that client
        // fails closed anyway (`OAuthClient::requires_client_assertion`).
        if request.profile.is_some()
            || request.jwks.is_some()
            || request.assertion_public_key.is_some()
        {
            Self::check_fapi2_client_keys(&client)?;
        }
        if let Some(mfa_req) = request.mfa_required {
            client.set_mfa_required(mfa_req);
        }
        if let Some(cors) = &request.cors_origins {
            client.set_cors_origins(cors.clone());
        }
        // ID-token signing algorithm (task 26.55): validated, and the realm's
        // RSA key provisioned, before the change is persisted. `client` already
        // carries any profile change above, so FAPI 2.0 (§5.4.1: no RS256) is
        // judged on the client as it will be written — which also refuses
        // moving an RS256 client to the FAPI 2.0 profile.
        let fapi = client.profile().is_fapi2() || self.realm_enforces_fapi(realm_id)?;
        if let Some(alg) = request.id_token_signed_response_alg.as_deref() {
            client.set_id_token_signed_response_alg(self.resolve_client_id_token_alg(
                realm_id,
                Some(alg),
                fapi,
            )?);
        } else if request.profile.is_some_and(ClientProfile::is_fapi2) {
            Self::refuse_rs256_under_fapi(client.id_token_signed_response_alg(), fapi)?;
        }

        let updated_bytes =
            serde_json::to_vec(&client).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &key, &updated_bytes)
            .map_err(Self::storage_err)?;
        if archiving {
            self.revoke_client_grants(realm_id, client_id)?;
        }

        self.record_audit(
            realm_id,
            None,
            AuditAction::ClientUpdated,
            "client",
            &client_id.as_uuid().to_string(),
        )?;

        Ok(client)
    }

    pub(super) fn regenerate_client_secret_inner(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<String, IdentityError> {
        let key = keys::encode_oauth_client(client_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ClientNotFound)?;

        let mut client: OAuthClient =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        if client.profile().is_fapi2() {
            return Err(IdentityError::FapiViolation {
                reason: "FAPI 2.0 clients must not use client_secret".to_string(),
            });
        }

        if !client.is_confidential() {
            return Err(IdentityError::InvalidInput {
                reason: "cannot regenerate secret for a public client".to_string(),
            });
        }

        // A fresh 256-bit CSPRNG secret, stored in the fast format — rotation
        // is also how a client with a legacy Argon2id hash moves onto it.
        let secret = crate::identity::oidc::GeneratedClientSecret::generate();
        client.set_client_secret_hash(credentials::hash_generated_client_secret(&secret));

        let updated_bytes =
            serde_json::to_vec(&client).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &key, &updated_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::ClientUpdated,
            "client",
            &client_id.as_uuid().to_string(),
        )?;

        Ok(secret.expose().to_string())
    }

    pub(super) fn delete_client_inner(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_oauth_client(client_id);
        // Verify the client exists first
        self.storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ClientNotFound)?;

        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)?;

        // Cascade: scrub every consent record referencing this client.
        // A consent key is `oauth:consent:{user}:{client}` (legacy) or
        // `oauth:consent:{user}:{client}:{org}:{resource}` (canonical). The
        // client UUID is always the fourth colon-delimited field. The old
        // scrub matched `ends_with(client_uuid)`, which caught only the legacy
        // form — every extended-key consent survived and was handed to the
        // deterministic YAML `ClientId`'s next occupant (audit 2026-08-28
        // §4.20#1). Match the field, not the suffix.
        let consent_prefix = keys::oauth_consent_scan_prefix();
        let consent_end = keys::prefix_end(&consent_prefix);
        let consent_entries = self
            .storage
            .scan(realm_id, &consent_prefix, &consent_end)
            .map_err(Self::storage_err)?;
        let client_uuid_str = client_id.as_uuid().to_string();
        for entry in &consent_entries {
            if let Ok(key_str) = std::str::from_utf8(&entry.key) {
                // Fields: ["oauth", "consent", "{user}", "{client}", ...].
                if key_str.split(':').nth(3) == Some(client_uuid_str.as_str()) {
                    self.storage
                        .delete(realm_id, &entry.key)
                        .map_err(Self::storage_err)?;
                }
            }
        }

        // Cascade: revoke every outstanding grant family issued to this
        // client. Deleting only the client record left its families live
        // while removing the record `rotate_grant_family` reads its
        // confidential-client and FAPI DPoP gates from, so a deleted client's
        // refresh tokens kept rotating with LESS authentication than before
        // the deletion (audit 2026-08-28 §4.16#3).
        self.revoke_client_grants(realm_id, client_id)?;
        self.record_audit(
            realm_id,
            None,
            AuditAction::ClientDeleted,
            "client",
            &client_id.as_uuid().to_string(),
        )?;
        Ok(())
    }

    /// The revoked-JTI projection id under which a client's `client_credentials`
    /// cutoff is stored (GA audit L5). Real `jti`s are UUIDs, so the prefix
    /// cannot collide with one.
    pub(super) fn client_token_cutoff_id(client_id: &crate::core::ClientId) -> String {
        format!("{CLIENT_TOKEN_CUTOFF_PREFIX}{}", client_id.as_uuid())
    }

    /// Kills everything a client holds when it is archived or deleted:
    ///
    /// 1. every grant family issued to it is marked revoked (its refresh
    ///    tokens stop rotating — GA audit B9, audit 2026-08-28 §4.16#3);
    /// 2. a client-wide cutoff is projected into the revoked-JTI cache, so
    ///    every sessionless access token issued to it so far (the
    ///    `client_credentials` and jwt-bearer grants, whose `sub` is the
    ///    client) stops validating immediately instead of at expiry (GA audit
    ///    L5). The cutoff's value is the latest `exp` any such token can
    ///    carry; `validate_token` refuses a token whose `exp` is not after it,
    ///    so a token issued after a restore is unaffected, and the row
    ///    self-evicts once every covered token has expired.
    pub(super) fn revoke_client_grants(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<(), IdentityError> {
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        let cutoff_exp = now_secs.saturating_add(self.config.token.access_token_ttl_secs);
        let cutoff_id = Self::client_token_cutoff_id(client_id);
        // Durable first: the cache insert would otherwise mask a failed write
        // (the cutoff would vanish on restart while the operator believed the
        // tokens were dead). Same order as the sessionless revoke arm.
        self.storage
            .put(
                realm_id,
                &keys::encode_revoked_jti(&cutoff_id),
                &cutoff_exp.to_le_bytes(),
            )
            .map_err(Self::storage_err)?;
        self.insert_revoked_jti_cache(realm_id, &cutoff_id, cutoff_exp);

        self.revoke_grant_families_where(realm_id, |family| {
            family.client_id.as_ref() == Some(client_id)
        })
    }

    /// Marks revoked every not-yet-revoked grant family in the realm that
    /// `matches`, so its refresh tokens stop rotating.
    ///
    /// Each family is re-read and written under its rotation lock, so the
    /// revocation neither clobbers a concurrent rotation's hash write nor is
    /// clobbered by it.
    pub(super) fn revoke_grant_families_where(
        &self,
        realm_id: &RealmId,
        matches: impl Fn(&StoredGrantFamily) -> bool,
    ) -> Result<(), IdentityError> {
        let family_prefix = keys::grant_family_scan_prefix();
        let family_end = keys::prefix_end(&family_prefix);
        let family_entries = self
            .storage
            .scan(realm_id, &family_prefix, &family_end)
            .map_err(Self::storage_err)?;
        for entry in &family_entries {
            let listed: StoredGrantFamily =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if !matches(&listed) {
                continue;
            }
            let lock = self.grant_family_lock(realm_id, &listed.family_id);
            // INVARIANT: guard held only across the sync re-read + revoke-write window; no .await in scope.
            let _guard = lock.lock().expect("grant family lock poisoned");
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
        }
        Ok(())
    }

    /// The revoked-JTI projection id of the audience cutoff for `aud`:
    /// `aud-cutoff:` followed by the first 16 bytes of SHA-256(`aud`) in hex.
    ///
    /// Hashed so the id has a fixed length (80 bytes with the realm prefix)
    /// that always fits `StackKeyBuf` — `validate_token` derives it for every
    /// `aud` entry without allocating. Real `jti`s are UUIDs, so the prefix
    /// cannot collide with one.
    pub(super) fn audience_token_cutoff_id(aud: &str) -> String {
        let mut hex = [0u8; AUDIENCE_CUTOFF_HASH_HEX_LEN];
        audience_cutoff_hash_hex(aud, &mut hex);
        let mut id = String::with_capacity(AUDIENCE_TOKEN_CUTOFF_PREFIX.len() + hex.len());
        id.push_str(AUDIENCE_TOKEN_CUTOFF_PREFIX);
        // INVARIANT: `audience_cutoff_hash_hex` writes only ASCII hex digits.
        id.push_str(std::str::from_utf8(&hex).unwrap_or_default());
        id
    }

    /// Stops every token bound to a protected resource that is being removed
    /// (AGENT_AUTH.md §2.5):
    ///
    /// 1. an audience cutoff for `resource_uri` (canonical) is projected into
    ///    the revoked-JTI cache. Its value is the latest `exp` any token minted
    ///    for the resource so far can carry; `validate_token` and introspection
    ///    refuse a token that names the resource in `aud` and whose `exp` is
    ///    not after it. A token minted after the resource is re-registered is
    ///    unaffected, and the row self-evicts once every covered token has
    ///    expired;
    /// 2. every grant family bound to the resource is revoked, so its refresh
    ///    tokens cannot mint fresh (post-cutoff) tokens for it.
    ///
    /// Tokens whose `aud` does not include Hearth's own audience are never
    /// validated by Hearth; a resource server that verifies them offline keeps
    /// accepting them until they expire.
    pub(super) fn revoke_resource_tokens(
        &self,
        realm_id: &RealmId,
        resource_uri: &Uri,
    ) -> Result<(), IdentityError> {
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        // Exchange tokens are capped by the global TTL, code/refresh tokens by
        // the realm's effective TTL: cover the longer of the two.
        let (realm_access_ttl, _) = self.effective_token_ttl_secs(realm_id);
        let ttl = realm_access_ttl.max(self.config.token.access_token_ttl_secs);
        let cutoff_exp = now_secs.saturating_add(ttl);
        let cutoff_id = Self::audience_token_cutoff_id(resource_uri.as_str());
        // Durable first, as for the client cutoff.
        self.storage
            .put(
                realm_id,
                &keys::encode_revoked_jti(&cutoff_id),
                &cutoff_exp.to_le_bytes(),
            )
            .map_err(Self::storage_err)?;
        self.insert_revoked_jti_cache(realm_id, &cutoff_id, cutoff_exp);
        self.revoke_grant_families_where(realm_id, |family| {
            family.resources.iter().any(|r| r == resource_uri)
        })
    }

    // ===== OAuth consent =====

    pub(super) fn get_consent_inner(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
    ) -> Result<Option<ConsentRecord>, IdentityError> {
        // Legacy key (`oauth:consent:{user}:{client}`) — checked first for
        // backward compatibility with records written before the extended key
        // schema was introduced.
        let legacy_key = keys::encode_consent_key(user_id, client_id);
        if let Some(bytes) = self
            .storage
            .get(realm_id, &legacy_key)
            .map_err(Self::storage_err)?
        {
            let rec: ConsentRecord =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            return Ok(Some(rec));
        }

        // Extended key (`oauth:consent:{user}:{client}:_realm:_default`) —
        // the canonical form for new records.
        let extended_key = keys::encode_consent_key_extended(
            user_id,
            client_id,
            keys::CONSENT_ORG_KEY_REALM,
            keys::CONSENT_RESOURCE_KEY_DEFAULT,
        );
        if let Some(bytes) = self
            .storage
            .get(realm_id, &extended_key)
            .map_err(Self::storage_err)?
        {
            let rec: ConsentRecord =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            return Ok(Some(rec));
        }

        Ok(None)
    }

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
        let mut out = Vec::with_capacity(entries.len());
        for entry in &entries {
            let rec: ConsentRecord =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            // Join with current client. Orphaned consents (client deleted)
            // are filtered out — callers see only actionable entries.
            let client_key = keys::encode_oauth_client(&rec.client_id);
            let Some(client_bytes) = self
                .storage
                .get(realm_id, &client_key)
                .map_err(Self::storage_err)?
            else {
                continue;
            };
            let client: OAuthClient = serde_json::from_slice(&client_bytes).map_err(|e| {
                IdentityError::Serialization {
                    reason: e.to_string(),
                }
            })?;
            out.push(ConsentListEntry {
                record: rec,
                client_name: client.client_name().to_string(),
                client_logo_url: client.client_logo_url().map(str::to_string),
            });
        }
        Ok(out)
    }

    pub(super) fn grant_consent_inner(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
        approved_scopes: &[String],
    ) -> Result<ConsentRecord, IdentityError> {
        // Verify the client exists — avoids orphan consents.
        let client_key = keys::encode_oauth_client(client_id);
        self.storage
            .get(realm_id, &client_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ClientNotFound)?;

        let now = self.clock.now();

        // Use the extended key as the canonical storage location for new
        // records. The realm-level sentinel values (`_realm`, `_default`)
        // are used when no org/resource context is supplied by the caller.
        let key = keys::encode_consent_key_extended(
            user_id,
            client_id,
            keys::CONSENT_ORG_KEY_REALM,
            keys::CONSENT_RESOURCE_KEY_DEFAULT,
        );

        // Also check the legacy key so that pre-migration records are merged
        // rather than duplicated.
        let legacy_key = keys::encode_consent_key(user_id, client_id);
        let existing_bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .or_else(|| self.storage.get(realm_id, &legacy_key).unwrap_or_default());

        let mut record = if let Some(bytes) = existing_bytes {
            let mut rec: ConsentRecord =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            rec.merge_scopes(approved_scopes, now);
            rec
        } else {
            ConsentRecord::new(
                user_id.clone(),
                client_id.clone(),
                approved_scopes.to_vec(),
                now,
            )
        };

        // Compute and store the scope digest so future authorize /
        // refresh_token calls can detect stale consent.
        record.scope_digest = Self::compute_scope_digest(&record.granted_scopes);

        let bytes = serde_json::to_vec(&record).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)?;

        // Remove the legacy key if it existed to avoid stale duplicates.
        let _ = self.storage.delete(realm_id, &legacy_key);

        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::ConsentGranted,
            "consent",
            &client_id.as_uuid().to_string(),
        )?;

        Ok(record)
    }

    /// Revokes every outstanding refresh-token grant family this user holds for
    /// `client_id`.
    ///
    /// Consent is the authority the grant was issued under. Deleting the
    /// consent record alone left the families live, and
    /// `rotate_grant_family`'s consent check only compares scope digests *when
    /// a record exists* — so deleting the record removed the only thing that
    /// check could fail on and the application refreshed forever
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

    pub(super) fn revoke_consent_inner(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
    ) -> Result<(), IdentityError> {
        // Try the extended key (canonical location for new records) first.
        let extended_key = keys::encode_consent_key_extended(
            user_id,
            client_id,
            keys::CONSENT_ORG_KEY_REALM,
            keys::CONSENT_RESOURCE_KEY_DEFAULT,
        );
        let extended_exists = self
            .storage
            .get(realm_id, &extended_key)
            .map_err(Self::storage_err)?
            .is_some();
        if extended_exists {
            self.storage
                .delete(realm_id, &extended_key)
                .map_err(Self::storage_err)?;
            // Also clean up any lingering legacy key.
            let legacy_key = keys::encode_consent_key(user_id, client_id);
            let _ = self.storage.delete(realm_id, &legacy_key);
            // The grant families issued under this consent are dead with it
            // (audit 2026-08-28 §4.16#11).
            self.revoke_grant_families_for_consent(realm_id, user_id, Some(client_id))?;
            self.record_audit(
                realm_id,
                Some(&AuditContext {
                    actor: Actor::User(user_id.clone()),
                    metadata: None,
                }),
                AuditAction::ConsentRevoked,
                "consent",
                &client_id.as_uuid().to_string(),
            )?;
            return Ok(());
        }

        // Fall back to the legacy key for pre-migration records.
        let legacy_key = keys::encode_consent_key(user_id, client_id);
        let legacy_exists = self
            .storage
            .get(realm_id, &legacy_key)
            .map_err(Self::storage_err)?
            .is_some();
        if legacy_exists {
            self.storage
                .delete(realm_id, &legacy_key)
                .map_err(Self::storage_err)?;
            // The grant families issued under this consent are dead with it
            // (audit 2026-08-28 §4.16#11).
            self.revoke_grant_families_for_consent(realm_id, user_id, Some(client_id))?;
            self.record_audit(
                realm_id,
                Some(&AuditContext {
                    actor: Actor::User(user_id.clone()),
                    metadata: None,
                }),
                AuditAction::ConsentRevoked,
                "consent",
                &client_id.as_uuid().to_string(),
            )?;
            return Ok(());
        }

        Err(IdentityError::ConsentNotFound)
    }

    pub(super) fn revoke_all_consents_for_user_inner(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<usize, IdentityError> {
        let prefix = keys::encode_consent_prefix_for_user(user_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let count = entries.len();
        for entry in &entries {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }
        // Every grant family this user holds against any client was issued
        // under one of the consents just deleted (audit 2026-08-28 §4.16#11).
        self.revoke_grant_families_for_consent(realm_id, user_id, None)?;
        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::ConsentRevoked,
            "consent",
            "all",
        )?;
        Ok(count)
    }

    pub(super) fn put_pending_authorization_inner(
        &self,
        realm_id: &RealmId,
        request: &PendingAuthorizationRequest,
    ) -> Result<String, IdentityError> {
        // 22.27 (audit 2026-08-28 §4.25#5): 128-bit consent ticket; a UUID v4
        // spends six bits on the version/variant and carries only 122.
        let ticket = crate::core::random_secret_hex();
        let key = keys::encode_pending_auth_key(&ticket);
        let bytes = serde_json::to_vec(request).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)?;
        Ok(ticket)
    }

    pub(super) fn get_pending_authorization_inner(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<Option<PendingAuthorizationRequest>, IdentityError> {
        let key = keys::encode_pending_auth_key(ticket);
        let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        let pending: PendingAuthorizationRequest =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        if self.clock.now().as_micros() >= pending.expires_at.as_micros() {
            return Err(IdentityError::ConsentTicketExpired);
        }
        Ok(Some(pending))
    }

    pub(super) fn take_pending_authorization_inner(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<PendingAuthorizationRequest, IdentityError> {
        // Single-use: claimed (G4) and deleted before we even validate expiry
        // so callers can never replay the same ticket twice, on any node.
        let pending: PendingAuthorizationRequest = self.take_single_use_row(
            realm_id,
            &keys::encode_pending_auth_key(ticket),
            &keys::encode_consumed_pending_auth(&Self::sha256_hex(ticket.as_bytes())),
            || IdentityError::ConsentTicketNotFound,
            |p: &PendingAuthorizationRequest| p.expires_at,
        )?;
        if self.clock.now().as_micros() >= pending.expires_at.as_micros() {
            return Err(IdentityError::ConsentTicketExpired);
        }
        Ok(pending)
    }

    pub(super) fn sign_jarm_error_jwt_inner(
        &self,
        realm_id: &RealmId,
        client_id: &str,
        error: &str,
        error_description: &str,
        state_param: &str,
    ) -> Result<String, IdentityError> {
        use crate::identity::oidc::JarmErrorClaims;
        let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        let claims = JarmErrorClaims {
            iss: self.config.oidc.issuer.clone(),
            aud: client_id.to_string(),
            // FAPI 2.0 §5.3.2.2 requires JARM JWT lifetime ≤ 5 minutes.
            exp: now_secs + 300,
            iat: now_secs,
            jti: uuid::Uuid::new_v4().to_string(),
            error: error.to_string(),
            error_description: error_description.to_string(),
            state: state_param.to_string(),
        };
        signing_key.sign_jwt(&claims, "oauth-authz-resp+jwt")
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn issue_authorization_code_inner(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
        redirect_uri: &str,
        scope: &str,
        state: &str,
        code_challenge: Option<String>,
        code_challenge_method: Option<CodeChallengeMethod>,
        nonce: Option<String>,
        amr_values: Vec<String>,
        response_mode: Option<crate::identity::oidc::ResponseMode>,
        jar_request: Option<String>,
        via_par: bool,
    ) -> Result<AuthorizationResponse, IdentityError> {
        let request = AuthorizationRequest {
            client_id: client_id.clone(),
            redirect_uri: redirect_uri.to_string(),
            scope: scope.to_string(),
            state: state.to_string(),
            resource: None,
            response_type: "code".to_string(),
            user_id: user_id.clone(),
            code_challenge,
            code_challenge_method,
            nonce,
            amr_values,
            response_mode,
            request: jar_request,
            via_par,
        };
        self.authorize(realm_id, &request)
    }

    pub(super) fn bulk_create_users_inner(
        &self,
        realm_id: &RealmId,
        requests: &[CreateUserRequest],
    ) -> Result<Vec<BulkResult<User>>, IdentityError> {
        let count = requests.len();
        let mut results = Vec::with_capacity(count);
        for (index, request) in requests.iter().enumerate() {
            let result = match self.create_user(realm_id, request) {
                Ok(user) => BulkResult {
                    index,
                    result: Ok(user),
                },
                Err(e) => BulkResult {
                    index,
                    result: Err(e.to_string()),
                },
            };
            results.push(result);
        }
        self.record_audit(
            realm_id,
            None,
            AuditAction::BulkUsersCreated,
            "user",
            &count.to_string(),
        )?;
        Ok(results)
    }

    pub(super) fn bulk_disable_users_inner(
        &self,
        realm_id: &RealmId,
        user_ids: &[UserId],
    ) -> Result<Vec<BulkResult<()>>, IdentityError> {
        let count = user_ids.len();
        let mut results = Vec::with_capacity(count);
        for (index, user_id) in user_ids.iter().enumerate() {
            let result = match self.update_user(
                realm_id,
                user_id,
                &UpdateUserRequest {
                    status: Some(UserStatus::Disabled),
                    ..UpdateUserRequest::default()
                },
            ) {
                Ok(_) => BulkResult {
                    index,
                    result: Ok(()),
                },
                Err(e) => BulkResult {
                    index,
                    result: Err(e.to_string()),
                },
            };
            results.push(result);
        }
        self.record_audit(
            realm_id,
            None,
            AuditAction::BulkUsersDisabled,
            "user",
            &count.to_string(),
        )?;
        Ok(results)
    }

    pub(super) fn initiate_logout_inner(
        &self,
        realm_id: &RealmId,
        request: &RpLogoutRequest,
    ) -> Result<RpLogoutResult, IdentityError> {
        // Resolve session ID and user ID from id_token_hint or explicit session_id.
        let (session_id, user_id) = if let Some(hint) = &request.id_token_hint {
            // Verify the hint's signature against this realm's keys (retiring
            // keys included) BEFORE acting on any claim: Ed25519, or — for a
            // client that registered RS256 — the realm's RSA ID-token key
            // (task 26.55), which only ever verifies an `id_token`. Expiry is
            // deliberately not enforced — OIDC RP-Initiated Logout §2 allows an
            // expired hint — but an unsigned or forged hint must revoke no
            // session and mint no logout token: otherwise an unauthenticated
            // caller sets `sub`/`sid` freely and gets a realm-signed logout
            // token for a victim (audit 2026-08-28 §4.2#3, §4.19#1).
            let claims = self.verify_realm_issued_id_token(realm_id, hint)?;
            let sid = Self::parse_session_id_claim(&claims)?.ok_or(IdentityError::InvalidToken)?;
            let uid = Self::parse_user_id_claim(&claims)?;
            (sid, uid)
        } else if let Some(sid) = &request.session_id {
            let session = self
                .get_session(realm_id, sid)?
                .ok_or(IdentityError::SessionNotFound)?;
            (sid.clone(), session.user_id().clone())
        } else {
            return Err(IdentityError::InvalidToken);
        };

        // Revoke the session (and cascade to grant families).
        match self.revoke_session(realm_id, &session_id) {
            Ok(()) | Err(IdentityError::SessionNotFound) => {}
            Err(e) => return Err(e),
        }

        // Collect all OAuth clients that received tokens under this session.
        let sfam_prefix = keys::encode_session_grant_family_prefix(&session_id);
        let sfam_end = keys::prefix_end(&sfam_prefix);

        let mut backchannel_targets: Vec<BackchannelTarget> = Vec::new();
        let mut frontchannel_targets: Vec<FrontchannelTarget> = Vec::new();

        if let Ok(entries) = self.storage.scan(realm_id, &sfam_prefix, &sfam_end) {
            let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
            let issuer = self.config.oidc.issuer.clone();
            let now = self.clock.now();
            let iat = now.as_micros() / 1_000_000;

            let mut seen_client_ids = std::collections::HashSet::new();

            for entry in &entries {
                let family_id = match std::str::from_utf8(&entry.key[sfam_prefix.len()..]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => continue,
                };

                let family_key = keys::encode_grant_family(family_id);
                let fam = match self.storage.get(realm_id, &family_key) {
                    Ok(Some(bytes)) => match serde_json::from_slice::<StoredGrantFamily>(&bytes) {
                        Ok(f) => f,
                        Err(_) => continue,
                    },
                    _ => continue,
                };

                let client_id = match fam.client_id {
                    Some(id) => id,
                    None => continue,
                };

                if !seen_client_ids.insert(client_id.clone()) {
                    continue; // Already processed this client for this session.
                }

                let client_key = keys::encode_oauth_client(&client_id);
                let client = match self.storage.get(realm_id, &client_key) {
                    Ok(Some(bytes)) => match serde_json::from_slice::<OAuthClient>(&bytes) {
                        Ok(c) => c,
                        Err(_) => continue,
                    },
                    _ => continue,
                };

                // Read-side backstop: a row written before the scheme
                // allowlist existed must not be framed or fetched now.
                if let Some(bcl_uri) = client
                    .backchannel_logout_uri()
                    .filter(|u| validation::is_allowed_backchannel_logout_uri(u))
                {
                    let jti = uuid::Uuid::new_v4().to_string();
                    let logout_claims = LogoutTokenClaims::new(
                        issuer.clone(),
                        user_id.as_uuid().to_string(),
                        Audience::single(client_id.as_uuid().to_string()),
                        session_id.as_uuid().to_string(),
                        jti,
                        iat,
                    );
                    if let Ok(token) = signing_key.issue_logout_token(&logout_claims) {
                        backchannel_targets.push(BackchannelTarget {
                            uri: bcl_uri.to_string(),
                            logout_token: token,
                        });
                    }
                }

                if let Some(fcl_uri) = client
                    .frontchannel_logout_uri()
                    .filter(|u| validation::is_allowed_frontchannel_logout_uri(u))
                {
                    frontchannel_targets.push(FrontchannelTarget {
                        uri: fcl_uri.to_string(),
                        client_id: client_id.clone(),
                    });
                }
            }
        }

        // Validate post_logout_redirect_uri against the registering client's list.
        // When no client_id is provided we cannot validate the URI, so we drop it
        // to prevent open-redirect (OIDC RP-Initiated Logout 1.0 §3).
        let post_logout_redirect_uri = match &request.post_logout_redirect_uri {
            None => None,
            Some(uri) => {
                let valid = match &request.client_id {
                    None => false, // No client to validate against — reject unvalidated redirect.
                    Some(cid) => {
                        let client_key = keys::encode_oauth_client(cid);
                        match self.storage.get(realm_id, &client_key) {
                            Ok(Some(bytes)) => {
                                match serde_json::from_slice::<OAuthClient>(&bytes) {
                                    Ok(c) => c.post_logout_redirect_uris().contains(uri),
                                    Err(_) => false,
                                }
                            }
                            _ => false,
                        }
                    }
                };
                if valid {
                    Some(uri.clone())
                } else {
                    None
                }
            }
        };

        Ok(RpLogoutResult {
            user_id,
            session_id,
            backchannel_targets,
            frontchannel_targets,
            post_logout_redirect_uri,
            state: request.state.clone(),
        })
    }

    pub(super) fn store_delegation_grant_inner(
        &self,
        realm_id: &RealmId,
        grant: &StoredDelegationGrant,
    ) -> Result<(), IdentityError> {
        let primary_key = keys::encode_delegation_grant(&grant.delegation_id);
        let index_key =
            keys::encode_delegation_grant_user_index(&grant.user_sub, &grant.delegation_id);
        let bytes = serde_json::to_vec(grant).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &primary_key, &bytes)
            .map_err(Self::storage_err)?;
        self.storage
            .put(realm_id, &index_key, b"1")
            .map_err(Self::storage_err)?;
        Ok(())
    }

    pub(super) fn list_delegation_grants_inner(
        &self,
        realm_id: &RealmId,
        user_sub: &str,
    ) -> Result<Vec<DelegationGrantEntry>, IdentityError> {
        let prefix = keys::delegation_grant_user_prefix(user_sub);
        let end = keys::prefix_end(&prefix);
        let index_entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let now_micros = self.clock.now().as_micros();
        let mut out = Vec::with_capacity(index_entries.len());
        for entry in &index_entries {
            let key_str = String::from_utf8_lossy(&entry.key);
            let delegation_id = match key_str.rsplit(':').next() {
                Some(id) => id.to_string(),
                None => continue,
            };
            let primary_key = keys::encode_delegation_grant(&delegation_id);
            let Some(bytes) = self
                .storage
                .get(realm_id, &primary_key)
                .map_err(Self::storage_err)?
            else {
                continue;
            };
            let grant: StoredDelegationGrant =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if grant.revoked || grant.expires_at.as_micros() <= now_micros {
                continue;
            }
            out.push(DelegationGrantEntry {
                delegation_id: grant.delegation_id,
                actor_sub: grant.actor_sub,
                granted_scopes: grant
                    .granted_scope
                    .split_whitespace()
                    .map(str::to_string)
                    .collect(),
                created_at: grant.created_at,
                expires_at: grant.expires_at,
            });
        }
        Ok(out)
    }

    pub(super) fn revoke_delegation_grant_inner(
        &self,
        realm_id: &RealmId,
        delegation_id: &str,
        user_sub: &str,
    ) -> Result<(), IdentityError> {
        let primary_key = keys::encode_delegation_grant(delegation_id);
        let Some(bytes) = self
            .storage
            .get(realm_id, &primary_key)
            .map_err(Self::storage_err)?
        else {
            return Err(IdentityError::DelegationGrantNotFound);
        };
        let mut grant: StoredDelegationGrant =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        if grant.user_sub != user_sub {
            return Err(IdentityError::DelegationGrantNotFound);
        }
        if grant.revoked {
            return Ok(());
        }
        grant.revoked = true;
        let updated_bytes =
            serde_json::to_vec(&grant).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &primary_key, &updated_bytes)
            .map_err(Self::storage_err)?;
        let jti_key = keys::encode_revoked_jti(&grant.token_jti);
        let exp_secs = grant.expires_at.as_micros() / 1_000_000;
        self.storage
            .put(realm_id, &jti_key, &exp_secs.to_le_bytes())
            .map_err(Self::storage_err)?;
        self.insert_revoked_jti_cache(realm_id, &grant.token_jti, exp_secs);
        let _ = self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::System,
                metadata: Some(serde_json::json!({
                    "delegation_id": delegation_id,
                    "actor_sub": grant.actor_sub,
                    "via": "self",
                })),
            }),
            AuditAction::AgentTokenRevoked,
            "delegation",
            delegation_id,
        );
        Ok(())
    }
}
