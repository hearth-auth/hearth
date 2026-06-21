//! OAuth 2.0 / OIDC method implementations for [`EmbeddedIdentityEngine`].
//!
//! Extracted from `mod.rs` for navigability. Public API is unchanged —
//! `mod.rs` delegates to these `pub(super)` methods via thin wrappers in
//! `impl IdentityEngine for EmbeddedIdentityEngine`.

use std::collections::BTreeSet;
use std::sync::Arc;

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
    CodeChallengeMethod, FrontchannelTarget, OAuthClient, OidcDiscoveryDocument, OidcTokenResponse,
    RegisterClientRequest, ResponseMode, RpLogoutRequest, RpLogoutResult, StoredAuthorizationCode,
    StoredDeviceCode, StoredGrantFamily, TokenExchangeRequest,
};
use crate::identity::tokens::{self, Audience, LogoutTokenClaims, TokenClaims};
use crate::identity::types::{
    BulkResult, ConsentListEntry, ConsentRecord, CreateUserRequest, DelegationGrantEntry, Page,
    PendingAuthorizationRequest, SessionContext, StoredDelegationGrant, UpdateUserRequest, User,
    UserStatus,
};
use crate::identity::validation;
use crate::identity::IdentityEngine;
use crate::rbac::error::RbacError;

use super::validate_claim_payload;
use super::EmbeddedIdentityEngine;
use super::CLOCK_SKEW_SECS;

impl EmbeddedIdentityEngine {
    // ===== OIDC signing-key helpers (moved from mod.rs) =====

    /// Generates the key the first time it is requested and caches it for
    /// the life of the engine. Future M1 follow-ups will replace this with
    /// a storage-backed lookup so `kid`s remain stable across restarts.
    fn oidc_rsa_signing_key(
        &self,
    ) -> Result<Arc<crate::identity::tokens::RsaSigningKey>, IdentityError> {
        if let Some(existing) = self.oidc_rsa_key.get() {
            return Ok(Arc::clone(existing));
        }
        let generated = Arc::new(crate::identity::tokens::RsaSigningKey::generate(
            "hearth-oidc",
            3650,
        )?);
        // Race: if another thread initialized in parallel, prefer the
        // already-stored value so all callers observe the same `kid`.
        let _ = self.oidc_rsa_key.set(Arc::clone(&generated));
        Ok(Arc::clone(
            self.oidc_rsa_key
                .get()
                .expect("oidc_rsa_key set above or by racing thread"),
        ))
    }

    pub(super) fn oidc_rsa_jwk(&self) -> Result<crate::identity::tokens::Jwk, IdentityError> {
        self.oidc_rsa_signing_key()?.to_jwk()
    }

    /// Returns the server-wide ECDSA P-256 signing key used to publish the
    /// ES256 entry in the `/certs` JWKS. See `oidc_rsa_signing_key` for
    /// the same caching / persistence caveats.
    fn oidc_ecdsa_signing_key(
        &self,
    ) -> Result<Arc<crate::identity::tokens::EcdsaSigningKey>, IdentityError> {
        if let Some(existing) = self.oidc_ecdsa_key.get() {
            return Ok(Arc::clone(existing));
        }
        let generated = Arc::new(crate::identity::tokens::EcdsaSigningKey::generate()?);
        let _ = self.oidc_ecdsa_key.set(Arc::clone(&generated));
        Ok(Arc::clone(
            self.oidc_ecdsa_key
                .get()
                .expect("oidc_ecdsa_key set above or by racing thread"),
        ))
    }

    pub(super) fn oidc_ecdsa_jwk(&self) -> Result<crate::identity::tokens::Jwk, IdentityError> {
        Ok(self.oidc_ecdsa_signing_key()?.to_jwk())
    }
}

#[allow(clippy::too_many_lines)]
impl EmbeddedIdentityEngine {
    // ===== OAuth / OIDC trait method implementations =====

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
            vec!["authorization_code".to_string()]
        } else {
            request.grant_types.clone()
        };

        let mut client = if let Some(ref secret) = request.client_secret {
            // Confidential client — hash the secret with Argon2id
            let secret_hash =
                credentials::hash_raw_secret(secret.as_bytes(), &self.config.credential)?;
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

        // FAPI 2.0 registration constraints.
        if request.profile.is_fapi2() {
            // FAPI2 clients must not use client_secret — private_key_jwt only.
            if request.client_secret.is_some() {
                return Err(IdentityError::FapiViolation {
                    reason: "FAPI 2.0 clients must not use client_secret; \
                             register with jwks or jwks_uri for private_key_jwt authentication"
                        .to_string(),
                });
            }
            // FAPI2 clients must have a registered JWKS (inline or by URI).
            if request.jwks.is_none() && request.jwks_uri.is_none() {
                return Err(IdentityError::FapiViolation {
                    reason: "FAPI 2.0 clients must register a JWKS (jwks or jwks_uri) \
                             for private_key_jwt client authentication"
                        .to_string(),
                });
            }
        }
        client.set_profile(request.profile);
        if request.mfa_required.is_some() {
            client.set_mfa_required(request.mfa_required);
        }

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

    #[allow(clippy::too_many_lines)]
    pub(super) fn authorize_inner(
        &self,
        realm_id: &RealmId,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationResponse, IdentityError> {
        use crate::identity::oidc::{CodeChallengeMethod as CCM, JarmClaims};
        use crate::identity::types::FapiProfile;

        // Retained for potential future use; FAPI Advanced JAR enforcement
        // moved to push_authorization_request where the JTI is not yet consumed.
        let _jar_was_present = request.request.is_some();

        // 0. JAR (RFC 9101): if a signed request object is present, verify it
        //    and use its claims to override the outer query parameters. This must
        //    happen before any other validation so that JAR-supplied values
        //    (state, redirect_uri, scope, …) are used for subsequent checks.
        let jar_override;
        let request = if let Some(ref jar_jwt) = request.request {
            let jar = self.verify_jar(realm_id, &request.client_id, jar_jwt)?;

            // JAR client_id claim must match the outer client_id (RFC 9101 §4).
            if let Some(ref jar_cid) = jar.client_id {
                if jar_cid != &request.client_id.to_string() {
                    return Err(IdentityError::InvalidJar {
                        reason: "client_id in JAR claims does not match the request".to_string(),
                    });
                }
            }

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

        // 2b. Nonce replay protection (when enforcement is enabled)
        if self.config.oidc.enforce_nonces {
            if let Some(ref nonce) = request.nonce {
                let now = self.clock.now();
                let ttl_micros = self.config.oidc.authorization_code_ttl_secs * 1_000_000;
                let mut nonces = self.used_nonces.lock().expect("nonce lock");
                // Sweep nonces older than the auth-code TTL to bound memory.
                nonces.retain(|_, inserted_at| {
                    now.as_micros() - inserted_at.as_micros() < ttl_micros
                });
                if nonces.insert(nonce.clone(), now).is_some() {
                    return Err(IdentityError::InvalidGrant {
                        reason: "nonce has already been used".to_string(),
                    });
                }
            }
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

        self.validate_client_scope_request(&client, &request.scope)?;

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
        let resource_key = request
            .resource
            .as_deref()
            .unwrap_or(keys::CONSENT_RESOURCE_KEY_DEFAULT);
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

        // 5. PKCE enforcement (RFC 9700 §2.1.1)
        // All clients must provide PKCE by default. Confidential clients may be
        // exempted via `require_pkce_for_confidential_clients: false` for legacy
        // compatibility only.
        let pkce_required =
            !client.is_confidential() || self.config.oidc.require_pkce_for_confidential_clients;
        if pkce_required && request.code_challenge.is_none() {
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
            used: false,
            nonce: request.nonce.clone(),
            resource: request.resource.clone(),
            amr_values: request.amr_values.clone(),
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
        let response_mode = if client.authorization_signed_response_alg().is_some() {
            let requested = request.response_mode.clone().unwrap_or(ResponseMode::Query);
            if requested.is_jarm() {
                requested
            } else {
                ResponseMode::QueryJwt
            }
        } else {
            request.response_mode.clone().unwrap_or(ResponseMode::Query)
        };
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
            ));
        }

        Ok(AuthorizationResponse::new(
            raw_code,
            request.state.clone(),
            issuer,
        ))
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

        // 2. Load the stored code
        let code_bytes = self
            .storage
            .get(realm_id, &code_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidAuthorizationCode)?;

        let mut stored_code: StoredAuthorizationCode = serde_json::from_slice(&code_bytes)
            .map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // 3. Check if already used (single-use enforcement)
        if stored_code.used {
            return Err(IdentityError::InvalidAuthorizationCode);
        }

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
        // If no assertion is supplied, we must still block private_key_jwt-only clients
        // (those with an assertion_public_key but no client_secret_hash) from silently
        // bypassing client authentication.
        const PRIVATE_KEY_JWT_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        if request.client_assertion_type.as_deref() == Some(PRIVATE_KEY_JWT_TYPE) {
            let assertion = request.client_assertion.as_deref().ok_or_else(|| {
                IdentityError::InvalidClientAssertion {
                    reason: "client_assertion is required when client_assertion_type is set"
                        .to_string(),
                }
            })?;
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
                    if client.assertion_public_key().is_some()
                        && client.client_secret_hash().is_none()
                    {
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

            // Compute S256: BASE64URL(SHA256(code_verifier))
            let computed_challenge = Self::pkce_s256_challenge(verifier);
            if computed_challenge != *challenge {
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
        let scope_for_resolver =
            if scope_value.is_empty() || scope_value.split_whitespace().count() != 1 {
                None
            } else {
                Some(scope_value.as_str())
            };
        let resolved = self
            .rbac
            .resolve_permissions(&stored_code.user_id, realm_id, None, scope_for_resolver)
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
        let granted_scopes: BTreeSet<String> =
            scope_value.split_whitespace().map(str::to_string).collect();

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
        let access_custom =
            crate::identity::pre_token_webhook::merge_extra_claims(access_custom, webhook_extra);

        // 9. Mark the code as used
        stored_code.used = true;
        let updated_bytes =
            serde_json::to_vec(&stored_code).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &code_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // 10. Create a session for the user (OAuth code exchange — no browser context)
        let session =
            self.create_session(realm_id, &stored_code.user_id, &SessionContext::default())?;

        // 11. Create grant family for refresh token rotation
        let family_id = uuid::Uuid::new_v4().to_string();

        // 12. Issue tokens with family ID
        let iat = now.as_micros() / 1_000_000;
        let signing_key = self.get_signing_key_or_default(realm_id);

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
            iss: self.config.token.issuer.clone(),
            aud: aud.clone(),
            exp: iat + access_ttl_secs,
            iat,
            sid: session.id().to_string(),
            tid: realm_id.to_string(),
            oid: None,
            token_type: "access".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: Some(family_id.clone()),
            scope: (!scope_value.is_empty()).then(|| scope_value.clone()),
            nonce: None,
            roles: access_roles,
            groups: access_groups,
            org_groups: Vec::new(),
            permissions: access_permissions,
            required_actions: Vec::new(),
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
            iss: self.config.token.issuer.clone(),
            aud,
            exp: iat + refresh_ttl_secs,
            iat,
            sid: session.id().to_string(),
            tid: realm_id.to_string(),
            oid: None,
            token_type: "refresh".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: Some(family_id.clone()),
            scope: (!scope_value.is_empty()).then(|| scope_value.clone()),
            nonce: None,
            roles: access_claims.roles.clone(),
            groups: access_claims.groups.clone(),
            org_groups: Vec::new(),
            permissions: access_claims.permissions.clone(),
            required_actions: Vec::new(),
            act: None,
            amr: Vec::new(),
            cnf: None,
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
            sid: session.id().to_string(),
            tid: realm_id.to_string(),
            oid: None,
            token_type: "id_token".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: None,
            scope: (!scope_value.is_empty()).then(|| scope_value.clone()),
            nonce: stored_code.nonce.clone(),
            roles: id_roles,
            groups: id_groups,
            org_groups: Vec::new(),
            permissions: id_permissions,
            required_actions: Vec::new(),
            act: None,
            amr: stored_code.amr_values.clone(),
            cnf: None,
            custom: id_custom,
            sv: None,
        };
        let id_token =
            signing_key
                .issue_token(&id_token_claims)
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
        // 1. Look up user by email (timing-safe: dummy-hash on miss)
        let user = match self.get_user_by_email(realm_id, &request.email)? {
            Some(u) => u,
            None => {
                let dummy_pw = CleartextPassword::from_string(request.password.clone());
                let _ = credentials::verify_hash(&dummy_pw, &self.dummy_hash);
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

        // 4. Create session and issue token pair
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
        // 1. Look up user by email (timing-safe: dummy-hash on miss)
        let user = match self.get_user_by_email(realm_id, &request.email)? {
            Some(u) => u,
            None => {
                let dummy_pw = CleartextPassword::from_string(request.password.clone());
                let _ = credentials::verify_hash(&dummy_pw, &self.dummy_hash);
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

        // 4. Create session and issue token pair.
        let session = self.create_session(
            realm_id,
            user.id(),
            &crate::identity::SessionContext::default(),
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
        // 1. Load the client
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

        // 2. Verify this client supports client_credentials grant
        if !client
            .grant_types()
            .contains(&"client_credentials".to_string())
        {
            return Err(IdentityError::UnsupportedGrantType);
        }

        // 3. Authenticate client: private_key_jwt takes precedence over client_secret
        const PRIVATE_KEY_JWT_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        if request.client_assertion_type.as_deref() == Some(PRIVATE_KEY_JWT_TYPE) {
            let assertion = request.client_assertion.as_deref().ok_or_else(|| {
                IdentityError::InvalidClientAssertion {
                    reason: "client_assertion is required when client_assertion_type is set"
                        .to_string(),
                }
            })?;
            self.verify_client_assertion(realm_id, &request.client_id, assertion)?;
        } else {
            let secret = request
                .client_secret
                .as_deref()
                .ok_or(IdentityError::InvalidClientSecret)?;
            let secret_hash = client
                .client_secret_hash()
                .ok_or(IdentityError::InvalidClientSecret)?;
            let valid = credentials::verify_raw_secret(secret.as_bytes(), secret_hash)?;
            if !valid {
                return Err(IdentityError::InvalidClientSecret);
            }
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
            iss: self.config.token.issuer.clone(),
            aud: Audience::single(self.config.token.audience.clone()),
            exp: iat + self.config.token.access_token_ttl_secs,
            iat,
            sid: "none".to_string(), // No session for client credentials
            tid: realm_id.to_string(),
            oid: None,
            token_type: "access".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: None,
            scope: scope.clone(),
            nonce: None,
            roles: Vec::new(),
            groups: Vec::new(),
            org_groups: Vec::new(),
            permissions: Vec::new(),
            required_actions: Vec::new(),
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
        if assertion_claims.iss != request.client_id.to_string() {
            return Err(IdentityError::JwtBearerAssertionInvalid {
                reason: "iss claim must equal the client_id".to_string(),
            });
        }

        // sub MUST equal client_id (RFC 7523 §3 / OIDC Core §9)
        if assertion_claims.sub != request.client_id.to_string() {
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
            sub: assertion_claims.sub,
            iss: self.config.token.issuer.clone(),
            aud: Audience::single(self.config.token.audience.clone()),
            exp: iat + self.config.token.access_token_ttl_secs,
            iat,
            sid: "none".to_string(),
            tid: realm_id.to_string(),
            oid: None,
            token_type: "access".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: None,
            scope: scope.clone(),
            nonce: None,
            roles: Vec::new(),
            groups: Vec::new(),
            org_groups: Vec::new(),
            permissions: Vec::new(),
            required_actions: Vec::new(),
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

        let pk_b64 =
            client
                .assertion_public_key()
                .ok_or_else(|| IdentityError::InvalidClientAssertion {
                    reason: "no assertion public key registered for this client".to_string(),
                })?;
        let pk_bytes =
            URL_SAFE_NO_PAD
                .decode(pk_b64)
                .map_err(|_| IdentityError::InvalidClientAssertion {
                    reason: "client has an invalid assertion public key".to_string(),
                })?;

        // Verify EdDSA signature — rejects alg:none, HMAC, RSA, etc.
        let claims = tokens::verify_assertion_signature(assertion, &pk_bytes).map_err(|_| {
            IdentityError::InvalidClientAssertion {
                reason: "assertion signature verification failed".to_string(),
            }
        })?;

        // iss MUST equal client_id (RFC 7523 §3)
        if claims.iss != client_id.to_string() {
            return Err(IdentityError::InvalidClientAssertion {
                reason: "iss claim must equal the client_id".to_string(),
            });
        }

        // sub MUST equal client_id (RFC 7523 §3 / OIDC Core §9)
        if claims.sub != client_id.to_string() {
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

        // aud MUST contain this realm's token endpoint URL
        let expected_aud = self.realm_issuer_url(realm_id);
        if !claims.aud.contains(&expected_aud) {
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
        let jti_key = keys::encode_client_assertion_jti(jti);
        if self
            .storage
            .get(realm_id, &jti_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::InvalidClientAssertion {
                reason: "assertion jti has already been used (replay)".to_string(),
            });
        }
        self.storage
            .put(realm_id, &jti_key, b"1")
            .map_err(Self::storage_err)?;

        Ok(())
    }

    pub(super) fn verify_jar_inner(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        request_jwt: &str,
    ) -> Result<crate::identity::oidc::JarClaims, IdentityError> {
        use crate::identity::federation::oidc as fed_oidc;
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

        // 4. Parse the JWKS and select the matching key.
        #[derive(serde::Deserialize)]
        struct JwksContainer {
            keys: Vec<fed_oidc::Jwk>,
        }
        let jwks: JwksContainer =
            serde_json::from_str(jwks_json).map_err(|_| IdentityError::InvalidJar {
                reason: "client jwks is not valid JSON".to_string(),
            })?;

        let kid = header.kid.as_deref();
        let selected = if let Some(k) = kid {
            jwks.keys.iter().find(|j| j.kid.as_deref() == Some(k))
        } else if jwks.keys.len() == 1 {
            jwks.keys.first()
        } else {
            None
        }
        .ok_or_else(|| IdentityError::InvalidJar {
            reason: "no matching key found in client jwks".to_string(),
        })?;

        // 5. Verify signature based on key type.
        match alg {
            "EdDSA" => {
                if selected.crv.as_deref() != Some("Ed25519") {
                    return Err(IdentityError::InvalidJar {
                        reason: "EdDSA JWK must have crv=Ed25519".to_string(),
                    });
                }
                let x_b64 = selected
                    .x
                    .as_deref()
                    .ok_or_else(|| IdentityError::InvalidJar {
                        reason: "EdDSA JWK missing 'x' parameter".to_string(),
                    })?;
                let pk_bytes =
                    URL_SAFE_NO_PAD
                        .decode(x_b64)
                        .map_err(|_| IdentityError::InvalidJar {
                            reason: "EdDSA JWK 'x' is not valid base64url".to_string(),
                        })?;
                let signing_input = format!("{}.{}", parts[0], parts[1]);
                let sig_bytes =
                    URL_SAFE_NO_PAD
                        .decode(parts[2])
                        .map_err(|_| IdentityError::InvalidJar {
                            reason: "invalid signature encoding".to_string(),
                        })?;
                let public_key =
                    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pk_bytes);
                public_key
                    .verify(signing_input.as_bytes(), &sig_bytes)
                    .map_err(|_| IdentityError::InvalidJar {
                        reason: "EdDSA signature verification failed".to_string(),
                    })?;
            }
            "RS256" => {
                fed_oidc::verify_rs256(request_jwt, selected).map_err(|_| {
                    IdentityError::InvalidJar {
                        reason: "RS256 signature verification failed".to_string(),
                    }
                })?;
            }
            "PS256" => {
                if selected.kty != "RSA" {
                    return Err(IdentityError::InvalidJar {
                        reason: "PS256 requires an RSA key (kty=RSA)".to_string(),
                    });
                }
                let n_b64 = selected
                    .n
                    .as_deref()
                    .ok_or_else(|| IdentityError::InvalidJar {
                        reason: "PS256 JWK missing 'n' parameter".to_string(),
                    })?;
                let e_b64 = selected
                    .e
                    .as_deref()
                    .ok_or_else(|| IdentityError::InvalidJar {
                        reason: "PS256 JWK missing 'e' parameter".to_string(),
                    })?;
                let n = URL_SAFE_NO_PAD
                    .decode(n_b64)
                    .map_err(|_| IdentityError::InvalidJar {
                        reason: "PS256 JWK 'n' is not valid base64url".to_string(),
                    })?;
                let e = URL_SAFE_NO_PAD
                    .decode(e_b64)
                    .map_err(|_| IdentityError::InvalidJar {
                        reason: "PS256 JWK 'e' is not valid base64url".to_string(),
                    })?;
                let signing_input = format!("{}.{}", parts[0], parts[1]);
                let sig_bytes =
                    URL_SAFE_NO_PAD
                        .decode(parts[2])
                        .map_err(|_| IdentityError::InvalidJar {
                            reason: "invalid signature encoding".to_string(),
                        })?;
                let components = ring::signature::RsaPublicKeyComponents {
                    n: n.as_slice(),
                    e: e.as_slice(),
                };
                components
                    .verify(
                        &ring::signature::RSA_PSS_2048_8192_SHA256,
                        signing_input.as_bytes(),
                        &sig_bytes,
                    )
                    .map_err(|_| IdentityError::InvalidJar {
                        reason: "PS256 signature verification failed".to_string(),
                    })?;
            }
            "ES256" => {
                if selected.kty != "EC" {
                    return Err(IdentityError::InvalidJar {
                        reason: "ES256 requires an EC key (kty=EC)".to_string(),
                    });
                }
                if selected.crv.as_deref() != Some("P-256") {
                    return Err(IdentityError::InvalidJar {
                        reason: "ES256 JWK must have crv=P-256".to_string(),
                    });
                }
                let x_b64 = selected
                    .x
                    .as_deref()
                    .ok_or_else(|| IdentityError::InvalidJar {
                        reason: "ES256 JWK missing 'x' parameter".to_string(),
                    })?;
                let y_b64 = selected
                    .y
                    .as_deref()
                    .ok_or_else(|| IdentityError::InvalidJar {
                        reason: "ES256 JWK missing 'y' parameter".to_string(),
                    })?;
                let x_bytes =
                    URL_SAFE_NO_PAD
                        .decode(x_b64)
                        .map_err(|_| IdentityError::InvalidJar {
                            reason: "ES256 JWK 'x' is not valid base64url".to_string(),
                        })?;
                let y_bytes =
                    URL_SAFE_NO_PAD
                        .decode(y_b64)
                        .map_err(|_| IdentityError::InvalidJar {
                            reason: "ES256 JWK 'y' is not valid base64url".to_string(),
                        })?;
                // ring expects uncompressed point: 0x04 || x || y
                let mut pk_bytes = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
                pk_bytes.push(0x04);
                pk_bytes.extend_from_slice(&x_bytes);
                pk_bytes.extend_from_slice(&y_bytes);
                let signing_input = format!("{}.{}", parts[0], parts[1]);
                let sig_bytes =
                    URL_SAFE_NO_PAD
                        .decode(parts[2])
                        .map_err(|_| IdentityError::InvalidJar {
                            reason: "invalid signature encoding".to_string(),
                        })?;
                let public_key = ring::signature::UnparsedPublicKey::new(
                    &ring::signature::ECDSA_P256_SHA256_FIXED,
                    &pk_bytes,
                );
                public_key
                    .verify(signing_input.as_bytes(), &sig_bytes)
                    .map_err(|_| IdentityError::InvalidJar {
                        reason: "ES256 signature verification failed".to_string(),
                    })?;
            }
            _ => {
                return Err(IdentityError::InvalidJar {
                    reason: format!("unsupported JAR signing algorithm '{alg}'"),
                })
            }
        }

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

        // 7. Validate iss == client_id.
        if claims.iss != client_id.to_string() {
            return Err(IdentityError::InvalidJar {
                reason: "iss claim must equal the client_id".to_string(),
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
        if self
            .storage
            .get(realm_id, &jti_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::InvalidJar {
                reason: "jti has already been used (replay)".to_string(),
            });
        }
        // Store expiry as 8-byte little-endian i64 (Unix seconds) so the
        // background sweeper in cleanup::sweep_jar_jtis() can purge entries
        // once they can no longer represent a valid JWT (exp + clock skew).
        let jar_jti_expires_at = claims.exp.saturating_add(CLOCK_SKEW_SECS);
        self.storage
            .put(realm_id, &jti_key, &jar_jti_expires_at.to_le_bytes())
            .map_err(Self::storage_err)?;

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
        let expires_in = 600_i64; // 10 minutes
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
            verification_uri: format!("{}/device", self.config.oidc.issuer),
            expires_in,
            interval,
        })
    }

    pub(super) fn approve_device_inner(
        &self,
        realm_id: &RealmId,
        user_code: &str,
        user_id: &UserId,
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

        // 5. Approve
        stored.status = DeviceCodeStatus::Approved {
            user_id: user_id.clone(),
        };
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

    pub(super) fn poll_device_token_inner(
        &self,
        realm_id: &RealmId,
        device_code: &str,
        client_id: &ClientId,
    ) -> Result<OidcTokenResponse, IdentityError> {
        use crate::identity::oidc::DeviceCodeStatus;

        // 1. Look up device code by hash
        let dc_hash = Self::sha256_hex(device_code.as_bytes());
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

        // 2. Verify client matches
        if stored.client_id != *client_id {
            return Err(IdentityError::InvalidClient);
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

        // 5. Update last_polled_at
        stored.last_polled_at = Some(now);
        let updated_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &dc_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // 6. Check status
        match &stored.status {
            DeviceCodeStatus::Pending => Err(IdentityError::AuthorizationPending),
            DeviceCodeStatus::Denied => Err(IdentityError::DeviceCodeDenied),
            DeviceCodeStatus::Expired => Err(IdentityError::DeviceCodeExpired),
            DeviceCodeStatus::Approved { user_id } => {
                // Issue tokens like exchange_authorization_code (device flow — no browser context)
                let session = self.create_session(realm_id, user_id, &SessionContext::default())?;
                let token_pair = self.issue_tokens(realm_id, user_id, session.id())?;

                // Issue ID token
                // iss MUST match the discovery document's issuer (OIDC Core §2)
                let iat = now.as_micros() / 1_000_000;
                let id_token_claims = TokenClaims {
                    sub: user_id.to_string(),
                    iss: self.config.oidc.issuer.clone(),
                    aud: Audience::single(client_id.to_string()),
                    exp: iat + self.config.token.access_token_ttl_secs,
                    iat,
                    sid: session.id().to_string(),
                    tid: realm_id.to_string(),
                    oid: None,
                    token_type: "id_token".to_string(),
                    jti: Some(uuid::Uuid::new_v4().to_string()),
                    fid: None,
                    scope: stored.scope.clone(),
                    nonce: None,
                    roles: Vec::new(),
                    groups: Vec::new(),
                    org_groups: Vec::new(),
                    permissions: Vec::new(),
                    required_actions: Vec::new(),
                    act: None,
                    amr: Vec::new(),
                    cnf: None,
                    custom: std::collections::BTreeMap::new(),
                    sv: None,
                };
                let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
                let id_token = signing_key.issue_token(&id_token_claims).map_err(|e| {
                    IdentityError::SigningError {
                        reason: format!("failed to issue ID token: {e}"),
                    }
                })?;

                // Clean up device code and user code
                let _ = self.storage.delete(realm_id, &dc_key);
                let uc_key = keys::encode_user_code(&stored.user_code);
                let _ = self.storage.delete(realm_id, &uc_key);

                Ok(OidcTokenResponse::new(
                    token_pair.access_token().to_string(),
                    id_token,
                    "Bearer".to_string(),
                    self.config.token.access_token_ttl_secs,
                    token_pair.refresh_token().to_string(),
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
        ) = if let Some(ref jar_jwt) = request.request {
            let jar = self.verify_jar(realm_id, &request.client_id, jar_jwt)?;
            // JAR client_id claim must match the outer client_id.
            if let Some(ref jar_cid) = jar.client_id {
                if jar_cid != &request.client_id.to_string() {
                    return Err(IdentityError::InvalidJar {
                        reason: "client_id in JAR claims does not match the request".to_string(),
                    });
                }
            }
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
            )
        };

        // FAPI 2.0 post-JAR gate: PKCE must be checked against `effective_code_challenge`
        // so that clients who supply it only inside the JAR (RFC 9101 §6.1) are accepted.
        if realm.config().fapi_profile.is_some() {
            // Baseline + Advanced: PKCE (S256) is always required, even for confidential
            // clients. The `require_pkce_for_confidential_clients` config flag has no
            // effect under a FAPI profile.
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

        if !client.redirect_uris().contains(&effective_redirect_uri) {
            return Err(IdentityError::InvalidRedirectUri);
        }

        let pkce_required =
            !client.is_confidential() || self.config.oidc.require_pkce_for_confidential_clients;
        if pkce_required && effective_code_challenge.is_none() {
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

        let now = self.clock.now();
        let ttl_secs: i64 = 90;
        let expires_at = now.add_micros(ttl_secs * 1_000_000);
        let request_uri_id = uuid::Uuid::new_v4().to_string();

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
            created_at: now,
            expires_at,
            used: false,
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

    #[allow(private_interfaces)]
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
        let raw = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidPushedAuthorizationRequest)?;

        let mut stored: crate::identity::oidc::StoredPushedAuthorizationRequest =
            serde_json::from_slice(&raw).map_err(|e| IdentityError::Internal {
                reason: format!("failed to deserialize PAR request: {e}"),
            })?;

        if stored.used {
            return Err(IdentityError::InvalidPushedAuthorizationRequest);
        }
        let now = self.clock.now();
        if now >= stored.expires_at {
            return Err(IdentityError::InvalidPushedAuthorizationRequest);
        }

        stored.used = true;
        let updated = serde_json::to_vec(&stored).map_err(|e| IdentityError::Internal {
            reason: format!("failed to serialize updated PAR request: {e}"),
        })?;
        self.storage
            .put(realm_id, &key, &updated)
            .map_err(Self::storage_err)?;

        Ok(stored)
    }

    pub(super) fn revoke_token_inner(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::TokenRevocationRequest,
    ) -> Result<(), IdentityError> {
        // RFC 7009: invalid tokens → 200 OK (no error). Signature
        // verification prevents forged tokens from targeting real sessions
        // or grant families for revocation.
        let Ok(claims) = self.verify_token_signature_for_realm(realm_id, &request.token) else {
            return Ok(());
        };

        // Verify realm matches
        if claims.tid.parse::<RealmId>().ok().as_ref() != Some(realm_id) {
            return Ok(()); // Silent success per RFC 7009
        }

        match claims.token_type.as_str() {
            "access" | "id_token" => {
                if claims.sid != "none" {
                    // Session-bound token: revoke via session
                    let sid_str = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
                    if let Ok(uuid) = uuid::Uuid::parse_str(sid_str) {
                        let session_id = SessionId::new(uuid);
                        let _ = self.revoke_session(realm_id, &session_id);
                    }
                } else if let Some(ref jti) = claims.jti {
                    // Sessionless token (e.g., client_credentials): revoke via JTI blocklist.
                    // Store the token's exp so the hot-path projection can self-evict expired entries.
                    let jti_key = keys::encode_revoked_jti(jti);
                    let _ = self
                        .storage
                        .put(realm_id, &jti_key, &claims.exp.to_le_bytes());
                    self.insert_revoked_jti_cache(realm_id, jti, claims.exp);
                }
            }
            "refresh" => {
                // Revoke via grant family
                if let Some(ref fid) = claims.fid {
                    let family_key = keys::encode_grant_family(fid);
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
                // Also revoke session if present
                if claims.sid != "none" {
                    let sid_str = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
                    if let Ok(uuid) = uuid::Uuid::parse_str(sid_str) {
                        let session_id = SessionId::new(uuid);
                        let _ = self.revoke_session(realm_id, &session_id);
                    }
                }
            }
            _ => {} // Unknown token type → silent success
        }

        self.record_audit(
            realm_id,
            None,
            AuditAction::SessionRevoked,
            "token",
            &request.token,
        )?;

        Ok(())
    }

    pub(super) fn introspect_token_inner(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::TokenIntrospectionRequest,
    ) -> Result<crate::identity::oidc::IntrospectionResponse, IdentityError> {
        use crate::identity::oidc::IntrospectionResponse;

        // 1. Verify Ed25519 signature against realm key (with global-key
        // fallback for Phase 0 realms). Forged or tampered tokens are
        // cryptographically rejected; RFC 7662 semantics: return inactive.
        let Ok(claims) = self.verify_token_signature_for_realm(realm_id, &request.token) else {
            return Ok(IntrospectionResponse::inactive());
        };

        // 2. Verify realm matches
        if claims.tid.parse::<RealmId>().ok().as_ref() != Some(realm_id) {
            return Ok(IntrospectionResponse::inactive());
        }

        // 2a. RFC 7519 §4.1.3 — audience must include the configured value.
        if !claims.aud.contains(&self.config.token.audience) {
            return Ok(IntrospectionResponse::inactive());
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

        // 4. Check session validity (if session-bound) or JTI blocklist (if sessionless)
        if claims.sid != "none" {
            let sid_str = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
            if let Ok(uuid) = uuid::Uuid::parse_str(sid_str) {
                let session_id = SessionId::new(uuid);
                if self.get_session(realm_id, &session_id)?.is_none() {
                    return Ok(IntrospectionResponse::inactive());
                }
            }
        } else if let Some(ref jti) = claims.jti {
            // Sessionless token — check JTI revocation projection (hot-path safe).
            let cache_key = format!("{}:{}", realm_id.as_uuid(), jti);
            if self
                .revoked_jti_cache
                .load()
                .contains_key(cache_key.as_str())
            {
                return Ok(IntrospectionResponse::inactive());
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
                    if family.revoked {
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

        let (live_permissions, live_roles, live_groups) =
            if authz_mode != AccessTokenAuthorization::Embedded {
                // Parse user_id from sub — client-credential tokens use a client
                // UUID as sub, which won't parse as a UserId; they get no live data.
                let sub_str = &claims.sub;
                let user_uuid_str = sub_str.strip_prefix("user_").unwrap_or(sub_str);
                if let Ok(user_uuid) = uuid::Uuid::parse_str(user_uuid_str) {
                    let user_id = crate::core::UserId::new(user_uuid);
                    let org_id: Option<crate::core::OrganizationId> =
                        claims.oid.as_deref().and_then(|o| {
                            uuid::Uuid::parse_str(o.strip_prefix("org_").unwrap_or(o))
                                .ok()
                                .map(crate::core::OrganizationId::new)
                        });
                    let resolved_live = self
                        .rbac
                        .resolve_permissions(&user_id, realm_id, org_id.as_ref(), None)
                        .unwrap_or_default();
                    let perms: Vec<String> = resolved_live
                        .permissions
                        .iter()
                        .map(|p| p.as_str().to_string())
                        .collect();
                    (perms, resolved_live.roles, resolved_live.groups)
                } else {
                    (vec![], vec![], vec![])
                }
            } else {
                (vec![], vec![], vec![])
            };

        // 7. Active — return metadata
        Ok(IntrospectionResponse {
            active: true,
            scope: claims.scope,
            client_id: None, // Not stored in claims for session-bound tokens
            sub: Some(claims.sub),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            token_type: Some(claims.token_type),
            iss: Some(claims.iss),
            aud: Some(claims.aud.base().to_string()),
            mode: Some(authz_mode),
            permissions: live_permissions,
            roles: live_roles,
            groups: live_groups,
        })
    }

    pub(super) fn decide_token_permission_inner(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::DecidePermissionRequest,
    ) -> Result<crate::identity::oidc::DecidePermissionResponse, IdentityError> {
        use crate::identity::oidc::DecidePermissionResponse;
        use crate::rbac::Permission;

        // Validate signature + realm binding — fail-closed on any error.
        let Ok(claims) = self.verify_token_signature_for_realm(realm_id, &request.token) else {
            return Ok(DecidePermissionResponse { allowed: false });
        };
        if claims.tid.parse::<RealmId>().ok().as_ref() != Some(realm_id) {
            return Ok(DecidePermissionResponse { allowed: false });
        }
        if !claims.aud.contains(&self.config.token.audience) {
            return Ok(DecidePermissionResponse { allowed: false });
        }

        // Expiry check.
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        if now_secs >= claims.exp || claims.iat > now_secs + CLOCK_SKEW_SECS {
            return Ok(DecidePermissionResponse { allowed: false });
        }

        // Session / JTI revocation check.
        if claims.sid != "none" {
            let sid_str = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
            if let Ok(uuid) = uuid::Uuid::parse_str(sid_str) {
                if self.get_session(realm_id, &SessionId::new(uuid))?.is_none() {
                    return Ok(DecidePermissionResponse { allowed: false });
                }
            }
        } else if let Some(ref jti) = claims.jti {
            // Check JTI revocation projection (hot-path safe).
            let cache_key = format!("{}:{}", realm_id.as_uuid(), jti);
            if self
                .revoked_jti_cache
                .load()
                .contains_key(cache_key.as_str())
            {
                return Ok(DecidePermissionResponse { allowed: false });
            }
        }

        // Parse user from sub — client-credential tokens are never allowed
        // through the decision endpoint (no user context to check against).
        let sub_str = &claims.sub;
        let user_uuid_str = sub_str.strip_prefix("user_").unwrap_or(sub_str);
        let user_uuid = match uuid::Uuid::parse_str(user_uuid_str) {
            Ok(u) => u,
            Err(_) => return Ok(DecidePermissionResponse { allowed: false }),
        };
        let user_id = crate::core::UserId::new(user_uuid);

        // Validate requested permission string.
        let Ok(permission) = Permission::new(&request.permission) else {
            return Ok(DecidePermissionResponse { allowed: false });
        };

        // Parse optional org scoping.
        let org_id: Option<crate::core::OrganizationId> =
            request.organization_id.as_deref().and_then(|o| {
                uuid::Uuid::parse_str(o.strip_prefix("org_").unwrap_or(o))
                    .ok()
                    .map(crate::core::OrganizationId::new)
            });

        // Apply scope narrowing from the token if present.
        let scope_str = claims.scope.as_deref();
        let scope_single = scope_str.filter(|s| s.split_whitespace().count() == 1);

        let resolved =
            match self
                .rbac
                .resolve_permissions(&user_id, realm_id, org_id.as_ref(), scope_single)
            {
                Ok(r) => r,
                Err(_) => return Ok(DecidePermissionResponse { allowed: false }),
            };

        Ok(DecidePermissionResponse {
            allowed: resolved.permissions.contains(&permission),
        })
    }

    // ===== UserInfo (OIDC Core §5.3) =====

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
        let client = claims
            .aud
            .base()
            .strip_prefix("client_")
            .and_then(|uuid| uuid::Uuid::parse_str(uuid).ok())
            .and_then(|uuid| {
                self.get_client(realm_id, &ClientId::new(uuid))
                    .ok()
                    .flatten()
            });
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

        Ok(crate::identity::oidc::UserInfoResponse {
            sub: claims.sub,
            email: custom
                .get("email")
                .and_then(|value| value.as_str().map(str::to_string)),
            email_verified: scope_set.contains("email").then_some(true),
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
        let secret_hash = client
            .client_secret_hash()
            .ok_or(IdentityError::InvalidClientSecret)?;
        let valid = credentials::verify_raw_secret(client_secret.as_bytes(), secret_hash)?;
        if !valid {
            return Err(IdentityError::InvalidClientSecret);
        }
        Ok(())
    }

    pub(super) fn list_clients_inner(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OAuthClient>, IdentityError> {
        let prefix = keys::oauth_client_scan_prefix();
        let start = if let Some(cursor_str) = cursor {
            let uuid_str = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key = format!("oauth:client:{uuid_str}").into_bytes();
            cursor_key.push(0xFF);
            cursor_key
        } else {
            prefix.clone()
        };
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(realm_id, &start, &end)
            .map_err(Self::storage_err)?;

        let mut items = Vec::new();
        for entry in entries.iter().take(limit + 1) {
            let client: OAuthClient =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            items.push(client);
        }

        let next_cursor = if items.len() > limit {
            items.pop(); // discard the extra item
            let last_kept = items.last().expect("limit >= 1");
            Some(URL_SAFE_NO_PAD.encode(last_kept.client_id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
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

    pub(super) fn authenticate_client_inner(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        client_secret: Option<&str>,
    ) -> Result<(), IdentityError> {
        // Return InvalidClientSecret (not ClientNotFound) on any failure to
        // prevent client enumeration via error differentiation.
        let client = self
            .get_client(realm_id, client_id)?
            .ok_or(IdentityError::InvalidClientSecret)?;

        if let Some(hash) = client.client_secret_hash() {
            // Confidential client: secret is required and must match.
            let secret = client_secret.ok_or(IdentityError::InvalidClientSecret)?;
            if !credentials::verify_raw_secret(secret.as_bytes(), hash)? {
                return Err(IdentityError::InvalidClientSecret);
            }
        }
        // Public client: no secret needed, client_id alone suffices.
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
            client.set_backchannel_logout_uri(uri.clone());
        }
        if let Some(uri) = &request.frontchannel_logout_uri {
            client.set_frontchannel_logout_uri(uri.clone());
        }
        if let Some(uris) = &request.post_logout_redirect_uris {
            client.set_post_logout_redirect_uris(uris.clone());
        }
        if let Some(status) = request.status {
            client.set_status(status);
        }
        if let Some(pk) = &request.assertion_public_key {
            // Validate base64url decodes to exactly 32 bytes (Ed25519 public key)
            if let Some(key_str) = pk {
                let decoded =
                    URL_SAFE_NO_PAD
                        .decode(key_str)
                        .map_err(|_| IdentityError::InvalidInput {
                            reason: "assertion_public_key must be base64url-encoded".to_string(),
                        })?;
                if decoded.len() != 32 {
                    return Err(IdentityError::InvalidInput {
                        reason: "assertion_public_key must be a 32-byte Ed25519 public key"
                            .to_string(),
                    });
                }
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
        if let Some(profile) = request.profile {
            if profile.is_fapi2() && client.client_secret_hash().is_some() {
                return Err(IdentityError::FapiViolation {
                    reason: "Cannot set FAPI 2.0 profile on a client with a client_secret; \
                             remove the secret first or register a new FAPI2 client"
                        .to_string(),
                });
            }
            client.set_profile(profile);
        }
        if let Some(mfa_req) = request.mfa_required {
            client.set_mfa_required(mfa_req);
        }

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

        // Generate new random secret (32 bytes, base64url)
        let rng = ring::rand::SystemRandom::new();
        let mut secret_bytes = [0u8; 32];
        rng.fill(&mut secret_bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "failed to generate random bytes for client secret".to_string(),
            })?;
        let plaintext_secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        // Hash with Argon2id
        let secret_hash =
            credentials::hash_raw_secret(plaintext_secret.as_bytes(), &self.config.credential)?;
        client.set_client_secret_hash(secret_hash);

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

        Ok(plaintext_secret)
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
        // Consent keys are `oauth:consent:{user_uuid}:{client_uuid}`, so
        // we scan the whole namespace and match the trailing client segment.
        let consent_prefix = keys::oauth_consent_scan_prefix();
        let consent_end = keys::prefix_end(&consent_prefix);
        let consent_entries = self
            .storage
            .scan(realm_id, &consent_prefix, &consent_end)
            .map_err(Self::storage_err)?;
        let client_uuid_str = client_id.as_uuid().to_string();
        for entry in &consent_entries {
            if let Ok(key_str) = std::str::from_utf8(&entry.key) {
                if key_str.ends_with(&client_uuid_str) {
                    self.storage
                        .delete(realm_id, &entry.key)
                        .map_err(Self::storage_err)?;
                }
            }
        }
        self.record_audit(
            realm_id,
            None,
            AuditAction::ClientDeleted,
            "client",
            &client_id.as_uuid().to_string(),
        )?;
        Ok(())
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
        let ticket = uuid::Uuid::new_v4().to_string();
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
        let key = keys::encode_pending_auth_key(ticket);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ConsentTicketNotFound)?;
        // Single-use: delete before we even validate expiry so callers can
        // never replay the same ticket twice even on a narrow race.
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)?;
        let pending: PendingAuthorizationRequest =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
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
            // Decode without signature verification — OIDC spec allows expired hints.
            let claims =
                tokens::decode_claims_unverified(hint).map_err(|_| IdentityError::InvalidToken)?;
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

                if let Some(bcl_uri) = client.backchannel_logout_uri() {
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

                if let Some(fcl_uri) = client.frontchannel_logout_uri() {
                    frontchannel_targets.push(FrontchannelTarget {
                        uri: fcl_uri.to_string(),
                        client_id: client_id.clone(),
                    });
                }
            }
        }

        // Validate post_logout_redirect_uri against the registering client's list.
        let post_logout_redirect_uri = match &request.post_logout_redirect_uri {
            None => None,
            Some(uri) => {
                let valid = match &request.client_id {
                    None => true, // No client specified — accept without validation.
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
