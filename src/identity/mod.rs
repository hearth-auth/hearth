//! Identity engine: users, credentials, sessions, realms, and tokens.
//!
//! Domain logic layer that orchestrates authentication flows.
//! Depends on `storage` (for persistence) and `core` (for shared types).
//! May call `authz` (lateral dependency). Never the reverse.

pub mod approval_notifier;
pub mod claims_config;
pub(crate) mod cleanup;
pub(crate) mod credentials;
pub mod device_fingerprint;
pub mod device_fp;
pub mod dpop;
pub mod email;
mod engine;
pub mod error;
pub mod federation;
pub mod hibp;
pub mod kdf_gate;
pub mod key_encryption;
pub(crate) mod keys;
pub mod ldap;
pub(crate) mod magic_link;
pub mod mcp;
pub mod migration;
pub mod oidc;
pub mod onboarding;
pub mod pre_token_webhook;
pub mod ra_token;
pub mod reconcile;
pub mod risk;
pub mod search;
pub mod session_version;
pub mod sessions;
pub mod sms;
pub mod tokens;
pub mod tool_permissions;
pub(crate) mod totp;
mod types;
mod validation;
pub(crate) mod webauthn;

/// Public re-implementations of key-storage helpers for integration tests and
/// the `test-hooks` feature.  Not part of the stable public API.
#[cfg(any(test, feature = "test-hooks"))]
pub mod keys_test_helpers {
    use crate::core::RealmId;

    /// Returns the nil-UUID system realm used for internal key storage.
    pub fn system_realm_id() -> RealmId {
        RealmId::new(uuid::Uuid::nil())
    }

    /// Returns the storage key for the global Ed25519 signing key.
    pub fn encode_global_signing_key() -> Vec<u8> {
        b"sys:global:key".to_vec()
    }

    /// Returns the storage key for a per-realm Ed25519 signing key.
    pub fn encode_realm_signing_key(realm_id: &RealmId) -> Vec<u8> {
        format!("realm:key:{}", realm_id.as_uuid()).into_bytes()
    }

    /// Returns `true` when the given storage key holds cryptographic key
    /// material that must never appear in admin exports or scans.
    pub fn is_key_material(key: &[u8]) -> bool {
        super::keys::is_key_material(key)
    }
}

pub use credentials::{
    hash_password, verify_password_with_pepper, CleartextPassword, CredentialConfig, PepperConfig,
    PepperKey, StoredCredential,
};
pub use email::{
    ApiKey, EmailBranding, EmailError, EmailMessage, EmailSender, EmailService, LoggingEmailSender,
    MailgunEmailSender, MailtrapEmailSender, PostmarkEmailSender, SendgridEmailSender,
    SharedEmailSender, StubHttpTransport,
};
pub use engine::{
    EmbeddedIdentityEngine, IdentityConfig, RateLimitConfig, SessionConfig, TokenIssuanceContext,
};
pub use error::IdentityError;
pub use kdf_gate::{
    admin_gate, gate, init_admin_gate, init_gate, KdfGate, KdfGateConfig, KdfGateError,
    DEFAULT_ADMIN_MAX_IN_FLIGHT, DEFAULT_ADMIN_MAX_QUEUE_WAIT_MS,
};
pub use magic_link::MagicLinkResponse;
pub use oidc::{
    fuzz_parse_token_exchange, AccessTokenAuthorization, ApplicationStatus, AuthorizationRequest,
    AuthorizationResponse, ClientCredentialsRequest, ClientCredentialsResponse, ClientProfile,
    ClientTrustLevel, CodeChallengeMethod, DecidePermissionRequest, DecidePermissionResponse,
    DeviceAuthorizationRequest, DeviceAuthorizationResponse, DeviceCodeStatus,
    IntrospectionResponse, JarClaims, JwtBearerRequest, OAuthClient, OidcConfig,
    OidcDiscoveryDocument, OidcTokenResponse, PasswordGrantRequest, PasswordGrantResponse,
    PushedAuthorizationRequest, PushedAuthorizationResponse, RefreshBindContext,
    RegisterClientRequest, ResponseMode, StepUpMfaGrantRequest, TokenExchangeRequest,
    TokenIntrospectionRequest, TokenRevocationRequest, UpdateClientRequest, UserInfoResponse,
};
pub use session_version::{SessionVersionStore, SvDeltaEntry, SvDeltaResponse, SvSnapshotResponse};
pub use sms::{
    LoggingSmsSender, SharedSmsSender, SmsError, SmsMessage, SmsSecret, SmsSender, SnsSmsSender,
    StubSmsHttpTransport, TwilioSmsSender,
};
pub use tokens::{
    decode_claims_unverified, validate_token_with_time, verify_assertion_signature,
    verify_token_signature, CnfClaim, IssueTokenRequest, Jwk, JwksDocument, JwtAssertionClaims,
    SigningKey, TokenClaims, TokenConfig, TokenPair, REQUIRED_ACTION_TOKEN_TYPE,
};
pub use totp::{RecoveryCodes, TotpEnrollment};
pub use types::{
    canonicalize_scopes, AdaptiveMfaConfig, ApprovalWebhookConfig, AttributeDefinition,
    AttributeDefinitions, AttributeType, BreachCheckConfig, BulkResult, ConsentDecision,
    ConsentListEntry, ConsentRecord, CreateInvitationRequest, CreateOrganizationRequest,
    CreateRealmRequest, CreateUserRequest, CreateWebhookRequest, CredentialExport, DcrPolicy,
    DemoSeedOutcome, DemoSeedSpec, FapiProfile, ImportClientRequest, ImportUserRequest,
    InvitationStatus, MigrationReport, Organization, OrganizationConfig, OrganizationInvitation,
    OrganizationMembership, OrganizationRole, OrganizationStatus, Page, PasswordPolicy,
    PendingAuthorizationRequest, PreTokenWebhookConfig, PreTokenWebhookErrorPolicy, RawCredential,
    Realm, RealmConfig, RealmQuotaConfig, RealmStatus, RegisterUserRequest, RegisterUserResponse,
    RegistrationPolicy, RequiredAction, RequiredActionTokenResponse, Session, SessionContext,
    SessionLimitPolicy, SessionVersionConfig, UpdateOrganizationRequest, UpdateRealmRequest,
    UpdateUserRequest, UpdateWebhookRequest, User, UserStatus, WebAuthnAttestationPolicy, Webhook,
};
pub use types::{
    AatClaims, AatResponse, AatToolPermission, Agent, AgentCredential, AgentCredentialKind,
    AgentOwner, AgentStatus, ApprovalRequest, ApprovalRequestResponse, ApprovalRequestStatus,
    CapabilityTokenInfo, CreateAgentApiKeyRequest, CreateAgentApiKeyResponse, CreateAgentRequest,
    CreateApprovalRequestInput, CreateCrossRealmPolicyRequest, CreateTransactionTokenRequest,
    CrossRealmTrustPolicy, DelegationGrantEntry, DeriveAatRequest, IssueAatRequest,
    ListAgentsQuery, PlaintextApiKey, ProtectedResource, RegisterProtectedResourceRequest,
    RegisterSpiffeIdRequest, Rfc8693Request, Rfc8693Response, SpiffeIdentityMapping,
    StoredDelegationGrant, TransactionTokenClaims, TransactionTokenResponse, UpdateAgentRequest,
    UpdateProtectedResourceRequest,
};
pub use validation::fuzz_validate_redirect_uri;
pub use webauthn::{
    fuzz_parse_webauthn, AuthenticationOptions, CompleteAuthenticationParams, RegistrationOptions,
    WebAuthnAuthResult, WebAuthnCredentialInfo,
};

use crate::audit::AuditContext;
use crate::core::{
    AgentId, ClientId, InvitationId, OrganizationId, PageRequest, PagedResult, RealmId,
    ResourceServerId, SessionId, Timestamp, UserId, WebhookId,
};

// Maximum page size for all paginated list operations (A-23).
// Callers supplying `limit > MAX_PAGE_SIZE` receive `IdentityError::InvalidInput`.
// This constant is also re-exported from `crate::abuse::MAX_PAGE_SIZE`.

// ─────────────────────────────────────────────────────────────────────────────
// Migration helpers (pepper rotation tooling)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the storage scan prefix for credentials (used by migration tools).
#[must_use]
pub fn credential_scan_prefix_for_migration() -> Vec<u8> {
    crate::identity::keys::credential_scan_prefix()
}

pub const MAX_PAGE_SIZE: usize = crate::abuse::MAX_PAGE_SIZE;

/// Clamps `limit` to [`MAX_PAGE_SIZE`], returning an `IdentityError` if the
/// caller requested more rows than the cap allows.
///
/// Handlers should call this before passing `limit` to any trait method.
///
/// # Errors
///
/// Returns `IdentityError::InvalidInput` when `limit > MAX_PAGE_SIZE`.
pub fn cap_page_size(limit: usize) -> Result<usize, IdentityError> {
    if limit > MAX_PAGE_SIZE {
        return Err(IdentityError::InvalidInput {
            reason: format!("page size {limit} exceeds maximum {MAX_PAGE_SIZE}"),
        });
    }
    Ok(limit)
}

/// Trait defining the identity engine interface.
///
/// Synchronous for Phase 0 — callers should use `spawn_blocking` for async
/// contexts. All operations require a `RealmId` for multi-realm isolation.
///
/// # Realm lifecycle
///
/// Phase 1 adds first-class realm management. Realms are stored in a
/// system namespace and each realm gets an independent Ed25519 signing
/// key for token issuance.
pub trait IdentityEngine: Send + Sync {
    // ===== Realm lifecycle =====

    /// Creates a new realm with the given configuration.
    ///
    /// Generates a `RealmId`, creates a per-realm Ed25519 signing key,
    /// and persists both the realm record and key material.
    fn create_realm(&self, request: &CreateRealmRequest) -> Result<Realm, IdentityError>;

    /// Retrieves a realm by ID. Returns `None` if not found.
    fn get_realm(&self, realm_id: &RealmId) -> Result<Option<Realm>, IdentityError>;

    /// Retrieves a realm by name. Returns `None` if not found.
    ///
    /// Uses the `realm:name:{name}` index for O(1) lookup.
    fn get_realm_by_name(&self, name: &str) -> Result<Option<Realm>, IdentityError>;

    /// Updates an existing realm's fields.
    ///
    /// Only non-`None` fields in the request are applied.
    fn update_realm(
        &self,
        realm_id: &RealmId,
        request: &UpdateRealmRequest,
    ) -> Result<Realm, IdentityError>;

    /// Deletes a realm and all associated data.
    ///
    /// Cascading deletion removes all users, sessions, credentials,
    /// authorization tuples, OAuth clients, and the realm's signing key.
    fn delete_realm(&self, realm_id: &RealmId) -> Result<(), IdentityError>;

    /// Returns the JWKS document for a specific realm.
    ///
    /// Each realm has its own signing key, so its JWKS document contains
    /// only that realm's public key. During a key rotation grace period both
    /// the new active key and any non-expired retiring keys are included.
    fn realm_jwks(&self, realm_id: &RealmId) -> Result<JwksDocument, IdentityError>;

    /// Generates a signed Required-Action session JWT for the OIDC login path.
    ///
    /// Signs with the realm's Ed25519 key. The `pending_actions` list is
    /// embedded in the token verbatim — callers are responsible for sorting by
    /// priority before calling this function.
    fn generate_ra_token(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        pending_actions: Vec<RequiredAction>,
        oidc_params: ra_token::OidcParams,
        now: Timestamp,
    ) -> Result<String, IdentityError>;

    /// Generates a signed Required-Action session JWT for the direct browser
    /// login path.
    ///
    /// After all actions complete, the flow resumes by creating a session
    /// cookie and redirecting to `return_to` (or `/ui` when `None`).
    fn generate_browser_ra_token(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        pending_actions: Vec<RequiredAction>,
        return_to: Option<String>,
        now: Timestamp,
    ) -> Result<String, IdentityError>;

    /// Validates a Required-Action session JWT using the realm's public key.
    ///
    /// Checks signature, `alg`/`typ` headers, and expiry. Returns the decoded
    /// claims on success.
    fn validate_ra_token(
        &self,
        realm_id: &RealmId,
        token: &str,
        now: Timestamp,
    ) -> Result<ra_token::RaClaims, ra_token::RaTokenError>;

    /// Validates a `TokenClaims`-based Required-Action JWT issued for the new
    /// browser interstitial flow (`/ui/required-actions/…`).
    ///
    /// Verifies the Ed25519 signature against the realm key, checks that
    /// `token_type == REQUIRED_ACTION_TOKEN_TYPE`, checks expiry, and asserts
    /// that `required_actions` contains `action`.  Returns the decoded claims.
    fn validate_required_action_token(
        &self,
        realm_id: &RealmId,
        token: &str,
        action: RequiredAction,
    ) -> Result<tokens::TokenClaims, IdentityError>;

    /// Completes the `UPDATE_PASSWORD` required action for a browser-flow user.
    ///
    /// Validates the RA JWT, applies the new password (enforcing realm policy),
    /// removes `UPDATE_PASSWORD` from the user's pending action set, then:
    /// - if further actions remain — issues a new RA JWT for the next action;
    /// - if all actions are satisfied — creates a session and issues a
    ///   full-access token.
    ///
    /// The caller distinguishes the two outcomes by checking `token_type` in
    /// the decoded `access_token` claims: `"ra"` vs `"access"`.
    fn complete_update_password(
        &self,
        realm_id: &RealmId,
        ra_token: &str,
        new_password: CleartextPassword,
    ) -> Result<types::RequiredActionTokenResponse, IdentityError>;

    /// Initiates or re-sends an email-verification request for a user.
    ///
    /// Issues a single-use verification token (rate-limited), stores the
    /// SHA-256 hash, and returns `Ok(())`.  Email delivery is best-effort;
    /// callers may observe `RateLimited` when the user has requested too
    /// many tokens in a short window.
    fn request_email_verification(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<(), IdentityError>;

    /// Rotates the Ed25519 signing key for a realm.
    ///
    /// Generates a new key, writes it as the active key, and stores the old
    /// key as a retiring key with a deadline of `now + grace_period_secs`.
    /// The JWKS endpoint will serve both keys until the deadline passes.
    fn rotate_realm_signing_key(
        &self,
        realm_id: &RealmId,
        grace_period_secs: u64,
    ) -> Result<(), IdentityError>;

    /// Creates a new user in the given realm.
    ///
    /// Validates input, normalizes the email, checks uniqueness, generates
    /// a `UserId`, and persists the user record with both primary and email
    /// index entries.
    ///
    /// Rejects the reserved system realm with `SystemRealmProtected`.
    /// To create an administrator, use [`Self::create_admin_user`].
    fn create_user(
        &self,
        realm_id: &RealmId,
        request: &CreateUserRequest,
    ) -> Result<User, IdentityError>;

    /// Creates a new user record in the reserved system realm.
    ///
    /// This is the only public entry point that writes into the system
    /// realm. It does *not* grant the `realm.admin` RBAC role —
    /// callers (onboarding, admin UI) must issue the corresponding
    /// `assign_role` call themselves so the two writes sit next to each
    /// other at the call site rather than hidden inside the engine.
    fn create_admin_user(&self, request: &CreateUserRequest) -> Result<User, IdentityError>;

    /// Retrieves a user by ID. Returns `None` if not found.
    fn get_user(&self, realm_id: &RealmId, user_id: &UserId)
        -> Result<Option<User>, IdentityError>;

    /// Retrieves a user by email address. Returns `None` if not found.
    ///
    /// The email is normalized (lowercase, trimmed, NFC) before lookup.
    fn get_user_by_email(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<Option<User>, IdentityError>;

    /// Updates an existing user's fields.
    ///
    /// Only non-`None` fields in the request are applied. If the email changes,
    /// the old email index is removed and a new one is created (with uniqueness check).
    fn update_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        request: &UpdateUserRequest,
    ) -> Result<User, IdentityError>;

    /// Deletes a user by ID, removing both primary and email index entries.
    ///
    /// Returns `IdentityError::UserNotFound` if the user does not exist.
    fn delete_user(&self, realm_id: &RealmId, user_id: &UserId) -> Result<(), IdentityError>;

    /// Deletes all device fingerprints for a user (GDPR Art. 17 / AC-11).
    ///
    /// Used by the admin erasure endpoint
    /// (`DELETE /admin/users/{id}/device-fingerprints`) to satisfy DSAR
    /// erasure demands without deleting the entire account.
    ///
    /// Returns the number of fingerprint records removed. Does not error if
    /// the user has no fingerprints — returns `Ok(0)`.
    fn delete_user_device_fingerprints(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<usize, IdentityError>;

    /// Creates a new user and emits exactly one `UserCreated` audit event
    /// attributed to the provided actor.
    ///
    /// Equivalent to [`Self::create_user`] but the caller supplies the audit
    /// context (actor identity + optional metadata such as `{"via":"admin_api"}`).
    /// Use this from protocol handlers that have an authenticated principal —
    /// it replaces the pattern of calling `create_user` then appending a second
    /// `UserCreated` event manually.
    fn create_user_attributed(
        &self,
        realm_id: &RealmId,
        request: &CreateUserRequest,
        audit_ctx: &AuditContext,
    ) -> Result<User, IdentityError>;

    /// Updates an existing user and emits exactly one `UserUpdated` audit event
    /// attributed to the provided actor.
    ///
    /// See [`Self::create_user_attributed`] for the design rationale.
    fn update_user_attributed(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        request: &UpdateUserRequest,
        audit_ctx: &AuditContext,
    ) -> Result<User, IdentityError>;

    /// Deletes a user and emits exactly one `UserDeleted` audit event
    /// attributed to the provided actor.
    ///
    /// See [`Self::create_user_attributed`] for the design rationale.
    fn delete_user_attributed(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        audit_ctx: &AuditContext,
    ) -> Result<(), IdentityError>;

    /// Sets (or replaces) the password for a user.
    ///
    /// Hashes the password using Argon2id with the configured parameters
    /// and stores the credential. The user must exist.
    fn set_password(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        password: &CleartextPassword,
    ) -> Result<(), IdentityError>;

    /// Verifies a password against the stored credential for a user.
    ///
    /// Returns `Ok(true)` if the password matches, `Ok(false)` if it does
    /// not match. Returns `Err` if the user or credential does not exist.
    ///
    /// If the stored credential uses a legacy algorithm (bcrypt/scrypt),
    /// a successful verification will automatically upgrade the hash to
    /// Argon2id.
    fn verify_password(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        password: &CleartextPassword,
    ) -> Result<bool, IdentityError>;

    /// Runs a dummy Argon2id hash of `password` and discards the result.
    ///
    /// Call this when a user is not found during login so the response
    /// timing is indistinguishable from a real failed verification, preventing
    /// user enumeration via timing side-channels.
    fn dummy_verify_password(&self, password: &CleartextPassword);

    /// Checks whether the given IP has exceeded the per-IP login rate limit
    /// for a realm. Returns `Err(RateLimited)` when blocked.
    ///
    /// The default implementation is a no-op (`Ok(())`); the embedded engine
    /// overrides it with a sliding-window counter.
    fn check_ip_login_rate_limit(
        &self,
        _realm_id: &RealmId,
        _ip: &str,
    ) -> Result<(), IdentityError> {
        Ok(())
    }

    /// Records a failed login attempt for the given IP so subsequent calls
    /// to `check_ip_login_rate_limit` can enforce the window threshold.
    ///
    /// The default implementation is a no-op; the embedded engine overrides.
    fn record_ip_login_attempt(&self, _realm_id: &RealmId, _ip: &str) {}

    /// Returns the number of seconds remaining in the current rate-limit window
    /// for an IP that has already hit its limit (for `Retry-After` headers).
    ///
    /// Returns 0 when the IP is not blocked. Default implementation returns 0.
    fn ip_login_retry_after_secs(&self, _realm_id: &RealmId, _ip: &str) -> u64 {
        0
    }

    /// Changes a user's password after verifying the old one.
    ///
    /// Returns `Err(InvalidCredential)` if the old password is wrong.
    /// Returns `Err(CredentialNotFound)` if no credential exists.
    fn change_password(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        old_password: &CleartextPassword,
        new_password: &CleartextPassword,
    ) -> Result<(), IdentityError>;

    // ===== Session management =====

    /// Creates a new session bound to the given user.
    ///
    /// Generates a random `SessionId`, sets TTL from configuration,
    /// and persists the session record. The user must exist.
    ///
    /// `context` carries optional device and network metadata (IP, User-Agent)
    /// captured at the point of authentication. Pass `&SessionContext::default()`
    /// for API-originated or test sessions without browser context.
    fn create_session(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        context: &SessionContext,
    ) -> Result<Session, IdentityError>;

    /// Looks up a session by ID.
    ///
    /// Returns `Ok(Some(session))` only if the session exists, is not
    /// expired, and has not been revoked. Returns `Ok(None)` for all
    /// other cases (enumeration resistance).
    fn get_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Option<Session>, IdentityError>;

    /// Revokes a session immediately.
    ///
    /// After revocation, `get_session` will return `None`.
    /// Returns `Err(SessionNotFound)` if the session does not exist.
    fn revoke_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<(), IdentityError>;

    /// Refreshes a session, extending its TTL from the current time.
    ///
    /// Returns the updated session. Returns `Err(SessionNotFound)` if
    /// the session does not exist, is expired, or has been revoked.
    fn refresh_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Session, IdentityError>;

    /// Lists all sessions belonging to a user, with offset-based pagination.
    ///
    /// Sessions are returned by their UUID ordering in the
    /// `ses:user:{user_uuid}:{session_uuid}` index.
    fn list_sessions_by_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        page: &PageRequest,
    ) -> Result<PagedResult<Session>, IdentityError>;

    /// Lists all active sessions in a realm, with offset-based pagination.
    ///
    /// Revoked sessions are excluded. Sessions are returned by their UUID
    /// ordering in the `ses:id:{session_uuid}` primary key space.
    fn list_sessions_by_realm(
        &self,
        realm_id: &RealmId,
        page: &PageRequest,
    ) -> Result<PagedResult<Session>, IdentityError>;

    /// Revokes all active sessions (and their grant families) for a user.
    ///
    /// `keep` exempts one session from revocation so the caller's device
    /// can stay logged in after a sensitive credential mutation.
    /// Pass `None` to revoke every session.
    ///
    /// Returns the count of sessions that were actually revoked.
    fn revoke_all_user_sessions(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        keep: Option<&SessionId>,
    ) -> Result<u32, IdentityError>;

    // ===== Token management =====

    /// Issues an access/refresh token pair for a session.
    ///
    /// The user and session must exist and be valid. Tokens are signed
    /// with Ed25519 and contain claims binding the token to the user,
    /// session, and realm.
    fn issue_tokens(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        session_id: &SessionId,
    ) -> Result<TokenPair, IdentityError>;

    /// Issues a token pair with explicit OAuth / org context.
    ///
    /// Compared to the plain `issue_tokens`, this method additionally:
    /// - Looks up the `OAuthClient` identified by `ctx.client_id` (if any)
    ///   and uses it as the client context for claim-profile gate evaluation.
    /// - Passes `ctx.granted_scopes` to the claim-profile resolver so
    ///   scope-gated claim mappings are evaluated correctly.
    /// - Embeds `ctx.oid` as the `oid` (org context) claim.
    ///
    /// The existing `issue_tokens` is a thin wrapper that calls this method
    /// with `TokenIssuanceContext::default()`.
    fn issue_tokens_with_context(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        session_id: &SessionId,
        ctx: &TokenIssuanceContext,
    ) -> Result<TokenPair, IdentityError>;

    /// Validates an access token: verifies the Ed25519 signature, enforces
    /// `exp`, checks the realm binding (`tid`), and confirms the session is
    /// still active. Returns decoded claims only when all checks pass.
    ///
    /// Returns `Arc<TokenClaims>` so the zero-allocation hot path can serve a
    /// warm token-claims-cache hit by bumping a refcount rather than deep-cloning
    /// every claim field (HEA-1771). `Arc<TokenClaims>` derefs to `TokenClaims`,
    /// so callers reading claim fields need no change.
    fn validate_token(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<std::sync::Arc<TokenClaims>, IdentityError>;

    /// Refreshes tokens: validates the refresh token, then issues a new pair.
    ///
    /// The refresh token's session must still be valid. The session's TTL
    /// is also refreshed. Returns a new token pair with updated expiration.
    ///
    /// `dpop_jkt` is the JWK thumbprint extracted from the DPoP proof header on
    /// the current request (RFC 9449). FAPI 2.0 clients require it; the
    /// refreshed access token will carry `cnf.jkt` bound to this thumbprint.
    fn refresh_tokens(
        &self,
        realm_id: &RealmId,
        refresh_token: &str,
        dpop_jkt: Option<&str>,
        bind_ctx: Option<&RefreshBindContext>,
    ) -> Result<TokenPair, IdentityError>;

    /// Returns the JWKS document containing public keys for external verification.
    fn jwks(&self) -> JwksDocument;

    // ===== OIDC / OAuth 2.0 =====

    /// Registers a new OAuth 2.0 client.
    ///
    /// Validates the client name and redirect URIs, generates a `ClientId`,
    /// and persists the client record.
    fn register_client(
        &self,
        realm_id: &RealmId,
        request: &RegisterClientRequest,
    ) -> Result<OAuthClient, IdentityError>;

    /// Initiates an OAuth 2.0 authorization code flow.
    ///
    /// Validates the client, redirect URI, response type, and state parameter.
    /// Generates a cryptographically random authorization code, stores it
    /// (hashed), and returns the code with the echoed state.
    fn authorize(
        &self,
        realm_id: &RealmId,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationResponse, IdentityError>;

    /// Exchanges an authorization code for access, ID, and refresh tokens.
    ///
    /// Validates the code (exists, not expired, not used, correct client and
    /// redirect URI), verifies PKCE if a code challenge was present, marks
    /// the code as used, creates a session, and issues tokens.
    fn exchange_authorization_code(
        &self,
        realm_id: &RealmId,
        request: &TokenExchangeRequest,
    ) -> Result<OidcTokenResponse, IdentityError>;

    /// Returns the OIDC Discovery document.
    ///
    /// Contains metadata about the provider's endpoints, supported response
    /// types, signing algorithms, and PKCE methods.
    fn oidc_discovery(&self) -> OidcDiscoveryDocument;

    /// Processes RP-initiated logout (OIDC RPL §2 + OIDC BCL §2.5).
    ///
    /// Revokes the identified session and its associated refresh-token grant
    /// families, then collects back-channel and front-channel logout targets
    /// for all RPs that received tokens under this session. Pre-signs a
    /// logout token for each back-channel target so the HTTP layer can fan
    /// out notifications without touching cryptographic material directly.
    ///
    /// Accepts an expired `id_token_hint` per the OIDC spec (§2, ¶3). When
    /// neither an `id_token_hint` nor an explicit `session_id` is supplied,
    /// returns `InvalidToken`.
    fn initiate_logout(
        &self,
        realm_id: &RealmId,
        request: &oidc::RpLogoutRequest,
    ) -> Result<oidc::RpLogoutResult, IdentityError>;

    /// Returns a per-realm OIDC Discovery document.
    ///
    /// The `issuer` in the returned document is `{base_issuer}/realms/{name}`,
    /// enabling distinct OIDC issuers per realm. All endpoint URLs are prefixed
    /// with the per-realm issuer.
    ///
    /// Returns `RealmNotFound` when the realm does not exist.
    fn realm_oidc_discovery(
        &self,
        realm_id: &RealmId,
    ) -> Result<OidcDiscoveryDocument, IdentityError>;

    // ===== OAuth 2.0 Extended (Step 22) =====

    /// Issues tokens via the Resource Owner Password Credentials Grant (RFC 6749 §4.3).
    ///
    /// Looks up the user by email, verifies the password (enforcing per-account
    /// rate limits), creates a session, and issues an access + refresh token pair.
    /// Returns `Err(InvalidCredential)` for wrong email or password (intentionally
    /// vague for enumeration resistance).
    fn password_grant_token(
        &self,
        realm_id: &RealmId,
        request: &PasswordGrantRequest,
    ) -> Result<PasswordGrantResponse, IdentityError>;

    /// Completes a step-up MFA challenge and issues tokens (HEA-836).
    ///
    /// Used with `grant_type = urn:hearth:params:grant-type:step-up-mfa`.
    /// Re-verifies the user's password, validates the MFA code (TOTP or
    /// recovery), records the device fingerprint as trusted, and returns a
    /// full token pair.
    fn step_up_mfa_grant_token(
        &self,
        realm_id: &RealmId,
        request: &StepUpMfaGrantRequest,
    ) -> Result<PasswordGrantResponse, IdentityError>;

    /// Issues an access token via the Client Credentials Grant (RFC 6749 §4.4).
    ///
    /// Verifies the client secret using Argon2id, then issues an access token
    /// scoped to the client (no user context). Per RFC 6749 §4.4.3, refresh
    /// tokens SHOULD NOT be included.
    fn client_credentials_token(
        &self,
        realm_id: &RealmId,
        request: &ClientCredentialsRequest,
    ) -> Result<ClientCredentialsResponse, IdentityError>;

    /// Issues an access token via the JWT Bearer Grant (RFC 7523).
    ///
    /// Validates the JWT assertion against the client's registered Ed25519
    /// public key, enforces RFC 7523 §3 claim constraints (`iss`, `aud`,
    /// `exp`), and prevents JTI replay.  Issues a sessionless access token
    /// analogous to the client credentials grant.
    fn jwt_bearer_token(
        &self,
        realm_id: &RealmId,
        request: &JwtBearerRequest,
    ) -> Result<ClientCredentialsResponse, IdentityError>;

    /// Authenticates an OAuth confidential client using its client secret.
    ///
    /// Returns `Ok(())` only when the client exists in the target realm,
    /// is confidential, and the provided secret matches the stored hash.
    fn authenticate_oauth_client(
        &self,
        realm_id: &RealmId,
        client_id: &ClientId,
        client_secret: &str,
    ) -> Result<(), IdentityError>;

    /// Verifies a `private_key_jwt` client assertion per RFC 7523 §2.2.
    ///
    /// Validates signature, `iss == sub == client_id`, `exp` in the future,
    /// `aud` contains the realm issuer URL, and JTI replay prevention.
    fn verify_client_assertion(
        &self,
        realm_id: &RealmId,
        client_id: &ClientId,
        assertion: &str,
    ) -> Result<(), IdentityError>;

    /// Verifies a JAR (RFC 9101) signed request object.
    ///
    /// Looks up the client's registered `jwks`, selects the key matching the
    /// JWT header `kid`/`alg`, verifies the signature (EdDSA or RS256), and
    /// validates `iss == client_id`, `aud` contains the realm issuer URL, and
    /// `exp` is in the future. Returns the decoded [`JarClaims`] on success.
    ///
    /// Rejects `alg: none`, missing JWKS, unknown `kid`, and any claim
    /// validation failure with [`IdentityError::InvalidJar`].
    fn verify_jar(
        &self,
        realm_id: &RealmId,
        client_id: &ClientId,
        request_jwt: &str,
    ) -> Result<JarClaims, IdentityError>;

    /// Initiates a Device Authorization Grant (RFC 8628).
    ///
    /// Generates a device code and a short user code, stores them, and
    /// returns the verification URI and polling interval.
    fn device_authorize(
        &self,
        realm_id: &RealmId,
        request: &DeviceAuthorizationRequest,
    ) -> Result<DeviceAuthorizationResponse, IdentityError>;

    /// Approves a device authorization by user code.
    ///
    /// Transitions the device code status from `Pending` to `Approved`.
    fn approve_device(
        &self,
        realm_id: &RealmId,
        user_code: &str,
        user_id: &UserId,
    ) -> Result<(), IdentityError>;

    /// Polls for a device authorization token (RFC 8628 §3.4).
    ///
    /// Returns tokens if the user has approved, or an appropriate error
    /// (`AuthorizationPending`, `SlowDown`, `DeviceCodeExpired`, `DeviceCodeDenied`).
    fn poll_device_token(
        &self,
        realm_id: &RealmId,
        device_code: &str,
        client_id: &crate::core::ClientId,
    ) -> Result<OidcTokenResponse, IdentityError>;

    /// Revokes a token (RFC 7009).
    ///
    /// For access tokens: extracts session ID and revokes the session.
    /// For refresh tokens: looks up the grant family and marks it revoked.
    /// Pushes authorization parameters to the PAR endpoint (RFC 9126).
    ///
    /// Validates the client, redirect URI, and PKCE (required for public
    /// clients), then stores the parameters under a 90-second TTL.
    /// Returns a `request_uri` the client passes to `/authorize`.
    fn push_authorization_request(
        &self,
        realm_id: &RealmId,
        request: &PushedAuthorizationRequest,
    ) -> Result<PushedAuthorizationResponse, IdentityError>;

    /// Consumes a stored PAR entry identified by its `request_uri`.
    ///
    /// Returns the stored parameters on success. The entry is atomically
    /// marked used; subsequent calls return `InvalidPushedAuthorizationRequest`.
    #[allow(private_interfaces)]
    fn consume_par(
        &self,
        realm_id: &RealmId,
        request_uri: &str,
    ) -> Result<oidc::StoredPushedAuthorizationRequest, IdentityError>;

    fn revoke_token(
        &self,
        realm_id: &RealmId,
        request: &TokenRevocationRequest,
    ) -> Result<(), IdentityError>;

    /// Introspects a token (RFC 7662).
    ///
    /// Returns `active: true` with metadata if the token is valid, or
    /// `active: false` for expired, revoked, or invalid tokens.
    fn introspect_token(
        &self,
        realm_id: &RealmId,
        request: &TokenIntrospectionRequest,
    ) -> Result<IntrospectionResponse, IdentityError>;

    /// Evaluates whether the bearer token holder has a specific permission
    /// (`POST /oauth/authorize` — decision endpoint, HEA-922).
    ///
    /// Validates the token (signature, expiry, session, revocation), resolves
    /// the subject's live RBAC permissions, and returns `allowed: true` only
    /// when the resolved set contains the requested permission.  Fail-closed:
    /// any validation or resolution error returns `allowed: false`.
    fn decide_token_permission(
        &self,
        realm_id: &RealmId,
        request: &oidc::DecidePermissionRequest,
    ) -> Result<oidc::DecidePermissionResponse, IdentityError>;

    // ===== MFA / TOTP (Step 23) =====

    /// Begins TOTP enrollment for a user.
    ///
    /// Generates a secret, provisioning URI, and 8 recovery codes.
    /// The MFA state is stored in a disabled state until verified via
    /// `verify_totp_enrollment()`.
    fn enroll_totp(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<TotpEnrollment, IdentityError>;

    /// Verifies the initial TOTP setup code and enables MFA.
    ///
    /// The user must have a pending enrollment (from `enroll_totp()`).
    /// After success, MFA is active and `verify_totp()` must be used
    /// for subsequent authentication.
    fn verify_totp_enrollment(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError>;

    /// Verifies a TOTP code for an authenticated user.
    ///
    /// Enforces rate limiting (5 attempts / 5 min lockout) and
    /// replay protection (rejects codes for already-used time steps).
    fn verify_totp(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError>;

    /// Verifies a single-use recovery code.
    ///
    /// On success, the code is consumed and cannot be reused.
    fn verify_recovery_code(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError>;

    /// Disables MFA for a user, removing all TOTP state.
    fn disable_mfa(&self, realm_id: &RealmId, user_id: &UserId) -> Result<(), IdentityError>;

    /// Returns whether MFA is currently enabled for a user.
    fn mfa_enabled(&self, realm_id: &RealmId, user_id: &UserId) -> Result<bool, IdentityError>;

    /// Records a burned MFA pending cookie nonce in WAL storage.
    ///
    /// `exp_secs` is the Unix-second timestamp at which the nonce entry may be
    /// considered stale (it equals the cookie issue time plus
    /// `MFA_PENDING_TTL_SECS`). Must be called after a successful MFA
    /// verification, before creating the session — prevents replay of a
    /// captured pending cookie across server restarts.
    fn burn_mfa_nonce(
        &self,
        realm_id: &RealmId,
        nonce: &str,
        exp_secs: u64,
    ) -> Result<(), IdentityError>;

    /// Returns `true` if the nonce has already been burned (replay detected).
    ///
    /// Reads directly from WAL storage so the check survives server restarts.
    fn is_mfa_nonce_burned(&self, realm_id: &RealmId, nonce: &str) -> Result<bool, IdentityError>;

    /// Atomically redeems an MFA pending-cookie nonce.
    ///
    /// Holds a per-nonce redemption lock across the burned-check and burn write
    /// so two concurrent redemptions of the same nonce cannot both succeed
    /// (TOCTOU — HEA-1752 M1a). Returns `Ok(true)` when this call burned the
    /// nonce for the first time and the caller may proceed to create a session,
    /// or `Ok(false)` when it was already burned (replayed or concurrent).
    /// `exp_secs` matches the semantics of [`burn_mfa_nonce`](Self::burn_mfa_nonce).
    fn redeem_mfa_nonce(
        &self,
        realm_id: &RealmId,
        nonce: &str,
        exp_secs: u64,
    ) -> Result<bool, IdentityError>;

    /// Generates a new set of recovery codes, replacing any existing ones.
    ///
    /// Requires MFA to be already enabled. Returns the new plaintext codes
    /// (shown once; hashes are stored immediately).
    fn regenerate_recovery_codes(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<String>, IdentityError>;

    /// Returns the plaintext pending recovery codes if the user has a pending
    /// enrollment (codes not yet confirmed/hashed). Returns `None` if MFA is
    /// already enabled or there is no pending enrollment.
    fn load_pending_recovery_codes(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<Vec<String>>, IdentityError>;

    /// Returns the base32-encoded pending TOTP secret if the user has a pending
    /// enrollment that is not yet confirmed. Returns `None` if MFA is already
    /// enabled or there is no pending enrollment. Used to re-populate the QR
    /// code and secret on failed activation attempts.
    fn load_pending_totp_secret(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<String>, IdentityError>;

    // ===== WebAuthn / Passkeys (Step 24) =====

    /// Starts a `WebAuthn` registration ceremony.
    ///
    /// Generates a challenge and returns it along with the challenge key
    /// for use in `complete_webauthn_registration()`.
    fn start_webauthn_registration(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        options: &RegistrationOptions,
    ) -> Result<Vec<u8>, IdentityError>;

    /// Completes a `WebAuthn` registration ceremony.
    ///
    /// Validates the attestation response, extracts the credential, and
    /// stores it. Returns the credential info.
    fn complete_webauthn_registration(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_data_json: &[u8],
        attestation_object: &[u8],
        origin: &str,
        discoverable: bool,
    ) -> Result<WebAuthnCredentialInfo, IdentityError>;

    /// Starts a `WebAuthn` authentication ceremony.
    ///
    /// Generates a challenge. If `user_id` is `None`, this is a
    /// discoverable credential (username-less) flow.
    fn start_webauthn_authentication(
        &self,
        realm_id: &RealmId,
        user_id: Option<&UserId>,
        options: &AuthenticationOptions,
    ) -> Result<Vec<u8>, IdentityError>;

    /// Completes a `WebAuthn` authentication ceremony.
    ///
    /// Validates the assertion, verifies the signature, updates the
    /// sign counter, and returns the authentication result.
    fn complete_webauthn_authentication(
        &self,
        realm_id: &RealmId,
        params: &CompleteAuthenticationParams<'_>,
    ) -> Result<WebAuthnAuthResult, IdentityError>;

    /// Lists all `WebAuthn` credentials for a user.
    fn list_webauthn_credentials(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<WebAuthnCredentialInfo>, IdentityError>;

    /// Revokes (deletes) a `WebAuthn` credential.
    fn revoke_webauthn_credential(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        credential_id: &[u8],
    ) -> Result<(), IdentityError>;

    /// Sets a user-supplied display name on an existing `WebAuthn` credential.
    ///
    /// The name is cosmetic only (e.g., "MacBook Touch ID") and does not affect
    /// the cryptographic ceremony. Returns `WebAuthnCredentialNotFound` if the
    /// credential does not exist or belongs to a different user.
    fn rename_webauthn_credential(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        credential_id: &[u8],
        name: &str,
    ) -> Result<(), IdentityError>;

    // ===== Magic Link / Passwordless (Step 25) =====

    /// Requests a magic link token for the given email address.
    ///
    /// Generates a random 32-byte token, stores its SHA-256 hash, and
    /// returns the plaintext token exactly once. The consuming application
    /// is responsible for delivering the token to the user (e.g., via email).
    ///
    /// For enumeration resistance, this method always succeeds regardless
    /// of whether the email is registered. If the email is unknown, the
    /// link is still created — account creation happens at validation time.
    fn request_magic_link(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<MagicLinkResponse, IdentityError>;

    /// Validates a magic link token and returns the associated user.
    ///
    /// On success, marks the token as used (single-use enforcement).
    /// If the email was not registered at request time, a new user account
    /// is created automatically.
    ///
    /// Returns `Err(MagicLinkTokenInvalid)` if the token is not found,
    /// expired, or already used. The error is intentionally vague for
    /// enumeration resistance.
    fn validate_magic_link(&self, realm_id: &RealmId, token: &str)
        -> Result<UserId, IdentityError>;

    // ===== Self-service registration =====

    /// Registers a new user via the public signup flow.
    ///
    /// Enforces the realm's [`RegistrationPolicy`], applies per-email
    /// (3/hr) and per-IP (10/hr) rate limits, creates the user in
    /// [`UserStatus::PendingVerification`], sets their password, and
    /// issues an email-verification token. The plaintext token is
    /// returned exactly once so the caller can email it to the user.
    ///
    /// For enumeration resistance, a request targeting an already-registered
    /// email returns `Ok` with an unusable token rather than an error.
    fn register_user(
        &self,
        realm_id: &RealmId,
        request: &RegisterUserRequest,
    ) -> Result<RegisterUserResponse, IdentityError>;

    // ===== Password reset =====

    /// Requests a password reset token for the given email address.
    ///
    /// If the email belongs to an existing user, generates a random token,
    /// stores its SHA-256 hash under `rst:token:{hash}`, and returns
    /// `Some(plaintext_token)`. If the email is unknown, returns `None`.
    ///
    /// Unlike magic links, password reset tokens MUST NOT auto-create
    /// accounts for unknown emails.
    ///
    /// Rate-limited per email address (reuses magic link rate tracker).
    fn request_password_reset(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<Option<String>, IdentityError>;

    /// Resets a user's password using a password reset token.
    ///
    /// Validates the token (exists, not expired, not used), marks it as
    /// used, sets the new password via `set_password()`, and returns the
    /// user ID.
    ///
    /// Returns `Err(PasswordResetTokenInvalid)` if the token is not found,
    /// expired, or already used. Intentionally vague for enumeration
    /// resistance.
    fn reset_password_with_token(
        &self,
        realm_id: &RealmId,
        token: &str,
        new_password: &CleartextPassword,
    ) -> Result<UserId, IdentityError>;

    // ===== Email verification (onboarding) =====

    /// Issues an email-verification token bound to the given user.
    ///
    /// Generates 32 random bytes (base64url), stores the SHA-256 hash
    /// with a 24-hour expiry, and returns the plaintext token once for
    /// inclusion in a verification URL. The plaintext is never persisted.
    fn issue_email_verification_token(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<String, IdentityError>;

    /// Consumes an email-verification token and activates the user.
    ///
    /// Looks up the token by SHA-256 hash, validates expiry and single-use
    /// semantics, then transitions the user from `PendingVerification` to
    /// `Active`. Deletes the token entry on success.
    ///
    /// Returns `Err(VerificationTokenInvalid)` if the token is not found,
    /// expired, or already used. Intentionally vague for enumeration
    /// resistance.
    fn verify_email_token(&self, realm_id: &RealmId, token: &str) -> Result<UserId, IdentityError>;

    // ===== A-19: Email-change re-verification flow =====

    /// Begins an email-address change for `user_id` (A-19).
    ///
    /// Validates `new_email`, checks uniqueness (and the A-20 reservation),
    /// generates a 32-byte random verification token, stores SHA-256(token)
    /// in `email:change:{hash}`, emits `EmailChangeInitiated` audit.
    ///
    /// Returns the plaintext token. The caller is responsible for delivering
    /// it to `new_email` (e.g. via `WebState::email`). The old address is
    /// unchanged until `confirm_email_change` is called.
    fn initiate_email_change(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        new_email: &str,
    ) -> Result<String, IdentityError>;

    /// Completes an email-address change (A-19).
    ///
    /// Validates the token (expiry, single-use), swaps the email indexes,
    /// updates the user record, revokes all sessions, emits
    /// `EmailChangeConfirmed` audit.
    ///
    /// Returns `Err(EmailChangeTokenInvalid)` for any token failure.
    /// The caller MUST send a `security.email_changed` notification to the
    /// returned old address (available from the updated `User` record before
    /// this call or from the engine's old-email field in the stored token).
    fn confirm_email_change(&self, realm_id: &RealmId, token: &str) -> Result<User, IdentityError>;

    /// Checks and records a `prompt=none` probe for the given (realm, sub)
    /// pair (A-37).
    ///
    /// Increments a sliding-window counter stored under
    /// `rl:prompt_none:{user_uuid}`. Returns `Ok(())` while under the cap,
    /// `Err(SilentAuthRateLimited)` when the hourly limit is exceeded.
    /// Emits `OidcSilentAuthProbed` audit on every call (fail-open).
    fn check_silent_auth_probe(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &str,
        outcome: &str,
    ) -> Result<(), IdentityError>;

    // ===== UserInfo (OIDC Core §5.3) =====

    /// Returns user claims for the `UserInfo` endpoint.
    ///
    /// Validates the access token, looks up the user, and returns claims
    /// filtered by the token's granted scopes. Per OIDC Core §5.3, the
    /// `sub` claim is always included; other claims depend on scope:
    /// - `profile`: `name`
    /// - `email`: `email`, `email_verified`
    fn userinfo(
        &self,
        realm_id: &RealmId,
        access_token: &str,
    ) -> Result<UserInfoResponse, IdentityError>;

    // ===== Admin API (Step 27) =====

    /// Lists users with offset-based pagination.
    ///
    /// Returns a window of users plus the capped total count.
    fn list_users(
        &self,
        realm_id: &RealmId,
        page: &PageRequest,
    ) -> Result<PagedResult<User>, IdentityError>;

    /// Searches and/or sorts users.
    ///
    /// When `query` is non-trivial (≥ 2 characters or glob/exact syntax),
    /// filters results using the [`SearchQuery`] grammar over email +
    /// display name.  When `sort_field` is `Some`, the full matching set is
    /// sorted before the offset slice so page navigation is stable.
    ///
    /// When both `query` is trivial (`MatchAll`) **and** `sort_field` is
    /// `None`, callers should prefer [`Self::list_users`] for its fast
    /// key-order scan path.
    fn search_users(
        &self,
        realm_id: &RealmId,
        query: &str,
        page: &PageRequest,
        sort_field: Option<crate::identity::search::UserSortField>,
        sort_dir: crate::identity::search::SortDir,
    ) -> Result<PagedResult<User>, IdentityError>;

    /// Lists realms with offset-based pagination.
    ///
    /// Realms are stored under the system realm namespace, so no
    /// `realm_id` parameter is needed for scoping.
    fn list_realms(&self, page: &PageRequest) -> Result<PagedResult<Realm>, IdentityError>;

    /// Searches and/or sorts the realm list.
    ///
    /// Filters realms by name using the [`crate::identity::search::SearchQuery`]
    /// grammar. When `sort_field` is `Some`, the full matching set is sorted
    /// before the offset slice. Prefer [`Self::list_realms`] when both query is
    /// trivial and `sort_field` is `None`.
    fn search_realms(
        &self,
        query: &str,
        page: &PageRequest,
        sort_field: Option<crate::identity::search::RealmSortField>,
        sort_dir: crate::identity::search::SortDir,
    ) -> Result<PagedResult<Realm>, IdentityError>;

    /// Lists OAuth clients with offset-based pagination.
    fn list_clients(
        &self,
        realm_id: &RealmId,
        page: &PageRequest,
    ) -> Result<PagedResult<OAuthClient>, IdentityError>;

    /// Retrieves a single OAuth client by ID.
    fn get_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<Option<OAuthClient>, IdentityError>;

    /// Authenticates a caller for protected OAuth endpoints (revocation,
    /// introspection).
    ///
    /// `client_id` must identify an existing client in the realm.
    /// Confidential clients (those with a stored secret hash) additionally
    /// require a matching `client_secret`. Public clients (no stored secret)
    /// are accepted with `client_id` alone.
    ///
    /// Returns `Err(IdentityError::InvalidClientSecret)` for all authentication
    /// failures (unknown client, wrong or missing secret). Using a single error
    /// variant prevents client enumeration by timing or error differentiation.
    fn authenticate_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        client_secret: Option<&str>,
    ) -> Result<(), IdentityError>;

    /// Updates an existing OAuth client's fields.
    ///
    /// Only non-`None` fields in the request are applied.
    fn update_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        request: &UpdateClientRequest,
    ) -> Result<OAuthClient, IdentityError>;

    /// Regenerates the client secret for a confidential OAuth client.
    ///
    /// Generates a new random secret, hashes it with Argon2id, updates the
    /// stored client, and returns the plaintext secret exactly once. The
    /// old secret is permanently invalidated.
    ///
    /// Returns `Err(ClientNotFound)` if the client does not exist.
    /// Returns `Err(InvalidInput)` if the client is a public client (no secret).
    fn regenerate_client_secret(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<String, IdentityError>;

    /// Deletes an OAuth client by ID.
    fn delete_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<(), IdentityError>;

    /// Creates multiple users in a single batch operation.
    ///
    /// Each item is processed independently — individual failures do not
    /// abort the batch. Returns a `BulkResult` for each input item.
    fn bulk_create_users(
        &self,
        realm_id: &RealmId,
        requests: &[CreateUserRequest],
    ) -> Result<Vec<BulkResult<User>>, IdentityError>;

    /// Disables multiple users in a single batch operation.
    ///
    /// Each item is processed independently — individual failures do not
    /// abort the batch. Returns a `BulkResult` for each input item.
    fn bulk_disable_users(
        &self,
        realm_id: &RealmId,
        user_ids: &[UserId],
    ) -> Result<Vec<BulkResult<()>>, IdentityError>;

    // ===== Organizations =====

    /// Creates a new organization within a realm.
    ///
    /// Validates the slug, checks uniqueness, and persists the org record
    /// with primary and slug index entries.
    fn create_organization(
        &self,
        realm_id: &RealmId,
        request: &CreateOrganizationRequest,
    ) -> Result<Organization, IdentityError>;

    /// Retrieves an organization by ID. Returns `None` if not found.
    fn get_organization(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<Option<Organization>, IdentityError>;

    /// Retrieves an organization by slug. Returns `None` if not found.
    fn get_organization_by_slug(
        &self,
        realm_id: &RealmId,
        slug: &str,
    ) -> Result<Option<Organization>, IdentityError>;

    /// Updates an existing organization's fields.
    ///
    /// Only non-`None` fields in the request are applied.
    fn update_organization(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        request: &UpdateOrganizationRequest,
    ) -> Result<Organization, IdentityError>;

    /// Deletes an organization and all associated data.
    ///
    /// Cascading deletion removes all memberships (forward + reverse indexes),
    /// invitations (primary + token + email dedup + list indexes), RBAC
    /// role assignments, slug index, and the org record. Idempotent.
    fn delete_organization(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<(), IdentityError>;

    /// Lists all organizations in a realm with offset-based pagination.
    fn list_organizations(
        &self,
        realm_id: &RealmId,
        page: &PageRequest,
    ) -> Result<PagedResult<Organization>, IdentityError>;

    /// Adds a user as a member of an organization.
    ///
    /// Creates bidirectional membership indexes (org→user and user→org).
    /// If an authorization engine is configured, writes the corresponding
    /// RBAC role assignments atomically.
    fn add_member(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
        role: OrganizationRole,
    ) -> Result<OrganizationMembership, IdentityError>;

    /// Removes a user from an organization.
    ///
    /// Enforces last-owner protection: if the user is the sole Owner,
    /// returns `Err(LastOwner)`. Deletes both membership indexes and
    /// any RBAC role assignments.
    fn remove_member(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<(), IdentityError>;

    /// Updates a member's role within an organization.
    ///
    /// Enforces last-owner protection when downgrading from Owner.
    /// Updates both membership indexes and RBAC role assignments atomically.
    fn update_member_role(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
        new_role: OrganizationRole,
    ) -> Result<OrganizationMembership, IdentityError>;

    /// Retrieves a specific membership. Returns `None` if not a member.
    fn get_membership(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<Option<OrganizationMembership>, IdentityError>;

    /// Lists all members of an organization with cursor-based pagination.
    fn list_members(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationMembership>, IdentityError>;

    /// Lists all organizations a user belongs to with cursor-based pagination.
    fn list_user_organizations(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationMembership>, IdentityError>;

    /// Creates an invitation to join an organization.
    ///
    /// Generates a 32-byte random token, stores the SHA-256 hash, and
    /// returns the invitation record plus the plaintext token (for email
    /// delivery). The plaintext token is never stored.
    fn create_invitation(
        &self,
        realm_id: &RealmId,
        request: &CreateInvitationRequest,
    ) -> Result<(OrganizationInvitation, String), IdentityError>;

    /// Accepts an invitation using the plaintext token.
    ///
    /// Hashes the token, looks up the invitation, validates status and
    /// expiry, creates the membership, marks the invitation as accepted,
    /// and returns the new membership.
    fn accept_invitation(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<OrganizationMembership, IdentityError>;

    /// Revokes a pending invitation.
    fn revoke_invitation(
        &self,
        realm_id: &RealmId,
        invitation_id: &InvitationId,
    ) -> Result<(), IdentityError>;

    /// Lists invitations for an organization with cursor-based pagination.
    fn list_invitations(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationInvitation>, IdentityError>;

    // ===== OAuth Consent =====

    /// Returns the user's consent record for a specific OAuth client, if any.
    fn get_consent(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &crate::core::ClientId,
    ) -> Result<Option<ConsentRecord>, IdentityError>;

    /// Lists every consent the given user has granted in this realm.
    ///
    /// Each entry is joined with the current client name and logo URL for
    /// UI rendering. Clients that no longer exist (orphaned consents) are
    /// filtered out — callers see only live consents.
    fn list_consents_by_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<ConsentListEntry>, IdentityError>;

    /// Upserts a consent record, merging `approved_scopes` into any
    /// pre-existing granted scopes. Returns the resulting canonical record.
    fn grant_consent(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &crate::core::ClientId,
        approved_scopes: &[String],
    ) -> Result<ConsentRecord, IdentityError>;

    /// Revokes the user's consent for a specific client. Returns
    /// `ConsentNotFound` if no record existed. Idempotent from the
    /// caller's perspective — the HTTP layer translates to 404.
    fn revoke_consent(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &crate::core::ClientId,
    ) -> Result<(), IdentityError>;

    /// Revokes every consent granted by the user in this realm. Returns
    /// the number of records deleted.
    fn revoke_all_consents_for_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<usize, IdentityError>;

    /// Stores an in-flight pending authorization request awaiting consent.
    ///
    /// The ticket is an opaque, single-use identifier. The engine generates
    /// it and persists the request under `oauth:pending_auth:{ticket}` with
    /// a short TTL (typically 10 minutes). Returns the ticket.
    fn put_pending_authorization(
        &self,
        realm_id: &RealmId,
        request: &PendingAuthorizationRequest,
    ) -> Result<String, IdentityError>;

    /// Retrieves and deletes the pending authorization request for `ticket`.
    ///
    /// Single-use: the record is deleted whether or not the caller
    /// succeeds in using it. Returns `ConsentTicketNotFound` if the ticket
    /// doesn't exist or was already consumed; `ConsentTicketExpired` if
    /// past `expires_at`.
    fn take_pending_authorization(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<PendingAuthorizationRequest, IdentityError>;

    /// Non-destructive read of a pending authorization ticket. Used by
    /// the consent page to render client name + scope list without
    /// consuming the ticket. Returns `Ok(None)` when the ticket does not
    /// exist or has been consumed. Returns `Err(ConsentTicketExpired)`
    /// when the ticket exists but is past its `expires_at` — in that
    /// case the caller should treat it as invalid (the POST path will
    /// delete the stale record on next take).
    fn get_pending_authorization(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<Option<PendingAuthorizationRequest>, IdentityError>;

    /// Signs a JARM error response JWT for mandatory-JARM clients (JARM §4.3).
    ///
    /// Called from the authorization endpoint when an error must be returned to
    /// a client whose `authorization_signed_response_alg` is set. The resulting
    /// JWT carries `error` + `error_description` + `state` so the client can
    /// verify the error with the same signature check it applies to success
    /// responses. The `typ` header is `oauth-authz-resp+jwt`.
    fn sign_jarm_error_jwt(
        &self,
        realm_id: &RealmId,
        client_id: &str,
        error: &str,
        error_description: &str,
        state_param: &str,
    ) -> Result<String, IdentityError>;

    /// Issues an authorization code for a previously-approved authorization
    /// request. Unlike [`IdentityEngine::authorize`], this variant skips
    /// the consent gating and is called only after consent has been
    /// recorded (or explicitly bypassed for a trusted client). Returns
    /// the authorization code response.
    /// `jar_request`: when `Some`, the signed request object (RFC 9101) is
    /// verified against the client's JWKS and its claims override the other
    /// parameters. Pass `None` for non-JAR flows.
    #[allow(clippy::too_many_arguments)]
    fn issue_authorization_code(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &crate::core::ClientId,
        redirect_uri: &str,
        scope: &str,
        state: &str,
        code_challenge: Option<String>,
        code_challenge_method: Option<CodeChallengeMethod>,
        nonce: Option<String>,
        amr_values: Vec<String>,
        response_mode: Option<ResponseMode>,
        jar_request: Option<String>,
        via_par: bool,
    ) -> Result<AuthorizationResponse, IdentityError>;

    // ===== External IdP federation (Phase 2: Gap #5) =====

    /// Persists (or updates) an external IdP connector for a realm.
    fn register_idp(&self, config: &federation::IdpConfig) -> Result<(), IdentityError>;

    /// Retrieves a connector by id.
    fn get_idp(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
    ) -> Result<Option<federation::IdpConfig>, IdentityError>;

    /// Retrieves a connector by operator-assigned name (e.g., `"google"`).
    fn get_idp_by_name(
        &self,
        realm_id: &RealmId,
        name: &str,
    ) -> Result<Option<federation::IdpConfig>, IdentityError>;

    /// Lists all connectors registered in a realm.
    fn list_idps(&self, realm_id: &RealmId) -> Result<Vec<federation::IdpConfig>, IdentityError>;

    /// Deletes a connector and all its external-identity links.
    fn delete_idp(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
    ) -> Result<(), IdentityError>;

    /// Persists a state bag under its `state_token` for a federation
    /// login round trip. 10-minute TTL enforced by `take_federation_state`.
    fn put_federation_state(&self, bag: &federation::StateBag) -> Result<(), IdentityError>;

    /// Retrieves and deletes a state bag (single-use). Returns
    /// `FederationInvalidState` on miss or expiry.
    fn take_federation_state(
        &self,
        realm_id: &RealmId,
        state_token: &str,
    ) -> Result<federation::StateBag, IdentityError>;

    /// Persists a pending confirm-to-link ticket.
    fn put_confirm_link_ticket(
        &self,
        ticket: &federation::ConfirmLinkTicket,
    ) -> Result<(), IdentityError>;

    /// Retrieves and deletes a confirm-to-link ticket (single-use).
    fn take_confirm_link_ticket(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<federation::ConfirmLinkTicket, IdentityError>;

    /// Attaches an external identity to a Hearth user. Idempotent on
    /// `(user, idp)` — re-linking the same tuple replaces the external
    /// sub. Returns `FederationAlreadyLinked` if the external identity
    /// is currently owned by a *different* user in the realm.
    fn link_external_identity(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        idp_id: &crate::core::IdpId,
        external_sub: &str,
    ) -> Result<(), IdentityError>;

    /// Severs a user's link to a specific connector. `FederationNotLinked`
    /// when no such link exists.
    fn unlink_external_identity(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        idp_id: &crate::core::IdpId,
    ) -> Result<(), IdentityError>;

    /// Resolves an external identity to its Hearth `UserId`. `None` when
    /// no Hearth user has linked this upstream subject in this realm.
    fn find_user_by_external_identity(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
        external_sub: &str,
    ) -> Result<Option<UserId>, IdentityError>;

    /// Enumerates a user's linked external identities for the
    /// `/ui/account/linked-accounts` page. Returns `(idp_id, external_sub)`
    /// pairs.
    fn list_external_identities_for_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<(crate::core::IdpId, String)>, IdentityError>;

    // ===== SAML 2.0 =====

    /// Returns (or lazily creates) this realm's RSA signing key used for
    /// SAML metadata and `<Response>`/`<Assertion>` signing.
    ///
    /// Off the hot path: RSA keygen is slow and happens once per realm.
    fn get_or_create_saml_signing_key(
        &self,
        realm_id: &RealmId,
        issuer_cn: &str,
    ) -> Result<std::sync::Arc<crate::identity::tokens::RsaSigningKey>, IdentityError>;

    /// Registers (or updates) a SAML Service Provider in a realm.
    fn register_saml_sp(
        &self,
        realm_id: &RealmId,
        sp: &federation::saml::SamlServiceProvider,
    ) -> Result<(), IdentityError>;

    /// Resolves a registered SP by its entity ID.
    fn get_saml_sp_by_entity_id(
        &self,
        realm_id: &RealmId,
        entity_id: &str,
    ) -> Result<Option<federation::saml::SamlServiceProvider>, IdentityError>;

    /// Resolves a registered SP by operator-assigned key.
    fn get_saml_sp_by_key(
        &self,
        realm_id: &RealmId,
        sp_key: &str,
    ) -> Result<Option<federation::saml::SamlServiceProvider>, IdentityError>;

    /// Lists all registered SPs in a realm.
    fn list_saml_sps(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<federation::saml::SamlServiceProvider>, IdentityError>;

    /// Deletes a registered SP.
    fn delete_saml_sp(&self, realm_id: &RealmId, sp_key: &str) -> Result<(), IdentityError>;

    /// Persists a SAML state bag (SP-initiated login; 10-minute TTL).
    fn put_saml_state(&self, bag: &federation::saml::SamlStateBag) -> Result<(), IdentityError>;

    /// Retrieves and deletes a SAML state bag (single-use).
    fn take_saml_state(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<federation::saml::SamlStateBag, IdentityError>;

    /// Marks an assertion ID consumed for this IdP (replay guard).
    /// Returns `SamlReplay` if the ID has already been seen.
    fn mark_saml_assertion_consumed(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
        assertion_id: &str,
    ) -> Result<(), IdentityError>;

    /// Records that the IdP issued an assertion to an SP for a user session.
    /// Enables SLO fan-out at logout time.
    fn record_saml_sp_session(
        &self,
        realm_id: &RealmId,
        registration: &federation::saml::SamlSessionRegistration,
    ) -> Result<(), IdentityError>;

    /// Enumerates an IdP-issued session's SP registrations for SLO.
    fn list_saml_sp_sessions(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Vec<federation::saml::SamlSessionRegistration>, IdentityError>;

    // ===== Migration / import (Phase 1 Step 30) =====

    /// Imports a realm, optionally with a caller-supplied `RealmId`.
    ///
    /// Unlike `create_realm`, this allows preserving an external system's
    /// realm/organization UUID. Returns `DuplicateRealmName` or a
    /// realm-id-conflict error if one already exists with the same id.
    ///
    /// When `signing_key_pkcs8` is `Some`, the bytes are installed as the
    /// realm's signing key instead of generating a fresh one. The realm
    /// record and signing key are written atomically in a single batch,
    /// preserving the invariant that a realm always has a usable key. This
    /// is the disaster-recovery restore path: any token issued under the
    /// original key must still validate after restore. Pass `None` for
    /// new realms imported from external providers (Keycloak, Auth0,
    /// migrations) where token continuity is not a requirement.
    fn import_realm(
        &self,
        request: &CreateRealmRequest,
        requested_id: Option<RealmId>,
        signing_key_pkcs8: Option<&[u8]>,
    ) -> Result<Realm, IdentityError>;

    /// Imports a user with a pre-hashed credential from an external system.
    ///
    /// Preserves the source-system hash verbatim so users can authenticate
    /// with their existing passwords. New hashes produced by Hearth
    /// (via `change_password`) are always Argon2id; successful verification
    /// against the imported hash auto-upgrades it in place on first login.
    fn import_user(
        &self,
        realm_id: &RealmId,
        request: &ImportUserRequest,
    ) -> Result<User, IdentityError>;

    /// Imports an OAuth 2.0 client from an external system.
    ///
    /// Preserves the source-system client identifier if provided. The
    /// supplied `client_secret` (if any) is hashed with Argon2id at
    /// import time — the source system's hashed secret is not reusable
    /// because Hearth's storage format requires Argon2id.
    fn import_client(
        &self,
        realm_id: &RealmId,
        request: &ImportClientRequest,
    ) -> Result<OAuthClient, IdentityError>;

    /// Bulk-seeds synthetic demo users for the large-scale demo seeder.
    ///
    /// Generates `spec.target_count` accounts named `user0000001@<domain>`, …,
    /// all pre-activated and all sharing `password`. The password is hashed
    /// **once** and the resulting hash is reused for every account, so there is
    /// no per-user Argon2id cost. Writes are batched per chunk to minimize WAL
    /// fsync amplification.
    ///
    /// Idempotent and resumable: a per-realm sentinel records how many users
    /// have been seeded, so re-running creates only the delta above that count
    /// and never modifies existing accounts. Raising `target_count` between
    /// runs seeds the additional users.
    ///
    /// This is a demo-only fast path — it skips per-user email-uniqueness
    /// checks (generated emails are unique by construction) and records a single
    /// summary audit event rather than one per user. It refuses to run against
    /// the system realm. Callers must gate invocation on the operator having
    /// explicitly enabled demo mode (`demo.enabled = true`).
    fn seed_demo_users(
        &self,
        realm_id: &RealmId,
        password: &CleartextPassword,
        spec: &DemoSeedSpec,
    ) -> Result<DemoSeedOutcome, IdentityError>;

    // ===== SCIM externalId management =====

    /// Sets the SCIM `externalId` for a user. Replaces any prior value.
    ///
    /// Returns `DuplicateScimExternalId` when the `external_id` is already
    /// associated with a different user in this realm.
    fn set_scim_external_id(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        external_id: &str,
    ) -> Result<(), IdentityError>;

    /// Clears the SCIM `externalId` for a user, if one was set.
    /// Idempotent — no error when none is present.
    fn clear_scim_external_id(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<(), IdentityError>;

    /// Returns the SCIM `externalId` associated with the user, if any.
    fn get_scim_external_id(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<String>, IdentityError>;

    /// Resolves a SCIM `externalId` to the Hearth user that owns it.
    fn find_user_by_scim_external_id(
        &self,
        realm_id: &RealmId,
        external_id: &str,
    ) -> Result<Option<User>, IdentityError>;

    /// Sets the SCIM `externalId` for an organization (group).
    fn set_scim_group_external_id(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        external_id: &str,
    ) -> Result<(), IdentityError>;

    /// Clears the SCIM `externalId` for an organization. Idempotent.
    fn clear_scim_group_external_id(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<(), IdentityError>;

    /// Returns the SCIM `externalId` associated with the organization, if any.
    fn get_scim_group_external_id(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<Option<String>, IdentityError>;

    /// Resolves a SCIM `externalId` to the Hearth organization that owns it.
    fn find_group_by_scim_external_id(
        &self,
        realm_id: &RealmId,
        external_id: &str,
    ) -> Result<Option<Organization>, IdentityError>;

    // =========================================================================
    // Webhooks
    // =========================================================================

    /// Registers a new webhook endpoint for the given realm.
    fn create_webhook(
        &self,
        realm_id: &RealmId,
        req: &CreateWebhookRequest,
    ) -> Result<Webhook, IdentityError>;

    /// Returns a single webhook by ID, or `None` if not found.
    fn get_webhook(
        &self,
        realm_id: &RealmId,
        webhook_id: &WebhookId,
    ) -> Result<Option<Webhook>, IdentityError>;

    /// Lists webhooks registered in a realm, sorted by insertion order.
    fn list_webhooks(
        &self,
        realm_id: &RealmId,
        page: &PageRequest,
    ) -> Result<PagedResult<Webhook>, IdentityError>;

    /// Updates an existing webhook's configuration.
    ///
    /// Returns `WebhookNotFound` when no webhook with that ID exists in the realm.
    fn update_webhook(
        &self,
        realm_id: &RealmId,
        webhook_id: &WebhookId,
        req: &UpdateWebhookRequest,
    ) -> Result<Webhook, IdentityError>;

    /// Deletes a webhook from the realm.
    fn delete_webhook(
        &self,
        realm_id: &RealmId,
        webhook_id: &WebhookId,
    ) -> Result<(), IdentityError>;

    // =========================================================================
    // Agents (AGENT_AUTH.md Phase A, HEA-1325)
    // =========================================================================

    /// Creates a new agent in the given realm.
    ///
    /// Validates `display_name` (1–256 chars), `max_delegation_depth` (1–10),
    /// and verifies that the owning user/organization exists in the realm.
    /// Persists the agent record and owner index atomically.
    fn create_agent(
        &self,
        realm_id: &RealmId,
        request: &types::CreateAgentRequest,
        caller: Option<&crate::core::UserId>,
    ) -> Result<types::Agent, IdentityError>;

    /// Retrieves an agent by ID. Returns `None` if not found.
    fn get_agent(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
    ) -> Result<Option<types::Agent>, IdentityError>;

    /// Updates mutable fields on an agent.
    ///
    /// Only non-`None` fields in the request are applied. Returns the
    /// updated agent. Validates `max_delegation_depth` (1–10) when supplied.
    fn update_agent(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        request: &types::UpdateAgentRequest,
        caller: Option<&crate::core::UserId>,
    ) -> Result<types::Agent, IdentityError>;

    /// Permanently deletes an agent and cascades: removes all credentials,
    /// RBAC role assignments, and the owner index entry. Emits `AgentDeleted` audit.
    fn delete_agent(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        caller: Option<&crate::core::UserId>,
    ) -> Result<(), IdentityError>;

    /// Lists agents in a realm with optional filtering and cursor-based pagination.
    ///
    /// Supports filtering by owner, status, and declared capability URI.
    fn list_agents(
        &self,
        realm_id: &RealmId,
        query: &types::ListAgentsQuery,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<types::Page<types::Agent>, IdentityError>;

    /// Transitions an agent from `Active` to `Suspended`.
    ///
    /// Returns `AgentRevoked` if the agent is already revoked (terminal).
    fn suspend_agent(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        caller: Option<&crate::core::UserId>,
    ) -> Result<types::Agent, IdentityError>;

    /// Transitions an agent from `Suspended` back to `Active`.
    ///
    /// Returns `AgentRevoked` if the agent is revoked (terminal).
    fn reactivate_agent(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        caller: Option<&crate::core::UserId>,
    ) -> Result<types::Agent, IdentityError>;

    /// Permanently revokes an agent (`Active | Suspended → Revoked`).
    ///
    /// Revocation is terminal — a revoked agent cannot be reactivated.
    /// Emits `AgentRevoked` audit event.
    fn revoke_agent(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        caller: Option<&crate::core::UserId>,
    ) -> Result<types::Agent, IdentityError>;

    // ── A.3 Agent credentials ────────────────────────────────────────────────

    /// Issues a new API-key credential for an agent.
    ///
    /// Generates 256 bits of entropy, returns the hex-encoded plaintext once
    /// (show-once contract), and stores only the SHA-256 hash.
    fn create_agent_api_key(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        request: &types::CreateAgentApiKeyRequest,
        caller: Option<&crate::core::UserId>,
    ) -> Result<types::CreateAgentApiKeyResponse, IdentityError>;

    /// Returns all credentials (active and revoked) for the given agent.
    fn list_agent_credentials(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
    ) -> Result<Vec<types::AgentCredential>, IdentityError>;

    /// Marks a credential as revoked. Revoked credentials cannot authenticate.
    ///
    /// Returns `AgentCredentialNotFound` if the credential does not exist or
    /// belongs to a different agent.
    fn revoke_agent_credential(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        cred_id: &crate::core::AgentCredentialId,
        caller: Option<&crate::core::UserId>,
    ) -> Result<(), IdentityError>;

    /// Verifies a plaintext API key against all active credentials for an agent.
    ///
    /// Returns `true` if any active credential's hash matches. Uses
    /// constant-time comparison to prevent timing attacks.
    fn verify_agent_api_key(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        plaintext_key_hex: &str,
    ) -> Result<bool, IdentityError>;

    /// Sweeps expired entities (authorization codes, device codes,
    /// pending authorization tickets, grant families) from storage.
    ///
    /// Called periodically by a background task. Returns deletion counts
    /// per entity type. Errors from individual sweeps are logged and
    /// counted; the function always returns stats (best-effort).
    fn sweep_expired(
        &self,
        realm_id: &RealmId,
    ) -> Result<crate::identity::cleanup::CleanupStats, IdentityError>;

    /// Proactively evicts expired device-fingerprint entries from `realm_id`.
    ///
    /// Scans all `dfp:user:*` keys and deletes any whose 8-byte LE i64 expiry
    /// (Unix seconds) is <= `now_secs`. Returns `(evicted, active)` counts.
    /// Called by the background dfp sweeper task on a configurable interval.
    fn sweep_expired_fingerprints(
        &self,
        realm_id: &RealmId,
        now_secs: i64,
    ) -> Result<(u64, u64), IdentityError>;

    /// Probes the underlying storage engine for basic liveness.
    ///
    /// Performs a minimal read (`get` on a probe key) and returns `true`
    /// when the storage layer responds without error. Used by the `/readyz`
    /// endpoint to gate inbound traffic until storage is confirmed healthy.
    ///
    /// The default implementation returns `true` (suitable for in-memory or
    /// mock engines used in tests).
    fn is_storage_healthy(&self) -> bool {
        true
    }

    // ===== Backup export helpers =====

    /// Returns all stored credentials in a realm for backup export.
    ///
    /// Each entry pairs a `UserId` with the PHC-formatted hash and its
    /// creation timestamp. Credentials are stored per-user, so this method
    /// performs a prefix scan across all `cred:user:*` keys.
    fn export_all_credentials(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<CredentialExport>, IdentityError>;

    /// Returns the raw PKCS#8 DER bytes for a realm's Ed25519 signing key.
    ///
    /// The caller is responsible for encrypting the bytes before writing
    /// them to an archive. Used exclusively by the backup exporter.
    fn export_realm_signing_key_pkcs8(&self, realm_id: &RealmId) -> Result<Vec<u8>, IdentityError>;

    // ===== Adaptive MFA — device fingerprint (HEA-839) =====

    /// Checks whether the device described by `(ip, user_agent)` is recognised
    /// for this user in this realm.
    ///
    /// If the realm's `adaptive_mfa.enabled` is `false`, or if the
    /// `fingerprint_hmac_secret` is empty, returns
    /// [`DeviceFingerprintOutcome::Skipped`] immediately.
    ///
    /// On an unrecognised device:
    /// - If the user has an enrolled MFA factor → [`DeviceFingerprintOutcome::StepUpRequired`].
    /// - If the user has **no** enrolled factor → [`DeviceFingerprintOutcome::EnrollMfaRequired`].
    ///
    /// The TTL of an existing recognised fingerprint is refreshed in-place on
    /// every call (AC-9 rolling window).
    ///
    /// An audit event (`StepUpMfaTriggered`) is emitted on every step-up.
    fn check_device_fingerprint(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        ip: &str,
        user_agent: &str,
    ) -> Result<device_fp::DeviceFingerprintOutcome, IdentityError>;

    /// Records `(ip, user_agent)` as a trusted device for this user, resetting
    /// the rolling window to `realm.config.adaptive_mfa.recognition_window_days`.
    ///
    /// Call this after a successful step-up MFA challenge to mark the device.
    /// No-ops when adaptive MFA is disabled or the HMAC secret is empty.
    fn record_device_fingerprint(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        ip: &str,
        user_agent: &str,
    ) -> Result<(), IdentityError>;

    // =========================================================================
    // SMS OTP (HEA-829)
    // =========================================================================

    /// Issues a 6-digit SMS OTP to `phone` and returns the opaque nonce.
    ///
    /// Checks the per-phone resend throttle (15-minute window, max 5 sends),
    /// generates a CSPRNG nonce and code via rejection sampling, stores
    /// HMAC-SHA256(key, digits) under `sms:pending_otp:{nonce}`, and sends
    /// the SMS. Returns `SmsResendLimitExceeded` on throttle breach.
    fn issue_sms_otp(
        &self,
        realm_id: &RealmId,
        phone: &str,
        otp_hmac_key_bytes: &[u8],
        sender: &dyn sms::SmsSender,
        now_unix_ts: u64,
    ) -> Result<String, IdentityError>;

    /// Verifies an SMS OTP previously issued by `issue_sms_otp`.
    ///
    /// Loads the pending record, checks expiry and attempt count, increments
    /// attempts, verifies HMAC in constant time via `ring::hmac::verify`.
    /// On success deletes the record (replay prevention). Returns
    /// `InvalidSmsOtp` for any failure (not-found, expired, wrong code,
    /// exhausted).
    fn verify_sms_otp(
        &self,
        realm_id: &RealmId,
        nonce: &str,
        candidate_code: &str,
        otp_hmac_key_bytes: &[u8],
        now_unix_ts: u64,
    ) -> Result<(), IdentityError>;

    // =========================================================================
    // Email OTP (HEA-1329)
    // =========================================================================

    /// Issues a 6-digit Email OTP to `email` and returns the opaque nonce.
    ///
    /// Generates a CSPRNG nonce and code via rejection sampling, stores
    /// HMAC-SHA256(key, digits) under `email:pending_otp:{nonce}`, and sends
    /// the OTP email via `email_service`.
    fn issue_email_otp(
        &self,
        realm_id: &RealmId,
        email: &str,
        otp_hmac_key_bytes: &[u8],
        email_service: &email::EmailService,
        realm_branding: Option<&email::EmailBranding>,
        now_unix_ts: u64,
    ) -> Result<String, IdentityError>;

    /// Verifies an Email OTP previously issued by `issue_email_otp`.
    ///
    /// Loads the pending record, checks expiry and attempt count, increments
    /// attempts, verifies HMAC in constant time via `ring::hmac::verify`.
    /// On success deletes the record (replay prevention). Returns
    /// `InvalidEmailOtp` for any failure (not-found, expired, wrong code,
    /// exhausted).
    fn verify_email_otp(
        &self,
        realm_id: &RealmId,
        nonce: &str,
        candidate_code: &str,
        otp_hmac_key_bytes: &[u8],
        now_unix_ts: u64,
    ) -> Result<(), IdentityError>;

    // ------- Session-version feed -------

    /// Returns delta entries with `seq > since` (up to `limit`).
    ///
    /// Returns `None` when `since` is older than the retention window;
    /// callers must fall back to [`Self::sv_snapshot`].
    fn sv_list_deltas(
        &self,
        realm_id: &RealmId,
        since: u64,
        limit: usize,
    ) -> Result<Option<SvDeltaResponse>, IdentityError>;

    /// Returns a point-in-time snapshot of `{session_id → min_sv}` for the realm.
    fn sv_snapshot(&self, realm_id: &RealmId) -> Result<SvSnapshotResponse, IdentityError>;

    /// Manually bumps the session version for a single session.
    ///
    /// Returns `IdentityError::SessionVersionDisabled` when the feature is
    /// off for the realm.
    fn sv_bump_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<u64, IdentityError>;

    /// Bumps all active sessions in the realm (admin operation).
    ///
    /// Returns `IdentityError::SessionVersionDisabled` when the feature is
    /// off for the realm.
    fn sv_bump_all(&self, realm_id: &RealmId) -> Result<usize, IdentityError>;

    // ===== DPoP storage operations (AGENT_AUTH.md §13.2) =====

    /// Checks a DPoP proof `jti` for replay and records it in persistent storage.
    ///
    /// Stores `jti` under `agt:dpop:jti:{jti}` in the realm's storage namespace
    /// with an 8-byte little-endian i64 expiry of `now_secs + DPOP_MAX_AGE_SECS`.
    /// Returns `Err(DPopProofReplay)` if the key already exists. The background
    /// cleanup sweeper evicts expired entries on each tick.
    ///
    /// Unlike the in-memory `DPopJtiCache`, this survives server restarts and
    /// is consistent across Raft nodes (both read from the same storage).
    fn check_and_record_dpop_jti(
        &self,
        realm_id: &RealmId,
        jti: &str,
        now_secs: i64,
    ) -> Result<(), IdentityError>;

    /// Returns the per-realm DPoP nonce HMAC secret, creating it if absent.
    ///
    /// On first call for a realm, generates a 32-byte CSPRNG secret, persists
    /// it under `agt:dpop:nonce-secret` in the realm's storage namespace, and
    /// caches it in memory. Subsequent calls return the cached value without
    /// touching storage. The stored value survives server restarts.
    ///
    /// The returned secret is used with `current_dpop_nonce` / `is_valid_dpop_nonce`
    /// to generate and validate per-realm DPoP nonces.
    fn get_realm_dpop_nonce_secret(&self, realm_id: &RealmId) -> Result<[u8; 32], IdentityError>;

    // ── B.1 Protected Resource Registration (AGENT_AUTH.md §2.5) ─────────────

    /// Registers a new protected resource (MCP server) within a realm.
    ///
    /// The `resource_uri` MUST be unique within the realm. In `--dev` mode HTTP
    /// is permitted; in production HTTPS is required.
    /// Emits `ProtectedResourceRegistered` audit event.
    fn register_protected_resource(
        &self,
        realm_id: &RealmId,
        request: &types::RegisterProtectedResourceRequest,
    ) -> Result<types::ProtectedResource, IdentityError>;

    /// Retrieves a protected resource by its ID.
    fn get_protected_resource(
        &self,
        realm_id: &RealmId,
        resource_id: &ResourceServerId,
    ) -> Result<Option<types::ProtectedResource>, IdentityError>;

    /// Lists all protected resources within a realm.
    fn list_protected_resources(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<types::ProtectedResource>, IdentityError>;

    /// Updates a protected resource.
    ///
    /// Only the fields present in `request` are updated.
    /// Emits `ProtectedResourceUpdated` audit event.
    fn update_protected_resource(
        &self,
        realm_id: &RealmId,
        resource_id: &ResourceServerId,
        request: &types::UpdateProtectedResourceRequest,
    ) -> Result<types::ProtectedResource, IdentityError>;

    /// Deletes a protected resource.
    ///
    /// All outstanding tokens scoped to this resource's `resource_uri` are NOT
    /// automatically revoked in this milestone; see AGENT_AUTH.md §2.5 for the
    /// future revocation requirement. Emits `ProtectedResourceDeleted` audit event.
    fn delete_protected_resource(
        &self,
        realm_id: &RealmId,
        resource_id: &ResourceServerId,
    ) -> Result<(), IdentityError>;

    // ── B.4 RFC 8693 Token Exchange ───────────────────────────────────────────

    /// Processes an RFC 8693 `urn:ietf:params:oauth:grant-type:token-exchange` request.
    ///
    /// Validates:
    /// 1. `subject_token` is a valid, non-expired access token for this realm.
    /// 2. `actor_token` (when present) is a signed JWT assertion from the agent,
    ///    with `sub` = agent identifier, `aud` = token endpoint, and a fresh `jti`
    ///    (replay prevention; stored for `≤5 min`).
    /// 3. The agent's `max_delegation_depth` is not exceeded.
    /// 4. Effective scope = `subject_scope ∩ actor_permitted ∩ requested_scope`
    ///    (rejects with `InvalidScope` when the intersection is empty).
    /// 5. Resulting token lifetime ≤ remaining subject token lifetime.
    ///
    /// Emits `AgentDelegation` audit event on success.
    fn rfc8693_token_exchange(
        &self,
        realm_id: &RealmId,
        request: &types::Rfc8693Request,
    ) -> Result<types::Rfc8693Response, IdentityError>;

    /// Checks whether an actor-token `jti` has already been used and records it.
    ///
    /// Actor tokens are short-lived JWT assertions (`exp - iat ≤ 5 min`).
    /// Their `jti` is stored for the remaining lifetime to prevent replay.
    /// Returns `Err(DPopProofReplay)` (reusing the replay guard) if already seen.
    fn check_and_record_actor_jti(
        &self,
        realm_id: &RealmId,
        jti: &str,
        now_secs: i64,
        exp_secs: i64,
    ) -> Result<(), IdentityError>;

    /// Lists active (non-revoked, non-expired) RFC 8693 delegation grants for
    /// the given subject user. Used by `GET /ui/consent/delegations`.
    fn list_delegation_grants(
        &self,
        realm_id: &RealmId,
        user_sub: &str,
    ) -> Result<Vec<types::DelegationGrantEntry>, IdentityError>;

    /// Revokes the delegation grant with the given `delegation_id`, if it
    /// belongs to `user_sub`. Immediately adds the bound JTI to the revoked-JTI
    /// blocklist so the issued access token becomes invalid.
    fn revoke_delegation_grant(
        &self,
        realm_id: &RealmId,
        delegation_id: &str,
        user_sub: &str,
    ) -> Result<(), IdentityError>;

    fn create_approval_request(
        &self,
        realm_id: &RealmId,
        request: &types::CreateApprovalRequestInput,
    ) -> Result<types::ApprovalRequest, IdentityError>;
    fn get_approval_request(
        &self,
        realm_id: &RealmId,
        request_id: &str,
    ) -> Result<types::ApprovalRequest, IdentityError>;
    fn approve_approval_request(
        &self,
        realm_id: &RealmId,
        request_id: &str,
        capability_ttl_secs: Option<i64>,
    ) -> Result<types::ApprovalRequestResponse, IdentityError>;
    fn deny_approval_request(
        &self,
        realm_id: &RealmId,
        request_id: &str,
        reason: Option<String>,
    ) -> Result<types::ApprovalRequestResponse, IdentityError>;
    fn list_approval_requests(
        &self,
        realm_id: &RealmId,
        status_filter: Option<types::ApprovalRequestStatus>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<types::Page<types::ApprovalRequest>, IdentityError>;

    /// Validates a capability token for a tool invocation (Phase C — Complete Mediation).
    ///
    /// Verifies signature, token type, audience, expiry, tool/action match,
    /// single-use JTI, and that the token's `sub` matches `caller_sub` (M5 —
    /// prevents confused-deputy attacks where agent A presents a token minted
    /// for agent B). Returns the calling `AgentId` on success.
    /// All failure modes return `ToolApprovalRequired { tool }`.
    fn validate_capability_token(
        &self,
        realm_id: &RealmId,
        token: &str,
        tool_name: &str,
        action: &str,
        caller_sub: &str,
    ) -> Result<crate::core::AgentId, IdentityError>;

    // ── Phase D.1: Attenuating Authorization Tokens ──────────────────────────

    /// Issues a root Attenuating Authorization Token for an agent.
    ///
    /// The AAT is signed by the realm's Ed25519 key (typ: `"aat+jwt"`).
    /// Returns `AgentNotFound` if the agent does not exist or is not Active.
    fn issue_aat(
        &self,
        realm_id: &RealmId,
        request: &types::IssueAatRequest,
    ) -> Result<types::AatResponse, IdentityError>;

    /// Derives a child AAT by narrowing the permissions of an existing parent AAT.
    ///
    /// Validates that:
    /// - The parent AAT has a valid Hearth Ed25519 signature.
    /// - The parent has not expired and is not revoked.
    /// - The child's `tools` and `scope` are subsets of the parent's.
    /// - The child's `exp` is ≤ the parent's `exp`.
    /// Returns `AatScopeEscalation` if the child attempts to widen permissions.
    fn derive_aat(
        &self,
        realm_id: &RealmId,
        request: &types::DeriveAatRequest,
    ) -> Result<types::AatResponse, IdentityError>;

    /// Validates the full attenuation chain of a presented AAT.
    ///
    /// Returns the decoded `AatClaims` on success.
    /// Returns `AatChainBroken` / `AatRevoked` / `AatExpired` / `AatAudienceMismatch` on failure.
    ///
    /// When `expected_aud` is `Some`, the `aud` claim must exactly match; otherwise
    /// `AatAudienceMismatch` is returned. Pass `None` to skip audience checking.
    fn validate_aat(
        &self,
        realm_id: &RealmId,
        aat: &str,
        expected_aud: Option<&str>,
    ) -> Result<types::AatClaims, IdentityError>;

    /// Revokes an AAT by JTI. Any descendant chain validation will also fail.
    fn revoke_aat(&self, realm_id: &RealmId, jti: &str) -> Result<(), IdentityError>;

    // ── Phase D.3: Transaction Tokens ────────────────────────────────────────

    /// Issues a single-use transaction token binding two agents to one operation.
    ///
    /// The token carries a `txn` claim (the provided `txn_id`) and expires in 60 s.
    /// Returns `TransactionTokenReplayed` if `txn_id` has already been used.
    fn issue_transaction_token(
        &self,
        realm_id: &RealmId,
        request: &types::CreateTransactionTokenRequest,
    ) -> Result<types::TransactionTokenResponse, IdentityError>;

    /// Validates a transaction token and marks it consumed (replay prevention).
    ///
    /// Returns the decoded `TransactionTokenClaims` on success.
    /// Returns `TransactionTokenReplayed` if the token has already been used.
    fn consume_transaction_token(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<types::TransactionTokenClaims, IdentityError>;

    // ── Phase D: DPoP JKT blocklist (§10.4) ──────────────────────────────────

    /// Adds a DPoP JWK thumbprint to the server-side blocklist (§10.4).
    ///
    /// After this call, every access token whose `cnf.jkt` matches `jkt`
    /// will be rejected at `validate_token` time without a storage lookup.
    fn block_dpop_jkt(&self, realm_id: &RealmId, jkt: &str) -> Result<(), IdentityError>;

    /// Removes a DPoP JWK thumbprint from the server-side blocklist (§10.4).
    fn unblock_dpop_jkt(&self, realm_id: &RealmId, jkt: &str) -> Result<(), IdentityError>;

    // ── Phase D.4: Cross-Realm Trust Policies ────────────────────────────────

    /// Creates a cross-realm trust policy in the given realm.
    ///
    /// The policy allows agents from `source_realm_id` to interact with
    /// resources in this realm, limited to `allowed_capabilities`.
    fn create_cross_realm_policy(
        &self,
        realm_id: &RealmId,
        request: &types::CreateCrossRealmPolicyRequest,
    ) -> Result<types::CrossRealmTrustPolicy, IdentityError>;

    /// Retrieves a cross-realm trust policy by ID.
    fn get_cross_realm_policy(
        &self,
        realm_id: &RealmId,
        policy_id: &str,
    ) -> Result<Option<types::CrossRealmTrustPolicy>, IdentityError>;

    /// Lists all cross-realm trust policies in the given realm.
    fn list_cross_realm_policies(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<types::CrossRealmTrustPolicy>, IdentityError>;

    /// Deletes a cross-realm trust policy.
    ///
    /// Returns `CrossRealmPolicyNotFound` if the policy does not exist.
    fn delete_cross_realm_policy(
        &self,
        realm_id: &RealmId,
        policy_id: &str,
    ) -> Result<(), IdentityError>;

    /// Checks whether a capability is permitted under the active cross-realm
    /// trust policy between `source_realm` and `target_realm`.
    fn check_cross_realm_policy(
        &self,
        target_realm: &RealmId,
        source_realm: &RealmId,
        capability: &str,
    ) -> Result<bool, IdentityError>;

    // ── Phase D.7: SPIFFE / Workload Identity ────────────────────────────────

    /// Registers a SPIFFE ID → `AgentId` mapping for mTLS workload authentication.
    ///
    /// Returns `SpiffeIdInvalid` if the SPIFFE ID format is wrong.
    /// Returns `SpiffeMappingConflict` if the agent already has a mapping.
    fn register_spiffe_mapping(
        &self,
        realm_id: &RealmId,
        request: &types::RegisterSpiffeIdRequest,
    ) -> Result<types::SpiffeIdentityMapping, IdentityError>;

    /// Looks up an `AgentId` by SPIFFE ID.
    fn lookup_agent_by_spiffe_id(
        &self,
        realm_id: &RealmId,
        spiffe_id: &str,
    ) -> Result<Option<AgentId>, IdentityError>;

    /// Removes the SPIFFE mapping for the given agent.
    fn delete_spiffe_mapping(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
    ) -> Result<(), IdentityError>;

    /// Validates an X.509 client certificate presented via mTLS against the
    /// realm's SPIFFE trust bundle and returns the mapped `AgentId`.
    ///
    /// This is called by the TLS termination layer when a workload presents a
    /// client certificate. The DER-encoded leaf certificate is passed in
    /// `der_cert`; the chain is not passed here (validated at TLS layer).
    ///
    /// Returns `SpiffeCertInvalid` if the certificate is malformed or expired.
    /// Returns `SpiffeMappingNotFound` if the SPIFFE ID is not registered.
    fn validate_spiffe_svid(
        &self,
        realm_id: &RealmId,
        der_cert: &[u8],
    ) -> Result<AgentId, IdentityError>;
}
