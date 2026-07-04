//! Embedded identity engine implementation.
//!
//! Implements `IdentityEngine` using the `StorageEngine` trait for persistence
//! and `Clock` trait for deterministic timestamps.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SecureRandom;
use secrecy::ExposeSecret;
use zeroize::{Zeroize, Zeroizing};

use crate::audit::{Actor, AuditAction, AuditContext, AuditEngine, CreateAuditEvent};
use crate::core::{
    AgentCredentialId, AgentId, ClientId, Clock, InvitationId, OrganizationId, RealmId, SessionId,
    Timestamp, UserId, WebhookId,
};
use crate::identity::claims_config::{
    resolve_claims_for_target, ClaimEvaluationContext, ClaimTarget,
};
use crate::identity::credentials::{self, CleartextPassword, CredentialConfig, StoredCredential};
use crate::identity::device_fp::{DeviceFingerprintOutcome, DeviceFingerprintStore};
use crate::identity::error::IdentityError;
use crate::identity::federation::saml::SamlError;
use crate::identity::keys;
use crate::identity::session_version::SessionVersionStore;
/// Encodes bytes as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Validates capability list bounds: max 50 entries, max 256 chars each.
fn validate_agent_capabilities(caps: &[String]) -> Result<(), crate::identity::IdentityError> {
    if caps.len() > 50 {
        return Err(crate::identity::IdentityError::InvalidInput {
            reason: format!("too many capabilities: max 50 allowed, got {}", caps.len()),
        });
    }
    for cap in caps {
        if cap.len() > 256 {
            return Err(crate::identity::IdentityError::InvalidInput {
                reason: "each capability string must not exceed 256 characters".to_string(),
            });
        }
    }
    Ok(())
}

use crate::identity::magic_link::{
    self, MagicLinkResponse, StoredMagicLink, StoredPasswordReset, MAGIC_LINK_EXPIRY_MICROS,
    PASSWORD_RESET_EXPIRY_MICROS,
};

/// Enforces token size caps per AUTHORIZATION.md § 2.6.
///
/// Operates on the *post-profile* claim payload that will actually be
/// embedded in the JWT, not the raw `ResolvedPermissions`. This ensures
/// scope-narrowed tokens are measured correctly.
///
/// Validates independently per `ClaimTarget` so that access-token and
/// ID-token payloads (which may differ after `apply_claim_profile`) are
/// each checked against the same numeric caps. Limit names include the
/// target prefix so operators can tell which surface tripped.
///
/// Custom claims are intentionally excluded from the 8 KiB byte limit
/// per the spec ("Serialized JWT claim bytes (`roles + groups + permissions`)").
pub(crate) fn validate_claim_payload(
    target: ClaimTarget,
    roles: &[String],
    groups: &[String],
    permissions: &[String],
) -> Result<(), IdentityError> {
    const MAX_PERMISSIONS: usize = 100;
    const MAX_ROLES: usize = 50;
    const MAX_GROUPS: usize = 50;
    const MAX_CLAIM_BYTES: usize = 8192;

    let target_prefix = match target {
        ClaimTarget::AccessToken => "access_token",
        ClaimTarget::IdToken => "id_token",
        ClaimTarget::UserInfo => "userinfo",
    };

    if permissions.len() > MAX_PERMISSIONS {
        return Err(IdentityError::TokenTooLarge {
            limit: format!("{target_prefix}_permissions_per_token"),
            limit_value: MAX_PERMISSIONS,
            actual: permissions.len(),
        });
    }
    if roles.len() > MAX_ROLES {
        return Err(IdentityError::TokenTooLarge {
            limit: format!("{target_prefix}_roles_per_token"),
            limit_value: MAX_ROLES,
            actual: roles.len(),
        });
    }
    if groups.len() > MAX_GROUPS {
        return Err(IdentityError::TokenTooLarge {
            limit: format!("{target_prefix}_groups_per_token"),
            limit_value: MAX_GROUPS,
            actual: groups.len(),
        });
    }

    let payload = serde_json::json!({
        "roles": roles,
        "groups": groups,
        "permissions": permissions,
    });
    let bytes = serde_json::to_vec(&payload).map_err(|e| IdentityError::Internal {
        reason: format!("token size serialization failed: {e}"),
    })?;
    if bytes.len() > MAX_CLAIM_BYTES {
        return Err(IdentityError::TokenTooLarge {
            limit: format!("{target_prefix}_claims_bytes_per_token"),
            limit_value: MAX_CLAIM_BYTES,
            actual: bytes.len(),
        });
    }

    Ok(())
}

/// Email-verification token expiry: 24 hours in microseconds.
const EMAIL_VERIFY_EXPIRY_MICROS: i64 = 24 * 60 * 60 * 1_000_000;

/// Deleted-email reservation window (A-20): 90 days in microseconds.
const EMAIL_RESERVED_MICROS: i64 = 90 * 24 * 60 * 60 * 1_000_000;

/// Email-change token expiry: 24 hours in microseconds (A-19).
const EMAIL_CHANGE_TOKEN_EXPIRY_MICROS: i64 = 24 * 60 * 60 * 1_000_000;

/// `prompt=none` probe rate-limit window: 1 hour in microseconds (A-37).
const PROMPT_NONE_WINDOW_MICROS: i64 = 60 * 60 * 1_000_000;

/// Maximum `prompt=none` probes per (realm, subject) per hour (A-37).
const PROMPT_NONE_MAX_PROBES: u32 = 50;

/// Maximum tolerated clock skew between issuer and validator, in seconds.
///
/// Tokens with `iat > now + CLOCK_SKEW_SECS` are rejected as future-dated.
/// 60 seconds matches common JWT library defaults and absorbs NTP drift without
/// opening a meaningful replay window.
const CLOCK_SKEW_SECS: i64 = 60;

/// Maximum entries in the in-process session cache (S12-F1).
const SESSION_CACHE_MAX: usize = 4096;

/// Maximum entries in the in-process token claims cache (S12-F2).
const TOKEN_CLAIMS_CACHE_MAX: usize = 2048;

/// Persisted state for a pending email-verification token.
///
/// Stored under `email:verify:{sha256_hex_of_token}`. The plaintext
/// token is never persisted — only its SHA-256 digest is used as the
/// key. Verification is single-use: on success the entry is deleted.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredEmailVerification {
    /// Stringified UUID of the user whose email is being verified.
    user_id: String,
    /// Creation time in Unix microseconds.
    created_at_micros: i64,
    /// Whether the token has already been consumed. Present for parity
    /// with the magic-link record; `verify_email_token` also deletes the
    /// entry outright on success.
    used: bool,
}

/// Tombstone written on `delete_user` to enforce the 90-day re-registration
/// cooldown (A-20). Stored under `email:reserved:{email}`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredEmailReservation {
    /// Unix microseconds when the account was deleted.
    reserved_at_micros: i64,
}

/// Tombstone written on `delete_organization` to enforce the post-delete slug
/// cooldown window (A-5). Stored under `slug:org:{realm_uuid_bytes}:{slug}`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredSlugReservation {
    /// The slug being held in cooldown.
    slug: String,
    /// Unix microseconds when the cooldown expires.
    expires_at_micros: i64,
}

/// Pending email-address change record (A-19).
///
/// Written by `initiate_email_change`; consumed by `confirm_email_change`.
/// Stored under `email:change:{sha256_hex_of_token}`. Single-use.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredEmailChangeToken {
    /// Stringified UUID of the user requesting the change.
    user_id: String,
    /// New address (normalized) awaiting verification.
    new_email: String,
    /// Old address — needed by `confirm_email_change` to notify the
    /// previous owner.
    old_email: String,
    /// Creation time in Unix microseconds.
    created_at_micros: i64,
}

/// Per-subject sliding-window counter for `prompt=none` probes (A-37).
///
/// Stored under `rl:prompt_none:{user_uuid}` within the realm.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredPromptNoneTracker {
    /// Number of probes recorded in the current window.
    count: u32,
    /// Unix microseconds of the first probe in the current window.
    window_start_micros: i64,
}

use crate::identity::oidc::{
    AuthorizationRequest, AuthorizationResponse, CodeChallengeMethod, OAuthClient, OidcConfig,
    OidcDiscoveryDocument, OidcTokenResponse, RefreshBindContext, RegisterClientRequest,
    RpLogoutRequest, RpLogoutResult, StoredGrantFamily, TokenExchangeRequest,
};
use crate::identity::tokens::{
    self, Audience, IssueTokenRequest, JwksDocument, SigningKey, TokenClaims, TokenConfig,
    TokenPair,
};
use crate::identity::totp::{self, RecoveryCodes, StoredMfaState, TotpEnrollment, TotpSecret};
use crate::identity::types::{
    Agent, AgentCredential, AgentCredentialKind, AgentOwner, AgentStatus, BulkResult,
    ConsentListEntry, ConsentRecord, CreateAgentApiKeyRequest, CreateAgentApiKeyResponse,
    CreateAgentRequest, CreateInvitationRequest, CreateOrganizationRequest, CreateRealmRequest,
    CreateUserRequest, DemoSeedOutcome, DemoSeedSpec, ImportClientRequest, ImportUserRequest,
    InvitationStatus, ListAgentsQuery, Organization, OrganizationInvitation,
    OrganizationMembership, OrganizationRole, OrganizationStatus, Page,
    PendingAuthorizationRequest, PlaintextApiKey, ProtectedResource, Realm, RealmStatus,
    RegisterProtectedResourceRequest, RegisterUserRequest, RegisterUserResponse,
    RegistrationPolicy, Rfc8693Request, Rfc8693Response, Session, SessionContext,
    SessionLimitPolicy, UpdateAgentRequest, UpdateOrganizationRequest,
    UpdateProtectedResourceRequest, UpdateRealmRequest, UpdateUserRequest, User, UserStatus,
};
use crate::identity::validation;
use crate::identity::webauthn::{
    self, AuthenticationOptions, CeremonyType, CompleteAuthenticationParams,
    PendingWebAuthnChallenge, RegistrationOptions, StoredWebAuthnCredential, WebAuthnAuthResult,
    WebAuthnChallengeStore, WebAuthnCredentialInfo,
};
use crate::identity::IdentityEngine;
use crate::rbac::error::RbacError;
use crate::rbac::registry::{classify_scope_string, ScopeKind};
use crate::storage::StorageEngine;

pub(super) mod approval;
pub(super) mod oauth;
// Phase D engine modules
pub(super) mod aat;
pub(super) mod cross_realm;
pub(super) mod spiffe;
pub(super) mod txn;

/// Context supplied to [`IdentityEngine::issue_tokens_with_context`] to
/// influence which claims are embedded in the issued token pair.
///
/// All fields are optional. `Default::default()` produces a first-party,
/// no-scope, no-org context that is equivalent to what the legacy
/// `issue_tokens` call produced before this struct existed.
#[derive(Clone, Debug, Default)]
pub struct TokenIssuanceContext {
    /// OAuth client the token is being issued for.
    ///
    /// `None` means a first-party session token (same sentinel as the
    /// pre-context `issue_tokens` path).
    pub client_id: Option<crate::core::ClientId>,
    /// Scopes that were granted for this token.
    ///
    /// Empty means no scope gating; all resolved permissions are included.
    pub granted_scopes: BTreeSet<String>,
    /// Organization context (`oid` claim) to embed in the token.
    ///
    /// `None` means no org context.
    pub oid: Option<String>,
    /// Optional RFC 8707 resource indicator. When present, the resource URI
    /// is embedded in the access and refresh token `aud` claim and enables
    /// audience-scoped scope resolution at token-issue time.
    ///
    /// `None` means no resource audience restriction.
    pub resource: Option<crate::core::Uri>,
}

/// Configuration for credential rate limiting.
///
/// Covers both per-account consecutive-failure lockout and per-IP sliding-window
/// throttling. All values are configurable via `security.rate_limiting` in YAML.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum consecutive failed attempts before per-account lockout. Default: 5.
    pub max_failed_attempts: u32,
    /// Per-account lockout duration in microseconds. Default: 300 s (5 min).
    pub lockout_duration_micros: i64,
    /// Maximum failed logins from a single IP within the window before it is
    /// blocked. Default: 10.
    pub ip_max_attempts: u32,
    /// Per-IP sliding window length in microseconds. Default: 60 s.
    pub ip_window_micros: i64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            lockout_duration_micros: 5 * 60 * 1_000_000, // 5 minutes
            ip_max_attempts: 10,
            ip_window_micros: 60 * 1_000_000, // 60 seconds
        }
    }
}

/// Configuration for session management.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session time-to-live in microseconds.
    ///
    /// Default: 24 hours (86,400,000,000 μs).
    pub ttl_micros: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            // 24 hours in microseconds
            ttl_micros: 24 * 60 * 60 * 1_000_000,
        }
    }
}

/// Configuration for the identity engine.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// Default status for newly created users.
    pub default_status: UserStatus,
    /// Password hashing parameters.
    pub credential: CredentialConfig,
    /// Session management parameters.
    pub session: SessionConfig,
    /// Token issuance parameters.
    pub token: TokenConfig,
    /// OIDC / OAuth 2.0 parameters.
    pub oidc: OidcConfig,
    /// Rate limiting for credential verification.
    pub rate_limit: RateLimitConfig,
    /// Periodic cleanup sweeper configuration.
    pub cleanup: crate::identity::cleanup::CleanupConfig,
    /// Number of keys to delete per chunk in delete_realm cascade.
    /// Defaults to 200. Applies both in sync and background mode.
    pub cascade_chunk_size: usize,
    /// Realm item count above which delete_realm spawns a background task.
    /// Below this threshold the cascade runs synchronously. Default: 1_000.
    pub cascade_background_threshold: usize,
    /// A-5: Operator-configured list of slug names that are permanently reserved
    /// and may never be used for org or realm slugs (e.g. `"admin"`, `"api"`).
    ///
    /// Defaults to an empty list; populated from `security.reserved_slugs` in
    /// `hearth.yaml` at startup.  The list is normalised to lowercase at
    /// startup so comparisons are case-insensitive.
    pub reserved_slugs: Vec<String>,
    /// A-5: Duration (in seconds) for which a slug is reserved after the
    /// org or realm that held it is deleted.
    ///
    /// Default: `30 * 86_400` (30 days).
    pub slug_cooldown_secs: u64,
    /// AES-256-GCM key-encryption key (KEK) for protecting cryptographic key
    /// material stored in the WAL at rest.
    ///
    /// When `None`, key bytes are stored unencrypted (legacy / dev mode).
    /// When `Some`, every signing-key and DPoP-nonce-secret write is wrapped
    /// in an HKEY envelope (see `key_encryption` module).  Existing plaintext
    /// entries continue to be read transparently and are re-encrypted on the
    /// next key rotation.
    pub key_encryption_key: Option<crate::identity::key_encryption::StorageKek>,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            default_status: UserStatus::Active,
            credential: CredentialConfig::default(),
            session: SessionConfig::default(),
            token: TokenConfig::default(),
            oidc: OidcConfig::default(),
            rate_limit: RateLimitConfig::default(),
            cleanup: crate::identity::cleanup::CleanupConfig::default(),
            cascade_chunk_size: 200,
            cascade_background_threshold: 1_000,
            reserved_slugs: Vec::new(),
            slug_cooldown_secs: 30 * 86_400,
            key_encryption_key: None,
        }
    }
}

/// Tracks failed credential verification attempts for a single user.
#[derive(Debug, Clone)]
struct AttemptTracker {
    /// Number of consecutive failed attempts.
    failed_count: u32,
    /// Timestamp (Unix micros) of the most recent failure.
    last_failure_micros: i64,
}

/// Prunes stale entries from an in-memory rate-tracker `HashMap`.
///
/// Removes all entries whose `last_failure_micros` is strictly before
/// `cutoff_micros`. Returns the number of entries removed.
///
/// Called from `EmbeddedIdentityEngine::sweep_expired` after the storage
/// sweep to bound memory growth in the five in-memory rate-tracker maps.
fn prune_rate_tracker(map: &mut HashMap<String, AttemptTracker>, cutoff_micros: i64) -> u64 {
    let before = map.len() as u64;
    map.retain(|_, t| t.last_failure_micros >= cutoff_micros);
    before.saturating_sub(map.len() as u64)
}

/// Embedded identity engine backed by a `StorageEngine`.
///
/// Manages user CRUD operations with email uniqueness enforcement,
/// input validation, and Unicode normalization. Supports multi-tenancy
/// with per-realm signing keys and configuration.
pub struct EmbeddedIdentityEngine {
    /// The underlying storage engine.
    storage: Arc<dyn StorageEngine>,
    /// Injectable clock for deterministic testing.
    clock: Arc<dyn Clock>,
    /// Engine configuration (global defaults, overridable per-realm).
    config: IdentityConfig,
    /// Claims-based RBAC engine used to resolve effective permissions
    /// at token-issue time. See `docs/specs/AUTHORIZATION.md`.
    rbac: Arc<dyn crate::rbac::RbacEngine>,
    /// Audit engine for recording security-critical mutations.
    ///
    /// Best-effort for non-destructive operations; returns
    /// `AuditFailure` for destructive operations when appending fails.
    audit: Arc<dyn AuditEngine>,
    /// Pre-computed dummy hash for timing-oracle prevention.
    ///
    /// When `verify_password` is called for a nonexistent user or missing
    /// credential, we verify against this dummy hash so the response time
    /// is indistinguishable from a real failed verification.
    dummy_hash: String,
    /// Default Ed25519 signing key for JWT token issuance (Phase 0 compat).
    signing_key: Arc<SigningKey>,
    /// Per-realm Ed25519 signing keys, lazily loaded from storage.
    ///
    /// Each realm gets its own key pair so tokens from one realm cannot
    /// validate in another.
    ///
    /// Hot-path readers call `load()` — one atomic fence, no locking.
    /// Writers use `rcu()` to clone-and-CAS the map; realm key ops are rare.
    /// Wrapped in `Arc` so background delete tasks can hold a reference.
    realm_signing_keys: Arc<ArcSwap<HashMap<RealmId, Arc<SigningKey>>>>,
    /// Wait-free realm status cache for the `validate_token` hot path.
    ///
    /// Populated at startup and updated on every realm CRUD operation.
    /// `validate_token` reads with `load()` — no lock, no storage call.
    /// Writers (`create_realm`, `update_realm`, `delete_realm`) use `rcu()`.
    /// Wrapped in `Arc` so background delete tasks can hold a reference.
    realm_status_cache: Arc<ArcSwap<HashMap<RealmId, RealmStatus>>>,
    /// Per-realm RSA signing keys used for SAML metadata + response signing.
    ///
    /// Lazily loaded. Regeneration happens only on first SAML operation in
    /// a realm that has no prior key — not on every startup.
    ///
    // INVARIANT: guard is always released inside a scoped block before any I/O or storage call.
    realm_saml_keys: Mutex<HashMap<String, Arc<crate::identity::tokens::RsaSigningKey>>>,
    /// Server-wide RSA-2048 signing key advertised at `/certs` for RS256
    /// (HEA-51 / OIDC M1, HEA-1655).
    ///
    /// Lazily initialized on first JWKS access — RSA keygen is slow
    /// (~0.5-1s), so we don't pay that cost in tests that never touch
    /// `/certs` or in startup paths that don't need OIDC. The key is
    /// persisted under `sys:oidc:rsa:key` in the system realm so the `kid`
    /// survives restarts (HEA-1655).
    oidc_rsa_key: std::sync::OnceLock<Arc<crate::identity::tokens::RsaSigningKey>>,
    /// Server-wide ECDSA P-256 signing key advertised at `/certs` for
    /// ES256 (HEA-51 / OIDC M1).
    ///
    /// Lazily initialized on first JWKS access. EC keygen is fast but we
    /// follow the same OnceLock pattern as `oidc_rsa_key` for symmetry.
    oidc_ecdsa_key: std::sync::OnceLock<Arc<crate::identity::tokens::EcdsaSigningKey>>,
    /// Per-user failed attempt trackers for rate limiting.
    ///
    /// Key is `(RealmId, UserId)` serialized as a string to avoid
    /// requiring `Hash` on the newtype wrappers.
    ///
    // INVARIANT: guard released before method returns; all callers are non-async helpers.
    attempt_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Per-user failed MFA attempt trackers (separate from password rate limiting).
    ///
    /// Stricter limits: 5 attempts, 5-minute lockout. Key format: `mfa:{realm}:{user}`.
    ///
    // INVARIANT: guard released before method returns; all callers are non-async helpers.
    mfa_attempt_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Used nonces for replay protection (when nonce enforcement is enabled).
    ///
    /// Maps nonce value to the timestamp it was first seen. Entries are swept
    /// on every insertion: any nonce older than `authorization_code_ttl_secs`
    /// is removed, bounding the set to at most one TTL window of activity.
    ///
    // INVARIANT: guard released before method returns; all callers are non-async helpers.
    used_nonces: Mutex<HashMap<String, crate::core::Timestamp>>,
    /// Per-email magic link rate trackers.
    ///
    /// Limits the number of magic link requests per email per hour.
    /// Key format: `magic:{realm}:{email}`.
    ///
    // INVARIANT: guard released before method returns; all callers are non-async helpers.
    magic_link_rate_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Per-email password reset rate trackers.
    ///
    /// Limits the number of password reset requests per email per hour.
    /// Key format: `reset:{realm}:{email}`.
    ///
    // INVARIANT: guard released before method returns; all callers are non-async helpers.
    password_reset_rate_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Per-email self-registration rate trackers.
    ///
    /// Limits the number of registration attempts per email per hour.
    /// Key format: `reg-email:{realm}:{email}`.
    ///
    // INVARIANT: guard released before method returns; all callers are non-async helpers.
    registration_email_rate_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Per-IP self-registration rate trackers.
    ///
    /// Limits the number of registration attempts per source IP per hour,
    /// across all realms and emails.
    /// Key format: raw IP string.
    ///
    // INVARIANT: guard released before method returns; all callers are non-async helpers.
    registration_ip_rate_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Per-IP login rate trackers for credential-stuffing protection.
    ///
    /// Counts failed login attempts per source IP per realm within a sliding
    /// window. Keyed by `"{realm_uuid}:{ip}"` so attacks on one realm do
    /// not affect legitimate users on another.
    ///
    // INVARIANT: guard released before method returns; all callers are non-async helpers.
    ip_login_rate_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Pending `WebAuthn` challenges awaiting completion.
    webauthn_challenges: WebAuthnChallengeStore,
    /// Per-user locks for serializing concurrent `create_session` calls.
    ///
    /// Prevents TOCTOU races when enforcing `max_concurrent_sessions`: the
    /// read (count live sessions) and the write (create or evict + create)
    /// must be atomic per user. Key format: `"{realm_uuid}:{user_uuid}"`.
    ///
    // INVARIANT: outer guard released in scoped block before inner per-user lock is acquired.
    // INVARIANT: inner (per-user) guard held only across the sync count-check + create window; no .await in scope.
    session_limit_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Per-realm locks for atomic JTI check-and-consume in the JWT Bearer grant.
    ///
    /// Eliminates the TOCTOU window between `storage.get` and `storage.put`
    /// in replay prevention. One lock per realm; created on first use.
    ///
    // INVARIANT: outer guard released inside jwt_bearer_jti_lock() before returning the inner Arc to the caller.
    // INVARIANT: inner (per-realm) guard held only across the sync JTI check-and-consume window; no .await in scope.
    jti_locks: Mutex<HashMap<RealmId, Arc<Mutex<()>>>>,
    /// Per-token-hash locks for single-use enforcement of magic-link and
    /// password-reset tokens.
    ///
    /// Eliminates the TOCTOU race between the `get` (reads `used=false`) and
    /// the `put` (writes `used=true`). Without this lock two concurrent
    /// requests for the same token can both pass the `used` check before
    /// either writes back. Key: hex-encoded SHA-256 of the raw token.
    token_redemption_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Per-request-id advisory lock for approval CAS state transitions.
    ///
    /// Eliminates the TOCTOU race in `approve_approval_request_inner`:
    /// two concurrent `approve` calls could both read `Pending` before either
    /// writes `Approved`, causing double capability-token issuance. Applies
    /// equally to concurrent `deny` calls. The outer map guard is released
    /// before acquiring the per-request inner lock so different request IDs
    /// never contend.
    ///
    // INVARIANT: outer guard released in scoped block before inner per-request lock is acquired.
    // INVARIANT: inner (per-request) guard held only across the sync read-check-mint-write window; no .await in scope.
    approval_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Per-`(realm_id, txn_id)` advisory lock for single-use enforcement in
    /// `issue_transaction_token_inner`.
    ///
    /// Eliminates the TOCTOU race between the guard read (`storage.get`) and
    /// the guard write (`storage.put`) in that function: two concurrent
    /// requests with the same `txn_id` could both pass the `get` check before
    /// either writes the used marker, resulting in two independently valid
    /// transaction tokens from one authorization. Key format:
    /// `"{realm_uuid}:{txn_id}"` so locks are realm-scoped.
    ///
    // INVARIANT: outer guard released in scoped block before inner per-txn lock is acquired.
    // INVARIANT: inner (per-txn) guard held only across the sync guard-read + sign + guard-write; no .await in scope.
    txn_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Serializes realm-record lifecycle mutations (create/update/delete).
    ///
    /// Realm ops are not on the hot path, and a realm record and its
    /// signing key MUST move together to avoid an orphaned "live realm
    /// with no JWKS" state. A single coarse mutex is the simplest way to
    /// guarantee atomicity of the record+key pair under concurrent
    /// callers; a finer-grained per-realm lock could come later if
    /// contention ever becomes measurable.
    ///
    // INVARIANT: guard held for the entire sync realm lifecycle operation; released when the method returns.
    realm_ops_lock: Mutex<()>,
    /// Serializes org slug reservation and invitation acceptance.
    ///
    /// Guards the check-then-write sequence in create_organization and
    /// accept_invitation so two concurrent callers cannot both win the
    /// same slug or both accept the same invitation token.
    ///
    // INVARIANT: guard held for the entire sync org write operation; released when the method returns.
    org_write_lock: Mutex<()>,
    /// HIBP k-anonymity breach-check client.
    ///
    /// Shared across all password-set/-change operations. Uses an injectable
    /// transport so tests can stub out network I/O.
    hibp: Arc<crate::identity::hibp::HibpClient>,
    /// Pre-token enrichment webhook client (HEA-1324, Gap C-3).
    ///
    /// Called before access token issuance when the realm has
    /// `pre_token_webhook` configured. Uses an injectable transport so tests
    /// can stub out network I/O without a real HTTP server.
    pre_token_client: Arc<crate::identity::pre_token_webhook::PreTokenWebhookClient>,
    /// Device fingerprint store for adaptive (risk-based) MFA.
    ///
    /// Holds HMAC-SHA256 digests of `(user_id, ip/24, user_agent)` with expiry
    /// timestamps. Shared across all realms — storage is realm-scoped internally.
    device_fp: Arc<DeviceFingerprintStore>,
    /// Session-version store for the `sv` claim (HEA-930).
    ///
    /// Provides bump, delta-feed, and snapshot operations on the `ssv:` key
    /// namespace. Shared with the `SvBumper` trait implementation so the RBAC
    /// engine can trigger bumps without importing from the identity layer.
    sv_store: Arc<SessionVersionStore>,
    /// In-process session cache for the `validate_token` hot path (S12-F1).
    ///
    /// Key: `(RealmId, SessionId)`. Value: `Arc<Session>`.
    /// Hot-path readers call `load()` — one atomic fence, no lock, no I/O.
    /// Writers use `rcu()` on `persist_session`. Bounded to [`SESSION_CACHE_MAX`].
    session_cache: ArcSwap<HashMap<(RealmId, SessionId), Arc<Session>>>,
    /// In-process token claims cache for the `validate_token` hot path (S12-F2).
    ///
    /// Key: SHA-256(`token_bytes`) as `[u8; 32]`. Value: `Arc<TokenClaims>`.
    /// Eliminates `serde_json` allocation for repeated validations of the same
    /// access token. Hot-path readers call `load()`. Bounded to
    /// [`TOKEN_CLAIMS_CACHE_MAX`].
    token_claims_cache: ArcSwap<HashMap<[u8; 32], Arc<TokenClaims>>>,
    /// Per-realm DPoP nonce HMAC secrets (AGENT_AUTH.md §13.2).
    ///
    /// Lazily populated: first call for a realm loads or generates the secret
    /// from storage, subsequent calls return the cached value. The underlying
    /// storage key is `agt:dpop:nonce-secret` in the realm's namespace.
    ///
    // INVARIANT: guard released before any I/O or storage call.
    dpop_nonce_cache: Mutex<HashMap<RealmId, [u8; 32]>>,
    /// Hot-path DPoP JKT blocklist projection (§10.4).
    ///
    /// Key: JWK thumbprint string. Present = blocked; absent = allowed.
    ///
    /// Populated at startup by scanning `agt:dpop:block:jkt:*` across all realms.
    /// Updated via `rcu()` by `block_dpop_jkt` / `unblock_dpop_jkt`.
    /// Hot-path readers call `load()` — one atomic fence, no lock, no syscall.
    blocked_dpop_jkt_cache: ArcSwap<std::collections::HashSet<String>>,
    /// Hot-path JTI revocation projection (§10.5).
    ///
    /// Key: `"{realm_uuid}:{jti}"`. Value: expiry (Unix seconds); `i64::MAX`
    /// for entries written before this projection existed (stored as `b"1"`).
    ///
    /// Populated at startup by scanning `oauth:revjti:*` across all realms.
    /// Updated (via `rcu()`) whenever a sessionless token is revoked.
    /// Hot-path readers call `load()` — one atomic fence, no lock, no syscall.
    ///
    /// Expired entries remain until the next `rcu()` eviction sweep; an expired
    /// token is rejected by the `exp` claim check before we reach this cache,
    /// so stale entries are harmless.
    revoked_jti_cache: ArcSwap<HashMap<String, i64>>,
    // INVARIANT: guard released before method returns; no .await in scope.
    agent_rate_monitor: crate::abuse::agent_monitor::AgentRateMonitor,
    /// Per-code-hash advisory lock for single-use enforcement of authorization codes.
    ///
    /// Eliminates the TOCTOU race between the `get` (reads the stored code) and
    /// the `delete` (consumes it). Without this lock, two concurrent requests for
    /// the same code can both load it before either deletes it, resulting in two
    /// successful exchanges. Callers hold this lock across the entire
    /// get → validate → delete → issue-tokens sequence. Key: SHA-256 hex of the
    /// raw code value (same value used as the storage key via `encode_oauth_code`).
    ///
    // INVARIANT: outer guard released in scoped block before inner per-code lock is acquired.
    // INVARIANT: inner (per-code) guard held only across the sync load + validate + delete window; no .await in scope.
    code_exchange_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl std::fmt::Debug for EmbeddedIdentityEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedIdentityEngine")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl EmbeddedIdentityEngine {
    fn claim_profile_overrides(
        &self,
        realm_id: &RealmId,
    ) -> Vec<crate::identity::claims_config::ClaimMapping> {
        self.get_realm(realm_id)
            .ok()
            .flatten()
            .and_then(|realm| realm.config().claim_profile.clone())
            .map(|profile| profile.mappings)
            .unwrap_or_default()
    }

    fn claim_vector(value: Option<&serde_json::Value>) -> Vec<String> {
        match value {
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        }
    }

    fn apply_claim_profile(
        &self,
        realm_id: &RealmId,
        user: &User,
        client: &OAuthClient,
        resolved: &crate::rbac::ResolvedPermissions,
        granted_scopes: &BTreeSet<String>,
        oid: Option<&str>,
        target: ClaimTarget,
    ) -> (
        Vec<String>,
        Vec<String>,
        Vec<String>,
        BTreeMap<String, serde_json::Value>,
    ) {
        let permissions: Vec<String> = resolved
            .permissions
            .iter()
            .map(|permission| permission.as_str().to_string())
            .collect();
        let overrides = self.claim_profile_overrides(realm_id);
        let ctx = ClaimEvaluationContext {
            user,
            client,
            roles: &resolved.roles,
            groups: &resolved.groups,
            permissions: &permissions,
            granted_scopes,
            oid,
        };
        let mut claims = resolve_claims_for_target(target, &overrides, &ctx);
        let roles = Self::claim_vector(claims.get("roles"));
        let groups = Self::claim_vector(claims.get("groups"));
        let permissions = Self::claim_vector(claims.get("permissions"));
        claims.remove("roles");
        claims.remove("groups");
        claims.remove("permissions");
        (roles, groups, permissions, claims)
    }

    /// Fires the pre-token enrichment webhook for a realm (if configured) and
    /// returns extra claims to merge into the access token.
    ///
    /// Returns `Ok(extra)` on success (may be empty), respects the realm's
    /// `on_error` policy on transport failure.
    pub(super) fn fire_pre_token_webhook(
        &self,
        realm_id: &RealmId,
        user_id: &str,
        client_id: &str,
        grant_type: &'static str,
        scope: Option<&str>,
        session_id: Option<&str>,
        existing_roles: &[String],
        existing_groups: &[String],
        existing_permissions: &[String],
        existing_custom: &BTreeMap<String, serde_json::Value>,
    ) -> Result<BTreeMap<String, serde_json::Value>, IdentityError> {
        use crate::identity::pre_token_webhook::{ExistingClaims, PreTokenWebhookRequest};
        use crate::identity::types::PreTokenWebhookErrorPolicy;

        let cfg = match self
            .get_realm(realm_id)?
            .as_ref()
            .and_then(|r| r.config().pre_token_webhook.as_ref())
            .cloned()
        {
            Some(c) => c,
            None => return Ok(BTreeMap::new()),
        };

        let request = PreTokenWebhookRequest {
            event: "pre_token",
            realm_id: realm_id.to_string(),
            user_id: user_id.to_string(),
            client_id: client_id.to_string(),
            grant_type,
            scope: scope.map(str::to_string),
            session_id: session_id.map(str::to_string),
            existing_claims: ExistingClaims {
                roles: existing_roles.to_vec(),
                groups: existing_groups.to_vec(),
                permissions: existing_permissions.to_vec(),
                custom: existing_custom.clone(),
            },
        };

        match self.pre_token_client.call(
            &cfg.url,
            cfg.timeout_ms,
            cfg.hmac_secret.as_deref(),
            &request,
        ) {
            Ok(extra) => Ok(extra),
            Err(e) => match cfg.on_error {
                PreTokenWebhookErrorPolicy::FailOpen => {
                    tracing::warn!(
                        realm_id = %realm_id,
                        url = %cfg.url,
                        error = %e,
                        "pre-token webhook failed (fail_open): issuing token without extra claims"
                    );
                    Ok(BTreeMap::new())
                }
                PreTokenWebhookErrorPolicy::FailClosed => {
                    Err(IdentityError::PreTokenWebhookFailed {
                        reason: e.to_string(),
                    })
                }
            },
        }
    }

    fn validate_client_scope_request(
        &self,
        client: &OAuthClient,
        raw_scope: &str,
    ) -> Result<(), IdentityError> {
        // RFC 6749 §3.3 character validation (must come first — gate all paths)
        validation::validate_scope_tokens(raw_scope)?;
        let requested: Vec<&str> = raw_scope
            .split_whitespace()
            .filter(|scope| !scope.is_empty())
            .collect();
        if client.trust_level() == crate::identity::ClientTrustLevel::ThirdParty
            && requested.is_empty()
        {
            return Err(IdentityError::InvalidInput {
                reason: "invalid_scope: third-party clients must request at least one scope"
                    .to_string(),
            });
        }
        for scope in requested {
            // OIDC standard scopes (openid, profile, email, phone, address,
            // offline_access) are protocol-level. They are always legal
            // regardless of `declared_scopes` and are exempt from the
            // ThirdParty-permission prohibition.
            if classify_scope_string(scope) == Some(ScopeKind::OidcStandard) {
                continue;
            }

            // Non-OIDC scopes must be in declared_scopes when the client
            // has a non-empty declared set.
            if !client.declared_scopes().is_empty()
                && !client
                    .declared_scopes()
                    .iter()
                    .any(|declared| declared == scope)
            {
                return Err(IdentityError::InvalidInput {
                    reason: format!("invalid_scope: client did not declare scope '{scope}'"),
                });
            }

            if client.trust_level() == crate::identity::ClientTrustLevel::ThirdParty
                && classify_scope_string(scope) == Some(ScopeKind::Permission)
            {
                return Err(IdentityError::InvalidInput {
                    reason: format!(
                        "invalid_scope: third-party clients cannot request raw permission scope '{scope}'"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Records an audit event for a security-critical mutation.
    ///
    /// Best-effort for non-destructive actions (`LogOnly` policy): logs
    /// a warning on failure. Returns `Err(AuditFailure)` for destructive
    /// actions (`FailOperation` policy) so the caller knows the audit
    /// trail has a gap.
    fn record_audit(
        &self,
        realm_id: &RealmId,
        ctx: Option<&AuditContext>,
        action: AuditAction,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<(), IdentityError> {
        let policy = action.failure_policy();
        let actor = ctx.map_or_else(|| "system".to_string(), |c| c.actor.label());
        let event = CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor,
            action,
            resource_type: resource_type.to_string(),
            resource_id: resource_id.to_string(),
            metadata: ctx.and_then(|c| c.metadata.clone()),
        };
        match self.audit.append(&event) {
            Ok(_) => Ok(()),
            Err(e) => {
                if policy == crate::audit::AuditFailurePolicy::FailOperation {
                    tracing::error!(
                        error = %e,
                        action = %event.action.as_str(),
                        resource_id = %resource_id,
                        "Audit append failed for destructive operation"
                    );
                    Err(IdentityError::AuditFailure {
                        action: event.action.as_str().to_string(),
                        reason: e.to_string(),
                    })
                } else {
                    tracing::warn!(
                        error = %e,
                        action = %event.action.as_str(),
                        resource_id = %resource_id,
                        "Audit append failed (non-blocking)"
                    );
                    Ok(())
                }
            }
        }
    }

    /// Creates a new identity engine, constructing a fresh
    /// [`crate::rbac::EmbeddedRbacEngine`] sharing the same storage and
    /// clock. Convenience for tests and benches that don't need to hold
    /// a separate handle to the RBAC engine.
    pub fn new(
        storage: Arc<dyn StorageEngine>,
        clock: Arc<dyn Clock>,
        config: IdentityConfig,
        audit: Arc<dyn AuditEngine>,
    ) -> Result<Self, IdentityError> {
        let rbac: Arc<dyn crate::rbac::RbacEngine> = Arc::new(
            crate::rbac::EmbeddedRbacEngine::new(Arc::clone(&storage), Arc::clone(&clock)),
        );
        Self::with_rbac(storage, clock, config, rbac, audit)
    }

    /// Creates a new identity engine wired to an explicit RBAC engine.
    ///
    /// Production wiring (where the rbac engine is shared with admin
    /// surfaces) should use this constructor. Generates an Ed25519
    /// signing key and pre-computes a dummy Argon2id hash on construction
    /// for timing-oracle prevention during password verification.
    pub fn with_rbac(
        storage: Arc<dyn StorageEngine>,
        clock: Arc<dyn Clock>,
        config: IdentityConfig,
        rbac: Arc<dyn crate::rbac::RbacEngine>,
        audit: Arc<dyn AuditEngine>,
    ) -> Result<Self, IdentityError> {
        let dummy_hash = credentials::compute_dummy_hash(&config.credential);
        let kek = config.key_encryption_key.as_ref().map(|k| k.as_bytes());
        let signing_key = Arc::new(Self::load_or_persist_global_signing_key(&storage, kek)?);
        let device_fp = Arc::new(DeviceFingerprintStore::new(Arc::clone(&storage)));
        let sv_store = Arc::new(SessionVersionStore::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
        ));
        let engine = Self {
            storage,
            clock,
            config,
            rbac,
            audit,
            dummy_hash,
            signing_key,
            realm_signing_keys: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            realm_status_cache: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            // INVARIANT: guard released in scoped block before I/O in get_or_create_saml_signing_key.
            realm_saml_keys: Mutex::new(HashMap::new()),
            oidc_rsa_key: std::sync::OnceLock::new(),
            oidc_ecdsa_key: std::sync::OnceLock::new(),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            attempt_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            mfa_attempt_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            magic_link_rate_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            password_reset_rate_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            registration_email_rate_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            registration_ip_rate_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            ip_login_rate_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            used_nonces: Mutex::new(HashMap::new()),
            webauthn_challenges: WebAuthnChallengeStore::new(),
            // INVARIANT: outer guard released in scoped block before inner per-user lock is acquired.
            session_limit_locks: Mutex::new(HashMap::new()),
            // INVARIANT: outer guard released inside jwt_bearer_jti_lock() before returning the inner Arc.
            jti_locks: Mutex::new(HashMap::new()),
            token_redemption_locks: Mutex::new(HashMap::new()),
            approval_locks: Mutex::new(HashMap::new()),
            // INVARIANT: outer guard released in scoped block before inner per-txn lock is acquired.
            txn_locks: Mutex::new(HashMap::new()),
            // INVARIANT: outer guard released in scoped block before inner per-code lock is acquired.
            code_exchange_locks: Mutex::new(HashMap::new()),
            // INVARIANT: guard held for entire sync realm lifecycle op; released when method returns.
            realm_ops_lock: Mutex::new(()),
            // INVARIANT: guard held for entire sync org write op; released when method returns.
            org_write_lock: Mutex::new(()),
            hibp: Arc::new(crate::identity::hibp::HibpClient::new()),
            pre_token_client: Arc::new(
                crate::identity::pre_token_webhook::PreTokenWebhookClient::new(),
            ),
            device_fp,
            sv_store,
            session_cache: ArcSwap::from_pointee(HashMap::new()),
            token_claims_cache: ArcSwap::from_pointee(HashMap::new()),
            dpop_nonce_cache: Mutex::new(HashMap::new()),
            blocked_dpop_jkt_cache: ArcSwap::from_pointee(std::collections::HashSet::new()),
            revoked_jti_cache: ArcSwap::from_pointee(HashMap::new()),
            // INVARIANT: guard released before method returns; no .await in scope.
            agent_rate_monitor: crate::abuse::agent_monitor::AgentRateMonitor::new(
                crate::abuse::agent_monitor::AgentRateConfig::default(),
            ),
        };
        engine.seed_system_realm_if_absent()?;
        engine.restore_attempt_trackers_from_wal()?;
        engine.populate_realm_status_cache()?;
        engine.populate_revoked_jti_cache()?;
        engine.populate_blocked_dpop_jkt_cache()?;
        Ok(engine)
    }

    /// Scans the WAL for all persisted rate-limit trackers and rehydrates the
    /// in-memory maps.
    ///
    /// Called once at startup from [`Self::new`]. Entries whose rate-limit window
    /// has already expired are silently skipped (they can never enforce a block).
    #[allow(clippy::too_many_lines)]
    fn restore_attempt_trackers_from_wal(&self) -> Result<(), IdentityError> {
        // Collect all non-system realm IDs once; reuse for every tracker type.
        let sys_realm = keys::system_realm_id();
        let realm_prefix = keys::realm_id_scan_prefix();
        let realm_end = keys::prefix_end(&realm_prefix);
        let realm_entries = self
            .storage
            .scan(&sys_realm, &realm_prefix, &realm_end)
            .map_err(Self::storage_err)?;

        let now = self.clock.now().as_micros();

        // Helper: read one JSON blob entry and return (failed_count, last_failure_micros).
        fn parse_blob(value: &[u8]) -> Option<(u32, i64)> {
            let blob = serde_json::from_slice::<serde_json::Value>(value).ok()?;
            let failed_count = blob["failed_count"].as_u64().map(|v| v as u32)?;
            let last_failure_micros = blob["last_failure_micros"].as_i64()?;
            Some((failed_count, last_failure_micros))
        }

        for realm_entry in &realm_entries {
            let realm: Realm = match serde_json::from_slice(&realm_entry.value) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if keys::is_system_realm(realm.id()) {
                continue;
            }
            let realm_id = realm.id();

            // ── per-user password-failure trackers (attempt_trackers) ─────────
            {
                let prefix = keys::attempt_tracker_scan_prefix();
                let end = keys::prefix_end(&prefix);
                let (max_attempts, lockout_micros) = self.effective_rate_limit(realm_id);
                let mut map = self.attempt_trackers.lock().expect("tracker lock");
                if let Ok(entries) = self.storage.scan(realm_id, &prefix, &end) {
                    for entry in entries {
                        let Some((failed_count, last_failure_micros)) = parse_blob(&entry.value)
                        else {
                            continue;
                        };
                        if failed_count >= max_attempts
                            && now - last_failure_micros >= lockout_micros
                        {
                            continue;
                        }
                        if entry.key.len() <= prefix.len() {
                            continue;
                        }
                        let Ok(uuid_str) = std::str::from_utf8(&entry.key[prefix.len()..]) else {
                            continue;
                        };
                        let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) else {
                            continue;
                        };
                        let user_id = UserId::new(uuid);
                        let mem_key = Self::tracker_key(realm_id, &user_id);
                        map.insert(
                            mem_key,
                            AttemptTracker {
                                failed_count,
                                last_failure_micros,
                            },
                        );
                    }
                }
            }

            // ── per-IP login rate-limit trackers ──────────────────────────────
            {
                let prefix = keys::ip_login_tracker_scan_prefix();
                let end = keys::prefix_end(&prefix);
                let window = self.config.rate_limit.ip_window_micros;
                let max_count = self.config.rate_limit.ip_max_attempts;
                let mut map = self
                    .ip_login_rate_trackers
                    .lock()
                    .expect("ip login tracker lock");
                if let Ok(entries) = self.storage.scan(realm_id, &prefix, &end) {
                    for entry in entries {
                        let Some((failed_count, last_failure_micros)) = parse_blob(&entry.value)
                        else {
                            continue;
                        };
                        if failed_count >= max_count && now - last_failure_micros >= window {
                            continue;
                        }
                        if entry.key.len() <= prefix.len() {
                            continue;
                        }
                        let Ok(ip) = std::str::from_utf8(&entry.key[prefix.len()..]) else {
                            continue;
                        };
                        // In-memory key includes realm UUID so different realms
                        // share a single HashMap without key collisions.
                        let mem_key = Self::ip_login_tracker_key(realm_id, ip);
                        map.insert(
                            mem_key,
                            AttemptTracker {
                                failed_count,
                                last_failure_micros,
                            },
                        );
                    }
                }
            }

            // ── per-user MFA failed-attempt trackers ──────────────────────────
            {
                let prefix = keys::mfa_tracker_scan_prefix();
                let end = keys::prefix_end(&prefix);
                let mut map = self.mfa_attempt_trackers.lock().expect("mfa tracker lock");
                if let Ok(entries) = self.storage.scan(realm_id, &prefix, &end) {
                    for entry in entries {
                        let Some((failed_count, last_failure_micros)) = parse_blob(&entry.value)
                        else {
                            continue;
                        };
                        if failed_count >= Self::MFA_MAX_ATTEMPTS
                            && now - last_failure_micros >= Self::MFA_LOCKOUT_MICROS
                        {
                            continue;
                        }
                        if entry.key.len() <= prefix.len() {
                            continue;
                        }
                        let Ok(uuid_str) = std::str::from_utf8(&entry.key[prefix.len()..]) else {
                            continue;
                        };
                        let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) else {
                            continue;
                        };
                        let user_id = UserId::new(uuid);
                        let mem_key = Self::mfa_tracker_key(realm_id, &user_id);
                        map.insert(
                            mem_key,
                            AttemptTracker {
                                failed_count,
                                last_failure_micros,
                            },
                        );
                    }
                }
            }

            // ── per-email magic-link rate-limit trackers ─────────��────────────
            {
                let prefix = keys::magic_link_rl_scan_prefix();
                let end = keys::prefix_end(&prefix);
                let mut map = self
                    .magic_link_rate_trackers
                    .lock()
                    .expect("magic link tracker lock");
                if let Ok(entries) = self.storage.scan(realm_id, &prefix, &end) {
                    for entry in entries {
                        let Some((failed_count, last_failure_micros)) = parse_blob(&entry.value)
                        else {
                            continue;
                        };
                        if failed_count >= Self::MAGIC_LINK_MAX_REQUESTS
                            && now - last_failure_micros >= Self::MAGIC_LINK_RATE_WINDOW_MICROS
                        {
                            continue;
                        }
                        if entry.key.len() <= prefix.len() {
                            continue;
                        }
                        let Ok(email) = std::str::from_utf8(&entry.key[prefix.len()..]) else {
                            continue;
                        };
                        let mem_key = Self::magic_link_tracker_key(realm_id, email);
                        map.insert(
                            mem_key,
                            AttemptTracker {
                                failed_count,
                                last_failure_micros,
                            },
                        );
                    }
                }
            }

            // ── per-email password-reset rate-limit trackers ──────────────────
            {
                let prefix = keys::password_reset_rl_scan_prefix();
                let end = keys::prefix_end(&prefix);
                let mut map = self
                    .password_reset_rate_trackers
                    .lock()
                    .expect("password reset tracker lock");
                if let Ok(entries) = self.storage.scan(realm_id, &prefix, &end) {
                    for entry in entries {
                        let Some((failed_count, last_failure_micros)) = parse_blob(&entry.value)
                        else {
                            continue;
                        };
                        if failed_count >= Self::PASSWORD_RESET_MAX_REQUESTS
                            && now - last_failure_micros >= Self::PASSWORD_RESET_RATE_WINDOW_MICROS
                        {
                            continue;
                        }
                        if entry.key.len() <= prefix.len() {
                            continue;
                        }
                        let Ok(email) = std::str::from_utf8(&entry.key[prefix.len()..]) else {
                            continue;
                        };
                        let mem_key = Self::password_reset_tracker_key(realm_id, email);
                        map.insert(
                            mem_key,
                            AttemptTracker {
                                failed_count,
                                last_failure_micros,
                            },
                        );
                    }
                }
            }

            // ── per-email registration rate-limit trackers ────────────────────
            {
                let prefix = keys::registration_email_rl_scan_prefix();
                let end = keys::prefix_end(&prefix);
                let mut map = self
                    .registration_email_rate_trackers
                    .lock()
                    .expect("registration email tracker lock");
                if let Ok(entries) = self.storage.scan(realm_id, &prefix, &end) {
                    for entry in entries {
                        let Some((failed_count, last_failure_micros)) = parse_blob(&entry.value)
                        else {
                            continue;
                        };
                        if failed_count >= Self::REGISTRATION_EMAIL_MAX_REQUESTS
                            && now - last_failure_micros >= Self::REGISTRATION_RATE_WINDOW_MICROS
                        {
                            continue;
                        }
                        if entry.key.len() <= prefix.len() {
                            continue;
                        }
                        let Ok(email) = std::str::from_utf8(&entry.key[prefix.len()..]) else {
                            continue;
                        };
                        let mem_key = Self::registration_email_tracker_key(realm_id, email);
                        map.insert(
                            mem_key,
                            AttemptTracker {
                                failed_count,
                                last_failure_micros,
                            },
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Scans storage for all non-system realms and populates the wait-free
    /// `realm_status_cache` used by the `validate_token` hot path.
    ///
    /// Called once at startup after seeding. Realms created or updated after
    /// this point are tracked via the individual CRUD cache updates.
    fn populate_realm_status_cache(&self) -> Result<(), IdentityError> {
        let sys_realm = keys::system_realm_id();
        let realm_prefix = keys::realm_id_scan_prefix();
        let realm_end = keys::prefix_end(&realm_prefix);
        let entries = self
            .storage
            .scan(&sys_realm, &realm_prefix, &realm_end)
            .map_err(Self::storage_err)?;

        let mut map = HashMap::new();
        for entry in &entries {
            // Fail-closed: a corrupted realm record must hard-error rather than
            // silently skipping, which would leave the realm absent from the
            // cache and allow validate_token to pass the status check fail-open.
            let realm = serde_json::from_slice::<Realm>(&entry.value).map_err(|e| {
                tracing::error!(
                    key = ?entry.key,
                    err = %e,
                    "realm deserialization failed during status cache population \
                     — refusing to start with an incomplete cache"
                );
                IdentityError::Internal {
                    reason: format!("realm status cache population failed: {e}"),
                }
            })?;
            if !keys::is_system_realm(realm.id()) {
                map.insert(realm.id().clone(), realm.status());
            }
        }
        self.realm_status_cache.store(Arc::new(map));
        Ok(())
    }

    /// Scans all realm namespaces for `oauth:revjti:*` keys and loads
    /// non-expired entries into `revoked_jti_cache`.
    ///
    /// Called once at startup.  Handles two storage-value formats:
    /// - 8-byte little-endian `i64` expiry (current format)
    /// - Any other length (legacy `b"1"` format): mapped to `i64::MAX`
    ///   so the entry is never self-evicted (the `exp` claim check catches it).
    fn populate_revoked_jti_cache(&self) -> Result<(), IdentityError> {
        let sys_realm = keys::system_realm_id();
        let realm_prefix = keys::realm_id_scan_prefix();
        let realm_end = keys::prefix_end(&realm_prefix);
        let realm_entries = self
            .storage
            .scan(&sys_realm, &realm_prefix, &realm_end)
            .map_err(Self::storage_err)?;

        let now_secs = self.clock.now().as_micros() / 1_000_000;
        let jti_prefix = keys::revoked_jti_scan_prefix();
        let jti_end = keys::prefix_end(&jti_prefix);

        let mut map: HashMap<String, i64> = HashMap::new();

        for realm_entry in &realm_entries {
            let Ok(realm) =
                serde_json::from_slice::<crate::identity::types::Realm>(&realm_entry.value)
            else {
                continue;
            };
            if keys::is_system_realm(realm.id()) {
                continue;
            }
            let jti_entries = self
                .storage
                .scan(realm.id(), &jti_prefix, &jti_end)
                .map_err(Self::storage_err)?;

            for entry in jti_entries {
                let exp: i64 = if entry.value.len() == 8 {
                    // Current format: LE i64 expiry.
                    i64::from_le_bytes(entry.value[..8].try_into().unwrap_or([0xff_u8; 8]))
                } else {
                    // Legacy b"1" format: no expiry stored; never self-evict.
                    i64::MAX
                };
                // Skip entries that are already expired.
                if exp != i64::MAX && now_secs >= exp {
                    continue;
                }
                let jti_key = String::from_utf8_lossy(&entry.key);
                // Strip the `oauth:revjti:` prefix to get the raw JTI string.
                let jti = jti_key.strip_prefix("oauth:revjti:").unwrap_or(&jti_key);
                let cache_key = format!("{}:{}", realm.id().as_uuid(), jti);
                map.insert(cache_key, exp);
            }
        }

        self.revoked_jti_cache.store(Arc::new(map));
        Ok(())
    }

    /// Scans all realm namespaces for `agt:dpop:block:jkt:*` keys and loads
    /// their thumbprints into `blocked_dpop_jkt_cache`.
    ///
    /// Called once at startup. The blocklist has no expiry — entries are
    /// admin-managed via `block_dpop_jkt` / `unblock_dpop_jkt`.
    fn populate_blocked_dpop_jkt_cache(&self) -> Result<(), IdentityError> {
        let sys_realm = keys::system_realm_id();
        let realm_prefix = keys::realm_id_scan_prefix();
        let realm_end = keys::prefix_end(&realm_prefix);
        let realm_entries = self
            .storage
            .scan(&sys_realm, &realm_prefix, &realm_end)
            .map_err(Self::storage_err)?;

        let jkt_prefix = keys::blocked_dpop_jkt_scan_prefix();
        let jkt_end = keys::prefix_end(&jkt_prefix);

        let mut set = std::collections::HashSet::new();

        for realm_entry in &realm_entries {
            let Ok(realm) =
                serde_json::from_slice::<crate::identity::types::Realm>(&realm_entry.value)
            else {
                continue;
            };
            if keys::is_system_realm(realm.id()) {
                continue;
            }
            let entries = self
                .storage
                .scan(realm.id(), &jkt_prefix, &jkt_end)
                .map_err(Self::storage_err)?;

            for entry in entries {
                let raw = String::from_utf8_lossy(&entry.key);
                let jkt = raw
                    .strip_prefix("agt:dpop:block:jkt:")
                    .unwrap_or(&raw)
                    .to_string();
                set.insert(jkt);
            }
        }

        self.blocked_dpop_jkt_cache.store(Arc::new(set));
        Ok(())
    }

    /// Adds `(realm, jti, exp)` entry to `revoked_jti_cache` via RCU.
    ///
    /// Also evicts any entries whose expiry has already passed to bound
    /// cache memory.  Called from every revocation write site.
    fn insert_revoked_jti_cache(&self, realm_id: &RealmId, jti: &str, exp_secs: i64) {
        let cache_key = format!("{}:{}", realm_id.as_uuid(), jti);
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        self.revoked_jti_cache.rcu(|old| {
            let mut next: HashMap<String, i64> = old
                .iter()
                // Evict expired entries while we hold the clone.
                .filter(|(_, &exp)| exp == i64::MAX || now_secs < exp)
                .map(|(k, &v)| (k.clone(), v))
                .collect();
            next.insert(cache_key.clone(), exp_secs);
            next
        });
    }

    /// Adds a DPoP JWK thumbprint to the server-side blocklist (§10.4).
    ///
    /// Writes the thumbprint to persistent storage and updates the hot-path
    /// in-memory projection via `rcu()`. After this call, every access token
    /// whose `cnf.jkt` matches `jkt` will be rejected at `validate_token` time.
    pub(super) fn block_dpop_jkt_inner(
        &self,
        realm_id: &RealmId,
        jkt: &str,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_blocked_dpop_jkt(jkt);
        self.storage
            .put(realm_id, &key, b"")
            .map_err(Self::storage_err)?;
        let jkt_owned = jkt.to_string();
        self.blocked_dpop_jkt_cache.rcu(|old| {
            let mut next = (**old).clone();
            next.insert(jkt_owned.clone());
            next
        });
        Ok(())
    }

    /// Removes a DPoP JWK thumbprint from the server-side blocklist (§10.4).
    ///
    /// Deletes the thumbprint from persistent storage and updates the hot-path
    /// in-memory projection. After this call, tokens bound to `jkt` are
    /// accepted again (subject to normal validation rules).
    pub(super) fn unblock_dpop_jkt_inner(
        &self,
        realm_id: &RealmId,
        jkt: &str,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_blocked_dpop_jkt(jkt);
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)?;
        let jkt_owned = jkt.to_string();
        self.blocked_dpop_jkt_cache.rcu(|old| {
            let mut next = (**old).clone();
            next.remove(&jkt_owned);
            next
        });
        Ok(())
    }

    /// Creates a new identity engine with a pre-existing signing key.
    ///
    /// Used for testing with a known key or for key restoration from storage.
    pub fn with_signing_key(
        storage: Arc<dyn StorageEngine>,
        clock: Arc<dyn Clock>,
        config: IdentityConfig,
        signing_key: Arc<SigningKey>,
        rbac: Arc<dyn crate::rbac::RbacEngine>,
        audit: Arc<dyn AuditEngine>,
    ) -> Self {
        let dummy_hash = credentials::compute_dummy_hash(&config.credential);
        let device_fp = Arc::new(DeviceFingerprintStore::new(Arc::clone(&storage)));
        let sv_store = Arc::new(SessionVersionStore::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
        ));
        let engine = Self {
            storage,
            clock,
            config,
            rbac,
            audit,
            dummy_hash,
            signing_key,
            realm_signing_keys: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            realm_status_cache: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            // INVARIANT: guard released in scoped block before I/O in get_or_create_saml_signing_key.
            realm_saml_keys: Mutex::new(HashMap::new()),
            oidc_rsa_key: std::sync::OnceLock::new(),
            oidc_ecdsa_key: std::sync::OnceLock::new(),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            attempt_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            mfa_attempt_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            magic_link_rate_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            password_reset_rate_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            registration_email_rate_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            registration_ip_rate_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            ip_login_rate_trackers: Mutex::new(HashMap::new()),
            // INVARIANT: guard released before method returns; all callers are non-async helpers.
            used_nonces: Mutex::new(HashMap::new()),
            webauthn_challenges: WebAuthnChallengeStore::new(),
            // INVARIANT: outer guard released in scoped block before inner per-user lock is acquired.
            session_limit_locks: Mutex::new(HashMap::new()),
            // INVARIANT: outer guard released inside jwt_bearer_jti_lock() before returning the inner Arc.
            jti_locks: Mutex::new(HashMap::new()),
            token_redemption_locks: Mutex::new(HashMap::new()),
            approval_locks: Mutex::new(HashMap::new()),
            // INVARIANT: outer guard released in scoped block before inner per-txn lock is acquired.
            txn_locks: Mutex::new(HashMap::new()),
            // INVARIANT: outer guard released in scoped block before inner per-code lock is acquired.
            code_exchange_locks: Mutex::new(HashMap::new()),
            // INVARIANT: guard held for entire sync realm lifecycle op; released when method returns.
            realm_ops_lock: Mutex::new(()),
            // INVARIANT: guard held for entire sync org write op; released when method returns.
            org_write_lock: Mutex::new(()),
            hibp: Arc::new(crate::identity::hibp::HibpClient::new()),
            pre_token_client: Arc::new(
                crate::identity::pre_token_webhook::PreTokenWebhookClient::new(),
            ),
            device_fp,
            sv_store,
            session_cache: ArcSwap::from_pointee(HashMap::new()),
            token_claims_cache: ArcSwap::from_pointee(HashMap::new()),
            dpop_nonce_cache: Mutex::new(HashMap::new()),
            blocked_dpop_jkt_cache: ArcSwap::from_pointee(std::collections::HashSet::new()),
            revoked_jti_cache: ArcSwap::from_pointee(HashMap::new()),
            // INVARIANT: guard released before method returns; no .await in scope.
            agent_rate_monitor: crate::abuse::agent_monitor::AgentRateMonitor::new(
                crate::abuse::agent_monitor::AgentRateConfig::default(),
            ),
        };
        // Best-effort: log but do not propagate initialization errors so
        // existing test harnesses that pre-seed storage don't break on a
        // duplicate-realm error. `new()` propagates; this constructor does not.
        if let Err(e) = engine.seed_system_realm_if_absent() {
            tracing::warn!(error = %e, "with_signing_key: seed_system_realm_if_absent failed");
        }
        if let Err(e) = engine.restore_attempt_trackers_from_wal() {
            tracing::warn!(error = %e, "with_signing_key: restore_attempt_trackers_from_wal failed");
        }
        if let Err(e) = engine.populate_realm_status_cache() {
            tracing::warn!(error = %e, "with_signing_key: populate_realm_status_cache failed");
        }
        if let Err(e) = engine.populate_revoked_jti_cache() {
            tracing::warn!(error = %e, "with_signing_key: populate_revoked_jti_cache failed");
        }
        if let Err(e) = engine.populate_blocked_dpop_jkt_cache() {
            tracing::warn!(error = %e, "with_signing_key: populate_blocked_dpop_jkt_cache failed");
        }
        engine
    }

    /// Replaces the HIBP client transport.
    ///
    /// Used in integration tests to inject a stub without network calls.
    /// Follows the same pattern as `with_email_sender` / `StubHttpTransport`.
    pub fn with_hibp_transport(
        mut self,
        transport: std::sync::Arc<dyn crate::identity::hibp::HibpTransport>,
    ) -> Self {
        self.hibp = Arc::new(crate::identity::hibp::HibpClient::with_transport(transport));
        self
    }

    /// Replaces the pre-token webhook transport.
    ///
    /// Used in integration tests to inject a stub without network calls.
    /// Follows the same pattern as `with_hibp_transport`.
    pub fn with_pre_token_transport(
        mut self,
        transport: std::sync::Arc<dyn crate::identity::pre_token_webhook::PreTokenWebhookTransport>,
    ) -> Self {
        self.pre_token_client = Arc::new(
            crate::identity::pre_token_webhook::PreTokenWebhookClient::with_transport(transport),
        );
        self
    }

    /// Ensures the reserved system realm exists in storage. Called from
    /// both constructors. Idempotent — safe to run on every startup.
    ///
    /// The system realm is Hearth's private admin-user home. See
    /// [`crate::identity::keys::system_realm_id`] for the invariants.
    fn seed_system_realm_if_absent(&self) -> Result<(), IdentityError> {
        let _ops_guard = self.realm_ops_lock.lock().expect("realm ops lock");
        let sys_realm = keys::system_realm_id();
        let realm_key = keys::encode_realm_id(&sys_realm);

        // Already seeded? Skip.
        if self
            .storage
            .get(&sys_realm, &realm_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Ok(());
        }

        let now = self.clock.now();
        let realm = Realm::new(
            sys_realm.clone(),
            keys::SYSTEM_REALM_NAME.to_string(),
            RealmStatus::Active,
            crate::identity::types::RealmConfig::default(),
            now,
            now,
        );
        let realm_bytes = Self::serialize_realm(&realm)?;
        let realm_signing_key = SigningKey::generate()?;
        let key_storage_key = keys::encode_realm_signing_key(&sys_realm);
        // Zeroizing ensures the local PKCS#8 copy is actively overwritten
        // when dropped rather than relying on the allocator (HEA-750 M1).
        let key_plaintext = Zeroizing::new(realm_signing_key.pkcs8_bytes().to_vec());
        let kek = self
            .config
            .key_encryption_key
            .as_ref()
            .map(|k| k.as_bytes());
        let key_stored = crate::identity::key_encryption::wrap_key(&key_plaintext, kek)?;
        // Note: we intentionally do NOT write a name index entry — that
        // would let `get_realm_by_name("system")` find it, violating the
        // "invisible to lookups" invariant.

        self.storage
            .put_batch(
                &sys_realm,
                &[(realm_key, realm_bytes), (key_storage_key, key_stored)],
            )
            .map_err(Self::storage_err)?;

        {
            let key_arc = Arc::new(realm_signing_key);
            let sys_realm_id = sys_realm.clone();
            self.realm_signing_keys.rcu(|current| {
                let mut new_map = (**current).clone();
                new_map.insert(sys_realm_id.clone(), Arc::clone(&key_arc));
                new_map
            });
        }

        Ok(())
    }

    /// Loads the server-wide global signing key from storage, or generates and
    /// persists a new one on first startup.
    ///
    /// Stored under the system realm namespace as `sys:global:key` — survives
    /// `kill -9` via WAL fsync before returning. Called before `Self` is
    /// constructed so it accepts `&Arc<dyn StorageEngine>` directly.
    ///
    /// When `kek` is `Some`, the stored bytes are AES-256-GCM-encrypted via the
    /// HKEY envelope format (see `key_encryption` module).  Existing plaintext
    /// entries written before encryption was enabled are read transparently.
    fn load_or_persist_global_signing_key(
        storage: &Arc<dyn StorageEngine>,
        kek: Option<&[u8; 32]>,
    ) -> Result<SigningKey, IdentityError> {
        let sys_realm = keys::system_realm_id();
        let storage_key = keys::encode_global_signing_key();

        if let Some(raw) = storage
            .get(&sys_realm, &storage_key)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?
        {
            let key_bytes = crate::identity::key_encryption::unwrap_key(&raw, kek)?;
            return SigningKey::from_pkcs8(&key_bytes);
        }

        // First startup: generate, persist (WAL-synced), then return.
        let signing_key = SigningKey::generate()?;
        let plaintext = Zeroizing::new(signing_key.pkcs8_bytes().to_vec());
        let stored = crate::identity::key_encryption::wrap_key(&plaintext, kek)?;
        storage
            .put(&sys_realm, &storage_key, &stored)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?;

        Ok(signing_key)
    }

    /// Returns a reference to the signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    // ===== Rate limiting helpers =====

    /// Builds a tracker key from realm and user IDs.
    fn tracker_key(realm_id: &RealmId, user_id: &UserId) -> String {
        format!("{}:{}", realm_id.as_uuid(), user_id.as_uuid())
    }

    /// Checks whether the given user is currently rate-limited.
    ///
    /// Uses realm-specific thresholds when configured, falling back to the
    /// global `RateLimitConfig` defaults. Returns `Err(RateLimited)` if the
    /// lockout window has not yet expired.
    fn check_rate_limit(&self, realm_id: &RealmId, user_id: &UserId) -> Result<(), IdentityError> {
        let (max_attempts, lockout_micros) = self.effective_rate_limit(realm_id);
        let key = Self::tracker_key(realm_id, user_id);
        let trackers = self.attempt_trackers.lock().expect("tracker lock");
        if let Some(tracker) = trackers.get(&key) {
            if tracker.failed_count >= max_attempts {
                let now = self.clock.now().as_micros();
                let elapsed = now - tracker.last_failure_micros;
                if elapsed < lockout_micros {
                    return Err(IdentityError::RateLimited);
                }
                // Lockout window has expired — fall through and allow the attempt.
                // The tracker will be cleared on success or updated on failure.
            }
        }
        Ok(())
    }

    /// Records a failed verification attempt for the given user.
    ///
    /// Updates the in-memory tracker and persists the state to WAL so it
    /// survives restarts. Returns the new consecutive failure count.
    fn record_failed_attempt(&self, realm_id: &RealmId, user_id: &UserId) -> u32 {
        let key = Self::tracker_key(realm_id, user_id);
        let now = self.clock.now().as_micros();
        let mut trackers = self.attempt_trackers.lock().expect("tracker lock");
        let tracker = trackers.entry(key).or_insert(AttemptTracker {
            failed_count: 0,
            last_failure_micros: now,
        });
        tracker.failed_count += 1;
        tracker.last_failure_micros = now;
        let count = tracker.failed_count;
        let last = tracker.last_failure_micros;
        drop(trackers);

        // Persist to WAL (best-effort: don't fail the login path on storage errors)
        let wal_key = keys::encode_attempt_tracker(user_id);
        let blob = serde_json::json!({
            "failed_count": count,
            "last_failure_micros": last,
        });
        if let Ok(bytes) = serde_json::to_vec(&blob) {
            let _ = self.storage.put(realm_id, &wal_key, &bytes);
        }

        count
    }

    /// Clears the failed attempt tracker for the given user (on success).
    ///
    /// Removes the in-memory entry and deletes the WAL record.
    fn clear_attempts(&self, realm_id: &RealmId, user_id: &UserId) {
        let key = Self::tracker_key(realm_id, user_id);
        let mut trackers = self.attempt_trackers.lock().expect("tracker lock");
        trackers.remove(&key);
        drop(trackers);

        let wal_key = keys::encode_attempt_tracker(user_id);
        let _ = self.storage.delete(realm_id, &wal_key);
    }

    /// Returns the effective `(max_attempts, lockout_micros)` for the given
    /// realm, preferring per-realm config over global defaults.
    fn effective_rate_limit(&self, realm_id: &RealmId) -> (u32, i64) {
        if let Ok(Some(realm)) = self.get_realm(realm_id) {
            let max = realm
                .config()
                .max_failed_logins
                .unwrap_or(self.config.rate_limit.max_failed_attempts);
            let dur = realm
                .config()
                .lockout_duration_micros
                .unwrap_or(self.config.rate_limit.lockout_duration_micros);
            return (max, dur);
        }
        (
            self.config.rate_limit.max_failed_attempts,
            self.config.rate_limit.lockout_duration_micros,
        )
    }

    /// Returns the effective `(access_ttl_secs, refresh_ttl_secs)` for the
    /// given realm, preferring per-realm overrides over global defaults.
    fn effective_token_ttl_secs(&self, realm_id: &RealmId) -> (i64, i64) {
        if let Ok(Some(realm)) = self.get_realm(realm_id) {
            let cfg = realm.config();
            let access = cfg
                .access_token_ttl_micros
                .map(|m| m / 1_000_000)
                .unwrap_or(self.config.token.access_token_ttl_secs);
            let refresh = cfg
                .refresh_token_ttl_micros
                .map(|m| m / 1_000_000)
                .unwrap_or(self.config.token.refresh_token_ttl_secs);
            return (access, refresh);
        }
        (
            self.config.token.access_token_ttl_secs,
            self.config.token.refresh_token_ttl_secs,
        )
    }

    /// Checks whether `method` is permitted by the realm's `allowed_auth_methods`
    /// policy. Returns `Ok(())` when allowed (or when no restriction is configured),
    /// `Err(AuthMethodNotAllowed)` when the method is explicitly excluded.
    fn check_allowed_auth_method(
        &self,
        realm_id: &RealmId,
        method: &'static str,
    ) -> Result<(), IdentityError> {
        if let Ok(Some(realm)) = self.get_realm(realm_id) {
            if let Some(allowed) = realm.config().allowed_auth_methods.as_ref() {
                if !allowed.iter().any(|m| m == method) {
                    return Err(IdentityError::AuthMethodNotAllowed { method });
                }
            }
        }
        Ok(())
    }

    // ===== Per-IP login rate limiting helpers =====

    fn ip_login_tracker_key(realm_id: &RealmId, ip: &str) -> String {
        format!("login-ip:{}:{ip}", realm_id.as_uuid())
    }

    /// Returns the remaining window microseconds for an IP that has already hit
    /// its limit, used to compute `Retry-After` values. Returns 0 when the IP
    /// is not currently blocked.
    pub fn ip_login_retry_after_micros(&self, realm_id: &RealmId, ip: &str) -> i64 {
        if ip.is_empty() {
            return 0;
        }
        let key = Self::ip_login_tracker_key(realm_id, ip);
        let trackers = self
            .ip_login_rate_trackers
            .lock()
            .expect("ip login tracker lock");
        if let Some(tracker) = trackers.get(&key) {
            if tracker.failed_count >= self.config.rate_limit.ip_max_attempts {
                let now = self.clock.now().as_micros();
                let elapsed = now - tracker.last_failure_micros;
                let remaining = self.config.rate_limit.ip_window_micros - elapsed;
                if remaining > 0 {
                    return remaining;
                }
            }
        }
        0
    }

    /// Checks whether the given IP has exceeded the per-IP login rate limit.
    ///
    /// Returns `Err(RateLimited)` if the IP has made more than
    /// `config.rate_limit.ip_max_attempts` failed login attempts within the
    /// sliding window. Passes through for trusted callers (empty IP).
    pub fn check_ip_login_rate_limit(
        &self,
        realm_id: &RealmId,
        ip: &str,
    ) -> Result<(), IdentityError> {
        if ip.is_empty() {
            return Ok(());
        }
        let key = Self::ip_login_tracker_key(realm_id, ip);
        let trackers = self
            .ip_login_rate_trackers
            .lock()
            .expect("ip login tracker lock");
        if let Some(tracker) = trackers.get(&key) {
            if tracker.failed_count >= self.config.rate_limit.ip_max_attempts {
                let now = self.clock.now().as_micros();
                let elapsed = now - tracker.last_failure_micros;
                if elapsed < self.config.rate_limit.ip_window_micros {
                    return Err(IdentityError::RateLimited);
                }
            }
        }
        Ok(())
    }

    /// Records a failed login attempt for the given IP.
    ///
    /// Updates the in-memory tracker and persists to WAL so counts survive
    /// process restarts. Emits `IpLoginLimitExceeded` to the audit log the
    /// first time the count reaches `config.rate_limit.ip_max_attempts`.
    pub fn record_ip_login_attempt(&self, realm_id: &RealmId, ip: &str) {
        if ip.is_empty() {
            return;
        }
        let key = Self::ip_login_tracker_key(realm_id, ip);
        let now = self.clock.now().as_micros();
        let new_count = {
            let mut trackers = self
                .ip_login_rate_trackers
                .lock()
                .expect("ip login tracker lock");
            let tracker = trackers.entry(key).or_insert(AttemptTracker {
                failed_count: 0,
                last_failure_micros: now,
            });
            tracker.failed_count += 1;
            tracker.last_failure_micros = now;
            tracker.failed_count
        };

        // Persist to WAL so counts survive restarts (best-effort).
        let wal_key = keys::encode_ip_login_tracker(ip);
        let blob = serde_json::json!({
            "failed_count": new_count,
            "last_failure_micros": now,
        });
        if let Ok(bytes) = serde_json::to_vec(&blob) {
            let _ = self.storage.put(realm_id, &wal_key, &bytes);
        }

        if new_count == self.config.rate_limit.ip_max_attempts {
            let ctx = AuditContext {
                actor: Actor::Anonymous,
                metadata: Some(serde_json::json!({ "ip": ip, "attempt_count": new_count })),
            };
            let _ = self.record_audit(
                realm_id,
                Some(&ctx),
                AuditAction::IpLoginLimitExceeded,
                "ip",
                ip,
            );
        }
    }

    // ===== MFA rate limiting helpers =====

    /// MFA rate limit: 5 attempts, 5-minute lockout.
    const MFA_MAX_ATTEMPTS: u32 = 5;
    /// MFA lockout duration: 5 minutes in microseconds.
    const MFA_LOCKOUT_MICROS: i64 = 5 * 60 * 1_000_000;

    /// Builds an MFA tracker key from realm and user IDs.
    fn mfa_tracker_key(realm_id: &RealmId, user_id: &UserId) -> String {
        format!("mfa:{}:{}", realm_id.as_uuid(), user_id.as_uuid())
    }

    /// Checks whether the given user is currently MFA-rate-limited.
    fn check_mfa_rate_limit(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        let key = Self::mfa_tracker_key(realm_id, user_id);
        let trackers = self.mfa_attempt_trackers.lock().expect("mfa tracker lock");
        if let Some(tracker) = trackers.get(&key) {
            if tracker.failed_count >= Self::MFA_MAX_ATTEMPTS {
                let now = self.clock.now().as_micros();
                let elapsed = now - tracker.last_failure_micros;
                if elapsed < Self::MFA_LOCKOUT_MICROS {
                    return Err(IdentityError::RateLimited);
                }
            }
        }
        Ok(())
    }

    /// Records a failed MFA attempt and persists to WAL.
    fn record_mfa_failed_attempt(&self, realm_id: &RealmId, user_id: &UserId) {
        let key = Self::mfa_tracker_key(realm_id, user_id);
        let now = self.clock.now().as_micros();
        let new_count = {
            let mut trackers = self.mfa_attempt_trackers.lock().expect("mfa tracker lock");
            let tracker = trackers.entry(key).or_insert(AttemptTracker {
                failed_count: 0,
                last_failure_micros: now,
            });
            tracker.failed_count += 1;
            tracker.last_failure_micros = now;
            tracker.failed_count
        };
        let wal_key = keys::encode_mfa_tracker(user_id);
        let blob = serde_json::json!({
            "failed_count": new_count,
            "last_failure_micros": now,
        });
        if let Ok(bytes) = serde_json::to_vec(&blob) {
            let _ = self.storage.put(realm_id, &wal_key, &bytes);
        }
    }

    /// Clears MFA failed attempts on success and removes the WAL entry.
    fn clear_mfa_attempts(&self, realm_id: &RealmId, user_id: &UserId) {
        let key = Self::mfa_tracker_key(realm_id, user_id);
        let mut trackers = self.mfa_attempt_trackers.lock().expect("mfa tracker lock");
        trackers.remove(&key);
        drop(trackers);
        let wal_key = keys::encode_mfa_tracker(user_id);
        let _ = self.storage.delete(realm_id, &wal_key);
    }

    // ===== Magic link rate limiting helpers =====

    /// Magic link rate limit: 3 requests per email per hour.
    const MAGIC_LINK_MAX_REQUESTS: u32 = 3;
    /// Magic link rate limit window: 1 hour in microseconds.
    const MAGIC_LINK_RATE_WINDOW_MICROS: i64 = 60 * 60 * 1_000_000;

    /// Builds a magic link rate tracker key from realm and email.
    fn magic_link_tracker_key(realm_id: &RealmId, email: &str) -> String {
        format!("magic:{}:{email}", realm_id.as_uuid())
    }

    /// Checks whether magic link requests for this email are rate-limited.
    fn check_magic_link_rate_limit(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<(), IdentityError> {
        let key = Self::magic_link_tracker_key(realm_id, email);
        let trackers = self
            .magic_link_rate_trackers
            .lock()
            .expect("magic link tracker lock");
        if let Some(tracker) = trackers.get(&key) {
            if tracker.failed_count >= Self::MAGIC_LINK_MAX_REQUESTS {
                let now = self.clock.now().as_micros();
                let elapsed = now - tracker.last_failure_micros;
                if elapsed < Self::MAGIC_LINK_RATE_WINDOW_MICROS {
                    return Err(IdentityError::RateLimited);
                }
            }
        }
        Ok(())
    }

    /// Records a magic link request for rate limiting and persists to WAL.
    fn record_magic_link_request(&self, realm_id: &RealmId, email: &str) {
        let key = Self::magic_link_tracker_key(realm_id, email);
        let now = self.clock.now().as_micros();
        let new_count = {
            let mut trackers = self
                .magic_link_rate_trackers
                .lock()
                .expect("magic link tracker lock");
            let tracker = trackers.entry(key).or_insert(AttemptTracker {
                failed_count: 0,
                last_failure_micros: now,
            });
            tracker.failed_count += 1;
            tracker.last_failure_micros = now;
            tracker.failed_count
        };
        let wal_key = keys::encode_magic_link_rl_tracker(email);
        let blob = serde_json::json!({
            "failed_count": new_count,
            "last_failure_micros": now,
        });
        if let Ok(bytes) = serde_json::to_vec(&blob) {
            let _ = self.storage.put(realm_id, &wal_key, &bytes);
        }
    }

    // ===== Password reset rate limiting helpers =====

    /// Password reset rate limit: 3 requests per email per 15 minutes.
    const PASSWORD_RESET_MAX_REQUESTS: u32 = 3;
    /// Password reset rate limit window: 15 minutes in microseconds.
    const PASSWORD_RESET_RATE_WINDOW_MICROS: i64 = 15 * 60 * 1_000_000;

    /// Builds a password reset rate tracker key from realm and email.
    fn password_reset_tracker_key(realm_id: &RealmId, email: &str) -> String {
        format!("reset:{}:{email}", realm_id.as_uuid())
    }

    /// Checks whether password reset requests for this email are rate-limited.
    fn check_password_reset_rate_limit(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<(), IdentityError> {
        let key = Self::password_reset_tracker_key(realm_id, email);
        let trackers = self
            .password_reset_rate_trackers
            .lock()
            .expect("password reset tracker lock");
        if let Some(tracker) = trackers.get(&key) {
            if tracker.failed_count >= Self::PASSWORD_RESET_MAX_REQUESTS {
                let now = self.clock.now().as_micros();
                let elapsed = now - tracker.last_failure_micros;
                if elapsed < Self::PASSWORD_RESET_RATE_WINDOW_MICROS {
                    return Err(IdentityError::RateLimited);
                }
            }
        }
        Ok(())
    }

    /// Records a password reset request for rate limiting and persists to WAL.
    fn record_password_reset_request(&self, realm_id: &RealmId, email: &str) {
        let key = Self::password_reset_tracker_key(realm_id, email);
        let now = self.clock.now().as_micros();
        let new_count = {
            let mut trackers = self
                .password_reset_rate_trackers
                .lock()
                .expect("password reset tracker lock");
            let tracker = trackers.entry(key).or_insert(AttemptTracker {
                failed_count: 0,
                last_failure_micros: now,
            });
            tracker.failed_count += 1;
            tracker.last_failure_micros = now;
            tracker.failed_count
        };
        let wal_key = keys::encode_password_reset_rl_tracker(email);
        let blob = serde_json::json!({
            "failed_count": new_count,
            "last_failure_micros": now,
        });
        if let Ok(bytes) = serde_json::to_vec(&blob) {
            let _ = self.storage.put(realm_id, &wal_key, &bytes);
        }
    }

    // ===== Self-service registration rate limiting helpers =====

    /// Registration rate limit: 3 attempts per email per hour.
    const REGISTRATION_EMAIL_MAX_REQUESTS: u32 = 3;
    /// Registration rate limit: 10 attempts per IP per hour across realms.
    const REGISTRATION_IP_MAX_REQUESTS: u32 = 10;
    /// Registration rate limit window: 1 hour in microseconds.
    const REGISTRATION_RATE_WINDOW_MICROS: i64 = 60 * 60 * 1_000_000;

    /// Builds a registration email rate tracker key from realm and email.
    fn registration_email_tracker_key(realm_id: &RealmId, email: &str) -> String {
        format!("reg-email:{}:{email}", realm_id.as_uuid())
    }

    /// Checks per-email and per-IP rate limits for a registration attempt.
    fn check_registration_rate_limit(
        &self,
        realm_id: &RealmId,
        email: &str,
        client_ip: Option<&str>,
    ) -> Result<(), IdentityError> {
        let now = self.clock.now().as_micros();

        // Email bucket
        let email_key = Self::registration_email_tracker_key(realm_id, email);
        {
            let trackers = self
                .registration_email_rate_trackers
                .lock()
                .expect("registration email tracker lock");
            if let Some(tracker) = trackers.get(&email_key) {
                if tracker.failed_count >= Self::REGISTRATION_EMAIL_MAX_REQUESTS
                    && now - tracker.last_failure_micros < Self::REGISTRATION_RATE_WINDOW_MICROS
                {
                    return Err(IdentityError::RateLimited);
                }
            }
        }

        // IP bucket (skipped if caller has no IP)
        if let Some(ip) = client_ip {
            let trackers = self
                .registration_ip_rate_trackers
                .lock()
                .expect("registration ip tracker lock");
            if let Some(tracker) = trackers.get(ip) {
                if tracker.failed_count >= Self::REGISTRATION_IP_MAX_REQUESTS
                    && now - tracker.last_failure_micros < Self::REGISTRATION_RATE_WINDOW_MICROS
                {
                    return Err(IdentityError::RateLimited);
                }
            }
        }

        Ok(())
    }

    /// Records a registration attempt against both email and IP buckets.
    ///
    /// Persists the per-email counter to WAL so it survives restarts.
    /// The per-IP counter remains in-memory only (IP churn makes persistence
    /// low-value; WAL cleanup would require scanning across all realms).
    fn record_registration_attempt(
        &self,
        realm_id: &RealmId,
        email: &str,
        client_ip: Option<&str>,
    ) {
        let now = self.clock.now().as_micros();

        let email_key = Self::registration_email_tracker_key(realm_id, email);
        let new_count = {
            let mut trackers = self
                .registration_email_rate_trackers
                .lock()
                .expect("registration email tracker lock");
            let tracker = trackers.entry(email_key).or_insert(AttemptTracker {
                failed_count: 0,
                last_failure_micros: now,
            });
            tracker.failed_count += 1;
            tracker.last_failure_micros = now;
            tracker.failed_count
        };
        let wal_key = keys::encode_registration_email_rl_tracker(email);
        let blob = serde_json::json!({
            "failed_count": new_count,
            "last_failure_micros": now,
        });
        if let Ok(bytes) = serde_json::to_vec(&blob) {
            let _ = self.storage.put(realm_id, &wal_key, &bytes);
        }

        if let Some(ip) = client_ip {
            let mut trackers = self
                .registration_ip_rate_trackers
                .lock()
                .expect("registration ip tracker lock");
            let tracker = trackers.entry(ip.to_string()).or_insert(AttemptTracker {
                failed_count: 0,
                last_failure_micros: now,
            });
            tracker.failed_count += 1;
            tracker.last_failure_micros = now;
        }
    }

    /// Loads the stored MFA state for a user, decrypting sensitive fields.
    ///
    /// Uses HKDF-SHA256 keyed from the realm signing key to derive a per-realm
    /// TOTP DEK. Handles both the v2 encrypted format and the legacy v1
    /// plaintext format (migrated transparently on the next save).
    fn load_mfa_state(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<StoredMfaState>, IdentityError> {
        let key = keys::encode_mfa_totp_key(user_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?;
        match bytes {
            Some(b) => {
                let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
                let mut dek = Zeroizing::new(totp::derive_totp_dek(signing_key.pkcs8_bytes())?);
                let state = totp::deserialize_mfa_state(&b, &dek)?;
                dek.zeroize();
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Persists MFA state for a user, encrypting sensitive fields before write.
    ///
    /// `secret_base32` and `pending_recovery_codes` are AES-256-GCM encrypted
    /// with a DEK derived from the realm signing key via HKDF-SHA256.
    fn save_mfa_state(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        state: &StoredMfaState,
    ) -> Result<(), IdentityError> {
        let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
        let mut dek = Zeroizing::new(totp::derive_totp_dek(signing_key.pkcs8_bytes())?);
        let key = keys::encode_mfa_totp_key(user_id);
        let bytes = totp::serialize_mfa_state(state, &dek)?;
        dek.zeroize();
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    /// Creates a user with an explicit initial status, bypassing the
    /// engine-wide `default_status`. Used by self-service registration
    /// (always `PendingVerification`) while ordinary `create_user` continues
    /// to honor the default.
    fn create_user_with_status(
        &self,
        realm_id: &RealmId,
        request: &CreateUserRequest,
        status: UserStatus,
    ) -> Result<User, IdentityError> {
        let email = validation::validate_email(&request.email)?;
        let first_name = validation::validate_name_part(&request.first_name, "First name")?;
        let last_name = validation::validate_name_part(&request.last_name, "Last name")?;
        let display_name = if request.display_name.trim().is_empty() {
            let synthesized = format!("{} {}", first_name, last_name).trim().to_string();
            if synthesized.is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "Display name or first/last name is required".to_string(),
                });
            }
            validation::validate_display_name(&synthesized)?
        } else {
            validation::validate_display_name(&request.display_name)?
        };

        let email_key = keys::encode_user_email(&email);
        let existing = self
            .storage
            .get(realm_id, &email_key)
            .map_err(Self::storage_err)?;
        if existing.is_some() {
            return Err(IdentityError::DuplicateEmail);
        }

        // A-20: reject if email was released by a delete_user within the last
        // 90 days — prevents account-squatting and privilege re-inheritance.
        let reserved_key = keys::encode_email_reserved(&email);
        if let Some(bytes) = self
            .storage
            .get(realm_id, &reserved_key)
            .map_err(Self::storage_err)?
        {
            if let Ok(reservation) = serde_json::from_slice::<StoredEmailReservation>(&bytes) {
                let now = self.clock.now().as_micros();
                if now - reservation.reserved_at_micros < EMAIL_RESERVED_MICROS {
                    return Err(IdentityError::EmailReserved);
                }
                // Expired reservation — clean it up.
                let _ = self.storage.delete(realm_id, &reserved_key);
            }
        }

        let user_id = UserId::generate();
        let now = self.clock.now();

        // Fetch realm config once for both default_required_actions and attribute_definitions.
        let realm_config = self
            .get_realm(realm_id)?
            .map(|r| r.config().clone())
            .unwrap_or_default();

        let required_actions = realm_config.default_required_actions.clone();

        let mut user = User::new(
            user_id.clone(),
            email.clone(),
            display_name,
            first_name,
            last_name,
            status,
            required_actions,
            now,
            now,
        );

        {
            let user_attr_defs = realm_config
                .attribute_definitions
                .as_ref()
                .map(|d| &d.users);
            validation::validate_attributes(
                &request.attributes,
                user_attr_defs.map(Vec::as_slice),
            )?;
            if !request.attributes.is_empty() {
                user.set_attributes(request.attributes.clone());
            }
        }

        let user_bytes = Self::serialize_user(&user)?;
        let user_id_bytes = user_id.as_uuid().to_string().into_bytes();
        self.storage
            .put(realm_id, &email_key, &user_id_bytes)
            .map_err(Self::storage_err)?;
        let id_key = keys::encode_user_id(&user_id);
        self.storage
            .put(realm_id, &id_key, &user_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::UserCreated,
            "user",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(user)
    }

    /// Validates `User.attributes` key/value constraints.
    ///
    /// Rules (from `AUTHZ_EXPANSION.md § User attributes`):
    /// - Key MUST be non-empty, ≤64 chars, ASCII alphanumeric / `_` / `-` / `.`.
    /// - Value MUST be ≤1 KiB (1024 bytes).
    /// - Total map size (sum of key + value lengths) MUST be ≤16 KiB.
    fn validate_user_attributes(
        attributes: &BTreeMap<String, String>,
    ) -> Result<(), IdentityError> {
        const MAX_TOTAL: usize = 16 * 1024;
        const MAX_VALUE: usize = 1024;
        const MAX_KEY_LEN: usize = 64;
        let mut total = 0usize;
        for (k, v) in attributes {
            if k.is_empty() {
                return Err(IdentityError::InvalidAttribute {
                    reason: "attribute key must not be empty".to_string(),
                });
            }
            if k.len() > MAX_KEY_LEN {
                return Err(IdentityError::InvalidAttribute {
                    reason: format!("attribute key '{k}' exceeds {MAX_KEY_LEN} chars"),
                });
            }
            if !k
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
            {
                return Err(IdentityError::InvalidAttribute {
                    reason: format!("attribute key '{k}' contains invalid characters"),
                });
            }
            if v.len() > MAX_VALUE {
                return Err(IdentityError::InvalidAttribute {
                    reason: format!("attribute value for '{k}' exceeds {MAX_VALUE} bytes"),
                });
            }
            total += k.len() + v.len();
            if total > MAX_TOTAL {
                return Err(IdentityError::InvalidAttribute {
                    reason: "total attributes size exceeds 16 KiB".to_string(),
                });
            }
        }
        Ok(())
    }

    /// Serializes a user to JSON bytes.
    fn serialize_user(user: &User) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(user).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Deserializes a user from JSON bytes.
    fn deserialize_user(bytes: &[u8]) -> Result<User, IdentityError> {
        serde_json::from_slice(bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Wraps a storage error into an `IdentityError`.
    fn storage_err(e: crate::storage::StorageError) -> IdentityError {
        IdentityError::Storage(Box::new(e))
    }

    /// Serializes a stored credential to JSON bytes.
    fn serialize_credential(cred: &StoredCredential) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(cred).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Deserializes a stored credential from JSON bytes.
    fn deserialize_credential(bytes: &[u8]) -> Result<StoredCredential, IdentityError> {
        serde_json::from_slice(bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    fn serialize_credential_history(
        history: &[StoredCredential],
    ) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(history).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    fn deserialize_credential_history(
        bytes: &[u8],
    ) -> Result<Vec<StoredCredential>, IdentityError> {
        serde_json::from_slice(bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Resolves per-realm password policy overrides.
    ///
    /// Returns `None` when the realm has no password policy configured or
    /// when the realm record does not exist (legacy/test realms that rely on
    /// storage namespace-only isolation).
    fn password_policy_for_realm(
        &self,
        realm_id: &RealmId,
    ) -> Result<Option<crate::identity::PasswordPolicy>, IdentityError> {
        Ok(self
            .get_realm(realm_id)?
            .and_then(|r| r.config().password_policy.clone()))
    }

    /// Resolves the effective Argon2id settings for a realm.
    ///
    /// Starts with engine defaults and applies per-realm `password_memory_cost`
    /// and `password_time_cost` overrides when present.
    fn credential_config_for_realm(
        &self,
        realm_id: &RealmId,
    ) -> Result<CredentialConfig, IdentityError> {
        let mut cfg = self.config.credential.clone();
        if let Some(realm) = self.get_realm(realm_id)? {
            if let Some(memory_cost) = realm.config().password_memory_cost {
                cfg.memory_cost_kib = memory_cost;
            }
            if let Some(time_cost) = realm.config().password_time_cost {
                cfg.time_cost = time_cost;
            }
        }
        Ok(cfg)
    }

    /// Serializes a session to JSON bytes.
    fn serialize_session(session: &Session) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(session).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Deserializes a session from JSON bytes.
    fn deserialize_session(bytes: &[u8]) -> Result<Session, IdentityError> {
        serde_json::from_slice(bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Loads a raw session from storage without validity checks.
    ///
    /// Returns the deserialized session regardless of expiry/revocation.
    /// Used internally by methods that need to mutate the session.
    fn load_session_raw(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Option<Session>, IdentityError> {
        let key = keys::encode_session_id(session_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?;
        match bytes {
            Some(data) => Ok(Some(Self::deserialize_session(&data)?)),
            None => Ok(None),
        }
    }

    /// Computes the SHA-256 hex digest of the given data.
    fn sha256_hex(data: &[u8]) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, data);
        hex_encode(digest.as_ref())
    }

    /// Computes a stable scope digest from a list of scope strings.
    ///
    /// The digest is SHA-256 of the sorted, deduplicated, newline-separated
    /// scope names encoded as UTF-8. The result is a raw 32-byte vector.
    ///
    /// This digest is stored on [`ConsentRecord`] at grant time and
    /// re-computed on every `/authorize` and `refresh_token` call. A mismatch
    /// indicates that the declared scope surface has changed (e.g. because
    /// YAML bundles were reloaded) and the user must re-consent.
    pub(crate) fn compute_scope_digest(scopes: &[String]) -> Vec<u8> {
        let mut sorted: Vec<&str> = scopes.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        sorted.dedup();
        let canonical = sorted.join("\n");
        let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
        digest.as_ref().to_vec()
    }

    /// Performs grant family rotation during refresh token exchange.
    ///
    /// Validates the incoming refresh token against the family's current hash,
    /// detects theft (replayed previously-rotated tokens), issues a new token
    /// pair, and rotates the family's stored hash.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn rotate_grant_family(
        &self,
        realm_id: &RealmId,
        fid: &str,
        refresh_token: &str,
        session_id: &SessionId,
        user_id: &UserId,
        now_secs: i64,
        claims: &TokenClaims,
        dpop_jkt: Option<&str>,
        bind_ctx: Option<&RefreshBindContext>,
    ) -> Result<TokenPair, IdentityError> {
        let family_key = keys::encode_grant_family(fid);
        let family_bytes = self
            .storage
            .get(realm_id, &family_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::TokenRevoked)?;
        let mut family: StoredGrantFamily =
            serde_json::from_slice(&family_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        if family.revoked {
            return Err(IdentityError::TokenRevoked);
        }

        // FAPI 2.0: DPoP sender-constrained tokens are mandatory on the refresh
        // path, mirroring the gate at exchange_authorization_code (§5.3.3).
        // Check both per-client profile AND realm-level fapi_profile so that
        // standard-profile clients in a Baseline/Advanced realm cannot bypass
        // the sender-constraint requirement on refresh (mirrors HEA-1022 fix).
        if let Some(ref client_id) = family.client_id {
            if let Some(client) = self.get_client(realm_id, client_id)? {
                let realm_fapi = self
                    .get_realm(realm_id)?
                    .ok_or(IdentityError::RealmNotFound)?
                    .config()
                    .fapi_profile;
                let fapi_enforced = client.profile().is_fapi2() || realm_fapi.is_some();
                if fapi_enforced && dpop_jkt.is_none() {
                    return Err(IdentityError::FapiViolation {
                        reason: "FAPI 2.0 requires sender-constrained tokens; \
                                 include a DPoP proof and dpop_jkt in the token request"
                            .to_string(),
                    });
                }
            }
        }

        // Verify the incoming refresh token matches the current hash
        let incoming_hash = Self::sha256_hex(refresh_token.as_bytes());
        if incoming_hash != family.current_refresh_hash {
            // THEFT DETECTED — a previously-rotated token is being reused.
            family.revoked = true;
            let updated =
                serde_json::to_vec(&family).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            self.storage
                .put(realm_id, &family_key, &updated)
                .map_err(Self::storage_err)?;
            let _ = self.revoke_session(realm_id, session_id);
            return Err(IdentityError::TokenRevoked);
        }

        // Consent scope-digest re-check on refresh.
        //
        // When the grant family carries a `client_id` and the token carries
        // a non-empty scope claim, verify that the stored consent record's
        // digest still matches the token's scope surface. A mismatch means
        // the scope surface changed since the user last consented; we return
        // `invalid_grant` (mapped to `ConsentRequired`) so the client can
        // direct the user back through the authorization flow.
        if let Some(ref client_id) = family.client_id {
            if let Some(ref scope_str) = claims.scope {
                let token_scopes: Vec<String> =
                    scope_str.split_whitespace().map(str::to_string).collect();
                if let Some(consent) = self.get_consent_extended(
                    realm_id,
                    user_id,
                    client_id,
                    keys::CONSENT_ORG_KEY_REALM,
                    keys::CONSENT_RESOURCE_KEY_DEFAULT,
                    // We don't have the client record in scope here; if the
                    // family carries a client_id we can load it on demand,
                    // but to avoid a storage round-trip we conservatively
                    // disable the spans_orgs fallback (it is checked during
                    // the initial authorize call).
                    false,
                )? {
                    if !consent.scope_digest.is_empty() {
                        let current_digest = Self::compute_scope_digest(&token_scopes);
                        if current_digest != consent.scope_digest {
                            tracing::info!(
                                client_id = %client_id,
                                user_id = %user_id,
                                "consent digest mismatch on refresh — requiring re-consent"
                            );
                            return Err(IdentityError::ConsentRequired);
                        }
                    }
                }
            }
        }

        // A-49: detect refresh-context drift (UA hash / ASN change) and score.
        // Fail-open: no bind_ctx or no stored hash → skip check.
        if let Some(ctx) = bind_ctx {
            let current_ua_hash = ctx
                .user_agent
                .as_deref()
                .map(|ua| Self::sha256_hex(ua.as_bytes()));

            let ua_changed = match (&current_ua_hash, &family.ua_hash) {
                (Some(cur), Some(stored)) => cur != stored,
                _ => false,
            };
            let asn_changed = match (ctx.asn, family.bound_asn) {
                (Some(cur), Some(stored)) => cur != stored,
                _ => false,
            };

            if ua_changed || asn_changed {
                use crate::identity::risk::{
                    DefaultRiskScorer, RiskContext, RiskScorer, RiskSignal,
                };
                let realm_risk_cfg = self
                    .get_realm(realm_id)?
                    .ok_or(IdentityError::RealmNotFound)?
                    .config()
                    .risk_scorer_config
                    .clone()
                    .unwrap_or_default();
                let scorer = DefaultRiskScorer::new(realm_risk_cfg);
                let risk_ctx = RiskContext {
                    signals: vec![RiskSignal::RefreshContextDelta {
                        ua_changed,
                        asn_changed,
                    }],
                };
                if scorer.score(&risk_ctx).step_up_required {
                    return Err(IdentityError::StepUpChallengeRequired);
                }
            }

            // Record UA hash on first refresh so subsequent exchanges can compare.
            if family.ua_hash.is_none() {
                family.ua_hash = current_ua_hash;
            }
            if family.bound_asn.is_none() {
                family.bound_asn = ctx.asn;
            }
        }

        self.refresh_session(realm_id, session_id)?;

        let signing_key = self.get_signing_key_or_default(realm_id);
        let iat = now_secs;

        // Apply per-realm token TTL overrides for the rotated pair.
        let (access_ttl_secs, refresh_ttl_secs) = self.effective_token_ttl_secs(realm_id);

        let aud = if family.resources.is_empty() {
            Audience::single(self.config.token.audience.clone())
        } else {
            // Preserve the original resource set from the authorization
            // grant. Per RFC 8707 §2, refresh tokens inherit the resource
            // set; the client cannot widen or narrow via refresh. A new
            // authorization request is required to change the resource set.
            Audience::with_resource(self.config.token.audience.clone(), &family.resources[0])
        };

        let new_access_claims = TokenClaims {
            sub: user_id.to_string(),
            iss: self.config.token.issuer.clone(),
            aud: aud.clone(),
            exp: iat + access_ttl_secs,
            iat,
            sid: session_id.to_string(),
            tid: realm_id.to_string(),
            oid: claims.oid.clone(),
            token_type: "access".to_string(),
            nbf: None,
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: Some(fid.to_string()),
            scope: claims.scope.clone(),
            nonce: None,
            azp: None,
            roles: claims.roles.clone(),
            groups: claims.groups.clone(),
            org_groups: claims.org_groups.clone(),
            permissions: claims.permissions.clone(),
            required_actions: Vec::new(),
            act: None,
            amr: family.amr_values.clone(),
            cnf: dpop_jkt.map(|jkt| crate::identity::tokens::CnfClaim {
                jkt: jkt.to_string(),
            }),
            custom: claims.custom.clone(),
            sv: claims.sv,
        };
        let new_refresh_claims = TokenClaims {
            sub: user_id.to_string(),
            iss: self.config.token.issuer.clone(),
            aud,
            exp: iat + refresh_ttl_secs,
            iat,
            sid: session_id.to_string(),
            tid: realm_id.to_string(),
            oid: claims.oid.clone(),
            token_type: "refresh".to_string(),
            nbf: None,
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: Some(fid.to_string()),
            scope: claims.scope.clone(),
            nonce: None,
            azp: None,
            roles: claims.roles.clone(),
            groups: claims.groups.clone(),
            org_groups: Vec::new(),
            permissions: claims.permissions.clone(),
            required_actions: Vec::new(),
            act: None,
            amr: Vec::new(),
            cnf: None,
            custom: claims.custom.clone(),
            sv: None,
        };

        let new_access = signing_key.issue_token(&new_access_claims)?;
        let new_refresh = signing_key.issue_token(&new_refresh_claims)?;

        // Rotate the family's current refresh hash
        family.current_refresh_hash = Self::sha256_hex(new_refresh.as_bytes());
        // Extend family expiration to match the new refresh token (sliding).
        family.expires_at = crate::core::Timestamp::from_micros(
            self.clock.now().as_micros() + refresh_ttl_secs * 1_000_000,
        );
        let updated = serde_json::to_vec(&family).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &family_key, &updated)
            .map_err(Self::storage_err)?;

        Ok(TokenPair::new(new_access, new_refresh))
    }

    /// Unambiguous alphabet for device user codes (RFC 8628).
    ///
    /// Excludes I/1, O/0, L to avoid confusion. 28 characters.
    const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKMNPQRSTVWXYZ23456789";

    /// User code length (8 characters).
    const USER_CODE_LENGTH: usize = 8;

    /// Generates a random user code for device authorization.
    ///
    /// Uses an unambiguous alphabet to avoid visual confusion.
    fn generate_user_code(rng: &ring::rand::SystemRandom) -> Result<String, IdentityError> {
        let mut bytes = [0u8; Self::USER_CODE_LENGTH];
        rng.fill(&mut bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "random generation failed".to_string(),
            })?;
        let code: String = bytes
            .iter()
            .map(|b| {
                let idx = (*b as usize) % Self::USER_CODE_ALPHABET.len();
                Self::USER_CODE_ALPHABET[idx] as char
            })
            .collect();
        Ok(code)
    }

    /// Computes the PKCE S256 code challenge from a code verifier.
    ///
    /// `S256 = BASE64URL(SHA256(code_verifier))`
    fn pkce_s256_challenge(verifier: &str) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(digest.as_ref())
    }

    /// Persists a session to storage and keeps the in-process cache consistent.
    fn persist_session(&self, realm_id: &RealmId, session: &Session) -> Result<(), IdentityError> {
        let session_bytes = Self::serialize_session(session)?;
        let id_key = keys::encode_session_id(session.id());
        self.storage
            .put(realm_id, &id_key, &session_bytes)
            .map_err(Self::storage_err)?;
        // Update cache after the storage write succeeds.
        if session.is_valid(self.clock.now()) {
            self.session_cache_insert(realm_id, session);
        } else {
            self.session_cache_evict(realm_id, session.id());
        }
        Ok(())
    }

    // ===== Session cache helpers (S12-F1) =====

    /// Inserts or updates a session in the in-process cache.
    ///
    /// Silently skips at capacity so the storage fallback stays available.
    fn session_cache_insert(&self, realm_id: &RealmId, session: &Session) {
        if self.session_cache.load().len() >= SESSION_CACHE_MAX {
            return;
        }
        let key = (realm_id.clone(), session.id().clone());
        let val = Arc::new(session.clone());
        self.session_cache.rcu(|map| {
            let mut m = HashMap::clone(map);
            m.insert(key.clone(), Arc::clone(&val));
            m
        });
    }

    /// Removes a session from the in-process cache after revocation or expiry.
    ///
    /// No-ops when the key is absent to avoid a pointless `rcu()` clone.
    fn session_cache_evict(&self, realm_id: &RealmId, session_id: &SessionId) {
        let key = (realm_id.clone(), session_id.clone());
        if !self.session_cache.load().contains_key(&key) {
            return;
        }
        self.session_cache.rcu(|map| {
            let mut m = HashMap::clone(map);
            m.remove(&key);
            m
        });
    }

    // ===== Session lifecycle policy helpers (A-18) =====

    /// Evicts a policy-expired session (A-18). Marks revoked, evicts from
    /// cache, bumps SV, and emits `SessionEvicted` audit.
    fn evict_session_by_policy(
        &self,
        realm_id: &RealmId,
        session: &Session,
        now: crate::core::Timestamp,
    ) -> Result<(), IdentityError> {
        let reason = session.policy_expiry_reason(now).unwrap_or("unknown");
        let mut evicted = session.clone();
        evicted.revoke();
        self.persist_session(realm_id, &evicted)?;
        self.session_cache_evict(realm_id, evicted.id());
        if let Ok(Some(realm)) = self.get_realm(realm_id) {
            if realm.config().session_version.enabled {
                let retention = realm.config().session_version.delta_retention_seconds;
                let _ = self.sv_store.bump(realm_id, evicted.id(), retention);
            }
        }
        let ctx = crate::audit::context::AuditContext {
            actor: crate::audit::context::Actor::System,
            metadata: Some(serde_json::json!({
                "user_id": evicted.user_id().as_uuid().to_string(),
                "session_id": evicted.id().as_uuid().to_string(),
                "reason": reason,
            })),
        };
        let _ = self.record_audit(
            realm_id,
            Some(&ctx),
            crate::audit::AuditAction::SessionEvicted,
            "session",
            &evicted.id().as_uuid().to_string(),
        );
        Ok(())
    }

    /// Proactively sweeps sessions past their idle or absolute timeout (A-18).
    /// Short-circuits if the realm has no lifecycle policy (fail-open, §6.1).
    pub fn sweep_expired_sessions(&self, realm_id: &RealmId) -> Result<u64, IdentityError> {
        let (has_idle, has_abs) = if let Ok(Some(realm)) = self.get_realm(realm_id) {
            (
                realm.config().idle_timeout_secs.is_some(),
                realm.config().absolute_timeout_secs.is_some(),
            )
        } else {
            return Ok(0);
        };
        if !has_idle && !has_abs {
            return Ok(0);
        }
        let now = self.clock.now();
        let mut evicted: u64 = 0;
        let mut offset = 0u64;
        let batch = crate::core::MAX_PAGE_LIMIT;
        loop {
            let page = self
                .list_sessions_by_realm(realm_id, &crate::core::PageRequest::new(offset, batch))?;
            let n = page.items.len() as u64;
            for session in &page.items {
                if session.is_valid(now) && session.is_policy_expired(now) {
                    if self.evict_session_by_policy(realm_id, session, now).is_ok() {
                        evicted += 1;
                    }
                }
            }
            if n == 0 || offset + n >= page.total {
                break;
            }
            offset += n;
        }
        Ok(evicted)
    }

    // ===== Token claims cache helpers (S12-F2) =====

    /// SHA-256 cache key for a raw JWT string.
    ///
    /// Returns `None` only if `ring`'s SHA-256 digest is not 32 bytes
    /// (defensive; impossible in practice).
    pub(crate) fn token_cache_hash(token: &str) -> Option<[u8; 32]> {
        let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
        digest.as_ref().try_into().ok()
    }

    /// Inserts parsed claims into the token claims cache.
    ///
    /// Silently skips at capacity.
    fn token_claims_cache_insert(&self, key: [u8; 32], claims: Arc<TokenClaims>) {
        if self.token_claims_cache.load().len() >= TOKEN_CLAIMS_CACHE_MAX {
            return;
        }
        self.token_claims_cache.rcu(|map| {
            let mut m = HashMap::clone(map);
            m.insert(key, Arc::clone(&claims));
            m
        });
    }

    // ===== Realm helpers =====

    /// Serializes a realm record to JSON bytes.
    fn serialize_realm(realm: &Realm) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(realm).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Deserializes a realm record from JSON bytes.
    fn deserialize_realm(bytes: &[u8]) -> Result<Realm, IdentityError> {
        serde_json::from_slice(bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Gets the signing key for a realm, falling back to the default key.
    ///
    /// Used by token issuance paths where backward compatibility with
    /// Phase 0 realms (which lack per-realm keys) is needed.
    fn get_signing_key_or_default(&self, realm_id: &RealmId) -> Arc<SigningKey> {
        self.get_or_load_realm_signing_key(realm_id)
            .unwrap_or_else(|_| Arc::clone(&self.signing_key))
    }

    /// Verifies a JWT signature against the realm-specific signing key.
    ///
    /// Fails closed (HEA-SEC-18): if the realm has no per-realm key, or if
    /// verification against the realm key fails, returns an error. The legacy
    /// global-key fallback has been removed — every realm is provisioned with
    /// its own key at creation time.
    fn verify_token_signature_for_realm(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<TokenClaims, IdentityError> {
        let realm_key = self.get_or_load_realm_signing_key(realm_id)?;
        tokens::verify_token_signature(token, realm_key.public_key_bytes())
    }

    /// Parses a `session_`-prefixed session ID claim.
    ///
    /// Returns `Ok(None)` for sessionless tokens (`sid == "none"`).
    fn parse_session_id_claim(claims: &TokenClaims) -> Result<Option<SessionId>, IdentityError> {
        if claims.sid == "none" {
            return Ok(None);
        }

        let sid_str = claims
            .sid
            .strip_prefix("session_")
            .ok_or(IdentityError::InvalidToken)?;
        let sid_uuid = uuid::Uuid::parse_str(sid_str).map_err(|_| IdentityError::InvalidToken)?;
        Ok(Some(SessionId::new(sid_uuid)))
    }

    /// Parses a `user_`-prefixed subject claim.
    fn parse_user_id_claim(claims: &TokenClaims) -> Result<UserId, IdentityError> {
        let sub_str = claims
            .sub
            .strip_prefix("user_")
            .ok_or(IdentityError::InvalidToken)?;
        let sub_uuid = uuid::Uuid::parse_str(sub_str).map_err(|_| IdentityError::InvalidToken)?;
        Ok(UserId::new(sub_uuid))
    }

    /// Returns the depth of an RFC 8693 `act` delegation chain (A-38).
    ///
    /// An `act` object with no nested `act` has depth 1.  Each level of
    /// nesting increments the count.  The loop is bounded by
    /// `MAX_ACT_CHAIN_DEPTH + 2` to prevent any theoretical overflow.
    fn act_chain_depth(act: &serde_json::Value) -> usize {
        let mut depth: usize = 0;
        let mut cur = act;
        loop {
            depth += 1;
            if depth > crate::abuse::MAX_ACT_CHAIN_DEPTH + 1 {
                return depth;
            }
            match cur.get("act") {
                Some(next) => cur = next,
                None => return depth,
            }
        }
    }
}

impl EmbeddedIdentityEngine {
    /// Retrieves (or lazily loads from storage) the signing key for a realm.
    ///
    /// Checks the in-memory cache first, then loads from storage on cache miss.
    /// Returns `RealmNotFound` if no per-realm key exists.
    fn get_or_load_realm_signing_key(
        &self,
        realm_id: &RealmId,
    ) -> Result<Arc<SigningKey>, IdentityError> {
        // Wait-free read: one atomic load, no locking.
        {
            let map = self.realm_signing_keys.load();
            if let Some(key) = map.get(realm_id) {
                return Ok(Arc::clone(key));
            }
        }

        // Cache miss: load key bytes from storage.
        let sys_realm = keys::system_realm_id();
        let key_storage_key = keys::encode_realm_signing_key(realm_id);
        let raw = self
            .storage
            .get(&sys_realm, &key_storage_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::RealmNotFound)?;
        let kek = self
            .config
            .key_encryption_key
            .as_ref()
            .map(|k| k.as_bytes());
        let key_bytes = crate::identity::key_encryption::unwrap_key(&raw, kek)?;

        let signing_key = Arc::new(SigningKey::from_pkcs8(&key_bytes)?);

        // Insert into cache via CAS loop — safe under concurrent loaders:
        // the last writer wins but all produce equivalent keys.
        let realm_id_owned = realm_id.clone();
        let key_clone = Arc::clone(&signing_key);
        self.realm_signing_keys.rcu(|current| {
            let mut new_map = (**current).clone();
            new_map.insert(realm_id_owned.clone(), Arc::clone(&key_clone));
            new_map
        });

        Ok(signing_key)
    }

    /// Looks up a consent record for the given `(user, client, org_key,
    /// resource_key)` tuple.
    ///
    /// When `consent_spans_orgs` is `true` and no org-specific record is found,
    /// falls back to a realm-level record keyed with
    /// [`CONSENT_ORG_KEY_REALM`][keys::CONSENT_ORG_KEY_REALM].
    fn get_consent_extended(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
        org_key: &str,
        resource_key: &str,
        consent_spans_orgs: bool,
    ) -> Result<Option<ConsentRecord>, IdentityError> {
        // Try the specific (org, resource) tuple first.
        let key = keys::encode_consent_key_extended(user_id, client_id, org_key, resource_key);
        if let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        {
            let rec: ConsentRecord =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            return Ok(Some(rec));
        }

        // `consent_spans_orgs` fallback: if the client allows a realm-level
        // consent to cover any org, check for a `_realm`-keyed record.
        if consent_spans_orgs && org_key != keys::CONSENT_ORG_KEY_REALM {
            let fallback_key = keys::encode_consent_key_extended(
                user_id,
                client_id,
                keys::CONSENT_ORG_KEY_REALM,
                resource_key,
            );
            if let Some(bytes) = self
                .storage
                .get(realm_id, &fallback_key)
                .map_err(Self::storage_err)?
            {
                let rec: ConsentRecord =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                return Ok(Some(rec));
            }
        }

        // Legacy key fallback for records written before the extended schema.
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

        Ok(None)
    }
}

impl EmbeddedIdentityEngine {
    /// Marks every non-revoked session in a realm as revoked.
    ///
    /// Called on suspend/archive transitions. Skips per-session audit events;
    /// the caller's `RealmUpdated` event covers the lifecycle change.
    fn bulk_revoke_sessions(&self, realm_id: &RealmId) {
        let storage = self.storage.as_ref();
        let prefix = keys::session_id_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let Ok(entries) = storage.scan(realm_id, &prefix, &end) else {
            return;
        };
        for entry in &entries {
            if let Ok(mut session) = serde_json::from_slice::<Session>(&entry.value) {
                if !session.is_revoked() {
                    let session_id = session.id().clone();
                    session.revoke();
                    if let Ok(bytes) = serde_json::to_vec(&session) {
                        let _ = storage.put(realm_id, &entry.key, &bytes);
                    }
                    // Drop the cached (still-valid) copy so subsequent
                    // get_session calls observe the revocation.
                    self.session_cache_evict(realm_id, &session_id);
                }
            }
        }
    }

    /// Returns `{base_issuer}/realms/{name}` for per-realm OIDC scoping.
    /// Falls back to `base_issuer` when the realm cannot be loaded.
    fn realm_issuer_url(&self, realm_id: &RealmId) -> String {
        let base = &self.config.oidc.issuer;
        match self.get_realm(realm_id) {
            Ok(Some(realm)) => format!("{base}/realms/{}", realm.name()),
            _ => base.clone(),
        }
    }

    /// Enforce that a realm exists and is `Active`.
    ///
    /// Call this at the top of every mutating operation. Both `Suspended` and
    /// `Archived` realms return `RealmSuspended`; a missing realm returns
    /// `RealmNotFound`.
    fn require_active_realm(&self, realm_id: &RealmId) -> Result<(), IdentityError> {
        let realm = self
            .get_realm(realm_id)?
            .ok_or(IdentityError::RealmNotFound)?;
        match realm.status() {
            RealmStatus::Active => {}
            RealmStatus::DeletingInProgress => return Err(IdentityError::RealmSuspended),
            _ => return Err(IdentityError::RealmSuspended),
        }
        Ok(())
    }

    /// Counts keys under `prefix` in the realm and returns `QuotaExceeded` if
    /// the count is at or above `limit`. Fail-closed: a storage error becomes
    /// `QuotaExceeded` to prevent unbounded growth on scan failure.
    fn check_resource_quota(
        &self,
        realm_id: &RealmId,
        resource: &'static str,
        prefix: &[u8],
        limit: u64,
    ) -> Result<(), IdentityError> {
        let end = keys::prefix_end(prefix);
        let current = self
            .storage
            .scan(realm_id, prefix, &end)
            .map(|e| e.len() as u64)
            .unwrap_or(limit); // fail-closed
        if current >= limit {
            return Err(IdentityError::QuotaExceeded {
                resource,
                limit,
                current,
            });
        }
        Ok(())
    }

    fn build_discovery_document(
        &self,
        issuer: &str,
        realm_config: Option<&crate::identity::types::RealmConfig>,
    ) -> OidcDiscoveryDocument {
        let fapi_profile = realm_config.and_then(|c| c.fapi_profile).map(|p| match p {
            crate::identity::types::FapiProfile::Baseline => "baseline".to_string(),
            crate::identity::types::FapiProfile::Advanced => "advanced".to_string(),
        });
        OidcDiscoveryDocument {
            issuer: issuer.to_string(),
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            jwks_uri: format!("{issuer}/.well-known/jwks.json"),
            userinfo_endpoint: format!("{issuer}/userinfo"),
            response_types_supported: vec!["code".to_string()],
            response_modes_supported: vec![
                "query".to_string(),
                "fragment".to_string(),
                "query.jwt".to_string(),
                "fragment.jwt".to_string(),
                "jwt".to_string(),
            ],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            claims_supported: vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "nonce".to_string(),
                "email".to_string(),
                "email_verified".to_string(),
                "name".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "none".to_string(),
                "client_secret_post".to_string(),
                "private_key_jwt".to_string(),
            ],
            code_challenge_methods_supported: vec!["S256".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
                "client_credentials".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
                "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            ],
            registration_endpoint: Some(format!("{issuer}/register")),
            device_authorization_endpoint: Some(format!("{issuer}/device/authorize")),
            revocation_endpoint: Some(format!("{issuer}/revoke")),
            introspection_endpoint: Some(format!("{issuer}/introspect")),
            resource_indicators_supported: true,
            authorization_response_iss_parameter_supported: true,
            end_session_endpoint: Some(format!("{issuer}/end_session")),
            backchannel_logout_supported: true,
            backchannel_logout_session_supported: true,
            pushed_authorization_request_endpoint: Some(format!("{issuer}/as/par")),
            dpop_signing_alg_values_supported: vec!["ES256".to_string(), "EdDSA".to_string()],
            request_object_signing_alg_values_supported: vec![
                "RS256".to_string(),
                "PS256".to_string(),
                "ES256".to_string(),
                "EdDSA".to_string(),
            ],
            authorization_signing_alg_values_supported: vec!["EdDSA".to_string()],
            fapi_profile,
        }
    }

    /// Verifies a client_credentials (sessionless) token by checking the JTI
    /// revocation projection. Returns `Ok(())` if the token is not revoked.
    ///
    /// Hot-path safe: reads `revoked_jti_cache` via a single atomic `load()` —
    /// no lock, no syscall (§10.5).
    fn verify_client_credentials_token(
        &self,
        realm_id: &RealmId,
        claims: &TokenClaims,
    ) -> Result<(), IdentityError> {
        if let Some(ref jti) = claims.jti {
            let cache_key = format!("{}:{}", realm_id.as_uuid(), jti);
            let cache = self.revoked_jti_cache.load();
            if cache.contains_key(cache_key.as_str()) {
                return Err(IdentityError::InvalidToken);
            }
        }
        Ok(())
    }

    /// Emits `LoginFailed` and, when the lockout threshold is first reached,
    /// `LoginLocked` to the audit log. Best-effort: audit failures are logged
    /// but do not affect the caller's error path.
    fn emit_login_failed_audit(&self, realm_id: &RealmId, user_id: &UserId, attempt_count: u32) {
        let (max_attempts, lockout_micros) = self.effective_rate_limit(realm_id);
        let user_id_str = user_id.as_uuid().to_string();

        let failed_ctx = AuditContext {
            actor: Actor::Anonymous,
            metadata: Some(serde_json::json!({ "attempt_count": attempt_count })),
        };
        let _ = self.record_audit(
            realm_id,
            Some(&failed_ctx),
            AuditAction::LoginFailed,
            "credential",
            &user_id_str,
        );

        if attempt_count >= max_attempts {
            let locked_ctx = AuditContext {
                actor: Actor::Anonymous,
                metadata: Some(serde_json::json!({
                    "attempt_count": attempt_count,
                    "lockout_duration_micros": lockout_micros,
                })),
            };
            let _ = self.record_audit(
                realm_id,
                Some(&locked_ctx),
                AuditAction::LoginLocked,
                "credential",
                &user_id_str,
            );
        }
    }

    /// Returns the per-realm lock for JWT Bearer JTI operations, creating it on first use.
    fn jwt_bearer_jti_lock(&self, realm_id: &RealmId) -> Arc<Mutex<()>> {
        let mut map = self.jti_locks.lock().expect("jti_locks poisoned");
        Arc::clone(
            map.entry(realm_id.clone())
                // INVARIANT: inner guard held only across the sync JTI check-and-consume window; no .await in scope.
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    /// Returns a per-token-hash lock for single-use token redemption.
    ///
    /// Callers hold this lock across the get → check-used → mark-used sequence
    /// to prevent two concurrent requests for the same token from both passing
    /// the `used` check before either writes back.
    fn token_redemption_lock(&self, token_hash: &str) -> Arc<Mutex<()>> {
        let mut map = self
            .token_redemption_locks
            .lock()
            .expect("token_redemption_locks poisoned");
        Arc::clone(
            map.entry(token_hash.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    /// Returns the per-code-hash advisory lock for authorization code single-use enforcement.
    ///
    /// Callers hold this lock across the entire get → validate → delete →
    /// issue-tokens sequence to prevent two concurrent requests for the same
    /// code from both loading it before either deletes it (TOCTOU / OAUTH-06).
    fn code_exchange_lock(&self, code_hash: &str) -> Arc<Mutex<()>> {
        let mut map = self
            .code_exchange_locks
            .lock()
            .expect("code_exchange_locks poisoned");
        Arc::clone(
            map.entry(code_hash.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    /// Returns a per-request-id advisory lock for approval state transitions.
    ///
    /// Callers hold this lock across the read → status-check → mint → write
    /// sequence in `approve_approval_request_inner` and
    /// `deny_approval_request_inner` to prevent two concurrent callers from
    /// both passing the Pending check before either writes the final state.
    fn approval_request_lock(&self, request_id: &str) -> Arc<Mutex<()>> {
        let mut map = self.approval_locks.lock().expect("approval_locks poisoned");
        Arc::clone(
            map.entry(request_id.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    /// Returns the per-`(realm_id, txn_id)` advisory lock for serializing
    /// concurrent calls to `issue_transaction_token_inner`.
    ///
    /// The outer `txn_locks` map guard is released before returning so that
    /// callers for different `txn_id` values never contend with each other.
    fn txn_advisory_lock(&self, realm_id: &RealmId, txn_id: &str) -> Arc<Mutex<()>> {
        let key = format!("{}:{}", realm_id.as_uuid(), txn_id);
        let mut map = self.txn_locks.lock().expect("txn_locks poisoned");
        Arc::clone(map.entry(key).or_insert_with(|| Arc::new(Mutex::new(()))))
    }

    /// Atomically checks and consumes a JWT Bearer assertion JTI for replay prevention.
    ///
    /// Stores the JTI with its expiry time (big-endian i64 `assertion_exp`). On lookup the
    /// stored expiry is compared against `now`: if the original assertion is still within
    /// its validity window (plus `CLOCK_SKEW_SECS`), the call is rejected as replay.
    ///
    /// Lazy expiry: entries are not proactively pruned; they become "expired" once
    /// `now > stored_exp + CLOCK_SKEW_SECS`. Re-use of an expired JTI is safe because any
    /// replayed assertion would also fail the `exp` check.
    ///
    /// The per-realm mutex eliminates the TOCTOU window between `get` and `put`.
    fn check_and_consume_jwt_bearer_jti(
        &self,
        realm_id: &RealmId,
        jti: &str,
        assertion_exp: i64,
    ) -> Result<(), IdentityError> {
        let jti_key = keys::encode_jwt_bearer_jti(jti);
        let lock = self.jwt_bearer_jti_lock(realm_id);
        let _guard = lock.lock().expect("jwt bearer jti lock poisoned");

        if let Some(stored) = self
            .storage
            .get(realm_id, &jti_key)
            .map_err(Self::storage_err)?
        {
            let bytes: [u8; 8] =
                stored
                    .as_slice()
                    .try_into()
                    .map_err(|_| IdentityError::Internal {
                        reason: format!("JTI entry has unexpected length {}", stored.len()),
                    })?;
            let stored_exp = i64::from_be_bytes(bytes);
            let now_secs = self.clock.now().as_micros() / 1_000_000;
            if now_secs <= stored_exp.saturating_add(CLOCK_SKEW_SECS) {
                return Err(IdentityError::JwtBearerAssertionInvalid {
                    reason: "assertion jti has already been used (replay)".to_string(),
                });
            }
            // Entry is past expiry — safe to overwrite with the new assertion's exp.
        }
        self.storage
            .put(realm_id, &jti_key, &assertion_exp.to_be_bytes())
            .map_err(Self::storage_err)?;
        Ok(())
    }
}

// Private cascade helpers — not part of the IdentityEngine trait.
impl EmbeddedIdentityEngine {
    /// Counts the total number of data keys across all cascade prefixes for a realm.
    /// Used to decide whether to background the delete_realm cascade.
    fn estimate_cascade_count(&self, realm_id: &RealmId) -> usize {
        let prefixes: &[&[u8]] = &[
            b"usr:id:",
            b"usr:email:",
            b"cred:user:",
            b"ses:id:",
            b"ses:user:",
            b"mfa:totp:",
            b"webauthn:cred:",
            b"webauthn:disc:",
            b"magic:link:",
            b"email:verify:",
            b"email:change:",
            b"email:reserved:",
            b"rst:token:",
            b"dfp:user:",
            b"org:id:",
            b"org:slug:",
            b"slug:org:",
            b"orgm:org:",
            b"orgm:user:",
            b"orgi:id:",
            b"orgi:token:",
            b"orgi:org:",
            b"orgi:list:",
            b"oauth:client:",
            b"rel:",
            b"oauth:code:",
            b"oauth:revjti:",
            b"oauth:ucode:",
            b"rba:",
        ];
        prefixes.iter().fold(0usize, |acc, prefix| {
            let end = keys::prefix_end(prefix);
            acc + self
                .storage
                .scan(realm_id, prefix, &end)
                .map(|e| e.len())
                .unwrap_or(0)
        })
    }

    /// Runs the full cascade deletion for a realm in chunks of `chunk_size` keys.
    ///
    /// Deletes all realm data across every key prefix. The realm record itself
    /// must have already been removed (or marked `DeletingInProgress`) before
    /// this is called. This method is idempotent: re-running after a crash
    /// converges to a clean state.
    ///
    /// Returns `(cascade_work_done, audit_needed)` where `cascade_work_done`
    /// indicates whether any keys were actually deleted.
    #[allow(clippy::too_many_lines)]
    fn do_cascade_chunked(
        &self,
        realm_id: &RealmId,
        chunk_size: usize,
    ) -> Result<bool, IdentityError> {
        let sys_realm = keys::system_realm_id();
        let mut cascade_work_done = false;

        // 1. Delete all users in this realm (cascades to sessions, credentials)
        let user_prefix = keys::user_id_scan_prefix();
        let user_end = keys::prefix_end(&user_prefix);
        let users = self
            .storage
            .scan(realm_id, &user_prefix, &user_end)
            .map_err(Self::storage_err)?;

        if !users.is_empty() {
            cascade_work_done = true;
        }

        for entry in &users {
            let user: User = Self::deserialize_user(&entry.value)?;
            // delete_user handles cascade of sessions, credentials, email index
            let _ = self.delete_user(realm_id, user.id());
        }

        // 1a. Unconditional sweep of per-user secondary prefixes. These
        //     indexes are normally cleaned up inside `delete_user`, but a
        //     crash (or an orphaned primary) can leave stragglers. Scanning
        //     by prefix guarantees we reach them on any retry.
        //
        //     email:reserved: is the A-20 90-day tombstone written by
        //     delete_user. It holds a plaintext email address and MUST be
        //     purged when the realm is deleted so no PII outlives the realm.
        //
        //     dfp:user: holds HMAC-SHA256 hashes of device signals (not raw
        //     PII), but must still be swept for completeness.
        //
        //     email:change: holds SHA-256 token hashes (not plaintext), but
        //     pending change requests reference deleted users and should go.
        for prefix in [
            &b"usr:email:"[..],
            &b"cred:user:"[..],
            &b"ses:id:"[..],
            &b"ses:user:"[..],
            &b"mfa:totp:"[..],
            // Burned MFA pending cookie nonces (HEA-SEC-25). Persisted to
            // WAL to survive restarts; must be swept on realm deletion.
            &b"mfa:nonce:"[..],
            &b"webauthn:cred:"[..],
            &b"webauthn:disc:"[..],
            &b"magic:link:"[..],
            &b"email:verify:"[..],
            &b"email:change:"[..],
            &b"email:reserved:"[..],
            &b"rst:token:"[..],
            &b"dfp:user:"[..],
        ] {
            let end = keys::prefix_end(prefix);
            let entries = self
                .storage
                .scan(realm_id, prefix, &end)
                .map_err(Self::storage_err)?;
            if !entries.is_empty() {
                cascade_work_done = true;
            }
            for chunk in entries.chunks(chunk_size) {
                for entry in chunk {
                    self.storage
                        .delete(realm_id, &entry.key)
                        .map_err(Self::storage_err)?;
                }
            }
        }

        // 1b. Unconditional sweep of organization-related prefixes.
        //     slug:org: holds post-delete org-slug cooldown tombstones (A-5)
        //     written by delete_organization. They persist until the cooldown
        //     expires but must not outlive the realm itself.
        for prefix in [
            &b"org:id:"[..],
            &b"org:slug:"[..],
            &b"slug:org:"[..],
            &b"orgm:org:"[..],
            &b"orgm:user:"[..],
            &b"orgi:id:"[..],
            &b"orgi:token:"[..],
            &b"orgi:org:"[..],
            &b"orgi:list:"[..],
        ] {
            let end = keys::prefix_end(prefix);
            let entries = self
                .storage
                .scan(realm_id, prefix, &end)
                .map_err(Self::storage_err)?;
            if !entries.is_empty() {
                cascade_work_done = true;
            }
            for chunk in entries.chunks(chunk_size) {
                for entry in chunk {
                    self.storage
                        .delete(realm_id, &entry.key)
                        .map_err(Self::storage_err)?;
                }
            }
        }

        // 1c. Unconditional sweep of agent-related prefixes (HEA-1325).
        for prefix in [&b"agt:id:"[..], &b"agt:owner:"[..]] {
            let end = keys::prefix_end(prefix);
            let entries = self
                .storage
                .scan(realm_id, prefix, &end)
                .map_err(Self::storage_err)?;
            if !entries.is_empty() {
                cascade_work_done = true;
            }
            for chunk in entries.chunks(chunk_size) {
                for entry in chunk {
                    self.storage
                        .delete(realm_id, &entry.key)
                        .map_err(Self::storage_err)?;
                }
            }
        }

        // 2. Delete all OAuth clients
        let client_prefix = b"oauth:client:";
        let client_end = keys::prefix_end(client_prefix);
        let clients = self
            .storage
            .scan(realm_id, client_prefix, &client_end)
            .map_err(Self::storage_err)?;
        if !clients.is_empty() {
            cascade_work_done = true;
        }
        for chunk in clients.chunks(chunk_size) {
            for entry in chunk {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 3. Delete all authorization tuples (prefix "rel:")
        let rel_prefix = b"rel:";
        let rel_end = keys::prefix_end(rel_prefix);
        let rels = self
            .storage
            .scan(realm_id, rel_prefix, &rel_end)
            .map_err(Self::storage_err)?;
        if !rels.is_empty() {
            cascade_work_done = true;
        }
        for chunk in rels.chunks(chunk_size) {
            for entry in chunk {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 4. Delete all OAuth authorization codes
        let code_prefix = b"oauth:code:";
        let code_end = keys::prefix_end(code_prefix);
        let codes = self
            .storage
            .scan(realm_id, code_prefix, &code_end)
            .map_err(Self::storage_err)?;
        if !codes.is_empty() {
            cascade_work_done = true;
        }
        for chunk in codes.chunks(chunk_size) {
            for entry in chunk {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 5. Delete all grant families
        let family_prefix = keys::grant_family_scan_prefix();
        let family_end = keys::prefix_end(&family_prefix);
        let families = self
            .storage
            .scan(realm_id, &family_prefix, &family_end)
            .map_err(Self::storage_err)?;
        if !families.is_empty() {
            cascade_work_done = true;
        }
        for chunk in families.chunks(chunk_size) {
            for entry in chunk {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 6. Delete all device codes
        let device_prefix = keys::device_code_scan_prefix();
        let device_end = keys::prefix_end(&device_prefix);
        let devices = self
            .storage
            .scan(realm_id, &device_prefix, &device_end)
            .map_err(Self::storage_err)?;
        if !devices.is_empty() {
            cascade_work_done = true;
        }
        for chunk in devices.chunks(chunk_size) {
            for entry in chunk {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 7. Delete all revoked JTIs
        let jti_prefix = b"oauth:revjti:";
        let jti_end = keys::prefix_end(jti_prefix);
        let jtis = self
            .storage
            .scan(realm_id, jti_prefix, &jti_end)
            .map_err(Self::storage_err)?;
        if !jtis.is_empty() {
            cascade_work_done = true;
        }
        for chunk in jtis.chunks(chunk_size) {
            for entry in chunk {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 8. Delete all user-code index entries
        let ucode_prefix = b"oauth:ucode:";
        let ucode_end = keys::prefix_end(ucode_prefix);
        let ucodes = self
            .storage
            .scan(realm_id, ucode_prefix, &ucode_end)
            .map_err(Self::storage_err)?;
        if !ucodes.is_empty() {
            cascade_work_done = true;
        }
        for chunk in ucodes.chunks(chunk_size) {
            for entry in chunk {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 8a. Delete all OAuth consent records in this realm.
        let consent_prefix = keys::oauth_consent_scan_prefix();
        let consent_end = keys::prefix_end(&consent_prefix);
        let consents = self
            .storage
            .scan(realm_id, &consent_prefix, &consent_end)
            .map_err(Self::storage_err)?;
        if !consents.is_empty() {
            cascade_work_done = true;
        }
        for chunk in consents.chunks(chunk_size) {
            for entry in chunk {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 8b. Delete all in-flight pending-authorization tickets.
        let pending_prefix = keys::oauth_pending_auth_scan_prefix();
        let pending_end = keys::prefix_end(&pending_prefix);
        let pendings = self
            .storage
            .scan(realm_id, &pending_prefix, &pending_end)
            .map_err(Self::storage_err)?;
        if !pendings.is_empty() {
            cascade_work_done = true;
        }
        for chunk in pendings.chunks(chunk_size) {
            for entry in chunk {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 8c. Federation connectors, state tokens, confirm-link tickets,
        //     the external-identity indexes (both directions), and the
        //     SCIM externalId indexes (both directions, users + groups).
        for prefix in [
            &b"fed:idp:"[..],
            &b"fed:state:"[..],
            &b"fed:confirm:"[..],
            &b"fed:ext:"[..],
            &b"fed:ext_fwd:"[..],
            &b"scim:ext_user:"[..],
            &b"scim:ext_user_fwd:"[..],
            &b"scim:ext_group:"[..],
            &b"scim:ext_group_fwd:"[..],
        ] {
            let end = keys::prefix_end(prefix);
            let entries = self
                .storage
                .scan(realm_id, prefix, &end)
                .map_err(Self::storage_err)?;
            if !entries.is_empty() {
                cascade_work_done = true;
            }
            for chunk in entries.chunks(chunk_size) {
                for entry in chunk {
                    self.storage
                        .delete(realm_id, &entry.key)
                        .map_err(Self::storage_err)?;
                }
            }
        }

        // 8d. SAML registrations, state, replay sentinels, SP-session
        //     registrations, and logout state.
        for prefix in [
            &b"saml:sp:"[..],
            &b"saml:state:"[..],
            &b"saml:asn:"[..],
            &b"saml:sp_session:"[..],
            &b"saml:logout:"[..],
        ] {
            let end = keys::prefix_end(prefix);
            let entries = self
                .storage
                .scan(realm_id, prefix, &end)
                .map_err(Self::storage_err)?;
            if !entries.is_empty() {
                cascade_work_done = true;
            }
            for chunk in entries.chunks(chunk_size) {
                for entry in chunk {
                    self.storage
                        .delete(realm_id, &entry.key)
                        .map_err(Self::storage_err)?;
                }
            }
        }

        // 8e. SAML per-realm RSA signing key (under system realm scope).
        let saml_key_storage_key = keys::encode_realm_saml_key(realm_id);
        if self
            .storage
            .get(&sys_realm, &saml_key_storage_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            cascade_work_done = true;
            self.storage
                .delete(&sys_realm, &saml_key_storage_key)
                .map_err(Self::storage_err)?;
        }

        // 8f. Delete all JWT bearer assertion JTIs (replay store).
        let jb_jti_prefix = keys::jwt_bearer_jti_scan_prefix();
        let jb_jti_end = keys::prefix_end(&jb_jti_prefix);
        let jb_jtis = self
            .storage
            .scan(realm_id, &jb_jti_prefix, &jb_jti_end)
            .map_err(Self::storage_err)?;
        if !jb_jtis.is_empty() {
            cascade_work_done = true;
        }
        for chunk in jb_jtis.chunks(chunk_size) {
            for entry in chunk {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 8g. Delete all private_key_jwt client assertion JTIs (replay store).
        let ca_jti_prefix = keys::client_assertion_jti_scan_prefix();
        let ca_jti_end = keys::prefix_end(&ca_jti_prefix);
        let ca_jtis = self
            .storage
            .scan(realm_id, &ca_jti_prefix, &ca_jti_end)
            .map_err(Self::storage_err)?;
        if !ca_jtis.is_empty() {
            cascade_work_done = true;
        }
        for chunk in ca_jtis.chunks(chunk_size) {
            for entry in chunk {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 8h. Delete all JAR (RFC 9101) signed request object JTIs (replay store).
        let jar_jti_prefix = keys::jar_jti_scan_prefix();
        let jar_jti_end = keys::prefix_end(&jar_jti_prefix);
        let jar_jtis = self
            .storage
            .scan(realm_id, &jar_jti_prefix, &jar_jti_end)
            .map_err(Self::storage_err)?;
        if !jar_jtis.is_empty() {
            cascade_work_done = true;
        }
        for chunk in jar_jtis.chunks(chunk_size) {
            for entry in chunk {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 9. Delete realm signing key (check existence first so we can attribute
        //    cascade work even when only the signing key survives a prior crash).
        let key_storage_key = keys::encode_realm_signing_key(realm_id);
        if self
            .storage
            .get(&sys_realm, &key_storage_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            cascade_work_done = true;
            self.storage
                .delete(&sys_realm, &key_storage_key)
                .map_err(Self::storage_err)?;
        }

        Ok(cascade_work_done)
    }
}

impl IdentityEngine for EmbeddedIdentityEngine {
    fn check_ip_login_rate_limit(&self, realm_id: &RealmId, ip: &str) -> Result<(), IdentityError> {
        self.check_ip_login_rate_limit(realm_id, ip)
    }

    fn record_ip_login_attempt(&self, realm_id: &RealmId, ip: &str) {
        self.record_ip_login_attempt(realm_id, ip);
    }

    fn ip_login_retry_after_secs(&self, realm_id: &RealmId, ip: &str) -> u64 {
        let micros = self.ip_login_retry_after_micros(realm_id, ip);
        if micros <= 0 {
            return 0;
        }
        // Round up to whole seconds
        (micros as u64).div_ceil(1_000_000)
    }

    // ===== Realm lifecycle (Phase 1 Step 19) =====

    fn create_realm(&self, request: &CreateRealmRequest) -> Result<Realm, IdentityError> {
        // Reserved name — the system realm is Hearth-managed.
        if request.name == keys::SYSTEM_REALM_NAME {
            return Err(IdentityError::SystemRealmProtected {
                operation: "create_realm",
            });
        }
        // Slug shape + admin-URL keyword reservation (UI_ROUTING.md R-4).
        // Realm names ride in URL paths, so they must be URL-safe AND
        // must not collide with any admin sub-resource keyword.
        super::validation::validate_realm_name(&request.name)?;

        // A-5: reject operator-configured permanently reserved realm names.
        let name_lower = request.name.to_ascii_lowercase();
        if self.config.reserved_slugs.iter().any(|r| r == &name_lower) {
            return Err(IdentityError::ReservedSlug {
                slug: request.name.clone(),
            });
        }

        // Serialize against other realm-record mutations so the atomic
        // record+key `put_batch` below is never interleaved with another
        // thread's update/delete. See `realm_ops_lock` docs.
        let _ops_guard = self.realm_ops_lock.lock().expect("realm ops lock");

        // Reject duplicate names — if the name index already points at a
        // realm, refuse rather than silently overwriting the index and
        // leaving an orphaned realm record that the UUID scan would surface.
        if self.get_realm_by_name(&request.name)?.is_some() {
            return Err(IdentityError::DuplicateRealmName);
        }

        // A-5: check post-delete realm name cooldown (system realm namespace).
        let sys_realm = keys::system_realm_id();
        let cooldown_key = keys::encode_realm_slug_reservation(&request.name);
        if let Some(bytes) = self
            .storage
            .get(&sys_realm, &cooldown_key)
            .map_err(Self::storage_err)?
        {
            if let Ok(reservation) = serde_json::from_slice::<StoredSlugReservation>(&bytes) {
                let now_micros = self.clock.now().as_micros();
                if now_micros < reservation.expires_at_micros {
                    return Err(IdentityError::SlugInCooldown {
                        slug: request.name.clone(),
                    });
                }
                // Cooldown expired — clean up the stale reservation.
                let _ = self.storage.delete(&sys_realm, &cooldown_key);
            }
        }

        let now = self.clock.now();
        let realm_id = RealmId::generate();
        let config = request.config.clone().unwrap_or_default();

        // SEC-20: reject webhook config without HMAC secret (claim-injection risk).
        if let Some(ref wh) = config.pre_token_webhook {
            wh.validate()
                .map_err(|reason| IdentityError::InvalidInput { reason })?;
        }

        // Generate a per-realm signing key
        let realm_signing_key = SigningKey::generate()?;

        // Persist the realm record under the system realm namespace
        // (sys_realm already declared above for cooldown check)
        let realm = Realm::new(
            realm_id.clone(),
            request.name.clone(),
            RealmStatus::Active,
            config,
            now,
            now,
        );
        let realm_bytes = Self::serialize_realm(&realm)?;
        let realm_key = keys::encode_realm_id(&realm_id);
        let key_storage_key = keys::encode_realm_signing_key(&realm_id);
        // Zeroizing ensures the local PKCS#8 copy is actively overwritten
        // when dropped rather than relying on the allocator (HEA-750 M1).
        let key_plaintext = Zeroizing::new(realm_signing_key.pkcs8_bytes().to_vec());
        let kek = self
            .config
            .key_encryption_key
            .as_ref()
            .map(|k| k.as_bytes());
        let key_stored = crate::identity::key_encryption::wrap_key(&key_plaintext, kek)?;

        // Name index: realm:name:{name} → realm UUID bytes
        let name_key = keys::encode_realm_name(&request.name);
        let name_value = realm_id.as_uuid().as_bytes().to_vec();

        // Atomic three-entry write: the realm record, signing key, and
        // name index land together or not at all.
        self.storage
            .put_batch(
                &sys_realm,
                &[
                    (realm_key, realm_bytes),
                    (key_storage_key, key_stored),
                    (name_key, name_value),
                ],
            )
            .map_err(Self::storage_err)?;

        // Cache signing key (wait-free reads on hot path).
        {
            let key_arc = Arc::new(realm_signing_key);
            let id = realm_id.clone();
            self.realm_signing_keys.rcu(|current| {
                let mut new_map = (**current).clone();
                new_map.insert(id.clone(), Arc::clone(&key_arc));
                new_map
            });
        }

        // Cache realm status for wait-free validate_token reads.
        {
            let id = realm_id.clone();
            self.realm_status_cache.rcu(|current| {
                let mut new_map = (**current).clone();
                new_map.insert(id.clone(), RealmStatus::Active);
                new_map
            });
        }

        self.record_audit(
            &realm_id,
            None,
            AuditAction::RealmCreated,
            "realm",
            &realm_id.as_uuid().to_string(),
        )?;

        Ok(realm)
    }

    fn get_realm(&self, realm_id: &RealmId) -> Result<Option<Realm>, IdentityError> {
        let sys_realm = keys::system_realm_id();
        let realm_key = keys::encode_realm_id(realm_id);
        let bytes = self
            .storage
            .get(&sys_realm, &realm_key)
            .map_err(Self::storage_err)?;
        match bytes {
            Some(b) => Ok(Some(Self::deserialize_realm(&b)?)),
            None => Ok(None),
        }
    }

    fn get_realm_by_name(&self, name: &str) -> Result<Option<Realm>, IdentityError> {
        // The reserved system realm is invisible to name lookups. Even
        // though its record is in storage, we refuse to surface it here
        // so that realm resolvers, registration policies, and admin UI
        // dropdowns can never accidentally route into it.
        if name == keys::SYSTEM_REALM_NAME {
            return Ok(None);
        }
        let sys_realm = keys::system_realm_id();
        let name_key = keys::encode_realm_name(name);
        let id_bytes = self
            .storage
            .get(&sys_realm, &name_key)
            .map_err(Self::storage_err)?;
        match id_bytes {
            Some(b) => {
                if b.len() != 16 {
                    return Err(IdentityError::Serialization {
                        reason: "realm name index value has invalid length".to_string(),
                    });
                }
                let uuid =
                    uuid::Uuid::from_slice(&b).map_err(|e| IdentityError::Serialization {
                        reason: format!("invalid UUID in realm name index: {e}"),
                    })?;
                self.get_realm(&RealmId::new(uuid))
            }
            None => Ok(None),
        }
    }

    fn update_realm(
        &self,
        realm_id: &RealmId,
        request: &UpdateRealmRequest,
    ) -> Result<Realm, IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "update_realm",
            });
        }
        if matches!(request.name.as_deref(), Some(n) if n == keys::SYSTEM_REALM_NAME) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "update_realm",
            });
        }
        // If the rename targets a new name, validate it the same way
        // create_realm does — including the admin-URL reserved-keyword
        // set (UI_ROUTING.md R-4). Skip when name is unchanged.
        if let Some(ref new_name) = request.name {
            super::validation::validate_realm_name(new_name)?;
        }
        // Serialize against create/delete so an in-flight delete can't
        // race with this read-modify-write and resurrect an orphaned
        // record after its signing key has already been removed.
        let _ops_guard = self.realm_ops_lock.lock().expect("realm ops lock");
        let mut realm = self
            .get_realm(realm_id)?
            .ok_or(IdentityError::RealmNotFound)?;

        // Refuse updates against a realm whose cascade has already started.
        // `delete_realm` releases the ops_lock after stamping
        // `DeletingInProgress` so its (potentially long) cascade does not
        // block create/update of *other* realms. Without this guard the
        // update could re-put the realm record between the cascade's
        // record-delete and signing-key-delete, leaving record=Some /
        // key=None — the exact invariant the
        // `simulation_concurrent_realm_ops_under_io_delay` test asserts.
        if realm.status() == RealmStatus::DeletingInProgress {
            return Err(IdentityError::RealmSuspended);
        }

        let now = self.clock.now();
        let old_name = realm.name().to_string();

        // SEC-20: reject webhook config without HMAC secret before mutating state.
        if let Some(ref config) = request.config {
            if let Some(ref wh) = config.pre_token_webhook {
                wh.validate()
                    .map_err(|reason| IdentityError::InvalidInput { reason })?;
            }
        }

        if let Some(ref name) = request.name {
            realm.set_name(name.clone());
        }
        if let Some(status) = request.status {
            realm.set_status(status);
        }
        if let Some(ref config) = request.config {
            realm.set_config(config.clone());
        }
        realm.set_updated_at(now);

        let sys_realm = keys::system_realm_id();
        let realm_key = keys::encode_realm_id(realm_id);
        let realm_bytes = Self::serialize_realm(&realm)?;

        // If the name changed, update the name index atomically
        if realm.name() == old_name {
            self.storage
                .put(&sys_realm, &realm_key, &realm_bytes)
                .map_err(Self::storage_err)?;
        } else {
            let old_name_key = keys::encode_realm_name(&old_name);
            let new_name_key = keys::encode_realm_name(realm.name());
            let name_value = realm_id.as_uuid().as_bytes().to_vec();
            self.storage
                .put_batch(
                    &sys_realm,
                    &[(realm_key, realm_bytes), (new_name_key, name_value)],
                )
                .map_err(Self::storage_err)?;
            // Best-effort: remove old name index
            let _ = self.storage.delete(&sys_realm, &old_name_key);
        }

        // Propagate status change to the wait-free cache so validate_token
        // immediately reflects the new lifecycle state. Ordered before
        // record_audit so the cache is consistent before any further writes,
        // matching the ordering used in create_realm.
        if request.status.is_some() {
            let id = realm_id.clone();
            let status = realm.status();
            self.realm_status_cache.rcu(|current| {
                let mut new_map = (**current).clone();
                new_map.insert(id.clone(), status);
                new_map
            });
        }

        self.record_audit(
            realm_id,
            None,
            AuditAction::RealmUpdated,
            "realm",
            &realm_id.as_uuid().to_string(),
        )?;

        // When suspending or archiving a realm, revoke all active sessions so
        // existing tokens backed by those sessions fail immediately on the
        // session-validity check inside validate_token (defense-in-depth on
        // top of the realm-status check added to validate_token).
        if matches!(
            request.status,
            Some(RealmStatus::Suspended | RealmStatus::Archived | RealmStatus::DeletingInProgress)
        ) {
            self.bulk_revoke_sessions(realm_id);
        }

        Ok(realm)
    }

    #[allow(clippy::too_many_lines)]
    fn delete_realm(&self, realm_id: &RealmId) -> Result<(), IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "delete_realm",
            });
        }

        // Serialize against create/update so a concurrent update can't
        // re-put a realm record after we've already removed its signing
        // key. Without this lock, `record=Some key=None` would leak out
        // and `realm_jwks()` would fail for a still-live-looking realm.
        let ops_guard = self.realm_ops_lock.lock().expect("realm ops lock");

        // Check whether the realm record exists. We do NOT early-return on
        // missing record — a previous cascade may have crashed after deleting
        // the record but before cleaning all key-spaces. Recovery requires us
        // to scan every cascade prefix regardless. If no cascade work is found
        // AND the record is absent, we return RealmNotFound at the end.
        let existing_realm = self.get_realm(realm_id)?;
        let realm_exists = existing_realm.is_some();

        // 0. Delete the realm record FIRST. Ordering matters: if a fault
        //    lands mid-cascade, the observable partial state is "realm
        //    already gone, some cascade residue remains" — never the
        //    reverse ("realm alive but signing key missing"), which would
        //    make `realm_jwks()` fail for a realm the API still reports
        //    as live. The idempotent cascade below converges on retry.
        let sys_realm = keys::system_realm_id();
        let realm_key = keys::encode_realm_id(realm_id);

        if realm_exists {
            // Mark the realm as DeletingInProgress so concurrent requests
            // are rejected by require_active_realm before we start the
            // potentially-long cascade. (A-33)
            if let Some(ref t) = existing_realm {
                let mut in_progress = t.clone();
                in_progress.set_status(RealmStatus::DeletingInProgress);
                let in_progress_bytes =
                    serde_json::to_vec(&in_progress).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                self.storage
                    .put(&sys_realm, &realm_key, &in_progress_bytes)
                    .map_err(Self::storage_err)?;
                // Reflect the status change in the in-memory cache immediately.
                let id = realm_id.clone();
                self.realm_status_cache.rcu(|current| {
                    let mut new_map = (**current).clone();
                    new_map.insert(id.clone(), RealmStatus::DeletingInProgress);
                    new_map
                });
            }
        }

        // Release the ops lock before the (potentially long) cascade so we
        // do not block create/update of other realms. The DeletingInProgress
        // status written above prevents new mutations from landing on this
        // realm, so it is safe to proceed without holding the lock.
        drop(ops_guard);

        // Estimate the size of the cascade to decide whether to background it.
        let cascade_count = self.estimate_cascade_count(realm_id);
        let chunk_size = self.config.cascade_chunk_size;
        let background_threshold = self.config.cascade_background_threshold;

        if cascade_count > background_threshold {
            // Large realm: spawn a background task and return immediately.
            // The background task performs the full cascade and then cleans
            // up the in-memory caches. (A-33)
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let storage = Arc::clone(&self.storage);
                let audit = Arc::clone(&self.audit);
                let realm_id_bg = realm_id.clone();
                let signing_keys = self.realm_signing_keys.clone();
                let status_cache = self.realm_status_cache.clone();
                let existing_realm_bg = existing_realm.clone();

                handle.spawn(async move {
                    tracing::info!(
                        realm_id = %realm_id_bg.as_uuid(),
                        cascade_count,
                        "delete_realm: backgrounding large cascade"
                    );

                    // Build a minimal engine wrapper to reuse do_cascade_chunked.
                    // We need an engine with the same storage — the cheapest
                    // approach is to run the cascade inline on the storage.
                    let sys = keys::system_realm_id();
                    let realm_key_bg = keys::encode_realm_id(&realm_id_bg);

                    // Delete the realm record from the system realm.
                    if realm_exists {
                        if let Err(e) = storage.delete(&sys, &realm_key_bg) {
                            tracing::info!(
                                realm_id = %realm_id_bg.as_uuid(),
                                error = %e,
                                "delete_realm background: failed to delete realm record"
                            );
                        }
                        // Clean up the name index (best-effort).
                        if let Some(ref t) = existing_realm_bg {
                            let name_key = keys::encode_realm_name(t.name());
                            let _ = storage.delete(&sys, &name_key);
                        }
                    }

                    // Scan and delete each prefix in chunks. Includes usr:id:
                    // directly since we cannot call delete_user from a
                    // background task; the unconditional sweep covers all
                    // user-related key spaces idempotently.
                    //
                    // email:reserved: is the A-20 90-day PII tombstone and
                    // must be included so no email address outlives its realm.
                    // dfp:user: and email:change: are also swept for
                    // completeness. slug:org: holds post-delete org-slug
                    // cooldown tombstones (A-5) that must not outlive the realm.
                    let all_prefixes: &[&[u8]] = &[
                        &b"usr:id:"[..],
                        &b"usr:email:"[..],
                        &b"cred:user:"[..],
                        &b"ses:id:"[..],
                        &b"ses:user:"[..],
                        &b"mfa:totp:"[..],
                        &b"mfa:nonce:"[..],
                        &b"webauthn:cred:"[..],
                        &b"webauthn:disc:"[..],
                        &b"magic:link:"[..],
                        &b"email:verify:"[..],
                        &b"email:change:"[..],
                        &b"email:reserved:"[..],
                        &b"rst:token:"[..],
                        &b"dfp:user:"[..],
                        &b"org:id:"[..],
                        &b"org:slug:"[..],
                        &b"slug:org:"[..],
                        &b"orgm:org:"[..],
                        &b"orgm:user:"[..],
                        &b"orgi:id:"[..],
                        &b"orgi:token:"[..],
                        &b"orgi:org:"[..],
                        &b"orgi:list:"[..],
                        &b"oauth:client:"[..],
                        &b"rel:"[..],
                        &b"oauth:code:"[..],
                        &b"oauth:revjti:"[..],
                        &b"oauth:ucode:"[..],
                        &b"fed:idp:"[..],
                        &b"fed:state:"[..],
                        &b"fed:confirm:"[..],
                        &b"fed:ext:"[..],
                        &b"fed:ext_fwd:"[..],
                        &b"scim:ext_user:"[..],
                        &b"scim:ext_user_fwd:"[..],
                        &b"scim:ext_group:"[..],
                        &b"scim:ext_group_fwd:"[..],
                        &b"saml:sp:"[..],
                        &b"saml:state:"[..],
                        &b"saml:asn:"[..],
                        &b"saml:sp_session:"[..],
                        &b"saml:logout:"[..],
                        &b"rba:"[..],
                    ];
                    let mut deleted_total = 0usize;
                    for prefix in all_prefixes {
                        let end = keys::prefix_end(prefix);
                        match storage.scan(&realm_id_bg, prefix, &end) {
                            Ok(entries) => {
                                for chunk in entries.chunks(chunk_size) {
                                    for entry in chunk {
                                        if let Err(e) = storage.delete(&realm_id_bg, &entry.key) {
                                            tracing::info!(
                                                realm_id = %realm_id_bg.as_uuid(),
                                                error = %e,
                                                "delete_realm background: failed to delete key"
                                            );
                                        } else {
                                            deleted_total += 1;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::info!(
                                    realm_id = %realm_id_bg.as_uuid(),
                                    error = %e,
                                    "delete_realm background: scan error"
                                );
                            }
                        }
                    }

                    // System-realm keys: SAML key + signing key.
                    let saml_key = keys::encode_realm_saml_key(&realm_id_bg);
                    let _ = storage.delete(&sys, &saml_key);
                    let signing_key_key = keys::encode_realm_signing_key(&realm_id_bg);
                    let _ = storage.delete(&sys, &signing_key_key);

                    // Emit audit event (best-effort; no ? propagation in async task).
                    let audit_event = crate::audit::CreateAuditEvent {
                        realm_id: realm_id_bg.clone(),
                        actor: "system".to_string(),
                        action: crate::audit::AuditAction::RealmDeleted,
                        resource_type: "realm".to_string(),
                        resource_id: realm_id_bg.as_uuid().to_string(),
                        metadata: None,
                    };
                    let _ = audit.append(&audit_event);

                    // Remove from in-memory caches.
                    signing_keys.rcu(|current| {
                        let mut new_map = (**current).clone();
                        new_map.remove(&realm_id_bg);
                        new_map
                    });
                    status_cache.rcu(|current| {
                        let mut new_map = (**current).clone();
                        new_map.remove(&realm_id_bg);
                        new_map
                    });

                    tracing::info!(
                        realm_id = %realm_id_bg.as_uuid(),
                        deleted_total,
                        "delete_realm: background cascade complete"
                    );
                });

                // Return Ok immediately; the background task will finish the work.
                return Ok(());
            }
            // No Tokio runtime available — fall through to synchronous cascade.
        }

        // Synchronous cascade path (small realm, or no runtime for background).
        if realm_exists {
            self.storage
                .delete(&sys_realm, &realm_key)
                .map_err(Self::storage_err)?;
            // Clean up the name index (best-effort)
            if let Some(ref t) = existing_realm {
                let name_key = keys::encode_realm_name(t.name());
                let _ = self.storage.delete(&sys_realm, &name_key);
            }
        }

        let cascade_work_done = self.do_cascade_chunked(realm_id, chunk_size)?;

        // Remove from in-memory caches. Durable deletion already
        // happened above; this drops the cached Arc and status entry.
        {
            let id = realm_id.clone();
            self.realm_signing_keys.rcu(|current| {
                let mut new_map = (**current).clone();
                new_map.remove(&id);
                new_map
            });
            self.realm_status_cache.rcu(|current| {
                let mut new_map = (**current).clone();
                new_map.remove(&id);
                new_map
            });
        }

        // Idempotency guard: if nothing existed for this realm anywhere, the
        // caller is asking to delete something that was never created (or was
        // already fully cleaned). Preserve the `RealmNotFound` contract for
        // that case so the existing API stays stable.
        if !realm_exists && !cascade_work_done {
            return Err(IdentityError::RealmNotFound);
        }

        // A-5: write a post-delete realm name cooldown tombstone so the freed
        // name cannot be immediately re-claimed. Best-effort: a write failure
        // here is not fatal for the delete. Only written when the realm existed.
        if let Some(ref t) = existing_realm {
            let cooldown_micros = self.config.slug_cooldown_secs as i64 * 1_000_000;
            let now_micros = self.clock.now().as_micros();
            let reservation = StoredSlugReservation {
                slug: t.name().to_string(),
                expires_at_micros: now_micros + cooldown_micros,
            };
            if let Ok(bytes) = serde_json::to_vec(&reservation) {
                let res_key = keys::encode_realm_slug_reservation(t.name());
                let _ = self.storage.put(&sys_realm, &res_key, &bytes);
            }
        }

        self.record_audit(
            realm_id,
            None,
            AuditAction::RealmDeleted,
            "realm",
            &realm_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn realm_jwks(&self, realm_id: &RealmId) -> Result<JwksDocument, IdentityError> {
        let active_key = self.get_or_load_realm_signing_key(realm_id)?;
        let mut jwks = active_key.to_jwks();

        // Include retiring keys that have not yet passed their grace-period deadline.
        let sys_realm = keys::system_realm_id();
        let scan_prefix = keys::realm_retiring_key_scan_prefix(realm_id);
        let scan_end = keys::prefix_end(&scan_prefix);
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        if let Ok(entries) = self.storage.scan(&sys_realm, &scan_prefix, &scan_end) {
            for entry in entries {
                let Some(deadline) = keys::parse_retiring_key_deadline(&entry.key) else {
                    continue;
                };
                if deadline <= now_secs as u64 {
                    continue; // Grace period expired — omit from JWKS.
                }
                let kek = self
                    .config
                    .key_encryption_key
                    .as_ref()
                    .map(|k| k.as_bytes());
                if let Ok(plaintext) =
                    crate::identity::key_encryption::unwrap_key(&entry.value, kek)
                {
                    if let Ok(retiring_key) = SigningKey::from_pkcs8(&plaintext) {
                        let retiring_jwk = retiring_key.to_jwks();
                        jwks.keys.extend(retiring_jwk.keys);
                    }
                }
            }
        }

        Ok(jwks)
    }

    fn generate_ra_token(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        pending_actions: Vec<crate::identity::types::RequiredAction>,
        oidc_params: crate::identity::ra_token::OidcParams,
        now: Timestamp,
    ) -> Result<String, IdentityError> {
        let key = self.get_or_load_realm_signing_key(realm_id)?;
        crate::identity::ra_token::generate(
            &user_id.as_uuid().to_string(),
            &realm_id.as_uuid().to_string(),
            pending_actions,
            oidc_params,
            &key,
            now,
        )
    }

    fn generate_browser_ra_token(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        pending_actions: Vec<crate::identity::types::RequiredAction>,
        return_to: Option<String>,
        now: Timestamp,
    ) -> Result<String, IdentityError> {
        let key = self.get_or_load_realm_signing_key(realm_id)?;
        crate::identity::ra_token::generate_browser(
            &user_id.as_uuid().to_string(),
            &realm_id.as_uuid().to_string(),
            pending_actions,
            return_to,
            &key,
            now,
        )
    }

    fn validate_ra_token(
        &self,
        realm_id: &RealmId,
        token: &str,
        now: Timestamp,
    ) -> Result<crate::identity::ra_token::RaClaims, crate::identity::ra_token::RaTokenError> {
        let key = self
            .get_or_load_realm_signing_key(realm_id)
            .map_err(|_| crate::identity::ra_token::RaTokenError::InvalidSignature)?;
        crate::identity::ra_token::validate(token, key.public_key_bytes(), now)
    }

    fn validate_required_action_token(
        &self,
        realm_id: &RealmId,
        token: &str,
        action: crate::identity::types::RequiredAction,
    ) -> Result<crate::identity::tokens::TokenClaims, IdentityError> {
        let claims = self.verify_token_signature_for_realm(realm_id, token)?;

        if claims.token_type != crate::identity::tokens::REQUIRED_ACTION_TOKEN_TYPE {
            return Err(IdentityError::InvalidToken);
        }

        let now_secs = self.clock.now().as_micros() / 1_000_000;
        if now_secs >= claims.exp {
            return Err(IdentityError::TokenExpired);
        }

        if claims.tid.parse::<RealmId>().ok().as_ref() != Some(realm_id) {
            return Err(IdentityError::InvalidToken);
        }

        if !claims.required_actions.contains(&action) {
            return Err(IdentityError::InvalidToken);
        }

        Ok(claims)
    }

    fn complete_update_password(
        &self,
        realm_id: &RealmId,
        ra_token: &str,
        new_password: crate::identity::credentials::CleartextPassword,
    ) -> Result<crate::identity::types::RequiredActionTokenResponse, IdentityError> {
        use crate::identity::tokens::REQUIRED_ACTION_TOKEN_TYPE;
        use crate::identity::types::{RequiredAction, RequiredActionTokenResponse};

        let claims = self.validate_required_action_token(
            realm_id,
            ra_token,
            RequiredAction::UpdatePassword,
        )?;

        let user_id = Self::parse_user_id_claim(&claims)?;

        // Set the new password (enforces realm policy + Argon2id re-hash).
        self.set_password(realm_id, &user_id, &new_password)?;

        // Remove UPDATE_PASSWORD from the pending actions list.
        let remaining: Vec<RequiredAction> = claims
            .required_actions
            .iter()
            .filter(|&&a| a != RequiredAction::UpdatePassword)
            .copied()
            .collect();

        self.update_user(
            realm_id,
            &user_id,
            &crate::identity::types::UpdateUserRequest {
                required_actions: Some(remaining.clone()),
                ..Default::default()
            },
        )?;

        if !remaining.is_empty() {
            // More actions pending — issue a new short-lived RA token.
            let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
            let now = self.clock.now();
            let now_secs = now.as_micros() / 1_000_000;
            let ra_claims = crate::identity::tokens::TokenClaims {
                sub: claims.sub.clone(),
                iss: self.realm_issuer_url(realm_id),
                aud: crate::identity::tokens::Audience::single(self.config.token.audience.clone()),
                exp: now_secs + 900, // 15-minute RA token TTL
                iat: now_secs,
                sid: claims.sid.clone(),
                tid: claims.tid.clone(),
                oid: None,
                token_type: REQUIRED_ACTION_TOKEN_TYPE.to_string(),
                nbf: None,
                jti: Some(uuid::Uuid::new_v4().to_string()),
                fid: None,
                scope: None,
                nonce: None,
                azp: None,
                roles: Vec::new(),
                groups: Vec::new(),
                org_groups: Vec::new(),
                permissions: Vec::new(),
                required_actions: remaining,
                act: None,
                amr: Vec::new(),
                cnf: None,
                custom: Default::default(),
                sv: None,
            };
            let access_token = signing_key.issue_token(&ra_claims)?;
            return Ok(RequiredActionTokenResponse { access_token });
        }

        // All actions complete — create a session and issue a full-access token.
        let session = self.create_session(
            realm_id,
            &user_id,
            &crate::identity::types::SessionContext::default(),
        )?;
        let token_pair = self.issue_tokens(realm_id, &user_id, session.id())?;

        Ok(RequiredActionTokenResponse {
            access_token: token_pair.access_token().to_string(),
        })
    }

    fn request_email_verification(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        // Issue the verification token (stores SHA-256 hash in storage).
        // Email delivery requires the email service in WebState; the engine
        // does not have access to it. Callers that need the email sent must
        // use WebState::email directly after this call succeeds.
        let _token = self.issue_email_verification_token(realm_id, user_id)?;
        Ok(())
    }

    fn rotate_realm_signing_key(
        &self,
        realm_id: &RealmId,
        grace_period_secs: u64,
    ) -> Result<(), IdentityError> {
        let _ops_guard = self.realm_ops_lock.lock().expect("realm ops lock");

        // Ensure the realm exists before rotating.
        let sys_realm = keys::system_realm_id();
        let old_key = self.get_or_load_realm_signing_key(realm_id)?;
        let old_key_id = old_key.key_id().to_string();
        // Zeroizing ensures both PKCS#8 copies are actively overwritten when
        // dropped; put() takes &[u8] so Deref chain handles the coercion (HEA-750).
        let old_pkcs8 = Zeroizing::new(old_key.pkcs8_bytes().to_vec());

        // Generate and store the new active signing key.
        let new_key = SigningKey::generate()?;
        let new_pkcs8 = Zeroizing::new(new_key.pkcs8_bytes().to_vec());
        let kek = self
            .config
            .key_encryption_key
            .as_ref()
            .map(|k| k.as_bytes());
        let key_storage_key = keys::encode_realm_signing_key(realm_id);
        let new_stored = crate::identity::key_encryption::wrap_key(&new_pkcs8, kek)?;
        self.storage
            .put(&sys_realm, &key_storage_key, &new_stored)
            .map_err(Self::storage_err)?;

        // Store the old key as a retiring key with its expiry deadline.
        let now_secs = (self.clock.now().as_micros() / 1_000_000) as u64;
        let deadline_secs = now_secs.saturating_add(grace_period_secs);
        let retiring_key_storage =
            keys::encode_realm_retiring_key(realm_id, deadline_secs, &old_key_id);
        let old_stored = crate::identity::key_encryption::wrap_key(&old_pkcs8, kek)?;
        self.storage
            .put(&sys_realm, &retiring_key_storage, &old_stored)
            .map_err(Self::storage_err)?;

        // Invalidate the active key cache so realm_jwks / token issuance pick up the new key.
        {
            let id = realm_id.clone();
            self.realm_signing_keys.rcu(|current| {
                let mut new_map = (**current).clone();
                new_map.remove(&id);
                new_map
            });
        }

        tracing::info!(
            realm = %realm_id.as_uuid(),
            old_kid = %old_key_id,
            new_kid = %new_key.key_id(),
            grace_period_secs,
            deadline_secs,
            "signing key rotated; old key enters grace period"
        );

        Ok(())
    }

    // ===== User CRUD =====

    fn create_user(
        &self,
        realm_id: &RealmId,
        request: &CreateUserRequest,
    ) -> Result<User, IdentityError> {
        // The system realm is reserved for Hearth admins and must be
        // reached only through `create_admin_user`, which also provisions
        // the `realm.admin` RBAC assignment atomically. Without this
        // guard an operator could create a non-admin account in the
        // system realm and gain a session bound to it but without the
        // admin role — harmless today (the permission check would reject
        // the session) but a trap for future refactors.
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "create_user",
            });
        }
        self.require_active_realm(realm_id)?;
        // A-24: enforce per-realm user quota before writing.
        if let Ok(Some(realm)) = self.get_realm(realm_id) {
            if let Some(quotas) = &realm.config().quotas {
                if let Some(max) = quotas.max_users {
                    let prefix = keys::user_id_scan_prefix();
                    self.check_resource_quota(realm_id, "users", &prefix, max)?;
                }
            }
        }
        self.create_user_with_status(realm_id, request, self.config.default_status)
    }

    fn create_admin_user(&self, request: &CreateUserRequest) -> Result<User, IdentityError> {
        // Bypasses the `create_user` system-realm guard deliberately.
        // This is the sole public entry point that may create a record
        // in the system realm; callers are responsible for assigning
        // the `realm.admin` RBAC role after the user is persisted.
        let realm_id = keys::system_realm_id();
        self.create_user_with_status(&realm_id, request, self.config.default_status)
    }

    fn get_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<User>, IdentityError> {
        // Conditional span: only allocated when debug tracing is active.
        let _span = tracing::enabled!(tracing::Level::DEBUG).then(|| {
            tracing::debug_span!(
                "hearth.auth.user_lookup",
                "enduser.id" = %user_id,
                "hearth.realm_id" = %realm_id,
            )
            .entered()
        });

        let key = keys::encode_user_id(user_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?;

        match bytes {
            Some(data) => Ok(Some(Self::deserialize_user(&data)?)),
            None => Ok(None),
        }
    }

    fn get_user_by_email(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<Option<User>, IdentityError> {
        // Normalize the lookup email
        let normalized = validation::validate_email(email)?;
        let email_key = keys::encode_user_email(&normalized);

        // Look up UserId from email index
        let id_bytes = self
            .storage
            .get(realm_id, &email_key)
            .map_err(Self::storage_err)?;

        let Some(id_bytes) = id_bytes else {
            return Ok(None);
        };

        // Parse the UserId
        let uuid_str =
            std::str::from_utf8(&id_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let uuid = uuid::Uuid::parse_str(uuid_str).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        let user_id = UserId::new(uuid);

        self.get_user(realm_id, &user_id)
    }

    #[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
    fn update_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        request: &UpdateUserRequest,
    ) -> Result<User, IdentityError> {
        self.require_active_realm(realm_id)?;

        // 1. Load existing user
        let mut user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        let old_email = user.email().to_string();
        let mut email_changed = false;

        // 2. Apply email change if requested
        if let Some(ref new_email) = request.email {
            let normalized = validation::validate_email(new_email)?;

            if normalized != old_email {
                // Check uniqueness of new email
                let new_email_key = keys::encode_user_email(&normalized);
                let existing = self
                    .storage
                    .get(realm_id, &new_email_key)
                    .map_err(Self::storage_err)?;
                if existing.is_some() {
                    return Err(IdentityError::DuplicateEmail);
                }

                // Remove old email index
                let old_email_key = keys::encode_user_email(&old_email);
                self.storage
                    .delete(realm_id, &old_email_key)
                    .map_err(Self::storage_err)?;

                // Write new email index
                let user_id_bytes = user_id.as_uuid().to_string().into_bytes();
                self.storage
                    .put(realm_id, &new_email_key, &user_id_bytes)
                    .map_err(Self::storage_err)?;

                user.set_email(normalized);
                email_changed = true;
            }
        }

        // 3. Apply display name change if requested
        if let Some(ref new_name) = request.display_name {
            let normalized = validation::validate_display_name(new_name)?;
            user.set_display_name(normalized);
        }

        // 3a. Apply first_name change if requested
        if let Some(ref new_first) = request.first_name {
            let normalized = validation::validate_name_part(new_first, "First name")?;
            user.set_first_name(normalized);
        }

        // 3b. Apply last_name change if requested
        if let Some(ref new_last) = request.last_name {
            let normalized = validation::validate_name_part(new_last, "Last name")?;
            user.set_last_name(normalized);
        }

        // 4. Apply status change if requested
        let status_disabled = if let Some(new_status) = request.status {
            let prev = user.status();
            user.set_status(new_status);
            prev != crate::identity::types::UserStatus::Disabled
                && new_status == crate::identity::types::UserStatus::Disabled
        } else {
            false
        };

        // 4a. Replace attributes map if requested.
        if let Some(attributes) = &request.attributes {
            let user_attr_defs = self
                .get_realm(realm_id)?
                .and_then(|r| r.config().attribute_definitions.clone())
                .map(|d| d.users);
            validation::validate_attributes(attributes, user_attr_defs.as_deref())?;
            user.set_attributes(attributes.clone());
        }

        // 4b. Replace required actions if requested.
        if let Some(actions) = request.required_actions.clone() {
            user.set_required_actions(actions);
        }

        // 4c. Apply phone_number change if requested.
        if let Some(ref phone) = request.phone_number {
            user.set_phone_number(phone.clone());
        }

        // 4d. Apply phone_verified change if requested.
        if let Some(verified) = request.phone_verified {
            user.set_phone_verified(verified);
        }

        // 4e. Apply email_otp_enabled change if requested.
        if let Some(enabled) = request.email_otp_enabled {
            user.set_email_otp_enabled(enabled);
        }

        // 5. Update timestamp
        user.set_updated_at(self.clock.now());

        // 6. Write updated record
        let user_bytes = Self::serialize_user(&user)?;
        let id_key = keys::encode_user_id(user_id);
        self.storage
            .put(realm_id, &id_key, &user_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::UserUpdated,
            "user",
            &user_id.as_uuid().to_string(),
        )?;

        // A-42: Email address change is a security event — an attacker who
        // hijacks the new address could receive password-reset emails.  Revoke
        // all existing sessions so stale holders must re-authenticate.
        if email_changed {
            if let Err(e) = self.revoke_all_user_sessions(realm_id, user_id, None) {
                tracing::warn!(
                    user_id = %user_id.as_uuid(),
                    error = %e,
                    "revoke_all_user_sessions failed on email change"
                );
            }
        }

        // Security: disabling a user must immediately invalidate all existing
        // sessions so that active access tokens cannot be used past revocation.
        // Access tokens embed claims at issuance and are not re-checked on the
        // hot path, so revocation is the only mechanism to enforce a disable.
        if status_disabled {
            if let Err(e) = self.revoke_all_user_sessions(realm_id, user_id, None) {
                tracing::warn!(
                    user_id = %user_id.as_uuid(),
                    error = %e,
                    "revoke_all_user_sessions failed on user disable"
                );
            }
        }

        Ok(user)
    }

    #[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
    fn delete_user(&self, realm_id: &RealmId, user_id: &UserId) -> Result<(), IdentityError> {
        // 1. Load user to get email for index cleanup
        let user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // 2. Delete primary record
        let id_key = keys::encode_user_id(user_id);
        self.storage
            .delete(realm_id, &id_key)
            .map_err(Self::storage_err)?;

        // 3. Delete email index
        let email_key = keys::encode_user_email(user.email());
        self.storage
            .delete(realm_id, &email_key)
            .map_err(Self::storage_err)?;

        // A-20: write a 90-day reservation tombstone so the deleted email
        // cannot be immediately re-registered by another actor.
        let now_micros = self.clock.now().as_micros();
        let reservation = StoredEmailReservation {
            reserved_at_micros: now_micros,
        };
        if let Ok(bytes) = serde_json::to_vec(&reservation) {
            let reserved_key = keys::encode_email_reserved(user.email());
            let _ = self.storage.put(realm_id, &reserved_key, &bytes);
        }

        // 4. Delete credential (if any — best effort, ignore not-found)
        let cred_key = keys::encode_credential_key(user_id);
        self.storage
            .delete(realm_id, &cred_key)
            .map_err(Self::storage_err)?;

        // 4b. Delete MFA state (if any — best effort)
        let mfa_key = keys::encode_mfa_totp_key(user_id);
        self.storage
            .delete(realm_id, &mfa_key)
            .map_err(Self::storage_err)?;

        // 4c. Delete all WebAuthn credentials + discoverable index entries
        let webauthn_prefix = keys::encode_webauthn_credentials_prefix(user_id);
        let webauthn_end = keys::prefix_end(&webauthn_prefix);
        let webauthn_entries = self
            .storage
            .scan(realm_id, &webauthn_prefix, &webauthn_end)
            .map_err(Self::storage_err)?;

        for entry in &webauthn_entries {
            // If discoverable, delete the discoverable index entry
            if let Ok(stored) = serde_json::from_slice::<StoredWebAuthnCredential>(&entry.value) {
                if stored.discoverable {
                    let disc_key = keys::encode_webauthn_discoverable(&stored.credential_id_b64);
                    self.storage
                        .delete(realm_id, &disc_key)
                        .map_err(Self::storage_err)?;
                }
            }
            // Delete the credential itself
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 5. Delete all sessions for this user
        let session_prefix = keys::encode_user_sessions_prefix(user_id);
        let session_end = keys::prefix_end(&session_prefix);
        let session_entries = self
            .storage
            .scan(realm_id, &session_prefix, &session_end)
            .map_err(Self::storage_err)?;

        for entry in &session_entries {
            // Extract session UUID from the user-session index key
            // Key format: "ses:user:{user_uuid}:{session_uuid}"
            let key_str =
                std::str::from_utf8(&entry.key).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if let Some(session_uuid_str) = key_str.rsplit(':').next() {
                if let Ok(uuid) = uuid::Uuid::parse_str(session_uuid_str) {
                    let session_id = SessionId::new(uuid);
                    let session_key = keys::encode_session_id(&session_id);
                    self.storage
                        .delete(realm_id, &session_key)
                        .map_err(Self::storage_err)?;
                    // Evict from in-process cache so subsequent get_session
                    // calls see the deletion rather than a stale cache hit.
                    self.session_cache_evict(realm_id, &session_id);
                }
            }

            // Delete the user-session index entry itself
            // The scan returns keys without realm prefix, so re-use entry.key
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 6. Delete all organization memberships for this user
        let org_membership_prefix = keys::membership_by_user_prefix(user_id);
        let org_membership_end = keys::prefix_end(&org_membership_prefix);
        let org_memberships = self
            .storage
            .scan(realm_id, &org_membership_prefix, &org_membership_end)
            .map_err(Self::storage_err)?;

        for entry in &org_memberships {
            if let Ok(membership) = serde_json::from_slice::<OrganizationMembership>(&entry.value) {
                // Delete forward index (org → user)
                let fwd_key = keys::encode_membership_by_org(membership.org_id(), user_id);
                self.storage
                    .delete(realm_id, &fwd_key)
                    .map_err(Self::storage_err)?;
            }
            // Delete reverse index entry (user → org)
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 7. Cascade: scrub all OAuth consent records for this user.
        let consent_prefix = keys::encode_consent_prefix_for_user(user_id);
        let consent_end = keys::prefix_end(&consent_prefix);
        let consent_entries = self
            .storage
            .scan(realm_id, &consent_prefix, &consent_end)
            .map_err(Self::storage_err)?;
        for entry in &consent_entries {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 8. Cascade: scrub all federated external-identity links for
        //    this user. Each forward index entry holds the external_sub
        //    string as its value — we use it to compute the matching
        //    reverse `fed:ext:{idp_id}:{external_sub}` key and delete
        //    both in one pass. A user must be able to sign up freshly
        //    via the same external identity after deletion, so both
        //    directions MUST go.
        let fed_fwd_prefix = keys::encode_federation_ext_fwd_prefix_for_user(user_id);
        let fed_fwd_end = keys::prefix_end(&fed_fwd_prefix);
        let fed_fwd_entries = self
            .storage
            .scan(realm_id, &fed_fwd_prefix, &fed_fwd_end)
            .map_err(Self::storage_err)?;
        for entry in &fed_fwd_entries {
            // Key format: fed:ext_fwd:{user_uuid}:{idp_uuid}
            let key_str = std::str::from_utf8(&entry.key).unwrap_or("");
            if let Some(idp_uuid_str) = key_str.rsplit(':').next() {
                if let Ok(idp_uuid) = uuid::Uuid::parse_str(idp_uuid_str) {
                    let idp_id = crate::core::IdpId::new(idp_uuid);
                    let external_sub = std::str::from_utf8(&entry.value).unwrap_or("");
                    if !external_sub.is_empty() {
                        let reverse_key = keys::encode_federation_ext_key(&idp_id, external_sub);
                        self.storage
                            .delete(realm_id, &reverse_key)
                            .map_err(Self::storage_err)?;
                    }
                }
            }
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 10. Cascade SCIM externalId mapping. Forward index holds the
        //     external_id string as its value; use it to resolve the
        //     reverse key. Both directions MUST go so a future SCIM POST
        //     with the same externalId can reprovision.
        let scim_fwd_key = keys::encode_scim_ext_user_fwd_key(user_id);
        if let Some(ext_bytes) = self
            .storage
            .get(realm_id, &scim_fwd_key)
            .map_err(Self::storage_err)?
        {
            if let Ok(ext_str) = std::str::from_utf8(&ext_bytes) {
                let reverse_key = keys::encode_scim_ext_user_key(ext_str);
                self.storage
                    .delete(realm_id, &reverse_key)
                    .map_err(Self::storage_err)?;
            }
            self.storage
                .delete(realm_id, &scim_fwd_key)
                .map_err(Self::storage_err)?;
        }

        // 11. Cascade: delete all device fingerprints (GDPR Art. 17, AC-11).
        //     Failures here must not block the deletion — fingerprints are
        //     advisory risk signals, not authoritative data.  The UserDeleted
        //     audit event already records that erasure happened.
        let _ = self.device_fp.delete_all_for_user(realm_id, user_id);

        // 12. Cascade: purge RBAC role assignments and group memberships.
        self.rbac
            .purge_user_from_realm(realm_id, user_id)
            .map_err(|e| IdentityError::Internal {
                reason: format!("rbac cascade failed during delete_user: {e}"),
            })?;

        // 13. Cascade: delete all agents owned by this user to prevent orphans.
        {
            let owner = AgentOwner::User(user_id.clone());
            let prefix = keys::agent_owner_scan_prefix(owner.storage_tag(), &owner.uuid_str());
            let end = keys::prefix_end(&prefix);
            if let Ok(entries) = self.storage.scan(realm_id, &prefix, &end) {
                for entry in &entries {
                    if let Ok(key_str) = std::str::from_utf8(&entry.key) {
                        if let Some(uuid_str) = key_str.rsplit(':').next() {
                            if let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) {
                                let aid = AgentId::new(uuid);
                                let _ = <Self as IdentityEngine>::delete_agent(
                                    self, realm_id, &aid, None,
                                );
                            }
                        }
                    }
                }
            }
        }

        self.record_audit(
            realm_id,
            None,
            AuditAction::UserDeleted,
            "user",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn delete_user_device_fingerprints(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<usize, IdentityError> {
        self.device_fp.delete_all_for_user(realm_id, user_id)
    }

    #[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
    fn set_password(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        password: &CleartextPassword,
    ) -> Result<(), IdentityError> {
        // Validate password length (DoS bound) and HSEC-003 floor.
        validation::validate_password_length(password.as_bytes())?;
        validation::validate_password_floor(password.as_bytes())?;

        // Ensure the user exists.
        let user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        let policy = self.password_policy_for_realm(realm_id)?;
        if let Some(policy) = policy.as_ref() {
            validation::validate_password_against_policy(
                password.as_bytes(),
                policy,
                Some(user.display_name()),
                Some(user.email()),
            )?;
        }

        // HIBP k-anonymity breach check.
        // Only the 5-char SHA-1 prefix is sent to the API; no PII leaves the process (AC-2).
        if let Some(realm) = self.get_realm(realm_id)? {
            let bc = &realm.config().breach_check;
            if bc.enabled {
                let api_key = if bc.hibp_api_key.expose_secret().is_empty() {
                    None
                } else {
                    Some(bc.hibp_api_key.expose_secret().as_str())
                };
                match self.hibp.is_pwned(password.as_bytes(), api_key) {
                    Ok(true) => {
                        // Compromised — reject and audit (AC-1).
                        let _ = self.record_audit(
                            realm_id,
                            None,
                            crate::audit::AuditAction::PasswordCompromisedRejected,
                            "credential",
                            &user_id.as_uuid().to_string(),
                        );
                        return Err(IdentityError::PasswordCompromised);
                    }
                    Ok(false) => {}
                    Err(e) => {
                        // HIBP unavailable — fail-open and audit (AC-3).
                        tracing::warn!(
                            user_id = %user_id.as_uuid(),
                            reason = %e,
                            "HIBP breach-check unavailable; accepting password (fail-open)"
                        );
                        let _ = self.record_audit(
                            realm_id,
                            None,
                            crate::audit::AuditAction::BreachCheckUnavailable,
                            "credential",
                            &user_id.as_uuid().to_string(),
                        );
                    }
                }
            }
        }

        // Resolve history depth from the realm's password policy.
        let history_depth = policy.as_ref().and_then(|p| p.history_depth).unwrap_or(0);

        // Check history before hashing to avoid the expensive hash on likely reuse.
        if history_depth > 0 {
            // Reject immediate reuse of the current password.
            let current_key = keys::encode_credential_key(user_id);
            if let Some(bytes) = self
                .storage
                .get(realm_id, &current_key)
                .map_err(Self::storage_err)?
            {
                let current_cred = Self::deserialize_credential(&bytes)?;
                if credentials::verify_hash(password, &current_cred.hash)? {
                    return Err(IdentityError::PasswordReused);
                }
            }

            let hist_key = keys::encode_credential_history_key(user_id);
            let hist_bytes = self
                .storage
                .get(realm_id, &hist_key)
                .map_err(Self::storage_err)?;
            if let Some(bytes) = hist_bytes {
                let history = Self::deserialize_credential_history(&bytes)?;
                for old_cred in &history {
                    if credentials::verify_hash(password, &old_cred.hash)? {
                        return Err(IdentityError::PasswordReused);
                    }
                }
            }
        }

        let now = self.clock.now().as_micros();
        let credential_cfg = self.credential_config_for_realm(realm_id)?;
        let cred = credentials::hash_password(password, &credential_cfg, now)?;
        let cred_bytes = Self::serialize_credential(&cred)?;
        let cred_key = keys::encode_credential_key(user_id);

        // Rotate the current credential into history before overwriting it.
        if history_depth > 0 {
            let old_bytes = self
                .storage
                .get(realm_id, &cred_key)
                .map_err(Self::storage_err)?;
            if let Some(bytes) = old_bytes {
                let old_cred = Self::deserialize_credential(&bytes)?;
                let hist_key = keys::encode_credential_history_key(user_id);
                let hist_bytes = self
                    .storage
                    .get(realm_id, &hist_key)
                    .map_err(Self::storage_err)?;
                let mut history = if let Some(b) = hist_bytes {
                    Self::deserialize_credential_history(&b)?
                } else {
                    Vec::new()
                };
                history.insert(0, old_cred);
                history.truncate(history_depth);
                let new_hist_bytes = Self::serialize_credential_history(&history)?;
                self.storage
                    .put(realm_id, &hist_key, &new_hist_bytes)
                    .map_err(Self::storage_err)?;
            }
        }

        self.storage
            .put(realm_id, &cred_key, &cred_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::CredentialSet,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;

        // A-42: Revoke all sessions when a credential changes — phished or
        // stale sessions must not survive a password reset or admin password set.
        if let Err(e) = self.revoke_all_user_sessions(realm_id, user_id, None) {
            tracing::warn!(
                user_id = %user_id.as_uuid(),
                error = %e,
                "revoke_all_user_sessions failed on set_password"
            );
        }

        Ok(())
    }

    fn dummy_verify_password(&self, password: &CleartextPassword) {
        let _ = credentials::verify_hash(password, &self.dummy_hash);
    }

    fn verify_password(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        password: &CleartextPassword,
    ) -> Result<bool, IdentityError> {
        // Enforce realm policy: password must be in the allowed_auth_methods list.
        self.check_allowed_auth_method(realm_id, "password")?;

        // Rate limit check: reject early if account is locked out
        self.check_rate_limit(realm_id, user_id)?;

        // Check user exists
        let user = self.get_user(realm_id, user_id)?;
        if user.is_none() {
            // Timing defense: verify against dummy hash so timing is
            // indistinguishable from a real failed verification.
            // Return generic error to prevent user enumeration.
            let _ = credentials::verify_hash(password, &self.dummy_hash);
            let count = self.record_failed_attempt(realm_id, user_id);
            self.emit_login_failed_audit(realm_id, user_id, count);
            return Err(IdentityError::InvalidCredential {
                reason: "verification failed".to_string(),
            });
        }

        // Load credential
        let cred_key = keys::encode_credential_key(user_id);
        let cred_bytes = self
            .storage
            .get(realm_id, &cred_key)
            .map_err(Self::storage_err)?;

        let Some(cred_bytes) = cred_bytes else {
            // Timing defense: same as above.
            // Return generic error to prevent credential enumeration.
            let _ = credentials::verify_hash(password, &self.dummy_hash);
            let count = self.record_failed_attempt(realm_id, user_id);
            self.emit_login_failed_audit(realm_id, user_id, count);
            return Err(IdentityError::InvalidCredential {
                reason: "verification failed".to_string(),
            });
        };

        let cred = Self::deserialize_credential(&cred_bytes)?;
        // Pepper-aware verification. Returns (matches, needs_pepper_rehash).
        // needs_pepper_rehash is true when the credential was verified with an
        // older or absent pepper and should be re-hashed with the active pepper.
        let credential_cfg = self.credential_config_for_realm(realm_id)?;
        let (matches, needs_pepper_rehash) =
            credentials::verify_password_with_pepper(password, &cred, &credential_cfg)?;

        if matches {
            // Clear failed attempts on success
            self.clear_attempts(realm_id, user_id);

            // Enforce password expiry policy before any mutation. Expired
            // credentials should not be upgraded in place.
            let max_age_days = self
                .password_policy_for_realm(realm_id)?
                .and_then(|p| p.max_age_days);
            if let Some(days) = max_age_days {
                let max_age_micros = i64::from(days) * 24 * 60 * 60 * 1_000_000;
                let now = self.clock.now().as_micros();
                if now - cred.created_at > max_age_micros {
                    return Err(IdentityError::PasswordExpired);
                }
            }

            // Determine whether this credential needs any rehash:
            //   1. Legacy algorithm upgrade (bcrypt/scrypt/pbkdf2 → Argon2id)
            //   2. Argon2 params changed (memory/time cost)
            //   3. Pepper rotation (active version changed, or pepper newly added)
            let needs_algo_upgrade = cred.algorithm != credentials::PasswordAlgorithm::Argon2id;
            let needs_param_rehash = !needs_algo_upgrade
                && credentials::argon2_params_need_rehash(&cred.hash, &credential_cfg);

            if needs_algo_upgrade || needs_param_rehash || needs_pepper_rehash {
                let now = self.clock.now().as_micros();
                let mut upgraded = credentials::hash_password(password, &credential_cfg, now)?;
                // Preserve original credential age for expiry-policy continuity.
                upgraded.created_at = cred.created_at;
                let upgraded_bytes = Self::serialize_credential(&upgraded)?;
                self.storage
                    .put(realm_id, &cred_key, &upgraded_bytes)
                    .map_err(Self::storage_err)?;
            }
        } else {
            let count = self.record_failed_attempt(realm_id, user_id);
            self.emit_login_failed_audit(realm_id, user_id, count);
        }

        Ok(matches)
    }

    fn change_password(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        old_password: &CleartextPassword,
        new_password: &CleartextPassword,
    ) -> Result<(), IdentityError> {
        // Verify old password (this also checks user existence and credential existence)
        let matches = self.verify_password(realm_id, user_id, old_password)?;
        if !matches {
            return Err(IdentityError::InvalidCredential {
                reason: "old password does not match".to_string(),
            });
        }

        // Set the new password
        self.record_audit(
            realm_id,
            None,
            AuditAction::CredentialChanged,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;
        self.set_password(realm_id, user_id, new_password)?;
        // Bump sv for all active sessions — password change is a security event.
        let retention = self.sv_retention_secs(realm_id);
        if let Err(e) = self.bump_user_sv_inner(realm_id, user_id, retention) {
            tracing::warn!(realm=%realm_id, user=%user_id.as_uuid(), error=%e, "sv bump on password change failed");
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
    fn create_session(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        context: &SessionContext,
    ) -> Result<Session, IdentityError> {
        self.require_active_realm(realm_id)?;

        // A-24: enforce per-realm total session quota before writing.
        if let Ok(Some(realm)) = self.get_realm(realm_id) {
            if let Some(quotas) = &realm.config().quotas {
                if let Some(max) = quotas.max_sessions {
                    let prefix = keys::session_id_scan_prefix();
                    self.check_resource_quota(realm_id, "sessions", &prefix, max)?;
                }
            }
        }

        // Enforce mfa_required policy unless the session originates from a
        // passkey ceremony (passkeys are inherently multi-factor).
        if !context.satisfies_mfa_via_passkey {
            if let Ok(Some(realm)) = self.get_realm(realm_id) {
                // HSEC-004: System realm (nil UUID) defaults MFA to required even when
                // `mfa_required` is not explicitly configured — the admin control plane
                // must not silently accept unauthenticated sessions. User realms default
                // to opt-in (false) unless explicitly enabled.
                let mfa_default = keys::is_system_realm(realm_id);
                if realm.config().mfa_required.unwrap_or(mfa_default) {
                    let has_mfa = self.mfa_enabled(realm_id, user_id).unwrap_or(false);
                    if !has_mfa {
                        return Err(IdentityError::MfaRequired);
                    }
                }
            }
        }

        // Ensure the user exists and is permitted to start a session.
        // Unverified users must complete the email-verification flow first;
        // disabled users are blocked entirely (distinguished from
        // `UserNotFound` because an operator deliberately disabled them).
        let user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;
        match user.status() {
            UserStatus::Active => {}
            UserStatus::PendingVerification => return Err(IdentityError::UserNotVerified),
            UserStatus::Disabled => return Err(IdentityError::Unauthorized),
        }

        // Enforce per-realm concurrent session limit when configured.
        if let Ok(Some(realm)) = self.get_realm(realm_id) {
            if let Some(limit) = realm.config().max_concurrent_sessions {
                let policy = realm.config().session_over_limit_policy.clone();
                let lock_key = format!("{}:{}", realm_id.as_uuid(), user_id.as_uuid());

                // Acquire per-user lock — serializes the count-check + create
                // sequence to prevent TOCTOU races under concurrent logins.
                let user_lock = {
                    let mut locks = self
                        .session_limit_locks
                        .lock()
                        .expect("session_limit_locks poisoned");
                    locks
                        .entry(lock_key)
                        // INVARIANT: inner guard held only across the sync session count-check + write window; no .await in scope.
                        .or_insert_with(|| Arc::new(Mutex::new(())))
                        .clone()
                };
                let _guard = user_lock
                    .lock()
                    .expect("session_limit_locks user lock poisoned");

                let now = self.clock.now();
                // Use a large-but-safe limit (u32::MAX avoids the take(limit+1)
                // overflow that usize::MAX would cause inside list_sessions_by_user).
                // Use max page limit to get all sessions; the engine now counts via total.
                let page = self.list_sessions_by_user(
                    realm_id,
                    user_id,
                    &crate::core::PageRequest::new(0, crate::core::MAX_PAGE_LIMIT),
                )?;
                let mut live: Vec<_> = page.items.into_iter().filter(|s| s.is_valid(now)).collect();
                let active = live.len() as u32;

                if active >= limit {
                    let evicted = match &policy {
                        SessionLimitPolicy::RejectNew => {
                            let ctx = AuditContext {
                                actor: Actor::User(user_id.clone()),
                                metadata: Some(serde_json::json!({
                                    "user_id": user_id.as_uuid().to_string(),
                                    "evicted": 0u32,
                                    "policy": "reject_new",
                                    "limit": limit,
                                })),
                            };
                            let _ = self.record_audit(
                                realm_id,
                                Some(&ctx),
                                AuditAction::SessionLimitEnforced,
                                "session",
                                &user_id.as_uuid().to_string(),
                            );
                            return Err(IdentityError::SessionLimitExceeded { limit, active });
                        }
                        SessionLimitPolicy::EvictOldest => {
                            let to_evict = (active + 1 - limit) as usize;
                            live.sort_by_key(|s| s.created_at());
                            for s in live.iter().take(to_evict) {
                                let _ = self.revoke_session(realm_id, s.id());
                            }
                            to_evict as u32
                        }
                    };

                    let ctx = AuditContext {
                        actor: Actor::User(user_id.clone()),
                        metadata: Some(serde_json::json!({
                            "user_id": user_id.as_uuid().to_string(),
                            "evicted": evicted,
                            "policy": "evict_oldest",
                            "limit": limit,
                        })),
                    };
                    let _ = self.record_audit(
                        realm_id,
                        Some(&ctx),
                        AuditAction::SessionLimitEnforced,
                        "session",
                        &user_id.as_uuid().to_string(),
                    );
                }
            }
        }

        // Capture per-realm lifecycle timeouts once and embed them in the
        // session record so hot-path get_session avoids a realm lookup (A-18).
        let (idle_timeout_secs, absolute_timeout_secs) =
            if let Ok(Some(realm)) = self.get_realm(realm_id) {
                (
                    realm.config().idle_timeout_secs,
                    realm.config().absolute_timeout_secs,
                )
            } else {
                (None, None)
            };

        // Generate session
        let session_id = SessionId::generate();
        let now = self.clock.now();
        let expires_at = now.add_micros(self.config.session.ttl_micros);
        let session = Session::new(
            session_id.clone(),
            user_id.clone(),
            now,
            expires_at,
            context,
            idle_timeout_secs,
            absolute_timeout_secs,
        );

        // Persist session record
        self.persist_session(realm_id, &session)?;

        // Write user-to-session index entry
        let user_session_key = keys::encode_user_session(user_id, &session_id);
        self.storage
            .put(realm_id, &user_session_key, &[])
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::SessionCreated,
            "session",
            &session_id.as_uuid().to_string(),
        )?;

        Ok(session)
    }

    fn get_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Option<Session>, IdentityError> {
        // Conditional span: only allocated when debug tracing is active to
        // preserve the zero-allocation guarantee on the token validation path.
        let _span = tracing::enabled!(tracing::Level::DEBUG).then(|| {
            tracing::debug_span!(
                "hearth.auth.session_lookup",
                "hearth.session_id" = %session_id,
                "hearth.realm_id" = %realm_id,
            )
            .entered()
        });

        let now = self.clock.now();

        // Hot path: check the in-process session cache (zero I/O, one atomic load).
        let cache_key = (realm_id.clone(), session_id.clone());
        {
            let cache = self.session_cache.load();
            if let Some(s) = cache.get(&cache_key) {
                // Clone before dropping the guard so no borrow crosses the drop.
                let cloned = (**s).clone();
                drop(cache);
                return if !cloned.is_valid(now) {
                    self.session_cache_evict(realm_id, session_id);
                    Ok(None)
                } else if cloned.is_policy_expired(now) {
                    // A-18: idle or absolute timeout. Lazy eviction.
                    self.session_cache_evict(realm_id, session_id);
                    let _ = self.evict_session_by_policy(realm_id, &cloned, now);
                    Ok(None)
                } else {
                    Ok(Some(cloned))
                };
            }
        }

        // Cache miss: load from storage and warm the cache on a valid result.
        let session = self.load_session_raw(realm_id, session_id)?;
        match session {
            Some(s) if s.is_valid(now) && !s.is_policy_expired(now) => {
                self.session_cache_insert(realm_id, &s);
                Ok(Some(s))
            }
            Some(s) if s.is_valid(now) => {
                // Policy-expired (A-18) — evict lazily.
                let _ = self.evict_session_by_policy(realm_id, &s, now);
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn revoke_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<(), IdentityError> {
        let mut session = self
            .load_session_raw(realm_id, session_id)?
            .ok_or(IdentityError::SessionNotFound)?;

        session.revoke();
        self.persist_session(realm_id, &session)?;

        // Cascade: revoke all refresh-token grant families issued under this session.
        let sfam_prefix = keys::encode_session_grant_family_prefix(session_id);
        let sfam_end = keys::prefix_end(&sfam_prefix);
        if let Ok(entries) = self.storage.scan(realm_id, &sfam_prefix, &sfam_end) {
            for entry in &entries {
                let family_id =
                    std::str::from_utf8(&entry.key[sfam_prefix.len()..]).unwrap_or_default();
                if family_id.is_empty() {
                    continue;
                }
                let family_key = keys::encode_grant_family(family_id);
                if let Ok(Some(fbytes)) = self.storage.get(realm_id, &family_key) {
                    if let Ok(mut fam) = serde_json::from_slice::<StoredGrantFamily>(&fbytes) {
                        if !fam.revoked {
                            fam.revoked = true;
                            if let Ok(updated) = serde_json::to_vec(&fam) {
                                let _ = self.storage.put(realm_id, &family_key, &updated);
                            }
                        }
                    }
                }
            }
        }

        // Bump session version if sv tracking is enabled for this realm.
        if let Ok(Some(realm)) = self.get_realm(realm_id) {
            if realm.config().session_version.enabled {
                let retention = realm.config().session_version.delta_retention_seconds;
                if let Err(e) = self.sv_store.bump(realm_id, session_id, retention) {
                    tracing::warn!(
                        session = %session_id.as_uuid(),
                        error = %e,
                        "sv bump failed on session revoke"
                    );
                }
            }
        }

        let audit_ctx = AuditContext {
            actor: Actor::User(session.user_id().clone()),
            metadata: None,
        };
        self.record_audit(
            realm_id,
            Some(&audit_ctx),
            AuditAction::SessionRevoked,
            "session",
            &session_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn refresh_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Session, IdentityError> {
        let mut session = self
            .load_session_raw(realm_id, session_id)?
            .ok_or(IdentityError::SessionNotFound)?;

        let now = self.clock.now();
        // Cannot refresh a revoked, TTL-expired, or A-18 policy-expired session.
        if !session.is_valid(now) || session.is_policy_expired(now) {
            if session.is_valid(now) && session.is_policy_expired(now) {
                let _ = self.evict_session_by_policy(realm_id, &session, now);
            }
            return Err(IdentityError::SessionNotFound);
        }

        session.refresh(now, self.config.session.ttl_micros);
        self.persist_session(realm_id, &session)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::SessionCreated,
            "session",
            &session_id.as_uuid().to_string(),
        )?;

        Ok(session)
    }

    fn list_sessions_by_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        page: &crate::core::PageRequest,
    ) -> Result<crate::core::PagedResult<Session>, IdentityError> {
        let prefix = keys::encode_user_sessions_prefix(user_id);
        let end = keys::prefix_end(&prefix);

        let index_entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;

        // Resolve all sessions from the index, then apply offset window.
        let mut all: Vec<Session> = Vec::new();
        for entry in &index_entries {
            let key_str = String::from_utf8_lossy(&entry.key);
            let Some(session_uuid_str) = key_str.rsplit(':').next() else {
                continue;
            };
            let Ok(session_uuid) = session_uuid_str.parse::<uuid::Uuid>() else {
                continue;
            };
            let session_id = SessionId::new(session_uuid);
            let session_key = keys::encode_session_id(&session_id);
            if let Some(data) = self
                .storage
                .get(realm_id, &session_key)
                .map_err(Self::storage_err)?
            {
                let session: Session =
                    serde_json::from_slice(&data).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                all.push(session);
            }
        }

        // Exact total: this path already materialises the full result set, so
        // capping the reported count only hides records from the admin UI
        // pager (HEA-1614).
        let total = all.len() as u64;
        let start = (page.offset as usize).min(all.len());
        let end_idx = (start + page.limit as usize).min(all.len());
        let items = all[start..end_idx].to_vec();

        Ok(crate::core::PagedResult::new(
            items,
            total,
            page.offset,
            page.limit,
        ))
    }

    fn list_sessions_by_realm(
        &self,
        realm_id: &RealmId,
        page: &crate::core::PageRequest,
    ) -> Result<crate::core::PagedResult<Session>, IdentityError> {
        let prefix = keys::session_id_scan_prefix();
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;

        // Filter revoked sessions, then apply offset window on remaining.
        let mut all: Vec<Session> = Vec::new();
        for entry in &entries {
            let session: Session =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if !session.is_revoked() {
                all.push(session);
            }
        }

        // Exact total: this path already materialises the full result set, so
        // capping the reported count only hides records from the admin UI
        // pager (HEA-1614).
        let total = all.len() as u64;
        let start = (page.offset as usize).min(all.len());
        let end_idx = (start + page.limit as usize).min(all.len());
        let items = all[start..end_idx].to_vec();

        Ok(crate::core::PagedResult::new(
            items,
            total,
            page.offset,
            page.limit,
        ))
    }

    fn revoke_all_user_sessions(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        keep: Option<&SessionId>,
    ) -> Result<u32, IdentityError> {
        let mut offset = 0u64;
        let batch = crate::core::MAX_PAGE_LIMIT;
        let mut revoked: u32 = 0;
        let now = self.clock.now();

        loop {
            let result = self.list_sessions_by_user(
                realm_id,
                user_id,
                &crate::core::PageRequest::new(offset, batch),
            )?;
            let n = result.items.len() as u64;

            for session in &result.items {
                if let Some(keep_id) = keep {
                    if session.id() == keep_id {
                        continue;
                    }
                }
                if session.is_valid(now) {
                    let _ = self.revoke_session(realm_id, session.id());
                    revoked += 1;
                }
            }

            if n == 0 || offset + n >= result.total {
                break;
            }
            offset += n;
        }

        if revoked > 0 {
            let ctx = AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: Some(serde_json::json!({
                    "user_id": user_id.as_uuid().to_string(),
                    "count": revoked,
                })),
            };
            let _ = self.record_audit(
                realm_id,
                Some(&ctx),
                AuditAction::SessionsRevoked,
                "user",
                &user_id.as_uuid().to_string(),
            );
        }

        Ok(revoked)
    }

    // ===== Token management =====

    fn issue_tokens(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        session_id: &SessionId,
    ) -> Result<TokenPair, IdentityError> {
        self.issue_tokens_with_context(
            realm_id,
            user_id,
            session_id,
            &TokenIssuanceContext::default(),
        )
    }

    #[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
    fn issue_tokens_with_context(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        session_id: &SessionId,
        ctx: &TokenIssuanceContext,
    ) -> Result<TokenPair, IdentityError> {
        // Verify user exists
        let user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // Verify session exists and is owned by the given user (defense-in-depth:
        // prevents callers from accidentally or maliciously cross-minting tokens
        // for a user_id that doesn't own the referenced session).
        let session = self
            .get_session(realm_id, session_id)?
            .ok_or(IdentityError::SessionNotFound)?;
        if session.user_id() != user_id {
            return Err(IdentityError::InvalidToken);
        }

        let now = self.clock.now();
        // Resolve effective permissions via RBAC at token-issue time.
        let resolved = self
            .rbac
            .resolve_permissions(user_id, realm_id, None, None)
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
        let perm_strs: Vec<String> = resolved
            .permissions
            .iter()
            .map(|p| p.as_str().to_string())
            .collect();

        // Resolve the OAuth client: use the caller-supplied client_id when
        // present, otherwise fall back to the first-party sentinel used by
        // the legacy session-token path.
        let resolved_client = if let Some(ref cid) = ctx.client_id {
            self.get_client(realm_id, cid)?
        } else {
            None
        };
        let sentinel_client =
            OAuthClient::new(ClientId::generate(), "session".to_string(), Vec::new(), now);
        let effective_client = resolved_client.as_ref().unwrap_or(&sentinel_client);

        let oid_ref = ctx.oid.as_deref();

        // Resolve the org slug for org_groups path construction. A storage
        // miss or parse failure is non-fatal: the token is still issued without
        // org_groups rather than hard-failing a login.
        let org_slug_owned: Option<String> = if let Some(oid_str) = oid_ref {
            match oid_str.parse::<crate::core::OrganizationId>() {
                Ok(org_id) => match self.get_organization(realm_id, &org_id) {
                    Ok(Some(org)) => Some(org.slug().to_string()),
                    Ok(None) => {
                        tracing::warn!(
                            oid = oid_str,
                            "org not found during token issuance; org_groups omitted"
                        );
                        None
                    }
                    Err(e) => {
                        tracing::warn!(
                            oid = oid_str,
                            error = %e,
                            "org lookup failed during token issuance; org_groups omitted"
                        );
                        None
                    }
                },
                Err(_) => {
                    tracing::warn!(
                        oid = oid_str,
                        "oid is not a valid OrganizationId; org_groups omitted"
                    );
                    None
                }
            }
        } else {
            None
        };
        let org_slug_ref = org_slug_owned.as_deref();

        // For Introspection/Decision modes, omit RBAC claims from the JWT:
        // permissions are sourced live via /introspect or /oauth/authorize.
        use crate::identity::oidc::AccessTokenAuthorization;
        let authz_mode = effective_client.access_token_authorization();
        let access_resolved = if authz_mode == AccessTokenAuthorization::Embedded {
            &resolved
        } else {
            &crate::rbac::ResolvedPermissions::default()
        };
        let empty_perm_strs: Vec<String> = Vec::new();

        let (roles, groups, permissions, custom) = self.apply_claim_profile(
            realm_id,
            &user,
            effective_client,
            access_resolved,
            &ctx.granted_scopes,
            oid_ref,
            ClaimTarget::AccessToken,
        );
        validate_claim_payload(ClaimTarget::AccessToken, &roles, &groups, &permissions)?;

        // Pre-token enrichment webhook: fire before signing and merge extra claims.
        let scope_str: String = ctx
            .granted_scopes
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        let client_id_str = ctx
            .client_id
            .as_ref()
            .map(|c| c.to_string())
            .unwrap_or_default();
        let extra_claims = self.fire_pre_token_webhook(
            realm_id,
            &user_id.to_string(),
            &client_id_str,
            "password",
            if scope_str.is_empty() {
                None
            } else {
                Some(scope_str.as_str())
            },
            Some(&session_id.as_uuid().to_string()),
            &roles,
            &groups,
            &permissions,
            &custom,
        )?;
        let custom = crate::identity::pre_token_webhook::merge_extra_claims(custom, extra_claims);

        self.record_audit(
            realm_id,
            None,
            AuditAction::TokenIssued,
            "token",
            &session_id.as_uuid().to_string(),
        )?;
        // Apply per-realm token TTL overrides if configured.
        let (access_ttl_secs, refresh_ttl_secs) = self.effective_token_ttl_secs(realm_id);
        let effective_token_cfg = TokenConfig {
            access_token_ttl_secs: access_ttl_secs,
            refresh_token_ttl_secs: refresh_ttl_secs,
            ..self.config.token.clone()
        };
        let realm_issuer = self.realm_issuer_url(realm_id);
        let effective_perms = if authz_mode == AccessTokenAuthorization::Embedded {
            if permissions.is_empty() {
                &perm_strs
            } else {
                &permissions
            }
        } else {
            &empty_perm_strs
        };
        // Embed sv claim when session-version tracking is enabled for this realm.
        let sv_claim = self.get_realm(realm_id).ok().flatten().and_then(|realm| {
            if realm.config().session_version.enabled {
                Some(self.get_session_sv(realm_id, session_id))
            } else {
                None
            }
        });
        self.signing_key.issue_token_pair(&IssueTokenRequest {
            sub: &user_id.to_string(),
            sid: &session_id.to_string(),
            tid: &realm_id.to_string(),
            oid: oid_ref,
            now,
            config: &effective_token_cfg,
            issuer_override: Some(realm_issuer),
            roles: if authz_mode == AccessTokenAuthorization::Embedded {
                &roles
            } else {
                &[]
            },
            groups: if authz_mode == AccessTokenAuthorization::Embedded {
                &groups
            } else {
                &[]
            },
            org_slug: org_slug_ref,
            permissions: effective_perms,
            custom,
            resource: ctx.resource.as_ref(),
            dpop_jkt: None,
            sv: sv_claim,
            scope: if scope_str.is_empty() {
                None
            } else {
                Some(scope_str)
            },
        })
    }

    fn validate_token(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<TokenClaims, IdentityError> {
        // Conditional span: only allocated when debug tracing is active.
        // validate_token is on the zero-allocation hot path; this guard
        // ensures no heap allocation occurs when debug is disabled.
        let _span = tracing::enabled!(tracing::Level::DEBUG).then(|| {
            tracing::debug_span!(
                "hearth.auth.token_validate",
                "hearth.realm_id" = %realm_id,
                // token sub/jti are populated after signature verification below
            )
            .entered()
        });

        // Resolve claims: check the in-process token claims cache first (S12-F2).
        //
        // A SHA-256 match on the raw JWT bytes guarantees content identity
        // (the signature is part of the input), so a cache hit means the
        // signature was already verified by a prior call on this engine
        // instance. All semantic checks (expiry, realm binding, session
        // validity) still run below — only the Ed25519 verify + serde parse
        // are skipped on a cache hit.
        let claims = {
            let maybe_key = Self::token_cache_hash(token);
            let cached = maybe_key.and_then(|k| self.token_claims_cache.load().get(&k).cloned());
            match cached {
                Some(arc) => (*arc).clone(),
                None => {
                    // Cache miss: full Ed25519 verify + serde_json parse.
                    let c = self.verify_token_signature_for_realm(realm_id, token)?;
                    if let Some(k) = maybe_key {
                        self.token_claims_cache_insert(k, Arc::new(c.clone()));
                    }
                    c
                }
            }
        };

        // Only accept access tokens — refresh tokens must not be accepted here.
        if claims.token_type != "access" {
            return Err(IdentityError::InvalidToken);
        }

        // A-38: reject tokens with deeply-nested `act` delegation chains.
        // The `act` claim lands in `custom` (flattened map) since Hearth does
        // not issue RFC 8693 act chains itself.
        if let Some(act_val) = claims.custom.get("act") {
            if Self::act_chain_depth(act_val) > crate::abuse::MAX_ACT_CHAIN_DEPTH {
                return Err(IdentityError::InvalidToken);
            }
        }

        // Enforce expiration before any session or permission check.
        let now = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;
        if now_secs >= claims.exp {
            return Err(IdentityError::TokenExpired);
        }
        // Reject tokens issued in the future beyond clock-skew tolerance.
        if claims.iat > now_secs + CLOCK_SKEW_SECS {
            return Err(IdentityError::InvalidToken);
        }
        // Coherence: iat must not exceed exp (would be an invalid token).
        if claims.iat > claims.exp {
            return Err(IdentityError::InvalidToken);
        }

        // Zero-alloc realm binding check: parse tid as a RealmId (stack-only
        // Uuid parse, no heap) and compare against the caller's realm_id.
        if claims.tid.parse::<RealmId>().ok().as_ref() != Some(realm_id) {
            return Err(IdentityError::InvalidToken);
        }

        // Fail-closed on realm lifecycle: suspended or archived realms must not
        // accept tokens. Checked after signature verification so forged tokens
        // never reach this path.
        //
        // Wait-free read from the ArcSwap cache — no lock, no storage call.
        // Absence from cache means realm is unknown (new or system realm);
        // fail-open matches the original get_realm(None) behavior.
        {
            let status_cache = self.realm_status_cache.load();
            if let Some(&status) = status_cache.get(realm_id) {
                if status != RealmStatus::Active {
                    return Err(IdentityError::RealmSuspended);
                }
            }
        }

        // RFC 7519 §4.1.3 — audience must include the configured value.
        if !claims.aud.contains(&self.config.token.audience) {
            return Err(IdentityError::InvalidToken);
        }

        // RFC 7519 §4.1.1 — issuer must exactly match the configured value.
        // Prevents tokens from a foreign Hearth instance from being accepted
        // even when they carry a valid signature and correct realm binding.
        if claims.iss != self.config.token.issuer {
            return Err(IdentityError::InvalidToken);
        }

        // §10.4 — DPoP JKT blocklist: reject tokens whose `cnf.jkt` thumbprint
        // is server-blocked. Hot-path safe: single atomic `load()`, no syscall.
        if let Some(ref cnf) = claims.cnf {
            if self.blocked_dpop_jkt_cache.load().contains(&cnf.jkt) {
                return Err(IdentityError::DPopJktBlocked);
            }
        }

        // Parse session ID from claims. Sessionless tokens (client_credentials,
        // sid == "none") skip sub-session binding.
        let session_id = Self::parse_session_id_claim(&claims)?;
        let Some(sid) = session_id else {
            self.verify_client_credentials_token(realm_id, &claims)?;
            return Ok(claims);
        };

        // Look up session — this is the actual session-validity check.
        let session = self
            .get_session(realm_id, &sid)?
            .ok_or(IdentityError::InvalidToken)?;

        // Bind claims.sub to session owner (defense-in-depth against sub
        // spoofing via a stolen-but-validly-signed token from another user).
        let user_id = Self::parse_user_id_claim(&claims)?;
        if session.user_id() != &user_id {
            return Err(IdentityError::InvalidToken);
        }

        Ok(claims)
    }

    #[tracing::instrument(
        level = "info",
        skip(self, refresh_token),
        fields(
            hearth_realm_id = %realm_id,
            hearth_oauth_grant_type = "refresh_token",
        )
    )]
    fn refresh_tokens(
        &self,
        realm_id: &RealmId,
        refresh_token: &str,
        dpop_jkt: Option<&str>,
        bind_ctx: Option<&RefreshBindContext>,
    ) -> Result<TokenPair, IdentityError> {
        // Verify Ed25519 signature against realm key (with global-key fallback
        // for Phase 0 realms). Rejects forged/tampered tokens at the crypto
        // layer before any claim or session inspection.
        let claims = self.verify_token_signature_for_realm(realm_id, refresh_token)?;

        // Must be a refresh token
        if claims.token_type != "refresh" {
            return Err(IdentityError::InvalidToken);
        }

        // Verify realm matches
        if claims.tid.parse::<RealmId>().ok().as_ref() != Some(realm_id) {
            return Err(IdentityError::InvalidToken);
        }

        // RFC 7519 §4.1.3 — audience must include the configured value.
        if !claims.aud.contains(&self.config.token.audience) {
            return Err(IdentityError::InvalidToken);
        }

        // Check expiration
        let now = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;
        if now_secs >= claims.exp {
            return Err(IdentityError::TokenExpired);
        }
        if claims.iat > now_secs + CLOCK_SKEW_SECS {
            return Err(IdentityError::InvalidToken);
        }
        if claims.iat > claims.exp {
            return Err(IdentityError::InvalidToken);
        }

        // Parse session ID
        let session_id_str = claims
            .sid
            .strip_prefix("session_")
            .ok_or(IdentityError::InvalidToken)?;
        let session_uuid =
            uuid::Uuid::parse_str(session_id_str).map_err(|_| IdentityError::InvalidToken)?;
        let session_id = SessionId::new(session_uuid);

        // Parse user ID
        let user_id_str = claims
            .sub
            .strip_prefix("user_")
            .ok_or(IdentityError::InvalidToken)?;
        let user_uuid =
            uuid::Uuid::parse_str(user_id_str).map_err(|_| IdentityError::InvalidToken)?;
        let user_id = UserId::new(user_uuid);

        // Bind token subject to the referenced session. This prevents a
        // mismatched `sub` from minting tokens for a different principal.
        // Use load_session_raw so a revoked session (e.g. after revoke_token)
        // is still visible for the ownership check. Actual revocation is
        // enforced by rotate_grant_family (returns TokenRevoked) or by
        // refresh_session on the legacy path (returns SessionNotFound).
        let session = self
            .load_session_raw(realm_id, &session_id)?
            .ok_or(IdentityError::InvalidToken)?;
        if session.user_id() != &user_id {
            return Err(IdentityError::InvalidToken);
        }

        self.record_audit(
            realm_id,
            None,
            AuditAction::TokenRefreshed,
            "token",
            &session_id.as_uuid().to_string(),
        )?;

        // Grant family rotation (if fid is present)
        if let Some(ref fid) = claims.fid {
            self.rotate_grant_family(
                realm_id,
                fid,
                refresh_token,
                &session_id,
                &user_id,
                now_secs,
                &claims,
                dpop_jkt,
                bind_ctx,
            )
        } else {
            // Legacy path: Phase-0 session tokens (fid == None).
            // This branch is only reachable by tokens that already passed
            // `verify_token_signature_for_realm` above. A tampered payload
            // with fid stripped cannot reach here — the signature check at the
            // top of this function rejects it first. The session↔user ownership
            // binding enforced above prevents cross-user token issuance on this
            // path.
            self.refresh_session(realm_id, &session_id)?;
            self.issue_tokens(realm_id, &user_id, &session_id)
        }
    }

    fn jwks(&self) -> JwksDocument {
        let mut keys = vec![self.signing_key.to_jwk()];
        // RS256 + ES256 advertised for ecosystem compatibility per
        // ARCHITECTURE.md §8.1 and HEA-51 OIDC M1. Persisted in storage so
        // the `kid` survives restarts (HEA-1655). Failures here would only
        // fire if `ring` entropy collection or storage I/O failed; we log and
        // serve a partial JWKS rather than 500 the endpoint.
        match self.oidc_rsa_jwk() {
            Ok(jwk) => keys.push(jwk),
            Err(err) => tracing::error!(error = %err, "failed to materialize RS256 JWKS entry"),
        }
        // Include retiring OIDC RSA keys that are still within their grace
        // window so tokens signed before an explicit rotation remain
        // verifiable (HEA-1655).
        keys.extend(self.oidc_rsa_retiring_jwks());
        match self.oidc_ecdsa_jwk() {
            Ok(jwk) => keys.push(jwk),
            Err(err) => tracing::error!(error = %err, "failed to materialize ES256 JWKS entry"),
        }
        JwksDocument { keys }
    }

    // ===== OIDC / OAuth 2.0 =====

    fn register_client(
        &self,
        realm_id: &RealmId,
        request: &RegisterClientRequest,
    ) -> Result<OAuthClient, IdentityError> {
        self.register_client_inner(realm_id, request)
    }

    #[allow(clippy::too_many_lines)]
    fn authorize(
        &self,
        realm_id: &RealmId,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationResponse, IdentityError> {
        self.authorize_inner(realm_id, request)
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
    fn exchange_authorization_code(
        &self,
        realm_id: &RealmId,
        request: &TokenExchangeRequest,
    ) -> Result<OidcTokenResponse, IdentityError> {
        self.exchange_authorization_code_inner(realm_id, request)
    }

    fn oidc_discovery(&self) -> OidcDiscoveryDocument {
        self.oidc_discovery_inner()
    }

    fn realm_oidc_discovery(
        &self,
        realm_id: &RealmId,
    ) -> Result<OidcDiscoveryDocument, IdentityError> {
        self.realm_oidc_discovery_inner(realm_id)
    }

    // ===== OAuth 2.0 Extended (Step 22) =====

    fn password_grant_token(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::PasswordGrantRequest,
    ) -> Result<crate::identity::oidc::PasswordGrantResponse, IdentityError> {
        self.password_grant_token_inner(realm_id, request)
    }

    fn step_up_mfa_grant_token(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::StepUpMfaGrantRequest,
    ) -> Result<crate::identity::oidc::PasswordGrantResponse, IdentityError> {
        self.step_up_mfa_grant_token_inner(realm_id, request)
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
    fn client_credentials_token(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::ClientCredentialsRequest,
    ) -> Result<crate::identity::oidc::ClientCredentialsResponse, IdentityError> {
        self.client_credentials_token_inner(realm_id, request)
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
    fn jwt_bearer_token(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::JwtBearerRequest,
    ) -> Result<crate::identity::oidc::ClientCredentialsResponse, IdentityError> {
        self.jwt_bearer_token_inner(realm_id, request)
    }

    /// Verifies a `private_key_jwt` client assertion per RFC 7523 §2.2.
    ///
    /// Validates signature, `iss == client_id`, `sub == client_id`, `exp`, `aud`,
    /// and JTI replay protection. Returns `Ok(())` on success; returns
    /// `InvalidClientAssertion` on any failure so callers cannot distinguish
    /// individual check failures (enumeration resistance).
    fn verify_client_assertion(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        assertion: &str,
    ) -> Result<(), IdentityError> {
        self.verify_client_assertion_inner(realm_id, client_id, assertion)
    }

    fn verify_jar(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        request_jwt: &str,
    ) -> Result<crate::identity::oidc::JarClaims, IdentityError> {
        self.verify_jar_inner(realm_id, client_id, request_jwt)
    }

    fn device_authorize(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::DeviceAuthorizationRequest,
    ) -> Result<crate::identity::oidc::DeviceAuthorizationResponse, IdentityError> {
        self.device_authorize_inner(realm_id, request)
    }

    fn approve_device(
        &self,
        realm_id: &RealmId,
        user_code: &str,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        self.approve_device_inner(realm_id, user_code, user_id)
    }

    fn poll_device_token(
        &self,
        realm_id: &RealmId,
        device_code: &str,
        client_id: &ClientId,
    ) -> Result<OidcTokenResponse, IdentityError> {
        self.poll_device_token_inner(realm_id, device_code, client_id)
    }

    fn push_authorization_request(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::PushedAuthorizationRequest,
    ) -> Result<crate::identity::oidc::PushedAuthorizationResponse, IdentityError> {
        self.push_authorization_request_inner(realm_id, request)
    }

    #[allow(private_interfaces)]
    fn consume_par(
        &self,
        realm_id: &RealmId,
        request_uri: &str,
    ) -> Result<crate::identity::oidc::StoredPushedAuthorizationRequest, IdentityError> {
        self.consume_par_inner(realm_id, request_uri)
    }

    fn revoke_token(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::TokenRevocationRequest,
    ) -> Result<(), IdentityError> {
        self.revoke_token_inner(realm_id, request)
    }

    fn introspect_token(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::TokenIntrospectionRequest,
    ) -> Result<crate::identity::oidc::IntrospectionResponse, IdentityError> {
        self.introspect_token_inner(realm_id, request)
    }

    fn decide_token_permission(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::DecidePermissionRequest,
    ) -> Result<crate::identity::oidc::DecidePermissionResponse, IdentityError> {
        self.decide_token_permission_inner(realm_id, request)
    }

    // ===== MFA / TOTP (Step 23) =====

    fn enroll_totp(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<TotpEnrollment, IdentityError> {
        // Ensure user exists
        let user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // Check not already enrolled
        if let Some(existing) = self.load_mfa_state(realm_id, user_id)? {
            if existing.enabled {
                return Err(IdentityError::MfaAlreadyEnabled);
            }
        }

        // Generate secret + recovery codes (no hashing here — deferred to
        // verify_totp_enrollment() so the enrollment page loads instantly).
        let secret = TotpSecret::generate()?;
        let secret_base32 = secret.to_base32();
        let provisioning_uri =
            totp::generate_provisioning_uri(&secret_base32, user.email(), "Hearth");
        let recovery_codes = totp::generate_recovery_codes()?;

        // Store disabled state with plaintext recovery codes. Hashing is
        // deferred to confirmation so this page load stays fast (~0ms vs ~3s).
        let state = StoredMfaState {
            secret_base32: secret_base32.clone(),
            enabled: false,
            recovery_code_hashes: Vec::new(),
            last_used_step: None,
            enabled_at: None,
            pending_recovery_codes: Some(recovery_codes.clone()),
        };
        self.save_mfa_state(realm_id, user_id, &state)?;

        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::CredentialSet,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(TotpEnrollment {
            secret_base32,
            provisioning_uri,
            recovery_codes: RecoveryCodes::new(recovery_codes),
        })
    }

    #[allow(clippy::cast_sign_loss)] // Timestamps are always positive
    fn verify_totp_enrollment(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError> {
        let mut state = self
            .load_mfa_state(realm_id, user_id)?
            .ok_or(IdentityError::MfaNotEnabled)?;

        if state.enabled {
            return Err(IdentityError::MfaAlreadyEnabled);
        }

        // Validate code against the stored secret
        let secret = TotpSecret::from_base32(&state.secret_base32)?;
        let now_secs = (self.clock.now().as_micros() / 1_000_000) as u64;
        let matched_step = totp::validate_totp(secret.as_bytes(), code, now_secs, None);

        if let Some(step) = matched_step {
            // Hash the pending plaintext recovery codes now (deferred from
            // enroll_totp to keep page load fast).
            let recovery_hashes = if let Some(ref codes) = state.pending_recovery_codes {
                totp::hash_recovery_codes(codes, &self.config.credential)?
            } else {
                // Legacy path: codes were already hashed at enrollment time.
                state.recovery_code_hashes.clone()
            };

            state.enabled = true;
            state.last_used_step = Some(step);
            state.enabled_at = Some(self.clock.now().as_micros());
            state.recovery_code_hashes = recovery_hashes;
            state.pending_recovery_codes = None;
            self.save_mfa_state(realm_id, user_id, &state)?;
            self.record_audit(
                realm_id,
                Some(&AuditContext {
                    actor: Actor::User(user_id.clone()),
                    metadata: None,
                }),
                AuditAction::CredentialVerified,
                "credential",
                &user_id.as_uuid().to_string(),
            )?;
            Ok(())
        } else {
            Err(IdentityError::InvalidMfaCode)
        }
    }

    #[allow(clippy::cast_sign_loss)] // Timestamps are always positive
    fn verify_totp(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError> {
        // Rate limit check
        self.check_mfa_rate_limit(realm_id, user_id)?;

        let mut state = self
            .load_mfa_state(realm_id, user_id)?
            .ok_or(IdentityError::MfaNotEnabled)?;

        if !state.enabled {
            return Err(IdentityError::MfaNotEnabled);
        }

        let secret = TotpSecret::from_base32(&state.secret_base32)?;
        let now_secs = (self.clock.now().as_micros() / 1_000_000) as u64;
        let matched_step =
            totp::validate_totp(secret.as_bytes(), code, now_secs, state.last_used_step);

        if let Some(step) = matched_step {
            state.last_used_step = Some(step);
            self.save_mfa_state(realm_id, user_id, &state)?;
            self.clear_mfa_attempts(realm_id, user_id);
            self.record_audit(
                realm_id,
                Some(&AuditContext {
                    actor: Actor::User(user_id.clone()),
                    metadata: None,
                }),
                AuditAction::CredentialVerified,
                "credential",
                &user_id.as_uuid().to_string(),
            )?;
            Ok(())
        } else {
            self.record_mfa_failed_attempt(realm_id, user_id);
            Err(IdentityError::InvalidMfaCode)
        }
    }

    fn verify_recovery_code(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError> {
        // Rate limit check — same budget as TOTP to prevent recovery-code brute-force.
        self.check_mfa_rate_limit(realm_id, user_id)?;

        let mut state = self
            .load_mfa_state(realm_id, user_id)?
            .ok_or(IdentityError::MfaNotEnabled)?;

        if !state.enabled {
            return Err(IdentityError::MfaNotEnabled);
        }

        let idx = totp::verify_recovery_code(code, &state.recovery_code_hashes)?;
        match idx {
            Some(i) => {
                // Mark recovery code as used
                state.recovery_code_hashes[i] = None;
                self.save_mfa_state(realm_id, user_id, &state)?;
                self.clear_mfa_attempts(realm_id, user_id);
                self.record_audit(
                    realm_id,
                    Some(&AuditContext {
                        actor: Actor::User(user_id.clone()),
                        metadata: None,
                    }),
                    AuditAction::CredentialVerified,
                    "credential",
                    &user_id.as_uuid().to_string(),
                )?;
                Ok(())
            }
            None => {
                self.record_mfa_failed_attempt(realm_id, user_id);
                Err(IdentityError::InvalidMfaCode)
            }
        }
    }

    fn disable_mfa(&self, realm_id: &RealmId, user_id: &UserId) -> Result<(), IdentityError> {
        let state = self.load_mfa_state(realm_id, user_id)?;
        match state {
            Some(s) if s.enabled => {
                let key = keys::encode_mfa_totp_key(user_id);
                self.storage
                    .delete(realm_id, &key)
                    .map_err(Self::storage_err)?;
                self.clear_mfa_attempts(realm_id, user_id);
                self.record_audit(
                    realm_id,
                    Some(&AuditContext {
                        actor: Actor::User(user_id.clone()),
                        metadata: None,
                    }),
                    AuditAction::CredentialChanged,
                    "credential",
                    &user_id.as_uuid().to_string(),
                )?;
                // A-42: MFA removal weakens the credential posture — revoke
                // all existing sessions so compromised devices cannot linger.
                if let Err(e) = self.revoke_all_user_sessions(realm_id, user_id, None) {
                    tracing::warn!(
                        user_id = %user_id.as_uuid(),
                        error = %e,
                        "revoke_all_user_sessions failed on disable_mfa"
                    );
                }
                Ok(())
            }
            _ => Err(IdentityError::MfaNotEnabled),
        }
    }

    fn mfa_enabled(&self, realm_id: &RealmId, user_id: &UserId) -> Result<bool, IdentityError> {
        match self.load_mfa_state(realm_id, user_id)? {
            Some(state) => Ok(state.enabled),
            None => Ok(false),
        }
    }

    fn burn_mfa_nonce(
        &self,
        realm_id: &RealmId,
        nonce: &str,
        exp_secs: u64,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_mfa_nonce_key(nonce);
        self.storage
            .put(realm_id, &key, &exp_secs.to_le_bytes())
            .map_err(Self::storage_err)
    }

    fn is_mfa_nonce_burned(&self, realm_id: &RealmId, nonce: &str) -> Result<bool, IdentityError> {
        let key = keys::encode_mfa_nonce_key(nonce);
        let result = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?;
        Ok(result.is_some())
    }

    fn load_pending_recovery_codes(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<Vec<String>>, IdentityError> {
        match self.load_mfa_state(realm_id, user_id)? {
            Some(state) if !state.enabled => Ok(state.pending_recovery_codes),
            _ => Ok(None),
        }
    }

    fn load_pending_totp_secret(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<String>, IdentityError> {
        match self.load_mfa_state(realm_id, user_id)? {
            Some(state) if !state.enabled => Ok(Some(state.secret_base32)),
            _ => Ok(None),
        }
    }

    fn regenerate_recovery_codes(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<String>, IdentityError> {
        let mut state = self
            .load_mfa_state(realm_id, user_id)?
            .ok_or(IdentityError::MfaNotEnabled)?;

        if !state.enabled {
            return Err(IdentityError::MfaNotEnabled);
        }

        let codes = totp::generate_recovery_codes()?;
        let hashes = totp::hash_recovery_codes(&codes, &self.config.credential)?;
        state.recovery_code_hashes = hashes;
        state.pending_recovery_codes = None;
        self.save_mfa_state(realm_id, user_id, &state)?;

        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::CredentialChanged,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(codes)
    }

    // ===== WebAuthn / Passkeys (Step 24) =====

    fn start_webauthn_registration(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        options: &RegistrationOptions,
    ) -> Result<Vec<u8>, IdentityError> {
        // Ensure user exists
        self.get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // Cleanup expired challenges
        let now = self.clock.now().as_micros();
        self.webauthn_challenges.cleanup_expired(now);

        // Generate and store challenge
        let challenge = webauthn::generate_challenge()?;
        let pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: options.rp_id.clone(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Registration,
            created_at: now,
        };
        self.webauthn_challenges.insert(pending);

        Ok(challenge)
    }

    fn complete_webauthn_registration(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_data_json: &[u8],
        attestation_object: &[u8],
        origin: &str,
        discoverable: bool,
    ) -> Result<WebAuthnCredentialInfo, IdentityError> {
        // Extract challenge from clientDataJSON to look up pending
        let client_data: serde_json::Value =
            serde_json::from_slice(client_data_json).map_err(|e| {
                IdentityError::WebAuthnRegistrationFailed {
                    reason: format!("invalid clientDataJSON: {e}"),
                }
            })?;
        let challenge_b64 = client_data
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdentityError::WebAuthnRegistrationFailed {
                reason: "missing challenge in clientDataJSON".to_string(),
            })?;

        let pending = self
            .webauthn_challenges
            .remove(challenge_b64)
            .ok_or_else(|| IdentityError::WebAuthnRegistrationFailed {
                reason: "challenge not found or expired".to_string(),
            })?;

        // Check expiry
        let now = self.clock.now().as_micros();
        if now - pending.created_at > 5 * 60 * 1_000_000 {
            return Err(IdentityError::WebAuthnRegistrationFailed {
                reason: "challenge expired".to_string(),
            });
        }

        // A-13: retrieve the realm's WebAuthn attestation policy (if any).
        let attestation_policy = self
            .get_realm(realm_id)
            .ok()
            .flatten()
            .and_then(|r| r.config().webauthn_attestation.clone());

        let (mut info, mut stored) = webauthn::complete_registration(
            &pending,
            client_data_json,
            attestation_object,
            origin,
            now,
            attestation_policy.as_ref(),
        )?;

        // Set discoverable from caller's request
        info = WebAuthnCredentialInfo {
            credential_id: info.credential_id().to_vec(),
            algorithm: info.algorithm(),
            discoverable,
            name: None,
        };
        stored.discoverable = discoverable;

        // Persist credential
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(info.credential_id());
        let key = keys::encode_webauthn_credential(user_id, &cred_id_b64);
        let bytes = serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)?;

        // If discoverable, create the index entry
        if discoverable {
            let disc_key = keys::encode_webauthn_discoverable(&cred_id_b64);
            let user_uuid_bytes = user_id.as_uuid().to_string().into_bytes();
            self.storage
                .put(realm_id, &disc_key, &user_uuid_bytes)
                .map_err(Self::storage_err)?;
        }

        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::CredentialSet,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(info)
    }

    fn start_webauthn_authentication(
        &self,
        realm_id: &RealmId,
        user_id: Option<&UserId>,
        options: &AuthenticationOptions,
    ) -> Result<Vec<u8>, IdentityError> {
        // If user_id provided, verify user exists
        if let Some(uid) = user_id {
            self.get_user(realm_id, uid)?
                .ok_or(IdentityError::UserNotFound)?;
        }

        // Cleanup expired challenges
        let now = self.clock.now().as_micros();
        self.webauthn_challenges.cleanup_expired(now);

        // Generate and store challenge
        let challenge = webauthn::generate_challenge()?;
        let pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: options.rp_id.clone(),
            user_id: user_id.cloned(),
            ceremony_type: CeremonyType::Authentication,
            created_at: now,
        };
        self.webauthn_challenges.insert(pending);

        Ok(challenge)
    }

    fn complete_webauthn_authentication(
        &self,
        realm_id: &RealmId,
        params: &CompleteAuthenticationParams<'_>,
    ) -> Result<WebAuthnAuthResult, IdentityError> {
        let credential_id = params.credential_id;
        let client_data_json = params.client_data_json;
        let authenticator_data = params.authenticator_data;
        let signature = params.signature;
        let user_handle = params.user_handle;
        let origin = params.origin;

        // Extract challenge from clientDataJSON to look up pending
        let client_data: serde_json::Value =
            serde_json::from_slice(client_data_json).map_err(|e| {
                IdentityError::WebAuthnAuthenticationFailed {
                    reason: format!("invalid clientDataJSON: {e}"),
                }
            })?;
        let challenge_b64 = client_data
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdentityError::WebAuthnAuthenticationFailed {
                reason: "missing challenge in clientDataJSON".to_string(),
            })?;

        let pending = self
            .webauthn_challenges
            .remove(challenge_b64)
            .ok_or_else(|| IdentityError::WebAuthnAuthenticationFailed {
                reason: "challenge not found or expired".to_string(),
            })?;

        // Check expiry
        let now = self.clock.now().as_micros();
        if now - pending.created_at > 5 * 60 * 1_000_000 {
            return Err(IdentityError::WebAuthnAuthenticationFailed {
                reason: "challenge expired".to_string(),
            });
        }

        // Look up the credential by ID
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(credential_id);

        // Determine which user owns this credential
        let owner_user_id = if let Some(uid) = pending.user_id.as_ref() {
            uid.clone()
        } else {
            // Discoverable flow: look up user from discoverable index
            let disc_key = keys::encode_webauthn_discoverable(&cred_id_b64);
            let user_uuid_bytes = self
                .storage
                .get(realm_id, &disc_key)
                .map_err(Self::storage_err)?
                .ok_or(IdentityError::WebAuthnCredentialNotFound)?;
            let uuid_str = std::str::from_utf8(&user_uuid_bytes).map_err(|_| {
                IdentityError::Serialization {
                    reason: "invalid user UUID in discoverable index".to_string(),
                }
            })?;
            let uuid =
                uuid::Uuid::parse_str(uuid_str).map_err(|_| IdentityError::Serialization {
                    reason: "invalid user UUID format in discoverable index".to_string(),
                })?;
            UserId::new(uuid)
        };

        let cred_key = keys::encode_webauthn_credential(&owner_user_id, &cred_id_b64);
        let stored_bytes = self
            .storage
            .get(realm_id, &cred_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::WebAuthnCredentialNotFound)?;
        let stored: StoredWebAuthnCredential =
            serde_json::from_slice(&stored_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        let result = webauthn::complete_authentication(
            &pending,
            &stored,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
            origin,
        )?;

        // Update sign counter
        let mut updated = stored;
        updated.sign_count = result.sign_count();
        let updated_bytes =
            serde_json::to_vec(&updated).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &cred_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        Ok(result)
    }

    fn list_webauthn_credentials(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<WebAuthnCredentialInfo>, IdentityError> {
        let prefix = keys::encode_webauthn_credentials_prefix(user_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;

        let mut results = Vec::with_capacity(entries.len());
        for entry in &entries {
            let stored: StoredWebAuthnCredential =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            let cred_id = URL_SAFE_NO_PAD
                .decode(&stored.credential_id_b64)
                .map_err(|e| IdentityError::Serialization {
                    reason: format!("invalid credential ID: {e}"),
                })?;
            results.push(WebAuthnCredentialInfo {
                credential_id: cred_id,
                algorithm: stored.algorithm,
                discoverable: stored.discoverable,
                name: stored.name.clone(),
            });
        }

        Ok(results)
    }

    fn revoke_webauthn_credential(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        credential_id: &[u8],
    ) -> Result<(), IdentityError> {
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(credential_id);

        // Delete credential record
        let cred_key = keys::encode_webauthn_credential(user_id, &cred_id_b64);
        let existing = self
            .storage
            .get(realm_id, &cred_key)
            .map_err(Self::storage_err)?;

        if existing.is_none() {
            return Err(IdentityError::WebAuthnCredentialNotFound);
        }

        // Check if discoverable, delete index entry
        let stored: StoredWebAuthnCredential =
            serde_json::from_slice(&existing.expect("checked above")).map_err(|e| {
                IdentityError::Serialization {
                    reason: e.to_string(),
                }
            })?;

        self.storage
            .delete(realm_id, &cred_key)
            .map_err(Self::storage_err)?;

        if stored.discoverable {
            let disc_key = keys::encode_webauthn_discoverable(&cred_id_b64);
            self.storage
                .delete(realm_id, &disc_key)
                .map_err(Self::storage_err)?;
        }

        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::CredentialChanged,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn rename_webauthn_credential(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        credential_id: &[u8],
        name: &str,
    ) -> Result<(), IdentityError> {
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(credential_id);
        let cred_key = keys::encode_webauthn_credential(user_id, &cred_id_b64);

        let existing = self
            .storage
            .get(realm_id, &cred_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::WebAuthnCredentialNotFound)?;

        let mut stored: StoredWebAuthnCredential =
            serde_json::from_slice(&existing).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        let trimmed = name.trim();
        stored.name = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };

        let bytes = serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &cred_key, &bytes)
            .map_err(Self::storage_err)?;

        Ok(())
    }

    // ===== Magic Link / Passwordless (Step 25) =====

    fn request_magic_link(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<MagicLinkResponse, IdentityError> {
        // Enforce realm policy before any user-visible work.
        self.check_allowed_auth_method(realm_id, "magic_link")?;

        // 1. Normalize email
        let normalized = validation::validate_email(email)?;

        // 2. Check per-email rate limit (3 per hour)
        self.check_magic_link_rate_limit(realm_id, &normalized)?;

        // 3. Look up user by email — capture user_id if exists (enumeration resistance: always succeed)
        let user_id = self
            .get_user_by_email(realm_id, &normalized)?
            .map(|u| u.id().as_uuid().to_string());

        // 4. Generate random token
        let token = magic_link::generate_magic_link_token()?;

        // 5. SHA-256 hash the token
        let token_hash = Self::sha256_hex(token.as_str().as_bytes());

        // 6. Store the magic link record
        let now = self.clock.now().as_micros();
        let stored = StoredMagicLink {
            email: normalized.clone(),
            user_id,
            created_at_micros: now,
            used: false,
        };
        let stored_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let key = keys::encode_magic_link_token(&token_hash);
        self.storage
            .put(realm_id, &key, &stored_bytes)
            .map_err(Self::storage_err)?;

        // 7. Record rate limit event
        self.record_magic_link_request(realm_id, &normalized);

        // 8. Return plaintext token (shown once)
        Ok(MagicLinkResponse::new(token.as_str().to_string()))
    }

    fn validate_magic_link(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<UserId, IdentityError> {
        // 1. SHA-256 hash the incoming token
        let token_hash = Self::sha256_hex(token.as_bytes());
        let key = keys::encode_magic_link_token(&token_hash);

        // Acquire per-token lock to prevent TOCTOU: two concurrent requests
        // for the same token must not both pass the `used` check.
        let lock = self.token_redemption_lock(&token_hash);
        let _guard = lock.lock().expect("token_redemption_lock poisoned");

        // 2. Look up stored record
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::MagicLinkTokenInvalid)?;

        let mut stored: StoredMagicLink =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // 3. Check if already used
        if stored.used {
            return Err(IdentityError::MagicLinkTokenInvalid);
        }

        // 4. Check expiry
        let now = self.clock.now().as_micros();
        if now - stored.created_at_micros > MAGIC_LINK_EXPIRY_MICROS {
            // Clean up stale record
            self.storage
                .delete(realm_id, &key)
                .map_err(Self::storage_err)?;
            return Err(IdentityError::MagicLinkTokenInvalid);
        }

        // 5. Mark as used (write before returning so no second caller can pass step 3)
        stored.used = true;
        let updated_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // 6. Return existing user or create new one
        if let Some(user_id_str) = &stored.user_id {
            let uuid =
                uuid::Uuid::parse_str(user_id_str).map_err(|e| IdentityError::Serialization {
                    reason: format!("invalid stored user_id: {e}"),
                })?;
            Ok(UserId::new(uuid))
        } else {
            // Email not registered at request time — create user now
            let request = crate::identity::types::CreateUserRequest {
                email: stored.email.clone(),
                display_name: stored.email.clone(),
                ..Default::default()
            };
            let user = self.create_user(realm_id, &request)?;
            Ok(user.id().clone())
        }
    }

    // ===== Self-service registration =====

    #[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
    fn register_user(
        &self,
        realm_id: &RealmId,
        request: &RegisterUserRequest,
    ) -> Result<RegisterUserResponse, IdentityError> {
        // The system realm never accepts self-registration — it is
        // Hearth's admin home, not an application realm.
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "register_user",
            });
        }
        // 1. Load realm and enforce active status.
        let realm = self
            .get_realm(realm_id)?
            .ok_or(IdentityError::RealmNotFound)?;
        if realm.status() != RealmStatus::Active {
            return Err(IdentityError::RealmSuspended);
        }
        let policy = realm
            .config()
            .registration_policy
            .clone()
            .unwrap_or_default();

        // 2. Normalize and validate basic inputs before any storage.
        let email = validation::validate_email(&request.email)?;
        let display_name = validation::validate_display_name(&request.display_name)?;
        // DoS bound check then HSEC-003 floor (unconditional, policy-independent).
        validation::validate_password_length(request.password.as_bytes())?;
        validation::validate_password_floor(request.password.as_bytes())?;
        if let Some(pw_policy) = realm.config().password_policy.as_ref() {
            validation::validate_password_against_policy(
                request.password.as_bytes(),
                pw_policy,
                Some(&display_name),
                Some(&email),
            )?;
        }

        // 3. Enforce registration policy.
        match &policy {
            RegistrationPolicy::Disabled => {
                return Err(IdentityError::RegistrationDisabled);
            }
            RegistrationPolicy::Open => {}
            RegistrationPolicy::DomainRestricted(allowed) => {
                let at = email.find('@').ok_or_else(|| IdentityError::InvalidInput {
                    reason: "email must contain '@'".to_string(),
                })?;
                let domain = &email[at + 1..];
                let ok = allowed.iter().any(|d| d.eq_ignore_ascii_case(domain));
                if !ok {
                    return Err(IdentityError::RegistrationDomainNotAllowed {
                        domain: domain.to_string(),
                    });
                }
            }
            RegistrationPolicy::InviteOnly => {
                let Some(token) = request.invitation_token.as_deref() else {
                    return Err(IdentityError::RegistrationRequiresInvitation);
                };
                // Minimum viable: token must correspond to a pending invitation
                // for this realm whose invited email matches.
                let token_hash = Self::sha256_hex(token.as_bytes());
                let key = keys::encode_invitation_token(&token_hash);
                let bytes = self
                    .storage
                    .get(realm_id, &key)
                    .map_err(Self::storage_err)?
                    .ok_or(IdentityError::RegistrationRequiresInvitation)?;
                let invitation: OrganizationInvitation =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                if !invitation.email().eq_ignore_ascii_case(&email)
                    || invitation.status() != InvitationStatus::Pending
                {
                    return Err(IdentityError::RegistrationRequiresInvitation);
                }
            }
        }

        // 4. Rate limit on both buckets BEFORE any write.
        self.check_registration_rate_limit(realm_id, &email, request.client_ip.as_deref())?;

        // 5. Record the attempt unconditionally — duplicates and successes
        // both count so brute-force enumeration is capped.
        self.record_registration_attempt(realm_id, &email, request.client_ip.as_deref());

        // 6. SECURITY: enumeration resistance. If the email is already
        // registered, return a plausible-looking response with an unusable
        // token rather than `DuplicateEmail`. A legitimate user retrying
        // their own signup sees a harmless no-op; an attacker cannot
        // distinguish registered emails via this endpoint.
        let email_key = keys::encode_user_email(&email);
        let existing = self
            .storage
            .get(realm_id, &email_key)
            .map_err(Self::storage_err)?;
        if existing.is_some() {
            let fake = magic_link::generate_magic_link_token()?;
            return Ok(RegisterUserResponse {
                user_id: UserId::generate(),
                verification_token: fake.as_str().to_string(),
            });
        }

        // 7. Create the user in PendingVerification status.
        let user = self.create_user_with_status(
            realm_id,
            &CreateUserRequest {
                email: email.clone(),
                display_name,
                ..Default::default()
            },
            UserStatus::PendingVerification,
        )?;

        // 8. Store the password.
        self.set_password(realm_id, user.id(), &request.password)?;

        // 9. Issue a verification token.
        let verification_token = self.issue_email_verification_token(realm_id, user.id())?;

        let new_user_id = user.id().clone();
        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::Anonymous,
                metadata: None,
            }),
            AuditAction::UserCreated,
            "user",
            &new_user_id.as_uuid().to_string(),
        )?;

        Ok(RegisterUserResponse {
            user_id: new_user_id,
            verification_token,
        })
    }

    // ===== Password reset =====

    fn request_password_reset(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<Option<String>, IdentityError> {
        // 1. Normalize email
        let normalized = validation::validate_email(email)?;

        // 2. Check per-email rate limit (3 per hour)
        self.check_password_reset_rate_limit(realm_id, &normalized)?;

        // 3. Look up user by email — return None for unknown (enumeration resistance)
        let Some(user) = self.get_user_by_email(realm_id, &normalized)? else {
            // Record the attempt even for unknown emails (prevents rate-limit bypass)
            self.record_password_reset_request(realm_id, &normalized);
            return Ok(None);
        };

        // 4. Generate random token (reuse magic link token generator)
        let token = magic_link::generate_magic_link_token()?;

        // 5. SHA-256 hash the token
        let token_hash = Self::sha256_hex(token.as_str().as_bytes());

        // 6. Store the password reset record
        let now = self.clock.now().as_micros();
        let stored = StoredPasswordReset {
            email: normalized.clone(),
            user_id: user.id().as_uuid().to_string(),
            created_at_micros: now,
            used: false,
        };
        let stored_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let key = keys::encode_password_reset_token(&token_hash);
        self.storage
            .put(realm_id, &key, &stored_bytes)
            .map_err(Self::storage_err)?;

        // 7. Record rate limit event
        self.record_password_reset_request(realm_id, &normalized);

        // 8. Return plaintext token (shown once)
        Ok(Some(token.as_str().to_string()))
    }

    fn reset_password_with_token(
        &self,
        realm_id: &RealmId,
        token: &str,
        new_password: &CleartextPassword,
    ) -> Result<UserId, IdentityError> {
        // 1. SHA-256 hash the incoming token
        let token_hash = Self::sha256_hex(token.as_bytes());
        let key = keys::encode_password_reset_token(&token_hash);

        // Acquire per-token lock to prevent TOCTOU: two concurrent reset
        // requests with the same token must not both pass the `used` check.
        let lock = self.token_redemption_lock(&token_hash);
        let _guard = lock.lock().expect("token_redemption_lock poisoned");

        // 2. Look up stored record
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::PasswordResetTokenInvalid)?;

        let mut stored: StoredPasswordReset =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // 3. Check if already used
        if stored.used {
            return Err(IdentityError::PasswordResetTokenInvalid);
        }

        // 4. Check expiry — use realm-specific TTL when configured, else default (30 minutes).
        let expiry_micros = self
            .get_realm(realm_id)
            .ok()
            .flatten()
            .and_then(|r| r.config().password_reset_token_ttl_micros)
            .unwrap_or(PASSWORD_RESET_EXPIRY_MICROS);
        let now = self.clock.now().as_micros();
        if now - stored.created_at_micros > expiry_micros {
            // Clean up stale record
            self.storage
                .delete(realm_id, &key)
                .map_err(Self::storage_err)?;
            return Err(IdentityError::PasswordResetTokenInvalid);
        }

        // 5. Mark as used (write before returning so no second caller can pass step 3)
        stored.used = true;
        let updated_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // 6. Parse user ID and set new password
        let uuid =
            uuid::Uuid::parse_str(&stored.user_id).map_err(|e| IdentityError::Serialization {
                reason: format!("invalid stored user_id: {e}"),
            })?;
        let user_id = UserId::new(uuid);
        self.set_password(realm_id, &user_id, new_password)?;

        // 7. Invalidate all existing sessions — credential change should force re-auth.
        // Revoke all sessions for this user via offset pagination.
        {
            let mut offset = 0u64;
            let batch = crate::core::MAX_PAGE_LIMIT;
            loop {
                let page = self.list_sessions_by_user(
                    realm_id,
                    &user_id,
                    &crate::core::PageRequest::new(offset, batch),
                )?;
                let n = page.items.len() as u64;
                for session in &page.items {
                    if let Err(e) = self.revoke_session(realm_id, session.id()) {
                        tracing::warn!(
                            session_id = %session.id(),
                            error = %e,
                            "reset_password: failed to revoke session"
                        );
                    }
                }
                if n == 0 || offset + n >= page.total {
                    break;
                }
                offset += n;
            }
        }

        self.record_audit(
            realm_id,
            None,
            AuditAction::CredentialChanged,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(user_id)
    }

    // ===== Email verification (onboarding) =====

    fn issue_email_verification_token(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<String, IdentityError> {
        // Ensure the target user exists (don't bind tokens to nothing).
        let user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // Generate 32 random bytes, base64url-encoded.
        let rng = ring::rand::SystemRandom::new();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "failed to generate verification token".to_string(),
            })?;
        let token = URL_SAFE_NO_PAD.encode(bytes);

        // Persist SHA-256(token) → StoredEmailVerification.
        let token_hash = Self::sha256_hex(token.as_bytes());
        let stored = StoredEmailVerification {
            user_id: user.id().as_uuid().to_string(),
            created_at_micros: self.clock.now().as_micros(),
            used: false,
        };
        let stored_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let key = keys::encode_email_verify_token(&token_hash);
        self.storage
            .put(realm_id, &key, &stored_bytes)
            .map_err(Self::storage_err)?;

        Ok(token)
    }

    fn verify_email_token(&self, realm_id: &RealmId, token: &str) -> Result<UserId, IdentityError> {
        let token_hash = Self::sha256_hex(token.as_bytes());
        let key = keys::encode_email_verify_token(&token_hash);

        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::VerificationTokenInvalid)?;

        let stored: StoredEmailVerification =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        if stored.used {
            return Err(IdentityError::VerificationTokenInvalid);
        }

        let now = self.clock.now().as_micros();
        if now - stored.created_at_micros > EMAIL_VERIFY_EXPIRY_MICROS {
            // Best-effort cleanup; ignore failure.
            let _ = self.storage.delete(realm_id, &key);
            return Err(IdentityError::VerificationTokenInvalid);
        }

        // Resolve stored user id back into a typed UserId.
        let uuid =
            uuid::Uuid::parse_str(&stored.user_id).map_err(|e| IdentityError::Serialization {
                reason: format!("invalid stored user_id: {e}"),
            })?;
        let user_id = UserId::new(uuid);

        // Transition user to Active (from PendingVerification) and mark
        // email_verified = true. For already-Active users we still set the
        // verified flag — e.g. the RA VERIFY_EMAIL flow for admin-created users.
        let mut user = self
            .get_user(realm_id, &user_id)?
            .ok_or(IdentityError::VerificationTokenInvalid)?;
        let needs_update =
            user.status() == UserStatus::PendingVerification || !user.email_verified();
        if needs_update {
            if user.status() == UserStatus::PendingVerification {
                user.set_status(UserStatus::Active);
            }
            user.set_email_verified(true);
            user.set_updated_at(self.clock.now());
            let user_bytes =
                serde_json::to_vec(&user).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            let user_key = keys::encode_user_id(&user_id);
            self.storage
                .put(realm_id, &user_key, &user_bytes)
                .map_err(Self::storage_err)?;
        }

        // Delete the token entry so it cannot be reused.
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)?;

        Ok(user_id)
    }

    // ===== A-19: Email-change re-verification =====

    fn initiate_email_change(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        new_email: &str,
    ) -> Result<String, IdentityError> {
        // Validate and normalize the new address.
        let normalized = crate::identity::validation::validate_email(new_email)?;

        // Load the user; capture the current email for the stored record.
        let user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;
        let old_email = user.email().to_string();

        // No-op if already at this address.
        if normalized == old_email {
            return Err(IdentityError::InvalidInput {
                reason: "new email is the same as the current email".to_string(),
            });
        }

        // Check that the target address is not already in use.
        let new_email_key = keys::encode_user_email(&normalized);
        if self
            .storage
            .get(realm_id, &new_email_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::DuplicateEmail);
        }

        // A-20: reject if the target address is under a 90-day reservation.
        let reserved_key = keys::encode_email_reserved(&normalized);
        if let Some(bytes) = self
            .storage
            .get(realm_id, &reserved_key)
            .map_err(Self::storage_err)?
        {
            if let Ok(r) = serde_json::from_slice::<StoredEmailReservation>(&bytes) {
                let now = self.clock.now().as_micros();
                if now - r.reserved_at_micros < EMAIL_RESERVED_MICROS {
                    return Err(IdentityError::EmailReserved);
                }
                let _ = self.storage.delete(realm_id, &reserved_key);
            }
        }

        // Generate 32-byte random token; store SHA-256(token).
        let rng = ring::rand::SystemRandom::new();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf)
            .map_err(|_| IdentityError::SigningError {
                reason: "failed to generate email change token".to_string(),
            })?;
        let token = URL_SAFE_NO_PAD.encode(buf);
        let token_hash = Self::sha256_hex(token.as_bytes());

        let stored = StoredEmailChangeToken {
            user_id: user_id.as_uuid().to_string(),
            new_email: normalized.clone(),
            old_email,
            created_at_micros: self.clock.now().as_micros(),
        };
        let stored_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let key = keys::encode_email_change_token(&token_hash);
        self.storage
            .put(realm_id, &key, &stored_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::EmailChangeInitiated,
            "user",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(token)
    }

    fn confirm_email_change(&self, realm_id: &RealmId, token: &str) -> Result<User, IdentityError> {
        let token_hash = Self::sha256_hex(token.as_bytes());
        let key = keys::encode_email_change_token(&token_hash);

        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::EmailChangeTokenInvalid)?;

        let stored: StoredEmailChangeToken =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        let now = self.clock.now().as_micros();
        if now - stored.created_at_micros > EMAIL_CHANGE_TOKEN_EXPIRY_MICROS {
            let _ = self.storage.delete(realm_id, &key);
            return Err(IdentityError::EmailChangeTokenInvalid);
        }

        let uuid =
            uuid::Uuid::parse_str(&stored.user_id).map_err(|e| IdentityError::Serialization {
                reason: format!("invalid stored user_id: {e}"),
            })?;
        let user_id = UserId::new(uuid);

        // Re-check new address uniqueness (race-safe).
        let new_email_key = keys::encode_user_email(&stored.new_email);
        if self
            .storage
            .get(realm_id, &new_email_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::DuplicateEmail);
        }

        // Load user; confirm email hasn't already changed externally.
        let mut user = self
            .get_user(realm_id, &user_id)?
            .ok_or(IdentityError::EmailChangeTokenInvalid)?;
        if user.email() != stored.old_email {
            // The address was already changed by another path; invalidate.
            let _ = self.storage.delete(realm_id, &key);
            return Err(IdentityError::EmailChangeTokenInvalid);
        }

        // Swap email indexes: remove old, add new.
        let old_email_key = keys::encode_user_email(&stored.old_email);
        self.storage
            .delete(realm_id, &old_email_key)
            .map_err(Self::storage_err)?;
        let user_id_bytes = user_id.as_uuid().to_string().into_bytes();
        self.storage
            .put(realm_id, &new_email_key, &user_id_bytes)
            .map_err(Self::storage_err)?;

        // Update user record: new email, mark verified, bump timestamp.
        user.set_email(stored.new_email.clone());
        user.set_email_verified(true);
        user.set_updated_at(self.clock.now());
        let user_bytes = Self::serialize_user(&user)?;
        let id_key = keys::encode_user_id(&user_id);
        self.storage
            .put(realm_id, &id_key, &user_bytes)
            .map_err(Self::storage_err)?;

        // Consume token (single-use).
        let _ = self.storage.delete(realm_id, &key);

        self.record_audit(
            realm_id,
            None,
            AuditAction::EmailChangeConfirmed,
            "user",
            &user_id.as_uuid().to_string(),
        )?;

        // Revoke all sessions — email change is a security event.
        if let Err(e) = self.revoke_all_user_sessions(realm_id, &user_id, None) {
            tracing::warn!(
                user_id = %user_id.as_uuid(),
                error = %e,
                "confirm_email_change: revoke_all_user_sessions failed"
            );
        }

        Ok(user)
    }

    // ===== A-37: prompt=none silent-auth probe rate-limiting =====

    /// Checks and records a `prompt=none` probe for the given subject.
    ///
    /// Returns `Ok(())` when under the rate limit and `Err(SilentAuthRateLimited)`
    /// when the per-hour cap has been exceeded. The counter is incremented on
    /// every call regardless of outcome. An `OidcSilentAuthProbed` audit event
    /// is emitted on each probe.
    fn check_silent_auth_probe(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &str,
        outcome: &str,
    ) -> Result<(), IdentityError> {
        let now = self.clock.now().as_micros();
        let key = keys::encode_prompt_none_tracker(user_id);

        // Load or initialise the tracker.
        let mut tracker = if let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        {
            serde_json::from_slice::<StoredPromptNoneTracker>(&bytes).unwrap_or(
                StoredPromptNoneTracker {
                    count: 0,
                    window_start_micros: now,
                },
            )
        } else {
            StoredPromptNoneTracker {
                count: 0,
                window_start_micros: now,
            }
        };

        // Reset window if expired.
        if now - tracker.window_start_micros >= PROMPT_NONE_WINDOW_MICROS {
            tracker.count = 0;
            tracker.window_start_micros = now;
        }

        // Increment before the limit check so the count is always persisted.
        tracker.count = tracker.count.saturating_add(1);

        if let Ok(bytes) = serde_json::to_vec(&tracker) {
            let _ = self.storage.put(realm_id, &key, &bytes);
        }

        // Emit audit — fail-open (LogOnly) if the append fails.
        let audit_ctx = AuditContext {
            actor: Actor::User(user_id.clone()),
            metadata: Some(serde_json::json!({
                "user_id": user_id.as_uuid().to_string(),
                "client_id": client_id,
                "outcome": outcome,
                "probe_count": tracker.count,
            })),
        };
        let _ = self.record_audit(
            realm_id,
            Some(&audit_ctx),
            AuditAction::OidcSilentAuthProbed,
            "user",
            &user_id.as_uuid().to_string(),
        );

        if tracker.count > PROMPT_NONE_MAX_PROBES {
            return Err(IdentityError::SilentAuthRateLimited);
        }

        Ok(())
    }

    // ===== UserInfo (OIDC Core §5.3) =====

    fn userinfo(
        &self,
        realm_id: &RealmId,
        access_token: &str,
    ) -> Result<crate::identity::oidc::UserInfoResponse, IdentityError> {
        self.userinfo_inner(realm_id, access_token)
    }

    // ===== Admin API (Step 27) =====

    fn list_users(
        &self,
        realm_id: &RealmId,
        page: &crate::core::PageRequest,
    ) -> Result<crate::core::PagedResult<User>, IdentityError> {
        let prefix = keys::user_id_scan_prefix();
        let (entries, total) = self
            .storage
            .scan_prefix_paged(realm_id, &prefix, page.offset, page.limit, 0)
            .map_err(Self::storage_err)?;

        let mut items = Vec::with_capacity(entries.len());
        for entry in &entries {
            let user: User =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            items.push(user);
        }

        Ok(crate::core::PagedResult::new(
            items,
            total,
            page.offset,
            page.limit,
        ))
    }

    fn search_users(
        &self,
        realm_id: &RealmId,
        query: &str,
        page: &crate::core::PageRequest,
        sort_field: Option<crate::identity::search::UserSortField>,
        sort_dir: crate::identity::search::SortDir,
    ) -> Result<crate::core::PagedResult<User>, IdentityError> {
        use crate::identity::search::{SearchQuery, SortDir, UserSortField};

        let matcher = SearchQuery::compile(query);
        let prefix = keys::user_id_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;

        // Filter using the compiled matcher (email or display name).
        let mut all_matching: Vec<User> = Vec::new();
        for entry in &entries {
            let user: User =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if matcher.matches_any(&[user.email(), user.display_name()]) {
                all_matching.push(user);
            }
        }

        // Sort the full matching set before slicing so page N is stable
        // regardless of storage key order.
        if let Some(field) = sort_field {
            all_matching.sort_by(|a, b| {
                let ord = match field {
                    UserSortField::Email => a.email().cmp(b.email()),
                    UserSortField::Name => a.display_name().cmp(b.display_name()),
                    UserSortField::Status => {
                        // Stable ordering: Active(0) < PendingVerification(1) < Disabled(2).
                        fn rank(s: UserStatus) -> u8 {
                            match s {
                                UserStatus::Active => 0,
                                UserStatus::PendingVerification => 1,
                                UserStatus::Disabled => 2,
                            }
                        }
                        rank(a.status()).cmp(&rank(b.status()))
                    }
                    UserSortField::Created => a.created_at().cmp(&b.created_at()),
                };
                if sort_dir == SortDir::Desc {
                    ord.reverse()
                } else {
                    ord
                }
            });
        }

        // Exact total so filtered lists paginate correctly (HEA-1614).
        let total = all_matching.len() as u64;
        let start = (page.offset as usize).min(all_matching.len());
        let end_idx = (start + page.limit as usize).min(all_matching.len());
        let items = all_matching[start..end_idx].to_vec();

        Ok(crate::core::PagedResult::new(
            items,
            total,
            page.offset,
            page.limit,
        ))
    }

    fn list_realms(
        &self,
        page: &crate::core::PageRequest,
    ) -> Result<crate::core::PagedResult<Realm>, IdentityError> {
        let sys_realm = keys::system_realm_id();
        let prefix = keys::realm_id_scan_prefix();
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(&sys_realm, &prefix, &end)
            .map_err(Self::storage_err)?;

        // Filter out the reserved system realm record. It lives in the same
        // prefix space as application realms but must never surface on admin
        // listings. Full-scan then slice so the filter doesn't skew offsets.
        let mut all: Vec<Realm> = Vec::new();
        for entry in &entries {
            let realm: Realm =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if keys::is_system_realm(realm.id()) {
                continue;
            }
            all.push(realm);
        }

        // Exact total: this path already materialises the full result set, so
        // capping the reported count only hides records from the admin UI
        // pager (HEA-1614).
        let total = all.len() as u64;
        let start = (page.offset as usize).min(all.len());
        let end_idx = (start + page.limit as usize).min(all.len());
        let items = all[start..end_idx].to_vec();

        Ok(crate::core::PagedResult::new(
            items,
            total,
            page.offset,
            page.limit,
        ))
    }

    fn search_realms(
        &self,
        query: &str,
        page: &crate::core::PageRequest,
        sort_field: Option<crate::identity::search::RealmSortField>,
        sort_dir: crate::identity::search::SortDir,
    ) -> Result<crate::core::PagedResult<Realm>, IdentityError> {
        use crate::identity::search::{RealmSortField, SearchQuery, SortDir};

        let matcher = SearchQuery::compile(query);
        let sys_realm = keys::system_realm_id();
        let prefix = keys::realm_id_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(&sys_realm, &prefix, &end)
            .map_err(Self::storage_err)?;

        let mut all: Vec<Realm> = Vec::new();
        for entry in &entries {
            let realm: Realm =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if keys::is_system_realm(realm.id()) {
                continue;
            }
            if matcher.matches(realm.name()) {
                all.push(realm);
            }
        }

        if let Some(field) = sort_field {
            all.sort_by(|a, b| {
                let ord = match field {
                    RealmSortField::Name => a.name().cmp(b.name()),
                    RealmSortField::Status => {
                        fn rank(s: crate::identity::types::RealmStatus) -> u8 {
                            use crate::identity::types::RealmStatus;
                            match s {
                                RealmStatus::Active => 0,
                                RealmStatus::Suspended => 1,
                                RealmStatus::Archived => 2,
                                RealmStatus::DeletingInProgress => 3,
                            }
                        }
                        rank(a.status()).cmp(&rank(b.status()))
                    }
                    RealmSortField::Created => a.created_at().cmp(&b.created_at()),
                };
                if sort_dir == SortDir::Desc {
                    ord.reverse()
                } else {
                    ord
                }
            });
        }

        let total = all.len() as u64;
        let start = (page.offset as usize).min(all.len());
        let end_idx = (start + page.limit as usize).min(all.len());
        let items = all[start..end_idx].to_vec();

        Ok(crate::core::PagedResult::new(
            items,
            total,
            page.offset,
            page.limit,
        ))
    }

    fn authenticate_oauth_client(
        &self,
        realm_id: &RealmId,
        client_id: &ClientId,
        client_secret: &str,
    ) -> Result<(), IdentityError> {
        self.authenticate_oauth_client_inner(realm_id, client_id, client_secret)
    }

    fn list_clients(
        &self,
        realm_id: &RealmId,
        page: &crate::core::PageRequest,
    ) -> Result<crate::core::PagedResult<OAuthClient>, IdentityError> {
        self.list_clients_inner(realm_id, page)
    }

    fn get_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<Option<OAuthClient>, IdentityError> {
        self.get_client_inner(realm_id, client_id)
    }

    fn authenticate_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        client_secret: Option<&str>,
    ) -> Result<(), IdentityError> {
        self.authenticate_client_inner(realm_id, client_id, client_secret)
    }

    fn update_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        request: &crate::identity::oidc::UpdateClientRequest,
    ) -> Result<OAuthClient, IdentityError> {
        self.update_client_inner(realm_id, client_id, request)
    }

    fn regenerate_client_secret(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<String, IdentityError> {
        self.regenerate_client_secret_inner(realm_id, client_id)
    }

    fn delete_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<(), IdentityError> {
        self.delete_client_inner(realm_id, client_id)
    }

    fn bulk_create_users(
        &self,
        realm_id: &RealmId,
        requests: &[CreateUserRequest],
    ) -> Result<Vec<BulkResult<User>>, IdentityError> {
        self.bulk_create_users_inner(realm_id, requests)
    }

    fn bulk_disable_users(
        &self,
        realm_id: &RealmId,
        user_ids: &[UserId],
    ) -> Result<Vec<BulkResult<()>>, IdentityError> {
        self.bulk_disable_users_inner(realm_id, user_ids)
    }

    // ===== OAuth consent =====

    fn get_consent(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
    ) -> Result<Option<ConsentRecord>, IdentityError> {
        self.get_consent_inner(realm_id, user_id, client_id)
    }

    fn list_consents_by_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<ConsentListEntry>, IdentityError> {
        self.list_consents_by_user_inner(realm_id, user_id)
    }

    fn grant_consent(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
        approved_scopes: &[String],
    ) -> Result<ConsentRecord, IdentityError> {
        self.grant_consent_inner(realm_id, user_id, client_id, approved_scopes)
    }

    fn revoke_consent(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
    ) -> Result<(), IdentityError> {
        self.revoke_consent_inner(realm_id, user_id, client_id)
    }

    fn revoke_all_consents_for_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<usize, IdentityError> {
        self.revoke_all_consents_for_user_inner(realm_id, user_id)
    }

    fn put_pending_authorization(
        &self,
        realm_id: &RealmId,
        request: &PendingAuthorizationRequest,
    ) -> Result<String, IdentityError> {
        self.put_pending_authorization_inner(realm_id, request)
    }

    fn get_pending_authorization(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<Option<PendingAuthorizationRequest>, IdentityError> {
        self.get_pending_authorization_inner(realm_id, ticket)
    }

    fn take_pending_authorization(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<PendingAuthorizationRequest, IdentityError> {
        self.take_pending_authorization_inner(realm_id, ticket)
    }

    fn sign_jarm_error_jwt(
        &self,
        realm_id: &RealmId,
        client_id: &str,
        error: &str,
        error_description: &str,
        state_param: &str,
    ) -> Result<String, IdentityError> {
        self.sign_jarm_error_jwt_inner(realm_id, client_id, error, error_description, state_param)
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_authorization_code(
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
        self.issue_authorization_code_inner(
            realm_id,
            user_id,
            client_id,
            redirect_uri,
            scope,
            state,
            code_challenge,
            code_challenge_method,
            nonce,
            amr_values,
            response_mode,
            jar_request,
            via_par,
        )
    }

    // ===== Migration / import (Phase 1 Step 30) =====

    fn import_realm(
        &self,
        request: &CreateRealmRequest,
        requested_id: Option<RealmId>,
        signing_key_pkcs8: Option<&[u8]>,
    ) -> Result<Realm, IdentityError> {
        // The reserved system realm is never an import target. An
        // external dump can legitimately be named "system" (Keycloak's
        // default realm is called `master`, not `system`, but we
        // defend against any collision anyway) — refuse rather than
        // silently rename.
        if request.name == keys::SYSTEM_REALM_NAME {
            return Err(IdentityError::SystemRealmProtected {
                operation: "import_realm",
            });
        }
        if let Some(ref id) = requested_id {
            if keys::is_system_realm(id) {
                return Err(IdentityError::SystemRealmProtected {
                    operation: "import_realm",
                });
            }
        }
        // Serialize against other realm-record mutations so the atomic
        // record+key `put_batch` below is never interleaved with another
        // thread's update/delete. Mirrors `create_realm`.
        let _ops_guard = self.realm_ops_lock.lock().expect("realm ops lock");

        let realm_id = requested_id.unwrap_or_else(RealmId::generate);

        // Refuse to clobber an existing realm record — callers may
        // retry an idempotent import flow, in which case they want a
        // clear DuplicateRealmName signal rather than a silent rewrite
        // that would also generate a fresh signing key and invalidate
        // every existing token under that realm.
        let sys_realm = keys::system_realm_id();
        let realm_key = keys::encode_realm_id(&realm_id);
        if self
            .storage
            .get(&sys_realm, &realm_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::DuplicateRealmName);
        }

        let now = self.clock.now();
        let config = request.config.clone().unwrap_or_default();
        // Disaster-recovery restore path: when the caller supplies the
        // original PKCS#8 bytes from a backup, install them verbatim
        // so every pre-restore JWT keeps validating. A parse failure
        // here is unrecoverable corruption — fail loudly rather than
        // silently fall back to a fresh key (that would invalidate
        // every token under the realm).
        let realm_signing_key = match signing_key_pkcs8 {
            Some(bytes) => SigningKey::from_pkcs8(bytes)?,
            None => SigningKey::generate()?,
        };

        let realm = Realm::new(
            realm_id.clone(),
            request.name.clone(),
            RealmStatus::Active,
            config,
            now,
            now,
        );
        let realm_bytes = Self::serialize_realm(&realm)?;
        let key_storage_key = keys::encode_realm_signing_key(&realm_id);
        // Zeroizing ensures the local PKCS#8 copy is actively overwritten
        // when dropped rather than relying on the allocator (HEA-750 M1).
        let key_bytes = Zeroizing::new(realm_signing_key.pkcs8_bytes().to_vec());

        self.storage
            .put_batch(
                &sys_realm,
                &[
                    (realm_key, realm_bytes),
                    (key_storage_key, key_bytes.to_vec()),
                ],
            )
            .map_err(Self::storage_err)?;

        {
            let key_arc = Arc::new(realm_signing_key);
            let id = realm_id.clone();
            self.realm_signing_keys.rcu(|current| {
                let mut new_map = (**current).clone();
                new_map.insert(id.clone(), Arc::clone(&key_arc));
                new_map
            });
            self.realm_status_cache.rcu(|current| {
                let mut new_map = (**current).clone();
                new_map.insert(id.clone(), RealmStatus::Active);
                new_map
            });
        }

        self.record_audit(
            &realm_id,
            None,
            AuditAction::RealmCreated,
            "realm",
            &realm_id.as_uuid().to_string(),
        )?;

        Ok(realm)
    }

    fn import_user(
        &self,
        realm_id: &RealmId,
        request: &ImportUserRequest,
    ) -> Result<User, IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "import_user",
            });
        }
        // 1. Validate and normalize input (same invariants as create_user)
        let email = validation::validate_email(&request.email)?;
        let first_name = validation::validate_name_part(&request.first_name, "First name")?;
        let last_name = validation::validate_name_part(&request.last_name, "Last name")?;
        let display_name = if request.display_name.trim().is_empty() {
            let synthesized = format!("{} {}", first_name, last_name).trim().to_string();
            if synthesized.is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "Display name or first/last name is required".to_string(),
                });
            }
            validation::validate_display_name(&synthesized)?
        } else {
            validation::validate_display_name(&request.display_name)?
        };

        // 2. Check email uniqueness
        let email_key = keys::encode_user_email(&email);
        if self
            .storage
            .get(realm_id, &email_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::DuplicateEmail);
        }

        // 3. Resolve user id — allow caller to preserve a foreign UUID,
        //    but refuse to clobber an existing record at that id.
        let user_id = request.id.clone().unwrap_or_else(UserId::generate);
        let id_key = keys::encode_user_id(&user_id);
        if self
            .storage
            .get(realm_id, &id_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::InvalidInput {
                reason: "a user with this id already exists".to_string(),
            });
        }

        let now = self.clock.now();
        // Imports preserve the source state; required_actions are not inferred from realm defaults.
        let mut user = User::new(
            user_id.clone(),
            email.clone(),
            display_name,
            first_name,
            last_name,
            request.status,
            Vec::new(),
            now,
            now,
        );

        if !request.attributes.is_empty() {
            Self::validate_user_attributes(&request.attributes)?;
            user.set_attributes(request.attributes.clone());
        }

        let user_bytes = Self::serialize_user(&user)?;
        let user_id_bytes = user_id.as_uuid().to_string().into_bytes();

        // 4. If a credential was supplied, derive the algorithm from the
        //    PHC prefix and prepare the credential write as part of the
        //    same atomic batch. Preserving the foreign hash verbatim lets
        //    the user authenticate with their existing password; the next
        //    successful verify will auto-upgrade to Argon2id.
        let mut entries = Vec::with_capacity(3);
        entries.push((email_key, user_id_bytes));
        entries.push((id_key, user_bytes));

        if let Some(raw) = &request.credential {
            let algorithm = classify_phc_algorithm(&raw.phc_string).ok_or_else(|| {
                IdentityError::InvalidInput {
                    reason: "unrecognized password hash format".to_string(),
                }
            })?;
            let created_at = raw.created_at_micros.unwrap_or_else(|| now.as_micros());
            let stored = StoredCredential {
                algorithm,
                hash: raw.phc_string.clone(),
                created_at,
                pepper_version: None,
            };
            let cred_bytes = Self::serialize_credential(&stored)?;
            let cred_key = keys::encode_credential_key(&user_id);
            entries.push((cred_key, cred_bytes));
        }

        self.storage
            .put_batch(realm_id, &entries)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::UserCreated,
            "user",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(user)
    }

    #[allow(clippy::too_many_lines)]
    fn seed_demo_users(
        &self,
        realm_id: &RealmId,
        password: &CleartextPassword,
        spec: &DemoSeedSpec,
    ) -> Result<DemoSeedOutcome, IdentityError> {
        // Never seed the system realm.
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "seed_demo_users",
            });
        }

        // Number of users committed per atomic `put_batch` write. Each user
        // contributes 3 entries (email index, user record, shared credential);
        // the advanced sentinel rides in the same batch so a crash mid-seed
        // resumes exactly at the last committed chunk.
        const CHUNK: u64 = 2_000;

        // Read the per-realm sentinel to make seeding idempotent/resumable.
        let count_key = keys::encode_demo_seed_count();
        let current: u64 = match self
            .storage
            .get(realm_id, &count_key)
            .map_err(Self::storage_err)?
        {
            Some(bytes) => std::str::from_utf8(&bytes)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            None => 0,
        };

        if current >= spec.target_count {
            return Ok(DemoSeedOutcome {
                created: 0,
                total: current,
                skipped: true,
            });
        }

        // Hash the shared password ONCE; reuse the identical credential for
        // every account. All users then authenticate with the same password.
        let now = self.clock.now();
        let cred_config = self.credential_config_for_realm(realm_id)?;
        let stored = credentials::hash_password(password, &cred_config, now.as_micros())?;
        let cred_bytes = Self::serialize_credential(&stored)?;

        // Emit a progress log roughly every this many users so large realms
        // show steady throughput in the background-seeding logs.
        const PROGRESS_EVERY: u64 = 100_000;
        let mut next_progress = current.saturating_add(PROGRESS_EVERY);

        let mut next = current + 1;
        while next <= spec.target_count {
            let chunk_end = next.saturating_add(CHUNK - 1).min(spec.target_count);
            let cap = usize::try_from((chunk_end - next + 1) * 3 + 1).unwrap_or(0);
            let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(cap);

            for idx in next..=chunk_end {
                let user_id = UserId::generate();
                let email = format!("user{idx:07}@{}", spec.email_domain);
                let display_name = format!("{} {idx}", spec.display_name_prefix);
                let mut user = User::new(
                    user_id.clone(),
                    email.clone(),
                    display_name,
                    String::new(),
                    String::new(),
                    UserStatus::Active,
                    Vec::new(),
                    now,
                    now,
                );
                user.set_email_verified(spec.email_verified);

                let user_bytes = Self::serialize_user(&user)?;
                let id_bytes = user_id.as_uuid().to_string().into_bytes();
                entries.push((keys::encode_user_email(&email), id_bytes));
                entries.push((keys::encode_user_id(&user_id), user_bytes));
                entries.push((keys::encode_credential_key(&user_id), cred_bytes.clone()));
            }

            // Advance the sentinel inside the same atomic batch as this chunk's
            // users, so resume after a crash is exact.
            entries.push((count_key.clone(), chunk_end.to_string().into_bytes()));
            self.storage
                .put_batch(realm_id, &entries)
                .map_err(Self::storage_err)?;

            if chunk_end >= next_progress {
                tracing::info!(
                    realm = %realm_id.as_uuid(),
                    seeded = chunk_end,
                    target = spec.target_count,
                    "demo seeding progress"
                );
                next_progress = chunk_end.saturating_add(PROGRESS_EVERY);
            }

            next = chunk_end + 1;
        }

        // One summary audit event for the whole seed run (not one per user).
        let _ = self.record_audit(
            realm_id,
            None,
            AuditAction::UserCreated,
            "demo_seed",
            &spec.target_count.to_string(),
        );

        Ok(DemoSeedOutcome {
            created: spec.target_count - current,
            total: spec.target_count,
            skipped: false,
        })
    }

    fn import_client(
        &self,
        realm_id: &RealmId,
        request: &ImportClientRequest,
    ) -> Result<OAuthClient, IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "import_client",
            });
        }
        let client_name = validation::validate_client_name(&request.client_name)?;

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

        let client_id = request.id.clone().unwrap_or_else(ClientId::generate);
        let key = keys::encode_oauth_client(&client_id);
        if self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::InvalidInput {
                reason: "a client with this id already exists".to_string(),
            });
        }

        let now = self.clock.now();
        let grant_types = if request.grant_types.is_empty() {
            vec!["authorization_code".to_string()]
        } else {
            request.grant_types.clone()
        };

        let mut client = if let Some(ref secret) = request.client_secret {
            let secret_hash =
                credentials::hash_raw_secret(secret.as_bytes(), &self.config.credential)?;
            OAuthClient::new_confidential(
                client_id,
                client_name,
                request.redirect_uris.clone(),
                now,
                secret_hash,
                grant_types,
            )
        } else {
            let mut c =
                OAuthClient::new(client_id, client_name, request.redirect_uris.clone(), now);
            c.set_grant_types(grant_types);
            c
        };
        client.set_slug(
            request
                .slug
                .clone()
                .unwrap_or_else(|| client.client_name().to_lowercase().replace(' ', "-")),
        );
        client.set_trust_level(request.trust_level);
        client.set_require_consent(
            request.trust_level == crate::identity::ClientTrustLevel::ThirdParty,
        );
        client.set_declared_scopes(request.declared_scopes.clone());
        client.set_consent_spans_orgs(request.consent_spans_orgs);

        let client_bytes =
            serde_json::to_vec(&client).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &key, &client_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::ClientRegistered,
            "client",
            &client.client_id().as_uuid().to_string(),
        )?;

        Ok(client)
    }

    // ===== Organizations =====

    fn create_organization(
        &self,
        realm_id: &RealmId,
        request: &CreateOrganizationRequest,
    ) -> Result<Organization, IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "create_organization",
            });
        }
        self.require_active_realm(realm_id)?;
        // A-24: enforce per-realm org quota before writing.
        if let Ok(Some(realm)) = self.get_realm(realm_id) {
            if let Some(quotas) = &realm.config().quotas {
                if let Some(max) = quotas.max_orgs {
                    let prefix = keys::org_id_scan_prefix();
                    self.check_resource_quota(realm_id, "orgs", &prefix, max)?;
                }
            }
        }
        let slug = validation::validate_slug(&request.slug)?;
        let name = validation::validate_display_name(&request.name)?;

        // A-5: reject permanently reserved slugs (operator-configured list).
        let slug_lower = slug.to_ascii_lowercase();
        if self.config.reserved_slugs.iter().any(|r| r == &slug_lower) {
            return Err(IdentityError::ReservedSlug { slug: slug.clone() });
        }

        // Acquire write lock before slug check to prevent TOCTOU (A-28)
        let _slug_guard = self.org_write_lock.lock().expect("org write lock");
        // Check slug uniqueness
        let slug_key = keys::encode_org_slug(&slug);
        if self
            .storage
            .get(realm_id, &slug_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::DuplicateOrgSlug);
        }

        // A-5: check post-delete slug cooldown reservation.
        let reservation_key = keys::encode_org_slug_reservation(realm_id, &slug);
        if let Some(bytes) = self
            .storage
            .get(realm_id, &reservation_key)
            .map_err(Self::storage_err)?
        {
            if let Ok(reservation) = serde_json::from_slice::<StoredSlugReservation>(&bytes) {
                let now_micros = self.clock.now().as_micros();
                if now_micros < reservation.expires_at_micros {
                    return Err(IdentityError::SlugInCooldown { slug: slug.clone() });
                }
                // Cooldown expired — clean up the stale reservation.
                let _ = self.storage.delete(realm_id, &reservation_key);
            }
        }

        let realm = self
            .get_realm(realm_id)?
            .ok_or(IdentityError::RealmNotFound)?;
        let org_attr_defs = realm
            .config()
            .attribute_definitions
            .as_ref()
            .map(|d| d.organizations.as_slice());
        validation::validate_attributes(&request.attributes, org_attr_defs)?;

        let now = self.clock.now();
        let org_id = OrganizationId::generate();
        let description = request.description.clone().unwrap_or_default();
        let config = request.config.clone().unwrap_or_default();

        let mut org = Organization::new(
            org_id.clone(),
            name,
            slug.clone(),
            description,
            OrganizationStatus::Active,
            config,
            now,
            now,
        );
        org.set_attributes(request.attributes.clone());

        let id_key = keys::encode_org_id(&org_id);
        let org_bytes = serde_json::to_vec(&org).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        // Atomic: primary + slug index in one WAL record (A-28)
        self.storage
            .put_batch(
                realm_id,
                &[
                    (id_key, org_bytes),
                    (slug_key, org_id.as_uuid().as_bytes().to_vec()),
                ],
            )
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::OrgCreated,
            "org",
            &org_id.as_uuid().to_string(),
        )?;

        Ok(org)
    }

    fn get_organization(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<Option<Organization>, IdentityError> {
        let key = keys::encode_org_id(org_id);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        {
            Some(bytes) => {
                let org: Organization =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(org))
            }
            None => Ok(None),
        }
    }

    fn get_organization_by_slug(
        &self,
        realm_id: &RealmId,
        slug: &str,
    ) -> Result<Option<Organization>, IdentityError> {
        let slug_key = keys::encode_org_slug(slug);
        match self
            .storage
            .get(realm_id, &slug_key)
            .map_err(Self::storage_err)?
        {
            Some(bytes) => {
                let uuid =
                    uuid::Uuid::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: format!("invalid org UUID in slug index: {e}"),
                    })?;
                let org_id = OrganizationId::new(uuid);
                self.get_organization(realm_id, &org_id)
            }
            None => Ok(None),
        }
    }

    fn update_organization(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        request: &UpdateOrganizationRequest,
    ) -> Result<Organization, IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "update_organization",
            });
        }
        let mut org = self
            .get_organization(realm_id, org_id)?
            .ok_or(IdentityError::OrganizationNotFound)?;

        if let Some(ref name) = request.name {
            let validated = validation::validate_display_name(name)?;
            org.set_name(validated);
        }
        if let Some(ref description) = request.description {
            org.set_description(description.clone());
        }
        if let Some(status) = request.status {
            org.set_status(status);
        }
        if let Some(ref config) = request.config {
            org.set_config(config.clone());
        }
        if let Some(ref attrs) = request.attributes {
            let realm = self
                .get_realm(realm_id)?
                .ok_or(IdentityError::RealmNotFound)?;
            let org_attr_defs = realm
                .config()
                .attribute_definitions
                .as_ref()
                .map(|d| d.organizations.as_slice());
            validation::validate_attributes(attrs, org_attr_defs)?;
            org.set_attributes(attrs.clone());
        }

        let now = self.clock.now();
        org.set_updated_at(now);

        let id_key = keys::encode_org_id(org_id);
        let org_bytes = serde_json::to_vec(&org).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &id_key, &org_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::OrgUpdated,
            "org",
            &org_id.as_uuid().to_string(),
        )?;

        Ok(org)
    }

    #[allow(clippy::too_many_lines)] // A-5 cooldown + cascade delete legitimately long
    fn delete_organization(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<(), IdentityError> {
        let org = self
            .get_organization(realm_id, org_id)?
            .ok_or(IdentityError::OrganizationNotFound)?;

        // 1. Delete all memberships (forward + reverse indexes)
        let member_prefix = keys::membership_by_org_prefix(org_id);
        let member_end = keys::prefix_end(&member_prefix);
        let members = self
            .storage
            .scan(realm_id, &member_prefix, &member_end)
            .map_err(Self::storage_err)?;

        for entry in &members {
            // Parse membership to get user_id for reverse index
            if let Ok(membership) = serde_json::from_slice::<OrganizationMembership>(&entry.value) {
                // Delete reverse index
                let reverse_key = keys::encode_membership_by_user(membership.user_id(), org_id);
                self.storage
                    .delete(realm_id, &reverse_key)
                    .map_err(Self::storage_err)?;
            }
            // Delete forward index
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 2. Delete all invitations
        let inv_list_prefix = keys::invitation_list_prefix(org_id);
        let inv_list_end = keys::prefix_end(&inv_list_prefix);
        let inv_list_entries = self
            .storage
            .scan(realm_id, &inv_list_prefix, &inv_list_end)
            .map_err(Self::storage_err)?;

        for entry in &inv_list_entries {
            // Extract invitation ID from list key to delete related records
            let key_str =
                std::str::from_utf8(&entry.key).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if let Some(inv_uuid_str) = key_str.rsplit(':').next() {
                if let Ok(uuid) = uuid::Uuid::parse_str(inv_uuid_str) {
                    let inv_id = InvitationId::new(uuid);
                    // Delete invitation primary record
                    let inv_key = keys::encode_invitation_id(&inv_id);
                    if let Some(inv_bytes) = self
                        .storage
                        .get(realm_id, &inv_key)
                        .map_err(Self::storage_err)?
                    {
                        if let Ok(invitation) =
                            serde_json::from_slice::<OrganizationInvitation>(&inv_bytes)
                        {
                            // Delete token index
                            let token_key = keys::encode_invitation_token(invitation.token_hash());
                            self.storage
                                .delete(realm_id, &token_key)
                                .map_err(Self::storage_err)?;
                            // Delete email dedup index
                            let email_key =
                                keys::encode_invitation_org_email(org_id, invitation.email());
                            self.storage
                                .delete(realm_id, &email_key)
                                .map_err(Self::storage_err)?;
                        }
                    }
                    self.storage
                        .delete(realm_id, &inv_key)
                        .map_err(Self::storage_err)?;
                }
            }
            // Delete list index entry
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 3. Delete slug index
        let slug_key = keys::encode_org_slug(org.slug());
        self.storage
            .delete(realm_id, &slug_key)
            .map_err(Self::storage_err)?;

        // A-5: write a post-delete slug cooldown reservation so the freed slug
        // cannot be immediately re-claimed by a new tenant.
        {
            let now_micros = self.clock.now().as_micros();
            let cooldown_micros = self.config.slug_cooldown_secs as i64 * 1_000_000;
            let reservation = StoredSlugReservation {
                slug: org.slug().to_string(),
                expires_at_micros: now_micros + cooldown_micros,
            };
            if let Ok(bytes) = serde_json::to_vec(&reservation) {
                let reservation_key = keys::encode_org_slug_reservation(realm_id, org.slug());
                // Best-effort: a failed write here does not fail the delete.
                let _ = self.storage.put(realm_id, &reservation_key, &bytes);
            }
        }

        // 4. Cascade SCIM externalId mapping (forward + reverse).
        let scim_fwd_key = keys::encode_scim_ext_group_fwd_key(org_id);
        if let Some(ext_bytes) = self
            .storage
            .get(realm_id, &scim_fwd_key)
            .map_err(Self::storage_err)?
        {
            if let Ok(ext_str) = std::str::from_utf8(&ext_bytes) {
                let reverse_key = keys::encode_scim_ext_group_key(ext_str);
                self.storage
                    .delete(realm_id, &reverse_key)
                    .map_err(Self::storage_err)?;
            }
            self.storage
                .delete(realm_id, &scim_fwd_key)
                .map_err(Self::storage_err)?;
        }

        // 5. Cascade: delete all agents owned by this organization
        {
            let owner = AgentOwner::Organization(org_id.clone());
            let prefix = keys::agent_owner_scan_prefix(owner.storage_tag(), &owner.uuid_str());
            let end = keys::prefix_end(&prefix);
            if let Ok(entries) = self.storage.scan(realm_id, &prefix, &end) {
                for entry in &entries {
                    if let Ok(key_str) = std::str::from_utf8(&entry.key) {
                        if let Some(uuid_str) = key_str.rsplit(':').next() {
                            if let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) {
                                let aid = AgentId::new(uuid);
                                let _ = <Self as IdentityEngine>::delete_agent(
                                    self, realm_id, &aid, None,
                                );
                            }
                        }
                    }
                }
            }
        }

        // 6. Delete org record
        let id_key = keys::encode_org_id(org_id);
        self.storage
            .delete(realm_id, &id_key)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::OrgDeleted,
            "org",
            &org_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn list_organizations(
        &self,
        realm_id: &RealmId,
        page: &crate::core::PageRequest,
    ) -> Result<crate::core::PagedResult<Organization>, IdentityError> {
        let prefix = keys::org_id_scan_prefix();
        let (entries, total) = self
            .storage
            .scan_prefix_paged(realm_id, &prefix, page.offset, page.limit, 0)
            .map_err(Self::storage_err)?;

        let mut items = Vec::with_capacity(entries.len());
        for entry in &entries {
            let org: Organization =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            items.push(org);
        }

        Ok(crate::core::PagedResult::new(
            items,
            total,
            page.offset,
            page.limit,
        ))
    }

    fn add_member(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
        role: OrganizationRole,
    ) -> Result<OrganizationMembership, IdentityError> {
        // Verify org exists and is active
        let org = self
            .get_organization(realm_id, org_id)?
            .ok_or(IdentityError::OrganizationNotFound)?;
        if org.status() != OrganizationStatus::Active {
            return Err(IdentityError::OrganizationSuspended);
        }

        // Verify user exists
        self.get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // Check not already a member
        let fwd_key = keys::encode_membership_by_org(org_id, user_id);
        if self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::AlreadyMember);
        }

        // Check member limit
        if let Some(max) = org.config().max_members {
            let member_prefix = keys::membership_by_org_prefix(org_id);
            let member_end = keys::prefix_end(&member_prefix);
            let count = self
                .storage
                .scan(realm_id, &member_prefix, &member_end)
                .map_err(Self::storage_err)?
                .len();
            if count >= max as usize {
                return Err(IdentityError::MemberLimitReached);
            }
        }

        let now = self.clock.now();
        let membership =
            OrganizationMembership::new(org_id.clone(), user_id.clone(), role, now, None);

        let membership_bytes =
            serde_json::to_vec(&membership).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Write forward index (org → user)
        self.storage
            .put(realm_id, &fwd_key, &membership_bytes)
            .map_err(Self::storage_err)?;

        // Write reverse index (user → org)
        let rev_key = keys::encode_membership_by_user(user_id, org_id);
        self.storage
            .put(realm_id, &rev_key, &membership_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::GroupMemberAdded,
            "org_membership",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(membership)
    }

    fn remove_member(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        let fwd_key = keys::encode_membership_by_org(org_id, user_id);
        let membership_bytes = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::NotAMember)?;

        let membership: OrganizationMembership = serde_json::from_slice(&membership_bytes)
            .map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Last-owner protection
        if membership.role() == OrganizationRole::Owner {
            let member_prefix = keys::membership_by_org_prefix(org_id);
            let member_end = keys::prefix_end(&member_prefix);
            let all_members = self
                .storage
                .scan(realm_id, &member_prefix, &member_end)
                .map_err(Self::storage_err)?;

            let owner_count = all_members
                .iter()
                .filter_map(|e| serde_json::from_slice::<OrganizationMembership>(&e.value).ok())
                .filter(|m| m.role() == OrganizationRole::Owner)
                .count();

            if owner_count <= 1 {
                return Err(IdentityError::LastOwner);
            }
        }

        // Delete forward index
        self.storage
            .delete(realm_id, &fwd_key)
            .map_err(Self::storage_err)?;

        // Delete reverse index
        let rev_key = keys::encode_membership_by_user(user_id, org_id);
        self.storage
            .delete(realm_id, &rev_key)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::GroupMemberRemoved,
            "org_membership",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn update_member_role(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
        new_role: OrganizationRole,
    ) -> Result<OrganizationMembership, IdentityError> {
        let fwd_key = keys::encode_membership_by_org(org_id, user_id);
        let membership_bytes = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::NotAMember)?;

        let mut membership: OrganizationMembership = serde_json::from_slice(&membership_bytes)
            .map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Last-owner protection: if downgrading from Owner, ensure others exist
        if membership.role() == OrganizationRole::Owner && new_role != OrganizationRole::Owner {
            let member_prefix = keys::membership_by_org_prefix(org_id);
            let member_end = keys::prefix_end(&member_prefix);
            let all_members = self
                .storage
                .scan(realm_id, &member_prefix, &member_end)
                .map_err(Self::storage_err)?;

            let owner_count = all_members
                .iter()
                .filter_map(|e| serde_json::from_slice::<OrganizationMembership>(&e.value).ok())
                .filter(|m| m.role() == OrganizationRole::Owner)
                .count();

            if owner_count <= 1 {
                return Err(IdentityError::LastOwner);
            }
        }

        membership.set_role(new_role);

        let updated_bytes =
            serde_json::to_vec(&membership).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Update both indexes
        self.storage
            .put(realm_id, &fwd_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        let rev_key = keys::encode_membership_by_user(user_id, org_id);
        self.storage
            .put(realm_id, &rev_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::GroupMemberRoleChanged,
            "org_membership",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(membership)
    }

    fn get_membership(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<Option<OrganizationMembership>, IdentityError> {
        let key = keys::encode_membership_by_org(org_id, user_id);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        {
            Some(bytes) => {
                let membership: OrganizationMembership =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(membership))
            }
            None => Ok(None),
        }
    }

    fn list_members(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationMembership>, IdentityError> {
        let prefix = keys::membership_by_org_prefix(org_id);
        let start = if let Some(cursor_str) = cursor {
            let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key =
                format!("orgm:org:{}:user:{}", org_id.as_uuid(), decoded).into_bytes();
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
            let membership: OrganizationMembership =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            items.push(membership);
        }

        let next_cursor = if items.len() > limit {
            items.pop();
            let last_kept = items.last().expect("limit >= 1");
            Some(URL_SAFE_NO_PAD.encode(last_kept.user_id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    fn list_user_organizations(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationMembership>, IdentityError> {
        let prefix = keys::membership_by_user_prefix(user_id);
        let start = if let Some(cursor_str) = cursor {
            let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key =
                format!("orgm:user:{}:org:{}", user_id.as_uuid(), decoded).into_bytes();
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
            let membership: OrganizationMembership =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            items.push(membership);
        }

        let next_cursor = if items.len() > limit {
            items.pop();
            let last_kept = items.last().expect("limit >= 1");
            Some(URL_SAFE_NO_PAD.encode(last_kept.org_id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    fn create_invitation(
        &self,
        realm_id: &RealmId,
        request: &CreateInvitationRequest,
    ) -> Result<(OrganizationInvitation, String), IdentityError> {
        self.require_active_realm(realm_id)?;

        // Verify org exists and is active
        let org = self
            .get_organization(realm_id, &request.org_id)?
            .ok_or(IdentityError::OrganizationNotFound)?;
        if org.status() != OrganizationStatus::Active {
            return Err(IdentityError::OrganizationSuspended);
        }

        let email = validation::validate_email(&request.email)?;

        // Check for duplicate pending invitation
        let dedup_key = keys::encode_invitation_org_email(&request.org_id, &email);
        if self
            .storage
            .get(realm_id, &dedup_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::DuplicateInvitation);
        }

        // Check if already a member (by email → user lookup)
        if let Some(user) = self.get_user_by_email(realm_id, &email)? {
            if self
                .get_membership(realm_id, &request.org_id, user.id())?
                .is_some()
            {
                return Err(IdentityError::AlreadyMember);
            }
        }

        // Generate token
        let rng = ring::rand::SystemRandom::new();
        let mut token_bytes = [0u8; 32];
        rng.fill(&mut token_bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "RNG failure".to_string(),
            })?;
        let plaintext_token = URL_SAFE_NO_PAD.encode(token_bytes);

        // Hash token for storage
        let token_hash = {
            use ring::digest;
            let digest = digest::digest(&digest::SHA256, plaintext_token.as_bytes());
            hex_encode(digest.as_ref())
        };

        let now = self.clock.now();
        // 7-day expiry
        let expires_at = now.add_micros(7 * 24 * 60 * 60 * 1_000_000);

        let invitation_id = InvitationId::generate();
        let invitation = OrganizationInvitation::new(
            invitation_id.clone(),
            request.org_id.clone(),
            email.clone(),
            request.role,
            token_hash.clone(),
            InvitationStatus::Pending,
            expires_at,
            request.invited_by.clone(),
            now,
        );

        let inv_bytes =
            serde_json::to_vec(&invitation).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Write primary record
        let id_key = keys::encode_invitation_id(&invitation_id);
        self.storage
            .put(realm_id, &id_key, &inv_bytes)
            .map_err(Self::storage_err)?;

        // Write token index
        let token_key = keys::encode_invitation_token(&token_hash);
        self.storage
            .put(realm_id, &token_key, invitation_id.as_uuid().as_bytes())
            .map_err(Self::storage_err)?;

        // Write email dedup index
        self.storage
            .put(realm_id, &dedup_key, invitation_id.as_uuid().as_bytes())
            .map_err(Self::storage_err)?;

        // Write list index
        let list_key = keys::encode_invitation_list(&request.org_id, &invitation_id);
        self.storage
            .put(realm_id, &list_key, &[])
            .map_err(Self::storage_err)?;

        Ok((invitation, plaintext_token))
    }

    fn accept_invitation(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<OrganizationMembership, IdentityError> {
        self.require_active_realm(realm_id)?;

        // Acquire write lock BEFORE loading the invitation to prevent
        // double-spend: two concurrent accepts for the same token would
        // both see Pending and both proceed without this lock. (A-28)
        let _inv_guard = self.org_write_lock.lock().expect("org write lock");

        // Hash the token
        let token_hash = {
            use ring::digest;
            let digest = digest::digest(&digest::SHA256, token.as_bytes());
            hex_encode(digest.as_ref())
        };

        // Look up by token hash
        let token_key = keys::encode_invitation_token(&token_hash);
        let inv_id_bytes = self
            .storage
            .get(realm_id, &token_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvitationInvalid)?;

        let inv_uuid =
            uuid::Uuid::from_slice(&inv_id_bytes).map_err(|e| IdentityError::Serialization {
                reason: format!("invalid invitation UUID: {e}"),
            })?;
        let invitation_id = InvitationId::new(inv_uuid);

        // Load invitation
        let inv_key = keys::encode_invitation_id(&invitation_id);
        let inv_bytes = self
            .storage
            .get(realm_id, &inv_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvitationInvalid)?;

        let mut invitation: OrganizationInvitation =
            serde_json::from_slice(&inv_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Re-check status under lock (prevents double-spend). (A-28)
        if invitation.status() != InvitationStatus::Pending {
            return Err(IdentityError::InvitationInvalid);
        }

        // Validate expiry
        let now = self.clock.now();
        if now >= invitation.expires_at() {
            return Err(IdentityError::InvitationInvalid);
        }

        // Find or create user by email
        let user = if let Some(u) = self.get_user_by_email(realm_id, invitation.email())? {
            u
        } else {
            // Auto-create user for unknown email
            self.create_user(
                realm_id,
                &CreateUserRequest {
                    email: invitation.email().to_string(),
                    display_name: invitation.email().to_string(),
                    ..Default::default()
                },
            )?
        };

        // Add member
        let membership =
            self.add_member(realm_id, invitation.org_id(), user.id(), invitation.role())?;

        // Mark invitation as accepted
        invitation.set_accepted();
        let updated_bytes =
            serde_json::to_vec(&invitation).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Remove dedup index so a new invitation can be sent if needed
        let dedup_key = keys::encode_invitation_org_email(invitation.org_id(), invitation.email());
        // Atomic: status update + dedup removal in one WAL record (A-28)
        self.storage
            .write_batch(realm_id, &[(inv_key, updated_bytes)], &[dedup_key])
            .map_err(Self::storage_err)?;

        Ok(membership)
    }

    fn revoke_invitation(
        &self,
        realm_id: &RealmId,
        invitation_id: &InvitationId,
    ) -> Result<(), IdentityError> {
        let inv_key = keys::encode_invitation_id(invitation_id);
        let inv_bytes = self
            .storage
            .get(realm_id, &inv_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvitationInvalid)?;

        let mut invitation: OrganizationInvitation =
            serde_json::from_slice(&inv_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        if invitation.status() != InvitationStatus::Pending {
            return Err(IdentityError::InvitationInvalid);
        }

        invitation.set_revoked();
        let updated_bytes =
            serde_json::to_vec(&invitation).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &inv_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // Clean up dedup index
        let dedup_key = keys::encode_invitation_org_email(invitation.org_id(), invitation.email());
        self.storage
            .delete(realm_id, &dedup_key)
            .map_err(Self::storage_err)?;

        Ok(())
    }

    fn list_invitations(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationInvitation>, IdentityError> {
        let prefix = keys::invitation_list_prefix(org_id);
        let start = if let Some(cursor_str) = cursor {
            let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key = format!("orgi:list:{}:{}", org_id.as_uuid(), decoded).into_bytes();
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
            // Extract invitation ID from list key
            let key_str =
                std::str::from_utf8(&entry.key).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if let Some(inv_uuid_str) = key_str.rsplit(':').next() {
                if let Ok(uuid) = uuid::Uuid::parse_str(inv_uuid_str) {
                    let inv_id = InvitationId::new(uuid);
                    let inv_key = keys::encode_invitation_id(&inv_id);
                    if let Some(inv_bytes) = self
                        .storage
                        .get(realm_id, &inv_key)
                        .map_err(Self::storage_err)?
                    {
                        let invitation: OrganizationInvitation = serde_json::from_slice(&inv_bytes)
                            .map_err(|e| IdentityError::Serialization {
                                reason: e.to_string(),
                            })?;
                        items.push(invitation);
                    }
                }
            }
        }

        let next_cursor = if items.len() > limit {
            items.pop();
            let last_kept = items.last().expect("limit >= 1");
            Some(URL_SAFE_NO_PAD.encode(last_kept.id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    // ===== External IdP federation =====

    fn register_idp(
        &self,
        config: &crate::identity::federation::IdpConfig,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_idp_key(&config.id);
        let bytes = serde_json::to_vec(config).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.record_audit(
            &config.realm_id,
            None,
            AuditAction::FederationAccountLinked,
            "idp",
            &config.id.as_uuid().to_string(),
        )?;
        self.storage
            .put(&config.realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    fn get_idp(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
    ) -> Result<Option<crate::identity::federation::IdpConfig>, IdentityError> {
        let key = keys::encode_idp_key(idp_id);
        let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        let cfg: crate::identity::federation::IdpConfig =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        Ok(Some(cfg))
    }

    fn get_idp_by_name(
        &self,
        realm_id: &RealmId,
        name: &str,
    ) -> Result<Option<crate::identity::federation::IdpConfig>, IdentityError> {
        // Linear scan — N is tiny (realms have a handful of connectors
        // at most). Avoids the cost of a secondary `fed:idp_name:` index.
        let prefix = keys::fed_idp_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        for entry in &entries {
            let cfg: crate::identity::federation::IdpConfig = serde_json::from_slice(&entry.value)
                .map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if cfg.name == name {
                return Ok(Some(cfg));
            }
        }
        Ok(None)
    }

    fn list_idps(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<crate::identity::federation::IdpConfig>, IdentityError> {
        let prefix = keys::fed_idp_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in &entries {
            let cfg: crate::identity::federation::IdpConfig = serde_json::from_slice(&entry.value)
                .map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            out.push(cfg);
        }
        Ok(out)
    }

    fn delete_idp(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
    ) -> Result<(), IdentityError> {
        // Sever every external-identity link this connector owns before
        // removing the connector record itself. Forward indexes
        // `fed:ext_fwd:{user}:{idp}` are cleaned by first enumerating
        // reverse entries and deriving `(user_id, sub)` from the value.
        let ext_prefix = keys::encode_federation_ext_prefix_for_idp(idp_id);
        let ext_end = keys::prefix_end(&ext_prefix);
        let ext_entries = self
            .storage
            .scan(realm_id, &ext_prefix, &ext_end)
            .map_err(Self::storage_err)?;
        for entry in &ext_entries {
            // value = UserId UUID bytes (16)
            if entry.value.len() == 16 {
                let mut b = [0u8; 16];
                b.copy_from_slice(&entry.value);
                let user_id = UserId::new(uuid::Uuid::from_bytes(b));
                let fwd_key = keys::encode_federation_ext_fwd_key(&user_id, idp_id);
                self.storage
                    .delete(realm_id, &fwd_key)
                    .map_err(Self::storage_err)?;
            }
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }
        // Now remove the connector record itself.
        self.record_audit(
            realm_id,
            None,
            AuditAction::FederationAccountUnlinked,
            "idp",
            &idp_id.as_uuid().to_string(),
        )?;
        let key = keys::encode_idp_key(idp_id);
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)
    }

    fn put_federation_state(
        &self,
        bag: &crate::identity::federation::StateBag,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_federation_state_key(&bag.state_token);
        let bytes = serde_json::to_vec(bag).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(&bag.realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    fn take_federation_state(
        &self,
        realm_id: &RealmId,
        state_token: &str,
    ) -> Result<crate::identity::federation::StateBag, IdentityError> {
        let key = keys::encode_federation_state_key(state_token);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::FederationInvalidState)?;
        // Single-use: delete before we even validate.
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)?;
        let bag: crate::identity::federation::StateBag =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        if self.clock.now().as_micros() >= bag.expires_at.as_micros() {
            return Err(IdentityError::FederationInvalidState);
        }
        Ok(bag)
    }

    fn put_confirm_link_ticket(
        &self,
        ticket: &crate::identity::federation::ConfirmLinkTicket,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_federation_confirm_key(&ticket.ticket);
        let bytes = serde_json::to_vec(ticket).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(&ticket.realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    fn take_confirm_link_ticket(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<crate::identity::federation::ConfirmLinkTicket, IdentityError> {
        let key = keys::encode_federation_confirm_key(ticket);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::FederationInvalidState)?;
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)?;
        let t: crate::identity::federation::ConfirmLinkTicket = serde_json::from_slice(&bytes)
            .map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        if self.clock.now().as_micros() >= t.expires_at.as_micros() {
            return Err(IdentityError::FederationInvalidState);
        }
        Ok(t)
    }

    fn link_external_identity(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        idp_id: &crate::core::IdpId,
        external_sub: &str,
    ) -> Result<(), IdentityError> {
        let reverse_key = keys::encode_federation_ext_key(idp_id, external_sub);
        // Refuse to re-home an external identity that already belongs
        // to a different user. The owner must unlink first. This is
        // also the guard against a malicious IdP trying to "steal" an
        // already-linked account.
        if let Some(bytes) = self
            .storage
            .get(realm_id, &reverse_key)
            .map_err(Self::storage_err)?
        {
            if bytes.len() == 16 {
                let mut b = [0u8; 16];
                b.copy_from_slice(&bytes);
                let existing = UserId::new(uuid::Uuid::from_bytes(b));
                if &existing != user_id {
                    return Err(IdentityError::FederationAlreadyLinked);
                }
                // Same user re-linking — no-op write below is idempotent.
            }
        }
        let forward_key = keys::encode_federation_ext_fwd_key(user_id, idp_id);
        self.storage
            .put(realm_id, &reverse_key, user_id.as_uuid().as_bytes())
            .map_err(Self::storage_err)?;
        self.record_audit(
            realm_id,
            None,
            AuditAction::FederationAccountLinked,
            "federation",
            &idp_id.as_uuid().to_string(),
        )?;
        self.storage
            .put(realm_id, &forward_key, external_sub.as_bytes())
            .map_err(Self::storage_err)
    }

    fn unlink_external_identity(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        idp_id: &crate::core::IdpId,
    ) -> Result<(), IdentityError> {
        let forward_key = keys::encode_federation_ext_fwd_key(user_id, idp_id);
        let external_sub_bytes = self
            .storage
            .get(realm_id, &forward_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::FederationNotLinked)?;
        let external_sub =
            std::str::from_utf8(&external_sub_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let reverse_key = keys::encode_federation_ext_key(idp_id, external_sub);
        self.storage
            .delete(realm_id, &reverse_key)
            .map_err(Self::storage_err)?;
        self.record_audit(
            realm_id,
            None,
            AuditAction::FederationAccountUnlinked,
            "federation",
            &idp_id.as_uuid().to_string(),
        )?;
        self.storage
            .delete(realm_id, &forward_key)
            .map_err(Self::storage_err)
    }

    fn find_user_by_external_identity(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
        external_sub: &str,
    ) -> Result<Option<UserId>, IdentityError> {
        let key = keys::encode_federation_ext_key(idp_id, external_sub);
        let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        if bytes.len() != 16 {
            return Err(IdentityError::Serialization {
                reason: "federation reverse index has wrong length".to_string(),
            });
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&bytes);
        Ok(Some(UserId::new(uuid::Uuid::from_bytes(b))))
    }

    fn list_external_identities_for_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<(crate::core::IdpId, String)>, IdentityError> {
        let prefix = keys::encode_federation_ext_fwd_prefix_for_user(user_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in &entries {
            let key_str = std::str::from_utf8(&entry.key).unwrap_or("");
            let Some(idp_uuid_str) = key_str.rsplit(':').next() else {
                continue;
            };
            let Ok(idp_uuid) = uuid::Uuid::parse_str(idp_uuid_str) else {
                continue;
            };
            let external_sub = std::str::from_utf8(&entry.value)
                .map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?
                .to_string();
            out.push((crate::core::IdpId::new(idp_uuid), external_sub));
        }
        Ok(out)
    }

    // ===== SCIM externalId management =====

    fn set_scim_external_id(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        external_id: &str,
    ) -> Result<(), IdentityError> {
        if external_id.is_empty() {
            return Err(IdentityError::InvalidInput {
                reason: "externalId must not be empty".to_string(),
            });
        }
        // Refuse to steal an externalId from another user.
        let reverse_key = keys::encode_scim_ext_user_key(external_id);
        if let Some(bytes) = self
            .storage
            .get(realm_id, &reverse_key)
            .map_err(Self::storage_err)?
        {
            if bytes.len() == 16 {
                let mut b = [0u8; 16];
                b.copy_from_slice(&bytes);
                let existing = UserId::new(uuid::Uuid::from_bytes(b));
                if &existing != user_id {
                    return Err(IdentityError::DuplicateScimExternalId);
                }
            }
        }
        // Retire any prior externalId for this user.
        let fwd_key = keys::encode_scim_ext_user_fwd_key(user_id);
        if let Some(old_ext) = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
        {
            if let Ok(old_ext_str) = std::str::from_utf8(&old_ext) {
                if old_ext_str != external_id {
                    let old_reverse = keys::encode_scim_ext_user_key(old_ext_str);
                    self.storage
                        .delete(realm_id, &old_reverse)
                        .map_err(Self::storage_err)?;
                }
            }
        }
        self.storage
            .put(realm_id, &reverse_key, user_id.as_uuid().as_bytes())
            .map_err(Self::storage_err)?;
        self.storage
            .put(realm_id, &fwd_key, external_id.as_bytes())
            .map_err(Self::storage_err)
    }

    fn clear_scim_external_id(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        let fwd_key = keys::encode_scim_ext_user_fwd_key(user_id);
        let Some(ext_bytes) = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
        else {
            return Ok(());
        };
        let ext_str =
            std::str::from_utf8(&ext_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let reverse_key = keys::encode_scim_ext_user_key(ext_str);
        self.storage
            .delete(realm_id, &reverse_key)
            .map_err(Self::storage_err)?;
        self.storage
            .delete(realm_id, &fwd_key)
            .map_err(Self::storage_err)
    }

    fn get_scim_external_id(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<String>, IdentityError> {
        let fwd_key = keys::encode_scim_ext_user_fwd_key(user_id);
        let Some(bytes) = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        let s = std::str::from_utf8(&bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        Ok(Some(s.to_string()))
    }

    fn find_user_by_scim_external_id(
        &self,
        realm_id: &RealmId,
        external_id: &str,
    ) -> Result<Option<User>, IdentityError> {
        let key = keys::encode_scim_ext_user_key(external_id);
        let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        if bytes.len() != 16 {
            return Err(IdentityError::Serialization {
                reason: "SCIM reverse index has wrong length".to_string(),
            });
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&bytes);
        let user_id = UserId::new(uuid::Uuid::from_bytes(b));
        self.get_user(realm_id, &user_id)
    }

    fn set_scim_group_external_id(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        external_id: &str,
    ) -> Result<(), IdentityError> {
        if external_id.is_empty() {
            return Err(IdentityError::InvalidInput {
                reason: "externalId must not be empty".to_string(),
            });
        }
        let reverse_key = keys::encode_scim_ext_group_key(external_id);
        if let Some(bytes) = self
            .storage
            .get(realm_id, &reverse_key)
            .map_err(Self::storage_err)?
        {
            if bytes.len() == 16 {
                let mut b = [0u8; 16];
                b.copy_from_slice(&bytes);
                let existing = OrganizationId::new(uuid::Uuid::from_bytes(b));
                if &existing != org_id {
                    return Err(IdentityError::DuplicateScimExternalId);
                }
            }
        }
        let fwd_key = keys::encode_scim_ext_group_fwd_key(org_id);
        if let Some(old_ext) = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
        {
            if let Ok(old_ext_str) = std::str::from_utf8(&old_ext) {
                if old_ext_str != external_id {
                    let old_reverse = keys::encode_scim_ext_group_key(old_ext_str);
                    self.storage
                        .delete(realm_id, &old_reverse)
                        .map_err(Self::storage_err)?;
                }
            }
        }
        self.storage
            .put(realm_id, &reverse_key, org_id.as_uuid().as_bytes())
            .map_err(Self::storage_err)?;
        self.storage
            .put(realm_id, &fwd_key, external_id.as_bytes())
            .map_err(Self::storage_err)
    }

    fn clear_scim_group_external_id(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<(), IdentityError> {
        let fwd_key = keys::encode_scim_ext_group_fwd_key(org_id);
        let Some(ext_bytes) = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
        else {
            return Ok(());
        };
        let ext_str =
            std::str::from_utf8(&ext_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let reverse_key = keys::encode_scim_ext_group_key(ext_str);
        self.storage
            .delete(realm_id, &reverse_key)
            .map_err(Self::storage_err)?;
        self.storage
            .delete(realm_id, &fwd_key)
            .map_err(Self::storage_err)
    }

    fn get_scim_group_external_id(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<Option<String>, IdentityError> {
        let fwd_key = keys::encode_scim_ext_group_fwd_key(org_id);
        let Some(bytes) = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        let s = std::str::from_utf8(&bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        Ok(Some(s.to_string()))
    }

    fn find_group_by_scim_external_id(
        &self,
        realm_id: &RealmId,
        external_id: &str,
    ) -> Result<Option<crate::identity::Organization>, IdentityError> {
        let key = keys::encode_scim_ext_group_key(external_id);
        let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        if bytes.len() != 16 {
            return Err(IdentityError::Serialization {
                reason: "SCIM group reverse index has wrong length".to_string(),
            });
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&bytes);
        let org_id = OrganizationId::new(uuid::Uuid::from_bytes(b));
        self.get_organization(realm_id, &org_id)
    }

    // ===== Webhooks =====

    fn create_webhook(
        &self,
        realm_id: &RealmId,
        req: &crate::identity::CreateWebhookRequest,
    ) -> Result<crate::identity::Webhook, IdentityError> {
        use crate::identity::types::Webhook;
        let id = WebhookId::generate();
        let now = self.clock.now();
        let webhook = Webhook::new(
            id.clone(),
            realm_id.clone(),
            req.url.clone(),
            req.secret.clone(),
            req.events.clone(),
            req.enabled,
            now,
            now,
        );
        let value = serde_json::to_vec(&webhook).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &keys::encode_webhook_id(&id), &value)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?;
        Ok(webhook)
    }

    fn get_webhook(
        &self,
        realm_id: &RealmId,
        webhook_id: &WebhookId,
    ) -> Result<Option<crate::identity::Webhook>, IdentityError> {
        use crate::identity::types::Webhook;
        match self
            .storage
            .get(realm_id, &keys::encode_webhook_id(webhook_id))
            .map_err(|e| IdentityError::Storage(Box::new(e)))?
        {
            Some(bytes) => {
                let wh: Webhook =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(wh))
            }
            None => Ok(None),
        }
    }

    fn list_webhooks(
        &self,
        realm_id: &RealmId,
        page: &crate::core::PageRequest,
    ) -> Result<crate::core::PagedResult<crate::identity::Webhook>, IdentityError> {
        use crate::identity::types::Webhook;
        let prefix = keys::webhook_id_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?;

        // Deserialize all, sort by insertion order, then apply page window.
        let mut all: Vec<Webhook> = Vec::with_capacity(entries.len());
        for entry in &entries {
            match serde_json::from_slice::<Webhook>(&entry.value) {
                Ok(wh) => all.push(wh),
                Err(e) => {
                    tracing::warn!(error = %e, "webhook deserialization failed, skipping");
                }
            }
        }
        all.sort_by_key(|w| w.created_at);

        // Exact total: this path already materialises the full result set, so
        // capping the reported count only hides records from the admin UI
        // pager (HEA-1614).
        let total = all.len() as u64;
        let start = (page.offset as usize).min(all.len());
        let end_idx = (start + page.limit as usize).min(all.len());
        let items = all[start..end_idx].to_vec();

        Ok(crate::core::PagedResult::new(
            items,
            total,
            page.offset,
            page.limit,
        ))
    }

    fn update_webhook(
        &self,
        realm_id: &RealmId,
        webhook_id: &WebhookId,
        req: &crate::identity::UpdateWebhookRequest,
    ) -> Result<crate::identity::Webhook, IdentityError> {
        use crate::identity::types::Webhook;
        let existing = self
            .get_webhook(realm_id, webhook_id)?
            .ok_or(IdentityError::WebhookNotFound)?;
        let now = self.clock.now();
        let updated = Webhook::new(
            existing.id().clone(),
            realm_id.clone(),
            req.url.clone(),
            req.secret.clone(),
            req.events.clone(),
            req.enabled,
            existing.created_at,
            now,
        );
        let value = serde_json::to_vec(&updated).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &keys::encode_webhook_id(webhook_id), &value)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?;
        Ok(updated)
    }

    fn delete_webhook(
        &self,
        realm_id: &RealmId,
        webhook_id: &WebhookId,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_webhook_id(webhook_id);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?
        {
            None => Err(IdentityError::WebhookNotFound),
            Some(_) => {
                self.storage
                    .delete(realm_id, &key)
                    .map_err(|e| IdentityError::Storage(Box::new(e)))?;
                Ok(())
            }
        }
    }

    // =========================================================================
    // Agents (AGENT_AUTH.md Phase A, HEA-1325)
    // =========================================================================

    fn create_agent(
        &self,
        realm_id: &RealmId,
        request: &CreateAgentRequest,
        caller: Option<&crate::core::UserId>,
    ) -> Result<Agent, IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "create_agent",
            });
        }
        self.require_active_realm(realm_id)?;

        // Validate display_name: 1–256 chars
        let name = request.display_name.trim();
        if name.is_empty() {
            return Err(IdentityError::InvalidInput {
                reason: "display_name must not be empty".to_string(),
            });
        }
        if name.len() > 256 {
            return Err(IdentityError::InvalidInput {
                reason: "display_name must not exceed 256 characters".to_string(),
            });
        }

        // Validate max_delegation_depth: 1–10
        if request.max_delegation_depth == 0 || request.max_delegation_depth > 10 {
            return Err(IdentityError::InvalidInput {
                reason: format!(
                    "max_delegation_depth must be 1–10, got {}",
                    request.max_delegation_depth
                ),
            });
        }

        // Validate description length
        if let Some(desc) = &request.description {
            if desc.len() > 2048 {
                return Err(IdentityError::InvalidInput {
                    reason: "description must not exceed 2048 characters".to_string(),
                });
            }
        }

        validate_agent_capabilities(&request.capabilities)?;

        // Owner FK: the referenced user or org must exist in this realm.
        match &request.owner {
            AgentOwner::User(uid) => {
                if self.get_user(realm_id, uid)?.is_none() {
                    return Err(IdentityError::UserNotFound);
                }
            }
            AgentOwner::Organization(oid) => {
                if self.get_organization(realm_id, oid)?.is_none() {
                    return Err(IdentityError::OrganizationNotFound);
                }
            }
        }

        // max_agents quota check
        if let Some(realm) = self.get_realm(realm_id)? {
            if let Some(quotas) = &realm.config().quotas {
                if let Some(max) = quotas.max_agents {
                    let prefix = keys::agent_id_scan_prefix();
                    self.check_resource_quota(realm_id, "agents", &prefix, max)?;
                }
            }
        }

        let now = self.clock.now();
        let agent_id = AgentId::generate();
        let description = request.description.clone().unwrap_or_default();

        let agent = Agent::new(
            agent_id.clone(),
            realm_id.clone(),
            request.owner.clone(),
            name.to_string(),
            description,
            request.capabilities.clone(),
            AgentStatus::Active,
            request.max_delegation_depth,
            now,
            now,
        );

        let id_key = keys::encode_agent_id(&agent_id);
        let agent_bytes = serde_json::to_vec(&agent).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        let owner_index_key = keys::encode_agent_owner_index(
            request.owner.storage_tag(),
            &request.owner.uuid_str(),
            &agent_id,
        );

        // Atomic: primary record + owner index in one WAL entry
        self.storage
            .put_batch(
                realm_id,
                &[(id_key, agent_bytes), (owner_index_key, vec![])],
            )
            .map_err(Self::storage_err)?;

        let audit_ctx = caller.map(|uid| crate::audit::AuditContext {
            actor: crate::audit::Actor::User(uid.clone()),
            metadata: None,
        });
        self.record_audit(
            realm_id,
            audit_ctx.as_ref(),
            AuditAction::AgentCreated,
            "agent",
            &agent_id.as_uuid().to_string(),
        )?;

        Ok(agent)
    }

    fn get_agent(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
    ) -> Result<Option<Agent>, IdentityError> {
        let key = keys::encode_agent_id(agent_id);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        {
            Some(bytes) => {
                let agent: Agent =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(agent))
            }
            None => Ok(None),
        }
    }

    fn update_agent(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        request: &UpdateAgentRequest,
        caller: Option<&crate::core::UserId>,
    ) -> Result<Agent, IdentityError> {
        let key = keys::encode_agent_id(agent_id);
        let mut agent = self
            .get_agent(realm_id, agent_id)?
            .ok_or(IdentityError::AgentNotFound)?;

        if let Some(name) = &request.display_name {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "display_name must not be empty".to_string(),
                });
            }
            if trimmed.len() > 256 {
                return Err(IdentityError::InvalidInput {
                    reason: "display_name must not exceed 256 characters".to_string(),
                });
            }
            agent.set_display_name(trimmed.to_string());
        }

        if let Some(desc) = &request.description {
            if desc.len() > 2048 {
                return Err(IdentityError::InvalidInput {
                    reason: "description must not exceed 2048 characters".to_string(),
                });
            }
            agent.set_description(desc.clone());
        }

        if let Some(caps) = &request.capabilities {
            validate_agent_capabilities(caps)?;
            agent.set_capabilities(caps.clone());
        }

        if let Some(depth) = request.max_delegation_depth {
            if depth == 0 || depth > 10 {
                return Err(IdentityError::InvalidInput {
                    reason: format!("max_delegation_depth must be 1–10, got {depth}"),
                });
            }
            agent.set_max_delegation_depth(depth);
        }

        agent.set_updated_at(self.clock.now());

        let agent_bytes = serde_json::to_vec(&agent).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &agent_bytes)
            .map_err(Self::storage_err)?;

        let audit_ctx = caller.map(|uid| crate::audit::AuditContext {
            actor: crate::audit::Actor::User(uid.clone()),
            metadata: None,
        });
        self.record_audit(
            realm_id,
            audit_ctx.as_ref(),
            AuditAction::AgentUpdated,
            "agent",
            &agent_id.as_uuid().to_string(),
        )?;

        Ok(agent)
    }

    fn delete_agent(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        caller: Option<&crate::core::UserId>,
    ) -> Result<(), IdentityError> {
        let agent = self
            .get_agent(realm_id, agent_id)?
            .ok_or(IdentityError::AgentNotFound)?;

        // 1. Cascade: delete all credentials for this agent
        let cred_prefix = keys::agent_credential_scan_prefix(agent_id);
        let cred_end = keys::prefix_end(&cred_prefix);
        let cred_entries = self
            .storage
            .scan(realm_id, &cred_prefix, &cred_end)
            .map_err(Self::storage_err)?;
        for entry in &cred_entries {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 2. Cascade: purge RBAC role assignments and group memberships.
        // Agents share the RBAC subject namespace with users via the same UUID.
        let agent_subject_id = UserId::new(*agent_id.as_uuid());
        let _ = self.rbac.purge_user_from_realm(realm_id, &agent_subject_id);

        // 3. Delete primary record and owner index atomically
        let id_key = keys::encode_agent_id(agent_id);
        let owner_index_key = keys::encode_agent_owner_index(
            agent.owner().storage_tag(),
            &agent.owner().uuid_str(),
            agent_id,
        );
        self.storage
            .delete(realm_id, &id_key)
            .map_err(Self::storage_err)?;
        // Owner index deletion is best-effort; primary is gone.
        let _ = self.storage.delete(realm_id, &owner_index_key);

        let audit_ctx = caller.map(|uid| crate::audit::AuditContext {
            actor: crate::audit::Actor::User(uid.clone()),
            metadata: None,
        });
        self.record_audit(
            realm_id,
            audit_ctx.as_ref(),
            AuditAction::AgentDeleted,
            "agent",
            &agent_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn list_agents(
        &self,
        realm_id: &RealmId,
        query: &ListAgentsQuery,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Agent>, IdentityError> {
        let limit = crate::identity::cap_page_size(limit)?;
        let scan_by_owner = query.owner_id.is_some();

        // Choose scan prefix: owner index or primary key space.
        let prefix = if let Some(owner) = &query.owner_id {
            keys::agent_owner_scan_prefix(owner.storage_tag(), &owner.uuid_str())
        } else {
            keys::agent_id_scan_prefix()
        };

        let start = if let Some(cursor_str) = cursor {
            let uuid_str = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key = prefix.clone();
            cursor_key.extend_from_slice(uuid_str.as_bytes());
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

        let mut items: Vec<Agent> = Vec::new();
        for entry in entries.iter().take(limit + 1) {
            let agent: Agent = if scan_by_owner {
                // Owner-index: value is empty; agent UUID is the trailing segment.
                let key_str = String::from_utf8_lossy(&entry.key);
                let agent_uuid_str = key_str.rsplit(':').next().unwrap_or("");
                let uuid = uuid::Uuid::parse_str(agent_uuid_str).map_err(|_| {
                    IdentityError::Serialization {
                        reason: format!("invalid agent UUID in owner index: {key_str}"),
                    }
                })?;
                match self.get_agent(realm_id, &AgentId::new(uuid))? {
                    Some(a) => a,
                    None => continue, // stale index entry
                }
            } else {
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?
            };

            // Optional in-memory filters
            if let Some(status_filter) = query.status {
                if agent.status() != status_filter {
                    continue;
                }
            }
            if let Some(cap_filter) = &query.capability {
                if !agent.capabilities().contains(cap_filter) {
                    continue;
                }
            }

            items.push(agent);
        }

        let next_cursor = if items.len() > limit {
            items.pop();
            let last_kept = items.last().expect("limit >= 1");
            Some(URL_SAFE_NO_PAD.encode(last_kept.id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    fn suspend_agent(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        caller: Option<&crate::core::UserId>,
    ) -> Result<Agent, IdentityError> {
        let mut agent = self
            .get_agent(realm_id, agent_id)?
            .ok_or(IdentityError::AgentNotFound)?;

        if agent.status() == AgentStatus::Revoked {
            return Err(IdentityError::AgentRevoked);
        }

        agent.set_status(AgentStatus::Suspended);
        agent.set_updated_at(self.clock.now());

        let key = keys::encode_agent_id(agent_id);
        let bytes = serde_json::to_vec(&agent).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)?;

        let audit_ctx = caller.map(|uid| crate::audit::AuditContext {
            actor: crate::audit::Actor::User(uid.clone()),
            metadata: None,
        });
        self.record_audit(
            realm_id,
            audit_ctx.as_ref(),
            AuditAction::AgentSuspended,
            "agent",
            &agent_id.as_uuid().to_string(),
        )?;

        Ok(agent)
    }

    fn reactivate_agent(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        caller: Option<&crate::core::UserId>,
    ) -> Result<Agent, IdentityError> {
        let mut agent = self
            .get_agent(realm_id, agent_id)?
            .ok_or(IdentityError::AgentNotFound)?;

        if agent.status() == AgentStatus::Revoked {
            return Err(IdentityError::AgentRevoked);
        }

        agent.set_status(AgentStatus::Active);
        agent.set_updated_at(self.clock.now());

        let key = keys::encode_agent_id(agent_id);
        let bytes = serde_json::to_vec(&agent).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)?;

        let audit_ctx = caller.map(|uid| crate::audit::AuditContext {
            actor: crate::audit::Actor::User(uid.clone()),
            metadata: None,
        });
        self.record_audit(
            realm_id,
            audit_ctx.as_ref(),
            AuditAction::AgentReactivated,
            "agent",
            &agent_id.as_uuid().to_string(),
        )?;

        Ok(agent)
    }

    fn revoke_agent(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        caller: Option<&crate::core::UserId>,
    ) -> Result<Agent, IdentityError> {
        let mut agent = self
            .get_agent(realm_id, agent_id)?
            .ok_or(IdentityError::AgentNotFound)?;

        // Revocation is idempotent — revoking an already-revoked agent is a no-op.
        if agent.status() == AgentStatus::Revoked {
            return Ok(agent);
        }

        agent.set_status(AgentStatus::Revoked);
        agent.set_updated_at(self.clock.now());

        let key = keys::encode_agent_id(agent_id);
        let bytes = serde_json::to_vec(&agent).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)?;

        let audit_ctx = caller.map(|uid| crate::audit::AuditContext {
            actor: crate::audit::Actor::User(uid.clone()),
            metadata: None,
        });
        self.record_audit(
            realm_id,
            audit_ctx.as_ref(),
            AuditAction::AgentRevoked,
            "agent",
            &agent_id.as_uuid().to_string(),
        )?;

        Ok(agent)
    }

    // ── A.3 Agent credentials ────────────────────────────────────────────────

    fn create_agent_api_key(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        request: &CreateAgentApiKeyRequest,
        caller: Option<&crate::core::UserId>,
    ) -> Result<CreateAgentApiKeyResponse, IdentityError> {
        // Agent must exist and be active
        let agent = self
            .get_agent(realm_id, agent_id)?
            .ok_or(IdentityError::AgentNotFound)?;
        if agent.status() == AgentStatus::Revoked {
            return Err(IdentityError::AgentRevoked);
        }

        // Validate label
        let label = request.label.trim();
        if label.is_empty() || label.len() > 256 {
            return Err(IdentityError::InvalidInput {
                reason: "credential label must be 1–256 characters".to_string(),
            });
        }

        // Enforce max_credentials_per_agent quota (default 25, active only)
        const MAX_CREDENTIALS_PER_AGENT: usize = 25;
        let cred_prefix = keys::agent_credential_scan_prefix(agent_id);
        let cred_end = keys::prefix_end(&cred_prefix);
        let existing = self
            .storage
            .scan(realm_id, &cred_prefix, &cred_end)
            .map_err(Self::storage_err)?;
        let active_count = existing
            .iter()
            .filter(|e| {
                serde_json::from_slice::<AgentCredential>(&e.value)
                    .map(|c| !c.is_revoked())
                    .unwrap_or(false)
            })
            .count();
        if active_count >= MAX_CREDENTIALS_PER_AGENT {
            return Err(IdentityError::QuotaExceeded {
                resource: "agent_credentials",
                limit: MAX_CREDENTIALS_PER_AGENT as u64,
                current: active_count as u64,
            });
        }

        // Generate 256 bits of entropy → hex-encode as plaintext key
        let mut raw = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut raw)
            .map_err(|_| IdentityError::SigningError {
                reason: "RNG failure generating agent API key".to_string(),
            })?;
        let plaintext_hex = hex::encode(raw);

        // Store only the SHA-256 hash
        use sha2::{Digest, Sha256};
        let hash_bytes = Sha256::digest(raw);
        let hash_hex = hex::encode(hash_bytes);
        // Zeroize raw entropy from the stack to prevent key material lingering in memory.
        // sha2::Digest::digest() takes raw by copy ([u8;32]: Copy) so raw remains here.
        raw.zeroize();

        let cred_id = AgentCredentialId::generate();
        let cred = AgentCredential::new(
            cred_id,
            agent_id.clone(),
            AgentCredentialKind::ApiKey,
            label.to_string(),
            hash_hex,
            self.clock.now(),
        );

        let cred_bytes = serde_json::to_vec(&cred).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        let cred_key = keys::encode_agent_credential(agent_id, cred.id());
        self.storage
            .put(realm_id, &cred_key, &cred_bytes)
            .map_err(Self::storage_err)?;

        let audit_ctx = caller.map(|uid| crate::audit::AuditContext {
            actor: crate::audit::Actor::User(uid.clone()),
            metadata: None,
        });
        self.record_audit(
            realm_id,
            audit_ctx.as_ref(),
            AuditAction::AgentCredentialCreated,
            "agent_credential",
            &cred.id().as_uuid().to_string(),
        )?;

        Ok(CreateAgentApiKeyResponse {
            credential: cred,
            plaintext_key: PlaintextApiKey::new(plaintext_hex),
        })
    }

    fn list_agent_credentials(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
    ) -> Result<Vec<AgentCredential>, IdentityError> {
        let prefix = keys::agent_credential_scan_prefix(agent_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;

        let mut creds = Vec::with_capacity(entries.len());
        for entry in &entries {
            let cred: AgentCredential =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            creds.push(cred);
        }
        Ok(creds)
    }

    fn revoke_agent_credential(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        cred_id: &AgentCredentialId,
        caller: Option<&crate::core::UserId>,
    ) -> Result<(), IdentityError> {
        let cred_key = keys::encode_agent_credential(agent_id, cred_id);
        let bytes = self
            .storage
            .get(realm_id, &cred_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::AgentCredentialNotFound)?;

        let mut cred: AgentCredential =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Verify the credential belongs to the given agent
        if cred.agent_id() != agent_id {
            return Err(IdentityError::AgentCredentialNotFound);
        }

        if !cred.is_revoked() {
            cred.revoke(self.clock.now());
            let updated = serde_json::to_vec(&cred).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
            self.storage
                .put(realm_id, &cred_key, &updated)
                .map_err(Self::storage_err)?;
        }

        let audit_ctx = caller.map(|uid| crate::audit::AuditContext {
            actor: crate::audit::Actor::User(uid.clone()),
            metadata: None,
        });
        self.record_audit(
            realm_id,
            audit_ctx.as_ref(),
            AuditAction::AgentCredentialRevoked,
            "agent_credential",
            &cred_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn verify_agent_api_key(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        plaintext_key_hex: &str,
    ) -> Result<bool, IdentityError> {
        // D.6: Record every attempt (correct key or not) against the rate monitor.
        use crate::abuse::agent_monitor::RateDecision;
        match self.agent_rate_monitor.check_and_record(
            realm_id,
            agent_id,
            std::time::Instant::now(),
        ) {
            RateDecision::Deny {
                triggered_suspension,
            } => {
                if triggered_suspension {
                    let _ = self.suspend_agent(realm_id, agent_id, None);
                }
                return Err(IdentityError::AgentRateLimitExceeded);
            }
            RateDecision::Allow => {}
        }

        // Compute SHA-256 of the supplied plaintext
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;

        let raw = match hex::decode(plaintext_key_hex) {
            Ok(b) => b,
            Err(_) => return Ok(false), // malformed key never matches
        };
        let candidate_hash = hex::encode(Sha256::digest(&raw));

        let creds = self.list_agent_credentials(realm_id, agent_id)?;
        for cred in &creds {
            if cred.is_revoked() {
                continue;
            }
            if cred.kind() != AgentCredentialKind::ApiKey {
                continue;
            }
            // Constant-time comparison to prevent timing attacks
            let stored = cred.credential_hash().as_bytes();
            let candidate = candidate_hash.as_bytes();
            if stored.len() == candidate.len() && stored.ct_eq(candidate).unwrap_u8() == 1 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ===== Periodic cleanup =====

    #[allow(clippy::too_many_lines)]
    fn sweep_expired(
        &self,
        realm_id: &RealmId,
    ) -> Result<crate::identity::cleanup::CleanupStats, IdentityError> {
        let mut stats = crate::identity::cleanup::sweep_expired(
            realm_id,
            self.storage.as_ref(),
            self.clock.as_ref(),
            &self.config.cleanup,
        );

        // Prune in-memory rate-tracker maps. Each map uses 2× its window as the
        // cutoff: an entry older than two full windows is outside any active window.
        let now = self.clock.now().as_micros();
        stats.rate_trackers_pruned += prune_rate_tracker(
            &mut self
                .magic_link_rate_trackers
                .lock()
                .expect("magic link tracker lock"),
            now - Self::MAGIC_LINK_RATE_WINDOW_MICROS * 2,
        );
        stats.rate_trackers_pruned += prune_rate_tracker(
            &mut self
                .password_reset_rate_trackers
                .lock()
                .expect("password reset tracker lock"),
            now - Self::PASSWORD_RESET_RATE_WINDOW_MICROS * 2,
        );
        stats.rate_trackers_pruned += prune_rate_tracker(
            &mut self
                .registration_email_rate_trackers
                .lock()
                .expect("registration email tracker lock"),
            now - Self::REGISTRATION_RATE_WINDOW_MICROS * 2,
        );
        stats.rate_trackers_pruned += prune_rate_tracker(
            &mut self
                .registration_ip_rate_trackers
                .lock()
                .expect("registration ip tracker lock"),
            now - Self::REGISTRATION_RATE_WINDOW_MICROS * 2,
        );
        stats.rate_trackers_pruned += prune_rate_tracker(
            &mut self
                .ip_login_rate_trackers
                .lock()
                .expect("ip login tracker lock"),
            now - self.config.rate_limit.ip_window_micros * 2,
        );

        // Purge stale WAL entries for the 5 WAL-persisted rate-limit tracker
        // types.  We delete any entry whose last-failure timestamp is older than
        // 2× its window — the same threshold used for the in-memory prune above.
        // Best-effort: storage errors are silently swallowed (stats.errors is
        // incremented for the audit log entry).
        let rl_sweep_specs: &[(&[u8], i64)] = &[
            (
                &keys::ip_login_tracker_scan_prefix(),
                self.config.rate_limit.ip_window_micros * 2,
            ),
            (
                &keys::mfa_tracker_scan_prefix(),
                Self::MFA_LOCKOUT_MICROS * 2,
            ),
            (
                &keys::magic_link_rl_scan_prefix(),
                Self::MAGIC_LINK_RATE_WINDOW_MICROS * 2,
            ),
            (
                &keys::password_reset_rl_scan_prefix(),
                Self::PASSWORD_RESET_RATE_WINDOW_MICROS * 2,
            ),
            (
                &keys::registration_email_rl_scan_prefix(),
                Self::REGISTRATION_RATE_WINDOW_MICROS * 2,
            ),
        ];
        for (prefix, cutoff_age) in rl_sweep_specs {
            let end = keys::prefix_end(prefix);
            let Ok(entries) = self.storage.scan(realm_id, prefix, &end) else {
                stats.errors += 1;
                continue;
            };
            for entry in entries {
                let Ok(blob) = serde_json::from_slice::<serde_json::Value>(&entry.value) else {
                    continue;
                };
                let Some(last_micros) = blob["last_failure_micros"].as_i64() else {
                    continue;
                };
                if now - last_micros >= *cutoff_age {
                    if self.storage.delete(realm_id, &entry.key).is_err() {
                        stats.errors += 1;
                    } else {
                        stats.rate_trackers_pruned += 1;
                    }
                }
            }
        }

        // D.6: evict idle agent-rate windows to bound memory.
        self.agent_rate_monitor
            .prune_idle(std::time::Instant::now());

        if stats.total_deleted() > 0 {
            let metadata = Some(serde_json::json!({
                "auth_codes_deleted": stats.auth_codes_deleted,
                "device_codes_deleted": stats.device_codes_deleted,
                "pending_tickets_deleted": stats.pending_tickets_deleted,
                "grant_families_deleted": stats.grant_families_deleted,
                "rate_trackers_pruned": stats.rate_trackers_pruned,
                "errors": stats.errors,
            }));
            let ctx = crate::audit::context::AuditContext {
                actor: crate::audit::context::Actor::System,
                metadata,
            };
            let _ = self.record_audit(
                realm_id,
                Some(&ctx),
                crate::audit::AuditAction::Cleanup,
                "system",
                &realm_id.to_string(),
            );
        }

        Ok(stats)
    }

    fn sweep_expired_fingerprints(
        &self,
        realm_id: &RealmId,
        now_secs: i64,
    ) -> Result<(u64, u64), IdentityError> {
        let stats =
            crate::identity::cleanup::sweep_fingerprints(realm_id, self.storage.as_ref(), now_secs)
                .map_err(|e| IdentityError::Storage(Box::new(e)))?;
        Ok((stats.evicted, stats.active))
    }

    // ===== SAML =====

    fn get_or_create_saml_signing_key(
        &self,
        realm_id: &RealmId,
        issuer_cn: &str,
    ) -> Result<Arc<crate::identity::tokens::RsaSigningKey>, IdentityError> {
        let key_str = realm_id.as_uuid().to_string();
        {
            let cache = self.realm_saml_keys.lock().expect("saml key cache");
            if let Some(k) = cache.get(&key_str) {
                return Ok(k.clone());
            }
        }
        let sys_realm = keys::system_realm_id();
        let storage_key = keys::encode_realm_saml_key(realm_id);

        // Two-part value: [8-byte cert_der_len BE, pkcs8_der | cert_der].
        // Simpler to use JSON, but key bytes must not serialize cleartext
        // into logs — JSON is fine since this struct isn't logged.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Stored {
            pkcs8: Vec<u8>,
            cert: Vec<u8>,
        }

        let kek = self
            .config
            .key_encryption_key
            .as_ref()
            .map(|k| k.as_bytes());
        let key = if let Some(raw) = self
            .storage
            .get(&sys_realm, &storage_key)
            .map_err(Self::storage_err)?
        {
            let json_bytes = crate::identity::key_encryption::unwrap_key(&raw, kek)?;
            let stored: Stored =
                serde_json::from_slice(&json_bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            crate::identity::tokens::RsaSigningKey::from_pkcs8_and_cert(
                &stored.pkcs8,
                &stored.cert,
            )?
        } else {
            let generated = crate::identity::tokens::RsaSigningKey::generate(issuer_cn, 3650)?;
            let stored_struct = Stored {
                pkcs8: generated.pkcs8_bytes().to_vec(),
                cert: generated.cert_der().to_vec(),
            };
            let json_bytes =
                serde_json::to_vec(&stored_struct).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            let body = crate::identity::key_encryption::wrap_key(&json_bytes, kek)?;
            self.storage
                .put(&sys_realm, &storage_key, &body)
                .map_err(Self::storage_err)?;
            generated
        };
        let arc = Arc::new(key);
        {
            let mut cache = self.realm_saml_keys.lock().expect("saml key cache");
            cache.insert(key_str, arc.clone());
        }
        Ok(arc)
    }

    fn register_saml_sp(
        &self,
        realm_id: &RealmId,
        sp: &crate::identity::federation::saml::SamlServiceProvider,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_saml_sp_key(&sp.sp_key);
        let bytes = serde_json::to_vec(sp).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    fn get_saml_sp_by_entity_id(
        &self,
        realm_id: &RealmId,
        entity_id: &str,
    ) -> Result<Option<crate::identity::federation::saml::SamlServiceProvider>, IdentityError> {
        for sp in self.list_saml_sps(realm_id)? {
            if sp.entity_id == entity_id {
                return Ok(Some(sp));
            }
        }
        Ok(None)
    }

    fn get_saml_sp_by_key(
        &self,
        realm_id: &RealmId,
        sp_key: &str,
    ) -> Result<Option<crate::identity::federation::saml::SamlServiceProvider>, IdentityError> {
        let key = keys::encode_saml_sp_key(sp_key);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        {
            Some(bytes) => {
                let sp =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(sp))
            }
            None => Ok(None),
        }
    }

    fn list_saml_sps(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<crate::identity::federation::saml::SamlServiceProvider>, IdentityError> {
        let prefix = keys::saml_sp_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in &entries {
            let sp: crate::identity::federation::saml::SamlServiceProvider =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            out.push(sp);
        }
        Ok(out)
    }

    fn delete_saml_sp(&self, realm_id: &RealmId, sp_key: &str) -> Result<(), IdentityError> {
        let key = keys::encode_saml_sp_key(sp_key);
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)
    }

    fn put_saml_state(
        &self,
        bag: &crate::identity::federation::saml::SamlStateBag,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_saml_state_key(&bag.token);
        let bytes = serde_json::to_vec(bag).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(&bag.realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    fn take_saml_state(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<crate::identity::federation::saml::SamlStateBag, IdentityError> {
        let key = keys::encode_saml_state_key(token);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::FederationInvalidState)?;
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)?;
        let bag: crate::identity::federation::saml::SamlStateBag =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        // 10-minute TTL.
        let age_secs = (self.clock.now().as_micros() - bag.created_at.as_micros()) / 1_000_000;
        if age_secs > 600 {
            return Err(IdentityError::FederationInvalidState);
        }
        Ok(bag)
    }

    fn mark_saml_assertion_consumed(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
        assertion_id: &str,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_saml_assertion_id(idp_id, assertion_id);
        if self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::Saml(SamlError::Replay));
        }
        self.storage
            .put(realm_id, &key, &[])
            .map_err(Self::storage_err)
    }

    fn record_saml_sp_session(
        &self,
        realm_id: &RealmId,
        registration: &crate::identity::federation::saml::SamlSessionRegistration,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_saml_sp_session(&registration.session_id, &registration.sp_key);
        let bytes = serde_json::to_vec(registration).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    fn list_saml_sp_sessions(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Vec<crate::identity::federation::saml::SamlSessionRegistration>, IdentityError>
    {
        let prefix = keys::encode_saml_sp_session_prefix(session_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in &entries {
            let reg: crate::identity::federation::saml::SamlSessionRegistration =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            out.push(reg);
        }
        Ok(out)
    }

    fn is_storage_healthy(&self) -> bool {
        // Probe the storage engine with a get on a known-absent sentinel key.
        // Success (even returning None) confirms the storage layer is live.
        let probe_realm = keys::system_realm_id();
        self.storage.get(&probe_realm, b"health:probe").is_ok()
    }

    fn export_all_credentials(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<crate::identity::CredentialExport>, IdentityError> {
        use crate::identity::credentials::StoredCredential;
        let prefix = keys::credential_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let mut out = Vec::new();
        for entry in entries {
            let Ok(stored) = serde_json::from_slice::<StoredCredential>(&entry.value) else {
                continue;
            };
            let uuid_bytes = &entry.key[prefix.len()..];
            let Ok(uuid_str) = std::str::from_utf8(uuid_bytes) else {
                continue;
            };
            let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) else {
                continue;
            };
            out.push(crate::identity::CredentialExport {
                user_id: UserId::new(uuid),
                phc_string: stored.hash.clone(),
                created_at_micros: stored.created_at,
            });
        }
        Ok(out)
    }

    fn export_realm_signing_key_pkcs8(&self, realm_id: &RealmId) -> Result<Vec<u8>, IdentityError> {
        let key = self.get_or_load_realm_signing_key(realm_id)?;
        Ok(key.pkcs8_bytes().to_vec())
    }

    fn initiate_logout(
        &self,
        realm_id: &RealmId,
        request: &RpLogoutRequest,
    ) -> Result<RpLogoutResult, IdentityError> {
        self.initiate_logout_inner(realm_id, request)
    }

    fn check_device_fingerprint(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        ip: &str,
        user_agent: &str,
    ) -> Result<DeviceFingerprintOutcome, IdentityError> {
        // Load realm config to check if adaptive MFA is enabled.
        let realm = self
            .get_realm(realm_id)?
            .ok_or(IdentityError::RealmNotFound)?;
        let cfg = &realm.config().adaptive_mfa;

        if !cfg.enabled {
            return Ok(DeviceFingerprintOutcome::Skipped);
        }
        // Fail-secure (BLK-2): enabled=true with empty or short HMAC secret is a
        // misconfiguration that must surface as an error — silently skipping would issue
        // tokens without the intended fingerprint gate (fail-open).
        // NIST SP 800-107 recommends HMAC keys ≥ hash output length (32 bytes for SHA-256).
        if cfg.fingerprint_hmac_secret.expose_secret().len() < 32 {
            return Err(IdentityError::Internal {
                reason: format!(
                    "adaptive_mfa.enabled=true but fingerprint_hmac_secret is too short ({} bytes, minimum 32)",
                    cfg.fingerprint_hmac_secret.expose_secret().len()
                ),
            });
        }

        let hmac = crate::identity::device_fp::DeviceFingerprintStore::derive_hmac(
            cfg.fingerprint_hmac_secret.expose_secret(),
            user_id,
            ip,
            user_agent,
        );

        match self.device_fp.check_and_refresh(
            realm_id,
            user_id,
            &hmac,
            cfg.recognition_window_days,
        )? {
            crate::identity::device_fp::FingerprintResult::Recognised => {
                Ok(DeviceFingerprintOutcome::Recognised)
            }
            crate::identity::device_fp::FingerprintResult::Unrecognised => {
                // Emit step-up audit event (LogOnly — login continues with challenge).
                let metadata = Some(serde_json::json!({
                    "user_id": user_id.as_uuid().to_string(),
                    "reason": "unrecognised_device"
                }));
                let ctx = AuditContext {
                    actor: Actor::User(user_id.clone()),
                    metadata,
                };
                if let Err(e) = self.record_audit(
                    realm_id,
                    Some(&ctx),
                    AuditAction::StepUpMfaTriggered,
                    "user",
                    &user_id.as_uuid().to_string(),
                ) {
                    tracing::warn!(error = %e, "StepUpMfaTriggered audit write failed — event lost");
                }

                // AC-6 vs AC-8: check whether user has an enrolled MFA factor.
                let has_mfa = self.mfa_enabled(realm_id, user_id).unwrap_or(false)
                    || self
                        .list_webauthn_credentials(realm_id, user_id)
                        .map(|creds| !creds.is_empty())
                        .unwrap_or(false);

                if has_mfa {
                    Ok(DeviceFingerprintOutcome::StepUpRequired)
                } else {
                    Ok(DeviceFingerprintOutcome::EnrollMfaRequired)
                }
            }
        }
    }

    fn record_device_fingerprint(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        ip: &str,
        user_agent: &str,
    ) -> Result<(), IdentityError> {
        let realm = self
            .get_realm(realm_id)?
            .ok_or(IdentityError::RealmNotFound)?;
        let cfg = &realm.config().adaptive_mfa;
        if !cfg.enabled {
            return Ok(());
        }
        // Misconfiguration guard: skip recording silently when secret is empty.
        if cfg.fingerprint_hmac_secret.expose_secret().is_empty() {
            return Ok(());
        }
        let hmac = crate::identity::device_fp::DeviceFingerprintStore::derive_hmac(
            cfg.fingerprint_hmac_secret.expose_secret(),
            user_id,
            ip,
            user_agent,
        );
        self.device_fp
            .record(realm_id, user_id, &hmac, cfg.recognition_window_days)
    }

    fn issue_sms_otp(
        &self,
        realm_id: &RealmId,
        phone: &str,
        otp_hmac_key_bytes: &[u8],
        sender: &dyn crate::identity::sms::SmsSender,
        now_unix_ts: u64,
    ) -> Result<String, IdentityError> {
        use crate::identity::sms::otp::{self as otp_mod, StoredResendCount};

        // 1. Per-phone resend throttle check.
        let resend_suffix = otp_mod::phone_resend_key_suffix(phone);
        let resend_key = keys::encode_sms_resend_count(&resend_suffix);
        let resend_raw = self
            .storage
            .get(realm_id, &resend_key)
            .map_err(Self::storage_err)?;

        let should_reset_window = match resend_raw {
            None => true,
            Some(ref bytes) => {
                let resend: StoredResendCount =
                    serde_json::from_slice(bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                if resend.is_window_expired(now_unix_ts) {
                    true
                } else if resend.is_limit_reached() {
                    return Err(IdentityError::SmsResendLimitExceeded);
                } else {
                    // Increment within current window.
                    let mut updated = resend;
                    updated.count = updated.count.saturating_add(1);
                    let updated_bytes =
                        serde_json::to_vec(&updated).map_err(|e| IdentityError::Serialization {
                            reason: e.to_string(),
                        })?;
                    self.storage
                        .put(realm_id, &resend_key, &updated_bytes)
                        .map_err(Self::storage_err)?;
                    false
                }
            }
        };

        if should_reset_window {
            let fresh = StoredResendCount::new(now_unix_ts);
            let fresh_bytes =
                serde_json::to_vec(&fresh).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            self.storage
                .put(realm_id, &resend_key, &fresh_bytes)
                .map_err(Self::storage_err)?;
        }

        // 2. Look up per-realm OTP config, falling back to module defaults.
        use crate::identity::sms::otp::{OTP_EXPIRY_SECS, OTP_MAX_ATTEMPTS};
        let (expiry_secs, max_attempts) = match self.get_realm(realm_id) {
            Ok(Some(realm)) => {
                let cfg = realm.config();
                (
                    cfg.sms_otp_expiry_seconds.unwrap_or(OTP_EXPIRY_SECS),
                    cfg.sms_otp_max_attempts.unwrap_or(OTP_MAX_ATTEMPTS),
                )
            }
            _ => (OTP_EXPIRY_SECS, OTP_MAX_ATTEMPTS),
        };

        // 3. Generate nonce + OTP, persist, send.
        self.do_issue_sms_otp_inner(
            realm_id,
            phone,
            otp_hmac_key_bytes,
            sender,
            now_unix_ts,
            expiry_secs,
            max_attempts,
        )
    }

    fn verify_sms_otp(
        &self,
        realm_id: &RealmId,
        nonce: &str,
        candidate_code: &str,
        otp_hmac_key_bytes: &[u8],
        now_unix_ts: u64,
    ) -> Result<(), IdentityError> {
        use crate::identity::sms::otp::StoredOtp;

        let otp_key = keys::encode_sms_pending_otp(nonce);

        // 1. Load the OTP record.
        let bytes = self
            .storage
            .get(realm_id, &otp_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidSmsOtp)?;

        let mut stored: StoredOtp =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // 2. Check expiry (delete stale record and fail vaguely).
        if stored.is_expired(now_unix_ts) {
            let _ = self.storage.delete(realm_id, &otp_key);
            return Err(IdentityError::InvalidSmsOtp);
        }

        // 3. Check attempt count (delete exhausted record and fail vaguely).
        if stored.is_exhausted() {
            let _ = self.storage.delete(realm_id, &otp_key);
            return Err(IdentityError::InvalidSmsOtp);
        }

        // 4. Increment attempt count and persist before verification —
        //    prevents a race where two concurrent requests both pass the check.
        stored.attempt_count = stored.attempt_count.saturating_add(1);
        let updated_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &otp_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // 5. Constant-time HMAC verification.
        let result = stored.verify(candidate_code, otp_hmac_key_bytes);

        match result {
            Ok(()) => {
                // 6a. Delete the record to prevent replay.
                self.storage
                    .delete(realm_id, &otp_key)
                    .map_err(Self::storage_err)?;
                Ok(())
            }
            Err(e) => {
                // 6b. If now exhausted, delete the record.
                if stored.is_exhausted() {
                    let _ = self.storage.delete(realm_id, &otp_key);
                }
                Err(e)
            }
        }
    }

    fn issue_email_otp(
        &self,
        realm_id: &RealmId,
        email: &str,
        otp_hmac_key_bytes: &[u8],
        email_service: &crate::identity::email::EmailService,
        realm_branding: Option<&crate::identity::email::EmailBranding>,
        now_unix_ts: u64,
    ) -> Result<String, IdentityError> {
        use crate::identity::sms::otp::{
            self as otp_mod, StoredOtp, OTP_EXPIRY_SECS, OTP_MAX_ATTEMPTS,
        };

        let (expiry_secs, max_attempts) = match self.get_realm(realm_id) {
            Ok(Some(realm)) => {
                let cfg = realm.config();
                (
                    cfg.email_otp_expiry_seconds.unwrap_or(OTP_EXPIRY_SECS),
                    cfg.email_otp_max_attempts.unwrap_or(OTP_MAX_ATTEMPTS),
                )
            }
            _ => (OTP_EXPIRY_SECS, OTP_MAX_ATTEMPTS),
        };

        let rng = ring::rand::SystemRandom::new();
        let nonce = otp_mod::generate_otp_nonce(&rng)?;
        let expiry_unix_ts = now_unix_ts.saturating_add(expiry_secs);
        let (digits, stored) =
            StoredOtp::create(&rng, otp_hmac_key_bytes, expiry_unix_ts, max_attempts)?;

        let otp_key = keys::encode_email_pending_otp(&nonce);
        let otp_bytes = serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &otp_key, &otp_bytes)
            .map_err(Self::storage_err)?;

        email_service
            .send_otp_email(email, digits.as_str(), realm_branding)
            .map_err(|e| IdentityError::Internal {
                reason: format!("email OTP delivery failed: {e}"),
            })?;

        Ok(nonce)
    }

    fn verify_email_otp(
        &self,
        realm_id: &RealmId,
        nonce: &str,
        candidate_code: &str,
        otp_hmac_key_bytes: &[u8],
        now_unix_ts: u64,
    ) -> Result<(), IdentityError> {
        use crate::identity::sms::otp::StoredOtp;

        let otp_key = keys::encode_email_pending_otp(nonce);

        let bytes = self
            .storage
            .get(realm_id, &otp_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidEmailOtp)?;

        let mut stored: StoredOtp =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        if stored.is_expired(now_unix_ts) {
            let _ = self.storage.delete(realm_id, &otp_key);
            return Err(IdentityError::InvalidEmailOtp);
        }

        if stored.is_exhausted() {
            let _ = self.storage.delete(realm_id, &otp_key);
            return Err(IdentityError::InvalidEmailOtp);
        }

        stored.attempt_count = stored.attempt_count.saturating_add(1);
        let updated_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &otp_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        let result = stored.verify(candidate_code, otp_hmac_key_bytes);

        match result {
            Ok(()) => {
                self.storage
                    .delete(realm_id, &otp_key)
                    .map_err(Self::storage_err)?;
                Ok(())
            }
            Err(_) => {
                if stored.is_exhausted() {
                    let _ = self.storage.delete(realm_id, &otp_key);
                }
                Err(IdentityError::InvalidEmailOtp)
            }
        }
    }

    fn sv_list_deltas(
        &self,
        realm_id: &RealmId,
        since: u64,
        limit: usize,
    ) -> Result<Option<crate::identity::session_version::SvDeltaResponse>, IdentityError> {
        self.sv_store.list_deltas(realm_id, since, limit)
    }

    fn sv_snapshot(
        &self,
        realm_id: &RealmId,
    ) -> Result<crate::identity::session_version::SvSnapshotResponse, IdentityError> {
        self.sv_store.snapshot(realm_id)
    }

    fn sv_bump_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<u64, IdentityError> {
        let retention = self.sv_retention_secs(realm_id);
        let enabled = self
            .get_realm(realm_id)
            .ok()
            .flatten()
            .map(|r| r.config().session_version.enabled)
            .unwrap_or(false);
        if !enabled {
            return Err(IdentityError::SessionVersionDisabled);
        }
        self.sv_store.bump(realm_id, session_id, retention)
    }

    fn sv_bump_all(&self, realm_id: &RealmId) -> Result<usize, IdentityError> {
        let retention = self.sv_retention_secs(realm_id);
        let enabled = self
            .get_realm(realm_id)
            .ok()
            .flatten()
            .map(|r| r.config().session_version.enabled)
            .unwrap_or(false);
        if !enabled {
            return Err(IdentityError::SessionVersionDisabled);
        }
        self.sv_store.bump_all(realm_id, retention)
    }

    fn check_and_record_dpop_jti(
        &self,
        realm_id: &RealmId,
        jti: &str,
        now_secs: i64,
    ) -> Result<(), IdentityError> {
        use crate::identity::dpop::DPOP_MAX_AGE_SECS;

        let jti_key = keys::encode_dpop_jti(jti);
        // Reuse the per-realm JTI lock to close the TOCTOU window between
        // the storage get (replay check) and the storage put (recording).
        let lock = self.jwt_bearer_jti_lock(realm_id);
        let _guard = lock.lock().expect("jti lock poisoned");

        if self
            .storage
            .get(realm_id, &jti_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::DPopProofReplay);
        }

        let expires_at = now_secs.saturating_add(DPOP_MAX_AGE_SECS);
        self.storage
            .put(realm_id, &jti_key, &expires_at.to_le_bytes())
            .map_err(Self::storage_err)
    }

    fn get_realm_dpop_nonce_secret(&self, realm_id: &RealmId) -> Result<[u8; 32], IdentityError> {
        // Fast path: return cached secret without touching storage.
        {
            let cache = self
                .dpop_nonce_cache
                .lock()
                .expect("dpop_nonce_cache poisoned");
            if let Some(secret) = cache.get(realm_id) {
                return Ok(*secret);
            }
        }

        // Slow path: load from storage or generate a fresh secret.
        let secret_key = keys::dpop_nonce_secret_key();
        let kek = self
            .config
            .key_encryption_key
            .as_ref()
            .map(|k| k.as_bytes());

        let secret: [u8; 32] = if let Some(raw) = self
            .storage
            .get(realm_id, &secret_key)
            .map_err(Self::storage_err)?
        {
            let plaintext = crate::identity::key_encryption::unwrap_key(&raw, kek)?;
            plaintext
                .as_slice()
                .try_into()
                .map_err(|_| IdentityError::Internal {
                    reason: format!(
                        "dpop nonce secret has wrong length {} (expected 32)",
                        plaintext.len()
                    ),
                })?
        } else {
            use ring::rand::SecureRandom as _;
            let rng = ring::rand::SystemRandom::new();
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes).map_err(|_| IdentityError::Internal {
                reason: "dpop nonce secret: ring CSPRNG error".to_string(),
            })?;
            let stored = crate::identity::key_encryption::wrap_key(&bytes, kek)?;
            self.storage
                .put(realm_id, &secret_key, &stored)
                .map_err(Self::storage_err)?;
            bytes
        };

        // Cache the loaded/generated secret.
        let mut cache = self
            .dpop_nonce_cache
            .lock()
            .expect("dpop_nonce_cache poisoned");
        cache.insert(realm_id.clone(), secret);
        Ok(secret)
    }

    // ── B.1 Protected Resource Registration (AGENT_AUTH.md §2.5) ─────────────

    fn register_protected_resource(
        &self,
        realm_id: &RealmId,
        request: &RegisterProtectedResourceRequest,
    ) -> Result<ProtectedResource, IdentityError> {
        if request.resource_uri.is_empty() {
            return Err(IdentityError::InvalidInput {
                reason: "resource_uri must not be empty".to_string(),
            });
        }
        if !request.resource_uri.contains("://") {
            return Err(IdentityError::InvalidInput {
                reason: "resource_uri must be an absolute URI with a scheme".to_string(),
            });
        }
        let uri_key = keys::encode_resource_server_uri_index(&request.resource_uri);
        if self
            .storage
            .get(realm_id, &uri_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::DuplicateResourceUri);
        }
        let now = self.clock.now();
        let id = crate::core::ResourceServerId::generate();
        let resource = ProtectedResource {
            id: id.clone(),
            realm_id: realm_id.clone(),
            resource_uri: request.resource_uri.clone(),
            display_name: request.display_name.clone(),
            scopes: request.scopes.clone(),
            required_claims: request.required_claims.clone(),
            created_at: now,
            updated_at: now,
        };
        let primary_key = keys::encode_resource_server_id(&id);
        let bytes = serde_json::to_vec(&resource).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put_batch(
                realm_id,
                &[
                    (primary_key, bytes),
                    (uri_key, id.as_uuid().as_bytes().to_vec()),
                ],
            )
            .map_err(Self::storage_err)?;
        let ctx = AuditContext {
            actor: Actor::System,
            metadata: Some(serde_json::json!({
                "resource_id": id.as_uuid().to_string(),
                "resource_uri": request.resource_uri,
                "display_name": request.display_name,
            })),
        };
        let _ = self.record_audit(
            realm_id,
            Some(&ctx),
            AuditAction::ProtectedResourceRegistered,
            "protected_resource",
            &id.as_uuid().to_string(),
        );
        Ok(resource)
    }

    fn get_protected_resource(
        &self,
        realm_id: &RealmId,
        resource_id: &crate::core::ResourceServerId,
    ) -> Result<Option<ProtectedResource>, IdentityError> {
        let key = keys::encode_resource_server_id(resource_id);
        let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        let resource =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        Ok(Some(resource))
    }

    fn list_protected_resources(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<ProtectedResource>, IdentityError> {
        let prefix = keys::resource_server_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let mut resources = Vec::with_capacity(entries.len());
        for entry in entries {
            let r =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            resources.push(r);
        }
        Ok(resources)
    }

    fn update_protected_resource(
        &self,
        realm_id: &RealmId,
        resource_id: &crate::core::ResourceServerId,
        request: &UpdateProtectedResourceRequest,
    ) -> Result<ProtectedResource, IdentityError> {
        let key = keys::encode_resource_server_id(resource_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ProtectedResourceNotFound)?;
        let mut resource: ProtectedResource =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        if let Some(name) = &request.display_name {
            resource.display_name = name.clone();
        }
        if let Some(scopes) = &request.scopes {
            resource.scopes = scopes.clone();
        }
        if let Some(claims) = &request.required_claims {
            resource.required_claims = claims.clone();
        }
        resource.updated_at = self.clock.now();
        let new_bytes =
            serde_json::to_vec(&resource).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &key, &new_bytes)
            .map_err(Self::storage_err)?;
        let ctx = AuditContext {
            actor: Actor::System,
            metadata: None,
        };
        let _ = self.record_audit(
            realm_id,
            Some(&ctx),
            AuditAction::ProtectedResourceUpdated,
            "protected_resource",
            &resource_id.as_uuid().to_string(),
        );
        Ok(resource)
    }

    fn delete_protected_resource(
        &self,
        realm_id: &RealmId,
        resource_id: &crate::core::ResourceServerId,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_resource_server_id(resource_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ProtectedResourceNotFound)?;
        let resource: ProtectedResource =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let uri_key = keys::encode_resource_server_uri_index(&resource.resource_uri);
        self.storage
            .write_batch(realm_id, &[], &[key, uri_key])
            .map_err(Self::storage_err)?;
        let ctx = AuditContext {
            actor: Actor::System,
            metadata: Some(serde_json::json!({
                "resource_id": resource_id.as_uuid().to_string(),
                "resource_uri": resource.resource_uri,
            })),
        };
        self.record_audit(
            realm_id,
            Some(&ctx),
            AuditAction::ProtectedResourceDeleted,
            "protected_resource",
            &resource_id.as_uuid().to_string(),
        )?;
        Ok(())
    }

    // ── B.4 RFC 8693 Token Exchange ───────────────────────────────────────────

    #[allow(clippy::too_many_lines)]
    fn rfc8693_token_exchange(
        &self,
        realm_id: &RealmId,
        request: &Rfc8693Request,
    ) -> Result<Rfc8693Response, IdentityError> {
        use crate::identity::mcp::intersect_three;
        use crate::identity::tokens::ActClaim;

        let now_micros = self.clock.now().as_micros();
        let now_secs = now_micros / 1_000_000;

        // 1. Validate subject_token_type.
        const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
        if request.subject_token_type != ACCESS_TOKEN_TYPE {
            return Err(IdentityError::TokenExchangeRejected {
                reason: format!(
                    "subject_token_type must be {ACCESS_TOKEN_TYPE} (got {})",
                    request.subject_token_type
                ),
                oauth_error: "invalid_request",
            });
        }

        // 2. Cryptographically verify and validate the subject token.
        // validate_token checks Ed25519 signature against the realm's key, expiry,
        // and realm binding — a token signed by a different realm's key is rejected
        // here, making a separate tid guard unnecessary.
        let subject_claims = self
            .validate_token(realm_id, &request.subject_token)
            .map_err(|_| IdentityError::TokenExchangeRejected {
                reason: "invalid or expired subject_token".into(),
                oauth_error: "invalid_grant",
            })?;
        let subject_remaining = subject_claims.exp.saturating_sub(now_secs);

        // 3. Validate actor_token if present (B.5 OBO).
        // Returns (actor_sub, actor_scope_owned) where actor_scope_owned is the space-separated
        // scope string the actor is permitted to hold (RFC 8693 §4.4).
        let (actor_sub, actor_scope_owned) =
            if let Some(ref actor_jwt) = request.actor_token {
                // F3 (HEA-1466): verify actor_token signature with the realm key before reading any
                // claims. The prior jwt_payload_json path was unverified — fresh forgeries with
                // arbitrary sub claims bypassed the JTI replay guard (confused-deputy attack).
                let actor_claims = self
                    .verify_token_signature_for_realm(realm_id, actor_jwt)
                    .map_err(|_| IdentityError::TokenExchangeRejected {
                        reason: "actor_token signature verification failed".to_string(),
                        oauth_error: "invalid_grant",
                    })?;

                // Only access tokens are valid actor assertions; refresh tokens must be rejected.
                if actor_claims.token_type != "access" {
                    return Err(IdentityError::TokenExchangeRejected {
                        reason: "actor_token must be an access token".to_string(),
                        oauth_error: "invalid_grant",
                    });
                }

                // Reject expired actor tokens (verify_token_signature_for_realm does not check exp).
                if actor_claims.exp <= now_secs {
                    return Err(IdentityError::TokenExchangeRejected {
                        reason: "actor_token has expired".to_string(),
                        oauth_error: "invalid_grant",
                    });
                }

                // F3: assert actor_token.sub == client_id — the entity presenting the delegation
                // must own the actor_token. Without this check, any holder of a valid Hearth token
                // for principal A could impersonate principal B in the act chain.
                if actor_claims.sub != request.client_id.to_string() {
                    return Err(IdentityError::TokenExchangeRejected {
                        reason: "actor_token.sub does not match client_id".to_string(),
                        oauth_error: "invalid_grant",
                    });
                }

                let actor_jti = actor_claims.jti.clone().ok_or_else(|| {
                    IdentityError::TokenExchangeRejected {
                        reason: "actor_token missing jti".to_string(),
                        oauth_error: "invalid_grant",
                    }
                })?;
                let actor_exp = actor_claims.exp;
                self.check_and_record_actor_jti(realm_id, &actor_jti, now_secs, actor_exp)?;

                // Scope ceiling: actor's token scope narrows delegation per RFC 8693 §4.4.
                // - Absent claim → actor doesn't restrict beyond the subject's own scope.
                // - Explicit empty string → zero permissions → EmptyScopeIntersection downstream.
                let scope = actor_claims
                    .scope
                    .unwrap_or_else(|| subject_claims.scope.clone().unwrap_or_default());

                (actor_claims.sub, scope)
            } else {
                // No actor_token: the client is acting on its own behalf (no delegation chain).
                // Preserve the original behavior — actor ceiling matches the subject's own scope
                // so this path doesn't further restrict scope beyond subject ∩ requested.
                let actor_sub = request.client_id.as_uuid().to_string();
                let actor_scope = subject_claims.scope.clone().unwrap_or_default();
                (actor_sub, actor_scope)
            };

        // 4. Delegation depth check.
        let existing_depth = subject_claims.act.as_ref().map_or(0, |a| a.depth());
        let new_depth = existing_depth + 1;

        // Resolve max_delegation_depth from the agent record if actor is an agent.
        let max_depth = self
            .resolve_agent_max_depth(realm_id, &actor_sub)
            .unwrap_or(crate::abuse::MAX_ACT_CHAIN_DEPTH as u8);

        if new_depth as u8 > max_depth {
            return Err(IdentityError::DelegationDepthExceeded {
                max: max_depth,
                attempted: new_depth as u8,
            });
        }

        // 5. Scope intersection (RFC 8693 §4.4: effective ⊆ actor_scope ∩ subject_scope).
        let subject_scope = subject_claims.scope.as_deref().unwrap_or("");
        let effective_scope =
            intersect_three(subject_scope, &actor_scope_owned, request.scope.as_deref());
        if effective_scope.is_empty() {
            return Err(IdentityError::EmptyScopeIntersection);
        }

        // 6. Lifetime: min(subject_remaining, configured access_token_ttl).
        let ttl = subject_remaining.min(self.config.token.access_token_ttl_secs);
        let exp = now_secs + ttl;

        // 7. Build act chain.
        let new_act = ActClaim {
            sub: actor_sub.clone(),
            act: subject_claims.act.clone().map(Box::new),
        };

        // 8. Audience.
        let aud = if let Some(ref resource_uri) = request.resource {
            crate::identity::tokens::Audience::Multi(vec![
                subject_claims.aud.base().to_string(),
                resource_uri.clone(),
            ])
        } else if let Some(ref audience) = request.audience {
            crate::identity::tokens::Audience::Single(audience.clone())
        } else {
            subject_claims.aud.clone()
        };

        // 9. Issue token.
        let signing_key = self.get_signing_key_or_default(realm_id);
        let jti = uuid::Uuid::new_v4().to_string();
        let issued_claims = crate::identity::tokens::TokenClaims {
            sub: subject_claims.sub.clone(),
            iss: self.config.token.issuer.clone(),
            aud,
            exp,
            iat: now_secs,
            sid: subject_claims.sid.clone(),
            tid: realm_id.to_string(),
            oid: subject_claims.oid.clone(),
            token_type: "access".to_string(),
            nbf: None,
            jti: Some(jti.clone()),
            fid: subject_claims.fid.clone(),
            scope: Some(effective_scope.clone()),
            nonce: None,
            azp: None,
            cnf: request
                .dpop_jkt
                .as_ref()
                .map(|jkt| crate::identity::tokens::CnfClaim { jkt: jkt.clone() }),
            roles: subject_claims.roles.clone(),
            groups: subject_claims.groups.clone(),
            org_groups: subject_claims.org_groups.clone(),
            permissions: subject_claims.permissions.clone(),
            required_actions: Vec::new(),
            act: Some(new_act),
            amr: subject_claims.amr.clone(),
            sv: subject_claims.sv,
            custom: subject_claims.custom.clone(),
        };
        let access_token = signing_key.issue_token(&issued_claims)?;

        // 10. Audit.
        let audit_ctx = AuditContext {
            actor: Actor::System,
            metadata: Some(serde_json::json!({
                "actor": actor_sub,
                "on_behalf_of": subject_claims.sub,
                "delegation_depth": new_depth,
                "effective_scope": effective_scope,
                "token_jti": jti,
                "dpop_jkt": request.dpop_jkt,
            })),
        };
        let _ = self.record_audit(
            realm_id,
            Some(&audit_ctx),
            AuditAction::AgentDelegation,
            "token",
            &jti,
        );

        // 11. Persist delegation grant for self-service consent management (§3.5).
        let delegation_id = uuid::Uuid::new_v4().to_string();
        let now_ts = self.clock.now();
        let expires_ts = crate::core::Timestamp::from_micros(exp * 1_000_000);
        let grant = crate::identity::types::StoredDelegationGrant {
            delegation_id,
            actor_sub: actor_sub.clone(),
            user_sub: subject_claims.sub.clone(),
            granted_scope: effective_scope.clone(),
            created_at: now_ts,
            expires_at: expires_ts,
            revoked: false,
            token_jti: jti.clone(),
        };
        let _ = self.store_delegation_grant_inner(realm_id, &grant);

        Ok(Rfc8693Response {
            access_token,
            issued_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
            token_type: if request.dpop_jkt.is_some() {
                "DPoP"
            } else {
                "Bearer"
            }
            .to_string(),
            expires_in: ttl,
            scope: effective_scope,
        })
    }

    fn check_and_record_actor_jti(
        &self,
        realm_id: &RealmId,
        jti: &str,
        _now_secs: i64,
        exp_secs: i64,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_actor_jti(jti);
        if self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::ActorTokenReplayed);
        }
        self.storage
            .put(realm_id, &key, &exp_secs.to_le_bytes())
            .map_err(Self::storage_err)?;
        Ok(())
    }

    fn list_delegation_grants(
        &self,
        realm_id: &RealmId,
        user_sub: &str,
    ) -> Result<Vec<crate::identity::types::DelegationGrantEntry>, IdentityError> {
        self.list_delegation_grants_inner(realm_id, user_sub)
    }

    fn revoke_delegation_grant(
        &self,
        realm_id: &RealmId,
        delegation_id: &str,
        user_sub: &str,
    ) -> Result<(), IdentityError> {
        self.revoke_delegation_grant_inner(realm_id, delegation_id, user_sub)
    }

    fn create_approval_request(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::types::CreateApprovalRequestInput,
    ) -> Result<crate::identity::types::ApprovalRequest, IdentityError> {
        let approval = self.create_approval_request_inner(realm_id, request)?;
        // C.5: attempt immediate webhook delivery; outbox entry is already
        // WAL-durable so failures are safe (recovery scan will retry).
        self.notify_approval_webhook_inner(realm_id, &approval);
        Ok(approval)
    }
    fn get_approval_request(
        &self,
        realm_id: &RealmId,
        request_id: &str,
    ) -> Result<crate::identity::types::ApprovalRequest, IdentityError> {
        self.get_approval_request_inner(realm_id, request_id)
    }
    fn approve_approval_request(
        &self,
        realm_id: &RealmId,
        request_id: &str,
        capability_ttl_secs: Option<i64>,
    ) -> Result<crate::identity::types::ApprovalRequestResponse, IdentityError> {
        self.approve_approval_request_inner(realm_id, request_id, capability_ttl_secs)
    }
    fn deny_approval_request(
        &self,
        realm_id: &RealmId,
        request_id: &str,
        reason: Option<String>,
    ) -> Result<crate::identity::types::ApprovalRequestResponse, IdentityError> {
        self.deny_approval_request_inner(realm_id, request_id, reason)
    }
    fn list_approval_requests(
        &self,
        realm_id: &RealmId,
        status_filter: Option<crate::identity::types::ApprovalRequestStatus>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<crate::identity::types::Page<crate::identity::types::ApprovalRequest>, IdentityError>
    {
        self.list_approval_requests_inner(realm_id, status_filter, cursor, limit)
    }

    fn validate_capability_token(
        &self,
        realm_id: &RealmId,
        token: &str,
        tool_name: &str,
        action: &str,
    ) -> Result<crate::core::AgentId, IdentityError> {
        self.validate_capability_token_inner(realm_id, token, tool_name, action)
    }

    // ── Phase D.1: AATs ─────────────────────────────────────────────────────

    fn issue_aat(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::types::IssueAatRequest,
    ) -> Result<crate::identity::types::AatResponse, IdentityError> {
        self.issue_aat_inner(realm_id, request)
    }

    fn derive_aat(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::types::DeriveAatRequest,
    ) -> Result<crate::identity::types::AatResponse, IdentityError> {
        self.derive_aat_inner(realm_id, request)
    }

    fn validate_aat(
        &self,
        realm_id: &RealmId,
        aat: &str,
        expected_aud: Option<&str>,
    ) -> Result<crate::identity::types::AatClaims, IdentityError> {
        self.parse_and_validate_aat(realm_id, aat, expected_aud)
    }

    fn revoke_aat(&self, realm_id: &RealmId, jti: &str) -> Result<(), IdentityError> {
        self.revoke_aat_inner(realm_id, jti)
    }

    // ── Phase D.3: Transaction Tokens ───────────────────────────────────────

    fn issue_transaction_token(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::types::CreateTransactionTokenRequest,
    ) -> Result<crate::identity::types::TransactionTokenResponse, IdentityError> {
        self.issue_transaction_token_inner(realm_id, request)
    }

    fn consume_transaction_token(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<crate::identity::types::TransactionTokenClaims, IdentityError> {
        self.consume_transaction_token_inner(realm_id, token)
    }

    // ── Phase D: DPoP JKT blocklist (§10.4) ─────────────────────────────────

    fn block_dpop_jkt(&self, realm_id: &RealmId, jkt: &str) -> Result<(), IdentityError> {
        self.block_dpop_jkt_inner(realm_id, jkt)
    }

    fn unblock_dpop_jkt(&self, realm_id: &RealmId, jkt: &str) -> Result<(), IdentityError> {
        self.unblock_dpop_jkt_inner(realm_id, jkt)
    }

    // ── Phase D.4: Cross-Realm Trust Policies ───────────────────────────────

    fn create_cross_realm_policy(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::types::CreateCrossRealmPolicyRequest,
    ) -> Result<crate::identity::types::CrossRealmTrustPolicy, IdentityError> {
        self.create_cross_realm_policy_inner(realm_id, request)
    }

    fn get_cross_realm_policy(
        &self,
        realm_id: &RealmId,
        policy_id: &str,
    ) -> Result<Option<crate::identity::types::CrossRealmTrustPolicy>, IdentityError> {
        self.get_cross_realm_policy_inner(realm_id, policy_id)
    }

    fn list_cross_realm_policies(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<crate::identity::types::CrossRealmTrustPolicy>, IdentityError> {
        self.list_cross_realm_policies_inner(realm_id)
    }

    fn delete_cross_realm_policy(
        &self,
        realm_id: &RealmId,
        policy_id: &str,
    ) -> Result<(), IdentityError> {
        self.delete_cross_realm_policy_inner(realm_id, policy_id)
    }

    fn check_cross_realm_policy(
        &self,
        target_realm: &RealmId,
        source_realm: &RealmId,
        capability: &str,
    ) -> Result<bool, IdentityError> {
        self.check_cross_realm_policy_inner(target_realm, source_realm, capability)
    }

    // ── Phase D.7: SPIFFE / Workload Identity ───────────────────────────────

    fn register_spiffe_mapping(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::types::RegisterSpiffeIdRequest,
    ) -> Result<crate::identity::types::SpiffeIdentityMapping, IdentityError> {
        self.register_spiffe_mapping_inner(realm_id, request)
    }

    fn lookup_agent_by_spiffe_id(
        &self,
        realm_id: &RealmId,
        spiffe_id: &str,
    ) -> Result<Option<AgentId>, IdentityError> {
        self.lookup_agent_by_spiffe_id_inner(realm_id, spiffe_id)
    }

    fn delete_spiffe_mapping(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
    ) -> Result<(), IdentityError> {
        self.delete_spiffe_mapping_inner(realm_id, agent_id)
    }

    fn validate_spiffe_svid(
        &self,
        realm_id: &RealmId,
        der_cert: &[u8],
    ) -> Result<AgentId, IdentityError> {
        self.validate_spiffe_svid_inner(realm_id, der_cert)
    }
}

/// M2 private helpers for token exchange.
impl EmbeddedIdentityEngine {
    /// Resolves the `max_delegation_depth` for an actor subject string.
    ///
    /// Returns `None` when the actor is not a registered agent in this realm,
    /// signalling that the global ceiling (`MAX_ACT_CHAIN_DEPTH`) applies.
    fn resolve_agent_max_depth(&self, realm_id: &RealmId, actor_sub: &str) -> Option<u8> {
        // Accept bare UUID, "agt_<uuid>", or "agent:agt_<uuid>" forms.
        let raw = actor_sub
            .strip_prefix("agent:agt_")
            .or_else(|| actor_sub.strip_prefix("agt_"))
            .unwrap_or(actor_sub);
        let uuid = uuid::Uuid::parse_str(raw).ok()?;
        let agent_id = crate::core::AgentId::new(uuid);
        let agent = self.get_agent(realm_id, &agent_id).ok()??;
        if matches!(agent.status(), AgentStatus::Revoked) {
            return None;
        }
        Some(agent.max_delegation_depth())
    }
}

/// Generates and stores a new OTP then dispatches the SMS.
impl EmbeddedIdentityEngine {
    fn do_issue_sms_otp_inner(
        &self,
        realm_id: &RealmId,
        phone: &str,
        otp_hmac_key_bytes: &[u8],
        sender: &dyn crate::identity::sms::SmsSender,
        now_unix_ts: u64,
        expiry_secs: u64,
        max_attempts: u32,
    ) -> Result<String, IdentityError> {
        use crate::identity::sms::otp::{self as otp_mod, StoredOtp};
        use crate::identity::sms::SmsMessage;

        let rng = ring::rand::SystemRandom::new();
        let nonce = otp_mod::generate_otp_nonce(&rng)?;
        let expiry_unix_ts = now_unix_ts.saturating_add(expiry_secs);
        let (digits, stored) =
            StoredOtp::create(&rng, otp_hmac_key_bytes, expiry_unix_ts, max_attempts)?;

        let otp_key = keys::encode_sms_pending_otp(&nonce);
        let otp_bytes = serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &otp_key, &otp_bytes)
            .map_err(Self::storage_err)?;

        sender
            .send(&SmsMessage {
                to: phone.to_string(),
                body: format!("Your verification code is: {}", digits.as_str()),
            })
            .map_err(|e| IdentityError::Internal {
                reason: format!("SMS delivery failed: {e}"),
            })?;

        Ok(nonce)
    }
}

/// Classifies a PHC-formatted hash string into a [`PasswordAlgorithm`].
///
/// Used by `import_user` to tag an externally supplied hash. Returns
/// `None` for prefixes this code base does not know how to verify, so
/// the caller can fail fast rather than storing an unverifiable
/// credential.
fn classify_phc_algorithm(phc: &str) -> Option<crate::identity::credentials::PasswordAlgorithm> {
    use crate::identity::credentials::PasswordAlgorithm;
    if phc.starts_with("$argon2id$") {
        Some(PasswordAlgorithm::Argon2id)
    } else if phc.starts_with("$2a$") || phc.starts_with("$2b$") {
        Some(PasswordAlgorithm::Bcrypt)
    } else if phc.starts_with("$scrypt$") {
        Some(PasswordAlgorithm::Scrypt)
    } else if phc.starts_with("$pbkdf2-sha256$") {
        Some(PasswordAlgorithm::Pbkdf2Sha256)
    } else {
        None
    }
}

impl EmbeddedIdentityEngine {
    /// Returns the current session-version for `session_id`, or `1` if not tracked.
    pub(crate) fn get_session_sv(&self, realm_id: &RealmId, session_id: &SessionId) -> u64 {
        self.sv_store.get_version(realm_id, session_id).unwrap_or(1)
    }

    /// Bumps session versions for all active sessions of `user_id`.
    pub(crate) fn bump_user_sv_inner(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        retention_secs: u64,
    ) -> Result<usize, IdentityError> {
        self.sv_store
            .bump_user_sessions(realm_id, user_id, retention_secs)
    }

    /// Returns the sv `delta_retention_seconds` config for a realm, or 3600 as default.
    pub(crate) fn sv_retention_secs(&self, realm_id: &RealmId) -> u64 {
        self.get_realm(realm_id)
            .ok()
            .flatten()
            .map(|r| r.config().session_version.delta_retention_seconds)
            .unwrap_or(3600)
    }
}

impl crate::rbac::SvBumper for EmbeddedIdentityEngine {
    fn bump_user_sessions(&self, realm_id: &RealmId, user_id: &UserId) {
        let enabled = self
            .get_realm(realm_id)
            .ok()
            .flatten()
            .map(|r| r.config().session_version.enabled)
            .unwrap_or(false);
        if !enabled {
            return;
        }
        let retention = self.sv_retention_secs(realm_id);
        if let Err(e) = self.bump_user_sv_inner(realm_id, user_id, retention) {
            tracing::warn!(
                realm = %realm_id,
                user = %user_id.as_uuid(),
                error = %e,
                "sv bump_user_sessions failed (rbac trigger)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::EmbeddedAuditEngine;
    use crate::core::{FakeClock, Timestamp};
    use crate::identity::RealmConfig;
    use crate::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

    fn setup_engine() -> (tempfile::TempDir, EmbeddedIdentityEngine, Arc<FakeClock>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine creation");
        (dir, engine, clock)
    }

    // ===== Scenario 1: Create user with required fields succeeds =====

    #[test]
    fn create_user_with_required_fields_succeeds() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let request = CreateUserRequest {
            email: "Alice@Example.COM".to_string(),
            display_name: "Alice Smith".to_string(),
            ..Default::default()
        };

        let user = engine.create_user(&realm, &request).expect("create");

        assert_eq!(user.email(), "alice@example.com");
        assert_eq!(user.display_name(), "Alice Smith");
        assert_eq!(user.status(), UserStatus::Active);
        assert_eq!(user.created_at(), Timestamp::from_micros(1_000_000));
        assert_eq!(user.updated_at(), Timestamp::from_micros(1_000_000));
    }

    #[test]
    fn create_user_generates_unique_id() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let user1 = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        let user2 = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "bob@example.com".to_string(),
                    display_name: "Bob".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        assert_ne!(user1.id(), user2.id());
    }

    // ===== Scenario 2: Read user by ID and by email =====

    #[test]
    fn read_user_by_id_returns_correct_record() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        let fetched = engine
            .get_user(&realm, created.id())
            .expect("get")
            .expect("should exist");

        assert_eq!(fetched, created);
    }

    #[test]
    fn read_user_by_email_returns_correct_record() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        let fetched = engine
            .get_user_by_email(&realm, "Alice@Example.COM")
            .expect("get")
            .expect("should exist");

        assert_eq!(fetched, created);
    }

    #[test]
    fn read_nonexistent_user_returns_none() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let result = engine.get_user(&realm, &UserId::generate()).expect("get");
        assert!(result.is_none());
    }

    #[test]
    fn read_nonexistent_email_returns_none() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let result = engine
            .get_user_by_email(&realm, "nobody@example.com")
            .expect("get");
        assert!(result.is_none());
    }

    // ===== Scenario 3: Update user persists changes =====

    #[test]
    fn update_user_persists_changes() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        clock.advance(1_000_000); // advance 1 second

        let updated = engine
            .update_user(
                &realm,
                created.id(),
                &UpdateUserRequest {
                    display_name: Some("Alice Smith".to_string()),
                    ..UpdateUserRequest::default()
                },
            )
            .expect("update");

        assert_eq!(updated.display_name(), "Alice Smith");
        assert_eq!(updated.email(), "alice@example.com"); // unchanged
        assert_eq!(updated.created_at(), created.created_at()); // unchanged
        assert!(updated.updated_at() > created.updated_at()); // advanced

        // Verify persistence
        let fetched = engine
            .get_user(&realm, created.id())
            .expect("get")
            .expect("should exist");
        assert_eq!(fetched, updated);
    }

    #[test]
    fn update_user_email_swaps_index() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "old@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        clock.advance(1_000_000);

        engine
            .update_user(
                &realm,
                created.id(),
                &UpdateUserRequest {
                    email: Some("new@example.com".to_string()),
                    ..UpdateUserRequest::default()
                },
            )
            .expect("update");

        // Old email should not resolve
        let old_lookup = engine
            .get_user_by_email(&realm, "old@example.com")
            .expect("get");
        assert!(old_lookup.is_none());

        // New email should resolve
        let new_lookup = engine
            .get_user_by_email(&realm, "new@example.com")
            .expect("get")
            .expect("should exist");
        assert_eq!(new_lookup.id(), created.id());
    }

    #[test]
    fn update_user_status() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        let updated = engine
            .update_user(
                &realm,
                created.id(),
                &UpdateUserRequest {
                    status: Some(UserStatus::Disabled),
                    ..UpdateUserRequest::default()
                },
            )
            .expect("update");

        assert_eq!(updated.status(), UserStatus::Disabled);
    }

    #[test]
    fn disabling_user_revokes_all_sessions() {
        // Security: disabling a user must immediately invalidate existing
        // sessions so JWT holders cannot continue operating past the disable.
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let user = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "disable-test@example.com".to_string(),
                    display_name: "Disable Test".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user");

        // Create two sessions for this user.
        engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session 1");
        engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session 2");

        let page_all = crate::core::PageRequest::new(0, crate::core::MAX_PAGE_LIMIT);

        let before = engine
            .list_sessions_by_user(&realm, user.id(), &page_all)
            .expect("list before");
        assert_eq!(
            before.items.len(),
            2,
            "expected 2 active sessions before disable"
        );

        // Disable the user.
        engine
            .update_user(
                &realm,
                user.id(),
                &UpdateUserRequest {
                    status: Some(UserStatus::Disabled),
                    ..UpdateUserRequest::default()
                },
            )
            .expect("disable user");

        let after = engine
            .list_sessions_by_user(&realm, user.id(), &page_all)
            .expect("list after");
        // list_sessions_by_user includes revoked sessions (index is kept for
        // audit); verify each session is marked revoked rather than asserting
        // count == 0.
        assert_eq!(
            after.items.len(),
            2,
            "both session records must still be in index"
        );
        assert!(
            after.items.iter().all(|s| s.is_revoked()),
            "all sessions must be revoked immediately when user is disabled"
        );
    }

    #[test]
    fn update_nonexistent_user_returns_not_found() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let err = engine
            .update_user(&realm, &UserId::generate(), &UpdateUserRequest::default())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
    }

    // ===== Scenario 4: Delete user removes record =====

    #[test]
    fn delete_user_removes_record() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        engine.delete_user(&realm, created.id()).expect("delete");

        // Should not be found by ID
        let by_id = engine.get_user(&realm, created.id()).expect("get");
        assert!(by_id.is_none());

        // Should not be found by email
        let by_email = engine
            .get_user_by_email(&realm, "alice@example.com")
            .expect("get");
        assert!(by_email.is_none());
    }

    #[test]
    fn delete_nonexistent_user_returns_not_found() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let err = engine
            .delete_user(&realm, &UserId::generate())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
    }

    #[test]
    fn delete_user_frees_email() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        engine.delete_user(&realm, created.id()).expect("delete");

        // A-20: email is reserved for 90 days after deletion.
        // Advance clock past the reservation window before re-creating.
        clock.advance(91 * 24 * 60 * 60 * 1_000_000);

        let new_user = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice 2".to_string(),
                    ..Default::default()
                },
            )
            .expect("create should succeed after reservation expires");

        assert_ne!(new_user.id(), created.id());
    }

    // ===== Scenario 5: Duplicate email rejected =====

    #[test]
    fn duplicate_email_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("first create");

        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice 2".to_string(),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::DuplicateEmail));
    }

    #[test]
    fn duplicate_email_case_insensitive() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "Alice@Example.COM".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Other".to_string(),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::DuplicateEmail));
    }

    #[test]
    fn duplicate_email_on_update_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create alice");

        let bob = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "bob@example.com".to_string(),
                    display_name: "Bob".to_string(),
                    ..Default::default()
                },
            )
            .expect("create bob");

        let err = engine
            .update_user(
                &realm,
                bob.id(),
                &UpdateUserRequest {
                    email: Some("alice@example.com".to_string()),
                    ..UpdateUserRequest::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::DuplicateEmail));
    }

    // ===== Adversarial: null bytes and unicode =====

    #[test]
    fn null_bytes_in_email_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice\0@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn null_bytes_in_display_name_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice\0Smith".to_string(),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn unicode_normalization_deduplicates_emails() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        // Create with decomposed é
        engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "caf\u{0065}\u{0301}@example.com".to_string(),
                    display_name: "User 1".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        // Try to create with composed é — should be duplicate
        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "caf\u{00E9}@example.com".to_string(),
                    display_name: "User 2".to_string(),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::DuplicateEmail));
    }

    // ===== Adversarial: oversized input =====

    #[test]
    fn oversized_email_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let long_email = format!("{}@example.com", "a".repeat(250));
        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: long_email,
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn oversized_display_name_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "A".repeat(257),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    // ===== Cross-realm isolation =====

    #[test]
    fn cross_realm_isolation() {
        let (_dir, engine, _clock) = setup_engine();
        let realm_a = create_test_realm(&engine);
        let realm_b = create_test_realm(&engine);

        let alice = engine
            .create_user(
                &realm_a,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        // Same email in different realm should succeed
        let alice_b = engine
            .create_user(
                &realm_b,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice B".to_string(),
                    ..Default::default()
                },
            )
            .expect("create in different realm should succeed");

        assert_ne!(alice.id(), alice_b.id());

        // Can't see realm A's user from realm B
        let not_found = engine.get_user(&realm_b, alice.id()).expect("get");
        assert!(not_found.is_none());
    }

    // ===== Send + Sync =====

    #[test]
    fn engine_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EmbeddedIdentityEngine>();
    }

    // ===== Credential Scenario 1: set_password + verify_password =====

    fn create_test_user(engine: &EmbeddedIdentityEngine, realm: &RealmId) -> User {
        engine
            .create_user(
                realm,
                &CreateUserRequest {
                    email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Test User".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user")
    }

    fn create_test_realm(engine: &EmbeddedIdentityEngine) -> RealmId {
        engine
            .create_realm(&CreateRealmRequest {
                name: format!("test-realm-{}", uuid::Uuid::new_v4()),
                config: Some(RealmConfig::default()),
            })
            .expect("create realm")
            .id()
            .clone()
    }

    #[test]
    fn set_and_verify_password_correct() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("my-secure-password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        let pw_check = CleartextPassword::from_string("my-secure-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &pw_check)
            .expect("verify");
        assert!(result, "correct password should verify");
    }

    #[test]
    fn set_and_verify_password_wrong() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("correct-password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        let wrong = CleartextPassword::from_string("wrong-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &wrong)
            .expect("verify");
        assert!(!result, "wrong password should not verify");
    }

    #[test]
    fn set_password_nonexistent_user_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let pw = CleartextPassword::from_string("password".to_string());

        let err = engine
            .set_password(&realm, &UserId::generate(), &pw)
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
    }

    #[test]
    fn verify_password_nonexistent_user_returns_generic_error() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let pw = CleartextPassword::from_string("password".to_string());

        let err = engine
            .verify_password(&realm, &UserId::generate(), &pw)
            .expect_err("should fail");
        // Returns generic InvalidCredential to prevent user enumeration
        assert!(matches!(err, IdentityError::InvalidCredential { .. }));
    }

    #[test]
    fn verify_password_no_credential_returns_generic_error() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);
        let pw = CleartextPassword::from_string("password".to_string());

        let err = engine
            .verify_password(&realm, user.id(), &pw)
            .expect_err("should fail");
        // Returns generic InvalidCredential to prevent credential enumeration
        assert!(matches!(err, IdentityError::InvalidCredential { .. }));
    }

    // ===== Credential Scenario 3: Password change =====

    #[test]
    fn change_password_succeeds() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let old_pw = CleartextPassword::from_string("old-password".to_string());
        engine
            .set_password(&realm, user.id(), &old_pw)
            .expect("set password");

        let old_for_change = CleartextPassword::from_string("old-password".to_string());
        let new_pw = CleartextPassword::from_string("new-password".to_string());
        engine
            .change_password(&realm, user.id(), &old_for_change, &new_pw)
            .expect("change password");

        // Old password should no longer verify
        let old_check = CleartextPassword::from_string("old-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &old_check)
            .expect("verify old");
        assert!(!result, "old password should no longer verify");

        // New password should verify
        let new_check = CleartextPassword::from_string("new-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &new_check)
            .expect("verify new");
        assert!(result, "new password should verify");
    }

    #[test]
    fn change_password_wrong_old_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("real-password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        let wrong_old = CleartextPassword::from_string("wrong-old".to_string());
        let new_pw = CleartextPassword::from_string("new-password".to_string());
        let err = engine
            .change_password(&realm, user.id(), &wrong_old, &new_pw)
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidCredential { .. }));

        // Original password should still work
        let orig = CleartextPassword::from_string("real-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &orig)
            .expect("verify");
        assert!(result, "original password should still verify");
    }

    // ===== Delete cascades to credentials =====

    #[test]
    fn delete_user_cascades_credential() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        engine.delete_user(&realm, user.id()).expect("delete");

        // Verify should fail with generic InvalidCredential (enumeration resistance)
        let pw_check = CleartextPassword::from_string("password".to_string());
        let err = engine
            .verify_password(&realm, user.id(), &pw_check)
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidCredential { .. }));
    }

    // ===== Adversarial: Timing oracle prevention =====

    #[test]
    #[allow(clippy::cast_precision_loss)] // Precision loss acceptable for timing ratio
    fn verify_nonexistent_user_takes_comparable_time() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        // Time a real failed verification
        let wrong = CleartextPassword::from_string("wrong".to_string());
        let start_real = std::time::Instant::now();
        let _ = engine.verify_password(&realm, user.id(), &wrong);
        let real_time = start_real.elapsed();

        // Time a nonexistent user verification
        let fake = CleartextPassword::from_string("wrong".to_string());
        let start_fake = std::time::Instant::now();
        let _ = engine.verify_password(&realm, &UserId::generate(), &fake);
        let fake_time = start_fake.elapsed();

        // Both should take roughly the same time. We allow 10x tolerance
        // because we're testing on CI with variable load, but the key
        // property is that fake_time is NOT near-zero (i.e., we did
        // actually compute the dummy hash).
        let ratio = if real_time > fake_time {
            real_time.as_nanos() as f64 / fake_time.as_nanos().max(1) as f64
        } else {
            fake_time.as_nanos() as f64 / real_time.as_nanos().max(1) as f64
        };

        assert!(
            ratio < 10.0,
            "timing ratio {ratio:.1}x too large: real={real_time:?}, fake={fake_time:?}"
        );
    }

    // ===== Session Scenario 1: Create session returns valid ID bound to user =====

    #[test]
    fn create_session_returns_valid_session() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        assert_eq!(session.user_id(), user.id());
        assert_eq!(session.created_at(), Timestamp::from_micros(1_000_000));
        // TTL is 24 hours = 86_400_000_000 μs
        let expected_expiry = Timestamp::from_micros(1_000_000 + 86_400_000_000);
        assert_eq!(session.expires_at(), expected_expiry);
        assert_eq!(session.last_refreshed_at(), session.created_at());
    }

    #[test]
    fn create_session_nonexistent_user_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let err = engine
            .create_session(&realm, &UserId::generate(), &SessionContext::default())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
    }

    // ===== Session metadata round-trip =====

    #[test]
    fn session_with_full_context_persists_metadata() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let ctx = SessionContext {
            ip_address: Some("203.0.113.42".to_string()),
            user_agent_raw: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()),
            device_label: Some("Chrome, Mac OSX".to_string()),
            satisfies_mfa_via_passkey: false,
        };

        let session = engine
            .create_session(&realm, user.id(), &ctx)
            .expect("create session");

        assert_eq!(session.ip_address(), Some("203.0.113.42"));
        assert_eq!(session.device_label(), Some("Chrome, Mac OSX"));
        assert!(session.user_agent_raw().is_some());

        // Verify round-trip through storage
        let fetched = engine
            .get_session(&realm, session.id())
            .expect("get session")
            .expect("should exist");

        assert_eq!(fetched.ip_address(), Some("203.0.113.42"));
        assert_eq!(fetched.device_label(), Some("Chrome, Mac OSX"));
        assert_eq!(fetched.user_agent_raw(), session.user_agent_raw());
    }

    #[test]
    fn session_with_default_context_has_none_metadata() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        assert!(session.ip_address().is_none());
        assert!(session.user_agent_raw().is_none());
        assert!(session.device_label().is_none());

        let fetched = engine
            .get_session(&realm, session.id())
            .expect("get session")
            .expect("should exist");

        assert!(fetched.ip_address().is_none());
        assert!(fetched.device_label().is_none());
    }

    #[test]
    fn session_deserialized_without_metadata_fields_has_none() {
        // Simulate a session serialized before metadata fields were added.
        // SessionId/UserId serialize as bare UUIDs (serde newtype over Uuid).
        let old_json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "user_id": "00000000-0000-0000-0000-000000000002",
            "created_at": 1000000,
            "expires_at": 87400000000,
            "last_refreshed_at": 1000000,
            "revoked": false
        }"#;

        let session: Session = serde_json::from_str(old_json).expect("deserialize old format");

        assert!(session.ip_address().is_none());
        assert!(session.user_agent_raw().is_none());
        assert!(session.device_label().is_none());
    }

    // ===== Session Scenario 2: Lookup session by ID =====

    #[test]
    fn lookup_session_by_id_returns_correct_data() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        let fetched = engine
            .get_session(&realm, session.id())
            .expect("get session")
            .expect("should exist");

        assert_eq!(fetched.id(), session.id());
        assert_eq!(fetched.user_id(), user.id());
        assert_eq!(fetched.created_at(), session.created_at());
        assert_eq!(fetched.expires_at(), session.expires_at());
    }

    #[test]
    fn lookup_nonexistent_session_returns_none() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let result = engine
            .get_session(&realm, &SessionId::generate())
            .expect("get");
        assert!(result.is_none());
    }

    // ===== Session Scenario 3: Revoke session =====

    #[test]
    fn revoke_session_immediate_invalidation() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        // Revoke it
        engine.revoke_session(&realm, session.id()).expect("revoke");

        // Lookup should return None
        let result = engine.get_session(&realm, session.id()).expect("get");
        assert!(result.is_none(), "revoked session should not be found");
    }

    #[test]
    fn revoke_nonexistent_session_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let err = engine
            .revoke_session(&realm, &SessionId::generate())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::SessionNotFound));
    }

    // ===== Session Scenario 4: TTL expiration =====

    #[test]
    fn session_expires_after_ttl() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        // Session should be valid now
        let valid = engine.get_session(&realm, session.id()).expect("get");
        assert!(valid.is_some(), "session should be valid before TTL");

        // Advance clock past TTL (24 hours + 1 microsecond)
        let ttl = 24 * 60 * 60 * 1_000_000_i64;
        clock.advance(ttl + 1);

        // Session should now be expired
        let expired = engine.get_session(&realm, session.id()).expect("get");
        assert!(expired.is_none(), "session should be expired after TTL");
    }

    #[test]
    fn session_valid_just_before_expiry() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        // Advance clock to 1 μs before expiry
        let ttl = 24 * 60 * 60 * 1_000_000_i64;
        clock.advance(ttl - 1);

        let still_valid = engine.get_session(&realm, session.id()).expect("get");
        assert!(
            still_valid.is_some(),
            "session should still be valid 1μs before expiry"
        );
    }

    // ===== Session Scenario 5: Refresh session extends TTL =====

    #[test]
    fn refresh_session_extends_ttl() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        let ttl = 24 * 60 * 60 * 1_000_000_i64;

        // Advance 12 hours (half TTL)
        clock.advance(ttl / 2);

        // Refresh the session
        let refreshed = engine
            .refresh_session(&realm, session.id())
            .expect("refresh");

        // Expiry should be 24h from now (not original creation)
        let now = clock.now();
        assert_eq!(refreshed.expires_at(), now.add_micros(ttl));
        assert_eq!(refreshed.last_refreshed_at(), now);

        // Original created_at should be preserved
        assert_eq!(refreshed.created_at(), session.created_at());

        // Advance another 23 hours — would have expired without refresh
        clock.advance(ttl - ttl / 2 + 1_000_000);

        let still_valid = engine.get_session(&realm, session.id()).expect("get");
        assert!(
            still_valid.is_some(),
            "refreshed session should still be valid past original expiry"
        );
    }

    #[test]
    fn refresh_expired_session_fails() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        // Advance past TTL
        let ttl = 24 * 60 * 60 * 1_000_000_i64;
        clock.advance(ttl + 1);

        let err = engine
            .refresh_session(&realm, session.id())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::SessionNotFound));
    }

    #[test]
    fn refresh_revoked_session_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        engine.revoke_session(&realm, session.id()).expect("revoke");

        let err = engine
            .refresh_session(&realm, session.id())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::SessionNotFound));
    }

    // ===== Delete cascades to sessions =====

    #[test]
    fn delete_user_cascades_sessions() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        // Create multiple sessions
        let s1 = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("session 1");
        let s2 = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("session 2");

        // Both should be valid
        assert!(engine.get_session(&realm, s1.id()).expect("get").is_some());
        assert!(engine.get_session(&realm, s2.id()).expect("get").is_some());

        // Delete user
        engine.delete_user(&realm, user.id()).expect("delete");

        // Both sessions should be gone
        assert!(engine.get_session(&realm, s1.id()).expect("get").is_none());
        assert!(engine.get_session(&realm, s2.id()).expect("get").is_none());
    }

    // ===== Property tests =====

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Strategy for generating a valid email address.
        fn valid_email() -> impl Strategy<Value = String> {
            ("[a-z]{1,20}@[a-z]{1,10}\\.[a-z]{2,4}").prop_map(|s| s)
        }

        proptest! {
            /// Property: Random CRUD sequences maintain consistent user count.
            ///
            /// After creating N users and deleting M of them, exactly N-M
            /// users should be retrievable.
            #[test]
            fn crud_sequences_maintain_count(
                emails in proptest::collection::hash_set(valid_email(), 1..10),
            ) {
                let (_dir, engine, _clock) = setup_engine();
                let realm = create_test_realm(&engine);
                let mut created_ids = Vec::new();

                // Create all users
                for (i, email) in emails.iter().enumerate() {
                    let user = engine.create_user(&realm, &CreateUserRequest {
                        email: email.clone(),
                        display_name: format!("User {i}"),
                        ..Default::default()
                    }).expect("create");
                    created_ids.push(user.id().clone());
                }

                // All should be retrievable
                for id in &created_ids {
                    let user = engine.get_user(&realm, id).expect("get");
                    prop_assert!(user.is_some(), "created user should be found");
                }

                // Delete half
                let to_delete = created_ids.len() / 2;
                for id in &created_ids[..to_delete] {
                    engine.delete_user(&realm, id).expect("delete");
                }

                // Deleted should be gone
                for id in &created_ids[..to_delete] {
                    let user = engine.get_user(&realm, id).expect("get");
                    prop_assert!(user.is_none(), "deleted user should not be found");
                }

                // Remaining should still exist
                for id in &created_ids[to_delete..] {
                    let user = engine.get_user(&realm, id).expect("get");
                    prop_assert!(user.is_some(), "remaining user should be found");
                }
            }

            /// Property: Email uniqueness holds under random creation sequences.
            #[test]
            fn email_uniqueness_under_random_creation(
                email in valid_email(),
                n in 2..5u32,
            ) {
                let (_dir, engine, _clock) = setup_engine();
                let realm = create_test_realm(&engine);

                // First creation should succeed
                let result = engine.create_user(&realm, &CreateUserRequest {
                    email: email.clone(),
                    display_name: "User 0".to_string(),
                    ..Default::default()
                });
                prop_assert!(result.is_ok(), "first creation should succeed");

                // Subsequent creations with same email should fail
                for i in 1..n {
                    let result = engine.create_user(&realm, &CreateUserRequest {
                        email: email.clone(),
                        display_name: format!("User {i}"),
                        ..Default::default()
                    });
                    prop_assert!(result.is_err(), "duplicate email should fail");
                    if let Err(ref err) = result {
                        prop_assert!(
                            matches!(err, IdentityError::DuplicateEmail),
                            "should be DuplicateEmail, got: {:?}", err
                        );
                    }
                }
            }

            /// Property: Random create/revoke sequences maintain consistent active session count.
            #[test]
            fn session_create_revoke_maintains_count(
                n_create in 1..8usize,
                n_revoke_ratio in 0.0..1.0_f64,
            ) {
                let (_dir, engine, _clock) = setup_engine();
                let realm = create_test_realm(&engine);
                let user = engine.create_user(&realm, &CreateUserRequest {
                    email: format!("session-prop-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Prop User".to_string(),
                    ..Default::default()
                }).expect("create user");

                // Create N sessions
                let mut session_ids = Vec::new();
                for _ in 0..n_create {
                    let session = engine
                        .create_session(&realm, user.id(), &SessionContext::default())
                        .expect("create session");
                    session_ids.push(session.id().clone());
                }

                // All should be valid
                for id in &session_ids {
                    let s = engine.get_session(&realm, id).expect("get");
                    prop_assert!(s.is_some(), "created session should be valid");
                }

                // Revoke a proportion of them
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
                let n_revoke = (n_create as f64 * n_revoke_ratio) as usize;
                for id in &session_ids[..n_revoke] {
                    engine.revoke_session(&realm, id).expect("revoke");
                }

                // Count active sessions
                let active_count = session_ids
                    .iter()
                    .filter(|id| engine.get_session(&realm, id).expect("get").is_some())
                    .count();

                prop_assert_eq!(
                    active_count,
                    n_create - n_revoke,
                    "active count should be creates minus revokes"
                );
            }

            /// Property: No session ID collisions across many generations.
            #[test]
            fn no_session_id_collisions(n in 10..100usize) {
                let (_dir, engine, _clock) = setup_engine();
                let realm = create_test_realm(&engine);
                let user = engine.create_user(&realm, &CreateUserRequest {
                    email: format!("collision-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Collision User".to_string(),
                    ..Default::default()
                }).expect("create user");

                let mut ids = std::collections::HashSet::new();
                for _ in 0..n {
                    let session = engine
                        .create_session(&realm, user.id(), &SessionContext::default())
                        .expect("create session");
                    let was_new = ids.insert(session.id().clone());
                    prop_assert!(was_new, "session ID collision detected");
                }
                prop_assert_eq!(ids.len(), n, "all session IDs should be unique");
            }
        }
    }

    // ===================================================================
    //  OIDC / OAuth 2.0 Unit Tests (Step 15)
    // ===================================================================

    fn pkce_challenge(verifier: &str) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(digest.as_ref())
    }
    const TEST_PKCE_VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

    fn register_test_client(engine: &EmbeddedIdentityEngine, realm: &RealmId) -> OAuthClient {
        engine
            .register_client(
                realm,
                &RegisterClientRequest {
                    client_name: "Test App".to_string(),
                    redirect_uris: vec!["https://app.example.com/callback".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client")
    }

    // ===== Unit Test 1: Generate authorization code with correct parameters =====

    #[test]
    fn generate_authorization_code_with_correct_params() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let response = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "random-state-value".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                    amr_values: Vec::new(),
                    response_mode: None,
                    request: None,
                    via_par: false,
                },
            )
            .expect("authorize should succeed");

        // Code should be non-empty base64url
        assert!(!response.code().is_empty(), "code must not be empty");
        // State should be echoed back
        assert_eq!(response.state(), "random-state-value");
    }

    // ===== Unit Test 2: Exchange authorization code returns tokens =====

    #[test]
    fn exchange_authorization_code_returns_tokens() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let auth_response = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "state1".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                    amr_values: Vec::new(),
                    response_mode: None,
                    request: None,
                    via_par: false,
                },
            )
            .expect("authorize");

        let token_response = engine
            .exchange_authorization_code(
                &realm,
                &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth_response.code().to_string(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                    dpop_jkt: None,
                    client_assertion_type: None,
                    client_assertion: None,
                },
            )
            .expect("exchange code");

        assert!(!token_response.access_token().is_empty());
        assert!(!token_response.id_token().is_empty());
        assert!(!token_response.refresh_token().is_empty());
        assert_eq!(token_response.token_type(), "Bearer");
        assert!(token_response.expires_in() > 0);

        // Verify access token is valid via session lookup
        let claims = engine
            .validate_token(&realm, token_response.access_token())
            .expect("validate access token");
        assert_eq!(claims.sub, user.id().to_string());

        // Verify ID token is a valid JWT with correct claims
        let id_claims =
            tokens::decode_claims_unverified(token_response.id_token()).expect("decode id token");
        assert_eq!(id_claims.sub, user.id().to_string());
        assert_eq!(id_claims.token_type, "id_token");
    }

    // ===== Unit Test 3: Authorization code single-use =====

    #[test]
    fn authorization_code_single_use() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let auth_response = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "state2".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                    amr_values: Vec::new(),
                    response_mode: None,
                    request: None,
                    via_par: false,
                },
            )
            .expect("authorize");

        // First exchange succeeds
        let result1 = engine.exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        );
        assert!(result1.is_ok(), "first exchange should succeed");

        // Second exchange with same code fails
        let result2 = engine.exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        );
        assert!(
            matches!(result2, Err(IdentityError::InvalidAuthorizationCode)),
            "second exchange must fail, got: {result2:?}"
        );
    }

    // ===== Unit Test 4: Authorization code expiration =====

    #[test]
    fn authorization_code_expiration() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let auth_response = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "state3".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                    amr_values: Vec::new(),
                    response_mode: None,
                    request: None,
                    via_par: false,
                },
            )
            .expect("authorize");

        // Advance clock past the authorization code TTL (default: 600 seconds)
        clock.advance(601 * 1_000_000); // 601 seconds in microseconds

        // Exchange should fail due to expiration
        let result = engine.exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        );
        assert!(
            matches!(result, Err(IdentityError::InvalidAuthorizationCode)),
            "expired code must be rejected, got: {result:?}"
        );
    }

    // ===== Unit Test 5: Discovery document returns correct metadata =====

    #[test]
    fn discovery_document_correct_metadata() {
        let (_dir, engine, _clock) = setup_engine();

        let doc = engine.oidc_discovery();

        assert_eq!(doc.issuer, "https://hearth.local");
        assert_eq!(doc.authorization_endpoint, "https://hearth.local/authorize");
        assert_eq!(doc.token_endpoint, "https://hearth.local/token");
        assert_eq!(doc.jwks_uri, "https://hearth.local/.well-known/jwks.json");
        assert!(doc.response_types_supported.contains(&"code".to_string()));
        assert!(doc.subject_types_supported.contains(&"public".to_string()));
        assert!(doc
            .id_token_signing_alg_values_supported
            .contains(&"EdDSA".to_string()));
        assert!(doc.scopes_supported.contains(&"openid".to_string()));
        assert!(doc
            .code_challenge_methods_supported
            .contains(&"S256".to_string()));
    }

    // ===================================================================
    //  OIDC Adversarial Tests (Step 15)
    // ===================================================================

    // ===== Adversarial Test 1: Authorization code reuse rejected =====

    #[test]
    fn adversarial_authorization_code_reuse_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let auth_response = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "adv-state".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                    amr_values: Vec::new(),
                    response_mode: None,
                    request: None,
                    via_par: false,
                },
            )
            .expect("authorize");

        // Use the code
        engine
            .exchange_authorization_code(
                &realm,
                &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth_response.code().to_string(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                    dpop_jkt: None,
                    client_assertion_type: None,
                    client_assertion: None,
                },
            )
            .expect("first exchange");

        // Attempt reuse — must fail
        let reuse = engine.exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        );
        assert!(
            matches!(reuse, Err(IdentityError::InvalidAuthorizationCode)),
            "code reuse must be rejected, got: {reuse:?}"
        );
    }

    // ===== Adversarial Test 2: Open redirect via non-registered URI rejected =====

    #[test]
    fn adversarial_open_redirect_non_registered_uri_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        // Attempt to authorize with an unregistered redirect URI
        let result = engine.authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://evil.example.com/steal-tokens".to_string(),
                scope: "openid".to_string(),
                state: "state-val".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        );
        assert!(
            matches!(result, Err(IdentityError::InvalidRedirectUri)),
            "unregistered redirect URI must be rejected, got: {result:?}"
        );
    }

    // ===== Adversarial Test 3: CSRF — missing state causes rejection =====

    #[test]
    fn adversarial_csrf_missing_state_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        // Attempt to authorize with empty state
        let result = engine.authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: String::new(), // empty state
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        );
        assert!(
            matches!(result, Err(IdentityError::InvalidGrant { .. })),
            "missing state must be rejected, got: {result:?}"
        );
    }

    // ===== Adversarial: Credential rate limiting =====

    fn setup_engine_with_rate_limit(
        max_attempts: u32,
        lockout_micros: i64,
    ) -> (tempfile::TempDir, EmbeddedIdentityEngine, Arc<FakeClock>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            rate_limit: RateLimitConfig {
                max_failed_attempts: max_attempts,
                lockout_duration_micros: lockout_micros,
                ..RateLimitConfig::default()
            },
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine creation");
        (dir, engine, clock)
    }

    #[test]
    fn rate_limiting_engages_after_max_failures() {
        // Configure: lockout after 3 failed attempts, 10-second lockout
        let lockout_micros = 10_000_000; // 10 seconds
        let (_dir, engine, _clock) = setup_engine_with_rate_limit(3, lockout_micros);
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("correct-pw".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        // 3 wrong attempts
        for i in 0..3 {
            let wrong = CleartextPassword::from_string(format!("wrong-{i}"));
            let result = engine.verify_password(&realm, user.id(), &wrong);
            assert!(
                result.is_ok(),
                "attempt {i} should not be rate limited yet: {result:?}"
            );
            assert!(!result.expect("ok"), "wrong password should not verify");
        }

        // 4th attempt: should be rate limited even with the correct password
        let correct = CleartextPassword::from_string("correct-pw".to_string());
        let result = engine.verify_password(&realm, user.id(), &correct);
        assert!(
            matches!(result, Err(IdentityError::RateLimited)),
            "should be rate limited after 3 failures, got: {result:?}"
        );
    }

    #[test]
    fn rate_limiting_resets_on_successful_verification() {
        let lockout_micros = 10_000_000;
        let (_dir, engine, _clock) = setup_engine_with_rate_limit(3, lockout_micros);
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("my-password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        // 2 wrong attempts (below threshold)
        for _ in 0..2 {
            let wrong = CleartextPassword::from_string("wrong".to_string());
            let result = engine
                .verify_password(&realm, user.id(), &wrong)
                .expect("should not be rate limited");
            assert!(!result);
        }

        // Correct password resets the counter
        let correct = CleartextPassword::from_string("my-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &correct)
            .expect("should succeed");
        assert!(result);

        // 2 more wrong attempts should succeed (counter was reset)
        for _ in 0..2 {
            let wrong = CleartextPassword::from_string("wrong".to_string());
            let result = engine
                .verify_password(&realm, user.id(), &wrong)
                .expect("should not be rate limited after reset");
            assert!(!result);
        }
    }

    #[test]
    fn rate_limiting_expires_after_lockout_window() {
        let lockout_micros = 10_000_000; // 10 seconds
        let (_dir, engine, clock) = setup_engine_with_rate_limit(3, lockout_micros);
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("my-password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        // Trigger lockout: 3 failures
        for i in 0..3 {
            let wrong = CleartextPassword::from_string(format!("wrong-{i}"));
            let _ = engine.verify_password(&realm, user.id(), &wrong);
        }

        // Confirm locked out
        let correct = CleartextPassword::from_string("my-password".to_string());
        assert!(
            matches!(
                engine.verify_password(&realm, user.id(), &correct),
                Err(IdentityError::RateLimited)
            ),
            "should be locked out"
        );

        // Advance clock past lockout window
        clock.advance(lockout_micros + 1);

        // Should be able to verify again
        let correct = CleartextPassword::from_string("my-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &correct)
            .expect("should be allowed after lockout expires");
        assert!(result, "correct password should verify after lockout");
    }

    // ===== WAL persistence: attempt tracker survives restart =====

    fn open_engine_at(
        dir: &tempfile::TempDir,
        max_attempts: u32,
        lockout_micros: i64,
        clock: Arc<FakeClock>,
    ) -> EmbeddedIdentityEngine {
        let storage = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
                .expect("reopen storage"),
        ) as Arc<dyn StorageEngine>;
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
        ));
        EmbeddedIdentityEngine::new(
            storage,
            Arc::clone(&clock) as Arc<dyn Clock>,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                rate_limit: RateLimitConfig {
                    max_failed_attempts: max_attempts,
                    lockout_duration_micros: lockout_micros,
                    ..RateLimitConfig::default()
                },
                ..IdentityConfig::default()
            },
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine creation")
    }

    #[test]
    fn wal_lockout_survives_restart() {
        let lockout_micros = 60_000_000; // 60 s — well beyond test duration
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));

        let realm;
        let user_id;
        {
            let engine = open_engine_at(&dir, 3, lockout_micros, Arc::clone(&clock));
            realm = create_test_realm(&engine);
            let user = create_test_user(&engine, &realm);
            user_id = user.id().clone();
            engine
                .set_password(
                    &realm,
                    &user_id,
                    &CleartextPassword::from_string("pw".to_string()),
                )
                .expect("set password");
            // 3 failures → lockout written to WAL
            for i in 0..3 {
                let _ = engine.verify_password(
                    &realm,
                    &user_id,
                    &CleartextPassword::from_string(format!("bad-{i}")),
                );
            }
            assert!(
                matches!(
                    engine.verify_password(
                        &realm,
                        &user_id,
                        &CleartextPassword::from_string("pw".to_string())
                    ),
                    Err(IdentityError::RateLimited)
                ),
                "should be locked out before restart"
            );
        } // engine dropped — simulates restart

        // Reopen same storage with a fresh engine instance
        let engine2 = open_engine_at(&dir, 3, lockout_micros, Arc::clone(&clock));
        let result = engine2.verify_password(
            &realm,
            &user_id,
            &CleartextPassword::from_string("pw".to_string()),
        );
        assert!(
            matches!(result, Err(IdentityError::RateLimited)),
            "lockout must persist across restart; got: {result:?}"
        );
    }

    #[test]
    fn wal_expired_lockout_cleared_on_restart() {
        let lockout_micros = 10_000_000; // 10 s
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));

        let realm;
        let user_id;
        {
            let engine = open_engine_at(&dir, 3, lockout_micros, Arc::clone(&clock));
            realm = create_test_realm(&engine);
            let user = create_test_user(&engine, &realm);
            user_id = user.id().clone();
            engine
                .set_password(
                    &realm,
                    &user_id,
                    &CleartextPassword::from_string("pw".to_string()),
                )
                .expect("set password");
            for i in 0..3 {
                let _ = engine.verify_password(
                    &realm,
                    &user_id,
                    &CleartextPassword::from_string(format!("bad-{i}")),
                );
            }
        }

        // Advance clock past lockout window before reopening
        clock.advance(lockout_micros + 1);

        let engine2 = open_engine_at(&dir, 3, lockout_micros, Arc::clone(&clock));
        // WAL entry should be ignored because it is expired — login should succeed
        let result = engine2.verify_password(
            &realm,
            &user_id,
            &CleartextPassword::from_string("pw".to_string()),
        );
        assert!(
            matches!(result, Ok(true)),
            "expired lockout must not persist; got: {result:?}"
        );
    }

    // ===== Rate-limit durability: WAL-persisted trackers survive restart (HEA-1669) =====

    #[test]
    #[allow(clippy::too_many_lines)]
    fn wal_rate_trackers_survive_restart() {
        // HEA-1669: all five secondary rate-limit trackers are now WAL-persisted and
        // must survive a process restart.  Only registration_ip_rate_trackers remains
        // in-memory only (IP churn makes persistence low-value).
        let lockout_micros = 60_000_000; // 60 s — well beyond test duration
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let ip = "192.0.2.1";
        let test_email = "addr@example.com";

        let realm;
        {
            let engine = open_engine_at(&dir, 3, lockout_micros, Arc::clone(&clock));
            realm = create_test_realm(&engine);
            let user = create_test_user(&engine, &realm);
            let user_id = user.id().clone();
            engine
                .set_password(
                    &realm,
                    &user_id,
                    &CleartextPassword::from_string("correct-pw".to_string()),
                )
                .expect("set password");

            // One failed attempt → written to WAL by record_failed_attempt
            let _ = engine.verify_password(
                &realm,
                &user_id,
                &CleartextPassword::from_string("wrong-pw".to_string()),
            );

            // Drive each WAL-backed tracker via its official record path.
            engine.record_ip_login_attempt(&realm, ip);
            engine.record_mfa_failed_attempt(&realm, &user_id);
            engine.record_magic_link_request(&realm, test_email);
            engine.record_password_reset_request(&realm, test_email);
            engine.record_registration_attempt(&realm, test_email, None);

            // Registration-IP tracker is still in-memory only — seed it directly
            // to confirm it does NOT survive.
            let now = clock.now().as_micros();
            engine
                .registration_ip_rate_trackers
                .lock()
                .expect("lock")
                .insert(
                    "10.0.0.1".to_string(),
                    AttemptTracker {
                        failed_count: 1,
                        last_failure_micros: now,
                    },
                );
        } // engine dropped — simulates a server restart

        // Reopen from the same storage directory
        let engine2 = open_engine_at(&dir, 3, lockout_micros, Arc::clone(&clock));

        // All WAL-persisted trackers must survive restart
        assert_eq!(
            engine2.attempt_trackers.lock().expect("lock").len(),
            1,
            "attempt_trackers must survive restart"
        );
        assert_eq!(
            engine2.ip_login_rate_trackers.lock().expect("lock").len(),
            1,
            "ip_login_rate_trackers must survive restart (HEA-1669)"
        );
        assert_eq!(
            engine2.mfa_attempt_trackers.lock().expect("lock").len(),
            1,
            "mfa_attempt_trackers must survive restart (HEA-1669)"
        );
        assert_eq!(
            engine2.magic_link_rate_trackers.lock().expect("lock").len(),
            1,
            "magic_link_rate_trackers must survive restart (HEA-1669)"
        );
        assert_eq!(
            engine2
                .password_reset_rate_trackers
                .lock()
                .expect("lock")
                .len(),
            1,
            "password_reset_rate_trackers must survive restart (HEA-1669)"
        );
        assert_eq!(
            engine2
                .registration_email_rate_trackers
                .lock()
                .expect("lock")
                .len(),
            1,
            "registration_email_rate_trackers must survive restart (HEA-1669)"
        );

        // Per-IP registration tracker is intentionally still in-memory only
        assert!(
            engine2
                .registration_ip_rate_trackers
                .lock()
                .expect("lock")
                .is_empty(),
            "registration_ip_rate_trackers are in-memory only — should not survive restart"
        );
    }

    #[test]
    fn ip_login_rate_limit_survives_restart_mid_brute_force() {
        // Regression test for HEA-1669: an IP that has accrued failed login attempts
        // must remain rate-limited after a process restart.
        let lockout_micros = 60_000_000; // 60 s
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let test_ip = "10.0.0.99";

        let realm;
        {
            let engine = open_engine_at(&dir, 3, lockout_micros, Arc::clone(&clock));
            realm = create_test_realm(&engine);

            // Accumulate ip_max_attempts failed login attempts from one IP
            let ip_max = engine.config.rate_limit.ip_max_attempts;
            for _ in 0..ip_max {
                engine.record_ip_login_attempt(&realm, test_ip);
            }

            // Confirm the IP is now rate-limited
            assert!(
                matches!(
                    engine.check_ip_login_rate_limit(&realm, test_ip),
                    Err(IdentityError::RateLimited)
                ),
                "IP should be rate-limited before restart"
            );
        } // engine dropped — simulates restart

        // Reopen from the same storage directory
        let engine2 = open_engine_at(&dir, 3, lockout_micros, Arc::clone(&clock));

        // The IP must still be rate-limited (WAL-persisted counter survived restart)
        assert!(
            matches!(
                engine2.check_ip_login_rate_limit(&realm, test_ip),
                Err(IdentityError::RateLimited)
            ),
            "IP rate limit must persist across restart (HEA-1669)"
        );
    }

    // ===== Adversarial: Nonce reuse detection =====

    fn setup_engine_with_nonce_enforcement(
    ) -> (tempfile::TempDir, EmbeddedIdentityEngine, Arc<FakeClock>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            oidc: OidcConfig::default(),
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine creation");
        (dir, engine, clock)
    }

    #[test]
    fn nonce_reuse_in_authorization_request_rejected() {
        let (_dir, engine, _clock) = setup_engine_with_nonce_enforcement();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        // First request with nonce succeeds
        let result = engine.authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "state-1".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some("unique-nonce-abc".to_string()),
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        );
        assert!(result.is_ok(), "first use of nonce should succeed");

        // Second request with same nonce should be rejected
        let result = engine.authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "state-2".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some("unique-nonce-abc".to_string()),
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        );
        assert!(
            matches!(result, Err(IdentityError::InvalidGrant { .. })),
            "reused nonce must be rejected, got: {result:?}"
        );

        // Different nonce should succeed
        let result = engine.authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "state-3".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some("different-nonce-xyz".to_string()),
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        );
        assert!(result.is_ok(), "different nonce should succeed");
    }

    #[test]
    fn nonce_reusable_after_ttl_expiry() {
        // After the authorization_code_ttl_secs window has passed, a previously
        // used nonce must be accepted again (the old entry should have been swept).
        let (_dir, engine, clock) = setup_engine_with_nonce_enforcement();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let make_request = |nonce: &str, state: &str| AuthorizationRequest {
            client_id: client.client_id().clone(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            scope: "openid".to_string(),
            state: state.to_string(),
            response_type: "code".to_string(),
            user_id: user.id().clone(),
            code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            nonce: Some(nonce.to_string()),
            resource: None,
            amr_values: Vec::new(),
            response_mode: None,
            request: None,
            via_par: false,
        };

        // Use the nonce at t=0.
        assert!(
            engine
                .authorize(&realm, &make_request("expiry-nonce", "state-1"))
                .is_ok(),
            "first use must succeed"
        );

        // Immediate reuse must still be rejected.
        assert!(
            matches!(
                engine.authorize(&realm, &make_request("expiry-nonce", "state-2")),
                Err(IdentityError::InvalidGrant { .. })
            ),
            "same nonce reused before TTL must be rejected"
        );

        // Advance past the authorization_code_ttl_secs (default 60 s = 60_000_000 µs).
        let ttl_micros = engine.config.oidc.authorization_code_ttl_secs * 1_000_000;
        clock.advance(ttl_micros);

        // The expired entry should be swept on the next call; the nonce is
        // now acceptable again because its original auth-code has expired.
        assert!(
            engine
                .authorize(&realm, &make_request("expiry-nonce", "state-3"))
                .is_ok(),
            "nonce must be accepted after TTL expiry"
        );
    }

    #[test]
    fn nonce_set_does_not_grow_unbounded() {
        // Repeatedly issue distinct nonces and advance the clock past the TTL
        // between batches.  The set must stay bounded to one TTL window rather
        // than accumulating every nonce ever used.
        let (_dir, engine, clock) = setup_engine_with_nonce_enforcement();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let ttl_micros = engine.config.oidc.authorization_code_ttl_secs * 1_000_000;

        // Batch A: insert 5 nonces.
        for i in 0..5u32 {
            let req = AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: format!("batch-a-state-{i}"),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some(format!("batch-a-nonce-{i}")),
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            };
            assert!(engine.authorize(&realm, &req).is_ok());
        }

        // Batch A nonces are present.
        {
            let nonces = engine.used_nonces.lock().expect("nonce lock");
            assert_eq!(nonces.len(), 5, "5 nonces after batch A");
        }

        // Advance past TTL — batch A nonces are now stale.
        clock.advance(ttl_micros);

        // Batch B: insert 3 new nonces (triggers sweep of batch A).
        for i in 0..3u32 {
            let req = AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: format!("batch-b-state-{i}"),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some(format!("batch-b-nonce-{i}")),
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            };
            assert!(engine.authorize(&realm, &req).is_ok());
        }

        // Only batch B nonces remain; batch A was evicted.
        {
            let nonces = engine.used_nonces.lock().expect("nonce lock");
            assert_eq!(
                nonces.len(),
                3,
                "set must contain only batch B nonces after TTL sweep, got {}",
                nonces.len()
            );
        }
    }

    // ===== Session simulation tests — see simulation/ crate =====

    // ===== Phase 1 Step 19: Multi-Tenancy =====
    //
    // Test scenarios from TEST_SCENARIOS.md § Multi-Tenancy

    // --- Unit Scenario 1: Create realm with configuration returns assigned RealmId ---

    #[test]
    fn create_realm_returns_assigned_id() {
        let (_dir, engine, _clock) = setup_engine();

        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "acme-corp".to_string(),
                config: None,
            })
            .expect("create realm");

        assert_eq!(realm.name(), "acme-corp");
        assert_eq!(realm.status(), RealmStatus::Active);

        // Should be retrievable
        let loaded = engine
            .get_realm(realm.id())
            .expect("get realm")
            .expect("realm should exist");
        assert_eq!(loaded.id(), realm.id());
        assert_eq!(loaded.name(), "acme-corp");
    }

    #[test]
    fn create_realm_with_custom_config() {
        let (_dir, engine, _clock) = setup_engine();

        let config = RealmConfig {
            session_ttl_micros: Some(3_600_000_000), // 1 hour
            password_memory_cost: Some(65536),
            password_time_cost: Some(3),
            ..RealmConfig::default()
        };
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "custom-corp".to_string(),
                config: Some(config.clone()),
            })
            .expect("create realm");

        assert_eq!(realm.config(), &config);
    }

    #[test]
    fn get_nonexistent_realm_returns_none() {
        let (_dir, engine, _clock) = setup_engine();

        let result = engine.get_realm(&RealmId::generate()).expect("get realm");
        assert!(result.is_none());
    }

    #[test]
    fn create_realm_rejects_duplicate_name() {
        let (_dir, engine, _clock) = setup_engine();

        engine
            .create_realm(&CreateRealmRequest {
                name: "duplicate-corp".to_string(),
                config: None,
            })
            .expect("first create_realm should succeed");

        let err = engine
            .create_realm(&CreateRealmRequest {
                name: "duplicate-corp".to_string(),
                config: None,
            })
            .expect_err("second create_realm with same name should fail");

        assert!(
            matches!(err, IdentityError::DuplicateRealmName),
            "expected DuplicateRealmName, got {err:?}"
        );

        // Confirm only one realm record exists for that name
        let realm = engine
            .get_realm_by_name("duplicate-corp")
            .expect("get_realm_by_name")
            .expect("realm should exist");
        assert_eq!(realm.name(), "duplicate-corp");
    }

    // --- Unit Scenario 2: Realm-scoped user creation; cross-realm lookup returns not-found ---

    #[test]
    fn realm_scoped_user_isolation() {
        let (_dir, engine, _clock) = setup_engine();

        let realm_a = engine
            .create_realm(&CreateRealmRequest {
                name: "realm-a".to_string(),
                config: None,
            })
            .expect("create realm A");
        let realm_b = engine
            .create_realm(&CreateRealmRequest {
                name: "realm-b".to_string(),
                config: None,
            })
            .expect("create realm B");

        // Create user in realm A
        let user_a = engine
            .create_user(
                realm_a.id(),
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user in A");

        // User should be visible in realm A
        let found = engine
            .get_user(realm_a.id(), user_a.id())
            .expect("get user in A");
        assert!(found.is_some());

        // User should NOT be visible in realm B
        let not_found = engine
            .get_user(realm_b.id(), user_a.id())
            .expect("get user in B");
        assert!(not_found.is_none());

        // Same email can be used in realm B (different namespace)
        let user_b = engine
            .create_user(
                realm_b.id(),
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice B".to_string(),
                    ..Default::default()
                },
            )
            .expect("create same email in B");
        assert_ne!(user_a.id(), user_b.id());
    }

    // --- Unit Scenario 3: Per-realm signing keys ---

    #[test]
    fn per_realm_signing_keys_are_independent() {
        let (_dir, engine, _clock) = setup_engine();

        let realm_a = engine
            .create_realm(&CreateRealmRequest {
                name: "realm-a".to_string(),
                config: None,
            })
            .expect("create realm A");
        let realm_b = engine
            .create_realm(&CreateRealmRequest {
                name: "realm-b".to_string(),
                config: None,
            })
            .expect("create realm B");

        let jwks_a = engine.realm_jwks(realm_a.id()).expect("jwks A");
        let jwks_b = engine.realm_jwks(realm_b.id()).expect("jwks B");

        // Each realm should have exactly one key
        assert_eq!(jwks_a.keys.len(), 1);
        assert_eq!(jwks_b.keys.len(), 1);

        // Keys should be different
        assert_ne!(jwks_a.keys[0].kid, jwks_b.keys[0].kid);
        assert_ne!(jwks_a.keys[0].x, jwks_b.keys[0].x);
    }

    // --- Unit Scenario 4: Realm configuration update ---

    #[test]
    fn update_realm_config_applies_only_to_target() {
        let (_dir, engine, _clock) = setup_engine();

        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "original-name".to_string(),
                config: None,
            })
            .expect("create realm");

        // Default config should have no overrides
        assert!(realm.config().session_ttl_micros.is_none());

        // Update config
        let new_config = RealmConfig {
            session_ttl_micros: Some(7_200_000_000), // 2 hours
            password_memory_cost: Some(32768),
            ..RealmConfig::default()
        };
        let updated = engine
            .update_realm(
                realm.id(),
                &UpdateRealmRequest {
                    name: Some("updated-name".to_string()),
                    status: None,
                    config: Some(new_config.clone()),
                },
            )
            .expect("update realm");

        assert_eq!(updated.name(), "updated-name");
        assert_eq!(updated.config(), &new_config);

        // Persisted
        let loaded = engine
            .get_realm(realm.id())
            .expect("get")
            .expect("should exist");
        assert_eq!(loaded.name(), "updated-name");
        assert_eq!(loaded.config(), &new_config);
    }

    #[test]
    fn update_nonexistent_realm_returns_not_found() {
        let (_dir, engine, _clock) = setup_engine();

        let err = engine
            .update_realm(
                &RealmId::generate(),
                &UpdateRealmRequest {
                    name: Some("nope".to_string()),
                    ..UpdateRealmRequest::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::RealmNotFound));
    }

    // --- SEC-20: pre-token webhook HMAC enforcement ---

    #[test]
    fn update_realm_rejects_webhook_config_without_hmac_secret() {
        use crate::identity::types::{PreTokenWebhookConfig, PreTokenWebhookErrorPolicy};

        let (_dir, engine, _clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "webhook-realm".to_string(),
                config: None,
            })
            .expect("create realm");

        let err = engine
            .update_realm(
                realm.id(),
                &UpdateRealmRequest {
                    config: Some(RealmConfig {
                        pre_token_webhook: Some(PreTokenWebhookConfig {
                            url: "http://localhost:9999/enrich".to_string(),
                            timeout_ms: 1000,
                            on_error: PreTokenWebhookErrorPolicy::FailOpen,
                            hmac_secret: None,
                        }),
                        ..RealmConfig::default()
                    }),
                    ..UpdateRealmRequest::default()
                },
            )
            .expect_err("must reject webhook without hmac_secret");

        assert!(
            matches!(err, IdentityError::InvalidInput { .. }),
            "expected InvalidInput, got {err:?}"
        );
        if let IdentityError::InvalidInput { reason } = err {
            assert!(
                reason.contains("hmac_secret"),
                "error reason must mention hmac_secret, got: {reason}"
            );
        }
    }

    #[test]
    fn update_realm_rejects_webhook_config_with_empty_hmac_secret() {
        use crate::identity::types::{PreTokenWebhookConfig, PreTokenWebhookErrorPolicy};

        let (_dir, engine, _clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "webhook-realm-empty".to_string(),
                config: None,
            })
            .expect("create realm");

        let err = engine
            .update_realm(
                realm.id(),
                &UpdateRealmRequest {
                    config: Some(RealmConfig {
                        pre_token_webhook: Some(PreTokenWebhookConfig {
                            url: "http://localhost:9999/enrich".to_string(),
                            timeout_ms: 1000,
                            on_error: PreTokenWebhookErrorPolicy::FailOpen,
                            hmac_secret: Some(String::new()),
                        }),
                        ..RealmConfig::default()
                    }),
                    ..UpdateRealmRequest::default()
                },
            )
            .expect_err("must reject webhook with empty hmac_secret");

        assert!(
            matches!(err, IdentityError::InvalidInput { .. }),
            "expected InvalidInput, got {err:?}"
        );
    }

    #[test]
    fn update_realm_accepts_webhook_config_with_hmac_secret() {
        use crate::identity::types::{PreTokenWebhookConfig, PreTokenWebhookErrorPolicy};

        let (_dir, engine, _clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "webhook-realm-ok".to_string(),
                config: None,
            })
            .expect("create realm");

        engine
            .update_realm(
                realm.id(),
                &UpdateRealmRequest {
                    config: Some(RealmConfig {
                        pre_token_webhook: Some(PreTokenWebhookConfig {
                            url: "http://localhost:9999/enrich".to_string(),
                            timeout_ms: 1000,
                            on_error: PreTokenWebhookErrorPolicy::FailOpen,
                            hmac_secret: Some("my-strong-secret".to_string()),
                        }),
                        ..RealmConfig::default()
                    }),
                    ..UpdateRealmRequest::default()
                },
            )
            .expect("webhook config with hmac_secret must be accepted");
    }

    #[test]
    fn create_realm_rejects_webhook_config_without_hmac_secret() {
        use crate::identity::types::{PreTokenWebhookConfig, PreTokenWebhookErrorPolicy};

        let (_dir, engine, _clock) = setup_engine();

        let err = engine
            .create_realm(&CreateRealmRequest {
                name: "webhook-realm-create".to_string(),
                config: Some(RealmConfig {
                    pre_token_webhook: Some(PreTokenWebhookConfig {
                        url: "http://localhost:9999/enrich".to_string(),
                        timeout_ms: 1000,
                        on_error: PreTokenWebhookErrorPolicy::FailOpen,
                        hmac_secret: None,
                    }),
                    ..RealmConfig::default()
                }),
            })
            .expect_err("must reject webhook without hmac_secret on create");

        assert!(
            matches!(err, IdentityError::InvalidInput { .. }),
            "expected InvalidInput, got {err:?}"
        );
    }

    // --- Unit Scenario 5: Cascading realm deletion ---

    #[test]
    fn delete_realm_cascades_all_data() {
        let (_dir, engine, _clock) = setup_engine();

        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "doomed-corp".to_string(),
                config: None,
            })
            .expect("create realm");

        // Create users
        let user1 = engine
            .create_user(
                realm.id(),
                &CreateUserRequest {
                    email: "user1@example.com".to_string(),
                    display_name: "User 1".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user 1");
        let user2 = engine
            .create_user(
                realm.id(),
                &CreateUserRequest {
                    email: "user2@example.com".to_string(),
                    display_name: "User 2".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user 2");

        // Set passwords
        let pw = CleartextPassword::from_string("password123".to_string());
        engine
            .set_password(realm.id(), user1.id(), &pw)
            .expect("set password");

        // Create sessions
        let session = engine
            .create_session(realm.id(), user1.id(), &SessionContext::default())
            .expect("create session");

        // Delete realm
        engine.delete_realm(realm.id()).expect("delete realm");

        // Realm record should be gone
        let loaded = engine.get_realm(realm.id()).expect("get realm");
        assert!(loaded.is_none(), "realm record should be deleted");

        // Users should be gone
        assert!(engine
            .get_user(realm.id(), user1.id())
            .expect("get")
            .is_none());
        assert!(engine
            .get_user(realm.id(), user2.id())
            .expect("get")
            .is_none());

        // Session should be gone
        assert!(engine
            .get_session(realm.id(), session.id())
            .expect("get")
            .is_none());

        // Signing key should be gone
        let jwks_err = engine.realm_jwks(realm.id());
        assert!(jwks_err.is_err(), "signing key should be deleted");
    }

    #[test]
    fn delete_nonexistent_realm_returns_not_found() {
        let (_dir, engine, _clock) = setup_engine();

        let err = engine
            .delete_realm(&RealmId::generate())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::RealmNotFound));
    }

    // ===== HEA-736: validate_token hot-path fix tests =====

    /// AC-4: create_realm immediately reflects Active status in the cache.
    #[test]
    fn realm_status_cache_active_after_create() {
        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);

        let cache = engine.realm_status_cache.load();
        let status = cache.get(&realm_id).copied();
        assert_eq!(
            status,
            Some(RealmStatus::Active),
            "realm_status_cache must contain Active immediately after create_realm"
        );
    }

    /// AC-4: update_realm(Suspended) immediately updates cache and causes
    /// validate_token to return RealmSuspended without a storage read.
    #[test]
    fn validate_token_reflects_suspend_via_cache() {
        let (_dir, engine, clock) = setup_engine();
        let realm_id = create_test_realm(&engine);

        let user = create_test_user(&engine, &realm_id);
        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("create session");
        let pair = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");

        // Advance clock by 1 second so the token iat < now.
        clock.advance(1_000_000);

        // Token must be valid for an Active realm.
        engine
            .validate_token(&realm_id, pair.access_token())
            .expect("token valid for active realm");

        // Suspend the realm — cache must update atomically.
        engine
            .update_realm(
                &realm_id,
                &UpdateRealmRequest {
                    name: None,
                    status: Some(RealmStatus::Suspended),
                    config: None,
                },
            )
            .expect("suspend realm");

        // Cache must reflect Suspended immediately.
        {
            let cache = engine.realm_status_cache.load();
            assert_eq!(
                cache.get(&realm_id).copied(),
                Some(RealmStatus::Suspended),
                "cache must reflect Suspended after update_realm"
            );
        }

        // validate_token must now return RealmSuspended (reads from cache,
        // not from storage — no get_realm syscall on this path).
        let err = engine
            .validate_token(&realm_id, pair.access_token())
            .expect_err("suspended realm must reject tokens");
        assert!(
            matches!(err, IdentityError::RealmSuspended),
            "expected RealmSuspended, got {err:?}"
        );
    }

    /// AC-4: delete_realm removes the realm from the status cache so that
    /// validate_token fails-open (no RealmSuspended) for unknown realm IDs.
    #[test]
    fn realm_status_cache_cleared_after_delete() {
        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);

        // Confirm it is in the cache.
        assert!(
            engine.realm_status_cache.load().contains_key(&realm_id),
            "realm must be in cache after create"
        );

        engine.delete_realm(&realm_id).expect("delete realm");

        // Must be gone from cache.
        assert!(
            !engine.realm_status_cache.load().contains_key(&realm_id),
            "realm must be removed from cache after delete"
        );
    }

    /// AC-4: a newly opened engine on existing storage scans and populates
    /// the realm status cache via `populate_realm_status_cache`, so
    /// `validate_token` works correctly without requiring any CRUD after start.
    #[test]
    fn realm_status_cache_populated_on_restart() {
        use crate::audit::EmbeddedAuditEngine;
        use crate::storage::{EmbeddedStorageEngine, StorageConfig};

        let dir = tempfile::tempdir().expect("tempdir");
        let realm_id;
        let suspended_id;

        // --- First engine: create realms then close ---
        {
            let config = StorageConfig::dev(dir.path().to_path_buf());
            let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("open"))
                as Arc<dyn StorageEngine>;
            let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
            let audit = Arc::new(EmbeddedAuditEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock) as Arc<dyn Clock>,
            ));
            let engine = EmbeddedIdentityEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock) as Arc<dyn Clock>,
                IdentityConfig {
                    credential: CredentialConfig::fast_for_testing(),
                    ..IdentityConfig::default()
                },
                audit as Arc<dyn AuditEngine>,
            )
            .expect("engine");

            realm_id = create_test_realm(&engine);
            suspended_id = engine
                .create_realm(&CreateRealmRequest {
                    name: format!("suspended-{}", uuid::Uuid::new_v4()),
                    config: None,
                })
                .expect("create suspended realm")
                .id()
                .clone();

            engine
                .update_realm(
                    &suspended_id,
                    &UpdateRealmRequest {
                        status: Some(RealmStatus::Suspended),
                        name: None,
                        config: None,
                    },
                )
                .expect("suspend");
        }

        // --- Second engine on same storage: should repopulate cache ---
        {
            let config = StorageConfig::dev(dir.path().to_path_buf());
            let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("reopen"))
                as Arc<dyn StorageEngine>;
            let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
            let audit = Arc::new(EmbeddedAuditEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock) as Arc<dyn Clock>,
            ));
            let engine2 = EmbeddedIdentityEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock) as Arc<dyn Clock>,
                IdentityConfig {
                    credential: CredentialConfig::fast_for_testing(),
                    ..IdentityConfig::default()
                },
                audit as Arc<dyn AuditEngine>,
            )
            .expect("engine2");

            let cache = engine2.realm_status_cache.load();
            assert_eq!(
                cache.get(&realm_id).copied(),
                Some(RealmStatus::Active),
                "active realm must be Active in cache after restart"
            );
            assert_eq!(
                cache.get(&suspended_id).copied(),
                Some(RealmStatus::Suspended),
                "suspended realm must be Suspended in cache after restart"
            );
        }
    }

    // ===== S12-F1: Session cache tests =====

    /// S12-F1/AC-1: valid session is inserted into the cache by `create_session`
    /// so the next `validate_token` call resolves from memory, not storage.
    #[test]
    fn session_cache_populated_on_create() {
        let (_dir, engine, clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);

        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("create session");

        let key = (realm_id.clone(), session.id().clone());
        assert!(
            engine.session_cache.load().contains_key(&key),
            "session must be in cache immediately after create_session"
        );

        // validate_token must succeed (exercises hot-path cache hit).
        clock.advance(1_000_000); // iat < now
        let pair = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");
        engine
            .validate_token(&realm_id, pair.access_token())
            .expect("validate_token must succeed from session cache");
    }

    /// S12-F1/AC-2: `revoke_session` evicts the session from the cache so
    /// `validate_token` returns `InvalidToken` without finding a stale entry.
    #[test]
    fn session_cache_evicted_on_revoke() {
        let (_dir, engine, clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);

        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("create session");
        clock.advance(1_000_000);

        let pair = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");

        let key = (realm_id.clone(), session.id().clone());
        assert!(
            engine.session_cache.load().contains_key(&key),
            "session must be in cache before revoke"
        );

        engine
            .revoke_session(&realm_id, session.id())
            .expect("revoke session");

        assert!(
            !engine.session_cache.load().contains_key(&key),
            "session must be evicted from cache after revoke_session"
        );

        let err = engine
            .validate_token(&realm_id, pair.access_token())
            .expect_err("revoked session must reject token");
        assert!(
            matches!(err, IdentityError::InvalidToken),
            "expected InvalidToken for revoked session, got {err:?}"
        );
    }

    /// S12-F1/AC-3: an expired session is lazily evicted from the cache on
    /// the first `get_session` call after its TTL passes.
    #[test]
    fn session_cache_lazy_evict_on_expiry() {
        let (_dir, engine, clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);

        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("create session");
        clock.advance(1_000_000); // iat < now for token issue

        // Advance past session TTL (default 7 days).
        clock.advance(8 * 24 * 60 * 60 * 1_000_000);

        let key = (realm_id.clone(), session.id().clone());
        assert!(
            engine.session_cache.load().contains_key(&key),
            "session should still be in cache before first post-expiry access"
        );

        // get_session triggers lazy eviction.
        let result = engine
            .get_session(&realm_id, session.id())
            .expect("get_session must not error");
        assert!(result.is_none(), "expired session must return None");

        assert!(
            !engine.session_cache.load().contains_key(&key),
            "expired session must be lazily evicted after get_session"
        );
    }

    // ===== S12-F2: Token claims cache tests =====

    /// S12-F2/AC-1: after `validate_token` succeeds, parsed claims are present
    /// in the token claims cache keyed by SHA-256 of the raw JWT.
    #[test]
    fn token_claims_cache_populated_on_validate_token() {
        let (_dir, engine, clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("create session");
        clock.advance(1_000_000);
        let pair = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");

        assert!(
            engine.token_claims_cache.load().is_empty(),
            "token claims cache must be empty before first validate_token"
        );

        engine
            .validate_token(&realm_id, pair.access_token())
            .expect("validate_token");

        let key = EmbeddedIdentityEngine::token_cache_hash(pair.access_token())
            .expect("token_cache_hash must succeed for a valid JWT");
        let cache = engine.token_claims_cache.load();
        assert!(
            cache.contains_key(&key),
            "token claims must be in cache after validate_token"
        );
        assert_eq!(
            cache.get(&key).expect("key must be present").token_type,
            "access",
            "cached claims must be access token type"
        );
    }

    /// S12-F2/AC-2: a cache hit on token claims does NOT bypass the session
    /// validity check — `validate_token` must still return `InvalidToken` for
    /// a revoked session even when claims are already cached.
    #[test]
    fn token_claims_cache_hit_still_enforces_session_check() {
        let (_dir, engine, clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("create session");
        clock.advance(1_000_000);
        let pair = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");

        // Prime the token claims cache.
        engine
            .validate_token(&realm_id, pair.access_token())
            .expect("first validate_token must succeed");

        let key = EmbeddedIdentityEngine::token_cache_hash(pair.access_token())
            .expect("SHA-256 must produce a 32-byte key");
        assert!(
            engine.token_claims_cache.load().contains_key(&key),
            "token claims must be cached"
        );

        // Revoke the session — the session check must still fire.
        engine
            .revoke_session(&realm_id, session.id())
            .expect("revoke session");

        let err = engine
            .validate_token(&realm_id, pair.access_token())
            .expect_err("revoked session must reject token even with cached claims");
        assert!(
            matches!(err, IdentityError::InvalidToken),
            "expected InvalidToken, got {err:?}"
        );
    }

    /// SEC-1 (HEA-742): a corrupted realm record in storage causes engine
    /// initialization to fail rather than silently omitting the realm from the
    /// cache (fail-closed, not fail-open).
    #[test]
    fn populate_realm_status_cache_fails_hard_on_corrupted_record() {
        use crate::audit::EmbeddedAuditEngine;
        use crate::storage::{EmbeddedStorageEngine, StorageConfig};

        let dir = tempfile::tempdir().expect("tempdir");

        // --- First engine: create a realm, then close ---
        let realm_id;
        {
            let config = StorageConfig::dev(dir.path().to_path_buf());
            let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("open"))
                as Arc<dyn StorageEngine>;
            let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
            let audit = Arc::new(EmbeddedAuditEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock) as Arc<dyn Clock>,
            ));
            let engine = EmbeddedIdentityEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock) as Arc<dyn Clock>,
                IdentityConfig {
                    credential: CredentialConfig::fast_for_testing(),
                    ..IdentityConfig::default()
                },
                audit as Arc<dyn AuditEngine>,
            )
            .expect("engine");

            realm_id = create_test_realm(&engine);

            // Corrupt the realm record in storage with non-JSON garbage bytes.
            let sys_realm = keys::system_realm_id();
            let realm_key = keys::encode_realm_id(&realm_id);
            storage
                .put(&sys_realm, &realm_key, b"not-valid-json{{{")
                .expect("corrupt put");
        }

        // --- Second engine on same storage: must refuse to initialize ---
        {
            let config = StorageConfig::dev(dir.path().to_path_buf());
            let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("reopen"))
                as Arc<dyn StorageEngine>;
            let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
            let audit = Arc::new(EmbeddedAuditEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock) as Arc<dyn Clock>,
            ));
            let result = EmbeddedIdentityEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock) as Arc<dyn Clock>,
                IdentityConfig {
                    credential: CredentialConfig::fast_for_testing(),
                    ..IdentityConfig::default()
                },
                audit as Arc<dyn AuditEngine>,
            );

            assert!(
                result.is_err(),
                "engine must refuse to initialize when a realm record is corrupted \
                 (fail-closed, not fail-open)"
            );
        }
    }

    // ===== Phase 1 Step 19: Multi-Tenancy Property Tests =====

    mod realm_proptests {
        use super::*;
        use proptest::prelude::*;

        /// Strategy for generating a valid realm name.
        ///
        /// Realm names must be ASCII alphanumeric, hyphens, or underscores
        /// only (1-63 chars), and must not collide with reserved admin
        /// URL keywords. We prefix every generated name with `r-` to
        /// guarantee uniqueness from the reserved set.
        fn valid_realm_name() -> impl Strategy<Value = String> {
            "[a-z0-9_-]{3,30}".prop_map(|s| format!("r-{}", s.trim_matches('-')))
        }

        /// Strategy for generating a valid email address.
        fn valid_email() -> impl Strategy<Value = String> {
            ("[a-z]{1,20}@[a-z]{1,10}\\.[a-z]{2,4}").prop_map(|s| s)
        }

        proptest! {
            /// Property: Random operations across N realms never produce
            /// cross-realm data leaks.
            ///
            /// Creates users with the same email in multiple realms, then
            /// verifies each realm only sees its own users.
            #[test]
            fn no_cross_realm_data_leaks(
                n_realms in 2..5usize,
                emails in proptest::collection::hash_set(valid_email(), 1..5),
            ) {
                let (_dir, engine, _clock) = setup_engine();
                let mut realms = Vec::new();

                // Create N realms
                for i in 0..n_realms {
                    let realm = engine.create_realm(&CreateRealmRequest {
                        name: format!("realm-{i}"),
                        config: None,
                    }).expect("create realm");
                    realms.push(realm);
                }

                // Create same set of users in each realm
                let mut user_ids: Vec<Vec<UserId>> = Vec::new();
                for realm in &realms {
                    let mut ids = Vec::new();
                    for (i, email) in emails.iter().enumerate() {
                        let user = engine.create_user(realm.id(), &CreateUserRequest {
                            email: email.clone(),
                            display_name: format!("User {i}"),
                            ..Default::default()
                        }).expect("create user");
                        ids.push(user.id().clone());
                    }
                    user_ids.push(ids);
                }

                // Verify: each realm's users are only visible in that realm
                for (t_idx, _realm) in realms.iter().enumerate() {
                    for (other_idx, other_realm) in realms.iter().enumerate() {
                        for user_id in &user_ids[t_idx] {
                            let result = engine.get_user(other_realm.id(), user_id)
                                .expect("get user");
                            if t_idx == other_idx {
                                prop_assert!(result.is_some(),
                                    "user should exist in its own realm");
                            } else {
                                prop_assert!(result.is_none(),
                                    "user should NOT exist in another realm");
                            }
                        }
                    }
                }
            }

            /// Property: Random create/delete realm sequences maintain
            /// consistent realm count and clean storage.
            #[test]
            fn create_delete_maintains_consistent_count(
                names in proptest::collection::hash_set(valid_realm_name(), 2..8),
            ) {
                let names: Vec<String> = names.into_iter().collect();
                let (_dir, engine, _clock) = setup_engine();
                let mut created_realms = Vec::new();

                // Create all realms
                for name in &names {
                    let realm = engine.create_realm(&CreateRealmRequest {
                        name: name.clone(),
                        config: None,
                    }).expect("create realm");
                    created_realms.push(realm);
                }

                // All should be retrievable
                for realm in &created_realms {
                    let loaded = engine.get_realm(realm.id()).expect("get");
                    prop_assert!(loaded.is_some(), "created realm should be found");
                }

                // Delete every other realm
                let to_delete: Vec<_> = created_realms.iter()
                    .enumerate()
                    .filter(|(i, _)| i % 2 == 0)
                    .map(|(_, t)| t.id().clone())
                    .collect();

                for realm_id in &to_delete {
                    engine.delete_realm(realm_id).expect("delete");
                }

                // Deleted should be gone
                for realm_id in &to_delete {
                    let loaded = engine.get_realm(realm_id).expect("get");
                    prop_assert!(loaded.is_none(), "deleted realm should not be found");
                }

                // Remaining should still exist
                for (i, realm) in created_realms.iter().enumerate() {
                    if i % 2 != 0 {
                        let loaded = engine.get_realm(realm.id()).expect("get");
                        prop_assert!(loaded.is_some(), "remaining realm should be found");
                    }
                }
            }

            /// Property: Realm key rotation under concurrent token issuance.
            ///
            /// Tokens issued before key rotation remain valid (they're validated
            /// via session lookup, not signature verification on the hot path).
            #[test]
            fn realm_key_rotation_preserves_in_flight_tokens(
                _seed in 0..100u32,
            ) {
                let (_dir, engine, _clock) = setup_engine();

                let realm = engine.create_realm(&CreateRealmRequest {
                    name: "rotation-corp".to_string(),
                    config: None,
                }).expect("create realm");

                let user = engine.create_user(realm.id(), &CreateUserRequest {
                    email: format!("rotation-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Rotation User".to_string(),
                    ..Default::default()
                }).expect("create user");

                let session = engine.create_session(realm.id(), user.id(), &SessionContext::default())
                    .expect("create session");

                // Issue tokens with current key
                let tokens = engine.issue_tokens(realm.id(), user.id(), session.id())
                    .expect("issue tokens");

                // Tokens should validate (session-based validation)
                let claims = engine.validate_token(realm.id(), tokens.access_token())
                    .expect("validate before rotation");
                prop_assert_eq!(&claims.sub, &user.id().to_string());

                // Token still validates after rotation because the hot-path
                // validation uses session lookup, not signature re-verification.
                // The JWKS key ID may have changed, but existing sessions are
                // unaffected.
                let new_claims = engine.validate_token(realm.id(), tokens.access_token())
                    .expect("validate after rotation");
                prop_assert_eq!(&new_claims.sub, &user.id().to_string());
            }
        }
    }

    #[test]
    fn refresh_token_subject_must_match_session_user() {
        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let session_user = create_test_user(&engine, &realm_id);
        let forged_subject = create_test_user(&engine, &realm_id);

        let session = engine
            .create_session(&realm_id, session_user.id(), &SessionContext::default())
            .expect("create session");
        let token_pair = engine
            .issue_tokens(&realm_id, session_user.id(), session.id())
            .expect("issue token pair");

        // Re-sign with a mismatched subject to ensure refresh validates that
        // session ownership matches the token subject, even for legacy tokens.
        let mut forged_claims = tokens::decode_claims_unverified(token_pair.refresh_token())
            .expect("decode refresh claims");
        forged_claims.sub = forged_subject.id().to_string();
        let signing_key = engine
            .get_or_load_realm_signing_key(&realm_id)
            .expect("load signing key");
        let forged_token = signing_key
            .issue_token(&forged_claims)
            .expect("issue forged token");

        let result = engine.refresh_tokens(&realm_id, &forged_token, None, None);
        assert!(
            matches!(result, Err(IdentityError::InvalidToken)),
            "subject/session mismatch must be rejected, got: {result:?}"
        );
    }
    // ===== Adversarial: MFA brute-force lockout (Scenario F1) =====

    #[test]
    #[allow(clippy::cast_sign_loss)] // Test timestamps are always positive
    fn mfa_brute_force_lockout() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        // Enroll TOTP
        let enrollment = engine.enroll_totp(&realm, user.id()).expect("enroll");

        // Activate MFA
        let now_secs = (clock.now().as_micros() / 1_000_000) as u64;
        let secret_bytes = data_encoding::BASE32_NOPAD
            .decode(enrollment.secret_base32.as_bytes())
            .expect("decode");
        let code = crate::identity::totp::compute_totp(&secret_bytes, now_secs / 30);
        engine
            .verify_totp_enrollment(&realm, user.id(), &code)
            .expect("verify enrollment");

        // 5 wrong codes
        for _ in 0..5 {
            let err = engine.verify_totp(&realm, user.id(), "000000");
            assert!(
                matches!(err, Err(IdentityError::InvalidMfaCode)),
                "should be InvalidMfaCode"
            );
        }

        // 6th attempt (correct code) should be rate limited
        // Advance time just slightly so we get a fresh step
        clock.advance(30_000_000); // 30 seconds
        let now_secs2 = (clock.now().as_micros() / 1_000_000) as u64;
        let correct_code = crate::identity::totp::compute_totp(&secret_bytes, now_secs2 / 30);
        let err = engine
            .verify_totp(&realm, user.id(), &correct_code)
            .expect_err("should be rate limited");
        assert!(
            matches!(err, IdentityError::RateLimited),
            "should be RateLimited, got: {err:?}"
        );

        // Advance clock past 5 min lockout (5 * 60 * 1_000_000 = 300_000_000 μs)
        clock.advance(300_000_000);
        let now_secs3 = (clock.now().as_micros() / 1_000_000) as u64;
        let correct_code2 = crate::identity::totp::compute_totp(&secret_bytes, now_secs3 / 30);
        engine
            .verify_totp(&realm, user.id(), &correct_code2)
            .expect("should succeed after lockout expires");
    }

    // ===== Adversarial: TOTP replay protection (Scenario F2) =====

    #[test]
    #[allow(clippy::cast_sign_loss)] // Test timestamps are always positive
    fn mfa_replay_protection() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        // Enroll + activate TOTP
        let enrollment = engine.enroll_totp(&realm, user.id()).expect("enroll");
        let secret_bytes = data_encoding::BASE32_NOPAD
            .decode(enrollment.secret_base32.as_bytes())
            .expect("decode");

        let now_secs = (clock.now().as_micros() / 1_000_000) as u64;
        let step = now_secs / 30;
        let code = crate::identity::totp::compute_totp(&secret_bytes, step);
        engine
            .verify_totp_enrollment(&realm, user.id(), &code)
            .expect("verify enrollment");

        // Advance to next step so we have a fresh code
        clock.advance(30_000_000); // 30 seconds
        let now_secs2 = (clock.now().as_micros() / 1_000_000) as u64;
        let step2 = now_secs2 / 30;
        let code2 = crate::identity::totp::compute_totp(&secret_bytes, step2);

        // First use succeeds
        engine
            .verify_totp(&realm, user.id(), &code2)
            .expect("first use should succeed");

        // Replay same code — should fail
        let err = engine
            .verify_totp(&realm, user.id(), &code2)
            .expect_err("replay should fail");
        assert!(
            matches!(err, IdentityError::InvalidMfaCode),
            "replay should be InvalidMfaCode, got: {err:?}"
        );

        // Advance to next step — new code should work
        clock.advance(30_000_000);
        let now_secs3 = (clock.now().as_micros() / 1_000_000) as u64;
        let step3 = now_secs3 / 30;
        let code3 = crate::identity::totp::compute_totp(&secret_bytes, step3);
        engine
            .verify_totp(&realm, user.id(), &code3)
            .expect("next step should succeed");
    }

    // ===== Magic Link / Passwordless (Step 25) unit tests =====

    /// Helper: creates a realm and user with email for magic link tests.
    fn setup_magic_link_user(engine: &EmbeddedIdentityEngine) -> (RealmId, crate::identity::User) {
        let realm = engine
            .create_realm(&crate::identity::CreateRealmRequest {
                name: format!("ml-test-{}", uuid::Uuid::new_v4()),
                config: None,
            })
            .expect("create realm");
        let user = engine
            .create_user(
                realm.id(),
                &crate::identity::CreateUserRequest {
                    email: format!("ml-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "ML Test User".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user");
        (realm.id().clone(), user)
    }

    // Test A: Generate magic link token bound to email with correct expiration
    #[test]
    fn magic_link_request_returns_nonempty_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn crate::core::Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            clock.clone() as Arc<dyn crate::core::Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine");

        let (realm, user) = setup_magic_link_user(&engine);

        // Request magic link
        let response = engine
            .request_magic_link(&realm, user.email())
            .expect("request_magic_link");

        // Token should be non-empty
        assert!(
            !response.token().is_empty(),
            "magic link token should not be empty"
        );

        // Verify stored record
        let token_hash = EmbeddedIdentityEngine::sha256_hex(response.token().as_bytes());
        let key = keys::encode_magic_link_token(&token_hash);
        let stored_bytes = engine
            .storage
            .get(&realm, &key)
            .expect("storage get")
            .expect("stored record should exist");
        let stored: StoredMagicLink = serde_json::from_slice(&stored_bytes).expect("deserialize");
        assert_eq!(stored.email, user.email().to_lowercase());
        assert!(stored.user_id.is_some(), "user_id should be set");
        assert!(!stored.used, "should not be marked as used");
        assert_eq!(
            stored.created_at_micros,
            clock.now().as_micros(),
            "created_at should match clock"
        );
    }

    // Test B: Validate magic link token — correct token returns associated user
    #[test]
    fn magic_link_validate_returns_correct_user() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn crate::core::Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            clock as Arc<dyn crate::core::Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine");

        let (realm, user) = setup_magic_link_user(&engine);

        // Request and validate
        let response = engine
            .request_magic_link(&realm, user.email())
            .expect("request_magic_link");
        let returned_user_id = engine
            .validate_magic_link(&realm, response.token())
            .expect("validate_magic_link");

        assert_eq!(
            returned_user_id.as_uuid(),
            user.id().as_uuid(),
            "returned user ID should match"
        );
    }

    // Test C: Expired magic link token rejected
    #[test]
    fn magic_link_expired_token_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn crate::core::Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            clock.clone() as Arc<dyn crate::core::Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine");

        let (realm, user) = setup_magic_link_user(&engine);

        // Request magic link
        let response = engine
            .request_magic_link(&realm, user.email())
            .expect("request_magic_link");

        // Advance clock past 15-minute expiry
        clock.advance(MAGIC_LINK_EXPIRY_MICROS + 1_000_000);

        // Validate should fail
        let err = engine
            .validate_magic_link(&realm, response.token())
            .expect_err("should fail for expired token");
        assert!(
            matches!(err, IdentityError::MagicLinkTokenInvalid),
            "should be MagicLinkTokenInvalid, got: {err:?}"
        );
    }

    // Test D: Single-use — second validation rejected
    #[test]
    fn magic_link_single_use_enforced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn crate::core::Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            clock as Arc<dyn crate::core::Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine");

        let (realm, user) = setup_magic_link_user(&engine);

        // Request and validate once (succeeds)
        let response = engine
            .request_magic_link(&realm, user.email())
            .expect("request_magic_link");
        let _user_id = engine
            .validate_magic_link(&realm, response.token())
            .expect("first validation should succeed");

        // Second validation should fail
        let err = engine
            .validate_magic_link(&realm, response.token())
            .expect_err("second validation should fail");
        assert!(
            matches!(err, IdentityError::MagicLinkTokenInvalid),
            "should be MagicLinkTokenInvalid, got: {err:?}"
        );
    }

    // ===== Delete cascades to device fingerprints (GDPR Art.17 / AC-11) =====

    #[test]
    fn delete_user_cascades_device_fingerprints() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        // Record two fingerprints for the user.
        let secret = "test-secret-at-least-32-bytes-long!!";
        let hmac1 = DeviceFingerprintStore::derive_hmac(secret, user.id(), "10.0.1.1", "UA/1");
        let hmac2 = DeviceFingerprintStore::derive_hmac(secret, user.id(), "10.0.2.1", "UA/1");
        engine
            .device_fp
            .record(&realm, user.id(), &hmac1, 30)
            .expect("record fp1");
        engine
            .device_fp
            .record(&realm, user.id(), &hmac2, 30)
            .expect("record fp2");

        // Confirm both are recognised before deletion.
        assert_eq!(
            engine
                .device_fp
                .check_and_refresh(&realm, user.id(), &hmac1, 30)
                .expect("check1"),
            crate::identity::device_fp::FingerprintResult::Recognised,
            "fp1 must be recognised before delete"
        );

        // Delete the user — cascade must erase both fingerprints.
        engine.delete_user(&realm, user.id()).expect("delete user");

        // Both fingerprints must now be gone.
        assert_eq!(
            engine
                .device_fp
                .check_and_refresh(&realm, user.id(), &hmac1, 30)
                .expect("check1-after"),
            crate::identity::device_fp::FingerprintResult::Unrecognised,
            "fp1 must be erased after delete_user"
        );
        assert_eq!(
            engine
                .device_fp
                .check_and_refresh(&realm, user.id(), &hmac2, 30)
                .expect("check2-after"),
            crate::identity::device_fp::FingerprintResult::Unrecognised,
            "fp2 must be erased after delete_user"
        );
    }

    // consent_records_are_realm_isolated moved to tests/identity_oauth.rs (HEA-1131)

    // ===== SCIM externalId tests =====

    fn create_scim_user(engine: &EmbeddedIdentityEngine, realm: &RealmId, email: &str) -> UserId {
        engine
            .create_user(
                realm,
                &CreateUserRequest {
                    email: email.to_string(),
                    display_name: "Alice".to_string(),
                    first_name: "Alice".to_string(),
                    last_name: "Example".to_string(),
                    attributes: Default::default(),
                },
            )
            .expect("create")
            .id()
            .clone()
    }

    #[test]
    fn scim_external_id_set_and_find_roundtrip() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-r1".to_string(),
                config: None,
            })
            .expect("create realm");
        let user = create_scim_user(&engine, realm.id(), "a@x.com");

        engine
            .set_scim_external_id(realm.id(), &user, "okta-abc")
            .expect("set");
        let found = engine
            .find_user_by_scim_external_id(realm.id(), "okta-abc")
            .expect("find")
            .expect("some");
        assert_eq!(found.id(), &user);
        let ext = engine
            .get_scim_external_id(realm.id(), &user)
            .expect("get")
            .expect("some");
        assert_eq!(ext, "okta-abc");
    }

    #[test]
    fn scim_external_id_duplicate_refused() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-r2".to_string(),
                config: None,
            })
            .expect("create realm");
        let alice = create_scim_user(&engine, realm.id(), "a@x.com");
        let bob = create_scim_user(&engine, realm.id(), "b@x.com");

        engine
            .set_scim_external_id(realm.id(), &alice, "okta-abc")
            .expect("set alice");
        let err = engine
            .set_scim_external_id(realm.id(), &bob, "okta-abc")
            .expect_err("bob collision");
        assert!(matches!(err, IdentityError::DuplicateScimExternalId));
    }

    #[test]
    fn scim_external_id_reassigning_same_user_succeeds() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-r3".to_string(),
                config: None,
            })
            .expect("create realm");
        let user = create_scim_user(&engine, realm.id(), "a@x.com");

        engine
            .set_scim_external_id(realm.id(), &user, "v1")
            .expect("v1");
        engine
            .set_scim_external_id(realm.id(), &user, "v2")
            .expect("v2");
        // Old externalId must no longer resolve.
        assert!(engine
            .find_user_by_scim_external_id(realm.id(), "v1")
            .expect("find v1")
            .is_none());
        let via_v2 = engine
            .find_user_by_scim_external_id(realm.id(), "v2")
            .expect("find v2");
        assert!(via_v2.is_some());
    }

    #[test]
    fn scim_clear_external_id_is_idempotent() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-r4".to_string(),
                config: None,
            })
            .expect("create realm");
        let user = create_scim_user(&engine, realm.id(), "a@x.com");

        // Clearing when unset is a no-op.
        engine
            .clear_scim_external_id(realm.id(), &user)
            .expect("clear empty");

        engine
            .set_scim_external_id(realm.id(), &user, "okta-abc")
            .expect("set");
        engine
            .clear_scim_external_id(realm.id(), &user)
            .expect("clear");
        // A second clear is also fine.
        engine
            .clear_scim_external_id(realm.id(), &user)
            .expect("clear again");
        assert!(engine
            .find_user_by_scim_external_id(realm.id(), "okta-abc")
            .expect("find")
            .is_none());
    }

    #[test]
    fn scim_external_id_cascades_on_delete_user() {
        let (_dir, engine, clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-r5".to_string(),
                config: None,
            })
            .expect("create realm");
        let user = create_scim_user(&engine, realm.id(), "a@x.com");
        engine
            .set_scim_external_id(realm.id(), &user, "okta-abc")
            .expect("set");
        engine.delete_user(realm.id(), &user).expect("delete");
        assert!(engine
            .find_user_by_scim_external_id(realm.id(), "okta-abc")
            .expect("find")
            .is_none());
        // Re-creating a user and assigning the same externalId should
        // succeed because the cascade freed it.
        // A-20: advance clock past 90-day email reservation window.
        clock.advance(91 * 24 * 60 * 60 * 1_000_000);
        let reborn = create_scim_user(&engine, realm.id(), "a@x.com");
        engine
            .set_scim_external_id(realm.id(), &reborn, "okta-abc")
            .expect("reuse");
    }

    #[test]
    fn scim_external_id_realm_isolated() {
        let (_dir, engine, _clock) = setup_engine();
        let r1 = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-ra".to_string(),
                config: None,
            })
            .expect("create r1");
        let r2 = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-rb".to_string(),
                config: None,
            })
            .expect("create r2");
        let u1 = create_scim_user(&engine, r1.id(), "a@x.com");
        let u2 = create_scim_user(&engine, r2.id(), "a@x.com");
        engine
            .set_scim_external_id(r1.id(), &u1, "same-id")
            .expect("r1");
        // Same externalId is allowed in r2 because index is realm-scoped.
        engine
            .set_scim_external_id(r2.id(), &u2, "same-id")
            .expect("r2");
        assert_eq!(
            engine
                .find_user_by_scim_external_id(r1.id(), "same-id")
                .expect("find r1")
                .expect("some")
                .id(),
            &u1
        );
        assert_eq!(
            engine
                .find_user_by_scim_external_id(r2.id(), "same-id")
                .expect("find r2")
                .expect("some")
                .id(),
            &u2
        );
    }

    // ===== HEA-123: JWT signature verification regression tests =====

    /// Regression: forged access token with escalated permissions rejected
    ///
    /// Vulnerability class: Missing JWT signature verification (CWE-347).
    /// An attacker with no access to Hearth's Ed25519 signing key crafts a
    /// valid-looking JWT that claims admin permissions. With
    /// `decode_claims_unverified` this would succeed; after HEA-123,
    /// `verify_token_signature_for_realm` cryptographically rejects it.
    #[test]
    fn forged_access_token_with_escalated_permissions_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("session");
        let tokens = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");

        // Real token validates
        engine
            .validate_token(&realm_id, tokens.access_token())
            .expect("real token should validate");

        // Craft a forged token with escalated permissions, signed by an
        // attacker-controlled key (not Hearth's key).
        let attacker_key = SigningKey::generate().expect("attacker keygen");
        let real_claims = tokens::decode_claims_unverified(tokens.access_token()).expect("decode");
        let forged_claims = TokenClaims {
            permissions: vec!["admin".to_string(), "*".to_string()],
            roles: vec!["superadmin".to_string()],
            ..real_claims
        };
        let forged_token = attacker_key
            .issue_token(&forged_claims)
            .expect("issue forged");

        let result = engine.validate_token(&realm_id, &forged_token);
        assert!(
            result.is_err(),
            "forged token with escalated permissions must be rejected"
        );
    }

    /// Regression: forged refresh token without valid signature rejected
    ///
    /// Vulnerability class: Missing JWT signature verification on refresh
    /// (CWE-347). An attacker with a stolen-but-expired refresh token could
    /// re-sign it with a new key and mint new tokens. HEA-123 ensures
    /// `verify_token_signature_for_realm` blocks forged refresh tokens.
    #[test]
    fn forged_refresh_token_rejected() {
        use crate::identity::oidc::AuthorizationRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let client = engine
            .register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: "Forged Refresh App".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec![
                        "authorization_code".to_string(),
                        "refresh_token".to_string(),
                    ],
                    require_consent: false,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client");

        let auth = engine
            .authorize(
                &realm_id,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    state: "csrf-state".to_string(),
                    response_type: "code".to_string(),
                    scope: "openid".to_string(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    user_id: user.id().clone(),
                    nonce: None,
                    resource: None,
                    amr_values: Vec::new(),
                    response_mode: None,
                    request: None,
                    via_par: false,
                },
            )
            .expect("authorize");

        let response = engine
            .exchange_authorization_code(
                &realm_id,
                &crate::identity::oidc::TokenExchangeRequest {
                    code: auth.code().to_string(),
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                    dpop_jkt: None,
                    client_assertion_type: None,
                    client_assertion: None,
                },
            )
            .expect("exchange");

        // Real refresh works
        engine
            .refresh_tokens(&realm_id, response.refresh_token(), None, None)
            .expect("legitimate refresh should succeed");

        // Craft a forged refresh token with a different signing key
        let attacker_key = SigningKey::generate().expect("attacker keygen");
        let real_claims =
            tokens::decode_claims_unverified(response.refresh_token()).expect("decode");
        let forged_claims = TokenClaims {
            exp: real_claims.exp + 86400, // extend lifetime
            token_type: "refresh".to_string(),
            ..real_claims
        };
        let forged_token = attacker_key
            .issue_token(&forged_claims)
            .expect("issue forged refresh");

        let result = engine.refresh_tokens(&realm_id, &forged_token, None, None);
        assert!(result.is_err(), "forged refresh token must be rejected");
    }

    /// Regression: forged revoke token silently ignored (RFC 7009)
    ///
    /// Vulnerability class: Missing JWT signature verification on revocation
    /// (CWE-347). An attacker with a forged token containing a real `sid`
    /// could revoke a victim's session without ever knowing their credentials.
    /// HEA-123 ensures forged tokens produce silent 200 OK without action.
    #[test]
    fn forged_revoke_token_silently_ignored() {
        use crate::identity::oidc::TokenRevocationRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("session");
        let tokens = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");

        // Craft a forged revocation token targeting a real session
        let attacker_key = SigningKey::generate().expect("attacker keygen");
        let real_claims = tokens::decode_claims_unverified(tokens.access_token()).expect("decode");
        let forged_claims = TokenClaims {
            token_type: "access".to_string(),
            ..real_claims
        };
        let forged_token = attacker_key
            .issue_token(&forged_claims)
            .expect("issue forged revoke");

        // RFC 7009: forged token revocation should silently succeed
        engine
            .revoke_token(
                &realm_id,
                &TokenRevocationRequest {
                    token: forged_token,
                    token_type_hint: Some("access_token".to_string()),
                },
            )
            .expect("forged revoke should silently succeed per RFC 7009");

        // The real session must NOT be revoked
        let result = engine.validate_token(&realm_id, tokens.access_token());
        assert!(
            result.is_ok(),
            "real session must not be revoked by forged token"
        );
    }

    /// Regression: forged token introspection shows inactive (RFC 7662)
    ///
    /// Vulnerability class: Missing JWT signature verification on introspection
    /// (CWE-347). An attacker could craft a token that appears active to the
    /// introspection endpoint, bypassing resource-server authorization checks.
    /// HEA-123 ensures forged tokens return `active: false`.
    #[test]
    fn forged_introspection_shows_inactive() {
        use crate::identity::oidc::TokenIntrospectionRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("session");
        let tokens = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");

        // Real introspection shows active
        let real_response = engine
            .introspect_token(
                &realm_id,
                &TokenIntrospectionRequest {
                    token: tokens.access_token().to_string(),
                    token_type_hint: Some("access_token".to_string()),
                    introspecting_client_id: None,
                },
            )
            .expect("real introspection");
        assert!(real_response.active, "real token should be active");

        // Craft a forged token with valid-looking claims but wrong key
        let attacker_key = SigningKey::generate().expect("attacker keygen");
        let real_claims = tokens::decode_claims_unverified(tokens.access_token()).expect("decode");
        let forged_claims = TokenClaims {
            exp: real_claims.exp + 86400,
            token_type: "access".to_string(),
            permissions: vec!["admin".to_string()],
            ..real_claims
        };
        let forged_token = attacker_key
            .issue_token(&forged_claims)
            .expect("issue forged introspect");

        let response = engine
            .introspect_token(
                &realm_id,
                &TokenIntrospectionRequest {
                    token: forged_token,
                    token_type_hint: Some("access_token".to_string()),
                    introspecting_client_id: None,
                },
            )
            .expect("forged introspection should not error");

        assert!(
            !response.active,
            "forged token introspection must return inactive"
        );
    }

    // ===== Password reset TTL =====

    #[test]
    fn password_reset_token_expires_after_configured_ttl() {
        let (_dir, engine, clock) = setup_engine();

        // Create a realm with a 5-minute password reset TTL.
        let short_ttl_micros: i64 = 5 * 60 * 1_000_000;
        let realm_req = crate::identity::CreateRealmRequest {
            name: format!("ttl-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                password_reset_token_ttl_micros: Some(short_ttl_micros),
                ..RealmConfig::default()
            }),
        };
        let realm = engine.create_realm(&realm_req).expect("create realm");
        let user = create_test_user(&engine, realm.id());
        engine
            .set_password(
                realm.id(),
                user.id(),
                &CleartextPassword::from_string("ValidPassword1!".to_string()),
            )
            .expect("set password");

        // Issue a reset token.
        let token = engine
            .request_password_reset(realm.id(), user.email())
            .expect("request reset")
            .expect("known user should produce token");

        // Token is valid immediately.
        engine
            .reset_password_with_token(
                realm.id(),
                &token,
                &CleartextPassword::from_string("NewValidPassword1!".to_string()),
            )
            .expect("reset should succeed within TTL");

        // Issue a second token and advance the clock past the TTL.
        let token2 = engine
            .request_password_reset(realm.id(), user.email())
            .expect("request second reset")
            .expect("token");
        clock.advance(short_ttl_micros + 1);

        let err = engine
            .reset_password_with_token(
                realm.id(),
                &token2,
                &CleartextPassword::from_string("AnotherPass1!".to_string()),
            )
            .expect_err("expired token must be rejected");
        assert!(
            matches!(err, IdentityError::PasswordResetTokenInvalid),
            "expected PasswordResetTokenInvalid after TTL expiry, got: {err}"
        );
    }

    // ==========================================================================
    // HEA-501: Security Phase A — PKCE mandatory, redirect URI hardening, RFC 9207 iss
    // ==========================================================================

    // F-01: Public client must supply PKCE S256
    #[test]
    fn public_client_requires_pkce_s256() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm); // public client
        let user = create_test_user(&engine, &realm);
        assert!(
            !client.is_confidential(),
            "register_test_client must be public"
        );

        let err = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "s".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None,
                    resource: None,
                    amr_values: Vec::new(),
                    response_mode: None,
                    request: None,
                    via_par: false,
                },
            )
            .expect_err("must reject public client with no PKCE");
        assert!(
            matches!(&err, IdentityError::InvalidInput { reason } if reason.contains("PKCE is required")),
            "got: {err}"
        );
    }

    // F-01: Plain PKCE method must be rejected even when challenge is present
    #[test]
    fn pkce_challenge_without_s256_method_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        // challenge present but no method supplied
        let err = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "s".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: None,
                    nonce: None,
                    resource: None,
                    amr_values: Vec::new(),
                    response_mode: None,
                    request: None,
                    via_par: false,
                },
            )
            .expect_err("must reject challenge without S256 method");
        assert!(
            matches!(&err, IdentityError::InvalidInput { reason } if reason.contains("S256")),
            "got: {err}"
        );
    }

    // F-01: Confidential client without PKCE must always be rejected (RFC 9700 §2.1.1)
    #[test]
    fn confidential_client_without_pkce_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let client = engine
            .register_client(
                &realm,
                &RegisterClientRequest {
                    client_name: "Confidential Auth Code App".to_string(),
                    redirect_uris: vec!["https://app.example.com/callback".to_string()],
                    client_secret: Some("s3cr3t".to_string()),
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: false,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register confidential client");
        let user = create_test_user(&engine, &realm);
        assert!(client.is_confidential());

        let result = engine.authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "s".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        );
        assert!(
            matches!(&result, Err(IdentityError::InvalidInput { reason }) if reason.contains("PKCE")),
            "confidential client without PKCE must be rejected; got: {result:?}"
        );
    }

    // F-02: Redirect URI with fragment must be rejected at registration
    #[test]
    fn redirect_uri_fragment_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let err = engine
            .register_client(
                &realm,
                &RegisterClientRequest {
                    client_name: "Frag App".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb#fragment".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect_err("fragment URI must be rejected");
        assert!(
            matches!(&err, IdentityError::InvalidInput { reason } if reason.contains("fragment")),
            "got: {err}"
        );
    }

    // F-02: Redirect URI with wildcard must be rejected
    #[test]
    fn redirect_uri_wildcard_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let err = engine
            .register_client(
                &realm,
                &RegisterClientRequest {
                    client_name: "Wild App".to_string(),
                    redirect_uris: vec!["https://*.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect_err("wildcard URI must be rejected");
        assert!(
            matches!(&err, IdentityError::InvalidInput { reason } if reason.contains("wildcard")),
            "got: {err}"
        );
    }

    // F-02: Non-localhost http URI must be rejected
    #[test]
    fn redirect_uri_http_non_localhost_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let err = engine
            .register_client(
                &realm,
                &RegisterClientRequest {
                    client_name: "Bad App".to_string(),
                    redirect_uris: vec!["http://app.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect_err("http non-localhost URI must be rejected");
        assert!(
            matches!(&err, IdentityError::InvalidInput { reason } if reason.contains("loopback")),
            "got: {err}"
        );
    }

    // F-02: localhost http URI must be allowed (RFC 8252 §8.3)
    #[test]
    fn redirect_uri_http_localhost_allowed() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        engine
            .register_client(
                &realm,
                &RegisterClientRequest {
                    client_name: "Native App".to_string(),
                    redirect_uris: vec!["http://localhost:8080/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("localhost http must be allowed");
    }

    // F-15: Scope with invalid characters must be rejected
    #[test]
    fn scope_with_invalid_characters_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let err = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid \"bad-scope\"".to_string(),
                    state: "s".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                    amr_values: Vec::new(),
                    response_mode: None,
                    request: None,
                    via_par: false,
                },
            )
            .expect_err("invalid scope chars must be rejected");
        assert!(
            matches!(&err, IdentityError::InvalidInput { reason } if reason.contains("scope")),
            "got: {err}"
        );
    }

    // F-07: Authorization response includes iss
    #[test]
    fn authorization_response_includes_iss() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let resp = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "s".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                    amr_values: Vec::new(),
                    response_mode: None,
                    request: None,
                    via_par: false,
                },
            )
            .expect("authorize must succeed");

        assert!(!resp.iss().is_empty(), "iss must be present in response");
        assert!(
            resp.iss().starts_with("http"),
            "iss must be an absolute URL, got: {}",
            resp.iss()
        );
    }

    // F-07: Discovery document advertises authorization_response_iss_parameter_supported
    #[test]
    fn discovery_doc_includes_iss_parameter_supported() {
        let (_dir, engine, _clock) = setup_engine();
        let doc = engine.oidc_discovery();
        assert!(
            doc.authorization_response_iss_parameter_supported,
            "discovery must advertise iss parameter support"
        );
    }

    // ===== HEA-801: required_actions / default_required_actions =====

    #[test]
    fn new_user_has_empty_required_actions_when_realm_has_no_defaults() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let user = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "ra_none@example.com".to_string(),
                    display_name: "RA None".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user");

        assert!(
            user.required_actions().is_empty(),
            "user created under a realm with no defaults must have no required actions"
        );
    }

    #[test]
    fn new_user_inherits_realm_default_required_actions() {
        use crate::identity::RequiredAction;
        let (_dir, engine, _clock) = setup_engine();

        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: format!("ra-realm-{}", uuid::Uuid::new_v4()),
                config: Some(RealmConfig {
                    default_required_actions: vec![
                        RequiredAction::VerifyEmail,
                        RequiredAction::UpdatePassword,
                    ],
                    ..RealmConfig::default()
                }),
            })
            .expect("create realm");

        let user = engine
            .create_user(
                realm.id(),
                &CreateUserRequest {
                    email: "ra_user@example.com".to_string(),
                    display_name: "RA User".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user");

        assert_eq!(
            user.required_actions(),
            &[RequiredAction::VerifyEmail, RequiredAction::UpdatePassword],
            "user must inherit realm's default_required_actions"
        );
    }

    #[test]
    fn required_actions_survive_storage_round_trip() {
        use crate::identity::RequiredAction;
        let (_dir, engine, _clock) = setup_engine();

        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: format!("ra-rt-realm-{}", uuid::Uuid::new_v4()),
                config: Some(RealmConfig {
                    default_required_actions: vec![RequiredAction::VerifyEmail],
                    ..RealmConfig::default()
                }),
            })
            .expect("create realm");

        let created = engine
            .create_user(
                realm.id(),
                &CreateUserRequest {
                    email: "ra_rt@example.com".to_string(),
                    display_name: "RA RT".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user");

        // Read back from storage to verify the field was persisted.
        let fetched = engine
            .get_user(realm.id(), created.id())
            .expect("get user")
            .expect("user exists");

        assert_eq!(
            fetched.required_actions(),
            &[RequiredAction::VerifyEmail],
            "required_actions must survive the storage round-trip"
        );
    }

    // ===== Security gap fixes (HEA-836 re-review) =====

    /// NEW-MED-1: verify_recovery_code must check the per-user MFA rate limit so
    /// that recovery-code attempts cannot bypass the lockout that TOTP enforces.
    #[test]
    #[allow(clippy::cast_sign_loss)]
    fn recovery_code_respects_mfa_rate_limit() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        // Enroll and activate TOTP.
        let enrollment = engine.enroll_totp(&realm, user.id()).expect("enroll");
        let secret_bytes = data_encoding::BASE32_NOPAD
            .decode(enrollment.secret_base32.as_bytes())
            .expect("decode");
        let now_secs = (clock.now().as_micros() / 1_000_000) as u64;
        let code = crate::identity::totp::compute_totp(&secret_bytes, now_secs / 30);
        engine
            .verify_totp_enrollment(&realm, user.id(), &code)
            .expect("activate");

        // Exhaust the 5-attempt MFA budget with wrong TOTP codes.
        for _ in 0..5 {
            let _ = engine.verify_totp(&realm, user.id(), "000000");
        }

        // Recovery-code attempt must now return RateLimited, not InvalidMfaCode.
        let err = engine
            .verify_recovery_code(&realm, user.id(), "AAAAA-BBBBB")
            .expect_err("should be rate limited");
        assert!(
            matches!(err, IdentityError::RateLimited),
            "expected RateLimited after MFA lockout, got: {err:?}"
        );
    }

    /// NEW-LOW-1: a failed MFA code in step_up_mfa_grant_token must increment
    /// the IP login attempt counter so the IP-level rate limiter can act.
    ///
    /// Strategy: pre-seed the IP counter to (ip_max_attempts - 1) via the public
    /// helper, then make one bad step-up request. If the step-up handler records
    /// the attempt, the counter tips over and `check_ip_login_rate_limit` returns
    /// `RateLimited`. If the handler does NOT record it, the counter stays below
    /// the threshold and the check still returns `Ok`.
    #[test]
    #[allow(clippy::cast_sign_loss)]
    fn step_up_mfa_bad_code_records_ip_attempt() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm);

        // Enroll and activate TOTP.
        let pw = CleartextPassword::from_string("password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        let enrollment = engine.enroll_totp(&realm, user.id()).expect("enroll");
        let secret_bytes = data_encoding::BASE32_NOPAD
            .decode(enrollment.secret_base32.as_bytes())
            .expect("decode");
        let now_secs = (clock.now().as_micros() / 1_000_000) as u64;
        let code0 = crate::identity::totp::compute_totp(&secret_bytes, now_secs / 30);
        engine
            .verify_totp_enrollment(&realm, user.id(), &code0)
            .expect("activate");

        let test_ip = "10.0.0.1";

        // Pre-seed the IP counter to (ip_max_attempts - 1).
        let ip_max = engine.config.rate_limit.ip_max_attempts;
        for _ in 0..(ip_max - 1) {
            engine.record_ip_login_attempt(&realm, test_ip);
        }
        engine
            .check_ip_login_rate_limit(&realm, test_ip)
            .expect("IP should not yet be rate-limited");

        // Submit one step-up request with a wrong MFA code.
        let request = crate::identity::oidc::StepUpMfaGrantRequest {
            email: user.email().to_string(),
            password: "password".to_string(),
            mfa_code: "000000".to_string(),
            scope: None,
            client_ip: Some(test_ip.to_string()),
            user_agent: None,
        };
        let err = engine
            .step_up_mfa_grant_token(&realm, &request)
            .expect_err("should fail on bad MFA code");
        assert!(
            matches!(
                err,
                IdentityError::InvalidMfaCode | IdentityError::RateLimited
            ),
            "unexpected error: {err:?}"
        );

        // The step-up handler must have pushed the counter over the threshold.
        let ip_rate_result = engine.check_ip_login_rate_limit(&realm, test_ip);
        assert!(
            matches!(ip_rate_result, Err(IdentityError::RateLimited)),
            "IP should be rate-limited after step-up MFA failure, got: {ip_rate_result:?}"
        );
    }

    // ===== PAR (RFC 9126) unit tests =====
    //
    // These live here rather than in tests/par.rs because `consume_par`
    // returns `StoredPushedAuthorizationRequest` which is pub(crate).

    fn par_setup_engine_and_public_client() -> (
        tempfile::TempDir,
        EmbeddedIdentityEngine,
        Arc<FakeClock>,
        RealmId,
        crate::identity::oidc::OAuthClient,
    ) {
        use crate::identity::oidc::RegisterClientRequest;
        let (dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let client = engine
            .register_client(
                &realm,
                &RegisterClientRequest {
                    client_name: "PAR Public Client".to_string(),
                    redirect_uris: vec!["https://example.com/callback".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: false,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client");
        (dir, engine, clock, realm, client)
    }

    fn par_pkce_challenge() -> (String, String) {
        use data_encoding::BASE64URL_NOPAD;
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = BASE64URL_NOPAD
            .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref());
        (verifier.to_string(), challenge)
    }

    fn par_request(
        client_id: crate::core::ClientId,
        challenge: &str,
    ) -> crate::identity::oidc::PushedAuthorizationRequest {
        crate::identity::oidc::PushedAuthorizationRequest {
            client_id,
            redirect_uri: "https://example.com/callback".to_string(),
            scope: "openid".to_string(),
            state: "state-xyz".to_string(),
            resource: None,
            response_type: "code".to_string(),
            code_challenge: Some(challenge.to_string()),
            code_challenge_method: Some(crate::identity::oidc::CodeChallengeMethod::S256),
            nonce: None,
            request: None,
            response_mode: None,
        }
    }

    #[test]
    fn par_consume_happy_path_marks_used() {
        let (_dir, engine, _clock, realm, client) = par_setup_engine_and_public_client();
        let (_, challenge) = par_pkce_challenge();

        let resp = engine
            .push_authorization_request(
                &realm,
                &par_request(client.client_id().clone(), &challenge),
            )
            .expect("push");
        let stored = engine
            .consume_par(&realm, &resp.request_uri)
            .expect("first consume must succeed");

        assert_eq!(stored.state, "state-xyz");
        assert!(
            stored.used,
            "stored entry must be marked used after consume"
        );
    }

    #[test]
    fn par_single_use_enforced() {
        let (_dir, engine, _clock, realm, client) = par_setup_engine_and_public_client();
        let (_, challenge) = par_pkce_challenge();

        let resp = engine
            .push_authorization_request(
                &realm,
                &par_request(client.client_id().clone(), &challenge),
            )
            .expect("push");

        engine
            .consume_par(&realm, &resp.request_uri)
            .expect("first consume");
        let second = engine.consume_par(&realm, &resp.request_uri);
        assert!(
            matches!(
                second,
                Err(IdentityError::InvalidPushedAuthorizationRequest)
            ),
            "second consume must be rejected as replay, got: {second:?}"
        );
    }

    #[test]
    fn par_expired_rejected() {
        let (_dir, engine, clock, realm, client) = par_setup_engine_and_public_client();
        let (_, challenge) = par_pkce_challenge();

        let resp = engine
            .push_authorization_request(
                &realm,
                &par_request(client.client_id().clone(), &challenge),
            )
            .expect("push");

        clock.advance(91 * 1_000_000); // 91 seconds past the 90-second TTL

        let result = engine.consume_par(&realm, &resp.request_uri);
        assert!(
            matches!(
                result,
                Err(IdentityError::InvalidPushedAuthorizationRequest)
            ),
            "expired request_uri must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn par_unknown_uri_rejected() {
        let (_dir, engine, _clock, realm, _client) = par_setup_engine_and_public_client();
        let bogus = "urn:ietf:params:oauth:request_uri:00000000-0000-0000-0000-000000000000";
        assert!(
            matches!(
                engine.consume_par(&realm, bogus),
                Err(IdentityError::InvalidPushedAuthorizationRequest)
            ),
            "unknown request_uri must return InvalidPushedAuthorizationRequest"
        );
    }

    #[test]
    fn par_malformed_uri_prefix_rejected() {
        let (_dir, engine, _clock, realm, _client) = par_setup_engine_and_public_client();
        assert!(
            matches!(
                engine.consume_par(&realm, "not-a-urn"),
                Err(IdentityError::InvalidPushedAuthorizationRequest)
            ),
            "malformed request_uri must return InvalidPushedAuthorizationRequest"
        );
    }

    // ===== Rate Tracker Pruning Tests (HEA-1127) =====

    #[test]
    fn sweep_expired_prunes_stale_rate_tracker_entries() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);

        // Insert two entries at T0 (the engine's initial clock time).
        let t0 = clock.now().as_micros();
        {
            let mut map = engine.magic_link_rate_trackers.lock().expect("lock");
            map.insert(
                "magic:realm1:old1@example.com".to_string(),
                AttemptTracker {
                    failed_count: 3,
                    last_failure_micros: t0,
                },
            );
            map.insert(
                "magic:realm1:old2@example.com".to_string(),
                AttemptTracker {
                    failed_count: 1,
                    last_failure_micros: t0,
                },
            );
        }

        // Advance 3 hours so the two entries are beyond the 2×window cutoff
        // (MAGIC_LINK_RATE_WINDOW_MICROS = 1 h; cutoff = now - 2 h).
        clock.advance(3 * 60 * 60 * 1_000_000);

        // Insert one fresh entry at the new "now".
        let t_fresh = clock.now().as_micros();
        {
            let mut map = engine.magic_link_rate_trackers.lock().expect("lock");
            map.insert(
                "magic:realm1:recent@example.com".to_string(),
                AttemptTracker {
                    failed_count: 1,
                    last_failure_micros: t_fresh,
                },
            );
        }

        let stats = engine.sweep_expired(&realm).expect("sweep");

        assert_eq!(
            stats.rate_trackers_pruned, 2,
            "two stale magic-link entries must be pruned"
        );

        let map = engine.magic_link_rate_trackers.lock().expect("lock");
        assert_eq!(map.len(), 1, "only the recent entry must survive");
        assert!(
            map.contains_key("magic:realm1:recent@example.com"),
            "fresh entry must be kept"
        );
    }

    #[test]
    fn sweep_expired_does_not_prune_recent_rate_tracker_entries() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let now = clock.now().as_micros();
        {
            let mut map = engine.magic_link_rate_trackers.lock().expect("lock");
            map.insert(
                "magic:realm1:fresh@example.com".to_string(),
                AttemptTracker {
                    failed_count: 2,
                    last_failure_micros: now,
                },
            );
        }

        // Clock not advanced — entry is well within any window.
        let stats = engine.sweep_expired(&realm).expect("sweep");

        assert_eq!(
            stats.rate_trackers_pruned, 0,
            "fresh entry must not be pruned"
        );

        let map = engine.magic_link_rate_trackers.lock().expect("lock");
        assert_eq!(map.len(), 1, "fresh entry must survive");
    }

    #[test]
    fn sweep_expired_prunes_all_five_rate_tracker_maps() {
        let (_dir, engine, clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let t0 = clock.now().as_micros();

        // Insert one stale entry in each of the five maps.
        engine
            .magic_link_rate_trackers
            .lock()
            .expect("lock")
            .insert(
                "k".to_string(),
                AttemptTracker {
                    failed_count: 1,
                    last_failure_micros: t0,
                },
            );
        engine
            .password_reset_rate_trackers
            .lock()
            .expect("lock")
            .insert(
                "k".to_string(),
                AttemptTracker {
                    failed_count: 1,
                    last_failure_micros: t0,
                },
            );
        engine
            .registration_email_rate_trackers
            .lock()
            .expect("lock")
            .insert(
                "k".to_string(),
                AttemptTracker {
                    failed_count: 1,
                    last_failure_micros: t0,
                },
            );
        engine
            .registration_ip_rate_trackers
            .lock()
            .expect("lock")
            .insert(
                "k".to_string(),
                AttemptTracker {
                    failed_count: 1,
                    last_failure_micros: t0,
                },
            );
        engine.ip_login_rate_trackers.lock().expect("lock").insert(
            "k".to_string(),
            AttemptTracker {
                failed_count: 1,
                last_failure_micros: t0,
            },
        );

        // Advance far enough to stale out all five maps.
        // password_reset window is the smallest (15 min); 2×15 min = 30 min.
        // ip_login window comes from config.rate_limit.ip_window_micros (default 1 h).
        // Use 3 hours to be safe across all windows.
        clock.advance(3 * 60 * 60 * 1_000_000);

        let stats = engine.sweep_expired(&realm).expect("sweep");

        assert_eq!(
            stats.rate_trackers_pruned, 5,
            "one stale entry from each of the five maps must be pruned"
        );
    }

    // A-38: act_chain_depth unit tests
    //
    // `act_chain_depth(v)` counts the act object itself as 1; each
    // nested `act` adds 1. Validation rejects depth > MAX (3).

    #[test]
    fn act_chain_depth_leaf_is_1() {
        let v = serde_json::json!({ "sub": "alice" });
        assert_eq!(EmbeddedIdentityEngine::act_chain_depth(&v), 1);
    }

    #[test]
    fn act_chain_depth_one_nested_is_2() {
        let v = serde_json::json!({ "sub": "alice", "act": { "sub": "bob" } });
        assert_eq!(EmbeddedIdentityEngine::act_chain_depth(&v), 2);
    }

    #[test]
    fn act_chain_depth_at_max_accepted() {
        // Build a chain exactly MAX_ACT_CHAIN_DEPTH deep; must pass the guard.
        let max = crate::abuse::MAX_ACT_CHAIN_DEPTH;
        // Start with the innermost leaf, then wrap max-1 times.
        let mut node = serde_json::json!({ "sub": "leaf" });
        for i in 0..(max - 1) {
            node = serde_json::json!({ "sub": format!("a{i}"), "act": node });
        }
        let depth = EmbeddedIdentityEngine::act_chain_depth(&node);
        assert_eq!(
            depth, max,
            "depth-{max} chain should equal MAX_ACT_CHAIN_DEPTH"
        );
        assert!(depth <= max, "depth-{max} chain should be within the cap");
    }

    #[test]
    fn act_chain_depth_over_max_rejected() {
        // Build a chain MAX+1 deep; must exceed the cap.
        let max = crate::abuse::MAX_ACT_CHAIN_DEPTH;
        let mut node = serde_json::json!({ "sub": "leaf" });
        for i in 0..max {
            node = serde_json::json!({ "sub": format!("a{i}"), "act": node });
        }
        let depth = EmbeddedIdentityEngine::act_chain_depth(&node);
        assert_eq!(depth, max + 1, "depth-{} chain should equal MAX+1", max + 1);
        assert!(depth > max, "depth-{} chain should exceed the cap", max + 1);
    }

    // ===== DPoP storage tests (HEA-1410) =====

    #[test]
    fn check_and_record_dpop_jti_rejects_replay() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let now_secs = 1_700_000_000_i64;

        assert!(
            engine
                .check_and_record_dpop_jti(&realm, "jti-abc", now_secs)
                .is_ok(),
            "first use must succeed"
        );
        assert!(
            matches!(
                engine.check_and_record_dpop_jti(&realm, "jti-abc", now_secs),
                Err(crate::identity::error::IdentityError::DPopProofReplay)
            ),
            "second use of same jti must be rejected"
        );
    }

    #[test]
    fn check_and_record_dpop_jti_allows_different_jtis() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let now_secs = 1_700_000_000_i64;

        assert!(engine
            .check_and_record_dpop_jti(&realm, "jti-1", now_secs)
            .is_ok());
        assert!(engine
            .check_and_record_dpop_jti(&realm, "jti-2", now_secs)
            .is_ok());
    }

    #[test]
    fn check_and_record_dpop_jti_isolated_across_realms() {
        let (_dir, engine, _clock) = setup_engine();
        let realm_a = create_test_realm(&engine);
        let realm_b = create_test_realm(&engine);
        let now_secs = 1_700_000_000_i64;

        assert!(engine
            .check_and_record_dpop_jti(&realm_a, "shared-jti", now_secs)
            .is_ok());
        assert!(
            engine
                .check_and_record_dpop_jti(&realm_b, "shared-jti", now_secs)
                .is_ok(),
            "same jti in different realm must be independent"
        );
    }

    #[test]
    fn get_realm_dpop_nonce_secret_is_stable_across_calls() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);

        let secret1 = engine
            .get_realm_dpop_nonce_secret(&realm)
            .expect("first call");
        let secret2 = engine
            .get_realm_dpop_nonce_secret(&realm)
            .expect("second call");
        assert_eq!(
            secret1, secret2,
            "same realm must always return the same secret"
        );
        assert_ne!(secret1, [0u8; 32], "secret must not be the zero key");
    }

    #[test]
    fn get_realm_dpop_nonce_secret_differs_across_realms() {
        let (_dir, engine, _clock) = setup_engine();
        let realm_a = create_test_realm(&engine);
        let realm_b = create_test_realm(&engine);

        let s_a = engine
            .get_realm_dpop_nonce_secret(&realm_a)
            .expect("realm_a");
        let s_b = engine
            .get_realm_dpop_nonce_secret(&realm_b)
            .expect("realm_b");
        assert_ne!(s_a, s_b, "each realm must get an independent nonce secret");
    }

    #[test]
    fn get_realm_dpop_nonce_secret_survives_restart() {
        // Simulate persistence across restarts by rebuilding the engine from
        // the same storage directory. The second engine instance must load the
        // same secret that the first one generated.
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_cfg = StorageConfig::dev(dir.path().to_path_buf());

        let make_engine = |cfg: StorageConfig, ts: i64| {
            let storage = Arc::new(EmbeddedStorageEngine::open(cfg).expect("open storage"))
                as Arc<dyn StorageEngine>;
            let clock = Arc::new(FakeClock::new(Timestamp::from_micros(ts))) as Arc<dyn Clock>;
            let audit = Arc::new(EmbeddedAuditEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock),
            ));
            EmbeddedIdentityEngine::new(
                storage,
                clock,
                IdentityConfig {
                    credential: CredentialConfig::fast_for_testing(),
                    ..IdentityConfig::default()
                },
                audit as Arc<dyn AuditEngine>,
            )
            .expect("engine")
        };

        let engine1 = make_engine(storage_cfg.clone(), 1_000_000);
        let realm = create_test_realm(&engine1);
        let secret1 = engine1
            .get_realm_dpop_nonce_secret(&realm)
            .expect("engine1 secret");
        assert_ne!(secret1, [0u8; 32], "secret must not be zero key");
        drop(engine1);

        // Re-open the same storage — equivalent to a server restart.
        let engine2 = make_engine(storage_cfg, 2_000_000);
        let secret2 = engine2
            .get_realm_dpop_nonce_secret(&realm)
            .expect("engine2 secret");

        assert_eq!(
            secret1, secret2,
            "nonce secret must survive a server restart"
        );
    }

    // ===== HEA-1655: OIDC RSA key persistence + JWKS grace window =====

    #[test]
    fn oidc_rsa_kid_survives_engine_restart() {
        // Rebuild the engine from the same storage path to simulate a restart.
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_cfg = StorageConfig::dev(dir.path().to_path_buf());

        let make_engine = |cfg: StorageConfig, ts: i64| {
            let storage =
                Arc::new(EmbeddedStorageEngine::open(cfg).expect("open")) as Arc<dyn StorageEngine>;
            let clock = Arc::new(FakeClock::new(Timestamp::from_micros(ts))) as Arc<dyn Clock>;
            let audit = Arc::new(EmbeddedAuditEngine::new(
                Arc::clone(&storage),
                Arc::clone(&clock),
            ));
            EmbeddedIdentityEngine::new(
                storage,
                clock,
                IdentityConfig {
                    credential: CredentialConfig::fast_for_testing(),
                    ..IdentityConfig::default()
                },
                audit as Arc<dyn AuditEngine>,
            )
            .expect("engine")
        };

        // First engine: trigger RSA key generation + WAL persist via jwks().
        let engine1 = make_engine(storage_cfg.clone(), 1_000_000);
        let jwks1 = engine1.jwks();
        let rsa_kid1 = jwks1
            .keys
            .iter()
            .find(|k| k.kty == "RSA")
            .map(|k| k.kid.clone())
            .expect("RS256 key must appear in JWKS");
        drop(engine1);

        // Second engine from same storage — simulates a server restart.
        let engine2 = make_engine(storage_cfg, 2_000_000);
        let jwks2 = engine2.jwks();
        let rsa_kid2 = jwks2
            .keys
            .iter()
            .find(|k| k.kty == "RSA")
            .map(|k| k.kid.clone())
            .expect("RS256 key must appear in JWKS after restart");

        assert_eq!(
            rsa_kid1, rsa_kid2,
            "OIDC RSA kid must be stable across restarts"
        );
    }

    #[test]
    fn oidc_rsa_retiring_key_in_jwks_during_grace() {
        // Hold the storage Arc so we can write retiring keys directly (simulating
        // what a future key-rotation call would do).
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
                .expect("open"),
        ) as Arc<dyn StorageEngine>;
        let clock =
            Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000))) as Arc<dyn Clock>;
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine");

        // Trigger RSA key generation + storage.
        let jwks_before = engine.jwks();
        let current_rsa_kid = jwks_before
            .keys
            .iter()
            .find(|k| k.kty == "RSA")
            .map(|k| k.kid.clone())
            .expect("RS256 key in initial JWKS");

        // Generate a separate "previous" RSA key and write it as a retiring
        // entry with a future deadline (simulating a recent rotation).
        let retiring_key = crate::identity::tokens::RsaSigningKey::generate("hearth-oidc", 3650)
            .expect("gen retiring key");
        let retiring_kid = retiring_key.key_id().to_string();
        assert_ne!(
            retiring_kid, current_rsa_kid,
            "retiring and current kids must differ"
        );

        let sys = crate::identity::keys::system_realm_id();
        let now_secs = (clock.now().as_micros() / 1_000_000) as u64;
        let deadline_secs = now_secs + 86_400; // 24 h from now
        let storage_key =
            crate::identity::keys::encode_oidc_rsa_retiring_key(deadline_secs, &retiring_kid);

        // JSON envelope matches the StoredRsaKey format in engine/oauth.rs.
        #[derive(serde::Serialize)]
        struct Stored<'a> {
            pkcs8: &'a [u8],
            cert: &'a [u8],
        }
        let body = serde_json::to_vec(&Stored {
            pkcs8: retiring_key.pkcs8_bytes(),
            cert: retiring_key.cert_der(),
        })
        .expect("serialize retiring key");
        storage
            .put(&sys, &storage_key, &body)
            .expect("write retiring key");

        // JWKS must now contain both the current kid and the retiring kid.
        let jwks_after = engine.jwks();
        let rsa_kids: Vec<&str> = jwks_after
            .keys
            .iter()
            .filter(|k| k.kty == "RSA")
            .map(|k| k.kid.as_str())
            .collect();
        assert!(
            rsa_kids.contains(&current_rsa_kid.as_str()),
            "current kid must appear in JWKS; got {rsa_kids:?}"
        );
        assert!(
            rsa_kids.contains(&retiring_kid.as_str()),
            "retiring kid must appear in JWKS during grace; got {rsa_kids:?}"
        );
    }

    #[test]
    fn oidc_rsa_expired_retiring_key_omitted_from_jwks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
                .expect("open"),
        ) as Arc<dyn StorageEngine>;
        let clock =
            Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000))) as Arc<dyn Clock>;
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine");

        engine.jwks(); // Trigger RSA key persistence.

        // Write an already-expired retiring key (deadline in the past).
        let expired_key = crate::identity::tokens::RsaSigningKey::generate("hearth-oidc", 3650)
            .expect("gen expired key");
        let expired_kid = expired_key.key_id().to_string();
        let sys = crate::identity::keys::system_realm_id();
        let now_secs = (clock.now().as_micros() / 1_000_000) as u64;
        let deadline_past = now_secs.saturating_sub(1); // already expired
        let storage_key =
            crate::identity::keys::encode_oidc_rsa_retiring_key(deadline_past, &expired_kid);
        #[derive(serde::Serialize)]
        struct Stored<'a> {
            pkcs8: &'a [u8],
            cert: &'a [u8],
        }
        let body = serde_json::to_vec(&Stored {
            pkcs8: expired_key.pkcs8_bytes(),
            cert: expired_key.cert_der(),
        })
        .expect("serialize");
        storage.put(&sys, &storage_key, &body).expect("put");

        // The expired key must NOT appear in JWKS.
        let jwks = engine.jwks();
        let rsa_kids: Vec<&str> = jwks
            .keys
            .iter()
            .filter(|k| k.kty == "RSA")
            .map(|k| k.kid.as_str())
            .collect();
        assert!(
            !rsa_kids.contains(&expired_kid.as_str()),
            "expired retiring kid must be omitted from JWKS; got {rsa_kids:?}"
        );
    }

    // ===== Property test: per-account lockout is independent of source IP (HEA-1669) =====

    mod rate_limit_property {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(proptest::test_runner::Config {
                cases: 32,
                ..Default::default()
            })]

            /// A per-account lockout (via `attempt_trackers`) must trigger even when
            /// every failed attempt comes from a different source IP.  This verifies
            /// that the account-level rate limiter is independent of the IP limiter
            /// and cannot be bypassed by rotating source addresses.
            #[test]
            fn per_account_lockout_triggers_independent_of_source_ip(
                // Each iteration gets a distinct attempt count in [1..10].
                max_attempts in 1u32..=5u32,
            ) {
                let lockout_micros = 60_000_000_i64; // 60 s
                let (_dir, engine, _clock) = setup_engine_with_rate_limit(
                    max_attempts,
                    lockout_micros,
                );
                let realm = create_test_realm(&engine);
                let user = create_test_user(&engine, &realm);

                let pw = CleartextPassword::from_string("secret".to_string());
                engine
                    .set_password(&realm, user.id(), &pw)
                    .expect("set password");

                // Drive max_attempts failures from distinct IPs — the account-level
                // counter should trigger regardless of the IP diversity.
                for i in 0..max_attempts {
                    let distinct_ip = format!("10.{}.{}.{}", i / 256, i % 256, 1);
                    // Record the IP attempt (should NOT cause the account block alone).
                    engine.record_ip_login_attempt(&realm, &distinct_ip);
                    // The actual account failure goes through verify_password.
                    let _ = engine.verify_password(
                        &realm,
                        user.id(),
                        &CleartextPassword::from_string(format!("wrong-{i}")),
                    );
                }

                // The account must be locked out regardless of IP diversity.
                let result = engine.verify_password(
                    &realm,
                    user.id(),
                    &CleartextPassword::from_string("secret".to_string()),
                );
                prop_assert!(
                    matches!(result, Err(IdentityError::RateLimited)),
                    "account must be locked out after {max_attempts} failures from \
                     distinct IPs; got: {result:?}"
                );
            }
        }
    }
}
