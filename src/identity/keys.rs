//! Storage key encoding for identity records.
//!
//! Indexes maintained, all realm-scoped via `StorageEngine`:
//!
//! - **User primary**: `usr:id:{uuid}` → JSON-serialized `User`
//! - **User email index**: `usr:email:{normalized_email}` → `UserId` UUID bytes
//! - **Session primary**: `ses:id:{uuid}` → JSON-serialized `Session`
//! - **Session user index**: `ses:user:{user_uuid}:{session_uuid}` → empty
//! - **Credential**: `cred:user:{uuid}` → JSON-serialized `StoredCredential`
//! - **Credential history**: `cred:history:{uuid}` → JSON-serialized `Vec<StoredCredential>`
//! - **OAuth client**: `oauth:client:{uuid}` → JSON-serialized `OAuthClient`
//! - **OAuth code**: `oauth:code:{sha256_hex}` → JSON-serialized code
//! - **Realm primary**: `realm:id:{uuid}` → JSON-serialized `Realm` (system realm scope)
//! - **Realm signing key**: `realm:key:{uuid}` → PKCS#8 DER bytes (system realm scope)
//! - **DPoP JTI replay cache**: `agt:dpop:jti:{jti}` → 8-byte LE i64 expiry (Unix seconds)
//! - **DPoP nonce secret**: `agt:dpop:nonce-secret` → 32 raw bytes (HMAC-SHA256 key, per realm)
//!
//! Scan prefix `usr:id:` enables listing all users in a realm.

use crate::core::{
    AgentCredentialId, AgentId, ClientId, IdpId, InvitationId, OrganizationId, RealmId,
    ResourceServerId, SessionId, UserId, WebhookId,
};

// ───────────────────────────────────────────────────────────────────────
// ssv: (session-version) key namespace
// Kept separate from ses: so the hot-path session lookup is unaffected.
// ───────────────────────────────────────────────────────────────────────

/// Prefix for per-session version counters.
///
/// Format: `ssv:sid:{session_uuid}` → 8 bytes little-endian u64
const SSV_SESSION_PREFIX: &str = "ssv:sid:";

/// Key for the realm-scoped monotonic bump-sequence counter.
///
/// Format: `ssv:seq` → 8 bytes little-endian u64
const SSV_SEQ_KEY: &str = "ssv:seq";

/// Prefix for delta log entries (append-only, TTL-bounded).
///
/// Format: `ssv:delta:{seq:020}` → JSON `SvDeltaEntry`
const SSV_DELTA_PREFIX: &str = "ssv:delta:";

/// Prefix for user primary keys.
const USER_ID_PREFIX: &str = "usr:id:";

/// Prefix for user email index keys.
const USER_EMAIL_PREFIX: &str = "usr:email:";

/// Prefix for user credential keys.
const CREDENTIAL_PREFIX: &str = "cred:user:";

/// Prefix for credential history keys.
const CREDENTIAL_HISTORY_PREFIX: &str = "cred:history:";

/// Prefix for OAuth client keys.
const OAUTH_CLIENT_PREFIX: &str = "oauth:client:";

/// Prefix for OAuth authorization code keys (stored by hash).
const OAUTH_CODE_PREFIX: &str = "oauth:code:";

/// Prefix for realm primary keys (stored under system realm).
const REALM_ID_PREFIX: &str = "realm:id:";

/// Prefix for realm signing key storage (stored under system realm).
const REALM_KEY_PREFIX: &str = "realm:key:";

/// Prefix for realm name index (stored under system realm).
const REALM_NAME_PREFIX: &str = "realm:name:";

/// Prefix for grant family storage (refresh token rotation).
const GRANT_FAMILY_PREFIX: &str = "oauth:family:";

/// Prefix for session → grant-family secondary index.
///
/// Format: `oauth:session_fam:{session_uuid}:{family_id}` — empty value.
/// Written at grant family creation; scanned during session revocation for
/// cascade refresh-token family invalidation.
const SESSION_GRANT_FAMILY_PREFIX: &str = "oauth:session_fam:";

/// Prefix for device authorization code storage.
const DEVICE_CODE_PREFIX: &str = "oauth:device:";

/// Prefix for user code to device code mapping.
const USER_CODE_PREFIX: &str = "oauth:ucode:";

/// Prefix for revoked token JTI storage (sessionless token revocation).
const REVOKED_JTI_PREFIX: &str = "oauth:revjti:";

/// Prefix for JWT bearer assertion JTI replay store (RFC 7523).
const JWT_BEARER_JTI_PREFIX: &str = "oauth:jb-jti:";

/// Prefix for `private_key_jwt` client assertion JTI replay store (RFC 7523 §2.2).
const CLIENT_ASSERTION_JTI_PREFIX: &str = "oauth:ca-jti:";

/// Prefix for JAR (RFC 9101) signed request object JTI replay store.
const JAR_JTI_PREFIX: &str = "oauth:jar-jti:";

/// Prefix for OAuth consent record storage.
const OAUTH_CONSENT_PREFIX: &str = "oauth:consent:";

/// Prefix for OAuth pending-authorization ticket storage.
///
/// Holds in-flight browser authorization requests awaiting consent, keyed
/// by an opaque ticket UUID. Short-TTL (10 minutes) and single-use — the
/// analog of `oauth:device:` for the browser flow.
const OAUTH_PENDING_AUTH_PREFIX: &str = "oauth:pending_auth:";

/// Prefix for MFA TOTP state per user.
const MFA_TOTP_PREFIX: &str = "mfa:totp:";

/// Storage key for the per-realm MFA at-rest DEK.
///
/// A 32-byte random key stored in the realm namespace, KEK-wrapped when a
/// `key_encryption_key` is configured.  Completely independent of the signing
/// key so that signing-key rotation cannot invalidate existing TOTP blobs
/// (HEA-1724).
const MFA_DEK_KEY: &str = "mfa:dek:key";

/// Prefix for burned MFA pending cookie nonces.
///
/// Format: `mfa:nonce:{nonce_b64url}` → 8-byte LE u64 Unix-second expiry.
/// Written at the moment a pending cookie is successfully consumed; read to
/// detect replay on subsequent submits with the same cookie. Entries are
/// self-expiring: the stored timestamp lets startup pruning skip dead entries.
const MFA_NONCE_PREFIX: &str = "mfa:nonce:";

/// Prefix for `WebAuthn` credential storage.
const WEBAUTHN_CRED_PREFIX: &str = "webauthn:cred:";

/// Prefix for `WebAuthn` discoverable credential index.
const WEBAUTHN_DISC_PREFIX: &str = "webauthn:disc:";

/// Prefix for magic link token storage (stored by SHA-256 hash of token).
const MAGIC_LINK_PREFIX: &str = "magic:link:";

/// Prefix for email verification token storage (stored by SHA-256 hash).
const EMAIL_VERIFY_PREFIX: &str = "email:verify:";

/// Prefix for deleted-account email reservations (A-20).
///
/// Format: `email:reserved:{normalized_email}`
///
/// Written on `delete_user`; read in `create_user_with_status` to enforce the
/// 90-day re-registration cooldown. The value is a JSON `StoredEmailReservation`.
const EMAIL_RESERVED_PREFIX: &str = "email:reserved:";

/// Prefix for pending email-change tokens (A-19).
///
/// Format: `email:change:{sha256_hex_of_token}`
///
/// Written by `initiate_email_change`; consumed (and deleted) by
/// `confirm_email_change`. The plaintext token is never stored.
const EMAIL_CHANGE_TOKEN_PREFIX: &str = "email:change:";

/// Prefix for password reset token storage (stored by SHA-256 hash).
const PASSWORD_RESET_PREFIX: &str = "rst:token:";

/// Prefix for organization primary keys.
const ORG_ID_PREFIX: &str = "org:id:";

/// Prefix for organization slug uniqueness index.
const ORG_SLUG_PREFIX: &str = "org:slug:";

/// Prefix for membership by org (org → user direction).
const ORGM_ORG_PREFIX: &str = "orgm:org:";

/// Prefix for membership by user (user → org direction).
const ORGM_USER_PREFIX: &str = "orgm:user:";

/// Prefix for invitation primary keys.
const ORGI_ID_PREFIX: &str = "orgi:id:";

/// Prefix for invitation token lookup (hashed).
const ORGI_TOKEN_PREFIX: &str = "orgi:token:";

/// Prefix for invitation dedup by org+email.
const ORGI_ORG_PREFIX: &str = "orgi:org:";

/// Prefix for listing invitations by org.
const ORGI_LIST_PREFIX: &str = "orgi:list:";

/// Prefix for external Identity Provider connector records (per realm).
///
/// Holds `IdpConfig` JSON reconciled from YAML. Keyed by `IdpId` to
/// preserve connector identity across reconciliation cycles (so existing
/// `fed:ext:*` account links survive config edits).
const FED_IDP_PREFIX: &str = "fed:idp:";

/// Prefix for short-lived federation login state.
///
/// Holds the `StateBag` (nonce, PKCE verifier, return_to, realm, idp_id)
/// for an in-flight `begin` → `callback` round trip. 10-minute TTL;
/// single-use — `take_federation_state` removes the entry after read.
const FED_STATE_PREFIX: &str = "fed:state:";

/// Prefix for confirm-to-link tickets.
///
/// Holds the pending external identity awaiting local-account
/// re-authentication, in the `link_existing_accounts: confirm` flow.
/// HMAC-bound to the matched user; single-use; 10-minute TTL.
const FED_CONFIRM_PREFIX: &str = "fed:confirm:";

/// Prefix for WAL-persisted per-user login-failure attempt trackers.
///
/// Format: `rl:user:{user_uuid}`
/// Storage is already realm-scoped via the `StorageEngine` realm handle,
/// so no realm UUID is embedded in the key.
const ATTEMPT_TRACKER_PREFIX: &str = "rl:user:";

/// Prefix for WAL-persisted per-IP login rate-limit counters.
///
/// Format: `rl:ip-login:{ip}` — realm-scoped via `StorageEngine` handle.
const IP_LOGIN_TRACKER_PREFIX: &str = "rl:ip-login:";

/// Prefix for WAL-persisted per-user MFA failed-attempt trackers.
///
/// Format: `rl:mfa:{user_uuid}` — realm-scoped via `StorageEngine` handle.
const MFA_TRACKER_PREFIX: &str = "rl:mfa:";

/// Prefix for WAL-persisted per-email magic-link request rate-limit counters.
///
/// Format: `rl:rml:{email}` — realm-scoped via `StorageEngine` handle.
const MAGIC_LINK_RL_PREFIX: &str = "rl:rml:";

/// Prefix for WAL-persisted per-email password-reset request rate-limit counters.
///
/// Format: `rl:rpwreset:{email}` — realm-scoped via `StorageEngine` handle.
const PASSWORD_RESET_RL_PREFIX: &str = "rl:rpwreset:";

/// Prefix for WAL-persisted per-email registration rate-limit counters.
///
/// Format: `rl:rreg-email:{email}` — realm-scoped via `StorageEngine` handle.
const REGISTRATION_EMAIL_RL_PREFIX: &str = "rl:rreg-email:";

/// Prefix for `prompt=none` silent-auth probe counters (A-37).
///
/// Format: `rl:prompt_none:{user_uuid}`
///
/// Realm-scoped (via the `StorageEngine` handle). Counts `prompt=none`
/// authorize attempts per subject within a sliding window; enforced in
/// `authorize_get_impl` before code issuance.
const PROMPT_NONE_TRACKER_PREFIX: &str = "rl:prompt_none:";

/// Prefix for the reverse external-identity → user index.
///
/// Keyed by `(realm, idp_id, external_sub)`. Primary lookup on every
/// federation login — O(1) resolution of "which Hearth user owns this
/// upstream identity?"
const FED_EXT_PREFIX: &str = "fed:ext:";

/// Prefix for the forward user → external-identity index.
///
/// Keyed by `(realm, user_id, idp_id)`. Used for `/ui/account/linked-accounts`
/// enumeration and for cascade cleanup in `delete_user`. Value is the
/// `external_sub` string.
const FED_EXT_FWD_PREFIX: &str = "fed:ext_fwd:";

/// Prefix for retiring Ed25519 signing keys during a rotation grace period.
///
/// Format: `realm:retiring:{realm_uuid}:{deadline_secs:020}:{key_id}` — PKCS#8 DER bytes.
/// Stored under the system realm. The 20-digit zero-padded deadline allows
/// lexicographic ordering and prefix-scanning by realm.
const REALM_RETIRING_KEY_PREFIX: &str = "realm:retiring:";

/// Prefix for per-realm RSA signing key for SAML (stored under system realm).
///
/// Format: `realm:saml_key:{uuid}` — PKCS#8 DER bytes.
const REALM_SAML_KEY_PREFIX: &str = "realm:saml_key:";

/// Prefix for SAML registered Service Providers (per realm).
///
/// Format: `saml:sp:{sp_key}` — JSON-serialized `SamlServiceProvider`.
/// The SP key is a stable slug (from YAML) so reconciliation survives edits.
const SAML_SP_PREFIX: &str = "saml:sp:";

/// Prefix for SAML outbound-request state (SP side).
///
/// Format: `saml:state:{token}` — JSON-serialized `SamlStateBag`. 10-minute
/// TTL; single-use; HMAC-bound echo in `RelayState`.
const SAML_STATE_PREFIX: &str = "saml:state:";

/// Prefix for SAML assertion-ID replay sentinels (SP side).
///
/// Format: `saml:asn:{idp_uuid}:{assertion_id}` — empty value. TTL equals
/// the assertion's `NotOnOrAfter - now`; duplicates are replay attacks.
const SAML_ASSERTION_PREFIX: &str = "saml:asn:";

/// Prefix for SAML IdP-issued session → SP registration (IdP side).
///
/// Format: `saml:sp_session:{session_uuid}:{sp_key}` — JSON-serialized
/// `SamlSessionRegistration`. Used for SLO fan-out: when a user logs out
/// at Hearth (acting as IdP), we find all SPs that consumed an assertion
/// for that session and propagate `LogoutRequest`s.
const SAML_SP_SESSION_PREFIX: &str = "saml:sp_session:";

/// Prefix for SAML in-flight logout state.
///
/// Format: `saml:logout:{token}` — JSON-serialized `SamlLogoutStateBag`.
/// Matches the SP-side / IdP-side logout round-trip (LogoutRequest sent →
/// LogoutResponse received). 5-minute TTL; single-use.
#[allow(dead_code)]
const SAML_LOGOUT_STATE_PREFIX: &str = "saml:logout:";

/// Prefix for the SCIM `externalId` → Hearth `UserId` index.
///
/// Format: `scim:ext_user:{external_id}` — value is the stringified
/// `UserId` UUID. External IDs are supplied by the SCIM client (IdP) for
/// idempotent provisioning; enforced unique per realm.
const SCIM_EXT_USER_PREFIX: &str = "scim:ext_user:";

/// Prefix for the reverse Hearth `UserId` → SCIM `externalId` index.
///
/// Format: `scim:ext_user_fwd:{user_uuid}` — value is the external ID.
/// Maintained in lockstep with `scim:ext_user:*` so cascade cleanup on
/// `delete_user` doesn't require scanning the forward space.
const SCIM_EXT_USER_FWD_PREFIX: &str = "scim:ext_user_fwd:";

/// Prefix for the SCIM `externalId` → Hearth `OrganizationId` index.
///
/// Format: `scim:ext_group:{external_id}` — value is the stringified
/// `OrganizationId` UUID.
const SCIM_EXT_GROUP_PREFIX: &str = "scim:ext_group:";

/// Prefix for the reverse Hearth `OrganizationId` → SCIM `externalId` index.
///
/// Format: `scim:ext_group_fwd:{org_uuid}` — value is the external ID.
const SCIM_EXT_GROUP_FWD_PREFIX: &str = "scim:ext_group_fwd:";

/// Prefix for session primary keys.
const SESSION_ID_PREFIX: &str = "ses:id:";

/// Key for the persisted configuration snapshot (stored under the system realm).
///
/// Written atomically on each successful startup after reconciliation.
/// Read on the next startup to compute a `ConfigDiff` and drive migration
/// handlers. The `v1` suffix is part of the key so a future format change
/// can write a `config:snapshot:v2` in parallel without invalidating old nodes.
const CONFIG_SNAPSHOT_KEY: &str = "config:snapshot:v1";

/// Prefix for user-to-sessions index keys.
const SESSION_USER_PREFIX: &str = "ses:user:";

/// Prefix for device-fingerprint records.
///
/// Format: `dfp:user:{user_uuid}:{hmac_hex}` → 8-byte little-endian i64 (Unix seconds expiry).
/// Stored under the realm to which the user belongs. Scan by `dfp:user:{uuid}:` to enumerate
/// all fingerprints for one user.
const DEVICE_FP_PREFIX: &str = "dfp:user:";

/// Encodes the primary key for a user record.
///
/// Format: `usr:id:{uuid}`
pub(crate) fn encode_user_id(user_id: &UserId) -> Vec<u8> {
    format!("{USER_ID_PREFIX}{}", user_id.as_uuid()).into_bytes()
}

/// Encodes the email index key for a user.
///
/// Format: `usr:email:{normalized_email}`
///
/// The email must already be normalized (lowercase, trimmed, NFC)
/// before calling this function.
pub(crate) fn encode_user_email(email: &str) -> Vec<u8> {
    format!("{USER_EMAIL_PREFIX}{email}").into_bytes()
}

/// Encodes the *value* stored under an email-index key: 16 raw UUID bytes.
///
/// This is the single canonical writer for the `usr:email:` index value.
/// Every site that populates the index MUST go through it — HEA-1896 changed
/// only the `create_user` writer to raw bytes and left three others emitting
/// a 36-char hyphenated string, which broke `get_user_by_email` for every
/// affected user (HEA-1902).
pub(crate) fn encode_user_id_value(user_id: &UserId) -> Vec<u8> {
    user_id.as_uuid().as_bytes().to_vec()
}

/// Decodes a user id previously written by [`encode_user_id_value`].
///
/// Returns `None` if `bytes` is neither the canonical 16-byte form nor a
/// hyphenated UUID string. The string form is accepted only to heal index
/// entries written during the mixed-format window on this branch; new writes
/// are always canonical.
pub(crate) fn decode_user_id_value(bytes: &[u8]) -> Option<UserId> {
    if let Ok(uuid) = uuid::Uuid::from_slice(bytes) {
        return Some(UserId::new(uuid));
    }
    let text = std::str::from_utf8(bytes).ok()?;
    uuid::Uuid::parse_str(text).ok().map(UserId::new)
}

/// Returns the scan prefix for listing all user records.
///
/// Format: `usr:id:`
#[allow(dead_code)]
pub(crate) fn user_id_scan_prefix() -> Vec<u8> {
    USER_ID_PREFIX.as_bytes().to_vec()
}

/// Encodes the credential key for a user.
///
/// Format: `cred:user:{uuid}`
pub(crate) fn encode_credential_key(user_id: &UserId) -> Vec<u8> {
    format!("{CREDENTIAL_PREFIX}{}", user_id.as_uuid()).into_bytes()
}

/// Key for the large-scale demo seeder's per-realm sentinel.
const DEMO_SEED_COUNT_KEY: &str = "demo:seed:count";

/// Encodes the demo-seeder sentinel key.
///
/// Format: `demo:seed:count` → number of synthetic demo users seeded so far,
/// stored as decimal ASCII. Read on each reconcile to make seeding idempotent
/// and resumable: only users above this count are created. Stored under the
/// realm namespace, so it is inherently per-realm.
pub(crate) fn encode_demo_seed_count() -> Vec<u8> {
    DEMO_SEED_COUNT_KEY.as_bytes().to_vec()
}

/// Scan prefix for all credential records in a realm.
pub(crate) fn credential_scan_prefix() -> Vec<u8> {
    CREDENTIAL_PREFIX.as_bytes().to_vec()
}

/// Encodes the credential history key for a user.
///
/// Format: `cred:history:{uuid}`
pub(crate) fn encode_credential_history_key(user_id: &UserId) -> Vec<u8> {
    format!("{CREDENTIAL_HISTORY_PREFIX}{}", user_id.as_uuid()).into_bytes()
}

/// Encodes the primary key for a session record.
///
/// Format: `ses:id:{uuid}`
pub(crate) fn encode_session_id(session_id: &SessionId) -> Vec<u8> {
    format!("{SESSION_ID_PREFIX}{}", session_id.as_uuid()).into_bytes()
}

/// Encodes the user-to-session index key.
///
/// Format: `ses:user:{user_uuid}:{session_uuid}`
///
/// This enables prefix-scanning all sessions for a user (e.g., for cascade delete).
pub(crate) fn encode_user_session(user_id: &UserId, session_id: &SessionId) -> Vec<u8> {
    format!(
        "{SESSION_USER_PREFIX}{}:{}",
        user_id.as_uuid(),
        session_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for listing all sessions belonging to a user.
///
/// Format: `ses:user:{user_uuid}:`
pub(crate) fn encode_user_sessions_prefix(user_id: &UserId) -> Vec<u8> {
    format!("{SESSION_USER_PREFIX}{}:", user_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for listing all sessions in a realm.
///
/// Format: `ses:id:`
pub(crate) fn session_id_scan_prefix() -> Vec<u8> {
    SESSION_ID_PREFIX.as_bytes().to_vec()
}

/// Computes the exclusive end bound for a prefix scan.
///
/// Increments the last byte of the prefix.
#[allow(dead_code)]
pub(crate) fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

/// Returns the scan prefix for listing all OAuth clients.
///
/// Format: `oauth:client:`
pub(crate) fn oauth_client_scan_prefix() -> Vec<u8> {
    OAUTH_CLIENT_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for an OAuth client.
///
/// Format: `oauth:client:{client_id_uuid}`
pub(crate) fn encode_oauth_client(client_id: &ClientId) -> Vec<u8> {
    format!("{OAUTH_CLIENT_PREFIX}{}", client_id.as_uuid()).into_bytes()
}

/// Encodes the storage key for an OAuth authorization code.
///
/// The code is stored by its SHA-256 hex digest, not the raw code value.
/// Format: `oauth:code:{sha256_hex}`
pub(crate) fn encode_oauth_code(code_hash: &str) -> Vec<u8> {
    format!("{OAUTH_CODE_PREFIX}{code_hash}").into_bytes()
}

/// Returns the scan prefix for all OAuth authorization codes.
///
/// Format: `oauth:code:`
pub(crate) fn oauth_code_scan_prefix() -> Vec<u8> {
    OAUTH_CODE_PREFIX.as_bytes().to_vec()
}

// ===== Realm key encoding =====

/// The well-known system `RealmId`.
///
/// Uses the nil UUID (`00000000-0000-0000-0000-000000000000`) as a
/// reserved namespace. Real realms use random v4 UUIDs and will never
/// collide with this.
///
/// Historically this realm held only Hearth-owned metadata (realm
/// records, per-realm signing keys). It is now **also the home of all
/// Hearth administrator users**: admins authenticate against this
/// realm, and RBAC role assignments (at the `rba:` key prefix) live
/// here as well. Operators
/// administer application realms via a `TargetRealm` parameter (see
/// `src/protocol/web/auth.rs`) while their session always belongs to
/// the system realm.
///
/// The system realm is deliberately invisible on public surfaces:
/// [`EmbeddedIdentityEngine::list_realms`] filters it out,
/// [`EmbeddedIdentityEngine::get_realm_by_name`] returns `None` for
/// the reserved name, and YAML `realms:` blocks reject it at parse
/// time. Operators cannot target it via API; it is managed entirely
/// by the server.
pub(crate) fn system_realm_id() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

/// Reserved name for the invisible system realm. YAML `realms:` may
/// not declare it; `get_realm_by_name` filters it; admin UI realm
/// switchers skip it.
pub(crate) const SYSTEM_REALM_NAME: &str = "system";

/// Returns `true` when the given `RealmId` is the reserved system
/// realm (nil UUID). Use this at every API boundary that accepts a
/// `RealmId` from operator input to guard against accidental writes
/// to Hearth's internal realm.
pub(crate) fn is_system_realm(realm_id: &RealmId) -> bool {
    *realm_id == system_realm_id()
}

/// Encodes the primary key for a realm record.
///
/// Format: `realm:id:{uuid}`
///
/// Stored under the system realm namespace.
pub(crate) fn encode_realm_id(realm_id: &RealmId) -> Vec<u8> {
    format!("{REALM_ID_PREFIX}{}", realm_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for listing all realm records.
///
/// Format: `realm:id:`
#[allow(dead_code)]
pub(crate) fn realm_id_scan_prefix() -> Vec<u8> {
    REALM_ID_PREFIX.as_bytes().to_vec()
}

/// Encodes the name index key for a realm.
///
/// Format: `realm:name:{name}`
///
/// Stored under the system realm namespace.
pub(crate) fn encode_realm_name(name: &str) -> Vec<u8> {
    format!("{REALM_NAME_PREFIX}{name}").into_bytes()
}

/// Encodes the storage key for a realm's signing key material.
///
/// Format: `realm:key:{uuid}`
///
/// Stored under the system realm namespace.
pub(crate) fn encode_realm_signing_key(realm_id: &RealmId) -> Vec<u8> {
    format!("{REALM_KEY_PREFIX}{}", realm_id.as_uuid()).into_bytes()
}

/// Storage key for the server-wide global (Phase 0) fallback signing key.
///
/// Distinct from per-realm keys (`realm:key:{uuid}`). Stored under the system
/// realm namespace so it is co-located with other system-scoped data.
pub(crate) fn encode_global_signing_key() -> Vec<u8> {
    b"sys:global:key".to_vec()
}

/// Storage key for the server-wide OIDC RSA-2048 signing key.
///
/// Format: `sys:oidc:rsa:key` — JSON `{"pkcs8": [...], "cert": [...]}`.
/// Stored under the system realm. Generated once on first JWKS request and
/// persisted so the `kid` survives restarts (HEA-1655).
pub(crate) fn encode_oidc_rsa_key() -> Vec<u8> {
    b"sys:oidc:rsa:key".to_vec()
}

/// Storage key for a retiring OIDC RSA key during its grace window.
///
/// Format: `sys:oidc:rsa:retiring:{deadline_secs:020}:{kid}`
///
/// `deadline_secs` is zero-padded to 20 digits so lexicographic order
/// matches time order, enabling efficient range scan.
/// Stored under the system realm.
///
/// Called by the OIDC RSA key-rotation function (and by tests). Suppressing
/// `dead_code` because the production write-path (rotation) is a follow-up.
#[allow(dead_code)]
pub(crate) fn encode_oidc_rsa_retiring_key(deadline_secs: u64, kid: &str) -> Vec<u8> {
    format!("sys:oidc:rsa:retiring:{deadline_secs:020}:{kid}").into_bytes()
}

/// Scan prefix for all retiring OIDC RSA keys.
///
/// Used to enumerate grace-window keys for inclusion in JWKS.
pub(crate) fn oidc_rsa_retiring_scan_prefix() -> Vec<u8> {
    b"sys:oidc:rsa:retiring:".to_vec()
}

/// Parses the deadline (Unix seconds) from a retiring OIDC RSA storage key.
///
/// Expected format: `sys:oidc:rsa:retiring:{deadline:020}:{kid}`.
/// Returns `None` when the key does not match.
pub(crate) fn parse_oidc_rsa_retiring_deadline(key_bytes: &[u8]) -> Option<u64> {
    const PREFIX: &str = "sys:oidc:rsa:retiring:";
    let s = std::str::from_utf8(key_bytes).ok()?;
    let after = s.strip_prefix(PREFIX)?;
    // First 20 characters are the zero-padded deadline.
    let deadline_str = after.get(..20)?;
    deadline_str.parse::<u64>().ok()
}

/// Encodes the storage key for a retiring realm signing key.
///
/// Format: `realm:retiring:{realm_uuid}:{deadline_secs:020}:{key_id}`
///
/// `deadline_secs` is zero-padded to 20 digits so lexicographic order
/// matches time order, enabling efficient range-delete when purging.
/// Stored under the system realm.
pub(crate) fn encode_realm_retiring_key(
    realm_id: &RealmId,
    deadline_secs: u64,
    key_id: &str,
) -> Vec<u8> {
    format!(
        "{REALM_RETIRING_KEY_PREFIX}{}:{:020}:{key_id}",
        realm_id.as_uuid(),
        deadline_secs
    )
    .into_bytes()
}

/// Returns the inclusive scan-start prefix for all retiring keys of a realm.
///
/// Format: `realm:retiring:{realm_uuid}:`
pub(crate) fn realm_retiring_key_scan_prefix(realm_id: &RealmId) -> Vec<u8> {
    format!("{REALM_RETIRING_KEY_PREFIX}{}:", realm_id.as_uuid()).into_bytes()
}

/// Parses the deadline (Unix seconds) encoded in a retiring-key storage key.
///
/// The key is expected to follow the format produced by
/// [`encode_realm_retiring_key`]. Returns `None` when the key does not match
/// the expected format.
pub(crate) fn parse_retiring_key_deadline(key_bytes: &[u8]) -> Option<u64> {
    let key_str = std::str::from_utf8(key_bytes).ok()?;
    // key format: "realm:retiring:{uuid}:{deadline:020}:{kid}"
    // After the prefix comes "{uuid}:", then the deadline field, then ":{kid}"
    let after_prefix = key_str.strip_prefix(REALM_RETIRING_KEY_PREFIX)?;
    // Skip the UUID segment (36 chars) + ":"
    let after_uuid = after_prefix.get(37..)?;
    // Deadline is the next 20 chars
    let deadline_str = after_uuid.get(..20)?;
    deadline_str.parse::<u64>().ok()
}

/// Returns `true` when `key` holds raw cryptographic material (private keys,
/// HMAC secrets) that MUST NOT appear in admin exports or storage scans.
///
/// Covered prefixes / exact keys:
/// - `realm:key:*`           — per-realm Ed25519 signing keys (PKCS#8 DER)
/// - `realm:retiring:*`      — retiring per-realm Ed25519 signing keys
/// - `realm:saml_key:*`      — per-realm SAML signing keys
/// - `sys:global:key`        — server-wide Phase-0 fallback signing key
/// - `sys:oidc:rsa:key`      — server-wide OIDC RSA-2048 signing key
/// - `sys:oidc:rsa:retiring:*` — retiring OIDC RSA keys
/// - `agt:dpop:nonce-secret` — per-realm DPoP nonce HMAC secret
#[cfg(any(test, feature = "test-hooks"))]
pub(crate) fn is_key_material(key: &[u8]) -> bool {
    key.starts_with(REALM_KEY_PREFIX.as_bytes())
        || key.starts_with(REALM_RETIRING_KEY_PREFIX.as_bytes())
        || key.starts_with(REALM_SAML_KEY_PREFIX.as_bytes())
        || key.starts_with(b"sys:oidc:rsa:retiring:")
        || key == b"sys:global:key"
        || key == b"sys:oidc:rsa:key"
        || key == DPOP_NONCE_SECRET_KEY.as_bytes()
}

/// Encodes the storage key for a grant family (refresh token rotation).
///
/// Format: `oauth:family:{family_id}`
pub(crate) fn encode_grant_family(family_id: &str) -> Vec<u8> {
    format!("{GRANT_FAMILY_PREFIX}{family_id}").into_bytes()
}

/// Returns the scan prefix for all grant families.
///
/// Format: `oauth:family:`
#[allow(dead_code)]
pub(crate) fn grant_family_scan_prefix() -> Vec<u8> {
    GRANT_FAMILY_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a device authorization code.
///
/// Format: `oauth:device:{device_code_hash}`
pub(crate) fn encode_device_code(device_code_hash: &str) -> Vec<u8> {
    format!("{DEVICE_CODE_PREFIX}{device_code_hash}").into_bytes()
}

/// Returns the scan prefix for all device codes.
///
/// Format: `oauth:device:`
#[allow(dead_code)]
pub(crate) fn device_code_scan_prefix() -> Vec<u8> {
    DEVICE_CODE_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a user code to device code mapping.
///
/// Format: `oauth:ucode:{user_code}`
pub(crate) fn encode_user_code(user_code: &str) -> Vec<u8> {
    format!("{USER_CODE_PREFIX}{user_code}").into_bytes()
}

/// Returns the scan prefix for all user codes.
///
/// Format: `oauth:ucode:`
#[allow(dead_code)]
pub(crate) fn user_code_scan_prefix() -> Vec<u8> {
    USER_CODE_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a user's MFA TOTP state.
///
/// Format: `mfa:totp:{user_uuid}`
pub(crate) fn encode_mfa_totp_key(user_id: &UserId) -> Vec<u8> {
    format!("{MFA_TOTP_PREFIX}{}", user_id.as_uuid()).into_bytes()
}

/// Returns the scan-start prefix for all MFA TOTP blobs in a realm.
///
/// Used by `rotate_realm_signing_key` to enumerate blobs for re-encryption.
#[allow(dead_code)]
pub(crate) fn mfa_totp_scan_prefix() -> Vec<u8> {
    MFA_TOTP_PREFIX.as_bytes().to_vec()
}

/// Returns the storage key for the per-realm MFA at-rest DEK.
///
/// Value is a 32-byte random key, KEK-wrapped when configured (HEA-1724).
pub(crate) fn mfa_dek_key() -> Vec<u8> {
    MFA_DEK_KEY.as_bytes().to_vec()
}

/// Encodes the storage key for a burned MFA pending cookie nonce.
///
/// Format: `mfa:nonce:{nonce_b64url}`
///
/// The value is an 8-byte little-endian `u64` Unix-second expiry. Entries
/// remain in storage until realm deletion or an explicit pruning pass; the
/// stored expiry allows callers to skip stale entries cheaply.
pub(crate) fn encode_mfa_nonce_key(nonce: &str) -> Vec<u8> {
    format!("{MFA_NONCE_PREFIX}{nonce}").into_bytes()
}

/// Encodes the storage key for a `WebAuthn` credential.
///
/// Format: `webauthn:cred:{user_uuid}:{credential_id_b64url}`
///
/// Supports prefix scanning all credentials for a user.
pub(crate) fn encode_webauthn_credential(user_id: &UserId, credential_id_b64: &str) -> Vec<u8> {
    format!(
        "{WEBAUTHN_CRED_PREFIX}{}:{credential_id_b64}",
        user_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for listing all `WebAuthn` credentials for a user.
///
/// Format: `webauthn:cred:{user_uuid}:`
pub(crate) fn encode_webauthn_credentials_prefix(user_id: &UserId) -> Vec<u8> {
    format!("{WEBAUTHN_CRED_PREFIX}{}:", user_id.as_uuid()).into_bytes()
}

/// Encodes the discoverable credential index key.
///
/// Format: `webauthn:disc:{credential_id_b64url}`
///
/// Maps a credential ID to a user UUID for username-less authentication.
pub(crate) fn encode_webauthn_discoverable(credential_id_b64: &str) -> Vec<u8> {
    format!("{WEBAUTHN_DISC_PREFIX}{credential_id_b64}").into_bytes()
}

/// Encodes the storage key for a magic link token.
///
/// Format: `magic:link:{sha256_hex_of_token}`
///
/// The token hash is the SHA-256 hex digest of the plaintext token.
/// The plaintext is never stored.
pub(crate) fn encode_magic_link_token(token_hash: &str) -> Vec<u8> {
    format!("{MAGIC_LINK_PREFIX}{token_hash}").into_bytes()
}

/// Returns the scan prefix for all magic link tokens in a realm.
///
/// Used by `request_magic_link` to invalidate prior tokens for the same email
/// (HSS-008). Pair with `storage::prefix_scan_end` to get the half-open range.
pub(crate) fn magic_link_token_scan_prefix() -> Vec<u8> {
    MAGIC_LINK_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for an email verification token.
///
/// Format: `email:verify:{sha256_hex_of_token}`
///
/// The token hash is the SHA-256 hex digest of the plaintext token.
/// The plaintext is never stored.
pub(crate) fn encode_email_verify_token(token_hash: &str) -> Vec<u8> {
    format!("{EMAIL_VERIFY_PREFIX}{token_hash}").into_bytes()
}

/// Encodes the storage key for a deleted-account email reservation (A-20).
///
/// Format: `email:reserved:{normalized_email}`
///
/// Written by `delete_user` to enforce a 90-day re-registration cooldown.
/// Read by `create_user_with_status` before accepting a new registration.
pub(crate) fn encode_email_reserved(email: &str) -> Vec<u8> {
    format!("{EMAIL_RESERVED_PREFIX}{email}").into_bytes()
}

/// Encodes the storage key for a pending email-change token (A-19).
///
/// Format: `email:change:{sha256_hex_of_token}`
///
/// Written by `initiate_email_change`; consumed by `confirm_email_change`.
/// The plaintext token is never stored — only its SHA-256 digest.
pub(crate) fn encode_email_change_token(token_hash: &str) -> Vec<u8> {
    format!("{EMAIL_CHANGE_TOKEN_PREFIX}{token_hash}").into_bytes()
}

/// Encodes the storage key for a password reset token.
///
/// Format: `rst:token:{sha256_hex_of_token}`
///
/// The token hash is the SHA-256 hex digest of the plaintext token.
/// The plaintext is never stored.
pub(crate) fn encode_password_reset_token(token_hash: &str) -> Vec<u8> {
    format!("{PASSWORD_RESET_PREFIX}{token_hash}").into_bytes()
}

/// Returns the scan prefix for password reset tokens (cascade deletion).
///
/// Format: `rst:token:`
#[allow(dead_code)]
pub(crate) fn password_reset_scan_prefix() -> Vec<u8> {
    PASSWORD_RESET_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a revoked token JTI.
///
/// Format: `oauth:revjti:{jti}`
///
/// Used for revoking sessionless tokens (e.g., `client_credentials` access tokens)
/// that cannot be revoked via session revocation.
pub(crate) fn encode_revoked_jti(jti: &str) -> Vec<u8> {
    format!("{REVOKED_JTI_PREFIX}{jti}").into_bytes()
}

/// Returns the scan prefix for all revoked OAuth JTIs in a realm.
///
/// Used at startup to populate the hot-path revocation projection and during
/// cascade realm deletion to purge the blocklist.
pub(crate) fn revoked_jti_scan_prefix() -> Vec<u8> {
    REVOKED_JTI_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a consumed JWT bearer assertion JTI.
///
/// Format: `oauth:jb-jti:{jti}`
///
/// Used for JWT bearer (RFC 7523) JTI replay prevention.  Stored per-realm;
/// survives engine restarts; pruned only on realm deletion.
pub(crate) fn encode_jwt_bearer_jti(jti: &str) -> Vec<u8> {
    format!("{JWT_BEARER_JTI_PREFIX}{jti}").into_bytes()
}

/// Encodes the storage key for a consumed `private_key_jwt` assertion JTI.
///
/// Format: `oauth:ca-jti:{jti}`
///
/// Used for RFC 7523 §2.2 `private_key_jwt` JTI replay prevention.
pub(crate) fn encode_client_assertion_jti(jti: &str) -> Vec<u8> {
    format!("{CLIENT_ASSERTION_JTI_PREFIX}{jti}").into_bytes()
}

/// Encodes the storage key for a JAR (RFC 9101) signed request object JTI.
///
/// Format: `oauth:jar-jti:{jti}`
///
/// Used for RFC 9101 §4 JAR replay prevention.
pub(crate) fn encode_jar_jti(jti: &str) -> Vec<u8> {
    format!("{JAR_JTI_PREFIX}{jti}").into_bytes()
}

/// Returns the scan prefix for all JAR JTIs in a realm.
///
/// Used during cascade realm deletion to purge the replay store.
pub(crate) fn jar_jti_scan_prefix() -> Vec<u8> {
    JAR_JTI_PREFIX.as_bytes().to_vec()
}

// ===== OAuth consent key encoding =====

/// Encodes the primary key for an OAuth consent record.
///
/// Format: `oauth:consent:{user_uuid}:{client_uuid}`
///
/// The compound key enables:
/// - O(1) lookup of a specific `(user, client)` consent.
/// - Prefix scan by user for "list my consents".
/// - Cascade delete of all consent records on user deletion.
pub(crate) fn encode_consent_key(user_id: &UserId, client_id: &ClientId) -> Vec<u8> {
    format!(
        "{OAUTH_CONSENT_PREFIX}{}:{}",
        user_id.as_uuid(),
        client_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for listing all consents granted by a user.
///
/// Format: `oauth:consent:{user_uuid}:`
pub(crate) fn encode_consent_prefix_for_user(user_id: &UserId) -> Vec<u8> {
    format!("{OAUTH_CONSENT_PREFIX}{}:", user_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all consent records in a realm.
///
/// Format: `oauth:consent:`
///
/// Used by `delete_realm` cascade and by `delete_oauth_client` cascade
/// (which then filters by the trailing `:{client_uuid}` segment).
pub(crate) fn oauth_consent_scan_prefix() -> Vec<u8> {
    OAUTH_CONSENT_PREFIX.as_bytes().to_vec()
}

/// Encodes the extended consent key for a `(user, client, org_key, resource_key)` tuple.
///
/// Format: `oauth:consent:{user_uuid}:{client_uuid}:{org_key}:{resource_key}`
///
/// - `org_key` is the org UUID string, or `"_realm"` for realm-scoped consent.
/// - `resource_key` is the resource URI, or `"_default"` when no resource indicator.
///
/// This is the preferred key for consent records created under the expanded
/// authorization model. Legacy records keyed by `encode_consent_key` remain
/// readable during migration.
pub(crate) fn encode_consent_key_extended(
    user_id: &UserId,
    client_id: &ClientId,
    org_key: &str,
    resource_key: &str,
) -> Vec<u8> {
    format!(
        "{OAUTH_CONSENT_PREFIX}{}:{}:{}:{}",
        user_id.as_uuid(),
        client_id.as_uuid(),
        org_key,
        resource_key,
    )
    .into_bytes()
}

/// The sentinel `org_key` value meaning the consent applies at realm scope
/// (i.e. not tied to a specific organization).
pub(crate) const CONSENT_ORG_KEY_REALM: &str = "_realm";

/// The sentinel `resource_key` value meaning no resource indicator was
/// supplied by the client.
pub(crate) const CONSENT_RESOURCE_KEY_DEFAULT: &str = "_default";

/// Encodes the storage key for a pending-authorization ticket.
///
/// Format: `oauth:pending_auth:{ticket_uuid}`
pub(crate) fn encode_pending_auth_key(ticket: &str) -> Vec<u8> {
    format!("{OAUTH_PENDING_AUTH_PREFIX}{ticket}").into_bytes()
}

/// Returns the scan prefix for all pending-authorization tickets.
///
/// Format: `oauth:pending_auth:`
pub(crate) fn oauth_pending_auth_scan_prefix() -> Vec<u8> {
    OAUTH_PENDING_AUTH_PREFIX.as_bytes().to_vec()
}

// ===== Organization key encoding =====

/// Encodes the primary key for an organization record.
///
/// Format: `org:id:{uuid}`
pub(crate) fn encode_org_id(org_id: &OrganizationId) -> Vec<u8> {
    format!("{ORG_ID_PREFIX}{}", org_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for listing all organizations.
///
/// Format: `org:id:`
pub(crate) fn org_id_scan_prefix() -> Vec<u8> {
    ORG_ID_PREFIX.as_bytes().to_vec()
}

/// Encodes the slug uniqueness index key.
///
/// Format: `org:slug:{slug}`
pub(crate) fn encode_org_slug(slug: &str) -> Vec<u8> {
    format!("{ORG_SLUG_PREFIX}{slug}").into_bytes()
}

/// Returns the scan prefix for all organization slug entries.
///
/// Format: `org:slug:`
#[allow(dead_code)]
pub(crate) fn org_slug_scan_prefix() -> Vec<u8> {
    ORG_SLUG_PREFIX.as_bytes().to_vec()
}

/// Encodes the membership key (org → user direction).
///
/// Format: `orgm:org:{org_uuid}:user:{user_uuid}`
pub(crate) fn encode_membership_by_org(org_id: &OrganizationId, user_id: &UserId) -> Vec<u8> {
    format!(
        "{ORGM_ORG_PREFIX}{}:user:{}",
        org_id.as_uuid(),
        user_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all members of an organization.
///
/// Format: `orgm:org:{org_uuid}:`
pub(crate) fn membership_by_org_prefix(org_id: &OrganizationId) -> Vec<u8> {
    format!("{ORGM_ORG_PREFIX}{}:", org_id.as_uuid()).into_bytes()
}

/// Encodes the reverse membership key (user → org direction).
///
/// Format: `orgm:user:{user_uuid}:org:{org_uuid}`
pub(crate) fn encode_membership_by_user(user_id: &UserId, org_id: &OrganizationId) -> Vec<u8> {
    format!(
        "{ORGM_USER_PREFIX}{}:org:{}",
        user_id.as_uuid(),
        org_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all organizations a user belongs to.
///
/// Format: `orgm:user:{user_uuid}:`
pub(crate) fn membership_by_user_prefix(user_id: &UserId) -> Vec<u8> {
    format!("{ORGM_USER_PREFIX}{}:", user_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all membership-by-org entries (realm-wide).
///
/// Format: `orgm:org:`
#[allow(dead_code)]
pub(crate) fn membership_org_scan_prefix() -> Vec<u8> {
    ORGM_ORG_PREFIX.as_bytes().to_vec()
}

/// Returns the scan prefix for all membership-by-user entries (realm-wide).
///
/// Format: `orgm:user:`
#[allow(dead_code)]
pub(crate) fn membership_user_scan_prefix() -> Vec<u8> {
    ORGM_USER_PREFIX.as_bytes().to_vec()
}

/// Encodes the primary key for an invitation record.
///
/// Format: `orgi:id:{uuid}`
pub(crate) fn encode_invitation_id(invitation_id: &InvitationId) -> Vec<u8> {
    format!("{ORGI_ID_PREFIX}{}", invitation_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all invitation records.
///
/// Format: `orgi:id:`
#[allow(dead_code)]
pub(crate) fn invitation_id_scan_prefix() -> Vec<u8> {
    ORGI_ID_PREFIX.as_bytes().to_vec()
}

/// Encodes the token lookup key for an invitation.
///
/// Format: `orgi:token:{sha256_hex}`
///
/// The token is stored as a SHA-256 hash, never as plaintext.
pub(crate) fn encode_invitation_token(token_hash: &str) -> Vec<u8> {
    format!("{ORGI_TOKEN_PREFIX}{token_hash}").into_bytes()
}

/// Returns the scan prefix for all invitation token entries.
///
/// Format: `orgi:token:`
#[allow(dead_code)]
pub(crate) fn invitation_token_scan_prefix() -> Vec<u8> {
    ORGI_TOKEN_PREFIX.as_bytes().to_vec()
}

/// Encodes the invitation dedup key (prevents duplicate invites per org+email).
///
/// Format: `orgi:org:{org_uuid}:email:{email}`
pub(crate) fn encode_invitation_org_email(org_id: &OrganizationId, email: &str) -> Vec<u8> {
    format!("{ORGI_ORG_PREFIX}{}:email:{email}", org_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all invitation dedup entries for an org.
///
/// Format: `orgi:org:{org_uuid}:`
#[allow(dead_code)]
pub(crate) fn invitation_org_prefix(org_id: &OrganizationId) -> Vec<u8> {
    format!("{ORGI_ORG_PREFIX}{}:", org_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all invitation org entries (realm-wide).
///
/// Format: `orgi:org:`
#[allow(dead_code)]
pub(crate) fn invitation_org_scan_prefix() -> Vec<u8> {
    ORGI_ORG_PREFIX.as_bytes().to_vec()
}

/// Encodes the invitation listing key (for paginated org-scoped listing).
///
/// Format: `orgi:list:{org_uuid}:{invitation_uuid}`
pub(crate) fn encode_invitation_list(
    org_id: &OrganizationId,
    invitation_id: &InvitationId,
) -> Vec<u8> {
    format!(
        "{ORGI_LIST_PREFIX}{}:{}",
        org_id.as_uuid(),
        invitation_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for listing all invitations for an org.
///
/// Format: `orgi:list:{org_uuid}:`
pub(crate) fn invitation_list_prefix(org_id: &OrganizationId) -> Vec<u8> {
    format!("{ORGI_LIST_PREFIX}{}:", org_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all invitation list entries (realm-wide).
///
/// Format: `orgi:list:`
#[allow(dead_code)]
pub(crate) fn invitation_list_scan_prefix() -> Vec<u8> {
    ORGI_LIST_PREFIX.as_bytes().to_vec()
}

// ===== Federation key encoding =====

/// Encodes the storage key for an external IdP connector record.
///
/// Format: `fed:idp:{idp_uuid}`
///
/// Connector records are realm-scoped via the underlying `StorageEngine`;
/// no realm segment is embedded in the key because every read goes through
/// the realm handle (same convention as `oauth:client:{client_uuid}`).
pub(crate) fn encode_idp_key(idp_id: &IdpId) -> Vec<u8> {
    format!("{FED_IDP_PREFIX}{}", idp_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for listing every IdP connector in a realm.
///
/// Format: `fed:idp:`
pub(crate) fn fed_idp_scan_prefix() -> Vec<u8> {
    FED_IDP_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for an in-flight federation state record.
///
/// Format: `fed:state:{opaque_token}`
///
/// The token is an opaque random string that is echoed to the upstream
/// IdP via the OAuth `state` query parameter and verified on callback.
pub(crate) fn encode_federation_state_key(state_token: &str) -> Vec<u8> {
    format!("{FED_STATE_PREFIX}{state_token}").into_bytes()
}

/// Returns the scan prefix for federation state (for cascade cleanup).
///
/// Format: `fed:state:`
#[allow(dead_code)]
pub(crate) fn fed_state_scan_prefix() -> Vec<u8> {
    FED_STATE_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a confirm-to-link ticket.
///
/// Format: `fed:confirm:{ticket_uuid}`
///
/// Used in `link_existing_accounts: confirm` mode: after an external
/// login matches an existing local user by email, the external identity
/// is parked here while the user re-authenticates locally to prove
/// ownership of the matched account.
pub(crate) fn encode_federation_confirm_key(ticket: &str) -> Vec<u8> {
    format!("{FED_CONFIRM_PREFIX}{ticket}").into_bytes()
}

/// Returns the scan prefix for federation confirm-link tickets.
///
/// Format: `fed:confirm:`
#[allow(dead_code)]
pub(crate) fn fed_confirm_scan_prefix() -> Vec<u8> {
    FED_CONFIRM_PREFIX.as_bytes().to_vec()
}

/// Encodes the reverse external-identity → user index key.
///
/// Format: `fed:ext:{idp_uuid}:{external_sub}`
///
/// On every federation callback, Hearth asks "who owns this upstream
/// identity?" This key answers that in one lookup. The value is the
/// `UserId` UUID bytes.
///
/// The external sub is used verbatim; upstream providers commit to its
/// stability (Google: sub claim is the Google user ID; GitHub: numeric
/// user id as string; Apple: sub claim).
pub(crate) fn encode_federation_ext_key(idp_id: &IdpId, external_sub: &str) -> Vec<u8> {
    format!("{FED_EXT_PREFIX}{}:{external_sub}", idp_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for every external-identity record owned by
/// a given IdP connector.
///
/// Format: `fed:ext:{idp_uuid}:`
///
/// Used by `delete_idp` cascade to sever every link for the connector
/// without touching other connectors in the realm.
pub(crate) fn encode_federation_ext_prefix_for_idp(idp_id: &IdpId) -> Vec<u8> {
    format!("{FED_EXT_PREFIX}{}:", idp_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for every external-identity record in the realm.
///
/// Format: `fed:ext:`
///
/// Used by `delete_realm` cascade.
#[allow(dead_code)]
pub(crate) fn fed_ext_scan_prefix() -> Vec<u8> {
    FED_EXT_PREFIX.as_bytes().to_vec()
}

/// Encodes the forward user → external-identity index key.
///
/// Format: `fed:ext_fwd:{user_uuid}:{idp_uuid}`
///
/// Lets `/ui/account/linked-accounts` enumerate a user's linked IdPs in
/// a single scan, and lets `delete_user` cascade severs every reverse
/// index entry without a full-realm scan. Value is the external sub
/// (the same string used as the trailing segment of `fed:ext:*`).
pub(crate) fn encode_federation_ext_fwd_key(user_id: &UserId, idp_id: &IdpId) -> Vec<u8> {
    format!(
        "{FED_EXT_FWD_PREFIX}{}:{}",
        user_id.as_uuid(),
        idp_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for every external identity linked to a user.
///
/// Format: `fed:ext_fwd:{user_uuid}:`
pub(crate) fn encode_federation_ext_fwd_prefix_for_user(user_id: &UserId) -> Vec<u8> {
    format!("{FED_EXT_FWD_PREFIX}{}:", user_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for the realm-wide forward index.
///
/// Format: `fed:ext_fwd:`
///
/// Used by `delete_realm` cascade.
#[allow(dead_code)]
pub(crate) fn fed_ext_fwd_scan_prefix() -> Vec<u8> {
    FED_EXT_FWD_PREFIX.as_bytes().to_vec()
}

/// Encodes the SCIM `externalId` → `UserId` index key.
///
/// Format: `scim:ext_user:{external_id}` — value is the stringified
/// `UserId` UUID. Called by the SCIM layer to provide idempotent
/// provisioning: an IdP that sends the same `externalId` twice resolves
/// to the same Hearth user.
pub(crate) fn encode_scim_ext_user_key(external_id: &str) -> Vec<u8> {
    format!("{SCIM_EXT_USER_PREFIX}{external_id}").into_bytes()
}

/// Returns the scan prefix for every SCIM external-id-to-user mapping.
///
/// Format: `scim:ext_user:` — used by `delete_realm` cascade.
#[allow(dead_code)]
pub(crate) fn scim_ext_user_scan_prefix() -> Vec<u8> {
    SCIM_EXT_USER_PREFIX.as_bytes().to_vec()
}

/// Encodes the reverse `UserId` → SCIM `externalId` index key.
///
/// Format: `scim:ext_user_fwd:{user_uuid}` — value is the external id.
/// Lets `delete_user` cascade revoke the SCIM mapping in O(1) without
/// scanning the forward space.
pub(crate) fn encode_scim_ext_user_fwd_key(user_id: &UserId) -> Vec<u8> {
    format!("{SCIM_EXT_USER_FWD_PREFIX}{}", user_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for every SCIM forward index entry in a realm.
///
/// Format: `scim:ext_user_fwd:` — used by `delete_realm` cascade.
#[allow(dead_code)]
pub(crate) fn scim_ext_user_fwd_scan_prefix() -> Vec<u8> {
    SCIM_EXT_USER_FWD_PREFIX.as_bytes().to_vec()
}

/// Encodes the SCIM `externalId` → `OrganizationId` (group) index key.
///
/// Format: `scim:ext_group:{external_id}` — value is the stringified
/// `OrganizationId` UUID.
pub(crate) fn encode_scim_ext_group_key(external_id: &str) -> Vec<u8> {
    format!("{SCIM_EXT_GROUP_PREFIX}{external_id}").into_bytes()
}

/// Returns the scan prefix for every SCIM group external-id mapping.
///
/// Format: `scim:ext_group:` — used by `delete_realm` cascade.
#[allow(dead_code)]
pub(crate) fn scim_ext_group_scan_prefix() -> Vec<u8> {
    SCIM_EXT_GROUP_PREFIX.as_bytes().to_vec()
}

/// Encodes the reverse `OrganizationId` → SCIM `externalId` index key.
///
/// Format: `scim:ext_group_fwd:{org_uuid}` — value is the external id.
pub(crate) fn encode_scim_ext_group_fwd_key(org_id: &OrganizationId) -> Vec<u8> {
    format!("{SCIM_EXT_GROUP_FWD_PREFIX}{}", org_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for every SCIM group forward index entry.
///
/// Format: `scim:ext_group_fwd:` — used by `delete_realm` cascade.
#[allow(dead_code)]
pub(crate) fn scim_ext_group_fwd_scan_prefix() -> Vec<u8> {
    SCIM_EXT_GROUP_FWD_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a realm's SAML signing key (RSA-2048 PKCS#8).
///
/// Format: `realm:saml_key:{uuid}` — stored under the system realm scope,
/// parallel to the realm's Ed25519 JWT signing key at `realm:key:`.
pub(crate) fn encode_realm_saml_key(realm_id: &RealmId) -> Vec<u8> {
    format!("{REALM_SAML_KEY_PREFIX}{}", realm_id.as_uuid()).into_bytes()
}

/// Encodes the storage key for a SAML registered Service Provider.
///
/// Format: `saml:sp:{sp_key}` — the SP key is a stable slug from YAML.
pub(crate) fn encode_saml_sp_key(sp_key: &str) -> Vec<u8> {
    format!("{SAML_SP_PREFIX}{sp_key}").into_bytes()
}

/// Returns the scan prefix for every SAML SP registration in the realm.
///
/// Format: `saml:sp:` — used by reconcile and cascade cleanup.
pub(crate) fn saml_sp_scan_prefix() -> Vec<u8> {
    SAML_SP_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for SAML SP-side outbound request state.
///
/// Format: `saml:state:{opaque_token}`.
pub(crate) fn encode_saml_state_key(state_token: &str) -> Vec<u8> {
    format!("{SAML_STATE_PREFIX}{state_token}").into_bytes()
}

/// Returns the scan prefix for SAML outbound request state.
#[allow(dead_code)]
pub(crate) fn saml_state_scan_prefix() -> Vec<u8> {
    SAML_STATE_PREFIX.as_bytes().to_vec()
}

/// Encodes the SAML assertion-ID replay sentinel key.
///
/// Format: `saml:asn:{idp_uuid}:{assertion_id}`.
pub(crate) fn encode_saml_assertion_id(idp_id: &IdpId, assertion_id: &str) -> Vec<u8> {
    format!("{SAML_ASSERTION_PREFIX}{}:{assertion_id}", idp_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all SAML assertion-ID sentinels owned by an IdP.
#[allow(dead_code)]
pub(crate) fn encode_saml_assertion_prefix_for_idp(idp_id: &IdpId) -> Vec<u8> {
    format!("{SAML_ASSERTION_PREFIX}{}:", idp_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all SAML assertion sentinels in the realm.
#[allow(dead_code)]
pub(crate) fn saml_assertion_scan_prefix() -> Vec<u8> {
    SAML_ASSERTION_PREFIX.as_bytes().to_vec()
}

/// Encodes the SAML SP-session registration key (IdP side, for SLO fan-out).
///
/// Format: `saml:sp_session:{session_uuid}:{sp_key}`.
pub(crate) fn encode_saml_sp_session(session_id: &SessionId, sp_key: &str) -> Vec<u8> {
    format!("{SAML_SP_SESSION_PREFIX}{}:{sp_key}", session_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all SP registrations on a session.
pub(crate) fn encode_saml_sp_session_prefix(session_id: &SessionId) -> Vec<u8> {
    format!("{SAML_SP_SESSION_PREFIX}{}:", session_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all SP session registrations in the realm.
#[allow(dead_code)]
pub(crate) fn saml_sp_session_scan_prefix() -> Vec<u8> {
    SAML_SP_SESSION_PREFIX.as_bytes().to_vec()
}

/// Encodes the SAML logout state key.
///
/// Format: `saml:logout:{opaque_token}`.
#[allow(dead_code)]
pub(crate) fn encode_saml_logout_key(token: &str) -> Vec<u8> {
    format!("{SAML_LOGOUT_STATE_PREFIX}{token}").into_bytes()
}

/// Returns the scan prefix for SAML logout state.
#[allow(dead_code)]
pub(crate) fn saml_logout_scan_prefix() -> Vec<u8> {
    SAML_LOGOUT_STATE_PREFIX.as_bytes().to_vec()
}

/// Encodes the session → grant-family index key.
///
/// Format: `oauth:session_fam:{session_uuid}:{family_id}`.
pub(crate) fn encode_session_grant_family(session_id: &SessionId, family_id: &str) -> Vec<u8> {
    format!(
        "{SESSION_GRANT_FAMILY_PREFIX}{}:{family_id}",
        session_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all grant families on a session.
///
/// Format: `oauth:session_fam:{session_uuid}:`.
pub(crate) fn encode_session_grant_family_prefix(session_id: &SessionId) -> Vec<u8> {
    format!("{SESSION_GRANT_FAMILY_PREFIX}{}:", session_id.as_uuid()).into_bytes()
}

// ---------------------------------------------------------------------------
// Webhook keys
// ---------------------------------------------------------------------------

/// Prefix for webhook primary keys.
const WEBHOOK_ID_PREFIX: &str = "wh:id:";

/// Encodes the primary key for a webhook record.
///
/// Format: `wh:id:{uuid}`
pub(crate) fn encode_webhook_id(webhook_id: &WebhookId) -> Vec<u8> {
    format!("{WEBHOOK_ID_PREFIX}{}", webhook_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for listing all webhooks in a realm.
///
/// Format: `wh:id:`
pub(crate) fn webhook_id_scan_prefix() -> Vec<u8> {
    WEBHOOK_ID_PREFIX.as_bytes().to_vec()
}

/// Returns the storage key for the persisted configuration snapshot.
///
/// Stored under the system realm. Carry the `v1` suffix so a future
/// format change can write a `config:snapshot:v2` key without
/// invalidating nodes that haven't upgraded yet.
pub(crate) fn config_snapshot_key() -> Vec<u8> {
    CONFIG_SNAPSHOT_KEY.as_bytes().to_vec()
}

/// Prefix for orphaned-realm records under the system realm.
const CONFIG_ORPHAN_PREFIX: &str = "config:orphan:";

/// Returns the storage key for an orphaned-realm record.
///
/// Written when a realm is archived while it still contains users and no
/// `migrate_from` claim or `archive_drop` flag exists for its slug.
/// Deleted when the orphan condition is resolved.
pub(crate) fn config_orphan_key(slug: &str) -> Vec<u8> {
    format!("{CONFIG_ORPHAN_PREFIX}{slug}").into_bytes()
}

/// Returns the byte prefix used to scan all orphaned-realm keys in storage.
pub(crate) fn config_orphan_scan_prefix() -> Vec<u8> {
    CONFIG_ORPHAN_PREFIX.as_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Cross-realm migration progress keys (system realm)
// ---------------------------------------------------------------------------

/// Prefix for per-user migration progress records.
///
/// Written under the system realm as `config:migration:progress:{src_slug}:{user_uuid}` = `b"done"`.
/// Allows crash-safe idempotent resume: skip users whose marker already exists.
const CONFIG_MIGRATION_PROGRESS_PREFIX: &str = "config:migration:progress:";

/// Returns the progress key for a single migrated user.
///
/// Format: `config:migration:progress:{source_slug}:{user_uuid}`
pub(crate) fn config_migration_progress_key(source_slug: &str, user_id: &UserId) -> Vec<u8> {
    format!(
        "{CONFIG_MIGRATION_PROGRESS_PREFIX}{source_slug}:{}",
        user_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all progress keys belonging to a single migration.
///
/// Format: `config:migration:progress:{source_slug}:`
#[allow(dead_code)]
pub(crate) fn config_migration_progress_prefix(source_slug: &str) -> Vec<u8> {
    format!("{CONFIG_MIGRATION_PROGRESS_PREFIX}{source_slug}:").into_bytes()
}

/// Returns the storage key that marks an entire realm migration as complete.
///
/// Written after ALL users have been moved. Checked at startup to skip
/// re-running an already-finished migration.
///
/// Format: `config:migration:completed:{source_slug}`
pub(crate) fn config_migration_completed_key(source_slug: &str) -> Vec<u8> {
    format!("config:migration:completed:{source_slug}").into_bytes()
}

// ---------------------------------------------------------------------------
// Migration history keys (system realm)
// ---------------------------------------------------------------------------

/// Prefix for migration history records under the system realm.
const CONFIG_MIGRATION_HISTORY_PREFIX: &str = "config:migration:hist:";

/// Returns the storage key for a migration history record.
///
/// Written at the end of each cross-realm migration run (success or conflict
/// failure). A new run overwrites the previous record for the same source slug.
///
/// Format: `config:migration:hist:{source_slug}`
pub(crate) fn config_migration_history_key(source_slug: &str) -> Vec<u8> {
    format!("{CONFIG_MIGRATION_HISTORY_PREFIX}{source_slug}").into_bytes()
}

/// Returns the byte prefix used to scan all migration history records.
pub(crate) fn config_migration_history_scan_prefix() -> Vec<u8> {
    CONFIG_MIGRATION_HISTORY_PREFIX.as_bytes().to_vec()
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent key encoding (AGENT_AUTH.md §13.1)
// ─────────────────────────────────────────────────────────────────────────────

/// Prefix for agent primary keys.
///
/// Format: `agt:id:{agent_uuid}`
const AGENT_ID_PREFIX: &str = "agt:id:";

/// Prefix for the owner → agent index.
///
/// Format: `agt:owner:{owner_tag}:{owner_uuid}:{agent_uuid}` — empty value.
/// Supports prefix scanning all agents for a given owner.
const AGENT_OWNER_PREFIX: &str = "agt:owner:";

/// Encodes the primary key for an agent record.
///
/// Format: `agt:id:{agent_uuid}`
pub(crate) fn encode_agent_id(agent_id: &AgentId) -> Vec<u8> {
    format!("{AGENT_ID_PREFIX}{}", agent_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all agent records in a realm.
///
/// Format: `agt:id:`
pub(crate) fn agent_id_scan_prefix() -> Vec<u8> {
    AGENT_ID_PREFIX.as_bytes().to_vec()
}

/// Encodes the owner index key for an agent.
///
/// Format: `agt:owner:{owner_tag}:{owner_uuid}:{agent_uuid}`
///
/// `owner_tag` is `"user"` or `"org"` — enables separate prefix scans
/// by owner type if needed, while a single `agt:owner:` scan lists all.
pub(crate) fn encode_agent_owner_index(
    owner_tag: &str,
    owner_uuid: &str,
    agent_id: &AgentId,
) -> Vec<u8> {
    format!(
        "{AGENT_OWNER_PREFIX}{owner_tag}:{owner_uuid}:{}",
        agent_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all agents owned by a specific owner.
///
/// Format: `agt:owner:{owner_tag}:{owner_uuid}:`
pub(crate) fn agent_owner_scan_prefix(owner_tag: &str, owner_uuid: &str) -> Vec<u8> {
    format!("{AGENT_OWNER_PREFIX}{owner_tag}:{owner_uuid}:").into_bytes()
}

/// Returns the realm-wide scan prefix for all owner index entries.
///
/// Format: `agt:owner:`
#[allow(dead_code)]
pub(crate) fn agent_owner_global_scan_prefix() -> Vec<u8> {
    AGENT_OWNER_PREFIX.as_bytes().to_vec()
}

// ===== Agent credential keys (A.3) =====

/// Prefix for agent credential records.
///
/// Format: `agt:cred:{agent_uuid}:{credential_uuid}`
const AGENT_CRED_PREFIX: &str = "agt:cred:";

/// Encodes the primary key for a single agent credential.
///
/// Format: `agt:cred:{agent_uuid}:{credential_uuid}`
pub(crate) fn encode_agent_credential(agent_id: &AgentId, cred_id: &AgentCredentialId) -> Vec<u8> {
    format!(
        "{AGENT_CRED_PREFIX}{}:{}",
        agent_id.as_uuid(),
        cred_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all credentials belonging to one agent.
///
/// Format: `agt:cred:{agent_uuid}:`
pub(crate) fn agent_credential_scan_prefix(agent_id: &AgentId) -> Vec<u8> {
    format!("{AGENT_CRED_PREFIX}{}:", agent_id.as_uuid()).into_bytes()
}

// ===== DPoP storage keys (AGENT_AUTH.md §13.2) =====

/// Prefix for DPoP proof JTI replay-prevention entries.
///
/// Format: `agt:dpop:jti:{jti}`
///
/// Value: 8 bytes, little-endian `i64` Unix-seconds expiry.
/// Realm-scoped by the storage engine — no realm segment in the key itself.
const DPOP_JTI_PREFIX: &str = "agt:dpop:jti:";

/// Storage key for the per-realm DPoP nonce HMAC secret.
///
/// Format: `agt:dpop:nonce-secret`
///
/// Value: 32 raw bytes — the HMAC-SHA256 key used for stateless nonce
/// generation (`HMAC-SHA256(secret, window_id)`). Generated once per realm,
/// persisted so nonces survive server restarts. Realm-scoped by the storage
/// engine.
const DPOP_NONCE_SECRET_KEY: &str = "agt:dpop:nonce-secret";

/// Encodes the storage key for a DPoP proof JTI replay-cache entry.
///
/// Format: `agt:dpop:jti:{jti}`
pub(crate) fn encode_dpop_jti(jti: &str) -> Vec<u8> {
    format!("{DPOP_JTI_PREFIX}{jti}").into_bytes()
}

/// Returns the scan prefix for all DPoP JTI entries in a realm.
///
/// Used by the cleanup sweeper to evict expired entries.
pub(crate) fn dpop_jti_scan_prefix() -> Vec<u8> {
    DPOP_JTI_PREFIX.as_bytes().to_vec()
}

/// Returns the storage key for the per-realm DPoP nonce HMAC secret.
pub(crate) fn dpop_nonce_secret_key() -> Vec<u8> {
    DPOP_NONCE_SECRET_KEY.as_bytes().to_vec()
}

// ===== DPoP JKT blocklist keys (§10.4) =====

/// Storage key prefix for the server-side DPoP JWK thumbprint (jkt) blocklist.
///
/// Format: `agt:dpop:block:jkt:{thumbprint}`
///
/// Value: empty (`b""`). Presence of the key means the thumbprint is blocked.
/// All tokens carrying `cnf.jkt` equal to this thumbprint will be rejected at
/// validate_token time via the hot-path in-memory projection.
const DPOP_BLOCKED_JKT_PREFIX: &str = "agt:dpop:block:jkt:";

/// Encodes the storage key for a blocked DPoP JWK thumbprint.
///
/// Format: `agt:dpop:block:jkt:{jkt}`
pub(crate) fn encode_blocked_dpop_jkt(jkt: &str) -> Vec<u8> {
    format!("{DPOP_BLOCKED_JKT_PREFIX}{jkt}").into_bytes()
}

/// Returns the scan prefix for all blocked DPoP JKT entries in a realm.
///
/// Used at startup to populate the hot-path blocklist projection.
pub(crate) fn blocked_dpop_jkt_scan_prefix() -> Vec<u8> {
    DPOP_BLOCKED_JKT_PREFIX.as_bytes().to_vec()
}

// ===== Attempt tracker WAL keys =====

/// Encodes the WAL storage key for a per-user login-failure attempt tracker.
///
/// Format: `rl:user:{user_uuid}`
///
/// Keys are realm-scoped via the `StorageEngine` handle; no realm segment is
/// embedded here (same convention as `oauth:client:`, `cred:user:`, etc.).
pub(crate) fn encode_attempt_tracker(user_id: &UserId) -> Vec<u8> {
    format!("{ATTEMPT_TRACKER_PREFIX}{}", user_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all persisted attempt trackers in a realm.
///
/// Format: `rl:user:`
pub(crate) fn attempt_tracker_scan_prefix() -> Vec<u8> {
    ATTEMPT_TRACKER_PREFIX.as_bytes().to_vec()
}

/// Encodes the WAL storage key for a per-IP login rate-limit counter.
///
/// Format: `rl:ip-login:{ip}` — realm-scoped via `StorageEngine` handle.
pub(crate) fn encode_ip_login_tracker(ip: &str) -> Vec<u8> {
    format!("{IP_LOGIN_TRACKER_PREFIX}{ip}").into_bytes()
}

/// Returns the scan prefix for all persisted per-IP login trackers in a realm.
///
/// Format: `rl:ip-login:`
pub(crate) fn ip_login_tracker_scan_prefix() -> Vec<u8> {
    IP_LOGIN_TRACKER_PREFIX.as_bytes().to_vec()
}

/// Encodes the WAL storage key for a per-user MFA failed-attempt tracker.
///
/// Format: `rl:mfa:{user_uuid}` — realm-scoped via `StorageEngine` handle.
pub(crate) fn encode_mfa_tracker(user_id: &UserId) -> Vec<u8> {
    format!("{MFA_TRACKER_PREFIX}{}", user_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all persisted per-user MFA trackers in a realm.
///
/// Format: `rl:mfa:`
pub(crate) fn mfa_tracker_scan_prefix() -> Vec<u8> {
    MFA_TRACKER_PREFIX.as_bytes().to_vec()
}

/// Encodes the WAL storage key for a per-email magic-link rate-limit counter.
///
/// Format: `rl:rml:{email}` — realm-scoped via `StorageEngine` handle.
pub(crate) fn encode_magic_link_rl_tracker(email: &str) -> Vec<u8> {
    format!("{MAGIC_LINK_RL_PREFIX}{email}").into_bytes()
}

/// Returns the scan prefix for all persisted magic-link rate-limit trackers.
///
/// Format: `rl:rml:`
pub(crate) fn magic_link_rl_scan_prefix() -> Vec<u8> {
    MAGIC_LINK_RL_PREFIX.as_bytes().to_vec()
}

/// Encodes the WAL storage key for a per-email password-reset rate-limit counter.
///
/// Format: `rl:rpwreset:{email}` — realm-scoped via `StorageEngine` handle.
pub(crate) fn encode_password_reset_rl_tracker(email: &str) -> Vec<u8> {
    format!("{PASSWORD_RESET_RL_PREFIX}{email}").into_bytes()
}

/// Returns the scan prefix for all persisted password-reset rate-limit trackers.
///
/// Format: `rl:rpwreset:`
pub(crate) fn password_reset_rl_scan_prefix() -> Vec<u8> {
    PASSWORD_RESET_RL_PREFIX.as_bytes().to_vec()
}

/// Encodes the WAL storage key for a per-email registration rate-limit counter.
///
/// Format: `rl:rreg-email:{email}` — realm-scoped via `StorageEngine` handle.
pub(crate) fn encode_registration_email_rl_tracker(email: &str) -> Vec<u8> {
    format!("{REGISTRATION_EMAIL_RL_PREFIX}{email}").into_bytes()
}

/// Returns the scan prefix for all persisted registration email rate-limit trackers.
///
/// Format: `rl:rreg-email:`
pub(crate) fn registration_email_rl_scan_prefix() -> Vec<u8> {
    REGISTRATION_EMAIL_RL_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a `prompt=none` probe counter (A-37).
///
/// Format: `rl:prompt_none:{user_uuid}`
///
/// Realm-scoped — no realm UUID in the key itself (same convention as
/// `rl:user:`). Value is a JSON `StoredPromptNoneTracker`.
pub(crate) fn encode_prompt_none_tracker(user_id: &UserId) -> Vec<u8> {
    format!("{PROMPT_NONE_TRACKER_PREFIX}{}", user_id.as_uuid()).into_bytes()
}

/// Encodes a device-fingerprint storage key.
///
/// Format: `dfp:user:{user_uuid}:{hmac_hex}`
///
/// `hmac_hex` is the lower-case hex encoding of the 32-byte HMAC-SHA256 output.
/// The compound key supports scanning all fingerprints for a user and O(1)
/// existence checks for a specific fingerprint.
pub(crate) fn encode_device_fp(user_id: &UserId, hmac_hex: &str) -> Vec<u8> {
    format!("{DEVICE_FP_PREFIX}{}:{hmac_hex}", user_id.as_uuid()).into_bytes()
}

/// Returns the per-user device-fingerprint scan prefix.
///
/// Format: `dfp:user:{user_uuid}:`
///
/// Use with [`prefix_end`] to scan all fingerprints for a given user.
pub(crate) fn device_fp_scan_prefix(user_id: &UserId) -> Vec<u8> {
    format!("{DEVICE_FP_PREFIX}{}:", user_id.as_uuid()).into_bytes()
}

/// Returns the realm-wide device-fingerprint scan prefix.
///
/// Format: `dfp:user:`
///
/// Use with [`prefix_end`] to scan **all** fingerprints in a realm, across
/// every user.  Intended for the proactive background sweeper.
pub(crate) fn device_fp_global_scan_prefix() -> Vec<u8> {
    DEVICE_FP_PREFIX.as_bytes().to_vec()
}

// ─────────────────────────────────────────────────────────────────────────────
//  SMS OTP keys
// ─────────────────────────────────────────────────────────────────────────────

/// Prefix for pending SMS OTP records.
const SMS_PENDING_OTP_PREFIX: &str = "sms:pending_otp:";

/// Prefix for per-phone SMS resend throttle counters.
const SMS_RESEND_COUNT_PREFIX: &str = "sms:resend_count:";

/// Encodes the storage key for a pending SMS OTP record.
///
/// Format: `sms:pending_otp:{nonce_hex}`
///
/// The nonce is a 128-bit CSPRNG value encoded as 32 lowercase hex characters.
/// Value: JSON-serialized `StoredOtp`.
pub(crate) fn encode_sms_pending_otp(nonce: &str) -> Vec<u8> {
    format!("{SMS_PENDING_OTP_PREFIX}{nonce}").into_bytes()
}

/// Returns the scan prefix for all pending SMS OTP records in a realm.
///
/// Format: `sms:pending_otp:`
#[allow(dead_code)]
pub(crate) fn sms_pending_otp_scan_prefix() -> Vec<u8> {
    SMS_PENDING_OTP_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a per-phone SMS resend throttle counter.
///
/// Format: `sms:resend_count:{phone_hash8}`
///
/// `phone_hash8` is the first 8 hex characters of SHA-256(E.164 phone),
/// derived by `otp::phone_resend_key_suffix`. Value: JSON-serialized
/// `StoredResendCount` with a 15-minute TTL.
pub(crate) fn encode_sms_resend_count(phone_hash8: &str) -> Vec<u8> {
    format!("{SMS_RESEND_COUNT_PREFIX}{phone_hash8}").into_bytes()
}

/// Returns the scan prefix for all SMS resend counters in a realm.
///
/// Format: `sms:resend_count:`
#[allow(dead_code)]
pub(crate) fn sms_resend_count_scan_prefix() -> Vec<u8> {
    SMS_RESEND_COUNT_PREFIX.as_bytes().to_vec()
}

// ─────────────────────────────────────────────────────────────────────────────
//  Email OTP keys
// ─────────────────────────────────────────────────────────────────────────────

/// Prefix for pending Email OTP records.
const EMAIL_PENDING_OTP_PREFIX: &str = "email:pending_otp:";

/// Encodes the storage key for a pending Email OTP record.
///
/// Format: `email:pending_otp:{nonce_hex}`
///
/// The nonce is a 128-bit CSPRNG value encoded as 32 lowercase hex characters.
/// Value: JSON-serialized `StoredOtp`.
pub(crate) fn encode_email_pending_otp(nonce: &str) -> Vec<u8> {
    format!("{EMAIL_PENDING_OTP_PREFIX}{nonce}").into_bytes()
}

/// Prefix for Pushed Authorization Request entries (RFC 9126).
const PAR_PREFIX: &str = "oauth:par:";

/// Encodes the storage key for a PAR entry by its UUID.
pub(crate) fn encode_par_request(request_uri_id: &str) -> Vec<u8> {
    format!("{PAR_PREFIX}{request_uri_id}").into_bytes()
}

/// Scan prefix for all PAR entries in a realm.
#[allow(dead_code)]
pub(crate) fn par_scan_prefix() -> Vec<u8> {
    PAR_PREFIX.as_bytes().to_vec()
}

// ===== Session-version key encoding =====

/// Encodes the per-session version counter key.
///
/// Format: `ssv:sid:{session_uuid}`
pub(crate) fn encode_ssv_session(session_id: &SessionId) -> Vec<u8> {
    format!("{SSV_SESSION_PREFIX}{}", session_id.as_uuid()).into_bytes()
}

/// Returns the realm-scoped monotonic sequence counter key.
///
/// Format: `ssv:seq`
pub(crate) fn ssv_seq_key() -> Vec<u8> {
    SSV_SEQ_KEY.as_bytes().to_vec()
}

/// Encodes a delta log entry key for the given sequence number.
///
/// Format: `ssv:delta:{seq:020}` — zero-padded for lexicographic ordering.
pub(crate) fn encode_ssv_delta(seq: u64) -> Vec<u8> {
    format!("{SSV_DELTA_PREFIX}{seq:020}").into_bytes()
}

/// Returns the scan prefix for all per-session version counter keys.
///
/// Format: `ssv:sid:`
pub(crate) fn encode_ssv_session_prefix() -> Vec<u8> {
    SSV_SESSION_PREFIX.as_bytes().to_vec()
}

/// Returns the scan prefix for all delta log entries.
///
/// Format: `ssv:delta:`
pub(crate) fn ssv_delta_scan_prefix() -> Vec<u8> {
    SSV_DELTA_PREFIX.as_bytes().to_vec()
}

// ===== Slug reservation key encoding (A-5) =====

/// Key stored under the **system realm** for a reserved realm slug (A-5 cooldown).
///
/// Format: `slug:realm:{slug}`
///
/// Value: JSON-serialized `StoredSlugReservation` (private to the engine).
/// Written by `delete_realm`; read by `create_realm` to enforce the
/// post-delete cooldown window configured in `security.slug_cooldown_days`.
pub(crate) fn encode_realm_slug_reservation(slug: &str) -> Vec<u8> {
    let mut k = b"slug:realm:".to_vec();
    k.extend_from_slice(slug.as_bytes());
    k
}

/// Key stored under a **realm** for a reserved org slug (A-5 cooldown).
///
/// Format: `slug:org:{realm_uuid_bytes (16)}:{slug}`
///
/// Value: JSON-serialized `StoredSlugReservation` (private to the engine).
/// Written by `delete_organization`; read by `create_organization` to enforce
/// the post-delete cooldown window configured in `security.slug_cooldown_days`.
pub(crate) fn encode_org_slug_reservation(realm_id: &RealmId, slug: &str) -> Vec<u8> {
    let mut k = b"slug:org:".to_vec();
    k.extend_from_slice(realm_id.as_uuid().as_bytes());
    k.push(b':');
    k.extend_from_slice(slug.as_bytes());
    k
}

// ── Protected Resource keys (AGENT_AUTH.md §2.5 / RFC 9728) ──────────────────

/// Prefix for protected resource primary records.
///
/// Format: `rs:id:{resource_server_uuid}` → JSON-serialized `ProtectedResource`
const RESOURCE_SERVER_ID_PREFIX: &str = "rs:id:";

/// Prefix for the resource-URI uniqueness index.
///
/// Format: `rs:uri:{uri_sha256_hex}` → `ResourceServerId` UUID bytes
const RESOURCE_SERVER_URI_PREFIX: &str = "rs:uri:";

/// Encodes the primary key for a protected resource.
pub(crate) fn encode_resource_server_id(id: &ResourceServerId) -> Vec<u8> {
    format!("{RESOURCE_SERVER_ID_PREFIX}{}", id.as_uuid()).into_bytes()
}

/// Returns the realm-level scan prefix for all protected resources.
pub(crate) fn resource_server_scan_prefix() -> Vec<u8> {
    RESOURCE_SERVER_ID_PREFIX.as_bytes().to_vec()
}

/// Encodes the URI index key for a protected resource.
///
/// The URI is SHA-256 hashed to avoid putting potentially long URIs in storage
/// keys. The hex digest is 64 chars and is safe in a key.
pub(crate) fn encode_resource_server_uri_index(uri: &str) -> Vec<u8> {
    use ring::digest;
    let hash = digest::digest(&digest::SHA256, uri.as_bytes());
    let hex: String = hash.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("{RESOURCE_SERVER_URI_PREFIX}{hex}").into_bytes()
}

// ── Actor JTI replay cache (RFC 8693 §4 / AGENT_AUTH.md §3.3) ────────────────

/// Prefix for actor-token JTI replay entries.
///
/// Format: `agt:actor:jti:{jti}` → 8-byte LE i64 expiry
const ACTOR_JTI_PREFIX: &str = "agt:actor:jti:";

/// Encodes the storage key for an actor-token JTI replay-cache entry.
pub(crate) fn encode_actor_jti(jti: &str) -> Vec<u8> {
    format!("{ACTOR_JTI_PREFIX}{jti}").into_bytes()
}

/// Returns the scan prefix for all actor JTI entries (used by cleanup sweeper).
pub(crate) fn actor_jti_scan_prefix() -> Vec<u8> {
    ACTOR_JTI_PREFIX.as_bytes().to_vec()
}

const DELEGATION_GRANT_PREFIX: &str = "dgrant:id:";
const DELEGATION_GRANT_USER_PREFIX: &str = "dgrant:user:";

/// Encodes the primary storage key for a delegation grant.
pub(crate) fn encode_delegation_grant(delegation_id: &str) -> Vec<u8> {
    format!("{DELEGATION_GRANT_PREFIX}{delegation_id}").into_bytes()
}

/// Encodes the user-index key for a delegation grant.
pub(crate) fn encode_delegation_grant_user_index(user_sub: &str, delegation_id: &str) -> Vec<u8> {
    format!("{DELEGATION_GRANT_USER_PREFIX}{user_sub}:{delegation_id}").into_bytes()
}

/// Returns the scan prefix for all delegation grants belonging to a user.
pub(crate) fn delegation_grant_user_prefix(user_sub: &str) -> Vec<u8> {
    format!("{DELEGATION_GRANT_USER_PREFIX}{user_sub}:").into_bytes()
}

// Approval Request keys (Phase C.4)
const APPROVAL_REQUEST_ID_PREFIX: &str = "appreq:id:";
const APPROVAL_REQUEST_LIST_PREFIX: &str = "appreq:list:";
const APPROVAL_REQUEST_PENDING_PREFIX: &str = "appreq:pending:";

pub(crate) fn encode_approval_request_id(request_id: &str) -> Vec<u8> {
    format!("{APPROVAL_REQUEST_ID_PREFIX}{request_id}").into_bytes()
}
pub(crate) fn encode_approval_request_list(request_id: &str) -> Vec<u8> {
    format!("{APPROVAL_REQUEST_LIST_PREFIX}{request_id}").into_bytes()
}
pub(crate) fn approval_request_list_scan_prefix() -> Vec<u8> {
    APPROVAL_REQUEST_LIST_PREFIX.as_bytes().to_vec()
}
pub(crate) fn encode_approval_request_pending(request_id: &str) -> Vec<u8> {
    format!("{APPROVAL_REQUEST_PENDING_PREFIX}{request_id}").into_bytes()
}
pub(crate) fn approval_request_pending_scan_prefix() -> Vec<u8> {
    APPROVAL_REQUEST_PENDING_PREFIX.as_bytes().to_vec()
}

// Capability token single-use JTI blocklist (Phase C — enforce complete mediation)
//
// Written on first use; subsequent uses of the same JTI are rejected.
// Separate namespace from `oauth:revjti:` to avoid key collisions.
const CAPABILITY_JTI_PREFIX: &str = "appreq:cap-jti:";

/// Encodes the blocklist key for a spent capability token JTI.
///
/// Presence means the token has already been used; further use is rejected
/// with `ToolApprovalRequired`.
pub(crate) fn encode_capability_jti(jti: &str) -> Vec<u8> {
    format!("{CAPABILITY_JTI_PREFIX}{jti}").into_bytes()
}

// Approval webhook outbox (Phase C.5 — durable at-least-once delivery)
const APPROVAL_WEBHOOK_OUTBOX_PREFIX: &str = "appreq:outbox:";

/// Outbox key for a pending approval webhook delivery.
///
/// Written atomically with the approval request record. Deleted on
/// successful delivery. The background scanner uses the prefix to find
/// undelivered entries on startup.
pub(crate) fn encode_approval_webhook_outbox(request_id: &str) -> Vec<u8> {
    format!("{APPROVAL_WEBHOOK_OUTBOX_PREFIX}{request_id}").into_bytes()
}

#[allow(dead_code)]
pub(crate) fn approval_webhook_outbox_scan_prefix() -> Vec<u8> {
    APPROVAL_WEBHOOK_OUTBOX_PREFIX.as_bytes().to_vec()
}

// ── Phase D.1: AAT (Attenuating Authorization Token) revocation ───────────────

/// Prefix for AAT revocation entries.
///
/// Format: `aat:rev:{jti}`
const AAT_REVOKED_JTI_PREFIX: &str = "aat:rev:";

/// Storage key for a revoked AAT JTI.
pub(crate) fn encode_aat_revoked_jti(jti: &str) -> Vec<u8> {
    format!("{AAT_REVOKED_JTI_PREFIX}{jti}").into_bytes()
}

// ── Phase D.3: Transaction token replay prevention ───────────────────────────

/// Prefix for consumed transaction token entries.
///
/// Format: `txn:used:{txn_id}` — value is the expiry timestamp (Unix seconds).
const TXN_TOKEN_USED_PREFIX: &str = "txn:used:";

/// Storage key marking a transaction token ID as consumed.
pub(crate) fn encode_txn_token_used(txn_id: &str) -> Vec<u8> {
    format!("{TXN_TOKEN_USED_PREFIX}{txn_id}").into_bytes()
}

// ── Phase D.4: Cross-realm trust policies ────────────────────────────────────

/// Prefix for cross-realm trust policy records.
///
/// Format: `xrealm:pol:{policy_id}`
const CROSS_REALM_POLICY_PREFIX: &str = "xrealm:pol:";

/// Prefix for the source-realm → policy index.
///
/// Format: `xrealm:from:{source_realm_uuid}:{policy_id}` — empty value.
const CROSS_REALM_FROM_INDEX_PREFIX: &str = "xrealm:from:";

/// Primary key for a cross-realm trust policy record.
pub(crate) fn encode_cross_realm_policy(policy_id: &str) -> Vec<u8> {
    format!("{CROSS_REALM_POLICY_PREFIX}{policy_id}").into_bytes()
}

/// Source-realm index key for a cross-realm trust policy.
pub(crate) fn encode_cross_realm_from_index(
    source_realm_id: &crate::core::RealmId,
    policy_id: &str,
) -> Vec<u8> {
    format!(
        "{CROSS_REALM_FROM_INDEX_PREFIX}{}:{policy_id}",
        source_realm_id.as_uuid()
    )
    .into_bytes()
}

/// Scan prefix for all policies trusting a specific source realm.
pub(crate) fn cross_realm_from_scan_prefix(source_realm_id: &crate::core::RealmId) -> Vec<u8> {
    format!(
        "{CROSS_REALM_FROM_INDEX_PREFIX}{}:",
        source_realm_id.as_uuid()
    )
    .into_bytes()
}

/// Scan prefix for all cross-realm policy records (within a realm).
pub(crate) fn cross_realm_policy_scan_prefix() -> Vec<u8> {
    CROSS_REALM_POLICY_PREFIX.as_bytes().to_vec()
}

// ── Phase D.7: SPIFFE identity mapping ───────────────────────────────────────

/// Prefix for SPIFFE ID → AgentId mapping records.
///
/// Format: `spiffe:map:{spiffe_id_sha256}` — value is the `SpiffeIdentityMapping` JSON.
const SPIFFE_MAPPING_PREFIX: &str = "spiffe:map:";

/// Prefix for the agent → SPIFFE ID reverse index.
///
/// Format: `spiffe:agt:{agent_uuid}` — value is the SPIFFE ID string.
const SPIFFE_AGENT_INDEX_PREFIX: &str = "spiffe:agt:";

/// Primary key for a SPIFFE ID mapping.
///
/// The SPIFFE ID is SHA-256 hashed to produce a fixed-length key.
pub(crate) fn encode_spiffe_mapping(spiffe_id: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(spiffe_id.as_bytes());
    let hex = hex::encode(hash);
    format!("{SPIFFE_MAPPING_PREFIX}{hex}").into_bytes()
}

/// Reverse-index key: agent UUID → SPIFFE ID.
pub(crate) fn encode_spiffe_agent_index(agent_id: &crate::core::AgentId) -> Vec<u8> {
    format!("{SPIFFE_AGENT_INDEX_PREFIX}{}", agent_id.as_uuid()).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{ClientId, IdpId, InvitationId, OrganizationId, RealmId, SessionId};
    use uuid::Uuid;

    #[test]
    fn encode_user_id_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(uuid);
        let key = encode_user_id(&user_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "usr:id:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn encode_user_email_format() {
        let key = encode_user_email("alice@example.com");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "usr:email:alice@example.com");
    }

    #[test]
    fn user_id_value_round_trips_canonically() {
        let user_id = UserId::generate();
        let encoded = encode_user_id_value(&user_id);
        assert_eq!(encoded.len(), 16, "canonical form is 16 raw UUID bytes");
        assert_eq!(
            decode_user_id_value(&encoded).expect("decodes"),
            user_id,
            "canonical encoding must round-trip"
        );
    }

    #[test]
    fn user_id_value_heals_legacy_string_form() {
        let user_id = UserId::generate();
        let legacy = user_id.as_uuid().to_string().into_bytes();
        assert_eq!(legacy.len(), 36);
        assert_eq!(
            decode_user_id_value(&legacy).expect("decodes"),
            user_id,
            "index entries from the mixed-format window must still resolve"
        );
    }

    #[test]
    fn user_id_value_rejects_garbage() {
        assert!(decode_user_id_value(b"not-a-uuid").is_none());
        assert!(decode_user_id_value(&[0xff, 0xfe, 0xfd]).is_none());
        assert!(decode_user_id_value(b"").is_none());
    }

    #[test]
    fn user_id_scan_prefix_format() {
        let prefix = user_id_scan_prefix();
        let prefix_str = std::str::from_utf8(&prefix).expect("utf8");
        assert_eq!(prefix_str, "usr:id:");
    }

    #[test]
    fn user_id_key_starts_with_scan_prefix() {
        let user_id = UserId::generate();
        let key = encode_user_id(&user_id);
        let prefix = user_id_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn prefix_end_increments_last_byte() {
        let prefix = user_id_scan_prefix();
        let end = prefix_end(&prefix);
        // ':' is 0x3A, incrementing gives ';' (0x3B)
        assert_eq!(end.last(), Some(&0x3B));
        assert!(end > prefix);
    }

    #[test]
    fn prefix_end_empty() {
        let end = prefix_end(b"");
        assert!(end.is_empty());
    }

    #[test]
    fn encode_credential_key_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(uuid);
        let key = encode_credential_key(&user_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "cred:user:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn different_users_produce_different_keys() {
        let id1 = UserId::generate();
        let id2 = UserId::generate();
        let key1 = encode_user_id(&id1);
        let key2 = encode_user_id(&id2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn different_emails_produce_different_keys() {
        let key1 = encode_user_email("alice@example.com");
        let key2 = encode_user_email("bob@example.com");
        assert_ne!(key1, key2);
    }

    #[test]
    fn encode_session_id_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let session_id = SessionId::new(uuid);
        let key = encode_session_id(&session_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "ses:id:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn encode_user_session_format() {
        let user_uuid =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let session_uuid =
            Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(user_uuid);
        let session_id = SessionId::new(session_uuid);
        let key = encode_user_session(&user_id, &session_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(
            key_str,
            "ses:user:550e8400-e29b-41d4-a716-446655440000:660e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn user_sessions_prefix_enables_scan() {
        let user_id = UserId::generate();
        let session_id = SessionId::generate();
        let key = encode_user_session(&user_id, &session_id);
        let prefix = encode_user_sessions_prefix(&user_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn different_sessions_produce_different_keys() {
        let id1 = SessionId::generate();
        let id2 = SessionId::generate();
        let key1 = encode_session_id(&id1);
        let key2 = encode_session_id(&id2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn encode_oauth_client_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let client_id = ClientId::new(uuid);
        let key = encode_oauth_client(&client_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "oauth:client:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn encode_oauth_code_format() {
        // deepcode ignore HardcodedNonCryptoSecret: storage key format fixture — verifies encode_oauth_code prefix
        let hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let key = encode_oauth_code(hash);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(
            key_str,
            "oauth:code:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }

    #[test]
    fn different_clients_produce_different_keys() {
        let id1 = ClientId::generate();
        let id2 = ClientId::generate();
        let key1 = encode_oauth_client(&id1);
        let key2 = encode_oauth_client(&id2);
        assert_ne!(key1, key2);
    }

    // ===== Realm key tests =====

    #[test]
    fn system_realm_id_is_nil_uuid() {
        let sys = system_realm_id();
        assert_eq!(*sys.as_uuid(), Uuid::nil());
    }

    #[test]
    fn system_realm_id_is_stable() {
        assert_eq!(system_realm_id(), system_realm_id());
    }

    #[test]
    fn encode_realm_id_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let realm_id = RealmId::new(uuid);
        let key = encode_realm_id(&realm_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "realm:id:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn realm_id_key_starts_with_scan_prefix() {
        let realm_id = RealmId::generate();
        let key = encode_realm_id(&realm_id);
        let prefix = realm_id_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_realm_signing_key_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let realm_id = RealmId::new(uuid);
        let key = encode_realm_signing_key(&realm_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "realm:key:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn encode_mfa_totp_key_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(uuid);
        let key = encode_mfa_totp_key(&user_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "mfa:totp:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn encode_webauthn_credential_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(uuid);
        let key = encode_webauthn_credential(&user_id, "cred123");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(
            key_str,
            "webauthn:cred:550e8400-e29b-41d4-a716-446655440000:cred123"
        );
    }

    #[test]
    fn webauthn_credential_prefix_enables_scan() {
        let user_id = UserId::generate();
        let key = encode_webauthn_credential(&user_id, "credABC");
        let prefix = encode_webauthn_credentials_prefix(&user_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_webauthn_discoverable_format() {
        let key = encode_webauthn_discoverable("abc123");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "webauthn:disc:abc123");
    }

    #[test]
    fn different_realms_produce_different_keys() {
        let id1 = RealmId::generate();
        let id2 = RealmId::generate();
        assert_ne!(encode_realm_id(&id1), encode_realm_id(&id2));
        assert_ne!(
            encode_realm_signing_key(&id1),
            encode_realm_signing_key(&id2)
        );
    }

    // ===== Organization key tests =====

    #[test]
    fn encode_org_id_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let org_id = OrganizationId::new(uuid);
        let key = encode_org_id(&org_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "org:id:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn org_id_key_starts_with_scan_prefix() {
        let org_id = OrganizationId::generate();
        let key = encode_org_id(&org_id);
        let prefix = org_id_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_org_slug_format() {
        let key = encode_org_slug("acme-corp");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "org:slug:acme-corp");
    }

    #[test]
    fn membership_by_org_format() {
        let org_id = OrganizationId::generate();
        let user_id = UserId::generate();
        let key = encode_membership_by_org(&org_id, &user_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert!(key_str.starts_with("orgm:org:"));
        assert!(key_str.contains(":user:"));
    }

    #[test]
    fn membership_by_org_starts_with_prefix() {
        let org_id = OrganizationId::generate();
        let user_id = UserId::generate();
        let key = encode_membership_by_org(&org_id, &user_id);
        let prefix = membership_by_org_prefix(&org_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn membership_by_user_format() {
        let org_id = OrganizationId::generate();
        let user_id = UserId::generate();
        let key = encode_membership_by_user(&user_id, &org_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert!(key_str.starts_with("orgm:user:"));
        assert!(key_str.contains(":org:"));
    }

    #[test]
    fn membership_by_user_starts_with_prefix() {
        let org_id = OrganizationId::generate();
        let user_id = UserId::generate();
        let key = encode_membership_by_user(&user_id, &org_id);
        let prefix = membership_by_user_prefix(&user_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_invitation_id_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let inv_id = InvitationId::new(uuid);
        let key = encode_invitation_id(&inv_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "orgi:id:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn invitation_id_starts_with_scan_prefix() {
        let inv_id = InvitationId::generate();
        let key = encode_invitation_id(&inv_id);
        let prefix = invitation_id_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_invitation_token_format() {
        let key = encode_invitation_token("abc123def456");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "orgi:token:abc123def456");
    }

    #[test]
    fn encode_invitation_org_email_format() {
        let org_id = OrganizationId::generate();
        let key = encode_invitation_org_email(&org_id, "alice@example.com");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert!(key_str.starts_with("orgi:org:"));
        assert!(key_str.ends_with(":email:alice@example.com"));
    }

    #[test]
    fn invitation_list_starts_with_prefix() {
        let org_id = OrganizationId::generate();
        let inv_id = InvitationId::generate();
        let key = encode_invitation_list(&org_id, &inv_id);
        let prefix = invitation_list_prefix(&org_id);
        assert!(key.starts_with(&prefix));
    }

    // ===== Consent key tests =====

    #[test]
    fn encode_consent_key_format() {
        let user_uuid =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let client_uuid =
            Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(user_uuid);
        let client_id = ClientId::new(client_uuid);
        let key = encode_consent_key(&user_id, &client_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(
            key_str,
            "oauth:consent:550e8400-e29b-41d4-a716-446655440000:660e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn consent_key_starts_with_user_prefix() {
        let user_id = UserId::generate();
        let client_id = ClientId::generate();
        let key = encode_consent_key(&user_id, &client_id);
        let prefix = encode_consent_prefix_for_user(&user_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn consent_key_starts_with_scan_prefix() {
        let user_id = UserId::generate();
        let client_id = ClientId::generate();
        let key = encode_consent_key(&user_id, &client_id);
        let prefix = oauth_consent_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn different_users_produce_different_consent_prefixes() {
        let u1 = UserId::generate();
        let u2 = UserId::generate();
        assert_ne!(
            encode_consent_prefix_for_user(&u1),
            encode_consent_prefix_for_user(&u2)
        );
    }

    #[test]
    fn encode_pending_auth_key_format() {
        let key = encode_pending_auth_key("ticket-abc-123");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "oauth:pending_auth:ticket-abc-123");
    }

    #[test]
    fn pending_auth_key_starts_with_scan_prefix() {
        let key = encode_pending_auth_key("t1");
        let prefix = oauth_pending_auth_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    // ===== Federation key tests =====

    #[test]
    fn encode_idp_key_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let idp_id = IdpId::new(uuid);
        let key = encode_idp_key(&idp_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "fed:idp:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn idp_key_starts_with_scan_prefix() {
        let key = encode_idp_key(&IdpId::generate());
        assert!(key.starts_with(&fed_idp_scan_prefix()));
    }

    #[test]
    fn encode_federation_state_key_format() {
        let key = encode_federation_state_key("state-token-abc");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "fed:state:state-token-abc");
    }

    #[test]
    fn federation_state_key_starts_with_scan_prefix() {
        let key = encode_federation_state_key("xyz");
        assert!(key.starts_with(&fed_state_scan_prefix()));
    }

    #[test]
    fn encode_federation_confirm_key_format() {
        let key = encode_federation_confirm_key("ticket-uuid-1");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "fed:confirm:ticket-uuid-1");
    }

    #[test]
    fn federation_confirm_key_starts_with_scan_prefix() {
        let key = encode_federation_confirm_key("t");
        assert!(key.starts_with(&fed_confirm_scan_prefix()));
    }

    #[test]
    fn encode_federation_ext_key_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let idp_id = IdpId::new(uuid);
        let key = encode_federation_ext_key(&idp_id, "google-sub-12345");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(
            key_str,
            "fed:ext:550e8400-e29b-41d4-a716-446655440000:google-sub-12345"
        );
    }

    #[test]
    fn federation_ext_key_starts_with_idp_prefix() {
        let idp_id = IdpId::generate();
        let key = encode_federation_ext_key(&idp_id, "sub-abc");
        let prefix = encode_federation_ext_prefix_for_idp(&idp_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn federation_ext_key_starts_with_realm_scan_prefix() {
        let key = encode_federation_ext_key(&IdpId::generate(), "sub");
        assert!(key.starts_with(&fed_ext_scan_prefix()));
    }

    #[test]
    fn different_idps_produce_disjoint_ext_prefixes() {
        let p1 = encode_federation_ext_prefix_for_idp(&IdpId::generate());
        let p2 = encode_federation_ext_prefix_for_idp(&IdpId::generate());
        assert_ne!(p1, p2);
        // Critical: one prefix must not be a prefix of the other, or a
        // cascade scan for IdP-A would delete IdP-B's records.
        assert!(!p1.starts_with(&p2));
        assert!(!p2.starts_with(&p1));
    }

    #[test]
    fn encode_federation_ext_fwd_key_format() {
        let user_uuid =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let idp_uuid = Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(user_uuid);
        let idp_id = IdpId::new(idp_uuid);
        let key = encode_federation_ext_fwd_key(&user_id, &idp_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(
            key_str,
            "fed:ext_fwd:550e8400-e29b-41d4-a716-446655440000:660e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn federation_ext_fwd_key_starts_with_user_prefix() {
        let user_id = UserId::generate();
        let idp_id = IdpId::generate();
        let key = encode_federation_ext_fwd_key(&user_id, &idp_id);
        let prefix = encode_federation_ext_fwd_prefix_for_user(&user_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn federation_ext_fwd_key_starts_with_realm_scan_prefix() {
        let key = encode_federation_ext_fwd_key(&UserId::generate(), &IdpId::generate());
        assert!(key.starts_with(&fed_ext_fwd_scan_prefix()));
    }

    #[test]
    fn different_users_produce_disjoint_ext_fwd_prefixes() {
        let p1 = encode_federation_ext_fwd_prefix_for_user(&UserId::generate());
        let p2 = encode_federation_ext_fwd_prefix_for_user(&UserId::generate());
        assert_ne!(p1, p2);
        // Critical: cross-user cascade deletes must not leak.
        assert!(!p1.starts_with(&p2));
        assert!(!p2.starts_with(&p1));
    }

    #[test]
    fn federation_prefixes_do_not_overlap_with_legacy_prefixes() {
        // Regression guard: a future rename of legacy prefixes that
        // happened to begin with "fed" would cascade-delete federation
        // data. All legacy prefixes used by hearth today.
        let fed = fed_idp_scan_prefix();
        let legacy_prefixes = [
            user_id_scan_prefix(),
            session_id_scan_prefix(),
            oauth_client_scan_prefix(),
            oauth_consent_scan_prefix(),
            oauth_pending_auth_scan_prefix(),
            org_id_scan_prefix(),
        ];
        for p in &legacy_prefixes {
            assert!(!fed.starts_with(p));
            assert!(!p.starts_with(&fed));
        }
    }
}
