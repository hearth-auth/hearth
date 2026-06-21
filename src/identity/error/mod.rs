//! Identity engine error types.
//!
//! The `IdentityError` enum is the single error type for the identity layer.
//! Per-subdomain sub-errors (e.g. `SamlError`) delegate via `From` impls so
//! SAML/federation modules can return their own typed errors and callers use `?`.

use crate::identity::federation::saml::SamlError;

mod display;
mod source;
mod wire_codes;

#[cfg(test)]
mod tests;

/// Errors originating from the identity engine.
#[derive(Debug)]
#[non_exhaustive]
pub enum IdentityError {
    /// The requested realm was not found.
    RealmNotFound,
    /// The realm is suspended; operations are denied.
    RealmSuspended,
    /// A realm with the given name already exists.
    DuplicateRealmName,
    /// The requested user was not found.
    UserNotFound,
    /// A user with the given email already exists in this realm.
    DuplicateEmail,
    /// The input failed validation.
    InvalidInput {
        /// Description of what was invalid.
        reason: String,
    },
    /// No credential found for this user.
    CredentialNotFound,
    /// The provided credential was invalid (e.g., wrong password).
    InvalidCredential {
        /// Description of why the credential was invalid.
        reason: String,
    },
    /// The requested session was not found, expired, or revoked.
    ///
    /// Intentionally conflates not-found, expired, and revoked for
    /// enumeration resistance — callers cannot distinguish the three.
    SessionNotFound,
    /// Session-version feature is not enabled for this realm.
    SessionVersionDisabled,
    /// The token is invalid (malformed, bad signature, unsupported algorithm).
    ///
    /// Intentionally vague to prevent information leakage about why
    /// validation failed.
    InvalidToken,
    /// The token has expired.
    TokenExpired,
    /// A cryptographic signing or key generation error.
    SigningError {
        /// Description of the signing failure (no secrets).
        reason: String,
    },
    /// The OAuth client was not found or is invalid.
    InvalidClient,
    /// The redirect URI does not match any registered URI for the client.
    InvalidRedirectUri,
    /// The authorization code is not found, expired, already used, or invalid.
    InvalidAuthorizationCode,
    /// A generic OAuth error for code exchange failures (e.g., PKCE mismatch).
    InvalidGrant {
        /// Description of why the grant was invalid.
        reason: String,
    },
    /// The client secret is invalid.
    ///
    /// Intentionally vague — does not distinguish wrong vs. expired
    /// for enumeration resistance.
    InvalidClientSecret,
    /// The `private_key_jwt` client assertion is invalid (RFC 7523 §2.2).
    InvalidClientAssertion {
        /// Why the assertion was rejected.
        reason: String,
    },
    /// A JAR (RFC 9101) signed request object is invalid.
    ///
    /// Covers: unsupported algorithm (including `none`), bad signature,
    /// expired token, wrong `iss`, wrong `aud`, no registered JWKS, missing
    /// key for `kid`. Intentionally aggregated to limit information leakage.
    InvalidJar {
        /// Why the JAR was rejected. Safe to include in error responses.
        reason: String,
    },
    /// The device authorization is still pending user action.
    AuthorizationPending,
    /// The device is polling too frequently; must slow down.
    SlowDown,
    /// The device authorization code has expired.
    DeviceCodeExpired,
    /// The device authorization was denied by the user.
    DeviceCodeDenied,
    /// The token has been revoked (grant family revoked).
    TokenRevoked,
    /// The requested grant type is not supported for this client.
    UnsupportedGrantType,
    /// Password authentication succeeded but MFA verification is required.
    MfaRequired,
    /// The TOTP code or recovery code is invalid.
    InvalidMfaCode,
    /// MFA is not enabled for this user.
    MfaNotEnabled,
    /// MFA is already enabled; disable it before re-enrolling.
    MfaAlreadyEnabled,
    /// A `WebAuthn` registration ceremony failed.
    WebAuthnRegistrationFailed {
        /// Description of the failure (no secrets).
        reason: String,
    },
    /// A `WebAuthn` authentication ceremony failed.
    WebAuthnAuthenticationFailed {
        /// Description of the failure (no secrets).
        reason: String,
    },
    /// The requested `WebAuthn` credential was not found.
    WebAuthnCredentialNotFound,
    /// The attestation provided during registration is invalid or unsupported.
    InvalidAttestation {
        /// Description of the attestation failure.
        reason: String,
    },
    /// The assertion provided during authentication is invalid.
    InvalidAssertion {
        /// Description of the assertion failure.
        reason: String,
    },
    /// The caller is not authorized to perform this operation.
    ///
    /// Used for admin API access control. Intentionally vague to
    /// prevent information leakage about what resources exist.
    Unauthorized,
    /// The requested OAuth client was not found.
    ClientNotFound,
    /// The magic link token is invalid, expired, or already used.
    ///
    /// Intentionally conflates not-found, expired, and already-used for
    /// enumeration resistance — callers cannot distinguish the three.
    MagicLinkTokenInvalid,
    /// The email-verification token is invalid, expired, or already used.
    ///
    /// Intentionally conflates not-found, expired, and already-used for
    /// enumeration resistance — callers cannot distinguish the three.
    VerificationTokenInvalid,
    /// The password-reset token is invalid, expired, or already used.
    ///
    /// Intentionally conflates not-found, expired, and already-used for
    /// enumeration resistance — callers cannot distinguish the three.
    PasswordResetTokenInvalid,
    /// The user account has not yet verified their email address.
    UserNotVerified,
    /// Too many failed credential attempts; the account is temporarily locked.
    ///
    /// Intentionally vague to avoid leaking lockout state to attackers.
    RateLimited,
    /// The requested organization was not found.
    OrganizationNotFound,
    /// An organization with the given slug already exists in this realm.
    DuplicateOrgSlug,
    /// The organization is suspended; operations are denied.
    OrganizationSuspended,
    /// The user is already a member of this organization.
    AlreadyMember,
    /// The user is not a member of this organization.
    NotAMember,
    /// Cannot remove the last owner of an organization.
    LastOwner,
    /// The organization has reached its maximum member count.
    MemberLimitReached,
    /// The invitation is invalid, expired, or already used.
    ///
    /// Intentionally conflates not-found, expired, and already-used for
    /// enumeration resistance — callers cannot distinguish the three.
    InvitationInvalid,
    /// An invitation for this email already exists for this organization.
    DuplicateInvitation,
    /// The realm name or org slug is in the operator-configured reserved list (A-5).
    ReservedSlug {
        /// The name that was rejected.
        slug: String,
    },
    /// The realm name or org slug is in a post-delete cooldown period (A-5).
    SlugInCooldown {
        /// The name that was rejected.
        slug: String,
    },
    /// An operation targeted the reserved system realm.
    SystemRealmProtected {
        /// The operation that was attempted (e.g. `"create_realm"`).
        operation: &'static str,
    },
    /// Self-service registration is disabled for this realm.
    RegistrationDisabled,
    /// Self-service registration is enabled but the email's domain is not
    /// in the realm's allow-list.
    RegistrationDomainNotAllowed {
        /// The domain that was rejected.
        domain: String,
    },
    /// Self-service registration is enabled in invite-only mode and the
    /// caller did not present a valid invitation token.
    RegistrationRequiresInvitation,
    /// The OAuth client requires user consent and no sufficient consent record exists.
    ConsentRequired,
    /// The pending-authorization ticket was not found.
    ConsentTicketNotFound,
    /// The pending-authorization ticket has expired.
    ConsentTicketExpired,
    /// The user attempted to approve a scope not present in the original request.
    ConsentScopeNotRequested,
    /// No consent record exists for the requested `(user, client)` pair.
    ConsentNotFound,
    /// No delegation grant record exists for the given `delegation_id` and user.
    DelegationGrantNotFound,
    /// The referenced external IdP connector is not registered in this realm.
    FederationUnknownConnector,
    /// The federation `state` parameter returned by the upstream IdP does not
    /// correspond to any known in-flight login.
    FederationInvalidState,
    /// The upstream Identity Provider returned an error or unexpected response.
    FederationUpstreamError {
        /// Connector the error originated from. Never contains PII.
        provider: String,
        /// Sanitized human-readable description.
        reason: String,
    },
    /// Verification of an upstream ID token failed.
    FederationTokenVerificationFailed,
    /// The RFC 9207 `iss` authorization-response parameter did not match the
    /// expected issuer for this IdP connector.
    FederationIdpMixup,
    /// The upstream IdP returned `email_verified: false` for an operation that
    /// requires verified email.
    FederationEmailNotVerified,
    /// The external login requires local confirmation before the link is persisted.
    FederationLinkConfirmationRequired {
        /// Opaque single-use ticket. 10-minute TTL.
        ticket: String,
    },
    /// The user has no linked external identity for this connector.
    FederationNotLinked,
    /// The external identity is already linked.
    FederationAlreadyLinked,
    /// The supplied SCIM `externalId` is already associated with a different user.
    DuplicateScimExternalId,
    /// The user has reached the per-realm maximum number of concurrent active sessions.
    SessionLimitExceeded {
        /// The configured session limit.
        limit: u32,
        /// The number of currently active sessions at rejection time.
        active: u32,
    },
    /// YAML-authored realm configuration failed registry validation.
    ConfigInvalid {
        /// Name of the realm whose config failed validation.
        realm_name: String,
        /// Every validation error found in the registry.
        errors: Vec<crate::rbac::RegistryError>,
    },
    /// An error from the underlying storage layer.
    Storage(Box<dyn std::error::Error + Send + Sync>),
    /// Serialization or deserialization failed.
    Serialization {
        /// Description of the serialization failure.
        reason: String,
    },
    /// An internal engine-layer failure.
    Internal {
        /// Sanitized description of what went wrong.
        reason: String,
    },
    /// Token issuance aborted because the resolved claim set exceeds a size bound.
    TokenTooLarge {
        /// Name of the specific limit that was exceeded.
        limit: String,
        /// Configured maximum for this limit.
        limit_value: usize,
        /// The size actually produced at resolve time.
        actual: usize,
    },
    /// A user attribute key or value failed validation.
    InvalidAttribute {
        /// Description of what was invalid.
        reason: String,
    },
    /// A security-critical mutation succeeded but the audit event could not be recorded.
    AuditFailure {
        /// The action that could not be recorded.
        action: String,
        /// Why the audit append failed.
        reason: String,
    },
    /// The user's password has expired.
    PasswordExpired,
    /// The new password matches a previously used password.
    PasswordReused,
    /// The requested authentication method is not permitted by the realm's policy.
    AuthMethodNotAllowed {
        /// The method that was attempted.
        method: &'static str,
    },
    /// The requested webhook was not found in this realm.
    WebhookNotFound,
    /// The new password has appeared in a known data breach (HIBP check).
    PasswordCompromised,
    /// Adaptive step-up MFA required: login from unrecognised device.
    StepUpChallengeRequired,
    /// Adaptive step-up MFA enrollment required: login from unrecognised device with no factor.
    EnrollMfaRequired,
    /// One or more required actions are pending for this user.
    RequiredActionsBlocking {
        /// The actions the user must complete.
        actions: Vec<crate::identity::types::RequiredAction>,
    },
    /// The SMS OTP is invalid, expired, not found, or max attempts exceeded.
    InvalidSmsOtp,
    /// The phone number has exceeded the per-phone SMS resend limit.
    SmsResendLimitExceeded,
    /// The Email OTP is invalid, expired, not found, or max attempts exceeded.
    InvalidEmailOtp,
    /// The pushed `request_uri` is not found, already used, or expired.
    InvalidPushedAuthorizationRequest,
    /// The DPoP proof JWT is invalid.
    InvalidDPopProof {
        /// Human-readable description of the specific failure.
        reason: String,
    },
    /// The DPoP proof JTI has already been seen — replay attack detected.
    DPopProofReplay,
    /// The access token carries a `cnf.jkt` binding but the DPoP proof's JWK
    /// thumbprint does not match.
    DPopBindingMismatch,
    /// The `nonce` in the DPoP proof does not match the server-issued nonce.
    DPopNonceInvalid,
    /// The `cnf.jkt` thumbprint in the access token is in the server-side
    /// blocklist (§10.4). The key has been revoked by an administrator.
    DPopJktBlocked,
    /// A JWT bearer assertion (RFC 7523) is invalid.
    JwtBearerAssertionInvalid {
        /// Machine-readable reason string.
        reason: String,
    },
    /// The request violates a FAPI 2.0 Security Profile constraint.
    FapiViolation {
        /// Human-readable description of the violated constraint.
        reason: String,
    },
    /// The requested email is under a 90-day post-deletion reservation (A-20).
    EmailReserved,
    /// The email-change verification token is invalid, expired, or already used.
    EmailChangeTokenInvalid,
    /// The `prompt=none` silent-auth probe rate limit was exceeded (A-37).
    SilentAuthRateLimited,
    /// A per-realm resource quota was exceeded (A-24).
    QuotaExceeded {
        /// Resource type that hit the limit.
        resource: &'static str,
        /// The configured maximum.
        limit: u64,
        /// The count at the time of the check.
        current: u64,
    },
    /// A `WebAuthn` registration was rejected by the realm's attestation policy (A-13).
    AttestationPolicyViolation {
        /// Human-readable description of the violated policy constraint.
        reason: String,
    },
    /// The requested agent was not found in this realm.
    AgentNotFound,
    /// The agent has been permanently revoked.
    AgentRevoked,
    /// The requested agent credential was not found.
    AgentCredentialNotFound,
    /// The pre-token enrichment webhook call failed and the realm's policy is `fail_closed`.
    PreTokenWebhookFailed {
        /// Description of the transport or parse failure.
        reason: String,
    },
    /// An error from the SAML federation flow.
    Saml(SamlError),
    // ── M2: Protected Resource + RFC 8693 Token Exchange ─────────────────────
    /// The requested protected resource was not found in this realm.
    ProtectedResourceNotFound,
    /// A protected resource with this URI already exists in the realm.
    DuplicateResourceUri,
    /// RFC 8693 token exchange was rejected.
    ///
    /// Wraps a human-readable reason for the rejection. Error responses
    /// use `error: "invalid_grant"` or `error: "invalid_scope"` as
    /// appropriate; the `reason` is logged but NOT exposed to callers.
    TokenExchangeRejected {
        /// Internal reason (not sent to client).
        reason: String,
        /// OAuth 2.0 error code to return to the caller.
        oauth_error: &'static str,
    },
    /// The delegation chain depth would exceed the agent's `max_delegation_depth`.
    DelegationDepthExceeded {
        /// The agent's configured maximum.
        max: u8,
        /// The depth the exchange would produce.
        attempted: u8,
    },
    /// The scope intersection of subject, actor, and requested is empty.
    EmptyScopeIntersection,
    /// An actor token `jti` was replayed (B.5 replay prevention).
    ActorTokenReplayed,

    // Phase C
    ToolAccessDenied {
        tool: String,
    },
    ToolApprovalRequired {
        tool: String,
    },
    ApprovalRequestNotFound,
    ApprovalRequestNotPending {
        current_status: String,
    },
    ApprovalRequestExpired,

    // Phase D.1 — Attenuating Authorization Tokens
    /// A crafted AAT attempts to widen scope beyond its parent's permissions.
    AatScopeEscalation,
    /// The AAT attenuation chain is structurally invalid (missing link, wrong parent JTI).
    AatChainBroken {
        /// Human-readable description of the broken invariant.
        reason: String,
    },
    /// An AAT or one of its ancestors has been explicitly revoked.
    AatRevoked,
    /// The presented AAT has expired.
    AatExpired,

    // Phase D.3 — Transaction Tokens
    /// A transaction token with this `txn_id` has already been consumed.
    TransactionTokenReplayed,

    // Phase D.4 — Cross-Realm Trust Policies
    /// No cross-realm trust policy was found for the given (source, target) pair.
    CrossRealmPolicyNotFound,
    /// A cross-realm trust policy already exists for this (source, target) pair.
    CrossRealmPolicyConflict,
    /// The requested capability is not permitted under the applicable cross-realm policy.
    CrossRealmCapabilityNotAllowed {
        /// The capability that was denied.
        capability: String,
    },

    // Phase D.7 — SPIFFE / Workload Identity
    /// The SPIFFE ID string does not match the expected `spiffe://{domain}/agent/{uuid}` format.
    SpiffeIdInvalid {
        /// Human-readable reason for the rejection.
        reason: String,
    },
    /// No SPIFFE ID mapping was found for this agent or SPIFFE ID.
    SpiffeMappingNotFound,
    /// A SPIFFE ID mapping already exists for this agent.
    SpiffeMappingConflict,
    /// The X.509 certificate presented for SPIFFE authentication is invalid.
    SpiffeCertInvalid {
        /// Reason the certificate was rejected.
        reason: String,
    },
    /// The X.509 SVID presented for SPIFFE authentication has expired.
    SpiffeCertExpired,
}

impl From<SamlError> for IdentityError {
    fn from(e: SamlError) -> Self {
        Self::Saml(e)
    }
}
