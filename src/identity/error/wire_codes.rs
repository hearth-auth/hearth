//! Wire error codes for `IdentityError`.

use super::IdentityError;

impl IdentityError {
    /// Returns the stable wire error code for this variant, or `None` for
    /// server-side (5xx) errors where leaking detail would be inappropriate.
    ///
    /// This keeps the cross-layer variant match inside the identity crate so
    /// the protocol layer can call `err.wire_error_code()` without pattern-
    /// matching on identity internals.
    #[allow(clippy::too_many_lines)]
    pub fn wire_error_code(&self) -> Option<&'static str> {
        match self {
            Self::TokenExpired => Some("HEARTH_TOKEN_EXPIRED"),
            Self::TokenRevoked => Some("HEARTH_TOKEN_REVOKED"),
            Self::InvalidToken => Some("HEARTH_TOKEN_INVALID"),
            Self::TokenTooLarge { .. } => Some("HEARTH_TOKEN_TOO_LARGE"),

            Self::InvalidCredential { .. } | Self::CredentialNotFound => {
                Some("HEARTH_INVALID_CREDENTIAL")
            }
            Self::InvalidClient | Self::InvalidClientSecret => Some("HEARTH_INVALID_CLIENT"),
            Self::InvalidClientAssertion { .. } => Some("HEARTH_INVALID_CLIENT_ASSERTION"),
            Self::InvalidAuthorizationCode | Self::InvalidGrant { .. } => {
                Some("HEARTH_INVALID_GRANT")
            }
            Self::DeviceCodeExpired => Some("HEARTH_DEVICE_CODE_EXPIRED"),
            Self::InvalidRedirectUri => Some("HEARTH_INVALID_REDIRECT_URI"),
            Self::UnsupportedGrantType => Some("HEARTH_UNSUPPORTED_GRANT_TYPE"),

            Self::MfaRequired => Some("HEARTH_MFA_REQUIRED"),
            Self::InvalidMfaCode => Some("HEARTH_MFA_INVALID_CODE"),
            Self::MfaNotEnabled => Some("HEARTH_MFA_NOT_ENABLED"),
            Self::MfaAlreadyEnabled => Some("HEARTH_MFA_ALREADY_ENABLED"),

            Self::WebAuthnRegistrationFailed { .. } => Some("HEARTH_WEBAUTHN_REGISTRATION_FAILED"),
            Self::WebAuthnAuthenticationFailed { .. } => {
                Some("HEARTH_WEBAUTHN_AUTHENTICATION_FAILED")
            }
            Self::WebAuthnCredentialNotFound => Some("HEARTH_WEBAUTHN_CREDENTIAL_NOT_FOUND"),
            Self::InvalidAttestation { .. } => Some("HEARTH_INVALID_ATTESTATION"),
            Self::InvalidAssertion { .. } => Some("HEARTH_INVALID_ASSERTION"),
            Self::JwtBearerAssertionInvalid { .. } => Some("HEARTH_JWT_BEARER_ASSERTION_INVALID"),

            Self::AuthorizationPending => Some("HEARTH_AUTHORIZATION_PENDING"),
            Self::SlowDown => Some("HEARTH_SLOW_DOWN"),
            Self::DeviceCodeDenied => Some("HEARTH_DEVICE_CODE_DENIED"),

            Self::RateLimited => Some("HEARTH_RATE_LIMITED"),
            Self::SessionLimitExceeded { .. } => Some("HEARTH_SESSION_LIMIT_EXCEEDED"),
            Self::QuotaExceeded { .. } => Some("HEARTH_QUOTA_EXCEEDED"),

            Self::UserNotVerified => Some("HEARTH_EMAIL_UNVERIFIED"),
            Self::PasswordExpired => Some("HEARTH_PASSWORD_EXPIRED"),
            Self::PasswordReused => Some("HEARTH_PASSWORD_REUSED"),
            Self::PasswordCompromised => Some("HEARTH_PASSWORD_COMPROMISED"),
            Self::AuthMethodNotAllowed { .. } => Some("HEARTH_AUTH_METHOD_NOT_ALLOWED"),
            Self::StepUpChallengeRequired => Some("HEARTH_STEP_UP_CHALLENGE_REQUIRED"),
            Self::EnrollMfaRequired => Some("HEARTH_ENROLL_MFA_REQUIRED"),
            Self::RequiredActionsBlocking { .. } => Some("HEARTH_REQUIRED_ACTIONS_PENDING"),
            Self::InvalidSmsOtp => Some("HEARTH_INVALID_SMS_OTP"),
            Self::SmsResendLimitExceeded => Some("HEARTH_SMS_RESEND_LIMIT_EXCEEDED"),
            Self::InvalidEmailOtp => Some("HEARTH_INVALID_EMAIL_OTP"),

            Self::RealmNotFound
            | Self::UserNotFound
            | Self::ClientNotFound
            | Self::WebhookNotFound
            | Self::ConsentNotFound
            | Self::DelegationGrantNotFound => Some("HEARTH_NOT_FOUND"),
            Self::SessionNotFound => Some("HEARTH_SESSION_NOT_FOUND"),
            Self::SessionVersionDisabled => Some("HEARTH_SESSION_VERSION_DISABLED"),

            Self::RealmSuspended => Some("HEARTH_REALM_SUSPENDED"),

            Self::InvalidInput { .. } | Self::InvalidAttribute { .. } => {
                Some("HEARTH_INVALID_INPUT")
            }

            Self::DuplicateEmail | Self::EmailReserved => Some("HEARTH_DUPLICATE_EMAIL"),
            Self::DuplicateRealmName => Some("HEARTH_DUPLICATE_REALM_NAME"),

            Self::OrganizationNotFound => Some("HEARTH_ORG_NOT_FOUND"),
            Self::OrganizationSuspended => Some("HEARTH_ORG_SUSPENDED"),
            Self::AlreadyMember => Some("HEARTH_ORG_ALREADY_MEMBER"),
            Self::NotAMember => Some("HEARTH_ORG_NOT_MEMBER"),
            Self::LastOwner => Some("HEARTH_ORG_LAST_OWNER"),
            Self::MemberLimitReached => Some("HEARTH_ORG_MEMBER_LIMIT"),
            Self::DuplicateOrgSlug => Some("HEARTH_ORG_DUPLICATE_SLUG"),

            Self::InvitationInvalid => Some("HEARTH_INVITATION_INVALID"),
            Self::DuplicateInvitation => Some("HEARTH_INVITATION_DUPLICATE"),

            Self::ReservedSlug { .. } => Some("HEARTH_RESERVED_SLUG"),
            Self::SlugInCooldown { .. } => Some("HEARTH_SLUG_IN_COOLDOWN"),

            Self::RegistrationDisabled => Some("HEARTH_REGISTRATION_DISABLED"),
            Self::RegistrationDomainNotAllowed { .. } => {
                Some("HEARTH_REGISTRATION_DOMAIN_NOT_ALLOWED")
            }
            Self::RegistrationRequiresInvitation => Some("HEARTH_REGISTRATION_REQUIRES_INVITATION"),

            Self::MagicLinkTokenInvalid => Some("HEARTH_MAGIC_LINK_INVALID"),
            Self::VerificationTokenInvalid => Some("HEARTH_VERIFICATION_TOKEN_INVALID"),
            Self::PasswordResetTokenInvalid => Some("HEARTH_PASSWORD_RESET_TOKEN_INVALID"),
            Self::EmailChangeTokenInvalid => Some("HEARTH_EMAIL_CHANGE_TOKEN_INVALID"),
            Self::SilentAuthRateLimited => Some("HEARTH_SILENT_AUTH_RATE_LIMITED"),

            Self::ConsentRequired => Some("HEARTH_CONSENT_REQUIRED"),
            Self::ConsentTicketNotFound | Self::ConsentTicketExpired => {
                Some("HEARTH_CONSENT_TICKET_INVALID")
            }
            Self::ConsentScopeNotRequested => Some("HEARTH_CONSENT_SCOPE_NOT_REQUESTED"),

            Self::FederationUnknownConnector => Some("HEARTH_FEDERATION_UNKNOWN_CONNECTOR"),
            Self::FederationInvalidState => Some("HEARTH_FEDERATION_INVALID_STATE"),
            Self::FederationUpstreamError { .. } => Some("HEARTH_FEDERATION_UPSTREAM_ERROR"),
            Self::FederationTokenVerificationFailed => {
                Some("HEARTH_FEDERATION_TOKEN_VERIFICATION_FAILED")
            }
            Self::FederationIdpMixup => Some("HEARTH_FEDERATION_IDP_MIXUP"),
            Self::FederationEmailNotVerified => Some("HEARTH_FEDERATION_EMAIL_NOT_VERIFIED"),
            Self::FederationLinkConfirmationRequired { .. } => {
                Some("HEARTH_FEDERATION_LINK_CONFIRMATION_REQUIRED")
            }
            Self::FederationNotLinked => Some("HEARTH_FEDERATION_NOT_LINKED"),
            Self::FederationAlreadyLinked => Some("HEARTH_FEDERATION_ALREADY_LINKED"),

            Self::DuplicateScimExternalId => Some("HEARTH_DUPLICATE_SCIM_EXTERNAL_ID"),

            Self::Unauthorized => Some("HEARTH_FORBIDDEN"),
            Self::SystemRealmProtected { .. } => Some("HEARTH_SYSTEM_REALM_PROTECTED"),

            Self::InvalidPushedAuthorizationRequest => Some("invalid_request"),
            Self::InvalidJar { .. } => Some("invalid_request_object"),
            Self::FapiViolation { .. } => Some("fapi_violation"),

            Self::InvalidDPopProof { .. } => Some("invalid_dpop_proof"),
            Self::DPopProofReplay | Self::DPopNonceInvalid => Some("use_dpop_nonce"),
            Self::DPopBindingMismatch => Some("invalid_token"),

            Self::AttestationPolicyViolation { .. } => Some("HEARTH_ATTESTATION_POLICY_VIOLATION"),

            Self::AgentNotFound => Some("agent_not_found"),
            Self::AgentRevoked => Some("agent_revoked"),
            Self::AgentCredentialNotFound => Some("agent_credential_not_found"),

            Self::PreTokenWebhookFailed { .. } => Some("HEARTH_PRE_TOKEN_WEBHOOK_FAILED"),

            Self::Saml(e) => e.wire_error_code(),

            // M2: protected resource + token exchange
            Self::ProtectedResourceNotFound => Some("protected_resource_not_found"),
            Self::DuplicateResourceUri => Some("duplicate_resource_uri"),
            Self::TokenExchangeRejected { oauth_error, .. } => Some(oauth_error),
            Self::DelegationDepthExceeded { .. } => Some("invalid_grant"),
            Self::EmptyScopeIntersection => Some("invalid_scope"),
            Self::ActorTokenReplayed => Some("invalid_grant"),
            // Phase C
            Self::ToolAccessDenied { .. } => Some("HEARTH_TOOL_ACCESS_DENIED"),
            Self::ToolApprovalRequired { .. } => Some("HEARTH_TOOL_APPROVAL_REQUIRED"),
            Self::ApprovalRequestNotFound => Some("HEARTH_APPROVAL_REQUEST_NOT_FOUND"),
            Self::ApprovalRequestNotPending { .. } => Some("HEARTH_APPROVAL_REQUEST_NOT_PENDING"),
            Self::ApprovalRequestExpired => Some("HEARTH_APPROVAL_REQUEST_EXPIRED"),
            // Phase D
            Self::AatScopeEscalation => Some("HEARTH_AAT_SCOPE_ESCALATION"),
            Self::AatChainBroken { .. } => Some("HEARTH_AAT_CHAIN_BROKEN"),
            Self::AatRevoked => Some("HEARTH_AAT_REVOKED"),
            Self::AatExpired => Some("HEARTH_AAT_EXPIRED"),
            Self::TransactionTokenReplayed => Some("HEARTH_TXN_TOKEN_REPLAYED"),
            Self::CrossRealmPolicyNotFound => Some("HEARTH_CROSS_REALM_POLICY_NOT_FOUND"),
            Self::CrossRealmPolicyConflict => Some("HEARTH_CROSS_REALM_POLICY_CONFLICT"),
            Self::CrossRealmCapabilityNotAllowed { .. } => {
                Some("HEARTH_CROSS_REALM_CAPABILITY_NOT_ALLOWED")
            }
            Self::SpiffeIdInvalid { .. } => Some("HEARTH_SPIFFE_ID_INVALID"),
            Self::SpiffeMappingNotFound => Some("HEARTH_SPIFFE_MAPPING_NOT_FOUND"),
            Self::SpiffeMappingConflict => Some("HEARTH_SPIFFE_MAPPING_CONFLICT"),
            Self::SpiffeCertInvalid { .. } => Some("HEARTH_SPIFFE_CERT_INVALID"),

            // 5xx — do not leak internal detail
            Self::SigningError { .. }
            | Self::Storage(_)
            | Self::Serialization { .. }
            | Self::Internal { .. }
            | Self::ConfigInvalid { .. }
            | Self::AuditFailure { .. } => None,
        }
    }
}
