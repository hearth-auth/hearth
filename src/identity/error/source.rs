//! `std::error::Error::source` impl for `IdentityError`.

use super::IdentityError;

impl std::error::Error for IdentityError {
    #[allow(clippy::too_many_lines)]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(&**err),
            Self::Saml(e) => e.source(),
            Self::RealmNotFound
            | Self::RealmSuspended
            | Self::DuplicateRealmName
            | Self::UserNotFound
            | Self::DuplicateEmail
            | Self::InvalidInput { .. }
            | Self::CredentialNotFound
            | Self::InvalidCredential { .. }
            | Self::SessionNotFound
            | Self::InvalidToken
            | Self::TokenExpired
            | Self::SigningError { .. }
            | Self::InvalidClient
            | Self::InvalidRedirectUri
            | Self::InvalidAuthorizationCode
            | Self::InvalidGrant { .. }
            | Self::InvalidClientSecret
            | Self::InvalidClientAssertion { .. }
            | Self::AuthorizationPending
            | Self::SlowDown
            | Self::DeviceCodeExpired
            | Self::DeviceCodeDenied
            | Self::TokenRevoked
            | Self::UnsupportedGrantType
            | Self::MfaRequired
            | Self::InvalidMfaCode
            | Self::MfaNotEnabled
            | Self::MfaAlreadyEnabled
            | Self::WebAuthnRegistrationFailed { .. }
            | Self::WebAuthnAuthenticationFailed { .. }
            | Self::WebAuthnCredentialNotFound
            | Self::InvalidAttestation { .. }
            | Self::InvalidAssertion { .. }
            | Self::Unauthorized
            | Self::ClientNotFound
            | Self::MagicLinkTokenInvalid
            | Self::VerificationTokenInvalid
            | Self::PasswordResetTokenInvalid
            | Self::UserNotVerified
            | Self::RateLimited
            | Self::OrganizationNotFound
            | Self::DuplicateOrgSlug
            | Self::OrganizationSuspended
            | Self::AlreadyMember
            | Self::NotAMember
            | Self::LastOwner
            | Self::MemberLimitReached
            | Self::InvitationInvalid
            | Self::DuplicateInvitation
            | Self::ReservedSlug { .. }
            | Self::SlugInCooldown { .. }
            | Self::RegistrationDisabled
            | Self::RegistrationDomainNotAllowed { .. }
            | Self::RegistrationRequiresInvitation
            | Self::ConsentRequired
            | Self::ConsentTicketNotFound
            | Self::ConsentTicketExpired
            | Self::ConsentScopeNotRequested
            | Self::ConsentNotFound
            | Self::DelegationGrantNotFound
            | Self::FederationUnknownConnector
            | Self::FederationInvalidState
            | Self::FederationUpstreamError { .. }
            | Self::FederationTokenVerificationFailed
            | Self::FederationIdpMixup
            | Self::FederationEmailNotVerified
            | Self::FederationLinkConfirmationRequired { .. }
            | Self::FederationNotLinked
            | Self::FederationAlreadyLinked
            | Self::SystemRealmProtected { .. }
            | Self::DuplicateScimExternalId
            | Self::ConfigInvalid { .. }
            | Self::Serialization { .. }
            | Self::Internal { .. }
            | Self::TokenTooLarge { .. }
            | Self::InvalidAttribute { .. }
            | Self::AuditFailure { .. }
            | Self::PasswordExpired
            | Self::PasswordReused
            | Self::PasswordCompromised
            | Self::AuthMethodNotAllowed { .. }
            | Self::WebhookNotFound
            | Self::StepUpChallengeRequired
            | Self::EnrollMfaRequired
            | Self::RequiredActionsBlocking { .. }
            | Self::InvalidSmsOtp
            | Self::SmsResendLimitExceeded
            | Self::InvalidEmailOtp
            | Self::InvalidPushedAuthorizationRequest
            | Self::InvalidDPopProof { .. }
            | Self::DPopProofReplay
            | Self::DPopBindingMismatch
            | Self::DPopNonceInvalid
            | Self::DPopJktBlocked
            | Self::JwtBearerAssertionInvalid { .. }
            | Self::InvalidJar { .. }
            | Self::SessionVersionDisabled
            | Self::SessionLimitExceeded { .. }
            | Self::FapiViolation { .. }
            | Self::EmailReserved
            | Self::EmailChangeTokenInvalid
            | Self::SilentAuthRateLimited
            | Self::QuotaExceeded { .. }
            | Self::AttestationPolicyViolation { .. }
            | Self::AgentNotFound
            | Self::AgentRevoked
            | Self::AgentCredentialNotFound
            | Self::PreTokenWebhookFailed { .. }
            // M2
            | Self::ProtectedResourceNotFound
            | Self::DuplicateResourceUri
            | Self::TokenExchangeRejected { .. }
            | Self::DelegationDepthExceeded { .. }
            | Self::EmptyScopeIntersection
            | Self::ActorTokenReplayed
            // Phase C
            | Self::ToolAccessDenied { .. }
            | Self::ToolApprovalRequired { .. }
            | Self::ApprovalRequestNotFound
            | Self::ApprovalRequestNotPending { .. }
            | Self::ApprovalRequestExpired
            // Phase D
            | Self::AatScopeEscalation
            | Self::AatChainBroken { .. }
            | Self::AatRevoked
            | Self::AatExpired
            | Self::TransactionTokenReplayed
            | Self::CrossRealmPolicyNotFound
            | Self::CrossRealmPolicyConflict
            | Self::CrossRealmCapabilityNotAllowed { .. }
            | Self::SpiffeIdInvalid { .. }
            | Self::SpiffeMappingNotFound
            | Self::SpiffeMappingConflict
            | Self::SpiffeCertInvalid { .. }
            | Self::SpiffeCertExpired => None,
        }
    }
}
