//! `Display` impl for `IdentityError`.

use std::fmt;

use super::IdentityError;

#[allow(clippy::too_many_lines)]
impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RealmNotFound => write!(f, "realm not found"),
            Self::RealmSuspended => write!(f, "realm is suspended"),
            Self::DuplicateRealmName => write!(f, "a realm with this name already exists"),
            Self::UserNotFound => write!(f, "user not found"),
            Self::DuplicateEmail => write!(f, "a user with this email already exists"),
            Self::InvalidInput { reason } => write!(f, "invalid input: {reason}"),
            Self::CredentialNotFound => write!(f, "no credential found for this user"),
            Self::InvalidCredential { reason } => write!(f, "invalid credential: {reason}"),
            Self::SessionNotFound => write!(f, "session not found"),
            Self::SessionVersionDisabled => {
                write!(f, "session versioning is not enabled for this realm")
            }
            Self::InvalidToken => write!(f, "invalid token"),
            Self::TokenExpired => write!(f, "token expired"),
            Self::SigningError { reason } => write!(f, "signing error: {reason}"),
            Self::InvalidClient => write!(f, "invalid client"),
            Self::InvalidRedirectUri => write!(f, "invalid redirect URI"),
            Self::InvalidAuthorizationCode => write!(f, "invalid authorization code"),
            Self::InvalidGrant { reason } => write!(f, "invalid grant: {reason}"),
            Self::InvalidClientSecret => write!(f, "invalid client secret"),
            Self::InvalidClientAssertion { reason } => {
                write!(f, "invalid client assertion: {reason}")
            }
            Self::InvalidJar { reason } => write!(f, "invalid request object (JAR): {reason}"),
            Self::AuthorizationPending => write!(f, "authorization pending"),
            Self::SlowDown => write!(f, "polling too frequently"),
            Self::DeviceCodeExpired => write!(f, "device code expired"),
            Self::DeviceCodeDenied => write!(f, "device authorization denied"),
            Self::TokenRevoked => write!(f, "token has been revoked"),
            Self::UnsupportedGrantType => write!(f, "unsupported grant type"),
            Self::MfaRequired => write!(f, "MFA verification required"),
            Self::InvalidMfaCode => write!(f, "invalid MFA code"),
            Self::MfaNotEnabled => write!(f, "MFA is not enabled for this user"),
            Self::MfaAlreadyEnabled => write!(f, "MFA is already enabled"),
            Self::WebAuthnRegistrationFailed { reason } => {
                write!(f, "WebAuthn registration failed: {reason}")
            }
            Self::WebAuthnAuthenticationFailed { reason } => {
                write!(f, "WebAuthn authentication failed: {reason}")
            }
            Self::WebAuthnCredentialNotFound => write!(f, "WebAuthn credential not found"),
            Self::InvalidAttestation { reason } => write!(f, "invalid attestation: {reason}"),
            Self::InvalidAssertion { reason } => write!(f, "invalid assertion: {reason}"),
            Self::Unauthorized => write!(f, "forbidden"),
            Self::ClientNotFound => write!(f, "client not found"),
            Self::MagicLinkTokenInvalid => write!(f, "invalid or expired magic link"),
            Self::VerificationTokenInvalid => write!(f, "invalid or expired verification link"),
            Self::PasswordResetTokenInvalid => {
                write!(f, "invalid or expired password reset link")
            }
            Self::UserNotVerified => write!(f, "user email not verified"),
            Self::RateLimited => write!(f, "too many failed attempts"),
            Self::OrganizationNotFound => write!(f, "organization not found"),
            Self::DuplicateOrgSlug => {
                write!(f, "an organization with this slug already exists")
            }
            Self::OrganizationSuspended => write!(f, "organization is suspended"),
            Self::AlreadyMember => write!(f, "user is already a member of this organization"),
            Self::NotAMember => write!(f, "user is not a member of this organization"),
            Self::LastOwner => write!(f, "cannot remove the last owner of an organization"),
            Self::MemberLimitReached => write!(f, "organization member limit reached"),
            Self::InvitationInvalid => write!(f, "invalid or expired invitation"),
            Self::DuplicateInvitation => {
                write!(f, "an invitation for this email already exists")
            }
            Self::ReservedSlug { slug } => {
                write!(f, "name or slug '{slug}' is reserved and cannot be used")
            }
            Self::SlugInCooldown { slug } => write!(
                f,
                "name or slug '{slug}' is in a post-delete cooldown and cannot be reused yet"
            ),
            Self::SystemRealmProtected { operation } => write!(
                f,
                "operation not permitted on the system realm: {operation}"
            ),
            Self::RegistrationDisabled => write!(f, "self-service registration is disabled"),
            Self::RegistrationDomainNotAllowed { domain } => write!(
                f,
                "email domain is not permitted for self-service registration: {domain}"
            ),
            Self::RegistrationRequiresInvitation => {
                write!(f, "self-service registration requires a valid invitation")
            }
            Self::ConsentRequired => write!(f, "user consent is required"),
            Self::ConsentTicketNotFound => write!(f, "consent ticket not found"),
            Self::ConsentTicketExpired => write!(f, "consent ticket expired"),
            Self::ConsentScopeNotRequested => {
                write!(f, "approved scope was not in the original request")
            }
            Self::ConsentNotFound => write!(f, "no consent record for this client"),
            Self::DelegationGrantNotFound => write!(f, "no delegation grant record found"),
            Self::FederationUnknownConnector => write!(f, "unknown federation connector"),
            Self::FederationInvalidState => write!(f, "invalid federation state"),
            Self::FederationUpstreamError { provider, reason } => {
                write!(f, "federation upstream error ({provider}): {reason}")
            }
            Self::FederationTokenVerificationFailed => {
                write!(f, "federation token verification failed")
            }
            Self::FederationIdpMixup => {
                write!(f, "federation IdP-mixup: iss parameter mismatch")
            }
            Self::FederationEmailNotVerified => write!(f, "upstream email is not verified"),
            Self::FederationLinkConfirmationRequired { .. } => {
                write!(f, "federation login requires confirm-to-link")
            }
            Self::FederationNotLinked => write!(f, "external identity is not linked"),
            Self::FederationAlreadyLinked => write!(f, "external identity is already linked"),
            Self::DuplicateScimExternalId => {
                write!(f, "SCIM externalId is already associated with another user")
            }
            Self::ConfigInvalid { realm_name, errors } => write!(
                f,
                "realm '{realm_name}' config is invalid ({} error(s)): {}",
                errors.len(),
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Self::Storage(err) => write!(f, "storage error: {err}"),
            Self::Serialization { reason } => write!(f, "serialization error: {reason}"),
            Self::Internal { reason } => write!(f, "internal error: {reason}"),
            Self::TokenTooLarge {
                limit,
                limit_value,
                actual,
            } => write!(
                f,
                "resolved claim set exceeds size limit {limit} ({actual} > {limit_value})"
            ),
            Self::InvalidAttribute { reason } => write!(f, "invalid attribute: {reason}"),
            Self::AuditFailure { action, reason } => write!(
                f,
                "audit append failed for destructive action '{action}': {reason}"
            ),
            Self::PasswordExpired => write!(f, "password has expired and must be reset"),
            Self::PasswordReused => {
                write!(f, "password was recently used and cannot be reused")
            }
            Self::AuthMethodNotAllowed { method } => write!(
                f,
                "authentication method '{method}' is not permitted by realm policy"
            ),
            Self::WebhookNotFound => write!(f, "webhook not found"),
            Self::PasswordCompromised => {
                write!(f, "password has appeared in a known data breach")
            }
            Self::StepUpChallengeRequired => {
                write!(f, "MFA challenge required: login from unrecognised device")
            }
            Self::EnrollMfaRequired => write!(
                f,
                "MFA enrollment required: login from unrecognised device with no enrolled factor"
            ),
            Self::RequiredActionsBlocking { actions } => {
                write!(f, "token blocked: pending required actions: {actions:?}")
            }
            Self::InvalidSmsOtp => write!(f, "invalid or expired SMS OTP"),
            Self::SmsResendLimitExceeded => {
                write!(f, "SMS OTP resend limit exceeded for this phone number")
            }
            Self::InvalidEmailOtp => write!(f, "invalid or expired email OTP"),
            Self::InvalidPushedAuthorizationRequest => {
                write!(f, "invalid, expired, or already used request_uri")
            }
            Self::InvalidDPopProof { reason } => write!(f, "invalid DPoP proof: {reason}"),
            Self::DPopProofReplay => write!(f, "DPoP proof JTI already used"),
            Self::DPopBindingMismatch => {
                write!(f, "DPoP proof key does not match token cnf.jkt binding")
            }
            Self::DPopNonceInvalid => write!(f, "DPoP proof nonce invalid or expired"),
            Self::JwtBearerAssertionInvalid { reason } => {
                write!(f, "invalid JWT bearer assertion: {reason}")
            }
            Self::FapiViolation { reason } => write!(f, "FAPI 2.0 violation: {reason}"),
            Self::EmailReserved => write!(
                f,
                "a user with this email already exists or was recently deleted"
            ),
            Self::EmailChangeTokenInvalid => {
                write!(f, "email change token is invalid or has expired")
            }
            Self::SilentAuthRateLimited => {
                write!(f, "too many silent-auth requests; slow down")
            }
            Self::SessionLimitExceeded { limit, active } => write!(
                f,
                "session limit exceeded: {active} active sessions, limit is {limit}"
            ),
            Self::QuotaExceeded {
                resource,
                limit,
                current,
            } => write!(
                f,
                "realm quota exceeded: {resource} count is {current}, limit is {limit}"
            ),
            Self::AttestationPolicyViolation { reason } => {
                write!(f, "attestation policy violation: {reason}")
            }
            Self::AgentNotFound => write!(f, "agent not found"),
            Self::AgentRevoked => write!(f, "agent has been permanently revoked"),
            Self::AgentCredentialNotFound => write!(f, "agent credential not found"),
            Self::PreTokenWebhookFailed { reason } => {
                write!(f, "pre-token webhook failed: {reason}")
            }
            Self::Saml(e) => write!(f, "{e}"),
            // M2
            Self::ProtectedResourceNotFound => write!(f, "protected resource not found"),
            Self::DuplicateResourceUri => {
                write!(
                    f,
                    "a protected resource with this URI already exists in this realm"
                )
            }
            Self::TokenExchangeRejected { oauth_error, .. } => {
                write!(f, "token exchange rejected: {oauth_error}")
            }
            Self::DelegationDepthExceeded { max, attempted } => write!(
                f,
                "delegation depth {attempted} exceeds agent maximum {max}"
            ),
            Self::EmptyScopeIntersection => {
                write!(f, "scope intersection is empty — exchange rejected")
            }
            Self::ActorTokenReplayed => write!(f, "actor token jti has already been used"),
            // Phase C
            Self::ToolAccessDenied { tool } => {
                write!(f, "access to tool `{tool}` is explicitly denied")
            }
            Self::ToolApprovalRequired { tool } => {
                write!(f, "tool `{tool}` requires human approval")
            }
            Self::ApprovalRequestNotFound => write!(f, "approval request not found"),
            Self::ApprovalRequestNotPending { current_status } => write!(
                f,
                "approval request is not pending (current status: {current_status})"
            ),
            Self::ApprovalRequestExpired => write!(f, "approval request has expired"),
            // Phase D
            Self::AatScopeEscalation => {
                write!(f, "AAT derivation rejected: child scope exceeds parent")
            }
            Self::AatChainBroken { reason } => write!(f, "AAT chain invalid: {reason}"),
            Self::AatRevoked => write!(f, "AAT or an ancestor in the chain has been revoked"),
            Self::AatExpired => write!(f, "AAT has expired"),
            Self::TransactionTokenReplayed => {
                write!(f, "transaction token has already been consumed")
            }
            Self::CrossRealmPolicyNotFound => write!(f, "cross-realm trust policy not found"),
            Self::CrossRealmPolicyConflict => {
                write!(f, "a cross-realm trust policy already exists for this pair")
            }
            Self::CrossRealmCapabilityNotAllowed { capability } => {
                write!(
                    f,
                    "capability `{capability}` is not permitted by the cross-realm trust policy"
                )
            }
            Self::SpiffeIdInvalid { reason } => write!(f, "SPIFFE ID invalid: {reason}"),
            Self::SpiffeMappingNotFound => write!(f, "SPIFFE identity mapping not found"),
            Self::SpiffeMappingConflict => {
                write!(f, "a SPIFFE mapping already exists for this agent")
            }
            Self::SpiffeCertInvalid { reason } => {
                write!(f, "SPIFFE X.509 certificate invalid: {reason}")
            }
            Self::SpiffeCertExpired => write!(f, "SPIFFE X.509 certificate has expired"),
        }
    }
}
