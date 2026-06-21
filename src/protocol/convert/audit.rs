//! Audit type conversions: domain <-> proto wire types.

use crate::audit::{self as domain};
use crate::protocol::proto::events::v1 as pb;

// ==================== AuditAction ====================

/// Converts domain `AuditAction` to proto enum value.
#[allow(clippy::too_many_lines)]
pub(crate) fn domain_audit_action_to_proto(a: &domain::AuditAction) -> pb::AuditAction {
    match a {
        domain::AuditAction::UserCreated => pb::AuditAction::UserCreated,
        domain::AuditAction::UserUpdated => pb::AuditAction::UserUpdated,
        domain::AuditAction::UserDeleted => pb::AuditAction::UserDeleted,
        domain::AuditAction::CredentialSet => pb::AuditAction::CredentialSet,
        domain::AuditAction::CredentialChanged => pb::AuditAction::CredentialChanged,
        domain::AuditAction::CredentialVerified => pb::AuditAction::CredentialVerified,
        domain::AuditAction::SessionCreated => pb::AuditAction::SessionCreated,
        domain::AuditAction::SessionRevoked => pb::AuditAction::SessionRevoked,
        domain::AuditAction::TokenIssued => pb::AuditAction::TokenIssued,
        domain::AuditAction::TokenRefreshed => pb::AuditAction::TokenRefreshed,
        domain::AuditAction::RealmCreated => pb::AuditAction::RealmCreated,
        domain::AuditAction::RealmUpdated => pb::AuditAction::RealmUpdated,
        domain::AuditAction::RealmDeleted => pb::AuditAction::RealmDeleted,
        domain::AuditAction::ClientRegistered => pb::AuditAction::ClientRegistered,
        domain::AuditAction::AuthorizationCodeIssued => pb::AuditAction::AuthorizationCodeIssued,
        domain::AuditAction::AuthorizationCodeExchanged => {
            pb::AuditAction::AuthorizationCodeExchanged
        }
        domain::AuditAction::TupleWritten => pb::AuditAction::TupleWritten,
        domain::AuditAction::TupleDeleted => pb::AuditAction::TupleDeleted,
        domain::AuditAction::ClientUpdated => pb::AuditAction::ClientUpdated,
        domain::AuditAction::ClientDeleted => pb::AuditAction::ClientDeleted,
        domain::AuditAction::BulkUsersCreated => pb::AuditAction::BulkUsersCreated,
        domain::AuditAction::BulkUsersDisabled => pb::AuditAction::BulkUsersDisabled,
        domain::AuditAction::OrgCreated => pb::AuditAction::OrgCreated,
        domain::AuditAction::OrgUpdated => pb::AuditAction::OrgUpdated,
        domain::AuditAction::OrgDeleted => pb::AuditAction::OrgDeleted,
        domain::AuditAction::ConsentGranted => pb::AuditAction::ConsentGranted,
        domain::AuditAction::ConsentDenied => pb::AuditAction::ConsentDenied,
        domain::AuditAction::ConsentRevoked => pb::AuditAction::ConsentRevoked,
        domain::AuditAction::FederationLoginStarted => pb::AuditAction::FederationLoginStarted,
        domain::AuditAction::FederationLoginCompleted => pb::AuditAction::FederationLoginCompleted,
        domain::AuditAction::FederationAccountLinked => pb::AuditAction::FederationAccountLinked,
        domain::AuditAction::FederationAccountUnlinked => {
            pb::AuditAction::FederationAccountUnlinked
        }
        domain::AuditAction::FederationJitProvisioned => pb::AuditAction::FederationJitProvisioned,
        domain::AuditAction::SamlLoginInitiated => pb::AuditAction::SamlLoginInitiated,
        domain::AuditAction::SamlLoginCompleted => pb::AuditAction::SamlLoginCompleted,
        domain::AuditAction::SamlLoginFailed => pb::AuditAction::SamlLoginFailed,
        domain::AuditAction::SamlIdpAuthnRequestReceived => {
            pb::AuditAction::SamlIdpAuthnRequestReceived
        }
        domain::AuditAction::SamlIdpResponseIssued => pb::AuditAction::SamlIdpResponseIssued,
        domain::AuditAction::SamlIdpInitiatedSso => pb::AuditAction::SamlIdpInitiatedSso,
        domain::AuditAction::SamlSloRequested => pb::AuditAction::SamlSloRequested,
        domain::AuditAction::SamlSloCompleted => pb::AuditAction::SamlSloCompleted,
        domain::AuditAction::ScimUserCreated => pb::AuditAction::ScimUserCreated,
        domain::AuditAction::ScimUserUpdated => pb::AuditAction::ScimUserUpdated,
        domain::AuditAction::ScimUserDeleted => pb::AuditAction::ScimUserDeleted,
        domain::AuditAction::ScimGroupCreated => pb::AuditAction::ScimGroupCreated,
        domain::AuditAction::ScimGroupUpdated => pb::AuditAction::ScimGroupUpdated,
        domain::AuditAction::ScimGroupDeleted => pb::AuditAction::ScimGroupDeleted,
        domain::AuditAction::RoleAssigned => pb::AuditAction::RoleAssigned,
        domain::AuditAction::RoleRevoked => pb::AuditAction::RoleRevoked,
        domain::AuditAction::Cleanup => pb::AuditAction::Cleanup,
        // RBAC group management
        domain::AuditAction::GroupCreated => pb::AuditAction::GroupCreated,
        domain::AuditAction::GroupUpdated => pb::AuditAction::GroupUpdated,
        domain::AuditAction::GroupDeleted => pb::AuditAction::GroupDeleted,
        domain::AuditAction::GroupMemberAdded => pb::AuditAction::GroupMemberAdded,
        domain::AuditAction::GroupMemberRemoved => pb::AuditAction::GroupMemberRemoved,
        domain::AuditAction::GroupMemberRoleChanged => pb::AuditAction::GroupMemberRoleChanged,
        // Permission management
        domain::AuditAction::OrphanedReferenceSkipped => pb::AuditAction::OrphanedReferenceSkipped,
        domain::AuditAction::UserPermissionGranted => pb::AuditAction::UserPermissionGranted,
        domain::AuditAction::UserPermissionRevoked => pb::AuditAction::UserPermissionRevoked,
        domain::AuditAction::ClientConsentGranted => pb::AuditAction::ClientConsentGranted,
        domain::AuditAction::ClientConsentRevoked => pb::AuditAction::ClientConsentRevoked,
        domain::AuditAction::ConsentRequiredOnRefresh => pb::AuditAction::ConsentRequiredOnRefresh,
        // Login events
        domain::AuditAction::LoginFailed => pb::AuditAction::LoginFailed,
        domain::AuditAction::LoginLocked => pb::AuditAction::LoginLocked,
        domain::AuditAction::IpLoginLimitExceeded => pb::AuditAction::IpLoginLimitExceeded,
        // Backup and export
        domain::AuditAction::BackupCreated => pb::AuditAction::BackupCreated,
        domain::AuditAction::BackupRestored => pb::AuditAction::BackupRestored,
        domain::AuditAction::RealmExportWatermarked => pb::AuditAction::RealmExportWatermarked,
        // Required actions
        domain::AuditAction::RequiredActionAssigned => pb::AuditAction::RequiredActionAssigned,
        domain::AuditAction::RequiredActionRemoved => pb::AuditAction::RequiredActionRemoved,
        domain::AuditAction::RequiredActionCompleted => pb::AuditAction::RequiredActionCompleted,
        domain::AuditAction::RequiredActionAutoCleared => {
            pb::AuditAction::RequiredActionAutoCleared
        }
        // Password security
        domain::AuditAction::PasswordCompromisedRejected => {
            pb::AuditAction::PasswordCompromisedRejected
        }
        domain::AuditAction::BreachCheckUnavailable => pb::AuditAction::BreachCheckUnavailable,
        // Adaptive MFA / step-up
        domain::AuditAction::StepUpMfaTriggered => pb::AuditAction::StepUpMfaTriggered,
        domain::AuditAction::StepUpMfaCompleted => pb::AuditAction::StepUpMfaCompleted,
        // SMS OTP enrollment
        domain::AuditAction::SmsOtpEnrollmentStarted => pb::AuditAction::SmsOtpEnrollmentStarted,
        domain::AuditAction::SmsOtpEnrollmentVerified => pb::AuditAction::SmsOtpEnrollmentVerified,
        domain::AuditAction::SmsOtpEnrollmentFailed => pb::AuditAction::SmsOtpEnrollmentFailed,
        // SMS MFA challenges
        domain::AuditAction::SmsMfaChallengeSucceeded => pb::AuditAction::SmsMfaChallengeSucceeded,
        domain::AuditAction::SmsMfaChallengeFailed => pb::AuditAction::SmsMfaChallengeFailed,
        domain::AuditAction::SmsMfaLocked => pb::AuditAction::SmsMfaLocked,
        // Device fingerprints
        domain::AuditAction::DeviceFingerprintsErased => pb::AuditAction::DeviceFingerprintsErased,
        // Session management
        domain::AuditAction::SessionLimitEnforced => pb::AuditAction::SessionLimitEnforced,
        domain::AuditAction::SessionsRevoked => pb::AuditAction::SessionsRevoked,
        domain::AuditAction::SessionEvicted => pb::AuditAction::SessionEvicted,
        // Abuse detection
        domain::AuditAction::AbuseDetected => pb::AuditAction::AbuseDetected,
        // Email change
        domain::AuditAction::EmailChangeInitiated => pb::AuditAction::EmailChangeInitiated,
        domain::AuditAction::EmailChangeConfirmed => pb::AuditAction::EmailChangeConfirmed,
        // OIDC silent auth
        domain::AuditAction::OidcSilentAuthProbed => pb::AuditAction::OidcSilentAuthProbed,
        // Agent lifecycle
        domain::AuditAction::AgentCreated => pb::AuditAction::AgentCreated,
        domain::AuditAction::AgentUpdated => pb::AuditAction::AgentUpdated,
        domain::AuditAction::AgentSuspended => pb::AuditAction::AgentSuspended,
        domain::AuditAction::AgentReactivated => pb::AuditAction::AgentReactivated,
        domain::AuditAction::AgentRevoked => pb::AuditAction::AgentRevoked,
        domain::AuditAction::AgentDeleted => pb::AuditAction::AgentDeleted,
        domain::AuditAction::AgentCredentialCreated => pb::AuditAction::AgentCredentialCreated,
        domain::AuditAction::AgentCredentialRevoked => pb::AuditAction::AgentCredentialRevoked,
        // Agent delegation and MCP (M2)
        domain::AuditAction::AgentDelegation => pb::AuditAction::AgentDelegation,
        domain::AuditAction::AgentToolInvocation => pb::AuditAction::AgentToolInvocation,
        domain::AuditAction::ApprovalRequested => pb::AuditAction::ApprovalRequested,
        domain::AuditAction::ApprovalGranted => pb::AuditAction::ApprovalGranted,
        domain::AuditAction::ApprovalDenied => pb::AuditAction::ApprovalDenied,
        domain::AuditAction::AgentTokenRevoked => pb::AuditAction::AgentTokenRevoked,
        domain::AuditAction::CrossRealmTrustCreated => pb::AuditAction::CrossRealmTrustCreated,
        domain::AuditAction::CrossRealmTrustRevoked => pb::AuditAction::CrossRealmTrustRevoked,
        domain::AuditAction::ProtectedResourceRegistered => {
            pb::AuditAction::ProtectedResourceRegistered
        }
        domain::AuditAction::ProtectedResourceUpdated => pb::AuditAction::ProtectedResourceUpdated,
        domain::AuditAction::ProtectedResourceDeleted => pb::AuditAction::ProtectedResourceDeleted,
        // Phase D actions — proto variants now available.
        domain::AuditAction::AatIssued => pb::AuditAction::AatIssued,
        domain::AuditAction::AatRevoked => pb::AuditAction::AatRevoked,
        domain::AuditAction::TransactionTokenIssued => pb::AuditAction::TransactionTokenIssued,
        domain::AuditAction::CrossRealmTokenIssued => pb::AuditAction::CrossRealmTokenIssued,
        domain::AuditAction::SpiffeIdMapped => pb::AuditAction::SpiffeIdMapped,
        domain::AuditAction::SpiffeAuthSuccess => pb::AuditAction::SpiffeAuthSuccess,
    }
}

// ==================== Reverse mapping ====================

/// Converts a proto `AuditAction` enum value to the domain type.
///
/// Returns `None` for `Unspecified` and any future unknown variant received
/// from a newer server — callers should treat `None` as "action not recognized".
#[must_use]
#[allow(clippy::too_many_lines)]
pub(crate) fn proto_audit_action_to_domain(a: pb::AuditAction) -> Option<domain::AuditAction> {
    match a {
        pb::AuditAction::Unspecified => None,
        pb::AuditAction::UserCreated => Some(domain::AuditAction::UserCreated),
        pb::AuditAction::UserUpdated => Some(domain::AuditAction::UserUpdated),
        pb::AuditAction::UserDeleted => Some(domain::AuditAction::UserDeleted),
        pb::AuditAction::CredentialSet => Some(domain::AuditAction::CredentialSet),
        pb::AuditAction::CredentialChanged => Some(domain::AuditAction::CredentialChanged),
        pb::AuditAction::CredentialVerified => Some(domain::AuditAction::CredentialVerified),
        pb::AuditAction::SessionCreated => Some(domain::AuditAction::SessionCreated),
        pb::AuditAction::SessionRevoked => Some(domain::AuditAction::SessionRevoked),
        pb::AuditAction::TokenIssued => Some(domain::AuditAction::TokenIssued),
        pb::AuditAction::TokenRefreshed => Some(domain::AuditAction::TokenRefreshed),
        pb::AuditAction::RealmCreated => Some(domain::AuditAction::RealmCreated),
        pb::AuditAction::RealmUpdated => Some(domain::AuditAction::RealmUpdated),
        pb::AuditAction::RealmDeleted => Some(domain::AuditAction::RealmDeleted),
        pb::AuditAction::ClientRegistered => Some(domain::AuditAction::ClientRegistered),
        pb::AuditAction::AuthorizationCodeIssued => {
            Some(domain::AuditAction::AuthorizationCodeIssued)
        }
        pb::AuditAction::AuthorizationCodeExchanged => {
            Some(domain::AuditAction::AuthorizationCodeExchanged)
        }
        pb::AuditAction::TupleWritten => Some(domain::AuditAction::TupleWritten),
        pb::AuditAction::TupleDeleted => Some(domain::AuditAction::TupleDeleted),
        pb::AuditAction::ClientUpdated => Some(domain::AuditAction::ClientUpdated),
        pb::AuditAction::ClientDeleted => Some(domain::AuditAction::ClientDeleted),
        pb::AuditAction::BulkUsersCreated => Some(domain::AuditAction::BulkUsersCreated),
        pb::AuditAction::BulkUsersDisabled => Some(domain::AuditAction::BulkUsersDisabled),
        pb::AuditAction::OrgCreated => Some(domain::AuditAction::OrgCreated),
        pb::AuditAction::OrgUpdated => Some(domain::AuditAction::OrgUpdated),
        pb::AuditAction::OrgDeleted => Some(domain::AuditAction::OrgDeleted),
        pb::AuditAction::ConsentGranted => Some(domain::AuditAction::ConsentGranted),
        pb::AuditAction::ConsentDenied => Some(domain::AuditAction::ConsentDenied),
        pb::AuditAction::ConsentRevoked => Some(domain::AuditAction::ConsentRevoked),
        pb::AuditAction::FederationLoginStarted => {
            Some(domain::AuditAction::FederationLoginStarted)
        }
        pb::AuditAction::FederationLoginCompleted => {
            Some(domain::AuditAction::FederationLoginCompleted)
        }
        pb::AuditAction::FederationAccountLinked => {
            Some(domain::AuditAction::FederationAccountLinked)
        }
        pb::AuditAction::FederationAccountUnlinked => {
            Some(domain::AuditAction::FederationAccountUnlinked)
        }
        pb::AuditAction::FederationJitProvisioned => {
            Some(domain::AuditAction::FederationJitProvisioned)
        }
        pb::AuditAction::SamlLoginInitiated => Some(domain::AuditAction::SamlLoginInitiated),
        pb::AuditAction::SamlLoginCompleted => Some(domain::AuditAction::SamlLoginCompleted),
        pb::AuditAction::SamlLoginFailed => Some(domain::AuditAction::SamlLoginFailed),
        pb::AuditAction::SamlIdpAuthnRequestReceived => {
            Some(domain::AuditAction::SamlIdpAuthnRequestReceived)
        }
        pb::AuditAction::SamlIdpResponseIssued => Some(domain::AuditAction::SamlIdpResponseIssued),
        pb::AuditAction::SamlIdpInitiatedSso => Some(domain::AuditAction::SamlIdpInitiatedSso),
        pb::AuditAction::SamlSloRequested => Some(domain::AuditAction::SamlSloRequested),
        pb::AuditAction::SamlSloCompleted => Some(domain::AuditAction::SamlSloCompleted),
        pb::AuditAction::ScimUserCreated => Some(domain::AuditAction::ScimUserCreated),
        pb::AuditAction::ScimUserUpdated => Some(domain::AuditAction::ScimUserUpdated),
        pb::AuditAction::ScimUserDeleted => Some(domain::AuditAction::ScimUserDeleted),
        pb::AuditAction::ScimGroupCreated => Some(domain::AuditAction::ScimGroupCreated),
        pb::AuditAction::ScimGroupUpdated => Some(domain::AuditAction::ScimGroupUpdated),
        pb::AuditAction::ScimGroupDeleted => Some(domain::AuditAction::ScimGroupDeleted),
        pb::AuditAction::RoleAssigned => Some(domain::AuditAction::RoleAssigned),
        pb::AuditAction::RoleRevoked => Some(domain::AuditAction::RoleRevoked),
        pb::AuditAction::Cleanup => Some(domain::AuditAction::Cleanup),
        pb::AuditAction::GroupCreated => Some(domain::AuditAction::GroupCreated),
        pb::AuditAction::GroupUpdated => Some(domain::AuditAction::GroupUpdated),
        pb::AuditAction::GroupDeleted => Some(domain::AuditAction::GroupDeleted),
        pb::AuditAction::GroupMemberAdded => Some(domain::AuditAction::GroupMemberAdded),
        pb::AuditAction::GroupMemberRemoved => Some(domain::AuditAction::GroupMemberRemoved),
        pb::AuditAction::GroupMemberRoleChanged => {
            Some(domain::AuditAction::GroupMemberRoleChanged)
        }
        pb::AuditAction::OrphanedReferenceSkipped => {
            Some(domain::AuditAction::OrphanedReferenceSkipped)
        }
        pb::AuditAction::UserPermissionGranted => Some(domain::AuditAction::UserPermissionGranted),
        pb::AuditAction::UserPermissionRevoked => Some(domain::AuditAction::UserPermissionRevoked),
        pb::AuditAction::ClientConsentGranted => Some(domain::AuditAction::ClientConsentGranted),
        pb::AuditAction::ClientConsentRevoked => Some(domain::AuditAction::ClientConsentRevoked),
        pb::AuditAction::ConsentRequiredOnRefresh => {
            Some(domain::AuditAction::ConsentRequiredOnRefresh)
        }
        pb::AuditAction::LoginFailed => Some(domain::AuditAction::LoginFailed),
        pb::AuditAction::LoginLocked => Some(domain::AuditAction::LoginLocked),
        pb::AuditAction::IpLoginLimitExceeded => Some(domain::AuditAction::IpLoginLimitExceeded),
        pb::AuditAction::BackupCreated => Some(domain::AuditAction::BackupCreated),
        pb::AuditAction::BackupRestored => Some(domain::AuditAction::BackupRestored),
        pb::AuditAction::RealmExportWatermarked => {
            Some(domain::AuditAction::RealmExportWatermarked)
        }
        pb::AuditAction::RequiredActionAssigned => {
            Some(domain::AuditAction::RequiredActionAssigned)
        }
        pb::AuditAction::RequiredActionRemoved => Some(domain::AuditAction::RequiredActionRemoved),
        pb::AuditAction::RequiredActionCompleted => {
            Some(domain::AuditAction::RequiredActionCompleted)
        }
        pb::AuditAction::RequiredActionAutoCleared => {
            Some(domain::AuditAction::RequiredActionAutoCleared)
        }
        pb::AuditAction::PasswordCompromisedRejected => {
            Some(domain::AuditAction::PasswordCompromisedRejected)
        }
        pb::AuditAction::BreachCheckUnavailable => {
            Some(domain::AuditAction::BreachCheckUnavailable)
        }
        pb::AuditAction::StepUpMfaTriggered => Some(domain::AuditAction::StepUpMfaTriggered),
        pb::AuditAction::StepUpMfaCompleted => Some(domain::AuditAction::StepUpMfaCompleted),
        pb::AuditAction::SmsOtpEnrollmentStarted => {
            Some(domain::AuditAction::SmsOtpEnrollmentStarted)
        }
        pb::AuditAction::SmsOtpEnrollmentVerified => {
            Some(domain::AuditAction::SmsOtpEnrollmentVerified)
        }
        pb::AuditAction::SmsOtpEnrollmentFailed => {
            Some(domain::AuditAction::SmsOtpEnrollmentFailed)
        }
        pb::AuditAction::SmsMfaChallengeSucceeded => {
            Some(domain::AuditAction::SmsMfaChallengeSucceeded)
        }
        pb::AuditAction::SmsMfaChallengeFailed => Some(domain::AuditAction::SmsMfaChallengeFailed),
        pb::AuditAction::SmsMfaLocked => Some(domain::AuditAction::SmsMfaLocked),
        pb::AuditAction::DeviceFingerprintsErased => {
            Some(domain::AuditAction::DeviceFingerprintsErased)
        }
        pb::AuditAction::SessionLimitEnforced => Some(domain::AuditAction::SessionLimitEnforced),
        pb::AuditAction::SessionsRevoked => Some(domain::AuditAction::SessionsRevoked),
        pb::AuditAction::SessionEvicted => Some(domain::AuditAction::SessionEvicted),
        pb::AuditAction::AbuseDetected => Some(domain::AuditAction::AbuseDetected),
        pb::AuditAction::EmailChangeInitiated => Some(domain::AuditAction::EmailChangeInitiated),
        pb::AuditAction::EmailChangeConfirmed => Some(domain::AuditAction::EmailChangeConfirmed),
        pb::AuditAction::OidcSilentAuthProbed => Some(domain::AuditAction::OidcSilentAuthProbed),
        pb::AuditAction::AgentCreated => Some(domain::AuditAction::AgentCreated),
        pb::AuditAction::AgentUpdated => Some(domain::AuditAction::AgentUpdated),
        pb::AuditAction::AgentSuspended => Some(domain::AuditAction::AgentSuspended),
        pb::AuditAction::AgentReactivated => Some(domain::AuditAction::AgentReactivated),
        pb::AuditAction::AgentRevoked => Some(domain::AuditAction::AgentRevoked),
        pb::AuditAction::AgentDeleted => Some(domain::AuditAction::AgentDeleted),
        pb::AuditAction::AgentCredentialCreated => {
            Some(domain::AuditAction::AgentCredentialCreated)
        }
        pb::AuditAction::AgentCredentialRevoked => {
            Some(domain::AuditAction::AgentCredentialRevoked)
        }
        pb::AuditAction::AgentDelegation => Some(domain::AuditAction::AgentDelegation),
        pb::AuditAction::AgentToolInvocation => Some(domain::AuditAction::AgentToolInvocation),
        pb::AuditAction::ApprovalRequested => Some(domain::AuditAction::ApprovalRequested),
        pb::AuditAction::ApprovalGranted => Some(domain::AuditAction::ApprovalGranted),
        pb::AuditAction::ApprovalDenied => Some(domain::AuditAction::ApprovalDenied),
        pb::AuditAction::AgentTokenRevoked => Some(domain::AuditAction::AgentTokenRevoked),
        pb::AuditAction::CrossRealmTrustCreated => {
            Some(domain::AuditAction::CrossRealmTrustCreated)
        }
        pb::AuditAction::CrossRealmTrustRevoked => {
            Some(domain::AuditAction::CrossRealmTrustRevoked)
        }
        pb::AuditAction::ProtectedResourceRegistered => {
            Some(domain::AuditAction::ProtectedResourceRegistered)
        }
        pb::AuditAction::ProtectedResourceUpdated => {
            Some(domain::AuditAction::ProtectedResourceUpdated)
        }
        pb::AuditAction::ProtectedResourceDeleted => {
            Some(domain::AuditAction::ProtectedResourceDeleted)
        }
        // Phase D
        pb::AuditAction::AatIssued => Some(domain::AuditAction::AatIssued),
        pb::AuditAction::AatRevoked => Some(domain::AuditAction::AatRevoked),
        pb::AuditAction::TransactionTokenIssued => {
            Some(domain::AuditAction::TransactionTokenIssued)
        }
        pb::AuditAction::CrossRealmTokenIssued => Some(domain::AuditAction::CrossRealmTokenIssued),
        pb::AuditAction::SpiffeIdMapped => Some(domain::AuditAction::SpiffeIdMapped),
        pb::AuditAction::SpiffeAuthSuccess => Some(domain::AuditAction::SpiffeAuthSuccess),
    }
}

// ==================== AuditEvent ====================

impl From<&domain::AuditEvent> for pb::AuditEvent {
    fn from(e: &domain::AuditEvent) -> Self {
        Self {
            id: e.id.as_uuid().to_string(),
            realm_id: e.realm_id.as_uuid().to_string(),
            actor: e.actor.clone(),
            action: domain_audit_action_to_proto(&e.action).into(),
            resource_type: e.resource_type.clone(),
            resource_id: e.resource_id.clone(),
            timestamp: e.timestamp.as_micros(),
            metadata: e.metadata.as_ref().map(ToString::to_string),
            integrity_hash: e.integrity_hash.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{AuditEventId, RealmId, Timestamp};

    #[test]
    fn audit_event_to_proto() {
        let event = domain::AuditEvent {
            id: AuditEventId::generate(),
            realm_id: RealmId::generate(),
            actor: "user_123".to_string(),
            action: domain::AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "user_456".to_string(),
            timestamp: Timestamp::from_micros(1_700_000_000_000_000),
            metadata: Some(serde_json::json!({"ip": "127.0.0.1"})),
            integrity_hash: "abc123".to_string(),
        };

        let proto = pb::AuditEvent::from(&event);
        assert_eq!(proto.id, event.id.as_uuid().to_string());
        assert_eq!(proto.actor, "user_123");
        assert_eq!(proto.action, pb::AuditAction::UserCreated as i32);

        // Verify JSON serialization
        let json: serde_json::Value = serde_json::to_value(&proto).expect("serialize");
        assert_eq!(json["action"], "AUDIT_ACTION_USER_CREATED");
    }

    #[test]
    fn audit_action_all_variants_map_no_unspecified() {
        // Every domain variant must map to a real proto value — none may fall
        // through to Unspecified, which would silently lose information on the wire.
        for variant in domain::AuditAction::all() {
            let proto = domain_audit_action_to_proto(&variant);
            assert_ne!(
                proto,
                pb::AuditAction::Unspecified,
                "domain variant {variant:?} maps to Unspecified — add it to the proto enum and convert layer"
            );
        }
    }

    #[test]
    fn audit_action_proto_round_trip() {
        // Every domain variant should survive a domain→proto→domain round-trip.
        for variant in domain::AuditAction::all() {
            let proto = domain_audit_action_to_proto(&variant);
            let round_tripped = proto_audit_action_to_domain(proto).unwrap_or_else(|| {
                panic!("proto variant {proto:?} has no reverse mapping for domain {variant:?}")
            });
            assert_eq!(
                round_tripped, variant,
                "round-trip mismatch for {variant:?}"
            );
        }
    }

    #[test]
    fn proto_unspecified_maps_to_none() {
        assert_eq!(
            proto_audit_action_to_domain(pb::AuditAction::Unspecified),
            None
        );
    }
}
