//! Tests for `IdentityError`.

use std::error::Error;

use super::IdentityError;
use crate::identity::federation::saml::SamlError;

#[test]
fn display_realm_not_found() {
    let err = IdentityError::RealmNotFound;
    let display = format!("{err}");
    assert!(display.contains("realm not found"), "got: {display}");
}

#[test]
fn display_realm_suspended() {
    let err = IdentityError::RealmSuspended;
    let display = format!("{err}");
    assert!(display.contains("suspended"), "got: {display}");
}

#[test]
fn display_duplicate_realm_name() {
    let err = IdentityError::DuplicateRealmName;
    let display = format!("{err}");
    assert!(display.contains("already exists"), "got: {display}");
}

#[test]
fn display_user_not_found() {
    let err = IdentityError::UserNotFound;
    let display = format!("{err}");
    assert!(display.contains("user not found"), "got: {display}");
}

#[test]
fn display_duplicate_email() {
    let err = IdentityError::DuplicateEmail;
    let display = format!("{err}");
    assert!(display.contains("already exists"), "got: {display}");
}

#[test]
fn display_invalid_input() {
    let err = IdentityError::InvalidInput {
        reason: "email missing @".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("invalid input"), "got: {display}");
    assert!(display.contains("email missing @"), "got: {display}");
}

#[test]
fn display_storage() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
    let err = IdentityError::Storage(Box::new(io_err));
    let display = format!("{err}");
    assert!(display.contains("storage error"), "got: {display}");
    assert!(display.contains("file missing"), "got: {display}");
}

#[test]
fn display_serialization() {
    let err = IdentityError::Serialization {
        reason: "invalid JSON".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("serialization error"), "got: {display}");
    assert!(display.contains("invalid JSON"), "got: {display}");
}

#[test]
fn implements_error_trait() {
    let err = IdentityError::UserNotFound;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn source_storage_has_inner() {
    let io_err = std::io::Error::other("disk full");
    let err = IdentityError::Storage(Box::new(io_err));
    assert!(err.source().is_some(), "Storage variant should have source");
}

#[test]
fn display_credential_not_found() {
    let err = IdentityError::CredentialNotFound;
    let display = format!("{err}");
    assert!(display.contains("no credential found"), "got: {display}");
}

#[test]
fn display_invalid_credential() {
    let err = IdentityError::InvalidCredential {
        reason: "wrong password".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("invalid credential"), "got: {display}");
    assert!(display.contains("wrong password"), "got: {display}");
}

#[test]
fn display_session_not_found() {
    let err = IdentityError::SessionNotFound;
    let display = format!("{err}");
    assert!(display.contains("session not found"), "got: {display}");
}

#[test]
fn display_invalid_token() {
    let err = IdentityError::InvalidToken;
    let display = format!("{err}");
    assert!(display.contains("invalid token"), "got: {display}");
}

#[test]
fn display_token_expired() {
    let err = IdentityError::TokenExpired;
    let display = format!("{err}");
    assert!(display.contains("token expired"), "got: {display}");
}

#[test]
fn display_signing_error() {
    let err = IdentityError::SigningError {
        reason: "key generation failed".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("signing error"), "got: {display}");
    assert!(display.contains("key generation failed"), "got: {display}");
}

#[test]
fn display_invalid_client() {
    let err = IdentityError::InvalidClient;
    let display = format!("{err}");
    assert!(display.contains("invalid client"), "got: {display}");
}

#[test]
fn display_invalid_redirect_uri() {
    let err = IdentityError::InvalidRedirectUri;
    let display = format!("{err}");
    assert!(display.contains("invalid redirect URI"), "got: {display}");
}

#[test]
fn display_invalid_authorization_code() {
    let err = IdentityError::InvalidAuthorizationCode;
    let display = format!("{err}");
    assert!(
        display.contains("invalid authorization code"),
        "got: {display}"
    );
}

#[test]
fn display_invalid_grant() {
    let err = IdentityError::InvalidGrant {
        reason: "PKCE mismatch".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("invalid grant"), "got: {display}");
    assert!(display.contains("PKCE mismatch"), "got: {display}");
}

#[test]
fn display_invalid_client_secret() {
    let err = IdentityError::InvalidClientSecret;
    let display = format!("{err}");
    assert!(display.contains("invalid client secret"), "got: {display}");
}

#[test]
fn display_authorization_pending() {
    let err = IdentityError::AuthorizationPending;
    let display = format!("{err}");
    assert!(display.contains("authorization pending"), "got: {display}");
}

#[test]
fn display_slow_down() {
    let err = IdentityError::SlowDown;
    let display = format!("{err}");
    assert!(display.contains("polling too frequently"), "got: {display}");
}

#[test]
fn display_device_code_expired() {
    let err = IdentityError::DeviceCodeExpired;
    let display = format!("{err}");
    assert!(display.contains("device code expired"), "got: {display}");
}

#[test]
fn display_device_code_denied() {
    let err = IdentityError::DeviceCodeDenied;
    let display = format!("{err}");
    assert!(display.contains("denied"), "got: {display}");
}

#[test]
fn display_token_revoked() {
    let err = IdentityError::TokenRevoked;
    let display = format!("{err}");
    assert!(display.contains("revoked"), "got: {display}");
}

#[test]
fn display_unsupported_grant_type() {
    let err = IdentityError::UnsupportedGrantType;
    let display = format!("{err}");
    assert!(display.contains("unsupported grant type"), "got: {display}");
}

#[test]
fn display_mfa_required() {
    let err = IdentityError::MfaRequired;
    let display = format!("{err}");
    assert!(
        display.contains("MFA verification required"),
        "got: {display}"
    );
}

#[test]
fn display_invalid_mfa_code() {
    let err = IdentityError::InvalidMfaCode;
    let display = format!("{err}");
    assert!(display.contains("invalid MFA code"), "got: {display}");
}

#[test]
fn display_mfa_not_enabled() {
    let err = IdentityError::MfaNotEnabled;
    let display = format!("{err}");
    assert!(display.contains("not enabled"), "got: {display}");
}

#[test]
fn display_mfa_already_enabled() {
    let err = IdentityError::MfaAlreadyEnabled;
    let display = format!("{err}");
    assert!(display.contains("already enabled"), "got: {display}");
}

#[test]
fn display_webauthn_registration_failed() {
    let err = IdentityError::WebAuthnRegistrationFailed {
        reason: "challenge mismatch".to_string(),
    };
    let display = format!("{err}");
    assert!(
        display.contains("WebAuthn registration failed"),
        "got: {display}"
    );
    assert!(display.contains("challenge mismatch"), "got: {display}");
}

#[test]
fn display_webauthn_authentication_failed() {
    let err = IdentityError::WebAuthnAuthenticationFailed {
        reason: "signature invalid".to_string(),
    };
    let display = format!("{err}");
    assert!(
        display.contains("WebAuthn authentication failed"),
        "got: {display}"
    );
}

#[test]
fn display_webauthn_credential_not_found() {
    let err = IdentityError::WebAuthnCredentialNotFound;
    let display = format!("{err}");
    assert!(
        display.contains("WebAuthn credential not found"),
        "got: {display}"
    );
}

#[test]
fn display_invalid_attestation() {
    let err = IdentityError::InvalidAttestation {
        reason: "unsupported format".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("invalid attestation"), "got: {display}");
}

#[test]
fn display_invalid_assertion() {
    let err = IdentityError::InvalidAssertion {
        reason: "counter replay".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("invalid assertion"), "got: {display}");
}

#[test]
fn display_unauthorized() {
    let err = IdentityError::Unauthorized;
    let display = format!("{err}");
    assert!(display.contains("forbidden"), "got: {display}");
}

#[test]
fn display_client_not_found() {
    let err = IdentityError::ClientNotFound;
    let display = format!("{err}");
    assert!(display.contains("client not found"), "got: {display}");
}

#[test]
fn display_magic_link_token_invalid() {
    let err = IdentityError::MagicLinkTokenInvalid;
    let display = format!("{err}");
    assert!(
        display.contains("invalid or expired magic link"),
        "got: {display}"
    );
}

#[test]
fn display_verification_token_invalid() {
    let err = IdentityError::VerificationTokenInvalid;
    let display = format!("{err}");
    assert!(
        display.contains("invalid or expired verification link"),
        "got: {display}"
    );
}

#[test]
fn display_password_reset_token_invalid() {
    let err = IdentityError::PasswordResetTokenInvalid;
    let display = format!("{err}");
    assert!(
        display.contains("invalid or expired password reset link"),
        "got: {display}"
    );
}

#[test]
fn display_user_not_verified() {
    let err = IdentityError::UserNotVerified;
    let display = format!("{err}");
    assert!(display.contains("not verified"), "got: {display}");
}

#[test]
fn display_organization_not_found() {
    let err = IdentityError::OrganizationNotFound;
    let display = format!("{err}");
    assert!(display.contains("organization not found"), "got: {display}");
}

#[test]
fn display_duplicate_org_slug() {
    let err = IdentityError::DuplicateOrgSlug;
    let display = format!("{err}");
    assert!(display.contains("slug already exists"), "got: {display}");
}

#[test]
fn display_organization_suspended() {
    let err = IdentityError::OrganizationSuspended;
    let display = format!("{err}");
    assert!(display.contains("suspended"), "got: {display}");
}

#[test]
fn display_already_member() {
    let err = IdentityError::AlreadyMember;
    let display = format!("{err}");
    assert!(display.contains("already a member"), "got: {display}");
}

#[test]
fn display_not_a_member() {
    let err = IdentityError::NotAMember;
    let display = format!("{err}");
    assert!(display.contains("not a member"), "got: {display}");
}

#[test]
fn display_last_owner() {
    let err = IdentityError::LastOwner;
    let display = format!("{err}");
    assert!(display.contains("last owner"), "got: {display}");
}

#[test]
fn display_member_limit_reached() {
    let err = IdentityError::MemberLimitReached;
    let display = format!("{err}");
    assert!(display.contains("member limit"), "got: {display}");
}

#[test]
fn display_invitation_invalid() {
    let err = IdentityError::InvitationInvalid;
    let display = format!("{err}");
    assert!(
        display.contains("invalid or expired invitation"),
        "got: {display}"
    );
}

#[test]
fn display_duplicate_invitation() {
    let err = IdentityError::DuplicateInvitation;
    let display = format!("{err}");
    assert!(display.contains("already exists"), "got: {display}");
}

#[test]
fn display_consent_variants() {
    assert!(format!("{}", IdentityError::ConsentRequired).contains("consent is required"));
    assert!(format!("{}", IdentityError::ConsentTicketNotFound).contains("ticket not found"));
    assert!(format!("{}", IdentityError::ConsentTicketExpired).contains("expired"));
    assert!(format!("{}", IdentityError::ConsentScopeNotRequested)
        .contains("not in the original request"));
    assert!(format!("{}", IdentityError::ConsentNotFound).contains("no consent record"));
}

#[test]
fn display_federation_variants() {
    assert!(format!("{}", IdentityError::FederationUnknownConnector)
        .contains("unknown federation connector"));
    assert!(
        format!("{}", IdentityError::FederationInvalidState).contains("invalid federation state")
    );
    assert!(format!(
        "{}",
        IdentityError::FederationUpstreamError {
            provider: "google".to_string(),
            reason: "bad response".to_string(),
        }
    )
    .contains("google"));
    assert!(
        format!("{}", IdentityError::FederationTokenVerificationFailed)
            .contains("token verification failed")
    );
    assert!(
        format!("{}", IdentityError::FederationEmailNotVerified).contains("email is not verified")
    );
    assert!(format!(
        "{}",
        IdentityError::FederationLinkConfirmationRequired {
            ticket: "abc".to_string()
        }
    )
    .contains("confirm-to-link"));
    assert!(format!("{}", IdentityError::FederationNotLinked)
        .contains("external identity is not linked"));
    assert!(format!("{}", IdentityError::FederationAlreadyLinked).contains("already linked"));
}

#[test]
fn federation_errors_have_no_source() {
    assert!(IdentityError::FederationUnknownConnector.source().is_none());
    assert!(IdentityError::FederationInvalidState.source().is_none());
    assert!((IdentityError::FederationUpstreamError {
        provider: "x".to_string(),
        reason: "y".to_string(),
    })
    .source()
    .is_none());
    assert!(IdentityError::FederationTokenVerificationFailed
        .source()
        .is_none());
    assert!(IdentityError::FederationEmailNotVerified.source().is_none());
    assert!((IdentityError::FederationLinkConfirmationRequired {
        ticket: "t".to_string()
    })
    .source()
    .is_none());
    assert!(IdentityError::FederationNotLinked.source().is_none());
    assert!(IdentityError::FederationAlreadyLinked.source().is_none());
}

#[test]
fn display_invalid_sms_otp() {
    let err = IdentityError::InvalidSmsOtp;
    let display = format!("{err}");
    assert!(display.contains("SMS OTP"), "got: {display}");
}

#[test]
fn display_sms_resend_limit_exceeded() {
    let err = IdentityError::SmsResendLimitExceeded;
    let display = format!("{err}");
    assert!(display.contains("resend limit"), "got: {display}");
}

#[test]
fn sms_errors_have_no_source() {
    assert!(IdentityError::InvalidSmsOtp.source().is_none());
    assert!(IdentityError::SmsResendLimitExceeded.source().is_none());
}

#[test]
fn source_others_none() {
    assert!(IdentityError::RealmNotFound.source().is_none());
    assert!(IdentityError::UserNotFound.source().is_none());
    assert!(IdentityError::SessionNotFound.source().is_none());
    assert!(IdentityError::InvalidToken.source().is_none());
    assert!(IdentityError::InvalidClient.source().is_none());
    assert!(IdentityError::MfaRequired.source().is_none());
    assert!(IdentityError::Unauthorized.source().is_none());
    assert!((IdentityError::InvalidInput {
        reason: "x".to_string()
    })
    .source()
    .is_none());
}

#[test]
fn saml_error_delegates_display_and_source() {
    let err = IdentityError::Saml(SamlError::Signature);
    let display = format!("{err}");
    assert!(display.contains("SAML signature"), "got: {display}");
    assert!(err.source().is_none());
}

#[test]
fn saml_from_converts_to_identity_error() {
    let saml_err = SamlError::Replay;
    let identity_err: IdentityError = saml_err.into();
    assert!(matches!(
        identity_err,
        IdentityError::Saml(SamlError::Replay)
    ));
}

#[test]
fn display_attestation_policy_violation() {
    let err = IdentityError::AttestationPolicyViolation {
        reason: "AAGUID not in allowlist".to_string(),
    };
    let display = format!("{err}");
    assert!(
        display.contains("attestation policy violation"),
        "got: {display}"
    );
    assert!(
        display.contains("AAGUID not in allowlist"),
        "got: {display}"
    );
}

#[test]
fn attestation_policy_violation_has_wire_code() {
    let err = IdentityError::AttestationPolicyViolation {
        reason: "none not permitted".to_string(),
    };
    assert_eq!(
        err.wire_error_code(),
        Some("HEARTH_ATTESTATION_POLICY_VIOLATION"),
        "expected stable wire code"
    );
}

#[test]
fn attestation_policy_violation_has_no_source() {
    let err = IdentityError::AttestationPolicyViolation {
        reason: "test".to_string(),
    };
    assert!(err.source().is_none());
}
