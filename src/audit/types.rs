//! Audit event types and query structures.
//!
//! Audit events are append-only structured records of security-critical
//! mutations. Each event includes an integrity hash forming a hash chain
//! for tamper detection.

use crate::core::{AuditEventId, RealmId, Timestamp};
use serde::{Deserialize, Serialize};

/// Categories of security-critical actions recorded in the audit log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuditAction {
    /// A new user was created.
    UserCreated,
    /// A user record was updated.
    UserUpdated,
    /// A user was deleted.
    UserDeleted,
    /// A password was set for a user.
    CredentialSet,
    /// A password was changed.
    CredentialChanged,
    /// A credential verification was attempted (login).
    CredentialVerified,
    /// A new session was created.
    SessionCreated,
    /// A session was revoked.
    SessionRevoked,
    /// All sessions for a user were revoked due to a sensitive credential
    /// mutation (`set_password`, `change_password`, `disable_mfa`, or email
    /// change).
    ///
    /// Metadata carries `user_id`, `count` (sessions revoked), and `trigger`
    /// (e.g. `"set_password"` / `"disable_mfa"` / `"email_change"`).
    SessionsRevoked,
    /// A session was evicted by a realm-level lifecycle policy (idle or
    /// absolute timeout). Distinct from [`SessionRevoked`] (user/admin action).
    ///
    /// Metadata carries `user_id`, `session_id`, and `reason`
    /// (`"idle_timeout"` | `"absolute_timeout"`). Fail-open (LogOnly).
    SessionEvicted,
    /// Tokens were issued for a session.
    TokenIssued,
    /// Tokens were refreshed.
    TokenRefreshed,
    /// A new realm was created.
    RealmCreated,
    /// A realm record was updated.
    RealmUpdated,
    /// A realm was deleted.
    RealmDeleted,
    /// An OAuth client was registered.
    ClientRegistered,
    /// An authorization code was issued.
    AuthorizationCodeIssued,
    /// An authorization code was exchanged for tokens.
    AuthorizationCodeExchanged,
    /// An authorization tuple was written.
    TupleWritten,
    /// An authorization tuple was deleted.
    TupleDeleted,
    /// An OAuth client was updated via admin API.
    ClientUpdated,
    /// An OAuth client was deleted via admin API.
    ClientDeleted,
    /// Users were bulk-created via admin API.
    BulkUsersCreated,
    /// Users were bulk-disabled via admin API.
    BulkUsersDisabled,
    /// An organization was created.
    OrgCreated,
    /// An organization was updated.
    OrgUpdated,
    /// An organization was deleted.
    OrgDeleted,
    /// An RBAC group was created (admin UI / API, not SCIM).
    GroupCreated,
    /// An RBAC group was updated (name / slug / description).
    GroupUpdated,
    /// An RBAC group was deleted.
    GroupDeleted,
    /// A member (user or nested group) was added to a group.
    /// Metadata carries `member_type` (`"user"` / `"group"`) + `member_id`.
    GroupMemberAdded,
    /// A member was removed from a group.
    /// Metadata carries `member_type` + `member_id`.
    GroupMemberRemoved,
    /// A member's role within an organization was changed
    /// (promotion / demotion).
    ///
    /// Metadata carries `previous_role` + `new_role`.
    GroupMemberRoleChanged,
    /// A role was assigned to a subject (user) on an object (realm / organization / application).
    ///
    /// Metadata carries `object_type`, `object_id`, `role`, and the previous
    /// role (if any) so downgrades/upgrades are visible in the audit trail.
    RoleAssigned,
    /// A role previously held by a subject was revoked.
    ///
    /// Metadata carries `object_type`, `object_id`, and `role`.
    RoleRevoked,
    /// A user granted OAuth consent to a client for one or more scopes.
    ConsentGranted,
    /// A user denied an OAuth consent request.
    ConsentDenied,
    /// A previously granted OAuth consent was revoked (by the user or an admin).
    ConsentRevoked,
    /// A federation login was initiated (user clicked "Sign in with X").
    FederationLoginStarted,
    /// A federation login completed successfully — either for an
    /// existing user (linked), a JIT-provisioned user, or after a
    /// confirm-to-link step.
    FederationLoginCompleted,
    /// An external identity was attached to a Hearth user.
    FederationAccountLinked,
    /// An external identity was detached from a Hearth user.
    FederationAccountUnlinked,
    /// A fresh Hearth user was JIT-provisioned from a federation login.
    FederationJitProvisioned,
    /// A SAML SP-initiated login was started (AuthnRequest sent).
    SamlLoginInitiated,
    /// A SAML SP-initiated login completed — assertion accepted.
    SamlLoginCompleted,
    /// A SAML assertion was rejected.
    ///
    /// Metadata carries `reason`: `signature` / `expired` / `replay` /
    /// `audience` / `issuer` / `destination` / `parse`.
    SamlLoginFailed,
    /// Hearth (acting as IdP) received a SAML `<AuthnRequest>` from an SP.
    SamlIdpAuthnRequestReceived,
    /// Hearth (acting as IdP) issued a SAML `<Response>` to an SP.
    SamlIdpResponseIssued,
    /// A SAML IdP-initiated SSO was fired (operator launched a login at
    /// a registered SP).
    SamlIdpInitiatedSso,
    /// A SAML Single Logout was requested.
    SamlSloRequested,
    /// A SAML Single Logout completed.
    SamlSloCompleted,
    /// A user was provisioned via the SCIM 2.0 API. Metadata carries
    /// `external_id` (SCIM `externalId`) when supplied by the client.
    ScimUserCreated,
    /// A user was updated (PUT or PATCH) via SCIM.
    ScimUserUpdated,
    /// A user was deprovisioned (DELETE) via SCIM.
    ScimUserDeleted,
    /// A group was provisioned via SCIM.
    ScimGroupCreated,
    /// A group was updated via SCIM.
    ScimGroupUpdated,
    /// A group was deleted via SCIM.
    ScimGroupDeleted,
    /// A dangling role-ID or registry reference was silently skipped
    /// during permission resolution.
    ///
    /// Emitted at most once per `(realm, reference)` per hour so operators
    /// are notified of YAML-storage drift without flooding the audit log.
    /// The `resource_id` field carries the opaque reference (e.g. a
    /// `role_<uuid>` string) that could not be resolved; `metadata` may
    /// carry `ref_kind` for disambiguation. See `AUTHZ_EXPANSION.md`
    /// §"Dangling references".
    OrphanedReferenceSkipped,
    /// A direct permission was granted to a user outside any role.
    ///
    /// Metadata may carry `scope_type` (`"realm"` or `"org"`) and
    /// `permission`. See `AUTHZ_EXPANSION.md` gap #6.
    UserPermissionGranted,
    /// A direct permission previously granted to a user was revoked.
    ///
    /// Metadata may carry `scope_type` and `permission`.
    UserPermissionRevoked,
    /// OAuth consent was granted (new grant or scope update).
    ///
    /// Metadata carries `client_id` and `scopes` (space-separated).
    ClientConsentGranted,
    /// OAuth consent was revoked — either by the user or an admin.
    ///
    /// Metadata carries `client_id` and the actor type (`"self"` or `"admin"`).
    ClientConsentRevoked,
    /// A refresh token was rejected because the stored consent digest no
    /// longer matches the current scope surface (e.g. bundle YAML was
    /// updated). Equivalent to `invalid_grant consent_required`.
    ///
    /// Metadata carries `client_id`.
    ConsentRequiredOnRefresh,
    /// Periodic sweep of expired entities (authorization codes, device
    /// codes, pending tickets, grant families). Emitted once per realm
    /// per sweep; metadata carries deletion counts.
    Cleanup,
    /// A credential verification attempt failed (wrong password or no
    /// credential set). Metadata carries `attempt_count`.
    LoginFailed,
    /// An account was temporarily locked out after too many consecutive
    /// failed login attempts. Metadata carries `attempt_count` and
    /// `lockout_duration_micros`.
    LoginLocked,
    /// A per-IP login rate limit was exceeded. Metadata carries `ip`
    /// and `attempt_count`.
    IpLoginLimitExceeded,
    /// An admin-triggered backup archive was created and downloaded.
    ///
    /// Metadata carries `filename` and, when a realm filter was applied,
    /// `realm_slug`.
    BackupCreated,
    /// An admin-triggered restore from a backup archive completed.
    ///
    /// Metadata carries `dry_run` (`"true"` / `"false"`) and the list of
    /// restored realm slugs.
    BackupRestored,
    /// A realm export was requested and watermarked (A-30).
    ///
    /// Emitted on every invocation of `/admin/backup`, `/admin/users/export`,
    /// and `/admin/realms/{r}/audit/export` regardless of the outcome.
    /// Metadata carries `export_id` (UUIDv4), `export_type` (one of
    /// `"backup"`, `"users"`, `"audit"`), `realm_slug` (when filtered), and
    /// `actor_ip` (the request's remote address when available).
    RealmExportWatermarked,
    /// A new agent was registered in the realm.
    ///
    /// Metadata carries `agent_id`, `display_name`, and `owner_id`.
    AgentCreated,
    /// An agent's metadata was updated (name, description, capabilities).
    ///
    /// Metadata carries `agent_id` and changed fields.
    AgentUpdated,
    /// An agent was temporarily suspended.
    ///
    /// Metadata carries `agent_id`.
    AgentSuspended,
    /// An active or suspended agent was reactivated.
    ///
    /// Metadata carries `agent_id`.
    AgentReactivated,
    /// An agent was permanently revoked.
    ///
    /// Metadata carries `agent_id`.
    AgentRevoked,
    /// An agent was deleted (cascading delete of credentials and RBAC assignments).
    ///
    /// Metadata carries `agent_id`.
    AgentDeleted,
    /// An API key credential was created for an agent.
    ///
    /// Metadata carries `agent_id` and `credential_id`.
    AgentCredentialCreated,
    /// An agent credential was permanently revoked.
    ///
    /// Metadata carries `agent_id` and `credential_id`.
    AgentCredentialRevoked,
    /// A required action was assigned to a user by an admin.
    ///
    /// Metadata carries `action_type` (e.g. `"VERIFY_EMAIL"`) and `admin_id`.
    RequiredActionAssigned,
    /// A required action was removed from a user by an admin.
    ///
    /// Metadata carries `action_type` (e.g. `"VERIFY_EMAIL"`) and `admin_id`.
    RequiredActionRemoved,
    /// A required action was completed by the user during the OIDC intercept flow.
    ///
    /// Metadata carries `action_type` (e.g. `"UPDATE_PASSWORD"`).
    RequiredActionCompleted,
    /// A required action was automatically cleared without user interaction.
    ///
    /// Metadata carries `action_type` (e.g. `"VERIFY_EMAIL"`) and `reason`
    /// (e.g. `"email_already_verified"`). Used to self-heal data-migration
    /// artifacts where a required action was added spuriously.
    RequiredActionAutoCleared,
    /// A password-set or password-change was rejected because the candidate
    /// password appeared in a known HIBP data breach.
    ///
    /// Failure policy: `FailOperation` (the credential was NOT stored).
    /// Metadata carries `user_id`.
    PasswordCompromisedRejected,
    /// The HIBP breach-check API was unavailable (timeout or network error).
    ///
    /// Failure policy: `LogOnly`. The password was accepted (fail-open).
    /// Metadata carries `user_id` and `reason`.
    BreachCheckUnavailable,
    /// Adaptive MFA step-up was triggered because the login arrived from an
    /// unrecognised device or IP subnet.
    ///
    /// Failure policy: `LogOnly` — the login continues with an MFA challenge or
    /// enrollment redirect; the step-up event itself is informational.
    /// Metadata carries `user_id` and `reason` (e.g. `"unrecognised_device"`).
    StepUpMfaTriggered,
    /// A step-up MFA challenge was successfully completed — the user passed
    /// the MFA check after an unrecognised-device trigger.
    /// Metadata carries `user_id`.
    StepUpMfaCompleted,
    /// An SMS OTP was generated and sent to a user's phone to begin
    /// phone-number enrollment. Metadata carries `phone_suffix` (last 4 digits,
    /// never full number).
    SmsOtpEnrollmentStarted,
    /// A user successfully verified their phone number via SMS OTP during
    /// enrollment. Metadata carries `phone_suffix`.
    SmsOtpEnrollmentVerified,
    /// A phone enrollment SMS OTP verification attempt failed (wrong code,
    /// expired, or max attempts). Metadata carries `phone_suffix` and
    /// `reason` (`"wrong_code"` / `"expired"` / `"exhausted"`).
    SmsOtpEnrollmentFailed,
    /// An SMS MFA challenge was satisfied — the user entered the correct OTP
    /// during the OIDC login pipeline. Metadata carries `user_id`.
    SmsMfaChallengeSucceeded,
    /// An SMS MFA challenge attempt failed (wrong code or expired).
    /// Metadata carries `user_id` and `reason`.
    SmsMfaChallengeFailed,
    /// An SMS MFA challenge was locked because the maximum number of
    /// incorrect attempts was exceeded. Metadata carries `user_id` and
    /// `attempt_count`.
    SmsMfaLocked,
    /// All device fingerprints for a user were erased — either as part of
    /// `delete_user` (GDPR Art. 17 cascade) or via the admin erasure API
    /// (`DELETE /admin/users/{id}/device-fingerprints`).
    ///
    /// Metadata carries `user_id` and `count` (number of records removed).
    DeviceFingerprintsErased,
    /// The per-realm concurrent session limit was enforced.
    ///
    /// Emitted whenever `max_concurrent_sessions` is set and a new session
    /// would exceed it — whether the policy is `RejectNew` (evicted=0, no
    /// session created) or `EvictOldest` (evicted≥1, oldest sessions revoked).
    ///
    /// Metadata carries `user_id`, `evicted` (number of sessions removed,
    /// 0 for `RejectNew`), `policy` (`"reject_new"` | `"evict_oldest"`),
    /// and `limit`.
    SessionLimitEnforced,
    /// An abuse pattern was detected by the distributed-attack detector
    /// (A-3: cardinality sketch per realm) — e.g. too many distinct usernames
    /// from one IP, or too many distinct IPs targeting one username.
    ///
    /// Failure policy: `LogOnly` (informational; the request continues into
    /// `Challenge` state per the `AbuseGuard` decision). Metadata carries
    /// `ip`, `username` (if targeted), `detector` (`"credential_stuffing"` /
    /// `"password_spray"` / `"distributed_brute_force"`), and `realm_id`.
    AbuseDetected,
    /// A user initiated an email-address change (A-19).
    ///
    /// A verification token has been issued for the new address; the old
    /// address remains in use until `confirm_email_change` is called.
    /// Metadata carries `user_id` and `new_email` (partially redacted:
    /// domain retained, local-part starred).
    EmailChangeInitiated,
    /// A user confirmed an email-address change via the verification token (A-19).
    ///
    /// The old address received a `security.email_changed` notification
    /// with a revoke link; all sessions were revoked.
    /// Metadata carries `user_id`, `old_email` (partially redacted), and
    /// `new_email` (partially redacted).
    EmailChangeConfirmed,
    /// A `prompt=none` OIDC authorization request was observed for an
    /// authenticated subject (A-37).
    ///
    /// Emitted on every `prompt=none` request while a valid session exists,
    /// regardless of outcome (bypass / `consent_required`). Rate-limited
    /// callers also receive `SilentAuthRateLimited`.
    /// Metadata carries `user_id`, `client_id`, and `outcome`
    /// (`"code_issued"` / `"consent_required"` / `"rate_limited"`).
    OidcSilentAuthProbed,
    /// A delegated token was issued via OBO or RFC 8693 token exchange
    /// (§12.2 of AGENT_AUTH.md).
    ///
    /// Metadata carries `actor` (immediate actor subject), `on_behalf_of`
    /// (delegating principal), `delegation_chain` (JSON array), `token_jti`,
    /// and optionally `dpop_jkt`, `tool`, `approval_id`.
    AgentDelegation,
    /// An agent invoked a tool on an MCP server (logged by Hearth proxy or
    /// resource server).
    ///
    /// Metadata carries `agent_id`, `tool`, `resource_uri`, and optionally
    /// `approval_id` and `token_jti`.
    AgentToolInvocation,
    /// An agent requested human-in-the-loop approval for a tool invocation.
    ///
    /// Metadata carries `agent_id`, `tool`, `request_id`.
    ApprovalRequested,
    /// A human approved an agent's tool-invocation request.
    ///
    /// Metadata carries `agent_id`, `tool`, `request_id`, `approver_id`.
    ApprovalGranted,
    /// A human denied an agent's tool-invocation request.
    ///
    /// Metadata carries `agent_id`, `tool`, `request_id`, `approver_id`.
    ApprovalDenied,
    /// An agent token was explicitly revoked (manual or CAEP-triggered).
    ///
    /// Metadata carries `agent_id`, `token_jti`, and `reason`.
    AgentTokenRevoked,
    /// A cross-realm agent trust policy was created.
    ///
    /// Metadata carries `source_realm_id`, `target_realm_id`, and
    /// `allowed_capabilities`.
    CrossRealmTrustCreated,
    /// A cross-realm agent trust policy was revoked.
    ///
    /// Metadata carries `source_realm_id` and `target_realm_id`.
    CrossRealmTrustRevoked,
    /// A protected resource (MCP server) was registered in the realm.
    ///
    /// Metadata carries `resource_id`, `resource_uri`, and `display_name`.
    ProtectedResourceRegistered,
    /// A protected resource was updated.
    ///
    /// Metadata carries `resource_id` and the changed fields.
    ProtectedResourceUpdated,
    /// A protected resource was deleted.
    ///
    /// Metadata carries `resource_id` and `resource_uri`.
    ProtectedResourceDeleted,

    // Phase D audit actions
    /// An Attenuating Authorization Token (AAT) was issued for an agent.
    ///
    /// Metadata carries `agent_id`, `jti`, `scope`, and `tools`.
    AatIssued,
    /// An AAT was revoked (by JTI).
    ///
    /// Metadata carries `jti` and `revoked_by`.
    AatRevoked,
    /// A transaction token was issued for an agent-to-agent call.
    ///
    /// Metadata carries `requesting_agent_id`, `target_agent_id`, and `txn_id`.
    TransactionTokenIssued,
    /// A cross-realm token exchange was authorized.
    ///
    /// Metadata carries `source_realm_id`, `target_realm_id`, and `capability`.
    CrossRealmTokenIssued,
    /// A SPIFFE ID was mapped to an agent.
    ///
    /// Metadata carries `agent_id` and `spiffe_id`.
    SpiffeIdMapped,
    /// An agent authenticated via SPIFFE mTLS.
    ///
    /// Metadata carries `agent_id` and `spiffe_id`.
    SpiffeAuthSuccess,
    /// An administrative prune of the audit log was executed.
    ///
    /// Recorded **before** the deletion so that even a crash-interrupted
    /// prune leaves a trace.  Metadata carries `cutoff_micros` (the
    /// exclusive upper bound), `retention_days`, and `realm_id`.
    AuditLogPruned,
    /// TOTP enrollment was confirmed — MFA is now active for the user.
    ///
    /// Emitted from `verify_totp_enrollment` after `state.enabled` is
    /// flipped to `true`.
    MfaEnabled,
    /// MFA was disabled for a user (admin action or self-service).
    ///
    /// Emitted from `disable_mfa`. All existing sessions are revoked
    /// immediately after this event.
    MfaDisabled,
}

impl AuditAction {
    /// Every variant in declaration order. Used by the admin audit-log
    /// filter UI to populate the Action `<select>` so administrators
    /// don't have to remember exact string tags. Keep alphabetised on
    /// the wire format for stable rendering.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn all() -> Vec<Self> {
        let mut v = vec![
            Self::UserCreated,
            Self::UserUpdated,
            Self::UserDeleted,
            Self::CredentialSet,
            Self::CredentialChanged,
            Self::CredentialVerified,
            Self::SessionCreated,
            Self::SessionRevoked,
            Self::SessionEvicted,
            Self::TokenIssued,
            Self::TokenRefreshed,
            Self::RealmCreated,
            Self::RealmUpdated,
            Self::RealmDeleted,
            Self::ClientRegistered,
            Self::ClientUpdated,
            Self::ClientDeleted,
            Self::AuthorizationCodeIssued,
            Self::AuthorizationCodeExchanged,
            Self::TupleWritten,
            Self::TupleDeleted,
            Self::BulkUsersCreated,
            Self::BulkUsersDisabled,
            Self::OrgCreated,
            Self::OrgUpdated,
            Self::OrgDeleted,
            Self::ConsentGranted,
            Self::ConsentDenied,
            Self::ConsentRevoked,
            Self::FederationLoginStarted,
            Self::FederationLoginCompleted,
            Self::FederationAccountLinked,
            Self::FederationAccountUnlinked,
            Self::FederationJitProvisioned,
            Self::SamlLoginInitiated,
            Self::SamlLoginCompleted,
            Self::SamlLoginFailed,
            Self::SamlIdpAuthnRequestReceived,
            Self::SamlIdpResponseIssued,
            Self::SamlIdpInitiatedSso,
            Self::SamlSloRequested,
            Self::SamlSloCompleted,
            Self::ScimUserCreated,
            Self::ScimUserUpdated,
            Self::ScimUserDeleted,
            Self::ScimGroupCreated,
            Self::ScimGroupUpdated,
            Self::ScimGroupDeleted,
            Self::GroupCreated,
            Self::GroupUpdated,
            Self::GroupDeleted,
            Self::GroupMemberAdded,
            Self::GroupMemberRemoved,
            Self::GroupMemberRoleChanged,
            Self::RoleAssigned,
            Self::RoleRevoked,
            Self::OrphanedReferenceSkipped,
            Self::UserPermissionGranted,
            Self::UserPermissionRevoked,
            Self::ClientConsentGranted,
            Self::ClientConsentRevoked,
            Self::ConsentRequiredOnRefresh,
            Self::Cleanup,
            Self::LoginFailed,
            Self::LoginLocked,
            Self::IpLoginLimitExceeded,
            Self::BackupCreated,
            Self::BackupRestored,
            Self::RequiredActionAssigned,
            Self::RequiredActionRemoved,
            Self::RequiredActionCompleted,
            Self::RequiredActionAutoCleared,
            Self::PasswordCompromisedRejected,
            Self::BreachCheckUnavailable,
            Self::StepUpMfaTriggered,
            Self::StepUpMfaCompleted,
            Self::SmsOtpEnrollmentStarted,
            Self::SmsOtpEnrollmentVerified,
            Self::SmsOtpEnrollmentFailed,
            Self::SmsMfaChallengeSucceeded,
            Self::SmsMfaChallengeFailed,
            Self::SmsMfaLocked,
            Self::DeviceFingerprintsErased,
            Self::SessionLimitEnforced,
            Self::SessionsRevoked,
            Self::AbuseDetected,
            Self::EmailChangeInitiated,
            Self::EmailChangeConfirmed,
            Self::OidcSilentAuthProbed,
            Self::RealmExportWatermarked,
        ];
        v.extend([
            Self::AgentCreated,
            Self::AgentUpdated,
            Self::AgentSuspended,
            Self::AgentReactivated,
            Self::AgentRevoked,
            Self::AgentDeleted,
            Self::AgentCredentialCreated,
            Self::AgentCredentialRevoked,
            // M2 delegation + MCP
            Self::AgentDelegation,
            Self::AgentToolInvocation,
            Self::ApprovalRequested,
            Self::ApprovalGranted,
            Self::ApprovalDenied,
            Self::AgentTokenRevoked,
            Self::CrossRealmTrustCreated,
            Self::CrossRealmTrustRevoked,
            Self::ProtectedResourceRegistered,
            Self::ProtectedResourceUpdated,
            Self::ProtectedResourceDeleted,
            // Phase D
            Self::AatIssued,
            Self::AatRevoked,
            Self::TransactionTokenIssued,
            Self::CrossRealmTokenIssued,
            Self::SpiffeIdMapped,
            Self::SpiffeAuthSuccess,
            Self::AuditLogPruned,
            // MFA lifecycle
            Self::MfaEnabled,
            Self::MfaDisabled,
        ]);
        v.sort_by_key(|a| a.as_str());
        v
    }

    /// Returns the string tag for storage key encoding.
    #[allow(clippy::too_many_lines)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserCreated => "user_created",
            Self::UserUpdated => "user_updated",
            Self::UserDeleted => "user_deleted",
            Self::CredentialSet => "credential_set",
            Self::CredentialChanged => "credential_changed",
            Self::CredentialVerified => "credential_verified",
            Self::SessionCreated => "session_created",
            Self::SessionRevoked => "session_revoked",
            Self::SessionEvicted => "session_evicted",
            Self::TokenIssued => "token_issued",
            Self::TokenRefreshed => "token_refreshed",
            Self::RealmCreated => "realm_created",
            Self::RealmUpdated => "realm_updated",
            Self::RealmDeleted => "realm_deleted",
            Self::ClientRegistered => "client_registered",
            Self::AuthorizationCodeIssued => "authz_code_issued",
            Self::AuthorizationCodeExchanged => "authz_code_exchanged",
            Self::TupleWritten => "tuple_written",
            Self::TupleDeleted => "tuple_deleted",
            Self::ClientUpdated => "client_updated",
            Self::ClientDeleted => "client_deleted",
            Self::BulkUsersCreated => "bulk_users_created",
            Self::BulkUsersDisabled => "bulk_users_disabled",
            Self::OrgCreated => "org_created",
            Self::OrgUpdated => "org_updated",
            Self::OrgDeleted => "org_deleted",
            Self::GroupCreated => "group_created",
            Self::GroupUpdated => "group_updated",
            Self::GroupDeleted => "group_deleted",
            Self::GroupMemberAdded => "group_member_added",
            Self::GroupMemberRemoved => "group_member_removed",
            Self::GroupMemberRoleChanged => "group_member_role_changed",
            Self::ConsentGranted => "consent_granted",
            Self::ConsentDenied => "consent_denied",
            Self::ConsentRevoked => "consent_revoked",
            Self::FederationLoginStarted => "federation_login_started",
            Self::FederationLoginCompleted => "federation_login_completed",
            Self::FederationAccountLinked => "federation_account_linked",
            Self::FederationAccountUnlinked => "federation_account_unlinked",
            Self::FederationJitProvisioned => "federation_jit_provisioned",
            Self::SamlLoginInitiated => "saml_login_initiated",
            Self::SamlLoginCompleted => "saml_login_completed",
            Self::SamlLoginFailed => "saml_login_failed",
            Self::SamlIdpAuthnRequestReceived => "saml_idp_authn_request_received",
            Self::SamlIdpResponseIssued => "saml_idp_response_issued",
            Self::SamlIdpInitiatedSso => "saml_idp_initiated_sso",
            Self::SamlSloRequested => "saml_slo_requested",
            Self::SamlSloCompleted => "saml_slo_completed",
            Self::ScimUserCreated => "scim_user_created",
            Self::ScimUserUpdated => "scim_user_updated",
            Self::ScimUserDeleted => "scim_user_deleted",
            Self::ScimGroupCreated => "scim_group_created",
            Self::ScimGroupUpdated => "scim_group_updated",
            Self::ScimGroupDeleted => "scim_group_deleted",
            Self::RoleAssigned => "role_assigned",
            Self::RoleRevoked => "role_revoked",
            Self::OrphanedReferenceSkipped => "orphaned_reference_skipped",
            Self::UserPermissionGranted => "user_permission_granted",
            Self::UserPermissionRevoked => "user_permission_revoked",
            Self::ClientConsentGranted => "client_consent_granted",
            Self::ClientConsentRevoked => "client_consent_revoked",
            Self::ConsentRequiredOnRefresh => "consent_required_on_refresh",
            Self::Cleanup => "cleanup",
            Self::LoginFailed => "login_failed",
            Self::LoginLocked => "login_locked",
            Self::IpLoginLimitExceeded => "ip_login_limit_exceeded",
            Self::BackupCreated => "backup_created",
            Self::BackupRestored => "backup_restored",
            Self::RequiredActionAssigned => "required_action_assigned",
            Self::RequiredActionRemoved => "required_action_removed",
            Self::RequiredActionCompleted => "required_action_completed",
            Self::RequiredActionAutoCleared => "required_action_auto_cleared",
            Self::PasswordCompromisedRejected => "password_compromised_rejected",
            Self::BreachCheckUnavailable => "breach_check_unavailable",
            Self::StepUpMfaTriggered => "step_up_mfa_triggered",
            Self::StepUpMfaCompleted => "step_up_mfa_completed",
            Self::SmsOtpEnrollmentStarted => "sms_otp_enrollment_started",
            Self::SmsOtpEnrollmentVerified => "sms_otp_enrollment_verified",
            Self::SmsOtpEnrollmentFailed => "sms_otp_enrollment_failed",
            Self::SmsMfaChallengeSucceeded => "sms_mfa_challenge_succeeded",
            Self::SmsMfaChallengeFailed => "sms_mfa_challenge_failed",
            Self::SmsMfaLocked => "sms_mfa_locked",
            Self::DeviceFingerprintsErased => "device_fingerprints_erased",
            Self::SessionLimitEnforced => "session_limit_enforced",
            Self::SessionsRevoked => "sessions_revoked",
            Self::AbuseDetected => "abuse_detected",
            Self::EmailChangeInitiated => "email_change_initiated",
            Self::EmailChangeConfirmed => "email_change_confirmed",
            Self::OidcSilentAuthProbed => "oidc_silent_auth_probed",
            Self::RealmExportWatermarked => "realm_export_watermarked",
            Self::AgentCreated => "agent_created",
            Self::AgentUpdated => "agent_updated",
            Self::AgentSuspended => "agent_suspended",
            Self::AgentReactivated => "agent_reactivated",
            Self::AgentRevoked => "agent_revoked",
            Self::AgentDeleted => "agent_deleted",
            Self::AgentCredentialCreated => "agent_credential_created",
            Self::AgentCredentialRevoked => "agent_credential_revoked",
            // M2 delegation + MCP
            Self::AgentDelegation => "agent_delegation",
            Self::AgentToolInvocation => "agent_tool_invocation",
            Self::ApprovalRequested => "approval_requested",
            Self::ApprovalGranted => "approval_granted",
            Self::ApprovalDenied => "approval_denied",
            Self::AgentTokenRevoked => "agent_token_revoked",
            Self::CrossRealmTrustCreated => "cross_realm_trust_created",
            Self::CrossRealmTrustRevoked => "cross_realm_trust_revoked",
            Self::ProtectedResourceRegistered => "protected_resource_registered",
            Self::ProtectedResourceUpdated => "protected_resource_updated",
            Self::ProtectedResourceDeleted => "protected_resource_deleted",
            // Phase D
            Self::AatIssued => "aat_issued",
            Self::AatRevoked => "aat_revoked",
            Self::TransactionTokenIssued => "transaction_token_issued",
            Self::CrossRealmTokenIssued => "cross_realm_token_issued",
            Self::SpiffeIdMapped => "spiffe_id_mapped",
            Self::SpiffeAuthSuccess => "spiffe_auth_success",
            Self::AuditLogPruned => "audit_log_pruned",
            Self::MfaEnabled => "mfa_enabled",
            Self::MfaDisabled => "mfa_disabled",
        }
    }
}

impl std::str::FromStr for AuditAction {
    type Err = String;

    #[allow(clippy::too_many_lines)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user_created" => Ok(Self::UserCreated),
            "user_updated" => Ok(Self::UserUpdated),
            "user_deleted" => Ok(Self::UserDeleted),
            "credential_set" => Ok(Self::CredentialSet),
            "credential_changed" => Ok(Self::CredentialChanged),
            "credential_verified" => Ok(Self::CredentialVerified),
            "session_created" => Ok(Self::SessionCreated),
            "session_revoked" => Ok(Self::SessionRevoked),
            "session_evicted" => Ok(Self::SessionEvicted),
            "token_issued" => Ok(Self::TokenIssued),
            "token_refreshed" => Ok(Self::TokenRefreshed),
            "realm_created" => Ok(Self::RealmCreated),
            "realm_updated" => Ok(Self::RealmUpdated),
            "realm_deleted" => Ok(Self::RealmDeleted),
            "client_registered" => Ok(Self::ClientRegistered),
            "authz_code_issued" => Ok(Self::AuthorizationCodeIssued),
            "authz_code_exchanged" => Ok(Self::AuthorizationCodeExchanged),
            "tuple_written" => Ok(Self::TupleWritten),
            "tuple_deleted" => Ok(Self::TupleDeleted),
            "client_updated" => Ok(Self::ClientUpdated),
            "client_deleted" => Ok(Self::ClientDeleted),
            "bulk_users_created" => Ok(Self::BulkUsersCreated),
            "bulk_users_disabled" => Ok(Self::BulkUsersDisabled),
            "org_created" => Ok(Self::OrgCreated),
            "org_updated" => Ok(Self::OrgUpdated),
            "org_deleted" => Ok(Self::OrgDeleted),
            "group_created" => Ok(Self::GroupCreated),
            "group_updated" => Ok(Self::GroupUpdated),
            "group_deleted" => Ok(Self::GroupDeleted),
            "group_member_added" => Ok(Self::GroupMemberAdded),
            "group_member_removed" => Ok(Self::GroupMemberRemoved),
            "group_member_role_changed" => Ok(Self::GroupMemberRoleChanged),
            "consent_granted" => Ok(Self::ConsentGranted),
            "consent_denied" => Ok(Self::ConsentDenied),
            "consent_revoked" => Ok(Self::ConsentRevoked),
            "federation_login_started" => Ok(Self::FederationLoginStarted),
            "federation_login_completed" => Ok(Self::FederationLoginCompleted),
            "federation_account_linked" => Ok(Self::FederationAccountLinked),
            "federation_account_unlinked" => Ok(Self::FederationAccountUnlinked),
            "federation_jit_provisioned" => Ok(Self::FederationJitProvisioned),
            "saml_login_initiated" => Ok(Self::SamlLoginInitiated),
            "saml_login_completed" => Ok(Self::SamlLoginCompleted),
            "saml_login_failed" => Ok(Self::SamlLoginFailed),
            "saml_idp_authn_request_received" => Ok(Self::SamlIdpAuthnRequestReceived),
            "saml_idp_response_issued" => Ok(Self::SamlIdpResponseIssued),
            "saml_idp_initiated_sso" => Ok(Self::SamlIdpInitiatedSso),
            "saml_slo_requested" => Ok(Self::SamlSloRequested),
            "saml_slo_completed" => Ok(Self::SamlSloCompleted),
            "scim_user_created" => Ok(Self::ScimUserCreated),
            "scim_user_updated" => Ok(Self::ScimUserUpdated),
            "scim_user_deleted" => Ok(Self::ScimUserDeleted),
            "scim_group_created" => Ok(Self::ScimGroupCreated),
            "scim_group_updated" => Ok(Self::ScimGroupUpdated),
            "scim_group_deleted" => Ok(Self::ScimGroupDeleted),
            "role_assigned" => Ok(Self::RoleAssigned),
            "role_revoked" => Ok(Self::RoleRevoked),
            "orphaned_reference_skipped" => Ok(Self::OrphanedReferenceSkipped),
            "user_permission_granted" => Ok(Self::UserPermissionGranted),
            "user_permission_revoked" => Ok(Self::UserPermissionRevoked),
            "client_consent_granted" => Ok(Self::ClientConsentGranted),
            "client_consent_revoked" => Ok(Self::ClientConsentRevoked),
            "consent_required_on_refresh" => Ok(Self::ConsentRequiredOnRefresh),
            "cleanup" => Ok(Self::Cleanup),
            "login_failed" => Ok(Self::LoginFailed),
            "login_locked" => Ok(Self::LoginLocked),
            "ip_login_limit_exceeded" => Ok(Self::IpLoginLimitExceeded),
            "backup_created" => Ok(Self::BackupCreated),
            "backup_restored" => Ok(Self::BackupRestored),
            "required_action_assigned" => Ok(Self::RequiredActionAssigned),
            "required_action_removed" => Ok(Self::RequiredActionRemoved),
            "required_action_completed" => Ok(Self::RequiredActionCompleted),
            "required_action_auto_cleared" => Ok(Self::RequiredActionAutoCleared),
            "password_compromised_rejected" => Ok(Self::PasswordCompromisedRejected),
            "breach_check_unavailable" => Ok(Self::BreachCheckUnavailable),
            "step_up_mfa_triggered" => Ok(Self::StepUpMfaTriggered),
            "step_up_mfa_completed" => Ok(Self::StepUpMfaCompleted),
            "sms_otp_enrollment_started" => Ok(Self::SmsOtpEnrollmentStarted),
            "sms_otp_enrollment_verified" => Ok(Self::SmsOtpEnrollmentVerified),
            "sms_otp_enrollment_failed" => Ok(Self::SmsOtpEnrollmentFailed),
            "sms_mfa_challenge_succeeded" => Ok(Self::SmsMfaChallengeSucceeded),
            "sms_mfa_challenge_failed" => Ok(Self::SmsMfaChallengeFailed),
            "sms_mfa_locked" => Ok(Self::SmsMfaLocked),
            "device_fingerprints_erased" => Ok(Self::DeviceFingerprintsErased),
            "session_limit_enforced" => Ok(Self::SessionLimitEnforced),
            "sessions_revoked" => Ok(Self::SessionsRevoked),
            "abuse_detected" => Ok(Self::AbuseDetected),
            "email_change_initiated" => Ok(Self::EmailChangeInitiated),
            "email_change_confirmed" => Ok(Self::EmailChangeConfirmed),
            "oidc_silent_auth_probed" => Ok(Self::OidcSilentAuthProbed),
            "realm_export_watermarked" => Ok(Self::RealmExportWatermarked),
            "agent_created" => Ok(Self::AgentCreated),
            "agent_updated" => Ok(Self::AgentUpdated),
            "agent_suspended" => Ok(Self::AgentSuspended),
            "agent_reactivated" => Ok(Self::AgentReactivated),
            "agent_revoked" => Ok(Self::AgentRevoked),
            "agent_deleted" => Ok(Self::AgentDeleted),
            "agent_credential_created" => Ok(Self::AgentCredentialCreated),
            "agent_credential_revoked" => Ok(Self::AgentCredentialRevoked),
            // M2 delegation + MCP
            "agent_delegation" => Ok(Self::AgentDelegation),
            "agent_tool_invocation" => Ok(Self::AgentToolInvocation),
            "approval_requested" => Ok(Self::ApprovalRequested),
            "approval_granted" => Ok(Self::ApprovalGranted),
            "approval_denied" => Ok(Self::ApprovalDenied),
            "agent_token_revoked" => Ok(Self::AgentTokenRevoked),
            "cross_realm_trust_created" => Ok(Self::CrossRealmTrustCreated),
            "cross_realm_trust_revoked" => Ok(Self::CrossRealmTrustRevoked),
            "protected_resource_registered" => Ok(Self::ProtectedResourceRegistered),
            "protected_resource_updated" => Ok(Self::ProtectedResourceUpdated),
            "protected_resource_deleted" => Ok(Self::ProtectedResourceDeleted),
            // Phase D
            "aat_issued" => Ok(Self::AatIssued),
            "aat_revoked" => Ok(Self::AatRevoked),
            "transaction_token_issued" => Ok(Self::TransactionTokenIssued),
            "cross_realm_token_issued" => Ok(Self::CrossRealmTokenIssued),
            "spiffe_id_mapped" => Ok(Self::SpiffeIdMapped),
            "spiffe_auth_success" => Ok(Self::SpiffeAuthSuccess),
            "audit_log_pruned" => Ok(Self::AuditLogPruned),
            "mfa_enabled" => Ok(Self::MfaEnabled),
            "mfa_disabled" => Ok(Self::MfaDisabled),
            other => Err(format!("unknown audit action: {other}")),
        }
    }
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the identity engine should handle a failed audit append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFailurePolicy {
    /// Log a warning and continue. The mutation succeeded but the
    /// audit event was lost; the WAL is still the durable record.
    LogOnly,
    /// Log an error AND return [`crate::identity::IdentityError::AuditFailure`]
    /// to the caller. The mutation already happened (it is in the WAL),
    /// but the caller learns that no audit trail was created.
    FailOperation,
}

impl AuditAction {
    /// Returns the failure policy for this action.
    ///
    /// Non-destructive mutations use [`AuditFailurePolicy::LogOnly`].
    /// Destructive / security-sensitive mutations (deletions,
    /// credential changes, consent revocations, bulk disables) use
    /// [`AuditFailurePolicy::FailOperation`] so operators are alerted
    /// when an auditable destructive operation happens without a
    /// corresponding audit event.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn failure_policy(&self) -> AuditFailurePolicy {
        use AuditFailurePolicy::{FailOperation, LogOnly};
        match self {
            // ---- LogOnly (non-destructive) ----
            Self::UserCreated
            | Self::UserUpdated
            | Self::CredentialSet
            | Self::CredentialVerified
            | Self::SessionCreated
            | Self::TokenIssued
            | Self::TokenRefreshed
            | Self::RealmCreated
            | Self::RealmUpdated
            | Self::ClientRegistered
            | Self::ClientUpdated
            | Self::AuthorizationCodeIssued
            | Self::AuthorizationCodeExchanged
            | Self::TupleWritten
            | Self::OrgCreated
            | Self::OrgUpdated
            | Self::GroupCreated
            | Self::GroupUpdated
            | Self::GroupMemberAdded
            | Self::GroupMemberRoleChanged
            | Self::BulkUsersCreated
            | Self::ConsentGranted
            | Self::FederationLoginStarted
            | Self::FederationLoginCompleted
            | Self::FederationAccountLinked
            | Self::FederationJitProvisioned
            | Self::SamlLoginInitiated
            | Self::SamlLoginCompleted
            | Self::SamlIdpAuthnRequestReceived
            | Self::SamlIdpResponseIssued
            | Self::SamlIdpInitiatedSso
            | Self::SamlSloRequested
            | Self::SamlSloCompleted
            | Self::ScimUserCreated
            | Self::ScimUserUpdated
            | Self::ScimGroupCreated
            | Self::ScimGroupUpdated
            | Self::RoleAssigned
            | Self::UserPermissionGranted
            | Self::UserPermissionRevoked
            | Self::ClientConsentGranted
            | Self::OrphanedReferenceSkipped
            | Self::ConsentRequiredOnRefresh
            | Self::Cleanup
            | Self::LoginFailed
            | Self::IpLoginLimitExceeded
            | Self::BackupCreated
            | Self::BackupRestored
            | Self::RequiredActionAssigned
            | Self::RequiredActionRemoved
            | Self::RequiredActionCompleted
            | Self::RequiredActionAutoCleared
            | Self::BreachCheckUnavailable
            | Self::StepUpMfaTriggered
            | Self::StepUpMfaCompleted
            | Self::SmsOtpEnrollmentStarted
            | Self::SmsOtpEnrollmentVerified
            | Self::SmsMfaChallengeSucceeded
            | Self::SessionLimitEnforced
            | Self::SessionEvicted
            | Self::AbuseDetected
            | Self::EmailChangeInitiated
            | Self::OidcSilentAuthProbed
            | Self::RealmExportWatermarked
            | Self::AgentCreated
            | Self::AgentUpdated
            | Self::AgentSuspended
            | Self::AgentReactivated
            | Self::AgentCredentialCreated
            // M2: delegation events are informational
            | Self::AgentDelegation
            | Self::AgentToolInvocation
            | Self::ApprovalRequested
            | Self::ApprovalGranted
            | Self::ApprovalDenied
            | Self::CrossRealmTrustCreated
            | Self::ProtectedResourceRegistered
            | Self::ProtectedResourceUpdated
            // Phase D — non-destructive issuance events
            | Self::AatIssued
            | Self::TransactionTokenIssued
            | Self::CrossRealmTokenIssued
            | Self::SpiffeIdMapped
            | Self::SpiffeAuthSuccess
            // Meta-event about the audit log itself; loss is not critical.
            | Self::AuditLogPruned
            // Enabling MFA strengthens auth posture; non-destructive.
            | Self::MfaEnabled => LogOnly,
            // ---- FailOperation (destructive / security-sensitive) ----
            Self::UserDeleted
            | Self::CredentialChanged
            | Self::SessionRevoked
            | Self::RealmDeleted
            | Self::ClientDeleted
            | Self::TupleDeleted
            | Self::OrgDeleted
            | Self::GroupDeleted
            | Self::GroupMemberRemoved
            | Self::BulkUsersDisabled
            | Self::ConsentRevoked
            | Self::ConsentDenied
            | Self::FederationAccountUnlinked
            | Self::SamlLoginFailed
            | Self::ScimUserDeleted
            | Self::ScimGroupDeleted
            | Self::RoleRevoked
            | Self::ClientConsentRevoked
            | Self::LoginLocked
            | Self::PasswordCompromisedRejected
            | Self::SmsOtpEnrollmentFailed
            | Self::SmsMfaChallengeFailed
            | Self::SmsMfaLocked
            | Self::DeviceFingerprintsErased
            | Self::SessionsRevoked
            // Email-change confirmation revokes all sessions — security-sensitive.
            | Self::EmailChangeConfirmed
            // Agent revocation and deletion are terminal/security-sensitive.
            | Self::AgentRevoked
            | Self::AgentDeleted
            // Credential revocation is a terminal security action — must be audited.
            | Self::AgentCredentialRevoked
            // Token revocation and cross-realm trust teardown are security-sensitive.
            | Self::AgentTokenRevoked
            | Self::CrossRealmTrustRevoked
            | Self::ProtectedResourceDeleted
            // Phase D — AAT revocation is security-sensitive.
            | Self::AatRevoked
            // Disabling MFA weakens authentication posture — must not be lost.
            | Self::MfaDisabled => FailOperation,
        }
    }
}

/// A recorded audit event in the append-only log.
///
/// Each event forms part of a hash chain for tamper detection.
/// The `integrity_hash` links to the previous event's hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique identifier for this event.
    pub id: AuditEventId,
    /// The realm this event belongs to.
    pub realm_id: RealmId,
    /// The actor who performed the action (user ID, "system", etc.).
    pub actor: String,
    /// The type of action performed.
    pub action: AuditAction,
    /// The type of resource affected (e.g., "user", "session", "realm").
    pub resource_type: String,
    /// The identifier of the affected resource.
    pub resource_id: String,
    /// When the event occurred.
    pub timestamp: Timestamp,
    /// Optional additional context (e.g., IP address, user agent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// SHA-256 hash chain link: `SHA256(prev_hash || event_data)`.
    ///
    /// For the first event in a realm's log, `prev_hash` is the
    /// string "genesis".
    pub integrity_hash: String,
}

/// Request to append a new audit event.
///
/// The caller provides the event details; the engine assigns the `id`,
/// `timestamp`, and `integrity_hash`.
#[derive(Clone, Debug)]
pub struct CreateAuditEvent {
    /// The realm this event belongs to.
    pub realm_id: RealmId,
    /// The actor who performed the action.
    pub actor: String,
    /// The type of action performed.
    pub action: AuditAction,
    /// The type of resource affected.
    pub resource_type: String,
    /// The identifier of the affected resource.
    pub resource_id: String,
    /// Optional additional context.
    pub metadata: Option<serde_json::Value>,
}

/// Retention configuration for a realm's audit log (A-25).
///
/// Controls automatic pruning of old audit events. Pruning intentionally
/// breaks the hash chain for the removed window — this is expected and
/// acceptable for compliance-driven data deletion (e.g., COPPA).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRetentionConfig {
    /// Number of days to retain audit events. `0` means unlimited (no pruning).
    /// Default: 90 days.
    pub retention_days: u32,
    /// Hard row backstop (A-25): if the realm has more than this many audit
    /// events after the time-based prune pass, the oldest rows are removed
    /// until the count is within the limit. `None` means no row backstop.
    ///
    /// Use this together with `retention_days` for defence-in-depth: the
    /// time window bounds normal growth; `max_rows` caps runaway event storms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rows: Option<u64>,
}

impl Default for AuditRetentionConfig {
    fn default() -> Self {
        Self {
            retention_days: 90,
            max_rows: None,
        }
    }
}

/// Query parameters for filtering audit events.
///
/// All filters are optional and combined with AND semantics.
/// Results are always returned in chronological order.
#[derive(Clone, Debug)]
pub struct AuditQuery {
    /// Filter by realm (required).
    pub realm_id: RealmId,
    /// Only events at or after this timestamp.
    pub start_time: Option<Timestamp>,
    /// Only events before this timestamp (exclusive).
    pub end_time: Option<Timestamp>,
    /// Only events by this actor.
    pub actor: Option<String>,
    /// Only events of this action type.
    pub action: Option<AuditAction>,
    /// Maximum number of events to return.
    pub limit: Option<usize>,
    /// Only events involving this agent ID (§12.4 MUST).
    ///
    /// Matches audit events where `metadata.agent_id` equals the provided
    /// string. Covers delegation (`AgentDelegation`), approval (`ApprovalRequested`,
    /// `ApprovalGranted`, `ApprovalDenied`), AAT (`AatIssued`, `AatRevoked`),
    /// and tool-invocation (`ToolInvoked`) events.
    pub agent_id: Option<String>,
    /// Only events involving this tool name (§12.4 MUST).
    ///
    /// Matches `ToolInvoked` and `ApprovalRequested` events where
    /// `metadata.tool` equals the provided name.
    pub tool: Option<String>,
}

impl AuditQuery {
    /// Creates a new query for a specific realm with no filters.
    pub fn for_realm(realm_id: RealmId) -> Self {
        Self {
            realm_id,
            start_time: None,
            end_time: None,
            actor: None,
            action: None,
            limit: None,
            agent_id: None,
            tool: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_action_as_str_round_trips() {
        let actions = [
            AuditAction::UserCreated,
            AuditAction::UserUpdated,
            AuditAction::UserDeleted,
            AuditAction::CredentialSet,
            AuditAction::SessionCreated,
            AuditAction::RealmCreated,
            AuditAction::TupleWritten,
        ];
        for action in &actions {
            let s = action.as_str();
            assert!(!s.is_empty(), "action {action:?} has empty string");
        }
    }

    #[test]
    fn audit_action_display() {
        let action = AuditAction::UserCreated;
        assert_eq!(format!("{action}"), "user_created");
    }

    #[test]
    fn audit_action_serde_round_trip() {
        let action = AuditAction::SessionRevoked;
        let json = serde_json::to_string(&action).expect("serialize");
        let deserialized: AuditAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(action, deserialized);
    }

    #[test]
    fn audit_event_serde_round_trip() {
        let event = AuditEvent {
            id: AuditEventId::generate(),
            realm_id: RealmId::generate(),
            actor: "user_123".to_string(),
            action: AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "user_456".to_string(),
            timestamp: Timestamp::from_micros(1_700_000_000_000_000),
            metadata: Some(serde_json::json!({"ip": "127.0.0.1"})),
            integrity_hash: "abc123".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let deserialized: AuditEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, deserialized);
    }

    #[test]
    fn create_audit_event_debug() {
        let req = CreateAuditEvent {
            realm_id: RealmId::generate(),
            actor: "system".to_string(),
            action: AuditAction::RealmCreated,
            resource_type: "realm".to_string(),
            resource_id: "realm_789".to_string(),
            metadata: None,
        };
        let debug = format!("{req:?}");
        assert!(debug.contains("RealmCreated"));
    }
}
