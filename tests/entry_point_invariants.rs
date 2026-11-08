//! Entry-point invariant registry (OpenSpec `trusted-core-confidence` group 3, #640).
//!
//! Most past Critical defects were one entry point that skipped a check that
//! its siblings made. This file lists every entry point that creates a session
//! or issues a token, as data:
//!
//! - [`ENTRY_POINTS`]: the HTTP routes that create a session, issue a token,
//!   issue an authorization code or approve a grant.
//! - [`NON_ISSUING_ROUTES`]: every other route. Each route in the router must
//!   be in exactly one of the two tables.
//! - [`CLI_ENTRY_POINTS`] and [`CLI_NON_ISSUING`]: the same split for the CLI
//!   subcommands.
//!
//! The guard tests walk the route tree in the source (`.route(...)` calls under
//! `src/`) and the `Subcommand` enums in `src/main.rs`. axum cannot list the
//! routes of a built `Router`, so the walk reads the source. A route or
//! subcommand that is not classified fails the guard and names the route. A row
//! that no longer matches a route also fails, so the tables cannot rot.
//!
//! When the guard fails on a new route: read its handler. If it can create a
//! session or issue a token, add a row to [`ENTRY_POINTS`] (the invariant tests
//! then cover it). Otherwise add it to [`NON_ISSUING_ROUTES`].
//!
//! The invariant tests (below the guard) run each entry point against six
//! invariants: realm status, organization status, user status, client status,
//! the MFA policy and the pre-token webhook. A new row in [`ENTRY_POINTS`]
//! needs a driver in `entry_point_invariants/drivers.rs`; until then
//! `drivers::run` panics on it. Each invariant applies to a case, or the rule
//! gives the reason why not, or a `TRACKED` row names the open issue.

mod common;

#[path = "support/browser.rs"]
mod browser;
#[path = "entry_point_invariants/drivers.rs"]
mod drivers;
#[path = "entry_point_invariants/fixture.rs"]
mod fixture;
#[path = "common/webauthn_helper.rs"]
mod webauthn_helper;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use drivers::{Case, Variant, GRANTS, ORG_GRANTS};
use fixture::Violation;

// ─── Registry ───────────────────────────────────────────────────────────────

/// What an entry point gives the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Issues {
    /// A browser session (the session cookie), or the step that completes one.
    Session,
    /// An access token (and maybe a refresh or ID token).
    Token,
    /// An authorization code, redeemed later at `/token`.
    Code,
    /// The user's approval of a device code, redeemed later at `/token`.
    DeviceApproval,
    /// A long-lived credential (an API key or an operator token).
    Credential,
}

/// When the route is in the router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Build {
    /// Every build.
    Always,
    /// Only builds with the `dev-endpoints` feature, run with `--dev`.
    DevEndpoints,
}

/// One HTTP route that creates a session or issues a token.
#[derive(Debug)]
struct EntryPoint {
    /// Stable name, used in failure messages.
    id: &'static str,
    /// Source file with the `.route(...)` call.
    file: &'static str,
    /// HTTP method.
    method: &'static str,
    /// Path as written in the `.route(...)` call, before any `nest` prefix.
    path: &'static str,
    /// Last path segment of the handler function.
    handler: &'static str,
    /// Path that a client calls (with the `nest` prefix).
    url: &'static str,
    /// What the entry point gives the caller.
    issues: Issues,
    /// When the route is in the router.
    build: Build,
}

/// Shorthand for an [`EntryPoint`] row.
const fn ep(
    id: &'static str,
    file: &'static str,
    route: (&'static str, &'static str, &'static str),
    url: &'static str,
    issues: Issues,
    build: Build,
) -> EntryPoint {
    EntryPoint {
        id,
        file,
        method: route.0,
        path: route.1,
        handler: route.2,
        url,
        issues,
        build,
    }
}

const WEB: &str = "src/protocol/web/mod.rs";
const OAUTH: &str = "src/protocol/http/oauth.rs";
const ADVANCED: &str = "src/protocol/http/advanced.rs";
const AGENTS: &str = "src/protocol/http/agents.rs";
const HTTP: &str = "src/protocol/http.rs";
const DEV_CONSOLE: &str = "src/protocol/web/dev_console.rs";

use Build::{Always, DevEndpoints};
use Issues::{Code, Credential, DeviceApproval, Session, Token};

/// Every HTTP route that creates a session or issues a token (task 3.1).
#[rustfmt::skip]
const ENTRY_POINTS: &[EntryPoint] = &[
    // Browser sign-in: first factor.
    ep("password-login", WEB, ("POST", "/login", "login_submit"), "/ui/login", Session, Always),
    ep("password-login-realm", WEB, ("POST", "/realms/{realm}/login", "login_submit_scoped"), "/ui/realms/{realm}/login", Session, Always),
    ep("password-login-admin", WEB, ("POST", "/admin/login", "admin_login_submit"), "/ui/admin/login", Session, Always),
    ep("passkey-login", WEB, ("POST", "/login/passkey-complete", "passkey_login_complete"), "/ui/login/passkey-complete", Session, Always),
    ep("passkey-login-realm", WEB, ("POST", "/realms/{realm}/login/passkey-complete", "passkey_login_complete_scoped"), "/ui/realms/{realm}/login/passkey-complete", Session, Always),
    ep("passkey-login-admin", WEB, ("POST", "/admin/login/passkey-complete", "passkey_login_complete_admin"), "/ui/admin/login/passkey-complete", Session, Always),
    ep("magic-link", WEB, ("POST", "/magic-link", "magic_link_redeem"), "/ui/magic-link", Session, Always),
    ep("magic-link-realm", WEB, ("POST", "/realms/{realm}/magic-link", "magic_link_redeem_scoped"), "/ui/realms/{realm}/magic-link", Session, Always),
    // Browser sign-in: second factor and forced enrolment.
    ep("totp-step", WEB, ("POST", "/mfa-challenge", "mfa_challenge_submit"), "/ui/mfa-challenge", Session, Always),
    ep("email-otp-step", WEB, ("POST", "/mfa-otp-challenge", "mfa_otp_challenge_submit"), "/ui/mfa-otp-challenge", Session, Always),
    ep("passkey-step", WEB, ("POST", "/mfa-passkey-challenge/complete", "mfa_passkey_challenge_complete"), "/ui/mfa-passkey-challenge/complete", Session, Always),
    ep("mfa-enroll-required", WEB, ("POST", "/mfa-enroll-required/activate", "mfa_enroll_required_submit"), "/ui/mfa-enroll-required/activate", Session, Always),
    // Browser sign-in: required actions. Each one can finish the pending
    // sign-in when it is the last action.
    ep("ra-verify-email-page", WEB, ("GET", "/required-action/VERIFY_EMAIL", "verify_email_page"), "/required-action/VERIFY_EMAIL", Session, Always),
    ep("ra-verify-email-confirm", WEB, ("POST", "/required-action/VERIFY_EMAIL/confirm", "verify_email_confirm_submit"), "/required-action/VERIFY_EMAIL/confirm", Session, Always),
    ep("ra-update-password", WEB, ("POST", "/required-action/UPDATE_PASSWORD", "update_password_submit"), "/required-action/UPDATE_PASSWORD", Session, Always),
    ep("ra-email-otp-page", WEB, ("GET", "/required-action/ENROLL_EMAIL_OTP", "enroll_email_otp_page"), "/required-action/ENROLL_EMAIL_OTP", Session, Always),
    ep("ra-email-otp-verify", WEB, ("POST", "/required-action/ENROLL_EMAIL_OTP/verify", "enroll_email_otp_verify_submit"), "/required-action/ENROLL_EMAIL_OTP/verify", Session, Always),
    ep("ra-enroll-mfa-page", WEB, ("GET", "/required-action/enroll-mfa", "enroll_mfa_page"), "/required-action/enroll-mfa", Session, Always),
    ep("ra-enroll-mfa", WEB, ("POST", "/required-action/enroll-mfa", "enroll_mfa_submit"), "/required-action/enroll-mfa", Session, Always),
    ep("ra-enroll-passkey", WEB, ("POST", "/required-action/enroll-mfa/passkey/complete", "passkey_complete"), "/required-action/enroll-mfa/passkey/complete", Session, Always),
    // Browser sign-in: federation (social OIDC/OAuth and SAML).
    ep("social-callback", WEB, ("GET", "/federation/callback", "callback"), "/ui/federation/callback", Session, Always),
    ep("social-callback-post", WEB, ("POST", "/federation/callback", "callback_post"), "/ui/federation/callback", Session, Always),
    ep("social-callback-realm", WEB, ("GET", "/realms/{realm}/federation/callback", "callback_scoped"), "/ui/realms/{realm}/federation/callback", Session, Always),
    ep("social-callback-realm-post", WEB, ("POST", "/realms/{realm}/federation/callback", "callback_scoped_post"), "/ui/realms/{realm}/federation/callback", Session, Always),
    ep("social-confirm-link", WEB, ("POST", "/federation/confirm-link", "confirm_link_submit"), "/ui/federation/confirm-link", Session, Always),
    ep("social-confirm-link-realm", WEB, ("POST", "/realms/{realm}/federation/confirm-link", "confirm_link_submit_scoped"), "/ui/realms/{realm}/federation/confirm-link", Session, Always),
    ep("saml-acs", WEB, ("POST", "/realms/{realm}/federation/saml/acs", "sp_acs"), "/ui/realms/{realm}/federation/saml/acs", Session, Always),
    // OAuth 2.0 / OIDC: authorization codes and device approval.
    ep("authorize-browser", WEB, ("GET", "/oauth/authorize", "authorize_get"), "/ui/oauth/authorize", Code, Always),
    ep("authorize-browser-realm", WEB, ("GET", "/realms/{realm}/oauth/authorize", "authorize_get_scoped"), "/ui/realms/{realm}/oauth/authorize", Code, Always),
    ep("consent", WEB, ("POST", "/oauth/consent", "consent_submit"), "/ui/oauth/consent", Code, Always),
    ep("authorize-api", OAUTH, ("POST", "/authorize", "authorize"), "/authorize", Code, Always),
    ep("authorize-api-realm", OAUTH, ("POST", "/authorize", "realm_authorize"), "/realms/{realm_name}/authorize", Code, Always),
    ep("device-approval", WEB, ("POST", "/device", "device_approve_submit"), "/ui/device", DeviceApproval, Always),
    // OAuth 2.0 token endpoint: every grant (authorization_code,
    // refresh_token, client_credentials, device_code, jwt-bearer,
    // token-exchange, magic-link).
    ep("token", OAUTH, ("POST", "/token", "token_exchange"), "/token", Token, Always),
    ep("token-realm", OAUTH, ("POST", "/token", "realm_token_exchange"), "/realms/{realm_name}/token", Token, Always),
    // Agent and delegation tokens.
    ep("aat-issue", ADVANCED, ("POST", "/v1/aats", "issue_aat"), "/v1/aats", Token, Always),
    ep("aat-derive", ADVANCED, ("POST", "/v1/aats/derive", "derive_aat"), "/v1/aats/derive", Token, Always),
    ep("transaction-token", ADVANCED, ("POST", "/v1/transaction-tokens", "issue_transaction_token"), "/v1/transaction-tokens", Token, Always),
    ep("agent-api-key", AGENTS, ("POST", "/v1/agents/{id}/credentials/keys", "create_api_key"), "/v1/agents/{id}/credentials/keys", Credential, Always),
    // Admin console.
    ep("admin-api-token", WEB, ("POST", "/admin/api-tokens", "admin_api_token_issue"), "/ui/admin/api-tokens", Credential, Always),
    // Development builds only.
    ep("dev-console-sign-in", DEV_CONSOLE, ("POST", "/dev/sign-in/{account}", "sign_in"), "/ui/dev/sign-in/{account}", Session, DevEndpoints),
    ep("dev-bootstrap", HTTP, ("POST", "/admin/bootstrap", "admin_bootstrap"), "/admin/bootstrap", Token, DevEndpoints),
    ep("dev-seed-session", HTTP, ("POST", "/dev/seed-session", "dev_seed_session"), "/dev/seed-session", Session, DevEndpoints),
    ep("dev-seed-token", HTTP, ("POST", "/dev/seed-token", "dev_seed_token"), "/dev/seed-token", Token, DevEndpoints),
];

/// One CLI subcommand that creates a session or issues a token.
#[derive(Debug)]
struct CliEntryPoint {
    /// Stable name, used in failure messages.
    id: &'static str,
    /// `Enum::Variant` of the clap subcommand in `src/main.rs`.
    variant: &'static str,
    /// What an operator types.
    command: &'static str,
    /// What the command gives the caller.
    issues: Issues,
}

/// Every CLI subcommand that creates a session or issues a token (task 3.1).
const CLI_ENTRY_POINTS: &[CliEntryPoint] = &[CliEntryPoint {
    id: "cli-admin-token",
    variant: "AdminAction::Token",
    command: "hearth admin token",
    issues: Token,
}];

/// Every other CLI subcommand, with the reason it issues nothing.
const CLI_NON_ISSUING: &[(&str, &str)] = &[
    (
        "Commands::Serve",
        "runs the server; its routes are classified above",
    ),
    ("Commands::Realm", "group"),
    ("Commands::App", "group"),
    ("Commands::Migrate", "group"),
    ("Commands::Config", "group"),
    ("Commands::Rbac", "group"),
    ("Commands::Backup", "group"),
    ("Commands::Admin", "group"),
    ("Commands::Completions", "prints a shell completion script"),
    ("BackupAction::Create", "writes an archive of existing data"),
    (
        "BackupAction::Restore",
        "restores existing data; mints nothing",
    ),
    ("BackupAction::Sign", "signs an archive"),
    (
        "BackupAction::Keygen",
        "creates an archive-signing key pair",
    ),
    ("BackupAction::Verify", "checks an archive signature"),
    ("BackupAction::Inspect", "reads an archive"),
    (
        "MigrateSource::Keycloak",
        "imports users; creates no session",
    ),
    ("MigrateSource::Auth0", "imports users; creates no session"),
    (
        "MigrateSource::RotatePepper",
        "re-keys stored password hashes",
    ),
    ("RealmAction::Create", "creates a realm"),
    (
        "ConfigAction::Reload",
        "asks a running server to reload its config",
    ),
    ("ConfigAction::Validate", "checks a config file"),
    ("ConfigAction::Example", "prints an example config"),
    ("RbacAction::Orphans", "group"),
    ("OrphansAction::List", "lists orphaned RBAC rows"),
    ("OrphansAction::Purge", "deletes orphaned RBAC rows"),
    (
        "AppAction::Create",
        "registers a client; tokens for it come only from /token",
    ),
];

/// Every route that does not create a session or issue a token, per source
/// file, as `"METHOD path handler"`. `closure` names an inline handler.
#[rustfmt::skip]
const NON_ISSUING_ROUTES: &[(&str, &[&str])] = &[
    (
        "src/protocol/http/admin.rs",
        &[
            "GET /users admin_list_users",
            "POST /users admin_create_user",
            "POST /users/bulk admin_bulk_users",
            "POST /users/import admin_import_users",
            "GET /users/export admin_export_users",
            "GET /users/{id} admin_get_user",
            "PATCH /users/{id} admin_update_user",
            "DELETE /users/{id} admin_delete_user",
            "POST /users/{id}/password-email admin_send_password_email",
            "GET /realms admin_list_realms",
            "POST /realms admin_create_realm",
            "GET /realms/{id} admin_get_realm",
            "PATCH /realms/{id} admin_update_realm",
            "DELETE /realms/{id} admin_delete_realm",
            "POST /realms/{id}/rotate-signing-key admin_rotate_realm_signing_key",
            "POST /realms/{id}/suspend admin_suspend_realm",
            "POST /realms/{id}/unsuspend admin_unsuspend_realm",
            "GET /realms/{id}/branding admin_get_realm_branding",
            "PATCH /realms/{id}/branding admin_patch_realm_branding",
            "GET /realms/{id}/email-templates admin_list_realm_email_templates",
            "GET /realms/{id}/email-templates/{kind} admin_get_realm_email_template",
            "PUT /realms/{id}/email-templates/{kind} admin_put_realm_email_template",
            "DELETE /realms/{id}/email-templates/{kind} admin_delete_realm_email_template",
            "GET /applications admin_list_clients",
            "POST /applications admin_register_client",
            "GET /applications/{id} admin_get_client",
            "PATCH /applications/{id} admin_update_client",
            "DELETE /applications/{id} admin_delete_client",
            "POST /applications/{id}/regenerate-secret admin_regenerate_client_secret",
            "GET /users/{id}/consents admin_list_user_consents",
            "DELETE /users/{id}/consents/{client_id} admin_revoke_user_consent",
            "GET /users/{id}/effective-permissions admin_get_user_effective_permissions",
            "GET /audit admin_list_audit",
            "GET /roles admin_list_roles",
            "POST /roles admin_create_role",
            "GET /roles/{id}/members admin_list_role_members",
            "GET /permissions admin_list_permissions",
            "POST /audit/verify admin_verify_audit",
            "POST /groups/{id}/roles admin_assign_group_role",
            "GET /users/{id}/permissions admin_list_user_permissions",
            "POST /users/{id}/permissions admin_grant_user_permission",
            "DELETE /users/{id}/permissions/{permission} admin_revoke_user_permission",
            "GET /organizations admin_list_organizations",
            "POST /organizations admin_create_organization",
            "GET /organizations/{id} admin_get_organization",
            "PATCH /organizations/{id} admin_update_organization",
            "DELETE /organizations/{id} admin_delete_organization",
            "GET /organizations/{id}/members/{user_id}/roles admin_list_additional_roles",
            "POST /organizations/{id}/members/{user_id}/roles admin_add_additional_role",
            "DELETE /organizations/{id}/members/{user_id}/roles/{role_name} admin_remove_additional_role",
            "GET /roles/{id} admin_get_role",
            "PATCH /roles/{id} admin_update_role",
            "DELETE /roles/{id} admin_delete_role",
            "GET /groups admin_list_groups",
            "POST /groups admin_create_group",
            "GET /groups/{id} admin_get_group",
            "PATCH /groups/{id} admin_update_group",
            "DELETE /groups/{id} admin_delete_group",
            "GET /groups/{id}/members admin_list_group_members",
            "POST /groups/{id}/members admin_add_group_member",
            "DELETE /groups/{id}/members/{member_id} admin_remove_group_member",
            "GET /users/{id}/roles admin_list_user_assignments",
            "POST /users/{id}/roles admin_assign_role",
            "DELETE /assignments/{id} admin_unassign_role",
            "GET /webhooks admin_list_webhooks",
            "POST /webhooks admin_create_webhook",
            "GET /webhooks/{id} admin_get_webhook",
            "PUT /webhooks/{id} admin_update_webhook",
            "DELETE /webhooks/{id} admin_delete_webhook",
            "GET /webhooks/{id}/deliveries admin_list_webhook_deliveries",
            "POST /backup admin_backup_create",
            "POST /backup/restore admin_backup_restore",
            "PATCH /realms/{realm_id}/users/{user_id}/required-actions admin_patch_user_required_actions",
            "PATCH /realms/{realm_id}/config admin_patch_realm_config",
            "GET /realms/{realm_id}/cross-realm-policies admin_list_cross_realm_policies",
            "POST /realms/{realm_id}/cross-realm-policies admin_create_cross_realm_policy",
            "DELETE /realms/{realm_id}/cross-realm-policies/{policy_id} admin_delete_cross_realm_policy",
            "POST /sessions/{session_id}/sv-bump admin_sv_bump_session",
            "DELETE /sessions/{id} admin_revoke_session",
            "GET /users/{id}/sessions admin_list_user_sessions",
            "POST /realms/{realm_id}/sv-bump-all admin_sv_bump_all",
            "POST /cluster/bootstrap admin_cluster_bootstrap",
            "GET /cluster/status admin_cluster_status",
            "POST /cluster/transfer-leadership admin_cluster_transfer_leadership",
        ],
    ),
    (
        "src/protocol/http/advanced.rs",
        &[
            "POST /v1/aats/validate validate_aat",
            "DELETE /v1/aats/{jti} revoke_aat",
            "POST /v1/transaction-tokens/consume consume_transaction_token",
            "POST /v1/spiffe-mappings register_spiffe_mapping",
            "GET /v1/spiffe-mappings/{agent_id} get_spiffe_mapping",
            "DELETE /v1/spiffe-mappings/{agent_id} delete_spiffe_mapping",
            "GET /v1/cross-realm-policies list_cross_realm_policies",
            "POST /v1/cross-realm-policies create_cross_realm_policy",
            "GET /v1/cross-realm-policies/{id} get_cross_realm_policy",
            "DELETE /v1/cross-realm-policies/{id} delete_cross_realm_policy",
        ],
    ),
    (
        "src/protocol/http/agents.rs",
        &[
            "GET /.well-known/agent.json agent_card",
            "GET /v1/agents list_agents",
            "POST /v1/agents create_agent",
            "GET /v1/agents/{id} get_agent",
            "PATCH /v1/agents/{id} update_agent",
            "DELETE /v1/agents/{id} delete_agent",
            "POST /v1/agents/{id}/suspend suspend_agent",
            "POST /v1/agents/{id}/reactivate reactivate_agent",
            "POST /v1/agents/{id}/revoke revoke_agent",
            "GET /v1/agents/{id}/credentials list_credentials",
            "DELETE /v1/agents/{id}/credentials/{cred_id} revoke_credential",
        ],
    ),
    (
        "src/protocol/http/approval.rs",
        &[
            "GET /v1/approval-requests list_approval_requests",
            "POST /v1/approval-requests create_approval_request",
            "GET /v1/approval-requests/{id} get_approval_request",
            "POST /v1/approval-requests/{id}/approve approve_approval_request",
            "POST /v1/approval-requests/{id}/deny deny_approval_request",
        ],
    ),
    (
        "src/protocol/http/health.rs",
        &[
            "GET /health health",
            "GET /healthz healthz",
            "GET /readyz readyz",
            "GET /metrics metrics_handler",
        ],
    ),
    (
        "src/protocol/http/mfa.rs",
        &[
            "POST /webauthn/register/begin webauthn_register_begin",
            "POST /webauthn/register/complete webauthn_register_complete",
            "POST /webauthn/auth/begin webauthn_auth_begin",
            "POST /webauthn/auth/complete webauthn_auth_complete",
            "GET /webauthn/credentials webauthn_list_credentials",
            "DELETE /webauthn/credentials/{credential_id} webauthn_delete_credential",
            "POST /v1/{realm}/auth/magic-link magic_link_request",
        ],
    ),
    (
        "src/protocol/http/oauth.rs",
        &[
            "GET /.well-known/openid-configuration oidc_discovery",
            "GET /.well-known/oauth-protected-resource protected_resource_metadata",
            "GET /jwks jwks",
            "GET /certs jwks",
            "GET /.well-known/jwks.json jwks",
            "POST /register register_client_dynamic",
            "GET /authorize authorize_browser_redirect",
            "POST /as/par pushed_authorization_request",
            "OPTIONS /token token_preflight",
            "POST /revoke token_revocation",
            "OPTIONS /revoke token_preflight",
            "POST /introspect token_introspection",
            "OPTIONS /introspect token_preflight",
            "POST /device_authorization device_authorization",
            "OPTIONS /device_authorization token_preflight",
            "GET /userinfo userinfo",
            "GET /v1/me/permissions me_permissions",
            "POST /oauth/authorize oauth_decide_permission",
            "GET /oauth/consents self_list_consents",
            "DELETE /oauth/consents/{client_id} self_revoke_consent",
            "POST /clients register_client",
            "GET /.well-known/openid-configuration realm_oidc_discovery",
            "GET /.well-known/jwks.json realm_jwks",
            "GET /authorize realm_authorize_browser_redirect",
            "POST /as/par realm_pushed_authorization_request",
            "OPTIONS /token realm_token_preflight",
            "POST /revoke realm_token_revocation",
            "OPTIONS /revoke realm_token_preflight",
            "POST /introspect realm_token_introspection",
            "OPTIONS /introspect realm_token_preflight",
            "POST /device_authorization realm_device_authorization",
            "OPTIONS /device_authorization realm_token_preflight",
            "GET /userinfo realm_userinfo",
            "POST /register realm_register_client_dynamic",
        ],
    ),
    (
        "src/protocol/http/session.rs",
        &[
            "GET /end_session end_session",
            "POST /end_session end_session",
            "GET /oauth/session-versions oauth_sv_delta_feed",
            "GET /oauth/session-versions/snapshot oauth_sv_snapshot",
            "GET /end_session realm_end_session",
            "POST /end_session realm_end_session",
        ],
    ),
    (
        "src/protocol/http/tool_invocation.rs",
        &[
            "POST /v1/tools/invoke invoke_tool",
        ],
    ),
    (
        "src/protocol/http/users.rs",
        &[
            "POST /users create_user",
        ],
    ),
    (
        "src/protocol/http.rs",
        &[
            "GET /dev/probe-user dev_probe_user",
            "POST /dev/seed-password dev_seed_password",
        ],
    ),
    (
        "src/protocol/scim/mod.rs",
        &[
            "GET /ServiceProviderConfig service_provider_config",
            "GET /ResourceTypes resource_types",
            "GET /Schemas schemas",
            "POST /Users create_user",
            "GET /Users list_users",
            "GET /Users/{id} get_user",
            "PUT /Users/{id} replace_user",
            "DELETE /Users/{id} delete_user",
            "PATCH /Users/{id} patch_user",
            "POST /Groups create_group",
            "GET /Groups list_groups",
            "GET /Groups/{id} get_group",
            "PUT /Groups/{id} replace_group",
            "DELETE /Groups/{id} delete_group",
            "PATCH /Groups/{id} patch_group",
        ],
    ),
    (
        "src/protocol/web/dev_console.rs",
        &[
            "GET /dev console",
            "GET /dev/codes codes",
            "GET /dev/credentials credentials",
        ],
    ),
    (
        "src/protocol/web/mailcatcher.rs",
        &[
            "GET /dev/mail inbox",
            "DELETE /dev/mail clear_inbox",
            "POST /dev/mail/clear clear_inbox",
            "GET /dev/mail/login login_form",
            "POST /dev/mail/login login_submit",
            "GET /dev/mail/{id} email_detail",
            "DELETE /dev/mail/{id} delete_email",
            "POST /dev/mail/{id}/delete delete_email",
        ],
    ),
    (
        "src/protocol/web/mod.rs",
        &[
            "GET /admin closure",
            "GET /ui/ closure",
            "GET /setup setup_form",
            "POST /setup setup_submit",
            "GET /setup/sent setup_sent",
            "GET /verify-email verify_email",
            "POST /verify-email verify_email_submit",
            "GET /login login_form",
            "GET /login/passkey-begin passkey_login_begin",
            "GET /mfa-challenge mfa_challenge_form",
            "GET /mfa-otp-challenge mfa_otp_challenge_form",
            "GET /mfa-passkey-challenge mfa_passkey_challenge_form",
            "POST /mfa-passkey-challenge/begin mfa_passkey_challenge_begin",
            "GET /mfa-enroll-required mfa_enroll_required_form",
            "GET /forgot-password forgot_password_form",
            "POST /forgot-password forgot_password_submit",
            "GET /accept-invitation accept_invitation_page",
            "POST /accept-invitation accept_invitation_submit",
            "GET /forgot-password/sent forgot_password_sent",
            "GET /reset-password reset_password_form",
            "POST /reset-password reset_password_submit",
            "GET /magic-link magic_link_page",
            "GET /register register_form",
            "POST /register register_submit",
            "GET /register/sent register_sent",
            "GET /realms/{realm}/login login_form_scoped",
            "GET /realms/{realm}/login/passkey-begin passkey_login_begin_scoped",
            "GET /realms/{realm}/register register_form_scoped",
            "POST /realms/{realm}/register register_submit_scoped",
            "GET /realms/{realm}/register/sent register_sent_scoped",
            "GET /realms/{realm}/forgot-password forgot_password_form_scoped",
            "POST /realms/{realm}/forgot-password forgot_password_submit_scoped",
            "GET /realms/{realm}/forgot-password/sent forgot_password_sent_scoped",
            "GET /realms/{realm}/reset-password reset_password_form_scoped",
            "POST /realms/{realm}/reset-password reset_password_submit_scoped",
            "GET /realms/{realm}/magic-link magic_link_page_scoped",
            "GET /realms/{realm}/verify-email verify_email_scoped",
            "POST /realms/{realm}/verify-email verify_email_submit_scoped",
            "GET /realms/{realm}/accept-invitation accept_invitation_page_scoped",
            "POST /realms/{realm}/accept-invitation accept_invitation_submit_scoped",
            "GET /admin/login admin_login_form",
            "GET /admin/login/passkey-begin passkey_login_begin_admin",
            "GET /admin/verify-email admin_verify_email",
            "POST /admin/verify-email admin_verify_email_submit",
            "GET /admin/forgot-password admin_forgot_password_form",
            "POST /admin/forgot-password admin_forgot_password_submit",
            "GET /admin/forgot-password/sent admin_forgot_password_sent",
            "GET /admin/reset-password admin_reset_password_form",
            "POST /admin/reset-password admin_reset_password_submit",
            "GET / dashboard",
            "GET /device device_approve_form",
            "POST /logout logout_submit",
            "GET /account account_index",
            "POST /account/password account_change_password",
            "GET /account/totp totp_enroll_form",
            "POST /account/totp/activate totp_activate",
            "POST /account/totp/disable totp_disable",
            "GET /account/totp/recovery-codes.txt totp_download_recovery_codes",
            "POST /account/totp/regenerate-codes totp_regenerate_codes",
            "POST /account/passkeys/step-up-begin passkey_step_up_begin",
            "POST /account/passkeys/register-begin passkey_register_begin",
            "POST /account/passkeys/register-complete passkey_register_complete",
            "POST /account/passkeys/{cred_id}/delete passkey_delete",
            "POST /account/passkeys/{cred_id}/rename passkey_rename",
            "GET /account/sessions sessions_index",
            "POST /account/sessions/revoke-others revoke_other_sessions",
            "POST /account/sessions/{sid}/revoke revoke_session",
            "GET /account/consents consents_index",
            "GET /account/applications account_applications",
            "POST /account/consents/revoke-all revoke_all_consents",
            "POST /account/applications/revoke-all revoke_all_consents",
            "POST /account/consents/{client_id}/revoke revoke_consent",
            "POST /account/applications/{client_id}/revoke revoke_consent",
            "GET /consent/delegations delegations_index",
            "POST /consent/delegations/{delegation_id}/revoke revoke_delegation",
            "GET /account/linked-accounts linked_accounts_index",
            "POST /account/linked-accounts/{idp_id}/unlink unlink",
            "GET /federation/begin begin",
            "GET /federation/confirm-link confirm_link_page",
            "GET /realms/{realm}/federation/begin begin_scoped",
            "GET /realms/{realm}/federation/confirm-link confirm_link_page_scoped",
            "GET /realms/{realm}/federation/saml/metadata sp_metadata",
            "GET /realms/{realm}/federation/saml/begin sp_begin",
            "GET /oauth/consent consent_page",
            "GET /admin/onboarding admin_onboarding_get",
            "POST /admin/onboarding/realm admin_onboarding_realm_post",
            "GET /admin/onboarding/app admin_onboarding_app_get",
            "POST /admin/onboarding/app admin_onboarding_app_post",
            "GET /admin/onboarding/invite admin_onboarding_invite_get",
            "POST /admin/onboarding/invite admin_onboarding_invite_post",
            "GET /admin/onboarding/email admin_onboarding_email_get",
            "POST /admin/onboarding/email/test admin_onboarding_email_test_post",
            "GET /admin/onboarding/complete admin_onboarding_complete_get",
            "GET /admin/admin-users admin_admin_users_list",
            "GET /admin/admin-users/new admin_admin_user_create_alias",
            "GET /admin/admin-users/import admin_admin_users_import_form",
            "POST /admin/admin-users/import admin_admin_users_import_submit",
            "GET /admin/admin-users/import/template.csv admin_admin_users_import_template_csv",
            "GET /admin/api-tokens admin_api_token_form",
            "GET /admin/migrations admin_migrations_list",
            "POST /admin/migrations/orphans/resolve admin_migrations_orphan_resolve",
            "GET /admin/realms admin_realms_list",
            "GET /admin/realms/{realm}/users admin_users_list",
            "GET /admin/realms/{realm}/users/new admin_user_create_form",
            "POST /admin/realms/{realm}/users/new admin_user_create_submit",
            "GET /admin/realms/{realm}/users/{id} admin_user_detail",
            "GET /admin/realms/{realm}/users/{id}/edit admin_user_edit_form",
            "POST /admin/realms/{realm}/users/{id}/edit admin_user_edit_submit",
            "POST /admin/realms/{realm}/users/{id}/delete admin_user_delete",
            "POST /admin/realms/{realm}/users/{id}/reset-password admin_user_send_reset",
            "POST /admin/realms/{realm}/users/{id}/disable-mfa admin_user_disable_mfa",
            "POST /admin/realms/{realm}/users/{id}/reset-mfa-codes admin_user_reset_mfa_codes",
            "POST /admin/realms/{realm}/users/{id}/sessions/{sid}/revoke admin_user_revoke_session",
            "POST /admin/realms/{realm}/users/{id}/webauthn/{cred_id}/revoke admin_user_revoke_webauthn",
            "POST /admin/realms/{realm}/users/{id}/roles/assign admin_user_assign_role",
            "POST /admin/realms/{realm}/users/{id}/roles/{assignment_id}/unassign admin_user_unassign_role",
            "POST /admin/realms/{realm}/users/{id}/permissions/grant admin_user_grant_permission",
            "POST /admin/realms/{realm}/users/{id}/permissions/revoke admin_user_revoke_permission",
            "GET /admin/realms/{realm}/users/{id}/consents admin_user_consents_list",
            "GET /admin/realms/{realm}/users/{id}/applications admin_user_consents_list",
            "POST /admin/realms/{realm}/users/{id}/consents/{client_id}/revoke admin_user_consent_revoke",
            "POST /admin/realms/{realm}/users/{id}/applications/{client_id}/revoke admin_user_consent_revoke",
            "PATCH /admin/realms/{realm}/users/{id}/required-actions admin_api_user_required_actions_patch",
            "PATCH /admin/realms/{realm}/config admin_api_realm_config_patch",
            "GET /admin/realms/{realm} admin_realm_detail",
            "POST /admin/realms/{realm}/delete admin_realm_delete",
            "GET /admin/realms/{realm}/admins/picker admin_realm_admin_picker",
            "POST /admin/realms/{realm}/admins/grant admin_realm_admin_grant",
            "POST /admin/realms/{realm}/admins/{uid}/revoke admin_realm_admin_revoke",
            "GET /admin/realms/{realm}/claims admin_realm_claims",
            "GET /admin/realms/{realm}/rbac/debug admin_rbac_debug",
            "GET /admin/realms/{realm}/permissions/resolve admin_permissions_resolve_alias",
            "GET /admin/realms/{realm}/rbac/token-preview admin_rbac_token_preview",
            "GET /admin/realms/{realm}/rbac/permissions admin_rbac_permissions",
            "GET /admin/realms/{realm}/rbac/roles admin_rbac_roles",
            "GET /admin/realms/{realm}/rbac/roles/new admin_role_create_form",
            "POST /admin/realms/{realm}/rbac/roles/new admin_role_create_submit",
            "GET /admin/realms/{realm}/rbac/roles/{id} admin_role_detail",
            "GET /admin/realms/{realm}/rbac/roles/{id}/edit admin_role_edit_form",
            "POST /admin/realms/{realm}/rbac/roles/{id}/edit admin_role_edit_submit",
            "POST /admin/realms/{realm}/rbac/roles/{id}/delete admin_role_delete",
            "GET /admin/realms/{realm}/rbac/scopes admin_rbac_scopes",
            "GET /admin/realms/{realm}/organizations admin_orgs_list",
            "GET /admin/realms/{realm}/organizations/new admin_org_create_form",
            "POST /admin/realms/{realm}/organizations/new admin_org_create_submit",
            "POST /admin/realms/{realm}/organizations/bulk-delete admin_orgs_bulk_delete",
            "GET /admin/realms/{realm}/organizations/{id} admin_org_detail",
            "GET /admin/realms/{realm}/organizations/{id}/edit admin_org_edit_form",
            "POST /admin/realms/{realm}/organizations/{id}/edit admin_org_edit_submit",
            "POST /admin/realms/{realm}/organizations/{id}/delete admin_org_delete",
            "POST /admin/realms/{realm}/organizations/{id}/members admin_org_add_member",
            "GET /admin/realms/{realm}/organizations/{id}/members/picker admin_org_member_picker",
            "POST /admin/realms/{realm}/organizations/{id}/members/{uid}/remove admin_org_remove_member",
            "POST /admin/realms/{realm}/organizations/{id}/members/{uid}/role admin_org_update_role",
            "POST /admin/realms/{realm}/organizations/{id}/invite admin_org_invite",
            "POST /admin/realms/{realm}/organizations/{id}/status admin_org_status_toggle",
            "POST /admin/realms/{realm}/organizations/{id}/invitations/{iid}/revoke admin_org_revoke_invite",
            "POST /admin/realms/{realm}/organizations/{id}/invitations/{iid}/resend admin_org_resend_invite",
            "POST /admin/realms/{realm}/organizations/{id}/members/{uid}/rbac/assign admin_org_member_assign_role",
            "POST /admin/realms/{realm}/organizations/{id}/members/{uid}/rbac/{aid}/unassign admin_org_member_unassign_role",
            "POST /admin/realms/{realm}/organizations/{id}/members/{uid}/permissions/grant admin_org_member_grant_perm",
            "POST /admin/realms/{realm}/organizations/{id}/members/{uid}/permissions/revoke admin_org_member_revoke_perm",
            "GET /admin/realms/{realm}/groups admin_groups_list",
            "GET /admin/realms/{realm}/groups/new admin_group_create_form",
            "POST /admin/realms/{realm}/groups/new admin_group_create_submit",
            "GET /admin/realms/{realm}/groups/{id} admin_group_detail",
            "GET /admin/realms/{realm}/groups/{id}/edit admin_group_edit_form",
            "POST /admin/realms/{realm}/groups/{id}/edit admin_group_edit_submit",
            "POST /admin/realms/{realm}/groups/{id}/delete admin_group_delete",
            "POST /admin/realms/{realm}/groups/{id}/members admin_group_member_add",
            "GET /admin/realms/{realm}/groups/{id}/members/picker admin_group_member_picker",
            "POST /admin/realms/{realm}/groups/{id}/members/{kind}/{mid}/remove admin_group_member_remove",
            "POST /admin/realms/{realm}/groups/{id}/roles/assign admin_group_role_assign",
            "POST /admin/realms/{realm}/groups/{id}/roles/{aid}/unassign admin_group_role_unassign",
            "GET /admin/realms/{realm}/api/users/search admin_api_user_search",
            "GET /admin/realms/{realm}/rbac/api/users/search admin_api_rbac_user_search",
            "POST /admin/api/config/reload admin_api_config_reload",
            "GET /admin/api/nav/realms admin_api_nav_realms",
            "GET /admin/realms/{realm}/applications admin_apps_list",
            "GET /admin/realms/{realm}/applications/new admin_app_create_form",
            "POST /admin/realms/{realm}/applications/new admin_app_create_submit",
            "GET /admin/realms/{realm}/applications/{id} admin_app_detail",
            "GET /admin/realms/{realm}/applications/{id}/edit admin_app_edit_form",
            "POST /admin/realms/{realm}/applications/{id}/edit admin_app_edit_submit",
            "POST /admin/realms/{realm}/applications/{id}/delete admin_app_delete",
            "POST /admin/realms/{realm}/applications/{id}/regenerate-secret admin_app_regenerate_secret",
            "GET /admin/realms/{realm}/identity-providers admin_idp_list",
            "GET /admin/realms/{realm}/identity-providers/{id} admin_idp_detail",
            "GET /admin/realms/{realm}/sessions admin_sessions_list",
            "POST /admin/realms/{realm}/sessions/{id}/revoke admin_session_revoke",
            "GET /admin/realms/{realm}/audit admin_audit_list",
            "POST /admin/realms/{realm}/audit/verify admin_audit_verify_integrity",
            "GET /admin/realms/{realm}/audit/export admin_audit_export",
            "GET /admin/api/realms/{realm}/audit/events admin_api_audit_events",
            "GET /admin/api/realms/{realm}/audit/config admin_api_audit_config_get",
            "PUT /admin/api/realms/{realm}/audit/config admin_api_audit_config_put",
            "POST /admin/api/realms/{realm}/audit/prune admin_api_audit_prune",
            "GET /admin/settings admin_system_info",
            "GET /admin/settings/editor admin_config_editor",
            "POST /admin/settings/editor/preview admin_config_editor_preview",
            "POST /admin/settings/editor/apply admin_config_editor_apply",
            "POST /admin/settings/editor/visual/preview admin_config_editor_visual_preview",
            "POST /admin/settings/editor/visual/validate admin_config_editor_visual_validate",
            "POST /admin/settings/editor/visual/apply admin_config_editor_visual_apply",
            "POST /admin/settings/editor/visual/export admin_config_editor_visual_export",
            "GET /admin/settings/editor/export admin_config_editor_export",
            "POST /admin/test-email admin_test_email",
            "POST /admin/realms/{realm}/users/bulk-action admin_users_bulk_action",
            "GET /admin/realms/{realm}/users/import admin_users_import_form",
            "POST /admin/realms/{realm}/users/import admin_users_import_submit",
            "GET /admin/realms/{realm}/users/import/template.csv admin_users_import_template_csv",
            "GET /admin/realms/{realm}/abuse admin_abuse_dashboard",
            "GET /admin/realms/{realm}/webhooks admin_webhooks_list",
            "GET /admin/realms/{realm}/webhooks/new admin_webhook_create_form",
            "POST /admin/realms/{realm}/webhooks/new admin_webhook_create_submit",
            "POST /admin/realms/{realm}/webhooks/test-ping admin_webhook_test_ping",
            "GET /admin/realms/{realm}/webhooks/{id}/edit admin_webhook_edit_form",
            "POST /admin/realms/{realm}/webhooks/{id}/edit admin_webhook_edit_submit",
            "POST /admin/realms/{realm}/webhooks/{id}/delete admin_webhook_delete",
            "POST /admin/realms/{realm}/webhooks/{id}/test admin_webhook_test",
            "GET /admin/realms/{realm}/approvals admin_approvals_queue",
            "GET /admin/realms/{realm}/approvals/{id} admin_approval_detail",
            "POST /admin/realms/{realm}/approvals/{id}/approve admin_approval_approve",
            "POST /admin/realms/{realm}/approvals/{id}/deny admin_approval_deny",
            "GET /static/{*file} serve_static",
            "GET /favicon.ico serve_favicon",
            "GET /favicon.svg serve_favicon",
            "GET /required-action/VERIFY_EMAIL/confirm verify_email_confirm",
            "GET /required-action/UPDATE_PASSWORD update_password_page",
            "POST /required-action/ENROLL_EMAIL_OTP/send enroll_email_otp_send",
            "POST /required-action/enroll-mfa/passkey/begin passkey_begin",
        ],
    ),
    (
        "src/protocol/web/openapi.rs",
        &[
            "GET /openapi.json serve_openapi_json",
            "GET /openapi.yaml serve_openapi_yaml",
            "GET /docs serve_swagger_ui",
            "GET /docs/assets/swagger-ui.css serve_swagger_css",
            "GET /docs/assets/swagger-ui-bundle.js serve_swagger_bundle",
            "GET /docs/assets/init.js serve_swagger_init",
        ],
    ),
];

// ─── Source walk ────────────────────────────────────────────────────────────

/// One `.route(...)` method handler found in the source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FoundRoute {
    file: String,
    method: String,
    path: String,
    handler: String,
    line: usize,
}

impl FoundRoute {
    fn key(&self) -> RouteKey {
        (
            self.file.clone(),
            self.method.clone(),
            self.path.clone(),
            self.handler.clone(),
        )
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `dir`, except test-only files (`tests.rs`, `tests/`).
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("read source dir")
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name != "tests" && name != "generated" {
                rust_sources(&path, out);
            }
        } else if path.extension().is_some_and(|x| x == "rs") && name != "tests.rs" {
            out.push(path);
        }
    }
}

/// The source before an inline `#[cfg(test)] mod tests {` block.
fn strip_test_module(src: &str) -> &str {
    let mut from = 0;
    while let Some(at) = src[from..].find("#[cfg(test)]") {
        let start = from + at;
        let rest = src[start + "#[cfg(test)]".len()..].trim_start();
        if let Some(after) = rest.strip_prefix("mod tests") {
            if after.trim_start().starts_with('{') {
                return &src[..start];
            }
        }
        from = start + 1;
    }
    src
}

/// Index just past the `)` that closes the `(` before `open`, skipping string
/// literals and line comments.
fn matching_paren(bytes: &[u8], open: usize) -> usize {
    let mut depth = 1usize;
    let mut i = open;
    while depth > 0 {
        assert!(i < bytes.len(), "unbalanced `.route(` call");
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'"' => {
                i += 1;
                while bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while bytes[i] != b'\n' {
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    i
}

/// Drops leading whitespace and `//` comment lines.
fn skip_comments(mut s: &str) -> &str {
    loop {
        s = s.trim_start();
        if s.starts_with("//") {
            s = s.find('\n').map_or("", |n| &s[n..]);
        } else {
            return s;
        }
    }
}

const METHODS: &[&str] = &[
    "get", "post", "put", "delete", "patch", "head", "options", "trace", "any",
];

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The `(METHOD, handler)` pairs of a method-router expression such as
/// `axum::routing::get(handlers::a).post(b)`. Only tokens outside nested
/// brackets count, so a closure body cannot add a method.
fn method_handlers(expr: &str) -> Vec<(String, String)> {
    let bytes = expr.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'{' | b'[' => depth += 1,
            b')' | b'}' | b']' => depth -= 1,
            b'"' => {
                i += 1;
                while bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            c if depth == 0 && is_ident(c) && (i == 0 || !is_ident(bytes[i - 1])) => {
                let start = i;
                while i < bytes.len() && is_ident(bytes[i]) {
                    i += 1;
                }
                let word = &expr[start..i];
                let after = expr[i..].trim_start();
                if METHODS.contains(&word) && after.starts_with('(') {
                    let arg = skip_comments(&after[1..]);
                    let handler = if arg.starts_with('|') || arg.starts_with("move") {
                        "closure".to_string()
                    } else {
                        let end = arg
                            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
                            .unwrap_or(arg.len());
                        arg[..end].rsplit("::").next().unwrap_or("").to_string()
                    };
                    out.push((word.to_ascii_uppercase(), handler));
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Walks every `.route(...)` call under `src/` (test modules excluded).
///
/// Panics on a call the walk cannot read (a path that is not a string
/// literal, or a method router that is not an inline `get(..)`-style chain),
/// so a route cannot hide from the guard.
fn walk_routes() -> Vec<FoundRoute> {
    let root = repo_root();
    let mut files = Vec::new();
    rust_sources(&root.join("src"), &mut files);
    let mut routes = Vec::new();
    for file in files {
        let full = std::fs::read_to_string(&file).expect("read source");
        let src = strip_test_module(&full);
        let rel = file
            .strip_prefix(&root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = src.as_bytes();
        let mut from = 0;
        while let Some(at) = src[from..].find(".route(") {
            let open = from + at + ".route(".len();
            let line_start = src[..from + at].rfind('\n').map_or(0, |n| n + 1);
            if src[line_start..from + at].trim_start().starts_with("//") {
                from = open;
                continue;
            }
            let close = matching_paren(bytes, open);
            let line = src[..open].matches('\n').count() + 1;
            let args = skip_comments(&src[open..close - 1]);
            let path = args
                .strip_prefix('"')
                .and_then(|a| a.split_once('"'))
                .unwrap_or_else(|| {
                    panic!("{rel}:{line}: route path is not a string literal; teach walk_routes")
                });
            let expr = path
                .1
                .trim_start()
                .strip_prefix(',')
                .unwrap_or_else(|| panic!("{rel}:{line}: no method router after the path"));
            let pairs = method_handlers(expr);
            assert!(
                !pairs.is_empty(),
                "{rel}:{line}: route {} has no inline method router; teach walk_routes",
                path.0
            );
            for (method, handler) in pairs {
                routes.push(FoundRoute {
                    file: rel.clone(),
                    method,
                    path: path.0.to_string(),
                    handler,
                    line,
                });
            }
            from = close;
        }
    }
    routes
}

/// Every `Enum::Variant` of the `#[derive(Subcommand)]` enums in `src/main.rs`.
fn walk_cli_variants() -> Vec<String> {
    let src = std::fs::read_to_string(repo_root().join("src/main.rs")).expect("read main.rs");
    let mut out = Vec::new();
    let mut lines = src.lines();
    while let Some(line) = lines.next() {
        if !(line.starts_with("#[derive(") && line.contains("Subcommand")) {
            continue;
        }
        let name = lines
            .by_ref()
            .find_map(|l| {
                l.strip_prefix("enum ")
                    .or_else(|| l.strip_prefix("pub enum "))
                    .or_else(|| l.strip_prefix("pub(crate) enum "))
            })
            .and_then(|l| l.split_whitespace().next())
            .expect("enum after #[derive(Subcommand)]")
            .to_string();
        for l in lines.by_ref() {
            if l.starts_with('}') {
                break;
            }
            let Some(rest) = l.strip_prefix("    ") else {
                continue;
            };
            if rest.starts_with(|c: char| c.is_ascii_uppercase()) {
                let end = rest
                    .find(|c: char| !c.is_ascii_alphanumeric())
                    .unwrap_or(rest.len());
                out.push(format!("{name}::{}", &rest[..end]));
            }
        }
    }
    out
}

/// `(file, method, path, handler)` of one route.
type RouteKey = (String, String, String, String);

fn registry_keys() -> (BTreeSet<RouteKey>, BTreeSet<RouteKey>) {
    let issuing = ENTRY_POINTS
        .iter()
        .map(|e| {
            (
                e.file.to_string(),
                e.method.to_string(),
                e.path.to_string(),
                e.handler.to_string(),
            )
        })
        .collect();
    let mut other = BTreeSet::new();
    for (file, rows) in NON_ISSUING_ROUTES {
        for row in *rows {
            let mut parts = row.splitn(3, ' ');
            let (Some(m), Some(p), Some(h)) = (parts.next(), parts.next(), parts.next()) else {
                panic!("{file}: bad row {row:?}; want \"METHOD path handler\"");
            };
            assert!(
                other.insert((
                    file.to_string(),
                    m.to_string(),
                    p.to_string(),
                    h.to_string()
                )),
                "{file}: duplicate row {row:?}"
            );
        }
    }
    (issuing, other)
}

// ─── Guard tests ────────────────────────────────────────────────────────────

/// The walk sees the real route tree: it finds the token endpoint and a few
/// hundred routes. Without this, an empty walk would pass every guard.
#[test]
fn the_walk_finds_the_route_tree() {
    let routes = walk_routes();
    assert!(
        routes.len() > 400,
        "the walk found only {} routes; it no longer reads the router",
        routes.len()
    );
    for (file, method, path, handler) in [
        (OAUTH, "POST", "/token", "token_exchange"),
        (WEB, "POST", "/login", "login_submit"),
        (WEB, "GET", "/admin", "closure"),
    ] {
        assert!(
            routes.iter().any(|r| r.file == file
                && r.method == method
                && r.path == path
                && r.handler == handler),
            "the walk did not find {method} {path} -> {handler} in {file}"
        );
    }
}

/// Every route in the router is in exactly one of [`ENTRY_POINTS`] and
/// [`NON_ISSUING_ROUTES`]. A new route fails here until someone classifies it.
#[test]
fn every_route_is_classified() {
    let (issuing, other) = registry_keys();
    let mut unclassified = Vec::new();
    for route in walk_routes() {
        let key = route.key();
        let (a, b) = (issuing.contains(&key), other.contains(&key));
        assert!(
            !(a && b),
            "{}:{}: {} {} -> {} is in both tables",
            route.file,
            route.line,
            route.method,
            route.path,
            route.handler
        );
        if !a && !b {
            unclassified.push(format!(
                "  {}:{}: {} {} -> {}",
                route.file, route.line, route.method, route.path, route.handler
            ));
        }
    }
    assert!(
        unclassified.is_empty(),
        "routes missing from the entry-point registry. If a route can create a session \
         or issue a token, add it to ENTRY_POINTS; otherwise add it to \
         NON_ISSUING_ROUTES:\n{}",
        unclassified.join("\n")
    );
}

/// Every registry row names a route that exists, so the tables cannot rot.
#[test]
fn every_registry_row_matches_a_route() {
    let found: BTreeSet<_> = walk_routes().iter().map(FoundRoute::key).collect();
    let (issuing, other) = registry_keys();
    let stale: Vec<String> = issuing
        .iter()
        .chain(other.iter())
        .filter(|k| !found.contains(*k))
        .map(|(f, m, p, h)| format!("  {f}: {m} {p} -> {h}"))
        .collect();
    assert!(
        stale.is_empty(),
        "registry rows with no matching route (remove or update them):\n{}",
        stale.join("\n")
    );
}

/// Entry-point ids are unique, so failure messages name one row.
#[test]
fn entry_point_ids_are_unique() {
    let mut seen = BTreeMap::new();
    for e in ENTRY_POINTS {
        if let Some(prev) = seen.insert(e.id, e.url) {
            panic!("duplicate entry-point id {} ({prev} and {})", e.id, e.url);
        }
    }
    for c in CLI_ENTRY_POINTS {
        assert!(
            seen.insert(c.id, c.command).is_none(),
            "duplicate id {}",
            c.id
        );
    }
}

/// Every CLI subcommand is in exactly one of [`CLI_ENTRY_POINTS`] and
/// [`CLI_NON_ISSUING`], and every row names a subcommand that exists.
#[test]
fn every_cli_subcommand_is_classified() {
    let found: BTreeSet<String> = walk_cli_variants().into_iter().collect();
    assert!(
        found.contains("AdminAction::Token") && found.len() > 20,
        "the CLI walk found only {found:?}; it no longer reads src/main.rs"
    );
    let issuing: BTreeSet<String> = CLI_ENTRY_POINTS
        .iter()
        .map(|c| c.variant.to_string())
        .collect();
    let other: BTreeSet<String> = CLI_NON_ISSUING
        .iter()
        .map(|(v, _)| (*v).to_string())
        .collect();
    let unclassified: Vec<_> = found
        .iter()
        .filter(|v| !issuing.contains(*v) && !other.contains(*v))
        .collect();
    assert!(
        unclassified.is_empty(),
        "CLI subcommands missing from the entry-point registry. If one can create a \
         session or issue a token, add it to CLI_ENTRY_POINTS; otherwise add it to \
         CLI_NON_ISSUING with a reason: {unclassified:?}"
    );
    let both: Vec<_> = issuing.intersection(&other).collect();
    assert!(both.is_empty(), "CLI subcommands in both tables: {both:?}");
    let stale: Vec<_> = issuing
        .union(&other)
        .filter(|v| !found.contains(*v))
        .collect();
    assert!(
        stale.is_empty(),
        "CLI rows with no matching subcommand: {stale:?}"
    );
}

/// The registry covers each kind of entry point that task 3.1 names, so a
/// table that lost its rows cannot pass the guard by being empty.
#[test]
fn the_registry_covers_every_family() {
    for issues in [Session, Token, Code, DeviceApproval, Credential] {
        assert!(
            ENTRY_POINTS.iter().any(|e| e.issues == issues),
            "no entry point issues {issues:?}"
        );
    }
    assert!(ENTRY_POINTS.iter().any(|e| e.build == DevEndpoints));
    assert!(ENTRY_POINTS.iter().any(|e| e.build == Always));
    assert!(CLI_ENTRY_POINTS
        .iter()
        .all(|c| c.issues == Token && !c.command.is_empty()));
}

// ─── Invariants (task 3.3) ──────────────────────────────────────────────────
//
// Six invariants, each a table-driven test over every case: an entry point
// (and, for the token endpoint, each grant; for an entry point that accepts an
// `organization`, the org-context variant too). For each case where the
// invariant applies, a fresh fixture runs the case's driver with the
// violation applied just before the request to the entry point, and the entry
// point must not issue. `every_case_issues_without_a_violation` runs each case
// once with no violation and proves that the same request issues, so a
// refusal under a violation is the violation's effect, not a broken driver.

/// A property that every entry point must enforce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Invariant {
    /// A suspended realm issues nothing.
    RealmStatus,
    /// A suspended organization issues nothing in its context.
    OrgStatus,
    /// A disabled or locked user gets nothing.
    UserStatus,
    /// An archived client gets nothing.
    ClientStatus,
    /// A realm that requires MFA issues nothing without a second factor.
    MfaPolicy,
    /// A fail-closed pre-token webhook that fails stops the token.
    PreTokenWebhook,
}

const INVARIANTS: [Invariant; 6] = [
    Invariant::RealmStatus,
    Invariant::OrgStatus,
    Invariant::UserStatus,
    Invariant::ClientStatus,
    Invariant::MfaPolicy,
    Invariant::PreTokenWebhook,
];

/// Whether an invariant applies to a case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    /// The case must refuse under the violation.
    Applies,
    /// The invariant has no meaning for the case, for the reason given.
    NotApplicable(&'static str),
    /// A known gap, open on the GitHub issue named: the case still issues
    /// under the violation. The test asserts that it does, so the fix must
    /// change the rule to `Applies` (or, after an owner decision, to
    /// `NotApplicable`) in the same PR.
    Tracked(&'static str),
    /// A known defect, open on the GitHub issue named, stops the entry point
    /// from issuing at all, so no invariant can be checked. The baseline test
    /// asserts that it still issues nothing, so the fix must remove the
    /// `BROKEN` row in the same PR.
    Broken(&'static str),
}

/// Entry points that issue agent tokens or credentials through the admin
/// API: an admin acts for an agent that the user owns.
const AGENT_TOKENS: &[&str] = &[
    "aat-issue",
    "aat-derive",
    "transaction-token",
    "agent-api-key",
];

/// Entry points that issue nothing even with no violation: `(entry, issue)`.
const BROKEN: &[(&str, &str)] = &[("passkey-login-admin", "#769")];

/// Entry points that create a browser session and act for no client.
const SESSION_ONLY: &[&str] = &[
    "password-login",
    "password-login-realm",
    "passkey-login",
    "passkey-login-realm",
    "magic-link",
    "magic-link-realm",
    "totp-step",
    "email-otp-step",
    "passkey-step",
    "mfa-enroll-required",
    "password-login-admin",
    "passkey-login-admin",
    "ra-verify-email-page",
    "ra-verify-email-confirm",
    "ra-update-password",
    "ra-email-otp-page",
    "ra-email-otp-verify",
    "ra-enroll-mfa-page",
    "ra-enroll-mfa",
    "ra-enroll-passkey",
    "social-callback",
    "social-callback-post",
    "social-callback-realm",
    "social-callback-realm-post",
    "social-confirm-link",
    "social-confirm-link-realm",
    "saml-acs",
];

/// Second-factor steps: they are the MFA, so the MFA policy cannot apply.
const SECOND_FACTOR_STEPS: &[&str] = &[
    "totp-step",
    "email-otp-step",
    "passkey-step",
    "mfa-enroll-required",
];

/// Required actions that enrol the second factor: they are the MFA.
const FACTOR_ENROLMENTS: &[&str] = &["ra-email-otp-verify", "ra-enroll-mfa", "ra-enroll-passkey"];

/// Required actions that the login reaches only after it proved a second
/// factor (the page completes the action because the factor is held).
const AFTER_FACTOR: &[&str] = &["ra-email-otp-page", "ra-enroll-mfa-page"];

/// Operator console entry points, in the system realm.
const OPERATOR: &[&str] = &[
    "password-login-admin",
    "passkey-login-admin",
    "admin-api-token",
];

/// Entry points that check the password, where a locked login applies.
const PASSWORD_CHECKS: &[&str] = &[
    "password-login",
    "password-login-realm",
    "password-login-admin",
    "ra-update-password",
    "admin-api-token",
    "social-confirm-link",
    "social-confirm-link-realm",
];

/// Entry points that accept an `organization`. The JSON `POST /authorize`
/// has no `organization` field, so it issues in realm context only.
const ORG_CAPABLE: &[&str] = &["authorize-browser", "authorize-browser-realm", "consent"];

/// Grants with no user: the client acts for itself.
const MACHINE_GRANTS: &[&str] = &[
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
];

/// Known gaps: `(case, invariant, issue)`. A case is `entry` or
/// `entry[grant]`, as [`Case`] prints it.
const TRACKED: &[(&str, Invariant, &str)] = &[
    ("aat-issue", Invariant::UserStatus, "#770"),
    ("aat-derive", Invariant::UserStatus, "#770"),
    ("transaction-token", Invariant::UserStatus, "#770"),
    ("agent-api-key", Invariant::UserStatus, "#770"),
    (
        "token[client_credentials]",
        Invariant::PreTokenWebhook,
        "#766",
    ),
    (
        "token-realm[client_credentials]",
        Invariant::PreTokenWebhook,
        "#766",
    ),
    (
        "token[urn:ietf:params:oauth:grant-type:jwt-bearer]",
        Invariant::PreTokenWebhook,
        "#766",
    ),
    (
        "token-realm[urn:ietf:params:oauth:grant-type:jwt-bearer]",
        Invariant::PreTokenWebhook,
        "#766",
    ),
    ("token[authorization_code]", Invariant::MfaPolicy, "#767"),
    (
        "token[authorization_code, org]",
        Invariant::MfaPolicy,
        "#767",
    ),
    ("token[refresh_token]", Invariant::MfaPolicy, "#767"),
    ("token[refresh_token, org]", Invariant::MfaPolicy, "#767"),
    (
        "token[urn:ietf:params:oauth:grant-type:device_code]",
        Invariant::MfaPolicy,
        "#767",
    ),
    (
        "token[urn:ietf:params:oauth:grant-type:token-exchange]",
        Invariant::MfaPolicy,
        "#767",
    ),
    (
        "token-realm[authorization_code]",
        Invariant::MfaPolicy,
        "#767",
    ),
    (
        "token-realm[authorization_code, org]",
        Invariant::MfaPolicy,
        "#767",
    ),
    ("token-realm[refresh_token]", Invariant::MfaPolicy, "#767"),
    (
        "token-realm[refresh_token, org]",
        Invariant::MfaPolicy,
        "#767",
    ),
    (
        "token-realm[urn:ietf:params:oauth:grant-type:device_code]",
        Invariant::MfaPolicy,
        "#767",
    ),
    (
        "token-realm[urn:ietf:params:oauth:grant-type:token-exchange]",
        Invariant::MfaPolicy,
        "#767",
    ),
];

const NO_ORG: &str = "issues in realm context: no organization is named";
const NO_CLIENT: &str = "acts for no OAuth client";
const NO_USER: &str = "a machine grant: the client acts for itself, with no user";
const IS_FACTOR: &str = "the entry point is the second factor";
const PASSKEY_UV: &str = "a user-verified passkey is a multi-factor proof by itself";
const NO_ACCESS_TOKEN: &str =
    "issues no access token; the webhook runs before an access token is issued";
const DEV_ONLY: &str = "dev-endpoints builds only; never in a release build";
const SYSTEM_REALM: &str = "the system realm cannot be suspended";
const ENROLS_FACTOR: &str = "the entry point enrols the second factor";
const FACTOR_PROVED: &str = "the login proved a second factor before this entry point";
const NO_SIGN_IN: &str = "an admin API call for an agent: no user signs in";
const STEP_UP: &str = "the form asks for the password and the second factor itself";

/// Every case: each entry point, each token grant, each org variant.
fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for ep in ENTRY_POINTS {
        let case = |variant| Case {
            entry: ep.id,
            variant,
        };
        if matches!(ep.id, "token" | "token-realm") {
            out.extend(GRANTS.iter().map(|g| case(Variant::Grant(g))));
            out.extend(ORG_GRANTS.iter().map(|g| case(Variant::OrgGrant(g))));
        } else {
            out.push(case(Variant::Plain));
            if ORG_CAPABLE.contains(&ep.id) {
                out.push(case(Variant::Org));
            }
        }
    }
    out
}

fn entry(id: &str) -> &'static EntryPoint {
    ENTRY_POINTS
        .iter()
        .find(|e| e.id == id)
        .unwrap_or_else(|| panic!("no entry point {id}"))
}

/// Whether `inv` applies to `case`.
fn rule(case: Case, inv: Invariant) -> Rule {
    match base_rule(case, inv) {
        Rule::Applies => {
            let name = case.to_string();
            TRACKED
                .iter()
                .find(|(c, i, _)| *c == name && *i == inv)
                .map_or(Rule::Applies, |(_, _, issue)| Rule::Tracked(issue))
        }
        other => other,
    }
}

/// [`rule`] before the known gaps.
fn base_rule(case: Case, inv: Invariant) -> Rule {
    use Rule::{Applies, NotApplicable as Na};
    let e = case.entry;
    if entry(e).build == DevEndpoints {
        return Na(DEV_ONLY);
    }
    if let Some((_, issue)) = BROKEN.iter().find(|(b, _)| *b == e) {
        return Rule::Broken(issue);
    }
    let grant = case.grant();
    let machine = grant.is_some_and(|g| MACHINE_GRANTS.contains(&g));
    match inv {
        Invariant::RealmStatus if OPERATOR.contains(&e) => Na(SYSTEM_REALM),
        Invariant::RealmStatus => Applies,
        Invariant::OrgStatus if case.org() => Applies,
        Invariant::OrgStatus => Na(NO_ORG),
        Invariant::UserStatus if machine => Na(NO_USER),
        Invariant::UserStatus => Applies,
        Invariant::ClientStatus
            if SESSION_ONLY.contains(&e)
                || e == "admin-api-token"
                || AGENT_TOKENS.contains(&e)
                || grant == Some("urn:hearth:grant-type:magic-link") =>
        {
            Na(NO_CLIENT)
        }
        Invariant::ClientStatus => Applies,
        Invariant::MfaPolicy if SECOND_FACTOR_STEPS.contains(&e) => Na(IS_FACTOR),
        Invariant::MfaPolicy if FACTOR_ENROLMENTS.contains(&e) => Na(ENROLS_FACTOR),
        Invariant::MfaPolicy if AFTER_FACTOR.contains(&e) => Na(FACTOR_PROVED),
        Invariant::MfaPolicy if e == "admin-api-token" => Na(STEP_UP),
        Invariant::MfaPolicy if AGENT_TOKENS.contains(&e) => Na(NO_SIGN_IN),
        Invariant::MfaPolicy if e.starts_with("passkey-login") => Na(PASSKEY_UV),
        Invariant::MfaPolicy if machine => Na(NO_USER),
        Invariant::MfaPolicy => Applies,
        Invariant::PreTokenWebhook if grant.is_some() => Applies,
        Invariant::PreTokenWebhook => Na(NO_ACCESS_TOKEN),
    }
}

/// The violations that break `inv` for `case`.
fn violations(inv: Invariant, case: Case) -> Vec<Violation> {
    match inv {
        Invariant::RealmStatus => vec![Violation::RealmSuspended],
        Invariant::OrgStatus => vec![Violation::OrgSuspended],
        Invariant::UserStatus if PASSWORD_CHECKS.contains(&case.entry) => {
            vec![Violation::UserDisabled, Violation::UserLocked]
        }
        Invariant::UserStatus => vec![Violation::UserDisabled],
        Invariant::ClientStatus => vec![Violation::ClientArchived],
        Invariant::MfaPolicy => vec![Violation::MfaRequired],
        Invariant::PreTokenWebhook => vec![Violation::WebhookDenies],
    }
}

/// Runs every case where `inv` applies, under each of its violations, and
/// fails with the list of cases that still issued.
async fn check(inv: Invariant) {
    let mut ran = 0;
    let mut failures = Vec::new();
    for case in cases() {
        let tracked = match rule(case, inv) {
            Rule::Applies => None,
            Rule::Tracked(issue) => Some(issue),
            Rule::NotApplicable(_) | Rule::Broken(_) => continue,
        };
        for v in violations(inv, case) {
            ran += 1;
            let fx = fixture::fixture().await;
            let issued = drivers::run(&fx, case, Some(v)).await;
            match (issued, tracked) {
                (true, None) => failures.push(format!("  {case}: issued under {v:?}")),
                (false, Some(issue)) => failures.push(format!(
                    "  {case}: refuses under {v:?} now; {issue} is fixed, so change its \
                     TRACKED row to a rule"
                )),
                _ => {}
            }
        }
    }
    assert!(ran > 0, "{inv:?} applies to no case");
    assert!(
        failures.is_empty(),
        "{inv:?}: entry points that break the invariant:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
async fn every_case_issues_without_a_violation() {
    let mut refused = Vec::new();
    for case in cases() {
        if let Some(Rule::Broken(issue)) = INVARIANTS
            .iter()
            .map(|i| rule(case, *i))
            .find(|r| matches!(r, Rule::Broken(_)))
        {
            let fx = fixture::fixture().await;
            if drivers::run(&fx, case, None).await {
                refused.push(format!(
                    "  {case}: issues now; {issue} is fixed, so remove its BROKEN row"
                ));
            }
            continue;
        }
        if !INVARIANTS
            .iter()
            .any(|i| matches!(rule(case, *i), Rule::Applies | Rule::Tracked(_)))
        {
            continue;
        }
        let fx = fixture::fixture().await;
        if !drivers::run(&fx, case, None).await {
            refused.push(format!("  {case}"));
        }
    }
    assert!(
        refused.is_empty(),
        "cases that issue nothing with no violation (a broken driver), or BROKEN rows that \
         issue:\n{}",
        refused.join("\n")
    );
}

#[tokio::test]
async fn a_suspended_realm_issues_nothing() {
    check(Invariant::RealmStatus).await;
}

#[tokio::test]
async fn a_suspended_organization_issues_nothing_in_its_context() {
    check(Invariant::OrgStatus).await;
}

#[tokio::test]
async fn a_disabled_or_locked_user_gets_nothing() {
    check(Invariant::UserStatus).await;
}

#[tokio::test]
async fn an_archived_client_gets_nothing() {
    check(Invariant::ClientStatus).await;
}

#[tokio::test]
async fn required_mfa_is_never_skipped() {
    check(Invariant::MfaPolicy).await;
}

#[tokio::test]
async fn a_failing_fail_closed_webhook_stops_the_token() {
    check(Invariant::PreTokenWebhook).await;
}

/// Each invariant names, for each case, whether it applies and why not. A
/// case with a rule of `NotApplicable` for every invariant would be an
/// entry point that nothing checks.
#[test]
fn every_case_has_an_applicable_invariant() {
    let unchecked: Vec<String> = cases()
        .into_iter()
        .filter(|c| entry(c.entry).build == Always)
        .filter(|c| {
            INVARIANTS
                .iter()
                .all(|i| matches!(rule(*c, *i), Rule::NotApplicable(_)))
        })
        .map(|c| c.to_string())
        .collect();
    assert!(
        unchecked.is_empty(),
        "cases that no invariant checks: {unchecked:?}"
    );
}

/// Every `TRACKED` row names a case and an invariant that applies to it, so
/// a typo cannot hide a gap.
#[test]
fn every_tracked_row_names_a_case() {
    for (e, _) in BROKEN {
        entry(e);
    }
    let names: BTreeSet<String> = cases().iter().map(ToString::to_string).collect();
    for (case, inv, issue) in TRACKED {
        assert!(names.contains(*case), "TRACKED names no case: {case}");
        let c = cases()
            .into_iter()
            .find(|c| c.to_string() == *case)
            .expect("case");
        assert_eq!(
            base_rule(c, *inv),
            Rule::Applies,
            "TRACKED row {case} {inv:?} ({issue}) is for an invariant that does not apply"
        );
    }
}
