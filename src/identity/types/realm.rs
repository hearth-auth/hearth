//! Realm types.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::core::{RealmId, Timestamp};
use crate::identity::claims_config::ClaimProfile;
use crate::identity::email::stored_templates::LocalizedEmailTemplate;
use crate::identity::email::EmailBranding;
use crate::identity::federation::LinkMode;
use crate::identity::risk::RiskScorerConfig;
use crate::rbac::{Group, PermissionDefinition, ProtectedResource, Role, ScopeBundle};

use super::user::RequiredAction;

/// The lifecycle status of a realm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RealmStatus {
    /// Realm is active; all operations proceed normally.
    Active,
    /// Realm is suspended; authentication and authorization are denied.
    Suspended,
    /// Realm was removed from YAML config and soft-deleted.
    ///
    /// Behaves like `Suspended` (auth denied) but additionally signals
    /// that the realm can be permanently deleted from the admin UI.
    Archived,
    /// Background cascade deletion is running. Auth is denied; the realm
    /// will be fully removed once the cascade completes.
    DeletingInProgress,
}

/// Controls who may self-register in a realm.
///
/// When `None` is stored on `RealmConfig.registration_policy`, the engine
/// treats it as `Disabled` — a safe default so existing deployments don't
/// silently open registration after upgrade.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode", content = "value")]
pub enum RegistrationPolicy {
    /// Public signup is disabled. Only admin-created users exist.
    #[default]
    Disabled,
    /// Anyone with a valid email may register.
    Open,
    /// Only emails whose domain appears in the list may register.
    DomainRestricted(Vec<String>),
    /// Users must present a valid organization invitation token.
    InviteOnly,
}

/// Controls whether Dynamic Client Registration (RFC 7591) is enabled for a realm.
///
/// When `None` is stored on `RealmConfig.dcr_policy`, the engine treats it as
/// `Disabled` — a safe default so existing deployments don't silently open
/// DCR after upgrade.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DcrPolicy {
    /// Dynamic client registration is disabled. Only admins may create clients.
    #[default]
    Disabled,
    /// Any caller may register an OAuth client via `POST /register`.
    ///
    /// # Security Warning
    /// Unauthenticated — production deployments should prefer `Authenticated`.
    Open,
    /// Requires a valid realm bearer token (RFC 7591 §3.1 initial access token).
    /// The caller must present `Authorization: Bearer <token>` with a token
    /// issued by this realm.
    Authenticated,
}

/// Password complexity policy stored in a realm's configuration.
///
/// These are *declarations* — enforcement is a separate concern in the identity
/// engine. When all fields are `None`, no additional complexity requirements
/// are imposed beyond the default minimum.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// Minimum password length. Must be >= 1 when set.
    pub min_length: Option<usize>,
    /// Require at least one uppercase letter.
    pub require_uppercase: Option<bool>,
    /// Require at least one digit.
    pub require_number: Option<bool>,
    /// Require at least one special character.
    pub require_special: Option<bool>,
    /// Password must not be equal to or contain the user's username/display name.
    pub not_username: Option<bool>,
    /// Password must not be equal to or contain the user's email address (local part).
    pub not_email: Option<bool>,
    /// Number of previous passwords to retain and reject on reuse. 0 or `None` disables.
    pub history_depth: Option<usize>,
    /// Maximum password age in days before the user must rotate. `None` disables expiry.
    pub max_age_days: Option<u32>,
}

/// Data type hint for a custom attribute value.
///
/// Values are always stored as UTF-8 strings. The type drives admin UI
/// rendering and lightweight format validation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributeType {
    /// Plain text (default).
    #[default]
    String,
    /// Numeric string; the admin UI renders a number input.
    Number,
    /// `"true"` or `"false"`; the admin UI renders a checkbox.
    Boolean,
    /// One of a fixed set of values; the admin UI renders a `<select>`.
    Enum,
}

/// A single runtime attribute definition derived from YAML config.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeDefinition {
    /// Machine-readable key used as the storage key in the attribute map.
    pub key: String,
    /// Human-readable label shown in the admin UI. Defaults to `key` when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Data type hint for the admin UI and basic format validation.
    #[serde(default)]
    pub type_: AttributeType,
    /// When `true`, the attribute must be present on record creation.
    #[serde(default)]
    pub required: bool,
    /// Short description shown as a placeholder or tooltip in the admin UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Allowed values when `type_: Enum`. Ignored for other types.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<String>,
}

impl AttributeDefinition {
    /// Returns the display label, falling back to `key` when no label is set.
    pub fn display_label(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.key)
    }

    /// Returns `true` when this attribute is a boolean type.
    pub fn is_boolean(&self) -> bool {
        matches!(self.type_, AttributeType::Boolean)
    }

    /// Returns `true` when this attribute is an enum type.
    pub fn is_enum(&self) -> bool {
        matches!(self.type_, AttributeType::Enum)
    }

    /// Returns `true` when this attribute is a number type.
    pub fn is_number(&self) -> bool {
        matches!(self.type_, AttributeType::Number)
    }

    /// Looks up the current value for this attribute key in a flat `(key, value)` slice.
    ///
    /// Returns the first matching value, or `""` if not found. Used by templates
    /// to avoid closure syntax that Askama's expression parser cannot handle.
    pub fn find_value<'a>(&self, attrs: &'a [(String, String)]) -> &'a str {
        attrs
            .iter()
            .find(|(k, _)| k == &self.key)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }

    /// Returns the description as a `&str` option, avoiding reference syntax in templates.
    pub fn description_str(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// Runtime attribute definitions scoped per entity type.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeDefinitions {
    /// Definitions that apply to user records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<AttributeDefinition>,
    /// Definitions that apply to organization records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub organizations: Vec<AttributeDefinition>,
}

/// Per-realm configuration overrides.
///
/// Fields are optional — when `None`, the engine-level default is used.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RealmConfig {
    /// Session time-to-live in microseconds. Overrides engine default.
    pub session_ttl_micros: Option<i64>,
    /// Argon2id memory cost in KiB. Overrides engine default.
    pub password_memory_cost: Option<u32>,
    /// Argon2id time cost (iterations). Overrides engine default.
    pub password_time_cost: Option<u32>,
    /// Per-realm email branding overrides.
    pub email_branding: Option<EmailBranding>,
    /// Per-realm logo URL override. When set, overrides the global
    /// `branding.logo_url` in outbound emails for this realm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    /// Per-realm primary/accent color (hex, e.g. `"#E85D04"`).
    /// Overrides `EmailBranding.accent_color` when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    /// Per-realm email template overrides keyed by template kind
    /// (`"verification"`, `"password_reset"`, `"welcome"`, `"invitation"`).
    /// Each value holds a default body plus optional locale variants.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub email_templates: std::collections::HashMap<String, LocalizedEmailTemplate>,
    /// Composed CSS block (named theme + optional custom file contents) served
    /// as the realm-specific theme stylesheet. `None` means no per-realm
    /// theme is configured — the global theme applies.
    pub web_theme_css: Option<String>,
    /// Source theme name (e.g. `"ember"`, `"ocean"`, `"midnight"`,
    /// `"forest"`, `"cloud"`, `"parchment"`) when the realm overrides
    /// `branding.theme` via `realms.<id>.web.theme` in `hearth.yaml`.
    /// Surfaced read-only on the realm detail page so operators can see
    /// which named theme drives this realm without inspecting the CSS.
    /// `None` means the global theme applies.
    pub web_theme_name: Option<String>,
    /// Whether MFA is required for all users in this realm.
    pub mfa_required: Option<bool>,
    /// Role names (slugs) whose holders must have MFA enrolled.
    ///
    /// When set, any user assigned one of these roles is intercepted by the
    /// `EnrollMfa` required-action gate if they have no MFA factor enrolled.
    /// This is orthogonal to `mfa_required` (which applies to all users).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa_required_roles: Option<Vec<String>>,
    /// Allowed MFA methods (e.g. `["totp", "webauthn", "sms"]`).
    pub mfa_methods: Option<Vec<String>>,
    /// Per-realm SMS OTP expiry in seconds. `None` falls back to the module default (600 s / 10 min).
    pub sms_otp_expiry_seconds: Option<u64>,
    /// Per-realm SMS OTP maximum verification attempts before the record is discarded.
    /// `None` falls back to the module default (5).
    pub sms_otp_max_attempts: Option<u32>,
    /// Per-realm Email OTP expiry in seconds. `None` falls back to the module default (600 s / 10 min).
    pub email_otp_expiry_seconds: Option<u64>,
    /// Per-realm Email OTP maximum verification attempts before the record is discarded.
    /// `None` falls back to the module default (5).
    pub email_otp_max_attempts: Option<u32>,
    /// Allowed authentication methods (e.g. `["password", "magic_link", "passkey"]`).
    pub allowed_auth_methods: Option<Vec<String>>,
    /// Password complexity policy.
    pub password_policy: Option<PasswordPolicy>,
    /// Per-realm access token TTL in microseconds.
    pub access_token_ttl_micros: Option<i64>,
    /// Per-realm refresh token TTL in microseconds.
    pub refresh_token_ttl_micros: Option<i64>,
    /// Per-realm password reset token TTL in microseconds.
    /// `None` falls back to the compiled default (30 minutes).
    pub password_reset_token_ttl_micros: Option<i64>,
    /// Maximum failed login attempts before lockout.
    pub max_failed_logins: Option<u32>,
    /// Lockout duration in microseconds after max failed logins.
    pub lockout_duration_micros: Option<i64>,
    /// Whether passkey login still requires a TOTP challenge.
    /// When `Some(true)`, passkey auth is treated like password auth
    /// with respect to MFA gating.
    pub passkey_requires_mfa: Option<bool>,
    /// Whether passkeys are required for all users in this realm.
    /// When `Some(true)`, users must register a passkey; password-only
    /// login is rejected at the MFA gate.
    pub webauthn_required: Option<bool>,
    /// `residentKey` preference sent in `authenticatorSelection` during
    /// registration. Values: `"required"`, `"preferred"`, `"discouraged"`.
    /// `None` inherits the engine default (`"preferred"`).
    pub webauthn_resident_key: Option<String>,
    /// `userVerification` preference sent during registration and
    /// authentication ceremonies. Values: `"required"`, `"preferred"`,
    /// `"discouraged"`. `None` inherits the engine default (`"preferred"`).
    pub webauthn_user_verification: Option<String>,
    /// Who may self-register in this realm. `None` means `Disabled`.
    pub registration_policy: Option<RegistrationPolicy>,
    /// Whether dynamic client registration (RFC 7591) is enabled. `None` means `Disabled`.
    pub dcr_policy: Option<DcrPolicy>,
    /// How external-IdP logins interact with an existing local user
    /// when the upstream asserts a matching verified email. `None`
    /// means [`LinkMode::Confirm`] — the Keycloak-equivalent safety
    /// default that requires local re-authentication before linking.
    pub federation_link_mode: Option<LinkMode>,
    /// YAML-authored permission registry for this realm.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<PermissionDefinition>,
    /// YAML-authored RBAC roles for this realm.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<Role>,
    /// YAML-authored roles visible in the admin/authz surfaces.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<ScopeBundle>,
    /// YAML-authored protected resources and their local scope namespaces.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_resources: Vec<ProtectedResource>,
    /// YAML-declared groups for this realm.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<Group>,
    /// YAML-authored claim profile overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_profile: Option<ClaimProfile>,
    /// SHA-256 hash of the realm-scoped SCIM bearer token.
    ///
    /// The plaintext token is intended to remain in configuration input
    /// only; persisted realm records store just the hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scim_bearer_token_hash: Option<String>,
    /// Custom attribute definitions for users and organizations in this realm.
    ///
    /// `None` means free-form mode (any key accepted). When set, only declared
    /// keys are accepted; unknown keys are rejected with `InvalidAttribute`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute_definitions: Option<AttributeDefinitions>,
    /// Actions automatically assigned to every new user created in this realm.
    ///
    /// Defaults to `[]` (no required actions). Existing realms without this
    /// field deserialize to `[]` via serde default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_required_actions: Vec<RequiredAction>,
    /// HIBP k-anonymity breach-check configuration.
    ///
    /// Existing realms deserialised without this field get the safe migration
    /// default (`enabled = false`). Newly provisioned realms should set
    /// `enabled = true` explicitly in their configuration.
    #[serde(default)]
    pub breach_check: BreachCheckConfig,
    /// Adaptive (risk-based) MFA configuration.
    ///
    /// Existing realms deserialised without this field get the safe migration
    /// default (`enabled = false`). Set `enabled = true` and supply a
    /// `fingerprint_hmac_secret` to activate device-recognition step-up.
    #[serde(default)]
    pub adaptive_mfa: AdaptiveMfaConfig,
    /// Session-version (`sv`) revocation tracking.
    ///
    /// When enabled, access tokens carry an `sv` claim that resource servers
    /// check against a locally-cached minimum version polled from the delta
    /// feed. Defaults to disabled for backward compatibility.
    #[serde(default)]
    pub session_version: SessionVersionConfig,
    /// Maximum number of concurrent active (non-revoked, non-expired) sessions
    /// per user in this realm. `None` means unlimited (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_sessions: Option<u32>,
    /// What to do when a new session would exceed `max_concurrent_sessions`.
    /// Defaults to `RejectNew`. Set to `EvictOldest` to opt in to eviction.
    #[serde(default)]
    pub session_over_limit_policy: SessionLimitPolicy,
    /// FAPI 2.0 Security Profile enforcement level for this realm.
    ///
    /// When set, the authorization server enforces the corresponding FAPI profile
    /// on all authorization requests in this realm:
    ///
    /// - `baseline` — requires PAR + PKCE (S256) on every request.
    /// - `advanced` — additionally requires JAR, JARM, and `private_key_jwt`.
    ///
    /// `None` (default) means standard OAuth 2.0 / OIDC rules apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fapi_profile: Option<FapiProfile>,
    /// Idle session timeout in seconds (A-18).
    ///
    /// A session whose `last_refreshed_at` is older than this window is evicted
    /// on next access and by the background session reaper. `None` = no idle
    /// timeout (fail-open; standard TTL governs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u32>,
    /// Absolute session lifetime cap in seconds (A-18).
    ///
    /// A session older than this is evicted regardless of recent activity.
    /// `None` = no hard cap (fail-open; standard TTL governs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absolute_timeout_secs: Option<u32>,
    /// Per-realm risk scorer configuration (A-11 / A-49).
    ///
    /// `None` → scorer disabled (fail-open per §6.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_scorer_config: Option<RiskScorerConfig>,
    /// Per-realm resource quota limits (A-24).
    ///
    /// `None` means no quotas (unlimited). When set, create operations for the
    /// covered resource types are rejected with [`crate::identity::IdentityError::QuotaExceeded`]
    /// when the current count equals or exceeds the configured limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quotas: Option<RealmQuotaConfig>,
    /// Per-realm magic link token TTL in microseconds (A-14).
    ///
    /// `None` falls back to the compiled default (15 minutes). Hard-capped at
    /// 30 minutes unless `allow_unsafe_ttl` is also set in the realm's YAML.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_link_ttl_micros: Option<i64>,
    /// Per-realm device authorization code TTL in seconds (HSEC-008).
    ///
    /// `None` falls back to the compiled default (600 seconds / 10 minutes).
    /// Hard-capped at 1800 seconds unless `allow_unsafe_ttl` is set in YAML.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_code_ttl_secs: Option<i64>,
    /// WebAuthn attestation policy for this realm (A-13).
    ///
    /// `None` means no policy — attestation format and AAGUID are unrestricted
    /// (fail-open per §6.1 of the abuse plan).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn_attestation: Option<WebAuthnAttestationPolicy>,
    /// Tool-group membership map (Phase C — `toolgroup.*` permission expansion).
    ///
    /// Maps group name → list of tool names that belong to the group. Used by
    /// `evaluate_tool_access` to resolve `toolgroup.{name}.{action}` permissions.
    /// Empty by default (no groups defined). Set via `tool_registry.groups` in
    /// `hearth.yaml`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub tool_groups: HashMap<String, Vec<String>>,
    /// Pre-token enrichment webhook (HEA-1324, Gap C-3).
    ///
    /// When set, Hearth POSTs a JSON context payload to the configured URL
    /// immediately before issuing an access token. The endpoint may return
    /// `extra_claims` that are merged into the token's top-level claims.
    /// Reserved JWT claims (`sub`, `iss`, `exp`, etc.) cannot be overridden.
    ///
    /// `None` (default) disables the webhook for this realm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_token_webhook: Option<PreTokenWebhookConfig>,
    /// Per-realm approval webhook configuration (Phase C.5).
    ///
    /// When set, Hearth sends a durable at-least-once HTTP POST to the
    /// configured URL whenever an approval request is created. The payload
    /// carries the request ID, agent identity, tool, delegation chain, and
    /// approve/deny URLs.
    ///
    /// `None` (default) disables approval webhook notifications for this realm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_webhook: Option<ApprovalWebhookConfig>,
}

/// How to handle a pre-token webhook call failure.
///
/// Governs whether a webhook transport error (network failure, timeout,
/// non-2xx response) blocks token issuance or is tolerated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PreTokenWebhookErrorPolicy {
    /// Token is issued without extra claims; a warning is logged and a
    /// `PreTokenWebhookFailed` audit event is emitted. This is the safe
    /// default — Auth availability takes precedence over enrichment.
    #[default]
    FailOpen,
    /// Token issuance is rejected with `IdentityError::PreTokenWebhookFailed`.
    /// Use when the enrichment data is required for authorization decisions
    /// downstream and issuing a token without it would be a security risk.
    FailClosed,
}

/// Per-realm pre-token enrichment webhook configuration (HEA-1324, Gap C-3).
///
/// When configured, Hearth POSTs a JSON context payload to `url` immediately
/// before issuing an access token. The response may include `extra_claims`
/// that are merged into the token.
///
/// See `docs/specs/CONFIGURATION.md §realms.<name>.pre_token_webhook` for
/// the full YAML reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreTokenWebhookConfig {
    /// The HTTPS endpoint to POST to.
    pub url: String,
    /// Request timeout in milliseconds. Defaults to `1000`.
    #[serde(default = "default_webhook_timeout_ms")]
    pub timeout_ms: u64,
    /// What to do when the webhook call fails. Defaults to `fail_open`.
    #[serde(default)]
    pub on_error: PreTokenWebhookErrorPolicy,
    /// HMAC-SHA256 signing secret.
    ///
    /// **Required.** When set, the request body is signed and the signature
    /// is sent in `X-Hearth-Signature-256: sha256=<hex>` so the endpoint
    /// can verify authenticity. Omitting this field is rejected at realm
    /// update/create time — an unauthenticated webhook endpoint is a direct
    /// claim-injection path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<String>,
}

impl PreTokenWebhookConfig {
    /// Validates the webhook configuration.
    ///
    /// Returns `Err` with a human-readable reason when the configuration is
    /// insecure. Enforces:
    /// - `url` MUST use the `https://` scheme (M7 SSRF guard — scheme check at
    ///   registration time; DNS-based check runs pre-flight on each delivery).
    /// - `hmac_secret` MUST be set: an unsigned webhook endpoint allows any
    ///   network-reachable caller to inject arbitrary JWT claims.
    pub fn validate(&self) -> Result<(), String> {
        if !self.url.starts_with("https://") {
            return Err("pre_token_webhook.url must use the https:// scheme".to_string());
        }
        if self.hmac_secret.as_deref().map_or(true, str::is_empty) {
            return Err(
                "pre_token_webhook.hmac_secret is required: an unsigned webhook endpoint \
                 allows any caller reachable from the webhook URL to inject arbitrary JWT \
                 claims into issued tokens"
                    .to_string(),
            );
        }
        Ok(())
    }
}

fn default_webhook_timeout_ms() -> u64 {
    1000
}

/// Per-realm approval webhook configuration (Phase C.5).
///
/// When configured, Hearth delivers a durable at-least-once HTTP POST to
/// `url` whenever an approval request is created. The payload is
/// HMAC-SHA256 signed when `secret` is set, following the same convention
/// as `pre_token_webhook` and the general webhook engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalWebhookConfig {
    /// HTTPS endpoint to POST the approval notification payload to.
    pub url: String,
    /// HMAC-SHA256 signing secret.
    ///
    /// When set, the body is signed and `X-Hearth-Signature-256: sha256=<hex>`
    /// is added so the receiver can verify authenticity.
    /// `None` skips signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Request timeout in milliseconds. Defaults to 5 000.
    #[serde(default = "default_approval_webhook_timeout_ms")]
    pub timeout_ms: u64,
}

impl ApprovalWebhookConfig {
    /// Validates the approval webhook configuration.
    ///
    /// Enforces that `url` uses the `https://` scheme. The full SSRF DNS-based
    /// check runs pre-flight on each delivery attempt in the production transport.
    pub fn validate(&self) -> Result<(), String> {
        if !self.url.starts_with("https://") {
            return Err("approval_webhook.url must use the https:// scheme".to_string());
        }
        Ok(())
    }
}

fn default_approval_webhook_timeout_ms() -> u64 {
    5_000
}

/// Per-realm WebAuthn attestation policy (A-13).
///
/// Controls which authenticators are permitted to register credentials in this
/// realm. All fields fail-open by default (absent policy = any authenticator).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WebAuthnAttestationPolicy {
    /// Whether attestation format `"none"` is accepted (default: `true`).
    pub allow_none: bool,
    /// AAGUID allowlist (lowercase UUID format). Empty = any AAGUID accepted.
    pub aaguid_allowlist: Vec<String>,
    /// Require PRF extension on registered credentials (default: `false`).
    pub require_prf: bool,
    /// Require `largeBlob` extension on registered credentials (default: `false`).
    pub require_large_blob: bool,
}

impl Default for WebAuthnAttestationPolicy {
    fn default() -> Self {
        Self {
            allow_none: true,
            aaguid_allowlist: Vec::new(),
            require_prf: false,
            require_large_blob: false,
        }
    }
}

/// FAPI 2.0 Security Profile enforcement level.
///
/// Activates when set on a `RealmConfig`. Controls which FAPI 2.0 constraints
/// the AS enforces for all authorization requests in the realm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum FapiProfile {
    /// FAPI 2.0 Baseline Security Profile.
    ///
    /// Requires: PAR (RFC 9126), PKCE with S256 (RFC 7636), `iss` in responses
    /// (RFC 9207). All authorization requests must be submitted as PAR.
    Baseline,
    /// FAPI 2.0 Advanced Security Profile.
    ///
    /// Requires all Baseline constraints plus: JAR (RFC 9101), JARM
    /// (OAuth 2.0 JARM), and `private_key_jwt` client authentication.
    Advanced,
}

/// Per-realm session-version (`sv`) tracking configuration.
///
/// Controls whether the `sv` claim is included in access tokens and whether
/// the delta-feed and snapshot endpoints are active for this realm.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionVersionConfig {
    /// Enable session-version claim emission and delta log.
    ///
    /// `false` (default) — no `sv` claim in tokens, no delta log written,
    /// feed endpoints return 404.
    #[serde(default)]
    pub enabled: bool,
    /// How long delta log entries are retained, in seconds.
    ///
    /// Resource servers that fall further behind must fetch the full snapshot
    /// to recover. Defaults to 3 600 s (1 hour).
    #[serde(default = "SessionVersionConfig::default_delta_retention_seconds")]
    pub delta_retention_seconds: u64,
}

impl SessionVersionConfig {
    fn default_delta_retention_seconds() -> u64 {
        3600
    }
}

impl Default for SessionVersionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            delta_retention_seconds: Self::default_delta_retention_seconds(),
        }
    }
}

/// What to do when a new `create_session` would push a user's live session
/// count past `RealmConfig::max_concurrent_sessions`.
///
/// The default is [`RejectNew`][SessionLimitPolicy::RejectNew]. Operators must
/// explicitly opt in to [`EvictOldest`][SessionLimitPolicy::EvictOldest] via
/// `session_over_limit_policy = "evict_oldest"` in realm config.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLimitPolicy {
    /// Reject the new session with [`crate::identity::IdentityError::SessionLimitExceeded`].
    ///
    /// This is the default. An attacker cannot silently evict a victim's
    /// sessions by flooding new-session requests — the victim's existing
    /// sessions remain intact and the attacker receives an error instead.
    #[default]
    RejectNew,
    /// Revoke the oldest active session(s) to make room, then proceed.
    ///
    /// Opt-in only. Enables a DoS vector where an attacker can evict a
    /// victim's sessions via repeated login. Only use when the application
    /// requires single-session semantics and the threat model accepts it.
    EvictOldest,
}

/// Per-realm resource quota configuration (A-24).
///
/// All limits are `None` by default (unlimited). When a limit is set, the
/// corresponding create operation is rejected with
/// [`crate::identity::IdentityError::QuotaExceeded`] once the current count
/// reaches the limit.  Enforcement is synchronous and fail-closed: if the
/// storage scan that determines the count fails, the create is rejected.
///
/// Disk-usage (`max_disk_bytes`) is checked asynchronously by the background
/// audit-pruner task (sampled). Enforcement is a warning log only; no create
/// is blocked. Pair it with `max_audit_rows` for a hard data-size backstop.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RealmQuotaConfig {
    /// Maximum number of users that may exist in this realm at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_users: Option<u64>,
    /// Maximum number of organizations that may exist in this realm at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_orgs: Option<u64>,
    /// Maximum number of OAuth/OIDC clients registered in this realm at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_clients: Option<u64>,
    /// Maximum number of agents registered in this realm at once.
    ///
    /// Checked synchronously on `create_agent`. When `None` (default), no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_agents: Option<u64>,
    /// Maximum total number of active sessions across all users in this realm.
    ///
    /// Checked synchronously on `create_session`. Because checking the total
    /// requires a full-prefix scan, set this only when the realm has a known
    /// bounded user population.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sessions: Option<u64>,
    /// Maximum number of audit log rows for this realm (A-24 hard backstop
    /// complement to A-25 `max_rows`). Enforced by the background pruner;
    /// see also [`crate::audit::types::AuditRetentionConfig::max_rows`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_audit_rows: Option<u64>,
    /// Disk-usage warning threshold in bytes for this realm's storage prefix.
    ///
    /// Checked by the background pruner task (sampled, once per day).
    /// Exceeding this limit emits a `warn!()` but does NOT block writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_disk_bytes: Option<u64>,
}

// ── SecretString serde helpers ────────────────────────────────────────────────
//
// Used by BreachCheckConfig and AdaptiveMfaConfig to safely round-trip secret
// fields through storage without relying on SecretString's missing Serialize impl.
mod secret_string_serde {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(secret.expose_secret())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::Deserialize;
        let val = String::deserialize(deserializer)?;
        Ok(SecretString::new(val))
    }
}

fn is_empty_secret(s: &SecretString) -> bool {
    s.expose_secret().is_empty()
}

fn default_secret_string() -> SecretString {
    SecretString::new(String::new())
}

/// Configuration for the HIBP Pwned Passwords k-anonymity breach-check.
///
/// Only the first 5 hex characters of the SHA-1 hash are sent to the HIBP
/// Range API — no plaintext password or full hash leaves the process.
#[derive(Clone, Serialize, Deserialize)]
pub struct BreachCheckConfig {
    /// When `true`, every password-set or password-change call queries the HIBP
    /// Range API before accepting the new credential.
    pub enabled: bool,
    /// Request timeout for the HIBP API in milliseconds.
    ///
    /// Defaults to 3000 ms. On timeout the call fails-open (password accepted,
    /// `BreachCheckUnavailable` audit event emitted).
    pub timeout_ms: u64,
    /// Optional HIBP API key. When non-empty, sent as the `hibp-api-key` header.
    /// Required for paid HIBP Enterprise plans.
    #[serde(
        default = "default_secret_string",
        skip_serializing_if = "is_empty_secret",
        serialize_with = "secret_string_serde::serialize",
        deserialize_with = "secret_string_serde::deserialize"
    )]
    pub hibp_api_key: SecretString,
}

impl fmt::Debug for BreachCheckConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BreachCheckConfig")
            .field("enabled", &self.enabled)
            .field("timeout_ms", &self.timeout_ms)
            .field("hibp_api_key", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for BreachCheckConfig {
    fn eq(&self, other: &Self) -> bool {
        self.enabled == other.enabled
            && self.timeout_ms == other.timeout_ms
            && self.hibp_api_key.expose_secret() == other.hibp_api_key.expose_secret()
    }
}

impl Default for BreachCheckConfig {
    fn default() -> Self {
        Self {
            // Safe migration default: disabled so existing realms are unaffected.
            enabled: false,
            timeout_ms: 3000,
            hibp_api_key: SecretString::new(String::new()),
        }
    }
}

/// Adaptive MFA configuration for a realm.
///
/// Controls device-fingerprint–based step-up MFA injection. When `enabled`,
/// every login from an unrecognised device triggers a step-up challenge or
/// an MFA-enrollment required-action. Only the HMAC output is stored —
/// never raw IP or User-Agent strings (AC-11 / GDPR).
#[derive(Clone, Serialize, Deserialize)]
pub struct AdaptiveMfaConfig {
    /// Whether adaptive MFA is active for this realm.
    ///
    /// Defaults to `false` for existing realms (safe migration default).
    /// New realms should set this to `true` explicitly.
    pub enabled: bool,
    /// Number of days a recognised device is trusted before requiring re-verification.
    pub recognition_window_days: u32,
    /// HMAC-SHA256 key used to derive device fingerprints.
    ///
    /// Should be at least 32 bytes of cryptographically-random data. When empty,
    /// the feature behaves as if `enabled = false` to prevent accidentally
    /// treating every device as unrecognised due to a trivially-guessable key.
    #[serde(
        default = "default_secret_string",
        skip_serializing_if = "is_empty_secret",
        serialize_with = "secret_string_serde::serialize",
        deserialize_with = "secret_string_serde::deserialize"
    )]
    pub fingerprint_hmac_secret: SecretString,
}

impl fmt::Debug for AdaptiveMfaConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdaptiveMfaConfig")
            .field("enabled", &self.enabled)
            .field("recognition_window_days", &self.recognition_window_days)
            .field("fingerprint_hmac_secret", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for AdaptiveMfaConfig {
    fn eq(&self, other: &Self) -> bool {
        self.enabled == other.enabled
            && self.recognition_window_days == other.recognition_window_days
            && self.fingerprint_hmac_secret.expose_secret()
                == other.fingerprint_hmac_secret.expose_secret()
    }
}

impl Default for AdaptiveMfaConfig {
    fn default() -> Self {
        Self {
            // Safe migration default: disabled so existing realms are unaffected.
            enabled: false,
            recognition_window_days: 30,
            fingerprint_hmac_secret: SecretString::new(String::new()),
        }
    }
}

/// A realm record.
///
/// Each realm is an isolated namespace for users, sessions, credentials,
/// tokens, and authorization tuples. Fields are private; access via
/// accessor methods.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Realm {
    id: RealmId,
    name: String,
    status: RealmStatus,
    config: RealmConfig,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl Realm {
    /// Creates a new realm. Used internally by the identity engine.
    pub(crate) fn new(
        id: RealmId,
        name: String,
        status: RealmStatus,
        config: RealmConfig,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            id,
            name,
            status,
            config,
            created_at,
            updated_at,
        }
    }

    /// Returns the realm's unique identifier.
    pub fn id(&self) -> &RealmId {
        &self.id
    }

    /// Returns the realm's display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the realm's lifecycle status.
    pub fn status(&self) -> RealmStatus {
        self.status
    }

    /// Returns the realm's configuration overrides.
    pub fn config(&self) -> &RealmConfig {
        &self.config
    }

    /// Returns when the realm was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when the realm was last updated (UTC microseconds).
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Updates the realm name. Used internally during updates.
    pub(crate) fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Updates the realm status. Used internally during updates.
    pub(crate) fn set_status(&mut self, status: RealmStatus) {
        self.status = status;
    }

    /// Updates the realm configuration. Used internally during updates.
    pub(crate) fn set_config(&mut self, config: RealmConfig) {
        self.config = config;
    }

    /// Updates the `updated_at` timestamp.
    pub(crate) fn set_updated_at(&mut self, ts: Timestamp) {
        self.updated_at = ts;
    }
}

/// Request to create a new realm.
#[derive(Clone, Debug)]
pub struct CreateRealmRequest {
    /// The realm's display name.
    pub name: String,
    /// Optional per-realm configuration. Defaults applied if omitted.
    pub config: Option<RealmConfig>,
}

/// Request to update an existing realm.
///
/// Only `Some` fields are applied; `None` fields are left unchanged.
#[derive(Clone, Debug, Default)]
pub struct UpdateRealmRequest {
    /// New display name.
    pub name: Option<String>,
    /// New realm status.
    pub status: Option<RealmStatus>,
    /// New configuration overrides.
    pub config: Option<RealmConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_token_webhook_config_validate_rejects_none_secret() {
        let cfg = PreTokenWebhookConfig {
            url: "http://localhost:9999/enrich".to_string(),
            timeout_ms: 1000,
            on_error: PreTokenWebhookErrorPolicy::FailOpen,
            hmac_secret: None,
        };
        let err = cfg.validate().expect_err("None secret must be rejected");
        assert!(
            err.contains("hmac_secret"),
            "error must mention hmac_secret, got: {err}"
        );
    }

    #[test]
    fn pre_token_webhook_config_validate_rejects_empty_secret() {
        let cfg = PreTokenWebhookConfig {
            url: "http://localhost:9999/enrich".to_string(),
            timeout_ms: 1000,
            on_error: PreTokenWebhookErrorPolicy::FailOpen,
            hmac_secret: Some(String::new()),
        };
        let err = cfg.validate().expect_err("empty secret must be rejected");
        assert!(
            err.contains("hmac_secret"),
            "error must mention hmac_secret, got: {err}"
        );
    }

    #[test]
    fn pre_token_webhook_config_validate_accepts_non_empty_secret() {
        let cfg = PreTokenWebhookConfig {
            url: "http://localhost:9999/enrich".to_string(),
            timeout_ms: 1000,
            on_error: PreTokenWebhookErrorPolicy::FailOpen,
            hmac_secret: Some("my-secret".to_string()),
        };
        cfg.validate().expect("non-empty secret must be accepted");
    }
}
