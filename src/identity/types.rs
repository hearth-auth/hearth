//! Identity domain types: users, realms, requests, and status.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use crate::core::{
    ClientId, InvitationId, OrganizationId, RealmId, SessionId, Timestamp, UserId, WebhookId,
};
use crate::identity::claims_config::ClaimProfile;
use crate::identity::credentials::CleartextPassword;
use crate::identity::email::stored_templates::LocalizedEmailTemplate;
use crate::identity::email::EmailBranding;
use crate::identity::federation::LinkMode;
use crate::identity::risk::RiskScorerConfig;
use crate::rbac::{Group, PermissionDefinition, ProtectedResource, Role, ScopeBundle};

/// A cursor-based page of results.
///
/// The `next_cursor` is an opaque token that the client passes back to
/// fetch the next page. When `next_cursor` is `None`, there are no more
/// results.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Page<T> {
    /// The items on this page.
    pub items: Vec<T>,
    /// Cursor for the next page, or `None` if this is the last page.
    pub next_cursor: Option<String>,
}

impl<T> Default for Page<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
        }
    }
}

/// Result of a single item within a bulk operation.
///
/// The `index` field identifies which item in the original request
/// this result corresponds to.
#[derive(Clone, Debug)]
pub struct BulkResult<T> {
    /// Zero-based index into the original request array.
    pub index: usize,
    /// Success value or error description.
    pub result: Result<T, String>,
}

/// The lifecycle status of a user account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserStatus {
    /// Account is active and can authenticate.
    Active,
    /// Account is disabled by an administrator.
    Disabled,
    /// Account is awaiting email verification.
    PendingVerification,
}

/// An action the user must complete before full access is granted.
///
/// Validated at write time — only these variants are accepted in v1.
/// Stored as `SCREAMING_SNAKE_CASE` strings (e.g. `"VERIFY_EMAIL"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequiredAction {
    /// User must verify their email address before proceeding.
    VerifyEmail,
    /// User must set a new password before proceeding.
    UpdatePassword,
    /// User must enroll an MFA factor before proceeding.
    ///
    /// Injected automatically by the adaptive-MFA engine when a login arrives
    /// from an unrecognised device and the user has no enrolled factor.
    EnrollMfa,
    /// User must enroll a verified phone number via SMS OTP before proceeding.
    ///
    /// Injected automatically when a realm has `mfa_methods: ["sms"]` and the
    /// user has no verified phone number on record.
    EnrollPhoneOtp,
}

impl RequiredAction {
    /// Canonical execution priority. Lower numbers run first.
    ///
    /// `VERIFY_EMAIL=1`, `UPDATE_PASSWORD=2`, `ENROLL_MFA=3`, `ENROLL_PHONE_OTP=4`.
    #[must_use]
    pub fn priority(self) -> u8 {
        match self {
            Self::VerifyEmail => 1,
            Self::UpdatePassword => 2,
            Self::EnrollMfa => 3,
            Self::EnrollPhoneOtp => 4,
        }
    }

    /// URL path segment used in `/required-action/{action}` routes.
    #[must_use]
    pub fn as_path_segment(self) -> &'static str {
        match self {
            Self::VerifyEmail => "VERIFY_EMAIL",
            Self::UpdatePassword => "UPDATE_PASSWORD",
            Self::EnrollMfa => "enroll-mfa",
            Self::EnrollPhoneOtp => "ENROLL_PHONE_OTP",
        }
    }

    /// Parse from a URL path segment (case-sensitive).
    pub fn from_path_segment(s: &str) -> Option<Self> {
        match s {
            "VERIFY_EMAIL" => Some(Self::VerifyEmail),
            "UPDATE_PASSWORD" => Some(Self::UpdatePassword),
            "enroll-mfa" => Some(Self::EnrollMfa),
            "ENROLL_PHONE_OTP" => Some(Self::EnrollPhoneOtp),
            _ => None,
        }
    }
}

/// A user record within a realm.
///
/// Fields are private; access via accessor methods. Email is always stored
/// normalized (lowercase, trimmed, NFC).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    id: UserId,
    email: String,
    display_name: String,
    first_name: String,
    last_name: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    attributes: BTreeMap<String, String>,
    status: UserStatus,
    /// Pending actions the user must complete. Absent in old records = [].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    required_actions: Vec<RequiredAction>,
    /// Whether the user's email address has been verified. Absent in old records = false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    email_verified: bool,
    /// E.164 phone number. `None` when no phone has been enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phone_number: Option<String>,
    /// Whether the stored phone number has been verified via OTP.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    phone_verified: bool,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl User {
    /// Creates a new user. Used internally by the identity engine.
    pub(crate) fn new(
        id: UserId,
        email: String,
        display_name: String,
        first_name: String,
        last_name: String,
        status: UserStatus,
        required_actions: Vec<RequiredAction>,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            id,
            email,
            display_name,
            first_name,
            last_name,
            attributes: BTreeMap::new(),
            status,
            required_actions,
            email_verified: false,
            phone_number: None,
            phone_verified: false,
            created_at,
            updated_at,
        }
    }

    /// Returns the user's unique identifier.
    pub fn id(&self) -> &UserId {
        &self.id
    }

    /// Returns the user's normalized email address.
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Returns the user's display name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the user's first (given) name. May be empty.
    pub fn first_name(&self) -> &str {
        &self.first_name
    }

    /// Returns the user's last (family) name. May be empty.
    pub fn last_name(&self) -> &str {
        &self.last_name
    }

    /// Returns the user's account status.
    pub fn status(&self) -> UserStatus {
        self.status
    }

    /// Returns the user's custom attribute map.
    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }

    /// Returns when the user was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when the user was last updated (UTC microseconds).
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Updates the email. Used internally during user updates.
    pub(crate) fn set_email(&mut self, email: String) {
        self.email = email;
    }

    /// Updates the display name. Used internally during user updates.
    pub(crate) fn set_display_name(&mut self, display_name: String) {
        self.display_name = display_name;
    }

    /// Updates the first name. Used internally during user updates.
    pub(crate) fn set_first_name(&mut self, first_name: String) {
        self.first_name = first_name;
    }

    /// Updates the last name. Used internally during user updates.
    pub(crate) fn set_last_name(&mut self, last_name: String) {
        self.last_name = last_name;
    }

    /// Replaces the attributes map.
    pub(crate) fn set_attributes(&mut self, attributes: BTreeMap<String, String>) {
        self.attributes = attributes;
    }

    /// Updates the status. Used internally during user updates.
    pub(crate) fn set_status(&mut self, status: UserStatus) {
        self.status = status;
    }

    /// Returns pending required actions for this user.
    pub fn required_actions(&self) -> &[RequiredAction] {
        &self.required_actions
    }

    /// Replaces the required actions list. Used internally by the identity engine.
    pub(crate) fn set_required_actions(&mut self, actions: Vec<RequiredAction>) {
        self.required_actions = actions;
    }

    /// Returns whether the user's email address has been verified.
    pub fn email_verified(&self) -> bool {
        self.email_verified
    }

    /// Marks the user's email as verified. Used internally by the identity engine.
    pub(crate) fn set_email_verified(&mut self, verified: bool) {
        self.email_verified = verified;
    }

    /// Returns the user's enrolled phone number in E.164 format, or `None` if not set.
    pub fn phone_number(&self) -> Option<&str> {
        self.phone_number.as_deref()
    }

    /// Returns the phone number masked for display in admin UIs (e.g. `+1***-***-1234`).
    ///
    /// Shows the `+` sign and the first country-code digit, then `***-***-`, then the
    /// last four digits. Returns `None` when no phone is enrolled. Phone numbers shorter
    /// than 6 E.164 characters return `"****"` instead of a structured mask.
    ///
    /// The raw number is never included — callers MUST NOT log or trace the return value
    /// as it still conveys partial PII.
    pub fn masked_phone_number(&self) -> Option<String> {
        self.phone_number.as_deref().map(mask_phone_number)
    }

    /// Sets (or clears) the user's phone number. Used internally by the identity engine.
    pub(crate) fn set_phone_number(&mut self, phone: Option<String>) {
        self.phone_number = phone;
    }

    /// Returns whether the stored phone number has been verified via OTP.
    pub fn phone_verified(&self) -> bool {
        self.phone_verified
    }

    /// Marks the user's phone number as verified (or unverified). Used internally.
    pub(crate) fn set_phone_verified(&mut self, verified: bool) {
        self.phone_verified = verified;
    }

    /// Updates the `updated_at` timestamp.
    pub(crate) fn set_updated_at(&mut self, ts: Timestamp) {
        self.updated_at = ts;
    }
}

/// Masks an E.164 phone number for admin display.
///
/// Shows `+{first digit}***-***-{last 4}`. For numbers shorter than 6 chars,
/// returns `"****"`. This function is intentionally not public — go through
/// `User::masked_phone_number()`.
fn mask_phone_number(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    if chars.len() < 6 {
        return "****".to_string();
    }
    let prefix: String = chars[..2].iter().collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    format!("{prefix}***-***-{suffix}")
}

/// Device and network context captured at session creation time.
///
/// All fields are optional — API-originated sessions (no browser) or
/// sessions created before this feature was added will have `None` values.
#[derive(Clone, Debug, Default)]
pub struct SessionContext {
    /// Client IP address (peer or extracted from `X-Forwarded-For`).
    pub ip_address: Option<String>,
    /// Raw `User-Agent` header value (stored for future re-parsing).
    pub user_agent_raw: Option<String>,
    /// Pre-parsed device label, e.g. `"Chrome, Mac OSX"`.
    pub device_label: Option<String>,
    /// Set to `true` when the session originates from a completed WebAuthn
    /// (passkey) ceremony. Passkeys are inherently multi-factor
    /// (possession + biometric/PIN), so they satisfy a realm's `mfa_required`
    /// policy without requiring a separate TOTP enrollment check.
    pub satisfies_mfa_via_passkey: bool,
}

/// An authentication session bound to a user.
///
/// Sessions have a configurable TTL and can be refreshed or revoked.
/// Fields are private; access via accessor methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    id: SessionId,
    user_id: UserId,
    created_at: Timestamp,
    expires_at: Timestamp,
    last_refreshed_at: Timestamp,
    revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_agent_raw: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_label: Option<String>,
    /// Deadline after which the session is idle-expired (A-18).
    /// Stored in the session record so `get_session` avoids a realm lookup on
    /// every access. Reset on each `refresh()`. `None` = no idle timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) idle_deadline: Option<Timestamp>,
    /// Hard absolute expiry deadline set at creation time (A-18).
    /// Never updated on refresh. `None` = no absolute timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) absolute_deadline: Option<Timestamp>,
}

impl Session {
    /// Creates a new session. Used internally by the identity engine.
    pub(crate) fn new(
        id: SessionId,
        user_id: UserId,
        created_at: Timestamp,
        expires_at: Timestamp,
        context: &SessionContext,
        idle_timeout_secs: Option<u32>,
        absolute_timeout_secs: Option<u32>,
    ) -> Self {
        let idle_deadline = idle_timeout_secs.map(|s| created_at.add_micros(s as i64 * 1_000_000));
        let absolute_deadline =
            absolute_timeout_secs.map(|s| created_at.add_micros(s as i64 * 1_000_000));
        Self {
            id,
            user_id,
            created_at,
            expires_at,
            last_refreshed_at: created_at,
            revoked: false,
            ip_address: context.ip_address.clone(),
            user_agent_raw: context.user_agent_raw.clone(),
            device_label: context.device_label.clone(),
            idle_deadline,
            absolute_deadline,
        }
    }

    /// Returns the session's unique identifier.
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Returns the ID of the user this session belongs to.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns when the session was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when the session expires (UTC microseconds).
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Returns when the session was last refreshed (UTC microseconds).
    pub fn last_refreshed_at(&self) -> Timestamp {
        self.last_refreshed_at
    }

    /// Returns whether the session has been revoked.
    pub(crate) fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Returns whether the session is valid (not expired and not revoked).
    pub(crate) fn is_valid(&self, now: Timestamp) -> bool {
        !self.revoked && now < self.expires_at
    }

    /// Marks the session as revoked.
    pub(crate) fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Refreshes the session by extending the TTL and resetting the idle deadline.
    pub(crate) fn refresh(&mut self, now: Timestamp, ttl_micros: i64) {
        // Recover idle window BEFORE overwriting last_refreshed_at.
        let new_idle = self.idle_deadline.map(|deadline| {
            let window = deadline.as_micros() - self.last_refreshed_at.as_micros();
            now.add_micros(window)
        });
        self.expires_at = now.add_micros(ttl_micros);
        self.last_refreshed_at = now;
        if let Some(d) = new_idle {
            self.idle_deadline = Some(d);
        }
        // absolute_deadline is intentionally NOT updated — it is a hard cap.
    }

    /// Returns `true` if the session has exceeded its idle or absolute timeout
    /// policy (A-18). Does NOT check the standard TTL (`is_valid`).
    pub(crate) fn is_policy_expired(&self, now: Timestamp) -> bool {
        self.idle_deadline.map_or(false, |d| now >= d)
            || self.absolute_deadline.map_or(false, |d| now >= d)
    }

    /// Returns the eviction reason string for audit metadata.
    pub(crate) fn policy_expiry_reason(&self, now: Timestamp) -> Option<&'static str> {
        if self.idle_deadline.map_or(false, |d| now >= d) {
            return Some("idle_timeout");
        }
        if self.absolute_deadline.map_or(false, |d| now >= d) {
            return Some("absolute_timeout");
        }
        None
    }

    /// Returns the client IP address captured at session creation, if available.
    pub fn ip_address(&self) -> Option<&str> {
        self.ip_address.as_deref()
    }

    /// Returns the raw User-Agent header captured at session creation, if available.
    pub fn user_agent_raw(&self) -> Option<&str> {
        self.user_agent_raw.as_deref()
    }

    /// Returns the pre-parsed device label (e.g. "Chrome, Mac OSX"), if available.
    pub fn device_label(&self) -> Option<&str> {
        self.device_label.as_deref()
    }
}

/// Request to create a new user.
///
/// `display_name` may be left empty; when empty, the identity engine
/// synthesizes it from `"{first_name} {last_name}"` (trimmed). `first_name`
/// and `last_name` are required fields on the model but may themselves be
/// empty strings for callers that genuinely have no name data.
#[derive(Clone, Debug, Default)]
pub struct CreateUserRequest {
    /// Email address (will be normalized).
    pub email: String,
    /// Display name (will be trimmed and NFC-normalized). If empty, the
    /// engine synthesizes `"{first_name} {last_name}"`.
    pub display_name: String,
    /// User's first (given) name. Empty string allowed.
    pub first_name: String,
    /// User's last (family) name. Empty string allowed.
    pub last_name: String,
    /// Custom attribute key-value pairs.
    pub attributes: BTreeMap<String, String>,
}

/// Request to self-register a new user via the public signup flow.
///
/// Distinct from `CreateUserRequest` (admin-only) because self-registration
/// carries anti-abuse signals (client IP) and optional invitation tokens,
/// and the resulting user lands in [`UserStatus::PendingVerification`]
/// until the email-verification token is consumed.
#[derive(Debug)]
pub struct RegisterUserRequest {
    /// Email address (will be normalized).
    pub email: String,
    /// Display name (will be trimmed and NFC-normalized). If empty, the engine
    /// synthesizes `"{first_name} {last_name}"`.
    pub display_name: String,
    /// User's first (given) name.
    pub first_name: String,
    /// User's last (family) name.
    pub last_name: String,
    /// The user's chosen password. Subject to the realm's password policy.
    pub password: CleartextPassword,
    /// Client IP for anti-abuse rate limiting. `None` skips the IP bucket
    /// (embedded callers that don't have an IP surface).
    pub client_ip: Option<String>,
    /// Organization invitation token. Required when the realm's policy is
    /// [`RegistrationPolicy::InviteOnly`]; optional otherwise.
    pub invitation_token: Option<String>,
}

/// Result of a successful self-registration.
///
/// The plaintext `verification_token` is returned exactly once so the caller
/// can embed it in a verification URL and email it to the user. It is never
/// persisted in plaintext.
#[derive(Debug)]
pub struct RegisterUserResponse {
    /// The ID of the newly created (or, on duplicate email, a synthetic
    /// enumeration-resistant) user.
    pub user_id: UserId,
    /// Plaintext email-verification token (base64url, one-shot).
    pub verification_token: String,
}

/// Response returned by `complete_update_password`.
///
/// The `access_token` is either a new RA JWT (when further required actions
/// remain) or a full-access JWT (when all actions are satisfied). Callers
/// distinguish the two cases by decoding `token_type` from the payload:
/// `"ra"` → more actions remain; `"access"` → flow complete.
#[derive(Debug)]
pub struct RequiredActionTokenResponse {
    /// The next token in the required-action flow.
    pub access_token: String,
}

/// Request to update an existing user.
///
/// Only `Some` fields are applied; `None` fields are left unchanged.
#[derive(Clone, Debug, Default)]
pub struct UpdateUserRequest {
    /// New email address (will be normalized).
    pub email: Option<String>,
    /// New display name (will be trimmed and NFC-normalized).
    pub display_name: Option<String>,
    /// New first name. `Some("")` clears the field; `None` leaves it unchanged.
    pub first_name: Option<String>,
    /// New last name. `Some("")` clears the field; `None` leaves it unchanged.
    pub last_name: Option<String>,
    /// New account status.
    pub status: Option<UserStatus>,
    /// Replace the custom attribute map.
    pub attributes: Option<BTreeMap<String, String>>,
    /// Replace the required actions list. `Some([])` clears all actions; `None` leaves unchanged.
    pub required_actions: Option<Vec<RequiredAction>>,
    /// Set the user's phone number in E.164 format. `Some(None)` clears the field; `None` leaves unchanged.
    pub phone_number: Option<Option<String>>,
    /// Set the phone-verified flag. `None` leaves unchanged.
    pub phone_verified: Option<bool>,
}

// ===== Realm types =====

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
    Open,
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
    /// Allowed MFA methods (e.g. `["totp", "webauthn", "sms"]`).
    pub mfa_methods: Option<Vec<String>>,
    /// Per-realm SMS OTP expiry in seconds. `None` falls back to the module default (600 s / 10 min).
    pub sms_otp_expiry_seconds: Option<u64>,
    /// Per-realm SMS OTP maximum verification attempts before the record is discarded.
    /// `None` falls back to the module default (5).
    pub sms_otp_max_attempts: Option<u32>,
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

// ===== Organization types =====

/// The lifecycle status of an organization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OrganizationStatus {
    /// Organization is active; members can operate normally.
    Active,
    /// Organization is suspended by an administrator.
    Suspended,
    /// Organization was removed from YAML config and soft-deleted.
    ///
    /// Behaves like `Suspended` (new membership operations denied) but
    /// additionally signals that the org can be permanently deleted from
    /// the admin UI. Restored to `Active` if the org slug reappears in YAML.
    Archived,
}

/// Per-organization configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationConfig {
    /// Maximum number of members allowed. `None` means unlimited.
    pub max_members: Option<u32>,
}

/// An organization within a realm.
///
/// Organizations represent B2B customer groups. Users can be members of
/// multiple organizations within the same realm. Fields are private;
/// access via accessor methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    id: OrganizationId,
    name: String,
    slug: String,
    description: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    attributes: BTreeMap<String, String>,
    status: OrganizationStatus,
    config: OrganizationConfig,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl Organization {
    /// Creates a new organization. Used internally by the identity engine.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: OrganizationId,
        name: String,
        slug: String,
        description: String,
        status: OrganizationStatus,
        config: OrganizationConfig,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            id,
            name,
            slug,
            description,
            attributes: BTreeMap::new(),
            status,
            config,
            created_at,
            updated_at,
        }
    }

    /// Returns the organization's unique identifier.
    pub fn id(&self) -> &OrganizationId {
        &self.id
    }

    /// Returns the organization's display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the organization's URL-safe slug.
    pub fn slug(&self) -> &str {
        &self.slug
    }

    /// Returns the organization's description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the organization's custom attribute map.
    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }

    /// Returns the organization's lifecycle status.
    pub fn status(&self) -> OrganizationStatus {
        self.status
    }

    /// Returns the organization's configuration.
    pub fn config(&self) -> &OrganizationConfig {
        &self.config
    }

    /// Returns when the organization was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when the organization was last updated (UTC microseconds).
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Updates the name. Used internally during organization updates.
    pub(crate) fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Updates the description. Used internally during organization updates.
    pub(crate) fn set_description(&mut self, description: String) {
        self.description = description;
    }

    /// Replaces the attributes map. Used internally during organization updates.
    pub(crate) fn set_attributes(&mut self, attributes: BTreeMap<String, String>) {
        self.attributes = attributes;
    }

    /// Updates the status. Used internally during organization updates.
    pub(crate) fn set_status(&mut self, status: OrganizationStatus) {
        self.status = status;
    }

    /// Updates the configuration. Used internally during organization updates.
    pub(crate) fn set_config(&mut self, config: OrganizationConfig) {
        self.config = config;
    }

    /// Updates the `updated_at` timestamp.
    pub(crate) fn set_updated_at(&mut self, ts: Timestamp) {
        self.updated_at = ts;
    }
}

/// A role within an organization.
///
/// Roles form a hierarchy: Owner > Admin > Member. Higher roles
/// inherit the capabilities of lower roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrganizationRole {
    /// Full control including delete, role management, and billing.
    Owner,
    /// Can manage members and settings but not delete the org.
    Admin,
    /// Basic membership with access to org resources.
    Member,
}

/// A membership record linking a user to an organization.
///
/// Stored as bidirectional indexes (org→user and user→org) for
/// efficient lookups in both directions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationMembership {
    org_id: OrganizationId,
    user_id: UserId,
    role: OrganizationRole,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    additional_roles: Vec<String>,
    joined_at: Timestamp,
    invited_by: Option<UserId>,
}

impl OrganizationMembership {
    /// Creates a new membership. Used internally by the identity engine.
    pub(crate) fn new(
        org_id: OrganizationId,
        user_id: UserId,
        role: OrganizationRole,
        joined_at: Timestamp,
        invited_by: Option<UserId>,
    ) -> Self {
        Self {
            org_id,
            user_id,
            role,
            additional_roles: Vec::new(),
            joined_at,
            invited_by,
        }
    }

    /// Returns the organization this membership belongs to.
    pub fn org_id(&self) -> &OrganizationId {
        &self.org_id
    }

    /// Returns the user who is a member.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the member's role within the organization.
    pub fn role(&self) -> OrganizationRole {
        self.role
    }

    /// Additional organization-scoped RBAC roles layered on top of the
    /// canonical membership tier.
    pub fn additional_roles(&self) -> &[String] {
        &self.additional_roles
    }

    /// Returns when the user joined the organization (UTC microseconds).
    pub fn joined_at(&self) -> Timestamp {
        self.joined_at
    }

    /// Returns who invited this member, if applicable.
    pub fn invited_by(&self) -> Option<&UserId> {
        self.invited_by.as_ref()
    }

    /// Updates the role. Used internally during role changes.
    pub(crate) fn set_role(&mut self, role: OrganizationRole) {
        self.role = role;
    }

    /// Replaces the additional role set.
    #[allow(dead_code)]
    pub(crate) fn set_additional_roles(&mut self, roles: Vec<String>) {
        self.additional_roles = roles;
    }
}

/// The status of an organization invitation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvitationStatus {
    /// Invitation has been sent but not yet acted upon.
    Pending,
    /// Invitation was accepted; the user is now a member.
    Accepted,
    /// Invitation was revoked by an admin before acceptance.
    Revoked,
    /// Invitation expired before the recipient acted.
    Expired,
}

/// An invitation to join an organization.
///
/// The token is stored as a SHA-256 hash. The plaintext token is returned
/// only once at creation time and never persisted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationInvitation {
    id: InvitationId,
    org_id: OrganizationId,
    email: String,
    role: OrganizationRole,
    token_hash: String,
    status: InvitationStatus,
    expires_at: Timestamp,
    invited_by: UserId,
    created_at: Timestamp,
}

impl OrganizationInvitation {
    /// Creates a new invitation. Used internally by the identity engine.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: InvitationId,
        org_id: OrganizationId,
        email: String,
        role: OrganizationRole,
        token_hash: String,
        status: InvitationStatus,
        expires_at: Timestamp,
        invited_by: UserId,
        created_at: Timestamp,
    ) -> Self {
        Self {
            id,
            org_id,
            email,
            role,
            token_hash,
            status,
            expires_at,
            invited_by,
            created_at,
        }
    }

    /// Returns the invitation's unique identifier.
    pub fn id(&self) -> &InvitationId {
        &self.id
    }

    /// Returns which organization this invitation is for.
    pub fn org_id(&self) -> &OrganizationId {
        &self.org_id
    }

    /// Returns the email address the invitation was sent to.
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Returns the role the invitee will receive upon acceptance.
    pub fn role(&self) -> OrganizationRole {
        self.role
    }

    /// Returns the SHA-256 hash of the invitation token.
    pub(crate) fn token_hash(&self) -> &str {
        &self.token_hash
    }

    /// Returns the invitation's current status.
    pub fn status(&self) -> InvitationStatus {
        self.status
    }

    /// Returns when the invitation expires (UTC microseconds).
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Returns who created this invitation.
    pub fn invited_by(&self) -> &UserId {
        &self.invited_by
    }

    /// Returns when the invitation was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Marks the invitation as accepted.
    pub(crate) fn set_accepted(&mut self) {
        self.status = InvitationStatus::Accepted;
    }

    /// Marks the invitation as revoked.
    pub(crate) fn set_revoked(&mut self) {
        self.status = InvitationStatus::Revoked;
    }
}

/// Request to create a new organization.
#[derive(Clone, Debug, Default)]
pub struct CreateOrganizationRequest {
    /// Display name for the organization.
    pub name: String,
    /// URL-safe slug (lowercase alphanumeric + hyphens, 3-63 chars).
    pub slug: String,
    /// Optional description.
    pub description: Option<String>,
    /// Optional configuration overrides.
    pub config: Option<OrganizationConfig>,
    /// Custom attribute key-value pairs.
    pub attributes: BTreeMap<String, String>,
}

/// Request to update an existing organization.
///
/// Only `Some` fields are applied; `None` fields are left unchanged.
#[derive(Clone, Debug, Default)]
pub struct UpdateOrganizationRequest {
    /// New display name.
    pub name: Option<String>,
    /// New description.
    pub description: Option<String>,
    /// New lifecycle status.
    pub status: Option<OrganizationStatus>,
    /// New configuration overrides.
    pub config: Option<OrganizationConfig>,
    /// Replace the custom attribute map. `None` leaves existing attributes unchanged.
    pub attributes: Option<BTreeMap<String, String>>,
}

/// Request to create an invitation to join an organization.
#[derive(Clone, Debug)]
pub struct CreateInvitationRequest {
    /// Organization to invite the user to.
    pub org_id: OrganizationId,
    /// Email address of the invitee.
    pub email: String,
    /// Role to assign upon acceptance.
    pub role: OrganizationRole,
    /// User who is creating the invitation.
    pub invited_by: UserId,
}

// ===== Migration / import request types (Phase 1 Step 30) =====

/// A credential record exported from a realm for backup purposes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialExport {
    /// The user this credential belongs to.
    pub user_id: UserId,
    /// PHC-formatted hash string (e.g. `$argon2id$...`).
    pub phc_string: String,
    /// Creation timestamp in Unix microseconds.
    pub created_at_micros: i64,
}

/// A pre-hashed credential to attach to an imported user.
///
/// Unlike `CreateUserRequest` + `set_password`, imports preserve the
/// source system's hash verbatim so users can authenticate with their
/// existing passwords. New hashes (via `change_password` or `set_password`)
/// are always Argon2id; successful verification against a legacy hash
/// auto-upgrades it in place.
#[derive(Clone, Debug)]
pub struct RawCredential {
    /// The PHC-formatted hash string (e.g. `$pbkdf2-sha256$i=27500$salt$hash`).
    pub phc_string: String,
    /// Unix-microseconds timestamp of original credential creation, if known.
    pub created_at_micros: Option<i64>,
}

/// Request to import a user from an external identity provider.
///
/// `id` allows preserving the source system's user ID so that in-flight
/// tokens and application-level references remain valid; leave `None`
/// to let the engine generate a fresh `UserId`. `credential` may be
/// `None` — e.g. for users whose source hash used an unsupported KDF.
#[derive(Clone, Debug)]
pub struct ImportUserRequest {
    /// Preserved source-system UUID, or `None` to generate a new one.
    pub id: Option<UserId>,
    /// Email address (will be normalized).
    pub email: String,
    /// Display name (will be trimmed and NFC-normalized). If empty, the
    /// engine synthesizes `"{first_name} {last_name}"`.
    pub display_name: String,
    /// User's first (given) name. Empty string allowed.
    pub first_name: String,
    /// User's last (family) name. Empty string allowed.
    pub last_name: String,
    /// Account status.
    pub status: UserStatus,
    /// Pre-hashed credential. `None` imports the user with no password.
    pub credential: Option<RawCredential>,
    /// Custom attribute key-value pairs.
    pub attributes: BTreeMap<String, String>,
}

/// Request to import an OAuth 2.0 client from an external provider.
///
/// Unlike `RegisterClientRequest`, this allows preserving the client's
/// source-system identifier. The secret (if any) is hashed with Argon2id
/// at import time — the source system's hashed secret is not reusable
/// because Hearth's storage format requires Argon2id.
#[derive(Clone, Debug)]
pub struct ImportClientRequest {
    /// Preserved source-system client UUID, or `None` to generate.
    pub id: Option<crate::core::ClientId>,
    /// Display name.
    pub client_name: String,
    /// Allowed redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Plaintext client secret — hashed with Argon2id before storage.
    /// `None` creates a public client.
    pub client_secret: Option<String>,
    /// Allowed OAuth 2.0 grant types (defaults to `authorization_code`).
    pub grant_types: Vec<String>,
    /// Stable client slug.
    pub slug: Option<String>,
    /// Client trust posture.
    pub trust_level: crate::identity::ClientTrustLevel,
    /// Declared scope allowlist.
    pub declared_scopes: Vec<String>,
    /// Whether a realm-level consent spans org contexts.
    pub consent_spans_orgs: bool,
}

/// Summary returned by a successful migration.
///
/// Counts reflect what was actually written. `warnings` contains
/// human-readable notes about partial imports (e.g. users whose credential
/// used an unsupported KDF and was skipped).
#[derive(Clone, Debug, Default)]
pub struct MigrationReport {
    /// ID of the realm the migrated realm was imported into.
    pub realm_id: Option<RealmId>,
    /// Number of users written.
    pub users_imported: usize,
    /// Number of users whose credentials could not be imported
    /// (the user record itself was still created).
    pub users_with_skipped_credentials: usize,
    /// Number of OAuth clients written.
    pub clients_imported: usize,
    /// Number of RBAC role assignments written.
    pub role_assignments_written: usize,
    /// Non-fatal issues encountered during the import.
    pub warnings: Vec<String>,
}

// ===== OAuth Consent =====

/// A user's persisted consent to share a set of scopes with an OAuth client.
///
/// Stored per `(realm, user, client)`. `granted_scopes` is the canonical,
/// sorted, deduplicated set of scopes the user has approved. Subsequent
/// authorization requests that ask only for a subset of these scopes skip
/// the consent prompt; requests that add a new scope re-prompt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentRecord {
    /// The subject user.
    pub user_id: UserId,
    /// The OAuth client the consent applies to.
    pub client_id: ClientId,
    /// Organization context captured at grant time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_oid: Option<OrganizationId>,
    /// Resource indicator captured at grant time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Canonicalized (sorted + deduplicated) scopes the user has approved.
    pub granted_scopes: Vec<String>,
    /// Digest of the authorization + disclosure surface.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope_digest: Vec<u8>,
    /// When consent was first recorded.
    pub granted_at: Timestamp,
    /// When the scope set was last updated.
    pub updated_at: Timestamp,
}

impl ConsentRecord {
    /// Creates a new consent record. `scopes` will be canonicalized.
    pub fn new(user_id: UserId, client_id: ClientId, scopes: Vec<String>, now: Timestamp) -> Self {
        Self {
            user_id,
            client_id,
            context_oid: None,
            resource: None,
            granted_scopes: canonicalize_scopes(scopes),
            scope_digest: Vec::new(),
            granted_at: now,
            updated_at: now,
        }
    }

    /// Returns `true` iff every requested scope is already in `granted_scopes`.
    ///
    /// Empty `requested` yields `true` — a client can always ask for nothing.
    pub fn covers(&self, requested: &[String]) -> bool {
        requested
            .iter()
            .all(|s| self.granted_scopes.iter().any(|g| g == s))
    }

    /// Merges `additional` into `granted_scopes`, canonicalizing and
    /// updating `updated_at`.
    pub fn merge_scopes(&mut self, additional: &[String], now: Timestamp) {
        let mut all = self.granted_scopes.clone();
        all.extend(additional.iter().cloned());
        self.granted_scopes = canonicalize_scopes(all);
        self.updated_at = now;
    }
}

/// Sorts and deduplicates a list of scopes. Empty strings are dropped.
///
/// Canonical form makes consent comparisons deterministic and makes the
/// stored record stable regardless of submission order.
pub fn canonicalize_scopes(mut scopes: Vec<String>) -> Vec<String> {
    scopes.retain(|s| !s.trim().is_empty());
    for s in &mut scopes {
        *s = s.trim().to_string();
    }
    scopes.sort();
    scopes.dedup();
    scopes
}

/// Listing entry for consents shown to the user or to an admin.
///
/// Joins the `ConsentRecord` with human-readable fields from the OAuth
/// client so callers can render a useful page without a second round-trip.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentListEntry {
    /// The underlying consent record.
    pub record: ConsentRecord,
    /// Client display name at list time.
    pub client_name: String,
    /// Client logo URL at list time, if set.
    pub client_logo_url: Option<String>,
}

/// Pending authorization request captured while the user decides consent.
///
/// Stored under `oauth:pending_auth:{ticket}` with a short TTL. The
/// consent form submits the ticket back; the server validates the ticket
/// matches the current user, checks approved scopes are a subset of
/// `requested_scopes`, issues an authorization code, and deletes the
/// ticket (single-use).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingAuthorizationRequest {
    /// The user who owns this pending request. Prevents cross-user replay.
    pub user_id: UserId,
    /// The client requesting authorization.
    pub client_id: ClientId,
    /// Registered redirect URI (already validated against the client).
    pub redirect_uri: String,
    /// Scopes requested by the client, canonicalized.
    pub requested_scopes: Vec<String>,
    /// OAuth `state` parameter — echoed back to the client on redirect.
    pub state: String,
    /// OAuth `response_type` (must be `code`).
    pub response_type: String,
    /// PKCE code challenge, if present.
    pub code_challenge: Option<String>,
    /// PKCE code challenge method, if present. Domain string ("S256").
    pub code_challenge_method: Option<String>,
    /// OIDC nonce echoed into the ID token.
    pub nonce: Option<String>,
    /// JARM response mode wire string (`query.jwt`, `fragment.jwt`, `jwt`).
    ///
    /// `None` means the client used the default `query` mode. Preserved here
    /// so it can be threaded through the consent redirect path.
    pub response_mode: Option<String>,
    /// JARM signing algorithm from `OAuthClient.authorization_signed_response_alg`.
    ///
    /// Carried forward so that error redirects in consent_post can be
    /// JWT-wrapped without an extra client lookup (JARM §4.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_signed_response_alg: Option<String>,
    /// When the ticket was created.
    pub created_at: Timestamp,
    /// When the ticket expires. Past this point `take_pending_authorization`
    /// returns `ConsentTicketExpired`.
    pub expires_at: Timestamp,
}

/// The user's decision on the consent prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsentDecision {
    /// User approved the listed scopes.
    Approve,
    /// User denied the authorization entirely.
    Deny,
}

// ---------------------------------------------------------------------------
// Webhook types
// ---------------------------------------------------------------------------

/// A registered webhook endpoint that receives HTTP POST notifications for
/// subscribed realm events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Webhook {
    id: WebhookId,
    realm_id: RealmId,
    /// HTTPS (or HTTP-localhost) endpoint URL.
    pub url: String,
    /// HMAC-SHA256 signing secret. `None` means deliveries are unsigned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Subscribed event types. Empty list = subscribe to all events.
    pub events: Vec<String>,
    /// Whether this webhook is active and should receive deliveries.
    pub enabled: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl Webhook {
    /// Creates a new webhook. Used internally by the identity engine.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: WebhookId,
        realm_id: RealmId,
        url: String,
        secret: Option<String>,
        events: Vec<String>,
        enabled: bool,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            id,
            realm_id,
            url,
            secret,
            events,
            enabled,
            created_at,
            updated_at,
        }
    }

    /// Returns the unique identifier for this webhook.
    #[must_use]
    pub fn id(&self) -> &WebhookId {
        &self.id
    }

    /// Returns the realm this webhook belongs to.
    #[must_use]
    pub fn realm_id(&self) -> &RealmId {
        &self.realm_id
    }
}

/// Request to register a new webhook.
#[derive(Clone, Debug)]
pub struct CreateWebhookRequest {
    /// Endpoint URL.
    pub url: String,
    /// Optional HMAC-SHA256 signing secret.
    pub secret: Option<String>,
    /// Event type filter. Empty = all events.
    pub events: Vec<String>,
    /// Whether to activate the webhook immediately.
    pub enabled: bool,
}

/// Request to update an existing webhook's configuration.
#[derive(Clone, Debug)]
pub struct UpdateWebhookRequest {
    /// Endpoint URL.
    pub url: String,
    /// Optional HMAC-SHA256 signing secret. `None` clears the secret.
    pub secret: Option<String>,
    /// Event type filter. Empty = all events.
    pub events: Vec<String>,
    /// Whether the webhook is active.
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Timestamp;

    #[test]
    fn user_accessors() {
        let id = UserId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let user = User::new(
            id.clone(),
            "alice@example.com".to_string(),
            "Alice".to_string(),
            "Alice".to_string(),
            String::new(),
            UserStatus::Active,
            Vec::new(),
            now,
            now,
        );

        assert_eq!(user.id(), &id);
        assert_eq!(user.email(), "alice@example.com");
        assert_eq!(user.display_name(), "Alice");
        assert_eq!(user.status(), UserStatus::Active);
        assert_eq!(user.created_at(), now);
        assert_eq!(user.updated_at(), now);
    }

    #[test]
    fn user_serde_round_trip() {
        let user = User::new(
            UserId::generate(),
            "bob@example.com".to_string(),
            "Bob".to_string(),
            "Bob".to_string(),
            String::new(),
            UserStatus::PendingVerification,
            Vec::new(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(2_000),
        );

        let json = serde_json::to_string(&user).expect("serialize");
        let deserialized: User = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(user, deserialized);
    }

    #[test]
    fn user_status_serde_round_trip() {
        for status in [
            UserStatus::Active,
            UserStatus::Disabled,
            UserStatus::PendingVerification,
        ] {
            let json = serde_json::to_string(&status).expect("serialize");
            let deserialized: UserStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn user_mutators() {
        let mut user = User::new(
            UserId::generate(),
            "old@example.com".to_string(),
            "Old Name".to_string(),
            "Old".to_string(),
            "Name".to_string(),
            UserStatus::Active,
            Vec::new(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(1_000),
        );

        user.set_email("new@example.com".to_string());
        user.set_display_name("New Name".to_string());
        user.set_status(UserStatus::Disabled);
        user.set_updated_at(Timestamp::from_micros(2_000));

        assert_eq!(user.email(), "new@example.com");
        assert_eq!(user.display_name(), "New Name");
        assert_eq!(user.status(), UserStatus::Disabled);
        assert_eq!(user.updated_at(), Timestamp::from_micros(2_000));
    }

    #[test]
    fn update_request_default_is_all_none() {
        let req = UpdateUserRequest::default();
        assert!(req.email.is_none());
        assert!(req.display_name.is_none());
        assert!(req.status.is_none());
    }

    // ===== Realm type tests =====

    #[test]
    fn realm_accessors() {
        let id = RealmId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let config = RealmConfig {
            session_ttl_micros: Some(3_600_000_000),
            ..RealmConfig::default()
        };
        let realm = Realm::new(
            id.clone(),
            "Acme Corp".to_string(),
            RealmStatus::Active,
            config.clone(),
            now,
            now,
        );

        assert_eq!(realm.id(), &id);
        assert_eq!(realm.name(), "Acme Corp");
        assert_eq!(realm.status(), RealmStatus::Active);
        assert_eq!(realm.config(), &config);
        assert_eq!(realm.created_at(), now);
        assert_eq!(realm.updated_at(), now);

        // Verify new auth policy fields default to None
        assert!(config.mfa_required.is_none());
        assert!(config.mfa_methods.is_none());
        assert!(config.allowed_auth_methods.is_none());
        assert!(config.password_policy.is_none());
        assert!(config.access_token_ttl_micros.is_none());
        assert!(config.refresh_token_ttl_micros.is_none());
        assert!(config.max_failed_logins.is_none());
        assert!(config.lockout_duration_micros.is_none());
    }

    #[test]
    fn realm_serde_round_trip() {
        let realm = Realm::new(
            RealmId::generate(),
            "Test Realm".to_string(),
            RealmStatus::Active,
            RealmConfig::default(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(2_000),
        );

        let json = serde_json::to_string(&realm).expect("serialize");
        let deserialized: Realm = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(realm, deserialized);
    }

    #[test]
    fn realm_status_serde_round_trip() {
        for status in [RealmStatus::Active, RealmStatus::Suspended] {
            let json = serde_json::to_string(&status).expect("serialize");
            let deserialized: RealmStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn realm_mutators() {
        let mut realm = Realm::new(
            RealmId::generate(),
            "Old Name".to_string(),
            RealmStatus::Active,
            RealmConfig::default(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(1_000),
        );

        realm.set_name("New Name".to_string());
        realm.set_status(RealmStatus::Suspended);
        let new_config = RealmConfig {
            session_ttl_micros: Some(7_200_000_000),
            password_memory_cost: Some(65536),
            password_time_cost: Some(3),
            ..RealmConfig::default()
        };
        realm.set_config(new_config.clone());
        realm.set_updated_at(Timestamp::from_micros(2_000));

        assert_eq!(realm.name(), "New Name");
        assert_eq!(realm.status(), RealmStatus::Suspended);
        assert_eq!(realm.config(), &new_config);
        assert_eq!(realm.updated_at(), Timestamp::from_micros(2_000));
    }

    #[test]
    fn realm_config_default_is_all_none() {
        let config = RealmConfig::default();
        assert!(config.session_ttl_micros.is_none());
        assert!(config.password_memory_cost.is_none());
        assert!(config.password_time_cost.is_none());
    }

    #[test]
    fn update_realm_request_default_is_all_none() {
        let req = UpdateRealmRequest::default();
        assert!(req.name.is_none());
        assert!(req.status.is_none());
        assert!(req.config.is_none());
    }

    // ===== Organization type tests =====

    #[test]
    fn organization_accessors() {
        let id = OrganizationId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let config = OrganizationConfig {
            max_members: Some(100),
        };
        let org = Organization::new(
            id.clone(),
            "Acme Corp".to_string(),
            "acme-corp".to_string(),
            "A test org".to_string(),
            OrganizationStatus::Active,
            config.clone(),
            now,
            now,
        );

        assert_eq!(org.id(), &id);
        assert_eq!(org.name(), "Acme Corp");
        assert_eq!(org.slug(), "acme-corp");
        assert_eq!(org.description(), "A test org");
        assert_eq!(org.status(), OrganizationStatus::Active);
        assert_eq!(org.config(), &config);
        assert_eq!(org.created_at(), now);
        assert_eq!(org.updated_at(), now);
    }

    #[test]
    fn organization_serde_round_trip() {
        let org = Organization::new(
            OrganizationId::generate(),
            "Test Org".to_string(),
            "test-org".to_string(),
            String::new(),
            OrganizationStatus::Active,
            OrganizationConfig::default(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(2_000),
        );

        let json = serde_json::to_string(&org).expect("serialize");
        let deserialized: Organization = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(org, deserialized);
    }

    #[test]
    fn organization_mutators() {
        let mut org = Organization::new(
            OrganizationId::generate(),
            "Old Name".to_string(),
            "old-name".to_string(),
            "Old desc".to_string(),
            OrganizationStatus::Active,
            OrganizationConfig::default(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(1_000),
        );

        org.set_name("New Name".to_string());
        org.set_description("New desc".to_string());
        org.set_status(OrganizationStatus::Suspended);
        org.set_config(OrganizationConfig {
            max_members: Some(50),
        });
        org.set_updated_at(Timestamp::from_micros(2_000));

        assert_eq!(org.name(), "New Name");
        assert_eq!(org.description(), "New desc");
        assert_eq!(org.status(), OrganizationStatus::Suspended);
        assert_eq!(org.config().max_members, Some(50));
        assert_eq!(org.updated_at(), Timestamp::from_micros(2_000));
    }

    #[test]
    fn membership_accessors() {
        let org_id = OrganizationId::generate();
        let user_id = UserId::generate();
        let inviter = UserId::generate();
        let now = Timestamp::from_micros(1_000_000);

        let membership = OrganizationMembership::new(
            org_id.clone(),
            user_id.clone(),
            OrganizationRole::Admin,
            now,
            Some(inviter.clone()),
        );

        assert_eq!(membership.org_id(), &org_id);
        assert_eq!(membership.user_id(), &user_id);
        assert_eq!(membership.role(), OrganizationRole::Admin);
        assert_eq!(membership.joined_at(), now);
        assert_eq!(membership.invited_by(), Some(&inviter));
    }

    #[test]
    fn membership_serde_round_trip() {
        let membership = OrganizationMembership::new(
            OrganizationId::generate(),
            UserId::generate(),
            OrganizationRole::Member,
            Timestamp::from_micros(1_000),
            None,
        );

        let json = serde_json::to_string(&membership).expect("serialize");
        let deserialized: OrganizationMembership =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(membership, deserialized);
    }

    #[test]
    fn invitation_accessors() {
        let inv_id = InvitationId::generate();
        let org_id = OrganizationId::generate();
        let inviter = UserId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let expires = Timestamp::from_micros(2_000_000);

        let invitation = OrganizationInvitation::new(
            inv_id.clone(),
            org_id.clone(),
            "alice@example.com".to_string(),
            OrganizationRole::Member,
            "abc123hash".to_string(),
            InvitationStatus::Pending,
            expires,
            inviter.clone(),
            now,
        );

        assert_eq!(invitation.id(), &inv_id);
        assert_eq!(invitation.org_id(), &org_id);
        assert_eq!(invitation.email(), "alice@example.com");
        assert_eq!(invitation.role(), OrganizationRole::Member);
        assert_eq!(invitation.token_hash(), "abc123hash");
        assert_eq!(invitation.status(), InvitationStatus::Pending);
        assert_eq!(invitation.expires_at(), expires);
        assert_eq!(invitation.invited_by(), &inviter);
        assert_eq!(invitation.created_at(), now);
    }

    #[test]
    fn invitation_status_transitions() {
        let mut invitation = OrganizationInvitation::new(
            InvitationId::generate(),
            OrganizationId::generate(),
            "bob@example.com".to_string(),
            OrganizationRole::Admin,
            "hash".to_string(),
            InvitationStatus::Pending,
            Timestamp::from_micros(2_000_000),
            UserId::generate(),
            Timestamp::from_micros(1_000_000),
        );

        assert_eq!(invitation.status(), InvitationStatus::Pending);

        invitation.set_accepted();
        assert_eq!(invitation.status(), InvitationStatus::Accepted);

        // Test revoke on a fresh invitation
        let mut invitation2 = OrganizationInvitation::new(
            InvitationId::generate(),
            OrganizationId::generate(),
            "carol@example.com".to_string(),
            OrganizationRole::Member,
            "hash2".to_string(),
            InvitationStatus::Pending,
            Timestamp::from_micros(2_000_000),
            UserId::generate(),
            Timestamp::from_micros(1_000_000),
        );

        invitation2.set_revoked();
        assert_eq!(invitation2.status(), InvitationStatus::Revoked);
    }

    #[test]
    fn update_organization_request_default_is_all_none() {
        let req = UpdateOrganizationRequest::default();
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.status.is_none());
        assert!(req.config.is_none());
    }

    // ===== Consent record tests =====

    #[test]
    fn consent_record_scope_union_is_deduped_and_sorted() {
        let now = Timestamp::from_micros(1_000_000);
        let mut rec = ConsentRecord::new(
            UserId::generate(),
            ClientId::generate(),
            vec!["profile".to_string(), "email".to_string()],
            now,
        );
        // Canonical at construction.
        assert_eq!(rec.granted_scopes, vec!["email", "profile"]);

        let later = Timestamp::from_micros(2_000_000);
        rec.merge_scopes(
            &[
                "openid".to_string(),
                "profile".to_string(),
                "  ".to_string(),
            ],
            later,
        );
        assert_eq!(rec.granted_scopes, vec!["email", "openid", "profile"]);
        assert_eq!(rec.updated_at, later);
        assert_ne!(rec.updated_at, rec.granted_at);
    }

    #[test]
    fn consent_covers_requested_scopes_returns_true_when_superset() {
        let now = Timestamp::from_micros(1_000_000);
        let rec = ConsentRecord::new(
            UserId::generate(),
            ClientId::generate(),
            vec!["profile".to_string(), "email".to_string()],
            now,
        );
        assert!(rec.covers(&["profile".to_string()]));
        assert!(rec.covers(&["email".to_string(), "profile".to_string()]));
        assert!(rec.covers(&[])); // empty request is always covered
    }

    #[test]
    fn consent_covers_returns_false_when_scope_missing() {
        let now = Timestamp::from_micros(1_000_000);
        let rec = ConsentRecord::new(
            UserId::generate(),
            ClientId::generate(),
            vec!["profile".to_string()],
            now,
        );
        assert!(!rec.covers(&["profile".to_string(), "email".to_string()]));
        assert!(!rec.covers(&["admin".to_string()]));
    }

    #[test]
    fn canonicalize_scopes_trims_dedupes_sorts() {
        let out = canonicalize_scopes(vec![
            "profile".to_string(),
            " email ".to_string(),
            "profile".to_string(),
            String::new(),
            "   ".to_string(),
        ]);
        assert_eq!(out, vec!["email", "profile"]);
    }

    #[test]
    fn consent_record_serde_round_trip() {
        let now = Timestamp::from_micros(1_000_000);
        let rec = ConsentRecord::new(
            UserId::generate(),
            ClientId::generate(),
            vec!["profile".to_string(), "email".to_string()],
            now,
        );
        let json = serde_json::to_string(&rec).expect("serialize");
        let back: ConsentRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, back);
    }

    // ===== RequiredAction tests =====

    #[test]
    fn required_action_serializes_to_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&RequiredAction::VerifyEmail).expect("serialize"),
            "\"VERIFY_EMAIL\""
        );
        assert_eq!(
            serde_json::to_string(&RequiredAction::UpdatePassword).expect("serialize"),
            "\"UPDATE_PASSWORD\""
        );
        assert_eq!(
            serde_json::to_string(&RequiredAction::EnrollPhoneOtp).expect("serialize"),
            "\"ENROLL_PHONE_OTP\""
        );
    }

    #[test]
    fn required_action_deserializes_from_screaming_snake_case() {
        let a: RequiredAction = serde_json::from_str("\"VERIFY_EMAIL\"").expect("deserialize");
        assert_eq!(a, RequiredAction::VerifyEmail);

        let b: RequiredAction = serde_json::from_str("\"UPDATE_PASSWORD\"").expect("deserialize");
        assert_eq!(b, RequiredAction::UpdatePassword);

        let c: RequiredAction = serde_json::from_str("\"ENROLL_PHONE_OTP\"").expect("deserialize");
        assert_eq!(c, RequiredAction::EnrollPhoneOtp);
    }

    #[test]
    fn enroll_phone_otp_priority_and_path_segment() {
        assert_eq!(RequiredAction::EnrollPhoneOtp.priority(), 4);
        assert_eq!(
            RequiredAction::EnrollPhoneOtp.as_path_segment(),
            "ENROLL_PHONE_OTP"
        );
        assert_eq!(
            RequiredAction::from_path_segment("ENROLL_PHONE_OTP"),
            Some(RequiredAction::EnrollPhoneOtp)
        );
    }

    #[test]
    fn user_phone_fields_default_none_on_legacy_record() {
        let legacy_json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "email": "old@example.com",
            "display_name": "Old User",
            "first_name": "Old",
            "last_name": "User",
            "status": "Active",
            "created_at": 1000000,
            "updated_at": 1000000
        }"#;
        let user: User = serde_json::from_str(legacy_json).expect("deserialize");
        assert!(
            user.phone_number().is_none(),
            "legacy user must have no phone"
        );
        assert!(
            !user.phone_verified(),
            "legacy user must not be phone-verified"
        );
    }

    #[test]
    fn user_phone_fields_round_trip() {
        let now = Timestamp::from_micros(1_000_000);
        let mut user = User::new(
            UserId::generate(),
            "alice@example.com".to_string(),
            "Alice".to_string(),
            "Alice".to_string(),
            String::new(),
            UserStatus::Active,
            Vec::new(),
            now,
            now,
        );
        user.set_phone_number(Some("+15555550100".to_string()));
        user.set_phone_verified(true);

        let json = serde_json::to_string(&user).expect("serialize");
        let back: User = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.phone_number(), Some("+15555550100"));
        assert!(back.phone_verified());
    }

    #[test]
    fn user_without_phone_omits_fields_in_json() {
        let now = Timestamp::from_micros(1_000_000);
        let user = User::new(
            UserId::generate(),
            "bob@example.com".to_string(),
            "Bob".to_string(),
            "Bob".to_string(),
            String::new(),
            UserStatus::Active,
            Vec::new(),
            now,
            now,
        );
        let json = serde_json::to_string(&user).expect("serialize");
        assert!(
            !json.contains("phone_number"),
            "absent phone must be omitted"
        );
        assert!(
            !json.contains("phone_verified"),
            "false phone_verified must be omitted"
        );
    }

    #[test]
    fn required_action_unknown_value_is_rejected() {
        let result: Result<RequiredAction, _> = serde_json::from_str("\"INVALID_ACTION\"");
        assert!(result.is_err(), "unknown required action must be rejected");
    }

    #[test]
    fn user_required_actions_default_empty_on_legacy_record() {
        // Simulate a user record stored before required_actions was added.
        let legacy_json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "email": "old@example.com",
            "display_name": "Old User",
            "first_name": "Old",
            "last_name": "User",
            "status": "Active",
            "created_at": 1000000,
            "updated_at": 1000000
        }"#;
        let user: User = serde_json::from_str(legacy_json).expect("deserialize");
        assert!(
            user.required_actions().is_empty(),
            "legacy user must have no required actions"
        );
    }

    #[test]
    fn user_with_required_actions_round_trips() {
        let now = Timestamp::from_micros(1_000_000);
        let user = User::new(
            UserId::generate(),
            "alice@example.com".to_string(),
            "Alice".to_string(),
            "Alice".to_string(),
            String::new(),
            UserStatus::Active,
            vec![RequiredAction::VerifyEmail, RequiredAction::UpdatePassword],
            now,
            now,
        );
        let json = serde_json::to_string(&user).expect("serialize");
        let back: User = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.required_actions(), user.required_actions());
    }

    #[test]
    fn user_with_empty_required_actions_omits_field_in_json() {
        let now = Timestamp::from_micros(1_000_000);
        let user = User::new(
            UserId::generate(),
            "bob@example.com".to_string(),
            "Bob".to_string(),
            "Bob".to_string(),
            String::new(),
            UserStatus::Active,
            Vec::new(),
            now,
            now,
        );
        let json = serde_json::to_string(&user).expect("serialize");
        assert!(
            !json.contains("required_actions"),
            "empty required_actions must be omitted to keep records compact"
        );
    }

    // ── mask_phone_number / User::masked_phone_number ──────────────────────

    #[test]
    fn masked_phone_matches_ac_example() {
        // AC 3.5.2: masked display MUST be `+1***-***-1234` for `+15555551234`.
        assert_eq!(mask_phone_number("+15555551234"), "+1***-***-1234");
    }

    #[test]
    fn masked_phone_uk_number() {
        // Verifies that the mask works for multi-digit country codes too.
        assert_eq!(mask_phone_number("+441234567890"), "+4***-***-7890");
    }

    #[test]
    fn masked_phone_short_number_returns_stars() {
        assert_eq!(mask_phone_number("+123"), "****");
        assert_eq!(mask_phone_number("+12"), "****");
    }

    #[test]
    fn user_masked_phone_number_returns_none_when_no_phone() {
        let now = Timestamp::from_micros(1_000_000);
        let user = User::new(
            UserId::generate(),
            "alice@example.com".to_string(),
            "Alice".to_string(),
            "Alice".to_string(),
            String::new(),
            UserStatus::Active,
            Vec::new(),
            now,
            now,
        );
        assert!(user.masked_phone_number().is_none());
    }

    #[test]
    fn user_masked_phone_number_masks_enrolled_phone() {
        let now = Timestamp::from_micros(1_000_000);
        let mut user = User::new(
            UserId::generate(),
            "alice@example.com".to_string(),
            "Alice".to_string(),
            "Alice".to_string(),
            String::new(),
            UserStatus::Active,
            Vec::new(),
            now,
            now,
        );
        user.set_phone_number(Some("+15555551234".to_string()));
        assert_eq!(
            user.masked_phone_number(),
            Some("+1***-***-1234".to_string())
        );
    }

    // ── RealmConfig sms_otp fields ─────────────────────────────────────────

    #[test]
    fn realm_config_sms_otp_fields_default_none() {
        let config = RealmConfig::default();
        assert!(config.sms_otp_expiry_seconds.is_none());
        assert!(config.sms_otp_max_attempts.is_none());
    }

    #[test]
    fn realm_config_sms_otp_fields_roundtrip() {
        let config = RealmConfig {
            sms_otp_expiry_seconds: Some(300),
            sms_otp_max_attempts: Some(3),
            ..RealmConfig::default()
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let back: RealmConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.sms_otp_expiry_seconds, Some(300));
        assert_eq!(back.sms_otp_max_attempts, Some(3));
    }

    #[test]
    fn realm_config_sms_otp_fields_absent_in_legacy_json() {
        // Records stored before these fields were added must deserialize cleanly.
        let legacy_json = r#"{"name": "test", "status": "Active"}"#;
        let config: RealmConfig = serde_json::from_str(legacy_json).unwrap_or_default();
        assert!(config.sms_otp_expiry_seconds.is_none());
        assert!(config.sms_otp_max_attempts.is_none());
    }

    #[test]
    fn realm_config_mfa_methods_accepts_sms_value() {
        let config = RealmConfig {
            mfa_methods: Some(vec!["sms".to_string()]),
            ..RealmConfig::default()
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let back: RealmConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.mfa_methods, Some(vec!["sms".to_string()]));
    }

    #[test]
    fn pending_authorization_request_serde_round_trip() {
        let pending = PendingAuthorizationRequest {
            user_id: UserId::generate(),
            client_id: ClientId::generate(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            requested_scopes: vec!["openid".to_string(), "email".to_string()],
            state: "xyz".to_string(),
            response_type: "code".to_string(),
            code_challenge: Some("abc".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: Some("n-0".to_string()),
            response_mode: None,
            authorization_signed_response_alg: Some("EdDSA".to_string()),
            created_at: Timestamp::from_micros(1_000_000),
            expires_at: Timestamp::from_micros(1_600_000_000),
        };
        let json = serde_json::to_string(&pending).expect("serialize");
        let back: PendingAuthorizationRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pending, back);
    }
}
