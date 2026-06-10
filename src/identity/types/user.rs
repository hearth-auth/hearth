//! Identity domain types: users, requests, and status.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::{Timestamp, UserId};
use crate::identity::credentials::CleartextPassword;

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
    /// User must enroll email OTP (6-digit code) as an MFA factor before proceeding.
    ///
    /// Injected automatically when a realm has `mfa_methods: ["email_otp"]` and the
    /// user has not yet enrolled email OTP.
    EnrollEmailOtp,
}

impl RequiredAction {
    /// Canonical execution priority. Lower numbers run first.
    ///
    /// `VERIFY_EMAIL=1`, `UPDATE_PASSWORD=2`, `ENROLL_MFA=3`, `ENROLL_PHONE_OTP=4`,
    /// `ENROLL_EMAIL_OTP=5`.
    #[must_use]
    pub fn priority(self) -> u8 {
        match self {
            Self::VerifyEmail => 1,
            Self::UpdatePassword => 2,
            Self::EnrollMfa => 3,
            Self::EnrollPhoneOtp => 4,
            Self::EnrollEmailOtp => 5,
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
            Self::EnrollEmailOtp => "ENROLL_EMAIL_OTP",
        }
    }

    /// Parse from a URL path segment (case-sensitive).
    pub fn from_path_segment(s: &str) -> Option<Self> {
        match s {
            "VERIFY_EMAIL" => Some(Self::VerifyEmail),
            "UPDATE_PASSWORD" => Some(Self::UpdatePassword),
            "enroll-mfa" => Some(Self::EnrollMfa),
            "ENROLL_PHONE_OTP" => Some(Self::EnrollPhoneOtp),
            "ENROLL_EMAIL_OTP" => Some(Self::EnrollEmailOtp),
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
    /// Whether the user has enrolled email OTP as an MFA factor.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    email_otp_enabled: bool,
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
            email_otp_enabled: false,
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

    /// Returns whether the user has email OTP enrolled as an MFA factor.
    pub fn email_otp_enabled(&self) -> bool {
        self.email_otp_enabled
    }

    /// Sets the email OTP enabled flag. Used internally by the identity engine.
    pub(crate) fn set_email_otp_enabled(&mut self, enabled: bool) {
        self.email_otp_enabled = enabled;
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
pub(super) fn mask_phone_number(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    if chars.len() < 6 {
        return "****".to_string();
    }
    let prefix: String = chars[..2].iter().collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    format!("{prefix}***-***-{suffix}")
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
    /// Set the email OTP enrolled flag. `None` leaves unchanged.
    pub email_otp_enabled: Option<bool>,
}
