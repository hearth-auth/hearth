//! Identity domain types: users, requests, and status.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::{Timestamp, UserId};
use crate::identity::credentials::CleartextPassword;

// Re-export the canonical cursor-based page type from core so that
// identity and rbac share a single definition.
pub use crate::core::Page;

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

/// Where an email-verification link is completed, as far as the federated
/// links of a `PendingVerification` account are concerned (GA audit round 3,
/// G-3).
///
/// A federated just-in-time account on an address the upstream did not
/// verify waits for the address owner. The mail that asks them to verify is
/// unsolicited when someone else's upstream identity named their address, so
/// the link that created the account survives verification only when the
/// same browser that performed the federated login completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationOrigin {
    /// The browser that performed the federated login which created the
    /// account (it holds the binding that login set): the account's
    /// federated links are kept.
    FederatedLoginBrowser,
    /// Any other browser or caller: a `PendingVerification` account is
    /// activated WITHOUT its federated links, and each removal is audited.
    Elsewhere,
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
    /// User must enroll email OTP (6-digit code) as an MFA factor before proceeding.
    ///
    /// Injected automatically when a realm has `mfa_methods: ["email_otp"]` and the
    /// user has not yet enrolled email OTP.
    EnrollEmailOtp,
}

impl RequiredAction {
    /// Canonical execution priority. Lower numbers run first.
    ///
    /// `VERIFY_EMAIL=1`, `UPDATE_PASSWORD=2`, `ENROLL_MFA=3`, `ENROLL_EMAIL_OTP=5`.
    /// (4 was `ENROLL_PHONE_OTP`, removed in 3.0.0 with SMS one-time codes.)
    #[must_use]
    pub fn priority(self) -> u8 {
        match self {
            Self::VerifyEmail => 1,
            Self::UpdatePassword => 2,
            Self::EnrollMfa => 3,
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
            Self::EnrollEmailOtp => "ENROLL_EMAIL_OTP",
        }
    }

    /// Parse from a URL path segment (case-sensitive).
    pub fn from_path_segment(s: &str) -> Option<Self> {
        match s {
            "VERIFY_EMAIL" => Some(Self::VerifyEmail),
            "UPDATE_PASSWORD" => Some(Self::UpdatePassword),
            "enroll-mfa" => Some(Self::EnrollMfa),
            "ENROLL_EMAIL_OTP" => Some(Self::EnrollEmailOtp),
            _ => None,
        }
    }
}

/// Wire form of [`RequiredAction`] in stored and exported user records.
///
/// Postcard writes an enum by variant position and the JSON export by name,
/// so a removed action keeps its slot here: never reorder these variants.
/// A retired action decodes, and [`Self::into_current`] drops it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum StoredRequiredAction {
    /// [`RequiredAction::VerifyEmail`].
    VerifyEmail,
    /// [`RequiredAction::UpdatePassword`].
    UpdatePassword,
    /// [`RequiredAction::EnrollMfa`].
    EnrollMfa,
    /// `ENROLL_PHONE_OTP`, retired in 3.0.0 with SMS one-time codes.
    #[serde(rename = "ENROLL_PHONE_OTP")]
    RetiredEnrollPhoneOtp,
    /// [`RequiredAction::EnrollEmailOtp`].
    EnrollEmailOtp,
}

impl StoredRequiredAction {
    /// The current action, or `None` for a retired one.
    pub(crate) fn into_current(self) -> Option<RequiredAction> {
        match self {
            Self::VerifyEmail => Some(RequiredAction::VerifyEmail),
            Self::UpdatePassword => Some(RequiredAction::UpdatePassword),
            Self::EnrollMfa => Some(RequiredAction::EnrollMfa),
            Self::RetiredEnrollPhoneOtp => None,
            Self::EnrollEmailOtp => Some(RequiredAction::EnrollEmailOtp),
        }
    }
}

impl From<RequiredAction> for StoredRequiredAction {
    fn from(a: RequiredAction) -> Self {
        match a {
            RequiredAction::VerifyEmail => Self::VerifyEmail,
            RequiredAction::UpdatePassword => Self::UpdatePassword,
            RequiredAction::EnrollMfa => Self::EnrollMfa,
            RequiredAction::EnrollEmailOtp => Self::EnrollEmailOtp,
        }
    }
}

/// Deserializes a required-action list and drops retired actions, so a user
/// exported before 3.0.0 with `ENROLL_PHONE_OTP` still imports.
fn deserialize_current_actions<'de, D>(deserializer: D) -> Result<Vec<RequiredAction>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let stored = Vec::<StoredRequiredAction>::deserialize(deserializer)?;
    Ok(stored
        .into_iter()
        .filter_map(StoredRequiredAction::into_current)
        .collect())
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
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_current_actions"
    )]
    required_actions: Vec<RequiredAction>,
    /// Whether the user's email address has been verified. Absent in old records = false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    email_verified: bool,
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

    /// Converts to a flat storage record for binary (postcard) encoding.
    ///
    /// Unlike [`User`]'s serde impl, [`UserStorageRecord`] has no
    /// `skip_serializing_if` attributes so postcard can write every field
    /// positionally without misalignment.
    pub(crate) fn to_storage_record(&self) -> UserStorageRecord {
        UserStorageRecord {
            id: self.id.clone(),
            email: self.email.clone(),
            display_name: self.display_name.clone(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            attributes: self.attributes.clone(),
            status: self.status,
            required_actions: self
                .required_actions
                .iter()
                .copied()
                .map(StoredRequiredAction::from)
                .collect(),
            email_verified: self.email_verified,
            retired_phone_number: None,
            retired_phone_verified: false,
            email_otp_enabled: self.email_otp_enabled,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    /// Reconstructs a [`User`] from a [`UserStorageRecord`] decoded by postcard.
    pub(crate) fn from_storage_record(r: UserStorageRecord) -> Self {
        Self {
            id: r.id,
            email: r.email,
            display_name: r.display_name,
            first_name: r.first_name,
            last_name: r.last_name,
            attributes: r.attributes,
            status: r.status,
            required_actions: r
                .required_actions
                .into_iter()
                .filter_map(StoredRequiredAction::into_current)
                .collect(),
            email_verified: r.email_verified,
            email_otp_enabled: r.email_otp_enabled,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// Binary-storage mirror of [`User`] without `skip_serializing_if` attributes.
///
/// All fields are always written so that `postcard` can encode/decode the
/// struct positionally. Never exposes this type outside the storage layer.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct UserStorageRecord {
    pub(crate) id: UserId,
    pub(crate) email: String,
    pub(crate) display_name: String,
    pub(crate) first_name: String,
    pub(crate) last_name: String,
    pub(crate) attributes: BTreeMap<String, String>,
    pub(crate) status: UserStatus,
    pub(crate) required_actions: Vec<StoredRequiredAction>,
    pub(crate) email_verified: bool,
    /// Retired in 3.0.0 with SMS one-time codes: written `None`, ignored on
    /// read. The slot stays because postcard is positional.
    pub(crate) retired_phone_number: Option<String>,
    /// Retired in 3.0.0 with SMS one-time codes: written `false`, ignored on
    /// read.
    pub(crate) retired_phone_verified: bool,
    pub(crate) email_otp_enabled: bool,
    pub(crate) created_at: Timestamp,
    pub(crate) updated_at: Timestamp,
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
    /// Set the email OTP enrolled flag. `None` leaves unchanged.
    pub email_otp_enabled: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Timestamp;
    use proptest::prelude::*;
    use uuid::Uuid;

    fn arb_uuid() -> impl Strategy<Value = Uuid> {
        any::<[u8; 16]>().prop_map(Uuid::from_bytes)
    }

    fn arb_timestamp() -> impl Strategy<Value = Timestamp> {
        any::<i64>().prop_map(Timestamp::from_micros)
    }

    fn arb_user_status() -> impl Strategy<Value = UserStatus> {
        prop_oneof![
            Just(UserStatus::Active),
            Just(UserStatus::Disabled),
            Just(UserStatus::PendingVerification),
        ]
    }

    fn arb_required_action() -> impl Strategy<Value = StoredRequiredAction> {
        prop_oneof![
            Just(StoredRequiredAction::VerifyEmail),
            Just(StoredRequiredAction::UpdatePassword),
            Just(StoredRequiredAction::EnrollMfa),
            Just(StoredRequiredAction::RetiredEnrollPhoneOtp),
            Just(StoredRequiredAction::EnrollEmailOtp),
        ]
    }

    // Split into two nested tuples to stay within proptest's 12-tuple limit.
    fn arb_user_storage_record() -> impl Strategy<Value = UserStorageRecord> {
        (
            (
                arb_uuid(),
                ".*",
                ".*",
                ".*",
                ".*",
                proptest::collection::btree_map(".*", ".*", 0..4),
                arb_user_status(),
            ),
            (
                proptest::collection::vec(arb_required_action(), 0..3),
                any::<bool>(),
                proptest::option::of(".*"),
                any::<bool>(),
                any::<bool>(),
                arb_timestamp(),
                arb_timestamp(),
            ),
        )
            .prop_map(
                |(
                    (uuid, email, display_name, first_name, last_name, attributes, status),
                    (
                        required_actions,
                        email_verified,
                        retired_phone_number,
                        retired_phone_verified,
                        email_otp_enabled,
                        created_at,
                        updated_at,
                    ),
                )| UserStorageRecord {
                    id: UserId::new(uuid),
                    email,
                    display_name,
                    first_name,
                    last_name,
                    attributes,
                    status,
                    required_actions,
                    email_verified,
                    retired_phone_number,
                    retired_phone_verified,
                    email_otp_enabled,
                    created_at,
                    updated_at,
                },
            )
    }

    proptest! {
        /// Property: `UserStorageRecord` survives a postcard encode→decode round-trip.
        #[test]
        fn user_storage_record_roundtrip(rec in arb_user_storage_record()) {
            let bytes = crate::codec::encode(&rec).expect("encode");
            let decoded: UserStorageRecord = crate::codec::decode(&bytes).expect("decode");
            prop_assert_eq!(rec, decoded);
        }
    }

    /// Postcard writes enum variants by position. The retired SMS action keeps
    /// slot 3, so a stored `ENROLL_EMAIL_OTP` still reads as itself.
    #[test]
    fn stored_action_positions_are_pinned() {
        let pos = |a: StoredRequiredAction| crate::codec::encode(&a).expect("encode");
        assert_eq!(pos(StoredRequiredAction::VerifyEmail), vec![0]);
        assert_eq!(pos(StoredRequiredAction::UpdatePassword), vec![1]);
        assert_eq!(pos(StoredRequiredAction::EnrollMfa), vec![2]);
        assert_eq!(pos(StoredRequiredAction::RetiredEnrollPhoneOtp), vec![3]);
        assert_eq!(pos(StoredRequiredAction::EnrollEmailOtp), vec![4]);
    }

    /// A user stored before 3.0.0 with a phone and a pending
    /// `ENROLL_PHONE_OTP` still decodes; the retired data is dropped.
    #[test]
    fn a_pre_3_0_record_with_sms_data_decodes_without_it() {
        let ts = Timestamp::from_micros(1_000);
        let record = UserStorageRecord {
            id: UserId::new(uuid::Uuid::new_v4()),
            email: "old@example.com".to_string(),
            display_name: "Old".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: BTreeMap::new(),
            status: UserStatus::Active,
            required_actions: vec![
                StoredRequiredAction::RetiredEnrollPhoneOtp,
                StoredRequiredAction::EnrollEmailOtp,
            ],
            email_verified: true,
            retired_phone_number: Some("+15555550100".to_string()),
            retired_phone_verified: true,
            email_otp_enabled: false,
            created_at: ts,
            updated_at: ts,
        };
        let bytes = crate::codec::encode(&record).expect("encode");
        let decoded: UserStorageRecord = crate::codec::decode(&bytes).expect("decode");
        let user = User::from_storage_record(decoded);
        assert_eq!(user.required_actions(), &[RequiredAction::EnrollEmailOtp]);

        let rewritten = user.to_storage_record();
        assert_eq!(rewritten.retired_phone_number, None, "never written again");
        assert!(!rewritten.retired_phone_verified);
        assert_eq!(
            rewritten.required_actions,
            vec![StoredRequiredAction::EnrollEmailOtp]
        );
    }

    /// The JSON form (backup export) drops the retired action by name.
    #[test]
    fn json_with_enroll_phone_otp_imports_without_it() {
        let user = User::new(
            UserId::new(uuid::Uuid::new_v4()),
            "j@example.com".to_string(),
            "J".to_string(),
            String::new(),
            String::new(),
            UserStatus::Active,
            vec![RequiredAction::VerifyEmail],
            Timestamp::from_micros(1),
            Timestamp::from_micros(1),
        );
        let mut json = serde_json::to_value(&user).expect("to json");
        json["required_actions"] = serde_json::json!(["ENROLL_PHONE_OTP", "VERIFY_EMAIL"]);
        json["phone_number"] = serde_json::json!("+15555550100");
        json["phone_verified"] = serde_json::json!(true);
        let back: User = serde_json::from_value(json).expect("old export must import");
        assert_eq!(back.required_actions(), &[RequiredAction::VerifyEmail]);
    }
}
