//! Request and response types for the Hearth REST API.

use serde::{Deserialize, Serialize};

/// Controls how access-token authorization data is delivered to resource servers.
///
/// Mirrors the server-side `access_token_authorization` field on `OAuthClient`.
/// SDK middleware and [`crate::HearthClient::check_permission`] take an explicit
/// mode — absence of `permissions` in the JWT is **never** used to infer mode
/// (HEA-921 design constraint).
///
/// Serializes as `snake_case` (`embedded`, …). Deserialization also accepts the
/// proto enum names (`EMBEDDED`, …), which is what every client route answers
/// with inside an `OAuthClient`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenAuthorization {
    /// Permissions, roles, and groups are embedded in the JWT at issuance (default).
    #[default]
    #[serde(alias = "EMBEDDED")]
    Embedded,
    /// JWT carries only identity claims; resource servers call `/introspect` for live data.
    #[serde(alias = "INTROSPECTION")]
    Introspection,
    /// JWT carries only identity claims; resource servers call `POST /oauth/authorize` per request.
    #[serde(alias = "DECISION")]
    Decision,
}

impl AccessTokenAuthorization {
    /// The proto `AccessTokenAuthorization` enum name (`EMBEDDED`, …).
    fn proto_name(self) -> &'static str {
        match self {
            Self::Embedded => "EMBEDDED",
            Self::Introspection => "INTROSPECTION",
            Self::Decision => "DECISION",
        }
    }
}

/// Serde helpers for the proto `RegisterClientRequest` body shared by
/// `POST /clients` and `POST /admin/applications`.
///
/// That body is deserialized by the generated proto JSON codec, which takes
/// enums by their proto names only: `embedded` and `first_party` answer
/// `422 unknown variant`. `PATCH /admin/applications/{id}` is the opposite — it
/// reads `snake_case` strings — so only the create/register types use these.
mod proto_wire {
    use super::AccessTokenAuthorization;
    use serde::Serializer;

    /// Serialize an [`AccessTokenAuthorization`] as its proto enum name.
    #[allow(clippy::trivially_copy_pass_by_ref)] // serde's `serialize_with` signature
    pub(super) fn access_token_authorization<S: Serializer>(
        mode: &AccessTokenAuthorization,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(mode.proto_name())
    }

    /// Serialize a trust level, mapping `first_party` / `third_party` to the
    /// proto `ClientTrustLevel` names. Any other value is sent unchanged so
    /// the server rejects it instead of the SDK silently choosing a level.
    #[allow(clippy::ref_option)] // serde's `serialize_with` signature
    pub(super) fn trust_level<S: Serializer>(
        level: &Option<String>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match level.as_deref() {
            Some("first_party") => s.serialize_str("CLIENT_TRUST_LEVEL_FIRST_PARTY"),
            Some("third_party") => s.serialize_str("CLIENT_TRUST_LEVEL_THIRD_PARTY"),
            Some(other) => s.serialize_str(other),
            None => s.serialize_none(),
        }
    }
}

/// Response from `POST /introspect` (RFC 7662, extended by Hearth).
///
/// Do **not** cache this response — RFC 7662 §2.1 prohibits caching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    /// `true` if the token is active (not expired, not revoked, valid signature).
    pub active: bool,
    /// Subject (user ID) of the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Expiry timestamp (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Issued-at timestamp (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Issuer claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// JWT ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Token type hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// Access-token authorization mode echoed from the issuing client's configuration.
    ///
    /// Use this to validate that the token originates from a client configured for
    /// the expected mode. If absent, the server does not support mode-echo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<AccessTokenAuthorization>,
    /// Live permission strings (present for `Introspection` and `Decision` mode clients).
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Live role names (present for `Introspection` and `Decision` mode clients).
    #[serde(default)]
    pub roles: Vec<String>,
    /// Live group slugs (present for `Introspection` and `Decision` mode clients).
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Response from `POST /oauth/authorize` (Decision-mode per-request check).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCheckResponse {
    /// `true` if the token holder has the requested permission.
    pub allowed: bool,
}

/// Options for [`crate::HearthClient::check_permission`].
#[derive(Debug, Clone, Default)]
pub struct CheckPermissionOpts {
    /// Restrict the check to a specific organization.
    pub organization_id: Option<String>,
    /// Restrict the check to a specific resource URI (RFC 8707).
    pub resource: Option<String>,
    /// Required for `Introspection` mode: `(client_id, client_secret)` used for
    /// RFC 7662 §2.1 Basic Auth on the `/introspect` call.
    pub client_credentials: Option<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapResponse {
    pub admin_token: String,
    pub realm_id: String,
    pub user_id: String,
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageResponse<T> {
    pub items: Vec<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Realm {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// Realm mutation payload.
///
/// Retained for callers that model a realm patch locally; there is no client
/// method that sends it. Realms are provisioned from `hearth.yaml` and the
/// server answers 405 to `PATCH /admin/realms/{id}` (audit 2026-08-28 §25.4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateRealmRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    pub code: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    /// Absent for `client_credentials` grant responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MePermissionsResponse {
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
}

/// An OAuth client, as returned by `POST /clients` and every
/// `/admin/applications` route.
///
/// All of them answer with the proto `OAuthClient` shape, so the wire keys are
/// `client_id` / `client_name`; `id` / `name` are only this struct's field
/// names. Deserialization also accepts `id` / `name` so JSON this struct
/// serialized under earlier SDK versions still loads — no Hearth route sends
/// them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    #[serde(rename = "client_id", alias = "id")]
    pub id: String,
    #[serde(rename = "client_name", alias = "name")]
    pub name: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,
    /// The generated secret (wire key `client_secret`): present only on the
    /// response that created a `client_secret_basic` / `client_secret_post`
    /// client or regenerated its secret, never again. Store it on receipt.
    #[serde(
        default,
        rename = "client_secret",
        alias = "secret",
        skip_serializing_if = "Option::is_none"
    )]
    pub secret: Option<String>,
    /// How access-token authorization data is delivered for tokens issued by this client.
    #[serde(default)]
    pub access_token_authorization: AccessTokenAuthorization,
}

/// Body of `POST /clients` (the proto `RegisterClientRequest`).
///
/// `name` is sent on the wire as `client_name` — the server rejects an
/// unknown `name` key with `422` — and `trust_level` (`first_party` /
/// `third_party`) as the proto `ClientTrustLevel` name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterClientRequest {
    #[serde(rename = "client_name", alias = "name")]
    pub name: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "proto_wire::trust_level"
    )]
    pub trust_level: Option<String>,
    /// RFC 7591 §2: `client_secret_basic` / `client_secret_post` make the
    /// server generate the secret and return it once
    /// ([`OAuthClient::secret`]); `private_key_jwt` or `none`. `None`
    /// registers a public client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<Jwk>,
}

// ── §12 Admin SDK types ──────────────────────────────────────────────────────

/// A realm-level role definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateRoleRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
}

/// A realm-level group definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateGroupRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Body of `POST /admin/applications` (the proto `RegisterClientRequest`).
///
/// Same wire shape as [`RegisterClientRequest`]: `name` is sent as
/// `client_name`, and `trust_level` / `access_token_authorization` as their
/// proto enum names (`CLIENT_TRUST_LEVEL_FIRST_PARTY`, `EMBEDDED`, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateClientRequest {
    #[serde(rename = "client_name", alias = "name")]
    pub name: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "proto_wire::trust_level"
    )]
    pub trust_level: Option<String>,
    #[serde(default, serialize_with = "proto_wire::access_token_authorization")]
    pub access_token_authorization: AccessTokenAuthorization,
    /// RFC 7591 §2: `client_secret_basic` / `client_secret_post` make the
    /// server generate the secret and return it once
    /// ([`OAuthClient::secret`]); `private_key_jwt` or `none`. `None`
    /// registers a public client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
}

/// Body of `PATCH /admin/applications/{id}`.
///
/// `name` is sent as `client_name`. The route ignores unknown keys, so a
/// `name` key would answer `200` and rename nothing. Unlike the create body,
/// this route reads `trust_level` and `access_token_authorization` as
/// `snake_case` strings (`first_party`, `introspection`, …).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateClientRequest {
    #[serde(
        default,
        rename = "client_name",
        alias = "name",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token_authorization: Option<AccessTokenAuthorization>,
}

// OrgMember, AddOrgMemberRequest and UpdateOrgMemberRequest were removed with
// the org-membership methods: Hearth serves no organization route over HTTP
// (audit 2026-08-28 §25.19).

/// Result of [`crate::HearthClient::begin_login`].
///
/// Redirect the browser to `authorization_url`, then persist `state` and
/// `code_verifier` in session storage so they can be verified and supplied to
/// [`crate::HearthClient::complete_login`] on the callback route.
#[derive(Debug, Clone)]
pub struct LoginBeginResult {
    /// Full PKCE authorization URL — redirect the browser here.
    pub authorization_url: String,
    /// Random CSRF-protection value — persist and verify against the callback `state` param.
    pub state: String,
    /// PKCE code verifier — persist and pass to `complete_login`.
    pub code_verifier: String,
}

// ── §4.5.2 Device Authorization Flow (RFC 8628) ──────────────────────────────

/// Response from the device authorization endpoint (RFC 8628 §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationResponse {
    /// Opaque device code; pass to `poll_device_token`.
    pub device_code: String,
    /// Short code displayed to the user (e.g., `"WDJB-MJHT"`).
    pub user_code: String,
    /// URL the user visits to authorize the device.
    pub verification_uri: String,
    /// `verification_uri` with `user_code` pre-filled (server-optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    /// Seconds until the device code expires.
    pub expires_in: i64,
    /// Minimum polling interval in seconds (default 5 per RFC 8628 §3.5).
    pub interval: i64,
}

// ── Session-version polling ───────────────────────────────────────────────────

/// A single entry in a session-version delta or snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SvDeltaEntry {
    /// The session ID this entry describes.
    pub session_id: String,
    /// Monotonically increasing version counter for this session.
    pub version: i64,
    /// Event type: `"created"`, `"refreshed"`, or `"revoked"`.
    pub event: String,
    /// ISO-8601 timestamp of the event, if provided by the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

/// Response from `GET /v1/session-version/delta`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SvDeltaResponse {
    pub entries: Vec<SvDeltaEntry>,
    /// Opaque cursor for the next delta poll.
    pub cursor: String,
    #[serde(default)]
    pub has_more: bool,
}

/// Response from `GET /v1/session-version/snapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SvSnapshotResponse {
    pub sessions: Vec<SvDeltaEntry>,
    /// Opaque cursor to use for subsequent delta polls.
    pub cursor: String,
}

/// An assertion from an already-enrolled passkey, offered as a step-up proof.
///
/// Every field is base64url without padding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepUpAssertion {
    /// Credential ID the assertion was produced with.
    pub credential_id: String,
    /// `clientDataJSON` from the authenticator.
    pub client_data_json: String,
    /// Authenticator data bytes.
    pub authenticator_data: String,
    /// Signature bytes.
    pub signature: String,
    /// User handle, for discoverable credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

/// Proof that the caller holds a credential the account already has.
///
/// Passkey enrolment refuses a request that carries no proof: an access token
/// alone is one factor, and enrolling with it would turn a stolen token into a
/// permanent credential.
#[derive(Debug, Clone)]
pub enum StepUpProof {
    /// The account's current password.
    Password(String),
    /// A current code from the account's enrolled authenticator.
    TotpCode(String),
    /// An assertion from an already-enrolled passkey.
    Assertion(Box<StepUpAssertion>),
}

impl StepUpProof {
    /// Writes the proof's field into a JSON request body.
    ///
    /// # Panics
    ///
    /// Panics if `body` is not a JSON object.
    pub fn merge_into(&self, body: &mut serde_json::Value) {
        let object = body
            .as_object_mut()
            .expect("step-up proof merges into a JSON object");
        match self {
            Self::Password(password) => {
                object.insert("password".to_string(), serde_json::json!(password));
            }
            Self::TotpCode(code) => {
                object.insert("totp_code".to_string(), serde_json::json!(code));
            }
            Self::Assertion(assertion) => {
                object.insert(
                    "assertion".to_string(),
                    serde_json::to_value(assertion.as_ref()).unwrap_or(serde_json::Value::Null),
                );
            }
        }
    }
}
