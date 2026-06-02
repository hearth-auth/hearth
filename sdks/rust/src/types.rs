//! Request and response types for the Hearth REST API.

use serde::{Deserialize, Serialize};

/// Controls how access-token authorization data is delivered to resource servers.
///
/// Mirrors the server-side `access_token_authorization` field on `OAuthClient`.
/// SDK middleware and [`crate::HearthClient::check_permission`] take an explicit
/// mode — absence of `permissions` in the JWT is **never** used to infer mode
/// (HEA-921 design constraint).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenAuthorization {
    /// Permissions, roles, and groups are embedded in the JWT at issuance (default).
    #[default]
    Embedded,
    /// JWT carries only identity claims; resource servers call `/introspect` for live data.
    Introspection,
    /// JWT carries only identity claims; resource servers call `POST /oauth/authorize` per request.
    Decision,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRealmRequest {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
}

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
    pub refresh_token: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// How access-token authorization data is delivered for tokens issued by this client.
    #[serde(default)]
    pub access_token_authorization: AccessTokenAuthorization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterClientRequest {
    pub name: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,
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

/// A create/update request for an OAuth client via admin API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,
    #[serde(default)]
    pub access_token_authorization: AccessTokenAuthorization,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateClientRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token_authorization: Option<AccessTokenAuthorization>,
}

/// A member of an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMember {
    pub user_id: String,
    pub org_id: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddOrgMemberRequest {
    pub user_id: String,
    #[serde(default)]
    pub role: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateOrgMemberRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}
