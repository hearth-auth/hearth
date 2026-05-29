//! OIDC domain logic: OAuth 2.0 Authorization Code Flow with PKCE.
//!
//! Contains client registration, authorization code issuance/exchange,
//! PKCE validation, and OIDC Discovery document construction.
//!
//! This is domain logic — no HTTP or wire format dependencies. The protocol
//! layer will be a thin adapter that translates HTTP requests into calls to
//! these types and `IdentityEngine` methods.

use serde::{Deserialize, Serialize};

use crate::core::{ClientId, RealmId, Timestamp};

/// Client trust posture used by authz and consent evaluation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientTrustLevel {
    #[default]
    FirstParty,
    ThirdParty,
}

/// The lifecycle status of an OAuth 2.0 application client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ApplicationStatus {
    /// Client is active; all OAuth flows are permitted.
    #[default]
    Active,
    /// Client was removed from YAML config and soft-deleted.
    ///
    /// New OAuth flows are rejected. The client record is preserved so that
    /// existing sessions and tokens can be audited. Restored to `Active` if
    /// the application re-appears in YAML. Permanently deleted only when the
    /// admin chooses "Delete permanently" in the UI or via the API.
    Archived,
}

/// Configuration for OIDC / OAuth 2.0 operations.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Time-to-live for authorization codes, in seconds.
    ///
    /// Default: 10 minutes (600 seconds). RFC 6749 recommends a maximum
    /// lifetime of 10 minutes.
    pub authorization_code_ttl_secs: i64,

    /// The issuer URL used in discovery documents and ID tokens.
    ///
    /// Must match the `iss` claim in issued tokens.
    pub issuer: String,

    /// Whether to enforce nonce uniqueness in authorization requests.
    ///
    /// Enabled by default. When enabled, duplicate nonces in authorization
    /// requests are rejected to prevent replay attacks. Set to `false` only for
    /// legacy clients that cannot supply nonces; a startup warning is emitted.
    pub enforce_nonces: bool,

    /// Require PKCE for confidential clients (RFC 9700 §2.1.1).
    ///
    /// `true` (default) — all clients, including those with a `client_secret`,
    /// must supply `code_challenge`/`code_verifier`.  Set to `false` only for
    /// legacy clients that cannot be updated; document the exemption.
    pub require_pkce_for_confidential_clients: bool,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            authorization_code_ttl_secs: 600, // 10 minutes
            issuer: "https://hearth.local".to_string(),
            enforce_nonces: true,
            require_pkce_for_confidential_clients: true,
        }
    }
}

/// Request to register a new OAuth 2.0 client.
#[derive(Debug, Clone)]
pub struct RegisterClientRequest {
    /// Human-readable client name.
    pub client_name: String,
    /// Allowed redirect URIs (at least one required for public clients).
    pub redirect_uris: Vec<String>,
    /// Optional client secret for confidential clients.
    ///
    /// If provided, the secret is hashed with Argon2id and stored.
    /// The raw secret is returned once in the registration response
    /// and never stored. If `None`, this is a public client.
    pub client_secret: Option<String>,
    /// OAuth 2.0 grant types this client is allowed to use.
    ///
    /// Defaults to `["authorization_code"]` if not specified.
    pub grant_types: Vec<String>,
    /// Whether user consent is required before issuing authorization codes.
    ///
    /// Defaults to `true`. Set to `false` only for first-party / trusted
    /// clients where the user has an implicit trust relationship with the
    /// client (e.g. first-party SSO inside an enterprise realm).
    pub require_consent: bool,
    /// Optional URL to a client logo displayed on the consent screen.
    pub client_logo_url: Option<String>,
    /// Stable slug for managed clients; runtime registrations may omit it.
    pub slug: Option<String>,
    /// Authz trust posture for this client.
    pub trust_level: ClientTrustLevel,
    /// Scopes this client is allowed to request.
    pub declared_scopes: Vec<String>,
    /// Whether a realm-scoped consent can cover all org contexts.
    pub consent_spans_orgs: bool,
    /// Access-token authorization mode. Defaults to `Embedded`.
    pub access_token_authorization: AccessTokenAuthorization,
    /// Inline JWKS JSON for JAR (RFC 9101) signed request objects.
    ///
    /// When set, the client may pass `request=<JWT>` on `/authorize` or
    /// `/as/par`. Value must be a JSON string, e.g. `{"keys":[{...}]}`.
    pub jwks: Option<String>,
    /// JWKS URI for JAR signed request object verification (stored for future use).
    pub jwks_uri: Option<String>,
    /// JARM signing algorithm for authorization responses (OAuth 2.0 JARM §4).
    ///
    /// When set, JARM is mandatory for this client. Supported values: `"EdDSA"`.
    pub authorization_signed_response_alg: Option<String>,
}

impl Default for RegisterClientRequest {
    fn default() -> Self {
        Self {
            client_name: String::new(),
            redirect_uris: Vec::new(),
            client_secret: None,
            grant_types: Vec::new(),
            require_consent: true,
            client_logo_url: None,
            slug: None,
            // Per AUTHZ_EXPANSION.md: DCR-registered clients default to
            // ThirdParty trust. Managed (YAML) clients should set trust_level
            // explicitly. Choosing ThirdParty here preserves the existing
            // "consent always required" behavior for any caller that doesn't
            // override the field.
            trust_level: ClientTrustLevel::ThirdParty,
            declared_scopes: Vec::new(),
            consent_spans_orgs: false,
            access_token_authorization: AccessTokenAuthorization::Embedded,
            jwks: None,
            jwks_uri: None,
            authorization_signed_response_alg: None,
        }
    }
}

/// Controls how access-token authorization data is exposed to resource servers.
///
/// Defaults to `Embedded` for backward compatibility with existing clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenAuthorization {
    /// Permissions, roles, and groups are embedded in the JWT at issuance (default).
    #[default]
    Embedded,
    /// JWT carries only identity claims; resource servers call `/introspect` for live data.
    Introspection,
    /// JWT carries only identity claims; resource servers call `POST /oauth/authorize` per-request.
    Decision,
}

/// A registered OAuth 2.0 client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthClient {
    /// Unique client identifier.
    client_id: ClientId,
    /// Human-readable client name.
    client_name: String,
    /// Stable human-readable slug used by YAML refs and mapper gates.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    slug: String,
    /// Allowed redirect URIs.
    redirect_uris: Vec<String>,
    /// When the client was registered.
    created_at: Timestamp,
    /// Argon2id hash of the client secret (confidential clients only).
    ///
    /// `None` for public clients. Uses `#[serde(default)]` for backward
    /// compatibility with existing stored public clients from Phase 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_secret_hash: Option<String>,
    /// OAuth 2.0 grant types this client is allowed to use.
    #[serde(default)]
    grant_types: Vec<String>,
    /// Whether user consent is required before issuing authorization codes.
    ///
    /// Defaults to `true` for backward compatibility with records persisted
    /// before consent was introduced.
    #[serde(default = "default_require_consent")]
    require_consent: bool,
    /// Optional URL to a client logo displayed on the consent screen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_logo_url: Option<String>,
    /// Authz trust posture.
    #[serde(default)]
    trust_level: ClientTrustLevel,
    /// Scopes this client may request.
    #[serde(default)]
    declared_scopes: Vec<String>,
    /// Whether a realm-level consent covers all org contexts.
    #[serde(default)]
    consent_spans_orgs: bool,
    /// Lifecycle status. Defaults to `Active` for backward-compatible deserialization
    /// of records written before the status field was introduced.
    #[serde(default)]
    status: ApplicationStatus,
    /// OIDC back-channel logout URI (OIDC BCL §2.5).
    ///
    /// When set, Hearth delivers a signed logout token to this URI after
    /// session termination. Delivery is async fire-and-forget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backchannel_logout_uri: Option<String>,
    /// OIDC front-channel logout URI.
    ///
    /// When set, Hearth embeds an iframe pointing to this URI on the
    /// post-logout page so the RP can perform its own session cleanup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    frontchannel_logout_uri: Option<String>,
    /// Allowed post-logout redirect URIs.
    ///
    /// After RP-initiated logout, Hearth redirects to `post_logout_redirect_uri`
    /// only if it matches one of these registered values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    post_logout_redirect_uris: Vec<String>,
    /// Base64url-encoded raw Ed25519 public key for JWT bearer assertion
    /// validation (RFC 7523).
    ///
    /// When set, this client may authenticate using
    /// `urn:ietf:params:oauth:grant-type:jwt-bearer`.  The key is stored as
    /// raw 32 bytes encoded with base64url (no PEM wrapping).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assertion_public_key: Option<String>,
    /// Controls how access-token authorization data is exposed to resource servers.
    #[serde(default)]
    access_token_authorization: AccessTokenAuthorization,
    /// Inline JSON Web Key Set for JAR (RFC 9101) signature verification.
    ///
    /// When set, this client may sign authorization requests (`request=<JWT>`)
    /// on `/authorize` or `/as/par`. The value is a JSON string containing a
    /// JWKS object, e.g. `{"keys":[{...}]}`. Supports `RS256` (RSA) and
    /// `EdDSA` (Ed25519) key types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jwks: Option<String>,
    /// URL pointing to a JSON Web Key Set for JAR signature verification.
    ///
    /// When set and `jwks` is absent, the AS MAY fetch this URL to resolve
    /// signing keys. MUST be an `https://` URI. Actual HTTP fetching is not
    /// yet implemented — this field validates and stores the URI for future use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jwks_uri: Option<String>,
    /// JARM signing algorithm for authorization responses (OAuth 2.0 JARM §4).
    ///
    /// When set, JARM is mandatory for this client: every authorization response
    /// is wrapped in a signed JWT regardless of `response_mode`. Supported
    /// values: `"EdDSA"`. Omit to allow plain responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization_signed_response_alg: Option<String>,
}

fn default_require_consent() -> bool {
    true
}

impl OAuthClient {
    /// Creates a new OAuth client. Used internally by the identity engine.
    pub(crate) fn new(
        client_id: ClientId,
        client_name: String,
        redirect_uris: Vec<String>,
        created_at: Timestamp,
    ) -> Self {
        Self {
            client_id,
            client_name,
            slug: String::new(),
            redirect_uris,
            created_at,
            client_secret_hash: None,
            grant_types: vec!["authorization_code".to_string()],
            require_consent: true,
            client_logo_url: None,
            trust_level: ClientTrustLevel::FirstParty,
            declared_scopes: Vec::new(),
            consent_spans_orgs: false,
            status: ApplicationStatus::Active,
            backchannel_logout_uri: None,
            frontchannel_logout_uri: None,
            post_logout_redirect_uris: Vec::new(),
            assertion_public_key: None,
            access_token_authorization: AccessTokenAuthorization::Embedded,
            jwks: None,
            jwks_uri: None,
            authorization_signed_response_alg: None,
        }
    }

    /// Creates a new confidential OAuth client with a secret hash.
    pub(crate) fn new_confidential(
        client_id: ClientId,
        client_name: String,
        redirect_uris: Vec<String>,
        created_at: Timestamp,
        client_secret_hash: String,
        grant_types: Vec<String>,
    ) -> Self {
        Self {
            client_id,
            client_name,
            slug: String::new(),
            redirect_uris,
            created_at,
            client_secret_hash: Some(client_secret_hash),
            grant_types,
            require_consent: true,
            client_logo_url: None,
            trust_level: ClientTrustLevel::FirstParty,
            declared_scopes: Vec::new(),
            consent_spans_orgs: false,
            status: ApplicationStatus::Active,
            backchannel_logout_uri: None,
            frontchannel_logout_uri: None,
            post_logout_redirect_uris: Vec::new(),
            assertion_public_key: None,
            access_token_authorization: AccessTokenAuthorization::Embedded,
            jwks: None,
            jwks_uri: None,
            authorization_signed_response_alg: None,
        }
    }

    /// Returns the client's unique identifier.
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// Returns the client's human-readable name.
    pub fn client_name(&self) -> &str {
        &self.client_name
    }

    /// Returns the stable client slug.
    pub fn slug(&self) -> &str {
        &self.slug
    }

    /// Returns the client's registered redirect URIs.
    pub fn redirect_uris(&self) -> &[String] {
        &self.redirect_uris
    }

    /// Returns when the client was registered.
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns the client secret hash, if this is a confidential client.
    pub fn client_secret_hash(&self) -> Option<&str> {
        self.client_secret_hash.as_deref()
    }

    /// Returns whether this client is confidential (has a secret).
    pub fn is_confidential(&self) -> bool {
        self.client_secret_hash.is_some()
    }

    /// Returns the grant types allowed for this client.
    pub fn grant_types(&self) -> &[String] {
        &self.grant_types
    }

    /// Sets the grant types for this client.
    pub(crate) fn set_grant_types(&mut self, grant_types: Vec<String>) {
        self.grant_types = grant_types;
    }

    /// Sets the client name. Used internally during updates.
    pub(crate) fn set_client_name(&mut self, name: String) {
        self.client_name = name;
    }

    /// Sets the redirect URIs. Used internally during updates.
    pub(crate) fn set_redirect_uris(&mut self, uris: Vec<String>) {
        self.redirect_uris = uris;
    }

    /// Sets the client secret hash. Used internally during secret regeneration.
    pub(crate) fn set_client_secret_hash(&mut self, hash: String) {
        self.client_secret_hash = Some(hash);
    }

    /// Returns whether user consent is required before this client can
    /// receive an authorization code. Trusted first-party clients opt out.
    pub fn require_consent(&self) -> bool {
        self.require_consent
    }

    /// Sets whether user consent is required. Used during admin updates.
    pub(crate) fn set_require_consent(&mut self, require: bool) {
        self.require_consent = require;
    }

    /// Returns the optional logo URL displayed on the consent screen.
    pub fn client_logo_url(&self) -> Option<&str> {
        self.client_logo_url.as_deref()
    }

    /// Returns the client trust level.
    pub fn trust_level(&self) -> ClientTrustLevel {
        self.trust_level
    }

    /// Returns the declared scopes.
    pub fn declared_scopes(&self) -> &[String] {
        &self.declared_scopes
    }

    /// Returns whether consent spans org contexts.
    pub fn consent_spans_orgs(&self) -> bool {
        self.consent_spans_orgs
    }

    /// Sets the client logo URL. `None` clears it. Used during admin updates.
    pub(crate) fn set_client_logo_url(&mut self, url: Option<String>) {
        self.client_logo_url = url;
    }

    /// Sets the stable slug.
    pub(crate) fn set_slug(&mut self, slug: String) {
        self.slug = slug;
    }

    /// Sets the trust level.
    pub(crate) fn set_trust_level(&mut self, trust_level: ClientTrustLevel) {
        self.trust_level = trust_level;
    }

    /// Sets the declared scope allowlist.
    pub(crate) fn set_declared_scopes(&mut self, declared_scopes: Vec<String>) {
        self.declared_scopes = declared_scopes;
    }

    /// Sets whether consent spans org contexts.
    pub(crate) fn set_consent_spans_orgs(&mut self, value: bool) {
        self.consent_spans_orgs = value;
    }

    /// Returns the back-channel logout URI, if configured.
    pub fn backchannel_logout_uri(&self) -> Option<&str> {
        self.backchannel_logout_uri.as_deref()
    }

    /// Returns the front-channel logout URI, if configured.
    pub fn frontchannel_logout_uri(&self) -> Option<&str> {
        self.frontchannel_logout_uri.as_deref()
    }

    /// Returns the allowed post-logout redirect URIs.
    pub fn post_logout_redirect_uris(&self) -> &[String] {
        &self.post_logout_redirect_uris
    }

    /// Sets the back-channel logout URI. `None` clears it.
    pub(crate) fn set_backchannel_logout_uri(&mut self, uri: Option<String>) {
        self.backchannel_logout_uri = uri;
    }

    /// Sets the front-channel logout URI. `None` clears it.
    pub(crate) fn set_frontchannel_logout_uri(&mut self, uri: Option<String>) {
        self.frontchannel_logout_uri = uri;
    }

    /// Sets the allowed post-logout redirect URIs.
    pub(crate) fn set_post_logout_redirect_uris(&mut self, uris: Vec<String>) {
        self.post_logout_redirect_uris = uris;
    }

    /// Returns the base64url-encoded Ed25519 public key for JWT bearer
    /// assertion validation, if one has been registered.
    pub fn assertion_public_key(&self) -> Option<&str> {
        self.assertion_public_key.as_deref()
    }

    /// Sets the assertion public key.  `None` clears it, disabling the
    /// `jwt-bearer` grant for this client.
    pub(crate) fn set_assertion_public_key(&mut self, key: Option<String>) {
        self.assertion_public_key = key;
    }

    /// Returns the client's lifecycle status.
    pub fn status(&self) -> ApplicationStatus {
        self.status
    }

    /// Sets the lifecycle status. Used internally during archive/restore operations.
    pub(crate) fn set_status(&mut self, status: ApplicationStatus) {
        self.status = status;
    }

    /// Returns the access-token authorization mode configured for this client.
    pub fn access_token_authorization(&self) -> AccessTokenAuthorization {
        self.access_token_authorization
    }

    /// Sets the access-token authorization mode.
    pub(crate) fn set_access_token_authorization(&mut self, mode: AccessTokenAuthorization) {
        self.access_token_authorization = mode;
    }

    /// Returns the inline JWKS (JSON string) for JAR signature verification, if set.
    pub fn jwks(&self) -> Option<&str> {
        self.jwks.as_deref()
    }

    /// Sets the inline JWKS JSON for JAR signature verification. `None` clears it.
    pub(crate) fn set_jwks(&mut self, jwks: Option<String>) {
        self.jwks = jwks;
    }

    /// Returns the JWKS URI for JAR signature verification, if set.
    pub fn jwks_uri(&self) -> Option<&str> {
        self.jwks_uri.as_deref()
    }

    /// Sets the JWKS URI for JAR signature verification. `None` clears it.
    pub(crate) fn set_jwks_uri(&mut self, uri: Option<String>) {
        self.jwks_uri = uri;
    }

    /// Returns the JARM signing algorithm, if mandatory JARM is configured.
    pub fn authorization_signed_response_alg(&self) -> Option<&str> {
        self.authorization_signed_response_alg.as_deref()
    }

    /// Sets the JARM signing algorithm. `None` disables mandatory JARM.
    pub(crate) fn set_authorization_signed_response_alg(&mut self, alg: Option<String>) {
        self.authorization_signed_response_alg = alg;
    }

    /// Returns `true` if this client was provisioned from YAML configuration.
    ///
    /// YAML-managed clients have deterministic UUID v5 identifiers (derived
    /// from realm name + app key via `reconcile_applications`). Manually-
    /// registered clients always use random UUID v4. Edits made via the UI
    /// will be overwritten on the next server restart when YAML is present.
    pub fn is_yaml_managed(&self) -> bool {
        self.client_id.as_uuid().get_version_num() == 5
    }
}

/// Request to update an existing OAuth 2.0 client.
///
/// Only `Some` fields are applied; `None` fields are left unchanged.
#[derive(Debug, Clone, Default)]
pub struct UpdateClientRequest {
    /// New client display name.
    pub client_name: Option<String>,
    /// New set of redirect URIs.
    pub redirect_uris: Option<Vec<String>>,
    /// New set of allowed grant types.
    pub grant_types: Option<Vec<String>>,
    /// Whether user consent is required (trusted-client bypass).
    pub require_consent: Option<bool>,
    /// Logo URL for the consent screen. Passing `Some(None)` clears it;
    /// `None` leaves it untouched.
    pub client_logo_url: Option<Option<String>>,
    /// Updated stable slug.
    pub slug: Option<String>,
    /// Updated trust posture.
    pub trust_level: Option<ClientTrustLevel>,
    /// Updated declared scope allowlist.
    pub declared_scopes: Option<Vec<String>>,
    /// Updated org-spanning consent behavior.
    pub consent_spans_orgs: Option<bool>,
    /// Back-channel logout URI (OIDC BCL §2.5). `Some(None)` clears it.
    pub backchannel_logout_uri: Option<Option<String>>,
    /// Front-channel logout URI. `Some(None)` clears it.
    pub frontchannel_logout_uri: Option<Option<String>>,
    /// Allowed post-logout redirect URIs. Replaces the existing list.
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// New lifecycle status. Used to archive or restore a client.
    pub status: Option<ApplicationStatus>,
    /// Ed25519 assertion public key for JWT bearer grant (RFC 7523).
    ///
    /// Pass `Some(Some(key_b64url))` to set, `Some(None)` to clear.
    /// `None` leaves the current value unchanged.
    pub assertion_public_key: Option<Option<String>>,
    /// New access-token authorization mode. `None` leaves unchanged.
    pub access_token_authorization: Option<AccessTokenAuthorization>,
    /// JARM signing algorithm update. `Some(Some("EdDSA"))` enables mandatory JARM,
    /// `Some(None)` clears it (disables mandatory JARM). `None` leaves unchanged.
    pub authorization_signed_response_alg: Option<Option<String>>,
}

// ===== RP-Initiated Logout =====

/// A client that needs a back-channel logout notification.
#[derive(Debug, Clone)]
pub struct BackchannelTarget {
    /// The registered back-channel logout URI.
    pub uri: String,
    /// Pre-signed logout token JWT to POST to `uri`.
    pub logout_token: String,
}

/// A client that needs a front-channel logout via iframe.
#[derive(Debug, Clone)]
pub struct FrontchannelTarget {
    /// The registered front-channel logout URI.
    pub uri: String,
    /// The client's ID, included as query param per OIDC FCL spec.
    pub client_id: crate::core::ClientId,
}

/// Request for RP-initiated logout (OIDC RPL §2).
#[derive(Debug, Clone, Default)]
pub struct RpLogoutRequest {
    /// Optional ID token hint — used to bind the logout to a specific session.
    /// Accepted even when expired, per the OIDC spec.
    pub id_token_hint: Option<String>,
    /// Explicit session ID override (alternative to id_token_hint).
    pub session_id: Option<crate::core::SessionId>,
    /// Post-logout redirect URI. Validated against `post_logout_redirect_uris`
    /// when a `client_id` is present.
    pub post_logout_redirect_uri: Option<String>,
    /// The client initiating the logout. Used to validate `post_logout_redirect_uri`.
    pub client_id: Option<crate::core::ClientId>,
    /// Opaque state parameter — echoed back in the redirect.
    pub state: Option<String>,
}

/// Result of RP-initiated logout.
#[derive(Debug, Clone)]
pub struct RpLogoutResult {
    /// The user whose session was terminated.
    pub user_id: crate::core::UserId,
    /// The session that was revoked.
    pub session_id: crate::core::SessionId,
    /// Clients requiring back-channel notification, with pre-signed tokens.
    pub backchannel_targets: Vec<BackchannelTarget>,
    /// Clients requiring front-channel notification via iframe.
    pub frontchannel_targets: Vec<FrontchannelTarget>,
    /// Validated post-logout redirect URI (absent if unregistered or not provided).
    pub post_logout_redirect_uri: Option<String>,
    /// State parameter from the request, echoed back.
    pub state: Option<String>,
}

/// The PKCE code challenge method.
///
/// Only `S256` is supported. `plain` is a security anti-pattern and
/// is deliberately excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    /// SHA-256 hash of the code verifier.
    S256,
}

/// OAuth 2.0 authorization response mode (OIDC Core §3 + JARM).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ResponseMode {
    /// Standard query-string redirect (default for `response_type=code`).
    #[default]
    Query,
    /// Fragment-based redirect.
    Fragment,
    /// JARM: signed JWT response delivered via query string (`?response=<jwt>`).
    QueryJwt,
    /// JARM: signed JWT response delivered via fragment (`#response=<jwt>`).
    FragmentJwt,
    /// JARM: `response_mode=jwt` — defaults to `query.jwt` for code flow.
    Jwt,
}

impl ResponseMode {
    /// Returns the wire string sent by the client.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Fragment => "fragment",
            Self::QueryJwt => "query.jwt",
            Self::FragmentJwt => "fragment.jwt",
            Self::Jwt => "jwt",
        }
    }

    /// Whether this mode produces a signed JWT authorization response.
    pub fn is_jarm(&self) -> bool {
        matches!(self, Self::QueryJwt | Self::FragmentJwt | Self::Jwt)
    }
}

impl std::str::FromStr for ResponseMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "query" => Ok(Self::Query),
            "fragment" => Ok(Self::Fragment),
            "query.jwt" => Ok(Self::QueryJwt),
            "fragment.jwt" => Ok(Self::FragmentJwt),
            "jwt" => Ok(Self::Jwt),
            _ => Err(()),
        }
    }
}

/// Request to initiate an OAuth 2.0 authorization.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// The client requesting authorization.
    pub client_id: ClientId,
    /// The redirect URI (must match a registered URI).
    pub redirect_uri: String,
    /// Requested scopes (space-delimited).
    pub scope: String,
    /// Opaque state value for CSRF protection (MUST be non-empty).
    pub state: String,
    /// Optional RFC 8707 resource indicator.
    pub resource: Option<String>,
    /// Response type (must be "code" for authorization code flow).
    pub response_type: String,
    /// The authenticated user granting authorization.
    pub user_id: crate::core::UserId,
    /// PKCE code challenge (base64url-encoded SHA-256 hash).
    pub code_challenge: Option<String>,
    /// PKCE code challenge method (must be S256 if present).
    pub code_challenge_method: Option<CodeChallengeMethod>,
    /// Optional nonce for replay protection.
    ///
    /// When nonce enforcement is enabled (`OidcConfig::enforce_nonces`),
    /// duplicate nonces are rejected.
    pub nonce: Option<String>,
    /// Authentication Methods References (RFC 8176) established before code
    /// issuance. Non-empty when an MFA challenge was successfully completed
    /// (e.g. `["sms"]`). Propagated to `StoredAuthorizationCode.amr_values`
    /// and then into the issued tokens at exchange time.
    pub amr_values: Vec<String>,
    /// JARM response mode (RFC 9207 / OAuth 2.0 JARM). When set to a JWT
    /// variant, the authorization response is wrapped in a signed JWT.
    pub response_mode: Option<ResponseMode>,
    /// Signed JAR JWT (RFC 9101) carrying authorization parameters.
    ///
    /// When present, the engine validates the JWT signature against the
    /// client's registered `jwks`, then uses the JWT claims to populate
    /// (and override) the request fields. The outer `client_id` must match
    /// the `iss` claim inside the JWT.
    pub request: Option<String>,
}

/// Response from a successful authorization request.
#[derive(Debug, Clone)]
pub struct AuthorizationResponse {
    /// The authorization code (raw, base64url-encoded).
    code: String,
    /// The state value echoed back for CSRF verification.
    state: String,
    /// RFC 9207 issuer identifier — appended to the redirect as `iss=`.
    iss: String,
    /// JARM signed JWT wrapping `{iss, aud, exp, code, state}`. Present only
    /// when the request used a JARM response mode (`query.jwt` / `fragment.jwt`
    /// / `jwt`). When present, the redirect MUST use `response=<jwt>` instead
    /// of plain `code=...&state=...`.
    jarm_jwt: Option<String>,
    /// The effective response mode for this response.
    response_mode: ResponseMode,
}

impl AuthorizationResponse {
    /// Creates a new authorization response.
    pub(crate) fn new(code: String, state: String, iss: String) -> Self {
        Self {
            code,
            state,
            iss,
            jarm_jwt: None,
            response_mode: ResponseMode::Query,
        }
    }

    /// Creates a JARM authorization response with a signed JWT.
    pub(crate) fn new_jarm(
        code: String,
        state: String,
        iss: String,
        jarm_jwt: String,
        response_mode: ResponseMode,
    ) -> Self {
        Self {
            code,
            state,
            iss,
            jarm_jwt: Some(jarm_jwt),
            response_mode,
        }
    }

    /// Returns the authorization code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the state value.
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Returns the RFC 9207 issuer identifier.
    pub fn iss(&self) -> &str {
        &self.iss
    }

    /// Returns the JARM signed JWT, if this is a JARM response.
    pub fn jarm_jwt(&self) -> Option<&str> {
        self.jarm_jwt.as_deref()
    }

    /// Returns the effective response mode.
    pub fn response_mode(&self) -> &ResponseMode {
        &self.response_mode
    }
}

/// JWT claims for a JARM (JWT Authorization Response Message) response.
///
/// Signed with the realm's Ed25519 key. The JWT wraps code + state so
/// the client can verify the response was issued by the expected AS.
/// Spec: OAuth 2.0 JARM (draft-fett-oauth-jwarm).
#[derive(Debug, serde::Serialize)]
pub(crate) struct JarmClaims {
    /// Issuer — the authorization server's issuer URL.
    pub iss: String,
    /// Audience — the client_id that sent the authorization request.
    pub aud: String,
    /// Expiry — short-lived (max 10 minutes, typically 2–5 min per FAPI).
    pub exp: i64,
    /// The authorization code.
    pub code: String,
    /// The echoed state value.
    pub state: String,
}

/// Request to exchange an authorization code for tokens.
#[derive(Debug, Clone)]
pub struct TokenExchangeRequest {
    /// The client exchanging the code.
    pub client_id: ClientId,
    /// The authorization code to exchange.
    pub code: String,
    /// The redirect URI (must match the one used during authorization).
    pub redirect_uri: String,
    /// PKCE code verifier (required if `code_challenge` was sent during authorization).
    pub code_verifier: Option<String>,
    /// JWK thumbprint for DPoP binding (RFC 9449). When present, the issued access token
    /// will carry a `cnf.jkt` claim and `token_type` will be `DPoP`.
    pub dpop_jkt: Option<String>,
    /// Assertion type for `private_key_jwt` client authentication (RFC 7523).
    pub client_assertion_type: Option<String>,
    /// The signed JWT assertion for `private_key_jwt` client authentication.
    pub client_assertion: Option<String>,
}

/// Response from a successful token exchange.
#[derive(Debug, Clone)]
pub struct OidcTokenResponse {
    /// The access token (JWT).
    access_token: String,
    /// The OIDC ID token (JWT).
    id_token: String,
    /// The token type (always "Bearer").
    token_type: String,
    /// Seconds until the access token expires.
    expires_in: i64,
    /// The refresh token (JWT).
    refresh_token: String,
}

impl OidcTokenResponse {
    /// Creates a new OIDC token response.
    pub(crate) fn new(
        access_token: String,
        id_token: String,
        token_type: String,
        expires_in: i64,
        refresh_token: String,
    ) -> Self {
        Self {
            access_token,
            id_token,
            token_type,
            expires_in,
            refresh_token,
        }
    }

    /// Returns the access token.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the OIDC ID token.
    pub fn id_token(&self) -> &str {
        &self.id_token
    }

    /// Returns the token type (always "Bearer").
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Returns seconds until the access token expires.
    pub fn expires_in(&self) -> i64 {
        self.expires_in
    }

    /// Returns the refresh token.
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }
}

/// Internal storage representation of an authorization code.
///
/// Stored by SHA-256 hash of the raw code value for security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredAuthorizationCode {
    /// SHA-256 hex digest of the raw code.
    pub(crate) code_hash: String,
    /// The client that requested authorization.
    pub(crate) client_id: ClientId,
    /// The user who granted authorization.
    pub(crate) user_id: crate::core::UserId,
    /// The redirect URI used during authorization.
    pub(crate) redirect_uri: String,
    /// Requested scopes.
    pub(crate) scope: String,
    /// PKCE code challenge (if provided).
    pub(crate) code_challenge: Option<String>,
    /// PKCE code challenge method (if provided).
    pub(crate) code_challenge_method: Option<CodeChallengeMethod>,
    /// When the code was issued.
    pub(crate) created_at: Timestamp,
    /// When the code expires.
    pub(crate) expires_at: Timestamp,
    /// Whether the code has already been used.
    pub(crate) used: bool,
    /// The nonce from the authorization request (echoed in ID token per OIDC Core §2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) nonce: Option<String>,
    /// Optional RFC 8707 resource indicator from the authorization request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resource: Option<String>,
    /// Authentication Methods References (RFC 8176) established during the
    /// authorization flow (e.g. `["sms"]` after a successful SMS MFA challenge).
    /// Propagated verbatim to both access and ID token claims at exchange time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) amr_values: Vec<String>,
}

/// OIDC Discovery document (`OpenID` Connect Discovery 1.0).
///
/// Contains metadata about the `OpenID` Provider's configuration.
/// All REQUIRED fields per `OpenID` Connect Discovery 1.0 §3 are included.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcDiscoveryDocument {
    /// The issuer identifier URL.
    pub issuer: String,
    /// URL of the authorization endpoint.
    pub authorization_endpoint: String,
    /// URL of the token endpoint.
    pub token_endpoint: String,
    /// URL of the JWKS endpoint.
    pub jwks_uri: String,
    /// URL of the `UserInfo` endpoint (OIDC Core §5.3).
    pub userinfo_endpoint: String,
    /// Supported response types.
    pub response_types_supported: Vec<String>,
    /// Supported response modes (OIDC Core §3).
    pub response_modes_supported: Vec<String>,
    /// Supported subject identifier types.
    pub subject_types_supported: Vec<String>,
    /// Supported ID token signing algorithms.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Supported scopes.
    pub scopes_supported: Vec<String>,
    /// Claims supported by this provider.
    pub claims_supported: Vec<String>,
    /// Supported token endpoint auth methods.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Supported PKCE code challenge methods.
    pub code_challenge_methods_supported: Vec<String>,
    /// Supported grant types.
    pub grant_types_supported: Vec<String>,
    /// URL of the dynamic client registration endpoint (RFC 7591).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// URL of the device authorization endpoint (RFC 8628).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    /// URL of the token revocation endpoint (RFC 7009).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    /// URL of the token introspection endpoint (RFC 7662).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    /// Whether RFC 8707 resource indicators are supported.
    #[serde(default)]
    pub resource_indicators_supported: bool,
    /// Whether the RFC 9207 `iss` parameter is included in authorization responses.
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
    /// URL of the RP-initiated logout endpoint (OIDC RP-Initiated Logout 1.0 §3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,
    /// Whether back-channel logout is supported (OIDC BCL draft §2.1).
    #[serde(default)]
    pub backchannel_logout_supported: bool,
    /// Whether back-channel logout tokens include a `sid` claim.
    #[serde(default)]
    pub backchannel_logout_session_supported: bool,
    /// URL of the pushed authorization request endpoint (RFC 9126).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,
    /// DPoP signing algorithms supported (RFC 9449 §5.1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// JAR request-object signing algorithms supported (RFC 9101 §10.6).
    ///
    /// Advertises which algorithms the AS accepts in `request=<JWT>` parameters
    /// on `/authorize` and `/as/par`. Clients MUST use one of these algorithms.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_object_signing_alg_values_supported: Vec<String>,
    /// JARM authorization response signing algorithms supported (OAuth 2.0 JARM §10).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_signing_alg_values_supported: Vec<String>,
}

// ===== JWT Authorization Requests — RFC 9101 (JAR) =====

/// Claims carried in a JAR JWT (RFC 9101 §4).
///
/// The JWT body contains both the standard JWT claims (`iss`, `aud`, `exp`,
/// `nbf`, `iat`, `jti`) and the authorization request parameters that it
/// carries on behalf of the client. The AS validates the envelope claims
/// first, then uses the authorization parameters to drive the flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JarClaims {
    /// Issuer — MUST equal the `client_id`.
    pub iss: String,
    /// Audience — MUST identify this AS (issuer URL or authorization endpoint).
    pub aud: crate::identity::tokens::Audience,
    /// Expiration time (Unix seconds). MUST be in the future.
    pub exp: i64,
    /// Not-before time (Unix seconds). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Issued-at time (Unix seconds). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// JWT ID — unique identifier, used for replay prevention if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    // ── Authorization request parameters ──
    /// Must be "code".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    /// The client identifier — must match the `client_id` query parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Redirect URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// Space-delimited scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// CSRF protection state value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// PKCE S256 code challenge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    /// Code challenge method (`S256` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
    /// OIDC nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// RFC 8707 resource indicator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

// ===== Pushed Authorization Requests (RFC 9126) =====

/// Request to push authorization parameters to the PAR endpoint.
///
/// Returns a `request_uri` that the client passes to `/authorize` instead
/// of the full parameter set.
#[derive(Debug, Clone)]
pub struct PushedAuthorizationRequest {
    /// The client making the request.
    pub client_id: ClientId,
    /// The redirect URI to use after authorization.
    pub redirect_uri: String,
    /// Space-delimited scope string.
    pub scope: String,
    /// CSRF protection state value.
    pub state: String,
    /// RFC 8707 resource indicator.
    pub resource: Option<String>,
    /// Must be "code".
    pub response_type: String,
    /// PKCE S256 code challenge (required for public clients).
    pub code_challenge: Option<String>,
    /// Code challenge method — only S256 is accepted.
    pub code_challenge_method: Option<CodeChallengeMethod>,
    /// OIDC nonce claim to bind to the ID token.
    pub nonce: Option<String>,
    /// Signed JAR JWT (RFC 9101) carrying the authorization parameters.
    ///
    /// When present, the server validates the JWT signature against the
    /// client's registered `jwks`, then uses the JWT claims to populate
    /// (and override) the request fields. `client_id` on the outer request
    /// must match `iss` inside the JWT.
    pub request: Option<String>,
}

/// Response from a successful PAR push (RFC 9126 §2.2).
#[derive(Debug, Clone, serde::Serialize)]
pub struct PushedAuthorizationResponse {
    /// URN referencing the stored authorization parameters.
    pub request_uri: String,
    /// Seconds until the `request_uri` expires.
    pub expires_in: i64,
}

/// Stored PAR entry — persisted under `oauth:par:{uuid}`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct StoredPushedAuthorizationRequest {
    /// The UUID portion of the `request_uri`.
    pub(crate) request_uri_id: String,
    /// The client that pushed the request.
    pub(crate) client_id: ClientId,
    /// The redirect URI from the push.
    pub(crate) redirect_uri: String,
    /// Space-delimited scope.
    pub(crate) scope: String,
    /// CSRF state.
    pub(crate) state: String,
    /// RFC 8707 resource indicator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resource: Option<String>,
    /// Response type.
    pub(crate) response_type: String,
    /// PKCE S256 code challenge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) code_challenge: Option<String>,
    /// PKCE code challenge method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) code_challenge_method: Option<CodeChallengeMethod>,
    /// OIDC nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) nonce: Option<String>,
    /// When this entry was created.
    pub(crate) created_at: Timestamp,
    /// When this entry expires (created_at + 90 s).
    pub(crate) expires_at: Timestamp,
    /// Whether the `request_uri` has already been consumed.
    pub(crate) used: bool,
}

// ===== Client Credentials Grant =====

/// Request for the OAuth 2.0 Client Credentials Grant (RFC 6749 §4.4).
#[derive(Debug, Clone)]
pub struct ClientCredentialsRequest {
    /// The client requesting tokens.
    pub client_id: ClientId,
    /// The client secret for authentication (required unless `client_assertion` is provided).
    pub client_secret: Option<String>,
    /// Requested scope (space-delimited).
    pub scope: Option<String>,
    /// JWK thumbprint for DPoP binding (RFC 9449).
    pub dpop_jkt: Option<String>,
    /// Assertion type for `private_key_jwt` client authentication (RFC 7523).
    pub client_assertion_type: Option<String>,
    /// The signed JWT assertion for `private_key_jwt` client authentication.
    pub client_assertion: Option<String>,
}

/// Request for the JWT Bearer Grant (RFC 7523).
///
/// The client authenticates by presenting a self-signed JWT `assertion`
/// instead of a client secret.  The assertion MUST be signed with the
/// Ed25519 private key whose public key is registered on the client.
#[derive(Debug, Clone)]
pub struct JwtBearerRequest {
    /// The client requesting tokens.
    pub client_id: ClientId,
    /// The signed JWT bearer assertion.
    pub assertion: String,
    /// Requested scope (space-delimited).
    pub scope: Option<String>,
    /// JWK thumbprint for DPoP binding (RFC 9449).
    pub dpop_jkt: Option<String>,
}

/// Response from a client credentials grant.
///
/// Per RFC 6749 §4.4.3, refresh tokens SHOULD NOT be included.
#[derive(Debug, Clone)]
pub struct ClientCredentialsResponse {
    /// The access token (JWT).
    access_token: String,
    /// The token type (always "Bearer").
    token_type: String,
    /// Seconds until the access token expires.
    expires_in: i64,
    /// The scope granted.
    scope: Option<String>,
}

impl ClientCredentialsResponse {
    /// Creates a new client credentials response.
    pub(crate) fn new(
        access_token: String,
        token_type: String,
        expires_in: i64,
        scope: Option<String>,
    ) -> Self {
        Self {
            access_token,
            token_type,
            expires_in,
            scope,
        }
    }

    /// Returns the access token.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the token type.
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Returns seconds until expiration.
    pub fn expires_in(&self) -> i64 {
        self.expires_in
    }

    /// Returns the granted scope.
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
}

// ===== Device Authorization (RFC 8628) =====

/// Request for the Device Authorization Grant (RFC 8628).
#[derive(Debug, Clone)]
pub struct DeviceAuthorizationRequest {
    /// The client requesting device authorization.
    pub client_id: ClientId,
    /// Requested scope (space-delimited).
    pub scope: Option<String>,
}

/// Response from a device authorization request (RFC 8628 §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationResponse {
    /// The device verification code.
    pub device_code: String,
    /// The end-user verification code (short, displayed to user).
    pub user_code: String,
    /// The end-user verification URI.
    pub verification_uri: String,
    /// Seconds until the device code expires.
    pub expires_in: i64,
    /// Minimum polling interval in seconds.
    pub interval: i64,
}

/// Status of a device authorization code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceCodeStatus {
    /// Awaiting user action.
    Pending,
    /// User approved the authorization.
    Approved {
        /// The user who approved.
        user_id: crate::core::UserId,
    },
    /// User denied the authorization.
    Denied,
    /// The device code has expired.
    Expired,
}

/// Internal storage representation of a device authorization code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredDeviceCode {
    /// The device code (hashed in storage key).
    pub(crate) device_code_hash: String,
    /// The user code (short, displayed to user).
    pub(crate) user_code: String,
    /// The client that requested authorization.
    pub(crate) client_id: ClientId,
    /// The realm context.
    pub(crate) realm_id: RealmId,
    /// Requested scope.
    pub(crate) scope: Option<String>,
    /// Current status.
    pub(crate) status: DeviceCodeStatus,
    /// When the code was issued.
    pub(crate) created_at: Timestamp,
    /// When the code expires.
    pub(crate) expires_at: Timestamp,
    /// Minimum polling interval in seconds.
    pub(crate) interval: i64,
    /// Last time the device polled (for rate limiting).
    pub(crate) last_polled_at: Option<Timestamp>,
}

// ===== Grant Family (Refresh Token Rotation) =====

/// Tracks a grant family for refresh token rotation and theft detection.
///
/// Each authorization code exchange or client credentials grant creates
/// a family. On refresh, the hash is rotated. If a stale hash is presented,
/// the entire family (and its session) is revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredGrantFamily {
    /// Unique family identifier.
    pub(crate) family_id: String,
    /// SHA-256 hex of the current valid refresh token.
    pub(crate) current_refresh_hash: String,
    /// The session bound to this family.
    pub(crate) session_id: crate::core::SessionId,
    /// The realm owning this family.
    pub(crate) realm_id: RealmId,
    /// Whether this family has been revoked (e.g., theft detection).
    pub(crate) revoked: bool,
    /// When the family was created.
    pub(crate) created_at: Timestamp,
    /// When this family expires and becomes eligible for sweep.
    ///
    /// Set to `created_at + refresh_token_ttl` at creation and extended
    /// on each successful rotation so the family lifetime tracks the
    /// latest refresh token's `exp` claim.
    pub(crate) expires_at: Timestamp,
    /// The OAuth client that owns this grant family.
    ///
    /// Optional for backward compatibility — families created before this
    /// field was added will have `None`. When present, used for consent
    /// digest re-checking on refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) client_id: Option<ClientId>,
    /// RFC 8707 resource indicators from the authorization grant. Used
    /// to preserve the resource binding across refresh token rotations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) resources: Vec<crate::core::Uri>,
    /// AMR values from the original authorization grant (RFC 8176).
    /// Stored here so they are preserved across all refresh rotations
    /// without needing to embed them in the refresh token itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) amr_values: Vec<String>,
}

// ===== Token Revocation (RFC 7009) =====

/// Request to revoke an OAuth 2.0 token (RFC 7009).
#[derive(Debug, Clone)]
pub struct TokenRevocationRequest {
    /// The token to revoke (access or refresh).
    pub token: String,
    /// Optional hint about the token type.
    pub token_type_hint: Option<String>,
}

// ===== Token Introspection (RFC 7662) =====

/// Request for token introspection (RFC 7662).
#[derive(Debug, Clone)]
pub struct TokenIntrospectionRequest {
    /// The token to introspect.
    pub token: String,
    /// Optional hint about the token type.
    pub token_type_hint: Option<String>,
    /// The client that authenticated for this introspection call.
    ///
    /// When present, the engine looks up this client's `access_token_authorization`
    /// mode and includes live RBAC claims in the response for
    /// `Introspection` and `Decision` clients.
    pub introspecting_client_id: Option<crate::core::ClientId>,
}

/// Response from token introspection (RFC 7662).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    /// Whether the token is currently active.
    pub active: bool,
    /// The scope associated with the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Client identifier for the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Subject (user/client) of the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Token expiration time (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Issued-at time (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Token type (e.g., "access" or "refresh").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// Issuer of the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience of the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Access-token authorization mode configured on the issuing client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<AccessTokenAuthorization>,
    /// Live permission strings (Introspection/Decision mode only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
    /// Live role names (Introspection/Decision mode only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    /// Live group slugs (Introspection/Decision mode only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

impl IntrospectionResponse {
    /// Returns an inactive introspection response.
    ///
    /// Per RFC 7662, an inactive response MUST contain `active: false`
    /// and MAY omit all other fields.
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            sub: None,
            exp: None,
            iat: None,
            token_type: None,
            iss: None,
            aud: None,
            mode: None,
            permissions: Vec::new(),
            roles: Vec::new(),
            groups: Vec::new(),
        }
    }
}

// ===== Decision Endpoint (HEA-922) =====

/// Request body for `POST /oauth/authorize` — the per-request decision endpoint.
#[derive(Debug, Clone)]
pub struct DecidePermissionRequest {
    /// Bearer access token presented by the resource server.
    pub token: String,
    /// Permission to check (e.g. `"docs.write"`).
    pub permission: String,
    /// Optional organization scope for org-scoped permission checks.
    pub organization_id: Option<String>,
    /// Optional resource URI for RFC 8707 audience-scoped checks.
    pub resource: Option<String>,
}

/// Response from `POST /oauth/authorize`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecidePermissionResponse {
    /// Whether the token holder has the requested permission.
    pub allowed: bool,
}

// ===== UserInfo (OIDC Core §5.3) =====

/// Response from the `UserInfo` endpoint (OIDC Core §5.3).
///
/// The `sub` claim is always returned. Other claims are filtered by
/// the access token's granted scopes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserInfoResponse {
    /// Subject — the user ID. Always present.
    pub sub: String,
    /// User's email address. Present when scope includes `email`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether the email is verified. Present when scope includes `email`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// User's display name. Present when scope includes `profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Additional declaratively-shaped claims.
    #[serde(default, flatten)]
    pub custom: std::collections::BTreeMap<String, serde_json::Value>,
}

/// Exercises the token exchange body parsing and validation pipeline on arbitrary bytes.
///
/// Intended for fuzz testing: interprets `data` as a JSON token request body,
/// exercising grant_type dispatch, scope normalization, redirect URI validation,
/// and PKCE verifier length checks. Must never panic — always returns `Ok` or `Err`.
pub fn fuzz_parse_token_exchange(data: &[u8]) {
    use crate::identity::types::canonicalize_scopes;
    use crate::identity::validation::{validate_redirect_uri, validate_scope_tokens};

    // Exercise JSON parsing of the token exchange body.
    let _ = serde_json::from_slice::<serde_json::Value>(data);

    // Exercise OIDC discovery document deserialization.
    let input = String::from_utf8_lossy(data);
    let _ = serde_json::from_str::<OidcDiscoveryDocument>(&input);

    // Exercise introspection response deserialization.
    let _ = serde_json::from_str::<IntrospectionResponse>(&input);

    // Treat the input as a scope string and exercise normalization.
    let scope_tokens: Vec<String> = input.split_whitespace().map(String::from).collect();
    let _ = canonicalize_scopes(scope_tokens);
    let _ = validate_scope_tokens(&input);

    // Treat the input as a redirect URI and exercise validation.
    let _ = validate_redirect_uri(&input);

    // Extract grant_type-like string from raw JSON and exercise matching logic.
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(&input) {
        if let Some(serde_json::Value::String(s)) = map.get("redirect_uri") {
            let _ = validate_redirect_uri(s);
        }
        if let Some(serde_json::Value::String(s)) = map.get("scope") {
            let _ = validate_scope_tokens(s);
            let tokens: Vec<String> = s.split_whitespace().map(String::from).collect();
            let _ = canonicalize_scopes(tokens);
        }
        // Exercise code_verifier length boundary.
        if let Some(serde_json::Value::String(v)) = map.get("code_verifier") {
            let _ = v.len() > 128;
            let _ = v.len() < 43;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_config_default_values() {
        let config = OidcConfig::default();
        assert_eq!(config.authorization_code_ttl_secs, 600);
        assert_eq!(config.issuer, "https://hearth.local");
    }

    #[test]
    fn oauth_client_serde_round_trip() {
        let client = OAuthClient::new(
            ClientId::generate(),
            "Test App".to_string(),
            vec!["https://app.example.com/callback".to_string()],
            Timestamp::from_micros(1_700_000_000_000_000),
        );

        let json = serde_json::to_string(&client).expect("serialize");
        let deserialized: OAuthClient = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(client, deserialized);
    }

    #[test]
    fn oauth_client_accessors() {
        let client_id = ClientId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let client = OAuthClient::new(
            client_id.clone(),
            "My App".to_string(),
            vec![
                "https://app.example.com/cb".to_string(),
                "https://app.example.com/alt".to_string(),
            ],
            now,
        );

        assert_eq!(client.client_id(), &client_id);
        assert_eq!(client.client_name(), "My App");
        assert_eq!(client.redirect_uris().len(), 2);
        assert_eq!(client.created_at(), now);
    }

    #[test]
    fn authorization_response_accessors() {
        let resp = AuthorizationResponse::new(
            "code123".to_string(),
            "state456".to_string(),
            "https://auth.example.com".to_string(),
        );
        assert_eq!(resp.code(), "code123");
        assert_eq!(resp.state(), "state456");
        assert_eq!(resp.iss(), "https://auth.example.com");
    }

    #[test]
    fn oidc_token_response_accessors() {
        let resp = OidcTokenResponse::new(
            "access".to_string(),
            "id".to_string(),
            "Bearer".to_string(),
            900,
            "refresh".to_string(),
        );
        assert_eq!(resp.access_token(), "access");
        assert_eq!(resp.id_token(), "id");
        assert_eq!(resp.token_type(), "Bearer");
        assert_eq!(resp.expires_in(), 900);
        assert_eq!(resp.refresh_token(), "refresh");
    }

    #[test]
    fn stored_authorization_code_serde_round_trip() {
        let code = StoredAuthorizationCode {
            code_hash: "abc123".to_string(),
            client_id: ClientId::generate(),
            user_id: crate::core::UserId::generate(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            scope: "openid".to_string(),
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            created_at: Timestamp::from_micros(1_000_000),
            expires_at: Timestamp::from_micros(2_000_000),
            used: false,
            nonce: Some("test-nonce-abc".to_string()),
            resource: None,
            amr_values: Vec::new(),
        };

        let json = serde_json::to_string(&code).expect("serialize");
        let deserialized: StoredAuthorizationCode =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.code_hash, code.code_hash);
        assert!(!deserialized.used);
    }

    #[test]
    fn discovery_document_serde_round_trip() {
        let doc = OidcDiscoveryDocument {
            issuer: "https://hearth.local".to_string(),
            authorization_endpoint: "https://hearth.local/authorize".to_string(),
            token_endpoint: "https://hearth.local/token".to_string(),
            jwks_uri: "https://hearth.local/.well-known/jwks.json".to_string(),
            userinfo_endpoint: "https://hearth.local/userinfo".to_string(),
            response_types_supported: vec!["code".to_string()],
            response_modes_supported: vec!["query".to_string()],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
            scopes_supported: vec!["openid".to_string()],
            claims_supported: vec!["sub".to_string()],
            token_endpoint_auth_methods_supported: vec!["none".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
            ],
            registration_endpoint: Some("https://hearth.local/register".to_string()),
            device_authorization_endpoint: Some(
                "https://hearth.local/device/authorize".to_string(),
            ),
            revocation_endpoint: Some("https://hearth.local/revoke".to_string()),
            introspection_endpoint: Some("https://hearth.local/introspect".to_string()),
            resource_indicators_supported: false,
            authorization_response_iss_parameter_supported: true,
            end_session_endpoint: Some("https://hearth.local/end_session".to_string()),
            backchannel_logout_supported: false,
            backchannel_logout_session_supported: false,
            pushed_authorization_request_endpoint: None,
            dpop_signing_alg_values_supported: Vec::new(),
            request_object_signing_alg_values_supported: Vec::new(),
            authorization_signing_alg_values_supported: Vec::new(),
        };

        let json = serde_json::to_string(&doc).expect("serialize");
        let deserialized: OidcDiscoveryDocument = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(doc, deserialized);
    }
}

// ===== Resource Owner Password Credentials Grant (RFC 6749 §4.3) =====

/// Request for the Resource Owner Password Credentials (ROPC) grant.
///
/// Identifies the end-user by email address. The client_id is used for
/// per-client rate limiting only; no client authentication is required for
/// public clients.
#[derive(Debug, Clone, Default)]
pub struct PasswordGrantRequest {
    /// The user's email address.
    pub email: String,
    /// The user's plaintext password.
    pub password: String,
    /// Optional OAuth scope (space-delimited). Passed through to the token.
    pub scope: Option<String>,
    /// Client IP address for device-fingerprint step-up MFA.
    ///
    /// Pass the value of `X-Forwarded-For` / peer address after proxy normalisation.
    /// When `None`, adaptive MFA is skipped (behaves as if feature is disabled for
    /// this request). Falls back to `"unknown"` prefix in the HMAC input.
    pub client_ip: Option<String>,
    /// Raw `User-Agent` header value for device-fingerprint step-up MFA.
    ///
    /// When `None`, adaptive MFA uses an empty string for the UA component.
    pub user_agent: Option<String>,
}

/// Response from a successful ROPC grant — mirrors `OidcTokenResponse`.
#[derive(Debug, Clone)]
pub struct PasswordGrantResponse {
    /// Short-lived access token (JWT).
    pub access_token: String,
    /// Long-lived refresh token (JWT).
    pub refresh_token: String,
    /// Always `"Bearer"`.
    pub token_type: String,
    /// Access token lifetime in seconds.
    pub expires_in: i64,
}

impl PasswordGrantResponse {
    /// Returns the access token.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the refresh token.
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }
}

/// Request to complete a step-up MFA challenge issued during ROPC login.
///
/// Used with `grant_type = urn:hearth:params:grant-type:step-up-mfa`.
/// The caller re-supplies the password and adds an `mfa_code`; both are
/// verified before tokens are issued and the device fingerprint is recorded.
#[derive(Debug)]
pub struct StepUpMfaGrantRequest {
    /// The user's email address.
    pub email: String,
    /// The user's plaintext password (re-verified to prevent session fixation).
    pub password: String,
    /// TOTP code or recovery code presented by the user.
    pub mfa_code: String,
    /// Optional OAuth scope (space-delimited).
    pub scope: Option<String>,
    /// Client IP address — used to record the trusted device fingerprint.
    pub client_ip: Option<String>,
    /// Raw `User-Agent` header value — used to record the trusted device fingerprint.
    pub user_agent: Option<String>,
}
