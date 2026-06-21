//! OAuth consent, webhook, and agent types.

use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

use crate::core::{
    AgentCredentialId, AgentId, ClientId, OrganizationId, RealmId, ResourceServerId, Timestamp,
    UserId, WebhookId,
};

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
    /// The realm this pending request belongs to. Prevents cross-realm replay:
    /// a consent ticket issued in realm A cannot be redeemed in realm B even
    /// if the ticket cookie somehow survives a realm switch.
    pub realm_id: RealmId,
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

// ─────────────────────────────────────────────────────────────────────────────
// Agent entity types (AGENT_AUTH.md Phase A, HEA-1325)
// ─────────────────────────────────────────────────────────────────────────────

/// Lifecycle state of an agent entity.
///
/// Transitions:
/// - `Active → Suspended → Active` (reversible)
/// - `Active | Suspended → Revoked` (terminal; no re-activation)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    /// Agent is operational and may authenticate.
    Active,
    /// Agent is temporarily suspended; cannot authenticate or be delegated to.
    Suspended,
    /// Agent is permanently revoked; no re-activation possible.
    Revoked,
}

/// The owner of an agent — either a user or an organization within the same realm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "id")]
pub enum AgentOwner {
    /// The agent is owned by a specific user.
    User(UserId),
    /// The agent is owned by an organization (B2B workload identity).
    Organization(OrganizationId),
}

impl AgentOwner {
    /// Returns the string tag used in storage key indexes.
    pub fn storage_tag(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Organization(_) => "org",
        }
    }

    /// Returns the UUID string of the inner owner ID for storage key encoding.
    pub fn uuid_str(&self) -> String {
        match self {
            Self::User(id) => id.as_uuid().to_string(),
            Self::Organization(id) => id.as_uuid().to_string(),
        }
    }
}

/// An autonomous agent entity registered in a realm.
///
/// Agents are distinct from users and OAuth clients. They represent
/// autonomous software entities with their own identity lifecycle,
/// credential set, capability declarations, and delegation chain support.
/// See `AGENT_AUTH.md` for the normative specification.
///
/// Fields are private; access via accessor methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agent {
    id: AgentId,
    realm_id: RealmId,
    owner: AgentOwner,
    display_name: String,
    description: String,
    capabilities: Vec<String>,
    status: AgentStatus,
    /// Maximum number of delegation hops this agent may initiate (1–10).
    max_delegation_depth: u8,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl Agent {
    /// Creates a new agent record. Used internally by the identity engine.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: AgentId,
        realm_id: RealmId,
        owner: AgentOwner,
        display_name: String,
        description: String,
        capabilities: Vec<String>,
        status: AgentStatus,
        max_delegation_depth: u8,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            id,
            realm_id,
            owner,
            display_name,
            description,
            capabilities,
            status,
            max_delegation_depth,
            created_at,
            updated_at,
        }
    }

    /// Returns the agent's unique identifier.
    pub fn id(&self) -> &AgentId {
        &self.id
    }

    /// Returns the realm this agent belongs to.
    pub fn realm_id(&self) -> &RealmId {
        &self.realm_id
    }

    /// Returns the owner of this agent.
    pub fn owner(&self) -> &AgentOwner {
        &self.owner
    }

    /// Returns the agent's human-readable display name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the agent's description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the declared capability URIs for this agent.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Returns the agent's current lifecycle status.
    pub fn status(&self) -> AgentStatus {
        self.status
    }

    /// Returns the maximum delegation chain depth this agent may initiate.
    pub fn max_delegation_depth(&self) -> u8 {
        self.max_delegation_depth
    }

    /// Returns when the agent was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when the agent was last updated (UTC microseconds).
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Updates the display name. Used internally during agent updates.
    pub(crate) fn set_display_name(&mut self, name: String) {
        self.display_name = name;
    }

    /// Updates the description. Used internally during agent updates.
    pub(crate) fn set_description(&mut self, description: String) {
        self.description = description;
    }

    /// Updates the capability list. Used internally during agent updates.
    pub(crate) fn set_capabilities(&mut self, capabilities: Vec<String>) {
        self.capabilities = capabilities;
    }

    /// Updates the status. Used internally for lifecycle transitions.
    pub(crate) fn set_status(&mut self, status: AgentStatus) {
        self.status = status;
    }

    /// Updates the max delegation depth.
    pub(crate) fn set_max_delegation_depth(&mut self, depth: u8) {
        self.max_delegation_depth = depth;
    }

    /// Updates the `updated_at` timestamp.
    pub(crate) fn set_updated_at(&mut self, ts: Timestamp) {
        self.updated_at = ts;
    }
}

/// Request to create a new agent.
#[derive(Clone, Debug)]
pub struct CreateAgentRequest {
    /// Human-readable display name (1–256 chars).
    pub display_name: String,
    /// Optional description of what the agent does (max 2048 chars).
    pub description: Option<String>,
    /// Owner of this agent — a user or organization in the same realm.
    pub owner: AgentOwner,
    /// Declared capability URIs (informational; enforcement via RBAC).
    pub capabilities: Vec<String>,
    /// Maximum number of delegation hops (1–10, default 1).
    pub max_delegation_depth: u8,
}

/// Request to update an existing agent's mutable fields.
#[derive(Clone, Debug, Default)]
pub struct UpdateAgentRequest {
    /// New display name, or `None` to leave unchanged.
    pub display_name: Option<String>,
    /// New description, or `None` to leave unchanged.
    pub description: Option<String>,
    /// New capability list, or `None` to leave unchanged.
    pub capabilities: Option<Vec<String>>,
    /// New max delegation depth, or `None` to leave unchanged.
    pub max_delegation_depth: Option<u8>,
}

/// Query parameters for listing agents.
#[derive(Clone, Debug, Default)]
pub struct ListAgentsQuery {
    /// Filter agents by owner. `None` returns all owners.
    pub owner_id: Option<AgentOwner>,
    /// Filter agents by status. `None` returns all statuses.
    pub status: Option<AgentStatus>,
    /// Filter agents that declare a specific capability URI.
    pub capability: Option<String>,
}

// ── Agent Credentials (A.3) ──────────────────────────────────────────────────

/// Discriminates the kind of credential stored for an agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCredentialKind {
    /// A server-generated 256-bit random API key. Only the SHA-256 hash is stored.
    ApiKey,
    /// An Ed25519 public key supplied by the agent at registration time.
    Ed25519PublicKey,
    /// An mTLS client-certificate fingerprint (SHA-256 of the DER-encoded cert).
    MtlsCert,
}

/// A stored agent credential record (no secret material).
///
/// API keys are stored as SHA-256 hashes; public keys and cert fingerprints
/// are stored as-is. Plaintext API keys are never persisted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCredential {
    id: AgentCredentialId,
    agent_id: AgentId,
    kind: AgentCredentialKind,
    /// Human-readable label chosen at creation time (max 256 chars).
    label: String,
    /// SHA-256 hex of the API key, or the raw Ed25519/cert material (no secrets).
    credential_hash: String,
    created_at: Timestamp,
    /// When the credential was revoked, or `None` if still active.
    revoked_at: Option<Timestamp>,
}

impl AgentCredential {
    /// Creates a new credential record. Used internally by the identity engine.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: AgentCredentialId,
        agent_id: AgentId,
        kind: AgentCredentialKind,
        label: String,
        credential_hash: String,
        created_at: Timestamp,
    ) -> Self {
        Self {
            id,
            agent_id,
            kind,
            label,
            credential_hash,
            created_at,
            revoked_at: None,
        }
    }

    /// Returns the credential's unique identifier.
    pub fn id(&self) -> &AgentCredentialId {
        &self.id
    }

    /// Returns the agent this credential belongs to.
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// Returns the kind of this credential.
    pub fn kind(&self) -> AgentCredentialKind {
        self.kind
    }

    /// Returns the human-readable label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the stored hash or public key material.
    pub fn credential_hash(&self) -> &str {
        &self.credential_hash
    }

    /// Returns when this credential was created.
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when this credential was revoked, or `None` if active.
    pub fn revoked_at(&self) -> Option<Timestamp> {
        self.revoked_at
    }

    /// Returns `true` if this credential has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Marks the credential revoked. Used internally by the engine.
    pub(crate) fn revoke(&mut self, at: Timestamp) {
        self.revoked_at = Some(at);
    }
}

/// Request to issue a new API-key credential for an agent.
#[derive(Clone, Debug)]
pub struct CreateAgentApiKeyRequest {
    /// Human-readable label for the key (max 256 chars).
    pub label: String,
}

/// Response from creating an agent API key.
///
/// The `plaintext_key` field is the only time the raw key is visible.
/// It is wrapped in a `Zeroize`-on-drop guard and MUST NOT be logged.
pub struct CreateAgentApiKeyResponse {
    /// The stored credential record (no secrets).
    pub credential: AgentCredential,
    /// The raw 256-bit API key — show once, never stored.
    pub plaintext_key: PlaintextApiKey,
}

/// A 256-bit random API key shown exactly once at creation time.
///
/// Wraps the hex-encoded key in a `Zeroize`-on-drop guard.
/// MUST NOT implement `Debug`, `Display`, `Serialize`, or `Clone`.
pub struct PlaintextApiKey(String);

impl PlaintextApiKey {
    /// Creates a new plaintext API key from its hex representation.
    pub(crate) fn new(hex: String) -> Self {
        Self(hex)
    }

    /// Returns the hex-encoded key. Call once and discard.
    pub fn expose_once(&self) -> &str {
        &self.0
    }
}

impl Drop for PlaintextApiKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// ── Protected Resource / MCP Authorization Server (AGENT_AUTH.md §2.5) ───────

/// A protected resource (MCP tool server) registered within a realm.
///
/// MCP clients discover these via PRM (`.well-known/oauth-protected-resource`)
/// and request tokens scoped to a specific resource URI per RFC 8707.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedResource {
    /// Unique identifier.
    pub id: ResourceServerId,
    /// The owning realm.
    pub realm_id: RealmId,
    /// Canonical URI of the MCP server (used as `aud` in access tokens).
    pub resource_uri: String,
    /// Human-readable name for admin display.
    pub display_name: String,
    /// Scopes this resource accepts. Empty means all realm-level scopes apply.
    pub scopes: Vec<String>,
    /// JWT claims the resource requires in tokens presented to it.
    pub required_claims: Vec<String>,
    /// When the resource was registered.
    pub created_at: Timestamp,
    /// When the resource record was last updated.
    pub updated_at: Timestamp,
}

/// Request to register a new protected resource.
#[derive(Clone, Debug)]
pub struct RegisterProtectedResourceRequest {
    /// Canonical URI of the MCP server.
    pub resource_uri: String,
    /// Human-readable name.
    pub display_name: String,
    /// Scopes this resource supports.
    #[allow(clippy::struct_field_names)]
    pub scopes: Vec<String>,
    /// Claims required in tokens.
    pub required_claims: Vec<String>,
}

/// Request to update an existing protected resource.
#[derive(Clone, Debug, Default)]
pub struct UpdateProtectedResourceRequest {
    /// New human-readable name, if changing.
    pub display_name: Option<String>,
    /// New scope list, if replacing.
    pub scopes: Option<Vec<String>>,
    /// New required-claims list, if replacing.
    pub required_claims: Option<Vec<String>>,
}

// ── RFC 8693 Token Exchange ───────────────────────────────────────────────────

/// RFC 8693 `urn:ietf:params:oauth:grant-type:token-exchange` request.
///
/// Distinct from the (misnamed) `TokenExchangeRequest` which handles
/// authorization-code exchange. This struct maps to the actual RFC 8693
/// token exchange grant type.
#[derive(Clone, Debug)]
pub struct Rfc8693Request {
    /// Authenticating client_id.
    pub client_id: ClientId,
    /// The subject token (user's access token whose authority is being delegated).
    pub subject_token: String,
    /// Token type of `subject_token`. MUST be
    /// `urn:ietf:params:oauth:token-type:access_token`.
    pub subject_token_type: String,
    /// Actor token (agent's JWT assertion proving the agent's identity).
    pub actor_token: Option<String>,
    /// Token type of `actor_token`. MUST be
    /// `urn:ietf:params:oauth:token-type:jwt` when present.
    pub actor_token_type: Option<String>,
    /// Requested token type. Defaults to
    /// `urn:ietf:params:oauth:token-type:access_token`.
    pub requested_token_type: Option<String>,
    /// Requested scope — intersected with subject token's scope and agent's
    /// permitted scope. Optional; if absent, defaults to subject token's scope.
    pub scope: Option<String>,
    /// Optional RFC 8707 resource indicator.
    pub resource: Option<String>,
    /// Optional target audience claim override.
    pub audience: Option<String>,
    /// DPoP key thumbprint, if the caller provided a DPoP proof header.
    pub dpop_jkt: Option<String>,
}

/// Successful RFC 8693 token exchange response.
#[derive(Clone, Debug)]
pub struct Rfc8693Response {
    /// The issued access token.
    pub access_token: String,
    /// Always `urn:ietf:params:oauth:token-type:access_token`.
    pub issued_token_type: String,
    /// `"Bearer"` or `"DPoP"` depending on DPoP binding.
    pub token_type: String,
    /// Seconds until access token expiry.
    pub expires_in: i64,
    /// Effective scopes in the issued token (may be narrower than requested).
    pub scope: String,
}

/// Persisted record of an RFC 8693 token-exchange delegation.
///
/// Created when `rfc8693_token_exchange` issues a delegated access token.
/// Stored so the user can list active delegations and revoke them via
/// `GET /ui/consent/delegations`. Revoking adds `token_jti` to the
/// JTI blocklist, immediately invalidating the issued access token.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredDelegationGrant {
    /// Unique ID for this delegation record (UUID string).
    pub delegation_id: String,
    /// `sub` claim of the actor (agent identifier, e.g. `"agt_xxxx"`).
    pub actor_sub: String,
    /// `sub` claim of the subject (the user who authorized the delegation).
    pub user_sub: String,
    /// Effective scope string as issued.
    pub granted_scope: String,
    /// When this delegation was created.
    pub created_at: Timestamp,
    /// When the issued access token expires.
    pub expires_at: Timestamp,
    /// Whether the user has explicitly revoked this delegation.
    pub revoked: bool,
    /// JTI of the issued delegated access token, for immediate revocation.
    pub token_jti: String,
}

/// Listing entry returned from [`IdentityEngine::list_delegation_grants`].
#[derive(Clone, Debug)]
pub struct DelegationGrantEntry {
    /// Unique ID of this delegation record.
    pub delegation_id: String,
    /// Actor identifier (agent or client).
    pub actor_sub: String,
    /// Granted scopes as individual tokens.
    pub granted_scopes: Vec<String>,
    /// When this delegation was created.
    pub created_at: Timestamp,
    /// When the delegation expires.
    pub expires_at: Timestamp,
}

// Approval Request Lifecycle (AGENT_AUTH.md §9 / Phase C.4)

/// Status of a human-in-the-loop approval request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRequestStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// Input for creating a new approval request.
#[derive(Clone, Debug)]
pub struct CreateApprovalRequestInput {
    pub agent_id: AgentId,
    pub tool: String,
    pub action: String,
    pub context: serde_json::Value,
    pub delegation_chain: Vec<String>,
    pub expires_in_secs: Option<i64>,
}

/// A persisted approval request record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub request_id: String,
    pub agent_id: AgentId,
    pub tool: String,
    pub action: String,
    pub context: serde_json::Value,
    pub delegation_chain: Vec<String>,
    pub status: ApprovalRequestStatus,
    pub requested_at: Timestamp,
    pub expires_at: Timestamp,
    pub resolved_at: Option<Timestamp>,
    pub denial_reason: Option<String>,
}

/// A short-lived capability token issued after approval.
#[derive(Clone, Debug)]
pub struct CapabilityTokenInfo {
    pub token: String,
    pub expires_in_secs: i64,
}

/// Response from approving or denying an approval request.
#[derive(Clone, Debug)]
pub struct ApprovalRequestResponse {
    pub request_id: String,
    pub status: ApprovalRequestStatus,
    pub capability_token: Option<CapabilityTokenInfo>,
}
