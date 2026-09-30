"""Hearth API request and response types."""

from typing import Literal, Optional, List, Any, Generic, TypeVar

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_serializer

T = TypeVar("T")

#: Controls how the SDK and middleware verify permissions for a given resource-server client.
#: Must be configured explicitly — the middleware will NOT silently fall back from one mode
#: to another based on what claims happen to be present in the token.
AccessTokenAuthorizationMode = Literal["embedded", "introspection", "decision"]


class BootstrapResponse(BaseModel):
    admin_token: str
    realm_id: str
    user_id: str
    access_token: str
    refresh_token: str


class User(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    status: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class CreateUserRequest(BaseModel):
    username: str
    email: Optional[str] = None
    password: Optional[str] = None
    attributes: Optional[dict] = None


class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    status: Optional[str] = None
    attributes: Optional[dict] = None


class PageResponse(BaseModel, Generic[T]):
    items: List[T]
    next_cursor: Optional[str] = None
    total: Optional[int] = None


class Realm(BaseModel):
    id: str
    name: str
    status: str
    config: Optional[dict] = None
    created_at: Optional[str] = None


class UpdateRealmRequest(BaseModel):
    name: Optional[str] = None
    config: Optional[dict] = None
    status: Optional[str] = None


class AuthorizeResponse(BaseModel):
    code: str
    state: str
    redirect_uri: Optional[str] = None


class LoginBeginResult(BaseModel):
    """Result of :meth:`~hearth.HearthClient.begin_login`.

    Redirect the browser to ``authorization_url``, then persist ``state`` and
    ``code_verifier`` in your session so they can be verified and supplied to
    :meth:`~hearth.HearthClient.complete_login` on the callback route.
    """

    authorization_url: str
    """Full PKCE authorization URL — redirect the browser here."""
    state: str
    """Random CSRF-protection value — verify against the callback ``state`` param."""
    code_verifier: str
    """PKCE code verifier — pass to ``complete_login`` on the callback route."""


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    id_token: Optional[str] = None


class UserInfoResponse(BaseModel):
    sub: str
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    name: Optional[str] = None
    preferred_username: Optional[str] = None
    permissions: Optional[List[str]] = None
    roles: Optional[List[str]] = None
    groups: Optional[List[str]] = None


class MePermissionsResponse(BaseModel):
    permissions: List[str]
    roles: List[str]
    groups: List[str]


# Proto ``ClientTrustLevel`` names for the SDK's snake_case trust levels.
#
# ``POST /clients`` and ``POST /admin/applications`` deserialize the proto
# ``RegisterClientRequest``, whose ``trust_level`` is an enum: the server answers
# ``422 unknown variant`` for ``first_party``. ``PATCH /admin/applications/{id}``
# is the opposite — it reads the snake_case string.
_PROTO_TRUST_LEVEL = {
    "first_party": "CLIENT_TRUST_LEVEL_FIRST_PARTY",
    "third_party": "CLIENT_TRUST_LEVEL_THIRD_PARTY",
}


def _proto_trust_level(value: Optional[str]) -> Optional[str]:
    """Map ``first_party`` / ``third_party`` to the proto enum name.

    Any other value is sent unchanged, so the server rejects a typo instead of
    the SDK silently choosing a trust level.
    """
    if value is None:
        return None
    return _PROTO_TRUST_LEVEL.get(value, value)


class OAuthClient(BaseModel):
    """An OAuth client.

    Every client route (``POST /clients`` and ``/admin/applications``) answers
    with the proto ``OAuthClient`` shape, so the wire keys are ``client_id`` /
    ``client_name``. ``id`` / ``name`` are only this model's attribute names
    (accepted as constructor keywords too); no Hearth route sends them.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(validation_alias="client_id")
    name: str = Field(validation_alias="client_name")
    redirect_uris: List[str] = []
    trust_level: Optional[str] = None
    #: The generated secret (wire key ``client_secret``) — present only on the
    #: response that created a ``client_secret_basic`` / ``client_secret_post``
    #: client or regenerated its secret, never again. Store it on receipt.
    secret: Optional[str] = Field(
        default=None, validation_alias=AliasChoices("client_secret", "secret")
    )


class RegisterClientRequest(BaseModel):
    """Body of ``POST /clients`` (the proto ``RegisterClientRequest``).

    ``name`` is sent as ``client_name`` — the server rejects an unknown ``name``
    key with ``422`` — and ``trust_level`` (``first_party`` / ``third_party``)
    as the proto enum name.
    """

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(validation_alias="client_name", serialization_alias="client_name")
    redirect_uris: List[str] = []
    trust_level: Optional[str] = None
    #: RFC 7591 §2: ``client_secret_basic`` / ``client_secret_post`` make the
    #: server generate the secret and return it once (``OAuthClient.secret``);
    #: ``private_key_jwt`` or ``none``. Omitted registers a public client.
    token_endpoint_auth_method: Optional[str] = None

    @field_serializer("trust_level")
    def _serialize_trust_level(self, value: Optional[str]) -> Optional[str]:
        return _proto_trust_level(value)


class CreateClientRequest(BaseModel):
    """Body of ``POST /admin/applications`` (the proto ``RegisterClientRequest``).

    Same wire shape as :class:`RegisterClientRequest`: ``name`` is sent as
    ``client_name`` and ``trust_level`` as the proto enum name.
    """

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(validation_alias="client_name", serialization_alias="client_name")
    redirect_uris: List[str] = []
    trust_level: Optional[str] = None
    #: RFC 7591 §2: ``client_secret_basic`` / ``client_secret_post`` make the
    #: server generate the secret and return it once (``OAuthClient.secret``);
    #: ``private_key_jwt`` or ``none``. Omitted registers a public client.
    token_endpoint_auth_method: Optional[str] = None

    @field_serializer("trust_level")
    def _serialize_trust_level(self, value: Optional[str]) -> Optional[str]:
        return _proto_trust_level(value)


class UpdateClientRequest(BaseModel):
    """Body of ``PATCH /admin/applications/{id}``.

    ``name`` is sent as ``client_name``. The route ignores unknown keys, so a
    ``name`` key would answer ``200`` and rename nothing. ``trust_level`` stays
    snake_case (``first_party`` / ``third_party``), which is what this route
    reads.
    """

    model_config = ConfigDict(populate_by_name=True)

    name: Optional[str] = Field(
        default=None, validation_alias="client_name", serialization_alias="client_name"
    )
    redirect_uris: Optional[List[str]] = None
    trust_level: Optional[str] = None


class Role(BaseModel):
    """A realm-level role definition."""

    id: str
    name: str
    description: Optional[str] = None


class CreateRoleRequest(BaseModel):
    """Request body for POST /admin/roles."""

    name: str
    description: Optional[str] = None


class UpdateRoleRequest(BaseModel):
    """Request body for PUT /admin/roles/{id}."""

    name: Optional[str] = None
    description: Optional[str] = None


class Group(BaseModel):
    """A realm-level group definition."""

    id: str
    name: str
    description: Optional[str] = None


class CreateGroupRequest(BaseModel):
    """Request body for POST /admin/groups."""

    name: str
    description: Optional[str] = None


class UpdateGroupRequest(BaseModel):
    """Request body for PUT /admin/groups/{id}."""

    name: Optional[str] = None
    description: Optional[str] = None


# OrgMember and AddOrgMemberRequest were removed with the org-membership
# methods: Hearth serves no organization route over HTTP
# (audit 2026-08-28 §25.19).


class Jwk(BaseModel):
    kty: str
    crv: str
    x: str
    kid: str
    use: str
    alg: str


class JwksDocument(BaseModel):
    keys: List[Jwk]


class IntrospectRequest(BaseModel):
    """Parameters for RFC 7662 token introspection (POST /realms/{realm_id}/introspect)."""

    token: str
    client_id: str
    client_secret: Optional[str] = None
    token_type_hint: Optional[str] = None


class IntrospectResponse(BaseModel):
    """RFC 7662 introspection response.

    The ``mode`` field echoes the ``access_token_authorization`` setting on the issuing
    OAuth client. Middleware MUST reject the token when ``mode`` differs from the
    configured ``expected_mode``.
    """

    active: bool
    sub: Optional[str] = None
    client_id: Optional[str] = None
    scope: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    token_type: Optional[str] = None
    iss: Optional[str] = None
    #: Access-token authorization mode echoed from the issuing client.
    mode: Optional[str] = None
    #: Live-resolved permission set (introspection/decision modes only).
    permissions: Optional[List[str]] = None
    roles: Optional[List[str]] = None
    groups: Optional[List[str]] = None


class CheckPermissionRequest(BaseModel):
    """Parameters for POST /oauth/authorize (decision endpoint)."""

    permission: str
    organization_id: Optional[str] = None
    resource: Optional[str] = None


class CheckPermissionResponse(BaseModel):
    """Response from POST /oauth/authorize."""

    allowed: bool
    sub: Optional[str] = None
    permission: Optional[str] = None


# ---------------------------------------------------------------------------
# PKCE (§7)
# ---------------------------------------------------------------------------

class PkcePair(BaseModel):
    """RFC 7636 S256 PKCE pair — verifier is secret, challenge is sent to server."""

    code_verifier: str
    code_challenge: str


# ---------------------------------------------------------------------------
# Device Authorization Flow (§4.5.2)
# ---------------------------------------------------------------------------

class DeviceAuthorizationResponse(BaseModel):
    """Response from the device authorization endpoint (RFC 8628)."""

    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int = 5
    verification_uri_complete: Optional[str] = None


# ---------------------------------------------------------------------------
# Session-version feed (HEA-930)
# ---------------------------------------------------------------------------

class SvDeltaEntry(BaseModel):
    """A single session-version bump event."""

    seq: int
    session_id: str
    min_sv: int
    bumped_at: Optional[int] = None


class SvDeltaResponse(BaseModel):
    """Response from GET /oauth/session-versions?since=<seq>."""

    realm: str
    next_seq: int
    deltas: List[SvDeltaEntry]


class SvSnapshotResponse(BaseModel):
    """Response from GET /oauth/session-versions/snapshot."""

    realm: str
    current_seq: int
    versions: Any  # dict[session_id → min_sv]
