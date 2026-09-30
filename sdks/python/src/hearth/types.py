"""Hearth API request and response types."""

from typing import Any, Generic, Literal, TypeVar

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
    email: str | None = None
    status: str
    created_at: str | None = None
    updated_at: str | None = None


class CreateUserRequest(BaseModel):
    username: str
    email: str | None = None
    password: str | None = None
    attributes: dict | None = None


class UpdateUserRequest(BaseModel):
    username: str | None = None
    email: str | None = None
    status: str | None = None
    attributes: dict | None = None


class PageResponse(BaseModel, Generic[T]):
    items: list[T]
    next_cursor: str | None = None
    total: int | None = None


class Realm(BaseModel):
    id: str
    name: str
    status: str
    config: dict | None = None
    created_at: str | None = None


class UpdateRealmRequest(BaseModel):
    name: str | None = None
    config: dict | None = None
    status: str | None = None


class AuthorizeResponse(BaseModel):
    code: str
    state: str
    redirect_uri: str | None = None


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
    refresh_token: str | None = None
    scope: str | None = None
    id_token: str | None = None


class UserInfoResponse(BaseModel):
    sub: str
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    preferred_username: str | None = None
    permissions: list[str] | None = None
    roles: list[str] | None = None
    groups: list[str] | None = None


class MePermissionsResponse(BaseModel):
    permissions: list[str]
    roles: list[str]
    groups: list[str]


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


def _proto_trust_level(value: str | None) -> str | None:
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
    redirect_uris: list[str] = []
    trust_level: str | None = None
    #: The generated secret (wire key ``client_secret``) — present only on the
    #: response that created a ``client_secret_basic`` / ``client_secret_post``
    #: client or regenerated its secret, never again. Store it on receipt.
    secret: str | None = Field(
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
    redirect_uris: list[str] = []
    trust_level: str | None = None
    #: RFC 7591 §2: ``client_secret_basic`` / ``client_secret_post`` make the
    #: server generate the secret and return it once (``OAuthClient.secret``);
    #: ``private_key_jwt`` or ``none``. Omitted registers a public client.
    token_endpoint_auth_method: str | None = None

    @field_serializer("trust_level")
    def _serialize_trust_level(self, value: str | None) -> str | None:
        return _proto_trust_level(value)


class CreateClientRequest(BaseModel):
    """Body of ``POST /admin/applications`` (the proto ``RegisterClientRequest``).

    Same wire shape as :class:`RegisterClientRequest`: ``name`` is sent as
    ``client_name`` and ``trust_level`` as the proto enum name.
    """

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(validation_alias="client_name", serialization_alias="client_name")
    redirect_uris: list[str] = []
    trust_level: str | None = None
    #: RFC 7591 §2: ``client_secret_basic`` / ``client_secret_post`` make the
    #: server generate the secret and return it once (``OAuthClient.secret``);
    #: ``private_key_jwt`` or ``none``. Omitted registers a public client.
    token_endpoint_auth_method: str | None = None

    @field_serializer("trust_level")
    def _serialize_trust_level(self, value: str | None) -> str | None:
        return _proto_trust_level(value)


class UpdateClientRequest(BaseModel):
    """Body of ``PATCH /admin/applications/{id}``.

    ``name`` is sent as ``client_name``. The route ignores unknown keys, so a
    ``name`` key would answer ``200`` and rename nothing. ``trust_level`` stays
    snake_case (``first_party`` / ``third_party``), which is what this route
    reads.
    """

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = Field(
        default=None, validation_alias="client_name", serialization_alias="client_name"
    )
    redirect_uris: list[str] | None = None
    trust_level: str | None = None


class Role(BaseModel):
    """A realm-level role definition."""

    id: str
    name: str
    description: str | None = None


class CreateRoleRequest(BaseModel):
    """Request body for POST /admin/roles."""

    name: str
    description: str | None = None


class UpdateRoleRequest(BaseModel):
    """Request body for PUT /admin/roles/{id}."""

    name: str | None = None
    description: str | None = None


class Group(BaseModel):
    """A realm-level group definition."""

    id: str
    name: str
    description: str | None = None


class CreateGroupRequest(BaseModel):
    """Request body for POST /admin/groups."""

    name: str
    description: str | None = None


class UpdateGroupRequest(BaseModel):
    """Request body for PUT /admin/groups/{id}."""

    name: str | None = None
    description: str | None = None


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
    keys: list[Jwk]


class IntrospectRequest(BaseModel):
    """Parameters for RFC 7662 token introspection (POST /realms/{realm_id}/introspect)."""

    token: str
    client_id: str
    client_secret: str | None = None
    token_type_hint: str | None = None


class IntrospectResponse(BaseModel):
    """RFC 7662 introspection response.

    The ``mode`` field echoes the ``access_token_authorization`` setting on the issuing
    OAuth client. Middleware MUST reject the token when ``mode`` differs from the
    configured ``expected_mode``.
    """

    active: bool
    sub: str | None = None
    client_id: str | None = None
    scope: str | None = None
    exp: int | None = None
    iat: int | None = None
    token_type: str | None = None
    iss: str | None = None
    #: Access-token authorization mode echoed from the issuing client.
    mode: str | None = None
    #: Live-resolved permission set (introspection/decision modes only).
    permissions: list[str] | None = None
    roles: list[str] | None = None
    groups: list[str] | None = None


class CheckPermissionRequest(BaseModel):
    """Parameters for POST /oauth/authorize (decision endpoint)."""

    permission: str
    organization_id: str | None = None
    resource: str | None = None


class CheckPermissionResponse(BaseModel):
    """Response from POST /oauth/authorize."""

    allowed: bool
    sub: str | None = None
    permission: str | None = None


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
    verification_uri_complete: str | None = None


# ---------------------------------------------------------------------------
# Session-version feed (HEA-930)
# ---------------------------------------------------------------------------


class SvDeltaEntry(BaseModel):
    """A single session-version bump event."""

    seq: int
    session_id: str
    min_sv: int
    bumped_at: int | None = None


class SvDeltaResponse(BaseModel):
    """Response from GET /oauth/session-versions?since=<seq>."""

    realm: str
    next_seq: int
    deltas: list[SvDeltaEntry]


class SvSnapshotResponse(BaseModel):
    """Response from GET /oauth/session-versions/snapshot."""

    realm: str
    current_seq: int
    versions: Any  # dict[session_id → min_sv]
