"""FastAPI dependency adapter for Hearth authentication.

Provides :class:`HearthFastAPIDep` — a ``Depends()``-compatible callable that
verifies a Bearer JWT and returns a :class:`VerifiedClaims` object injectable
into route handlers.  Also exposes :func:`require_permission` as an
``Annotated`` shorthand and :class:`HearthSettings` for pydantic-settings
environment configuration.

Usage::

    from fastapi import FastAPI, Depends
    from hearth import HearthClient
    from hearth.fastapi import HearthFastAPIDep, VerifiedClaims, require_permission

    client = HearthClient(base_url, realm_id=realm_id)
    auth = HearthFastAPIDep(client=client, mode="embedded")
    ReadDocs = require_permission("docs.read", dep=auth)

    app = FastAPI()

    @app.get("/docs")
    def list_docs(claims: VerifiedClaims = Depends(auth)):
        return {"sub": claims.sub}

    @app.post("/docs")
    def create_doc(claims: ReadDocs):           # annotation IS the dependency
        return {"sub": claims.sub}
"""

from __future__ import annotations

from typing import Annotated, List, Optional, TYPE_CHECKING

from pydantic import BaseModel

from .claims import Claims
from .errors import (
    TokenExpiredError,
    TokenInvalidError,
    TokenNotYetValidError,
    TokenIssuerError,
    TokenAudienceError,
    HearthSdkError,
)

try:
    from starlette.requests import Request
except ImportError as _exc:  # pragma: no cover
    raise ImportError(
        "hearth.fastapi requires FastAPI/Starlette. "
        "Install it with: pip install fastapi"
    ) from _exc

if TYPE_CHECKING:
    from .client import HearthClient


# ---------------------------------------------------------------------------
# VerifiedClaims — typed return value for route handlers
# ---------------------------------------------------------------------------

class VerifiedClaims(BaseModel):
    """A verified JWT's claims, ready to inject into FastAPI route handlers.

    All fields are populated from a cryptographically verified token — never
    constructed from untrusted user input directly.
    """

    sub: str
    """Subject (user ID)."""
    iss: str
    """Issuer URL."""
    exp: Optional[int] = None
    """Expiry timestamp (Unix seconds)."""
    aud: Optional[List[str]] = None
    """Audiences."""
    permissions: List[str] = []
    """Embedded permission set (``permissions`` claim)."""
    roles: List[str] = []
    """Assigned roles (``roles`` claim)."""
    groups: List[str] = []
    """Group memberships (``groups`` claim)."""
    organization_id: Optional[str] = None
    """Organization ID (``oid`` claim)."""
    jti: Optional[str] = None
    """JWT ID (``jti`` claim)."""

    @classmethod
    def from_claims(cls, claims: Claims) -> "VerifiedClaims":
        """Build a :class:`VerifiedClaims` from a :class:`~hearth.claims.Claims` object."""
        return cls(
            sub=claims.subject(),
            iss=claims.issuer(),
            exp=claims.expiry(),
            aud=claims.audiences() or None,
            permissions=list(claims.get("permissions") or []),
            roles=list(claims.get("roles") or []),
            groups=list(claims.get("groups") or []),
            organization_id=claims.organization_id(),
            jti=claims.jwtID(),
        )

    def has_permission(self, permission: str) -> bool:
        """Return ``True`` iff the token contains the given permission."""
        return permission in self.permissions

    def has_role(self, role: str) -> bool:
        """Return ``True`` iff the token contains the given role."""
        return role in self.roles

    def in_group(self, group_id: str) -> bool:
        """Return ``True`` iff the token's ``groups`` claim contains *group_id*."""
        return group_id in self.groups


# ---------------------------------------------------------------------------
# HearthFastAPIDep — Depends()-compatible callable
# ---------------------------------------------------------------------------

class HearthFastAPIDep:
    """A ``Depends()``-compatible callable that verifies Hearth Bearer JWTs.

    Inject it into route handlers to authenticate requests and optionally gate
    on a required permission.  The returned :class:`VerifiedClaims` is typed,
    so FastAPI propagates it to the OpenAPI schema.

    :param client: An authenticated :class:`~hearth.client.HearthClient`.
    :param mode: Authorization mode — ``"embedded"`` performs local JWT
        verification; ``"introspection"`` and ``"decision"`` make network calls.
    :param permission: Optional permission to enforce.  When set, the
        dependency raises ``HTTP 403`` if the verified token lacks it.
    :param audience: Optional expected ``aud`` claim value.

    Raises ``HTTP 401`` on missing / invalid / expired tokens.
    Raises ``HTTP 403`` on insufficient permissions.
    """

    def __init__(
        self,
        *,
        client: "HearthClient",
        mode: str,
        permission: Optional[str] = None,
        audience: Optional[str] = None,
    ) -> None:
        self._client = client
        self._mode = mode
        self._permission = permission
        self._audience = audience

    def __call__(self, request: Request) -> VerifiedClaims:
        """FastAPI calls this with the injected ``request: Request`` argument."""
        from fastapi import HTTPException

        # FastAPI injects the real Request; tests pass a mock with .headers dict.
        headers: dict = getattr(request, "headers", {})
        auth_header: str = headers.get("authorization", "") or headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Missing or malformed Authorization header",
                headers={"WWW-Authenticate": 'Bearer realm="hearth"'},
            )

        token = auth_header[7:]

        # required_action tokens must never be accepted for general API access (spec §6 rule 6).
        try:
            raw = Claims.decode(token)
            if raw.token_type() == "required_action":
                raise HTTPException(
                    status_code=401,
                    detail="Required actions pending — complete required actions first",
                    headers={"WWW-Authenticate": 'Bearer realm="hearth", error="required_action"'},
                )
        except HTTPException:
            raise
        except Exception:
            # decode failure handled below via verify_token
            pass

        try:
            claims = self._client.verify_token(token, audience=self._audience)
        except (TokenExpiredError, TokenInvalidError, TokenNotYetValidError,
                TokenIssuerError, TokenAudienceError, HearthSdkError) as exc:
            raise HTTPException(
                status_code=401,
                detail=str(exc),
                headers={"WWW-Authenticate": 'Bearer realm="hearth", error="invalid_token"'},
            ) from exc

        verified = VerifiedClaims.from_claims(claims)

        if self._permission is not None and not verified.has_permission(self._permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission required: {self._permission}",
            )

        return verified


# ---------------------------------------------------------------------------
# require_permission() — Annotated shorthand
# ---------------------------------------------------------------------------

def require_permission(
    permission: str,
    *,
    dep: HearthFastAPIDep,
) -> type:
    """Return an ``Annotated[VerifiedClaims, Depends(...)]`` type alias.

    Use this as a type annotation in route handler signatures to both declare
    the permission requirement and inject the verified claims::

        WriteDoc = require_permission("docs.write", dep=auth)

        @app.post("/docs")
        def create_doc(claims: WriteDoc):
            ...

    :param permission: The permission string to enforce.
    :param dep: A :class:`HearthFastAPIDep` configured with at least ``client``
        and ``mode``.  A new dep sharing the same client/mode but with
        *permission* attached is created internally.
    :returns: ``Annotated[VerifiedClaims, Depends(gating_dep)]``
    """
    from fastapi import Depends

    gating_dep = HearthFastAPIDep(
        client=dep._client,
        mode=dep._mode,
        permission=permission,
        audience=dep._audience,
    )
    return Annotated[VerifiedClaims, Depends(gating_dep)]


# ---------------------------------------------------------------------------
# HearthSettings — optional pydantic-settings integration
# ---------------------------------------------------------------------------

try:
    from pydantic_settings import BaseSettings

    class HearthSettings(BaseSettings):
        """Pydantic-settings model for Hearth configuration via environment variables.

        Reads variables with the ``HEARTH_`` prefix::

            HEARTH_BASE_URL=https://auth.example.com
            HEARTH_REALM_ID=my-realm
            HEARTH_CLIENT_ID=my-client          # optional
            HEARTH_CLIENT_SECRET=my-secret      # optional

        Usage::

            settings = HearthSettings()
            client = settings.to_client()
        """

        base_url: str = ""
        realm_id: str = ""
        client_id: Optional[str] = None
        client_secret: Optional[str] = None

        model_config = {"env_prefix": "HEARTH_"}

        def to_client(self) -> "HearthClient":
            """Construct a :class:`~hearth.client.HearthClient` from these settings."""
            from .client import HearthClient
            return HearthClient(
                base_url=self.base_url,
                realm_id=self.realm_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )

except ImportError:
    # pydantic-settings is optional; define a placeholder so imports don't fail.
    class HearthSettings:  # type: ignore[no-redef]
        """HearthSettings requires ``pydantic-settings``; install it with
        ``pip install pydantic-settings``.
        """

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise ImportError(
                "HearthSettings requires pydantic-settings. "
                "Install it with: pip install pydantic-settings"
            )
