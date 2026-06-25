"""HearthClient: OAuth auth flows, RBAC predicates, and API operations."""

from __future__ import annotations

import base64
import json
import time
from typing import Optional, Dict, Any, List

import httpx

from .claims import Claims
from .errors import (
    ConfigurationError,
    HearthError,
    JWKSFetchError,
    TokenAudienceError,
    TokenExpiredError,
    TokenInvalidError,
    TokenIssuerError,
    TokenNotYetValidError,
)
from .types import (
    BootstrapResponse,
    AuthorizeResponse,
    DeviceAuthorizationResponse,
    SvDeltaResponse,
    SvSnapshotResponse,
    TokenResponse,
    UserInfoResponse,
    MePermissionsResponse,
    JwksDocument,
    OAuthClient,
    RegisterClientRequest,
    CheckPermissionResponse,
    IntrospectResponse,
)


class HearthClient:
    """Client for Hearth OAuth flows, userinfo, and RBAC predicates.

    RBAC predicate methods (has_permission, has_role, in_group, in_org)
    decode the JWT locally — no network call needed.

    Attributes:
        base_url: The Hearth server base URL (e.g. ``https://auth.example.com``).
        realm_id: The realm identifier for all scoped requests.
    """

    def __init__(
        self,
        base_url: str,
        realm_id: str,
        access_token: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        jwks_ttl: Optional[float] = None,
        timeout: float = 30.0,
    ):
        self._base = base_url.rstrip("/")
        self._realm = realm_id
        self._token = access_token
        self._client_id = client_id
        self._client_secret = client_secret
        self._jwks_ttl = jwks_ttl
        self._jwks_cache: Optional[Any] = None  # JwksCache, lazily initialised
        self._http = httpx.Client(
            headers={"X-Realm-ID": realm_id},
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Static bootstrap (dev-only)
    # ------------------------------------------------------------------

    @staticmethod
    def bootstrap(base_url: str) -> BootstrapResponse:
        """Bootstrap a dev server, returning admin credentials (dev mode only)."""
        resp = httpx.post(f"{base_url.rstrip('/')}/admin/bootstrap")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return BootstrapResponse(**resp.json())

    # ------------------------------------------------------------------
    # OAuth flows
    # ------------------------------------------------------------------

    def authorize(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str = "openid",
        state: str = "",
        resource: Optional[str] = None,
    ) -> AuthorizeResponse:
        """Initiate an OAuth 2.0 authorization code request."""
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": state,
        }
        if resource:
            params["resource"] = resource

        resp = self._http.get(f"{self._base}/authorize", params=params)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return AuthorizeResponse(**resp.json())

    def exchange_code(
        self,
        code: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> TokenResponse:
        """Exchange an authorization code for tokens."""
        body = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        }
        if code_verifier:
            body["code_verifier"] = code_verifier

        resp = self._http.post(f"{self._base}/token", data=body)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return TokenResponse(**resp.json())

    def refresh_tokens(
        self,
        refresh_token: str,
        client_id: str,
        client_secret: str,
    ) -> TokenResponse:
        """Refresh an access token."""
        resp = self._http.post(
            f"{self._base}/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return TokenResponse(**resp.json())

    def register_client(self, req: RegisterClientRequest) -> OAuthClient:
        """Register a new OAuth client (requires admin/realm token)."""
        resp = self._http.post(
            f"{self._base}/clients", json=req.model_dump(exclude_none=True)
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return OAuthClient(**resp.json())

    # ------------------------------------------------------------------
    # Protected endpoints
    # ------------------------------------------------------------------

    def userinfo(self, access_token: Optional[str] = None) -> UserInfoResponse:
        """Retrieve OpenID Connect userinfo."""
        token = access_token or self._token
        if not token:
            raise HearthError(401, "no access token provided")
        resp = self._http.get(
            f"{self._base}/userinfo",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return UserInfoResponse(**resp.json())

    def permissions(self, access_token: Optional[str] = None) -> MePermissionsResponse:
        """Retrieve the current user's effective permissions."""
        token = access_token or self._token
        if not token:
            raise HearthError(401, "no access token provided")
        resp = self._http.get(
            f"{self._base}/v1/me/permissions",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return MePermissionsResponse(**resp.json())

    def jwks(self) -> JwksDocument:
        """Fetch the JSON Web Key Set document."""
        resp = self._http.get(f"{self._base}/.well-known/jwks.json")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return JwksDocument(**resp.json())

    def discovery(self) -> Dict[str, Any]:
        """Fetch the OIDC discovery document."""
        resp = self._http.get(f"{self._base}/.well-known/openid-configuration")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return resp.json()

    # ------------------------------------------------------------------
    # RBAC predicates (local, no network call)
    # ------------------------------------------------------------------

    @staticmethod
    def has_permission(token: str, permission: str) -> bool:
        """Check whether the JWT contains a specific permission."""
        try:
            return Claims.decode(token).hasPermission(permission)
        except Exception:
            return False

    @staticmethod
    def has_role(token: str, role: str) -> bool:
        """Check whether the JWT contains a specific role."""
        try:
            return Claims.decode(token).hasRole(role)
        except Exception:
            return False

    @staticmethod
    def in_group(token: str, group_slug: str) -> bool:
        """Check whether the JWT indicates membership in a group."""
        try:
            return Claims.decode(token).in_group(group_slug)
        except Exception:
            return False

    @staticmethod
    def in_org(token: str, org_id: str) -> bool:
        """Check whether the JWT is scoped to a specific organization."""
        try:
            return Claims.decode(token).in_org(org_id)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Permission delivery (HEA-921 — decision + introspection modes)
    # ------------------------------------------------------------------

    def check_permission(
        self,
        access_token: str,
        permission: str,
        organization_id: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> CheckPermissionResponse:
        """Call POST /oauth/authorize to check a permission (decision mode).

        This is the *decision-mode* counterpart to the local ``has_permission``
        predicate.  The server resolves live RBAC state and returns an explicit
        ``allowed`` / ``denied`` decision.

        Fail-closed per spec §15.3: any network or server error returns
        ``CheckPermissionResponse(allowed=False)`` rather than raising.

        :param access_token: Bearer token to check on behalf of.
        :param permission: Permission string to check, e.g. ``"docs.write"``.
        :param organization_id: Optionally scope the check to an organisation.
        :param resource: Optional RFC 8707 resource indicator.
        """
        try:
            body: Dict[str, Any] = {"permission": permission}
            if organization_id is not None:
                body["organization_id"] = organization_id
            if resource is not None:
                body["resource"] = resource
            resp = self._http.post(
                f"{self._base}/oauth/authorize",
                json=body,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if resp.status_code != 200:
                return CheckPermissionResponse(allowed=False)
            return CheckPermissionResponse(**resp.json())
        except Exception:
            return CheckPermissionResponse(allowed=False)

    def introspect(
        self,
        access_token: str,
        client_id: str,
        client_secret: Optional[str] = None,
        token_type_hint: Optional[str] = None,
    ) -> IntrospectResponse:
        """Call POST /realms/{realm_id}/introspect (RFC 7662) to inspect a token.

        The response includes a ``mode`` field echoing the ``access_token_authorization``
        setting on the issuing client.  Callers in introspection mode MUST compare this
        against their configured expected mode and reject on mismatch.

        :raises HearthError: on non-200 HTTP responses.
        """
        body: Dict[str, Any] = {"token": access_token, "client_id": client_id}
        if client_secret is not None:
            body["client_secret"] = client_secret
        if token_type_hint is not None:
            body["token_type_hint"] = token_type_hint
        resp = self._http.post(
            f"{self._base}/realms/{self._realm}/introspect",
            json=body,
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return IntrospectResponse(**resp.json())

    # ------------------------------------------------------------------
    # WebAuthn
    # ------------------------------------------------------------------

    def webauthn_register_begin(
        self, rp_id: str = "", discoverable: bool = True
    ) -> dict:
        """Start a WebAuthn registration ceremony."""
        body = {"rp_id": rp_id, "discoverable": discoverable}
        resp = self._http.post(f"{self._base}/webauthn/register/begin", json=body)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return resp.json()

    def webauthn_register_complete(
        self,
        client_data_json: str,
        attestation_object: str,
        origin: str,
        discoverable: bool = False,
    ) -> dict:
        """Complete a WebAuthn registration ceremony."""
        body = {
            "client_data_json": client_data_json,
            "attestation_object": attestation_object,
            "origin": origin,
            "discoverable": discoverable,
        }
        resp = self._http.post(f"{self._base}/webauthn/register/complete", json=body)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return resp.json()

    def webauthn_auth_begin(
        self, rp_id: str = "", user_id: Optional[str] = None
    ) -> dict:
        """Start a WebAuthn authentication ceremony."""
        body: dict = {"rp_id": rp_id}
        if user_id:
            body["user_id"] = user_id
        resp = self._http.post(f"{self._base}/webauthn/auth/begin", json=body)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return resp.json()

    def webauthn_auth_complete(
        self,
        credential_id: str,
        client_data_json: str,
        authenticator_data: str,
        signature: str,
        origin: str,
        user_handle: Optional[str] = None,
    ) -> dict:
        """Complete a WebAuthn authentication ceremony."""
        body = {
            "credential_id": credential_id,
            "client_data_json": client_data_json,
            "authenticator_data": authenticator_data,
            "signature": signature,
            "origin": origin,
        }
        if user_handle:
            body["user_handle"] = user_handle
        resp = self._http.post(f"{self._base}/webauthn/auth/complete", json=body)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return resp.json()

    # ------------------------------------------------------------------
    # §2 — verify_token: full EdDSA/Ed25519 local signature verification
    # ------------------------------------------------------------------

    def verify_token(
        self,
        token: str,
        audience: Optional[str] = None,
        issuer_url: Optional[str] = None,
    ) -> Claims:
        """Verify a JWT locally using JWKS-based Ed25519 signature verification.

        Performs all five mandatory validation steps (spec §2) in order:

        1. Verify Ed25519 signature against cached JWKS keys.
        2. Verify ``exp`` claim (reject if expired).
        3. Verify ``iss`` matches the configured ``base_url`` (or *issuer_url*).
        4. Verify ``aud`` contains *audience* (server SDKs only; skipped when None).
        5. Verify ``iat`` is not more than 5 s in the future.

        :param token: Raw JWT string.
        :param audience: Expected ``aud`` value.  When ``None``, audience is not checked.
        :param issuer_url: Expected ``iss`` value.  Defaults to ``base_url``.
        :returns: :class:`~hearth.claims.Claims` on success.
        :raises TokenInvalidError: Structural failure or bad signature.
        :raises TokenExpiredError: ``exp`` is in the past.
        :raises TokenIssuerError: ``iss`` does not match.
        :raises TokenAudienceError: ``aud`` does not include the expected value.
        :raises TokenNotYetValidError: ``iat`` is more than 5 s in the future.
        :raises JWKSFetchError: JWKS endpoint unreachable.
        """
        from cryptography.exceptions import InvalidSignature

        parts = token.split(".")
        if len(parts) != 3:
            raise TokenInvalidError("expected three dot-separated segments")

        try:
            header_bytes = base64.urlsafe_b64decode(parts[0] + "==")
            header: Dict[str, Any] = json.loads(header_bytes)
        except Exception as exc:
            raise TokenInvalidError(f"failed to decode JWT header: {exc}") from exc

        alg = header.get("alg")
        if alg != "EdDSA":
            raise TokenInvalidError(f"unsupported algorithm: {alg!r}")

        kid: str = header.get("kid") or ""

        # Lazy-init JWKS cache.
        if self._jwks_cache is None:
            from .jwks import JwksCache
            self._jwks_cache = JwksCache(
                f"{self._base}/.well-known/jwks.json",
                ttl=self._jwks_ttl,
            )

        pub_key = self._jwks_cache.get_key(kid)

        # Verify signature: message = header.payload (ASCII bytes).
        message = f"{parts[0]}.{parts[1]}".encode("ascii")
        try:
            sig_bytes = base64.urlsafe_b64decode(parts[2] + "==")
        except Exception as exc:
            raise TokenInvalidError(f"failed to decode JWT signature: {exc}") from exc

        try:
            pub_key.verify(sig_bytes, message)
        except InvalidSignature as exc:
            raise TokenInvalidError("signature verification failed") from exc

        # Decode payload claims.
        try:
            payload_bytes = base64.urlsafe_b64decode(parts[1] + "==")
            payload: Dict[str, Any] = json.loads(payload_bytes)
        except Exception as exc:
            raise TokenInvalidError(f"failed to decode JWT payload: {exc}") from exc

        now = int(time.time())

        # Step 2: exp
        exp = payload.get("exp")
        if exp is not None and now > int(exp):
            raise TokenExpiredError(int(exp))

        # Step 3: iss
        expected_iss = (issuer_url or self._base).rstrip("/")
        actual_iss = str(payload.get("iss", ""))
        if actual_iss != expected_iss:
            raise TokenIssuerError(expected=expected_iss, actual=actual_iss)

        # Step 4: aud (server SDKs only, skipped when audience is None)
        if audience is not None:
            aud = payload.get("aud", [])
            if isinstance(aud, str):
                aud = [aud]
            if audience not in aud:
                raise TokenAudienceError(expected=audience, actual=list(aud))

        # Step 5: iat — must not be more than 5 s in the future
        iat = payload.get("iat")
        if iat is not None and int(iat) > now + 5:
            raise TokenNotYetValidError(int(iat))

        return Claims(payload)

    # ------------------------------------------------------------------
    # §4.5.1 — client_credentials (M2M)
    # ------------------------------------------------------------------

    def client_credentials(self, scope: Optional[str] = None) -> TokenResponse:
        """Obtain a token using the Client Credentials grant (RFC 6749 §4.4).

        :param scope: Optional space-delimited scope string.
        :raises ConfigurationError: if ``client_id`` or ``client_secret`` are missing.
        :raises HearthError: on non-200 responses.
        """
        if not self._client_id:
            raise ConfigurationError("client_id is required for client_credentials flow")
        if not self._client_secret:
            raise ConfigurationError("client_secret is required for client_credentials flow")

        body: Dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if scope is not None:
            body["scope"] = scope

        resp = self._http.post(
            f"{self._base}/realms/{self._realm}/token",
            data=body,
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return TokenResponse(**resp.json())

    # ------------------------------------------------------------------
    # §4.5.2 — Device Authorization Flow
    # ------------------------------------------------------------------

    def start_device_flow(
        self, scope: Optional[str] = None
    ) -> DeviceAuthorizationResponse:
        """Initiate the Device Authorization Flow (RFC 8628).

        :param scope: Optional scope string.
        :raises ConfigurationError: if ``client_id`` is missing.
        :raises HearthError: on non-200 responses.
        """
        if not self._client_id:
            raise ConfigurationError("client_id is required for device authorization flow")

        body: Dict[str, str] = {"client_id": self._client_id}
        if scope is not None:
            body["scope"] = scope

        resp = self._http.post(
            f"{self._base}/realms/{self._realm}/device/authorize",
            data=body,
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return DeviceAuthorizationResponse(**resp.json())

    def poll_device_token(
        self,
        device_code: str,
        client_id: Optional[str] = None,
    ) -> Optional[TokenResponse]:
        """Poll the token endpoint for Device Flow completion (RFC 8628 §3.4).

        Returns ``None`` when authorization is still pending (``authorization_pending``
        or ``slow_down``).  The caller owns the sleep loop.

        :param device_code: The ``device_code`` from :meth:`start_device_flow`.
        :param client_id: Override client ID (falls back to constructor value).
        :raises TokenExpiredError: when the device code has expired.
        :raises HearthError: on other fatal errors (e.g. ``access_denied``).
        """
        cid = client_id or self._client_id
        if not cid:
            raise ConfigurationError("client_id is required for device flow polling")

        body: Dict[str, str] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": cid,
        }
        if self._client_secret:
            body["client_secret"] = self._client_secret

        resp = self._http.post(
            f"{self._base}/realms/{self._realm}/token",
            data=body,
        )

        if resp.status_code == 200:
            return TokenResponse(**resp.json())

        # Parse error body.
        try:
            error_body = resp.json()
            error = error_body.get("error", "")
        except Exception:
            error = ""

        if error in ("authorization_pending", "slow_down"):
            return None

        if error == "expired_token":
            raise TokenExpiredError(0, "device code expired")

        raise HearthError(resp.status_code, resp.text)

    # ------------------------------------------------------------------
    # §4.5.3 — Magic Link initiation (passwordless)
    # ------------------------------------------------------------------

    def request_magic_link(self, email: str) -> None:
        """Request a magic-link email for passwordless sign-in (§4.5.3).

        Always silently succeeds on 202 (enumeration resistance).

        :param email: The email address to send the magic link to.
        :raises HearthError: on non-202 responses (e.g. HTTP 429 rate limit).
        """
        resp = self._http.post(
            f"{self._base}/v1/{self._realm}/auth/magic-link",
            json={"email": email},
        )
        if resp.status_code == 202:
            return
        raise HearthError(resp.status_code, resp.text)

    # ------------------------------------------------------------------
    # Session-version feed (HEA-930)
    # ------------------------------------------------------------------

    def sv_snapshot(self, access_token: str) -> SvSnapshotResponse:
        """Fetch the full session-version snapshot.

        Requires ``hearth.sv_feed`` permission on *access_token*.

        :param access_token: Bearer token with ``hearth.sv_feed`` permission.
        :raises HearthError: on non-200 responses.
        """
        resp = self._http.get(
            f"{self._base}/oauth/session-versions/snapshot",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return SvSnapshotResponse(**resp.json())

    def sv_delta(
        self, access_token: str, since: int, limit: Optional[int] = None
    ) -> Optional[SvDeltaResponse]:
        """Fetch session-version deltas since sequence number *since*.

        Returns ``None`` when there are no new deltas (HTTP 204).

        :param access_token: Bearer token with ``hearth.sv_feed`` permission.
        :param since: Only return events with seq > since.
        :param limit: Maximum number of deltas (default: server-side default of 1000).
        :raises HearthError: on error responses (including 400 when *since* is
            older than the retention window).
        """
        params: Dict[str, Any] = {"since": since}
        if limit is not None:
            params["limit"] = limit

        resp = self._http.get(
            f"{self._base}/oauth/session-versions",
            params=params,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if resp.status_code == 204:
            return None
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return SvDeltaResponse(**resp.json())

    def close(self):
        """Close the underlying HTTP client."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
