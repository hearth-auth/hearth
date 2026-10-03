"""HearthClient: OAuth auth flows, RBAC predicates, and API operations."""

from __future__ import annotations

from typing import Any

import httpx
import jwt

from .claims import Claims
from .errors import (
    ConfigurationError,
    HearthError,
    TokenAudienceError,
    TokenExpiredError,
    TokenInvalidError,
    TokenIssuerError,
    TokenNotYetValidError,
)
from .types import (
    AuthorizeResponse,
    BootstrapResponse,
    CheckPermissionResponse,
    DeviceAuthorizationResponse,
    IntrospectResponse,
    JwksDocument,
    LoginBeginResult,
    MePermissionsResponse,
    OAuthClient,
    RegisterClientRequest,
    SvDeltaResponse,
    SvSnapshotResponse,
    TokenResponse,
    UserInfoResponse,
)

#: Clock-skew allowance for ``exp``, ``nbf`` and ``iat``, in seconds (SDK spec §2).
_CLOCK_SKEW_SECONDS = 5


def _claims_after_decode(token: str) -> dict[str, Any]:
    """Read the claims of a token that ``jwt.decode`` refused on a claim.

    Only the error arms of ``verify_token`` call this, to fill the error's
    fields. PyJWT checks the signature before any claim, so a claim error
    means the signature was good.
    """
    return jwt.decode(token, options={"verify_signature": False})


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
        access_token: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        jwks_ttl: float | None = None,
        timeout: float = 30.0,
    ):
        self._base = base_url.rstrip("/")
        self._realm = realm_id
        self._token = access_token
        self._client_id = client_id
        self._client_secret = client_secret
        self._jwks_ttl = jwks_ttl
        self._jwks_cache: Any | None = None  # JwksCache, lazily initialised
        self._http = httpx.Client(
            headers={"X-Realm-ID": realm_id},
            timeout=timeout,
        )

    def _post_realm_path(self, url: str, **kwargs: Any) -> httpx.Response:
        """POST to a ``/realms/{realm}/...`` endpoint without ``X-Realm-ID``.

        The path names the realm. The server refuses an ``X-Realm-ID`` that
        does not resolve to that realm (``400 realm_mismatch``), and
        ``realm_id`` here is the realm name, not its UUID.
        """
        request = self._http.build_request("POST", url, **kwargs)
        del request.headers["X-Realm-ID"]
        return self._http.send(request)

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

    def begin_login(
        self,
        redirect_uri: str,
        scopes: str | None = None,
    ) -> LoginBeginResult:
        """Begin an authorization-code login: generate PKCE, build the authorization URL.

        Developer flow:

        1. Call ``begin_login(redirect_uri)`` — receive a :class:`LoginBeginResult`.
        2. Persist ``result.state`` and ``result.code_verifier`` in session storage.
        3. Redirect the browser to ``result.authorization_url``.
        4. On the callback route, call ``complete_login(code, code_verifier, redirect_uri)``.

        :param redirect_uri: Callback URL registered with the authorization server.
        :param scopes: Space-delimited scope string (defaults to ``"openid"``).
        :raises ConfigurationError: if ``client_id`` is not set.
        """
        import secrets
        import urllib.parse

        from .pkce import generate_pkce_pair

        if not self._client_id:
            raise ConfigurationError("client_id is required for begin_login")

        pkce = generate_pkce_pair()
        state = secrets.token_urlsafe(16)

        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
            "scope": scopes or "openid",
            "state": state,
            "code_challenge": pkce.code_challenge,
            "code_challenge_method": "S256",
        }
        authorization_url = f"{self._base}/authorize?" + urllib.parse.urlencode(params)
        return LoginBeginResult(
            authorization_url=authorization_url,
            state=state,
            code_verifier=pkce.code_verifier,
        )

    def complete_login(
        self,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> TokenResponse:
        """Complete an authorization-code login: exchange the callback code for tokens.

        :param code: Authorization code from the callback ``code`` query parameter.
        :param code_verifier: PKCE verifier returned by :meth:`begin_login`.
        :param redirect_uri: Same ``redirect_uri`` used in :meth:`begin_login`.
        :raises ConfigurationError: if ``client_id`` or ``client_secret`` are not set.
        :raises HearthError: on non-200 HTTP responses.
        """
        if not self._client_id or not self._client_secret:
            raise ConfigurationError(
                "client_id and client_secret are required for complete_login"
            )
        return self.exchange_code(
            code, self._client_id, self._client_secret, redirect_uri, code_verifier
        )

    def authorize(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str = "openid",
        state: str = "",
        resource: str | None = None,
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
        code_verifier: str | None = None,
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

    def register_client(
        self, req: RegisterClientRequest, access_token: str | None = None
    ) -> OAuthClient:
        """Register a new OAuth client via the admin ``POST /clients`` endpoint.

        This is an admin operation: the bearer token (``access_token``, or the
        one this client was constructed with) must carry
        ``hearth.clients.admin`` (or ``hearth.admin``) in this client's realm.

        Raises:
            HearthError: 401 without any token (no request is sent), or the
                server's status on any non-2xx response.
        """
        token = access_token or self._token
        if not token:
            raise HearthError(401, "no access token provided")
        resp = self._http.post(
            f"{self._base}/clients",
            json=req.model_dump(exclude_none=True, by_alias=True),
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code not in (200, 201):
            raise HearthError(resp.status_code, resp.text)
        return OAuthClient.model_validate(resp.json())

    # ------------------------------------------------------------------
    # Protected endpoints
    # ------------------------------------------------------------------

    def userinfo(self, access_token: str | None = None) -> UserInfoResponse:
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

    def permissions(self, access_token: str | None = None) -> MePermissionsResponse:
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

    def discovery(self) -> dict[str, Any]:
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
        except Exception:  # noqa: BLE001 -- fail closed: an undecodable token has no permission
            return False

    @staticmethod
    def has_role(token: str, role: str) -> bool:
        """Check whether the JWT contains a specific role."""
        try:
            return Claims.decode(token).hasRole(role)
        except Exception:  # noqa: BLE001 -- fail closed: an undecodable token has no role
            return False

    @staticmethod
    def in_group(token: str, group_slug: str) -> bool:
        """Check whether the JWT indicates membership in a group."""
        try:
            return Claims.decode(token).in_group(group_slug)
        except Exception:  # noqa: BLE001 -- fail closed: an undecodable token is in no group
            return False

    @staticmethod
    def in_org(token: str, org_id: str) -> bool:
        """Check whether the JWT is scoped to a specific organization."""
        try:
            return Claims.decode(token).in_org(org_id)
        except Exception:  # noqa: BLE001 -- fail closed: an undecodable token is in no org
            return False

    # ------------------------------------------------------------------
    # Permission delivery (HEA-921 — decision + introspection modes)
    # ------------------------------------------------------------------

    def check_permission(
        self,
        access_token: str,
        permission: str,
        organization_id: str | None = None,
        resource: str | None = None,
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
            body: dict[str, Any] = {"permission": permission}
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
        except Exception:  # noqa: BLE001 -- fail closed: any error is a deny
            return CheckPermissionResponse(allowed=False)

    def introspect(
        self,
        access_token: str,
        client_id: str,
        client_secret: str | None = None,
        token_type_hint: str | None = None,
    ) -> IntrospectResponse:
        """Call POST /realms/{realm_id}/introspect (RFC 7662) to inspect a token.

        The response includes a ``mode`` field echoing the ``access_token_authorization``
        setting on the issuing client.  Callers in introspection mode MUST compare this
        against their configured expected mode and reject on mismatch.

        Introspection serves CONFIDENTIAL clients only: Hearth answers a public
        client (``client_id`` alone) with ``401 invalid_client``, so
        ``client_secret`` is required and a missing one is refused before any
        request is sent.

        :raises ConfigurationError: when ``client_id`` or ``client_secret`` is missing.
        :raises HearthError: on non-200 HTTP responses.
        """
        if not client_id or not client_secret:
            raise ConfigurationError(
                "introspection requires a confidential client's client_id and client_secret",
                field="client_secret",
            )
        body: dict[str, Any] = {
            "token": access_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if token_type_hint is not None:
            body["token_type_hint"] = token_type_hint
        resp = self._post_realm_path(
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
        self,
        rp_id: str = "",
        discoverable: bool = True,
        *,
        password: str | None = None,
        totp_code: str | None = None,
        assertion: dict[str, Any] | None = None,
    ) -> dict:
        """Start a WebAuthn registration ceremony.

        Supply exactly one step-up proof: ``password``, ``totp_code``, or
        ``assertion`` (an assertion from an already-enrolled passkey, with
        base64url ``credential_id``, ``client_data_json``,
        ``authenticator_data`` and ``signature`` fields).

        The server answers ``403 step_up_required`` without one: an access
        token alone is one factor and does not enrol a credential.
        """
        body: dict[str, Any] = {"rp_id": rp_id, "discoverable": discoverable}
        if password is not None:
            body["password"] = password
        if totp_code is not None:
            body["totp_code"] = totp_code
        if assertion is not None:
            body["assertion"] = assertion
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

    def webauthn_auth_begin(self, rp_id: str = "", user_id: str | None = None) -> dict:
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
        user_handle: str | None = None,
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
        audience: str | None = None,
        issuer_url: str | None = None,
    ) -> Claims:
        """Verify a JWT locally using JWKS-based Ed25519 signature verification.

        Performs all mandatory validation steps (spec §2) in order:

        1. Verify Ed25519 signature against cached JWKS keys.
        2. Verify ``exp`` claim (reject if expired).
        3. Verify ``iss`` matches the configured ``base_url`` (or *issuer_url*).
        4. Verify ``aud`` contains *audience* (server SDKs only; skipped when None).
        5. Verify ``nbf`` is not more than 5 s in the future.
        6. Verify ``iat`` is not more than 5 s in the future.

        :param token: Raw JWT string.
        :param audience: Expected ``aud`` value.  When ``None``, audience is not checked.
        :param issuer_url: Expected ``iss`` value.  Defaults to ``base_url``.
        :returns: :class:`~hearth.claims.Claims` on success.
        :raises TokenInvalidError: Structural failure or bad signature.
        :raises TokenExpiredError: ``exp`` is in the past.
        :raises TokenIssuerError: ``iss`` does not match.
        :raises TokenAudienceError: ``aud`` does not include the expected value.
        :raises TokenNotYetValidError: ``nbf`` or ``iat`` is more than 5 s in the future.
        :raises TokenInvalidError: also when the token's ``kid`` is not published.
        :raises JWKSFetchError: JWKS endpoint unreachable or invalid.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenInvalidError(f"failed to decode JWT header: {exc}") from exc

        # Access tokens are EdDSA only. Refuse any other alg (``none``, an
        # RS256 ID token, HS256) before a JWKS fetch; ``jwt.decode`` below
        # enforces the same allow-list.
        alg = header.get("alg")
        if alg != "EdDSA":
            raise TokenInvalidError(f"unsupported algorithm: {alg!r}")

        # Lazy-init JWKS cache.
        if self._jwks_cache is None:
            from .jwks import JwksCache

            self._jwks_cache = JwksCache(
                f"{self._base}/.well-known/jwks.json",
                ttl=self._jwks_ttl,
            )

        key = self._jwks_cache.get_key(str(header.get("kid") or ""))
        expected_iss = (issuer_url or self._base).rstrip("/")

        # PyJWT checks the signature first, then exp, iss, aud (only when an
        # audience is configured), nbf and iat, with the spec's clock-skew
        # allowance. The except arms only map its errors onto the SDK taxonomy.
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=["EdDSA"],
                issuer=expected_iss,
                audience=audience,
                leeway=_CLOCK_SKEW_SECONDS,
                options={"verify_aud": audience is not None},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError(
                int(_claims_after_decode(token).get("exp", 0))
            ) from exc
        except jwt.ImmatureSignatureError as exc:
            claims = _claims_after_decode(token)
            raise TokenNotYetValidError(
                int(claims.get("nbf") or claims.get("iat") or 0)
            ) from exc
        except jwt.MissingRequiredClaimError as exc:
            if exc.claim == "aud":
                raise TokenAudienceError(expected=str(audience), actual=[]) from exc
            if exc.claim == "iss":
                raise TokenIssuerError(expected=expected_iss, actual="") from exc
            raise TokenInvalidError(str(exc)) from exc
        except jwt.InvalidIssuerError as exc:
            actual_iss = str(_claims_after_decode(token).get("iss", ""))
            raise TokenIssuerError(expected=expected_iss, actual=actual_iss) from exc
        except jwt.InvalidAudienceError as exc:
            aud = _claims_after_decode(token).get("aud", [])
            raise TokenAudienceError(
                expected=str(audience),
                actual=[aud] if isinstance(aud, str) else list(aud),
            ) from exc
        except jwt.PyJWTError as exc:
            raise TokenInvalidError(str(exc) or type(exc).__name__) from exc

        return Claims(payload)

    # ------------------------------------------------------------------
    # §4.5.1 — client_credentials (M2M)
    # ------------------------------------------------------------------

    def client_credentials(self, scope: str | None = None) -> TokenResponse:
        """Obtain a token using the Client Credentials grant (RFC 6749 §4.4).

        :param scope: Optional space-delimited scope string.
        :raises ConfigurationError: if ``client_id`` or ``client_secret`` are missing.
        :raises HearthError: on non-200 responses.
        """
        if not self._client_id:
            raise ConfigurationError(
                "client_id is required for client_credentials flow"
            )
        if not self._client_secret:
            raise ConfigurationError(
                "client_secret is required for client_credentials flow"
            )

        body: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if scope is not None:
            body["scope"] = scope

        resp = self._post_realm_path(
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
        self, scope: str | None = None
    ) -> DeviceAuthorizationResponse:
        """Initiate the Device Authorization Flow (RFC 8628).

        :param scope: Optional scope string.
        :raises ConfigurationError: if ``client_id`` is missing.
        :raises HearthError: on non-200 responses.
        """
        if not self._client_id:
            raise ConfigurationError(
                "client_id is required for device authorization flow"
            )

        body: dict[str, str] = {"client_id": self._client_id}
        if scope is not None:
            body["scope"] = scope

        resp = self._post_realm_path(
            f"{self._base}/realms/{self._realm}/device/authorize",
            data=body,
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return DeviceAuthorizationResponse(**resp.json())

    def poll_device_token(
        self,
        device_code: str,
        client_id: str | None = None,
    ) -> TokenResponse | None:
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

        body: dict[str, str] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": cid,
        }
        if self._client_secret:
            body["client_secret"] = self._client_secret

        resp = self._post_realm_path(
            f"{self._base}/realms/{self._realm}/token",
            data=body,
        )

        if resp.status_code == 200:
            return TokenResponse(**resp.json())

        # Parse error body.
        try:
            error_body = resp.json()
            error = error_body.get("error", "")
        except Exception:  # noqa: BLE001 -- any unparseable error body is "no error code"
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

    def exchange_magic_link(self, token: str) -> TokenResponse:
        """Exchange a magic-link token for tokens (§4.5.3 / §7.2 C-12).

        Completes the passwordless flow started by :meth:`request_magic_link`:
        posts ``grant_type=urn:hearth:grant-type:magic-link`` with the opaque
        ``token`` from the magic-link URL to the token endpoint. The token is
        sent in the form body, never the URL.

        :param token: The opaque magic-link token from the email/redirect URL.
        :raises HearthError: on a non-200 response (e.g. expired/used token).
        """
        body: dict[str, str] = {
            "grant_type": "urn:hearth:grant-type:magic-link",
            "token": token,
        }
        if self._client_id:
            body["client_id"] = self._client_id

        resp = self._post_realm_path(
            f"{self._base}/realms/{self._realm}/token",
            data=body,
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return TokenResponse(**resp.json())

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
        self, access_token: str, since: int, limit: int | None = None
    ) -> SvDeltaResponse | None:
        """Fetch session-version deltas since sequence number *since*.

        Returns ``None`` when there are no new deltas (HTTP 204).

        :param access_token: Bearer token with ``hearth.sv_feed`` permission.
        :param since: Only return events with seq > since.
        :param limit: Maximum number of deltas (default: server-side default of 1000).
        :raises HearthError: on error responses (including 400 when *since* is
            older than the retention window).
        """
        params: dict[str, Any] = {"since": since}
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
