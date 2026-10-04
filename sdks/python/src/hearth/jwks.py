"""JWKS key cache with TTL (spec §2).

Caches Ed25519/OKP public keys by ``kid`` as PyJWT :class:`jwt.PyJWK` objects, so the
signature check itself is PyJWT's (``jwt.decode``), never SDK code.  Respects
``Cache-Control: max-age``
from the server, capped at 24 hours.  Re-fetches once on a cache miss before
raising :exc:`~hearth.errors.TokenInvalidError` (an unknown ``kid``);
:exc:`~hearth.errors.JWKSFetchError` is kept for an unreachable or invalid
endpoint.
"""

from __future__ import annotations

import time

import httpx
import jwt

from .errors import JWKSFetchError, TokenInvalidError

#: Default TTL when the server provides no Cache-Control header (5 minutes).
_DEFAULT_TTL = 300.0
#: Hard maximum cache age regardless of Cache-Control (24 hours, spec §2 rule 5).
_MAX_AGE = 86400.0


class JwksCache:
    """Thread-unsafe JWKS cache.  Holds Ed25519 :class:`jwt.PyJWK` keys keyed by ``kid``.

    :param jwks_url: Full URL of the JWKS endpoint.
    :param ttl: Override cache TTL in seconds (default: respect ``Cache-Control``,
        fall back to 5 minutes).
    :param timeout: HTTP request timeout in seconds (default: 10).
    """

    def __init__(
        self,
        jwks_url: str,
        ttl: float | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._url = jwks_url
        self._configured_ttl: float = ttl if ttl is not None else _DEFAULT_TTL
        self._ttl: float = self._configured_ttl
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at: float = 0.0
        self._http = httpx.Client(timeout=timeout)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get_key(self, kid: str) -> jwt.PyJWK:
        """Return the cached Ed25519 key for *kid*.

        Fetches the JWKS endpoint if the cache is stale.  On a cache miss,
        re-fetches once before raising :exc:`~hearth.errors.TokenInvalidError`.

        :raises JWKSFetchError: if the JWKS endpoint is unreachable or invalid.
        :raises TokenInvalidError: if *kid* is not published after re-fetching
            (openspec/specs/sdk-support-contract/spec.md: an unknown ``kid`` is a bad token, not a fetch failure).
        """
        if self._is_stale():
            self._fetch()

        if kid not in self._keys:
            # Spec §2 rule 3: re-fetch once on cache miss.
            self._fetch()

        if kid not in self._keys:
            raise TokenInvalidError(f"no JWKS key for kid={kid!r}")
        return self._keys[kid]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_stale(self) -> bool:
        return (time.time() - self._fetched_at) > min(self._ttl, _MAX_AGE)

    def _fetch(self) -> None:
        try:
            resp = self._http.get(self._url)
        except httpx.HTTPError as exc:
            raise JWKSFetchError(
                f"JWKS fetch failed: {exc}", url=self._url, cause=exc
            ) from exc

        if resp.status_code != 200:
            raise JWKSFetchError(
                f"JWKS fetch failed: HTTP {resp.status_code}", url=self._url
            )

        # Honour Cache-Control: max-age, capped at 24 h.
        cc = resp.headers.get("cache-control", "")
        ttl = self._configured_ttl
        for part in cc.split(","):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    ttl = float(part[8:])
                except ValueError:
                    pass
        self._ttl = min(ttl, _MAX_AGE)

        try:
            data = resp.json()
        except Exception as exc:
            raise JWKSFetchError(
                f"JWKS parse failed: {exc}", url=self._url, cause=exc
            ) from exc

        for key in data.get("keys", []):
            kty = key.get("kty", "")
            if kty != "OKP":
                # Spec §2: skip (do not error on) unrecognised kty values.
                continue
            if key.get("crv") != "Ed25519":
                continue
            try:
                self._keys[key.get("kid", "")] = jwt.PyJWK(key, algorithm="EdDSA")
            except jwt.PyJWTError:
                # A malformed key entry is skipped, not fatal.
                continue

        self._fetched_at = time.time()
