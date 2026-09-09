"""Shared signing helpers for the SDK test suite.

The embedded-mode authorization gates verify a token before reading its claims,
so a test that expects a request to be *allowed* must present a token this
module signed, against a client this module seeded with the matching key.

``install_test_key`` seeds the client's JWKS cache directly, so no HTTP mock is
needed for the common case; use ``respx`` only when the fetch itself is under
test.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TEST_KID = "test-kid"

# One key pair for the whole suite — deterministic within a process, and the
# tests never need key rotation.
_PRIVATE_KEY = Ed25519PrivateKey.generate()
_PUBLIC_KEY = _PRIVATE_KEY.public_key()


class _SeededJwksCache:
    """A JwksCache stand-in that always returns the suite's test public key."""

    def __init__(self, public_key) -> None:
        self._public_key = public_key

    def get_key(self, kid: str):  # noqa: ARG002 — one key, kid is irrelevant
        return self._public_key


def install_test_key(client):
    """Seed *client*'s JWKS cache with the suite's public key and return it."""
    client._jwks_cache = _SeededJwksCache(_PUBLIC_KEY)
    return client


def sign_jwt(
    payload: Dict[str, Any],
    *,
    issuer: Optional[str] = "http://localhost:8420",
    kid: str = TEST_KID,
) -> str:
    """Sign *payload* with the suite's Ed25519 key, filling in iss/exp/iat."""
    import jwt as pyjwt

    body = dict(payload)
    now = int(time.time())
    if issuer is not None:
        body.setdefault("iss", issuer)
    body.setdefault("exp", now + 3600)
    body.setdefault("iat", now)
    return pyjwt.encode(body, _PRIVATE_KEY, algorithm="EdDSA", headers={"kid": kid})


def unsigned_jwt(payload: Dict[str, Any]) -> str:
    """Build an ``alg: none`` token — an attacker's forgery, never acceptable."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}."
