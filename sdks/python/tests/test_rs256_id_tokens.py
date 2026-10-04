"""Task 26.55 — a realm JWKS may carry an RS256 ID-token key.

A realm whose clients selected ``id_token_signed_response_alg: RS256``
publishes an RSA ``id-token-signing`` key beside its Ed25519 key.
``verify_token`` verifies ACCESS tokens, which Hearth signs with EdDSA only,
so it must (a) keep verifying EdDSA tokens against such a JWKS and (b) refuse
an RS256 token even though the key that signed it is published — otherwise an
ID token could be replayed as a bearer token.

Run with:  .venv/bin/pytest tests/test_rs256_id_tokens.py -v
"""

from __future__ import annotations

import base64
import time

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ISSUER = "http://localhost:8420"
ED_KID = "ed-1"
RSA_KID = "rsa-id-token-key"


def _b64u_int(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _mixed_jwks(ed_private: Ed25519PrivateKey, rsa_private) -> dict:
    x = (
        base64.urlsafe_b64encode(
            ed_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        .rstrip(b"=")
        .decode()
    )
    numbers = rsa_private.public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": RSA_KID,
                "n": _b64u_int(numbers.n),
                "e": _b64u_int(numbers.e),
                "x-key-role": "id-token-signing",
            },
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x,
                "kid": ED_KID,
                "use": "sig",
                "alg": "EdDSA",
                "x-key-role": "access-token-signing",
            },
        ]
    }


def _payload(**extra) -> dict:
    now = int(time.time())
    return {
        "sub": "user-abc",
        "iss": ISSUER,
        "aud": "hearth",
        "exp": now + 3600,
        "iat": now,
        **extra,
    }


def _client():
    from hearth.client import HearthClient

    return HearthClient(ISSUER, realm_id="realm-1")


@pytest.fixture
def keys():
    return Ed25519PrivateKey.generate(), rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )


def test_eddsa_access_token_still_verifies_against_a_jwks_with_an_rsa_key(
    respx_mock, keys
):
    ed_private, rsa_private = keys
    respx_mock.get(f"{ISSUER}/.well-known/jwks.json").mock(
        return_value=httpx.Response(200, json=_mixed_jwks(ed_private, rsa_private))
    )
    token = pyjwt.encode(
        _payload(), ed_private, algorithm="EdDSA", headers={"kid": ED_KID}
    )

    claims = _client().verify_token(token)
    assert claims.subject() == "user-abc"


def test_rs256_token_signed_by_the_published_rsa_key_is_refused(respx_mock, keys):
    from hearth.errors import TokenInvalidError

    ed_private, rsa_private = keys
    respx_mock.get(f"{ISSUER}/.well-known/jwks.json").mock(
        return_value=httpx.Response(200, json=_mixed_jwks(ed_private, rsa_private))
    )
    id_token = pyjwt.encode(
        _payload(token_type="id_token"),
        rsa_private,
        algorithm="RS256",
        headers={"kid": RSA_KID, "typ": "JWT"},
    )

    with pytest.raises(TokenInvalidError):
        _client().verify_token(id_token)
