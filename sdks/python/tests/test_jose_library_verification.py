"""sdk-standard-libraries 2.3 — tokens are verified by PyJWT, not by SDK code.

The ``sdk-support-contract`` capability requires each SDK to check signatures,
JWKS keys and registered claims through a widely used JOSE library. These
tests pin the observable contract (tampered, unsigned and unknown-kid tokens
fail; a good Ed25519 token returns its claims) and the structural one (no
direct Ed25519/RSA ``verify`` call is left in the package source).

Run with:  .venv/bin/pytest tests/test_jose_library_verification.py -v
"""

from __future__ import annotations

import base64
import json
import pathlib
import re
import time

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ISSUER = "http://localhost:8420"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"
KID = "ed-1"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def jwks(respx_mock, private_key):
    x = _b64u(private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    doc = {
        "keys": [
            {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": KID, "alg": "EdDSA"},
        ]
    }
    respx_mock.get(JWKS_URL).mock(return_value=httpx.Response(200, json=doc))
    return doc


def _payload(**extra) -> dict:
    now = int(time.time())
    return {"sub": "user-abc", "iss": ISSUER, "exp": now + 3600, "iat": now, **extra}


def _sign(private_key, payload: dict, kid: str = KID) -> str:
    return pyjwt.encode(payload, private_key, algorithm="EdDSA", headers={"kid": kid})


def _client():
    from hearth.client import HearthClient

    return HearthClient(ISSUER, realm_id="realm-1")


def test_ed25519_token_validates(jwks, private_key):
    claims = _client().verify_token(_sign(private_key, _payload(scope="read")))
    assert claims.subject() == "user-abc"
    assert claims.scope() == "read"


def test_tampered_payload_fails(jwks, private_key):
    from hearth.errors import TokenInvalidError

    header, _body, sig = _sign(private_key, _payload()).split(".")
    forged = _b64u(json.dumps(_payload(sub="admin")).encode())
    with pytest.raises(TokenInvalidError):
        _client().verify_token(f"{header}.{forged}.{sig}")


def test_alg_none_fails(jwks):
    from hearth.errors import TokenInvalidError

    header = _b64u(json.dumps({"alg": "none", "kid": KID}).encode())
    body = _b64u(json.dumps(_payload()).encode())
    with pytest.raises(TokenInvalidError):
        _client().verify_token(f"{header}.{body}.")


def test_unknown_kid_fails(jwks, private_key):
    from hearth.errors import TokenInvalidError

    with pytest.raises(TokenInvalidError):
        _client().verify_token(_sign(private_key, _payload(), kid="not-published"))


def test_missing_aud_claim_fails_when_an_audience_is_expected(jwks, private_key):
    from hearth.errors import TokenAudienceError

    with pytest.raises(TokenAudienceError) as excinfo:
        _client().verify_token(_sign(private_key, _payload()), audience="client-1")
    assert excinfo.value.actual == []


def test_missing_iss_claim_fails(jwks, private_key):
    from hearth.errors import TokenIssuerError

    payload = _payload()
    del payload["iss"]
    with pytest.raises(TokenIssuerError) as excinfo:
        _client().verify_token(_sign(private_key, payload))
    assert excinfo.value.expected == ISSUER


def test_expired_error_carries_the_exp_claim(jwks, private_key):
    from hearth.errors import TokenExpiredError

    exp = int(time.time()) - 60
    with pytest.raises(TokenExpiredError) as excinfo:
        _client().verify_token(_sign(private_key, _payload(exp=exp)))
    assert excinfo.value.expired_at == exp


def test_jwks_cache_holds_pyjwk_keys(jwks):
    from hearth.jwks import JwksCache

    key = JwksCache(JWKS_URL).get_key(KID)
    assert isinstance(key, pyjwt.PyJWK)
    assert key.algorithm_name == "EdDSA"


def test_no_handwritten_signature_check_remains():
    """No direct Ed25519/RSA verify call in the package (the library does it)."""
    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "hearth"
    offenders = [
        f"{path.name}:{lineno}"
        for path in sorted(src.rglob("*.py"))
        for lineno, line in enumerate(path.read_text().splitlines(), start=1)
        if re.search(r"\.verify\(|Ed25519PublicKey|InvalidSignature", line)
    ]
    assert offenders == []
