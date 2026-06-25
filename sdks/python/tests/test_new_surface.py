"""TDD tests for new Python SDK surface: PKCE, JWKS cache, verify_token,
client_credentials, device_flow, magic_link, session_version.

Written before implementation — run with:
  .venv/bin/pytest tests/test_new_surface.py -v
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Optional
from unittest.mock import patch

import httpx
import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_ed25519_key() -> tuple:
    """Return (private_key, x_b64url, kid) for test JWT signing."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    x_b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    kid = "test-key-1"
    return private_key, x_b64, kid


def _make_jwks(x_b64: str, kid: str) -> dict:
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x_b64,
                "kid": kid,
                "use": "sig",
                "alg": "EdDSA",
            }
        ]
    }


def _sign_jwt(private_key, payload: dict, kid: str) -> str:
    """Sign a JWT with an Ed25519 private key via PyJWT."""
    import jwt as pyjwt
    return pyjwt.encode(payload, private_key, algorithm="EdDSA", headers={"kid": kid})


def _valid_payload(issuer: str = "http://localhost:8420") -> dict:
    now = int(time.time())
    return {
        "sub": "user-abc",
        "iss": issuer,
        "aud": "client-1",
        "exp": now + 3600,
        "iat": now,
    }


# ---------------------------------------------------------------------------
# §7 — PKCE generation helper
# ---------------------------------------------------------------------------

class TestPkce:
    """Tests for generate_pkce_pair() (RFC 7636)."""

    def test_returns_pair_with_verifier_and_challenge(self):
        from hearth.pkce import generate_pkce_pair
        pair = generate_pkce_pair()
        assert pair.code_verifier
        assert pair.code_challenge

    def test_verifier_length_within_rfc_bounds(self):
        from hearth.pkce import generate_pkce_pair
        pair = generate_pkce_pair()
        # RFC 7636 §4.1: 43–128 characters
        assert 43 <= len(pair.code_verifier) <= 128

    def test_verifier_contains_only_unreserved_chars(self):
        from hearth.pkce import generate_pkce_pair
        import re
        pair = generate_pkce_pair()
        # RFC 7636 §4.1: ALPHA / DIGIT / "-" / "." / "_" / "~"
        assert re.fullmatch(r"[A-Za-z0-9\-._~]+", pair.code_verifier)

    def test_challenge_is_s256_of_verifier(self):
        from hearth.pkce import generate_pkce_pair
        pair = generate_pkce_pair()
        digest = hashlib.sha256(pair.code_verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        assert pair.code_challenge == expected

    def test_each_call_produces_different_pair(self):
        from hearth.pkce import generate_pkce_pair
        a = generate_pkce_pair()
        b = generate_pkce_pair()
        assert a.code_verifier != b.code_verifier

    def test_challenge_has_no_padding(self):
        from hearth.pkce import generate_pkce_pair
        pair = generate_pkce_pair()
        assert "=" not in pair.code_challenge


# ---------------------------------------------------------------------------
# §2 — JWKS cache with TTL
# ---------------------------------------------------------------------------

class TestJwksCache:
    """Tests for JwksCache: TTL, cache miss re-fetch, skip unknown kty."""

    def test_caches_ed25519_key_by_kid(self, respx_mock):
        from hearth.jwks import JwksCache
        private_key, x_b64, kid = _make_ed25519_key()
        jwks = _make_jwks(x_b64, kid)
        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks)
        )
        cache = JwksCache("http://localhost:8420/.well-known/jwks.json")
        key = cache.get_key(kid)
        assert key is not None

    def test_raises_jwks_fetch_error_on_http_failure(self, respx_mock):
        from hearth.jwks import JwksCache
        from hearth.errors import JWKSFetchError
        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(
            return_value=httpx.Response(503, text="down")
        )
        cache = JwksCache("http://localhost:8420/.well-known/jwks.json")
        with pytest.raises(JWKSFetchError):
            cache.get_key("some-kid")

    def test_refetches_on_kid_cache_miss(self, respx_mock):
        from hearth.jwks import JwksCache
        private_key, x_b64, kid = _make_ed25519_key()
        jwks = _make_jwks(x_b64, kid)
        # First call returns empty JWKS, second returns the real one
        call_count = [0]
        def handler(request):
            call_count[0] += 1
            if call_count[0] == 1:
                return httpx.Response(200, json={"keys": []})
            return httpx.Response(200, json=jwks)

        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(side_effect=handler)
        cache = JwksCache("http://localhost:8420/.well-known/jwks.json")
        key = cache.get_key(kid)
        assert key is not None
        assert call_count[0] == 2  # fetched twice (initial miss + retry)

    def test_raises_on_kid_not_found_after_refetch(self, respx_mock):
        from hearth.jwks import JwksCache
        from hearth.errors import JWKSFetchError
        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json={"keys": []})
        )
        cache = JwksCache("http://localhost:8420/.well-known/jwks.json")
        with pytest.raises(JWKSFetchError):
            cache.get_key("missing-kid")

    def test_skips_non_okp_keys_without_error(self, respx_mock):
        from hearth.jwks import JwksCache
        private_key, x_b64, kid = _make_ed25519_key()
        jwks = {
            "keys": [
                # RSA key (should be skipped)
                {"kty": "RSA", "n": "abc", "e": "AQAB", "kid": "rsa-1"},
                # Valid OKP key
                {"kty": "OKP", "crv": "Ed25519", "x": x_b64, "kid": kid, "use": "sig", "alg": "EdDSA"},
            ]
        }
        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks)
        )
        cache = JwksCache("http://localhost:8420/.well-known/jwks.json")
        # OKP key found; RSA skip didn't raise
        key = cache.get_key(kid)
        assert key is not None

    def test_respects_cache_control_max_age(self, respx_mock):
        from hearth.jwks import JwksCache
        private_key, x_b64, kid = _make_ed25519_key()
        jwks = _make_jwks(x_b64, kid)
        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(
            return_value=httpx.Response(
                200, json=jwks, headers={"Cache-Control": "max-age=120"}
            )
        )
        cache = JwksCache("http://localhost:8420/.well-known/jwks.json")
        cache.get_key(kid)
        assert cache._ttl == 120.0

    def test_max_age_capped_at_24h(self, respx_mock):
        from hearth.jwks import JwksCache
        private_key, x_b64, kid = _make_ed25519_key()
        jwks = _make_jwks(x_b64, kid)
        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(
            return_value=httpx.Response(
                200, json=jwks, headers={"Cache-Control": "max-age=999999"}
            )
        )
        cache = JwksCache("http://localhost:8420/.well-known/jwks.json")
        cache.get_key(kid)
        assert cache._ttl <= 86400.0


# ---------------------------------------------------------------------------
# §2 — verify_token() with full EdDSA signature verification
# ---------------------------------------------------------------------------

class TestVerifyToken:
    """verify_token must do full Ed25519 signature verification and claim checks."""

    def _client(self, **kw):
        from hearth.client import HearthClient
        return HearthClient("http://localhost:8420", realm_id="realm-1", **kw)

    def _setup_jwks_mock(self, respx_mock, x_b64: str, kid: str):
        jwks = _make_jwks(x_b64, kid)
        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks)
        )

    def test_returns_claims_for_valid_token(self, respx_mock):
        private_key, x_b64, kid = _make_ed25519_key()
        self._setup_jwks_mock(respx_mock, x_b64, kid)
        token = _sign_jwt(private_key, _valid_payload(), kid)
        claims = self._client().verify_token(token)
        assert claims.subject() == "user-abc"
        assert claims.issuer() == "http://localhost:8420"

    def test_raises_token_invalid_on_bad_signature(self, respx_mock):
        from hearth.errors import TokenInvalidError
        private_key, x_b64, kid = _make_ed25519_key()
        # Publish a different key than was used to sign
        _, x_b64_wrong, _ = _make_ed25519_key()
        jwks = {"keys": [
            {"kty": "OKP", "crv": "Ed25519", "x": x_b64_wrong, "kid": kid, "use": "sig", "alg": "EdDSA"}
        ]}
        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks)
        )
        token = _sign_jwt(private_key, _valid_payload(), kid)
        with pytest.raises(TokenInvalidError):
            self._client().verify_token(token)

    def test_raises_token_expired(self, respx_mock):
        from hearth.errors import TokenExpiredError
        private_key, x_b64, kid = _make_ed25519_key()
        self._setup_jwks_mock(respx_mock, x_b64, kid)
        payload = _valid_payload()
        payload["exp"] = int(time.time()) - 10  # already expired
        token = _sign_jwt(private_key, payload, kid)
        with pytest.raises(TokenExpiredError):
            self._client().verify_token(token)

    def test_raises_token_issuer_error(self, respx_mock):
        from hearth.errors import TokenIssuerError
        private_key, x_b64, kid = _make_ed25519_key()
        self._setup_jwks_mock(respx_mock, x_b64, kid)
        payload = _valid_payload(issuer="https://wrong.example.com")
        token = _sign_jwt(private_key, payload, kid)
        with pytest.raises(TokenIssuerError):
            self._client().verify_token(token)

    def test_raises_token_audience_error(self, respx_mock):
        from hearth.errors import TokenAudienceError
        private_key, x_b64, kid = _make_ed25519_key()
        self._setup_jwks_mock(respx_mock, x_b64, kid)
        token = _sign_jwt(private_key, _valid_payload(), kid)
        with pytest.raises(TokenAudienceError):
            self._client().verify_token(token, audience="wrong-client")

    def test_raises_token_invalid_for_malformed_jwt(self, respx_mock):
        from hearth.errors import TokenInvalidError
        private_key, x_b64, kid = _make_ed25519_key()
        self._setup_jwks_mock(respx_mock, x_b64, kid)
        with pytest.raises(TokenInvalidError):
            self._client().verify_token("not.a.valid.jwt.at.all")

    def test_raises_token_invalid_for_wrong_algorithm(self, respx_mock):
        from hearth.errors import TokenInvalidError
        private_key, x_b64, kid = _make_ed25519_key()
        self._setup_jwks_mock(respx_mock, x_b64, kid)
        # Craft JWT with alg=HS256
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "kid": kid}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps(_valid_payload()).encode()
        ).rstrip(b"=").decode()
        token = f"{header}.{payload}.fake_signature"
        with pytest.raises(TokenInvalidError):
            self._client().verify_token(token)

    def test_does_not_fallback_to_introspection(self, respx_mock):
        """verify_token MUST use local EdDSA verification, never introspection."""
        private_key, x_b64, kid = _make_ed25519_key()
        self._setup_jwks_mock(respx_mock, x_b64, kid)
        token = _sign_jwt(private_key, _valid_payload(), kid)
        # No introspect endpoint is mocked — if verify_token called it, test would error
        claims = self._client().verify_token(token)
        assert claims.subject() == "user-abc"

    def test_audience_check_skipped_when_not_specified(self, respx_mock):
        """Without audience param, aud claim is not validated."""
        private_key, x_b64, kid = _make_ed25519_key()
        self._setup_jwks_mock(respx_mock, x_b64, kid)
        token = _sign_jwt(private_key, _valid_payload(), kid)
        # Should not raise TokenAudienceError
        claims = self._client().verify_token(token)
        assert claims.subject() == "user-abc"

    def test_reuses_jwks_cache_on_second_call(self, respx_mock):
        """JWKS should not be re-fetched when cache is fresh."""
        private_key, x_b64, kid = _make_ed25519_key()
        call_count = [0]
        jwks = _make_jwks(x_b64, kid)

        def handler(request):
            call_count[0] += 1
            return httpx.Response(200, json=jwks)

        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(side_effect=handler)
        client = self._client()
        token = _sign_jwt(private_key, _valid_payload(), kid)
        client.verify_token(token)
        client.verify_token(token)
        assert call_count[0] == 1  # only fetched once


# ---------------------------------------------------------------------------
# §4.5.1 — client_credentials()
# ---------------------------------------------------------------------------

class TestClientCredentials:
    def _client(self):
        from hearth.client import HearthClient
        return HearthClient(
            "http://localhost:8420",
            realm_id="realm-1",
            client_id="svc-client",
            client_secret="super-secret",
        )

    def test_returns_token_response(self, respx_mock):
        respx_mock.post("http://localhost:8420/realms/realm-1/token").mock(
            return_value=httpx.Response(200, json={
                "access_token": "eyJ...",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "read:users",
            })
        )
        resp = self._client().client_credentials()
        assert resp.access_token == "eyJ..."
        assert resp.token_type == "Bearer"
        assert resp.expires_in == 3600

    def test_sends_credentials_in_body_not_query_params(self, respx_mock):
        captured = {}

        def handler(request):
            captured["content_type"] = request.headers.get("content-type", "")
            captured["body"] = request.content.decode()
            return httpx.Response(200, json={
                "access_token": "t", "token_type": "Bearer", "expires_in": 3600
            })

        respx_mock.post("http://localhost:8420/realms/realm-1/token").mock(side_effect=handler)
        self._client().client_credentials()
        assert "application/x-www-form-urlencoded" in captured["content_type"]
        assert "client_id=svc-client" in captured["body"]
        assert "client_secret=super-secret" in captured["body"]
        assert "client_secret" not in str(respx_mock.calls[-1].request.url)  # not in query string

    def test_sends_grant_type_client_credentials(self, respx_mock):
        captured = {}

        def handler(request):
            captured["body"] = request.content.decode()
            return httpx.Response(200, json={
                "access_token": "t", "token_type": "Bearer", "expires_in": 3600
            })

        respx_mock.post("http://localhost:8420/realms/realm-1/token").mock(side_effect=handler)
        self._client().client_credentials()
        assert "grant_type=client_credentials" in captured["body"]

    def test_sends_optional_scope(self, respx_mock):
        captured = {}

        def handler(request):
            captured["body"] = request.content.decode()
            return httpx.Response(200, json={
                "access_token": "t", "token_type": "Bearer", "expires_in": 3600
            })

        respx_mock.post("http://localhost:8420/realms/realm-1/token").mock(side_effect=handler)
        self._client().client_credentials(scope="read:users write:users")
        assert "scope=read%3Ausers+write%3Ausers" in captured["body"] or "scope=read" in captured["body"]

    def test_raises_configuration_error_when_no_client_id(self):
        from hearth.client import HearthClient
        from hearth.errors import ConfigurationError
        client = HearthClient("http://localhost:8420", realm_id="realm-1")
        with pytest.raises(ConfigurationError):
            client.client_credentials()

    def test_raises_configuration_error_when_no_client_secret(self):
        from hearth.client import HearthClient
        from hearth.errors import ConfigurationError
        client = HearthClient("http://localhost:8420", realm_id="realm-1", client_id="id")
        with pytest.raises(ConfigurationError):
            client.client_credentials()


# ---------------------------------------------------------------------------
# §4.5.2 — device_authorization() + poll_device_token()
# ---------------------------------------------------------------------------

class TestDeviceFlow:
    def _client(self, **kw):
        from hearth.client import HearthClient
        return HearthClient(
            "http://localhost:8420",
            realm_id="realm-1",
            client_id="cli-app",
            **kw,
        )

    def test_start_device_flow_returns_response(self, respx_mock):
        respx_mock.post("http://localhost:8420/realms/realm-1/device/authorize").mock(
            return_value=httpx.Response(200, json={
                "device_code": "DEV123",
                "user_code": "ABCD-1234",
                "verification_uri": "https://auth.example.com/activate",
                "expires_in": 300,
                "interval": 5,
            })
        )
        resp = self._client().start_device_flow()
        assert resp.device_code == "DEV123"
        assert resp.user_code == "ABCD-1234"
        assert resp.interval == 5

    def test_start_device_flow_sends_client_id(self, respx_mock):
        captured = {}

        def handler(request):
            captured["body"] = request.content.decode()
            return httpx.Response(200, json={
                "device_code": "d", "user_code": "u",
                "verification_uri": "v", "expires_in": 300, "interval": 5
            })

        respx_mock.post("http://localhost:8420/realms/realm-1/device/authorize").mock(side_effect=handler)
        self._client().start_device_flow()
        assert "client_id=cli-app" in captured["body"]

    def test_poll_device_token_returns_token_on_success(self, respx_mock):
        respx_mock.post("http://localhost:8420/realms/realm-1/token").mock(
            return_value=httpx.Response(200, json={
                "access_token": "eyJ...",
                "token_type": "Bearer",
                "expires_in": 3600,
            })
        )
        resp = self._client().poll_device_token("DEV123")
        assert resp is not None
        assert resp.access_token == "eyJ..."

    def test_poll_device_token_returns_none_on_authorization_pending(self, respx_mock):
        respx_mock.post("http://localhost:8420/realms/realm-1/token").mock(
            return_value=httpx.Response(400, json={"error": "authorization_pending"})
        )
        result = self._client().poll_device_token("DEV123")
        assert result is None

    def test_poll_device_token_returns_none_on_slow_down(self, respx_mock):
        respx_mock.post("http://localhost:8420/realms/realm-1/token").mock(
            return_value=httpx.Response(400, json={"error": "slow_down"})
        )
        result = self._client().poll_device_token("DEV123")
        assert result is None

    def test_poll_device_token_raises_token_expired_on_expired_token(self, respx_mock):
        from hearth.errors import TokenExpiredError
        respx_mock.post("http://localhost:8420/realms/realm-1/token").mock(
            return_value=httpx.Response(400, json={"error": "expired_token"})
        )
        with pytest.raises(TokenExpiredError):
            self._client().poll_device_token("DEV123")

    def test_poll_device_token_raises_on_other_errors(self, respx_mock):
        from hearth.errors import HearthError
        respx_mock.post("http://localhost:8420/realms/realm-1/token").mock(
            return_value=httpx.Response(400, json={"error": "access_denied"})
        )
        with pytest.raises(HearthError):
            self._client().poll_device_token("DEV123")

    def test_start_device_flow_raises_configuration_error_when_no_client_id(self):
        from hearth.client import HearthClient
        from hearth.errors import ConfigurationError
        client = HearthClient("http://localhost:8420", realm_id="realm-1")
        with pytest.raises(ConfigurationError):
            client.start_device_flow()


# ---------------------------------------------------------------------------
# §4.5.3 — request_magic_link()
# ---------------------------------------------------------------------------

class TestMagicLink:
    def _client(self):
        from hearth.client import HearthClient
        return HearthClient("http://localhost:8420", realm_id="realm-1")

    def test_posts_to_correct_endpoint(self, respx_mock):
        respx_mock.post("http://localhost:8420/v1/realm-1/auth/magic-link").mock(
            return_value=httpx.Response(202, json={"message": "If an account exists, a magic link has been sent"})
        )
        self._client().request_magic_link("user@example.com")

    def test_sends_email_in_json_body(self, respx_mock):
        captured = {}

        def handler(request):
            captured["json"] = json.loads(request.content)
            return httpx.Response(202, json={"message": "ok"})

        respx_mock.post("http://localhost:8420/v1/realm-1/auth/magic-link").mock(side_effect=handler)
        self._client().request_magic_link("user@example.com")
        assert captured["json"]["email"] == "user@example.com"

    def test_does_not_raise_on_202(self, respx_mock):
        """202 Accepted must not raise (enumeration resistance — always 202)."""
        respx_mock.post("http://localhost:8420/v1/realm-1/auth/magic-link").mock(
            return_value=httpx.Response(202, json={"message": "ok"})
        )
        self._client().request_magic_link("nobody@example.com")

    def test_raises_hearth_error_on_429(self, respx_mock):
        from hearth.errors import HearthError
        respx_mock.post("http://localhost:8420/v1/realm-1/auth/magic-link").mock(
            return_value=httpx.Response(429, text="too many requests")
        )
        with pytest.raises(HearthError) as exc_info:
            self._client().request_magic_link("user@example.com")
        assert exc_info.value.status_code == 429

    def test_exchange_returns_token_response(self, respx_mock):
        respx_mock.post("http://localhost:8420/realms/realm-1/token").mock(
            return_value=httpx.Response(200, json={
                "access_token": "at", "token_type": "Bearer", "expires_in": 3600,
            })
        )
        result = self._client().exchange_magic_link("magic-token-xyz")
        assert result.access_token == "at"
        assert result.token_type == "Bearer"

    def test_exchange_sends_magic_link_grant_with_token_in_body(self, respx_mock):
        captured = {}

        def handler(request):
            captured["body"] = request.content.decode()
            return httpx.Response(200, json={
                "access_token": "at", "token_type": "Bearer", "expires_in": 3600,
            })

        respx_mock.post("http://localhost:8420/realms/realm-1/token").mock(side_effect=handler)
        from hearth.client import HearthClient
        HearthClient("http://localhost:8420", realm_id="realm-1", client_id="cid").exchange_magic_link("magic-token-xyz")
        assert "grant_type=urn%3Ahearth%3Agrant-type%3Amagic-link" in captured["body"]
        assert "token=magic-token-xyz" in captured["body"]
        assert "client_id=cid" in captured["body"]

    def test_exchange_raises_hearth_error_on_invalid_token(self, respx_mock):
        from hearth.errors import HearthError
        respx_mock.post("http://localhost:8420/realms/realm-1/token").mock(
            return_value=httpx.Response(400, json={"error": "invalid_grant"})
        )
        with pytest.raises(HearthError):
            self._client().exchange_magic_link("expired")


# ---------------------------------------------------------------------------
# Session-version endpoints
# ---------------------------------------------------------------------------

class TestSessionVersionEndpoints:
    """Tests for sv_snapshot() and sv_delta() methods."""

    def _client(self):
        from hearth.client import HearthClient
        return HearthClient("http://localhost:8420", realm_id="realm-1")

    def test_sv_snapshot_returns_response(self, respx_mock):
        respx_mock.get("http://localhost:8420/oauth/session-versions/snapshot").mock(
            return_value=httpx.Response(200, json={
                "realm": "realm-1",
                "current_seq": 42,
                "versions": {"session-abc": 3, "session-def": 1},
            })
        )
        resp = self._client().sv_snapshot("tok")
        assert resp.current_seq == 42
        assert resp.versions["session-abc"] == 3

    def test_sv_snapshot_sends_bearer_token(self, respx_mock):
        captured = {}

        def handler(request):
            captured["auth"] = request.headers.get("authorization", "")
            return httpx.Response(200, json={
                "realm": "realm-1", "current_seq": 0, "versions": {}
            })

        respx_mock.get("http://localhost:8420/oauth/session-versions/snapshot").mock(side_effect=handler)
        self._client().sv_snapshot("my-service-token")
        assert captured["auth"] == "Bearer my-service-token"

    def test_sv_delta_returns_response_with_deltas(self, respx_mock):
        respx_mock.get("http://localhost:8420/oauth/session-versions").mock(
            return_value=httpx.Response(200, json={
                "realm": "realm-1",
                "next_seq": 10,
                "deltas": [
                    {"seq": 5, "session_id": "sess-1", "min_sv": 2, "bumped_at": 1700000000},
                ],
            })
        )
        resp = self._client().sv_delta("tok", since=4)
        assert resp is not None
        assert resp.next_seq == 10
        assert len(resp.deltas) == 1
        assert resp.deltas[0].session_id == "sess-1"

    def test_sv_delta_returns_none_on_204(self, respx_mock):
        respx_mock.get("http://localhost:8420/oauth/session-versions").mock(
            return_value=httpx.Response(204)
        )
        resp = self._client().sv_delta("tok", since=42)
        assert resp is None

    def test_sv_delta_sends_since_param(self, respx_mock):
        captured = {}

        def handler(request):
            captured["params"] = dict(request.url.params)
            return httpx.Response(204)

        respx_mock.get("http://localhost:8420/oauth/session-versions").mock(side_effect=handler)
        self._client().sv_delta("tok", since=17)
        assert captured["params"].get("since") == "17"

    def test_sv_delta_raises_on_400(self, respx_mock):
        from hearth.errors import HearthError
        respx_mock.get("http://localhost:8420/oauth/session-versions").mock(
            return_value=httpx.Response(400, json={"error": "since is older than retention window"})
        )
        with pytest.raises(HearthError) as exc_info:
            self._client().sv_delta("tok", since=0)
        assert exc_info.value.status_code == 400


# ---------------------------------------------------------------------------
# New types exposed via hearth package
# ---------------------------------------------------------------------------

class TestNewPublicTypes:
    """Smoke-test that new types are importable from the top-level package."""

    def test_pkce_pair_importable(self):
        from hearth import PkcePair
        assert PkcePair

    def test_device_authorization_response_importable(self):
        from hearth import DeviceAuthorizationResponse
        p = DeviceAuthorizationResponse(
            device_code="d",
            user_code="u",
            verification_uri="v",
            expires_in=300,
            interval=5,
        )
        assert p.device_code == "d"

    def test_sv_snapshot_response_importable(self):
        from hearth import SvSnapshotResponse
        r = SvSnapshotResponse(realm="r", current_seq=0, versions={})
        assert r.current_seq == 0

    def test_sv_delta_response_importable(self):
        from hearth import SvDeltaResponse
        r = SvDeltaResponse(realm="r", next_seq=1, deltas=[])
        assert r.next_seq == 1
