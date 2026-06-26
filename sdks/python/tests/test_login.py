"""Tests for HearthClient.begin_login and complete_login (HEA-1592)."""

from __future__ import annotations

import base64
import hashlib
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from hearth import HearthClient, LoginBeginResult
from hearth.errors import ConfigurationError
from hearth.types import TokenResponse


def make_client(**kwargs) -> HearthClient:
    defaults = {
        "base_url": "https://auth.example.com",
        "realm_id": "test-realm",
        "client_id": "test-client",
        "client_secret": "s3cr3t",
    }
    defaults.update(kwargs)
    return HearthClient(**defaults)


# ── begin_login ───────────────────────────────────────────────────────────────

class TestBeginLogin:
    def test_returns_login_begin_result(self):
        client = make_client()
        result = client.begin_login("https://app.example.com/callback")
        assert isinstance(result, LoginBeginResult)

    def test_authorization_url_contains_code_challenge_derived_from_verifier(self):
        client = make_client()
        result = client.begin_login("https://app.example.com/callback")
        params = parse_qs(urlparse(result.authorization_url).query)
        challenge = params["code_challenge"][0]

        # Recompute challenge from verifier
        digest = hashlib.sha256(result.code_verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        assert challenge == expected, "code_challenge must be BASE64URL(SHA256(code_verifier))"

    def test_state_is_non_empty_and_present_in_url(self):
        client = make_client()
        result = client.begin_login("https://app.example.com/callback")
        assert result.state, "state must not be empty"
        params = parse_qs(urlparse(result.authorization_url).query)
        assert params["state"][0] == result.state

    def test_required_query_params_are_present(self):
        client = make_client()
        result = client.begin_login("https://app.example.com/callback", "openid profile")
        params = parse_qs(urlparse(result.authorization_url).query)
        assert params["response_type"][0] == "code"
        assert params["client_id"][0] == "test-client"
        assert params["redirect_uri"][0] == "https://app.example.com/callback"
        assert params["scope"][0] == "openid profile"
        assert params["code_challenge_method"][0] == "S256"

    def test_defaults_scope_to_openid(self):
        client = make_client()
        result = client.begin_login("https://app.example.com/callback")
        params = parse_qs(urlparse(result.authorization_url).query)
        assert params["scope"][0] == "openid"

    def test_raises_configuration_error_when_client_id_missing(self):
        client = make_client(client_id=None)
        with pytest.raises(ConfigurationError):
            client.begin_login("https://app.example.com/callback")


# ── complete_login ────────────────────────────────────────────────────────────

class TestCompleteLogin:
    def test_calls_exchange_code_with_verifier(self):
        client = make_client()
        mock_response = TokenResponse(
            access_token="eyJ.access.token",
            token_type="Bearer",
            expires_in=3600,
        )
        with patch.object(client, "exchange_code", return_value=mock_response) as mock_ec:
            result = client.complete_login(
                "auth-code-xyz",
                "my-verifier-abc",
                "https://app.example.com/callback",
            )
        mock_ec.assert_called_once_with(
            "auth-code-xyz",
            "test-client",
            "s3cr3t",
            "https://app.example.com/callback",
            "my-verifier-abc",
        )
        assert result.access_token == "eyJ.access.token"

    def test_raises_configuration_error_when_no_client_credentials(self):
        client = make_client(client_id=None, client_secret=None)
        with pytest.raises(ConfigurationError):
            client.complete_login("code", "verifier", "https://app.example.com/callback")
