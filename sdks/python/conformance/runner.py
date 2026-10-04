"""Hearth SDK conformance runner — Python.

Reads a case file (sdks/conformance/README.md) and prints one JSON line per
case. Uses only the public SDK API.

Usage: python runner.py <cases.json>
"""

from __future__ import annotations

import json
import sys
from typing import Any

from hearth import HearthClient
from hearth.errors import HearthSdkError

# openspec/specs/sdk-support-contract/spec.md error names.
SPEC_ERRORS = {
    "ConfigurationError",
    "DiscoveryError",
    "JWKSFetchError",
    "TokenExpiredError",
    "TokenNotYetValidError",
    "TokenInvalidError",
    "TokenIssuerError",
    "TokenAudienceError",
    "IntrospectionError",
    "RequiredActionError",
}


def _verify(config: dict[str, Any], token: str, names: list[str]) -> dict[str, Any]:
    # The SDK reads JWKS from `{base_url}/.well-known/jwks.json` and checks
    # `iss` against it, so a verifying client is rooted at the realm issuer.
    client = HearthClient(base_url=config["issuer"], realm_id=config["realm"])
    claims = client.verify_token(
        token, audience=config.get("audience"), issuer_url=config["issuer"]
    )
    out: dict[str, Any] = {}
    for name in names:
        if name == "sub":
            out["sub"] = claims.subject()
        elif name == "scope":
            out["scope"] = claims.get("scope")
        elif name == "permissions":
            out["permissions"] = list(claims.get("permissions") or [])
        else:
            out[name] = claims.get(name)
    return out


def _run(case: dict[str, Any]) -> dict[str, Any]:
    config = case["config"]
    names = case.get("claims") or []
    if case["kind"] == "verify_token":
        return _verify(config, case["token"], names)
    if case["kind"] == "client_credentials":
        client = HearthClient(
            base_url=config["base_url"],
            realm_id=config["realm"],
            client_id=config["client_id"],
            client_secret=config["client_secret"],
        )
        tokens = client.client_credentials(scope=case.get("scope"))
        return _verify(config, tokens.access_token, names)
    raise ValueError(f"unknown case kind: {case['kind']!r}")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: runner.py <cases.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1]) as f:
        cases = json.load(f)["cases"]
    for case in cases:
        line: dict[str, Any] = {"id": case["id"]}
        try:
            line.update(outcome="ok", claims=_run(case))
        except HearthSdkError as exc:
            name = type(exc).__name__
            error = name if name in SPEC_ERRORS else f"Unexpected:{name}"
            line.update(outcome="error", error=error)
        except Exception as exc:  # noqa: BLE001 — every case must report a line
            line.update(outcome="error", error=f"Unexpected:{type(exc).__name__}")
        print(json.dumps(line), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
