#!/usr/bin/env python3
"""Run the shared SDK conformance scenarios against live Hearth servers.

Usage:
    python3 scripts/sdk_conformance.py --main-url URL --expiry-url URL \
        [--sdk typescript --sdk go ...] [--work DIR]

Called by scripts/sdk-conformance.sh, which builds and boots the two servers.
Reads sdks/conformance/scenarios.yaml, mints a real token for each scenario,
writes the cases file (format: sdks/conformance/README.md), runs
sdks/<sdk>/conformance/run.sh on it for each SDK, and compares each result
with the scenario's `expect` and with the other SDKs. Exits 1 on any
difference; every failure line names the SDK and the scenario.
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS = os.path.join(REPO_ROOT, "sdks", "conformance", "scenarios.yaml")
SDKS = ["typescript", "go", "python", "php"]

# The server derives a YAML-declared client's id as UUIDv5 over
# "<realm>/<app key>" (src/identity/reconcile.rs, APP_NAMESPACE).
APP_NAMESPACE = uuid.UUID(bytes=bytes([
    0x8B, 0x07, 0x4E, 0x8C, 0x3E, 0x6A, 0x5A, 0x8E,
    0x96, 0x1D, 0x8F, 0x2B, 0xAA, 0xE7, 0x1B, 0xF4,
]))
CONFORMANCE_REALM = "conformance"
M2M_SECRET = "conformance-secret-not-for-production"
AUDIENCE = "hearth"
# SDK.md §2: one 5 s clock-skew allowance. Wait past it, with margin.
EXPIRY_WAIT_SECS = 1 + 5 + 2


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_json(segment: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def http(method: str, url: str, *, json_body=None, form=None, headers=None):
    data = None
    hdrs = dict(headers or {})
    if json_body is not None:
        data = json.dumps(json_body).encode()
        hdrs["Content-Type"] = "application/json"
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {url} answered {e.code}: {e.read()[:300]!r}")


def m2m_client_id(realm: str) -> str:
    return str(uuid.uuid5(APP_NAMESPACE, f"{realm}/m2m"))


def m2m_token(base_url: str, scope: str) -> str:
    body = http(
        "POST",
        f"{base_url}/realms/{CONFORMANCE_REALM}/token",
        form={
            "grant_type": "client_credentials",
            "client_id": m2m_client_id(CONFORMANCE_REALM),
            "client_secret": M2M_SECRET,
            "scope": scope,
        },
    )
    return body["access_token"]


def config(base_url: str, realm: str, *, audience=AUDIENCE, with_client=False) -> dict:
    return {
        "base_url": base_url,
        "realm": realm,
        "issuer": f"{base_url}/realms/{realm}",
        "audience": audience,
        "client_id": m2m_client_id(realm) if with_client else None,
        "client_secret": M2M_SECRET if with_client else None,
    }


def mint(main_url: str, expiry_url: str) -> dict:
    """Mint every token kind of scenarios.yaml; return {kind: (token, realm, base_url)}."""
    boot = http("POST", f"{main_url}/admin/bootstrap")
    user = boot["access_token"]
    user_realm = b64url_json(user.split(".")[1])["iss"].rsplit("/", 1)[1]
    header, payload, signature = user.split(".")

    claims = b64url_json(payload)
    claims["sub"] = "user_00000000-0000-0000-0000-000000000000"
    tampered = ".".join([header, b64url(json.dumps(claims).encode()), signature])

    none_header = {**b64url_json(header), "alg": "none"}
    alg_none = ".".join([b64url(json.dumps(none_header).encode()), payload, ""])

    kid_header = {**b64url_json(header), "kid": "conformance-unknown-kid"}
    unknown_kid = ".".join([b64url(json.dumps(kid_header).encode()), payload, signature])

    expired = m2m_token(expiry_url, "openid")
    return {
        "user_access": (user, user_realm, main_url),
        "m2m_access": (m2m_token(main_url, "openid"), CONFORMANCE_REALM, main_url),
        "tampered": (tampered, user_realm, main_url),
        "alg_none": (alg_none, user_realm, main_url),
        "unknown_kid": (unknown_kid, user_realm, main_url),
        "expired": (expired, CONFORMANCE_REALM, expiry_url),
        "_expired_minted_at": time.monotonic(),
    }


def build_cases(scenarios: list, tokens: dict, main_url: str) -> list:
    cases = []
    for s in scenarios:
        case = {"id": s["id"], "kind": s["kind"], "claims": s["expect"].get("claims", [])}
        if s["kind"] == "verify_token":
            token, realm, base_url = tokens[s["token"]]
            variant = s.get("config", "default")
            if variant == "default":
                cfg = config(base_url, realm)
            elif variant == "wrong_audience":
                cfg = config(base_url, realm, audience="not-hearth")
            elif variant == "wrong_issuer":
                # Same server and keys, reached by another host name, so
                # the configured issuer differs from the token's `iss`.
                cfg = config(base_url.replace("127.0.0.1", "localhost"), realm)
            else:
                sys.exit(f"{s['id']}: unknown config variant {variant!r}")
            case.update(token=token, config=cfg)
        elif s["kind"] == "client_credentials":
            case.update(config=config(main_url, CONFORMANCE_REALM, with_client=True), scope=s["scope"])
        else:
            sys.exit(f"{s['id']}: unknown kind {s['kind']!r}")
        cases.append(case)
    return cases


def expected_claims(case: dict, tokens: dict, scenario: dict) -> dict | None:
    """The claims a correct SDK reports, from the minted token itself."""
    if scenario["kind"] == "client_credentials":
        return {
            "sub": f"client_{case['config']['client_id']}",
            "scope": scenario["scope"],
            "permissions": [],
        }
    payload = b64url_json(tokens[scenario["token"]][0].split(".")[1])
    return {
        "sub": payload["sub"],
        "scope": payload.get("scope"),
        "permissions": payload.get("permissions", []),
    }


def run_sdk(sdk: str, cases_path: str, n_cases: int) -> tuple[dict, str | None]:
    """Run one SDK's runner; return ({id: result}, error or None)."""
    runner = os.path.join(REPO_ROOT, "sdks", sdk, "conformance", "run.sh")
    if not os.path.exists(runner):
        return {}, f"no runner at {os.path.relpath(runner, REPO_ROOT)}"
    proc = subprocess.run(
        ["bash", runner, cases_path], capture_output=True, text=True, timeout=900
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout)[-1500:]
        return {}, f"runner exited {proc.returncode}:\n{tail}"
    results = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return {}, f"runner printed a non-JSON line: {line[:200]}"
        results[row.get("id")] = row
    if len(results) != n_cases:
        return results, f"runner printed {len(results)} results for {n_cases} cases"
    return results, None


def verdict(result: dict | None, scenario: dict, want_claims: dict | None) -> str | None:
    """None when `result` meets the scenario's `expect`; else the reason."""
    if result is None:
        return "no result"
    expect = scenario["expect"]
    if result.get("outcome") != expect["outcome"]:
        got = result.get("error") if result.get("outcome") == "error" else "ok"
        want = expect.get("error", "ok")
        return f"expected {want}, got {got}"
    if expect["outcome"] == "error":
        if result.get("error") != expect["error"]:
            return f"expected {expect['error']}, got {result.get('error')}"
        return None
    got = result.get("claims") or {}
    for name in expect.get("claims", []):
        if got.get(name) != want_claims.get(name):
            return f"claim {name}: expected {want_claims.get(name)!r}, got {got.get(name)!r}"
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--main-url", required=True)
    parser.add_argument("--expiry-url", required=True)
    parser.add_argument("--sdk", action="append", choices=SDKS)
    parser.add_argument("--work", default=None, help="directory for cases.json and results")
    args = parser.parse_args()
    sdks = args.sdk or SDKS
    work = args.work or os.path.join(REPO_ROOT, "target", "sdk-conformance")
    os.makedirs(work, exist_ok=True)

    with open(SCENARIOS) as f:
        scenarios = yaml.safe_load(f)["scenarios"]
    by_id = {s["id"]: s for s in scenarios}

    tokens = mint(args.main_url, args.expiry_url)
    cases = build_cases(scenarios, tokens, args.main_url)
    remaining = EXPIRY_WAIT_SECS - (time.monotonic() - tokens["_expired_minted_at"])
    if remaining > 0:
        time.sleep(remaining)

    cases_path = os.path.join(work, "cases.json")
    with open(cases_path, "w") as f:
        json.dump({"cases": cases}, f, indent=2)

    failures = []
    all_results = {}
    for sdk in sdks:
        print(f"==> {sdk}", flush=True)
        results, err = run_sdk(sdk, cases_path, len(cases))
        all_results[sdk] = results
        if err:
            failures.append(f"{sdk}: {err}")
        for case in cases:
            scenario = by_id[case["id"]]
            reason = verdict(results.get(case["id"]), scenario, expected_claims(case, tokens, scenario))
            mark = "ok  " if reason is None else "FAIL"
            print(f"    {mark} {case['id']}" + ("" if reason is None else f" — {reason}"))
            if reason is not None:
                failures.append(f"{sdk} / {case['id']}: {reason}")

    # Cross-SDK agreement: every SDK must give the same answer per scenario.
    for case in cases:
        seen = {}
        for sdk in sdks:
            r = all_results[sdk].get(case["id"])
            if r is not None:
                key = json.dumps({k: r.get(k) for k in ("outcome", "error", "claims")}, sort_keys=True)
                seen.setdefault(key, []).append(sdk)
        if len(seen) > 1:
            groups = "; ".join(f"{', '.join(v)} → {k}" for k, v in seen.items())
            failures.append(f"SDKs disagree on {case['id']}: {groups}")

    with open(os.path.join(work, "results.json"), "w") as f:
        json.dump(all_results, f, indent=2)

    print()
    if failures:
        print(f"SDK conformance FAILED ({len(failures)}):")
        for line in failures:
            print(f"  ✗ {line}")
        sys.exit(1)
    print(f"✓ SDK conformance: {len(cases)} scenarios × {len(sdks)} SDKs agree.")


if __name__ == "__main__":
    main()
