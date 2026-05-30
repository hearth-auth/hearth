# FAPI 2.0 Operator Guide

**Financial-grade API Security Profile 2.0** — how to enable, configure, and validate Hearth's
FAPI 2.0 support for regulated environments such as open banking, payment initiation, and
government identity programs.

> **Engineering status** — FAPI 2.0 shipped in PR #128 (commit eeca42f). The `fapi_profile`
> YAML key is tracked in [HEA-1040](/HEA/issues/HEA-1040) and will be wired in the next minor
> release. Until then, use the Admin API PATCH route described in §2 to activate the profile.

---

## Table of Contents

1. [When to use FAPI 2.0](#1-when-to-use-fapi-20)
2. [Enable FAPI 2.0 at realm level](#2-enable-fapi-20-at-realm-level)
3. [Register a FAPI 2.0 client](#3-register-a-fapi-20-client)
4. [PAR — Pushed Authorization Requests](#4-par--pushed-authorization-requests)
5. [JAR — JWT Authorization Requests](#5-jar--jwt-authorization-requests)
6. [JARM — JWT Authorization Response Mode](#6-jarm--jwt-authorization-response-mode)
7. [DPoP token binding](#7-dpop-token-binding)
8. [Testing FAPI 2.0 compliance](#8-testing-fapi-20-compliance)
9. [Common misconfiguration errors](#9-common-misconfiguration-errors)

---

## 1. When to use FAPI 2.0

FAPI 2.0 is the right choice when:

| Scenario | Why FAPI 2.0 |
|----------|-------------|
| Open banking / PSD2 | Mandatory in EU, UK, Brazil, Australia by regulation |
| Payment initiation APIs | Requires binding access tokens to client key material (DPoP) |
| Account aggregation (FDX, CDR) | US/AU data-sharing mandates require PAR + PKCE S256 |
| High-value B2B APIs | Protect against authorization code interception and CSRF |
| Government identity (eIDAS 2) | Level of Assurance High requires phishing-resistant auth |

### FAPI 2.0 Baseline vs Advanced

| Feature | Plain OAuth 2.1 | FAPI 2.0 Baseline | FAPI 2.0 Advanced |
|---------|----------------|-------------------|-------------------|
| PKCE required | S256 recommended | **S256 mandatory** | **S256 mandatory** |
| PAR required | No | **Yes** | **Yes** |
| `private_key_jwt` auth | Optional | **Mandatory** | **Mandatory** |
| `client_secret` allowed | Yes | **No** | **No** |
| JAR (signed request object) | Optional | Optional | **Mandatory** |
| JARM (signed response) | Optional | Optional | **Mandatory** |
| DPoP token binding | Optional | Optional | **Mandatory** |
| `response_type` | code, token | **code only** | **code only** |

Use **Baseline** for open banking read-only APIs and most PSD2 AIS flows.
Use **Advanced** for payment initiation (PIS), high-value data write operations, and eIDAS LoA High.

---

## 2. Enable FAPI 2.0 at realm level

### Via hearth.yaml (requires HEA-1040)

```yaml
realms:
  banking:
    fapi_profile: baseline   # or: advanced
    auth:
      mfa_required: true
      mfa_methods:
        - webauthn            # FAPI 2.0 Advanced recommends phishing-resistant MFA
    token:
      access_token_ttl: "5m"
      refresh_token_ttl: "8h"
```

> **Note:** The `fapi_profile` YAML key is pending [HEA-1040](/HEA/issues/HEA-1040). Use the
> Admin API method below until the key is available.

### Via Admin API (available now)

```bash
# Activate FAPI 2.0 Baseline on the "banking" realm
curl -s -X PATCH https://auth.example.com/admin/realms/banking \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "fapi_profile": "baseline"
  }'

# Activate FAPI 2.0 Advanced
curl -s -X PATCH https://auth.example.com/admin/realms/banking \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "fapi_profile": "advanced"
  }'
```

### What changes when a FAPI profile is active

Hearth enforces these constraints **server-side** — a client cannot opt out by omitting
parameters:

| Enforcement | Baseline | Advanced |
|-------------|----------|----------|
| Reject authorization requests not submitted via PAR | Yes | Yes |
| Reject PKCE methods other than S256 | Yes | Yes |
| Reject `client_secret_basic` / `client_secret_post` auth | Yes | Yes |
| Reject authorization requests without a signed JAR | No | Yes |
| Reject token requests without a valid DPoP proof | No | Yes |
| Force `response_mode=jwt` (JARM) | No | Yes |

---

## 3. Register a FAPI 2.0 client

FAPI 2.0 clients **must**:
- Authenticate with `private_key_jwt` (Ed25519 or ES256 key pair)
- Register a JWKS URI or inline JWK set
- **Not** use `client_secret`

### Step 1 — Generate a signing key pair

```bash
# ES256 (P-256) — widely supported by conformance tools
openssl ecparam -name prime256v1 -genkey -noout -out client.key.pem
openssl ec -in client.key.pem -pubout -out client.pub.pem

# Convert to JWK (requires python-jose or jwcrypto)
python3 - <<'EOF'
from jwcrypto import jwk
import json

with open("client.key.pem", "rb") as f:
    key = jwk.JWK.from_pem(f.read())

key["kid"] = "banking-client-2026-01"
key["use"] = "sig"
key["alg"] = "ES256"

print("Private JWK (keep secret):")
print(json.dumps(key.export_private(as_dict=True), indent=2))
print("\nPublic JWK (register with Hearth):")
print(json.dumps(key.export_public(as_dict=True), indent=2))
EOF
```

### Step 2 — Register the client via Admin API

```bash
curl -s -X POST https://auth.example.com/admin/realms/banking/clients \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "payment-initiation-service",
    "name": "Payment Initiation Service",
    "confidential": true,
    "token_endpoint_auth_method": "private_key_jwt",
    "jwks": {
      "keys": [
        {
          "kty": "EC",
          "crv": "P-256",
          "kid": "banking-client-2026-01",
          "use": "sig",
          "alg": "ES256",
          "x": "<base64url-encoded-x>",
          "y": "<base64url-encoded-y>"
        }
      ]
    },
    "grant_types": ["authorization_code", "refresh_token"],
    "redirect_uris": ["https://app.example.com/callback"],
    "require_pushed_authorization_requests": true,
    "declared_scopes": ["openid", "accounts", "payments"]
  }'
```

Alternatively, register a `jwks_uri` instead of inline `jwks` to allow key rotation without
re-registering:

```json
{
  "jwks_uri": "https://app.example.com/.well-known/jwks.json"
}
```

### Step 3 — Verify registration

```bash
curl -s https://auth.example.com/admin/realms/banking/clients/payment-initiation-service \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  | jq '.token_endpoint_auth_method, .require_pushed_authorization_requests'
# "private_key_jwt"
# true
```

### Dynamic Client Registration (RFC 7591)

FAPI 2.0 clients may also register via the DCR endpoint. When a FAPI profile is active, the
DCR endpoint enforces the same constraints (rejects `client_secret`, requires JWKS):

```bash
curl -s -X POST https://auth.example.com/realms/banking/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Payment App",
    "redirect_uris": ["https://app.example.com/callback"],
    "token_endpoint_auth_method": "private_key_jwt",
    "jwks_uri": "https://app.example.com/.well-known/jwks.json",
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "openid accounts payments"
  }'
```

---

## 4. PAR — Pushed Authorization Requests

PAR (RFC 9126) moves all authorization parameters out of the browser redirect URL and into a
server-to-server POST. This prevents:
- Authorization code injection (attacker swaps `code` in the redirect)
- CSRF via crafted `state` in open redirectors
- Parameter tampering in the browser

### Standard OAuth 2.1 flow vs FAPI 2.0 flow

```
Standard OAuth 2.1:
  Browser → GET /authorize?response_type=code&client_id=...&scope=...&redirect_uri=...

FAPI 2.0 with PAR:
  Server  → POST /par        (all parameters in body, signed with private_key_jwt)
          ← { request_uri, expires_in }
  Browser → GET /authorize?client_id=...&request_uri=urn:hearth:par:...
```

### Step 1 — Push authorization request

```bash
# Build client_assertion (private_key_jwt) — see §5 for a signing helper
CLIENT_ASSERTION=$(python3 sign_jar.py \
  --client-id payment-initiation-service \
  --key client.key.pem \
  --audience https://auth.example.com/realms/banking/par)

curl -s -X POST https://auth.example.com/realms/banking/par \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=payment-initiation-service" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${CLIENT_ASSERTION}" \
  --data-urlencode "response_type=code" \
  --data-urlencode "scope=openid accounts" \
  --data-urlencode "redirect_uri=https://app.example.com/callback" \
  --data-urlencode "code_challenge=${CODE_CHALLENGE}" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "state=$(openssl rand -hex 16)" \
  --data-urlencode "nonce=$(openssl rand -hex 16)"
```

**Response:**

```json
{
  "request_uri": "urn:hearth:par:banking:a1b2c3d4e5f6",
  "expires_in": 60
}
```

The `request_uri` is single-use and expires in 60 seconds. Hearth rejects it after first use
or after expiry.

### Step 2 — Redirect the browser

```
https://auth.example.com/realms/banking/authorize
  ?client_id=payment-initiation-service
  &request_uri=urn:hearth:par:banking:a1b2c3d4e5f6
```

No other parameters are accepted in the authorization redirect when a `request_uri` is present.

### Step 3 — Exchange code at token endpoint

```bash
curl -s -X POST https://auth.example.com/realms/banking/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=${CODE}" \
  --data-urlencode "redirect_uri=https://app.example.com/callback" \
  --data-urlencode "code_verifier=${CODE_VERIFIER}" \
  --data-urlencode "client_id=payment-initiation-service" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${CLIENT_ASSERTION}"
```

---

## 5. JAR — JWT Authorization Requests

JAR (RFC 9101) signs all authorization parameters as a JWT. Combined with PAR, this provides
**integrity protection** — the authorization server can verify the parameters were issued by the
registered client and were not tampered with in transit.

JAR is **optional** for FAPI 2.0 Baseline and **mandatory** for Advanced.

### Building a signed request object

```python
#!/usr/bin/env python3
# sign_jar.py — build a signed JWT authorization request object
import argparse, time, secrets, json
from jwcrypto import jwk, jwt

parser = argparse.ArgumentParser()
parser.add_argument("--client-id", required=True)
parser.add_argument("--key", required=True, help="Path to PEM private key")
parser.add_argument("--audience", required=True, help="PAR or authorize endpoint URL")
parser.add_argument("--kid", default="banking-client-2026-01")
# Authorization params
parser.add_argument("--scope", default="openid accounts")
parser.add_argument("--redirect-uri", required=True)
parser.add_argument("--code-challenge", required=True)
parser.add_argument("--state", default=None)
parser.add_argument("--nonce", default=None)
args = parser.parse_args()

with open(args.key, "rb") as f:
    key = jwk.JWK.from_pem(f.read())
    key["kid"] = args.kid

now = int(time.time())
claims = {
    # JWT claims
    "iss": args.client_id,
    "sub": args.client_id,
    "aud": args.audience,
    "iat": now,
    "exp": now + 60,
    "jti": secrets.token_urlsafe(16),
    # Authorization request claims
    "response_type": "code",
    "client_id": args.client_id,
    "scope": args.scope,
    "redirect_uri": args.redirect_uri,
    "code_challenge": args.code_challenge,
    "code_challenge_method": "S256",
    "state": args.state or secrets.token_hex(16),
    "nonce": args.nonce or secrets.token_hex(16),
}

token = jwt.JWT(header={"alg": "ES256", "kid": args.kid}, claims=claims)
token.make_signed_token(key)
print(token.serialize())
```

### Using JAR with PAR (PAR+JAR combined — recommended for Advanced)

```bash
REQUEST_OBJECT=$(python3 sign_jar.py \
  --client-id payment-initiation-service \
  --key client.key.pem \
  --audience https://auth.example.com/realms/banking/par \
  --redirect-uri https://app.example.com/callback \
  --code-challenge "${CODE_CHALLENGE}")

# Build client_assertion separately (authenticates the client to the PAR endpoint)
CLIENT_ASSERTION=$(python3 sign_jar.py \
  --client-id payment-initiation-service \
  --key client.key.pem \
  --audience https://auth.example.com/realms/banking/par \
  --redirect-uri https://app.example.com/callback \
  --code-challenge "${CODE_CHALLENGE}")

curl -s -X POST https://auth.example.com/realms/banking/par \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=payment-initiation-service" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${CLIENT_ASSERTION}" \
  --data-urlencode "request=${REQUEST_OBJECT}"
```

When a `request` parameter is present, Hearth validates the JWT signature against the
registered JWKS, then extracts all authorization parameters from the JWT payload. Parameters
outside the JWT are ignored (except `client_id` and `client_assertion*` which are always
read from the form body for authentication).

---

## 6. JARM — JWT Authorization Response Mode

JARM (JWT Secured Authorization Response Mode, FAPI 2.0 §4.3.1) wraps the authorization
response in a signed JWT delivered as a single `response` query parameter. This prevents:
- Injection of a code from another session
- Leaking response parameters in server logs (via `response_mode=form_post.jwt`)

JARM is **optional** for FAPI 2.0 Baseline and **mandatory** for Advanced.

### Requesting JARM

Add `response_mode=jwt` to the PAR body:

```bash
curl -s -X POST https://auth.example.com/realms/banking/par \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=payment-initiation-service" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${CLIENT_ASSERTION}" \
  --data-urlencode "response_type=code" \
  --data-urlencode "response_mode=jwt" \
  --data-urlencode "scope=openid accounts" \
  --data-urlencode "redirect_uri=https://app.example.com/callback" \
  --data-urlencode "code_challenge=${CODE_CHALLENGE}" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "state=${STATE}"
```

### JARM redirect response

Instead of:
```
https://app.example.com/callback?code=abc123&state=xyz
```

Hearth redirects to:
```
https://app.example.com/callback?response=eyJhbGciOiJFZERTQSIsImtpZCI6...
```

### Decoding the JARM response

```python
from jwcrypto import jwt, jwk
import urllib.request, json

# Fetch Hearth's public signing key from the JWKS endpoint
with urllib.request.urlopen(
    "https://auth.example.com/realms/banking/certs"
) as r:
    keyset = jwk.JWKSet.from_json(r.read())

response_jwt = "<value of ?response= parameter>"
tok = jwt.JWT(key=keyset, jwt=response_jwt)
claims = json.loads(tok.claims)

print(claims["code"])   # authorization code
print(claims["state"])  # must match the state you sent in the PAR request
print(claims["iss"])    # must equal the issuer (https://auth.example.com/realms/banking)
```

**Decoded JARM claims:**

| Claim | Value | Notes |
|-------|-------|-------|
| `iss` | Hearth issuer URL | Verify this matches the realm's `oidc.issuer` |
| `aud` | `client_id` | Must match your registered client ID |
| `exp` | Unix timestamp | Short-lived (≤ 600 s); reject expired responses |
| `code` | Authorization code | Single-use |
| `state` | Echoed from request | Verify against stored state to prevent CSRF |

### JARM error responses

On error, Hearth also wraps the response in a signed JARM JWT:

```json
{
  "iss": "https://auth.example.com/realms/banking",
  "aud": "payment-initiation-service",
  "exp": 1748556000,
  "error": "access_denied",
  "error_description": "User denied the authorization request",
  "state": "abc123"
}
```

### Response mode variants

| `response_mode` | Delivery | Notes |
|----------------|----------|-------|
| `jwt` | Redirect with `?response=` | Default JARM mode |
| `form_post.jwt` | HTTP POST with `response=` form field | Avoids logging in referrer headers |
| `fragment.jwt` | Redirect with `#response=` | Native apps / SPA only |

---

## 7. DPoP token binding

DPoP (Demonstrating Proof of Possession, RFC 9449) binds access tokens to the client's private
key. Even if a token is stolen, it cannot be used by an attacker who does not hold the matching
private key.

DPoP is **optional** for FAPI 2.0 Baseline and **mandatory** for Advanced.

### How DPoP works

1. Client generates an ephemeral key pair (one per session is fine; per-request is safer).
2. Client sends a `DPoP` header containing a signed JWT proof on every token endpoint request.
3. Hearth issues a DPoP-bound token (includes `cnf.jkt` = JWK thumbprint of the public key).
4. Resource servers verify the DPoP proof on every API call.

### Token exchange with DPoP

```bash
# 1. Build a DPoP proof JWT
DPOP_PROOF=$(python3 - <<'EOF'
import time, secrets, json
from jwcrypto import jwk, jwt

# Load (or generate) the client's DPoP key
with open("dpop.key.pem", "rb") as f:
    dpop_key = jwk.JWK.from_pem(f.read())

public_jwk = json.loads(dpop_key.export_public())

now = int(time.time())
claims = {
    "jti": secrets.token_urlsafe(16),
    "htm": "POST",
    "htu": "https://auth.example.com/realms/banking/token",
    "iat": now,
    "exp": now + 60,
}

token = jwt.JWT(
    header={"alg": "ES256", "typ": "dpop+jwt", "jwk": public_jwk},
    claims=claims
)
token.make_signed_token(dpop_key)
print(token.serialize())
EOF
)

# 2. Exchange the authorization code with the DPoP proof
curl -s -X POST https://auth.example.com/realms/banking/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "DPoP: ${DPOP_PROOF}" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=${CODE}" \
  --data-urlencode "redirect_uri=https://app.example.com/callback" \
  --data-urlencode "code_verifier=${CODE_VERIFIER}" \
  --data-urlencode "client_id=payment-initiation-service" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${CLIENT_ASSERTION}"
```

**Response** — Hearth returns a DPoP-bound access token:

```json
{
  "access_token": "eyJ...",
  "token_type": "DPoP",
  "expires_in": 300,
  "refresh_token": "...",
  "scope": "openid accounts"
}
```

Note `"token_type": "DPoP"` (not `"Bearer"`). The access token's payload includes:

```json
{
  "cnf": {
    "jkt": "<SHA-256 thumbprint of the client's DPoP public key>"
  }
}
```

Resource servers must verify that the `DPoP` header on every API request:
- Contains a valid signature by the key matching `cnf.jkt`
- Has `htm` matching the HTTP method and `htu` matching the request URL
- Has `iat` within an acceptable clock skew (Hearth issues tokens with ±30 s tolerance)

---

## 8. Testing FAPI 2.0 compliance

### Smoke tests with curl

The following sequence validates the full FAPI 2.0 Baseline PAR+PKCE flow against a running
Hearth instance:

```bash
#!/bin/bash
set -euo pipefail
BASE="https://auth.example.com/realms/banking"
CLIENT_ID="payment-initiation-service"

# 1. Generate PKCE
CODE_VERIFIER=$(openssl rand -base64 48 | tr -d '=+/' | cut -c1-64)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -binary -sha256 | openssl base64 | tr '+/' '-_' | tr -d '=')

# 2. Build client_assertion
CLIENT_ASSERTION=$(python3 sign_jar.py \
  --client-id "$CLIENT_ID" \
  --key client.key.pem \
  --audience "$BASE/par" \
  --redirect-uri "https://app.example.com/callback" \
  --code-challenge "$CODE_CHALLENGE")

# 3. PAR
PAR_RESPONSE=$(curl -sf -X POST "$BASE/par" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=$CLIENT_ASSERTION" \
  --data-urlencode "response_type=code" \
  --data-urlencode "scope=openid accounts" \
  --data-urlencode "redirect_uri=https://app.example.com/callback" \
  --data-urlencode "code_challenge=$CODE_CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "state=test-state-$(date +%s)")

REQUEST_URI=$(echo "$PAR_RESPONSE" | jq -r '.request_uri')
echo "✓ PAR succeeded: $REQUEST_URI"

# 4. Verify /par rejects missing client_assertion (must return 401)
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/par" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "response_type=code" \
  --data-urlencode "scope=openid" \
  --data-urlencode "redirect_uri=https://app.example.com/callback")
[[ "$HTTP_STATUS" == "401" ]] && echo "✓ Rejected missing client_assertion" \
  || echo "✗ Expected 401, got $HTTP_STATUS"

# 5. Verify /authorize rejects direct (non-PAR) requests (must return 400)
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE/authorize?response_type=code&client_id=$CLIENT_ID&scope=openid&redirect_uri=https://app.example.com/callback")
[[ "$HTTP_STATUS" == "400" ]] && echo "✓ Rejected non-PAR authorize request" \
  || echo "✗ Expected 400, got $HTTP_STATUS"

echo "Smoke tests complete. Continue with user-interactive flow manually."
```

### OpenID Foundation conformance suite

The authoritative FAPI 2.0 conformance test suite is run by the OpenID Foundation:

1. **Register** at <https://www.certification.openid.net>
2. Choose **FAPI 2.0 Security Profile** → **Baseline** or **Advanced**
3. Configure the test plan:
   - `discovery_url`: `https://auth.example.com/realms/banking/.well-known/openid-configuration`
   - `client_id`: your registered FAPI client ID
   - `jwks`: your client's public JWK set
   - `redirect_uri`: a URI registered with the conformance suite
4. Run all test variants (happy path, error injection, replay attacks)
5. Download the certification package; required for open banking certifications in EU/UK/AU

### Key test scenarios to cover

| Scenario | Expected result |
|----------|----------------|
| PAR with valid `private_key_jwt` | 201 + `request_uri` |
| PAR with expired `client_assertion` | 401 `invalid_client` |
| `/authorize` without `request_uri` (FAPI active) | 400 `invalid_request` |
| `/authorize` with reused `request_uri` | 400 `invalid_request` |
| Token exchange without PKCE verifier | 400 `invalid_grant` |
| Token exchange with wrong `code_verifier` | 400 `invalid_grant` |
| Token exchange with `client_secret_basic` (FAPI active) | 401 `invalid_client` |
| DPoP proof with wrong `htm` | 401 `use_dpop_nonce` or `invalid_dpop_proof` |
| JARM response signature verification | Must verify against `/certs` JWKS |

---

## 9. Common misconfiguration errors

| Error | HTTP | `error` | Cause and fix |
|-------|------|---------|---------------|
| Missing PAR step | 400 | `invalid_request` | Realm has `fapi_profile` active; all authorization requests must go through `/par` first |
| `client_secret_basic` auth | 401 | `invalid_client` | FAPI 2.0 disallows shared secrets; switch to `private_key_jwt` |
| Wrong `code_challenge_method` | 400 | `invalid_request` | Must be `S256`; `plain` is rejected under FAPI |
| Expired `request_uri` | 400 | `invalid_request` | `/par` URIs expire in 60 s; do not cache them across requests |
| Reused `request_uri` | 400 | `invalid_request` | Each PAR URI is single-use |
| `client_assertion` audience mismatch | 401 | `invalid_client` | Set `aud` to the exact endpoint URL (e.g., `/par` or `/token`) |
| `client_assertion` expired | 401 | `invalid_client` | `exp` must be ≤ 60 s from `iat`; check server clock sync (NTP) |
| Missing `kid` in JWKS | 400 | `invalid_request` | Every JWK registered with Hearth must have a `kid`; Hearth uses it to select the verification key |
| JAR `request` parameter missing (Advanced) | 400 | `invalid_request` | FAPI 2.0 Advanced requires a signed `request` JWT in the PAR body |
| DPoP proof missing (Advanced) | 400 | `use_dpop_nonce` | Include a `DPoP` header on every token endpoint request under Advanced profile |
| `response_mode` not `jwt` (Advanced) | 400 | `invalid_request` | Set `response_mode=jwt` in the PAR body; JARM is mandatory for Advanced |
| Wrong issuer in JARM | Reject | (client-side) | `iss` in the JARM JWT must match your realm's `oidc.issuer`; verify before accepting the code |

---

*See [docs/specs/OIDC.md §2](../specs/OIDC.md#2-fapi-20-security-profile) for the normative
implementation spec. See [hearth-yaml-examples.md — Example 41](hearth-yaml-examples.md#example-41--fapi-20-realm-banking)
for a copy-paste YAML configuration.*
