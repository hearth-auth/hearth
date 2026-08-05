# FAPI 2.0 Operator Guide

**Audience:** Operators deploying Hearth in financial-grade or regulated environments.
**Task:** Enable FAPI 2.0 enforcement, register compliant clients, and validate the PAR → JAR → JARM
authorization flow.

---

## 1. When to Use FAPI 2.0

Use FAPI 2.0 when any of the following apply:

| Context | Trigger |
|---------|---------|
| Open Banking APIs (UK, EU, Brazil, Australia) | Regulatory mandate |
| Payment initiation services (PSD2) | PSD2 / EBA RTS requirement |
| High-value API access (healthcare, insurance) | Internal security policy |
| OAuth 2.0 Security BCP compliance audits | RFC 9700 / OpenID FAPI 2.0 profile requirement |
| Any API where token replay = financial loss | Threat model |

FAPI 2.0 layered requirements in Hearth:

| Requirement | Baseline | Advanced |
|-------------|----------|----------|
| PAR mandatory (RFC 9126) | ✓ | ✓ |
| PKCE S256 mandatory (RFC 7636) | ✓ | ✓ |
| `iss` in every redirect response (RFC 9207) | ✓ | ✓ |
| JAR mandatory — signed request object (RFC 9101) | | ✓ |
| JARM mandatory — JWT-wrapped response | | ✓ |
| `private_key_jwt` only — no `client_secret` | | ✓ |
| DPoP sender-constrained tokens (RFC 9449) | ✓ | ✓ |

**Keycloak equivalent:** Keycloak's FAPI 1.0 Advanced / FAPI CIBA profiles are analogous to
Hearth's per-client `profile: fapi2`. Hearth does not implement CIBA (yet). Hearth FAPI 2.0
Advanced corresponds most closely to Keycloak's "FAPI 1 Advanced (OpenID Connect)" client policy.

---

## 2. Realm-Level FAPI Profile

Set `fapi_profile` on a realm to enforce FAPI 2.0 constraints on **every** client in that realm,
regardless of the client's individual `profile` setting.

### `hearth.yaml` configuration

```yaml
realms:
  - name: banking
    fapi_profile: baseline   # "baseline" | "advanced"
```

Valid values:

- `baseline` — all authorization requests in the realm must use PAR + PKCE S256. Clients that call
  `/authorize` directly (without a `request_uri`) receive `400 invalid_request`.
- `advanced` — all Baseline requirements plus: JAR required inside the PAR body; JARM required;
  any client without `authorization_signed_response_alg` set is rejected.
- Absent / `null` — standard OAuth 2.0 / OIDC rules apply; no FAPI constraints forced.

### Runtime update via Admin API

```bash
# Enable FAPI 2.0 Baseline for an existing realm
curl -s -X PATCH "$ISSUER/admin/realms/$REALM_ID/config" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"fapi_profile": "baseline"}'

# Upgrade to Advanced
curl -s -X PATCH "$ISSUER/admin/realms/$REALM_ID/config" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"fapi_profile": "advanced"}'

# Remove realm-level FAPI enforcement (revert to standard)
curl -s -X PATCH "$ISSUER/admin/realms/$REALM_ID/config" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"fapi_profile": null}'
```

Unknown values (`"enterprise"`, etc.) return `400 Bad Request`.

---

## 3. Register a FAPI 2.0 Client

Per-client FAPI 2.0 is enabled by setting `profile: "fapi2"` at registration. Use this when
only specific clients in a realm require FAPI 2.0 constraints; use realm-level `fapi_profile`
(§2) to enforce FAPI across all clients in a realm.

### Requirements

| Field | Required | Forbidden |
|-------|----------|-----------|
| `profile` | `"fapi2"` | |
| `jwks` | JWKS JSON string with the client's public key | |
| `client_secret` | | Must be absent — FAPI 2.0 clients authenticate with `private_key_jwt` |
| `redirect_uris` | At least one HTTPS URI | `http://` (non-TLS) |
| `response_type` | `"code"` only | `"token"`, `"id_token"` |

### Generate a key pair

```bash
# Generate Ed25519 private key
openssl genpkey -algorithm ed25519 -out client.key

# Extract public key
openssl pkey -in client.key -pubout -out client.pub

# Get the raw 32-byte public key as base64url (for JWKS x coordinate)
openssl pkey -in client.key -pubout -outform DER | tail -c 32 | base64 -w0 | \
  tr '+/' '-_' | tr -d '='
# → e.g. "ySW5vc7X8jSWdgMDfNNHrxRoCLvkSqV_EXAMPLE"
```

Build the JWKS JSON with your public key:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "alg": "EdDSA",
      "kid": "my-fapi-key-1",
      "x": "<base64url-encoded-public-key>"
    }
  ]
}
```

### Register via Admin API

```bash
REALM_ID="<realm-uuid>"
ADMIN_TOKEN="<hearth-admin-token>"
ISSUER="https://auth.example.com"

curl -s -X POST "$ISSUER/admin/applications" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My FAPI 2.0 Client",
    "profile": "fapi2",
    "redirect_uris": ["https://app.example.com/callback"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "jwks": "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"alg\":\"EdDSA\",\"kid\":\"my-fapi-key-1\",\"x\":\"<base64url-public-key>\"}]}",
    "authorization_signed_response_alg": "EdDSA"
  }'
```

**Successful response (201 Created):**

```json
{
  "client_id": "<uuid>",
  "client_name": "My FAPI 2.0 Client",
  "profile": "fapi2",
  "redirect_uris": ["https://app.example.com/callback"],
  "jwks": "...",
  "authorization_signed_response_alg": "EdDSA"
}
```

**Rejected — `client_secret` present:**
```json
{ "error": "invalid_client_metadata", "error_description": "FAPI 2.0 clients must use private_key_jwt" }
```

**Rejected — `jwks` missing:**
```json
{ "error": "invalid_client_metadata", "error_description": "FAPI 2.0 clients must register a JWKS" }
```

### Dynamic Client Registration (RFC 7591)

Alternatively, use the realm-scoped dynamic registration endpoint:

```bash
curl -s -X POST "$ISSUER/realms/<realm-name>/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My FAPI 2.0 Client",
    "profile": "fapi2",
    "redirect_uris": ["https://app.example.com/callback"],
    "jwks": "...",
    "authorization_signed_response_alg": "EdDSA"
  }'
```

---

## 4. PAR — Pushed Authorization Requests

In FAPI 2.0, clients must never call `/authorize` directly. Instead they push the authorization
parameters first, receive a `request_uri`, then redirect the user agent with only that URI.

**Flow:**
```
Client → POST /realms/{realm}/as/par   → 201 { request_uri, expires_in }
Client → redirect user to /realms/{realm}/authorize?request_uri=urn:...&client_id=...
User  → authenticates with Hearth
Hearth → redirect to redirect_uri?code=...&iss=...
Client → POST /realms/{realm}/token (with DPoP proof)
```

### Step 1: Push the authorization request

```bash
ISSUER="https://auth.example.com"
REALM="banking"
CLIENT_ID="<client-uuid>"
VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE=$(echo -n "$VERIFIER" | openssl dgst -sha256 -binary | base64 -w0 | tr '+/' '-_' | tr -d '=')

curl -s -X POST "$ISSUER/realms/$REALM/as/par" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"$CLIENT_ID\",
    \"redirect_uri\": \"https://app.example.com/callback\",
    \"scope\": \"openid\",
    \"response_type\": \"code\",
    \"state\": \"$(openssl rand -hex 16)\",
    \"nonce\": \"$(openssl rand -hex 16)\",
    \"code_challenge\": \"$CHALLENGE\",
    \"code_challenge_method\": \"S256\"
  }"
```

**Response (201 Created):**
```json
{
  "request_uri": "urn:ietf:params:oauth:request_uri:abc123def456",
  "expires_in": 90
}
```

The `request_uri` is valid for 90 seconds and may only be consumed once.

### Step 2: Redirect the user

Build the authorization redirect URL:

```
https://auth.example.com/realms/banking/authorize
  ?request_uri=urn:ietf:params:oauth:request_uri:abc123def456
  &client_id=<client-uuid>
```

**Rejected — direct `/authorize` without PAR (FAPI 2.0 client):**
```
HTTP 400
{ "error": "invalid_request", "error_description": "FAPI 2.0 clients must use PAR" }
```

---

## 5. JAR — JWT Authorization Requests

JAR (RFC 9101) places the authorization parameters inside a signed JWT. Under FAPI Advanced (§2),
JAR is required inside the PAR body. With per-client FAPI 2.0, JAR is optional but strongly
recommended.

### Building a JAR JWT

The JAR JWT must be signed with the client's private key (matching the registered JWKS).

Required claims:

| Claim | Value |
|-------|-------|
| `iss` | Client ID (prefixed: `client:<uuid>`) |
| `aud` | Realm issuer URL (`https://auth.example.com/realms/<name>`) |
| `iat` | Current Unix timestamp (seconds) |
| `exp` | `iat + 60` — max 300 seconds |
| `client_id` | Client ID (prefixed) |
| `redirect_uri` | Must match registered redirect URI |
| `scope` | Space-separated scopes |
| `response_type` | `code` |
| `code_challenge` | PKCE challenge |
| `code_challenge_method` | `S256` |

**Example (Python — signing with Ed25519):**

```python
import jwt  # PyJWT >= 2.0
import time
from cryptography.hazmat.primitives.serialization import load_pem_private_key

with open("client.key", "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None)

now = int(time.time())
client_id = "client:<your-client-uuid>"
issuer = "https://auth.example.com/realms/banking"

jar = jwt.encode(
    {
        "iss": client_id,
        "aud": issuer,
        "iat": now,
        "exp": now + 60,
        "client_id": client_id,
        "redirect_uri": "https://app.example.com/callback",
        "scope": "openid",
        "response_type": "code",
        "code_challenge": "<your-pkce-challenge>",
        "code_challenge_method": "S256",
        "state": "<random-state>",
        "nonce": "<random-nonce>",
    },
    private_key,
    algorithm="EdDSA",
    headers={"kid": "my-fapi-key-1"},
)
```

### PAR with JAR

Include the signed JWT as the `request` field in the PAR body:

```bash
curl -s -X POST "$ISSUER/realms/$REALM/as/par" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"$CLIENT_ID\",
    \"request\": \"$JAR_JWT\"
  }"
```

Claims in the JAR override any matching query parameters. The PAR response is the same
`{ request_uri, expires_in }` structure.

**Rejected — JAR signature invalid:**
```json
{ "error": "invalid_request_object", "error_description": "JAR signature verification failed" }
```

**Rejected — `client_id` in JAR does not match query parameter:**
```json
{ "error": "invalid_request", "error_description": "JAR client_id mismatch" }
```

---

## 6. JARM — JWT Authorization Response Mode

JARM wraps the authorization response in a signed JWT instead of plain query parameters.
For clients registered with `authorization_signed_response_alg: "EdDSA"`, JARM is always
applied — Hearth upgrades `response_mode=query` to `response_mode=query.jwt` automatically.

### What changes in the redirect

**Standard (non-JARM):**
```
https://app.example.com/callback?code=abc123&state=xyz&iss=https://auth.example.com/realms/banking
```

**JARM (`query.jwt`):**
```
https://app.example.com/callback?response=eyJhbGci...
```

The `response` parameter is a compact JWT signed with the realm's Ed25519 key. Verify it against
the realm JWKS at `GET /realms/<name>/.well-known/jwks.json`.

### JARM JWT structure

```json
{
  "iss": "https://auth.example.com/realms/banking",
  "aud": "client:<uuid>",
  "exp": 1234567890,
  "iat": 1234567830,
  "jti": "<unique-id>",
  "code": "<authorization-code>",
  "state": "<echoed-state>",
  "s_hash": "<state-hash>"     ← only for FAPI 2.0 clients
}
```

The `s_hash` claim is present only for FAPI 2.0 clients. It binds the response to the original
state value, preventing state-injection attacks:

```
s_hash = BASE64URL( LEFT( SHA-256( ASCII(state) ), 16 ) )
```

### JARM error responses

Authorization failures for FAPI/JARM clients also produce a JWT-wrapped error:

```json
{
  "iss": "https://auth.example.com/realms/banking",
  "aud": "client:<uuid>",
  "exp": 1234567890,
  "iat": 1234567830,
  "jti": "<unique-id>",
  "error": "invalid_request",
  "error_description": "PKCE required"
}
```

### Response modes

| Mode | Delivery | Use case |
|------|----------|----------|
| `query.jwt` | `?response=<jwt>` | Server-side web apps |
| `fragment.jwt` | `#response=<jwt>` | SPAs / native apps |
| `jwt` | Alias for `query.jwt` | Convenience |

---

## 7. Token Exchange with DPoP

FAPI 2.0 clients must prove possession of a private key at the token endpoint (DPoP, RFC 9449).
Requests without a valid `DPoP` header are rejected with `invalid_dpop_proof`.

### Build a DPoP proof

```python
import jwt
import time
import hashlib
import base64

now = int(time.time())

# token_endpoint_url = the URL you are sending the POST to
token_url = "https://auth.example.com/realms/banking/token"

dpop_proof = jwt.encode(
    {
        "jti": "<random-uuid>",
        "htm": "POST",          # HTTP method
        "htu": token_url,       # HTTP target URI (no query string)
        "iat": now,
        "exp": now + 30,
    },
    private_key,
    algorithm="EdDSA",
    headers={
        "typ": "dpop+jwt",
        "jwk": {                # Embed the PUBLIC key, not the private key
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "<base64url-public-key>"
        }
    },
)
```

### Exchange the authorization code

```bash
curl -s -X POST "$ISSUER/realms/$REALM/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "DPoP: $DPOP_PROOF" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$AUTH_CODE" \
  --data-urlencode "redirect_uri=https://app.example.com/callback" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=$CLIENT_ASSERTION_JWT" \
  --data-urlencode "code_verifier=$VERIFIER"
```

`client_assertion` is a short-lived JWT signed with the client private key (separate from the
DPoP proof). See RFC 7523 for the assertion structure.

**Rejected — DPoP header missing (FAPI 2.0 client):**
```json
{ "error": "invalid_dpop_proof", "error_description": "DPoP proof required for FAPI 2.0 clients" }
```

### Calling resource endpoints with a DPoP-bound token

A `cnf`-bound access token is not usable as a plain `Bearer`. Hearth verifies the sender-constraint
on every resource request, so each call needs its own fresh DPoP proof — including `/userinfo`,
`/realms/{realm}/userinfo`, and `/v1/me/permissions`. See
[OIDC.md §3.3](../specs/OIDC.md#33-resource-endpoint-enforcement-rfc-9449-72) for the full endpoint
list and normative rules.

The resource proof differs from the token-endpoint proof in three ways:

1. `htm` / `htu` describe the **resource request**, not the token request.
2. `ath` — the base64url SHA-256 hash of the access token — is **required**.
3. `htu` must be built from the **issuer** plus the request path, not from the host you dialled.
   Behind a reverse proxy or a private hostname, sign `https://auth.example.com/userinfo`, not the
   internal address.

```python
import jwt, time, uuid, hashlib, base64

def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

now = int(time.time())
issuer = "https://auth.example.com"          # must match the configured issuer
path = "/userinfo"                            # "/realms/banking/userinfo" for realm-scoped

resource_proof = jwt.encode(
    {
        "jti": str(uuid.uuid4()),             # unique per request — replayed jti is rejected
        "htm": "GET",
        "htu": issuer + path,
        "ath": b64url(hashlib.sha256(access_token.encode()).digest()),
        "iat": now,
        "exp": now + 30,                      # proofs older than 120 s are rejected
    },
    private_key,                              # the SAME key the token was bound to
    algorithm="EdDSA",
    headers={
        "typ": "dpop+jwt",
        "jwk": {"kty": "OKP", "crv": "Ed25519", "x": "<base64url-public-key>"},
    },
)
```

Send the token under the **`Bearer`** scheme — Hearth uses `Bearer` even for DPoP-bound tokens
(this deviates from RFC 9449 §7.1; `Authorization: DPoP ...` is not recognised):

```bash
curl -s "$ISSUER/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "DPoP: $RESOURCE_PROOF" \
  -H "X-Realm-ID: $REALM_ID"

# Realm-scoped variant — note htu must include the /realms/<realm> prefix:
curl -s "$ISSUER/realms/$REALM/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "DPoP: $RESOURCE_PROOF"
```

**Rejected — bound token replayed without a proof:**
```json
{
  "error": "invalid_token",
  "error_description": "DPoP proof required for cnf-bound access token"
}
```

**Rejected — proof signed with a different key than the token was bound to:**
```json
{
  "error": "invalid_token",
  "error_description": "DPoP proof key does not match token cnf.jkt binding"
}
```

Tokens issued without a DPoP proof carry no `cnf.jkt` and are unaffected — they keep working as
plain Bearer tokens with no `DPoP` header.

---

## 8. Testing FAPI 2.0 Compliance

### Discover the FAPI profile

Check the realm discovery document to confirm FAPI enforcement is active:

```bash
curl -s "https://auth.example.com/realms/banking/.well-known/openid-configuration" | \
  python3 -m json.tool | grep -E 'fapi|par|pushed|require'
```

For a realm with `fapi_profile: advanced`, the discovery document includes:
```json
{
  "pushed_authorization_request_endpoint": "https://auth.example.com/realms/banking/as/par",
  "require_pushed_authorization_requests": true,
  "request_parameter_supported": true,
  "authorization_signing_alg_values_supported": ["EdDSA"],
  "authorization_response_iss_parameter_supported": true,
  "fapi_profile": "advanced"
}
```

For standard realms, `fapi_profile` is absent and `require_pushed_authorization_requests` is
`false`.

### Smoke test — per-client FAPI 2.0

Run these checks after registering a FAPI 2.0 client:

```bash
# 1. Verify direct /authorize is rejected
curl -s -X POST "$ISSUER/realms/$REALM/authorize" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"'$CLIENT_ID'","redirect_uri":"https://app.example.com/callback","scope":"openid","response_type":"code","code_challenge":"'$CHALLENGE'","code_challenge_method":"S256"}' \
  | python3 -m json.tool
# Expected: { "error": "invalid_request", "error_description": "FAPI 2.0 clients must use PAR" }

# 2. Verify PAR without PKCE is rejected
curl -s -X POST "$ISSUER/realms/$REALM/as/par" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"'$CLIENT_ID'","redirect_uri":"https://app.example.com/callback","scope":"openid","response_type":"code"}' \
  | python3 -m json.tool
# Expected: { "error": "invalid_request", "error_description": "PKCE required" }

# 3. Verify token exchange without DPoP is rejected
curl -s -X POST "$ISSUER/realms/$REALM/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=fake-code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  | python3 -m json.tool
# Expected: { "error": "invalid_dpop_proof", ... }
```

### OpenID Foundation FAPI Conformance Suite

The [OpenID FAPI Conformance Suite](https://openid.net/certification/fapi_op_testing/) tests
server conformance against the full FAPI 2.0 Security Profile. To run it against a local
Hearth instance:

1. Expose Hearth over HTTPS (use a reverse proxy or `make dev` with an ngrok tunnel).
2. Point the suite at `https://<your-host>/realms/<realm-name>/.well-known/openid-configuration`.
3. Select **FAPI 2.0 Security Profile SP1** (Baseline) or **SP1 + JARM + PAR + JAR** (Advanced).
4. Register a test client using the suite's JWKS when prompted.

Hearth's internal test suite covers the conformance scenarios in `tests/fapi_conformance.rs` and
`tests/fapi2_conformance.rs`.

---

## 9. Common Misconfiguration Errors

| Error | HTTP status | Cause | Fix |
|-------|-------------|-------|-----|
| `invalid_client_metadata: FAPI 2.0 clients must use private_key_jwt` | 400 | `client_secret` present in registration | Remove `client_secret` |
| `invalid_client_metadata: FAPI 2.0 clients must register a JWKS` | 400 | `jwks` missing in registration | Add `jwks` with client public key |
| `invalid_request: FAPI 2.0 clients must use PAR` | 400 | Client called `/authorize` directly | Submit PAR first; use `request_uri` |
| `invalid_request: code_challenge required` | 400 | PKCE challenge missing in PAR body | Add `code_challenge` + `code_challenge_method=S256` |
| `invalid_request: PKCE method must be S256` | 400 | `code_challenge_method=plain` used | Use `S256` only |
| `invalid_dpop_proof: DPoP proof required for FAPI 2.0 clients` | 400 | Token request missing `DPoP` header | Build and attach a DPoP proof JWT |
| `invalid_dpop_proof: DPoP htm mismatch` | 400 | DPoP `htm` claim doesn't match HTTP method | Set `htm: "POST"` |
| `invalid_dpop_proof: DPoP htu mismatch` | 400 | DPoP `htu` claim is the wrong URL | Use the exact token endpoint URL (no query string) |
| `invalid_token: DPoP proof required for cnf-bound access token` | 401 | Bound token sent to a resource endpoint with no `DPoP` header | Attach a per-request resource proof (§7) |
| `invalid_token: DPoP proof key does not match token cnf.jkt binding` | 401 | Resource proof signed with a different key than the token was bound to | Reuse the key pair the token was issued against |
| `invalid_dpop_proof` at `/userinfo` (no description) | 401 | Resource proof missing `ath`, or `htu` built from the request `Host` instead of the issuer | Add `ath` = base64url SHA-256 of the access token; build `htu` from the configured issuer |
| `use_dpop_nonce` at a resource endpoint | 401 | Same `jti` presented twice (proof replay) | Generate a fresh `jti` per request |
| `invalid_request_object: JAR signature verification failed` | 400 | JAR JWT signed with wrong key | Sign with the private key matching the registered JWKS |
| `invalid_request: JAR client_id mismatch` | 400 | `client_id` in JAR ≠ `client_id` query param | Set both to the same prefixed client ID |
| `invalid_request: request_uri expired or already consumed` | 400 | PAR `request_uri` older than 90 s or replayed | Push a fresh PAR request |

---

## See Also

- [docs/specs/OIDC.md §2](../specs/OIDC.md#2-fapi-20-security-profile) — normative spec for FAPI 2.0 enforcement rules
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html) — OpenID Foundation spec
- [RFC 9126 — PAR](https://www.rfc-editor.org/rfc/rfc9126)
- [RFC 9101 — JAR](https://www.rfc-editor.org/rfc/rfc9101)
- [RFC 9449 — DPoP](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 7523 — `private_key_jwt`](https://www.rfc-editor.org/rfc/rfc7523)
- Conformance tests: `tests/fapi_conformance.rs`, `tests/fapi2_conformance.rs`, `tests/jarm.rs`,
  `tests/jar.rs`, `tests/par.rs`
