# Hearth OIDC & OAuth 2.0 Security Profiles

## Purpose

This document specifies Hearth's OIDC / OAuth 2.0 conformance profile and the FAPI 2.0 Security Profile
enforcement model. It is the normative reference for all FAPI-related implementation work.

Terminology follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 1. Standard OIDC Profile

Hearth implements OpenID Connect Core 1.0 and the following related specifications:

| Specification | Status |
|---------------|--------|
| OpenID Connect Core 1.0 | MUST |
| OpenID Connect Discovery 1.0 | MUST |
| OpenID Connect Dynamic Registration 1.0 (RFC 7591 / 7592) | MUST |
| OAuth 2.0 (RFC 6749) | MUST |
| OAuth 2.0 PKCE (RFC 7636) | MUST — S256 only |
| OAuth 2.0 Token Introspection (RFC 7662) | MUST |
| OAuth 2.0 Token Revocation (RFC 7009) | MUST |
| OAuth 2.0 Device Authorization Grant (RFC 8628) | MUST |
| OAuth 2.0 Authorization Server Issuer Identification (RFC 9207) | MUST |
| JWT Authorization Requests (JAR, RFC 9101) | MUST |
| Pushed Authorization Requests (PAR, RFC 9126) | MUST |
| JWT Authorization Response Mode (JARM) | MUST |
| JWT Profile for Access Tokens (RFC 9068) | MUST |
| OAuth 2.0 Demonstrating Proof of Possession (DPoP, RFC 9449) | MUST |
| OAuth 2.0 Rich Authorization Requests (RAR, RFC 9396) | SHOULD |
| OpenID Connect RP-Initiated Logout 1.0 | MUST |

### 1.1 PKCE Enforcement

PKCE (`code_challenge` + `code_challenge_method=S256`) is required for all clients by default per
RFC 9700 §2.1.1. Confidential clients may opt-out via `OidcConfig::require_pkce_for_confidential_clients: false`,
but this is STRONGLY DISCOURAGED and emits a startup warning.

### 1.2 Signing

- **ID tokens** and **JARM responses** are signed with Ed25519 (EdDSA) using the realm's per-realm
  signing key.
- The realm JWKS is published at `/.well-known/jwks.json` relative to the issuer URL.
- HS256 and `alg:none` are never issued.

---

## 2. FAPI 2.0 Security Profile

> **Operator guide:** For step-by-step setup, curl examples, and error reference, see
> [docs/guides/fapi2.md](../guides/fapi2.md).

Hearth supports two FAPI 2.0 enforcement mechanisms:

| Mechanism | Scope | Config field |
|-----------|-------|--------------|
| **Realm-level profile** | All clients in a realm | `RealmConfig::fapi_profile` |
| **Per-client profile** | A single OAuth 2.0 client | `OAuthClient::profile` |

These two controls are orthogonal. A realm without a FAPI profile can still have individual FAPI 2.0
clients; conversely, a FAPI 2.0 realm can host standard clients (though that is unusual).

### 2.1 Realm-Level Profile (`FapiProfile`)

Set in realm configuration as `fapi_profile: "baseline"` or `fapi_profile: "advanced"`.

#### 2.1.1 Baseline (`FapiProfile::Baseline`)

Enforced for every authorization request in the realm:

1. **PAR required** — authorization requests MUST be submitted via Pushed Authorization Requests
   (RFC 9126). Direct `/authorize` calls without a `request_uri` are rejected with `invalid_request`.
2. **PKCE S256 required** — `code_challenge` MUST be present; `code_challenge_method` MUST be `S256`.
3. **`iss` in responses** — all redirect responses include `iss` per RFC 9207.

#### 2.1.2 Advanced (`FapiProfile::Advanced`)

Enforces all Baseline requirements plus:

4. **JAR required** — authorization requests (including those sent via PAR) MUST contain a `request`
   parameter (RFC 9101 JWT Authorization Request). Requests without `request` are rejected.
5. **JARM required** — all authorization responses MUST be JARM-wrapped JWTs. The plain query/fragment
   response mode is forbidden.
6. **`private_key_jwt` required** — clients MUST authenticate at the token endpoint using
   `private_key_jwt` (RFC 7523). `client_secret_basic`, `client_secret_post`, and `none` are rejected.

### 2.2 Per-Client Profile (`ClientProfile::Fapi2`)

Set at client registration via `RegisterClientRequest::profile = ClientProfile::Fapi2`.
Stored on the `OAuthClient` record; evaluated independently of realm-level profile.

When a client has `profile = ClientProfile::Fapi2`, the following constraints apply to that client
regardless of the realm's `fapi_profile` setting:

| Constraint | Enforcement point | Error code |
|-----------|-------------------|------------|
| No `client_secret` at registration | `register_client` | `invalid_client_metadata` |
| JWKS required at registration | `register_client` | `invalid_client_metadata` |
| PAR-only authorization | `authorize` (`via_par` must be `true`) | `invalid_request` |
| `response_type=code` only | `authorize` | `unsupported_response_type` |
| DPoP required at token exchange | `exchange_code` / token endpoint | `invalid_dpop_proof` |
| `s_hash` in JARM responses | JARM JWT signing | Added automatically |

#### 2.2.1 Registration Enforcement

```
POST /realms/{realm}/clients/register

# FAPI2 client — OK
{ "profile": "fapi2", "jwks": "...", "redirect_uris": [...] }

# FAPI2 client with client_secret — REJECTED
{ "profile": "fapi2", "client_secret": "...", "redirect_uris": [...] }
# → 400 invalid_client_metadata: "FAPI 2.0 clients must use private_key_jwt"

# FAPI2 client without JWKS — REJECTED
{ "profile": "fapi2", "redirect_uris": [...] }
# → 400 invalid_client_metadata: "FAPI 2.0 clients must register a JWKS"
```

#### 2.2.2 Authorization Enforcement

FAPI 2.0 clients MUST reach `/authorize` through PAR. The identity engine sets `via_par = true`
on the `AuthorizationRequest` when it was constructed from a consumed `request_uri`. If `via_par`
is `false` for a FAPI 2.0 client, the request is rejected:

```
GET /authorize?client_id=fapi2-client&...
# → 400 invalid_request: "FAPI 2.0 clients must use PAR"

# Correct flow:
POST /par → { request_uri: "urn:..." }
GET /authorize?request_uri=urn:...&client_id=fapi2-client
# → accepted
```

#### 2.2.3 Token Endpoint Enforcement

FAPI 2.0 clients MUST provide a DPoP proof header at the token endpoint.
Requests without the `DPoP` header are rejected:

```
POST /token
Authorization: Basic <client_id>:<client_secret>    # rejected — no client_secret allowed anyway
DPoP: <proof-JWT>                                   # required
```

#### 2.2.4 `s_hash` in JARM

When a FAPI 2.0 client receives a JARM JWT and the authorization request included a non-empty `state`,
the JARM JWT MUST contain an `s_hash` claim:

```
s_hash = BASE64URL(LEFT(SHA-256(ASCII(state)), 16))
```

This binds the authorization response to the specific state value, preventing state-injection attacks.
Standard clients never receive `s_hash` in their JARM JWTs.

---

## 3. JAR (JWT Authorization Requests, RFC 9101)

Authorization requests may include a `request` parameter containing a signed JWT. Hearth enforces:

- The `request` JWT MUST be signed with the client's registered public key (from the client JWKS).
- Claims in the `request` JWT override corresponding query parameters.
- `client_id` in the JWT MUST match the query parameter `client_id`.
- For Advanced FAPI realms and applicable clients, a `request` JWT is mandatory.

Supported signing algorithms: `EdDSA` (Ed25519), `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`,
`ES256`, `ES384`, `ES512`.

---

## 4. JARM (JWT Authorization Response Mode)

Hearth supports three JARM response modes per the JARM specification:

| Response mode | Delivery mechanism | Use case |
|---------------|--------------------|----------|
| `query.jwt` | `?response=<jwt>` in redirect URI query | Standard web apps |
| `fragment.jwt` | `#response=<jwt>` in redirect URI fragment | SPAs / native |
| `jwt` | Alias for `query.jwt` by default | Convenience |

### 4.1 Per-Client Mandatory JARM

Clients may register with `authorization_signed_response_alg` set (e.g., `"EdDSA"`). When set:

- The AS issues JARM-wrapped responses regardless of the `response_mode` requested.
- If the client requests `response_mode=query` (plain), the AS silently upgrades it to `query.jwt`.
- JARM JWTs are signed with the realm signing key; the client verifies against the realm JWKS.

### 4.2 JARM Error Responses

When authorization fails for a FAPI/JARM client, the error is also JWT-wrapped:

```json
{
  "iss": "https://as.example.com",
  "aud": "client-id",
  "exp": 1234567890,
  "iat": 1234567830,
  "jti": "unique-id",
  "typ": "JWT",
  "error": "invalid_request",
  "error_description": "PKCE required"
}
```

---

## 5. Discovery Advertisement

The `/.well-known/openid-configuration` endpoint advertises FAPI-relevant capabilities:

```json
{
  "authorization_signing_alg_values_supported": ["EdDSA"],
  "authorization_response_iss_parameter_supported": true,
  "pushed_authorization_request_endpoint": "https://as.example.com/par",
  "require_pushed_authorization_requests": false,
  "response_modes_supported": ["query", "fragment", "form_post", "query.jwt", "fragment.jwt", "jwt"],
  "request_parameter_supported": true,
  "request_uri_parameter_supported": true,
  "end_session_endpoint": "https://as.example.com/realms/{realm}/end_session"
}
```

When a FAPI 2.0 Advanced realm is active, `require_pushed_authorization_requests` is set to `true`.

> **Note — Discovery serialization path.** The realm-scoped discovery handler at
> `GET /realms/{realm}/.well-known/openid-configuration` serializes the domain type directly
> (not through protobuf) to ensure all fields including `end_session_endpoint` are included.
> The global `/.well-known/openid-configuration` handler uses the same approach.

---

## 6. RP-Initiated Logout

Hearth implements [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).

### 6.1 Endpoints

| Endpoint | Method | Realm resolution |
|----------|--------|-----------------|
| `/end_session` | GET, POST | `X-Realm-ID` header (machine clients) |
| `/realms/{realm}/end_session` | GET, POST | URL path (browser / SPA clients) |

The realm-path-scoped endpoint additionally clears Hearth UI session cookies in the response so that a browser redirect after logout forces re-authentication on the next `/authorize` visit.

### 6.2 Query Parameters

All parameters are optional.

| Parameter | Description |
|-----------|-------------|
| `id_token_hint` | Previously issued ID token. Accepted even when expired. Used to identify the session to revoke. |
| `post_logout_redirect_uri` | URI to redirect the browser after logout. Must be registered on the client when `client_id` is present. |
| `client_id` | Client identifier — used to validate `post_logout_redirect_uri` against the client's registered list. |
| `state` | Opaque value echoed to `post_logout_redirect_uri` as `?state=…`. |

When neither `id_token_hint` nor an inferable session is present, the endpoint returns `400 invalid_request`.
When the session is already gone, the endpoint still redirects cleanly (idempotent behavior).

### 6.3 Back-Channel Logout Fan-Out

On successful logout, Hearth fans out back-channel logout tokens to all registered RPs that have a `backchannel_logout_uri` configured. Front-channel logout URIs are served via a redirect page when `post_logout_redirect_uri` is absent.

### 6.4 Authorization Endpoint — GET Shim for SPAs

The OIDC discovery document advertises `authorization_endpoint` as `{issuer}/authorize`. Browser-based PKCE clients (SPAs) redirect the user's browser there via `GET`. The interactive login+consent UI lives at `/ui/realms/{realm}/oauth/authorize`, so:

- `GET /realms/{realm}/authorize` — 302-redirects to the UI authorize page, preserving all query parameters.
- `POST /realms/{realm}/authorize` — machine API path for server-to-server flows. Returns a JSON authorization code that the caller can exchange at `/token`.

**Authentication required.** `POST /realms/{realm}/authorize` requires a valid Bearer token (HEA-1721). The token's `sub` claim is the authoritative user identity; any `user_id` field in the request body is ignored. This prevents unauthenticated callers from minting authorization codes for arbitrary accounts.

```http
POST /realms/{realm_id}/authorize
Authorization: Bearer <access_token>
X-Realm-ID: <realm_uuid>
Content-Type: application/json

{
  "client_id": "<client_uuid>",
  "redirect_uri": "https://app.example.com/callback",
  "scope": "openid profile",
  "code_challenge": "<S256-hash>",
  "code_challenge_method": "S256",
  "state": "<csrf-state>"
}
```

```json
{
  "code": "<single-use-authorization-code>",
  "state": "<csrf-state>"
}
```

The same Bearer-auth requirement applies to the equivalent gRPC `Authorize` RPC.

---

## 7. Test Coverage

| Test file | What it covers |
|-----------|----------------|
| `tests/fapi_conformance.rs` | Realm-level FAPI Baseline + Advanced enforcement |
| `tests/fapi2_conformance.rs` | Per-client `ClientProfile::Fapi2` enforcement (10 tests) |
| `tests/jarm.rs` | JARM JWT structure, signing, response mode negotiation, error wrapping |
| `tests/jar.rs` | JAR (RFC 9101) request JWT parsing, signature verification |
| `tests/private_key_jwt.rs` | `private_key_jwt` client authentication |
| `tests/rfc9207_iss.rs` | `iss` in authorization responses per RFC 9207 |
| `tests/fixtures/fapi2/conformance_vectors.json` | Test vectors for per-client FAPI 2.0 |

---

## 8. References

- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html)
- [RFC 9126 — Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126)
- [RFC 9101 — JWT Authorization Requests](https://www.rfc-editor.org/rfc/rfc9101)
- [RFC 9207 — Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207)
- [RFC 9449 — OAuth 2.0 DPoP](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [OAuth 2.0 JARM](https://openid.net/specs/oauth-v2-jarm.html)
