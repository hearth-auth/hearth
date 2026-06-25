# Hearth SDK Common Specification

> **Canonical reference.** This document is the board-approved specification for all Hearth client SDKs.  
> Generated from [HEA-332](https://github.com/hearth-auth/hearth) — do not edit without board approval.

> **Pre-release note (board, 2026-05-15):** Hearth has not shipped yet. Breaking changes are fully acceptable during all remediation phases. No backward-compatibility work, deprecation periods, or migration guides are required.

---

## 1. Configuration

Every SDK must accept a single primary entry point (a `HearthClient` class, struct, or equivalent) configured with:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `issuer_url` | string | Yes | Root URL of the Hearth instance (e.g. `https://auth.example.com`) |
| `client_id` | string | Conditional | Required for flows that need a client identity |
| `client_secret` | string | Conditional | Required for confidential client flows |
| `jwks_ttl` | duration | No | Override cache TTL for JWKS. Default: respect `Cache-Control`, fall back to 5 min |
| `introspection_endpoint` | string | No | Override discovered introspection URL |
| `http_timeout` | duration | No | Timeout for all outbound HTTP calls. Default: 10s |

SDKs **must** auto-discover all endpoint URLs from `{issuer_url}/.well-known/openid-configuration` on first use. Hard-coded endpoint paths are prohibited.

---

## 2. JWKS & Token Verification

**Required algorithm:** Ed25519 (`alg: "EdDSA"`, `kty: "OKP"`). Hearth exclusively issues tokens signed with Ed25519; SDKs **must** support OKP key verification.

> **Federation exception:** Hearth may relay tokens from third-party identity providers (e.g., enterprise SSO) that use RS256 or ES256. SDKs _should_ accept these algorithms when the corresponding key is present in the JWKS and the token's `alg` header matches, but RS256/ES256 are **never issued by Hearth itself**.

**OKP (Ed25519) JWKS key format:**

Hearth's JWKS endpoint emits Ed25519 public keys using the OKP key type defined in [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037):

| Field | Value |
|-------|-------|
| `kty` | `"OKP"` |
| `crv` | `"Ed25519"` |
| `x`   | Base64url-encoded 32-byte public key (the only coordinate) |
| `y`   | **Absent** — OKP/Ed25519 keys have no y-coordinate |
| `alg` | `"EdDSA"` |
| `use` | `"sig"` |

SDKs must parse OKP JWKs that omit `y`. Parsers that assume `y` is always present (common in EC-only JWK implementations) will fail to load Hearth's signing keys.

**JWKS caching rules (mandatory):**
1. Cache keys by `kid`. Do not discard keys not present in the latest fetch.
2. Respect `Cache-Control: max-age` from the JWKS endpoint response.
3. On cache miss for a `kid`: re-fetch once before returning an error.
4. On HTTP 401 from a protected resource: re-fetch JWKS once, then retry the verification.
5. Maximum cache age: 24 hours regardless of Cache-Control.
6. When parsing a cached JWKS, skip (do not error on) any key with an unrecognized `kty`; Hearth may add new key types for federation keys without a version bump.

**JWT validation steps (mandatory, in order):**
1. Verify signature against cached JWKS.
2. Verify `exp` claim (reject if expired).
3. Verify `iss` matches configured `issuer_url`.
4. Verify `aud` contains the configured `client_id` (server SDKs only; configurable).
5. Verify `iat` is not in the future (allow up to 5s clock skew).

**Rejected tokens must return a typed error** (see Section 5), not a bare string or generic exception.

**`verifyToken()` — required in every SDK, no per-language exception ([HEA-1553](/HEA/issues/HEA-1553) §7.1):**

Every SDK MUST expose a `verifyToken()` method — or the language-idiomatic equivalent (`VerifyToken` in Go, `verify_token` in Python/Rust/Kotlin) — with the following contract:

```
verifyToken(token: string) → Claims
```

- MUST execute all five JWT validation steps above, in order.
- MUST use JWKS-based Ed25519/EdDSA local signature verification. An introspection-only path does not satisfy this requirement.
- MUST return a typed `Claims` object on success (see §4).
- MUST return a typed error from §5 on any validation failure — never a bare string or generic exception.
- MUST NOT silently fall back to introspection or skip signature verification on any recoverable error.

**No per-language or per-platform exception applies.** Go, Python, Rust, Kotlin, PHP, and all future language SDKs must implement full EdDSA JWKS-based local verification. If a language's standard library does not include an Ed25519 verifier, the SDK MUST declare a dependency on a reputable Ed25519 library (e.g., `golang.org/x/crypto` for Go; `PyNaCl` or `cryptography` for Python; `ring` or `ed25519-dalek` for Rust; `tink` or `bouncycastle` for Kotlin/Java). Delegating signature verification to a reverse-proxy header, gateway, or remote service is non-conformant.

---

## 3. Token Introspection

All SDKs must expose an introspection method (RFC 7662):

```
introspect(token: string) → IntrospectionResult
```

`IntrospectionResult` must include:

| Field | Type | Required |
|-------|------|----------|
| `active` | bool | Always |
| `sub` | string | When active |
| `exp` | timestamp/int | When active |
| `iat` | timestamp/int | When active |
| `iss` | string | When active |
| `aud` | string or string[] | When active |
| `scope` | string | When active and present |
| `client_id` | string | When active and present |
| `extra` | map/dict | All non-standard claims |

Introspection results **must not be cached** (RFC 7662 §2.1 — the token state can change at any time).

---

## 3.5. Token Verification Modes

`OAuthClient.access_token_authorization` controls how resource servers must verify access tokens. The mode is operator-configured at client registration and determines whether JWKS verification alone is sufficient.

| Mode | Wire Value | Meaning |
|------|------------|---------|
| `Embedded` (default) | `"embedded"` | RBAC claims (`roles`, `permissions`, `groups`, `oid`) are fully embedded in the JWT; verify via JWKS |
| `Introspection` | `"introspection"` | JWT carries identity claims only; resource servers **MUST** call `introspect()` (§3) for live authorization data |
| `Decision` | `"decision"` | JWT carries identity claims only; resource servers **MUST** call `POST /oauth/authorize` per-request for live authorization decisions |

### Required SDK Behavior Per Mode

**`Embedded` (default)**

- Verify the token via JWKS (standard §2 flow).
- Trust RBAC claims embedded in the JWT: `roles`, `permissions`, `groups`, `oid`, `org_groups`.
- Introspection is not required and SHOULD NOT be called on the hot path.

**`Introspection`**

- **MUST** call `introspect()` (§3) before accepting the token for any authorization decision.
- **MUST NOT** rely on JWKS-verified JWT claims for authorization data (`roles`, `permissions`, `groups`, `oid`, `org_groups` are absent or empty in the JWT by design).
- JWKS signature verification MAY be performed for structural identity validation, but RBAC claims from the JWT **MUST** be ignored; all authorization data comes from the `IntrospectionResult`.
- An SDK that skips introspection and reads JWT RBAC claims directly will silently accept stale or missing authorization data — this is a security error.

**`Decision`**

- **MUST** call `POST /oauth/authorize` per-request to obtain a live authorization decision.
- **MUST NOT** rely on JWT claims or introspection results for access control.
- The token provides identity only; the authorization server evaluates all access control in real time.

### Mode Discovery and Configuration

The `access_token_authorization` mode is set by the operator at client registration (via `POST /admin/clients` or YAML `clients:` config). It is **not** advertised in the OIDC discovery document or embedded in the token — resource servers receive their mode through operator documentation or configuration management.

SDKs **MAY** expose a `token_authorization_mode` constructor parameter so operators can explicitly declare the expected mode. When declared:

- The SDK middleware (§6) **MUST** enforce the corresponding verification path.
- If the mode requires introspection but `client_id` / `client_secret` are not provided, the SDK **MUST** raise `ConfigurationError` at construction time rather than silently falling back to JWKS-only verification.

---

## 4. Claims API

Every SDK must provide typed access to standard JWT claims from a verified token, without requiring consumers to parse raw JSON:

| Method/Property | Returns |
|-----------------|---------|
| `subject()` | string |
| `issuer()` | string |
| `audiences()` | string[] |
| `expiry()` | native datetime/time type |
| `issuedAt()` | native datetime/time type |
| `jwtID()` | string (may be empty) |
| `scope()` | string (space-delimited) |
| `scopes()` | string[] (parsed) |
| `hasScope(s)` | bool |
| `hasRole(r)` | bool — reads Hearth `roles` claim |
| `hasPermission(p)` | bool — reads Hearth `permissions` claim |
| `inGroup(g)` | bool — reads Hearth `groups: string[]` claim |
| `inOrg(o)` | bool — reads Hearth `oid: string` claim |
| `tokenType()` | string — reads `token_type` claim (`"access"`, `"refresh"`, `"required_action"`) |
| `organizationId()` | string \| null — reads `oid` claim |
| `orgGroups()` | string[] — reads `org_groups` claim (Keycloak-style paths, e.g. `/org-slug/group`) |
| `get(claim)` | raw value (for custom claims) |

`hasRole` and `hasPermission` must read from Hearth's standard custom claims (`roles: string[]`, `permissions: string[]`). If the claim is absent, return `false` (never error).

`inGroup` reads `groups: string[]`; `inOrg` reads the `oid` string claim (exact match). Both must return `false` (never error) when the claim is absent.

### Hearth custom claims reference

The following non-standard claims are embedded in every Hearth-issued JWT. SDKs must expose typed accessors for them and must never error when they are absent (older tokens or third-party relay tokens may omit them):

| Claim | Type | Description |
|-------|------|-------------|
| `roles` | `string[]` | Roles assigned to the subject in the issuing realm |
| `permissions` | `string[]` | Expanded permission strings derived from roles |
| `groups` | `string[]` | Groups the subject belongs to within the realm |
| `oid` | `string` | Organization ID the token was issued for (B2B tenancy) |
| `org_groups` | `string[]` | Group paths scoped to the organization (Keycloak-style, e.g. `/org-slug/group`) |
| `tid` | `string` | Realm / tenant ID (matches the realm's `RealmId`) |
| `sid` | `string` | Session ID — present on access tokens tied to an interactive session |
| `token_type` | `string` | Token purpose: `"access"`, `"refresh"`, or `"required_action"` |

---

## 4.5 Required OAuth Flows

**Board decision ([HEA-1553](/HEA/issues/HEA-1553) §7.2):** Client-credentials, device authorization, and magic-link initiation are canonical required flows. Every Hearth SDK MUST implement all three. These are not optional extensions and are not browser-only: all server-side, CLI, and language SDKs must expose them.

> All endpoint URLs MUST be discovered from `{issuer_url}/.well-known/openid-configuration` on first use. Hard-coded paths are prohibited (see §1).

### 4.5.1 Client Credentials Grant (RFC 6749 §4.4)

Required for machine-to-machine (M2M) authentication: services, daemons, and admin tooling acting as their own principal.

**Required method:**

```
clientCredentials(scope?: string) → TokenResponse
```

`TokenResponse` must expose:

| Field | Type | Notes |
|-------|------|-------|
| `access_token` | string | The issued access token |
| `token_type` | string | `"Bearer"` or `"DPoP"` when DPoP is active |
| `expires_in` | int | Seconds until expiry |
| `scope` | string | Granted scope (may differ from requested) |

- MUST send `client_id` and `client_secret` as `application/x-www-form-urlencoded` body fields (RFC 6749 §2.3.1). Sending credentials as query parameters is explicitly prohibited.
- MUST discover the token endpoint (`token_endpoint`) from the OIDC discovery document.

**Example** (token endpoint path discovered from `/.well-known/openid-configuration`):

```bash
curl -s -X POST https://auth.example.com/realms/my-realm/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=<your-client-id>" \
  -d "client_secret=<your-client-secret>" \
  -d "scope=read:users"
# → {"access_token":"eyJ...","token_type":"Bearer","expires_in":3600,"scope":"read:users"}
```

### 4.5.2 Device Authorization Flow (RFC 8628)

Required for devices and CLI tools with limited input capability (headless servers, CI pipelines, IoT devices).

**Required methods:**

```
startDeviceFlow(scope?: string) → DeviceAuthorizationResponse
pollDeviceToken(deviceCode: string, interval: int) → TokenResponse
```

`DeviceAuthorizationResponse` must expose:

| Field | Type | Notes |
|-------|------|-------|
| `device_code` | string | Opaque code passed to `pollDeviceToken` |
| `user_code` | string | Short code the user enters at `verification_uri` |
| `verification_uri` | string | URL the user visits to authorize |
| `verification_uri_complete` | string | `verification_uri` with `user_code` pre-filled (when provided by server) |
| `expires_in` | int | Seconds until device code expires |
| `interval` | int | Minimum polling interval in seconds |

`pollDeviceToken` MUST:
- Respect the server's `interval` value (RFC 8628 §3.5 default: 5 s).
- Handle `authorization_pending` by continuing to poll without surfacing an error to the caller.
- Handle `slow_down` by increasing the polling interval by 5 s per occurrence and continuing to poll.
- Raise `TokenExpiredError` when the device code expires (`expired_token` error response).

**Example — initiate** (endpoint path from `device_authorization_endpoint` in discovery):

```bash
curl -s -X POST https://auth.example.com/realms/my-realm/device/authorize \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=<your-client-id>" \
  -d "scope=openid profile"
# → {"device_code":"GmRh...","user_code":"WDJB-MJHT",
#    "verification_uri":"https://auth.example.com/realms/my-realm/activate",
#    "expires_in":600,"interval":5}
```

**Example — poll** (token endpoint path from `token_endpoint` in discovery):

```bash
curl -s -X POST https://auth.example.com/realms/my-realm/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=<device_code>" \
  -d "client_id=<your-client-id>"
# User approved → {"access_token":"eyJ...","token_type":"Bearer","expires_in":900}
# Still waiting → {"error":"authorization_pending"}
# Polling too fast → {"error":"slow_down"}
```

### 4.5.3 Magic-Link Initiation (Passwordless)

Required for passwordless authentication flows where a user authenticates by clicking a single-use link delivered by email.

**Required method:**

```
requestMagicLink(email: string) → void
```

- MUST call `POST /v1/{realm}/auth/magic-link` with a JSON body `{"email": "<address>"}`, where `{realm}` is the realm's slug extracted from `issuer_url`.
- MUST accept any 202 response as success without surfacing additional detail.
- MUST NOT raise a "user not found" or equivalent error when the email is unrecognized. The server always returns `202 Accepted` regardless of whether the email is registered (enumeration resistance); the SDK must pass this behavior through unchanged.
- MUST surface HTTP 429 (`Too Many Requests`) as a typed rate-limit error.

The magic-link endpoint is a Hearth-specific endpoint and is **not** advertised in the OIDC discovery document. The SDK derives the path using the realm slug from `issuer_url`: `POST {base_url}/v1/{realm_slug}/auth/magic-link`.

After the SDK method returns, authentication completes entirely in the user's browser. Hearth validates the token when the user clicks the link and establishes a session cookie — no further API call is required from the SDK.

**Example:**

```bash
curl -s -X POST https://auth.example.com/v1/my-realm/auth/magic-link \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
# Always → 202 Accepted: {"message":"If an account exists, a magic link has been sent"}
```

---

## 5. Error Taxonomy

All SDKs must define and expose the following error/exception types. Language-native error handling patterns apply (Go: sentinel errors + types; Python: exceptions; TypeScript: typed Error subclasses; etc.):

| Error | When Thrown |
|-------|-------------|
| `ConfigurationError` | Missing required config, invalid issuer URL |
| `DiscoveryError` | OIDC discovery endpoint unreachable or returned invalid JSON |
| `JWKSFetchError` | JWKS endpoint unreachable or returned invalid response |
| `TokenExpiredError` | `exp` claim is in the past |
| `TokenNotYetValidError` | `nbf` claim is in the future (beyond clock skew) |
| `TokenInvalidError` | Signature invalid, malformed JWT, or algorithm mismatch |
| `TokenIssuerError` | `iss` does not match configured issuer |
| `TokenAudienceError` | `aud` does not contain expected audience |
| `IntrospectionError` | Introspection endpoint unreachable or returned error |
| `RequiredActionError` | Token has `token_type === "required_action"` (required-action JWT presented as a regular access token), or server returns `error_code: "HEARTH_REQUIRED_ACTIONS_PENDING"` |

`RequiredActionError` must additionally expose:
- `requiredActions: string[]` — the pending action names from the token's `required_actions` claim (e.g. `["VERIFY_EMAIL", "UPDATE_PASSWORD"]`).
- `redirectUri?: string` — optional URL to the Hearth interstitial page, when one is provided by the server.

All errors must include a human-readable `message`. Errors that wrap an underlying network or parse error must expose the original cause (Go: `Unwrap()`; Python: `__cause__`; TypeScript: `cause` property).

**Tokens and secrets must never appear in error messages or log output.**

---

## 6. Middleware

All server-side SDKs (node, go, python) must provide HTTP middleware that:

1. Extracts the Bearer token from `Authorization: Bearer <token>`.
2. Verifies the token locally (JWKS path) by default. Introspection must be opt-in.
3. On success: injects verified claims into the request context using a well-known key.
4. On missing/invalid token: responds with `401 Unauthorized`, `WWW-Authenticate: Bearer realm="hearth"`.
5. On insufficient scope/role: responds with `403 Forbidden`.
6. On a token where `token_type === "required_action"`: MUST respond with `401 Unauthorized` and throw `RequiredActionError` (not a generic `UnauthorizedError`). The `requiredActions` field MUST be populated from the `required_actions` claim in the JWT. This token is valid but scoped only to completing the required actions — it MUST NOT be accepted for general API access.
7. Does not call `next` on auth failure.

The browser SDK (`@hearth-auth/browser`) is exempt from the middleware requirement but must provide equivalent helpers for SPA route guards.

**Framework adapters** (Express, Fastify, Flask, FastAPI, net/http, chi, gin) are bundled with the SDK or in a companion package. The core SDK has no framework dependency.

---

## 7. PKCE & Browser Flows (browser SDK only)

The browser SDK must additionally implement:

- **PKCE authorization code flow** (RFC 7636): `login()` → redirect, `handleCallback()` → tokens
- **Silent refresh**: Attempt token renewal via hidden iframe before expiry. Configurable lead time (default: 60s before exp).
- **Logout**: Local session clear + RP-initiated logout redirect.
- **Storage abstraction**: Default `sessionStorage`; pluggable (localStorage, in-memory, custom). Storage key prefix must be configurable.
- **Cross-tab state sync**: Broadcast channel or storage events to sync login/logout across tabs (optional but recommended).

### `handleCallback()` — required-action detection

After exchanging the authorization code for tokens, `handleCallback()` MUST inspect `token_type` before resolving with a usable access token:

1. If the server issues a token with `token_type === "required_action"`: MUST throw `RequiredActionError` instead of storing the token as a valid access token. Populate `requiredActions` from the token's `required_actions` claim.
2. If the callback URL contains a `required_action_redirect_uri` query parameter (server-supplied interstitial redirect): MUST throw `RequiredActionError` and set `error.redirectUri` to that value so the application can forward the user to the Hearth interstitial page.
3. If neither condition applies, resolve normally and return the access/refresh token pair.

Applications that catch `RequiredActionError` from `handleCallback()` SHOULD redirect the user to `error.redirectUri` (when present) or construct the appropriate `/ui/required-actions/{action}` URL for the first pending action.

---

## 8. Versioning

- All SDKs use **SemVer** (MAJOR.MINOR.PATCH).
- Each SDK release declares a minimum compatible Hearth server version in its README and package metadata.
- A `CHANGELOG.md` is required and maintained per release.
- **During Phase 2–3 remediation:** major version bumps and breaking API changes are freely permitted with no deprecation period or migration guide required. The product is unreleased and has no external users to protect.

---

## 9. Testing Requirements

| Category | Requirement |
|----------|-------------|
| Unit tests | All public methods and error paths |
| Integration tests | Verified against a live Hearth instance (or Hearth test server in CI) |
| JWKS rotation test | Force a key rollover and verify transparent recovery |
| Clock skew test | Verify tolerance at boundaries |
| Coverage target | ≥ 80% line coverage |
| CI gate | Tests must pass on every PR; coverage check enforced |

---

## 10. Documentation Requirements

Every SDK repo must contain:

- `README.md` with installation + quickstart (< 5 min to first verified token)
- Full API reference (generated from source or hand-written)
- One runnable example per supported framework
- Troubleshooting section covering common errors from Section 5
- Link to Hearth server compatibility matrix

---

## 11. Security Requirements

- Tokens and secrets must **never** appear in logs, error messages, or stack traces.
- All HTTPS connections must validate TLS certificates (no `InsecureSkipVerify` or equivalent).
- Timing-safe comparison for any credential or secret comparison.
- Dependencies must be minimal and pinned/audited (e.g., `dependabot` enabled).
- No eval, exec, or dynamic code generation on token data.

---

## 12. Admin SDK

The Admin SDK is an **optional** surface exposing management operations against the Hearth admin API (`/admin/*` endpoints). It is a separate entry point from the resource-server (`HearthClient`) and browser SDKs — not a subobject or method on `HearthClient`.

### Entry Point

SDKs must expose a dedicated `AdminClient` type. Instantiation requires:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `base_url` | string | Yes | Root URL of the Hearth instance (no trailing slash) |
| `realm_id` | string | Yes | ID of the realm to administer |
| `access_token` | string | Yes | A valid access token whose subject holds the `admin` role in the target realm |

`AdminClient` does **not** perform OIDC discovery and does **not** manage token lifecycle. The caller is responsible for obtaining and refreshing the admin access token (typically via a confidential client's `client_credentials` grant).

All requests must include the following headers:

```
Authorization: Bearer {access_token}
X-Realm-ID: {realm_id}
```

### Scoping and Auth

- All operations are scoped to the realm identified by `realm_id`.
- The `access_token` must belong to a subject with the `admin` role in that realm.
- Tokens scoped to the system realm (`RealmId::nil()`) may administer realm-level metadata (e.g., creating or deleting realms via `/admin/realms`).
- A `403 Forbidden` response indicates the token's subject lacks the required admin role; SDKs should surface this as a distinct error (e.g., an HTTP error type carrying the status code) rather than silently failing.

### Minimum Required Operations

All `AdminClient` implementations must provide at minimum:

#### Users

| Method | HTTP Equivalent |
|--------|-----------------|
| `createUser(params)` | `POST /admin/users` |
| `getUser(id)` | `GET /admin/users/{id}` |
| `updateUser(id, params)` | `PUT /admin/users/{id}` |
| `deleteUser(id)` | `DELETE /admin/users/{id}` |
| `listUsers(options)` | `GET /admin/users?limit=N&cursor=C` |

#### Realms

| Method | HTTP Equivalent |
|--------|-----------------|
| `createRealm(params)` | `POST /admin/realms` |
| `getRealm(id)` | `GET /admin/realms/{id}` |
| `updateRealm(id, params)` | `PUT /admin/realms/{id}` |
| `deleteRealm(id)` | `DELETE /admin/realms/{id}` |
| `listRealms(options)` | `GET /admin/realms?limit=N&cursor=C` |

#### OAuth Clients, Roles, Groups, Organization Memberships

These entities follow the same CRUD + list pattern targeting:
- `/admin/clients` — OAuth 2.0 client registrations
- `/admin/roles` — realm-level role definitions
- `/admin/groups` — realm-level group definitions
- `/admin/orgs/{orgId}/members` — organization membership management

### Pagination

All list methods must accept an optional `limit` (integer, server-defined default) and `cursor` (opaque string for continuation) parameter. Responses must include a `PageResponse` envelope with items and an optional `next_cursor`. When `next_cursor` is absent or null, no further pages exist.

### Error Handling

`AdminClient` errors must use the same error taxonomy from Section 5 where applicable. HTTP 4xx/5xx responses not covered by that taxonomy (e.g., `403 Forbidden` on insufficient admin role) must be surfaced as typed errors that include the HTTP status code — not swallowed or mapped to a generic exception.

---

## Conformance Checklist

For use in PR reviews and automated CI checks (see `.github/workflows/sdk-conformance.yml` and `scripts/check-sdk-conformance.sh`):

- [ ] Error types match the 10 names from Section 5 (`ConfigurationError`, `DiscoveryError`, `JWKSFetchError`, `TokenExpiredError`, `TokenNotYetValidError`, `TokenInvalidError`, `TokenIssuerError`, `TokenAudienceError`, `IntrospectionError`, `RequiredActionError`)
- [ ] `RequiredActionError` exposes `requiredActions: string[]` and optional `redirectUri: string` (Section 5)
- [ ] Browser SDK `handleCallback()` throws `RequiredActionError` on `token_type === "required_action"` or `required_action_redirect_uri` callback param (Section 7)
- [ ] Server-side middleware returns `401` and throws `RequiredActionError` on `token_type === "required_action"` (Section 6)
- [ ] All 17 public Claims API methods from Section 4 are present (`subject`, `issuer`, `audiences`, `expiry`, `issuedAt`, `jwtID`, `scope`, `scopes`, `hasScope`, `hasRole`, `hasPermission`, `inGroup`, `inOrg`, `tokenType`, `organizationId`, `orgGroups`, `get`)
- [ ] No tokens or secrets can appear in error messages or logs (Section 11)
- [ ] JWKS caching follows the 5-rule contract (Section 2)
- [ ] Tests cover JWKS rotation and clock skew edge cases (Section 9)
- [ ] README includes quickstart, API reference, and troubleshooting (Section 10)
- [ ] CHANGELOG.md present and updated (Section 8)
- [ ] `access_token_authorization` mode handling: `Introspection` and `Decision` modes enforce introspect/authorize call before accepting claims; JWKS-only verification is not used for authorization in those modes (Section 3.5)
- [ ] Ed25519/OKP JWKS key parsing: SDK correctly parses OKP keys (`kty: "OKP"`, `crv: "Ed25519"`) from the JWKS endpoint; does not require a `y` coordinate; does not error on unrecognized `kty` values (Section 2)
- [ ] Admin SDK entry-point pattern: `AdminClient` is a separate type from `HearthClient`; takes `(base_url, realm_id, access_token)` directly (no OIDC discovery); sends `X-Realm-ID` header on every request; implements minimum CRUD + list for users, realms, clients, roles, groups, and org memberships (Section 12)
- [ ] Agent auth section present in README: covers agent CRUD (`/v1/agents`), API-key issuance, DPoP proof construction (RFC 9449), RFC 8693 token exchange, AAT issuance/derivation (`/v1/aats`), transaction token lifecycle (`/v1/transaction-tokens`), and draft-tracking owner reference (Section 13)
- [ ] `verifyToken()` (or language-idiomatic equivalent `VerifyToken` / `verify_token`) present in every SDK: performs full Ed25519/EdDSA JWKS signature verification locally; returns typed `Claims` on success; returns typed §5 error on failure; does not delegate to introspection-only or reverse-proxy verification (§2)
- [ ] No per-language EdDSA exception: SDK declares an Ed25519 library dependency rather than skipping or proxying local signature verification; verification works without a running proxy or gateway (§2)
- [ ] Client credentials grant present: `clientCredentials()` (or equivalent) sends `client_id` and `client_secret` as POST body fields (`application/x-www-form-urlencoded`); discovers token endpoint from OIDC discovery document; does not send credentials as query parameters (§4.5.1)
- [ ] Device authorization flow present: `startDeviceFlow()` (or equivalent) calls discovered `device_authorization_endpoint`; `pollDeviceToken()` respects server `interval`; `authorization_pending` handled transparently; `slow_down` increases interval by 5 s per occurrence; `expired_token` raises `TokenExpiredError` (§4.5.2)
- [ ] Magic-link initiation present: `requestMagicLink()` (or equivalent) POSTs JSON `{"email":"..."}` to `/v1/{realm_slug}/auth/magic-link`; always passes through `202 Accepted` without surfacing a "user not found" error; surfaces HTTP 429 as a rate-limit error (§4.5.3)

---

## Section 13 — Agent Authentication Surface (M5)

This section is informational for SDK authors. The agent-auth surface is exposed entirely as REST endpoints; no new SDK type is strictly required beyond the existing `AdminClient` HTTP methods. SDK READMEs MUST document the surface below.

### Required README coverage

Every SDK README MUST include an "Agent Authentication" section covering:

1. **Prerequisites** — `agent_auth.capabilities.identity = true` (plus `advanced = true` for AATs/txn tokens)
2. **Agent CRUD** — `POST /v1/agents`, `POST /v1/agents/{id}/credentials/keys`
3. **DPoP-bound tokens (RFC 9449)** — EC P-256 key pair generation, JWK thumbprint (RFC 7638), proof JWT construction (`typ: dpop+jwt`, `cnf.jkt` binding), nonce flow
4. **RFC 8693 token exchange** — `urn:ietf:params:oauth:grant-type:token-exchange`, `act` claim chain, `on_behalf_of` extension
5. **AATs** — `POST /v1/aats` (root issuance), `POST /v1/aats/derive` (scope narrowing, child ⊆ parent)
6. **Transaction tokens** — `POST /v1/transaction-tokens` + `/consume` (single-use, 60s TTL, replay prevention)
7. **Draft-tracking owner** — name the owner responsible for re-checking IETF draft advancement

### Draft standards (as of 2026-06-21)

| Draft | Pinned version | Hearth feature |
|-------|---------------|----------------|
| On-Behalf-Of for Agents | draft-oauth-ai-agents-on-behalf-of-user-02 | `on_behalf_of` claim in RFC 8693 exchange |
| Attenuating Agent Tokens | draft-niyikiza-oauth-attenuating-agent-tokens | `/v1/aats` AAT engine |
| Transaction Tokens for Agents | draft-oauth-transaction-tokens-for-agents | `/v1/transaction-tokens` |
| Agent Identity Protocol | draft-prakash-aip | Agent CRUD, Agent Card |
| OpenID SSF/CAEP | CAEP draft | DPoP JKT blocklist, risk signals |

**Draft-tracking owner:** @therecluse26 (CTO). When any draft advances to a new revision or RFC, open a follow-up issue on [HEA-1409](/HEA/issues/HEA-1409).
