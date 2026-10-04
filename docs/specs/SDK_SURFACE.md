# Hearth SDK Canonical Surface

> **Status:** As-built — coverage matrix re-verified from source after [PR #229](https://github.com/) (HEA-1552), 2026-06-25.  
> **Coverage:** C-01–C-19 ship across all applicable SDKs; PKCE (C-17, the original trigger gap) is now universal. Residual gaps tracked in §7.1.  
> **Source of truth for:** capability identity, required behavior contracts, and language-idiomatic symbol names.  
> **Full behavioral spec:** [`docs/specs/SDK.md`](SDK.md) — this document maps capabilities to symbols; SDK.md is normative for behavior.  
> **Scope trim (2026-10):** Hearth now ships four SDKs — TypeScript, Go, Python, PHP. The Node.js SDK (`@hearth-auth/node`) was folded into `@hearth-auth/sdk`; the Rust and Kotlin SDKs were removed. The TypeScript rows below are re-checked against `sdks/typescript/src`; the Go, Python and PHP status cells in §4 still record the 2026-06 design target. The [`sdk-standard-libraries`](../../openspec/changes/sdk-standard-libraries/) change moved all four SDKs onto standard JOSE libraries (C-03, C-04), generated each admin client from OpenAPI (C-19), and added a shared live conformance harness (SDK.md §9); the C-04 and C-19 rows are re-checked against all four SDKs.

---

## 1. Purpose

This document is the **design artifact** that enumerates every capability every Hearth SDK must expose, assigns a stable capability ID to each, states the required behavioral contract, and names the exact public symbol (class, method, function) for each SDK.

C2–C8 engineers use the symbol-name mapping as their implementation target. Any SDK that ships without all capabilities in this document (or an explicit exception below) is non-conforming.

---

## 2. SDK Inventory

| SDK key | Package | Role | Primary entry point |
| --------- | --------- | ------ | --------------------- |
| **TS** | `@hearth-auth/sdk` | Browser SPA, Node.js server, Next.js | `HearthClient` |
| **Go** | `github.com/hearth-auth/hearth-go` | Server / service | `NewClient()` → `*Client` |
| **PHP** | `hearth-auth/sdk` | Server (PSR-18) | `HearthClient` |
| **Python** | `hearth-sdk` | Server (sync HTTP) | `HearthClient` |

> **Per-capability reference implementations** — no single SDK is most complete; consult the SDK that has shipped the capability you are implementing:
>
> | Area | Best reference | Why |
> |------|---------------|-----|
> | C-10 client_credentials, C-11 device_flow, C-12 magic_link | **TS** | All three §7.2 flows on `HearthClient` |
> | C-04 verifyToken + EdDSA selector | **TS** | `jose` with `algorithms: ["EdDSA"]` in `JwksClient.verify` |
> | C-06 Claims API (full 17 accessors) | **TS** or **Python** | Both ship all 17 accessors |
> | C-16 Middleware (embedded/introspection/decision modes) | **Python** | Both ASGI + WSGI; Go is a close second |
> | C-19 Admin SDK | **Python** or **Go** | Most complete CRUD coverage |
> | C-08/C-09 Auth code + refresh | **TS**, **Go**, **PHP**, **Python** | All ship these; any is a valid reference |

---

## 3. Capability Registry

Each capability has a stable **C-ID** used throughout this doc and in child issues.

### Tier 1 — Verification (all SDKs)

| C-ID | Capability | Behavioral contract |
| ------ | ----------- | --------------------- |
| **C-01** | Client configuration | Single entry point (`HearthClient`/`NewClient`/etc.) accepting `issuerUrl`, optional `clientId`, `clientSecret`, `jwksTtl`, `introspectionEndpoint`, `httpTimeout`. Validates required params at construction. Throws `ConfigurationError` on invalid URL. See SDK.md §1. |
| **C-02** | OIDC discovery | Auto-discovers all endpoint URLs from `{issuerUrl}/.well-known/openid-configuration` on first use. Hard-coded paths are prohibited. Caches the document for the session lifetime. Throws `DiscoveryError` on failure. |
| **C-03** | JWKS fetch & cache | Fetches keys from the discovered `jwks_uri`. Caches by `kid`. Respects `Cache-Control: max-age`, 24 h ceiling. On `kid` miss: re-fetches once; a `kid` still absent is `TokenInvalidError`. Skips unrecognized `kty` values. Throws `JWKSFetchError` only when the endpoint is unreachable or answers an invalid document. See SDK.md §2. |
| **C-04** | Token verification (`verifyToken`) | Verifies through the SDK's JOSE library (TS `jose`, Go `go-jose/v4`, Python `PyJWT`, PHP `lcobucci/jwt`; no handwritten signature code): signature against JWKS, then `exp`, `iss` (against the configured issuer), `aud` (optional), `nbf` and `iat`, with one 5 s clock-skew allowance on all three time claims. **EdDSA (`alg: "EdDSA"`, `kty: "OKP"`) is the only accepted algorithm; every other `alg` — RS256 and ES256 included — must be rejected.** Returns typed `Claims`. Throws typed errors (§C-07). On `kid` miss: re-fetches once. See SDK.md §2 and §6.1 below. |
| **C-05** | Token introspection | RFC 7662 `POST /introspect`. Never cached. Requires `clientId` + `clientSecret`. Returns typed `IntrospectionResult` (`active`, `sub`, `exp`, `iat`, `iss`, `aud`, `scope`, `client_id`, `extra`). Throws `IntrospectionError` on failure. See SDK.md §3. |
| **C-06** | Claims API | 17 typed accessors on a `Claims` (or `VerifiedToken`) object. All accessors return `false`/empty (never error) when the claim is absent. Full accessor list in §6.2 below. See SDK.md §4. |
| **C-07** | Error taxonomy | 10 named error types. Language-native error handling applies (Go: sentinel errors; Python: exceptions; TS: Error subclasses; PHP: `\Throwable`). Errors must never include token values. See SDK.md §5. |

### Tier 2 — OAuth Flows (all SDKs; §7.2 required)

| C-ID | Capability | Behavioral contract |
| ------ | ----------- | --------------------- |
| **C-08** | Authorization code exchange | `exchangeCode(code, redirectUri, codeVerifier?)` → `TokenResponse`. Posts `grant_type=authorization_code` to `token_endpoint`. PKCE `code_verifier` is required for public clients. |
| **C-09** | Refresh token flow | `refreshTokens(refreshToken)` → `TokenResponse`. Posts `grant_type=refresh_token`. |
| **C-10** | **Client credentials flow** | `clientCredentials(scope?)` → `TokenResponse`. Posts `grant_type=client_credentials`. Requires `clientId` + `clientSecret`. **Required in every SDK per §7.2.** |
| **C-11** | **Device authorization flow (RFC 8628)** | Two methods: (1) `deviceAuthorization(scope?)` → `DeviceAuthorizationResponse` — posts to `device_authorization_endpoint`, returns `device_code`, `user_code`, `verification_uri`, `expires_in`, `interval`. (2) `pollDeviceToken(deviceCode)` → `TokenResponse | null` — polls `token_endpoint`; returns `null` on `authorization_pending`/`slow_down`; throws on fatal errors. **Required in every SDK per §7.2.** |
| **C-12** | **Magic link (send + exchange)** | **Both halves required in every SDK** (board decision 2026-06-25): (1) *send* — `requestMagicLink(email)` → `void`, posts `{email}` to `/v1/{realm}/auth/magic-link`, always succeeds on 202 (enumeration-resistant). (2) *exchange* — `exchangeMagicLink(token)` → `TokenResponse`, posts `grant_type=urn:hearth:grant-type:magic-link` with the opaque token to `token_endpoint`. A magic link you can send but not redeem is not a usable flow. **Required in every SDK per §7.2.** |

### Tier 3 — Identity & Authorization (all SDKs)

| C-ID | Capability | Behavioral contract |
| ------ | ----------- | --------------------- |
| **C-13** | UserInfo endpoint | `userInfo(accessToken)` → typed user claims. GET to discovered `userinfo_endpoint` with `Authorization: Bearer {token}`. |
| **C-14** | Permissions query | `permissions(accessToken)` → `MePermissionsResponse`. GET `/v1/me/permissions` for live-resolved permission set (not baked-in JWT claims). |
| **C-15** | Decision check permission | `checkPermission(token, permission, organizationId?, resource?)` → `bool`. POST `/oauth/authorize`. Fail-closed: network/4xx/5xx returns `false`. Requires `realmId` on the client config. See SDK.md §3.5. |

### Tier 4 — Server-Side (server SDKs only)

| C-ID | Capability | Behavioral contract |
| ------ | ----------- | --------------------- |
| **C-16** | HTTP middleware | Framework middleware/handler that extracts `Authorization: Bearer <token>`, verifies/introspects/decides (per mode), injects `Claims` into request context, returns `401` on missing/invalid token, `401 + RequiredActionError` on `token_type="required_action"`, `403` on insufficient permission. Does not call `next` on failure. See SDK.md §6. |

### Tier 5 — Browser (TypeScript browser SDK only)

| C-ID | Capability | Behavioral contract |
| ------ | ----------- | --------------------- |
| **C-17** | PKCE utilities | `generateCodeVerifier()`, `generateCodeChallenge(verifier)`, `buildAuthorizationUrl(params)`. RFC 7636 compliant. |
| **C-18** | Browser auth flow | `createHearthAuth(config)` → `{ startLogin(), handleCallback(), logout() }`. PKCE login redirect, callback token exchange, logout + RP-initiated redirect. See SDK.md §7. |

### Tier 6 — Admin (all SDKs)

| C-ID | Capability | Behavioral contract |
| ------ | ----------- | --------------------- |
| **C-19** | Admin SDK | `AdminClient` separate from `HearthClient`. Takes `(baseUrl, adminToken, realmId)`. Sends `X-Realm-ID` header. CRUD + list for: users, realms (read + delete only), OAuth clients (at `/admin/applications*`, **not** `/admin/clients*`), roles, groups. **No org-membership methods** — membership has no REST route (audit 2026-08-28 §25.19). Organization CRUD and extra member roles at `/admin/organizations*` in every SDK. A thin wrapper over a client generated from `docs/api/openapi.json` (`make sdk-admin-gen`, freshness-gated in CI). Pagination via `limit` + `cursor`. 403 = typed `AdminPermissionError` (or equivalent HTTP error type). See SDK.md §12. |

### Tier 7 — Optional Advanced

| C-ID | Capability | Behavioral contract |
| ------ | ----------- | --------------------- |
| **C-20** | Session version cache | Optional. Polls `/v1/session-versions/snapshot` and `/delta` to detect revoked sessions without introspection. Configurable `pollIntervalMs`, `staleThresholdMs`. Background goroutine/thread released on `stop()`/`close()`. Not required; note its presence when implemented. |

---

## 4. Symbol-Name Mapping

### Legend

| Symbol | Meaning |
| -------- | --------- |
| `symbol` — monospace | Implemented. Use this exact public name. |
| **`→ proposed_name`** | Not yet implemented. Engineers must add this symbol in C2–C8. |
| N/A | Platform exception. See §5. |
| ⚠ | Implemented but with a known gap (described inline). |

---

### C-01 — Client Configuration

| SDK | Entry point | Status |
| ----- | ------------ | -------- |
| TS | `new HearthClient(config: HearthClientConfig)` | ✅ |
| Go | `hearth.NewClient(baseURL, realmID, opts...)` returns `*Client` | ✅ |
| PHP | `new HearthClient(issuerUrl, clientId?, clientSecret?, ...)` | ✅ |
| Python | `HearthClient(issuer_url, client_id?, client_secret?, ...)` | ✅ |

---

### C-02 — OIDC Discovery

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `HearthClient.discover()` → `OidcConfiguration` | ✅ |
| Go | auto-invoked on first endpoint use | ✅ internal |
| PHP | `HearthClient::discoverEndpoint(key)` (internal) | ✅ internal |
| Python | `HearthClient.discovery()` → `Dict[str, Any]` | ✅ |

---

### C-03 — JWKS Fetch & Cache

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `HearthClient.jwksClient()` → `JwksClient`; `JwksClient.fetchKeys()` | ✅ |
| Go | internal to middleware and verify path | ✅ internal |
| PHP | `HearthClient::getJwksClient()` → `JwksClient` | ✅ |
| Python | `HearthClient.jwks()` → `JwksDocument` | ✅ |

---

### C-04 — Token Verification (`verifyToken`) — §7.1 Required in Every SDK

> **EdDSA requirement:** The verifier MUST accept `alg: "EdDSA"` (`kty: "OKP"`, `crv: "Ed25519"`) and MUST reject every other algorithm, RS256 and ES256 included. There is no federation relay and therefore no federation fallback — see SDK.md §2 and §6.1 below.

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `HearthClient.verifyToken(token: string): Promise<Claims>` → `JwksClient.verify()` | ✅ — EdDSA only (`algorithms: ["EdDSA"]`) |
| Go | `Client.VerifyToken(ctx context.Context, token string, audience ...string) (*Claims, error)` | ✅ — go-jose `jwt.ParseSigned` with `jose.EdDSA` only |
| PHP | `HearthClient::verifyToken(string $rawToken): Claims` → `TokenVerifier::verify()` | ✅ — lcobucci `Signer\Eddsa` + `SignedWith` constraint |
| Python | `HearthClient.verify_token(token) → Claims` | ✅ — `jwt.decode(algorithms=["EdDSA"])` with a `PyJWK` |

All four pass the same live scenarios (SDK.md §9, `make sdk-conformance`).

---

### C-05 — Token Introspection

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `HearthClient.introspect(token)` → `IntrospectionResult`; `IntrospectionClient.introspect()` | ✅ |
| Go | `Client.Introspect(ctx, IntrospectRequest)` → `*IntrospectResponse` | ✅ |
| PHP | `HearthClient::getIntrospectionClient()` → `IntrospectionClient` | ✅ |
| Python | `HearthClient.introspect(token, ...)` → `IntrospectResponse` | ✅ |

---

### C-06 — Claims API

> **17 required accessors** (per SDK.md §4). All must return `false`/empty (never error) when the claim is absent. Names follow language conventions.

| Logical accessor | TS | Go | PHP | Python |
| ----------------- | ------- | ----- | ----- | -------- |
| `subject()` | `Claims.subject()` | — (see the Go note below) | `Claims::subject()` | `Claims.subject()` |
| `issuer()` | `Claims.issuer()` | — | `Claims::issuer()` | `Claims.issuer()` |
| `audiences()` | `Claims.audiences()` | — | `Claims::audiences()` | `Claims.audiences()` |
| `expiry()` | `Claims.expiry()` | — | `Claims::expiry()` | `Claims.expiry()` |
| `issuedAt()` | `Claims.issuedAt()` | — | `Claims::issuedAt()` | `Claims.issuedAt()` |
| `jwtID()` | `Claims.jwtID()` | — | `Claims::jwtID()` | `Claims.jwtID()` |
| `scope()` | `Claims.scope()` | — | `Claims::scope()` | `Claims.scope()` |
| `scopes()` | `Claims.scopes()` | — | `Claims::scopes()` | `Claims.scopes()` |
| `hasScope(s)` | `Claims.hasScope(s)` | — | `Claims::hasScope(s)` | `Claims.hasScope(s)` |
| `hasRole(r)` | `Claims.hasRole(r)` | `Client.HasRole(ctx, token, role)` | `Claims::hasRole(r)` | `Claims.hasRole(r)` |
| `hasPermission(p)` | `Claims.hasPermission(p)` | `Client.HasPermission(ctx, token, perm)` | `Claims::hasPermission(p)` | `Claims.hasPermission(p)` |
| `inGroup(g)` | `Claims.inGroup(g)` | `Client.InGroup(ctx, token, slug)` | `Claims::inGroup(g)` | `Claims.in_group(g)` |
| `inOrg(o)` | `Claims.inOrg(o)` | `Client.InOrg(ctx, token, orgID)` | `Claims::inOrg(o)` | `Claims.in_org(o)` |
| `tokenType()` | `Claims.tokenType()` | — | `Claims::tokenType()` | `Claims.token_type()` |
| `organizationId()` | `Claims.organizationId()` | — | `Claims::organizationId()` | `Claims.organization_id()` |
| `orgGroups()` | `Claims.orgGroups()` | — | `Claims::orgGroups()` | `Claims.org_groups()` |
| `get(claim)` | `Claims.get(claim)` | — | `Claims::get(claim)` | `Claims.get(key)` |

> **Go note:** Go uses top-level client methods (`Client.HasPermission`, `HasRole`, `InGroup`, `InOrg`). Each takes a leading `context.Context` and verifies the token against the realm JWKS before reading any claim — the JWKS is cached, so there is usually no network round-trip, but the check is a signature verification, not a bare decode (audit 2026-08-28 §25.1). The remaining 13 accessors (`subject`, `issuer`, `audiences`, `expiry`, `issuedAt`, `jwtID`, `scope`, `scopes`, `hasScope`, `tokenType`, `organizationId`, `orgGroups`, `get`) must be added to a `Claims` struct in Go. Use snake_case for `in_group`/`in_org`/`token_type`/`organization_id`/`org_groups` per Go convention for exported accessors that are multi-word — or PascalCase exported methods: `InGroup`, `InOrg`, `TokenType`, `OrganizationId`, `OrgGroups`.
>

---

### C-07 — Error Taxonomy

> All 10 error types required. Language-native naming applies. In Go: sentinel errors + named types. Tokens and secrets must never appear in error messages.

| Error | TS class | Go type | PHP class | Python exc |
| ------- | ---------- | --------- | ----------- | ------------ |
| Configuration | `ConfigurationError` | `ConfigurationError` | `ConfigurationError` | `ConfigurationError` |
| Discovery | `DiscoveryError` | `DiscoveryError` | `DiscoveryError` | `DiscoveryError` |
| JWKS Fetch | `JWKSFetchError` | `JWKSFetchError` | `JWKSFetchError` | `JWKSFetchError` |
| Token Expired | `TokenExpiredError` | `TokenExpiredError` | `TokenExpiredError` | `TokenExpiredError` |
| Token Not Yet Valid | `TokenNotYetValidError` | `TokenNotYetValidError` | `TokenNotYetValidError` | `TokenNotYetValidError` |
| Token Invalid | `TokenInvalidError` | `TokenInvalidError` | `TokenInvalidError` | `TokenInvalidError` |
| Token Issuer | `TokenIssuerError` | `TokenIssuerError` | `TokenIssuerError` | `TokenIssuerError` |
| Token Audience | `TokenAudienceError` | `TokenAudienceError` | `TokenAudienceError` | `TokenAudienceError` |
| Introspection | `IntrospectionError` | `IntrospectionError` | `IntrospectionError` | `IntrospectionError` |
| Required Action | `RequiredActionError` | `RequiredActionError` | `RequiredActionError` | `RequiredActionError` |

---

### C-08 — Authorization Code Exchange

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `HearthClient.exchangeCode(code, redirectUri, opts?)`; `beginLogin(redirectUri, scope?)` / `completeLogin(code, verifier, redirectUri)` | ✅ |
| Go | `Client.ExchangeCode(ctx, TokenRequest)` → `*TokenResponse` | ✅ |
| PHP | `HearthClient::exchangeCode(string $code, string $redirectUri, ?string $codeVerifier): TokenResponse` | ✅ |
| Python | `HearthClient.exchange_code(code, redirect_uri, code_verifier?)` → `TokenResponse` | ✅ |

---

### C-09 — Refresh Token Flow

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `HearthClient.refreshTokens(refreshToken, scope?)` | ✅ |
| Go | `Client.RefreshTokens(ctx, clientID, refreshToken)` → `*TokenResponse` | ✅ |
| PHP | **`→ HearthClient::refreshTokens(string $refreshToken): TokenResponse`** | ❌ missing |
| Python | `HearthClient.refresh_tokens(refresh_token, ...)` → `TokenResponse` | ✅ |

---

### C-10 — Client Credentials Flow (§7.2 Required)

> **Required in every SDK.** Posts `grant_type=client_credentials` to the discovered `token_endpoint`. Requires `clientId` + `clientSecret`.

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `HearthClient.clientCredentials(scope?: string): Promise<TokenResponse>` | ✅ |
| Go | **`→ Client.ClientCredentials(ctx context.Context, scope string) (*TokenResponse, error)`** | ❌ missing |
| PHP | **`→ HearthClient::clientCredentials(?string $scope = null): TokenResponse`** | ❌ missing |
| Python | **`→ HearthClient.client_credentials(scope: Optional[str] = None) → TokenResponse`** | ❌ missing |

---

### C-11 — Device Authorization Flow (§7.2 Required)

> **Required in every SDK.** RFC 8628. Two methods: initiate and poll.

**Initiate (`deviceAuthorization`):**

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `HearthClient.startDeviceFlow(scope?: string): Promise<DeviceAuthorizationResponse>` | ✅ |
| Go | **`→ Client.DeviceAuthorization(ctx context.Context, scope string) (*DeviceAuthorizationResponse, error)`** | ❌ missing |
| PHP | **`→ HearthClient::deviceAuthorization(?string $scope = null): DeviceAuthorizationResponse`** | ❌ missing |
| Python | **`→ HearthClient.device_authorization(scope: Optional[str] = None) → DeviceAuthorizationResponse`** | ❌ missing |

**Poll (`pollDeviceToken`):**

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `HearthClient.pollDeviceToken(deviceCode: string, intervalSeconds: number): Promise<TokenResponse>` — polls until approved; throws `TokenExpiredError` on `expired_token` | ✅ |
| Go | **`→ Client.PollDeviceToken(ctx context.Context, deviceCode string) (*TokenResponse, error)`** | ❌ missing — return `nil, nil` on `authorization_pending`/`slow_down` |
| PHP | **`→ HearthClient::pollDeviceToken(string $deviceCode): ?TokenResponse`** | ❌ missing |
| Python | **`→ HearthClient.poll_device_token(device_code: str) → Optional[TokenResponse]`** | ❌ missing |

`DeviceAuthorizationResponse` required fields: `device_code`, `user_code`, `verification_uri`, `verification_uri_complete?`, `expires_in`, `interval`.

---

### C-12 — Magic Link Exchange (§7.2 Required)

> **Required in every SDK.** Posts `grant_type=urn:hearth:grant-type:magic-link` with the opaque token from the magic-link URL.

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `HearthClient.exchangeMagicLink(token: string): Promise<TokenResponse>`; send: `requestMagicLink(email)` | ✅ |
| Go | **`→ Client.ExchangeMagicLink(ctx context.Context, token string) (*TokenResponse, error)`** | ❌ missing |
| PHP | **`→ HearthClient::exchangeMagicLink(string $token): TokenResponse`** | ❌ missing |
| Python | **`→ HearthClient.exchange_magic_link(token: str) → TokenResponse`** | ❌ missing |

Grant type wire value: `urn:hearth:grant-type:magic-link`. Token parameter name: `token`.

---

### C-13 — UserInfo Endpoint

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `HearthClient.userinfo(accessToken: string): Promise<UserInfoResponse>` | ✅ |
| Go | `Client.UserInfo(ctx, accessToken)` → `*UserInfoResponse` | ✅ |
| PHP | `HearthClient::getUserInfo(string $accessToken): UserInfoResponse` | ✅ |
| Python | `HearthClient.userinfo(access_token?)` → `UserInfoResponse` | ✅ |

---

### C-14 — Permissions Query

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `HearthClient.mePermissions(accessToken: string): Promise<MePermissionsResponse>` (needs `realmId`) | ✅ |
| Go | `Client.Permissions(ctx, token)` → `*MePermissionsResponse` | ✅ |
| PHP | **`→ HearthClient::permissions(string $accessToken): MePermissionsResponse`** | ❌ missing |
| Python | `HearthClient.permissions(access_token?)` → `MePermissionsResponse` | ✅ |

---

### C-15 — Decision Check Permission

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `HearthClient.authorize(token, permission, opts?)` → `boolean` | ✅ (naming differs — see exception §5.1) |
| Go | `Client.CheckPermission(ctx, token, CheckPermissionRequest)` → `*CheckPermissionResponse` | ✅ |
| PHP | **`→ HearthClient::checkPermission(string $token, string $permission, ?string $orgId = null): bool`** | ❌ missing |
| Python | `HearthClient.check_permission(token, permission, ...)` → `CheckPermissionResponse` | ✅ |

---

### C-16 — HTTP Middleware (server SDKs)

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `hearthMiddleware(options)` (Express), `hearthFastifyHook(options)` (Fastify), `authenticateRequest(header, options)`; Next.js: `withHearthAuth`, `getHearthClaims` (`@hearth-auth/sdk/nextjs`), `hearthEdgeMiddleware` (`@hearth-auth/sdk/nextjs/edge`) | ✅ |
| Go | `RequirePermission(client, permission, cfg)` → `http.Handler` | ✅ |
| PHP | **`→ HearthMiddleware` (PSR-15 compatible)** | ❌ missing |
| Python | `RequirePermissionMiddleware` (ASGI); `WsgiPermissionMiddleware` | ✅ |

---

### C-17 — PKCE Utilities

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `generateCodeVerifier()`, `generateCodeChallenge(verifier)`, `buildAuthorizationUrl(params)`, `startLogin(opts)` | ✅ |
| Go | `pkce.GenerateCodeVerifier()`, `pkce.GenerateCodeChallenge(verifier)` | ✅ optional |
| PHP | **`→ Pkce::generateCodeVerifier()`, `Pkce::generateCodeChallenge(verifier)`** | ❌ missing |
| Python | **`→ generate_code_verifier()`, `generate_code_challenge(verifier)`** | ❌ missing |

---

### C-18 — Browser Auth Flow

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `createHearthAuth(config)` → `{ startLogin(), handleCallback(), logout() }`; `getAccessToken()`, `isAuthenticated()`, `clearTokens()` | ✅ |
| Go | N/A — server SDK | N/A |
| PHP | N/A — server SDK | N/A |
| Python | N/A — server SDK | N/A |

---

### C-19 — Admin SDK

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `AdminClient` (separate type); CRUD users/realms/applications/roles/groups | ✅ |
| Go | `AdminClient` via `Client.Admin(accessToken)` | ✅ |
| PHP | **`→ AdminClient`** | ❌ not seen — add separate class |
| Python | `AdminClient(base_url, admin_token, realm_id)` | ✅ |

---

### C-20 — Session Version Cache (optional)

| SDK | Symbol | Status |
| ----- | -------- | -------- |
| TS | `SessionVersionCache` | ✅ |
| Go | `WithSessionVersions(cfg)` option; `Client.Stop()` | ✅ |
| PHP | N/A | — |
| Python | N/A | — |

---

## 5. Platform Exceptions

### 5.1 — TypeScript SDK: `authorize()` naming differs from canonical `checkPermission()`

The TypeScript SDK uses `HearthClient.authorize(token, permission, opts?)` for the decision-mode permission check (C-15), where the other SDKs use `checkPermission(...)`. The name came from the former Node.js SDK, whose features moved into `@hearth-auth/sdk`.

**Decision:** Accept the naming divergence. The behavioral contract is identical.

---

## 6. Normative Addenda

### 6.1 — EdDSA Algorithm Selector (§7.1)

Every SDK implementing `verifyToken` (C-04) **must** enforce the following algorithm selection:

1. **Accepted:** `alg: "EdDSA"` (`kty: "OKP"`, `crv: "Ed25519"`) — every Hearth-issued token
2. **Rejected:** every other `alg`, **including `RS256` and `ES256`**

**There is no federation exception.** An earlier revision of this section listed RS256 and ES256 as
"federation fallbacks" for relayed third-party IdP tokens. Hearth relays no such token: a federated
login is exchanged for a Hearth-issued Ed25519 token, and the JWKS has never carried a third-party
key. The RS256 and ES256 entries it once published were Hearth's own and were withdrawn (audit
2026-08-28 §4.2#4). A verifier that accepts an algorithm other than EdDSA is non-conforming —
accepting more only widens the set of keys an attacker can steer it onto.

**Reference implementation:** TypeScript `JwksClient.verify` passes `algorithms: ["EdDSA"]` to
`jose`, which refuses any other JWS header algorithm before a key is looked up, so the refusal does
not trigger the `kid`-miss JWKS re-fetch.

```typescript
// TypeScript reference (sdks/typescript/src/jwks-client.ts) — EdDSA or nothing
const { payload } = await jwtVerify(token, ks, {
  issuer,
  audience,
  algorithms: ["EdDSA"],
  clockTolerance,
});
```

**OKP key parsing constraint:** Parsers must not require a `y` coordinate on OKP keys. Hearth's JWKS emits OKP keys with only `kty: "OKP"`, `crv: "Ed25519"`, `x: "<base64url>"`. Any parser that assumes `y` is always present will fail to load Hearth signing keys.

### 6.2 — Full Claims Accessor Reference

The 17 required accessors, their source claim, and return-when-absent behavior:

| Accessor | Source claim | Type | When absent |
| ---------- | ------------- | ------ | ------------- |
| `subject()` | `sub` | string | `""` |
| `issuer()` | `iss` | string | `""` |
| `audiences()` | `aud` | string[] | `[]` |
| `expiry()` | `exp` | datetime/int64 | `null` |
| `issuedAt()` | `iat` | datetime/int64 | `null` |
| `jwtID()` | `jti` | string | `""` |
| `scope()` | `scope` | string (space-delimited) | `""` |
| `scopes()` | `scope` | string[] (split on space) | `[]` |
| `hasScope(s)` | `scope` | bool | `false` |
| `hasRole(r)` | `roles: string[]` | bool | `false` |
| `hasPermission(p)` | `permissions: string[]` | bool | `false` |
| `inGroup(g)` | `groups: string[]` | bool | `false` |
| `inOrg(o)` | `oid: string` | bool | `false` |
| `tokenType()` | `token_type` | string | `"access"` |
| `organizationId()` | `oid` | string \| null | `null` |
| `orgGroups()` | `org_groups: string[]` | string[] | `[]` |
| `get(key)` | any claim | raw value | `null` |

Language naming variants — `inGroup`/`in_group`, `inOrg`/`in_org`, `tokenType`/`token_type`, `organizationId`/`organization_id`, `orgGroups`/`org_groups` follow language convention (camelCase for TS/Go/PHP, snake_case for Python).

### 6.3 — §7.2 OAuth Flow Wire Contracts

**C-10 Client Credentials:**
```
POST {token_endpoint}
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id={clientId}&client_secret={clientSecret}[&scope={scope}]
```

**C-11 Device Authorization initiate:**
```
POST {device_authorization_endpoint}
Content-Type: application/x-www-form-urlencoded

client_id={clientId}[&scope={scope}]
```

**C-11 Device Authorization poll:**
```
POST {token_endpoint}
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={deviceCode}&client_id={clientId}
```
Return `null` / `None` on `error: "authorization_pending"` or `error: "slow_down"`. Propagate all other errors.

**C-12 Magic Link:**
```
POST {token_endpoint}
Content-Type: application/x-www-form-urlencoded

grant_type=urn:hearth:grant-type:magic-link&token={magicToken}&client_id={clientId}
```

---

## 7. Coverage Summary (as-built — re-verified from source 2026-06-25, post-#229; TS column re-checked 2026-10)

| C-ID | Capability | TS | Go | PHP | Python |
| ------ | ----------- | :--: | :--: | :---: | :------: |
| C-01 | Config | ✅ | ✅ | ✅ | ✅ |
| C-02 | Discovery | ✅ | ✅ | ✅ | ✅ |
| C-03 | JWKS cache | ✅ | ✅ | ✅ | ✅ |
| C-04 | verifyToken (EdDSA) | ✅ | ✅ | ✅ | ✅ |
| C-05 | Introspect | ✅ | ✅ | ✅ | ✅ |
| C-06 | Claims API (17) | ✅ | ✅ | ✅ | ✅ |
| C-07 | Errors | ✅ | ✅ | ✅ | ✅ |
| C-08 | Auth code | ✅ | ✅ | ✅ | ✅ |
| C-09 | Refresh | ✅ | ✅ | ✅ | ✅ |
| C-10 | Client creds | ✅ | ✅ | ✅ | ✅ |
| C-11 | Device flow | ✅ | ✅ | ✅ | ✅ |
| C-12 | Magic link | ✅² | ✅² | ✅² | ✅² |
| C-13 | UserInfo | ✅ | ✅ | ✅ | ✅ |
| C-14 | Permissions | ✅ | ✅ | ✅ | ✅ |
| C-15 | Check perm | ✅³ | ✅ | ✅ | ✅ |
| C-16 | Middleware | ✅ | ✅ | ✅ | ✅ |
| C-17 | PKCE utils | ✅ | ✅ | ✅ | ✅ |
| C-18 | Browser auth | ✅ | N/A | N/A | N/A |
| C-19 | Admin SDK | ✅ | ✅ | ✅ | ✅ |
| C-20 | Session cache (managed) | ✅ | ✅ | ⚠⁴ | ⚠ |
| C-21 | WebAuthn helpers | ✅ | ✅ | ✅ | ✅ |

**Legend:** ✅ implemented · ⚠ primitive only / partial · ❌ missing · N/A platform exception · — out of scope

**Notes:**
- ² **Magic-link — both halves now shipped (resolved 2026-06-25).** Per board decision, C-12 requires *both* send and exchange in every SDK. Exchange (`exchangeMagicLink`/`exchange_magic_link`/`ExchangeMagicLink`) and send (`requestMagicLink`/`request_magic_link`/`RequestMagicLink`) ship in all four SDKs.
- ³ TS uses `authorize(token, permission, opts?)` in place of `checkPermission` (§5.1).
- ⁴ **PHP C-20 is intentionally primitive-only.** PHP's request-scoped execution model (no long-lived process between requests) makes a background-polling cache non-idiomatic; the single-shot `getSessionVersion()` poll is the correct primitive there. Python still exposes only raw `sv_snapshot`/`sv_delta` and remains an optional managed-cache candidate.
- **C-20** is optional. TS and Go ship the managed background-polling `SessionVersionCache` facade (`start`/`stop`/`validateSv`/`age`).
- **C-21 WebAuthn** is a newly-recognized capability (not in the original C-01–C-20 registry). **TS now ships** `startWebAuthnRegistration`/`finishWebAuthnRegistration`/`startWebAuthnAuthentication`/`finishWebAuthnAuthentication` on `HearthApiClient`, joining Go/PHP/Python. C-21 should be promoted into §3 with a formal behavioral contract.

### 7.1 Residual parity gaps (post-#229, updated 2026-06-25)

The original trigger gap — hand-rolled PKCE in Python and PHP — is **fully closed**: C-17 is universal across the four SDKs. Status of the gaps surfaced in the first re-review:

1. ✅ **C-09 refresh, C-16 middleware and C-20 managed cache for Node.js servers — DONE.** They shipped in the former Node.js SDK and moved into `@hearth-auth/sdk` (`HearthClient.refreshTokens`, `hearthMiddleware`, `hearthFastifyHook`, `SessionVersionCache`).
2. ✅ **C-21 WebAuthn in TS — DONE.** Four ceremony helpers added to `HearthApiClient` with tests (`sdks/typescript/tests/webauthn.test.ts`).
3. ✅ **C-12 magic-link send + exchange — DONE.** Board decided both halves are required. All four SDKs expose the full send→exchange flow.
4. ⏳ **C-20 managed cache in Python (P3, optional).** Recommended-optional; PHP intentionally exempt (note ⁴). Tracked in [HEA-1590](/HEA/issues/HEA-1590).
5. ✅ **Standard JOSE libraries, generated admin clients, shared conformance harness — DONE** in the [`sdk-standard-libraries`](../../openspec/changes/sdk-standard-libraries/) change (SDK.md §2, §9, §12).

---

*This document was generated for [HEA-1555](/HEA/issues/HEA-1555); §7 coverage matrix re-verified from source for [HEA-1552](/HEA/issues/HEA-1552) on 2026-06-25. Updates must be accompanied by a revision comment on the originating issue.*
