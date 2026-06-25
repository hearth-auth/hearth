# Hearth SDK Canonical Surface

> **Status:** Draft — pending CTO review.  
> **Gates:** C2–C8 implementation. [C1 (Kotlin EdDSA fix)](/HEA/issues/HEA-1556) may proceed without waiting for this document.  
> **Source of truth for:** capability identity, required behavior contracts, and language-idiomatic symbol names.  
> **Full behavioral spec:** [`docs/specs/SDK.md`](SDK.md) — this document maps capabilities to symbols; SDK.md is normative for behavior.

---

## 1. Purpose

This document is the **design artifact** that enumerates every capability every Hearth SDK must expose, assigns a stable capability ID to each, states the required behavioral contract, and names the exact public symbol (class, method, function) for each SDK.

C2–C8 engineers use the symbol-name mapping as their implementation target. Any SDK that ships without all capabilities in this document (or an explicit exception below) is non-conforming.

---

## 2. SDK Inventory

| SDK key | Package | Role | Primary entry point |
|---------|---------|------|---------------------|
| **TS** | `@hearth-auth/sdk` (browser) | Browser SPA / isomorphic | `HearthClient` |
| **Node** | `@hearth-auth/node` (server) | Node.js resource server | `HearthClient` |
| **Go** | `github.com/hearth-auth/hearth-go` | Server / service | `NewClient()` → `*Client` |
| **PHP** | `hearth-auth/sdk` | Server (PSR-18) | `HearthClient` |
| **Python** | `hearth-sdk` | Server (sync HTTP) | `HearthClient` |
| **Rust** | `hearth-sdk` (crate) | Server / service | `HearthClient` |
| **Kotlin** | `io.hearth:hearth-core` | JVM / Android | `HearthClient` |

> **Per-capability reference implementations** — no single SDK is most complete; consult the SDK that has shipped the capability you are implementing:
>
> | Area | Best reference | Why |
> |------|---------------|-----|
> | C-10 client_credentials, C-11 device_flow, C-12 magic_link | **Kotlin** | Only SDK with all three §7.2 flows implemented |
> | C-04 verifyToken + EdDSA selector | **Kotlin** | Only SDK with explicit `JWSAlgorithm.EdDSA` + `CompositeKeySelector` |
> | C-06 Claims API (full 17 accessors) | **Rust** | Ships all 17 accessors; Python is a close second |
> | C-16 Middleware (embedded/introspection/decision modes) | **Python** | Both ASGI + WSGI; Go is a close second |
> | C-19 Admin SDK | **Python** or **Go** | Most complete CRUD coverage |
> | C-08/C-09 Auth code + refresh | **Go**, **PHP**, **Python**, **Rust**, **Kotlin** | All ship these; any is a valid reference |

---

## 3. Capability Registry

Each capability has a stable **C-ID** used throughout this doc and in child issues.

### Tier 1 — Verification (all SDKs)

| C-ID | Capability | Behavioral contract |
|------|-----------|---------------------|
| **C-01** | Client configuration | Single entry point (`HearthClient`/`NewClient`/etc.) accepting `issuerUrl`, optional `clientId`, `clientSecret`, `jwksTtl`, `introspectionEndpoint`, `httpTimeout`. Validates required params at construction. Throws `ConfigurationError` on invalid URL. See SDK.md §1. |
| **C-02** | OIDC discovery | Auto-discovers all endpoint URLs from `{issuerUrl}/.well-known/openid-configuration` on first use. Hard-coded paths are prohibited. Caches the document for the session lifetime. Throws `DiscoveryError` on failure. |
| **C-03** | JWKS fetch & cache | Fetches keys from the discovered `jwks_uri`. Caches by `kid`. Respects `Cache-Control: max-age`, 24 h ceiling. On `kid` miss: re-fetches once before failing. Skips unrecognized `kty` values. Throws `JWKSFetchError` on failure. See SDK.md §2. |
| **C-04** | Token verification (`verifyToken`) | Verifies signature against JWKS, then validates `exp`, `iss`, `aud` (optional), `iat` (±5 s clock skew) in that order. **EdDSA (`alg: "EdDSA"`, `kty: "OKP"`) must be the primary algorithm selector; RS256/ES256 are federation fallbacks only.** Returns typed `Claims`. Throws typed errors (§C-07). On `kid` miss: re-fetches once. See SDK.md §2 and §6.1 below. |
| **C-05** | Token introspection | RFC 7662 `POST /introspect`. Never cached. Requires `clientId` + `clientSecret`. Returns typed `IntrospectionResult` (`active`, `sub`, `exp`, `iat`, `iss`, `aud`, `scope`, `client_id`, `extra`). Throws `IntrospectionError` on failure. See SDK.md §3. |
| **C-06** | Claims API | 17 typed accessors on a `Claims` (or `VerifiedToken`) object. All accessors return `false`/empty (never error) when the claim is absent. Full accessor list in §6.2 below. See SDK.md §4. |
| **C-07** | Error taxonomy | 10 named error types. Language-native error handling applies (Go: sentinel errors; Python: exceptions; TS/Node: Error subclasses; PHP: `\Throwable`; Rust: enum variants; Kotlin: exceptions). Errors must never include token values. See SDK.md §5. |

### Tier 2 — OAuth Flows (all SDKs; §7.2 required)

| C-ID | Capability | Behavioral contract |
|------|-----------|---------------------|
| **C-08** | Authorization code exchange | `exchangeCode(code, redirectUri, codeVerifier?)` → `TokenResponse`. Posts `grant_type=authorization_code` to `token_endpoint`. PKCE `code_verifier` is required for public clients. |
| **C-09** | Refresh token flow | `refreshTokens(refreshToken)` → `TokenResponse`. Posts `grant_type=refresh_token`. |
| **C-10** | **Client credentials flow** | `clientCredentials(scope?)` → `TokenResponse`. Posts `grant_type=client_credentials`. Requires `clientId` + `clientSecret`. **Required in every SDK per §7.2.** |
| **C-11** | **Device authorization flow (RFC 8628)** | Two methods: (1) `deviceAuthorization(scope?)` → `DeviceAuthorizationResponse` — posts to `device_authorization_endpoint`, returns `device_code`, `user_code`, `verification_uri`, `expires_in`, `interval`. (2) `pollDeviceToken(deviceCode)` → `TokenResponse | null` — polls `token_endpoint`; returns `null` on `authorization_pending`/`slow_down`; throws on fatal errors. **Required in every SDK per §7.2.** |
| **C-12** | **Magic link exchange** | `exchangeMagicLink(token)` → `TokenResponse`. Posts `grant_type=urn:hearth:grant-type:magic-link` with the opaque magic-link token. **Required in every SDK per §7.2.** |

### Tier 3 — Identity & Authorization (all SDKs)

| C-ID | Capability | Behavioral contract |
|------|-----------|---------------------|
| **C-13** | UserInfo endpoint | `userInfo(accessToken)` → typed user claims. GET to discovered `userinfo_endpoint` with `Authorization: Bearer {token}`. |
| **C-14** | Permissions query | `permissions(accessToken)` → `MePermissionsResponse`. GET `/v1/me/permissions` for live-resolved permission set (not baked-in JWT claims). |
| **C-15** | Decision check permission | `checkPermission(token, permission, organizationId?, resource?)` → `bool`. POST `/oauth/authorize`. Fail-closed: network/4xx/5xx returns `false`. Requires `realmId` on the client config. See SDK.md §3.5. |

### Tier 4 — Server-Side (server SDKs only)

| C-ID | Capability | Behavioral contract |
|------|-----------|---------------------|
| **C-16** | HTTP middleware | Framework middleware/handler that extracts `Authorization: Bearer <token>`, verifies/introspects/decides (per mode), injects `Claims` into request context, returns `401` on missing/invalid token, `401 + RequiredActionError` on `token_type="required_action"`, `403` on insufficient permission. Does not call `next` on failure. See SDK.md §6. |

### Tier 5 — Browser (TypeScript browser SDK only)

| C-ID | Capability | Behavioral contract |
|------|-----------|---------------------|
| **C-17** | PKCE utilities | `generateCodeVerifier()`, `generateCodeChallenge(verifier)`, `buildAuthorizationUrl(params)`. RFC 7636 compliant. |
| **C-18** | Browser auth flow | `createHearthAuth(config)` → `{ startLogin(), handleCallback(), logout() }`. PKCE login redirect, callback token exchange (with `RequiredActionError` detection), logout + RP-initiated redirect. See SDK.md §7. |

### Tier 6 — Admin (all SDKs)

| C-ID | Capability | Behavioral contract |
|------|-----------|---------------------|
| **C-19** | Admin SDK | `AdminClient` separate from `HearthClient`. Takes `(baseUrl, adminToken, realmId)`. Sends `X-Realm-ID` header. CRUD + list for: users, realms, OAuth clients, roles, groups, org members. Pagination via `limit` + `cursor`. 403 = typed `AdminPermissionError` (or equivalent HTTP error type). See SDK.md §12. |

### Tier 7 — Optional Advanced

| C-ID | Capability | Behavioral contract |
|------|-----------|---------------------|
| **C-20** | Session version cache | Optional. Polls `/v1/session-versions/snapshot` and `/delta` to detect revoked sessions without introspection. Configurable `pollIntervalMs`, `staleThresholdMs`. Background goroutine/thread released on `stop()`/`close()`. Not required; note its presence when implemented. |

---

## 4. Symbol-Name Mapping

### Legend

| Symbol | Meaning |
|--------|---------|
| `symbol` — monospace | Implemented. Use this exact public name. |
| **`→ proposed_name`** | Not yet implemented. Engineers must add this symbol in C2–C8. |
| N/A | Platform exception. See §5. |
| ⚠ | Implemented but with a known gap (described inline). |

---

### C-01 — Client Configuration

| SDK | Entry point | Status |
|-----|------------|--------|
| TS | `new HearthClient(config: HearthClientConfig)` | ✅ |
| Node | `new HearthClient(config: HearthConfig)` | ✅ |
| Go | `hearth.NewClient(baseURL, realmID, opts...)` returns `*Client` | ✅ |
| PHP | `new HearthClient(issuerUrl, clientId?, clientSecret?, ...)` | ✅ |
| Python | `HearthClient(issuer_url, client_id?, client_secret?, ...)` | ✅ |
| Rust | `HearthClient::new(base_url, realm_id)` | ✅ |
| Kotlin | `HearthClient(issuerUrl, clientId?, clientSecret?, ...)` | ✅ |

---

### C-02 — OIDC Discovery

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | `HearthClient.discover()` → `OidcConfiguration` | ✅ |
| Node | `DiscoveryClient` (internal; auto-invoked) | ✅ internal |
| Go | auto-invoked on first endpoint use | ✅ internal |
| PHP | `HearthClient::discoverEndpoint(key)` (internal) | ✅ internal |
| Python | `HearthClient.discovery()` → `Dict[str, Any]` | ✅ |
| Rust | `HearthClient::discovery()` → `serde_json::Value` | ✅ |
| Kotlin | `HearthClient.discover()` → `JsonObject` | ✅ |

---

### C-03 — JWKS Fetch & Cache

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | `HearthClient.jwksClient()` → `JwksClient`; `JwksClient.fetchKeys()` | ✅ |
| Node | `JwksVerifier` (internal to `HearthClient`); `JwksVerifier.invalidateCache()` | ✅ |
| Go | internal to middleware and verify path | ✅ internal |
| PHP | `HearthClient::getJwksClient()` → `JwksClient` | ✅ |
| Python | `HearthClient.jwks()` → `JwksDocument` | ✅ |
| Rust | `HearthClient::jwks()` → `JwksDocument` | ✅ |
| Kotlin | `HearthClient.jwksClient()` → `JwksClient`; `JwksClient.getOrFetchSet()` | ✅ |

---

### C-04 — Token Verification (`verifyToken`) — §7.1 Required in Every SDK

> **EdDSA requirement:** The verifier MUST select `alg: "EdDSA"` (`kty: "OKP"`, `crv: "Ed25519"`) as the primary algorithm. RS256 and ES256 are accepted for federation relay tokens only. The implementation must use a composite selector that tries EdDSA first. See §6.1.

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | **`→ HearthClient.verifyToken(token: string): Promise<Claims>`** | ❌ missing — add to `HearthClient` backed by `JwksClient` |
| Node | `HearthClient.verifyToken(token)` → `VerifiedToken`; `JwksVerifier.verifyToken(token)` | ⚠ present but EdDSA (`kty: "OKP"`) not explicitly listed as supported algorithm in docs or enforced in verifyOptions — C5 must verify and fix |
| Go | **`→ Client.VerifyToken(ctx context.Context, token string) (*Claims, error)`** | ❌ missing — no explicit verify path, only middleware internals |
| PHP | `HearthClient::verifyToken(string $rawToken): Claims` → delegates to `TokenVerifier::verify()` | ⚠ present — verify `TokenVerifier` explicitly selects EdDSA; fix if not |
| Python | **`→ HearthClient.verify_token(token: str) → Claims`** | ❌ missing |
| Rust | **`→ HearthClient::verify_token(token: &str) → Result<Claims, HearthError>`** | ❌ missing — `Claims::decode()` decodes without signature verification |
| Kotlin | `HearthClient.verifyToken(token: String): Claims` → `TokenVerifier.verify(token)` | ✅ (C1) — uses `JWSAlgorithm.EdDSA` + `CompositeKeySelector(edDSA, RS256, ES256)` |

---

### C-05 — Token Introspection

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | `HearthClient.introspect(token)` → `IntrospectionResult`; `IntrospectionClient.introspect()` | ✅ |
| Node | `HearthClient.introspect(token, hint?)` → `IntrospectionResult`; `IntrospectionClient` | ✅ |
| Go | `Client.Introspect(ctx, IntrospectRequest)` → `*IntrospectResponse` | ✅ |
| PHP | `HearthClient::getIntrospectionClient()` → `IntrospectionClient` | ✅ |
| Python | `HearthClient.introspect(token, ...)` → `IntrospectResponse` | ✅ |
| Rust | `HearthClient::introspect(...)` → `IntrospectResponse` | ✅ |
| Kotlin | `HearthClient.introspect(token)` → `IntrospectionResult`; `IntrospectionClient.introspect()` | ✅ |

---

### C-06 — Claims API

> **17 required accessors** (per SDK.md §4). All must return `false`/empty (never error) when the claim is absent. Names follow language conventions.

| Logical accessor | TS | Node | Go | PHP | Python | Rust | Kotlin |
|-----------------|-------|------|-----|-----|--------|------|--------|
| `subject()` | `Claims.subject()` | `VerifiedToken.subject` (getter) | `Client.HasPermission` (local decode) | `Claims::subject()` | `Claims.subject()` | `Claims::subject()` | `Claims.subject()` |
| `issuer()` | `Claims.issuer()` | — | — | `Claims::issuer()` | `Claims.issuer()` | `Claims::issuer()` | `Claims.issuer()` |
| `audiences()` | `Claims.audiences()` | — | — | `Claims::audiences()` | `Claims.audiences()` | `Claims::audiences()` | `Claims.audiences()` |
| `expiry()` | `Claims.expiry()` | — | — | `Claims::expiry()` | `Claims.expiry()` | `Claims::expiry()` | `Claims.expiry()` |
| `issuedAt()` | `Claims.issuedAt()` | — | — | `Claims::issuedAt()` | `Claims.issuedAt()` | `Claims::issuedAt()` | `Claims.issuedAt()` |
| `jwtID()` | `Claims.jwtID()` | — | — | `Claims::jwtID()` | `Claims.jwtID()` | `Claims::jwtID()` | `Claims.jwtID()` |
| `scope()` | `Claims.scope()` | — | — | `Claims::scope()` | `Claims.scope()` | `Claims::scope()` | `Claims.scope()` |
| `scopes()` | `Claims.scopes()` | — | — | `Claims::scopes()` | `Claims.scopes()` | `Claims::scopes()` | `Claims.scopes()` |
| `hasScope(s)` | `Claims.hasScope(s)` | — | — | `Claims::hasScope(s)` | `Claims.hasScope(s)` | `Claims::hasScope(s)` | `Claims.hasScope(s)` |
| `hasRole(r)` | `Claims.hasRole(r)` | — | `Client.HasRole(token, role)` | `Claims::hasRole(r)` | `Claims.hasRole(r)` | `Claims::hasRole(r)` | `Claims.hasRole(r)`; `HearthClient.hasRole(token, role)` |
| `hasPermission(p)` | `Claims.hasPermission(p)` | — | `Client.HasPermission(token, perm)` | `Claims::hasPermission(p)` | `Claims.hasPermission(p)` | `Claims::hasPermission(p)` | `Claims.hasPermission(p)`; `HearthClient.hasPermission(token, perm)` |
| `inGroup(g)` | `Claims.inGroup(g)` | — | `Client.InGroup(token, slug)` | `Claims::inGroup(g)` | `Claims.in_group(g)` | `Claims::inGroup(g)` | — |
| `inOrg(o)` | `Claims.inOrg(o)` | — | `Client.InOrg(token, orgID)` | `Claims::inOrg(o)` | `Claims.in_org(o)` | `Claims::inOrg(o)` | — |
| `tokenType()` | `Claims.tokenType()` | — | — | `Claims::tokenType()` | `Claims.token_type()` | `Claims::tokenType()` | — |
| `organizationId()` | `Claims.organizationId()` | — | — | `Claims::organizationId()` | `Claims.organization_id()` | `Claims::organizationId()` | — |
| `orgGroups()` | `Claims.orgGroups()` | — | — | `Claims::orgGroups()` | `Claims.org_groups()` | `Claims::orgGroups()` | — |
| `get(claim)` | `Claims.get(claim)` | — | — | `Claims::get(claim)` | `Claims.get(key)` | `Claims::get(key)` | — |

> **Go note:** Go uses top-level client methods (`Client.HasPermission`, `HasRole`, `InGroup`, `InOrg`) that local-decode the JWT without network. The remaining 13 accessors (`subject`, `issuer`, `audiences`, `expiry`, `issuedAt`, `jwtID`, `scope`, `scopes`, `hasScope`, `tokenType`, `organizationId`, `orgGroups`, `get`) must be added to a `Claims` struct in Go. Use snake_case for `in_group`/`in_org`/`token_type`/`organization_id`/`org_groups` per Go convention for exported accessors that are multi-word — or PascalCase exported methods: `InGroup`, `InOrg`, `TokenType`, `OrganizationId`, `OrgGroups`.
>
> **Node note:** `VerifiedToken` currently exposes raw payload. Add typed accessor methods matching this table.
>
> **Kotlin note:** `Claims` lacks `inGroup`, `inOrg`, `tokenType`, `organizationId`, `orgGroups`, `get`. Add to `Claims`. `HearthClient.hasPermission/hasRole` (local-decode shortcuts) already exist.

---

### C-07 — Error Taxonomy

> All 10 error types required. Language-native naming applies. In Go: sentinel errors + named types. In Rust: enum variants. Tokens and secrets must never appear in error messages.

| Error | TS class | Node class | Go type | PHP class | Python exc | Rust variant | Kotlin class |
|-------|----------|------------|---------|-----------|------------|--------------|--------------|
| Configuration | `ConfigurationError` | `ConfigurationError` | `ConfigurationError` | `ConfigurationError` | `ConfigurationError` | `HearthError::ConfigurationError` | `ConfigurationError` |
| Discovery | `DiscoveryError` | `DiscoveryError` | `DiscoveryError` | `DiscoveryError` | `DiscoveryError` | `HearthError::DiscoveryError` | `DiscoveryError` |
| JWKS Fetch | `JWKSFetchError` | `JWKSFetchError` | `JWKSFetchError` | `JWKSFetchError` | `JWKSFetchError` | `HearthError::JWKSFetchError` | `JWKSFetchError` |
| Token Expired | `TokenExpiredError` | `TokenExpiredError` | `TokenExpiredError` | `TokenExpiredError` | `TokenExpiredError` | `HearthError::TokenExpiredError` | `TokenExpiredError` |
| Token Not Yet Valid | `TokenNotYetValidError` | `TokenNotYetValidError` | `TokenNotYetValidError` | `TokenNotYetValidError` | `TokenNotYetValidError` | `HearthError::TokenNotYetValidError` | `TokenNotYetValidError` |
| Token Invalid | `TokenInvalidError` | `TokenInvalidError` | `TokenInvalidError` | `TokenInvalidError` | `TokenInvalidError` | `HearthError::TokenInvalidError` | `TokenInvalidError` |
| Token Issuer | `TokenIssuerError` | `TokenIssuerError` | `TokenIssuerError` | `TokenIssuerError` | `TokenIssuerError` | `HearthError::TokenIssuerError` | `TokenIssuerError` |
| Token Audience | `TokenAudienceError` | `TokenAudienceError` | `TokenAudienceError` | `TokenAudienceError` | `TokenAudienceError` | `HearthError::TokenAudienceError` | `TokenAudienceError` |
| Introspection | `IntrospectionError` | `IntrospectionError` | `IntrospectionError` | `IntrospectionError` | `IntrospectionError` | `HearthError::IntrospectionError` | `IntrospectionError` |
| Required Action | `RequiredActionError` | `RequiredActionError` | `RequiredActionError` | `RequiredActionError` | `RequiredActionError` | `HearthError::RequiredActionError` | `RequiredActionError` |

---

### C-08 — Authorization Code Exchange

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | `HearthApiClient.exchangeCode(params)` (legacy); **`→ HearthClient.exchangeCode(code, redirectUri, codeVerifier?)`** (add to primary) | ⚠ exists on legacy client; missing on primary `HearthClient` |
| Node | **`→ HearthClient.exchangeCode(code: string, redirectUri: string, codeVerifier?: string): Promise<TokenResponse>`** | ❌ missing — Node SDK is resource-server focused; add token-acquisition flows |
| Go | `Client.ExchangeCode(ctx, TokenRequest)` → `*TokenResponse` | ✅ |
| PHP | `HearthClient::exchangeCode(string $code, string $redirectUri, ?string $codeVerifier): TokenResponse` | ✅ |
| Python | `HearthClient.exchange_code(code, redirect_uri, code_verifier?)` → `TokenResponse` | ✅ |
| Rust | `HearthClient::exchange_code(code, client_id, client_secret, redirect_uri, code_verifier?)` → `TokenResponse` | ✅ |
| Kotlin | `HearthClient.exchangeCode(code, redirectUri, codeVerifier?)` → `TokenResponse` | ✅ |

---

### C-09 — Refresh Token Flow

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | `HearthApiClient.refreshTokens(...)` (legacy); **`→ HearthClient.refreshTokens(refreshToken)`** | ⚠ exists on legacy client |
| Node | **`→ HearthClient.refreshTokens(refreshToken: string, clientId: string, clientSecret?: string): Promise<TokenResponse>`** | ❌ missing |
| Go | `Client.RefreshTokens(ctx, clientID, refreshToken)` → `*TokenResponse` | ✅ |
| PHP | **`→ HearthClient::refreshTokens(string $refreshToken): TokenResponse`** | ❌ missing |
| Python | `HearthClient.refresh_tokens(refresh_token, ...)` → `TokenResponse` | ✅ |
| Rust | `HearthClient::refresh_tokens(refresh_token, client_id, client_secret)` → `TokenResponse` | ✅ |
| Kotlin | `HearthClient.refreshTokens(refreshToken)` → `TokenResponse` | ✅ |

---

### C-10 — Client Credentials Flow (§7.2 Required)

> **Required in every SDK.** Posts `grant_type=client_credentials` to the discovered `token_endpoint`. Requires `clientId` + `clientSecret`.

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | **`→ HearthClient.clientCredentials(scope?: string): Promise<TokenResponse>`** | ❌ missing |
| Node | **`→ HearthClient.clientCredentials(scope?: string): Promise<TokenResponse>`** | ❌ missing |
| Go | **`→ Client.ClientCredentials(ctx context.Context, scope string) (*TokenResponse, error)`** | ❌ missing |
| PHP | **`→ HearthClient::clientCredentials(?string $scope = null): TokenResponse`** | ❌ missing |
| Python | **`→ HearthClient.client_credentials(scope: Optional[str] = None) → TokenResponse`** | ❌ missing |
| Rust | **`→ HearthClient::client_credentials(scope: Option<&str>) → Result<TokenResponse, HearthError>`** | ❌ missing |
| Kotlin | `HearthClient.clientCredentials(scope?)` → `TokenResponse` | ✅ reference implementation |

---

### C-11 — Device Authorization Flow (§7.2 Required)

> **Required in every SDK.** RFC 8628. Two methods: initiate and poll.

**Initiate (`deviceAuthorization`):**

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | **`→ HearthClient.deviceAuthorization(scope?: string): Promise<DeviceAuthorizationResponse>`** | ❌ missing |
| Node | **`→ HearthClient.deviceAuthorization(scope?: string): Promise<DeviceAuthorizationResponse>`** | ❌ missing |
| Go | **`→ Client.DeviceAuthorization(ctx context.Context, scope string) (*DeviceAuthorizationResponse, error)`** | ❌ missing |
| PHP | **`→ HearthClient::deviceAuthorization(?string $scope = null): DeviceAuthorizationResponse`** | ❌ missing |
| Python | **`→ HearthClient.device_authorization(scope: Optional[str] = None) → DeviceAuthorizationResponse`** | ❌ missing |
| Rust | **`→ HearthClient::device_authorization(scope: Option<&str>) → Result<DeviceAuthorizationResponse, HearthError>`** | ❌ missing |
| Kotlin | `HearthClient.deviceAuthorization(scope?)` → `DeviceAuthorizationResponse` | ✅ reference implementation |

**Poll (`pollDeviceToken`):**

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | **`→ HearthClient.pollDeviceToken(deviceCode: string): Promise<TokenResponse \| null>`** | ❌ missing |
| Node | **`→ HearthClient.pollDeviceToken(deviceCode: string): Promise<TokenResponse \| null>`** | ❌ missing |
| Go | **`→ Client.PollDeviceToken(ctx context.Context, deviceCode string) (*TokenResponse, error)`** | ❌ missing — return `nil, nil` on `authorization_pending`/`slow_down` |
| PHP | **`→ HearthClient::pollDeviceToken(string $deviceCode): ?TokenResponse`** | ❌ missing |
| Python | **`→ HearthClient.poll_device_token(device_code: str) → Optional[TokenResponse]`** | ❌ missing |
| Rust | **`→ HearthClient::poll_device_token(device_code: &str) → Result<Option<TokenResponse>, HearthError>`** | ❌ missing |
| Kotlin | `HearthClient.pollDeviceToken(deviceCode)` → `TokenResponse?` | ✅ reference implementation |

`DeviceAuthorizationResponse` required fields: `device_code`, `user_code`, `verification_uri`, `verification_uri_complete?`, `expires_in`, `interval`.

---

### C-12 — Magic Link Exchange (§7.2 Required)

> **Required in every SDK.** Posts `grant_type=urn:hearth:grant-type:magic-link` with the opaque token from the magic-link URL.

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | **`→ HearthClient.exchangeMagicLink(token: string): Promise<TokenResponse>`** | ❌ missing |
| Node | **`→ HearthClient.exchangeMagicLink(token: string): Promise<TokenResponse>`** | ❌ missing |
| Go | **`→ Client.ExchangeMagicLink(ctx context.Context, token string) (*TokenResponse, error)`** | ❌ missing |
| PHP | **`→ HearthClient::exchangeMagicLink(string $token): TokenResponse`** | ❌ missing |
| Python | **`→ HearthClient.exchange_magic_link(token: str) → TokenResponse`** | ❌ missing |
| Rust | **`→ HearthClient::exchange_magic_link(token: &str) → Result<TokenResponse, HearthError>`** | ❌ missing |
| Kotlin | `HearthClient.exchangeMagicLink(magicToken)` → `TokenResponse` | ✅ reference implementation |

Grant type wire value: `urn:hearth:grant-type:magic-link`. Token parameter name: `token`.

---

### C-13 — UserInfo Endpoint

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | **`→ HearthClient.userInfo(accessToken: string): Promise<UserInfoResponse>`** | ❌ not seen on primary `HearthClient` |
| Node | **`→ HearthClient.userInfo(accessToken: string): Promise<UserInfoResponse>`** | ❌ missing |
| Go | `Client.UserInfo(ctx, accessToken)` → `*UserInfoResponse` | ✅ |
| PHP | `HearthClient::getUserInfo(string $accessToken): UserInfoResponse` | ✅ |
| Python | `HearthClient.userinfo(access_token?)` → `UserInfoResponse` | ✅ |
| Rust | `HearthClient::userinfo(access_token?)` → `UserInfoResponse` | ✅ |
| Kotlin | `HearthClient.userInfo(accessToken)` → `UserInfoResponse` | ✅ |

---

### C-14 — Permissions Query

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | (not seen on primary `HearthClient`); **`→ HearthClient.permissions(accessToken: string): Promise<MePermissionsResponse>`** | ❌ missing on primary |
| Node | **`→ HearthClient.permissions(accessToken: string): Promise<MePermissionsResponse>`** | ❌ missing |
| Go | `Client.Permissions(ctx, token)` → `*MePermissionsResponse` | ✅ |
| PHP | **`→ HearthClient::permissions(string $accessToken): MePermissionsResponse`** | ❌ missing |
| Python | `HearthClient.permissions(access_token?)` → `MePermissionsResponse` | ✅ |
| Rust | `HearthClient::permissions(access_token?)` → `MePermissionsResponse` | ✅ |
| Kotlin | **`→ HearthClient.permissions(accessToken: String): PermissionsResponse`** | ❌ not seen — add |

---

### C-15 — Decision Check Permission

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | (via `HearthApiClient`); **`→ HearthClient.checkPermission(token, permission, orgId?, resource?)`** | ⚠ exists on legacy client |
| Node | `HearthClient.authorize(token, permission, opts?)` → `AuthorizeResult` | ✅ (naming differs — see exception §5.1) |
| Go | `Client.CheckPermission(ctx, token, CheckPermissionRequest)` → `*CheckPermissionResponse` | ✅ |
| PHP | **`→ HearthClient::checkPermission(string $token, string $permission, ?string $orgId = null): bool`** | ❌ missing |
| Python | `HearthClient.check_permission(token, permission, ...)` → `CheckPermissionResponse` | ✅ |
| Rust | `HearthClient::check_permission(...)` → `CheckPermissionResponse` | ✅ |
| Kotlin | `HearthClient.checkPermission(token, permission, organizationId?, resource?)` → `Boolean` | ✅ |

---

### C-16 — HTTP Middleware (server SDKs)

| SDK | Symbol | Status |
|-----|--------|--------|
| TS (browser) | N/A — browser SDK; see platform exception §5.2 | N/A |
| Node | `hearthMiddleware(client, opts)` (Express/Fastify); `hearthFastifyHook` | ✅ |
| Go | `RequirePermission(client, permission, cfg)` → `http.Handler` | ✅ |
| PHP | **`→ HearthMiddleware` (PSR-15 compatible)** | ❌ missing |
| Python | `RequirePermissionMiddleware` (ASGI); `WsgiPermissionMiddleware` | ✅ |
| Rust | `HearthLayer` / `RequirePermission` middleware | ✅ |
| Kotlin | `HearthMiddleware.requirePermission(client, permission, ...)` → `Boolean` (handler) | ✅ |

---

### C-17 — PKCE Utilities

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | `generateCodeVerifier()`, `generateCodeChallenge(verifier)`, `buildAuthorizationUrl(params)`, `startLogin(opts)` | ✅ |
| Node | N/A — resource-server SDK (see exception §5.3) | N/A |
| Go | `pkce.GenerateCodeVerifier()`, `pkce.GenerateCodeChallenge(verifier)` | ✅ optional |
| PHP | **`→ Pkce::generateCodeVerifier()`, `Pkce::generateCodeChallenge(verifier)`** | ❌ missing |
| Python | **`→ generate_code_verifier()`, `generate_code_challenge(verifier)`** | ❌ missing |
| Rust | **`→ pkce::generate_code_verifier()`, `pkce::generate_code_challenge(verifier)`** | ❌ missing |
| Kotlin | **`→ Pkce.generateCodeVerifier()`, `Pkce.generateCodeChallenge(verifier)`** | ❌ missing |

---

### C-18 — Browser Auth Flow

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | `createHearthAuth(config)` → `{ startLogin(), handleCallback(), logout() }`; `getAccessToken()`, `isAuthenticated()`, `clearTokens()` | ✅ |
| Node | N/A — resource-server SDK | N/A |
| Go | N/A — server SDK | N/A |
| PHP | N/A — server SDK | N/A |
| Python | N/A — server SDK | N/A |
| Rust | N/A — server SDK | N/A |
| Kotlin | N/A — JVM/Android; token management is app-layer concern | N/A |

---

### C-19 — Admin SDK

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | `AdminClient` (separate type); CRUD users/realms/clients/roles/groups/org-members | ✅ |
| Node | `AdminClient` (separate type) | ✅ |
| Go | `AdminClient` via `Client.Admin(accessToken)` | ✅ |
| PHP | **`→ AdminClient`** | ❌ not seen — add separate class |
| Python | `AdminClient(base_url, admin_token, realm_id)` | ✅ |
| Rust | **`→ AdminClient`** | ❌ not seen — add |
| Kotlin | `AdminClient` via `HearthClient.admin(accessToken)` | ✅ |

---

### C-20 — Session Version Cache (optional)

| SDK | Symbol | Status |
|-----|--------|--------|
| TS | `SessionVersionCache` | ✅ |
| Node | N/A | — |
| Go | `WithSessionVersions(cfg)` option; `Client.Stop()` | ✅ |
| PHP | N/A | — |
| Python | N/A | — |
| Rust | N/A | — |
| Kotlin | N/A | — |

---

## 5. Platform Exceptions

### 5.1 — Node SDK: `authorize()` naming differs from canonical `checkPermission()`

The Node SDK uses `HearthClient.authorize(token, permission, opts?)` for the decision-mode permission check (C-15), where all other SDKs use `checkPermission(...)`. The Node SDK's naming predates this canonical surface doc.

**Decision:** Accept the Node naming divergence. The behavioral contract is identical. Document this in the Node SDK README as an alias for `checkPermission`.

### 5.2 — TypeScript (browser) SDK: exempt from HTTP Middleware (C-16)

The browser SDK does not run in a server context and cannot provide traditional HTTP middleware. As documented in SDK.md §6, it is explicitly exempt and provides SPA route guards via React hooks (`useHasPermission`, `useHasRole`) and `createHearthAuth()` instead.

**Rationale:** Browsers cannot execute server middleware; the React hooks and `isAuthenticated()` pattern cover the equivalent protection for SPA route protection.

### 5.3 — Node SDK: exempt from PKCE Utilities (C-17)

The Node SDK is a **resource-server** SDK — it verifies tokens issued to clients but does not itself initiate authorization flows. PKCE is a client/browser concern. SPAs using Node as a backend-for-frontend should use the TypeScript browser SDK for flow initiation.

**Rationale:** The Node SDK's scope is token verification, not flow initiation. Adding PKCE generation is out of scope for a resource-server SDK.

### 5.4 — Android / Kotlin: Browser Auth Flow (C-18) is N/A

The Kotlin SDK targets JVM servers and Android applications. Token storage and session management in Android is the application's responsibility. The SDK does not provide a browser-embedded login facade.

**Rationale:** Android uses custom tab intents or embedded WebView for the authorization redirect; the app manages token storage using Android `EncryptedSharedPreferences`. SDK.md §7 explicitly scopes C-18 to the browser SDK.

---

## 6. Normative Addenda

### 6.1 — EdDSA Algorithm Selector (§7.1)

Every SDK implementing `verifyToken` (C-04) **must** enforce the following algorithm selection:

1. **Primary:** `alg: "EdDSA"` (`kty: "OKP"`, `crv: "Ed25519"`) — all Hearth-issued tokens
2. **Federation fallbacks:** `alg: "RS256"` and `alg: "ES256"` — relayed tokens from third-party IdPs

The verifier **must** try EdDSA first and only attempt RS256/ES256 if the JWKS key for the token's `kid` is of those types. A verifier that accepts any of the three without ordering (or that omits EdDSA entirely) is non-conforming.

**Reference implementation:** Kotlin `TokenVerifier` uses `CompositeKeySelector(edDSASelector, rs256Selector, es256Selector)` which tries each in order and returns keys from the first matching selector.

```kotlin
// Kotlin reference — CompositeKeySelector priority
val edSelector  = JWSVerificationKeySelector(JWSAlgorithm.EdDSA, source)  // primary
val rsaSelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, source)  // federation fallback
val ecSelector  = JWSVerificationKeySelector(JWSAlgorithm.ES256, source)  // federation fallback
jwsKeySelector  = CompositeKeySelector(edSelector, rsaSelector, ecSelector)
```

**Node-specific gap:** `HearthClient.verifyToken()` documentation currently states "Supports RS256 and ES256" without mentioning EdDSA. C5 (Node SDK) must verify the `jose`-based `jwtVerify` call explicitly handles OKP keys and update the documentation to list EdDSA as the primary algorithm.

**OKP key parsing constraint:** Parsers must not require a `y` coordinate on OKP keys. Hearth's JWKS emits OKP keys with only `kty: "OKP"`, `crv: "Ed25519"`, `x: "<base64url>"`. Any parser that assumes `y` is always present will fail to load Hearth signing keys.

### 6.2 — Full Claims Accessor Reference

The 17 required accessors, their source claim, and return-when-absent behavior:

| Accessor | Source claim | Type | When absent |
|----------|-------------|------|-------------|
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

Language naming variants — `inGroup`/`in_group`, `inOrg`/`in_org`, `tokenType`/`token_type`, `organizationId`/`organization_id`, `orgGroups`/`org_groups` follow language convention (camelCase for TS/Node/Go/Kotlin/PHP, snake_case for Python/Rust).

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

## 7. Coverage Summary

| C-ID | Capability | TS | Node | Go | PHP | Python | Rust | Kotlin |
|------|-----------|:--:|:----:|:--:|:---:|:------:|:----:|:------:|
| C-01 | Config | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| C-02 | Discovery | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| C-03 | JWKS cache | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| C-04 | verifyToken | ❌ | ⚠ | ❌ | ⚠ | ❌ | ❌ | ✅ |
| C-05 | Introspect | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| C-06 | Claims API | ✅ | ⚠ | ⚠ | ✅ | ✅ | ✅ | ⚠ |
| C-07 | Errors | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| C-08 | Auth code | ⚠ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| C-09 | Refresh | ⚠ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ |
| C-10 | **Client creds** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| C-11 | **Device flow** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| C-12 | **Magic link** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| C-13 | UserInfo | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| C-14 | Permissions | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ |
| C-15 | Check perm | ⚠ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| C-16 | Middleware | N/A | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| C-17 | PKCE utils | ✅ | N/A | ✅ | ❌ | ❌ | ❌ | ❌ |
| C-18 | Browser auth | ✅ | N/A | N/A | N/A | N/A | N/A | N/A |
| C-19 | Admin SDK | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| C-20 | Session cache | ✅ | — | ✅ | — | — | — | — |

**Legend:** ✅ implemented · ⚠ partial/gap · ❌ missing (C2–C8 target) · N/A platform exception · — not applicable/out of scope

---

*This document was generated for [HEA-1555](/HEA/issues/HEA-1555). Updates must be accompanied by a revision comment on that issue.*
