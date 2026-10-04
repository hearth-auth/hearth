# sdk-support-contract Specification

## Purpose
The common contract every supported Hearth SDK (TypeScript, Go, Python, PHP) satisfies: configuration, token verification, claims, OAuth flows, errors, middleware, and the admin client.
## Requirements
### Requirement: SDK client configuration
Every SDK SHALL expose one primary entry point, configured as below.

| SDK | Entry point | Configuration | Checked at construction |
|---|---|---|---|
| TypeScript | `new HearthClient(config)` | `issuerUrl` (required), `clientId`, `clientSecret`, `jwksTtl` (ms), `introspectionEndpoint`, `httpTimeout` (ms), `realmId`, `expectedMode` | `ConfigurationError` when `issuerUrl` is missing or is not a valid URL |
| Go | `hearth.NewClient(baseURL, realmID, opts...)` | options `WithClientCredentials(clientID, clientSecret)`, `WithJWKSTTL(ttl)`, `WithSessionVersions(cfg)` | nothing |
| Python | `HearthClient(base_url, realm_id, access_token=None, client_id=None, client_secret=None, jwks_ttl=None, timeout=30.0)` | the parameters listed | nothing |
| PHP | `new HearthClient($issuerUrl, $clientId, $clientSecret, $jwksTtl, $introspectionEndpoint, $httpTimeout = 10, $tokenAuthorizationMode, ...)` | the parameters listed, plus optional PSR-18 and PSR-17 objects | `ConfigurationException` when `issuerUrl` is empty |

- The client ID is required for flows that need a client identity. The client secret is required for confidential-client flows.
- Only the TypeScript and PHP SDKs accept an override for the discovered introspection URL.
- The timeout for every outbound HTTP call SHALL default to 10 s. The Python SDK's `timeout` defaults to 30 s.
- The JWKS TTL defaults to 5 min. "JWKS cache rules" states how each SDK combines it with `Cache-Control`.

#### Scenario: Issuer URL is not a URL
- **WHEN** an application constructs the TypeScript `HearthClient` with an `issuerUrl` that is not a valid URL
- **THEN** construction fails with `ConfigurationError`, and the SDK sends no request

#### Scenario: Empty issuer URL in PHP
- **WHEN** an application constructs the PHP `HearthClient` with an empty `issuerUrl`
- **THEN** construction fails with `ConfigurationException`

#### Scenario: Default HTTP timeout
- **WHEN** the TypeScript or PHP client is constructed without a timeout, and an outbound call gets no answer
- **THEN** the call fails after 10 s

#### Scenario: Python default timeout
- **WHEN** the Python client is constructed without `timeout`, and an outbound call gets no answer
- **THEN** the call fails after 30 s

### Requirement: Endpoint URLs come from OIDC discovery
Every SDK SHALL discover endpoint URLs from the realm's `/.well-known/openid-configuration` (under the issuer URL; Go `baseURL`, Python `base_url`) on first use. Hard-coded endpoint paths are prohibited. The SDK SHALL cache the discovery document for the lifetime of the client. When the discovery endpoint is unreachable, or answers with a document that is not valid JSON, the SDK SHALL throw `DiscoveryError`. Routes that the discovery document does not advertise use the paths this specification names for them.

#### Scenario: Token endpoint from discovery
- **WHEN** the discovery document advertises a `token_endpoint`, and the application calls `clientCredentials()`
- **THEN** the SDK posts to that `token_endpoint`, not to a path it built itself

#### Scenario: Discovery is down
- **WHEN** the discovery endpoint is unreachable, and the application calls `verifyToken()`
- **THEN** the SDK throws `DiscoveryError`, and does not guess a JWKS path

#### Scenario: Discovery is fetched once
- **WHEN** the application makes two calls that need endpoint URLs on the same client
- **THEN** the SDK fetches the discovery document once

### Requirement: Access tokens verify only with EdDSA
An SDK SHALL accept only `alg: "EdDSA"` (`kty: "OKP"`, `crv: "Ed25519"`) when it verifies an access token. It SHALL reject every other `alg`, including `RS256` and `ES256`, with `TokenInvalidError`. It SHALL reject an `RS256` token even when the realm JWKS publishes the RSA key that signed it: an ID token must never pass as a bearer access token. A client that registered `id_token_signed_response_alg: RS256` receives ID tokens signed `RS256` with the realm's RSA key, and the realm JWKS publishes that key. No SDK verifies ID tokens; an application that needs to validate an `RS256` ID token uses its OIDC library against the same JWKS. There is no federation exception: a federated login is exchanged for a Hearth-issued Ed25519 token.

#### Scenario: RS256 ID token presented as an access token
- **WHEN** `verifyToken()` receives an `RS256` ID token whose signing key is in the realm JWKS
- **THEN** the SDK throws `TokenInvalidError`

#### Scenario: EdDSA token beside a published RSA key
- **WHEN** the realm JWKS carries an `RSA` ID-token key and an `OKP` access-token key, and `verifyToken()` receives a valid EdDSA access token
- **THEN** the SDK returns the claims

#### Scenario: ES256 token
- **WHEN** `verifyToken()` receives a token whose header says `alg: ES256`
- **THEN** the SDK throws `TokenInvalidError`

### Requirement: OKP JWK parsing
An SDK SHALL parse Ed25519 public keys in the RFC 8037 OKP format that Hearth's JWKS endpoint emits. The format has no `y` coordinate, and the SDK SHALL NOT require one.

| Field | Value |
|---|---|
| `kty` | `"OKP"` |
| `crv` | `"Ed25519"` |
| `x` | Base64url-encoded 32-byte public key, the only coordinate |
| `y` | Absent |
| `alg` | `"EdDSA"` |
| `use` | `"sig"` |

When it parses a JWKS, the SDK SHALL skip, without an error, every key that is not `OKP`/`Ed25519`. A realm JWKS carries `OKP`/`Ed25519` access-token keys (`x-key-role: "access-token-signing"`) and, once a client in the realm selected `RS256`, `RSA`/`RS256` ID-token keys (`x-key-role: "id-token-signing"`). The SDK SHALL NOT branch on `x-key-role`, and SHALL NOT select a verifier from it. The `alg` check refuses an `RS256` token.

#### Scenario: Key without a y coordinate
- **WHEN** the JWKS carries an `OKP`/`Ed25519` key with only `kty`, `crv`, `x`, `kid`, `alg` and `use`
- **THEN** the SDK loads the key, and verifies tokens signed with it

#### Scenario: RSA key in the realm JWKS
- **WHEN** the JWKS carries an `RSA` key with `x-key-role: "id-token-signing"` beside the access-token key
- **THEN** the SDK skips the `RSA` key without an error, and access-token verification works

### Requirement: JWKS cache rules
Every SDK SHALL cache the realm's JWKS keys. On a token whose `kid` is not cached, the SDK SHALL re-fetch the JWKS once. When the `kid` is still absent, the token is bad, and the SDK SHALL throw `TokenInvalidError`. The SDK SHALL use `JWKSFetchError` for a JWKS endpoint that is unreachable, or that answers with an error status or an invalid document, and never for an unknown `kid`. The cache lifetime differs per SDK:

| SDK | Keys absent from the latest fetch | Cache lifetime |
|---|---|---|
| Go, Python | Kept | `Cache-Control: max-age` of the JWKS response, capped at 24 hours. The configured TTL (default 5 min) applies when the response has no `max-age`. |
| PHP | Kept | The configured `jwksTtl` when set; otherwise `Cache-Control: max-age`; otherwise 5 min. Capped at 24 hours. |
| TypeScript | Dropped: each fetch replaces the whole key set | The configured `jwksTtl` (ms), default 5 min. `Cache-Control` is not read. |

#### Scenario: Key rotation
- **WHEN** Hearth starts signing with a new key, and the SDK receives a token whose `kid` is not cached
- **THEN** the SDK re-fetches the JWKS once, and verifies the token with the new key

#### Scenario: Unknown kid after one re-fetch
- **WHEN** a token's header `kid` is replaced with a `kid` that the JWKS does not publish
- **THEN** the SDK re-fetches once, then throws `TokenInvalidError`, not `JWKSFetchError`

#### Scenario: JWKS endpoint unreachable
- **WHEN** the JWKS endpoint does not answer
- **THEN** the SDK throws `JWKSFetchError`

#### Scenario: Long max-age is capped
- **WHEN** the Go, Python or PHP SDK gets a JWKS response with `Cache-Control: max-age=172800`
- **THEN** the SDK fetches the JWKS again after at most 24 hours

#### Scenario: TypeScript uses its own TTL
- **WHEN** the TypeScript SDK gets a JWKS response with `Cache-Control: max-age=60`, and no `jwksTtl` is configured
- **THEN** the SDK keeps the key set for 5 min

### Requirement: JWT validation steps
`verifyToken()` SHALL run these six checks on every token:

| # | Check | Error on failure |
|---|---|---|
| 1 | The signature verifies against the cached JWKS. | `TokenInvalidError` |
| 2 | `exp` is not in the past. | `TokenExpiredError` |
| 3 | `iss` equals the configured issuer (TypeScript and PHP `issuerUrl`, Go `baseURL`, Python `base_url` or the `issuer_url` argument). The issuer in the discovery document does not replace it. | `TokenIssuerError` |
| 4 | `aud` contains the configured `client_id`. Server SDKs only; configurable. | `TokenAudienceError` |
| 5 | `iat` is not in the future. | — |
| 6 | When `nbf` is present, `now` is not before `nbf`. | `TokenNotYetValidError` |

The SDK need not run the checks in this order. A token with two faults (for example expired and with the wrong issuer) MAY get either error, and different SDKs MAY answer differently. A token with one fault SHALL get the same error in every SDK.

#### Scenario: Expired token
- **WHEN** an SDK verifies an access token presented after its `exp` plus the 5 s clock skew
- **THEN** the SDK throws `TokenExpiredError`

#### Scenario: Wrong audience
- **WHEN** the SDK is configured with audience `not-hearth`, and verifies a token issued for `hearth`
- **THEN** the SDK throws `TokenAudienceError`

#### Scenario: Wrong issuer with the same keys
- **WHEN** the SDK is configured with the realm reached as `localhost`, and verifies a token whose `iss` names `127.0.0.1`
- **THEN** the SDK throws `TokenIssuerError`, although the signature verifies

#### Scenario: Token not yet valid
- **WHEN** the SDK verifies a token whose `nbf` is 60 s in the future
- **THEN** the SDK throws `TokenNotYetValidError`

#### Scenario: One fault, same error everywhere
- **WHEN** the four SDKs verify the same token, which has exactly one fault
- **THEN** all four throw the same error type

### Requirement: One clock-skew allowance for time claims
Every SDK SHALL apply one clock-skew allowance of 5 s to `exp`, `nbf` and `iat` alike, through its JOSE library. Where the SDK exposes the allowance (TypeScript `clockSkewSeconds`), a caller MAY widen it.

#### Scenario: Expired inside the allowance
- **WHEN** an SDK verifies a token whose `exp` passed 3 s ago
- **THEN** the SDK returns the claims

#### Scenario: Expired beyond the allowance
- **WHEN** an SDK verifies a token whose `exp` passed 6 s ago
- **THEN** the SDK throws `TokenExpiredError`

#### Scenario: Future iat beyond the allowance
- **WHEN** an SDK verifies a token whose `iat` is 60 s in the future
- **THEN** the SDK rejects the token

### Requirement: verifyToken in every SDK
Every SDK MUST expose `verifyToken(token: string) → Claims`, or its language-idiomatic name (`VerifyToken` in Go, `verify_token` in Python). The method:

- MUST run all six JWT validation steps.
- MUST verify the EdDSA/Ed25519 signature locally against the JWKS. An introspection-only path does not satisfy this requirement.
- MUST return a typed `Claims` object on success.
- MUST throw a typed error from the error taxonomy on any validation failure, never a bare string or a generic exception.
- MUST NOT silently fall back to introspection, or skip signature verification, on any recoverable error.

No per-language or per-platform exception applies, including for future SDKs. Delegating signature verification to a reverse-proxy header, a gateway or a remote service is non-conformant. Verification SHALL work without a running proxy or gateway.

#### Scenario: Tokens verified with fetched public keys
- **WHEN** an application calls `verifyToken()` with a valid Hearth access token
- **THEN** the SDK fetches the realm JWKS, verifies the token locally, and returns typed `Claims`

#### Scenario: No fallback to introspection
- **WHEN** the JWKS endpoint is unreachable, and the client also has introspection credentials
- **THEN** `verifyToken()` throws `JWKSFetchError`, and does not call the introspection endpoint

#### Scenario: Alg none
- **WHEN** `verifyToken()` receives a token with an `alg: none` header and no signature
- **THEN** the SDK throws `TokenInvalidError`

#### Scenario: Tampered payload
- **WHEN** `verifyToken()` receives a token whose payload changed after signing
- **THEN** the SDK throws `TokenInvalidError`

### Requirement: SDK packages and entry points
Each supported SDK SHALL ship under the package name and primary entry point below.

| SDK | Package | Role | Primary entry point |
|---|---|---|---|
| TypeScript | `@hearth-auth/sdk` | Browser SPA, Node.js server, Next.js | `HearthClient` |
| Go | `github.com/hearth-auth/hearth/sdks/go` (package `hearth`) | Server, service | `NewClient()` returning `*Client` |
| PHP | `hearth-auth/php-sdk` | Server (PSR-18) | `HearthClient` |
| Python | `hearth-sdk` | Server (sync HTTP) | `HearthClient` |

The TypeScript package SHALL serve browser and Node.js code. `HearthApiClient` is its lower-level client, kept for backwards compatibility.

#### Scenario: One TypeScript package for browser and server
- **WHEN** a developer installs `@hearth-auth/sdk`
- **THEN** `HearthClient` works in browser code and in Node.js code

### Requirement: SDK capability registry
Every SDK SHALL ship every capability below that applies to it, unless a platform exception in this specification exempts it. An SDK that lacks an applicable capability, with no exception, is non-conforming.

| C-ID | Capability | Applies to |
|---|---|---|
| C-01 | Client configuration | All SDKs |
| C-02 | OIDC discovery | All SDKs |
| C-03 | JWKS fetch and cache | All SDKs |
| C-04 | Token verification (`verifyToken`) | All SDKs |
| C-05 | Token introspection | All SDKs |
| C-06 | Claims API | All SDKs |
| C-07 | Error taxonomy | All SDKs |
| C-08 | Authorization code exchange | All SDKs |
| C-09 | Refresh token flow | All SDKs |
| C-10 | Client credentials flow | All SDKs |
| C-11 | Device authorization flow | All SDKs |
| C-12 | Magic link, send and exchange | All SDKs |
| C-13 | UserInfo endpoint | All SDKs |
| C-14 | Permissions query | All SDKs |
| C-15 | Decision check permission | All SDKs |
| C-16 | HTTP middleware | Server SDKs |
| C-17 | PKCE utilities | TypeScript browser SDK |
| C-18 | Browser auth flow | TypeScript browser SDK |
| C-19 | Admin SDK | All SDKs |
| C-20 | Session-version cache | Optional |

#### Scenario: Server SDK without middleware
- **WHEN** a server SDK ships without HTTP middleware (C-16), and no platform exception names it
- **THEN** the SDK is non-conforming

#### Scenario: Server SDK without a browser flow
- **WHEN** the Go, Python or PHP SDK ships without the browser auth flow (C-18)
- **THEN** the SDK is still conforming, because C-18 applies only to the TypeScript browser SDK

### Requirement: Per-SDK symbol names
Every SDK SHALL expose each canonical method under the language-specific name in this table. A rule that says "every SDK MUST expose `verifyToken()`" means the name in the Canonical column, in the form of each SDK's column.

| Canonical | TypeScript (`@hearth-auth/sdk`) | Go (`hearth`) | Python (`hearth`) | PHP (`HearthClient`) |
|---|---|---|---|---|
| client construction | `new HearthClient(config: HearthClientConfig)` | `hearth.NewClient(baseURL, realmID, opts...)` | `HearthClient(base_url, realm_id, ...)` | `new HearthClient(issuerUrl, clientId?, clientSecret?, ...)` |
| discovery | `HearthClient.discover()` | internal, on first endpoint use | `HearthClient.discovery()` | `HearthClient::discoverEndpoint(key)` |
| JWKS | `HearthClient.jwksClient()`, `JwksClient.fetchKeys()` | internal | `HearthClient.jwks()` | `HearthClient::getJwksClient()` |
| `verifyToken(token)` | `client.verifyToken(token)` | `client.VerifyToken(ctx, token, aud...)` | `client.verify_token(token)` | `$client->verifyToken($token)` |
| `introspect(token)` | `client.introspect(token)` | `client.Introspect(ctx, req)` | `client.introspect(token, ...)` | `$client->getIntrospectionClient()->introspect(...)` |
| `exchangeCode(code, redirectUri, codeVerifier?)` | `HearthClient.exchangeCode(code, redirectUri, opts?)`; `beginLogin(redirectUri, scope?)` / `completeLogin(code, verifier, redirectUri)` | `Client.ExchangeCode(ctx, TokenRequest)` | `HearthClient.exchange_code(code, redirect_uri, code_verifier?)` | `HearthClient::exchangeCode($code, $redirectUri, $codeVerifier)` |
| `refreshTokens(refreshToken)` | `HearthClient.refreshTokens(refreshToken, scope?)` | `Client.RefreshTokens(ctx, clientID, refreshToken)` | `HearthClient.refresh_tokens(refresh_token, ...)` | `HearthClient::refreshToken($refreshToken)` |
| `clientCredentials(scope?)` | `client.clientCredentials(scope?)` | `client.ClientCredentials(ctx, scope...)` | `client.client_credentials(scope?)` | `$client->clientCredentials($scope)` |
| `startDeviceFlow(scope?)` | `client.startDeviceFlow(scope?)` | `client.StartDeviceFlow(ctx, scope...)` | `client.start_device_flow(scope?)` | `$client->startDeviceFlow($scope)` |
| `pollDeviceToken(deviceCode, interval)` | `client.pollDeviceToken(deviceCode, intervalSeconds)` | `client.PollDeviceToken(ctx, deviceCode)` (platform exception) | `client.poll_device_token(device_code, client_id=None)` (platform exception) | `$client->pollDeviceToken($deviceCode, $interval, $sleepFn = null)` |
| `requestMagicLink(email)` | `client.requestMagicLink(email)` | `client.RequestMagicLink(ctx, email)` | `client.request_magic_link(email)` | `$client->requestMagicLink($email)` |
| `exchangeMagicLink(token)` | `HearthClient.exchangeMagicLink(token)` | `Client.ExchangeMagicLink(ctx, token)` | `HearthClient.exchange_magic_link(token)` | `HearthClient::exchangeMagicLink($token)` |
| `userInfo(accessToken)` | `HearthClient.userinfo(accessToken)` | `Client.UserInfo(ctx, accessToken)` | `HearthClient.userinfo(access_token?)` | `HearthClient::getUserInfo($accessToken)` |
| `permissions(accessToken)` | `HearthClient.mePermissions(accessToken)` | `Client.Permissions(ctx, token)` | `HearthClient.permissions(access_token?)` | `HearthClient::getMyPermissions($accessToken)` |
| `checkPermission(token, permission, organizationId?, resource?)` | `HearthClient.authorize(token, permission, opts?)` (platform exception) | `Client.CheckPermission(ctx, token, CheckPermissionRequest)` | `HearthClient.check_permission(token, permission, ...)` | `HearthClient::checkDecision($accessToken, $params)` (platform exception) |
| middleware | `hearthMiddleware(options)` (Express), `hearthFastifyHook(options)` (Fastify), `authenticateRequest(header, options)`; Next.js `withHearthAuth`, `getHearthClaims` (`@hearth-auth/sdk/nextjs`), `hearthEdgeMiddleware` (`@hearth-auth/sdk/nextjs/edge`) | `RequirePermission(client, permission, cfg)` | `RequirePermissionMiddleware` (ASGI), `WsgiPermissionMiddleware` | `HearthMiddleware` (PSR-15) |
| PKCE | `generateCodeVerifier()`, `generateCodeChallenge(verifier)`, `buildAuthorizationUrl(params)`, `startLogin(opts)` | `GeneratePKCE()` | `generate_pkce_pair()` | `HearthClient::generatePkce()` |
| browser auth flow | `createHearthAuth(client, config)` returning `startLogin()`, `handleCallback()`, `logout()`; `getAccessToken()`, `isAuthenticated()`, `clearTokens()` | N/A (server SDK) | N/A (server SDK) | N/A (server SDK) |
| admin client | `AdminClient` | `Client.Admin(accessToken)` returning `AdminClient` | `AdminClient(base_url, admin_token, realm_id)` | `AdminClient` |
| session-version cache | `SessionVersionCache` | `WithSessionVersions(cfg)` option; `Client.Stop()` | N/A | N/A |

These deviations from the canonical shape are intentional and permanent:

- **Go and Python poll the device token once per call.** Go `PollDeviceToken(ctx context.Context, deviceCode string) (*TokenResponse, error)` and Python `poll_device_token(device_code, client_id=None)` take no interval. Each call makes one poll. It returns `nil` (Go) or `None` (Python) while the server answers `authorization_pending` or `slow_down`. The caller waits and calls again, and owns the interval.
- **TypeScript OAuth flows live on `HearthClient`.** `beginLogin`, `completeLogin`, `exchangeCode`, `refreshTokens`, `clientCredentials`, `startDeviceFlow`, `pollDeviceToken` and `requestMagicLink` are methods of `HearthClient`, the primary entry point.
- **TypeScript names the decision check `authorize()`.** `HearthClient.authorize(token, permission, opts?)` has the same behavioural contract as `checkPermission()`.
- **PHP names the decision check `checkDecision()`.** `HearthClient::checkDecision($accessToken, $params)` takes the decision parameters (`permission`, `organization_id`, `resource`) as an array.
- **Go, Python and PHP generate PKCE values as a pair.** `GeneratePKCE()` returns a `PKCEPair`, `generate_pkce_pair()` a `PkcePair`, and `HearthClient::generatePkce()` a `PkceChallenge`; each holds the verifier and its `S256` challenge.

#### Scenario: Canonical name maps to a Go symbol
- **WHEN** a rule says every SDK MUST expose `verifyToken()`
- **THEN** the Go SDK satisfies it with `Client.VerifyToken(ctx, token, aud...)`

#### Scenario: TypeScript decision check
- **WHEN** a TypeScript application needs the decision-mode permission check
- **THEN** it calls `HearthClient.authorize(token, permission, opts?)`, which behaves as `checkPermission()`

### Requirement: Token introspection method
Every SDK SHALL expose `introspect(token: string) → IntrospectionResult` (RFC 7662), which posts the token to the introspection endpoint. The endpoint is the configured introspection override, where the SDK has one, or the one in the discovery document. Introspection requires the client ID and the client secret. The SDK SHALL throw `IntrospectionError` when the endpoint is unreachable or answers with an error. `IntrospectionResult` SHALL include:

| Field | Type | Present |
|---|---|---|
| `active` | bool | Always |
| `sub` | string | When active |
| `exp` | timestamp or int | When active |
| `iat` | timestamp or int | When active |
| `iss` | string | When active |
| `aud` | string or string[] | When active; TypeScript and PHP only |
| `scope` | string | When active and present |
| `client_id` | string | When active and present |
| `extra` | map | All non-standard claims; PHP `extra`, TypeScript an index signature; not in Go or Python |

The Go `IntrospectResponse` and the Python `IntrospectResponse` carry neither `aud` nor `extra`. The SDK SHALL NOT cache introspection results (RFC 7662 §2.1): the token state can change at any time.

#### Scenario: Revoked token
- **WHEN** the application introspects a token that Hearth has revoked
- **THEN** the result has `active: false`

#### Scenario: No caching
- **WHEN** the application introspects the same token twice
- **THEN** the SDK sends two introspection requests

#### Scenario: Endpoint fails
- **WHEN** the introspection endpoint is unreachable
- **THEN** the SDK throws `IntrospectionError`

### Requirement: Access-token authorization modes
An SDK used by a resource server SHALL follow the verification path of the client's `access_token_authorization` mode. The operator sets the mode at client registration, and it decides whether JWKS verification alone is enough.

| Mode | Wire value | Meaning |
|---|---|---|
| `Embedded` (default) | `"embedded"` | The JWT embeds the RBAC claims (`roles`, `permissions`, `groups`, `oid`); verify through JWKS. |
| `Introspection` | `"introspection"` | The JWT carries identity claims only; the resource server MUST call `introspect()` for live authorization data. |
| `Decision` | `"decision"` | The JWT carries identity claims only; the resource server MUST call `POST /oauth/authorize` per request for a live decision. |

- **Embedded:** verify the token through JWKS, and trust the embedded RBAC claims `roles`, `permissions`, `groups`, `oid` and `org_groups`. Introspection is not required, and SHOULD NOT be called on the hot path.
- **Introspection:** the SDK MUST call `introspect()` before it accepts the token for any authorization decision. It MUST NOT use JWKS-verified JWT claims for authorization data; `roles`, `permissions`, `groups`, `oid` and `org_groups` are absent or empty in the JWT by design. The SDK MAY verify the JWKS signature for structural identity validation, but MUST ignore RBAC claims from the JWT; all authorization data comes from the `IntrospectionResult`.
- **Decision:** the SDK MUST call `POST /oauth/authorize` per request. It MUST NOT use JWT claims or introspection results for access control. The token provides identity only.

#### Scenario: Introspection mode ignores JWT claims
- **WHEN** a resource server in introspection mode receives a token whose JWT carries a `permissions` claim, and introspection returns no such permission
- **THEN** the SDK denies the request

#### Scenario: Decision mode asks per request
- **WHEN** a resource server in decision mode handles two requests with the same token
- **THEN** the SDK calls `POST /oauth/authorize` once for each request

#### Scenario: Embedded mode stays local
- **WHEN** a resource server in embedded mode verifies a token with a cached JWKS
- **THEN** the SDK makes no introspection call

### Requirement: Declared authorization mode
An SDK SHALL NOT expect the `access_token_authorization` mode from the discovery document or from the token: the mode is not advertised in either. Resource servers get their mode from operator documentation or configuration management. An SDK MAY expose a `token_authorization_mode` constructor parameter, so operators can declare the expected mode. When the mode is declared:

- The SDK middleware MUST enforce that mode's verification path.
- When the mode requires introspection and `client_id` or `client_secret` is missing, the SDK MUST raise `ConfigurationError` at construction, and MUST NOT fall back to JWKS-only verification.

#### Scenario: Introspection mode without credentials
- **WHEN** an application constructs the client with `token_authorization_mode` set to introspection, and no `client_secret`
- **THEN** construction fails with `ConfigurationError`

### Requirement: Claims accessors
Every SDK SHALL give typed access to the claims of a verified token through the 17 accessors below, so consumers never parse raw JSON. An accessor SHALL return the "when absent" value, and never an error, when its claim is absent.

| Accessor | Source claim | Type | When absent |
|---|---|---|---|
| `subject()` | `sub` | string | `""` |
| `issuer()` | `iss` | string | `""` |
| `audiences()` | `aud` | string[] | `[]` |
| `expiry()` | `exp` | native date-time or int64 | `null` |
| `issuedAt()` | `iat` | native date-time or int64 | `null` |
| `jwtID()` | `jti` | string | `""` in Go and PHP; `null` in TypeScript; `None` in Python |
| `scope()` | `scope` | string, space-delimited | `""` |
| `scopes()` | `scope` | string[], split on spaces | `[]` |
| `hasScope(s)` | `scope` | bool | `false` |
| `hasRole(r)` | `roles: string[]` | bool | `false` |
| `hasPermission(p)` | `permissions: string[]` | bool | `false` |
| `inGroup(g)` | `groups: string[]` | bool | `false` |
| `inOrg(o)` | `oid: string`, exact match | bool | `false` |
| `tokenType()` | `token_type` (`"access"`, `"refresh"`, `"required_action"`) | string | `""` |
| `organizationId()` | `oid` | string or null | `null` |
| `orgGroups()` | `org_groups: string[]` (Keycloak-style paths, for example `/org-slug/group`) | string[] | `[]` |
| `get(claim)` | any claim | raw value | `null` |

Names follow the language. TypeScript and PHP use the names above. Python uses snake_case for `in_group`, `in_org`, `token_type`, `organization_id` and `org_groups`. Go exposes `Client.HasPermission`, `Client.HasRole`, `Client.InGroup` and `Client.InOrg`; each takes a leading `context.Context` and the token, and verifies the token against the realm JWKS (a signature verification, not a bare decode) before it reads any claim. Go exposes the other 13 accessors as exported PascalCase methods of a `Claims` struct.

#### Scenario: Token without roles
- **WHEN** an application calls `hasRole("admin")` on claims whose token has no `roles` claim
- **THEN** the call returns `false`, and throws nothing

#### Scenario: Organization check
- **WHEN** the token carries `oid: "org-1"`, and the application calls `inOrg("org-1")` and `inOrg("org-2")`
- **THEN** the first call returns `true`, and the second returns `false`

#### Scenario: Token type absent
- **WHEN** an application calls `tokenType()` on claims whose token has no `token_type` claim
- **THEN** the call returns `""`, and throws nothing

#### Scenario: Go check with a forged token
- **WHEN** a Go application calls `Client.HasPermission(ctx, token, "docs.edit")` with a token whose signature does not verify
- **THEN** the call returns `false`

### Requirement: Hearth custom claim accessors
Every SDK SHALL expose a typed accessor for each Hearth custom claim below. The accessor SHALL NOT error when the claim is absent; older tokens may omit it.

| Claim | Type | Meaning |
|---|---|---|
| `roles` | `string[]` | Roles assigned to the subject in the issuing realm |
| `permissions` | `string[]` | Expanded permission strings derived from the roles |
| `groups` | `string[]` | Groups the subject belongs to in the realm |
| `oid` | `string` | Organization ID the token was issued for (B2B tenancy) |
| `org_groups` | `string[]` | Group paths scoped to the organization, for example `/org-slug/group` |
| `token_type` | `string` | Token purpose: `"access"`, `"refresh"` or `"required_action"` |

#### Scenario: Organization groups
- **WHEN** an application reads the organization groups from claims whose token carries `org_groups: ["/acme/leads"]`
- **THEN** the typed accessor returns `["/acme/leads"]`

#### Scenario: Token without organization groups
- **WHEN** an application reads the organization groups from claims whose token has no `org_groups` claim
- **THEN** the typed accessor returns an empty list, and throws nothing

### Requirement: Claim check methods
Every SDK SHALL expose the four claim checks `hasPermission`, `hasRole`, `inGroup` and `inOrg`, with these rules:

- `hasPermission` matches an exact permission string: no glob, no prefix.
- `hasRole` matches an exact role name.
- `inGroup` matches an exact group slug.
- `inOrg` matches the `oid` claim exactly.
- When no token is present, or the claim is absent, each returns `false`.

Where the checks live differs per SDK:

| SDK | Methods | Network |
|---|---|---|
| TypeScript | `hasPermission(permission)`, `hasRole(role)`, `inGroup(group)`, `inOrg(org)` on the `createHearth(...)` facade; synchronous | None |
| Go | `Client.HasPermission(ctx, token, permission)`, `HasRole`, `InGroup`, `InOrg` | Verifies the token against the cached JWKS first; fetches the JWKS on a miss |
| Python | static `HearthClient.has_permission(token, permission)`, `has_role`, `in_group`, `in_org` | None |
| PHP | `Claims::hasPermission`, `hasRole`, `inGroup`, `inOrg` on the claims that `verifyToken()` returns | None |

#### Scenario: No prefix match
- **WHEN** the token's `permissions` claim holds `docs.edit`, and the application calls `hasPermission("docs")` and `hasPermission("docs.*")`
- **THEN** both calls return `false`

#### Scenario: Unauthenticated
- **WHEN** the TypeScript facade's `getToken` returns no token, and the application calls each of the four methods
- **THEN** all four return `false`, and the SDK makes no network call

### Requirement: Token getter on the claim-check client
The TypeScript SDK SHALL build its claim-check facade with `createHearth({ baseUrl, realmId, getToken })`, for example `createHearth({ baseUrl, realmId, getToken: () => currentAccessToken })`. The SDK SHALL call `getToken` synchronously on every check. It MUST NOT cache the token internally: tokens change through the application's auth flow, and the getter is the contract. The facade SHALL use `baseUrl` and `realmId` only for the live permission query and for the optional session-version cache. The Go, Python and PHP SDKs take the token on each call instead.

#### Scenario: Token changes between checks
- **WHEN** the application's token changes from one without `docs.edit` to one with it, and the application calls `hasPermission("docs.edit")` again
- **THEN** the second call returns `true`

### Requirement: Reactive framework bindings
Every reactive SDK binding (React, Vue, Svelte and similar) MUST expose hook, composable or property-wrapper equivalents of the four claim checks. Today the TypeScript SDK ships React hooks: `useHasPermission`, `useHasRole`, `useInGroup` and `useInOrg`, which read the facade from `HearthProvider`.

- They return the same boolean as the imperative method.
- They have no loading state and no third state (`true | false | undefined`): the JWT is already in memory.
- They return `false` when no `HearthProvider` is mounted.

#### Scenario: Hook matches the imperative check
- **WHEN** a React component calls `useHasPermission("docs.edit")` under a provider whose client answers `hasPermission("docs.edit")` with `true`
- **THEN** the hook returns `true` on the first render

#### Scenario: No provider
- **WHEN** a React component calls `useHasRole("admin")` outside any `HearthProvider`
- **THEN** the hook returns `false`

### Requirement: Claim checks verify the token signature
An SDK MUST verify the JWT signature against the realm's JWKS when it takes in a token for claim checks, and MUST reject unsigned or tampered tokens. The SDK MUST NOT call `/v1/me/permissions` for routine `hasPermission` checks; that endpoint is the escape hatch, not the primary path.

#### Scenario: Tampered token in a claim check
- **WHEN** the token's `permissions` claim was edited after signing, and the application calls `hasPermission` for the added permission
- **THEN** the SDK does not report the permission as held

#### Scenario: Routine check stays local
- **WHEN** the application calls `hasPermission` 100 times
- **THEN** the SDK sends no request to `/v1/me/permissions`

### Requirement: Live permission query
Every SDK SHALL expose a permissions query that calls `GET /v1/me/permissions` with the bearer token, and returns the live-resolved `MePermissionsResponse` (`permissions`, `roles`, `groups`). The answer has the same shape that `hasPermission`, `hasRole` and the other checks read, but the server resolves it at call time; it does not come from the claims baked into the JWT. Documentation SHALL describe it as the call to use when the cached JWT cannot be trusted, for example a long-running background job that checks again before a sensitive action.

#### Scenario: Role removed after issuance
- **WHEN** an admin removes a role from a user after the token was issued, and the application calls the permissions query
- **THEN** the response no longer lists the permissions of that role, while the token's claims still do

### Requirement: Decision-mode permission check
Every SDK SHALL expose a decision check that posts to `POST /oauth/authorize` with the token as a bearer credential and the `permission` (plus optional `organization_id` and `resource`) in the body. The check SHALL fail closed: a network error, a 4xx or a 5xx answer is a deny. The result differs per SDK: TypeScript `authorize()` returns a `boolean`; Go `CheckPermission` returns a `*CheckPermissionResponse` and Python `check_permission` a `CheckPermissionResponse`, each with `allowed: false` on a failure; PHP `checkDecision()` returns the decision payload. The TypeScript check requires `realmId` in the client configuration.

#### Scenario: Server error denies
- **WHEN** `POST /oauth/authorize` answers `500`
- **THEN** the decision check reports a deny, and throws nothing

#### Scenario: Allowed
- **WHEN** the decision endpoint answers that the token holder has the permission
- **THEN** the decision check reports the permission as allowed

### Requirement: UserInfo call
Every SDK SHALL expose `userInfo(accessToken)`, which sends `GET` to the discovered `userinfo_endpoint` with `Authorization: Bearer {token}`, and returns typed user claims.

#### Scenario: Claims for a valid token
- **WHEN** the application calls `userInfo` with a valid access token
- **THEN** the SDK returns the user's claims as a typed object

### Requirement: Authorization code exchange and refresh
Every SDK SHALL expose `exchangeCode(code, redirectUri, codeVerifier?) → TokenResponse`, which posts `grant_type=authorization_code` to the discovered `token_endpoint`. A PKCE `code_verifier` is required for public clients. Every SDK SHALL expose `refreshTokens(refreshToken) → TokenResponse`, which posts `grant_type=refresh_token` to the same endpoint.

#### Scenario: Complete authorization code flow
- **WHEN** a TypeScript or Go application authorizes, exchanges the code, validates the access token and refreshes it
- **THEN** each step succeeds, and the refreshed access token validates

#### Scenario: Public client without a verifier
- **WHEN** a public client exchanges a code without a `code_verifier`
- **THEN** the exchange fails

### Requirement: Client credentials grant
Every SDK MUST implement the client credentials grant (RFC 6749 §4.4), for machine-to-machine authentication, as `clientCredentials(scope?: string) → TokenResponse`. The client credentials, device authorization and magic-link flows are required flows: every server-side, CLI and language SDK exposes them; they are not optional extensions and not browser-only. The method:

- MUST discover `token_endpoint` from the OIDC discovery document.
- MUST send `client_id` and `client_secret` as `application/x-www-form-urlencoded` body fields (RFC 6749 §2.3.1). Sending credentials as query parameters is prohibited.
- MUST NOT send `X-Realm-ID` to the realm token endpoint. The realm is in the path; a header that disagrees with it (for example the realm name where the server expects the id) is refused with `400 realm_mismatch`.
- Requires `client_id` and `client_secret` in the client configuration.

The request is `POST {token_endpoint}` with body `grant_type=client_credentials&client_id={clientId}&client_secret={clientSecret}[&scope={scope}]`. `TokenResponse` SHALL expose:

| Field | Type | Notes |
|---|---|---|
| `access_token` | string | The issued access token |
| `token_type` | string | `"Bearer"`, or `"DPoP"` when DPoP is active |
| `expires_in` | int | Seconds until expiry |
| `scope` | string | Granted scope; may differ from the requested scope |

#### Scenario: Machine token
- **WHEN** a service calls `clientCredentials("read:users")` with valid client credentials
- **THEN** the SDK posts a form-encoded body to the discovered `token_endpoint`, and returns a `TokenResponse` whose access token validates

#### Scenario: Realm name configured
- **WHEN** the SDK is configured with a realm name, and calls `clientCredentials()`
- **THEN** the token request carries no `X-Realm-ID` header, and does not fail with `400 realm_mismatch`

### Requirement: Device authorization flow
Every SDK MUST implement the device authorization flow (RFC 8628) for devices and CLI tools with limited input: `startDeviceFlow(scope?: string) → DeviceAuthorizationResponse`, plus a poll method.

`startDeviceFlow` posts `client_id={clientId}[&scope={scope}]`, form-encoded, to the discovered `device_authorization_endpoint`. Hearth advertises that endpoint as `{issuer}/device_authorization`. `DeviceAuthorizationResponse` SHALL expose:

| Field | Type | Notes |
|---|---|---|
| `device_code` | string | Opaque code passed to the poll method |
| `user_code` | string | Short code the user enters at `verification_uri` |
| `verification_uri` | string | URL the user visits to authorize |
| `verification_uri_complete` | string | `verification_uri` with `user_code` filled in, when the server provides it |
| `expires_in` | int | Seconds until the device code expires |
| `interval` | int | Minimum polling interval in seconds |

Every poll posts `grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={deviceCode}&client_id={clientId}`, form-encoded, to the discovered `token_endpoint`. The poll method has two shapes:

- **TypeScript and PHP** `pollDeviceToken(deviceCode, interval)` poll until the user decides. They MUST wait `interval` seconds between polls; on `authorization_pending`, keep polling without surfacing an error; on `slow_down`, add 5 s to the interval per occurrence, and keep polling.
- **Go and Python** `PollDeviceToken(ctx, deviceCode)` and `poll_device_token(device_code, client_id=None)` make one poll per call. They return `nil` or `None` on `authorization_pending` or `slow_down`. The caller waits and calls again.

On `expired_token`, every SDK MUST raise `TokenExpiredError`.

#### Scenario: User approves after two polls
- **WHEN** the token endpoint answers `authorization_pending` twice, then a token, to the TypeScript or PHP `pollDeviceToken`
- **THEN** `pollDeviceToken` returns the `TokenResponse`, and surfaces no error for the pending answers

#### Scenario: Slow down
- **WHEN** the token endpoint answers `slow_down` to a TypeScript or PHP poll at a 5 s interval
- **THEN** the SDK waits 10 s before the next poll

#### Scenario: Go and Python pending poll
- **WHEN** the token endpoint answers `authorization_pending` to a Go or Python poll
- **THEN** the call returns `nil` or `None`, and no error

#### Scenario: Device code expires
- **WHEN** the token endpoint answers `expired_token`
- **THEN** the poll raises `TokenExpiredError`

### Requirement: Magic-link request
Every SDK MUST expose `requestMagicLink(email: string) → void`, which starts passwordless sign-in.

- It MUST send `POST` with the JSON body `{"email": "<address>"}` to `/v1/{realm}/auth/magic-link`. The endpoint is Hearth-specific, and is not in the discovery document. The URL differs per SDK: PHP posts to `{base_url}/v1/{realm_slug}/auth/magic-link` and takes the slug from `issuerUrl`; TypeScript posts to `{issuerUrl}/v1/{realmId}/auth/magic-link` and throws `ConfigurationError` without a configured `realmId`; Go posts to `{baseURL}/v1/{realmID}/auth/magic-link`; Python posts to `{base_url}/v1/{realm_id}/auth/magic-link`.
- It MUST treat any `202` answer as success, and surface no further detail.
- It MUST NOT raise a "user not found" or similar error for an unknown email. The server answers `202 Accepted` whether the email is registered or not (enumeration resistance), and the SDK passes that through unchanged.
- It MUST surface HTTP `429 Too Many Requests` as a typed error that carries the status: PHP `RateLimitException` (with the `Retry-After` value), TypeScript `OAuthFlowError` with `statusCode: 429`, Go `*APIError` with `StatusCode: 429`, Python `HearthError` with `status_code: 429`.

When the user opens the link in a browser, Hearth validates it and sets a session cookie; that path needs no further SDK call.

#### Scenario: Unknown email
- **WHEN** the application calls `requestMagicLink("nobody@example.com")` for an address with no account
- **THEN** the server answers `202`, and the method returns without an error

#### Scenario: Rate limited
- **WHEN** the magic-link endpoint answers `429`
- **THEN** the SDK raises its typed error, and the error carries status `429`

### Requirement: Magic-link exchange
Every SDK SHALL expose `exchangeMagicLink(token: string) → TokenResponse`, which redeems the opaque token from a magic link. It posts `grant_type=urn:hearth:grant-type:magic-link&token={magicToken}&client_id={clientId}`, form-encoded, to the discovered `token_endpoint`. The grant-type wire value is `urn:hearth:grant-type:magic-link`, and the token parameter is `token`.

#### Scenario: Redeem a link
- **WHEN** the application calls `exchangeMagicLink` with the token from a fresh magic link
- **THEN** the SDK returns a `TokenResponse`

### Requirement: Client registration calls
An SDK that exposes client registration SHALL send the credential that each route requires; neither route is anonymous by default.

| Route | Credential | Success |
|---|---|---|
| `POST /clients` (admin) | `Authorization: Bearer <token>` carrying `hearth.clients.admin` (or `hearth.admin`) in the realm, plus `X-Realm-ID` | `201` with the proto `OAuthClient` (`client_id`, `client_name`, …), plus a generated `client_secret`, once, when `token_endpoint_auth_method` is `client_secret_basic` or `client_secret_post` |
| `registration_endpoint` from discovery (RFC 7591, for example `/realms/{name}/register`) | Set by the realm's `dcr_policy`: `disabled` (default) answers `403`; `open` needs none; `authenticated` needs an RFC 7591 §3.1 initial access token (a realm token carrying `hearth.clients.admin`) as `Authorization: Bearer` | `201` with `client_id` and a generated `client_secret` |

- The admin route answers `401 missing authorization header` without a token. SDKs MUST send the caller's token: the client's configured access token, or an explicit token argument. Adding that argument MUST NOT break existing callers where the language allows it (optional or variadic parameter).
- The admin route's body is the proto `RegisterClientRequest`. The name key is `client_name`; the server rejects an unknown `name` key with `422`. The enum fields take their proto names: `trust_level` is `CLIENT_TRUST_LEVEL_FIRST_PARTY` or `CLIENT_TRUST_LEVEL_THIRD_PARTY`, and `access_token_authorization` is `EMBEDDED`, `INTROSPECTION` or `DECISION`. The snake_case spellings (`first_party`, `embedded`) are a `422`.
- SDKs MUST treat `201 Created` as success.
- SDKs SHOULD let the caller pass `token_endpoint_auth_method` (`client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none`). They MUST surface the `client_secret` of the create response: it is the only time the server returns the generated secret. The server refuses a caller-chosen `client_secret` on these routes with `422`.
- `POST /admin/applications/{id}/regenerate-secret` returns the client record with a new `client_secret`, once; the old secret stops working at once. SDKs MUST offer it on their admin client: `regenerateClientSecret` (TypeScript, PHP), `RegenerateClientSecret` (Go), `regenerate_client_secret` (Python).
- An RFC 7591 registration method MUST accept an optional initial access token, and send it as `Authorization: Bearer` when it is given.

#### Scenario: Admin registration without a token
- **WHEN** an SDK registers a client through `POST /clients` without a token
- **THEN** the server answers `401 missing authorization header`

#### Scenario: Generated secret surfaced once
- **WHEN** an SDK registers a client with `token_endpoint_auth_method: client_secret_post`, and the server answers `201`
- **THEN** the SDK returns the generated `client_secret` to the caller

#### Scenario: Secret regenerated
- **WHEN** an admin calls `regenerateClientSecret` for a client
- **THEN** the SDK returns the new `client_secret`, and the old secret no longer authenticates

### Requirement: Error types
Every SDK MUST define and expose these 10 error types. Language-native error handling applies: Go uses sentinel errors and named types, Python uses exceptions, TypeScript uses typed `Error` subclasses, PHP uses `\Throwable`.

| Error | When thrown |
|---|---|
| `ConfigurationError` | Required configuration is missing, or the issuer URL is invalid |
| `DiscoveryError` | The OIDC discovery endpoint is unreachable, or returned invalid JSON |
| `JWKSFetchError` | The JWKS endpoint is unreachable, or returned an invalid response (not an unknown `kid`) |
| `TokenExpiredError` | The `exp` claim is in the past |
| `TokenNotYetValidError` | The `nbf` claim is in the future, beyond the 5 s clock skew |
| `TokenInvalidError` | Invalid signature, malformed JWT, algorithm mismatch, or a `kid` absent from the JWKS after one re-fetch |
| `TokenIssuerError` | `iss` does not match the configured issuer |
| `TokenAudienceError` | `aud` does not contain the expected audience |
| `IntrospectionError` | The introspection endpoint is unreachable, or returned an error |
| `RequiredActionError` | A token with `token_type === "required_action"` is presented as an access token |

TypeScript classes, Go types and Python exceptions use the names in the Error column. PHP classes end in `Exception` instead: `ConfigurationException`, `DiscoveryException`, `JWKSFetchException`, `TokenExpiredException`, `TokenNotYetValidException`, `TokenInvalidException`, `TokenIssuerException`, `TokenAudienceException`, `IntrospectionException`, `RequiredActionException`.

#### Scenario: Unknown kid error name
- **WHEN** each SDK verifies a token whose `kid` is not published
- **THEN** each SDK reports `TokenInvalidError` (PHP `TokenInvalidException`)

#### Scenario: Discovery failure error name
- **WHEN** the discovery endpoint answers with HTML instead of JSON
- **THEN** the SDK throws `DiscoveryError`

### Requirement: Required-action errors
`RequiredActionError` SHALL expose the names of the pending actions (for example `["VERIFY_EMAIL", "UPDATE_PASSWORD"]`), filled from the presented token's `required_actions` claim: TypeScript `requiredActions`, Go `RequiredActions`, Python `required_actions`, PHP `getRequiredActions()`. It SHALL carry no redirect URL: the server never supplies one. Hearth issues no required-action token; the check is defensive. In browser and OIDC flows nothing reaches the application: Hearth runs the pending actions itself, at `/required-action/{ACTION}` during `/authorize`, before it issues an authorization code.

#### Scenario: Required-action token at the middleware
- **WHEN** the middleware receives a token with `token_type: "required_action"` and `required_actions: ["VERIFY_EMAIL"]`
- **THEN** the SDK raises `RequiredActionError` whose pending actions are `["VERIFY_EMAIL"]`, with no redirect URL

### Requirement: Error messages and causes
Every SDK error SHALL include a human-readable `message`. An error that wraps a network or parse error SHALL expose the original cause: Go through `Unwrap()`, Python through `__cause__`, TypeScript through the `cause` property. Tokens and secrets MUST NOT appear in error messages or log output.

#### Scenario: Wrapped network error
- **WHEN** a JWKS fetch fails because the connection is refused
- **THEN** the `JWKSFetchError` exposes the connection error as its cause

#### Scenario: Token not echoed
- **WHEN** `verifyToken()` rejects a token
- **THEN** the error message does not contain the token

### Requirement: HTTP error shape
Every SDK SHALL surface a non-2xx Hearth API answer that the error taxonomy does not cover as a typed error that carries the HTTP status. The ten taxonomy errors stay for discovery, JWKS, token verification, introspection and required actions.

| SDK | Error type | Fields | Network failure |
|---|---|---|---|
| TypeScript | `HearthError` from `HearthApiClient` and `AdminClient`; `OAuthFlowError` from `HearthClient` flows | `status`, `body`; `statusCode`, `errorCode` | `HearthClient` raises `OAuthFlowError` with `statusCode: 0` |
| Go | `*APIError` | `StatusCode`, `Message` | The `net/http` error, returned as is |
| Python | `HearthError` | `status_code`, `message`, `details` | The `httpx` exception |
| PHP | `HearthException` subclasses; a plain `RuntimeException` with the status in its message for some calls | message, int code | `NetworkException` |

#### Scenario: Server refuses the call
- **WHEN** an SDK call gets `403` from the Hearth API
- **THEN** the SDK raises its HTTP error type, and the error carries status `403`

#### Scenario: TypeScript network failure
- **WHEN** a TypeScript `HearthClient` flow cannot connect to the server
- **THEN** the SDK raises `OAuthFlowError` with `statusCode: 0`

### Requirement: Resource-server middleware
Every server-side SDK (TypeScript on Node.js, Go, Python, PHP) MUST provide HTTP middleware that:

1. Extracts the bearer token from `Authorization: Bearer <token>`.
2. Verifies the token locally, through JWKS, by default. Introspection is opt-in.
3. On success, injects the verified claims into the request context under a well-known key.
4. On a missing or invalid token, answers `401 Unauthorized` with `WWW-Authenticate: Bearer realm="hearth"`.
5. On insufficient scope or role, answers `403 Forbidden`.
6. On a token with `token_type === "required_action"`, MUST answer `401 Unauthorized` and raise `RequiredActionError`, not a generic unauthorized error, with `requiredActions` filled from the token's `required_actions` claim. Such a token MUST NOT be accepted for general API access. Hearth issues no such token; the check is defensive.
7. Does not call `next` when authentication fails.

The middleware SHALL follow the configured authorization mode: verify, introspect or decide. The browser code of `@hearth-auth/sdk` is exempt from the middleware requirement, but MUST provide equivalent helpers for SPA route guards.

#### Scenario: No token
- **WHEN** a request without an `Authorization` header reaches the middleware
- **THEN** the middleware answers `401` with `WWW-Authenticate: Bearer realm="hearth"`, and the handler does not run

#### Scenario: Valid token reaches the handler
- **WHEN** a request carries a valid token that holds the required permission
- **THEN** the handler runs, and can read the verified claims from the request context

#### Scenario: Missing permission
- **WHEN** a request carries a valid token without the required permission
- **THEN** the middleware answers `403`, and the handler does not run

#### Scenario: Required-action token
- **WHEN** a request carries a token with `token_type: "required_action"`
- **THEN** the middleware answers `401`, and raises `RequiredActionError` with the token's `required_actions`

### Requirement: Framework adapters
Every SDK SHALL ship its framework adapters so that the core client does not import a web framework. The adapters live here:

| SDK | Adapters | Dependency |
|---|---|---|
| TypeScript | Express `hearthMiddleware`, Fastify `hearthFastifyHook`, Next.js (`@hearth-auth/sdk/nextjs`, `@hearth-auth/sdk/nextjs/edge`), React hooks | `react` and `next` are optional peer dependencies |
| Go | `net/http` `RequirePermission`; gin (package `hearth/gin`); echo (package `hearth/echo`) | Subpackages of the one module; its `go.mod` requires gin and echo |
| Python | ASGI and WSGI middleware in the core; FastAPI (`hearth.fastapi`); Django (`hearth.django`) | The `fastapi` and `django` extras |
| PHP | PSR-15 `HearthMiddleware`; Laravel (`Hearth\Laravel`) | `illuminate/support` is suggested, not required |

#### Scenario: TypeScript core without a framework
- **WHEN** an application installs `@hearth-auth/sdk` without React or Next.js
- **THEN** the SDK installs and verifies tokens

#### Scenario: Go service without gin
- **WHEN** a Go service imports only package `hearth`
- **THEN** it builds and verifies tokens without importing gin or echo

### Requirement: PKCE utilities
The TypeScript browser SDK SHALL ship RFC 7636 PKCE utilities: `generateCodeVerifier()`, `generateCodeChallenge(verifier)` and `buildAuthorizationUrl(params)`.

#### Scenario: Challenge from a verifier
- **WHEN** the application calls `generateCodeChallenge(verifier)`
- **THEN** it returns the base64url-encoded SHA-256 of the verifier, as RFC 7636 `S256` defines

### Requirement: Browser login flow
The TypeScript browser SDK SHALL implement, through `createHearthAuth(config)`:

- **PKCE authorization code flow** (RFC 7636): `startLogin()` redirects; `handleCallback()` exchanges the code for tokens.
- **Silent refresh**: renew the token through a hidden iframe before expiry. The lead time is configurable; default 60 s before `exp`.
- **Logout**: clear the local session, and redirect to RP-initiated logout.
- **Storage abstraction**: default `sessionStorage`; pluggable (`localStorage`, in-memory, custom). The storage key prefix is configurable.
- **Cross-tab state sync**: optional. The SDK SHOULD sync login and logout across tabs through a broadcast channel or storage events.

`handleCallback()` needs no required-action detection. Hearth runs pending required actions itself, at `/required-action/{ACTION}` during `/authorize`, before it issues a code. The callback always carries an ordinary `code`, and the exchange yields an ordinary access token. The server never adds a `required_action_redirect_uri` callback parameter, and never issues a `token_type === "required_action"` token from the code exchange.

#### Scenario: Login round trip
- **WHEN** a single-page app calls `startLogin()`, and the user signs in and returns to the callback
- **THEN** `handleCallback()` exchanges the code with the PKCE verifier, and the app holds an access token

#### Scenario: Custom storage
- **WHEN** the app configures an in-memory store and the key prefix `myapp_`
- **THEN** the SDK keeps its state there under keys that start with `myapp_`, and writes nothing to `sessionStorage`

#### Scenario: Logout
- **WHEN** the app calls `logout()`
- **THEN** the SDK clears the local session, and redirects to the realm's end-session endpoint

### Requirement: Session-version cache
An SDK MAY ship a session-version cache. One that does SHALL poll `GET /oauth/session-versions/snapshot?realm={realm}` once, then `GET /oauth/session-versions?since={seq}&realm={realm}`, to detect revoked sessions without introspection. It SHALL accept a configurable `pollIntervalMs` and `staleThresholdMs`, and SHALL release its background goroutine or thread on `stop()` or `close()`. The TypeScript `SessionVersionCache` and the Go `WithSessionVersions` option ship one.

#### Scenario: Revoked session detected
- **WHEN** a session is revoked, and the cache's next delta poll runs
- **THEN** a check on a token of that session fails as revoked, with no introspection call

#### Scenario: Stop releases the poller
- **WHEN** the application calls `stop()`
- **THEN** the background poll ends

### Requirement: SDK prohibitions
An SDK MUST NOT:

- poll any endpoint for permission changes. The optional session-version cache, which polls for revoked sessions, is the one allowed poller;
- hold persistent connections (SSE, WebSocket, streaming RPC) for cache coherence;
- accept a `subject` parameter in any check method: the subject is always the bearer-token user, as the token itself enforces;
- expose vocabulary from earlier tuple-based authorization models;
- persist decoded permissions to disk or across process restarts. Tokens are short-lived; persistence is the application's job, if it needs it.

#### Scenario: No subject parameter
- **WHEN** a developer looks for a way to check another user's permission with `hasPermission`
- **THEN** no check method accepts a subject; the check always applies to the bearer token's user

#### Scenario: Restart drops decoded permissions
- **WHEN** a process restarts
- **THEN** the SDK holds no permissions from before the restart

### Requirement: SDK versioning
Every SDK SHALL use SemVer (`MAJOR.MINOR.PATCH`), and SHALL keep a `CHANGELOG.md` that is updated for every release. A breaking SDK change SHALL bump the major version. Hearth has no production users, so a legacy SDK path is removed outright: no deprecated alias, no deprecation period. The `CHANGELOG.md` entry records the removal.

#### Scenario: Removed method
- **WHEN** an SDK removes a public method
- **THEN** the release bumps the major version, keeps no deprecated alias, and `CHANGELOG.md` records the removal

### Requirement: SDK test suites
Every SDK SHALL ship tests that meet these requirements:

| Category | Requirement |
|---|---|
| Unit tests | All public methods and error paths |
| Integration tests | Against a live Hearth instance, or a Hearth test server in CI |
| JWKS rotation test | Force a key rollover, and verify transparent recovery |
| Clock skew test | Verify the tolerance at its boundaries |
| Conformance runner | `sdks/<sdk>/conformance/run.sh`, run by the shared harness |
| CI gate | Tests pass on every PR |

The unit-test suite SHALL use an HTTP mock, not a live server, and cover: JWT decoding; `hasPermission`, `hasRole`, `inGroup` and `inOrg` returning the right booleans for given tokens; tokens without the claims defaulting to `false`; a rejected invalid JWT signature; and admin-client CRUD against mocked responses. Reactive bindings, where an SDK has them, SHALL be tested with the framework's test harness: the hook returns the right boolean. A new SDK is not supported until it ships `sdks/<sdk>/conformance/run.sh` and passes every harness scenario.

#### Scenario: Mocked unit suite
- **WHEN** an SDK's unit tests run
- **THEN** they use an HTTP mock, and one of them shows that a token with an invalid signature is rejected

#### Scenario: New SDK without a runner
- **WHEN** a new SDK has no `sdks/<sdk>/conformance/run.sh`
- **THEN** it is not a supported SDK

### Requirement: SDK documentation
Every SDK SHALL contain:

- a `README.md` with installation, configuration, usage examples and a quickstart that reaches a first verified token in under 5 minutes;
- a full API reference, generated from source or written by hand;
- one runnable example per supported framework;
- a troubleshooting section that covers the common errors of the error taxonomy;
- a link to the Hearth server compatibility matrix.

#### Scenario: Troubleshooting a common error
- **WHEN** a developer gets `TokenAudienceError` and opens the SDK README
- **THEN** the troubleshooting section explains the error and how to fix it

### Requirement: Agent-auth README section
Every SDK README MUST include an "Agent Authentication" section. The section covers these seven items:

1. **Prerequisites**: `agent_auth.capabilities.identity = true`, plus `advanced = true` for AATs and transaction tokens.
2. **Agent CRUD**: `POST /v1/agents`, `POST /v1/agents/{id}/credentials/keys`.
3. **DPoP-bound tokens (RFC 9449)**: EC P-256 key-pair generation, the JWK thumbprint (RFC 7638), proof JWT construction (`typ: dpop+jwt`, `cnf.jkt` binding), and the nonce flow.
4. **RFC 8693 token exchange**: `urn:ietf:params:oauth:grant-type:token-exchange`, the `act` claim chain, and the `on_behalf_of` extension.
5. **AATs**: `POST /v1/aats` (root issuance) and `POST /v1/aats/derive` (scope narrowing; the child is a subset of the parent).
6. **Transaction tokens**: `POST /v1/transaction-tokens` and `/consume` (single use, 60 s TTL, replay prevention).
7. **Draft-tracking owner**: the name of the owner who re-checks IETF draft advancement.

The TypeScript, Go and PHP READMEs cover the items in place. The Python README covers the prerequisites, DPoP, AAT issuance and transaction tokens, and links to the TypeScript README's "Agent Authentication" section for the rest, including RFC 8693 token exchange and the draft-tracking owner. The agent-auth surface is REST endpoints. It needs no SDK type beyond the admin client's HTTP methods.

#### Scenario: README review
- **WHEN** a reviewer opens the TypeScript, Go or PHP README
- **THEN** it has an "Agent Authentication" section that covers all seven items, including the named draft-tracking owner

#### Scenario: Python README links out
- **WHEN** a reviewer opens the Python README's "Agent Authentication" section
- **THEN** it covers DPoP, AAT issuance and transaction tokens, and links to the TypeScript README for token exchange and draft tracking

### Requirement: SDK security
Every SDK SHALL meet these rules:

- Tokens and secrets MUST NOT appear in logs, error messages or stack traces.
- Every HTTPS connection SHALL validate TLS certificates: no `InsecureSkipVerify` or equivalent.
- Every credential or secret comparison SHALL be timing-safe.
- Dependencies SHALL be minimal, and pinned by a committed lockfile (`package-lock.json`, `go.sum`, `uv.lock`, `composer.lock`).
- The SDK SHALL NOT use `eval`, `exec` or dynamic code generation on token data.

#### Scenario: Self-signed certificate
- **WHEN** the issuer presents a TLS certificate that does not validate
- **THEN** the SDK refuses the connection

### Requirement: Admin client entry point
Every SDK SHALL ship an `AdminClient` type for the Hearth admin API (`/admin/*`), separate from the resource-server `HearthClient`. The TypeScript, Python and PHP SDKs construct it directly. The Go SDK builds it with `Client.Admin(accessToken)`, which reuses the client's base URL, realm and HTTP client. `AdminClient` takes:

| Parameter | Type | Required | Meaning |
|---|---|---|---|
| `base_url` | string | Yes | Root URL of the Hearth instance, no trailing slash |
| `realm_id` | string | Yes | ID of the realm to administer |
| `access_token` | string | Yes | A valid access token whose subject holds the `admin` role in the target realm |

`AdminClient` SHALL NOT perform OIDC discovery, and SHALL NOT manage the token lifecycle; the caller obtains and refreshes the admin token, typically through a confidential client's `client_credentials` grant. Every request SHALL send `Authorization: Bearer {access_token}` and `X-Realm-ID: {realm_id}`.

#### Scenario: Headers on every admin call
- **WHEN** an application lists users through `AdminClient`
- **THEN** the request carries `Authorization: Bearer {access_token}` and `X-Realm-ID: {realm_id}`, and the SDK fetched no discovery document

#### Scenario: Go admin client from the client
- **WHEN** a Go application calls `Client.Admin(accessToken)`
- **THEN** it gets an `AdminClient` that sends that token and the client's realm on every call

### Requirement: Admin client scope and authorization
An `AdminClient` operation SHALL apply to the realm named by `realm_id`. The `access_token` must belong to a subject with the `admin` role in that realm. A token of the system realm (`RealmId::nil()`) may administer realm-level metadata through `/admin/realms`: reading realms, or deleting an archived realm. Realms are created in `hearth.yaml`; `POST /admin/realms` answers `405`. A `403 Forbidden` means the token's subject lacks the required admin role. The SDK SHOULD surface it as a distinct error, for example an HTTP error type that carries the status code, and SHALL NOT fail silently.

#### Scenario: Token without the admin role
- **WHEN** an `AdminClient` call is made with a token whose subject lacks the admin role
- **THEN** the SDK raises an error that carries status `403`

### Requirement: Admin users, realms, clients, roles and groups
Every `AdminClient` SHALL provide at least these operations:

| Entity | Methods | Routes |
|---|---|---|
| Users | `createUser(params)`, `getUser(id)`, `updateUser(id, params)`, `deleteUser(id)`, `listUsers(options)` | `POST /admin/users`, `GET /admin/users/{id}`, `PATCH /admin/users/{id}`, `DELETE /admin/users/{id}`, `GET /admin/users?limit=N&cursor=C` |
| Realms | `getRealm(id)`, `deleteRealm(id)` (archived realms only), `listRealms(options)` | `GET /admin/realms/{id}`, `DELETE /admin/realms/{id}`, `GET /admin/realms?limit=N&cursor=C` |
| OAuth clients | create, get, update, delete, list | `/admin/applications` |
| Roles | create, get, update, delete, list | `/admin/roles` |
| Groups | create, get, update, delete, list | `/admin/groups` |

- Realms are provisioned in `hearth.yaml` and reconciled at startup, not through the admin API. SDKs MUST NOT expose a `createRealm` method: the server answers `405 Method Not Allowed` for `POST /admin/realms` and `PATCH /admin/realms/{id}`.
- OAuth clients live at `/admin/applications`. The server has never served `/admin/clients`. The update verb is `PATCH`, not `PUT`.
- `POST /admin/applications` takes the proto `RegisterClientRequest`, the same body as `POST /clients`: `client_name`, and proto enum names for `trust_level` and `access_token_authorization`. An unknown key such as `name` is a `422`.
- `PATCH /admin/applications/{id}` takes `client_name`, with `trust_level` (`first_party`, `third_party`) and `access_token_authorization` (`embedded`, `introspection`, `decision`) as snake_case strings. It ignores unknown keys, so an SDK that sends `name` gets `200` and the client is not renamed.
- Every client route answers with the proto `OAuthClient`: `client_id`, `client_name`, `redirect_uris`, `grant_types`, `created_at`, and `access_token_authorization` as a proto enum name, omitted when it is `EMBEDDED`.
- No client route sends or reads `id` or `name`.
- Role assignment is not CRUD-shaped: `POST /admin/users/{id}/roles` with a `{ "role_id": ..., "org_id"?: ... }` body creates an assignment, `GET /admin/users/{id}/roles` lists them, and `DELETE /admin/assignments/{id}` removes one.

#### Scenario: Users CRUD
- **WHEN** an application creates, reads, updates and deletes a user through `AdminClient`
- **THEN** each call succeeds against a live Hearth server

#### Scenario: No realm creation
- **WHEN** a developer looks for `createRealm` on any SDK's `AdminClient`
- **THEN** no such method exists

#### Scenario: Rename a client
- **WHEN** an application renames an OAuth client through `AdminClient`
- **THEN** the SDK sends `PATCH /admin/applications/{id}` with `client_name`, and the client is renamed

### Requirement: Admin organization operations
Every SDK's `AdminClient` SHALL expose organization CRUD and a member's extra organization roles under these names:

| HTTP | TypeScript | Go | Python | PHP |
|---|---|---|---|---|
| `GET /admin/organizations` | `listOrganizations` | `ListOrganizations` | `list_organizations` | `listOrganizations` |
| `POST /admin/organizations` | `createOrganization` | `CreateOrganization` | `create_organization` | `createOrganization` |
| `GET /admin/organizations/{id}` | `getOrganization` | `GetOrganization` | `get_organization` | `getOrganization` |
| `PATCH /admin/organizations/{id}` | `updateOrganization` | `UpdateOrganization` | `update_organization` | `updateOrganization` |
| `DELETE /admin/organizations/{id}` | `deleteOrganization` | `DeleteOrganization` | `delete_organization` | `deleteOrganization` |
| `GET /admin/organizations/{id}/members/{user_id}/roles` | `listMemberRoles` | `ListMemberRoles` | `list_member_roles` | `listOrganizationMemberRoles` |
| `POST /admin/organizations/{id}/members/{user_id}/roles` | `addMemberRole` | `AddMemberRole` | `add_member_role` | `addOrganizationMemberRole` |
| `DELETE /admin/organizations/{id}/members/{user_id}/roles/{role_name}` | `removeMemberRole` | `RemoveMemberRole` | `remove_member_role` | `removeOrganizationMemberRole` |

The body fields are snake_case. Create takes `slug`, `display_name`, `member_limit`, `mfa_required` and `attributes`. Update takes the same fields without `slug` (immutable; sending it is a `400`), plus `status` (`active` or `suspended`). Adding a role takes `role_name`. Membership itself (adding or removing a member) has no REST route, so an SDK SHALL NOT expose membership methods; membership is administered through the admin console or SCIM.

#### Scenario: Slug is immutable
- **WHEN** an application updates an organization and sends a new `slug`
- **THEN** the server answers `400`

#### Scenario: No membership methods
- **WHEN** a developer looks for an add-member method on any SDK's `AdminClient`
- **THEN** no such method exists

### Requirement: Admin pagination and errors
Every `AdminClient` list method SHALL accept an optional `limit` (integer; server-defined default) and an optional `cursor` (opaque continuation string). Its response SHALL be a `PageResponse` envelope with the items and an optional `next_cursor`. An absent or null `next_cursor` means there are no more pages. `AdminClient` errors SHALL use the error taxonomy where it applies. An HTTP 4xx or 5xx answer that the taxonomy does not cover (for example `403 Forbidden` on a missing admin role) SHALL NOT be swallowed. TypeScript raises `HearthError` with `status`, Go returns `*APIError` with `StatusCode`, and Python raises `HearthError` with `status_code`. PHP raises a `RuntimeException` whose message names the HTTP status.

#### Scenario: Last page
- **WHEN** an application lists users with `limit=2`, and follows `next_cursor` until it is absent
- **THEN** it has read every user once, and the last page has no `next_cursor`

#### Scenario: Status on an uncovered error
- **WHEN** an admin call answers `409`
- **THEN** the TypeScript, Go and Python SDKs raise a typed error whose status is `409`, and the PHP SDK raises a `RuntimeException` whose message names HTTP `409`

