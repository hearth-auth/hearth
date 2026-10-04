## MODIFIED Requirements

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

#### Scenario: Regression — Go client without a timeout
- **WHEN** a Go client built with `hearth.NewClient(baseURL, realmID)` makes a call, and the server never answers
- **THEN** the call fails after 10 s

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

#### Scenario: Regression — Go and Python ignore the discovered token endpoint
- **WHEN** the discovery document advertises a `token_endpoint` that differs from the path the SDK would build, and the Go or Python SDK requests a client-credentials token
- **THEN** the SDK posts to the advertised `token_endpoint`

#### Scenario: Regression — Go guesses the JWKS path
- **WHEN** the Go SDK's discovery request fails, and the application calls `VerifyToken`
- **THEN** the SDK returns `*DiscoveryError`, and requests no `/.well-known/jwks.json`

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

#### Scenario: Regression — unreachable JWKS in TypeScript and PHP
- **WHEN** the TypeScript or PHP SDK verifies a token, and the JWKS endpoint refuses the connection
- **THEN** the SDK throws `JWKSFetchError` (PHP `JWKSFetchException`), not a raw fetch error or `NetworkException`

### Requirement: Decision-mode permission check
Every SDK SHALL expose a decision check that posts to `POST /oauth/authorize` with the token as a bearer credential and the `permission` (plus optional `organization_id` and `resource`) in the body. The check SHALL fail closed: a network error, a 4xx or a 5xx answer is a deny. The result differs per SDK: TypeScript `authorize()` returns a `boolean`; Go `CheckPermission` returns a `*CheckPermissionResponse` and Python `check_permission` a `CheckPermissionResponse`, each with `allowed: false` on a failure; PHP `checkDecision()` returns the decision payload. The TypeScript check requires `realmId` in the client configuration.

#### Scenario: Server error denies
- **WHEN** `POST /oauth/authorize` answers `500`
- **THEN** the decision check reports a deny, and throws nothing

#### Scenario: Allowed
- **WHEN** the decision endpoint answers that the token holder has the permission
- **THEN** the decision check reports the permission as allowed

#### Scenario: Regression — PHP decision check misses the decision endpoint
- **WHEN** a PHP application calls `checkDecision($accessToken, ['permission' => 'docs.edit'])`, and the decision endpoint answers `500`
- **THEN** the SDK posts to `POST /oauth/authorize`, not to the discovered `authorization_endpoint`, and reports a deny without throwing

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

#### Scenario: Regression — Go sends JSON to the token endpoint
- **WHEN** the Go SDK calls `ClientCredentials`
- **THEN** the request body is `application/x-www-form-urlencoded`

#### Scenario: Regression — Go sends X-Realm-ID to the token endpoint
- **WHEN** the Go client is built with a realm UUID, and calls `ClientCredentials`
- **THEN** the token request carries no `X-Realm-ID` header

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

#### Scenario: Regression — Python device authorization path
- **WHEN** the Python SDK calls `start_device_flow()` against a live Hearth realm
- **THEN** it posts to the discovered `device_authorization_endpoint` (`{issuer}/device_authorization`), and gets a `DeviceAuthorizationResponse`, not a `404`

#### Scenario: Regression — Go device flow sends JSON
- **WHEN** the Go SDK calls `StartDeviceFlow` or `PollDeviceToken`
- **THEN** the request body is `application/x-www-form-urlencoded`

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

#### Scenario: Regression — Go middleware without a token
- **WHEN** a request without an `Authorization` header reaches Go `RequirePermission`
- **THEN** it answers `401` with `WWW-Authenticate: Bearer realm="hearth"`, not `403`

#### Scenario: Regression — Go middleware hides the claims
- **WHEN** a request with a valid token passes Go `RequirePermission` in embedded mode
- **THEN** the handler can read the verified claims from the request context

#### Scenario: Regression — Python middleware without a token
- **WHEN** a request without an `Authorization` header, or with an invalid token, reaches `RequirePermissionMiddleware` or `WsgiPermissionMiddleware`
- **THEN** it answers `401` with `WWW-Authenticate: Bearer realm="hearth"`, not `403`

