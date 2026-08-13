# Changelog

All notable changes to the Hearth PHP SDK will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Removed
- **`AdminClient::createRealm()`** — realms are provisioned via `hearth.yaml` and
  reconciled at startup, not through the admin API. The server returns
  `405 Method Not Allowed` for `POST /admin/realms`, so this method never worked
  against a real server. Manage realms in `hearth.yaml` and restart Hearth to
  apply changes; read them with `getRealm()`/`listRealms()` (HEA-2171).

### Changed

- **§5 error taxonomy** — renamed exceptions to match the SDK Common Specification (HEA-963):
  - `JwksException` → `JWKSFetchException`
  - `TokenSignatureException` → `TokenInvalidException`
- **New exceptions added** — `DiscoveryException` (§5 `DiscoveryError`) and
  `TokenNotYetValidException` (§5 `TokenNotYetValidError`, exposes `getNotBefore()`).

### Added

- **`HearthClient`** — primary SDK entry point for resource-server and server-side
  authentication flows (HEA-954).
  - `verifyToken(string)` → `Claims` — Ed25519 JWT verification via JWKS with configurable
    token authorization modes: `embedded` (default), `introspection`, and `decision`.
  - `exchangeCode(string, string, ?string)` → `TokenResponse` — authorization code exchange
    with optional PKCE code verifier.
  - `getUserInfo(string)` → `UserInfoResponse` — OIDC UserInfo endpoint call.
  - `getJwksClient()`, `getTokenVerifier()`, `getIntrospectionClient()` — lazy sub-client
    accessors.
  - `discoverEndpoint(string)` → `string` — OIDC discovery document resolver (cached).

- **`Claims`** — typed accessor for verified JWT claims (HEA-954).
  - Standard OIDC claims: `subject()`, `issuer()`, `audiences()`, `expiry()`, `issuedAt()`,
    `jwtID()`, `scope()`, `scopes()`, `hasScope(string)`.
  - Hearth RBAC claims: `roles()`, `hasRole(string)`, `permissions()`, `hasPermission(string)`,
    `groups()`, `inGroup(string)`.
  - Organization claims: `organizationId()`, `inOrg(string)`, `orgGroups()`.
  - `tokenType()` — distinguishes `access`, `refresh`, and `required_action` tokens.
  - `get(string)` — raw claim accessor for custom or non-standard claims.

- **`AdminClient`** — admin SDK entry point for managing Hearth resources (HEA-954).
  Scoped per-realm; caller supplies an admin access token.
  - Users: `createUser`, `getUser`, `updateUser`, `deleteUser`, `listUsers`.
  - Realms: `createRealm`, `getRealm`, `updateRealm`, `deleteRealm`, `listRealms`.
  - OAuth clients: `createClient`, `getClient`, `updateClient`, `deleteClient`, `listClients`.
  - Roles: `createRole`, `getRole`, `updateRole`, `deleteRole`, `listRoles`.
  - Groups: `createGroup`, `getGroup`, `updateGroup`, `deleteGroup`, `listGroups`.
  - Org members: `addOrgMember`, `getOrgMember`, `updateOrgMember`, `removeOrgMember`,
    `listOrgMembers`.
  - All list methods return `PageResponse` with cursor-based pagination.

- **`TokenVerifier`** — standalone Ed25519 JWT verifier backed by `JwksClient` (HEA-954).
  Implements `Hearth\Contracts\TokenVerifierInterface`.

- **`JwksClient`** — JWKS fetcher with configurable TTL cache (default 300 s) (HEA-954).
  Implements `Hearth\Contracts\JwksClientInterface`.

- **`IntrospectionClient`** — RFC 7662 token introspection client (HEA-954).
  Returns `IntrospectionResult` with `active`, `sub`, `scope`, `clientId`, and raw claims.

- **PSR-15 middleware** — `Hearth\Middleware\HearthMiddleware` integrates with any PSR-15
  compatible dispatcher (Slim, Mezzio, etc.) (HEA-954). Reads `Authorization: Bearer`
  header; stores `Claims` under the `hearth.claims` request attribute.

- **Laravel integration** (HEA-955):
  - `Hearth\Laravel\HearthServiceProvider` — auto-discovered on Laravel 10/11/12;
    registers a `HearthClient` singleton under the `hearth` abstract and publishes
    `config/hearth.php` via `--tag=hearth-config`.
  - `hearth.auth` middleware alias — route-level token enforcement; honours
    `HEARTH_REQUIRE_AUTH` for optional-auth routes.
  - `Hearth\Laravel\Facades\Hearth` — static facade for `HearthClient`.
  - Config keys: `issuer_url`, `client_id`, `client_secret`, `jwks_ttl`,
    `introspection_endpoint`, `http_timeout`, `token_authorization_mode`, `require_auth`.
  - All keys read from environment variables (`HEARTH_*`) with sane defaults.

- **Type objects** (HEA-954):
  - `TokenResponse` — `accessToken`, `refreshToken`, `idToken`, `tokenType`, `expiresIn`,
    `scope`.
  - `UserInfoResponse` — `sub`, `name`, `email`, `emailVerified`, plus raw `claims()` map.
  - `IntrospectionResult` — `active`, `sub`, `scope`, `clientId`, raw `claims()` map.
  - `PageResponse<T>` — `items`, `nextCursor`, `hasMore` for paginated list endpoints.

- **Exception hierarchy** extending `Hearth\Exceptions\HearthException` (HEA-954):
  `ConfigurationException`, `TokenSignatureException`, `TokenExpiredException`,
  `TokenIssuerException`, `TokenAudienceException`, `RequiredActionException`,
  `JwksException`, `IntrospectionException`, `NetworkException`.

- **Test suite** — 7 unit test classes + 1 integration test class + 1 Laravel service
  provider test, all passing under PHPUnit 10 (HEA-956).
