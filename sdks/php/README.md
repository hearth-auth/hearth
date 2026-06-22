# Hearth PHP SDK

Official PHP SDK for [Hearth](https://github.com/hearth-auth/hearth) — a single-binary OIDC identity provider with claims-based RBAC.

**PHP ≥ 8.1 · Laravel 10/11/12 · PSR-7/15/18**

---

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Plain-PHP quickstart](#plain-php-quickstart)
- [Laravel quickstart](#laravel-quickstart)
- [API reference](#api-reference)
- [Troubleshooting](#troubleshooting)

---

## Requirements

| Requirement | Version |
|-------------|---------|
| PHP | ≥ 8.1 |
| `ext-sodium` | bundled with PHP 7.2+ |
| `ext-json` | bundled with PHP 8.x |
| Hearth server | any |

---

## Installation

```bash
composer require hearth-auth/php-sdk
```

For Laravel, also install the framework adapter dependencies (if not already present):

```bash
composer require illuminate/support
```

Laravel 10/11/12 automatically discovers the service provider — no manual registration needed.

---

## Plain-PHP quickstart

> **Goal:** verify a Bearer token and read RBAC claims in ≤ 5 minutes.

### 1. Create the client

```php
use Hearth\HearthClient;

$hearth = new HearthClient(
    issuerUrl: 'https://auth.example.com',  // root URL of your Hearth instance
    clientId:  'my-app',                     // OAuth client ID registered in Hearth
);
```

`HearthClient` performs OIDC discovery lazily — the first call to any method fetches
`/.well-known/openid-configuration` once and caches it for the lifetime of the object.

### 2. Verify a token

```php
use Hearth\Exceptions\TokenExpiredException;
use Hearth\Exceptions\TokenSignatureException;

$rawToken = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$rawToken = ltrim($rawToken, 'Bearer ');

try {
    $claims = $hearth->verifyToken($rawToken);
} catch (TokenExpiredException) {
    http_response_code(401);
    exit('Token expired');
} catch (TokenSignatureException) {
    http_response_code(401);
    exit('Invalid token signature');
}

echo $claims->subject();          // user ID (sub claim)
echo $claims->organizationId();   // B2B org ID (oid claim), or null
```

### 3. Check RBAC claims

```php
if ($claims->hasRole('admin')) {
    // …
}

if ($claims->hasPermission('documents:write')) {
    // …
}

if ($claims->inGroup('engineering')) {
    // …
}
```

### 4. Exchange an authorization code for tokens (server-side OAuth callback)

```php
$tokens = $hearth->exchangeCode(
    code:        $_GET['code'],
    redirectUri: 'https://myapp.example.com/callback',
    codeVerifier: $_SESSION['pkce_verifier'],  // omit for confidential clients without PKCE
);

echo $tokens->accessToken;
echo $tokens->refreshToken;
echo $tokens->expiresIn;    // seconds
```

### 5. Fetch UserInfo

```php
$info = $hearth->getUserInfo($tokens->accessToken);

echo $info->sub;
echo $info->email;
echo $info->name;
```

### 6. Use the PSR-15 middleware

```php
use Hearth\Middleware\HearthMiddleware;
use GuzzleHttp\Psr7\HttpFactory;

$middleware = new HearthMiddleware(
    tokenVerifier: $hearth->getTokenVerifier(),
    responseFactory: new HttpFactory(),
    requireAuth: true,   // false = optional-auth routes
);

// Wire into any PSR-15 compatible dispatcher (Slim, Mezzio, etc.)
$app->add($middleware);
```

The middleware reads the `Authorization: Bearer <token>` header and stores the
verified `Claims` object under the `hearth.claims` request attribute.

### 7. Admin operations

```php
use Hearth\AdminClient;

$admin = new AdminClient(
    baseUrl:     'https://auth.example.com',
    realmId:     'my-realm',
    accessToken: $adminToken,
);

// Users
$user  = $admin->createUser(['email' => 'alice@example.com', 'username' => 'alice']);
$page  = $admin->listUsers(limit: 20);          // returns PageResponse
$admin->updateUser($user['id'], ['username' => 'alice2']);
$admin->deleteUser($user['id']);

// Realms
$realm = $admin->createRealm(['name' => 'acme', 'display_name' => 'Acme Corp']);
$page  = $admin->listRealms();

// OAuth clients
$client = $admin->createClient(['client_id' => 'frontend', 'redirect_uris' => ['https://...']]);

// Roles, groups, org members — same CRUD pattern
$admin->createRole(['name' => 'editor']);
$admin->createGroup(['name' => 'engineering']);
$admin->addOrgMember($orgId, ['user_id' => $userId, 'role' => 'member']);
```

---

## Laravel quickstart

### 1. Publish the config

```bash
php artisan vendor:publish --tag=hearth-config
```

This creates `config/hearth.php`. Alternatively, set environment variables directly.

### 2. Configure `.env`

```dotenv
HEARTH_ISSUER_URL=https://auth.example.com
HEARTH_CLIENT_ID=my-laravel-app
HEARTH_CLIENT_SECRET=          # only required for introspection mode
HEARTH_JWKS_TTL=300            # seconds; omit to use SDK default (300)
HEARTH_HTTP_TIMEOUT=10
HEARTH_TOKEN_AUTHORIZATION_MODE=embedded   # embedded | introspection | decision
HEARTH_REQUIRE_AUTH=true
```

### 3. Protect routes with the `hearth.auth` middleware

The service provider registers the `hearth.auth` alias automatically.

```php
// routes/api.php
Route::middleware('hearth.auth')->group(function () {
    Route::get('/me', [ProfileController::class, 'show']);
});
```

### 4. Access the verified claims

```php
use Hearth\Claims;

class ProfileController extends Controller
{
    public function show(Request $request): JsonResponse
    {
        /** @var Claims $claims */
        $claims = $request->attributes->get('hearth.claims');

        return response()->json([
            'sub'   => $claims->subject(),
            'roles' => $claims->roles(),
            'org'   => $claims->organizationId(),
        ]);
    }
}
```

### 5. Use the facade

```php
use Hearth\Laravel\Facades\Hearth;

$claims = Hearth::verifyToken($rawToken);
$info   = Hearth::getUserInfo($accessToken);
```

### 6. Inject HearthClient directly

```php
use Hearth\HearthClient;

class TokenController extends Controller
{
    public function callback(Request $request, HearthClient $hearth): JsonResponse
    {
        $tokens = $hearth->exchangeCode(
            code:        $request->query('code'),
            redirectUri: route('auth.callback'),
        );

        return response()->json(['access_token' => $tokens->accessToken]);
    }
}
```

---

## API reference

### `HearthClient`

Primary entry point for resource-server and server-side authentication flows.

| Method | Returns | Description |
|--------|---------|-------------|
| `__construct(issuerUrl, clientId?, clientSecret?, jwksTtl?, introspectionEndpoint?, httpTimeout, tokenAuthorizationMode?, httpClient?, requestFactory?, streamFactory?)` | — | Constructs the client. All HTTP calls are lazy. |
| `verifyToken(string $rawToken)` | `Claims` | Verifies signature, expiry, issuer, and audience. Throws typed exceptions on failure. |
| `exchangeCode(string $code, string $redirectUri, ?string $codeVerifier)` | `TokenResponse` | Authorization code → tokens. |
| `getUserInfo(string $accessToken)` | `UserInfoResponse` | Calls the OIDC UserInfo endpoint. |
| `getJwksClient()` | `JwksClient` | Returns the cached JWKS sub-client. |
| `getTokenVerifier()` | `TokenVerifier` | Returns the token verifier sub-client. |
| `getIntrospectionClient()` | `IntrospectionClient` | Returns the introspection sub-client (requires `clientId` + `clientSecret`). |
| `discoverEndpoint(string $key)` | `string` | Resolves an endpoint URL from the OIDC discovery document. |

### `Claims`

Typed accessor for a verified JWT payload.

| Method | Returns | Description |
|--------|---------|-------------|
| `subject()` | `string` | `sub` claim — the user's ID. |
| `issuer()` | `string` | `iss` claim. |
| `audiences()` | `string[]` | `aud` claim, always an array. |
| `expiry()` | `DateTimeImmutable\|null` | `exp` claim. |
| `issuedAt()` | `DateTimeImmutable\|null` | `iat` claim. |
| `jwtID()` | `string` | `jti` claim. |
| `scope()` | `string` | Space-delimited scope string. |
| `scopes()` | `string[]` | Scope list. |
| `hasScope(string)` | `bool` | True if scope is present. |
| `roles()` | `string[]` | Hearth `roles` claim. |
| `hasRole(string)` | `bool` | True if role is present. |
| `permissions()` | `string[]` | Hearth `permissions` claim. |
| `hasPermission(string)` | `bool` | True if permission is present. |
| `groups()` | `string[]` | Hearth `groups` claim. |
| `inGroup(string)` | `bool` | True if group is present. |
| `organizationId()` | `string\|null` | `oid` claim — B2B org ID. |
| `inOrg(string)` | `bool` | True if `oid` matches. |
| `orgGroups()` | `string[]` | `org_groups` claim — org-scoped group paths. |
| `tokenType()` | `string` | `"access"`, `"refresh"`, or `"required_action"`. |
| `get(string)` | `mixed` | Raw claim by name; null if absent. |

### `AdminClient`

Manages Hearth resources with an admin access token. Each instance is scoped to one realm.

Resource groups: **Users**, **Realms**, **OAuth Clients**, **Roles**, **Groups**, **Org Members**.

Each group exposes the same five methods: `create*(array)`, `get*(string)`, `update*(string, array)`, `delete*(string)`, `list*(?int $limit, ?string $cursor)`.

`list*` returns `PageResponse<array>` with `items`, `nextCursor`, and `hasMore`.

### Exception hierarchy

All SDK exceptions extend `Hearth\Exceptions\HearthException`.

| Exception | When thrown |
|-----------|-------------|
| `ConfigurationException` | Missing or invalid constructor arguments |
| `TokenSignatureException` | Ed25519 signature verification failed |
| `TokenExpiredException` | Token `exp` claim is in the past |
| `TokenIssuerException` | `iss` claim does not match `issuerUrl` |
| `TokenAudienceException` | `aud` claim does not contain `clientId` |
| `RequiredActionException` | Token type is `required_action` (e.g. password reset) |
| `JwksException` | JWKS fetch or key-parse failure |
| `IntrospectionException` | Introspection endpoint returned inactive/error |
| `NetworkException` | Outbound HTTP call failed |

---

## Troubleshooting

### `sodium` extension missing

```
PHP Fatal error: Uncaught Error: Call to undefined function sodium_memzero()
```

The `ext-sodium` extension is bundled with PHP 7.2+ but may be disabled in some distributions.

- **Ubuntu/Debian**: `sudo apt install php8.x-common` (sodium is included)
- **Alpine**: `apk add php83-sodium`
- **Docker**: use the official `php:8.x-fpm` image and call `docker-php-ext-enable sodium`
- **Windows**: uncomment `extension=sodium` in `php.ini`

Verify with: `php -m | grep sodium`

### JWKS endpoint unreachable

```
Hearth\Exceptions\JwksException: Failed to fetch JWKS from https://…/.well-known/jwks.json
```

- Confirm `HEARTH_ISSUER_URL` is the root URL (no trailing slash, no path suffix).
- Check that the Hearth server is reachable from the PHP process: `curl https://auth.example.com/.well-known/openid-configuration`
- If running behind a firewall or in Docker, verify DNS resolution and egress rules.
- The SDK caches JWKS for `HEARTH_JWKS_TTL` seconds (default 300). A stale cache after a key rotation clears automatically on the next TTL expiry.

### Clock skew (`TokenExpiredException` for valid tokens)

JWT verification is sensitive to system clock drift. If your PHP host's clock is more than
a few seconds ahead of the Hearth server's clock, tokens will appear expired.

- Sync the PHP host clock with NTP: `timedatectl set-ntp true`
- In Kubernetes, ensure the node clock is synchronized.
- The `lcobucci/jwt` library used internally accepts a small built-in leeway. If you need
  to increase it, inject a custom `TokenVerifier` with an extended `Lcobucci\Clock\SystemClock`
  leeway and pass it to `HearthClient::getTokenVerifier()`.

### `ConfigurationException`: introspection requires client secret

Token authorization mode `"introspection"` requires both `HEARTH_CLIENT_ID` and
`HEARTH_CLIENT_SECRET` to be set. The client must be registered in Hearth as a
**confidential** client.

### Laravel: `hearth.claims` attribute is null

The `hearth.claims` request attribute is set by the `hearth.auth` middleware. Ensure:

1. The route is inside a `Route::middleware('hearth.auth')` group (or has `->middleware('hearth.auth')` applied).
2. The request has a valid `Authorization: Bearer <token>` header.
3. `HEARTH_REQUIRE_AUTH` is `true` — when `false`, unauthenticated requests pass through
   and `hearth.claims` will be null if no token was provided.

---

## Agent Authentication (M5)

Enable `agent_auth.capabilities.identity = true` (and `advanced = true` for AATs + transaction tokens) in `hearth.yaml`. The REST API is identical across all SDKs — use any HTTP client to call the endpoints below with an admin bearer token.

| Feature | Endpoint |
|---------|----------|
| Create agent | `POST /v1/agents` |
| Issue API key | `POST /v1/agents/{id}/credentials/keys` |
| DPoP token | `POST /realms/{id}/token` with `DPoP:` header (RFC 9449) |
| Token exchange | `POST /token` with `grant_type=…token-exchange` (RFC 8693) |
| Issue AAT | `POST /v1/aats` |
| Transaction token | `POST /v1/transaction-tokens` |

For PHP, use OpenSSL's `openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC])` to generate the P-256 key pair for DPoP. For the full flow and draft-tracking table, see the [TypeScript SDK README](../typescript/README.md#agent-authentication-m5).
