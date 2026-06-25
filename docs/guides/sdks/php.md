---
title: PHP SDK quickstart
sidebar_label: PHP
description: Verify Hearth tokens and enforce RBAC in a PHP app. Covers plain-PHP, Laravel, PSR-15 middleware, and the OAuth callback with PKCE.
---

# PHP SDK quickstart

Add token verification and permission checks to a PHP app using `hearth-auth/php-sdk`.

## Requirements

- PHP 8.1+
- `sodium` extension (enabled by default in most PHP distributions; verify with `php -m | grep sodium`)
- Laravel 10, 11, or 12 (optional — automatic service-provider discovery included)

## Install

```bash
composer require hearth-auth/php-sdk:^1.0
```

For Laravel, the `illuminate/support` package is required (already present in any Laravel project):

```bash
composer require illuminate/support  # only if not using a full Laravel install
```

Laravel 10/11/12 auto-discovers the service provider — no manual registration needed.

## Auth code flow with PKCE

### Step 1 — Build the authorization URL

Generate a PKCE verifier and challenge, store them in the session, then redirect:

```php
session_start();

$verifier  = bin2hex(random_bytes(32));
$challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
$state     = bin2hex(random_bytes(16)); // CSRF token

$_SESSION['pkce_verifier'] = $verifier;
$_SESSION['oauth_state']   = $state;

$params = http_build_query([
    'response_type'         => 'code',
    'client_id'             => '<client_id>',
    'redirect_uri'          => 'https://myapp.example.com/callback',
    'scope'                 => 'openid profile email',
    'state'                 => $state,
    'code_challenge'        => $challenge,
    'code_challenge_method' => 'S256',
]);

header("Location: https://hearth.example.com/realms/<realm_id>/authorize?{$params}");
exit;
```

### Step 2 — Exchange the code (callback handler)

```php
use HearthAuth\HearthClient;

$hearth = new HearthClient(
    issuerUrl: 'https://hearth.example.com',
    realmId:   '<realm_id>',
    clientId:  '<client_id>',
);

// Verify state before proceeding
if ($_GET['state'] !== $_SESSION['oauth_state']) {
    http_response_code(400);
    exit('State mismatch');
}

$tokens = $hearth->exchangeCode(
    code:         $_GET['code'],
    redirectUri:  'https://myapp.example.com/callback',
    codeVerifier: $_SESSION['pkce_verifier'],
);

// $tokens->accessToken, $tokens->refreshToken, $tokens->expiresIn
```

## Verify tokens and check RBAC

```php
use HearthAuth\HearthClient;

$hearth = new HearthClient(
    issuerUrl: 'https://hearth.example.com',
    realmId:   '<realm_id>',
    clientId:  '<client_id>',
);

$bearerToken = str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION'] ?? '');

$claims = $hearth->verifyToken($bearerToken);

// RBAC — synchronous, zero-network (reads embedded JWT claims)
if ($claims->hasRole('admin')) {
    // …
}

if ($claims->hasPermission('documents:write')) {
    // …
}

if ($claims->inGroup('engineering')) {
    // …
}

// UserInfo — network call, returns scope-filtered OIDC claims
$userInfo = $hearth->getUserInfo($tokens->accessToken);
// $userInfo->sub, $userInfo->name, $userInfo->email
```

## Machine-to-machine (client credentials)

For service-to-service calls where your server authenticates as its own principal:

```php
$hearth = new HearthClient(
    issuerUrl:    'https://hearth.example.com',
    realmId:      '<realm_id>',
    clientId:     '<service-client-id>',
    clientSecret: '<service-client-secret>',
);

$tokens = $hearth->clientCredentials('read:reports');
// $tokens->accessToken, $tokens->expiresIn
```

## Device authorization flow

For CLI tools or headless processes that need interactive user approval:

```php
$resp = $hearth->startDeviceFlow('openid');
echo "Visit {$resp->verificationUri}\nEnter code: {$resp->userCode}\n";

// Poll until the user approves (or the device code expires)
$tokens = null;
$interval = $resp->interval;
while (true) {
    sleep($interval);
    try {
        $tokens = $hearth->pollDeviceToken($resp->deviceCode, $interval);
        if ($tokens !== null) {
            break; // approved
        }
    } catch (TokenExpiredException $e) {
        throw new RuntimeException('device code expired before user approved');
    }
}
```

`pollDeviceToken` returns `null` on `authorization_pending` (continue polling)
and throws `TokenExpiredException` on `expired_token`.

## Magic-link (passwordless) initiation

```php
$hearth->requestMagicLink('user@example.com');
// Always succeeds — server returns 202 whether or not the email is registered
// (enumeration resistance). HTTP 429 throws RateLimitException.
```

## PSR-15 middleware (plain PHP)

```php
use HearthAuth\HearthClient;
use HearthAuth\Middleware\RequirePermission;

$hearth = new HearthClient(/* … */);

$middleware = new RequirePermission(
    client:     $hearth,
    permission: 'documents:write',
);

// Use with any PSR-15 compatible framework (Slim, Mezzio, etc.)
$app->add($middleware);
```

## Laravel quickstart

### 1. Publish the config

```bash
php artisan vendor:publish --tag=hearth-config
```

### 2. Configure `.env`

```env
HEARTH_ISSUER_URL=https://hearth.example.com
HEARTH_REALM_ID=<realm_id>
HEARTH_CLIENT_ID=<client_id>
HEARTH_CLIENT_SECRET=<client_secret>
HEARTH_JWKS_TTL=3600
HEARTH_REQUIRE_AUTH=true
```

### 3. Protect routes

```php
// routes/api.php
Route::middleware('hearth.auth')->group(function () {
    Route::get('/profile', [ProfileController::class, 'show']);
});

// Require a specific permission on a route
Route::post('/docs', [DocsController::class, 'create'])
     ->middleware('hearth.auth:documents.write');
```

### 4. Access verified claims

```php
// In a controller, access claims from the request attribute:
public function show(Request $request): JsonResponse
{
    $claims = $request->attributes->get('hearth.claims');

    return response()->json([
        'sub'  => $claims->sub,
        'roles' => $claims->roles,
    ]);
}
```

### 5. Facade and injection

```php
use HearthAuth\Laravel\Facades\Hearth;

// Facade
$claims = Hearth::verifyToken($bearerToken);

// Or inject HearthClient directly
public function __construct(private HearthClient $hearth) {}
```

## Error handling

| Exception | When thrown |
|-----------|-------------|
| `TokenExpiredException` | `exp` claim is in the past |
| `TokenInvalidException` | Signature invalid or malformed JWT |
| `TokenIssuerException` | `iss` mismatch |
| `TokenAudienceException` | `aud` mismatch |
| `JWKSException` | JWKS endpoint unreachable |
| `ConfigurationException` | Missing required config |

```php
use HearthAuth\Exceptions\TokenExpiredException;
use HearthAuth\Exceptions\TokenInvalidException;

try {
    $claims = $hearth->verifyToken($bearerToken);
} catch (TokenExpiredException $e) {
    http_response_code(401);
    echo json_encode(['error' => 'token_expired']);
    exit;
} catch (TokenInvalidException $e) {
    http_response_code(401);
    echo json_encode(['error' => 'invalid_token']);
    exit;
}
```

## Troubleshooting

**`sodium` extension missing** — run `php -m | grep sodium`. If absent, enable `extension=sodium` in `php.ini` or install `php8.x-sodium`.

**JWKS endpoint unreachable** — verify `HEARTH_ISSUER_URL` is reachable from your PHP process. Check firewall rules and that Hearth is running.

**`TokenExpiredException` for tokens that appear valid** — likely clock skew. Set `HEARTH_CLOCK_SKEW=30` (seconds) to allow tolerance, or synchronize server clocks with NTP.

**`ConfigurationException: introspection requires client secret`** — add `HEARTH_CLIENT_SECRET` to `.env` when using introspection or decision mode.

**Laravel: `hearth.claims` attribute is null** — ensure the route is inside the `hearth.auth` middleware group, or that the middleware is applied before your controller resolves the attribute.

## Next steps

- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Admin API guide](/docs/admin-api) — managing users and clients programmatically
- [PHP type reference](https://github.com/hearth-auth/hearth/blob/main/sdks/php/README.md) — full API surface
