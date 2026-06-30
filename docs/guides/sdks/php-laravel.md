---
title: Authenticate a Laravel app with Hearth
sidebar_label: Laravel
description: >
  Protect Laravel routes with Hearth tokens using the dedicated Laravel adapter.
  Covers service-provider setup, hearth.auth middleware, claims access, PKCE login, and optional-auth routes.
---

# Authenticate a Laravel app with Hearth

This guide is for **Laravel 10/11/12 developers** who want to protect routes and controllers with Hearth tokens. The `hearth-auth/php-sdk` package ships a dedicated Laravel adapter with auto-discovered service provider, the `hearth.auth` middleware alias, and a facade for direct token verification.

## Requirements

- Laravel 10, 11, or 12
- PHP 8.1+
- `sodium` extension (enabled by default in most PHP distributions; verify with `php -m | grep sodium`)

## Install

```bash
composer require hearth-auth/php-sdk:^1.0
```

Laravel 10/11/12 auto-discovers `Hearth\Laravel\HearthServiceProvider` via the `extra.laravel.providers` key in `composer.json` — no manual `config/app.php` entry needed.

## Publish the config

```bash
php artisan vendor:publish --tag=hearth-config
```

This writes `config/hearth.php` with all available configuration keys and their defaults.

## Configure `.env`

```env
HEARTH_ISSUER_URL=https://hearth.example.com
HEARTH_CLIENT_ID=<client_id>
# Only required for M2M (client_credentials) or introspection mode:
# HEARTH_CLIENT_SECRET=<client_secret>
HEARTH_JWKS_TTL=3600
HEARTH_REQUIRE_AUTH=true
```

All keys map directly to `config/hearth.php`:

| `.env` variable | Config key | Default | Purpose |
|---|---|---|---|
| `HEARTH_ISSUER_URL` | `issuer_url` | `""` | Root URL of the Hearth instance |
| `HEARTH_CLIENT_ID` | `client_id` | `null` | OAuth client ID for audience validation |
| `HEARTH_CLIENT_SECRET` | `client_secret` | `null` | Required for M2M flows or introspection mode |
| `HEARTH_JWKS_TTL` | `jwks_ttl` | `300` | JWKS key cache lifetime in seconds |
| `HEARTH_REQUIRE_AUTH` | `require_auth` | `true` | Return 401 when no Bearer token is present |
| `HEARTH_TOKEN_AUTHORIZATION_MODE` | `token_authorization_mode` | `"embedded"` | Token validation strategy |

## Protect routes

Apply the `hearth.auth` middleware to any route or group in `routes/api.php` or `routes/web.php`:

```php
// routes/api.php
use App\Http\Controllers\DocumentController;
use App\Http\Controllers\ProfileController;
use Illuminate\Support\Facades\Route;

Route::middleware('hearth.auth')->group(function () {
    Route::get('/profile', [ProfileController::class, 'show']);
    Route::post('/documents', [DocumentController::class, 'create']);
});
```

`hearth.auth` reads `Authorization: Bearer <token>`, verifies the JWT against Hearth's JWKS endpoint (Ed25519), and either forwards the request — with verified `Claims` attached — or returns `401 Unauthorized` with `WWW-Authenticate: Bearer realm="hearth"`.

## Read verified claims in a controller

Verified claims are attached to the request under the attribute key `hearth_claims`:

```php
// app/Http/Controllers/ProfileController.php
use Hearth\Claims;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function show(Request $request): JsonResponse
    {
        /** @var Claims $claims */
        $claims = $request->attributes->get('hearth_claims');

        return response()->json([
            'sub'    => $claims->subject(),
            'scopes' => $claims->scopes(),
            'roles'  => $claims->roles(),
        ]);
    }
}
```

## Check permissions and roles

`Claims` reads JWT payload claims in-process — zero network calls needed:

```php
public function create(Request $request): JsonResponse
{
    /** @var Claims $claims */
    $claims = $request->attributes->get('hearth_claims');

    if (!$claims->hasPermission('documents:write')) {
        return response()->json(['error' => 'forbidden'], 403);
    }

    // ... create the document
    return response()->json(['created' => true], 201);
}
```

| Method | Checks JWT claim | Returns |
|---|---|---|
| `$claims->subject()` | `sub` | `string` |
| `$claims->hasRole('admin')` | `roles` | `bool` |
| `$claims->hasPermission('docs:write')` | `permissions` | `bool` |
| `$claims->inGroup('engineering')` | `groups` | `bool` |
| `$claims->hasScope('openid')` | `scope` | `bool` |
| `$claims->organizationId()` | `oid` | `?string` |
| `$claims->tokenType()` | `token_type` | `string` |

## Facade and service-container injection

Use the `Hearth` facade or inject `HearthClient` directly for verification outside of request middleware (e.g. console commands, queued jobs):

```php
use Hearth\Laravel\Facades\Hearth;

// Facade — resolves the HearthClient singleton from the service container
$claims = Hearth::verifyToken($rawBearerToken);
```

Or inject `HearthClient` via the constructor:

```php
use Hearth\HearthClient;
use Illuminate\Console\Command;

class VerifyTokenCommand extends Command
{
    protected $signature = 'hearth:verify {token}';

    public function __construct(private readonly HearthClient $hearth)
    {
        parent::__construct();
    }

    public function handle(): void
    {
        $claims = $this->hearth->verifyToken($this->argument('token'));
        $this->info('Subject: ' . $claims->subject());
    }
}
```

## Optional-auth routes

To allow unauthenticated requests through (public + authenticated access on the same route), set `HEARTH_REQUIRE_AUTH=false` and check for `null` claims in the controller:

```env
# .env
HEARTH_REQUIRE_AUTH=false
```

```php
// app/Http/Controllers/FeedController.php
public function index(Request $request): JsonResponse
{
    /** @var \Hearth\Claims|null $claims */
    $claims = $request->attributes->get('hearth_claims');

    if ($claims === null) {
        // Unauthenticated — return public content only
        return response()->json(['items' => $this->publicItems()]);
    }

    // Authenticated — return personalized content
    return response()->json(['items' => $this->personalizedItems($claims->subject())]);
}
```

## OAuth login flow with PKCE

For a full web login (users authenticate via Hearth's authorization server), add two routes and a controller:

```php
// routes/web.php
Route::get('/login', [AuthController::class, 'login'])->name('auth.login');
Route::get('/auth/callback', [AuthController::class, 'callback'])->name('auth.callback');
```

```php
// app/Http/Controllers/AuthController.php
use Hearth\HearthClient;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function __construct(private readonly HearthClient $hearth) {}

    public function login(): RedirectResponse
    {
        $result = $this->hearth->beginLogin(
            redirectUri: route('auth.callback'),
            scopes:      'openid profile email',
        );
        // Persist PKCE values server-side in the Laravel session (HttpOnly cookie)
        session([
            'oauth_state'   => $result->state,
            'code_verifier' => $result->codeVerifier,
        ]);
        return redirect($result->authorizationUrl);
    }

    public function callback(Request $request): RedirectResponse
    {
        if ($request->query('state') !== session('oauth_state')) {
            abort(400, 'OAuth state mismatch');
        }

        $tokens = $this->hearth->completeLogin(
            code:         $request->query('code'),
            codeVerifier: session('code_verifier'),
            redirectUri:  route('auth.callback'),
        );

        // Store the access token in the Laravel session — never expose it to the browser
        session(['access_token' => $tokens->accessToken]);
        session()->forget(['oauth_state', 'code_verifier']);

        return redirect('/dashboard');
    }
}
```

:::tip[Token storage: server-side only]
Store the access token in the Laravel session (backed by an `HttpOnly` cookie). Never store tokens in `localStorage` or `sessionStorage` — JavaScript-accessible storage is vulnerable to XSS. Laravel's session uses `HttpOnly; Secure; SameSite=Lax` cookies by default.
:::

## Token authorization modes

`HEARTH_TOKEN_AUTHORIZATION_MODE` controls how the middleware validates tokens:

| Mode | Value | Requires `client_secret` | Description |
|------|-------|--------------------------|-------------|
| JWKS-only (default) | `embedded` | No | Verifies token signature locally via JWKS; no network call per request |
| JWKS + introspection | `introspection` | Yes | Adds an introspection call per request; enables immediate revocation |
| JWKS, authz deferred | `decision` | No | Verifies the token; caller decides authorization separately |

## Error handling

The `hearth.auth` middleware returns `401` automatically on verification failure. For manual verification (facade or injected client), catch specific exceptions:

```php
use Hearth\Exceptions\ConfigurationException;
use Hearth\Exceptions\JWKSFetchException;
use Hearth\Exceptions\TokenAudienceException;
use Hearth\Exceptions\TokenExpiredException;
use Hearth\Exceptions\TokenInvalidException;
use Hearth\Exceptions\TokenIssuerException;

try {
    $claims = $this->hearth->verifyToken($rawToken);
} catch (TokenExpiredException) {
    return response()->json(['error' => 'token_expired'], 401);
} catch (TokenInvalidException) {
    return response()->json(['error' => 'invalid_token'], 401);
} catch (TokenIssuerException) {
    return response()->json(['error' => 'invalid_issuer'], 401);
} catch (TokenAudienceException) {
    return response()->json(['error' => 'invalid_audience'], 401);
} catch (JWKSFetchException $e) {
    report($e);
    return response()->json(['error' => 'service_unavailable'], 503);
} catch (ConfigurationException $e) {
    report($e);
    return response()->json(['error' => 'server_error'], 500);
}
```

| Exception | Cause |
|-----------|-------|
| `TokenExpiredException` | `exp` claim is in the past |
| `TokenInvalidException` | Signature invalid or malformed JWT |
| `TokenIssuerException` | `iss` does not match `HEARTH_ISSUER_URL` |
| `TokenAudienceException` | `aud` does not match `HEARTH_CLIENT_ID` |
| `JWKSFetchException` | JWKS endpoint unreachable or returned invalid data |
| `ConfigurationException` | Missing required config key (e.g. `HEARTH_ISSUER_URL` empty) |

## Troubleshooting

**`hearth_claims` attribute is `null` in a protected controller** — confirm the route is inside `Route::middleware('hearth.auth')`. The attribute is set only on successful verification; it is `null` when `HEARTH_REQUIRE_AUTH=false` and no token is present.

**`ConfigurationException: introspection requires client secret`** — set `HEARTH_CLIENT_SECRET` in `.env` or change `HEARTH_TOKEN_AUTHORIZATION_MODE` back to `embedded`.

**JWKS endpoint unreachable** — verify `HEARTH_ISSUER_URL` is reachable from your PHP process (not just your browser). Check firewall rules and ensure Hearth is running.

**`sodium` extension missing** — run `php -m | grep sodium`. Enable `extension=sodium` in `php.ini` or install `php8.x-sodium`.

## Next steps

- [PHP SDK quickstart](./php.md) — raw PHP, Slim, and Symfony adapter patterns
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [PHP type reference](https://github.com/hearth-auth/hearth/blob/main/sdks/php/README.md) — full SDK API surface
