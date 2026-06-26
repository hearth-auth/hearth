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

Use `beginLogin` / `completeLogin` to handle the OAuth callback in two calls:

```php
use Hearth\HearthClient;

session_start();

$hearth = new HearthClient(
    issuerUrl:    'https://hearth.example.com',
    clientId:     '<client_id>',
    clientSecret: '<client_secret>',
);

// Login route — generate PKCE and build the authorization URL
$result = $hearth->beginLogin('https://myapp.example.com/callback', 'openid profile email');
// Persist state + codeVerifier in your session (one line you own)
$_SESSION['oauth_state']   = $result->state;
$_SESSION['code_verifier'] = $result->codeVerifier;
header('Location: ' . $result->authorizationUrl);
exit;
```

```php
// Callback handler — exchange the code for tokens
session_start();

if ($_GET['state'] !== $_SESSION['oauth_state']) {
    http_response_code(400);
    exit('state mismatch');
}

$tokens = $hearth->completeLogin(
    code:         $_GET['code'],
    codeVerifier: $_SESSION['code_verifier'],
    redirectUri:  'https://myapp.example.com/callback',
);
// $tokens->accessToken, $tokens->refreshToken, $tokens->expiresIn
```

:::tip[Where should the access token live?]
If your frontend is a browser SPA, consider the **Backend for Frontend (BFF)** pattern: your PHP server completes the OAuth callback, stores the access and refresh tokens server-side (session or a short-lived store), and issues the browser an `HttpOnly; Secure; SameSite=Strict` session cookie. The browser never receives an OAuth token directly.

This eliminates the XSS risk of browser-side token storage. See [Browser SPA Token Handling](../browser-spa-tokens.md) for a full comparison of storage options and the BFF flow diagram.
:::

## Verify tokens and check RBAC

```php
use Hearth\HearthClient;

$hearth = new HearthClient(
    issuerUrl: 'https://hearth.example.com',
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

## PSR-15 frameworks

### Slim

Slim 4 is PSR-15 native — add `HearthMiddleware` to the application or to a route group:

```php
use GuzzleHttp\Psr7\HttpFactory;
use Hearth\HearthClient;
use Hearth\Middleware\HearthMiddleware;
use Slim\Factory\AppFactory;

$app = AppFactory::create();

$hearth = new HearthClient(
    issuerUrl: 'https://hearth.example.com',
    clientId:  '<client_id>',
);

// Apply globally — all routes require a valid Bearer token
$app->add(new HearthMiddleware(
    tokenVerifier:   $hearth->getTokenVerifier(),
    responseFactory: new HttpFactory(),
));

// Read verified claims inside a route handler
$app->get('/profile', function ($request, $response) {
    $claims = $request->getAttribute(HearthMiddleware::CLAIMS_ATTRIBUTE);
    $data   = ['sub' => $claims->subject(), 'roles' => $claims->roles()];
    $response->getBody()->write(json_encode($data));
    return $response->withHeader('Content-Type', 'application/json');
});

$app->run();
```

To protect only a subset of routes, apply middleware to a route group instead:

```php
$app->group('/api', function ($group) {
    $group->get('/profile', ProfileHandler::class);
    $group->post('/documents', DocumentHandler::class);
})->add(new HearthMiddleware(
    tokenVerifier:   $hearth->getTokenVerifier(),
    responseFactory: new HttpFactory(),
));
```

`HearthMiddleware::CLAIMS_ATTRIBUTE` resolves to the string `'hearth_claims'`.

### Symfony

Symfony uses a `KernelEvents::REQUEST` subscriber. The subscriber extracts the Bearer token, calls `verifyToken()`, and sets the verified `Claims` on the Symfony request attributes under the same `hearth_claims` key.

```php
// src/EventSubscriber/HearthAuthSubscriber.php
namespace App\EventSubscriber;

use Hearth\Claims;
use Hearth\Exceptions\HearthException;
use Hearth\HearthClient;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

final class HearthAuthSubscriber implements EventSubscriberInterface
{
    public function __construct(private readonly HearthClient $hearth) {}

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::REQUEST => ['onKernelRequest', 10]];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $header = (string) $event->getRequest()->headers->get('Authorization', '');
        if (!str_starts_with($header, 'Bearer ')) {
            $event->setResponse(new JsonResponse(
                ['error' => 'unauthorized'],
                401,
                ['WWW-Authenticate' => 'Bearer realm="hearth"'],
            ));
            return;
        }

        try {
            $claims = $this->hearth->verifyToken(substr($header, 7));
            $event->getRequest()->attributes->set('hearth_claims', $claims);
        } catch (HearthException) {
            $event->setResponse(new JsonResponse(['error' => 'unauthorized'], 401));
        }
    }
}
```

Register `HearthClient` and the subscriber in `config/services.yaml`:

```yaml
# config/services.yaml
services:
    hearth.client:
        class: Hearth\HearthClient
        arguments:
            $issuerUrl: '%env(HEARTH_ISSUER_URL)%'
            $clientId:  '%env(HEARTH_CLIENT_ID)%'

    App\EventSubscriber\HearthAuthSubscriber:
        arguments: ['@hearth.client']
        tags: [{ name: kernel.event_subscriber }]
```

```env
# .env
HEARTH_ISSUER_URL=https://hearth.example.com
HEARTH_CLIENT_ID=<client_id>
```

In a controller, read the claims from request attributes:

```php
use Hearth\Claims;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class ProfileController extends AbstractController
{
    public function profile(Request $request): JsonResponse
    {
        /** @var Claims $claims */
        $claims = $request->attributes->get('hearth_claims');
        return $this->json([
            'sub'   => $claims->subject(),
            'roles' => $claims->roles(),
        ]);
    }
}
```

## Laravel

The PHP SDK ships a dedicated Laravel adapter with auto-discovered service provider and a `hearth.auth` middleware alias. See the full guide: [Authenticate a Laravel app with Hearth](./php-laravel.md).

### Quick reference

```bash
# 1. Publish the config
php artisan vendor:publish --tag=hearth-config
```

```env
# 2. Configure .env
HEARTH_ISSUER_URL=https://hearth.example.com
HEARTH_CLIENT_ID=<client_id>
HEARTH_REQUIRE_AUTH=true
```

```php
// 3. Protect routes
Route::middleware('hearth.auth')->group(function () {
    Route::get('/profile', [ProfileController::class, 'show']);
});
```

```php
// 4. Read verified claims in a controller
use Hearth\Claims;

/** @var Claims $claims */
$claims = $request->attributes->get('hearth_claims');

if (!$claims->hasPermission('documents:write')) {
    return response()->json(['error' => 'forbidden'], 403);
}
```

```php
// 5. Facade (for verification outside of middleware)
use Hearth\Laravel\Facades\Hearth;

$claims = Hearth::verifyToken($rawBearerToken);
```

## Error handling

| Exception | When thrown |
|-----------|-------------|
| `TokenExpiredException` | `exp` claim is in the past |
| `TokenInvalidException` | Signature invalid or malformed JWT |
| `TokenIssuerException` | `iss` mismatch |
| `TokenAudienceException` | `aud` mismatch |
| `JWKSFetchException` | JWKS endpoint unreachable |
| `ConfigurationException` | Missing required config |

```php
use Hearth\Exceptions\TokenExpiredException;
use Hearth\Exceptions\TokenInvalidException;

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

**Laravel: `hearth_claims` attribute is `null`** — ensure the route is inside the `hearth.auth` middleware group, or that the middleware is applied before your controller resolves the attribute.

## Next steps

- [Authenticate a Laravel app with Hearth](./php-laravel.md) — full Laravel adapter guide: PKCE login, optional-auth, facades, token modes
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Admin API guide](/docs/admin-api) — managing users and clients programmatically
- [PHP type reference](https://github.com/hearth-auth/hearth/blob/main/sdks/php/README.md) — full API surface
