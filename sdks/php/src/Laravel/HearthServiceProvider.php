<?php

declare(strict_types=1);

namespace Hearth\Laravel;

use GuzzleHttp\Psr7\HttpFactory;
use Hearth\HearthClient;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

/**
 * Laravel service provider for the Hearth PHP SDK.
 *
 * Registers a singleton `HearthClient` bound under the `hearth` abstract,
 * registers the `hearth.auth` middleware alias, and publishes the config
 * file under the `hearth-config` vendor-publish group.
 *
 * Usage in config/app.php (manual registration):
 *   'providers' => [Hearth\Laravel\HearthServiceProvider::class],
 *
 * Or rely on package auto-discovery via the `extra.laravel.providers` key in
 * composer.json — no manual registration needed on Laravel 10/11/12.
 *
 * Publish the config:
 *   php artisan vendor:publish --tag=hearth-config
 */
final class HearthServiceProvider extends ServiceProvider
{
    /**
     * Register SDK bindings into the service container.
     *
     * HearthClient is a singleton — OIDC discovery and JWKS caching happen
     * lazily on first token verification, not at boot time.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/config/hearth.php',
            'hearth',
        );

        $this->app->singleton('hearth', static function (Application $app): HearthClient {
            /** @var array<string, mixed> $config */
            $config = $app['config']['hearth'];

            $jwksTtl = isset($config['jwks_ttl']) ? (int) $config['jwks_ttl'] : null;

            return new HearthClient(
                issuerUrl: (string) ($config['issuer_url'] ?? ''),
                clientId: isset($config['client_id']) ? (string) $config['client_id'] : null,
                clientSecret: isset($config['client_secret']) ? (string) $config['client_secret'] : null,
                jwksTtl: $jwksTtl,
                introspectionEndpoint: isset($config['introspection_endpoint'])
                    ? (string) $config['introspection_endpoint']
                    : null,
                httpTimeout: (int) ($config['http_timeout'] ?? 10),
                tokenAuthorizationMode: isset($config['token_authorization_mode'])
                    ? (string) $config['token_authorization_mode']
                    : null,
            );
        });

        $this->app->alias('hearth', HearthClient::class);

        $this->app->singleton(HearthMiddleware::class, static function (Application $app): HearthMiddleware {
            /** @var HearthClient $client */
            $client = $app->make('hearth');
            /** @var array<string, mixed> $config */
            $config = $app['config']['hearth'];

            $coreMiddleware = new \Hearth\Middleware\HearthMiddleware(
                tokenVerifier: $client->getTokenVerifier(),
                responseFactory: new HttpFactory(),
                requireAuth: (bool) ($config['require_auth'] ?? true),
            );

            return new HearthMiddleware($coreMiddleware);
        });
    }

    /**
     * Boot the service provider.
     *
     * Publishes the config file and registers the `hearth.auth` middleware alias.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/config/hearth.php' => $this->app->configPath('hearth.php'),
        ], 'hearth-config');

        /** @var Router $router */
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('hearth.auth', HearthMiddleware::class);
    }
}
