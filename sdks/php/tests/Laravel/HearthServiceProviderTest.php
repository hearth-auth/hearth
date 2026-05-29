<?php

declare(strict_types=1);

namespace Hearth\Tests\Laravel;

use Hearth\HearthClient;
use Hearth\Laravel\Facades\Hearth;
use Hearth\Laravel\HearthMiddleware;
use Hearth\Laravel\HearthServiceProvider;
use Orchestra\Testbench\TestCase;

/**
 * Boots the HearthServiceProvider in an isolated Laravel kernel and asserts
 * that all container bindings and middleware aliases are correctly registered.
 *
 * These tests do NOT make real network calls — the HearthClient singleton is
 * only resolved to verify it is an instance of the correct class; OIDC
 * discovery is deferred until the first token verification attempt.
 */
final class HearthServiceProviderTest extends TestCase
{
    /**
     * Register the package service provider under test.
     *
     * @param \Illuminate\Foundation\Application $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    protected function getPackageProviders($app): array
    {
        return [HearthServiceProvider::class];
    }

    /**
     * Set a valid issuer URL so HearthClient construction does not throw.
     *
     * @param \Illuminate\Foundation\Application $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('hearth.issuer_url', 'https://hearth.example.test');
    }

    public function testHearth_abstractIsBound(): void
    {
        $this->assertTrue($this->app->bound('hearth'));
    }

    public function testHearth_resolvedClientIsHearthClientInstance(): void
    {
        $client = $this->app->make('hearth');
        $this->assertInstanceOf(HearthClient::class, $client);
    }

    public function testHearth_clientAliasResolvesToSameInstance(): void
    {
        $this->assertTrue($this->app->bound(HearthClient::class));
        $viaAbstract = $this->app->make('hearth');
        $viaClass    = $this->app->make(HearthClient::class);
        $this->assertSame($viaAbstract, $viaClass);
    }

    public function testHearth_clientIsSingleton(): void
    {
        $a = $this->app->make('hearth');
        $b = $this->app->make('hearth');
        $this->assertSame($a, $b);
    }

    public function testHearth_authMiddlewareAliasRegistered(): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router     = $this->app->make('router');
        $middleware = $router->getMiddleware();

        $this->assertArrayHasKey('hearth.auth', $middleware);
        $this->assertSame(HearthMiddleware::class, $middleware['hearth.auth']);
    }

    public function testHearth_configPublishPathExists(): void
    {
        $paths = HearthServiceProvider::pathsToPublish(HearthServiceProvider::class, 'hearth-config');

        $this->assertNotEmpty($paths, 'hearth-config publish group must not be empty');

        foreach (array_keys($paths) as $sourcePath) {
            $this->assertFileExists($sourcePath, "Published source file {$sourcePath} must exist on disk");
        }
    }

    public function testHearth_configMergedWithDefaults(): void
    {
        /** @var array<string, mixed> $config */
        $config = $this->app['config']['hearth'];

        $this->assertArrayHasKey('issuer_url', $config);
        $this->assertArrayHasKey('require_auth', $config);
        $this->assertSame('https://hearth.example.test', $config['issuer_url']);
    }

    public function testHearth_facadeResolvesHearthClient(): void
    {
        $this->assertInstanceOf(HearthClient::class, Hearth::getFacadeRoot());
    }
}
