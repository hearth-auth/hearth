<?php

declare(strict_types=1);

namespace Hearth\Tests\Unit;

use Hearth\Exceptions\ConfigurationException;
use Hearth\HearthClient;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for HearthClient — OIDC discovery, token exchange, verifyToken.
 *
 * These are stub tests that describe required behaviour. HTTP mocking and
 * full integration scenarios will be added in Phase 3.
 */
final class HearthClientTest extends TestCase
{
    public function testConstructionThrowsOnEmptyIssuerUrl(): void
    {
        $this->expectException(ConfigurationException::class);
        new HearthClient('');
    }

    public function testConstructionThrowsWhenIntrospectionModeHasNoCredentials(): void
    {
        $this->expectException(ConfigurationException::class);
        new HearthClient(
            issuerUrl: 'https://auth.example.com',
            clientId: null,
            clientSecret: null,
            tokenAuthorizationMode: 'introspection',
        );
    }

    public function testConstructionSucceedsWithValidMinimalConfig(): void
    {
        $client = new HearthClient('https://auth.example.com');
        self::assertInstanceOf(HearthClient::class, $client);
    }

    public function testConstructionSucceedsWithIntrospectionModeAndCredentials(): void
    {
        $client = new HearthClient(
            issuerUrl: 'https://auth.example.com',
            clientId: 'my-client',
            clientSecret: 'secret',
            tokenAuthorizationMode: 'introspection',
        );
        self::assertInstanceOf(HearthClient::class, $client);
    }
}
