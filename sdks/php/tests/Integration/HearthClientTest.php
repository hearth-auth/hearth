<?php

declare(strict_types=1);

namespace Hearth\Tests\Integration;

use Hearth\AdminClient;
use Hearth\Claims;
use Hearth\HearthClient;
use Hearth\Types\IntrospectionResult;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for HearthClient + AdminClient against a live Hearth dev server.
 *
 * @group integration
 *
 * These tests require a running `hearth serve --dev` instance. They are skipped
 * automatically when HEARTH_TEST_URL is not set in the environment.
 *
 * Quick start:
 *   make dev &
 *   HEARTH_TEST_URL=http://127.0.0.1:8420 vendor/bin/phpunit --group integration
 */
final class HearthClientTest extends TestCase
{
    private string $baseUrl;

    /** Bootstrap token from POST /admin/bootstrap — used for all admin API calls. */
    private string $bootstrapToken;

    /** Realm ID created during bootstrap. */
    private string $realmId;

    protected function setUp(): void
    {
        $url = getenv('HEARTH_TEST_URL');
        if ($url === false || $url === '') {
            self::markTestSkipped('HEARTH_TEST_URL is not set — skipping integration tests.');
        }

        $this->baseUrl = rtrim($url, '/');

        [$this->realmId, $this->bootstrapToken] = $this->bootstrap();
    }

    // -------------------------------------------------------------------------
    // Token verification
    // -------------------------------------------------------------------------

    public function testVerifyTokenReturnsClaimsForValidAccessToken(): void
    {
        [$clientId, $clientSecret] = $this->createOidcClient();

        $accessToken = $this->issueClientCredentialsToken($clientId, $clientSecret);

        $hearth = new HearthClient(
            issuerUrl: $this->baseUrl,
            clientId: $clientId,
        );

        $claims = $hearth->verifyToken($accessToken);

        self::assertInstanceOf(Claims::class, $claims);
        self::assertNotEmpty($claims->subject());
        self::assertSame($this->baseUrl, $claims->issuer());
    }

    // -------------------------------------------------------------------------
    // Token introspection
    // -------------------------------------------------------------------------

    public function testIntrospectReturnsActiveResultForValidToken(): void
    {
        [$clientId, $clientSecret] = $this->createOidcClient();

        $accessToken = $this->issueClientCredentialsToken($clientId, $clientSecret);

        $hearth = new HearthClient(
            issuerUrl: $this->baseUrl,
            clientId: $clientId,
            clientSecret: $clientSecret,
        );

        $result = $hearth->getIntrospectionClient()->introspect($accessToken);

        self::assertInstanceOf(IntrospectionResult::class, $result);
        self::assertTrue($result->active);
        self::assertNotEmpty($result->sub);
    }

    // -------------------------------------------------------------------------
    // Admin CRUD — Users
    // -------------------------------------------------------------------------

    public function testAdminCreateListAndDeleteUser(): void
    {
        $admin = new AdminClient(
            baseUrl: $this->baseUrl,
            realmId: $this->realmId,
            accessToken: $this->bootstrapToken,
        );

        $email    = 'integration-test-' . uniqid() . '@example.com';
        $username = 'itest-' . uniqid();

        // Create
        $created = $admin->createUser([
            'email'    => $email,
            'username' => $username,
        ]);
        self::assertArrayHasKey('id', $created);
        self::assertSame($email, $created['email'] ?? null);
        $userId = (string) $created['id'];

        // List — user should appear
        $page = $admin->listUsers();
        $ids  = array_column($page->items, 'id');
        self::assertContains($userId, $ids);

        // Delete
        $admin->deleteUser($userId);

        // Verify gone — listing again should not include it
        $pageAfter = $admin->listUsers();
        $idsAfter  = array_column($pageAfter->items, 'id');
        self::assertNotContains($userId, $idsAfter);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Calls POST /admin/bootstrap (dev-mode only) and returns [realmId, token].
     *
     * @return array{string, string}
     */
    private function bootstrap(): array
    {
        $ctx  = stream_context_create(['http' => [
            'method'  => 'POST',
            'header'  => "Content-Type: application/json\r\nAccept: application/json\r\n",
            'content' => '{}',
            'ignore_errors' => true,
        ]]);

        $body = file_get_contents($this->baseUrl . '/admin/bootstrap', false, $ctx);
        if ($body === false) {
            self::fail('Could not reach Hearth dev server at ' . $this->baseUrl);
        }

        $data = json_decode($body, true);
        if (!is_array($data) || !isset($data['access_token'], $data['realm_id'])) {
            self::fail('Unexpected bootstrap response: ' . $body);
        }

        return [(string) $data['realm_id'], (string) $data['access_token']];
    }

    /**
     * Creates a confidential OAuth client via the Admin API and returns [clientId, clientSecret].
     *
     * @return array{string, string}
     */
    private function createOidcClient(): array
    {
        $admin = new AdminClient(
            baseUrl: $this->baseUrl,
            realmId: $this->realmId,
            accessToken: $this->bootstrapToken,
        );

        $name   = 'test-client-' . uniqid();
        $result = $admin->createClient([
            'name'          => $name,
            'client_type'   => 'confidential',
            'grant_types'   => ['client_credentials'],
        ]);

        self::assertArrayHasKey('client_id', $result);
        self::assertArrayHasKey('client_secret', $result);

        return [(string) $result['client_id'], (string) $result['client_secret']];
    }

    /**
     * Issues a client_credentials access token from the OIDC token endpoint.
     */
    private function issueClientCredentialsToken(string $clientId, string $clientSecret): string
    {
        $tokenUrl = $this->baseUrl . '/oauth/token';
        $body     = http_build_query([
            'grant_type'    => 'client_credentials',
            'client_id'     => $clientId,
            'client_secret' => $clientSecret,
            'scope'         => 'openid',
        ]);

        $ctx = stream_context_create(['http' => [
            'method'  => 'POST',
            'header'  => "Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n",
            'content' => $body,
            'ignore_errors' => true,
        ]]);

        $raw = file_get_contents($tokenUrl, false, $ctx);
        if ($raw === false) {
            self::fail("Could not reach token endpoint {$tokenUrl}");
        }

        $data = json_decode($raw, true);
        if (!is_array($data) || !isset($data['access_token'])) {
            self::fail("Token endpoint did not return access_token. Got: {$raw}");
        }

        return (string) $data['access_token'];
    }
}
