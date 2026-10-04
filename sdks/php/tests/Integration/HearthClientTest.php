<?php

declare(strict_types=1);

namespace Hearth\Tests\Integration;

use Hearth\AdminClient;
use Hearth\Claims;
use Hearth\HearthClient;
use Hearth\Types\IntrospectionResult;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for HearthClient + AdminClient against a live Hearth dev server.
 *
 * These tests require a running `hearth serve --dev` instance (a binary built
 * with the `dev-endpoints` feature). They are skipped automatically when
 * HEARTH_TEST_URL is not set in the environment.
 *
 * Quick start (a FRESH server: only the first bootstrap call is anonymous):
 *   make dev &
 *   HEARTH_TEST_URL=http://127.0.0.1:8420 composer test-integration
 *
 * Against a server that was already bootstrapped, pass the admin access token
 * from that first call as HEARTH_TEST_ADMIN_TOKEN; re-bootstrap then refreshes
 * the tokens instead of answering 401.
 */
#[Group('integration')]
final class HearthClientTest extends TestCase
{
    /**
     * One bootstrap per process: `POST /admin/bootstrap` is anonymous only on
     * its first call, so every test shares the credentials it returned.
     *
     * @var array{realmId: string, token: string, realmName: string}|null
     */
    private static ?array $bootstrapped = null;

    private string $baseUrl;

    /** Admin access token from POST /admin/bootstrap — used for all admin API calls. */
    private string $bootstrapToken;

    /** ID of the dev realm created during bootstrap. */
    private string $realmId;

    /** Base URL of the dev realm: its issuer, discovery document and token endpoint. */
    private string $realmUrl;

    protected function setUp(): void
    {
        $url = getenv('HEARTH_TEST_URL');
        if ($url === false || $url === '') {
            self::markTestSkipped('HEARTH_TEST_URL is not set — skipping integration tests.');
        }

        $this->baseUrl = rtrim($url, '/');

        self::$bootstrapped ??= $this->bootstrap();
        $this->realmId        = self::$bootstrapped['realmId'];
        $this->bootstrapToken = self::$bootstrapped['token'];
        // A realm signs with its own key and issues `iss = {base}/realms/{name}`;
        // the server root is a different issuer with a different JWKS.
        $this->realmUrl = $this->baseUrl . '/realms/' . rawurlencode(self::$bootstrapped['realmName']);
    }

    // -------------------------------------------------------------------------
    // Token verification
    // -------------------------------------------------------------------------

    public function testVerifyTokenReturnsClaimsForValidAccessToken(): void
    {
        [$clientId, $clientSecret] = $this->createOidcClient();

        $accessToken = $this->issueClientCredentialsToken($clientId, $clientSecret);

        // A client_credentials token names no resource, so its aud is the
        // default "hearth" — the audience the client checks when none is set.
        $hearth = new HearthClient(issuerUrl: $this->realmUrl);

        $claims = $hearth->verifyToken($accessToken);

        self::assertInstanceOf(Claims::class, $claims);
        self::assertSame('client_' . $clientId, $claims->subject());
        self::assertSame($this->realmUrl, $claims->issuer());
    }

    // -------------------------------------------------------------------------
    // Token introspection
    // -------------------------------------------------------------------------

    public function testIntrospectReturnsActiveResultForValidToken(): void
    {
        [$clientId, $clientSecret] = $this->createOidcClient();

        $accessToken = $this->issueClientCredentialsToken($clientId, $clientSecret);

        $hearth = new HearthClient(
            issuerUrl: $this->realmUrl,
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

        $email = 'integration-test-' . uniqid() . '@example.com';

        // Create
        $created = $admin->createUser([
            'email'        => $email,
            'display_name' => 'PHP Integration Test',
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
     * Calls POST /admin/bootstrap (dev-mode only) and resolves the dev realm's name.
     *
     * @return array{realmId: string, token: string, realmName: string}
     */
    private function bootstrap(): array
    {
        $headers = "Content-Type: application/json\r\nAccept: application/json\r\n";
        $adminToken = getenv('HEARTH_TEST_ADMIN_TOKEN');
        if ($adminToken !== false && $adminToken !== '') {
            $headers .= "Authorization: Bearer {$adminToken}\r\n";
        }

        $ctx  = stream_context_create(['http' => [
            'method'  => 'POST',
            'header'  => $headers,
            'content' => '{}',
            'ignore_errors' => true,
        ]]);

        $body = file_get_contents($this->baseUrl . '/admin/bootstrap', false, $ctx);
        if ($body === false) {
            self::fail('Could not reach Hearth dev server at ' . $this->baseUrl);
        }

        $data = json_decode($body, true);
        if (!is_array($data) || !isset($data['access_token'], $data['realm_id'])) {
            self::fail(
                'Unexpected bootstrap response: ' . $body
                . ' (an already-bootstrapped server needs HEARTH_TEST_ADMIN_TOKEN)',
            );
        }

        $realmId = (string) $data['realm_id'];
        $token   = (string) $data['access_token'];

        $admin = new AdminClient(baseUrl: $this->baseUrl, realmId: $realmId, accessToken: $token);
        $realm = $admin->getRealm($realmId);
        self::assertArrayHasKey('name', $realm);

        return ['realmId' => $realmId, 'token' => $token, 'realmName' => (string) $realm['name']];
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

        // RFC 7591 registration metadata. The auth method makes the client
        // confidential, so the response carries a client_secret.
        $result = $admin->createClient([
            'client_name'                => 'php-it-' . uniqid(),
            'grant_types'                => ['client_credentials'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ]);

        self::assertArrayHasKey('client_id', $result);
        self::assertArrayHasKey('client_secret', $result);

        return [(string) $result['client_id'], (string) $result['client_secret']];
    }

    /**
     * Issues a client_credentials access token from the realm's token endpoint.
     */
    private function issueClientCredentialsToken(string $clientId, string $clientSecret): string
    {
        $tokenUrl = $this->realmUrl . '/token';
        $body     = http_build_query([
            'grant_type' => 'client_credentials',
            'scope'      => 'openid',
        ]);
        $basic = base64_encode(rawurlencode($clientId) . ':' . rawurlencode($clientSecret));

        $ctx = stream_context_create(['http' => [
            'method'  => 'POST',
            'header'  => "Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n"
                . "Authorization: Basic {$basic}\r\n",
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
