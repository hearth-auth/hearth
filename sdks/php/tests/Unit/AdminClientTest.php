<?php

declare(strict_types=1);

namespace Hearth\Tests\Unit;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Hearth\AdminClient;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A PSR-18 client that records the request it was handed and replies `{}`.
 */
final class RecordingHttpClient implements ClientInterface
{
    public ?RequestInterface $lastRequest = null;

    public int $status = 200;

    public string $body = '{}';

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->lastRequest = $request;

        return new Response($this->status, ['Content-Type' => 'application/json'], $this->body);
    }
}

/**
 * Wire-contract tests for AdminClient.
 *
 * Hearth implements every admin mutation as `PATCH`. Sending `PUT` gets a bare
 * 405 from axum's method router — no body, no error code — so an SDK that
 * sends the wrong verb fails at runtime with nothing an integrator can act on
 * (audit 2026-08-28 §25.4).
 */
final class AdminClientTest extends TestCase
{
    private RecordingHttpClient $http;

    private AdminClient $client;

    protected function setUp(): void
    {
        $this->http = new RecordingHttpClient();
        $factory    = new HttpFactory();
        $this->client = new AdminClient(
            baseUrl: 'https://auth.example.com',
            realmId: 'realm_1',
            accessToken: 'tok',
            httpClient: $this->http,
            requestFactory: $factory,
            streamFactory: $factory,
        );
    }

    private function assertSent(string $method, string $path): void
    {
        self::assertNotNull($this->http->lastRequest, 'no request was sent');
        self::assertSame($method, $this->http->lastRequest->getMethod());
        self::assertSame(
            'https://auth.example.com' . $path,
            (string) $this->http->lastRequest->getUri(),
        );
    }

    public function testUpdateUserSendsPatch(): void
    {
        $this->client->updateUser('u1', ['display_name' => 'New']);
        $this->assertSent('PATCH', '/admin/users/u1');
    }

    public function testCreateClientRequestsAndReturnsAGeneratedSecret(): void
    {
        // `token_endpoint_auth_method` asks the server to generate the secret;
        // the 201 create response carries it once, as `client_secret`.
        $this->http->status = 201;
        $this->http->body   = '{"client_id":"c1","client_name":"svc","is_confidential":true,'
            . '"client_secret":"generated-once"}';

        $created = $this->client->createClient([
            'client_name'                => 'svc',
            'redirect_uris'              => ['https://svc.example.com/cb'],
            'token_endpoint_auth_method' => AdminClient::AUTH_CLIENT_SECRET_BASIC,
        ]);

        $this->assertSent('POST', '/admin/applications');
        $sent = json_decode((string) $this->http->lastRequest?->getBody(), true);
        self::assertSame('client_secret_basic', $sent['token_endpoint_auth_method']);
        self::assertSame('generated-once', $created['client_secret']);
    }

    public function testRegenerateClientSecretPostsAndReturnsTheNewSecret(): void
    {
        $this->http->body = '{"client_id":"c1","client_secret":"new-secret"}';

        $result = $this->client->regenerateClientSecret('c1');

        $this->assertSent('POST', '/admin/applications/c1/regenerate-secret');
        self::assertSame('new-secret', $result['client_secret']);
    }

    public function testUpdateClientSendsPatchToApplications(): void
    {
        $this->client->updateClient('c1', ['name' => 'New']);
        $this->assertSent('PATCH', '/admin/applications/c1');
    }

    public function testUpdateRoleSendsPatch(): void
    {
        $this->client->updateRole('r1', ['description' => 'New']);
        $this->assertSent('PATCH', '/admin/roles/r1');
    }

    public function testUpdateGroupSendsPatch(): void
    {
        $this->client->updateGroup('g1', ['name' => 'New']);
        $this->assertSent('PATCH', '/admin/groups/g1');
    }

    /**
     * Realms are provisioned from `hearth.yaml`. `POST /admin/realms` and
     * `PATCH /admin/realms/{id}` both answer 405 with "Realms are managed via
     * hearth.yaml", so no verb makes `updateRealm()` work and the SDK must not
     * offer it at all.
     */
    public function testUpdateRealmIsNotOffered(): void
    {
        self::assertFalse(
            method_exists(AdminClient::class, 'updateRealm'),
            'updateRealm() cannot succeed against any Hearth server — the route 405s',
        );
        self::assertFalse(
            method_exists(AdminClient::class, 'createRealm'),
            'createRealm() cannot succeed against any Hearth server — the route 405s',
        );
    }
    /**
     * Hearth serves no organization route over HTTP at all. There is no
     * `/admin/orgs`, no `/admin/orgs/{id}/members` and no per-member route
     * anywhere in the router, so every one of these methods 404'd. There is
     * nothing to repoint them at (audit 2026-08-28 §25.19).
     */
    public function testOrgMembershipMethodsAreNotOffered(): void
    {
        foreach (
            ['addOrgMember', 'getOrgMember', 'updateOrgMember', 'removeOrgMember', 'listOrgMembers']
            as $dead
        ) {
            self::assertFalse(
                method_exists(AdminClient::class, $dead),
                "{$dead}() cannot succeed against any Hearth server — /admin/orgs is not a route",
            );
        }
    }
}
