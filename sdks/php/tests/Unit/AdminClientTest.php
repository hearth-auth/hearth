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
        $this->client->updateClient('c1', ['client_name' => 'New']);
        $this->assertSent('PATCH', '/admin/applications/c1');
        self::assertSame(['client_name' => 'New'], $this->sentJson());
    }

    /**
     * The create/update bodies go through the generated models, which carry
     * the REST field names (snake_case), whichever spelling the caller used.
     */
    public function testRoleAndGroupBodiesUseTheRestFieldNames(): void
    {
        $this->client->updateRole('r1', ['description' => 'New', 'parentRoles' => ['base']]);
        self::assertSame(['description' => 'New', 'parent_roles' => ['base']], $this->sentJson());

        $this->client->createGroup(['name' => 'Ops', 'slug' => 'ops']);
        $this->assertSent('POST', '/admin/groups');
        self::assertSame(['name' => 'Ops', 'slug' => 'ops'], $this->sentJson());
    }

    public function testAKeyTheApiDoesNotDefineIsRefusedBeforeSending(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->client->updateClient('c1', ['name' => 'New']);
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

    // ── Organizations (`/admin/organizations`, typed by the generated models) ──

    /** @return array<string, mixed> */
    private function sentJson(): array
    {
        self::assertNotNull($this->http->lastRequest, 'no request was sent');

        return (array) json_decode((string) $this->http->lastRequest->getBody(), true);
    }

    public function testEveryRequestCarriesBearerAndRealmHeaders(): void
    {
        $this->client->getOrganization('o1');

        self::assertSame('Bearer tok', $this->http->lastRequest?->getHeaderLine('Authorization'));
        self::assertSame('realm_1', $this->http->lastRequest?->getHeaderLine('X-Realm-ID'));
    }

    public function testCreateOrganizationPostsTheTypedBodyAndReturnsTheOrganization(): void
    {
        $this->http->status = 201;
        $this->http->body   = '{"id":"o1","slug":"acme","display_name":"Acme","status":"active",'
            . '"member_limit":null,"mfa_required":true,"attributes":{},"created_at":1,"updated_at":1}';

        $org = $this->client->createOrganization([
            'slug'         => 'acme',
            'display_name' => 'Acme',
            'mfa_required' => true,
        ]);

        $this->assertSent('POST', '/admin/organizations');
        self::assertSame(
            ['slug' => 'acme', 'display_name' => 'Acme', 'mfa_required' => true],
            $this->sentJson(),
        );
        self::assertSame('o1', $org['id']);
        self::assertSame('active', $org['status']);
    }

    public function testOrganizationBodyAcceptsCamelCaseKeys(): void
    {
        $this->client->createOrganization(['slug' => 'acme', 'displayName' => 'Acme']);

        self::assertSame(['slug' => 'acme', 'display_name' => 'Acme'], $this->sentJson());
    }

    public function testOrganizationBodyRefusesAnUnknownKeyBeforeSending(): void
    {
        try {
            $this->client->updateOrganization('o1', ['dispaly_name' => 'typo']);
            self::fail('an unknown key must be refused');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('dispaly_name', $e->getMessage());
        }
        self::assertNull($this->http->lastRequest, 'nothing may be sent for a refused body');
    }

    public function testUpdateOrganizationSendsPatch(): void
    {
        $this->client->updateOrganization('o1', ['status' => 'suspended']);

        $this->assertSent('PATCH', '/admin/organizations/o1');
        self::assertSame(['status' => 'suspended'], $this->sentJson());
    }

    public function testDeleteOrganizationSendsDelete(): void
    {
        $this->http->status = 204;
        $this->http->body   = '';

        $this->client->deleteOrganization('o1');

        $this->assertSent('DELETE', '/admin/organizations/o1');
    }

    public function testListOrganizationsPaginates(): void
    {
        $this->http->body = '{"items":[{"id":"o1"},{"id":"o2"}],"next_cursor":"2"}';

        $page = $this->client->listOrganizations(limit: 2, cursor: '0');

        $uri = $this->http->lastRequest?->getUri();
        self::assertSame('/admin/organizations', $uri?->getPath());
        parse_str((string) $uri?->getQuery(), $query);
        self::assertSame(['limit' => '2', 'cursor' => '0'], $query);
        self::assertSame(['o1', 'o2'], array_column($page->items, 'id'));
        self::assertSame('2', $page->nextCursor);
    }

    public function testListOrganizationMemberRolesReturnsRoleNames(): void
    {
        $this->http->body = '{"items":["billing","support"]}';

        $roles = $this->client->listOrganizationMemberRoles('o1', 'u1');

        $this->assertSent('GET', '/admin/organizations/o1/members/u1/roles');
        self::assertSame(['billing', 'support'], $roles);
    }

    public function testAddOrganizationMemberRolePostsTheRoleName(): void
    {
        $this->http->status = 204;
        $this->http->body   = '';

        $this->client->addOrganizationMemberRole('o1', 'u1', 'billing');

        $this->assertSent('POST', '/admin/organizations/o1/members/u1/roles');
        self::assertSame(['role_name' => 'billing'], $this->sentJson());
    }

    public function testRemoveOrganizationMemberRoleSendsDelete(): void
    {
        $this->http->status = 204;
        $this->http->body   = '';

        $this->client->removeOrganizationMemberRole('o1', 'u1', 'billing');

        $this->assertSent('DELETE', '/admin/organizations/o1/members/u1/roles/billing');
    }

    // ── Error taxonomy and raw bodies ───────────────────────────────────────

    public function testNon2xxRaisesRuntimeExceptionNamingTheRoute(): void
    {
        $this->http->status = 404;
        $this->http->body   = '{"error":"organization not found"}';

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('HTTP 404 for GET https://auth.example.com/admin/organizations/missing');

        $this->client->getOrganization('missing');
    }

    public function testNonOrganizationBodiesAreSentAsGiven(): void
    {
        // The proto-derived request models for users do not yet match the REST
        // JSON, so the caller's keys go on the wire unchanged.
        $this->client->createUser(['email' => 'a@example.com', 'display_name' => 'A']);

        $this->assertSent('POST', '/admin/users');
        self::assertSame(['email' => 'a@example.com', 'display_name' => 'A'], $this->sentJson());
    }
}
