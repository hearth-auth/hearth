<?php

declare(strict_types=1);

namespace Hearth;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Psr7\HttpFactory;
use Hearth\Exceptions\NetworkException;
use Hearth\Types\PageResponse;
use JsonException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use RuntimeException;
use Throwable;

/**
 * Admin SDK entry point for managing Hearth resources.
 *
 * Conforms to §12 of the Hearth SDK Common Specification.
 *
 * This class is intentionally separate from HearthClient — it performs no OIDC
 * discovery and does not manage token lifecycle. The caller is responsible for
 * providing a valid admin access token.
 *
 * Every request includes:
 *   Authorization: Bearer {access_token}
 *   X-Realm-ID: {realm_id}
 */
final class AdminClient
{
    private readonly ClientInterface $httpClient;
    private readonly RequestFactoryInterface $requestFactory;
    private readonly StreamFactoryInterface $streamFactory;

    /** @var string Base URL without trailing slash */
    private readonly string $baseUrl;

    /**
     * @param string                       $baseUrl        Root URL of the Hearth instance (no trailing slash)
     * @param string                       $realmId        ID of the realm to administer
     * @param string                       $accessToken    A valid admin access token
     * @param ClientInterface|null         $httpClient     Custom PSR-18 HTTP client
     * @param RequestFactoryInterface|null $requestFactory Custom PSR-17 request factory
     * @param StreamFactoryInterface|null  $streamFactory  Custom PSR-17 stream factory
     */
    public function __construct(
        string $baseUrl,
        private readonly string $realmId,
        private readonly string $accessToken,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');

        $factory = new HttpFactory();
        $this->httpClient     = $httpClient     ?? new GuzzleClient(['timeout' => 10]);
        $this->requestFactory = $requestFactory ?? $factory;
        $this->streamFactory  = $streamFactory  ?? $factory;
    }

    // =========================================================================
    // Users
    // =========================================================================

    /**
     * Creates a new user in the administered realm.
     *
     * @param array<string, mixed> $params User attributes (email, username, etc.)
     * @return array<string, mixed>
     */
    public function createUser(array $params): array
    {
        return $this->post('/admin/users', $params);
    }

    /**
     * Retrieves a user by ID.
     *
     * @return array<string, mixed>
     */
    public function getUser(string $id): array
    {
        return $this->get("/admin/users/{$id}");
    }

    /**
     * Updates a user by ID.
     *
     * @param array<string, mixed> $params Fields to update
     * @return array<string, mixed>
     */
    public function updateUser(string $id, array $params): array
    {
        return $this->put("/admin/users/{$id}", $params);
    }

    /** Deletes a user by ID. */
    public function deleteUser(string $id): void
    {
        $this->delete("/admin/users/{$id}");
    }

    /**
     * Lists users with optional cursor-based pagination.
     *
     * @param int|null    $limit  Maximum items per page
     * @param string|null $cursor Opaque continuation cursor from a previous response
     * @return PageResponse<array<string, mixed>>
     */
    public function listUsers(?int $limit = null, ?string $cursor = null): PageResponse
    {
        $data = $this->get('/admin/users', $this->paginationQuery($limit, $cursor));

        return PageResponse::fromArray($data, static fn (mixed $item): array => (array) $item);
    }

    // =========================================================================
    // Realms
    // =========================================================================

    // Realms are provisioned via hearth.yaml, not the admin API. There is no
    // createRealm() method: the server returns 405 for POST /admin/realms
    // (HEA-2171). Only read paths are exposed.

    /**
     * Retrieves a realm by ID.
     *
     * @return array<string, mixed>
     */
    public function getRealm(string $id): array
    {
        return $this->get("/admin/realms/{$id}");
    }

    /**
     * Updates a realm by ID.
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    public function updateRealm(string $id, array $params): array
    {
        return $this->put("/admin/realms/{$id}", $params);
    }

    /** Deletes a realm by ID. */
    public function deleteRealm(string $id): void
    {
        $this->delete("/admin/realms/{$id}");
    }

    /**
     * Lists realms with optional cursor-based pagination.
     *
     * @return PageResponse<array<string, mixed>>
     */
    public function listRealms(?int $limit = null, ?string $cursor = null): PageResponse
    {
        $data = $this->get('/admin/realms', $this->paginationQuery($limit, $cursor));

        return PageResponse::fromArray($data, static fn (mixed $item): array => (array) $item);
    }

    // =========================================================================
    // OAuth Clients
    // =========================================================================

    /**
     * Creates a new OAuth client registration.
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    public function createClient(array $params): array
    {
        return $this->post('/admin/clients', $params);
    }

    /**
     * Retrieves an OAuth client by ID.
     *
     * @return array<string, mixed>
     */
    public function getClient(string $id): array
    {
        return $this->get("/admin/clients/{$id}");
    }

    /**
     * Updates an OAuth client by ID.
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    public function updateClient(string $id, array $params): array
    {
        return $this->put("/admin/clients/{$id}", $params);
    }

    /** Deletes an OAuth client by ID. */
    public function deleteClient(string $id): void
    {
        $this->delete("/admin/clients/{$id}");
    }

    /**
     * Lists OAuth client registrations with optional pagination.
     *
     * @return PageResponse<array<string, mixed>>
     */
    public function listClients(?int $limit = null, ?string $cursor = null): PageResponse
    {
        $data = $this->get('/admin/clients', $this->paginationQuery($limit, $cursor));

        return PageResponse::fromArray($data, static fn (mixed $item): array => (array) $item);
    }

    // =========================================================================
    // Roles
    // =========================================================================

    /**
     * Creates a realm-level role.
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    public function createRole(array $params): array
    {
        return $this->post('/admin/roles', $params);
    }

    /**
     * Retrieves a role by ID.
     *
     * @return array<string, mixed>
     */
    public function getRole(string $id): array
    {
        return $this->get("/admin/roles/{$id}");
    }

    /**
     * Updates a role by ID.
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    public function updateRole(string $id, array $params): array
    {
        return $this->put("/admin/roles/{$id}", $params);
    }

    /** Deletes a role by ID. */
    public function deleteRole(string $id): void
    {
        $this->delete("/admin/roles/{$id}");
    }

    /**
     * Lists roles with optional pagination.
     *
     * @return PageResponse<array<string, mixed>>
     */
    public function listRoles(?int $limit = null, ?string $cursor = null): PageResponse
    {
        $data = $this->get('/admin/roles', $this->paginationQuery($limit, $cursor));

        return PageResponse::fromArray($data, static fn (mixed $item): array => (array) $item);
    }

    // =========================================================================
    // Groups
    // =========================================================================

    /**
     * Creates a realm-level group.
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    public function createGroup(array $params): array
    {
        return $this->post('/admin/groups', $params);
    }

    /**
     * Retrieves a group by ID.
     *
     * @return array<string, mixed>
     */
    public function getGroup(string $id): array
    {
        return $this->get("/admin/groups/{$id}");
    }

    /**
     * Updates a group by ID.
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    public function updateGroup(string $id, array $params): array
    {
        return $this->put("/admin/groups/{$id}", $params);
    }

    /** Deletes a group by ID. */
    public function deleteGroup(string $id): void
    {
        $this->delete("/admin/groups/{$id}");
    }

    /**
     * Lists groups with optional pagination.
     *
     * @return PageResponse<array<string, mixed>>
     */
    public function listGroups(?int $limit = null, ?string $cursor = null): PageResponse
    {
        $data = $this->get('/admin/groups', $this->paginationQuery($limit, $cursor));

        return PageResponse::fromArray($data, static fn (mixed $item): array => (array) $item);
    }

    // =========================================================================
    // Organization Memberships
    // =========================================================================

    /**
     * Adds a member to an organization.
     *
     * @param array<string, mixed> $params (e.g. ['user_id' => '...', 'role' => 'member'])
     * @return array<string, mixed>
     */
    public function addOrgMember(string $orgId, array $params): array
    {
        return $this->post("/admin/orgs/{$orgId}/members", $params);
    }

    /**
     * Retrieves an organization member by user ID.
     *
     * @return array<string, mixed>
     */
    public function getOrgMember(string $orgId, string $userId): array
    {
        return $this->get("/admin/orgs/{$orgId}/members/{$userId}");
    }

    /**
     * Updates an organization member's role.
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    public function updateOrgMember(string $orgId, string $userId, array $params): array
    {
        return $this->put("/admin/orgs/{$orgId}/members/{$userId}", $params);
    }

    /** Removes a member from an organization. */
    public function removeOrgMember(string $orgId, string $userId): void
    {
        $this->delete("/admin/orgs/{$orgId}/members/{$userId}");
    }

    /**
     * Lists organization members with optional pagination.
     *
     * @return PageResponse<array<string, mixed>>
     */
    public function listOrgMembers(string $orgId, ?int $limit = null, ?string $cursor = null): PageResponse
    {
        $data = $this->get("/admin/orgs/{$orgId}/members", $this->paginationQuery($limit, $cursor));

        return PageResponse::fromArray($data, static fn (mixed $item): array => (array) $item);
    }

    // =========================================================================
    // HTTP primitives
    // =========================================================================

    /**
     * Sends a GET request and returns the decoded JSON body.
     *
     * @param array<string, string> $query
     * @return array<string, mixed>
     */
    private function get(string $path, array $query = []): array
    {
        $url = $this->baseUrl . $path;
        if ($query !== []) {
            $url .= '?' . http_build_query($query);
        }

        $request = $this->requestFactory
            ->createRequest('GET', $url)
            ->withHeader('Authorization', "Bearer {$this->accessToken}")
            ->withHeader('X-Realm-ID', $this->realmId)
            ->withHeader('Accept', 'application/json');

        return $this->sendAndDecode($request);
    }

    /**
     * Sends a POST request with a JSON body.
     *
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     */
    private function post(string $path, array $body): array
    {
        $encoded = json_encode($body, JSON_THROW_ON_ERROR);
        $request = $this->requestFactory
            ->createRequest('POST', $this->baseUrl . $path)
            ->withHeader('Authorization', "Bearer {$this->accessToken}")
            ->withHeader('X-Realm-ID', $this->realmId)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream($encoded));

        return $this->sendAndDecode($request);
    }

    /**
     * Sends a PUT request with a JSON body.
     *
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     */
    private function put(string $path, array $body): array
    {
        $encoded = json_encode($body, JSON_THROW_ON_ERROR);
        $request = $this->requestFactory
            ->createRequest('PUT', $this->baseUrl . $path)
            ->withHeader('Authorization', "Bearer {$this->accessToken}")
            ->withHeader('X-Realm-ID', $this->realmId)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream($encoded));

        return $this->sendAndDecode($request);
    }

    /** Sends a DELETE request. */
    private function delete(string $path): void
    {
        $request = $this->requestFactory
            ->createRequest('DELETE', $this->baseUrl . $path)
            ->withHeader('Authorization', "Bearer {$this->accessToken}")
            ->withHeader('X-Realm-ID', $this->realmId);

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new NetworkException($this->baseUrl . $path, $e->getMessage(), 0, $e);
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw new RuntimeException("Admin API returned HTTP {$status} for DELETE {$path}");
        }
    }

    /**
     * Sends a request and JSON-decodes the response body.
     *
     * @return array<string, mixed>
     * @throws NetworkException
     * @throws RuntimeException
     */
    private function sendAndDecode(\Psr\Http\Message\RequestInterface $request): array
    {
        $url = (string) $request->getUri();

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new NetworkException($url, $e->getMessage(), 0, $e);
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw new RuntimeException("Admin API returned HTTP {$status} for {$request->getMethod()} {$url}");
        }

        $body = $response->getBody()->getContents();
        if ($body === '') {
            return [];
        }

        try {
            $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Admin API response is not valid JSON', 0, $e);
        }

        return is_array($data) ? $data : [];
    }

    /**
     * Builds the query string array for paginated list endpoints.
     *
     * @return array<string, string>
     */
    private function paginationQuery(?int $limit, ?string $cursor): array
    {
        $query = [];
        if ($limit !== null) {
            $query['limit'] = (string) $limit;
        }
        if ($cursor !== null) {
            $query['cursor'] = $cursor;
        }

        return $query;
    }
}
