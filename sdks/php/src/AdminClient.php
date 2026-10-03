<?php

declare(strict_types=1);

namespace Hearth;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Psr7\HttpFactory;
use Hearth\Exceptions\NetworkException;
use Hearth\Generated\Admin\Client as GeneratedClient;
use Hearth\Generated\Admin\Endpoint;
use Hearth\Generated\Admin\Model;
use Hearth\Generated\Admin\Normalizer\JaneObjectNormalizer;
use Hearth\Generated\Admin\Runtime\Client\Endpoint as GeneratedEndpoint;
use Hearth\Types\PageResponse;
use Http\Client\Common\Plugin\AddHostPlugin;
use Http\Client\Common\Plugin\AddPathPlugin;
use Http\Client\Common\Plugin\HeaderSetPlugin;
use Http\Client\Common\PluginClient;
use InvalidArgumentException;
use JsonException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use RuntimeException;
use Symfony\Component\Serializer\Encoder\JsonDecode;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\ArrayDenormalizer;
use Symfony\Component\Serializer\Serializer;

/**
 * Admin SDK entry point for managing Hearth resources.
 *
 * Conforms to §12 of the Hearth SDK Common Specification.
 *
 * A thin wrapper over the client generated from `docs/api/openapi.json`
 * (`Hearth\Generated\Admin`, see `gen-admin.sh`): the generated endpoints own
 * the routes, verbs, query options and request-body models. This class keeps
 * the ergonomic method names, the auth headers and the error taxonomy.
 *
 * This class is intentionally separate from HearthClient — it performs no OIDC
 * discovery and does not manage token lifecycle. The caller is responsible for
 * providing a valid admin access token.
 *
 * Every request includes:
 *   Authorization: Bearer {access_token}
 *   X-Realm-ID: {realm_id}
 *
 * Request bodies are arrays keyed by the API's JSON field names. Every body
 * goes through its generated model: snake_case (`display_name`) or camelCase
 * (`displayName`) keys both work, and a key the API does not define throws
 * InvalidArgumentException before any request is sent. Responses are the
 * decoded JSON body, as arrays: Jane's generated parsers model only `200`,
 * and several admin routes answer `201` or `204`.
 */
final class AdminClient
{
    /** `token_endpoint_auth_method`: server-generated secret, sent with HTTP Basic auth. */
    public const AUTH_CLIENT_SECRET_BASIC = 'client_secret_basic';

    /** `token_endpoint_auth_method`: server-generated secret, sent in the request body. */
    public const AUTH_CLIENT_SECRET_POST = 'client_secret_post';

    /** `token_endpoint_auth_method`: `private_key_jwt` (requires `jwks`). */
    public const AUTH_PRIVATE_KEY_JWT = 'private_key_jwt';

    /** `token_endpoint_auth_method`: a public client. */
    public const AUTH_NONE = 'none';

    private readonly GeneratedClient $api;

    private readonly Serializer $serializer;

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
        string $realmId,
        string $accessToken,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');

        $factory = new HttpFactory();
        $base    = $factory->createUri($this->baseUrl);
        $plugins = [
            new AddHostPlugin($base),
            new HeaderSetPlugin([
                'Authorization' => "Bearer {$accessToken}",
                'X-Realm-ID'    => $realmId,
            ]),
        ];
        if ($base->getPath() !== '') {
            $plugins[] = new AddPathPlugin($base);
        }

        $this->serializer = new Serializer(
            [new ArrayDenormalizer(), new JaneObjectNormalizer()],
            [new JsonEncoder(new JsonEncode(), new JsonDecode(['json_decode_associative' => true]))],
        );
        $this->api = new GeneratedClient(
            new PluginClient($httpClient ?? new GuzzleClient(['timeout' => 10]), $plugins),
            $requestFactory ?? $factory,
            $this->serializer,
            $streamFactory ?? $factory,
        );
    }

    // =========================================================================
    // Users
    // =========================================================================

    /**
     * Creates a new user in the administered realm.
     *
     * @param array<string, mixed> $params User attributes (email, display_name, etc.)
     * @return array<string, mixed>
     */
    public function createUser(array $params): array
    {
        return $this->call(new Endpoint\IdentityAdminServiceCreateUser($this->body($params, Model\V1CreateUserRequest::class)));
    }

    /**
     * Retrieves a user by ID.
     *
     * @return array<string, mixed>
     */
    public function getUser(string $id): array
    {
        return $this->call(new Endpoint\IdentityAdminServiceGetUser($id));
    }

    /**
     * Updates a user by ID.
     *
     * @param array<string, mixed> $params Fields to update
     * @return array<string, mixed>
     */
    public function updateUser(string $id, array $params): array
    {
        return $this->call(new Endpoint\IdentityAdminServiceUpdateUser($id, $this->body($params, Model\V1UpdateUserRequest::class)));
    }

    /** Deletes a user by ID. */
    public function deleteUser(string $id): void
    {
        $this->call(new Endpoint\IdentityAdminServiceDeleteUser($id));
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
        return $this->page(new Endpoint\IdentityAdminServiceListUsers($this->paginationQuery($limit, $cursor)));
    }

    // =========================================================================
    // Realms
    // =========================================================================

    // Realms are provisioned via hearth.yaml, not the admin API. There is no
    // createRealm() and no updateRealm() method: the server returns 405 with
    // "Realms are managed via hearth.yaml" for both POST /admin/realms and
    // PATCH /admin/realms/{id} (HEA-2171, audit 2026-08-28 §25.4). Only read
    // paths and deletion are exposed.

    /**
     * Retrieves a realm by ID.
     *
     * @return array<string, mixed>
     */
    public function getRealm(string $id): array
    {
        return $this->call(new Endpoint\IdentityAdminServiceGetRealm($id));
    }

    /** Deletes a realm by ID. */
    public function deleteRealm(string $id): void
    {
        $this->call(new Endpoint\IdentityAdminServiceDeleteRealm($id));
    }

    /**
     * Lists realms with optional cursor-based pagination.
     *
     * @return PageResponse<array<string, mixed>>
     */
    public function listRealms(?int $limit = null, ?string $cursor = null): PageResponse
    {
        return $this->page(new Endpoint\IdentityAdminServiceListRealms($this->paginationQuery($limit, $cursor)));
    }

    // =========================================================================
    // OAuth Clients
    // =========================================================================

    /**
     * Creates a new OAuth client registration (`POST /admin/applications`).
     *
     * `$params` is the proto `RegisterClientRequest` (`client_name`,
     * `redirect_uris`, …). Set `token_endpoint_auth_method` to
     * {@see self::AUTH_CLIENT_SECRET_BASIC} or {@see self::AUTH_CLIENT_SECRET_POST}
     * to create a confidential client: the server generates its secret and
     * returns it once, as `client_secret` in the returned array — store it on
     * receipt, no later read returns it. A caller-chosen `client_secret` is
     * refused (422).
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    public function createClient(array $params): array
    {
        return $this->call(new Endpoint\ApplicationAdminServiceCreateApplication(
            $this->body($params, Model\V1RegisterClientRequest::class),
        ));
    }

    /**
     * Retrieves an OAuth client by ID.
     *
     * @return array<string, mixed>
     */
    public function getClient(string $id): array
    {
        return $this->call(new Endpoint\ApplicationAdminServiceGetApplication($id));
    }

    /**
     * Updates an OAuth client by ID.
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    public function updateClient(string $id, array $params): array
    {
        return $this->call(new Endpoint\ApplicationAdminServiceUpdateApplication(
            $id,
            $this->body($params, Model\V1UpdateClientRequest::class),
        ));
    }

    /**
     * Replaces a confidential client's secret
     * (`POST /admin/applications/{id}/regenerate-secret`).
     *
     * The returned array carries the new `client_secret`, once; the old
     * secret stops working immediately.
     *
     * @return array<string, mixed>
     */
    public function regenerateClientSecret(string $id): array
    {
        return $this->call(new Endpoint\ApplicationAdminServiceRegenerateApplicationSecret($id));
    }

    /** Deletes an OAuth client by ID. */
    public function deleteClient(string $id): void
    {
        $this->call(new Endpoint\ApplicationAdminServiceDeleteApplication($id));
    }

    /**
     * Lists OAuth client registrations with optional pagination.
     *
     * @return PageResponse<array<string, mixed>>
     */
    public function listClients(?int $limit = null, ?string $cursor = null): PageResponse
    {
        return $this->page(new Endpoint\ApplicationAdminServiceListApplications(
            $this->paginationQuery($limit, $cursor),
        ));
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
        return $this->call(new Endpoint\AdminCreateRole($this->body($params, Model\AdminCreateRoleRequest::class)));
    }

    /**
     * Retrieves a role by ID.
     *
     * @return array<string, mixed>
     */
    public function getRole(string $id): array
    {
        return $this->call(new Endpoint\AdminGetRole($id));
    }

    /**
     * Updates a role by ID.
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    public function updateRole(string $id, array $params): array
    {
        return $this->call(new Endpoint\AdminUpdateRole($id, $this->body($params, Model\AdminUpdateRoleRequest::class)));
    }

    /** Deletes a role by ID. */
    public function deleteRole(string $id): void
    {
        $this->call(new Endpoint\AdminDeleteRole($id));
    }

    /**
     * Lists roles with optional pagination.
     *
     * @return PageResponse<array<string, mixed>>
     */
    public function listRoles(?int $limit = null, ?string $cursor = null): PageResponse
    {
        return $this->page(new Endpoint\AdminListRoles($this->paginationQuery($limit, $cursor)));
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
        return $this->call(new Endpoint\AdminCreateGroup($this->body($params, Model\AdminCreateGroupRequest::class)));
    }

    /**
     * Retrieves a group by ID.
     *
     * @return array<string, mixed>
     */
    public function getGroup(string $id): array
    {
        return $this->call(new Endpoint\AdminGetGroup($id));
    }

    /**
     * Updates a group by ID.
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    public function updateGroup(string $id, array $params): array
    {
        return $this->call(new Endpoint\AdminUpdateGroup($id, $this->body($params, Model\AdminUpdateGroupRequest::class)));
    }

    /** Deletes a group by ID. */
    public function deleteGroup(string $id): void
    {
        $this->call(new Endpoint\AdminDeleteGroup($id));
    }

    /**
     * Lists groups with optional pagination.
     *
     * @return PageResponse<array<string, mixed>>
     */
    public function listGroups(?int $limit = null, ?string $cursor = null): PageResponse
    {
        return $this->page(new Endpoint\AdminListGroups($this->paginationQuery($limit, $cursor)));
    }

    // =========================================================================
    // Organizations
    // =========================================================================

    /**
     * Creates an organization (`POST /admin/organizations`).
     *
     * @param array<string, mixed> $params slug, display_name, member_limit, mfa_required, attributes
     * @return array<string, mixed> The created organization
     */
    public function createOrganization(array $params): array
    {
        return $this->call(new Endpoint\AdminCreateOrganization(
            $this->body($params, Model\AdminCreateOrganizationRequest::class),
        ));
    }

    /**
     * Retrieves an organization by ID.
     *
     * @return array<string, mixed>
     */
    public function getOrganization(string $id): array
    {
        return $this->call(new Endpoint\AdminGetOrganization($id));
    }

    /**
     * Updates an organization (`PATCH`). Absent fields keep their value; the
     * slug is immutable.
     *
     * @param array<string, mixed> $params display_name, status (active|suspended), member_limit, mfa_required, attributes
     * @return array<string, mixed> The updated organization
     */
    public function updateOrganization(string $id, array $params): array
    {
        return $this->call(new Endpoint\AdminUpdateOrganization(
            $id,
            $this->body($params, Model\AdminUpdateOrganizationRequest::class),
        ));
    }

    /** Deletes an organization by ID. */
    public function deleteOrganization(string $id): void
    {
        $this->call(new Endpoint\AdminDeleteOrganization($id));
    }

    /**
     * Lists organizations with optional pagination.
     *
     * @return PageResponse<array<string, mixed>>
     */
    public function listOrganizations(?int $limit = null, ?string $cursor = null): PageResponse
    {
        return $this->page(new Endpoint\AdminListOrganizations($this->paginationQuery($limit, $cursor)));
    }

    /**
     * Lists the extra org roles a member holds in an organization.
     *
     * @return list<string> Role names
     */
    public function listOrganizationMemberRoles(string $organizationId, string $userId): array
    {
        $data = $this->call(new Endpoint\AdminListAdditionalRoles($organizationId, $userId));

        return array_values(array_map('strval', (array) ($data['items'] ?? [])));
    }

    /**
     * Gives an organization member an extra org role. The user must already be
     * a member (the server answers 409 otherwise).
     */
    public function addOrganizationMemberRole(string $organizationId, string $userId, string $roleName): void
    {
        $this->call(new Endpoint\AdminAddAdditionalRole(
            $organizationId,
            $userId,
            $this->body(['role_name' => $roleName], Model\AdminAddAdditionalRoleRequest::class),
        ));
    }

    /** Removes an extra org role from an organization member. */
    public function removeOrganizationMemberRole(string $organizationId, string $userId, string $roleName): void
    {
        $this->call(new Endpoint\AdminRemoveAdditionalRole($organizationId, $userId, $roleName));
    }

    // =========================================================================
    // Transport
    // =========================================================================

    /**
     * Sends a generated endpoint and returns the decoded JSON body (`[]` when
     * the body is empty, e.g. a 204).
     *
     * @return array<string, mixed>
     * @throws NetworkException
     * @throws RuntimeException
     */
    private function call(GeneratedEndpoint $endpoint): array
    {
        $url = $this->baseUrl . $endpoint->getUri();

        try {
            $response = $this->api->executeRawEndpoint($endpoint);
        } catch (ClientExceptionInterface $e) {
            throw new NetworkException($url, $e->getMessage(), 0, $e);
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw new RuntimeException("Admin API returned HTTP {$status} for {$endpoint->getMethod()} {$url}");
        }

        return $this->decode($response);
    }

    /**
     * Sends a list endpoint and wraps its `{items, next_cursor}` body.
     *
     * @return PageResponse<array<string, mixed>>
     */
    private function page(GeneratedEndpoint $endpoint): PageResponse
    {
        return PageResponse::fromArray($this->call($endpoint), static fn (mixed $item): array => (array) $item);
    }

    /**
     * @return array<string, mixed>
     * @throws RuntimeException
     */
    private function decode(ResponseInterface $response): array
    {
        $body = (string) $response->getBody();
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
     * Builds the generated request-body model from a caller's array.
     *
     * Accepts each field under its snake_case or camelCase name. Throws on a
     * key the model does not define, so a typo is not silently dropped.
     *
     * @template T of object
     * @param array<string, mixed> $params
     * @param class-string<T>      $model
     * @return T
     * @throws InvalidArgumentException
     */
    private function body(array $params, string $model): object
    {
        // Jane keeps unknown keys as extra properties, so each key is renamed
        // to the one JSON name the model reads before the real denormalize.
        $data = [];
        foreach ($params as $key => $value) {
            $data[$this->fieldName($key, $model)] = $value;
        }

        /** @var T */
        return $this->serializer->denormalize($data, $model, 'json');
    }

    /**
     * Returns the JSON name under which `$model` reads `$key` (as given, or its
     * snake_case or camelCase form).
     *
     * @param class-string $model
     * @throws InvalidArgumentException
     */
    private function fieldName(string $key, string $model): string
    {
        foreach (array_unique([$key, self::snake($key), self::camel($key)]) as $candidate) {
            $probe = $this->serializer->denormalize([$candidate => null], $model, 'json');
            if (is_object($probe) && method_exists($probe, 'isInitialized') && $probe->isInitialized(self::camel($key))) {
                return $candidate;
            }
        }

        $short = substr($model, (int) strrpos($model, '\\') + 1);
        throw new InvalidArgumentException("'{$key}' is not a field of the admin API's {$short}");
    }

    private static function camel(string $key): string
    {
        return lcfirst(str_replace('_', '', ucwords($key, '_')));
    }

    private static function snake(string $key): string
    {
        return strtolower((string) preg_replace('/(?<!^)[A-Z]/', '_$0', $key));
    }

    /**
     * Builds the query options for paginated list endpoints.
     *
     * @return array{limit?: int, cursor?: string}
     */
    private function paginationQuery(?int $limit, ?string $cursor): array
    {
        $query = [];
        if ($limit !== null) {
            $query['limit'] = $limit;
        }
        if ($cursor !== null) {
            $query['cursor'] = $cursor;
        }

        return $query;
    }
}
