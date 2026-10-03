<?php

namespace Hearth\Generated\Admin\Endpoint;

class IdentityAdminServiceSuspendRealm extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $id;
    /**
     * Every token of the realm stops validating, its sessions are revoked and no new session starts until the realm is reinstated. Caller must be a system-realm admin (`hearth.realm.admin` or `hearth.admin`, with `X-Realm-ID` set to the system realm); the target realm's cross-realm trust policy applies. The system realm cannot be suspended. Audited in the target realm with the actor and old/new status. YAML reconciliation never clears a suspension.
     * @param string $id
     */
    public function __construct(string $id)
    {
        $this->id = $id;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'POST';
    }
    public function getUri(): string
    {
        return str_replace(['{id}'], [rawurlencode($this->id)], '/admin/realms/{id}/suspend');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        return [[], null];
    }
    public function getExtraHeaders(): array
    {
        return ['Accept' => ['application/json']];
    }
    /**
     * {@inheritdoc}
     *
     * @throws \Hearth\Generated\Admin\Exception\IdentityAdminServiceSuspendRealmForbiddenException
     * @throws \Hearth\Generated\Admin\Exception\IdentityAdminServiceSuspendRealmNotFoundException
     * @throws \Hearth\Generated\Admin\Exception\IdentityAdminServiceSuspendRealmConflictException
     *
     * @return null|\Hearth\Generated\Admin\Model\V1Realm
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (is_null($contentType) === false && (200 === $status && stripos(strtolower($contentType), 'application/json') !== false)) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\V1Realm', 'json');
        }
        if (403 === $status) {
            throw new \Hearth\Generated\Admin\Exception\IdentityAdminServiceSuspendRealmForbiddenException($response);
        }
        if (404 === $status) {
            throw new \Hearth\Generated\Admin\Exception\IdentityAdminServiceSuspendRealmNotFoundException($response);
        }
        if (409 === $status) {
            throw new \Hearth\Generated\Admin\Exception\IdentityAdminServiceSuspendRealmConflictException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}