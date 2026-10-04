<?php

namespace Hearth\Generated\Admin\Endpoint;

class IdentityAdminServiceUnsuspendRealm extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $id;
    /**
     * Restores a suspended realm to active. Same gate as suspend. An archived realm is not revived (409): only reappearing in hearth.yaml does that.
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
        return str_replace(['{id}'], [rawurlencode($this->id)], '/admin/realms/{id}/unsuspend');
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
     * @throws \Hearth\Generated\Admin\Exception\IdentityAdminServiceUnsuspendRealmForbiddenException
     * @throws \Hearth\Generated\Admin\Exception\IdentityAdminServiceUnsuspendRealmNotFoundException
     * @throws \Hearth\Generated\Admin\Exception\IdentityAdminServiceUnsuspendRealmConflictException
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
            throw new \Hearth\Generated\Admin\Exception\IdentityAdminServiceUnsuspendRealmForbiddenException($response);
        }
        if (404 === $status) {
            throw new \Hearth\Generated\Admin\Exception\IdentityAdminServiceUnsuspendRealmNotFoundException($response);
        }
        if (409 === $status) {
            throw new \Hearth\Generated\Admin\Exception\IdentityAdminServiceUnsuspendRealmConflictException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}