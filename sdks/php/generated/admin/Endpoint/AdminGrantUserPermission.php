<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminGrantUserPermission extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $id;
    /**
     * Body: `{permission, org_id?}`. A sub-admin may grant only a permission it holds; `granted_by` is the caller.
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
        return str_replace(['{id}'], [rawurlencode($this->id)], '/admin/users/{id}/permissions');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        return [[], null];
    }
    /**
     * {@inheritdoc}
     *
     * @throws \Hearth\Generated\Admin\Exception\AdminGrantUserPermissionForbiddenException
     * @throws \Hearth\Generated\Admin\Exception\AdminGrantUserPermissionNotFoundException
     *
     * @return null
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (201 === $status) {
            return null;
        }
        if (403 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminGrantUserPermissionForbiddenException($response);
        }
        if (404 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminGrantUserPermissionNotFoundException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}