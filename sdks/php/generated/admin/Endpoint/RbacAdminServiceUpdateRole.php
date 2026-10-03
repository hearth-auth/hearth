<?php

namespace Hearth\Generated\Admin\Endpoint;

class RbacAdminServiceUpdateRole extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $roleId;
    /**
     * @param string $roleId
     * @param null|\Hearth\Generated\Admin\Model\RbacAdminServiceUpdateRoleBody $requestBody
     */
    public function __construct(string $roleId, ?\Hearth\Generated\Admin\Model\RbacAdminServiceUpdateRoleBody $requestBody = null)
    {
        $this->roleId = $roleId;
        $this->body = $requestBody;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'PATCH';
    }
    public function getUri(): string
    {
        return str_replace(['{roleId}'], [rawurlencode($this->roleId)], '/admin/roles/{roleId}');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        if ($this->body instanceof \Hearth\Generated\Admin\Model\RbacAdminServiceUpdateRoleBody) {
            return [['Content-Type' => ['application/json']], \Hearth\Generated\Admin\Runtime\Client\JsonPayload::encode($serializer, $this->body)];
        }
        return [[], null];
    }
    public function getExtraHeaders(): array
    {
        return ['Accept' => ['application/json']];
    }
    /**
     * {@inheritdoc}
     *
     *
     * @return null|\Hearth\Generated\Admin\Model\V1Role|\Hearth\Generated\Admin\Model\RpcStatus
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (is_null($contentType) === false && (200 === $status && stripos(strtolower($contentType), 'application/json') !== false)) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\V1Role', 'json');
        }
        if (stripos(strtolower($contentType), 'application/json') !== false) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\RpcStatus', 'json');
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}