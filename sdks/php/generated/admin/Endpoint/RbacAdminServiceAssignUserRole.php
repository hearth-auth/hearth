<?php

namespace Hearth\Generated\Admin\Endpoint;

class RbacAdminServiceAssignUserRole extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $userId;
    /**
     * @param string $userId
     * @param null|\Hearth\Generated\Admin\Model\RbacAdminServiceAssignUserRoleBody $requestBody
     */
    public function __construct(string $userId, ?\Hearth\Generated\Admin\Model\RbacAdminServiceAssignUserRoleBody $requestBody = null)
    {
        $this->userId = $userId;
        $this->body = $requestBody;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'POST';
    }
    public function getUri(): string
    {
        return str_replace(['{userId}'], [rawurlencode($this->userId)], '/admin/users/{userId}/roles');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        if ($this->body instanceof \Hearth\Generated\Admin\Model\RbacAdminServiceAssignUserRoleBody) {
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
     * @return null|\Hearth\Generated\Admin\Model\V1RoleAssignment|\Hearth\Generated\Admin\Model\RpcStatus
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (is_null($contentType) === false && (200 === $status && stripos(strtolower($contentType), 'application/json') !== false)) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\V1RoleAssignment', 'json');
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