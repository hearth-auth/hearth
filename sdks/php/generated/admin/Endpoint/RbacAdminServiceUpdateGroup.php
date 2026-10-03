<?php

namespace Hearth\Generated\Admin\Endpoint;

class RbacAdminServiceUpdateGroup extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $groupId;
    /**
     * @param string $groupId
     * @param null|\Hearth\Generated\Admin\Model\RbacAdminServiceUpdateGroupBody $requestBody
     */
    public function __construct(string $groupId, ?\Hearth\Generated\Admin\Model\RbacAdminServiceUpdateGroupBody $requestBody = null)
    {
        $this->groupId = $groupId;
        $this->body = $requestBody;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'PATCH';
    }
    public function getUri(): string
    {
        return str_replace(['{groupId}'], [rawurlencode($this->groupId)], '/admin/groups/{groupId}');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        if ($this->body instanceof \Hearth\Generated\Admin\Model\RbacAdminServiceUpdateGroupBody) {
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
     * @return null|\Hearth\Generated\Admin\Model\V1Group|\Hearth\Generated\Admin\Model\RpcStatus
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (is_null($contentType) === false && (200 === $status && stripos(strtolower($contentType), 'application/json') !== false)) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\V1Group', 'json');
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