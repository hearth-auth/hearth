<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminCreateRole extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    /**
     * @param null|\Hearth\Generated\Admin\Model\AdminCreateRoleRequest $requestBody
     */
    public function __construct(?\Hearth\Generated\Admin\Model\AdminCreateRoleRequest $requestBody = null)
    {
        $this->body = $requestBody;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'POST';
    }
    public function getUri(): string
    {
        return '/admin/roles';
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        if ($this->body instanceof \Hearth\Generated\Admin\Model\AdminCreateRoleRequest) {
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
     * @throws \Hearth\Generated\Admin\Exception\AdminCreateRoleBadRequestException
     * @throws \Hearth\Generated\Admin\Exception\AdminCreateRoleConflictException
     *
     * @return null|\Hearth\Generated\Admin\Model\AdminRole
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (is_null($contentType) === false && (201 === $status && stripos(strtolower($contentType), 'application/json') !== false)) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\AdminRole', 'json');
        }
        if (400 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminCreateRoleBadRequestException($response);
        }
        if (409 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminCreateRoleConflictException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}