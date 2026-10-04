<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminCreateGroup extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    /**
     * @param null|\Hearth\Generated\Admin\Model\AdminCreateGroupRequest $requestBody
     */
    public function __construct(?\Hearth\Generated\Admin\Model\AdminCreateGroupRequest $requestBody = null)
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
        return '/admin/groups';
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        if ($this->body instanceof \Hearth\Generated\Admin\Model\AdminCreateGroupRequest) {
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
     * @throws \Hearth\Generated\Admin\Exception\AdminCreateGroupConflictException
     *
     * @return null|\Hearth\Generated\Admin\Model\AdminGroup
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (is_null($contentType) === false && (201 === $status && stripos(strtolower($contentType), 'application/json') !== false)) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\AdminGroup', 'json');
        }
        if (409 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminCreateGroupConflictException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}