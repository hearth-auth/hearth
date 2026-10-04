<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminAddGroupMember extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $id;
    /**
     * @param string $id
     * @param null|\Hearth\Generated\Admin\Model\AdminAddGroupMemberRequest $requestBody
     */
    public function __construct(string $id, ?\Hearth\Generated\Admin\Model\AdminAddGroupMemberRequest $requestBody = null)
    {
        $this->id = $id;
        $this->body = $requestBody;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'POST';
    }
    public function getUri(): string
    {
        return str_replace(['{id}'], [rawurlencode($this->id)], '/admin/groups/{id}/members');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        if ($this->body instanceof \Hearth\Generated\Admin\Model\AdminAddGroupMemberRequest) {
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
     * @throws \Hearth\Generated\Admin\Exception\AdminAddGroupMemberBadRequestException
     * @throws \Hearth\Generated\Admin\Exception\AdminAddGroupMemberNotFoundException
     *
     * @return null|\Hearth\Generated\Admin\Model\AdminGroupMembership
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (is_null($contentType) === false && (201 === $status && stripos(strtolower($contentType), 'application/json') !== false)) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\AdminGroupMembership', 'json');
        }
        if (400 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminAddGroupMemberBadRequestException($response);
        }
        if (404 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminAddGroupMemberNotFoundException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}