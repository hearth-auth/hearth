<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminListAdditionalRoles extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $id;
    protected $user_id;
    /**
     * @param string $id
     * @param string $userId
     */
    public function __construct(string $id, string $userId)
    {
        $this->id = $id;
        $this->user_id = $userId;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'GET';
    }
    public function getUri(): string
    {
        return str_replace(['{id}', '{user_id}'], [rawurlencode($this->id), rawurlencode($this->user_id)], '/admin/organizations/{id}/members/{user_id}/roles');
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
     *
     * @return null|\Hearth\Generated\Admin\Model\AdminRoleNameList
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (is_null($contentType) === false && (200 === $status && stripos(strtolower($contentType), 'application/json') !== false)) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\AdminRoleNameList', 'json');
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}