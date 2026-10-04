<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminPatchUserRequiredActions extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $realm_id;
    protected $user_id;
    /**
     * @param string $realmId
     * @param string $userId
     * @param null|\stdClass $requestBody
     */
    public function __construct(string $realmId, string $userId, ?\stdClass $requestBody = null)
    {
        $this->realm_id = $realmId;
        $this->user_id = $userId;
        $this->body = $requestBody;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'PATCH';
    }
    public function getUri(): string
    {
        return str_replace(['{realm_id}', '{user_id}'], [rawurlencode($this->realm_id), rawurlencode($this->user_id)], '/admin/realms/{realm_id}/users/{user_id}/required-actions');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        if ($this->body instanceof \stdClass) {
            return [['Content-Type' => ['application/json']], $serializer->serialize($this->body, 'json')];
        }
        return [[], null];
    }
    /**
     * {@inheritdoc}
     *
     *
     * @return null
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (200 === $status) {
            return null;
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}