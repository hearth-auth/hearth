<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminRemoveAdditionalRole extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $id;
    protected $user_id;
    protected $role_name;
    /**
     * Checked against the admin privilege ceiling.
     * @param string $id
     * @param string $userId
     * @param string $roleName
     */
    public function __construct(string $id, string $userId, string $roleName)
    {
        $this->id = $id;
        $this->user_id = $userId;
        $this->role_name = $roleName;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'DELETE';
    }
    public function getUri(): string
    {
        return str_replace(['{id}', '{user_id}', '{role_name}'], [rawurlencode($this->id), rawurlencode($this->user_id), rawurlencode($this->role_name)], '/admin/organizations/{id}/members/{user_id}/roles/{role_name}');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
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
        if (204 === $status) {
            return null;
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}