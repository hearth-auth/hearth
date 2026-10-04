<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminAddAdditionalRole extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $id;
    protected $user_id;
    /**
     * Body: `{role_name}`. The user must be a member (409 otherwise); a sub-admin may only give roles within its own permissions.
     * @param string $id
     * @param string $userId
     * @param null|\Hearth\Generated\Admin\Model\AdminAddAdditionalRoleRequest $requestBody
     */
    public function __construct(string $id, string $userId, ?\Hearth\Generated\Admin\Model\AdminAddAdditionalRoleRequest $requestBody = null)
    {
        $this->id = $id;
        $this->user_id = $userId;
        $this->body = $requestBody;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'POST';
    }
    public function getUri(): string
    {
        return str_replace(['{id}', '{user_id}'], [rawurlencode($this->id), rawurlencode($this->user_id)], '/admin/organizations/{id}/members/{user_id}/roles');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        if ($this->body instanceof \Hearth\Generated\Admin\Model\AdminAddAdditionalRoleRequest) {
            return [['Content-Type' => ['application/json']], \Hearth\Generated\Admin\Runtime\Client\JsonPayload::encode($serializer, $this->body)];
        }
        return [[], null];
    }
    /**
     * {@inheritdoc}
     *
     * @throws \Hearth\Generated\Admin\Exception\AdminAddAdditionalRoleForbiddenException
     * @throws \Hearth\Generated\Admin\Exception\AdminAddAdditionalRoleNotFoundException
     * @throws \Hearth\Generated\Admin\Exception\AdminAddAdditionalRoleConflictException
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
        if (403 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminAddAdditionalRoleForbiddenException($response);
        }
        if (404 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminAddAdditionalRoleNotFoundException($response);
        }
        if (409 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminAddAdditionalRoleConflictException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}