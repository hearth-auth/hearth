<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminAssignGroupRole extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $id;
    /**
     * Body: `{role_id, org_id?}`. Same ceiling and org-existence rules as `POST /admin/users/{id}/roles`. Unassign with `DELETE /admin/assignments/{id}`.
     * @param string $id
     */
    public function __construct(string $id)
    {
        $this->id = $id;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'POST';
    }
    public function getUri(): string
    {
        return str_replace(['{id}'], [rawurlencode($this->id)], '/admin/groups/{id}/roles');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        return [[], null];
    }
    /**
     * {@inheritdoc}
     *
     * @throws \Hearth\Generated\Admin\Exception\AdminAssignGroupRoleForbiddenException
     * @throws \Hearth\Generated\Admin\Exception\AdminAssignGroupRoleNotFoundException
     *
     * @return null
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (201 === $status) {
            return null;
        }
        if (403 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminAssignGroupRoleForbiddenException($response);
        }
        if (404 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminAssignGroupRoleNotFoundException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}