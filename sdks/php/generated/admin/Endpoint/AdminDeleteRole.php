<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminDeleteRole extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $id;
    /**
     * @param string $id
     * @param array{
     *    "cascade"?: bool, //Also remove the role's assignments, parent links and extra org-role rows. Without it a referenced role answers `409 role_in_use`.
     * } $queryParameters
     */
    public function __construct(string $id, array $queryParameters = [])
    {
        $this->id = $id;
        $this->queryParameters = $queryParameters;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'DELETE';
    }
    public function getUri(): string
    {
        return str_replace(['{id}'], [rawurlencode($this->id)], '/admin/roles/{id}');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        return [[], null];
    }
    protected function getQueryOptionsResolver(): \Symfony\Component\OptionsResolver\OptionsResolver
    {
        $optionsResolver = parent::getQueryOptionsResolver();
        $optionsResolver->setDefined(['cascade']);
        $optionsResolver->setRequired([]);
        $optionsResolver->setDefaults(['cascade' => false]);
        $optionsResolver->addAllowedTypes('cascade', ['bool']);
        return $optionsResolver;
    }
    /**
     * {@inheritdoc}
     *
     * @throws \Hearth\Generated\Admin\Exception\AdminDeleteRoleNotFoundException
     * @throws \Hearth\Generated\Admin\Exception\AdminDeleteRoleConflictException
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
        if (404 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminDeleteRoleNotFoundException($response);
        }
        if (409 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminDeleteRoleConflictException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}