<?php

namespace Hearth\Generated\Admin\Endpoint;

class RbacAdminServiceGetRole extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $roleId;
    /**
     * @param string $roleId
     * @param array{
     *    "realmId"?: string,
     * } $queryParameters
     */
    public function __construct(string $roleId, array $queryParameters = [])
    {
        $this->roleId = $roleId;
        $this->queryParameters = $queryParameters;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'GET';
    }
    public function getUri(): string
    {
        return str_replace(['{roleId}'], [rawurlencode($this->roleId)], '/admin/roles/{roleId}');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        return [[], null];
    }
    public function getExtraHeaders(): array
    {
        return ['Accept' => ['application/json']];
    }
    protected function getQueryOptionsResolver(): \Symfony\Component\OptionsResolver\OptionsResolver
    {
        $optionsResolver = parent::getQueryOptionsResolver();
        $optionsResolver->setDefined(['realmId']);
        $optionsResolver->setRequired([]);
        $optionsResolver->setDefaults([]);
        $optionsResolver->addAllowedTypes('realmId', ['string']);
        return $optionsResolver;
    }
    /**
     * {@inheritdoc}
     *
     *
     * @return null|\Hearth\Generated\Admin\Model\V1Role|\Hearth\Generated\Admin\Model\RpcStatus
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (is_null($contentType) === false && (200 === $status && stripos(strtolower($contentType), 'application/json') !== false)) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\V1Role', 'json');
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