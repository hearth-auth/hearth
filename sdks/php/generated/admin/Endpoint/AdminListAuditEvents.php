<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminListAuditEvents extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    /**
     * Requires `hearth.realm.admin`. Newest first.
     * @param array{
     *    "actor"?: string,
     *    "action"?: string, //An audit action name, e.g. `UserCreated`.
     *    "start_time"?: int, //Microseconds since the Unix epoch.
     *    "end_time"?: int, //Microseconds since the Unix epoch.
     *    "limit"?: int, //Default 50, at most 200.
     * } $queryParameters
     */
    public function __construct(array $queryParameters = [])
    {
        $this->queryParameters = $queryParameters;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'GET';
    }
    public function getUri(): string
    {
        return '/admin/audit';
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
        $optionsResolver->setDefined(['actor', 'action', 'start_time', 'end_time', 'limit']);
        $optionsResolver->setRequired([]);
        $optionsResolver->setDefaults([]);
        $optionsResolver->addAllowedTypes('actor', ['string']);
        $optionsResolver->addAllowedTypes('action', ['string']);
        $optionsResolver->addAllowedTypes('start_time', ['int']);
        $optionsResolver->addAllowedTypes('end_time', ['int']);
        $optionsResolver->addAllowedTypes('limit', ['int']);
        return $optionsResolver;
    }
    /**
     * {@inheritdoc}
     *
     * @throws \Hearth\Generated\Admin\Exception\AdminListAuditEventsBadRequestException
     *
     * @return null|\Hearth\Generated\Admin\Model\AdminAuditEventList
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (is_null($contentType) === false && (200 === $status && stripos(strtolower($contentType), 'application/json') !== false)) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\AdminAuditEventList', 'json');
        }
        if (400 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminListAuditEventsBadRequestException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}