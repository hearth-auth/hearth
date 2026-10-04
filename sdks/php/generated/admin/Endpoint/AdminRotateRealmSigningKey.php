<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminRotateRealmSigningKey extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $id;
    /**
     * Publishes a new signing key and revokes every retired key for the realm. Tokens signed with the old key stop validating immediately, which is what makes this a usable remedy for a leaked key. A planned rotation may opt into a grace window with `grace_period_secs`; do not use it after a compromise, because the window protects whoever holds the leaked key too.
     * @param string $id
     * @param array{
     *    "grace_period_secs"?: int, //Seconds the retired key stays valid. Omit, or pass 0, to revoke it immediately. A value that is not a non-negative integer is rejected with 400.
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
        return 'POST';
    }
    public function getUri(): string
    {
        return str_replace(['{id}'], [rawurlencode($this->id)], '/admin/realms/{id}/rotate-signing-key');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        return [[], null];
    }
    protected function getQueryOptionsResolver(): \Symfony\Component\OptionsResolver\OptionsResolver
    {
        $optionsResolver = parent::getQueryOptionsResolver();
        $optionsResolver->setDefined(['grace_period_secs']);
        $optionsResolver->setRequired([]);
        $optionsResolver->setDefaults(['grace_period_secs' => 0]);
        $optionsResolver->addAllowedTypes('grace_period_secs', ['int']);
        return $optionsResolver;
    }
    /**
     * {@inheritdoc}
     *
     * @throws \Hearth\Generated\Admin\Exception\AdminRotateRealmSigningKeyBadRequestException
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
        if (400 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminRotateRealmSigningKeyBadRequestException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}