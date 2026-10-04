<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminCreateOrganization extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    /**
     * Requires `hearth.realm.admin`. Body: `{slug, display_name, member_limit?, mfa_required?, attributes?}`. `mfa_required` (default `false`) makes members need MFA even where the realm does not; it can only tighten. Refused in the system realm.
     * @param null|\Hearth\Generated\Admin\Model\AdminCreateOrganizationRequest $requestBody
     */
    public function __construct(?\Hearth\Generated\Admin\Model\AdminCreateOrganizationRequest $requestBody = null)
    {
        $this->body = $requestBody;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'POST';
    }
    public function getUri(): string
    {
        return '/admin/organizations';
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        if ($this->body instanceof \Hearth\Generated\Admin\Model\AdminCreateOrganizationRequest) {
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
     * @throws \Hearth\Generated\Admin\Exception\AdminCreateOrganizationForbiddenException
     *
     * @return null|\Hearth\Generated\Admin\Model\AdminOrganization
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (is_null($contentType) === false && (201 === $status && stripos(strtolower($contentType), 'application/json') !== false)) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\AdminOrganization', 'json');
        }
        if (403 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminCreateOrganizationForbiddenException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}