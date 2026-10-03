<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminUpdateOrganization extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    protected $id;
    /**
     * Body: `{display_name?, status? (active|suspended), member_limit?, mfa_required?, attributes?}`. A field left out keeps its value. A `slug` is refused with 400 (it is immutable). Suspending is checked against the admin privilege ceiling, like a delete.
     * @param string $id
     * @param null|\Hearth\Generated\Admin\Model\AdminUpdateOrganizationRequest $requestBody
     */
    public function __construct(string $id, ?\Hearth\Generated\Admin\Model\AdminUpdateOrganizationRequest $requestBody = null)
    {
        $this->id = $id;
        $this->body = $requestBody;
    }
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'PATCH';
    }
    public function getUri(): string
    {
        return str_replace(['{id}'], [rawurlencode($this->id)], '/admin/organizations/{id}');
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        if ($this->body instanceof \Hearth\Generated\Admin\Model\AdminUpdateOrganizationRequest) {
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
     * @throws \Hearth\Generated\Admin\Exception\AdminUpdateOrganizationBadRequestException
     * @throws \Hearth\Generated\Admin\Exception\AdminUpdateOrganizationForbiddenException
     *
     * @return null|\Hearth\Generated\Admin\Model\AdminOrganization
     */
    protected function transformResponseBody(\Psr\Http\Message\ResponseInterface $response, \Symfony\Component\Serializer\SerializerInterface $serializer, ?string $contentType = null)
    {
        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if (is_null($contentType) === false && (200 === $status && stripos(strtolower($contentType), 'application/json') !== false)) {
            return $serializer->deserialize($body, 'Hearth\Generated\Admin\Model\AdminOrganization', 'json');
        }
        if (400 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminUpdateOrganizationBadRequestException($response);
        }
        if (403 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminUpdateOrganizationForbiddenException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}