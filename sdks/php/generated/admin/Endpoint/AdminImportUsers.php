<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminImportUsers extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    /**
     * Creates one user for each entry. An entry that fails gets an error in `results`, and the other entries continue.
     * @param null|\Hearth\Generated\Admin\Model\AdminImportUsersRequest $requestBody
     */
    public function __construct(?\Hearth\Generated\Admin\Model\AdminImportUsersRequest $requestBody = null)
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
        return '/admin/users/import';
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        if ($this->body instanceof \Hearth\Generated\Admin\Model\AdminImportUsersRequest) {
            return [['Content-Type' => ['application/json']], \Hearth\Generated\Admin\Runtime\Client\JsonPayload::encode($serializer, $this->body)];
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