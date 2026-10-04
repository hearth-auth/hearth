<?php

namespace Hearth\Generated\Admin\Endpoint;

class AdminClusterTransferLeadership extends \Hearth\Generated\Admin\Runtime\Client\BaseEndpoint implements \Hearth\Generated\Admin\Runtime\Client\Endpoint
{
    use \Hearth\Generated\Admin\Runtime\Client\EndpointTrait;
    public function getMethod(): string
    {
        return 'POST';
    }
    public function getUri(): string
    {
        return '/admin/cluster/transfer-leadership';
    }
    public function getBody(\Symfony\Component\Serializer\SerializerInterface $serializer, $streamFactory = null): array
    {
        return [[], null];
    }
    /**
     * {@inheritdoc}
     *
     * @throws \Hearth\Generated\Admin\Exception\AdminClusterTransferLeadershipBadRequestException
     * @throws \Hearth\Generated\Admin\Exception\AdminClusterTransferLeadershipConflictException
     * @throws \Hearth\Generated\Admin\Exception\AdminClusterTransferLeadershipUnprocessableEntityException
     * @throws \Hearth\Generated\Admin\Exception\AdminClusterTransferLeadershipServiceUnavailableException
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
            throw new \Hearth\Generated\Admin\Exception\AdminClusterTransferLeadershipBadRequestException($response);
        }
        if (409 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminClusterTransferLeadershipConflictException($response);
        }
        if (422 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminClusterTransferLeadershipUnprocessableEntityException($response);
        }
        if (503 === $status) {
            throw new \Hearth\Generated\Admin\Exception\AdminClusterTransferLeadershipServiceUnavailableException($response);
        }
    }
    public function getAuthenticationScopes(): array
    {
        return [];
    }
}