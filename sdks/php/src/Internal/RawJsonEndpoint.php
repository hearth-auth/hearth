<?php

declare(strict_types=1);

namespace Hearth\Internal;

use Hearth\Generated\Admin\Runtime\Client\Client;
use Hearth\Generated\Admin\Runtime\Client\Endpoint;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\Serializer\SerializerInterface;

/**
 * A generated admin endpoint that sends the caller's array as its JSON body.
 *
 * The generated endpoint keeps the route, verb, query options and headers. The
 * body bypasses the generated request model: for users, applications, roles
 * and groups the proto-derived models in `docs/api/openapi.json` do not yet
 * match the REST JSON the handlers read (camelCase vs snake_case, different
 * field names), so serializing through them would change the wire JSON.
 *
 * @internal
 */
final class RawJsonEndpoint implements Endpoint
{
    /**
     * @param array<string, mixed> $body
     */
    public function __construct(
        private readonly Endpoint $endpoint,
        private readonly array $body,
    ) {}

    /**
     * @param mixed $streamFactory Unused: the body is a JSON string.
     * @return array{0: array<string, list<string>>, 1: string}
     */
    public function getBody(SerializerInterface $serializer, $streamFactory = null): array
    {
        return [
            ['Content-Type' => ['application/json']],
            json_encode($this->body, JSON_THROW_ON_ERROR),
        ];
    }

    public function getQueryString(): string
    {
        return $this->endpoint->getQueryString();
    }

    public function getUri(): string
    {
        return $this->endpoint->getUri();
    }

    public function getMethod(): string
    {
        return $this->endpoint->getMethod();
    }

    /**
     * @param array<string, mixed> $baseHeaders
     * @return array<string, mixed>
     */
    public function getHeaders(array $baseHeaders = []): array
    {
        return $this->endpoint->getHeaders($baseHeaders);
    }

    /** @return array<array-key, mixed> */
    public function getAuthenticationScopes(): array
    {
        return $this->endpoint->getAuthenticationScopes();
    }

    public function parseResponse(
        ResponseInterface $response,
        SerializerInterface $serializer,
        string $fetchMode = Client::FETCH_OBJECT,
    ): mixed {
        return $this->endpoint->parseResponse($response, $serializer, $fetchMode);
    }
}
