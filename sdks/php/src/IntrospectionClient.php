<?php

declare(strict_types=1);

namespace Hearth;

use Hearth\Exceptions\IntrospectionException;
use Hearth\Exceptions\NetworkException;
use Hearth\Types\IntrospectionResult;
use JsonException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Throwable;

/**
 * Calls the RFC 7662 token introspection endpoint.
 *
 * Per §3 of the SDK specification, introspection results must NOT be cached
 * because the token state can change at any time (RFC 7662 §2.1).
 *
 * Authentication against the introspection endpoint uses HTTP Basic Auth
 * with the configured `client_id` and `client_secret`.
 */
final class IntrospectionClient
{
    /**
     * @param string                  $introspectionEndpoint Full URL of the introspection endpoint
     * @param string                  $clientId              OAuth client ID (used as Basic auth username)
     * @param string                  $clientSecret          OAuth client secret (used as Basic auth password)
     * @param ClientInterface         $httpClient            PSR-18 HTTP client
     * @param RequestFactoryInterface $requestFactory        PSR-17 request factory
     * @param StreamFactoryInterface  $streamFactory         PSR-17 stream factory
     */
    public function __construct(
        private readonly string $introspectionEndpoint,
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {}

    /**
     * Introspects a token against the Hearth introspection endpoint.
     *
     * @throws NetworkException       When the endpoint is unreachable
     * @throws IntrospectionException When the endpoint returns an error or invalid JSON
     */
    public function introspect(string $token): IntrospectionResult
    {
        $body    = http_build_query(['token' => $token]);
        $request = $this->requestFactory
            ->createRequest('POST', $this->introspectionEndpoint)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withHeader('Authorization', 'Basic ' . base64_encode("{$this->clientId}:{$this->clientSecret}"))
            ->withBody($this->streamFactory->createStream($body));

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new NetworkException(
                $this->introspectionEndpoint,
                "Introspection request failed: {$e->getMessage()}",
                0,
                $e,
            );
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw new IntrospectionException(
                "Introspection endpoint returned HTTP {$status}",
                $status,
            );
        }

        try {
            $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new IntrospectionException('Introspection response is not valid JSON', $status, 0, $e);
        }

        if (!is_array($data)) {
            throw new IntrospectionException('Introspection response must be a JSON object', $status);
        }

        return IntrospectionResult::fromArray($data);
    }
}
