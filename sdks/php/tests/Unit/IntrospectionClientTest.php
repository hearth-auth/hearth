<?php

declare(strict_types=1);

namespace Hearth\Tests\Unit;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Hearth\Exceptions\IntrospectionException;
use Hearth\Exceptions\NetworkException;
use Hearth\IntrospectionClient;
use Hearth\Types\IntrospectionResult;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\ClientExceptionInterface;

/**
 * Unit tests for IntrospectionClient — RFC 7662 token introspection.
 *
 * Per SDK spec §3: introspection results MUST NOT be cached. Each call
 * must result in exactly one HTTP request regardless of prior calls.
 */
final class IntrospectionClientTest extends TestCase
{
    private ClientInterface&MockObject $httpClient;
    private IntrospectionClient $client;

    protected function setUp(): void
    {
        $this->httpClient = $this->createMock(ClientInterface::class);
        $factory          = new HttpFactory();

        $this->client = new IntrospectionClient(
            introspectionEndpoint: 'https://auth.example.com/oauth/introspect',
            clientId: 'my-client',
            clientSecret: 'secret',
            httpClient: $this->httpClient,
            requestFactory: $factory,
            streamFactory: $factory,
        );
    }

    public function testActiveTokenReturnsMappedIntrospectionResult(): void
    {
        $responseBody = json_encode([
            'active'      => true,
            'sub'         => 'usr_abc123',
            'iss'         => 'https://auth.example.com',
            'aud'         => ['my-client'],
            'exp'         => time() + 3600,
            'iat'         => time() - 60,
            'scope'       => 'openid profile',
            'client_id'   => 'my-client',
            'token_type'  => 'Bearer',
        ]);

        $this->httpClient
            ->expects($this->once())
            ->method('sendRequest')
            ->willReturn(new Response(200, ['Content-Type' => 'application/json'], $responseBody));

        $result = $this->client->introspect('some-access-token');

        self::assertInstanceOf(IntrospectionResult::class, $result);
        self::assertTrue($result->active);
        self::assertSame('usr_abc123', $result->sub);
        self::assertSame('https://auth.example.com', $result->iss);
        self::assertSame(['my-client'], $result->aud);
        self::assertSame('openid profile', $result->scope);
        self::assertSame('my-client', $result->clientId);
        self::assertSame('Bearer', $result->tokenType);
    }

    public function testInactiveTokenReturnsResultWithActiveFalse(): void
    {
        $this->httpClient
            ->method('sendRequest')
            ->willReturn(new Response(200, [], json_encode(['active' => false])));

        $result = $this->client->introspect('expired-token');

        self::assertInstanceOf(IntrospectionResult::class, $result);
        self::assertFalse($result->active);
        self::assertNull($result->sub);
        self::assertNull($result->exp);
    }

    public function testResultIsNeverCachedBetweenCalls(): void
    {
        // RFC 7662 §2.1: server MUST NOT cache introspection responses
        $this->httpClient
            ->expects($this->exactly(2))
            ->method('sendRequest')
            ->willReturn(new Response(200, [], json_encode(['active' => true, 'sub' => 'usr_1'])));

        $this->client->introspect('token-a');
        $this->client->introspect('token-b'); // must NOT serve from cache
    }

    public function testThrowsIntrospectionExceptionOnNonSuccessStatus(): void
    {
        $this->httpClient
            ->method('sendRequest')
            ->willReturn(new Response(401));

        $this->expectException(IntrospectionException::class);
        $this->client->introspect('bad-token');
    }

    public function testThrowsIntrospectionExceptionOnNonSuccessStatusPreservesHttpStatus(): void
    {
        $this->httpClient
            ->method('sendRequest')
            ->willReturn(new Response(503));

        try {
            $this->client->introspect('bad-token');
            self::fail('Expected IntrospectionException');
        } catch (IntrospectionException $e) {
            self::assertSame(503, $e->getHttpStatus());
        }
    }

    public function testThrowsIntrospectionExceptionOnInvalidJsonResponse(): void
    {
        $this->httpClient
            ->method('sendRequest')
            ->willReturn(new Response(200, [], 'not-json'));

        $this->expectException(IntrospectionException::class);
        $this->client->introspect('any-token');
    }

    public function testThrowsNetworkExceptionWhenEndpointUnreachable(): void
    {
        $transportFailure = new class ('connection refused') extends \RuntimeException implements ClientExceptionInterface {};

        $this->httpClient
            ->method('sendRequest')
            ->willThrowException($transportFailure);

        $this->expectException(NetworkException::class);
        $this->client->introspect('any-token');
    }

    public function testSendsBasicAuthCredentials(): void
    {
        $capturedRequest = null;

        $this->httpClient
            ->method('sendRequest')
            ->willReturnCallback(function (\Psr\Http\Message\RequestInterface $req) use (&$capturedRequest) {
                $capturedRequest = $req;
                return new Response(200, [], json_encode(['active' => false]));
            });

        $this->client->introspect('some-token');

        $authHeader = $capturedRequest?->getHeaderLine('Authorization');
        self::assertSame('Basic ' . base64_encode('my-client:secret'), $authHeader);
    }

    public function testSendsTokenInFormBody(): void
    {
        $capturedRequest = null;

        $this->httpClient
            ->method('sendRequest')
            ->willReturnCallback(function (\Psr\Http\Message\RequestInterface $req) use (&$capturedRequest) {
                $capturedRequest = $req;
                return new Response(200, [], json_encode(['active' => false]));
            });

        $this->client->introspect('my-secret-token');

        $body = (string) $capturedRequest?->getBody();
        self::assertStringContainsString('token=my-secret-token', $body);
    }

    public function testNonStandardClaimsPopulateExtraField(): void
    {
        $responseBody = json_encode([
            'active'         => true,
            'sub'            => 'usr_1',
            'custom_claim'   => 'custom_value',
            'another_custom' => 42,
        ]);

        $this->httpClient
            ->method('sendRequest')
            ->willReturn(new Response(200, [], $responseBody));

        $result = $this->client->introspect('token');

        self::assertSame('custom_value', $result->extra['custom_claim']);
        self::assertSame(42, $result->extra['another_custom']);
    }
}
