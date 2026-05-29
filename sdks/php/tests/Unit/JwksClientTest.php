<?php

declare(strict_types=1);

namespace Hearth\Tests\Unit;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Hearth\Exceptions\JWKSFetchException;
use Hearth\JwksClient;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Unit tests for JwksClient — JWKS fetch, OKP parse, and TTL cache.
 *
 * These tests are stubs: many will be RED until the implementation and
 * proper test fixtures (real Ed25519 key bytes) are wired in Phase 3.
 */
final class JwksClientTest extends TestCase
{
    /** A real 32-byte Ed25519 public key (base64url-encoded). */
    private const FAKE_X = 'JHlqIjnkXBYoFYMpFqCcuyVbgcxFrWUdqGVWLXs0k0Q';
    private const FAKE_KID = 'key-2025';

    private ClientInterface&MockObject $httpClient;
    private JwksClient $jwksClient;

    protected function setUp(): void
    {
        $this->httpClient = $this->createMock(ClientInterface::class);
        $factory          = new HttpFactory();

        $this->jwksClient = new JwksClient(
            'https://auth.example.com/jwks',
            $this->httpClient,
            $factory,
        );
    }

    public function testGetKeyFetchesJwksOnCacheMiss(): void
    {
        $jwks = json_encode([
            'keys' => [[
                'kty' => 'OKP',
                'crv' => 'Ed25519',
                'kid' => self::FAKE_KID,
                'alg' => 'EdDSA',
                'use' => 'sig',
                'x'   => self::FAKE_X,
            ]],
        ]);

        $this->httpClient
            ->expects($this->once())
            ->method('sendRequest')
            ->willReturn(new Response(200, ['Content-Type' => 'application/json'], $jwks));

        $key = $this->jwksClient->getKey(self::FAKE_KID);

        // The returned value should be a 32-byte binary string
        self::assertSame(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, strlen($key));
    }

    public function testGetKeyThrowsJWKSFetchExceptionForUnknownKid(): void
    {
        $jwks = json_encode(['keys' => []]);

        $this->httpClient
            ->method('sendRequest')
            ->willReturn(new Response(200, [], $jwks));

        $this->expectException(JWKSFetchException::class);
        $this->jwksClient->getKey('unknown-kid');
    }

    public function testSkipsKeysWithUnrecognisedKty(): void
    {
        // A JWKS with an RSA key that should be silently skipped
        $jwks = json_encode([
            'keys' => [
                ['kty' => 'RSA', 'kid' => 'rsa-key', 'n' => 'abc', 'e' => 'AQAB'],
                ['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => self::FAKE_KID, 'x' => self::FAKE_X, 'alg' => 'EdDSA'],
            ],
        ]);

        $this->httpClient
            ->method('sendRequest')
            ->willReturn(new Response(200, [], $jwks));

        // Should not throw even though an RSA key is present — it is simply skipped
        $key = $this->jwksClient->getKey(self::FAKE_KID);
        self::assertNotEmpty($key);
    }

    public function testRespectsCacheControlMaxAge(): void
    {
        $jwks = json_encode([
            'keys' => [[
                'kty' => 'OKP', 'crv' => 'Ed25519',
                'kid' => self::FAKE_KID, 'x' => self::FAKE_X,
            ]],
        ]);

        // Only one HTTP call should be made due to caching
        $this->httpClient
            ->expects($this->once())
            ->method('sendRequest')
            ->willReturn(new Response(200, ['Cache-Control' => 'max-age=600'], $jwks));

        $this->jwksClient->getKey(self::FAKE_KID);
        $this->jwksClient->getKey(self::FAKE_KID); // should hit cache
    }

    public function testThrowsJWKSFetchExceptionOnNonSuccessHttpStatus(): void
    {
        $this->httpClient
            ->method('sendRequest')
            ->willReturn(new Response(503));

        $this->expectException(JWKSFetchException::class);
        $this->jwksClient->getKey(self::FAKE_KID);
    }
}
