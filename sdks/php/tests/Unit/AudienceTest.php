<?php

declare(strict_types=1);

namespace Hearth\Tests\Unit;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Hearth\Contracts\JwksClientInterface;
use Hearth\Exceptions\ConfigurationException;
use Hearth\Exceptions\TokenAudienceException;
use Hearth\HearthClient;
use Hearth\TokenVerifier;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * The audience check is always on (sdk-support-contract, "JWT validation
 * steps", check 4). With no configuration the SDK expects `hearth`, the
 * audience Hearth mints when a client names no resource. Access tokens are
 * checked against the API's name, never the client ID.
 */
final class AudienceTest extends TestCase
{
    private const ISSUER = 'https://auth.example.com/realms/test';

    private string $keypair;

    protected function setUp(): void
    {
        $this->keypair = sodium_crypto_sign_keypair();
    }

    private static function b64url(string $raw): string
    {
        return strtr(rtrim(base64_encode($raw), '='), '+/', '-_');
    }

    /** @param array<string, mixed> $overrides Set a claim to null to leave it out. */
    private function token(array $overrides = []): string
    {
        $claims = array_filter(array_merge([
            'sub' => 'usr_abc',
            'iss' => self::ISSUER,
            'aud' => 'hearth',
            'exp' => time() + 3600,
            'iat' => time() - 10,
        ], $overrides), static fn ($v) => $v !== null);

        $message = self::b64url((string) json_encode(['alg' => 'EdDSA', 'typ' => 'JWT', 'kid' => 'k1']))
            . '.' . self::b64url((string) json_encode($claims));
        $sig = sodium_crypto_sign_detached($message, sodium_crypto_sign_secretkey($this->keypair));

        return $message . '.' . self::b64url($sig);
    }

    private function keys(): JwksClientInterface
    {
        $jwks = $this->createMock(JwksClientInterface::class);
        $jwks->method('getKey')->willReturn(sodium_crypto_sign_publickey($this->keypair));

        return $jwks;
    }

    /** A HearthClient whose discovery and JWKS fetches are served from memory. */
    private function client(array $args = []): HearthClient
    {
        $discovery = new Response(200, [], (string) json_encode([
            'issuer'   => self::ISSUER,
            'jwks_uri' => self::ISSUER . '/.well-known/jwks.json',
        ]));
        $jwks = new Response(200, [], (string) json_encode(['keys' => [[
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'kid' => 'k1',
            'x'   => self::b64url(sodium_crypto_sign_publickey($this->keypair)),
        ]]]));
        $http = new class ([$discovery, $jwks]) implements ClientInterface {
            private int $i = 0;

            /** @param list<ResponseInterface> $responses */
            public function __construct(private readonly array $responses) {}

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                return $this->responses[min($this->i++, count($this->responses) - 1)];
            }
        };
        $factory = new HttpFactory();

        return new HearthClient(...array_merge([
            'issuerUrl'      => self::ISSUER,
            'httpClient'     => $http,
            'requestFactory' => $factory,
            'streamFactory'  => $factory,
        ], $args));
    }

    public function testDefaultAudienceIsHearth(): void
    {
        self::assertSame('hearth', TokenVerifier::DEFAULT_AUDIENCE);
    }

    public function testVerifierRejectsAnotherApiByDefault(): void
    {
        $verifier = new TokenVerifier($this->keys(), self::ISSUER);

        try {
            $verifier->verify($this->token(['aud' => 'other-api']));
            self::fail('expected TokenAudienceException');
        } catch (TokenAudienceException $e) {
            self::assertSame('hearth', $e->getExpectedAudience());
        }
    }

    public function testVerifierRejectsTokenWithoutAudByDefault(): void
    {
        $this->expectException(TokenAudienceException::class);
        (new TokenVerifier($this->keys(), self::ISSUER))->verify($this->token(['aud' => null]));
    }

    public function testVerifierAcceptsHearthByDefault(): void
    {
        $claims = (new TokenVerifier($this->keys(), self::ISSUER))->verify($this->token());
        self::assertSame('usr_abc', $claims->subject());
    }

    public function testVerifierRefusesAnEmptyAudience(): void
    {
        $this->expectException(ConfigurationException::class);
        new TokenVerifier($this->keys(), self::ISSUER, '');
    }

    public function testClientRejectsAnotherApiByDefault(): void
    {
        $this->expectException(TokenAudienceException::class);
        $this->client()->verifyToken($this->token(['aud' => 'other-api']));
    }

    public function testClientIdIsNotTheAudience(): void
    {
        $client = $this->client(['clientId' => 'my-client']);
        self::assertSame('usr_abc', $client->verifyToken($this->token())->subject());

        $this->expectException(TokenAudienceException::class);
        $this->client(['clientId' => 'my-client'])->verifyToken($this->token(['aud' => 'my-client']));
    }

    public function testProtectedResourceSetsItsAudience(): void
    {
        $client = $this->client(['audience' => 'https://api.example.com']);
        $claims = $client->verifyToken($this->token(['aud' => 'https://api.example.com']));
        self::assertSame('usr_abc', $claims->subject());

        $this->expectException(TokenAudienceException::class);
        $this->client(['audience' => 'https://api.example.com'])->verifyToken($this->token());
    }

    public function testClientRefusesAnEmptyAudience(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->client(['audience' => '']);
    }
}
