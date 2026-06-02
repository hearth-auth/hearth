<?php

declare(strict_types=1);

namespace Hearth\Tests\Unit;

use Hearth\Claims;
use Hearth\Contracts\JwksClientInterface;
use Hearth\Exceptions\RequiredActionException;
use Hearth\Exceptions\TokenAudienceException;
use Hearth\Exceptions\TokenExpiredException;
use Hearth\Exceptions\TokenIssuerException;
use Hearth\Exceptions\TokenInvalidException;
use Hearth\TokenVerifier;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for TokenVerifier — Ed25519 JWT signature and claim validation.
 *
 * These tests are stubs that drive the TDD contract. Full JWT fixtures with
 * real Ed25519 signatures will be wired in Phase 3.
 */
final class TokenVerifierTest extends TestCase
{
    private JwksClientInterface&MockObject $jwksClient;
    private TokenVerifier $verifier;

    /** Generates a real Ed25519 keypair for signing test tokens. */
    private string $keypair;

    protected function setUp(): void
    {
        $this->keypair    = sodium_crypto_sign_keypair();
        $this->jwksClient = $this->createMock(JwksClientInterface::class);

        $this->verifier = new TokenVerifier(
            $this->jwksClient,
            'https://auth.example.com',
            'test-client',
        );
    }

    /** Creates a signed JWT with the given payload using our test keypair. */
    private function makeToken(array $claims, string $kid = 'test-key'): string
    {
        $header  = base64_encode(json_encode(['alg' => 'EdDSA', 'typ' => 'JWT', 'kid' => $kid]));
        $payload = base64_encode(json_encode($claims));

        $header  = strtr(rtrim($header, '='), '+/', '-_');
        $payload = strtr(rtrim($payload, '='), '+/', '-_');

        $message   = "{$header}.{$payload}";
        $secretKey = sodium_crypto_sign_secretkey($this->keypair);
        $sigRaw    = sodium_crypto_sign_detached($message, $secretKey);
        $sig       = strtr(rtrim(base64_encode($sigRaw), '='), '+/', '-_');

        return "{$header}.{$payload}.{$sig}";
    }

    private function validClaims(array $overrides = []): array
    {
        return array_merge([
            'sub'        => 'usr_abc',
            'iss'        => 'https://auth.example.com',
            'aud'        => ['test-client'],
            'exp'        => time() + 3600,
            'iat'        => time() - 10,
            'token_type' => 'access',
        ], $overrides);
    }

    protected function setUpJwksForKey(string $kid = 'test-key'): void
    {
        $publicKey = sodium_crypto_sign_publickey($this->keypair);
        $this->jwksClient
            ->method('getKey')
            ->with($kid)
            ->willReturn($publicKey);
    }

    public function testVerifyReturnsClaimsOnValidToken(): void
    {
        $this->setUpJwksForKey();
        $token  = $this->makeToken($this->validClaims());
        $claims = $this->verifier->verify($token);
        self::assertInstanceOf(Claims::class, $claims);
        self::assertSame('usr_abc', $claims->subject());
    }

    public function testVerifyThrowsOnMalformedJwt(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->verifier->verify('not.a.valid.jwt.parts');
    }

    public function testVerifyThrowsOnBadSignature(): void
    {
        $otherKeypair = sodium_crypto_sign_keypair();
        $otherPublic  = sodium_crypto_sign_publickey($otherKeypair);

        $this->jwksClient
            ->method('getKey')
            ->willReturn($otherPublic); // wrong public key

        $this->expectException(TokenInvalidException::class);
        $this->verifier->verify($this->makeToken($this->validClaims()));
    }

    public function testVerifyThrowsOnExpiredToken(): void
    {
        $this->setUpJwksForKey();
        $token = $this->makeToken($this->validClaims(['exp' => time() - 60]));

        $this->expectException(TokenExpiredException::class);
        $this->verifier->verify($token);
    }

    public function testVerifyThrowsOnIssuerMismatch(): void
    {
        $this->setUpJwksForKey();
        $token = $this->makeToken($this->validClaims(['iss' => 'https://evil.com']));

        $this->expectException(TokenIssuerException::class);
        $this->verifier->verify($token);
    }

    public function testVerifyThrowsOnAudienceMismatch(): void
    {
        $this->setUpJwksForKey();
        $token = $this->makeToken($this->validClaims(['aud' => ['other-client']]));

        $this->expectException(TokenAudienceException::class);
        $this->verifier->verify($token);
    }

    public function testVerifyThrowsRequiredActionExceptionForRequiredActionToken(): void
    {
        $this->setUpJwksForKey();
        $token = $this->makeToken($this->validClaims([
            'token_type'      => 'required_action',
            'required_actions' => ['VERIFY_EMAIL'],
        ]));

        $this->expectException(RequiredActionException::class);
        $this->verifier->verify($token);
    }

    public function testVerifyThrowsOnFutureIat(): void
    {
        $this->setUpJwksForKey();
        $token = $this->makeToken($this->validClaims(['iat' => time() + 60]));

        $this->expectException(TokenInvalidException::class);
        $this->verifier->verify($token);
    }

    public function testVerifyThrowsOnNonEddsaAlgorithm(): void
    {
        // Build a token with alg=RS256 manually (not signed with our keypair)
        $header  = strtr(rtrim(base64_encode(json_encode(['alg' => 'RS256', 'kid' => 'k1'])), '='), '+/', '-_');
        $payload = strtr(rtrim(base64_encode(json_encode($this->validClaims())), '='), '+/', '-_');
        $token   = "{$header}.{$payload}.fakesig";

        $this->expectException(TokenInvalidException::class);
        $this->verifier->verify($token);
    }
}
