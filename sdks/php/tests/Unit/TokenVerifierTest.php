<?php

declare(strict_types=1);

namespace Hearth\Tests\Unit;

use Hearth\Claims;
use Hearth\Contracts\JwksClientInterface;
use Hearth\Exceptions\JWKSFetchException;
use Hearth\Exceptions\JwksKeyNotFoundException;
use Hearth\Exceptions\RequiredActionException;
use Hearth\Exceptions\TokenAudienceException;
use Hearth\Exceptions\TokenExpiredException;
use Hearth\Exceptions\TokenIssuerException;
use Hearth\Exceptions\TokenNotYetValidException;
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

    public function testVerifyThrowsWhenNbfIsInTheFuture(): void
    {
        $this->setUpJwksForKey();
        $token = $this->makeToken($this->validClaims(['nbf' => time() + 3600]));

        $this->expectException(TokenNotYetValidException::class);
        $this->verifier->verify($token);
    }

    public function testVerifyAcceptsTokenWhoseNbfHasPassed(): void
    {
        $this->setUpJwksForKey();
        $token  = $this->makeToken($this->validClaims(['nbf' => time() - 3600]));
        $claims = $this->verifier->verify($token);
        self::assertSame('usr_abc', $claims->subject());
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

    /**
     * A signature of the wrong length used to escape as libsodium's
     * SodiumException, which is not a HearthException: HearthMiddleware only
     * catches HearthException, so the request died with a 500 instead of a 401.
     *
     * @return array<string, array{string}>
     */
    public static function wrongLengthSignatures(): array
    {
        return [
            'empty'     => [''],
            'truncated' => ['AAAA'],
            'too long'  => [strtr(rtrim(base64_encode(str_repeat("\x01", 65)), '='), '+/', '-_')],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('wrongLengthSignatures')]
    public function testVerifyRejectsWrongLengthSignatureAsInvalidToken(string $sig): void
    {
        $this->setUpJwksForKey();
        [$header, $payload] = explode('.', $this->makeToken($this->validClaims()));

        $this->expectException(TokenInvalidException::class);
        $this->verifier->verify("{$header}.{$payload}.{$sig}");
    }

    public function testVerifyRejectsWrongLengthPublicKeyAsInvalidToken(): void
    {
        // A custom JwksClientInterface is free to return any string.
        $this->jwksClient->method('getKey')->willReturn('short-key');

        $this->expectException(TokenInvalidException::class);
        $this->verifier->verify($this->makeToken($this->validClaims()));
    }

    // -------------------------------------------------------------------------
    // JOSE-library verification (sdk-standard-libraries 2.4)
    // -------------------------------------------------------------------------

    private static function b64url(string $raw): string
    {
        return strtr(rtrim(base64_encode($raw), '='), '+/', '-_');
    }

    public function testVerifyRejectsTamperedPayload(): void
    {
        $this->setUpJwksForKey();
        [$header, , $sig] = explode('.', $this->makeToken($this->validClaims()));
        $tampered = self::b64url((string) json_encode($this->validClaims(['sub' => 'usr_admin'])));

        $this->expectException(TokenInvalidException::class);
        $this->verifier->verify("{$header}.{$tampered}.{$sig}");
    }

    public function testVerifyRejectsUnsignedAlgNoneToken(): void
    {
        $this->setUpJwksForKey();
        $header  = self::b64url((string) json_encode(['alg' => 'none', 'typ' => 'JWT', 'kid' => 'test-key']));
        $payload = self::b64url((string) json_encode($this->validClaims()));

        $this->expectException(TokenInvalidException::class);
        $this->verifier->verify("{$header}.{$payload}.");
    }

    public function testVerifyRejectsAlgNoneHeaderEvenWithAValidEd25519Signature(): void
    {
        $this->setUpJwksForKey();
        $header  = self::b64url((string) json_encode(['alg' => 'none', 'typ' => 'JWT', 'kid' => 'test-key']));
        $payload = self::b64url((string) json_encode($this->validClaims()));
        $sig     = self::b64url(sodium_crypto_sign_detached(
            "{$header}.{$payload}",
            sodium_crypto_sign_secretkey($this->keypair),
        ));

        $this->expectException(TokenInvalidException::class);
        $this->verifier->verify("{$header}.{$payload}.{$sig}");
    }

    public function testVerifyRejectsTokenWhoseKidNamesADifferentKey(): void
    {
        $otherPublic = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());
        $this->jwksClient
            ->method('getKey')
            ->willReturnMap([['other-key', $otherPublic]]);

        $this->expectException(TokenInvalidException::class);
        $this->verifier->verify($this->makeToken($this->validClaims(), 'other-key'));
    }

    /**
     * openspec/specs/sdk-support-contract/spec.md: an unknown `kid` (absent after one re-fetch) is a bad token,
     * not a JWKS fetch failure.
     */
    public function testVerifyReportsUnknownKidAsTokenInvalid(): void
    {
        $this->jwksClient
            ->method('getKey')
            ->willThrowException(new JwksKeyNotFoundException('nope'));

        $this->expectException(TokenInvalidException::class);
        $this->verifier->verify($this->makeToken($this->validClaims(), 'nope'));
    }

    public function testVerifyPropagatesARealJwksFetchFailure(): void
    {
        $this->jwksClient
            ->method('getKey')
            ->willThrowException(new JWKSFetchException('JWKS endpoint returned HTTP 503'));

        $this->expectException(JWKSFetchException::class);
        $this->verifier->verify($this->makeToken($this->validClaims(), 'test-key'));
    }

    /**
     * The signature check belongs to lcobucci/jwt, not to the SDK
     * (spec: "No handwritten signature check remains").
     */
    public function testVerifierContainsNoHandwrittenSignatureCheck(): void
    {
        $source = (string) file_get_contents(__DIR__ . '/../../src/TokenVerifier.php');

        self::assertStringNotContainsString('sodium_crypto_sign_verify_detached', $source);
        self::assertStringContainsString('Lcobucci\\JWT\\Signer\\Eddsa', $source);
    }
}
