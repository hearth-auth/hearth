<?php

declare(strict_types=1);

namespace Hearth\Tests\Unit;

use Hearth\Types\PkceChallenge;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for PKCE code-verifier / code-challenge generation (RFC 7636).
 */
final class PkceTest extends TestCase
{
    public function testGenerateReturnsPkceChallenge(): void
    {
        $pkce = PkceChallenge::generate();

        self::assertInstanceOf(PkceChallenge::class, $pkce);
    }

    public function testCodeVerifierIsNonEmpty(): void
    {
        $pkce = PkceChallenge::generate();

        self::assertNotEmpty($pkce->codeVerifier);
    }

    /** RFC 7636 §4.1 mandates 43–128 characters. */
    public function testCodeVerifierLengthIsWithinRfcBounds(): void
    {
        $pkce = PkceChallenge::generate();

        $len = strlen($pkce->codeVerifier);
        self::assertGreaterThanOrEqual(43, $len, 'code_verifier must be at least 43 chars');
        self::assertLessThanOrEqual(128, $len, 'code_verifier must be at most 128 chars');
    }

    /** Verifier must use unreserved URL-safe characters only (base64url alphabet). */
    public function testCodeVerifierIsBase64UrlSafe(): void
    {
        $pkce = PkceChallenge::generate();

        self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $pkce->codeVerifier);
    }

    public function testCodeChallengeMethodIsS256(): void
    {
        $pkce = PkceChallenge::generate();

        self::assertSame('S256', $pkce->codeChallengeMethod);
    }

    /** S256 challenge = BASE64URL(SHA-256(ASCII(code_verifier))). */
    public function testCodeChallengeMatchesS256OfVerifier(): void
    {
        $pkce = PkceChallenge::generate();

        $expected = rtrim(strtr(base64_encode(hash('sha256', $pkce->codeVerifier, true)), '+/', '-_'), '=');
        self::assertSame($expected, $pkce->codeChallenge);
    }

    /** Two calls must produce different verifiers (probability of collision is negligible). */
    public function testGenerateProducesUniqueVerifiers(): void
    {
        $a = PkceChallenge::generate();
        $b = PkceChallenge::generate();

        self::assertNotSame($a->codeVerifier, $b->codeVerifier);
    }
}
