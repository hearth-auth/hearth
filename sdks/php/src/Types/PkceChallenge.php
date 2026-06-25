<?php

declare(strict_types=1);

namespace Hearth\Types;

/**
 * PKCE code-verifier / code-challenge pair (RFC 7636).
 *
 * Use `PkceChallenge::generate()` to produce a cryptographically random pair,
 * then pass `$pkce->codeChallenge` and `$pkce->codeChallengeMethod` in the
 * authorization request and `$pkce->codeVerifier` in the token exchange.
 */
final class PkceChallenge
{
    /** Minimum verifier length per RFC 7636 §4.1. */
    private const MIN_BYTES = 32;

    private function __construct(
        /** Raw code verifier — keep secret, send only to the token endpoint. */
        public readonly string $codeVerifier,
        /** S256 hash of the verifier — send in the authorization request. */
        public readonly string $codeChallenge,
        /** Always "S256" for this implementation. */
        public readonly string $codeChallengeMethod,
    ) {}

    /**
     * Generates a fresh cryptographically secure PKCE pair.
     *
     * Produces a 32-byte (256-bit) random verifier, base64url-encoded (43 chars),
     * and its S256 challenge per RFC 7636 §4.2.
     */
    public static function generate(): self
    {
        $randomBytes  = random_bytes(self::MIN_BYTES);
        $codeVerifier = self::base64url($randomBytes);

        $hash          = hash('sha256', $codeVerifier, true);
        $codeChallenge = self::base64url($hash);

        return new self($codeVerifier, $codeChallenge, 'S256');
    }

    /** Base64url-encodes bytes without padding (RFC 4648 §5). */
    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
