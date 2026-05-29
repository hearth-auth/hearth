<?php

declare(strict_types=1);

namespace Hearth;

use DateTimeImmutable;
use Hearth\Contracts\JwksClientInterface;
use Hearth\Contracts\TokenVerifierInterface;
use Hearth\Exceptions\JWKSFetchException;
use Hearth\Exceptions\RequiredActionException;
use Hearth\Exceptions\TokenAudienceException;
use Hearth\Exceptions\TokenExpiredException;
use Hearth\Exceptions\TokenIssuerException;
use Hearth\Exceptions\TokenInvalidException;
use JsonException;

/**
 * Verifies a raw JWT string against the Hearth JWKS and validates standard claims.
 *
 * Implements the mandatory §1.2–1.3 JWT validation steps in order:
 *   1. Verify Ed25519 signature against cached JWKS.
 *   2. Verify `exp` claim (reject if expired).
 *   3. Verify `iss` matches the configured issuer URL.
 *   4. Verify `aud` contains the configured client ID (when set).
 *   5. Verify `iat` is not in the future (allow up to 5 s clock skew).
 *
 * Tokens with `token_type === "required_action"` raise RequiredActionException.
 */
final class TokenVerifier implements TokenVerifierInterface
{
    /** Maximum clock skew tolerated for the `iat` claim (seconds). */
    private const CLOCK_SKEW_SECONDS = 5;

    /**
     * @param JwksClientInterface $jwksClient   Key source
     * @param string              $issuerUrl    Expected `iss` value
     * @param string|null         $clientId     Expected audience; if null, audience check is skipped
     */
    public function __construct(
        private readonly JwksClientInterface $jwksClient,
        private readonly string $issuerUrl,
        private readonly ?string $clientId = null,
    ) {}

    /**
     * Verifies and decodes a JWT, returning a typed Claims accessor.
     *
     * @throws TokenInvalidException  On malformed JWT or invalid Ed25519 signature
     * @throws JWKSFetchException            When the signing key cannot be resolved
     * @throws TokenExpiredException    When `exp` is in the past
     * @throws TokenIssuerException     When `iss` does not match
     * @throws TokenAudienceException   When `aud` does not include the client ID
     * @throws RequiredActionException  When `token_type === "required_action"`
     */
    public function verify(string $rawToken): Claims
    {
        [$headerB64, $payloadB64, $sigB64] = $this->splitToken($rawToken);

        $header = $this->decodeJsonPart($headerB64, 'header');
        $claims = $this->decodeJsonPart($payloadB64, 'payload');

        $this->checkAlgorithm($header);

        // Step 1 — signature verification (before any claim checks)
        $kid           = is_string($header['kid'] ?? null) ? $header['kid'] : '';
        $publicKeyBytes = $this->jwksClient->getKey($kid);
        $this->verifySignature($headerB64, $payloadB64, $sigB64, $publicKeyBytes);

        // Step 2 — expiration
        $this->checkExpiry($claims);

        // Step 3 — issuer
        $this->checkIssuer($claims);

        // Step 4 — audience
        if ($this->clientId !== null) {
            $this->checkAudience($claims);
        }

        // Step 5 — issued-at / clock skew
        $this->checkIssuedAt($claims);

        $claimsObj = new Claims($claims);

        // Required-action tokens must not be accepted as regular access tokens
        if ($claimsObj->tokenType() === 'required_action') {
            /** @var string[] $actions */
            $actions = is_array($claims['required_actions'] ?? null) ? $claims['required_actions'] : [];
            throw new RequiredActionException($actions, null);
        }

        return $claimsObj;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Splits a JWT into its three base64url-encoded parts.
     *
     * @return array{string, string, string}
     * @throws TokenInvalidException
     */
    private function splitToken(string $rawToken): array
    {
        $parts = explode('.', $rawToken);
        if (count($parts) !== 3) {
            throw new TokenInvalidException('Malformed JWT: expected 3 dot-separated parts');
        }

        return [$parts[0], $parts[1], $parts[2]];
    }

    /**
     * Base64url-decodes and JSON-decodes a JWT part.
     *
     * @return array<string, mixed>
     * @throws TokenInvalidException
     */
    private function decodeJsonPart(string $b64url, string $partName): array
    {
        $decoded = base64_decode(strtr($b64url, '-_', '+/'), true);
        if ($decoded === false) {
            throw new TokenInvalidException("Malformed JWT: could not base64url-decode {$partName}");
        }

        try {
            $data = json_decode($decoded, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new TokenInvalidException("Malformed JWT: {$partName} is not valid JSON", 0, $e);
        }

        if (!is_array($data)) {
            throw new TokenInvalidException("Malformed JWT: {$partName} must be a JSON object");
        }

        return $data;
    }

    /**
     * Rejects tokens that are not EdDSA-signed.
     *
     * @param array<string, mixed> $header
     * @throws TokenInvalidException
     */
    private function checkAlgorithm(array $header): void
    {
        $alg = $header['alg'] ?? null;
        if ($alg !== 'EdDSA') {
            throw new TokenInvalidException(
                "Unsupported JWT algorithm: expected EdDSA, got " . json_encode($alg),
            );
        }
    }

    /**
     * Verifies the Ed25519 signature using libsodium.
     *
     * @throws TokenInvalidException
     */
    private function verifySignature(
        string $headerB64,
        string $payloadB64,
        string $sigB64,
        string $publicKeyBytes,
    ): void {
        $message   = "{$headerB64}.{$payloadB64}";
        $signature = base64_decode(strtr($sigB64, '-_', '+/'), true);

        if ($signature === false) {
            throw new TokenInvalidException('Malformed JWT: could not base64url-decode signature');
        }

        if (!sodium_crypto_sign_verify_detached($signature, $message, $publicKeyBytes)) {
            throw new TokenInvalidException('JWT signature verification failed');
        }
    }

    /**
     * @param array<string, mixed> $claims
     * @throws TokenExpiredException
     */
    private function checkExpiry(array $claims): void
    {
        if (!isset($claims['exp'])) {
            return;
        }

        $exp = (int) $claims['exp'];
        if (time() > $exp) {
            $expiredAt = (new DateTimeImmutable())->setTimestamp($exp);
            throw new TokenExpiredException($expiredAt);
        }
    }

    /**
     * @param array<string, mixed> $claims
     * @throws TokenIssuerException
     */
    private function checkIssuer(array $claims): void
    {
        $iss = (string) ($claims['iss'] ?? '');
        if ($iss !== $this->issuerUrl) {
            throw new TokenIssuerException($this->issuerUrl, $iss);
        }
    }

    /**
     * @param array<string, mixed> $claims
     * @throws TokenAudienceException
     */
    private function checkAudience(array $claims): void
    {
        $aud = $claims['aud'] ?? [];
        $audiences = is_array($aud) ? array_map('strval', $aud) : [(string) $aud];

        if (!in_array($this->clientId, $audiences, true)) {
            throw new TokenAudienceException((string) $this->clientId, $audiences);
        }
    }

    /**
     * @param array<string, mixed> $claims
     * @throws TokenInvalidException
     */
    private function checkIssuedAt(array $claims): void
    {
        if (!isset($claims['iat'])) {
            return;
        }

        $iat = (int) $claims['iat'];
        if ($iat > time() + self::CLOCK_SKEW_SECONDS) {
            throw new TokenInvalidException('JWT was issued in the future (beyond clock skew tolerance)');
        }
    }
}
