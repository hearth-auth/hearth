<?php

declare(strict_types=1);

namespace Hearth;

use Hearth\Contracts\JwksClientInterface;
use Hearth\Exceptions\JWKSFetchException;
use Hearth\Exceptions\NetworkException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Throwable;

/**
 * Fetches and caches Ed25519/OKP public keys from a JWKS endpoint.
 *
 * Implements the mandatory §2 JWKS caching contract:
 *   1. Cache keys by `kid`; do not discard keys missing from the latest fetch.
 *   2. Respect `Cache-Control: max-age` from the JWKS response.
 *   3. On cache miss for a `kid`: re-fetch once before raising JWKSFetchException.
 *   4. Maximum cache age: 24 hours regardless of Cache-Control.
 *   5. Skip (do not error on) any key with an unrecognised `kty`.
 */
final class JwksClient implements JwksClientInterface
{
    private const DEFAULT_TTL_SECONDS = 300;          // 5 minutes fallback
    private const MAX_TTL_SECONDS     = 86_400;       // 24 hours hard cap

    /**
     * Per-kid cache entries: [publicKeyBytes => string, expiresAt => int (unix timestamp)].
     *
     * @var array<string, array{publicKeyBytes: string, expiresAt: int}>
     */
    private array $cache = [];

    /** Unix timestamp of the last full JWKS fetch (used to track max-age globally). */
    private int $lastFetchedAt = 0;

    /** TTL in seconds derived from the last JWKS response Cache-Control header. */
    private int $currentTtl;

    /**
     * @param string                  $jwksUri        URL of the JWKS endpoint
     * @param ClientInterface         $httpClient     PSR-18 HTTP client
     * @param RequestFactoryInterface $requestFactory PSR-17 request factory
     * @param int|null                $overrideTtl    Optional TTL override in seconds (ignores Cache-Control)
     */
    public function __construct(
        private readonly string $jwksUri,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly ?int $overrideTtl = null,
    ) {
        $this->currentTtl = $overrideTtl ?? self::DEFAULT_TTL_SECONDS;
    }

    /**
     * Returns the 32-byte raw Ed25519 public key for the given `kid`.
     *
     * On a cache miss, re-fetches the JWKS once before raising JWKSFetchException.
     *
     * @return non-empty-string Raw 32-byte Ed25519 public key
     * @throws JWKSFetchException    When the key is not found after a re-fetch
     * @throws NetworkException When the JWKS endpoint is unreachable
     */
    public function getKey(string $kid): string
    {
        if ($this->isCached($kid)) {
            return $this->cache[$kid]['publicKeyBytes'];
        }

        // On cache miss: re-fetch once per spec rule 3
        $this->fetch();

        if (!isset($this->cache[$kid])) {
            throw new JWKSFetchException("No key with kid '{$kid}' found in JWKS after re-fetch");
        }

        return $this->cache[$kid]['publicKeyBytes'];
    }

    /**
     * Forces a refresh of the JWKS cache, regardless of TTL.
     *
     * @throws NetworkException When the endpoint is unreachable
     * @throws JWKSFetchException    When the response is not valid JSON or lacks a `keys` array
     */
    public function refresh(): void
    {
        $this->fetch();
    }

    // -------------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------------

    private function isCached(string $kid): bool
    {
        if (!isset($this->cache[$kid])) {
            return false;
        }

        return time() < $this->cache[$kid]['expiresAt'];
    }

    /** Fetches the JWKS endpoint, parses OKP/Ed25519 keys, and updates the cache. */
    private function fetch(): void
    {
        $request = $this->requestFactory->createRequest('GET', $this->jwksUri);

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new NetworkException($this->jwksUri, "Failed to fetch JWKS: {$e->getMessage()}", 0, $e);
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw new JWKSFetchException("JWKS endpoint returned HTTP {$status}");
        }

        // Derive TTL: override > Cache-Control max-age > default
        $ttl = $this->overrideTtl ?? $this->parseCacheControlMaxAge($response->getHeaderLine('Cache-Control'));
        $ttl = min($ttl, self::MAX_TTL_SECONDS);

        $body = (string) $response->getBody();
        $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($data) || !isset($data['keys']) || !is_array($data['keys'])) {
            throw new JWKSFetchException('JWKS response is missing the "keys" array');
        }

        $this->lastFetchedAt = time();
        $this->currentTtl    = $ttl;
        $expiresAt           = $this->lastFetchedAt + $ttl;

        foreach ($data['keys'] as $jwk) {
            if (!is_array($jwk)) {
                continue;
            }

            // Spec rule 5: skip unrecognised kty without erroring
            $kty = $jwk['kty'] ?? null;
            if ($kty !== 'OKP') {
                continue;
            }

            $crv = $jwk['crv'] ?? null;
            if ($crv !== 'Ed25519') {
                continue;
            }

            $kid = $jwk['kid'] ?? null;
            $x   = $jwk['x'] ?? null;

            if (!is_string($kid) || $kid === '' || !is_string($x) || $x === '') {
                continue;
            }

            // Decode the base64url-encoded 32-byte public key coordinate
            $publicKeyBytes = base64_decode(strtr($x, '-_', '+/'), true);
            if ($publicKeyBytes === false || strlen($publicKeyBytes) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                continue;
            }

            // Spec rule 1: do not discard previously cached keys that are absent in new fetch
            $this->cache[$kid] = [
                'publicKeyBytes' => $publicKeyBytes,
                'expiresAt'      => $expiresAt,
            ];
        }
    }

    /**
     * Parses `max-age` from a Cache-Control header value.
     *
     * Returns the default TTL when max-age is absent or unparseable.
     */
    private function parseCacheControlMaxAge(string $header): int
    {
        if (preg_match('/\bmax-age\s*=\s*(\d+)/i', $header, $matches) === 1) {
            return (int) $matches[1];
        }

        return self::DEFAULT_TTL_SECONDS;
    }
}
