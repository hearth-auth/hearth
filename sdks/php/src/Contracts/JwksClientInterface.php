<?php

declare(strict_types=1);

namespace Hearth\Contracts;

use Hearth\Exceptions\JWKSFetchException;
use Hearth\Exceptions\JwksKeyNotFoundException;

/**
 * Contract for JWKS key-retrieval implementations.
 *
 * Extracted so that TokenVerifier (and tests) can depend on the
 * abstraction rather than the concrete final class.
 */
interface JwksClientInterface
{
    /**
     * Returns the raw Ed25519 public key bytes for the given `kid`.
     *
     * @return non-empty-string Raw public key bytes
     * @throws JwksKeyNotFoundException When the key is not found (a JWKSFetchException subclass)
     * @throws JWKSFetchException       When the endpoint is unreachable or its response is invalid
     */
    public function getKey(string $kid): string;

    /**
     * Forces a refresh of the key cache.
     *
     * @throws JWKSFetchException When the endpoint is unreachable or its response is invalid
     */
    public function refresh(): void;
}
