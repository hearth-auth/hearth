<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use Throwable;

/**
 * Thrown when the JWKS endpoint is unreachable or returns an invalid response.
 *
 * Its subclass JwksKeyNotFoundException marks a `kid` absent from the JWKS;
 * TokenVerifier reports that case as TokenInvalidException.
 *
 * Conforms to §5 of the Hearth SDK Common Specification (`JWKSFetchError`).
 */
class JWKSFetchException extends HearthException
{
    public function __construct(string $message = 'JWKS fetch or parse failed', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
