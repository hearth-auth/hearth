<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use Throwable;

/**
 * Thrown when the JWKS endpoint is unreachable or returns an invalid response.
 *
 * Also thrown when a key ID (kid) referenced by a JWT is not found in the
 * cached or freshly-fetched JWKS.
 */
class JwksException extends HearthException
{
    public function __construct(string $message = 'JWKS fetch or parse failed', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
