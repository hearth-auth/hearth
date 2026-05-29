<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use Throwable;

/**
 * Thrown when a JWT's signature is invalid, the token is malformed,
 * or the algorithm does not match the expected `EdDSA`.
 */
class TokenSignatureException extends HearthException
{
    public function __construct(string $message = 'Token signature verification failed', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
