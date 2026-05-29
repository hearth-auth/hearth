<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use Throwable;

/**
 * Thrown when the introspection endpoint is unreachable or returns an error response.
 */
class IntrospectionException extends HearthException
{
    public function __construct(
        string $message = 'Token introspection failed',
        private readonly ?int $httpStatus = null,
        int $code = 0,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    /** Returns the HTTP status code from the introspection endpoint, if available. */
    public function getHttpStatus(): ?int
    {
        return $this->httpStatus;
    }
}
