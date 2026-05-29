<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use DateTimeImmutable;
use Throwable;

/**
 * Thrown when a JWT's `exp` claim is in the past.
 */
class TokenExpiredException extends HearthException
{
    public function __construct(
        private readonly ?DateTimeImmutable $expiredAt = null,
        string $message = 'Token has expired',
        int $code = 0,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    /** Returns the timestamp at which the token expired, if available. */
    public function getExpiredAt(): ?DateTimeImmutable
    {
        return $this->expiredAt;
    }
}
