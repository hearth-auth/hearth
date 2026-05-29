<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use DateTimeImmutable;
use Throwable;

/**
 * Thrown when the JWT `nbf` (not-before) claim is in the future beyond the
 * allowed clock skew tolerance.
 *
 * Conforms to §5 of the Hearth SDK Common Specification (`TokenNotYetValidError`).
 */
class TokenNotYetValidException extends HearthException
{
    /**
     * @param DateTimeImmutable|null $notBefore The `nbf` timestamp from the token, or null if absent
     */
    public function __construct(
        private readonly ?DateTimeImmutable $notBefore = null,
        string $message = 'Token is not yet valid',
        int $code = 0,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * Returns the not-before timestamp from the token's `nbf` claim.
     */
    public function getNotBefore(): ?DateTimeImmutable
    {
        return $this->notBefore;
    }
}
