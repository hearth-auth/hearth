<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use Throwable;

/**
 * Thrown when a JWT's `iss` claim does not match the configured issuer URL.
 */
class TokenIssuerException extends HearthException
{
    public function __construct(
        private readonly string $expectedIssuer,
        private readonly string $actualIssuer,
        string $message = '',
        int $code = 0,
        ?Throwable $previous = null,
    ) {
        parent::__construct(
            $message ?: "Token issuer mismatch: expected '{$expectedIssuer}', got '{$actualIssuer}'",
            $code,
            $previous,
        );
    }

    /** Returns the issuer URL the SDK was configured to expect. */
    public function getExpectedIssuer(): string
    {
        return $this->expectedIssuer;
    }

    /** Returns the issuer URL embedded in the token. */
    public function getActualIssuer(): string
    {
        return $this->actualIssuer;
    }
}
