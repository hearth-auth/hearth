<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use Throwable;

/**
 * Thrown when a JWT's `aud` claim does not contain the configured client ID.
 */
class TokenAudienceException extends HearthException
{
    public function __construct(
        private readonly string $expectedAudience,
        /** @var string[] */
        private readonly array $actualAudiences,
        string $message = '',
        int $code = 0,
        ?Throwable $previous = null,
    ) {
        $actual = implode(', ', $actualAudiences);
        parent::__construct(
            $message ?: "Token audience mismatch: expected '{$expectedAudience}', got [{$actual}]",
            $code,
            $previous,
        );
    }

    /** Returns the audience the SDK was configured to expect. */
    public function getExpectedAudience(): string
    {
        return $this->expectedAudience;
    }

    /**
     * Returns the audiences embedded in the token.
     *
     * @return string[]
     */
    public function getActualAudiences(): array
    {
        return $this->actualAudiences;
    }
}
