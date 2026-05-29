<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use Throwable;

/**
 * Thrown when the SDK is misconfigured.
 *
 * Examples: missing required parameters, invalid issuer URL, or a mode
 * that requires introspection credentials but none were provided.
 */
class ConfigurationException extends HearthException
{
    public function __construct(string $message = 'Invalid SDK configuration', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
