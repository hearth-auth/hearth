<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use RuntimeException;
use Throwable;

/**
 * Base exception for all Hearth SDK errors.
 *
 * Catch this class to handle any SDK-level failure in a single catch block,
 * or use a subclass for fine-grained error handling.
 */
class HearthException extends RuntimeException
{
    public function __construct(string $message = '', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
