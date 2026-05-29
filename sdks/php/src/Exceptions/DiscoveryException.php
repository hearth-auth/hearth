<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use Throwable;

/**
 * Thrown when the OIDC discovery endpoint is unreachable or returns invalid JSON.
 *
 * Conforms to §5 of the Hearth SDK Common Specification (`DiscoveryError`).
 */
class DiscoveryException extends HearthException
{
    public function __construct(string $message = 'OIDC discovery endpoint unreachable or returned invalid JSON', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
