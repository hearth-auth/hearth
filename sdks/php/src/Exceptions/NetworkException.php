<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use Throwable;

/**
 * Thrown when an HTTP request to a Hearth endpoint fails.
 *
 * Covers OIDC discovery failures and any transport-level error (connection
 * refused, timeout, DNS failure). A JWKS fetch failure is a JWKSFetchException.
 */
class NetworkException extends HearthException
{
    /** @param string $url The URL that could not be reached */
    public function __construct(
        private readonly string $url,
        string $message = '',
        int $code = 0,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message ?: "Network request failed for: {$url}", $code, $previous);
    }

    /** Returns the URL that triggered the network failure. */
    public function getUrl(): string
    {
        return $this->url;
    }
}
