<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

/**
 * Raised when the server returns HTTP 429 Too Many Requests.
 */
final class RateLimitException extends HearthException
{
    /**
     * @param int            $retryAfter Seconds to wait before retrying (from `Retry-After` header, or 0 if absent).
     * @param string         $endpoint   URL that returned the rate-limit response.
     * @param \Throwable|null $previous
     */
    public function __construct(
        public readonly int $retryAfter,
        public readonly string $endpoint,
        string $message = '',
        \Throwable $previous = null,
    ) {
        parent::__construct(
            $message !== '' ? $message : "Rate limit exceeded for {$endpoint}" . ($retryAfter > 0 ? "; retry after {$retryAfter}s" : ''),
            429,
            $previous,
        );
    }
}
