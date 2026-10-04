<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use Throwable;

/**
 * Thrown by the JWKS client when no key matches a token's `kid`, even after
 * one re-fetch.
 *
 * It extends JWKSFetchException so callers of JwksClient::getKey() that catch
 * that class keep working. TokenVerifier turns it into TokenInvalidException:
 * openspec/specs/sdk-support-contract/spec.md keeps `JWKSFetchError` for an unreachable or invalid JWKS
 * endpoint, and a token signed with an unknown key is a bad token.
 */
class JwksKeyNotFoundException extends JWKSFetchException
{
    public function __construct(string $kid, int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct("No key with kid '{$kid}' found in JWKS after re-fetch", $code, $previous);
    }
}
