<?php

declare(strict_types=1);

namespace Hearth\Contracts;

use Hearth\Claims;
use Hearth\Exceptions\JwksException;
use Hearth\Exceptions\RequiredActionException;
use Hearth\Exceptions\TokenAudienceException;
use Hearth\Exceptions\TokenExpiredException;
use Hearth\Exceptions\TokenIssuerException;
use Hearth\Exceptions\TokenSignatureException;

/**
 * Contract for JWT verification implementations.
 *
 * Extracted so that HearthMiddleware (and tests) can depend on the
 * abstraction rather than the concrete final class.
 */
interface TokenVerifierInterface
{
    /**
     * Verifies and decodes a raw JWT string, returning a typed Claims accessor.
     *
     * @throws TokenSignatureException  On malformed JWT or invalid signature
     * @throws JwksException            When the signing key cannot be resolved
     * @throws TokenExpiredException    When `exp` is in the past
     * @throws TokenIssuerException     When `iss` does not match
     * @throws TokenAudienceException   When `aud` does not include the client ID
     * @throws RequiredActionException  When `token_type === "required_action"`
     */
    public function verify(string $rawToken): Claims;
}
