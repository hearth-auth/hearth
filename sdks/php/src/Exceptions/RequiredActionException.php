<?php

declare(strict_types=1);

namespace Hearth\Exceptions;

use Throwable;

/**
 * Thrown when a token has `token_type === "required_action"`.
 *
 * This token is valid but scoped only to completing pending required actions
 * (e.g. email verification, password change). It must NOT be accepted for
 * general API access.
 */
class RequiredActionException extends HearthException
{
    /**
     * @param string[] $requiredActions Pending action names from the `required_actions` claim
     * @param string|null $redirectUri  Optional URL to the Hearth interstitial page
     */
    public function __construct(
        private readonly array $requiredActions,
        private readonly ?string $redirectUri = null,
        string $message = 'Token requires completing pending actions before access is granted',
        int $code = 0,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * Returns the pending action names from the token's `required_actions` claim.
     *
     * @return string[]
     */
    public function getRequiredActions(): array
    {
        return $this->requiredActions;
    }

    /**
     * Returns the URL to the Hearth required-actions interstitial page, if provided.
     *
     * Applications should redirect the user to this URL when present.
     */
    public function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }
}
