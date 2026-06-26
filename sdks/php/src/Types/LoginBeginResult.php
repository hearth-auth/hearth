<?php

declare(strict_types=1);

namespace Hearth\Types;

/**
 * Result of {@see \Hearth\HearthClient::beginLogin()}.
 *
 * Redirect the browser to `$authorizationUrl`, then persist `$state` and
 * `$codeVerifier` in session storage so they can be verified and supplied to
 * {@see \Hearth\HearthClient::completeLogin()} on the callback route.
 */
final class LoginBeginResult
{
    public function __construct(
        /** Full PKCE authorization URL — redirect the browser here. */
        public readonly string $authorizationUrl,
        /** Random CSRF-protection value — verify against the callback `state` parameter. */
        public readonly string $state,
        /** PKCE code verifier — pass to `completeLogin()` on the callback route. */
        public readonly string $codeVerifier,
    ) {}
}
