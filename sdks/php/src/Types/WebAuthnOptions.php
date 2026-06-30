<?php

declare(strict_types=1);

namespace Hearth\Types;

/**
 * Options returned by the WebAuthn ceremony begin endpoints.
 *
 * Contains the raw options object from the server (publicKey creation/request options)
 * and an optional session token for stateless server implementations.
 */
final class WebAuthnOptions
{
    /**
     * @param array<string, mixed> $options       Raw PublicKeyCredentialCreationOptions or
     *                                            PublicKeyCredentialRequestOptions from the server.
     * @param string|null          $sessionToken  Opaque token to pass back to the finish endpoint
     *                                            (used when the server is stateless).
     */
    public function __construct(
        public readonly array $options,
        public readonly ?string $sessionToken,
    ) {}

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $options      = $data['publicKey'] ?? $data['options'] ?? $data;
        $sessionToken = isset($data['session_token']) ? (string) $data['session_token'] : null;

        return new self(
            options:      is_array($options) ? $options : $data,
            sessionToken: $sessionToken,
        );
    }
}
