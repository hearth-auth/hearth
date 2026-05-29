<?php

declare(strict_types=1);

namespace Hearth\Types;

/**
 * Result of an RFC 7662 token introspection call.
 *
 * When `active` is false, all other fields will be null or empty.
 */
final class IntrospectionResult
{
    /**
     * @param bool        $active    Whether the token is currently active
     * @param string|null $sub       Subject identifier (user ID)
     * @param int|null    $exp       Expiration time (Unix timestamp)
     * @param int|null    $iat       Issued-at time (Unix timestamp)
     * @param string|null $iss       Issuer
     * @param string[]    $aud       Audiences
     * @param string|null $scope     Space-delimited scope string
     * @param string|null $clientId  OAuth client ID
     * @param string|null $tokenType Token type identifier
     * @param array<string, mixed> $extra Non-standard claims
     */
    public function __construct(
        public readonly bool $active,
        public readonly ?string $sub = null,
        public readonly ?int $exp = null,
        public readonly ?int $iat = null,
        public readonly ?string $iss = null,
        public readonly array $aud = [],
        public readonly ?string $scope = null,
        public readonly ?string $clientId = null,
        public readonly ?string $tokenType = null,
        public readonly array $extra = [],
    ) {}

    /**
     * Construct from a raw introspection JSON response body.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $reserved = ['active', 'sub', 'exp', 'iat', 'iss', 'aud', 'scope', 'client_id', 'token_type'];

        $aud = $data['aud'] ?? [];
        if (is_string($aud)) {
            $aud = [$aud];
        }

        return new self(
            active: (bool) ($data['active'] ?? false),
            sub: isset($data['sub']) ? (string) $data['sub'] : null,
            exp: isset($data['exp']) ? (int) $data['exp'] : null,
            iat: isset($data['iat']) ? (int) $data['iat'] : null,
            iss: isset($data['iss']) ? (string) $data['iss'] : null,
            aud: $aud,
            scope: isset($data['scope']) ? (string) $data['scope'] : null,
            clientId: isset($data['client_id']) ? (string) $data['client_id'] : null,
            tokenType: isset($data['token_type']) ? (string) $data['token_type'] : null,
            extra: array_diff_key($data, array_flip($reserved)),
        );
    }
}
