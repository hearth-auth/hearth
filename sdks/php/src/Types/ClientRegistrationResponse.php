<?php

declare(strict_types=1);

namespace Hearth\Types;

/**
 * Response from the OAuth 2.0 Dynamic Client Registration endpoint (RFC 7591).
 */
final class ClientRegistrationResponse
{
    /**
     * @param string               $clientId               Issued client identifier.
     * @param string|null          $clientSecret           Client secret (confidential clients).
     * @param int|null             $clientSecretExpiresAt  Unix timestamp when the secret expires; 0 = never.
     * @param array<string, mixed> $raw                    Full response payload for non-standard fields.
     */
    public function __construct(
        public readonly string $clientId,
        public readonly ?string $clientSecret,
        public readonly ?int $clientSecretExpiresAt,
        public readonly array $raw,
    ) {}

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        if (!isset($data['client_id'])) {
            throw new \InvalidArgumentException(
                'Client registration response is missing required "client_id" field',
            );
        }

        return new self(
            clientId:             (string) $data['client_id'],
            clientSecret:         isset($data['client_secret']) ? (string) $data['client_secret'] : null,
            clientSecretExpiresAt: isset($data['client_secret_expires_at'])
                ? (int) $data['client_secret_expires_at']
                : null,
            raw: $data,
        );
    }
}
