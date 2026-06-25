<?php

declare(strict_types=1);

namespace Hearth\Types;

/**
 * Response from the dev-only `POST /admin/bootstrap` endpoint.
 */
final class BootstrapResponse
{
    /**
     * @param string               $realmId      UUID of the bootstrapped system realm.
     * @param string               $accessToken  Long-lived admin Bearer token.
     * @param string|null          $adminUserId  UUID of the created admin user.
     * @param array<string, mixed> $raw          Full response for non-standard fields.
     */
    public function __construct(
        public readonly string $realmId,
        public readonly string $accessToken,
        public readonly ?string $adminUserId,
        public readonly array $raw,
    ) {}

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        if (!isset($data['realm_id'], $data['access_token'])) {
            throw new \InvalidArgumentException(
                'Bootstrap response is missing required fields (realm_id, access_token)',
            );
        }

        return new self(
            realmId:     (string) $data['realm_id'],
            accessToken: (string) $data['access_token'],
            adminUserId: isset($data['admin_user_id']) ? (string) $data['admin_user_id'] : null,
            raw:         $data,
        );
    }
}
