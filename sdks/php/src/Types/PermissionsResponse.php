<?php

declare(strict_types=1);

namespace Hearth\Types;

/**
 * Response from the `GET /v1/me/permissions` endpoint.
 */
final class PermissionsResponse
{
    /**
     * @param string[] $permissions All permission strings granted to the authenticated user.
     */
    public function __construct(
        public readonly array $permissions,
    ) {}

    /** Returns true if the given permission string is present. */
    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->permissions, true);
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $raw = $data['permissions'] ?? [];
        $permissions = is_array($raw) ? array_map('strval', $raw) : [];

        return new self($permissions);
    }
}
