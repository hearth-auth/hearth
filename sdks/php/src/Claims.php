<?php

declare(strict_types=1);

namespace Hearth;

use DateTimeImmutable;

/**
 * Typed accessor for JWT claims from a verified Hearth token.
 *
 * All methods return safe defaults when a claim is absent — callers never need
 * to guard against missing claims unless the return type is nullable.
 *
 * Conforms to §4 of the Hearth SDK Common Specification.
 */
final class Claims
{
    /** @param array<string, mixed> $claims Raw decoded JWT claims payload */
    public function __construct(private readonly array $claims) {}

    // -------------------------------------------------------------------------
    // Standard OIDC claims
    // -------------------------------------------------------------------------

    /** Returns the `sub` (subject) claim — the authenticated user's ID. */
    public function subject(): string
    {
        return (string) ($this->claims['sub'] ?? '');
    }

    /** Returns the `iss` (issuer) claim. */
    public function issuer(): string
    {
        return (string) ($this->claims['iss'] ?? '');
    }

    /**
     * Returns the `aud` (audience) claim as an array.
     *
     * The JWT spec allows `aud` to be either a string or an array; this method
     * always normalises it to an array.
     *
     * @return string[]
     */
    public function audiences(): array
    {
        $aud = $this->claims['aud'] ?? [];

        return is_array($aud) ? array_map('strval', $aud) : [(string) $aud];
    }

    /**
     * Returns the `exp` (expiration) claim as a DateTimeImmutable.
     *
     * Returns null when the claim is absent (e.g. non-expiring tokens).
     */
    public function expiry(): ?DateTimeImmutable
    {
        if (!isset($this->claims['exp'])) {
            return null;
        }

        return (new DateTimeImmutable())->setTimestamp((int) $this->claims['exp']);
    }

    /**
     * Returns the `iat` (issued-at) claim as a DateTimeImmutable.
     *
     * Returns null when the claim is absent.
     */
    public function issuedAt(): ?DateTimeImmutable
    {
        if (!isset($this->claims['iat'])) {
            return null;
        }

        return (new DateTimeImmutable())->setTimestamp((int) $this->claims['iat']);
    }

    /** Returns the `jti` (JWT ID) claim, or an empty string if absent. */
    public function jwtID(): string
    {
        return (string) ($this->claims['jti'] ?? '');
    }

    /**
     * Returns the `scope` claim as a single space-delimited string.
     *
     * Returns an empty string when no scope claim is present.
     */
    public function scope(): string
    {
        return (string) ($this->claims['scope'] ?? '');
    }

    /**
     * Returns the `scope` claim split into individual scope strings.
     *
     * @return string[]
     */
    public function scopes(): array
    {
        $scope = $this->scope();
        if ($scope === '') {
            return [];
        }

        return explode(' ', $scope);
    }

    /** Returns true if the token's `scope` claim contains the given scope. */
    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes(), true);
    }

    // -------------------------------------------------------------------------
    // Hearth custom claims (§4 — Hearth custom claims reference)
    // -------------------------------------------------------------------------

    /**
     * Returns true if the `roles` claim contains the given role name.
     *
     * Returns false (never throws) when the claim is absent or malformed.
     */
    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles(), true);
    }

    /**
     * Returns true if the `permissions` claim contains the given permission string.
     *
     * Returns false (never throws) when the claim is absent or malformed.
     */
    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->permissions(), true);
    }

    /**
     * Returns true if the `groups` claim contains the given group name.
     *
     * Returns false (never throws) when the claim is absent or malformed.
     */
    public function inGroup(string $group): bool
    {
        return in_array($group, $this->groups(), true);
    }

    /**
     * Returns true if the `oid` claim exactly matches the given organization ID.
     *
     * Returns false (never throws) when the claim is absent.
     */
    public function inOrg(string $organizationId): bool
    {
        $oid = $this->claims['oid'] ?? null;

        return $oid !== null && (string) $oid === $organizationId;
    }

    /**
     * Returns the `token_type` claim: `"access"`, `"refresh"`, or `"required_action"`.
     *
     * Returns an empty string when the claim is absent.
     */
    public function tokenType(): string
    {
        return (string) ($this->claims['token_type'] ?? '');
    }

    /**
     * Returns the `oid` (organization ID) claim, or null when absent.
     *
     * This identifies the B2B tenant / organization the token was issued for.
     */
    public function organizationId(): ?string
    {
        return isset($this->claims['oid']) ? (string) $this->claims['oid'] : null;
    }

    /**
     * Returns the `org_groups` claim — group paths scoped to the organization.
     *
     * Paths follow the Keycloak convention, e.g. `/org-slug/group`.
     *
     * @return string[]
     */
    public function orgGroups(): array
    {
        return $this->claimAsStringArray('org_groups');
    }

    /**
     * Returns the raw value of any claim by name.
     *
     * Useful for custom or non-standard claims. Returns null when the claim is absent.
     */
    public function get(string $claim): mixed
    {
        return $this->claims[$claim] ?? null;
    }

    // -------------------------------------------------------------------------
    // Hearth RBAC convenience accessors (read by hasRole / hasPermission / inGroup)
    // -------------------------------------------------------------------------

    /**
     * Returns the `roles` claim as an array of role name strings.
     *
     * @return string[]
     */
    public function roles(): array
    {
        return $this->claimAsStringArray('roles');
    }

    /**
     * Returns the `permissions` claim as an array of permission strings.
     *
     * @return string[]
     */
    public function permissions(): array
    {
        return $this->claimAsStringArray('permissions');
    }

    /**
     * Returns the `groups` claim as an array of group name strings.
     *
     * @return string[]
     */
    public function groups(): array
    {
        return $this->claimAsStringArray('groups');
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Safely reads a claim expected to be a string array.
     *
     * Returns an empty array when the claim is absent, null, or not an array,
     * rather than throwing — callers should never need to handle missing RBAC claims.
     *
     * @return string[]
     */
    private function claimAsStringArray(string $claim): array
    {
        $value = $this->claims[$claim] ?? null;
        if (!is_array($value)) {
            return [];
        }

        return array_map('strval', $value);
    }
}
