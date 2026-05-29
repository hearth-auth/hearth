<?php

declare(strict_types=1);

namespace Hearth\Tests\Unit;

use DateTimeImmutable;
use Hearth\Claims;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for Claims — the typed JWT claims accessor.
 *
 * Tests are written before the implementation per the TDD contract.
 * Run with: vendor/bin/phpunit tests/Unit/ClaimsTest.php
 */
final class ClaimsTest extends TestCase
{
    private function makeClaims(array $overrides = []): Claims
    {
        return new Claims(array_merge([
            'sub'         => 'usr_abc123',
            'iss'         => 'https://auth.example.com',
            'aud'         => ['my-client'],
            'exp'         => time() + 3600,
            'iat'         => time() - 60,
            'jti'         => 'jwt-id-xyz',
            'scope'       => 'openid profile email',
            'token_type'  => 'access',
            'roles'       => ['admin', 'editor'],
            'permissions' => ['users:read', 'users:write'],
            'groups'      => ['engineering', 'backend'],
            'oid'         => 'org_tenant42',
            'org_groups'  => ['/tenant42/engineering'],
            'sid'         => 'sess_abc',
            'tid'         => 'realm_xyz',
        ], $overrides));
    }

    public function testSubjectReturnsSubClaim(): void
    {
        self::assertSame('usr_abc123', $this->makeClaims()->subject());
    }

    public function testIssuerReturnsIssClaim(): void
    {
        self::assertSame('https://auth.example.com', $this->makeClaims()->issuer());
    }

    public function testAudiencesNormalisesStringToArray(): void
    {
        $claims = $this->makeClaims(['aud' => 'single-aud']);
        self::assertSame(['single-aud'], $claims->audiences());
    }

    public function testAudiencesReturnsArrayUnchanged(): void
    {
        self::assertSame(['my-client'], $this->makeClaims()->audiences());
    }

    public function testExpiryReturnsDateTimeImmutable(): void
    {
        $exp    = time() + 3600;
        $claims = $this->makeClaims(['exp' => $exp]);
        $expiry = $claims->expiry();
        self::assertInstanceOf(DateTimeImmutable::class, $expiry);
        self::assertSame($exp, $expiry->getTimestamp());
    }

    public function testExpiryReturnsNullWhenAbsent(): void
    {
        $claims = $this->makeClaims(['exp' => null]);
        self::assertNull($this->makeClaims(array_diff_key([], ['exp' => '']))->expiry());
        // Inline null test
        self::assertNull((new Claims([]))->expiry());
    }

    public function testIssuedAtReturnsDateTimeImmutable(): void
    {
        $iat    = time() - 120;
        $claims = $this->makeClaims(['iat' => $iat]);
        $issuedAt = $claims->issuedAt();
        self::assertInstanceOf(DateTimeImmutable::class, $issuedAt);
        self::assertSame($iat, $issuedAt->getTimestamp());
    }

    public function testJwtIdReturnsJtiClaim(): void
    {
        self::assertSame('jwt-id-xyz', $this->makeClaims()->jwtID());
    }

    public function testJwtIdReturnsEmptyStringWhenAbsent(): void
    {
        self::assertSame('', (new Claims([]))->jwtID());
    }

    public function testScopeReturnsSpaceDelimitedString(): void
    {
        self::assertSame('openid profile email', $this->makeClaims()->scope());
    }

    public function testScopesReturnsParsedArray(): void
    {
        self::assertSame(['openid', 'profile', 'email'], $this->makeClaims()->scopes());
    }

    public function testHasScopeReturnsTrueForPresent(): void
    {
        self::assertTrue($this->makeClaims()->hasScope('profile'));
    }

    public function testHasScopeReturnsFalseForAbsent(): void
    {
        self::assertFalse($this->makeClaims()->hasScope('admin:write'));
    }

    public function testHasRoleReturnsTrueForPresent(): void
    {
        self::assertTrue($this->makeClaims()->hasRole('admin'));
    }

    public function testHasRoleReturnsFalseForAbsent(): void
    {
        self::assertFalse($this->makeClaims()->hasRole('superuser'));
    }

    public function testHasRoleReturnsFalseWhenClaimAbsent(): void
    {
        self::assertFalse((new Claims([]))->hasRole('admin'));
    }

    public function testHasPermissionReturnsTrueForPresent(): void
    {
        self::assertTrue($this->makeClaims()->hasPermission('users:read'));
    }

    public function testHasPermissionReturnsFalseForAbsent(): void
    {
        self::assertFalse($this->makeClaims()->hasPermission('billing:write'));
    }

    public function testInGroupReturnsTrueForPresent(): void
    {
        self::assertTrue($this->makeClaims()->inGroup('engineering'));
    }

    public function testInGroupReturnsFalseForAbsent(): void
    {
        self::assertFalse($this->makeClaims()->inGroup('sales'));
    }

    public function testInOrgReturnsTrueForExactMatch(): void
    {
        self::assertTrue($this->makeClaims()->inOrg('org_tenant42'));
    }

    public function testInOrgReturnsFalseForMismatch(): void
    {
        self::assertFalse($this->makeClaims()->inOrg('org_other'));
    }

    public function testInOrgReturnsFalseWhenClaimAbsent(): void
    {
        self::assertFalse((new Claims([]))->inOrg('org_any'));
    }

    public function testTokenTypeReturnsTokenTypeClaim(): void
    {
        self::assertSame('access', $this->makeClaims()->tokenType());
    }

    public function testOrganizationIdReturnsOidClaim(): void
    {
        self::assertSame('org_tenant42', $this->makeClaims()->organizationId());
    }

    public function testOrganizationIdReturnsNullWhenAbsent(): void
    {
        self::assertNull((new Claims([]))->organizationId());
    }

    public function testOrgGroupsReturnsOrgGroupsClaim(): void
    {
        self::assertSame(['/tenant42/engineering'], $this->makeClaims()->orgGroups());
    }

    public function testOrgGroupsReturnsEmptyArrayWhenAbsent(): void
    {
        self::assertSame([], (new Claims([]))->orgGroups());
    }

    public function testGetReturnsRawClaimValue(): void
    {
        self::assertSame('sess_abc', $this->makeClaims()->get('sid'));
    }

    public function testGetReturnsNullForAbsentClaim(): void
    {
        self::assertNull($this->makeClaims()->get('nonexistent'));
    }
}
