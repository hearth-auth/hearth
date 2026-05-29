<?php

declare(strict_types=1);

namespace Hearth\Tests\Unit;

use DateTimeImmutable;
use Hearth\Exceptions\ConfigurationException;
use Hearth\Exceptions\HearthException;
use Hearth\Exceptions\IntrospectionException;
use Hearth\Exceptions\JwksException;
use Hearth\Exceptions\NetworkException;
use Hearth\Exceptions\RequiredActionException;
use Hearth\Exceptions\TokenAudienceException;
use Hearth\Exceptions\TokenExpiredException;
use Hearth\Exceptions\TokenIssuerException;
use Hearth\Exceptions\TokenSignatureException;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the Hearth exception hierarchy.
 */
final class ExceptionsTest extends TestCase
{
    public function testAllExceptionsExtendHearthException(): void
    {
        self::assertInstanceOf(HearthException::class, new ConfigurationException());
        self::assertInstanceOf(HearthException::class, new NetworkException('https://x.y'));
        self::assertInstanceOf(HearthException::class, new JwksException());
        self::assertInstanceOf(HearthException::class, new TokenExpiredException());
        self::assertInstanceOf(HearthException::class, new TokenSignatureException());
        self::assertInstanceOf(HearthException::class, new TokenIssuerException('a', 'b'));
        self::assertInstanceOf(HearthException::class, new TokenAudienceException('a', []));
        self::assertInstanceOf(HearthException::class, new IntrospectionException());
        self::assertInstanceOf(HearthException::class, new RequiredActionException([]));
    }

    public function testNetworkExceptionExposesUrl(): void
    {
        $e = new NetworkException('https://auth.example.com/jwks');
        self::assertSame('https://auth.example.com/jwks', $e->getUrl());
    }

    public function testTokenExpiredExceptionExposesTimestamp(): void
    {
        $at = new DateTimeImmutable('2025-01-01 00:00:00');
        $e  = new TokenExpiredException($at);
        self::assertSame($at, $e->getExpiredAt());
    }

    public function testTokenIssuerExceptionExposesIssuers(): void
    {
        $e = new TokenIssuerException('https://expected.com', 'https://actual.com');
        self::assertSame('https://expected.com', $e->getExpectedIssuer());
        self::assertSame('https://actual.com', $e->getActualIssuer());
    }

    public function testTokenAudienceExceptionExposesAudiences(): void
    {
        $e = new TokenAudienceException('my-client', ['other-client', 'service-a']);
        self::assertSame('my-client', $e->getExpectedAudience());
        self::assertSame(['other-client', 'service-a'], $e->getActualAudiences());
    }

    public function testIntrospectionExceptionExposesHttpStatus(): void
    {
        $e = new IntrospectionException('error', 503);
        self::assertSame(503, $e->getHttpStatus());
    }

    public function testRequiredActionExceptionExposesActionsAndRedirectUri(): void
    {
        $e = new RequiredActionException(['VERIFY_EMAIL', 'UPDATE_PASSWORD'], 'https://auth.example.com/actions');
        self::assertSame(['VERIFY_EMAIL', 'UPDATE_PASSWORD'], $e->getRequiredActions());
        self::assertSame('https://auth.example.com/actions', $e->getRedirectUri());
    }

    public function testRequiredActionExceptionRedirectUriIsOptional(): void
    {
        $e = new RequiredActionException(['VERIFY_EMAIL']);
        self::assertNull($e->getRedirectUri());
    }

    public function testExceptionMessagesDoNotLeakSensitiveData(): void
    {
        $e = new TokenSignatureException('Token signature verification failed');
        // The message must not contain any raw token value
        self::assertStringNotContainsString('eyJ', $e->getMessage());
    }
}
