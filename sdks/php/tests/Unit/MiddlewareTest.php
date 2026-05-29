<?php

declare(strict_types=1);

namespace Hearth\Tests\Unit;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\ServerRequest;
use Hearth\Claims;
use Hearth\Contracts\TokenVerifierInterface;
use Hearth\Exceptions\RequiredActionException;
use Hearth\Exceptions\TokenInvalidException;
use Hearth\Middleware\HearthMiddleware;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Unit tests for HearthMiddleware — PSR-15 JWT authentication middleware.
 */
final class MiddlewareTest extends TestCase
{
    private TokenVerifierInterface&MockObject $verifier;
    private HearthMiddleware $middleware;
    private HttpFactory $factory;

    protected function setUp(): void
    {
        $this->verifier    = $this->createMock(TokenVerifierInterface::class);
        $this->factory     = new HttpFactory();
        $this->middleware  = new HearthMiddleware($this->verifier, $this->factory);
    }

    private function makeRequest(string $authHeader = ''): ServerRequestInterface
    {
        $request = new ServerRequest('GET', 'https://api.example.com/protected');
        if ($authHeader !== '') {
            $request = $request->withHeader('Authorization', $authHeader);
        }

        return $request;
    }

    private function makeHandler(?Claims $injectClaims = null): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler
            ->method('handle')
            ->willReturnCallback(function (ServerRequestInterface $req) use ($injectClaims): ResponseInterface {
                if ($injectClaims !== null) {
                    // Verify claims were injected into the request attribute
                    $attrs = $req->getAttribute(HearthMiddleware::CLAIMS_ATTRIBUTE);
                    if ($attrs !== $injectClaims) {
                        throw new \RuntimeException('Claims not injected');
                    }
                }

                return $this->factory->createResponse(200);
            });

        return $handler;
    }

    public function testReturns401WhenNoAuthorizationHeader(): void
    {
        $response = $this->middleware->process($this->makeRequest(), $this->createMock(RequestHandlerInterface::class));
        self::assertSame(401, $response->getStatusCode());
    }

    public function testReturns401WhenBearerPrefixMissing(): void
    {
        $response = $this->middleware->process($this->makeRequest('Basic dXNlcjpwYXNz'), $this->createMock(RequestHandlerInterface::class));
        self::assertSame(401, $response->getStatusCode());
    }

    public function testReturns401OnInvalidToken(): void
    {
        $this->verifier
            ->method('verify')
            ->willThrowException(new TokenInvalidException('bad sig'));

        $response = $this->middleware->process($this->makeRequest('Bearer bad.token.here'), $this->createMock(RequestHandlerInterface::class));
        self::assertSame(401, $response->getStatusCode());
    }

    public function testSetsWwwAuthenticateHeaderOn401(): void
    {
        $response = $this->middleware->process($this->makeRequest(), $this->createMock(RequestHandlerInterface::class));
        self::assertStringContainsString('Bearer realm="hearth"', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testReturns401OnRequiredActionToken(): void
    {
        $this->verifier
            ->method('verify')
            ->willThrowException(new RequiredActionException(['VERIFY_EMAIL']));

        $response = $this->middleware->process($this->makeRequest('Bearer ra.token.here'), $this->createMock(RequestHandlerInterface::class));
        self::assertSame(401, $response->getStatusCode());
    }

    public function testInjectsClaimsAndCallsNextOnValidToken(): void
    {
        $claims = new Claims(['sub' => 'usr_1', 'iss' => 'https://auth.example.com', 'token_type' => 'access']);

        $this->verifier
            ->method('verify')
            ->willReturn($claims);

        $capturedClaims = null;
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler
            ->method('handle')
            ->willReturnCallback(function (ServerRequestInterface $req) use (&$capturedClaims): ResponseInterface {
                $capturedClaims = $req->getAttribute(HearthMiddleware::CLAIMS_ATTRIBUTE);

                return $this->factory->createResponse(200);
            });

        $response = $this->middleware->process($this->makeRequest('Bearer valid.jwt.here'), $handler);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame($claims, $capturedClaims);
    }

    public function testDoesNotCallHandlerOnAuthFailure(): void
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $this->middleware->process($this->makeRequest(), $handler);
    }
}
