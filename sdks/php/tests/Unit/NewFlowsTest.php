<?php

declare(strict_types=1);

namespace Hearth\Tests\Unit;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Hearth\Exceptions\RateLimitException;
use Hearth\Exceptions\TokenExpiredException;
use Hearth\HearthClient;
use Hearth\Types\BootstrapResponse;
use Hearth\Types\ClientRegistrationResponse;
use Hearth\Types\DeviceAuthorizationResponse;
use Hearth\Types\PermissionsResponse;
use Hearth\Types\PkceChallenge;
use Hearth\Types\TokenResponse;
use Hearth\Types\WebAuthnOptions;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Unit tests for the new OAuth flows added in HEA-1560:
 * PKCE, authorize URL, refresh, client credentials, device flow,
 * magic-link, client registration, /me/permissions, decision-mode,
 * WebAuthn, session-version, and bootstrap.
 */
final class NewFlowsTest extends TestCase
{
    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Creates a HearthClient wired to a sequential mock HTTP client. */
    private function makeClient(array $responses, array $opts = []): HearthClient
    {
        $mock    = new SequentialMockClient($responses);
        $factory = new HttpFactory();

        return new HearthClient(
            issuerUrl:    $opts['issuerUrl']    ?? 'https://auth.example.com/realms/test',
            clientId:     $opts['clientId']     ?? 'test-client',
            clientSecret: $opts['clientSecret'] ?? 's3cr3t',
            httpClient:     $mock,
            requestFactory: $factory,
            streamFactory:  $factory,
        );
    }

    /** Standard OIDC discovery document response. */
    private function discoveryResponse(): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'issuer'                        => 'https://auth.example.com/realms/test',
            'authorization_endpoint'        => 'https://auth.example.com/realms/test/authorize',
            'token_endpoint'                => 'https://auth.example.com/realms/test/token',
            'device_authorization_endpoint' => 'https://auth.example.com/realms/test/device/authorize',
            'jwks_uri'                      => 'https://auth.example.com/realms/test/.well-known/jwks',
            'userinfo_endpoint'             => 'https://auth.example.com/realms/test/userinfo',
            'introspection_endpoint'        => 'https://auth.example.com/realms/test/introspect',
            'registration_endpoint'         => 'https://auth.example.com/realms/test/register',
        ]));
    }

    private function tokenResponseData(array $extra = []): array
    {
        return array_merge([
            'access_token' => 'eyJ.tok.en',
            'token_type'   => 'Bearer',
            'expires_in'   => 3600,
        ], $extra);
    }

    // -------------------------------------------------------------------------
    // Client Credentials (§4.5.1)
    // -------------------------------------------------------------------------

    public function testClientCredentialsReturnsTokenResponse(): void
    {
        $client = $this->makeClient([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($this->tokenResponseData())),
        ]);

        $result = $client->clientCredentials();

        self::assertInstanceOf(TokenResponse::class, $result);
        self::assertSame('eyJ.tok.en', $result->accessToken);
    }

    public function testClientCredentialsSendsGrantTypeInBody(): void
    {
        $mock    = new CapturingMockClient([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($this->tokenResponseData())),
        ]);
        $factory = new HttpFactory();
        $client  = new HearthClient('https://auth.example.com/realms/test', 'tc', 'sc', httpClient: $mock, requestFactory: $factory, streamFactory: $factory);

        $client->clientCredentials();

        $tokenRequest = $mock->requests[1];
        $body = (string) $tokenRequest->getBody();
        parse_str($body, $params);

        self::assertSame('client_credentials', $params['grant_type']);
        self::assertSame('tc', $params['client_id']);
        self::assertSame('sc', $params['client_secret']);
    }

    public function testClientCredentialsIncludesScopeWhenProvided(): void
    {
        $mock    = new CapturingMockClient([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($this->tokenResponseData())),
        ]);
        $factory = new HttpFactory();
        $client  = new HearthClient('https://auth.example.com/realms/test', 'tc', 'sc', httpClient: $mock, requestFactory: $factory, streamFactory: $factory);

        $client->clientCredentials('openid profile');

        $body = (string) $mock->requests[1]->getBody();
        parse_str($body, $params);

        self::assertSame('openid profile', $params['scope']);
    }

    // -------------------------------------------------------------------------
    // Token Refresh
    // -------------------------------------------------------------------------

    public function testRefreshTokenReturnsTokenResponse(): void
    {
        $client = $this->makeClient([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($this->tokenResponseData([
                'refresh_token' => 'new-refresh',
            ]))),
        ]);

        $result = $client->refreshToken('old-refresh-token');

        self::assertInstanceOf(TokenResponse::class, $result);
        self::assertSame('new-refresh', $result->refreshToken);
    }

    public function testRefreshTokenSendsRefreshGrantInBody(): void
    {
        $mock    = new CapturingMockClient([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($this->tokenResponseData())),
        ]);
        $factory = new HttpFactory();
        $client  = new HearthClient('https://auth.example.com/realms/test', 'tc', 'sc', httpClient: $mock, requestFactory: $factory, streamFactory: $factory);

        $client->refreshToken('rt_abc');

        $body = (string) $mock->requests[1]->getBody();
        parse_str($body, $params);

        self::assertSame('refresh_token', $params['grant_type']);
        self::assertSame('rt_abc', $params['refresh_token']);
    }

    // -------------------------------------------------------------------------
    // Build Authorization URL
    // -------------------------------------------------------------------------

    public function testBuildAuthorizeUrlContainsRequiredParams(): void
    {
        $client = $this->makeClient([$this->discoveryResponse()]);

        $url = $client->buildAuthorizeUrl('https://app.example.com/callback');

        self::assertStringContainsString('response_type=code', $url);
        self::assertStringContainsString('client_id=test-client', $url);
        self::assertStringContainsString('redirect_uri=', $url);
    }

    public function testBuildAuthorizeUrlIncludesPkceParams(): void
    {
        $client = $this->makeClient([$this->discoveryResponse()]);
        $pkce   = PkceChallenge::generate();

        $url = $client->buildAuthorizeUrl(
            redirectUri: 'https://app.example.com/callback',
            pkce: $pkce,
        );

        self::assertStringContainsString('code_challenge=', $url);
        self::assertStringContainsString('code_challenge_method=S256', $url);
        self::assertStringContainsString(urlencode($pkce->codeChallenge), $url);
    }

    public function testBuildAuthorizeUrlIncludesStateAndNonce(): void
    {
        $client = $this->makeClient([$this->discoveryResponse()]);

        $url = $client->buildAuthorizeUrl(
            redirectUri: 'https://app.example.com/callback',
            state: 'random-state',
            nonce: 'random-nonce',
            scope: 'openid profile',
        );

        self::assertStringContainsString('state=random-state', $url);
        self::assertStringContainsString('nonce=random-nonce', $url);
        self::assertStringContainsString('scope=', $url);
    }

    // -------------------------------------------------------------------------
    // Device Authorization Flow (§4.5.2)
    // -------------------------------------------------------------------------

    public function testStartDeviceFlowReturnsDeviceAuthorizationResponse(): void
    {
        $client = $this->makeClient([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'device_code'      => 'dev_abc',
                'user_code'        => 'ABCD-1234',
                'verification_uri' => 'https://auth.example.com/activate',
                'expires_in'       => 600,
                'interval'         => 5,
            ])),
        ]);

        $result = $client->startDeviceFlow();

        self::assertInstanceOf(DeviceAuthorizationResponse::class, $result);
        self::assertSame('dev_abc', $result->deviceCode);
        self::assertSame('ABCD-1234', $result->userCode);
        self::assertSame(5, $result->interval);
    }

    public function testStartDeviceFlowIncludesScopeWhenProvided(): void
    {
        $mock    = new CapturingMockClient([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'device_code'      => 'd',
                'user_code'        => 'U',
                'verification_uri' => 'https://v',
                'expires_in'       => 600,
                'interval'         => 5,
            ])),
        ]);
        $factory = new HttpFactory();
        $client  = new HearthClient('https://auth.example.com/realms/test', 'tc', 'sc', httpClient: $mock, requestFactory: $factory, streamFactory: $factory);

        $client->startDeviceFlow('openid');

        $body = (string) $mock->requests[1]->getBody();
        parse_str($body, $params);

        self::assertSame('openid', $params['scope']);
    }

    public function testPollDeviceTokenReturnsTokenOnSuccess(): void
    {
        $client = $this->makeClient([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($this->tokenResponseData())),
        ]);

        $result = $client->pollDeviceToken('dev_abc', 5, fn() => null);

        self::assertInstanceOf(TokenResponse::class, $result);
        self::assertSame('eyJ.tok.en', $result->accessToken);
    }

    public function testPollDeviceTokenHandlesAuthorizationPendingTransparently(): void
    {
        $client = $this->makeClient([
            $this->discoveryResponse(),
            // First poll: pending
            new Response(400, ['Content-Type' => 'application/json'], json_encode(['error' => 'authorization_pending'])),
            // Second poll: success
            new Response(200, ['Content-Type' => 'application/json'], json_encode($this->tokenResponseData())),
        ]);

        // no-op sleep injected — must NOT throw on authorization_pending
        $result = $client->pollDeviceToken('dev_abc', 5, fn() => null);

        self::assertSame('eyJ.tok.en', $result->accessToken);
    }

    public function testPollDeviceTokenHandlesSlowDownByIncreasingInterval(): void
    {
        $sleepCalls = [];

        $client = $this->makeClient([
            $this->discoveryResponse(),
            new Response(400, ['Content-Type' => 'application/json'], json_encode(['error' => 'slow_down'])),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($this->tokenResponseData())),
        ]);

        $client->pollDeviceToken('dev_abc', 5, function (int $seconds) use (&$sleepCalls): void {
            $sleepCalls[] = $seconds;
        });

        // After slow_down, the interval should have increased by 5
        self::assertCount(2, $sleepCalls);
        self::assertSame(5, $sleepCalls[0]);   // initial interval sleep (before first poll)
        self::assertSame(10, $sleepCalls[1]);  // increased by 5 after slow_down
    }

    public function testPollDeviceTokenThrowsTokenExpiredExceptionOnExpiredToken(): void
    {
        $client = $this->makeClient([
            $this->discoveryResponse(),
            new Response(400, ['Content-Type' => 'application/json'], json_encode(['error' => 'expired_token'])),
        ]);

        $this->expectException(TokenExpiredException::class);
        $client->pollDeviceToken('dev_abc', 5, fn() => null);
    }

    // -------------------------------------------------------------------------
    // Magic Link (§4.5.3)
    // -------------------------------------------------------------------------

    public function testRequestMagicLinkSucceedsOn202(): void
    {
        $mock    = new CapturingMockClient([
            new Response(202, [], json_encode(['message' => 'If an account exists, a magic link has been sent'])),
        ]);
        $factory = new HttpFactory();
        $client  = new HearthClient('https://auth.example.com/realms/test', httpClient: $mock, requestFactory: $factory, streamFactory: $factory);

        // A 202 response is a success and must not throw.
        $client->requestMagicLink('user@example.com');

        // Exactly one request was dispatched, carrying the requested email.
        self::assertCount(1, $mock->requests);
        self::assertSame('POST', $mock->requests[0]->getMethod());
        self::assertSame(
            ['email' => 'user@example.com'],
            json_decode((string) $mock->requests[0]->getBody(), true),
        );
    }

    public function testRequestMagicLinkThrowsRateLimitExceptionOn429(): void
    {
        $client = $this->makeClient([
            new Response(429, ['Retry-After' => '60'], ''),
        ]);

        $this->expectException(RateLimitException::class);
        $client->requestMagicLink('user@example.com');
    }

    public function testRequestMagicLinkSendsToCorrectEndpoint(): void
    {
        $mock    = new CapturingMockClient([
            new Response(202, [], '{}'),
        ]);
        $factory = new HttpFactory();
        $client  = new HearthClient('https://auth.example.com/realms/test', httpClient: $mock, requestFactory: $factory, streamFactory: $factory);

        $client->requestMagicLink('user@example.com');

        $req = $mock->requests[0];
        self::assertStringContainsString('/v1/', (string) $req->getUri());
        self::assertStringContainsString('magic-link', (string) $req->getUri());
        self::assertSame('POST', $req->getMethod());
    }

    public function testExchangeMagicLinkReturnsTokenResponse(): void
    {
        $client = $this->makeClient([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($this->tokenResponseData())),
        ]);

        $result = $client->exchangeMagicLink('magic-token-xyz');

        self::assertInstanceOf(TokenResponse::class, $result);
        self::assertSame('eyJ.tok.en', $result->accessToken);
    }

    public function testExchangeMagicLinkSendsMagicLinkGrantWithTokenInBody(): void
    {
        $mock    = new CapturingMockClient([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($this->tokenResponseData())),
        ]);
        $factory = new HttpFactory();
        $client  = new HearthClient('https://auth.example.com/realms/test', 'tc', 'sc', httpClient: $mock, requestFactory: $factory, streamFactory: $factory);

        $client->exchangeMagicLink('magic-token-xyz');

        $body = (string) $mock->requests[1]->getBody();
        parse_str($body, $params);

        self::assertSame('urn:hearth:grant-type:magic-link', $params['grant_type']);
        self::assertSame('magic-token-xyz', $params['token']);
        self::assertSame('tc', $params['client_id']);
    }

    // -------------------------------------------------------------------------
    // Client Registration (RFC 7591)
    // -------------------------------------------------------------------------

    public function testRegisterClientReturnsClientRegistrationResponse(): void
    {
        $client = $this->makeClient([
            $this->discoveryResponse(),
            new Response(201, ['Content-Type' => 'application/json'], json_encode([
                'client_id'     => 'new-client-id',
                'client_secret' => 'new-client-secret',
                'client_secret_expires_at' => 0,
            ])),
        ]);

        $result = $client->registerClient(['client_name' => 'My App', 'redirect_uris' => ['https://app.example.com/cb']]);

        self::assertInstanceOf(ClientRegistrationResponse::class, $result);
        self::assertSame('new-client-id', $result->clientId);
        self::assertSame('new-client-secret', $result->clientSecret);
    }

    // -------------------------------------------------------------------------
    // /v1/me/permissions
    // -------------------------------------------------------------------------

    public function testGetMyPermissionsReturnsPermissionsResponse(): void
    {
        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'permissions' => ['read:users', 'write:posts'],
            ])),
        ]);

        $result = $client->getMyPermissions('access-token-abc');

        self::assertInstanceOf(PermissionsResponse::class, $result);
        self::assertTrue($result->hasPermission('read:users'));
        self::assertFalse($result->hasPermission('delete:all'));
    }

    public function testGetMyPermissionsCallsCorrectEndpointWithBearer(): void
    {
        $mock    = new CapturingMockClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['permissions' => []])),
        ]);
        $factory = new HttpFactory();
        $client  = new HearthClient('https://auth.example.com/realms/test', httpClient: $mock, requestFactory: $factory, streamFactory: $factory);

        $client->getMyPermissions('my-access-token');

        $req = $mock->requests[0];
        self::assertStringContainsString('/me/permissions', (string) $req->getUri());
        self::assertSame('Bearer my-access-token', $req->getHeaderLine('Authorization'));
    }

    // -------------------------------------------------------------------------
    // Decision-mode check
    // -------------------------------------------------------------------------

    public function testCheckDecisionReturnsAuthorizationResult(): void
    {
        $client = $this->makeClient([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['allowed' => true])),
        ]);

        $result = $client->checkDecision('access-token', ['resource' => '/api/posts', 'action' => 'read']);

        self::assertArrayHasKey('allowed', $result);
        self::assertTrue($result['allowed']);
    }

    // -------------------------------------------------------------------------
    // WebAuthn
    // -------------------------------------------------------------------------

    public function testStartWebAuthnRegistrationReturnsWebAuthnOptions(): void
    {
        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'publicKey' => ['challenge' => 'abc123', 'rp' => ['name' => 'Hearth']],
                'session_token' => 'sess_xyz',
            ])),
        ]);

        $result = $client->startWebAuthnRegistration('access-tok');

        self::assertInstanceOf(WebAuthnOptions::class, $result);
        self::assertArrayHasKey('challenge', $result->options);
        self::assertSame('sess_xyz', $result->sessionToken);
    }

    public function testFinishWebAuthnRegistrationSendsCredentialToFinishEndpoint(): void
    {
        $mock    = new CapturingMockClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['verified' => true])),
        ]);
        $factory = new HttpFactory();
        $client  = new HearthClient('https://auth.example.com/realms/test', httpClient: $mock, requestFactory: $factory, streamFactory: $factory);

        $client->finishWebAuthnRegistration('access-tok', ['id' => 'cred-id', 'response' => []]);

        $req = $mock->requests[0];
        self::assertStringContainsString('register', (string) $req->getUri());
        self::assertSame('POST', $req->getMethod());
    }

    public function testStartWebAuthnAuthenticationReturnsWebAuthnOptions(): void
    {
        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'publicKey' => ['challenge' => 'xyz789', 'rpId' => 'auth.example.com'],
                'session_token' => 'sess_auth',
            ])),
        ]);

        $result = $client->startWebAuthnAuthentication();

        self::assertInstanceOf(WebAuthnOptions::class, $result);
        self::assertSame('sess_auth', $result->sessionToken);
    }

    public function testFinishWebAuthnAuthenticationReturnsTokenResponse(): void
    {
        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode($this->tokenResponseData())),
        ]);

        $result = $client->finishWebAuthnAuthentication(['id' => 'cred-id', 'response' => []]);

        self::assertInstanceOf(TokenResponse::class, $result);
        self::assertSame('eyJ.tok.en', $result->accessToken);
    }

    // -------------------------------------------------------------------------
    // Session Version Polling
    // -------------------------------------------------------------------------

    public function testGetSessionVersionReturnsInteger(): void
    {
        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['version' => 7])),
        ]);

        $version = $client->getSessionVersion('access-tok', 'session-id-123');

        self::assertSame(7, $version);
    }

    public function testGetSessionVersionCallsSessionVersionEndpoint(): void
    {
        $mock    = new CapturingMockClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['version' => 1])),
        ]);
        $factory = new HttpFactory();
        $client  = new HearthClient('https://auth.example.com/realms/test', httpClient: $mock, requestFactory: $factory, streamFactory: $factory);

        $client->getSessionVersion('access-tok', 'sid-abc');

        $req = $mock->requests[0];
        self::assertStringContainsString('sid-abc', (string) $req->getUri());
        self::assertStringContainsString('version', (string) $req->getUri());
        self::assertSame('GET', $req->getMethod());
    }

    // -------------------------------------------------------------------------
    // Bootstrap (dev-only)
    // -------------------------------------------------------------------------

    public function testBootstrapReturnsBootstrapResponse(): void
    {
        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'realm_id'    => 'realm-uuid',
                'access_token' => 'admin-token',
                'admin_user_id' => 'user-uuid',
            ])),
        ]);

        $result = $client->bootstrap();

        self::assertInstanceOf(BootstrapResponse::class, $result);
        self::assertSame('realm-uuid', $result->realmId);
        self::assertSame('admin-token', $result->accessToken);
    }
}

// -------------------------------------------------------------------------
// Test helpers
// -------------------------------------------------------------------------

/**
 * Minimal PSR-18 mock client that returns responses in sequence.
 */
final class SequentialMockClient implements ClientInterface
{
    private int $index = 0;

    /** @param ResponseInterface[] $responses */
    public function __construct(private readonly array $responses) {}

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        if (!isset($this->responses[$this->index])) {
            throw new \LogicException(
                sprintf('No mock response configured for request #%d to %s', $this->index, $request->getUri()),
            );
        }

        return $this->responses[$this->index++];
    }
}

/**
 * PSR-18 mock client that captures requests for assertion and returns responses in sequence.
 */
final class CapturingMockClient implements ClientInterface
{
    private int $index = 0;

    /** @var RequestInterface[] */
    public array $requests = [];

    /** @param ResponseInterface[] $responses */
    public function __construct(private readonly array $responses) {}

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;

        if (!isset($this->responses[$this->index])) {
            throw new \LogicException(
                sprintf('No mock response configured for request #%d to %s', $this->index, $request->getUri()),
            );
        }

        return $this->responses[$this->index++];
    }
}
