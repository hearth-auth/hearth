<?php

declare(strict_types=1);

namespace Hearth\Tests\Unit;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Hearth\HearthClient;
use Hearth\Types\LoginBeginResult;
use Hearth\Types\TokenResponse;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Unit tests for HearthClient::beginLogin() and completeLogin() (HEA-1592).
 */
final class LoginTest extends TestCase
{
    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function makeClient(array $responses, array $opts = []): HearthClient
    {
        $mock    = new LoginSequentialMockClient($responses);
        $factory = new HttpFactory();

        return new HearthClient(
            issuerUrl:      $opts['issuerUrl']    ?? 'https://auth.example.com',
            clientId:       $opts['clientId']     ?? 'test-client',
            clientSecret:   $opts['clientSecret'] ?? 's3cr3t',
            httpClient:     $mock,
            requestFactory: $factory,
            streamFactory:  $factory,
        );
    }

    private function discoveryResponse(): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'issuer'                 => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/authorize',
            'token_endpoint'         => 'https://auth.example.com/token',
            'jwks_uri'               => 'https://auth.example.com/.well-known/jwks.json',
        ]));
    }

    private function tokenResponseData(): array
    {
        return ['access_token' => 'eyJ.tok.en', 'token_type' => 'Bearer', 'expires_in' => 3600];
    }

    // -------------------------------------------------------------------------
    // beginLogin
    // -------------------------------------------------------------------------

    public function testBeginLoginReturnsLoginBeginResult(): void
    {
        $client = $this->makeClient([$this->discoveryResponse()]);
        $result = $client->beginLogin('https://app.example.com/callback');

        self::assertInstanceOf(LoginBeginResult::class, $result);
        self::assertNotEmpty($result->authorizationUrl);
        self::assertNotEmpty($result->state);
        self::assertNotEmpty($result->codeVerifier);
    }

    public function testBeginLoginCodeChallengeMatchesVerifier(): void
    {
        $client = $this->makeClient([$this->discoveryResponse()]);
        $result = $client->beginLogin('https://app.example.com/callback');

        parse_str(parse_url($result->authorizationUrl, PHP_URL_QUERY), $params);
        $challenge = $params['code_challenge'] ?? '';

        $expected = rtrim(strtr(base64_encode(hash('sha256', $result->codeVerifier, true)), '+/', '-_'), '=');
        self::assertSame($expected, $challenge, 'code_challenge must be BASE64URL(SHA256(codeVerifier))');
    }

    public function testBeginLoginStateAppearsInUrl(): void
    {
        $client = $this->makeClient([$this->discoveryResponse()]);
        $result = $client->beginLogin('https://app.example.com/callback');

        parse_str(parse_url($result->authorizationUrl, PHP_URL_QUERY), $params);
        self::assertSame($result->state, $params['state'] ?? '', 'state in URL must match returned state');
    }

    public function testBeginLoginUrlContainsRequiredParams(): void
    {
        $client = $this->makeClient([$this->discoveryResponse()]);
        $result = $client->beginLogin('https://app.example.com/callback', 'openid profile');

        parse_str(parse_url($result->authorizationUrl, PHP_URL_QUERY), $params);
        self::assertSame('code', $params['response_type'] ?? '');
        self::assertSame('test-client', $params['client_id'] ?? '');
        self::assertSame('https://app.example.com/callback', $params['redirect_uri'] ?? '');
        self::assertSame('openid profile', $params['scope'] ?? '');
        self::assertSame('S256', $params['code_challenge_method'] ?? '');
    }

    public function testBeginLoginDefaultsScopeToOpenid(): void
    {
        $client = $this->makeClient([$this->discoveryResponse()]);
        $result = $client->beginLogin('https://app.example.com/callback');

        parse_str(parse_url($result->authorizationUrl, PHP_URL_QUERY), $params);
        self::assertSame('openid', $params['scope'] ?? '');
    }

    // -------------------------------------------------------------------------
    // completeLogin
    // -------------------------------------------------------------------------

    public function testCompleteLoginReturnsTokenResponse(): void
    {
        $client = $this->makeClient([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($this->tokenResponseData())),
        ]);

        $result = $client->completeLogin('auth-code-xyz', 'my-verifier-abc', 'https://app.example.com/callback');

        self::assertInstanceOf(TokenResponse::class, $result);
        self::assertSame('eyJ.tok.en', $result->accessToken);
    }

    public function testCompleteLoginSendsCodeVerifierToTokenEndpoint(): void
    {
        $mock    = new LoginCapturingMockClient([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($this->tokenResponseData())),
        ]);
        $factory = new HttpFactory();
        $client  = new HearthClient(
            issuerUrl:      'https://auth.example.com',
            clientId:       'test-client',
            clientSecret:   's3cr3t',
            httpClient:     $mock,
            requestFactory: $factory,
            streamFactory:  $factory,
        );

        $client->completeLogin('auth-code-xyz', 'my-verifier-abc', 'https://app.example.com/callback');

        // The second request is to the token endpoint
        $tokenRequest = $mock->requests[1] ?? $mock->requests[0];
        $body         = (string) $tokenRequest->getBody();
        parse_str($body, $params);

        self::assertSame('my-verifier-abc', $params['code_verifier'] ?? '', 'code_verifier must be sent to token endpoint');
        self::assertSame('auth-code-xyz', $params['code'] ?? '', 'code must be sent to token endpoint');
        self::assertSame('authorization_code', $params['grant_type'] ?? '');
    }
}

// ── Test-local helpers ────────────────────────────────────────────────────────

final class LoginSequentialMockClient implements ClientInterface
{
    private int $index = 0;

    /** @param ResponseInterface[] $responses */
    public function __construct(private readonly array $responses) {}

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        return $this->responses[$this->index++]
            ?? throw new \LogicException("No mock response for request #{$this->index}");
    }
}

final class LoginCapturingMockClient implements ClientInterface
{
    private int $index = 0;
    /** @var RequestInterface[] */
    public array $requests = [];

    /** @param ResponseInterface[] $responses */
    public function __construct(private readonly array $responses) {}

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;
        return $this->responses[$this->index++]
            ?? throw new \LogicException("No mock response for request #{$this->index}");
    }
}
