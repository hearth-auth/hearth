<?php

declare(strict_types=1);

namespace Hearth;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Psr7\HttpFactory;
use Hearth\Exceptions\ConfigurationException;
use Hearth\Exceptions\NetworkException;
use Hearth\Types\TokenResponse;
use Hearth\Types\UserInfoResponse;
use JsonException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Throwable;

/**
 * Primary SDK entry point for resource-server and server-side authentication flows.
 *
 * Conforms to §1 (Configuration) and §3.5 (Token Verification Modes) of the
 * Hearth SDK Common Specification.
 *
 * OIDC discovery is performed lazily on first use, not at construction time.
 */
final class HearthClient
{
    /** @var array<string, mixed>|null Cached OIDC discovery document */
    private ?array $discovery = null;

    private ?JwksClient $jwksClient              = null;
    private ?TokenVerifier $tokenVerifier        = null;
    private ?IntrospectionClient $introspectionClient = null;

    private readonly ClientInterface $httpClient;
    private readonly RequestFactoryInterface $requestFactory;
    private readonly StreamFactoryInterface $streamFactory;

    /**
     * @param string      $issuerUrl               Root URL of the Hearth instance
     * @param string|null $clientId                OAuth client ID
     * @param string|null $clientSecret            OAuth client secret (required for confidential flows)
     * @param int|null    $jwksTtl                 JWKS cache TTL override in seconds
     * @param string|null $introspectionEndpoint   Override discovered introspection URL
     * @param int         $httpTimeout             Timeout for all outbound HTTP calls (seconds)
     * @param string|null $tokenAuthorizationMode  "embedded" | "introspection" | "decision"
     * @param ClientInterface|null         $httpClient     Custom PSR-18 HTTP client
     * @param RequestFactoryInterface|null $requestFactory Custom PSR-17 request factory
     * @param StreamFactoryInterface|null  $streamFactory  Custom PSR-17 stream factory
     *
     * @throws ConfigurationException When a required config combination is missing
     */
    public function __construct(
        private readonly string $issuerUrl,
        private readonly ?string $clientId = null,
        private readonly ?string $clientSecret = null,
        private readonly ?int $jwksTtl = null,
        private readonly ?string $introspectionEndpoint = null,
        private readonly int $httpTimeout = 10,
        private readonly ?string $tokenAuthorizationMode = null,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
    ) {
        $this->validateConfiguration();

        // Default to Guzzle when no PSR-18 client is injected
        $guzzle = new GuzzleClient(['timeout' => $this->httpTimeout]);
        $factory = new HttpFactory();

        $this->httpClient     = $httpClient     ?? $guzzle;
        $this->requestFactory = $requestFactory ?? $factory;
        $this->streamFactory  = $streamFactory  ?? $factory;
    }

    /**
     * Exchanges an authorization code for tokens.
     *
     * @param string $code         The authorization code from the callback
     * @param string $redirectUri  The redirect URI used in the initial authorization request
     * @param string|null $codeVerifier PKCE code verifier (required for public clients)
     *
     * @throws NetworkException        When the token endpoint is unreachable
     * @throws \RuntimeException       When the token endpoint returns an error
     */
    public function exchangeCode(string $code, string $redirectUri, ?string $codeVerifier = null): TokenResponse
    {
        $tokenEndpoint = $this->discoverEndpoint('token_endpoint');

        $params = [
            'grant_type'   => 'authorization_code',
            'code'         => $code,
            'redirect_uri' => $redirectUri,
        ];

        if ($this->clientId !== null) {
            $params['client_id'] = $this->clientId;
        }

        if ($this->clientSecret !== null) {
            $params['client_secret'] = $this->clientSecret;
        }

        if ($codeVerifier !== null) {
            $params['code_verifier'] = $codeVerifier;
        }

        $data = $this->postForm($tokenEndpoint, $params);

        return TokenResponse::fromArray($data);
    }

    /**
     * Verifies a raw access token JWT and returns typed claims.
     *
     * Honours the configured `token_authorization_mode`:
     * - `"embedded"` (default): JWKS-only verification.
     * - `"introspection"`: JWKS verification + mandatory introspection call.
     * - `"decision"`: JWKS verification only (caller must separately call `POST /oauth/authorize`).
     *
     * @throws \Hearth\Exceptions\TokenInvalidException
     * @throws \Hearth\Exceptions\TokenExpiredException
     * @throws \Hearth\Exceptions\TokenIssuerException
     * @throws \Hearth\Exceptions\TokenAudienceException
     * @throws \Hearth\Exceptions\RequiredActionException
     * @throws \Hearth\Exceptions\JWKSFetchException
     * @throws \Hearth\Exceptions\IntrospectionException When mode is "introspection"
     */
    public function verifyToken(string $rawToken): Claims
    {
        $claims = $this->getTokenVerifier()->verify($rawToken);

        if ($this->tokenAuthorizationMode === 'introspection') {
            // In introspection mode, RBAC claims from the JWT are intentionally absent;
            // callers must use IntrospectionResult for authorization data.
            $this->getIntrospectionClient()->introspect($rawToken);
        }

        return $claims;
    }

    /**
     * Fetches the UserInfo endpoint and returns a typed response.
     *
     * @throws NetworkException When the endpoint is unreachable
     */
    public function getUserInfo(string $accessToken): UserInfoResponse
    {
        $userInfoEndpoint = $this->discoverEndpoint('userinfo_endpoint');

        $request = $this->requestFactory
            ->createRequest('GET', $userInfoEndpoint)
            ->withHeader('Authorization', "Bearer {$accessToken}")
            ->withHeader('Accept', 'application/json');

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new NetworkException($userInfoEndpoint, "UserInfo request failed: {$e->getMessage()}", 0, $e);
        }

        $data = $this->decodeJsonResponse($response->getBody()->getContents(), $response->getStatusCode());

        return UserInfoResponse::fromArray($data);
    }

    // -------------------------------------------------------------------------
    // Lazy sub-client accessors
    // -------------------------------------------------------------------------

    /** Returns the JwksClient, instantiating it on first call. */
    public function getJwksClient(): JwksClient
    {
        if ($this->jwksClient === null) {
            $jwksUri = $this->discoverEndpoint('jwks_uri');
            $this->jwksClient = new JwksClient(
                $jwksUri,
                $this->httpClient,
                $this->requestFactory,
                $this->jwksTtl,
            );
        }

        return $this->jwksClient;
    }

    /** Returns the TokenVerifier, instantiating it on first call. */
    public function getTokenVerifier(): TokenVerifier
    {
        if ($this->tokenVerifier === null) {
            $this->tokenVerifier = new TokenVerifier(
                $this->getJwksClient(),
                $this->issuerUrl,
                $this->clientId,
            );
        }

        return $this->tokenVerifier;
    }

    /** Returns the IntrospectionClient, instantiating it on first call. */
    public function getIntrospectionClient(): IntrospectionClient
    {
        if ($this->introspectionClient === null) {
            $endpoint = $this->introspectionEndpoint ?? $this->discoverEndpoint('introspection_endpoint');

            if ($this->clientId === null || $this->clientSecret === null) {
                throw new ConfigurationException(
                    'Introspection requires both client_id and client_secret',
                );
            }

            $this->introspectionClient = new IntrospectionClient(
                $endpoint,
                $this->clientId,
                $this->clientSecret,
                $this->httpClient,
                $this->requestFactory,
                $this->streamFactory,
            );
        }

        return $this->introspectionClient;
    }

    // -------------------------------------------------------------------------
    // OIDC discovery
    // -------------------------------------------------------------------------

    /**
     * Discovers an endpoint URL from the OIDC discovery document.
     *
     * @throws NetworkException       When discovery is unreachable
     * @throws ConfigurationException When the endpoint key is missing from the document
     */
    public function discoverEndpoint(string $key): string
    {
        $doc = $this->getDiscoveryDocument();

        if (!isset($doc[$key]) || !is_string($doc[$key]) || $doc[$key] === '') {
            throw new ConfigurationException(
                "OIDC discovery document is missing '{$key}'. Ensure the Hearth server supports this endpoint.",
            );
        }

        return $doc[$key];
    }

    /**
     * Returns the cached OIDC discovery document, fetching it once on first call.
     *
     * @return array<string, mixed>
     * @throws NetworkException
     */
    private function getDiscoveryDocument(): array
    {
        if ($this->discovery !== null) {
            return $this->discovery;
        }

        $url     = rtrim($this->issuerUrl, '/') . '/.well-known/openid-configuration';
        $request = $this->requestFactory
            ->createRequest('GET', $url)
            ->withHeader('Accept', 'application/json');

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new NetworkException($url, "OIDC discovery failed: {$e->getMessage()}", 0, $e);
        }

        $this->discovery = $this->decodeJsonResponse($response->getBody()->getContents(), $response->getStatusCode());

        return $this->discovery;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * POST an application/x-www-form-urlencoded body and return the decoded JSON response.
     *
     * @param array<string, string> $params
     * @return array<string, mixed>
     * @throws NetworkException
     * @throws \RuntimeException
     */
    private function postForm(string $url, array $params): array
    {
        $body    = http_build_query($params);
        $request = $this->requestFactory
            ->createRequest('POST', $url)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream($body));

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new NetworkException($url, "HTTP request failed: {$e->getMessage()}", 0, $e);
        }

        return $this->decodeJsonResponse($response->getBody()->getContents(), $response->getStatusCode());
    }

    /**
     * JSON-decodes a response body; throws on non-2xx or invalid JSON.
     *
     * @return array<string, mixed>
     * @throws \RuntimeException
     */
    private function decodeJsonResponse(string $body, int $status): array
    {
        if ($status < 200 || $status >= 300) {
            throw new \RuntimeException("Server returned HTTP {$status}");
        }

        try {
            $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new \RuntimeException('Response body is not valid JSON', 0, $e);
        }

        if (!is_array($data)) {
            throw new \RuntimeException('Response body must be a JSON object');
        }

        return $data;
    }

    /** Validates constructor arguments that have inter-dependencies. */
    private function validateConfiguration(): void
    {
        if ($this->issuerUrl === '') {
            throw new ConfigurationException('issuerUrl must not be empty');
        }

        if ($this->tokenAuthorizationMode === 'introspection'
            && ($this->clientId === null || $this->clientSecret === null)
        ) {
            throw new ConfigurationException(
                'tokenAuthorizationMode "introspection" requires both clientId and clientSecret',
            );
        }
    }
}
