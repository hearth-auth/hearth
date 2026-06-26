<?php

declare(strict_types=1);

namespace Hearth;

use DateTimeImmutable;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Psr7\HttpFactory;
use Hearth\Exceptions\ConfigurationException;
use Hearth\Exceptions\NetworkException;
use Hearth\Exceptions\RateLimitException;
use Hearth\Exceptions\TokenExpiredException;
use Hearth\Types\BootstrapResponse;
use Hearth\Types\ClientRegistrationResponse;
use Hearth\Types\DeviceAuthorizationResponse;
use Hearth\Types\LoginBeginResult;
use Hearth\Types\PermissionsResponse;
use Hearth\Types\PkceChallenge;
use Hearth\Types\TokenResponse;
use Hearth\Types\UserInfoResponse;
use Hearth\Types\WebAuthnOptions;
use JsonException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Throwable;

/**
 * Primary SDK entry point for resource-server and server-side authentication flows.
 *
 * Conforms to §1 (Configuration), §3.5 (Token Verification Modes), §4.5 (Required OAuth Flows),
 * and §7 (PKCE & Browser Flows) of the Hearth SDK Common Specification.
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
        $guzzle  = new GuzzleClient(['timeout' => $this->httpTimeout]);
        $factory = new HttpFactory();

        $this->httpClient     = $httpClient     ?? $guzzle;
        $this->requestFactory = $requestFactory ?? $factory;
        $this->streamFactory  = $streamFactory  ?? $factory;
    }

    // =========================================================================
    // PKCE (RFC 7636)
    // =========================================================================

    /**
     * Generates a cryptographically random PKCE code-verifier / code-challenge pair.
     *
     * Call this before redirecting the user to the authorization URL. Store the
     * returned `codeVerifier` in the session and pass `codeChallenge` + `codeChallengeMethod`
     * to `buildAuthorizeUrl()`. Send `codeVerifier` to `exchangeCode()` at callback time.
     */
    public static function generatePkce(): PkceChallenge
    {
        return PkceChallenge::generate();
    }

    // =========================================================================
    // Browser login helpers (§HEA-1592)
    // =========================================================================

    /**
     * Begin an authorization-code login: generate PKCE, build the authorization URL.
     *
     * Developer flow:
     * 1. Call `beginLogin($redirectUri)` — receive a `LoginBeginResult`.
     * 2. Persist `$result->state` and `$result->codeVerifier` in `$_SESSION`.
     * 3. Redirect the browser to `$result->authorizationUrl`.
     * 4. On the callback route, call `completeLogin($code, $codeVerifier, $redirectUri)`.
     *
     * @param string      $redirectUri Callback URL registered with the authorization server.
     * @param string|null $scopes      Space-delimited scope string; defaults to "openid".
     *
     * @throws \Hearth\Exceptions\NetworkException       When discovery is unreachable.
     * @throws \Hearth\Exceptions\ConfigurationException When the authorization endpoint is absent.
     */
    public function beginLogin(string $redirectUri, ?string $scopes = null): LoginBeginResult
    {
        $pkce  = static::generatePkce();
        $state = bin2hex(random_bytes(16));
        $url   = $this->buildAuthorizeUrl($redirectUri, $state, null, $scopes ?? 'openid', $pkce);

        return new LoginBeginResult(
            authorizationUrl: $url,
            state:            $state,
            codeVerifier:     $pkce->codeVerifier,
        );
    }

    /**
     * Complete an authorization-code login: exchange the callback code for tokens.
     *
     * @param string $code          Authorization code from the callback `code` query parameter.
     * @param string $codeVerifier  PKCE verifier returned by {@see beginLogin()}.
     * @param string $redirectUri   Same redirect URI used in {@see beginLogin()}.
     *
     * @throws \Hearth\Exceptions\NetworkException When the token endpoint is unreachable.
     * @throws \RuntimeException                   When the server returns an error response.
     */
    public function completeLogin(string $code, string $codeVerifier, string $redirectUri): TokenResponse
    {
        return $this->exchangeCode($code, $redirectUri, $codeVerifier);
    }

    // =========================================================================
    // Authorization URL
    // =========================================================================

    /**
     * Builds the authorization URL to which the user should be redirected.
     *
     * Discovers the `authorization_endpoint` from the OIDC discovery document.
     * When `$pkce` is provided, `code_challenge` and `code_challenge_method` are appended.
     *
     * @param string            $redirectUri Registered redirect URI for the callback.
     * @param string|null       $state       Opaque value for CSRF protection.
     * @param string|null       $nonce       Opaque value to bind the ID token to the session.
     * @param string|null       $scope       Space-separated scope string; defaults to "openid".
     * @param PkceChallenge|null $pkce       PKCE pair from `generatePkce()`.
     * @param array<string, string> $extra   Additional query parameters to append.
     *
     * @throws NetworkException       When discovery is unreachable.
     * @throws ConfigurationException When the authorization endpoint is absent from the document.
     */
    public function buildAuthorizeUrl(
        string $redirectUri,
        ?string $state = null,
        ?string $nonce = null,
        ?string $scope = null,
        ?PkceChallenge $pkce = null,
        array $extra = [],
    ): string {
        $endpoint = $this->discoverEndpoint('authorization_endpoint');

        $params = [
            'response_type' => 'code',
            'redirect_uri'  => $redirectUri,
        ];

        if ($this->clientId !== null) {
            $params['client_id'] = $this->clientId;
        }

        $params['scope'] = $scope ?? 'openid';

        if ($state !== null) {
            $params['state'] = $state;
        }

        if ($nonce !== null) {
            $params['nonce'] = $nonce;
        }

        if ($pkce !== null) {
            $params['code_challenge']        = $pkce->codeChallenge;
            $params['code_challenge_method'] = $pkce->codeChallengeMethod;
        }

        foreach ($extra as $key => $value) {
            $params[$key] = $value;
        }

        return $endpoint . '?' . http_build_query($params);
    }

    // =========================================================================
    // Token lifecycle
    // =========================================================================

    /**
     * Exchanges an authorization code for tokens.
     *
     * @param string      $code          Authorization code from the callback.
     * @param string      $redirectUri   Redirect URI used in the initial authorization request.
     * @param string|null $codeVerifier  PKCE code verifier (required for public clients / PKCE flows).
     *
     * @throws NetworkException  When the token endpoint is unreachable.
     * @throws \RuntimeException When the token endpoint returns an error.
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
     * Refreshes an access token using a refresh token grant.
     *
     * @param string $refreshToken The refresh token issued with a previous access token.
     *
     * @throws NetworkException  When the token endpoint is unreachable.
     * @throws \RuntimeException When the server returns an error response.
     */
    public function refreshToken(string $refreshToken): TokenResponse
    {
        $tokenEndpoint = $this->discoverEndpoint('token_endpoint');

        $params = [
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refreshToken,
        ];

        if ($this->clientId !== null) {
            $params['client_id'] = $this->clientId;
        }

        if ($this->clientSecret !== null) {
            $params['client_secret'] = $this->clientSecret;
        }

        $data = $this->postForm($tokenEndpoint, $params);

        return TokenResponse::fromArray($data);
    }

    /**
     * Obtains an access token via the client credentials grant (RFC 6749 §4.4).
     *
     * Intended for machine-to-machine (M2M) flows. Credentials are sent as
     * `application/x-www-form-urlencoded` body fields per RFC 6749 §2.3.1.
     *
     * @param string|null $scope Space-separated scope string.
     *
     * @throws ConfigurationException When `clientId` or `clientSecret` is not configured.
     * @throws NetworkException       When the token endpoint is unreachable.
     * @throws \RuntimeException      When the server returns an error response.
     */
    public function clientCredentials(?string $scope = null): TokenResponse
    {
        if ($this->clientId === null || $this->clientSecret === null) {
            throw new ConfigurationException(
                'clientCredentials() requires both clientId and clientSecret',
            );
        }

        $tokenEndpoint = $this->discoverEndpoint('token_endpoint');

        $params = [
            'grant_type'    => 'client_credentials',
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        if ($scope !== null) {
            $params['scope'] = $scope;
        }

        $data = $this->postForm($tokenEndpoint, $params);

        return TokenResponse::fromArray($data);
    }

    // =========================================================================
    // Device Authorization Flow (RFC 8628) — §4.5.2
    // =========================================================================

    /**
     * Initiates a device authorization flow (RFC 8628 §3.1).
     *
     * The returned `DeviceAuthorizationResponse` contains the `user_code` to display
     * to the user and the `device_code` to pass to `pollDeviceToken()`.
     *
     * @param string|null $scope Space-separated scope string.
     *
     * @throws NetworkException  When the device authorization endpoint is unreachable.
     * @throws \RuntimeException When the server returns an error response.
     */
    public function startDeviceFlow(?string $scope = null): DeviceAuthorizationResponse
    {
        $endpoint = $this->discoverEndpoint('device_authorization_endpoint');

        $params = [];

        if ($this->clientId !== null) {
            $params['client_id'] = $this->clientId;
        }

        if ($scope !== null) {
            $params['scope'] = $scope;
        }

        $data = $this->postForm($endpoint, $params);

        return DeviceAuthorizationResponse::fromArray($data);
    }

    /**
     * Polls the token endpoint until the device code is authorized, expired, or denied.
     *
     * - `authorization_pending`: polling continues transparently (no error surfaced).
     * - `slow_down`: polling interval is increased by 5 s per occurrence and polling continues.
     * - `expired_token`: throws `TokenExpiredException`.
     * - Any other error: throws `\RuntimeException`.
     *
     * @param string        $deviceCode The `device_code` from `startDeviceFlow()`.
     * @param int           $interval   Initial polling interval in seconds (from `DeviceAuthorizationResponse::$interval`).
     * @param callable|null $sleepFn    Sleep function — injected in tests to avoid real waits.
     *                                  Signature: `(int $seconds): void`. Defaults to `sleep()`.
     *
     * @throws TokenExpiredException When the device code expires (`expired_token` error response).
     * @throws NetworkException      When the token endpoint is unreachable.
     * @throws \RuntimeException     On any other terminal error from the server.
     */
    public function pollDeviceToken(string $deviceCode, int $interval, ?callable $sleepFn = null): TokenResponse
    {
        $tokenEndpoint   = $this->discoverEndpoint('token_endpoint');
        $currentInterval = max(1, $interval);

        $params = [
            'grant_type'  => 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code' => $deviceCode,
        ];

        if ($this->clientId !== null) {
            $params['client_id'] = $this->clientId;
        }

        while (true) {
            // Sleep before each poll (RFC 8628 §3.5)
            if ($sleepFn !== null) {
                $sleepFn($currentInterval);
            } else {
                sleep($currentInterval);
            }

            [$status, $data] = $this->postFormAllowErrors($tokenEndpoint, $params);

            if ($status >= 200 && $status < 300) {
                return TokenResponse::fromArray($data);
            }

            $error = (string) ($data['error'] ?? '');

            if ($error === 'authorization_pending') {
                continue;
            }

            if ($error === 'slow_down') {
                $currentInterval += 5;
                continue;
            }

            if ($error === 'expired_token') {
                throw new TokenExpiredException(null, 'Device code has expired');
            }

            throw new \RuntimeException("Device flow error: {$error}");
        }
    }

    // =========================================================================
    // Magic-Link Initiation (Passwordless) — §4.5.3
    // =========================================================================

    /**
     * Sends a magic-link email to the given address (passwordless auth initiation).
     *
     * Always passes through `202 Accepted` from the server without surfacing a
     * "user not found" error — the server uses enumeration resistance and returns
     * 202 regardless of whether the email is registered.
     *
     * Throws `RateLimitException` on HTTP 429.
     *
     * @throws RateLimitException When the server returns HTTP 429.
     * @throws NetworkException   When the magic-link endpoint is unreachable.
     * @throws \RuntimeException  When the server returns any non-2xx/non-429 status.
     */
    public function requestMagicLink(string $email): void
    {
        $realmSlug = $this->extractRealmSlug();
        $baseUrl   = $this->extractBaseUrl();
        $url       = "{$baseUrl}/v1/{$realmSlug}/auth/magic-link";

        $encoded = json_encode(['email' => $email], JSON_THROW_ON_ERROR);
        $request = $this->requestFactory
            ->createRequest('POST', $url)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream($encoded));

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new NetworkException($url, "Magic-link request failed: {$e->getMessage()}", 0, $e);
        }

        $status = $response->getStatusCode();

        if ($status === 429) {
            $retryAfter = (int) ($response->getHeaderLine('Retry-After') ?: 0);
            throw new RateLimitException($retryAfter, $url);
        }

        if ($status < 200 || $status >= 300) {
            throw new \RuntimeException("Magic-link request returned HTTP {$status}");
        }
        // 202 Accepted — success, no body required
    }

    /**
     * Exchanges a magic-link token for tokens (spec §4.5.3 / §7.2 C-12).
     *
     * Completes the passwordless flow started by `requestMagicLink()`: posts
     * `grant_type=urn:hearth:grant-type:magic-link` with the opaque `$token`
     * from the magic-link URL to the token endpoint. The token is sent in the
     * form body, never the URL.
     *
     * @param string $token The opaque magic-link token from the email/redirect URL.
     *
     * @throws NetworkException When the token endpoint is unreachable.
     */
    public function exchangeMagicLink(string $token): TokenResponse
    {
        $endpoint = $this->discoverEndpoint('token_endpoint');

        $params = [
            'grant_type' => 'urn:hearth:grant-type:magic-link',
            'token'      => $token,
        ];

        if ($this->clientId !== null) {
            $params['client_id'] = $this->clientId;
        }

        $data = $this->postForm($endpoint, $params);

        return TokenResponse::fromArray($data);
    }

    // =========================================================================
    // Dynamic Client Registration (RFC 7591)
    // =========================================================================

    /**
     * Registers a new OAuth client via Dynamic Client Registration (RFC 7591).
     *
     * The registration endpoint is discovered from the OIDC discovery document
     * (`registration_endpoint` field).
     *
     * @param array<string, mixed> $params Client metadata (e.g. `redirect_uris`, `client_name`).
     *
     * @throws ConfigurationException When the registration endpoint is absent from discovery.
     * @throws NetworkException       When the endpoint is unreachable.
     * @throws \RuntimeException      When the server returns an error response.
     */
    public function registerClient(array $params): ClientRegistrationResponse
    {
        $endpoint = $this->discoverEndpoint('registration_endpoint');
        $data     = $this->postJson($endpoint, $params);

        return ClientRegistrationResponse::fromArray($data);
    }

    // =========================================================================
    // Token verification
    // =========================================================================

    /**
     * Verifies a raw access token JWT and returns typed claims.
     *
     * Honours the configured `token_authorization_mode`:
     * - `"embedded"` (default): JWKS-only verification.
     * - `"introspection"`: JWKS verification + mandatory introspection call.
     * - `"decision"`: JWKS verification only (caller must separately call `checkDecision()`).
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

    // =========================================================================
    // Permissions — /v1/me/permissions
    // =========================================================================

    /**
     * Fetches the effective permissions for the authenticated user from `/v1/me/permissions`.
     *
     * The bearer token determines which user's permissions are returned. The endpoint
     * is not realm-scoped in the URL — the realm is inferred from the token's `tid` claim.
     *
     * @throws NetworkException  When the permissions endpoint is unreachable.
     * @throws \RuntimeException When the server returns a non-2xx status.
     */
    public function getMyPermissions(string $accessToken): PermissionsResponse
    {
        $baseUrl = $this->extractBaseUrl();
        $url     = "{$baseUrl}/v1/me/permissions";
        $data    = $this->getJson($url, $accessToken);

        return PermissionsResponse::fromArray($data);
    }

    // =========================================================================
    // Decision-mode authorization (§3.5)
    // =========================================================================

    /**
     * Sends a per-request authorization decision check to the server (§3.5 Decision mode).
     *
     * Resource servers configured with `access_token_authorization = "decision"` MUST call
     * this method before accepting the token for any access-controlled operation.
     *
     * The authorization endpoint is discovered from the OIDC discovery document.
     *
     * @param string               $accessToken Bearer token to authorize.
     * @param array<string, mixed> $params      Decision parameters (resource, action, etc.).
     *
     * @return array<string, mixed> Server decision payload.
     *
     * @throws NetworkException  When the authorization endpoint is unreachable.
     * @throws \RuntimeException On non-2xx response.
     */
    public function checkDecision(string $accessToken, array $params): array
    {
        $endpoint = $this->discoverEndpoint('authorization_endpoint');

        return $this->postJson($endpoint, $params, $accessToken);
    }

    // =========================================================================
    // UserInfo
    // =========================================================================

    /**
     * Fetches the UserInfo endpoint and returns a typed response.
     *
     * @throws NetworkException When the endpoint is unreachable.
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

    // =========================================================================
    // WebAuthn
    // =========================================================================

    /**
     * Begins a WebAuthn credential registration ceremony.
     *
     * Returns the server-generated `PublicKeyCredentialCreationOptions` that the
     * browser's `navigator.credentials.create()` call requires.
     *
     * @param string $accessToken Bearer token of the authenticated user registering a passkey.
     *
     * @throws NetworkException  When the WebAuthn begin endpoint is unreachable.
     * @throws \RuntimeException On non-2xx response.
     */
    public function startWebAuthnRegistration(string $accessToken): WebAuthnOptions
    {
        $url  = $this->webAuthnUrl('register/begin');
        $data = $this->postJson($url, [], $accessToken);

        return WebAuthnOptions::fromArray($data);
    }

    /**
     * Completes a WebAuthn credential registration ceremony.
     *
     * @param string               $accessToken Bearer token of the authenticated user.
     * @param array<string, mixed> $credential  JSON-serializable `PublicKeyCredential` from the browser.
     *
     * @throws NetworkException  When the WebAuthn finish endpoint is unreachable.
     * @throws \RuntimeException On non-2xx response.
     */
    public function finishWebAuthnRegistration(string $accessToken, array $credential): void
    {
        $url = $this->webAuthnUrl('register/finish');
        $this->postJson($url, $credential, $accessToken);
    }

    /**
     * Begins a WebAuthn authentication ceremony.
     *
     * Returns the server-generated `PublicKeyCredentialRequestOptions` for the browser.
     *
     * @param string|null $username Optional username hint for discoverable-credential flows.
     *
     * @throws NetworkException  When the WebAuthn begin endpoint is unreachable.
     * @throws \RuntimeException On non-2xx response.
     */
    public function startWebAuthnAuthentication(?string $username = null): WebAuthnOptions
    {
        $url    = $this->webAuthnUrl('authenticate/begin');
        $params = $username !== null ? ['username' => $username] : [];
        $data   = $this->postJson($url, $params);

        return WebAuthnOptions::fromArray($data);
    }

    /**
     * Completes a WebAuthn authentication ceremony and returns the issued tokens.
     *
     * @param array<string, mixed> $credential  JSON-serializable `PublicKeyCredential` from the browser.
     *
     * @throws NetworkException  When the WebAuthn finish endpoint is unreachable.
     * @throws \RuntimeException On non-2xx response.
     */
    public function finishWebAuthnAuthentication(array $credential): TokenResponse
    {
        $url  = $this->webAuthnUrl('authenticate/finish');
        $data = $this->postJson($url, $credential);

        return TokenResponse::fromArray($data);
    }

    // =========================================================================
    // Session version polling
    // =========================================================================

    /**
     * Returns the current version (epoch counter) of a session.
     *
     * Callers poll this endpoint to detect session revocation or forced re-auth.
     * A change in version means the session has been modified server-side.
     *
     * @param string $accessToken Bearer token of the session owner.
     * @param string $sessionId   Session ID from the `sid` JWT claim.
     *
     * @throws NetworkException  When the session version endpoint is unreachable.
     * @throws \RuntimeException On non-2xx response.
     */
    public function getSessionVersion(string $accessToken, string $sessionId): int
    {
        $realmSlug = $this->extractRealmSlug();
        $baseUrl   = $this->extractBaseUrl();
        $url       = "{$baseUrl}/v1/{$realmSlug}/sessions/{$sessionId}/version";
        $data      = $this->getJson($url, $accessToken);

        return (int) ($data['version'] ?? 0);
    }

    // =========================================================================
    // Bootstrap (dev-only)
    // =========================================================================

    /**
     * Calls the dev-only `POST /admin/bootstrap` endpoint.
     *
     * Creates the system realm, an admin user, and a long-lived admin token.
     * This endpoint is idempotent — calling it multiple times is safe.
     *
     * **This endpoint is only available when the Hearth server runs with `--dev`.**
     *
     * @throws NetworkException  When the bootstrap endpoint is unreachable.
     * @throws \RuntimeException On non-2xx response.
     */
    public function bootstrap(): BootstrapResponse
    {
        $baseUrl = $this->extractBaseUrl();
        $url     = "{$baseUrl}/admin/bootstrap";
        $data    = $this->postJson($url, []);

        return BootstrapResponse::fromArray($data);
    }

    // =========================================================================
    // Lazy sub-client accessors
    // =========================================================================

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

    // =========================================================================
    // OIDC discovery
    // =========================================================================

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

    // =========================================================================
    // URL helpers
    // =========================================================================

    /**
     * Extracts the realm slug from the issuer URL.
     *
     * For `https://auth.example.com/realms/my-realm` → `my-realm`.
     * Falls back to `default` when no path segment is present.
     */
    private function extractRealmSlug(): string
    {
        $path = parse_url($this->issuerUrl, PHP_URL_PATH) ?? '';
        $slug = basename(rtrim((string) $path, '/'));

        return $slug !== '' ? $slug : 'default';
    }

    /**
     * Extracts the scheme+host+port portion of the issuer URL.
     *
     * For `https://auth.example.com/realms/my-realm` → `https://auth.example.com`.
     */
    private function extractBaseUrl(): string
    {
        $scheme = (string) (parse_url($this->issuerUrl, PHP_URL_SCHEME) ?? 'https');
        $host   = (string) (parse_url($this->issuerUrl, PHP_URL_HOST) ?? '');
        $port   = parse_url($this->issuerUrl, PHP_URL_PORT);

        $base = "{$scheme}://{$host}";
        if ($port !== null) {
            $base .= ":{$port}";
        }

        return $base;
    }

    /**
     * Builds a WebAuthn endpoint URL of the form `{base_url}/v1/{realm}/auth/webauthn/{suffix}`.
     */
    private function webAuthnUrl(string $suffix): string
    {
        $realmSlug = $this->extractRealmSlug();
        $baseUrl   = $this->extractBaseUrl();

        return "{$baseUrl}/v1/{$realmSlug}/auth/webauthn/{$suffix}";
    }

    // =========================================================================
    // HTTP primitives
    // =========================================================================

    /**
     * POSTs an `application/x-www-form-urlencoded` body and returns the decoded JSON response.
     * Throws on any non-2xx status.
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
     * POSTs form data and returns `[status_code, decoded_body]` without throwing on non-2xx.
     * Used internally by `pollDeviceToken()` which must inspect specific error codes.
     *
     * @param array<string, string> $params
     * @return array{int, array<string, mixed>}
     * @throws NetworkException On network-level failure.
     */
    private function postFormAllowErrors(string $url, array $params): array
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

        $status  = $response->getStatusCode();
        $content = $response->getBody()->getContents();

        if ($content === '') {
            return [$status, []];
        }

        try {
            $data = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return [$status, []];
        }

        return [$status, is_array($data) ? $data : []];
    }

    /**
     * POSTs a JSON body and returns the decoded JSON response.
     *
     * @param array<string, mixed> $body
     * @param string|null          $bearerToken Added as `Authorization: Bearer` header when provided.
     * @return array<string, mixed>
     * @throws NetworkException
     * @throws \RuntimeException
     */
    private function postJson(string $url, array $body, ?string $bearerToken = null): array
    {
        $encoded = json_encode($body, JSON_THROW_ON_ERROR);
        $request = $this->requestFactory
            ->createRequest('POST', $url)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream($encoded));

        if ($bearerToken !== null) {
            $request = $request->withHeader('Authorization', "Bearer {$bearerToken}");
        }

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new NetworkException($url, "HTTP request failed: {$e->getMessage()}", 0, $e);
        }

        return $this->decodeJsonResponse($response->getBody()->getContents(), $response->getStatusCode());
    }

    /**
     * GETs a URL and returns the decoded JSON response.
     *
     * @param string|null $bearerToken Added as `Authorization: Bearer` header when provided.
     * @return array<string, mixed>
     * @throws NetworkException
     * @throws \RuntimeException
     */
    private function getJson(string $url, ?string $bearerToken = null): array
    {
        $request = $this->requestFactory
            ->createRequest('GET', $url)
            ->withHeader('Accept', 'application/json');

        if ($bearerToken !== null) {
            $request = $request->withHeader('Authorization', "Bearer {$bearerToken}");
        }

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

        if ($body === '') {
            return [];
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
