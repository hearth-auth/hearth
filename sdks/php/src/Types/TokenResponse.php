<?php

declare(strict_types=1);

namespace Hearth\Types;

/**
 * Token endpoint response for an authorization code exchange or refresh.
 */
final class TokenResponse
{
    /**
     * @param string      $accessToken  The issued access token
     * @param string      $tokenType    Token type, typically "Bearer"
     * @param int|null    $expiresIn    Lifetime of the access token in seconds
     * @param string|null $refreshToken Refresh token, if issued
     * @param string|null $idToken      OIDC ID token, if issued
     * @param string|null $scope        Granted scope (space-delimited)
     */
    public function __construct(
        public readonly string $accessToken,
        public readonly string $tokenType,
        public readonly ?int $expiresIn = null,
        public readonly ?string $refreshToken = null,
        public readonly ?string $idToken = null,
        public readonly ?string $scope = null,
    ) {}

    /**
     * Construct from a raw token endpoint JSON response body.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        if (!isset($data['access_token'])) {
            throw new \InvalidArgumentException('Token response is missing required "access_token" field');
        }

        return new self(
            accessToken: (string) $data['access_token'],
            tokenType: (string) ($data['token_type'] ?? 'Bearer'),
            expiresIn: isset($data['expires_in']) ? (int) $data['expires_in'] : null,
            refreshToken: isset($data['refresh_token']) ? (string) $data['refresh_token'] : null,
            idToken: isset($data['id_token']) ? (string) $data['id_token'] : null,
            scope: isset($data['scope']) ? (string) $data['scope'] : null,
        );
    }
}
