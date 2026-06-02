<?php

declare(strict_types=1);

namespace Hearth\Types;

/**
 * Response from the OIDC UserInfo endpoint.
 */
final class UserInfoResponse
{
    /**
     * @param string      $sub           Subject identifier (user ID)
     * @param string|null $name          Full display name
     * @param string|null $email         Email address
     * @param bool|null   $emailVerified Whether the email address has been verified
     * @param string|null $picture       URL to profile picture
     * @param array<string, mixed> $extra Non-standard claims returned by the server
     */
    public function __construct(
        public readonly string $sub,
        public readonly ?string $name = null,
        public readonly ?string $email = null,
        public readonly ?bool $emailVerified = null,
        public readonly ?string $picture = null,
        public readonly array $extra = [],
    ) {}

    /**
     * Construct from a raw UserInfo endpoint JSON response body.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        if (!isset($data['sub'])) {
            throw new \InvalidArgumentException('UserInfo response is missing required "sub" field');
        }

        $reserved = ['sub', 'name', 'email', 'email_verified', 'picture'];

        return new self(
            sub: (string) $data['sub'],
            name: isset($data['name']) ? (string) $data['name'] : null,
            email: isset($data['email']) ? (string) $data['email'] : null,
            emailVerified: isset($data['email_verified']) ? (bool) $data['email_verified'] : null,
            picture: isset($data['picture']) ? (string) $data['picture'] : null,
            extra: array_diff_key($data, array_flip($reserved)),
        );
    }
}
