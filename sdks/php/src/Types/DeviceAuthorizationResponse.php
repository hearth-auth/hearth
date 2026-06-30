<?php

declare(strict_types=1);

namespace Hearth\Types;

/**
 * Response from the device authorization endpoint (RFC 8628 §3.2).
 */
final class DeviceAuthorizationResponse
{
    /**
     * @param string      $deviceCode              Opaque device code passed to `pollDeviceToken`.
     * @param string      $userCode                Short code the user enters at `verificationUri`.
     * @param string      $verificationUri         URL the user visits to authorize the device.
     * @param string|null $verificationUriComplete `verificationUri` with `user_code` pre-filled.
     * @param int         $expiresIn               Seconds until the device code expires.
     * @param int         $interval                Minimum polling interval in seconds.
     */
    public function __construct(
        public readonly string $deviceCode,
        public readonly string $userCode,
        public readonly string $verificationUri,
        public readonly ?string $verificationUriComplete,
        public readonly int $expiresIn,
        public readonly int $interval,
    ) {}

    /**
     * Constructs from the raw device authorization JSON response.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        if (!isset($data['device_code'], $data['user_code'], $data['verification_uri'])) {
            throw new \InvalidArgumentException(
                'Device authorization response is missing required fields (device_code, user_code, verification_uri)',
            );
        }

        return new self(
            deviceCode: (string) $data['device_code'],
            userCode:   (string) $data['user_code'],
            verificationUri: (string) $data['verification_uri'],
            verificationUriComplete: isset($data['verification_uri_complete'])
                ? (string) $data['verification_uri_complete']
                : null,
            expiresIn: (int) ($data['expires_in'] ?? 600),
            interval:  (int) ($data['interval']   ?? 5),
        );
    }
}
