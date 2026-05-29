<?php

declare(strict_types=1);

namespace Hearth\Laravel\Facades;

use Hearth\Claims;
use Hearth\HearthClient;
use Hearth\Types\TokenResponse;
use Hearth\Types\UserInfoResponse;
use Illuminate\Support\Facades\Facade;

/**
 * Laravel facade for the `hearth` service-container binding.
 *
 * Proxies static calls to the {@see HearthClient} singleton registered by
 * {@see \Hearth\Laravel\HearthServiceProvider}.
 *
 * @method static TokenResponse   exchangeCode(string $code, string $redirectUri, ?string $codeVerifier = null)
 * @method static Claims          verifyToken(string $rawToken)
 * @method static UserInfoResponse getUserInfo(string $accessToken)
 * @method static string          discoverEndpoint(string $key)
 *
 * @see HearthClient
 */
class Hearth extends Facade
{
    /**
     * Returns the service-container abstract that this facade resolves.
     */
    protected static function getFacadeAccessor(): string
    {
        return 'hearth';
    }
}
