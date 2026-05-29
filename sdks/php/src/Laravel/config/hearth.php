<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Hearth Issuer URL
    |--------------------------------------------------------------------------
    |
    | The root URL of your Hearth instance.  Used for OIDC discovery at
    | <issuer_url>/.well-known/openid-configuration.  Must not be empty.
    |
    */
    'issuer_url' => env('HEARTH_ISSUER_URL', ''),

    /*
    |--------------------------------------------------------------------------
    | OAuth Client Credentials
    |--------------------------------------------------------------------------
    |
    | client_id is required for audience validation.  client_secret is only
    | required when token_authorization_mode is "introspection".
    |
    */
    'client_id'     => env('HEARTH_CLIENT_ID'),
    'client_secret' => env('HEARTH_CLIENT_SECRET'),

    /*
    |--------------------------------------------------------------------------
    | JWKS Cache TTL
    |--------------------------------------------------------------------------
    |
    | How long (in seconds) to cache the JWKS key set.  Leave null to use the
    | SDK default (300 seconds).
    |
    */
    'jwks_ttl' => env('HEARTH_JWKS_TTL'),

    /*
    |--------------------------------------------------------------------------
    | Introspection Endpoint Override
    |--------------------------------------------------------------------------
    |
    | Override the introspection URL discovered via OIDC.  Leave null to use
    | the value from the discovery document.
    |
    */
    'introspection_endpoint' => env('HEARTH_INTROSPECTION_ENDPOINT'),

    /*
    |--------------------------------------------------------------------------
    | HTTP Timeout
    |--------------------------------------------------------------------------
    |
    | Timeout in seconds for all outbound HTTP calls made by the SDK.
    |
    */
    'http_timeout' => (int) env('HEARTH_HTTP_TIMEOUT', 10),

    /*
    |--------------------------------------------------------------------------
    | Token Authorization Mode
    |--------------------------------------------------------------------------
    |
    | Controls how access tokens are validated.  Accepted values:
    |   "embedded"      — JWKS-only verification (default)
    |   "introspection" — JWKS + mandatory introspection call (requires client_secret)
    |   "decision"      — JWKS verification; caller handles authorization separately
    |
    */
    'token_authorization_mode' => env('HEARTH_TOKEN_AUTHORIZATION_MODE'),

    /*
    |--------------------------------------------------------------------------
    | Require Authentication
    |--------------------------------------------------------------------------
    |
    | When true (default), the hearth.auth middleware rejects requests with no
    | Bearer token.  Set to false to allow unauthenticated requests through
    | (optional-auth routes).
    |
    */
    'require_auth' => (bool) env('HEARTH_REQUIRE_AUTH', true),

];
