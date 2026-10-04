<?php

declare(strict_types=1);

/**
 * PHP runner for the shared SDK conformance harness.
 *
 * Contract: sdks/conformance/README.md. Reads a case file, runs each case
 * through the public SDK API only, and prints one JSON line per case.
 *
 * Usage: php runner.php <cases.json>
 */

use Hearth\Claims;
use Hearth\HearthClient;

require __DIR__ . '/../vendor/autoload.php';

/** openspec/specs/sdk-support-contract/spec.md error names. PHP's `...Exception` classes report as `...Error`. */
const SPEC_ERRORS = [
    'ConfigurationError', 'DiscoveryError', 'JWKSFetchError', 'TokenExpiredError',
    'TokenNotYetValidError', 'TokenInvalidError', 'TokenIssuerError', 'TokenAudienceError',
    'IntrospectionError', 'RequiredActionError',
];

/**
 * Maps a throwable to its openspec/specs/sdk-support-contract/spec.md name, walking up the class hierarchy, or
 * `Unexpected:<class>` when it is not an SDK error.
 */
function errorName(Throwable $e): string
{
    for ($class = get_class($e); $class !== false; $class = get_parent_class($class)) {
        if (!str_starts_with($class, 'Hearth\\Exceptions\\')) {
            continue;
        }
        $short = substr($class, strrpos($class, '\\') + 1);
        $name  = preg_replace('/Exception$/', 'Error', $short);
        if (in_array($name, SPEC_ERRORS, true)) {
            return $name;
        }
    }

    return 'Unexpected:' . get_class($e);
}

/**
 * A client that verifies with the case's audience; a null audience leaves the
 * SDK on its default ("hearth").
 *
 * @param array<string, mixed> $config
 */
function verifier(array $config, ?string $audience): HearthClient
{
    return $audience === null
        ? new HearthClient(issuerUrl: (string) $config['issuer'])
        : new HearthClient(issuerUrl: (string) $config['issuer'], audience: $audience);
}

/**
 * The OAuth client for the client_credentials case.
 *
 * @param array<string, mixed> $config
 */
function m2mClient(array $config, string $clientId, string $clientSecret): HearthClient
{
    return new HearthClient(
        issuerUrl: (string) $config['issuer'],
        clientId: $clientId,
        clientSecret: $clientSecret,
    );
}

/**
 * @param list<string> $names
 * @return array<string, mixed>
 */
function pickClaims(Claims $claims, array $names): array
{
    $out = [];
    foreach ($names as $name) {
        $out[$name] = match ($name) {
            'sub'         => $claims->subject(),
            'scope'       => is_string($claims->get('scope')) ? $claims->get('scope') : null,
            'permissions' => array_values($claims->permissions()),
            default       => $claims->get($name),
        };
    }

    return $out;
}

/**
 * @param array<string, mixed> $case
 * @return array<string, mixed>
 */
function runCase(array $case): array
{
    $config   = (array) $case['config'];
    $audience = isset($config['audience']) ? (string) $config['audience'] : null;
    /** @var list<string> $names */
    $names = (array) ($case['claims'] ?? []);

    // A new client per case: no case reuses another case's JWKS cache.
    $token = match ($case['kind']) {
        'verify_token'       => (string) $case['token'],
        'client_credentials' => m2mClient(
            $config,
            (string) $config['client_id'],
            (string) $config['client_secret'],
        )->clientCredentials(isset($case['scope']) ? (string) $case['scope'] : null)->accessToken,
        default => throw new InvalidArgumentException('unknown case kind ' . json_encode($case['kind'])),
    };

    $claims = verifier($config, $audience)->verifyToken($token);

    return ['outcome' => 'ok', 'claims' => pickClaims($claims, $names)];
}

if ($argc !== 2) {
    fwrite(STDERR, "usage: runner.php <cases.json>\n");
    exit(2);
}

try {
    $file = json_decode((string) file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
} catch (JsonException $e) {
    fwrite(STDERR, 'cannot read case file: ' . $e->getMessage() . "\n");
    exit(2);
}

foreach ((array) ($file['cases'] ?? []) as $case) {
    try {
        $result = runCase((array) $case);
    } catch (Throwable $e) {
        $result = ['outcome' => 'error', 'error' => errorName($e)];
    }
    echo json_encode(['id' => $case['id']] + $result, JSON_UNESCAPED_SLASHES), "\n";
}
