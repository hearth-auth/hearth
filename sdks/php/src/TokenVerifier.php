<?php

declare(strict_types=1);

namespace Hearth;

use DateInterval;
use DateTimeImmutable;
use Hearth\Contracts\JwksClientInterface;
use Hearth\Contracts\TokenVerifierInterface;
use Hearth\Exceptions\JWKSFetchException;
use Hearth\Exceptions\JwksKeyNotFoundException;
use Hearth\Exceptions\RequiredActionException;
use Hearth\Exceptions\TokenAudienceException;
use Hearth\Exceptions\TokenExpiredException;
use Hearth\Exceptions\TokenIssuerException;
use Hearth\Exceptions\TokenInvalidException;
use Hearth\Exceptions\TokenNotYetValidException;
use JsonException;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Exception as JwtException;
use Lcobucci\JWT\Signer\Eddsa;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Psr\Clock\ClockInterface;

/**
 * Verifies a raw JWT string against the Hearth JWKS and validates standard claims.
 *
 * Parsing, the signature check and the registered-claim checks are done by
 * lcobucci/jwt (`Lcobucci\JWT\Signer\Eddsa` and the validation constraints). This class
 * only resolves the key by `kid` and maps a failed constraint to the SDK error taxonomy.
 * The checks run in this order:
 *   1. `alg` is `EdDSA` and the Ed25519 signature verifies (`SignedWith`).
 *   2. `exp`, `nbf` and `iat` hold at the current time, with 5 s clock skew (`LooseValidAt`).
 *   3. `iss` matches the configured issuer URL (`IssuedBy`).
 *   4. `aud` contains the configured client ID, when set (`PermittedFor`).
 *
 * Tokens with `token_type === "required_action"` raise RequiredActionException.
 */
final class TokenVerifier implements TokenVerifierInterface
{
    /** Clock skew tolerated for the `exp`, `nbf` and `iat` claims (seconds). */
    private const CLOCK_SKEW_SECONDS = 5;

    /**
     * @param JwksClientInterface $jwksClient   Key source
     * @param string              $issuerUrl    Expected `iss` value
     * @param string|null         $clientId     Expected audience; if null, audience check is skipped
     */
    public function __construct(
        private readonly JwksClientInterface $jwksClient,
        private readonly string $issuerUrl,
        private readonly ?string $clientId = null,
    ) {}

    /**
     * Verifies and decodes a JWT, returning a typed Claims accessor.
     *
     * @throws TokenInvalidException  On malformed JWT, invalid Ed25519 signature or unknown `kid`
     * @throws JWKSFetchException      When the JWKS endpoint fails
     * @throws TokenExpiredException    When `exp` is in the past
     * @throws TokenNotYetValidException When `nbf` is in the future
     * @throws TokenIssuerException     When `iss` does not match
     * @throws TokenAudienceException   When `aud` does not include the client ID
     * @throws RequiredActionException  When `token_type === "required_action"`
     */
    public function verify(string $rawToken): Claims
    {
        $token = $this->parse($rawToken);

        // Step 1 — algorithm allow-list and signature, before any claim check
        $kid = $token->headers()->get('kid');
        try {
            $key = $this->jwksClient->getKey(is_string($kid) ? $kid : '');
        } catch (JwksKeyNotFoundException $e) {
            // SDK.md §5: an unknown signing key makes the token invalid;
            // JWKSFetchException stays for a failing JWKS endpoint.
            throw new TokenInvalidException('JWT signed with an unknown key', 0, $e);
        }
        if ($key === '') {
            throw new TokenInvalidException('Signing key is empty');
        }
        if (!$this->satisfies($token, new SignedWith(new Eddsa(), InMemory::plainText($key)))) {
            throw new TokenInvalidException('JWT signature verification failed');
        }

        // Step 2 — exp / nbf / iat
        $this->checkValidAt($token);

        // Step 3 — issuer
        // An empty expected issuer or audience matches no token (lcobucci needs non-empty).
        if ($this->issuerUrl === '' || !$this->satisfies($token, new IssuedBy($this->issuerUrl))) {
            $iss = $token->claims()->get(RegisteredClaims::ISSUER);
            throw new TokenIssuerException($this->issuerUrl, is_string($iss) ? $iss : '');
        }

        // Step 4 — audience
        if (
            $this->clientId !== null
            && ($this->clientId === '' || !$this->satisfies($token, new PermittedFor($this->clientId)))
        ) {
            /** @var list<string> $audiences */
            $audiences = array_map('strval', (array) $token->claims()->get(RegisteredClaims::AUDIENCE, []));
            throw new TokenAudienceException($this->clientId, $audiences);
        }

        $claims    = $this->rawClaims($token);
        $claimsObj = new Claims($claims);

        // Required-action tokens must not be accepted as regular access tokens
        if ($claimsObj->tokenType() === 'required_action') {
            /** @var string[] $actions */
            $actions = is_array($claims['required_actions'] ?? null) ? $claims['required_actions'] : [];
            throw new RequiredActionException($actions);
        }

        return $claimsObj;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Parses the compact JWS with lcobucci/jwt.
     *
     * @throws TokenInvalidException
     */
    private function parse(string $rawToken): UnencryptedToken
    {
        if ($rawToken === '') {
            throw new TokenInvalidException('Malformed JWT: empty token');
        }

        try {
            $token = (new Parser(new JoseEncoder()))->parse($rawToken);
        } catch (JwtException $e) {
            throw new TokenInvalidException('Malformed JWT: ' . $e->getMessage(), 0, $e);
        }

        if (!$token instanceof UnencryptedToken) {
            throw new TokenInvalidException('Malformed JWT: not a signed token');
        }

        return $token;
    }

    /**
     * Runs one lcobucci constraint. A library error (for example a key or
     * signature of the wrong length) is a failed check, not a crash: it must
     * surface as a HearthException so HearthMiddleware answers 401, not 500.
     *
     * @throws TokenInvalidException
     */
    private function satisfies(UnencryptedToken $token, Constraint $constraint): bool
    {
        try {
            return (new Validator())->validate($token, $constraint);
        } catch (JwtException $e) {
            throw new TokenInvalidException('JWT verification failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Checks `exp`, `nbf` and `iat` with LooseValidAt, then names the failed claim.
     *
     * @throws TokenExpiredException
     * @throws TokenNotYetValidException
     * @throws TokenInvalidException
     */
    private function checkValidAt(UnencryptedToken $token): void
    {
        $clock = new class () implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable();
            }
        };
        $leeway = new DateInterval('PT' . self::CLOCK_SKEW_SECONDS . 'S');

        if ($this->satisfies($token, new LooseValidAt($clock, $leeway))) {
            return;
        }

        $claims = $token->claims();
        $now    = $clock->now();

        $exp = $claims->get(RegisteredClaims::EXPIRATION_TIME);
        if ($exp instanceof DateTimeImmutable && $token->isExpired($now->sub($leeway))) {
            throw new TokenExpiredException($exp);
        }

        $nbf = $claims->get(RegisteredClaims::NOT_BEFORE);
        if ($nbf instanceof DateTimeImmutable && !$token->isMinimumTimeBefore($now->add($leeway))) {
            throw new TokenNotYetValidException($nbf);
        }

        throw new TokenInvalidException('JWT was issued in the future (beyond clock skew tolerance)');
    }

    /**
     * Returns the payload as the JSON object the server signed, for the Claims accessor.
     *
     * @return array<string, mixed>
     * @throws TokenInvalidException
     */
    private function rawClaims(UnencryptedToken $token): array
    {
        try {
            $data = json_decode(
                (new JoseEncoder())->base64UrlDecode($token->claims()->toString()),
                true,
                512,
                JSON_THROW_ON_ERROR,
            );
        } catch (JsonException | JwtException $e) {
            throw new TokenInvalidException('Malformed JWT: payload is not valid JSON', 0, $e);
        }

        if (!is_array($data)) {
            throw new TokenInvalidException('Malformed JWT: payload must be a JSON object');
        }

        /** @var array<string, mixed> $data */
        return $data;
    }
}
