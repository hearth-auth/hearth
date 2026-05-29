<?php

declare(strict_types=1);

namespace Hearth\Middleware;

use Hearth\Claims;
use Hearth\Exceptions\HearthException;
use Hearth\Exceptions\RequiredActionException;
use Hearth\TokenVerifier;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware that authenticates requests using a Hearth-issued JWT.
 *
 * Implements §6 of the Hearth SDK Common Specification:
 *   1. Extracts the Bearer token from `Authorization: Bearer <token>`.
 *   2. Verifies the token via JWKS (Ed25519) by default.
 *   3. On success: injects verified Claims into the request as the `hearth_claims` attribute.
 *   4. On missing/invalid token: returns 401 with `WWW-Authenticate: Bearer realm="hearth"`.
 *   5. On `token_type === "required_action"`: returns 401 (never passes to handler).
 *   6. Never calls `next` on auth failure.
 *
 * The `hearth_claims` request attribute key is exported as the class constant
 * {@see self::CLAIMS_ATTRIBUTE} so downstream handlers can read it without a
 * magic string.
 */
final class HearthMiddleware implements MiddlewareInterface
{
    /** Request attribute key under which verified {@see Claims} are stored. */
    public const CLAIMS_ATTRIBUTE = 'hearth_claims';

    /**
     * @param TokenVerifier           $tokenVerifier   Configured verifier (JWKS + claim checks)
     * @param ResponseFactoryInterface $responseFactory PSR-17 factory for creating 401/403 responses
     * @param bool                     $requireAuth     When false, missing tokens are forwarded to the handler
     *                                                  (useful for optional-auth routes)
     */
    public function __construct(
        private readonly TokenVerifier $tokenVerifier,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly bool $requireAuth = true,
    ) {}

    /**
     * Authenticates the request or short-circuits with 401 / 403.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->extractBearerToken($request);

        if ($token === null) {
            if (!$this->requireAuth) {
                return $handler->handle($request);
            }

            return $this->unauthorized('Bearer token is required');
        }

        try {
            $claims = $this->tokenVerifier->verify($token);
        } catch (RequiredActionException $e) {
            // Spec §6 rule 6: required-action tokens MUST return 401, never 403
            return $this->unauthorized('Required actions pending: ' . implode(', ', $e->getRequiredActions()));
        } catch (HearthException) {
            return $this->unauthorized('Token verification failed');
        }

        $enriched = $request->withAttribute(self::CLAIMS_ATTRIBUTE, $claims);

        return $handler->handle($enriched);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Extracts the Bearer token value from the Authorization header, or returns null. */
    private function extractBearerToken(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine('Authorization');

        if ($header === '' || !str_starts_with($header, 'Bearer ')) {
            return null;
        }

        $token = substr($header, 7);

        return $token !== '' ? $token : null;
    }

    /** Builds a 401 response with the standard WWW-Authenticate challenge. */
    private function unauthorized(string $detail): ResponseInterface
    {
        return $this->responseFactory
            ->createResponse(401)
            ->withHeader('WWW-Authenticate', 'Bearer realm="hearth"')
            ->withHeader('Content-Type', 'application/json');
    }

    /** Builds a 403 response. */
    private function forbidden(string $detail): ResponseInterface
    {
        return $this->responseFactory
            ->createResponse(403)
            ->withHeader('Content-Type', 'application/json');
    }
}
