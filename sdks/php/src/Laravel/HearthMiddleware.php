<?php

declare(strict_types=1);

namespace Hearth\Laravel;

use Closure;
use GuzzleHttp\Psr7\Response as PsrResponse;
use GuzzleHttp\Psr7\ServerRequest as PsrServerRequest;
use Hearth\Middleware\HearthMiddleware as CoreMiddleware;
use Illuminate\Http\Request;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel HTTP middleware adapter for the Hearth PSR-15 core middleware.
 *
 * Converts the incoming Illuminate request to a minimal PSR-7 ServerRequest
 * (carrying only the Authorization header), delegates all JWT validation to
 * {@see CoreMiddleware}, then converts the result back to a Symfony/Laravel
 * response.
 *
 * On success the verified {@see \Hearth\Claims} object is attached to the
 * Illuminate request under the {@see CoreMiddleware::CLAIMS_ATTRIBUTE} key so
 * downstream controllers can read it via `$request->attributes->get('hearth_claims')`.
 *
 * Register via `HearthServiceProvider` or apply directly in a route group:
 *   Route::middleware('hearth.auth')->group(fn () => ...);
 */
final class HearthMiddleware
{
    public function __construct(
        private readonly CoreMiddleware $coreMiddleware,
    ) {}

    /**
     * @param Closure(Request): Response $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Build a minimal PSR-7 server request forwarding only the Authorization
        // header.  The PSR-15 core reads nothing else from the request object.
        $psrRequest = (new PsrServerRequest('GET', (string) $request->getUri()))
            ->withHeader('Authorization', $request->headers->get('Authorization') ?? '');

        // The anonymous handler exposes $claims as a public property so the outer
        // scope can read it after process() returns.  PHP anonymous classes cannot
        // close over outer variables by reference, so a public property is the
        // cleanest way to share state between the handler and the caller.
        $handler = new class implements RequestHandlerInterface {
            /** @var \Hearth\Claims|null */
            public mixed $claims = null;

            public function handle(ServerRequestInterface $psrRequest): ResponseInterface
            {
                /** @var \Hearth\Claims|null $claims */
                $claims        = $psrRequest->getAttribute(CoreMiddleware::CLAIMS_ATTRIBUTE);
                $this->claims  = $claims;

                // Dummy 200 — the real response is produced by $next below.
                return new PsrResponse(200);
            }
        };

        $psrResponse = $this->coreMiddleware->process($psrRequest, $handler);

        // The core middleware returns a non-200 (401 by spec) when authentication
        // fails and our handler was never called.  Our dummy handler always returns
        // 200 on success, so any other status means we must forward the failure.
        if ($psrResponse->getStatusCode() !== 200) {
            return $this->toSymfonyResponse($psrResponse);
        }

        // Authentication succeeded.  Attach claims to the request attributes so
        // downstream code can access them without re-verifying the token.
        $request->attributes->set(CoreMiddleware::CLAIMS_ATTRIBUTE, $handler->claims);

        return $next($request);
    }

    /** Converts a PSR-7 response to a Symfony HttpFoundation Response. */
    private function toSymfonyResponse(ResponseInterface $psrResponse): Response
    {
        $response = new Response(
            $psrResponse->getBody()->getContents(),
            $psrResponse->getStatusCode(),
        );

        foreach ($psrResponse->getHeaders() as $name => $values) {
            $response->headers->set($name, implode(', ', $values));
        }

        return $response;
    }
}
