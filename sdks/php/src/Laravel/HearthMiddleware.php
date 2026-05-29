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
 * {@see CoreMiddleware}, then converts the result back to an Illuminate/Symfony
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
            ->withHeader('Authorization', (string) $request->header('Authorization', ''));

        // Holder object for state shared with the anonymous handler below.
        // PHP anonymous classes capture constructor arguments by value, not by
        // reference — a holder object sidesteps this: both sides share the same
        // object identity, so mutations inside handle() are visible here.
        $holder          = new \stdClass();
        $holder->called  = false;
        $holder->claims  = null;

        $handler = new class($holder) implements RequestHandlerInterface {
            public function __construct(private readonly \stdClass $holder) {}

            public function handle(ServerRequestInterface $psrRequest): ResponseInterface
            {
                // Core middleware injects verified Claims into the request attribute
                // before calling this handler.  Capture and signal success.
                $this->holder->claims = $psrRequest->getAttribute(CoreMiddleware::CLAIMS_ATTRIBUTE);
                $this->holder->called = true;

                // Return a throwaway 200 — the real response is produced by $next below.
                return new PsrResponse(200);
            }
        };

        $psrResponse = $this->coreMiddleware->process($psrRequest, $handler);

        if (!$holder->called) {
            // Core middleware short-circuited without calling the handler, meaning
            // authentication failed.  Forward its status code and headers.
            return $this->toSymfonyResponse($psrResponse);
        }

        // Authentication succeeded.  Attach claims to the request attributes so
        // downstream code can access them without re-verifying the token.
        $request->attributes->set(CoreMiddleware::CLAIMS_ATTRIBUTE, $holder->claims);

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
