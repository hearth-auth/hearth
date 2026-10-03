/**
 * `@hearth-auth/sdk/nextjs/edge` — Next.js `middleware.ts` guard for the Edge
 * Runtime.
 *
 * Uses only `fetch` and Web Crypto (through `jose`); it imports no `node:`
 * module, so it runs in a V8 isolate.
 */

import { assertMiddlewareOptions, authenticateRequest } from "../middleware.js";
import type { HearthMiddlewareOptions } from "../middleware.js";

/** A request whose headers have a `get()` accessor (`NextRequest`, `Request`). */
export interface EdgeRequestLike {
  headers: { get(name: string): string | null };
}

/**
 * Build a guard for Next.js `middleware.ts`.
 *
 * The guard resolves to `undefined` when the request may proceed (return
 * `NextResponse.next()`), or to a 401/403 JSON `Response` to return as is.
 * Create it once at module scope so the client's discovery and JWKS caches
 * live as long as the isolate.
 *
 * @throws {@link ConfigurationError} when the client cannot serve the mode.
 */
export function hearthEdgeMiddleware(
  options: HearthMiddlewareOptions,
): (req: EdgeRequestLike) => Promise<Response | undefined> {
  assertMiddlewareOptions(options);
  return async (req: EdgeRequestLike): Promise<Response | undefined> => {
    const result = await authenticateRequest(req.headers.get("authorization"), options);
    if (result.ok) return undefined;
    return new Response(JSON.stringify(result.body), {
      status: result.status,
      headers: { ...result.headers, "Content-Type": "application/json" },
    });
  };
}

export type { HearthMiddlewareOptions } from "../middleware.js";
