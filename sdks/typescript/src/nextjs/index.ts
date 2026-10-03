/**
 * `@hearth-auth/sdk/nextjs` — Next.js helpers for the Node.js runtime
 * (Pages Router API routes and App Router Route Handlers).
 *
 * For `middleware.ts`, which runs on the Edge Runtime, import
 * `hearthEdgeMiddleware` from `@hearth-auth/sdk/nextjs/edge`.
 */

import type { Claims } from "../claims.js";
import type { HearthClient } from "../hearth-client.js";
import { hearthMiddleware } from "../middleware.js";
import type { HearthMiddlewareOptions } from "../middleware.js";

/** A request whose headers have a `get()` accessor (`NextRequest`, `Request`). */
export interface RequestLike {
  headers: { get(name: string): string | null };
}

/** The fields of `NextApiRequest` that {@link withHearthAuth} uses. */
export interface ApiRequest {
  headers: Record<string, string | string[] | undefined>;
  /** Verified claims, set by {@link withHearthAuth} before the handler runs. */
  hearthClaims?: Claims;
}

/** The methods of `NextApiResponse` that {@link withHearthAuth} uses. */
export interface ApiResponse {
  status(code: number): unknown;
  setHeader(name: string, value: string): unknown;
  json(body: unknown): unknown;
}

/** A Pages Router API route handler. */
export type ApiHandler<
  Req extends ApiRequest = ApiRequest,
  Res extends ApiResponse = ApiResponse,
> = (req: Req, res: Res) => unknown | Promise<unknown>;

/**
 * Wrap a Pages Router API route with Hearth authentication.
 *
 * Verifies the `Authorization: Bearer` token, applies the guards in `options`,
 * sets `req.hearthClaims` and calls `handler`. When the request fails it
 * answers 401 or 403 and `handler` is not called.
 *
 * @throws {@link ConfigurationError} when the client cannot serve the mode.
 */
export function withHearthAuth<Req extends ApiRequest, Res extends ApiResponse>(
  handler: ApiHandler<Req, Res>,
  options: HearthMiddlewareOptions,
): (req: Req, res: Res) => Promise<void> {
  const middleware = hearthMiddleware(options);
  return async (req: Req, res: Res): Promise<void> => {
    let proceed = false;
    let failure: unknown;
    await middleware(req, res, (err?: unknown) => {
      if (err === undefined) proceed = true;
      else failure = err;
    });
    if (failure !== undefined) throw failure;
    if (proceed) await handler(req, res);
  };
}

/**
 * Verify the bearer token on an App Router Route Handler request.
 *
 * Returns the verified {@link Claims}, or `null` when the `Authorization`
 * header is missing or not a bearer token, the token does not verify, or the
 * token is a `required_action` token. Create the {@link HearthClient} once at
 * module scope so its JWKS cache is shared across requests.
 */
export async function getHearthClaims(
  req: RequestLike,
  client: HearthClient,
): Promise<Claims | null> {
  const match = /^Bearer[ ]+(\S+)\s*$/i.exec(req.headers.get("authorization") ?? "");
  if (!match) return null;
  try {
    const claims = await client.verifyToken(match[1]);
    return claims.tokenType() === "required_action" ? null : claims;
  } catch {
    return null;
  }
}

export type { HearthMiddlewareOptions } from "../middleware.js";
