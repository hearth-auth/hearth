/** Express/Fastify-compatible middleware for JWT verification */

import type { JWTPayload } from "jose";
import { JwksClient, type JwksClientConfig } from "./jwks.js";

declare global {
  namespace Express {
    interface Request {
      auth?: JWTPayload;
    }
  }
}

type NextFunction = (err?: unknown) => void;
interface Request { headers: Record<string, string | string[] | undefined> }
interface Response { status(code: number): this; json(body: unknown): this }

export interface MiddlewareOptions extends JwksClientConfig {
  /** Return 401 on missing/invalid token (default: true) */
  required?: boolean;
  /**
   * Also accept tokens delivered as the `hearth_access_token` HttpOnly cookie
   * when no Authorization: Bearer header is present (default: false).
   *
   * Enable this when the Hearth client is configured with `token_delivery: cookie`.
   * The Authorization header always takes precedence so bearer-mode clients are
   * unaffected.
   */
  acceptCookieToken?: boolean;
}

/** Parse a Cookie header string into a name→value map. */
function parseCookies(cookieHeader: string | string[] | undefined): Record<string, string> {
  const header = Array.isArray(cookieHeader) ? cookieHeader.join("; ") : (cookieHeader ?? "");
  const result: Record<string, string> = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    try {
      result[name] = decodeURIComponent(value);
    } catch {
      result[name] = value;
    }
  }
  return result;
}

function extractToken(req: Request, acceptCookie: boolean): string | null {
  const authHeader = req.headers["authorization"];
  const header = Array.isArray(authHeader) ? authHeader[0] : authHeader;
  if (header?.startsWith("Bearer ")) return header.slice(7);
  if (acceptCookie) {
    const cookies = parseCookies(req.headers["cookie"]);
    return cookies["hearth_access_token"] ?? null;
  }
  return null;
}

/** Express middleware — attaches verified claims to req.auth */
export function hearthMiddleware(options: MiddlewareOptions) {
  const client = new JwksClient(options);
  const required = options.required !== false;
  const acceptCookie = options.acceptCookieToken === true;

  return async (req: Request & { auth?: JWTPayload }, res: Response, next: NextFunction): Promise<void> => {
    const token = extractToken(req, acceptCookie);

    if (!token) {
      if (required) {
        res.status(401).json({ error: "unauthorized", error_description: "Bearer token required" });
        return;
      }
      next();
      return;
    }

    try {
      const { payload } = await client.verify(token);
      req.auth = payload;
      next();
    } catch {
      if (required) {
        res.status(401).json({ error: "invalid_token", error_description: "Token verification failed" });
        return;
      }
      next();
    }
  };
}

/** Fastify-compatible plugin factory */
export function hearthFastifyPlugin(options: MiddlewareOptions) {
  const client = new JwksClient(options);
  const required = options.required !== false;
  const acceptCookie = options.acceptCookieToken === true;

  return async (request: { headers: Record<string, string | undefined>; auth?: JWTPayload }, reply: { status(n: number): void; send(body: unknown): void }): Promise<void> => {
    const authHeader = request.headers["authorization"];
    let token: string | null = null;
    if (authHeader?.startsWith("Bearer ")) {
      token = authHeader.slice(7);
    } else if (acceptCookie) {
      const cookies = parseCookies(request.headers["cookie"]);
      token = cookies["hearth_access_token"] ?? null;
    }

    if (!token) {
      if (required) {
        reply.status(401);
        reply.send({ error: "unauthorized" });
        return;
      }
      return;
    }

    try {
      const { payload } = await client.verify(token);
      request.auth = payload;
    } catch {
      if (required) {
        reply.status(401);
        reply.send({ error: "invalid_token" });
      }
    }
  };
}
