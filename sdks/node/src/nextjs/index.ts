/**
 * @hearth-auth/node — Next.js adapter (Node.js runtime).
 *
 * This module runs in Node.js runtime only (Pages Router API routes, App Router
 * Route Handlers). For Edge Runtime (`middleware.ts`), import from
 * `@hearth-auth/node/nextjs/edge` instead.
 *
 * Exports:
 *   withHearthAuth()     — Pages Router API route wrapper
 *   getHearthToken()     — App Router Route Handler helper
 *   requirePermission()  — composable guard (re-exported from edge module)
 *   EdgeToken            — edge-compatible token class (re-exported)
 *   EdgeMiddlewareOptions
 *   hearthEdgeMiddleware()
 */

// Re-export everything from the Edge module so users only need one import path
// for non-edge usage.
export {
  EdgeToken,
  EdgeMiddlewareOptions,
  hearthEdgeMiddleware,
  requirePermission,
} from "./edge.js";

import { HearthClient } from "../client.js";
import type { HearthConfig } from "../config.js";
import type { VerifiedToken } from "../token.js";
import { hearthMiddleware } from "../middleware.js";
import type { MiddlewareOptions } from "../middleware.js";

// ── Type augmentation for Pages Router ───────────────────────────────────────

declare module "http" {
  interface IncomingMessage {
    hearthToken?: VerifiedToken;
  }
}

// ── Shared duck-typed interfaces ──────────────────────────────────────────────

/** Any request whose `headers` object has a `.get()` accessor (NextRequest, Request). */
export interface RequestLike {
  headers: {
    get(name: string): string | null;
  };
}

/** Pages Router API request — compatible with `NextApiRequest`. */
export interface ApiRequest {
  headers: Record<string, string | string[] | undefined>;
  hearthToken?: VerifiedToken;
  [key: string]: unknown;
}

/** Pages Router API response — compatible with `NextApiResponse`. */
export interface ApiResponse {
  status(code: number): ApiResponse;
  json(body: unknown): void;
  setHeader?(name: string, value: string | string[]): void;
  writableEnded?: boolean;
  [key: string]: unknown;
}

/** A Next.js Pages Router API handler. */
export type ApiHandler = (req: ApiRequest, res: ApiResponse) => void | Promise<void>;

// ── withHearthAuth — Pages Router ─────────────────────────────────────────────

/**
 * Wrap a Pages Router API route handler with Hearth authentication.
 *
 * Reads the `Authorization: Bearer` header, verifies the JWT, and attaches
 * `req.hearthToken` before calling `handler`. Returns 401 or 403 if the token
 * is missing or invalid (controlled by `options`).
 *
 * @example
 * // pages/api/profile.ts
 * import { withHearthAuth } from "@hearth-auth/node/nextjs";
 * import type { NextApiRequest, NextApiResponse } from "next";
 *
 * export default withHearthAuth(
 *   (req, res) => {
 *     res.json({ sub: req.hearthToken!.subject() });
 *   },
 *   { issuer_url: process.env.HEARTH_ISSUER_URL!, client_id: "my-app" },
 * );
 */
export function withHearthAuth(handler: ApiHandler, options: MiddlewareOptions): ApiHandler {
  const mw = hearthMiddleware(options);

  return async (req: ApiRequest, res: ApiResponse): Promise<void> => {
    let middlewareError: unknown = undefined;
    let middlewareCalled = false;

    await mw(
      req as Parameters<typeof mw>[0],
      res as Parameters<typeof mw>[1],
      (err?: unknown) => {
        middlewareCalled = true;
        middlewareError = err;
      },
    );

    if (middlewareError) {
      throw middlewareError;
    }

    // If middleware sent a response (401/403), writableEnded is true — skip handler.
    if (!middlewareCalled || res.writableEnded) {
      return;
    }

    await handler(req, res);
  };
}

// ── getHearthToken — App Router Route Handlers ────────────────────────────────

/**
 * Verify and return the Hearth token from an App Router Route Handler request.
 *
 * Reads `Authorization: Bearer <token>`, verifies the JWT via JWKS, and returns
 * a typed `VerifiedToken`. Returns `null` when the header is absent or the token
 * is invalid.
 *
 * Uses a per-`config` singleton `HearthClient` internally (JWKS cache is shared
 * across requests as long as the config object reference is stable).
 *
 * @example
 * // app/api/profile/route.ts
 * import { getHearthToken } from "@hearth-auth/node/nextjs";
 * import { NextRequest, NextResponse } from "next/server";
 *
 * const hearthConfig = {
 *   issuer_url: process.env.HEARTH_ISSUER_URL!,
 *   client_id: "my-app",
 * };
 *
 * export async function GET(request: NextRequest) {
 *   const token = await getHearthToken(request, hearthConfig);
 *   if (!token) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
 *   return NextResponse.json({ sub: token.subject() });
 * }
 */
export async function getHearthToken(
  req: RequestLike,
  config: HearthConfig,
): Promise<VerifiedToken | null> {
  const auth = req.headers.get("authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  const rawToken = auth.slice(7);
  const client = new HearthClient(config);
  try {
    return await client.verifyToken(rawToken);
  } catch {
    return null;
  }
}

// Re-export VerifiedToken for consumers of this module.
export type { VerifiedToken } from "../token.js";
