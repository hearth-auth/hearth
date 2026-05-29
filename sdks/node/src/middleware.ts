/** §6 — Framework-decoupled Express and Fastify middleware for JWT verification. */

import { HearthClient } from "./client.js";
import type { HearthConfig } from "./config.js";
import { resolveConfig } from "./config.js";
import { IntrospectionClient } from "./introspect.js";
import { AuthorizeClient } from "./authorize.js";
import type { VerifiedToken } from "./token.js";
import type { AccessTokenAuthorizationMode } from "./token.js";
import { TokenVerificationError, AuthorizationModeError } from "./errors.js";

// No import from 'express' or 'fastify' — decoupled from any framework.

export interface MiddlewareOptions extends HearthConfig {
  /** If true (default), return 401 when no Bearer token is present. */
  required?: boolean;
  /** If provided, return 403 when the verified token is missing this scope. */
  requiredScope?: string;
  /** If provided, return 403 when the verified token is missing this role. */
  requiredRole?: string;
  /** If provided, return 403 when the verified token is missing this permission. */
  requiredPermission?: string;
  /**
   * Authorization mode to enforce. Defaults to `"embedded"` (JWT claims only).
   *
   * - `"embedded"`: check permissions/roles from JWT claims — no network calls.
   * - `"introspection"`: call `/introspect` for live RBAC data; reject on mode mismatch.
   * - `"decision"`: call `POST /oauth/authorize` per-request; fail-closed on network errors.
   *
   * IMPORTANT: absence of `permissions` in a token MUST NOT silently fall back to
   * a different mode. Set `expectedMode` explicitly for any non-embedded behavior.
   */
  expectedMode?: AccessTokenAuthorizationMode;
}

const WWW_AUTHENTICATE = 'Bearer realm="hearth"';

// Generic framework-agnostic types — satisfied by both Express and Fastify request shapes.
interface MinimalRequest {
  headers: Record<string, string | string[] | undefined>;
}

interface MinimalResponse {
  status(code: number): MinimalResponse;
  setHeader?(name: string, value: string): void;
  json(body: unknown): unknown;
  send?(body: unknown): unknown;
  header?(name: string, value: string): void;
}

// Module augmentation for Express (optional — safe if express is not installed).
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      hearthToken?: VerifiedToken;
    }
  }
}

type ExpressRequest = MinimalRequest & { hearthToken?: VerifiedToken };
type NextFn = (err?: unknown) => void;

function extractBearer(headers: Record<string, string | string[] | undefined>): string | null {
  const raw = headers["authorization"];
  const header = Array.isArray(raw) ? raw[0] : raw;
  if (!header?.startsWith("Bearer ")) return null;
  return header.slice(7);
}

function sendUnauthorized(res: MinimalResponse, description: string): void {
  if (res.setHeader) res.setHeader("WWW-Authenticate", WWW_AUTHENTICATE);
  if (res.header) res.header("WWW-Authenticate", WWW_AUTHENTICATE);
  res.status(401);
  const body = { error: "unauthorized", error_description: description };
  if (res.json) res.json(body);
  else if (res.send) res.send(body);
}

function sendForbidden(res: MinimalResponse): void {
  res.status(403);
  const body = { error: "forbidden", error_description: "Insufficient scope, role, or permission" };
  if (res.json) res.json(body);
  else if (res.send) res.send(body);
}

/** Check scope and role from JWT claims — always used for embedded mode. */
function checkScopeAndRole(token: VerifiedToken, opts: MiddlewareOptions): boolean {
  if (opts.requiredScope && !token.hasScope(opts.requiredScope)) return false;
  if (opts.requiredRole && !token.hasRole(opts.requiredRole)) return false;
  return true;
}

type AuthDecision = "allow" | "deny_forbidden" | "deny_unauthorized";

/** Embedded: all checks from JWT claims — no network calls. */
function checkEmbedded(token: VerifiedToken, opts: MiddlewareOptions): AuthDecision {
  if (!checkScopeAndRole(token, opts)) return "deny_forbidden";
  if (opts.requiredPermission && !token.hasPermission(opts.requiredPermission)) return "deny_forbidden";
  return "allow";
}

/** Introspection: call /introspect for live RBAC; enforce mode echo match. */
async function checkIntrospection(
  token: string,
  introspectionClient: IntrospectionClient,
  opts: MiddlewareOptions,
  verifiedToken: VerifiedToken,
): Promise<AuthDecision> {
  // Scope/role are still checked from JWT (lightweight, no extra roundtrip)
  if (!checkScopeAndRole(verifiedToken, opts)) return "deny_forbidden";

  let result: Awaited<ReturnType<IntrospectionClient["introspect"]>>;
  try {
    result = await introspectionClient.introspect(token, "access_token");
  } catch {
    return "deny_forbidden";
  }

  if (!result.active) return "deny_unauthorized";

  // Mode-echo check: server must confirm the token was issued for introspection mode.
  if (result.mode !== undefined && result.mode !== opts.expectedMode) {
    // Typed error for callers who inspect the cause, but middleware is fail-closed.
    const _ = new AuthorizationModeError(opts.expectedMode!, result.mode);
    void _;
    return "deny_forbidden";
  }

  if (opts.requiredPermission) {
    const livePermissions = result.permissions ?? [];
    if (!livePermissions.includes(opts.requiredPermission)) return "deny_forbidden";
  }

  return "allow";
}

/** Decision: per-request POST /oauth/authorize — fail-closed. */
async function checkDecision(
  token: string,
  authorizeClient: AuthorizeClient,
  opts: MiddlewareOptions,
  verifiedToken: VerifiedToken,
): Promise<AuthDecision> {
  if (!checkScopeAndRole(verifiedToken, opts)) return "deny_forbidden";

  if (opts.requiredPermission) {
    const result = await authorizeClient.decide(token, opts.requiredPermission);
    if (!result.allowed) return "deny_forbidden";
  }

  return "allow";
}

/** Express-compatible middleware factory. Attaches verified token to `req.hearthToken`. */
export function hearthMiddleware(options: MiddlewareOptions) {
  const resolved = resolveConfig(options);
  const client = new HearthClient(options);
  const introspectionClient = new IntrospectionClient(resolved, async () => {
    throw new Error("Discovery not available in middleware context; configure introspection_endpoint explicitly");
  });
  const authorizeClient = new AuthorizeClient(resolved);
  const required = options.required !== false;
  const mode: AccessTokenAuthorizationMode = options.expectedMode ?? "embedded";

  return async (req: ExpressRequest, res: MinimalResponse, next: NextFn): Promise<void> => {
    const rawToken = extractBearer(req.headers);
    if (!rawToken) {
      if (required) {
        sendUnauthorized(res, "Bearer token required");
        return;
      }
      next();
      return;
    }

    let verified: VerifiedToken;
    try {
      verified = await client.verifyToken(rawToken);
    } catch (err) {
      if (required) {
        const desc = err instanceof TokenVerificationError ? err.message : "Token verification failed";
        sendUnauthorized(res, desc);
        return;
      }
      next();
      return;
    }

    let decision: AuthDecision;
    if (mode === "introspection") {
      decision = await checkIntrospection(rawToken, introspectionClient, options, verified);
    } else if (mode === "decision") {
      decision = await checkDecision(rawToken, authorizeClient, options, verified);
    } else {
      decision = checkEmbedded(verified, options);
    }

    if (decision === "deny_unauthorized") {
      sendUnauthorized(res, "Token is no longer active");
      return;
    }
    if (decision === "deny_forbidden") {
      sendForbidden(res);
      return;
    }

    req.hearthToken = verified;
    next();
  };
}

// ── Fastify ──────────────────────────────────────────────────────────────────

interface FastifyRequest {
  headers: Record<string, string | undefined>;
  hearthToken?: VerifiedToken;
}

interface FastifyReply {
  code(statusCode: number): FastifyReply;
  header(name: string, value: string): FastifyReply;
  send(body: unknown): void;
}

/** Fastify hook/plugin factory. Attaches verified token to `request.hearthToken`. */
export function hearthFastifyHook(options: MiddlewareOptions) {
  const resolved = resolveConfig(options);
  const client = new HearthClient(options);
  const introspectionClient = new IntrospectionClient(resolved, async () => {
    throw new Error("Discovery not available in middleware context; configure introspection_endpoint explicitly");
  });
  const authorizeClient = new AuthorizeClient(resolved);
  const required = options.required !== false;
  const mode: AccessTokenAuthorizationMode = options.expectedMode ?? "embedded";

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const authHeader = request.headers["authorization"];
    if (!authHeader?.startsWith("Bearer ")) {
      if (required) {
        reply.header("WWW-Authenticate", WWW_AUTHENTICATE).code(401).send({
          error: "unauthorized",
          error_description: "Bearer token required",
        });
        return;
      }
      return;
    }

    const rawToken = authHeader.slice(7);
    let verified: VerifiedToken;
    try {
      verified = await client.verifyToken(rawToken);
    } catch (err) {
      if (required) {
        const desc = err instanceof TokenVerificationError ? err.message : "Token verification failed";
        reply.header("WWW-Authenticate", WWW_AUTHENTICATE).code(401).send({
          error: "unauthorized",
          error_description: desc,
        });
        return;
      }
      return;
    }

    // Reuse Express-side request wrapper for auth-options check
    const minimalReq = { headers: request.headers as Record<string, string | string[] | undefined> };
    let decision: AuthDecision;
    if (mode === "introspection") {
      decision = await checkIntrospection(rawToken, introspectionClient, options, verified);
    } else if (mode === "decision") {
      decision = await checkDecision(rawToken, authorizeClient, options, verified);
    } else {
      decision = checkEmbedded(verified, options);
    }
    void minimalReq;

    if (decision === "deny_unauthorized") {
      reply.header("WWW-Authenticate", WWW_AUTHENTICATE).code(401).send({
        error: "unauthorized",
        error_description: "Token is no longer active",
      });
      return;
    }
    if (decision === "deny_forbidden") {
      reply.code(403).send({
        error: "forbidden",
        error_description: "Insufficient scope, role, or permission",
      });
      return;
    }

    request.hearthToken = verified;
  };
}
