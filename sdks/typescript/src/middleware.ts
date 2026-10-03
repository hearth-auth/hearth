import {
  AuthorizationModeMismatchError,
  ConfigurationError,
  TokenVerificationError,
} from "./errors.js";
import type { Claims } from "./claims.js";
import type { HearthClient } from "./hearth-client.js";
import type { AccessTokenAuthorizationMode, AuthorizePermissionOptions } from "./types.js";

/** Options for {@link requirePermission}. */
export interface RequirePermissionOptions extends AuthorizePermissionOptions {
  /**
   * Which permission delivery mode the resource server expects.
   *
   * MUST be set explicitly — the middleware MUST NOT auto-detect the mode from
   * JWT claim presence. Absence of a `permissions` claim in the token does not
   * change behavior (per HEA-923 design constraint).
   */
  mode: AccessTokenAuthorizationMode;
  /** HearthClient instance used for network calls in decision/introspection modes. */
  client: HearthClient;
}

/**
 * A synchronous-or-async gate that returns `true` iff the token holder has
 * the given permission under the configured mode.
 */
export type PermissionChecker = (token: string) => Promise<boolean>;

/**
 * Returns a mode-aware permission checker for the given `permission`.
 *
 * Behaviour by mode:
 * - **embedded** — verifies the JWT with `client.verifyToken()` (EdDSA signature
 *   against the realm's cached JWKS, plus `exp`, `nbf`, `iss` and `aud`) and only
 *   then checks the `permissions` claim. No per-request network traffic once the
 *   JWKS is warm. Returns `false` when the token does not verify or the claim is
 *   absent; DOES NOT fall back to network (design constraint: absence of claims ≠
 *   switch mode).
 * - **decision** — calls `client.authorize(token, permission, opts)` which
 *   POSTs to `POST /oauth/authorize`. Fail-closed on network/server errors.
 * - **introspection** — calls `client.introspectionClient().introspect(token)`,
 *   validates the echoed `mode` field if present, then checks the returned
 *   `permissions` array. Throws {@link AuthorizationModeMismatchError} if the
 *   server echoes a mode that differs from `opts.mode`.
 *
 * @param permission - The permission string to check (e.g. `"docs.write"`).
 * @param opts - Mode, client reference, and optional scoping parameters.
 */
export function requirePermission(
  permission: string,
  opts: RequirePermissionOptions,
): PermissionChecker {
  const { mode, client, organizationId, resource } = opts;

  switch (mode) {
    case "embedded":
      return async (token: string): Promise<boolean> => {
        // Verify BEFORE reading a claim. Decoding without verifying would let
        // anyone mint `{"alg":"none"}` with any permission they liked.
        try {
          return (await client.verifyToken(token)).hasPermission(permission);
        } catch {
          return false;
        }
      };

    case "decision":
      return async (token: string): Promise<boolean> =>
        client.authorize(token, permission, { organizationId, resource });

    case "introspection":
      return async (token: string): Promise<boolean> => {
        const ic = await client.introspectionClient();
        const result = await ic.introspect(token);

        // Validate mode echo when present — catches misconfigured deployments.
        if (result.mode !== undefined && result.mode !== "introspection") {
          throw new AuthorizationModeMismatchError("introspection", String(result.mode));
        }

        if (!result.active) return false;
        return Array.isArray(result.permissions) && result.permissions.includes(permission);
      };
  }
}

// ── Request middleware (Express, Fastify, Next.js) ─────────────────────────

/** Options for {@link hearthMiddleware}, {@link hearthFastifyHook} and the Next.js helpers. */
export interface HearthMiddlewareOptions extends AuthorizePermissionOptions {
  /** Client used to verify tokens and, in non-embedded modes, to call the server. */
  client: HearthClient;
  /**
   * How the permission check is made. Defaults to the client's `expectedMode`,
   * then to `"embedded"`.
   *
   * - `"embedded"` — read `permissions` from the verified JWT. No network call.
   * - `"introspection"` — introspect the token on every request. An inactive
   *   token answers 401; a missing live permission, a different echoed mode or
   *   a failed introspection call answers 403.
   * - `"decision"` — ask `POST /oauth/authorize` for `requiredPermission` on
   *   every request. Any failure counts as a denial (403).
   *
   * A token without a `permissions` claim never changes the mode (HEA-923).
   */
  mode?: AccessTokenAuthorizationMode;
  /** When `true` (default), a request without a usable bearer token answers 401. */
  required?: boolean;
  /** Answer 403 unless the token's `scope` contains this value. */
  requiredScope?: string;
  /** Answer 403 unless the token's `roles` claim contains this value. */
  requiredRole?: string;
  /** Answer 403 unless the token holder has this permission (checked per `mode`). */
  requiredPermission?: string;
}

/** JSON error body sent with a 401 or 403. */
export interface HearthAuthErrorBody {
  error: "unauthorized" | "forbidden";
  error_description: string;
}

/**
 * Outcome of {@link authenticateRequest}.
 *
 * `ok: true` means the request may proceed; `claims` is `null` when no token
 * was sent and `required` is `false`. `ok: false` carries the response to send.
 */
export type HearthAuthResult =
  | { ok: true; claims: Claims | null }
  | {
      ok: false;
      status: 401 | 403;
      body: HearthAuthErrorBody;
      headers: Record<string, string>;
    };

const WWW_AUTHENTICATE = 'Bearer realm="hearth"';

function unauthorized(description: string): HearthAuthResult {
  return {
    ok: false,
    status: 401,
    body: { error: "unauthorized", error_description: description },
    headers: { "WWW-Authenticate": WWW_AUTHENTICATE },
  };
}

const FORBIDDEN: HearthAuthResult = {
  ok: false,
  status: 403,
  body: { error: "forbidden", error_description: "Insufficient scope, role, or permission" },
  headers: {},
};

/** The token from an `Authorization: Bearer <token>` header, or `null`. */
function bearerToken(header: string | null | undefined): string | null {
  const match = /^Bearer[ ]+(\S+)\s*$/i.exec(header ?? "");
  return match ? match[1] : null;
}

/** The mode in force for `opts`, after defaults. */
function resolveMode(opts: HearthMiddlewareOptions): AccessTokenAuthorizationMode {
  return opts.mode ?? opts.client.expectedMode ?? "embedded";
}

/**
 * Check at setup time that the client can serve the configured mode, so a
 * misconfiguration fails at startup rather than on the first request. The
 * middleware factories call it; call it yourself when building on
 * {@link authenticateRequest}.
 *
 * @throws {@link ConfigurationError}
 */
export function assertMiddlewareOptions(opts: HearthMiddlewareOptions): void {
  const mode = resolveMode(opts);
  const { client } = opts;
  if (mode === "introspection" && (!client.clientId || !client.clientSecret)) {
    throw new ConfigurationError(
      "introspection mode needs a client with clientId and clientSecret",
    );
  }
  if (mode === "decision" && opts.requiredPermission && !client.realmId) {
    throw new ConfigurationError("decision mode needs a client with realmId");
  }
}

/**
 * Authenticate and authorize one request from its `Authorization` header.
 *
 * Framework-neutral core of {@link hearthMiddleware}, {@link hearthFastifyHook}
 * and the Next.js helpers; use it to adapt Hearth to another framework.
 *
 * Steps: extract the bearer token, verify it (EdDSA signature, `exp`, `nbf`,
 * `iss`, `aud`), refuse `required_action` tokens, check `requiredScope` and
 * `requiredRole` against the JWT, then check `requiredPermission` per `mode`.
 */
export async function authenticateRequest(
  authorization: string | null | undefined,
  opts: HearthMiddlewareOptions,
): Promise<HearthAuthResult> {
  const required = opts.required !== false;
  const token = bearerToken(authorization);
  if (!token) {
    return required ? unauthorized("Bearer token required") : { ok: true, claims: null };
  }

  let claims: Claims;
  try {
    claims = await opts.client.verifyToken(token);
  } catch (err) {
    if (!required) return { ok: true, claims: null };
    return unauthorized(
      err instanceof TokenVerificationError ? err.message : "Token verification failed",
    );
  }

  // A required_action token is only good for completing the pending actions,
  // never for general API access (spec §6 rule 6) — even on optional routes.
  if (claims.tokenType() === "required_action") {
    return unauthorized("Token requires completion of required actions");
  }

  if (opts.requiredScope && !claims.hasScope(opts.requiredScope)) return FORBIDDEN;
  if (opts.requiredRole && !claims.hasRole(opts.requiredRole)) return FORBIDDEN;

  switch (resolveMode(opts)) {
    case "embedded":
      if (opts.requiredPermission && !claims.hasPermission(opts.requiredPermission)) {
        return FORBIDDEN;
      }
      return { ok: true, claims };

    case "decision":
      if (opts.requiredPermission) {
        const allowed = await opts.client.authorize(token, opts.requiredPermission, {
          organizationId: opts.organizationId,
          resource: opts.resource,
        });
        if (!allowed) return FORBIDDEN;
      }
      return { ok: true, claims };

    case "introspection": {
      let result;
      try {
        const ic = await opts.client.introspectionClient();
        result = await ic.introspect(token, "access_token");
      } catch {
        return FORBIDDEN; // fail closed
      }
      if (!result.active) return unauthorized("Token is no longer active");
      if (result.mode !== undefined && result.mode !== "introspection") return FORBIDDEN;
      if (
        opts.requiredPermission &&
        !(Array.isArray(result.permissions) && result.permissions.includes(opts.requiredPermission))
      ) {
        return FORBIDDEN;
      }
      return { ok: true, claims };
    }
  }
}

// ── Express ────────────────────────────────────────────────────────────────

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** Verified claims, set by `hearthMiddleware()`. */
      hearthClaims?: Claims;
    }
  }
}

/** The request fields {@link hearthMiddleware} reads and writes (Express-compatible). */
export interface MiddlewareRequest {
  headers: Record<string, string | string[] | undefined>;
  hearthClaims?: Claims;
}

/** The response methods {@link hearthMiddleware} calls (Express-compatible). */
export interface MiddlewareResponse {
  status(code: number): unknown;
  setHeader(name: string, value: string): unknown;
  json(body: unknown): unknown;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/**
 * Express (or Connect-style) middleware.
 *
 * On success it sets `req.hearthClaims` and calls `next()`. Otherwise it
 * answers 401 (with `WWW-Authenticate: Bearer realm="hearth"`) or 403 with a
 * JSON body and does not call `next`. An unexpected error goes to `next(err)`.
 *
 * @throws {@link ConfigurationError} when the client cannot serve the mode.
 */
export function hearthMiddleware(opts: HearthMiddlewareOptions) {
  assertMiddlewareOptions(opts);
  return async (
    req: MiddlewareRequest,
    res: MiddlewareResponse,
    next: (err?: unknown) => void,
  ): Promise<void> => {
    let result: HearthAuthResult;
    try {
      result = await authenticateRequest(headerValue(req.headers["authorization"]), opts);
    } catch (err) {
      next(err);
      return;
    }
    if (!result.ok) {
      for (const [name, value] of Object.entries(result.headers)) res.setHeader(name, value);
      res.status(result.status);
      res.json(result.body);
      return;
    }
    if (result.claims) req.hearthClaims = result.claims;
    next();
  };
}

// ── Fastify ────────────────────────────────────────────────────────────────

/** The request fields {@link hearthFastifyHook} reads and writes. */
export interface FastifyRequestLike {
  headers: Record<string, string | string[] | undefined>;
  hearthClaims?: Claims;
}

/** The reply methods {@link hearthFastifyHook} calls. */
export interface FastifyReplyLike {
  code(statusCode: number): FastifyReplyLike;
  header(name: string, value: string): FastifyReplyLike;
  send(body: unknown): unknown;
}

/**
 * Fastify `onRequest` / `preHandler` hook.
 *
 * On success it sets `request.hearthClaims`. Otherwise it sends 401 or 403
 * with a JSON body, which ends the request.
 *
 * @throws {@link ConfigurationError} when the client cannot serve the mode.
 */
export function hearthFastifyHook(opts: HearthMiddlewareOptions) {
  assertMiddlewareOptions(opts);
  return async (request: FastifyRequestLike, reply: FastifyReplyLike): Promise<void> => {
    const result = await authenticateRequest(headerValue(request.headers["authorization"]), opts);
    if (!result.ok) {
      for (const [name, value] of Object.entries(result.headers)) reply.header(name, value);
      reply.code(result.status).send(result.body);
      return;
    }
    if (result.claims) request.hearthClaims = result.claims;
  };
}
