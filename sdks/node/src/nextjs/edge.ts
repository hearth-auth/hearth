/**
 * @hearth-auth/node — Next.js Edge Runtime adapter.
 *
 * This file is safe to import from `middleware.ts` (Vercel/Next.js Edge Runtime):
 * it never imports `node:crypto` and relies only on Web Crypto (`globalThis.crypto`)
 * which is available in V8 Isolate environments.
 *
 * Exports:
 *   EdgeToken                — typed claim accessors (no node:crypto)
 *   hearthEdgeMiddleware()   — edge-compatible middleware.ts factory
 *   requirePermission()      — composable guard for edge middleware
 *   EdgeMiddlewareOptions    — config type
 */

import { createRemoteJWKSet, jwtVerify } from "jose";
import type { JWTPayload, RemoteJWKSetOptions, JWSHeaderParameters, FlattenedJWSInput, GetKeyFunction } from "jose";

// ── Constant-time comparison (Web Crypto compatible) ─────────────────────────

/**
 * Timing-safe string equality that works in both Edge Runtime and Node.js.
 * Permission/role/scope strings are not secret values, but constant-time
 * comparison prevents implementation-level timing variance from leaking
 * which strings are tested at runtime.
 */
function ctEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const maxLen = Math.max(a.length, b.length);
  const bufA = enc.encode(a.padEnd(maxLen, "\0"));
  const bufB = enc.encode(b.padEnd(maxLen, "\0"));
  let diff = bufA.length !== bufB.length ? 1 : 0;
  for (let i = 0; i < bufA.length; i++) {
    diff |= bufA[i]! ^ (bufB[i] ?? 0);
  }
  return diff === 0;
}

// ── EdgeToken ─────────────────────────────────────────────────────────────────

/** Raw JWT payload shape with Hearth custom claims. */
interface RawClaims extends JWTPayload {
  scope?: string;
  scopes?: string[];
  roles?: string[];
  permissions?: string[];
  groups?: string[];
  oid?: string;
  org_groups?: string[];
  token_type?: string;
  required_actions?: string[];
  [key: string]: unknown;
}

/**
 * Edge-compatible verified token.
 *
 * Mirrors the Node SDK's `VerifiedToken` API but uses only Web Crypto APIs
 * so it can be safely constructed in Edge Runtime (V8 Isolate) environments.
 */
export class EdgeToken {
  private readonly _payload: RawClaims;
  private readonly _header: Record<string, unknown>;

  constructor(payload: JWTPayload, header: Record<string, unknown>) {
    this._payload = payload as RawClaims;
    this._header = header;
  }

  /** The `sub` claim. Returns empty string if absent. */
  subject(): string {
    return this._payload.sub ?? "";
  }

  /** The `iss` claim. Returns empty string if absent. */
  issuer(): string {
    return this._payload.iss ?? "";
  }

  /** The `aud` claim normalized to an array. */
  audiences(): string[] {
    const aud = this._payload.aud;
    if (!aud) return [];
    return Array.isArray(aud) ? aud : [aud];
  }

  /** The `iat` claim as a Date, or null if absent. */
  issuedAt(): Date | null {
    return this._payload.iat !== undefined ? new Date(this._payload.iat * 1000) : null;
  }

  /** The `exp` claim as a Date, or null if absent. */
  expiry(): Date | null {
    return this._payload.exp !== undefined ? new Date(this._payload.exp * 1000) : null;
  }

  /** The `jti` claim. Returns empty string if absent. */
  jwtID(): string {
    return this._payload.jti ?? "";
  }

  /** The raw `scope` string (space-separated). Returns empty string if absent. */
  scope(): string {
    return this._payload.scope ?? "";
  }

  /** Individual scope values from `scope` or `scopes` claim. */
  scopes(): string[] {
    if (this._payload.scopes) return [...this._payload.scopes];
    const sc = this._payload.scope;
    if (!sc) return [];
    return sc.split(/\s+/).filter(Boolean);
  }

  /** Get an arbitrary claim by key. */
  get(key: string): unknown {
    return this._payload[key];
  }

  /** Return a frozen copy of the raw JWT payload. */
  raw(): Readonly<RawClaims> {
    return Object.freeze({ ...this._payload });
  }

  /** Timing-safe scope check. */
  hasScope(s: string): boolean {
    return this.scopes().some((sc) => ctEqual(sc, s));
  }

  /** Timing-safe role check from `roles` claim. */
  hasRole(r: string): boolean {
    return (this._payload.roles ?? []).some((role) => ctEqual(role, r));
  }

  /** Timing-safe permission check from `permissions` claim. */
  hasPermission(p: string): boolean {
    return (this._payload.permissions ?? []).some((perm) => ctEqual(perm, p));
  }

  /** Returns true if the token's `groups` claim contains the given group id. */
  inGroup(groupId: string): boolean {
    return (this._payload.groups ?? []).some((g) => ctEqual(g, groupId));
  }

  /** Returns true if the token's `oid` claim matches the given org id. */
  inOrg(orgId: string): boolean {
    const oid = this._payload.oid;
    if (!oid) return false;
    return ctEqual(oid, orgId);
  }

  /** The `token_type` claim (`"access"`, `"refresh"`, `"required_action"`). */
  tokenType(): string {
    return this._payload.token_type ?? "";
  }

  /** The `oid` (organization ID) claim, or undefined if absent. */
  organizationId(): string | undefined {
    return this._payload.oid;
  }

  /** The `required_actions` claim. Returns empty array if absent. */
  requiredActions(): string[] {
    return this._payload.required_actions ? [...this._payload.required_actions] : [];
  }

  /** @internal */
  get _rawHeader(): Record<string, unknown> {
    return this._header;
  }
}

// ── requirePermission ─────────────────────────────────────────────────────────

/**
 * Composable guard — returns a predicate that tests a single permission.
 *
 * Works with both `EdgeToken` and the Node SDK's `VerifiedToken` (both expose
 * `hasPermission()`).
 *
 * @example
 * const guardAdmin = requirePermission("users:write");
 * if (!guardAdmin(token)) return new Response(null, { status: 403 });
 */
export function requirePermission(permission: string): (token: { hasPermission(p: string): boolean }) => boolean {
  return (token) => token.hasPermission(permission);
}

// ── hearthEdgeMiddleware ──────────────────────────────────────────────────────

/** Options for the Edge-compatible middleware factory. */
export interface EdgeMiddlewareOptions {
  /** Issuer URL — must match the `iss` claim in tokens. */
  issuerUrl: string;
  /**
   * JWKS endpoint (e.g. `https://auth.example.com/.well-known/jwks.json`).
   * Required for edge middleware because OIDC discovery involves a network round-trip
   * that is wasteful to perform on every edge invocation.
   */
  jwksUri: string;
  /** Expected audience claim(s). Optional — if omitted, `aud` is not checked. */
  audience?: string | string[];
  /** Clock skew tolerance in seconds (default: 60). */
  clockSkewSeconds?: number;
  /** If true (default), return 401 when no Bearer token is present. */
  required?: boolean;
  /** Return 403 when the verified token is missing this scope. */
  requiredScope?: string;
  /** Return 403 when the verified token is missing this role. */
  requiredRole?: string;
  /** Return 403 when the verified token is missing this permission. */
  requiredPermission?: string;
  /** JWKS cache TTL in milliseconds (default: 10 minutes). */
  jwksCacheTtlMs?: number;
}

const WWW_AUTH = 'Bearer realm="hearth"';

type RequestLike = {
  headers: {
    get(name: string): string | null;
    entries(): IterableIterator<[string, string]>;
  };
};

type JwkKeyArg = GetKeyFunction<JWSHeaderParameters, FlattenedJWSInput>;

/**
 * Edge-compatible middleware factory for Next.js `middleware.ts`.
 *
 * Verifies the `Authorization: Bearer` token via JWKS — uses only Web Crypto
 * (`globalThis.crypto`) so it runs safely in the V8 Isolate Edge Runtime.
 *
 * Returns `undefined` on success (call `NextResponse.next()` in your middleware).
 * Returns a `Response` (401 or 403) on failure — return it directly.
 *
 * @example
 * // middleware.ts
 * import { NextResponse } from "next/server";
 * import { hearthEdgeMiddleware } from "@hearth-auth/node/nextjs/edge";
 *
 * const guard = hearthEdgeMiddleware({
 *   issuerUrl: "https://auth.example.com",
 *   jwksUri: "https://auth.example.com/.well-known/jwks.json",
 * });
 *
 * export async function middleware(request: NextRequest) {
 *   const result = await guard(request);
 *   if (result) return result; // 401 or 403 Response
 *   return NextResponse.next();
 * }
 *
 * export const config = { matcher: ["/api/:path*"] };
 */
export function hearthEdgeMiddleware(options: EdgeMiddlewareOptions): (req: RequestLike) => Promise<Response | undefined> {
  const {
    issuerUrl,
    jwksUri,
    clockSkewSeconds = 60,
    required = true,
    jwksCacheTtlMs = 10 * 60 * 1000,
  } = options;

  const jwkSet: JwkKeyArg = createRemoteJWKSet(
    new URL(jwksUri),
    { cacheMaxAge: jwksCacheTtlMs, cooldownDuration: 30_000 } as RemoteJWKSetOptions,
  ) as unknown as JwkKeyArg;

  return async (req: RequestLike): Promise<Response | undefined> => {
    const authHeader = req.headers.get("authorization");

    if (!authHeader?.startsWith("Bearer ")) {
      if (required) {
        return new Response(
          JSON.stringify({ error: "unauthorized", error_description: "Bearer token required" }),
          {
            status: 401,
            headers: {
              "WWW-Authenticate": WWW_AUTH,
              "Content-Type": "application/json",
            },
          },
        );
      }
      return undefined;
    }

    const rawToken = authHeader.slice(7);
    let token: EdgeToken;

    try {
      const result = await jwtVerify(rawToken, jwkSet, {
        issuer: issuerUrl,
        audience: options.audience,
        clockTolerance: clockSkewSeconds,
        algorithms: ["EdDSA", "RS256", "ES256", "RS384", "ES384", "RS512", "ES512"],
      });
      token = new EdgeToken(result.payload, result.protectedHeader as Record<string, unknown>);
    } catch {
      if (required) {
        return new Response(
          JSON.stringify({ error: "unauthorized", error_description: "Token verification failed" }),
          {
            status: 401,
            headers: {
              "WWW-Authenticate": WWW_AUTH,
              "Content-Type": "application/json",
            },
          },
        );
      }
      return undefined;
    }

    // §6 Rule 6: required_action tokens must not be accepted for general API access
    if (token.tokenType() === "required_action") {
      return new Response(
        JSON.stringify({
          error: "unauthorized",
          error_description: "Token requires completion of required actions",
        }),
        {
          status: 401,
          headers: {
            "WWW-Authenticate": WWW_AUTH,
            "Content-Type": "application/json",
          },
        },
      );
    }

    // Scope / role / permission guards
    if (options.requiredScope && !token.hasScope(options.requiredScope)) {
      return new Response(
        JSON.stringify({ error: "forbidden", error_description: "Insufficient scope, role, or permission" }),
        { status: 403, headers: { "Content-Type": "application/json" } },
      );
    }
    if (options.requiredRole && !token.hasRole(options.requiredRole)) {
      return new Response(
        JSON.stringify({ error: "forbidden", error_description: "Insufficient scope, role, or permission" }),
        { status: 403, headers: { "Content-Type": "application/json" } },
      );
    }
    if (options.requiredPermission && !token.hasPermission(options.requiredPermission)) {
      return new Response(
        JSON.stringify({ error: "forbidden", error_description: "Insufficient scope, role, or permission" }),
        { status: 403, headers: { "Content-Type": "application/json" } },
      );
    }

    return undefined;
  };
}
