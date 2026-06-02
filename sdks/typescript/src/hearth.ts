import { decodeJwt } from "jose";
import { HearthApiClient } from "./client.js";
import { SessionVersionCache } from "./session-version-cache.js";
import type { MePermissionsResponse, SessionVersionConfig } from "./types.js";

/** Options for creating a {@link HearthFacade} via {@link createHearth}. */
export interface HearthOptions {
  /** Base URL of the Hearth server, e.g. `https://hearth.example.com`. */
  baseUrl: string;
  /** Realm ID to scope all requests to. */
  realmId: string;
  /**
   * Called synchronously on every `hasPermission` / `hasRole` /
   * `inGroup` / `inOrg` check. Return `null`/`undefined` when the
   * caller is unauthenticated.
   */
  getToken: () => string | null | undefined;
  /**
   * Optional session-version cache configuration (RFC HEA-930 § 13).
   *
   * When `enabled: true` the SDK fetches a session-version snapshot on
   * startup and polls the delta feed at `pollIntervalMs` intervals.
   * Every `hasPermission` / `hasRole` / `inGroup` / `inOrg` call then
   * validates the token's `sv` claim against the local cache — no
   * per-request network hop required.
   *
   * Tokens without an `sv` claim pass through unchanged (backward compat).
   */
  sessionVersions?: SessionVersionConfig;
}

/**
 * Minimum HTTP surface exposed by the facade.
 *
 * For the full API (auth code flow, admin, JWKS, etc.) construct a
 * {@link HearthClient} directly.
 */
export interface HearthHttpClient {
  /**
   * Calls `GET /v1/me/permissions` and returns the freshly-resolved
   * RBAC claim set for the current bearer token.
   */
  permissions(): Promise<MePermissionsResponse>;
}

/**
 * RBAC claim-oriented facade over the Hearth SDK.
 *
 * When `sessionVersions` is not configured all boolean predicates are
 * synchronous, lock-free, and decode the JWT returned by `getToken()` on
 * every call. No network traffic, no cache. When the token is absent or
 * malformed every predicate returns `false`.
 *
 * When `sessionVersions.enabled` is `true`, the predicates additionally
 * validate the `sv` claim and may throw {@link SessionVersionRevokedError}
 * or {@link SessionVersionCacheStaleError} (see RFC HEA-930 § 8).
 */
export interface HearthFacade {
  /**
   * Returns `true` iff the JWT `permissions` claim contains `permission`.
   *
   * May throw {@link SessionVersionRevokedError} or
   * {@link SessionVersionCacheStaleError} when session-version tracking
   * is enabled and the token's `sv` claim fails validation.
   */
  hasPermission(permission: string): boolean;
  /**
   * Returns `true` iff the JWT `roles` claim contains `role`.
   *
   * Same session-version throw semantics as {@link hasPermission}.
   */
  hasRole(role: string): boolean;
  /**
   * Returns `true` iff the JWT `groups` claim contains `group`.
   *
   * Same session-version throw semantics as {@link hasPermission}.
   */
  inGroup(group: string): boolean;
  /**
   * Returns `true` iff the JWT `oid` claim equals `org`.
   *
   * Same session-version throw semantics as {@link hasPermission}.
   */
  inOrg(org: string): boolean;
  /**
   * Returns the age of the session-version cache in milliseconds.
   *
   * Returns `Infinity` when session-version tracking is not configured or
   * the cache has never been successfully seeded. Use this in health-check
   * endpoints to confirm the cache is fresh before accepting requests.
   */
  sessionVersionCacheAge(): number;
  /**
   * Stops the background session-version poll loop.
   *
   * Call this when disposing the facade in long-running Node.js services
   * to avoid keeping the event loop alive.
   */
  stop(): void;
  /** Narrow HTTP surface for live RBAC resolution. */
  client: HearthHttpClient;
}

interface RbacJwtClaims {
  permissions?: unknown;
  roles?: unknown;
  groups?: unknown;
  oid?: unknown;
  /** Session version — `u64` emitted when session_version.enabled=true. */
  sv?: unknown;
  /** Session ID — present on all session-bearing access tokens. */
  sid?: unknown;
}

/**
 * Decode the middle JWT segment using `jose.decodeJwt`. Returns `null`
 * when the token is missing, malformed, or cannot be parsed as JSON.
 * Signature is NOT verified — the app trusts its own token.
 */
function safeDecode(token: string | null | undefined): RbacJwtClaims | null {
  if (!token || typeof token !== "string") return null;
  try {
    return decodeJwt(token) as RbacJwtClaims;
  } catch {
    return null;
  }
}

function arrayContains(claim: unknown, value: string): boolean {
  return Array.isArray(claim) && claim.includes(value);
}

/** Extract the `sv` claim as `bigint`, or `undefined` if absent/non-numeric. */
function extractSv(c: RbacJwtClaims): bigint | undefined {
  if (c.sv === undefined || c.sv === null) return undefined;
  if (typeof c.sv === "number") return BigInt(Math.trunc(c.sv));
  if (typeof c.sv === "bigint") return c.sv;
  return undefined;
}

/** Extract the `sid` claim as `string`, or `undefined` if absent. */
function extractSid(c: RbacJwtClaims): string | undefined {
  return typeof c.sid === "string" ? c.sid : undefined;
}

/**
 * Create a {@link HearthFacade} over the RBAC claim set embedded in the
 * JWT returned by `opts.getToken()`.
 *
 * When `opts.sessionVersions.enabled` is `true` the facade additionally
 * starts a background session-version poll loop. Call `facade.stop()` to
 * tear it down.
 */
export function createHearth(opts: HearthOptions): HearthFacade {
  const http = new HearthApiClient({
    baseUrl: opts.baseUrl,
    realmId: opts.realmId,
  });

  let svCache: SessionVersionCache | null = null;
  if (opts.sessionVersions?.enabled) {
    svCache = new SessionVersionCache(
      opts.baseUrl,
      opts.realmId,
      opts.sessionVersions,
    );
    svCache.start();
  }

  function claims(): RbacJwtClaims | null {
    return safeDecode(opts.getToken());
  }

  /** Runs the sv check; throws on revoked or stale. No-op when sv absent. */
  function assertSv(c: RbacJwtClaims): void {
    if (svCache !== null) {
      svCache.validateSv(extractSv(c), extractSid(c));
    }
  }

  return {
    hasPermission(permission: string): boolean {
      const c = claims();
      if (c === null) return false;
      assertSv(c);
      return arrayContains(c.permissions, permission);
    },
    hasRole(role: string): boolean {
      const c = claims();
      if (c === null) return false;
      assertSv(c);
      return arrayContains(c.roles, role);
    },
    inGroup(group: string): boolean {
      const c = claims();
      if (c === null) return false;
      assertSv(c);
      return arrayContains(c.groups, group);
    },
    inOrg(org: string): boolean {
      const c = claims();
      if (c === null) return false;
      assertSv(c);
      return typeof c.oid === "string" && c.oid === org;
    },
    sessionVersionCacheAge(): number {
      return svCache?.age() ?? Number.POSITIVE_INFINITY;
    },
    stop(): void {
      svCache?.stop();
    },
    client: {
      permissions(): Promise<MePermissionsResponse> {
        const token = opts.getToken();
        if (!token) {
          return Promise.reject(
            new Error("getToken() returned no token; cannot call permissions()"),
          );
        }
        return http.permissions(token);
      },
    },
  };
}
