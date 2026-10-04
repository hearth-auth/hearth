import type { Claims } from "./claims.js";
import { HearthApiClient } from "./client.js";
import { HearthClient } from "./hearth-client.js";
import { SessionVersionCache } from "./session-version-cache.js";
import type { MePermissionsResponse, SessionVersionConfig } from "./types.js";

/** Options for creating a {@link HearthFacade} via {@link createHearth}. */
export interface HearthOptions {
  /** Base URL of the Hearth server, e.g. `https://hearth.example.com`. */
  baseUrl: string;
  /** Realm ID to scope all requests to. */
  realmId: string;
  /**
   * The realm's issuer URL, e.g. `https://hearth.example.com/realms/acme`.
   * Tokens are verified against the JWKS this issuer publishes, and their
   * `iss` must equal it.
   */
  issuerUrl: string;
  /**
   * Expected `aud` of the token: the name of the API that checks it
   * (RFC 9068 §4). Default `"hearth"`, the audience Hearth mints when a
   * client names no resource. The check is always on.
   */
  audience?: string;
  /**
   * Called on every `hasPermission` / `hasRole` / `inGroup` / `inOrg`
   * check. Return `null`/`undefined` when the caller is unauthenticated.
   */
  getToken: () => string | null | undefined | Promise<string | null | undefined>;
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
 * Every predicate verifies the token returned by `getToken()` before it
 * reads a claim: the EdDSA signature against the realm JWKS (fetched once,
 * then cached), plus `exp`, `nbf`, `iat`, `iss` and `aud`. A token that is
 * absent or does not verify holds nothing, and the predicate resolves to
 * `false`.
 *
 * When `sessionVersions.enabled` is `true`, the predicates additionally
 * validate the `sv` claim and may reject with
 * {@link SessionVersionRevokedError} or {@link SessionVersionCacheStaleError}
 * (see RFC HEA-930 § 8).
 */
export interface HearthFacade {
  /**
   * Resolves `true` iff the token verifies and its `permissions` claim
   * contains `permission`.
   *
   * May reject with {@link SessionVersionRevokedError} or
   * {@link SessionVersionCacheStaleError} when session-version tracking
   * is enabled and the token's `sv` claim fails validation.
   */
  hasPermission(permission: string): Promise<boolean>;
  /**
   * Resolves `true` iff the token verifies and its `roles` claim contains `role`.
   *
   * Same session-version semantics as {@link hasPermission}.
   */
  hasRole(role: string): Promise<boolean>;
  /**
   * Resolves `true` iff the token verifies and its `groups` claim contains `group`.
   *
   * Same session-version semantics as {@link hasPermission}.
   */
  inGroup(group: string): Promise<boolean>;
  /**
   * Resolves `true` iff the token verifies and its `oid` claim equals `org`.
   *
   * Same session-version semantics as {@link hasPermission}.
   */
  inOrg(org: string): Promise<boolean>;
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

function arrayContains(claim: unknown, value: string): boolean {
  return Array.isArray(claim) && claim.includes(value);
}

/** Extract the `sv` claim as `bigint`, or `undefined` if absent/non-numeric. */
function extractSv(c: Claims): bigint | undefined {
  const sv = c.get("sv");
  if (typeof sv === "number") return BigInt(Math.trunc(sv));
  if (typeof sv === "bigint") return sv;
  return undefined;
}

/** Extract the `sid` claim as `string`, or `undefined` if absent. */
function extractSid(c: Claims): string | undefined {
  const sid = c.get("sid");
  return typeof sid === "string" ? sid : undefined;
}

/**
 * Create a {@link HearthFacade} over the RBAC claims of the token returned
 * by `opts.getToken()`. Each check verifies that token first.
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
  // Discovery and the JWKS are fetched on the first check and cached.
  const verifier = new HearthClient({ issuerUrl: opts.issuerUrl, audience: opts.audience });

  let svCache: SessionVersionCache | null = null;
  if (opts.sessionVersions?.enabled) {
    svCache = new SessionVersionCache(opts.baseUrl, opts.realmId, opts.sessionVersions);
    svCache.start();
  }

  /**
   * The verified claims of the current token, or `null` when there is no
   * token or it does not verify. Runs the `sv` check on verified claims; that
   * check throws on a revoked or stale session.
   */
  async function verifiedClaims(): Promise<Claims | null> {
    const token = await opts.getToken();
    if (!token || typeof token !== "string") return null;
    let claims: Claims;
    try {
      claims = await verifier.verifyToken(token);
    } catch {
      return null;
    }
    svCache?.validateSv(extractSv(claims), extractSid(claims));
    return claims;
  }

  return {
    async hasPermission(permission: string): Promise<boolean> {
      const c = await verifiedClaims();
      return c !== null && arrayContains(c.get("permissions"), permission);
    },
    async hasRole(role: string): Promise<boolean> {
      const c = await verifiedClaims();
      return c !== null && arrayContains(c.get("roles"), role);
    },
    async inGroup(group: string): Promise<boolean> {
      const c = await verifiedClaims();
      return c !== null && arrayContains(c.get("groups"), group);
    },
    async inOrg(org: string): Promise<boolean> {
      const c = await verifiedClaims();
      const oid = c?.get("oid");
      return typeof oid === "string" && oid === org;
    },
    sessionVersionCacheAge(): number {
      return svCache?.age() ?? Number.POSITIVE_INFINITY;
    },
    stop(): void {
      svCache?.stop();
    },
    client: {
      async permissions(): Promise<MePermissionsResponse> {
        const token = await opts.getToken();
        if (!token) {
          throw new Error("getToken() returned no token; cannot call permissions()");
        }
        return http.permissions(token);
      },
    },
  };
}
