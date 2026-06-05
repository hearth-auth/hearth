import { decodeJwt } from "jose";
import { HearthApiClient } from "./client.js";
import { Claims } from "./claims.js";
import type { MePermissionsResponse } from "./types.js";

/** Options for creating a {@link HearthClient} facade. */
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
   * Optional: wire up a token-change event bus (e.g. from a browser auth
   * client's silent-refresh mechanism). The callback is invoked whenever the
   * access token changes. Returns an unsubscribe function.
   *
   * When absent, {@link HearthFacade.subscribe} is a no-op — existing
   * integrations continue to work, they just will not auto-rerender on
   * silent refresh.
   */
  subscribe?: (callback: () => void) => () => void;
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
 * RBAC claim-oriented facade over {@link HearthClient}.
 *
 * All boolean predicates are synchronous, lock-free, and decode the JWT
 * returned by `getToken()` on every call. No network traffic, no cache.
 * When the token is absent or malformed, every predicate returns `false`.
 */
export interface HearthFacade {
  /**
   * Returns `true` iff the JWT `permissions` claim contains `permission`.
   */
  hasPermission(permission: string): boolean;
  /**
   * Returns `true` iff the JWT `roles` claim contains `role`.
   */
  hasRole(role: string): boolean;
  /**
   * Returns `true` iff the JWT `groups` claim contains `group`.
   */
  inGroup(group: string): boolean;
  /**
   * Returns `true` iff the JWT `oid` claim equals `org`.
   */
  inOrg(org: string): boolean;
  /**
   * Returns the typed {@link Claims} decoded from the current access token,
   * or `null` when the token is absent or unparseable.
   * Signature is NOT verified.
   */
  getClaims(): Claims | null;
  /**
   * Subscribe to token-change events (e.g. silent refresh).
   * The callback is invoked each time the access token is replaced.
   * Returns an unsubscribe function to be called on cleanup.
   *
   * When no `subscribe` option was provided to {@link createHearth},
   * this is a no-op that returns an empty unsubscribe function.
   */
  subscribe(callback: () => void): () => void;
  /** Narrow HTTP surface for live RBAC resolution. */
  client: HearthHttpClient;
}

interface RbacJwtClaims {
  permissions?: unknown;
  roles?: unknown;
  groups?: unknown;
  oid?: unknown;
}

/**
 * Decode the middle JWT segment using `jose.decodeJwt`. Returns `null`
 * when the token is missing, malformed, or cannot be parsed as JSON.
 * Signature is NOT verified — the app trusts its own token.
 */
function safeDecode(token: string | null | undefined): RbacJwtClaims | null {
  if (!token || typeof token !== "string") {
    return null;
  }
  try {
    return decodeJwt(token) as RbacJwtClaims;
  } catch {
    return null;
  }
}

function arrayContains(claim: unknown, value: string): boolean {
  return Array.isArray(claim) && claim.includes(value);
}

/**
 * Create a {@link HearthFacade} over the RBAC claim set embedded in the
 * JWT returned by `opts.getToken()`.
 */
export function createHearth(opts: HearthOptions): HearthFacade {
  const http = new HearthApiClient({
    baseUrl: opts.baseUrl,
    realmId: opts.realmId,
  });

  function claims(): RbacJwtClaims | null {
    return safeDecode(opts.getToken());
  }

  const subscribeFn = opts.subscribe ?? (() => () => undefined);

  return {
    hasPermission(permission: string): boolean {
      const c = claims();
      return c !== null && arrayContains(c.permissions, permission);
    },
    hasRole(role: string): boolean {
      const c = claims();
      return c !== null && arrayContains(c.roles, role);
    },
    inGroup(group: string): boolean {
      const c = claims();
      return c !== null && arrayContains(c.groups, group);
    },
    inOrg(org: string): boolean {
      const c = claims();
      return c !== null && typeof c.oid === "string" && c.oid === org;
    },
    getClaims(): Claims | null {
      const token = opts.getToken();
      if (!token) return null;
      try {
        return Claims.decode(token);
      } catch {
        return null;
      }
    },
    subscribe(callback: () => void): () => void {
      return subscribeFn(callback);
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
