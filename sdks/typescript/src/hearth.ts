import { decodeJwt } from "jose";
import { HearthApiClient } from "./client.js";
import { Claims } from "./claims.js";
import { resolveRealmId } from "./realm-resolver.js";
import type { MePermissionsResponse, TokenResponse } from "./types.js";

// ─── Legacy facade types ──────────────────────────────────────────────────────

/** Options for creating a {@link HearthFacade} via the legacy overload. */
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
 * on every call. No network traffic, no cache.
 * When the token is absent or malformed, every predicate returns `false`.
 */
export interface HearthFacade {
  /** Returns `true` iff the JWT `permissions` claim contains `permission`. */
  hasPermission(permission: string): boolean;
  /** Returns `true` iff the JWT `roles` claim contains `role`. */
  hasRole(role: string): boolean;
  /** Returns `true` iff the JWT `groups` claim contains `group`. */
  inGroup(group: string): boolean;
  /** Returns `true` iff the JWT `oid` claim equals `org`. */
  inOrg(org: string): boolean;
  /**
   * Returns the typed {@link Claims} decoded from the current access token,
   * or `null` when the token is absent or unparseable.
   * Signature is NOT verified.
   */
  getClaims(): Claims | null;
  /**
   * Subscribe to token-change events (e.g. silent refresh).
   * Returns an unsubscribe function to be called on cleanup.
   *
   * When no `subscribe` option was provided to {@link createHearth},
   * this is a no-op that returns an empty unsubscribe function.
   */
  subscribe(callback: () => void): () => void;
  /** Narrow HTTP surface for live RBAC resolution. */
  client: HearthHttpClient;
}

// ─── Unified facade types (HEA-1306) ─────────────────────────────────────────

/**
 * Explicit realm configuration for the unified {@link createHearth} factory.
 *
 * At least one of `id` or `slug` must be supplied. When only one is provided,
 * the SDK auto-resolves the other via `GET {baseUrl}/v1/realms/{value}` on
 * first use and caches the result for the process lifetime.
 *
 * @example Both forms explicit (no network round-trip needed)
 * ```ts
 * realm: { id: "550e8400-...", slug: "acme" }
 * ```
 *
 * @example Slug only — UUID resolved automatically
 * ```ts
 * realm: { slug: "acme" }
 * ```
 *
 * @example UUID only — slug resolved on demand if needed
 * ```ts
 * realm: { id: "550e8400-..." }
 * ```
 */
export interface HearthRealmConfig {
  /** Realm UUID — used for `X-Realm-ID` request headers. */
  id?: string;
  /** Human-readable slug — used in OIDC URL paths. */
  slug?: string;
}

/** Auth configuration for the browser-auth token store. */
export interface HearthAuthConfig {
  /** OAuth client ID. */
  clientId: string;
  /**
   * Default redirect URI for token exchange. Can be overridden per-call
   * in {@link UnifiedHearthAuth.exchangeCode}.
   */
  redirectUri?: string;
  /** Default scopes. Informational only — not enforced by the facade. */
  scopes?: string[];
}

/**
 * Options for the unified {@link createHearth} factory.
 *
 * Use this form instead of {@link HearthOptions} for new integrations —
 * it manages the token internally so there is no need for an external
 * `tokenRef` or `getToken` callback.
 *
 * The `realm` field accepts any of:
 * - A plain **string** — either a UUID or a human-readable slug. The SDK
 *   auto-detects the form and resolves the other on first API call.
 * - A {@link HearthRealmConfig} object with `id`, `slug`, or both. When both
 *   are present no network round-trip is needed.
 *
 * **One env var is enough:**
 * ```ts
 * createHearth({ baseUrl, realm: import.meta.env.VITE_REALM, auth: { clientId } })
 * ```
 */
export interface HearthConfig {
  /** Base URL of the Hearth server, e.g. `https://hearth.example.com`. */
  baseUrl: string;
  /**
   * Realm identifier — either a UUID, a human-readable slug, or an explicit
   * {@link HearthRealmConfig} object. The SDK auto-resolves the other form on
   * first use and caches the result.
   */
  realm: string | HearthRealmConfig;
  /**
   * Optional auth configuration. When provided, `auth` on the returned
   * {@link UnifiedHearthFacade} will be non-null and exposes token exchange
   * and refresh operations bound to the configured `clientId`.
   */
  auth?: HearthAuthConfig;
  /**
   * Timeout for realm resolution HTTP calls in milliseconds.
   * Default: 10 000 (10 seconds).
   */
  realmResolutionTimeout?: number;
}

/** Auth operations on the unified facade; non-null when `auth` config was supplied. */
export interface UnifiedHearthAuth {
  /** The OAuth client ID this facade was configured with. */
  readonly clientId: string;
  /**
   * Exchanges an authorization code for tokens.
   * `redirectUri` defaults to `HearthAuthConfig.redirectUri` when omitted.
   */
  exchangeCode(params: {
    code: string;
    redirectUri?: string;
    codeVerifier?: string;
  }): Promise<TokenResponse>;
  /**
   * Refreshes tokens using a stored refresh token.
   * Call `setToken(response.access_token)` after a successful refresh to
   * keep the facade's internal store and React subscriptions in sync.
   */
  refreshTokens(refreshToken: string): Promise<TokenResponse>;
}

/**
 * Extended facade returned by the unified {@link createHearth} overload.
 *
 * Extends {@link HearthFacade} with an internal token store so the caller
 * does not need an external `tokenRef` or `getToken` callback.
 */
export interface UnifiedHearthFacade extends HearthFacade {
  /**
   * Stores a new access token in the facade and notifies all subscribers.
   * Pass `null` to clear the token (e.g. on sign-out).
   */
  setToken(accessToken: string | null): void;
  /** Returns the current access token from the internal store, or `null`. */
  getToken(): string | null;
  /**
   * Auth operations. `null` when no `auth` config was provided to
   * {@link createHearth}.
   */
  readonly auth: UnifiedHearthAuth | null;
}

// ─── Shared internals ─────────────────────────────────────────────────────────

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

// ─── Factory overloads ────────────────────────────────────────────────────────

/**
 * Create a unified {@link UnifiedHearthFacade} with an internal token store.
 *
 * @example
 * ```ts
 * const hearth = createHearth({
 *   baseUrl: "https://auth.example.com",
 *   realm: { id: "default" },
 *   auth: { clientId: "spa-client" },
 * });
 *
 * // In your session restore hook:
 * useSession({
 *   getRefreshToken: () => localStorage.getItem("hearth_rt"),
 *   refresh: (rt) => hearth.auth!.refreshTokens(rt),
 *   onRefresh: (tokens) => {
 *     localStorage.setItem("hearth_rt", tokens.refresh_token);
 *     hearth.setToken(tokens.access_token);
 *   },
 * });
 * ```
 */
export function createHearth(opts: HearthConfig): UnifiedHearthFacade;
/**
 * Create a {@link HearthFacade} from an external token callback.
 *
 * @deprecated Prefer the `realm`-based overload (HEA-1306) for new
 * integrations — it manages the token store internally and removes the
 * need for a `tokenRef` / `getToken` callback.
 */
export function createHearth(opts: HearthOptions): HearthFacade;
export function createHearth(
  opts: HearthConfig | HearthOptions,
): HearthFacade | UnifiedHearthFacade {
  if ("realm" in opts) {
    return buildUnifiedFacade(opts);
  }
  return buildLegacyFacade(opts);
}

// ─── Deprecated shim (HEA-1306) ──────────────────────────────────────────────

/**
 * @deprecated Use {@link createHearth} with an `auth` config block instead.
 *
 * This shim was introduced in HEA-1306 to guide integrations that would
 * otherwise build a separate browser-auth client alongside `createHearth`.
 * It delegates directly to `createHearth` and will be removed in the next
 * major version.
 *
 * @example
 * ```ts
 * // Before (deprecated):
 * const h = createHearthAuth({ baseUrl, realm, auth: { clientId } });
 *
 * // After (preferred):
 * const h = createHearth({ baseUrl, realm, auth: { clientId } });
 * ```
 */
export function createHearthAuth(opts: HearthConfig): UnifiedHearthFacade {
  return buildUnifiedFacade(opts);
}

// ─── Unified implementation ───────────────────────────────────────────────────

/**
 * Normalise the `realm` config field to a single opaque string that is either
 * a UUID or a slug. When both `id` and `slug` are present on a config object
 * the UUID is preferred (no resolution needed).
 */
function realmToString(realm: string | HearthRealmConfig): string {
  if (typeof realm === "string") return realm;
  if (realm.id) return realm.id;
  if (realm.slug) return realm.slug;
  throw new Error(
    "realm config must supply at least one of `id` or `slug`",
  );
}

/**
 * Lazy API client factory that resolves the realm UUID on first use.
 *
 * When both `id` and `slug` are provided in the config no network call is
 * ever needed. When only one is provided the resolver fetches and caches
 * the mapping on the first call that needs `realmId`.
 */
class LazyRealmApiClient {
  private _promise: Promise<HearthApiClient> | null = null;

  constructor(
    private readonly baseUrl: string,
    private readonly realm: string | HearthRealmConfig,
    private readonly httpTimeout: number,
  ) {}

  /**
   * Returns (and caches) a `HearthApiClient` bound to the resolved realm UUID.
   * Subsequent calls return the same instance without network overhead.
   *
   * Resolution rules:
   * - `realm: { id: "..." }` — `id` is used directly (no network call).
   * - `realm: "uuid-shaped-string"` — UUID detected, used directly.
   * - `realm: "slug-string"` or `realm: { slug: "..." }` — fetch
   *   `GET /v1/realms/{slug}` to obtain the UUID.
   */
  get(): Promise<HearthApiClient> {
    if (!this._promise) {
      const realm = this.realm;
      let idPromise: Promise<string>;

      if (typeof realm !== "string" && realm.id !== undefined) {
        // Explicit id in config object — trust it without resolution.
        idPromise = Promise.resolve(realm.id);
      } else {
        const slugOrId = realmToString(realm);
        idPromise = resolveRealmId(this.baseUrl, slugOrId, this.httpTimeout);
      }

      this._promise = idPromise.then(
        (realmId) => new HearthApiClient({ baseUrl: this.baseUrl, realmId }),
      );
    }
    return this._promise;
  }
}

function buildUnifiedFacade(opts: HearthConfig): UnifiedHearthFacade {
  const httpTimeout = opts.realmResolutionTimeout ?? 10_000;
  const lazy = new LazyRealmApiClient(opts.baseUrl, opts.realm, httpTimeout);

  let currentToken: string | null = null;
  const listeners = new Set<() => void>();

  function notify(): void {
    for (const cb of listeners) cb();
  }

  function decodedClaims(): RbacJwtClaims | null {
    return safeDecode(currentToken);
  }

  // Build auth ops lazily too — they route through the same lazy client.
  const auth: UnifiedHearthAuth | null = opts.auth
    ? buildAuthOps(lazy, opts.auth)
    : null;

  return {
    setToken(accessToken: string | null): void {
      currentToken = accessToken;
      notify();
    },
    getToken(): string | null {
      return currentToken;
    },
    hasPermission(permission: string): boolean {
      const c = decodedClaims();
      return c !== null && arrayContains(c.permissions, permission);
    },
    hasRole(role: string): boolean {
      const c = decodedClaims();
      return c !== null && arrayContains(c.roles, role);
    },
    inGroup(group: string): boolean {
      const c = decodedClaims();
      return c !== null && arrayContains(c.groups, group);
    },
    inOrg(org: string): boolean {
      const c = decodedClaims();
      return c !== null && typeof c.oid === "string" && c.oid === org;
    },
    getClaims(): Claims | null {
      if (!currentToken) return null;
      try {
        return Claims.decode(currentToken);
      } catch {
        return null;
      }
    },
    subscribe(callback: () => void): () => void {
      listeners.add(callback);
      return () => {
        listeners.delete(callback);
      };
    },
    client: {
      async permissions(): Promise<MePermissionsResponse> {
        if (!currentToken) {
          throw new Error("No token stored; cannot call permissions()");
        }
        const http = await lazy.get();
        return http.permissions(currentToken);
      },
    },
    auth,
  };
}

function buildAuthOps(
  lazy: LazyRealmApiClient,
  authCfg: HearthAuthConfig,
): UnifiedHearthAuth {
  return {
    get clientId(): string {
      return authCfg.clientId;
    },
    async exchangeCode(params: {
      code: string;
      redirectUri?: string;
      codeVerifier?: string;
    }): Promise<TokenResponse> {
      const http = await lazy.get();
      return http.exchangeCode({
        clientId: authCfg.clientId,
        code: params.code,
        redirectUri: params.redirectUri ?? authCfg.redirectUri ?? "",
        codeVerifier: params.codeVerifier,
      });
    },
    async refreshTokens(refreshToken: string): Promise<TokenResponse> {
      const http = await lazy.get();
      return http.refreshTokens(authCfg.clientId, refreshToken);
    },
  };
}

// ─── Legacy implementation ────────────────────────────────────────────────────

function buildLegacyFacade(opts: HearthOptions): HearthFacade {
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
