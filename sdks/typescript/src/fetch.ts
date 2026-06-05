import type { TokenResponse } from "./types.js";

/** Options for {@link createAuthenticatedFetch}. */
export interface AuthenticatedFetchOptions {
  /**
   * Returns the current access token, or `null`/`undefined` when not
   * authenticated. Called before every request.
   */
  getAccessToken: () => string | null | undefined;
  /**
   * Returns the stored refresh token, or `null`/`undefined` when absent.
   * When absent, a 401 response is returned without attempting a refresh.
   */
  getRefreshToken: () => string | null | undefined;
  /**
   * Performs a token refresh given the current refresh token.
   *
   * Guaranteed to be called **at most once per concurrent 401 storm** — all
   * in-flight requests that receive a 401 share a single pending promise.
   */
  refresh: (refreshToken: string) => Promise<TokenResponse>;
  /**
   * Called after a successful refresh with the new token pair.
   *
   * Use this to persist the new tokens and update `getAccessToken`'s source.
   * Called at most once per refresh cycle regardless of how many concurrent
   * requests were waiting on the result.
   */
  onRefresh?: (tokens: TokenResponse) => void;
  /**
   * Called when the refresh fails (expired/revoked grant) or when no refresh
   * token is available.
   *
   * Typical usage: clear stored tokens and redirect to the login route. When
   * omitted, the original 401 response is returned silently.
   *
   * Called at most once per refresh failure.
   */
  onRefreshFailure?: (error: unknown) => void;
  /** Optional base URL prepended to relative (non-`http`) request paths. */
  baseUrl?: string;
}

/** A `fetch`-shaped function returned by {@link createAuthenticatedFetch}. */
export type AuthenticatedFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

function withBearer(init: RequestInit | undefined, token: string): RequestInit {
  const headers = new Headers(init?.headers);
  headers.set("Authorization", `Bearer ${token}`);
  return { ...init, headers };
}

/**
 * Creates a `fetch`-shaped function that automatically attaches `Bearer`
 * tokens and handles 401 responses with refresh-and-retry logic.
 *
 * **De-duplication guarantee:** when multiple in-flight requests all receive
 * a 401 simultaneously, exactly one token refresh is triggered. All waiting
 * callers share the single in-flight promise and retry with the new token.
 *
 * **Lifecycle callbacks** (`onRefresh`, `onRefreshFailure`) are called at most
 * once per refresh cycle regardless of how many callers were waiting.
 *
 * @example
 * ```ts
 * const apiFetch = createAuthenticatedFetch({
 *   getAccessToken: () => tokenStore.access,
 *   getRefreshToken: () => tokenStore.refresh,
 *   refresh: (rt) => apiClient.refreshTokens(CLIENT_ID, rt),
 *   onRefresh: (t) => tokenStore.set(t),
 *   onRefreshFailure: () => router.push("/login"),
 *   baseUrl: "https://api.example.com",
 * });
 * const data = await apiFetch("/v1/users").then((r) => r.json());
 * ```
 */
export function createAuthenticatedFetch(
  opts: AuthenticatedFetchOptions,
): AuthenticatedFetch {
  // Single in-flight promise shared across concurrent callers — the storm de-dup mechanism.
  // Assigned synchronously (before any await) so concurrent microtask-queue
  // continuations always observe the set value before the promise settles.
  let inflightRefresh: Promise<string> | null = null;

  function resolveInput(input: RequestInfo | URL): RequestInfo | URL {
    const base = opts.baseUrl;
    if (!base || typeof input !== "string" || /^https?:\/\//i.test(input)) {
      return input;
    }
    return `${base.replace(/\/$/, "")}/${input.replace(/^\//, "")}`;
  }

  function acquireRefresh(): Promise<string> {
    if (inflightRefresh !== null) return inflightRefresh;

    // Async IIFE executes synchronously until the first `await`, ensuring
    // `inflightRefresh` is set before any concurrent caller can check it.
    inflightRefresh = (async (): Promise<string> => {
      const rt = opts.getRefreshToken();
      if (!rt) {
        const err = new Error("No refresh token available");
        opts.onRefreshFailure?.(err);
        throw err;
      }
      let tokens: TokenResponse;
      try {
        tokens = await opts.refresh(rt);
      } catch (err) {
        opts.onRefreshFailure?.(err);
        throw err;
      }
      opts.onRefresh?.(tokens);
      return tokens.access_token;
    })().finally(() => {
      inflightRefresh = null;
    });

    return inflightRefresh;
  }

  return async function authenticatedFetch(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    const resolved = resolveInput(input);
    const token = opts.getAccessToken();
    const firstInit = token != null ? withBearer(init, token) : init;

    const response = await fetch(resolved, firstInit);
    if (response.status !== 401) return response;

    // 401 path: acquire the single in-flight refresh (de-duped across all concurrent callers).
    let newToken: string;
    try {
      newToken = await acquireRefresh();
    } catch {
      // onRefreshFailure already called inside acquireRefresh.
      return response;
    }

    return fetch(resolved, withBearer(init, newToken));
  };
}
