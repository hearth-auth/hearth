import * as React from "react";
import { Claims } from "./claims.js";
import type { HearthFacade } from "./hearth.js";
import type { TokenResponse } from "./types.js";
import {
  createAuthenticatedFetch,
  type AuthenticatedFetch,
  type AuthenticatedFetchOptions,
} from "./fetch.js";

/**
 * React context carrying a {@link HearthFacade} down the tree.
 *
 * The default value is `null`; the hooks treat a `null` context as
 * unauthenticated and return `false`.
 */
export const HearthContext = React.createContext<HearthFacade | null>(null);

/** Props for {@link HearthProvider}. */
export interface HearthProviderProps {
  client: HearthFacade;
  children: React.ReactNode;
}

/**
 * Provides a {@link HearthFacade} to descendants via {@link HearthContext}.
 *
 * Wrap your React tree once with this after calling `createHearth(...)`.
 */
export function HearthProvider(props: HearthProviderProps): React.ReactElement {
  return React.createElement(
    HearthContext.Provider,
    { value: props.client },
    props.children,
  );
}

/**
 * Returns `true` iff the nearest {@link HearthProvider} client reports
 * the permission as present in the JWT claim set. Returns `false`
 * when no provider is mounted.
 */
export function useHasPermission(permission: string): boolean {
  const client = React.useContext(HearthContext);
  return client !== null && client.hasPermission(permission);
}

/** Returns `true` iff the JWT `roles` claim contains `role`. */
export function useHasRole(role: string): boolean {
  const client = React.useContext(HearthContext);
  return client !== null && client.hasRole(role);
}

/** Returns `true` iff the JWT `groups` claim contains `group`. */
export function useInGroup(group: string): boolean {
  const client = React.useContext(HearthContext);
  return client !== null && client.inGroup(group);
}

/** Returns `true` iff the JWT `oid` claim equals `org`. */
export function useInOrg(org: string): boolean {
  const client = React.useContext(HearthContext);
  return client !== null && client.inOrg(org);
}

// ─── useSession ──────────────────────────────────────────────────────────────

/** Restore lifecycle status. */
export type SessionStatus = "loading" | "authenticated" | "unauthenticated";

/** Value returned by {@link useSession}. */
export interface SessionState {
  /** Lifecycle status of the session restore. */
  status: SessionStatus;
  /**
   * Identity profile extracted from the access token, or `null` when
   * unauthenticated or loading.
   */
  user: UserProfile | null;
  /**
   * Typed claims from the access token (see {@link Claims}), or `null` when
   * unauthenticated or loading.
   */
  claims: Claims | null;
  /**
   * Raw access token string, or `null` when unauthenticated or loading.
   * Use this to drive `getToken` in {@link createHearth}.
   */
  accessToken: string | null;
}

/** Options for {@link useSession}. */
export interface UseSessionOptions {
  /**
   * Returns the persisted refresh token, or `null`/`undefined` when none is
   * stored. When falsy the hook immediately resolves to `'unauthenticated'`
   * without a network call.
   */
  getRefreshToken: () => string | null | undefined;
  /**
   * Calls the Hearth token refresh endpoint. Receives the current refresh
   * token and must return a new {@link TokenResponse}.
   *
   * @example
   * ```ts
   * refresh: (rt) => apiClient.refreshTokens(clientId, rt)
   * ```
   */
  refresh: (refreshToken: string) => Promise<TokenResponse>;
  /**
   * Called after a successful restore with the new token response. Use this
   * to persist the new `refresh_token` and/or store the new `access_token`
   * (e.g. in a `useRef` that feeds `getToken` in `createHearth`).
   */
  onRefresh?: (tokens: TokenResponse) => void;
}

const UNAUTHENTICATED: SessionState = {
  status: "unauthenticated",
  user: null,
  claims: null,
  accessToken: null,
};

function tokenToProfile(claims: Claims): UserProfile {
  return {
    sub: claims.subject(),
    name: String(claims.get("name") ?? ""),
    email: String(claims.get("email") ?? ""),
    emailVerified: Boolean(claims.get("email_verified")),
    picture:
      typeof claims.get("picture") === "string"
        ? (claims.get("picture") as string)
        : null,
  };
}

/**
 * Restores a Hearth session on mount using a stored refresh token.
 *
 * Starts in `'loading'`, transitions to `'authenticated'` when the refresh
 * succeeds, or `'unauthenticated'` when no refresh token is stored or the
 * refresh fails (expired / revoked grant).
 *
 * Standalone — no {@link HearthProvider} required. Compose with
 * {@link HearthProvider} by wiring `onRefresh` into the `getToken` callback:
 *
 * @example
 * ```tsx
 * const tokenRef = useRef<string | null>(null);
 * const hearth = useMemo(() =>
 *   createHearth({ baseUrl, realmId, getToken: () => tokenRef.current }), []);
 *
 * const { status, user } = useSession({
 *   getRefreshToken: () => localStorage.getItem("hearth_rt"),
 *   refresh: (rt) => apiClient.refreshTokens(clientId, rt),
 *   onRefresh: (tokens) => {
 *     localStorage.setItem("hearth_rt", tokens.refresh_token);
 *     tokenRef.current = tokens.access_token;
 *   },
 * });
 * ```
 */
export function useSession(opts: UseSessionOptions): SessionState {
  const [state, setState] = React.useState<SessionState>({
    status: "loading",
    user: null,
    claims: null,
    accessToken: null,
  });

  React.useEffect(() => {
    const refreshToken = opts.getRefreshToken();
    if (!refreshToken) {
      setState(UNAUTHENTICATED);
      return;
    }

    let cancelled = false;

    opts
      .refresh(refreshToken)
      .then((tokens) => {
        if (cancelled) return;
        opts.onRefresh?.(tokens);
        let user: UserProfile | null = null;
        let claims: Claims | null = null;
        try {
          claims = Claims.decode(tokens.access_token);
          user = tokenToProfile(claims);
        } catch {
          // Malformed token — still authenticated, claims/user unavailable.
        }
        setState({
          status: "authenticated",
          accessToken: tokens.access_token,
          user,
          claims,
        });
      })
      .catch(() => {
        if (cancelled) return;
        setState(UNAUTHENTICATED);
      });

    return () => {
      cancelled = true;
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps -- intentional mount-only

  return state;
}

/**
 * Returns the typed {@link Claims} from the current access token, or `null`
 * when unauthenticated or no {@link HearthProvider} is mounted.
 *
 * Subscribes to token-change events (e.g. silent refresh) so the component
 * re-renders automatically when the token is replaced — avoiding the latent
 * bug of manually decoded claims going stale after refresh.
 */
export function useClaims(): Claims | null {
  const client = React.useContext(HearthContext);
  const [claims, setClaims] = React.useState<Claims | null>(
    () => client?.getClaims() ?? null,
  );

  React.useEffect(() => {
    if (!client) {
      setClaims(null);
      return;
    }
    setClaims(client.getClaims());
    return client.subscribe(() => {
      setClaims(client.getClaims());
    });
  }, [client]);

  return claims;
}

/** Common user identity fields extracted from the JWT for convenience. */
export interface UserProfile {
  /** The `sub` (subject) claim — typically a stable user ID. */
  sub: string;
  /** The `name` claim, or an empty string when absent. */
  name: string;
  /** The `email` claim, or an empty string when absent. */
  email: string;
  /** The `email_verified` claim. */
  emailVerified: boolean;
  /** The `picture` claim (avatar URL), or null when absent. */
  picture: string | null;
}

/**
 * Returns common user identity fields from the current access token, or
 * `null` when unauthenticated. Re-renders on token refresh via
 * {@link useClaims}.
 */
export function useUser(): UserProfile | null {
  const claims = useClaims();
  if (!claims) return null;
  return {
    sub: claims.subject(),
    name: String(claims.get("name") ?? ""),
    email: String(claims.get("email") ?? ""),
    emailVerified: Boolean(claims.get("email_verified")),
    picture:
      typeof claims.get("picture") === "string"
        ? (claims.get("picture") as string)
        : null,
  };
}

// ─── useOAuthCallback / HearthCallback ───────────────────────────────────────

/**
 * A structured error produced during the OAuth authorization-code callback.
 *
 * The `code` field is always present; `description` carries the OAuth
 * `error_description` param when available.
 */
export interface CallbackError {
  /**
   * Machine-readable error code:
   * - The OAuth `error` param value (e.g. `"access_denied"`, `"server_error"`)
   * - `"state_mismatch"` — `state` URL param does not match {@link UseOAuthCallbackOptions.expectedState}
   * - `"missing_code"` — URL contains neither `code` nor `error`
   * - `"exchange_failed"` — `exchangeCode` threw
   */
  code: string;
  /** The OAuth `error_description` URL param, or `null` when absent. */
  description: string | null;
}

/** Lifecycle status of the OAuth callback flow. */
export type CallbackStatus = "loading" | "success" | "error";

/** Value returned by {@link useOAuthCallback}. */
export interface CallbackState {
  /** Current phase of the callback flow. */
  status: CallbackStatus;
  /** Non-null when `status === "error"`. */
  error: CallbackError | null;
}

/** Options for {@link useOAuthCallback}. */
export interface UseOAuthCallbackOptions {
  /**
   * Exchanges the authorization code for tokens. Called once on mount when
   * `code` is present and `state` validates.
   *
   * @example
   * ```ts
   * exchangeCode: (code) =>
   *   apiClient.exchangeCode({ clientId, code, redirectUri, codeVerifier })
   * ```
   */
  exchangeCode: (code: string) => Promise<TokenResponse>;
  /**
   * Called after a successful token exchange. Typically persists tokens
   * and navigates to the post-login route.
   */
  onSuccess: (tokens: TokenResponse) => void;
  /**
   * Called when any error occurs (OAuth error response, state mismatch,
   * missing code, or exchange failure). Optional — the hook's return value
   * always carries the error for inline rendering.
   */
  onError?: (error: CallbackError) => void;
  /**
   * Expected `state` value for CSRF protection. When provided the hook
   * compares it against the `state` URL parameter and aborts with
   * `"state_mismatch"` if they differ.
   *
   * Pass the value you stored in `sessionStorage` before the authorization
   * redirect and clear it on success. Pass `null` to explicitly skip the
   * check.
   */
  expectedState?: string | null;
  /**
   * URL search string to parse. Defaults to `window.location.search`.
   * Override in tests or non-browser environments.
   */
  search?: string;
}

/** Props for {@link HearthCallback}. */
export interface HearthCallbackProps {
  /** @see {@link UseOAuthCallbackOptions.exchangeCode} */
  exchangeCode: (code: string) => Promise<TokenResponse>;
  /** Called after a successful token exchange. Use to navigate away. */
  onSuccess: (tokens: TokenResponse) => void;
  /** Called when any error occurs. Optional. */
  onError?: (error: CallbackError) => void;
  /** Rendered while the token exchange is in-flight. */
  loading?: React.ReactNode;
  /** @see {@link UseOAuthCallbackOptions.expectedState} */
  expectedState?: string | null;
  /** @see {@link UseOAuthCallbackOptions.search} */
  search?: string;
}

/**
 * Headless hook that handles the OAuth authorization-code callback.
 *
 * Parses `code`, `state`, `error`, and `error_description` from the URL,
 * validates the `state` parameter when `expectedState` is provided, then
 * calls `exchangeCode` exactly once. Fires `onSuccess` or `onError`.
 *
 * @example
 * ```tsx
 * function CallbackPage() {
 *   const navigate = useNavigate();
 *   const [authError, setAuthError] = React.useState<string | null>(null);
 *
 *   const { status } = useOAuthCallback({
 *     expectedState: sessionStorage.getItem("oauth_state"),
 *     exchangeCode: (code) =>
 *       apiClient.exchangeCode({ clientId, code, redirectUri, codeVerifier }),
 *     onSuccess: (tokens) => {
 *       sessionStorage.removeItem("oauth_state");
 *       localStorage.setItem("hearth_rt", tokens.refresh_token);
 *       navigate("/dashboard");
 *     },
 *     onError: (err) => setAuthError(err.description ?? err.code),
 *   });
 *
 *   if (status === "loading") return <Spinner />;
 *   if (authError) return <p>Login failed: {authError}</p>;
 *   return null;
 * }
 * ```
 */
export function useOAuthCallback(opts: UseOAuthCallbackOptions): CallbackState {
  const [state, setState] = React.useState<CallbackState>({
    status: "loading",
    error: null,
  });

  React.useEffect(() => {
    const params = new URLSearchParams(
      opts.search ??
        (typeof window !== "undefined" ? window.location.search : ""),
    );

    function fail(err: CallbackError): void {
      setState({ status: "error", error: err });
      opts.onError?.(err);
    }

    // RFC 6749 §4.1.2.1: check for error response before code.
    const errorCode = params.get("error");
    if (errorCode) {
      fail({ code: errorCode, description: params.get("error_description") });
      return;
    }

    const code = params.get("code");
    if (!code) {
      fail({ code: "missing_code", description: null });
      return;
    }

    // CSRF protection: validate state when caller supplied an expected value.
    if (opts.expectedState != null) {
      if (params.get("state") !== opts.expectedState) {
        fail({ code: "state_mismatch", description: null });
        return;
      }
    }

    let cancelled = false;

    opts
      .exchangeCode(code)
      .then((tokens) => {
        if (cancelled) return;
        setState({ status: "success", error: null });
        opts.onSuccess(tokens);
      })
      .catch(() => {
        if (cancelled) return;
        fail({ code: "exchange_failed", description: null });
      });

    return () => {
      cancelled = true;
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps -- intentional mount-only

  return state;
}

/**
 * Declarative OAuth authorization-code callback component.
 *
 * Drop this into your callback route. It parses the URL, validates `state`
 * when `expectedState` is provided, exchanges the code, then calls
 * `onSuccess`. Renders `loading` while the exchange is in-flight and `null`
 * once complete — `onSuccess` and `onError` drive navigation and error UI.
 *
 * @example
 * ```tsx
 * // In your router: <Route path="/auth/callback" element={<CallbackPage />} />
 * function CallbackPage() {
 *   const navigate = useNavigate();
 *   const [error, setError] = React.useState<string | null>(null);
 *
 *   if (error) return <p>Login failed: {error}</p>;
 *
 *   return (
 *     <HearthCallback
 *       expectedState={sessionStorage.getItem("oauth_state")}
 *       exchangeCode={(code) =>
 *         apiClient.exchangeCode({ clientId, code, redirectUri, codeVerifier })
 *       }
 *       onSuccess={(tokens) => {
 *         sessionStorage.removeItem("oauth_state");
 *         localStorage.setItem("hearth_rt", tokens.refresh_token);
 *         navigate("/dashboard");
 *       }}
 *       onError={(err) => setError(err.description ?? err.code)}
 *       loading={<Spinner />}
 *     />
 *   );
 * }
 * ```
 */
export function HearthCallback(
  props: HearthCallbackProps,
): React.ReactElement | null {
  const { status } = useOAuthCallback({
    exchangeCode: props.exchangeCode,
    onSuccess: props.onSuccess,
    onError: props.onError,
    expectedState: props.expectedState,
    search: props.search,
  });

  if (status === "loading" && props.loading != null) {
    return React.createElement(React.Fragment, null, props.loading);
  }

  return null;
}

// ---------------------------------------------------------------------------
// RequireAuth — session gate component (HEA-1303)
// ---------------------------------------------------------------------------

/** Props for {@link RequireAuth}. */
export interface RequireAuthProps {
  /** Rendered when an authenticated session exists. */
  children: React.ReactNode;
  /**
   * Rendered when unauthenticated or when no {@link HearthProvider} is
   * mounted. Pass a router redirect, a spinner, or any ReactNode.
   * Defaults to `null`.
   */
  fallback?: React.ReactNode;
}

/**
 * Renders `children` only when there is an authenticated session (non-null
 * {@link Claims} from the nearest {@link HearthProvider}).
 *
 * SSR-safe: without a provider the context is `null`, so `fallback` is
 * always rendered server-side. Works with React Router (`<Navigate>`),
 * Next.js, plain SPAs, or no router at all.
 *
 * @example
 * ```tsx
 * <RequireAuth fallback={<Navigate to="/login" />}>
 *   <Dashboard />
 * </RequireAuth>
 * ```
 */
export function RequireAuth({
  children,
  fallback = null,
}: RequireAuthProps): React.ReactElement {
  const claims = useClaims();
  return React.createElement(
    React.Fragment,
    null,
    claims !== null ? children : fallback,
  );
}

// ---------------------------------------------------------------------------
// Authorized — multi-claim gate component (HEA-1303)
// ---------------------------------------------------------------------------

/** Props for {@link Authorized}. */
export interface AuthorizedProps {
  /** Rendered when all specified claim constraints pass. */
  children: React.ReactNode;
  /** JWT `roles` claim must contain this value. */
  role?: string;
  /** JWT `permissions` claim must contain this value. */
  permission?: string;
  /** JWT `groups` claim must contain this value. */
  group?: string;
  /** JWT `oid` claim must equal this value. */
  org?: string;
  /**
   * Rendered when any constraint fails or when no session exists.
   * Defaults to `null`.
   */
  fallback?: React.ReactNode;
}

/**
 * Renders `children` iff the current session satisfies ALL specified claim
 * constraints (AND semantics). Omitted props are treated as satisfied.
 * Renders `fallback` when any constraint fails or no session exists.
 *
 * SSR-safe: without a provider, all constraints fail and `fallback` is
 * rendered.
 *
 * @example
 * ```tsx
 * <Authorized permission="invoices.write" role="billing">
 *   <BillingPanel />
 * </Authorized>
 * ```
 */
export function Authorized({
  children,
  role,
  permission,
  group,
  org,
  fallback = null,
}: AuthorizedProps): React.ReactElement {
  const claims = useClaims();

  const authorized =
    claims !== null &&
    (role === undefined || claims.hasRole(role)) &&
    (permission === undefined || claims.hasPermission(permission)) &&
    (group === undefined || claimsInGroup(claims, group)) &&
    (org === undefined || claimsInOrg(claims, org));

  return React.createElement(
    React.Fragment,
    null,
    authorized ? children : fallback,
  );
}

function claimsInGroup(claims: Claims, group: string): boolean {
  const groups = claims.get("groups");
  return Array.isArray(groups) && (groups as unknown[]).includes(group);
}

function claimsInOrg(claims: Claims, org: string): boolean {
  const oid = claims.get("oid");
  return typeof oid === "string" && oid === org;
}

// ---------------------------------------------------------------------------
// useApiClient — authenticated fetch hook (HEA-1305)
// ---------------------------------------------------------------------------

/** Options for {@link useApiClient}. Same surface as {@link AuthenticatedFetchOptions}. */
export type UseApiClientOptions = AuthenticatedFetchOptions;

/**
 * React hook that returns a stable {@link AuthenticatedFetch} function for
 * use in SPAs.
 *
 * The returned function never changes identity across renders, making it safe
 * to pass as a prop, store in context, or use as a `useEffect` dependency.
 * All callbacks are always the latest versions via a ref indirection — no
 * stale-closure bugs.
 *
 * Delegates to {@link createAuthenticatedFetch} for the actual logic,
 * including the refresh-storm de-duplication guarantee.
 *
 * @example
 * ```tsx
 * function Dashboard() {
 *   const [accessToken, setAccessToken] = React.useState<string | null>(null);
 *
 *   const apiFetch = useApiClient({
 *     getAccessToken: () => accessToken,
 *     getRefreshToken: () => localStorage.getItem("hearth_rt"),
 *     refresh: (rt) => apiClient.refreshTokens(CLIENT_ID, rt),
 *     onRefresh: (t) => {
 *       localStorage.setItem("hearth_rt", t.refresh_token);
 *       setAccessToken(t.access_token);
 *     },
 *     onRefreshFailure: () => router.push("/login"),
 *     baseUrl: "https://api.example.com",
 *   });
 *
 *   React.useEffect(() => {
 *     apiFetch("/v1/profile").then((r) => r.json()).then(setProfile);
 *   }, [apiFetch]);
 * }
 * ```
 */
export function useApiClient(opts: UseApiClientOptions): AuthenticatedFetch {
  // Ref holds the latest opts so the memoized fetch instance always calls
  // current callbacks without needing to be recreated.
  const optsRef = React.useRef(opts);
  optsRef.current = opts;

  return React.useMemo(
    () =>
      createAuthenticatedFetch({
        getAccessToken: () => optsRef.current.getAccessToken(),
        getRefreshToken: () => optsRef.current.getRefreshToken(),
        refresh: (rt) => optsRef.current.refresh(rt),
        onRefresh: (tokens) => optsRef.current.onRefresh?.(tokens),
        onRefreshFailure: (err) => optsRef.current.onRefreshFailure?.(err),
        get baseUrl(): string | undefined {
          return optsRef.current.baseUrl;
        },
      }),
    [], // eslint-disable-line react-hooks/exhaustive-deps -- opts threaded via ref
  );
}

export type { AuthenticatedFetch, AuthenticatedFetchOptions } from "./fetch.js";
