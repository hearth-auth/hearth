/**
 * Capstone demo — full-stack SPA using every new SDK ergonomic (HEA-1309).
 *
 * What this file demonstrates (one-to-one with the S1–S7 + C3–C4 audit items):
 *
 *   S1  useUser()        — identity from context, no manual decodePayload
 *   S2  useSession()     — session restore from stored RT, no custom loop
 *   S3  <RequireAuth>    — auth gate, no custom ProtectedRoute component
 *       <Authorized>     — claim gate, no custom RoleGate component
 *   S4  <HearthCallback> — code→token exchange, no custom Callback.tsx
 *   S5  useApiClient()   — authenticated fetch, no custom api.ts
 *   S6  createHearth()   — single unified facade, no dual-construct
 *   S7  VITE_REALM       — one env var, accepts UUID or slug
 *   C3  <UserMenu>       — "Sign out everywhere" revokes the RT so silent-
 *                          refresh fails on all open tabs (HEA-1300)
 *   C4  <ClaimProbe>     — useInGroup / useInOrg wired to real seeded values
 *                          from hearth.yaml (demo-team group, acme org) (HEA-1300)
 *
 * Zero custom auth code. Zero manual JWT parsing. Imports from @hearth/sdk,
 * react, and react-router-dom only.
 */
import * as React from "react";
import { BrowserRouter, Routes, Route, useNavigate } from "react-router-dom";
import type { TokenResponse } from "@hearth/sdk";
import {
  Authorized,
  HearthCallback,
  HearthProvider,
  RequireAuth,
  createHearth,
  useApiClient,
  useInGroup,
  useInOrg,
  useSession,
  useUser,
} from "@hearth/sdk";

// ─── Config ───────────────────────────────────────────────────────────────────

const BASE_URL = import.meta.env.VITE_HEARTH_URL ?? "https://auth.example.com";
// S7: one env var — SDK auto-resolves UUID ↔ slug on first API call (HEA-1307).
const REALM = import.meta.env.VITE_REALM ?? "default";
const CLIENT_ID = import.meta.env.VITE_CLIENT_ID ?? "spa-client";
const REDIRECT_URI =
  (typeof window !== "undefined" ? window.location.origin : "") +
  "/auth/callback";

// ─── S6: single facade ────────────────────────────────────────────────────────

// Module-scope singleton — stable for the page lifetime, no useMemo needed.
const hearth = createHearth({
  baseUrl: BASE_URL,
  realm: REALM,
  auth: { clientId: CLIENT_ID },
});

// Shared helper: persist tokens and notify the React subscriber bus.
// setToken() triggers hearth.subscribe() listeners → useClaims() re-renders.
function storeTokens(tokens: TokenResponse): void {
  localStorage.setItem("hearth_rt", tokens.refresh_token);
  hearth.setToken(tokens.access_token);
}

// ─── App root ─────────────────────────────────────────────────────────────────

export function App(): React.ReactElement {
  return (
    // S6: HearthProvider distributes the facade to all SDK hooks in the tree.
    <HearthProvider client={hearth}>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </HearthProvider>
  );
}

// ─── Routes ───────────────────────────────────────────────────────────────────

function AppRoutes(): React.ReactElement {
  // S2: useSession restores an existing session from localStorage on mount.
  // Transitions: loading → authenticated | unauthenticated — no custom loop.
  const { status } = useSession({
    getRefreshToken: () => localStorage.getItem("hearth_rt"),
    refresh: (rt) => hearth.auth!.refreshTokens(rt),
    onRefresh: storeTokens,
  });

  if (status === "loading") return <div aria-busy="true">Restoring session…</div>;

  return (
    <Routes>
      {/* S4: HearthCallback owns the OAuth code→token exchange */}
      <Route path="/auth/callback" element={<CallbackPage />} />
      {/* S3: RequireAuth gates protected content — no custom ProtectedRoute */}
      <Route
        path="/"
        element={
          <RequireAuth fallback={<LoginPrompt />}>
            <Dashboard />
          </RequireAuth>
        }
      />
    </Routes>
  );
}

// ─── Login prompt ─────────────────────────────────────────────────────────────

function LoginPrompt(): React.ReactElement {
  const loginUrl =
    `${BASE_URL}/authorize` +
    `?client_id=${CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&response_type=code&scope=openid+profile`;
  return (
    <div>
      <p>You are not signed in.</p>
      <a href={loginUrl}>Sign in with Hearth</a>
    </div>
  );
}

// ─── S4: OAuth callback page ──────────────────────────────────────────────────

function CallbackPage(): React.ReactElement {
  const navigate = useNavigate();
  const [error, setError] = React.useState<string | null>(null);

  if (error) return <p role="alert">Login failed: {error}</p>;

  return (
    <HearthCallback
      expectedState={sessionStorage.getItem("oauth_state")}
      exchangeCode={(code) =>
        hearth.auth!.exchangeCode({ code, redirectUri: REDIRECT_URI })
      }
      onSuccess={(tokens) => {
        sessionStorage.removeItem("oauth_state");
        storeTokens(tokens);
        navigate("/");
      }}
      onError={(err) => setError(err.description ?? err.code)}
      loading={<div aria-busy="true">Completing login…</div>}
    />
  );
}

// ─── C3: User menu — "Sign out everywhere" ───────────────────────────────────

/**
 * C3: Demonstrates session-version logout. "Sign out everywhere" revokes the
 * stored refresh token via POST /revoke, clears local state, and hard-reloads
 * to the root. On the next silent-refresh cycle any other open tab receives a
 * token_revoked error and falls back to the LoginPrompt (HEA-1300).
 *
 * When a session-version bump endpoint lands (HEA-1288), replace the /revoke
 * call with POST /v1/me/session-version to invalidate all sessions atomically.
 */
function UserMenu(): React.ReactElement {
  const user = useUser();
  const [busy, setBusy] = React.useState(false);

  async function signOutEverywhere(): Promise<void> {
    setBusy(true);
    const rt = localStorage.getItem("hearth_rt");
    if (rt) {
      try {
        // Revoke the refresh token — any future silent-refresh using this RT
        // will receive token_revoked and fall through to LoginPrompt.
        await fetch(`${BASE_URL}/realms/${REALM}/revoke`, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization: `Bearer ${hearth.getToken() ?? ""}`,
          },
          body: new URLSearchParams({
            token: rt,
            token_type_hint: "refresh_token",
          }),
        });
      } catch {
        // Proceed with local sign-out even if the network call fails.
      }
    }
    localStorage.removeItem("hearth_rt");
    hearth.setToken(null);
    // Hard-reload so React state is fully reset; RequireAuth shows LoginPrompt.
    window.location.assign("/");
  }

  return (
    <div>
      <span>{user?.name || user?.email || user?.sub || "Signed in"}</span>
      {" · "}
      <button disabled={busy} onClick={() => void signOutEverywhere()}>
        Sign out everywhere
      </button>
    </div>
  );
}

// ─── C4: Claim probe ──────────────────────────────────────────────────────────

/**
 * C4: Wires useInGroup / useInOrg to real seeded values from hearth.yaml.
 * Shows `true` once admin@hearth.test is a member of `demo-team` / `acme`
 * (add via Admin UI → Groups / Organisations after bootstrapping) (HEA-1300).
 */
export function ClaimProbe(): React.ReactElement {
  const inDemoTeam = useInGroup("demo-team");
  const inAcme = useInOrg("acme");
  return (
    <dl>
      <dt>
        <code>useInGroup("demo-team")</code>
      </dt>
      <dd aria-label="in-demo-team">{String(inDemoTeam)}</dd>
      <dt>
        <code>useInOrg("acme")</code>
      </dt>
      <dd aria-label="in-acme">{String(inAcme)}</dd>
    </dl>
  );
}

// ─── Protected dashboard ──────────────────────────────────────────────────────

/**
 * S1: useUser() reads identity from the SDK context — no displayName prop,
 *     no manual JWT decoding, re-renders automatically on token refresh.
 * S3: <Authorized> gates UI by claim — no custom RoleGate component.
 * S5: useApiClient() returns a stable authenticated fetch — no custom api.ts.
 * C3: <UserMenu> provides "Sign out everywhere".
 * C4: <ClaimProbe> surfaces group/org claims from real seeded YAML data.
 */
export function Dashboard(): React.ReactElement {
  const user = useUser(); // S1: identity from context, not a prop

  // S5: authenticated fetch — storm-deduplicated refresh, stable reference.
  const apiFetch = useApiClient({
    getAccessToken: () => hearth.getToken(),
    getRefreshToken: () => localStorage.getItem("hearth_rt"),
    refresh: (rt) => hearth.auth!.refreshTokens(rt),
    onRefresh: storeTokens,
    baseUrl: BASE_URL,
  });

  return (
    <main>
      {/* C3: user identity + sign-out-everywhere */}
      <UserMenu />
      {/* S1: user identity from hook, not prop */}
      <h1>Welcome, {user?.name || user?.sub || "Unknown"}</h1>
      {/* C4: group / org claim probe */}
      <ClaimProbe />
      {/* S3: <Authorized> replaces manual useHasPermission guard */}
      <Authorized permission="docs.edit">
        <button>Edit document</button>
      </Authorized>
      {/* S5: apiFetch called on demand via event handler */}
      <Authorized role="admin">
        <button onClick={() => void apiFetch("/v1/admin/stats")}>
          Admin panel
        </button>
      </Authorized>
    </main>
  );
}
