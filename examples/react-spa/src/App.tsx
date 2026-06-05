/**
 * Minimal React SPA demonstrating the unified createHearth() facade (HEA-1306).
 *
 * Before (two separate clients + manual tokenRef wiring, App.tsx:17-28):
 *
 *   const apiClient = new HearthApiClient({ baseUrl, realmId });
 *   const tokenRef = useRef<string | null>(null);
 *   const hearth = useMemo(() =>
 *     createHearth({ baseUrl, realmId, getToken: () => tokenRef.current }), []);
 *   useSession({
 *     refresh: (rt) => apiClient.refreshTokens(CLIENT_ID, rt),
 *     onRefresh: (tokens) => { tokenRef.current = tokens.access_token; ... },
 *   });
 *
 * After (single facade, no tokenRef, no separate apiClient):
 */
import * as React from "react";
import {
  HearthProvider,
  createHearth,
  useHasPermission,
  useSession,
} from "@hearth/sdk";

const BASE_URL = import.meta.env.VITE_HEARTH_URL ?? "https://auth.example.com";
// VITE_REALM accepts either a realm UUID or a human-readable slug.
// The SDK auto-resolves the other form on first API call (HEA-1307).
const REALM = import.meta.env.VITE_REALM ?? "default";
const CLIENT_ID = import.meta.env.VITE_CLIENT_ID ?? "spa-client";

export function App(): React.ReactElement {
  // One facade owns both the RBAC claim predicates and the auth token store.
  const hearth = React.useMemo(
    () =>
      createHearth({
        baseUrl: BASE_URL,
        realm: REALM,
        auth: { clientId: CLIENT_ID },
      }),
    [],
  );

  const { status, user } = useSession({
    getRefreshToken: () => localStorage.getItem("hearth_rt"),
    refresh: (rt) => hearth.auth!.refreshTokens(rt),
    onRefresh: (tokens) => {
      localStorage.setItem("hearth_rt", tokens.refresh_token);
      // setToken() stores the token in the facade AND fires React subscribers
      // so HearthProvider-backed hooks re-render automatically.
      hearth.setToken(tokens.access_token);
    },
  });

  if (status === "loading") return <LoadingScreen />;
  if (status === "unauthenticated") return <LoginRedirect />;

  return (
    <HearthProvider client={hearth}>
      <Dashboard displayName={user?.name ?? user?.sub ?? "Unknown"} />
    </HearthProvider>
  );
}

function LoadingScreen(): React.ReactElement {
  return <div aria-busy="true">Restoring session…</div>;
}

function LoginRedirect(): React.ReactElement {
  React.useEffect(() => {
    window.location.href = `${BASE_URL}/login?realm=${REALM}&redirect_uri=${encodeURIComponent(window.location.href)}`;
  }, []);
  return <div>Redirecting to login…</div>;
}

export function Dashboard({
  displayName,
}: {
  displayName: string;
}): React.ReactElement {
  const canEditDocs = useHasPermission("docs.edit");
  return (
    <main>
      <h1>Welcome, {displayName}</h1>
      {canEditDocs && <button>Edit document</button>}
    </main>
  );
}
