import React from "react";
import ReactDOM from "react-dom/client";
import {
  HearthApiClient,
  HearthProvider,
  createHearth,
  createHearthAuth,
} from "@hearth-auth/sdk";
import App from "./App.js";
import "./index.css";

const hearthUrl = import.meta.env.VITE_HEARTH_URL as string;
const realmSlug = import.meta.env.VITE_REALM_SLUG as string;
const realmId = import.meta.env.VITE_REALM_ID as string;
// The `iss` of the realm's tokens. The SPA reaches Hearth through the Vite
// proxy, so `hearthUrl` is this page's origin, not the issuer; demo.sh reads
// the issuer from discovery.
const issuerUrl =
  (import.meta.env.VITE_HEARTH_ISSUER as string | undefined) ?? `${hearthUrl}/realms/${realmSlug}`;

const apiClient = new HearthApiClient({ baseUrl: `${hearthUrl}/realms/${realmSlug}`, realmId });

export const hearthAuth = createHearthAuth(apiClient, {
  clientId: import.meta.env.VITE_CLIENT_ID as string,
  redirectUri: `${window.location.origin}/callback`,
  hearthUrl,
  realmSlug,
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <HearthProvider client={createHearth({
        baseUrl: hearthUrl,
        realmId,
        issuerUrl,
        getToken: () => hearthAuth.getAccessToken(),
      })}>
      <App />
    </HearthProvider>
  </React.StrictMode>,
);
