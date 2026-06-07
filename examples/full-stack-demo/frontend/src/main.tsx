import React from "react";
import ReactDOM from "react-dom/client";
import {
  HearthApiClient,
  HearthProvider,
  createHearth,
  createHearthAuth,
  getAccessToken,
} from "@hearth/sdk";
import App from "./App.js";
import "./index.css";

const hearthUrl = import.meta.env.VITE_HEARTH_URL as string;
const realmSlug = import.meta.env.VITE_REALM_SLUG as string;
const realmId = import.meta.env.VITE_REALM_ID as string;

const apiClient = new HearthApiClient({ baseUrl: `${hearthUrl}/realms/${realmSlug}`, realmId });

export const hearthAuth = createHearthAuth(apiClient, {
  clientId: import.meta.env.VITE_CLIENT_ID as string,
  redirectUri: `${window.location.origin}/callback`,
  hearthUrl,
  realmSlug,
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <HearthProvider client={createHearth({ baseUrl: hearthUrl, realmId, getToken: () => getAccessToken() })}>
      <App />
    </HearthProvider>
  </React.StrictMode>,
);
