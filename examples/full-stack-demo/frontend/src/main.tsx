import React from "react";
import ReactDOM from "react-dom/client";
import { HearthApiClient, createHearth, HearthProvider } from "@hearth/sdk";
import { createHearthAuth } from "./auth/index.js";
import { getAccessToken } from "./auth/session.js";
import App from "./App.js";
import "./index.css";

const hearthUrl = import.meta.env.VITE_HEARTH_URL as string;
const realmSlug = import.meta.env.VITE_REALM_SLUG as string;
const realmId = import.meta.env.VITE_REALM_ID as string;
const clientId = import.meta.env.VITE_CLIENT_ID as string;

// SDK API client — handles discovery, token exchange, and refresh.
const apiClient = new HearthApiClient({
  baseUrl: `${hearthUrl}/${realmSlug}`,
  realmId,
});

// Auth facade: wires SDK methods to session storage. No custom auth logic.
export const hearthAuth = createHearthAuth(apiClient, {
  clientId,
  redirectUri: `${window.location.origin}/callback`,
  hearthUrl,
  realmSlug,
});

// SDK facade — decodes JWT claims synchronously for useHasPermission / useHasRole hooks.
const hearthFacade = createHearth({
  baseUrl: hearthUrl,
  realmId,
  getToken: () => getAccessToken(),
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <HearthProvider client={hearthFacade}>
      <App />
    </HearthProvider>
  </React.StrictMode>,
);
