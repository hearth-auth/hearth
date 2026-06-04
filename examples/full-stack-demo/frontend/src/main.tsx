import React from "react";
import ReactDOM from "react-dom/client";
import { createHearth, HearthProvider } from "@hearth/sdk";
import { HearthAuthClient } from "./auth/index.js";
import { getAccessToken } from "./auth/session.js";
import App from "./App.js";
import "./index.css";

// Auth client — handles PKCE / token exchange / refresh / logout.
export const hearthAuth = new HearthAuthClient({
  hearthUrl: import.meta.env.VITE_HEARTH_URL as string,
  realmSlug: import.meta.env.VITE_REALM_SLUG as string,
  clientId: import.meta.env.VITE_CLIENT_ID as string,
  redirectUri: `${window.location.origin}/callback`,
});

// SDK facade — decodes JWT claims synchronously for permission/role hooks.
const hearthFacade = createHearth({
  baseUrl: import.meta.env.VITE_HEARTH_URL as string,
  realmId: import.meta.env.VITE_REALM_ID as string,
  getToken: () => getAccessToken(),
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <HearthProvider client={hearthFacade}>
      <App />
    </HearthProvider>
  </React.StrictMode>,
);
