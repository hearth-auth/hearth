import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

// Proxy Hearth API paths through the Vite dev server so the browser
// never crosses origins — OIDC discovery and token requests stay on
// the frontend origin and Vite forwards them to the Hearth server.
// HEARTH_PORT and FRONTEND_PORT are set by demo.sh; default to the dev values.
const HEARTH_TARGET = `http://127.0.0.1:${process.env.HEARTH_PORT ?? "8420"}`;

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // Resolve the local SDK from TypeScript sources so Vite
      // handles transpilation rather than requiring a build step.
      "@hearth-auth/sdk": resolve(
        __dirname,
        "../../../sdks/typescript/src/index.ts",
      ),
    },
  },
  server: {
    port: Number(process.env.FRONTEND_PORT) || 5173,
    proxy: {
      // NOTE: do NOT proxy "/admin" here. The SPA owns a client-side /admin
      // route (App.tsx), and a proxy entry shadows it — a direct visit,
      // bookmark, or hard refresh on /admin gets forwarded to Hearth's admin
      // API and returns JSON instead of loading the app. The SPA reaches its
      // admin data through the Go backend (VITE_API_URL), not this proxy.
      "/realms": HEARTH_TARGET,
      "/health": HEARTH_TARGET,
      "/clients": HEARTH_TARGET,
    },
  },
});
