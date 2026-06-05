import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

// Proxy Hearth API paths through the Vite dev server so the browser
// never crosses origins — OIDC discovery and token requests stay on
// localhost:5173 and Vite forwards them to the Hearth server on :8420.
const HEARTH_TARGET = "http://127.0.0.1:8420";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // Resolve the local SDK from TypeScript sources so Vite
      // handles transpilation rather than requiring a build step.
      "@hearth/sdk": resolve(
        __dirname,
        "../../../sdks/typescript/src/index.ts",
      ),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/realms": HEARTH_TARGET,
      "/admin":  HEARTH_TARGET,
      "/health": HEARTH_TARGET,
      "/clients": HEARTH_TARGET,
    },
  },
});
