import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

// No Vite proxy — the Go backend handles CORS directly.
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
  },
});
