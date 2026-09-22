import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 30_000,
    // Three files (admin-crud, auth-flow, jwks) each boot their own hearth
    // server in `beforeAll`: a cargo freshness check, a process spawn, a health
    // poll, then a bootstrap that generates the realm's Ed25519 key and hashes
    // an admin password. On a two-core CI runner those three run concurrently
    // and did not fit vitest's default 60 s, which is a default rather than a
    // measured budget — every run failed with "Hook timed out in 60000ms"
    // while passing on a developer machine. The work is legitimate, so the
    // budget is raised rather than the work deferred.
    hookTimeout: 180_000,
  },
});
