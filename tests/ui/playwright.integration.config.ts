/**
 * Playwright config for the reference-integration suite (HEA-2058).
 *
 * Runs the tests in `integration/` against a live demo stack:
 *   Hearth  :8420  (started with examples/full-stack-demo/hearth.yaml)
 *   Backend :8421  (examples/full-stack-demo/backend)
 *   Vite    :5173  (examples/full-stack-demo/frontend — npm run dev)
 *
 * Invoked by the `reference-integration` nightly CI job and optionally
 * locally after running `examples/full-stack-demo/demo.sh`:
 *
 *   cd tests/ui && npx playwright test --config=playwright.integration.config.ts
 *
 * The tests are informational only (continue-on-error in CI). They MUST NOT
 * gate PRs — branch protection for main never lists this config's checks.
 *
 * Service coords and credentials come from env vars defined in
 * `integration/config.ts`; all have sensible defaults for a local demo.sh run.
 */
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  // No globalSetup — services are started externally (demo.sh / CI job).
  outputDir: 'reports/integration-output',
  reporter: [
    ['html', { outputFolder: 'reports/integration-html', open: 'never' }],
    ['list'],
  ],
  use: {
    headless: true,
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    trace: 'retain-on-failure',
    // Playwright test fixtures' `request` baseURL does not matter here —
    // every test constructs its own absolute URLs from integration/config.ts.
    ignoreHTTPSErrors: false,
  },
  // Run sequentially: each login flow mutates in-memory SPA state (localStorage)
  // and must complete before the next test clears the storage.
  workers: 1,
  timeout: 40_000,
  retries: 1,
  projects: [
    {
      name: 'integration',
      testMatch: 'integration/**/*.spec.ts',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
