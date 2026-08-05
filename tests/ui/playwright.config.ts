import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  globalSetup: './globalSetup.ts',
  outputDir: 'reports/playwright-output',
  reporter: [
    ['html', { outputFolder: 'reports/html', open: 'never' }],
    ['list'],
  ],
  use: {
    baseURL: process.env.HEARTH_URL ?? 'http://127.0.0.1:8420',
    headless: true,
    screenshot: 'only-on-failure',
    video: 'off',
    // Allow self-signed certs in the HTTPS CI leg (https-tls-chromium matrix).
    ignoreHTTPSErrors: true,
    // NixOS: point at the nixpkgs chromium binary via CHROMIUM_EXECUTABLE_PATH
    // (set automatically by tests/ui/shell.nix). Ignored when unset.
    launchOptions: {
      executablePath: process.env.CHROMIUM_EXECUTABLE_PATH,
    },
  },
  // Visual regression snapshot storage
  snapshotDir: 'snapshots',
  expect: {
    toHaveScreenshot: {
      // Allow 3% pixel difference — accounts for minor antialiasing between runs.
      // Tighten to 0.01 after baselines are locked with --update-snapshots.
      maxDiffPixelRatio: 0.03,
      animations: 'disabled',
    },
  },
  workers: 4,
  timeout: 30_000,
  projects: [
    // Smoke: crawler-based page coverage (Phase 0)
    {
      name: 'smoke',
      testMatch: 'smoke/**/*.spec.ts',
      use: { ...devices['Desktop Chrome'] },
    },
    // Flows: multi-step user flow tests (onboarding wizard, MFA TOTP, email)
    {
      name: 'flows',
      testMatch: 'flows/**/*.spec.ts',
      use: { ...devices['Desktop Chrome'] },
    },
    // Regression: form and flow tests — parallelised, no destructive mutations
    {
      name: 'regression',
      testMatch: 'regression/**/*.spec.ts',
      testIgnore: '**/visual_baseline.spec.ts',
      grepInvert: /@destructive/,
      use: { ...devices['Desktop Chrome'] },
    },
    // Components: HTMX and UI component interaction tests — parallelised
    {
      name: 'components',
      testMatch: 'components/**/*.spec.ts',
      grepInvert: /@destructive/,
      use: { ...devices['Desktop Chrome'] },
    },
    // Destructive: tests that mutate shared state run sequentially to avoid races
    {
      name: 'destructive',
      testMatch: '{regression,components}/**/*.spec.ts',
      testIgnore: '**/visual_baseline.spec.ts',
      grep: /@destructive/,
      workers: 1,
      use: { ...devices['Desktop Chrome'] },
    },
    // Accessibility: axe-core scans — critical/serious violations = FAIL, minor/moderate = WARN
    {
      name: 'accessibility',
      testMatch: 'accessibility/**/*.spec.ts',
      use: { ...devices['Desktop Chrome'] },
    },
    // Exploratory: deep crawl with pagination discovery — non-blocking, separate CI job
    {
      name: 'exploratory',
      testMatch: 'exploratory/**/*.spec.ts',
      use: { ...devices['Desktop Chrome'] },
    },
    // Visual: pixel-perfect screenshot baselines — run with --update-snapshots to lock
    {
      name: 'visual',
      testMatch: 'regression/visual_baseline.spec.ts',
      use: { ...devices['Desktop Chrome'] },
    },
    // Integration: drives the examples/full-stack-demo SPA end-to-end against a
    // real Hearth + Go backend + Vite (HEA-2056). Booted by run-integration.sh
    // (which reuses the demo's demo.sh). Multi-navigation flows get a longer
    // per-test budget; runs sequentially so control-plane mutations (revoke,
    // key-rotation) in one flow never race another.
    {
      name: 'integration',
      testMatch: 'integration/**/*.spec.ts',
      timeout: 60_000,
      workers: 1,
      use: {
        ...devices['Desktop Chrome'],
        // Project-level launchOptions REPLACES the top-level one (shallow), so
        // repeat executablePath here. --no-sandbox is required for Chromium to
        // launch in containerised / restricted-namespace environments (CI and
        // the sandboxed dev box); harmless elsewhere.
        launchOptions: {
          executablePath: process.env.CHROMIUM_EXECUTABLE_PATH,
          args: ['--no-sandbox', '--disable-dev-shm-usage'],
        },
      },
    },
  ],
});
