/**
 * vision-crawl.cjs — Playwright screenshot crawler for the nightly UI critic.
 *
 * Exit codes:
 *   0  success — screenshots + manifest written to SCRATCH_DIR
 *   1  crawl error (partial screenshots may exist)
 *   2  BROWSER_LAUNCH_FAILED — no working browser; abort the run immediately,
 *      never degrade to curl/grep
 *
 * Required env vars:
 *   SCRATCH_DIR           Where to write screenshots + manifest.json
 *   ADMIN_PASSWORD        Admin password from bootstrap (for UI login)
 *
 * Optional env vars:
 *   HEARTH_URL            Defaults to http://127.0.0.1:8420
 *   CHROMIUM_EXECUTABLE_PATH   Nix chromium path (set automatically by shell.nix)
 *
 * Run inside nix-shell so the Nix chromium is used:
 *   cd tests/ui
 *   SCRATCH_DIR=/path/to/scratch ADMIN_PASSWORD=pw \
 *     nix-shell shell.nix --run "node scripts/vision-crawl.cjs"
 */

'use strict';

const { chromium } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

// ── Validate required env ──────────────────────────────────────────────────
const SCRATCH_DIR = process.env.SCRATCH_DIR;
if (!SCRATCH_DIR) {
  console.error('BROWSER_LAUNCH_FAILED: SCRATCH_DIR env var is required');
  process.exit(2);
}
fs.mkdirSync(SCRATCH_DIR, { recursive: true });

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
  console.error('BROWSER_LAUNCH_FAILED: ADMIN_PASSWORD env var is required');
  process.exit(2);
}

const BASE_URL   = (process.env.HEARTH_URL ?? 'http://127.0.0.1:8420').replace(/\/$/, '');
const EXEC_PATH  = process.env.CHROMIUM_EXECUTABLE_PATH || undefined;
const ADMIN_EMAIL = 'admin@hearth.test';

// ── Route lists ────────────────────────────────────────────────────────────

// Public (no auth needed)
const PUBLIC_ROUTES = [
  '/ui/admin/login',
];

// Admin routes (require session cookie)
const ADMIN_ROUTES = [
  '/ui/admin',
  '/ui/admin/realms',
  '/ui/admin/users',
  '/ui/admin/organizations',
  '/ui/admin/roles',
  '/ui/admin/groups',
  '/ui/admin/clients',
  '/ui/admin/api-keys',
  '/ui/admin/settings',
];

// Forced error paths
const ERROR_ROUTES = [
  { url: '/ui/admin/realms/__nonexistent__/users', label: 'not-found-realm-users' },
];

// ── Main ───────────────────────────────────────────────────────────────────

async function main() {
  const source = EXEC_PATH ? `nix-chromium (${EXEC_PATH})` : 'playwright-bundled-chromium';
  console.log(`BROWSER_CHECK: launching ${source} ...`);

  // Hard launch — exit 2 (BROWSER_LAUNCH_FAILED) if browser will not start
  let browser;
  try {
    browser = await chromium.launch({
      headless: true,
      executablePath: EXEC_PATH,
      args: ['--no-sandbox', '--disable-dev-shm-usage'],
    });
  } catch (err) {
    console.error(`BROWSER_LAUNCH_FAILED: ${err.message}`);
    process.exit(2);
  }

  // Health check: can the browser render about:blank?
  {
    const p = await browser.newPage();
    try {
      await p.goto('about:blank', { timeout: 10_000 });
      const healthPath = path.join(SCRATCH_DIR, 'health-check.png');
      await p.screenshot({ path: healthPath });
      if (!fs.existsSync(healthPath) || fs.statSync(healthPath).size < 100) {
        throw new Error('health-check screenshot is empty or missing');
      }
      console.log(`BROWSER_CHECK: ok — health-check.png written`);
    } catch (err) {
      console.error(`BROWSER_LAUNCH_FAILED: health check failed — ${err.message}`);
      await browser.close();
      process.exit(2);
    } finally {
      await p.close();
    }
  }

  const manifest = {
    baseUrl: BASE_URL,
    chromiumPath: EXEC_PATH || '(playwright-bundled)',
    screenshots: [],
    errors: [],
  };

  // ── Context + viewport ─────────────────────────────────────────────────
  const ctx  = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();

  // ── Public routes ──────────────────────────────────────────────────────
  for (const route of PUBLIC_ROUTES) {
    await capture(page, BASE_URL + route, route, manifest);
  }

  // ── Login via form to get session cookie ───────────────────────────────
  console.log('AUTH: logging in as admin...');
  try {
    await page.goto(BASE_URL + '/ui/admin/login', { waitUntil: 'networkidle', timeout: 15_000 });
    await page.fill('input[name="email"], input[type="email"]', ADMIN_EMAIL);
    await page.fill('input[name="password"], input[type="password"]', ADMIN_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL(/\/ui\/admin($|\/)/, { timeout: 15_000 });
    console.log('AUTH: ok — session cookie acquired');
  } catch (err) {
    console.error(`AUTH_FAILED: could not log in — ${err.message}`);
    // Take a screenshot of whatever state we landed in
    await capture(page, page.url(), 'auth-failure', manifest);
    await browser.close();
    process.exit(1);
  }

  // ── Admin routes ───────────────────────────────────────────────────────
  for (const route of ADMIN_ROUTES) {
    await capture(page, BASE_URL + route, route, manifest);
  }

  // ── Forced error paths ─────────────────────────────────────────────────
  // Clear cookies first for the unauthenticated check
  const publicCtx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const publicPage = await publicCtx.newPage();

  // Unauthenticated admin page → expect redirect to login
  await capture(publicPage, BASE_URL + '/ui/admin', 'unauth-admin', manifest);
  await publicCtx.close();

  // 404-style routes (while authenticated)
  for (const { url, label } of ERROR_ROUTES) {
    await capture(page, BASE_URL + url, label, manifest);
  }

  await browser.close();

  const manifestPath = path.join(SCRATCH_DIR, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  console.log(`CRAWL_COMPLETE: ${manifest.screenshots.length} screenshots, ${manifest.errors.length} navigation errors`);
  console.log(`MANIFEST: ${manifestPath}`);
  process.exit(0);
}

// ── Helpers ────────────────────────────────────────────────────────────────

async function capture(page, url, label, manifest) {
  const slug = label.replace(/[^a-z0-9]/gi, '-').replace(/-+/g, '-').replace(/^-|-$/g, '').substring(0, 80);
  const filePath = path.join(SCRATCH_DIR, `${slug}.png`);
  try {
    await page.goto(url, { waitUntil: 'networkidle', timeout: 20_000 });
    await page.screenshot({ path: filePath, fullPage: true });

    if (!fs.existsSync(filePath) || fs.statSync(filePath).size < 100) {
      throw new Error(`screenshot file missing or empty: ${filePath}`);
    }
    manifest.screenshots.push({ label, url, file: filePath, slug });
    console.log(`SCREENSHOT: ${label} → ${slug}.png`);
  } catch (err) {
    manifest.errors.push({ label, url, error: err.message });
    console.error(`SCREENSHOT_ERROR: ${label}: ${err.message}`);
  }
}

main().catch(err => {
  console.error(`CRAWL_ERROR: ${err.message}`);
  process.exit(1);
});
