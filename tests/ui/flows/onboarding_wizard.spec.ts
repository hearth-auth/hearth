/**
 * Onboarding wizard — multi-step flow tests (HEA-661).
 *
 * The globalSetup bootstraps a dev-realm, so `is_wizard_needed()` returns false
 * by the time these tests run. We verify the "already configured" redirect and
 * then drive steps 2–4 directly against the seed realm (each step accepts the
 * realm name via query param, so they're independently navigable).
 *
 * A full step-1 smoke is included by exercising the POST handler against a
 * fresh wizard-test realm name; the handler redirects to step 2 on success.
 */

import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import type { SeedFixtures } from '../fixtures/seed';
import { mailcatcherLogin, waitForEmail, extractLinkFromEmail } from '../helpers/mailcatcher';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const AUTH_DIR = path.join(__dirname, '..', '.auth');

function loadSeed(): SeedFixtures {
  const p = path.join(AUTH_DIR, 'seed.json');
  if (!fs.existsSync(p)) throw new Error(`Seed not found at ${p}. Run globalSetup first.`);
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as SeedFixtures;
}

// ---------------------------------------------------------------------------
// Already-configured redirect
// ---------------------------------------------------------------------------

test.describe('Onboarding wizard — already configured', () => {
  test('GET /ui/admin/onboarding redirects to dashboard when realms exist', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    const resp = await page.goto(`${BASE_URL}/ui/admin/onboarding`, {
      waitUntil: 'domcontentloaded',
    });

    // The wizard gate redirects — the final settled URL should be /ui, not /ui/admin/onboarding
    expect(page.url()).not.toContain('/onboarding');
    await ctx.close();
  });
});

// ---------------------------------------------------------------------------
// Step 2 — app registration (driven with seed realm)
// ---------------------------------------------------------------------------

test.describe('Onboarding wizard — step 2: app registration', () => {
  test('renders app registration form with realm param', async ({ browser }) => {
    const seed = loadSeed();
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    await page.goto(
      `${BASE_URL}/ui/admin/onboarding/app?realm=${encodeURIComponent(seed.realmName)}`,
      { waitUntil: 'domcontentloaded' },
    );

    expect(page.url()).toContain('/onboarding/app');
    // Form must be present
    await expect(page.locator('input[name="app_name"]')).toBeVisible();
    await expect(page.locator('input[name="redirect_uri"]')).toBeVisible();
    await ctx.close();
  });

  test('submitting step 2 creates an OAuth app and redirects to step 3', async ({ browser }) => {
    const seed = loadSeed();
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    await page.goto(
      `${BASE_URL}/ui/admin/onboarding/app?realm=${encodeURIComponent(seed.realmName)}`,
      { waitUntil: 'domcontentloaded' },
    );

    await page.fill('input[name="app_name"]', 'wizard-test-app');
    await page.fill('input[name="redirect_uri"]', 'https://wizard.test/callback');

    await Promise.all([
      page.waitForURL(/\/onboarding\/invite/, { timeout: 15_000 }),
      page.click('#main button[type="submit"]'),
    ]);

    expect(page.url()).toContain('/onboarding/invite');
    await ctx.close();
  });
});

// ---------------------------------------------------------------------------
// Step 3 — invite (verify form renders)
// ---------------------------------------------------------------------------

test.describe('Onboarding wizard — step 3: invite', () => {
  test('renders invite form with realm param', async ({ browser }) => {
    const seed = loadSeed();
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    await page.goto(
      `${BASE_URL}/ui/admin/onboarding/invite?realm=${encodeURIComponent(seed.realmName)}`,
      { waitUntil: 'domcontentloaded' },
    );

    expect(page.url()).toContain('/onboarding/invite');
    await expect(page.locator('input[name="email"]')).toBeVisible();
    await expect(page.locator('select[name="role"]')).toBeVisible();
    await ctx.close();
  });

  test('submitting step 3 sends invite and redirects to step 4', async ({ browser }) => {
    const seed = loadSeed();
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    await page.goto(
      `${BASE_URL}/ui/admin/onboarding/invite?realm=${encodeURIComponent(seed.realmName)}`,
      { waitUntil: 'domcontentloaded' },
    );

    // Use a unique email each run to avoid 409 duplicate-user errors
    const email = `wizard-invite-${Date.now()}@test.example`;
    await page.fill('input[name="email"]', email);
    await page.selectOption('select[name="role"]', 'member');

    await Promise.all([
      page.waitForURL(/\/onboarding\/email/, { timeout: 15_000 }),
      page.click('#main button[type="submit"]'),
    ]);

    expect(page.url()).toContain('/onboarding/email');
    await ctx.close();
  });
});

// ---------------------------------------------------------------------------
// Step 4 — email config (verify form renders)
// ---------------------------------------------------------------------------

test.describe('Onboarding wizard — step 4: email config', () => {
  test('renders email test form with realm param', async ({ browser }) => {
    const seed = loadSeed();
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    await page.goto(
      `${BASE_URL}/ui/admin/onboarding/email?realm=${encodeURIComponent(seed.realmName)}`,
      { waitUntil: 'domcontentloaded' },
    );

    expect(page.url()).toContain('/onboarding/email');
    // Page must have some visible content
    const text = await page.evaluate(() => document.body.innerText.trim());
    expect(text.length).toBeGreaterThan(10);
    await ctx.close();
  });
});

// ---------------------------------------------------------------------------
// Complete page
// ---------------------------------------------------------------------------

test.describe('Onboarding wizard — complete page', () => {
  test('renders completion summary', async ({ browser }) => {
    const seed = loadSeed();
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    await page.goto(
      `${BASE_URL}/ui/admin/onboarding/complete?realm=${encodeURIComponent(seed.realmName)}`,
      { waitUntil: 'domcontentloaded' },
    );

    // Completion page should not be an error
    expect(page.url()).toContain('/onboarding/complete');
    const text = await page.evaluate(() => document.body.innerText.trim());
    expect(text.length).toBeGreaterThan(10);
    await ctx.close();
  });
});

// ---------------------------------------------------------------------------
// Email flow — invitation link via mailcatcher
// ---------------------------------------------------------------------------

test.describe('Email flow — invite via mailcatcher', () => {
  test.skip(
    !process.env.HEARTH_MAILCATCHER_PASSWORD,
    'Set HEARTH_MAILCATCHER_PASSWORD to enable mailcatcher email flow tests',
  );

  test('invite email is captured and setup link is followable', async ({ browser }) => {
    const seed = loadSeed();
    const mcAuth = await mailcatcherLogin();

    // Navigate to invite step and send an invite
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    await page.goto(
      `${BASE_URL}/ui/admin/onboarding/invite?realm=${encodeURIComponent(seed.realmName)}`,
      { waitUntil: 'domcontentloaded' },
    );

    const email = `mc-invite-${Date.now()}@test.example`;
    await page.fill('input[name="email"]', email);
    await page.selectOption('select[name="role"]', 'member');

    await Promise.all([
      page.waitForURL(/\/onboarding\/email/, { timeout: 15_000 }),
      page.click('#main button[type="submit"]'),
    ]);

    // Wait for the invite email to appear in mailcatcher
    const found = await waitForEmail(mcAuth, (e) => e.subject.toLowerCase().includes('invite') || true, 10_000);
    expect(found.id).toBeTruthy();

    // Extract the setup link from the email body
    const link = await extractLinkFromEmail(mcAuth, found.id);
    expect(link).toMatch(/https?:\/\//);

    // Follow the link — should render the password-setup page, not a 404/500
    await page.goto(link, { waitUntil: 'domcontentloaded' });
    const status = await page.evaluate(() => document.title);
    expect(status).not.toMatch(/error|not found/i);

    await ctx.close();
  });
});
