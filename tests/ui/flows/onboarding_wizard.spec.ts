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
import { mailcatcherLogin, waitForEmail, fetchEmailBody, extractFirstLink } from '../helpers/mailcatcher';
import { newInstrumentedPage, assertPageClean } from '../helpers/assertions';

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
    const page = await newInstrumentedPage(ctx);

    const resp = await page.goto(`${BASE_URL}/ui/admin/onboarding`, {
      waitUntil: 'domcontentloaded',
    });

    // The wizard gate redirects — the final settled URL should be /ui, not /ui/admin/onboarding
    expect(page.url()).not.toContain('/onboarding');
    assertPageClean(page);
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
    const page = await newInstrumentedPage(ctx);

    await page.goto(
      `${BASE_URL}/ui/admin/onboarding/app?realm=${encodeURIComponent(seed.realmName)}`,
      { waitUntil: 'domcontentloaded' },
    );

    expect(page.url()).toContain('/onboarding/app');
    // Form must be present
    await expect(page.locator('input[name="app_name"]')).toBeVisible();
    await expect(page.locator('input[name="redirect_uri"]')).toBeVisible();
    assertPageClean(page);
    await ctx.close();
  });

  test('submitting step 2 creates an OAuth app and redirects to step 3', async ({ browser }) => {
    const seed = loadSeed();
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await newInstrumentedPage(ctx);

    await page.goto(
      `${BASE_URL}/ui/admin/onboarding/app?realm=${encodeURIComponent(seed.realmName)}`,
      { waitUntil: 'domcontentloaded' },
    );

    // Unique app name so the downstream list assertion is unambiguous across runs.
    const appName = `wizard-test-app-${Date.now()}`;
    await page.fill('input[name="app_name"]', appName);
    await page.fill('input[name="redirect_uri"]', 'https://wizard.test/callback');

    await Promise.all([
      page.waitForURL(/\/onboarding\/invite/, { timeout: 15_000 }),
      page.click('#main button[type="submit"]'),
    ]);

    // Landed on the invite step (step 3), not an error page.
    expect(page.url()).toContain('/onboarding/invite');
    await expect(page.locator('#main')).toContainText('Invite a team member', { timeout: 10_000 });

    // The OAuth app was actually created — it must now appear in the realm's
    // applications list, not merely have produced a redirect.
    await page.goto(
      `${BASE_URL}/ui/admin/realms/${encodeURIComponent(seed.realmName)}/applications`,
      { waitUntil: 'domcontentloaded' },
    );
    await expect(page.locator('#main')).toContainText(appName, { timeout: 10_000 });

    assertPageClean(page);
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
    const page = await newInstrumentedPage(ctx);

    await page.goto(
      `${BASE_URL}/ui/admin/onboarding/invite?realm=${encodeURIComponent(seed.realmName)}`,
      { waitUntil: 'domcontentloaded' },
    );

    expect(page.url()).toContain('/onboarding/invite');
    await expect(page.locator('input[name="email"]')).toBeVisible();
    await expect(page.locator('select[name="role"]')).toBeVisible();
    assertPageClean(page);
    await ctx.close();
  });

  test('submitting step 3 sends invite and redirects to step 4', async ({ browser }) => {
    const seed = loadSeed();
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await newInstrumentedPage(ctx);

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

    // Landed on the email step (step 4), not an error page.
    expect(page.url()).toContain('/onboarding/email');
    await expect(page.locator('#main')).toContainText('Test email delivery', { timeout: 10_000 });

    // The invited user was actually created — it must now appear in the realm's
    // users list, not merely have produced a redirect.
    await page.goto(
      `${BASE_URL}/ui/admin/realms/${encodeURIComponent(seed.realmName)}/users?q=${encodeURIComponent(email)}`,
      { waitUntil: 'domcontentloaded' },
    );
    await expect(page.locator('#main')).toContainText(email, { timeout: 10_000 });

    assertPageClean(page);
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
    const page = await newInstrumentedPage(ctx);

    await page.goto(
      `${BASE_URL}/ui/admin/onboarding/email?realm=${encodeURIComponent(seed.realmName)}`,
      { waitUntil: 'domcontentloaded' },
    );

    expect(page.url()).toContain('/onboarding/email');
    // Assert the actual step-4 copy renders — not merely a non-empty (possibly error) body.
    await expect(page.locator('#main')).toContainText('Test email delivery', { timeout: 10_000 });
    await expect(page.locator('input[name="email"], input[type="email"]').first()).toBeVisible();
    assertPageClean(page);
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
    const page = await newInstrumentedPage(ctx);

    await page.goto(
      `${BASE_URL}/ui/admin/onboarding/complete?realm=${encodeURIComponent(seed.realmName)}`,
      { waitUntil: 'domcontentloaded' },
    );

    // Completion page renders its specific summary copy — not merely a non-empty
    // (possibly error) body.
    expect(page.url()).toContain('/onboarding/complete');
    await expect(page.locator('#main')).toContainText("You're all set", { timeout: 10_000 });
    await expect(page.locator('#main')).toContainText('Quick start', { timeout: 10_000 });
    assertPageClean(page);
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
    const page = await newInstrumentedPage(ctx);

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

    // Wait for the invite/setup email to appear in mailcatcher. The wizard invite
    // sends a "<product> setup required" message (identity/email/templates.rs) — match
    // that specific subject, not "any email".
    const found = await waitForEmail(
      mcAuth,
      (e) => e.subject.toLowerCase().includes('setup required'),
      10_000,
    );
    expect(found.id).toBeTruthy();

    // Bind the captured email to the freshly-invited recipient and extract the
    // setup link from its body — proving the invite for THIS user was delivered.
    const body = await fetchEmailBody(mcAuth, found.id);
    expect(body).toContain(email);
    const link = extractFirstLink(body);
    if (!link) throw new Error('No setup link found in the captured invite email body');
    expect(link).toMatch(/https?:\/\//);

    // Follow the link — should render the password-setup page, not a 404/500
    await page.goto(link, { waitUntil: 'domcontentloaded' });
    const status = await page.evaluate(() => document.title);
    expect(status).not.toMatch(/error|not found/i);

    assertPageClean(page);
    await ctx.close();
  });
});
