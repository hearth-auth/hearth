/**
 * Flow 2 — Self-registration.
 *
 * A brand-new user signs up and ends up authenticated in the SPA. The demo SPA
 * delegates registration to its IdP (Hearth's hosted pages), reached via the
 * "Sign in with Hearth" → hosted login → "Create account" path. Registration
 * requires email verification (Hearth issues a `PendingVerification` user and
 * emails a link), which the test completes through the dev mailcatcher before
 * logging in.
 *
 * Requires the demo realm to have self-registration enabled
 * (`registration_policy: open` in `hearth.yaml`, added as config plumbing) and
 * the mailcatcher password to be known (`HEARTH_MAILCATCHER_PASSWORD`, set by
 * `run-integration.sh`). When the password is absent the email leg cannot be
 * driven deterministically, so the test skips with an explicit reason.
 */

import { test, expect } from '@playwright/test';
import { FRONTEND_URL, HEARTH_URL, DEMO_PASSWORD } from './config';
import { loginViaSpa } from './ui';
import { mailcatcherLogin, waitForEmail, extractLinkFromEmail } from '../helpers/mailcatcher';

test.describe('Flow 2 — self-registration', () => {
  test('new user signs up, verifies email, and lands authenticated', async ({ page }) => {
    test.skip(
      !process.env.HEARTH_MAILCATCHER_PASSWORD,
      'HEARTH_MAILCATCHER_PASSWORD unset — email verification cannot be driven deterministically',
    );
    // Unique email so the verification message is unambiguous in the inbox.
    const email = `it-signup-${Date.now()}@example.test`;

    // Authenticate a mailcatcher session BEFORE registering so we can poll the
    // inbox for the verification mail as soon as it is sent.
    const mcCookie = await mailcatcherLogin();

    // ── Reach the hosted registration form via the SPA ──────────────────────
    await page.goto(`${FRONTEND_URL}/`);
    await page.getByRole('button', { name: 'Sign in with Hearth' }).click();
    await page.waitForURL(/\/ui\/realms\/[^/]+\/(oauth\/authorize|login)/, { timeout: 20_000 });

    // "Create account" link is shown only when self-registration is enabled.
    const registerLink = page.locator('a[href*="register"]');
    await expect(registerLink).toBeVisible();
    await registerLink.click();
    await page.waitForURL(/\/register/, { timeout: 20_000 });

    // ── Fill and submit the registration form ───────────────────────────────
    await page.fill('input[name="email"]', email);
    await page.fill('input[name="first_name"]', 'Ivy');
    await page.fill('input[name="last_name"]', 'Newcomer');
    await page.fill('input[name="password"]', DEMO_PASSWORD);
    await page.fill('input[name="password_confirm"]', DEMO_PASSWORD);
    await page.getByRole('button', { name: 'Create account' }).click();

    // Confirmation page ("check your email") — signup accepted, not yet active.
    await expect(page.locator('body')).toContainText(/email|verify|check/i);

    // ── Complete email verification via mailcatcher ─────────────────────────
    const mail = await waitForEmail(mcCookie, () => true, 15_000);
    const verifyLink = await extractLinkFromEmail(mcCookie, mail.id);
    // Hearth may build the link with 127.0.0.1 instead of localhost; accept both.
    expect(verifyLink).toMatch(/^https?:\/\/(localhost|127\.0\.0\.1)/);
    await page.goto(verifyLink);
    // Verification lands on a success/sign-in page, not an error.
    await expect(page.locator('body')).not.toContainText(/invalid|expired|error/i);

    // ── Sign in as the freshly-verified user through the SPA ────────────────
    const tokens = await loginViaSpa(page, email, DEMO_PASSWORD);
    expect(tokens.accessToken).toBeTruthy();

    // Authenticated on the dashboard; a brand-new user holds no roles yet.
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await expect(page.locator('.badge-row').first()).toContainText(/no roles/i);
  });
});
