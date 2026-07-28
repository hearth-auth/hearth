/**
 * MFA TOTP enrollment / disable flow (HEA-661).
 *
 * Flow:
 *   1. Navigate to /ui/account/totp — enrollment page renders QR code + secret.
 *   2. Extract the base32 secret from the `code.hearth-secret` element.
 *   3. Compute a valid TOTP code using Node.js crypto (RFC 6238 / HMAC-SHA1).
 *   4. Submit the activation form — MFA becomes enabled.
 *   5. Re-visit /ui/account/totp — disable form is now shown.
 *   6. Submit disable — MFA becomes disabled.
 *   7. Re-visit /ui/account/totp — enrollment form is shown again.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { test, expect } from '@playwright/test';
import { instrumentPage, assertPageClean } from '../helpers/assertions';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const AUTH_DIR = path.join(__dirname, '..', '.auth');

// ---------------------------------------------------------------------------
// RFC 6238 TOTP (HMAC-SHA1, 30s step, 6 digits)
// ---------------------------------------------------------------------------

function base32Decode(s: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = s.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error(`Invalid base32 char: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function computeTotp(secretBase32: string, unixSec = Math.floor(Date.now() / 1000)): string {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(unixSec / 30);
  const buf = Buffer.alloc(8);
  // Write counter as big-endian 64-bit integer (high word first)
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (code % 1_000_000).toString().padStart(6, '0');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function navigateToTotpPage(page: import('@playwright/test').Page): Promise<void> {
  await page.goto(`${BASE_URL}/ui/account/totp`, { waitUntil: 'domcontentloaded' });
}

async function extractSecret(page: import('@playwright/test').Page): Promise<string> {
  const el = page.locator('code.hearth-secret');
  await expect(el).toBeVisible({ timeout: 5_000 });
  return (await el.textContent())?.trim() ?? '';
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Serial ensures MFA state transitions (enable → disable) don't race
test.describe.serial('MFA TOTP enrollment and disable cycle', () => {
  test.use({ storageState: path.join(AUTH_DIR, 'admin.json') });

  test.beforeEach(async ({ page }) => {
    instrumentPage(page);
  });

  test.afterEach(async ({ page }) => {
    assertPageClean(page);
  });

  test('enrollment page renders QR secret and recovery codes', async ({ page }) => {
    await navigateToTotpPage(page);

    // Secret must be present and look like base32
    const secret = await extractSecret(page);
    expect(secret).toMatch(/^[A-Z2-7]{16,}$/);

    // Recovery codes section should exist (contains at least one code-looking element)
    const body = await page.evaluate(() => document.body.innerText);
    expect(body).toMatch(/recovery/i);
  });

  test('valid TOTP code activates MFA and disable form appears', async ({ page }) => {
    await navigateToTotpPage(page);

    const secret = await extractSecret(page);
    expect(secret).toBeTruthy();

    // Compute code just before submitting to stay within the 30s window
    const code = computeTotp(secret);
    await page.fill('input[name="code"]', code);
    await page.click('#main button[type="submit"]');

    // On success the handler redirects to /ui/account
    await page.waitForURL(/\/ui\/account($|\?)/, { timeout: 10_000 });

    // Return to the TOTP page — it should now show the *disable* form
    await navigateToTotpPage(page);
    const bodyText = await page.evaluate(() => document.body.innerText);
    expect(bodyText).toMatch(/disable.*mfa|mfa.*enabled/i);
    await expect(page.locator('form[action*="totp/disable"]')).toBeVisible();
  });

  test('disabling MFA returns to enrollment form', async ({ page }) => {
    // Ensure MFA is enabled first (re-enroll if needed)
    await navigateToTotpPage(page);
    const bodyBefore = await page.evaluate(() => document.body.innerText);

    if (!bodyBefore.match(/disable.*mfa|mfa.*enabled/i)) {
      // MFA is not enabled — activate it
      const secret = await extractSecret(page);
      const code = computeTotp(secret);
      await page.fill('input[name="code"]', code);
      await Promise.all([
        page.waitForURL(/\/ui\/account($|\?)/, { timeout: 10_000 }),
        page.click('#main button[type="submit"]'),
      ]);
      await navigateToTotpPage(page);
    }

    // Now MFA should be enabled — submit the disable form
    const disableForm = page.locator('form[action*="totp/disable"]');
    await expect(disableForm).toBeVisible();
    await disableForm.locator('button[type="submit"]').click();

    // On success redirects to /ui/account
    await page.waitForURL(/\/ui\/account($|\?)/, { timeout: 10_000 });

    // Return to TOTP page — enrollment form should be visible again
    await navigateToTotpPage(page);
    const bodyAfter = await page.evaluate(() => document.body.innerText);
    expect(bodyAfter).not.toMatch(/mfa.*enabled/i);
    // Enrollment form inputs should be present
    await expect(page.locator('input[name="code"]')).toBeVisible();
  });

  test('wrong TOTP code shows error and does not enable MFA', async ({ page }) => {
    await navigateToTotpPage(page);

    // Legitimate runtime state: a previous test left MFA enabled, so the
    // enrollment form (and its code input) isn't shown. Skip with a descriptive
    // reason rather than a silent skip that hides why.
    const bodyText = await page.evaluate(() => document.body.innerText);
    if (bodyText.match(/mfa.*enabled/i)) {
      test.skip(true, 'MFA already enabled from a prior test — enrollment form not shown');
      return;
    }

    await page.fill('input[name="code"]', '000000');

    // Use Promise.all to avoid a race where the navigation completes before
    // waitForURL installs its listener.  Scope to #main so the sidebar's
    // logout button[type="submit"] is never accidentally clicked.
    await Promise.all([
      page.waitForURL(/\/account\/totp/, { timeout: 10_000 }),
      page.click('#main button[type="submit"]'),
    ]);

    // An inline error must be shown — a silently-broken error-display UI would
    // otherwise pass this test on the "MFA not enabled" check alone. The handler
    // renders "Invalid authentication code." (account.rs render_totp_error).
    await expect(page.locator('#main')).toContainText('Invalid authentication code', {
      timeout: 10_000,
    });

    const afterText = await page.evaluate(() => document.body.innerText);
    // MFA must NOT be enabled
    expect(afterText).not.toMatch(/mfa.*enabled/i);
  });
});
