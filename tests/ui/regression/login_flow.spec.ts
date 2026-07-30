import { test, expect } from '@playwright/test';
import { ADMIN_EMAIL, ADMIN_PASSWORD } from '../fixtures/auth';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

// No storageState — these tests exercise the credential flow itself.

test.describe('Login flow', () => {
  test('admin login → dashboard → logout', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/admin/login`);

    await expect(page.locator('input[name="email"]')).toBeVisible();

    await page.fill('input[name="email"]', ADMIN_EMAIL);
    await page.fill('input[name="password"]', ADMIN_PASSWORD);
    await Promise.all([
      page.waitForURL(/\/ui(?:\/|$)/, { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    // Sidebar nav confirms authenticated shell rendered
    await expect(page.locator('nav[aria-label="Admin"]')).toBeVisible();

    // Logout via the user-pill form in the sidebar
    await page.click('form[action="/ui/logout"] button[type="submit"]');

    // Should return to a login page
    await page.waitForURL(/\/ui\/(?:admin\/)?login/, { timeout: 10_000 });
    await expect(page.locator('input[name="email"]')).toBeVisible();
  });

  test('wrong credentials → error banner stays on login page', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/admin/login`);

    await page.fill('input[name="email"]', 'nobody@nowhere.example');
    await page.fill('input[name="password"]', 'ThisIsDefinitelyWrong!99');
    await page.click('button[type="submit"]');

    // Server re-renders the form with an error — not redirected away.
    // Use .first() because the passkey error div also has role="alert" (initially hidden).
    await expect(page.locator('[role="alert"]').first()).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('input[name="email"]')).toBeVisible();
  });

  test('unauthenticated access to admin redirects to login', async ({ page }) => {
    // Start with no cookies
    await page.goto(`${BASE_URL}/ui/admin/realms`);
    await page.waitForURL(/\/ui\/(?:admin\/)?login/, { timeout: 10_000 });
    await expect(page.locator('input[name="email"]')).toBeVisible();
  });

  // HEA-1983: CSRF error page must carry a fresh token so the user can
  // resubmit immediately without a separate reload.
  test('stale CSRF token → error page has fresh token → resubmit succeeds', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/admin/login`);
    await expect(page.locator('input[name="email"]')).toBeVisible();

    await page.fill('input[name="email"]', ADMIN_EMAIL);
    await page.fill('input[name="password"]', ADMIN_PASSWORD);

    // Corrupt the embedded _csrf field so the double-submit check fails while
    // the cookie still carries the original valid value.
    await page.evaluate(() => {
      const csrf = document.querySelector('input[name="_csrf"]') as HTMLInputElement | null;
      if (csrf) csrf.value = 'deliberately-invalid-csrf-token';
    });

    await page.click('button[type="submit"]');

    // Server should re-render with a 422 error banner.
    await expect(page.locator('[role="alert"]').first()).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('[role="alert"]').first()).toContainText('expired');

    // The error page must embed a non-empty, non-stale _csrf value.
    const freshCsrf = await page.locator('input[name="_csrf"]').inputValue();
    expect(freshCsrf).not.toBe('');
    expect(freshCsrf).not.toBe('deliberately-invalid-csrf-token');

    // Email field should be pre-filled (not cleared) after CSRF error.
    await expect(page.locator('input[name="email"]')).toHaveValue(ADMIN_EMAIL);

    // Fill password again (it is always cleared for security) and resubmit.
    await page.fill('input[name="password"]', ADMIN_PASSWORD);
    await Promise.all([
      page.waitForURL(/\/ui(?:\/|$)/, { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    // Successful login — authenticated admin shell is visible.
    await expect(page.locator('nav[aria-label="Admin"]')).toBeVisible();
  });
});
