import * as path from 'path';
import { test, expect } from '@playwright/test';
import { AUTH_DIR } from '../helpers/actions';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

test.use({ storageState: path.join(AUTH_DIR, 'admin.json') });

test.describe('Account settings page', () => {
  test('account page loads with expected sections', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/account`);

    await expect(page.locator('h1')).toContainText('My Account');
    // Change password card
    await expect(page.locator('h2').filter({ hasText: 'Change password' })).toBeVisible();
    await expect(page.locator('input[name="current_password"]')).toBeVisible();
    await expect(page.locator('input[name="new_password"]')).toBeVisible();
    await expect(page.locator('input[name="confirm_password"]')).toBeVisible();
    // MFA card
    await expect(page.locator('h2').filter({ hasText: 'Multi-factor authentication' })).toBeVisible();
    // Sessions link
    await expect(page.locator('a[href="/ui/account/sessions"]')).toBeVisible();
  });

  test('password change form rejects wrong current password', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/account`);

    await page.fill('input[name="current_password"]', 'TotallyWrong!1234567');
    await page.fill('input[name="new_password"]', 'NewPassword!9876543');
    await page.fill('input[name="confirm_password"]', 'NewPassword!9876543');
    await page.click('form[action="/ui/account/password"] button[type="submit"]');

    // Server re-renders the page with an error alert — still on /ui/account
    await expect(page.locator('[role="alert"]')).toBeVisible({ timeout: 10_000 });
    await expect(page).toHaveURL(/\/ui\/account/);
  });

  test('sessions list page loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/account/sessions`);

    await expect(page.locator('h1')).toContainText('My sessions');
    // Current session row is always present
    await expect(page.locator('[data-current-session="true"]')).toBeVisible();
  });
});
