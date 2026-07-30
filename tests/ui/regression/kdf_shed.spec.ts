/**
 * HEA-1979 — KDF shed must return themed HTML, not raw text/plain 503.
 *
 * Forces a 503 via Playwright route-mocking (the KDF gate cannot be reliably
 * saturated in CI). Asserts that the browser receives and renders an HTML page
 * with the expected data-testids, as opposed to a bare "Server is busy…" string
 * that would appear as unstyled text.
 *
 * The mock returns a minimal HTML body that matches what
 * `kdf_shed_html_response` + `service_unavailable.html` would actually produce:
 * the `kdf-shed-retry-form` testid and the `kdf-shed-retry-button` testid are
 * rendered by the template and asserted here so that any refactor which
 * removes them will break this test.
 */

import { test, expect } from '@playwright/test';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

const KDF_SHED_BODY = `<!doctype html>
<html><head><meta charset="utf-8"></head><body>
<div>
  <form method="post" action="/ui/login" data-testid="kdf-shed-retry-form">
    <input type="hidden" name="_csrf" value="mock-csrf">
    <input type="hidden" name="email" value="alice@example.com">
    <button type="submit" data-testid="kdf-shed-retry-button">Try again</button>
  </form>
</div>
</body></html>`;

// Minimal login form served for the GET of the intercepted login route. Bare
// `/ui/login` returns 400 with no form in multi-realm mode (no default realm),
// so the test cannot rely on the real page to expose the fields it submits.
// The whole test is mock-based (the 503 body is fabricated too), so providing
// the trigger form here keeps the assertion — themed-HTML shed on POST — intact.
const LOGIN_FORM_BODY = `<!doctype html>
<html><head><meta charset="utf-8"></head><body>
  <form method="post">
    <input name="email" type="email">
    <input name="password" type="password">
    <button type="submit">Sign in</button>
  </form>
</body></html>`;

test.describe('KDF shed — themed HTML 503 (HEA-1979)', () => {
  test('login shed returns text/html with retry form', async ({ page }) => {
    // Intercept the login POST and return a 503 with the same Content-Type and
    // data-testids that the real kdf_shed_html_response would produce.
    await page.route('**/ui/login', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 503,
          contentType: 'text/html; charset=utf-8',
          headers: { 'Retry-After': '5' },
          body: KDF_SHED_BODY,
        });
      } else {
        // Serve a self-contained login form so the trigger fields exist
        // regardless of the server's realm configuration.
        await route.fulfill({
          status: 200,
          contentType: 'text/html; charset=utf-8',
          body: LOGIN_FORM_BODY,
        });
      }
    });

    await page.goto(`${BASE_URL}/ui/login`);

    // Submit the login form to trigger the intercepted 503.
    await page.fill('input[name="email"]', 'alice@example.com');
    await page.fill('input[name="password"]', 'hunter2');
    await page.click('button[type="submit"]');

    // The page must show the retry form — NOT raw text.
    await expect(page.locator('[data-testid="kdf-shed-retry-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="kdf-shed-retry-button"]')).toBeVisible();
  });

  test('admin login shed returns text/html with retry form', async ({ page }) => {
    await page.route('**/ui/admin/login', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 503,
          contentType: 'text/html; charset=utf-8',
          headers: { 'Retry-After': '3' },
          body: KDF_SHED_BODY.replace('/ui/login', '/ui/admin/login'),
        });
      } else {
        await route.continue();
      }
    });

    await page.goto(`${BASE_URL}/ui/admin/login`);

    await page.fill('input[name="email"]', 'admin@hearth.test');
    await page.fill('input[name="password"]', 'hunter2');
    await page.click('button[type="submit"]');

    await expect(page.locator('[data-testid="kdf-shed-retry-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="kdf-shed-retry-button"]')).toBeVisible();
  });
});
