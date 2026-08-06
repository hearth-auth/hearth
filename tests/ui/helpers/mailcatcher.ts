/**
 * Helpers for interacting with the dev mailcatcher inbox at /dev/mail.
 *
 * The mailcatcher is only available when the server runs with --dev and
 * email.transport = mailcatcher. The inbox password is printed to stderr at
 * startup. For automated tests, set HEARTH_MAILCATCHER_PASSWORD to a known
 * value so the server uses that password instead of a random one.
 */

import type { Page } from '@playwright/test';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const MC_PASSWORD = process.env.HEARTH_MAILCATCHER_PASSWORD ?? '';

export interface CapturedEmail {
  id: string;
  subject: string;
  to: string;
  body: string;
}

/**
 * Authenticates with the mailcatcher inbox and returns a session cookie value.
 * Throws when HEARTH_MAILCATCHER_PASSWORD is not set or login fails.
 */
export async function mailcatcherLogin(): Promise<string> {
  if (!MC_PASSWORD) {
    throw new Error(
      'HEARTH_MAILCATCHER_PASSWORD is not set — ' +
        'start the server with that env var to make email flow tests deterministic.',
    );
  }

  const resp = await fetch(`${BASE_URL}/dev/mail/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ password: MC_PASSWORD }),
    redirect: 'manual',
  });

  const cookie = resp.headers.get('set-cookie') ?? '';
  const match = /mcauth=([^;]+)/.exec(cookie);
  if (!match) {
    throw new Error(`Mailcatcher login failed (HTTP ${resp.status})`);
  }
  return match[1];
}

/**
 * Lists emails in the mailcatcher inbox. Returns raw HTML of the inbox page.
 */
async function fetchInboxHtml(mcauthCookie: string): Promise<string> {
  const resp = await fetch(`${BASE_URL}/dev/mail`, {
    headers: { Cookie: `mcauth=${mcauthCookie}` },
  });
  if (!resp.ok) throw new Error(`Mailcatcher inbox fetch failed: HTTP ${resp.status}`);
  return resp.text();
}

/**
 * Extracts email IDs and subjects from the inbox page HTML.
 * The mailcatcher renders a list of `<a href="/dev/mail/{id}">` links.
 */
function parseInboxLinks(html: string): Array<{ id: string; subject: string }> {
  const emails: Array<{ id: string; subject: string }> = [];
  // Match: <a href="/dev/mail/{id}">...</a>  (possibly with inner text containing the subject)
  const linkRe = /href="\/dev\/mail\/([a-zA-Z0-9_-]+)"[^>]*>([^<]*)<\/a>/g;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) !== null) {
    const id = m[1];
    const subject = m[2].trim();
    if (id && id !== 'clear' && id !== 'login') {
      emails.push({ id, subject });
    }
  }
  return emails;
}

/**
 * Fetches the full email detail page and extracts the plain-text body.
 */
export async function fetchEmailBody(mcauthCookie: string, emailId: string): Promise<string> {
  const resp = await fetch(`${BASE_URL}/dev/mail/${emailId}`, {
    headers: { Cookie: `mcauth=${mcauthCookie}` },
  });
  if (!resp.ok) throw new Error(`Mailcatcher email fetch failed: HTTP ${resp.status}`);
  return resp.text();
}

/**
 * Extracts the first URL from an email body (text or HTML).
 * Looks for the first https?:// link inside an <a href="..."> or as raw text.
 */
export function extractFirstLink(body: string): string | undefined {
  // Prefer href values first (they appear in the HTML-format email body)
  // Literal href attribute (plain-text body or unescaped rendering).
  const hrefMatch = /href="(https?:\/\/[^"]+)"/.exec(body);
  if (hrefMatch) return hrefMatch[1];
  // Entity-encoded href inside an srcdoc attribute (HTML body embedded via Askama).
  // The email HTML body is HTML-escaped into srcdoc="..." so href="..." becomes href=&quot;...&quot;.
  const encodedHrefMatch = /href=&quot;(https?:\/\/[^&]+)&quot;/.exec(body);
  if (encodedHrefMatch) return encodedHrefMatch[1];
  // Fallback: bare URL in plain-text body — skip w3.org namespace URIs from SVG elements.
  const urlRe = /(https?:\/\/\S+)/g;
  let urlMatch: RegExpExecArray | null;
  while ((urlMatch = urlRe.exec(body)) !== null) {
    if (!urlMatch[1].startsWith('http://www.w3.org/') && !urlMatch[1].startsWith('https://www.w3.org/')) {
      return urlMatch[1];
    }
  }
  return undefined;
}

/**
 * Waits for an email matching `predicate` to appear in the mailcatcher inbox.
 * Polls every 500 ms for up to `timeoutMs` milliseconds.
 */
export async function waitForEmail(
  mcauthCookie: string,
  predicate: (e: { id: string; subject: string }) => boolean,
  timeoutMs = 10_000,
): Promise<{ id: string; subject: string }> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const html = await fetchInboxHtml(mcauthCookie);
    const links = parseInboxLinks(html);
    const found = links.find(predicate);
    if (found) return found;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Timed out waiting for mailcatcher email after ${timeoutMs}ms`);
}

/**
 * Fetches an email's body and extracts the first link from it.
 */
export async function extractLinkFromEmail(
  mcauthCookie: string,
  emailId: string,
): Promise<string> {
  const body = await fetchEmailBody(mcauthCookie, emailId);
  const link = extractFirstLink(body);
  if (!link) throw new Error(`No URL found in email ${emailId}`);
  return link;
}

/**
 * Authenticates the Playwright page with the mailcatcher and navigates to /dev/mail.
 * Used when the test drives the mailcatcher UI via Playwright rather than fetch.
 */
export async function loginMailcatcherPage(page: Page): Promise<void> {
  await page.goto(`${BASE_URL}/dev/mail/login`);
  await page.fill('input[name="password"]', MC_PASSWORD);
  await Promise.all([
    page.waitForURL(/\/dev\/mail($|\?)/, { timeout: 10_000 }),
    page.click('button[type="submit"]'),
  ]);
}
