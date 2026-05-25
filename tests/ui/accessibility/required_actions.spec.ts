// Axe-core accessibility audit for the required-action interstitial pages (HEA-765 / HEA-766).
//
// Each page has a distinct token requirement that shapes how the test obtains a URL:
//
//   update-password   — realm_id_from_ra_token only (no Ed25519 sig check): craft a minimal JWT
//   verify-email      — validate_required_action_token (full sig check): drive real login flow
//   verify-email/success — no token; only optional redirect_url query param

import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { loadCredentials } from '../helpers/actions';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const REPORTS_DIR = path.join(__dirname, '..', 'reports');

const BLOCKING_IMPACTS = new Set(['critical', 'serious']);

// Dev-realm user created by the dev bootstrap — has a known password.
const DEV_REALM_USER_EMAIL = 'admin@dev.local';
const DEV_REALM_USER_PASSWORD = 'HearthDev123!';

interface ViolationSummary {
  id: string;
  impact: string | null;
  description: string;
  nodes: number;
}

function summarize(v: {
  id: string;
  impact?: string | null;
  description: string;
  nodes: unknown[];
}): ViolationSummary {
  return { id: v.id, impact: v.impact ?? null, description: v.description, nodes: v.nodes.length };
}

function saveAxeReport(label: string, results: unknown): void {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  fs.writeFileSync(path.join(REPORTS_DIR, `axe-${label}.json`), JSON.stringify(results, null, 2));
}

// Craft a minimal JWT that passes realm_id_from_ra_token without triggering
// full Ed25519 signature verification.  The update-password GET handler only
// calls decode_claims_unverified to extract the realm ID — the signature is
// never checked at render time, so any structurally valid JWT with the correct
// `tid` claim renders the form.
function craftMinimalRaToken(realmId: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      tid: `realm_${realmId}`,
      sub: 'user_00000000-0000-0000-0000-000000000001',
      sid: 'session_00000000-0000-0000-0000-000000000001',
      required_actions: ['UPDATE_PASSWORD'],
      token_type: 'required_action',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    }),
  ).toString('base64url');
  // Signature is never verified for the GET endpoint; any base64url value works.
  const sig = Buffer.from('placeholder').toString('base64url');
  return `${header}.${payload}.${sig}`;
}

async function adminFetch(urlPath: string, method: string, body?: unknown): Promise<Response> {
  const creds = loadCredentials();
  return fetch(`${BASE_URL}${urlPath}`, {
    method,
    headers: {
      Authorization: `Bearer ${creds.access_token}`,
      'X-Realm-ID': creds.realm_id,
      'Content-Type': 'application/json',
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

function devRealmUserId(): string {
  // The bootstrap response includes user_id (the dev-realm admin) directly.
  // No additional search needed — use it straight from credentials.json.
  return loadCredentials().user_id;
}

test.describe('Accessibility audit — required-action interstitials', () => {
  test('update-password — no critical/serious violations', async ({ page }) => {
    const creds = loadCredentials();
    // update-password renders purely from structural JWT validity — no sig check.
    const raToken = craftMinimalRaToken(creds.realm_id);

    await page.goto(
      `${BASE_URL}/ui/required-actions/update-password?ra_token=${encodeURIComponent(raToken)}`,
    );
    await page.waitForLoadState('domcontentloaded');

    const results = await new AxeBuilder({ page }).analyze();
    const blocking = results.violations.filter((v) => BLOCKING_IMPACTS.has(v.impact ?? ''));
    const advisory = results.violations.filter((v) => !BLOCKING_IMPACTS.has(v.impact ?? ''));

    if (advisory.length > 0) {
      console.warn(
        `[a11y:required-actions/update-password] ${advisory.length} advisory violation(s):`,
        advisory.map(summarize),
      );
    }

    saveAxeReport('required-actions-update-password', results);
    expect(
      blocking.map(summarize),
      'Critical/serious a11y violations on /ui/required-actions/update-password',
    ).toHaveLength(0);
  });

  test('verify-email — no critical/serious violations', async ({ page }) => {
    // verify-email validates the full Ed25519 signature.  We obtain a real token
    // via the OAuth ROPC password grant (POST /realms/dev-realm/token), which
    // calls issue_required_action_jwt when the user has pending required actions.
    // The web login form does NOT issue ra_tokens — it creates a session cookie
    // and redirects to /ui, bypassing the required-action check entirely.
    const userId = devRealmUserId();

    // Register a run-unique OAuth client so parallel/repeated runs don't 409.
    const clientName = `ra-axe-test-${Date.now()}`;
    const clientResp = await adminFetch('/admin/applications', 'POST', {
      client_name: clientName,
      redirect_uris: ['https://example.com/callback'],
      grant_types: ['password'],
    });
    if (!clientResp.ok) {
      const errText = await clientResp.text().catch(() => '(unreadable)');
      console.error(`[verify-email] client creation failed ${clientResp.status}: ${errText}`);
      test.skip();
      return;
    }
    const clientData = (await clientResp.json()) as {
      client_id: string;
      client_secret?: string;
    };
    const clientId = clientData.client_id;

    let raToken = '';
    try {
      // Add VERIFY_EMAIL required action — idempotent.
      const addResp = await adminFetch(`/admin/users/${userId}/required-actions`, 'POST', {
        action: 'VERIFY_EMAIL',
      });
      if (!addResp.ok) {
        const errText = await addResp.text().catch(() => '(unreadable)');
        console.error(`[verify-email] add required action failed ${addResp.status}: ${errText}`);
        test.skip();
        return;
      }

      // ROPC grant: with VERIFY_EMAIL pending, the response access_token is the ra_token.
      // Hearth's token endpoint uses Json<> extraction, so Content-Type must be application/json.
      const tokenResp = await fetch(`${BASE_URL}/realms/dev-realm/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant_type: 'password',
          username: DEV_REALM_USER_EMAIL,
          password: DEV_REALM_USER_PASSWORD,
          client_id: clientId,
        }),
      });
      if (!tokenResp.ok) {
        const errText = await tokenResp.text().catch(() => '(unreadable)');
        console.error(`[verify-email] ROPC token failed ${tokenResp.status}: ${errText}`);
        test.skip();
        return;
      }
      const tokenData = (await tokenResp.json()) as { access_token: string };
      raToken = tokenData.access_token ?? '';
    } finally {
      // Always clean up required action and test client regardless of path taken.
      await adminFetch(`/admin/users/${userId}/required-actions/VERIFY_EMAIL`, 'DELETE');
      await adminFetch(`/admin/applications/${clientId}`, 'DELETE');
    }

    if (!raToken) {
      test.skip();
      return;
    }

    await page.goto(
      `${BASE_URL}/ui/required-actions/verify-email?ra_token=${encodeURIComponent(raToken)}`,
    );
    await page.waitForLoadState('domcontentloaded');

    const results = await new AxeBuilder({ page }).analyze();
    const blocking = results.violations.filter((v) => BLOCKING_IMPACTS.has(v.impact ?? ''));
    const advisory = results.violations.filter((v) => !BLOCKING_IMPACTS.has(v.impact ?? ''));

    if (advisory.length > 0) {
      console.warn(
        `[a11y:required-actions/verify-email] ${advisory.length} advisory violation(s):`,
        advisory.map(summarize),
      );
    }

    saveAxeReport('required-actions-verify-email', results);
    expect(
      blocking.map(summarize),
      'Critical/serious a11y violations on /ui/required-actions/verify-email',
    ).toHaveLength(0);
  });

  test('verify-email/success — no critical/serious violations', async ({ page }) => {
    // verify-email/success accepts only an optional redirect_url param — no token needed.
    await page.goto(
      `${BASE_URL}/ui/required-actions/verify-email/success?redirect_url=${encodeURIComponent('/ui/login')}`,
    );
    await page.waitForLoadState('domcontentloaded');

    const results = await new AxeBuilder({ page }).analyze();
    const blocking = results.violations.filter((v) => BLOCKING_IMPACTS.has(v.impact ?? ''));
    const advisory = results.violations.filter((v) => !BLOCKING_IMPACTS.has(v.impact ?? ''));

    if (advisory.length > 0) {
      console.warn(
        `[a11y:required-actions/verify-email/success] ${advisory.length} advisory violation(s):`,
        advisory.map(summarize),
      );
    }

    saveAxeReport('required-actions-verify-email-success', results);
    expect(
      blocking.map(summarize),
      'Critical/serious a11y violations on /ui/required-actions/verify-email/success',
    ).toHaveLength(0);
  });
});
