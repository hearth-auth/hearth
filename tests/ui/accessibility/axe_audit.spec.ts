import * as fs from 'fs';
import * as path from 'path';
import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { AUTH_DIR } from '../helpers/actions';
import type { SeedFixtures } from '../fixtures/seed';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const REPORTS_DIR = path.join(__dirname, '..', 'reports');

function loadSeed(): SeedFixtures {
  const p = path.join(AUTH_DIR, 'seed.json');
  if (!fs.existsSync(p)) {
    throw new Error(`Seed not found at ${p}. Did globalSetup run?`);
  }
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as SeedFixtures;
}

/** Critical and serious violations block CI; moderate/minor are advisory. */
const BLOCKING_IMPACTS = new Set(['critical', 'serious']);

/**
 * Rules that block CI regardless of axe's impact rating.
 *
 * axe tags `skip-link`, `region`, and `landmark-one-main` as `best-practice`
 * with impact `moderate`, so `BLOCKING_IMPACTS` alone silently discards them
 * into a `console.warn` (see HEA-2074 Part C — this is exactly why the gate
 * passed with a broken skip link on every chromeless page). These are
 * structural landmark / skip-link guarantees we never want to regress, so we
 * promote them to blocking irrespective of impact. Generalising to a rule-id
 * set (rather than hard-coding this one bug) means future structural rules can
 * be promoted the same way.
 */
const BLOCKING_RULE_IDS = new Set(['skip-link', 'region', 'landmark-one-main']);

interface AxeViolation {
  id: string;
  impact?: string | null;
  description: string;
  nodes: unknown[];
}

function isBlocking(v: AxeViolation): boolean {
  return BLOCKING_IMPACTS.has(v.impact ?? '') || BLOCKING_RULE_IDS.has(v.id);
}

interface ViolationSummary {
  id: string;
  impact: string | null;
  description: string;
  nodes: number;
}

function summarize(v: AxeViolation): ViolationSummary {
  return { id: v.id, impact: v.impact ?? null, description: v.description, nodes: v.nodes.length };
}

function saveAxeReport(label: string, results: unknown): void {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  fs.writeFileSync(path.join(REPORTS_DIR, `axe-${label}.json`), JSON.stringify(results, null, 2));
}

/**
 * Bespoke label-binding check (HEA-2074 Part B.1).
 *
 * axe's `label` rule accepts a bare `placeholder` (and a `title`) as an
 * accessible name, so a placeholder-only `<input type="search">` passes axe
 * outright. We require a *real* accessible name derived ONLY from `aria-label`,
 * `aria-labelledby`, a wrapping `<label>`, or `label[for=id]` — placeholder and
 * title are explicitly excluded.
 */
async function assertControlsHaveAccessibleName(page: Page, label: string): Promise<void> {
  const offenders = await page.evaluate(() => {
    function hasAccessibleName(el: Element): boolean {
      const aria = el.getAttribute('aria-label');
      if (aria && aria.trim()) return true;

      const labelledby = el.getAttribute('aria-labelledby');
      if (labelledby) {
        const named = labelledby.split(/\s+/).some((id) => {
          const target = document.getElementById(id);
          return !!(target && target.textContent && target.textContent.trim());
        });
        if (named) return true;
      }

      const wrapping = el.closest('label');
      if (wrapping && wrapping.textContent && wrapping.textContent.trim()) return true;

      const id = (el as HTMLElement).id;
      if (id) {
        const escaped = window.CSS && CSS.escape ? CSS.escape(id) : id;
        const bound = document.querySelector(`label[for="${escaped}"]`);
        if (bound && bound.textContent && bound.textContent.trim()) return true;
      }
      return false;
    }

    const selector =
      'input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=reset]):not([type=image]), select, textarea';
    const bad: Array<Record<string, unknown>> = [];
    for (const el of Array.from(document.querySelectorAll(selector))) {
      if (!hasAccessibleName(el)) {
        bad.push({
          tag: el.tagName.toLowerCase(),
          type: el.getAttribute('type'),
          name: el.getAttribute('name'),
          id: (el as HTMLElement).id || null,
          html: el.outerHTML.slice(0, 200),
        });
      }
    }
    return bad;
  });

  expect(
    offenders,
    `Form controls without an accessible name (aria-label / aria-labelledby / <label> / label[for]; ` +
      `placeholder and title do NOT count) on ${label}`,
  ).toEqual([]);
}

/**
 * Bespoke `scope="col"` check (HEA-2074 Part B.2). axe has no rule for a
 * *missing* scope (`scope-attr-valid` only validates a scope that is present),
 * so we assert every column header carries `scope="col"` directly.
 */
async function assertColumnHeadersScoped(page: Page, label: string): Promise<void> {
  const offenders = await page.evaluate(() => {
    const bad: string[] = [];
    for (const th of Array.from(document.querySelectorAll('thead th'))) {
      if (th.getAttribute('scope') !== 'col') {
        bad.push(th.outerHTML.slice(0, 160));
      }
    }
    return bad;
  });

  expect(offenders, `<thead> <th> without scope="col" on ${label}`).toEqual([]);
}

/**
 * Skip-link-target check (HEA-2074 Part B.3). Asserts `#main` exists and is
 * focusable so the `<a href="#main">` skip link actually moves keyboard focus.
 */
async function assertMainLandmarkFocusable(page: Page, label: string): Promise<void> {
  const main = page.locator('#main');
  await expect(main, `#main landmark missing on ${label}`).toHaveCount(1);
  await main.focus();
  const focusedId = await page.evaluate(() => document.activeElement?.id ?? null);
  expect(focusedId, `#main is present but not focusable (skip link would not work) on ${label}`).toBe(
    'main',
  );
}

/** Navigate, run axe with the promoted blocking set, and run the bespoke checks. */
async function auditPage(page: Page, label: string, url: string): Promise<void> {
  await page.goto(url);
  await page.waitForLoadState('domcontentloaded');

  const results = await new AxeBuilder({ page }).analyze();
  const blocking = results.violations.filter(isBlocking);
  const advisory = results.violations.filter((v) => !isBlocking(v));

  if (advisory.length > 0) {
    console.warn(
      `[a11y:${label}] ${advisory.length} advisory (non-blocking) violation(s):`,
      advisory.map(summarize),
    );
  }

  saveAxeReport(label, results);

  await assertControlsHaveAccessibleName(page, label);
  await assertColumnHeadersScoped(page, label);

  expect(
    blocking.map(summarize),
    `Blocking a11y violations (critical/serious impact OR rule in {${[...BLOCKING_RULE_IDS].join(
      ', ',
    )}}) on ${label}`,
  ).toHaveLength(0);
}

// ── Authenticated admin pages ─────────────────────────────────────────────────

test.describe('Accessibility audit — admin sections', () => {
  // Widened beyond the original list/settings set: findings #1 (theme token on
  // CTAs / destructive buttons) and #5 (Redirect URIs label binding) live on
  // new/detail pages the gate never loaded (HEA-2074 Part B / Part C.4). URLs
  // are resolved lazily from the seed inside each test body (globalSetup must
  // have run first).
  const AUTHED_PAGES: Array<{ label: string; url: (s: SeedFixtures) => string }> = [
    // Dashboard — canonical *chromed* page (sidebar + <main id="main">).
    { label: 'admin-dashboard', url: () => `${BASE_URL}/ui` },
    // List pages.
    { label: 'admin-users', url: (s) => `${BASE_URL}/ui/admin/realms/${s.realmName}/users` },
    {
      label: 'admin-applications',
      url: (s) => `${BASE_URL}/ui/admin/realms/${s.realmName}/applications`,
    },
    { label: 'admin-groups', url: (s) => `${BASE_URL}/ui/admin/realms/${s.realmName}/groups` },
    {
      label: 'admin-organizations',
      url: (s) => `${BASE_URL}/ui/admin/realms/${s.realmName}/organizations`,
    },
    { label: 'admin-audit', url: (s) => `${BASE_URL}/ui/admin/realms/${s.realmName}/audit` },
    { label: 'admin-settings', url: () => `${BASE_URL}/ui/admin/settings` },
    // Widened coverage — new / detail pages.
    {
      label: 'admin-applications-new',
      url: (s) => `${BASE_URL}/ui/admin/realms/${s.realmName}/applications/new`,
    },
    {
      label: 'admin-applications-detail',
      url: (s) => `${BASE_URL}/ui/admin/realms/${s.realmName}/applications/${s.appClientId}`,
    },
    { label: 'admin-rbac-roles', url: (s) => `${BASE_URL}/ui/admin/realms/${s.realmName}/rbac/roles` },
    {
      label: 'admin-users-detail',
      url: (s) => `${BASE_URL}/ui/admin/realms/${s.realmName}/users/${s.userId}`,
    },
  ];

  for (const spec of AUTHED_PAGES) {
    test(`${spec.label} — no blocking a11y violations`, async ({ browser }) => {
      const seed = loadSeed();
      const context = await browser.newContext({
        storageState: path.join(AUTH_DIR, 'admin.json'),
      });
      const page = await context.newPage();
      try {
        await auditPage(page, spec.label, spec.url(seed));
      } finally {
        await context.close();
      }
    });
  }

  test('admin-dashboard — skip-link target is focusable (chromed branch)', async ({ browser }) => {
    const context = await browser.newContext({
      storageState: path.join(AUTH_DIR, 'admin.json'),
    });
    const page = await context.newPage();
    try {
      await page.goto(`${BASE_URL}/ui`);
      await page.waitForLoadState('domcontentloaded');
      await assertMainLandmarkFocusable(page, 'admin-dashboard (chromed)');
    } finally {
      await context.close();
    }
  });
});

// ── Public / pre-auth (chromeless) pages ──────────────────────────────────────

const PUBLIC_PAGES = [
  { label: 'admin-login', path: '/ui/admin/login' },
  { label: 'user-login', path: '/ui/login' },
] as const;

test.describe('Accessibility audit — public pages', () => {
  for (const { label, path: pagePath } of PUBLIC_PAGES) {
    test(`${label} — no blocking a11y violations`, async ({ page }) => {
      await auditPage(page, label, `${BASE_URL}${pagePath}`);
    });

    test(`${label} — skip-link target is focusable (chromeless branch)`, async ({ page }) => {
      await page.goto(`${BASE_URL}${pagePath}`);
      await page.waitForLoadState('domcontentloaded');
      await assertMainLandmarkFocusable(page, `${label} (chromeless)`);
    });
  }
});
