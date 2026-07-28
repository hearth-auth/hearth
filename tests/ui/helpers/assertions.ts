import type { BrowserContext, Page, Response } from '@playwright/test';

export interface ConsoleErrorCollector {
  readonly errors: string[];
}

/**
 * Attaches a console-error listener to the page before navigation.
 * Returns the collector; call assertNoConsoleErrors(collector, page.url()) after.
 */
export function attachConsoleErrorCollector(page: Page): ConsoleErrorCollector {
  const collector: ConsoleErrorCollector = { errors: [] };
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      (collector.errors as string[]).push(msg.text());
    }
  });
  return collector;
}

export function assertNoConsoleErrors(
  collector: ConsoleErrorCollector,
  url: string,
): void {
  if (collector.errors.length > 0) {
    throw new Error(
      `Console errors on ${url}:\n${collector.errors.join('\n')}`,
    );
  }
}

export function assertNoFailedRequests(
  responses: Response[],
  url: string,
): void {
  const failures = responses.filter(
    (r) =>
      r.status() >= 500 &&
      // Metrics endpoint may temporarily return 503 during boot — skip
      !r.url().endsWith('/metrics'),
  );
  if (failures.length > 0) {
    throw new Error(
      `Failed requests on ${url}:\n` +
        failures.map((r) => `  HTTP ${r.status()} ${r.url()}`).join('\n'),
    );
  }
}

interface PageDiagnostics {
  errors: string[];
  responses: Response[];
}

// Per-page diagnostics, keyed by the Page object so beforeEach/afterEach (or a
// manual attach/assert pair) can share the same collector without threading a
// variable through the test body. WeakMap lets closed pages be GC'd.
const diagnostics = new WeakMap<Page, PageDiagnostics>();

/**
 * Instruments a page to collect console errors and every HTTP response.
 * Call once per page (e.g. in `beforeEach` or right after `newPage()`), then
 * call {@link assertPageClean} before the test ends to fail on JS errors or 5xx.
 */
export function instrumentPage(page: Page): void {
  const collector: PageDiagnostics = { errors: [], responses: [] };
  page.on('console', (msg) => {
    if (msg.type() === 'error') collector.errors.push(msg.text());
  });
  page.on('response', (r) => collector.responses.push(r));
  diagnostics.set(page, collector);
}

/**
 * Creates a new page in `ctx` and instruments it in one step. Convenience for
 * specs that build their own contexts (so they can't use a `beforeEach` hook on
 * the shared fixture page). Pair with {@link assertPageClean} before closing.
 */
export async function newInstrumentedPage(ctx: BrowserContext): Promise<Page> {
  const page = await ctx.newPage();
  instrumentPage(page);
  return page;
}

/**
 * Asserts the page saw no console errors and no failed (5xx) requests since
 * {@link instrumentPage} was called. No-op if the page was never instrumented.
 */
export function assertPageClean(page: Page): void {
  const collector = diagnostics.get(page);
  if (!collector) return;
  const url = page.url();
  assertNoConsoleErrors({ errors: collector.errors }, url);
  assertNoFailedRequests(collector.responses, url);
}

export async function assertPageNonEmpty(page: Page): Promise<void> {
  const text = (await page.evaluate(
    () => document.body?.innerText?.trim() ?? '',
  )) as string;
  if (text.length < 10) {
    throw new Error(
      `Page appears empty (${text.length} chars) at ${page.url()}`,
    );
  }
}
