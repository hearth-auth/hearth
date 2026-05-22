import type { Page, Response } from '@playwright/test';

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
