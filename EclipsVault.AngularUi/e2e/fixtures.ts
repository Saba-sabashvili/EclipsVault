import { test as base, expect, type BrowserContext } from '@playwright/test';

declare global {
  interface Window {
    reportCspViolation: (details: string) => Promise<void>;
  }
}

/** A console error a test causes on purpose, such as the browser logging an expected 401. */
interface ExpectedConsoleError {
  text: RegExp;
  url: RegExp;
}

export interface BrowserHealth {
  /**
   * Excuses console errors matching both `text` and the URL they are logged for. Nothing else is
   * excused, and the test fails if no such error occurs.
   */
  expectConsoleError(expected: ExpectedConsoleError): void;
  /** Another browser context (another browser, in effect), held to the same checks and closed after the test. */
  newContext(): Promise<BrowserContext>;
}

// Every spec imports this test. Install before the first document, and keep collecting through
// navigations and popups. Assertions in teardown make even an otherwise passing test fail.
export const test = base.extend<{ browserHealth: BrowserHealth }>({
  browserHealth: [async ({ browser, context }, use) => {
    const problems: string[] = [];
    const expected: (ExpectedConsoleError & { seen: boolean })[] = [];
    const others: BrowserContext[] = [];

    async function watch(watched: BrowserContext) {
      watched.on('console', (message) => {
        if (message.type() !== 'error') return;
        const excuse = expected.find((e) => e.text.test(message.text()) && e.url.test(message.location().url));
        if (excuse) {
          excuse.seen = true;
        } else {
          problems.push(`console.error: ${message.text()}`);
        }
      });
      watched.on('weberror', (error) => problems.push(`pageerror: ${error.error().message}`));
      await watched.exposeBinding('reportCspViolation', (_source, details: string) => {
        problems.push(`CSP violation: ${details}`);
      });
      await watched.addInitScript(() => {
        document.addEventListener('securitypolicyviolation', (event) => {
          void window.reportCspViolation(`${event.effectiveDirective}: ${event.blockedURI}`);
        });
      });
    }

    await watch(context);
    await use({
      expectConsoleError: (error) => expected.push({ ...error, seen: false }),
      newContext: async () => {
        const other = await browser.newContext();
        others.push(other);
        await watch(other);
        return other;
      },
    });

    for (const other of others) await other.close();
    expect.soft(problems, '[browser-health] CSP violations and browser errors').toEqual([]);
    expect.soft(
      expected.filter((e) => !e.seen).map((e) => `${e.text} at ${e.url}`),
      '[browser-health] expected console errors that never occurred',
    ).toEqual([]);
  }, { auto: true }],
});

export { expect };
