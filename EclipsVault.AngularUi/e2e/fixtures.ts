import { test as base, expect } from '@playwright/test';

declare global {
  interface Window {
    reportCspViolation: (details: string) => Promise<void>;
  }
}

// Every spec imports this test. Install before the first document, and keep collecting through
// navigations and popups. Assertions in teardown make even an otherwise passing test fail.
export const test = base.extend<{ browserHealth: void }>({
  browserHealth: [async ({ context }, use) => {
    const problems: string[] = [];
    context.on('console', (message) => {
      if (message.type() === 'error') {
        problems.push(`console.error: ${message.text()}`);
      }
    });
    context.on('weberror', (error) => problems.push(`pageerror: ${error.error().message}`));
    await context.exposeBinding('reportCspViolation', (_source, details: string) => {
      problems.push(`CSP violation: ${details}`);
    });
    await context.addInitScript(() => {
      document.addEventListener('securitypolicyviolation', (event) => {
        void window.reportCspViolation(`${event.effectiveDirective}: ${event.blockedURI}`);
      });
    });

    await use();

    expect(problems, '[browser-health] CSP violations and browser errors').toEqual([]);
  }, { auto: true }],
});

export { expect };
