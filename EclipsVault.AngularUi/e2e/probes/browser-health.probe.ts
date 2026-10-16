import { test, expect } from '../fixtures';

// Intentionally failing tests, run only by e2e:verify-guards. The driver checks that each failed
// specifically in the shared browser-health fixture, rather than accepting any nonzero exit.
test('CSP violation', async ({ page }) => {
  await page.goto('/Account/Login');
  await page.evaluate(() => new Promise<void>((resolve) => {
    document.addEventListener('securitypolicyviolation', () => resolve(), { once: true });
    const script = document.createElement('script');
    script.textContent = 'window.inlineScriptRan = true';
    document.body.append(script);
  }));
  await expect.poll(() => page.evaluate(() => 'inlineScriptRan' in window)).toBe(false);
});

test('console.error after navigation in a second page', async ({ context, page }) => {
  await page.goto('/Account/Login');
  const other = await context.newPage();
  await other.goto('/Account/Login');
  await other.evaluate(() => console.error('e2e console sentinel'));
  await other.close();
});

test('uncaught browser exception', async ({ page }) => {
  await page.goto('/Account/Login');
  const error = page.waitForEvent('pageerror');
  await page.evaluate(() => {
    setTimeout(() => { throw new Error('e2e exception sentinel'); }, 0);
  });
  await error;
});
