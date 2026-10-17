import type { BrowserContext, Page } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { test, expect } from './fixtures';
import { verifySidebar } from './sidebar';
import { freshTotp } from './totp';

// The tests share one vault: the first enrolls the administrator's authenticator, the next signs in with it.
test.describe.configure({ mode: 'serial' });
let authenticatorSecret = '';
let lastSignInStep = -1;
let administratorCookies: Awaited<ReturnType<BrowserContext['cookies']>> = [];

function adminPassword(): string {
  const password = process.env['Seed__AdminPassword'];
  if (!password) throw new Error('Run through npm run e2e with Seed__AdminPassword supplied');
  return password;
}

/** The enrolled administrator's ordinary sign-in, with a code from an authenticator step not used before. */
async function signIn(page: Page): Promise<void> {
  await page.goto('/Account/Login');
  await page.getByLabel('Username').fill('vault-admin');
  await page.getByLabel('Password', { exact: true }).fill(adminPassword());
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await expect(page).toHaveURL(/\/Account\/Totp$/);
  await page.getByLabel('Authenticator code').fill(await freshTotp(authenticatorSecret, lastSignInStep));
  lastSignInStep = Math.floor(Date.now() / 30_000);
  await page.getByRole('button', { name: 'Verify and sign in' }).click();
  await expect(page).toHaveURL(/\/Secrets$/);
}

/** The ids of the sessions Signed-in devices offers to sign out: every session but the current one. */
async function otherSessionIds(page: Page): Promise<string[]> {
  await page.goto('/Sessions');
  return page.locator('form input[name="id"]').evaluateAll((inputs) => inputs.map((input) => (input as HTMLInputElement).value));
}

test('sign in, lazy-load the Angular account with Trusted Types, visit Legacy UI and return', async ({ page, context, browserHealth }) => {
  const password = process.env['Seed__AdminPassword'];
  if (!password) throw new Error('Run through npm run e2e with Seed__AdminPassword supplied');

  await test.step('provision the production bootstrap administrator and enroll MFA', async () => {
    await page.goto('/Account/Login');
    await page.getByLabel('Username').fill('vault-admin');
    await page.getByLabel('Password', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await expect(page).toHaveURL(/\/Account\/EnrollTotp$/);
  });

  const secret = await page.locator('.secret-code').innerText();
  await page.getByLabel('Confirmation code').fill(await freshTotp(secret));
  const enrollmentStep = Math.floor(Date.now() / 30_000);
  await page.getByRole('button', { name: 'Confirm enrollment' }).click();
  await expect(page).toHaveURL(/\/Secrets$/);

  await test.step('sign out through the Angular account menu, which ends the session on the server', async () => {
    const enrolled = (await context.cookies()).find((cookie) => cookie.name === 'EclipsVault.Session');
    if (!enrolled) throw new Error('Enrollment created no session cookie');
    // Another browser holding a copy of this session signs out; this one keeps its copy to replay.
    const other = await browserHealth.newContext();
    await other.addCookies([enrolled]);
    const angular = await other.newPage();
    await angular.goto('/Access');
    await expect(angular.locator('dd')).toHaveText(['Vault Administrator', 'vault-admin', 'Top Secret', 'GLOBAL']);

    const xsrf = (await other.cookies()).find((cookie) => cookie.name === 'XSRF-TOKEN');
    expect(xsrf).toMatchObject({ secure: true, httpOnly: false, sameSite: 'Strict', path: '/' });
    expect(xsrf?.value).not.toBe(enrolled.value);

    await angular.locator('summary.user-card').click();
    const signOut = angular.waitForRequest((request) =>
      request.method() === 'POST' && new URL(request.url()).pathname === '/Account/Logout');
    await angular.getByRole('menuitem', { name: 'Sign out', exact: true }).click();
    expect((await signOut).headers()['requestverificationtoken']).toBe(xsrf?.value);
    await expect(angular).toHaveURL(/\/Account\/Login$/);
    await expect(angular.getByLabel('Username')).toBeVisible();
    expect((await other.cookies()).some((cookie) => cookie.name === 'EclipsVault.Session')).toBe(false);

    const replayed = await page.request.get('/api/ui/me');
    expect(replayed.status()).toBe(401);
    expect(replayed.headers()['content-type']).toBe('application/problem+json');
  });

  // Exercise an enrolled account's ordinary two-factor sign-in.
  await page.goto('/Account/Login');
  await page.getByLabel('Username').fill('vault-admin');
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await expect(page).toHaveURL(/\/Account\/Totp$/);
  await page.getByLabel('Authenticator code').fill(await freshTotp(secret, enrollmentStep));
  authenticatorSecret = secret;
  lastSignInStep = Math.floor(Date.now() / 30_000);
  await page.getByRole('button', { name: 'Verify and sign in' }).click();
  await expect(page).toHaveURL(/\/Secrets$/);

  const signInRequests: string[] = [];
  page.on('request', (request) => {
    if (/\/Account\/(Login|Totp|EnrollTotp)/i.test(new URL(request.url()).pathname)) {
      signInRequests.push(request.url());
    }
  });
  const session = (await context.cookies()).find((cookie) => cookie.name === 'EclipsVault.Session');
  expect(session?.secure).toBe(true);
  expect(session?.httpOnly).toBe(true);

  // The account component is a dynamic import, not part of main.js. Observe its actual chunk load.
  const lazyAccount = page.waitForResponse(async (response) =>
    /\/ui\/chunk-[\w-]+\.js$/.test(response.url()) && (await response.text()).includes('Signed in'));
  const angularDocument = await page.goto('/Access');
  expect(angularDocument?.headers()['content-security-policy']).toContain(
    "; require-trusted-types-for 'script'; trusted-types angular angular#bundler",
  );
  expect((await lazyAccount).status()).toBe(200);
  await expect(page.getByRole('heading', { name: 'Signed in', exact: true })).toBeVisible();
  await expect(page.locator('dd')).toHaveText(['Vault Administrator', 'vault-admin', 'Top Secret', 'GLOBAL']);

  await page.goto('/Access/Index');
  await expect(page.getByRole('heading', { name: 'Signed in', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Refresh' }).click();
  await expect(page.locator('dd')).toHaveText(['Vault Administrator', 'vault-admin', 'Top Secret', 'GLOBAL']);

  await test.step('Trusted Types rejects a raw DOM assignment before it changes the DOM', async () => {
    // One precise, required violation is intentional; the shared fixture still rejects every other one.
    browserHealth.expectCspViolation({
      effectiveDirective: 'require-trusted-types-for',
      blockedURI: 'trusted-types-sink',
      sample: 'Element innerHTML|<p>tt-unsafe-assignment</p>',
      documentURI: page.url(),
      disposition: 'enforce',
    });
    browserHealth.expectConsoleError({
      text: /^This document requires 'TrustedHTML' assignment\. The action has been blocked\.$/,
      // Chromium attributes this browser-generated rejection to no source URL.
      url: /^$/,
    });
    const result = await page.evaluate(async () => {
      const target = document.createElement('div');
      target.textContent = 'safe original';
      document.body.append(target);
      const violation = new Promise<SecurityPolicyViolationEvent>((resolve) => {
        document.addEventListener('securitypolicyviolation', resolve, { once: true });
      });
      let threwTypeError = false;
      try {
        target.innerHTML = '<p>tt-unsafe-assignment</p>';
      } catch (error) {
        threwTypeError = error instanceof TypeError;
      }
      const event = await violation;
      const evidence = {
        threwTypeError,
        html: target.innerHTML,
        directive: event.effectiveDirective,
        disposition: event.disposition,
      };
      target.remove();
      return evidence;
    });
    expect(result).toEqual({
      threwTypeError: true,
      html: 'safe original',
      directive: 'require-trusted-types-for',
      disposition: 'enforce',
    });
  });

  const legacyDocument = page.waitForResponse((response) => response.request().isNavigationRequest());
  await page.getByRole('link', { name: 'Secrets', exact: true }).click();
  expect((await legacyDocument).headers()['content-security-policy']).not.toContain('trusted-types');
  await expect(page).toHaveURL(/\/Secrets$/);
  await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();
  await expect(page.locator('.sidebar')).toContainText('Vault Administrator');
  await page.getByText('Access', { exact: true }).click();
  await page.getByRole('link', { name: 'My access', exact: true }).click();
  await expect(page).toHaveURL(/\/Access$/);
  await expect(page.locator('dd')).toHaveText(['Vault Administrator', 'vault-admin', 'Top Secret', 'GLOBAL']);
  expect(signInRequests).toEqual([]);
  expect((await context.cookies()).find((cookie) => cookie.name === 'EclipsVault.Session')?.value).toBe(session?.value);
  administratorCookies = await context.cookies();
});

test('the administrator and Standard sidebars match Legacy in both themes and navigate across UIs', async ({ page, browserHealth }, info) => {
  test.setTimeout(180_000);
  // Reuse the real session established above. Extra sign-ins would exhaust the production per-IP
  // password budget before the revocation test; the limiter stays fully enabled.
  await page.context().addCookies(administratorCookies);
  await page.goto('/Access');
  await test.step('administrator navigation and visual comparison', async () => {
    await verifySidebar(page, info, 'administrator');
  });

  const username = 'e2e-standard-sidebar';
  const password = `E2e-${randomBytes(24).toString('hex')}`;
  await test.step('provision a Standard account through the administrator UI', async () => {
    await page.goto('/Admin/CreateUser');
    await page.getByLabel('First name').fill('Standard');
    await page.getByLabel('Last name').fill('Sidebar');
    await page.getByLabel('Username').fill(username);
    await page.getByLabel('Initial password', { exact: true }).fill(password);
    await page.getByLabel('Clearance').selectOption({ label: 'Standard' });
    await page.getByLabel('Project').fill('GLOBAL');
    await page.getByRole('button', { name: 'Create user', exact: true }).click();
    await expect(page).toHaveURL(/\/Admin\/Users$/);
  });

  const standard = await (await browserHealth.newContext()).newPage();
  await test.step('Standard account signs in with its own password and enrolls MFA', async () => {
    await standard.goto('/Account/Login');
    await standard.getByLabel('Username').fill(username);
    await standard.getByLabel('Password', { exact: true }).fill(password);
    await standard.getByRole('button', { name: 'Continue', exact: true }).click();
    await expect(standard).toHaveURL(/\/Account\/EnrollTotp$/);
    await standard.getByLabel('Confirmation code').fill(await freshTotp(await standard.locator('.secret-code').innerText()));
    await standard.getByRole('button', { name: 'Confirm enrollment' }).click();
    await expect(standard).toHaveURL(/\/Secrets$/);
  });
  await test.step('Standard navigation and visual comparison', async () => {
    await verifySidebar(standard, info, 'standard');
  });
});

test('both UIs share the theme, and the Angular UI applies it before it starts', async ({ page }) => {
  await page.context().addCookies(administratorCookies);
  await page.goto('/Secrets');
  await page.context().addCookies([{ name: 'EclipsVault.Theme', value: 'dark', url: new URL('/', page.url()).href, secure: true }]);
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');

  await test.step('switched in the Legacy UI, the theme is on the Angular document before Angular runs', async () => {
    await page.locator('summary.user-card').click();
    await page.getByRole('menuitem', { name: 'Switch to light', exact: true }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');

    // Hold the application bundle, so only the external boot script can have set the theme.
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => (release = resolve));
    const bundle = /\/ui\/main-[\w-]+\.js$/;
    await page.route(bundle, async (route) => {
      await held;
      await route.continue();
    });
    await page.goto('/Access', { waitUntil: 'commit' });
    await page.waitForFunction(() => document.documentElement.hasAttribute('data-theme'));
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await expect(page.locator('app-root')).toBeEmpty();
    release();
    await expect(page.getByRole('heading', { name: 'Signed in', exact: true })).toBeVisible();
    await page.unroute(bundle);
  });

  await test.step('switched in the Angular UI, the theme reaches the Legacy UI', async () => {
    await page.locator('summary.user-card').click();
    await page.getByRole('menuitem', { name: 'Switch to dark', exact: true }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    expect((await page.context().cookies()).find((cookie) => cookie.name === 'EclipsVault.Theme')?.value).toBe('dark');
    await page.goto('/Secrets');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  });
});

test('a session revoked from another browser is sent to sign-in on its next UI API action', async ({ page, browserHealth }) => {
  // Two sign-ins, each of which may wait for a new authenticator step.
  test.setTimeout(150_000);
  if (!authenticatorSecret) throw new Error('Runs after the sign-in test, which enrolls the authenticator');

  // Every session but the first browser's, as Signed-in devices shows them to it.
  let othersOfFirst: string[] = [];
  await test.step('the first browser signs in and opens the Angular UI', async () => {
    await signIn(page);
    othersOfFirst = await otherSessionIds(page);
    await page.goto('/Access');
    await expect(page.locator('dd')).toHaveText(['Vault Administrator', 'vault-admin', 'Top Secret', 'GLOBAL']);
  });

  const second = await (await browserHealth.newContext()).newPage();
  await test.step("a second browser signs the first browser's session out from Signed-in devices", async () => {
    await signIn(second);
    const first = (await otherSessionIds(second)).filter((id) => !othersOfFirst.includes(id));
    expect(first).toHaveLength(1);
    await second.locator(`form:has(input[name="id"][value="${first[0]}"])`).getByRole('button', { name: 'Sign out' }).click();
    await second.getByRole('alertdialog').getByRole('button', { name: 'Continue' }).click();
    await expect(second.getByText('That session was signed out')).toBeVisible();
  });

  await test.step("the first browser's next UI API action sends it to sign-in, returning to My access", async () => {
    // The browser logs the refused request as a console error; that one error is the point of this step.
    browserHealth.expectConsoleError({ text: /status of 401/, url: /\/api\/ui\/me$/ });
    const refused = page.waitForResponse((response) => new URL(response.url()).pathname === '/api/ui/me');
    await page.getByRole('button', { name: 'Refresh' }).click();
    const response = await refused;
    expect(response.status()).toBe(401);
    expect(response.headers()['content-type']).toBe('application/problem+json');
    expect(response.headers()['cache-control']).toContain('no-store');
    await expect(page).toHaveURL(/\/Account\/Login\?ReturnUrl=%2FAccess$/);
    await expect(page.getByLabel('Username')).toBeVisible();
  });

  await test.step('the production image serves none of the integration tests\' test-only endpoints', async () => {
    // Signed in, so a missing endpoint answers 404 rather than asking for a session.
    expect((await second.request.get('/api/ui/test-only/throw/unhandled')).status()).toBe(404);
    expect((await second.request.get('/test-only/throw/unhandled')).status()).toBe(404);
  });
});
