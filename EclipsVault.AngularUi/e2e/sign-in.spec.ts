import type { Page } from '@playwright/test';
import { test, expect } from './fixtures';
import { freshTotp } from './totp';

// The tests share one vault: the first enrolls the administrator's authenticator, the next signs in with it.
test.describe.configure({ mode: 'serial' });
let authenticatorSecret = '';
let lastSignInStep = -1;

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

test('sign in, see the Angular account, visit Legacy UI and return with the same session', async ({ page, context }) => {
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

  // Sign out through the vault, then exercise an enrolled account's ordinary two-factor sign-in.
  await page.locator('summary.user-card').click();
  await page.getByRole('menuitem', { name: 'Sign out', exact: true }).click();
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

  await page.goto('/Access');
  await expect(page.getByRole('heading', { name: 'Signed in', exact: true })).toBeVisible();
  await expect(page.locator('dd')).toHaveText(['Vault Administrator', 'vault-admin', 'Top Secret', 'GLOBAL']);

  // /Secrets is still served by MVC. Direct navigation exercises the same-origin handoff before
  // the Angular shell's navigation arrives in a later migration ticket.
  await page.goto('/Secrets');
  await expect(page).toHaveURL(/\/Secrets$/);
  await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();
  await expect(page.locator('.sidebar')).toContainText('Vault Administrator');
  await page.getByText('Access', { exact: true }).click();
  await page.getByRole('link', { name: 'My access', exact: true }).click();
  await expect(page).toHaveURL(/\/Access$/);
  await expect(page.locator('dd')).toHaveText(['Vault Administrator', 'vault-admin', 'Top Secret', 'GLOBAL']);
  expect(signInRequests).toEqual([]);
  expect((await context.cookies()).find((cookie) => cookie.name === 'EclipsVault.Session')?.value).toBe(session?.value);
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
