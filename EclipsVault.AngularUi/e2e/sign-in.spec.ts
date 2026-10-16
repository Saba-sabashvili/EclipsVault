import { test, expect } from './fixtures';
import { freshTotp } from './totp';

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
