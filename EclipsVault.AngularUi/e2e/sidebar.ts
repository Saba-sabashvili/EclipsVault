import type { Page, TestInfo } from '@playwright/test';
import { expect } from './fixtures';

/** Observable navigation, including the exact SVG geometry and styles a person sees. */
async function navigation(page: Page) {
  return page.locator('.sidenav').evaluate((nav) => ({
    sections: [...nav.querySelectorAll('.nav-section')].map((section) => section.textContent?.trim()),
    items: [...nav.querySelectorAll('a, summary')].map((item) => {
      const style = getComputedStyle(item);
      return {
        label: item.textContent?.trim(),
        url: item.getAttribute('href'),
        active: item.classList.contains('active'),
        groupActive: item.classList.contains('has-active'),
        icon: [...item.querySelector('svg')!.children].map((shape) => ({
          tag: shape.tagName,
          attributes: [...shape.attributes].map((attribute) => [attribute.name, attribute.value]),
        })),
        style: [style.color, style.backgroundColor, style.fontFamily, style.fontSize, style.fontWeight,
          style.padding, style.gap, style.borderRadius],
      };
    }),
    groups: [...nav.querySelectorAll('details')].map((group) => group.open),
  }));
}

/** Crop to navigation content; account menu and palette are intentionally separate tickets. */
async function screenshot(page: Page, info: TestInfo, name: string) {
  await page.evaluate(() => document.fonts.ready);
  const clip = await page.locator('.sidenav').evaluate((nav) => {
    const bounds = nav.getBoundingClientRect();
    const last = nav.lastElementChild!.getBoundingClientRect();
    return { x: bounds.x, y: bounds.y, width: bounds.width, height: last.bottom - bounds.y };
  });
  const path = info.outputPath(`${name}.png`);
  await page.screenshot({ path, clip });
  await info.attach(name, { path, contentType: 'image/png' });
}

/** Compare the two real UIs on the same session, in each theme, and then use their links to cross over. */
export async function verifySidebar(page: Page, info: TestInfo, account: 'administrator' | 'standard') {
  await page.setViewportSize({ width: 1440, height: 1200 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const session = (await page.context().cookies()).find((cookie) => cookie.name === 'EclipsVault.Session');
  expect(session).toBeDefined();

  for (const theme of ['dark', 'light']) {
    await page.context().addCookies([{ name: 'EclipsVault.Theme', value: theme, url: new URL('/', page.url()).href, secure: true }]);
    // Until #52 removes the Razor tracer, MVC's ordinary optional-id route lets us compare the
    // same active page without adding a test-only production endpoint or bypassing authorization.
    const legacy = await page.goto('/Access/Index/legacy');
    expect(legacy?.headers()['content-security-policy']).not.toContain('trusted-types');
    await expect(page.locator('.sidenav a.active')).toHaveText('My access');
    await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
    const reference = await navigation(page);
    // Razor's tag helper retains this reference route's ambient optional id on its own link.
    // Assert that one known alias, then compare it as the canonical Angular-owned destination.
    const access = reference.items.find((item) => item.label === 'My access');
    expect(access?.url).toBe('/Access/Index/legacy');
    if (access) access.url = '/Access';
    await screenshot(page, info, `${account}-${theme}-legacy`);

    const angular = await page.goto('/aCcEsS/INDEX');
    expect(angular?.headers()['content-security-policy']).toContain("require-trusted-types-for 'script'");
    await expect(page.getByRole('heading', { name: 'Signed in', exact: true })).toBeVisible();
    // Theme boot and switching belong to #50. Exercise both ported token sets without implementing
    // that account-menu feature here. No style injection or sanitization bypass is involved.
    await page.evaluate((value) => { document.documentElement.dataset['theme'] = value; }, theme);
    await expect(page.locator('.sidenav a.active')).toHaveAttribute('aria-current', 'page');
    expect(await navigation(page)).toEqual(reference);
    if (account === 'standard') {
      await expect(page.locator('.sidenav')).not.toContainText('Administration');
      await expect(page.locator('.sidenav a')).toHaveCount(13);
      await expect(page.locator('a[href^="/Admin"], a[href="/ServiceAccounts"], a[href="/Audit"], a[href="/Notifications"], a[href="/Encryption"], a[href="/License"]')).toHaveCount(0);
    } else {
      await expect(page.locator('.sidenav .nav-section')).toHaveText(['Vault', 'Account', 'Administration']);
      await expect(page.locator('.sidenav a')).toHaveCount(20);
    }
    await expect(page.locator('style, [style]')).toHaveCount(0);
    await screenshot(page, info, `${account}-${theme}-angular`);
  }

  const signInRequests: string[] = [];
  const documents: string[] = [];
  page.on('request', (request) => {
    if (/\/Account\/(Login|Totp|EnrollTotp)/i.test(new URL(request.url()).pathname)) signInRequests.push(request.url());
    if (request.isNavigationRequest() && request.resourceType() === 'document') documents.push(request.url());
  });

  // Angular-owned links keep the document; aliases still mark My access and its parent active.
  await page.getByRole('link', { name: 'My access', exact: true }).click();
  await expect(page).toHaveURL(/\/Access$/);
  await expect(page.locator('.sidenav a.active')).toHaveText('My access');
  expect(documents).toEqual([]);

  // Legacy links replace the document. The return link reuses the same authenticated session.
  const legacyDocument = page.waitForResponse((response) => response.request().isNavigationRequest());
  await page.getByRole('link', { name: 'Secrets', exact: true }).click();
  expect((await legacyDocument).headers()['content-security-policy']).not.toContain('trusted-types');
  await expect(page).toHaveURL(/\/Secrets$/);
  await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();
  await page.getByText('Access', { exact: true }).click();
  const angularDocument = page.waitForResponse((response) => response.request().isNavigationRequest());
  await page.getByRole('link', { name: 'My access', exact: true }).click();
  expect((await angularDocument).headers()['content-security-policy']).toContain("require-trusted-types-for 'script'");
  await expect(page).toHaveURL(/\/Access$/);
  await expect(page.locator('.sidenav a.active')).toHaveText('My access');
  expect(documents.map((url) => new URL(url).pathname)).toEqual(['/Secrets', '/Access']);
  expect(signInRequests).toEqual([]);
  expect((await page.context().cookies()).find((cookie) => cookie.name === 'EclipsVault.Session')?.value).toBe(session?.value);
}
