import { expect, test, type Page } from '@playwright/test';
import { axeViolations, go, loginAs, prepare } from './axe';

// «Identità dell'utente» (policy.md §7.1, §7.4) in Sources > Policy, on the demo build: the detected source with its
// reasons, the left-out candidates with why, a header of any name typed by the person applies at once. axe on the
// drawer, light and dark, desktop and phone width.

async function clean(page: Page, name: string): Promise<void> {
  const bad = await axeViolations(page);
  expect(bad, `axe violations on ${name}\n${bad.join('\n')}`).toEqual([]);
}

for (const [theme, width] of [['light', 1280], ['dark', 390]] as const) {
  test.describe(`user identity, ${theme} ${width}px`, () => {
    test.use({ viewport: { width, height: 900 } });
    test.beforeEach(async ({ page }) => {
      await prepare(page, theme);
    });

    test('the drawer shows the detected source and applies a header of any name at once', async ({ page }) => {
      const errors: string[] = [];
      page.on('pageerror', (e) => errors.push(e.message));
      await loginAs(page);
      await go(page, '#/sources?tab=policy');
      await page.getByRole('button', { name: 'User identity', exact: true }).click();
      const dlg = page.locator('dialog[open]').last();
      const ctl = dlg.getByTestId('identity-control');
      await expect(ctl.getByTestId('identity-detected')).toBeVisible({ timeout: 20_000 });
      await expect(ctl.getByTestId('identity-detected')).toContainText('authorization');
      await ctl.locator('summary').click();
      await expect(ctl).toContainText('a new value on almost every call');
      await clean(page, 'identity drawer');
      await ctl.getByText('Another one: type the name').click();
      await ctl.getByTestId('identity-name').fill('X-Kunden-Nr');
      await expect(ctl.getByTestId('identity-verdict')).toContainText('Applies at once');
      await clean(page, 'identity drawer, custom name');
      await ctl.getByRole('button', { name: 'Use this identity' }).click();
      await expect(ctl.getByTestId('identity-current')).toContainText('x-kunden-nr');
      expect(errors).toEqual([]);
    });
  });
}
