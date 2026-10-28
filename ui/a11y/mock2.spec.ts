import { expect, test, type Page } from '@playwright/test';
import { axeViolations, go, loginAs, prepare } from './axe';

// Relative dates (contract tab), third-party pages (Mock page) and the derived value of a rule (rule editor), on the
// demo build: the forms that only appear after a click, axe in light and dark, desktop and phone width.

async function clean(page: Page, name: string): Promise<void> {
  const bad = await axeViolations(page);
  expect(bad, `axe violations on ${name}\n${bad.join('\n')}`).toEqual([]);
}

for (const [theme, width] of [['light', 1280], ['dark', 390]] as const) {
  test.describe(`relative dates, third-party pages, derived values, ${theme} ${width}px`, () => {
    test.use({ viewport: { width, height: 900 } });
    test.beforeEach(async ({ page }) => {
      await prepare(page, theme);
    });

    test('the relative dates tab shows the learned range and previews a chosen one', async ({ page }) => {
      const errors: string[] = [];
      page.on('pageerror', (e) => errors.push(e.message));
      await loginAs(page);
      await go(page, '#/contracts/service/shipping-ext?tab=dates');
      const row = page.getByTestId('date-offset-row').first();
      await expect(row).toContainText('Learned from the traffic: from +1d to +5d');
      await row.getByLabel('Minimum offset').fill('+30d');
      await row.getByLabel('Maximum offset').fill('+365d');
      await expect(row.getByTestId('date-offset-preview')).toContainText('with offsets from +30d to +365d');
      await clean(page, 'relative dates');
      await row.getByLabel('Maximum offset').fill('+1d');
      await expect(row).toContainText('The minimum comes after the maximum');
      await clean(page, 'relative dates, invalid range');
      expect(errors).toEqual([]);
    });

    test('the third-party pages card lists the demo page and opens its guided form', async ({ page }) => {
      const errors: string[] = [];
      page.on('pageerror', (e) => errors.push(e.message));
      await loginAs(page);
      await go(page, '#/mock');
      const card = page.getByTestId('pages-card');
      await expect(card.getByTestId('page-item').first()).toContainText('/__pages/pay');
      await card.getByText('In tests without a browser').click();
      await clean(page, 'pages card');
      await card.getByRole('button', { name: 'Edit “pay”' }).click();
      const form = card.getByTestId('page-form');
      await expect(form.getByLabel('Test HMAC key')).toHaveAttribute('type', 'password');
      await clean(page, 'page form');
      await form.getByLabel('Id', { exact: true }).fill('Pay!');
      await expect(form).toContainText('To fix before saving');
      await clean(page, 'page form with problems');
      expect(errors).toEqual([]);
    });

    test('the rule editor shows a derived value with its preview', async ({ page }) => {
      const errors: string[] = [];
      page.on('pageerror', (e) => errors.push(e.message));
      await loginAs(page);
      await go(page, '#/rules/r-0016');
      await page.getByRole('button', { name: 'Edit conditions and effects' }).click();
      const dlg = page.locator('dialog[open]').last();
      const dv = dlg.getByTestId('derived-value');
      await expect(dv).toBeVisible({ timeout: 20_000 });
      await expect(dv.getByTestId('derived-preview')).toContainText('date(now +3d)');
      await page.waitForTimeout(400); // the drawer slides in: axe would measure the colours mid-animation
      await clean(page, 'rule editor, derived value');
      await dv.getByLabel('Function').selectOption('sum');
      await expect(dv.getByTestId('derived-preview')).toContainText('sum(items[*].price)');
      await clean(page, 'rule editor, derived sum');
      expect(errors).toEqual([]);
    });
  });
}
