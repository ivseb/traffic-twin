import { expect, test, type Page } from '@playwright/test';
import { axeViolations, go, loginAs, prepare } from './axe';

// Rules v1.9 in the console, on the demo build: the candidates below k on the Rules page open the editor already filled
// in (template prefilled), and the «Domains and test group» drawer of Sources › Policy joins two HMAC domains and marks
// a group as test with a lower k. axe on each, light and dark, desktop and phone width.

async function clean(page: Page, name: string): Promise<void> {
  const bad = await axeViolations(page);
  expect(bad, `axe violations on ${name}\n${bad.join('\n')}`).toEqual([]);
}

for (const [theme, width] of [['light', 1280], ['dark', 390]] as const) {
  test.describe(`rules v1.9, ${theme} ${width}px`, () => {
    test.use({ viewport: { width, height: 900 } });
    test.beforeEach(async ({ page }) => {
      await prepare(page, theme);
    });

    test('a candidate below k opens the editor with its template filled in', async ({ page }) => {
      const errors: string[] = [];
      page.on('pageerror', (e) => errors.push(e.message));
      await loginAs(page);
      await go(page, '#/rules');
      const cands = page.getByTestId('candidates');
      await expect(cands).toContainText('Candidates below the threshold', { timeout: 20_000 });
      await expect(cands).toContainText('POST /orders/{id}/cancel');
      await clean(page, 'rules with candidates');
      await cands.getByTestId('candidate-draft').first().click();
      const dlg = page.locator('dialog[open]').last();
      const tpl = dlg.getByTestId('rule-templates');
      await expect(tpl).toContainText('Filled in from the candidate', { timeout: 20_000 });
      await expect(dlg.getByTestId('rule-preview')).toContainText('CANCELLED');
      await page.waitForTimeout(400); // the drawer slides in
      await clean(page, 'editor from a candidate');
      expect(errors).toEqual([]);
    });

    test('domains are joined and a group is marked as test', async ({ page }) => {
      const errors: string[] = [];
      page.on('pageerror', (e) => errors.push(e.message));
      await loginAs(page);
      await go(page, '#/sources?tab=policy');
      await page.getByTestId('open-group-domains').click();
      const dlg = page.locator('dialog[open]').last();
      const fams = dlg.getByTestId('families');
      await expect(fams).toContainText('order + order_ref', { timeout: 20_000 });
      await page.waitForTimeout(400);
      await clean(page, 'domains drawer');
      await fams.getByRole('button', { name: 'Join', exact: true }).click();
      await expect(fams).toContainText('Families in use');
      await expect(fams.getByRole('button', { name: 'Split', exact: true })).toBeVisible();
      const tk = dlg.getByTestId('test-k');
      await tk.getByTestId('test-k-input').fill('3');
      await tk.getByLabel('Reason').fill('acceptance with 5 testers');
      await tk.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(tk.getByTestId('test-k-current')).toContainText('k = 3');
      await page.waitForTimeout(500); // the toasts fade in
      await clean(page, 'domains drawer after the changes');
      expect(errors).toEqual([]);
    });
  });
}
