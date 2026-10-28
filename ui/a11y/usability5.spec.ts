import { expect, test, type Page } from '@playwright/test';
import { axeViolations, go, loginAs, prepare } from './axe';

// Usability round 5 (backend developer, deliveries-api, codes already in clear): the pages that changed, on the demo
// build. Each scenario checks what the person sees and, where the page is new or changed, axe. The 390 px run also
// checks that the bulk review rows do not spill out of the drawer.

async function clean(page: Page, name: string): Promise<void> {
  const bad = await axeViolations(page);
  expect(bad, `axe violations on ${name}\n${bad.join('\n')}`).toEqual([]);
}

const pageErrors = (page: Page): (() => string[]) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  return () => errors;
};

/** The parts of the bulk review rows that spill out of their group box, or overlap the next row (cosmetic 12). */
async function spill(page: Page): Promise<string[]> {
  return page.locator('dialog[open]').last().evaluate((d) => {
    const bad: string[] = [];
    const rows = [...d.querySelectorAll('[data-testid="bulk-field"]')];
    rows.forEach((li, i) => {
      const box = li.closest('section')!.getBoundingClientRect();
      const own = li.getBoundingClientRect();
      for (const el of li.querySelectorAll('*')) {
        const r = (el as HTMLElement).getBoundingClientRect();
        if (r.width === 0) continue;
        const name = (el as HTMLElement).tagName + ' ' + (el.textContent ?? '').slice(0, 30);
        if (r.right > box.right + 1 || r.left < box.left - 1) bad.push(`out of the box: ${name}`);
        if (r.bottom > own.bottom + 1) bad.push(`under the next row: ${name}`);
      }
      const next = rows[i + 1];
      if (next && next.closest('section') === li.closest('section') && next.getBoundingClientRect().top < own.bottom - 1) bad.push(`row ${i} overlaps the next`);
    });
    return bad;
  });
}

// The drawer of «Rivedi in blocco» at the widths in between: the rows stay aligned and inside their box.
for (const width of [600, 768, 1024, 1600]) {
  test(`cosmetic 12: bulk review rows aligned at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await prepare(page, 'light');
    await loginAs(page);
    await go(page, '#/sources?tab=policy&bulk=1');
    const dlg = page.locator('dialog[open]').last();
    await expect(dlg.getByTestId('bulk-how')).toBeVisible({ timeout: 20_000 });
    for (const g of ['bulk-ids', 'bulk-states']) {
      const sec = dlg.getByTestId(g);
      if (await sec.count()) await sec.getByRole('combobox').selectOption({ index: 1 });
    }
    await expect(dlg.getByTestId('bulk-field').first()).toBeVisible();
    expect(await spill(page)).toEqual([]);
  });
}

for (const [theme, width] of [['light', 1280], ['dark', 390]] as const) {
  test.describe(`usability 5, ${theme} ${width}px`, () => {
    test.use({ viewport: { width, height: 900 } });
    test.beforeEach(async ({ page }) => {
      await prepare(page, theme);
    });

    test('M2: bulk review field by field, a code is never turned into keep, the approvals are said before applying', async ({ page }) => {
      const errors = pageErrors(page);
      await loginAs(page);
      await go(page, '#/sources?tab=policy&bulk=1');
      const dlg = page.locator('dialog[open]').last();
      await expect(dlg.getByTestId('bulk-how')).toBeVisible({ timeout: 20_000 });
      const states = dlg.getByTestId('bulk-states');
      await expect(states).toBeVisible();
      // the status of shipping-ext already is code: it is listed, with its checkbox, and not touched by the proposal
      await states.getByRole('combobox').selectOption({ label: 'Apply the proposal' });
      const rows = states.getByTestId('bulk-field');
      await expect(rows.first()).toBeVisible();
      const codeRow = rows.filter({ hasText: 'items[*].status' });
      await expect(codeRow).toContainText('stays as it is');
      await expect(codeRow.getByRole('checkbox')).not.toBeChecked();
      // the others open values: the summary counts them and says who approves
      await expect(dlg.getByTestId('bulk-summary')).toContainText('open');
      await expect(dlg.getByTestId('bulk-approvals')).toBeVisible();
      await expect(dlg.getByTestId('bulk-approvals')).toContainText('approvals');
      // untick every field: nothing opens any more and no approval is mentioned
      await states.getByRole('button', { name: 'Untick all', exact: true }).click();
      await expect(dlg.getByTestId('bulk-approvals')).toHaveCount(0);
      await expect(dlg.getByTestId('bulk-summary')).toContainText('no field changes');
      await states.getByRole('button', { name: 'Tick all', exact: true }).click();
      await expect(dlg.getByTestId('bulk-approvals')).toBeVisible();
      // nothing spills out of the drawer, at any width: the rows keep inside their group box
      expect(await spill(page)).toEqual([]);
      await page.waitForTimeout(200);
      await clean(page, 'bulk review field by field');
      expect(errors()).toEqual([]);
    });

    test('major 2: a pending draft is withdrawn from the policy list, after a confirmation that says what is lost', async ({ page }) => {
      await loginAs(page);
      await go(page, '#/sources?tab=policy');
      const btn = page.getByTestId('withdraw-draft').first();
      await expect(btn).toBeVisible();
      await btn.click();
      const dlg = page.locator('dialog[open]').last();
      await expect(dlg).toContainText('never becomes active');
      await clean(page, 'withdraw dialog');
      await dlg.getByRole('button', { name: 'Withdraw the draft' }).click();
      await expect(page.locator('dialog[open]')).toHaveCount(0);
      await expect(page.getByText('Withdrawn').first()).toBeVisible();
    });

    test('major 1: an approved rule is retired from its page and leaves the list of the approved ones', async ({ page }) => {
      await loginAs(page);
      await go(page, '#/rules/r-0003');
      const retire = page.getByTestId('retire-rule-button');
      await expect(retire).toBeVisible();
      await clean(page, 'approved rule with retire');
      await retire.click();
      const dlg = page.locator('dialog[open]').last();
      await expect(dlg).toContainText('leaves the packs');
      await clean(page, 'retire dialog');
      await dlg.getByRole('button', { name: 'Retire the rule' }).click();
      await expect(page.getByTestId('rule-retired')).toBeVisible();
    });

    test('M3: the Panoramica does not ask to approve the statuses when they already come out as codes', async ({ page }) => {
      await loginAs(page);
      await go(page, '#/home');
      const card = page.getByTestId('approval-next-step');
      await expect(card).toBeVisible();
      await expect(card.getByTestId('states-in-clear').first()).toContainText('already come out in clear, with no approval');
      await expect(card).not.toContainText('static values');
      await clean(page, 'home with states in clear');
    });

    test('m10: external hosts count every host and list each once', async ({ page }) => {
      await loginAs(page);
      await go(page, '#/hosts');
      await expect(page.getByTestId('tile-hosts')).toBeVisible();
      const n = Number(await page.getByTestId('tile-hosts').innerText());
      expect(n).toBeGreaterThan(0);
      const keys = await page.getByTestId('host-row').evaluateAll((rows) => rows.map((r) => (r.querySelector('.host') as HTMLElement | null)?.innerText.split('\n')[0] ?? ''));
      expect(new Set(keys).size).toBe(keys.length);
      await clean(page, 'external hosts');
    });

    test('M4: the rule editor opens on the catalog read ahead and the new text of the drift is on the alerts page', async ({ page }) => {
      await loginAs(page);
      await go(page, '#/rules');
      await page.getByRole('button', { name: 'New rule', exact: true }).click();
      const dlg = page.locator('dialog[open]').last();
      await expect(dlg.getByRole('textbox', { name: /title/i }).first()).toBeVisible({ timeout: 20_000 });
      await expect(dlg.getByTestId('editor-loading')).toHaveCount(0);
      await page.waitForTimeout(400);
      await clean(page, 'rule editor');
      await dlg.getByRole('button', { name: 'Cancel' }).click();
      await go(page, '#/alerts');
      await expect(page.getByTestId('drift-note')).toBeVisible();
      await clean(page, 'alerts');
    });

    test('m7: leaving the Mock page during the preparation, the steps and the running job come back', async ({ page }) => {
      await loginAs(page);
      await go(page, '#/mock');
      await page.getByTestId('prepare-button').click();
      await expect(page.getByRole('list', { name: /progress/i })).toBeVisible();
      await go(page, '#/home');
      await go(page, '#/mock');
      await expect(page.getByRole('list', { name: /progress/i })).toBeVisible();
      await expect(page.getByTestId('prep-resumed').or(page.getByTestId('prep-last'))).toBeVisible();
      await clean(page, 'mock page with a resumed preparation');
    });
  });
}
