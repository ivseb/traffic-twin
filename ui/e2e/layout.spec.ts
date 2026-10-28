import { expect, test, type Page } from '@playwright/test';

// Layout sweep: at four widths, no page scrolls sideways and no text is clipped inside a card
// (an element whose content is wider than the box and that neither scrolls nor wraps).
// Tables and code blocks scroll on purpose and are left out.
const PASSWORD = 'correct-horse-battery-1';
const WIDTHS = [390, 1024, 1440, 2000];
const PAGES = [
  '/#/onboarding',
  '/#/sources',
  '/#/sources?tab=policy',
  '/#/services',
  '/#/contracts',
  '/#/contracts/service/shipping-ext',
  '/#/contracts/service/shipping-ext?tab=snapshots',
  '/#/contracts/service/shipping-ext?tab=openapi',
  '/#/gaps',
  '/#/alerts',
  '/#/alerts?tab=webhooks',
  '/#/quarantine',
  '/#/events',
  '/#/settings?tab=keyguard',
  '/#/settings?tab=data',
  '/#/audit',
  '/#/settings?tab=approvals',
  '/#/settings?tab=keys',
  '/#/users',
  '/#/rules',
  '/#/archetypes',
  '/#/worlds',
  '/#/packs',
  '/#/scenarios',
  '/#/glossary',
];

async function clipped(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const skip = new Set(['TABLE', 'THEAD', 'TBODY', 'TR', 'TD', 'TH', 'PRE', 'CODE', 'SVG', 'PATH', 'HTML', 'BODY', 'INPUT', 'SELECT', 'TEXTAREA', 'OPTION']);
    const out: string[] = [];
    // Visually hidden on purpose (the screen-reader-only pattern: 1px box, clipped): not text a person has to read.
    const srOnly = (el: HTMLElement): boolean => {
      for (let n: HTMLElement | null = el; n && n !== document.body; n = n.parentElement) {
        const cs = getComputedStyle(n);
        if (cs.clipPath !== 'none' && n.clientWidth <= 1) return true;
      }
      return false;
    };
    for (const el of document.querySelectorAll<HTMLElement>('main *, header *, nav *')) {
      if (skip.has(el.tagName.toUpperCase())) continue;
      if (el.closest('table, pre, [data-scroll], .table-wrap, .scroll, svg, dialog:not([open])')) continue;
      if (el.scrollWidth <= el.clientWidth + 1 || el.clientWidth === 0) continue;
      if (srOnly(el)) continue;
      const ox = getComputedStyle(el).overflowX;
      if (ox === 'auto' || ox === 'scroll') continue;
      // A connector line drawn by an absolutely positioned pseudo-element (the stepper) is not text.
      if (getComputedStyle(el, '::after').position === 'absolute' || getComputedStyle(el, '::before').position === 'absolute') continue;
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) continue;
      out.push(`${el.tagName.toLowerCase()}.${String(el.className).split(' ')[0]} "${(el.textContent ?? '').trim().slice(0, 40)}" ${el.scrollWidth}>${el.clientWidth}`);
    }
    return out;
  });
}

for (const width of WIDTHS) {
  test(`no clipped text, no sideways scroll at ${width}px`, async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width, height: 900 });
    await page.goto('/#/login');
    await page.getByRole('textbox', { name: 'Username' }).fill('root');
    await page.getByRole('textbox', { name: 'Password' }).fill(PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.locator('header .trigger')).toBeVisible();
    const problems: string[] = [];
    for (const path of PAGES) {
      await page.goto(path);
      await page.waitForLoadState('networkidle');
      const sideways = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      if (sideways > 1) problems.push(`${path}: page scrolls sideways by ${sideways}px`);
      for (const c of await clipped(page)) problems.push(`${path}: ${c}`);
    }
    expect(problems).toEqual([]);
  });
}

test('the sidebar background spans the whole page', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 700 });
  await page.goto('/#/login');
  await page.getByRole('textbox', { name: 'Username' }).fill('root');
  await page.getByRole('textbox', { name: 'Password' }).fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.goto('/#/onboarding');
  await page.waitForLoadState('networkidle');
  const { nav, doc } = await page.evaluate(() => ({ nav: document.querySelector('nav')?.getBoundingClientRect().bottom ?? 0, doc: document.documentElement.scrollHeight }));
  expect(doc).toBeGreaterThan(700); // the page really is taller than the viewport
  expect(Math.round(nav)).toBeGreaterThanOrEqual(doc - 1);
});
