import { expect, test, type Page } from '@playwright/test';
import { go, loginAs, prepare } from './axe';

// What axe cannot see: keyboard operation, focus order and return, visible focus, live regions,
// language switching and reduced motion.

// Inside a modal dialog Tab cycles through the dialog and the browser's own interface; it never reaches the page behind.
const insideOrChrome = (page: Page) => page.evaluate(() => !document.activeElement || document.activeElement === document.body || !!document.activeElement.closest('dialog[open]'));
const active = (page: Page) => page.evaluate(() => document.activeElement?.id || document.activeElement?.tagName || '');

test.describe('keyboard and behaviour (light, 1280px)', () => {
  test.use({ viewport: { width: 1280, height: 900 } });
  test.beforeEach(async ({ page }) => {
    await prepare(page, 'light');
  });

  test('skip link: first tab stop on a fresh load, visible on focus, moves the focus to main', async ({ page }) => {
    await page.goto('/#/login');
    await page.locator('main h1').waitFor();
    await page.keyboard.press('Tab');
    const skip = page.getByRole('link', { name: 'Skip to content' });
    await expect(skip).toBeFocused();
    const box = await skip.boundingBox();
    expect(box && box.x >= 0 && box.y >= 0, 'visible on screen when focused').toBe(true);
    await page.keyboard.press('Enter');
    expect(await active(page)).toBe('main');
  });

  test('skip link works inside the application shell', async ({ page }) => {
    await loginAs(page);
    await go(page, '#/sources');
    const skip = page.getByRole('link', { name: 'Skip to content' });
    await skip.focus();
    const box = await skip.boundingBox();
    expect(box && box.x >= 0 && box.y >= 0, 'visible on screen when focused').toBe(true);
    await page.keyboard.press('Enter');
    expect(await active(page)).toBe('main');
    await page.keyboard.press('Tab');
    expect(await page.evaluate(() => !!document.activeElement?.closest('main'))).toBe(true); // the next stop is in the page, not the sidebar
  });

  test('language switch updates <html lang> and the texts, both ways', async ({ page }) => {
    await loginAs(page);
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await page.locator('header .lang').getByRole('button', { name: 'IT' }).click();
    await expect(page.locator('html')).toHaveAttribute('lang', 'it');
    await expect(page.getByRole('link', { name: 'Vai al contenuto' })).toHaveCount(1);
    await page.locator('header .lang').getByRole('button', { name: 'EN' }).click();
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await expect(page.getByRole('link', { name: 'Skip to content' })).toHaveCount(1);
  });

  test('lang follows the browser language on first visit', async ({ browser }) => {
    const ctx = await browser.newContext({ locale: 'it-IT' });
    const page = await ctx.newPage();
    await page.goto('/#/login');
    await expect(page.locator('html')).toHaveAttribute('lang', 'it');
    await ctx.close();
  });

  test('tabs: arrow keys, Home and End move and select, one tab stop', async ({ page }) => {
    await loginAs(page);
    await go(page, '#/settings?tab=general');
    const tabs = page.getByRole('tab');
    await tabs.first().focus();
    await page.keyboard.press('ArrowRight');
    await expect(tabs.nth(1)).toBeFocused();
    await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('End');
    await expect(tabs.last()).toBeFocused();
    await page.keyboard.press('Home');
    await expect(tabs.first()).toBeFocused();
    await page.keyboard.press('ArrowLeft');
    await expect(tabs.last()).toBeFocused();
    // roving tabindex: only the selected tab is in the tab order
    expect(await tabs.evaluateAll((els) => els.filter((e) => (e as HTMLElement).tabIndex === 0).length)).toBe(1);
    // the panel is labelled by the selected tab
    const panel = page.getByRole('tabpanel');
    await expect(panel).toHaveAccessibleName(await tabs.last().innerText());
  });

  test('table: sort with the keyboard, aria-sort follows, filter announces the count', async ({ page }) => {
    await loginAs(page);
    await go(page, '#/sources');
    const sorts = page.locator('table th button.sort');
    await sorts.first().focus();
    const th = page.locator('table th:has(button.sort)').first();
    await expect(th).toHaveAttribute('aria-sort', 'none');
    await page.keyboard.press('Enter');
    await expect(th).toHaveAttribute('aria-sort', 'ascending');
    await page.keyboard.press('Space');
    await expect(th).toHaveAttribute('aria-sort', 'descending');
    await expect(sorts.first()).toBeFocused();
    const count = page.locator('.count[aria-live="polite"]');
    const before = await count.innerText();
    await page.getByRole('searchbox', { name: 'Search…' }).first().fill('zzzz-nothing');
    await expect(count).not.toHaveText(before);
  });

  test('every row-click table has a keyboard way to the same thing (a link or a button in the row)', async ({ page }) => {
    await loginAs(page);
    for (const hash of ['#/sources', '#/packs', '#/worlds']) {
      await go(page, hash);
      const missing = await page.evaluate(() => [...document.querySelectorAll('tbody tr.clickable')].filter((tr) => !tr.querySelector('a[href], button:not([disabled])')).length);
      expect(missing, hash).toBe(0);
    }
  });

  test('modal: focus is trapped, returns to the opener, Esc closes; the toast host lives inside the dialog', async ({ page }) => {
    await loginAs(page);
    await go(page, '#/users');
    const opener = page.getByRole('button', { name: 'New user' });
    await opener.click();
    const dlg = page.getByRole('dialog', { name: 'New user' });
    await expect(dlg).toBeVisible();
    for (let i = 0; i < 25; i++) {
      await page.keyboard.press('Tab');
      expect(await insideOrChrome(page), `tab ${i}`).toBe(true);
    }
    for (let i = 0; i < 25; i++) {
      await page.keyboard.press('Shift+Tab');
      expect(await insideOrChrome(page), `shift-tab ${i}`).toBe(true);
    }
    await expect(dlg.locator('[role="status"]')).toHaveCount(1);
    await expect(dlg.locator('[role="alert"]')).toHaveCount(1);
    await page.keyboard.press('Escape');
    await expect(dlg).toBeHidden();
    await expect(opener).toBeFocused();
  });

  test('a toast is announced through a status live region and stays while it is hovered', async ({ page }) => {
    await loginAs(page);
    await go(page, '#/rules');
    await page.getByRole('button', { name: 'Look for new rules' }).click();
    const status = page.locator('section[aria-label] [role="status"]').first();
    await expect(status).toContainText(/./);
    await status.hover();
    await page.waitForTimeout(5200); // longer than the 4.5 s lifetime
    await expect(status).toContainText(/./);
    await page.mouse.move(5, 5);
    await expect(status).toHaveText('', { timeout: 6000 });
  });

  test('page title is announced on navigation', async ({ page }) => {
    await loginAs(page);
    await go(page, '#/glossary');
    await expect(page.locator('div.sr-only[role="status"]')).toHaveText('Glossary');
  });

  test('focus ring is visible on the first 40 tab stops of three pages', async ({ page }) => {
    await loginAs(page);
    const bad: string[] = [];
    for (const hash of ['#/hosts', '#/settings?tab=general', '#/rules']) {
      await go(page, hash);
      await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
      for (let i = 0; i < 40; i++) {
        await page.keyboard.press('Tab');
        const r = await page.evaluate(() => {
          const el = document.activeElement as HTMLElement | null;
          if (!el || el === document.body) return null;
          // switches draw the ring on their track, the real input is visually hidden
          const target = el.matches('input[role="switch"]') ? (el.nextElementSibling as HTMLElement) : el;
          const cs = getComputedStyle(target);
          const sw = el.matches('input[role="switch"]');
          const ring = sw ? getComputedStyle(target) : cs;
          const hasOutline = ring.outlineStyle !== 'none' && parseFloat(ring.outlineWidth) >= 2;
          const hasShadow = ring.boxShadow !== 'none' && /\d/.test(ring.boxShadow);
          return { ok: hasOutline || hasShadow, id: `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') || '').split(' ')[0]} "${(el.getAttribute('aria-label') || el.textContent || '').trim().slice(0, 30)}"` };
        });
        if (r && !r.ok) bad.push(`${hash} #${i}: ${r.id}`);
      }
    }
    expect(bad).toEqual([]);
  });

  test('the menu is the journey in four numbered steps; Advanced is collapsed, opens with Enter and opens itself on its pages', async ({ page }) => {
    await loginAs(page);
    await go(page, '#/home');
    const nav = page.locator('nav#sidebar');
    for (const step of ['Connect', 'Observe', 'Review', 'Use the mock']) await expect(nav.locator('.step', { hasText: step })).toBeVisible();
    await expect(nav.getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page');
    const adv = nav.getByRole('button', { name: 'Advanced' });
    await expect(adv).toHaveAttribute('aria-expanded', 'false');
    await expect(nav.getByRole('link', { name: 'Quarantine' })).toBeHidden();
    await adv.focus();
    await page.keyboard.press('Enter');
    await expect(adv).toHaveAttribute('aria-expanded', 'true');
    await expect(nav.getByRole('link', { name: 'Quarantine' })).toBeVisible();
    await page.keyboard.press('Enter');
    await expect(nav.getByRole('link', { name: 'Quarantine' })).toBeHidden();
    // a page of the group opens it by itself
    await go(page, '#/audit');
    await expect(adv).toHaveAttribute('aria-expanded', 'true');
    await expect(nav.getByRole('link', { name: 'Audit' })).toHaveAttribute('aria-current', 'page');
  });

  test('the world explorer: search, page and pick a customer with the keyboard', async ({ page }) => {
    await loginAs(page);
    await go(page, '#/worlds');
    const search = page.getByRole('searchbox', { name: 'Search a customer' });
    await search.focus();
    await search.fill('CUS-SYN-0002');
    const customers = page.getByRole('region', { name: 'Synthetic customers' });
    const rows = customers.locator('tbody').getByRole('button');
    await expect(rows).toHaveCount(1);
    await rows.focus();
    await page.keyboard.press('Enter');
    const detail = page.getByRole('region', { name: 'Customer detail' });
    await expect(detail.getByRole('heading', { level: 3 })).toBeVisible();
    await expect(detail.locator('ol.steps').first()).toBeVisible();
  });

  test('mobile navigation is out of the tab order while closed, takes focus when opened and gives it back on Esc', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await loginAs(page);
    await go(page, '#/sources');
    const nav = page.locator('nav#sidebar');
    await expect(nav).toBeHidden(); // visibility: hidden removes it from tab order and accessibility tree
    const burger = page.getByRole('button', { name: 'Menu' });
    await burger.click();
    await expect(nav).toBeVisible();
    await expect(nav.locator('a').first()).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(nav).toBeHidden();
    await expect(burger).toBeFocused();
  });

  test('the phone header keeps names for the brand link and the user menu', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await loginAs(page);
    await expect(page.getByRole('link', { name: 'traffic-twin' })).toBeVisible();
    await expect(page.locator('header .trigger')).toHaveAccessibleName(/Admin/);
  });
});

test.describe('reduced motion', () => {
  test.use({ viewport: { width: 390, height: 844 }, reducedMotion: 'reduce' });
  test('animations and transitions are neutralised', async ({ page }) => {
    await prepare(page, 'light');
    await loginAs(page);
    await page.getByRole('button', { name: 'Menu' }).click();
    const r = await page.evaluate(() => {
      const secs = (v: string) => Math.max(...v.split(',').map((x) => parseFloat(x) * (x.trim().endsWith('ms') ? 0.001 : 1)));
      const nav = getComputedStyle(document.querySelector('nav#sidebar')!);
      const sk = document.createElement('span');
      sk.className = 'skeleton';
      document.body.appendChild(sk);
      const s = getComputedStyle(sk);
      const out = { nav: secs(nav.transitionDuration), skeleton: secs(s.animationDuration), scroll: getComputedStyle(document.documentElement).scrollBehavior };
      sk.remove();
      return out;
    });
    expect(r.nav).toBeLessThan(0.01);
    expect(r.skeleton).toBeLessThan(0.01);
    expect(r.scroll).not.toBe('smooth');
  });
});
