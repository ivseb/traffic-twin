// In-memory relative dates and third-party pages for the demo build and the tests (invented data: an e-commerce
// that sends the browser to a payment page). Same validation, error codes and roles as tt-core.

import { ApiError, type Permission, type User } from '../types';
import { DATE_FIELD_RE, rangeProblem, type DateOffset, type DateOffsetsApi } from '../dates';
import { pageProblems, type MockPages, type ThirdPartyPage } from '../pages';
import { permissionsOf } from '../../rbac';

export interface DemoMock2Deps {
  authed(): User;
  audit(actor: string, action: string, target: string): void;
  now(): number;
  wait(): Promise<void>;
}

function needAny(d: DemoMock2Deps, perms: Permission[]): User {
  const u = d.authed();
  const have = permissionsOf(u.roles);
  if (!perms.some((p) => have.has(p))) throw new ApiError('forbidden', `Permesso mancante: ${perms.join(' / ')}`, 403);
  return u;
}

const GROUP_RE = /^([a-z0-9][a-z0-9._-]{0,62})?$/;

export function createDemoDateOffsets(d: DemoMock2Deps): DateOffsetsApi {
  const store = new Map<string, DateOffset>();
  const key = (g: string, f: string) => `${g}\u0000${f}`;
  return {
    async list(group) {
      await d.wait();
      needAny(d, ['worlds.generate', 'rules.edit', 'publish.run', 'audit.view']);
      return [...store.values()].filter((o) => o.group === group).sort((a, b) => a.field.localeCompare(b.field)).map((o) => ({ ...o }));
    },
    async set(group, field, min, max) {
      await d.wait();
      const u = needAny(d, ['worlds.generate', 'rules.edit']);
      if (!GROUP_RE.test(group)) throw new ApiError('invalid', 'malformed group', 422, 'invalid_group');
      if (!DATE_FIELD_RE.test(field)) throw new ApiError('invalid', 'malformed field name', 422, 'invalid_field');
      const p = rangeProblem(min, max);
      if (p) throw new ApiError('invalid', p === 'order' ? 'min is after max' : `${p}: an offset looks like +30d, -2d or +12h`, 422, 'invalid_offset');
      const o: DateOffset = { group, field, min: min.trim(), max: max.trim(), updatedBy: u.username, updatedAt: new Date(d.now()).toISOString() };
      store.set(key(group, field), o);
      d.audit(u.username, 'dateoffset.set', `${group}/${field}`);
      return { ...o };
    },
    async remove(group, field) {
      await d.wait();
      const u = needAny(d, ['worlds.generate', 'rules.edit']);
      if (!store.delete(key(group, field))) throw new ApiError('not_found', 'not found', 404, 'not_found');
      d.audit(u.username, 'dateoffset.delete', `${group}/${field}`);
    },
  };
}

/** The demo's payment page (group shop-api): approve / decline with a signed callback, cancel without one. */
export function demoPaymentPage(): ThirdPartyPage {
  return {
    id: 'pay',
    title: 'Pagamento simulato',
    description: 'Il gestore dei pagamenti chiede di confermare l’addebito: scegli l’esito.',
    ref: '{query.paymentId}',
    show: ['amount'],
    return_url: 'https://shop.test/pay/return?ref={ref}&outcome={action}',
    buttons: [
      { action: 'approve', label: 'Approva', values: { code: 'AUTHORISED' }, set: { status: '{value.code}' } },
      { action: 'decline', label: 'Rifiuta', values: { code: 'REFUSED' }, set: { status: '{value.code}' } },
      { action: 'cancel', label: 'Annulla', no_callback: true },
    ],
    callback: {
      method: 'POST',
      url: 'https://shop.test/api/pay/notify',
      headers: { 'Content-Type': 'application/json' },
      body: '{"ref":"{ref}","status":"{value.code}","at":"{now}"}',
      body_type: 'json',
      hmac: { header: 'X-Signature', key: '', algorithm: 'sha256', encoding: 'hex', prefix: 'sha256=' },
    },
    links: [{ service: 'payments-ext', op: 'POST /v1/charges', path: '$.redirectUrl', ref_path: '$.chargeId', return_from: { from: 'req.body', path: '$.returnUrl' } }],
    auto: { 'sc-flaky-payments': 'decline' },
  };
}

export function createDemoPages(d: DemoMock2Deps) {
  const store = new Map<string, MockPages>();
  // The HMAC keys stay here: the answers carry them empty, like the console's.
  const keys = new Map<string, string>();
  const kkey = (g: string, id: string) => `${g}\u0000${id}`;
  store.set('shop-api', { group: 'shop-api', pages: [demoPaymentPage()], updatedBy: 'olga.operator', updatedAt: new Date(d.now() - 2 * 3600000).toISOString() });
  keys.set(kkey('shop-api', 'pay'), 'demo-signing-key-0001');
  const view = (m: MockPages): MockPages => structuredClone(m);
  return {
    async pages(group: string): Promise<MockPages> {
      await d.wait();
      needAny(d, ['publish.build', 'publish.run', 'audit.view']);
      return view(store.get(group) ?? { group, pages: [] });
    },
    async setPages(group: string, pages: ThirdPartyPage[]): Promise<MockPages> {
      await d.wait();
      const u = needAny(d, ['publish.build']);
      if (!GROUP_RE.test(group)) throw new ApiError('invalid', 'malformed group name', 422, 'invalid_group');
      if (pages.length > 32) throw new ApiError('invalid', 'at most 32 pages', 422, 'invalid_pages');
      const next = structuredClone(pages);
      const newKeys = new Map<string, string>();
      for (let i = 0; i < next.length; i++) {
        const p = next[i];
        const stored = keys.get(kkey(group, p.id));
        const problems = pageProblems(p, next.slice(0, i), !!stored);
        if (problems.length) throw new ApiError('invalid', `pages[${i}] (${p.id}): ${problems[0].field}: ${problems[0].code}${problems[0].item ? ` ${problems[0].item}` : ''}`, 422, 'invalid_pages');
        const h = p.callback?.hmac;
        if (h) {
          newKeys.set(kkey(group, p.id), h.key || stored || '');
          h.key = '';
        }
      }
      for (const k of [...keys.keys()]) if (k.startsWith(`${group}\u0000`)) keys.delete(k);
      for (const [k, v] of newKeys) keys.set(k, v);
      const m: MockPages = { group, pages: next, updatedBy: u.username, updatedAt: new Date(d.now()).toISOString() };
      store.set(group, m);
      d.audit(u.username, 'mock.pages_set', group);
      return view(m);
    },
  };
}
