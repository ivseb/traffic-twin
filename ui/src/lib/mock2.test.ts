import { describe, expect, it } from 'vitest';
import { dateFields, offsetHours, rangeDates, rangeProblem } from './api/dates';
import { badPlaceholder, cleanPage, fixedOrigin, newPage, pageProblems, parseList, parseSet, parseValues, setText, valuesText, type ThirdPartyPage } from './api/pages';
import { demoPaymentPage } from './api/mock/mock2';
import { createMockApi } from './api/mock/adapter';
import { ApiError } from './api/types';

// Relative dates and third-party pages: pure helpers and the demo adapter. Invented e-commerce data only.

describe('relative dates', () => {
  it('reads offsets as the server does', () => {
    expect(['+30d', '-2d', '+12h', '0d', '36600d'].map(offsetHours)).toEqual([720, -48, 12, 0, 36600 * 24]);
    expect(['30', '+30 d', '+1w', '36601d', '+1234567d', ''].map(offsetHours)).toEqual([null, null, null, null, null, null]);
    expect(rangeProblem('+30d', '+365d')).toBeNull();
    expect(rangeProblem('x', '+1d')).toBe('min');
    expect(rangeProblem('+1d', 'y')).toBe('max');
    expect(rangeProblem('+2d', '+1d')).toBe('order');
    expect(rangeProblem('-36500d', '-6570d')).toBeNull();
  });
  it('previews the dates of a range from now', () => {
    const r = rangeDates(new Date('2026-10-28T00:00:00Z'), '+30d', '+365d')!;
    expect(r.from.toISOString().slice(0, 10)).toBe('2026-11-27');
    expect(r.to.toISOString().slice(0, 10)).toBe('2027-10-28');
    expect(rangeDates(new Date(), '+2d', '+1d')).toBeNull();
  });
  it('lists the date fields of a contract once per property name, with the learned range', () => {
    const doc = {
      openapi: '3.1.0',
      paths: {
        '/v1/subscriptions/{id}': {
          get: {
            parameters: [{ name: 'since', in: 'query', schema: { type: 'string', format: 'date' } }],
            responses: {
              200: {
                content: {
                  'application/json': {
                    schema: {
                      type: 'object',
                      properties: {
                        renewsOn: { type: 'string', format: 'date', 'x-tt-value': { kind: 'shape', date_offset: { min: '+300d', max: '+365d' } } },
                        createdAt: { type: 'string', format: 'date-time' },
                        bucketed: { type: 'string', 'x-tt-value': { kind: 'bucket', unit: 'day' } },
                        plain: { type: 'string' },
                        items: { type: 'array', items: { $ref: '#/components/schemas/Line' } },
                      },
                    },
                    example: { renewsOn: { format: 'date' } },
                  },
                },
              },
            },
          },
        },
        '/v1/subscriptions': { post: { responses: { 201: { content: { 'application/json': { schema: { type: 'object', properties: { renewsOn: { type: 'string', format: 'date' } } } } } } } } },
      },
      components: { schemas: { Line: { type: 'object', properties: { deliveredAt: { type: 'string', format: 'date-time', 'x-tt-value': { kind: 'shape', date_offset: { min: 'bad', max: '+1d' } } } } } } },
    };
    expect(dateFields(doc)).toEqual([
      { field: 'bucketed', format: 'date-time' },
      { field: 'createdAt', format: 'date-time' },
      { field: 'deliveredAt', format: 'date-time' },
      { field: 'renewsOn', format: 'date', learned: { min: '+300d', max: '+365d' } },
    ]);
  });
  it('demo: an operator chooses a range, a publisher only reads it, the learned range of the demo contract shows', async () => {
    const api = createMockApi({ latencyMs: 0, storage: null });
    await api.demo!.loginAs('operator');
    const fields = dateFields(await api.contracts.openapi('shipping-ext'));
    expect(fields).toEqual([{ field: 'eta', format: 'date-time', learned: { min: '+1d', max: '+5d' } }]);
    const bad = await api.dateOffsets.set('shop-api', 'eta', '+5d', '+1d').catch((e: unknown) => e);
    expect(bad).toBeInstanceOf(ApiError);
    expect(bad).toMatchObject({ status: 422, serverCode: 'invalid_offset' });
    expect(await api.dateOffsets.set('shop-api', 'eta', '+2d', '+3d')).toMatchObject({ group: 'shop-api', field: 'eta', min: '+2d', max: '+3d', updatedBy: 'olga.operator' });
    expect(await api.dateOffsets.list('shop-api')).toHaveLength(1);
    expect(await api.dateOffsets.list('legacy')).toEqual([]);
    await api.demo!.loginAs('publisher');
    expect(await api.dateOffsets.list('shop-api')).toHaveLength(1);
    expect(await api.dateOffsets.remove('shop-api', 'eta').catch((e: ApiError) => e.code)).toBe('forbidden');
    await api.demo!.loginAs('rule-reviewer');
    await api.dateOffsets.remove('shop-api', 'eta');
    expect(await api.dateOffsets.list('shop-api')).toEqual([]);
  });
});

const page = (p: Partial<ThirdPartyPage> = {}): ThirdPartyPage => ({ ...demoPaymentPage(), ...p });

describe('third-party pages', () => {
  it('know the placeholders of the mock', () => {
    expect(badPlaceholder('{ref}/{action}/{now.date}/{query.paymentId}/{value.code}/{customer.name}/{uuid}')).toBeNull();
    expect(badPlaceholder('{ref.x}')).toBe('{ref.x}');
    expect(badPlaceholder('{query}')).toBe('{query}');
    expect(badPlaceholder('{now.week}')).toBe('{now.week}');
    expect(badPlaceholder('{customer.email}')).toBe('{customer.email}');
    expect(badPlaceholder('{order}')).toBe('{order}');
  });
  it('need a fixed origin for the callback', () => {
    expect(fixedOrigin('https://shop.test/api/notify?ref={ref}')).toBe(true);
    expect(fixedOrigin('https://shop.test')).toBe(true);
    expect(fixedOrigin('https://{query.host}/x')).toBe(false);
    expect(fixedOrigin('https://shop.test{ref}')).toBe(false);
    expect(fixedOrigin('ftp://shop.test/')).toBe(false);
    expect(fixedOrigin('/relative')).toBe(false);
  });
  it('accept the demo page and find what the server would refuse', () => {
    expect(pageProblems(page(), [], true)).toEqual([]);
    expect(pageProblems(page(), [], false).map((p) => p.code)).toEqual(['hmacKey']);
    const codes = (p: ThirdPartyPage, others: ThirdPartyPage[] = []) => pageProblems(p, others, true).map((x) => x.code);
    expect(codes(page({ id: 'Pay' }))).toEqual(['id']);
    expect(codes(page(), [page()])).toEqual(['idTaken']);
    expect(codes(page({ title: ' ' }))).toEqual(['title']);
    expect(codes(page({ buttons: [] }))).toEqual(['buttons', 'autoAction']);
    expect(codes(page({ buttons: [{ action: 'ok', label: 'Ok' }, { action: 'ok', label: 'Ok' }], auto: undefined }))).toEqual(['action']);
    expect(codes(page({ return_url: 'https://{query.host}/back' }))).toEqual(['returnHosts']);
    expect(codes(page({ return_url: 'https://{query.host}/back', return_hosts: ['shop.test'] }))).toEqual([]);
    expect(codes(page({ return_url: 'shop.test/back' }))).toEqual(['returnUrl']);
    expect(codes(page({ callback: { method: 'POST', url: '{query.notify}' } }))).toEqual(['callbackUrl']);
    expect(codes(page({ callback: { method: 'POST', url: 'https://shop.test/n', body: '{order.id}' } }))).toEqual(['placeholder']);
    expect(codes(page({ links: [{ service: 'payments-ext', op: 'post /x', path: 'redirectUrl' }] }))).toEqual(['linkOp', 'linkPath']);
    expect(codes(page({ auto: { 'Not A Scenario': 'approve', '*': 'refund' } }))).toEqual(['autoKey', 'autoAction']);
  });
  it('clean a page before it is sent and read the values of a button', () => {
    const p = cleanPage({ ...newPage(['pay']), title: ' Firma ', buttons: [{ action: 'sign', label: 'Firma', values: {} }], show: [' ', 'doc'], return_hosts: [] });
    expect(p).toEqual({ id: 'pay-2', title: 'Firma', ref: '{query.ref}', show: ['doc'], buttons: [{ action: 'sign', label: 'Firma' }] });
    expect(parseValues('code=AUTHORISED; reason = ok; broken')).toEqual({ code: 'AUTHORISED', reason: 'ok' });
    expect(valuesText({ code: 'AUTHORISED', reason: 'ok' })).toBe('code=AUTHORISED; reason=ok');
    expect(parseList(' amount, ,order ')).toEqual(['amount', 'order']);
  });
  it('demo: the keys never come back, an empty key keeps the stored one, a new signed page needs one', async () => {
    const api = createMockApi({ latencyMs: 0, storage: null });
    await api.demo!.loginAs('auditor');
    const v = await api.mocks.pages('shop-api');
    expect(v.pages.map((p) => p.id)).toEqual(['pay']);
    expect(v.pages[0].callback?.hmac?.key).toBe('');
    expect(await api.mocks.setPages('shop-api', v.pages).catch((e: ApiError) => e.code)).toBe('forbidden');
    await api.demo!.loginAs('operator');
    expect((await api.mocks.setPages('shop-api', v.pages)).updatedBy).toBe('olga.operator');
    const sign = { ...page({ id: 'sign', title: 'Firma elettronica', auto: undefined, links: undefined }) };
    const refused = await api.mocks.setPages('shop-api', [...v.pages, sign]).catch((e: unknown) => e);
    expect(refused).toMatchObject({ status: 422, serverCode: 'invalid_pages' });
    expect((refused as ApiError).message).toContain('pages[1] (sign)');
    sign.callback = { ...sign.callback!, hmac: { ...sign.callback!.hmac!, key: 'test-key-1234' } };
    const saved = await api.mocks.setPages('shop-api', [...v.pages, sign]);
    expect(saved.pages.map((p) => [p.id, p.callback?.hmac?.key])).toEqual([
      ['pay', ''],
      ['sign', ''],
    ]);
    expect(await api.mocks.pages('legacy')).toEqual({ group: 'legacy', pages: [] });
  });
});

describe('third-party pages: linked object and return URL from the request', () => {
  const base = (): ThirdPartyPage => ({
    id: 'pay',
    title: 'Pagamento',
    return_url: '{link.return}',
    return_hosts: ['app.test'],
    buttons: [{ action: 'approve', label: 'Approva', set: { status: '{value.code}', paid: true } }],
    links: [{ service: 'pay-ext', op: 'POST /v1/sessions', path: '$.redirectUrl', ref_path: '$.id', entity: 'payment', return_from: { from: 'req.body', path: '$.returnUrl' } }],
  });
  it('accepts link.return, set fields and return_from', () => {
    expect(badPlaceholder('{link.return}')).toBeNull();
    expect(badPlaceholder('{link.other}')).toBe('{link.other}');
    expect(pageProblems(base())).toEqual([]);
    const c = cleanPage(base());
    expect(c.buttons[0].set).toEqual({ status: '{value.code}', paid: true });
    expect(c.links![0]).toMatchObject({ entity: 'payment', return_from: { from: 'req.body', path: '$.returnUrl' } });
  });
  it('finds the problems the mock would refuse', () => {
    const p = base();
    p.buttons[0].set = { 'a..b': 1, ok: '{nope}' };
    p.links![0].ref_path = undefined;
    p.links![0].return_from = { from: 'req.query', name: 'bad name' };
    expect(pageProblems(p).map((x) => x.code)).toEqual(['setField', 'placeholder', 'linkReturnFrom', 'linkEntityRef']);
  });
  it('reads and writes the set text with types', () => {
    const v = parseSet('status=AUTHORISED; paid=true; amount=10.5; code=007; none=null');
    expect(v).toEqual({ status: 'AUTHORISED', paid: true, amount: 10.5, code: '007', none: null });
    expect(parseSet(setText(v))).toEqual(v);
  });
});
