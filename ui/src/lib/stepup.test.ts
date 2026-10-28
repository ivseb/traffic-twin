import { describe, expect, it, vi } from 'vitest';
import {
  STEPUP_KEY,
  STEPUP_MAX_AGE_MS,
  beginStepUp,
  bindingOf,
  consumeStepUpReturn,
  parseStepUpQuery,
  peekPending,
  savePending,
  shouldStepUp,
  stepUpUrl,
  stripStepUpQuery,
  takePending,
  type PendingStepUp,
} from './stepup';

function memStore() {
  const m = new Map<string, string>();
  return {
    m,
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
  };
}

const T0 = Date.parse('2026-10-24T09:30:00Z');
const rec = (over: Partial<PendingStepUp> = {}): PendingStepUp => ({
  purpose: 'policy-approve',
  ref: 'p-shop/3',
  hash: '#/sources?tab=policy',
  payload: { kind: 'policy-approve', policyId: 'p-shop', version: 3 },
  at: T0,
  ...over,
});

describe('step-up binding and URL', () => {
  it('binds each purpose to its ref', () => {
    expect(bindingOf({ kind: 'policy-approve', policyId: 'p-shop', version: 3, reason: 'x' })).toEqual({ purpose: 'policy-approve', ref: 'p-shop/3' });
    expect(bindingOf({ kind: 'pack-publish', packId: 'pk-1' })).toEqual({ purpose: 'pack-publish', ref: 'pk-1' });
    expect(bindingOf({ kind: 'quarantine-dismiss', itemId: 'q-12' })).toEqual({ purpose: 'quarantine-dismiss', ref: 'q-12' });
  });
  it('builds the start URL with encoded parameters', () => {
    const u = new URL(stepUpUrl('policy-approve', 'p-shop/3'), 'https://tt.test');
    expect(u.pathname).toBe('/api/v1/auth/oidc/stepup');
    expect(Object.fromEntries(u.searchParams)).toEqual({ purpose: 'policy-approve', ref: 'p-shop/3', return_to: '/' });
  });
});

describe('step-up query', () => {
  it('parses ok and error results', () => {
    expect(parseStepUpQuery('?stepup=ok')).toEqual({ status: 'ok' });
    expect(parseStepUpQuery('?stepup_error=nonce_mismatch')).toEqual({ status: 'error', code: 'nonce_mismatch' });
    expect(parseStepUpQuery('?stepup_error=%3Cscript%3E')).toEqual({ status: 'error', code: 'unknown' });
    expect(parseStepUpQuery('?stepup=ok&stepup_error=idp_error')).toEqual({ status: 'error', code: 'idp_error' });
    expect(parseStepUpQuery('')).toBeNull();
    expect(parseStepUpQuery('?stepup=maybe')).toBeNull();
  });
  it('strips only its own parameters', () => {
    expect(stripStepUpQuery('?stepup=ok')).toBe('');
    expect(stripStepUpQuery('?a=1&stepup_error=x')).toBe('?a=1');
  });
});

describe('pending record', () => {
  it('round-trips and is removed by take', () => {
    const s = memStore();
    expect(savePending(rec(), s)).toBe(true);
    expect(peekPending(T0 + 1000, s)).toEqual(rec());
    expect(takePending(T0 + 1000, s)).toEqual(rec());
    expect(s.m.has(STEPUP_KEY)).toBe(false);
  });
  it('expires after 10 minutes and ignores records from the future', () => {
    const s = memStore();
    savePending(rec(), s);
    expect(peekPending(T0 + STEPUP_MAX_AGE_MS, s)).not.toBeNull();
    expect(peekPending(T0 + STEPUP_MAX_AGE_MS + 1, s)).toBeNull();
    expect(peekPending(T0 - 120_000, s)).toBeNull();
  });
  it('rejects malformed or inconsistent records', () => {
    const s = memStore();
    s.setItem(STEPUP_KEY, '{not json');
    expect(peekPending(T0, s)).toBeNull();
    s.setItem(STEPUP_KEY, JSON.stringify(rec({ ref: 'p-other/9' })));
    expect(peekPending(T0, s)).toBeNull();
    s.setItem(STEPUP_KEY, JSON.stringify({ ...rec(), purpose: 'delete-everything' }));
    expect(peekPending(T0, s)).toBeNull();
  });
  it('survives a storage that throws', () => {
    const bad = {
      getItem: () => {
        throw new Error('blocked');
      },
      setItem: () => {
        throw new Error('blocked');
      },
      removeItem: () => {
        throw new Error('blocked');
      },
    };
    expect(savePending(rec(), bad)).toBe(false);
    expect(takePending(T0, bad)).toBeNull();
  });
});

describe('begin and return', () => {
  it('saves the call with the current hash and navigates to the start URL', () => {
    const assign = vi.fn();
    const s = memStore();
    beginStepUp({ kind: 'pack-publish', packId: 'pk-1', reason: 'r' }, { location: { hash: '#/packs/pk-1', assign } as unknown as Location }, T0, s);
    expect(assign).toHaveBeenCalledWith(stepUpUrl('pack-publish', 'pk-1', '/'));
    const saved = peekPending(T0, s);
    expect(saved).toMatchObject({ purpose: 'pack-publish', ref: 'pk-1', hash: '#/packs/pk-1', payload: { kind: 'pack-publish', packId: 'pk-1', reason: 'r' } });
  });
  it('restores the saved hash, cleans the URL and returns the pending call', () => {
    const s = memStore();
    savePending(rec(), s);
    const replaceState = vi.fn();
    const w = { location: { search: '?stepup=ok', pathname: '/', hash: '' }, history: { state: null, replaceState } } as unknown as Window;
    const back = consumeStepUpReturn(w, T0 + 5000, s);
    expect(back).toEqual({ result: { status: 'ok' }, pending: rec() });
    expect(replaceState).toHaveBeenCalledWith(null, '', '/#/sources?tab=policy');
    expect(s.m.has(STEPUP_KEY)).toBe(false);
    // Just completed: a repeated stepup_required for the same change must not loop.
    expect(shouldStepUp('policy-approve', 'p-shop/3', T0 + 6000)).toBe(false);
    expect(shouldStepUp('pack-publish', 'pk-1', T0 + 6000)).toBe(true);
    expect(shouldStepUp('policy-approve', 'p-shop/3', T0 + 5000 + 61_000)).toBe(true);
  });
  it('reports an error result and clears the record; nothing to do without a result', () => {
    const s = memStore();
    savePending(rec(), s);
    const replaceState = vi.fn();
    const w = { location: { search: '?stepup_error=subject_mismatch', pathname: '/', hash: '' }, history: { state: null, replaceState } } as unknown as Window;
    expect(consumeStepUpReturn(w, T0, s)).toEqual({ result: { status: 'error', code: 'subject_mismatch' }, pending: rec() });
    expect(s.m.has(STEPUP_KEY)).toBe(false);
    const none = { location: { search: '', pathname: '/', hash: '#/x' }, history: { state: null, replaceState } } as unknown as Window;
    expect(consumeStepUpReturn(none, T0, s)).toBeNull();
  });
});
