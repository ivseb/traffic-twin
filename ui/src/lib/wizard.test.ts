import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { clearTokenMeta, clearWizard, clockTime, declareDefault, loadTokenMeta, loadWizard, rememberDeclare, rememberedDeclare, saveTokenMeta, saveWizard, suggestGroup, visibleAssistServices, type WizardState } from './wizard';

function memoryStorage(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k) => m.get(k) ?? null,
    key: (i) => [...m.keys()][i] ?? null,
    removeItem: (k) => void m.delete(k),
    setItem: (k, v) => void m.set(k, String(v)),
  };
}

const base = (over: Partial<WizardState> = {}): WizardState => ({
  step: 4,
  choice: 'sdk-node',
  group: 'shop',
  svcNames: '',
  samplingRate: '1',
  token: null,
  starter: null,
  twin: {},
  twinBefore: {},
  choices: { 'sg-1': { action: 'hmac', arg: 'order' } },
  include: {},
  svcName: { 'host:localhost:8080': 'carrier' },
  svcScheme: { 'host:localhost:8080': 'http' },
  svcBase: {},
  idMode: 'pick',
  idFrom: 'header',
  idName: 'authorization',
  idClaim: 'sub',
  proposal: null,
  hostsCurrent: 'auto',
  hostsMode: 'auto',
  hostsLoaded: false,
  ...over,
});

describe('wizard state in the tab', () => {
  beforeEach(() => vi.stubGlobal('sessionStorage', memoryStorage()));
  afterEach(() => vi.unstubAllGlobals());

  it('survives a reload: what was saved comes back', () => {
    saveWizard(base());
    expect(loadWizard()).toEqual(base());
    clearWizard();
    expect(loadWizard()).toBeNull();
  });
  it('an expired token sends the token steps back to the start, the later steps stay', () => {
    const token = { tokenId: 't', token: 'tte_x', expiresAt: '2000-01-01T00:00:00Z', choice: 'sdk-node' as const, group: 'shop', snippets: [] };
    saveWizard(base({ step: 2, token }));
    expect(loadWizard()).toMatchObject({ step: 0, token: null, group: 'shop' });
    saveWizard(base({ step: 4, token }));
    expect(loadWizard()?.step).toBe(4);
  });
  it('ignores garbage and works without storage', () => {
    sessionStorage.setItem('tt.wizard.v1', '{"step":99}');
    expect(loadWizard()).toBeNull();
    sessionStorage.setItem('tt.wizard.v1', 'not json');
    expect(loadWizard()).toBeNull();
    vi.stubGlobal('sessionStorage', undefined);
    expect(() => saveWizard(base())).not.toThrow();
    expect(loadWizard()).toBeNull();
  });
});

describe('policy assistant: "Declare in the policy"', () => {
  beforeEach(() => vi.stubGlobal('sessionStorage', memoryStorage()));
  afterEach(() => vi.unstubAllGlobals());

  it('defaults to the server preselect, keeps declared services, never checks a stale host', () => {
    expect(declareDefault({ declared: false, preselect: true })).toBe(true);
    expect(declareDefault({ declared: false, preselect: false })).toBe(false);
    // An undeclared host is no longer checked just because it is undeclared.
    expect(declareDefault({ declared: false, preselect: false, stale: false })).toBe(false);
    expect(declareDefault({ declared: false, preselect: true, stale: true })).toBe(false);
    expect(declareDefault({ declared: true, preselect: false })).toBe(true);
    // An older server without preselect: the old default.
    expect(declareDefault({ declared: false })).toBe(true);
  });
  it('does not show a block folded into another one', () => {
    const svcs = [
      { service: 'pay', hostPattern: 'ip:private:9301', mergedPatterns: ['ip:private:9301', 'ip:private:9302'] },
      { service: 'host:ip:private:9301', hostPattern: 'ip:private:9301' },
      { service: 'host:ip:private:9302' },
      { service: 'host:new.example', hostPattern: 'new.example' },
    ];
    expect(visibleAssistServices(svcs).map((s) => s.service)).toEqual(['pay', 'host:new.example']);
    expect(visibleAssistServices(svcs.slice(1)).map((s) => s.service)).toEqual(['host:ip:private:9301', 'host:ip:private:9302', 'host:new.example']);
  });
  it('remembers the choice per policy and service for the session', () => {
    expect(rememberedDeclare('p-shop', 'host:x')).toBeUndefined();
    rememberDeclare('p-shop', 'host:x', false);
    rememberDeclare('p-other', 'host:x', true);
    expect(rememberedDeclare('p-shop', 'host:x')).toBe(false);
    expect(rememberedDeclare('p-other', 'host:x')).toBe(true);
    // A reset of the wizard does not forget it.
    clearWizard();
    expect(rememberedDeclare('p-shop', 'host:x')).toBe(false);
    vi.stubGlobal('sessionStorage', undefined);
    expect(() => rememberDeclare('p-shop', 'host:x', true)).not.toThrow();
    expect(rememberedDeclare('p-shop', 'host:x')).toBeUndefined();
  });
});

describe('the enrollment token: only its metadata outlives the tab', () => {
  beforeEach(() => vi.stubGlobal('localStorage', memoryStorage()));
  afterEach(() => vi.unstubAllGlobals());
  const tok = { tokenId: 'tok-1', group: 'library', choice: 'sdk-python' as const, expiresAt: new Date(Date.now() + 3600_000).toISOString(), createdAt: new Date().toISOString() };

  it('keeps when it was created and when it expires, never the secret', () => {
    saveTokenMeta({ ...tok, token: 'tte_secret' } as typeof tok);
    const raw = localStorage.getItem('tt.wizard.token.v1') ?? '';
    expect(raw).not.toContain('tte_secret');
    expect(loadTokenMeta()).toEqual(tok);
    clearTokenMeta();
    expect(loadTokenMeta()).toBeNull();
  });
  it('forgets a token expired for more than a day, keeps a recently expired one', () => {
    saveTokenMeta({ ...tok, expiresAt: new Date(Date.now() - 600_000).toISOString() });
    expect(loadTokenMeta()?.tokenId).toBe('tok-1');
    saveTokenMeta({ ...tok, expiresAt: new Date(Date.now() - 2 * 24 * 3600_000).toISOString() });
    expect(loadTokenMeta()).toBeNull();
  });
  it('ignores garbage and works without storage', () => {
    localStorage.setItem('tt.wizard.token.v1', '{"tokenId":"x"}');
    expect(loadTokenMeta()).toBeNull();
    vi.stubGlobal('localStorage', undefined);
    expect(() => saveTokenMeta(tok)).not.toThrow();
    expect(loadTokenMeta()).toBeNull();
  });
  it('formats HH:MM and tolerates a bad date', () => {
    expect(clockTime('2026-10-24T10:12:00Z')).toMatch(/\d{1,2}[:.]\d{2}/);
    expect(clockTime('nope')).toBe('');
  });
});

describe('the group name is suggested from the service name, never prefilled', () => {
  it('drops the usual suffix of a service name', () => {
    expect(suggestGroup('library-loans-api')).toBe('library-loans');
    expect(suggestGroup('bookings-api, bookings-worker')).toBe('bookings');
    expect(suggestGroup('Shop_Service')).toBe('shop');
  });
  it('suggests nothing without a usable name', () => {
    expect(suggestGroup('')).toBe('');
    expect(suggestGroup('  ,  ')).toBe('');
    expect(suggestGroup('-api')).toBe('');
  });
});
