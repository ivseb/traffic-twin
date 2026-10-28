import { describe, expect, it } from 'vitest';
import type { PolicySuggestion } from './api/types';
import { applyGroupAction, credentialLikeName, fieldGroup, groupActions, identityObserveSafe, valueReasonsOf } from './observe';

const sg = (over: Partial<PolicySuggestion>): PolicySuggestion => ({
  id: 'sg-x',
  service: 'shop-api',
  op: 'POST /orders',
  part: 'response',
  path: '$.id',
  shape: 'drop:str:l32',
  observed: 400,
  distinct: 380,
  suggestion: { action: 'hmac', arg: 'order' },
  current: { action: 'drop' },
  reason: '',
  ...over,
});

describe('observe-safe classification (policy.md §7)', () => {
  it('drop and hmac open no values; keep and bucket do', () => {
    expect(valueReasonsOf([{ change: 'added', where: 'a', from: 'drop', to: 'hmac(order)' }])).toEqual([]);
    expect(valueReasonsOf([{ change: 'removed', where: 'a', from: 'keep', to: 'drop' }])).toEqual([]);
    expect(valueReasonsOf([{ change: 'changed', where: 'a', from: 'keep', to: 'hmac(order)' }])).toEqual([]);
    expect(valueReasonsOf([{ change: 'added', where: 'a', from: 'drop', to: 'keep' }])).toEqual([{ code: 'keep', where: 'a' }]);
    expect(valueReasonsOf([{ change: 'changed', where: 'a', from: 'hmac(order)', to: 'keep' }])).toEqual([{ code: 'keep', where: 'a' }]);
    expect(valueReasonsOf([{ change: 'added', where: 'b', from: 'drop', to: 'bucket(num, [0, 50])' }])).toEqual([{ code: 'bucket', where: 'b' }]);
  });
  it('coarser bands and keep -> bucket close; finer bands open', () => {
    expect(valueReasonsOf([{ change: 'changed', where: 'b', from: 'bucket(num, [0, 50, 100])', to: 'bucket(num, [0, 100])' }])).toEqual([]);
    expect(valueReasonsOf([{ change: 'changed', where: 'b', from: 'keep', to: 'bucket(num, [0, 100])' }])).toEqual([]);
    expect(valueReasonsOf([{ change: 'changed', where: 'b', from: 'bucket(num, [0, 100])', to: 'bucket(num, [0, 50, 100])' }])).toEqual([{ code: 'bucket', where: 'b' }]);
  });
  it('leaving the strict hosts mode opens; entering it closes', () => {
    expect(valueReasonsOf([{ change: 'changed', where: 'hosts.discovery', from: 'off', to: 'auto' }])).toEqual([{ code: 'hosts_discovery', where: 'hosts.discovery' }]);
    expect(valueReasonsOf([{ change: 'changed', where: 'hosts.discovery', from: 'auto', to: 'off' }])).toEqual([]);
  });
  it('any header that is not a credential is an observe-safe identity; cookies and credentials are not', () => {
    expect(identityObserveSafe('header', 'Authorization', 'sub')).toBe(true);
    expect(identityObserveSafe('header', 'authorization', 'member_no')).toBe(true);
    expect(identityObserveSafe('header', 'authorization', '')).toBe(false);
    for (const n of ['x-user-id', 'x-kunden-nr', 'X-Codice-Utente', 'x-qz-7', 'personId', 'x-member']) {
      expect(identityObserveSafe('header', n)).toBe(true);
      expect(identityObserveSafe('header', n, 'sub')).toBe(true);
    }
    expect(identityObserveSafe('cookie', 'uid')).toBe(false);
    for (const n of ['x-session', 'x-auth-token', 'x-csrf-token', 'x-client-secret', 'x-tenant-key']) {
      expect(identityObserveSafe('header', n)).toBe(false);
    }
    expect(identityObserveSafe('header', 'x-id-token', 'sub')).toBe(true);
    for (const n of ['cookie', 'set-cookie', 'proxy-authorization', 'x-api-key']) expect(identityObserveSafe('header', n, 'sub')).toBe(false);
    expect(identityObserveSafe('header', '')).toBe(false);
    expect(credentialLikeName('x-keyboard-layout')).toBe(false);
    expect(credentialLikeName('monkey-id')).toBe(false);
    expect(credentialLikeName('sessionid')).toBe(true);
    expect(valueReasonsOf([], { from: 'cookie', name: 'uid' })).toEqual([{ code: 'identity', where: 'identity.subject' }]);
    expect(valueReasonsOf([], { from: 'header', name: 'authorization', claim: 'sub' })).toEqual([]);
  });
});

describe('bulk review groups', () => {
  it('groups the fields by the assistant reason', () => {
    expect(fieldGroup({ reasonCode: 'id' })).toBe('ids');
    expect(fieldGroup({ reasonCode: 'path_id' })).toBe('ids');
    expect(fieldGroup({ reasonCode: 'enum_name' })).toBe('states');
    expect(fieldGroup({ reasonCode: 'amount' })).toBe('numbers');
    expect(fieldGroup({ reasonCode: 'time' })).toBe('dates');
    expect(fieldGroup({ reasonCode: 'personal_name' })).toBe('personal');
    expect(fieldGroup({ reasonCode: 'free' })).toBe('other');
    expect(fieldGroup({})).toBe('other');
    // without a reason (older servers, the demo): from the proposal
    expect(fieldGroup({ suggestion: { action: 'hmac', arg: 'order' } })).toBe('ids');
    expect(fieldGroup({ suggestion: { action: 'keep' } })).toBe('states');
    expect(fieldGroup({ suggestion: { action: 'bucket', arg: '0, 50' } })).toBe('numbers');
  });
  it('one action per group: proposal, all hmac, all drop, as is', () => {
    const s = sg({ current: { action: 'keep' }, suggestion: { action: 'hmac', arg: 'order' } });
    expect(applyGroupAction(s, 'proposal')).toEqual({ action: 'hmac', arg: 'order' });
    expect(applyGroupAction(s, 'drop')).toEqual({ action: 'drop' });
    expect(applyGroupAction(s, 'keep-current')).toEqual({ action: 'keep' });
    expect(applyGroupAction(sg({ suggestion: { action: 'keep' } }), 'hmac')).toEqual({ action: 'hmac', arg: 'id' });
    // personal data can only stay as it is or go to drop
    expect(groupActions('personal')).toEqual(['keep-current', 'drop']);
    expect(groupActions('ids')).not.toContain('hmac');
  });
});
