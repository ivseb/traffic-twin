import { beforeEach, describe, expect, it } from 'vitest';
import { ALL, MINE, contractHref, inGroups, ruleServices, scope, scopeGroups, scopeLabel, scopeNoGroups, scopeReady, scopeValue, setScope, showGroupColumn } from './scope.svelte';
import { session } from './stores.svelte';
import type { Rule } from './api';

const data = { groups: ['bookings', 'shop'], mine: ['bookings'], services: { 'bookings-api': ['bookings'], 'payments-ext': ['bookings'], 'shop-api': ['shop'], 'shipping-ext': ['shop'], 'host:unlisted': [] } };

describe('group filter', () => {
  beforeEach(() => {
    scope.value = null;
    scope.data = data;
    scope.loaded = false;
    session.user = { id: 'u1', username: 'dev', displayName: 'Dev', roles: ['operator'], authMethod: 'local' };
  });

  it('defaults to the groups the user works with, all groups for an administrator', () => {
    expect(scopeValue()).toBe(MINE);
    session.user = { ...session.user!, roles: ['admin'] };
    expect(scopeValue()).toBe(ALL);
    // «I miei gruppi» also before the user has one (usability test #4, m2): the home page counts nothing then.
    scope.data = { ...data, mine: [] };
    scope.loaded = true;
    session.user = { ...session.user!, roles: ['operator'] };
    expect(scopeValue()).toBe(MINE);
    expect(scopeNoGroups()).toBe(true);
    expect(scopeReady()).toBe(true);
    scope.data = data;
    expect(scopeNoGroups()).toBe(false);
  });

  it('is not ready for a non-admin until the groups are known', () => {
    scope.data = null;
    scope.loaded = false;
    expect(scopeReady()).toBe(false);
    setScope('shop');
    expect(scopeReady()).toBe(true);
    scope.value = null;
    scope.loaded = true;
    expect(scopeReady()).toBe(true);
    session.user = { ...session.user!, roles: ['admin'] };
    scope.loaded = false;
    expect(scopeReady()).toBe(true);
  });

  it('gives the groups the API calls send (null: no group parameter)', () => {
    expect(scopeGroups()).toEqual(['bookings']);
    setScope('shop');
    expect(scopeGroups()).toEqual(['shop']);
    expect(scopeLabel()).toBe('shop');
    setScope(ALL);
    expect(scopeGroups()).toBeNull();
    expect(scopeLabel()).toBe('');
  });

  it('one named group needs no scope data; "mine" does', () => {
    scope.data = null;
    setScope('shop');
    expect(scopeGroups()).toEqual(['shop']);
    setScope(MINE);
    expect(scopeGroups()).toBeNull();
  });

  it('shows the Group column when rows of several groups are listed together', () => {
    setScope('shop');
    expect(showGroupColumn()).toBe(false);
    setScope(ALL);
    expect(showGroupColumn()).toBe(true);
    scope.data = { ...data, mine: ['bookings', 'shop'] };
    setScope(MINE);
    expect(showGroupColumn()).toBe(true);
  });

  it('tells the rows inside the filter (approve buttons only there)', () => {
    setScope('shop');
    expect(inGroups(['shop'])).toBe(true);
    expect(inGroups(['bookings', 'shop'])).toBe(true);
    expect(inGroups(['bookings'])).toBe(false);
    expect(inGroups([])).toBe(false);
    expect(inGroups('shop')).toBe(true);
    expect(inGroups(undefined)).toBe(false);
    setScope(ALL);
    expect(inGroups(['bookings'])).toBe(true);
    expect(inGroups(undefined)).toBe(true);
  });

  it('links the contract of one (group, service)', () => {
    expect(contractHref('host:ip:private:9301', 'shop')).toBe('#/contracts/service/host%3Aip%3Aprivate%3A9301?group=shop');
    expect(contractHref('shop-api')).toBe('#/contracts/service/shop-api');
    expect(contractHref('shop-api', '')).toBe('#/contracts/service/shop-api');
  });

  it('lists the services of a rule', () => {
    const rule = { cause: { service: 'shop-api', op: 'POST /orders', whenStatus: [201], bind: {} }, effects: [{ id: 'e1', entity: 'shipment', kind: 'create', values: {}, target: 'shipping-ext', after: '5m' }] } as unknown as Rule;
    expect(ruleServices(rule)).toEqual(['shop-api', 'shipping-ext']);
  });
});
