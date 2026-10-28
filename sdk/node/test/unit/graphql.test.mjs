import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gqlIsName, gqlNameSafe, gqlShape } from '../../dist/esm/sanitizer/graphql.js';

// Cases from sanitizer.md 5.7.1 and from the Go/Python differential corpus.
const shape = (s) => {
  const r = gqlShape(s);
  return r === null ? null : [r.shape, r.introspection];
};

test('graphql shape: names kept, literals replaced', () => {
  assert.deepEqual(shape('query GetOrder($id: ID!) { order(id: $id) { id status items { sku } } }'),
    ['query GetOrder($id:ID!){order(id:$id){id status items{sku}}}', false]);
  assert.deepEqual(shape('{ order(id: "ORD-123", n: 5, r: 1.5, ok: true, st: SHIPPED, x: null) { id } }'),
    ['{order(id:?s n:?i r:?f ok:?b st:?e x:?n){id}}', false]);
  assert.deepEqual(shape('mutation M($in: [OrderIn!]! = [{note: "urgente"}]) { a: create(in: $in) { ...F } } fragment F on Order { id }'),
    ['mutation M($in:[OrderIn!]!=[{note:?s}]){a:create(in:$in){...F}}fragment F on Order{id}', false]);
  assert.deepEqual(shape('{ o4821553: order(id: 1) { id } }'), ['{*:order(id:?i){id}}', false]);
  assert.deepEqual(shape('﻿# c\n{ a(s: """x \\""" y""", e: 1e5) }'), ['{a(s:?s e:?f)}', false]);
});

test('graphql shape: introspection only', () => {
  assert.deepEqual(shape('query { __schema { types { name } } __typename }'), ['query{__schema{types{name}}__typename}', true]);
  assert.deepEqual(shape('{ __type(name: "X") { name } } fragment F on T { a }'), ['{__type(name:?s){name}}fragment F on T{a}', true]);
  assert.equal(shape('{ __schema: order { id } }')[1], false);
  assert.equal(shape('{ __schema { a } order }')[1], false);
  assert.equal(shape('{ ...F } fragment F on Query { __schema { a } }')[1], false);
});

test('graphql shape: errors and limits', () => {
  for (const s of ['', 'ciao', 'type Query { a: Int }', '{ a(x: 01) }', '{ a(x: 1abc) }', '{ a }}', '{ a(x: "\n") }',
    '{ a(x: "\\q") }', '{}', 'fragment on on X { a }', '{ a. }', '{ è }', 'query ()  { a }']) {
    assert.equal(gqlShape(s), null, JSON.stringify(s));
  }
  // 64 open brackets at most: 32 braces, one parenthesis, then 31 or 32 square brackets.
  assert.notEqual(gqlShape('{a'.repeat(32) + '(x: [' + '['.repeat(30) + ']'.repeat(30) + '])' + '}'.repeat(32)), null);
  assert.equal(gqlShape('{a'.repeat(32) + '(x: [' + '['.repeat(31) + ']'.repeat(31) + '])' + '}'.repeat(32)), null);
  const long = '{ ' + 'abcdefgh '.repeat(3640) + '}';
  assert.notEqual(gqlShape(long), null);
  assert.equal(gqlShape('{ ' + 'abcdefgh '.repeat(3641) + '}'), null);
});

test('graphql name rule', () => {
  assert.ok(gqlNameSafe('order_12345'));
  assert.ok(!gqlNameSafe('order_123456'));
  assert.ok(!gqlNameSafe('deadbeefdeadbeef'));
  assert.ok(gqlNameSafe('deadbeefdeadbee'));
  assert.ok(!gqlNameSafe('a'.repeat(65)));
  assert.ok(gqlIsName('__Type') && !gqlIsName('1a') && !gqlIsName('a-b') && !gqlIsName(''));
});
