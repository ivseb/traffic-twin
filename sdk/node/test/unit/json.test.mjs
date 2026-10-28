import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalNumber, lexemeWithinLimits, nodeToOut, parseJson, writeCanonical } from '../../dist/esm/sanitizer/json.js';

const p = (s) => parseJson(Buffer.isBuffer(s) ? s : Buffer.from(s, 'utf8'));

test('canonical numbers (sanitizer.md 10.2)', () => {
  const cases = {
    '1.50': '1.5', '15e-1': '1.5', '-0.0': '0', '1E3': '1000', '184': '184', '73.40': '73.4', '0.0015': '0.0015',
    '1000000': '1000000', '1e21': '1e+21', '1e20': '100000000000000000000', '1.5e-7': '1.5e-7', '0.000001': '0.000001',
    '123456789012345678901234567890': '1.2345678901234567890123456789e+29', '-12.500e2': '-1250', '0e5': '0',
  };
  for (const [lex, want] of Object.entries(cases)) assert.equal(canonicalNumber(lex), want, lex);
});

test('lexeme limits (5.3)', () => {
  assert.ok(lexemeWithinLimits('1e9999'));
  assert.ok(lexemeWithinLimits('1e-0009999'));
  assert.ok(!lexemeWithinLimits('1e10000'));
  assert.ok(!lexemeWithinLimits('1'.repeat(65)));
});

test('strict RFC 8259 parsing', () => {
  for (const bad of ['', ' ', '{"a":1,}', '[1,]', '{a:1}', "{'a':1}", 'NaN', '01', '1.', '.5', '+1', '1e', 'tru', 'True',
    '{"a":1}{"b":2}', '"\\x"', '"\\u12"', '"a\nb"', '/*c*/1', '[1 2]']) {
    assert.throws(() => p(bad), undefined, JSON.stringify(bad));
  }
  assert.throws(() => p(Buffer.from([0xef, 0xbb, 0xbf, 0x31])), undefined, 'BOM');
  assert.throws(() => p(Buffer.from([0x22, 0xc0, 0xaf, 0x22])), undefined, 'overlong');
  assert.throws(() => p(Buffer.from([0x22, 0xed, 0xa0, 0x80, 0x22])), undefined, 'CESU surrogate');
  assert.deepEqual(p(' {"a" : [1, 2.50, -0, true, false, null]} '), {
    k: 'o',
    m: [[{ k: 's', s: 'a', bad: false }, { k: 'a', a: [{ k: 'n', lex: '1' }, { k: 'n', lex: '2.50' }, { k: 'n', lex: '-0' }, { k: 'b', v: true }, { k: 'b', v: false }, { k: 'z' }] }]],
  });
});

test('lone surrogates are flagged, pairs are joined', () => {
  assert.equal(p('"\\ud800"').bad, true);
  assert.equal(p('"\\udc00x"').bad, true);
  const ok = p('"\\ud83d\\ude00"');
  assert.equal(ok.bad, false);
  assert.equal(ok.s, '\u{1F600}');
});

test('deep nesting is validated iteratively', () => {
  const deep = '['.repeat(100000) + ']'.repeat(100000);
  assert.doesNotThrow(() => p(deep));
  assert.throws(() => p('['.repeat(100000) + ']'.repeat(99999)));
});

test('tt-cjson writer: sorted keys, lowercase \\u escapes, no short escapes', () => {
  const s = writeCanonical(nodeToOut(p('{"b":"\\n\\u00e9\\u007f/\\"","a":[1.0,{"y":1,"x":2}],"\\u00e9":null}')));
  assert.equal(s, '{"a":[1,{"x":2,"y":1}],"b":"\\u000a\\u00e9\\u007f/\\"","\\u00e9":null}');
  assert.equal(writeCanonical(nodeToOut(p('"\\ud83d\\ude00"'))), '"\\ud83d\\ude00"');
});
