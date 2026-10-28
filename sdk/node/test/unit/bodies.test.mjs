// Spec v1.19 (sanitizer.md 22): the XML reader, the multipart parser, base64 documents,
// large bodies and the `bodies` / code(alnum) policy fields. The vectors (2200-2453) are the
// normative check; these tests cover hostile inputs and edge cases around them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  InvalidMultipart, InvalidXml, base64Doc, mediaParams, nsPattern, parseMultipart, parseXml, xmlValue,
} from '../../dist/esm/sanitizer/bodies.js';
import { Sanitizer } from '../../dist/esm/sanitizer/sanitizer.js';
import { Policy, Refused, parseKeyRing, selectKey, validateBodySchema } from '../../dist/esm/sanitizer/policy.js';
import { Lex, nodeToPlain, parseJson } from '../../dist/esm/sanitizer/json.js';
import { ROOT } from '../helpers/procs.mjs';

const CONF = join(ROOT, '..', '..', 'conformance');
const KEY = 'k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const L = (n) => new Lex(String(n));
const BODIES_ON = { xml: true, multipart: true, docs: true, max_large_body_bytes: L(0), large_array: L(0), large_nested_array: L(0) };

function policy(extra = {}) {
  const base = nodeToPlain(parseJson(readFileSync(join(CONF, 'policies', 'empty.json'))), true);
  return new Policy({ ...base, bodies: BODIES_ON, ...extra });
}

function run(p, ct, body, extraHeaders = []) {
  const s = new Sanitizer(p, selectKey(parseKeyRing(KEY), p));
  const res = s.run({
    dir: 'inbound', service_name: 'shop-api', method: 'POST', raw_path: Buffer.from('/x'),
    req_headers: [['content-type', Buffer.from(ct)], ...extraHeaders], req_body: Buffer.from(body), status: 200,
  }, Date.parse('2026-10-21T08:00:00Z'));
  assert.equal(res.outcome, 'event');
  return JSON.parse(res.canonical).req;
}

const invalidXml = (doc) => assert.throws(() => parseXml(Buffer.from(doc)), InvalidXml, doc.slice(0, 80));

// --- XML (22.2) ------------------------------------------------------------------------

test('XML: DTDs, entities and external references are refused, never resolved', () => {
  invalidXml('<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>');
  invalidXml('<?xml version="1.0"?><!DOCTYPE a SYSTEM "http://evil.example/a.dtd"><a/>');
  invalidXml('<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><a>&lol2;</a>');
  invalidXml('<a>&nbsp;</a>');
  invalidXml('<a>&lol</a>');
  invalidXml('<a>AT&T</a>');
  invalidXml('<a><!ENTITY x "y"></a>');
  invalidXml('<a><!DOCTYPE b></a>');
  invalidXml('<a b="&ext;"/>');
  invalidXml('<a>&#0;</a>');
  invalidXml('<a>&#x110000;</a>');
  invalidXml('<a>&#xD800;</a>');
  invalidXml('<a>&#99999999999999999999999;</a>');
  invalidXml('<a>&#X41;</a>');
  assert.equal(xmlValue(parseXml(Buffer.from('<a>&lt;&amp;&#65;&#x42;&#x1F600;</a>'))), '<&AB\u{1F600}');
});

test('XML: nesting is bounded at 256 elements', () => {
  const nest = (n) => '<a>'.repeat(n) + '</a>'.repeat(n);
  assert.doesNotThrow(() => parseXml(Buffer.from(nest(256))));
  invalidXml(nest(257));
  invalidXml(nest(100000)); // no recursion: a deep document fails fast, without a stack overflow
});

test('XML: strict syntax (roots, names, attributes, characters, sections)', () => {
  invalidXml('');
  invalidXml('   ');
  invalidXml('<a/><b/>');
  invalidXml('text<a/>');
  invalidXml('<a/>text');
  invalidXml('<a>');
  invalidXml('<a></b>');
  invalidXml('<a b="1"c="2"/>');
  invalidXml('<a b="1" b="2"/>');
  invalidXml('<a b="<"/>');
  invalidXml('<a b=1/>');
  invalidXml('<1a/>');
  invalidXml('<a:b:c/>');
  invalidXml('<p:a/>');
  invalidXml('<a p:b="1"/>');
  invalidXml('<a xmlns:="u"/>');
  invalidXml('<a>\u0001</a>');
  invalidXml('<a>￾</a>');
  invalidXml('<a><![CDATA[x</a>');
  invalidXml('<a><!-- x </a>');
  assert.throws(() => parseXml(Buffer.from([0x3c, 0x61, 0x3e, 0xff, 0x3c, 0x2f, 0x61, 0x3e])), InvalidXml, 'not UTF-8');
  // Accepted: BOM, prolog, comments, PIs, CDATA, CR LF, xml prefix, single quotes.
  const root = parseXml(Buffer.from('﻿<?xml version="1.0"?><!-- c --><r xml:lang=\'it\' a="x\ty"><![CDATA[<raw>]]>t\r\n<?pi?></r><!-- e -->'));
  assert.deepEqual(xmlValue(root), { members: [['@lang', 'it'], ['@a', 'x y'], ['#text', '<raw>t\n']] });
});

test('XML: tree mapping, repeated elements and namespaces', () => {
  const root = parseXml(Buffer.from('<s:E xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:B><i id="1">x</i><i>y</i><j/></s:B></s:E>'));
  assert.equal(root.local, 'E');
  assert.deepEqual(xmlValue(root), { members: [['B', { members: [['i', [{ members: [['@id', '1'], ['#text', 'x']] }, 'y']], ['j', '']] }]] });
  assert.equal(nsPattern(''), 'ns:{none}');
  assert.equal(nsPattern('http://a.example/customers/3912345678/x'), 'ns:http://a.example/customers/{*}/x');
  assert.equal(nsPattern('urn:9f8e7d6c5b4a3f2e:v1'), 'ns:urn:{*}:v1');
  assert.equal(nsPattern('mailto:mario.rossi@example.com'), 'ns:{*}');
  assert.equal(nsPattern('http://a.example/' + 'x'.repeat(600)), 'ns:{*}');
});

test('XML in the sanitizer: invalid documents give trunc:invalid-xml, values never leave', () => {
  const p = policy();
  const bad = run(p, 'application/xml', '<!DOCTYPE a [<!ENTITY x "giulia.neri">]><a>&x;</a>');
  assert.equal(bad.body, 'trunc:invalid-xml');
  assert.equal(bad.fmt, 'xml');
  assert.equal(bad.xmlns, undefined);
  const ok = run(p, 'text/xml; charset=utf-8', '<order id="ORD-2026000184"><customer>giulia.neri@example.com</customer><n>3912345678</n></order>',
    [['soapaction', Buffer.from('"http://ws.example/orders/v2/GetOrder"')]]);
  assert.equal(ok.fmt, 'xml');
  assert.equal(ok.soap_action, 'GetOrder');
  const text = JSON.stringify(ok);
  for (const secret of ['ORD-2026000184', 'giulia', '3912345678']) assert.ok(!text.includes(secret), text);
  // XML off: the same body is not parsed and has no fmt.
  const off = run(policy({ bodies: { ...BODIES_ON, xml: false } }), 'application/xml', '<a>x</a>');
  assert.equal(off.body, 'drop:bytes:l8');
  assert.equal(off.fmt, undefined);
  assert.equal(off.soap_action, undefined);
});

// --- multipart (22.3) --------------------------------------------------------------------

const mp = (s) => Buffer.from(s.replace(/\n/g, '\r\n'), 'latin1');
const invalidMp = (body, boundary = 'b') => assert.throws(() => parseMultipart(mp(body), boundary), InvalidMultipart, body.slice(0, 60));

test('multipart: framing and part headers', () => {
  const parts = parseMultipart(mp('pre\n--b \t\nContent-Disposition: FORM-DATA; name="a\\"q"; filename=x.pdf\ncontent-disposition: form-data; name=other\n'
    + 'Content-Type: Application/PDF; x=1\n\n%PDF-1\n\n--b\nContent-Disposition: form-data; name=plain ; flag\n\n\n--b--\nepilogue'), 'b');
  assert.deepEqual(parts.map((p) => [p.name, p.isFile, p.content.toString('latin1'), p.ct]), [
    ['a"q', true, '%PDF-1\r\n', 'application/pdf'], // first header occurrence wins; content keeps its own CR LF
    ['plain', false, '', null],
  ]);
});

test('multipart: edge cases are refused', () => {
  invalidMp('--b\nContent-Disposition: form-data; name="a"\n\nx\n'); // no close delimiter
  invalidMp('--b\n\nx\n--b--'); // no content-disposition
  invalidMp('--b\nContent-Disposition: attachment; name="a"\n\nx\n--b--');
  invalidMp('--b\nContent-Disposition: form-data; filename="a"\n\nx\n--b--'); // no name
  invalidMp('--b\nContent-Disposition: form-data; name="a\n\nx\n--b--'); // unterminated quote
  invalidMp('--b\nContent-Disposition: form-data; name="a"x\n\nx\n--b--');
  invalidMp('--b\nContent-Disposition: form-data;\n name="a"\n\nx\n--b--'); // continuation line
  invalidMp('--b\nBad Header: 1\nContent-Disposition: form-data; name="a"\n\nx\n--b--');
  invalidMp('--bx\nContent-Disposition: form-data; name="a"\n\nx\n--b--'); // garbage after the delimiter
  assert.throws(() => parseMultipart(mp('--b\n\nx\n--b--'), undefined), InvalidMultipart, 'no boundary');
  invalidMp('--b \nContent-Disposition: form-data; name="a"\n\nx\n--b--', 'b ');
  invalidMp('x', 'b'.repeat(71));
  assert.deepEqual(parseMultipart(mp('--b--'), 'b'), []);
});

test('multipart: file parts leave only as drop:file, fields follow the form rules', () => {
  assert.equal(mediaParams(Buffer.from('multipart/form-data; Boundary="x y"; boundary=z')).get('boundary'), 'x y');
  const body = mp('--XyZ\nContent-Disposition: form-data; name="note"\n\ngiulia.neri\n'
    + '--XyZ\nContent-Disposition: form-data; name="doc"; filename="tax-3912345678.pdf"\nContent-Type: application/octet-stream\n\n%PDF-1.7 secret\n'
    + '--XyZ\nContent-Disposition: form-data; name="csv"; filename*=UTF-8\'\'a.csv\nContent-Type: text/csv\n\nname,iban\n'
    + '--XyZ\nContent-Disposition: form-data; name="code"\n\nR\n--XyZ--\n');
  const req = run(policy({ global: { request: { body: [{ path: '$.*', action: { action: 'keep' } }] } } }),
    'multipart/form-data; boundary=XyZ', body);
  assert.equal(req.fmt, 'multipart');
  assert.deepEqual(req.body, {
    note: ['keep:giulia.neri'], doc: ['drop:file:pdf:l1k'], csv: ['drop:file:csv:l1k'], code: ['keep:R'],
  });
  const bad = run(policy(), 'multipart/form-data', body);
  assert.equal(bad.body, 'trunc:invalid-multipart');
  assert.equal(bad.fmt, 'multipart');
});

// --- base64 documents (22.4) ---------------------------------------------------------------

test('base64 documents: kinds, alphabets, data URIs and non-documents', () => {
  const b64 = (b) => Buffer.from(b).toString('base64');
  const pdf = Buffer.concat([Buffer.from('%PDF-1.7\n'), Buffer.alloc(2000, 0x41)]);
  assert.equal(base64Doc(b64(pdf)), 'drop:doc:pdf:l16k');
  assert.equal(base64Doc(Buffer.from(pdf).toString('base64url')), 'drop:doc:pdf:l16k');
  assert.equal(base64Doc('data:application/pdf;base64,' + b64(pdf)), 'drop:doc:pdf:l16k');
  assert.equal(base64Doc('data:application/pdf,' + b64(pdf)), null);
  const zip = (name) => b64(Buffer.concat([Buffer.from('PK\x03\x04', 'latin1'), Buffer.alloc(30), Buffer.from(name)]));
  assert.equal(base64Doc(zip('word/document.xml')), 'drop:doc:docx:l1k');
  assert.equal(base64Doc(zip('xl/workbook.xml')), 'drop:doc:xlsx:l1k');
  assert.equal(base64Doc(zip('ppt/presentation.xml')), 'drop:doc:pptx:l1k');
  assert.equal(base64Doc(zip('other.txt')), 'drop:doc:zip:l1k');
  assert.equal(base64Doc(b64(Buffer.from('just some text that is long enough'))), null);
  assert.equal(base64Doc(b64(pdf).slice(0, 15)), null, 'under 16 characters');
  assert.equal(base64Doc(b64(pdf) + ' '), null);
  assert.equal(base64Doc(b64(pdf).slice(0, 17)), null, 'length mod 4 = 1');
  assert.equal(base64Doc('JVBERi0xLjcKQUFBQUE='), 'drop:doc:pdf:l1k');
  assert.equal(base64Doc('JVBERi0xLjcKQUFBQUE'), 'drop:doc:pdf:l1k');
  assert.equal(base64Doc('JVBERi0xLjcKQUFBQUE=='), null, 'padding with a length not multiple of 4');
  assert.equal(base64Doc('JVBERi0xLjcKQUFBQUE==='), null, 'three padding characters');
});

// --- large bodies (22.5) and the capture limit -----------------------------------------------

test('large bodies: array caps by array ancestry; the capture keeps max(limits) + 1 bytes', () => {
  const p = policy({
    limits: { max_body_bytes: L(64), max_depth: L(32), max_array: L(32), max_keys: L(256), keep_max_bytes: L(64) },
    bodies: { ...BODIES_ON, max_large_body_bytes: L(4096), large_array: L(2), large_nested_array: L(1) },
  });
  assert.equal(p.captureLimit, 4097);
  assert.equal(policy().captureLimit, 1048577);
  const body = JSON.stringify({ items: [{ c: [1, 2, 3] }, { c: [4] }, { c: [] }], pad: 'x'.repeat(100) });
  const req = run(p, 'application/json', body);
  assert.deepEqual(req.body.items, [{ c: ['drop:int', 'trunc:n:l8'] }, { c: ['drop:int'] }, 'trunc:n:l8']);
  // Not parsed by type: still trunc:size above max_body_bytes.
  assert.equal(run(p, 'text/plain', body).body, 'trunc:size');
});

// --- policy fields -------------------------------------------------------------------------

test('policy body: bodies needs every field in range; code takes only shape alnum', () => {
  const base = JSON.parse(readFileSync(join(CONF, 'policies', 'empty.json'), 'utf8'));
  const check = (extra) => validateBodySchema(nodeToPlain(parseJson(Buffer.from(JSON.stringify({ ...base, ...extra }))), true));
  const bodies = { xml: true, multipart: false, docs: true, max_large_body_bytes: 0, large_array: 0, large_nested_array: 1024 };
  const rule = (action, path = '$.a') => ({ global: { request: { body: [{ path, action }] } } });
  assert.doesNotThrow(() => check({ bodies }));
  assert.doesNotThrow(() => check({ bodies: { ...bodies, max_large_body_bytes: 67108864 } }));
  assert.doesNotThrow(() => check(rule({ action: 'code', shape: 'alnum' })));
  assert.doesNotThrow(() => check(rule({ action: 'keep' }, '$.Envelope.Body.order.@id')));
  assert.doesNotThrow(() => check(rule({ action: 'keep' }, '$.order.#text')));
  const refused = (extra, why) => assert.throws(() => check(extra), (e) => e instanceof Refused && e.code === 'policy_rejected', why);
  refused({ bodies: { ...bodies, max_large_body_bytes: 67108865 } }, 'large limit');
  refused({ bodies: { ...bodies, large_array: 1025 } }, 'large_array');
  refused({ bodies: { ...bodies, large_nested_array: -1 } }, 'negative');
  refused({ bodies: { ...bodies, xml: 1 } }, 'xml not boolean');
  refused({ bodies: { ...bodies, extra: true } }, 'unknown field');
  const { docs, ...missing } = bodies;
  void docs;
  refused({ bodies: missing }, 'missing field');
  refused(rule({ action: 'code', shape: 'digits' }), 'unknown shape');
  refused(rule({ action: 'keep', shape: 'alnum' }), 'shape on keep');
  refused(rule({ action: 'code', shape: 'alnum' }, '$.*'), 'H2 with code(alnum)');
  refused({ global: { request: { headers: { authorization: { action: 'code', shape: 'alnum' } } } } }, 'H1 with code(alnum)');
  refused(rule({ action: 'keep' }, '$.#txt'), 'bad #text step');
  refused(rule({ action: 'keep' }, '$.@'), 'empty attribute');
  assert.equal(new Policy(check({})).bodies.xml, false);
  assert.equal(new Policy(check({})).captureLimit, 1048577);
});
