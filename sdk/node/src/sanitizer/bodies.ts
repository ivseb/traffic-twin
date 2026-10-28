// Body formats of spec v1.19 (sanitizer.md 22): XML and SOAP (22.2), multipart/form-data
// (22.3), base64 documents and the document size classes (22.4). Pure functions: they never
// see the policy. Mirrors conformance/ref/bodies.py.
//
// The XML reader is a hand-written strict subset of XML 1.0 + Namespaces: no DTD, no entity
// other than the five predefined ones and character references, never a platform XML library
// (hardening: XXE and entity expansion are impossible by construction).

import { decodeUtf8 } from './utf8.js';

// ------------------------------------------------------------------ documents (22.4)

/** 22.4: document class on the decoded length. */
export function docClass(n: number): string {
  if (n <= 1024) return 'l1k';
  if (n <= 16384) return 'l16k';
  if (n <= 131072) return 'l128k';
  if (n <= 1048576) return 'l1m';
  if (n <= 8388608) return 'l8m';
  return 'lmax';
}

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const OLE = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);

function startsWith(b: Uint8Array, prefix: Uint8Array | string, at = 0): boolean {
  const n = prefix.length;
  if (b.length < at + n) return false;
  for (let i = 0; i < n; i++) {
    const c = typeof prefix === 'string' ? prefix.charCodeAt(i) : prefix[i]!;
    if (b[at + i] !== c) return false;
  }
  return true;
}

/** 22.4 point 3 without the zip refinement: kind from the first 12 bytes; 'zip?' for a zip. */
function headKind(b: Uint8Array): string | null {
  if (startsWith(b, '%PDF-')) return 'pdf';
  if (startsWith(b, PNG)) return 'png';
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'jpeg';
  if (startsWith(b, 'GIF87a') || startsWith(b, 'GIF89a')) return 'gif';
  if (startsWith(b, 'RIFF') && startsWith(b, 'WEBP', 8)) return 'webp';
  if (startsWith(b, OLE)) return 'ole';
  if (startsWith(b, 'PK\x03\x04')) return 'zip?';
  return null;
}

function zipKind(b: Buffer): string {
  if (b.indexOf('word/document.xml', 0, 'latin1') >= 0) return 'docx';
  if (b.indexOf('xl/workbook.xml', 0, 'latin1') >= 0) return 'xlsx';
  if (b.indexOf('ppt/presentation.xml', 0, 'latin1') >= 0) return 'pptx';
  return 'zip';
}

/** 22.4 point 3: kind of a document from its bytes, or null. */
export function magicKind(b: Buffer): string | null {
  const k = headKind(b);
  return k === 'zip?' ? zipKind(b) : k;
}

const B64_RE = /^[A-Za-z0-9+/_-]*={0,2}$/;
const DATA_PREFIX_RE = /^data:[!-+\--~]*;base64$/; // printable ASCII without ','
const DOC_MIN_CHARS = 16;

/** 22.4: 'drop:doc:<kind>:<class>' if the string is the base64 of a document, else null. */
export function base64Doc(str: string): string | null {
  let s = str;
  if (s.startsWith('data:')) {
    const i = s.indexOf(',');
    if (i < 0 || !DATA_PREFIX_RE.test(s.slice(0, i))) return null;
    s = s.slice(i + 1);
  }
  if (s.length < DOC_MIN_CHARS || !B64_RE.test(s)) return null;
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 0x3d) end--;
  if (end !== s.length && s.length % 4 !== 0) return null;
  if (end % 4 === 1) return null;
  const body = s.slice(0, end);
  // The first 16 characters give the first 12 bytes: enough for every magic number but
  // the zip names, which need the whole document.
  const head = Buffer.from(body.slice(0, 16), 'base64url');
  let kind = headKind(head);
  if (kind === null) return null;
  const length = Math.floor((end * 3) / 4);
  if (kind === 'zip?') kind = zipKind(Buffer.from(body, 'base64url'));
  return 'drop:doc:' + kind + ':' + docClass(length);
}

// ------------------------------------------------------------------ media type parameters (22.2, 22.3)

function trimSpTab(s: string): string {
  let a = 0;
  let b = s.length;
  while (a < b && (s[a] === ' ' || s[a] === '\t')) a++;
  while (b > a && (s[b - 1] === ' ' || s[b - 1] === '\t')) b--;
  return s.slice(a, b);
}

function asciiLowerStr(s: string): string {
  return s.replace(/[A-Z]+/g, (m) => m.toLowerCase());
}

/**
 * Parameters of a normalized content-type value: lowercase name -> value, first occurrence
 * wins. Split on ';', each piece trimmed and split on the first '='; a value starting with '"'
 * must end with '"' (length >= 2) and loses both quotes, no escapes. Not UTF-8: no parameters.
 */
export function mediaParams(value: Buffer | null | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (!value) return out;
  const s = decodeUtf8(value);
  if (s === null) return out;
  const pieces = s.split(';');
  for (let i = 1; i < pieces.length; i++) {
    const piece = trimSpTab(pieces[i]!);
    const eq = piece.indexOf('=');
    if (eq < 0) continue;
    const name = asciiLowerStr(trimSpTab(piece.slice(0, eq)));
    let v = trimSpTab(piece.slice(eq + 1));
    if (v.startsWith('"')) {
      if (v.length < 2 || !v.endsWith('"')) continue;
      v = v.slice(1, -1);
    }
    if (!out.has(name)) out.set(name, v);
  }
  return out;
}

// ------------------------------------------------------------------ multipart (22.3)

const BOUNDARY_RE = /^[0-9A-Za-z'()+_,./:=? -]{0,69}[0-9A-Za-z'()+_,./:=?-]$/;
const PART_HEADER_NAME_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;
const FILE_TYPES: ReadonlyMap<string, string> = new Map([
  ['text/plain', 'text'], ['text/csv', 'csv'], ['application/json', 'json'], ['application/xml', 'xml'], ['text/xml', 'xml'],
]);
const CRLF = Buffer.from('\r\n');
const CRLFCRLF = Buffer.from('\r\n\r\n');

export class InvalidMultipart extends Error {}

export interface MultipartPart { name: string; isFile: boolean; content: Buffer; ct: string | null }

const bad = (why: string): never => {
  throw new InvalidMultipart(why);
};

/** content-disposition of a part -> params (first wins); InvalidMultipart if not form-data. */
function disposition(s: string): Map<string, string> {
  const i = s.indexOf(';');
  const kind = trimSpTab(i < 0 ? s : s.slice(0, i));
  if (kind.toLowerCase() !== 'form-data') bad('disposition');
  const params = new Map<string, string>();
  let pos = i < 0 ? s.length : i;
  const n = s.length;
  while (pos < n) {
    while (pos < n && (s[pos] === ' ' || s[pos] === '\t' || s[pos] === ';')) pos++;
    if (pos >= n) break;
    const start = pos;
    while (pos < n && s[pos] !== '=' && s[pos] !== ';') pos++;
    const name = trimSpTab(s.slice(start, pos)).toLowerCase();
    if (pos >= n || s[pos] === ';') {
      if (!params.has(name)) params.set(name, '');
      continue;
    }
    pos++; // '='
    while (pos < n && (s[pos] === ' ' || s[pos] === '\t')) pos++;
    let val: string;
    if (pos < n && s[pos] === '"') {
      pos++;
      let buf = '';
      for (;;) {
        if (pos >= n) bad('unterminated quoted string');
        const c = s[pos]!;
        if (c === '\\' && pos + 1 < n) {
          buf += s[pos + 1];
          pos += 2;
          continue;
        }
        if (c === '"') {
          pos++;
          break;
        }
        buf += c;
        pos++;
      }
      val = buf;
      while (pos < n && (s[pos] === ' ' || s[pos] === '\t')) pos++;
      if (pos < n && s[pos] !== ';') bad('garbage after quoted string');
    } else {
      const start2 = pos;
      while (pos < n && s[pos] !== ';') pos++;
      val = trimSpTab(s.slice(start2, pos));
    }
    if (!params.has(name)) params.set(name, val);
  }
  return params;
}

function trimSpTabBytes(b: Buffer): Buffer {
  let a = 0;
  let e = b.length;
  while (a < e && (b[a] === 0x20 || b[a] === 0x09)) a++;
  while (e > a && (b[e - 1] === 0x20 || b[e - 1] === 0x09)) e--;
  return b.subarray(a, e);
}

/** 22.3 points 1-5: the parts of a multipart body. Throws InvalidMultipart. */
export function parseMultipart(data: Buffer, boundary: string | undefined): MultipartPart[] {
  if (boundary === undefined || !BOUNDARY_RE.test(boundary)) bad('boundary');
  const delim = Buffer.from('--' + boundary, 'latin1');
  const crlfDelim = Buffer.concat([CRLF, delim]);
  let pos: number;
  if (startsWith(data, delim)) pos = 0;
  else {
    const i = data.indexOf(crlfDelim);
    if (i < 0) bad('no delimiter');
    pos = i + 2;
  }
  const parts: Buffer[] = [];
  for (;;) {
    pos += delim.length;
    if (data[pos] === 0x2d && data[pos + 1] === 0x2d) break;
    while (pos < data.length && (data[pos] === 0x20 || data[pos] === 0x09)) pos++;
    if (!(data[pos] === 0x0d && data[pos + 1] === 0x0a)) bad('delimiter line');
    pos += 2;
    const nxt = data.indexOf(crlfDelim, pos);
    if (nxt < 0) bad('no close delimiter');
    parts.push(data.subarray(pos, nxt));
    pos = nxt + 2;
  }
  const out: MultipartPart[] = [];
  for (const p of parts) {
    let head: Buffer;
    let content: Buffer;
    if (p[0] === 0x0d && p[1] === 0x0a) {
      head = p.subarray(0, 0);
      content = p.subarray(2);
    } else {
      const j = p.indexOf(CRLFCRLF);
      if (j < 0) bad('part headers');
      head = p.subarray(0, j);
      content = p.subarray(j + 4);
    }
    const headers = new Map<string, Buffer>();
    if (head.length > 0) {
      let start = 0;
      for (;;) {
        const e = head.indexOf(CRLF, start);
        const line = head.subarray(start, e < 0 ? head.length : e);
        const k = line.indexOf(0x3a);
        if (k <= 0) bad('part header line');
        const nm = line.subarray(0, k).toString('latin1');
        if (!PART_HEADER_NAME_RE.test(nm)) bad('part header line');
        const lname = nm.toLowerCase();
        if (!headers.has(lname)) headers.set(lname, trimSpTabBytes(line.subarray(k + 1)));
        if (e < 0) break;
        start = e + 2;
      }
    }
    const cd = headers.get('content-disposition');
    if (cd === undefined) bad('no content-disposition');
    const cds = decodeUtf8(cd!);
    if (cds === null) bad('content-disposition not UTF-8');
    const params = disposition(cds!);
    const name = params.get('name');
    if (name === undefined) bad('no name');
    const isFile = params.has('filename') || params.has('filename*');
    let ct: string | null = null;
    const ctb = headers.get('content-type');
    if (ctb !== undefined) {
      const cts = decodeUtf8(ctb);
      if (cts !== null) ct = trimSpTab(cts.split(';', 1)[0]!).toLowerCase();
    }
    out.push({ name: name!, isFile, content, ct });
  }
  return out;
}

/** 22.3: drop:file:<kind>:<class> of a file part. */
export function fileToken(content: Buffer, ct: string | null): string {
  const kind = magicKind(content) ?? FILE_TYPES.get(ct ?? '') ?? 'bin';
  return 'drop:file:' + kind + ':' + docClass(content.length);
}

// ------------------------------------------------------------------ XML (22.2)

export const NS_XML = 'http://www.w3.org/XML/1998/namespace';
export const SOAP11 = 'http://schemas.xmlsoap.org/soap/envelope/';
export const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';
export const XML_MAX_NESTING = 256;
const NS_MAX_BYTES = 512;

export class InvalidXml extends Error {}

const xbad = (why: string): never => {
  throw new InvalidXml(why);
};

function nameStart(c: number): boolean {
  return (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x5f || c >= 0x80;
}

function nameChar(c: number): boolean {
  return nameStart(c) || (c >= 0x30 && c <= 0x39) || c === 0x2e || c === 0x2d || c === 0x3a;
}

function xmlChar(cp: number): boolean {
  return cp === 0x9 || cp === 0xa || cp === 0xd || (cp >= 0x20 && cp <= 0xd7ff) || (cp >= 0xe000 && cp <= 0xfffd) || (cp >= 0x10000 && cp <= 0x10ffff);
}

function isWs(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a;
}

const ENTITIES: ReadonlyMap<string, string> = new Map([['lt', '<'], ['gt', '>'], ['amp', '&'], ['apos', "'"], ['quot', '"']]);
const HEX_DIGITS = /^[0-9a-fA-F]+$/;
const DEC_DIGITS = /^[0-9]+$/;

/** Character and predefined entity references; attribute values turn tab and newline into spaces. */
function refs(raw: string, attr: boolean): string {
  if (raw.indexOf('&') < 0 && !(attr && /[\t\n]/.test(raw))) return raw;
  let out = '';
  let i = 0;
  const n = raw.length;
  while (i < n) {
    const c = raw[i]!;
    if (c === '&') {
      const j = raw.indexOf(';', i + 1);
      if (j < 0) xbad('unterminated reference');
      const ent = raw.slice(i + 1, j);
      const named = ENTITIES.get(ent);
      if (named !== undefined) out += named;
      else {
        let digits: string;
        let radix: number;
        if (ent.startsWith('#x') && ent.length > 2 && HEX_DIGITS.test(ent.slice(2))) {
          digits = ent.slice(2);
          radix = 16;
        } else if (ent.startsWith('#') && ent.length > 1 && DEC_DIGITS.test(ent.slice(1))) {
          digits = ent.slice(1);
          radix = 10;
        } else {
          return xbad('unknown entity');
        }
        let cp = 0;
        for (const d of digits) {
          cp = cp * radix + parseInt(d, 16);
          if (cp > 0x10ffff) xbad('reference out of range');
        }
        if (!xmlChar(cp)) xbad('reference to a forbidden character');
        out += String.fromCodePoint(cp);
      }
      i = j + 1;
      continue;
    }
    out += attr && (c === '\t' || c === '\n') ? ' ' : c;
    i++;
  }
  return out;
}

function splitQname(q: string): [string | null, string] {
  const i = q.indexOf(':');
  if (i < 0) return [null, q];
  const p = q.slice(0, i);
  const l = q.slice(i + 1);
  if (!p || !l || l.includes(':')) xbad('qualified name');
  return [p, l];
}

export interface XmlElem {
  local: string;
  ns: string;
  /** (local name, value) without namespace declarations. */
  attrs: Array<[string, string]>;
  children: XmlElem[];
  text: string[];
}

/** 22.2 points 1-6 -> root element. Throws InvalidXml for anything outside the accepted subset. */
export function parseXml(input: Buffer): XmlElem {
  let data = input;
  if (data.length >= 3 && data[0] === 0xef && data[1] === 0xbb && data[2] === 0xbf) data = data.subarray(3);
  const decoded = decodeUtf8(data);
  if (decoded === null) xbad('not UTF-8');
  let s = decoded!;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    // Valid UTF-8 never yields lone surrogates: only pairs, which are allowed.
    if ((c < 0x20 && c !== 9 && c !== 10 && c !== 13) || c === 0xfffe || c === 0xffff) xbad('forbidden character');
  }
  if (s.indexOf('\r') >= 0) s = s.replace(/\r\n?/g, '\n');
  const n = s.length;
  let pos = 0;

  const readName = (p: number): [string, number] => {
    if (p >= n || !nameStart(s.charCodeAt(p))) xbad('name');
    let q = p + 1;
    while (q < n && nameChar(s.charCodeAt(q))) q++;
    return [s.slice(p, q), q];
  };
  const skipWs = (p: number): number => {
    while (p < n && isWs(s.charCodeAt(p))) p++;
    return p;
  };
  /** Comment or processing instruction at p -> its end, or -1 if none starts there. */
  const misc = (p: number): number => {
    if (s.startsWith('<!--', p)) {
      const e = s.indexOf('-->', p + 4);
      if (e < 0) xbad('unterminated comment');
      return e + 3;
    }
    if (s.startsWith('<?', p)) {
      const e = s.indexOf('?>', p + 2);
      if (e < 0) xbad('unterminated processing instruction');
      return e + 2;
    }
    return -1;
  };
  const startTag = (p0: number, parentNs: Map<string, string>): { qname: string; el: XmlElem; nsmap: Map<string, string>; empty: boolean; pos: number } => {
    let [qname, p] = readName(p0 + 1);
    const rawAttrs: Array<[string, string]> = [];
    const seen = new Set<string>();
    let empty = false;
    for (;;) {
      let q = skipWs(p);
      if (s.startsWith('/>', q)) {
        p = q + 2;
        empty = true;
        break;
      }
      if (s.startsWith('>', q)) {
        p = q + 1;
        break;
      }
      if (q === p) xbad('attribute without space');
      let aname: string;
      [aname, q] = readName(q);
      q = skipWs(q);
      if (q >= n || s[q] !== '=') xbad('attribute without =');
      q = skipWs(q + 1);
      if (q >= n || (s[q] !== '"' && s[q] !== "'")) xbad('attribute value');
      const e = s.indexOf(s[q]!, q + 1);
      if (e < 0) xbad('unterminated attribute value');
      const raw = s.slice(q + 1, e);
      if (raw.includes('<')) xbad('< in attribute value');
      if (seen.has(aname)) xbad('duplicate attribute');
      seen.add(aname);
      rawAttrs.push([aname, refs(raw, true)]);
      p = e + 1;
    }
    let nsmap = parentNs;
    for (const [aname, v] of rawAttrs) {
      let pre: string | null = null;
      if (aname === 'xmlns') pre = '';
      else if (aname.startsWith('xmlns:')) {
        pre = aname.slice(6);
        if (!pre || pre.includes(':')) xbad('namespace declaration');
      }
      if (pre === null) continue;
      if (nsmap === parentNs) nsmap = new Map(parentNs);
      nsmap.set(pre, v);
    }
    const [prefix, local] = splitQname(qname);
    let ns: string;
    if (prefix === null) ns = nsmap.get('') ?? '';
    else if (prefix === 'xml') ns = NS_XML;
    else if (nsmap.has(prefix)) ns = nsmap.get(prefix)!;
    else return xbad('undeclared prefix');
    const attrs: Array<[string, string]> = [];
    for (const [aname, v] of rawAttrs) {
      if (aname === 'xmlns' || aname.startsWith('xmlns:')) continue;
      const [ap, al] = splitQname(aname);
      if (ap !== null && ap !== 'xml' && !nsmap.has(ap)) xbad('undeclared attribute prefix');
      attrs.push([al, v]);
    }
    return { qname, el: { local, ns, attrs, children: [], text: [] }, nsmap, empty, pos: p };
  };

  // prolog
  for (;;) {
    pos = skipWs(pos);
    if (pos >= n) xbad('no root element');
    const e = misc(pos);
    if (e >= 0) {
      pos = e;
      continue;
    }
    if (s.startsWith('<!', pos) || s[pos] !== '<') xbad('prolog');
    break;
  }
  const stack: Array<{ qname: string; el: XmlElem; nsmap: Map<string, string> }> = [];
  const first = startTag(pos, new Map());
  const root = first.el;
  pos = first.pos;
  if (!first.empty) stack.push({ qname: first.qname, el: first.el, nsmap: first.nsmap });
  while (stack.length > 0) {
    if (pos >= n) xbad('unclosed element');
    const top = stack[stack.length - 1]!;
    if (s.charCodeAt(pos) !== 0x3c) {
      const e = s.indexOf('<', pos);
      if (e < 0) xbad('unclosed element');
      top.el.text.push(refs(s.slice(pos, e), false));
      pos = e;
      continue;
    }
    if (s.startsWith('<![CDATA[', pos)) {
      const e = s.indexOf(']]>', pos + 9);
      if (e < 0) xbad('unterminated CDATA');
      top.el.text.push(s.slice(pos + 9, e));
      pos = e + 3;
      continue;
    }
    const e = misc(pos);
    if (e >= 0) {
      pos = e;
      continue;
    }
    if (s.startsWith('<!', pos)) xbad('declaration in content');
    if (s.startsWith('</', pos)) {
      const [name, q0] = readName(pos + 2);
      const q = skipWs(q0);
      if (q >= n || s[q] !== '>' || name !== top.qname) xbad('end tag');
      stack.pop();
      pos = q + 1;
      continue;
    }
    const t = startTag(pos, top.nsmap);
    top.el.children.push(t.el);
    pos = t.pos;
    if (!t.empty) {
      if (stack.length >= XML_MAX_NESTING) xbad('nesting');
      stack.push({ qname: t.qname, el: t.el, nsmap: t.nsmap });
    }
  }
  // epilogue
  for (;;) {
    pos = skipWs(pos);
    if (pos >= n) break;
    const e = misc(pos);
    if (e < 0) xbad('content after the root element');
    pos = e;
  }
  return root;
}

/** Tree value of an element (22.2 point 7): a string, or an object as ordered members. */
export type XmlValue = string | XmlObj | XmlValue[];
export interface XmlObj { members: Array<[string, XmlValue]> }

function hasNonSpace(t: string): boolean {
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return true;
  }
  return false;
}

export function xmlValue(el: XmlElem): XmlValue {
  if (el.attrs.length === 0 && el.children.length === 0) return el.text.join('');
  let members: Array<[string, XmlValue] | null> = [];
  const index = new Map<string, number>();
  for (const [local, v] of el.attrs) {
    // Same local name twice: the last wins, at its own position.
    const k = '@' + local;
    const prev = index.get(k);
    if (prev !== undefined) members[prev] = null;
    index.set(k, members.length);
    members.push([k, v]);
  }
  members = members.filter((m) => m !== null);
  const groups = new Map<string, XmlValue[]>();
  for (const c of el.children) {
    let g = groups.get(c.local);
    if (!g) {
      g = [];
      groups.set(c.local, g);
    }
    g.push(xmlValue(c));
  }
  for (const [k, vs] of groups) members.push([k, vs.length === 1 ? vs[0]! : vs]);
  const text = el.text.join('');
  if (hasNonSpace(text)) members.push(['#text', text]);
  return { members: members as Array<[string, XmlValue]> };
}

const NS_RUN_RE = /[A-Za-z0-9_-]+/g;
const NS_BAD_CHAR = /[^!-~]|[@{}]/;

/** 22.2 point 9: 'ns:' + pattern of a namespace URI. */
export function nsPattern(uri: string): string {
  if (uri === '') return 'ns:{none}';
  if (Buffer.byteLength(uri, 'utf8') > NS_MAX_BYTES || NS_BAD_CHAR.test(uri)) return 'ns:{*}';
  return 'ns:' + uri.replace(NS_RUN_RE, (t) => (t.length > 64 || /[0-9]{6}/.test(t) || /[0-9A-Fa-f]{12}/.test(t) ? '{*}' : t));
}

/** 22.2 points 9-10: xmlns entries [(path, token)] in document order (no limit) and fmt. */
export function xmlNamespaces(root: XmlElem, literal: (k: string) => boolean, maxDepth: number): { entries: Array<[string, string]>; fmt: string } {
  const entries: Array<[string, string]> = [];
  const seen = new Set<string>();
  const visit = (el: XmlElem, path: string, parentNs: string, depth: number): void => {
    if (depth > maxDepth) return;
    if (el.ns !== parentNs && !seen.has(path)) {
      seen.add(path);
      entries.push([path, nsPattern(el.ns)]);
    }
    const counts = new Map<string, number>();
    for (const c of el.children) counts.set(c.local, (counts.get(c.local) ?? 0) + 1);
    for (const c of el.children) {
      const p = path + (literal(c.local) ? '.' + c.local : '.*') + (counts.get(c.local)! > 1 ? '[*]' : '');
      visit(c, p, el.ns, depth + 1);
    }
  };
  visit(root, '$' + (literal(root.local) ? '.' + root.local : '.*'), '', 1);
  let fmt = 'xml';
  if (root.local === 'Envelope' && root.ns === SOAP11) fmt = 'soap11';
  else if (root.local === 'Envelope' && root.ns === SOAP12) fmt = 'soap12';
  return { entries, fmt };
}

/** 22.2 point 11: the operation name of a SOAPAction value, or null when empty. */
export function soapActionName(raw: string, literal: (k: string) => boolean): string | null {
  let s = trimSpTab(raw);
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) s = s.slice(1, -1);
  if (s === '') return null;
  const cut = Math.max(s.lastIndexOf('/'), s.lastIndexOf('#'), s.lastIndexOf(':'));
  const name = s.slice(cut + 1);
  return literal(name) ? name : '{*}';
}
