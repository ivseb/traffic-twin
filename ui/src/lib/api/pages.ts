// Third-party pages ("Pagine di terzi", /api/v1/mocks/pages): a payment gateway or an e-signature page the
// application under test sends the browser to. The mock serves /__pages/<id> with buttons; a click calls the
// application back server to server (optional HMAC signature) and sends the browser to the return URL. The objects
// are the wire ones (snake_case), as the mock reads them (internal/mock/pages.go): the console stores them as typed.

export interface PageButton {
  action: string;
  label: string;
  /** Extra placeholders of this choice ({value.<name>}). */
  values?: Record<string, string>;
  /** No callback for this choice (a cancel button). */
  no_callback?: boolean;
  /**
   * Fields of the linked object (the entity or static object the linked answer created) written with this choice:
   * dotted paths, scalar values; strings take the placeholders ("{value.code}").
   */
  set?: Record<string, PageSetValue>;
}

export type PageSetValue = string | number | boolean | null;

/** Where the request of a linked operation carries the application's return URL ({link.return}). */
export interface PageFrom {
  from: 'req.body' | 'req.query' | 'req.headers';
  /** With req.body: a body path like $.returnUrl. */
  path?: string;
  /** With req.query or req.headers. */
  name?: string;
}

export interface PageHmac {
  header: string;
  /** Always "" in the answers of the console: an empty key on save keeps the stored one. */
  key: string;
  algorithm?: '' | 'sha256' | 'sha1' | 'sha512';
  encoding?: '' | 'hex' | 'base64';
  prefix?: string;
}

export interface PageCallback {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  url: string;
  headers?: Record<string, string>;
  body?: string;
  body_type?: '' | 'json' | 'form' | 'text';
  hmac?: PageHmac;
}

export interface PageLink {
  service: string;
  op: string;
  path: string;
  ref_path?: string;
  base_url?: string;
  return_from?: PageFrom;
  /** The entity of the rules whose object (id at ref_path) the buttons' set changes; absent: the static object. */
  entity?: string;
}

export interface ThirdPartyPage {
  id: string;
  title: string;
  description?: string;
  ref?: string;
  show?: string[];
  return_url?: string;
  return_hosts?: string[];
  buttons: PageButton[];
  callback?: PageCallback;
  links?: PageLink[];
  /** Completes a visit at once: by scenario preset id, "*" for every session. */
  auto?: Record<string, string>;
}

/** The pages of a group's mocks. */
export interface MockPages {
  group: string;
  pages: ThirdPartyPage[];
  updatedBy?: string;
  updatedAt?: string;
}

export const PAGE_ID_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
export const PAGE_ACTION_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const HEADER_NAME_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/;
const PLACEHOLDER_RE = /\{([a-z]+(?:\.[A-Za-z0-9_-]{1,64})?)\}/g;
const OP_RE = /^[A-Z]{1,16} \/[!-~]*$/;
const BODY_PATH_RE = /^\$(\.[A-Za-z_][A-Za-z0-9_-]{0,63}|\.\*|\[\*\])*$/;

/** The placeholders of the templates, as the page help lists them. */
export const PAGE_PLACEHOLDERS = ['ref', 'action', 'session', 'uuid', 'now', 'now.date', 'now.unix', 'query.<name>', 'value.<name>', 'customer.id', 'customer.name', 'link.return'] as const;
const SET_FIELD_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$/;
const ENTITY_RE = /^[a-z][a-z0-9_-]{0,62}$/;

/** The first placeholder of a template the mock does not know, or null. */
export function badPlaceholder(t: string | undefined): string | null {
  for (const m of (t ?? '').matchAll(PLACEHOLDER_RE)) {
    const [name, sub = ''] = m[1].split('.', 2);
    const hasSub = m[1].includes('.');
    switch (name) {
      case 'ref':
      case 'action':
      case 'session':
      case 'uuid':
        if (hasSub) return m[0];
        break;
      case 'now':
        if (hasSub && sub !== 'date' && sub !== 'unix') return m[0];
        break;
      case 'query':
      case 'value':
        if (!hasSub) return m[0];
        break;
      case 'customer':
        if (sub !== 'id' && sub !== 'name') return m[0];
        break;
      case 'link':
        if (sub !== 'return') return m[0];
        break;
      default:
        return m[0];
    }
  }
  return null;
}

/** Whether a URL template starts with a literal http(s)://host/ (no placeholder before the path). */
export function fixedOrigin(t: string): boolean {
  const i = t.indexOf('{');
  const head = i >= 0 ? t.slice(0, i) : t;
  const m = /^(https?):\/\/([^/?#{}@\s]+)(.*)$/.exec(head);
  if (!m || !m[2]) return false;
  return i < 0 || m[3].startsWith('/') || m[3].startsWith('?');
}

/** A problem of a page found by the form before the server: a stable code and the field it is about. */
export interface PageProblem {
  code: string;
  field: string;
  /** The button, header, link or placeholder named by the problem. */
  item?: string;
}

/** What the server would refuse in a page (the rules of internal/mock/pages.go), in a stable order. */
export function pageProblems(p: ThirdPartyPage, others: ThirdPartyPage[] = [], keyStored = false): PageProblem[] {
  const out: PageProblem[] = [];
  if (!PAGE_ID_RE.test(p.id)) out.push({ code: 'id', field: 'id' });
  else if (others.some((o) => o.id === p.id)) out.push({ code: 'idTaken', field: 'id' });
  if (!p.title.trim() || p.title.length > 120) out.push({ code: 'title', field: 'title' });
  if ((p.description ?? '').length > 1000) out.push({ code: 'description', field: 'description' });
  if (p.buttons.length < 1 || p.buttons.length > 6) out.push({ code: 'buttons', field: 'buttons' });
  const actions = new Set<string>();
  for (const b of p.buttons) {
    if (!PAGE_ACTION_RE.test(b.action) || actions.has(b.action)) out.push({ code: 'action', field: 'buttons', item: b.action || '?' });
    actions.add(b.action);
    if (!b.label.trim() || b.label.length > 60) out.push({ code: 'label', field: 'buttons', item: b.action || '?' });
    for (const [k, v] of Object.entries(b.values ?? {})) if (!PAGE_ACTION_RE.test(k) || v.length > 200) out.push({ code: 'value', field: 'buttons', item: k || '?' });
    const set = Object.entries(b.set ?? {});
    if (set.length > 32) out.push({ code: 'setSize', field: 'buttons', item: b.action || '?' });
    for (const [k, v] of set) {
      if (!SET_FIELD_RE.test(k)) out.push({ code: 'setField', field: 'buttons', item: k || '?' });
      else if (typeof v === 'string' && v.length > 1024) out.push({ code: 'setValue', field: 'buttons', item: k });
      const bad = typeof v === 'string' ? badPlaceholder(v) : null;
      if (bad) out.push({ code: 'placeholder', field: 'buttons', item: bad });
    }
  }
  for (const s of p.show ?? []) if (!HEADER_NAME_RE.test(s)) out.push({ code: 'show', field: 'show', item: s });
  for (const [field, t] of [['ref', p.ref], ['return_url', p.return_url]] as const) {
    const bad = badPlaceholder(t);
    if (bad) out.push({ code: 'placeholder', field, item: bad });
  }
  const ret = (p.return_url ?? '').trim();
  if (ret && !fixedOrigin(ret)) {
    if (!/\{[a-z]/.test(ret)) out.push({ code: 'returnUrl', field: 'return_url' });
    else if (!(p.return_hosts ?? []).length) out.push({ code: 'returnHosts', field: 'return_hosts' });
  }
  for (const h of p.return_hosts ?? []) if (!h || /[/:@ ]/.test(h)) out.push({ code: 'returnHost', field: 'return_hosts', item: h });
  const cb = p.callback;
  if (cb) {
    if (!fixedOrigin(cb.url)) out.push({ code: 'callbackUrl', field: 'callback.url' });
    for (const [field, t] of [['callback.url', cb.url], ['callback.body', cb.body]] as const) {
      const bad = badPlaceholder(t);
      if (bad) out.push({ code: 'placeholder', field, item: bad });
    }
    if ((cb.body ?? '').length > 16384) out.push({ code: 'bodySize', field: 'callback.body' });
    for (const [k, v] of Object.entries(cb.headers ?? {})) {
      if (!HEADER_NAME_RE.test(k) || /[\r\n]/.test(v) || v.length > 1024) out.push({ code: 'header', field: 'callback.headers', item: k || '?' });
      const bad = badPlaceholder(v);
      if (bad) out.push({ code: 'placeholder', field: 'callback.headers', item: bad });
    }
    const h = cb.hmac;
    if (h) {
      if (!HEADER_NAME_RE.test(h.header)) out.push({ code: 'hmacHeader', field: 'callback.hmac.header' });
      if (h.key ? h.key.length < 8 || h.key.length > 256 : !keyStored) out.push({ code: 'hmacKey', field: 'callback.hmac.key' });
      if ((h.prefix ?? '').length > 32) out.push({ code: 'hmacPrefix', field: 'callback.hmac.prefix' });
    }
  }
  for (const l of p.links ?? []) {
    if (!l.service.trim() || !OP_RE.test(l.op)) out.push({ code: 'linkOp', field: 'links', item: l.op || '?' });
    if (!l.path.startsWith('$.') || !BODY_PATH_RE.test(l.path)) out.push({ code: 'linkPath', field: 'links', item: l.path || '?' });
    if (l.ref_path && !BODY_PATH_RE.test(l.ref_path)) out.push({ code: 'linkRefPath', field: 'links', item: l.ref_path });
    if (l.base_url && !fixedOrigin(l.base_url)) out.push({ code: 'linkBase', field: 'links', item: l.base_url });
    const rf = l.return_from;
    if (rf && (rf.from === 'req.body' ? !(rf.path ?? '').startsWith('$.') || !BODY_PATH_RE.test(rf.path ?? '') : !HEADER_NAME_RE.test(rf.name ?? '')))
      out.push({ code: 'linkReturnFrom', field: 'links', item: rf.path || rf.name || '?' });
    if (l.entity) {
      if (!ENTITY_RE.test(l.entity)) out.push({ code: 'linkEntity', field: 'links', item: l.entity });
      else if (!l.ref_path) out.push({ code: 'linkEntityRef', field: 'links', item: l.entity });
    }
  }
  for (const [k, a] of Object.entries(p.auto ?? {})) {
    if (k !== '*' && !PAGE_ID_RE.test(k)) out.push({ code: 'autoKey', field: 'auto', item: k });
    if (!actions.has(a)) out.push({ code: 'autoAction', field: 'auto', item: a });
  }
  return out;
}

/** A new page with sensible defaults (invented, generic: a payment gateway). */
export function newPage(taken: string[] = []): ThirdPartyPage {
  let id = 'pay';
  for (let i = 2; taken.includes(id); i++) id = `pay-${i}`;
  return {
    id,
    title: '',
    ref: '{query.ref}',
    show: [],
    return_url: '',
    buttons: [
      { action: 'approve', label: '' },
      { action: 'decline', label: '' },
    ],
  };
}

/** The page as it is sent: empty optional parts left out (the server reads absent and empty alike). */
export function cleanPage(p: ThirdPartyPage): ThirdPartyPage {
  const out: ThirdPartyPage = { id: p.id.trim(), title: p.title.trim(), buttons: p.buttons.map((b) => ({ action: b.action.trim(), label: b.label.trim(), ...(b.values && Object.keys(b.values).length ? { values: { ...b.values } } : {}), ...(b.no_callback ? { no_callback: true } : {}), ...(b.set && Object.keys(b.set).length ? { set: { ...b.set } } : {}) })) };
  if (p.description?.trim()) out.description = p.description.trim();
  if (p.ref?.trim()) out.ref = p.ref.trim();
  const show = (p.show ?? []).map((s) => s.trim()).filter(Boolean);
  if (show.length) out.show = show;
  if (p.return_url?.trim()) out.return_url = p.return_url.trim();
  const hosts = (p.return_hosts ?? []).map((s) => s.trim()).filter(Boolean);
  if (hosts.length) out.return_hosts = hosts;
  if (p.callback) {
    const cb = p.callback;
    out.callback = { method: cb.method, url: cb.url.trim() };
    if (cb.headers && Object.keys(cb.headers).length) out.callback.headers = { ...cb.headers };
    if (cb.body) out.callback.body = cb.body;
    if (cb.body_type) out.callback.body_type = cb.body_type;
    if (cb.hmac) {
      const h = cb.hmac;
      out.callback.hmac = { header: h.header.trim(), key: h.key, ...(h.algorithm ? { algorithm: h.algorithm } : {}), ...(h.encoding ? { encoding: h.encoding } : {}), ...(h.prefix ? { prefix: h.prefix } : {}) };
    }
  }
  const links = (p.links ?? []).map((l) => ({
    service: l.service.trim(),
    op: l.op.trim(),
    path: l.path.trim(),
    ...(l.ref_path?.trim() ? { ref_path: l.ref_path.trim() } : {}),
    ...(l.base_url?.trim() ? { base_url: l.base_url.trim() } : {}),
    ...(l.return_from && (l.return_from.path?.trim() || l.return_from.name?.trim()) ? { return_from: cleanFrom(l.return_from) } : {}),
    ...(l.entity?.trim() ? { entity: l.entity.trim() } : {}),
  }));
  if (links.length) out.links = links;
  if (p.auto && Object.keys(p.auto).length) out.auto = { ...p.auto };
  return out;
}

function cleanFrom(f: PageFrom): PageFrom {
  return f.from === 'req.body' ? { from: f.from, path: (f.path ?? '').trim() } : { from: f.from, name: (f.name ?? '').trim() };
}

/** The fields a button sets, as the form writes them: "status=AUTHORISED; paid=true" (texts as they are). */
export function setText(v: Record<string, PageSetValue> | undefined): string {
  return Object.entries(v ?? {})
    .map(([k, x]) => `${k}=${x === null ? 'null' : String(x)}`)
    .join('; ');
}

/** Reads "status=AUTHORISED; paid=true; amount=10": true/false/null and plain numbers are typed, the rest is text. */
export function parseSet(s: string): Record<string, PageSetValue> {
  const out: Record<string, PageSetValue> = {};
  for (const [k, raw] of Object.entries(parseValues(s))) {
    if (raw === 'true' || raw === 'false') out[k] = raw === 'true';
    else if (raw === 'null') out[k] = null;
    else if (/^-?(0|[1-9][0-9]{0,14})(\.[0-9]{1,9})?$/.test(raw)) out[k] = Number(raw);
    else out[k] = raw;
  }
  return out;
}

/** The values of a button as the form writes them: "code=AUTHORISED; reason=ok". */
export function valuesText(v: Record<string, string> | undefined): string {
  return Object.entries(v ?? {})
    .map(([k, x]) => `${k}=${x}`)
    .join('; ');
}

/** Reads "code=AUTHORISED; reason=ok" (pairs without "=" are left out). */
export function parseValues(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of s.split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

/** A comma-separated list ("amount, order") as an array, empty items left out. */
export const parseList = (s: string): string[] =>
  s
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);

/** The commands a test uses to complete a page without a browser (control API of the mock). */
export function pageControlCommands(pageId: string, action: string): string {
  return [
    `curl -s -X POST "$MOCK/__tt/sessions/$S/pages/${pageId}/complete" -d '{"action":"${action}","query":{"ref":"PAY-0001"}}'`,
    `curl -s -X PUT "$MOCK/__tt/sessions/$S/pages/${pageId}/auto" -d '{"action":"${action}"}'`,
  ].join('\n');
}
