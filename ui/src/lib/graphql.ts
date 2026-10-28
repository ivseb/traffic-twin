// GraphQL operations of a contract (x-tt-graphql, x-tt-graphql-schemas: docs/spec/event.md section 6 and
// sanitizer.md 5.7). One HTTP endpoint (POST /graphql) carries many logical operations, each an operation of the
// contract ("POST /graphql#GetOrder"). Documents are shapes: names, and ?s ?i ... in place of every inline value.

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string => (typeof v === 'string' ? v : '');

export interface GraphQLVar {
  name: string;
  type: string;
}

export interface GraphQLOpInfo {
  /** query | mutation | subscription */
  type: string;
  /** Operation name, or "~" and a hash for an anonymous operation. */
  name: string;
  anonymous: boolean;
  introspection: boolean;
  /** Endpoint path ("/graphql") and its method. */
  endpoint: string;
  method: string;
  /** Shape of the document (no value). */
  document: string;
  variables: GraphQLVar[];
  /** Response keys of the root selection. */
  fields: string[];
}

/** The x-tt-graphql extension of an OpenAPI operation, if any. */
export function graphqlOf(op: unknown): GraphQLOpInfo | undefined {
  const x = isObj(op) && isObj(op['x-tt-graphql']) ? op['x-tt-graphql'] : undefined;
  if (!x) return undefined;
  return {
    type: str(x.type) || 'query',
    name: str(x.name),
    anonymous: x.anonymous === true,
    introspection: x.introspection === true,
    endpoint: str(x.endpoint),
    method: str(x.method),
    document: str(x.document),
    variables: (Array.isArray(x.variables) ? x.variables : []).filter(isObj).map((v) => ({ name: str(v.name), type: str(v.type) })),
    fields: (Array.isArray(x.fields) ? x.fields : []).map(String),
  };
}

/** "QUERY GetOrder"; an anonymous operation shows `anonymous` (translated by the caller) instead of its hash. */
export function graphqlLabel(g: GraphQLOpInfo, anonymous = 'anonymous'): string {
  return `${g.type.toUpperCase()} ${g.anonymous ? anonymous : g.name}`.trim();
}

/** Indents a document shape for reading: one selection per line. */
export function prettyDocument(shape: string): string {
  let out = '';
  let depth = 0;
  let paren = 0;
  const nl = () => {
    out = out.trimEnd() + '\n' + '  '.repeat(depth);
  };
  for (let i = 0; i < shape.length; i++) {
    const c = shape[i];
    if (c === '(') paren++;
    if (c === ')') paren--;
    // Spaces outside a selection set ("query GetOrder", "fragment F on T") and after "...on" stay.
    const keepSpace = c === ' ' && (depth === 0 || /\.\.\.on$/.test(out));
    if (paren > 0 || keepSpace || (c !== '{' && c !== '}' && c !== ' ')) {
      out += c;
      continue;
    }
    if (c === '{') {
      out = out.trimEnd() + (out ? ' {' : '{');
      depth++;
      nl();
    } else if (c === '}') {
      depth = Math.max(0, depth - 1);
      nl();
      out += '}';
      if (depth === 0 && i + 1 < shape.length) out += '\n';
      else nl();
    } else {
      nl();
    }
  }
  return out
    .split('\n')
    .map((l) => l.trimEnd())
    .filter((l) => l.trim() !== '')
    .join('\n');
}

/** The captured introspection result of an endpoint (x-tt-graphql-schemas). */
export function capturedSchemas(doc: unknown): { endpoint: string; capturedAt: string; schema: Obj }[] {
  const list = isObj(doc) && Array.isArray(doc['x-tt-graphql-schemas']) ? doc['x-tt-graphql-schemas'] : [];
  const out: { endpoint: string; capturedAt: string; schema: Obj }[] = [];
  for (const e of list) {
    if (!isObj(e) || !isObj(e.data) || !isObj(e.data.__schema)) continue;
    out.push({ endpoint: str(e.endpoint), capturedAt: str(e.captured_at), schema: e.data.__schema });
  }
  return out;
}

function typeRef(t: unknown): string {
  if (!isObj(t)) return '?';
  if (t.kind === 'NON_NULL') return `${typeRef(t.ofType)}!`;
  if (t.kind === 'LIST') return `[${typeRef(t.ofType)}]`;
  return str(t.name) || '?';
}

function args(list: unknown): string {
  const a = (Array.isArray(list) ? list : []).filter(isObj);
  return a.length ? `(${a.map((x) => `${str(x.name)}: ${typeRef(x.type)}`).join(', ')})` : '';
}

const BUILTIN = new Set(['String', 'Int', 'Float', 'Boolean', 'ID']);

/** SDL of a captured (or synthesized) __schema: names and types only, the descriptions never leave the sources. */
export function sdlOf(schema: Obj): string {
  const out: string[] = [];
  const roots: string[] = [];
  for (const [k, op] of [['queryType', 'query'], ['mutationType', 'mutation'], ['subscriptionType', 'subscription']] as const) {
    const n = isObj(schema[k]) ? str((schema[k] as Obj).name) : '';
    if (n) roots.push(`  ${op}: ${n}`);
  }
  if (roots.length) out.push(`schema {\n${roots.join('\n')}\n}`);
  const types = (Array.isArray(schema.types) ? schema.types : []).filter(isObj);
  for (const t of [...types].sort((a, b) => str(a.name).localeCompare(str(b.name)))) {
    const name = str(t.name);
    if (!name || name.startsWith('__') || BUILTIN.has(name)) continue;
    switch (t.kind) {
      case 'SCALAR':
        out.push(`scalar ${name}`);
        break;
      case 'ENUM':
        out.push(`enum ${name} {\n${(Array.isArray(t.enumValues) ? t.enumValues : []).filter(isObj).map((v) => `  ${str(v.name)}`).join('\n')}\n}`);
        break;
      case 'UNION':
        out.push(`union ${name} = ${(Array.isArray(t.possibleTypes) ? t.possibleTypes : []).filter(isObj).map((p) => str(p.name)).join(' | ')}`);
        break;
      case 'INPUT_OBJECT':
        out.push(`input ${name} {\n${(Array.isArray(t.inputFields) ? t.inputFields : []).filter(isObj).map((f) => `  ${str(f.name)}: ${typeRef(f.type)}`).join('\n')}\n}`);
        break;
      default: {
        const ifaces = (Array.isArray(t.interfaces) ? t.interfaces : []).filter(isObj).map((i) => str(i.name)).filter(Boolean);
        const kw = t.kind === 'INTERFACE' ? 'interface' : 'type';
        const fields = (Array.isArray(t.fields) ? t.fields : []).filter(isObj).map((f) => `  ${str(f.name)}${args(f.args)}: ${typeRef(f.type)}`);
        out.push(`${kw} ${name}${ifaces.length ? ` implements ${ifaces.join(' & ')}` : ''} {\n${fields.join('\n')}\n}`);
      }
    }
  }
  return out.join('\n\n');
}

/** Every GraphQL operation of a contract, by endpoint. */
export function graphqlOperations(doc: unknown): { key: string; info: GraphQLOpInfo }[] {
  const paths = isObj(doc) && isObj(doc.paths) ? doc.paths : {};
  const out: { key: string; info: GraphQLOpInfo }[] = [];
  for (const [path, item] of Object.entries(paths)) {
    if (!isObj(item)) continue;
    for (const [m, op] of Object.entries(item)) {
      const g = graphqlOf(op);
      if (g) out.push({ key: `${m.toUpperCase()} ${path}`, info: g });
    }
  }
  return out.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

/** The operations as a GraphQL document a person reads (the observed shapes, one per operation). */
export function operationsText(doc: unknown): string {
  return graphqlOperations(doc)
    .filter((o) => !o.info.introspection)
    .map((o) => `# ${graphqlLabel(o.info, '(anonymous)')} · ${o.info.method} ${o.info.endpoint}\n${prettyDocument(o.info.document)}`)
    .join('\n\n');
}
