// GraphQL document shape, sanitizer.md 5.7 (spec v1.14): the same algorithm as the Go
// reference (internal/graphql) and conformance/ref/gqlshape.py, step by step.
//
// The input is a well-formed JavaScript string (no lone surrogates: the caller checks).
// Everything outside strings and comments is ASCII, so code units and bytes coincide
// wherever the algorithm looks; any other character there is an error.

/** Largest number of open brackets ({, ( and [ together). */
export const GQL_MAX_NESTING = 64;
/** Largest shape; a longer one is not emitted. */
export const GQL_MAX_SHAPE_BYTES = 32768;
/** Longest name emitted as written. */
export const GQL_MAX_NAME_BYTES = 64;
/** Array limit of a response body when the introspection gate is open (5.7.2). */
export const GQL_INTROSPECTION_MAX_ARRAY = 4096;

export interface GqlShape {
  /** Canonical shape, without the `gql:` prefix. */
  shape: string;
  /** Every operation selects only __schema, __type, __typename at its root, without aliases. */
  introspection: boolean;
}

/** Token kind: punctuator, name, integer, float, string or block string. */
type K = 'punct' | 'name' | 'int' | 'float' | 'str';

interface Tok {
  k: K;
  /** Punctuator or name. */
  s: string;
  /** A name in value position (enum, true, false, null). */
  value: boolean;
}

class GqlError extends Error {}
const ERR = new GqlError('graphql');

function isNameStart(c: number): boolean {
  return c === 0x5f || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
}
function isNameCont(c: number): boolean {
  return isNameStart(c) || (c >= 0x30 && c <= 0x39);
}
function isDigit(c: number): boolean {
  return c >= 0x30 && c <= 0x39;
}
function isHex(c: number): boolean {
  return (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66) || (c >= 0x41 && c <= 0x46);
}

function lex(src: string): Tok[] {
  const toks: Tok[] = [];
  const n = src.length;
  let i = 0;
  let open = 0;
  while (i < n) {
    const c = src.charCodeAt(i);
    switch (c) {
      case 0x20: case 0x09: case 0x0a: case 0x0d: case 0x2c: case 0xfeff:
        i++;
        continue;
      case 0x23: // #
        while (i < n && src.charCodeAt(i) !== 0x0a && src.charCodeAt(i) !== 0x0d) i++;
        continue;
      case 0x21: case 0x24: case 0x26: case 0x3a: case 0x3d: case 0x40: case 0x7c: // ! $ & : = @ |
        toks.push({ k: 'punct', s: src[i]!, value: false });
        i++;
        continue;
      case 0x28: case 0x5b: case 0x7b: // ( [ {
        if (++open > GQL_MAX_NESTING) throw ERR;
        toks.push({ k: 'punct', s: src[i]!, value: false });
        i++;
        continue;
      case 0x29: case 0x5d: case 0x7d: // ) ] }
        if (--open < 0) throw ERR;
        toks.push({ k: 'punct', s: src[i]!, value: false });
        i++;
        continue;
      case 0x2e: // .
        if (src.startsWith('...', i)) {
          toks.push({ k: 'punct', s: '...', value: false });
          i += 3;
          continue;
        }
        throw ERR;
      case 0x22: // "
        i = lexString(src, i);
        toks.push({ k: 'str', s: '', value: false });
        continue;
      default:
        break;
    }
    if (isNameStart(c)) {
      let j = i + 1;
      while (j < n && isNameCont(src.charCodeAt(j))) j++;
      toks.push({ k: 'name', s: src.slice(i, j), value: false });
      i = j;
      continue;
    }
    if (c === 0x2d || isDigit(c)) {
      const [j, k] = lexNumber(src, i);
      toks.push({ k, s: '', value: false });
      i = j;
      continue;
    }
    throw ERR;
  }
  if (open !== 0) throw ERR;
  return toks;
}

function lexNumber(src: string, i: number): [number, K] {
  const n = src.length;
  let j = i;
  if (src.charCodeAt(j) === 0x2d) j++;
  if (j >= n || !isDigit(src.charCodeAt(j))) throw ERR;
  if (src.charCodeAt(j) === 0x30) {
    j++;
    if (j < n && isDigit(src.charCodeAt(j))) throw ERR; // leading zero
  } else {
    while (j < n && isDigit(src.charCodeAt(j))) j++;
  }
  let k: K = 'int';
  if (j < n && src.charCodeAt(j) === 0x2e) {
    j++;
    if (j >= n || !isDigit(src.charCodeAt(j))) throw ERR;
    while (j < n && isDigit(src.charCodeAt(j))) j++;
    k = 'float';
  }
  if (j < n && (src.charCodeAt(j) === 0x65 || src.charCodeAt(j) === 0x45)) {
    j++;
    if (j < n && (src.charCodeAt(j) === 0x2b || src.charCodeAt(j) === 0x2d)) j++;
    if (j >= n || !isDigit(src.charCodeAt(j))) throw ERR;
    while (j < n && isDigit(src.charCodeAt(j))) j++;
    k = 'float';
  }
  // A number is not followed by '.' or a NameStart.
  if (j < n && (src.charCodeAt(j) === 0x2e || isNameStart(src.charCodeAt(j)))) throw ERR;
  return [j, k];
}

/** Index after the string or block string starting at the quote at i. */
function lexString(src: string, i: number): number {
  const n = src.length;
  if (src.startsWith('"""', i)) {
    let j = i + 3;
    while (j < n) {
      const c = src.charCodeAt(j);
      if (c === 0x5c && src.startsWith('"""', j + 1)) j += 4;
      else if (c === 0x22 && src.startsWith('"""', j)) return j + 3;
      else if (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) throw ERR;
      else j++;
    }
    throw ERR;
  }
  let j = i + 1;
  while (j < n) {
    const c = src.charCodeAt(j);
    if (c === 0x22) return j + 1;
    if (c === 0x5c) {
      if (j + 1 >= n) throw ERR;
      switch (src[j + 1]) {
        case '"': case '\\': case '/': case 'b': case 'f': case 'n': case 'r': case 't':
          j += 2;
          break;
        case 'u':
          if (j + 5 >= n) throw ERR;
          for (let h = j + 2; h < j + 6; h++) if (!isHex(src.charCodeAt(h))) throw ERR;
          j += 6;
          break;
        default:
          throw ERR;
      }
    } else if (c < 0x20 && c !== 0x09) {
      throw ERR; // line terminators and control characters
    } else {
      j++;
    }
  }
  throw ERR;
}

interface RootSel { field: boolean; alias: boolean; name: string }

class Parser {
  private p = 0;
  /** Root selections of every operation (fragments excluded). */
  readonly ops: RootSel[][] = [];

  constructor(private readonly t: Tok[]) {}

  private isPunct(s: string): boolean {
    const t = this.t[this.p];
    return t !== undefined && t.k === 'punct' && t.s === s;
  }

  private isName(s?: string): boolean {
    const t = this.t[this.p];
    return t !== undefined && t.k === 'name' && (s === undefined || t.s === s);
  }

  private expect(s: string): void {
    if (!this.isPunct(s)) throw ERR;
    this.p++;
  }

  private name(): string {
    if (!this.isName()) throw ERR;
    return this.t[this.p++]!.s;
  }

  document(): void {
    if (this.t.length === 0) throw ERR;
    while (this.p < this.t.length) {
      if (this.isPunct('{')) {
        this.ops.push(this.selectionSet());
      } else if (this.isName('query') || this.isName('mutation') || this.isName('subscription')) {
        this.p++;
        if (this.isName()) this.p++;
        if (this.isPunct('(')) {
          this.p++;
          if (this.isPunct(')')) throw ERR;
          while (!this.isPunct(')')) this.varDef();
          this.p++;
        }
        this.directives();
        this.ops.push(this.selectionSet());
      } else if (this.isName('fragment')) {
        this.p++;
        if (this.name() === 'on') throw ERR;
        if (!this.isName('on')) throw ERR;
        this.p++;
        this.name();
        this.directives();
        this.selectionSet();
      } else {
        throw ERR;
      }
    }
  }

  private varDef(): void {
    this.expect('$');
    this.name();
    this.expect(':');
    this.typeRef();
    if (this.isPunct('=')) {
      this.p++;
      this.value();
    }
    this.directives();
  }

  private typeRef(): void {
    if (this.isPunct('[')) {
      this.p++;
      this.typeRef();
      this.expect(']');
    } else {
      this.name();
    }
    if (this.isPunct('!')) this.p++;
  }

  private selectionSet(): RootSel[] {
    this.expect('{');
    const out: RootSel[] = [];
    while (!this.isPunct('}')) out.push(this.selection());
    if (out.length === 0) throw ERR;
    this.p++;
    return out;
  }

  private selection(): RootSel {
    if (this.isPunct('...')) {
      this.p++;
      if (this.isName() && !this.isName('on')) {
        this.p++;
        this.directives();
        return { field: false, alias: false, name: '' };
      }
      if (this.isName()) {
        this.p++; // on
        this.name();
      }
      this.directives();
      this.selectionSet();
      return { field: false, alias: false, name: '' };
    }
    let name = this.name();
    let alias = false;
    if (this.isPunct(':')) {
      this.p++;
      name = this.name();
      alias = true;
    }
    if (this.isPunct('(')) this.arguments();
    this.directives();
    if (this.isPunct('{')) this.selectionSet();
    return { field: true, alias, name };
  }

  private arguments(): void {
    this.expect('(');
    if (this.isPunct(')')) throw ERR;
    while (!this.isPunct(')')) {
      this.name();
      this.expect(':');
      this.value();
    }
    this.p++;
  }

  private directives(): void {
    while (this.isPunct('@')) {
      this.p++;
      this.name();
      if (this.isPunct('(')) this.arguments();
    }
  }

  private value(): void {
    const t = this.t[this.p];
    if (t === undefined) throw ERR;
    if (t.k === 'punct') {
      if (t.s === '$') {
        this.p++;
        this.name();
        return;
      }
      if (t.s === '[') {
        this.p++;
        while (!this.isPunct(']')) this.value();
        this.p++;
        return;
      }
      if (t.s === '{') {
        this.p++;
        while (!this.isPunct('}')) {
          this.name();
          this.expect(':');
          this.value();
        }
        this.p++;
        return;
      }
      throw ERR;
    }
    if (t.k === 'name') t.value = true;
    this.p++;
  }
}

/** The key rule of 9.3 on a GraphQL name (5.7.1). */
export function gqlNameSafe(name: string): boolean {
  const n = name.length;
  if (n === 0 || n > GQL_MAX_NAME_BYTES || !isNameStart(name.charCodeAt(0))) return false;
  let allHex = n >= 16;
  let run = 0;
  for (let i = 0; i < n; i++) {
    const c = name.charCodeAt(i);
    if (!isNameCont(c)) return false;
    if (!isHex(c)) allHex = false;
    if (isDigit(c)) {
      if (++run >= 6) return false;
    } else {
      run = 0;
    }
  }
  return !allHex;
}

/** True if s is a GraphQL name (any length). */
export function gqlIsName(s: string): boolean {
  if (s.length === 0 || !isNameStart(s.charCodeAt(0))) return false;
  for (let i = 1; i < s.length; i++) if (!isNameCont(s.charCodeAt(i))) return false;
  return true;
}

function isWord(c: number): boolean {
  return isNameCont(c) || c === 0x3f || c === 0x2a; // ? *
}

/**
 * Shape of an executable document (5.7.1), or null when `src` is not an executable
 * document within the limits (the caller then emits the drop form of the string).
 */
export function gqlShape(src: string): GqlShape | null {
  let toks: Tok[];
  let p: Parser;
  try {
    toks = lex(src);
    p = new Parser(toks);
    p.document();
  } catch (e) {
    if (e instanceof GqlError) return null;
    throw e;
  }
  let out = '';
  let prevWord = false;
  for (const t of toks) {
    let s: string;
    switch (t.k) {
      case 'punct':
        s = t.s;
        break;
      case 'name':
        if (t.value) s = t.s === 'true' || t.s === 'false' ? '?b' : t.s === 'null' ? '?n' : '?e';
        else s = gqlNameSafe(t.s) ? t.s : '*';
        break;
      case 'int':
        s = '?i';
        break;
      case 'float':
        s = '?f';
        break;
      default:
        s = '?s';
    }
    if (prevWord && isWord(s.charCodeAt(0))) out += ' ';
    out += s;
    prevWord = isWord(s.charCodeAt(s.length - 1));
    if (out.length > GQL_MAX_SHAPE_BYTES) return null;
  }
  const introspection = p.ops.length > 0 && p.ops.every((sel) => sel.every((r) =>
    r.field && !r.alias && (r.name === '__schema' || r.name === '__type' || r.name === '__typename')));
  return { shape: out, introspection };
}
