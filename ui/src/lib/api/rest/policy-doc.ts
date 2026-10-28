// Reads and edits author policies (tt.policy/v1, docs/spec/policy.md section 1)
// at the places the policy assistant talks about. Comments and layout of the
// original YAML are kept, so the review diff shows only what changed.

import { parseDocument, type Document } from 'yaml';
import type { HostsDiscovery, PolicyChoice, PolicySuggestion } from '../types';
import { actionSpec, parseAction } from './map';

type Loc = { kind: 'body' | 'query' | 'headers' | 'cookies'; key: string } | { kind: 'segment' };

/** Where in an operation part the discovery path lives. */
export function locate(path: string): Loc {
  if (path.startsWith('$')) return { kind: 'body', key: path };
  const m = /^(query|headers|cookies)\.(.+)$/.exec(path);
  if (m) return { kind: m[1] as 'query' | 'headers' | 'cookies', key: m[2] };
  return { kind: 'segment' };
}

type S = Pick<PolicySuggestion, 'service' | 'op' | 'part' | 'path'>;

const base = (s: S): string[] => ['services', s.service, 'ops', s.op, s.part];

/** The ways the same rule can be written (shortcut `$...` or inside `body`). */
function keysFor(s: S): string[][] {
  const l = locate(s.path);
  if (l.kind === 'segment') return [];
  if (l.kind === 'body') return [[...base(s), l.key], [...base(s), 'body', l.key]];
  return [[...base(s), l.kind, l.key]];
}

export function parsePolicy(text: string): Document {
  const doc = parseDocument(text);
  if (doc.errors.length) throw new Error(doc.errors[0].message);
  return doc;
}

/** What the policy does today with the field ("drop" when nothing says otherwise). */
export function currentChoice(doc: Document, s: S): PolicyChoice {
  for (const k of keysFor(s)) {
    const v = doc.getIn(k);
    if (typeof v === 'string') return parseAction(v);
  }
  return { action: 'drop' };
}

export interface ApplyResult {
  yaml: string;
  /** Fields that cannot be written (path words, services not in the policy). */
  skipped: string[];
}

function prune(doc: Document, path: string[]): void {
  for (let n = path.length; n > 1; n--) {
    const here = path.slice(0, n);
    const node = doc.getIn(here, true) as { items?: unknown[] } | undefined;
    if (node && Array.isArray(node.items) && node.items.length === 0 && here.length > 2) doc.deleteIn(here);
    else break;
  }
}

/** Applies the per-field choices to a copy of the policy text. */
export function applyChoices<T extends S>(text: string, suggestions: readonly T[], choices: Record<string, PolicyChoice>, idOf: (s: T) => string): ApplyResult {
  const doc = parsePolicy(text);
  const skipped: string[] = [];
  let changed = false;
  for (const s of suggestions) {
    const want = choices[idOf(s)];
    if (!want) continue;
    const have = currentChoice(doc, s);
    if (actionSpec(have) === actionSpec(want)) continue;
    const keys = keysFor(s);
    const label = `${s.service} · ${s.op} · ${s.part} · ${s.path}`;
    if (keys.length === 0) {
      skipped.push(label);
      continue;
    }
    // Keep the existing spelling of the rule; new rules use the first form.
    const where = keys.find((k) => typeof doc.getIn(k) === 'string') ?? keys[0];
    if (want.action === 'drop') {
      if (doc.hasIn(where)) {
        doc.deleteIn(where);
        prune(doc, where.slice(0, -1));
        changed = true;
      }
      continue;
    }
    if (!doc.hasIn(['services', s.service])) {
      skipped.push(label);
      continue;
    }
    doc.setIn(where, actionSpec(want));
    changed = true;
  }
  // Untouched text stays byte for byte as it was (re-printing may normalise spaces).
  return { yaml: changed ? String(doc) : text, skipped };
}

/** `hosts.discovery` written in an author policy; a policy without the block is in `auto`. */
export function hostsDiscoveryOf(text: string): HostsDiscovery {
  try {
    return parsePolicy(text).getIn(['hosts', 'discovery']) === 'off' ? 'off' : 'auto';
  } catch {
    return 'auto';
  }
}

/**
 * Sets `hosts.discovery`. `auto` is the default, so it removes the block (and the key `hosts` when nothing else is
 * in it); `off` writes `hosts: { discovery: off }`. Text that already says what is asked stays byte for byte.
 */
export function applyHostsDiscovery(text: string, mode: HostsDiscovery): string {
  if (hostsDiscoveryOf(text) === mode) return text;
  const doc = parsePolicy(text);
  if (mode === 'off') doc.setIn(['hosts', 'discovery'], 'off');
  else {
    doc.deleteIn(['hosts', 'discovery']);
    const rest = doc.getIn(['hosts'], true) as { items?: unknown[] } | undefined;
    if (rest && Array.isArray(rest.items) && rest.items.length === 0) doc.deleteIn(['hosts']);
  }
  return String(doc);
}
