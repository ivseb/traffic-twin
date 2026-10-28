// Server texts in English that reach the screen (usability test #5, m6 and m13): the drift of a contract, the gaps, the
// warnings of the miner and of the rule check. The server sends them as one sentence (and a code the UI maps where the
// server gives one); here the sentence is read back into its pieces and said in the language of the console. A text
// that matches nothing is shown as it came: the server's English is better than a wrong translation.
import { t } from './i18n/index.svelte';
import type { MsgKey } from './i18n/index.svelte';

type P = Record<string, string | number>;
interface Rule {
  re: RegExp;
  key: MsgKey;
  /** Names of the groups of the pattern, in order, that become the parameters. */
  params: string[];
}

const yesNo = (v: string): string => (v === 'true' ? t('fix5.msg.yes') : t('fix5.msg.no'));

/** `req header 'content-length'`, `resp 200 body`, `field 'eta'`: the place a change is about. */
export function subjectText(s: string): string {
  return s
    .replace(/\bresp (\d+)/g, (_m, n: string) => t('fix5.msg.w.resp', { n }))
    .replace(/\breq\b/g, () => t('fix5.msg.w.req'))
    .replace(/\bbody\b/g, () => t('fix5.msg.w.body'))
    .replace(/\bfield '([^']*)'/g, (_m, n: string) => t('fix5.msg.w.field', { name: n }))
    .replace(/\bmap values\b/g, () => t('fix5.msg.w.mapValues'))
    .replace(/\bitems\b/g, () => t('fix5.msg.w.items'))
    .replace(/'([^']*)'/g, '«$1»');
}

const PCT = '([0-9.]+%)';
const RULES: Rule[] = [
  // contract drift (internal/contract/diff.go)
  { re: new RegExp(`^new error status (\\d+) \\(${PCT} of calls\\)$`), key: 'fix5.msg.newErrorStatus', params: ['st', 'p'] },
  { re: new RegExp(`^new rare error status (\\d+) \\(${PCT} of calls\\)$`), key: 'fix5.msg.newRareErrorStatus', params: ['st', 'p'] },
  { re: new RegExp(`^new status (\\d+) \\(${PCT} of calls\\)$`), key: 'fix5.msg.newStatus', params: ['st', 'p'] },
  { re: /^error status (\d+) no longer observed$/, key: 'fix5.msg.errorStatusGone', params: ['st'] },
  { re: /^success status (\d+) no longer observed$/, key: 'fix5.msg.successStatusGone', params: ['st'] },
  { re: /^rare status (\d+) no longer observed$/, key: 'fix5.msg.rareStatusGone', params: ['st'] },
  { re: new RegExp(`^error status (\\d+) became frequent \\(${PCT} -> ${PCT}\\)$`), key: 'fix5.msg.errorStatusFrequent', params: ['st', 'a', 'b'] },
  { re: new RegExp(`^frequency of status (\\d+) changed \\(${PCT} -> ${PCT}\\)$`), key: 'fix5.msg.frequencyChanged', params: ['st', 'a', 'b'] },
  { re: /^(.+) content type (\S+) added$/, key: 'fix5.msg.contentAdded', params: ['subject', 'ct'] },
  { re: /^(.+) content type (\S+) removed$/, key: 'fix5.msg.contentRemoved', params: ['subject', 'ct'] },
  { re: /^field '([^']*)' added \(required\)$/, key: 'fix5.msg.fieldAddedRequired', params: ['name'] },
  { re: new RegExp(`^field '([^']*)' added \\(optional, presence ${PCT}\\)$`), key: 'fix5.msg.fieldAddedOptional', params: ['name', 'p'] },
  { re: /^field '([^']*)' added$/, key: 'fix5.msg.fieldAdded', params: ['name'] },
  { re: /^field '([^']*)' removed$/, key: 'fix5.msg.fieldRemoved', params: ['name'] },
  { re: new RegExp(`^field '([^']*)' almost never present now \\(${PCT} -> ${PCT}\\)$`), key: 'fix5.msg.fieldVanished', params: ['name', 'a', 'b'] },
  { re: new RegExp(`^field '([^']*)' presence dropped \\(${PCT} -> ${PCT}\\)$`), key: 'fix5.msg.presenceDropped', params: ['name', 'a', 'b'] },
  { re: new RegExp(`^field '([^']*)' presence increased \\(${PCT} -> ${PCT}\\)$`), key: 'fix5.msg.presenceIncreased', params: ['name', 'a', 'b'] },
  { re: /^(.+) required changed: (true|false) -> (true|false)$/, key: 'fix5.msg.requiredChanged', params: ['subject', 'from', 'to'] },
  { re: /^(.+) enum: (\d+) value\(s\) added$/, key: 'fix5.msg.enumAdded', params: ['subject', 'n'] },
  { re: /^(.+) enum: (\d+) value\(s\) removed$/, key: 'fix5.msg.enumRemoved', params: ['subject', 'n'] },
  { re: /^(.+) type changed: (.+) -> (.+)$/, key: 'fix5.msg.typeChanged', params: ['subject', 'a', 'b'] },
  { re: /^(.+) type widened: (.+) -> (.+)$/, key: 'fix5.msg.typeWidened', params: ['subject', 'a', 'b'] },
  { re: /^(.+) type narrowed: (.+) -> (.+)$/, key: 'fix5.msg.typeNarrowed', params: ['subject', 'a', 'b'] },
  { re: /^(.+) format changed: (.+) -> (.+)$/, key: 'fix5.msg.formatChanged', params: ['subject', 'a', 'b'] },
  { re: /^(.+) added$/, key: 'fix5.msg.added', params: ['subject'] },
  { re: /^(.+) removed$/, key: 'fix5.msg.removed', params: ['subject'] },
  // gaps (internal/contract/gaps.go)
  { re: /^only (\d+) calls observed \(minimum (\d+)\)$/, key: 'fix5.msg.fewSamples', params: ['n', 'min'] },
  { re: /^no 4xx or 5xx response observed$/, key: 'fix5.msg.noErrors', params: [] },
  { re: /^no 4xx response observed$/, key: 'fix5.msg.no4xx', params: [] },
  { re: /^no 5xx response observed$/, key: 'fix5.msg.no5xx', params: [] },
  { re: /^(.+): every observed value is below the k threshold$/, key: 'fix5.msg.valueUnknown', params: ['where'] },
  // the rule check (internal/miner/manual.go)
  { re: /^status (\d+) was never observed for (.+)$/, key: 'fix5.msg.statusNotObserved', params: ['status', 'op'] },
  // the miner's warnings (internal/miner/status.go)
  { re: /^entity (\S+) dropped: (.+)$/, key: 'fix5.msg.entityDropped', params: ['name', 'reason'] },
  { re: /^rule (\S+) on watch \((\d+) of (\d+) runs\): (.+)$/, key: 'fix5.msg.ruleWatch', params: ['id', 'a', 'b', 'reason'] },
  { re: /^rule (\S+) stale: (.+)$/, key: 'fix5.msg.ruleStale', params: ['id', 'reason'] },
  { re: /^few distinct sampled users: (\d+) < k=(\d+);.*$/, key: 'fix5.msg.fewSubjects', params: ['n', 'k'] },
  { re: /^no rule proposed: see the entity and rule diagnostics$/, key: 'fix5.msg.noRule', params: [] },
  // the stale alert of a rule (internal/drift/manager.go)
  { re: /^rule (\S+) confidence fell from ([0-9.]+) to ([0-9.]+) \((.+)\)$/, key: 'fix5.msg.ruleConfidence', params: ['id', 'a', 'b', 'reason'] },
  // reasons of the miner (internal/miner/repo.go)
  { re: /^its cause was not seen in the window: nothing to judge$/, key: 'fix5.msg.causeNotSeen', params: [] },
  { re: /^confirmed by the run$/, key: 'fix5.msg.confirmed', params: [] },
  { re: /^new draft$/, key: 'fix5.msg.newDraft', params: [] },
  { re: /^draft refreshed$/, key: 'fix5.msg.draftRefreshed', params: [] },
  { re: /^structure changed: new draft supersedes (\S+)$/, key: 'fix5.msg.supersedes', params: ['id'] },
];

const SUBJECT_PARAMS = new Set(['subject', 'where']);
const PLAIN_PARAMS = new Set(['reason']);

/**
 * The sentence in the console's language, or `text` itself when it is not one of the server's known sentences.
 * `reason` pieces (the tail of a warning) are localized again when they are known sentences too.
 */
export function serverText(text: string | undefined | null): string {
  const src = (text ?? '').trim();
  if (!src) return '';
  for (const r of RULES) {
    const m = r.re.exec(src);
    if (!m) continue;
    const params: P = {};
    r.params.forEach((name, i) => {
      const v = m[i + 1] ?? '';
      if (SUBJECT_PARAMS.has(name)) params[name] = subjectText(v);
      else if (PLAIN_PARAMS.has(name)) params[name] = serverText(v);
      else if (name === 'from' || name === 'to') params[name] = yesNo(v);
      else params[name] = v;
    });
    return t(r.key, params);
  }
  return src;
}

/** The place of a rule problem (`effects[0].respond.status`) is shown as the server wrote it; the message is localized. */
export function problemMessage(message: string): string {
  return serverText(message);
}
