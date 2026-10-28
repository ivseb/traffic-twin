import { DEFAULT_LANG, detectLang, translate, type Lang, type Params } from './core';
import { it as itBase, type MsgKey as BaseKey } from './it';
import { en as enBase } from './en';
import { itConsole, type ConsoleKey } from './it-console';
import { enConsole } from './en-console';
import { itUx, type UxKey } from './it-ux';
import { enUx } from './en-ux';
import { itRules, type RulesKey } from './it-rules';
import { enRules } from './en-rules';
import { itJourney, type JourneyKey } from './it-journey';
import { enJourney } from './en-journey';
import { itObserve, type ObserveKey } from './it-observe';
import { enObserve } from './en-observe';
import { itMock, type MockKey } from './it-mock';
import { enMock } from './en-mock';
import { itWorld, type WorldKey } from './it-world';
import { enWorld } from './en-world';
import { itFix4, type Fix4Key } from './it-fix4';
import { enFix4 } from './en-fix4';
import { itFix5, type Fix5Key } from './it-fix5';
import { enFix5 } from './en-fix5';
import { itIdfmt, type IdfmtKey } from './it-idfmt';
import { enIdfmt } from './en-idfmt';
import { itIdentity, type IdentityKey } from './it-identity';
import { enIdentity } from './en-identity';
import { itGraphql, type GraphqlKey } from './it-graphql';
import { enGraphql } from './en-graphql';
import { itWave1, type Wave1Key } from './it-wave1';
import { enWave1 } from './en-wave1';
import { itWave3, type Wave3Key } from './it-wave3';
import { enWave3 } from './en-wave3';
import { itWave4, type Wave4Key } from './it-wave4';
import { enWave4 } from './en-wave4';
import { itMock2, type Mock2Key } from './it-mock2';
import { enMock2 } from './en-mock2';

/** Keys of it.ts plus the console texts of it-console.ts (installed-console help, group filter, contracts status, ...). */
export type MsgKey = BaseKey | ConsoleKey | UxKey | JourneyKey | ObserveKey | RulesKey | MockKey | WorldKey | Fix4Key | Fix5Key | IdfmtKey | IdentityKey | GraphqlKey | Wave1Key | Wave3Key | Wave4Key | Mock2Key;
export type { Lang };

const dicts = {
  it: { ...itBase, ...itConsole, ...itUx, ...itJourney, ...itObserve, ...itRules, ...itMock, ...itWorld, ...itFix4, ...itFix5, ...itIdfmt, ...itIdentity, ...itGraphql, ...itWave1, ...itWave3, ...itWave4, ...itMock2 },
  en: { ...enBase, ...enConsole, ...enUx, ...enJourney, ...enObserve, ...enRules, ...enMock, ...enWorld, ...enFix4, ...enFix5, ...enIdfmt, ...enIdentity, ...enGraphql, ...enWave1, ...enWave3, ...enWave4, ...enMock2 },
} as const;

function readSaved(): string | null {
  try {
    return localStorage.getItem('tt.lang');
  } catch {
    return null;
  }
}

export const i18n = $state<{ lang: Lang }>({
  lang: typeof navigator === 'undefined' ? DEFAULT_LANG : detectLang(readSaved(), navigator.languages ?? []),
});

if (typeof document !== 'undefined') document.documentElement.lang = i18n.lang;

export function setLang(lang: Lang): void {
  i18n.lang = lang;
  if (typeof document !== 'undefined') document.documentElement.lang = lang;
  try {
    localStorage.setItem('tt.lang', lang);
  } catch {
    /* storage unavailable: preference lasts for this session only */
  }
}

/** Adds messages that only some builds have (the demo texts). Existing keys are kept. */
export function registerMessages(lang: Lang, messages: Record<string, string>): void {
  const dict = dicts[lang] as Record<string, string>;
  for (const [k, v] of Object.entries(messages)) if (!(k in dict)) dict[k] = v;
}

/** Typed translation (checked by svelte-check). */
export function t(key: MsgKey, params?: Params): string {
  return translate(dicts, i18n.lang, key, params);
}

/** Untyped translation for keys built at runtime (status.${x}); falls back to `fallback ?? key`. */
export function tk(key: string, params?: Params, fallback?: string): string {
  const out = translate(dicts, i18n.lang, key, params);
  return out === key && fallback !== undefined ? fallback : out;
}

export function locale(): string {
  return i18n.lang === 'it' ? 'it-IT' : 'en-GB';
}
