// i18n core (pure). Messages use {name} placeholders and one plural form:
//   "{n, plural, one {# fonte} other {# fonti}}"   ('#' is the number)

export type Lang = 'it' | 'en';
export const LANGS: readonly Lang[] = ['it', 'en'];
export const DEFAULT_LANG: Lang = 'it';
export type Params = Record<string, string | number>;
export type Dict = Record<string, string>;

const PLURAL = /\{(\w+), plural, one \{([^{}]*)\} other \{([^{}]*)\}\}/g;

export function interpolate(msg: string, params: Params | undefined, lang: Lang): string {
  if (!params) return msg;
  const pr = new Intl.PluralRules(lang);
  const withPlural = msg.replace(PLURAL, (_m, name: string, one: string, other: string) => {
    const n = Number(params[name] ?? 0);
    const form = pr.select(n) === 'one' ? one : other;
    return form.replace(/#/g, new Intl.NumberFormat(lang).format(n));
  });
  return withPlural.replace(/\{(\w+)\}/g, (m, name: string) => (name in params ? String(params[name]) : m));
}

export function translate(dicts: Record<Lang, Dict>, lang: Lang, key: string, params?: Params): string {
  const msg = dicts[lang][key] ?? dicts[DEFAULT_LANG][key];
  if (msg === undefined) return key;
  return interpolate(msg, params, lang);
}

export function detectLang(saved: string | null | undefined, navigatorLangs: readonly string[] = []): Lang {
  if (saved === 'it' || saved === 'en') return saved;
  for (const l of navigatorLangs) {
    const base = l.toLowerCase().slice(0, 2);
    if (base === 'en') return 'en';
    if (base === 'it') return 'it';
  }
  return DEFAULT_LANG;
}

/** Placeholders ({x}) used by a message, for the dictionary consistency test. */
export function placeholders(msg: string): string[] {
  const out = new Set<string>();
  for (const m of msg.matchAll(/\{(\w+)(?:,)?/g)) out.add(m[1]);
  out.delete('plural');
  out.delete('one');
  out.delete('other');
  return [...out].sort();
}
