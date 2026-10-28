import { loc, setQuery } from './router.svelte';

/** A tab selection stored in the URL (?tab=…), so links and reloads keep it. */
export function queryTab(def: string, allowed: readonly string[]): { value: string } {
  return {
    get value() {
      const q = loc.query.tab;
      return q && allowed.includes(q) ? q : def;
    },
    set value(v: string) {
      setQuery({ tab: v === def ? '' : v });
    },
  };
}

/** A generic URL-backed choice (?key=value), e.g. the time range of a list. */
export function queryParam<T extends string>(key: string, def: T, allowed: readonly T[]): { value: T } {
  return {
    get value() {
      const q = loc.query[key] as T | undefined;
      return q && allowed.includes(q) ? q : def;
    },
    set value(v: T) {
      setQuery({ [key]: v === def ? '' : v });
    },
  };
}
