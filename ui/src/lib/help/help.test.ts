import { describe, expect, it } from 'vitest';
import { helpIt, helpEn } from './index.svelte';
import { glossaryRefs, parseRich } from './rich';
import type { HelpPack } from './types';

const sources = import.meta.glob(['../../**/*.svelte', '../../**/*.ts', '!../../**/*.test.ts', '!../../lib/help/*.ts', '!../../lib/i18n/*.ts'], { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
const packs: [string, HelpPack][] = [['it', helpIt], ['en', helpEn]];

describe('help content', () => {
  it('has the same ids in Italian and English', () => {
    for (const k of ['pages', 'fields', 'glossary', 'ui'] as const) expect(Object.keys(helpEn[k]).sort(), k).toEqual(Object.keys(helpIt[k]).sort());
  });

  for (const [lang, p] of packs) {
    it(`${lang}: every glossary link and "term" points to an existing entry`, () => {
      const texts: string[] = [];
      for (const g of Object.values(p.glossary)) texts.push(g.short, g.long, g.example ?? '');
      for (const f of Object.values(p.fields)) texts.push(f.meaning, f.effect ?? '', f.default ?? '', f.when ?? '');
      for (const g of Object.values(p.pages)) texts.push(g.purpose, g.firstVisit, ...g.steps, ...g.effects, ...g.concepts.map((c) => c.text));
      const bad = texts.flatMap(glossaryRefs).filter((id) => !(id in p.glossary));
      expect(bad).toEqual([]);
      const badTerm = Object.entries(p.fields).filter(([, f]) => f.term && !(f.term in p.glossary)).map(([k]) => k);
      expect(badTerm).toEqual([]);
      const badSee = Object.values(p.glossary).flatMap((g) => g.see ?? []).filter((id) => !(id in p.glossary));
      expect(badSee).toEqual([]);
    });
    it(`${lang}: every page guide is complete`, () => {
      for (const [id, g] of Object.entries(p.pages)) {
        expect(g.title, id).toBeTruthy();
        expect(g.purpose.length, id).toBeGreaterThan(20);
        expect(g.firstVisit.length, id).toBeGreaterThan(10);
        expect(g.steps.length, id).toBeGreaterThan(0);
      }
    });
    it(`${lang}: glossary covers the required terms`, () => {
      const need = ['zone-a', 'zone-b', 'zone-c', 'sanitizer', 'policy', 'drop', 'keep', 'hmac', 'bucket', 'token', 'epoch-kid', 'discovery', 'auto-words', 'sampling', 'fleet', 'keyguard', 'gate', 'reverse-hmac', 'k-anonymity', 'archetype', 'world', 'twin-pack', 'rule', 'effect', 'outcome', 'figurative-delay', 'batch-rule', 'drift', 'mock-session', 'virtual-clock', 'scenario', 'export-losses'];
      expect(need.filter((n) => !(n in p.glossary))).toEqual([]);
    });
  }

  it('Fleet is described as UX-inspired, not an Elastic integration', () => {
    expect(helpIt.glossary.fleet.long).toMatch(/non è un.integrazione/);
    expect(helpEn.glossary.fleet.long).toMatch(/not an Elastic integration/);
  });

  it('every help id used by the code exists', () => {
    const fieldIds = new Set(Object.keys(helpIt.fields));
    const pageIds = new Set(Object.keys(helpIt.pages));
    const missing: string[] = [];
    for (const [f, src] of Object.entries(sources)) {
      for (const m of src.matchAll(/<InfoTip id="([a-z0-9.-]+)"/g)) if (!fieldIds.has(m[1])) missing.push(`${f}: InfoTip ${m[1]}`);
      for (const m of src.matchAll(/\bhelp: '([a-z0-9.-]+)'/g)) if (!fieldIds.has(m[1])) missing.push(`${f}: column ${m[1]}`);
      for (const m of src.matchAll(/<Field [^>]*\bhelp="([a-z0-9.-]+)"/g)) if (!fieldIds.has(m[1])) missing.push(`${f}: Field ${m[1]}`);
      for (const m of src.matchAll(/<PageHeader[^>]*\bhelp="([a-z0-9.-]+)"/g)) if (!pageIds.has(m[1])) missing.push(`${f}: page ${m[1]}`);
      for (const m of src.matchAll(/guide\?: string|guide: '([a-z-]+)'/g)) if (m[1] && !pageIds.has(m[1])) missing.push(`${f}: guide ${m[1]}`);
    }
    expect(missing).toEqual([]);
  });

  it('every route has a guide', () => {
    const routes = sources['../../routes.ts'];
    const ids = [...routes.matchAll(/\n  r\('[^']+', '([a-z-]+)'/g)].map((m) => m[1]);
    const guides = new Set(Object.keys(helpIt.pages));
    const alias: Record<string, string> = { 'contract-docs': 'contract-service', login: 'onboarding', setup: 'onboarding' };
    expect(ids.filter((i) => !guides.has(alias[i] ?? i))).toEqual([]);
  });

  it('has an explanation for every status shown as a pill', () => {
    for (const s of ['healthy', 'degraded', 'offline', 'killed', 'revoked', 'draft', 'approved', 'rejected', 'stale', 'active', 'pass', 'fail', 'skipped', 'breaking', 'non-breaking', 'open', 'resolved']) {
      expect(helpIt.fields[`status.${s}`], s).toBeTruthy();
    }
  });
});

describe('parseRich', () => {
  it('parses bold and glossary links', () => {
    const segs = parseRich('Vedi [[policy]] e [[mock|il mock]]: **importante**.', (id) => (id === 'policy' ? 'Policy' : undefined));
    expect(segs).toEqual([
      { t: 'text', v: 'Vedi ' },
      { t: 'g', id: 'policy', v: 'Policy' },
      { t: 'text', v: ' e ' },
      { t: 'g', id: 'mock', v: 'il mock' },
      { t: 'text', v: ': ' },
      { t: 'b', v: 'importante' },
      { t: 'text', v: '.' },
    ]);
  });
  it('leaves plain text alone', () => {
    expect(parseRich('niente')).toEqual([{ t: 'text', v: 'niente' }]);
  });
});
