import { describe, expect, it } from 'vitest';
import { detectLang, interpolate, placeholders, translate } from './core';
import { it as itBase } from './it';
import { en as enBase } from './en';
import { itConsole } from './it-console';
import { enConsole } from './en-console';
import { itUx } from './it-ux';
import { enUx } from './en-ux';
import { itJourney } from './it-journey';
import { enJourney } from './en-journey';
import { itObserve } from './it-observe';
import { enObserve } from './en-observe';
import { itRules } from './it-rules';
import { enRules } from './en-rules';
import { itMock } from './it-mock';
import { enMock } from './en-mock';
import { itWorld } from './it-world';
import { enWorld } from './en-world';
import { itFix4 } from './it-fix4';
import { enFix4 } from './en-fix4';
import { itFix5 } from './it-fix5';
import { enFix5 } from './en-fix5';
import { itIdfmt } from './it-idfmt';
import { enIdfmt } from './en-idfmt';
import { ID_FORMAT_ERROR_CODES } from '../api/idfmt';
import { itIdentity } from './it-identity';
import { enIdentity } from './en-identity';
import { itGraphql } from './it-graphql';
import { enGraphql } from './en-graphql';
import { itWave1 } from './it-wave1';
import { enWave1 } from './en-wave1';
import { itWave3 } from './it-wave3';
import { enWave3 } from './en-wave3';
import { itWave4 } from './it-wave4';
import { enWave4 } from './en-wave4';

import { itMock2 } from './it-mock2';
import { enMock2 } from './en-mock2';
import { DERIVE_FNS } from '../derive';
import { PAGE_PLACEHOLDERS } from '../api/pages';

const itDict = { ...itBase, ...itConsole, ...itUx, ...itJourney, ...itObserve, ...itRules, ...itMock, ...itWorld, ...itFix4, ...itFix5, ...itIdfmt, ...itIdentity, ...itGraphql, ...itWave1, ...itWave3, ...itWave4, ...itMock2 };
const en = { ...enBase, ...enConsole, ...enUx, ...enJourney, ...enObserve, ...enRules, ...enMock, ...enWorld, ...enFix4, ...enFix5, ...enIdfmt, ...enIdentity, ...enGraphql, ...enWave1, ...enWave3, ...enWave4, ...enMock2 };

const dicts = { it: itDict as Record<string, string>, en: en as Record<string, string> };

describe('dictionaries', () => {
  it('keep the console texts apart from the base dictionary', () => {
    expect(Object.keys(itConsole).filter((k) => k in itBase)).toEqual([]);
    expect(Object.keys(enConsole).sort()).toEqual(Object.keys(itConsole).sort());
  });
  it('keep the usability texts apart from the other dictionaries', () => {
    expect(Object.keys(itUx).filter((k) => k in itBase || k in itConsole)).toEqual([]);
    expect(Object.keys(enUx).sort()).toEqual(Object.keys(itUx).sort());
  });
  it('keep the journey texts apart from the other dictionaries', () => {
    expect(Object.keys(itJourney).filter((k) => k in itBase || k in itConsole || k in itUx)).toEqual([]);
    expect(Object.keys(enJourney).sort()).toEqual(Object.keys(itJourney).sort());
  });
  it('keep the observe texts apart from the other dictionaries', () => {
    expect(Object.keys(itObserve).filter((k) => k in itBase || k in itConsole || k in itUx || k in itJourney || k in itRules)).toEqual([]);
    expect(Object.keys(enObserve).sort()).toEqual(Object.keys(itObserve).sort());
  });
  it('keep the rule editor texts apart from the other dictionaries', () => {
    expect(Object.keys(itRules).filter((k) => k in itBase || k in itConsole || k in itUx || k in itJourney)).toEqual([]);
    expect(Object.keys(enRules).sort()).toEqual(Object.keys(itRules).sort());
  });
  it('keep the Mock page texts apart from the other dictionaries', () => {
    expect(Object.keys(itMock).filter((k) => k in itBase || k in itConsole || k in itUx || k in itJourney || k in itObserve || k in itRules)).toEqual([]);
    expect(Object.keys(enMock).sort()).toEqual(Object.keys(itMock).sort());
  });
  it('keep the world texts apart from the other dictionaries', () => {
    expect(Object.keys(itWorld).filter((k) => k in itBase || k in itConsole || k in itUx || k in itJourney || k in itObserve || k in itRules || k in itMock)).toEqual([]);
    expect(Object.keys(enWorld).sort()).toEqual(Object.keys(itWorld).sort());
  });
  it('keep the texts of usability pass 4 apart from the other dictionaries', () => {
    const others = { ...itBase, ...itConsole, ...itUx, ...itJourney, ...itObserve, ...itRules, ...itMock, ...itWorld };
    expect(Object.keys(itFix4).filter((k) => k in others)).toEqual([]);
    expect(Object.keys(enFix4).sort()).toEqual(Object.keys(itFix4).sort());
  });
  it('keep the texts of usability pass 5 apart from the other dictionaries', () => {
    const others = { ...itBase, ...itConsole, ...itUx, ...itJourney, ...itObserve, ...itRules, ...itMock, ...itWorld, ...itFix4 };
    expect(Object.keys(itFix5).filter((k) => k in others)).toEqual([]);
    expect(Object.keys(enFix5).sort()).toEqual(Object.keys(itFix5).sort());
  });
  it('keep the id format and identity texts apart from the other dictionaries', () => {
    const others = { ...itBase, ...itConsole, ...itUx, ...itJourney, ...itObserve, ...itRules, ...itMock, ...itWorld, ...itFix4, ...itFix5 };
    expect(Object.keys(itIdfmt).filter((k) => k in others)).toEqual([]);
    expect(Object.keys(enIdfmt).sort()).toEqual(Object.keys(itIdfmt).sort());
  });
  it('translate every id format error code in both languages', () => {
    for (const c of ID_FORMAT_ERROR_CODES) {
      expect(dicts.it[`idf.err.${c}`], c).toBeTruthy();
      expect(dicts.en[`idf.err.${c}`], c).toBeTruthy();
    }
    for (const c of ['invalid_format', 'invalid_header', 'invalid_claim', 'invalid_customer']) expect(dicts.it[`err.${c}`], c).toBeTruthy();
  });
  it('keep the user identity texts apart from the other dictionaries', () => {
    const others = { ...itBase, ...itConsole, ...itUx, ...itJourney, ...itObserve, ...itRules, ...itMock, ...itWorld, ...itFix4, ...itFix5 };
    expect(Object.keys(itIdentity).filter((k) => k in others)).toEqual([]);
    expect(Object.keys(enIdentity).sort()).toEqual(Object.keys(itIdentity).sort());
  });
  it('keep the GraphQL texts apart from the other dictionaries', () => {
    const others = { ...itBase, ...itConsole, ...itUx, ...itJourney, ...itObserve, ...itRules, ...itMock, ...itWorld, ...itFix4, ...itFix5, ...itIdfmt, ...itIdentity };
    expect(Object.keys(itGraphql).filter((k) => k in others)).toEqual([]);
    expect(Object.keys(enGraphql).sort()).toEqual(Object.keys(itGraphql).sort());
  });
  it('keep the wave 1 texts apart from the other dictionaries', () => {
    const others = { ...itBase, ...itConsole, ...itUx, ...itJourney, ...itObserve, ...itRules, ...itMock, ...itWorld, ...itFix4, ...itFix5, ...itIdfmt, ...itIdentity, ...itGraphql };
    expect(Object.keys(itWave1).filter((k) => k in others)).toEqual([]);
    expect(Object.keys(enWave1).sort()).toEqual(Object.keys(itWave1).sort());
  });
  it('keep the wave 3 texts apart from the other dictionaries', () => {
    const others = { ...itBase, ...itConsole, ...itUx, ...itJourney, ...itObserve, ...itRules, ...itMock, ...itWorld, ...itFix4, ...itFix5, ...itIdfmt, ...itIdentity, ...itGraphql, ...itWave1 };
    expect(Object.keys(itWave3).filter((k) => k in others)).toEqual([]);
    expect(Object.keys(enWave3).sort()).toEqual(Object.keys(itWave3).sort());
  });
  it('keep the wave 4 texts apart from the other dictionaries', () => {
    const others = { ...itBase, ...itConsole, ...itUx, ...itJourney, ...itObserve, ...itRules, ...itMock, ...itWorld, ...itFix4, ...itFix5, ...itIdfmt, ...itIdentity, ...itGraphql, ...itWave1, ...itWave3 };
    expect(Object.keys(itWave4).filter((k) => k in others)).toEqual([]);
    expect(Object.keys(enWave4).sort()).toEqual(Object.keys(itWave4).sort());
  });
  it('cover the candidate kinds, templates and family signals of the server (rules v1.9)', () => {
    const kinds = ['create', 'update', 'keyed_update', 'update_all', 'remove', 'limit', 'precondition', 'later', 'revert'].map((x) => `w4.cand.kind.${x}`);
    const tpls = ['write_changes_field', 'expires_after', 'at_most_n', 'until'].flatMap((x) => [`w4.tpl.name.${x}`, `w4.tpl.desc.${x}`]);
    const sigs = ['same_cardinality', 'write_read_follow', 'same_ops'].map((x) => `w4.fam.sig.${x}`);
    expect([...kinds, ...tpls, ...sigs].filter((k) => !(k in itDict))).toEqual([]);
  });
  it('cover the identity signals and exclusions of the server', () => {
    const sig = ['jwt_bearer', 'jwt_shape', 'id_shape', 'short_shape', 'personal_shape', 'long_shape', 'repeats', 'most_calls', 'some_calls', 'name_hint'].map((x) => `id.sig.${x}`);
    const excl = ['credential', 'cookie', 'few_values', 'per_call', 'not_id_shape', 'rare'].map((x) => `id.excl.${x}`);
    expect([...sig, ...excl].filter((k) => !(k in itDict))).toEqual([]);
  });
  it('keep the relative dates, third-party pages and derived values texts apart from the other dictionaries', () => {
    const others = { ...itBase, ...itConsole, ...itUx, ...itJourney, ...itObserve, ...itRules, ...itMock, ...itWorld, ...itFix4, ...itFix5, ...itIdfmt, ...itIdentity };
    expect(Object.keys(itMock2).filter((k) => k in others)).toEqual([]);
    expect(Object.keys(enMock2).sort()).toEqual(Object.keys(itMock2).sort());
  });
  it('cover the derived value functions, kinds and errors and the page placeholders and problems', () => {
    const keys = [
      ...DERIVE_FNS.flatMap((f) => [`drv.fn.${f}`, `drv.fn.${f}.help`]),
      ...['number', 'var', 'field', 'effect', 'now', 'text', 'nested'].map((k) => `drv.kind.${k}`),
      ...['shape', 'unknownKey', 'depth', 'fn', 'args', 'digits', 'offset', 'format', 'template', 'onlyDate', 'onlyTemplate', 'onlyRound', 'argNumber', 'argRef', 'argText', 'argType'].map((c) => `drv.err.${c}`),
      ...PAGE_PLACEHOLDERS.map((x) => `pg.ph.${x.replace('.<name>', '')}`),
      ...['id', 'idTaken', 'title', 'description', 'buttons', 'action', 'label', 'value', 'show', 'placeholder', 'returnUrl', 'returnHosts', 'returnHost', 'callbackUrl', 'bodySize', 'header', 'hmacHeader', 'hmacKey', 'hmacPrefix', 'linkOp', 'linkPath', 'linkRefPath', 'linkBase', 'linkReturnFrom', 'linkEntity', 'linkEntityRef', 'setSize', 'setField', 'setValue', 'autoKey', 'autoAction'].map((c) => `pg.err.${c}`),
      ...['type', 'size', 'json'].map((c) => `ebody.err.${c}`),
      ...['bad_derived', 'derived_type', 'unknown_field'].map((c) => `re.code.${c}`),
      ...['invalid_offset', 'invalid_field', 'invalid_group', 'invalid_pages'].map((c) => `err.${c}`),
    ];
    expect(keys.filter((k) => !(k in itDict))).toEqual([]);
  });
  it('have exactly the same keys', () => {
    expect(Object.keys(en).sort()).toEqual(Object.keys(itDict).sort());
  });
  it('use the same placeholders in both languages', () => {
    for (const k of Object.keys(itDict)) {
      expect(placeholders(dicts.en[k]), k).toEqual(placeholders(dicts.it[k]));
    }
  });
  it('have no empty messages', () => {
    for (const lang of ['it', 'en'] as const) for (const [k, v] of Object.entries(dicts[lang])) expect(v.trim(), `${lang}:${k}`).not.toBe('');
  });
  it('define every key referenced statically from the sources', () => {
    const sources = import.meta.glob(['../../**/*.svelte', '../../**/*.ts', '!../../**/*.test.ts', '!../../lib/i18n/*.ts', '!../../lib/api/mock/*.ts', '!../../demo/*.ts', '!../../demo/*.svelte'], { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
    expect(Object.keys(sources).length).toBeGreaterThan(40);
    const missing: string[] = [];
    for (const [f, src] of Object.entries(sources)) {
      for (const m of src.matchAll(/\b(?:t|tk)\(\s*'([a-zA-Z0-9_.-]+)'/g)) if (!(m[1] in itDict)) missing.push(`${f}: ${m[1]}`);
    }
    expect(missing).toEqual([]);
  });
  it('cover the dynamic key families', () => {
    const roles = ['admin', 'operator', 'rule-reviewer', 'policy-approver', 'publisher', 'auditor', 'event-exporter'];
    const checks = ['provenance', 'reverse-hmac', 'pii-detectors', 'k-thresholds'];
    const problems = ['token_expired', 'cert_rejected', 'no_policy', 'policy_rejected', 'key_missing', 'key_mismatch', 'no_subject_found', 'intake_rejecting', 'clock_skew'];
    const keys = [
      ...roles.flatMap((r) => [`role.${r}`, `role.${r}.desc`]),
      ...checks.flatMap((c) => [`gate.${c}.name`, `gate.${c}.desc`]),
      ...problems.map((p) => `problem.${p}`),
      ...['network', 'unavailable', 'rate_limited', 'unsupported', 'server', 'forbidden'].map((c) => `err.code.${c}`),
      ...['signed', 'published', 'gate-failed', 'building'].map((x) => `status.${x}`),
      ...['healthy', 'degraded', 'offline', 'killed', 'revoked', 'capturing', 'approved', 'active', 'pass', 'fail', 'ok', 'resolved', 'stale', 'draft', 'running', 'pending', 'skipped', 'acknowledged', 'superseded', 'rejected', 'denied', 'error', 'open', 'breaking', 'non-breaking', 'info'].map((s) => `status.${s}`),
      ...['wiremock', 'microcks', 'prism'].map((x) => `export.${x}`),
      ...['production', 'staging', 'development'].map((x) => `env.${x}`),
      ...['few-samples', 'status-never-seen', 'low-support-rule', 'value-unknown', 'entity-without-creator'].map((x) => `gaps.kind.${x}`),
      ...['s', 'm', 'h', 'd'].map((x) => `time.unit.${x}`),
      ...['approve', 'reject', 'confirm', 'retire'].map((x) => `rules.done.${x}`),
      ...['withdrawn', 'retired'].map((x) => `status.${x}`),
      ...['contract.drift', 'rule.stale', 'quarantine.opened', 'source.problem', 'kill.changed', 'keyguard.alert', 'pack.published', 'storage.high_watermark', 'source.health', 'policy.admin_approval'].map((x) => `al.type.${x}`),
      ...['1h', '24h', '7d', '30d', 'all'].map((x) => `range.${x}`),
      ...['swagger', 'redoc', 'scalar'].flatMap((x) => [`docs.v.${x}`, `cs.v.${x}`]),
      ...['seconds', 'minutes', 'hours', 'days'].map((x) => `magnitude.${x}`),
      ...['few-samples', 'status-never-seen', 'low-support-rule', 'value-unknown', 'entity-without-creator'].map((x) => `gj.do.${x}`),
      ...['connect', 'observe', 'review', 'mock'].flatMap((x) => [`journey.step.${x}`, `journey.lead.${x}`, `journey.open.${x}`]),
      ...['pending', 'running', 'done', 'skipped', 'failed'].map((x) => `ps.${x}`),
      ...['sources.manage', 'sources.kill', 'policy.propose', 'policy.approve', 'rules.edit', 'rules.review', 'worlds.generate', 'publish.build', 'webhooks.manage', 'publish.run', 'publish.download', 'scenarios.edit', 'alerts.manage', 'users.manage', 'settings.edit', 'audit.view'].map((x) => `perm.${x}`),
    ];
    expect(keys.filter((k) => !(k in itDict))).toEqual([]);
  });
});

describe('interpolate', () => {
  it('replaces placeholders and keeps unknown ones', () => {
    expect(interpolate('Ciao {name} {x}', { name: 'Ada' }, 'it')).toBe('Ciao Ada {x}');
  });
  it('picks plural forms per language', () => {
    const m = '{n, plural, one {# fonte} other {# fonti}}';
    expect(interpolate(m, { n: 1 }, 'it')).toBe('1 fonte');
    expect(interpolate(m, { n: 3 }, 'it')).toBe('3 fonti');
    expect(interpolate(m, { n: 0 }, 'it')).toBe('0 fonti');
  });
  it('formats big numbers with the locale', () => {
    expect(interpolate('{n, plural, one {# x} other {# x}}', { n: 18400 }, 'it')).toBe('18.400 x');
  });
});

describe('translate / detectLang', () => {
  it('translates and falls back to the default language, then to the key', () => {
    expect(translate({ it: { a: 'uno' }, en: { a: 'one' } }, 'en', 'a')).toBe('one');
    expect(translate({ it: { a: 'uno' }, en: {} }, 'en', 'a')).toBe('uno');
    expect(translate({ it: {}, en: {} }, 'en', 'zzz')).toBe('zzz');
  });
  it('defaults to Italian', () => {
    expect(detectLang(null, [])).toBe('it');
    expect(detectLang(null, ['fr-FR'])).toBe('it');
  });
  it('honours a saved choice, then the browser languages', () => {
    expect(detectLang('en', ['it-IT'])).toBe('en');
    expect(detectLang(null, ['en-GB', 'it'])).toBe('en');
    expect(detectLang('xx', ['it-IT'])).toBe('it');
  });
});
