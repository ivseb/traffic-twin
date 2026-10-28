import { i18n } from '../i18n/index.svelte';
import type { FieldHelp, GlossaryEntry, HelpPack, PageGuide } from './types';
import { helpIt as helpItBase } from './it';
import { helpEn as helpEnBase } from './en';
import { consoleFieldsEn, consoleFieldsIt, consolePagesEn, consolePagesIt } from './console';
import { journeyFieldsEn, journeyFieldsIt, journeyPagesEn, journeyPagesIt } from './journey';
import { observeFieldsEn, observeFieldsIt, observeGlossaryEn, observeGlossaryIt, observePagesEn, observePagesIt } from './observe';
import { mockFieldsEn, mockFieldsIt, mockGlossaryEn, mockGlossaryIt, mockPagesEn, mockPagesIt } from './mock';
import { fix5FieldsEn, fix5FieldsIt } from './fix5';
import { parseRich, type Seg } from './rich';

export type { FieldHelp, GlossaryEntry, PageGuide, Seg };

const withConsole = (p: HelpPack, pages: HelpPack['pages'], fields: HelpPack['fields']): HelpPack => ({ ...p, pages: { ...p.pages, ...pages }, fields: { ...p.fields, ...fields } });
// The journey texts come last: they replace the guides of the same id.
// The observe phase (spec v1.6) comes after: onboarding, approvals and the glossary entries it changes.
const withObserve = (p: HelpPack, pages: HelpPack['pages'], fields: HelpPack['fields'], glossary: HelpPack['glossary']): HelpPack => ({ ...withConsole(p, pages, fields), glossary: { ...p.glossary, ...glossary } });
const helpItObs = withObserve(withConsole(withConsole(helpItBase, consolePagesIt, consoleFieldsIt), journeyPagesIt, journeyFieldsIt), observePagesIt, observeFieldsIt, observeGlossaryIt);
const helpEnObs = withObserve(withConsole(withConsole(helpEnBase, consolePagesEn, consoleFieldsEn), journeyPagesEn, journeyFieldsEn), observePagesEn, observeFieldsEn, observeGlossaryEn);
// The Mock page (mock as a service) comes last: its guide replaces the placeholder of the journey.
export const helpIt = withObserve(helpItObs, mockPagesIt, { ...mockFieldsIt, ...fix5FieldsIt }, mockGlossaryIt);
export const helpEn = withObserve(helpEnObs, mockPagesEn, { ...mockFieldsEn, ...fix5FieldsEn }, mockGlossaryEn);
const packs = { it: helpIt, en: helpEn } as const;
export const pack = (): HelpPack => packs[i18n.lang];

export function pageGuide(id: string): PageGuide | undefined {
  return pack().pages[id] ?? packs.it.pages[id];
}
export function fieldHelp(id: string): FieldHelp | undefined {
  return pack().fields[id] ?? packs.it.fields[id];
}
export function glossaryEntry(id: string): GlossaryEntry | undefined {
  return pack().glossary[id] ?? packs.it.glossary[id];
}
export function helpUi(key: string): string {
  return pack().ui[key] ?? packs.it.ui[key] ?? key;
}

export function rich(src: string): Seg[] {
  return parseRich(src, (id) => glossaryEntry(id)?.term);
}
