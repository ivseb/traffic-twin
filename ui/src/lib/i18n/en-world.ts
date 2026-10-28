import type { WorldKey } from './it-world';

// English texts of the worlds without usable rules (see it-world.ts).
export const enWorld: Record<WorldKey, string> = {
  'err.no_usable_rules': 'None of this group’s approved rules can be used: the world would be empty (no object, no rule) and the mock would simulate nothing of what you approved.',
  'err.no_usable_rules.out_of_scope': 'Rule {rule} uses {services}, which is not a service of this group.',
  'err.no_usable_rules.unusable': 'Rule {rule} cannot be used: {detail}.',
  'err.no_usable_rules.fix': 'This usually happens when another team has an object with the same name: on Rules, run “Look for new rules” and approve the rules the miner proposes again for the group.',
  'world.excluded': 'World {id} was generated without {n, plural, one {# of the group’s rules} other {# of the group’s rules}}: {rules}. They need services that are not of this group: {services}.',
  'world.failedTitle': 'The world was not generated',
  'mk.step.code.no_usable_rules': 'none of the group’s approved rules can be used ({rules}; missing services: {services})',
  'mk.step.code.rules_excluded': '{customers} invented customers, {entities} objects; rules {rules} left out (they use {services})',
  'mk.err.no_usable_rules': 'The group’s world would be empty: none of its approved rules can be used (the details are in the world step). On Rules, run “Look for new rules”, approve the rules proposed for the group and try again.',
};
