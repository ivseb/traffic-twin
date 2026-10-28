import type { Fix4Key } from './it-fix4';

// Texts of usability pass 4 (see it-fix4.ts).
export const enFix4: Record<Fix4Key, string> = {
  'fix4.loading': 'Loading…',
  'fix4.computing': 'Computing…',
  'fix4.slow': 'This takes longer than usual: the server is still working.',
  'fix4.renderFailed': 'This part of the page could not be shown ({error}).',
  'fix4.renderRetry': 'Try again',

  'fix4.re.loading': 'Preparing the editor: reading the contracts and entities of the group…',
  'fix4.re.noStates':
    'No object states seen yet: rules on states (an order going from created to shipped) need the status in clear. It usually happens by itself as “code in clear” (code), with no approval; only when the field has a name that is not a state’s does it need a keep, which another person has to approve. Meanwhile you can write rules that use no state: “the next call answers X” or “one call in N answers with an error”.',
  'fix4.re.noStatesLink': 'Let the states out in clear (Bulk review › States and codes)',
  'fix4.re.noValues': 'There are entities, but no field has values in clear: type the state values yourself until the status is in clear (usually as “code in clear”, with no approval).',
  'fix4.re.batchNeedsEntity': 'Scheduled rules change objects: they need entities recognised by the miner.',

  'fix4.bulk.loading': 'Computing the fields of the group from the observed traffic…',

  'fix4.rules.mining.queued': 'Search queued behind another heavy job ({s} s). The page follows it by itself: you can stay here.',
  'fix4.rules.mining.running': 'Search running for {s} s: with a lot of traffic it takes a minute or two. The page follows it by itself.',
  'fix4.rules.mining.retrying': 'The server is not answering for a moment: still following the search ({s} s)…',
  'fix4.rules.lastTitle': 'Result of the last search ({time})',
  'fix4.rules.noEffect':
    '{op} on {service} creates {entity}, but no lifecycle was observed: the state of the objects does not leave the service. The status must get out in clear: usually “code in clear” (code) is enough, which applies with no approval; a keep is only needed for fields that are not named like a state, and has to be approved.',
  'fix4.rules.noEffectLink': 'Open Bulk review › States and codes',
  'fix4.rules.failed': 'The search stopped with a server error ({code}). Try again; if it happens again, ask an administrator to look at the tt-core logs.',

  'fix4.sc.deterministicHint': 'The faults you add below always fire: the switch turns off only the random ones copied from the traffic.',
  'fix4.sc.status': 'HTTP status',
  'fix4.sc.p': 'Probability (0–1)',
  'fix4.sc.legacyOff': 'Saved by an earlier version of the console: the faults of this preset do not fire. Open it and save it again.',

  'fix4.twin.note':
    'A new policy version adds this host as an external service. If it opens no values in clear it applies at once; if it does, it stays a draft to approve. Before you confirm, you see what the server says.',
  'fix4.twin.check': 'Check what changes',
  'fix4.twin.confirm': 'Confirm and create',
  'fix4.twin.checking': 'Asking the server how the change applies…',
  'fix4.twin.safe': 'The server says: this change opens no values in clear and applies at once, with no approval.',
  'fix4.twin.opens': 'The server says: this change opens values in clear and needs {n, plural, one {# approval} other {# approvals from different people}}. Until it is approved the sources do not change behaviour.',
  'fix4.twin.unknown': 'The server cannot classify the change yet (the assistant has not seen this host): it will tell as soon as you create it.',
  'fix4.twin.applied': 'Applied at {time}: version {v} is active, no approval was needed.',
  'fix4.twin.waiting': 'Draft v{v} waiting: {n} of {total} approvals. Until it is approved the sources do not change behaviour.',
  'fix4.twin.ids': 'The identifiers in the answers of the new service stay hidden (drop) until they become tokens (hmac): check them with Bulk review › Identifiers.',
  'fix4.twin.idsLink': 'Open Bulk review',

  'fix4.next.title': 'Next step: have the values in clear approved',
  'fix4.next.draft': 'Draft {policy} v{v} of group {group} waits for {n, plural, one {# approval} other {# approvals from different people}} ({have} so far).',
  'fix4.next.lose': 'Until it is approved:',
  'fix4.next.lose1': 'no rules with states (an order going from created to delivered): the miner sees no lifecycle;',
  'fix4.next.lose2': 'no linked fields in the contracts (macro-category → category);',
  'fix4.next.lose3': 'the mock answers fake, static values (“synthetic”).',
  'fix4.next.self': 'You proposed this draft: another person has to approve it.',
  'fix4.next.message': 'Message for the approver',
  'fix4.next.copy': 'Copy the message',
  'fix4.next.open': 'Open the draft',
  'fix4.next.msgText':
    'Hi, could you approve the policy draft {policy} v{v} of group {group} in traffic-twin? It lets some fields out in clear (keep) and amounts in buckets: needed for rules with states, linked fields and a realistic mock. Link to the draft: {link}',
  'fix4.appr.adminTag': '(administrator: approves alone, with a reason)',
  'fix4.appr.none': 'Nobody can approve the policies of this group: ask an administrator to give someone the Policy approver role.',

  'fix4.mk.cli': 'tt (kit)',
  'fix4.mk.cliNote':
    'With the tt binary of the kit, the same version as the console ({version}): check with “tt version”. Put console-ca.pem next to the command, the CA of the console certificate (with a certificate of a public CA drop --console-ca).',
  'fix4.mk.dockerNote': 'The image is the same version as the console ({version}). The command mounts console-ca.pem (the CA of the console certificate) and passes it with --console-ca.',
  'fix4.mk.tokenPrefix': 'ttm_… is the secret (it goes into TT_MOCK_TOKEN, shown only once); mtk-… is only its id, the one of the list below you revoke it with.',

  'fix4.scope.mineNone': 'My groups (none yet)',
  'fix4.scope.noneNote': 'You work with no group yet (no token created, no policy proposed): the lists show the data of every team, the Overview counts only yours.',
  'fix4.home.noGroups': 'You have not connected a service yet: the Overview counts only the groups you work with. Start from Connect.',

  'fix4.prep.last': 'Last preparation of group {group}, started at {time}:',

  'fix4.wiz.capturing': 'Capture is already active with policy v{v}: the drafts below only let values out in clear.',
  'fix4.wiz.pickGroup': 'The policy assistant needs the group: pick one at the bottom of this page (“Resume a group”), or connect a new service.',
  'fix4.wiz.stepLoading': 'Opening the policy assistant of group {group}…',
  'fix4.wiz.stepFailed': 'This step cannot be opened.',
  'fix4.wiz.backStart': 'Back to the start',

  'fix4.cs.downloadJson': 'Download JSON',
  'fix4.cs.downloadYaml': 'Download YAML',
  'fix4.cs.show': 'Show {f}',
  'fix4.src.draftsBadge': 'drafts waiting',
  'fix4.pub.risk.how': 'How to read these numbers',
  'fix4.pub.risk.explain':
    'They are measures on the real profiles the archetypes come from: they are not part of the pack, which holds synthetic data only. Every archetype groups at least k people (“Smallest archetype”): the k-thresholds check of the gate blocks the pack if a group is smaller.',
  'fix4.pub.risk.exactHint': 'share of real profiles identical to the typical profile of their archetype. At 100% with few archetypes the customers almost all behave the same way (normal with a test load): the archetype describes everyone, but each one stays among at least k people.',
  'fix4.pub.risk.homogeneityHint': 'in the most uniform archetype, the share of members with the same profile. At 100% knowing that a person is in that archetype tells all of their (aggregated) behaviour, not who they are.',
  'fix4.pub.risk.uniqueHint': 'shares of profiles unique before grouping and of archetypes matching a single real person: these are the numbers that must stay low.',
};
