import type { Wave1Key } from './it-wave1';

// English texts of the wave 1 generic capabilities (rules v1.6, see it-wave1.ts).
export const enWave1: Record<Wave1Key, string> = {
  'w1.kind.title': 'Read or write',
  'w1.kind.subtitle':
    'To find the objects and their rules traffic-twin must know which operations read and which write. It tells by behaviour, not by method: a POST that only returns objects that already exist, always the same for the same request, without changing them, is a read.',
  'w1.kind.isRead': 'This operation is a read',
  'w1.kind.choice.auto': 'The traffic decides',
  'w1.kind.choice.read': 'It is a read',
  'w1.kind.choice.write': 'It is a write',
  'w1.kind.now.read': 'Today it is treated as a read.',
  'w1.kind.now.write': 'Today it is treated as a write.',
  'w1.kind.why.method': 'Its method says so ({method}).',
  'w1.kind.why.auto': 'Its behaviour says so: in the last analysis it only returned objects that already existed, always the same for the same request.',
  'w1.kind.why.person': '{by} decided it on {date}.',
  'w1.kind.next': 'The choice applies from the next analysis of the traffic and stays in the audit log.',
  'w1.kind.saved': 'Choice saved: it applies from the next analysis of the traffic.',
  'w1.kind.readonly': 'Only rule reviewers can change it.',
  'w1.rules.removes': 'removes {entity}: it leaves the lists, a read by id answers as for a removed object',
  'w2.rules.copy': '{field} takes the value the call sends in {ref}',
  'w2.rules.toggle': '{field} flips (true ↔ false) at every call',
  'w2.rules.where': 'only while {entity} still has {cond}: a write that already moved it elsewhere wins',
};
