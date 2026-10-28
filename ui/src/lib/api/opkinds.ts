// "Questa operazione è una lettura" (rules v1.6, admin-api 1.20.0, /api/v1/rules/op-kinds): the miner classifies an
// operation by what it does, not by its method; a person can decide instead, per group and operation.

/** A person's decision on the kind of an operation. */
export interface OpKindDecision {
  group: string;
  service: string;
  op: string;
  read: boolean;
  setBy: string;
  setAt: string;
}

/** An operation the latest mining run classified as a read from the traffic (a POST that only reads). */
export interface OpKindAuto {
  group: string;
  service: string;
  op: string;
}

export interface OpKinds {
  decisions: OpKindDecision[];
  auto: OpKindAuto[];
}

/** auto: the traffic decides; read / write: a person decided. */
export type OpKindChoice = 'auto' | 'read' | 'write';

export interface OpKindsApi {
  list(group?: string): Promise<OpKinds>;
  /** Stores the choice of a person (rule-reviewer); `auto` removes it. The next mining run uses it. */
  set(group: string, service: string, op: string, choice: OpKindChoice): Promise<void>;
}

/** What the console shows for one operation. */
export interface OpKindState {
  choice: OpKindChoice;
  /** The latest run classified it as a read from the traffic. */
  autoRead: boolean;
  decision?: OpKindDecision;
}

export function opKindState(k: OpKinds | undefined, group: string, service: string, op: string): OpKindState {
  const same = (x: { group: string; service: string; op: string }) => x.group === group && x.service === service && x.op === op;
  const decision = k?.decisions.find(same);
  return {
    choice: decision ? (decision.read ? 'read' : 'write') : 'auto',
    autoRead: !!k?.auto.some(same),
    decision,
  };
}

/** The kind an operation has by its method alone (GET reads; a GraphQL query reads). */
export function readByMethod(method: string, graphqlType?: string): boolean {
  if (graphqlType) return graphqlType === 'query';
  return method.toUpperCase() === 'GET';
}
