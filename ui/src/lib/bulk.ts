// «Rivedi in blocco», field by field (usability test #5, M2). The group action is only the default: every field has its
// own checkbox, the current action and the proposal are on the row, a field that already is `code` is never turned
// into `keep`, and only the fields that really let values out in clear are counted as «aperti».
import type { GroupApprover, PolicyChoice, PolicySuggestion } from './api/types';
import { approverNames } from './approval';
import { applyGroupAction, keepsCode, opensField, type GroupAction } from './observe';
import { sameChoice } from './policy';

/** The state of one field row of the bulk review. */
export interface BulkRow {
  field: PolicySuggestion;
  /** The checkbox: the field takes the action of its group. */
  selected: boolean;
  /** What the policy gets for this field (the current action when the box is off or the action changes nothing). */
  choice: PolicyChoice;
  /** The choice differs from what the policy does today. */
  changes: boolean;
  /** The change lets values out in clear (keep / finer bucket): it needs approvals. */
  opens: boolean;
  /** The assistant proposed `keep` for a field that already is `code`: it stays as it is, nothing to choose. */
  protectedCode: boolean;
}

/** Whether the box of a field starts on for `action`: when the action would change the field. */
export function defaultSelected(f: PolicySuggestion, action: GroupAction): boolean {
  return !sameChoice(applyGroupAction(f, action), f.current);
}

/** The row of a field. `override` is the box as the person left it (undefined: the default for the action). */
export function bulkRow(f: PolicySuggestion, action: GroupAction, override?: boolean): BulkRow {
  const selected = override ?? defaultSelected(f, action);
  const choice = selected ? applyGroupAction(f, action) : { ...f.current };
  const changes = !sameChoice(choice, f.current);
  return { field: f, selected, choice, changes, opens: changes && opensField(f.current, choice), protectedCode: action === 'proposal' && keepsCode(f) };
}

export interface BulkSummary {
  /** Fields whose action changes. */
  changed: number;
  /** Of those, the fields that let values out in clear (they ask for approvals). */
  opening: number;
  /** Fields that close or only mask (drop, hmac, code): no approval. */
  quiet: number;
  /** The fields that open values, by id. */
  openingIds: string[];
}

export function summarizeRows(rows: readonly BulkRow[]): BulkSummary {
  const changed = rows.filter((r) => r.changes);
  const opening = changed.filter((r) => r.opens);
  return { changed: changed.length, opening: opening.length, quiet: changed.length - opening.length, openingIds: opening.map((r) => r.field.id) };
}

/** How the approvals of a draft that opens values will go: how many, who can give them, and whether an admin must step in. */
export interface ApprovalPlan {
  /** Approvals needed (0: nothing opens). */
  need: number;
  /** People who can approve, the user excluded (policy-approvers; the administrators when there are none). */
  names: string[];
  /** Only administrators are listed: they approve alone, with a reason. */
  adminOnly: boolean;
  /** Fewer people than approvals needed: the draft would wait. */
  short: boolean;
  /** The user is an administrator: can approve alone, with a reason. */
  selfAdmin: boolean;
  /** Names could not be read (older server, not a member of the group). */
  unknown: boolean;
}

export function approvalPlan(opening: number, required: number, approvers: readonly GroupApprover[] | null, selfAdmin: boolean): ApprovalPlan {
  const need = opening > 0 ? required : 0;
  if (!approvers) return { need, names: [], adminOnly: false, short: false, selfAdmin, unknown: true };
  const r = approverNames(approvers);
  // The administrators alone do not make two approvals (each approves alone, as the override): the draft waits for them.
  const people = r.adminOnly ? 0 : r.names.length;
  return { need, names: r.names, adminOnly: r.adminOnly, short: need > 0 && people < need, selfAdmin, unknown: false };
}
