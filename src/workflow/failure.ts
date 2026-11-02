/** Fixed diagnostics only: exception messages can contain evidence or credentials. */
const FAILURES = new Map<string, string>([
  ["lsblk did not return the requested source device", "source-device-identity-unresolved"],
  ["mountedReadOnlyRoot is not on a read-only mount", "source-mount-not-read-only"],
  ["workflow recovery did not complete successfully", "recovery-stage-failed"],
  ["a selected recovery output has no completed producing stage", "recovery-output-incomplete"],
  ["workflow requires the exact error-free completed scan selection", "scan-completion-mismatch"],
  ["workflow mining inventory and checkpoint disagree", "scan-inventory-mismatch"],
  ["workflow input root changed after scanning", "input-root-changed"],
  ["workflow input tree differs from its complete frozen scan coverage", "input-coverage-changed"],
  ["workflow input tree contains unscanned files", "input-coverage-incomplete"],
  ["workflow input coverage walk failed", "input-walk-failed"],
  ["workflow finding occurrence escaped its authorized scan inputs", "finding-outside-inputs"],
  ["workflow mining controls changed during verification", "scan-controls-changed"],
  ["workflow mining checkpoint changed during verification", "scan-controls-changed"],
]);

export const FAILURE_CODES = new Set([...FAILURES.values(), "unclassified-failure"]);

export function workflowFailureCode(error: unknown): string {
  const visited = new Set<unknown>();
  let current = error;
  for (let depth = 0; depth < 8 && current instanceof Error && !visited.has(current); depth++) {
    visited.add(current);
    const code = FAILURES.get(current.message);
    if (code !== undefined) return code;
    current = current.cause;
  }
  return "unclassified-failure";
}
