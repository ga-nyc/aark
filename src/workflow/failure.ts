import { StorageQuotaError } from "../core/storage.js";

/** Fixed diagnostics only: exception messages can contain evidence or credentials. */
const FAILURES = new Map<string, string>([
  ["lsblk did not return the requested source device", "source-device-identity-unresolved"],
  ["mountedReadOnlyRoot is not on a read-only mount", "source-mount-not-read-only"],
  ["workflow recovery did not complete successfully", "recovery-stage-failed"],
  ["recovery source identity differs from workflow authorization", "source-identity-changed"],
  ["a selected recovery output has no completed producing stage", "recovery-output-incomplete"],
  ["workflow scan did not complete without errors", "scan-completed-with-errors"],
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

const STORAGE_FAILURES = ["free-space-reserve", "output-cap"] as const;
const MAX_DIAGNOSTIC_ERRORS = 8;

export const FAILURE_CODES = new Set([...FAILURES.values(), ...STORAGE_FAILURES, "unclassified-failure"]);

export function workflowFailureCode(error: unknown): string {
  const pending = [error];
  const visited = new Set<Error>();
  while (pending.length > 0 && visited.size < MAX_DIAGNOSTIC_ERRORS) {
    const current = pending.pop();
    if (!(current instanceof Error) || visited.has(current)) continue;
    visited.add(current);
    if (current instanceof StorageQuotaError && STORAGE_FAILURES.includes(current.reason)) return current.reason;
    const code = FAILURES.get(current.message);
    if (code !== undefined) return code;
    // Recovery aggregates its original error before report and lock-release errors.
    if (current instanceof AggregateError && Array.isArray(current.errors)) {
      pending.push(...current.errors.slice(0, MAX_DIAGNOSTIC_ERRORS).reverse());
    }
    pending.push(current.cause);
  }
  return "unclassified-failure";
}
