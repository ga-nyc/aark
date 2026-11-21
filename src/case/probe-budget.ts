import type { CaseConfig, PreparedAttempt } from "./types.js";

// Each source inspection can make several serial, independently bounded kernel
// metadata queries. These aggregate caps provide headroom, not a promise that
// every maximum-sized mapper graph fits within one observation.
export const RECOVERY_BINDING_TIMEOUT_MS = 120_000;
export const RECOVERY_CAPACITY_TIMEOUT_MS = 360_000;

export function bindingProbeTimeoutMs(attempt: PreparedAttempt, ordinary: number): number {
  return attempt.workflow.recovery === undefined ? ordinary : Math.max(ordinary, RECOVERY_BINDING_TIMEOUT_MS);
}

export function capacityProbeTimeoutMs(attempt: PreparedAttempt, ordinary: number): number {
  return attempt.workflow.recovery === undefined ? ordinary : Math.max(ordinary, RECOVERY_CAPACITY_TIMEOUT_MS);
}

/** A resume launch performs binding and readiness sequentially before submission. */
export function caseMetadataProbeBudget(config: CaseConfig): number {
  return Math.max(config.probeTimeoutMs, ...config.jobs.flatMap(job => job.attempts.map(attempt =>
    bindingProbeTimeoutMs(attempt, config.probeTimeoutMs)
    + (job.resumeAfterQuota ? capacityProbeTimeoutMs(attempt, config.probeTimeoutMs) : 0))));
}
