import { createHash } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { assertNoSymlinkComponents, nearestExistingParent } from "../core/fs-safe.js";
import { inspectSourceSafety } from "../recovery/source-safety.js";
import { overlaps, type WorkflowConfig } from "../workflow/config.js";
import { workflowSourceIdentity } from "../workflow/verify.js";
import type { CaseConfig, CaseSourceBinding, CaseSourceBindings } from "./types.js";

export class CaseSourceIdentityError extends Error {
  public constructor() { super("case source identity differs from its authorization"); this.name = "CaseSourceIdentityError"; }
}
const fingerprint = (value: string): string => createHash("sha256").update(value).digest("hex");

/** Same ordering as native workflow resultsSafety; a generated image is not an original source. */
export function workflowExternalSources(config: WorkflowConfig): string[] {
  const recovery = config.recovery;
  return recovery === undefined ? [] : [recovery.source, ...(recovery.analysisSource === undefined || recovery.analysisSource === recovery.source
    || (recovery.image.enabled && recovery.analysisSource === recovery.image.path) ? [] : [recovery.analysisSource])];
}

async function resolvedLocation(value: string): Promise<string> {
  const existing = await nearestExistingParent(value);
  const canonical = await realpath(existing);
  const resolved = path.resolve(canonical, path.relative(existing, value));
  await assertNoSymlinkComponents(canonical, resolved);
  return resolved;
}

/** Missing sources produced by approved dependencies are checked natively at launch. */
export async function caseRecoverySourcesToInspect(config: CaseConfig): Promise<string[]> {
  const jobs = new Map(config.jobs.map(job => [job.id, job]));
  const ancestors = new Map<string, Set<string>>();
  const dependencies = (id: string): Set<string> => {
    const known = ancestors.get(id);
    if (known !== undefined) return known;
    const result = new Set<string>();
    ancestors.set(id, result); // Stored configurations already passed cycle validation.
    for (const parent of jobs.get(id)!.dependsOn) { result.add(parent); for (const root of dependencies(parent)) result.add(root); }
    return result;
  };
  const paths = new Map<string, Promise<string>>();
  const canonical = (value: string): Promise<string> => {
    let result = paths.get(value);
    if (result === undefined) { result = resolvedLocation(value); paths.set(value, result); }
    return result;
  };
  const sources = new Set<string>();
  for (const job of config.jobs) for (const attempt of job.attempts) for (const source of workflowExternalSources(attempt.workflow)) {
    try { await lstat(source); sources.add(source); continue; }
    catch (error) { if (!["ENOENT", "ENOTDIR"].includes((error as NodeJS.ErrnoException).code ?? "")) throw error; }
    const resolved = await canonical(source);
    let produced = false;
    for (const producer of dependencies(job.id)) for (const candidate of jobs.get(producer)!.attempts) {
      const workflow = candidate.workflow;
      for (const output of [workflow.output, ...(workflow.recovery === undefined ? [] : [workflow.recovery.destination])]) {
        if (overlaps(await canonical(output), resolved)) produced = true;
      }
    }
    if (!produced) sources.add(source);
  }
  return [...sources];
}

export async function captureSourceBindings(config: WorkflowConfig, sources = workflowExternalSources(config)): Promise<CaseSourceBinding[]> {
  const originals = new Set(workflowExternalSources(config));
  const result: CaseSourceBinding[] = [];
  const seen = new Set<string>();
  for (const source of sources) {
    if (!originals.has(source) || seen.has(source)) throw new CaseSourceIdentityError();
    seen.add(source);
    const safety = await inspectSourceSafety(source, config.output);
    if (!safety.safe) throw new CaseSourceIdentityError();
    result.push({source, sha256: fingerprint(workflowSourceIdentity(safety))});
  }
  return result;
}

export async function captureCaseSourceBindings(config: CaseConfig): Promise<CaseSourceBindings> {
  const originals = new Set(await caseRecoverySourcesToInspect(config));
  const bindings: CaseSourceBindings = {};
  for (const job of config.jobs) for (const attempt of job.attempts) {
    bindings[attempt.configHash] = await captureSourceBindings(attempt.workflow, workflowExternalSources(attempt.workflow).filter(source => originals.has(source)));
  }
  return bindings;
}

/** Compare native captured identities when supplied, avoiding a second source read. */
export async function assertSourceBindings(config: WorkflowConfig, bindings: CaseSourceBinding[], resultsSafety?: string[]): Promise<void> {
  const originals = workflowExternalSources(config);
  if (!Array.isArray(bindings) || (resultsSafety !== undefined && (!Array.isArray(resultsSafety) || resultsSafety.length !== originals.length))) {
    throw new CaseSourceIdentityError();
  }
  const seen = new Set<string>();
  for (const binding of bindings) {
    if (typeof binding !== "object" || binding === null || Object.keys(binding).some(key => !["source", "sha256"].includes(key))
      || typeof binding.source !== "string" || !originals.includes(binding.source) || seen.has(binding.source)
      || typeof binding.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(binding.sha256)) throw new CaseSourceIdentityError();
    seen.add(binding.source);
    let identity: string;
    if (resultsSafety !== undefined) {
      const captured = resultsSafety[originals.indexOf(binding.source)];
      if (typeof captured !== "string") throw new CaseSourceIdentityError();
      identity = captured;
    } else {
      const safety = await inspectSourceSafety(binding.source, config.output);
      if (!safety.safe) throw new CaseSourceIdentityError();
      identity = workflowSourceIdentity(safety);
    }
    if (fingerprint(identity) !== binding.sha256) throw new CaseSourceIdentityError();
  }
}
