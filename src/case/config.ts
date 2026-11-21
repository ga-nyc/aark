import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import path from "node:path";
import { assertNoSymlinkComponents, nearestExistingParent, readJson } from "../core/fs-safe.js";
import { loadWorkflowConfig, MAX_WORKFLOW_CONFIG_BYTES, overlaps } from "../workflow/config.js";
import { workflowPlan } from "../workflow/runner.js";
import type { CaseConfig, CaseJob, PreparedAttempt } from "./types.js";

export const MAX_CASE_BYTES = 16 * 1024 ** 2;
export function digest(value: unknown): string { return createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
export function caseConfigHash(config: CaseConfig): string { return digest(config); }

function object(value: unknown, keys: string[], label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)
    || Object.keys(value).some(key => !keys.includes(key))) throw new Error(`invalid case ${label}`);
  return value as Record<string, unknown>;
}
function location(value: unknown): string {
  if (typeof value !== "string" || !path.isAbsolute(value) || path.resolve(value) !== value
    || Buffer.byteLength(value) > 4096 || /[\x00-\x1f\x7f]/.test(value)) throw new Error("case paths must be canonical absolute paths");
  return value;
}
function integer(value: unknown, fallback: number, min: number, max: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || Number(result) < min || Number(result) > max) throw new Error("case numeric option outside its supported range");
  return Number(result);
}
function jobId(value: unknown): string {
  if (typeof value !== "string" || !/^job-[0-9]{6}$/.test(value)) throw new Error("case job IDs must use job-NNNNNN");
  return value;
}

/** Fresh attempts may move outputs, but cannot silently shrink detector/source coverage. */
function scope(attempt: PreparedAttempt): string {
  const workflow = attempt.workflow;
  const roots = [[workflow.output, "$RESULTS"], ...(workflow.recovery === undefined ? [] : [[workflow.recovery.destination, "$RECOVERY"]])];
  const normalize = (value: unknown): unknown => {
    if (typeof value === "string") {
      for (const [root, replacement] of roots) if (root !== undefined && replacement !== undefined && (value === root || value.startsWith(root + path.sep))) return replacement + value.slice(root.length);
      return value;
    }
    if (Array.isArray(value)) return value.map(normalize);
    if (typeof value === "object" && value !== null) return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, key === "caseId" ? "$CASE" : normalize(entry)]));
    return value;
  };
  return digest(normalize(workflow));
}

function sourceRoots(attempt: PreparedAttempt): string[] {
  const workflow = attempt.workflow;
  const recovery = workflow.recovery;
  return [...workflow.scans.flatMap(scan => scan.inputs), ...(recovery === undefined ? [] : [recovery.source,
    ...(recovery.analysisSource === undefined ? [] : [recovery.analysisSource]),
    ...(recovery.mountedReadOnlyRoot === undefined ? [] : [recovery.mountedReadOnlyRoot]),
    ...(recovery.unallocatedStreamFromCase === undefined ? [] : [recovery.unallocatedStreamFromCase])])];
}

/** Resolve existing aliases without requiring future output directories to exist. */
async function resolvedLocation(value: string): Promise<string> {
  const existing = await nearestExistingParent(value);
  const canonical = await realpath(existing);
  const resolved = path.resolve(canonical, path.relative(existing, value));
  // A dangling symlink in the unresolved suffix must not become a future alias.
  await assertNoSymlinkComponents(canonical, resolved);
  return resolved;
}

export async function loadCaseConfig(filename: string): Promise<CaseConfig> {
  const configurationFiles = new Set([location(path.resolve(filename))]);
  const raw = object(await readJson(filename, MAX_CASE_BYTES), ["version", "execute", "control", "jobs", "pollMs", "probeTimeoutMs", "maxConcurrent", "agent"], "configuration");
  if (raw.version !== 1 || typeof raw.execute !== "boolean") throw new Error("case configuration requires version 1 and an explicit execute flag");
  const control = location(raw.control);
  if (control === path.parse(control).root) throw new Error("case control must be a dedicated directory");
  if (!Array.isArray(raw.jobs) || raw.jobs.length < 1 || raw.jobs.length > 64) throw new Error("case requires 1 through 64 jobs");
  const jobs: CaseJob[] = [];
  for (const value of raw.jobs) {
    const input = object(value, ["id", "dependsOn", "attempts", "resumeAfterQuota"], "job");
    const id = jobId(input.id);
    if (!Array.isArray(input.dependsOn) || new Set(input.dependsOn).size !== input.dependsOn.length) throw new Error("case dependencies must be unique IDs");
    const dependsOn = input.dependsOn.map(jobId);
    if (!Array.isArray(input.attempts) || input.attempts.length < 1 || input.attempts.length > 4) throw new Error("case jobs require 1 through 4 reviewed attempts");
    if (typeof input.resumeAfterQuota !== "boolean") throw new Error("case quota-resume permission must be explicit");
    const attempts: PreparedAttempt[] = [];
    for (const entry of input.attempts) {
      const configFile = location(entry);
      configurationFiles.add(configFile);
      // The normalized workflow embeds its recovery settings, but omits the
      // original plan's filename. Protect that file from agent reads as well.
      const workflowDocument = await readJson<unknown>(configFile, MAX_WORKFLOW_CONFIG_BYTES);
      if (typeof workflowDocument !== "object" || workflowDocument === null || Array.isArray(workflowDocument)) {
        throw new Error("invalid case workflow configuration");
      }
      if ("recoveryConfig" in workflowDocument && workflowDocument.recoveryConfig !== undefined) {
        configurationFiles.add(location(workflowDocument.recoveryConfig));
      }
      const workflow = await loadWorkflowConfig(configFile);
      workflowPlan(workflow);
      if (!workflow.execute || (workflow.recovery !== undefined && (!workflow.recovery.execute || !workflow.recovery.requireReadOnlySource))) {
        throw new Error("case attempts require reviewed execution and read-only source protection");
      }
      attempts.push({configFile, configHash: digest(workflow), workflow});
    }
    if (attempts.some(attempt => scope(attempt) !== scope(attempts[0]!))) throw new Error("case retry attempts must preserve their exact authorized scan scope");
    jobs.push({id, dependsOn, attempts, resumeAfterQuota: input.resumeAfterQuota});
  }
  const ids = new Set(jobs.map(job => job.id));
  if (ids.size !== jobs.length || jobs.some(job => job.dependsOn.some(id => !ids.has(id) || id === job.id))) throw new Error("case contains duplicate or invalid dependencies");
  const byId = new Map(jobs.map(job => [job.id, job]));
  const dependencies = new Map<string, Set<string>>();
  const visiting = new Set<string>();
  const ancestors = (id: string): Set<string> => {
    if (visiting.has(id)) throw new Error("case dependency graph contains a cycle");
    const known = dependencies.get(id);
    if (known !== undefined) return known;
    visiting.add(id);
    const result = new Set<string>();
    for (const parent of byId.get(id)!.dependsOn) {
      result.add(parent);
      for (const ancestor of ancestors(parent)) result.add(ancestor);
    }
    visiting.delete(id);
    dependencies.set(id, result);
    return result;
  };
  for (const job of jobs) ancestors(job.id);
  const outputs = jobs.flatMap(job => job.attempts.flatMap(attempt => [attempt.workflow.output,
    ...(attempt.workflow.recovery === undefined ? [] : [attempt.workflow.recovery.destination])].map(root => ({job: job.id, root}))));
  const protectedPaths = [...configurationFiles, control, ...outputs.map(output => output.root),
    ...jobs.flatMap(job => job.attempts.flatMap(sourceRoots))];
  // Admission and the supervisor must agree on producers reached through an
  // alias, including outputs that do not exist yet. Resolve each distinct path
  // only once, using filesystem metadata without creating any case artifacts.
  const resolved = new Map<string, string>();
  for (const candidate of new Set(protectedPaths)) resolved.set(candidate, await resolvedLocation(candidate));
  const intersects = (left: string, right: string): boolean => overlaps(left, right) || overlaps(right, left)
    || overlaps(resolved.get(left)!, resolved.get(right)!) || overlaps(resolved.get(right)!, resolved.get(left)!);
  for (let i = 0; i < outputs.length; i++) for (let j = i + 1; j < outputs.length; j++) {
    if (intersects(outputs[i]!.root, outputs[j]!.root)) throw new Error("case attempt outputs must be independent non-overlapping directories");
  }
  for (const configFile of configurationFiles) {
    if (intersects(configFile, control)) throw new Error("case control overlaps a source, configuration, or job output");
    if (outputs.some(output => intersects(configFile, output.root))) {
      throw new Error("case configurations must remain outside job outputs");
    }
  }
  for (const job of jobs) for (const attempt of job.attempts) {
    const inputs = [...new Set(sourceRoots(attempt))];
    for (const candidate of [attempt.configFile, ...inputs, ...outputs.map(output => output.root)]) {
      if (intersects(candidate, control)) throw new Error("case control overlaps a source, configuration, or job output");
    }
    if (inputs.some(input => intersects(input, attempt.workflow.output))) throw new Error("case workflow inputs and output must be distinct non-overlapping paths");
    const recovery = attempt.workflow.recovery;
    if (recovery !== undefined && [recovery.source, recovery.mountedReadOnlyRoot, recovery.unallocatedStreamFromCase]
      .some(input => input !== undefined && intersects(input, recovery.destination))) {
      throw new Error("case recovery inputs and destination must be distinct non-overlapping paths");
    }
    for (const input of inputs) for (const output of outputs) {
      if (output.job !== job.id && intersects(output.root, input) && !dependencies.get(job.id)!.has(output.job)) {
        throw new Error("case inputs produced by another job require a successful dependency");
      }
    }
  }
  const inputAgent = object(raw.agent, ["ownership", "executable", "socketPath", "threadId", "user", "readableRoots", "timeoutMs", "maxRequests"], "agent registration");
  if (inputAgent.ownership !== "dedicated-thread") throw new Error("case agent requires a dedicated supervisor-owned thread");
  if (typeof inputAgent.threadId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(inputAgent.threadId)
    || typeof inputAgent.user !== "string" || !/^[A-Za-z_][A-Za-z0-9_.-]*[$]?$/.test(inputAgent.user)) throw new Error("invalid case agent registration");
  if (!Array.isArray(inputAgent.readableRoots) || inputAgent.readableRoots.length < 1 || inputAgent.readableRoots.length > 16) throw new Error("case agent requires restricted code/report roots");
  const readableRoots = inputAgent.readableRoots.map(location);
  if (new Set(readableRoots).size !== readableRoots.length) throw new Error("case agent read roots must be unique");
  const protectedSpellings = new Set(protectedPaths);
  for (const candidate of resolved.values()) protectedSpellings.add(candidate);
  const protectedLocations = [...protectedSpellings];
  for (const root of readableRoots) {
    const spellings = new Set([root, await resolvedLocation(root)]);
    if ([...spellings].some(spelling => protectedLocations.some(protectedPath => overlaps(spelling, protectedPath) || overlaps(protectedPath, spelling)))) {
      throw new Error("case agent read roots overlap protected case data");
    }
  }
  const config: CaseConfig = {version: 1, execute: raw.execute, control, jobs,
    pollMs: integer(raw.pollMs, 30_000, 1000, 300_000), probeTimeoutMs: integer(raw.probeTimeoutMs, 10_000, 100, 60_000),
    maxConcurrent: integer(raw.maxConcurrent, 1, 1, 4),
    agent: {ownership: "dedicated-thread", stateDirectory: path.join(control, "agent-private"), executable: location(inputAgent.executable),
      socketPath: location(inputAgent.socketPath), threadId: inputAgent.threadId, user: inputAgent.user, readableRoots,
      timeoutMs: integer(inputAgent.timeoutMs, 300_000, 1000, 900_000), maxRequests: integer(inputAgent.maxRequests, 20, 1, 100)}};
  if (Buffer.byteLength(JSON.stringify(config)) > MAX_CASE_BYTES) throw new Error("prepared case exceeds its bounded control size");
  return config;
}

export function casePlan(config: CaseConfig): Record<string, unknown> {
  return {version: 1, tool: "aark", layer: "case-plan", sourcePathsRedacted: true,
    jobs: config.jobs.map(job => ({id: job.id, dependsOn: job.dependsOn, reviewedAttempts: job.attempts.length, resumeAfterQuota: job.resumeAfterQuota})),
    maxConcurrent: config.maxConcurrent, agentMode: config.agent.ownership, agentRequestLimit: config.agent.maxRequests,
    independentEngineServices: true, cleanupAuthorized: false};
}
