import { randomUUID } from "node:crypto";
import { lstat, mkdir } from "node:fs/promises";
import path from "node:path";
import { assertNoSymlinkComponents, atomicWriteJson, atomicWriteFile, readJson } from "../core/fs-safe.js";
import { caseConfigHash, digest, loadCaseConfig, MAX_CASE_BYTES } from "./config.js";
import { validateAgentEvent, validateAgentReply } from "./codex.js";
import { engineUnitName } from "./systemd.js";
import { storagePolicyFromGiB } from "../core/storage.js";
import { FAILURE_CODES } from "../workflow/failure.js";
import { overlaps } from "../workflow/config.js";
import { workflowPlan } from "../workflow/runner.js";
import { captureCaseSourceBindings, workflowExternalSources } from "./sources.js";
import type { CaseConfig, CaseState } from "./types.js";

const STATE = "case-state-sensitive.json";
interface Envelope { version: 1; sha256: string; config: CaseConfig; state: CaseState }
const validId = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(value);
const integer = (value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number => Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= maximum;
const permissions = new Set(["new-plan-required", "new-media-required", "destructive-operation", "credentials-required", "physical-intervention", "scope-change", "agent-approval-required"]);
const provenance = new Set(["deleted-metadata", "unallocated-carve", "unallocated-stream", "shadow-copy", "residual-memory", "allocated-reference", "unknown"]);
const hash = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const location = (value: unknown): value is string => typeof value === "string" && path.isAbsolute(value) && path.resolve(value) === value
  && Buffer.byteLength(value) <= 4096 && !/[\x00-\x1f\x7f]/u.test(value);
function fields(value: unknown, required: string[], optional: string[] = []): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    && required.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => required.includes(key) || optional.includes(key));
}
function requireValid(condition: unknown): asserts condition {
  if (!condition) throw new Error("case control integrity validation failed");
}
function validStorage(value: unknown): boolean {
  if (!fields(value, ["minFreeGiB", "minFreePercent"], ["maxOutputGiB"]) || typeof value.minFreeGiB !== "number"
    || typeof value.minFreePercent !== "number" || (value.maxOutputGiB !== undefined && typeof value.maxOutputGiB !== "number")) return false;
  try { storagePolicyFromGiB(value.minFreeGiB, value.minFreePercent, value.maxOutputGiB as number | undefined); return true; }
  catch { return false; }
}

/** Validate the frozen snapshot, never the current contents of editable plan files. */
function validateWorkflow(value: unknown): void {
  requireValid(fields(value, ["version", "execute", "output", "scans", "mining", "finalizationStorage"], ["recovery"])
    && value.version === 1 && value.execute === true && location(value.output) && validStorage(value.finalizationStorage)
    && Array.isArray(value.scans) && value.scans.length >= 1 && value.scans.length <= 128);
  for (const scan of value.scans) requireValid(fields(scan, ["inputs", "provenance"]) && provenance.has(String(scan.provenance))
    && Array.isArray(scan.inputs) && scan.inputs.length >= 1 && scan.inputs.length <= 128
    && scan.inputs.every(location) && new Set(scan.inputs).size === scan.inputs.length
    && scan.inputs.every(input => !overlaps(input, value.output as string) && !overlaps(value.output as string, input)));
  const mining = value.mining;
  requireValid(fields(mining, ["workers", "chunkMiB", "overlapMiB", "wholeFileMiB", "cryptoOnly", "deepKeySchedules", "storage"])
    && integer(mining.workers, 4) && mining.workers >= 1 && integer(mining.chunkMiB, 128) && mining.chunkMiB >= 17
    && integer(mining.overlapMiB, mining.chunkMiB) && mining.overlapMiB >= 17
    && integer(mining.wholeFileMiB, 256) && mining.wholeFileMiB >= 1 && typeof mining.cryptoOnly === "boolean"
    && typeof mining.deepKeySchedules === "boolean" && !(mining.cryptoOnly && mining.deepKeySchedules) && validStorage(mining.storage));
  if (value.recovery !== undefined) {
    const recovery = value.recovery;
    requireValid(fields(recovery, ["version", "caseId", "source", "destination", "requireReadOnlySource", "execute", "sectorOffset", "photoRecCommand", "image", "stages"],
      ["analysisSource", "unallocatedStreamFromCase", "mountedReadOnlyRoot", "storage"])
      && recovery.version === 1 && recovery.execute === true && recovery.requireReadOnlySource === true
      && typeof recovery.caseId === "string" && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(recovery.caseId)
      && location(recovery.source) && location(recovery.destination) && recovery.destination !== path.parse(recovery.destination).root
      && recovery.source !== recovery.destination && !overlaps(recovery.destination, recovery.source)
      && integer(recovery.sectorOffset) && typeof recovery.photoRecCommand === "string" && recovery.photoRecCommand.length <= 4096
      && (recovery.storage === undefined || validStorage(recovery.storage)));
    for (const key of ["analysisSource", "unallocatedStreamFromCase", "mountedReadOnlyRoot"] as const) requireValid(recovery[key] === undefined || location(recovery[key]));
    requireValid(fields(recovery.image, ["enabled", "path", "mapfile", "retryPasses"]) && typeof recovery.image.enabled === "boolean"
      && location(recovery.image.path) && location(recovery.image.mapfile) && integer(recovery.image.retryPasses, 20));
    requireValid(fields(recovery.stages, ["deletedMetadata", "ntfsUndelete", "unallocatedStream", "signatureCarving", "volumeShadows", "residualMemory", "deletedRegistryCells"])
      && Object.values(recovery.stages).every(stage => typeof stage === "boolean"));
    const tokens = recovery.photoRecCommand.split(",");
    requireValid(!recovery.stages.signatureCarving || (tokens[0] === "partition_none" && tokens.at(-1) === "search" && tokens.length <= 256
      && tokens.every(token => /^[A-Za-z0-9_.+-]{1,64}$/u.test(token))));
    requireValid(!recovery.stages.signatureCarving || recovery.stages.unallocatedStream || recovery.unallocatedStreamFromCase !== undefined);
    requireValid(recovery.unallocatedStreamFromCase === undefined || (!recovery.stages.unallocatedStream && recovery.stages.signatureCarving));
  }
}

export async function assertCaseDirectory(control: string): Promise<void> {
  if (!path.isAbsolute(control) || path.resolve(control) !== control) throw new Error("case control must be canonical and absolute");
  await assertNoSymlinkComponents(path.parse(control).root, control);
  const info = await lstat(control);
  if (!info.isDirectory() || (info.mode & 0o077) !== 0 || info.uid !== process.getuid?.()) throw new Error("case control requires a private directory owned by its worker");
}

function validate(config: CaseConfig, state: CaseState, control: string): void {
  try { validateControls(config, state, control); }
  catch { throw new Error("case control integrity validation failed"); }
}

function validateControls(config: CaseConfig, state: CaseState, control: string): void {
  requireValid(fields(config, ["version", "execute", "control", "jobs", "pollMs", "probeTimeoutMs", "maxConcurrent", "agent"])
    && fields(state, ["version", "caseId", "revision", "configHash", "sourceBindings", "desired", "health", "jobs", "outbox", "agentRequests", "startedAt", "updatedAt", "complete", "completionDeliveredToAgent"], ["permissionReason", "commandId"]));
  if (config.version !== 1 || config.execute !== true || config.control !== control || !location(control) || state.version !== 1
    || !validId(state.caseId) || state.configHash !== caseConfigHash(config) || !integer(state.revision)
    || !["running", "user-paused", "stopped"].includes(state.desired)
    || !["healthy", "degraded", "awaiting-agent", "awaiting-permission", "agent-unavailable", "observation-unavailable"].includes(state.health)
    || typeof state.complete !== "boolean" || typeof state.completionDeliveredToAgent !== "boolean"
    || typeof state.startedAt !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u.test(state.startedAt) || !Number.isFinite(Date.parse(state.startedAt))
    || typeof state.updatedAt !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u.test(state.updatedAt) || !Number.isFinite(Date.parse(state.updatedAt))
    || (state.permissionReason !== undefined && !permissions.has(state.permissionReason)) || (state.commandId !== undefined && !validId(state.commandId))
    || !Array.isArray(config.jobs) || config.jobs.length < 1 || config.jobs.length > 64
    || !Array.isArray(state.jobs) || state.jobs.length !== config.jobs.length
    || !integer(config.maxConcurrent, 4) || config.maxConcurrent < 1 || !integer(config.pollMs, 300000) || config.pollMs < 1000
    || !integer(config.probeTimeoutMs, 60000) || config.probeTimeoutMs < 100
    || !fields(config.agent, ["ownership", "stateDirectory", "executable", "socketPath", "threadId", "user", "readableRoots", "timeoutMs", "maxRequests"])
    || config.agent.ownership !== "dedicated-thread" || config.agent.stateDirectory !== path.join(control, "agent-private")
    || !location(config.agent.executable) || !location(config.agent.socketPath)
    || typeof config.agent.threadId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(config.agent.threadId)
    || typeof config.agent.user !== "string" || !/^[A-Za-z_][A-Za-z0-9_.-]*[$]?$/u.test(config.agent.user)
    || !Array.isArray(config.agent.readableRoots) || config.agent.readableRoots.length < 1 || config.agent.readableRoots.length > 16
    || !config.agent.readableRoots.every(location) || new Set(config.agent.readableRoots).size !== config.agent.readableRoots.length
    || !integer(config.agent.timeoutMs, 900000) || config.agent.timeoutMs < 1000
    || !integer(config.agent.maxRequests, 100) || config.agent.maxRequests < 1
    || !integer(state.agentRequests, config.agent.maxRequests) || !Array.isArray(state.outbox) || state.outbox.length > 2048) throw new Error("case control integrity validation failed");
  const ids = new Set<string>();
  const tokens = new Set<string>();
  const protectedPaths = [control];
  for (let i = 0; i < config.jobs.length; i++) {
    const job = config.jobs[i]!;
    const saved = state.jobs[i]!;
    if (!fields(job, ["id", "dependsOn", "attempts", "resumeAfterQuota"]) || !fields(saved, ["id", "attempts"])
      || typeof job.id !== "string" || !/^job-[0-9]{6}$/u.test(job.id) || ids.has(job.id) || saved.id !== job.id
      || typeof job.resumeAfterQuota !== "boolean" || !Array.isArray(job.dependsOn) || job.dependsOn.length > 63 || new Set(job.dependsOn).size !== job.dependsOn.length
      || !Array.isArray(job.attempts) || job.attempts.length < 1 || job.attempts.length > 4
      || !Array.isArray(saved.attempts) || saved.attempts.length > 128) throw new Error("invalid case job controls");
    ids.add(job.id);
    for (const attempt of job.attempts) {
      requireValid(fields(attempt, ["configFile", "configHash", "workflow"]) && location(attempt.configFile) && hash(attempt.configHash));
      validateWorkflow(attempt.workflow);
      requireValid(attempt.configHash === digest(attempt.workflow));
      workflowPlan(attempt.workflow);
      protectedPaths.push(attempt.configFile, attempt.workflow.output, ...attempt.workflow.scans.flatMap(scan => scan.inputs));
      const recovery = attempt.workflow.recovery;
      if (recovery !== undefined) protectedPaths.push(recovery.source, recovery.destination,
        ...[recovery.analysisSource, recovery.mountedReadOnlyRoot, recovery.unallocatedStreamFromCase].filter((root): root is string => root !== undefined));
    }
    let lastIndex = -1;
    for (const attempt of saved.attempts) {
      if (!fields(attempt, ["index", "token", "status", "mode"], ["dispatched", "launchRefused", "identity", "observation", "proof", "resumeReady"])
        || !integer(attempt.index, job.attempts.length - 1) || !validId(attempt.token) || tokens.has(attempt.token)
        || !["launching", "running", "paused", "failed", "complete"].includes(attempt.status)
        || !["run", "resume"].includes(attempt.mode)
        || (attempt.mode === "run" ? attempt.index !== lastIndex + 1 : attempt.index !== lastIndex)
        || (attempt.dispatched !== undefined && typeof attempt.dispatched !== "boolean")) throw new Error("invalid case attempt controls");
      lastIndex = attempt.index;
      tokens.add(attempt.token);
      if (attempt.launchRefused !== undefined) requireValid(attempt.launchRefused === true && attempt.status === "failed"
        && attempt.dispatched === true && attempt.identity === undefined && attempt.observation?.status === "failed");
      if (attempt.status !== "launching" && attempt.launchRefused !== true) requireValid(attempt.identity !== undefined);
      if (attempt.identity !== undefined) requireValid(fields(attempt.identity, ["unit", "invocationId"])
        && attempt.identity.unit === engineUnitName(attempt.token) && typeof attempt.identity.invocationId === "string" && /^[a-f0-9]{32}$/u.test(attempt.identity.invocationId));
      if (attempt.observation !== undefined) {
        const observation = attempt.observation;
        requireValid(fields(observation, ["status"], ["failureCode", "pauseReason", "bytesScanned", "filesScanned", "scanErrors"])
          && ["absent", "running", "paused", "failed", "complete", "unknown"].includes(observation.status)
          && (observation.failureCode === undefined || FAILURE_CODES.has(observation.failureCode))
          && (observation.pauseReason === undefined || (observation.status === "paused" && ["signal", "free-space-reserve", "output-cap"].includes(observation.pauseReason))));
        for (const key of ["bytesScanned", "filesScanned", "scanErrors"] as const) requireValid(observation[key] === undefined || integer(observation[key]));
      }
      if (attempt.resumeReady !== undefined) requireValid(typeof attempt.resumeReady === "boolean" && attempt.status === "paused"
        && attempt.observation?.pauseReason === "free-space-reserve" && job.resumeAfterQuota);
      if (attempt.proof !== undefined) requireValid(attempt.status === "complete" && fields(attempt.proof, ["sha256", "scansVerified", "filesVerified"])
        && hash(attempt.proof.sha256) && attempt.proof.scansVerified === job.attempts[attempt.index]!.workflow.scans.length
        && integer(attempt.proof.filesVerified));
      if (attempt.status === "complete") requireValid(attempt.proof !== undefined);
    }
  }
  const prepared = new Map(config.jobs.flatMap(job => job.attempts.map(attempt => [attempt.configHash, attempt] as const)));
  requireValid(fields(state.sourceBindings, [...prepared.keys()]));
  for (const [configHash, attempt] of prepared) {
    const bindings = state.sourceBindings[configHash];
    const allowed = new Set(workflowExternalSources(attempt.workflow));
    requireValid(Array.isArray(bindings) && bindings.length <= 2);
    const sources = new Set<string>();
    for (const binding of bindings) {
      requireValid(fields(binding, ["source", "sha256"]) && location(binding.source) && allowed.has(binding.source)
        && !sources.has(binding.source) && hash(binding.sha256));
      sources.add(binding.source);
    }
  }
  requireValid(!config.agent.readableRoots.some(root => protectedPaths.some(protectedPath => overlaps(root, protectedPath) || overlaps(protectedPath, root))));
  const byId = new Map(config.jobs.map(job => [job.id, job]));
  const visited = new Set<string>(), visiting = new Set<string>();
  const visit = (id: string): void => {
    requireValid(!visiting.has(id));
    if (visited.has(id)) return;
    visiting.add(id);
    const job = byId.get(id);
    requireValid(job !== undefined);
    for (const dependency of job.dependsOn) { requireValid(typeof dependency === "string" && ids.has(dependency)); visit(dependency); }
    visiting.delete(id); visited.add(id);
  };
  for (const id of ids) visit(id);
  const events = new Set<string>();
  let deliveries = 0;
  for (const entry of state.outbox) {
    requireValid(fields(entry, ["event", "status", "deliveries", "nextDeliveryAt"], ["reply"]));
    const event = validateAgentEvent(entry.event);
    if (!validId(event.eventId) || events.has(event.eventId) || event.caseId !== state.caseId
      || !integer(entry.event.revision, state.revision) || !integer(entry.deliveries, config.agent.maxRequests)
      || !integer(entry.nextDeliveryAt) || !["pending", "delivering", "processed"].includes(entry.status)) throw new Error("invalid case outbox controls");
    events.add(entry.event.eventId);
    requireValid(event.jobs.length === config.jobs.length && event.jobs.every((job, index) => job.id === config.jobs[index]!.id
      && job.attemptsAllowed === config.jobs[index]!.attempts.length && job.resumeAfterQuota === config.jobs[index]!.resumeAfterQuota
      && job.attemptsUsed <= state.jobs[index]!.attempts.filter(attempt => attempt.mode === "run").length));
    if (entry.status === "delivering") requireValid(entry.deliveries >= 1);
    if (entry.reply !== undefined) { requireValid(entry.status === "processed" && entry.deliveries >= 1); validateAgentReply(entry.reply, event); }
    deliveries += entry.deliveries;
  }
  requireValid(deliveries === state.agentRequests);
  if (state.complete && state.jobs.some(job => job.attempts.at(-1)?.status !== "complete")) throw new Error("case completion is missing verified jobs");
  if (state.completionDeliveredToAgent) requireValid(state.complete && state.outbox.some(entry => entry.status === "processed"
    && entry.event.reason === "case-completed" && entry.reply?.action.type === "acknowledge"));
}

export async function initializeCase(configFile: string, options: {execute: boolean}): Promise<CaseState> {
  if (options.execute !== true) throw new Error("case initialization requires --execute confirmation");
  const config = await loadCaseConfig(configFile);
  if (!config.execute) throw new Error("case configuration requires execute confirmation");
  const sourceBindings = await captureCaseSourceBindings(config);
  const now = new Date().toISOString();
  const state: CaseState = {version: 1, caseId: randomUUID(), revision: 0, configHash: caseConfigHash(config), sourceBindings, desired: "running",
    health: "healthy", jobs: config.jobs.map(job => ({id: job.id, attempts: []})), outbox: [], agentRequests: 0,
    startedAt: now, updatedAt: now, complete: false, completionDeliveredToAgent: false};
  // The prepared configuration can fit by itself while its complete envelope
  // does not. Refuse before creating a directory that cannot be initialized.
  serializeCaseState(config.control, config, state);
  await assertNoSymlinkComponents(path.parse(config.control).root, config.control);
  await mkdir(config.control, {mode: 0o700}); // Never adopt or overwrite an existing control directory.
  await saveCaseState(config.control, config, state);
  return state;
}

export async function loadCaseState(control: string): Promise<{config: CaseConfig; state: CaseState}> {
  await assertCaseDirectory(control);
  const envelope = await readJson<Envelope>(path.join(control, STATE), MAX_CASE_BYTES);
  requireValid(fields(envelope, ["version", "sha256", "config", "state"]) && envelope.version === 1 && hash(envelope.sha256)
    && envelope.sha256 === digest({config: envelope.config, state: envelope.state}));
  validate(envelope.config, envelope.state, control);
  return {config: envelope.config, state: envelope.state};
}

export function redactedCaseStatus(config: CaseConfig, state: CaseState): Record<string, unknown> {
  validate(config, state, config?.control ?? "");
  return {version: 1, tool: "aark", layer: "case", caseId: state.caseId, revision: state.revision,
    desired: state.desired, health: state.health, complete: state.complete, completionDeliveredToAgent: state.completionDeliveredToAgent,
    permissionReason: state.permissionReason ?? null, updatedAt: state.updatedAt, sourcePathsRedacted: true,
    agentRequests: state.agentRequests, agentRequestLimit: config.agent.maxRequests,
    pendingEvents: state.outbox.filter(entry => entry.status !== "processed").length,
    jobs: state.jobs.map((job, index) => ({id: job.id, status: job.attempts.at(-1)?.status ?? "pending",
      attemptsUsed: job.attempts.filter(attempt => attempt.mode === "run").length,
      attemptsAllowed: config.jobs[index]!.attempts.length, verified: job.attempts.at(-1)?.proof !== undefined,
      failureCode: job.attempts.at(-1)?.observation?.failureCode ?? null,
      pauseReason: job.attempts.at(-1)?.observation?.pauseReason ?? null,
      currentScan: {bytesScanned: job.attempts.at(-1)?.observation?.bytesScanned ?? null,
        filesScanned: job.attempts.at(-1)?.observation?.filesScanned ?? null, errors: job.attempts.at(-1)?.observation?.scanErrors ?? null}})), cleanupAuthorized: false};
}

function serializeCaseState(control: string, config: CaseConfig, state: CaseState): string {
  validate(config, state, control);
  const payload = {config, state};
  const envelope: Envelope = {version: 1, sha256: digest(payload), ...payload};
  const serialized = JSON.stringify(envelope) + "\n";
  if (Buffer.byteLength(serialized) > MAX_CASE_BYTES) throw new Error("case controls exceed bounded capacity");
  return serialized;
}

export async function saveCaseState(control: string, config: CaseConfig, state: CaseState): Promise<void> {
  await assertCaseDirectory(control);
  const serialized = serializeCaseState(control, config, state);
  await atomicWriteFile(path.join(control, STATE), serialized);
  await atomicWriteJson(path.join(control, "case-progress-redacted.json"), redactedCaseStatus(config, state));
}

export async function writeCaseCompletion(config: CaseConfig, state: CaseState): Promise<void> {
  await assertCaseDirectory(config.control);
  validate(config, state, config?.control ?? "");
  if (state.jobs.some(job => job.attempts.at(-1)?.status !== "complete")) throw new Error("case has unverified jobs");
  const aggregate = {...redactedCaseStatus(config, state), complete: true, layer: "case-completion", completionScope: "registered-jobs-only",
    proofs: state.jobs.map(job => ({id: job.id, ...job.attempts.at(-1)!.proof})), cleanupAuthorized: false};
  await atomicWriteJson(path.join(config.control, "manifest-redacted.json"), aggregate);
  await atomicWriteFile(path.join(config.control, "final-report-redacted.md"), "# AARK case report\n\nAll registered jobs passed native completion verification.\n\n"
    + `Verified jobs: ${state.jobs.length}\n\nScope: registered jobs only. Additional recovery, backup, repair, and cleanup obligations require their own reviewed plans.\n\nCleanup authorized: no. Human acknowledgement: not recorded.\n`);
}

export async function requestCaseDesired(control: string, desired: "running" | "user-paused"): Promise<void> {
  await loadCaseState(control);
  await atomicWriteJson(path.join(control, "case-command.json"), {version: 1, id: randomUUID(), desired});
}
