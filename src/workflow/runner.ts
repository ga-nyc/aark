import { createHash } from "node:crypto";
import { mkdir, realpath } from "node:fs/promises";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { acquireExclusiveLock, assertNoSymlinkComponents, atomicWriteInformationalFile, atomicWriteJson, ensurePrivateDirectory, nearestExistingParent, readDirectoryNamesBounded, readJson } from "../core/fs-safe.js";
import type { ExclusiveLock } from "../core/fs-safe.js";
import { assertStorageCapacity, StorageQuotaError, storagePolicyFromGiB } from "../core/storage.js";
import { assertLoopBackingsOutside, mountForPath, mountIsNetworkBacked, protectedMountBacking } from "../core/mounts.js";
import { redactedProgress } from "../core/progress.js";
import { resumeSensitiveMaterial, scanSensitiveMaterial } from "../mining/scanner.js";
import { loadScanState } from "../mining/resume.js";
import { buildRecoveryPlan } from "../recovery/plan.js";
import { redactedPlan, runRecoveryPlan } from "../recovery/runner.js";
import type { MiningProgress } from "../mining/types.js";
import { inspectSourceSafety } from "../recovery/source-safety.js";
import { loadWorkflowConfig, MAX_WORKFLOW_CONFIG_BYTES, overlaps } from "./config.js";
import type { WorkflowConfig } from "./config.js";
import { finalizeWorkflow } from "./finalize.js";
import { controlIdentity, fileDigest, interrupted, miningDirectory, outputIdentity, samePath, verifyScan, workflowSourceIdentity } from "./verify.js";

type Phase = "recovery" | "mining" | "verification" | "packaging" | "complete";
type Status = "running" | "paused" | "complete" | "failed";
interface WorkflowState {
  version: 1;
  tool: "aark";
  layer: "workflow";
  status: Status;
  phase: Phase;
  configFile: string;
  config: WorkflowConfig;
  outputIdentity: string;
  resultsSafety: string[];
  startedAt: string;
  updatedAt: string;
  completedScans: Array<{bytes: number; sha256: string}>;
  recoveryProof?: {bytes: number; sha256: string};
  recoverySafety?: string;
  pausedScan?: number;
  finalizationAttempt: number;
  scansVerified: number;
  filesVerified?: number;
  currentScanFilesScanned?: number;
  currentScanBytesScanned?: number;
  recoveryProgress?: Record<string, unknown>;
  summary?: Record<string, unknown>;
  failureClass?: string;
  pauseReason?: "signal" | "free-space-reserve" | "output-cap";
}
export interface WorkflowOptions {
  execute: boolean;
  signal?: AbortSignal;
  progress?: (value: Record<string, unknown>) => void;
}
const STATE = "workflow-state-sensitive.json";
const CHECKPOINT = "workflow-checkpoint-redacted.json";
const PROGRESS = "progress-redacted.json";
const hash = (data: string) => createHash("sha256").update(data).digest("hex");
const storagePolicy = (config: WorkflowConfig) => storagePolicyFromGiB(config.finalizationStorage.minFreeGiB,
  config.finalizationStorage.minFreePercent, config.finalizationStorage.maxOutputGiB);

function observe(options: WorkflowOptions, snapshot: Record<string, unknown>): void {
  try { options.progress?.(snapshot); } catch { /* Observers cannot change durable workflow results. */ }
}

export function workflowPlan(config: WorkflowConfig): Record<string, unknown> {
  if (config.recovery !== undefined) {
    if (!config.recovery.requireReadOnlySource) throw new Error("workflow recovery requires read-only source protection");
    const steps = buildRecoveryPlan(config.recovery).steps;
    for (const scan of config.scans) {
      for (const input of scan.inputs) {
        if (!steps.some(step => step.provenance === scan.provenance && step.outputs.some(output => overlaps(output, input)))) {
          throw new Error("workflow scans must select declared recovery outputs with their matching provenance");
        }
      }
    }
  }
  return {version: 1, tool: "aark", layer: "workflow-plan", sourcePathsRedacted: true,
    recoveryConfigured: config.recovery !== undefined, scansPlanned: config.scans.length,
    ...(config.recovery === undefined ? {} : {recoveryPlan: redactedPlan(buildRecoveryPlan(config.recovery))}),
    scans: config.scans.map((scan, index) => ({number: index + 1, provenance: scan.provenance, inputRoots: scan.inputs.length})),
    phases: [...(config.recovery === undefined ? [] : ["recovery"]), "mining", "verification", "packaging", "complete"],
    automaticFinalization: true, originalSourcesAndMiningOutputsRetained: true, cleanupAuthorized: false,
    miningStoragePerScan: config.mining.storage, finalizationStorage: config.finalizationStorage};
}

function redacted(state: WorkflowState): Record<string, unknown> {
  return {version: 1, tool: "aark", layer: "workflow", sourcePathsRedacted: true,
    status: state.status, phase: state.phase, startedAt: state.startedAt, updatedAt: state.updatedAt,
    scansPlanned: state.config.scans.length, scansCompleted: state.completedScans.length,
    scansVerified: state.scansVerified, resumable: state.status === "paused",
    ...(state.filesVerified === undefined ? {} : {filesVerified: state.filesVerified}),
    ...(state.currentScanFilesScanned === undefined ? {} : {currentScanFilesScanned: state.currentScanFilesScanned, currentScanBytesScanned: state.currentScanBytesScanned}),
    ...(state.recoveryProgress === undefined ? {} : {recoveryProgress: state.recoveryProgress}),
    processId: state.status === "running" ? process.pid : null,
    cleanupAuthorized: false, ...(state.failureClass === undefined ? {} : {failureClass: state.failureClass}),
    ...(state.pauseReason === undefined ? {} : {pauseReason: state.pauseReason}),
    ...(state.summary === undefined ? {} : {summary: state.summary})};
}

async function release(locks: ExclusiveLock[]): Promise<void> {
  const errors: unknown[] = [];
  for (const lock of [...locks].reverse()) { try { await lock.release(); } catch (error) { errors.push(error); } }
  if (errors.length > 0) throw new AggregateError(errors, "workflow operation locks could not all be released");
}

async function lockPair(directory: string, layer: "recovery" | "mining", locks: ExclusiveLock[]): Promise<void> {
  await outputIdentity(directory, {minFreeGiB: 0, minFreePercent: 0}, false);
  for (const name of [`.aark-${layer}.lock`, `.agetnic-${layer}.lock`].sort()) {
    locks.push(await acquireExclusiveLock(directory, name));
  }
}

async function publish(state: WorkflowState, options: WorkflowOptions): Promise<void> {
  state.updatedAt = new Date().toISOString();
  const data = JSON.stringify(state, null, 2) + "\n";
  if (Buffer.byteLength(data) > 16 * MAX_WORKFLOW_CONFIG_BYTES) throw new Error("workflow state exceeds its bounded limit");
  await atomicWriteJson(path.join(state.config.output, STATE), state);
  await atomicWriteJson(path.join(state.config.output, CHECKPOINT), {version: 1, tool: "aark", stateSha256: hash(data), status: state.status});
  const report = redacted(state);
  if (state.status === "running") await atomicWriteInformationalFile(path.join(state.config.output, PROGRESS), JSON.stringify(report, null, 2) + "\n", 0o600);
  else await atomicWriteJson(path.join(state.config.output, PROGRESS), report);
  observe(options, report);
}

async function loadState(output: string): Promise<WorkflowState> {
  const state = await readJson<WorkflowState>(path.join(output, STATE), 16 * MAX_WORKFLOW_CONFIG_BYTES);
  const checkpoint = await readJson<{version?: unknown; stateSha256?: unknown}>(path.join(output, CHECKPOINT), 4096);
  const integrity = await fileDigest(path.join(output, STATE), 16 * MAX_WORKFLOW_CONFIG_BYTES);
  if (checkpoint.version !== 1 || checkpoint.stateSha256 !== integrity.sha256 || state.version !== 1
    || state.tool !== "aark" || state.layer !== "workflow" || state.config?.output !== output
    || !["running", "paused", "complete", "failed"].includes(state.status)
    || !["recovery", "mining", "verification", "packaging", "complete"].includes(state.phase)
    || !Array.isArray(state.completedScans) || !Number.isSafeInteger(state.finalizationAttempt) || state.finalizationAttempt < 0) {
    throw new Error("invalid or changed workflow checkpoint");
  }
  const config = await loadWorkflowConfig(state.configFile);
  if (!isDeepStrictEqual(config, state.config) || state.completedScans.length > config.scans.length) throw new Error("workflow reviewed configuration changed");
  workflowPlan(config);
  return state;
}

async function resultsSafety(config: WorkflowConfig): Promise<string[]> {
  if (config.recovery === undefined) return [];
  const recovery = config.recovery;
  const sources = [recovery.source];
  if (recovery.analysisSource !== undefined && recovery.analysisSource !== recovery.source
    && !(recovery.image.enabled && samePath(recovery.analysisSource, recovery.image.path))) sources.push(recovery.analysisSource);
  const identities: string[] = [];
  for (const source of sources) {
    const safety = await inspectSourceSafety(source, config.output);
    if (!safety.safe) throw new Error("workflow results need a safe local destination independent of the protected raw source");
    identities.push(workflowSourceIdentity(safety));
  }
  return identities;
}

async function execute(state: WorkflowState, options: WorkflowOptions, workflowLock: ExclusiveLock): Promise<Record<string, unknown>> {
  const {config} = state;
  const held: ExclusiveLock[] = [workflowLock];
  const seals = new Map<string, string>();
  const controller = new AbortController();
  const abort = () => controller.abort();
  options.signal?.addEventListener("abort", abort, {once: true});
  if (options.signal?.aborted) abort();
  let guardFailure: unknown;
  let checking: Promise<void> | undefined;
  let lastFullCheck = 0;
  let timer: ReturnType<typeof setInterval> | undefined;
  let heartbeat: Promise<void> | undefined;
  let nextPublish = 0;
  let publications = Promise.resolve();
  const serialize = (write: () => Promise<void>): Promise<void> => {
    const pending = publications.then(write);
    publications = pending.catch(() => undefined);
    return pending;
  };
  const save = () => serialize(async () => {
    await workflowLock.assertHeld();
    if (await outputIdentity(config.output, config.finalizationStorage, false) !== state.outputIdentity) throw new Error("workflow output changed before checkpoint publication");
    await publish(state, options);
  });
  const guarded = async (force = false): Promise<void> => {
    if (guardFailure !== undefined) throw guardFailure;
    if (checking !== undefined) {
      await checking;
      if (!force) return;
    }
    checking = (async () => {
      for (const lock of held) await lock.assertHeld();
      if (!force && Date.now() - lastFullCheck < 5000) return;
      if (await outputIdentity(config.output, config.finalizationStorage) !== state.outputIdentity) throw new Error("workflow output identity or mount changed");
      if (!isDeepStrictEqual(await resultsSafety(config), state.resultsSafety)) throw new Error("workflow results destination or source safety changed");
      for (const [filename, expected] of seals) if (await controlIdentity(filename) !== expected) throw new Error("verified workflow mining controls changed");
      if (config.recovery !== undefined && state.recoveryProof !== undefined) {
        await outputIdentity(config.recovery.destination, {minFreeGiB: 0, minFreePercent: 0}, false);
        const proof = await fileDigest(path.join(config.recovery.destination, "case-sensitive.json"), 16 * 1024 ** 2);
        if (!isDeepStrictEqual(proof, state.recoveryProof)) throw new Error("completed recovery controls changed");
        const safety = await inspectSourceSafety(config.recovery.source, config.recovery.destination);
        if (workflowSourceIdentity(safety) !== state.recoverySafety || !safety.safe) throw new Error("workflow recovery source safety changed");
      }
      lastFullCheck = Date.now();
    })();
    try { await checking; } catch (error) { guardFailure = error; controller.abort(); throw error; }
    finally { checking = undefined; }
  };
  const update = async () => { await guarded(); await save(); };
  let lastMiningEvent = 0;
  const miningProgress = (progress: MiningProgress) => {
    state.currentScanFilesScanned = progress.filesScanned;
    state.currentScanBytesScanned = progress.bytesScanned;
    if (Date.now() - lastMiningEvent >= 1000) {
      lastMiningEvent = Date.now(); observe(options, redacted(state));
    }
  };
  try {
    state.status = "running"; delete state.failureClass; delete state.pauseReason;
    await update();
    timer = setInterval(() => {
      if (heartbeat !== undefined) return;
      heartbeat = (async () => {
        await guarded();
        if (Date.now() < nextPublish) return;
        nextPublish = Date.now() + 5000;
        await serialize(async () => {
          if (state.status === "running") await atomicWriteInformationalFile(path.join(config.output, PROGRESS),
            JSON.stringify({...redacted(state), updatedAt: new Date().toISOString()}, null, 2) + "\n", 0o600);
        });
      })().catch(error => { guardFailure = error; controller.abort(); }).finally(() => { heartbeat = undefined; });
    }, 5000);
    if (config.recovery !== undefined) {
      if (state.recoveryProof === undefined) {
        state.phase = "recovery"; await update();
        const result = await runRecoveryPlan(config.recovery, buildRecoveryPlan(config.recovery), true, controller.signal, snapshot => {
          state.recoveryProgress = redactedProgress(snapshot, "recovery");
        });
        if (result.status === "paused") {
          const stop = result.storageStop;
          if (typeof stop === "object" && stop !== null && !Array.isArray(stop)
            && (stop.reason === "free-space-reserve" || stop.reason === "output-cap")) state.pauseReason = stop.reason;
          state.status = "paused"; await save(); return redacted(state);
        }
        if (result.status !== "complete" && result.status !== "complete-with-warnings") throw new Error("workflow recovery did not complete successfully");
      }
      await lockPair(config.recovery.destination, "recovery", held);
      const recoveryState = await readJson<{status: string; results: Array<{id: string; status: string}>}>(path.join(config.recovery.destination, "case-sensitive.json"));
      if (!["complete", "complete-with-warnings"].includes(recoveryState.status)) throw new Error("workflow recovery is no longer successful");
      const steps = buildRecoveryPlan(config.recovery).steps;
      for (const scan of config.scans) for (const input of scan.inputs) {
        const step = steps.find(item => item.provenance === scan.provenance && item.outputs.some(output => overlaps(output, input)));
        if (step === undefined || !recoveryState.results.some(result => result.id === step.id && result.status === "completed")) {
          throw new Error("a selected recovery output has no completed producing stage");
        }
      }
      const proof = await fileDigest(path.join(config.recovery.destination, "case-sensitive.json"), 16 * 1024 ** 2);
      if (state.recoveryProof !== undefined && !isDeepStrictEqual(proof, state.recoveryProof)) throw new Error("workflow recovery proof changed");
      const safety = await inspectSourceSafety(config.recovery.source, config.recovery.destination);
      if (state.recoverySafety !== undefined && state.recoverySafety !== workflowSourceIdentity(safety)) throw new Error("workflow recovery source identity changed");
      if (!safety.safe) throw new Error("workflow recovery source safety is not established");
      state.recoveryProof = proof;
      state.recoverySafety = workflowSourceIdentity(safety);
      await update();
    }
    for (let index = 0; index < config.scans.length; index++) {
      interrupted(controller.signal);
      const scan = config.scans[index];
      if (scan === undefined) throw new Error("missing reviewed workflow scan");
      const output = miningDirectory(config, index);
      if (index < state.completedScans.length) {
        await lockPair(output, "mining", held);
        const current = await verifyScan(config, scan, index, controller.signal, count => { state.filesVerified = count; });
        if (!isDeepStrictEqual(current.proof, state.completedScans[index])) throw new Error("workflow completed scan changed after checkpointing");
        for (const seal of current.seals) seals.set(seal.filename, seal.identity);
        continue;
      }
      delete state.currentScanFilesScanned; delete state.currentScanBytesScanned;
      state.phase = "mining"; await update();
      const result = state.pausedScan === index
        ? await resumeSensitiveMaterial({output, signal: controller.signal, progress: miningProgress})
        : await scanSensitiveMaterial({inputs: scan.inputs, output, provenance: scan.provenance,
          chunkBytes: config.mining.chunkMiB * 1024 ** 2, overlapBytes: config.mining.overlapMiB * 1024 ** 2,
          wholeFileBytes: config.mining.wholeFileMiB * 1024 ** 2, cryptoOnly: config.mining.cryptoOnly,
          deepKeySchedules: config.mining.deepKeySchedules, workers: config.mining.workers,
          minimumFreeGiB: config.mining.storage.minFreeGiB, minimumFreePercent: config.mining.storage.minFreePercent,
          ...(config.mining.storage.maxOutputGiB === undefined ? {} : {maximumOutputGiB: config.mining.storage.maxOutputGiB}), signal: controller.signal, progress: miningProgress});
      if (result.status === "paused") {
        if (guardFailure !== undefined && !(guardFailure instanceof StorageQuotaError)) throw guardFailure;
        const paused = await loadScanState(output);
        if (!paused.resumable || paused.status !== "paused") throw new Error("workflow scan did not publish a clean pause");
        state.pausedScan = index; state.status = "paused";
        if (guardFailure instanceof StorageQuotaError) state.pauseReason = guardFailure.reason;
        else if (paused.pauseReason !== undefined) state.pauseReason = paused.pauseReason;
        await save(); return redacted(state);
      }
      if (guardFailure !== undefined) throw guardFailure;
      if (result.status !== "complete" || result.scanErrors !== 0) throw new Error("workflow scan did not complete without errors");
      delete state.pausedScan;
      await lockPair(output, "mining", held);
      state.completedScans.push(await fileDigest(path.join(output, "scan-state-sensitive.json"), 16 * 1024 ** 2));
      state.phase = "verification"; await update();
      const verified = await verifyScan(config, scan, index, controller.signal, count => { state.filesVerified = count; });
      for (const seal of verified.seals) seals.set(seal.filename, seal.identity);
      await update();
    }
    interrupted(controller.signal);
    state.phase = "packaging"; state.finalizationAttempt++; state.scansVerified = 0; state.filesVerified = 0; await update();
    state.summary = await finalizeWorkflow(config, state.finalizationAttempt, () => guarded(), async count => {
      state.scansVerified = count; await update();
    }, controller.signal, count => { state.filesVerified = count; });
    await guarded(true);
    state.status = "complete"; state.phase = "complete";
    await atomicWriteJson(path.join(config.output, "manifest-redacted.json"), state.summary);
    await save();
    return redacted(state);
  } catch (error) {
    state.status = (guardFailure === undefined || guardFailure instanceof StorageQuotaError)
      && (controller.signal.aborted || error instanceof StorageQuotaError) ? "paused" : "failed";
    // A partial native recovery cannot be resumed unless its own quota checkpoint said so.
    if ((state.phase === "recovery" && state.recoveryProof === undefined) || state.phase === "mining") state.status = "failed";
    state.failureClass = error instanceof Error ? error.name : "Error";
    if (state.status === "paused") state.pauseReason = error instanceof StorageQuotaError ? error.reason : "signal";
    delete state.summary;
    await save();
    if (state.status === "paused") return redacted(state);
    throw new Error("workflow failed; retained local controls identify the stopped phase", {cause: error});
  } finally {
    if (timer !== undefined) clearInterval(timer);
    await heartbeat;
    await checking?.catch(() => undefined);
    await publications;
    options.signal?.removeEventListener("abort", abort);
    await release(held);
  }
}

export async function runWorkflow(filename: string, options: WorkflowOptions): Promise<Record<string, unknown>> {
  const configFile = path.resolve(filename);
  const config = await loadWorkflowConfig(configFile);
  workflowPlan(config);
  if (!config.execute || !options.execute || (config.recovery !== undefined && !config.recovery.execute)) {
    throw new Error("workflow execution requires reviewed execute=true configuration and --execute");
  }
  interrupted(options.signal);
  const parent = await nearestExistingParent(config.output);
  const mounted = await mountForPath(parent);
  if (mounted === undefined) throw new Error("workflow output has no mount");
  const backing = await protectedMountBacking(mounted);
  await assertLoopBackingsOutside(backing.loopBackings, [...config.scans.flatMap(scan => scan.inputs),
    ...(config.recovery === undefined ? [] : [config.recovery.destination])], "workflow input or recovery case");
  const expectedResultsSafety = await resultsSafety(config);
  await assertStorageCapacity(parent, storagePolicy(config));
  await assertNoSymlinkComponents(path.parse(config.output).root, config.output);
  await mkdir(config.output, {mode: 0o700});
  await ensurePrivateDirectory(config.output);
  if ((await readDirectoryNamesBounded(config.output, 1)).length !== 0) throw new Error("workflow requires a new empty output");
  const identity = await outputIdentity(config.output, config.finalizationStorage);
  const lock = await acquireExclusiveLock(config.output, ".aark-workflow.lock");
  const now = new Date().toISOString();
  return await execute({version: 1, tool: "aark", layer: "workflow", status: "running",
    phase: config.recovery === undefined ? "mining" : "recovery", configFile, config, outputIdentity: identity, resultsSafety: expectedResultsSafety,
    startedAt: now, updatedAt: now, completedScans: [], finalizationAttempt: 0, scansVerified: 0}, options, lock);
}

export async function resumeWorkflow(directory: string, options: WorkflowOptions): Promise<Record<string, unknown>> {
  const output = path.resolve(directory);
  if (!options.execute) throw new Error("workflow resume requires --execute");
  await assertNoSymlinkComponents(path.parse(output).root, output);
  const mounted = await mountForPath(output);
  if (mounted === undefined || await mountIsNetworkBacked(mounted)) throw new Error("workflow resume requires a local output mount");
  const state = await loadState(output);
  if (state.status !== "paused") throw new Error("only an explicitly paused workflow may resume; abrupt stops require local review");
  if (await outputIdentity(output, state.config.finalizationStorage) !== state.outputIdentity) throw new Error("workflow output identity changed since its pause");
  const lock = await acquireExclusiveLock(output, ".aark-workflow.lock");
  return await execute(state, options, lock);
}

export async function workflowStatus(directory: string): Promise<Record<string, unknown>> {
  const root = path.resolve(directory);
  await assertNoSymlinkComponents(path.parse(root).root, root);
  if (!samePath(await realpath(root), root)) throw new Error("workflow status root changed its canonical path");
  const mounted = await mountForPath(root);
  if (mounted === undefined || await mountIsNetworkBacked(mounted)) throw new Error("workflow status requires a local output mount");
  const input = await readJson<Record<string, unknown>>(path.join(root, PROGRESS), 64 * 1024);
  if (input.version !== 1 || input.tool !== "aark" || input.layer !== "workflow" || input.sourcePathsRedacted !== true
    || !["running", "paused", "complete", "failed"].includes(String(input.status))) throw new Error("invalid workflow progress");
  const result: Record<string, unknown> = {version: 1, tool: "aark", layer: "workflow", sourcePathsRedacted: true, status: input.status};
  if (["recovery", "mining", "verification", "packaging", "complete"].includes(String(input.phase))) result.phase = input.phase;
  for (const key of ["scansPlanned", "scansCompleted", "scansVerified", "filesVerified", "currentScanFilesScanned", "currentScanBytesScanned"] as const) if (Number.isSafeInteger(input[key]) && Number(input[key]) >= 0) result[key] = input[key];
  for (const key of ["startedAt", "updatedAt"] as const) if (typeof input[key] === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(input[key])) result[key] = input[key];
  result.resumable = input.status === "paused"; result.cleanupAuthorized = false;
  if (["signal", "free-space-reserve", "output-cap"].includes(String(input.pauseReason))) result.pauseReason = input.pauseReason;
  if (input.recoveryProgress !== undefined) {
    try { result.recoveryProgress = redactedProgress(input.recoveryProgress, "recovery"); } catch { /* Ignore untrusted extra progress. */ }
  }
  let processObserved = false;
  if (input.status === "running" && Number.isSafeInteger(input.processId) && Number(input.processId) > 0) {
    try { process.kill(Number(input.processId), 0); processObserved = true; } catch { /* Liveness is observational, never completion proof. */ }
  }
  result.processObserved = processObserved;
  result.needsReview = input.status === "failed" || (input.status === "running" && !processObserved);
  result.nextAction = result.needsReview ? "review-local-controls" : input.status === "complete" ? "review-local-results"
    : input.status === "paused" ? input.pauseReason === "free-space-reserve" ? "free-space-and-resume"
      : input.pauseReason === "output-cap" ? "review-configured-output-cap" : "resume-when-ready" : "monitor";
  return result;
}
