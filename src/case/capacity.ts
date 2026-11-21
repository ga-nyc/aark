import path from "node:path";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { assertNoSymlinkComponents, readJson, stableLstat } from "../core/fs-safe.js";
import { assertStorageCapacity, StorageQuotaError, storagePolicyFromGiB } from "../core/storage.js";
import { mountForPath, protectedMountBacking, type LoopBackingIdentity } from "../core/mounts.js";
import { loadScanState } from "../mining/resume.js";
import { buildRecoveryPlan } from "../recovery/plan.js";
import { redactedPlan } from "../recovery/runner.js";
import { inspectSourceSafety, type SourceSafety } from "../recovery/source-safety.js";
import { controlIdentity, fileDigest, miningDirectory, outputIdentity, workflowSourceIdentity } from "../workflow/verify.js";
import { MAX_WORKFLOW_CONFIG_BYTES, type WorkflowConfig } from "../workflow/config.js";
import { workflowExternalSources } from "./sources.js";
import { verifyPreparedAttempt } from "./verify.js";
import type { PreparedAttempt } from "./types.js";

export interface CapacityProbes {
  /** Native identity validation includes the destination and every loop host. */
  outputIdentity?: typeof outputIdentity;
  assertStorageCapacity?: typeof assertStorageCapacity;
  loopBackings?: (directory: string) => Promise<LoopBackingIdentity[]>;
  inspectSourceSafety?: typeof inspectSourceSafety;
}

async function assertAbsent(filename: string): Promise<void> {
  try { await stableLstat(filename); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return; throw error; }
  throw new Error("unknown quota readiness");
}

/** A native ddrescue pause has matching terminal run controls, never a live progress snapshot. */
async function recoveryPause(config: WorkflowConfig, state: Record<string, unknown>, probes: CapacityProbes): Promise<(() => Promise<void>) | undefined> {
  const recovery = config.recovery;
  if (recovery === undefined || !recovery.image.enabled || state.pausedScan !== undefined || state.recoveryProof !== undefined) return undefined;
  const limit = 16 * MAX_WORKFLOW_CONFIG_BYTES;
  const controls = new Map<string, {identity: string; digest: {bytes: number; sha256: string}}>();
  const read = async (filename: string): Promise<Record<string, unknown>> => {
    controls.set(filename, {identity: await controlIdentity(filename), digest: await fileDigest(filename, limit)});
    return await readJson<Record<string, unknown>>(filename, limit);
  };
  const native = await read(path.join(recovery.destination, "case-sensitive.json"));
  const manifest = await read(path.join(recovery.destination, "manifest-redacted.json"));
  const last = Array.isArray(native.results) ? native.results.at(-1) as Record<string, unknown> | undefined : undefined;
  const stop = manifest.storageStop as Record<string, unknown> | undefined;
  if (native.status !== "paused" || manifest.status !== "paused" || manifest.resumable !== true
    || last?.status !== "paused-disk-quota-resumable" || last.executable !== "ddrescue"
    || stop?.reason !== "free-space-reserve") return undefined;
  const plan = buildRecoveryPlan(recovery);
  const step = plan.steps.find(candidate => candidate.id === last.id);
  const prior = (native.results as Array<Record<string, unknown>>).slice(0, -1);
  const redactedResults = manifest.results;
  if (native.version !== 1 || native.currentStep !== null || typeof native.runId !== "string" || !/^[A-Za-z0-9-]{1,128}$/u.test(native.runId)
    || typeof native.finishedAt !== "string" || manifest.tool !== "aark" || manifest.layer !== "recovery" || manifest.complete !== false
    || manifest.runId !== native.runId || manifest.finishedAt !== native.finishedAt || !isDeepStrictEqual(native.plan, plan)
    || step?.executable !== "ddrescue" || !isDeepStrictEqual(last.args, step.args) || plan.steps.indexOf(step) !== prior.length
    || prior.some((result, index) => result?.id !== plan.steps[index]!.id || result.status !== "completed" || result.executable !== "ddrescue"
      || result.exitCode !== 0 || result.terminationReason !== null || !isDeepStrictEqual(result.args, plan.steps[index]!.args))
    || !Array.isArray(redactedResults) || redactedResults.length !== prior.length + 1
    || redactedResults.some((result: Record<string, unknown>, index: number) => result?.id !== (native.results as Array<Record<string, unknown>>)[index]!.id
      || result.status !== (native.results as Array<Record<string, unknown>>)[index]!.status)) throw new Error("unknown quota readiness");
  const run = path.join(recovery.destination, "runs", native.runId);
  if (!isDeepStrictEqual(await read(`${run}-sensitive.json`), native)
    || !isDeepStrictEqual(await read(`${run}-manifest-redacted.json`), manifest)
    || !isDeepStrictEqual(await read(path.join(recovery.destination, "plan-redacted.json")), redactedPlan(plan))
    || !isDeepStrictEqual(await read(`${run}-plan-redacted.json`), redactedPlan(plan))) throw new Error("unknown quota readiness");
  const mapfile = recovery.image.mapfile;
  const mapIdentity = await controlIdentity(mapfile);
  const mapDigest = await fileDigest(mapfile, limit);
  if (mapDigest.bytes === 0) throw new Error("unknown quota readiness");
  const imageIdentity = await controlIdentity(recovery.image.path);
  const safety = probes.inspectSourceSafety ?? inspectSourceSafety;
  const sources = workflowExternalSources(config);
  if (!Array.isArray(state.resultsSafety) || state.resultsSafety.length !== sources.length
    || state.resultsSafety.some(value => typeof value !== "string")) throw new Error("unknown quota readiness");
  const assertSources = async (): Promise<void> => {
    for (const [index, source] of sources.entries()) {
      const current = await safety(source, config.output);
      if (!current.safe || workflowSourceIdentity(current) !== (state.resultsSafety as string[])[index]) throw new Error("unknown quota readiness");
    }
    const current = await safety(recovery.source, recovery.destination);
    if (!current.safe || typeof native.sourceSafety !== "object" || native.sourceSafety === null
      || workflowSourceIdentity(current) !== workflowSourceIdentity(native.sourceSafety as SourceSafety)) throw new Error("unknown quota readiness");
  };
  await assertSources();
  return async () => {
    for (const [filename, before] of controls) {
      if (await controlIdentity(filename) !== before.identity || !isDeepStrictEqual(await fileDigest(filename, limit), before.digest)) throw new Error("unknown quota readiness");
    }
    if (await controlIdentity(mapfile) !== mapIdentity || !isDeepStrictEqual(await fileDigest(mapfile, limit), mapDigest)
      || await controlIdentity(recovery.image.path) !== imageIdentity) throw new Error("unknown quota readiness");
    await assertSources();
  };
}

async function inspectReadiness(attempt: PreparedAttempt, probes: CapacityProbes): Promise<boolean> {
  try {
    const approved = await verifyPreparedAttempt(attempt.configFile, attempt.configHash);
    if (!isDeepStrictEqual(approved.workflow, attempt.workflow)) return false;
    const config = approved.workflow;
    const statePath = path.join(config.output, "workflow-state-sensitive.json");
    const checkpointPath = path.join(config.output, "workflow-checkpoint-redacted.json");
    await assertNoSymlinkComponents(path.parse(config.output).root, config.output);
    const limit = 16 * MAX_WORKFLOW_CONFIG_BYTES;
    const before = await fileDigest(statePath, limit);
    const checkpointBefore = await fileDigest(checkpointPath, 4096);
    const state = await readJson<Record<string, unknown>>(statePath, limit);
    const checkpoint = await readJson<Record<string, unknown>>(checkpointPath, 4096);
    if (state.version !== 1 || state.tool !== "aark" || state.layer !== "workflow" || state.configFile !== attempt.configFile || !isDeepStrictEqual(state.config, config)
      || checkpoint.version !== 1 || checkpoint.status !== state.status || checkpoint.stateSha256 !== before.sha256
      || typeof state.outputIdentity !== "string") throw new Error("unknown quota readiness");
    if (state.status !== "paused" || state.pauseReason !== "free-space-reserve"
      || !["recovery", "mining", "verification", "packaging"].includes(String(state.phase))) return false;
    const locks = [path.join(config.output, ".aark-workflow.lock"), ...(config.recovery === undefined ? []
      : [".aark-recovery.lock", ".agetnic-recovery.lock"].map(name => path.join(config.recovery!.destination, name)))];
    for (const filename of locks) await assertAbsent(filename);
    const recoveryRecheck = state.phase === "recovery" ? await recoveryPause(config, state, probes) : undefined;
    if (state.phase === "recovery" && recoveryRecheck === undefined) return false;
    const identity = probes.outputIdentity ?? outputIdentity;
    const capacity = probes.assertStorageCapacity ?? assertStorageCapacity;
    const backings = probes.loopBackings ?? (async (directory: string) => {
      const mount = await mountForPath(directory);
      if (mount === undefined) throw new Error("unknown quota readiness");
      return (await protectedMountBacking(mount)).loopBackings;
    });
    const checkCapacity = async (directory: string, storage: typeof config.finalizationStorage): Promise<string> => {
      const binding = await identity(directory, storage, true);
      const policy = storagePolicyFromGiB(storage.minFreeGiB, storage.minFreePercent, storage.maxOutputGiB);
      await capacity(directory, policy, 0n, 1n);
      for (const backing of await backings(directory)) await capacity(backing.backingFile,
        {minimumFreeBytes: policy.minimumFreeBytes, minimumFreePercent: policy.minimumFreePercent}, 0n, 1n);
      return binding;
    };
    if (await checkCapacity(config.output, config.finalizationStorage) !== state.outputIdentity) throw new Error("unknown quota readiness");
    let scanPath: string | undefined;
    let scanBefore: {bytes: number; sha256: string} | undefined;
    let scanIdentity: string | undefined;
    let recoveryIdentity: string | undefined;
    if (recoveryRecheck !== undefined) recoveryIdentity = await checkCapacity(config.recovery!.destination, buildRecoveryPlan(config.recovery!).storage);
    if (state.phase === "mining") {
      if (!Number.isSafeInteger(state.pausedScan) || Number(state.pausedScan) < 0 || Number(state.pausedScan) >= config.scans.length) return false;
      const index = Number(state.pausedScan);
      const output = miningDirectory(config, index);
      scanPath = path.join(output, "scan-state-sensitive.json");
      scanBefore = await fileDigest(scanPath, limit);
      const scan = await loadScanState(output);
      const selection = config.scans[index]!;
      const semantic = {inputs: selection.inputs, output, provenance: selection.provenance,
        chunkBytes: config.mining.chunkMiB * 1024 ** 2, overlapBytes: config.mining.overlapMiB * 1024 ** 2,
        wholeFileBytes: config.mining.wholeFileMiB * 1024 ** 2, deepKeySchedules: config.mining.deepKeySchedules, cryptoOnly: config.mining.cryptoOnly};
      if (scan.status !== "paused" || !scan.resumable || scan.pauseReason !== "free-space-reserve" || !isDeepStrictEqual(scan.semantic, semantic)) return false;
      scanIdentity = await checkCapacity(output, config.mining.storage);
    } else if (state.pausedScan !== undefined) return false;
    await verifyPreparedAttempt(attempt.configFile, attempt.configHash);
    if (!isDeepStrictEqual(await fileDigest(statePath, limit), before)
      || !isDeepStrictEqual(await fileDigest(checkpointPath, 4096), checkpointBefore)
      || (scanPath !== undefined && !isDeepStrictEqual(await fileDigest(scanPath, limit), scanBefore))
      || await identity(config.output, config.finalizationStorage, false) !== state.outputIdentity
      || (recoveryIdentity !== undefined && await identity(config.recovery!.destination, buildRecoveryPlan(config.recovery!).storage, false) !== recoveryIdentity)
      || (scanPath !== undefined && await identity(path.dirname(scanPath), config.mining.storage, false) !== scanIdentity)) throw new Error("unknown quota readiness");
    await recoveryRecheck?.();
    for (const filename of locks) await assertAbsent(filename);
    return true;
  } catch (error) { if (error instanceof StorageQuotaError) return false; throw error; }
}

/** A readiness hint only: native resume retains all checkpoint and quota gates. */
export async function quotaResumeReady(attempt: PreparedAttempt, probes: CapacityProbes = {}): Promise<boolean> {
  try { return await inspectReadiness(attempt, probes); }
  catch { return false; }
}

if (process.argv[1] !== undefined && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const [configFile, configHash] = process.argv.slice(2);
    if (configFile === undefined || configHash === undefined) throw new Error();
    const ready = await inspectReadiness(await verifyPreparedAttempt(configFile, configHash), {});
    process.stdout.write(JSON.stringify({ready}) + "\n");
  } catch {
    process.stdout.write('{"ready":false}\n');
    process.exitCode = 1;
  }
}
