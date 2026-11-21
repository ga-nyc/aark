import path from "node:path";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { assertNoSymlinkComponents, readJson } from "../core/fs-safe.js";
import { assertStorageCapacity, StorageQuotaError, storagePolicyFromGiB } from "../core/storage.js";
import { mountForPath, protectedMountBacking, type LoopBackingIdentity } from "../core/mounts.js";
import { loadScanState } from "../mining/resume.js";
import { fileDigest, miningDirectory, outputIdentity } from "../workflow/verify.js";
import { MAX_WORKFLOW_CONFIG_BYTES } from "../workflow/config.js";
import { verifyPreparedAttempt } from "./verify.js";
import type { PreparedAttempt } from "./types.js";

export interface CapacityProbes {
  /** Native identity validation includes the destination and every loop host. */
  outputIdentity?: typeof outputIdentity;
  assertStorageCapacity?: typeof assertStorageCapacity;
  loopBackings?: (directory: string) => Promise<LoopBackingIdentity[]>;
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
      || !["mining", "verification", "packaging"].includes(String(state.phase))) return false;
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
      || (scanPath !== undefined && await identity(path.dirname(scanPath), config.mining.storage, false) !== scanIdentity)) throw new Error("unknown quota readiness");
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
