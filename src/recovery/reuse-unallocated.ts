import { lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { acquireExclusiveLock, assertNoSymlinkComponents, nearestExistingParent, readJson, stableLstat } from "../core/fs-safe.js";
import type { ExclusiveLock, StableStat } from "../core/fs-safe.js";
import { assertSupportedOutputMount, mountForPath, mountForPathFrom, mountIsNetworkBacked, mounts } from "../core/mounts.js";
import type { RecoveryConfig } from "./types.js";

const LOCKS = [".aark-recovery.lock", ".agetnic-recovery.lock"] as const;
const TERMINAL = ["complete", "complete-with-warnings", "failed", "interrupted"];

export interface ReusedUnallocatedStream {
  assertCurrent(): Promise<void>;
  release(): Promise<void>;
  summary: { sourcePathsRedacted: true; sourceRecoveryStatus: string; stage: "unallocated-stream"; bytes: string };
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("invalid recovery controls for unallocated-stream reuse");
  return value as Record<string, unknown>;
}

function overlaps(left: string, right: string): boolean {
  const relative = path.relative(left, right);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function sameFile(left: StableStat, right: StableStat): boolean {
  return left.device === right.device && left.inode === right.inode && left.bytes === right.bytes
    && left.modifiedMs === right.modifiedMs && left.changedMs === right.changedMs
    && right.raw.isFile() && right.raw.nlink === 1n;
}

async function validateRoot(config: RecoveryConfig): Promise<string> {
  if (process.platform !== "linux") throw new Error("reusing a recovery stream requires Linux");
  const root = config.unallocatedStreamFromCase;
  if (root === undefined || !path.isAbsolute(root) || overlaps(root, config.destination) || overlaps(config.destination, root)
    || config.stages.unallocatedStream || !config.stages.signatureCarving) {
    throw new Error("unallocated-stream reuse requires separate cases and carving without a new extraction");
  }
  await assertNoSymlinkComponents(path.parse(root).root, root);
  if (await realpath(root) !== root || !(await lstat(root)).isDirectory()) throw new Error("the earlier recovery case must be a canonical directory");
  const snapshot = await mounts();
  const mount = mountForPathFrom(snapshot, root);
  if (mount === undefined || await mountIsNetworkBacked(mount)) throw new Error("the earlier recovery case must be on a verifiable local mount");
  if (snapshot.some(item => path.resolve(item.target) !== root && overlaps(root, path.resolve(item.target)))) {
    throw new Error("the earlier recovery case must not contain a nested mount");
  }
  const destinationParent = await nearestExistingParent(config.destination);
  await assertNoSymlinkComponents(path.parse(destinationParent).root, destinationParent);
  const destinationMount = mountForPathFrom(snapshot, destinationParent);
  if (destinationMount === undefined) throw new Error("the follow-up destination must have a verifiable mount");
  const [sourceMetadata, destinationMetadata] = await Promise.all([
    lstat(root, { bigint: true }), lstat(destinationParent, { bigint: true }),
  ]);
  // Bind mounts and repeated mounts can hide directory overlap from realpath.
  // Allow ordinary sibling cases, but require an unambiguous filesystem view.
  if (sourceMetadata.dev === destinationMetadata.dev
    && path.resolve(mount.target) !== path.resolve(destinationMount.target)) {
    throw new Error("separate mount views of the same filesystem cannot prove that the cases do not overlap");
  }
  return root;
}

async function releaseLocks(locks: ExclusiveLock[]): Promise<void> {
  const errors: unknown[] = [];
  for (const lock of [...locks].reverse()) {
    try { await lock.release(); } catch (error) { errors.push(error); }
  }
  if (errors.length > 0) throw new AggregateError(errors, "could not release the earlier recovery case locks");
}

async function loadStream(config: RecoveryConfig, root: string, locks: ExclusiveLock[]): Promise<ReusedUnallocatedStream> {
  const controls = new Map<string, StableStat>();
  const load = async (relative: string): Promise<unknown> => {
    const filename = path.join(root, relative);
    await assertNoSymlinkComponents(root, filename);
    const before = await stableLstat(filename);
    const value = await readJson<unknown>(filename);
    const after = await stableLstat(filename);
    if (!sameFile(before, after)) throw new Error("earlier recovery controls changed while being read");
    controls.set(filename, after);
    return value;
  };
  const state = record(await load("case-sensitive.json"));
  if (state.version !== 1 || typeof state.runId !== "string" || !/^[0-9A-Za-z][0-9A-Za-z._-]{0,255}$/.test(state.runId)
    || !TERMINAL.includes(String(state.status)) || typeof state.finishedAt !== "string" || !Number.isFinite(Date.parse(state.finishedAt))
    || state.currentStep !== null || !Array.isArray(state.results)) {
    throw new Error("unallocated-stream reuse requires a terminal earlier recovery run");
  }
  const plan = record(state.plan);
  if (plan.version !== 1 || plan.destination !== root || typeof plan.source !== "string" || typeof plan.analysisSource !== "string"
    || !Array.isArray(plan.steps) || plan.steps.length > 128 || typeof plan.requireReadOnlySource !== "boolean"
    || (plan.requireReadOnlySource && !config.requireReadOnlySource)
    || await realpath(plan.source) !== await realpath(config.source)) {
    throw new Error("the reused stream must belong to the same authorized source without weaker source protection");
  }
  if (!isDeepStrictEqual(state, await load(path.join("runs", `${state.runId}-sensitive.json`)))) {
    throw new Error("earlier recovery state does not match its per-run control");
  }
  const publicPlan = await load("plan-redacted.json");
  if (!isDeepStrictEqual(publicPlan, await load(path.join("runs", `${state.runId}-plan-redacted.json`)))) {
    throw new Error("earlier recovery plan does not match its per-run control");
  }
  const manifest = record(await load("manifest-redacted.json"));
  if (manifest.runId !== state.runId || manifest.status !== state.status || !Array.isArray(manifest.results)
    || !isDeepStrictEqual(manifest, await load(path.join("runs", `${state.runId}-manifest-redacted.json`)))) {
    throw new Error("earlier recovery manifest does not match its run");
  }
  const steps = plan.steps.map(record);
  const index = steps.findIndex((step) => step.id === "unallocated-stream");
  const extraction = steps[index];
  const result = index < 0 ? undefined : record(state.results[index]);
  const publicResults = manifest.results.map(record).filter((item) => item.id === "unallocated-stream");
  const input = path.join(root, "recovery", "unallocated", "free-space.raw");
  const args = extraction?.args;
  const offset = Array.isArray(args) && args.length === 4 && args[1] === "-o"
    && typeof args[2] === "string" && /^[0-9]+$/.test(args[2]) && Number.isSafeInteger(Number(args[2]));
  if (steps.filter((step) => step.id === "unallocated-stream").length !== 1
    || extraction?.executable !== "blkls" || extraction.stdoutFile !== input || extraction.provenance !== "unallocated-stream"
    || !isDeepStrictEqual(extraction.outputs, [input]) || !Array.isArray(args) || args[0] !== "-A"
    || !(args.length === 2 || offset) || args.at(-1) !== plan.analysisSource
    || result?.id !== "unallocated-stream" || result.status !== "completed" || result.executable !== "blkls" || result.exitCode !== 0
    || (result.signal !== null && result.signal !== undefined) || (result.terminationReason !== null && result.terminationReason !== undefined)
    || !Array.isArray(result.args) || !isDeepStrictEqual(result.args.slice(0, -1), args.slice(0, -1))
    || typeof result.args.at(-1) !== "string" || await realpath(result.args.at(-1) as string) !== await realpath(plan.analysisSource)
    || publicResults.length !== 1 || publicResults[0]?.status !== "completed") {
    throw new Error("the earlier case does not prove a completed blkls -A extraction");
  }
  await assertNoSymlinkComponents(root, input);
  const inputMetadata = await stableLstat(input);
  if (!inputMetadata.raw.isFile() || inputMetadata.raw.nlink !== 1n || inputMetadata.bytes < 1 || await realpath(input) !== input) {
    throw new Error("the completed unallocated stream must be a nonempty single-link regular file");
  }
  const inputMount = await mountForPath(input);
  if (inputMount === undefined || await mountIsNetworkBacked(inputMount)) throw new Error("the reused stream must stay on a local mount");
  const rootIdentity = await lstat(root);
  const mountIdentity = JSON.stringify(inputMount);
  const assertCurrent = async (): Promise<void> => {
    for (const lock of locks) await lock.assertHeld();
    await validateRoot(config);
    if (locks.length === 0) {
      for (const name of LOCKS) {
        try { await lstat(path.join(root, name)); }
        catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
          throw error;
        }
        throw new Error("the earlier recovery case has an operation lock");
      }
    }
    await assertNoSymlinkComponents(path.parse(root).root, input);
    const currentRoot = await lstat(root);
    if (currentRoot.dev !== rootIdentity.dev || currentRoot.ino !== rootIdentity.ino || !currentRoot.isDirectory()
      || await realpath(root) !== root || JSON.stringify(await mountForPath(input)) !== mountIdentity
      || !sameFile(inputMetadata, await stableLstat(input))) {
      throw new Error("the reused stream, earlier case, or source mount changed");
    }
    for (const [filename, metadata] of controls) {
      await assertNoSymlinkComponents(root, filename);
      if (!sameFile(metadata, await stableLstat(filename))) throw new Error("earlier recovery controls changed during stream reuse");
    }
  };
  await assertCurrent();
  return { assertCurrent, release: () => releaseLocks(locks), summary: {
    sourcePathsRedacted: true, sourceRecoveryStatus: String(state.status), stage: "unallocated-stream", bytes: String(inputMetadata.bytes),
  } };
}

/** Read-only assessment: no locks are created, and active cases are rejected. */
export async function assessReusedUnallocatedStream(config: RecoveryConfig): Promise<ReusedUnallocatedStream["summary"]> {
  const root = await validateRoot(config);
  return (await loadStream(config, root, [])).summary;
}

/** Hold both compatibility locks until the new carving run has finished. */
export async function acquireReusedUnallocatedStream(config: RecoveryConfig): Promise<ReusedUnallocatedStream> {
  const root = await validateRoot(config);
  // These locks are writes, even though the reused recovery data is read-only.
  assertSupportedOutputMount(await mountForPath(root));
  const locks: ExclusiveLock[] = [];
  try {
    for (const name of [...LOCKS].sort()) locks.push(await acquireExclusiveLock(root, name));
    return await loadStream(config, root, locks);
  } catch (error) {
    try { await releaseLocks(locks); }
    catch (releaseError) { throw new AggregateError([error, releaseError], "stream validation and lock release failed"); }
    throw error;
  }
}
