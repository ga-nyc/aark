import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { assertNoSymlinkComponents, stableHandleStat, stableLstat, walkRegularFiles } from "../core/fs-safe.js";
import { assertLoopBackingCapacity, assertSupportedLoopOutputBackings, assertSupportedOutputMount, mountForPath, mountForPathFrom, mountIsNetworkBacked, mounts, outputLoopBinding, protectedMountBacking, stableLoopBackingIdentity } from "../core/mounts.js";
import { assertStorageCapacity, storagePolicyFromGiB } from "../core/storage.js";
import type { RecoveryStorageConfig } from "../recovery/types.js";
import { loadCompletedInventory, loadScanState, readScanManifest, verifyResumeArtifacts } from "../mining/resume.js";
import type { WorkflowConfig, WorkflowScan } from "./config.js";
import type { SourceSafety } from "../recovery/source-safety.js";

export function workflowSourceIdentity(safety: SourceSafety): string {
  // Output writes legitimately change a destination container's timestamps.
  // Block sources stay strict; regular images also freeze their own identity.
  return JSON.stringify({...safety,
    sourceLoopBackings: safety.kind === "regular-file" ? stableLoopBackingIdentity(safety.sourceLoopBackings) : safety.sourceLoopBackings,
    destinationLoopBackings: stableLoopBackingIdentity(safety.destinationLoopBackings)});
}

export function samePath(left: string, right: string): boolean {
  return process.platform === "win32" ? left.toLowerCase() === right.toLowerCase() : left === right;
}

export async function controlIdentity(filename: string): Promise<string> {
  await assertNoSymlinkComponents(path.parse(filename).root, filename);
  const value = await stableLstat(filename);
  if (!value.raw.isFile() || value.raw.nlink !== 1n || !samePath(await realpath(filename), filename)) {
    throw new Error("workflow mining control changed its canonical regular-file identity");
  }
  return JSON.stringify([value.device, value.inode, value.bytes, value.raw.mtimeNs.toString(), value.raw.ctimeNs.toString()]);
}

export function interrupted(signal?: AbortSignal): void {
  if (signal?.aborted === true) throw new Error("workflow interrupted");
}

export async function outputIdentity(directory: string, storage: RecoveryStorageConfig, checkCapacity = true): Promise<string> {
  const metadata = await stableLstat(directory);
  if (!metadata.raw.isDirectory() || metadata.raw.isSymbolicLink() || !samePath(await realpath(directory), directory)) {
    throw new Error("workflow output changed canonical directory identity");
  }
  const mounted = await mountForPath(directory);
  if (mounted === undefined || await mountIsNetworkBacked(mounted)) throw new Error("workflow requires a verifiable local output mount");
  assertSupportedOutputMount(mounted);
  const backing = await protectedMountBacking(mounted);
  assertSupportedLoopOutputBackings(backing.loopBackings);
  const policy = storagePolicyFromGiB(storage.minFreeGiB, storage.minFreePercent, storage.maxOutputGiB);
  if (checkCapacity) {
    await assertStorageCapacity(directory, policy);
    await assertLoopBackingCapacity(backing.loopBackings, policy);
  }
  return JSON.stringify({device: metadata.device, inode: metadata.inode, mount: backing.identity});
}

export async function fileDigest(filename: string, maximumBytes: number, signal?: AbortSignal): Promise<{bytes: number; sha256: string}> {
  await assertNoSymlinkComponents(path.parse(filename).root, filename);
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await stableHandleStat(handle);
    if (!before.raw.isFile() || before.raw.nlink !== 1n || before.bytes > maximumBytes) throw new Error("workflow control or artifact exceeds its regular-file limit");
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, before.bytes + 1));
    let consumed = 0;
    while (consumed < before.bytes) {
      interrupted(signal);
      const {bytesRead} = await handle.read(buffer, 0, Math.min(buffer.length, before.bytes - consumed), consumed);
      if (bytesRead === 0) throw new Error("workflow control or artifact ended prematurely");
      hash.update(buffer.subarray(0, bytesRead)); consumed += bytesRead;
    }
    const after = await stableHandleStat(handle);
    const current = await stableLstat(filename);
    if (before.device !== after.device || before.inode !== after.inode || before.bytes !== after.bytes
      || before.modifiedMs !== after.modifiedMs || before.changedMs !== after.changedMs
      || !current.raw.isFile() || current.raw.nlink !== 1n || current.device !== after.device || current.inode !== after.inode
      || current.bytes !== after.bytes || current.modifiedMs !== after.modifiedMs || current.changedMs !== after.changedMs
      || !samePath(await realpath(filename), filename)) throw new Error("workflow control or artifact changed during verification");
    return {bytes: consumed, sha256: hash.digest("hex")};
  } finally { await handle.close(); }
}

export function miningDirectory(config: WorkflowConfig, index: number): string {
  return path.join(config.output, "mining", `scan-${String(index + 1).padStart(6, "0")}`);
}

/** Caller holds both native mining locks until verification and packaging finish. */
export async function verifyScan(config: WorkflowConfig, scan: WorkflowScan, index: number, signal?: AbortSignal,
  progress?: (files: number) => void) {
  interrupted(signal);
  const output = miningDirectory(config, index);
  const seals = await Promise.all(["scan-state-sensitive.json", "inventory-sensitive.json", "scan-files-sensitive.ndjson"].map(async name => {
    const filename = path.join(output, name);
    return {filename, identity: await controlIdentity(filename)};
  }));
  const initialProof = await fileDigest(path.join(output, "scan-state-sensitive.json"), 16 * 1024 ** 2, signal);
  const state = await loadScanState(output, signal);
  const semantic = {inputs: scan.inputs, output, provenance: scan.provenance,
    chunkBytes: config.mining.chunkMiB * 1024 ** 2, overlapBytes: config.mining.overlapMiB * 1024 ** 2,
    wholeFileBytes: config.mining.wholeFileMiB * 1024 ** 2, deepKeySchedules: config.mining.deepKeySchedules,
    cryptoOnly: config.mining.cryptoOnly};
  if (!isDeepStrictEqual(state.semantic, semantic) || state.status !== "complete" || state.resumable || !state.inventoryComplete
    || state.progress.scanErrors !== 0 || state.progress.filesScanned !== state.manifest.entries
    || state.progress.filesVisited !== state.manifest.entries || state.cursor.fileIndex !== state.manifest.entries
    || state.cursor.phase !== "stream" || state.cursor.nextOffset !== 0) throw new Error("workflow requires the exact error-free completed scan selection");
  const inventory = await loadCompletedInventory(output, state.inventory, signal);
  const checkpoint = {runId: state.runId, status: state.status, inventoryComplete: state.inventoryComplete,
    semantic: state.semantic, inputRoots: state.inputRoots,
    ...(state.outputLoopBinding === undefined ? {} : {outputLoopBinding: state.outputLoopBinding}),
    manifest: state.manifest, cursor: state.cursor, progress: state.progress};
  if (!isDeepStrictEqual(inventory.resumeCheckpoint, checkpoint)
    || !isDeepStrictEqual(inventory.inputRoots, scan.inputs) || inventory.outputRoot !== output
    || inventory.findings.length !== state.progress.uniqueFindings
    || inventory.findings.reduce((n,f) => n + f.occurrences.length, 0) !== state.progress.occurrences) {
    throw new Error("workflow mining inventory and checkpoint disagree");
  }
  for (const finding of inventory.findings) for (const occurrence of finding.occurrences) {
    if (occurrence.provenance !== scan.provenance || !state.inputRoots.some(root => root.kind === "file"
      ? samePath(root.path, occurrence.sourcePath)
      : occurrence.sourcePath.startsWith(root.path + path.sep))) throw new Error("workflow finding occurrence escaped its authorized scan inputs");
  }
  const records = await mounts();
  const identities = new Map<string, ReturnType<typeof protectedMountBacking>>();
  const backingFor = async (filename: string) => {
    const mounted = mountForPathFrom(records, filename);
    if (mounted === undefined || await mountIsNetworkBacked(mounted)) throw new Error("workflow input or output lost its local mount");
    const key = JSON.stringify(mounted);
    let pending = identities.get(key);
    if (pending === undefined) { pending = protectedMountBacking(mounted); identities.set(key, pending); }
    return await pending;
  };
  if (state.outputLoopBinding !== outputLoopBinding(await backingFor(output))) throw new Error("workflow mining output binding changed");
  for (const root of state.inputRoots) {
    const current = await stableLstat(root.path);
    if (current.device !== root.device || current.inode !== root.inode || current.raw.isSymbolicLink()
      || (root.kind === "file" ? !current.raw.isFile() : !current.raw.isDirectory()) || !samePath(await realpath(root.path), root.path)
      || (await backingFor(root.path)).identity !== root.mount) throw new Error("workflow input root changed after scanning");
  }
  const currentFiles = walkRegularFiles(scan.inputs, {...(signal === undefined ? {} : {signal}), onError: () => { throw new Error("workflow input coverage walk failed"); },
    shouldEnterDirectory: async directory => { await backingFor(directory); return true; }})[Symbol.asyncIterator]();
  try {
    let checked = 0;
    for await (const file of readScanManifest(output, state.manifest, signal)) {
      const current = await currentFiles.next();
      if (current.done || !isDeepStrictEqual({...current.value, index: file.index}, file)
        || !samePath(await realpath(file.path), file.path)) {
        throw new Error("workflow input tree differs from its complete frozen scan coverage");
      }
      checked++;
      if (checked % 1000 === 0 || checked === state.manifest.entries) progress?.(checked);
    }
    if (!(await currentFiles.next()).done) throw new Error("workflow input tree contains unscanned files");
  } finally { await currentFiles.return?.(undefined); }
  await verifyResumeArtifacts(output, inventory, signal);
  if (!isDeepStrictEqual(initialProof, await fileDigest(path.join(output, "scan-state-sensitive.json"), 16 * 1024 ** 2, signal))) {
    throw new Error("workflow mining checkpoint changed during verification");
  }
  for (const seal of seals) if (await controlIdentity(seal.filename) !== seal.identity) throw new Error("workflow mining controls changed during verification");
  return {state, inventory, proof: initialProof, seals};
}
