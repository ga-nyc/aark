import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, realpath } from "node:fs/promises";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { assertCompletedInventoryMatchesState, verifyCompletedMiningForRetention } from "./cleanup.js";
import { acquireExclusiveLock, assertNoSymlinkComponents, atomicWriteJson, ensurePrivateDirectory, nearestExistingParent, readDirectoryNamesBounded, safeJoin, stableHandleStat, stableLstat, syncDirectory } from "./core/fs-safe.js";
import type { ExclusiveLock, StableStat } from "./core/fs-safe.js";
import { assertLoopBackingCapacity, assertSupportedLoopOutputBackings, assertSupportedOutputMount, mountForPath, mountForPathFrom, mountIsNetworkBacked, mounts, protectedMountBacking, resolveBlockBacking } from "./core/mounts.js";
import type { MountRecord } from "./core/mounts.js";
import { assertStorageCapacity, StorageBudget, storagePolicyFromGiB } from "./core/storage.js";
import type { StoragePolicy } from "./core/storage.js";
import { loadDetachedCompletedInventory, loadDetachedScanState, readScanManifest, verifyResumeArtifacts } from "./mining/resume.js";
import type { FrozenScanFile } from "./mining/resume.js";

const MANIFEST = "retention-manifest-sensitive.json";
const SUMMARY = "manifest-redacted.json";
const MAX_MANIFEST_BYTES = 16 * 1024 ** 2;
const MAX_FILES = 100_000;
const MAX_SCANS = 128;
const LOCKS = [".aark-mining.lock", ".agetnic-mining.lock"] as const;
const CONTROLS = ["scan-state-sensitive.json", "scan-files-sensitive.ndjson", "inventory-sensitive.json", "manifest-redacted.json", "final-report-sensitive.md", "final-report-redacted.md"] as const;
const HASH = /^[a-f0-9]{64}$/;

export interface RetentionOptions {
  miningOutputs: string[];
  destination: string;
  minimumFreeGiB?: number;
  minimumFreePercent?: number;
  maximumOutputGiB?: number;
  signal?: AbortSignal;
}
export interface RetentionRunOptions extends RetentionOptions { planToken: string; execute: boolean }
/** Programmatic fixture dependency only. The CLI never accepts a physical-device override. */
export interface RetentionDependencies { physicalDevices?: (filename: string) => Promise<string[]> }
interface Snapshot { device: StableStat["device"]; inode: StableStat["inode"]; bytes: number; modifiedMs: number; changedMs: number }
interface FileProof { path: string; bytes: number; sha256: string; kind: "source" | "control" | "artifact" }
interface SourceMapping { originalPath: string; relativePath: string; bytes: number; sha256: string; snapshots: Array<{scan: number; file: FrozenScanFile}> }
interface ScanMapping { number: number; originalOutput: string; relativeDirectory: string; runId: string }
interface Binding { filename: string; identity: string; entryIdentity: string; devices: string[]; role: "destination" | "mining" | "input" | "source" }
interface RetentionManifest {
  version: 1; tool: "aark"; layer: "whole-source-retention"; status: "complete"; planToken: string;
  scope: "selected-completed-scan-findings"; personalDataBackupComplete: false; erasureAuthorized: false;
  sourceHashesMeasuredAt: "export"; destinationAtExport: string; exportBindings: Binding[]; scans: ScanMapping[]; sources: SourceMapping[]; files: FileProof[];
}
interface PlannedCopy { original: string; relative: string; snapshot: Snapshot; kind: FileProof["kind"]; sha256?: string }
interface InternalPlan {
  public: Record<string, unknown> & {planToken: string}; copies: PlannedCopy[];
  sources: SourceMapping[]; scans: ScanMapping[]; proofs: Array<{controlDigest: string}>;
  destination: string; parent: string; parentIdentity: string; bindings: Binding[];
  policy: StoragePolicy;
}

const RETENTION_FILESYSTEMS = new Set(["ext2", "ext3", "ext4", "vfat", "exfat", "ntfs", "ntfs3", "fuse.exfat", "fuse.ntfs", "fuse.ntfs-3g", "fuseblk"]);
/** lsblk ancestry is sufficient only for these single-device filesystem drivers. */
type RetentionFilesystemRecord = Pick<MountRecord, "filesystem"> & Partial<Pick<MountRecord, "source" | "options">>;
export function assertRetentionFilesystem(record: RetentionFilesystemRecord, loopHostRecords: ReadonlyArray<RetentionFilesystemRecord> = []): void {
  for (const mounted of [record, ...loopHostRecords]) {
    if (!RETENTION_FILESYSTEMS.has(mounted.filesystem.toLowerCase())) throw new Error("retention cannot prove complete physical membership for this filesystem");
    if (/^ext[234]$/i.test(mounted.filesystem) && mounted.options?.some(option => /^(journal_dev|journal_path)(?:=|$)/i.test(option))) throw new Error("retention refuses external or overridden ext journals");
  }
}
/** Fixed ext superblock offsets follow the kernel's ext4/super.html and journal.html. */
export function assertInternalExtJournal(superblock: Buffer): "absent" | "internal" {
  if (superblock.length !== 1024 || superblock.readUInt16LE(0x38) !== 0xef53 || superblock.readUInt32LE(0x4c) > 1) throw new Error("retention ext journal metadata is invalid or unknown");
  const revision = superblock.readUInt32LE(0x4c), hasJournal = (superblock.readUInt32LE(0x5c) & 0x4) !== 0;
  const journalInode = superblock.readUInt32LE(0xe0), journalDevice = superblock.readUInt32LE(0xe4);
  if ((superblock.readUInt32LE(0x60) & 0x8) !== 0 || journalDevice !== 0 || superblock.subarray(0xd0, 0xe0).some(value => value !== 0)
    || (hasJournal ? revision !== 1 || journalInode === 0 : journalInode !== 0)) throw new Error("retention requires a proven internal or absent ext journal");
  return hasJournal ? "internal" : "absent";
}
async function verifyExtJournalDevice(mounted: RetentionFilesystemRecord): Promise<void> {
  if (!/^ext[234]$/i.test(mounted.filesystem)) return;
  if (typeof mounted.source !== "string" || !mounted.source.startsWith("/dev/")) throw new Error("retention cannot read ext journal metadata from a canonical local device");
  const filename = await realpath(mounted.source.replace(/\[[^\]]*\]$/, ""));
  await assertNoSymlinkComponents(path.parse(filename).root, filename);
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await stableHandleStat(handle), current = await stableLstat(filename);
    const sameDevice = (actual: StableStat) => actual.raw.isBlockDevice() && !actual.raw.isSymbolicLink() && actual.device === before.device && actual.inode === before.inode && actual.raw.rdev === before.raw.rdev;
    if (!sameDevice(before) || !sameDevice(current) || await realpath(filename) !== filename) throw new Error("retention ext journal device identity changed");
    const bytes = Buffer.allocUnsafe(1024);
    let consumed = 0;
    while (consumed < bytes.length) { const result = await handle.read(bytes, consumed, bytes.length - consumed, 1024 + consumed); if (result.bytesRead === 0) throw new Error("retention ext superblock ended prematurely"); consumed += result.bytesRead; }
    assertInternalExtJournal(bytes);
    if (!sameDevice(await stableHandleStat(handle)) || !sameDevice(await stableLstat(filename)) || await realpath(filename) !== filename) throw new Error("retention ext journal device identity changed during verification");
  } finally { await handle.close(); }
}
/** Directory scans may cross local mounts; this first export contract deliberately refuses them. */
export function assertRetentionInputMounts(root: string, kind: "file" | "directory", records: readonly MountRecord[]): void {
  const canonicalRoot = path.resolve(root);
  if (kind === "directory" && records.some(mounted => path.resolve(mounted.target) !== canonicalRoot && inside(canonicalRoot, path.resolve(mounted.target)))) throw new Error("retention selected directory input must not contain nested mounts");
}
function loopHostRecords(backings: ReadonlyArray<{mount: string}>): RetentionFilesystemRecord[] {
  return backings.map(backing => { let value: unknown; try { value = JSON.parse(backing.mount) as unknown; } catch { throw new Error("retention loop host identity is invalid"); } const host = record(value); if (typeof host.filesystem !== "string" || typeof host.source !== "string" || !Array.isArray(host.options) || host.options.some(value => typeof value !== "string")) throw new Error("retention loop host filesystem is unknown"); return {filesystem: host.filesystem, source: host.source, options: host.options as string[]}; });
}
async function verifyRetentionFilesystems(mounted: RetentionFilesystemRecord, backings: ReadonlyArray<{mount: string}>): Promise<void> {
  const hosts = loopHostRecords(backings);
  assertRetentionFilesystem(mounted, hosts);
  for (const record of [mounted, ...hosts]) await verifyExtJournalDevice(record);
}

function linuxOnly(): void { if (process.platform !== "linux") throw new Error("whole-source retention currently requires Linux physical-device verification"); }
function interrupted(signal?: AbortSignal): void { if (signal?.aborted) throw new Error("retention interrupted"); }
function snapshot(value: StableStat): Snapshot { return {device: value.device, inode: value.inode, bytes: value.bytes, modifiedMs: value.modifiedMs, changedMs: value.changedMs}; }
function sameFile(actual: StableStat, expected: Snapshot): boolean { return actual.raw.isFile() && !actual.raw.isSymbolicLink() && actual.device === expected.device && actual.inode === expected.inode && actual.bytes === expected.bytes && actual.modifiedMs === expected.modifiedMs && actual.changedMs === expected.changedMs; }
function inside(root: string, filename: string): boolean { const relative = path.relative(root, filename); return relative === "" || relative !== ".." && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative); }
function boundedJson(value: unknown): string { const data = JSON.stringify(value, null, 2) + "\n"; if (Buffer.byteLength(data) > MAX_MANIFEST_BYTES) throw new Error("retention manifest exceeds its bounded limit; use smaller explicit selections"); return data; }
function policyFor(options: RetentionOptions): StoragePolicy {
  if ((options.minimumFreeGiB ?? 5) < 5 || (options.minimumFreePercent ?? 5) < 5) throw new Error("retention storage reserves must be at least 5 GiB and 5 percent");
  return storagePolicyFromGiB(options.minimumFreeGiB, options.minimumFreePercent, options.maximumOutputGiB);
}
async function absent(filename: string): Promise<boolean> { try { await stableLstat(filename); return false; } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return true; throw error; } }
async function directoryIdentity(directory: string): Promise<string> {
  await assertNoSymlinkComponents(path.parse(directory).root, directory);
  const value = await stableLstat(directory);
  if (!value.raw.isDirectory() || value.raw.isSymbolicLink() || await realpath(directory) !== directory) throw new Error("retention directory lost its canonical identity");
  return JSON.stringify([value.device, value.inode]);
}
async function physicalDevices(filename: string, dependencies: RetentionDependencies): Promise<string[]> {
  let devices: string[];
  if (dependencies.physicalDevices !== undefined) devices = await dependencies.physicalDevices(filename);
  else {
    const mounted = await mountForPath(filename);
    if (mounted === undefined || await mountIsNetworkBacked(mounted) || !mounted.source.startsWith("/dev/")) throw new Error("retention cannot prove an independent local physical destination");
    const resolved = await resolveBlockBacking(mounted.source.replace(/\[[^\]]*\]$/, ""));
    assertRetentionFilesystem(mounted, loopHostRecords(resolved.loopBackings));
    if (resolved.networkBacked) throw new Error("retention refuses network-backed physical storage");
    devices = resolved.devices;
  }
  if (!Array.isArray(devices) || devices.length === 0 || devices.length > 1024 || devices.some(value => typeof value !== "string" || !/^\/dev\/[A-Za-z0-9_./!-]+$/.test(value))) throw new Error("retention physical ancestry is unknown");
  return [...new Set(devices)].sort();
}
interface BindingPass { records: Awaited<ReturnType<typeof mounts>>; cached: Map<string, Promise<{identity: string; devices: string[]}>> }
async function bindingPass(): Promise<BindingPass> { return {records: await mounts(), cached: new Map()}; }
async function binding(filename: string, dependencies: RetentionDependencies, role: Binding["role"], pass?: BindingPass): Promise<Binding> {
  await assertNoSymlinkComponents(path.parse(filename).root, filename);
  const mounted = pass === undefined ? await mountForPath(filename) : mountForPathFrom(pass.records, filename);
  if (mounted === undefined) throw new Error("retention requires verifiable local mounts");
  const inspect = async () => {
    if (await mountIsNetworkBacked(mounted)) throw new Error("retention requires verifiable local mounts");
    const backing = await protectedMountBacking(mounted);
    if (dependencies.physicalDevices === undefined) await verifyRetentionFilesystems(mounted, backing.loopBackings);
    return {identity: backing.identity, devices: await physicalDevices(filename, dependencies)};
  };
  // Test physical inspection can model independent disks on a single synthetic filesystem.
  const key = JSON.stringify(mounted);
  let pending = dependencies.physicalDevices === undefined ? pass?.cached.get(key) : undefined;
  if (pending === undefined) { pending = inspect(); if (dependencies.physicalDevices === undefined) pass?.cached.set(key, pending); }
  const checked = await pending;
  const metadata = await stableLstat(filename);
  if (metadata.raw.isSymbolicLink() || (!metadata.raw.isFile() && !metadata.raw.isDirectory()) || await realpath(filename) !== filename) throw new Error("retention protected path identity changed");
  return {filename, ...checked, entryIdentity: JSON.stringify([metadata.device, metadata.inode, metadata.raw.isFile() ? "file" : "directory"]), role};
}
async function assertNoNestedMounts(root: string): Promise<void> {
  if ((await mounts()).some(mounted => path.resolve(mounted.target) !== root && inside(root, path.resolve(mounted.target)))) throw new Error("retention bundle must not contain nested mounts");
}

async function destinationCapacity(directory: string, policy: StoragePolicy, planned = 0n): Promise<void> {
  const mounted = await mountForPath(directory);
  if (mounted === undefined || await mountIsNetworkBacked(mounted)) throw new Error("retention destination must remain local");
  assertSupportedOutputMount(mounted);
  const backing = await protectedMountBacking(mounted);
  assertSupportedLoopOutputBackings(backing.loopBackings);
  await assertStorageCapacity(directory, policy, 0n, planned);
  await assertLoopBackingCapacity(backing.loopBackings, policy);
}
async function digest(filename: string, maximum: number, signal?: AbortSignal, expected?: Snapshot): Promise<{bytes: number; sha256: string; snapshot: Snapshot}> {
  interrupted(signal);
  await assertNoSymlinkComponents(path.parse(filename).root, filename);
  const input = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await stableHandleStat(input);
    if (!before.raw.isFile() || before.bytes > maximum || expected !== undefined && !sameFile(before, expected) || !sameFile(await stableLstat(filename), snapshot(before)) || await realpath(filename) !== filename) throw new Error("retention file identity changed before verification");
    const hash = createHash("sha256"), buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    while (offset < before.bytes) {
      interrupted(signal);
      const read = await input.read(buffer, 0, Math.min(buffer.length, before.bytes - offset), offset);
      if (read.bytesRead === 0) throw new Error("retention file ended prematurely");
      hash.update(buffer.subarray(0, read.bytesRead)); offset += read.bytesRead;
    }
    if ((await input.read(buffer, 0, 1, offset)).bytesRead !== 0 || !sameFile(await stableHandleStat(input), snapshot(before)) || !sameFile(await stableLstat(filename), snapshot(before)) || await realpath(filename) !== filename) throw new Error("retention file changed during verification");
    return {bytes: offset, sha256: hash.digest("hex"), snapshot: snapshot(before)};
  } finally { await input.close(); }
}
async function stableJson(filename: string, signal?: AbortSignal): Promise<{value: Record<string, unknown>; proof: Awaited<ReturnType<typeof digest>>}> {
  interrupted(signal); await assertNoSymlinkComponents(path.parse(filename).root, filename);
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await stableHandleStat(handle);
    if (!before.raw.isFile() || before.raw.nlink !== 1n || before.bytes > MAX_MANIFEST_BYTES || !sameFile(await stableLstat(filename), snapshot(before))) throw new Error("retention JSON control is not a bounded stable regular file");
    const data = Buffer.allocUnsafe(before.bytes);
    let offset = 0;
    while (offset < data.length) { interrupted(signal); const result = await handle.read(data, offset, data.length - offset, offset); if (result.bytesRead === 0) throw new Error("retention JSON control ended prematurely"); offset += result.bytesRead; }
    if ((await handle.read(Buffer.allocUnsafe(1), 0, 1, offset)).bytesRead !== 0 || !sameFile(await stableHandleStat(handle), snapshot(before)) || !sameFile(await stableLstat(filename), snapshot(before)) || await realpath(filename) !== filename) throw new Error("retention JSON control changed while being read");
    let value: unknown;
    try { value = JSON.parse(data.toString("utf8")) as unknown; } catch { throw new Error("retention JSON control is invalid"); }
    return {value: record(value), proof: {bytes: data.length, sha256: createHash("sha256").update(data).digest("hex"), snapshot: snapshot(before)}};
  } finally { await handle.close(); }
}
function controlLimit(name: string): number { return name === "scan-state-sensitive.json" ? 16 * 1024 ** 2 : name === "inventory-sensitive.json" ? 128 * 1024 ** 2 : 256 * 1024 ** 2; }
function commonSummary(scans: number, sources: SourceMapping[], artifactFiles: number): Record<string, unknown> {
  return {version: 1, tool: "aark", layer: "whole-source-retention", pathsRedacted: true, valuesPrinted: false,
    scope: "selected-completed-scan-findings", selectedFindingSourcesOnly: true, miningScansVerified: scans,
    sourceFilesRetained: String(sources.length), sourceFileLogicalBytesRetained: sources.reduce((sum, source) => sum + BigInt(source.bytes), 0n).toString(),
    artifactFilesRetained: artifactFiles, personalDataBackupComplete: false, personalBackup: false, cleanupAuthorized: false, erasureAuthorized: false,
    sourceHashesMeasuredAt: "export", originalSourcesUnchangedDuringExport: true};
}
function makeManifest(plan: Pick<InternalPlan, "scans" | "sources" | "destination" | "bindings">, planToken: string, files: FileProof[]): RetentionManifest {
  return {version: 1, tool: "aark", layer: "whole-source-retention", status: "complete", planToken,
    scope: "selected-completed-scan-findings", personalDataBackupComplete: false, erasureAuthorized: false, sourceHashesMeasuredAt: "export",
    destinationAtExport: plan.destination, exportBindings: plan.bindings, scans: plan.scans, sources: plan.sources, files};
}
function completedSummary(plan: Record<string, unknown>, files: number, manifestHash: string): Record<string, unknown> {
  return {...plan, status: "complete", wholeSourceFilesCopied: true, copiedFilesVerified: files, bundleManifestSha256: manifestHash};
}
async function buildPlan(options: RetentionOptions, dependencies: RetentionDependencies, locksHeld = false): Promise<InternalPlan> {
  linuxOnly(); interrupted(options.signal);
  if (!Array.isArray(options.miningOutputs) || options.miningOutputs.length < 1 || options.miningOutputs.length > MAX_SCANS) throw new Error("retention requires 1 through 128 explicit completed mining outputs");
  const outputs = [...options.miningOutputs].sort();
  if (new Set(outputs).size !== outputs.length || outputs.some(output => !path.isAbsolute(output) || path.resolve(output) !== output)) throw new Error("retention outputs must be distinct canonical absolute paths");
  const destination = options.destination;
  if (!path.isAbsolute(destination) || path.resolve(destination) !== destination || !(await absent(destination))) throw new Error("retention requires a fresh canonical destination directory");
  const parent = path.dirname(destination);
  if (await nearestExistingParent(destination) !== parent) throw new Error("retention destination parent must already exist");
  const parentIdentity = await directoryIdentity(parent);
  const policy = policyFor(options);
  const pass = await bindingPass();
  const destinationBinding = await binding(parent, dependencies, "destination", pass);
  await destinationCapacity(parent, policy);
  const proofs: InternalPlan["proofs"] = [], copies: PlannedCopy[] = [], scans: ScanMapping[] = [];
  const sources = new Map<string, SourceMapping>();
  const bindings = [destinationBinding];
  let trackedBytes = 0, sourceReferences = 0;
  const charge = (value: unknown) => { trackedBytes += Buffer.byteLength(JSON.stringify(value)); if (trackedBytes > MAX_MANIFEST_BYTES) throw new Error("retention aggregate manifest exceeds its bounded limit"); };
  const addCopy = (copy: PlannedCopy) => { if (copies.length >= MAX_FILES) throw new Error("retention copied-file count exceeds its bounded limit"); charge(copy); copies.push(copy); };
  const addBinding = async (filename: string, role: Binding["role"]) => { const value = await binding(filename, dependencies, role, pass); charge(value); bindings.push(value); };
  for (const [index, output] of outputs.entries()) {
    interrupted(options.signal);
    if (inside(output, destination) || inside(destination, output)) throw new Error("retention destination overlaps a native mining output");
    for (const other of outputs) if (other !== output && inside(output, other)) throw new Error("retention mining outputs overlap");
    const proof = await verifyCompletedMiningForRetention(output, options.signal, locksHeld);
    proofs.push({controlDigest: proof.controlDigest});
    const relativeDirectory = `mining/scan-${String(index + 1).padStart(6, "0")}`;
    scans.push({number: index + 1, originalOutput: output, relativeDirectory, runId: proof.state.runId});
    await addBinding(output, "mining");
    for (const root of proof.state.inputRoots) {
      assertRetentionInputMounts(root.path, root.kind, pass.records);
      if (inside(root.path, destination) || inside(destination, root.path)) throw new Error("retention destination overlaps an original scan input");
      if (!bindings.some(value => value.role === "input" && value.filename === root.path)) await addBinding(root.path, "input");
    }
    const wanted = new Set(proof.inventory.findings.flatMap(finding => finding.occurrences.map(occurrence => occurrence.sourcePath)));
    for await (const file of readScanManifest(output, proof.state.manifest, options.signal)) {
      if (!wanted.has(file.path)) continue;
      let source = sources.get(file.path);
      if (source === undefined) {
        if (sources.size >= MAX_FILES) throw new Error("retention source count exceeds its bounded limit");
        source = {originalPath: file.path, relativePath: "", bytes: file.bytes, sha256: "", snapshots: []}; sources.set(file.path, source);
      }
      if (source.bytes !== file.bytes || source.snapshots.some(value => !isDeepStrictEqual({...value.file, index: file.index}, file))) throw new Error("retention scans disagree about a shared source snapshot");
      if (++sourceReferences > MAX_FILES) throw new Error("retention source reference count exceeds its bounded limit");
      charge({originalPath: file.path, scan: index + 1, file});
      source.snapshots.push({scan: index + 1, file}); wanted.delete(file.path);
    }
    if (wanted.size !== 0) throw new Error("retention finding source is absent from the frozen scan manifest");
    for (const name of CONTROLS) {
      const filename = safeJoin(output, name), value = await digest(filename, controlLimit(name), options.signal);
      addCopy({original: filename, relative: `${relativeDirectory}/${name}`, snapshot: value.snapshot, kind: "control", sha256: value.sha256});
    }
    for (const finding of proof.inventory.findings) for (const artifact of finding.artifactIntegrity) {
      const filename = safeJoin(output, artifact.path), value = await digest(filename, 256 * 1024 ** 2, options.signal);
      if (value.sha256 !== artifact.sha256 || value.bytes !== artifact.bytes) throw new Error("retention artifact integrity changed");
      addCopy({original: filename, relative: `${relativeDirectory}/${artifact.path.split(path.sep).join("/")}`, snapshot: value.snapshot, kind: "artifact", sha256: value.sha256});
    }
  }
  const orderedSources = [...sources.values()].sort((left, right) => left.originalPath < right.originalPath ? -1 : 1);
  for (const [index, source] of orderedSources.entries()) {
    const frozen = source.snapshots[0]?.file;
    if (frozen === undefined) throw new Error("retention source snapshot missing");
    source.relativePath = `sources/source-${String(index + 1).padStart(6, "0")}.bin`;
    const metadata = await stableLstat(source.originalPath);
    if (!sameFile(metadata, frozen)) throw new Error("retention source no longer matches its frozen scan snapshot");
    await addBinding(source.originalPath, "source");
    addCopy({original: source.originalPath, relative: source.relativePath, snapshot: snapshot(metadata), kind: "source"});
  }
  if (copies.length > MAX_FILES) throw new Error("retention copied-file count exceeds its bounded limit");
  for (const source of bindings.filter(value => value.role === "source" || value.role === "input")) if (source.devices.some(device => destinationBinding.devices.includes(device))) throw new Error("retention destination shares physical storage with a selected original input or source");
  const logicalBytes = copies.reduce((sum, copy) => sum + BigInt(copy.snapshot.bytes), 0n);
  await destinationCapacity(parent, policy, logicalBytes);
  const tokenData = {version: 1, outputs, destination, parentIdentity, bindings, copies, scans, sources: orderedSources,
    controls: proofs.map(proof => proof.controlDigest), policy: {minimumFreeBytes: policy.minimumFreeBytes.toString(), minimumFreePercent: policy.minimumFreePercent, maximumOutputBytes: policy.maximumOutputBytes?.toString()}};
  const planToken = createHash("sha256").update(boundedJson(tokenData)).digest("hex");
  const publicPlan = {...commonSummary(scans.length, orderedSources, copies.filter(copy => copy.kind === "artifact").length), status: "ready", destructive: false, planToken,
    logicalBytesToCopy: logicalBytes.toString(), logicalBundleBytes: "0", nativeControlFilesRetained: copies.filter(copy => copy.kind === "control").length,
    destinationPhysicallyIndependent: true, wholeSourceFilesCopied: false,
    storage: {minimumFreeGiB: options.minimumFreeGiB ?? 5, minimumFreePercent: options.minimumFreePercent ?? 5, ...(options.maximumOutputGiB === undefined ? {} : {maximumOutputGiB: options.maximumOutputGiB})}};
  const projectedManifest = makeManifest({scans, sources: orderedSources.map(source => ({...source, sha256: "0".repeat(64)})), destination, bindings}, planToken,
    copies.map(copy => ({path: copy.relative, bytes: copy.snapshot.bytes, sha256: copy.sha256 ?? "0".repeat(64), kind: copy.kind})));
  const manifestBytes = BigInt(Buffer.byteLength(boundedJson(projectedManifest)));
  // Decimal total length affects its own summary field; two passes normally converge.
  let finalSummaryBytes = 0n;
  for (let attempt = 0; attempt < 16; attempt++) {
    finalSummaryBytes = BigInt(Buffer.byteLength(boundedJson(completedSummary(publicPlan, copies.length, "0".repeat(64)))));
    const total = (logicalBytes + manifestBytes + finalSummaryBytes).toString();
    if (publicPlan.logicalBundleBytes === total) break;
    publicPlan.logicalBundleBytes = total;
    if (attempt === 15) throw new Error("retention metadata size estimate did not converge");
  }
  const initialSummaryBytes = BigInt(Buffer.byteLength(boundedJson({...publicPlan, status: "copying", wholeSourceFilesCopied: false})));
  await destinationCapacity(parent, {minimumFreeBytes: policy.minimumFreeBytes, minimumFreePercent: policy.minimumFreePercent}, BigInt(publicPlan.logicalBundleBytes) + initialSummaryBytes);
  await assertStorageCapacity(parent, policy, BigInt(publicPlan.logicalBundleBytes));
  return {public: publicPlan, copies, sources: orderedSources, scans, proofs, destination, parent, parentIdentity, bindings, policy};
}

export async function planRetention(options: RetentionOptions, dependencies: RetentionDependencies = {}): Promise<Record<string, unknown> & {planToken: string}> {
  return (await buildPlan(options, dependencies)).public;
}

async function copyFile(copy: PlannedCopy, destination: string, budget: StorageBudget, guard: () => Promise<void>, signal?: AbortSignal): Promise<FileProof> {
  await guard();
  await assertNoSymlinkComponents(path.parse(copy.original).root, copy.original);
  const input = await open(copy.original, constants.O_RDONLY | constants.O_NOFOLLOW);
  let output: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const before = await stableHandleStat(input);
    if (!sameFile(before, copy.snapshot) || !sameFile(await stableLstat(copy.original), copy.snapshot) || await realpath(copy.original) !== copy.original) throw new Error("retention source changed before copying");
    await mkdir(path.dirname(destination), {recursive: true, mode: 0o700});
    await assertNoNestedMounts(budget.target);
    const parentIdentity = await directoryIdentity(path.dirname(destination));
    const rootDevice = (await stableLstat(budget.target)).device;
    if ((await stableLstat(path.dirname(destination))).device !== rootDevice) throw new Error("retention copy parent crossed the destination filesystem");
    await assertNoSymlinkComponents(path.parse(destination).root, destination);
    output = await open(destination, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const outputOpened = await stableHandleStat(output);
    if (outputOpened.device !== rootDevice || !sameFile(await stableLstat(destination), snapshot(outputOpened))) throw new Error("retention destination file identity changed during creation");
    const hash = createHash("sha256"), buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    while (offset < copy.snapshot.bytes) {
      interrupted(signal); await guard();
      await assertNoSymlinkComponents(budget.target, destination);
      const outputNow = await stableHandleStat(output);
      if (await directoryIdentity(path.dirname(destination)) !== parentIdentity || !sameFile(await stableLstat(destination), snapshot(outputNow)) || !sameFile(await stableHandleStat(input), copy.snapshot) || !sameFile(await stableLstat(copy.original), copy.snapshot)) throw new Error("retention copy source or destination changed before a write");
      const {bytesRead} = await input.read(buffer, 0, Math.min(buffer.length, copy.snapshot.bytes - offset), offset);
      if (bytesRead === 0) throw new Error("retention source ended prematurely while copying");
      await budget.beforeWrite(BigInt(bytesRead));
      let written = 0;
      while (written < bytesRead) {
        const result = await output.write(buffer, written, bytesRead - written, offset + written);
        if (result.bytesWritten === 0) throw new Error("retention copy made no write progress");
        written += result.bytesWritten;
      }
      hash.update(buffer.subarray(0, bytesRead)); offset += bytesRead; budget.committedWrite(BigInt(bytesRead));
    }
    if ((await input.read(buffer, 0, 1, offset)).bytesRead !== 0 || !sameFile(await stableHandleStat(input), copy.snapshot) || !sameFile(await stableLstat(copy.original), copy.snapshot) || await realpath(copy.original) !== copy.original) throw new Error("retention source changed during copying");
    const sha256 = hash.digest("hex");
    if (copy.sha256 !== undefined && copy.sha256 !== sha256) throw new Error("retention control or artifact changed during copying");
    await output.sync(); await output.close(); output = undefined;
    await syncDirectory(path.dirname(destination)); await guard();
    await assertNoNestedMounts(budget.target);
    if (await directoryIdentity(path.dirname(destination)) !== parentIdentity) throw new Error("retention copy parent changed before readback");
    const actual = await digest(destination, Number.MAX_SAFE_INTEGER, signal);
    if (actual.bytes !== offset || actual.sha256 !== sha256) throw new Error("retention copied file failed independent readback");
    if (!sameFile(await stableHandleStat(input), copy.snapshot) || !sameFile(await stableLstat(copy.original), copy.snapshot)) throw new Error("retention original changed during destination verification");
    return {path: copy.relative, bytes: offset, sha256, kind: copy.kind};
  } finally { await output?.close(); await input.close(); }
}

export async function runRetention(options: RetentionRunOptions, dependencies: RetentionDependencies = {}): Promise<Record<string, unknown>> {
  linuxOnly();
  if (options.execute !== true || !HASH.test(options.planToken)) throw new Error("retention copying requires --execute and the exact reviewed plan token");
  // Verify the token before lock creation changes any native output directory.
  const initial = await buildPlan(options, dependencies);
  if (initial.public.planToken !== options.planToken) throw new Error("retention plan changed; review a fresh read-only plan");
  const locks: ExclusiveLock[] = [];
  let plan: InternalPlan | undefined, rootIdentity: string | undefined, created = false;
  let bundleBinding: Binding | undefined;
  try {
    for (const root of [...options.miningOutputs].sort()) for (const name of LOCKS) locks.push(await acquireExclusiveLock(root, name));
    plan = await buildPlan(options, dependencies, true);
    if (plan.public.planToken !== options.planToken) throw new Error("retention plan changed while acquiring operation locks");
    if (await directoryIdentity(plan.parent) !== plan.parentIdentity) throw new Error("retention destination parent changed");
    await mkdir(plan.destination, {mode: 0o700}); created = true;
    await ensurePrivateDirectory(plan.destination); rootIdentity = await directoryIdentity(plan.destination);
    await atomicWriteJson(safeJoin(plan.destination, SUMMARY), {...plan.public, status: "copying", wholeSourceFilesCopied: false});
    await syncDirectory(plan.parent);
    bundleBinding = await binding(plan.destination, dependencies, "destination");
    const expectedBinding = plan.bindings[0];
    if (expectedBinding === undefined || bundleBinding.identity !== expectedBinding.identity || !isDeepStrictEqual(bundleBinding.devices, expectedBinding.devices)) throw new Error("retention destination mount changed during creation");
    const initialSummaryBytes = BigInt(Buffer.byteLength(boundedJson({...plan.public, status: "copying", wholeSourceFilesCopied: false})));
    const budget = new StorageBudget(plan.destination, plan.policy, initialSummaryBytes);
    let lastMountCheck = 0, lastBytesCheck = 0n;
    const guard = async () => {
      interrupted(options.signal);
      for (const lock of locks) await lock.assertHeld();
      if (await directoryIdentity(plan!.destination) !== rootIdentity || await directoryIdentity(plan!.parent) !== plan!.parentIdentity) throw new Error("retention destination directory changed");
      if (Date.now() - lastMountCheck >= 30_000 || budget.outputBytes() - lastBytesCheck >= 1024n ** 3n) {
        const currentPass = await bindingPass();
        for (const expected of plan!.bindings) if (expected.role === "input") { const metadata = await stableLstat(expected.filename); assertRetentionInputMounts(expected.filename, metadata.raw.isDirectory() ? "directory" : "file", currentPass.records); }
        await assertNoNestedMounts(plan!.destination);
        for (const expected of plan!.bindings) if (!isDeepStrictEqual(await binding(expected.filename, dependencies, expected.role, currentPass), expected)) throw new Error("retention source or destination physical binding changed");
        if (!isDeepStrictEqual(await binding(plan!.destination, dependencies, "destination", currentPass), bundleBinding)) throw new Error("retention bundle physical binding changed");
        await destinationCapacity(plan!.destination, plan!.policy);
        lastMountCheck = Date.now(); lastBytesCheck = budget.outputBytes();
      }
    };
    for (const scan of plan.scans) await mkdir(safeJoin(plan.destination, scan.relativeDirectory, "artifacts"), {recursive: true, mode: 0o700});
    const files: FileProof[] = [];
    for (const copy of plan.copies) files.push(await copyFile(copy, safeJoin(plan.destination, copy.relative), budget, guard, options.signal));
    lastMountCheck = 0; await guard();
    for (const [index, scan] of plan.scans.entries()) {
      const fresh = await verifyCompletedMiningForRetention(scan.originalOutput, options.signal, true);
      if (fresh.controlDigest !== plan.proofs[index]?.controlDigest) throw new Error("retention native controls changed during export");
    }
    for (const source of plan.sources) { const proof = files.find(file => file.path === source.relativePath); if (proof === undefined) throw new Error("retention source proof missing"); source.sha256 = proof.sha256; }
    const durableDirectories = new Set<string>(["mining"]);
    for (const scan of plan.scans) durableDirectories.add(scan.relativeDirectory + "/artifacts");
    for (const file of files) { let parent = path.posix.dirname(file.path); while (parent !== ".") { durableDirectories.add(parent); parent = path.posix.dirname(parent); } }
    for (const directory of [...durableDirectories].sort((left, right) => right.split("/").length - left.split("/").length)) { await guard(); await syncDirectory(safeJoin(plan.destination, directory)); }
    const manifest = makeManifest(plan, options.planToken, files);
    const data = boundedJson(manifest);
    await guard(); await budget.beforeWrite(BigInt(Buffer.byteLength(data)));
    await atomicWriteJson(safeJoin(plan.destination, MANIFEST), manifest); budget.committedWrite(BigInt(Buffer.byteLength(data)));
    await verifyRetentionBundleAt(plan.destination, options.signal, true);
    lastMountCheck = 0; await guard();
    for (const copy of plan.copies) { interrupted(options.signal); await assertNoSymlinkComponents(path.parse(copy.original).root, copy.original); if (!sameFile(await stableLstat(copy.original), copy.snapshot) || await realpath(copy.original) !== copy.original) throw new Error("retention original changed before completion publication"); }
    const summary = completedSummary(plan.public, files.length, createHash("sha256").update(data).digest("hex"));
    const summaryBytes = BigInt(Buffer.byteLength(boundedJson(summary)));
    await budget.beforeWrite(summaryBytes, initialSummaryBytes);
    await atomicWriteJson(safeJoin(plan.destination, SUMMARY), summary);
    budget.committedWrite(summaryBytes, initialSummaryBytes);
    if (budget.outputBytes().toString() !== plan.public.logicalBundleBytes) throw new Error("retention final logical size differs from its reviewed plan");
    await syncDirectory(plan.destination); await syncDirectory(plan.parent);
    return summary;
  } catch (error) {
    if (created && plan !== undefined && rootIdentity !== undefined) {
      try {
        if (await directoryIdentity(plan.destination) === rootIdentity && await directoryIdentity(plan.parent) === plan.parentIdentity
          && (bundleBinding === undefined || isDeepStrictEqual(await binding(plan.destination, dependencies, "destination"), bundleBinding))) {
          await atomicWriteJson(safeJoin(plan.destination, SUMMARY), {...plan.public, status: options.signal?.aborted ? "interrupted-partial" : "failed-partial", wholeSourceFilesCopied: false});
        }
      } catch { /* A substituted output is not a safe report destination. */ }
    }
    throw error;
  } finally {
    const errors: unknown[] = [];
    for (const lock of locks.reverse()) try { await lock.release(); } catch (error) { errors.push(error); }
    if (errors.length !== 0) throw new AggregateError(errors, "retention operation locks could not all be released");
  }
}

function record(value: unknown): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("retention manifest requires an object"); return value as Record<string, unknown>; }
function relativeFile(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value) > 8192 || value.includes("\\") || path.isAbsolute(value) || value.split("/").some(part => part === "" || part === "." || part === "..")) throw new Error("retention bundle contains an unsafe relative path");
  return value;
}
async function exactBundleTree(root: string, expectedFiles: Set<string>, expectedDirectories: Set<string>, signal?: AbortSignal): Promise<void> {
  const pending = [""];
  let entries = 0;
  while (pending.length > 0) {
    interrupted(signal);
    const relative = pending.pop()!;
    const directory = relative === "" ? root : safeJoin(root, relative);
    for (const name of await readDirectoryNamesBounded(directory, MAX_FILES + 1)) {
      if (++entries > MAX_FILES * 4) throw new Error("retention bundle tree exceeds its bounded limit");
      const child = relative === "" ? name : relative + "/" + name;
      const value = await stableLstat(safeJoin(root, child));
      if (value.raw.isSymbolicLink()) throw new Error("retention bundle contains a symbolic link");
      if (value.raw.isDirectory() && expectedDirectories.delete(child)) pending.push(child);
      else if (value.raw.isFile() && value.raw.nlink === 1n && expectedFiles.delete(child)) { /* accounted */ }
      else throw new Error("retention bundle contains an unexpected filesystem entry");
    }
  }
  if (expectedFiles.size !== 0 || expectedDirectories.size !== 0) throw new Error("retention bundle contains missing files or directories");
}

/** Uses copied controls and bundle-relative files only; original paths are never opened. */
async function verifyRetentionBundleAt(bundle: string, signal: AbortSignal | undefined, allowCopyingSummary: boolean): Promise<Record<string, unknown>> {
  linuxOnly(); interrupted(signal);
  if (!path.isAbsolute(bundle) || path.resolve(bundle) !== bundle) throw new Error("retention bundle must be canonical");
  const rootIdentity = await directoryIdentity(bundle);
  await assertNoNestedMounts(bundle);
  const manifestRead = await stableJson(safeJoin(bundle, MANIFEST), signal);
  const manifestProof = manifestRead.proof, manifest = manifestRead.value;
  if (manifest.version !== 1 || manifest.tool !== "aark" || manifest.layer !== "whole-source-retention" || manifest.status !== "complete"
    || manifest.scope !== "selected-completed-scan-findings" || manifest.personalDataBackupComplete !== false || manifest.erasureAuthorized !== false
    || manifest.sourceHashesMeasuredAt !== "export" || typeof manifest.planToken !== "string" || !HASH.test(manifest.planToken)
    || !Array.isArray(manifest.scans) || manifest.scans.length < 1 || manifest.scans.length > MAX_SCANS
    || !Array.isArray(manifest.sources) || manifest.sources.length > MAX_FILES || !Array.isArray(manifest.files) || manifest.files.length > MAX_FILES) throw new Error("retention bundle manifest is invalid");
  const summaryRead = await stableJson(safeJoin(bundle, SUMMARY), signal);
  const summary = summaryRead.value;
  if (summary.status !== "complete" && !(allowCopyingSummary && summary.status === "copying")) throw new Error("retention bundle is incomplete");
  if (summary.planToken !== manifest.planToken || summary.erasureAuthorized !== false || summary.personalDataBackupComplete !== false
    || summary.status === "complete" && summary.bundleManifestSha256 !== manifestProof.sha256) throw new Error("retention bundle summary and private manifest disagree");
  const files = new Map<string, FileProof>();
  for (const value of manifest.files) {
    const file = record(value), relative = relativeFile(file.path);
    if (!Number.isSafeInteger(file.bytes) || Number(file.bytes) < 0 || typeof file.sha256 !== "string" || !HASH.test(file.sha256) || !["source", "control", "artifact"].includes(String(file.kind)) || files.has(relative)) throw new Error("retention bundle file proof is invalid");
    files.set(relative, file as unknown as FileProof);
  }
  const parsedSources = new Set<string>();
  for (const value of manifest.sources) { const source = record(value); if (typeof source.originalPath !== "string" || parsedSources.has(source.originalPath)) throw new Error("retention source list is invalid"); parsedSources.add(source.originalPath); }
  const expectedCopies = new Map<string, FileProof["kind"]>(), expectedSources = new Map<string, Array<{scan: number; file: FrozenScanFile}>>();
  const originalOutputs = new Set<string>();
  let artifacts = 0, sourceReferences = 0;
  const verifiedFiles = new Map<string, Snapshot>();
  for (const [index, value] of manifest.scans.entries()) {
    const scan = record(value), relative = relativeFile(scan.relativeDirectory);
    if (scan.number !== index + 1 || relative !== `mining/scan-${String(index + 1).padStart(6, "0")}` || typeof scan.originalOutput !== "string" || originalOutputs.has(scan.originalOutput)) throw new Error("retention copied scan mapping is invalid");
    originalOutputs.add(scan.originalOutput);
    const output = safeJoin(bundle, relative);
    const controlProofs = new Map<string, Awaited<ReturnType<typeof digest>>>();
    for (const name of CONTROLS) { const filename = safeJoin(output, name); const proof = await digest(filename, controlLimit(name), signal); const expected = files.get(relative + "/" + name); if (expected?.sha256 !== proof.sha256 || expected.bytes !== proof.bytes) throw new Error("retention copied control integrity disagrees before parsing"); controlProofs.set(filename, proof); }
    const state = await loadDetachedScanState(output, scan.originalOutput, signal);
    const inventory = await loadDetachedCompletedInventory(output, scan.originalOutput, state.inventory, signal);
    assertCompletedInventoryMatchesState(inventory, state);
    if (scan.runId !== state.runId) throw new Error("retention copied scan run identity disagrees");
    await verifyResumeArtifacts(output, inventory, signal);
    const wanted = new Set(inventory.findings.flatMap(finding => finding.occurrences.map(occurrence => occurrence.sourcePath)));
    if (wanted.size > parsedSources.size || [...wanted].some(filename => !parsedSources.has(filename))) throw new Error("retention copied scan contains an unmapped whole source");
    for await (const file of readScanManifest(output, state.manifest, signal)) if (wanted.delete(file.path)) {
      if (++sourceReferences > MAX_FILES) throw new Error("retention source references exceed the bounded limit");
      const references = expectedSources.get(file.path) ?? [];
      references.push({scan: index + 1, file}); expectedSources.set(file.path, references);
    }
    if (wanted.size !== 0) throw new Error("retention copied scan source is absent from its frozen manifest");
    for (const [filename, proof] of controlProofs) { if (!sameFile(await stableLstat(filename), proof.snapshot) || await realpath(filename) !== filename) throw new Error("retention copied control changed during parsing"); verifiedFiles.set(filename, proof.snapshot); }
    for (const name of CONTROLS) expectedCopies.set(relative + "/" + name, "control");
    for (const finding of inventory.findings) for (const artifact of finding.artifactIntegrity) { expectedCopies.set(relative + "/" + artifact.path.split(path.sep).join("/"), "artifact"); artifacts++; }
  }
  const sources: SourceMapping[] = [];
  for (const [index, value] of manifest.sources.entries()) {
    const source = record(value), relative = relativeFile(source.relativePath);
    if (typeof source.originalPath !== "string" || relative !== `sources/source-${String(index + 1).padStart(6, "0")}.bin`
      || !Number.isSafeInteger(source.bytes) || Number(source.bytes) < 0 || typeof source.sha256 !== "string" || !HASH.test(source.sha256)
      || !isDeepStrictEqual(source.snapshots, expectedSources.get(source.originalPath))) throw new Error("retention whole-source mapping disagrees with its native frozen manifests");
    const references = expectedSources.get(source.originalPath);
    if (references === undefined || references.some(reference => reference.file.bytes !== source.bytes)) throw new Error("retention whole-source size disagrees with its scan snapshots");
    expectedSources.delete(source.originalPath);
    const proof = files.get(relative);
    if (proof === undefined || proof.bytes !== source.bytes || proof.sha256 !== source.sha256) throw new Error("retention source integrity mapping disagrees");
    expectedCopies.set(relative, "source"); sources.push(source as unknown as SourceMapping);
  }
  if (expectedSources.size !== 0 || expectedCopies.size !== files.size) throw new Error("retention bundle omits or adds files outside its exact finding-source selection");
  if (typeof manifest.destinationAtExport !== "string" || !path.isAbsolute(manifest.destinationAtExport) || path.resolve(manifest.destinationAtExport) !== manifest.destinationAtExport || !Array.isArray(manifest.exportBindings) || manifest.exportBindings.length > MAX_FILES * 3) throw new Error("retention export binding receipt is invalid");
  const receipt = manifest.exportBindings.map(value => record(value));
  const destinationReceipt = receipt.filter(value => value.role === "destination");
  if (destinationReceipt.length !== 1 || destinationReceipt[0]?.filename !== path.dirname(manifest.destinationAtExport)) throw new Error("retention destination binding receipt is invalid");
  if (!Array.isArray(destinationReceipt[0]?.devices)) throw new Error("retention destination physical receipt is invalid");
  const expectedInputPaths = new Set<string>();
  for (const value of manifest.scans) { const scan = record(value); const state = await loadDetachedScanState(safeJoin(bundle, String(scan.relativeDirectory)), String(scan.originalOutput), signal); for (const input of state.inputRoots) expectedInputPaths.add(input.path); }
  const expectedReceiptPaths = new Set<string>([...originalOutputs].map(filename => "mining:" + filename).concat([...parsedSources].map(filename => "source:" + filename), [...expectedInputPaths].map(filename => "input:" + filename), ["destination:" + path.dirname(manifest.destinationAtExport)]));
  for (const value of receipt) {
    if (typeof value.filename !== "string" || !path.isAbsolute(value.filename) || path.resolve(value.filename) !== value.filename || typeof value.identity !== "string" || Buffer.byteLength(value.identity) > 64 * 1024 || typeof value.entryIdentity !== "string" || Buffer.byteLength(value.entryIdentity) > 1024 || !["mining", "source", "input", "destination"].includes(String(value.role))
      || !Array.isArray(value.devices) || value.devices.length < 1 || value.devices.length > 1024 || value.devices.some(device => typeof device !== "string" || !/^\/dev\/[A-Za-z0-9_./!-]+$/.test(device)) || !expectedReceiptPaths.delete(String(value.role) + ":" + value.filename)) throw new Error("retention physical binding receipt contains invalid or unexpected entries");
    if ((value.role === "source" || value.role === "input") && value.devices.some(device => (destinationReceipt[0]?.devices as unknown[]).includes(device))) throw new Error("retention receipt does not prove independent original source storage");
  }
  if (expectedReceiptPaths.size !== 0) throw new Error("retention physical binding receipt is incomplete");
  const directories = new Set<string>(["mining"]);
  // Empty artifacts directories are part of native scan outputs even for marker-only scans.
  for (const value of manifest.scans) directories.add(relativeFile(record(value).relativeDirectory) + "/artifacts");
  for (const [relative, proof] of files) {
    if (expectedCopies.get(relative) !== proof.kind) throw new Error("retention bundle file kind or scope disagrees");
    const actual = await digest(safeJoin(bundle, relative), proof.kind === "control" ? controlLimit(path.basename(relative)) : proof.kind === "artifact" ? 256 * 1024 ** 2 : Number.MAX_SAFE_INTEGER, signal);
    if (actual.bytes !== proof.bytes || actual.sha256 !== proof.sha256) throw new Error("retention bundle file failed integrity verification");
    const filename = safeJoin(bundle, relative);
    const prior = verifiedFiles.get(filename);
    if (prior !== undefined && !isDeepStrictEqual(prior, actual.snapshot)) throw new Error("retention copied control changed after parsing");
    verifiedFiles.set(filename, actual.snapshot);
    let parent = path.posix.dirname(relative);
    while (parent !== ".") { directories.add(parent); parent = path.posix.dirname(parent); }
  }
  await exactBundleTree(bundle, new Set([...files.keys(), MANIFEST, SUMMARY]), directories, signal);
  await assertNoNestedMounts(bundle);
  verifiedFiles.set(safeJoin(bundle, MANIFEST), manifestProof.snapshot);
  verifiedFiles.set(safeJoin(bundle, SUMMARY), summaryRead.proof.snapshot);
  for (const [filename, expected] of verifiedFiles) { interrupted(signal); if (!sameFile(await stableLstat(filename), expected) || await realpath(filename) !== filename) throw new Error("retention bundle file changed after hashing"); }
  if (await directoryIdentity(bundle) !== rootIdentity || !isDeepStrictEqual(await digest(safeJoin(bundle, MANIFEST), MAX_MANIFEST_BYTES, signal), manifestProof)) throw new Error("retention bundle changed during verification");
  const logicalBundleBytes = [...files.values()].reduce((sum, file) => sum + BigInt(file.bytes), 0n) + BigInt(manifestProof.bytes) + BigInt(summaryRead.proof.bytes);
  if (!allowCopyingSummary && summary.logicalBundleBytes !== logicalBundleBytes.toString()) throw new Error("retention logical bundle size disagrees with its reviewed plan");
  const result = {...commonSummary(manifest.scans.length, sources, artifacts), logicalBundleBytes: logicalBundleBytes.toString(), status: "complete", wholeSourceFilesCopied: true, copiedFilesVerified: files.size, destinationPhysicallyIndependentAtExport: true};
  for (const key of ["sourceFilesRetained", "sourceFileLogicalBytesRetained", "miningScansVerified", "artifactFilesRetained"]) if (summary[key] !== result[key as keyof typeof result]) throw new Error("retention redacted counts disagree with verified bundle");
  return result;
}

export async function verifyRetentionBundle(bundle: string, signal?: AbortSignal): Promise<Record<string, unknown>> { return await verifyRetentionBundleAt(bundle, signal, false); }

export async function verifyRetention(options: {bundle: string; signal?: AbortSignal}): Promise<Record<string, unknown>> { return await verifyRetentionBundle(options.bundle, options.signal); }
