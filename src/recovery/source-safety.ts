import { constants } from "node:fs";
import { access, lstat, readFile, readdir, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { captureCommand } from "../core/command.js";
import { nearestExistingParent } from "../core/fs-safe.js";
import { assertLoopBackingsOutside, blockTransportIsNetwork, filesystemIsNetwork, mountForPath, mountIsNetworkBacked, mountIsReadOnly, resolveBlockBacking, stableLoopBackingIdentity, type LoopBackingIdentity } from "../core/mounts.js";

interface LsblkNode {
  path?: string;
  kname?: string;
  type?: string;
  ro?: boolean | number;
  size?: number | string;
  fstype?: string | null;
  tran?: string | null;
  subsystems?: string | null;
  mountpoints?: Array<string | null> | null;
  children?: LsblkNode[];
}

export interface BlockMediaNode {
  device: string;
  majorMinor: string;
  diskseq: string;
  /** Kernel geometry uses 512-byte sectors, regardless of logical block size. */
  startSector: string;
  sizeSectors: string;
  /** A private native helper hashes the complete active mapping, including literal keys. */
  dmTableSha256?: string;
  parent: string | null;
  slaves: string[];
}
export interface BlockMediaIdentity {
  version: 1;
  bootId: string;
  devices: BlockMediaNode[];
}
export interface BlockMediaProbe {
  bootId(): Promise<string>;
  node(device: string): Promise<BlockMediaNode>;
}
const mediaError = (): Error => new Error("could not verify the kernel generation of every recovery source device");
const kernelDevice = (value: unknown): value is string => typeof value === "string" && /^\/dev\/[A-Za-z0-9_.!+-]+$/u.test(value);
function unsigned(value: unknown, maximum = (1n << 64n) - 1n): value is string {
  return typeof value === "string" && /^[1-9][0-9]{0,19}$/u.test(value) && BigInt(value) <= maximum;
}
function majorMinor(value: unknown): value is string {
  return typeof value === "string" && /^(?:0|[1-9][0-9]{0,9}):(?:0|[1-9][0-9]{0,9})$/u.test(value)
    && value.split(":").every(part => BigInt(part) <= 0xffff_ffffn);
}
function sectorCount(value: unknown): value is string { return value === "0" || unsigned(value); }
function validMediaNode(value: BlockMediaNode): boolean {
  return typeof value === "object" && value !== null && kernelDevice(value.device) && majorMinor(value.majorMinor) && unsigned(value.diskseq)
    && sectorCount(value.startSector) && sectorCount(value.sizeSectors) && (value.parent !== null || value.startSector === "0")
    && (/^\/dev\/dm-[0-9]+$/u.test(value.device) ? typeof value.dmTableSha256 === "string" && /^[a-f0-9]{64}$/u.test(value.dmTableSha256)
      : value.dmTableSha256 === undefined)
    && (value.parent === null || kernelDevice(value.parent)) && Array.isArray(value.slaves) && value.slaves.length <= 1024
    && value.slaves.every(kernelDevice) && new Set(value.slaves).size === value.slaves.length;
}
function linuxMajorMinor(device: bigint): string {
  return `${(device >> 8n & 0xfffn) | (device >> 32n & ~0xfffn)}:${(device & 0xffn) | (device >> 12n & ~0xffn)}`;
}

/** Pure metadata probe seam: no device contents are opened or read. */
export async function captureBlockMediaIdentityFrom(roots: string[], probe: BlockMediaProbe): Promise<BlockMediaIdentity> {
  if (roots.length === 0 || roots.length > 1024) throw mediaError();
  const bootId = (await probe.bootId()).trim();
  if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(bootId)) throw mediaError();
  const snapshot = async (): Promise<BlockMediaNode[]> => {
    const captured = new Map<string, BlockMediaNode>();
    const walk = async (device: string, ancestors: Set<string>, depth: number): Promise<void> => {
      if (depth > 16 || !path.posix.isAbsolute(device) || !device.startsWith("/dev/") || device.includes("\0")) throw mediaError();
      const current = await probe.node(device);
      if (!validMediaNode(current) || ancestors.has(current.device)) throw mediaError();
      const node = {...current, slaves: [...current.slaves].sort()};
      const previous = captured.get(node.device);
      if (previous !== undefined) { if (!isDeepStrictEqual(previous, node)) throw mediaError(); return; }
      if (captured.size >= 1024) throw mediaError();
      captured.set(node.device, node);
      for (const dependency of [...node.slaves, ...(node.parent === null ? [] : [node.parent])]) {
        await walk(dependency, new Set([...ancestors, node.device]), depth + 1);
      }
    };
    for (const root of [...new Set(roots)].sort()) await walk(root, new Set(), 0);
    for (const node of captured.values()) if (node.parent !== null) {
      const parent = captured.get(node.parent);
      if (parent?.diskseq !== node.diskseq || BigInt(node.startSector) + BigInt(node.sizeSectors) > BigInt(parent.sizeSectors)) throw mediaError();
    }
    return [...captured.values()].sort((left, right) => left.device.localeCompare(right.device));
  };
  const devices = await snapshot();
  if (!isDeepStrictEqual(devices, await snapshot()) || (await probe.bootId()).trim() !== bootId) throw mediaError();
  return {version: 1, bootId, devices};
}

async function kernelText(filename: string): Promise<string> {
  const data = await readFile(filename, "utf8");
  if (Buffer.byteLength(data) > 4096) throw mediaError();
  return data.trim();
}
async function dmTableDigest(id: string): Promise<string> {
  const filename = fileURLToPath(new URL("../../scripts/source-dm-digest.py", import.meta.url));
  if (await realpath(filename) !== filename) throw mediaError();
  const metadata = await lstat(filename);
  if (!metadata.isFile() || metadata.nlink !== 1 || metadata.uid !== 0 || (metadata.mode & 0o022) !== 0) throw mediaError();
  let directory = path.dirname(filename);
  while (true) {
    const current = await lstat(directory);
    if (!current.isDirectory() || current.isSymbolicLink() || current.uid !== 0 || (current.mode & 0o022) !== 0) throw mediaError();
    if (directory === path.dirname(directory)) break;
    directory = path.dirname(directory);
  }
  const result = await captureCommand("/usr/bin/python3", ["-I", "-B", filename, ...id.split(":")], {timeoutMs: 12_000, killGraceMs: 250, maxCaptureBytes: 128});
  if (result.exitCode !== 0 || result.terminationReason !== null || result.stdoutTruncated || result.stderrTruncated || result.stderr.length !== 0
    || !/^[a-f0-9]{64}\n$/u.test(result.stdout.toString())) throw mediaError();
  return result.stdout.toString().trim();
}
async function blockMediaNode(device: string): Promise<BlockMediaNode> {
  const metadata = await stat(device, {bigint: true});
  if (!metadata.isBlockDevice()) throw mediaError();
  const id = linuxMajorMinor(metadata.rdev);
  const sysfs = await realpath(`/sys/dev/block/${id}`);
  if (!sysfs.startsWith("/sys/devices/") || await kernelText(path.join(sysfs, "dev")) !== id) throw mediaError();
  const canonical = `/dev/${path.basename(sysfs)}`;
  if (!kernelDevice(canonical)) throw mediaError();
  const canonicalMetadata = await stat(canonical, {bigint: true});
  if (!canonicalMetadata.isBlockDevice() || canonicalMetadata.rdev !== metadata.rdev) throw mediaError();
  let parent: string | null = null;
  try {
    if (!unsigned(await kernelText(path.join(sysfs, "partition")))) throw mediaError();
    parent = `/dev/${path.basename(path.dirname(sysfs))}`;
    if (!kernelDevice(parent)) throw mediaError();
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  let names: string[];
  try { names = await readdir(path.join(sysfs, "slaves")); }
  catch (error) { if (parent === null || (error as NodeJS.ErrnoException).code !== "ENOENT") throw error; names = []; }
  if (names.length > 1024) throw mediaError();
  const slaves = names.map(name => `/dev/${name}`);
  if (!slaves.every(kernelDevice)) throw mediaError();
  // Partitions share their parent gendisk's sequence number.
  const diskseq = await kernelText(path.join(parent === null ? sysfs : path.dirname(sysfs), "diskseq"));
  const startSector = parent === null ? "0" : await kernelText(path.join(sysfs, "start"));
  const sizeSectors = await kernelText(path.join(sysfs, "size"));
  if (!unsigned(diskseq) || !sectorCount(startSector) || !sectorCount(sizeSectors)) throw mediaError();
  return {device: canonical, majorMinor: id, diskseq, startSector, sizeSectors, parent, slaves,
    ...(/^\/dev\/dm-[0-9]+$/u.test(canonical) ? {dmTableSha256: await dmTableDigest(id)} : {})};
}
async function captureBlockMediaIdentity(roots: string[]): Promise<BlockMediaIdentity> {
  try { return await captureBlockMediaIdentityFrom(roots, {bootId: () => kernelText("/proc/sys/kernel/random/boot_id"), node: blockMediaNode}); }
  catch { throw mediaError(); }
}
function sourceMediaRoots(source: string, physical: string[], loops: LoopBackingIdentity[]): string[] {
  try {
    return [source, ...physical, ...loops.flatMap(backing => {
      const mount: unknown = JSON.parse(backing.mount);
      if (typeof mount !== "object" || mount === null || !("source" in mount) || typeof mount.source !== "string" || !mount.source.startsWith("/dev/")) throw mediaError();
      return [backing.device, mount.source.replace(/\[[^\]]*\]$/u, "")];
    })];
  } catch { throw mediaError(); }
}

export interface SourceSafety {
  resolvedSource: string;
  kind: "block-device" | "regular-file";
  bytes: number;
  regularFileIdentity: { device: number; inode: number; bytes: number; modifiedMs: number; changedMs: number } | null;
  /** Optional only when parsing legacy controls; new block inspections always require it. */
  blockDeviceIdentity: { device: number; inode: number; rawDevice: number; media?: BlockMediaIdentity } | null;
  kernelReadOnly: boolean | null;
  writableMounts: string[];
  sourceTopDevices: string[];
  sourceTopDevice: string | null;
  sourceLoopBackings: LoopBackingIdentity[];
  destinationDevices: string[];
  destinationDevice: string | null;
  destinationLoopBackings: LoopBackingIdentity[];
  destinationFilesystemDevice: number;
  destinationMountSource: string | null;
  destinationBackingKind: "block-device" | "local-non-block" | "network" | "unresolved";
  deviceComparisonCertain: boolean;
  destinationOnSourceDevice: boolean;
  safe: boolean;
  reasons: string[];
}

/** Legacy raw checkpoints cannot be upgraded into an authorization by recapture. */
export function hasBlockMediaIdentity(safety: SourceSafety | string): boolean {
  try {
    const value: SourceSafety = typeof safety === "string" ? JSON.parse(safety) : safety;
    if (value.kind === "regular-file") return true;
    const block = value.blockDeviceIdentity;
    const media = block?.media;
    return value.kind === "block-device" && block !== null && block !== undefined && Number.isSafeInteger(block.rawDevice) && block.rawDevice >= 0
      && media?.version === 1 && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(media.bootId)
      && Array.isArray(media.devices) && media.devices.length > 0 && media.devices.length <= 1024 && media.devices.every(validMediaNode)
      && new Set(media.devices.map(node => node.device)).size === media.devices.length
      && media.devices.some(node => node.majorMinor === linuxMajorMinor(BigInt(block.rawDevice)))
      && media.devices.every(node => node.parent === null || media.devices.some(parent => parent.device === node.parent && parent.diskseq === node.diskseq
        && BigInt(node.startSector) + BigInt(node.sizeSectors) <= BigInt(parent.sizeSectors)))
      && media.devices.every(node => [node.parent, ...node.slaves].every(parent => parent === null || media.devices.some(candidate => candidate.device === parent)));
  } catch { return false; }
}

/** Compare native metadata with an existing workflow fingerprint independently of its destination. */
export function recoverySourceIdentity(safety: SourceSafety | string): string {
  if (!hasBlockMediaIdentity(safety)) throw mediaError();
  // Workflow fingerprints already serialize regular-image loop identities as
  // stable strings. Preserve that representation instead of normalizing twice.
  const captured: Omit<SourceSafety, "sourceLoopBackings"> & {sourceLoopBackings: SourceSafety["sourceLoopBackings"] | string}
    = typeof safety === "string" ? JSON.parse(safety) : safety;
  return JSON.stringify({resolvedSource: captured.resolvedSource, kind: captured.kind, bytes: captured.bytes,
    regularFileIdentity: captured.regularFileIdentity, blockDeviceIdentity: captured.blockDeviceIdentity,
    kernelReadOnly: captured.kernelReadOnly, writableMounts: captured.writableMounts,
    sourceTopDevices: captured.sourceTopDevices, sourceTopDevice: captured.sourceTopDevice,
    sourceLoopBackings: captured.kind === "regular-file" && typeof captured.sourceLoopBackings !== "string"
      ? stableLoopBackingIdentity(captured.sourceLoopBackings) : captured.sourceLoopBackings});
}

function flatten(nodes: LsblkNode[]): LsblkNode[] {
  return nodes.flatMap((node) => [node, ...flatten(node.children ?? [])]);
}

// PATH is the friendly mapper alias even when lsblk was passed /dev/dm-N.
// --paths makes KNAME the exact kernel path resolved from the requested source.
export function selectSourceDevice(nodes: LsblkNode[], resolvedSource: string): LsblkNode | undefined {
  return nodes.find(node => node.path === resolvedSource || node.kname === resolvedSource);
}

export function blockDeviceIsNetworkBacked(device: string, transport?: string | null, subsystems?: string | null): boolean {
  return blockTransportIsNetwork(device, transport, subsystems);
}

async function destinationBacking(destination: string): Promise<{
  devices: string[];
  loopBackings: LoopBackingIdentity[];
  filesystemDevice: number;
  mountSource: string | null;
  kind: "block-device" | "local-non-block" | "network" | "unresolved";
}> {
  const existing = await nearestExistingParent(destination);
  const resolvedExisting = await realpath(existing);
  const filesystemDevice = (await stat(resolvedExisting)).dev;
  const mounted = await mountForPath(resolvedExisting);
  if (mounted === undefined) return { devices: [], loopBackings: [], filesystemDevice, mountSource: null, kind: "unresolved" };
  const source = mounted.source;
  if (source.startsWith("/dev/")) {
    const resolution = await resolveBlockBacking(source.replace(/\[[^\]]*\]$/, ""));
    return {
      devices: resolution.devices,
      loopBackings: resolution.loopBackings,
      filesystemDevice,
      mountSource: source,
      kind: resolution.networkBacked ? "network" : resolution.devices.length === 0 ? "unresolved" : "block-device",
    };
  }
  const filesystem = mounted.filesystem.toLowerCase();
  if (filesystemIsNetwork(mounted)) return { devices: [], loopBackings: [], filesystemDevice, mountSource: source, kind: "network" };
  if (["ramfs", "tmpfs"].includes(filesystem)) return { devices: [], loopBackings: [], filesystemDevice, mountSource: source, kind: "local-non-block" };
  return { devices: [], loopBackings: [], filesystemDevice, mountSource: source || null, kind: "unresolved" };
}

export async function inspectSourceSafety(source: string, destination: string): Promise<SourceSafety> {
  await access(source, constants.R_OK);
  const resolvedSource = await realpath(source);
  const metadata = await stat(resolvedSource);
  if (!metadata.isBlockDevice() && !metadata.isFile()) throw new Error("source must be a block device or regular image file");
  let regularFileMount: Awaited<ReturnType<typeof mountForPath>>;
  if (metadata.isFile()) {
    regularFileMount = await mountForPath(resolvedSource);
    if (regularFileMount === undefined) throw new Error("could not determine the mount backing the recovery image");
    if (await mountIsNetworkBacked(regularFileMount)) throw new Error("network-mounted recovery sources are not allowed");
  }
  const reasons: string[] = [];
  let kernelReadOnly: boolean | null = null;
  let sourceTopDevices: string[] = [];
  let sourceLoopBackings: LoopBackingIdentity[] = [];
  let sourceBytes = metadata.size;
  let sourceMedia: BlockMediaIdentity | undefined;
  const writableMounts: string[] = [];

  if (metadata.isBlockDevice()) {
    const sourceResolution = await resolveBlockBacking(resolvedSource);
    if (sourceResolution.networkBacked) throw new Error("network-backed block-device recovery sources are not allowed");
    sourceTopDevices = sourceResolution.devices;
    sourceLoopBackings = sourceResolution.loopBackings;
    sourceMedia = await captureBlockMediaIdentity(sourceMediaRoots(resolvedSource, sourceTopDevices, sourceLoopBackings));
    const result = await captureCommand(
      "lsblk",
      ["--json", "--bytes", "--paths", "--output", "PATH,KNAME,TYPE,RO,SIZE,FSTYPE,MOUNTPOINTS", resolvedSource],
      { maxCaptureBytes: 1024 * 1024, timeoutMs: 30_000 },
    );
    if (result.exitCode !== 0) throw new Error("lsblk could not inspect the source device");
    if (result.stdoutTruncated) throw new Error("lsblk output exceeded its bounded safety limit while inspecting the source");
    let document: { blockdevices?: LsblkNode[] };
    try {
      document = JSON.parse(result.stdout.toString("utf8")) as { blockdevices?: LsblkNode[] };
    } catch (error) {
      throw new Error("lsblk returned invalid JSON while inspecting the source", { cause: error });
    }
    const nodes = flatten(document.blockdevices ?? []);
    const selected = selectSourceDevice(nodes, resolvedSource);
    if (selected === undefined) throw new Error("lsblk did not return the requested source device");
    kernelReadOnly = selected?.ro === true || selected?.ro === 1;
    const selectedBytes = typeof selected.size === "string" ? Number(selected.size) : selected.size;
    if (Number.isSafeInteger(selectedBytes) && (selectedBytes ?? 0) >= 0) sourceBytes = selectedBytes ?? 0;
    for (const node of nodes) {
      for (const mountpoint of node.mountpoints ?? []) {
        // lsblk also reports pseudo-labels such as "[SWAP]" in MOUNTPOINTS.
        // Only real absolute mount paths are meaningful to the mount table.
        if (mountpoint === null || !path.isAbsolute(mountpoint)) continue;
        const mounted = await mountForPath(mountpoint);
        if (!mountIsReadOnly(mounted)) writableMounts.push(mountpoint);
      }
    }
    if (!kernelReadOnly) reasons.push("kernel does not report the block device read-only");
    if (writableMounts.length > 0) reasons.push("source or a child volume has a writable mount");
  } else if (regularFileMount?.source.startsWith("/dev/") === true) {
    const sourceResolution = await resolveBlockBacking(regularFileMount.source.replace(/\[[^\]]*\]$/, ""));
    if (sourceResolution.networkBacked) throw new Error("network-backed recovery image files are not allowed");
    sourceTopDevices = sourceResolution.devices;
    sourceLoopBackings = sourceResolution.loopBackings;
  }

  const destinationInfo = await destinationBacking(destination);
  if (metadata.isBlockDevice()) {
    const current = await stat(resolvedSource);
    const resolution = await resolveBlockBacking(resolvedSource);
    if (!current.isBlockDevice() || current.dev !== metadata.dev || current.ino !== metadata.ino || current.rdev !== metadata.rdev
      || resolution.networkBacked || !isDeepStrictEqual(resolution.devices, sourceTopDevices) || !isDeepStrictEqual(resolution.loopBackings, sourceLoopBackings)
      || !sourceMedia?.devices.some(node => node.majorMinor === linuxMajorMinor(BigInt(metadata.rdev)))
      || !isDeepStrictEqual(sourceMedia, await captureBlockMediaIdentity(sourceMediaRoots(resolvedSource, sourceTopDevices, sourceLoopBackings)))) throw mediaError();
  }
  if (metadata.isFile()) await assertLoopBackingsOutside(destinationInfo.loopBackings, [resolvedSource], "recovery source image");
  await assertLoopBackingsOutside(sourceLoopBackings, [destination], "recovery destination");
  const destinationDevices = destinationInfo.devices;
  const deviceComparisonCertain = destinationInfo.kind === "local-non-block"
    || (sourceTopDevices.length > 0 && destinationInfo.kind === "block-device" && destinationDevices.length > 0);
  const destinationOnSourceDevice = metadata.isBlockDevice()
    && sourceTopDevices.some((device) => destinationDevices.includes(device));
  if (destinationOnSourceDevice) reasons.push("destination resolves to the same physical block device as the source");
  if (metadata.isBlockDevice() && !deviceComparisonCertain) reasons.push("could not prove that the destination is independent of the source block device");
  if (path.resolve(destination) === path.resolve(source)) reasons.push("destination and source resolve to the same path");
  return {
    resolvedSource,
    kind: metadata.isBlockDevice() ? "block-device" : "regular-file",
    bytes: sourceBytes,
    regularFileIdentity: metadata.isFile()
      ? { device: metadata.dev, inode: metadata.ino, bytes: metadata.size, modifiedMs: metadata.mtimeMs, changedMs: metadata.ctimeMs }
      : null,
    blockDeviceIdentity: metadata.isBlockDevice()
      ? { device: metadata.dev, inode: metadata.ino, rawDevice: metadata.rdev, media: sourceMedia! }
      : null,
    kernelReadOnly,
    writableMounts,
    sourceTopDevices,
    sourceTopDevice: sourceTopDevices[0] ?? null,
    sourceLoopBackings,
    destinationDevices,
    destinationDevice: destinationDevices[0] ?? null,
    destinationLoopBackings: destinationInfo.loopBackings,
    destinationFilesystemDevice: destinationInfo.filesystemDevice,
    destinationMountSource: destinationInfo.mountSource,
    destinationBackingKind: destinationInfo.kind,
    deviceComparisonCertain,
    destinationOnSourceDevice,
    safe: reasons.length === 0,
    reasons,
  };
}
