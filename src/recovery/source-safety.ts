import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { captureCommand } from "../core/command.js";
import { nearestExistingParent } from "../core/fs-safe.js";
import { assertLoopBackingsOutside, blockTransportIsNetwork, filesystemIsNetwork, mountForPath, mountIsNetworkBacked, mountIsReadOnly, resolveBlockBacking, type LoopBackingIdentity } from "../core/mounts.js";

interface LsblkNode {
  path?: string;
  type?: string;
  ro?: boolean | number;
  size?: number | string;
  fstype?: string | null;
  tran?: string | null;
  subsystems?: string | null;
  mountpoints?: Array<string | null> | null;
  children?: LsblkNode[];
}

export interface SourceSafety {
  resolvedSource: string;
  kind: "block-device" | "regular-file";
  bytes: number;
  regularFileIdentity: { device: number; inode: number; bytes: number; modifiedMs: number; changedMs: number } | null;
  blockDeviceIdentity: { device: number; inode: number; rawDevice: number } | null;
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

function flatten(nodes: LsblkNode[]): LsblkNode[] {
  return nodes.flatMap((node) => [node, ...flatten(node.children ?? [])]);
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
  const writableMounts: string[] = [];

  if (metadata.isBlockDevice()) {
    const result = await captureCommand(
      "lsblk",
      ["--json", "--bytes", "--output", "PATH,TYPE,RO,SIZE,FSTYPE,MOUNTPOINTS", resolvedSource],
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
    const selected = nodes.find((node) => node.path === resolvedSource);
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
    const sourceResolution = await resolveBlockBacking(resolvedSource);
    if (sourceResolution.networkBacked) throw new Error("network-backed block-device recovery sources are not allowed");
    sourceTopDevices = sourceResolution.devices;
    sourceLoopBackings = sourceResolution.loopBackings;
    if (!kernelReadOnly) reasons.push("kernel does not report the block device read-only");
    if (writableMounts.length > 0) reasons.push("source or a child volume has a writable mount");
  } else if (regularFileMount?.source.startsWith("/dev/") === true) {
    const sourceResolution = await resolveBlockBacking(regularFileMount.source.replace(/\[[^\]]*\]$/, ""));
    if (sourceResolution.networkBacked) throw new Error("network-backed recovery image files are not allowed");
    sourceTopDevices = sourceResolution.devices;
    sourceLoopBackings = sourceResolution.loopBackings;
  }

  const destinationInfo = await destinationBacking(destination);
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
      ? { device: metadata.dev, inode: metadata.ino, rawDevice: metadata.rdev }
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
