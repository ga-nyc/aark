import fs, { stat } from "node:fs/promises";
import { constants } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { captureCommand, WINDOWS_MOUNTVOL } from "./command.js";
import { assertStorageCapacity, type StoragePolicy } from "./storage.js";

export interface MountRecord {
  source: string;
  target: string;
  filesystem: string;
  options: string[];
}

function unescapeMount(value: string): string {
  return value.replace(/\\040/g, " ").replace(/\\011/g, "\t").replace(/\\012/g, "\n").replace(/\\134/g, "\\");
}

export function windowsMountvolToMounts(value: string): MountRecord[] {
  const records: MountRecord[] = [];
  let volume: string | undefined;
  for (const rawLine of value.split(/\r?\n/)) {
    const line = rawLine.trim();
    const volumeMatch = /^\\\\\?\\Volume\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}\\$/.exec(line);
    if (volumeMatch?.[1] !== undefined) {
      volume = volumeMatch[1].toUpperCase();
      continue;
    }
    if (volume === undefined || line === "") continue;
    if (!/^[A-Za-z]:\\(?:[^<>:"/\\|?*\x00-\x1F]+\\)*$/.test(line)) {
      // This also handles the localized form of "NO MOUNT POINTS" without
      // depending on display language or accepting a later unrelated line.
      volume = undefined;
      continue;
    }
    records.push({
      source: `windows-volume:${volume}`,
      target: `${line[0]?.toUpperCase()}${line.slice(1)}`,
      filesystem: "unknown",
      options: ["rw", "windows-local"],
    });
  }
  return records;
}

async function windowsMounts(): Promise<MountRecord[]> {
  const result = await captureCommand(WINDOWS_MOUNTVOL, [], {
    maxCaptureBytes: 256 * 1024,
    timeoutMs: 10_000,
  });
  if (result.exitCode !== 0 || result.terminationReason !== null || result.stdoutTruncated || result.stderrTruncated) {
    throw new Error("could not inventory Windows local volume mount points safely");
  }
  const records = windowsMountvolToMounts(result.stdout.toString("utf8"));
  if (records.length === 0) throw new Error("Windows volume inventory returned no usable local mount points");
  for (const record of records) {
    try {
      // mountvol lists volume-manager mount points and omits mapped network
      // drives. libuv's exact st_dev identity binds each reachable path to the
      // local volume that actually backs it without WMI or DriveInfo queries.
      const serial = (await stat(record.target, { bigint: true })).dev.toString(16).toUpperCase().padStart(8, "0");
      record.source = `${record.source}:${serial}`;
    } catch {
      // An inaccessible local drive cannot safely back a protected path. Leave
      // it marked so protected-path checks fail closed if it is selected.
      record.options.push("windows-inaccessible");
    }
  }
  return records;
}

export async function mounts(): Promise<MountRecord[]> {
  if (process.platform === "win32") return await windowsMounts();
  const records: MountRecord[] = [];
  for (const line of (await fs.readFile("/proc/self/mounts", "utf8")).split("\n")) {
    const fields = line.split(" ");
    if (fields.length < 4) continue;
    records.push({
      source: unescapeMount(fields[0] ?? ""),
      target: unescapeMount(fields[1] ?? ""),
      filesystem: fields[2] ?? "unknown",
      options: (fields[3] ?? "").split(","),
    });
  }
  return records;
}

export function mountForPathFrom(records: MountRecord[], input: string): MountRecord | undefined {
  const resolved = path.resolve(input);
  let selected: MountRecord | undefined;
  for (const record of records) {
    const target = path.resolve(record.target);
    const relative = path.relative(target, resolved);
    if (relative !== "" && (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative))) continue;
    // /proc/self/mounts is ordered by mount creation. For stacked mounts with
    // the same target, the later record is the visible topmost mount.
    if (selected === undefined || target.length >= path.resolve(selected.target).length) selected = record;
  }
  return selected;
}

export async function mountForPath(input: string): Promise<MountRecord | undefined> {
  return mountForPathFrom(await mounts(), input);
}

export function mountIsReadOnly(record: MountRecord | undefined): boolean {
  return record !== undefined && record.options.includes("ro") && !record.options.includes("rw");
}

export function assertSupportedOutputMount(record: MountRecord | undefined): void {
  if (record?.filesystem.toLowerCase() === "ntfs3") {
    throw new Error("ntfs3 output mounts are unsupported for write-intensive recovery and mining; use ntfs-3g or a native Linux filesystem");
  }
}

export function filesystemIsNetwork(record: MountRecord | undefined): boolean {
  if (record === undefined) return false;
  if (record.options.includes("windows-network")) return true;
  const filesystem = record.filesystem.toLowerCase();
  const known = new Set(["9p", "afs", "ceph", "cifs", "davfs", "glusterfs", "lustre", "nfs", "nfs4", "smb3", "virtiofs"]);
  const knownLocalFuse = new Set([
    "fuse.dislocker",
    "fuse.exfat",
    "fuse.ntfs",
    "fuse.ntfs-3g",
    "fuseblk",
  ]);
  return known.has(filesystem)
    || (filesystem === "fuse" || filesystem.startsWith("fuse.")) && !knownLocalFuse.has(filesystem)
    || record.source.startsWith("//")
    || /^\/dev\/(?:nbd|rbd|drbd)/.test(record.source);
}

export interface LsblkTransportNode {
  path?: string;
  type?: string;
  tran?: string | null;
  subsystems?: string | null;
  children?: LsblkTransportNode[];
}

export function blockTransportIsNetwork(device: string, transport?: string | null, subsystems?: string | null): boolean {
  const normalized = transport?.toLowerCase();
  const subsystemNames = new Set((subsystems ?? "").toLowerCase().split(":").filter(Boolean));
  return normalized === "iscsi"
    || normalized === "fcoe"
    || normalized === "aoe"
    || normalized === "tcp"
    || normalized === "rdma"
    || ["iscsi", "fcoe", "aoe", "nvme-fabrics", "nbd", "rbd", "drbd"].some((name) => subsystemNames.has(name))
    || /^\/dev\/(?:nbd|rbd|drbd)/.test(device);
}

export interface LoopBackingIdentity {
  device: string;
  backingFile: string;
  fileDevice: string;
  fileInode: string;
  bytes: string;
  modifiedNs: string;
  changedNs: string;
  offset: string;
  sizeLimit: string;
  mount: string;
}

export interface BlockBacking {
  devices: string[];
  networkBacked: boolean;
  loopBackings: LoopBackingIdentity[];
}

export interface BlockBackingProbe {
  canonicalDevice?: (device: string) => Promise<string>;
  topology: (device: string) => Promise<LsblkTransportNode[]>;
  loop: (device: string) => Promise<{ identity: LoopBackingIdentity; mountSource: string; networkBacked: boolean }>;
}

function loopBinding(value: Awaited<ReturnType<BlockBackingProbe["loop"]>>): string {
  return JSON.stringify({ identity: stableLoopBackingIdentity([value.identity]),
    mountSource: value.mountSource, networkBacked: value.networkBacked });
}

/** Bound every inverse-topology branch; an unknown leaf cannot prove locality. */
export async function resolveBlockBackingFrom(input: string, probe: BlockBackingProbe): Promise<BlockBacking> {
  const devices = new Set<string>();
  const loopBackings = new Map<string, LoopBackingIdentity>();
  let networkBacked = false;
  let visited = 0;
  async function resolve(device: string, ancestors: Set<string>, depth: number): Promise<void> {
    device = await probe.canonicalDevice?.(device) ?? device;
    if (depth > 16 || ancestors.has(device)) throw new Error("cyclic or excessively deep block backing topology");
    const nodes = await probe.topology(device);
    if (nodes.length === 0 || nodes.some((node) => node.path !== device)) {
      throw new Error("block topology did not return only branches of the requested device");
    }
    const next = new Set([...ancestors, device]);
    async function walk(node: LsblkTransportNode, branch: Set<string>, level: number): Promise<void> {
      visited += 1;
      if (visited > 1024 || level > 16) throw new Error("block backing topology exceeded its bounded safety limit");
      if (typeof node.path !== "string" || !node.path.startsWith("/dev/") || typeof node.type !== "string") {
        throw new Error("block backing topology contains an invalid device");
      }
      if (branch.has(node.path)) throw new Error("cyclic block backing topology");
      if (blockTransportIsNetwork(node.path, node.tran, node.subsystems)) {
        networkBacked = true;
        return;
      }
      const children = node.children ?? [];
      if (!Array.isArray(children)) throw new Error("block backing topology contains invalid parents");
      if (node.type === "disk") {
        if (children.length !== 0) throw new Error("physical disk unexpectedly has backing parents");
        devices.add(node.path);
      } else if (node.type === "loop") {
        if (children.length !== 0 || !/^\/dev\/loop[0-9]+$/.test(node.path)) throw new Error("unsupported loop backing topology");
        const before = await probe.loop(node.path);
        if (before.networkBacked) networkBacked = true;
        else {
          if (!before.mountSource.startsWith("/dev/")) throw new Error("loop backing file is not on a verifiable block filesystem");
          await resolve(before.mountSource, new Set([...next, ...branch, node.path]), level + 1);
        }
        const after = await probe.loop(node.path);
        if (loopBinding(before) !== loopBinding(after)) throw new Error("loop backing identity changed during resolution");
        const previous = loopBackings.get(node.path);
        if (previous !== undefined && stableLoopBackingIdentity([previous]) !== stableLoopBackingIdentity([before.identity])) {
          throw new Error("loop backing identity differs between topology branches");
        }
        loopBackings.set(node.path, before.identity);
      } else {
        if (children.length === 0) throw new Error("could not identify every physical device backing a protected mount");
        for (const child of children) await walk(child, new Set([...branch, node.path]), level + 1);
      }
    }
    // The requested root is checked above; detect cycles among its parents too.
    for (const node of nodes) await walk(node, new Set(ancestors), depth);
  }
  await resolve(input, new Set(), 0);
  return { devices: [...devices].sort(), networkBacked,
    loopBackings: [...loopBackings.values()].sort((a, b) => a.device.localeCompare(b.device)) };
}

async function blockTopology(source: string): Promise<LsblkTransportNode[]> {
  // --tree is required with a column list that omits NAME. KNAME avoids
  // device-mapper aliases differing from the canonical requested /dev/dm-N.
  const result = await captureCommand("lsblk", ["--inverse", "--tree", "--json", "--paths", "--output", "KNAME,TYPE,TRAN,SUBSYSTEMS", source], {
    maxCaptureBytes: 64 * 1024,
    timeoutMs: 30_000,
  });
  if (result.exitCode !== 0 || result.terminationReason !== null || result.stdoutTruncated || result.stderrTruncated) {
    throw new Error("could not resolve the physical transport backing a protected mount within its bounded safety limit");
  }
  let document: { blockdevices?: unknown };
  try {
    document = JSON.parse(result.stdout.toString("utf8")) as { blockdevices?: unknown };
  } catch (error) {
    throw new Error("lsblk returned invalid JSON while resolving a protected mount", { cause: error });
  }
  let count = 0;
  function kernelNames(values: unknown, depth: number): LsblkTransportNode[] {
    if (!Array.isArray(values) || depth > 16) throw new Error("lsblk returned invalid or excessively deep block parents");
    return values.map((value: unknown) => {
      count += 1;
      if (count > 1024 || typeof value !== "object" || value === null) throw new Error("lsblk exceeded its bounded device inventory");
      const node = value as Record<string, unknown>;
      if (typeof node.kname !== "string" || !node.kname.startsWith("/dev/") || typeof node.type !== "string"
        || (node.tran !== null && typeof node.tran !== "string") || (node.subsystems !== null && typeof node.subsystems !== "string")) {
        throw new Error("lsblk returned an incomplete kernel device identity");
      }
      return { path: node.kname, type: node.type, tran: node.tran, subsystems: node.subsystems,
        children: kernelNames(node.children ?? [], depth + 1) };
    });
  }
  return kernelNames(document.blockdevices, 0);
}

function exactLoopInteger(value: unknown): string {
  if (typeof value === "string" && /^(?:0|[1-9][0-9]*)$/.test(value)) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return String(value);
  throw new Error("loop metadata contains an inexact integer identity");
}

export function loopStatusFromJson(value: string, device: string): { file: string; inode: string; majorMinor: string; offset: string; sizeLimit: string } {
  const document = JSON.parse(value) as { loopdevices?: Array<Record<string, unknown>> };
  const row = document.loopdevices?.[0];
  if (document.loopdevices?.length !== 1 || row?.name !== device || typeof row["back-file"] !== "string"
    || typeof row["back-maj:min"] !== "string" || !/^[0-9]+:[0-9]+$/.test(row["back-maj:min"])) {
    throw new Error("loop inventory did not return one complete matching identity");
  }
  const file = row["back-file"];
  if (!path.posix.isAbsolute(file) || file.includes("\0") || file.endsWith(" (deleted)") || path.posix.resolve(file) !== file) {
    throw new Error("loop backing path is deleted, noncanonical, or inaccessible");
  }
  return { file, inode: exactLoopInteger(row["back-ino"]), majorMinor: row["back-maj:min"],
    offset: exactLoopInteger(row.offset), sizeLimit: exactLoopInteger(row.sizelimit) };
}

async function loopStatus(device: string): Promise<ReturnType<typeof loopStatusFromJson>> {
  const result = await captureCommand("losetup", ["--list", "--json", "--output", "NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT", device], {
    maxCaptureBytes: 64 * 1024, timeoutMs: 10_000,
  });
  if (result.exitCode !== 0 || result.terminationReason !== null || result.stdoutTruncated || result.stderrTruncated) {
    throw new Error("could not read loop backing identity safely");
  }
  const parsed = loopStatusFromJson(result.stdout.toString("utf8"), device);
  if (await fs.realpath(parsed.file) !== parsed.file) throw new Error("loop backing path changed from its canonical location");
  return parsed;
}

function linuxMajorMinor(device: bigint): string {
  const major = (device >> 8n & 0xfffn) | (device >> 32n & ~0xfffn);
  const minor = (device & 0xffn) | (device >> 12n & ~0xffn);
  return `${major}:${minor}`;
}

async function loopBacking(device: string): ReturnType<BlockBackingProbe["loop"]> {
  const before = await loopStatus(device);
  const handle = await fs.open(before.file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = await handle.stat({ bigint: true });
    const pathname = await fs.lstat(before.file, { bigint: true });
    if (!metadata.isFile() || metadata.nlink !== 1n || pathname.isSymbolicLink()
      || pathname.dev !== metadata.dev || pathname.ino !== metadata.ino || pathname.size !== metadata.size
      || metadata.ino.toString() !== before.inode || linuxMajorMinor(metadata.dev) !== before.majorMinor
      || BigInt(before.offset) >= metadata.size || (before.sizeLimit !== "0" && BigInt(before.sizeLimit) > metadata.size - BigInt(before.offset))) {
      throw new Error("loop backing path does not match the kernel's single-link regular backing file");
    }
    const mounted = await mountForPath(before.file);
    if (mounted === undefined) throw new Error("could not identify the mount hosting a loop backing file");
    if (mounted.source.startsWith("/dev/")) {
      const host = await fs.stat(mounted.source.replace(/\[[^\]]*\]$/, ""), { bigint: true });
      if (!host.isBlockDevice() || host.rdev !== metadata.dev) throw new Error("loop backing mount does not match its actual filesystem device");
    }
    if (JSON.stringify(before) !== JSON.stringify(await loopStatus(device))) throw new Error("loop binding changed during inspection");
    return {
      identity: { device, backingFile: before.file, fileDevice: metadata.dev.toString(), fileInode: metadata.ino.toString(),
        bytes: metadata.size.toString(), modifiedNs: metadata.mtimeNs.toString(), changedNs: metadata.ctimeNs.toString(),
        offset: before.offset, sizeLimit: before.sizeLimit,
        mount: JSON.stringify({ source: mounted.source, target: path.resolve(mounted.target),
          filesystem: mounted.filesystem.toLowerCase(), options: [...mounted.options].sort() }) },
      mountSource: mounted.source.replace(/\[[^\]]*\]$/, ""), networkBacked: filesystemIsNetwork(mounted),
    };
  } finally {
    await handle.close();
  }
}

/** Resolve file-backed loops to their actual host disks, never to a guessed disk. */
export async function resolveBlockBacking(input: string): Promise<BlockBacking> {
  return await resolveBlockBackingFrom(input, { canonicalDevice: kernelBlockDevice, topology: blockTopology, loop: loopBacking });
}

async function kernelBlockDevice(input: string): Promise<string> {
  const metadata = await fs.stat(input, { bigint: true });
  if (!metadata.isBlockDevice()) throw new Error("protected mount source is not a block device");
  // /dev/root can be a separately created block node, rather than a symlink.
  // realpath alone cannot normalize it to the KNAME reported by lsblk.
  const kernelPath = await fs.realpath(`/sys/dev/block/${linuxMajorMinor(metadata.rdev)}`);
  const name = path.basename(kernelPath);
  if (!/^[A-Za-z0-9_.!+-]+$/.test(name)) throw new Error("invalid kernel block-device name");
  const device = `/dev/${name}`;
  const canonical = await fs.stat(device, { bigint: true });
  if (!canonical.isBlockDevice() || canonical.rdev !== metadata.rdev) throw new Error("kernel block-device alias does not match its requested identity");
  return device;
}

/** Output writes legitimately change backing-file timestamps, never its binding. */
export function stableLoopBackingIdentity(backings: LoopBackingIdentity[]): string {
  return JSON.stringify(backings.map(({ modifiedNs: _modified, changedNs: _changed, ...identity }) => identity));
}

/** Bind output containers across checkpoints without changing direct-mount controls. */
export function outputLoopBinding(backing: { identity: string; loopBackings: LoopBackingIdentity[] }): string | undefined {
  return backing.loopBackings.length === 0 ? undefined : createHash("sha256").update(backing.identity).digest("hex");
}

/** A result must not write into its source image or depend on a deleted container. */
export async function assertLoopBackingsOutside(backings: LoopBackingIdentity[], protectedPaths: string[], label: string): Promise<void> {
  if (backings.length === 0) return;
  const protectedIdentities = new Set<string>();
  for (const filename of protectedPaths) {
    try {
      const metadata = await fs.lstat(filename, { bigint: true });
      protectedIdentities.add(`${metadata.dev}:${metadata.ino}`);
    } catch (error) {
      // Fixed cleanup targets may not exist; no live container can be inside
      // an absent directory. Other filesystem errors must still fail closed.
      if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
    }
  }
  if (protectedIdentities.size === 0) return;
  for (const backing of backings) {
    let cursor = backing.backingFile;
    let depth = 0;
    while (true) {
      if (++depth > 256) throw new Error("loop backing ancestry exceeded its bounded safety limit");
      const metadata = await fs.lstat(cursor, { bigint: true });
      if (metadata.isSymbolicLink()) throw new Error("loop backing ancestry changed to a symbolic link");
      if (protectedIdentities.has(`${metadata.dev}:${metadata.ino}`)) {
        throw new Error(`${label} must not contain or alias a required loop backing file`);
      }
      const parent = path.dirname(cursor);
      if (parent === cursor) break;
      cursor = parent;
    }
  }
}

/** Preserve legacy identities for direct mounts; bind file-backed mount layers. */
export async function protectedMountBacking(record: MountRecord): Promise<{ identity: string; loopBackings: LoopBackingIdentity[] }> {
  if (record.options.includes("windows-inaccessible") || filesystemIsNetwork(record)) {
    throw new Error("protected path must remain on a verifiable local mount");
  }
  const base = JSON.stringify({ source: record.source, target: path.resolve(record.target),
    filesystem: record.filesystem.toLowerCase(), options: [...record.options].sort() });
  if (!record.source.startsWith("/dev/")) return { identity: base, loopBackings: [] };
  const backing = await resolveBlockBacking(record.source.replace(/\[[^\]]*\]$/, ""));
  if (backing.networkBacked) throw new Error("protected path moved to a network block transport");
  return { identity: backing.loopBackings.length === 0 ? base : JSON.stringify({ mount: base,
    loopBackings: createHash("sha256").update(stableLoopBackingIdentity(backing.loopBackings)).digest("hex") }), loopBackings: backing.loopBackings };
}

export async function assertLoopBackingCapacity(backings: LoopBackingIdentity[], policy: StoragePolicy): Promise<void> {
  assertSupportedLoopOutputBackings(backings);
  const seen = new Set<string>();
  for (const backing of backings) {
    if (seen.has(backing.fileDevice)) continue;
    seen.add(backing.fileDevice);
    // The logical output cap belongs to the case, not to its container files.
    await assertStorageCapacity(backing.backingFile, {
      minimumFreeBytes: policy.minimumFreeBytes, minimumFreePercent: policy.minimumFreePercent,
    });
  }
}

export function assertSupportedLoopOutputBackings(backings: LoopBackingIdentity[]): void {
  for (const backing of backings) assertSupportedOutputMount(JSON.parse(backing.mount) as MountRecord);
}

export async function mountIsNetworkBacked(record: MountRecord | undefined): Promise<boolean> {
  if (record === undefined) throw new Error("could not determine the mount backing a protected path");
  if (record.options.includes("windows-inaccessible")) throw new Error("protected Windows volume identity could not be read safely");
  if (filesystemIsNetwork(record)) return true;
  if (record.options.includes("windows-local") && record.source.startsWith("windows-volume:")) return false;
  if (!record.source.startsWith("/dev/")) return false;
  return (await resolveBlockBacking(record.source.replace(/\[[^\]]*\]$/, ""))).networkBacked;
}

export function filesystemEnforcesUnixModes(record: MountRecord | undefined): boolean {
  if (record === undefined) return false;
  return new Set([
    "btrfs",
    "ext2",
    "ext3",
    "ext4",
    "f2fs",
    "jfs",
    "nilfs2",
    "reiserfs",
    "tmpfs",
    "ubifs",
    "xfs",
    "zfs",
  ]).has(record.filesystem.toLowerCase());
}
