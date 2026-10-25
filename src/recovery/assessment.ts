import { lstat, statfs } from "node:fs/promises";
import path from "node:path";
import { captureCommand, commandExists } from "../core/command.js";
import { nearestExistingParent } from "../core/fs-safe.js";
import { assertSupportedOutputMount, mountForPath } from "../core/mounts.js";
import { StorageQuotaError, storageCapacity, storagePolicyFromGiB } from "../core/storage.js";
import type { StorageCapacity } from "../core/storage.js";
import { inspectSourceSafety } from "./source-safety.js";
import type { RecoveryConfig, RecoveryStep } from "./types.js";
import { assessReusedUnallocatedStream } from "./reuse-unallocated.js";

export interface CapacityFacts {
  sourceBytes: bigint;
  unallocatedBytes: bigint | null;
  allocationUnitBytes: bigint;
  capacity: StorageCapacity;
  maximumOutputBytes?: bigint;
}

export interface OutputEstimate {
  stage: string;
  logicalBytes: string | null;
  allocationRoundedBytes: string | null;
}

export interface StageByteEstimate {
  logicalBytes: bigint | null;
  allocationBytes: bigint | null;
}

export function stageCapacityForecast(
  additionalBytes: bigint | null, capacity: StorageCapacity, allocationUnitBytes: bigint,
  caseLogicalBytes: bigint | null, maximumOutputBytes?: bigint,
  additionalAllocationBytes: bigint | null = additionalBytes,
): Record<string, unknown> {
  const physical = additionalAllocationBytes === null ? null : rounded(additionalAllocationBytes, allocationUnitBytes);
  return {
    additionalLogicalBytes: additionalBytes?.toString() ?? null,
    additionalAllocationRoundedBytes: physical?.toString() ?? null,
    fitsFreeSpace: physical === null ? null : capacity.availableBytes - physical >= capacity.reservedBytes,
    fitsOutputCap: additionalBytes === null || (maximumOutputBytes !== undefined && caseLogicalBytes === null)
      ? null : maximumOutputBytes === undefined || (caseLogicalBytes ?? 0n) + additionalBytes <= maximumOutputBytes,
  };
}

export function assertStageMinimumCapacity(
  additionalBytes: bigint | null, capacity: StorageCapacity, allocationUnitBytes: bigint,
  caseLogicalBytes: bigint | null, maximumOutputBytes?: bigint,
  additionalAllocationBytes: bigint | null = additionalBytes,
): void {
  const forecast = stageCapacityForecast(additionalBytes, capacity, allocationUnitBytes, caseLogicalBytes, maximumOutputBytes, additionalAllocationBytes);
  if (forecast.fitsFreeSpace === false && additionalAllocationBytes !== null) {
    throw new StorageQuotaError("free-space-reserve", { ...capacity, plannedBytes: rounded(additionalAllocationBytes, allocationUnitBytes) });
  }
  if (forecast.fitsOutputCap === false && additionalBytes !== null) {
    throw new StorageQuotaError("output-cap", { ...capacity, outputBytes: caseLogicalBytes ?? 0n, plannedBytes: additionalBytes });
  }
}

function rounded(bytes: bigint, unit: bigint): bigint {
  if (bytes < 0n || unit < 1n) throw new Error("invalid storage estimate facts");
  return (bytes + unit - 1n) / unit * unit;
}

/** Extract numeric fields only. The probe's labels and other output stay local. */
export function parseNtfsUnallocatedBytes(output: string, sourceBytes: bigint): bigint | null {
  const field = (name: string): bigint | null => {
    const matches = [...output.matchAll(new RegExp(`^\\s*${name}:\\s*([0-9]+)(?:\\s|$)`, "gm"))];
    return matches.length === 1 && matches[0]?.[1] !== undefined ? BigInt(matches[0][1]) : null;
  };
  const unit = field("Cluster Size");
  const clusters = field("Volume Size in Clusters");
  const free = field("Free Clusters");
  if (unit === null || clusters === null || free === null || unit < 512n || unit > 2n ** 21n
    || (unit & (unit - 1n)) !== 0n || clusters < 1n || free > clusters
    || clusters * unit > sourceBytes || sourceBytes < 0n) return null;
  return free * unit;
}

export async function probeUnallocatedBytes(source: string, sourceBytes: bigint, sectorOffset: number): Promise<bigint | null> {
  // ntfsinfo accepts a directly addressable volume/image, not a disk offset.
  // Missing tools, other filesystems, dirty-volume refusals, and timeouts are
  // unknown estimates, never a fabricated zero or an invitation to force access.
  if (sectorOffset !== 0 || !(await commandExists("ntfsinfo"))) return null;
  try {
    const result = await captureCommand("ntfsinfo", ["--mft", source], { timeoutMs: 10_000, maxCaptureBytes: 64 * 1024 });
    if (result.exitCode !== 0 || result.terminationReason !== null || result.stdoutTruncated) return null;
    return parseNtfsUnallocatedBytes(result.stdout.toString("utf8"), sourceBytes);
  } catch { return null; }
}

export function storageAssessment(config: RecoveryConfig, facts: CapacityFacts): Record<string, unknown> {
  if (facts.sourceBytes < 0n) throw new Error("invalid source size for storage assessment");
  const estimates: OutputEstimate[] = [];
  const add = (stage: string, bytes: bigint | null): void => {
    estimates.push({ stage, logicalBytes: bytes?.toString() ?? null,
      allocationRoundedBytes: bytes === null ? null : rounded(bytes, facts.allocationUnitBytes).toString() });
  };
  if (config.image.enabled) add("image", facts.sourceBytes);
  if (config.stages.deletedMetadata) add("deleted-metadata", null);
  if (config.stages.ntfsUndelete) add("ntfs-undelete", null);
  if (config.stages.unallocatedStream) add("unallocated-stream", facts.unallocatedBytes);
  if (config.stages.signatureCarving) add("signature-carving", null);
  if (config.stages.volumeShadows) add("volume-shadows", null);
  if (config.stages.residualMemory) add("residual-memory", null);
  if (config.stages.deletedRegistryCells) add("deleted-registry-cells", null);
  const logical = estimates.reduce((sum, e) => sum + BigInt(e.logicalBytes ?? "0"), 0n);
  const physical = estimates.reduce((sum, e) => sum + BigInt(e.allocationRoundedBytes ?? "0"), 0n);
  const spendable = facts.capacity.availableBytes > facts.capacity.reservedBytes
    ? facts.capacity.availableBytes - facts.capacity.reservedBytes : 0n;
  const exceedsCap = facts.maximumOutputBytes !== undefined && logical > facts.maximumOutputBytes;
  const knownMinimumFits = physical <= spendable && !exceedsCap
    && facts.capacity.availableBytes >= facts.capacity.reservedBytes;
  return {
    version: 1, tool: "aark", layer: "recovery", sourcePathsRedacted: true, generatedAt: new Date().toISOString(),
    assessmentScope: "new-bulk-outputs", status: knownMinimumFits ? "uncertain-total" : "insufficient-for-known-outputs",
    knownMinimumFits, fullWorkflowFits: "unknown", sourceBytes: facts.sourceBytes.toString(),
    availableBytes: facts.capacity.availableBytes.toString(), totalBytes: facts.capacity.totalBytes.toString(),
    reservedBytes: facts.capacity.reservedBytes.toString(), spendableBytes: spendable.toString(),
    allocationUnitBytes: facts.allocationUnitBytes.toString(),
    knownLogicalBytes: logical.toString(), knownAllocationRoundedBytes: physical.toString(),
    maximumOutputBytes: facts.maximumOutputBytes?.toString() ?? null,
    knownMinimumExceedsOutputCap: exceedsCap, estimates,
    unknownOutputStages: estimates.filter((e) => e.logicalBytes === null).map((e) => e.stage),
    warnings: [
      "Known outputs are a minimum, not a prediction that the complete workflow will fit.",
      "Images, unallocated streams, and multiple recovery outputs can coexist and duplicate content.",
      "Carving, recovered-file counts, logs, and filesystem metadata have no reliable size bound here.",
      "The logical case cap does not bound physical allocation; small files can consume entire allocation units.",
      "This assessment does not authorize execution, change reserves, or make interrupted engines resumable.",
    ],
  };
}

export async function assessRecoveryStorage(config: RecoveryConfig): Promise<Record<string, unknown>> {
  if (process.platform !== "linux") throw new Error("recovery storage assessment requires Linux");
  const reused = config.unallocatedStreamFromCase === undefined ? undefined : await assessReusedUnallocatedStream(config);
  const existing = await nearestExistingParent(config.destination);
  assertSupportedOutputMount(await mountForPath(existing));
  const source = await inspectSourceSafety(config.source, config.destination);
  const relativeSource = path.relative(path.resolve(config.destination), source.resolvedSource);
  if (relativeSource === "" || (relativeSource !== ".." && !relativeSource.startsWith(`..${path.sep}`) && !path.isAbsolute(relativeSource))) {
    throw new Error("the canonical source is inside its planned recovery destination");
  }
  if (source.destinationOnSourceDevice || source.destinationBackingKind === "network"
    || source.destinationBackingKind === "unresolved"
    || (source.kind === "block-device" && (!source.deviceComparisonCertain
      || (config.requireReadOnlySource && (!source.kernelReadOnly || source.writableMounts.length > 0))))) {
    throw new Error("source or destination failed storage-assessment safety checks");
  }
  if (!Number.isSafeInteger(source.bytes) || source.bytes < 0) throw new Error("source size cannot be represented safely");
  const policy = storagePolicyFromGiB(config.storage?.minFreeGiB, config.storage?.minFreePercent, config.storage?.maxOutputGiB);
  const sourceBytes = BigInt(source.bytes);
  // An explicitly different analysis view may have a different layout/size.
  // Do not silently apply the primary source's free-space map to that view.
  const unallocatedBytes = config.stages.unallocatedStream
    && (config.analysisSource === undefined || path.resolve(config.analysisSource) === path.resolve(config.source))
    ? await probeUnallocatedBytes(source.resolvedSource, sourceBytes, config.sectorOffset) : null;
  const current = await inspectSourceSafety(config.source, config.destination);
  if (current.resolvedSource !== source.resolvedSource || current.bytes !== source.bytes
    || JSON.stringify(current.regularFileIdentity) !== JSON.stringify(source.regularFileIdentity)
    || JSON.stringify(current.blockDeviceIdentity) !== JSON.stringify(source.blockDeviceIdentity)
    || current.kernelReadOnly !== source.kernelReadOnly || current.destinationFilesystemDevice !== source.destinationFilesystemDevice
    || current.destinationBackingKind !== source.destinationBackingKind
    || (current.kind === "block-device" && (!current.deviceComparisonCertain
      || (config.requireReadOnlySource && current.writableMounts.length > 0)))) {
    throw new Error("source or destination changed during storage assessment");
  }
  const [capacity, filesystem] = await Promise.all([storageCapacity(existing, policy), statfs(existing, { bigint: true })]);
  return { ...storageAssessment(config, { sourceBytes, unallocatedBytes, allocationUnitBytes: filesystem.bsize,
    capacity, ...(policy.maximumOutputBytes === undefined ? {} : { maximumOutputBytes: policy.maximumOutputBytes }) }),
    ...(reused === undefined ? {} : { reusedUnallocatedStream: reused }) };
}

/** Forecast only known bulk writes; unknown engine output remains explicit. */
export async function estimateStageBytes(
  step: RecoveryStep, sourceBytes: number, analysisSource: string, sectorOffset: number,
): Promise<StageByteEstimate> {
  const unknown = { logicalBytes: null, allocationBytes: null };
  if (!Number.isSafeInteger(sourceBytes) || sourceBytes < 0) return unknown;
  if (step.id === "image-fast-pass") {
    let existingLogical = 0n;
    let existingAllocated = 0n;
    try {
      const filename = step.outputs[0];
      if (filename !== undefined) {
        const info = await lstat(filename, { bigint: true });
        if (info.isFile() && !info.isSymbolicLink()) {
          existingLogical = info.size;
          existingAllocated = info.blocks * 512n;
        }
      }
    } catch (error) {
      if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
    }
    const total = BigInt(sourceBytes);
    // Filling holes consumes free space without extending the logical file.
    return {
      logicalBytes: total > existingLogical ? total - existingLogical : 0n,
      allocationBytes: total > existingAllocated ? total - existingAllocated : 0n,
    };
  }
  if (step.id === "unallocated-stream") {
    let bytes = BigInt(sourceBytes);
    try {
      const info = await lstat(analysisSource, { bigint: true });
      if (info.isFile() && !info.isSymbolicLink()) bytes = info.size;
    } catch { return unknown; }
    const unallocated = await probeUnallocatedBytes(analysisSource, bytes, sectorOffset);
    return { logicalBytes: unallocated, allocationBytes: unallocated };
  }
  return unknown;
}
