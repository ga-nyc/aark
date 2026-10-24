import path from "node:path";
import { realpath } from "node:fs/promises";
import { assertNoSymlinkComponents, readJson, safeJoin } from "./fs-safe.js";
import { mountForPath, mountIsNetworkBacked } from "./mounts.js";

export const PROGRESS_FILENAME = "progress-redacted.json";
const STATUSES = new Set(["running", "in-progress", "complete", "complete-with-warnings", "complete-with-errors", "paused", "failed", "interrupted"]);
const STAGES = new Set(["image-fast-pass", "image-retry-pass", "deleted-metadata-index", "deleted-metadata-recover", "ntfs-undelete-scan", "ntfs-undelete-recover", "unallocated-stream", "signature-carving", "volume-shadow-inventory", "residual-memory-hiberfil-sys", "residual-memory-pagefile-sys", "residual-memory-swapfile-sys", "deleted-registry-cells"]);
const PHASES = new Set(["inventory", "stream", "whole-file", "finalizing"]);
const COUNTERS = ["elapsedMs", "stageElapsedMs", "stageIndex", "stagesTotal", "filesTotal", "filesVisited", "filesScanned", "bytesScanned", "uniqueFindings", "occurrences", "scanErrors"] as const;
const BYTE_COUNTERS = ["availableBytes", "totalBytes", "reservedBytes", "outputBytes", "maximumOutputBytes", "caseLogicalBytes"] as const;
const isBytes = (value: unknown): value is string => typeof value === "string" && /^(?:0|[1-9][0-9]{0,29})$/.test(value);
const isTime = (value: unknown): value is string => typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value));

/** Return only known aggregate fields, even if a local status file is edited. */
export function redactedProgress(value: unknown, layer: "recovery" | "mining"): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("invalid progress snapshot");
  const input = value as Record<string, unknown>;
  if (input.version !== 1 || input.tool !== "aark" || input.layer !== layer || input.sourcePathsRedacted !== true
    || typeof input.status !== "string" || !STATUSES.has(input.status) || !isTime(input.updatedAt)) {
    throw new Error("invalid progress snapshot header");
  }
  const result: Record<string, unknown> = { version: 1, tool: "aark", layer, sourcePathsRedacted: true,
    status: input.status, updatedAt: input.updatedAt };
  for (const key of ["startedAt", "caseLogicalBytesUpdatedAt"] as const) if (isTime(input[key])) result[key] = input[key];
  for (const key of COUNTERS) if (Number.isSafeInteger(input[key]) && (input[key] as number) >= 0) result[key] = input[key];
  for (const key of BYTE_COUNTERS) if (isBytes(input[key]) || input[key] === null) result[key] = input[key];
  if (input.currentStage === null || (typeof input.currentStage === "string" && STAGES.has(input.currentStage))) result.currentStage = input.currentStage;
  if (typeof input.phase === "string" && PHASES.has(input.phase)) result.phase = input.phase;
  if (typeof input.engineRunning === "boolean") result.engineRunning = input.engineRunning;
  if (typeof input.pauseReason === "string" && ["signal", "free-space-reserve", "output-cap"].includes(input.pauseReason)) result.pauseReason = input.pauseReason;
  if (typeof input.storageStop === "object" && input.storageStop !== null && !Array.isArray(input.storageStop)) {
    const stop = input.storageStop as Record<string, unknown>;
    if (stop.reason === "free-space-reserve" || stop.reason === "output-cap") {
      const safe: Record<string, unknown> = { reason: stop.reason };
      for (const key of ["availableBytes", "totalBytes", "reservedBytes", "outputBytes", "plannedBytes", "maximumOutputBytes"] as const) {
        if (isBytes(stop[key]) || stop[key] === null) safe[key] = stop[key];
      }
      result.storageStop = safe;
    }
  }
  if (typeof input.activity === "object" && input.activity !== null && !Array.isArray(input.activity)) {
    const activity = input.activity as Record<string, unknown>;
    const safe: Record<string, unknown> = { scope: "engine-process-only" };
    for (const key of ["readBytes", "writeBytes", "cpuTicks"] as const) if (isBytes(activity[key]) || activity[key] === null) safe[key] = activity[key];
    if (typeof activity.observedSinceLastSample === "boolean" || activity.observedSinceLastSample === null) safe.observedSinceLastSample = activity.observedSinceLastSample;
    result.activity = safe;
  }
  if (typeof input.nextStageCapacity === "object" && input.nextStageCapacity !== null && !Array.isArray(input.nextStageCapacity)) {
    const capacity = input.nextStageCapacity as Record<string, unknown>;
    const safe: Record<string, unknown> = {};
    for (const key of ["additionalLogicalBytes", "additionalAllocationRoundedBytes"] as const) if (isBytes(capacity[key]) || capacity[key] === null) safe[key] = capacity[key];
    for (const key of ["fitsFreeSpace", "fitsOutputCap"] as const) if (typeof capacity[key] === "boolean" || capacity[key] === null) safe[key] = capacity[key];
    result.nextStageCapacity = safe;
  }
  return result;
}

export async function readProgress(directory: string, layer: "recovery" | "mining"): Promise<Record<string, unknown>> {
  const root = path.resolve(directory);
  await assertNoSymlinkComponents(path.parse(root).root, root);
  if (await realpath(root) !== root || await mountIsNetworkBacked(await mountForPath(root))) {
    throw new Error("progress must be read from a canonical local directory");
  }
  return redactedProgress(await readJson(safeJoin(root, PROGRESS_FILENAME), 64 * 1024), layer);
}
