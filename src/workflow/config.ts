import path from "node:path";
import { availableParallelism } from "node:os";
import { readJson } from "../core/fs-safe.js";
import { storagePolicyFromGiB } from "../core/storage.js";
import type { Provenance } from "../core/types.js";
import { MAX_INPUT_ROOTS } from "../mining/limits.js";
import { loadRecoveryConfig } from "../recovery/config.js";
import type { RecoveryConfig, RecoveryStorageConfig } from "../recovery/types.js";

export const MAX_WORKFLOW_JOBS = 128;
export const MAX_WORKFLOW_CONFIG_BYTES = 1024 * 1024;
const PROVENANCE = new Set<Provenance>(["deleted-metadata", "unallocated-carve", "unallocated-stream", "shadow-copy", "residual-memory", "allocated-reference", "unknown"]);

export interface WorkflowScan {
  inputs: string[];
  provenance: Provenance;
}

export interface WorkflowConfig {
  version: 1;
  execute: boolean;
  output: string;
  recovery?: RecoveryConfig;
  scans: WorkflowScan[];
  mining: {
    workers: number;
    chunkMiB: number;
    overlapMiB: number;
    wholeFileMiB: number;
    cryptoOnly: boolean;
    deepKeySchedules: boolean;
    storage: RecoveryStorageConfig;
  };
  finalizationStorage: RecoveryStorageConfig;
}

function object(value: unknown, keys: string[], label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)
    || Object.keys(value).some(key => !keys.includes(key))) throw new Error(`invalid ${label} fields`);
  return value as Record<string, unknown>;
}

function location(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value) > 4096 || /[\u0000-\u001f\u007f]/.test(value)
    || !path.isAbsolute(value) || path.resolve(value) !== value) throw new Error("workflow paths must be canonical absolute paths");
  return value;
}

function integer(value: unknown, fallback: number, minimum: number, maximum: number): number {
  const result = value === undefined ? fallback : value;
  if (typeof result !== "number" || !Number.isSafeInteger(result) || result < minimum || result > maximum) {
    throw new Error("workflow numeric option is outside its supported range");
  }
  return result;
}

function boolean(value: unknown, fallback = false): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new Error("workflow boolean option must be a JSON boolean");
  return value;
}

function storage(value: unknown): RecoveryStorageConfig {
  const input = object(value ?? {}, ["minFreeGiB", "minFreePercent", "maxOutputGiB"], "workflow storage");
  const minFreeGiB = input.minFreeGiB ?? 5;
  const minFreePercent = input.minFreePercent ?? 5;
  if (typeof minFreeGiB !== "number" || typeof minFreePercent !== "number"
    || (input.maxOutputGiB !== undefined && typeof input.maxOutputGiB !== "number")) throw new Error("invalid workflow storage numbers");
  storagePolicyFromGiB(minFreeGiB, minFreePercent, input.maxOutputGiB);
  return {minFreeGiB, minFreePercent, ...(input.maxOutputGiB === undefined ? {} : {maxOutputGiB: input.maxOutputGiB})};
}

export function overlaps(left: string, right: string): boolean {
  const a = process.platform === "win32" ? left.toLowerCase() : left;
  const b = process.platform === "win32" ? right.toLowerCase() : right;
  const relative = path.relative(a, b);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

export async function loadWorkflowConfig(filename: string): Promise<WorkflowConfig> {
  const input = object(await readJson(filename, MAX_WORKFLOW_CONFIG_BYTES),
    ["version", "execute", "output", "recoveryConfig", "scans", "mining", "finalizationStorage"], "workflow configuration");
  if (input.version !== 1) throw new Error("unsupported workflow configuration version");
  const output = location(input.output);
  if (!Array.isArray(input.scans) || input.scans.length < 1 || input.scans.length > MAX_WORKFLOW_JOBS) {
    throw new Error(`workflow requires 1 through ${MAX_WORKFLOW_JOBS} explicitly selected scans`);
  }
  const scans = input.scans.map(value => {
    const scan = object(value, ["inputs", "provenance"], "workflow scan");
    if (!Array.isArray(scan.inputs) || scan.inputs.length < 1 || scan.inputs.length > MAX_INPUT_ROOTS
      || !PROVENANCE.has(scan.provenance as Provenance)) throw new Error("invalid workflow scan selection");
    const inputs = scan.inputs.map(location);
    if (new Set(inputs).size !== inputs.length || inputs.some(root => overlaps(root, output) || overlaps(output, root))) {
      throw new Error("workflow inputs and output must be distinct non-overlapping paths");
    }
    return {inputs, provenance: scan.provenance as Provenance};
  });
  const mining = object(input.mining ?? {}, ["workers", "chunkMiB", "overlapMiB", "wholeFileMiB", "cryptoOnly", "deepKeySchedules", "storage"], "workflow mining");
  const chunkMiB = integer(mining.chunkMiB, 32, 17, 128);
  const cryptoOnly = boolean(mining.cryptoOnly);
  const deepKeySchedules = boolean(mining.deepKeySchedules);
  if (cryptoOnly && deepKeySchedules) throw new Error("crypto-only and deep-key-schedules are mutually exclusive");
  const recovery = input.recoveryConfig === undefined ? undefined : await loadRecoveryConfig(location(input.recoveryConfig));
  if (recovery !== undefined && (overlaps(recovery.destination, output) || overlaps(output, recovery.destination)
    || overlaps(output, recovery.source) || overlaps(recovery.source, output))) throw new Error("workflow output overlaps the recovery case or source");
  if (recovery !== undefined && [recovery.analysisSource, recovery.mountedReadOnlyRoot, recovery.unallocatedStreamFromCase]
    .some(source => source !== undefined && (overlaps(output, source) || overlaps(source, output)))) {
    throw new Error("workflow output overlaps a recovery input");
  }
  return {version: 1, execute: boolean(input.execute), output, ...(recovery === undefined ? {} : {recovery}), scans,
    mining: {workers: integer(mining.workers, Math.min(4, Math.max(1, availableParallelism() - 1)), 1, 4), chunkMiB, overlapMiB: integer(mining.overlapMiB, 17, 17, chunkMiB),
      wholeFileMiB: integer(mining.wholeFileMiB, 64, 1, 256), cryptoOnly, deepKeySchedules, storage: storage(mining.storage)},
    finalizationStorage: storage(input.finalizationStorage)};
}
