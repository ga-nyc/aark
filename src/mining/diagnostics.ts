import path from "node:path";
import { realpath } from "node:fs/promises";
import { assertNoSymlinkComponents } from "../core/fs-safe.js";
import { mountForPath, mountIsNetworkBacked } from "../core/mounts.js";
import { loadDiagnosticInventory, loadScanState } from "./resume.js";

const KNOWN_MESSAGES = new Map([
  ["scan input ended before its frozen file size", "input-short-read"],
  ["scan input changed from its frozen file manifest snapshot", "input-snapshot-changed"],
  ["scan input path is no longer stably addressable", "input-path-unavailable"],
  ["scan input path changed or crossed a symbolic-link component", "input-path-changed"],
  ["refusing to scan a network-mounted file", "network-input-refused"],
]);
const OPERATIONS = new Set(["walk-entry", "input-root", "read-or-scan", "scan-run", "finalize",
  "input-inventory", "manifest-or-worker-start"]);
const DETECTORS = new Set(["cryptographic-keys", "configuration-secrets", "wallet-secrets",
  "provider-credentials", "structured-artifacts", "deep-key-schedules"]);

export function diagnosticErrorCode(message: string): string {
  const known = KNOWN_MESSAGES.get(message);
  if (known !== undefined) return known;
  const system = /^(ENOENT|EACCES|EPERM|EIO|ENAMETOOLONG|EMFILE|ENFILE):/.exec(message)?.[1];
  if (system !== undefined) return `system-${system.toLowerCase()}`;
  if (/^detector (?:candidate|structural-validation)(?: and (?:candidate|structural-validation))? limit reached; the bounded window may contain additional matches$/.test(message)) {
    return "detector-resource-limit";
  }
  return "unclassified-scan-error";
}

export function diagnosticOperation(operation: string): string {
  if (OPERATIONS.has(operation)) return operation;
  const match = /^(detector|artifact):(.+)$/.exec(operation);
  return match !== null && DETECTORS.has(match[2]!) ? `${match[1]}:${match[2]}` : "unclassified-operation";
}

/** Only fixed codes and aggregate counters cross the sensitive-inventory boundary. */
export async function scanDiagnostics(directory: string): Promise<Record<string, unknown>> {
  const output = path.resolve(directory);
  await assertNoSymlinkComponents(path.parse(output).root, output);
  const mounted = await mountForPath(output);
  if (await realpath(output) !== output || mounted === undefined || await mountIsNetworkBacked(mounted)) {
    throw new Error("scan diagnostics require a canonical local output directory");
  }
  const state = await loadScanState(output);
  const inventory = await loadDiagnosticInventory(output, state);
  const groups = new Map<string, {operation: string; code: string; count: number}>();
  for (const error of inventory.errors) {
    const operation = diagnosticOperation(error.operation);
    const code = diagnosticErrorCode(error.message);
    const key = `${operation}:${code}`;
    const group = groups.get(key) ?? {operation, code, count: 0};
    group.count++;
    groups.set(key, group);
  }
  return {version: 1, tool: "aark", layer: "mining-diagnostics", sourcePathsRedacted: true,
    status: state.status, resumable: false, cleanupAuthorized: false,
    filesVisited: state.progress.filesVisited, filesScanned: state.progress.filesScanned,
    filesUnsuccessful: state.progress.filesVisited - state.progress.filesScanned,
    scanErrors: inventory.errors.length + inventory.errorsOmitted,
    errorsOmitted: inventory.errorsOmitted,
    errors: [...groups.values()].sort((a, b) => a.operation.localeCompare(b.operation) || a.code.localeCompare(b.code))};
}
