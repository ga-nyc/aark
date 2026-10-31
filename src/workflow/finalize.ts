import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open } from "node:fs/promises";
import path from "node:path";
import { atomicWriteFile, ensurePrivateDirectory, stableHandleStat } from "../core/fs-safe.js";
import { StorageBudget, storagePolicyFromGiB } from "../core/storage.js";
import { MAX_RECORDED_OCCURRENCES, MAX_SENSITIVE_INVENTORY_BYTES, MAX_UNIQUE_FINDINGS } from "../mining/limits.js";
import type { SensitiveFinding } from "../mining/types.js";
import type { WorkflowConfig } from "./config.js";
import { fileDigest, interrupted, miningDirectory, outputIdentity, verifyScan } from "./verify.js";

interface PackagedFinding {
  category: string;
  fingerprint: string;
  confidence: string;
  artifacts: Array<{path: string; bytes: number; sha256: string}>;
  scans: number[];
}

export async function finalizeWorkflow(config: WorkflowConfig, attempt: number,
  guard: () => Promise<void>, progress: (verified: number) => Promise<void>, signal?: AbortSignal,
  fileProgress?: (files: number) => void): Promise<Record<string, unknown>> {
  const root = path.join(config.output, `finalization-${String(attempt).padStart(6, "0")}`);
  await guard();
  await mkdir(root, {mode: 0o700}); // A partial attempt is retained; never overwritten on resume.
  await ensurePrivateDirectory(root);
  const expectedRoot = await outputIdentity(root, config.finalizationStorage);
  const budget = new StorageBudget(root, storagePolicyFromGiB(config.finalizationStorage.minFreeGiB,
    config.finalizationStorage.minFreePercent, config.finalizationStorage.maxOutputGiB), 0n);
  const safe = async () => {
    interrupted(signal); await guard();
    if (await outputIdentity(root, config.finalizationStorage) !== expectedRoot) throw new Error("workflow finalization directory changed");
  };
  const writeJson = async (filename: string, value: unknown) => {
    const data = JSON.stringify(value, null, 2) + "\n";
    const bytes = Buffer.byteLength(data);
    if (bytes > MAX_SENSITIVE_INVENTORY_BYTES) throw new Error("workflow final inventory exceeded its bounded limit");
    await safe(); await budget.beforeWrite(BigInt(bytes));
    await atomicWriteFile(filename, data);
    budget.committedWrite(BigInt(bytes)); await safe();
  };
  const copy = async (source: string, target: string, expected: {bytes: number; sha256: string}) => {
    const input = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW);
    let output: Awaited<ReturnType<typeof open>> | undefined;
    try {
      const before = await stableHandleStat(input);
      if (!before.raw.isFile() || before.raw.nlink !== 1n || before.bytes !== expected.bytes) throw new Error("workflow artifact changed before copying");
      await safe();
      output = await open(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, expected.bytes + 1));
      const hash = createHash("sha256");
      let offset = 0;
      while (offset < expected.bytes) {
        await safe();
        const {bytesRead} = await input.read(buffer, 0, Math.min(buffer.length, expected.bytes - offset), offset);
        if (bytesRead === 0) throw new Error("workflow artifact ended before its recorded size");
        await budget.beforeWrite(BigInt(bytesRead));
        let written = 0;
        while (written < bytesRead) {
          const result = await output.write(buffer, written, bytesRead - written, offset + written);
          if (result.bytesWritten === 0) throw new Error("workflow artifact copy made no progress");
          written += result.bytesWritten;
        }
        hash.update(buffer.subarray(0, bytesRead));
        offset += bytesRead; budget.committedWrite(BigInt(bytesRead));
      }
      if (hash.digest("hex") !== expected.sha256) throw new Error("workflow artifact hash changed during copying");
      await output.sync(); await output.close(); output = undefined;
      const actual = await fileDigest(target, 256 * 1024 ** 2, signal);
      if (actual.bytes !== expected.bytes || actual.sha256 !== expected.sha256) throw new Error("workflow copied artifact failed integrity verification");
      const sourceNow = await fileDigest(source, 256 * 1024 ** 2, signal);
      if (sourceNow.bytes !== expected.bytes || sourceNow.sha256 !== expected.sha256) throw new Error("workflow source artifact changed after copying");
    } finally { await output?.close(); await input.close(); }
  };
  const unique = new Map<string, PackagedFinding>();
  const artifacts = new Map<string, {path: string; bytes: number; sha256: string}>();
  let references = 0, filesScanned = 0, bytesScanned = 0, findingsAcrossScans = 0;
  const add = async (finding: SensitiveFinding, index: number) => {
    const key = finding.category + ":" + finding.sha256;
    let entry = unique.get(key);
    if (entry === undefined) {
      if (unique.size >= MAX_UNIQUE_FINDINGS) throw new Error("workflow distinct-finding limit reached; use smaller independent workflows");
      entry = {category: finding.category, fingerprint: finding.sha256, confidence: finding.confidence, artifacts: [], scans: []};
      unique.set(key, entry);
    }
    if (++references > MAX_RECORDED_OCCURRENCES) throw new Error("workflow finding-reference limit reached");
    entry.scans.push(index + 1);
    for (const artifact of finding.artifactIntegrity) {
      const identity = artifact.sha256 + ":" + artifact.bytes;
      let exported = artifacts.get(identity);
      if (exported === undefined) {
        const extension = path.extname(artifact.path);
        const basename = `artifact-${String(artifacts.size + 1).padStart(6, "0")}${/^\.[a-zA-Z0-9]{1,12}$/.test(extension) ? extension : ".bin"}`;
        await copy(path.join(miningDirectory(config, index), artifact.path), path.join(root, basename), artifact);
        exported = {path: basename, bytes: artifact.bytes, sha256: artifact.sha256}; artifacts.set(identity, exported);
      }
      if (!entry.artifacts.some(value => value.path === exported.path)) entry.artifacts.push(exported);
    }
  };
  for (let index = 0; index < config.scans.length; index++) {
    await safe();
    const scan = config.scans[index];
    if (scan === undefined) throw new Error("missing workflow scan");
    const result = await verifyScan(config, scan, index, signal, count => fileProgress?.(filesScanned + count));
    filesScanned += result.state.progress.filesScanned;
    bytesScanned += result.state.progress.bytesScanned;
    findingsAcrossScans += result.inventory.findings.length;
    if (!Number.isSafeInteger(filesScanned) || !Number.isSafeInteger(bytesScanned)) throw new Error("workflow aggregate exceeded safe numeric limits");
    for (const finding of result.inventory.findings) await add(finding, index);
    await progress(index + 1);
  }
  await writeJson(path.join(root, "index-sensitive.json"), {version: 1, tool: "aark", layer: "workflow-findings", status: "complete",
    findingIdentity: "category-and-content-fingerprint", originalSourcesAndMiningOutputsRetained: true,
    scans: config.scans.map((_, index) => ({number: index + 1, output: miningDirectory(config, index)})), findings: [...unique.values()]});
  const categories: Record<string, number> = {};
  for (const entry of unique.values()) categories[entry.category] = (categories[entry.category] ?? 0) + 1;
  const summary = {version: 1, tool: "aark", layer: "workflow-finalization", status: "complete", sourcePathsRedacted: true,
    finishedAt: new Date().toISOString(), scansVerified: config.scans.length, filesScanned, bytesScanned,
    scanCountsMayOverlap: true, findingsAcrossScans, distinctFindingFingerprints: unique.size,
    findingIdentity: "category-and-content-fingerprint; not a count of accounts or independently usable keys",
    artifactFilesVerified: artifacts.size, categories, originalSourcesAndMiningOutputsRetained: true,
    cleanupAuthorized: false, packageDirectory: path.basename(root)};
  await writeJson(path.join(root, "manifest-redacted.json"), summary);
  await safe();
  return summary;
}
