import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rm, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test, {type TestContext} from "node:test";
import { quotaResumeReady, type CapacityProbes } from "../case/capacity.js";
import { digest } from "../case/config.js";
import type { PreparedAttempt } from "../case/types.js";
import { captureCommand } from "../core/command.js";
import type { LoopBackingIdentity } from "../core/mounts.js";
import { StorageQuotaError, type StoragePolicy } from "../core/storage.js";
import type { ScanState } from "../mining/resume.js";
import { loadWorkflowConfig } from "../workflow/config.js";
import { mkdtemp } from "./helpers.js";

const GiB = 1024n ** 3n;
async function fixture(context: TestContext, mining = false) {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-capacity-test-"));
  context.after(() => rm(root, {recursive: true, force: true}));
  const input = path.join(root, "synthetic-input");
  const output = path.join(root, "workflow");
  await mkdir(input); await mkdir(output);
  const configFile = path.join(root, "workflow.json");
  await writeFile(configFile, JSON.stringify({version: 1, execute: true, output,
    scans: [{inputs: [input], provenance: "unknown"}], mining: {workers: 1, storage: {minFreeGiB: 2, minFreePercent: 20, maxOutputGiB: 1}},
    finalizationStorage: {minFreeGiB: 1, minFreePercent: 10, maxOutputGiB: 1}}));
  const workflow = await loadWorkflowConfig(configFile);
  const attempt: PreparedAttempt = {configFile, configHash: digest(workflow), workflow};
  const state: Record<string, unknown> = {version: 1, tool: "aark", layer: "workflow", status: "paused",
    phase: mining ? "mining" : "packaging", configFile, config: workflow, outputIdentity: "synthetic-binding", pauseReason: "free-space-reserve",
    ...(mining ? {pausedScan: 0} : {})};
  const statePath = path.join(output, "workflow-state-sensitive.json");
  const checkpointPath = path.join(output, "workflow-checkpoint-redacted.json");
  const seal = async () => {
    const bytes = JSON.stringify(state) + "\n";
    await writeFile(statePath, bytes);
    await writeFile(checkpointPath, JSON.stringify({version: 1, status: state.status,
      stateSha256: createHash("sha256").update(bytes).digest("hex")}));
  };
  await seal();
  const scanOutput = path.join(output, "mining", "scan-000001");
  let scan: ScanState | undefined;
  if (mining) {
    await mkdir(scanOutput, {recursive: true});
    scan = {version: 1, tool: "aark", layer: "mining-resume", runId: randomUUID(), status: "paused", resumable: true,
      inventoryComplete: true, pauseReason: "free-space-reserve", startedAt: "2030-01-01T00:00:00.000Z", updatedAt: "2030-01-01T00:00:00.000Z",
      semantic: {inputs: [input], output: scanOutput, provenance: "unknown", chunkBytes: workflow.mining.chunkMiB * 1024 ** 2,
        overlapBytes: workflow.mining.overlapMiB * 1024 ** 2, wholeFileBytes: workflow.mining.wholeFileMiB * 1024 ** 2,
        deepKeySchedules: false, cryptoOnly: false},
      operational: {workers: 1, minimumFreeGiB: 2, minimumFreePercent: 20, maximumOutputGiB: 1},
      inputRoots: [{path: input, device: 1, inode: 1, kind: "directory", mount: "synthetic-mount"}],
      manifest: {filename: "scan-files-sensitive.ndjson", entries: 0, bytes: 0, sha256: "a".repeat(64)},
      inventory: {filename: "inventory-sensitive.json", bytes: 0, sha256: "b".repeat(64)},
      cursor: {fileIndex: 0, phase: "stream", nextOffset: 0},
      progress: {filesTotal: 0, filesVisited: 0, filesScanned: 0, bytesScanned: 0, uniqueFindings: 0, occurrences: 0, scanErrors: 0}};
    await writeFile(path.join(scanOutput, "scan-state-sensitive.json"), JSON.stringify(scan));
  }
  const calls: Array<{target: string; policy: StoragePolicy; planned: bigint}> = [];
  const free = new Map<string, bigint>();
  const hosts = new Map<string, LoopBackingIdentity[]>();
  const probes: CapacityProbes = {
    outputIdentity: async () => "synthetic-binding",
    loopBackings: async directory => hosts.get(directory) ?? [],
    assertStorageCapacity: async (target, policy, outputBytes = 0n, planned = 0n) => {
      calls.push({target, policy, planned});
      const total = 100n * GiB;
      const percentage = total * BigInt(Math.round(policy.minimumFreePercent * 100)) / 10_000n;
      const reserved = percentage > policy.minimumFreeBytes ? percentage : policy.minimumFreeBytes;
      const available = free.get(target) ?? 50n * GiB;
      if (available - planned < reserved) throw new StorageQuotaError("free-space-reserve",
        {availableBytes: available, totalBytes: total, reservedBytes: reserved, outputBytes, plannedBytes: planned});
      return {availableBytes: available, totalBytes: total, reservedBytes: reserved, outputBytes, plannedBytes: planned};
    },
  };
  return {root, input, output, configFile, attempt, state, statePath, checkpointPath, scanOutput, scan, seal, probes, calls, free, hosts};
}

test("quota readiness requires physical headroom beyond the native reserve", async context => {
  const f = await fixture(context);
  f.free.set(f.output, 10n * GiB);
  assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
  f.free.set(f.output, 10n * GiB + 1n);
  assert.equal(await quotaResumeReady(f.attempt, f.probes), true);
  assert.ok(f.calls.every(call => call.planned === 1n));
});

test("quota readiness checks the paused mining reserve and every loop host", async context => {
  const f = await fixture(context, true);
  f.free.set(f.scanOutput, 20n * GiB);
  assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
  f.free.set(f.scanOutput, 50n * GiB);
  const host = path.join(f.root, "synthetic-loop-host");
  f.hosts.set(f.scanOutput, [{device: "/dev/loop-fixture", backingFile: host, fileDevice: "1", fileInode: "1", bytes: "1",
    modifiedNs: "1", changedNs: "1", offset: "0", sizeLimit: "0", mount: "{}"}]);
  f.free.set(host, 20n * GiB);
  assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
  f.free.set(host, 20n * GiB + 1n);
  assert.equal(await quotaResumeReady(f.attempt, f.probes), true);
  assert.ok(f.calls.some(call => call.target === f.output));
  assert.ok(f.calls.some(call => call.target === f.scanOutput));
  assert.ok(f.calls.filter(call => call.target === host).every(call => call.policy.maximumOutputBytes === undefined));
});

test("signal and output-cap pauses never become automatic physical-space resumes", async context => {
  const f = await fixture(context);
  for (const pauseReason of ["signal", "output-cap"]) {
    f.state.pauseReason = pauseReason; await f.seal();
    assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
  }
  assert.equal(f.calls.length, 0);
});

test("mining readiness requires a matching clean paused native checkpoint", async context => {
  const f = await fixture(context, true);
  f.scan!.pauseReason = "signal";
  await writeFile(path.join(f.scanOutput, "scan-state-sensitive.json"), JSON.stringify(f.scan));
  assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
  f.scan!.pauseReason = "free-space-reserve";
  f.scan!.semantic.cryptoOnly = true;
  await writeFile(path.join(f.scanOutput, "scan-state-sensitive.json"), JSON.stringify(f.scan));
  assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
});

test("unavailable capacity and changed sealed controls remain not ready", async context => {
  const f = await fixture(context);
  const unavailable: CapacityProbes = {...f.probes, outputIdentity: async () => { throw new Error("private synthetic mount failure"); }};
  assert.equal(await quotaResumeReady(f.attempt, unavailable), false);
  const mutate: CapacityProbes = {...f.probes, assertStorageCapacity: async (...args) => {
    await writeFile(f.statePath, (await readFile(f.statePath, "utf8")) + " ");
    return await f.probes.assertStorageCapacity!(...args);
  }};
  assert.equal(await quotaResumeReady(f.attempt, mutate), false);
  await f.seal();
  await writeFile(f.configFile, "invalid changed plan\n");
  assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
});

test("capacity CLI reports unknown metadata with fixed JSON and exit one", async context => {
  const f = await fixture(context);
  await unlink(f.statePath);
  const result = await captureCommand(process.execPath, [fileURLToPath(new URL("../case/capacity.js", import.meta.url)), f.configFile, f.attempt.configHash]);
  assert.equal(result.exitCode, 1);
  assert.deepEqual(JSON.parse(result.stdout.toString()), {ready: false});
  assert.equal(result.stdout.includes(Buffer.from(f.root)), false);
  assert.equal(result.stderr.length, 0);
});
