import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rm, unlink, writeFile } from "node:fs/promises";
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
import { buildRecoveryPlan } from "../recovery/plan.js";
import { redactedPlan } from "../recovery/runner.js";
import type { SourceSafety } from "../recovery/source-safety.js";
import { loadWorkflowConfig } from "../workflow/config.js";
import { workflowSourceIdentity } from "../workflow/verify.js";
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

async function recoveryFixture(context: TestContext) {
  const f = await fixture(context);
  const destination = path.join(f.root, "recovery-case");
  const source = path.join(f.root, "synthetic-source.img");
  const image = path.join(destination, "evidence", "source.img");
  const mapfile = path.join(destination, "evidence", "source.map");
  await mkdir(path.dirname(image), {recursive: true});
  await mkdir(path.join(destination, "runs"));
  await writeFile(source, Buffer.alloc(4096));
  await writeFile(image, Buffer.alloc(2048));
  // Native ddrescue syntax with a finished prefix and an untried suffix.
  await writeFile(mapfile, "# Mapfile. Created by GNU ddrescue version 1.27\n# current_pos current_status current_pass\n0x00000800 ? 1\n# pos size status\n0x00000000 0x00000800 +\n0x00000800 0x00000800 ?\n");
  const recoveryConfig = path.join(f.root, "recovery.json");
  await writeFile(recoveryConfig, JSON.stringify({version: 1, caseId: "synthetic-case", source, destination, execute: true, requireReadOnlySource: true,
    image: {enabled: true, path: image, mapfile, retryPasses: 1}, storage: {minFreeGiB: 3, minFreePercent: 30},
    stages: {deletedMetadata: false, ntfsUndelete: false, unallocatedStream: false, signatureCarving: false,
      volumeShadows: false, residualMemory: false, deletedRegistryCells: false}}));
  await writeFile(f.configFile, JSON.stringify({version: 1, execute: true, output: f.output, recoveryConfig,
    scans: [{inputs: [image], provenance: "allocated-reference"}], finalizationStorage: {minFreeGiB: 1, minFreePercent: 10}}));
  f.attempt.workflow = await loadWorkflowConfig(f.configFile);
  f.attempt.configHash = digest(f.attempt.workflow);
  const sourceSafety = (target: string): SourceSafety => ({resolvedSource: source, kind: "regular-file", bytes: 4096,
    regularFileIdentity: {device: 1, inode: 1, bytes: 4096, modifiedMs: 1, changedMs: 1}, blockDeviceIdentity: null,
    kernelReadOnly: null, writableMounts: [], sourceTopDevices: ["synthetic-source-device"], sourceTopDevice: "synthetic-source-device", sourceLoopBackings: [],
    destinationDevices: ["synthetic-destination-device"], destinationDevice: "synthetic-destination-device", destinationLoopBackings: [],
    destinationFilesystemDevice: 2, destinationMountSource: `synthetic-mount:${target}`, destinationBackingKind: "block-device",
    deviceComparisonCertain: true, destinationOnSourceDevice: false, safe: true, reasons: []});
  f.probes.inspectSourceSafety = async (requested, target) => {
    assert.equal(requested, source);
    return sourceSafety(target);
  };
  f.state.config = f.attempt.workflow;
  f.state.phase = "recovery";
  f.state.resultsSafety = [workflowSourceIdentity(sourceSafety(f.output))];
  await f.seal();
  const plan = buildRecoveryPlan(f.attempt.workflow.recovery!);
  const runId = "2030-01-01T00-00-00-000Z-" + randomUUID();
  const native: Record<string, unknown> = {version: 1, runId, status: "paused", startedAt: "2030-01-01T00:00:00.000Z",
    updatedAt: "2030-01-01T00:01:00.000Z", finishedAt: "2030-01-01T00:01:00.000Z", plan, sourceSafety: sourceSafety(destination),
    results: [{id: plan.steps[0]!.id, status: "paused-disk-quota-resumable", executable: "ddrescue", args: plan.steps[0]!.args,
      error: "synthetic quota pause", stdoutLog: "synthetic stdout log", stderrLog: "synthetic stderr log"}], currentStep: null,
    failure: {name: "RecoveryQuotaStop", message: "synthetic quota pause"}};
  const manifest: Record<string, unknown> = {tool: "aark", layer: "recovery", runId, status: "paused", complete: false, resumable: true,
    storageStop: {reason: "free-space-reserve", availableBytes: "1", totalBytes: "100", reservedBytes: "2", outputBytes: "0", plannedBytes: "0", maximumOutputBytes: null},
    finishedAt: native.finishedAt, results: [{id: plan.steps[0]!.id, status: "paused-disk-quota-resumable"}]};
  const nativePaths = [path.join(destination, "case-sensitive.json"), path.join(destination, "runs", `${runId}-sensitive.json`)];
  const manifestPaths = [path.join(destination, "manifest-redacted.json"), path.join(destination, "runs", `${runId}-manifest-redacted.json`)];
  const sealNative = async () => {
    for (const filename of nativePaths) await writeFile(filename, JSON.stringify(native));
    for (const filename of manifestPaths) await writeFile(filename, JSON.stringify(manifest));
    for (const filename of [path.join(destination, "plan-redacted.json"), path.join(destination, "runs", `${runId}-plan-redacted.json`)]) {
      await writeFile(filename, JSON.stringify(redactedPlan(plan)));
    }
  };
  await sealNative();
  return {...f, destination, source, image, mapfile, native, manifest, nativePaths, manifestPaths, sealNative};
}

async function treeSnapshot(root: string): Promise<unknown[]> {
  const result: unknown[] = [];
  for (const entry of (await readdir(root, {withFileTypes: true})).sort((a, b) => a.name.localeCompare(b.name))) {
    const filename = path.join(root, entry.name);
    result.push(entry.isDirectory() ? [entry.name, await treeSnapshot(filename)]
      : [entry.name, createHash("sha256").update(await readFile(filename)).digest("hex")]);
  }
  return result;
}

test("clean native ddrescue quota readiness checks both destinations and every loop host without writing", async context => {
  const f = await recoveryFixture(context);
  const before = await treeSnapshot(f.root);
  const host = path.join(f.root, "synthetic-recovery-loop-host");
  f.hosts.set(f.destination, [{device: "/dev/loop-fixture", backingFile: host, fileDevice: "1", fileInode: "1", bytes: "1",
    modifiedNs: "1", changedNs: "1", offset: "0", sizeLimit: "0", mount: "{}"}]);
  assert.equal(await quotaResumeReady(f.attempt, f.probes), true);
  assert.ok([f.output, f.destination, host].every(target => f.calls.some(call => call.target === target && call.planned === 1n)));
  assert.deepEqual(await treeSnapshot(f.root), before);
  for (const target of [f.output, f.destination, host]) {
    f.free.set(target, (target === f.output ? 10n : 30n) * GiB);
    assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
    f.free.delete(target);
  }
  assert.equal(await quotaResumeReady(f.attempt, f.probes), true);
  assert.ok(f.calls.filter(call => call.target === host).every(call => call.policy.maximumOutputBytes === undefined));
  assert.deepEqual(await treeSnapshot(f.root), before);
});

test("recovery readiness rejects signal, output caps and nonresumable native engines", async context => {
  const f = await recoveryFixture(context);
  for (const reason of ["signal", "output-cap"]) {
    f.state.pauseReason = reason; await f.seal();
    assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
  }
  f.state.pauseReason = "free-space-reserve"; await f.seal();
  f.manifest.resumable = false; await f.sealNative();
  assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
  f.manifest.resumable = true;
  (f.native.results as Array<Record<string, unknown>>)[0]!.executable = "photorec";
  await f.sealNative();
  assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
  assert.equal(f.calls.length, 0);
});

test("native ddrescue retry-pass pauses require the completed fast pass", async context => {
  const f = await recoveryFixture(context);
  const plan = buildRecoveryPlan(f.attempt.workflow.recovery!);
  const results = f.native.results as Array<Record<string, unknown>>;
  const first: Record<string, unknown> = {...results[0], status: "completed", exitCode: 0, terminationReason: null};
  results.splice(0, results.length, first, {...results[0], id: plan.steps[1]!.id, args: plan.steps[1]!.args});
  f.manifest.results = [{id: first.id, status: "completed"}, {id: plan.steps[1]!.id, status: "paused-disk-quota-resumable"}];
  await f.sealNative();
  assert.equal(await quotaResumeReady(f.attempt, f.probes), true);
  first.status = "failed";
  await f.sealNative();
  assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
});

test("ddrescue readiness requires quiescent native locks and unchanged authoritative controls", async context => {
  const f = await recoveryFixture(context);
  for (const lock of [path.join(f.output, ".aark-workflow.lock"), ...[".aark-recovery.lock", ".agetnic-recovery.lock"].map(name => path.join(f.destination, name))]) {
    await writeFile(lock, "synthetic lock");
    assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
    await unlink(lock);
  }
  await writeFile(f.nativePaths[1]!, "{}");
  assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
  await f.sealNative();
  const savedMap = await readFile(f.mapfile);
  await unlink(f.mapfile);
  assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
  await writeFile(f.mapfile, "");
  assert.equal(await quotaResumeReady(f.attempt, f.probes), false);
  await writeFile(f.mapfile, savedMap);
  assert.equal(await quotaResumeReady(f.attempt, {...f.probes, inspectSourceSafety: async (...args) => ({
    ...await f.probes.inspectSourceSafety!(...args), bytes: 8192})}), false);
  const mutate: CapacityProbes = {...f.probes, assertStorageCapacity: async (...args) => {
    await writeFile(f.mapfile, savedMap.toString() + "# changed\n");
    return await f.probes.assertStorageCapacity!(...args);
  }};
  assert.equal(await quotaResumeReady(f.attempt, mutate), false);
  await writeFile(f.mapfile, savedMap);
  const replaceImage: CapacityProbes = {...f.probes, assertStorageCapacity: async (...args) => {
    await unlink(f.image);
    await writeFile(f.image, Buffer.alloc(2048));
    return await f.probes.assertStorageCapacity!(...args);
  }};
  assert.equal(await quotaResumeReady(f.attempt, replaceImage), false);
  const lateLock: CapacityProbes = {...f.probes, assertStorageCapacity: async (...args) => {
    await writeFile(path.join(f.destination, ".aark-recovery.lock"), "synthetic concurrent recovery");
    return await f.probes.assertStorageCapacity!(...args);
  }};
  assert.equal(await quotaResumeReady(f.attempt, lateLock), false);
});

test("capacity CLI distinguishes unsupported recovery resumes from unknown native controls", async context => {
  const f = await recoveryFixture(context);
  const args = [fileURLToPath(new URL("../case/capacity.js", import.meta.url)), f.configFile, f.attempt.configHash];
  f.manifest.resumable = false; await f.sealNative();
  const denied = await captureCommand(process.execPath, args);
  assert.equal(denied.exitCode, 0);
  assert.deepEqual(JSON.parse(denied.stdout.toString()), {ready: false});
  await unlink(f.nativePaths[0]!);
  const unknown = await captureCommand(process.execPath, args);
  assert.equal(unknown.exitCode, 1);
  assert.deepEqual(JSON.parse(unknown.stdout.toString()), {ready: false});
  assert.equal(unknown.stdout.includes(Buffer.from(f.root)), false);
  assert.equal(unknown.stderr.length, 0);
});

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
