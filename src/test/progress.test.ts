import assert from "node:assert/strict";
import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { captureCommand } from "../core/command.js";
import { PROGRESS_FILENAME, readProgress, redactedProgress } from "../core/progress.js";
import { scanSensitiveMaterial } from "../mining/scanner.js";
import { mkdtemp } from "./helpers.js";

function header(layer: "mining" | "recovery") {
  return { version: 1, tool: "aark", layer, status: "running", sourcePathsRedacted: true, updatedAt: new Date().toISOString() };
}

test("progress readers return only validated aggregates and never extra local fields", () => {
  const report = redactedProgress({ ...header("recovery"), currentStage: "signature-carving", availableBytes: "123456789",
    source: "/synthetic/private-source", value: "synthetic-private-value", message: "synthetic-private-message",
    activity: { readBytes: "123", writeBytes: "456", cpuTicks: "9", observedSinceLastSample: true, privateField: "synthetic-private-value" },
    nextStageCapacity: { additionalLogicalBytes: null, fitsFreeSpace: null, privateField: "synthetic-private-value" },
    storageStop: { reason: "free-space-reserve", plannedBytes: "8192", privateField: "synthetic-private-value" },
  }, "recovery");
  assert.equal(report.currentStage, "signature-carving");
  assert.equal(report.availableBytes, "123456789");
  assert.deepEqual(report.storageStop, { reason: "free-space-reserve", plannedBytes: "8192" });
  assert.equal(JSON.stringify(report).includes("private"), false);
  assert.equal(redactedProgress({ ...header("recovery"), currentStage: "synthetic-private-value", availableBytes: "/synthetic/private-path" }, "recovery").currentStage, undefined);
  assert.throws(() => redactedProgress(header("recovery"), "mining"), /invalid progress/);
  assert.equal(redactedProgress({ ...header("mining"), pauseReason: ["signal"] }, "mining").pauseReason, undefined);
});

test("local status reads are bounded and reject symbolic-link controls", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-progress-read-"));
  const report = { ...header("mining"), status: "in-progress", phase: "inventory", filesTotal: 123 };
  await writeFile(path.join(root, PROGRESS_FILENAME), JSON.stringify(report));
  assert.equal((await readProgress(root, "mining")).filesTotal, 123);
  await writeFile(path.join(root, PROGRESS_FILENAME), " ".repeat(65 * 1024));
  await assert.rejects(readProgress(root, "mining"), /bounded size/);
  if (process.platform !== "win32") {
    const linked = path.join(root, "linked");
    await mkdir(linked);
    await symlink(path.join(root, PROGRESS_FILENAME), path.join(linked, PROGRESS_FILENAME));
    await assert.rejects(readProgress(linked, "mining"));
  }
});

test("command heartbeats report liveness while preserving bounded aggregate activity", async () => {
  const snapshots: Array<Record<string, unknown>> = [];
  const result = await captureCommand(process.execPath, ["-e", "setTimeout(()=>{},150)"], {
    progressIntervalMs: 10,
    progress: async (snapshot) => { snapshots.push({ ...snapshot }); },
  });
  assert.equal(result.exitCode, 0);
  assert.ok(snapshots.some((snapshot) => snapshot.engineRunning === true));
  assert.equal(JSON.stringify(snapshots).includes("/proc/"), false);
  for (const snapshot of snapshots) assert.ok(Number.isSafeInteger(snapshot.elapsedMs));
});

test("a failed progress sink stops its writer rather than silently losing status updates", async () => {
  await assert.rejects(captureCommand(process.execPath, ["-e", "setInterval(()=>{},1000)"], {
    progressIntervalMs: 10,
    progress: async () => { throw new Error("synthetic status write failed"); },
  }), /command safety invariant failed/);
});

test("a complete mining scan publishes matching terminal progress without input locations", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-mining-progress-"));
  const input = path.join(root, "input.txt");
  const output = path.join(root, "output");
  await writeFile(input, "ordinary synthetic content\n");
  const result = await scanSensitiveMaterial({ inputs: [input], output, provenance: "unknown", chunkBytes: 32 * 1024 ** 2,
    overlapBytes: 17 * 1024 ** 2, wholeFileBytes: 64 * 1024 ** 2, minimumFreeGiB: 0, minimumFreePercent: 0 });
  const snapshot = await readProgress(output, "mining");
  assert.equal(snapshot.status, "complete");
  assert.equal(snapshot.filesScanned, result.filesScanned);
  assert.equal(snapshot.bytesScanned, result.bytesScanned);
  assert.equal((await readFile(path.join(output, PROGRESS_FILENAME), "utf8")).includes(input), false);
});
