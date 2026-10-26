import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { statSync } from "node:fs";
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import test, { type TestContext } from "node:test";
import { mkdtemp } from "./helpers.js";
import { inspectSourceSafety } from "../recovery/source-safety.js";
import { resumeSensitiveMaterial, scanSensitiveMaterial } from "../mining/scanner.js";
import { planCleanup } from "../cleanup.js";
import { assertLoopBackingsOutside, mountForPath, outputLoopBinding, protectedMountBacking } from "../core/mounts.js";

const options = { provenance: "unknown" as const, workers: 1, minimumFreeGiB: 0, minimumFreePercent: 0,
  chunkBytes: 17 * 1024 * 1024, overlapBytes: 17 * 1024 * 1024, wholeFileBytes: 1024 * 1024 };

// Exercise the actual kernel adapter and public operations with synthetic
// command responses. All files remain ordinary temporary files: no real block
// device, mount, formatting command, or administrator permission is used.
async function loopFixture(context: TestContext, inLogs = false): Promise<{
  root: string; backing: string; mounted: string; output: string; recovery: string; caseRoot: string;
  setHostFilesystem: (filesystem: string) => void;
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-loop-safety-"));
  context.after(async () => {
    context.mock.restoreAll();
    syncBuiltinESMExports();
    await fs.rm(root, { recursive: true, force: true });
  });
  const caseRoot = path.join(root, "case");
  const recovery = path.join(caseRoot, "recovery");
  const logs = path.join(caseRoot, "logs");
  const mounted = path.join(root, "mounted");
  const backing = path.join(inLogs ? logs : root, "workspace.img");
  const output = path.join(mounted, "mining");
  for (const directory of [recovery, logs, mounted]) await fs.mkdir(directory, { recursive: true });
  await fs.writeFile(backing, Buffer.alloc(4096));
  await fs.writeFile(path.join(recovery, "ordinary.txt"), "ordinary synthetic data\n");
  const hostMetadata = await fs.stat(backing, { bigint: true });
  const loop = "/dev/loop987654";
  const host = "/dev/aark-synthetic-host";
  const originalStat = fs.stat;
  const originalRealpath = fs.realpath;
  const originalRead = fs.readFile;
  const originalSpawn = childProcess.spawn;
  let hostFilesystem = "ext4";
  context.mock.method(fs, "stat", async (...args: Parameters<typeof fs.stat>) => {
    if (args[0] === loop || args[0] === host) {
      return { ...hostMetadata, isBlockDevice: () => true,
        rdev: args[0] === loop ? 2042n : hostMetadata.dev };
    }
    return await originalStat(...args);
  });
  context.mock.method(fs, "realpath", async (...args: Parameters<typeof fs.realpath>) => {
    if (args[0] === "/sys/dev/block/7:250") return `/sys/devices/virtual/block/${path.basename(loop)}`;
    if (typeof args[0] === "string" && args[0].startsWith("/sys/dev/block/")) {
      return `/sys/devices/synthetic/block/${path.basename(host)}`;
    }
    return await originalRealpath(...args);
  });
  context.mock.method(fs, "readFile", async (...args: Parameters<typeof fs.readFile>) => {
    if (args[0] === "/proc/self/mounts") return `${host} / ${hostFilesystem} rw 0 0\n${loop} ${mounted} ext4 rw 0 0\n`;
    return await originalRead(...args);
  });
  context.mock.method(childProcess, "spawn", (command: string, args: string[], spawnOptions: Parameters<typeof childProcess.spawn>[2]) => {
    const executable = path.basename(command);
    if (executable !== "lsblk" && executable !== "losetup") return originalSpawn(command, args, spawnOptions);
    let response: unknown;
    if (executable === "lsblk") {
      const device = args.at(-1);
      assert.ok(device === loop || device === host);
      response = { blockdevices: [{ kname: device, type: device === loop ? "loop" : "disk", tran: "usb", subsystems: "block:usb" }] };
    } else {
      // Update the reported inode after replacement, as the real kernel would
      // after an operator rebinds the loop to a byte-identical copied file.
      const metadata = statSync(backing, { bigint: true });
      const major = metadata.dev >> 8n & 0xfffn | metadata.dev >> 32n & ~0xfffn;
      const minor = metadata.dev & 0xffn | metadata.dev >> 12n & ~0xffn;
      response = { loopdevices: [{ name: loop, "back-file": backing, "back-ino": metadata.ino.toString(),
        "back-maj:min": `${major}:${minor}`, offset: 0, sizelimit: 0 }] };
    }
    const child = new childProcess.ChildProcess();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    process.nextTick(() => {
      child.stdout?.emit("data", Buffer.from(JSON.stringify(response)));
      child.emit("exit", 0, null);
      child.emit("close", 0, null);
    });
    return child;
  });
  syncBuiltinESMExports();
  return { root, backing, mounted, output, recovery, caseRoot, setHostFilesystem: filesystem => { hostFilesystem = filesystem; } };
}

test("recovery rejects an image that backs its destination before modifying the image", { skip: process.platform !== "linux" }, async context => {
  const f = await loopFixture(context);
  const before = await fs.readFile(f.backing);
  await assert.rejects(inspectSourceSafety(f.backing, f.output), /source.*loop backing|loop backing.*source/);
  assert.deepEqual(await fs.readFile(f.backing), before);
  await assert.rejects(fs.access(f.output));
});

test("mining rejects its output container as a file input or part of a directory input", { skip: process.platform !== "linux" }, async context => {
  const f = await loopFixture(context, true);
  for (const input of [f.backing, path.dirname(f.backing)]) {
    await assert.rejects(scanSensitiveMaterial({ ...options, inputs: [input], output: f.output }), /input.*loop backing|loop backing.*input/);
    await assert.rejects(fs.access(f.output));
  }
});

test("cleanup refuses to delete the container retaining a completed mining result", { skip: process.platform !== "linux" }, async context => {
  const f = await loopFixture(context, true);
  assert.equal((await scanSensitiveMaterial({ ...options, inputs: [f.recovery], output: f.output })).status, "complete");
  const runId = "synthetic-loop-case";
  const state = { version: 1, runId, status: "running", startedAt: new Date().toISOString(), finishedAt: null,
    currentStep: "signature-carving", failure: null,
    plan: { version: 1, destination: f.caseRoot, steps: [{ id: "inventory", optional: false }, { id: "signature-carving", optional: false }] },
    results: [{ id: "inventory", status: "completed" }] };
  const runs = path.join(f.caseRoot, "runs");
  await fs.mkdir(runs);
  for (const filename of [path.join(f.caseRoot, "case-sensitive.json"), path.join(runs, `${runId}-sensitive.json`)]) {
    await fs.writeFile(filename, JSON.stringify(state));
  }
  for (const filename of [path.join(f.caseRoot, "plan-redacted.json"), path.join(runs, `${runId}-plan-redacted.json`)]) {
    await fs.writeFile(filename, "{}\n");
  }
  await assert.rejects(planCleanup({ caseDirectory: f.caseRoot, miningOutputs: [f.output], acceptInterruptedCase: true }), /cleanup.*loop backing|loop backing.*cleanup/);
  await fs.access(f.backing);
});

test("resume freezes the output loop binding even when all inputs are on a direct mount", { skip: process.platform !== "linux" }, async context => {
  const f = await loopFixture(context);
  const controller = new AbortController();
  controller.abort();
  assert.equal((await scanSensitiveMaterial({ ...options, inputs: [f.recovery], output: f.output, signal: controller.signal })).status, "paused");
  await fs.rename(f.backing, `${f.backing}.original`);
  await fs.copyFile(`${f.backing}.original`, f.backing);
  await assert.rejects(resumeSensitiveMaterial({ output: f.output }), /output.*loop binding/);
  const statePath = path.join(f.output, "scan-state-sensitive.json");
  const originalState = await fs.readFile(statePath, "utf8");
  const state = JSON.parse(originalState) as Record<string, unknown>;
  const mounted = await mountForPath(f.output);
  assert.ok(mounted);
  state.outputLoopBinding = outputLoopBinding(await protectedMountBacking(mounted));
  await fs.writeFile(statePath, JSON.stringify(state));
  await assert.rejects(resumeSensitiveMaterial({ output: f.output }), /checkpoint do not match/);
  await fs.writeFile(statePath, originalState);
  await fs.unlink(f.backing);
  await fs.rename(`${f.backing}.original`, f.backing);
  assert.equal((await resumeSensitiveMaterial({ output: f.output })).status, "complete");
});

test("cleanup accepts the original completed output container and rejects its replacement", { skip: process.platform !== "linux" }, async context => {
  const f = await loopFixture(context);
  assert.equal((await scanSensitiveMaterial({ ...options, inputs: [f.recovery], output: f.output })).status, "complete");
  // Use an otherwise valid inactive legacy case so the output binding is the
  // only reason to reject it. Keep the original container outside all targets.
  const runId = "synthetic-completed-loop-case";
  const state = { version: 1, runId, status: "running", startedAt: new Date().toISOString(), finishedAt: null,
    currentStep: "signature-carving", failure: null,
    plan: { version: 1, destination: f.caseRoot, steps: [{ id: "inventory", optional: false }, { id: "signature-carving", optional: false }] },
    results: [{ id: "inventory", status: "completed" }] };
  const runs = path.join(f.caseRoot, "runs");
  await fs.mkdir(runs);
  for (const filename of [path.join(f.caseRoot, "case-sensitive.json"), path.join(runs, `${runId}-sensitive.json`)]) {
    await fs.writeFile(filename, JSON.stringify(state));
  }
  for (const filename of [path.join(f.caseRoot, "plan-redacted.json"), path.join(runs, `${runId}-plan-redacted.json`)]) await fs.writeFile(filename, "{}\n");
  const cleanup = { caseDirectory: f.caseRoot, miningOutputs: [f.output], acceptInterruptedCase: true };
  assert.equal((await planCleanup(cleanup)).status, "ready");
  await fs.rename(f.backing, `${f.backing}.original`);
  await fs.copyFile(`${f.backing}.original`, f.backing);
  await assert.rejects(planCleanup(cleanup), /output loop binding/);
});

test("resume refuses an NTFS3 output host before writing operation locks", { skip: process.platform !== "linux" }, async context => {
  const f = await loopFixture(context);
  const controller = new AbortController();
  controller.abort();
  assert.equal((await scanSensitiveMaterial({ ...options, inputs: [f.recovery], output: f.output, signal: controller.signal })).status, "paused");
  f.setHostFilesystem("ntfs3");
  const originalOpen = fs.open;
  let lockWrites = 0;
  context.mock.method(fs, "open", async (...args: Parameters<typeof fs.open>) => {
    if (typeof args[0] === "string" && args[0].endsWith("-mining.lock")) lockWrites += 1;
    return await originalOpen(...args);
  });
  syncBuiltinESMExports();
  await assert.rejects(resumeSensitiveMaterial({ output: f.output }), /ntfs3 output mounts/);
  assert.equal(lockWrites, 0);
});

test("container overlap checks recognize directory identities behind another mount view", { skip: process.platform !== "linux" }, async context => {
  const f = await loopFixture(context, true);
  const alias = path.join(f.root, "other-view");
  await fs.mkdir(alias);
  const mounted = await mountForPath(f.output);
  assert.ok(mounted);
  const backing = await protectedMountBacking(mounted);
  const originalLstat = fs.lstat;
  context.mock.method(fs, "lstat", async (...args: Parameters<typeof fs.lstat>) => (
    // A bind mount exposes the same directory inode through another path.
    await originalLstat(args[0] === alias ? path.dirname(f.backing) : args[0], args[1])
  ));
  await assert.rejects(assertLoopBackingsOutside(backing.loopBackings, [alias], "cleanup deletion target"), /loop backing file/);
});
