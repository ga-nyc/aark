import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { access, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test, { type TestContext } from "node:test";
import { captureSourceBindings } from "../case/sources.js";
import { captureCommand } from "../core/command.js";
import { loadWorkflowConfig } from "../workflow/config.js";
import { resumeWorkflow, runWorkflow } from "../workflow/runner.js";
import { mkdtemp } from "./helpers.js";

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-case-binding-test-"));
  const input = path.join(root, "synthetic-input");
  await mkdir(input);
  await writeFile(path.join(input, "ordinary.txt"), "ordinary synthetic fixture data\n");
  const output = path.join(root, "output");
  const filename = path.join(root, "workflow.json");
  const config = {version: 1, execute: true, output, scans: [{inputs: [input], provenance: "unknown"}],
    mining: {workers: 1, storage: {minFreeGiB: 0, minFreePercent: 0}},
    finalizationStorage: {minFreeGiB: 0, minFreePercent: 0}};
  await writeFile(filename, JSON.stringify(config));
  const expected = createHash("sha256").update(JSON.stringify(await loadWorkflowConfig(filename))).digest("hex");
  return {root, output, filename, config, expected};
}

async function imageFixture(context: TestContext) {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-case-image-binding-test-"));
  context.after(() => rm(root, {recursive: true, force: true}));
  const source = path.join(root, "synthetic-original.img");
  await writeFile(source, Buffer.alloc(4096, 0x53));
  const recovery = path.join(root, "synthetic-recovery");
  const recoveryFile = path.join(root, "recovery.json");
  await writeFile(recoveryFile, JSON.stringify({version: 1, caseId: "synthetic-source-binding", source, destination: recovery,
    requireReadOnlySource: true, execute: true, image: {enabled: false},
    stages: {deletedMetadata: true, unallocatedStream: false, signatureCarving: false}}));
  const output = path.join(root, "synthetic-results");
  const filename = path.join(root, "workflow.json");
  await writeFile(filename, JSON.stringify({version: 1, execute: true, output, recoveryConfig: recoveryFile,
    scans: [{inputs: [path.join(recovery, "recovery", "metadata-deleted")], provenance: "deleted-metadata"}],
    mining: {workers: 1, storage: {minFreeGiB: 0, minFreePercent: 0}}, finalizationStorage: {minFreeGiB: 0, minFreePercent: 0}}));
  const workflow = await loadWorkflowConfig(filename);
  const expected = createHash("sha256").update(JSON.stringify(workflow)).digest("hex");
  const pins = await captureSourceBindings(workflow);
  return {root, source, recovery, filename, output, expected, pins};
}

test("supervised CLI rejects a changed loaded configuration before creating output", async () => {
  const f = await fixture();
  // A plan can change after the host's probe and before the engine reads it.
  await writeFile(f.filename, JSON.stringify({...f.config, mining: {...f.config.mining, cryptoOnly: true}}));
  const result = await captureCommand(process.execPath, [fileURLToPath(new URL("../cli.js", import.meta.url)), "workflow", "run",
    "--config", f.filename, "--execute", "--expected-config-hash", f.expected, "--expected-source-bindings", "[]", "--quiet"]);
  assert.equal(result.exitCode, 1);
  assert.match(result.stderr.toString(), /differs from the supervisor authorization/);
  await assert.rejects(access(f.output));
});

test("matching supervised CLI configuration completes its synthetic workflow", async () => {
  const f = await fixture();
  const result = await captureCommand(process.execPath, [fileURLToPath(new URL("../cli.js", import.meta.url)), "workflow", "run",
    "--config", f.filename, "--execute", "--expected-config-hash", f.expected, "--quiet"]);
  assert.equal(result.exitCode, 0, result.stderr.toString());
  assert.equal(JSON.parse(result.stdout.toString()).status, "complete");
  await access(path.join(f.output, "manifest-redacted.json"));
  assert.equal(result.stdout.includes(Buffer.from(f.root)), false);
});

test("resume authorization binds the frozen paused configuration before locking or modifying it", async () => {
  const f = await fixture();
  const controller = new AbortController();
  const paused = await runWorkflow(f.filename, {execute: true, expectedConfigHash: f.expected, expectedSourceBindings: [], signal: controller.signal,
    progress: snapshot => { if (snapshot.phase === "packaging") controller.abort(); }});
  assert.equal(paused.status, "paused");
  const stateFile = path.join(f.output, "workflow-state-sensitive.json");
  const before = await readFile(stateFile);
  const mismatch = f.expected === "0".repeat(64) ? "1".repeat(64) : "0".repeat(64);
  await assert.rejects(resumeWorkflow(f.output, {execute: true, expectedConfigHash: mismatch}), /differs from the supervisor authorization/);
  assert.deepEqual(await readFile(stateFile), before);
  await assert.rejects(access(path.join(f.output, ".aark-workflow.lock")));
  await assert.rejects(resumeWorkflow(f.output, {execute: true, expectedConfigHash: f.expected,
    expectedSourceBindings: [{source: path.join(f.root, "unregistered.img"), sha256: "0".repeat(64)}]}), /source identity|source-identity-changed/u);
  assert.deepEqual(await readFile(stateFile), before);
  await assert.rejects(access(path.join(f.output, ".aark-workflow.lock")));
  assert.equal((await resumeWorkflow(f.output, {execute: true, expectedConfigHash: f.expected, expectedSourceBindings: []})).status, "complete");
});

test("supervised native source identity refuses an inode replacement at the same reviewed path before creating outputs", {skip: process.platform !== "linux"}, async context => {
  const f = await imageFixture(context);
  const replacement = path.join(f.root, "replacement.img");
  await writeFile(replacement, Buffer.alloc(4096, 0x53)); // Same bytes and path spelling cannot hide a new identity.
  await rename(replacement, f.source);
  const result = await captureCommand(process.execPath, [fileURLToPath(new URL("../cli.js", import.meta.url)), "workflow", "run",
    "--config", f.filename, "--execute", "--expected-config-hash", f.expected,
    "--expected-source-bindings", JSON.stringify(f.pins), "--quiet"], {timeoutMs: 20_000, maxCaptureBytes: 32768});
  assert.equal(result.exitCode, 1);
  assert.match(result.stderr.toString(), /source identity|source-identity-changed/u);
  assert.equal(result.stdout.length, 0);
  assert.equal(result.stderr.includes(Buffer.from(f.source)), false);
  await assert.rejects(access(f.output));
  await assert.rejects(access(f.recovery));
});

test("matching source pins pass the native captured-safety baseline before output creation", {skip: process.platform !== "linux"}, async context => {
  const f = await imageFixture(context);
  const originalMkdir = fs.promises.mkdir;
  let outputReached = false;
  const stopAtOutput: typeof fs.promises.mkdir = (async (directory: Parameters<typeof fs.promises.mkdir>[0], options?: unknown) => {
    if (directory === f.output) { outputReached = true; throw new Error("synthetic checked baseline reached"); }
    return await originalMkdir(directory, options as Parameters<typeof fs.promises.mkdir>[1]);
  }) as typeof fs.promises.mkdir;
  fs.promises.mkdir = stopAtOutput;
  syncBuiltinESMExports();
  try {
    await assert.rejects(runWorkflow(f.filename, {execute: true, expectedConfigHash: f.expected, expectedSourceBindings: f.pins}), /synthetic checked baseline reached/u);
  } finally {
    fs.promises.mkdir = originalMkdir;
    syncBuiltinESMExports();
  }
  assert.equal(outputReached, true);
  await assert.rejects(access(f.output));
  await assert.rejects(access(f.recovery));
});

test("hidden source-binding CLI input is bounded, strict, and rejects invalid JSON without echoing values", async () => {
  const f = await fixture();
  const valid = {source: path.join(f.root, "synthetic-original.img"), sha256: "a".repeat(64)};
  const inputs = ["synthetic-private-payload", "{}", JSON.stringify([valid, {...valid, source: path.join(f.root, "second.img")}, {...valid, source: path.join(f.root, "third.img")}]),
    JSON.stringify([{...valid, source: "relative"}]), JSON.stringify([{...valid, sha256: "synthetic-private-payload"}]),
    JSON.stringify([{...valid, secret: "synthetic-private-payload"}]), JSON.stringify([valid, valid]),
    JSON.stringify([{...valid, source: valid.source + "\nsynthetic-private-payload"}]), "x".repeat(16 * 1024 + 1)];
  for (const input of inputs) {
    const result = await captureCommand(process.execPath, [fileURLToPath(new URL("../cli.js", import.meta.url)), "workflow", "run",
      "--config", f.filename, "--execute", "--expected-source-bindings", input, "--quiet"]);
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr.toString(), /invalid supervised source bindings/u);
    assert.equal(result.stderr.includes(Buffer.from("synthetic-private-payload")), false);
    assert.equal(result.stderr.includes(Buffer.from(f.root)), false);
    assert.equal(result.stdout.length, 0);
    await assert.rejects(access(f.output));
  }
});
