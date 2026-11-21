import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
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

test("supervised CLI rejects a changed loaded configuration before creating output", async () => {
  const f = await fixture();
  // A plan can change after the host's probe and before the engine reads it.
  await writeFile(f.filename, JSON.stringify({...f.config, mining: {...f.config.mining, cryptoOnly: true}}));
  const result = await captureCommand(process.execPath, [fileURLToPath(new URL("../cli.js", import.meta.url)), "workflow", "run",
    "--config", f.filename, "--execute", "--expected-config-hash", f.expected, "--quiet"]);
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
  const paused = await runWorkflow(f.filename, {execute: true, expectedConfigHash: f.expected, signal: controller.signal,
    progress: snapshot => { if (snapshot.phase === "packaging") controller.abort(); }});
  assert.equal(paused.status, "paused");
  const stateFile = path.join(f.output, "workflow-state-sensitive.json");
  const before = await readFile(stateFile);
  const mismatch = f.expected === "0".repeat(64) ? "1".repeat(64) : "0".repeat(64);
  await assert.rejects(resumeWorkflow(f.output, {execute: true, expectedConfigHash: mismatch}), /differs from the supervisor authorization/);
  assert.deepEqual(await readFile(stateFile), before);
  await assert.rejects(access(path.join(f.output, ".aark-workflow.lock")));
  assert.equal((await resumeWorkflow(f.output, {execute: true, expectedConfigHash: f.expected})).status, "complete");
});
