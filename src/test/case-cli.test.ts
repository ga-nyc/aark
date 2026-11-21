import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import { initializeCase } from "../case/store.js";
import { captureCommand, type CommandResult } from "../core/command.js";
import { mkdtemp } from "./helpers.js";

const CLI = fileURLToPath(new URL("../cli.js", import.meta.url));
const linuxOnly = { skip: process.platform !== "linux" };
interface Fixture {
  root: string; control: string; filename: string; blockedHostMarker: string;
  invoke(args: string[]): Promise<CommandResult>;
}
async function fixture(context: TestContext): Promise<Fixture> {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-case-cli-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const source = path.join(root, "synthetic-source-private");
  const code = path.join(root, "synthetic-code");
  await mkdir(source); await mkdir(code);
  await writeFile(path.join(source, "ordinary.txt"), "ordinary synthetic fixture bytes\n");
  const workflow = path.join(root, "workflow-private.json");
  await writeFile(workflow, JSON.stringify({ version: 1, execute: true, output: path.join(root, "synthetic-output"),
    scans: [{ inputs: [source], provenance: "unknown" }],
    mining: { workers: 1, storage: { minFreeGiB: 0, minFreePercent: 0 } }, finalizationStorage: { minFreeGiB: 0, minFreePercent: 0 } }));
  const control = path.join(root, "private-control");
  const filename = path.join(root, "case-private.json");
  await writeFile(filename, JSON.stringify({ version: 1, execute: true, control,
    jobs: [{ id: "job-000001", dependsOn: [], attempts: [workflow], resumeAfterQuota: false }],
    pollMs: 1000, probeTimeoutMs: 1000, maxConcurrent: 1,
    agent: { ownership: "dedicated-thread", executable: path.join(root, "synthetic-codex"), socketPath: path.join(root, "synthetic-app.sock"),
      threadId: "synthetic-registration", user: "fixtureuser", readableRoots: [code], timeoutMs: 1000, maxRequests: 4 } }));
  // Every CLI child installs this guard before loading AARK. A regression must
  // fail the test instead of issuing systemd, notification, or model commands.
  const blockedHostMarker = path.join(root, "unexpected-host-command");
  const preload = path.join(root, "deny-host-commands.mjs");
  await writeFile(preload, `import fs from "node:fs";
import childProcess from "node:child_process";
import {syncBuiltinESMExports} from "node:module";
const deny = () => { fs.writeFileSync(${JSON.stringify(blockedHostMarker)}, "blocked"); throw new Error("synthetic host command blocked"); };
for (const name of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]) childProcess[name] = deny;
syncBuiltinESMExports();\n`);
  const invoke = async (args: string[]): Promise<CommandResult> => captureCommand(process.execPath, ["--import", preload, CLI, "case", ...args],
    { timeoutMs: 10_000, killGraceMs: 100, maxCaptureBytes: 32_768 });
  return { root, control, filename, blockedHostMarker, invoke };
}
async function snapshot(root: string): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  const visit = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const filename = path.join(directory, entry.name);
      if (entry.isDirectory()) { result[path.relative(root, filename)] = "directory"; await visit(filename); }
      else result[path.relative(root, filename)] = createHash("sha256").update(await readFile(filename)).digest("hex");
    }
  };
  await visit(root);
  return result;
}
async function assertNoHostCommands(f: Fixture): Promise<void> { await assert.rejects(access(f.blockedHostMarker)); }

test("case plan CLI is redacted and creates no controls, jobs, agent, or notification effects", linuxOnly, async (context) => {
  const f = await fixture(context);
  const before = await snapshot(f.root);
  const response = await f.invoke(["plan", "--config", f.filename]);
  assert.equal(response.terminationReason, null);
  assert.equal(response.exitCode, 0, response.stderr.toString());
  const plan = JSON.parse(response.stdout.toString()) as Record<string, unknown>;
  assert.equal(plan.layer, "case-plan");
  assert.equal(plan.sourcePathsRedacted, true);
  assert.equal(plan.agentMode, "dedicated-thread");
  assert.equal(plan.independentEngineServices, true);
  assert.equal(plan.cleanupAuthorized, false);
  assert.deepEqual(plan.jobs, [{ id: "job-000001", dependsOn: [], reviewedAttempts: 1, resumeAfterQuota: false }]);
  assert.equal(response.stdout.includes(Buffer.from(f.root)), false);
  assert.equal(response.stdout.includes(Buffer.from("synthetic-source-private")), false);
  assert.deepEqual(await snapshot(f.root), before);
  await assert.rejects(access(f.control));
  await assertNoHostCommands(f);
});

test("case status CLI reads authoritative state and omits source, configuration, and injected cache fields", linuxOnly, async (context) => {
  const f = await fixture(context);
  const initialized = await initializeCase(f.filename, { execute: true });
  await writeFile(path.join(f.control, "case-progress-redacted.json"), JSON.stringify({ complete: true,
    source: "/synthetic/private-source", error: "synthetic-private-error" }));
  const before = await snapshot(f.root);
  const response = await f.invoke(["status", "--control", f.control]);
  assert.equal(response.exitCode, 0, response.stderr.toString());
  const status = JSON.parse(response.stdout.toString()) as Record<string, unknown>;
  assert.equal(status.caseId, initialized.caseId);
  assert.equal(status.layer, "case");
  assert.equal(status.sourcePathsRedacted, true);
  assert.equal(status.complete, false);
  assert.equal(status.health, "healthy");
  assert.equal(status.cleanupAuthorized, false);
  assert.equal(response.stdout.includes(Buffer.from(f.root)), false);
  assert.equal(response.stdout.includes(Buffer.from("synthetic-private-error")), false);
  assert.equal(response.stdout.includes(Buffer.from("private-source")), false);
  assert.deepEqual(await snapshot(f.root), before);
  await assertNoHostCommands(f);
});

for (const action of ["run", "serve"] as const) {
  for (const flags of [[], ["--execute"], ["--autonomous"]]) {
    test(`case ${action} refuses incomplete execution confirmations ${flags.join(" ") || "(none)"} before hosting`, linuxOnly, async (context) => {
      const f = await fixture(context);
      const before = await snapshot(f.root);
      const response = await f.invoke([action, "--control", f.control, ...flags]);
      assert.notEqual(response.exitCode, 0);
      assert.match(response.stderr.toString(), flags.includes("--execute") ? /--autonomous confirmation/u : /--execute confirmation/u);
      assert.equal(response.stdout.length, 0);
      assert.deepEqual(await snapshot(f.root), before);
      await assert.rejects(access(f.control));
      await assertNoHostCommands(f);
    });
  }
}

test("case CLI rejects unsupported bypass flags before loading or starting a host", linuxOnly, async (context) => {
  const f = await fixture(context);
  const before = await snapshot(f.root);
  for (const action of ["run", "serve"]) {
    const response = await f.invoke([action, "--control", f.control, "--yes"]);
    assert.notEqual(response.exitCode, 0);
    assert.match(response.stderr.toString(), /unknown option '--yes'/u);
  }
  assert.deepEqual(await snapshot(f.root), before);
  await assertNoHostCommands(f);
});

test("case init, desired-state changes, and watchdog delivery require explicit confirmation", linuxOnly, async (context) => {
  const f = await fixture(context);
  const before = await snapshot(f.root);
  const commands = [["init", "--config", f.filename], ...["pause", "resume", "watch"].map((action) => [action, "--control", f.control])];
  for (const command of commands) {
    const response = await f.invoke(command);
    assert.notEqual(response.exitCode, 0);
    assert.match(response.stderr.toString(), /--execute confirmation/u);
    assert.equal(response.stdout.length, 0);
  }
  assert.deepEqual(await snapshot(f.root), before);
  await assert.rejects(access(f.control));
  await assertNoHostCommands(f);
});
