import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { initializeCase, loadCaseState, saveCaseState } from "../case/store.js";
import { CaseSupervisor } from "../case/supervisor.js";
import { engineUnitName, SystemdEngineHost } from "../case/systemd.js";
import type { AgentBridge, EngineHost } from "../case/types.js";
import type { CommandResult } from "../core/command.js";
import { mkdtemp } from "./helpers.js";

const linux = {skip: process.platform !== "linux"};
const agent = (): AgentBridge => ({preflight: async () => {}, close: async () => {},
  request: async () => { throw new Error("no decision request is expected for this synthetic authorized intent"); }});
function result(executable: string, args: string[], stdout: string): CommandResult {
  return {executable, args, exitCode: 0, signal: null, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0),
    stdoutTruncated: false, stderrTruncated: false, durationMs: 1, terminationReason: null};
}

test("two cancelled prepared resumes retain fresh quota readiness across worker and host restarts", linux, async context => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-submit-phase-test-"));
  context.after(() => rm(root, {recursive: true, force: true}));
  const input = path.join(root, "input"), code = path.join(root, "code");
  await mkdir(input); await mkdir(code);
  const workflowFile = path.join(root, "workflow.json"), control = path.join(root, "control");
  await writeFile(workflowFile, JSON.stringify({version: 1, execute: true, output: path.join(root, "output"),
    scans: [{inputs: [input], provenance: "unknown"}], mining: {workers: 1, storage: {minFreeGiB: 0, minFreePercent: 0}},
    finalizationStorage: {minFreeGiB: 0, minFreePercent: 0}}));
  const configFile = path.join(root, "case.json");
  await writeFile(configFile, JSON.stringify({version: 1, execute: true, control, pollMs: 1000,
    jobs: [{id: "job-000001", dependsOn: [], attempts: [workflowFile], resumeAfterQuota: true}],
    agent: {ownership: "dedicated-thread", executable: "/usr/bin/codex", socketPath: path.join(root, "codex.sock"),
      threadId: "synthetic-parent", user: "syntheticuser", readableRoots: [code]}}));
  await initializeCase(configFile, {execute: true});
  const saved = await loadCaseState(control), resumeToken = randomUUID(), originalToken = randomUUID();
  saved.state.jobs[0]!.attempts.push({index: 0, token: originalToken, mode: "run", status: "paused", resumeReady: true,
    identity: {unit: engineUnitName(originalToken), invocationId: "a".repeat(32)},
    observation: {status: "paused", pauseReason: "free-space-reserve"}},
  {index: 0, token: resumeToken, mode: "resume", status: "launching"});
  saved.state.revision++;
  await saveCaseState(control, saved.config, saved.state);
  let ready = true, capacityChecks = 0, submissions = 0;
  const host = (): EngineHost => {
    const adapter = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: control,
      command: async (executable, args) => {
        if (executable.endsWith("systemctl")) return result(executable, args, "LoadState=not-found\n");
        if (args[0]?.endsWith("capacity.js")) { capacityChecks++; return result(executable, args, JSON.stringify({ready})); }
        if (args[1] === "binding") return result(executable, args, '{"valid":true}');
        if (executable.endsWith("systemd-run")) { submissions++; throw new Error("no engine submission is permitted in this test"); }
        throw new Error("unexpected synthetic helper");
      }});
    return {preflight: async () => {}, launch: adapter.launch.bind(adapter), reattach: adapter.reattach.bind(adapter),
      observe: adapter.observe.bind(adapter), verify: adapter.verify.bind(adapter), resumeReady: adapter.resumeReady.bind(adapter)};
  };
  const originalOpen = fs.promises.open;
  let controller = new AbortController();
  fs.promises.open = async (filename, flags, mode) => {
    if (typeof filename === "string" && filename.endsWith(`${engineUnitName(resumeToken)}.stderr.log`)) controller.abort();
    return await originalOpen(filename, flags, mode);
  };
  syncBuiltinESMExports();
  try {
    for (let worker = 0; worker < 2; worker++) {
      controller = new AbortController();
      const supervisor = await CaseSupervisor.open(control, {host: host(), agent: agent()});
      try { await supervisor.run(controller.signal); } finally { await supervisor.close(); }
      assert.equal((await loadCaseState(control)).state.jobs[0]!.attempts.at(-1)!.dispatched, undefined);
      const receipt = JSON.parse(await readFile(path.join(control, "engines", `${engineUnitName(resumeToken)}.json`), "utf8"));
      assert.equal(receipt.phase, "prepared");
      assert.equal(submissions, 0);
    }
  } finally { fs.promises.open = originalOpen; syncBuiltinESMExports(); }
  // Model a stop after the case debit but before its known-unsubmitted host
  // result was recorded. The durable prepared receipt must reconcile it first.
  const inherited = await loadCaseState(control);
  inherited.state.jobs[0]!.attempts.at(-1)!.dispatched = true;
  await saveCaseState(control, inherited.config, inherited.state);
  ready = false;
  const before = capacityChecks;
  const restarted = await CaseSupervisor.open(control, {host: host(), agent: agent()});
  try { await restarted.tick(); await restarted.tick(); } finally { await restarted.close(); }
  assert.ok(capacityChecks > before, "a new worker obtains fresh capacity after both cancellations");
  assert.equal(submissions, 0);
  const final = (await loadCaseState(control)).state;
  assert.equal(final.jobs[0]!.attempts[0]!.resumeReady, false);
  assert.equal(final.jobs[0]!.attempts.at(-1)!.dispatched, undefined);
});
