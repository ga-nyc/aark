import assert from "node:assert/strict";
import fs from "node:fs";
import { access, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { initializeCase, loadCaseState, saveCaseState } from "../case/store.js";
import { CaseSupervisor } from "../case/supervisor.js";
import { engineUnitName } from "../case/systemd.js";
import type { AgentBridge, AgentEvent, AgentReply, EngineHost, EngineIdentity, EngineObservation, PreparedAttempt } from "../case/types.js";
import { mkdtemp } from "./helpers.js";

const linuxOnly = {skip: process.platform !== "linux"};

/** Synthetic lifecycle effects only: no native engines, services, or model calls. */
class FakeHost implements EngineHost {
  observation: EngineObservation = {status: "running"};
  async preflight(): Promise<void> {}
  async launch(_attempt: PreparedAttempt, token: string): Promise<EngineIdentity> {
    return {unit: engineUnitName(token), invocationId: "a".repeat(32)};
  }
  async observe(): Promise<EngineObservation> { return this.observation; }
  async verify() { return {sha256: "b".repeat(64), scansVerified: 1, filesVerified: 1}; }
}

class FakeAgent implements AgentBridge {
  readonly requests: AgentEvent[] = [];
  private readonly pending: Array<(error: Error) => void> = [];
  async preflight(): Promise<void> {}
  async request(event: AgentEvent): Promise<AgentReply> {
    this.requests.push(structuredClone(event));
    return await new Promise<AgentReply>((_resolve, reject) => this.pending.push(reject));
  }
  async close(): Promise<void> {
    for (const reject of this.pending) reject(new Error("synthetic bridge closed"));
  }
}

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-case-cache-test-"));
  const input = path.join(root, "input");
  const code = path.join(root, "code");
  await mkdir(input);
  await mkdir(code);
  const workflow = path.join(root, "workflow.json");
  await writeFile(workflow, JSON.stringify({version: 1, execute: true, output: path.join(root, "output"),
    scans: [{inputs: [input], provenance: "unknown"}], mining: {workers: 1}}));
  const control = path.join(root, "control");
  const filename = path.join(root, "case.json");
  await writeFile(filename, JSON.stringify({version: 1, execute: true, control, pollMs: 1000, maxConcurrent: 1,
    jobs: [{id: "job-000001", dependsOn: [], attempts: [workflow], resumeAfterQuota: false}],
    agent: {ownership: "dedicated-thread", executable: "/usr/bin/codex", socketPath: path.join(root, "codex.sock"),
      threadId: "synthetic-thread", user: "syntheticuser", readableRoots: [code], timeoutMs: 1000, maxRequests: 1}}));
  await initializeCase(filename, {execute: true});
  return {root, control, stateFile: path.join(control, "case-state-sensitive.json"),
    progressFile: path.join(control, "case-progress-redacted.json"), host: new FakeHost(), agent: new FakeAgent()};
}

test("an advisory cache failure after an authoritative delivery debit cannot consume an undelivered request", linuxOnly, async context => {
  const f = await fixture();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  await supervisor.tick();
  f.host.observation = {status: "failed"};
  const controller = new AbortController();
  const originalRename = fs.promises.rename;
  let failedCache = false;
  fs.promises.rename = async (source, destination) => {
    if (!failedCache && destination === f.progressFile) {
      const {state} = await loadCaseState(f.control);
      if (state.outbox.some(entry => entry.status === "delivering")) {
        assert.equal(state.agentRequests, 1, "the debit is already authoritative at this cache boundary");
        failedCache = true;
        controller.abort();
        throw Object.assign(new Error("synthetic advisory rename failure"), {code: "EIO"});
      }
    }
    await originalRename(source, destination);
  };
  syncBuiltinESMExports();
  try { await supervisor.run(controller.signal); }
  finally {
    fs.promises.rename = originalRename;
    syncBuiltinESMExports();
    await supervisor.close();
  }
  assert.equal(failedCache, true);
  assert.equal(f.agent.requests.length, 0);
  const {state} = await loadCaseState(f.control);
  assert.equal(state.agentRequests, 0);
  assert.equal(state.outbox[0]!.status, "pending");
  assert.equal(state.outbox[0]!.deliveries, 0);
  const agent = new FakeAgent();
  const restarted = await CaseSupervisor.open(f.control, {host: f.host, agent});
  try {
    await restarted.tick();
    assert.equal(agent.requests.length, 1);
    assert.equal(agent.requests[0]!.eventId, state.outbox[0]!.event.eventId);
    assert.equal((await loadCaseState(f.control)).state.agentRequests, 1);
  } finally { await restarted.close(); }
});

test("an authoritative state write failure still rejects and preserves the last committed state and cache", linuxOnly, async context => {
  const f = await fixture();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const original = await loadCaseState(f.control);
  const stateBytes = await readFile(f.stateFile);
  const progressBytes = await readFile(f.progressFile);
  original.state.desired = "user-paused";
  original.state.revision++;
  const originalRename = fs.promises.rename;
  fs.promises.rename = async (source, destination) => {
    if (destination === f.stateFile) throw Object.assign(new Error("synthetic authoritative rename failure"), {code: "EIO"});
    await originalRename(source, destination);
  };
  syncBuiltinESMExports();
  try { await assert.rejects(saveCaseState(f.control, original.config, original.state), /synthetic authoritative rename failure/); }
  finally { fs.promises.rename = originalRename; syncBuiltinESMExports(); }
  assert.deepEqual(await readFile(f.stateFile), stateBytes);
  assert.deepEqual(await readFile(f.progressFile), progressBytes);
  assert.equal((await loadCaseState(f.control)).state.desired, "running");
});

test("advisory cache failure cannot hide control-directory replacement before bridge entry", linuxOnly, async context => {
  const f = await fixture();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  await supervisor.tick();
  f.host.observation = {status: "failed"};
  const displaced = path.join(f.root, "displaced-control");
  const controller = new AbortController();
  const originalRename = fs.promises.rename;
  let replaced = false;
  fs.promises.rename = async (source, destination) => {
    if (!replaced && destination === f.progressFile) {
      const {state} = await loadCaseState(f.control);
      if (state.outbox.some(entry => entry.status === "delivering")) {
        assert.equal(state.agentRequests, 1);
        replaced = true;
        await originalRename(f.control, displaced);
        await mkdir(f.control, {mode: 0o700});
        throw Object.assign(new Error("synthetic cache failure after control replacement"), {code: "EIO"});
      }
    }
    await originalRename(source, destination);
  };
  syncBuiltinESMExports();
  try { await assert.rejects(supervisor.run(controller.signal), /case control directory binding changed/); }
  finally {
    controller.abort();
    fs.promises.rename = originalRename;
    syncBuiltinESMExports();
    await supervisor.close();
  }
  assert.equal(replaced, true);
  assert.equal(f.agent.requests.length, 0);
  assert.deepEqual(await readdir(f.control), [], "the private replacement is never adopted as control authority");
  await assert.rejects(access(f.stateFile));
  await assert.rejects(access(path.join(f.control, ".case-service.lock")));
  await assert.rejects(CaseSupervisor.open(f.control, {host: f.host, agent: new FakeAgent()}), {code: "ENOENT"});
});
