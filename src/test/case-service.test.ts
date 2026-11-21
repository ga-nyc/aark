import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";
import { caseConfigHash, digest } from "../case/config.js";
import { caseNotificationStatus, caseRecoverySourcesToInspect, caseServiceUnit, watchCaseService } from "../case/service.js";
import { saveCaseState } from "../case/store.js";
import { engineUnitName } from "../case/systemd.js";
import type { CaseConfig, CaseState } from "../case/types.js";
import type { CommandOptions, CommandResult } from "../core/command.js";
import { atomicWriteJson } from "../core/fs-safe.js";
import type { WorkflowConfig } from "../workflow/config.js";
import { mkdtemp } from "./helpers.js";
import { inspectSourceSafety } from "../recovery/source-safety.js";
import { acquireCaseLease } from "../case/lease.js";

const linuxOnly = { skip: process.platform !== "linux" };
const NOW = Date.parse("2030-01-02T03:04:05.000Z");
const ACTIVE = "ActiveState=active\nSubState=running\nMainPID=4242\nResult=success\nExecMainStatus=0\nInvocationID=" + "1".repeat(32) + "\n";
interface Call { executable: string; args: string[]; options: CommandOptions }
function result(stdout = "", changes: Partial<CommandResult> = {}): CommandResult {
  return { executable: "synthetic", args: [], exitCode: 0, signal: null, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0),
    stdoutTruncated: false, stderrTruncated: false, durationMs: 1, terminationReason: null, ...changes };
}
class FakeCommands {
  readonly calls: Call[] = [];
  observation: CommandResult | Error = result(ACTIVE);
  delivery: CommandResult | Error = result();
  command = async (executable: string, args: string[], options: CommandOptions): Promise<CommandResult> => {
    this.calls.push({ executable, args, options });
    assert.ok((options.timeoutMs ?? 0) > 0, "watchdog subprocesses must have a deadline");
    if (executable === "/usr/bin/systemctl") {
      assert.ok(args.includes("show"), "watchdog only observes systemd");
      assert.equal(args.some((arg) => ["start", "stop", "restart", "kill", "reset-failed"].includes(arg)), false);
      if (this.observation instanceof Error) throw this.observation;
      return this.observation;
    }
    if (executable === "/usr/bin/python3") {
      assert.equal(path.basename(args[0]!), "notify-local.py");
      if (this.delivery instanceof Error) throw this.delivery;
      return this.delivery;
    }
    assert.fail("Unexpected watchdog command: " + executable);
  };
  notifications(): Call[] { return this.calls.filter((call) => call.executable === "/usr/bin/python3"); }
  token(index = this.notifications().length - 1): string {
    const args = this.notifications()[index]!.args;
    return args[args.indexOf("--invocation-id") + 1]!;
  }
  event(index = this.notifications().length - 1): string {
    const args = this.notifications()[index]!.args;
    return args[args.indexOf("--event") + 1]!;
  }
}
async function fixture(context: TestContext): Promise<{ control: string; config: CaseConfig; state: CaseState; commands: FakeCommands; save(): Promise<void> }> {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-case-service-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const control = path.join(root, "control");
  await mkdir(control, { mode: 0o700 });
  const workflow: WorkflowConfig = { version: 1, execute: true, output: path.join(root, "synthetic-output"),
    scans: [{ inputs: [path.join(root, "synthetic-source-private")], provenance: "unknown" }],
    mining: { workers: 1, chunkMiB: 32, overlapMiB: 17, wholeFileMiB: 1, cryptoOnly: false, deepKeySchedules: false,
      storage: { minFreeGiB: 0, minFreePercent: 0 } }, finalizationStorage: { minFreeGiB: 0, minFreePercent: 0 } };
  const config: CaseConfig = { version: 1, execute: true, control,
    jobs: [{ id: "job-000001", dependsOn: [], resumeAfterQuota: false, attempts: [{ configFile: path.join(root, "synthetic-workflow.json"), configHash: digest(workflow), workflow }] }],
    pollMs: 1000, probeTimeoutMs: 1000, maxConcurrent: 1,
    agent: { ownership: "dedicated-thread", stateDirectory: path.join(control, "agent-private"), executable: "/approved/bin/codex",
      socketPath: "/approved/runtime/app.sock", threadId: "synthetic-parent", user: "fixtureuser", readableRoots: [path.join(root, "synthetic-code")], timeoutMs: 1000, maxRequests: 4 } };
  const state: CaseState = { version: 1, caseId: randomUUID(), revision: 0, configHash: caseConfigHash(config),
    sourceBindings: Object.fromEntries(config.jobs.flatMap(job => job.attempts.map(attempt => [attempt.configHash, []]))), desired: "running", health: "healthy",
    jobs: [{ id: "job-000001", attempts: [{ index: 0, token: randomUUID(), status: "running", mode: "run", observation: { status: "running" } }] }],
    outbox: [], agentRequests: 0, startedAt: new Date(NOW - 10_000).toISOString(), updatedAt: new Date(NOW).toISOString(), complete: false, completionDeliveredToAgent: false };
  const attempt = state.jobs[0]!.attempts[0]!;
  attempt.identity = { unit: engineUnitName(attempt.token), invocationId: "1".repeat(32) };
  const unit = caseServiceUnit(control);
  await atomicWriteJson(path.join(control, "host-private.json"), { version: 1, unit, watchUnit: unit.replace(".service", "-watch"),
    user: "fixtureuser", bus: "unix:path=/run/user/4242/bus", cli: path.join(root, "synthetic-cli.js"), node: process.execPath });
  const save = async (): Promise<void> => saveCaseState(control, config, state);
  await save();
  return { control, config, state, commands: new FakeCommands(), save };
}
function verifiedComplete(state: CaseState): void {
  state.complete = true;
  state.jobs[0]!.attempts[0]!.status = "complete";
  state.jobs[0]!.attempts[0]!.observation = { status: "complete" };
  state.jobs[0]!.attempts[0]!.proof = { sha256: "a".repeat(64), scansVerified: 1, filesVerified: 1 };
}

test("case notification status filters unknown fields and preserves delivery versus acknowledgement", linuxOnly, async context => {
  const f = await fixture(context);
  assert.equal((await caseNotificationStatus(f.control)).status, "not-recorded");
  await atomicWriteJson(path.join(f.control, "notification-status-redacted.json"), {version: 1, event: "failed", deliveryAccepted: false,
    userAcknowledged: false, checkedAt: new Date(NOW).toISOString(), sourcePath: "/synthetic/private-source", error: "synthetic-private-error"});
  const status = await caseNotificationStatus(f.control);
  assert.equal(status.recorded, true);
  assert.equal(status.deliveryAccepted, false);
  assert.equal(status.userAcknowledged, false);
  assert.equal(JSON.stringify(status).includes("private"), false);
});

test("case watchdog leaves a healthy worker and fresh heartbeat quiet", linuxOnly, async (context) => {
  const f = await fixture(context);
  const before = await readFile(path.join(f.control, "case-state-sensitive.json"), "utf8");
  const status = await watchCaseService(f.control, f.commands.command, NOW);
  assert.equal(status.workerObservedActive, true);
  assert.equal(status.heartbeatStale, false);
  assert.equal(status.notificationRequired, false);
  assert.equal(status.deliveryAccepted, null);
  assert.equal(status.userAcknowledged, false);
  assert.equal(f.commands.notifications().length, 0);
  assert.equal(await readFile(path.join(f.control, "case-state-sensitive.json"), "utf8"), before);
  assert.ok(f.commands.calls[0]!.args.includes("--property=ActiveState,SubState,MainPID,Result,ExecMainStatus,InvocationID"));
});

test("case watchdog detects auto-restart crash loops despite fresh healthy heartbeats", linuxOnly, async context => {
  const f = await fixture(context);
  f.commands.observation = result("ActiveState=activating\nSubState=auto-restart\nMainPID=0\nResult=exit-code\nExecMainStatus=1\nInvocationID=" + "2".repeat(32) + "\n");
  for (const offset of [0, 30_000, 60_000]) {
    f.commands.observation = result("ActiveState=activating\nSubState=auto-restart\nMainPID=0\nResult=exit-code\nExecMainStatus=1\nInvocationID=" + String(offset / 30_000 + 2).repeat(32) + "\n");
    f.state.updatedAt = new Date(NOW + offset).toISOString();
    await f.save();
    const status = await watchCaseService(f.control, f.commands.command, NOW + offset);
    assert.equal(status.heartbeatStale, false);
    assert.equal(status.workerObservedActive, false);
    assert.equal(status.notificationRequired, true);
    assert.equal(f.commands.event(), "failed");
  }
  assert.equal(new Set(f.commands.notifications().map((_, index) => f.commands.token(index))).size, 1);
});

test("case watchdog alerts again after a healthy interval with either the same or a new worker invocation", linuxOnly, async context => {
  const f = await fixture(context);
  f.state.health = "degraded"; await f.save();
  await watchCaseService(f.control, f.commands.command, NOW);
  const firstToken = f.commands.token();
  for (const identity of ["1", "2"]) {
    f.state.health = "healthy"; await f.save();
    assert.equal((await watchCaseService(f.control, f.commands.command, NOW)).notificationRequired, false);
    f.commands.observation = result(ACTIVE.replace("1".repeat(32), identity.repeat(32)));
    f.state.health = "degraded"; await f.save();
    await watchCaseService(f.control, f.commands.command, NOW);
    assert.notEqual(f.commands.token(), firstToken);
    await watchCaseService(f.control, f.commands.command, NOW);
    assert.equal(f.commands.token(), f.commands.token(f.commands.notifications().length - 2));
  }
  assert.equal(new Set(f.commands.notifications().map((_, index) => f.commands.token(index))).size, 3);
});

test("case watchdog serializes incident updates independently of the supervisor", linuxOnly, async context => {
  const f = await fixture(context);
  const supervisor = await acquireCaseLease(f.control);
  const watcher = await acquireCaseLease(f.control, "watchdog");
  try {
    await assert.rejects(watchCaseService(f.control, f.commands.command, NOW), /lease unavailable/u);
    assert.equal(f.commands.calls.length, 0);
    await supervisor.assertHeld();
  } finally { await watcher.release(); }
  try { assert.equal((await watchCaseService(f.control, f.commands.command, NOW)).notificationRequired, false); }
  finally { await supervisor.release(); }
});

test("case watchdog allows the notifier's nested bus and desktop deadlines", linuxOnly, async context => {
  const f = await fixture(context);
  f.state.health = "degraded"; await f.save();
  const slowSuccessfulDelivery = async (executable: string, args: string[], options: CommandOptions): Promise<CommandResult> => {
    if (executable === "/usr/bin/python3" && (options.timeoutMs ?? 0) <= 35_000) return result("", {exitCode: 1, terminationReason: "timeout"});
    return f.commands.command(executable, args, options);
  };
  assert.equal((await watchCaseService(f.control, slowSuccessfulDelivery, NOW)).deliveryAccepted, true);
  assert.ok(f.commands.notifications()[0]!.options.timeoutMs! > 35_000);
});

test("case watchdog requires a complete successful running identity before remaining quiet", linuxOnly, async context => {
  const f = await fixture(context);
  const valid = Object.fromEntries(ACTIVE.trim().split("\n").map(line => line.split("=")));
  for (const key of Object.keys(valid)) {
    const incomplete = {...valid}; delete incomplete[key];
    f.commands.observation = result(Object.entries(incomplete).map(([name, value]) => `${name}=${value}`).join("\n"));
    assert.equal((await watchCaseService(f.control, f.commands.command, NOW)).notificationRequired, true, key);
  }
  for (const mutation of [{SubState: "auto-restart"}, {MainPID: "0"}, {MainPID: "not-a-pid"},
    {Result: "exit-code"}, {ExecMainStatus: "1"}, {InvocationID: "unverified"}, {ActiveState: "reloading"}]) {
    f.commands.observation = result(Object.entries({...valid, ...mutation}).map(([name, value]) => `${name}=${value}`).join("\n"));
    assert.equal((await watchCaseService(f.control, f.commands.command, NOW)).notificationRequired, true);
  }
  f.commands.observation = result(ACTIVE + "MainPID=0\n");
  assert.equal((await watchCaseService(f.control, f.commands.command, NOW)).notificationRequired, true);
  f.commands.observation = result(ACTIVE);
  assert.equal((await watchCaseService(f.control, f.commands.command, NOW)).notificationRequired, false);
});

test("production source planning defers only missing inputs produced by approved dependencies", linuxOnly, async context => {
  const f = await fixture(context);
  const config = structuredClone(f.config);
  const producer = config.jobs[0]!;
  const source = path.join(producer.attempts[0]!.workflow.output, "evidence", "produced.img");
  const root = path.dirname(f.control);
  const destination = path.join(root, "dependent-recovery");
  const workflow: WorkflowConfig = {...structuredClone(producer.attempts[0]!.workflow), output: path.join(root, "dependent-output"),
    scans: [{inputs: [path.join(destination, "recovery", "carved")], provenance: "unallocated-carve"}],
    recovery: {version: 1, caseId: "synthetic-dependent", source, destination, requireReadOnlySource: true, execute: true,
      sectorOffset: 0, photoRecCommand: "partition_none,fileopt,everything,enable,search",
      image: {enabled: false, path: path.join(destination, "evidence", "source.img"), mapfile: path.join(destination, "evidence", "source.map"), retryPasses: 0},
      stages: {deletedMetadata: false, ntfsUndelete: false, unallocatedStream: true, signatureCarving: true,
        volumeShadows: false, residualMemory: false, deletedRegistryCells: false}}};
  const consumer = {id: "job-000002", dependsOn: [producer.id], resumeAfterQuota: false,
    attempts: [{configFile: path.join(root, "dependent-workflow.json"), configHash: digest(workflow), workflow}]};
  config.jobs.push(consumer);
  assert.deepEqual(await caseRecoverySourcesToInspect(config), []);
  const analysis = path.join(root, "external-analysis.img");
  workflow.recovery!.analysisSource = analysis;
  assert.deepEqual(await caseRecoverySourcesToInspect(config), [analysis], "external analysis sources receive the same protection as the original source");
  workflow.recovery!.analysisSource = path.join(producer.attempts[0]!.workflow.output, "future-analysis.img");
  assert.deepEqual(await caseRecoverySourcesToInspect(config), [], "approved missing producer analysis inputs may wait for their dependency");
  workflow.recovery!.analysisSource = workflow.recovery!.image.path;
  workflow.recovery!.image.enabled = true;
  assert.deepEqual(await caseRecoverySourcesToInspect(config), [], "the image created by this recovery is checked by native recovery execution");
  workflow.recovery!.image.enabled = false;
  delete workflow.recovery!.analysisSource;
  // Deferring the host's early storage check does not weaken native preflight.
  await assert.rejects(inspectSourceSafety(source, f.control), {code: "ENOENT"});
  const alias = path.join(root, "metadata-alias");
  await symlink(root, alias, "dir");
  workflow.recovery!.source = path.join(alias, path.relative(root, source));
  assert.deepEqual(await caseRecoverySourcesToInspect(config), []);
  workflow.recovery!.source = source;
  consumer.dependsOn = [];
  assert.deepEqual(await caseRecoverySourcesToInspect(config), [source]);
  consumer.dependsOn = [producer.id];
  workflow.recovery!.source = path.join(root, "unproduced.img");
  assert.deepEqual(await caseRecoverySourcesToInspect(config), [workflow.recovery!.source]);
  workflow.recovery!.source = source;
  await mkdir(path.dirname(source), {recursive: true});
  await writeFile(source, "ordinary synthetic fixture bytes\n");
  assert.deepEqual(await caseRecoverySourcesToInspect(config), [source], "existing sources still require full source safety checks");
});

test("case watchdog does not treat a pending agent decision as failed supervision", linuxOnly, async (context) => {
  const f = await fixture(context);
  f.state.health = "awaiting-agent";
  f.state.jobs[0]!.attempts[0]!.status = "failed";
  f.state.jobs[0]!.attempts[0]!.observation = { status: "failed", failureCode: "unclassified-failure" };
  f.state.agentRequests = 1;
  f.state.outbox = [{ event: { version: 1, caseId: f.state.caseId, eventId: randomUUID(), revision: f.state.revision,
    reason: "job-failed", jobs: [{ id: "job-000001", status: "failed", attemptsUsed: 1, attemptsAllowed: 1, resumeAfterQuota: false }] },
    status: "delivering", deliveries: 1, nextDeliveryAt: 0 }];
  await f.save();
  const status = await watchCaseService(f.control, f.commands.command, NOW);
  assert.equal(status.workerObservedActive, true);
  assert.equal(status.notificationRequired, false);
  assert.equal(f.commands.notifications().length, 0);
});

test("case watchdog notifies unhealthy state with a stable redacted event token", linuxOnly, async (context) => {
  const f = await fixture(context);
  f.state.health = "agent-unavailable";
  f.state.jobs[0]!.attempts[0]!.status = "failed";
  f.state.jobs[0]!.attempts[0]!.observation = { status: "failed", failureCode: "unclassified-failure" };
  f.commands.observation = result("ActiveState=active\n", { stderr: Buffer.from("synthetic-private-error /private/source") });
  await f.save();
  const first = await watchCaseService(f.control, f.commands.command, NOW);
  f.state.revision++;
  f.state.updatedAt = new Date(NOW + 10_000).toISOString();
  f.state.jobs[0]!.attempts[0]!.observation!.bytesScanned = 2048;
  await f.save();
  const second = await watchCaseService(f.control, f.commands.command, NOW + 10_000);
  assert.equal(first.deliveryAccepted, true);
  assert.equal(second.deliveryAccepted, true);
  assert.equal(f.commands.event(0), "failed");
  assert.equal(f.commands.token(0), f.commands.token(1), "heartbeat, progress, and revision updates must not create new popups");
  assert.match(f.commands.token(), /^[a-f0-9]{64}$/u);
  const serialized = JSON.stringify(f.commands.calls);
  assert.equal(serialized.includes("synthetic-private-error"), false);
  assert.equal(serialized.includes(f.config.jobs[0]!.attempts[0]!.workflow.scans[0]!.inputs[0]!), false);
  const notice = JSON.parse(await readFile(path.join(f.control, "notification-status-redacted.json"), "utf8"));
  assert.equal(notice.deliveryAccepted, true);
  assert.equal(notice.userAcknowledged, false);
  assert.equal(JSON.stringify(notice).includes("synthetic-private-error"), false);
  const args = f.commands.notifications()[0]!.args;
  assert.equal(args[args.indexOf("--allow-unit") + 1], caseServiceUnit(f.control));
  assert.equal(args[args.indexOf("--unit") + 1], caseServiceUnit(f.control));
  assert.equal(args[args.indexOf("--session-user") + 1], "fixtureuser");
  assert.equal(args[args.indexOf("--bus-address") + 1], "unix:path=/run/user/4242/bus");
  assert.equal(args[args.indexOf("--state-directory") + 1], path.join(f.control, "notifications"));
});

test("case watchdog detects stale heartbeat even while worker appears active", linuxOnly, async (context) => {
  const f = await fixture(context);
  const first = await watchCaseService(f.control, f.commands.command, NOW + 180_001);
  const second = await watchCaseService(f.control, f.commands.command, NOW + 240_000);
  assert.equal(first.workerObservedActive, true);
  assert.equal(first.heartbeatStale, true);
  assert.equal(first.notificationRequired, true);
  assert.equal(second.deliveryAccepted, true);
  assert.equal(f.commands.event(), "failed");
  assert.equal(f.commands.token(0), f.commands.token(1));
});

test("case watchdog respects a supported long poll or first agent handshake instead of raising a false failure", linuxOnly, async context => {
  const f = await fixture(context);
  f.config.pollMs = 300_000;
  f.state.configHash = caseConfigHash(f.config);
  await f.save();
  const polling = await watchCaseService(f.control, f.commands.command, NOW + 300_001);
  assert.equal(polling.heartbeatStale, false);
  assert.equal(polling.notificationRequired, false);
  f.config.pollMs = 1000;
  f.config.agent.timeoutMs = 900_000;
  f.state.configHash = caseConfigHash(f.config);
  await f.save();
  const handshake = await watchCaseService(f.control, f.commands.command, NOW + 800_000);
  assert.equal(handshake.heartbeatStale, false);
  assert.equal(handshake.notificationRequired, false);
  const expired = await watchCaseService(f.control, f.commands.command, NOW + 961_001);
  assert.equal(expired.heartbeatStale, true);
  assert.equal(expired.notificationRequired, true);
});

test("case watchdog notices a dead worker without signaling any engine", linuxOnly, async (context) => {
  const f = await fixture(context);
  f.commands.observation = result("ActiveState=failed\nInvocationID=" + "2".repeat(32) + "\n");
  const status = await watchCaseService(f.control, f.commands.command, NOW);
  assert.equal(status.workerObservedActive, false);
  assert.equal(status.notificationRequired, true);
  assert.equal(f.commands.event(), "failed");
  assert.ok(f.commands.calls.every((call) => call.executable === "/usr/bin/python3" || call.args.includes("show")));
  assert.equal(JSON.stringify(f.commands.calls).includes("aark-case-engine-"), false);
});

test("case watchdog ignores incomplete worker observations and still alerts", linuxOnly, async (context) => {
  const f = await fixture(context);
  for (const changes of [{ terminationReason: "timeout" as const, exitCode: -1 }, { stdoutTruncated: true }, { stderrTruncated: true }, { exitCode: 1 }]) {
    f.commands.observation = result("ActiveState=active\n", changes);
    const status = await watchCaseService(f.control, f.commands.command, NOW);
    assert.equal(status.workerObservedActive, false);
    assert.equal(status.notificationRequired, true);
    assert.equal(f.commands.event(), "failed");
  }
});

test("case watchdog retries failed notification delivery using the same event token", linuxOnly, async (context) => {
  const f = await fixture(context);
  f.state.health = "degraded"; await f.save();
  f.commands.delivery = result("", { exitCode: 1, stderr: Buffer.from("synthetic-private-transport-error") });
  const failed = await watchCaseService(f.control, f.commands.command, NOW);
  assert.equal(failed.deliveryAccepted, false);
  const failedStatus = JSON.parse(await readFile(path.join(f.control, "notification-status-redacted.json"), "utf8"));
  assert.equal(failedStatus.deliveryAccepted, false);
  assert.equal(failedStatus.userAcknowledged, false);
  f.commands.delivery = result();
  const retried = await watchCaseService(f.control, f.commands.command, NOW + 1000);
  assert.equal(retried.deliveryAccepted, true);
  assert.equal(f.commands.token(0), f.commands.token(1));
  assert.equal(JSON.stringify(f.commands.calls).includes("synthetic-private-transport-error"), false);
});

test("case watchdog reports clean user pause with a paused event", linuxOnly, async (context) => {
  const f = await fixture(context);
  f.state.desired = "user-paused";
  f.state.jobs[0]!.attempts[0]!.status = "paused";
  f.state.jobs[0]!.attempts[0]!.observation = { status: "paused", pauseReason: "signal" };
  await f.save();
  const status = await watchCaseService(f.control, f.commands.command, NOW);
  assert.equal(status.notificationRequired, true);
  assert.equal(f.commands.event(), "paused");
});

test("case watchdog preserves verified completion after worker exit and stale heartbeat", linuxOnly, async (context) => {
  const f = await fixture(context);
  verifiedComplete(f.state); await f.save();
  await watchCaseService(f.control, f.commands.command, NOW);
  f.commands.observation = result("ActiveState=inactive\nInvocationID=" + "1".repeat(32) + "\n");
  await watchCaseService(f.control, f.commands.command, NOW + 600_000);
  assert.equal(f.commands.event(0), "complete");
  assert.equal(f.commands.event(1), "complete", "terminal success must not age into a failure alert");
  assert.equal(f.commands.token(0), f.commands.token(1), "worker exit must not create a second completion popup");
});

test("case watchdog uses fixed failure alerts when authoritative state is missing", linuxOnly, async (context) => {
  const f = await fixture(context);
  await unlink(path.join(f.control, "case-state-sensitive.json"));
  const first = await watchCaseService(f.control, f.commands.command, NOW);
  await watchCaseService(f.control, f.commands.command, NOW + 30_000);
  assert.equal(first.heartbeatStale, true);
  assert.equal(first.notificationRequired, true);
  assert.equal(f.commands.event(), "failed");
  assert.equal(f.commands.token(0), f.commands.token(1));
});

test("case watchdog rejects corrupt completion controls instead of trusting the redacted cache", linuxOnly, async (context) => {
  const f = await fixture(context);
  verifiedComplete(f.state); await f.save();
  delete f.state.jobs[0]!.attempts[0]!.proof;
  await atomicWriteJson(path.join(f.control, "case-state-sensitive.json"), { version: 1,
    sha256: digest({ config: f.config, state: f.state }), config: f.config, state: f.state });
  const status = await watchCaseService(f.control, f.commands.command, NOW);
  assert.equal(status.heartbeatStale, true);
  assert.equal(f.commands.event(), "failed");
});

test("case watchdog observation exceptions still attempt the independent fixed alert", linuxOnly, async (context) => {
  const f = await fixture(context);
  f.commands.observation = new Error("synthetic private systemctl exception");
  const status = await watchCaseService(f.control, f.commands.command, NOW);
  assert.equal(status.workerObservedActive, false);
  assert.equal(status.notificationRequired, true);
  assert.equal(f.commands.event(), "failed");
  assert.equal(JSON.stringify(status).includes("synthetic private"), false);
});

test("case watchdog notification exceptions are recorded for later retry", linuxOnly, async (context) => {
  const f = await fixture(context);
  f.state.health = "degraded"; await f.save();
  f.commands.delivery = new Error("synthetic private notification exception");
  const status = await watchCaseService(f.control, f.commands.command, NOW);
  assert.equal(status.deliveryAccepted, false);
  const notice = JSON.parse(await readFile(path.join(f.control, "notification-status-redacted.json"), "utf8"));
  assert.equal(notice.deliveryAccepted, false);
  f.commands.delivery = result();
  assert.equal((await watchCaseService(f.control, f.commands.command, NOW + 1000)).deliveryAccepted, true);
  assert.equal(f.commands.token(0), f.commands.token(1));
});

test("case watchdog rejects forged host identities before running commands", linuxOnly, async (context) => {
  const f = await fixture(context);
  const filename = path.join(f.control, "host-private.json");
  const receipt = JSON.parse(await readFile(filename, "utf8"));
  for (const mutation of [{ unit: "unrelated.service" }, { watchUnit: "unrelated-watch" }, { user: "-invalid" }, { bus: "tcp:host=synthetic.invalid" }]) {
    await atomicWriteJson(filename, { ...receipt, ...mutation });
    await assert.rejects(watchCaseService(f.control, f.commands.command, NOW), /invalid case host registration/u);
  }
  assert.equal(f.commands.calls.length, 0);
});

test("case watchdog refuses an unprotected control directory before using its registration", linuxOnly, async (context) => {
  const f = await fixture(context);
  await chmod(f.control, 0o755);
  await assert.rejects(watchCaseService(f.control, f.commands.command, NOW), /private directory/u);
  assert.equal(f.commands.calls.length, 0);
});
