import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { SystemdEngineHost, engineUnitName } from "../case/systemd.js";
import { verifyCompletedWorkflow } from "../case/verify.js";
import type { PreparedAttempt } from "../case/types.js";
import type { CommandOptions, CommandResult } from "../core/command.js";
import { loadWorkflowConfig } from "../workflow/config.js";
import { runWorkflow } from "../workflow/runner.js";
import { mkdtemp } from "./helpers.js";

const hash = (value: string) => createHash("sha256").update(value).digest("hex");
async function fixture(): Promise<{root: string; attempt: PreparedAttempt}> {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-case-systemd-test-"));
  const input = path.join(root, "input");
  await mkdir(input);
  const mnemonic = entropyToMnemonic(Buffer.alloc(16, 0x53), wordlist);
  await writeFile(path.join(input, "synthetic.txt"), mnemonic);
  const configFile = path.join(root, "workflow.json");
  await writeFile(configFile, JSON.stringify({version: 1, execute: true, output: path.join(root, "output"),
    scans: [{inputs: [input], provenance: "unknown"}], mining: {workers: 1, storage: {minFreeGiB: 0, minFreePercent: 0}},
    finalizationStorage: {minFreeGiB: 0, minFreePercent: 0}}));
  const workflow = await loadWorkflowConfig(configFile);
  return {root, attempt: {configFile, workflow, configHash: hash(JSON.stringify(workflow))}};
}
function result(executable: string, args: string[], stdout: string, extra: Partial<CommandResult> = {}): CommandResult {
  return {executable, args, exitCode: 0, signal: null, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0),
    stdoutTruncated: false, stderrTruncated: false, durationMs: 1, terminationReason: null, ...extra};
}
function manager() {
  const calls: Array<{executable: string; args: string[]; options: CommandOptions}> = [];
  let properties: Record<string, string> | undefined;
  let native: Record<string, unknown> = {status: "running", currentScanBytesScanned: 5};
  let timeoutProbe = false;
  let timeoutLaunch = false;
  const command = async (executable: string, args: string[], options: CommandOptions): Promise<CommandResult> => {
    calls.push({executable, args, options});
    if (args.includes("--version")) return result(executable, args, executable === process.execPath
      ? args.length === 1 ? "v24.0.0\n" : "0.1.0\n" : "systemd 259\n");
    if (args.includes("--property=Version")) return result(executable, args, "259\n");
    if (executable.endsWith("systemctl")) return result(executable, args, properties === undefined
      ? "LoadState=not-found\n" : Object.entries(properties).map(([key, value]) => `${key}=${value}`).join("\n"));
    if (executable.endsWith("systemd-run")) {
      properties = {LoadState: "loaded", ActiveState: "active", SubState: "running", Result: "success", MainPID: "100",
        ExecMainCode: "0", ExecMainStatus: "0", InvocationID: "a".repeat(32), Transient: "yes", Type: "exec", RemainAfterExit: "yes", Restart: "no", TasksAccounting: "yes", TasksCurrent: "1",
        ControlGroup: "/system.slice/" + args.find(value => value.startsWith("--unit="))!.slice("--unit=".length),
        Description: args.find(value => value.startsWith("--description="))!.slice("--description=".length)};
      return result(executable, args, "", timeoutLaunch ? {exitCode: 143, terminationReason: "timeout"} : {});
    }
    if (args[1] === "binding") return result(executable, args, '{"valid":true}');
    if (args[1] === "status") return result(executable, args, JSON.stringify(native), timeoutProbe ? {exitCode: 143, terminationReason: "timeout"} : {});
    if (args[1] === "verify") return result(executable, args, JSON.stringify({sha256: "b".repeat(64), scansVerified: 1, filesVerified: 1}));
    throw new Error("unexpected synthetic command");
  };
  return {calls, command, get properties() { return properties; }, set native(value: Record<string, unknown>) { native = value; },
    set timeoutProbe(value: boolean) { timeoutProbe = value; }, set timeoutLaunch(value: boolean) { timeoutLaunch = value; },
    forget() { properties = undefined; }};
}
const linux = {skip: process.platform !== "linux"};

test("host preflight checks privilege, binary versions, CLI availability, and manager connectivity without launching", linux, async t => {
  t.mock.method(process as NodeJS.Process & {getuid: () => number}, "getuid", () => 0);
  const f = await fixture();
  const host = manager();
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), command: host.command});
  await engine.preflight();
  assert.equal(host.calls.some(call => call.executable.endsWith("systemd-run") && !call.args.includes("--version")), false);
  assert(host.calls.some(call => call.args.includes("--property=Version")));
  const old = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "other-host"),
    command: async (executable, args, options) => executable.endsWith("systemd-run") && args.includes("--version")
      ? result(executable, args, "systemd 253\n") : await host.command(executable, args, options)});
  await assert.rejects(old.preflight(), /preflight failed/);
});

test("engine unit names use stable bounded hashes rather than caller syntax", () => {
  assert.equal(engineUnitName("synthetic token"), engineUnitName("synthetic token"));
  assert.match(engineUnitName("; $(synthetic) --scope"), /^aark-case-engine-[a-f0-9]{40}\.service$/);
  assert.notEqual(engineUnitName("first"), engineUnitName("second"));
  assert.throws(() => engineUnitName(""));
});

test("systemd launch is detached, bounded, reconciles client timeout, and reattaches idempotently", linux, async () => {
  const f = await fixture();
  const host = manager();
  host.timeoutLaunch = true;
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), probeTimeoutMs: 1234, command: host.command});
  const identity = await engine.launch(f.attempt, "persisted-token", "run");
  const again = await engine.launch(f.attempt, "persisted-token", "run");
  assert.deepEqual(identity, again);
  const launches = host.calls.filter(call => call.executable.endsWith("systemd-run"));
  assert.equal(launches.length, 1);
  const launch = launches[0]!;
  for (const argument of ["--service-type=exec", "--remain-after-exit", "--expand-environment=no", "--property=Restart=no", "--property=UMask=0077"]) assert(launch.args.includes(argument));
  for (const argument of ["--scope", "--wait", "--collect", "--pipe", "--pty"]) assert.equal(launch.args.includes(argument), false);
  assert.deepEqual(launch.args.slice(launch.args.indexOf("--") + 1), [process.execPath, path.resolve("dist/cli.js"), "workflow", "run", "--config", f.attempt.configFile,
    "--expected-config-hash", f.attempt.configHash, "--execute"]);
  assert(host.calls.every(call => call.options.timeoutMs === 1234 && call.options.stdoutFile === undefined && call.options.signal === undefined));
  assert.equal(host.calls.some(call => call.args.some(arg => ["kill", "stop", "restart", "reset-failed"].includes(arg))), false);
});

test("systemd launch refuses replacement or disappearance of an observed invocation", linux, async () => {
  const f = await fixture();
  const host = manager();
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), command: host.command});
  await engine.launch(f.attempt, "persisted-token", "run");
  host.properties!.InvocationID = "c".repeat(32);
  await assert.rejects(engine.launch(f.attempt, "persisted-token", "run"), /identity changed/);
  await assert.rejects(engine.launch(f.attempt, "persisted-token", "resume"), /identity changed/);
  host.forget();
  await assert.rejects(engine.launch(f.attempt, "persisted-token", "run"), /invocation disappeared/);
  assert.equal(host.calls.filter(call => call.executable.endsWith("systemd-run")).length, 1);
});

test("reattachment of an absent stable unit never launches an engine or creates hosting files", linux, async () => {
  const f = await fixture();
  const host = manager();
  const controlRoot = path.join(f.root, "host");
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot, command: host.command});
  assert.equal(await engine.reattach(f.attempt, "persisted-token", "run"), undefined);
  assert.equal(host.calls.every(call => call.executable.endsWith("systemctl")), true);
  await assert.rejects(access(controlRoot));
});

test("reattachment reconciles the matching invocation and can finalize only its pending receipt", linux, async () => {
  const f = await fixture();
  const host = manager();
  const options = {cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), command: host.command};
  const launched = await new SystemdEngineHost(options).launch(f.attempt, "persisted-token", "run");
  const receiptPath = path.join(options.controlRoot, "engines", `${launched.unit}.json`);
  const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
  delete receipt.invocationId;
  await writeFile(receiptPath, JSON.stringify(receipt));
  const engine = new SystemdEngineHost(options);
  assert.deepEqual(await engine.reattach(f.attempt, "persisted-token", "run"), launched);
  assert.equal(JSON.parse(await readFile(receiptPath, "utf8")).invocationId, launched.invocationId);
  assert.deepEqual(await engine.reattach(f.attempt, "persisted-token", "run"), launched);
  await assert.rejects(engine.reattach(f.attempt, "persisted-token", "resume"), /identity changed/);
  host.properties!.InvocationID = "c".repeat(32);
  await assert.rejects(engine.reattach(f.attempt, "persisted-token", "run"), /identity changed/);
  host.forget();
  assert.equal(await engine.reattach(f.attempt, "persisted-token", "run"), undefined);
  assert.equal(host.calls.filter(call => call.executable.endsWith("systemd-run")).length, 1);
});

test("observation distinguishes active engines, settled success, clean pauses, and unavailable probes", linux, async () => {
  const f = await fixture();
  const host = manager();
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), command: host.command});
  const identity = await engine.launch(f.attempt, "persisted-token", "run");
  host.native = {status: "complete", currentScanErrors: 0, currentScanFilesScanned: 1, currentScanBytesScanned: "sensitive injected value"};
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "running", filesScanned: 1, scanErrors: 0});
  Object.assign(host.properties!, {MainPID: "0", TasksCurrent: "0", SubState: "exited", ExecMainCode: "1", ExecMainStatus: "0"});
  assert.equal((await engine.observe(identity, f.attempt)).status, "complete");
  host.properties!.TasksCurrent = "1";
  assert.equal((await engine.observe(identity, f.attempt)).status, "unknown");
  host.properties!.TasksCurrent = "0";
  host.native = {status: "paused", resumable: true, pauseReason: "output-cap"};
  host.properties!.ExecMainStatus = "75";
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "paused", pauseReason: "output-cap"});
  host.timeoutProbe = true;
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "unknown"});
  host.timeoutProbe = false;
  host.properties!.InvocationID = "d".repeat(32);
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "unknown"});
  assert.equal(host.calls.some(call => call.args.includes("kill") || call.args.includes("restart")), false);
});

test("finished RemainAfterExit services support systemd's released-cgroup success and pause properties", linux, async () => {
  const f = await fixture();
  const host = manager();
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), command: host.command});
  const identity = await engine.launch(f.attempt, "persisted-token", "run");
  Object.assign(host.properties!, {ActiveState: "active", SubState: "exited", MainPID: "0", Result: "success",
    ExecMainCode: "1", ExecMainStatus: "0", TasksAccounting: "yes", TasksCurrent: "[not set]", ControlGroup: ""});
  host.native = {status: "complete"};
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "complete"});
  assert.equal((await engine.verify(f.attempt)).scansVerified, 1);
  host.properties!.ExecMainStatus = "75";
  host.native = {status: "paused", resumable: true, pauseReason: "output-cap"};
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "paused", pauseReason: "output-cap"});
  host.properties!.InvocationID = "c".repeat(32);
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "unknown"});
});

test("unset task counts need an explicitly released cgroup and zero task counts need the assigned unit cgroup", linux, async () => {
  const f = await fixture();
  const host = manager();
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), command: host.command});
  const identity = await engine.launch(f.attempt, "persisted-token", "run");
  Object.assign(host.properties!, {MainPID: "0", SubState: "exited", ExecMainCode: "1", ExecMainStatus: "0", TasksCurrent: "[not set]"});
  host.native = {status: "complete"};
  assert.equal((await engine.observe(identity, f.attempt)).status, "unknown");
  delete host.properties!.ControlGroup;
  assert.equal((await engine.observe(identity, f.attempt)).status, "unknown");
  host.properties!.ControlGroup = "";
  delete host.properties!.TasksCurrent;
  assert.equal((await engine.observe(identity, f.attempt)).status, "unknown");
  host.properties!.TasksCurrent = "0";
  host.properties!.ControlGroup = "/system.slice/unrelated.service";
  assert.equal((await engine.observe(identity, f.attempt)).status, "unknown");
  host.properties!.ControlGroup = `/system.slice/${identity.unit}`;
  assert.equal((await engine.observe(identity, f.attempt)).status, "complete");
});

test("a helper stuck after its deadline yields unknown and cannot accumulate duplicate probes", linux, async () => {
  const f = await fixture();
  const host = manager();
  let probes = 0;
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), probeTimeoutMs: 1,
    command: async (executable, args, options) => {
      if (args[1] === "status") { probes++; return await new Promise<CommandResult>(() => {}); }
      return await host.command(executable, args, options);
    }});
  const identity = await engine.launch(f.attempt, "persisted-token", "run");
  const observations = await Promise.all([engine.observe(identity, f.attempt), engine.observe(identity, f.attempt)]);
  assert.deepEqual(observations, [{status: "unknown"}, {status: "unknown"}]);
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "unknown"});
  assert.equal(probes, 1);
  assert.equal(host.calls.filter(call => call.executable.endsWith("systemd-run")).length, 1);
});

test("resume uses the native output gate and verification runs in a separate bounded helper", linux, async () => {
  const f = await fixture();
  const host = manager();
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), verificationTimeoutMs: 4321, command: host.command});
  const identity = await engine.launch(f.attempt, "resume-token", "resume");
  const launch = host.calls.find(call => call.executable.endsWith("systemd-run"))!;
  assert.deepEqual(launch.args.slice(launch.args.indexOf("--") + 1), [process.execPath, path.resolve("dist/cli.js"), "workflow", "resume", "--output", f.attempt.workflow.output,
    "--expected-config-hash", f.attempt.configHash, "--execute"]);
  Object.assign(host.properties!, {MainPID: "0", TasksCurrent: "0", SubState: "exited", ExecMainCode: "1", ExecMainStatus: "0"});
  host.native = {status: "complete"};
  await engine.observe(identity, f.attempt);
  assert.equal((await engine.verify(f.attempt)).scansVerified, 1);
  const proof = host.calls.find(call => call.args[1] === "verify")!;
  assert.equal(proof.executable, process.execPath);
  assert.equal(proof.options.timeoutMs, 4321);
  assert.equal(proof.args[2], f.attempt.configFile);
  assert.equal(proof.args[3], f.attempt.configHash);
});

test("completion verification requires sealed native scans and verifies packaged artifact bytes", async () => {
  const f = await fixture();
  await runWorkflow(f.attempt.configFile, {execute: true});
  const stateFile = path.join(f.attempt.workflow.output, "workflow-state-sensitive.json");
  const before = await readFile(stateFile);
  const proof = await verifyCompletedWorkflow(f.attempt);
  assert.match(proof.sha256, /^[a-f0-9]{64}$/);
  assert.equal(proof.scansVerified, 1);
  assert.equal(proof.filesVerified, 1);
  assert.deepEqual(await readFile(stateFile), before);
  await assert.rejects(access(path.join(f.attempt.workflow.output, ".aark-workflow.lock")));
  const lock = path.join(f.attempt.workflow.output, "mining", "scan-000001", ".aark-mining.lock");
  await writeFile(lock, "synthetic active operation");
  await assert.rejects(verifyCompletedWorkflow(f.attempt), /operation lock/);
  // Remove only the synthetic lock this test created, never a native operation lock.
  await unlink(lock);
  const index = JSON.parse(await readFile(path.join(f.attempt.workflow.output, "finalization-000001", "index-sensitive.json"), "utf8"));
  const artifact = path.join(f.attempt.workflow.output, "finalization-000001", index.findings[0].artifacts[0].path);
  await writeFile(artifact, "synthetic corruption");
  await assert.rejects(verifyCompletedWorkflow(f.attempt), /artifact integrity/);
  await assert.rejects(access(path.join(f.attempt.workflow.output, ".aark-workflow.lock")));
});

test("completion verification rejects a changed frozen input even when all result manifests still say complete", async () => {
  const f = await fixture();
  await runWorkflow(f.attempt.configFile, {execute: true});
  await writeFile(path.join(f.attempt.workflow.scans[0]!.inputs[0]!, "synthetic.txt"), "changed synthetic bytes");
  await assert.rejects(verifyCompletedWorkflow(f.attempt), /input coverage changed/);
  await assert.rejects(access(path.join(f.attempt.workflow.output, ".aark-workflow.lock")));
  await assert.rejects(access(path.join(f.attempt.workflow.output, "mining", "scan-000001", ".aark-mining.lock")));
});

test("completion verification ignores a forged progress snapshot and rejects changed sealed controls or configuration", async () => {
  const f = await fixture();
  await mkdir(f.attempt.workflow.output);
  await writeFile(path.join(f.attempt.workflow.output, "progress-redacted.json"), JSON.stringify({status: "complete"}));
  await assert.rejects(verifyCompletedWorkflow(f.attempt));
  const valid = await fixture();
  await runWorkflow(valid.attempt.configFile, {execute: true});
  const state = path.join(valid.attempt.workflow.output, "workflow-state-sensitive.json");
  await writeFile(state, (await readFile(state, "utf8")) + " ");
  await assert.rejects(verifyCompletedWorkflow(valid.attempt), /sealed completion/);
  await writeFile(valid.attempt.configFile, JSON.stringify({...valid.attempt.workflow, execute: false}));
  await assert.rejects(verifyCompletedWorkflow(valid.attempt), /configuration/);
});
