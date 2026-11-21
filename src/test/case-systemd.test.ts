import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { access, mkdir, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { SystemdEngineHost, engineUnitName } from "../case/systemd.js";
import { verifyCompletedWorkflow } from "../case/verify.js";
import type { CaseConfig, PreparedAttempt } from "../case/types.js";
import type { CommandOptions, CommandResult } from "../core/command.js";
import { loadWorkflowConfig } from "../workflow/config.js";
import { runWorkflow } from "../workflow/runner.js";
import { mkdtemp } from "./helpers.js";
import { CaseSourceIdentityError } from "../case/sources.js";
import { EngineLaunchCancelledError, EngineLaunchDeferredError, EngineLaunchRefusedError } from "../case/launch-error.js";
import { bindingProbeTimeoutMs, capacityProbeTimeoutMs, caseMetadataProbeBudget,
  RECOVERY_BINDING_TIMEOUT_MS, RECOVERY_CAPACITY_TIMEOUT_MS } from "../case/probe-budget.js";

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
async function recoveryFixture() {
  const f = await fixture();
  const recoveryFile = path.join(f.root, "recovery.json"), source = path.join(f.root, "source.img"), destination = path.join(f.root, "recovered");
  await writeFile(source, "ordinary synthetic image\n");
  await writeFile(recoveryFile, JSON.stringify({version: 1, caseId: "synthetic-budget", execute: true, requireReadOnlySource: true,
    source, destination, image: {enabled: false},
    stages: {deletedMetadata: false, ntfsUndelete: false, unallocatedStream: true, signatureCarving: false,
      volumeShadows: false, residualMemory: false, deletedRegistryCells: false}}));
  const document = JSON.parse(await readFile(f.attempt.configFile, "utf8"));
  await writeFile(f.attempt.configFile, JSON.stringify({...document, recoveryConfig: recoveryFile,
    scans: [{inputs: [path.join(destination, "recovery", "unallocated", "free-space.raw")], provenance: "unallocated-stream"}]}));
  const workflow = await loadWorkflowConfig(f.attempt.configFile);
  return {...f, attempt: {...f.attempt, workflow, configHash: hash(JSON.stringify(workflow))}};
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
    if (args[0]?.endsWith("capacity.js")) return result(executable, args, '{"ready":true}');
    if (args[1] === "status") return result(executable, args, JSON.stringify(native), timeoutProbe ? {exitCode: 143, terminationReason: "timeout"} : {});
    if (args[1] === "verify") return result(executable, args, JSON.stringify({sha256: "b".repeat(64), scansVerified: 1, filesVerified: 1}));
    throw new Error("unexpected synthetic command");
  };
  return {calls, command, get properties() { return properties; }, set native(value: Record<string, unknown>) { native = value; },
    set timeoutProbe(value: boolean) { timeoutProbe = value; }, set timeoutLaunch(value: boolean) { timeoutLaunch = value; },
    forget() { properties = undefined; }};
}
const linux = {skip: process.platform !== "linux"};

function barrier() {
  let resolve = () => {};
  const promise = new Promise<void>(done => { resolve = done; });
  return {promise, resolve};
}

for (const stage of ["probe", "logs"] as const) {
  test(`aborting ${stage} preflight prevents systemd submission without classifying engine failure`, linux, async context => {
    const f = await fixture(), host = manager();
    context.after(() => rm(f.root, {recursive: true, force: true}));
    const entered = barrier(), release = barrier(), controller = new AbortController();
    context.after(() => { controller.abort(); release.resolve(); });
    const controlRoot = path.join(f.root, "host");
    const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot,
      command: async (executable, args, options) => {
        if (stage === "probe" && args[1] === "binding") { entered.resolve(); await release.promise; }
        return await host.command(executable, args, options);
      }});
    const originalOpen = fs.promises.open;
    fs.promises.open = async (filename, flags, mode) => {
      if (stage === "logs" && typeof filename === "string" && filename.endsWith(".stderr.log")) {
        entered.resolve(); await release.promise;
      }
      return await originalOpen(filename, flags, mode);
    };
    syncBuiltinESMExports();
    try {
      const launching = engine.launch(f.attempt, "cancelled-token", "run", controller.signal);
      const cancelled = assert.rejects(launching, EngineLaunchCancelledError);
      await entered.promise;
      controller.abort(); release.resolve();
      await cancelled;
    } finally { fs.promises.open = originalOpen; syncBuiltinESMExports(); }
    assert.equal(host.calls.some(call => call.executable.endsWith("systemd-run")), false);
    const receiptPath = path.join(controlRoot, "engines", `${engineUnitName("cancelled-token")}.json`);
    assert.equal(JSON.parse(await readFile(receiptPath, "utf8")).phase, "prepared");
    assert.equal(JSON.parse(await readFile(receiptPath, "utf8")).invocationId, undefined);
    const identity = await engine.launch(f.attempt, "cancelled-token", "run");
    assert.equal(identity.unit, engineUnitName("cancelled-token"));
    assert.equal(host.calls.filter(call => call.executable.endsWith("systemd-run")).length, 1);
    assert.ok(host.calls.filter(call => call.args[1] !== "binding" && !call.args[0]?.endsWith("capacity.js")).every(call => call.options.signal === undefined));
    assert.equal(host.calls.some(call => call.args.some(arg => ["kill", "stop", "restart"].includes(arg))), false);
  });
}

test("cancellation after systemd submission leaves the independent engine and client intact", linux, async context => {
  const f = await fixture(), host = manager();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const entered = barrier(), release = barrier(), controller = new AbortController();
  context.after(() => { controller.abort(); release.resolve(); });
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"),
    command: async (executable, args, options) => {
      const completed = await host.command(executable, args, options);
      if (executable.endsWith("systemd-run")) { entered.resolve(); await release.promise; }
      return completed;
    }});
  const launching = engine.launch(f.attempt, "already-submitted-token", "run", controller.signal);
  await entered.promise;
  controller.abort(); release.resolve();
  const identity = await launching;
  assert.equal(identity.invocationId, "a".repeat(32));
  assert.equal(host.calls.filter(call => call.executable.endsWith("systemd-run")).length, 1);
  assert.ok(host.calls.filter(call => call.args[1] !== "binding" && !call.args[0]?.endsWith("capacity.js")).every(call => call.options.signal === undefined));
  assert.equal(host.calls.some(call => call.args.some(arg => ["kill", "stop", "restart"].includes(arg))), false);
});

test("prepared receipts remain provably unsubmitted across repeated cancellation and host restarts", linux, async context => {
  const f = await fixture(), host = manager();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const controlRoot = path.join(f.root, "host");
  const receiptPath = path.join(controlRoot, "engines", `${engineUnitName("repeat-cancelled")}.json`);
  const originalOpen = fs.promises.open;
  let controller = new AbortController();
  fs.promises.open = async (filename, flags, mode) => {
    if (typeof filename === "string" && filename.endsWith(".stderr.log")) controller.abort();
    return await originalOpen(filename, flags, mode);
  };
  syncBuiltinESMExports();
  try {
    for (let iteration = 0; iteration < 3; iteration++) {
      controller = new AbortController();
      const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot, command: host.command});
      await assert.rejects(engine.launch(f.attempt, "repeat-cancelled", "run", controller.signal), EngineLaunchCancelledError);
      const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
      assert.equal(receipt.version, 2);
      assert.equal(receipt.phase, "prepared");
      assert.equal(receipt.invocationId, undefined);
      await assert.rejects(engine.reattach(f.attempt, "repeat-cancelled", "run"), EngineLaunchCancelledError);
    }
  } finally { fs.promises.open = originalOpen; syncBuiltinESMExports(); }
  assert.equal(host.calls.some(call => call.executable.endsWith("systemd-run")), false);
});

test("a cancelled queued launch still proves its durable prepared state before returning cancellation", linux, async context => {
  const f = await fixture(), host = manager();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const controlRoot = path.join(f.root, "host"), controller = new AbortController();
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot, command: host.command});
  const launching = engine.launch(f.attempt, "cancel-before-entry", "run", controller.signal);
  controller.abort();
  await assert.rejects(launching, EngineLaunchCancelledError);
  assert.equal(host.calls.every(call => call.executable.endsWith("systemctl")), true);
  await assert.rejects(access(controlRoot));
});

test("a committed submitting phase stays unknown after cancellation before the client starts", linux, async context => {
  const f = await fixture(), host = manager();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const controlRoot = path.join(f.root, "host");
  const receiptPath = path.join(controlRoot, "engines", `${engineUnitName("commit-cancelled")}.json`);
  const controller = new AbortController(), originalRename = fs.promises.rename;
  fs.promises.rename = async (source, destination) => {
    if (destination === receiptPath && JSON.parse(await readFile(source, "utf8")).phase === "submitting") controller.abort();
    await originalRename(source, destination);
  };
  syncBuiltinESMExports();
  try {
    const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot, command: host.command});
    await assert.rejects(engine.launch(f.attempt, "commit-cancelled", "run", controller.signal),
      error => error instanceof Error && !(error instanceof EngineLaunchCancelledError) && !(error instanceof EngineLaunchRefusedError));
  } finally { fs.promises.rename = originalRename; syncBuiltinESMExports(); }
  assert.equal(JSON.parse(await readFile(receiptPath, "utf8")).phase, "submitting");
  assert.equal(host.calls.some(call => call.executable.endsWith("systemd-run")), false);
  const restarted = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot, command: host.command});
  assert.equal(await restarted.reattach(f.attempt, "commit-cancelled", "run"), undefined);
});

test("legacy receipts never acquire an unsubmitted proof and observed legacy invocations upgrade safely", linux, async context => {
  const f = await fixture(), host = manager();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const controlRoot = path.join(f.root, "host");
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot, command: host.command});
  const identity = await engine.launch(f.attempt, "legacy-token", "run");
  const receiptPath = path.join(controlRoot, "engines", `${identity.unit}.json`);
  const current = JSON.parse(await readFile(receiptPath, "utf8"));
  await writeFile(receiptPath, JSON.stringify({version: 1, binding: current.binding, invocationId: identity.invocationId}));
  const restarted = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot, command: host.command});
  assert.deepEqual(await restarted.reattach(f.attempt, "legacy-token", "run"), identity);
  assert.equal(JSON.parse(await readFile(receiptPath, "utf8")).phase, "submitting");
  host.forget();
  await writeFile(receiptPath, JSON.stringify({version: 1, binding: current.binding}));
  assert.equal(await restarted.reattach(f.attempt, "legacy-token", "run"), undefined);
  const controller = new AbortController();
  const cancelled = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot,
    command: async (executable, args, options) => {
      if (args[1] === "binding") controller.abort();
      return await host.command(executable, args, options);
    }});
  await assert.rejects(cancelled.launch(f.attempt, "legacy-token", "run", controller.signal),
    error => error instanceof Error && !(error instanceof EngineLaunchCancelledError) && !(error instanceof EngineLaunchRefusedError));
  assert.equal(JSON.parse(await readFile(receiptPath, "utf8")).version, 1);
});

test("same-token launch calls serialize their durable submission and attach to one invocation", linux, async context => {
  const f = await fixture(), host = manager();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const controlRoot = path.join(f.root, "host"), entered = barrier(), release = barrier();
  context.after(() => release.resolve());
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot,
    command: async (executable, args, options) => {
      if (executable.endsWith("systemd-run")) {
        const receipt = JSON.parse(await readFile(path.join(controlRoot, "engines", `${engineUnitName("concurrent-token")}.json`), "utf8"));
        assert.equal(receipt.phase, "submitting", "the submission intent is durable before entering the command runner");
        entered.resolve(); await release.promise;
      }
      return await host.command(executable, args, options);
    }});
  const first = engine.launch(f.attempt, "concurrent-token", "run");
  await entered.promise;
  const second = engine.launch(f.attempt, "concurrent-token", "run");
  release.resolve();
  assert.deepEqual(await second, await first);
  assert.equal(host.calls.filter(call => call.executable.endsWith("systemd-run")).length, 1);
});

test("receipt versions and submission phases reject contradictory or unknown control fields", linux, async context => {
  const f = await fixture(), host = manager();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const controlRoot = path.join(f.root, "host");
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot, command: host.command});
  const identity = await engine.launch(f.attempt, "strict-receipt", "run");
  const receiptPath = path.join(controlRoot, "engines", `${identity.unit}.json`);
  const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
  const calls = host.calls.length;
  for (const value of [{...receipt, phase: "prepared"}, {...receipt, phase: "unknown"}, {...receipt, version: 3},
    {...receipt, extra: true}, {version: 1, binding: receipt.binding, phase: "prepared"}]) {
    await writeFile(receiptPath, JSON.stringify(value));
    await assert.rejects(engine.reattach(f.attempt, "strict-receipt", "run"), /receipt unavailable/);
  }
  assert.equal(host.calls.length, calls, "malformed receipts cannot cause any command probe or submission");
  await writeFile(receiptPath, JSON.stringify({version: 2, phase: "prepared", binding: receipt.binding}));
  await assert.rejects(engine.reattach(f.attempt, "strict-receipt", "run"), /identity changed/,
    "a prepared receipt cannot claim an already-present invocation");
});

test("immutable local launch refusals are explicit and cannot create an engine or receipt", linux, async context => {
  const f = await fixture();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const host = manager();
  const control = path.join(f.root, "host");
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: control, command: host.command});
  const output = {...f.attempt.workflow, output: path.join(f.root, "output%reviewed")};
  for (const attempt of [{...f.attempt, configFile: path.join(f.root, "workflow%reviewed.json")},
    {...f.attempt, configHash: "0".repeat(64)}, {...f.attempt, workflow: output, configHash: hash(JSON.stringify(output))}]) {
    await assert.rejects(engine.launch(attempt, "unsubmitted-token", "run"), EngineLaunchRefusedError);
    await assert.rejects(engine.reattach(attempt, "unsubmitted-token", "run"), EngineLaunchRefusedError);
  }
  assert.equal(host.calls.length, 0);
  await assert.rejects(access(control));
});

test("an unavailable binding observation defers an absent unit without failing its attempt", linux, async context => {
  const f = await fixture();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const host = manager();
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"),
    command: async (executable, args, options) => args[1] === "binding" ? result(executable, args, '{"status":"unknown"}', {exitCode: 1})
      : host.command(executable, args, options)});
  await assert.rejects(engine.launch(f.attempt, "refused-token", "run"), error => error instanceof EngineLaunchDeferredError
    && error.unsubmitted === true && error.reason === "observation-unavailable");
  assert.equal(host.calls.some(call => call.executable.endsWith("systemd-run")), false);
  assert.equal(JSON.parse(await readFile(path.join(f.root, "host", "engines", `${engineUnitName("refused-token")}.json`), "utf8")).phase, "prepared");
  await assert.rejects(access(f.attempt.workflow.output));
});

test("a submitted launch and its existing receipt never become definitive prelaunch refusals", linux, async context => {
  const f = await fixture();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const host = manager();
  let denyBinding = false;
  let submitted = 0;
  let cancelOnBinding: AbortController | undefined;
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"),
    command: async (executable, args, options) => {
      if (executable.endsWith("systemd-run")) { submitted++; return result(executable, args, "", {exitCode: 143, terminationReason: "timeout"}); }
      if (args[1] === "binding") {
        cancelOnBinding?.abort();
        if (denyBinding) return result(executable, args, '{"status":"unknown"}', {exitCode: 1});
      }
      return host.command(executable, args, options);
    }});
  const unknown = (error: unknown) => error instanceof Error && !(error instanceof EngineLaunchRefusedError);
  await assert.rejects(engine.launch(f.attempt, "uncertain-token", "run"), unknown);
  assert.equal(submitted, 1);
  denyBinding = true;
  await assert.rejects(engine.launch(f.attempt, "uncertain-token", "run"), unknown);
  const invalid = {...f.attempt, configFile: path.join(f.root, "workflow%reviewed.json")};
  await assert.rejects(engine.launch(invalid, "uncertain-token", "run"), unknown);
  await assert.rejects(engine.reattach(invalid, "uncertain-token", "run"), unknown);
  cancelOnBinding = new AbortController();
  await assert.rejects(engine.launch(f.attempt, "uncertain-token", "run", cancelOnBinding.signal),
    error => unknown(error) && !(error instanceof EngineLaunchCancelledError));
  assert.equal(submitted, 1);
});

test("unavailable unit observations cannot prove a prelaunch refusal", linux, async context => {
  const f = await fixture();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  for (const observation of [{exitCode: 143, terminationReason: "timeout" as const}, {exitCode: 1}, {stdoutTruncated: true},
    {stderrTruncated: true}, {text: "LoadState=loaded\nLoadState=not-found\n"}]) {
    let commands = 0;
    const {text, ...extra} = observation as Partial<CommandResult> & {text?: string};
    const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"),
      command: async (executable, args) => { commands++; return result(executable, args, text ?? "LoadState=not-found\n", extra); }});
    await assert.rejects(engine.launch(f.attempt, "unobserved-token", "run"), error => error instanceof Error && !(error instanceof EngineLaunchRefusedError));
    assert.equal(commands, 1);
  }
  await assert.rejects(access(path.join(f.root, "host")));
});

test("changed case source authorization stops before any engine is started", linux, async () => {
  const f = await fixture();
  const recoveryConfig = path.join(f.root, "recovery.json");
  const source = path.join(f.root, "source.img");
  await writeFile(source, "ordinary synthetic source");
  await writeFile(recoveryConfig, JSON.stringify({version: 1, caseId: "synthetic-source-pin", execute: true, requireReadOnlySource: true,
    source, destination: path.join(f.root, "recovery"), image: {enabled: false},
    stages: {deletedMetadata: false, unallocatedStream: false, signatureCarving: false}}));
  const document = JSON.parse(await readFile(f.attempt.configFile, "utf8"));
  await writeFile(f.attempt.configFile, JSON.stringify({...document, recoveryConfig}));
  const workflow = await loadWorkflowConfig(f.attempt.configFile);
  const attempt = {...f.attempt, workflow, configHash: hash(JSON.stringify(workflow))};
  const pins = [{source, sha256: "a".repeat(64)}];
  const host = manager();
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"),
    sourceBindings: {[attempt.configHash]: pins}, command: async (executable, args, options) => {
      if (args[1] === "binding") {
        assert.equal(args[4], JSON.stringify(pins));
        return result(executable, args, '{"valid":false,"reason":"source-identity-changed"}', {exitCode: 2});
      }
      return await host.command(executable, args, options);
    }});
  await assert.rejects(engine.launch(attempt, "synthetic-source-token", "run"), CaseSourceIdentityError);
  assert.equal(host.calls.some(call => call.executable.endsWith("systemd-run")), false);
  await assert.rejects(access(workflow.output));
  const unregistered = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "unregistered-host"), command: host.command});
  const calls = host.calls.length;
  await assert.rejects(unregistered.launch(attempt, "missing-source-authorization", "run"), error => error instanceof Error && !(error instanceof EngineLaunchRefusedError));
  assert.equal(host.calls.length, calls, "missing authorization is not an absence proof");
});

test("quota readiness uses an isolated bounded helper and rejects unavailable or malformed replies", linux, async () => {
  const f = await fixture();
  const replies: Array<Partial<CommandResult> & {text?: string}> = [{text: '{"ready":false}'}, {text: '{"ready":true}'},
    {text: '{"ready":true}', terminationReason: "timeout"}, {text: '{"ready":false}', exitCode: 1}, {text: '{"ready":"true"}'}, {text: '{"ready":true,"error":"synthetic-private"}'}];
  let calls = 0;
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), probeTimeoutMs: 123,
    command: async (executable, args, options) => {
      assert.equal(executable, process.execPath);
      assert.equal(path.basename(args[0]!), "capacity.js");
      assert.deepEqual(args.slice(1), [f.attempt.configFile, f.attempt.configHash]);
      assert.equal(options.timeoutMs, 123);
      const {text, ...changes} = replies[calls++]!;
      return result(executable, args, text ?? "", changes);
    }});
  assert.equal(await engine.resumeReady(f.attempt), false);
  assert.equal(await engine.resumeReady(f.attempt), true);
  for (let index = 0; index < 4; index++) await assert.rejects(engine.resumeReady(f.attempt), /readiness observation unavailable/);
  assert.equal(calls, 6);
  await assert.rejects(access(path.join(f.root, "host")));
});

test("recovery metadata budgets cover sequential binding and quota probes without changing ordinary status deadlines", linux, async context => {
  const ordinary = await fixture(), f = await recoveryFixture(), host = manager();
  context.after(() => rm(ordinary.root, {recursive: true, force: true}));
  context.after(() => rm(f.root, {recursive: true, force: true}));
  assert.equal(bindingProbeTimeoutMs(ordinary.attempt, 123), 123);
  assert.equal(capacityProbeTimeoutMs(ordinary.attempt, 123), 123);
  assert.equal(bindingProbeTimeoutMs(f.attempt, 123), RECOVERY_BINDING_TIMEOUT_MS);
  assert.equal(capacityProbeTimeoutMs(f.attempt, 123), RECOVERY_CAPACITY_TIMEOUT_MS);
  const config = {probeTimeoutMs: 123, jobs: [{attempts: [f.attempt], resumeAfterQuota: false}]} as CaseConfig;
  assert.equal(caseMetadataProbeBudget(config), RECOVERY_BINDING_TIMEOUT_MS);
  config.jobs[0]!.resumeAfterQuota = true;
  assert.equal(caseMetadataProbeBudget(config), RECOVERY_BINDING_TIMEOUT_MS + RECOVERY_CAPACITY_TIMEOUT_MS);
  const signal = new AbortController().signal;
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), probeTimeoutMs: 123,
    sourceBindings: {[f.attempt.configHash]: []}, command: async (executable, args, options) => {
      const binding = args[1] === "binding", capacity = args[0]?.endsWith("capacity.js");
      assert.equal(options.timeoutMs, binding ? RECOVERY_BINDING_TIMEOUT_MS : capacity ? RECOVERY_CAPACITY_TIMEOUT_MS : 123);
      assert.equal(options.signal, binding || capacity ? signal : undefined);
      return await host.command(executable, args, options);
    }});
  const identity = await engine.launch(f.attempt, "aggregate-budget", "resume", signal);
  await engine.observe(identity, f.attempt);
  assert.ok(host.calls.some(call => call.args[1] === "binding"));
  assert.ok(host.calls.some(call => call.args[0]?.endsWith("capacity.js")));
  assert.ok(host.calls.some(call => call.args[1] === "status"));
});

for (const phase of ["prepared", "submitting", "legacy"] as const) {
  test(`an absent ${phase} resume waits for fresh host capacity after binding and log work`, linux, async context => {
    const f = await fixture(), host = manager(), order: string[] = [];
    context.after(() => rm(f.root, {recursive: true, force: true}));
    const controlRoot = path.join(f.root, "host");
    let ready = false;
    const command = async (executable: string, args: string[], options: CommandOptions) => {
      if (args[1] === "binding") order.push("binding");
      if (args[0]?.endsWith("capacity.js")) { order.push("capacity"); return result(executable, args, JSON.stringify({ready})); }
      if (executable.endsWith("systemd-run")) order.push("submit");
      return await host.command(executable, args, options);
    };
    const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot, command});
    await assert.rejects(engine.launch(f.attempt, "capacity-boundary", "resume"), error => error instanceof EngineLaunchDeferredError
      && error.unsubmitted === true && error.reason === "capacity-wait");
    const receiptPath = path.join(controlRoot, "engines", `${engineUnitName("capacity-boundary")}.json`);
    const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
    if (phase !== "prepared") await writeFile(receiptPath, JSON.stringify(phase === "legacy"
      ? {version: 1, binding: receipt.binding} : {...receipt, phase: "submitting"}));
    const restarted = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot, command});
    await assert.rejects(restarted.launch(f.attempt, "capacity-boundary", "resume"), error => error instanceof EngineLaunchDeferredError
      && error.unsubmitted === (phase === "prepared") && error.reason === "capacity-wait");
    assert.equal(host.calls.some(call => call.executable.endsWith("systemd-run")), false);
    const pending = JSON.parse(await readFile(receiptPath, "utf8"));
    assert.equal(pending.version, phase === "legacy" ? 1 : 2);
    assert.equal(pending.phase, phase === "legacy" ? undefined : phase);
    ready = true;
    await restarted.launch(f.attempt, "capacity-boundary", "resume");
    assert.deepEqual(order, ["binding", "capacity", "binding", "capacity", "binding", "capacity", "submit"]);
  });
}

test("metadata timeout and helper unavailability defer the same prepared attempt and recover later", linux, async context => {
  const f = await fixture(), host = manager();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  let observation: "timeout" | "unavailable" | "ready" = "timeout";
  const controlRoot = path.join(f.root, "host");
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot, bindingTimeoutMs: 2,
    command: async (executable, args, options) => {
      if (args[1] === "binding") {
        assert.equal(options.timeoutMs, 2);
        const prepared = JSON.parse(await readFile(path.join(controlRoot, "engines", `${engineUnitName("deferred-binding")}.json`), "utf8"));
        assert.equal(prepared.phase, "prepared", "the durable unsubmitted proof precedes the slow observation");
        if (observation === "unavailable") throw new Error("synthetic unavailable metadata helper");
        if (observation === "timeout") return result(executable, args, "", {exitCode: 143, terminationReason: "timeout"});
      }
      return await host.command(executable, args, options);
    }});
  for (const state of ["timeout", "unavailable"] as const) {
    observation = state;
    await assert.rejects(engine.launch(f.attempt, "deferred-binding", "run"), error => error instanceof EngineLaunchDeferredError
      && error.unsubmitted && error.reason === "observation-unavailable");
  }
  assert.equal(host.calls.some(call => call.executable.endsWith("systemd-run")), false);
  observation = "ready";
  const identity = await engine.launch(f.attempt, "deferred-binding", "run");
  assert.equal(identity.unit, engineUnitName("deferred-binding"));
  assert.equal(host.calls.filter(call => call.executable.endsWith("systemd-run")).length, 1);
});

test("unavailable host quota probes defer instead of submitting", linux, async context => {
  const f = await fixture(), host = manager();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), capacityTimeoutMs: 3,
    command: async (executable, args, options) => {
      if (args[0]?.endsWith("capacity.js")) {
        assert.equal(options.timeoutMs, 3);
        return result(executable, args, '{"ready":true}', {exitCode: 143, terminationReason: "timeout"});
      }
      return await host.command(executable, args, options);
    }});
  await assert.rejects(engine.launch(f.attempt, "deferred-capacity", "resume"), error => error instanceof EngineLaunchDeferredError
    && error.unsubmitted && error.reason === "observation-unavailable");
  assert.equal(host.calls.some(call => call.executable.endsWith("systemd-run")), false);
});

test("the host boundary waits for a fresh quota probe instead of reusing a timed-out helper", linux, async context => {
  const f = await fixture(), host = manager();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  let calls = 0, release!: () => void;
  const waiting = new Promise<void>(resolve => { release = resolve; });
  context.after(() => release());
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), capacityTimeoutMs: 1,
    command: async (executable, args, options) => {
      if (args[0]?.endsWith("capacity.js")) {
        assert.equal(options.waitForGroupExit, true, "the helper promise includes all live group members");
        calls++;
        if (calls === 1) await waiting;
        return result(executable, args, '{"ready":true}');
      }
      return await host.command(executable, args, options);
    }});
  await assert.rejects(engine.resumeReady(f.attempt), /deadline exceeded/);
  await assert.rejects(engine.launch(f.attempt, "fresh-capacity", "resume"), error => error instanceof EngineLaunchDeferredError
    && error.unsubmitted && error.reason === "observation-unavailable");
  assert.equal(calls, 1);
  assert.equal(host.calls.some(call => call.executable.endsWith("systemd-run")), false);
  release();
  await new Promise<void>(resolve => setImmediate(resolve));
  await engine.launch(f.attempt, "fresh-capacity", "resume");
  assert.equal(calls, 2);
  assert.equal(host.calls.filter(call => call.executable.endsWith("systemd-run")).length, 1);
});

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

test("settled systemd startup failure is observed without native progress or output", linux, async () => {
  const f = await fixture();
  const host = manager();
  let nativeProbes = 0;
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"),
    command: async (executable, args, options) => {
      if (args[1] === "status") { nativeProbes++; throw new Error("synthetic unavailable native progress"); }
      return await host.command(executable, args, options);
    }});
  const identity = await engine.launch(f.attempt, "startup-refusal-token", "run");
  // The native expected-config-hash guard can refuse before creating output.
  Object.assign(host.properties!, {ActiveState: "failed", SubState: "failed", Result: "exit-code",
    MainPID: "0", TasksCurrent: "0", ExecMainCode: "1", ExecMainStatus: "1"});
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "failed"});
  assert.ok(nativeProbes <= 1, "unavailable diagnostics must not hide proven failure or cause repeated probes");
  await assert.rejects(access(f.attempt.workflow.output));
  assert.deepEqual(await engine.launch(f.attempt, "startup-refusal-token", "run"), identity);
  assert.equal(host.calls.filter(call => call.executable.endsWith("systemd-run")).length, 1);
});

test("abruptly killed empty-cgroup invocation is failed even when native status looks paused", linux, async () => {
  const f = await fixture();
  const host = manager();
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), command: host.command});
  const identity = await engine.launch(f.attempt, "killed-token", "run");
  host.native = {status: "paused", resumable: true, pauseReason: "free-space-reserve"};
  Object.assign(host.properties!, {ActiveState: "failed", SubState: "failed", Result: "signal", MainPID: "0",
    TasksCurrent: "[not set]", ControlGroup: "", ExecMainCode: "2", ExecMainStatus: "9"});
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "failed"});
  assert.equal(host.calls.some(call => call.args.some(arg => ["kill", "stop", "restart"].includes(arg))), false);
});

test("a confirmed engine failure still preserves available fixed diagnostics and progress", linux, async () => {
  const f = await fixture(), host = manager();
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"), command: host.command});
  const identity = await engine.launch(f.attempt, "failed-with-progress", "run");
  Object.assign(host.properties!, {ActiveState: "failed", SubState: "failed", Result: "exit-code", MainPID: "0", ExecMainCode: "1",
    ExecMainStatus: "1", TasksCurrent: "[not set]", ControlGroup: ""});
  host.native = {status: "failed", failureCode: "scan-completed-with-errors", currentScanErrors: 1, currentScanBytesScanned: 128};
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "failed", failureCode: "scan-completed-with-errors", scanErrors: 1, bytesScanned: 128});
});

test("missing native progress cannot turn unproven cgroup death into failure or authorize replacement", linux, async () => {
  const f = await fixture();
  const host = manager();
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"),
    command: async (executable, args, options) => args[1] === "status"
      ? result(executable, args, '{"status":"unknown"}', {exitCode: 1}) : await host.command(executable, args, options)});
  const identity = await engine.launch(f.attempt, "unsettled-token", "run");
  Object.assign(host.properties!, {ActiveState: "failed", SubState: "failed", Result: "signal", MainPID: "0",
    TasksCurrent: "1", ExecMainCode: "2", ExecMainStatus: "9"});
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "unknown"});
  host.properties!.TasksCurrent = "0";
  host.properties!.MainPID = "100";
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "unknown"});
  host.properties!.MainPID = "0";
  host.properties!.ControlGroup = "/system.slice/unrelated.service";
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "unknown"});
  Object.assign(host.properties!, {ActiveState: "active", SubState: "running", MainPID: "100", TasksCurrent: "1",
    ControlGroup: `/system.slice/${identity.unit}`});
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "unknown"});
  assert.deepEqual(await engine.launch(f.attempt, "unsettled-token", "run"), identity);
  assert.equal(host.calls.filter(call => call.executable.endsWith("systemd-run")).length, 1);
});

test("successful exits without native progress prove neither completion nor clean pause", linux, async () => {
  const f = await fixture();
  const host = manager();
  const engine = new SystemdEngineHost({cliPath: path.resolve("dist/cli.js"), controlRoot: path.join(f.root, "host"),
    command: async (executable, args, options) => args[1] === "status"
      ? result(executable, args, '{"status":"unknown"}', {exitCode: 1}) : await host.command(executable, args, options)});
  const identity = await engine.launch(f.attempt, "missing-status-token", "run");
  Object.assign(host.properties!, {ActiveState: "active", SubState: "exited", Result: "success", MainPID: "0",
    TasksCurrent: "0", ExecMainCode: "1", ExecMainStatus: "0"});
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "unknown"});
  host.properties!.ExecMainStatus = "75";
  assert.deepEqual(await engine.observe(identity, f.attempt), {status: "unknown"});
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

for (const mutation of ["file-content", "deep-file", "deep-empty-directory"] as const) {
  test(`completion verification rejects ${mutation} changes after initial source coverage verification`, linux, async context => {
    const f = await fixture();
    context.after(() => rm(f.root, {recursive: true, force: true}));
    const source = f.attempt.workflow.scans[0]!.inputs[0]!;
    const deep = path.join(source, "existing", "nested");
    await mkdir(deep, {recursive: true});
    await runWorkflow(f.attempt.configFile, {execute: true});
    const output = f.attempt.workflow.output;
    const stateFile = path.join(output, "workflow-state-sensitive.json");
    const before = await readFile(stateFile);
    const indexFile = path.join(output, "finalization-000001", "index-sensitive.json");
    const originalOpen = fs.promises.open;
    let changed = false;
    const injected: typeof fs.promises.open = async (filename, flags, mode) => {
      // Package-index hashing happens after every scan's first coverage walk.
      if (filename === indexFile && !changed) {
        changed = true;
        if (mutation === "file-content") await writeFile(path.join(source, "synthetic.txt"), "changed synthetic bytes");
        else if (mutation === "deep-file") await writeFile(path.join(deep, "new.txt"), "new synthetic bytes");
        else await mkdir(path.join(deep, "new-empty"));
      }
      return await originalOpen(filename, flags, mode);
    };
    fs.promises.open = injected;
    syncBuiltinESMExports();
    try {
      await assert.rejects(verifyCompletedWorkflow(f.attempt), /input coverage changed|unscanned inputs|source snapshot changed/u);
    } finally {
      fs.promises.open = originalOpen;
      syncBuiltinESMExports();
    }
    assert.equal(changed, true, "the synthetic mutation must occur inside verification");
    assert.deepEqual(await readFile(stateFile), before);
    for (const filename of [path.join(output, ".aark-workflow.lock"), path.join(output, "mining", "scan-000001", ".aark-mining.lock")]) {
      await assert.rejects(access(filename));
    }
  });
}

test("completion source revalidation reads metadata without reopening original source bytes", linux, async context => {
  const f = await fixture();
  context.after(() => rm(f.root, {recursive: true, force: true}));
  await runWorkflow(f.attempt.configFile, {execute: true});
  const source = path.join(f.attempt.workflow.scans[0]!.inputs[0]!, "synthetic.txt");
  const originalOpen = fs.promises.open;
  let sourceReads = 0;
  const guarded: typeof fs.promises.open = async (filename, flags, mode) => {
    if (filename === source) { sourceReads++; throw new Error("original source contents must not be reopened"); }
    return await originalOpen(filename, flags, mode);
  };
  fs.promises.open = guarded;
  syncBuiltinESMExports();
  try { assert.equal((await verifyCompletedWorkflow(f.attempt)).scansVerified, 1); }
  finally { fs.promises.open = originalOpen; syncBuiltinESMExports(); }
  assert.equal(sourceReads, 0);
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
