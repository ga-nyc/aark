import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import { access, mkdir, readFile, rename, symlink, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type { AgentAction, AgentBridge, AgentEvent, AgentReply, CompletionProof, EngineHost, EngineIdentity,
  EngineObservation, PreparedAttempt, CaseConfig, CaseState } from "../case/types.js";
import { initializeCase, loadCaseState, redactedCaseStatus, saveCaseState, writeCaseCompletion } from "../case/store.js";
import { CaseSupervisor } from "../case/supervisor.js";
import { caseConfigHash, casePlan, digest, loadCaseConfig, MAX_CASE_BYTES } from "../case/config.js";
import { engineUnitName } from "../case/systemd.js";
import { CaseSourceIdentityError } from "../case/sources.js";
import { EngineLaunchRefusedError } from "../case/launch-error.js";
import { captureCommand } from "../core/command.js";
import { mkdtemp } from "./helpers.js";

/** No test starts systemd, a scanner, or a model; all host effects are injected. */
class FakeHost implements EngineHost {
  reattach?: NonNullable<EngineHost["reattach"]>;
  preflights = 0;
  launches: Array<{attempt: PreparedAttempt; token: string; mode: "run" | "resume"; identity: EngineIdentity}> = [];
  observations = new Map<string, EngineObservation | Error>();
  proofs = new Map<string, CompletionProof | Error>();
  verified: string[] = [];
  identities = new Map<string, EngineIdentity>();
  loseNextLaunchReply = false;
  resumeCapacity: boolean | Error = true;

  async preflight(): Promise<void> { this.preflights++; }
  async launch(attempt: PreparedAttempt, token: string, mode: "run" | "resume"): Promise<EngineIdentity> {
    let identity = this.identities.get(token);
    if (identity === undefined) {
      identity = {unit: engineUnitName(token), invocationId: String(this.identities.size + 1).padStart(32, "0")};
      this.identities.set(token, identity);
      this.observations.set(identity.unit, {status: "running"});
    }
    this.launches.push({attempt, token, mode, identity});
    if (this.loseNextLaunchReply) {
      this.loseNextLaunchReply = false;
      throw new Error("synthetic host reply lost after launch");
    }
    return identity;
  }
  async observe(identity: EngineIdentity): Promise<EngineObservation> {
    const observation = this.observations.get(identity.unit) ?? {status: "unknown"};
    if (observation instanceof Error) throw observation;
    return {...observation};
  }
  async verify(attempt: PreparedAttempt): Promise<CompletionProof> {
    this.verified.push(attempt.workflow.output);
    const proof = this.proofs.get(attempt.workflow.output);
    if (proof instanceof Error) throw proof;
    return proof ?? {sha256: "a".repeat(64), scansVerified: attempt.workflow.scans.length, filesVerified: 1};
  }
  async resumeReady(): Promise<boolean> {
    if (this.resumeCapacity instanceof Error) throw this.resumeCapacity;
    return this.resumeCapacity;
  }
}

class FakeAgent implements AgentBridge {
  preflights = 0;
  unavailablePreflights = 0;
  closed = 0;
  active = 0;
  maximumActive = 0;
  requests: Array<{event: AgentEvent; resolve: (reply: AgentReply) => void; reject: (error: Error) => void}> = [];
  automatic: ((event: AgentEvent) => AgentAction) | undefined;

  async preflight(): Promise<void> {
    this.preflights++;
    if (this.unavailablePreflights > 0) { this.unavailablePreflights--; throw new Error("synthetic agent registration unavailable"); }
  }
  async request(event: AgentEvent): Promise<AgentReply> {
    this.active++;
    this.maximumActive = Math.max(this.maximumActive, this.active);
    try {
      if (this.automatic !== undefined) {
        this.requests.push({event: structuredClone(event), resolve: () => {}, reject: () => {}});
        return {eventId: event.eventId, revision: event.revision, action: this.automatic(event)};
      }
      return await new Promise<AgentReply>((resolve, reject) => {
        this.requests.push({event: structuredClone(event), resolve, reject});
      });
    } finally { this.active--; }
  }
  reply(index: number, action: AgentAction, override: Partial<Pick<AgentReply, "eventId" | "revision">> = {}): void {
    const request = this.requests[index];
    assert.ok(request, "expected a pending synthetic agent request");
    request.resolve({eventId: request.event.eventId, revision: request.event.revision, action, ...override});
  }
  async close(): Promise<void> {
    this.closed++;
    for (const request of this.requests) request.reject(new Error("synthetic agent closed"));
  }
}

async function settle(): Promise<void> {
  await new Promise<void>(resolve => setImmediate(resolve));
}

function barrier() {
  let resolve = () => {};
  const promise = new Promise<void>(done => { resolve = done; });
  return {promise, resolve};
}

async function fixture(options: {jobs?: number; attempts?: number; maxConcurrent?: number; maxRequests?: number} = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-case-test-"));
  const control = path.join(root, "control");
  const filename = path.join(root, "case.json");
  const code = path.join(root, "synthetic-code");
  await mkdir(code);
  const jobs = [];
  const workflowFiles: string[][] = [];
  for (let job = 0; job < (options.jobs ?? 1); job++) {
    const input = path.join(root, `synthetic-input-${job}`);
    await mkdir(input);
    await writeFile(path.join(input, "ordinary.txt"), "ordinary synthetic fixture data\n");
    const attempts = [];
    for (let attempt = 0; attempt < (options.attempts ?? 1); attempt++) {
      const configFile = path.join(root, `workflow-${job}-${attempt}.json`);
      await writeFile(configFile, JSON.stringify({version: 1, execute: true,
        output: path.join(root, `output-${job}-${attempt}`),
        scans: [{inputs: [input], provenance: "unknown"}],
        mining: {workers: 1, storage: {minFreeGiB: 0, minFreePercent: 0}},
        finalizationStorage: {minFreeGiB: 0, minFreePercent: 0}}));
      attempts.push(configFile);
    }
    workflowFiles.push(attempts);
    jobs.push({id: `job-${String(job + 1).padStart(6, "0")}`, dependsOn: [] as string[], attempts, resumeAfterQuota: false});
  }
  const config = {version: 1, execute: true, control, jobs, pollMs: 1000, probeTimeoutMs: 1000,
    maxConcurrent: options.maxConcurrent ?? 2,
    agent: {ownership: "dedicated-thread", executable: "/usr/bin/codex", socketPath: path.join(root, "codex.sock"), threadId: "11111111-1111-4111-8111-111111111111",
      user: "syntheticuser", readableRoots: [code], timeoutMs: 1000, maxRequests: options.maxRequests ?? 8}};
  await writeFile(filename, JSON.stringify(config));
  return {root, control, filename, config, workflowFiles, host: new FakeHost(), agent: new FakeAgent()};
}

/** Large valid plans with repeated synthetic paths keep metadata work bounded. */
async function largeCaseFixture(preparedBytes: number) {
  const f = await fixture({jobs: 16});
  const prepared = await loadCaseConfig(f.filename);
  const inputs = Array.from({length: 32}, (_, index) => path.join(f.root, "bulk", `input-${String(index).padStart(3, "0")}-${"é".repeat(20)}`));
  for (const job of prepared.jobs) job.attempts[0]!.workflow.scans = Array.from({length: 128}, () => ({inputs: [...inputs], provenance: "unknown"}));
  const extra = preparedBytes - Buffer.byteLength(JSON.stringify(prepared));
  assert.ok(extra >= 0);
  const slotsPerJob = 128 * inputs.length;
  let jobRemainder = extra % prepared.jobs.length;
  for (const job of prepared.jobs) {
    const jobExtra = Math.floor(extra / prepared.jobs.length) + (jobRemainder-- > 0 ? 1 : 0);
    const padding = Math.floor(jobExtra / slotsPerJob);
    let remainder = jobExtra % slotsPerJob;
    const attempt = job.attempts[0]!;
    for (const scan of attempt.workflow.scans) scan.inputs = scan.inputs.map(input => input + "x".repeat(padding + (remainder-- > 0 ? 1 : 0)));
    attempt.configHash = digest(attempt.workflow);
    const document = JSON.stringify(attempt.workflow);
    assert.ok(Buffer.byteLength(document) <= 1024 * 1024, "each workflow remains within its own input limit");
    await writeFile(attempt.configFile, document);
  }
  assert.equal(Buffer.byteLength(JSON.stringify(prepared)), preparedBytes);
  return {...f, prepared};
}

function growSyntheticCase(saved: {config: CaseConfig; state: CaseState}, bytes: number): void {
  const sourceBindings: CaseState["sourceBindings"] = {};
  for (const job of saved.config.jobs) for (const attempt of job.attempts) {
    const bindings = saved.state.sourceBindings[attempt.configHash]!;
    for (const scan of attempt.workflow.scans) for (let index = 0; index < scan.inputs.length && bytes > 0; index++, bytes--) scan.inputs[index] += "x";
    attempt.configHash = digest(attempt.workflow);
    sourceBindings[attempt.configHash] = bindings;
  }
  assert.equal(bytes, 0, "fixture has enough independent path slots");
  saved.state.sourceBindings = sourceBindings;
  saved.state.configHash = caseConfigHash(saved.config);
}

async function recoverySourceFixture(missingSource = false) {
  const f = await fixture({attempts: 2});
  const source = path.join(f.root, "synthetic-original.img");
  const analysis = path.join(f.root, "synthetic-analysis.img");
  if (!missingSource) await writeFile(source, "ordinary synthetic source image\n");
  await writeFile(analysis, "ordinary synthetic analysis image\n");
  for (const [index, workflowFile] of f.workflowFiles[0]!.entries()) {
    const destination = path.join(f.root, `recovery-${index}`);
    const recoveryFile = path.join(f.root, `recovery-${index}.json`);
    await writeFile(recoveryFile, JSON.stringify({version: 1, caseId: `synthetic-recovery-${index}`, source, analysisSource: analysis,
      destination, execute: true, requireReadOnlySource: true, image: {enabled: false},
      stages: {deletedMetadata: false, ntfsUndelete: false, unallocatedStream: true, signatureCarving: true}}));
    const workflow = JSON.parse(await readFile(workflowFile, "utf8"));
    await writeFile(workflowFile, JSON.stringify({...workflow, recoveryConfig: recoveryFile,
      scans: [{inputs: [path.join(destination, "recovery", "carved")], provenance: "unallocated-carve"}]}));
  }
  return {...f, source, analysis};
}

const linuxOnly = {skip: process.platform !== "linux"};

test("a changed source requires media approval and an agent acknowledgement cannot erase it", linuxOnly, async t => {
  const f = await fixture();
  f.host.launch = async () => { throw new CaseSourceIdentityError(); };
  f.agent.automatic = () => ({type: "acknowledge"});
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor, 3);
  const {state} = await loadCaseState(f.control);
  assert.equal(state.permissionReason, "new-media-required");
  assert.equal(state.health, "awaiting-permission");
  assert.equal(f.host.identities.size, 0);
  assert.equal(state.jobs[0]!.attempts.length, 1);
  assert.notEqual(state.jobs[0]!.attempts[0]!.status, "failed");
});

async function tick(supervisor: CaseSupervisor, count = 1): Promise<void> {
  for (let index = 0; index < count; index++) {
    await supervisor.tick();
    await settle();
  }
}

test("case initialization requires both confirmations and every workflow authorization", linuxOnly, async () => {
  const f = await fixture();
  await assert.rejects(initializeCase(f.filename, {execute: false}), /execute|confirmation/i);
  await assert.rejects(access(f.control));
  await writeFile(f.filename, JSON.stringify({...f.config, execute: false}));
  await assert.rejects(initializeCase(f.filename, {execute: true}), /execut|confirmation/i);
  await assert.rejects(access(f.control));
  await writeFile(f.filename, JSON.stringify(f.config));
  const workflowFile = f.workflowFiles[0]![0]!;
  const workflow = JSON.parse(await readFile(workflowFile, "utf8"));
  await writeFile(workflowFile, JSON.stringify({...workflow, execute: false}));
  await assert.rejects(initializeCase(f.filename, {execute: true}), /execut|confirmation/i);
  await assert.rejects(access(f.control));
});

test("case state uses exact UTF-8 serialized bytes including its newline and preserves the last good state on overflow", linuxOnly, async () => {
  const f = await largeCaseFixture(MAX_CASE_BYTES - 16_384);
  await initializeCase(f.filename, {execute: true});
  const saved = await loadCaseState(f.control);
  const stateFile = path.join(f.control, "case-state-sensitive.json");
  const progressFile = path.join(f.control, "case-progress-redacted.json");
  const serialized = () => JSON.stringify({version: 1, sha256: digest(saved), ...saved}) + "\n";
  const initial = serialized();
  assert.ok(Buffer.byteLength(initial) > initial.length, "multibyte paths distinguish bytes from UTF-16 string length");
  assert.ok(Buffer.byteLength(JSON.stringify(JSON.parse(initial), null, 2) + "\n") > MAX_CASE_BYTES,
    "the former pretty writer would create an unreadable state");
  assert.equal((await readFile(stateFile)).toString(), initial);
  growSyntheticCase(saved, MAX_CASE_BYTES - Buffer.byteLength(initial));
  assert.equal(Buffer.byteLength(serialized()), MAX_CASE_BYTES);
  await saveCaseState(f.control, saved.config, saved.state);
  const accepted = await readFile(stateFile);
  const progress = await readFile(progressFile);
  assert.equal(accepted.length, MAX_CASE_BYTES);
  assert.equal(accepted.at(-1), 10, "the trailing newline counts toward the reader's size limit");
  assert.equal((await loadCaseState(f.control)).state.configHash, saved.state.configHash);
  growSyntheticCase(saved, 1);
  assert.equal(Buffer.byteLength(serialized()), MAX_CASE_BYTES + 1);
  await assert.rejects(saveCaseState(f.control, saved.config, saved.state), /controls exceed bounded capacity/);
  assert.deepEqual(await readFile(stateFile), accepted);
  assert.deepEqual(await readFile(progressFile), progress);
  assert.notEqual((await loadCaseState(f.control)).state.configHash, saved.state.configHash);
});

test("an oversized initial envelope is rejected before creating case controls or outputs", linuxOnly, async () => {
  const f = await largeCaseFixture(MAX_CASE_BYTES - 1024);
  assert.equal(Buffer.byteLength(JSON.stringify(await loadCaseConfig(f.filename))), MAX_CASE_BYTES - 1024);
  await assert.rejects(initializeCase(f.filename, {execute: true}), /controls exceed bounded capacity/);
  await assert.rejects(access(f.control));
  for (const job of f.prepared.jobs) await assert.rejects(access(job.attempts[0]!.workflow.output));
});

test("case initialization pins every reviewed recovery source/view and keeps those bindings out of public status", linuxOnly, async () => {
  const f = await recoverySourceFixture();
  await initializeCase(f.filename, {execute: true});
  const {config, state} = await loadCaseState(f.control);
  assert.deepEqual(Object.keys(state.sourceBindings).sort(), config.jobs[0]!.attempts.map(attempt => attempt.configHash).sort());
  const status = redactedCaseStatus(config, state);
  assert.equal(Object.hasOwn(status, "sourceBindings"), false);
  const serialized = JSON.stringify(status);
  for (const bindings of Object.values(state.sourceBindings)) {
    assert.deepEqual(bindings.map(binding => binding.source).sort(), [f.source, f.analysis].sort());
    for (const binding of bindings) {
      assert.match(binding.sha256, /^[a-f0-9]{64}$/u);
      assert.equal(serialized.includes(binding.source), false);
      assert.equal(serialized.includes(binding.sha256), false);
    }
  }
});

test("initial source identity failure occurs before the case control directory is created", linuxOnly, async () => {
  const f = await recoverySourceFixture(true);
  await assert.rejects(initializeCase(f.filename, {execute: true}));
  await assert.rejects(access(f.control));
});

test("case storage rejects malformed source identity bindings even after their envelope is rehashed", linuxOnly, async () => {
  const f = await recoverySourceFixture();
  await initializeCase(f.filename, {execute: true});
  const original = await loadCaseState(f.control);
  const stateFile = path.join(f.control, "case-state-sensitive.json");
  const bytes = await readFile(stateFile);
  const key = original.config.jobs[0]!.attempts[0]!.configHash;
  const changes: Array<(state: CaseState) => void> = [
    state => { delete state.sourceBindings[key]; },
    state => { state.sourceBindings["f".repeat(64)] = []; },
    state => { state.sourceBindings[key]![0]!.source = "/unregistered/synthetic-source.img"; },
    state => { state.sourceBindings[key]![0]!.sha256 = "invalid"; },
    state => { state.sourceBindings[key]!.push({...state.sourceBindings[key]![0]!}); },
    state => { state.sourceBindings[key] = [{...state.sourceBindings[key]![0]!}, {...state.sourceBindings[key]![0]!}]; },
    state => { (state.sourceBindings[key]![0] as unknown as Record<string, unknown>).message = "synthetic private diagnostic"; },
    state => { (state.sourceBindings as unknown as Record<string, unknown>)[key] = "synthetic private diagnostic"; },
  ];
  for (const change of changes) {
    const saved = structuredClone(original);
    change(saved.state);
    await assert.rejects(saveCaseState(f.control, saved.config, saved.state), /integrity/);
    assert.throws(() => redactedCaseStatus(saved.config, saved.state), /integrity/);
    await writeFile(stateFile, JSON.stringify({version: 1, sha256: digest(saved), ...saved}));
    await assert.rejects(loadCaseState(f.control), /integrity/);
    await writeFile(stateFile, bytes);
  }
});

test("case plans stay redacted and reject cycles, reused outputs, and evidence-readable agents", linuxOnly, async () => {
  const f = await fixture({jobs: 2, attempts: 2});
  const plan = casePlan(await loadCaseConfig(f.filename));
  assert.equal(JSON.stringify(plan).includes(f.root), false);
  assert.equal(plan.cleanupAuthorized, false);
  await assert.rejects(access(f.control));
  const cycle = structuredClone(f.config);
  cycle.jobs[0]!.dependsOn = [cycle.jobs[1]!.id];
  cycle.jobs[1]!.dependsOn = [cycle.jobs[0]!.id];
  await writeFile(f.filename, JSON.stringify(cycle));
  await assert.rejects(initializeCase(f.filename, {execute: true}), /cycle/i);
  await assert.rejects(access(f.control));
  const reused = structuredClone(f.config);
  reused.jobs[0]!.attempts[1] = reused.jobs[0]!.attempts[0]!;
  await writeFile(f.filename, JSON.stringify(reused));
  await assert.rejects(initializeCase(f.filename, {execute: true}), /output|overlap|independent/i);
  await assert.rejects(access(f.control));
  const readable = structuredClone(f.config);
  readable.agent.readableRoots = [f.root];
  await writeFile(f.filename, JSON.stringify(readable));
  await assert.rejects(initializeCase(f.filename, {execute: true}), /read roots|protected|overlap/i);
  await assert.rejects(access(f.control));
});

test("agent read roots exclude every recovery view and original configuration file", linuxOnly, async () => {
  const f = await fixture();
  const roots = Object.fromEntries(["source", "analysis", "mounted", "previous", "recovery-plans", "workflow-plans", "case-plans"]
    .map(name => [name, path.join(f.root, name)]));
  for (const directory of Object.values(roots)) await mkdir(directory);
  const recoveryFile = path.join(roots["recovery-plans"]!, "recovery.json");
  const destination = path.join(f.root, "recovered");
  await writeFile(recoveryFile, JSON.stringify({version: 1, caseId: "synthetic-recovery",
    source: path.join(roots.source!, "source.img"), analysisSource: path.join(roots.analysis!, "analysis.img"),
    mountedReadOnlyRoot: roots.mounted, unallocatedStreamFromCase: roots.previous, destination,
    requireReadOnlySource: true, execute: true, image: {enabled: false},
    stages: {deletedMetadata: false, ntfsUndelete: false, unallocatedStream: false, signatureCarving: true}}));
  const original = JSON.parse(await readFile(f.workflowFiles[0]![0]!, "utf8"));
  const workflowFile = path.join(roots["workflow-plans"]!, "workflow.json");
  await writeFile(workflowFile, JSON.stringify({...original, recoveryConfig: recoveryFile,
    scans: [{inputs: [path.join(destination, "recovery", "carved")], provenance: "unallocated-carve"}]}));
  f.config.jobs[0]!.attempts = [workflowFile];
  const caseFile = path.join(roots["case-plans"]!, "case.json");
  await writeFile(caseFile, JSON.stringify(f.config));
  await loadCaseConfig(caseFile);
  for (const directory of Object.values(roots)) {
    await writeFile(caseFile, JSON.stringify({...f.config, agent: {...f.config.agent, readableRoots: [directory]}}));
    await assert.rejects(loadCaseConfig(caseFile), /read roots overlap protected case data/);
  }
  // A prior extraction's case is also protected from control-directory writes.
  await writeFile(caseFile, JSON.stringify({...f.config, control: path.join(roots.previous!, "new-control")}));
  await assert.rejects(loadCaseConfig(caseFile), /control overlaps/);
  await assert.rejects(access(f.control));
});

test("dense valid dependency graphs remain bounded during configuration loading", linuxOnly, async () => {
  const f = await fixture({jobs: 64, maxConcurrent: 1});
  for (let index = 0; index < f.config.jobs.length; index++) {
    f.config.jobs[index]!.dependsOn = f.config.jobs.slice(0, index).map(job => job.id);
  }
  await writeFile(f.filename, JSON.stringify(f.config));
  // Isolate the time bound: a regression to exponential synchronous traversal
  // must not block the test runner's own deadline or start any engine.
  const code = `import {loadCaseConfig} from ${JSON.stringify(new URL("../case/config.js", import.meta.url).href)}; const config = await loadCaseConfig(process.argv[1]); process.stdout.write(String(config.jobs.length));`;
  const result = await captureCommand(process.execPath, ["--input-type=module", "-e", code, f.filename],
    {timeoutMs: 10_000, killGraceMs: 100, maxCaptureBytes: 1024});
  assert.equal(result.terminationReason, null);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout.toString(), "64");
  await assert.rejects(access(f.control));
});

test("agent registration rejects duplicate roots and unsupported thread identifiers before initialization", linuxOnly, async () => {
  const f = await fixture();
  for (const agent of [
    {...f.config.agent, threadId: "a".repeat(129)},
    {...f.config.agent, threadId: "-unregistered"},
    {...f.config.agent, readableRoots: [...f.config.agent.readableRoots, ...f.config.agent.readableRoots]},
  ]) {
    await writeFile(f.filename, JSON.stringify({...f.config, agent}));
    await assert.rejects(initializeCase(f.filename, {execute: true}), /agent registration|read roots must be unique/);
    await assert.rejects(access(f.control));
  }
});

test("failed jobs leave independent work running and dependent jobs unstarted", linuxOnly, async t => {
  const f = await fixture({jobs: 3});
  f.config.jobs[2]!.dependsOn = ["job-000001"];
  await writeFile(f.filename, JSON.stringify(f.config));
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  assert.equal(f.host.identities.size, 2);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed", failureCode: "scan-completed-with-errors", scanErrors: 1});
  await tick(supervisor, 2);
  const {state} = await loadCaseState(f.control);
  assert.equal(state.jobs[0]!.attempts.at(-1)!.status, "failed");
  assert.equal(state.jobs[1]!.attempts.at(-1)!.status, "running");
  assert.equal(state.jobs[2]!.attempts.length, 0);
  assert.equal(state.complete, false);
  assert.equal(f.host.identities.size, 2);
});

test("reported completion must pass verification before dependencies or case completion", linuxOnly, async t => {
  const f = await fixture({jobs: 2});
  f.config.jobs[1]!.dependsOn = ["job-000001"];
  await writeFile(f.filename, JSON.stringify(f.config));
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  const first = f.host.launches[0]!;
  f.host.observations.set(first.identity.unit, {status: "complete", bytesScanned: 1024, scanErrors: 0});
  f.host.proofs.set(first.attempt.workflow.output, new Error(`synthetic verification failure ${f.root}`));
  await tick(supervisor, 2);
  const {state} = await loadCaseState(f.control);
  assert.equal(state.complete, false);
  assert.notEqual(state.jobs[0]!.attempts.at(-1)!.status, "complete");
  assert.equal(state.jobs[1]!.attempts.length, 0);
  assert.equal(f.host.identities.size, 1);
  assert.ok(f.host.verified.length >= 1);
  assert.equal(JSON.stringify(await supervisor.snapshot()).includes(f.root), false);
  await assert.rejects(access(path.join(f.control, "manifest-redacted.json")));
});

test("user pause blocks new launches and never stops existing engines", linuxOnly, async t => {
  const f = await fixture();
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await supervisor.pause();
  await tick(supervisor);
  assert.equal(f.host.launches.length, 0);
  assert.equal((await loadCaseState(f.control)).state.desired, "user-paused");
  await supervisor.resume();
  await tick(supervisor);
  assert.equal(f.host.identities.size, 1);
  await supervisor.pause();
  await tick(supervisor, 2);
  assert.equal((await loadCaseState(f.control)).state.desired, "user-paused");
  assert.equal(f.host.identities.size, 1);
  const observation = f.host.observations.get(f.host.launches[0]!.identity.unit);
  assert.ok(observation && !(observation instanceof Error));
  assert.equal(observation.status, "running");
});

test("run cancellation during observation prevents an independent launch and preserves existing engines", linuxOnly, async t => {
  const f = await fixture({jobs: 3, maxConcurrent: 2});
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  const controller = new AbortController(), entered = barrier(), release = barrier();
  t.after(async () => { controller.abort(); release.resolve(); await supervisor.close(); });
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed"});
  const observe = f.host.observe.bind(f.host);
  f.host.observe = async identity => {
    if (identity.unit === f.host.launches[1]!.identity.unit) { entered.resolve(); await release.promise; }
    return await observe(identity);
  };
  const running = supervisor.run(controller.signal);
  await entered.promise;
  controller.abort(); release.resolve();
  await running;
  const {state} = await loadCaseState(f.control);
  assert.equal(state.jobs[0]!.attempts[0]!.status, "failed");
  assert.equal(state.jobs[1]!.attempts[0]!.status, "running");
  assert.equal(state.jobs[2]!.attempts.length, 0);
  assert.equal(f.host.launches.length, 2);
  assert.equal(f.agent.requests.length, 0, "shutdown does not dispatch a fresh agent decision");
  await tick(supervisor);
  assert.equal(f.host.launches.length, 3, "an explicit manual tick remains usable after run stops");
});

test("run cancellation during quota readiness settles the observation without launching new work", linuxOnly, async t => {
  const f = await fixture({jobs: 2, maxConcurrent: 1});
  f.config.jobs[0]!.resumeAfterQuota = true;
  await writeFile(f.filename, JSON.stringify(f.config));
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  const controller = new AbortController(), entered = barrier(), release = barrier();
  t.after(async () => { controller.abort(); release.resolve(); await supervisor.close(); });
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "paused", pauseReason: "free-space-reserve"});
  f.host.resumeReady = async () => { entered.resolve(); await release.promise; return true; };
  const running = supervisor.run(controller.signal);
  await entered.promise;
  controller.abort(); release.resolve();
  await running;
  const {state} = await loadCaseState(f.control);
  assert.equal(state.jobs[0]!.attempts[0]!.resumeReady, true);
  assert.equal(state.jobs[1]!.attempts.length, 0);
  assert.equal(f.host.launches.length, 1);
});

for (const stage of ["configuration", "new-intent", "uncertain-intent"] as const) {
  test(`run cancellation during ${stage} prelaunch work does not submit an engine`, linuxOnly, async t => {
    const f = await fixture();
    await initializeCase(f.filename, {execute: true});
    if (stage === "uncertain-intent") {
      const saved = await loadCaseState(f.control);
      saved.state.jobs[0]!.attempts.push({index: 0, token: randomUUID(), mode: "run", status: "launching", dispatched: true});
      await saveCaseState(f.control, saved.config, saved.state);
    }
    const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
    const controller = new AbortController(), entered = barrier(), release = barrier();
    t.after(async () => { controller.abort(); release.resolve(); await supervisor.close(); });
    const originalOpen = fs.promises.open, originalRename = fs.promises.rename;
    let blocked = false;
    fs.promises.open = async (filename, flags, mode) => {
      if (stage === "configuration" && filename === f.workflowFiles[0]![0] && !blocked) {
        blocked = true; entered.resolve(); await release.promise;
      }
      return await originalOpen(filename, flags, mode);
    };
    fs.promises.rename = async (source, destination) => {
      if (stage !== "configuration" && destination === path.join(f.control, "case-state-sensitive.json") && !blocked) {
        blocked = true; entered.resolve(); await release.promise;
      }
      await originalRename(source, destination);
    };
    syncBuiltinESMExports();
    try {
      const running = supervisor.run(controller.signal);
      await entered.promise;
      controller.abort(); release.resolve();
      await running;
    } finally {
      fs.promises.open = originalOpen; fs.promises.rename = originalRename; syncBuiltinESMExports();
    }
    const {state} = await loadCaseState(f.control);
    const attempt = state.jobs[0]!.attempts[0]!;
    assert.equal(attempt.status, "launching");
    assert.equal(attempt.dispatched, stage === "uncertain-intent" ? true : undefined);
    assert.equal(attempt.launchRefused, undefined);
    assert.equal(f.host.launches.length, 0);
    assert.equal(state.desired, "running", "worker shutdown does not turn into a user pause");
  });
}

test("agent retry selects only the next approved fresh output and cannot resume failure", linuxOnly, async t => {
  const f = await fixture({attempts: 2});
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
  await tick(supervisor);
  assert.equal(f.agent.requests.length, 1);
  f.agent.reply(0, {type: "retry", jobId: "job-000001"});
  await settle();
  await tick(supervisor, 2);
  assert.equal(f.host.identities.size, 2);
  const retry = f.host.launches.at(-1)!;
  assert.notEqual(retry.attempt.workflow.output, f.host.launches[0]!.attempt.workflow.output);
  assert.equal(retry.mode, "run");
  f.host.observations.set(retry.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
  await tick(supervisor);
  f.agent.reply(1, {type: "resume", jobId: "job-000001"});
  await settle();
  await tick(supervisor, 2);
  assert.equal(f.host.identities.size, 2);
  assert.ok(f.host.launches.every(launch => launch.mode === "run"));
  assert.equal((await loadCaseState(f.control)).state.jobs[0]!.attempts.length, 2);
});

test("quota resume remains explicitly opt-in", linuxOnly, async t => {
  const f = await fixture();
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "paused", pauseReason: "free-space-reserve"});
  await tick(supervisor, 3);
  assert.equal(f.agent.requests.length, 0);
  assert.equal(f.host.launches.length, 1);
  assert.equal((await loadCaseState(f.control)).state.jobs[0]!.attempts.at(-1)!.status, "paused");
});

test("exhausted approved attempts require a new plan instead of an unlisted retry", linuxOnly, async t => {
  const f = await fixture();
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
  await tick(supervisor);
  f.agent.reply(0, {type: "retry", jobId: "job-000001"});
  await settle();
  await tick(supervisor, 2);
  const {state} = await loadCaseState(f.control);
  assert.equal(state.permissionReason, "new-plan-required");
  assert.equal(state.jobs[0]!.attempts.length, 1);
  assert.equal(f.host.identities.size, 1);
});

test("an approved quota resume reuses the native output while a signal pause cannot", linuxOnly, async () => {
  for (const pauseReason of ["free-space-reserve", "signal"] as const) {
    const f = await fixture();
    f.config.jobs[0]!.resumeAfterQuota = true;
    await writeFile(f.filename, JSON.stringify(f.config));
    await initializeCase(f.filename, {execute: true});
    const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
    try {
      await tick(supervisor);
      const first = f.host.launches[0]!;
      f.host.observations.set(first.identity.unit, {status: "paused", pauseReason});
      await tick(supervisor);
      if (pauseReason === "signal") {
        assert.equal(f.host.launches.length, 1);
        assert.equal(f.agent.requests.length, 0);
      }
      else {
        f.agent.reply(0, {type: "resume", jobId: "job-000001"});
        await settle();
        await tick(supervisor, 2);
        assert.equal(f.host.identities.size, 2);
        assert.equal(f.host.launches.at(-1)!.mode, "resume");
        assert.equal(f.host.launches.at(-1)!.attempt.workflow.output, first.attempt.workflow.output);
      }
    } finally { await supervisor.close(); }
  }
});

test("an output-cap pause requires a new plan without consuming repeated resume requests", linuxOnly, async t => {
  const f = await fixture();
  f.config.jobs[0]!.resumeAfterQuota = true;
  await writeFile(f.filename, JSON.stringify(f.config));
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "paused", pauseReason: "output-cap"});
  await tick(supervisor, 10);
  const {state} = await loadCaseState(f.control);
  assert.equal(state.permissionReason, "new-plan-required");
  assert.equal(state.health, "awaiting-permission");
  assert.equal(state.jobs[0]!.attempts.length, 1);
  assert.equal(state.agentRequests, 0);
  assert.equal(f.agent.requests.length, 0);
  assert.equal(f.host.launches.length, 1);
});

test("free-space pauses wait for capacity before spending an agent decision or allocating a resume", linuxOnly, async t => {
  const f = await fixture();
  f.config.jobs[0]!.resumeAfterQuota = true;
  await writeFile(f.filename, JSON.stringify(f.config));
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  const first = f.host.launches[0]!;
  f.host.observations.set(first.identity.unit, {status: "paused", pauseReason: "free-space-reserve"});
  f.host.resumeCapacity = false;
  await tick(supervisor, 10);
  const waiting = (await loadCaseState(f.control)).state;
  assert.equal(waiting.health, "degraded");
  assert.equal(waiting.jobs[0]!.attempts[0]!.resumeReady, false);
  assert.equal(waiting.jobs[0]!.attempts.length, 1);
  assert.equal(waiting.agentRequests, 0);
  assert.equal(f.agent.requests.length, 0);
  assert.equal(f.host.launches.length, 1);
  f.host.resumeCapacity = true;
  await tick(supervisor);
  assert.equal(f.agent.requests.length, 1);
  f.agent.reply(0, {type: "resume", jobId: "job-000001"});
  await settle();
  await tick(supervisor, 2);
  assert.equal(f.host.launches.length, 2);
  assert.equal(f.host.launches[1]!.mode, "resume");
  assert.equal(f.host.launches[1]!.attempt.workflow.output, first.attempt.workflow.output);
});

test("unknown capacity stays observable without spending agent or engine retries", linuxOnly, async t => {
  const f = await fixture();
  f.config.jobs[0]!.resumeAfterQuota = true;
  await writeFile(f.filename, JSON.stringify(f.config));
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "paused", pauseReason: "free-space-reserve"});
  f.host.resumeCapacity = new Error("synthetic capacity probe unavailable");
  await tick(supervisor, 5);
  const {state} = await loadCaseState(f.control);
  assert.equal(state.health, "observation-unavailable");
  assert.equal(state.jobs[0]!.attempts[0]!.resumeReady, undefined);
  assert.equal(state.jobs[0]!.attempts.length, 1);
  assert.equal(state.agentRequests, 0);
  assert.equal(f.agent.requests.length, 0);
  assert.equal(f.host.launches.length, 1);
});

test("capacity loss invalidates an outstanding resume approval before it can allocate an intent", linuxOnly, async t => {
  const f = await fixture();
  f.config.jobs[0]!.resumeAfterQuota = true;
  await writeFile(f.filename, JSON.stringify(f.config));
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "paused", pauseReason: "free-space-reserve"});
  await tick(supervisor);
  const revision = f.agent.requests[0]!.event.revision;
  f.host.resumeCapacity = false;
  f.agent.reply(0, {type: "resume", jobId: "job-000001"});
  await settle();
  await tick(supervisor, 3);
  const {state} = await loadCaseState(f.control);
  assert.ok(state.revision > revision);
  assert.equal(state.jobs[0]!.attempts[0]!.resumeReady, false);
  assert.equal(state.jobs[0]!.attempts.length, 1);
  assert.equal(state.permissionReason, undefined);
  assert.equal(f.agent.requests.length, 1);
  assert.equal(f.host.launches.length, 1);
});

test("an unready resume from a mixed failure decision waits for capacity without demanding a new plan", linuxOnly, async t => {
  const f = await fixture({jobs: 2});
  f.config.jobs[0]!.resumeAfterQuota = true;
  await writeFile(f.filename, JSON.stringify(f.config));
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.resumeCapacity = false;
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "paused", pauseReason: "free-space-reserve"});
  f.host.observations.set(f.host.launches[1]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
  await tick(supervisor);
  assert.equal(f.agent.requests[0]!.event.reason, "job-failed");
  f.agent.reply(0, {type: "resume", jobId: "job-000001"});
  await settle();
  await tick(supervisor, 3);
  const {state} = await loadCaseState(f.control);
  assert.equal(state.permissionReason, undefined);
  assert.equal(state.jobs[0]!.attempts.length, 1);
  assert.equal(state.jobs[0]!.attempts[0]!.status, "paused");
  assert.equal(f.host.launches.length, 2);
  assert.equal(f.agent.requests.length, 1);
  f.host.resumeCapacity = true;
  await tick(supervisor);
  assert.equal(f.agent.requests.length, 2);
});

test("a lost launch reply reuses its persisted token after supervisor restart", linuxOnly, async () => {
  const f = await fixture();
  await initializeCase(f.filename, {execute: true});
  f.host.loseNextLaunchReply = true;
  const first = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  try { await first.tick(); } catch { /* Fault injection: the engine started before its reply was lost. */ }
  await settle();
  const persisted = (await loadCaseState(f.control)).state.jobs[0]!.attempts[0]!;
  assert.equal(persisted.status, "launching");
  assert.ok(persisted.token);
  await first.close();
  const second = await CaseSupervisor.open(f.control, {host: f.host, agent: new FakeAgent()});
  try {
    await tick(second, 2);
    assert.equal(f.host.identities.size, 1);
    assert.ok(f.host.launches.length >= 2);
    assert.ok(f.host.launches.every(launch => launch.token === persisted.token));
    assert.equal((await loadCaseState(f.control)).state.jobs[0]!.attempts[0]!.status, "running");
  } finally { await second.close(); }
});

test("restart observes the existing engine without launching another attempt", linuxOnly, async () => {
  const f = await fixture();
  await initializeCase(f.filename, {execute: true});
  const first = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  await tick(first);
  const identity = f.host.launches[0]!.identity;
  await first.close();
  const observation = f.host.observations.get(identity.unit);
  assert.ok(observation && !(observation instanceof Error));
  assert.equal(observation.status, "running");
  const second = await CaseSupervisor.open(f.control, {host: f.host, agent: new FakeAgent()});
  try {
    await tick(second, 2);
    assert.equal(f.host.launches.length, 1);
    assert.deepEqual((await loadCaseState(f.control)).state.jobs[0]!.attempts[0]!.identity, identity);
  } finally { await second.close(); }
});

test("unknown and failed observations do not manufacture engine failure or duplicate work", linuxOnly, async t => {
  const f = await fixture({attempts: 2});
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  const identity = f.host.launches[0]!.identity;
  for (const observation of [{status: "unknown"} as const, new Error(`synthetic private probe failure ${f.root}`)]) {
    f.host.observations.set(identity.unit, observation);
    await tick(supervisor, 2);
    const {state} = await loadCaseState(f.control);
    assert.equal(state.jobs[0]!.attempts[0]!.status, "running");
    assert.equal(state.jobs[0]!.attempts.length, 1);
    assert.equal(state.complete, false);
    assert.equal(f.host.launches.length, 1);
    const redacted = JSON.stringify(await supervisor.snapshot());
    assert.equal(redacted.includes(f.root), false);
    assert.equal(redacted.includes("synthetic private probe failure"), false);
  }
});

test("only one agent request can be pending while other engines keep progressing", linuxOnly, async t => {
  const f = await fixture({jobs: 2});
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
  await tick(supervisor);
  f.host.observations.set(f.host.launches[1]!.identity.unit, {status: "complete", scanErrors: 0});
  await tick(supervisor, 4);
  assert.equal(f.agent.requests.length, 1);
  assert.equal(f.agent.maximumActive, 1);
  assert.equal((await loadCaseState(f.control)).state.jobs[1]!.attempts[0]!.status, "complete");
  assert.equal(JSON.stringify(f.agent.requests[0]!.event).includes(f.root), false);
});

test("stale agent event revisions cannot authorize a fresh attempt", linuxOnly, async t => {
  const f = await fixture({jobs: 2, attempts: 2});
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
  await tick(supervisor);
  const requestedRevision = f.agent.requests[0]!.event.revision;
  f.host.observations.set(f.host.launches[1]!.identity.unit, {status: "complete", scanErrors: 0});
  await tick(supervisor, 2);
  assert.ok((await loadCaseState(f.control)).state.revision > requestedRevision);
  // A valid reply to the old request still cannot authorize a newer state.
  f.agent.reply(0, {type: "retry", jobId: "job-000001"});
  await settle();
  await tick(supervisor, 2);
  assert.equal(f.host.identities.size, 2);
  assert.equal((await loadCaseState(f.control)).state.jobs[0]!.attempts.length, 1);
});

for (const reason of ["agent-approval-required", "new-media-required"] as const) {
  test(`a stale ${reason} stop survives unrelated verification and prevents the next launch`, linuxOnly, async t => {
    const f = await fixture({jobs: 4, attempts: 2, maxConcurrent: 2});
    await initializeCase(f.filename, {execute: true});
    const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
    t.after(() => supervisor.close());
    await tick(supervisor);
    f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
    await tick(supervisor);
    assert.equal(f.host.launches.length, 3, "job 3 occupies the slot left by job 1");
    const event = f.agent.requests[0]!.event;
    f.host.observations.set(f.host.launches[1]!.identity.unit, {status: "complete", scanErrors: 0});
    await tick(supervisor); // Verification completes asynchronously before the next observation.
    f.agent.reply(0, {type: "needs-permission", reason});
    await settle();
    await tick(supervisor, 2);
    const {state} = await loadCaseState(f.control);
    assert.ok(state.revision > event.revision);
    assert.equal(state.jobs[1]!.attempts.at(-1)!.status, "complete");
    assert.equal(state.permissionReason, reason);
    assert.equal(state.health, "awaiting-permission");
    assert.equal(state.outbox[0]!.status, "processed");
    assert.deepEqual(state.outbox[0]!.reply?.action, {type: "needs-permission", reason});
    assert.equal(state.jobs[3]!.attempts.length, 0);
    assert.equal(state.jobs[2]!.attempts.at(-1)!.status, "running");
    assert.equal(f.host.launches.length, 3);
    await supervisor.close();
    const restarted = await CaseSupervisor.open(f.control, {host: f.host, agent: new FakeAgent()});
    try {
      await tick(restarted, 2);
      assert.equal((await loadCaseState(f.control)).state.permissionReason, reason);
      assert.equal(f.host.launches.length, 3, "the persisted stop also holds job 4 after restart");
    } finally { await restarted.close(); }
  });
}

test("a stale agent resume cannot authorize work after unrelated verification advances the case", linuxOnly, async t => {
  const f = await fixture({jobs: 2, maxConcurrent: 2});
  f.config.jobs[0]!.resumeAfterQuota = true;
  await writeFile(f.filename, JSON.stringify(f.config));
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "paused", pauseReason: "free-space-reserve"});
  await tick(supervisor);
  const event = f.agent.requests[0]!.event;
  assert.equal(event.reason, "job-paused");
  f.host.observations.set(f.host.launches[1]!.identity.unit, {status: "complete", scanErrors: 0});
  await tick(supervisor);
  f.agent.reply(0, {type: "resume", jobId: "job-000001"});
  await settle();
  await tick(supervisor, 2);
  const {state} = await loadCaseState(f.control);
  assert.ok(state.revision > event.revision);
  assert.equal(state.jobs[0]!.attempts.length, 1);
  assert.equal(state.jobs[0]!.attempts[0]!.status, "paused");
  assert.equal(state.permissionReason, undefined);
  assert.equal(f.host.launches.length, 2);
});

test("agent retries preserve event identity and stop at the persisted request budget", linuxOnly, async t => {
  const f = await fixture({maxRequests: 2});
  await initializeCase(f.filename, {execute: true});
  let now = Date.now();
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent, clock: () => now});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
  await tick(supervisor);
  const firstEvent = f.agent.requests[0]!.event;
  f.agent.requests[0]!.reject(new Error(`synthetic private agent transport error ${f.root}`));
  await settle();
  await tick(supervisor);
  now += 24 * 60 * 60 * 1000;
  await tick(supervisor, 2);
  assert.equal(f.agent.requests.length, 2);
  assert.equal(f.agent.requests[1]!.event.eventId, firstEvent.eventId);
  f.agent.requests[1]!.reject(new Error("synthetic second transport failure"));
  await settle();
  await tick(supervisor);
  now += 24 * 60 * 60 * 1000;
  await tick(supervisor, 4);
  const {state} = await loadCaseState(f.control);
  assert.equal(f.agent.requests.length, 2);
  assert.equal(state.agentRequests, 2);
  assert.equal(state.completionDeliveredToAgent, false);
  assert.equal(JSON.stringify(await supervisor.snapshot()).includes(f.root), false);
});

test("all verified jobs produce a consolidated redacted report and tracked completion event", linuxOnly, async t => {
  const f = await fixture({jobs: 2});
  f.agent.automatic = () => ({type: "acknowledge"});
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "complete", scanErrors: 0});
  await tick(supervisor);
  assert.equal((await loadCaseState(f.control)).state.complete, false);
  await assert.rejects(access(path.join(f.control, "manifest-redacted.json")));
  f.host.observations.set(f.host.launches[1]!.identity.unit, {status: "complete", scanErrors: 0});
  await tick(supervisor, 3);
  const {state} = await loadCaseState(f.control);
  assert.equal(state.complete, true);
  assert.equal(state.completionDeliveredToAgent, true);
  assert.equal(f.host.verified.length, 2);
  const manifest = await readFile(path.join(f.control, "manifest-redacted.json"), "utf8");
  const report = await readFile(path.join(f.control, "final-report-redacted.md"), "utf8");
  for (const value of [manifest, report, JSON.stringify(await supervisor.snapshot()), JSON.stringify(f.agent.requests.map(request => request.event))]) {
    assert.equal(value.includes(f.root), false);
    assert.equal(value.includes("ordinary synthetic fixture data"), false);
  }
  assert.equal(JSON.parse(manifest).cleanupAuthorized, false);
  assert.equal(f.agent.requests.filter(request => request.event.reason === "case-completed").length, 1);
});

test("completion publication rejects control replacement during the last observation before writing reports", linuxOnly, async t => {
  const f = await fixture();
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "complete", scanErrors: 0});
  await tick(supervisor); // Let the asynchronous proof finish before its commit.
  const observe = f.host.observe.bind(f.host);
  const displaced = path.join(f.root, "displaced-control");
  f.host.observe = async identity => {
    const result = await observe(identity);
    await rename(f.control, displaced);
    await mkdir(f.control, {mode: 0o700});
    await rename(path.join(displaced, ".case-service.lock"), path.join(f.control, ".case-service.lock"));
    return result;
  };
  await assert.rejects(supervisor.tick(), /control directory binding changed/);
  await assert.rejects(access(path.join(f.control, "manifest-redacted.json")));
  await assert.rejects(access(path.join(f.control, "final-report-redacted.md")));
});

test("completion publication never recreates a missing case control directory", linuxOnly, async () => {
  const f = await fixture();
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  let saved: Awaited<ReturnType<typeof loadCaseState>>;
  try {
    await tick(supervisor);
    f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "complete", scanErrors: 0});
    await tick(supervisor, 2);
    saved = await loadCaseState(f.control);
  } finally { await supervisor.close(); }
  await rename(f.control, path.join(f.root, "displaced-control"));
  await assert.rejects(writeCaseCompletion(saved.config, saved.state));
  await assert.rejects(access(f.control));
});

test("persisted delivering events are reconciled after a supervisor crash", linuxOnly, async () => {
  const f = await fixture();
  await initializeCase(f.filename, {execute: true});
  const first = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  await tick(first);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
  await tick(first);
  const eventId = f.agent.requests[0]!.event.eventId;
  await first.close();
  // Only synthetic control state is edited: model a process dying after dispatch.
  const saved = await loadCaseState(f.control);
  const entry = saved.state.outbox.find(row => row.event.eventId === eventId)!;
  entry.status = "delivering";
  entry.nextDeliveryAt = 0;
  await saveCaseState(f.control, saved.config, saved.state);
  const resumedAgent = new FakeAgent();
  const second = await CaseSupervisor.open(f.control, {host: f.host, agent: resumedAgent, clock: () => Date.now() + 86_400_000});
  try {
    await tick(second, 2);
    assert.equal(resumedAgent.requests[0]!.event.eventId, eventId);
    assert.equal(f.host.launches.length, 1);
  } finally { await second.close(); }
});

test("case storage rejects rehashed malformed fields before persistence, reload, or redaction", linuxOnly, async () => {
  const f = await fixture({jobs: 2, maxConcurrent: 1});
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "unknown"});
  await tick(supervisor);
  await supervisor.close();
  const original = await loadCaseState(f.control);
  const stateFile = path.join(f.control, "case-state-sensitive.json");
  const originalBytes = await readFile(stateFile);
  const progressFile = path.join(f.control, "case-progress-redacted.json");
  const progressBytes = await readFile(progressFile);
  const raw = (value: object) => value as unknown as Record<string, unknown>;
  const changes: Array<[string, (saved: {config: CaseConfig; state: CaseState}) => void]> = [
    ["arbitrary permission reason", ({state}) => { raw(state).permissionReason = "/private/synthetic-value"; }],
    ["unbounded timestamp", ({state}) => { state.updatedAt = "private-synthetic-value"; }],
    ["arbitrary job ID", ({config, state}) => { config.jobs[0]!.id = "private-synthetic-value"; state.jobs[0]!.id = config.jobs[0]!.id; }],
    ["duplicate job IDs", ({config, state}) => { config.jobs[1]!.id = config.jobs[0]!.id; state.jobs[1]!.id = config.jobs[0]!.id; }],
    ["unknown dependency", ({config}) => { config.jobs[0]!.dependsOn = ["job-999999"]; }],
    ["dependency cycle", ({config}) => { config.jobs[0]!.dependsOn = [config.jobs[1]!.id]; config.jobs[1]!.dependsOn = [config.jobs[0]!.id]; }],
    ["normalized worker limit", ({config}) => { config.jobs[0]!.attempts[0]!.workflow.mining.workers = 5; }],
    ["frozen workflow execution flag", ({config}) => { config.jobs[0]!.attempts[0]!.workflow.execute = false; }],
    ["agent timeout bound", ({config}) => { config.agent.timeoutMs = 0; }],
    ["agent roots expose controls", ({config}) => { config.agent.readableRoots = [f.root]; }],
    ["duplicate agent roots", ({config}) => { config.agent.readableRoots.push(config.agent.readableRoots[0]!); }],
    ["unit does not match launch token", ({state}) => { state.jobs[0]!.attempts[0]!.identity!.unit = engineUnitName(randomUUID()); }],
    ["arbitrary observation diagnostic", ({state}) => { state.jobs[0]!.attempts[0]!.observation = {status: "failed", failureCode: "private-synthetic-value"}; }],
    ["readiness on a running attempt", ({state}) => { state.jobs[0]!.attempts[0]!.resumeReady = true; }],
    ["readiness without quota permission", ({state}) => {
      const attempt = state.jobs[0]!.attempts[0]!; attempt.status = "paused";
      attempt.observation = {status: "paused", pauseReason: "free-space-reserve"}; attempt.resumeReady = true;
    }],
    ["nonboolean readiness", ({config, state}) => {
      config.jobs[0]!.resumeAfterQuota = true;
      for (const entry of state.outbox) entry.event.jobs[0]!.resumeAfterQuota = true;
      const attempt = state.jobs[0]!.attempts[0]!; attempt.status = "paused";
      attempt.observation = {status: "paused", pauseReason: "free-space-reserve"}; raw(attempt).resumeReady = "private-synthetic-value";
    }],
    ["event extra fields", ({state}) => { raw(state.outbox[0]!.event).message = "private-synthetic-value"; }],
    ["arbitrary event reason", ({state}) => { raw(state.outbox[0]!.event).reason = "private-synthetic-value"; }],
    ["unregistered event job", ({state}) => { state.outbox[0]!.event.jobs[0]!.id = "private-synthetic-value"; }],
    ["event attempt permission mismatch", ({state}) => { state.outbox[0]!.event.jobs[0]!.attemptsAllowed = 99; }],
    ["future event revision", ({state}) => { state.outbox[0]!.event.revision = state.revision + 1; }],
    ["request accounting mismatch", ({state}) => { state.agentRequests = 0; }],
    ["reply arbitrary permission reason", ({state}) => {
      const entry = state.outbox[0]!; entry.status = "processed";
      entry.reply = {eventId: entry.event.eventId, revision: entry.event.revision, action: {type: "needs-permission", reason: "new-plan-required"}};
      raw(entry.reply.action).reason = "private-synthetic-value";
    }],
    ["reply extra fields", ({state}) => {
      const entry = state.outbox[0]!; entry.status = "processed";
      entry.reply = {eventId: entry.event.eventId, revision: entry.event.revision, action: {type: "acknowledge"}};
      raw(entry.reply).message = "private-synthetic-value";
    }],
    ["completion scan count mismatch", ({state}) => {
      const attempt = state.jobs[0]!.attempts[0]!; attempt.status = "complete";
      attempt.proof = {sha256: "a".repeat(64), scansVerified: 99, filesVerified: 1};
    }],
    ["completion unsafe file count", ({state}) => {
      const attempt = state.jobs[0]!.attempts[0]!; attempt.status = "complete";
      attempt.proof = {sha256: "a".repeat(64), scansVerified: 1, filesVerified: Number.MAX_SAFE_INTEGER + 1};
    }],
    ["notification without completion", ({state}) => { state.completionDeliveredToAgent = true; }],
  ];
  for (const [label, change] of changes) {
    const saved = structuredClone(original);
    change(saved);
    for (const job of saved.config.jobs) for (const attempt of job.attempts) attempt.configHash = digest(attempt.workflow);
    saved.state.configHash = caseConfigHash(saved.config);
    await assert.rejects(saveCaseState(f.control, saved.config, saved.state), /integrity/, label);
    assert.throws(() => redactedCaseStatus(saved.config, saved.state), /integrity/, label);
    assert.deepEqual(await readFile(progressFile), progressBytes, label);
    // Recompute the envelope hash deliberately: schema validation must protect
    // even a self-consistent malformed temporary fixture, not just torn writes.
    await writeFile(stateFile, JSON.stringify({version: 1, sha256: digest(saved), ...saved}));
    await assert.rejects(loadCaseState(f.control), /integrity/, label);
    await writeFile(stateFile, originalBytes);
  }
});

test("saved case status survives later edits to its original plan files", linuxOnly, async () => {
  const f = await fixture();
  await initializeCase(f.filename, {execute: true});
  const before = await loadCaseState(f.control);
  await writeFile(f.filename, "invalid original case plan\n");
  await writeFile(f.workflowFiles[0]![0]!, "invalid original workflow plan\n");
  const after = await loadCaseState(f.control);
  assert.deepEqual(after, before);
  const status = redactedCaseStatus(after.config, after.state);
  assert.equal(status.complete, false);
  assert.equal(JSON.stringify(status).includes(f.root), false);
});

test("stale pending events are replaced in the same tick without bypassing transport cooldown", linuxOnly, async t => {
  const f = await fixture({attempts: 2});
  await initializeCase(f.filename, {execute: true});
  let now = Date.now();
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent, clock: () => now});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
  await tick(supervisor);
  f.agent.requests[0]!.reject(new Error("synthetic transport unavailable"));
  await settle();
  await tick(supervisor);
  const failed = (await loadCaseState(f.control)).state.outbox[0]!;
  assert.ok(failed.nextDeliveryAt > now);
  await supervisor.pause();
  await supervisor.resume();
  await tick(supervisor);
  const {state} = await loadCaseState(f.control);
  const current = state.outbox.filter(entry => entry.status === "pending" && entry.event.revision === state.revision);
  assert.equal(current.length, 1);
  assert.notEqual(current[0]!.event.eventId, failed.event.eventId);
  assert.equal(state.outbox.find(entry => entry.event.eventId === failed.event.eventId)!.status, "processed");
  assert.equal(f.agent.requests.length, 1);
  assert.equal(state.health, "agent-unavailable");
  now = failed.nextDeliveryAt;
  await tick(supervisor);
  assert.equal(f.agent.requests.length, 2);
  assert.equal(f.agent.requests[1]!.event.eventId, current[0]!.event.eventId);
  assert.equal((await loadCaseState(f.control)).state.health, "awaiting-agent");
});

test("retired observation delivery failures do not mask a native signal pause after recovery", linuxOnly, async t => {
  const f = await fixture();
  await initializeCase(f.filename, {execute: true});
  let now = Date.now();
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent, clock: () => now});
  t.after(() => supervisor.close());
  await tick(supervisor);
  const identity = f.host.launches[0]!.identity;
  f.host.observations.set(identity.unit, {status: "unknown"});
  await tick(supervisor);
  assert.equal(f.agent.requests[0]!.event.reason, "observation-unavailable");
  f.agent.requests[0]!.reject(new Error("synthetic retired transport failure"));
  await settle();
  await tick(supervisor);
  const failed = (await loadCaseState(f.control)).state;
  const deadline = failed.outbox[0]!.nextDeliveryAt;
  assert.ok(deadline > now);
  assert.equal(failed.health, "agent-unavailable");
  f.host.observations.set(identity.unit, {status: "paused", pauseReason: "signal"});
  await tick(supervisor);
  const paused = (await loadCaseState(f.control)).state;
  assert.equal(paused.outbox[0]!.status, "processed");
  assert.equal(paused.outbox[0]!.nextDeliveryAt, deadline, "retiring work preserves the durable dispatch cooldown");
  assert.equal(paused.health, "degraded", "a historical failure does not affect health without a pending delivery");
  now += 10 * 60_000;
  await tick(supervisor, 2);
  const recovered = (await loadCaseState(f.control)).state;
  assert.ok(recovered.outbox[0]!.nextDeliveryAt < now);
  assert.equal(recovered.health, "degraded");
  assert.equal(recovered.jobs[0]!.attempts[0]!.observation?.pauseReason, "signal");
  assert.equal(f.agent.requests.length, 1);
  assert.equal(f.host.launches.length, 1);
});

test("new failures and supervisor restart preserve consecutive transport backoff", linuxOnly, async () => {
  const f = await fixture({jobs: 3, maxConcurrent: 3});
  await initializeCase(f.filename, {execute: true});
  let now = Date.now();
  const first = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent, clock: () => now});
  await tick(first);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
  await tick(first);
  f.agent.requests[0]!.reject(new Error("synthetic first transport failure"));
  await settle();
  await tick(first);
  const firstDeadline = (await loadCaseState(f.control)).state.outbox[0]!.nextDeliveryAt;
  f.host.observations.set(f.host.launches[1]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
  await tick(first);
  assert.equal(f.agent.requests.length, 1);
  await first.close();
  const recoveredAgent = new FakeAgent();
  const second = await CaseSupervisor.open(f.control, {host: f.host, agent: recoveredAgent, clock: () => now});
  try {
    await tick(second);
    assert.equal(recoveredAgent.requests.length, 0);
    assert.equal((await loadCaseState(f.control)).state.health, "agent-unavailable");
    now = firstDeadline;
    await tick(second);
    assert.equal(recoveredAgent.requests.length, 1);
    assert.equal(recoveredAgent.requests[0]!.event.jobs.filter(job => job.status === "failed").length, 2);
    recoveredAgent.requests[0]!.reject(new Error("synthetic second transport failure"));
    await settle();
    await tick(second);
    const nextDeadline = Math.max(...(await loadCaseState(f.control)).state.outbox.map(entry => entry.nextDeliveryAt));
    assert.ok(nextDeadline >= now + 20_000);
    f.host.observations.set(f.host.launches[2]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
    await tick(second);
    assert.equal(recoveredAgent.requests.length, 1);
    now = nextDeadline;
    await tick(second);
    assert.equal(recoveredAgent.requests.length, 2);
    assert.equal(recoveredAgent.requests[1]!.event.jobs.filter(job => job.status === "failed").length, 3);
    recoveredAgent.reply(1, {type: "acknowledge"});
    await settle();
    await tick(second);
    assert.ok((await loadCaseState(f.control)).state.outbox.every(entry => entry.nextDeliveryAt === 0));
  } finally { await second.close(); }
});

test("agent registration retries reuse the bridge while approved native work continues", linuxOnly, async t => {
  const f = await fixture();
  f.agent.unavailablePreflights = 1;
  await initializeCase(f.filename, {execute: true});
  let now = Date.now();
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent, clock: () => now});
  t.after(() => supervisor.close());
  await tick(supervisor, 2);
  assert.equal(f.host.launches.length, 1);
  assert.equal(f.agent.preflights, 1);
  assert.equal((await loadCaseState(f.control)).state.health, "agent-unavailable");
  now += 60_000;
  await tick(supervisor);
  assert.equal(f.agent.preflights, 2);
  assert.equal(f.agent.closed, 0);
  assert.equal(f.host.launches.length, 1);
});

test("unavailable startup agent permits independent jobs but cannot authorize fresh retries", linuxOnly, async t => {
  const f = await fixture({jobs: 3, attempts: 2, maxConcurrent: 1});
  f.agent.unavailablePreflights = 100;
  await initializeCase(f.filename, {execute: true});
  let now = Date.now();
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent, clock: () => now});
  t.after(() => supervisor.close());
  for (let index = 0; index < 3; index++) {
    await tick(supervisor);
    assert.equal(f.host.launches.length, index + 1);
    assert.equal(f.host.launches[index]!.attempt.configFile, f.workflowFiles[index]![0]);
    f.host.observations.set(f.host.launches[index]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
    now += 60_000;
  }
  await tick(supervisor, 3);
  const {state} = await loadCaseState(f.control);
  assert.equal(state.health, "agent-unavailable");
  assert.equal(f.host.launches.length, 3);
  assert.equal(f.agent.requests.length, 0);
  assert.ok(state.jobs.every(job => job.attempts.length === 1));
  assert.ok(state.outbox.some(entry => entry.status === "pending"));
});

for (const recovered of [false, true]) {
  test(`a proven pre-launch refusal releases its slot${recovered ? " after restart reconciliation" : ""}`, linuxOnly, async t => {
    const f = await fixture({jobs: 2, maxConcurrent: 1});
    await initializeCase(f.filename, {execute: true});
    const saved = await loadCaseState(f.control);
    if (recovered) {
      saved.state.jobs[0]!.attempts.push({index: 0, token: randomUUID(), mode: "run", status: "launching", dispatched: true});
      await saveCaseState(f.control, saved.config, saved.state);
      f.host.reattach = async attempt => {
        if (attempt.configFile === f.workflowFiles[0]![0]) throw new EngineLaunchRefusedError();
        return undefined;
      };
    } else {
      const launch = f.host.launch.bind(f.host);
      f.host.launch = async (attempt, token, mode) => {
        if (attempt.configFile === f.workflowFiles[0]![0]) throw new EngineLaunchRefusedError();
        return launch(attempt, token, mode);
      };
    }
    const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
    t.after(() => supervisor.close());
    await tick(supervisor, 2);
    const {config, state} = await loadCaseState(f.control);
    const refused = state.jobs[0]!.attempts[0]!;
    assert.equal(refused.status, "failed");
    assert.equal(refused.launchRefused, true);
    assert.equal(refused.identity, undefined);
    assert.equal(state.jobs[1]!.attempts[0]!.status, "running");
    assert.equal(f.host.identities.size, 1);
    delete refused.launchRefused;
    await assert.rejects(saveCaseState(f.control, config, state), /case control integrity validation failed/u,
      "an ordinary unknown launch cannot be reclassified as failed without an invocation");
  });
}

test("the last permitted request remains awaiting-agent until it actually fails", linuxOnly, async t => {
  const f = await fixture({maxRequests: 1});
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
  await tick(supervisor, 2);
  assert.equal(f.agent.requests.length, 1);
  assert.equal((await loadCaseState(f.control)).state.health, "awaiting-agent");
  f.agent.requests[0]!.reject(new Error("synthetic last request failed"));
  await settle();
  await tick(supervisor);
  assert.equal((await loadCaseState(f.control)).state.health, "agent-unavailable");
  assert.equal(f.agent.requests.length, 1);
});

test("bounded progress is retained without invalidating an outstanding decision", linuxOnly, async t => {
  const f = await fixture({jobs: 2, attempts: 2});
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
  await tick(supervisor);
  const revision = f.agent.requests[0]!.event.revision;
  f.host.observations.set(f.host.launches[1]!.identity.unit, {status: "running", bytesScanned: 1024, filesScanned: 2,
    scanErrors: -1, failureCode: "/private/synthetic-value"});
  await tick(supervisor);
  const {state} = await loadCaseState(f.control);
  assert.equal(state.revision, revision);
  assert.deepEqual(state.jobs[1]!.attempts[0]!.observation, {status: "running", bytesScanned: 1024, filesScanned: 2});
  assert.equal(JSON.stringify(f.agent.requests[0]!.event).includes("/private/synthetic-value"), false);
  f.agent.reply(0, {type: "retry", jobId: "job-000001"});
  await settle();
  await tick(supervisor, 2);
  assert.equal((await loadCaseState(f.control)).state.jobs[0]!.attempts.length, 2);
});

test("a malformed control command requires review without poisoning persisted state", linuxOnly, async t => {
  const f = await fixture();
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await writeFile(path.join(f.control, "case-command.json"), JSON.stringify({version: 1, id: "-".repeat(36), desired: "running"}));
  await tick(supervisor, 2);
  const {state} = await loadCaseState(f.control);
  assert.equal(state.permissionReason, "new-plan-required");
  assert.equal(state.commandId, undefined);
  assert.equal(f.host.launches.length, 0);
});

test("consumer inputs stay bound to the exact verified producer attempt, including metadata aliases", linuxOnly, async () => {
  for (const alias of [false, true]) {
    const f = await fixture({jobs: 2, attempts: 2, maxConcurrent: 1});
    const firstProducer = JSON.parse(await readFile(f.workflowFiles[0]![0]!, "utf8"));
    let producingRoot = firstProducer.output as string;
    if (alias) {
      const alternateParent = path.join(f.root, "metadata-alias");
      await symlink(f.root, alternateParent, "dir");
      producingRoot = path.join(alternateParent, path.basename(producingRoot));
    }
    for (const filename of f.workflowFiles[1]!) {
      const config = JSON.parse(await readFile(filename, "utf8"));
      config.scans = [{inputs: [path.join(producingRoot, "selected-data")], provenance: "unknown"}];
      await writeFile(filename, JSON.stringify(config));
    }
    f.config.jobs[1]!.dependsOn = [f.config.jobs[0]!.id];
    await writeFile(f.filename, JSON.stringify(f.config));
    await initializeCase(f.filename, {execute: true});
    const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
    try {
      await tick(supervisor);
      f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "failed", failureCode: "unclassified-failure"});
      await tick(supervisor);
      f.agent.reply(0, {type: "retry", jobId: f.config.jobs[0]!.id});
      await settle();
      await tick(supervisor);
      const retry = f.host.launches.at(-1)!;
      assert.notEqual(retry.attempt.workflow.output, firstProducer.output);
      f.host.observations.set(retry.identity.unit, {status: "complete", scanErrors: 0});
      await tick(supervisor, 3);
      const {state} = await loadCaseState(f.control);
      assert.equal(state.jobs[0]!.attempts.at(-1)!.status, "complete");
      assert.equal(state.jobs[1]!.attempts.length, 0);
      assert.equal(state.permissionReason, "new-plan-required");
      assert.equal(state.complete, false);
      assert.equal(f.host.launches.length, 2);
    } finally { await supervisor.close(); }
  }
});

test("a consumer launches after its exact producer output passes verification", linuxOnly, async t => {
  const f = await fixture({jobs: 2, maxConcurrent: 1});
  const producer = JSON.parse(await readFile(f.workflowFiles[0]![0]!, "utf8"));
  const consumerFile = f.workflowFiles[1]![0]!;
  const consumer = JSON.parse(await readFile(consumerFile, "utf8"));
  consumer.scans = [{inputs: [path.join(producer.output, "selected-data")], provenance: "unknown"}];
  await writeFile(consumerFile, JSON.stringify(consumer));
  f.config.jobs[1]!.dependsOn = [f.config.jobs[0]!.id];
  await writeFile(f.filename, JSON.stringify(f.config));
  await initializeCase(f.filename, {execute: true});
  const supervisor = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  t.after(() => supervisor.close());
  await tick(supervisor);
  f.host.observations.set(f.host.launches[0]!.identity.unit, {status: "complete", scanErrors: 0});
  await tick(supervisor, 2);
  assert.equal(f.host.launches.length, 2);
  assert.equal(f.host.launches[1]!.attempt.configFile, consumerFile);
  assert.equal((await loadCaseState(f.control)).state.permissionReason, undefined);
});

test("read-only reattachment finds an uncertain running engine during a pause despite plan edits", linuxOnly, async () => {
  const f = await fixture();
  await initializeCase(f.filename, {execute: true});
  f.host.loseNextLaunchReply = true;
  const first = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  await tick(first);
  await first.pause();
  await first.close();
  await writeFile(f.workflowFiles[0]![0]!, "invalid edited plan\n");
  let attachments = 0;
  f.host.reattach = async (_attempt, token) => { attachments++; return f.host.identities.get(token); };
  const second = await CaseSupervisor.open(f.control, {host: f.host, agent: new FakeAgent()});
  try {
    await tick(second);
    const {state} = await loadCaseState(f.control);
    assert.equal(state.desired, "user-paused");
    assert.equal(state.jobs[0]!.attempts[0]!.status, "running");
    assert.ok(attachments >= 1);
    assert.equal(f.host.launches.length, 1);
  } finally { await second.close(); }
});

test("permission-blocked missing reattachments stay unknown and cannot start engines", linuxOnly, async () => {
  const f = await fixture();
  await initializeCase(f.filename, {execute: true});
  f.host.loseNextLaunchReply = true;
  const first = await CaseSupervisor.open(f.control, {host: f.host, agent: f.agent});
  await tick(first);
  await first.close();
  const saved = await loadCaseState(f.control);
  saved.state.permissionReason = "new-plan-required";
  await saveCaseState(f.control, saved.config, saved.state);
  f.host.reattach = async () => undefined;
  const second = await CaseSupervisor.open(f.control, {host: f.host, agent: new FakeAgent()});
  try {
    await tick(second, 2);
    const attempt = (await loadCaseState(f.control)).state.jobs[0]!.attempts[0]!;
    assert.equal(attempt.status, "launching");
    assert.equal(attempt.observation?.status, "unknown");
    assert.equal(f.host.launches.length, 1);
  } finally { await second.close(); }
});
