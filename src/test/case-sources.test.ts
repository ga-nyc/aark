import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { rename, rm, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, {type TestContext} from "node:test";
import { assertSourceBindings, captureCaseSourceBindings, captureSourceBindings, CaseSourceIdentityError,
  caseRecoverySourcesToInspect, workflowExternalSources } from "../case/sources.js";
import type { CaseConfig, PreparedAttempt } from "../case/types.js";
import { inspectSourceSafety } from "../recovery/source-safety.js";
import { loadWorkflowConfig } from "../workflow/config.js";
import { workflowSourceIdentity } from "../workflow/verify.js";
import { mkdtemp } from "./helpers.js";

const linuxOnly = {skip: process.platform !== "linux"};
const hash = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
async function fixture(context: TestContext) {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-case-sources-test-"));
  context.after(() => rm(root, {recursive: true, force: true}));
  const source = path.join(root, "synthetic-source.img");
  const analysis = path.join(root, "synthetic-analysis.img");
  await writeFile(source, "ordinary synthetic image fixture\n");
  await writeFile(analysis, "ordinary synthetic analysis fixture\n");
  const destination = path.join(root, "recovery");
  const recoveryFile = path.join(root, "recovery.json");
  await writeFile(recoveryFile, JSON.stringify({version: 1, caseId: "synthetic-case", source, analysisSource: analysis, destination,
    requireReadOnlySource: true, execute: true, image: {enabled: false},
    stages: {deletedMetadata: false, ntfsUndelete: false, unallocatedStream: true, signatureCarving: true}}));
  const configFile = path.join(root, "workflow.json");
  await writeFile(configFile, JSON.stringify({version: 1, execute: true, output: path.join(root, "workflow"), recoveryConfig: recoveryFile,
    scans: [{inputs: [path.join(destination, "recovery", "carved")], provenance: "unallocated-carve"}],
    mining: {workers: 1, storage: {minFreeGiB: 0, minFreePercent: 0}}, finalizationStorage: {minFreeGiB: 0, minFreePercent: 0}}));
  const workflow = await loadWorkflowConfig(configFile);
  const attempt: PreparedAttempt = {configFile, workflow, configHash: hash(workflow)};
  const config: CaseConfig = {version: 1, execute: true, control: path.join(root, "control"), pollMs: 1000, probeTimeoutMs: 1000, maxConcurrent: 1,
    jobs: [{id: "job-000001", dependsOn: [], resumeAfterQuota: false, attempts: [attempt]}],
    agent: {ownership: "dedicated-thread", stateDirectory: path.join(root, "control", "agent-private"), executable: "/approved/codex",
      socketPath: "/approved/app.sock", user: "fixtureuser", threadId: "registered-parent", readableRoots: [path.join(root, "code")], timeoutMs: 1000, maxRequests: 4}};
  return {root, source, analysis, workflow, attempt, config};
}

test("case source authorization detects a replaced image inode despite unchanged path and configuration", linuxOnly, async context => {
  const f = await fixture(context);
  const beforeConfig = hash(f.workflow);
  const pins = await captureSourceBindings(f.workflow);
  await assertSourceBindings(f.workflow, pins);
  const replacement = path.join(f.root, "replacement.img");
  await writeFile(replacement, "ordinary synthetic image fixture\n");
  await rename(replacement, f.source);
  assert.equal(hash(f.workflow), beforeConfig);
  const changed = await captureSourceBindings(f.workflow);
  assert.notEqual(changed[0]!.sha256, pins[0]!.sha256);
  await assert.rejects(assertSourceBindings(f.workflow, pins), error => {
    assert.ok(error instanceof CaseSourceIdentityError);
    assert.equal(error.message.includes(f.root), false);
    return true;
  });
});

test("case captures every reviewed attempt and external source view without exposing identity details", linuxOnly, async context => {
  const f = await fixture(context);
  const second = structuredClone(f.attempt);
  second.workflow.output = path.join(f.root, "second-workflow");
  second.configHash = hash(second.workflow);
  f.config.jobs[0]!.attempts.push(second);
  const bindings = await captureCaseSourceBindings(f.config);
  assert.deepEqual(Object.keys(bindings), [f.attempt.configHash, second.configHash]);
  for (const attempt of f.config.jobs[0]!.attempts) {
    assert.deepEqual(bindings[attempt.configHash]!.map(binding => binding.source), [f.source, f.analysis]);
    assert.ok(bindings[attempt.configHash]!.every(binding => /^[a-f0-9]{64}$/u.test(binding.sha256)));
    await assertSourceBindings(attempt.workflow, bindings[attempt.configHash]!);
  }
  f.workflow.recovery!.image.enabled = true;
  f.workflow.recovery!.analysisSource = f.workflow.recovery!.image.path;
  assert.deepEqual(workflowExternalSources(f.workflow), [f.source]);
  assert.equal((await captureSourceBindings(f.workflow)).length, 1);
});

test("future producer sources are excluded while original analysis sources stay bound", linuxOnly, async context => {
  const f = await fixture(context);
  const producer = structuredClone(f.attempt);
  delete producer.workflow.recovery;
  producer.workflow.output = path.join(f.root, "producer");
  producer.workflow.scans = [{inputs: [f.source], provenance: "unknown"}];
  producer.configHash = hash(producer.workflow);
  f.attempt.workflow.recovery!.source = path.join(producer.workflow.output, "future.img");
  f.attempt.configHash = hash(f.attempt.workflow);
  f.config.jobs = [{id: "job-000001", dependsOn: [], resumeAfterQuota: false, attempts: [producer]},
    {id: "job-000002", dependsOn: ["job-000001"], resumeAfterQuota: false, attempts: [f.attempt]}];
  assert.deepEqual(await caseRecoverySourcesToInspect(f.config), [f.analysis]);
  const bindings = await captureCaseSourceBindings(f.config);
  assert.deepEqual(bindings[producer.configHash], []);
  assert.deepEqual(bindings[f.attempt.configHash]!.map(binding => binding.source), [f.analysis]);
  await assertSourceBindings(f.workflow, bindings[f.attempt.configHash]!);
});

test("native captured source identities use original positional ordering even for partial pins", linuxOnly, async context => {
  const f = await fixture(context);
  const pins = await captureSourceBindings(f.workflow, [f.analysis]);
  const captured = await Promise.all(workflowExternalSources(f.workflow).map(async source =>
    workflowSourceIdentity(await inspectSourceSafety(source, f.workflow.output))));
  await assertSourceBindings(f.workflow, pins, captured);
  await assert.rejects(assertSourceBindings(f.workflow, pins, [...captured].reverse()), CaseSourceIdentityError);
  await assert.rejects(assertSourceBindings(f.workflow, pins, []), CaseSourceIdentityError);
  await unlink(f.source); await unlink(f.analysis);
  // The native caller already captured these identities; comparison rereads no source.
  await assertSourceBindings(f.workflow, pins, captured);
});

test("invalid source pins fail fixed while unknown filesystem errors remain distinguishable", linuxOnly, async context => {
  const f = await fixture(context);
  const pins = await captureSourceBindings(f.workflow);
  await assert.rejects(assertSourceBindings(f.workflow, [{source: "/unapproved/source", sha256: "a".repeat(64)}]), CaseSourceIdentityError);
  await assert.rejects(assertSourceBindings(f.workflow, [pins[0]!, pins[0]!]), CaseSourceIdentityError);
  await assert.rejects(assertSourceBindings(f.workflow, [{source: f.source, sha256: "invalid"}]), CaseSourceIdentityError);
  await unlink(f.source);
  await assert.rejects(assertSourceBindings(f.workflow, pins), {code: "ENOENT"});
});

test("supervised captured raw identities reject legacy snapshots and a media generation change", linuxOnly, async context => {
  const f = await fixture(context);
  const captured = await Promise.all(workflowExternalSources(f.workflow).map(async source =>
    workflowSourceIdentity(await inspectSourceSafety(source, f.workflow.output))));
  const raw = {...JSON.parse(captured[0]!), kind: "block-device", regularFileIdentity: null,
    blockDeviceIdentity: {device: 1, inode: 2, rawDevice: 2048, media: {version: 1,
      bootId: "11111111-1111-1111-1111-111111111111", devices: [{device: "/dev/synthetic", majorMinor: "8:0",
        diskseq: "11", parent: null, slaves: []}]}}};
  captured[0] = JSON.stringify(raw);
  const pin = {source: f.source, sha256: createHash("sha256").update(captured[0]).digest("hex")};
  await assertSourceBindings(f.workflow, [pin], captured);
  raw.blockDeviceIdentity.media.devices[0]!.diskseq = "12";
  await assert.rejects(assertSourceBindings(f.workflow, [pin], [JSON.stringify(raw), captured[1]!]), CaseSourceIdentityError);
  const legacy = {...raw, blockDeviceIdentity: {device: 1, inode: 2, rawDevice: 2048}};
  const legacyText = JSON.stringify(legacy);
  const legacyPin = {source: f.source, sha256: createHash("sha256").update(legacyText).digest("hex")};
  await assert.rejects(assertSourceBindings(f.workflow, [legacyPin], [legacyText, captured[1]!]), CaseSourceIdentityError);
});
