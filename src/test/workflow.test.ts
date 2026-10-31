import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync } from "node:fs";
import { access, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { mkdtemp } from "./helpers.js";
import { captureCommand } from "../core/command.js";
import { loadWorkflowConfig } from "../workflow/config.js";
import { resumeWorkflow, runWorkflow, workflowPlan, workflowStatus } from "../workflow/runner.js";
import { workflowSourceIdentity } from "../workflow/verify.js";
import type { SourceSafety } from "../recovery/source-safety.js";
import type { LoopBackingIdentity } from "../core/mounts.js";

async function fixture(jobs = 1) {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-workflow-test-"));
  const output = path.join(root, "workflow");
  const filename = path.join(root, "workflow.json");
  const value = entropyToMnemonic(Buffer.alloc(16, 0x42), wordlist);
  const scans = [];
  for (let index = 0; index < jobs; index++) {
    const input = path.join(root, `input-${index}`);
    await mkdir(input);
    await writeFile(path.join(input, "synthetic-seed.txt"), `synthetic wallet seed phrase: ${value}\n`);
    scans.push({inputs: [input], provenance: "unallocated-carve"});
  }
  const config = {version: 1, execute: true, output, scans,
    mining: {workers: 1, storage: {minFreeGiB: 0, minFreePercent: 0}},
    finalizationStorage: {minFreeGiB: 0, minFreePercent: 0}};
  await writeFile(filename, JSON.stringify(config));
  return {root, output, filename, config, value};
}

test("workflow automatically verifies, deduplicates, and packages all selected scans", async () => {
  const f = await fixture(2);
  const phases: string[] = [];
  let locksObserved = true;
  const result = await runWorkflow(f.filename, {execute: true, progress: snapshot => {
    phases.push(String(snapshot.phase));
    if (snapshot.phase === "packaging") for (const number of [1, 2]) for (const name of [".aark-mining.lock", ".agetnic-mining.lock"]) {
      locksObserved &&= existsSync(path.join(f.output, "mining", `scan-${String(number).padStart(6, "0")}`, name));
    }
  }});
  assert.equal(result.status, "complete");
  assert.equal(locksObserved, true);
  assert.deepEqual([...new Set(phases)], ["mining", "verification", "packaging", "complete"]);
  const summary = JSON.parse(await readFile(path.join(f.output, "manifest-redacted.json"), "utf8"));
  assert.equal(summary.scansVerified, 2);
  assert.equal(summary.distinctFindingFingerprints, 1);
  assert.equal(summary.artifactFilesVerified, 1);
  assert.equal(summary.cleanupAuthorized, false);
  const index = JSON.parse(await readFile(path.join(f.output, summary.packageDirectory, "index-sensitive.json"), "utf8"));
  assert.deepEqual(index.findings[0].scans, [1, 2]);
  const artifact = index.findings[0].artifacts[0];
  const bytes = await readFile(path.join(f.output, summary.packageDirectory, artifact.path));
  assert.equal(createHash("sha256").update(bytes).digest("hex"), artifact.sha256);
  assert.equal(bytes.toString(), f.value);
  for (const scan of f.config.scans) await access(path.join(scan.inputs[0]!, "synthetic-seed.txt"));
  await access(path.join(f.output, "mining", "scan-000001", "inventory-sensitive.json"));
  await assert.rejects(access(path.join(f.output, ".aark-workflow.lock")));
  const status = await workflowStatus(f.output);
  assert.equal(status.status, "complete");
  assert.equal(status.processObserved, false);
  assert.equal(JSON.stringify(status).includes(f.root), false);
  assert.equal(JSON.stringify(result).includes(f.value), false);
  assert.equal(JSON.stringify(result).includes(f.root), false);
});

test("workflow plan is read-only and execution requires both confirmations", async () => {
  const f = await fixture();
  const plan = workflowPlan(await loadWorkflowConfig(f.filename));
  assert.equal(plan.automaticFinalization, true);
  await assert.rejects(runWorkflow(f.filename, {execute: false}), /execute/);
  await assert.rejects(access(f.output));
  await writeFile(f.filename, JSON.stringify({...f.config, execute: false}));
  await assert.rejects(runWorkflow(f.filename, {execute: true}), /execute/);
  await assert.rejects(access(f.output));
  await writeFile(f.filename, JSON.stringify({...f.config, cleanup: true}));
  await assert.rejects(loadWorkflowConfig(f.filename), /fields/);
});

async function pauseFinalization() {
  const f = await fixture();
  const controller = new AbortController();
  const result = await runWorkflow(f.filename, {execute: true, signal: controller.signal,
    progress: snapshot => { if (snapshot.phase === "packaging") controller.abort(); }});
  assert.equal(result.status, "paused");
  assert.equal(result.resumable, true);
  assert.equal((await workflowStatus(f.output)).pauseReason, "signal");
  await assert.rejects(access(path.join(f.output, "manifest-redacted.json")));
  return f;
}

test("a clean finalization pause resumes automatically without rerunning completed scans", async () => {
  const f = await pauseFinalization();
  const nativeState = path.join(f.output, "mining", "scan-000001", "scan-state-sensitive.json");
  const before = await readFile(nativeState);
  const result = await resumeWorkflow(f.output, {execute: true});
  assert.equal(result.status, "complete");
  assert.deepEqual(await readFile(nativeState), before);
  const entries = await readdir(f.output);
  assert(entries.includes("finalization-000001"));
  assert(entries.includes("finalization-000002"));
});

test("workflow resume refuses changed inputs and never publishes completion", async () => {
  const f = await pauseFinalization();
  await writeFile(path.join(f.config.scans[0]!.inputs[0]!, "new-unscanned.txt"), "synthetic new data");
  await assert.rejects(resumeWorkflow(f.output, {execute: true}), /workflow failed/);
  assert.equal((await workflowStatus(f.output)).status, "failed");
  assert.equal((await workflowStatus(f.output)).needsReview, true);
  await assert.rejects(access(path.join(f.output, "manifest-redacted.json")));
  await assert.rejects(resumeWorkflow(f.output, {execute: true}), /explicitly paused/);
});

test("workflow resume rejects artifact corruption and configuration drift", async () => {
  const f = await pauseFinalization();
  const mining = path.join(f.output, "mining", "scan-000001");
  const inventory = JSON.parse(await readFile(path.join(mining, "inventory-sensitive.json"), "utf8"));
  await writeFile(path.join(mining, inventory.findings[0].artifactFiles[0]), "synthetic corrupted artifact");
  await assert.rejects(resumeWorkflow(f.output, {execute: true}), /workflow failed/);
  await assert.rejects(access(path.join(f.output, "manifest-redacted.json")));
  const other = await pauseFinalization();
  await writeFile(other.filename, JSON.stringify({...other.config, mining: {...other.config.mining, workers: 2}}));
  await assert.rejects(resumeWorkflow(other.output, {execute: true}), /configuration changed/);
});

test("a later scan failure retains earlier outputs and reports workflow failure", async () => {
  const f = await fixture(2);
  f.config.scans[1]!.inputs = [path.join(f.root, "missing-input")];
  await writeFile(f.filename, JSON.stringify(f.config));
  await assert.rejects(runWorkflow(f.filename, {execute: true}), /workflow failed/);
  const status = await workflowStatus(f.output);
  assert.equal(status.status, "failed");
  assert.equal(status.scansCompleted, 1);
  assert.equal(status.resumable, false);
  await access(path.join(f.output, "mining", "scan-000001", "inventory-sensitive.json"));
  await assert.rejects(access(path.join(f.output, "manifest-redacted.json")));
});

test("workflow CLI completes the whole sequence and status filters injected fields", async () => {
  const f = await fixture();
  const cli = path.join(process.cwd(), "dist", "cli.js");
  const plan = await captureCommand(process.execPath, [cli, "workflow", "plan", "--config", f.filename]);
  assert.equal(plan.exitCode, 0);
  assert.equal(plan.stdout.includes(Buffer.from(f.root)), false);
  await assert.rejects(access(f.output));
  const run = await captureCommand(process.execPath, [cli, "workflow", "run", "--config", f.filename, "--execute", "--quiet"]);
  assert.equal(run.exitCode, 0);
  assert.equal(JSON.parse(run.stdout.toString()).status, "complete");
  assert.equal(run.stdout.includes(Buffer.from(f.value)), false);
  assert.equal(run.stdout.includes(Buffer.from(f.root)), false);
  await writeFile(path.join(f.output, "progress-redacted.json"), JSON.stringify({version: 1, tool: "aark", layer: "workflow",
    status: "running", sourcePathsRedacted: true, phase: "packaging", processId: 2147483647, scansCompleted: 1,
    summary: {source: f.root, value: f.value}, phaseName: f.value, failureClass: f.value}));
  const status = await captureCommand(process.execPath, [cli, "workflow", "status", "--output", f.output]);
  assert.equal(status.exitCode, 0);
  assert.equal(JSON.parse(status.stdout.toString()).processObserved, false);
  assert.equal(JSON.parse(status.stdout.toString()).needsReview, true);
  assert.equal(status.stdout.includes(Buffer.from(f.value)), false);
  assert.equal(status.stdout.includes(Buffer.from(f.root)), false);
  await assert.rejects(resumeWorkflow(f.output, {execute: true}), /explicitly paused/);
});

test("storage preflight fails explicitly before creating workflow output", async () => {
  const f = await fixture();
  await writeFile(f.filename, JSON.stringify({...f.config, finalizationStorage: {minFreeGiB: 1_000_000_000, minFreePercent: 5}}));
  await assert.rejects(runWorkflow(f.filename, {execute: true}), /free-space reserve/);
  await assert.rejects(access(f.output));
});

test("failed recovery stops before mining and leaves a truthful workflow status", {skip: process.platform !== "linux"}, async () => {
  const f = await fixture();
  const recovery = path.join(f.root, "recovery.json");
  const source = path.join(f.root, "synthetic-invalid-image.img");
  const destination = path.join(f.root, "case");
  await writeFile(source, Buffer.alloc(512));
  await writeFile(recovery, JSON.stringify({version: 1, caseId: "synthetic-workflow", source, destination,
    execute: true, requireReadOnlySource: true, image: {enabled: false}, storage: {minFreeGiB: 0, minFreePercent: 0},
    stages: {deletedMetadata: false, ntfsUndelete: false, unallocatedStream: true, signatureCarving: false,
      volumeShadows: false, residualMemory: false, deletedRegistryCells: false}}));
  await writeFile(f.filename, JSON.stringify({...f.config, recoveryConfig: recovery,
    scans: [{inputs: [path.join(destination, "recovery", "unallocated", "free-space.raw")], provenance: "unallocated-stream"}]}));
  await assert.rejects(runWorkflow(f.filename, {execute: true}), /workflow failed/);
  assert.equal((await workflowStatus(f.output)).status, "failed");
  assert.equal((await workflowStatus(f.output)).scansCompleted, 0);
  await assert.rejects(access(path.join(f.output, "mining")));
  await assert.rejects(access(path.join(f.output, "manifest-redacted.json")));
});

test("clean native mining pauses resume through the workflow checkpoint", async () => {
  const f = await fixture();
  const controller = new AbortController();
  const paused = await runWorkflow(f.filename, {execute: true, signal: controller.signal, progress: snapshot => {
    if (snapshot.phase === "mining" && snapshot.currentScanFilesScanned !== undefined) controller.abort();
  }});
  assert.equal(paused.status, "paused");
  const nativeState = path.join(f.output, "mining", "scan-000001", "scan-state-sensitive.json");
  const before = JSON.parse(await readFile(nativeState, "utf8"));
  assert.equal(before.status, "paused");
  assert.equal(before.resumable, true);
  const result = await resumeWorkflow(f.output, {execute: true});
  assert.equal(result.status, "complete");
  assert.equal(JSON.parse(await readFile(nativeState, "utf8")).runId, before.runId);
});

test("source guards tolerate destination writes while preserving source and container bindings", () => {
  const backing = {device: "synthetic-loop", backingFile: "/synthetic/container", fileDevice: "1", fileInode: "2",
    bytes: 1000, offset: 0, sizeLimit: 0, mount: "synthetic-mount", modifiedNs: "1", changedNs: "1"} as unknown as LoopBackingIdentity;
  const base = {sourceLoopBackings: [backing], destinationLoopBackings: [backing]} as unknown as SourceSafety;
  const expected = workflowSourceIdentity(base);
  assert.equal(workflowSourceIdentity({...base, destinationLoopBackings: [{...backing, modifiedNs: "2", changedNs: "2"}]}), expected);
  assert.notEqual(workflowSourceIdentity({...base, sourceLoopBackings: [{...backing, modifiedNs: "2"}]}), expected);
  assert.notEqual(workflowSourceIdentity({...base, destinationLoopBackings: [{...backing, fileInode: "3"}]}), expected);
  const image = {...base, kind: "regular-file"} as SourceSafety;
  assert.equal(workflowSourceIdentity({...image, sourceLoopBackings: [{...backing, modifiedNs: "2"}]}), workflowSourceIdentity(image));
});

test("a native recovery feeds mining and finalization in the same invocation", {skip: process.platform !== "linux"}, async context => {
  try { await access("/usr/sbin/mkfs.ext4"); await access("/usr/bin/blkls"); }
  catch { context.skip("requires local mkfs.ext4 and blkls for a synthetic regular-file filesystem"); return; }
  const f = await fixture();
  const source = path.join(f.root, "synthetic-filesystem.img");
  const destination = path.join(f.root, "case");
  const recovery = path.join(f.root, "recovery.json");
  await writeFile(source, Buffer.alloc(32 * 1024 ** 2));
  const formatted = await captureCommand("/usr/sbin/mkfs.ext4", ["-q", "-F", source], {timeoutMs: 10000});
  assert.equal(formatted.exitCode, 0);
  await writeFile(recovery, JSON.stringify({version: 1, caseId: "synthetic-workflow", source, destination,
    execute: true, requireReadOnlySource: true, image: {enabled: false}, storage: {minFreeGiB: 0, minFreePercent: 0},
    stages: {deletedMetadata: false, ntfsUndelete: false, unallocatedStream: true, signatureCarving: false,
      volumeShadows: false, residualMemory: false, deletedRegistryCells: false}}));
  await writeFile(f.filename, JSON.stringify({...f.config, recoveryConfig: recovery,
    scans: [{inputs: [path.join(destination, "recovery", "unallocated", "free-space.raw")], provenance: "unallocated-stream"}]}));
  const phases: string[] = [];
  const result = await runWorkflow(f.filename, {execute: true, progress: snapshot => { phases.push(String(snapshot.phase)); }});
  assert.equal(result.status, "complete");
  assert.deepEqual([...new Set(phases)], ["recovery", "mining", "verification", "packaging", "complete"]);
  assert.equal(JSON.parse(await readFile(path.join(destination, "manifest-redacted.json"), "utf8")).status, "complete");
  assert.equal(JSON.parse(await readFile(path.join(f.output, "manifest-redacted.json"), "utf8")).scansVerified, 1);
});

test("completed mining controls cannot change before final publication", async () => {
  const f = await fixture(2);
  let changed = false;
  await assert.rejects(runWorkflow(f.filename, {execute: true, progress: snapshot => {
    if (!changed && snapshot.phase === "mining" && snapshot.scansCompleted === 1) {
      changed = true;
      appendFileSync(path.join(f.output, "mining", "scan-000001", "scan-state-sensitive.json"), "\n");
    }
  }}), /workflow failed/);
  assert.equal(changed, true);
  assert.equal((await workflowStatus(f.output)).status, "failed");
  await assert.rejects(access(path.join(f.output, "manifest-redacted.json")));
});

test("a failed progress observer cannot undo committed workflow completion", async () => {
  const f = await fixture();
  const result = await runWorkflow(f.filename, {execute: true, progress: snapshot => {
    if (snapshot.status === "complete") throw new Error("synthetic observer failure");
  }});
  assert.equal(result.status, "complete");
  assert.equal((await workflowStatus(f.output)).status, "complete");
  await access(path.join(f.output, "manifest-redacted.json"));
});

test("recovery source preflight happens before creating a separate workflow destination", {skip: process.platform !== "linux"}, async () => {
  const f = await fixture();
  const destination = path.join(f.root, "case");
  const recovery = path.join(f.root, "recovery.json");
  await writeFile(recovery, JSON.stringify({version: 1, caseId: "synthetic-invalid-source", source: "/dev/zero", destination,
    execute: true, requireReadOnlySource: true, image: {enabled: false},
    stages: {deletedMetadata: false, ntfsUndelete: false, unallocatedStream: true, signatureCarving: false,
      volumeShadows: false, residualMemory: false, deletedRegistryCells: false}}));
  await writeFile(f.filename, JSON.stringify({...f.config, recoveryConfig: recovery,
    scans: [{inputs: [path.join(destination, "recovery", "unallocated", "free-space.raw")], provenance: "unallocated-stream"}]}));
  await assert.rejects(runWorkflow(f.filename, {execute: true}), /block device or regular image file/);
  await assert.rejects(access(f.output));
  await assert.rejects(access(destination));
});
