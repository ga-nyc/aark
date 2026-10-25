import assert from "node:assert/strict";
import { access, link, mkdir, readFile, readdir, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { mkdtemp } from "./helpers.js";
import { loadRecoveryConfig } from "../recovery/config.js";
import { buildRecoveryPlan } from "../recovery/plan.js";
import { redactedPlan, runRecoveryPlan } from "../recovery/runner.js";
import { acquireReusedUnallocatedStream, assessReusedUnallocatedStream } from "../recovery/reuse-unallocated.js";
import type { RecoveryConfig } from "../recovery/types.js";

async function fixture(): Promise<{
  root: string; config: RecoveryConfig; input: string; state: Record<string, unknown>;
  updateState: (mutate: (state: Record<string, unknown>) => void) => Promise<void>;
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-reuse-test-"));
  const oldRoot = path.join(root, "earlier-case");
  const source = path.join(root, "source.img");
  await writeFile(source, Buffer.alloc(4096));
  await mkdir(path.join(oldRoot, "runs"), { recursive: true });
  await mkdir(path.join(oldRoot, "recovery", "unallocated"), { recursive: true });
  const input = path.join(oldRoot, "recovery", "unallocated", "free-space.raw");
  await writeFile(input, Buffer.alloc(2048));
  const oldConfig: RecoveryConfig = {
    version: 1, caseId: "earlier-case", source, destination: oldRoot, execute: true, requireReadOnlySource: true,
    sectorOffset: 0, photoRecCommand: "partition_none,search",
    image: { enabled: false, path: path.join(oldRoot, "evidence", "source.img"), mapfile: path.join(oldRoot, "evidence", "source.map"), retryPasses: 0 },
    stages: { deletedMetadata: false, ntfsUndelete: false, unallocatedStream: true, signatureCarving: true,
      volumeShadows: false, residualMemory: false, deletedRegistryCells: false },
  };
  const plan = buildRecoveryPlan(oldConfig);
  const extraction = plan.steps[0]!;
  const results = [
    { id: "unallocated-stream", status: "completed", exitCode: 0, signal: null, terminationReason: null, executable: "blkls", args: extraction.args },
    { id: "signature-carving", status: "failed-disk-quota", exitCode: -1, executable: "photorec" },
  ];
  const runId = "synthetic-recovery-run";
  const state: Record<string, unknown> = { version: 1, runId, status: "failed", finishedAt: "2026-01-01T00:00:00.000Z", currentStep: null, plan, results };
  const updateState = async (mutate: (state: Record<string, unknown>) => void): Promise<void> => {
    mutate(state);
    const manifest = { runId, status: state.status, results: state.results };
    for (const [name, value, runSuffix] of [
      ["case-sensitive.json", state, "sensitive.json"], ["plan-redacted.json", redactedPlan(plan), "plan-redacted.json"],
      ["manifest-redacted.json", manifest, "manifest-redacted.json"],
    ] as const) {
      const text = JSON.stringify(value);
      await writeFile(path.join(oldRoot, name), text);
      await writeFile(path.join(oldRoot, "runs", `${runId}-${runSuffix}`), text);
    }
  };
  await updateState(() => undefined);
  const config: RecoveryConfig = { ...oldConfig, caseId: "new-carving-case", destination: path.join(root, "new-case"),
    unallocatedStreamFromCase: oldRoot, stages: { ...oldConfig.stages, unallocatedStream: false } };
  return { root, config, input, state, updateState };
}

test("carving follow-up plans reuse the completed stream without reimaging or reextracting", { skip: process.platform !== "linux" }, async () => {
  const f = await fixture();
  const filename = path.join(f.root, "followup.json");
  await writeFile(filename, JSON.stringify(f.config));
  const config = await loadRecoveryConfig(filename);
  const plan = buildRecoveryPlan(config);
  assert.deepEqual(plan.steps.map((step) => step.id), ["signature-carving"]);
  assert.equal(plan.steps[0]?.args[3], f.input);
  assert.equal(plan.steps[0]?.args[1], path.join(config.destination, "recovery", "carved", "recup"));
  assert.equal(JSON.stringify(redactedPlan(plan)).includes(f.root), false);
  assert.equal(redactedPlan(plan).reusesCompletedUnallocatedStream, true);
  const before = await readFile(path.join(config.unallocatedStreamFromCase!, "case-sensitive.json"));
  const assessment = await assessReusedUnallocatedStream(config);
  assert.deepEqual(assessment, { sourcePathsRedacted: true, sourceRecoveryStatus: "failed", stage: "unallocated-stream", bytes: "2048" });
  await assert.rejects(access(config.destination), { code: "ENOENT" });
  assert.equal((await readdir(config.unallocatedStreamFromCase!)).some((name) => name.endsWith(".lock")), false);
  assert.deepEqual(await readFile(path.join(config.unallocatedStreamFromCase!, "case-sensitive.json")), before);
});

test("reuse configuration rejects ambiguous extraction, overlap, missing carving, and arbitrary input paths", async () => {
  const f = await fixture();
  const filename = path.join(f.root, "case.json");
  for (const value of [
    { ...f.config, stages: { ...f.config.stages, unallocatedStream: true } },
    { ...f.config, stages: { ...f.config.stages, signatureCarving: false } },
    { ...f.config, unallocatedStreamFromCase: f.config.destination },
    { ...f.config, destination: path.join(f.config.unallocatedStreamFromCase!, "child") },
    { ...f.config, unallocatedStreamFromCase: "relative-case" },
    { ...f.config, unallocatedInput: f.input },
  ]) {
    await writeFile(filename, JSON.stringify(value));
    await assert.rejects(loadRecoveryConfig(filename));
  }
});

test("reuse refuses active, incomplete, mismatched, allocated, and foreign-source controls", { skip: process.platform !== "linux" }, async () => {
  const mutations: Array<(f: Awaited<ReturnType<typeof fixture>>) => Promise<void>> = [
    async (f) => f.updateState((s) => { s.status = "running"; }),
    async (f) => f.updateState((s) => { (s.results as Array<Record<string, unknown>>)[0]!.status = "failed"; }),
    async (f) => f.updateState((s) => { (s.results as Array<Record<string, unknown>>)[0]!.terminationReason = "abort"; }),
    async (f) => f.updateState((s) => { (s.plan as { steps: Array<Record<string, unknown>> }).steps[0]!.args = ["-a", f.config.source]; }),
    async (f) => { await writeFile(path.join(f.config.unallocatedStreamFromCase!, "case-sensitive.json"), "{}"); },
    async (f) => { f.config.source = path.join(f.root, "other-source"); await writeFile(f.config.source, Buffer.alloc(4096)); },
    async (f) => { f.config.requireReadOnlySource = false; },
    async (f) => { await unlink(f.input); },
    async (f) => { await link(f.input, path.join(f.root, "aliased-stream")); },
    async (f) => { await unlink(f.input); await symlink(f.config.source, f.input); },
  ];
  for (const mutate of mutations) {
    const f = await fixture();
    await mutate(f);
    await assert.rejects(acquireReusedUnallocatedStream(f.config));
    assert.equal((await readdir(f.config.unallocatedStreamFromCase!)).some((name) => name.endsWith(".lock")), false);
    await assert.rejects(access(f.config.destination), { code: "ENOENT" });
  }
});

test("reuse holds both compatibility locks and notices stream or control mutations", { skip: process.platform !== "linux" }, async () => {
  for (const mutateControl of [false, true]) {
    const f = await fixture();
    const before = await readFile(path.join(f.config.unallocatedStreamFromCase!, "case-sensitive.json"));
    const held = await acquireReusedUnallocatedStream(f.config);
    try {
      await held.assertCurrent();
      await assert.rejects(acquireReusedUnallocatedStream(f.config), /lock/);
      await assert.rejects(assessReusedUnallocatedStream(f.config), /lock/);
      if (mutateControl) await writeFile(path.join(f.config.unallocatedStreamFromCase!, "manifest-redacted.json"), "{}");
      else await writeFile(f.input, Buffer.alloc(2049));
      await assert.rejects(held.assertCurrent(), /changed/);
    } finally { await held.release(); }
    assert.deepEqual(await readFile(path.join(f.config.unallocatedStreamFromCase!, "case-sensitive.json")), before);
    assert.equal((await readdir(f.config.unallocatedStreamFromCase!)).some((name) => name.endsWith(".lock")), false);
  }
});

test("follow-up execution refuses missing confirmation and forged plans before touching either case", { skip: process.platform !== "linux" }, async () => {
  const f = await fixture();
  const plan = buildRecoveryPlan(f.config);
  await assert.rejects(runRecoveryPlan(f.config, plan, false), /execution requires/);
  await assert.rejects(runRecoveryPlan(f.config, { ...plan, steps: [] }, true), /exactly match/);
  assert.equal((await readdir(f.config.unallocatedStreamFromCase!)).some((name) => name.endsWith(".lock")), false);
  await assert.rejects(access(f.config.destination), { code: "ENOENT" });
});

test("an interrupted follow-up records its own status and releases both cases without relabeling the earlier failure", { skip: process.platform !== "linux" }, async () => {
  const f = await fixture();
  f.config.storage = { minFreeGiB: 0, minFreePercent: 0 };
  const originalState = await readFile(path.join(f.config.unallocatedStreamFromCase!, "case-sensitive.json"));
  const originalInput = await readFile(f.input);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(runRecoveryPlan(f.config, buildRecoveryPlan(f.config), true, controller.signal), /interrupted/);
  const manifest = JSON.parse(await readFile(path.join(f.config.destination, "manifest-redacted.json"), "utf8")) as Record<string, unknown>;
  assert.equal(manifest.status, "interrupted");
  assert.deepEqual(manifest.reusedUnallocatedStream, {
    sourcePathsRedacted: true, sourceRecoveryStatus: "failed", stage: "unallocated-stream", bytes: "2048",
  });
  assert.deepEqual(await readFile(path.join(f.config.unallocatedStreamFromCase!, "case-sensitive.json")), originalState);
  assert.deepEqual(await readFile(f.input), originalInput);
  for (const root of [f.config.destination, f.config.unallocatedStreamFromCase!]) {
    assert.equal((await readdir(root)).some((name) => name.endsWith(".lock")), false);
  }
});
