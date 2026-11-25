import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { access, mkdir, readFile, readdir, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { planRetention, runRetention, verifyRetention } from "../retention.js";
import { loadCompletedInventory, loadScanState } from "../mining/resume.js";
import type { ScanState } from "../mining/resume.js";
import { scanSensitiveMaterial } from "../mining/scanner.js";
import type { SensitiveScanInventory } from "../mining/types.js";
import { mkdtemp } from "./helpers.js";

const linux = { skip: process.platform !== "linux" };

async function fixture(t: test.TestContext, scans = 1, paddingMiB = 0) {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-retention-test-"));
  t.after(async () => { await rm(root, { recursive: true, force: true }); });
  const input = path.join(root, "originals");
  const destinationParent = path.join(root, "destination-disk");
  const destination = path.join(destinationParent, "fresh-bundle");
  await mkdir(input);
  await mkdir(destinationParent);
  const mnemonic = entropyToMnemonic(Buffer.alloc(16, 0x42), wordlist);
  const contents = Buffer.concat([Buffer.from(`synthetic original context\nwallet seed phrase: ${mnemonic}\n${"ordinary trailing context\n".repeat(128)}`), Buffer.alloc(paddingMiB * 1024 * 1024, 0x20)]);
  const source = path.join(input, "whole-source.txt");
  await writeFile(source, contents);
  await writeFile(path.join(input, "ordinary.txt"), "ordinary neighboring data\n");
  const miningOutputs: string[] = [];
  for (let index = 0; index < scans; index++) {
    const output = path.join(root, `mining-${index + 1}`);
    const result = await scanSensitiveMaterial({
      inputs: [input], output, provenance: "allocated-reference", cryptoOnly: true,
      chunkBytes: 17 * 1024 * 1024, overlapBytes: 17 * 1024 * 1024, wholeFileBytes: 1024 * 1024,
      workers: 1, minimumFreeGiB: 0, minimumFreePercent: 0,
    });
    assert.equal(result.status, "complete");
    miningOutputs.push(output);
  }
  const physicalDevices = async (filename: string) => [filename === destinationParent || filename.startsWith(destinationParent + path.sep)
    ? "/dev/synthetic-destination" : "/dev/synthetic-original"];
  const options = { miningOutputs, destination };
  const deps = { physicalDevices };
  return { root, input, source, contents, mnemonic, destinationParent, destination, miningOutputs, options, deps };
}

interface RetainedManifest {
  sources: Array<{ originalPath: string; relativePath: string; bytes: number; sha256: string; snapshots: Array<{scan: number; file: {path: string}}> }>;
  scans: Array<{number: number; originalOutput: string; relativeDirectory: string; runId: string}>;
  files: Array<{path: string; bytes: number; sha256: string; kind: "source" | "control" | "artifact"}>;
}

async function readManifest(bundle: string): Promise<RetainedManifest> {
  return JSON.parse(await readFile(path.join(bundle, "retention-manifest-sensitive.json"), "utf8")) as RetainedManifest;
}

async function exported(t: test.TestContext, scans = 1) {
  const f = await fixture(t, scans);
  const plan = await planRetention(f.options, f.deps);
  const result = await runRetention({ ...f.options, planToken: String(plan.planToken), execute: true }, f.deps);
  assert.equal(result.status, "complete");
  return { ...f, plan, result, manifest: await readManifest(f.destination) };
}

test("retention plan is read-only and export preserves whole sources, native controls, and frozen scope", linux, async t => {
  const f = await fixture(t);
  const output = f.miningOutputs[0]!;
  const stateBefore = await readFile(path.join(output, "scan-state-sensitive.json"));
  const inventoryBefore = await readFile(path.join(output, "inventory-sensitive.json"));
  const plan = await planRetention(f.options, f.deps);
  assert.equal(plan.status, "ready");
  assert.equal(plan.pathsRedacted, true);
  assert.equal(plan.sourceFilesRetained, "1");
  assert.equal(plan.sourceFileLogicalBytesRetained, f.contents.length.toString());
  assert.equal(plan.miningScansVerified, 1);
  assert.equal(plan.personalDataBackupComplete, false);
  assert.equal(plan.erasureAuthorized, false);
  assert.match(String(plan.planToken), /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(plan).includes(f.root), false);
  assert.equal(JSON.stringify(plan).includes(f.mnemonic), false);
  await assert.rejects(access(f.destination));
  await assert.rejects(runRetention({ ...f.options, planToken: String(plan.planToken), execute: false }, f.deps), /execute/);
  await assert.rejects(access(f.destination));
  const sourceBefore = await stat(f.source);
  const result = await runRetention({ ...f.options, planToken: String(plan.planToken), execute: true }, f.deps);
  assert.equal(result.status, "complete");
  assert.equal(result.personalDataBackupComplete, false);
  assert.equal(result.erasureAuthorized, false);
  assert.equal(JSON.stringify(result).includes(f.root), false);
  assert.equal(JSON.stringify(result).includes(f.mnemonic), false);
  assert.deepEqual(await readFile(f.source), f.contents);
  assert.equal((await stat(f.source)).ino, sourceBefore.ino);
  const manifest = await readManifest(f.destination);
  assert.equal((await stat(f.destination)).mode & 0o777, 0o700);
  assert.equal((await stat(path.join(f.destination, "retention-manifest-sensitive.json"))).mode & 0o777, 0o600);
  assert.equal(manifest.sources.length, 1);
  const source = manifest.sources[0]!;
  assert.equal(source.originalPath, f.source);
  assert.equal(source.sha256, createHash("sha256").update(f.contents).digest("hex"));
  assert.deepEqual(await readFile(path.join(f.destination, source.relativePath)), f.contents);
  assert.equal((await stat(path.join(f.destination, source.relativePath))).mode & 0o777, 0o600);
  const copiedMining = path.join(f.destination, manifest.scans[0]!.relativeDirectory);
  assert.deepEqual(await readFile(path.join(copiedMining, "scan-state-sensitive.json")), stateBefore);
  assert.deepEqual(await readFile(path.join(copiedMining, "inventory-sensitive.json")), inventoryBefore);
  const inventory = JSON.parse(inventoryBefore.toString()) as SensitiveScanInventory;
  assert.equal(inventory.resumeCheckpoint!.semantic.cryptoOnly, true);
  const artifact = inventory.findings[0]!.artifactIntegrity[0]!;
  const artifactBytes = await readFile(path.join(copiedMining, artifact.path));
  assert.ok(artifactBytes.length < f.contents.length);
  assert.ok(!artifactBytes.equals(f.contents));
  await assert.rejects(loadScanState(copiedMining), /output|path|canonical/);
  const originalState = await loadScanState(output);
  await assert.rejects(loadCompletedInventory(copiedMining, originalState.inventory), /output|path|checkpoint/);
  assert.equal((await verifyRetention({ bundle: f.destination })).status, "complete");
  for (const name of [".aark-mining.lock", ".agetnic-mining.lock"]) await assert.rejects(access(path.join(output, name)));
});

test("retention deduplicates a whole source across scans and verifies without original files or outputs", linux, async t => {
  const f = await exported(t, 2);
  assert.equal(f.plan.miningScansVerified, 2);
  assert.equal(f.plan.sourceFilesRetained, "1");
  assert.equal(f.manifest.sources.length, 1);
  assert.equal(f.manifest.sources[0]!.snapshots.length, 2);
  assert.equal(f.manifest.scans.length, 2);
  await rm(f.input, { recursive: true });
  for (const output of f.miningOutputs) await rm(output, { recursive: true });
  const result = await verifyRetention({ bundle: f.destination });
  assert.equal(result.status, "complete");
  assert.equal(result.sourceFilesRetained, "1");
  assert.equal(result.personalDataBackupComplete, false);
  assert.equal(result.erasureAuthorized, false);
  assert.equal(JSON.stringify(result).includes(f.root), false);
});

test("retention includes marker-only whole sources even when no exact artifact exists", linux, async t => {
  const f = await fixture(t);
  const output = f.miningOutputs[0]!;
  const inventoryPath = path.join(output, "inventory-sensitive.json");
  const inventory = JSON.parse(await readFile(inventoryPath, "utf8")) as SensitiveScanInventory;
  assert.equal(inventory.findings.length, 1);
  // No current detector emits marker-only findings. Construct and seal this
  // supported checkpoint variant entirely from a synthetic native scan.
  inventory.findings[0]!.confidence = "marker-only";
  inventory.findings[0]!.artifactFiles = [];
  inventory.findings[0]!.artifactIntegrity = [];
  await rm(path.join(output, "artifacts"), { recursive: true });
  await mkdir(path.join(output, "artifacts"));
  const encoded = Buffer.from(JSON.stringify(inventory, null, 2) + "\n");
  await writeFile(inventoryPath, encoded);
  const statePath = path.join(output, "scan-state-sensitive.json");
  const state = JSON.parse(await readFile(statePath, "utf8")) as ScanState;
  state.inventory.bytes = encoded.length;
  state.inventory.sha256 = createHash("sha256").update(encoded).digest("hex");
  await writeFile(statePath, JSON.stringify(state, null, 2) + "\n");
  const plan = await planRetention(f.options, f.deps);
  assert.equal(plan.sourceFilesRetained, "1");
  const result = await runRetention({ ...f.options, planToken: String(plan.planToken), execute: true }, f.deps);
  assert.equal(result.status, "complete");
  const manifest = await readManifest(f.destination);
  assert.equal(manifest.sources.length, 1);
  assert.equal(manifest.files.filter(file => file.kind === "artifact").length, 0);
  assert.deepEqual(await readFile(path.join(f.destination, manifest.sources[0]!.relativePath)), f.contents);
  assert.equal((await verifyRetention({ bundle: f.destination })).status, "complete");
});

test("retention refuses same or unknown physical backing and active native or compatibility scans", linux, async t => {
  const f = await fixture(t);
  await assert.rejects(planRetention(f.options, { physicalDevices: async () => ["/dev/same-disk"] }), /independent|physical|same|overlap/);
  await assert.rejects(planRetention(f.options, { physicalDevices: async () => [] }), /physical|independent|backing|unknown/);
  await assert.rejects(planRetention({ ...f.options, minimumFreeGiB: 0 }, f.deps), /reserve|minimum|at least|5/);
  await assert.rejects(planRetention({ ...f.options, minimumFreePercent: 0 }, f.deps), /reserve|minimum|at least|5/);
  for (const name of [".aark-mining.lock", ".agetnic-mining.lock"]) {
    const lock = path.join(f.miningOutputs[0]!, name);
    await writeFile(lock, "synthetic active operation\n");
    await assert.rejects(planRetention(f.options, f.deps), /lock|active/);
    await rm(lock);
  }
  await assert.rejects(access(f.destination));
});

test("retention rejects source, control, and destination backing changes after planning", linux, async t => {
  await t.test("source replacement", async t => {
    const f = await fixture(t);
    const plan = await planRetention(f.options, f.deps);
    await rename(f.source, path.join(f.root, "original-kept.txt"));
    await writeFile(f.source, f.contents);
    await assert.rejects(runRetention({ ...f.options, planToken: String(plan.planToken), execute: true }, f.deps), /changed|differs|identity|manifest|coverage/);
    await assert.rejects(access(f.destination));
  });
  await t.test("control corruption", async t => {
    const f = await fixture(t);
    const plan = await planRetention(f.options, f.deps);
    const inventory = path.join(f.miningOutputs[0]!, "inventory-sensitive.json");
    await writeFile(inventory, Buffer.concat([await readFile(inventory), Buffer.from(" ")]));
    await assert.rejects(runRetention({ ...f.options, planToken: String(plan.planToken), execute: true }, f.deps), /inventory|integrity|hash|changed/);
    await assert.rejects(access(f.destination));
  });
  await t.test("physical destination changed", async t => {
    const f = await fixture(t);
    const plan = await planRetention(f.options, f.deps);
    const changed = { physicalDevices: async (filename: string) => (await f.deps.physicalDevices(filename)).map(device => device === "/dev/synthetic-destination" ? "/dev/replacement-destination" : device) };
    await assert.rejects(runRetention({ ...f.options, planToken: String(plan.planToken), execute: true }, changed), /changed|token|plan|backing|identity/);
    await assert.rejects(access(f.destination));
  });
});

test("standalone retention verification rejects changed sources, artifacts, and extra files", linux, async t => {
  const f = await exported(t);
  const source = path.join(f.destination, f.manifest.sources[0]!.relativePath);
  const sourceBytes = await readFile(source);
  await writeFile(source, Buffer.alloc(sourceBytes.length, 0x23));
  await assert.rejects(verifyRetention({ bundle: f.destination }), /hash|integrity|changed|digest/);
  await writeFile(source, sourceBytes);
  await rm(source);
  await symlink(f.source, source);
  await assert.rejects(verifyRetention({ bundle: f.destination }), /symbolic|symlink|regular|identity|link/);
  await rm(source);
  await writeFile(source, sourceBytes);
  const artifact = f.manifest.files.find(file => file.kind === "artifact")!;
  const artifactPath = path.join(f.destination, artifact.path);
  const artifactBytes = await readFile(artifactPath);
  await writeFile(artifactPath, Buffer.alloc(artifactBytes.length, 0x24));
  await assert.rejects(verifyRetention({ bundle: f.destination }), /hash|integrity|changed|digest/);
  await writeFile(artifactPath, artifactBytes);
  const extra = path.join(f.destination, "unrecorded-file.txt");
  await writeFile(extra, "synthetic unexpected file\n");
  await assert.rejects(verifyRetention({ bundle: f.destination }), /unexpected|extra|file set|contents/);
  await rm(extra);
  assert.equal((await verifyRetention({ bundle: f.destination })).status, "complete");
});

test("retention interruption preserves a truthful partial attempt and refuses reuse", linux, async t => {
  const f = await fixture(t);
  const controller = new AbortController();
  const plan = await planRetention(f.options, f.deps);
  let interrupted = false;
  const deps = { physicalDevices: async (filename: string) => {
    if (!interrupted && existsSync(f.destination)) { interrupted = true; controller.abort(); }
    return await f.deps.physicalDevices(filename);
  } };
  await assert.rejects(runRetention({ ...f.options, planToken: String(plan.planToken), execute: true, signal: controller.signal }, deps), /interrupt|abort|signal/);
  assert.equal(interrupted, true);
  await access(f.source);
  const partial = JSON.parse(await readFile(path.join(f.destination, "manifest-redacted.json"), "utf8")) as {status: string};
  assert.notEqual(partial.status, "complete");
  await assert.rejects(verifyRetention({ bundle: f.destination }), /partial|complete|manifest|missing/);
  await assert.rejects(runRetention({ ...f.options, planToken: String(plan.planToken), execute: true }, f.deps), /exist|fresh|new/);
});


test("retention refuses an insufficient reviewed cap before creating the destination", linux, async t => {
  const f = await fixture(t, 1, 2);
  await assert.rejects(planRetention({ ...f.options, maximumOutputGiB: 0.001 }, f.deps), /cap|quota|size|storage/);
  await assert.rejects(access(f.destination));
  await access(f.source);
});

test("retention detects source, control, and physical binding changes during an export", linux, async t => {
  for (const change of ["source", "control", "physical"] as const) await t.test(change, async t => {
    const f = await fixture(t);
    const plan = await planRetention(f.options, f.deps);
    let changed = false;
    const deps = { physicalDevices: async (filename: string) => {
      if (existsSync(f.destination)) {
        if (!changed && change !== "physical") {
          changed = true;
          const target = change === "source" ? f.source : path.join(f.miningOutputs[0]!, "inventory-sensitive.json");
          const bytes = await readFile(target);
          await writeFile(target, Buffer.concat([bytes, Buffer.from("synthetic mutation\n")]));
        }
        if (change === "physical" && !filename.startsWith(f.destinationParent + path.sep) && filename !== f.destinationParent) {
          changed = true;
          return ["/dev/synthetic-replacement-source"];
        }
      }
      return await f.deps.physicalDevices(filename);
    } };
    await assert.rejects(runRetention({ ...f.options, planToken: String(plan.planToken), execute: true }, deps), /changed|binding|identity|snapshot|integrity/);
    assert.equal(changed, true);
    await access(f.source);
    const summary = JSON.parse(await readFile(path.join(f.destination, "manifest-redacted.json"), "utf8")) as {status: string};
    assert.notEqual(summary.status, "complete");
    await assert.rejects(verifyRetention({ bundle: f.destination }));
  });
});

test("retention permits native mining outputs on the independent destination disk", linux, async t => {
  const f = await fixture(t);
  const deps = { physicalDevices: async (filename: string) => [filename === f.input || filename.startsWith(f.input + path.sep)
    ? "/dev/synthetic-internal" : "/dev/synthetic-external"] };
  const plan = await planRetention(f.options, deps);
  const result = await runRetention({ ...f.options, planToken: String(plan.planToken), execute: true }, deps);
  assert.equal(result.status, "complete");
  await rm(f.input, { recursive: true });
  assert.equal((await verifyRetention({ bundle: f.destination })).status, "complete");
});

test("retention physical inspection is bounded independently of the source copy chunk count", linux, async t => {
  const counts: number[] = [];
  for (const paddingMiB of [0, 4]) {
    const f = await fixture(t, 1, paddingMiB);
    let calls = 0;
    const deps = { physicalDevices: async (filename: string) => { calls++; return await f.deps.physicalDevices(filename); } };
    const plan = await planRetention(f.options, deps);
    await runRetention({ ...f.options, planToken: String(plan.planToken), execute: true }, deps);
    counts.push(calls);
  }
  assert.ok(counts[1]! <= counts[0]! + 2, `physical probes grew with 1 MiB copy chunks: ${counts.join(" -> ")}`);
});

test("retention verifies an empty finding selection and still protects its original input storage", linux, async t => {
  const f = await fixture(t, 0);
  const ordinary = path.join(f.input, "ordinary.txt");
  const output = path.join(f.root, "ordinary-mining");
  const scan = await scanSensitiveMaterial({
    inputs: [ordinary], output, provenance: "allocated-reference", cryptoOnly: true,
    chunkBytes: 17 * 1024 * 1024, overlapBytes: 17 * 1024 * 1024, wholeFileBytes: 1024 * 1024,
    workers: 1, minimumFreeGiB: 0, minimumFreePercent: 0,
  });
  assert.equal(scan.status, "complete");
  const options = { ...f.options, miningOutputs: [output] };
  const deps = { physicalDevices: async (filename: string) => [filename === ordinary ? "/dev/synthetic-internal" : "/dev/synthetic-external"] };
  const plan = await planRetention(options, deps);
  assert.equal(plan.sourceFilesRetained, "0");
  assert.equal((await runRetention({ ...options, planToken: String(plan.planToken), execute: true }, deps)).status, "complete");
  await rm(f.input, { recursive: true });
  assert.equal((await verifyRetention({ bundle: f.destination })).status, "complete");
  const anotherDestination = path.join(f.destinationParent, "another-fresh-bundle");
  // A no-finding scan is no reason to forget which original medium its
  // completed selection described. Restore and rescan a fresh synthetic input.
  await mkdir(f.input);
  await writeFile(ordinary, "ordinary neighboring data\n");
  const replacementOutput = path.join(f.root, "replacement-mining");
  await scanSensitiveMaterial({ inputs: [ordinary], output: replacementOutput, provenance: "allocated-reference",
    chunkBytes: 17 * 1024 * 1024, overlapBytes: 17 * 1024 * 1024, wholeFileBytes: 1024 * 1024,
    workers: 1, minimumFreeGiB: 0, minimumFreePercent: 0 });
  await assert.rejects(planRetention({miningOutputs: [replacementOutput], destination: anotherDestination}, {physicalDevices: async () => ["/dev/synthetic-external"]}), /independent|physical|same|shares/);
});


async function regularFileBytes(directory: string): Promise<bigint> {
  let total = 0n;
  for (const entry of await readdir(directory, {withFileTypes: true})) {
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) total += await regularFileBytes(filename);
    else { assert.equal(entry.isFile(), true); total += BigInt((await stat(filename)).size); }
  }
  return total;
}

test("retention plans the exact complete bundle size including manifests and summary replacement", linux, async t => {
  const f = await fixture(t);
  const baseline = await planRetention(f.options, f.deps);
  const narrowCap = 1024n ** 3n / 1000n;
  const padding = Number(narrowCap - 512n - BigInt(String(baseline.logicalBytesToCopy)));
  assert.ok(padding > 0);
  await writeFile(f.source, Buffer.concat([f.contents, Buffer.alloc(padding, 0x20)]));
  const output = path.join(f.root, "near-cap-mining");
  const scan = await scanSensitiveMaterial({
    inputs: [f.input], output, provenance: "allocated-reference", cryptoOnly: true,
    chunkBytes: 17 * 1024 * 1024, overlapBytes: 17 * 1024 * 1024, wholeFileBytes: 1024 * 1024,
    workers: 1, minimumFreeGiB: 0, minimumFreePercent: 0,
  });
  assert.equal(scan.status, "complete");
  const options = { ...f.options, miningOutputs: [output] };
  const uncapped = await planRetention(options, f.deps);
  // The copies fit with a little headroom; required bundle metadata does not.
  // Earlier planning accepted this cap and failed only after copying the source.
  assert.ok(BigInt(String(uncapped.logicalBytesToCopy)) < narrowCap);
  assert.ok(BigInt(String(uncapped.logicalBundleBytes)) > narrowCap);
  await assert.rejects(planRetention({ ...options, maximumOutputGiB: 0.001 }, f.deps), /cap|quota|size|storage/);
  await assert.rejects(access(f.destination));

  const capped = { ...options, maximumOutputGiB: 0.002 };
  const plan = await planRetention(capped, f.deps);
  const result = await runRetention({ ...capped, planToken: String(plan.planToken), execute: true }, f.deps);
  assert.equal(result.status, "complete");
  const actual = await regularFileBytes(f.destination);
  assert.equal(BigInt(String(plan.logicalBundleBytes)), actual);
  assert.equal(BigInt(String(result.logicalBundleBytes)), actual);
  assert.ok(actual <= 2n * 1024n ** 3n / 1000n);
  assert.ok(actual > BigInt(String(plan.logicalBytesToCopy)));
  assert.equal((await verifyRetention({ bundle: f.destination })).status, "complete");
});
