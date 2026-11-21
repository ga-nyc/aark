import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { assertSourceBindings, CaseSourceIdentityError } from "../case/sources.js";
import { captureBlockMediaIdentityFrom, hasBlockMediaIdentity, recoverySourceIdentity,
  type BlockMediaIdentity, type BlockMediaNode, type BlockMediaProbe, type SourceSafety } from "../recovery/source-safety.js";
import { assertRecoveryQuotaSourceCurrent } from "../recovery/runner.js";
import type { WorkflowConfig } from "../workflow/config.js";
import { workflowSourceIdentity } from "../workflow/verify.js";

const BOOT = "11111111-1111-1111-1111-111111111111";
function fixture() {
  const nodes = new Map<string, BlockMediaNode>([
    ["/dev/dm-0", {device: "/dev/dm-0", majorMinor: "253:0", diskseq: "9007199254740993", parent: null, slaves: ["/dev/dm-1"]}],
    ["/dev/dm-1", {device: "/dev/dm-1", majorMinor: "253:1", diskseq: "9007199254740994", parent: null, slaves: ["/dev/sda1"]}],
    ["/dev/sda1", {device: "/dev/sda1", majorMinor: "8:1", diskseq: "18446744073709551615", parent: "/dev/sda", slaves: []}],
    ["/dev/sda", {device: "/dev/sda", majorMinor: "8:0", diskseq: "18446744073709551615", parent: null, slaves: []}],
    ["/dev/loop0", {device: "/dev/loop0", majorMinor: "7:0", diskseq: "20", parent: null, slaves: []}],
    ["/dev/sdb", {device: "/dev/sdb", majorMinor: "8:16", diskseq: "21", parent: null, slaves: []}],
  ]);
  const calls: string[] = [];
  const probe: BlockMediaProbe = {bootId: async () => BOOT, node: async device => {
    calls.push(device);
    const node = nodes.get(device === "/dev/mapper/authorized" ? "/dev/dm-0" : device);
    if (node === undefined) throw new Error("missing synthetic kernel metadata");
    return structuredClone(node);
  }};
  return {nodes, probe, calls};
}
function safety(media: BlockMediaIdentity): SourceSafety {
  return {resolvedSource: "/dev/dm-0", kind: "block-device", bytes: 4096, regularFileIdentity: null,
    blockDeviceIdentity: {device: 1, inode: 2, rawDevice: 253 * 256, media}, kernelReadOnly: true, writableMounts: [],
    sourceTopDevices: ["/dev/sda"], sourceTopDevice: "/dev/sda", sourceLoopBackings: [], destinationDevices: ["/dev/sdz"],
    destinationDevice: "/dev/sdz", destinationLoopBackings: [], destinationFilesystemDevice: 3, destinationMountSource: "/dev/sdz1",
    destinationBackingKind: "block-device", deviceComparisonCertain: true, destinationOnSourceDevice: false, safe: true, reasons: []};
}

test("raw generation snapshots include mapper dependencies, partition parents and loop-host physical devices exactly", async () => {
  const f = fixture();
  const media = await captureBlockMediaIdentityFrom(["/dev/mapper/authorized", "/dev/sda", "/dev/loop0", "/dev/sdb"], f.probe);
  assert.equal(media.version, 1);
  assert.equal(media.bootId, BOOT);
  assert.deepEqual(media.devices.map(node => node.device), ["/dev/dm-0", "/dev/dm-1", "/dev/loop0", "/dev/sda", "/dev/sda1", "/dev/sdb"]);
  assert.equal(media.devices[0]!.diskseq, "9007199254740993");
  assert.equal(media.devices.find(node => node.device === "/dev/sda")!.diskseq, "18446744073709551615");
  assert.ok(f.calls.filter(device => device === "/dev/dm-1").length >= 2);
  assert.equal(hasBlockMediaIdentity(safety(media)), true);
});

for (const changed of ["/dev/dm-0", "/dev/dm-1", "/dev/sda"] as const) {
  test(`a changed ${changed} generation refuses case authorization and native quota reuse despite identical node metadata`, async () => {
    const f = fixture();
    const original = safety(await captureBlockMediaIdentityFrom(["/dev/dm-0"], f.probe));
    f.nodes.get(changed)!.diskseq = "100";
    if (changed === "/dev/sda") f.nodes.get("/dev/sda1")!.diskseq = "100";
    const replacement = safety(await captureBlockMediaIdentityFrom(["/dev/dm-0"], f.probe));
    const oldIdentity = workflowSourceIdentity(original);
    const source = original.resolvedSource;
    const workflow = {recovery: {source, image: {enabled: false}}} as WorkflowConfig;
    const bindings = [{source, sha256: createHash("sha256").update(oldIdentity).digest("hex")}];
    await assertSourceBindings(workflow, bindings, [oldIdentity]);
    await assert.rejects(assertSourceBindings(workflow, bindings, [workflowSourceIdentity(replacement)]), CaseSourceIdentityError);
    assert.notEqual(recoverySourceIdentity(original), recoverySourceIdentity(replacement));
    assert.throws(() => assertRecoveryQuotaSourceCurrent(original, replacement), /source identity differs/u);
  });
}

test("a new kernel boot cannot reuse a raw media authorization even when diskseq repeats", async () => {
  const f = fixture();
  const original = safety(await captureBlockMediaIdentityFrom(["/dev/dm-0"], f.probe));
  const rebooted = structuredClone(original);
  rebooted.blockDeviceIdentity!.media!.bootId = "22222222-2222-2222-2222-222222222222";
  assert.notEqual(recoverySourceIdentity(original), recoverySourceIdentity(rebooted));
  assert.throws(() => assertRecoveryQuotaSourceCurrent(original, rebooted), /source identity differs/u);
});

test("missing, malformed and legacy raw generations fail closed without recapturing a new baseline", async () => {
  const f = fixture();
  const original = safety(await captureBlockMediaIdentityFrom(["/dev/dm-0"], f.probe));
  const legacy = structuredClone(original);
  delete legacy.blockDeviceIdentity!.media;
  assert.equal(hasBlockMediaIdentity(legacy), false);
  assert.equal(hasBlockMediaIdentity(workflowSourceIdentity(legacy)), false);
  assert.throws(() => recoverySourceIdentity(legacy), /kernel generation/u);
  assert.throws(() => assertRecoveryQuotaSourceCurrent(legacy, original), /source identity differs/u);
  for (const diskseq of ["", "0", "01", "-1", "1.5", "18446744073709551616"]) {
    f.nodes.get("/dev/sda")!.diskseq = diskseq;
    await assert.rejects(captureBlockMediaIdentityFrom(["/dev/dm-0"], f.probe), /kernel generation/u);
  }
  f.nodes.delete("/dev/sda");
  await assert.rejects(captureBlockMediaIdentityFrom(["/dev/dm-0"], f.probe));
});

test("media and topology changes between metadata snapshots refuse capture", async () => {
  for (const change of ["generation", "topology", "boot"] as const) {
    const f = fixture();
    let roots = 0;
    let boots = 0;
    const probe: BlockMediaProbe = {bootId: async () => change === "boot" && ++boots > 1 ? "22222222-2222-2222-2222-222222222222" : BOOT,
      node: async device => {
        if (device === "/dev/dm-0" && ++roots > 1) {
          if (change === "generation") f.nodes.get("/dev/sda")!.diskseq = "100";
          if (change === "topology") f.nodes.get("/dev/dm-0")!.slaves = ["/dev/sdb"];
        }
        return f.probe.node(device);
      }};
    await assert.rejects(captureBlockMediaIdentityFrom(["/dev/dm-0"], probe), /kernel generation/u);
  }
});

test("cyclic or oversized source-generation graphs cannot produce an authorization", async () => {
  const f = fixture();
  f.nodes.get("/dev/sda")!.slaves = ["/dev/dm-0"];
  await assert.rejects(captureBlockMediaIdentityFrom(["/dev/dm-0"], f.probe), /kernel generation/u);
  await assert.rejects(captureBlockMediaIdentityFrom(Array.from({length: 1025}, () => "/dev/sda"), f.probe), /kernel generation/u);
});

test("regular-file legacy source identities and quota retries retain their existing semantics", async () => {
  const f = fixture();
  const image: SourceSafety = {...safety(await captureBlockMediaIdentityFrom(["/dev/dm-0"], f.probe)), kind: "regular-file",
    resolvedSource: "/synthetic/source.img", blockDeviceIdentity: null,
    regularFileIdentity: {device: 1, inode: 2, bytes: 4096, modifiedMs: 3, changedMs: 4}};
  assert.equal(hasBlockMediaIdentity(image), true);
  assert.equal(recoverySourceIdentity(image), recoverySourceIdentity(workflowSourceIdentity(image)));
  assert.doesNotThrow(() => assertRecoveryQuotaSourceCurrent(image, structuredClone(image)));
  assert.throws(() => assertRecoveryQuotaSourceCurrent(image, {...image, regularFileIdentity: {...image.regularFileIdentity!, inode: 5}}), /source identity differs/u);
});
