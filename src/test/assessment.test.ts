import assert from "node:assert/strict";
import { access, mkdir, open, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { StorageQuotaError } from "../core/storage.js";
import { assessRecoveryStorage, assertStageMinimumCapacity, estimateStageBytes, parseNtfsUnallocatedBytes, stageCapacityForecast, storageAssessment } from "../recovery/assessment.js";
import { buildRecoveryPlan } from "../recovery/plan.js";
import type { CapacityFacts } from "../recovery/assessment.js";
import type { RecoveryConfig } from "../recovery/types.js";
import { mkdtemp } from "./helpers.js";

function config(root: string): RecoveryConfig {
  const destination = path.join(root, "new", "case");
  return { version: 1, caseId: "synthetic-assessment", source: path.join(root, "source.img"), destination,
    requireReadOnlySource: true, execute: false, sectorOffset: 0, photoRecCommand: "partition_none,search",
    storage: { minFreeGiB: 0, minFreePercent: 0 },
    image: { enabled: true, path: path.join(destination, "evidence", "source.img"), mapfile: path.join(destination, "evidence", "source.map"), retryPasses: 0 },
    stages: { deletedMetadata: true, ntfsUndelete: true, unallocatedStream: true, signatureCarving: true,
      volumeShadows: false, residualMemory: false, deletedRegistryCells: false } };
}

function facts(): CapacityFacts {
  return { sourceBytes: 8192n, unallocatedBytes: 4096n, allocationUnitBytes: 4096n,
    capacity: { availableBytes: 16_384n, totalBytes: 32_768n, reservedBytes: 4096n, outputBytes: 0n, plannedBytes: 0n } };
}

test("assessment budgets simultaneous known copies while keeping unknown stages explicit", () => {
  const report = storageAssessment(config(path.join(os.tmpdir(), "synthetic-assessment")), facts());
  assert.equal(report.knownMinimumFits, true);
  assert.equal(report.knownLogicalBytes, "12288");
  assert.equal(report.fullWorkflowFits, "unknown");
  assert.equal(report.status, "uncertain-total");
  assert.deepEqual(report.unknownOutputStages, ["deleted-metadata", "ntfs-undelete", "signature-carving"]);
  const short = facts();
  short.capacity.availableBytes -= 1n;
  assert.equal(storageAssessment(config(os.tmpdir()), short).status, "insufficient-for-known-outputs");
});

test("physical allocation and the logical cap are independent storage constraints", () => {
  const input = config(os.tmpdir());
  input.stages.unallocatedStream = false;
  const physical = facts();
  physical.sourceBytes = 1n;
  physical.allocationUnitBytes = 131_072n;
  const report = storageAssessment(input, physical);
  assert.equal(report.knownLogicalBytes, "1");
  assert.equal(report.knownAllocationRoundedBytes, "131072");
  assert.equal(report.knownMinimumFits, false);
  const logical = { ...facts(), maximumOutputBytes: 12_287n };
  assert.equal(storageAssessment(config(os.tmpdir()), logical).knownMinimumExceedsOutputCap, true);
});

test("an unavailable filesystem estimate is unknown rather than zero or a promise of capacity", () => {
  const report = storageAssessment(config(os.tmpdir()), { ...facts(), unallocatedBytes: null });
  assert.ok((report.unknownOutputStages as string[]).includes("unallocated-stream"));
  assert.equal((report.estimates as Array<{ stage: string; logicalBytes: string | null }>).find((e) => e.stage === "unallocated-stream")?.logicalBytes, null);
  assert.equal(report.fullWorkflowFits, "unknown");
});

test("NTFS free-space probing validates units, geometry, duplicates, and source bounds", () => {
  const text = "Volume Name: synthetic-private-label\nCluster Size: 4096\nVolume Size in Clusters: 100\nFree Clusters: 90 (90%)\n";
  assert.equal(parseNtfsUnallocatedBytes(text, 409_600n), 368_640n);
  assert.equal(parseNtfsUnallocatedBytes(text, 409_599n), null);
  assert.equal(parseNtfsUnallocatedBytes(text.replace("90 (90%)", "101"), 409_600n), null);
  assert.equal(parseNtfsUnallocatedBytes(text.replace("4096", "4097"), 500_000n), null);
  assert.equal(parseNtfsUnallocatedBytes(text + "Free Clusters: 90\n", 409_600n), null);
  assert.equal(parseNtfsUnallocatedBytes("not a supported filesystem", 409_600n), null);
});

test("a known non-resumable stage is refused before its output can exceed headroom or the cap", () => {
  const input = facts();
  assertStageMinimumCapacity(12_288n, input.capacity, input.allocationUnitBytes, 0n);
  assert.throws(() => assertStageMinimumCapacity(12_289n, input.capacity, input.allocationUnitBytes, 0n),
    (error: unknown) => error instanceof StorageQuotaError && error.reason === "free-space-reserve" && error.capacity.plannedBytes === 16_384n);
  assert.throws(() => assertStageMinimumCapacity(4096n, input.capacity, 4096n, 8192n, 12_287n),
    (error: unknown) => error instanceof StorageQuotaError && error.reason === "output-cap");
  assert.deepEqual(stageCapacityForecast(null, input.capacity, 4096n, null, 100n), {
    additionalLogicalBytes: null, additionalAllocationRoundedBytes: null, fitsFreeSpace: null, fitsOutputCap: null,
  });
});

test("live assessment leaves a synthetic source and a nonexistent destination unchanged", { skip: process.platform !== "linux" }, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-assessment-"));
  const input = config(root);
  input.stages.unallocatedStream = false;
  await writeFile(input.source, Buffer.alloc(8192, 7));
  const before = await stat(input.source);
  const report = await assessRecoveryStorage(input);
  assert.equal(report.knownLogicalBytes, "8192");
  assert.equal(JSON.stringify(report).includes(root), false);
  assert.equal((await stat(input.source)).mtimeMs, before.mtimeMs);
  assert.deepEqual(await readFile(input.source), Buffer.alloc(8192, 7));
  await assert.rejects(access(input.destination));
});

test("physical allocation can exhaust headroom without increasing the logical case size", () => {
  const capacity = { ...facts().capacity, availableBytes: 8192n, reservedBytes: 0n, outputBytes: 16384n };
  const forecast = stageCapacityForecast(0n, capacity, 4096n, 16384n, 16384n, 12288n);
  assert.equal(forecast.additionalLogicalBytes, "0");
  assert.equal(forecast.additionalAllocationRoundedBytes, "12288");
  assert.equal(forecast.fitsOutputCap, true);
  assert.equal(forecast.fitsFreeSpace, false);
  assert.throws(() => assertStageMinimumCapacity(0n, capacity, 4096n, 16384n, 16384n, 12288n),
    (error: unknown) => error instanceof StorageQuotaError
      && error.reason === "free-space-reserve" && error.capacity.plannedBytes === 12288n);
});

test("image forecasts distinguish file extension from filling existing sparse holes", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-image-forecast-"));
  const input = config(root);
  const step = buildRecoveryPlan(input).steps.find(item => item.id === "image-fast-pass");
  assert.ok(step);
  const sourceBytes = 2 * 1024 * 1024;
  assert.deepEqual(await estimateStageBytes(step, sourceBytes, input.source, 0), {
    logicalBytes: BigInt(sourceBytes), allocationBytes: BigInt(sourceBytes),
  });
  await mkdir(path.dirname(input.image.path), { recursive: true });
  const image = await open(input.image.path, "w");
  try {
    for (const length of [sourceBytes / 2, sourceBytes]) {
      await image.truncate(length);
      const metadata = await image.stat({ bigint: true });
      const estimate = await estimateStageBytes(step, sourceBytes, input.source, 0);
      const remainingAllocation = BigInt(sourceBytes) - metadata.blocks * 512n;
      assert.equal(estimate.logicalBytes, BigInt(sourceBytes) - metadata.size);
      assert.equal(estimate.allocationBytes, remainingAllocation > 0n ? remainingAllocation : 0n);
      const forecast = stageCapacityForecast(estimate.logicalBytes,
        { ...facts().capacity, availableBytes: 0n, reservedBytes: 0n }, 4096n,
        metadata.size, BigInt(sourceBytes), estimate.allocationBytes);
      assert.equal(forecast.fitsOutputCap, true);
      assert.equal(forecast.fitsFreeSpace, estimate.allocationBytes === 0n);
    }
  } finally {
    await image.close();
  }
});
