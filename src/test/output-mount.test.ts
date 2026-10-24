import assert from "node:assert/strict";
import fs, { access, mkdir, readdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { loadRecoveryConfig } from "../recovery/config.js";
import { buildRecoveryPlan } from "../recovery/plan.js";
import { runRecoveryPlan } from "../recovery/runner.js";
import { resumeSensitiveMaterial, scanSensitiveMaterial } from "../mining/scanner.js";
import { mkdtemp } from "./helpers.js";

test("recovery, fresh mining, and resume reject NTFS3 before making directories or locks", { skip: process.platform !== "linux" }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-output-mount-"));
  const source = path.join(root, "synthetic-source");
  const outputParent = path.join(root, "ntfs-output");
  const resume = path.join(outputParent, "resume");
  await writeFile(source, Buffer.alloc(1024));
  await mkdir(outputParent);
  await mkdir(resume);
  const configuration = path.join(root, "config.json");
  await writeFile(configuration, JSON.stringify({
    version: 1, caseId: "synthetic-mount", source,
    destination: path.join(outputParent, "recovery"), execute: true,
    image: { enabled: false },
    stages: {
      deletedMetadata: false, ntfsUndelete: false, unallocatedStream: false,
      signatureCarving: false, volumeShadows: false, residualMemory: false,
      deletedRegistryCells: false,
    },
  }));
  const config = await loadRecoveryConfig(configuration);
  const originalRead = fs.readFile;
  context.mock.method(fs, "readFile", async (...args: Parameters<typeof fs.readFile>) => {
    if (args[0] === "/proc/self/mounts") {
      return `tmpfs / tmpfs rw 0 0\nsynthetic-device ${outputParent} ntfs3 rw 0 0\n`;
    }
    return await originalRead(...args);
  });
  const unsupported = /ntfs3 output mounts.*ntfs-3g/;
  await assert.rejects(runRecoveryPlan(config, buildRecoveryPlan(config), true), unsupported);
  await assert.rejects(access(config.destination));
  const freshOutput = path.join(outputParent, "mining");
  await assert.rejects(scanSensitiveMaterial({
    inputs: [source], output: freshOutput, provenance: "unknown",
    chunkBytes: 32 * 1024 * 1024, overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 64 * 1024 * 1024, workers: 1,
    minimumFreeGiB: 0, minimumFreePercent: 0,
  }), unsupported);
  await assert.rejects(access(freshOutput));
  await assert.rejects(resumeSensitiveMaterial({ output: resume }), unsupported);
  assert.deepEqual(await readdir(resume), []);
  assert.deepEqual(await readdir(outputParent), ["resume"]);
});
