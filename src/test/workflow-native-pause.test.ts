import assert from "node:assert/strict";
import fs, { existsSync } from "node:fs";
import { readFile, rm, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { PROGRESS_FILENAME } from "../core/progress.js";
import { loadScanState } from "../mining/resume.js";
import { runWorkflow, workflowStatus } from "../workflow/runner.js";
import { mkdtemp } from "./helpers.js";

for (const phase of ["recovery", "mining"] as const) {
  test(`a caller pause takes precedence over a native ${phase} quota checkpoint`, {
    skip: phase === "recovery" && process.platform !== "linux",
  }, async context => {
    const root = await mkdtemp(path.join(os.tmpdir(), "aark-native-pause-"));
    context.after(() => rm(root, {recursive: true, force: true}));
    const output = path.join(root, "workflow");
    const configFile = path.join(root, "workflow.json");
    const destination = phase === "recovery" ? path.join(root, "image-case") : path.join(output, "mining", "scan-000001");
    const source = path.join(root, "source.img");
    await writeFile(source, "synthetic input");
    const storage = {minFreeGiB: 0, minFreePercent: 1};
    let input = source;
    let recoveryConfig: string | undefined;
    if (phase === "recovery") {
      input = path.join(destination, "evidence", "source.img");
      recoveryConfig = path.join(root, "recovery.json");
      await writeFile(recoveryConfig, JSON.stringify({version: 1, execute: true, caseId: "native-pause", source, destination,
        image: {enabled: true, path: input, mapfile: path.join(destination, "evidence", "source.map")}, storage,
        stages: {deletedMetadata: false, unallocatedStream: false, signatureCarving: false}}));
    }
    await writeFile(configFile, JSON.stringify({version: 1, execute: true, output, recoveryConfig,
      scans: [{inputs: [input], provenance: "allocated-reference"}], mining: {workers: 1, storage},
      finalizationStorage: {minFreeGiB: 0, minFreePercent: 0}}));

    const caller = new AbortController();
    const statfs = fs.promises.statfs;
    const nativeProgress = path.join(destination, PROGRESS_FILENAME);
    const nativeManifest = path.join(destination, "scan-files-sensitive.ndjson");
    fs.promises.statfs = (async (...args: Parameters<typeof statfs>) => {
      const stat = await statfs(...args);
      if (args[0] !== destination || caller.signal.aborted) return stat;
      // Inject the race after the native stage starts, before its quota check returns.
      if (phase === "recovery") {
        if (!existsSync(nativeProgress) || JSON.parse(await readFile(nativeProgress, "utf8")).currentStage !== "image-fast-pass") return stat;
      } else if (!existsSync(nativeManifest)) return stat;
      caller.abort();
      return {...stat, bavail: typeof stat.bavail === "bigint" ? 0n : 0};
    }) as typeof statfs;
    syncBuiltinESMExports();
    try {
      const result = await runWorkflow(configFile, {execute: true, signal: caller.signal});
      const native = phase === "recovery" ? JSON.parse(await readFile(path.join(destination, "manifest-redacted.json"), "utf8"))
        : await loadScanState(destination);
      assert.equal(native.status, "paused");
      assert.equal(phase === "recovery" ? native.storageStop.reason : native.pauseReason, "free-space-reserve");
      assert.equal(result.status, "paused");
      assert.equal(result.phase, phase);
      assert.equal(result.pauseReason, "signal");
      assert.equal((await workflowStatus(output)).nextAction, "resume-when-ready");
    } finally {
      fs.promises.statfs = statfs;
      syncBuiltinESMExports();
    }
  });
}
