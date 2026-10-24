import assert from "node:assert/strict";
import { access, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { captureCommand } from "../core/command.js";
import { PROGRESS_FILENAME } from "../core/progress.js";
import { mkdtemp } from "./helpers.js";

const cli = path.join(process.cwd(), "dist", "cli.js");

test("assessment CLI reports a known cap shortfall without starting recovery or creating a case", { skip: process.platform !== "linux" }, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-assessment-cli-"));
  const source = path.join(root, "source.img");
  const destination = path.join(root, "case");
  const config = path.join(root, "case.json");
  await writeFile(source, Buffer.alloc(2 * 1024 * 1024));
  await writeFile(config, JSON.stringify({ version: 1, caseId: "synthetic-cli", source, destination,
    requireReadOnlySource: true, execute: false, image: { enabled: true },
    storage: { minFreeGiB: 0, minFreePercent: 0, maxOutputGiB: 0.001 },
    stages: { deletedMetadata: false, unallocatedStream: false, signatureCarving: false },
  }));
  const assessment = await captureCommand(process.execPath, [cli, "recover", "assess", "--config", config]);
  assert.equal(assessment.exitCode, 2);
  const result = JSON.parse(assessment.stdout.toString("utf8")) as Record<string, unknown>;
  assert.equal(result.status, "insufficient-for-known-outputs");
  assert.equal(result.knownMinimumExceedsOutputCap, true);
  assert.equal(assessment.stdout.includes(Buffer.from(root)), false);
  const plan = await captureCommand(process.execPath, [cli, "recover", "plan", "--config", config, "--assess-storage"]);
  assert.equal(plan.exitCode, 0);
  assert.equal((JSON.parse(plan.stdout.toString("utf8")) as { storageAssessment: Record<string, unknown> }).storageAssessment.knownMinimumFits, false);
  await assert.rejects(access(destination));
});

test("status CLIs omit injected fields from a local aggregate snapshot", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-status-cli-"));
  for (const layer of ["recovery", "mining"] as const) {
    await writeFile(path.join(root, PROGRESS_FILENAME), JSON.stringify({
      version: 1, tool: "aark", layer, status: "complete", updatedAt: new Date().toISOString(), sourcePathsRedacted: true,
      availableBytes: "1024", sourcePath: "/synthetic/private-source", error: "synthetic-private-value",
    }));
    const result = await captureCommand(process.execPath, [cli, layer === "mining" ? "mine" : "recover", "status",
      layer === "mining" ? "--output" : "--case", root]);
    assert.equal(result.exitCode, 0);
    assert.equal(JSON.parse(result.stdout.toString("utf8")).status, "complete");
    assert.equal(result.stdout.toString("utf8").includes("private"), false);
  }
});
