import assert from "node:assert/strict";
import { unlinkSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { diagnosticErrorCode, diagnosticOperation, scanDiagnostics } from "../mining/diagnostics.js";
import { loadCompletedInventory, loadScanState } from "../mining/resume.js";
import { resumeSensitiveMaterial, scanSensitiveMaterial } from "../mining/scanner.js";
import { mkdtemp } from "./helpers.js";

test("diagnostics classify errors without echoing evidence or arbitrary fields", () => {
  assert.equal(diagnosticErrorCode("ENOENT: no such file /private/synthetic"), "system-enoent");
  assert.equal(diagnosticErrorCode("EIO: i/o error, read"), "system-eio");
  assert.equal(diagnosticErrorCode("scan input changed from its frozen file manifest snapshot"), "input-snapshot-changed");
  assert.equal(diagnosticErrorCode("detector candidate and structural-validation limit reached; the bounded window may contain additional matches"), "detector-resource-limit");
  assert.equal(diagnosticErrorCode("private synthetic exception value"), "unclassified-scan-error");
  assert.equal(diagnosticOperation("detector:wallet-secrets"), "detector:wallet-secrets");
  assert.equal(diagnosticOperation("detector:private synthetic value"), "unclassified-operation");
});

test("terminal error diagnosis is redacted, read-only, and never authorizes cleanup or resume", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-diagnostics-test-"));
  const input = path.join(root, "synthetic-input.bin");
  const output = path.join(root, "mined");
  await writeFile(input, Buffer.alloc(1024 * 1024, 0x41));
  let removed = false;
  const result = await scanSensitiveMaterial({inputs: [input], output, provenance: "unknown", workers: 1,
    chunkBytes: 17 * 1024 ** 2, overlapBytes: 17 * 1024 ** 2, wholeFileBytes: 2 * 1024 ** 2,
    minimumFreeGiB: 0, minimumFreePercent: 0, progress: () => {
      if (!removed) { removed = true; unlinkSync(input); }
    }});
  assert.equal(result.status, "complete-with-errors");
  const before = await readFile(path.join(output, "scan-state-sensitive.json"));
  const report = await scanDiagnostics(output);
  assert.equal(report.status, "complete-with-errors");
  assert.equal(report.filesUnsuccessful, 1);
  // An explicit root can report both a root-identity and a later read error.
  assert.ok(Number(report.scanErrors) >= 1);
  assert.equal(report.cleanupAuthorized, false);
  assert.equal(report.resumable, false);
  assert.equal(JSON.stringify(report).includes(root), false);
  assert.equal(JSON.stringify(report).includes("synthetic-input"), false);
  assert.equal(JSON.stringify(report).includes("system-enoent"), true);
  assert.deepEqual(await readFile(path.join(output, "scan-state-sensitive.json")), before);
  const state = await loadScanState(output);
  await assert.rejects(loadCompletedInventory(output, state.inventory));
  await assert.rejects(resumeSensitiveMaterial({output}));
  const edited = JSON.parse(before.toString("utf8"));
  edited.progress.filesScanned = 1;
  await writeFile(path.join(output, "scan-state-sensitive.json"), JSON.stringify(edited));
  await assert.rejects(scanDiagnostics(output), /checkpoint and sealed inventory disagree/);
  await writeFile(path.join(output, "scan-state-sensitive.json"), before);
  await writeFile(path.join(output, "inventory-sensitive.json"), "{}\n");
  await assert.rejects(scanDiagnostics(output), /does not match/);
});

test("clean completed scans have an empty diagnostic summary", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-clean-diagnostics-test-"));
  const input = path.join(root, "input");
  await mkdir(input);
  const output = path.join(root, "mined");
  await scanSensitiveMaterial({inputs: [input], output, provenance: "unknown", workers: 1,
    chunkBytes: 17 * 1024 ** 2, overlapBytes: 17 * 1024 ** 2, wholeFileBytes: 2 * 1024 ** 2,
    minimumFreeGiB: 0, minimumFreePercent: 0});
  const report = await scanDiagnostics(output);
  assert.equal(report.status, "complete");
  assert.equal(report.scanErrors, 0);
  assert.deepEqual(report.errors, []);
  const stateFile = path.join(output, "scan-state-sensitive.json");
  const state = JSON.parse(await readFile(stateFile, "utf8"));
  state.runId = "11111111-1111-4111-8111-111111111111";
  await writeFile(stateFile, JSON.stringify(state));
  await assert.rejects(scanDiagnostics(output), /checkpoint and sealed inventory disagree/);
});
