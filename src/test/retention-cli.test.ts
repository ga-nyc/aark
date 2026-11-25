import assert from "node:assert/strict";
import { access, mkdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { captureCommand } from "../core/command.js";
import { mkdtemp } from "./helpers.js";

const CLI = fileURLToPath(new URL("../cli.js", import.meta.url));

test("retain CLI exposes a separate plan, copy, and verification handoff", async () => {
  const result = await captureCommand(process.execPath, [CLI, "retain", "--help"], {timeoutMs: 10_000, maxCaptureBytes: 16384});
  assert.equal(result.exitCode, 0);
  const help = result.stdout.toString();
  assert.match(help, /plan/);
  assert.match(help, /run/);
  assert.match(help, /verify/);
  assert.doesNotMatch(help, /confirm-delete|format|repair/);
});

test("retain CLI failures do not disclose source names, values, or create an export", async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-retention-cli-test-"));
  t.after(() => rm(root, {recursive: true, force: true}));
  const parent = path.join(root, "destination");
  await mkdir(parent);
  const sensitiveLabel = "synthetic-private-source-label";
  const missingScan = path.join(root, sensitiveLabel);
  const destination = path.join(parent, "bundle");
  const result = await captureCommand(process.execPath, [CLI, "retain", "plan", missingScan, "--destination", destination],
    {timeoutMs: 10_000, maxCaptureBytes: 16384});
  assert.equal(result.exitCode, 1);
  assert.equal(result.stdout.length, 0);
  assert.equal(result.stderr.toString(), "error: retention operation failed; inspect protected local controls\n");
  assert.equal(result.stderr.includes(sensitiveLabel), false);
  assert.equal(result.stderr.includes(root), false);
  await assert.rejects(access(destination));
});

test("retain verify refuses an absent bundle with a fixed public failure", async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-retention-verify-cli-test-"));
  t.after(() => rm(root, {recursive: true, force: true}));
  const result = await captureCommand(process.execPath, [CLI, "retain", "verify", "--bundle", path.join(root, "missing-private-bundle")],
    {timeoutMs: 10_000, maxCaptureBytes: 16384});
  assert.equal(result.exitCode, 1);
  assert.equal(result.stdout.length, 0);
  assert.equal(result.stderr.toString(), "error: retention verification failed; inspect protected local controls\n");
  assert.equal(result.stderr.includes(root), false);
});
