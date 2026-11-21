import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { chmod, chown, mkdir, readFile, rename, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { acquireCaseLease } from "../case/lease.js";
import { mkdtemp } from "./helpers.js";

const linux = {skip: process.platform !== "linux"};

function ready(child: ChildProcess): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error("synthetic lease worker did not become ready")), 5000);
    const message = (value: unknown) => {
      if (value !== null && typeof value === "object" && "ready" in value && value.ready === true) finish();
    };
    const failed = () => finish(new Error("synthetic lease worker exited before readiness"));
    const finish = (error?: Error) => {
      clearTimeout(timer);
      child.off("message", message);
      child.off("exit", failed);
      child.off("error", failed);
      if (error === undefined) resolve(); else reject(error);
    };
    child.on("message", message);
    child.once("exit", failed);
    child.once("error", failed);
  });
}

test("case lease refuses a second owner while its flock helper has already exited", linux, async () => {
  const control = await mkdtemp(path.join(os.tmpdir(), "aark-case-lease-test-"));
  const first = await acquireCaseLease(control);
  try {
    await first.assertHeld();
    await assert.rejects(acquireCaseLease(control), /already running or lease unavailable/);
    await first.assertHeld();
  } finally { await first.release(); }
});

test("case lease release is idempotent and allows a new owner without removing the lock file", linux, async () => {
  const control = await mkdtemp(path.join(os.tmpdir(), "aark-case-lease-test-"));
  const first = await acquireCaseLease(control);
  await first.release();
  await first.release();
  await assert.rejects(first.assertHeld(), /released/);
  const second = await acquireCaseLease(control);
  try { await second.assertHeld(); }
  finally { await second.release(); }
});

test("SIGKILL of a worker releases its retained flock descriptor without stale-lock deletion", linux, async () => {
  const control = await mkdtemp(path.join(os.tmpdir(), "aark-case-lease-kill-test-"));
  const moduleUrl = new URL("../case/lease.js", import.meta.url).href;
  const script = `const {acquireCaseLease}=await import(${JSON.stringify(moduleUrl)});
    const lease=await acquireCaseLease(${JSON.stringify(control)});
    process.send({ready:true});
    setInterval(()=>lease.assertHeld().catch(()=>process.exit(3)),1000);`;
  const child = spawn(process.execPath, ["--input-type=module", "-e", script], {stdio: ["ignore", "ignore", "ignore", "ipc"], shell: false});
  let exited = false;
  const exit = new Promise<void>(resolve => { child.once("close", () => { exited = true; resolve(); }); });
  try {
    await ready(child);
    await assert.rejects(acquireCaseLease(control), /already running or lease unavailable/);
    assert.equal(child.kill("SIGKILL"), true);
    await exit;
    const next = await acquireCaseLease(control);
    try { await next.assertHeld(); }
    finally { await next.release(); }
  } finally {
    if (!exited) { child.kill("SIGKILL"); await exit; }
  }
});

test("case lease detects lock pathname replacement and release preserves the replacement", linux, async () => {
  const control = await mkdtemp(path.join(os.tmpdir(), "aark-case-lease-replace-test-"));
  const lease = await acquireCaseLease(control);
  const filename = path.join(control, ".case-service.lock");
  try {
    await rename(filename, path.join(control, "displaced-synthetic-lock"));
    await writeFile(filename, "synthetic replacement", {mode: 0o600, flag: "wx"});
    await assert.rejects(lease.assertHeld(), /binding changed/);
  } finally { await lease.release(); }
  assert.equal(await readFile(filename, "utf8"), "synthetic replacement");
});

test("case lease rejects a replacement control directory even when the held lock is moved back", linux, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-case-directory-replace-test-"));
  const control = path.join(root, "control");
  const displaced = path.join(root, "displaced");
  await mkdir(control, {mode: 0o700});
  const lease = await acquireCaseLease(control);
  try {
    await rename(control, displaced);
    await mkdir(control, {mode: 0o700});
    await rename(path.join(displaced, ".case-service.lock"), path.join(control, ".case-service.lock"));
    await assert.rejects(lease.assertHeld(), /control directory binding changed/);
  } finally { await lease.release(); }
});

test("case lease rejects a newly introduced ancestor alias despite unchanged control and lock identities", linux, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-case-directory-alias-test-"));
  const parent = path.join(root, "parent");
  const displaced = path.join(root, "displaced");
  const control = path.join(parent, "control");
  await mkdir(control, {mode: 0o700, recursive: true});
  const lease = await acquireCaseLease(control);
  try {
    await rename(parent, displaced);
    await symlink(displaced, parent, "dir");
    await assert.rejects(lease.assertHeld(), /symbolic-link/);
  } finally { await lease.release(); }
});

test("case lease detects control directory permissions becoming public", linux, async () => {
  const control = await mkdtemp(path.join(os.tmpdir(), "aark-case-directory-permissions-test-"));
  const lease = await acquireCaseLease(control);
  try {
    await chmod(control, 0o755);
    await assert.rejects(lease.assertHeld(), /control directory binding changed/);
    await chmod(control, 0o700);
    await lease.assertHeld();
  } finally { await chmod(control, 0o700); await lease.release(); }
});

test("case lease detects control directory ownership changes", {skip: process.platform !== "linux" || process.getuid?.() !== 0}, async () => {
  const control = await mkdtemp(path.join(os.tmpdir(), "aark-case-directory-owner-test-"));
  const before = await stat(control);
  const lease = await acquireCaseLease(control);
  try {
    await chown(control, before.uid + 1, before.gid);
    await assert.rejects(lease.assertHeld(), /control directory binding changed/);
  } finally { await chown(control, before.uid, before.gid); await lease.release(); }
});
