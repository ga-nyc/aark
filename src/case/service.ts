import path from "node:path";
import { lstat, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { captureCommand, type CommandOptions, type CommandResult } from "../core/command.js";
import { atomicWriteJson, readJson } from "../core/fs-safe.js";
import { filesystemEnforcesUnixModes, mountForPath, mountIsNetworkBacked, resolveBlockBacking } from "../core/mounts.js";
import { inspectSourceSafety } from "../recovery/source-safety.js";
import { digest } from "./config.js";
import { assertCaseDirectory, loadCaseState, redactedCaseStatus } from "./store.js";
import type { CaseConfig } from "./types.js";

type Command = (executable: string, args: string[], options: CommandOptions) => Promise<CommandResult>;
interface HostReceipt {version: 1; unit: string; watchUnit: string; user: string; bus: string; cli: string; node: string}
const CTL = "/usr/bin/systemctl";
const RUN = "/usr/bin/systemd-run";
const NOTIFIER = fileURLToPath(new URL("../../scripts/notify-local.py", import.meta.url));
const ok = (result: CommandResult) => result.exitCode === 0 && result.terminationReason === null && !result.stdoutTruncated && !result.stderrTruncated;
const options = {timeoutMs: 10_000, killGraceMs: 250, maxCaptureBytes: 16384};

async function trustedHostFile(filename: string): Promise<void> {
  if (await realpath(filename) !== filename) throw new Error("case hosting requires canonical installed files");
  const file = await lstat(filename);
  if (!file.isFile() || file.nlink !== 1 || file.uid !== 0 || (file.mode & 0o022) !== 0) throw new Error("case hosting requires root-owned protected installed files");
  let directory = path.dirname(filename);
  while (true) {
    const metadata = await lstat(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid !== 0 || (metadata.mode & 0o022) !== 0) throw new Error("case installation has an untrusted parent directory");
    if (directory === path.dirname(directory)) break;
    directory = path.dirname(directory);
  }
}

export function caseServiceUnit(control: string): string { return `aark-case-${digest(control).slice(0, 32)}.service`; }

/** Production gate is intentionally outside the injected controller test API. */
export async function assertProductionCaseStorage(config: CaseConfig): Promise<void> {
  if (process.platform !== "linux" || process.getuid?.() !== 0) throw new Error("autonomous cases require privileged Linux hosting");
  const mounted = await mountForPath(config.control);
  if (mounted === undefined || !mounted.source.startsWith("/dev/") || mounted.options.includes("ro")
    || !filesystemEnforcesUnixModes(mounted) || ["tmpfs", "ramfs", "overlay", "squashfs"].includes(mounted.filesystem)
    || await mountIsNetworkBacked(mounted)) throw new Error("case control requires healthy persistent local storage with private Unix permissions");
  const backing = await resolveBlockBacking(mounted.source.replace(/\[[^\]]*\]$/u, ""));
  if (backing.devices.length === 0 || backing.networkBacked) throw new Error("case control storage backing is unverified");
  for (const job of config.jobs) for (const attempt of job.attempts) {
    if (attempt.workflow.recovery === undefined) continue;
    const safety = await inspectSourceSafety(attempt.workflow.recovery.source, config.control);
    if (!safety.safe) throw new Error("case control is not independent of its protected recovery source");
  }
}

async function notify(control: string, receipt: HostReceipt, event: "failed" | "paused" | "complete" | "notification-test", token: string, command: Command): Promise<boolean> {
  const result = await command("/usr/bin/python3", [NOTIFIER, "--state-directory", path.join(control, "notifications"),
    "--allow-unit", receipt.unit, "--session-user", receipt.user, "--bus-address", receipt.bus,
    "--unit", receipt.unit, "--event", event, "--invocation-id", token], options);
  return ok(result);
}

export async function startCaseService(control: string, cli: string, command: Command = captureCommand): Promise<Record<string, unknown>> {
  const {config, state} = await loadCaseState(control);
  await assertProductionCaseStorage(config);
  for (const filename of [control, cli, process.execPath]) {
    if (!path.isAbsolute(filename) || /[\x00-\x1f\x7f%]/u.test(filename)) throw new Error("case hosting requires supported absolute paths");
  }
  for (const filename of [cli, process.execPath, NOTIFIER]) await trustedHostFile(filename);
  const version = await command(RUN, ["--version"], options);
  if (!ok(version) || Number(/^systemd (\d+)/u.exec(version.stdout.toString())?.[1] ?? 0) < 254) throw new Error("case hosting requires systemd 254 or newer");
  const account = await command("/usr/bin/id", ["-u", config.agent.user], options);
  if (!ok(account) || !/^[1-9][0-9]*\n?$/u.test(account.stdout.toString())) throw new Error("case desktop session user is unavailable");
  const unit = caseServiceUnit(control);
  const watchUnit = unit.replace(".service", "-watch");
  const receipt: HostReceipt = {version: 1, unit, watchUnit, user: config.agent.user,
    bus: `unix:path=/run/user/${account.stdout.toString().trim()}/bus`, cli, node: process.execPath};
  const receiptPath = path.join(control, "host-private.json");
  try {
    const existing = await readJson<HostReceipt>(receiptPath, 16384);
    if (digest(existing) !== digest(receipt)) throw new Error("case host registration changed");
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  await atomicWriteJson(receiptPath, receipt);
  const channel = await command("/usr/sbin/runuser", ["-u", receipt.user, "--", "/usr/bin/env", "DBUS_SESSION_BUS_ADDRESS=" + receipt.bus,
    "/usr/bin/gdbus", "call", "--session", "--dest", "org.freedesktop.Notifications", "--object-path", "/org/freedesktop/Notifications",
    "--method", "org.freedesktop.Notifications.GetCapabilities"], options);
  if (!ok(channel)) throw new Error("case notification channel is unavailable; no engines started");
  if (!await notify(control, receipt, "notification-test", state.caseId, command)) throw new Error("case notification preflight failed; no engines started");
  const launch = async (name: string, args: string[], timer: boolean): Promise<void> => {
    const description = `AARK case ${timer ? "watch" : "worker"} ${digest(receipt)}`;
    const observedUnit = name + (timer ? ".timer" : "");
    const query = await command(CTL, ["--system", "--no-ask-password", "show", observedUnit, "--property=LoadState,ActiveState,Description,Transient", "--no-pager"], options);
    if (ok(query) && /^LoadState=loaded$/mu.test(query.stdout.toString())) {
      if (!query.stdout.toString().split("\n").includes("Description=" + description) || !/^Transient=yes$/mu.test(query.stdout.toString())) throw new Error("case service identity differs from its registration");
      if (!/^ActiveState=(active|activating)$/mu.test(query.stdout.toString())) {
        const started = await command(CTL, ["--system", "--no-ask-password", "start", observedUnit], options);
        if (!ok(started)) throw new Error("case service could not be reactivated");
      }
      return;
    }
    if (query.terminationReason !== null || query.stdoutTruncated || query.stderrTruncated || ![0, 4].includes(query.exitCode)
      || !/^LoadState=not-found$/mu.test(query.stdout.toString())) throw new Error("case service observation unavailable");
    const result = await command(RUN, ["--system", "--no-ask-password", "--quiet", "--expand-environment=no", "--unit=" + name,
      "--description=" + description,
      ...(timer ? ["--on-active=1s", "--on-unit-active=30s", "--timer-property=AccuracySec=1s", "--timer-property=Description=" + description, "--property=Type=oneshot", "--property=TimeoutStartSec=20s"]
        : ["--property=Type=exec", "--property=Restart=on-failure", "--property=RestartSec=15s", "--property=StartLimitIntervalSec=0"]),
      "--property=UMask=0077", "--property=KillMode=control-group", "--property=StandardOutput=null", "--property=StandardError=journal",
      process.execPath, cli, "case", ...args, "--control", control, "--execute"], options);
    if (!ok(result)) throw new Error("case service could not be launched");
  };
  // The watchdog lives in a different service/cgroup, and survives worker death.
  await launch(watchUnit, ["watch"], true);
  await launch(unit, ["serve", "--autonomous"], false);
  return {version: 1, started: true, worker: unit, watchdog: watchUnit + ".timer", independentEngines: true};
}

export async function watchCaseService(control: string, command: Command = captureCommand, now = Date.now()): Promise<Record<string, unknown>> {
  await assertCaseDirectory(control);
  const receipt = await readJson<HostReceipt>(path.join(control, "host-private.json"), 16384);
  if (receipt.version !== 1 || receipt.unit !== caseServiceUnit(control) || receipt.watchUnit !== receipt.unit.replace(".service", "-watch")
    || !/^[A-Za-z_][A-Za-z0-9_.-]*[$]?$/u.test(receipt.user) || !/^unix:path=\/run\/user\/[1-9][0-9]*\/bus$/u.test(receipt.bus)) throw new Error("invalid case host registration");
  let active = false;
  try {
    const result = await command(CTL, ["--system", "--no-ask-password", "show", receipt.unit, "--property=ActiveState,InvocationID", "--no-pager"], options);
    active = /^ActiveState=(active|activating|reloading)$/mu.test(result.stdout.toString()) && ok(result);
  } catch { /* Observation unavailable still requires notification. */ }
  let status: Record<string, unknown> | undefined;
  try { const loaded = await loadCaseState(control); status = redactedCaseStatus(loaded.config, loaded.state); } catch { /* Fixed failure alert below. */ }
  const stale = status === undefined || now - Date.parse(String(status.updatedAt)) > 180_000;
  const unhealthy = !active || stale || ["degraded", "awaiting-permission", "agent-unavailable", "observation-unavailable"].includes(String(status?.health));
  const complete = status?.complete === true;
  const event = complete ? "complete" : unhealthy ? "failed" : status?.desired === "user-paused" ? "paused" : undefined;
  let delivered: boolean | null = null;
  if (event !== undefined) {
    const jobs = Array.isArray(status?.jobs) ? status.jobs.map((job: Record<string, unknown>) => ({id: job.id, status: job.status,
      attemptsUsed: job.attemptsUsed, verified: job.verified, failureCode: job.failureCode, pauseReason: job.pauseReason})) : [];
    const key = complete ? digest({case: receipt.unit, event: "complete"})
      : digest({case: receipt.unit, event, active, stale, health: status?.health ?? "state-unavailable", jobs});
    try { delivered = await notify(control, receipt, event, key, command); } catch { delivered = false; }
    await atomicWriteJson(path.join(control, "notification-status-redacted.json"), {version: 1, event, deliveryAccepted: delivered,
      userAcknowledged: false, checkedAt: new Date(now).toISOString()});
  }
  return {version: 1, workerObservedActive: active, heartbeatStale: stale, notificationRequired: event !== undefined, deliveryAccepted: delivered, userAcknowledged: false};
}

export async function caseNotificationStatus(control: string): Promise<Record<string, unknown>> {
  await assertCaseDirectory(control);
  try {
    const value = await readJson<Record<string, unknown>>(path.join(control, "notification-status-redacted.json"), 4096);
    if (value.version !== 1 || !["failed", "paused", "complete"].includes(String(value.event)) || typeof value.deliveryAccepted !== "boolean"
      || value.userAcknowledged !== false || typeof value.checkedAt !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u.test(value.checkedAt)
      || !Number.isFinite(Date.parse(value.checkedAt))) throw new Error();
    return {recorded: true, event: value.event, deliveryAccepted: value.deliveryAccepted, userAcknowledged: false, checkedAt: value.checkedAt};
  } catch (error) {
    return {recorded: false, status: (error as NodeJS.ErrnoException).code === "ENOENT" ? "not-recorded" : "unavailable", userAcknowledged: false};
  }
}
