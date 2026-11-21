import path from "node:path";
import { randomUUID } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { captureCommand, type CommandOptions, type CommandResult } from "../core/command.js";
import { atomicWriteJson, readJson } from "../core/fs-safe.js";
import { filesystemEnforcesUnixModes, mountForPath, mountIsNetworkBacked, resolveBlockBacking } from "../core/mounts.js";
import { inspectSourceSafety } from "../recovery/source-safety.js";
import { digest } from "./config.js";
import { assertCaseDirectory, loadCaseState, redactedCaseStatus } from "./store.js";
import type { CaseConfig } from "./types.js";
import { caseRecoverySourcesToInspect } from "./sources.js";
import { acquireCaseLease } from "./lease.js";
export { caseRecoverySourcesToInspect } from "./sources.js";

type Command = (executable: string, args: string[], options: CommandOptions) => Promise<CommandResult>;
interface HostReceipt {version: 1; unit: string; watchUnit: string; user: string; bus: string; cli: string; node: string}
const CTL = "/usr/bin/systemctl";
const RUN = "/usr/bin/systemd-run";
const NOTIFIER = fileURLToPath(new URL("../../scripts/notify-local.py", import.meta.url));
const ok = (result: CommandResult) => result.exitCode === 0 && result.terminationReason === null && !result.stdoutTruncated && !result.stderrTruncated;
const options = {timeoutMs: 10_000, killGraceMs: 250, maxCaptureBytes: 16384};
// The notifier's 15s desktop deadline plus process startup must fit inside
// this outer deadline. The watchdog also needs its lease and status-query budget.
const notificationOptions = {...options, timeoutMs: 45_000};
const watchdogTimeoutSeconds = (notificationOptions.timeoutMs + options.timeoutMs + 15_000) / 1000;

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
  for (const source of await caseRecoverySourcesToInspect(config)) {
    const safety = await inspectSourceSafety(source, config.control);
    if (!safety.safe) throw new Error("case control is not independent of its protected recovery source");
  }
}

async function notify(control: string, receipt: HostReceipt, event: "failed" | "paused" | "complete" | "notification-test", token: string, command: Command): Promise<boolean> {
  const result = await command("/usr/bin/python3", [NOTIFIER, "--state-directory", path.join(control, "notifications"),
    "--allow-unit", receipt.unit, "--session-user", receipt.user, "--bus-address", receipt.bus,
    "--unit", receipt.unit, "--event", event, "--invocation-id", token], notificationOptions);
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
      ...(timer ? ["--on-active=1s", "--on-unit-active=30s", "--timer-property=AccuracySec=1s", "--timer-property=Description=" + description, "--property=Type=oneshot", "--property=TimeoutStartSec=" + watchdogTimeoutSeconds + "s"]
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
  // The watchdog's own lease serializes incident receipts without contending
  // with the independently running supervisor.
  const lease = await acquireCaseLease(control, "watchdog");
  try {
    const result = await watchCaseServiceHeld(control, command, now);
    await lease.assertHeld();
    return result;
  } finally { await lease.release(); }
}

async function watchCaseServiceHeld(control: string, command: Command, now: number): Promise<Record<string, unknown>> {
  const receipt = await readJson<HostReceipt>(path.join(control, "host-private.json"), 16384);
  if (receipt.version !== 1 || receipt.unit !== caseServiceUnit(control) || receipt.watchUnit !== receipt.unit.replace(".service", "-watch")
    || !/^[A-Za-z_][A-Za-z0-9_.-]*[$]?$/u.test(receipt.user) || !/^unix:path=\/run\/user\/[1-9][0-9]*\/bus$/u.test(receipt.bus)) throw new Error("invalid case host registration");
  let active = false;
  try {
    const result = await command(CTL, ["--system", "--no-ask-password", "show", receipt.unit,
      "--property=ActiveState,SubState,MainPID,Result,ExecMainStatus,InvocationID", "--no-pager"], options);
    const fields = new Map<string, string>();
    let duplicate = false;
    for (const line of result.stdout.toString().split("\n")) {
      const separator = line.indexOf("=");
      if (separator < 1) continue;
      const key = line.slice(0, separator);
      if (fields.has(key)) duplicate = true;
      fields.set(key, line.slice(separator + 1));
    }
    const pid = fields.get("MainPID") ?? "";
    active = ok(result) && !duplicate && fields.get("ActiveState") === "active" && fields.get("SubState") === "running"
      && /^[1-9][0-9]*$/u.test(pid) && Number.isSafeInteger(Number(pid)) && fields.get("Result") === "success"
      && fields.get("ExecMainStatus") === "0" && /^[a-f0-9]{32}$/u.test(fields.get("InvocationID") ?? "");
  } catch { /* Observation unavailable still requires notification. */ }
  let status: Record<string, unknown> | undefined;
  let staleAfter = 180_000;
  try {
    const loaded = await loadCaseState(control);
    status = redactedCaseStatus(loaded.config, loaded.state);
    // Respect supported polling intervals and a bounded first agent handshake.
    staleAfter = Math.max(staleAfter, loaded.config.pollMs * 3, loaded.config.agent.timeoutMs + loaded.config.pollMs + 60_000);
  } catch { /* Fixed failure alert below. */ }
  const stale = status === undefined || now - Date.parse(String(status.updatedAt)) > staleAfter;
  const unhealthy = !active || stale || ["degraded", "awaiting-permission", "agent-unavailable", "observation-unavailable"].includes(String(status?.health));
  const complete = status?.complete === true;
  const event = complete ? "complete" : unhealthy ? "failed" : status?.desired === "user-paused" ? "paused" : undefined;
  // Persist the incident before notification. Retries and crash loops reuse it;
  // an observed healthy interval closes it so the next failure alerts again,
  // including failures within the same systemd invocation.
  const incidentPath = path.join(control, "notification-incident.json");
  let incident: {version: 1; unit: string; event: string | null; token: string} | undefined;
  try {
    const value = await readJson<typeof incident>(incidentPath, 4096);
    if (value?.version === 1 && value.unit === receipt.unit && [null, "failed", "paused", "complete"].includes(value.event)
      && /^[a-f0-9-]{36}$/u.test(value.token)) incident = value;
  } catch { /* An unavailable incident receipt must not suppress a failure alert. */ }
  if (incident === undefined || incident.event !== (event ?? null)) {
    incident = {version: 1, unit: receipt.unit, event: event ?? null, token: randomUUID()};
    await atomicWriteJson(incidentPath, incident);
  }
  let delivered: boolean | null = null;
  if (event !== undefined) {
    const key = complete ? digest({case: receipt.unit, event: "complete"})
      : digest({case: receipt.unit, event, incident: incident.token});
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
