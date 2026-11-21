import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { captureCommand, type CommandOptions, type CommandResult } from "../core/command.js";
import { atomicWriteJson, ensurePrivateDirectory, readJson, stableHandleStat } from "../core/fs-safe.js";
import { FAILURE_CODES } from "../workflow/failure.js";
import { CaseSourceIdentityError } from "./sources.js";
import { isSupportedCasePath } from "./config.js";
import { EngineLaunchRefusedError } from "./launch-error.js";
import type { CaseSourceBinding, CaseSourceBindings, CompletionProof, EngineHost, EngineIdentity, EngineObservation, PreparedAttempt } from "./types.js";

type Command = (executable: string, args: string[], options: CommandOptions) => Promise<CommandResult>;
export interface SystemdEngineHostOptions {
  cliPath: string;
  controlRoot: string;
  probeTimeoutMs?: number;
  verificationTimeoutMs?: number;
  sourceBindings?: CaseSourceBindings;
  /** Test seam; production always uses captureCommand. */
  command?: Command;
}
interface Receipt { version: 1; binding: string; invocationId?: string }
type Properties = Record<string, string>;
const SYSTEMCTL = "/usr/bin/systemctl";
const SYSTEMD_RUN = "/usr/bin/systemd-run";
const PROBE = fileURLToPath(new URL("./verify.js", import.meta.url));
const CAPACITY = fileURLToPath(new URL("./capacity.js", import.meta.url));
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const successful = (result: CommandResult) => result.exitCode === 0 && result.terminationReason === null && !result.stdoutTruncated && !result.stderrTruncated;

export function engineUnitName(token: string): string {
  if (token.length < 1 || token.length > 4096) throw new Error("invalid case engine token");
  return `aark-case-engine-${hash(token).slice(0, 40)}.service`;
}

/** systemd owns engines; deadlines apply exclusively to disposable launch/probe helpers. */
export class SystemdEngineHost implements EngineHost {
  private readonly command: Command;
  private readonly timeout: number;
  private readonly verificationTimeout: number;
  private readonly directory: string;
  private readonly pending = new Map<string, Promise<EngineObservation>>();
  private readonly completed = new Map<string, EngineIdentity>();
  private readonly helpers = new Map<string, Promise<CommandResult>>();

  public constructor(private readonly options: SystemdEngineHostOptions) {
    for (const value of [options.cliPath, options.controlRoot, process.execPath]) {
      if (!isSupportedCasePath(value)) throw new Error("case engine paths must be absolute supported local paths");
    }
    this.timeout = options.probeTimeoutMs ?? 10_000;
    this.verificationTimeout = options.verificationTimeoutMs ?? 30 * 60_000;
    for (const value of [this.timeout, this.verificationTimeout]) {
      if (!Number.isSafeInteger(value) || value < 1) throw new Error("invalid case helper deadline");
    }
    this.command = options.command ?? captureCommand;
    this.directory = path.join(options.controlRoot, "engines");
  }

  private async capture(executable: string, args: string[], timeoutMs = this.timeout): Promise<CommandResult> {
    const key = JSON.stringify([executable, args]);
    let helper = this.helpers.get(key);
    if (helper === undefined) {
      helper = Promise.resolve().then(() => this.command(executable, args, {timeoutMs, killGraceMs: 250, maxCaptureBytes: 64 * 1024}))
        .finally(() => this.helpers.delete(key));
      this.helpers.set(key, helper);
    }
    // An uninterruptible helper can outlive SIGKILL. Keep its slot until it really
    // exits, while returning observation-unavailable instead of piling up probes.
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([helper, new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("case helper observation deadline exceeded")), timeoutMs + 1000);
      })]);
    } finally { if (timer !== undefined) clearTimeout(timer); }
  }

  public async preflight(): Promise<void> {
    if (process.platform !== "linux" || process.getuid?.() !== 0) throw new Error("case engines require privileged local Linux systemd hosting");
    try {
      const run = await this.capture(SYSTEMD_RUN, ["--version"]);
      const ctl = await this.capture(SYSTEMCTL, ["--version"]);
      const node = await this.capture(process.execPath, ["--version"]);
      const cli = await this.capture(process.execPath, [this.options.cliPath, "--version"]);
      const manager = await this.capture(SYSTEMCTL, ["--system", "--no-ask-password", "show", "--property=Version", "--value"]);
      const nodeVersion = /^v(\d+)\.(\d+)\./u.exec(node.stdout.toString());
      const versions = [run, ctl].map(result => /^systemd (\d+)/u.exec(result.stdout.toString())?.[1]);
      if (![run, ctl, node, cli, manager].every(successful) || versions.some(value => value === undefined || Number(value) < 254)
        || nodeVersion === null || Number(nodeVersion[1]) < 22 || (Number(nodeVersion[1]) === 22 && Number(nodeVersion[2]) < 12)
        || !/^\d+/u.test(manager.stdout.toString()) || !/^\d+\.\d+\.\d+/u.test(cli.stdout.toString())) throw new Error();
      await ensurePrivateDirectory(this.directory);
    } catch { throw new Error("case engine host preflight failed"); }
  }

  private async show(unit: string): Promise<Properties | undefined> {
    const result = await this.capture(SYSTEMCTL, ["--system", "--no-ask-password", "show", unit, "--no-pager",
      "--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MainPID,InvocationID,Description,Transient,Type,RemainAfterExit,Restart,TasksCurrent,TasksAccounting,ControlGroup"]);
    if (result.terminationReason !== null || result.stdoutTruncated || result.stderrTruncated) throw new Error("case engine observation unavailable");
    const values: Properties = {};
    for (const line of result.stdout.toString().trim().split("\n")) {
      const separator = line.indexOf("=");
      if (separator > 0) {
        const key = line.slice(0, separator);
        if (Object.hasOwn(values, key)) throw new Error("case engine observation unavailable");
        values[key] = line.slice(separator + 1);
      }
    }
    if (values.LoadState === "not-found") {
      if (![0, 4].includes(result.exitCode)) throw new Error("case engine observation unavailable");
      return undefined;
    }
    if (!successful(result) || values.LoadState !== "loaded") throw new Error("case engine observation unavailable");
    return values;
  }

  private binding(attempt: PreparedAttempt, mode: "run" | "resume"): string {
    if (!/^[a-f0-9]{64}$/u.test(attempt.configHash) || hash(JSON.stringify(attempt.workflow)) !== attempt.configHash
      || !isSupportedCasePath(attempt.configFile) || !isSupportedCasePath(attempt.workflow.output)) throw new EngineLaunchRefusedError();
    return hash(JSON.stringify([attempt.configFile, attempt.configHash, attempt.workflow.output, mode, process.execPath, this.options.cliPath, this.sourcePolicy(attempt)]));
  }

  private async receipt(unit: string): Promise<Receipt | undefined> {
    try { return await readJson<Receipt>(path.join(this.directory, `${unit}.json`), 4096); }
    catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined;
      throw new Error("case engine receipt unavailable");
    }
  }

  private checkedBinding(attempt: PreparedAttempt, mode: "run" | "resume", receipt: Receipt | undefined): string {
    try { return this.binding(attempt, mode); }
    catch (error) {
      // A previous intent still requires reconciliation, even if the caller's
      // immutable arguments have since become invalid.
      if (error instanceof EngineLaunchRefusedError && receipt !== undefined) throw new Error("invalid case engine binding");
      throw error;
    }
  }

  private sourcePolicy(attempt: PreparedAttempt): CaseSourceBinding[] {
    if (attempt.workflow.recovery === undefined) return [];
    const bindings = this.options.sourceBindings?.[attempt.configHash];
    if (bindings === undefined) throw new Error("case source authorization is missing");
    return bindings;
  }

  private assertUnit(values: Properties, binding: string): string {
    if (values.Description !== `AARK case engine ${binding}` || values.Transient !== "yes" || values.Type !== "exec"
      || values.RemainAfterExit !== "yes" || values.Restart !== "no" || values.TasksAccounting !== "yes" || !/^[a-f0-9]{32}$/u.test(values.InvocationID ?? "")) {
      throw new Error("case engine identity changed");
    }
    return values.InvocationID!;
  }

  public async reattach(attempt: PreparedAttempt, token: string, mode: "run" | "resume"): Promise<EngineIdentity | undefined> {
    const unit = engineUnitName(token);
    const receipt = await this.receipt(unit);
    const binding = this.checkedBinding(attempt, mode, receipt);
    const values = await this.show(unit);
    if (values === undefined) return undefined;
    const receiptPath = path.join(this.directory, `${unit}.json`);
    if (receipt === undefined) throw new Error("case engine receipt unavailable");
    if (receipt.version !== 1 || receipt.binding !== binding
      || (receipt.invocationId !== undefined && !/^[a-f0-9]{32}$/u.test(receipt.invocationId))) throw new Error("case engine identity changed");
    const invocationId = this.assertUnit(values, binding);
    if (receipt.invocationId !== undefined && receipt.invocationId !== invocationId) throw new Error("case engine identity changed");
    // An interrupted launch may have persisted its intent before observing identity.
    if (receipt.invocationId === undefined) await atomicWriteJson(receiptPath, {version: 1, binding, invocationId});
    return {unit, invocationId};
  }

  public async launch(attempt: PreparedAttempt, token: string, mode: "run" | "resume"): Promise<EngineIdentity> {
    const unit = engineUnitName(token);
    const receiptPath = path.join(this.directory, `${unit}.json`);
    const receipt = await this.receipt(unit);
    const binding = this.checkedBinding(attempt, mode, receipt);
    if (receipt !== undefined && (receipt.version !== 1 || receipt.binding !== binding
      || (receipt.invocationId !== undefined && !/^[a-f0-9]{32}$/u.test(receipt.invocationId)))) throw new Error("case engine identity changed");
    let values = await this.show(unit);
    if (values === undefined) {
      // A previously observed invocation must never be replaced under its old token.
      if (receipt?.invocationId !== undefined) throw new Error("case engine invocation disappeared");
      let submitted = false;
      try {
      await ensurePrivateDirectory(this.directory);
      const config = await this.capture(process.execPath, [PROBE, "binding", attempt.configFile, attempt.configHash, JSON.stringify(this.sourcePolicy(attempt))]);
      if (config.exitCode === 2 && config.terminationReason === null && !config.stdoutTruncated && !config.stderrTruncated
        && config.stdout.toString().trim() === '{"valid":false,"reason":"source-identity-changed"}') throw new CaseSourceIdentityError();
      if (!successful(config) || config.stdout.toString().trim() !== '{"valid":true}') throw new Error("case engine configuration binding changed");
      await atomicWriteJson(receiptPath, {version: 1, binding});
      const logs = ["stdout", "stderr"].map(kind => path.join(this.directory, `${unit}.${kind}.log`));
      for (const filename of logs) {
        const handle = await open(filename, constants.O_CREAT | constants.O_APPEND | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
        try {
          const metadata = await stableHandleStat(handle);
          if (!metadata.raw.isFile() || metadata.raw.nlink !== 1n || (metadata.raw.mode & 0o077n) !== 0n) throw new Error("case engine log is not private");
        } finally { await handle.close(); }
      }
      const args = ["--system", "--no-ask-password", "--quiet", `--unit=${unit}`, `--description=AARK case engine ${binding}`,
        "--service-type=exec", "--remain-after-exit", "--expand-environment=no", "--property=Restart=no", "--property=UMask=0077",
        "--property=SuccessExitStatus=75", "--property=TasksAccounting=yes", `--property=StandardOutput=append:${logs[0]}`, `--property=StandardError=append:${logs[1]}`,
        "--", process.execPath, this.options.cliPath, "workflow", mode,
        ...(mode === "run" ? ["--config", attempt.configFile] : ["--output", attempt.workflow.output]), "--expected-config-hash", attempt.configHash,
        ...(attempt.workflow.recovery === undefined ? [] : ["--expected-source-bindings", JSON.stringify(this.sourcePolicy(attempt))]), "--execute"];
      // A client timeout can leave a successfully started service. Always reconcile it.
      submitted = true;
      try { await this.capture(SYSTEMD_RUN, args); } catch { /* Only the launch client may have failed. */ }
      values = await this.show(unit);
      if (values === undefined) throw new Error("case engine launch was not observed");
      } catch (error) {
        if (error instanceof CaseSourceIdentityError) throw error;
        // An absent unit and no prior receipt prove this is a pre-submit
        // refusal. Once submission starts, even a timeout remains unknown.
        if (!submitted && receipt === undefined) throw new EngineLaunchRefusedError();
        throw error;
      }
    }
    const invocationId = this.assertUnit(values, binding);
    if (receipt?.invocationId !== undefined && receipt.invocationId !== invocationId) throw new Error("case engine identity changed");
    await atomicWriteJson(receiptPath, {version: 1, binding, invocationId});
    return {unit, invocationId};
  }

  public async observe(identity: EngineIdentity, attempt: PreparedAttempt): Promise<EngineObservation> {
    const existing = this.pending.get(identity.unit);
    if (existing !== undefined) return await existing;
    const observation = this.observeOnce(identity, attempt).finally(() => this.pending.delete(identity.unit));
    this.pending.set(identity.unit, observation);
    return await observation;
  }

  private async observeOnce(identity: EngineIdentity, attempt: PreparedAttempt): Promise<EngineObservation> {
    let confirmedFailure = false;
    try {
      if (!/^aark-case-engine-[a-f0-9]{40}\.service$/u.test(identity.unit) || !/^[a-f0-9]{32}$/u.test(identity.invocationId)) return {status: "unknown"};
      const receipt = await readJson<Receipt>(path.join(this.directory, `${identity.unit}.json`), 4096);
      if (![this.binding(attempt, "run"), this.binding(attempt, "resume")].includes(receipt.binding)) return {status: "unknown"};
      const values = await this.show(identity.unit);
      if (values === undefined || this.assertUnit(values, receipt.binding) !== identity.invocationId || receipt.invocationId !== identity.invocationId) return {status: "unknown"};
      const running = ["activating", "reloading", "deactivating"].includes(values.ActiveState ?? "")
        || (values.ActiveState === "active" && values.SubState !== "exited");
      const assignedEmptyGroup = values.TasksCurrent === "0" && values.ControlGroup === `/system.slice/${identity.unit}`;
      // systemd releases the empty cgroup of a RemainAfterExit service and then
      // reports TasksCurrent=[not set]. Missing properties are not this proof.
      const releasedEmptyGroup = values.TasksCurrent === "[not set]" && values.ControlGroup === "";
      const settled = !running && values.MainPID === "0" && (assignedEmptyGroup || releasedEmptyGroup)
        && ["exited", "dead", "failed"].includes(values.SubState ?? "");
      const exitedWithError = values.ExecMainCode === "1" && /^[1-9][0-9]*$/u.test(values.ExecMainStatus ?? "") && values.ExecMainStatus !== "75";
      const killed = ["2", "3"].includes(values.ExecMainCode ?? "") && /^[1-9][0-9]*$/u.test(values.ExecMainStatus ?? "");
      // Startup refusals and crashes can precede the first progress checkpoint,
      // or leave its disk unreadable. An owned, settled failed invocation proves
      // failure independently; it never proves completion or a resumable pause.
      confirmedFailure = settled && (values.ActiveState === "failed" || exitedWithError || killed);
      const result = await this.capture(process.execPath, [PROBE, "status", attempt.workflow.output]);
      if (!successful(result)) return {status: confirmedFailure ? "failed" : "unknown"};
      const native: unknown = JSON.parse(result.stdout.toString());
      if (typeof native !== "object" || native === null || Array.isArray(native)) return {status: confirmedFailure ? "failed" : "unknown"};
      const status = native as Record<string, unknown>;
      const counters: EngineObservation = {status: "unknown"};
      for (const [source, target] of [["currentScanBytesScanned", "bytesScanned"], ["currentScanFilesScanned", "filesScanned"], ["currentScanErrors", "scanErrors"]] as const) {
        const value = status[source];
        if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) counters[target] = value;
      }
      if (status.status === "failed" && typeof status.failureCode === "string" && FAILURE_CODES.has(status.failureCode)) counters.failureCode = status.failureCode;
      if (confirmedFailure) return {...counters, status: "failed"};
      if (running) return {...counters, status: "running"};
      if (!settled) return counters;
      if (status.status === "paused" && status.resumable === true && values.Result === "success" && values.ExecMainCode === "1" && values.ExecMainStatus === "75"
        && ["signal", "free-space-reserve", "output-cap"].includes(String(status.pauseReason))) {
        return {...counters, status: "paused", pauseReason: status.pauseReason as "signal" | "free-space-reserve" | "output-cap"};
      }
      if (status.status === "complete" && ["active", "inactive"].includes(values.ActiveState ?? "") && ["exited", "dead"].includes(values.SubState ?? "")
        && values.Result === "success" && values.ExecMainCode === "1" && values.ExecMainStatus === "0") {
        this.completed.set(attempt.configFile + ":" + attempt.configHash, identity);
        return {...counters, status: "complete"};
      }
      if (status.status === "failed") return {...counters, status: "failed"};
      return counters;
    } catch { return {status: confirmedFailure ? "failed" : "unknown"}; }
  }

  public async verify(attempt: PreparedAttempt): Promise<CompletionProof> {
    try {
      const identity = this.completed.get(attempt.configFile + ":" + attempt.configHash);
      if (identity === undefined || (await this.observe(identity, attempt)).status !== "complete") throw new Error();
      const result = await this.capture(process.execPath, [PROBE, "verify", attempt.configFile, attempt.configHash], this.verificationTimeout);
      if (!successful(result)) throw new Error();
      const proof = JSON.parse(result.stdout.toString()) as Partial<CompletionProof>;
      if (!/^[a-f0-9]{64}$/u.test(proof.sha256 ?? "") || !Number.isSafeInteger(proof.scansVerified) || proof.scansVerified !== attempt.workflow.scans.length
        || !Number.isSafeInteger(proof.filesVerified) || Number(proof.filesVerified) < 0) throw new Error();
      if ((await this.observe(identity, attempt)).status !== "complete") throw new Error();
      return proof as CompletionProof;
    } catch { throw new Error("case workflow completion verification failed"); }
  }

  public async resumeReady(attempt: PreparedAttempt): Promise<boolean> {
    const result = await this.capture(process.execPath, [CAPACITY, attempt.configFile, attempt.configHash]);
    if (!successful(result)) throw new Error("case quota readiness observation unavailable");
    let response: unknown;
    try { response = JSON.parse(result.stdout.toString()); } catch { throw new Error("case quota readiness observation unavailable"); }
    if (typeof response !== "object" || response === null || Array.isArray(response)
      || Object.keys(response).length !== 1 || !("ready" in response) || typeof response.ready !== "boolean") throw new Error("case quota readiness observation unavailable");
    return response.ready;
  }
}
