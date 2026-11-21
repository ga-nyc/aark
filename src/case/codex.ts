import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, realpath, rename, unlink } from "node:fs/promises";
import path from "node:path";
import type { Readable, Writable } from "node:stream";
import type { AgentBridge, AgentConfig, AgentEvent, AgentReply, PermissionReason } from "./types.js";
import { FAILURE_CODES } from "../workflow/failure.js";
import { readJson } from "../core/fs-safe.js";
import { CodexPipeTransport } from "./codex-transport.js";

export type CodexAgentErrorCode = "agent-unavailable" | "agent-busy" | "agent-timeout" | "agent-invalid-response" | "agent-approval-required" | "agent-request-limit";
export class CodexAgentError extends Error {
  constructor(readonly code: CodexAgentErrorCode) { super(code); this.name = "CodexAgentError"; }
}
function fail(code: CodexAgentErrorCode): never { throw new CodexAgentError(code); }
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (value: Record<string, unknown>, keys: string[]): boolean => Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const identifier = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);
const opaqueId = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(value);
const integer = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const REASONS = new Set(["job-failed", "job-paused", "configuration-changed", "observation-unavailable", "case-completed", "agent-unavailable"]);
const STATUSES = new Set(["pending", "launching", "running", "paused", "failed", "complete"]);
const PERMISSIONS: PermissionReason[] = ["new-plan-required", "new-media-required", "destructive-operation", "credentials-required", "physical-intervention", "scope-change", "agent-approval-required"];

/** Reject unknown fields rather than accidentally forwarding paths or diagnostics. */
export function validateAgentEvent(value: unknown): AgentEvent {
  if (!object(value) || !exact(value, ["version", "caseId", "eventId", "revision", "reason", "jobs"])
      || value.version !== 1 || !opaqueId(value.caseId) || !opaqueId(value.eventId) || !integer(value.revision)
      || typeof value.reason !== "string" || !REASONS.has(value.reason) || !Array.isArray(value.jobs) || value.jobs.length < 1 || value.jobs.length > 64) fail("agent-invalid-response");
  const seen = new Set<string>();
  for (const job of value.jobs) {
    if (!object(job) || !exact(job, ["id", "status", "attemptsUsed", "attemptsAllowed", "resumeAfterQuota",
      ...(Object.hasOwn(job, "pauseReason") ? ["pauseReason"] : []), ...(Object.hasOwn(job, "failureCode") ? ["failureCode"] : []),
      ...(Object.hasOwn(job, "resumeReady") ? ["resumeReady"] : [])])
        || typeof job.id !== "string" || !/^job-[0-9]{6}$/u.test(job.id) || seen.has(job.id) || typeof job.status !== "string" || !STATUSES.has(job.status)
        || !integer(job.attemptsUsed) || !integer(job.attemptsAllowed) || job.attemptsAllowed < 1 || job.attemptsAllowed > 4 || job.attemptsUsed > job.attemptsAllowed
        || typeof job.resumeAfterQuota !== "boolean"
        || (job.resumeReady !== undefined && (job.status !== "paused" || typeof job.resumeReady !== "boolean"))
        || (job.pauseReason !== undefined && (job.status !== "paused" || !["signal", "free-space-reserve", "output-cap"].includes(String(job.pauseReason))))
        || (job.failureCode !== undefined && (typeof job.failureCode !== "string" || !FAILURE_CODES.has(job.failureCode)))) fail("agent-invalid-response");
    seen.add(job.id);
  }
  return JSON.parse(JSON.stringify(value)) as AgentEvent;
}
export function validateAgentReply(value: unknown, event: AgentEvent): AgentReply {
  if (!object(value) || !exact(value, ["eventId", "revision", "action"]) || value.eventId !== event.eventId
      || value.revision !== event.revision || !object(value.action)) fail("agent-invalid-response");
  const action = value.action;
  if (action.type === "retry" || action.type === "resume") {
    if (!exact(action, ["type", "jobId"]) || !identifier(action.jobId) || !event.jobs.some((job) => job.id === action.jobId)) fail("agent-invalid-response");
  } else if (action.type === "needs-permission") {
    if (!exact(action, ["type", "reason"]) || !PERMISSIONS.includes(action.reason as PermissionReason)) fail("agent-invalid-response");
  } else if (action.type !== "acknowledge" || !exact(action, ["type"])) fail("agent-invalid-response");
  return JSON.parse(JSON.stringify(value)) as AgentReply;
}
function outputSchema(event: AgentEvent): unknown {
  const retry = event.jobs.filter(job => job.status === "failed" && job.attemptsUsed < job.attemptsAllowed).map(job => job.id);
  const resume = event.jobs.filter(job => job.status === "paused" && job.resumeAfterQuota && job.resumeReady === true
    && job.pauseReason === "free-space-reserve").map(job => job.id);
  const selections = [{type: "retry", ids: retry}, {type: "resume", ids: resume}];
  return { type: "object", additionalProperties: false, required: ["eventId", "revision", "action"], properties: {
    eventId: { type: "string", enum: [event.eventId] }, revision: { type: "integer", enum: [event.revision] },
    action: { anyOf: [
      ...selections.filter(selection => selection.ids.length > 0).map(({type, ids}) => ({type: "object", additionalProperties: false,
        required: ["type", "jobId"], properties: {type: {type: "string", enum: [type]}, jobId: {type: "string", enum: ids}}})),
      { type: "object", additionalProperties: false, required: ["type", "reason"], properties: { type: { type: "string", enum: ["needs-permission"] }, reason: { type: "string", enum: PERMISSIONS } } },
      { type: "object", additionalProperties: false, required: ["type"], properties: { type: { type: "string", enum: ["acknowledge"] } } },
    ] },
  } };
}

export interface CodexFileIdentity { canonical: string; kind: "file" | "directory" | "socket" | "other"; uid: number; mode: number }
export interface CodexBindingInspection {
  platform: string;
  currentUid: number;
  accounts(): Promise<string>;
  inspect(filename: string): Promise<CodexFileIdentity>;
}
export interface CodexValidatedBinding { uid: number; currentUid: number; home: string }
function absolute(value: string): boolean { return path.isAbsolute(value) && path.resolve(value) === value && !/[\x00-\x1f]/.test(value); }
function validateConfig(config: AgentConfig): void {
  if (config.ownership !== "dedicated-thread" || !absolute(config.executable) || !absolute(config.socketPath)
      || !absolute(config.stateDirectory) || !identifier(config.threadId) || !/^[A-Za-z_][A-Za-z0-9_.-]*[$]?$/.test(config.user)
      || !Array.isArray(config.readableRoots) || config.readableRoots.length < 1 || config.readableRoots.length > 32
      || config.readableRoots.some((root) => !absolute(root) || root === path.parse(root).root)
      || new Set(config.readableRoots).size !== config.readableRoots.length
      || !integer(config.timeoutMs) || config.timeoutMs < 1 || config.timeoutMs > 3_600_000
      || !integer(config.maxRequests) || config.maxRequests < 1 || config.maxRequests > 10_000) fail("agent-unavailable");
}
/** Metadata only: no evidence, tool logs, socket connection, or model request. */
export async function validateCodexAgentConfig(config: AgentConfig, inspection?: CodexBindingInspection): Promise<CodexValidatedBinding> {
  validateConfig(config);
  const io: CodexBindingInspection = inspection ?? {
    platform: process.platform, currentUid: process.getuid?.() ?? -1,
    accounts: () => readFile("/etc/passwd", "utf8"),
    inspect: async (filename) => {
      const metadata = await lstat(filename);
      return { canonical: await realpath(filename), kind: metadata.isSymbolicLink() ? "other" : metadata.isSocket() ? "socket" : metadata.isFile() ? "file" : metadata.isDirectory() ? "directory" : "other", uid: metadata.uid, mode: metadata.mode };
    },
  };
  try {
    if (io.platform !== "linux") fail("agent-unavailable");
    const account = (await io.accounts()).split("\n").map((line) => line.split(":"))
      .find((fields) => fields[0] === config.user);
    const uid = Number(account?.[2]);
    const home = account?.[5];
    if (!Number.isSafeInteger(uid) || uid <= 0 || !home || !absolute(home) || (io.currentUid !== 0 && io.currentUid !== uid)) fail("agent-unavailable");
    const executable = await io.inspect(config.executable);
    if (executable.canonical !== config.executable || executable.kind !== "file" || ![0, uid].includes(executable.uid)
        || (executable.mode & 0o022) !== 0 || (executable.mode & 0o111) === 0) fail("agent-unavailable");
    const socket = await io.inspect(config.socketPath);
    if (socket.canonical !== config.socketPath || socket.kind !== "socket" || socket.uid !== uid
        || (socket.mode & 0o077) !== 0 || (socket.mode & 0o600) !== 0o600) fail("agent-unavailable");
    const parent = await io.inspect(path.dirname(config.socketPath));
    if (parent.kind !== "directory" || parent.canonical !== path.dirname(config.socketPath) || ![0, uid].includes(parent.uid) || (parent.mode & 0o022) !== 0) fail("agent-unavailable");
    for (const root of config.readableRoots) {
      const metadata = await io.inspect(root);
      if (metadata.canonical !== root || metadata.kind !== "directory") fail("agent-unavailable");
    }
    if (io.currentUid === 0) {
      const runuser = await io.inspect("/usr/sbin/runuser");
      if (runuser.canonical !== "/usr/sbin/runuser" || runuser.kind !== "file" || runuser.uid !== 0
          || (runuser.mode & 0o022) !== 0 || (runuser.mode & 0o111) === 0) fail("agent-unavailable");
    }
    return { uid, currentUid: io.currentUid, home };
  } catch { fail("agent-unavailable"); }
}

export interface CodexProxyProcess {
  stdin: Writable; stdout: Readable; stderr: Readable;
  once(event: "error", listener: (error: Error) => void): unknown;
  once(event: "exit", listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
  kill(signal?: NodeJS.Signals): boolean;
}
export interface CodexSpawnOptions { cwd: string; env: NodeJS.ProcessEnv; stdio: "pipe"; shell: false; windowsHide: true }
export interface CodexBridgeDependencies {
  spawn?: (executable: string, args: string[], options: CodexSpawnOptions) => CodexProxyProcess;
  validate?: (config: AgentConfig) => Promise<CodexValidatedBinding>;
}
interface Receipt { version: 1; bindingHash: string; parentThreadId: string; threadId: string; profile: string }
interface Pending { resolve(value: unknown): void; reject(error: Error): void }
interface TurnWaiter {
  event: AgentEvent; id?: string; completed: Map<string, Record<string, unknown>>;
  messages: Map<string, Map<string, string>>;
  reply?: AgentReply;
  resolve(reply: AgentReply): void; reject(error: Error): void;
}

/**
 * Opt-in, local-IPC bridge. The case store must hold its exclusive process lock.
 * A fresh decision thread receives events without parent history or dynamic
 * tools. The registered human parent is association metadata only and is never
 * resumed, steered, or interrupted. A lost response can deliver an event again:
 * callers must persist event/revision replies and apply case actions idempotently.
 */
export class CodexAgentBridge implements AgentBridge {
  private readonly config: AgentConfig;
  private readonly deps: CodexBridgeDependencies;
  private child: CodexProxyProcess | undefined;
  private ready = false;
  private closed = false;
  private working = false;
  private requests = 0;
  private nextId = 1;
  private transport: CodexPipeTransport | undefined;
  private readonly pending = new Map<number, Pending>();
  private receipt: Receipt | undefined;
  private turn: TurnWaiter | undefined;
  private blockedReply: AgentReply | undefined;
  private readonly replies = new Map<string, AgentReply>();
  constructor(config: AgentConfig, dependencies: CodexBridgeDependencies = {}) {
    validateConfig(config);
    this.config = { ...config, readableRoots: [...config.readableRoots] };
    this.deps = dependencies;
  }
  async preflight(signal?: AbortSignal): Promise<void> {
    if (this.working || this.closed) fail(this.closed ? "agent-unavailable" : "agent-busy");
    this.working = true;
    try { await this.deadline((current) => this.setup(current), signal); }
    catch (error) {
      const fixed = error instanceof CodexAgentError ? error : new CodexAgentError("agent-unavailable");
      this.disconnect(fixed);
      throw fixed;
    }
    finally { this.working = false; }
  }
  async request(input: AgentEvent, externalSignal?: AbortSignal): Promise<AgentReply> {
    const event = validateAgentEvent(input);
    if (this.closed) fail("agent-unavailable");
    if (this.working) fail("agent-busy");
    const key = `${event.caseId}|${event.eventId}|${event.revision}`;
    const remembered = this.replies.get(key);
    if (remembered) return structuredClone(remembered);
    if (this.requests >= this.config.maxRequests) fail("agent-request-limit");
    this.working = true;
    try {
      const reply = await this.deadline(async (signal) => {
        await this.setup(signal);
        this.assertActive(signal);
        const receipt = this.receipt!;
        const thread = await this.rpc("thread/read", { threadId: receipt.threadId, includeTurns: false });
        this.assertActive(signal);
        this.checkThread(thread, receipt.threadId, true);
        // The transport can stay ready across many events. External/user goal
        // changes must be checked again before each decision turn, without ever
        // clearing a goal or taking over its automatic continuation lifecycle.
        const goal = await this.rpc("thread/goal/get", { threadId: receipt.threadId });
        this.assertActive(signal);
        if (!object(goal) || !Object.hasOwn(goal, "goal")) fail("agent-invalid-response");
        if (goal.goal !== null) fail("agent-approval-required");
        this.assertActive(signal);
        let resolve!: (reply: AgentReply) => void;
        let reject!: (error: Error) => void;
        const result = new Promise<AgentReply>((yes, no) => { resolve = yes; reject = no; });
        // Attach a handler before any RPC can synchronously receive a refusal.
        void result.catch(() => undefined);
        this.turn = { event, completed: new Map(), messages: new Map(), resolve, reject };
        this.requests++;
        const started = await this.rpc("turn/start", {
          threadId: receipt.threadId,
          input: [{ type: "text", text: JSON.stringify(event), text_elements: [] }],
          outputSchema: outputSchema(event), approvalPolicy: "on-request", approvalsReviewer: "user",
          permissions: receipt.profile, runtimeWorkspaceRoots: this.config.readableRoots,
          cwd: this.config.readableRoots[0], environments: [],
          clientUserMessageId: event.eventId,
        });
        if (!object(started) || !object(started.turn) || !identifier(started.turn.id)) fail("agent-invalid-response");
        if (this.turn) {
          this.turn.id = started.turn.id;
          this.finishTurn();
        }
        return result;
      }, externalSignal);
      this.replies.set(key, reply);
      if (this.blockedReply) this.disconnect(new CodexAgentError("agent-approval-required"));
      return structuredClone(reply);
    } catch (error) {
      // Completion can arrive before cancellation while its async return is
      // still propagating. A known validated reply must survive that race.
      if (this.turn?.reply !== undefined) {
        const reply = this.turn.reply;
        this.replies.set(key, reply);
        this.disconnect(new CodexAgentError("agent-unavailable"));
        return structuredClone(reply);
      }
      if (this.blockedReply || (error instanceof CodexAgentError && error.code === "agent-approval-required")) {
        const reply: AgentReply = this.blockedReply ?? { eventId: event.eventId, revision: event.revision,
          action: { type: "needs-permission", reason: "agent-approval-required" } };
        this.replies.set(key, reply);
        this.disconnect(new CodexAgentError("agent-approval-required"));
        return structuredClone(reply);
      }
      this.disconnect(error instanceof CodexAgentError ? error : new CodexAgentError("agent-unavailable"));
      throw error instanceof CodexAgentError ? error : new CodexAgentError("agent-unavailable");
    } finally { this.turn = undefined; this.blockedReply = undefined; this.working = false; }
  }
  async close(): Promise<void> {
    this.closed = true;
    this.disconnect(new CodexAgentError("agent-unavailable"));
  }
  private async deadline<T>(operation: (signal: AbortSignal) => Promise<T>, externalSignal?: AbortSignal): Promise<T> {
    if (externalSignal?.aborted) fail("agent-unavailable");
    const controller = new AbortController();
    let timer: NodeJS.Timeout | undefined;
    let rejectStopped!: (error: CodexAgentError) => void;
    const stopped = new Promise<never>((_resolve, reject) => { rejectStopped = reject; });
    const stop = () => {
      const error = new CodexAgentError("agent-unavailable");
      controller.abort(error);
      this.disconnect(error);
      rejectStopped(error);
    };
    externalSignal?.addEventListener("abort", stop, {once: true});
    const timedOut = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        const error = new CodexAgentError("agent-timeout");
        controller.abort(error);
        this.disconnect(error);
        reject(error);
      }, this.config.timeoutMs);
    });
    try { return await Promise.race([operation(controller.signal), timedOut, stopped]); }
    finally { if (timer) clearTimeout(timer); externalSignal?.removeEventListener("abort", stop); }
  }
  private assertActive(signal: AbortSignal): void {
    signal.throwIfAborted();
    if (this.closed) fail("agent-unavailable");
  }
  private bindingHash(): string {
    return createHash("sha256").update(JSON.stringify({ ownership: this.config.ownership, executable: this.config.executable, socketPath: this.config.socketPath,
      parentThreadId: this.config.threadId, user: this.config.user, readableRoots: this.config.readableRoots })).digest("hex");
  }
  private async setup(signal: AbortSignal): Promise<void> {
    this.assertActive(signal);
    if (this.ready) return;
    const identity = await (this.deps.validate ?? validateCodexAgentConfig)(this.config);
    this.assertActive(signal);
    await this.prepareState();
    this.assertActive(signal);
    await this.startProxy(identity, signal);
    this.assertActive(signal);
    await this.rpc("initialize", { clientInfo: { name: "aark-case-supervisor", version: "1" }, capabilities: { experimentalApi: true } });
    this.assertActive(signal);
    this.send({ method: "initialized", params: {} });
    this.receipt = await this.readReceipt();
    this.assertActive(signal);
    const profile = this.receipt?.profile ?? `aark-case-${randomUUID()}`;
    const settings = await this.restrictedSettings(profile);
    this.assertActive(signal);
    if (!this.receipt) {
      const parent = await this.rpc("thread/read", { threadId: this.config.threadId, includeTurns: false });
      this.assertActive(signal);
      this.checkThread(parent, this.config.threadId, false);
      await this.claimThread();
      this.assertActive(signal);
      const response = await this.rpc("thread/start", { dynamicTools: [], environments: [], ephemeral: false, ...settings });
      if (!object(response) || !object(response.thread) || !identifier(response.thread.id) || response.thread.id === this.config.threadId) fail("agent-invalid-response");
      this.receipt = { version: 1, bindingHash: this.bindingHash(), parentThreadId: this.config.threadId, threadId: response.thread.id, profile };
      // Persist identity before subsequent setup: uncertainty must not create another thread.
      await this.writeReceipt(this.receipt);
      this.assertActive(signal);
      await unlink(path.join(this.config.stateDirectory, "codex-thread-intent.json"));
      this.assertActive(signal);
      this.checkThread(response, this.receipt.threadId, true);
      this.checkSettings(response, profile);
    }
    this.assertActive(signal);
    const resumed = await this.rpc("thread/resume", { threadId: this.receipt.threadId, excludeTurns: true, ...settings });
    this.assertActive(signal);
    this.checkThread(resumed, this.receipt.threadId, true);
    this.checkSettings(resumed, profile);
    // A fresh decision thread has no inherited goal. A later goal belongs to
    // external/user intent and must not be cleared or automatically continued.
    const goal = await this.rpc("thread/goal/get", { threadId: this.receipt.threadId });
    this.assertActive(signal);
    if (!object(goal) || !Object.hasOwn(goal, "goal")) fail("agent-invalid-response");
    if (goal.goal !== null) fail("agent-approval-required");
    this.assertActive(signal);
    this.ready = true;
  }
  private async startProxy(identity: CodexValidatedBinding, signal: AbortSignal): Promise<void> {
    this.assertActive(signal);
    // This command is a stdio-to-Unix-socket proxy, not a new model session.
    const args = ["app-server", "proxy", "--sock", this.config.socketPath];
    const executable = identity.currentUid === 0 ? "/usr/sbin/runuser" : this.config.executable;
    const commandArgs = identity.currentUid === 0 ? ["-u", this.config.user, "--", this.config.executable, ...args] : args;
    const options: CodexSpawnOptions = { cwd: this.config.readableRoots[0]!, stdio: "pipe", shell: false, windowsHide: true,
      env: { PATH: "/usr/bin:/bin", HOME: identity.home, USER: this.config.user, LOGNAME: this.config.user, LANG: "C.UTF-8" } };
    const child: CodexProxyProcess = this.deps.spawn ? this.deps.spawn(executable, commandArgs, options) : spawn(executable, commandArgs, options);
    this.child = child;
    const transport = new CodexPipeTransport(bytes => child.stdin.write(bytes), text => this.message(JSON.parse(text)),
      kind => { if (this.child === child) this.disconnect(new CodexAgentError(kind === "invalid" ? "agent-invalid-response" : "agent-unavailable")); });
    this.transport = transport;
    child.stdout.on("data", (chunk: Buffer) => { if (this.child === child) transport.receive(chunk); });
    child.stderr.resume(); // Never retain or forward subprocess diagnostics.
    child.stdin.on("error", () => { if (this.child === child) this.disconnect(new CodexAgentError("agent-unavailable")); });
    child.once("error", () => { if (this.child === child) this.disconnect(new CodexAgentError("agent-unavailable")); });
    child.once("exit", () => { if (this.child === child) this.disconnect(new CodexAgentError("agent-unavailable")); });
    transport.start();
    await transport.ready;
    this.assertActive(signal);
  }
  private send(value: unknown): void {
    if (!this.child || this.closed || this.transport === undefined) fail("agent-unavailable");
    this.transport.send(value);
  }
  private rpc(method: string, params: unknown): Promise<unknown> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      try { this.send({ id, method, params }); }
      catch { this.pending.delete(id); reject(new CodexAgentError("agent-unavailable")); }
    });
  }
  private message(value: unknown): void {
    if (!object(value)) fail("agent-invalid-response");
    if (typeof value.method === "string") {
      if (Object.hasOwn(value, "id")) { this.refuse(value); return; }
      this.notification(value.method, value.params);
      return;
    }
    if (typeof value.id !== "number") return;
    const pending = this.pending.get(value.id);
    if (!pending) return;
    this.pending.delete(value.id);
    if (Object.hasOwn(value, "error") || !Object.hasOwn(value, "result")) pending.reject(new CodexAgentError("agent-unavailable"));
    else pending.resolve(value.result);
  }
  private refuse(request: Record<string, unknown>): void {
    const params = request.params;
    const ownedThread = this.receipt?.threadId;
    if (ownedThread === undefined || !object(params)) return;
    const scopes = ["threadId", "conversationId"].filter((key) => Object.hasOwn(params, key));
    // Managed-server connections can replay requests belonging to other clients.
    // Never decline, answer, or error a human/unscoped request. If both modern
    // and legacy scopes are present, both must identify this owned thread.
    if (scopes.length === 0 || scopes.some((key) => params[key] !== ownedThread)) return;
    let result: unknown;
    switch (request.method) {
      case "item/commandExecution/requestApproval": case "item/fileChange/requestApproval": result = { decision: "decline" }; break;
      case "execCommandApproval": case "applyPatchApproval": result = { decision: { denied: { rejection: "agent-approval-required" } } }; break;
      case "item/permissions/requestApproval": result = { permissions: {}, scope: "turn" }; break;
      case "item/tool/requestUserInput": result = { answers: {} }; break;
      case "mcpServer/elicitation/request": result = { action: "decline" }; break;
      case "item/tool/call": result = { success: false, contentItems: [] }; break;
      default: this.send({ id: request.id, error: { code: -32601, message: "agent-approval-required" } }); break;
    }
    if (result !== undefined) this.send({ id: request.id, result });
    if (this.turn) {
      this.blockedReply = { eventId: this.turn.event.eventId, revision: this.turn.event.revision,
        action: { type: "needs-permission", reason: "agent-approval-required" } };
      this.turn.resolve(this.blockedReply);
      for (const pending of this.pending.values()) pending.reject(new CodexAgentError("agent-approval-required"));
      this.pending.clear();
    } else this.disconnect(new CodexAgentError("agent-approval-required"));
  }
  private notification(method: string, params: unknown): void {
    const waiter = this.turn;
    if (!waiter || !object(params) || params.threadId !== this.receipt?.threadId) return;
    if (method === "item/completed" && identifier(params.turnId) && object(params.item)) this.rememberMessage(params.turnId, params.item);
    if (method === "turn/completed") {
      if (!object(params.turn) || !identifier(params.turn.id)) fail("agent-invalid-response");
      if (waiter.completed.size > 4) fail("agent-invalid-response");
      waiter.completed.set(params.turn.id, params.turn);
      this.finishTurn();
    }
  }
  private rememberMessage(turnId: string, item: Record<string, unknown>): void {
    if (!this.turn || item.type !== "agentMessage" || (item.phase !== undefined && item.phase !== null && item.phase !== "final_answer")) return;
    if (!identifier(item.id) || typeof item.text !== "string" || item.text.length > 16_384) fail("agent-invalid-response");
    let messages = this.turn.messages.get(turnId);
    if (!messages) { if (this.turn.messages.size > 4) fail("agent-invalid-response"); messages = new Map(); this.turn.messages.set(turnId, messages); }
    const old = messages.get(item.id);
    if (old !== undefined && old !== item.text) fail("agent-invalid-response");
    messages.set(item.id, item.text);
    if (messages.size > 4) fail("agent-invalid-response");
  }
  private finishTurn(): void {
    const waiter = this.turn;
    if (!waiter?.id) return;
    const completed = waiter.completed.get(waiter.id);
    if (!completed) return;
    try {
      if (completed.status !== "completed" || completed.error != null || !Array.isArray(completed.items)) fail("agent-invalid-response");
      for (const item of completed.items) if (object(item)) this.rememberMessage(waiter.id, item);
      const messages = waiter.messages.get(waiter.id);
      if (!messages || messages.size !== 1) fail("agent-invalid-response");
      const text = [...messages.values()][0]!;
      waiter.reply = validateAgentReply(JSON.parse(text), waiter.event);
      waiter.resolve(waiter.reply);
    } catch { waiter.reject(new CodexAgentError("agent-invalid-response")); }
  }
  private checkThread(response: unknown, expected: string, child: boolean): void {
    if (!object(response) || !object(response.thread) || response.thread.id !== expected || !object(response.thread.status)) fail("agent-invalid-response");
    // Parent status cannot block this independent thread; no input is sent to it.
    if (!child) return;
    if (response.thread.forkedFromId != null) fail("agent-invalid-response");
    const status = response.thread.status.type;
    if (status === "active") fail("agent-busy");
    if (status !== "idle" && status !== "notLoaded") fail("agent-unavailable");
    if (response.thread.canAcceptDirectInput === false) fail("agent-busy");
  }
  private checkSettings(response: unknown, profile: string): void {
    if (!object(response) || response.approvalPolicy !== "on-request" || response.approvalsReviewer !== "user"
        || !object(response.activePermissionProfile) || response.activePermissionProfile.id !== profile
        || response.activePermissionProfile.extends != null
        || !object(response.sandbox) || response.sandbox.type !== "readOnly" || response.sandbox.networkAccess !== false
        || JSON.stringify(response.runtimeWorkspaceRoots) !== JSON.stringify(this.config.readableRoots)) fail("agent-unavailable");
  }
  private async restrictedSettings(profile: string): Promise<Record<string, unknown>> {
    const read = await this.rpc("config/read", { cwd: this.config.readableRoots[0], includeLayers: false });
    if (!object(read) || !object(read.config)) fail("agent-invalid-response");
    const mcp: Record<string, unknown> = {};
    const plugins: Record<string, unknown> = {};
    if (object(read.config.mcp_servers)) for (const id of Object.keys(read.config.mcp_servers)) mcp[id] = { enabled: false };
    if (object(read.config.plugins)) for (const id of Object.keys(read.config.plugins)) plugins[id] = { enabled: false };
    const filesystem = Object.fromEntries([[":root", "deny"], [":minimal", "read"], ...this.config.readableRoots.map((root) => [root, "read"])]);
    return { permissions: profile, approvalPolicy: "on-request", approvalsReviewer: "user", cwd: this.config.readableRoots[0],
      baseInstructions: "You are the AARK case decision worker. Return only the JSON decision required by the output schema. Use only the redacted event supplied in the current request. Do not inspect files, call tools, contact services, or request secrets.",
      developerInstructions: "The native supervisor owns all execution authorization. Choose retry only for a failed job with an unused reviewed attempt; otherwise request new-plan-required. Choose resume only for a clean free-space-reserve pause with resumeAfterQuota and resumeReady both true; never override a signal or user pause. An output-cap pause requires a new plan. Acknowledge completion after all jobs are complete. Unknown observations do not prove failure. No decision authorizes cleanup, source writes, new scope, or arbitrary commands.",
      runtimeWorkspaceRoots: this.config.readableRoots, config: {
        default_permissions: profile, permissions: { [profile]: { filesystem, network: { enabled: false } } },
        web_search: "disabled", features: { apps: false, plugins: false, remote_plugin: false,
          shell_tool: false, unified_exec: false, browser_use: false, browser_use_external: false,
          computer_use: false, in_app_browser: false, multi_agent: false, multi_agent_v2: false,
          code_mode: false, code_mode_host: false, image_generation: false, view_image: false,
          hooks: false, goals: false, memories: false, skill_search: false, skill_mcp_dependency_install: false },
        apps: { _default: { enabled: false, destructive_enabled: false, open_world_enabled: false } }, mcp_servers: mcp, plugins,
      } };
  }
  private async prepareState(): Promise<void> {
    await mkdir(this.config.stateDirectory, { mode: 0o700 }).catch((error: unknown) => {
      if (!object(error) || error.code !== "EEXIST") throw error;
    });
    const metadata = await lstat(this.config.stateDirectory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid !== (process.getuid?.() ?? -1)
        || (metadata.mode & 0o077) !== 0 || await realpath(this.config.stateDirectory) !== this.config.stateDirectory) fail("agent-unavailable");
  }
  private async readReceipt(): Promise<Receipt | undefined> {
    const filename = path.join(this.config.stateDirectory, "codex-thread.json");
    try {
      const metadata = await lstat(filename);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o077) !== 0
          || metadata.uid !== (process.getuid?.() ?? -1) || await realpath(filename) !== filename) fail("agent-unavailable");
      const value = await readJson<unknown>(filename, 4096);
      if (!object(value) || !exact(value, ["version", "bindingHash", "parentThreadId", "threadId", "profile"])
          || value.version !== 1 || value.bindingHash !== this.bindingHash() || value.parentThreadId !== this.config.threadId
          || !identifier(value.threadId) || value.threadId === this.config.threadId || typeof value.profile !== "string"
          || !/^aark-case-[0-9a-f-]{36}$/.test(value.profile)) fail("agent-unavailable");
      return value as unknown as Receipt;
    } catch (error) {
      if (object(error) && error.code === "ENOENT") return undefined;
      fail("agent-unavailable");
    }
  }
  private async claimThread(): Promise<void> {
    const handle = await open(path.join(this.config.stateDirectory, "codex-thread-intent.json"), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(JSON.stringify({ version: 1, bindingHash: this.bindingHash() }) + "\n"); await handle.sync(); }
    finally { await handle.close(); }
    await this.syncState();
  }
  private async writeReceipt(receipt: Receipt): Promise<void> {
    const filename = path.join(this.config.stateDirectory, "codex-thread.json");
    const temporary = path.join(this.config.stateDirectory, `.codex-thread-${randomUUID()}.tmp`);
    const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(JSON.stringify(receipt) + "\n"); await handle.sync(); }
    finally { await handle.close(); }
    await rename(temporary, filename);
    await this.syncState();
  }
  private async syncState(): Promise<void> {
    const handle = await open(this.config.stateDirectory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await handle.sync(); } finally { await handle.close(); }
  }
  private disconnect(error: CodexAgentError): void {
    const child = this.child;
    this.child = undefined;
    this.ready = false;
    this.transport?.close(); this.transport = undefined;
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
    this.turn?.reject(error);
    if (child) { child.stdin.end(); child.kill("SIGTERM"); }
  }
}
