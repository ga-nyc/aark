import { randomUUID } from "node:crypto";
import { realpath } from "node:fs/promises";
import path from "node:path";
import { assertNoSymlinkComponents, nearestExistingParent, readJson } from "../core/fs-safe.js";
import { loadWorkflowConfig, overlaps } from "../workflow/config.js";
import { digest } from "./config.js";
import { CodexAgentError, validateAgentReply } from "./codex.js";
import { FAILURE_CODES } from "../workflow/failure.js";
import { acquireCaseLease, type CaseLease } from "./lease.js";
import { CaseSourceIdentityError } from "./sources.js";
import { EngineLaunchRefusedError } from "./launch-error.js";
import { loadCaseState, redactedCaseStatus, saveCaseState, writeCaseCompletion } from "./store.js";
import type { AgentBridge, AgentEvent, AgentReply, CaseAttempt, CaseConfig, CaseState, CompletionProof, EngineHost, EngineObservation, OutboxEntry, ReasonCode } from "./types.js";

interface Options {host: EngineHost; agent: AgentBridge; clock?: () => number}
type AgentResult = {entry: OutboxEntry; reply?: AgentReply; failed?: true};
type ProofResult = {proof?: CompletionProof; failed?: true};

/** Policy reconciliation owns no engine PID and never sends a signal to one. */
export class CaseSupervisor {
  private readonly clock: () => number;
  private tail: Promise<unknown> = Promise.resolve();
  private closed = false;
  private agentReady = false;
  private nextPreflight = 0;
  private agentInFlight = false;
  private agentResult: AgentResult | undefined;
  private readonly proofs = new Map<string, ProofResult | null>();
  private readonly nextVerification = new Map<string, number>();
  private readonly locations = new Map<string, Promise<string>>();
  private observationUnavailable = false;
  private capacityWaiting = false;
  private configChanged = false;

  private constructor(private readonly config: CaseConfig, private readonly state: CaseState,
    private readonly options: Options, private readonly lease: CaseLease) { this.clock = options.clock ?? Date.now; }

  public static async open(control: string, options: Options): Promise<CaseSupervisor> {
    const loaded = await loadCaseState(control);
    const lease = await acquireCaseLease(control);
    try {
      // Reload after ownership: another worker may have committed before releasing.
      const current = await loadCaseState(control);
      if (loaded.state.caseId !== current.state.caseId) throw new Error("case ownership changed");
      await options.host.preflight();
      const instance = new CaseSupervisor(current.config, current.state, options, lease);
      for (const entry of current.state.outbox) if (entry.status === "delivering") entry.status = "pending";
      await instance.preflightAgent();
      await instance.persist();
      return instance;
    } catch (error) { await lease.release(); await options.agent.close().catch(() => undefined); throw error; }
  }

  private serialized<T>(action: () => Promise<T>): Promise<T> {
    const next = this.tail.then(async () => { if (this.closed) throw new Error("case supervisor is closed"); return action(); });
    this.tail = next.catch(() => undefined);
    return next;
  }
  private changed(): void { this.state.revision++; this.state.updatedAt = new Date(this.clock()).toISOString(); }
  private async persist(): Promise<void> {
    await this.lease.assertHeld();
    this.state.updatedAt = new Date(this.clock()).toISOString();
    await saveCaseState(this.config.control, this.config, this.state);
  }

  private async preflightAgent(): Promise<void> {
    if (this.agentReady || this.clock() < this.nextPreflight) return;
    try { await this.options.agent.preflight(); this.agentReady = true; }
    catch (error) {
      if (error instanceof CodexAgentError && error.code === "agent-approval-required") this.state.permissionReason = "agent-approval-required";
      this.state.health = "agent-unavailable"; this.nextPreflight = this.clock() + 60_000;
    }
  }

  public tick(): Promise<void> { return this.serialized(() => this.reconcile()); }
  public snapshot(): Promise<Record<string, unknown>> { return this.serialized(async () => redactedCaseStatus(this.config, this.state)); }
  public pause(): Promise<void> { return this.serialized(async () => { this.setDesired("user-paused"); await this.persist(); }); }
  public resume(): Promise<void> { return this.serialized(async () => { this.setDesired("running"); await this.persist(); }); }
  private setDesired(desired: "running" | "user-paused"): void {
    if (desired === "running" && this.state.permissionReason === "agent-approval-required") {
      delete this.state.permissionReason; this.agentReady = false; this.nextPreflight = 0; this.changed();
    }
    if (this.state.desired !== desired) { this.state.desired = desired; this.changed(); }
  }

  private async readCommand(): Promise<void> {
    try {
      const command = await readJson<{version: number; id: string; desired: string}>(path.join(this.config.control, "case-command.json"), 1024);
      if (command.version !== 1 || typeof command.id !== "string"
        || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(command.id)
        || !["running", "user-paused"].includes(command.desired)) throw new Error("invalid command");
      if (command.id !== this.state.commandId) {
        this.state.commandId = command.id;
        this.setDesired(command.desired as "running" | "user-paused");
        await this.persist();
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") { this.state.permissionReason = "new-plan-required"; this.configChanged = true; }
    }
  }

  private async observe(): Promise<void> {
    this.observationUnavailable = false;
    for (let i = 0; i < this.state.jobs.length; i++) {
      const attempt = this.state.jobs[i]!.attempts.at(-1);
      if (attempt === undefined || attempt.status !== "running" || attempt.identity === undefined) continue;
      const approved = this.config.jobs[i]!.attempts[attempt.index]!;
      let observation;
      try { observation = await this.options.host.observe(attempt.identity, approved); }
      catch { observation = {status: "unknown" as const}; }
      if (!["running", "paused", "failed", "complete"].includes(observation.status)) { this.observationUnavailable = true; continue; }
      // Only fixed typed fields leave the host. Never persist arbitrary exception text.
      const safe: EngineObservation = {status: observation.status};
      if (observation.status === "paused" && ["signal", "free-space-reserve", "output-cap"].includes(observation.pauseReason ?? "")) safe.pauseReason = observation.pauseReason!;
      if (observation.status === "failed" && observation.failureCode !== undefined && FAILURE_CODES.has(observation.failureCode)) safe.failureCode = observation.failureCode;
      for (const key of ["bytesScanned", "filesScanned", "scanErrors"] as const) {
        const value = observation[key];
        if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) safe[key] = value;
      }
      attempt.observation = safe;
      if (observation.status === "failed" || observation.status === "paused") {
        attempt.status = observation.status; this.changed(); continue;
      }
      if (observation.status !== "complete") continue;
      const result = this.proofs.get(attempt.token);
      if (result === undefined) {
        if (this.clock() < (this.nextVerification.get(attempt.token) ?? 0)) { this.observationUnavailable = true; continue; }
        this.proofs.set(attempt.token, null);
        void Promise.resolve().then(() => this.options.host.verify(approved)).then(
          proof => { if (!this.closed) this.proofs.set(attempt.token, {proof}); },
          () => { if (!this.closed) this.proofs.set(attempt.token, {failed: true}); });
      } else if (result !== null) {
        if (result.proof !== undefined && /^[a-f0-9]{64}$/u.test(result.proof.sha256)
          && Number.isSafeInteger(result.proof.scansVerified) && result.proof.scansVerified === approved.workflow.scans.length
          && Number.isSafeInteger(result.proof.filesVerified) && result.proof.filesVerified >= 0) {
          attempt.proof = result.proof; attempt.status = "complete";
          this.changed();
        } else {
          this.observationUnavailable = true;
          this.proofs.delete(attempt.token);
          this.nextVerification.set(attempt.token, this.clock() + 60_000);
        }
      }
    }
  }

  private async launch(index: number, attempt: CaseAttempt): Promise<void> {
    const approved = this.config.jobs[index]!.attempts[attempt.index]!;
    if (attempt.mode === "resume" && attempt.dispatched !== true
      && this.state.jobs[index]!.attempts.at(-2)?.resumeReady !== true) return;
    try {
      if (digest(await loadWorkflowConfig(approved.configFile)) !== approved.configHash) throw new Error();
    } catch { this.state.permissionReason = "new-plan-required"; this.configChanged = true; return; }
    // The intent is committed BEFORE making the idempotent external launch call.
    attempt.dispatched = true;
    await this.persist();
    try {
      attempt.identity = await this.options.host.launch(approved, attempt.token, attempt.mode);
      attempt.status = "running";
      this.changed();
      await this.persist();
    } catch (error) {
      if (error instanceof EngineLaunchRefusedError) {
        attempt.status = "failed"; attempt.launchRefused = true; attempt.observation = {status: "failed"};
        this.changed(); await this.persist(); return;
      }
      // A missing launch reply cannot establish whether an engine started.
      this.observationUnavailable = true;
      if (error instanceof CaseSourceIdentityError) {
        this.state.permissionReason = "new-media-required"; this.configChanged = true; this.changed();
      }
    }
  }

  private newAttempt(index: number, mode: "run" | "resume"): void {
    const job = this.state.jobs[index]!;
    const previous = job.attempts.at(-1);
    const attemptIndex = mode === "resume" ? previous!.index : (previous?.index ?? -1) + 1;
    job.attempts.push({index: attemptIndex, token: randomUUID(), mode, status: "launching"});
    this.changed();
  }

  private async pollResumeReadiness(): Promise<void> {
    this.capacityWaiting = false;
    for (let index = 0; index < this.state.jobs.length; index++) {
      const saved = this.state.jobs[index]!;
      const latest = saved.attempts.at(-1);
      const paused = latest?.status === "paused" ? latest
        : latest?.status === "launching" && latest.mode === "resume" && latest.dispatched !== true ? saved.attempts.at(-2) : undefined;
      if (paused?.status !== "paused") continue;
      if (paused.observation?.pauseReason === "output-cap") {
        if (this.state.permissionReason === undefined) { this.state.permissionReason = "new-plan-required"; this.changed(); }
        continue;
      }
      if (!this.config.jobs[index]!.resumeAfterQuota || paused.observation?.pauseReason !== "free-space-reserve") continue;
      let ready: boolean | undefined;
      try {
        const observed = await this.options.host.resumeReady?.(this.config.jobs[index]!.attempts[paused.index]!);
        if (typeof observed === "boolean") ready = observed;
      } catch { /* Unavailable capacity observations do not authorize a resume. */ }
      if (paused.resumeReady !== ready) {
        if (ready === undefined) delete paused.resumeReady;
        else paused.resumeReady = ready;
        this.changed();
      }
      if (ready !== true) this.capacityWaiting = true;
      if (ready === undefined) this.observationUnavailable = true;
    }
  }

  private resolvedLocation(value: string): Promise<string> {
    let result = this.locations.get(value);
    if (result === undefined) {
      result = (async () => {
        const existing = await nearestExistingParent(value);
        const canonical = await realpath(existing);
        const resolved = path.resolve(canonical, path.relative(existing, value));
        await assertNoSymlinkComponents(canonical, resolved);
        return resolved;
      })();
      this.locations.set(value, result);
    }
    return result;
  }

  private async dependenciesReady(index: number, attemptIndex: number): Promise<boolean> {
    const job = this.config.jobs[index]!;
    if (!job.dependsOn.every(id => this.state.jobs.find(parent => parent.id === id)!.attempts.at(-1)?.status === "complete")) return false;
    const workflow = job.attempts[attemptIndex]!.workflow;
    const recovery = workflow.recovery;
    const inputs = [...workflow.scans.flatMap(scan => scan.inputs), ...(recovery === undefined ? [] : [recovery.source,
      ...[recovery.analysisSource, recovery.mountedReadOnlyRoot, recovery.unallocatedStreamFromCase].filter((root): root is string => root !== undefined)])];
    try {
      const canonicalInputs = await Promise.all(inputs.map(input => this.resolvedLocation(input)));
      for (let producer = 0; producer < this.config.jobs.length; producer++) {
        if (producer === index) continue;
        for (let producingAttempt = 0; producingAttempt < this.config.jobs[producer]!.attempts.length; producingAttempt++) {
          const planned = this.config.jobs[producer]!.attempts[producingAttempt]!.workflow;
          const roots = await Promise.all([planned.output, ...(planned.recovery === undefined ? [] : [planned.recovery.destination])]
            .map(root => this.resolvedLocation(root)));
          if (!roots.some(root => canonicalInputs.some(input => overlaps(root, input) || overlaps(input, root)))) continue;
          const saved = this.state.jobs[producer]!;
          if (saved.attempts.some(attempt => attempt.index === producingAttempt && attempt.status === "complete" && attempt.proof !== undefined)) continue;
          if (saved.attempts.at(-1)?.status === "complete") {
            this.state.permissionReason = "new-plan-required";
            this.configChanged = true;
            this.changed();
          }
          return false;
        }
      }
      return true;
    } catch { this.observationUnavailable = true; return false; }
  }

  /** Attach only; this path may run during a user pause or permission stop. */
  private async reattach(): Promise<Set<string>> {
    const unavailable = new Set<string>();
    for (let index = 0; index < this.state.jobs.length; index++) {
      const attempt = this.state.jobs[index]!.attempts.at(-1);
      if (attempt?.status !== "launching" || attempt.dispatched !== true) continue;
      const approved = this.config.jobs[index]!.attempts[attempt.index]!;
      if (this.options.host.reattach !== undefined) {
        try {
          const identity = await this.options.host.reattach(approved, attempt.token, attempt.mode);
          if (identity !== undefined) {
            attempt.identity = identity; attempt.status = "running"; attempt.observation = {status: "running"};
            this.changed(); await this.persist(); continue;
          }
        } catch (error) {
          if (error instanceof EngineLaunchRefusedError) {
            attempt.status = "failed"; attempt.launchRefused = true; attempt.observation = {status: "failed"};
            this.changed(); await this.persist(); continue;
          }
          unavailable.add(attempt.token);
        }
      }
      attempt.observation = {status: "unknown"};
      this.observationUnavailable = true;
    }
    return unavailable;
  }

  private processReply(): void {
    const result = this.agentResult;
    if (result === undefined) return;
    this.agentResult = undefined;
    const {entry} = result;
    let reply: AgentReply | undefined;
    try { if (result.reply !== undefined) reply = validateAgentReply(result.reply, entry.event); }
    catch { /* Invalid agent packets retry under the same transport budget. */ }
    if (result.failed || reply === undefined) {
      entry.status = "pending";
      const failures = this.state.outbox.reduce((count, row) => count + (row === entry || row.nextDeliveryAt > 0 ? row.deliveries : 0), 0);
      entry.nextDeliveryAt = this.clock() + Math.min(300_000, 5000 * 2 ** Math.min(failures, 6));
      this.state.health = "agent-unavailable";
      return;
    }
    entry.status = "processed";
    // A valid transport response ends the case-wide consecutive-failure period.
    for (const row of this.state.outbox) row.nextDeliveryAt = 0;
    if (reply.eventId !== entry.event.eventId || reply.revision !== entry.event.revision) return;
    const action = reply.action;
    // A permission stop remains valid when unrelated engines advance the case.
    // Only execution decisions and acknowledgements require its current revision.
    if (action.type === "needs-permission") {
      entry.reply = reply;
      if (this.state.permissionReason === undefined) this.state.permissionReason = action.reason;
      return;
    }
    if (reply.revision !== this.state.revision) return;
    entry.reply = reply;
    if (this.state.permissionReason !== undefined) return;
    if (action.type === "acknowledge") {
      if (entry.event.reason === "case-completed") this.state.completionDeliveredToAgent = true;
      else if (["job-failed", "job-paused", "configuration-changed"].includes(entry.event.reason)) this.state.permissionReason = "new-plan-required";
      return;
    }
    if (this.state.desired !== "running" || this.state.complete || this.state.permissionReason !== undefined) return;
    const index = this.config.jobs.findIndex(job => job.id === action.jobId);
    const previous = this.state.jobs[index]?.attempts.at(-1);
    const job = this.config.jobs[index];
    if (index < 0 || previous === undefined || job === undefined) { this.state.permissionReason = "new-plan-required"; return; }
    if (action.type === "retry" && previous.status === "failed" && previous.index + 1 < job.attempts.length) this.newAttempt(index, "run");
    else if (action.type === "resume" && previous.status === "paused" && job.resumeAfterQuota
      && previous.observation?.pauseReason === "free-space-reserve") {
      if (previous.resumeReady === true) this.newAttempt(index, "resume");
      // Capacity may change after a decision was prepared. Wait for a fresh
      // readiness edge instead of requiring a new authorization plan.
    }
    else this.state.permissionReason = "new-plan-required";
  }

  private eventJobs(): AgentEvent["jobs"] {
    return this.state.jobs.map((job, index) => ({id: job.id, status: job.attempts.at(-1)?.status ?? "pending",
      attemptsUsed: job.attempts.filter(attempt => attempt.mode === "run").length,
      attemptsAllowed: this.config.jobs[index]!.attempts.length, resumeAfterQuota: this.config.jobs[index]!.resumeAfterQuota,
      ...(job.attempts.at(-1)?.observation?.pauseReason === undefined ? {} : {pauseReason: job.attempts.at(-1)!.observation!.pauseReason!}),
      ...(job.attempts.at(-1)?.observation?.failureCode === undefined ? {} : {failureCode: job.attempts.at(-1)!.observation!.failureCode!}),
      ...(job.attempts.at(-1)?.resumeReady === undefined ? {} : {resumeReady: job.attempts.at(-1)!.resumeReady!})}));
  }
  private queueDecision(reason: ReasonCode): void {
    const jobs = this.eventJobs();
    if (this.state.outbox.some(entry => entry.event.revision === this.state.revision
      && entry.event.reason === reason && digest(entry.event.jobs) === digest(jobs))) return;
    // A processed stale request can be replaced at the current revision.
    if (this.state.outbox.length >= 2048) { this.state.permissionReason = "new-plan-required"; return; }
    this.state.outbox.push({event: {version: 1, caseId: this.state.caseId, eventId: randomUUID(), revision: this.state.revision, reason, jobs},
      status: "pending", deliveries: 0, nextDeliveryAt: this.transportBackoffUntil()});
  }

  private transportBackoffUntil(): number {
    return this.state.outbox.reduce((until, row) => row.deliveries > 0 ? Math.max(until, row.nextDeliveryAt) : until, 0);
  }

  private async dispatch(): Promise<void> {
    if (this.agentInFlight || !this.agentReady || this.state.desired !== "running") return;
    // A new event must not bypass a failed request's durable transport cooldown.
    if (this.clock() < this.transportBackoffUntil()) return;
    const entry = this.state.outbox.find(row => row.status === "pending" && row.nextDeliveryAt <= this.clock());
    if (entry === undefined) return;
    if (this.state.agentRequests >= this.config.agent.maxRequests) { this.state.health = "agent-unavailable"; return; }
    this.state.agentRequests++; entry.deliveries++; entry.status = "delivering";
    await this.persist();
    this.agentInFlight = true;
    void Promise.resolve().then(() => this.options.agent.request(structuredClone(entry.event))).then(
      reply => { if (!this.closed) this.agentResult = {entry, reply}; },
      () => { if (!this.closed) this.agentResult = {entry, failed: true}; })
      .finally(() => { this.agentInFlight = false; });
  }

  private async reconcile(): Promise<void> {
    await this.lease.assertHeld();
    this.locations.clear();
    await this.readCommand();
    await this.preflightAgent();
    await this.observe();
    const unavailableReattachments = await this.reattach();
    const unavailableBeforeCapacity = this.observationUnavailable;
    await this.pollResumeReadiness();
    this.processReply();
    // Listed independent jobs already have durable execution authorization.
    // Agent transport readiness gates decisions, not that approved native work;
    // explicit approval stops still gate both launch loops below.
    if (this.state.desired === "running") {
      for (let i = 0; i < this.state.jobs.length; i++) {
        const job = this.state.jobs[i]!;
        const attempt = job.attempts.at(-1);
        const occupied = this.state.jobs.filter(other => { const last = other.attempts.at(-1); return last?.status === "running" || (last?.status === "launching" && last.dispatched === true); }).length;
        if (attempt?.status === "launching" && this.state.permissionReason === undefined && !this.configChanged
          && !unavailableReattachments.has(attempt.token)
          && (attempt.dispatched === true || (occupied < this.config.maxConcurrent && await this.dependenciesReady(i, attempt.index)))) await this.launch(i, attempt);
      }
      for (let i = 0; i < this.state.jobs.length; i++) {
        if (this.state.jobs.filter(job => { const latest = job.attempts.at(-1); return latest?.status === "running"
          || (latest?.status === "launching" && latest.dispatched === true); }).length >= this.config.maxConcurrent) break;
        const job = this.state.jobs[i]!;
        if (this.state.permissionReason === undefined && !this.configChanged && job.attempts.length === 0 && await this.dependenciesReady(i, 0)) {
          this.newAttempt(i, "run"); await this.launch(i, job.attempts.at(-1)!);
        }
      }
    }
    if (!this.state.complete && this.state.jobs.every(job => job.attempts.at(-1)?.status === "complete")) {
      await this.lease.assertHeld();
      await writeCaseCompletion(this.config, this.state);
      this.state.complete = true; this.changed();
    }
    const statuses = this.state.jobs.map(job => job.attempts.at(-1)?.status);
    // Retire stale work before deduplication, health calculation, and publication
    // so this same tick can retain a decision for the current case revision.
    for (const row of this.state.outbox) if (row.status === "pending" && row.event.revision !== this.state.revision) row.status = "processed";
    if (this.state.complete && !this.state.completionDeliveredToAgent) this.queueDecision("case-completed");
    else if (this.configChanged) this.queueDecision("configuration-changed");
    else if (statuses.includes("failed")) this.queueDecision("job-failed");
    else if (this.state.jobs.some(job => { const latest = job.attempts.at(-1); return latest?.status === "paused" && latest.resumeReady === true; })) this.queueDecision("job-paused");
    else if (unavailableBeforeCapacity) this.queueDecision("observation-unavailable");
    const pendingDelivery = this.state.outbox.some(row => row.status === "pending");
    // Historical failures still constrain dispatch, but health describes work
    // that is currently waiting and only while its transport deadline is live.
    const transportBlocked = pendingDelivery && this.clock() < this.transportBackoffUntil();
    this.state.health = this.state.permissionReason !== undefined ? "awaiting-permission"
      : !this.agentReady || transportBlocked || (this.state.agentRequests >= this.config.agent.maxRequests && pendingDelivery) ? "agent-unavailable"
      : this.observationUnavailable ? "observation-unavailable"
      : this.state.outbox.some(row => row.status !== "processed") ? "awaiting-agent"
      : this.capacityWaiting || statuses.some(status => status === "failed" || status === "paused") ? "degraded" : "healthy";
    await this.persist();
    await this.dispatch();
  }

  public async run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted && !this.closed) {
      await this.tick();
      if (signal.aborted) break;
      await new Promise<void>(resolve => {
        const done = () => { clearTimeout(timer); signal.removeEventListener("abort", done); resolve(); };
        const timer = setTimeout(done, this.config.pollMs);
        signal.addEventListener("abort", done, {once: true});
        if (signal.aborted) done();
      });
    }
  }

  public async close(): Promise<void> {
    await this.tail;
    if (this.closed) return;
    this.closed = true;
    await this.options.agent.close().catch(() => undefined);
    await this.lease.release();
  }
}
