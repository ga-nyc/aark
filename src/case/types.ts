import type { WorkflowConfig } from "../workflow/config.js";

export type JobStatus = "pending" | "launching" | "running" | "paused" | "failed" | "complete";
export type CaseHealth = "healthy" | "degraded" | "awaiting-agent" | "awaiting-permission" | "agent-unavailable" | "observation-unavailable";
export type ReasonCode = "job-failed" | "job-paused" | "configuration-changed" | "observation-unavailable" | "case-completed" | "agent-unavailable";
export type PermissionReason = "new-plan-required" | "new-media-required" | "destructive-operation" | "credentials-required" | "physical-intervention" | "scope-change" | "agent-approval-required";

export interface PreparedAttempt {
  configFile: string;
  configHash: string;
  workflow: WorkflowConfig;
}
export interface CaseSourceBinding { source: string; sha256: string }
export type CaseSourceBindings = Record<string, CaseSourceBinding[]>;
export interface CaseJob {
  id: string;
  dependsOn: string[];
  attempts: PreparedAttempt[];
  resumeAfterQuota: boolean;
}
export interface AgentConfig {
  ownership: "dedicated-thread";
  stateDirectory: string;
  executable: string;
  socketPath: string;
  threadId: string;
  user: string;
  readableRoots: string[];
  timeoutMs: number;
  maxRequests: number;
}
export interface CaseConfig {
  version: 1;
  execute: boolean;
  control: string;
  jobs: CaseJob[];
  pollMs: number;
  probeTimeoutMs: number;
  maxConcurrent: number;
  agent: AgentConfig;
}
export interface EngineIdentity {
  unit: string;
  invocationId: string;
}
export interface EngineObservation {
  status: "absent" | "running" | "paused" | "failed" | "complete" | "unknown";
  failureCode?: string;
  pauseReason?: "signal" | "free-space-reserve" | "output-cap";
  bytesScanned?: number;
  filesScanned?: number;
  scanErrors?: number;
}
export interface CompletionProof {
  sha256: string;
  scansVerified: number;
  filesVerified: number;
}
export interface EngineHost {
  preflight(): Promise<void>;
  /** token is a persisted idempotency key; repeat launch must attach, not duplicate. */
  launch(attempt: PreparedAttempt, token: string, mode: "run" | "resume"): Promise<EngineIdentity>;
  /** Reconcile an uncertain launch without starting an absent engine. */
  reattach?(attempt: PreparedAttempt, token: string, mode: "run" | "resume"): Promise<EngineIdentity | undefined>;
  /** Fresh capacity check for an unchanged, clean free-space pause. */
  resumeReady?(attempt: PreparedAttempt): Promise<boolean>;
  observe(identity: EngineIdentity, attempt: PreparedAttempt): Promise<EngineObservation>;
  verify(attempt: PreparedAttempt): Promise<CompletionProof>;
}
export interface AgentEvent {
  version: 1;
  caseId: string;
  eventId: string;
  revision: number;
  reason: ReasonCode;
  jobs: Array<{id: string; status: JobStatus; attemptsUsed: number; attemptsAllowed: number; resumeAfterQuota: boolean;
    pauseReason?: "signal" | "free-space-reserve" | "output-cap"; failureCode?: string; resumeReady?: boolean}>;
}
export type AgentAction =
  | {type: "retry"; jobId: string}
  | {type: "resume"; jobId: string}
  | {type: "needs-permission"; reason: PermissionReason}
  | {type: "acknowledge"};
export interface AgentReply {
  eventId: string;
  revision: number;
  action: AgentAction;
}
export interface AgentBridge {
  preflight(): Promise<void>;
  request(event: AgentEvent): Promise<AgentReply>;
  close(): Promise<void>;
}
export interface CaseAttempt {
  index: number;
  token: string;
  status: JobStatus;
  mode: "run" | "resume";
  dispatched?: boolean;
  resumeReady?: boolean;
  identity?: EngineIdentity;
  observation?: EngineObservation;
  proof?: CompletionProof;
}
export interface JobState {
  id: string;
  attempts: CaseAttempt[];
}
export interface OutboxEntry {
  event: AgentEvent;
  status: "pending" | "delivering" | "processed";
  deliveries: number;
  nextDeliveryAt: number;
  reply?: AgentReply;
}
export interface CaseState {
  version: 1;
  caseId: string;
  revision: number;
  configHash: string;
  sourceBindings: CaseSourceBindings;
  desired: "running" | "user-paused" | "stopped";
  health: CaseHealth;
  jobs: JobState[];
  outbox: OutboxEntry[];
  agentRequests: number;
  permissionReason?: PermissionReason;
  startedAt: string;
  updatedAt: string;
  complete: boolean;
  completionDeliveredToAgent: boolean;
  commandId?: string;
}
