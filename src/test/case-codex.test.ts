import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { test, type TestContext } from "node:test";
import { CodexAgentBridge, validateAgentEvent, validateAgentReply, validateCodexAgentConfig,
  type CodexBindingInspection, type CodexFileIdentity, type CodexProxyProcess, type CodexSpawnOptions } from "../case/codex.js";
import type { AgentConfig, AgentEvent, AgentReply } from "../case/types.js";

const EVENT: AgentEvent = { version: 1, caseId: "11111111-1111-4111-8111-111111111111", eventId: "22222222-2222-4222-8222-222222222222", revision: 3, reason: "job-failed",
  jobs: [{ id: "job-000001", status: "failed", attemptsUsed: 1, attemptsAllowed: 2, resumeAfterQuota: false }] };
const REPLY: AgentReply = { eventId: EVENT.eventId, revision: EVENT.revision, action: { type: "retry", jobId: "job-000001" } };
const linuxTest = (name: string, fn: (context: TestContext) => Promise<void>): void => { test(name, { skip: process.platform !== "linux" }, fn); };
type Wire = Record<string, unknown>;
class FakeProxy extends EventEmitter implements CodexProxyProcess {
  readonly stdin = new PassThrough();
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  readonly killed: NodeJS.Signals[] = [];
  private buffer: Buffer = Buffer.alloc(0);
  private upgraded = false;
  constructor(readonly server: FakeServer) {
    super();
    this.stdin.on("data", (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      if (!this.upgraded) {
        const end = this.buffer.indexOf("\r\n\r\n");
        if (end < 0) return;
        const key = /Sec-WebSocket-Key: ([^\r\n]+)/u.exec(this.buffer.subarray(0, end).toString())?.[1];
        assert.ok(key, "real managed IPC requires an HTTP WebSocket upgrade");
        this.buffer = this.buffer.subarray(end + 4); this.upgraded = true;
        const accept = createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
        this.stdout.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
      }
      while (this.buffer.length >= 2) {
        const opcode = this.buffer[0]! & 15;
        assert.ok((this.buffer[1]! & 128) !== 0, "client WebSocket frames must be masked");
        let size = this.buffer[1]! & 127, offset = 2;
        if (size === 126) { if (this.buffer.length < 4) return; size = this.buffer.readUInt16BE(2); offset = 4; }
        else if (size === 127) { if (this.buffer.length < 10) return; size = Number(this.buffer.readBigUInt64BE(2)); offset = 10; }
        if (this.buffer.length < offset + 4 + size) return;
        const mask = this.buffer.subarray(offset, offset + 4);
        const payload = Buffer.from(this.buffer.subarray(offset + 4, offset + 4 + size));
        this.buffer = this.buffer.subarray(offset + 4 + size);
        for (let index = 0; index < payload.length; index++) payload[index] = payload[index]! ^ mask[index % 4]!;
        if (opcode !== 1) continue;
        const request = JSON.parse(payload.toString()) as Wire;
        server.wire.push(request);
        queueMicrotask(() => server.receive(request, this));
      }
    });
  }
  kill(signal: NodeJS.Signals = "SIGTERM"): boolean { this.killed.push(signal); return true; }
  send(value: unknown): void {
    const payload = Buffer.from(JSON.stringify(value));
    const header = Buffer.alloc(payload.length < 126 ? 2 : 4);
    header[0] = 0x81; header[1] = payload.length < 126 ? payload.length : 126;
    if (payload.length >= 126) header.writeUInt16BE(payload.length, 2);
    this.stdout.write(Buffer.concat([header, payload]));
  }
  result(request: Wire, value: unknown): void { this.send({ id: request.id, result: value }); }
}
class FakeServer {
  readonly wire: Wire[] = [];
  readonly proxies: FakeProxy[] = [];
  readonly spawns: Array<{ executable: string; args: string[]; options: CodexSpawnOptions }> = [];
  childStatus = "idle";
  parentStatus = "idle";
  goal: unknown = null;
  reply: unknown = REPLY;
  terminal = "completed";
  autoComplete = true;
  settings: Wire = {};
  custom: ((request: Wire, proxy: FakeProxy) => boolean) | undefined;
  spawn = (executable: string, args: string[], options: CodexSpawnOptions): FakeProxy => {
    this.spawns.push({ executable, args, options });
    const proxy = new FakeProxy(this); this.proxies.push(proxy); return proxy;
  };
  thread(id: string): Wire { return { id, forkedFromId: null,
    status: { type: id === "registered-parent" ? this.parentStatus : this.childStatus }, canAcceptDirectInput: true }; }
  resumeResult(): Wire { return { thread: this.thread("case-agent-thread"), approvalPolicy: "on-request", approvalsReviewer: "user",
    activePermissionProfile: { id: this.settings.permissions }, sandbox: { type: "readOnly", networkAccess: false },
    runtimeWorkspaceRoots: this.settings.runtimeWorkspaceRoots }; }
  complete(proxy: FakeProxy, status = this.terminal, reply: unknown = this.reply): void {
    proxy.send({ method: "turn/completed", params: { threadId: "case-agent-thread", turn: { id: "turn-fixture", status, error: null,
      items: [{ type: "agentMessage", id: "message-fixture", phase: "final_answer", text: typeof reply === "string" ? reply : JSON.stringify(reply) }] } } });
  }
  receive(request: Wire, proxy: FakeProxy): void {
    if (this.custom?.(request, proxy)) return;
    if (typeof request.method !== "string") return;
    const params = request.params as Wire;
    switch (request.method) {
      case "initialize": proxy.result(request, { userAgent: "synthetic" }); break;
      case "initialized": break;
      case "config/read": proxy.result(request, { config: { mcp_servers: { fixture_remote: { enabled: true } }, plugins: { "fixture-plugin": { enabled: true } } } }); break;
      case "thread/read": proxy.result(request, { thread: this.thread(params.threadId as string) }); break;
      case "thread/start": case "thread/resume": this.settings = params; proxy.result(request, this.resumeResult()); break;
      case "thread/goal/get": proxy.result(request, { goal: this.goal }); break;
      case "thread/goal/clear": this.goal = null; proxy.result(request, {}); break;
      case "turn/start":
        proxy.result(request, { turn: { id: "turn-fixture", status: "inProgress", items: [] } });
        if (this.autoComplete) queueMicrotask(() => this.complete(proxy));
        break;
      default: assert.fail("Unexpected method: " + request.method);
    }
  }
  calls(method: string): Wire[] { return this.wire.filter((request) => request.method === method); }
}
async function fixture(context: TestContext, changes: Partial<AgentConfig> = {}): Promise<{ config: AgentConfig; server: FakeServer; bridge: CodexAgentBridge }> {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "aark-codex-test-")));
  context.after(() => rm(root, { recursive: true, force: true }));
  const config: AgentConfig = { ownership: "dedicated-thread", stateDirectory: path.join(root, "agent"), executable: "/approved/bin/codex",
    socketPath: "/approved/runtime/app.sock", threadId: "registered-parent", user: "fixtureuser", readableRoots: [root], timeoutMs: 500, maxRequests: 4, ...changes };
  const server = new FakeServer();
  const bridge = new CodexAgentBridge(config, { spawn: server.spawn, validate: async () => ({ uid: 4242, currentUid: 4242, home: "/home/fixtureuser" }) });
  context.after(() => bridge.close());
  return { config, server, bridge };
}
const code = (message: string): { message: string } => ({ message });

linuxTest("Codex preflight creates a protected fresh decision thread without starting a model turn", async (context) => {
  const { config, server, bridge } = await fixture(context);
  await bridge.preflight();
  const initialized = server.calls("initialize")[0]!.params as Wire;
  assert.equal(Object.hasOwn(initialized.capabilities as Wire, "requiredHumanApproval"), false);
  assert.equal(server.calls("thread/start").length, 1);
  assert.equal(server.calls("turn/start").length, 0);
  assert.equal(server.calls("thread/goal/clear").length, 0);
  const created = server.calls("thread/start")[0]!.params as Wire;
  assert.deepEqual(created.dynamicTools, []);
  assert.deepEqual(created.environments, []);
  assert.equal(created.ephemeral, false);
  assert.equal(Object.hasOwn(created, "threadId"), false);
  assert.equal(server.calls("thread/fork").length, 0);
  assert.equal(server.calls("thread/resume").every((call) => (call.params as Wire).threadId === "case-agent-thread"), true);
  const receipt = JSON.parse(await readFile(path.join(config.stateDirectory, "codex-thread.json"), "utf8")) as Wire;
  assert.equal(receipt.threadId, "case-agent-thread");
  assert.equal(receipt.parentThreadId, "registered-parent");
  assert.equal((await stat(config.stateDirectory)).mode & 0o777, 0o700);
  assert.equal((await stat(path.join(config.stateDirectory, "codex-thread.json"))).mode & 0o777, 0o600);
  await bridge.preflight();
  assert.equal(server.calls("thread/start").length, 1);
});
linuxTest("Codex request sends only the fixed redacted event and binds the reply to event revision", async (context) => {
  const { bridge, server } = await fixture(context);
  assert.deepEqual(await bridge.request(EVENT), REPLY);
  const turn = server.calls("turn/start")[0]!.params as Wire;
  assert.equal(turn.threadId, "case-agent-thread");
  assert.deepEqual(turn.input, [{ type: "text", text: JSON.stringify(EVENT), text_elements: [] }]);
  assert.equal(turn.approvalPolicy, "on-request");
  assert.equal(turn.approvalsReviewer, "user");
  assert.deepEqual(turn.environments, []);
  assert.equal(Object.hasOwn(turn, "sandboxPolicy"), false); // named profile carries restrictive roots
  assert.equal(typeof turn.permissions, "string");
  assert.deepEqual(await bridge.request(EVENT), REPLY);
  assert.equal(server.calls("turn/start").length, 1);
  assert.equal(server.wire.some((item) => item.method === "turn/steer" || item.method === "turn/interrupt"), false);
});
linuxTest("Codex fresh-thread config disables network, web, apps, plugins, MCP, and execution tools", async (context) => {
  const { bridge, server, config } = await fixture(context);
  await bridge.preflight();
  const params = server.calls("thread/start")[0]!.params as Wire;
  const settings = params.config as Wire;
  const profiles = settings.permissions as Record<string, Wire>;
  const profile = profiles[params.permissions as string]!;
  assert.deepEqual(profile.network, { enabled: false });
  assert.deepEqual(profile.filesystem, Object.fromEntries([[":root", "deny"], [":minimal", "read"], [config.readableRoots[0], "read"]]));
  assert.equal(settings.default_permissions, params.permissions);
  assert.equal(settings.web_search, "disabled");
  assert.equal((settings.features as Wire).apps, false);
  assert.equal((settings.features as Wire).plugins, false);
  assert.equal((settings.features as Wire).shell_tool, false);
  assert.equal((settings.features as Wire).goals, false);
  assert.equal((settings.features as Wire).hooks, false);
  assert.equal((settings.features as Wire).code_mode_host, false);
  assert.deepEqual(settings.mcp_servers, { fixture_remote: { enabled: false } });
  assert.deepEqual(settings.plugins, { "fixture-plugin": { enabled: false } });
});
linuxTest("Codex start and resume use fixed decision instructions with the fixed decision policy", async (context) => {
  const { bridge, server } = await fixture(context);
  await bridge.preflight();
  const created = server.calls("thread/start")[0]!.params as Wire;
  assert.equal(typeof created.baseInstructions, "string");
  assert.equal(typeof created.developerInstructions, "string");
  assert.match(created.baseInstructions as string, /Use only the redacted event/);
  assert.match(created.developerInstructions as string, /never override a signal or user pause/);
  for (const call of server.calls("thread/resume")) {
    const resumed = call.params as Wire;
    assert.equal(resumed.baseInstructions, created.baseInstructions);
    assert.equal(resumed.developerInstructions, created.developerInstructions);
  }
});
for (const method of ["thread/start", "thread/resume"]) {
  for (const networkAccess of [undefined, null, true, "false", 0]) {
    linuxTest(`Codex rejects ${networkAccess === undefined ? "missing" : JSON.stringify(networkAccess)} network assurance on ${method}`, async (context) => {
      const { bridge, server } = await fixture(context);
      server.custom = (request, proxy) => {
        if (request.method !== method) return false;
        server.settings = request.params as Wire;
        const sandbox: Wire = { type: "readOnly" };
        if (networkAccess !== undefined) sandbox.networkAccess = networkAccess;
        proxy.result(request, { ...server.resumeResult(), sandbox });
        return true;
      };
      await assert.rejects(bridge.preflight(), code("agent-unavailable"));
      assert.equal(server.calls("turn/start").length, 0);
    });
  }
  linuxTest(`Codex rejects inherited effective permission profiles on ${method}`, async (context) => {
    const { bridge, server } = await fixture(context);
    server.custom = (request, proxy) => {
      if (request.method !== method) return false;
      server.settings = request.params as Wire;
      proxy.result(request, { ...server.resumeResult(), activePermissionProfile: { id: server.settings.permissions, extends: "inherited-profile" } });
      return true;
    };
    await assert.rejects(bridge.preflight(), code("agent-unavailable"));
    assert.equal(server.calls("turn/start").length, 0);
  });
}
linuxTest("Codex decision schema includes only approved retries and currently ready quota resumes", async context => {
  const {bridge, server} = await fixture(context);
  const event: AgentEvent = {...EVENT, jobs: [EVENT.jobs[0]!,
    {id: "job-000002", status: "failed", attemptsUsed: 1, attemptsAllowed: 1, resumeAfterQuota: false},
    {id: "job-000003", status: "paused", attemptsUsed: 1, attemptsAllowed: 1, resumeAfterQuota: true, pauseReason: "free-space-reserve", resumeReady: false},
    {id: "job-000004", status: "paused", attemptsUsed: 1, attemptsAllowed: 1, resumeAfterQuota: true, pauseReason: "free-space-reserve", resumeReady: true},
    {id: "job-000005", status: "paused", attemptsUsed: 1, attemptsAllowed: 1, resumeAfterQuota: true, pauseReason: "signal"}]};
  await bridge.request(event);
  const params = server.calls("turn/start")[0]!.params as Wire;
  const schema = params.outputSchema as {properties: {action: {anyOf: Array<{properties: {type: {enum: string[]}; jobId?: {enum: string[]}}}>}}};
  const actions = schema.properties.action.anyOf;
  assert.deepEqual(actions.find(action => action.properties.type.enum[0] === "retry")!.properties.jobId!.enum, ["job-000001"]);
  assert.deepEqual(actions.find(action => action.properties.type.enum[0] === "resume")!.properties.jobId!.enum, ["job-000004"]);
});

linuxTest("Codex root supervisor invokes only the proxy as the configured desktop account", async (context) => {
  const { bridge, server, config } = await fixture(context);
  await bridge.close();
  const rootBridge = new CodexAgentBridge(config, { spawn: server.spawn, validate: async () => ({ uid: 4242, currentUid: 0, home: "/home/fixtureuser" }) });
  context.after(() => rootBridge.close());
  await rootBridge.preflight();
  const invocation = server.spawns[0]!;
  assert.equal(invocation.executable, "/usr/sbin/runuser");
  assert.deepEqual(invocation.args.slice(0, 4), ["-u", "fixtureuser", "--", config.executable]);
  assert.deepEqual(invocation.args.slice(4), ["app-server", "proxy", "--sock", config.socketPath]);
  assert.equal(invocation.options.shell, false);
  assert.equal(invocation.options.env.HOME, "/home/fixtureuser");
  assert.deepEqual(Object.keys(invocation.options.env).sort(), ["HOME", "LANG", "LOGNAME", "PATH", "USER"]);
});
linuxTest("Codex reuses the persisted decision thread across bridge lifetimes", async (context) => {
  const { bridge, config, server } = await fixture(context);
  await bridge.preflight(); await bridge.close();
  const next = new CodexAgentBridge(config, { spawn: server.spawn, validate: async () => ({ uid: 4242, currentUid: 4242, home: "/home/fixtureuser" }) });
  context.after(() => next.close());
  await next.preflight();
  assert.equal(server.calls("thread/start").length, 1);
});
linuxTest("Codex preserves an unexpected user goal on reuse and requires permission without starting a turn", async (context) => {
  const { bridge, config, server } = await fixture(context);
  await bridge.preflight();
  await bridge.close();
  const goal = { objective: "synthetic external goal", status: "paused", tokenBudget: 1234 };
  server.goal = structuredClone(goal);
  const next = new CodexAgentBridge(config, { spawn: server.spawn, validate: async () => ({ uid: 4242, currentUid: 4242, home: "/home/fixtureuser" }) });
  context.after(() => next.close());
  await assert.rejects(next.preflight(), code("agent-approval-required"));
  assert.deepEqual(server.goal, goal);
  assert.equal(server.calls("thread/goal/clear").length, 0);
  assert.equal(server.calls("turn/start").length, 0);
  assert.equal(server.calls("thread/start").length, 1);
});
linuxTest("Codex rechecks a new user goal after preflight even while the connection is ready", async (context) => {
  const { bridge, server } = await fixture(context);
  await bridge.preflight();
  const checksBefore = server.calls("thread/goal/get").length;
  const goal = { objective: "synthetic external goal after preflight", status: "paused", tokenBudget: 100 };
  server.goal = structuredClone(goal);
  assert.deepEqual(await bridge.request(EVENT), { eventId: EVENT.eventId, revision: EVENT.revision,
    action: { type: "needs-permission", reason: "agent-approval-required" } });
  assert.equal(server.calls("thread/goal/get").length, checksBefore + 1);
  assert.deepEqual(server.goal, goal);
  assert.equal(server.calls("thread/goal/clear").length, 0);
  assert.equal(server.calls("turn/start").length, 0);
});
linuxTest("Codex rechecks user goals between successful decisions on the same ready connection", async (context) => {
  const { bridge, server } = await fixture(context);
  assert.deepEqual(await bridge.request(EVENT), REPLY);
  const next: AgentEvent = { ...EVENT, eventId: "33333333-3333-4333-8333-333333333333", revision: EVENT.revision + 1 };
  server.reply = { ...REPLY, eventId: next.eventId, revision: next.revision };
  const goal = { objective: "synthetic external goal after one decision", status: "paused" };
  server.goal = structuredClone(goal);
  assert.deepEqual(await bridge.request(next), { eventId: next.eventId, revision: next.revision,
    action: { type: "needs-permission", reason: "agent-approval-required" } });
  assert.deepEqual(server.goal, goal);
  assert.equal(server.calls("thread/goal/clear").length, 0);
  assert.equal(server.calls("turn/start").length, 1);
});
linuxTest("Codex checks an empty goal immediately before every new decision turn", async (context) => {
  const { bridge, server } = await fixture(context);
  await bridge.request(EVENT);
  const firstTurn = server.wire.findLastIndex((request) => request.method === "turn/start");
  const next: AgentEvent = { ...EVENT, eventId: "33333333-3333-4333-8333-333333333333", revision: EVENT.revision + 1 };
  const expected = { ...REPLY, eventId: next.eventId, revision: next.revision };
  server.reply = expected;
  assert.deepEqual(await bridge.request(next), expected);
  const goalCheck = server.wire.findLastIndex((request) => request.method === "thread/goal/get");
  const secondTurn = server.wire.findLastIndex((request) => request.method === "turn/start");
  assert.ok(firstTurn < goalCheck && goalCheck < secondTurn);
  assert.equal((server.wire[goalCheck]!.params as Wire).threadId, "case-agent-thread");
  assert.equal(server.calls("thread/start").length, 1);
});
linuxTest("Codex ignores unowned and unscoped managed-server request replays without answering or blocking its own decision", async (context) => {
  const { bridge, config, server } = await fixture(context);
  const ignored = new Set<string>();
  const replay = (proxy: FakeProxy, method: string, params: unknown): void => {
    const id = "unowned-replay-" + ignored.size;
    ignored.add(id);
    proxy.send({ id, method, params });
  };
  server.custom = (request, proxy) => {
    if (request.method === "initialize") {
      replay(proxy, "item/commandExecution/requestApproval", { threadId: config.threadId });
      replay(proxy, "execCommandApproval", { conversationId: "case-agent-thread" }); // No owned receipt exists yet.
      replay(proxy, "account/chatgptAuthTokens/refresh", {});
      proxy.result(request, { userAgent: "synthetic" });
      return true;
    }
    if (request.method !== "turn/start") return false;
    for (const method of ["item/commandExecution/requestApproval", "item/fileChange/requestApproval", "execCommandApproval", "applyPatchApproval",
      "item/permissions/requestApproval", "mcpServer/elicitation/request", "item/tool/requestUserInput", "item/tool/call",
      "account/chatgptAuthTokens/refresh", "attestation/generate", "fixture/unknownInheritedTool"]) {
      for (const params of [{ threadId: config.threadId }, { conversationId: config.threadId }, {}, null,
        { threadId: "case-agent-thread", conversationId: config.threadId }, { threadId: config.threadId, conversationId: "case-agent-thread" }]) {
        replay(proxy, method, params);
      }
    }
    proxy.result(request, { turn: { id: "turn-fixture", status: "inProgress", items: [] } });
    queueMicrotask(() => server.complete(proxy));
    return true;
  };
  assert.deepEqual(await bridge.request(EVENT), REPLY);
  assert.equal(server.wire.some((packet) => typeof packet.id === "string" && ignored.has(packet.id)), false);
  assert.equal(server.calls("turn/start").length, 1);
  assert.equal(server.calls("thread/goal/clear").length, 0);
});
for (const method of ["execCommandApproval", "applyPatchApproval"]) linuxTest(`Codex declines owned legacy ${method} scoped by conversationId`, async (context) => {
  const { bridge, server } = await fixture(context);
  server.custom = (request, proxy) => {
    if (request.method !== "turn/start") return false;
    proxy.send({ id: "owned-legacy-approval", method, params: { conversationId: "case-agent-thread", command: "synthetic private command" } });
    return true;
  };
  assert.deepEqual(await bridge.request(EVENT), { eventId: EVENT.eventId, revision: EVENT.revision,
    action: { type: "needs-permission", reason: "agent-approval-required" } });
  const response = server.wire.find((packet) => packet.id === "owned-legacy-approval");
  assert.deepEqual(response?.result, { decision: { denied: { rejection: "agent-approval-required" } } });
});
linuxTest("Codex ambiguous thread creation failure leaves an intent and refuses a duplicate thread creation", async (context) => {
  const { bridge, config, server } = await fixture(context);
  server.custom = (request, proxy) => {
    if (request.method !== "thread/start") return false;
    proxy.send({ id: request.id, error: { message: "fixture private diagnostic" } }); return true;
  };
  await assert.rejects(bridge.preflight(), code("agent-unavailable"));
  const intent = JSON.parse(await readFile(path.join(config.stateDirectory, "codex-thread-intent.json"), "utf8")) as Wire;
  assert.equal(intent.version, 1);
  await bridge.close();
  const next = new CodexAgentBridge(config, { spawn: server.spawn, validate: async () => ({ uid: 4242, currentUid: 4242, home: "/home/fixtureuser" }) });
  context.after(() => next.close());
  await assert.rejects(next.preflight(), code("agent-unavailable"));
  assert.equal(server.calls("thread/start").length, 1);
});
linuxTest("Codex rejects a supposedly fresh thread that identifies inherited parent history", async (context) => {
  const { bridge, server } = await fixture(context);
  server.custom = (request, proxy) => {
    if (request.method !== "thread/start") return false;
    server.settings = request.params as Wire;
    const response = server.resumeResult();
    proxy.result(request, { ...response, thread: { ...(response.thread as Wire), forkedFromId: "registered-parent" } });
    return true;
  };
  await assert.rejects(bridge.preflight(), code("agent-invalid-response"));
  assert.equal(server.calls("turn/start").length, 0);
  assert.equal(server.calls("thread/fork").length, 0);
});
linuxTest("Codex refuses a changed or corrupt dedicated-thread receipt", async (context) => {
  const { bridge, config, server } = await fixture(context);
  await bridge.preflight(); await bridge.close();
  await writeFile(path.join(config.stateDirectory, "codex-thread.json"), "{fixture-corrupt", { mode: 0o600 });
  const next = new CodexAgentBridge(config, { spawn: server.spawn, validate: async () => ({ uid: 4242, currentUid: 4242, home: "/home/fixtureuser" }) });
  context.after(() => next.close());
  await assert.rejects(next.preflight(), code("agent-unavailable"));
  assert.equal(server.calls("thread/start").length, 1);
});
linuxTest("Codex leaves an active registered parent untouched and refuses a busy decision thread", async (context) => {
  const { bridge, server } = await fixture(context);
  server.parentStatus = "active";
  await bridge.preflight();
  assert.equal(server.calls("thread/start").length, 1);
  assert.equal(server.calls("thread/fork").length, 0);
  assert.equal(server.calls("thread/resume").every(call => (call.params as Wire).threadId !== "registered-parent"), true);
  server.childStatus = "active";
  await assert.rejects(bridge.request(EVENT), code("agent-busy"));
  assert.equal(server.calls("turn/start").length, 0);
});
linuxTest("Codex rejects overlapping case requests without queuing extra model work", async (context) => {
  const { bridge, server } = await fixture(context, { timeoutMs: 100 });
  server.autoComplete = false;
  const first = bridge.request(EVENT);
  await assert.rejects(bridge.request({ ...EVENT, eventId: "33333333-3333-4333-8333-333333333333" }), code("agent-busy"));
  await assert.rejects(first, code("agent-timeout"));
  assert.equal(server.calls("turn/start").length, 1);
});
linuxTest("Codex deadline terminates only the proxy, never a model turn or scanner", async (context) => {
  const { bridge, server } = await fixture(context, { timeoutMs: 30 });
  server.autoComplete = false;
  await assert.rejects(bridge.request(EVENT), code("agent-timeout"));
  assert.deepEqual(server.proxies[0]!.killed, ["SIGTERM"]);
  assert.equal(server.wire.some((item) => item.method === "turn/interrupt" || item.method === "turn/steer" || item.method === "command/exec"), false);
});
linuxTest("Codex item completion alone cannot acknowledge a delivery", async (context) => {
  const { bridge, server } = await fixture(context, { timeoutMs: 30 });
  server.autoComplete = false;
  server.custom = (request, proxy) => {
    if (request.method !== "turn/start") return false;
    proxy.result(request, { turn: { id: "turn-fixture", status: "inProgress", items: [] } });
    proxy.send({ method: "item/completed", params: { threadId: "case-agent-thread", turnId: "turn-fixture",
      item: { type: "agentMessage", id: "message-fixture", phase: "final_answer", text: JSON.stringify(REPLY) } } }); return true;
  };
  await assert.rejects(bridge.request(EVENT), code("agent-timeout"));
});
for (const terminal of ["failed", "interrupted", "inProgress"]) linuxTest(`Codex rejects ${terminal} turn completion`, async (context) => {
  const { bridge, server } = await fixture(context); server.terminal = terminal;
  await assert.rejects(bridge.request(EVENT), code("agent-invalid-response"));
});
for (const reply of [
  { ...REPLY, eventId: "different-event" }, { ...REPLY, revision: 99 }, { ...REPLY, privatePath: "/fixture/private" },
  { ...REPLY, action: { type: "retry", jobId: "unknown-job" } }, { ...REPLY, action: { type: "delete" } },
  { ...REPLY, action: { type: "needs-permission", reason: "free-form-error" } }, "not-json",
]) linuxTest(`Codex rejects unbound or malformed agent reply ${JSON.stringify(reply)}`, async (context) => {
  const { bridge, server } = await fixture(context); server.reply = reply;
  await assert.rejects(bridge.request(EVENT), code("agent-invalid-response"));
});
for (const method of ["item/commandExecution/requestApproval", "item/fileChange/requestApproval", "execCommandApproval", "applyPatchApproval", "item/permissions/requestApproval", "mcpServer/elicitation/request", "item/tool/requestUserInput", "item/tool/call", "fixture/unknownInheritedTool"]) linuxTest(`Codex declines ${method} and reports a fixed permission reason`, async (context) => {
  const { bridge, server } = await fixture(context);
  server.custom = (request, proxy) => {
    if (request.method !== "turn/start") return false;
    // Deliberately request approval before replying to turn/start.
    proxy.send({ id: "approval-fixture", method, params: { threadId: "case-agent-thread", command: "fixture private command" } }); return true;
  };
  assert.deepEqual(await bridge.request(EVENT), { eventId: EVENT.eventId, revision: EVENT.revision,
    action: { type: "needs-permission", reason: "agent-approval-required" } });
  const refusal = server.wire.find((item) => item.id === "approval-fixture")!;
  assert.ok(refusal);
  assert.equal(JSON.stringify(refusal).includes("accept"), false);
  assert.equal(JSON.stringify(refusal).includes("approved"), false);
  assert.equal(JSON.stringify(refusal).includes("fixture private command"), false);
});
linuxTest("Codex rejects raw paths, error strings, and extra event fields before spawning", async (context) => {
  const { bridge, server } = await fixture(context);
  for (const event of [{ ...EVENT, source: "/fixture/private" }, { ...EVENT, reason: "fixture raw error" },
    { ...EVENT, jobs: [{ ...EVENT.jobs[0], source: "/fixture/private" }] }, { ...EVENT, caseId: "/fixture/private" }]) {
    await assert.rejects(bridge.request(event as AgentEvent), code("agent-invalid-response"));
  }
  assert.equal(server.spawns.length, 0);
});
linuxTest("Codex enforces the request budget and preserves idempotent replies", async (context) => {
  const { bridge, server } = await fixture(context, { maxRequests: 1 });
  await bridge.request(EVENT);
  assert.deepEqual(await bridge.request(EVENT), REPLY);
  await assert.rejects(bridge.request({ ...EVENT, eventId: "33333333-3333-4333-8333-333333333333" }), code("agent-request-limit"));
  assert.equal(server.calls("turn/start").length, 1);
});
linuxTest("Codex protocol errors and unexpected exits remain fixed, redacted failures", async (context) => {
  const { bridge, server } = await fixture(context);
  server.custom = (request, proxy) => { if (request.method !== "initialize") return false; proxy.stdout.write("fixture-private-non-json\n"); return true; };
  await assert.rejects(bridge.preflight(), code("agent-invalid-response"));
  assert.equal(server.calls("turn/start").length, 0);
});
linuxTest("Codex rejects broad effective permissions instead of falling back", async (context) => {
  const { bridge, server } = await fixture(context);
  server.custom = (request, proxy) => {
    if (request.method !== "thread/start") return false;
    server.settings = request.params as Wire;
    proxy.result(request, { ...server.resumeResult(), sandbox: { type: "dangerFullAccess" } }); return true;
  };
  await assert.rejects(bridge.preflight(), code("agent-unavailable"));
  assert.equal(server.calls("turn/start").length, 0);
});
linuxTest("Codex state directory must remain private", async (context) => {
  const { bridge, config } = await fixture(context);
  await bridge.preflight(); await bridge.close();
  await chmod(config.stateDirectory, 0o755);
  const next = new CodexAgentBridge(config, { validate: async () => ({ uid: 4242, currentUid: 4242, home: "/home/fixtureuser" }),
    spawn: () => { assert.fail("No proxy should spawn for an unprotected state directory"); } });
  context.after(() => next.close());
  await assert.rejects(next.preflight(), code("agent-unavailable"));
});
linuxTest("Codex binding validation requires canonical executable, private owned Unix socket, and approved roots", async (context) => {
  const { config } = await fixture(context);
  let change: Partial<CodexFileIdentity> = {};
  let changedPath = "";
  const inspection: CodexBindingInspection = { platform: "linux", currentUid: 0,
    accounts: async () => "fixtureuser:x:4242:4242:Fixture:/home/fixtureuser:/bin/bash\n",
    inspect: async (filename) => ({ canonical: filename, uid: filename === "/usr/sbin/runuser" ? 0 : 4242,
      kind: filename === config.socketPath ? "socket" : filename === config.executable || filename === "/usr/sbin/runuser" ? "file" : "directory",
      mode: filename === config.socketPath ? 0o600 : 0o755, ...(filename === changedPath ? change : {}) }),
  };
  assert.equal((await validateCodexAgentConfig(config, inspection)).uid, 4242);
  for (const [filename, mutation] of [[config.socketPath, { uid: 999 }], [config.socketPath, { mode: 0o666 }],
    [config.socketPath, { kind: "file" }], [config.executable, { canonical: "/different/codex" }],
    [config.executable, { mode: 0o777 }], [config.readableRoots[0]!, { canonical: "/different/root" }]] as Array<[string, Partial<CodexFileIdentity>]>) {
    changedPath = filename; change = mutation;
    await assert.rejects(validateCodexAgentConfig(config, inspection), code("agent-unavailable"));
  }
});

test("Codex event and reply validators accept only fixed enums and exact fields", () => {
  assert.deepEqual(validateAgentEvent(EVENT), EVENT);
  assert.deepEqual(validateAgentReply(REPLY, EVENT), REPLY);
  assert.throws(() => validateAgentReply({ ...REPLY, action: { type: "acknowledge", command: "fixture" } }, EVENT), code("agent-invalid-response"));
});
