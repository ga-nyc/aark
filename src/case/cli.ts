import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { Command } from "commander";
import { casePlan, loadCaseConfig } from "./config.js";
import { CodexAgentBridge } from "./codex.js";
import { assertProductionCaseStorage, caseNotificationStatus, caseServiceUnit, startCaseService, watchCaseService } from "./service.js";
import { initializeCase, loadCaseState, redactedCaseStatus, requestCaseDesired } from "./store.js";
import { CaseSupervisor } from "./supervisor.js";
import { SystemdEngineHost } from "./systemd.js";

const CLI = fileURLToPath(new URL("../cli.js", import.meta.url));
const json = (value: unknown): void => { process.stdout.write(JSON.stringify(value, null, 2) + "\n"); };
function confirm(execute: boolean, autonomous = true): void {
  if (execute !== true) throw new Error("case operation requires --execute confirmation");
  if (autonomous !== true) throw new Error("case execution requires --autonomous confirmation");
}

export function registerCaseCommands(program: Command): void {
  const command = program.command("case").description("Explicitly opt into persistent Linux case supervision and a restricted redacted agent bridge");
  command.command("plan").requiredOption("--config <path>", "reviewed case JSON")
    .action(async (options: {config: string}) => json(casePlan(await loadCaseConfig(options.config))));
  command.command("init").requiredOption("--config <path>", "reviewed case JSON").option("--execute", "confirm initialization", false)
    .action(async (options: {config: string; execute: boolean}) => {
      confirm(options.execute);
      const config = await loadCaseConfig(options.config);
      await assertProductionCaseStorage(config);
      await initializeCase(options.config, {execute: options.execute});
      const loaded = await loadCaseState(config.control);
      json(redactedCaseStatus(loaded.config, loaded.state));
    });
  command.command("run").requiredOption("--control <directory>", "initialized private case control")
    .option("--autonomous", "enable restricted agent continuation and managed services", false).option("--execute", "confirm hosting", false)
    .action(async (options: {control: string; autonomous: boolean; execute: boolean}) => {
      confirm(options.execute, options.autonomous);
      json(await startCaseService(options.control, CLI));
    });
  command.command("status").requiredOption("--control <directory>", "private case control")
    .action(async (options: {control: string}) => {
      const {config, state} = await loadCaseState(options.control);
      json({...redactedCaseStatus(config, state), lastDesktopNotification: await caseNotificationStatus(options.control)});
    });
  for (const action of ["pause", "resume"] as const) command.command(action).requiredOption("--control <directory>", "private case control")
    .option("--execute", "confirm desired state change", false)
    .action(async (options: {control: string; execute: boolean}) => {
      confirm(options.execute);
      await requestCaseDesired(options.control, action === "pause" ? "user-paused" : "running");
      json({version: 1, requested: action === "pause" ? "user-paused" : "running", appliedBy: "next-supervisor-reconciliation", engineSignalsSent: false});
    });
  command.command("serve", {hidden: true}).requiredOption("--control <directory>", "private case control")
    .option("--autonomous", "confirm agent continuation", false).option("--execute", "confirm managed worker", false)
    .action(async (options: {control: string; autonomous: boolean; execute: boolean}) => {
      confirm(options.execute, options.autonomous);
      const {config, state} = await loadCaseState(options.control);
      await assertProductionCaseStorage(config);
      const groups = (await readFile("/proc/self/cgroup", "utf8")).trim().split("\n");
      if (!groups.some(line => line.endsWith("/" + caseServiceUnit(config.control)))) throw new Error("case serve requires its registered systemd worker");
      const host = new SystemdEngineHost({cliPath: CLI, controlRoot: config.control, probeTimeoutMs: config.probeTimeoutMs, sourceBindings: state.sourceBindings});
      const supervisor = await CaseSupervisor.open(config.control, {host, agent: new CodexAgentBridge(config.agent)});
      const controller = new AbortController();
      const stop = () => controller.abort();
      process.once("SIGTERM", stop); process.once("SIGINT", stop);
      try { await supervisor.run(controller.signal); }
      finally {
        process.removeListener("SIGTERM", stop); process.removeListener("SIGINT", stop);
        await supervisor.close();
      }
    });
  command.command("watch", {hidden: true}).requiredOption("--control <directory>", "private case control")
    .option("--execute", "confirm desktop delivery", false)
    .action(async (options: {control: string; execute: boolean}) => {
      confirm(options.execute);
      const result = await watchCaseService(options.control);
      json(result);
      if (result.deliveryAccepted === false) process.exitCode = 1;
    });
}
