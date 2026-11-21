import assert from "node:assert/strict";
import { access, mkdir, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { loadCaseConfig } from "../case/config.js";
import { mkdtemp } from "./helpers.js";

const symlinks = {skip: process.platform === "win32"};
async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-case-alias-test-"));
  const protectedRoot = path.join(root, "protected");
  const publicRoot = path.join(root, "public");
  await mkdir(protectedRoot);
  await mkdir(publicRoot);
  const alias = path.join(root, "alias");
  await symlink(protectedRoot, alias, "dir");
  const workflowFile = path.join(root, "workflow.json");
  const workflow = {version: 1, execute: true, output: path.join(root, "output"),
    scans: [{inputs: [alias], provenance: "unknown"}], mining: {workers: 1}};
  await writeFile(workflowFile, JSON.stringify(workflow));
  const filename = path.join(root, "case.json");
  const config = {version: 1, execute: true, control: path.join(root, "control"),
    jobs: [{id: "job-000001", dependsOn: [], attempts: [workflowFile], resumeAfterQuota: false}],
    agent: {ownership: "dedicated-thread", executable: "/usr/bin/codex", socketPath: path.join(root, "codex.sock"),
      threadId: "synthetic-parent-thread", user: "syntheticuser", readableRoots: [protectedRoot]}};
  await writeFile(filename, JSON.stringify(config));
  return {root, protectedRoot, publicRoot, alias, workflowFile, workflow, filename, config};
}

test("case admission rejects a canonical agent root exposing an aliased protected scan input", symlinks, async () => {
  const f = await fixture();
  await assert.rejects(loadCaseConfig(f.filename), /read roots overlap protected case data/);
  await assert.rejects(access(f.config.control));
  await assert.rejects(access(f.workflow.output));
});

test("case admission protects future outputs beneath an existing alias", symlinks, async () => {
  const f = await fixture();
  await writeFile(f.workflowFile, JSON.stringify({...f.workflow, output: path.join(f.alias, "future", "output"),
    scans: [{inputs: [f.publicRoot], provenance: "unknown"}]}));
  await assert.rejects(loadCaseConfig(f.filename), /read roots overlap protected case data/);
  await assert.rejects(access(path.join(f.protectedRoot, "future")));
});

test("case admission protects configuration files reached through an aliased directory", symlinks, async () => {
  const f = await fixture();
  const actualWorkflow = path.join(f.protectedRoot, "workflow.json");
  await writeFile(actualWorkflow, JSON.stringify({...f.workflow, scans: [{inputs: [f.publicRoot], provenance: "unknown"}]}));
  await writeFile(f.filename, JSON.stringify({...f.config, jobs: [{...f.config.jobs[0], attempts: [path.join(f.alias, "workflow.json")]}]}));
  await assert.rejects(loadCaseConfig(f.filename), /read roots overlap protected case data/);
});

test("case admission still accepts public roots separate from protected aliases and future outputs", symlinks, async () => {
  const f = await fixture();
  await writeFile(f.filename, JSON.stringify({...f.config, agent: {...f.config.agent, readableRoots: [f.publicRoot]}}));
  const prepared = await loadCaseConfig(f.filename);
  assert.deepEqual(prepared.agent.readableRoots, [f.publicRoot]);
  await assert.rejects(access(f.config.control));
  await assert.rejects(access(f.workflow.output));
});

test("case admission rejects dangling aliases in future protected output paths", symlinks, async () => {
  const f = await fixture();
  const dangling = path.join(f.root, "dangling");
  const target = path.join(f.protectedRoot, "not-created");
  await symlink(target, dangling, "dir");
  await writeFile(f.workflowFile, JSON.stringify({...f.workflow, output: path.join(dangling, "output"),
    scans: [{inputs: [f.publicRoot], provenance: "unknown"}]}));
  await assert.rejects(loadCaseConfig(f.filename), /symbolic-link output component/);
  await assert.rejects(access(target));
});
