import assert from "node:assert/strict";
import { access, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { loadCaseConfig } from "../case/config.js";
import { initializeCase } from "../case/store.js";
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

for (const target of ["workflow-config", "workflow-output", "control"] as const) {
  test(`case admission rejects unsupported systemd characters in ${target} paths before initialization`, symlinks, async context => {
    const f = await fixture();
    context.after(() => rm(f.root, {recursive: true, force: true}));
    f.config.agent.readableRoots = [f.publicRoot];
    if (target === "workflow-config") {
      const unsupported = path.join(f.root, "workflow%reviewed.json");
      await writeFile(unsupported, JSON.stringify(f.workflow));
      f.config.jobs[0]!.attempts = [unsupported];
    } else if (target === "workflow-output") {
      f.workflow.output = path.join(f.root, "output%reviewed");
      await writeFile(f.workflowFile, JSON.stringify(f.workflow));
    } else f.config.control = path.join(f.root, "control%reviewed");
    await writeFile(f.filename, JSON.stringify(f.config));
    await assert.rejects(loadCaseConfig(f.filename), /case paths.*unsupported/u);
    await assert.rejects(initializeCase(f.filename, {execute: true}), /case paths.*unsupported/u);
    await assert.rejects(access(f.config.control));
    await assert.rejects(access(f.workflow.output));
  });
}

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

test("case admission rejects an alias-hidden producer cycle before plan or initialization has effects", symlinks, async () => {
  const f = await fixture();
  const outputA = path.join(f.root, "outA");
  const outputB = path.join(f.protectedRoot, "outB");
  await writeFile(f.workflowFile, JSON.stringify({...f.workflow, output: outputA,
    scans: [{inputs: [path.join(f.alias, "outB", "input")], provenance: "unknown"}]}));
  const workflowB = path.join(f.root, "workflowB.json");
  await writeFile(workflowB, JSON.stringify({...f.workflow, output: outputB,
    scans: [{inputs: [path.join(outputA, "input")], provenance: "unknown"}]}));
  await writeFile(f.filename, JSON.stringify({...f.config,
    jobs: [f.config.jobs[0], {id: "job-000002", dependsOn: ["job-000001"], attempts: [workflowB], resumeAfterQuota: false}],
    agent: {...f.config.agent, readableRoots: [f.publicRoot]}}));
  await assert.rejects(loadCaseConfig(f.filename), /produced by another job require a successful dependency/);
  await assert.rejects(initializeCase(f.filename, {execute: true}), /produced by another job require a successful dependency/);
  for (const directory of [f.config.control, outputA, outputB]) await assert.rejects(access(directory));
});

test("case admission accepts an aliased producer input with its explicit dependency", symlinks, async () => {
  const f = await fixture();
  const source = path.join(f.root, "source");
  await mkdir(source);
  const outputA = path.join(f.protectedRoot, "outA");
  const outputB = path.join(f.root, "outB");
  await writeFile(f.workflowFile, JSON.stringify({...f.workflow, output: outputA,
    scans: [{inputs: [source], provenance: "unknown"}]}));
  const workflowB = path.join(f.root, "workflowB.json");
  await writeFile(workflowB, JSON.stringify({...f.workflow, output: outputB,
    scans: [{inputs: [path.join(f.alias, "outA", "input")], provenance: "unknown"}]}));
  await writeFile(f.filename, JSON.stringify({...f.config,
    jobs: [f.config.jobs[0], {id: "job-000002", dependsOn: ["job-000001"], attempts: [workflowB], resumeAfterQuota: false}],
    agent: {...f.config.agent, readableRoots: [f.publicRoot]}}));
  const prepared = await loadCaseConfig(f.filename);
  assert.deepEqual(prepared.jobs[1]!.dependsOn, ["job-000001"]);
  for (const directory of [f.config.control, outputA, outputB]) await assert.rejects(access(directory));
  const state = await initializeCase(f.filename, {execute: true});
  assert.equal(state.jobs.length, 2);
  for (const directory of [outputA, outputB]) await assert.rejects(access(directory));
});

test("case admission rejects control/source and same-workflow output/source aliases without effects", symlinks, async () => {
  const f = await fixture();
  const agent = {...f.config.agent, readableRoots: [f.publicRoot]};
  const aliasedControl = path.join(f.protectedRoot, "new-control");
  await writeFile(f.filename, JSON.stringify({...f.config, control: aliasedControl, agent}));
  await assert.rejects(initializeCase(f.filename, {execute: true}), /control overlaps/);
  await assert.rejects(access(aliasedControl));
  const aliasedOutput = path.join(f.protectedRoot, "new-output");
  await writeFile(f.workflowFile, JSON.stringify({...f.workflow, output: aliasedOutput}));
  await writeFile(f.filename, JSON.stringify({...f.config, agent}));
  await assert.rejects(initializeCase(f.filename, {execute: true}), /inputs and output.*non-overlapping/);
  for (const directory of [f.config.control, aliasedOutput]) await assert.rejects(access(directory));
});

test("case admission rejects separate output spellings resolving into the same producer tree", symlinks, async () => {
  const f = await fixture();
  const source = path.join(f.root, "source");
  await mkdir(source);
  const output = path.join(f.protectedRoot, "out");
  await writeFile(f.workflowFile, JSON.stringify({...f.workflow, output, scans: [{inputs: [source], provenance: "unknown"}]}));
  const workflowB = path.join(f.root, "workflowB.json");
  await writeFile(workflowB, JSON.stringify({...f.workflow, output: path.join(f.alias, "out", "nested"),
    scans: [{inputs: [source], provenance: "unknown"}]}));
  await writeFile(f.filename, JSON.stringify({...f.config,
    jobs: [f.config.jobs[0], {id: "job-000002", dependsOn: [], attempts: [workflowB], resumeAfterQuota: false}],
    agent: {...f.config.agent, readableRoots: [f.publicRoot]}}));
  await assert.rejects(initializeCase(f.filename, {execute: true}), /outputs must be independent non-overlapping/);
  for (const directory of [f.config.control, output]) await assert.rejects(access(directory));
});

test("case admission protects configuration/control and configuration/output overlaps reached through aliases", symlinks, async () => {
  const f = await fixture();
  const source = path.join(f.root, "source");
  await mkdir(source);
  const actualWorkflow = path.join(f.protectedRoot, "workflow.json");
  const workflow = {...f.workflow, scans: [{inputs: [source], provenance: "unknown"}]};
  await writeFile(actualWorkflow, JSON.stringify(workflow));
  const config = {...f.config, jobs: [{...f.config.jobs[0], attempts: [actualWorkflow]}],
    agent: {...f.config.agent, readableRoots: [f.publicRoot]}};
  await writeFile(f.filename, JSON.stringify({...config, control: f.alias}));
  await assert.rejects(loadCaseConfig(f.filename), /control overlaps/);
  await writeFile(actualWorkflow, JSON.stringify({...workflow, output: f.alias}));
  await writeFile(f.filename, JSON.stringify(config));
  await assert.rejects(initializeCase(f.filename, {execute: true}), /configurations must remain outside job outputs/);
  await assert.rejects(access(f.config.control));
  await assert.rejects(access(f.workflow.output));
});

test("case metadata planning permits an existing raw-source alias separate from all destinations", symlinks, async () => {
  const f = await fixture();
  const source = path.join(f.protectedRoot, "synthetic-device.img");
  const sourceAlias = path.join(f.root, "synthetic-by-id");
  await writeFile(source, "ordinary synthetic image\n");
  await symlink(source, sourceAlias, "file");
  const recovery = path.join(f.root, "recovery.json");
  const destination = path.join(f.root, "recovered");
  await writeFile(recovery, JSON.stringify({version: 1, caseId: "synthetic-alias", source: sourceAlias, destination,
    execute: true, requireReadOnlySource: true, image: {enabled: false},
    stages: {deletedMetadata: false, ntfsUndelete: false, unallocatedStream: true, signatureCarving: false,
      volumeShadows: false, residualMemory: false, deletedRegistryCells: false}}));
  await writeFile(f.workflowFile, JSON.stringify({...f.workflow, recoveryConfig: recovery,
    scans: [{inputs: [path.join(destination, "recovery", "unallocated", "free-space.raw")], provenance: "unallocated-stream"}]}));
  await writeFile(f.filename, JSON.stringify({...f.config, agent: {...f.config.agent, readableRoots: [f.publicRoot]}}));
  const prepared = await loadCaseConfig(f.filename);
  assert.equal(prepared.jobs[0]!.attempts[0]!.workflow.recovery!.source, sourceAlias);
  for (const directory of [f.config.control, f.workflow.output, destination]) await assert.rejects(access(directory));
});

test("case admission rejects a recovery source resolving inside its own destination", symlinks, async () => {
  const f = await fixture();
  const recovery = path.join(f.root, "recovery.json");
  await writeFile(recovery, JSON.stringify({version: 1, caseId: "synthetic-alias", source: path.join(f.alias, "source.img"),
    destination: f.protectedRoot, execute: true, requireReadOnlySource: true, image: {enabled: false},
    stages: {deletedMetadata: false, ntfsUndelete: false, unallocatedStream: true, signatureCarving: false,
      volumeShadows: false, residualMemory: false, deletedRegistryCells: false}}));
  await writeFile(f.workflowFile, JSON.stringify({...f.workflow, recoveryConfig: recovery,
    scans: [{inputs: [path.join(f.protectedRoot, "recovery", "unallocated", "free-space.raw")], provenance: "unallocated-stream"}]}));
  await writeFile(f.filename, JSON.stringify({...f.config, agent: {...f.config.agent, readableRoots: [f.publicRoot]}}));
  await assert.rejects(initializeCase(f.filename, {execute: true}), /recovery inputs and destination.*non-overlapping/);
  for (const directory of [f.config.control, f.workflow.output, path.join(f.protectedRoot, "recovery")]) await assert.rejects(access(directory));
});
