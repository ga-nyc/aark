import { createHash } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { readDirectoryNamesBounded, readJson, stableLstat, walkRegularFiles } from "../core/fs-safe.js";
import { mountForPathFrom, mountIsNetworkBacked, mounts, outputLoopBinding, protectedMountBacking } from "../core/mounts.js";
import { MAX_RECORDED_OCCURRENCES, MAX_SENSITIVE_INVENTORY_BYTES, MAX_UNIQUE_FINDINGS } from "../mining/limits.js";
import { loadCompletedInventory, loadScanState, readScanManifest, verifyResumeArtifacts } from "../mining/resume.js";
import { realpath } from "node:fs/promises";
import { inspectSourceSafety } from "../recovery/source-safety.js";
import { loadWorkflowConfig, MAX_WORKFLOW_CONFIG_BYTES, type WorkflowConfig, type WorkflowScan } from "../workflow/config.js";
import { workflowStatus } from "../workflow/runner.js";
import { controlIdentity, fileDigest, miningDirectory, outputIdentity, samePath, workflowSourceIdentity } from "../workflow/verify.js";
import type { CompletionProof, PreparedAttempt } from "./types.js";
import { assertSourceBindings, CaseSourceIdentityError } from "./sources.js";
import { runCaseProbe } from "./probe.js";

const hash = (value: string) => createHash("sha256").update(value).digest("hex");
interface Artifact {path: string; bytes: number; sha256: string}
interface Finding {category: string; fingerprint: string; confidence: string; artifacts: Artifact[]; scans: number[]}

export async function verifyPreparedAttempt(configFile: string, configHash: string): Promise<PreparedAttempt> {
  if (!path.isAbsolute(configFile) || !/^[a-f0-9]{64}$/u.test(configHash)) throw new Error("invalid workflow configuration binding");
  const workflow = await loadWorkflowConfig(configFile);
  if (hash(JSON.stringify(workflow)) !== configHash || !workflow.execute) throw new Error("workflow configuration binding changed");
  return {configFile, configHash, workflow};
}

async function assertAbsent(filename: string): Promise<void> {
  try { await stableLstat(filename); }
  catch (error) { if (error instanceof Error && "code" in error && error.code === "ENOENT") return; throw error; }
  throw new Error("workflow completion has an operation lock");
}

/** Bounded metadata-only snapshot, including empty/deep directory entry changes. */
async function sourceSnapshot(scan: WorkflowScan, output: string, state: Awaited<ReturnType<typeof loadScanState>>): Promise<string> {
  const snapshot = createHash("sha256");
  const remember = (kind: string, value: unknown): void => { snapshot.update(JSON.stringify([kind, value]) + "\n"); };
  const records = await mounts();
  const backings = new Map<string, ReturnType<typeof protectedMountBacking>>();
  const backing = async (filename: string) => {
    const mounted = mountForPathFrom(records, filename);
    if (mounted === undefined || await mountIsNetworkBacked(mounted)) throw new Error("workflow completion lost its local mount");
    const key = JSON.stringify(mounted);
    let pending = backings.get(key);
    if (pending === undefined) { pending = protectedMountBacking(mounted); backings.set(key, pending); }
    return await pending;
  };
  if (state.outputLoopBinding !== outputLoopBinding(await backing(output))) throw new Error("workflow scan output binding changed");
  for (const root of state.inputRoots) {
    const current = await stableLstat(root.path);
    const mount = (await backing(root.path)).identity;
    if (current.device !== root.device || current.inode !== root.inode || current.raw.isSymbolicLink()
      || (root.kind === "file" ? !current.raw.isFile() : !current.raw.isDirectory()) || !samePath(await realpath(root.path), root.path)
      || mount !== root.mount) throw new Error("workflow scan input root changed");
    remember("root", [root.path, root.kind, current.device, current.inode, current.bytes,
      current.raw.mtimeNs.toString(), current.raw.ctimeNs.toString(), mount]);
  }
  const currentFiles = walkRegularFiles(scan.inputs, {onError: () => { throw new Error("workflow completion coverage walk failed"); },
    shouldEnterDirectory: async directory => {
      const current = await stableLstat(directory);
      if (!current.raw.isDirectory() || current.raw.isSymbolicLink() || !samePath(await realpath(directory), directory)) throw new Error("workflow scan input directory changed");
      remember("directory", [directory, current.device, current.inode, current.bytes,
        current.raw.mtimeNs.toString(), current.raw.ctimeNs.toString(), (await backing(directory)).identity]);
      return true;
    }})[Symbol.asyncIterator]();
  try {
    for await (const file of readScanManifest(output, state.manifest)) {
      const current = await currentFiles.next();
      if (current.done || !isDeepStrictEqual({...current.value, index: file.index}, file) || !samePath(await realpath(file.path), file.path)) throw new Error("workflow scan input coverage changed");
      remember("file", current.value);
    }
    if (!(await currentFiles.next()).done) throw new Error("workflow scan has unscanned inputs");
  } finally { await currentFiles.return?.(undefined); }
  return snapshot.digest("hex");
}

/** Separate read-only proof: unlike native verifyScan, this never acquires operation locks. */
async function verifyReadOnlyScan(config: WorkflowConfig, scan: WorkflowScan, index: number) {
  const output = miningDirectory(config, index);
  const seals = await Promise.all(["scan-state-sensitive.json", "inventory-sensitive.json", "scan-files-sensitive.ndjson"].map(async name => {
    const filename = path.join(output, name);
    return {filename, identity: await controlIdentity(filename)};
  }));
  const proof = await fileDigest(path.join(output, "scan-state-sensitive.json"), 16 * 1024 ** 2);
  const state = await loadScanState(output);
  const semantic = {inputs: scan.inputs, output, provenance: scan.provenance, chunkBytes: config.mining.chunkMiB * 1024 ** 2,
    overlapBytes: config.mining.overlapMiB * 1024 ** 2, wholeFileBytes: config.mining.wholeFileMiB * 1024 ** 2,
    deepKeySchedules: config.mining.deepKeySchedules, cryptoOnly: config.mining.cryptoOnly};
  if (!isDeepStrictEqual(state.semantic, semantic) || state.status !== "complete" || state.resumable || !state.inventoryComplete
    || state.progress.scanErrors !== 0 || state.progress.filesScanned !== state.manifest.entries || state.progress.filesVisited !== state.manifest.entries
    || state.cursor.fileIndex !== state.manifest.entries || state.cursor.phase !== "stream" || state.cursor.nextOffset !== 0) throw new Error("workflow scan coverage is not complete");
  const inventory = await loadCompletedInventory(output, state.inventory);
  const checkpoint = {runId: state.runId, status: state.status, inventoryComplete: state.inventoryComplete, semantic: state.semantic,
    inputRoots: state.inputRoots, ...(state.outputLoopBinding === undefined ? {} : {outputLoopBinding: state.outputLoopBinding}),
    manifest: state.manifest, cursor: state.cursor, progress: state.progress};
  if (inventory.status !== "complete" || inventory.complete !== true || inventory.errors.length + inventory.errorsOmitted !== 0
    || !isDeepStrictEqual(inventory.resumeCheckpoint, checkpoint) || !isDeepStrictEqual(inventory.inputRoots, scan.inputs)
    || inventory.outputRoot !== output || inventory.findings.length !== state.progress.uniqueFindings
    || inventory.findings.reduce((sum, finding) => sum + finding.occurrences.length, 0) !== state.progress.occurrences) throw new Error("workflow scan inventory disagrees");
  for (const finding of inventory.findings) for (const occurrence of finding.occurrences) {
    if (occurrence.provenance !== scan.provenance || !state.inputRoots.some(root => root.kind === "file"
      ? samePath(root.path, occurrence.sourcePath) : occurrence.sourcePath.startsWith(root.path + path.sep))) throw new Error("workflow occurrence escaped its inputs");
  }
  const snapshot = await sourceSnapshot(scan, output, state);
  await verifyResumeArtifacts(output, inventory);
  if (!isDeepStrictEqual(await fileDigest(path.join(output, "scan-state-sensitive.json"), 16 * 1024 ** 2), proof)) throw new Error("workflow scan proof changed");
  for (const seal of seals) if (await controlIdentity(seal.filename) !== seal.identity) throw new Error("workflow scan controls changed");
  return {state, inventory, proof, seals, verifySources: async () => {
    if (await sourceSnapshot(scan, output, state) !== snapshot) throw new Error("workflow completion source snapshot changed");
  }};
}

/** Strictly read-only case evidence, never cleanup authorization. Host must prove engine inactivity. */
export async function verifyCompletedWorkflow(attempt: PreparedAttempt): Promise<CompletionProof> {
  const checked = await verifyPreparedAttempt(attempt.configFile, attempt.configHash);
  if (!isDeepStrictEqual(checked.workflow, attempt.workflow)) throw new Error("workflow configuration binding changed");
  const config = checked.workflow;
  const seals = new Map<string, string>();
  const digest = async (filename: string, limit: number) => {
    const before = await controlIdentity(filename);
    const result = await fileDigest(filename, limit);
    const after = await controlIdentity(filename);
    if (before !== after) throw new Error("workflow completion input changed while hashing");
    seals.set(filename, after);
    return result;
  };
  const lockPaths = [path.join(config.output, ".aark-workflow.lock"),
    ...config.scans.flatMap((_, index) => [".aark-mining.lock", ".agetnic-mining.lock"].map(name => path.join(miningDirectory(config, index), name))),
    ...(config.recovery === undefined ? [] : [".aark-recovery.lock", ".agetnic-recovery.lock"].map(name => path.join(config.recovery!.destination, name)))];
  for (const filename of lockPaths) await assertAbsent(filename);
  const output = await outputIdentity(config.output, config.finalizationStorage, false);
  const statePath = path.join(config.output, "workflow-state-sensitive.json");
  const checkpointPath = path.join(config.output, "workflow-checkpoint-redacted.json");
  const stateDigest = await digest(statePath, 16 * MAX_WORKFLOW_CONFIG_BYTES);
  const checkpointDigest = await digest(checkpointPath, 4096);
  const state = await readJson<Record<string, unknown>>(statePath, 16 * MAX_WORKFLOW_CONFIG_BYTES);
  const checkpoint = await readJson<Record<string, unknown>>(checkpointPath, 4096);
  if (state.version !== 1 || state.tool !== "aark" || state.layer !== "workflow" || state.status !== "complete" || state.phase !== "complete"
    || state.configFile !== attempt.configFile || !isDeepStrictEqual(state.config, config) || state.outputIdentity !== output
    || checkpoint.version !== 1 || checkpoint.status !== "complete" || checkpoint.stateSha256 !== stateDigest.sha256
    || !Array.isArray(state.completedScans) || state.completedScans.length !== config.scans.length
    || state.scansVerified !== config.scans.length || !Number.isSafeInteger(state.finalizationAttempt) || Number(state.finalizationAttempt) < 1
    || Number(state.finalizationAttempt) > 999999) throw new Error("workflow has no valid sealed completion");
  if (config.recovery !== undefined) {
    await outputIdentity(config.recovery.destination, {minFreeGiB: 0, minFreePercent: 0}, false);
    const recoveryPath = path.join(config.recovery.destination, "case-sensitive.json");
    const proof = await digest(recoveryPath, 16 * 1024 ** 2);
    if (!isDeepStrictEqual(proof, state.recoveryProof)) throw new Error("workflow completed recovery changed");
    const recovery = await readJson<Record<string, unknown>>(recoveryPath, 16 * 1024 ** 2);
    const safety = await inspectSourceSafety(config.recovery.source, config.recovery.destination);
    if (!["complete", "complete-with-warnings"].includes(String(recovery.status)) || !safety.safe
      || workflowSourceIdentity(safety) !== state.recoverySafety) throw new Error("workflow completed recovery changed");
    const sources = [config.recovery.source];
    if (config.recovery.analysisSource !== undefined && config.recovery.analysisSource !== config.recovery.source
      && !(config.recovery.image.enabled && samePath(config.recovery.analysisSource, config.recovery.image.path))) sources.push(config.recovery.analysisSource);
    const identities: string[] = [];
    for (const source of sources) {
      const current = await inspectSourceSafety(source, config.output);
      if (!current.safe) throw new Error("workflow results binding changed");
      identities.push(workflowSourceIdentity(current));
    }
    if (!isDeepStrictEqual(identities, state.resultsSafety)) throw new Error("workflow results binding changed");
  } else if (!isDeepStrictEqual(state.resultsSafety, [])) throw new Error("workflow results binding changed");

  const findings = new Map<string, Finding>();
  const artifacts = new Map<string, Artifact>();
  const scanProofs: Array<{bytes: number; sha256: string}> = [];
  const verifySources: Array<() => Promise<void>> = [];
  let filesVerified = 0, bytesScanned = 0, findingsAcrossScans = 0, references = 0;
  for (let index = 0; index < config.scans.length; index++) {
    const scan = config.scans[index]!;
    const directory = miningDirectory(config, index);
    await outputIdentity(directory, config.mining.storage, false);
    const verified = await verifyReadOnlyScan(config, scan, index);
    verifySources.push(verified.verifySources);
    if (!isDeepStrictEqual(verified.proof, state.completedScans[index])) throw new Error("workflow completed scan proof changed");
    for (const seal of verified.seals) seals.set(seal.filename, seal.identity);
    scanProofs.push(verified.proof);
    filesVerified += verified.state.progress.filesScanned;
    bytesScanned += verified.state.progress.bytesScanned;
    findingsAcrossScans += verified.inventory.findings.length;
    if (!Number.isSafeInteger(filesVerified) || !Number.isSafeInteger(bytesScanned)) throw new Error("workflow completion aggregate overflow");
    for (const finding of verified.inventory.findings) {
      const key = finding.category + ":" + finding.sha256;
      let entry = findings.get(key);
      if (entry === undefined) {
        if (findings.size >= MAX_UNIQUE_FINDINGS) throw new Error("workflow completion finding limit reached");
        entry = {category: finding.category, fingerprint: finding.sha256, confidence: finding.confidence, artifacts: [], scans: []};
        findings.set(key, entry);
      }
      if (++references > MAX_RECORDED_OCCURRENCES) throw new Error("workflow completion reference limit reached");
      entry.scans.push(index + 1);
      for (const artifact of finding.artifactIntegrity) {
        const identity = artifact.sha256 + ":" + artifact.bytes;
        let exported = artifacts.get(identity);
        if (exported === undefined) {
          const extension = path.extname(artifact.path);
          const basename = `artifact-${String(artifacts.size + 1).padStart(6, "0")}${/^\.[a-zA-Z0-9]{1,12}$/u.test(extension) ? extension : ".bin"}`;
          exported = {path: basename, bytes: artifact.bytes, sha256: artifact.sha256};
          artifacts.set(identity, exported);
        }
        if (!entry.artifacts.some(value => value.path === exported.path)) entry.artifacts.push(exported);
      }
    }
  }
  const packageName = `finalization-${String(state.finalizationAttempt).padStart(6, "0")}`;
  const packageRoot = path.join(config.output, packageName);
  const packageIdentity = await outputIdentity(packageRoot, config.finalizationStorage, false);
  const indexPath = path.join(packageRoot, "index-sensitive.json");
  const manifestPath = path.join(packageRoot, "manifest-redacted.json");
  const rootManifestPath = path.join(config.output, "manifest-redacted.json");
  const indexDigest = await digest(indexPath, MAX_SENSITIVE_INVENTORY_BYTES);
  const manifestDigest = await digest(manifestPath, MAX_SENSITIVE_INVENTORY_BYTES);
  const rootManifestDigest = await digest(rootManifestPath, MAX_SENSITIVE_INVENTORY_BYTES);
  const packaged = await readJson<unknown>(indexPath, MAX_SENSITIVE_INVENTORY_BYTES);
  const expectedIndex = {version: 1, tool: "aark", layer: "workflow-findings", status: "complete",
    findingIdentity: "category-and-content-fingerprint", originalSourcesAndMiningOutputsRetained: true,
    scans: config.scans.map((_, index) => ({number: index + 1, output: miningDirectory(config, index)})), findings: [...findings.values()]};
  if (!isDeepStrictEqual(packaged, expectedIndex)) throw new Error("workflow packaged index differs from verified scans");
  const summary = await readJson<Record<string, unknown>>(manifestPath, MAX_SENSITIVE_INVENTORY_BYTES);
  const rootSummary = await readJson<unknown>(rootManifestPath, MAX_SENSITIVE_INVENTORY_BYTES);
  const categories: Record<string, number> = {};
  for (const finding of findings.values()) categories[finding.category] = (categories[finding.category] ?? 0) + 1;
  if (typeof summary.finishedAt !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u.test(summary.finishedAt)) throw new Error("invalid workflow completion timestamp");
  const expectedSummary = {version: 1, tool: "aark", layer: "workflow-finalization", status: "complete", sourcePathsRedacted: true,
    finishedAt: summary.finishedAt, scansVerified: config.scans.length, filesScanned: filesVerified, bytesScanned,
    scanCountsMayOverlap: true, findingsAcrossScans, distinctFindingFingerprints: findings.size,
    findingIdentity: "category-and-content-fingerprint; not a count of accounts or independently usable keys",
    artifactFilesVerified: artifacts.size, categories, originalSourcesAndMiningOutputsRetained: true, cleanupAuthorized: false, packageDirectory: packageName,
    // Legacy packages predate these advisory fields. When present, all sealed
    // copies must agree and may only disclaim whole-source copying and erasure.
    ...(Object.hasOwn(summary, "wholeFindingSourcesCopiedByWorkflow") ? {wholeFindingSourcesCopiedByWorkflow: false} : {}),
    ...(Object.hasOwn(summary, "sourceErasureAuthorized") ? {sourceErasureAuthorized: false} : {})};
  if (!isDeepStrictEqual(summary, expectedSummary) || !isDeepStrictEqual(rootSummary, expectedSummary)
    || !isDeepStrictEqual(state.summary, expectedSummary)) throw new Error("workflow packaged summary differs from verified scans");
  const packagedProofs = [];
  for (const artifact of artifacts.values()) {
    const proof = await digest(path.join(packageRoot, artifact.path), 256 * 1024 ** 2);
    if (proof.bytes !== artifact.bytes || proof.sha256 !== artifact.sha256) throw new Error("workflow packaged artifact integrity failed");
    packagedProofs.push(proof);
  }
  const expectedNames = [...artifacts.values()].map(artifact => artifact.path).concat("index-sensitive.json", "manifest-redacted.json").sort();
  if (!isDeepStrictEqual((await readDirectoryNamesBounded(packageRoot, expectedNames.length + 1)).sort(), expectedNames)) throw new Error("workflow package contains unexpected entries");
  // Artifact hashing can be lengthy. Recheck the complete source/entry snapshot
  // afterward, streaming the existing bounded manifest rather than retaining or
  // hashing original source contents. Final control seals still cover this pass.
  for (const verify of verifySources) await verify();
  for (const filename of lockPaths) await assertAbsent(filename);
  for (const [filename, expected] of seals) if (await controlIdentity(filename) !== expected) throw new Error("workflow completion inputs changed during verification");
  if (!isDeepStrictEqual(await fileDigest(statePath, 16 * MAX_WORKFLOW_CONFIG_BYTES), stateDigest)
    || await outputIdentity(config.output, config.finalizationStorage, false) !== output
    || await outputIdentity(packageRoot, config.finalizationStorage, false) !== packageIdentity) throw new Error("workflow completion binding changed");
  await verifyPreparedAttempt(attempt.configFile, attempt.configHash);
  return {sha256: hash(JSON.stringify({stateDigest, checkpointDigest, scanProofs, indexDigest, manifestDigest, rootManifestDigest, packagedProofs})),
    scansVerified: config.scans.length, filesVerified};
}

// A separate disposable process isolates blocked destination reads from the case worker.
if (process.argv[1] !== undefined && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  await runCaseProbe(async () => {
    try {
      const [operation, filename, configHash, bindings] = process.argv.slice(2);
      if (operation === "status" && filename !== undefined) process.stdout.write(JSON.stringify(await workflowStatus(filename)) + "\n");
      else if ((operation === "verify" || operation === "binding") && filename !== undefined && configHash !== undefined) {
        const attempt = await verifyPreparedAttempt(filename, configHash);
        if (operation === "binding" && bindings !== undefined) await assertSourceBindings(attempt.workflow, JSON.parse(bindings));
        process.stdout.write(JSON.stringify(operation === "verify" ? await verifyCompletedWorkflow(attempt) : {valid: true}) + "\n");
      } else throw new Error();
    } catch (error) {
      if (error instanceof CaseSourceIdentityError) {
        process.stdout.write('{"valid":false,"reason":"source-identity-changed"}\n');
        process.exitCode = 2;
      } else {
        process.stdout.write(JSON.stringify({status: "unknown"}) + "\n");
        process.exitCode = 1;
      }
    }
  });
}
