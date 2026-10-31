# Automatic workflow completion

`aark workflow` is a deterministic local supervisor for an explicitly reviewed
recovery and mining configuration. One invocation runs the selected recovery,
all selected scans, integrity verification, deduplication, and final results
packaging. It requires no later agent turn to trigger finalization. It is not an
autonomous AI agent and does not select new media, reveal values, contact
providers, or approve cleanup.

Start from [the workflow example](../examples/workflow.example.json), review the
recovery configuration separately, and select the intended scan inputs and their
provenance. Paths must be absolute and canonical. The workflow output must be a
new directory outside every input and the recovery case. With `recoveryConfig`,
scan roots must lie within declared outputs of completed recovery stages and
use their producing stage's provenance. Omitting `recoveryConfig` runs the same
mining and finalization sequence against explicitly selected existing local
inputs; ensure those inputs have no active external writer.
Completion describes that explicit selection. The example selects only carved
files; add other declared outputs when those are part of the intended scan scope.

```sh
aark workflow plan --config workflow.json
# After reviewing the plan and authorization, set execute=true in both
# configurations when recoveryConfig is present.
sudo aark workflow run --config workflow.json --execute
```

Unattended work still needs a persistent local process host. If a terminal or
agent session may end, launch this one command under an existing supervisor such
as systemd and preserve the output directory. The supervisor must retain exit
code 75 as a pause and must not restart failed or interrupted work automatically.
The native workflow drives every configured success stage itself; it does not
depend on scheduling another agent turn after a child stage exits.

Execution retains the existing recovery confirmations, read-only source and
independent-destination checks, local mount and loop-backing validation, mining
worker limits, and native checkpoints. Recovery remains Linux-only; mining-only
workflows also use the supported native Windows volume checks.
The results destination receives its own source-safety preflight before any
workflow directory is created, and its binding is checked during execution.
An output container must also remain outside the recovery case it depends on.

There may be 1 through 128 selected scans, each with 1 through 128 native input
roots. Inputs may be directories: the native scanner freezes and streams their
file manifests without building an unbounded in-memory list. The workflow keeps
each scan's results in `mining/scan-NNNNNN/`. Bounded native walk, inventory,
finding, and occurrence limits still apply; divide larger selections into
reviewed smaller scans or independent workflows rather than bypassing them.
Final packaging limits the combined distinct findings to 10,000 and finding
references across scans to 20,000.

## Progress and completion

```sh
aark workflow status --output /mnt/results/workflow-001
```

The aggregate status distinguishes recovery, mining, verification, packaging,
and completion. It includes planned, completed, and verified scan counts and a
heartbeat during long operations, current-scan file/byte counters, verification
file counts, and redacted native recovery progress. `processObserved` describes process liveness,
not successful work; `needsReview` flags a saved running state without an
observed process. Redacted progress is not an integrity or cleanup approval.
`pauseReason` distinguishes a signal, free-space reserve, and output cap;
`nextAction` gives bounded guidance to monitor, resume, free space, review a cap,
inspect local controls, or review completed results.
Running snapshots use protected atomic publication without durability flushes,
with at most one heartbeat publication in flight. Checkpoints and terminal
snapshots remain durable, following the same publication contract as native
recovery and mining.

Only successful recovery permits automatic mining of its declared outputs.
Failed or interrupted recovery stays truthful and stops this workflow. The
separate [WFL-001 backlog item](backlog.md#wfl-001-scan-completed-outputs-after-a-later-recovery-failure)
covers selecting completed or partial outputs after a later recovery failure.

Completion is published only after all selected scans are exactly complete and
error-free, their checkpoints and inventories match, their frozen input trees
still match, and all referenced artifacts pass integrity checks. The supervisor
holds both current and compatibility recovery/mining locks while verifying and
packaging. The finalization stage creates a private `finalization-NNNNNN/`
directory containing:

- exact artifact copies, deduplicated by their recorded SHA-256 and size;
- `index-sensitive.json`, mapping category/content fingerprints to artifact
  copies and original scan outputs; and
- `manifest-redacted.json`, with aggregate counts and category totals.

The workflow root also receives `manifest-redacted.json` after finalization
passes. Original files and all native mining outputs remain in place. The
package is convenient for local review and backup; it does not replace original
evidence, full finding-containing source files, or native integrity controls.
Content fingerprints are not counts of accounts or independently usable keys,
and a detector match does not establish current account access or funds.
Secure sensitive output physically or with encryption when the destination
filesystem cannot enforce Unix file modes.

## Pauses, failures, and storage

A native clean mining pause, recovery's supported ddrescue quota pause, or a
clean interruption during verification/finalization returns status `paused` and
exit code 75. Resume the same reviewed configuration explicitly:

```sh
sudo aark workflow resume --output /mnt/results/workflow-001 --execute
```

Resume checks the workflow checkpoint, unchanged configuration, output binding,
completed recovery controls, completed scans, inputs, and artifacts. Only the
paused native scan resumes; completed scans do not rerun. A partial finalization
attempt is retained, and another attempt uses a new directory. Hard kills leave
operation locks for local review. A saved running or failed workflow cannot be
silently resumed, and locks are never removed automatically. A failed scan
requires a fresh reviewed output rather than relabeling it as a clean pause.

`mining.storage` applies its reserve and optional logical output cap separately
to each native scan. `finalizationStorage` applies its reserve and optional cap
to each packaging attempt. Recovery retains its own configuration's policy.
The default reserve is the larger of 5 GiB and 5%; reserves also apply to loop
hosts. Retained native outputs and partial attempts still consume filesystem
space. Configurations remain frozen on resume: free space to resolve a reserve
pause; an inadequate configured cap requires a newly reviewed workflow. The
supervisor never deletes data to make room or lowers a reserve automatically.

Cleanup remains a separate exact plan, fresh owner approval, and explicit
execution through `aark cleanup`. Workflow success neither approves deletion nor
proves whole-source recovery or structured coverage beyond the selected scans.
