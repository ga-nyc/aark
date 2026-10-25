# Workflow backlog

## WFL-001: scan completed outputs after a later recovery failure

Status: deferred follow-up. Storage assessment, next-stage capacity checks, and
redacted progress reporting should land first.

A supervisor can currently stop the entire recovery-and-mining workflow when a
later recovery engine fails. Preserve the truthful failed or interrupted recovery
status while allowing independently authorized mining of immutable outputs from
completed stages. `mine scan` already accepts those directories; the missing work
is dependable orchestration and coverage reporting.

Acceptance criteria:

- Select inputs from verified stage results and declared outputs, rather than
  directory existence or process exit alone.
- Distinguish completed outputs from partial carving results. Require explicit
  selection of partial results and label their recovery coverage incomplete.
- Establish that selected engines and their descendants are inactive, and that
  inputs remain stable before freezing each mining manifest.
- Support a separate local mining destination with its own validated mount,
  reserve, and output budget.
- Report recovery stages and mining scans independently. A successful scan must
  not relabel failed recovery as complete or imply whole-source coverage.
- Resume only cleanly paused mining scans through existing integrity checks.
  Failed or interrupted scans require fresh outputs.
- Preserve read-only source protection, offline processing, redacted automation
  output, and separate cleanup approval. Do not weaken cleanup eligibility for a
  failed recovery case.
- Add synthetic tests for successful metadata recovery followed by carving quota
  failure, missing or changed outputs, active writers, mining capacity pauses,
  and truthful aggregate coverage reporting.

## WFL-002: keep live monitoring from stalling bulk carving

Status: live snapshot publication implemented; accounting and supervision follow-ups remain.

Recovery previously published live progress approximately every five seconds
through the durable case writer. That writer synchronizes the temporary file and containing
directory. NTFS-3G implements both file and directory fsync by synchronizing the
whole backing device. During bulk carving this can make a small status update
wait for unrelated recovery writes, blocking the userspace filesystem service
and the engine's next filesystem operation. A live inspection observed the AARK
progress worker waiting in FUSE fsync, NTFS-3G waiting in block-device fsync, and
PhotoRec waiting for FUSE while the drive completed small writes with second-scale
latencies. This establishes a shared flush bottleneck; it does not establish the
drive firmware, recording technology, hardware health, or the share of total
runtime attributable to progress publication.

The independent logical-cap guard also repeatedly enumerates the growing case
tree. That is additional metadata work on the same destination. Measure its
cost separately rather than assuming it explains the observed flush stall.

Acceptance criteria:

- Give informational running snapshots protected atomic publication without a
  per-update durability flush. Preserve single-link, symlink, directory, mount,
  and lock identity checks. Keep durable publication for authoritative state,
  checkpoints, manifests, artifacts, terminal reports, and terminal snapshots.
  Document that running snapshots may be stale or absent after a crash and never
  authorize resume, success, coverage, or cleanup.
- Coalesce pending progress updates and bound their resource use. A blocked
  publisher must not accumulate concurrent writes or imply engine advancement.
- Measure full-tree accounting duration and metadata work; design bounded or
  incremental accounting without weakening logical caps or physical free-space
  reserves. A fresh completed measurement must still gate stage acceptance.
- Let supervisors report probe timeouts and last known activity from a separate
  local filesystem. A destination status read must not block the supervisor
  indefinitely. Distinguish stale size accounting, observed engine I/O, and
  verified scan coverage; CPU ticks or active PIDs are not completion proof.
- Add synthetic tests for publication without running-snapshot fsync, retained
  terminal/control durability, path substitution, blocked progress publication,
  independent capacity enforcement, and truthful stale/timeout reporting.
- Benchmark the same synthetic many-file workload with and without the change
  on NTFS-3G and a native Linux filesystem. Report engine byte advancement,
  metadata operations, flush counts/latencies, and accounting duration. Do not
  promise an ETA improvement from source review alone.

Implemented: running recovery and mining snapshots now share protected atomic
publication without per-update file/directory sync. Authoritative outputs and
terminal snapshots retain durability. Regression tests cover flush behavior,
terminal durability, and link protections. `scripts/benchmark-progress.mjs`
provides a bounded synthetic comparison with both publication orders.

Sources: [NTFS-3G fsync implementation](https://github.com/tuxera/ntfs-3g/blob/edge/src/ntfs-3g.c#L2773),
[Linux writeback throttling interface](https://kernel.org/doc/html/latest/admin-guide/abi-stable.html).
