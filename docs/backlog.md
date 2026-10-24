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
