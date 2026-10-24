# Storage assessment and progress

Before starting a recovery, inventory the source and destination, establish the
case authorization, then assess the enabled stages:

```bash
aark recover assess --config recovery-case.json
aark recover plan --config recovery-case.json --assess-storage
```

Assessment is read-only. It does not create the destination, run a recovery
engine, change a source's read-only state, or lower a reserve. Recovery assessment
requires Linux. The ordinary `recover plan` command still works without access to
the configured media unless `--assess-storage` is supplied.

## What an estimate means

The report contains decimal-string byte counts for the source, destination free
space, reserve, filesystem-reported allocation unit, and configured logical cap.
Known new bulk outputs are added together because they coexist:

| Output | Estimate |
| --- | --- |
| Evidence image | Source size, rounded to the destination allocation unit |
| Unallocated stream | NTFS free clusters times cluster size when a directly addressable source can be probed |
| Recovered metadata files | Unknown; multiple engines may retain overlapping copies |
| Signature carving | Unknown; reconstructed and overlapping candidates can exceed input size |
| Other engine outputs and control/log overhead | Not bounded by this assessment |

`ntfsinfo --mft` from `ntfs-3g` supplies the optional NTFS estimate. No force flag
is used. Missing tools, unsupported filesystems, nonzero partition offsets,
invalid geometry, timeouts, and explicitly different analysis views produce an
unknown estimate. They never become a zero-byte requirement.

`knownMinimumFits: true` means only the known bulk minimum fits current headroom
and the logical cap. `fullWorkflowFits` remains `unknown`. The report estimates
new outputs, not an existing case's resume footprint. A known shortfall produces
`insufficient-for-known-outputs`; `recover assess` then exits with code `2`.
Keep the assessment separate from the frozen execution plan and resume controls.

Logical bytes and physical space are different constraints. Many small files on
a filesystem with large allocation units can consume far more disk space than
their combined lengths. The reserve is physical headroom; the case cap counts
logical sizes. Neither is a complete forecast of the remaining workflow.

## Checks before each stage

Recovery refreshes available space and records the next stage's known additional
bulk requirement. A known non-resumable write that exceeds remaining headroom or
the logical cap is rejected before that engine starts. For example, an NTFS
unallocated stream can be refused before creating a large partial copy.

Unknown-sized stages retain runtime quota enforcement; their forecasts explicitly
contain null estimates and fit decisions. They are not silently declared safe.
GNU ddrescue retains its existing mapfile-based quota pause and verified retry
contract, even when its forecast shows insufficient headroom. No new automatic
resume contract is introduced for other engines.

A preflight refusal can still leave the case terminal-failed. Preserve completed
outputs and use the normal fresh-destination rules; do not edit case controls to
force a retry.

## Local progress

```bash
aark recover status --case /mnt/recovery/case-001
aark mine status --output /mnt/results/mining-001
```

These commands read only a bounded `progress-redacted.json`, validate its header,
and return a fixed set of aggregate fields. They never open sensitive inventories
or reveal artifacts. Unknown fields in an edited snapshot are omitted. A status
snapshot is informational and does not authorize cleanup or prove checkpoint
integrity.

Recovery writes progress at stage transitions, approximately every five seconds
while an engine runs, and at terminal status. It reports stage, elapsed time,
physical headroom, reserve, cached logical-size measurement and its timestamp,
and the next-stage forecast. On Linux, engine-process read/write counters and CPU
ticks show observed activity between samples. Descendant work is not included;
unavailable counters remain null. Process liveness and activity are not a
completion percentage or proof that the engine will finish. Progress writes run
independently of case-size accounting and use the existing protected case writer.

`recover run` also emits aggregate progress on stderr; use `--quiet` to suppress
that stream. Its stdout remains the final JSON result.

Mining updates progress during inventory and at committed work boundaries, at
most once every five seconds, plus forced terminal updates. It reports phase,
file/byte counts, findings, errors, and output headroom. A long detector operation
may leave the last committed snapshot unchanged; an old timestamp alone does not
prove a kernel or process stall. These small control files are charged to the
normal output budget and use the existing reserved-space terminal-report path.

If the destination or lock becomes untrustworthy, AARK refuses further progress
writes along with its other protected output. Preserve all partial results and
inspect the local state; do not weaken identity or resume checks.

## Related backlog

See [WFL-001 in the workflow backlog](backlog.md) for independently scanning
completed outputs after a later recovery stage fails. That orchestration change
is separate from storage assessment and progress reporting.
