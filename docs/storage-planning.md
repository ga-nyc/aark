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

## File-backed local workspaces

A Linux filesystem inside a new workspace file can reduce small-file allocation
overhead without reformatting its hosting disk. For example, an ext4 workspace
with 4 KiB blocks can use substantially less space for millions of small carved
files than a hosting exFAT filesystem with 256 KiB allocation units. Choose both
the workspace size and its inode count for the expected file count. Unknown
carving output still requires headroom.

AARK accepts an already mounted loop-backed workspace only when it can trace
every block-device parent to physical disks. `losetup` from `util-linux` supplies
the kernel backing-file inode and filesystem device; the canonical single-link
regular file must match both. The binding includes file size, offset, size limit,
and host mount identity. Network filesystems/transports, deleted or replaced
backing paths, unknown parent branches, cycles, and inaccessible identities are
refused. An output container on the source disk remains on the source disk and
fails the independence check.
An ext4 workspace also cannot hide an unsupported NTFS3 host from output-driver
checks. Carving follow-ups reject shared container views and backing files
stored inside the other case.

Recovery and mining enforce the configured free-space reserve on the mounted
workspace and on every filesystem hosting its loop backing files. The case's
logical output cap applies to case outputs, not to container sizes. Binding
checks continue during execution and are frozen into mining resume controls and
cleanup approval tokens. Output writes may change backing-file timestamps;
replacement, resizing, re-offsetting, or remounting invalidates the binding.

AARK does not create, format, resize, or mount workspace containers. Prepare a
new dedicated file on the authorized destination with enough host headroom,
then assess the mounted destination before starting recovery. Preallocating the
container makes its host cost visible before carving. Keep it mounted and
preserve the file while any case, mining result, or retained source inside it is
still needed. Formatting a new workspace file never authorizes formatting the
hosting disk. Older AARK versions cannot resume or clean up scans that use the
new loop-binding identities.

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

For an existing evidence image, forecasts distinguish logical file growth from
remaining disk allocation. Filling sparse holes can require physical free space
without increasing the image's logical length or its charge against the case cap.

A preflight refusal can still leave the case terminal-failed. Preserve completed
outputs and use the normal fresh-destination rules; do not edit case controls to
force a retry.

## Restart carving on a separate destination

When extraction completed but a later engine failed, a fresh case can reuse the
existing unallocated stream instead of repeating imaging and `blkls`. Set
`unallocatedStreamFromCase` to the earlier case's absolute path, keep the same
authorized `source`, and use a separate, non-overlapping `destination`. Enable
`signatureCarving` and disable `unallocatedStream`; disable other stages unless
they are intentionally part of the new run. For example:

```json
{
  "version": 1,
  "caseId": "carving-followup",
  "source": "/dev/disk/by-id/your-authorized-source-partition",
  "destination": "/mnt/another-disk/carving-followup",
  "unallocatedStreamFromCase": "/mnt/recovery/earlier-case",
  "requireReadOnlySource": true,
  "execute": false,
  "storage": { "minFreeGiB": 20, "minFreePercent": 5 },
  "image": { "enabled": false },
  "stages": {
    "deletedMetadata": false,
    "ntfsUndelete": false,
    "unallocatedStream": false,
    "signatureCarving": true
  }
}
```

Run `recover assess --config ...` and `recover plan --config ...` first, then use
the normal two execution confirmations. The assessment remains read-only. It
checks that the earlier run is terminal, its controls match their per-run copies,
and both sensitive and redacted results record a successful `blkls -A` extraction.
An arbitrary image, incomplete extraction, foreign source, symlink, hard link,
or active operation lock cannot serve as the reused stream.

Execution holds both recovery compatibility locks in the earlier case. It checks
the stream's frozen file identity, size, timestamps, local mount, and controls
throughout the new run. Those checks detect changes after validation; they do not
establish a historical content hash for a legacy extraction. A source-case lock
must be writable, but its recovery data and terminal reports remain untouched.
The new case has its own reserve, cap, logs, and progress. Carving output size
remains unknown: enough space for the raw input does not promise enough space for
reconstructed files. Existing partial outputs may already exceed the capacity of
a proposed replacement destination.

The earlier case must not contain nested mounts, including mounts over its
control directories. Different mount views of the same filesystem are rejected
when they could hide overlap between the cases; ordinary sibling case directories
on one mount remain supported. These topology checks also run while carving.
Because acquiring the earlier case's operation locks writes to that filesystem,
execution requires a supported output driver there too: NTFS3 is rejected before
any lock is created. Read-only assessment can still inspect an NTFS3 case.

This starts PhotoRec again in fresh output directories. It does not resume an
interrupted PhotoRec session, move old outputs, delete data, or turn the earlier
failed case into a successful one. A completed follow-up records the earlier
case's status in `reusedUnallocatedStream`; cleanup requirements are unchanged.

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

Older outputs may have no progress snapshot; use their redacted manifests and
final reports instead. Existing cleanly paused scans remain resumable under the
normal checks. Older AARK revisions can reject a new progress file as an unknown
control, so use this or a newer compatible revision to resume new outputs.

Recovery writes progress at stage transitions, approximately every five seconds
while an engine runs, and at terminal status. It reports stage, elapsed time,
physical headroom, reserve, cached logical-size measurement and its timestamp,
and the next-stage forecast. On Linux, engine-process read/write counters and CPU
ticks show observed activity between samples. Descendant work is not included;
unavailable counters remain null. Process liveness and activity are not a
completion percentage or proof that the engine will finish. Progress writes run
independently of case-size accounting and use the existing protected case writer.
Terminal quota snapshots retain the redacted storage-stop reason and byte counts;
paused mining snapshots retain whether the cause was a signal, reserve, or cap.

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
