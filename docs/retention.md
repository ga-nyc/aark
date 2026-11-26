# Preserve findings before retiring a source

A completed scan proves its selected byte coverage and artifact integrity. It
does not copy every whole finding-containing source file, back up ordinary
personal data, or authorize erasing the source. The workflow package contains
exact finding artifacts; allocated-reference and residual-memory originals can
still reside on the disk you intend to reinstall.

`aark retain` creates a separate, opt-in export from an explicit selection of
error-free completed native mining outputs. It copies their controls and exact
artifacts without rewriting them, and the union of every complete source file
referenced by a finding occurrence. Marker-only findings require their whole
source file too. Duplicate source references share one retained copy.

## Review the selection and space

Select the native mining directories, including any allocated-reference or
memory scans that reference the media being retired. A workflow's native scan
directories are its `mining/scan-NNNNNN/` children. Selecting a subset proves
preservation only for that subset; there is no automatic whole-case or whole-disk
coverage claim. Failed, paused, interrupted, or error-bearing scans are refused.

```sh
aark retain plan /mnt/results/mining-allocated /mnt/results/mining-memory \
  --destination /mnt/backup/retained-case-001
```

The plan creates no export and prints aggregate counts, logical source bytes,
and a plan token, without local paths, recovered values, or content hashes.
Execution requires a fresh destination on independently verified physical
storage, separate from the selected original input/source storage. Existing
mining outputs may share the destination disk, but their directories must remain
distinct and untouched. Network, unresolved, same-source-disk, and unsafe
overlapping destinations are refused. The
first release supports Linux; Windows volume identity alone does not establish
separate physical disks.

Directory input roots must stay on one mount: nested mounts beneath a selected
directory are refused, including mounts containing only files without findings.
The first release accepts ext2/3/4, FAT/exFAT, and NTFS with known local
drivers, and applies that policy to every loop host too. It refuses XFS (whose data or log devices may be external), Btrfs, ZFS,
bcachefs, and unknown filesystem types because block-device ancestry alone does
not prove their complete physical membership. Block-level md and LVM remain
supported when their ancestry resolves completely. Existing output-driver
restrictions still apply.
Ext filesystems also require read-only access to the mounted block device for a
fixed 1024-byte superblock check proving the journal is internal or absent.
External journal fields, journal mount overrides, unavailable metadata access,
and unknown formats are refused, including on loop hosts. The layout and
external-journal distinction follow the [kernel superblock documentation](https://www.kernel.org/doc/html/latest/filesystems/ext4/super.html)
and [journal documentation](https://www.kernel.org/doc/html/latest/filesystems/ext4/journal.html).

A finding inside a large raw stream, archive, or memory container requires a
copy of that entire file. This can require terabytes even when the exported
finding is small. Allow physical allocation overhead and retain the free-space
reserve, which cannot be lowered below 5 GiB and 5 percent. Higher reserves and
an optional `--max-output-gib` cap are supported. The tool does not certify drive
hardware health; use healthy destination storage.

## Export and verify

```sh
aark retain run /mnt/results/mining-allocated /mnt/results/mining-memory \
  --destination /mnt/backup/retained-case-001 \
  --plan-token <TOKEN> --execute
aark retain verify --bundle /mnt/backup/retained-case-001
```

Run repeats the native completion and unchanged-input checks and holds the
current and compatibility mining locks while copying. Source selection,
controls, destination identity, and storage policy must still match the plan.
Files are streamed to exclusive new destinations, flushed, reopened, and hashed
independently. Sources and original mining controls remain untouched. An error,
quota stop, or interruption leaves an incomplete export rather than declaring
success or overwriting an earlier attempt; use a fresh destination for a new
reviewed attempt.

The private retention manifest maps the copied controls, findings, and whole
source files to their bundle locations and integrity records. The redacted
manifest reports only aggregates. Treat the bundle and private manifest as
sensitive recovered material. Keep them out of model-readable roots and do not
upload them or validate their contents with online services.

Bundle verification works independently of the original source paths. It checks
the copied control relationships, exact artifact tree, source mappings, expected
file set, and every retained file's content hash. Missing, extra, changed, or
unsafe files prevent successful verification. Native scan controls retain their
original absolute paths and seals: the export does not relocate a scan in place
or make its copied controls an ordinary resumable scan. Export hashes attest the
copy made under the frozen-input checks; they are not historical whole-file
hashes from the original mining run.
Local export receipts record the physical independence checked at export time;
offline verification does not retest original hardware. Integrity hashes do not
authenticate a bundle against someone able to rewrite its entire contents and
manifest.

## Before erasing media

Verify the export, establish that the selected scans cover every AARK source
file on the intended disk, and separately decide whether ordinary documents or
other data must also be backed up. Preserve case-level recovery reports and
supervision controls separately when needed. Retention export is not a full disk
image, filesystem backup, secure-erasure procedure, or permission to wipe.

Original media erasure, reinstalling an operating system, and recovery-case
cleanup remain separate operations. They require their own exact disk or cleanup
plan and end-user decision. `retain` never deletes, repairs, formats, or changes
the read-only state of a source. Existing [cleanup](cleanup.md) approval and
whole-source retention checks remain unchanged.
