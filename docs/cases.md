# Persistent case supervision

`aark case` is an opt-in Linux supervisor for a reviewed collection of
[workflows](workflows.md). It keeps durable job state, reconciles systemd engine
units after a supervisor restart, and asks a restricted Codex bridge about
bounded redacted events. The usual `recover`, `mine`, and `workflow` commands
remain deterministic local commands; installing AARK does not start a daemon or
enable model access.

The native engines continue to read and validate evidence locally. The agent
bridge receives fixed reason codes, opaque job identifiers, attempt counts, and
event revisions. It must not receive recovered values, source paths, sensitive
controls, tool logs, or arbitrary exception messages. Agent use is a separate
explicit choice: it may involve the configured Codex service, even though the
forensic engines themselves remain offline.

## Review and initialize

Start with [the case example](../examples/case.example.json). Each job names one
or more existing workflow configuration files. Review every workflow, its
recovery configuration when present, selected media, destination, reserves, and
scope before authorizing the case. All paths must be canonical absolute paths.
Job identifiers use the fixed `job-000001` format, so human labels cannot leak
through agent events.

Each entry in `attempts` is a separately approved workflow with a distinct fresh
output. The first entry is the initial attempt; subsequent entries are the only
fresh attempts the agent may select after a failure. Listing a second attempt
authorizes that exact plan, not arbitrary changes to the first plan. Do not put
the failed output path into another attempt. A successful follow-up preserves
the original failure and does not make the original output cleanup-eligible.

Jobs with no dependency can continue independently when another job fails.
`dependsOn` lists job IDs that must have verified completion before the dependent
job may start. Cycles and unknown dependencies are invalid. Use `maxConcurrent`
to bound simultaneous engine jobs; each workflow retains its native worker cap.
When a decision requires permission, the case holds new launches while existing
engine units continue. A consumer that references an old failed producer output
requires a new reviewed plan even if another producer attempt succeeds elsewhere.

Use a private persistent control directory on a healthy local filesystem,
separate from evidence and workflow outputs. Production hosting rejects volatile
or unsuitable backing storage. Keep the configuration, installed executable,
service definitions, and the Codex socket protected from untrusted writes. Do
not copy the control directory into a model workspace or reset it to repeat an
agent event: its journal and launch tokens are part of restart reconciliation.

```sh
aark workflow plan --config /etc/aark/carved-workflow.json
# Review every workflow and recovery plan, then enable their JSON execute flags.
aark case plan --config case.json
# After reviewing the case plan, set execute=true in the case configuration.
sudo aark case init --config case.json --execute
sudo aark case run --control /var/lib/aark/case-001 --autonomous --execute
```

Create the control directory's protected parent first if it is absent, for
example `sudo install -d -m 0700 /var/lib/aark`. Initialization requires a fresh
case directory and will not adopt an existing one.

Initialization requires both `execute: true` in the case and the CLI `--execute`
confirmation. Every listed workflow must also authorize execution; recovery
configurations additionally require their own execution flag and
`requireReadOnlySource: true`. A plan or an
invalid configuration creates no control directory and starts no engine. Case
execution additionally requires the explicit `--autonomous` option. Changes to
frozen configurations are detected rather than silently adopted.

Initialization pins the original recovery media and external analysis views.
Fresh jobs and retries compare those identities at the native engine's source
baseline. Raw sources bind the kernel boot identity and disk sequence of the
source and its underlying devices, plus exact partition start/size geometry, so kernel-observed media replacement fails
closed even if the device name and capacity are unchanged. Missing generations,
a reboot, and legacy raw checkpoints without this binding require local review
and new authorization. This cannot attest a physical change the driver has not
reported. Inputs that will be produced by an approved dependency remain
subject to that producer's exact verified attempt and native launch checks.
Device-mapper sources additionally require Python 3.7 or newer. A bounded Python
stdlib helper uses a read-only kernel ioctl to fingerprint the active mapping
table without a child command. It disables process dumpability before fetching
the table, including for piped crash collectors. Raw table and key bytes never
reach case reports, logs, or agent packets. The digest binds exported table
parameters, including literal keys and offsets; opaque kernel key references are
bound as references and do not attest non-exported key contents.

## Process host and restricted agent

Production execution requires root on Linux, systemd 254 or newer, and Node.js
22.12 or newer. Case execution uses systemd to keep engine jobs independent of the
supervisor process. Launch identities and idempotency tokens are persisted so a
restart attaches to the reviewed engine attempt instead of creating a duplicate.
Allow the supervisor to reconcile a launch whose reply was lost; do not remove
its state or start the workflow manually in the same output.

Install the built CLI, Node executable, and packaged `scripts/notify-local.py`
under canonical root-owned paths whose parent directories are protected from
other users' writes. A user-owned development checkout cannot host a privileged
case. The control filesystem must persist beyond the live session's RAM layer
and be independent of a raw recovery source. Use healthy storage; filesystem
validation does not certify hardware health. Recovered trees and image files
may share a healthy destination filesystem outside the protected source trees.

`case run` checks the configured user's desktop notification channel before
starting services. The worker restarts after a process failure; a separate
30-second systemd timer detects worker death, stale heartbeats, degraded work,
and required permission. Recoverable job failures remain visible in case status
while the bounded agent decision is pending; they do not produce a desktop
failure notice solely because a retry decision is outstanding. Agent timeout,
unavailable transport, exhausted requests, or a permission hold trigger that
notice. Desktop acceptance and human acknowledgement are
distinct. Failed deliveries retry the same durable event token. An observed
healthy interval closes a failure incident so a later failure alerts again;
continuous worker restart loops remain deduplicated. The notifier has a
45-second deadline and its watchdog service a 70-second deadline to accommodate
bounded desktop delivery, process startup, and worker observation. No watchdog
action stops, kills, or restarts a forensic engine. These transient systemd units
survive a worker restart, not a host reboot or lost live-session power.

Configure the bridge's absolute Codex executable, local socket, dedicated user,
and readable code roots before running the case. Set `ownership` to
`dedicated-thread`; `threadId` identifies the registered parent thread. The bridge
creates and persists a fresh dedicated supervisor-owned thread with no inherited
conversation or dynamic tools. The parent ID is only a local registration
association. It never resumes, steers, or interrupts the parent. Its read
allowlist must contain only the code or documentation needed for review. Keep
evidence, recovery outputs, sensitive controls, artifacts, credentials, and the
private case control directory outside that allowlist. A redacted event is the
only case data supplied to the agent. This bridge is not an unrestricted shell
and cannot approve cleanup or expand the authorized media or scope.

The bridge requests a unique named permission profile with a denied filesystem
root, minimal runtime reads, explicit code roots, and network access disabled;
it disables external tool integrations and declines approval requests. This
uses the experimental Codex app-server protocol and requires a compatible
server. Unsupported permissions or protocol responses fail visibly; they do
not fall back to broader access. See the upstream
[permission profile documentation](https://learn.chatgpt.com/docs/permissions).

The managed control socket uses WebSocket messages over the local Unix proxy;
no TCP listener is required. Configure the canonical physical socket path,
resolving the daemon's advertised symlink with `realpath` when necessary.
The bridge answers approval requests only for its own decision thread and
checks for an externally added or paused goal before every decision turn.

Only one agent request is pending at a time. Events carry stable IDs and state
revisions; stale replies cannot authorize execution in a newer case state.
Valid permission stops remain effective across unrelated revision changes.
Delivery retries and
the total number of agent requests are bounded. An unavailable agent or an
exhausted request budget is visible in case health, while independent authorized
engine work can continue. A transport failure is not an engine failure.

The allowed decisions are to acknowledge an event, select the next listed fresh
attempt, request a permitted clean quota resume, or identify a fixed reason that
requires user permission. New media, new plans, credentials, destructive work,
physical intervention, and scope changes require that permission. The bridge
cannot manufacture execution authorization from an agent reply.

## Observe, pause, and recover

```sh
sudo aark case status --control /var/lib/aark/case-001
sudo aark case pause --control /var/lib/aark/case-001 --execute
sudo aark case resume --control /var/lib/aark/case-001 --execute
```

A user pause changes the desired case state and prevents new engine launches.
It does not signal, stop, or kill an engine that is already running. Resuming the
case permits reconciliation and eligible launches again; it does not relabel a
failed native run as a clean pause. Supervisor shutdown closes the agent bridge
without killing engine units.

Set `resumeAfterQuota` to false unless automatic free-space resume is authorized.
When enabled, the supervisor waits for fresh destination and loop-host capacity
checks before requesting a resume decision. Waiting for space does not consume
model requests or launch attempts. Native checkpoint validation and storage
reserves still apply. An output-cap pause needs a new reviewed plan, since an
unchanged logical cap cannot be repaired by restarting the engine. Signal
pauses and failed or interrupted outputs do not become automatic quota retries.
Corrected failed work requires the next listed fresh attempt.
Recovery-phase free-space resumes require a native clean ddrescue pause, matching
run controls, an unchanged image and nonempty mapfile, protected source bindings,
and sufficient space at both workflow and recovery destinations. Mapfiles over
16 MiB leave readiness unknown and require local assessment.

Unknown or timed-out observations remain observation failures. They do not
establish that an engine failed, authorize a duplicate launch, or prove that its
output is complete. The case status distinguishes running work, degraded work,
unavailable observation, an outstanding agent request, and required permission.
Use its aggregate redacted status for routine monitoring rather than opening
sensitive workflow controls.

Recovery source-binding probes have a 120-second aggregate deadline; recovery
quota-readiness probes have a separate 360-second aggregate deadline. These
allow multiple bounded mapper queries without enlarging the configured
`probeTimeoutMs` for systemd and ordinary status checks. They are aggregate caps,
not a promise that every supported 1,024-mapper graph finishes within them.
Metadata timeout or unavailability leaves the same reviewed intent pending and
visible as an unknown observation rather than consuming a failed attempt.
Before submitting any absent-unit resume, the host checks quota readiness again,
including when an earlier submission outcome is uncertain. Native resume still
enforces the authoritative storage and checkpoint checks.

The watchdog allows the sequential binding-plus-readiness deadline and its
polling margin. The worker commits observations between readiness probes so a
queue of paused jobs does not extend that heartbeat window across the whole
case. A stopped worker is still detected from its systemd state independently
of heartbeat age.

## Completion and retention

An engine's progress file or successful process exit alone cannot complete a
job. The supervisor verifies its native completion proof first. All selected
jobs must have verified completion before the case writes its consolidated
`manifest-redacted.json` and `final-report-redacted.md` in the control directory.
The completion event is tracked separately from engine completion, so a model
delivery failure cannot disappear behind a successful scan. Agent acceptance
does not establish that a person acknowledged the result.

`completionDeliveredToAgent` records acceptance of the completion decision by
the agent. Desktop delivery is recorded separately in
`notification-status-redacted.json`, with `deliveryAccepted` and
`userAcknowledged: false`. Neither receipt grants cleanup authorization.

Case reports are aggregate supervision reports. Preserve every native workflow
output, proof, failure, and final package. A case report does not replace native
verification, create missing scan coverage, or authorize deletion. No case or
agent action approves cleanup automatically. The separate cleanup plan, exact
aggregate review, fresh end-user decision, approval token, and execution
confirmations remain required by [the operating guide](../AGENTS.md).
