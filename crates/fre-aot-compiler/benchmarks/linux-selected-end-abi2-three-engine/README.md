# Linux SelectedEnd ABI2 three-engine diagnostic

This source-only benchmark compares one exact 16-byte Search program through
three execution routes on a little-endian Linux/AArch64 Arm `0x41/0xd84` host:

1. the hidden identity-suffixed AOT entry, compiled offline and statically
   linked;
2. the byte-identical tag21 ABI2 image emitted at runtime and published through
   strict W^X; and
3. the portable preprocessed exact-literal plan.

It is diagnostic scaffolding, not promotion or deployment authority. The run
metadata and every result row say `promotion_authority=absent`, and the
deterministic P2b bundle itself says `runtime_authority=absent`. The generated
binding also contains the public lookup/fallback facade, but the runtime's
literal production table is empty; this benchmark deliberately uses the
separate qualification-private owner.

## Static AOT construction

`build.rs` deterministically runs
`plan_and_compile_linux_aarch64_selected_end_v2` and
`build_linux_selected_end_qualification_bundle_v2`, then passes that exact
bundle to `build_linux_selected_end_qualification_deployment_v2` for
`0123456789abcdef`. It writes the implementation object, canonical P2b
direct-glue object, expectation, receipts, header, and exact compiler-generated
deployment binding into Cargo's private `OUT_DIR`, then links the two objects
into this binary. The deployment binding is persisted separately from the
benchmark-only source/tree/path metadata and the consumer-loop adapter; the
benchmark does not render another FFI declaration or session
boundary.

Each hot sample enters one `inline(never)` engine-specific loop after the
timer starts, with engine selection outside that loop. The stable hidden AOT
loop symbol inlines the compiler-generated safe exact-entry function on every
iteration, so it adds one host boundary per sample rather than one AOT-only
boundary per searched value. The JIT and portable routes have the same
one-loop-boundary shape. The generated AOT body names the exact hidden
implementation entry directly and stores no function pointer, PLT target, ABI
x4 argument, or result slot. The compiler-generated raw proof callsite and
canonical P2b `stp/bl/ldp/ret` wrapper also stay linked; the wrapper is
exercised during correctness qualification but is not charged to the primary
AOT hot sample.

The AOT compiler and linker run before process start. Their cost is explicitly
`offline-excluded`; it is never folded into an AOT runtime-lifecycle sample.
JIT lifecycle rows include literal/KIR planning, tag21 ABI2 emission,
strict-WX publication, scalar preflight, session construction, and first call.
AOT lifecycle rows include literal planning, scalar preflight, session
construction, and first call. Portable lifecycle rows include literal planning,
scalar preflight, and first call.

Those three `stage=lifecycle` rows deliberately measure a common safe frontend,
not pure precompiled startup: the current architecture obtains its
non-forgeable window/resource certificate from a `LiteralPlan`. To expose the
other useful boundary without mislabeling it, each lifecycle command also emits
`stage=aot-activation`. That row prepares the authoritative plan/preflight
outside the timer and measures only AOT VL16 session activation plus the first
direct-entry call. It still excludes offline compiler and linker work.

## Thread and vector-length contract

Both native routes require OS-usable ASIMD, SVE, and SVE2 on the admitted
homogeneous Arm `0x41/0xd84` host class. The benchmark never changes the
calling thread's vector length.

The AOT route uses
`StaticSearchSelectedEndQualificationV2::begin_current_thread_session`; the
returned qualification-only static-runtime token is nominally distinct from a
source-qualified production token, is neither `Send` nor `Sync`, checks
features/tuning, and observes `PR_SVE_GET_VL == 16` once on the calling thread.
The separately named compiler-generated qualification bind consumes that
token, validates the exact literal once, and records the generated module's
hardcoded private compile-identity key in a field-private nominal session that
borrows only the external portable plan and qualification owner. There is no
safe conversion between production and qualification tokens. Nominal construction
discharges artifact identity; there is no runtime key comparison in the hot
path. This owning shape is storable without a self-reference. Repeated calls
check only issuing-plan identity before the exact direct symbol call. The JIT
route uses the runtime's independent non-transferable tag21 ABI2 session and
VL16 check, binds the same portable plan once at session creation, and likewise
uses plan provenance rather than literal bytes per call.

Hot cells construct and bind both sessions outside the timer and reuse one
authoritative scalar preflight token. Lifecycle and AOT-activation `session_ns`
include AOT thread admission plus the consuming exact-plan bind. Native hot
calls make no vector-length syscall, literal-byte comparison, artifact-pointer
comparison, or callable lookup.

## Semantics and timing

All three engines receive the same checked haystack/window and the same
`LiteralSearchPreflight`. Results use ABI2's `x0 = 0` miss or absolute match-end
encoding and are decoded against the exact window. A separate scalar
`windows(16)` oracle checks every fixture. Qualification covers present,
absent, dense filter near-misses, tail, included-window, excluded-window, and
four realized pointer alignments. The P2b wrapper is also compared in every
qualification case.

Hot samples calibrate to a target duration, warm every route, rotate all six
engine permutations by `repetition % 6`, retain CPU-affinity observations, and
consume match-dependent checksums. Warmup, calibration, and measurement all use
that repetition's order, so the route immediately preceding the first measured
route is balanced across the six permutations. Lifecycle warmup and samples use
the same six-order rotation and emit the individual plan, emit, publish,
preflight, session, and first-call stage totals.

Fixture alignment advances only after a complete six-order block:
`alignment = (repetition / 6) % 16`. A campaign must use a repetition count that
is a multiple of six; the canonical 96 repetitions cover the full
six-order-by-sixteen-alignment grid without correlating engine position with
alignment.

The runtime refuses unless its freshly emitted JIT artifact identity is exactly
the build-time AOT artifact identity. Rows bind source commit, source tree,
helper SHA-256, profile, artifact identity, compile identity, object identities,
and bundle identity.

## Deferred post-fence gates

No Cargo command or timing command was run while the resource-coordinator
admission fence was active. In particular, this nested workspace intentionally
does not yet have a generated `Cargo.lock`. It is not correct to claim
`--locked` build readiness until the following post-GO gates complete:

1. generate and review `Cargo.lock` without updating unrelated dependencies;
2. independently derive the source commit/tree and helper digest from the
   admitted clean checkout/helper, rather than accepting caller-provided labels;
3. build that exact source with the four required binding variables;
4. run `verify_post_link.py` against the final executable and the exact
   `OUT_DIR` implementation, glue, contract, generated binding, and deployment
   receipt paths;
5. run correctness qualification;
6. only then run controlled, source-bound hot and lifecycle cells.

Required build variables:

```text
FRE_ABI2_THREE_ENGINE_SOURCE_COMMIT=<40 lowercase hex>
FRE_ABI2_THREE_ENGINE_SOURCE_TREE=<40 lowercase hex>
FRE_ABI2_THREE_ENGINE_HELPER_SHA256=<64 lowercase hex>
FRE_ABI2_THREE_ENGINE_PROFILE=linux-target-cpu-local-v1
```

The binary's `metadata` command prints the exact object and contract paths for
the verifier. Invoke the verifier with isolated Python:

```text
python3 -I -B verify_post_link.py \
  --binary <exact-final-executable> \
  --implementation <metadata-implementation-object-path> \
  --glue <metadata-direct-glue-object-path> \
  --contract <metadata-post-link-contract-path> \
  --binding <metadata-deployment-binding-path> \
  --deployment-receipt <metadata-deployment-receipt-path> \
  --source-commit <exact-commit> \
  --source-tree <exact-tree>
```

The build roots both the payload and metadata symbols against section garbage
collection and explicitly retains the compiler proof and benchmark consumer
symbols. The verifier authenticates the exact generated binding and deployment
receipt, parses the original glue relocation and final ELF image from sealed
in-memory snapshots, and requires distinct nonzero extents for the exact
wrapper, entry, generated proof, and consumer-loop symbols. It
checks the glue's sole `R_AARCH64_CALL26`, the exact four-instruction wrapper,
the generated proof callsite, and the separately named consumer hot callsite.
The tiny generated proof must contain exactly one direct non-PLT `bl` to the
entry and no `blr` or x4. The actual timed consumer loop must contain one or
more direct calls, all to that exact entry, and no other host call, PLT target,
or `blr`; x4 is unconstrained there because rustc may legitimately use it as a
non-ABI loop scratch register. An unrelated direct call cannot satisfy either
symbol-bounded proof. The authenticated generated source, metadata, raw proof,
and P2b wrapper establish the four-argument/no-slot ABI. The verifier also
hashes the implementation and glue objects, cross-links the deployment
receipt's complete payload extent/digest, requires final entry/payload/metadata
bytes to equal the exact input extents, and rejects RWX load segments and an
executable stack. Observation schema v3 reports
`consumer_hot_callsite_final_observed=true` only after those checks. Runtime
and promotion authority remain absent.

## Fresh-process campaign and independent results verification

`run_campaign.py` is the bounded Linux/AArch64 campaign layer.
`verify_campaign.py` independently reads only its immutable evidence directory;
it does not import the runner. The runner performs one qualification process,
then one fresh process for each hot cell and one fresh process for each
lifecycle cell across all four sizes, all six scenarios, and every requested
repetition. The three engines remain together inside each process, so the
benchmark's six-order rotation remains paired.

Repetitions must be a multiple of six in `6..96`. A 96-repetition campaign is
the canonical full grid: each of the six engine orders occurs at each of the 16
realized pointer alignments. Smaller multiples of six are diagnostic subsets.
The runner takes no success threshold and the verifier never converts its
statistics into promotion authority.

This candidate composes the hardened benchmark v2 row contract, hardened
post-link observation, and row-authority follow-up after the original
three-engine benchmark commit. The follow-up repeats
`runtime_authority=absent` on every qualification/header/sample row. Missing
authority fields fail closed. The required post-link `PASS` row includes and
proves all of:

- `final_binary_sha256`, bound directly to the binary snapshot that is run;
- implementation and glue object identities;
- `entry_bytes_equal=true`, `payload_bytes_equal=true`, and
  `metadata_bytes_equal=true`;
- the exact hardened v2 observation field set, including
  `compile_identity_derived=true`;
- source commit/tree, helper SHA-256, profile, artifact/compile/bundle
  identities, and absent runtime/promotion authority.

Every benchmark qualification/header/sample row must independently repeat the
source commit/tree, run ID, instance type, helper SHA-256, profile,
artifact/bundle identities, evidence class, and absent authorities. Header rows
must also repeat the admitted affinity CPU. Missing fields are refusals, not
defaults.

### Continuous admission input

The runner does not guess or invoke a resource-coordinator CLI. It accepts
three exact files produced by a caller-controlled adapter around the reviewed
live helper:

1. a canonical retained admission receipt;
2. the opaque raw headroom evidence whose SHA-256 the receipt names; and
3. a canonical heartbeat file maintained atomically by the same live
   holder/session for the entire campaign.

This repository does not supply or claim a live cutover adapter. Until the
controller provides and reviews that external adapter/receipt contract, these
required inputs are unavailable and the campaign must fail closed.

The receipt schema is
`fre-aot-selected-end-abi2-retained-admission-v1`. It binds the exact
source/tree/helper/profile/run/instance/target CPU and a nonempty pin set. Its
headroom section must say:

```json
{"basis":"reviewed helper-specific description","evidence_sha256":"<64 lowercase hex>","other_work_kill_policy":"never","target_cpu_admitted":true,"unrelated_cpu_work":"coexist-if-target-cpu-admitted"}
```

Its acquisition section records `attempts_used`, `max_attempts`,
`started_unix_ns`, `completed_unix_ns`, and `deadline_unix_ns`; acquisition
must complete within both bounds. Its continuity section has this shape:

```json
{"continuous_since_unix_ns":0,"heartbeat_schema":"fre-aot-selected-end-abi2-admission-heartbeat-v1","holder_id":"<safe id>","lease_epoch":"<safe id>","maximum_heartbeat_age_ns":30000000000,"mode":"continuous-live-holder","session_id":"<safe id>"}
```

Use real positive timestamps; zero above is only a shape placeholder. The
receipt's validity must cover the entire bounded campaign deadline. The
heartbeat repeats the exact identity, receipt/holder/session/lease epoch,
continuous-start timestamp, target CPU, helper/profile, monotonically
nondecreasing sequence, observation and validity timestamps, and the same
headroom/evidence binding.

The runner snapshots and hashes the heartbeat immediately before and after
every child and once at campaign completion. It refuses stale, expired,
backward, replaced-session, or withdrawn-admission transitions. It never waits
for or retries admission itself, never retries a measurement, and never kills
unrelated work.

Heartbeat v1 is deliberately insufficient for campaign resume. A later
heartbeat with the same holder, session, lease epoch, and nondecreasing
sequence does not carry an irreversible lapse counter or authenticated history
that proves admission stayed continuously valid while the runner was absent.
The runner therefore has no resume mode and refuses every pre-existing output
directory. It also has no selective-cell retry: after any interruption or
failed child, the retained directory is diagnostic partial output only, never
gets a final manifest, and cannot be supplied to the campaign verifier.
Restarting requires a new whole campaign in a new output directory under a
fresh externally established continuous admission.

Every launched benchmark is the leader of a new runner-owned session and
process group. Before `exec`, that child sets target affinity and Linux
`PR_SET_PDEATHSIG=SIGKILL`, then verifies that its parent did not change across
the setup race. On a child timeout, runner exception, or handled
`SIGHUP`/`SIGINT`/`SIGQUIT`/`SIGTERM`, cleanup sends `SIGKILL` only to that exact
active runner-owned process group and bounds direct-child reaping to five
seconds. It never enumerates or signals unrelated processes. The parent-death
setting covers an otherwise uncatchable runner exit by killing the direct
benchmark leader when Linux reports parent death.

Handled runner signals use a non-throwing one-shot latch: the Python signal
handler never raises through an already-active exception or cleanup. The
bounded child-wait loop polls that latch at intervals of at most 250 ms.
Signals delivered during child launch or a durable progress-journal write stay
latched and are checked at the immediately following safe point; cleanup then
kills and reaps only the active owned process group, records the interruption,
and exits with the conventional signal status. Each absolute child deadline is
captured before `Popen`, capped by the absolute campaign deadline, and is not
rebased after launch or progress publication. The final manifest rename is a
short signal-blocked commit region, so a signal already latched before entry
aborts publication while a signal arriving after commit cannot invalidate or
retract complete evidence.

The campaign root contains `progress.v1.ndjson`. Each canonical event is at
most 4096 bytes, is appended through the runner's exclusive open descriptor,
and is `fsync`ed before the same record is emitted on standard error with a
`PROGRESS<TAB>` prefix. The journal is bounded to 8 MiB and 9,222 events,
covering campaign start/finalization plus started and terminal state for every
possible child. A successful journal ends in `campaign-finalizing`, is made
read-only, and is digest-bound by campaign manifest schema v2; manifest
presence remains the only completion claim. A partial journal ends in a
failure/interruption event and is made read-only when the runner can execute
cleanup. An uncatchable runner death can instead leave the already-`fsync`ed
prefix at mode `0600`; it still has no manifest, and every event explicitly
records `resumable=false` and `selective_retry=false`.

The manifest and digest sidecar are first written under private pending names.
After all raw/evidence directories and both pending files are durable, the
runner validates the deadline and live admission again, publishes the digest
sidecar without replacement, and publishes `manifest.v1.json` last. Handled
failures before that commit remove every pending/final completion file whose
exclusive inode ownership was established and append a failure/interruption
event through the still-open progress descriptor, even if a provisional
`campaign-finalizing` event was already written. If the kernel cannot report
the inode of a just-created pending file, cleanup leaves that unowned pending
name as fail-closed residue rather than risk deleting a replacement; it can
never become the final completion name.

The manifest's `completed_unix_ns` is the evidence/admission completion
boundary, sampled after the final child, final heartbeat, and finalizing event
and checked against both the monotonic campaign deadline and live admission.
File staging is then rechecked before publication, but scheduler delay between
that user-space check and `renameat2` does not redefine the already-recorded
evidence boundary. The final manifest name is the filesystem transaction
commit point. The runner retains the exact output-parent descriptor, verifies
that the parent still names the opened output-directory inode, and syncs both
the campaign root and its parent after commit. Reporting or directory-sync
errors after the name becomes visible do not retract a complete campaign. A
process death before that final publication may leave pending files or a
provisional finalizing journal but no final manifest; once the final name is
visible, all bound content and the sidecar were already staged and synced even
if the runner dies before printing its summary.

### Invocation and evidence

After the admission cutover GO and all deferred build/static-verifier gates,
run with isolated Python and absolute, non-symlink paths:

```text
python3 -I -B run_campaign.py \
  --binary /absolute/path/to/fre-aot-linux-selected-end-abi2-three-engine \
  --output /absolute/new/campaign-directory \
  --source-commit <40-lowercase-hex> \
  --source-tree <40-lowercase-hex> \
  --run-id <safe-run-id> \
  --instance-id <exact-instance-id> \
  --instance-type <c9g.*-or-m9g.*> \
  --helper-sha256 <64-lowercase-hex> \
  --profile linux-target-cpu-local-v1 \
  --target-cpu <admitted-cpu> \
  --repetitions 96 \
  --admission-receipt /absolute/path/admission-receipt.json \
  --admission-evidence /absolute/path/admission-evidence.raw \
  --admission-heartbeat /absolute/path/live-heartbeat.json \
  --post-link-observation /absolute/path/post-link-observation.txt
```

The runner clears the ambient environment, executes a read-only binary
snapshot through its already-open file descriptor, pins each child directly
with `sched_setaffinity`, and sets common thread-pool variables to one. It
stores the bounded progress journal, read-only raw stdout, stderr, before/after
admission heartbeats, the binary, host/admission/post-link evidence, a
canonical manifest, and a manifest digest sidecar. A partial campaign or any
pre-commit failure never gets a final manifest. A post-commit reporting or
directory-sync error may produce a nonzero runner exit, but it does not
reclassify or retract the already-complete manifest. Operators can follow the
durable status by running `tail -f` on the campaign's `progress.v1.ndjson`;
the emitted stderr records provide the same live child boundaries.

Retain the runner-printed manifest digest outside the campaign directory.
Verify using that digest and the other expected digests supplied independently
of the manifest:

```text
python3 -I -B verify_campaign.py \
  --campaign-dir /absolute/campaign-directory \
  --source-commit <40-lowercase-hex> \
  --source-tree <40-lowercase-hex> \
  --run-id <safe-run-id> \
  --instance-id <exact-instance-id> \
  --instance-type <c9g.*-or-m9g.*> \
  --helper-sha256 <64-lowercase-hex> \
  --profile linux-target-cpu-local-v1 \
  --target-cpu <admitted-cpu> \
  --expected-manifest-sha256 <runner-printed-64-lowercase-hex> \
  --expected-binary-sha256 <64-lowercase-hex> \
  --expected-admission-receipt-sha256 <64-lowercase-hex> \
  --expected-admission-evidence-sha256 <64-lowercase-hex> \
  --summary-out /absolute/new/summary.v1.json
```

The verifier rejects partial schedules, duplicate paths/coordinates/rows,
malformed numeric fields, identity/artifact/bundle drift, CPU/order/alignment
drift, broken continuous-admission chains, changed raw hashes, and unexpected
files. Its canonical summary reports per-cell and equal-weight aggregate
portable/JIT/AOT hot and lifecycle paired ratios, stage and AOT-activation
distributions, exact sign-test inputs, and break-even inputs. Because each
lifecycle measurement already contains its first call, break-even is reported
as the exact rational ceiling of additional hot calls after that lifecycle and
also as total calls (`1 + additional`). A ratio is left-over-right, so values
below one favor the left engine. AOT offline compiler and linker cost stays
explicitly unmeasured and excluded.
