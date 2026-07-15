# Stratified Rebar timing runner

Status: source-qualified timing infrastructure; performance results remain
external evidence and are not implied by this checkpoint.

`fre_rebar_runner` implements the four currently authenticated FRE operation
boundaries without branching on benchmark names:

- `compile` times a fresh `AggregateBuilder` configuration plus
  `build_compile`; semantic verification is untimed;
- `count` and `count-spans` build once, then time the public `count_value` and
  `span_sum_value` reducers respectively;
- `grep` builds once, requires both the K0 plan and runtime ID, and times the
  complete `bstr` line loop plus every public `is_match` call.

The runner requires the exact benchmark, model, plan, reducer and K0 runtime
identities supplied by the scheduler. It accepts exactly one measured
iteration, zero warmup iterations, one pattern and at most 64 MiB of KLV. Its
version string fails closed unless canonical, engine, runner, lockfile,
toolchain, target and release-profile identities were bound at build time.

`stratified_gate` is a separate scheduler. It is pinned to the 189-pass report
with SHA-256
`132e6c75034fe6ff720af3511eca8779ebb0dd9266c243dbc9061a5157209607`,
receipt digest
`106dce03fad55de68e32ef9bdf8be0541918119a8e189b9243fd1f4deec4df48`,
manifest digest
`09a7bfe5df8a4d78c21144b4d45f584167a1607f412990a60045878227553e43`
and clean Rebar revision `463d00f`. It authenticates canonical report bytes,
adapter identities, exact Rust/RE2/Rebar executable hashes, the caller-pinned
FRE executable hash, checkout commit/tree/cleanliness and every decoded KLV
field against the selected receipt. All binaries and the checkout are checked
again after the wave.

Every `(row, comparator)` receives six whole fresh-process pairs, exactly three
in each arm order and no warmup. Row and comparator phases rotate globally.
The report retains global sequence, arm order, durations, reducer, KLV/input
hashes, pair ratios, AB and BA medians and min/max dispersion. Ratios are
checked integer parts-per-million; there is no floating-point or cross-row
geomean. A point passes only when the median paired ratio, AB median and BA
median are all below 1.0 and FRE wins at least four of six pairs. Missing RE2
coverage is accepted only when the authenticated Rebar report has no RE2 job,
and is recorded explicitly.

## Preregistered campaigns

- `assertion-focused`: the two new ASCII-word/LF grep rows, the shared email
  and line-boundary neighbors, and the zero-result grep row (five rows).
- `assertion-full`: the two affected rows, all nine retention cells and the
  zero-result grep row (twelve rows).
- `compile-smoke`: two fresh compile rows plus the matching count and
  count-spans operation controls (four rows).
- `compile-focused`: the accepted eight representative compile rows plus three
  operation/fast-path controls (eleven rows).
- `compile-all`: every currently supported fresh compile row (seventeen rows).
- `compile-full`: `compile-all` union all nine retention cells (twenty-six
  unique rows).
- `unicode-full`: all eight authenticated 179-to-187 Unicode gains plus all
  nine retention cells (seventeen rows).

The scheduler rejects arbitrary row lists, pair counts, warmups, duplicate
campaign members and output overwrite. It must run through the resource
coordinator's exclusive timing lease with at least 20 GiB free and AC power;
pre/post load and power readings are retained. Any child, provenance, input or
guard failure aborts the whole campaign rather than retrying one arm.

## Qualification limits

The report-backed Unicode rows include two tiny functional checks. They do not
replace the separately required authenticated 4 KiB, 64 KiB and 1 MiB
empty/invalid/raw-byte scaling fixtures. A performance promotion for shared
Unicode execution therefore needs those fixtures in addition to
`unicode-full`.

The pointwise Rust/RE2 rule establishes competitor performance, not regression
against an earlier FRE binary. When a shared-engine candidate replaces an
already-promoted FRE implementation, retain a separately frozen old-FRE control
wave before accepting unrelated-cell regressions.

Generated KLV, raw samples, timing reports, sidecars and runner binaries remain
outside Git. Only this protocol, source and tests are source checkpoints.
