# Stratified Rebar timing runner

Status: source-qualified timing infrastructure; performance results remain
external evidence and are not implied by this checkpoint.

`fre_rebar_runner` implements the four currently authenticated FRE operation
boundaries without branching on benchmark names:

- `compile` times a fresh `AggregateBuilder` configuration plus
  `build_compile`; semantic verification is untimed;
- `count` and `count-spans` build once, then time the public `count_value` and
  `span_sum_value` reducers respectively;
- `grep` builds once, requires an authenticated runtime/plan pair (K0 or the
  linear Unicode word-run plan), and times the complete `bstr` line loop plus
  every public session `is_match` call.

The runner requires the exact benchmark, model, plan, reducer and runtime
identities supplied by the scheduler. It accepts exactly one measured
iteration, zero warmup iterations, one pattern and at most 64 MiB of KLV. Its
version string fails closed unless canonical, engine, runner, lockfile,
toolchain, target and release-profile identities were bound at build time.

`stratified_gate` is a separate scheduler. It is pinned to the 238-pass report
with SHA-256
`f1f40ff23aa316fc69fd32b5bb9c508d7085f0b91b360baea7387dd66c23273e`,
receipt digest
`6122094efae0d307e458ca8f07243f73bee0a1e31938610b4b386bbebd2d6fca`,
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

- `breadth-current`: the new Unicode word-run grep row, its ASCII grep
  neighbor, a direct Unicode scalar-class row, an exact-literal aggregate row
  and a continuation/assertion aggregate row (five rows). Results are
  pointwise only; missing authenticated RE2 coverage is recorded per row.

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
