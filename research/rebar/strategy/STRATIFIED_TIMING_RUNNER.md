# Stratified Rebar timing runner

Status: source-qualified timing infrastructure; performance results remain
external evidence and are not implied by this checkpoint.

`fre_rebar_runner` implements the four currently authenticated FRE operation
boundaries without branching on benchmark names:

- `compile` times one fresh deferred aggregate construction; its untimed
  semantic verification separately enumerates every complete match bound;
- `count` builds once, then times the source-independent certified Count
  portfolio with Aggregate Auto fallback; `count-spans` retains one
  construction-selected complete-span session, visits every returned
  `(start, end)` pair and sums every checked `end - start` width;
- capture models materialize every capture array and inspect every slot before
  reducing it, including the absolute full-haystack and line-oriented rows;
- `grep` builds once, requires an authenticated runtime/plan pair (exact
  literal, K0, or an admitted native word-run plan), and times the complete
  `bstr` line loop plus
  every public session `is_match` call. Its prepared-token policy is an
  allowlist: exact empty-literal, generic K0/line-total, Unicode word-run, and
  byte-class delimiter tokens are admitted; narrow AWS-prefix, three-field
  date, URI/composite, and anchored coding-cookie recognizers, along with every
  future unreviewed token, replay the ordinary retained semantic search. The
  empty-literal route still iterates every line and calls the public prepared
  matcher once per domain.

The runner accepts only the v2 canonical anonymous-workload protocol containing
the model, patterns, flags, haystack and, where applicable, lifecycle boundary.
The trusted collector retains and validates the Rebar KLV iteration/time limits,
but strips them before candidate execution: v2 derives its fixed one-operation
schedule and optional prime solely from the mode and lifecycle boundary and
rejects injected timing fields. Planner-disabled forced compilers are
deliberately absent from this protocol: formal Count selection is wholly
source-independent and construction-selected, with no caller-selected
implementation identity. Such compilers remain available only for generic
qualification outside the runner. The protocol rejects a
`forced-compiler` field, benchmark/job identity, and expected plan, runtime or
reducer values. It returns actual plan/runtime/reducer evidence. The trusted
outer scheduler owns every join to the authenticated receipt. It starts a
description process first and rejects a plan/runtime mismatch before starting
the measured process, then checks the measured response against both the
admitted description and expected reducer. The runner performs exactly one
measured operation, zero iteration-driven warmups, one or more patterns for
compile/count/count-spans, exactly one pattern for grep and capture models, and
no external patterns for regex-redux. Input is limited to 64 MiB. Its version
string fails closed unless canonical, engine, runner, lockfile, toolchain,
target and release-profile identities were bound at build time.
Identity-bearing legacy command lines fail closed.

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

Before starting any canonical timing pair, the scheduler now qualifies every
prepared `compile`, `count`, `count-spans`, and `grep` row on four same-length
haystacks: all-zero bytes, all-`0xff` bytes, an alternating `a`/LF probe or a
trusted literal witness, and a stream expanded from a fresh 256-bit
`/dev/urandom` seed. For a zero-result `compile`, `count`, or `count-spans` row
with exactly one case-sensitive, nonempty, metachar-free printable ASCII
pattern that fits in the haystack, the third probe contains exactly one copy of
that literal in a filler byte absent from the literal. This guarantees a
nonzero trusted reducer without admitting a historical specialist plan merely
because all generic probes happened to preserve zero. Escaped literals,
case-insensitive patterns, multiple patterns, and literals longer than the
haystack deliberately retain the alternating probe and remain subject to the
formal invariant allowlist. Nonempty probes are made distinct from each other
and from the canonical haystack. The
authenticated Rust runner supplies each expected reducer; the FRE child sees
only the anonymous v2 request and never the expected answer or row identity.
Every held-out description must retain the canonical preregistered plan and
runtime, and every actual must equal Rust exactly. Oracle-invariant rows are
admitted only with that exact formal aggregate identity or the existing grep
runtime allowlist. Empty haystacks necessarily have one byte representation,
but still receive all four executions and must use the formal invariant path.
Any qualification failure aborts before timing. To avoid uniquely warming FRE
and Rust relative to a scheduled RE2 arm, the scheduler then runs one untimed
canonical sample through every runner selected for every row, alternating arm
order by row, and takes the timing guard's start snapshot only after those
warmups. This reduces the new gross cache asymmetry; it does not make process
startup or host caches identical across implementations. The v3 timing report
records the seed digest, row/observation/literal-witness counts, the identities
of any rows that still required invariant admission, untimed canonical warmup
count, and a digest of the ordered qualification evidence without publishing
the held-out inputs.

The pinned semantic report still authenticates the historical v10 adapter,
while the source-tree runner identifies the current v123 adapter. This is an
intentional fail-closed cutover: no campaign from this source checkpoint is
eligible to time until the semantic frontier and its pinned hashes are
regenerated for the current runner. The witness above removes a latent
zero-result qualification failure after that regeneration; it does not bypass
the cutover gate.

Candidate child argv, environment and working directory are sanitized, and
FRE requests omit the original KLV name. Reference arms receive a fixed
anonymous KLV name. Stdin, stdout and stderr progress concurrently; stdout and
stderr stop at their live retention bounds. Every runner has a finite
monotonic wall deadline and joins a fresh process group whose collector-owned
anchor keeps the PGID live until group signaling is checked. Timeout, pipe
overflow or I/O failure kills the group and direct candidate, reaps the
candidate and group anchor and uses a bounded worker-join grace so a descendant
cannot hold the collector in a pipe join indefinitely. Same-group descendants
are also killed after an otherwise successful candidate exit. These are
protocol and availability hardening, not an OS isolation or CPU/RSS containment
boundary: the live scheduler command line still names the semantic report and
a same-UID child may inspect that report, scheduler descriptors or memory. A
descendant can deliberately escape a process group, although it still cannot
make the collector wait past the bounded worker grace. Production use therefore
requires an external sandbox or privilege boundary that prevents collector
inspection and process escape; this source checkpoint does not provide one.

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
