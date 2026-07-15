# Direct Unicode scalar-class stream

## Purpose

This lane adds one reusable mechanism for broad Unicode character classes. It
does not recognize benchmark names or special-case individual properties. The
constructor selects the mechanism from the canonical HIR shape and the typed
aggregate operation alone.

The current supported shapes are a nonempty Unicode scalar class at the root
and, after removing transparent captures, that class under canonical greedy or
lazy nonempty unbounded repetition (`CLASS+`/`CLASS+?`). The supported
operations are count, matched-byte span sum, and compile with an untimed count
verification. Span materialization, nullable or bounded repetition,
concatenation, alternation around the class, and anchors remain outside this
plan. Existing exact-literal, finite case-fold, ordered build-many, and
continuation paths are selected before or instead of this path where their
proofs apply. The repetition extension is detailed and preregistered in
`SCALAR_RUN_DFA_SCREEN.md`; the historical frontier below predates it.

## Mechanism

Construction converts the canonical scalar class into:

- a 128-bit ASCII membership bitmap; and
- sorted, disjoint non-ASCII scalar ranges retained in a compact boxed slice.

Traversal decodes each valid UTF-8 scalar once. An invalid, overlong,
surrogate, out-of-range, or truncated encoding advances by one byte and never
matches the Unicode class. This is the required Rust bytes-regex behavior; it
also guarantees progress on arbitrary byte strings and arbitrary valid search
windows.

ASCII membership is constant time. Non-ASCII membership uses binary search in
the retained ranges. An exact root class increments once per matching scalar.
Lazy `CLASS+?` does the same; greedy `CLASS+` increments once per maximal
matching run. Span sum adds the bytes in the selected scalar or run. Neither
reducer materializes matches.

The selected facade identity includes the operation, Rust compatibility
profile, canonical pattern identity, Unicode scalar semantic domain, retained
kernel identity, and every construction limit. The comparator dispatches from
that plan identity; it does not dispatch from a Rebar job name.

## Structural bounds

For an input window of `N` bytes and `R` retained non-ASCII ranges:

- decoding performs at most `4N` byte checks;
- membership performs at most `N` tests;
- non-ASCII lookup performs at most `N * (floor(log2(R)) + 1)` comparisons for
  nonzero `R`;
- repeated roots perform at most `N + 1` deterministic reducer transitions;
- traversal work is therefore `O(N log(R + 1))`;
- retained plan space is `O(R)`; and
- reducer scratch space is zero bytes.

Construction and traversal use checked accounting. Limits cover source and
retained ranges, construction work, temporary capacity, scratch, persistent
and peak bytes, input bytes, decode checks, membership tests, range
comparisons, reducer transitions, match events, result values, reducer work,
and reducer peak bytes.
Resource refusals are typed unsupported outcomes; arithmetic and invariant
violations are faults.

Every scalar quantity named `work` in this lane is a structural work counter,
not an executed-CPU-instruction estimate. Scalar selection charges one unit for
every HIR node and every canonical class range it examines. Kernel construction
charges range validation, ASCII bitmap population, and retained-range copies.
Traversal work is the sum of decoder byte examinations, membership tests,
non-ASCII range comparisons and, for repeated roots, deterministic reducer
transitions. Other loop control, checked counter maintenance,
allocator-internal operations, and allocator metadata are outside those work
counters; their input-dependent dimensions remain separately bounded by the
reported node, range, byte, scalar, match, capacity, and peak-byte limits.

The Rebar comparator exposes each scalar planner and builder quota directly:
planner structural work, source ranges, build structural work, temporary
capacity, persistent bytes, and peak bytes. It maps those named values into the
facade rather than inheriting hidden kernel defaults. The comparator defaults
reproduce the prior numeric facade and kernel defaults. Row retention remains
a semantic-report gate because the corrected structural counter can consume
more of the unchanged planner quota.

The kernel tests authenticate the bounds rather than merely checking outputs:

- every nonzero build and reduce dimension passes at the exact limit and
  refuses one below it;
- facade selection charges every canonical range examined, including
  non-qualifying singleton ranges before a late qualifying range, and refuses
  at exactly one structural unit below the required total;
- `N` doubling doubles the expected structural counters while scratch remains
  zero; and
- adversarial range counts from 1 through 511 have exact comparison counters
  consistent with logarithmic `R` scaling.

Exhaustive directed tests compare every window of representative ASCII,
property, script, symbol, digit, whitespace, word, dot, and dot-all classes to
the pinned Rust bytes oracle. Separate tests cover malformed UTF-8, overlong
forms, surrogates, truncation, out-of-range encodings, empty classes, captures,
and construction-selected operation identities.

## Current semantic frontier

The implementation was developed from isolated base `109409a` and replayed
onto corrected current base `d7e151e`. The replay commits are:

1. `8ec6cfd` -- bounded Unicode scalar aggregate kernel;
2. `69728e0` -- construction-selected facade plan; and
3. `905ce44` -- generic Rebar comparator integration.

The corrected-base worktree is
`/Users/danluu/dev/fre-worktrees/unicode-scalar-stream-d7e151e-r1`. It retains
the current ordered build-many and capture/timing APIs.

Focused gates at `905ce44` pass:

- scalar kernel: 8/8;
- aggregate facade: 27/27; and
- comparator library: 14/14, including ordered build-many.

Two independently launched full 344-row semantic reports are byte-identical:

- `/private/tmp/fre-control/results/UNICODE-SCALAR-D7E151E-905CE44-R1.json`
- `/private/tmp/fre-control/results/UNICODE-SCALAR-D7E151E-905CE44-R2.json`
- SHA-256:
  `923704b278597368b8608c193d8f7b29665191420ead2bb7e57d3aa7e19769b1`

The frontier moves from 189/344 to 214/344 supported Rust Rebar jobs: +25,
-0, with zero FRE fail, fault, or unresolved receipts. Both existing ordered
build-many rows remain on `aggregate-many-ordered-literal`.

The 25 newly supported rows are deliberately distributed across operations and
families:

- compile: `unicode/compile/negated-class-matches-codepoint`,
  `unicode/compile/one-letter`;
- count-spans: `imported/rsc/match-class-unicode`,
  `imported/sherlock/letters-lower`, `letters-upper`, and `letters`;
- count: `imported/leipzig/math-symbols`, Unicode decimal, whitespace, dot,
  invalid-UTF-8 dot, seven Unicode letter/property spellings, five Unicode word
  components, and `unicode/codepoints/any-one`.

Every row above has the target suffix `@rust/regex`. The exact added-ID list is
also reproducible as the set difference between the baseline report
`G0-REBAR-BUILDMANY-35B22AC-FRONTIER-001.json` and either report above.

## Performance status

The structural result removes the prior `O(NQ)` direction for these root
classes and gives a single-pass `O(N log(R + 1))` reducer with zero traversal
scratch. That is not yet a pointwise performance claim.

Construction time and reducer time still require coordinated pointwise timing
against Rust regex and RE2 on the exact 25 affected rows, plus representative
`N`-doubling and worst-case `R` sweeps in release mode. In particular, a broad
non-ASCII property can pay several binary-search comparisons per scalar, while
ASCII-heavy inputs use the bitmap fast path. No geomean improvement should be
reported or inferred until those measurements exist. Semantic support may be
promoted independently, but any performance regression found by the pointwise
gate must drive a general mechanism improvement or a typed construction-time
selection rule, never a benchmark-name exception.
