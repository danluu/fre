# Exact semantic comparison

This directory is the first executable semantic gate over
`../expanded/manifest.json` at Rebar revision
`463d00f31887e84c38467805b9e3122c314b9521`.

`report.json` is compact, deterministic `fre.rebar.comparison.v2` JSON. It
authenticates the expanded manifest and sidecar, every required source/evidence
file, definition metadata, first-matching expected-count rule, exact transformed
pattern bytes, and reconstructed haystack bytes before an adapter executes.
Every non-pass remains in the report with one of four distinct states:
`fail`, `unsupported`, `unresolved`, or `fault`.

`COVERAGE_FRONTIER.md` indexes the exact receipts by operation and benchmark
family and ties the next coverage gates to concrete Rebar job IDs.

## Retained report coverage

- Exact Rust/Rebar adapter: 344 jobs executed, 342 pass and 2 fail.
- Checked-in FRE baseline: 344 receipts, 144 pass and 200 explicitly
  unsupported, with no wrong answer or fault. The passes are 48 `count`, 89
  `count-spans`, and the existing 7 `grep` jobs. Every aggregate pass is a
  one-pattern, Unicode-disabled, whole-haystack operation admitted by the
  operation-specific facade; no build-many, Unicode, capture reducer,
  composite, syntax, or resource refusal is counted as a pass.
- Exact RE2/Rebar adapter: all 285 jobs execute and pass.
- Direct upstream KLV differentials: 9/9 agree with the pinned Rebar Rust
  runner. These cover every one of the seven Rebar models plus both retained
  Rust baseline failures.

The accepted compile/finite history reached 204 pass / 140 unsupported with no
FRE fail or fault. The later direct-scalar base independently reached 214 / 130.
The composed source has not generated a report; `COVERAGE_FRONTIER.md` records
only an overlap-aware arithmetic ceiling, never observed coverage.

The two Rust adapter failures are:

- `opt/reverse-suffix/unsound-leftmost-first@rust/regex`: expected 1, actual 2.
- `opt/reverse-suffix/unsound-start-literal-order-mismatch@rust/regex`:
  expected 1, actual 2.

Both actual values were reproduced through Rebar's own KLV generator and exact
`engines/rust/regex` executable. They are pinned Rust reverse-suffix
optimization bugs, not comparator disagreement. A separate hand-built,
fuel-bounded `fre-reference` AST interpreter selects the single span `0..4`
for both inputs. FRE returns the canonical count 1 and passes both receipts; it
deliberately does not reproduce the pinned optimizer's `actual=2` bug.

## FRE aggregate adapter boundary

- Pattern cardinality is checked before construction. `compile` remains exactly
  one pattern; multi-pattern `count` and `count-spans` route to the explicitly
  typed ordered build-many facade.
- `compile`, `count`, and `count-spans` construct distinct operation-specific
  artifacts; reducer verification or execution runs once over
  `0..haystack.len()`, preserving absolute-anchor context. Canonical direct-root
  `Literal`/`Empty` HIR selects the exact-literal whole-operation reducer.
  Eligible Unicode root scalar classes select the direct scalar reducer;
  bounded Unicode-off finite HIR may select the ordered finite reducer; other
  admitted HIR selects the continuation program. Selection is complete before
  publication and execution never falls back. Only the continuation plan
  carries the fixed `ReverseSequentialRows` strategy.
- Ordered build-many independently parses and retains every pattern identity.
  Eligible literal sets use the ordered-literal reducer; Unicode-off nonliteral
  sets use one ordered continuation alternation. Earliest start and lowest
  input ordinal define priority; no source concatenation or fallback occurs.
- Direct root capture annotations are transparently peeled by the
  allocation-free literal eligibility proof; the continuation compiler erases
  captures inside its bounded traversal. Both are limited to whole-match
  outputs. Source syntax and cache identities remain distinct even when
  capture erasure produces the same semantic plan.
- Unicode-enabled Rust jobs select exact literal or direct root scalar-class
  execution when eligible, then the byte-stable continuation subset. Empty,
  literals, ASCII-only classes,
  byte assertions, and their regular composition are eligible; non-singleton
  non-ASCII Unicode classes and Unicode word assertions remain typed refusals.
  Finite case folds are admitted when canonical HIR contains only singleton
  scalars.
- Every literal, finite, and build-many planner/build/reducer quota and every
  continuation operation-limit field is mapped explicitly. Bounds use
  authenticated cardinality/haystack length plus selected-plan construction
  accounting; continuation bounds use exact compiled state count. Resource
  refusals remain `unsupported`; arithmetic, allocation, and invariant failures
  would be `fault`.

The additive v2 `candidate_plan` field is present only after a candidate
operation successfully returns. It records the plan that actually executed; it
does not infer eligibility for unsupported receipts. In the retained 144-pass
baseline, candidate receipts split into 24 `aggregate-exact-literal`, 113
`aggregate-continuation-program`, and seven `portable-single-search` rows.

## Exact Rust adapter configuration

- `regex = =1.12.4`, default features plus `logging` and `perf-dfa-full`.
- `regex-automata = =0.4.14`.
- `meta::Regex::build_many`, `utf8_empty=false`, 100 MiB Thompson NFA limit,
  syntax `utf8=false`, and the per-job Unicode/case-insensitive flags.
- Reducers are direct translations of pinned
  `engines/rust/regex/main.rs` and `shared/regexredux/lib.rs`.

## Exact RE2 adapter configuration

- Rebar's untouched `engines/re2` runner, version `2025-11-05`.
- Vendored RE2 source is byte-identical at the audited evidence points to
  pinned RE2 commit `972a15cedd008d846f1a39b2e88ce48d7f166cbd`.
- Pinned Abseil `20250814.1` at commit
  `d38452e1ee03523a208362186fd42248ff2609f6` was installed into an isolated
  prefix to generate the pkg-config metadata required by Rebar's unchanged
  build script. `CXXFLAGS` supplied only that prefix's include path because the
  script performs its pkg-config probes after its `cc` compilation step.
- The resulting adapter reports version `2025-11-05` and has SHA-256
  `42a53794bc7a1a911484b84dd239b625e7241c8aca41b28d677ca76686266d4b`.
- Every RE2 result is produced by one exact KLV invocation, so no RE2 behavior
  is reimplemented or guessed in the comparator.

## Reproduction

From the FRE workspace, with the pinned checkout and its already-built exact
Rust adapter:

```text
cargo run --release -p rebar-compare -- \
  research/rebar/expanded/manifest.json \
  /tmp/rebar-fre \
  research/rebar/comparison/report.json \
  /tmp/rebar-fre/engines/rust/regex/target/release/main \
  /tmp/rebar-fre/engines/re2/target/release/main
```

Two consecutive post-field full generations were byte-identical; exact commands
and both hashes are retained in `REGENERATION.txt`. The report intentionally
contains no timestamps, absolute host paths, timings, or measured durations.
Input sizes, cache residency, pattern counts, reducer events, aggregate compile
work/program capacity, operation work, random/scratch/log/sequential/peak
storage, and each legacy FRE search have separate checked limits. Regex
reference construction additionally uses the exact adapter's 100 MiB NFA cap.

`report.sha256` authenticates the committed report. Performance qualification
is outside this artifact. The report also records
`receipts_sha256=23b072ac9cbcd6798bf76eaa39ffc7d45aea26115036f18dd2c185566f40f3d4`,
the SHA-256 of the comparator's compact JSON serialization of its sorted
`receipts` array (without a trailing newline).

`admission-frontier.json` is the retained pre-integration diagnostic over the
old portable single-search builder. It is authenticated construction evidence,
not a current coverage artifact and not a semantic receipt. The regenerated
`report.json` is authoritative for the production aggregate boundary and exact
per-job outcomes; its file SHA-256 is
`6a9e599ef7b3e2edeeec42dbad208e4a10f206a321f8f36e76bff3871f26b336`.
