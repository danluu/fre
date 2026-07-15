# Rebar compile-model production boundary

Status: the qualified one-pattern mechanism is retained. A source-only
multi-pattern extension was authored from exact clean base
`a92a4e5edfa4ee88650a7546fd6e3e7dcbdd4f66` without running a compiler,
formatter, executable test, report generation, assembly inspection, or timing
command.

## Lifecycle and identity

Rebar's `compile` model times only construction of a configured regex from the
ordered pattern input. It captures that duration before traversing the
haystack; the later non-overlapping match count is semantic verification, not
part of the compile sample.

`AggregateBuilder::build_compile` now exposes the corresponding production FRE
boundary for the currently certified one-pattern domain. Returning an
`AggregateCompileRegex` means that syntax parsing under the complete pinned
Rust/Rebar profile, exact-literal inspection or continuation lowering, checked
plan allocation, stable plan identity, and retained-plan publication have all
completed. `verify_count` can then check the artifact on the original complete
haystack without compiling or falling back.

Compile has its own `AggregateOperation::Compile` value and therefore cannot
alias a count operation in cache identity. Exact-literal and continuation
artifacts retain their existing kernel/program identities and complete build
accounting. Every comparator request constructs and drops a fresh artifact, so
neither samples nor jobs share warmed plans or parser state.

`AggregateManyBuilder::build_compile` exposes the same boundary for ordered
multi-pattern input. It independently parses every pattern with its ordinal
and complete profile identity, selects the already-bounded ordered-literal or
Unicode-off continuation plan, and publishes an `AggregateManyCompileRegex`.
Its `verify_count` method executes only that retained plan. It cannot parse,
reselect, concatenate source patterns, or fall back.

## Supported and refused domain

The source frontier contains exactly 33 Rust-regex `compile` rows, all 33
previously typed unsupported. This checkpoint routes compile requests through
the same certified syntax/profile and plan portfolio as the one-pattern count
surface:

- Unicode-off exact literals, empty patterns, case-insensitive byte lowering,
  and admitted continuation HIR;
- Unicode-on nonempty, case-sensitive canonical UTF-8 literals; and
- whole-match capture erasure only, because verification observes no capture
  history.

Ordered build-many compile uses the same cardinality, source-byte, composition,
scratch, report-capacity, persistent, and selected-engine limits as the
qualified ordered execution facade. Unicode-on remains limited to ordered
nonempty case-sensitive canonical UTF-8 literals; general Unicode,
unsupported assertions/syntax, and every compile resource limit retain typed
refusals. Syntax/profile identity is never inferred from the lowered HIR.

The canonical manifest and baseline receipt files are deliberately untracked
and are absent from this source-only worktree. Consequently the exact number
and family list of the 33 real rows inside the one-pattern domain is not
authenticated in phase A: the honest authenticated gain remains 0/33 until the
phase-B full report enumerates it. The implementation claims only the domain
above, not 33/33 support. The source tests exercise three distinct one-pattern
families plus ordered multi-pattern literals, priority-sensitive continuation,
Unicode/profile refusal, and cardinality refusal.

Relative to exact base `a92a4e5edfa4ee88650a7546fd6e3e7dcbdd4f66`,
the source-only multi-pattern extension projects exactly two additional
`compile` rows and no others:

- `curated/12-dictionary/compile-multi@rust/regex`;
- `curated/13-noseyparker/compile-multi@rust/regex`.

This is a projected increment, not authenticated coverage or performance.

## Focused semantic and structural gates

After a separately authenticated phase-B packet and coordinator receipt, run:

```text
cargo test -p fre --test aggregate_facade compile_artifact -- --nocapture
cargo test -p fre --test aggregate_many_facade compile_artifact -- --nocapture
cargo test -p rebar-compare current_fre_compile -- --nocapture
cargo test -p rebar-compare exact_rebar_model_reducers_cover_empty_and_crlf_semantics -- --nocapture
cargo run --release -p rebar-compare -- research/rebar/expanded/manifest.json /tmp/rebar-fre research/rebar/comparison/report.json /tmp/rebar-fre/engines/rust/regex/target/release/main /tmp/rebar-fre/engines/re2/target/release/main
```

The regenerated report must either confirm exactly the two projected
compile-multi job IDs above or reject the projection, retain typed unsupported
receipts for the broader Unicode/syntax/resource frontier, contain no new
fail/fault, and leave every pass in the authenticated pre-extension frontier
unchanged. The checked-in historical report must not be mistaken for current
comparison evidence. Run formatting, lint, test, and full-report gates only
under separate validation coordination.

## Preregistered performance matrix

Timing must use fresh artifacts and time only the `build_compile` call. Keep
pattern preparation, haystack loading, and `verify_count` outside the sample.
Alternate FRE with pinned Rust `Regex::builder().build_many` in fresh processes
and retain raw samples. Report pointwise results, never a fabricated supported-
suite geomean.

| Family | Profile | Plan/shape | Residency cells |
| --- | --- | --- | --- |
| exact literal | Unicode off and admitted Unicode on | empty, short, long | first cold sample; later allocator-warm samples |
| alternation/repetition | Unicode off | small, medium, near quota | first cold sample; later allocator-warm samples |
| captures/case folding | Unicode off | nested captures; ASCII folded class | first cold sample; later allocator-warm samples |
| rejection boundary | all relevant profiles | one-below work/storage; invalid syntax; Unicode/profile mismatch | deterministic outcome only, not speed |

Expected effect is the exact two-row source projection above, not authenticated
coverage or a measured speed claim. FRE may be faster or slower than Rust in
any matrix cell; this source-only extension established no timing evidence.
