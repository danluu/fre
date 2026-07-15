# Rebar compile-model production boundary

Status: source-only candidate. No compiler, executable test, report generation,
or timing command was run while authoring this checkpoint.

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

Ordered build-many remains explicitly unsupported before parsing or
construction. General Unicode, unsupported assertions/syntax, and every
compile resource limit retain typed refusals. Syntax/profile identity is never
inferred from the lowered HIR.

The canonical manifest and baseline receipt files are deliberately untracked
and are absent from this source-only worktree. Consequently the exact number
and family list of the 33 real rows inside the one-pattern domain is not
authenticated in phase A: the honest authenticated gain remains 0/33 until the
phase-B full report enumerates it. The implementation claims only the domain
above, not 33/33 support. The source tests exercise three distinct families
(literal, prioritized alternation/repetition, and captured case-folded class),
plus build-many refusal.

## Focused semantic and structural gates

After a separately authenticated phase-B packet and coordinator receipt, run:

```text
cargo test -p fre --test aggregate_facade compile_artifact -- --nocapture
cargo test -p rebar-compare current_fre_compile -- --nocapture
cargo test -p rebar-compare exact_rebar_model_reducers_cover_empty_and_crlf_semantics -- --nocapture
cargo run --release -p rebar-compare -- research/rebar/expanded/manifest.json /tmp/rebar-fre research/rebar/comparison/report.json /tmp/rebar-fre/engines/rust/regex/target/release/main /tmp/rebar-fre/engines/re2/target/release/main
```

The regenerated report must list every newly passing compile job ID grouped by
benchmark family and plan, retain typed unsupported receipts for build-many and
the broader Unicode/syntax/resource frontier, contain no new fail/fault, and
leave every pass in the authenticated pre-compile frontier unchanged. The root
handoff currently records that frontier as 161/344; the checked-in v2 report is
the older 144/344 baseline and must not be mistaken for the current comparison.
Run the workspace formatting, lint, and test gates only under that same phase-B
coordination.

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
| rejection boundary | all relevant profiles | one-below work/storage; invalid syntax; build-many | deterministic outcome only, not speed |

Expected effect is coverage, not a measured speed claim: compile rows in the
certified one-pattern domain can execute an honest complete production build.
FRE may be faster or slower than Rust in any matrix cell; phase A established
no timing evidence.
