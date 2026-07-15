# Finite ordered-language aggregate plan

Status: semantic qualification on exact source
`e86a6ce46e3313ed69558522c5785d307394060f` (tree
`b3d3acac9eda492dc9d779ea4615622d7019572f`). The exact report has SHA-256
`294aba2fdc0ac429dd525c351b5b3aa710ff0be30e6d0c408b8a7ee5aa0c6092`
and sorted-receipts SHA-256
`11a24d1800194e1f6ee2c42717d2a65723ca05146e418d1697cff4d7392f03f3`.

## Mechanism and semantic boundary

For one-pattern, Unicode-disabled `compile`, `count`, and `count-spans`, the
aggregate facade now attempts its existing bounded finite-language extraction
after the direct-root exact-literal proof and before continuation compilation.
A successful extraction is committed to the operation-typed reversed dense
Aho-Corasick/DP reducer in `fre-kernels`; `compile` retains the count plan for
its separately timed construction and untimed verification seam. A selected
build or execution refusal does not fall through to continuation.

Unicode-on profiles bypass finite extraction. In the composed scalar frontier
they retain aggregate schema 6, select the direct root scalar-class plan when
eligible, and otherwise retain the nonempty exact-UTF-8 literal or separately
certified byte-stable continuation identity. Thus the finite candidate cannot
erase or alias any Unicode profile proof.

The reducer consumes the haystack once from right to left, records the lowest
ordered alternative at every original start, and evaluates non-overlapping
iteration with distinct initial/progressed DP states. Therefore `[a^M b, a]`
on `a^N` performs exactly `N` DFA transitions, `N + 1` reducer positions, and
at most `min(N, maximum_literal_width) + 1` ring initializations. It does not
repeat a suffix search. Empty alternatives retain adjacent-empty suppression;
prefix order, duplicates, captures erased only for whole-match output, and
arbitrary byte literals remain part of the existing kernel identity.

Finite extraction, materialized word capacities, dense-DFA construction,
persistent bytes, combined construction peak, operation transitions, reducer
positions, ring initialization, total work, scratch, and operation peak all
have explicit limits or reported counters. The exact observed materialized-word
capacity is debited from the kernel peak budget before kernel construction and
is checked again with the kernel's exact observed peak before publication.
Source/profile, operation, selected plan, algorithm/operation tag, all build
limits, and all execution limits are in facade cache identity. The explain
schema remains version 6 while adding the finite operation identity alongside
the direct scalar and profile-tagged continuation identities.

Patterns with repetition or look assertions, extraction beyond 4,096 words or
4 MiB of word payload, Unicode-enabled profiles, and complete-span output stay
on their prior plan or typed-refusal boundary. The general continuation plan
and its finite-horizon counterexample behavior are unchanged.

## Historical qualification accounting

Authenticated coverage is exactly 204 pass / 140 unsupported. Relative to the
200-row base, four `count` rows pass, no prior pass is lost, and FRE has no
`fail` or `fault`: `imported/leipzig/awyer-inn`, `imported/leipzig/shing`,
`imported/leipzig/tom-sawyer-huckle-finn`, and
`imported/leipzig/twain-insensitive`.

Those figures authenticate the isolated finite history, not this later
composition. The current scalar-base composition requires a fresh report; its
overlap-aware arithmetic ceiling is recorded separately and is not a coverage
claim.

The committed fast-plan index identifies an exact 36-row finite-language
candidate universe in the canonical manifest:

| Prior single-search shape | `count` | `count-spans` | total |
| --- | ---: | ---: | ---: |
| packed literal set | 10 | 7 | 17 |
| literal-set DFA | 16 | 3 | 19 |
| **candidate universe** | **26** | **10** | **36** |

This mechanism can remove a resource refusal only where one of those rows is
in the exact 40-row one-pattern aggregate resource set and its finite
extraction/dense construction fits the new bounds. That set comprises three
`compile`, 28 `count`, and nine `count-spans` refusals. The other three resource
refusals are qualified build-many execution rows and are cardinality-disjoint
from this mechanism. The exact regenerated join shows four admitted rows from
the candidate universe; the remainder were already supported or retain their
prior typed plan/resource boundary. No support count is inferred from the
36-row upper bound.

The same regeneration classifies all 33 compile rows. No compile row is added;
the three compile-resource refusals remain typed unsupported.

## Focused semantic gates

The focused facade and comparator gates, strict relevant Clippy, formatting,
and exact report generation run through the enforced resource coordinator:

```text
cargo test -p fre --test aggregate_facade finite_ordered_plan_preserves_priority_nullable_captures_and_invalid_bytes
cargo test -p fre --test aggregate_facade finite_ordered_plan_charges_one_reverse_transition_per_byte_and_all_dp_state
cargo test -p fre --test aggregate_facade finite_ordered_planner_and_dense_state_limits_are_exact_rejections
cargo test -p rebar-compare current_fre_one_pattern_aggregate_models_cover_adversarial_semantics
cargo test -p fre
cargo test -p rebar-compare
cargo run --release -p rebar-compare -- research/rebar/expanded/manifest.json /tmp/rebar-fre research/rebar/comparison/report.json /tmp/rebar-fre/engines/rust/regex/target/release/main /tmp/rebar-fre/engines/re2/target/release/main
```

The final report must remain byte-identical across mechanical source-only
changes. Compare all formerly passing aggregate receipts and publish the exact
resource-refusal delta. The structural adversary gate requires
`transitions == N`, `reducer_steps == N + 1`, exact total-work equality, and a
one-below `TotalWorkLimit` refusal.

## Preregistered timing matrix

Do not time only newly passing rows. Measure cold construction, first
operation, and hot value-only operation against pinned Rust regex for each
cell, retaining losses:

| Family | absent | dense hit | late/priority hit |
| --- | --- | --- | --- |
| dictionary finite alternation | no token present | token at most boundaries | longest-prefix alternative fails before short fallback |
| imported byte/class product | bytes outside every word | alternating one-byte/class hits | final candidate near haystack end |
| opt/prefilter-style finite set | required bytes absent | every position begins a word | `[a^M b, a]` over `a^N` and terminal `b` variant |

Use at least small, medium, and largest authenticated haystacks. Publish
pointwise construction and operation ratios plus persistent/scratch/peak
bytes; do not claim a supported-suite geomean or speedup from source shape.
