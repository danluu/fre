# Finite ordered-language aggregate plan

Status: source-only candidate. No compiler, executable test, report generation,
or timing command was run in phase A.

## Mechanism and semantic boundary

For one-pattern, Unicode-disabled `count` and `count-spans`, the aggregate
facade now attempts its existing bounded finite-language extraction after the
direct-root exact-literal proof and before continuation compilation. A
successful extraction is committed to the operation-typed reversed dense
Aho-Corasick/DP reducer in `fre-kernels`; a selected build or execution refusal
does not fall through to the continuation program.

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
have explicit limits or reported counters. Source/profile, operation, selected
plan, algorithm/operation tag, all build limits, and all execution limits are
in facade cache identity. The explain schema advances from 3 to 4.

Patterns with repetition or look assertions, extraction beyond 4,096 words or
4 MiB of word payload, Unicode-enabled profiles, and complete-span output stay
on their prior plan or typed-refusal boundary. The general continuation plan
and its finite-horizon counterexample behavior are unchanged.

## Coverage accounting

Authenticated coverage remains exactly 144 pass / 200 unsupported until a
phase-B canonical regeneration runs; this source-only checkpoint claims zero
authenticated unlocks.

The committed fast-plan index identifies an exact 36-row finite-language
candidate universe among the 157 one-pattern construction opportunities:

| Prior single-search shape | `count` | `count-spans` | total |
| --- | ---: | ---: | ---: |
| packed literal set | 10 | 7 | 17 |
| literal-set DFA | 16 | 3 | 19 |
| **candidate universe** | **26** | **10** | **36** |

This mechanism can remove a resource refusal only where one of those rows is
in the exact 28-row resource set and its finite extraction/dense construction
fits the new bounds. The generated manifest/report containing job IDs and the
family join is intentionally not committed at this base, so the exact
intersection—21 `count` operation-work, two `count` row-log, three
`count-spans` operation-work, and two `count-spans` compile-work receipts—must
be measured rather than guessed. The phase-B report must publish job IDs,
families, model counts, prior refusal resource, selected plan, and remaining
typed refusal. No support count should be promoted from the 36-row upper bound.

## Focused phase-B gates

After an independently audited coordinator receipt and authenticated phase-B
packet, run normal commands through the enforced shim:

```text
cargo test -p fre --test aggregate_facade finite_ordered_plan_preserves_priority_nullable_captures_and_invalid_bytes
cargo test -p fre --test aggregate_facade finite_ordered_plan_charges_one_reverse_transition_per_byte_and_all_dp_state
cargo test -p fre --test aggregate_facade finite_ordered_planner_and_dense_state_limits_are_exact_rejections
cargo test -p rebar-compare current_fre_one_pattern_aggregate_models_cover_adversarial_semantics
cargo test -p fre
cargo test -p rebar-compare
cargo run --release -p rebar-compare -- research/rebar/expanded/manifest.json /tmp/rebar-fre research/rebar/comparison/report.json /tmp/rebar-fre/engines/rust/regex/target/release/main /tmp/rebar-fre/engines/re2/target/release/main
```

Regenerate twice and require byte-identical reports. Compare all formerly
passing aggregate receipts, then report the exact resource-refusal delta by
model, family, job ID, and reason. The structural adversary gate requires
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
