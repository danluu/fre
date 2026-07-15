# Ordered build-many projection

Status: source-only projection from canonical base
`c25f8c2ad4356c148256d8000cd483a9410c66a5`. No compiler, test executable,
generated report, assembly inspection, or timing command was run for this
composition.

## Semantic construction

Every input pattern is parsed independently under the pinned Rust bytes
profile. The immutable report retains its ordinal, source/cache key, admission
status, and parser accounting. Cardinality, aggregate source bytes, logical
composition storage, and source-preflight work are checked before parsing or
plan allocation. Observed vector capacities, parser work, selected-engine
work, scratch, persistent storage, and peak storage remain separately bounded
and reported.

All-literal sets select the existing reverse ordered-literal DFA/DP reducer.
Unicode-on is admitted only when every pattern is a case-sensitive, nonempty,
canonical valid-UTF-8 literal. Other Unicode-on sets remain a typed refusal.
Unicode-off nonliteral sets are joined as one ordered HIR alternation after
independent parsing and compiled by the bounded continuation engine. No source
string is concatenated, no job or fixture identity affects selection, and no
runtime fallback is available.

Both plans implement earliest start followed by the lowest input pattern
ordinal at that start. Successive matches are non-overlapping, empty matches
use the pinned initial/progressed rule, and absolute assertions retain the
original whole-haystack context. Captures may be erased only for whole-match
count and span-sum values. Span materialization and capture-count/history
outputs are typed preflight refusals.

## Exact projected cluster

The authenticated frontier remains 179 pass / 165 unsupported until fresh
canonical receipts exist. This source projects the following five existing
ordered build-many refusals:

| Rust-target row | Operation | Projected plan family |
|---|---|---|
| `curated/13-noseyparker/multi@rust/regex` | `count` | continuation program |
| `curated/12-dictionary/multi@rust/regex` | `count` | ordered literal |
| `opt/literal-alt/pattern-per-word@rust/regex` | `count` | ordered literal with Unicode literal proof |
| `curated/05-lexer-veryl/multi@rust/regex` | `count-spans` | continuation program |
| `wild/parol-veryl/multi-patternid-ascii@rust/regex` | `count-spans` | continuation program |

If and only if all five fresh semantic receipts pass every bounded gate, the
projected operation counts become 57 `count` and 102 `count-spans`, with a
projected total of 184 pass / 160 unsupported. The authenticated 16 `compile`
passes remain unchanged. These are projections, not
promotion evidence.

This five-row build-many projection is additive to any Unicode-continuation
rows separately qualified from the base candidate. Because that candidate has
no regenerated canonical receipt, this document does not claim a larger exact
composed total.

## Required follow-up

The representative construction row is
`curated/12-dictionary/compile-multi@rust/regex`; it remains unsupported until
compile-model timing and work publication are defined. Its paired execution
row, `curated/12-dictionary/multi@rust/regex`, is the representative count
measurement. Qualification must also measure adverse cases: reversed-priority
prefixes such as `[a{M}b, a]` over `a^N`, duplicate and empty alternatives,
late matches, no matches, thousands of literals, and large heterogeneous lexer
sets. Compile cost, retained capacity, cold count, and hot count must be
reported separately. A semantic pass does not imply a performance win.
