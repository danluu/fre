# Ordered build-many frontier

Status: semantic qualification from canonical base
`109409aaca9ce5acf5d35cd7b4cbc0c8c7c78152`. Exact candidate source
`35b22acf7db5ebf63992085a4ad3782a9e46f139` (tree
`b63266c7be97e82b565bf2b9ce78d9608536a2a9`) passed its focused facade,
comparator, strict Clippy, and format gates. The full Rebar report has SHA-256
`132e6c75034fe6ff720af3511eca8779ebb0dd9266c243dbc9061a5157209607`
and sorted-receipts SHA-256
`106dce03fad55de68e32ef9bdf8be0541918119a8e189b9243fd1f4deec4df48`.
The qualified mechanism is retained in exact 200-row Unicode compile frontier
`5f4da7b5536c42bbcdc467ea9c897bf990577938`; the bounded one-pattern finite
candidate is recomposed on that frontier source-only. No new compiler, test
executable, generated report, assembly inspection, or timing command was run
for this composition.

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

## Exact qualified cluster

The exact composed frontier is 200 pass / 144 unsupported. Two of the five
execution candidates pass; the other three now reach later typed resource
gates instead of being rejected for pattern cardinality:

| Rust-target row | Operation | Exact result |
|---|---|---|
| `curated/13-noseyparker/multi@rust/regex` | `count` | repeat-bound refusal |
| `curated/12-dictionary/multi@rust/regex` | `count` | pass, ordered literal |
| `opt/literal-alt/pattern-per-word@rust/regex` | `count` | pass, ordered literal with Unicode literal proof |
| `curated/05-lexer-veryl/multi@rust/regex` | `count-spans` | execution-work refusal |
| `wild/parol-veryl/multi-patternid-ascii@rust/regex` | `count-spans` | execution-work refusal |

The exact operation counts are 62 `count` and 101 `count-spans`; the two new
passes are additive to the independently authenticated Unicode and portable
rows. The 28 `compile` passes include the separately qualified Unicode compile
artifacts and remain unchanged. The two multi-pattern compile
jobs remain typed unsupported until the compile facade publishes a complete
ordered artifact.

The finite candidate is cardinality-disjoint from build-many and cannot alter
these five dispositions. Its one-pattern resource-refusal intersection remains
unmeasured, so this document claims no larger authenticated total.

## Required follow-up

The representative construction row is
`curated/12-dictionary/compile-multi@rust/regex`; it remains unsupported until
compile-model timing and work publication are defined. Its paired execution
row, `curated/12-dictionary/multi@rust/regex`, is the representative count
measurement. The named performance follow-up must also measure adverse cases:
reversed-priority
prefixes such as `[a{M}b, a]` over `a^N`, duplicate and empty alternatives,
late matches, no matches, thousands of literals, and large heterogeneous lexer
sets. Compile cost, retained capacity, cold count, and hot count must be
reported separately. A semantic pass does not imply a performance win.
