# Capture-history reducer frontier

This checkpoint promotes the existing persistent tagged-history executor into
an operation-specific FRE facade and connects it to Rebar's
`count-captures`/`grep-captures` reducers. It is a projected source frontier;
the authenticated comparison report remains unchanged until phase B.

## Certified mechanism and invariant

The Rust-byte HIR adapter admits literals, byte classes, ordered alternation,
concatenation, greedy/lazy repetition, captures, and absolute start/end. It
refuses Unicode mode and every other look assertion before publication. Each
ordered Pike thread owns an immutable history-node ID. A save appends one
`(slot, byte-offset, previous)` node; speculative forks share the prior ID and
never clone a slot vector. Only the selected winner is walked, newest event
first, into fixed slots. Thus absent groups remain absent, empty participating
groups remain present, and a later repetition that does not participate cannot
erase an earlier participating value on the selected path.

The non-empty reducer materializes and drops one winner at a time. It separately
accounts state visits, history-node allocation, winner walks, group events,
participating-group count, matches, searches, peak threads, and conservative
scratch. Construction identity includes exact source/profile/admission,
operation, plan kind, compiler limits, and tagged-program report. Execution
identity additionally includes every reducer limit.

## Exact projected Rebar rows

The admitted syntax projection is 18 of the current 37 capture gaps: nine
`count-captures` and nine `grep-captures`, across six families.

`count-captures`:

- `captures/contiguous-letters`
- `opt/prefilter/rust-functions`
- `test/model/count-captures`
- `wild/caddy/caddy`
- `wild/dot-star-capture/rust-src-tools`
- `wild/rustsec-cargo-audit/original-unix`
- `wild/rustsec-cargo-audit/original-windows`
- `wild/rustsec-cargo-audit/both-slashes`
- `wild/rustsec-cargo-audit/both-alternate`

`grep-captures`:

- `curated/04-ruff-noqa/real`
- `curated/04-ruff-noqa/tweaked`
- `curated/07-unicode-character-data/parse-line`
- `curated/09-aws-keys/full`
- `curated/11-unstructured-to-json/extract`
- `opt/onepass/fn-predicate`
- `opt/onepass/first-three-words-english`
- `test/model/grep-captures`
- `unicode/overlapping-words/ascii`

The 19 retained refusals are exact: all 14 Unicode-enabled capture rows; four
ASCII word-boundary-dependent rows (`curated/05-lexer-veryl/single`,
`opt/backtrack/words-english`, `opt/onepass/word-boundary-english`, and
`wild/parol-veryl/ascii`); and ordered multi-pattern
`wild/parol-veryl/multi-captures-ascii`. The Veryl alternation transforms
contain `\b` internally. They are not plain byte-class rows.

These 18 are syntax projections, not authenticated passes. Conservative
history/scratch admission or actual semantic differentials may retain a subset
as unsupported in phase B; no row is counted as supported until the canonical
report says so.

## Focused phase-B gates

Run only after the separately authenticated coordinator packet is installed;
use ordinary commands so its enforced shim acquires distinct holders:

```text
cargo test -p fre-capture-lab --test conformance
cargo test -p fre --test captures
cargo test -p rebar-compare fre_capture_reducers_cover_optional_repeated_and_line_models
cargo clippy -p fre-capture-lab -p fre -p rebar-compare --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p fre-capture-lab -p fre --no-deps
cargo run --release -p rebar-compare -- research/rebar/expanded/manifest.json /tmp/rebar-fre research/rebar/comparison/report.json /tmp/rebar-fre/engines/rust/regex/target/release/main /tmp/rebar-fre/engines/re2/target/release/main
```

The regenerated frontier gate must report exact pass/unsupported counts by
model and refusal reason, preserve all 144 baseline passes, and show no fail or
fault. Differential coverage includes nested/repeated/optional/absent/empty
groups, invalid bytes, anchors, CRLF line splitting, and 26-way fan-out.

## Preregistered performance matrix

No timing was run in phase A. After semantic authentication, compare the full
public reducer boundary against pinned Rust regex for:

| Family | Row | Regime |
|---|---|---|
| captures | `contiguous-letters` | dense 26-way participation/fan-out |
| curated | `07-unicode-character-data/parse-line` | match-dense per-line fixed fields |
| wild | `rustsec-cargo-audit/original-unix` | sparse literal-prefix candidates on binary bytes |
| opt | `onepass/first-three-words-english` | line-dense three-capture parsing |

Record pointwise medians and allocation/work counters, not a suite geomean.
The expected effect is reduced capture-slot copying versus inline speculative
vectors, at the cost of history nodes and winner reconstruction. Repeated
search can still be quadratic in adverse leftmost-first cases; state/history
counters and the resource refusal are the screening gate, and no speed claim
is made before measurement.
