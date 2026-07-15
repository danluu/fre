# Capture-history reducer frontier

This checkpoint replaces the rejected suffix-restarted capture reducer with a
whole-operation selector followed by exact-span tagged-history replay. It is a
source and counter checkpoint, not a performance result. No timing is allowed
until the current source has passed the full authenticated Rebar differential
twice with byte-identical reports.

## Certified mechanism and progress invariant

One canonical Rust-byte HIR produces two immutable programs:

1. the production aggregate compiler erases captures and selects the complete
   non-overlapping, non-empty whole-match span sequence in one
   `ReverseSequentialRows` operation; and
2. the capture compiler preserves ordered save events in persistent histories.
   It injects a start only at each selector-certified span start and replays
   only through that exact span end, while retaining the original haystack
   window for absolute-anchor context.

The selector owns leftmost-first/greedy span choice. Exact replay may discard a
match state before the certified end; at the certified end the first
prioritized match supplies the winning history. The overall capture is checked
against the certified span before any group participation is counted. A
selector/history disagreement is therefore a typed internal fault, never a
fallback search.

If `S` and `T` are the selector and tagged-program state counts, `N` is the
haystack length, `M` is the number of non-empty matches, and `L_i` are their
disjoint lengths, then:

- selector transition work is bounded by `O(SN)` and its span output by
  `O(M)`;
- tagged replay scans `sum(L_i) <= N` bytes;
- tagged replay processes `sum(L_i + 1) <= N + M <= 2N` boundaries for
  `N > 0`, so state/history work is `O(TN)`; and
- replay history scratch is released after each winner. Peak history scratch
  is bounded by the largest exact span, not by all suffixes or all matches.

Every selector and tagged-history work, scratch, output, history-node, winner
walk, group-event, match, and result dimension has a checked admission limit.
Line-oriented `grep-captures` invocations debit selector work and sequential
bytes from one public-job ledger rather than resetting either quota per line.
The operation peak is the larger of the selector peak and retained selector
spans plus one replay's admitted scratch; the combined cap constrains replay
before its history arena is allocated.
Construction identity includes both program identities and their limits;
execution identity includes both operation limit sets. Existing exact-literal,
continuation, and portable-grep dispatch is unchanged.

The retained suffix-restart adversary is `(?:a.*z|a)` over `a^N`. The rejected
implementation grew from 6,884 to 399,108 tagged state visits between 64 and
512 bytes. The operation-wide implementation records:

| `N` | selector work | combined selector/replay state visits | history nodes |
|---:|---:|---:|---:|
| 64 | 2,267 | 1,740 | 128 |
| 128 | 4,507 | 3,468 | 256 |
| 256 | 8,987 | 6,924 | 512 |
| 512 | 17,947 | 13,836 | 1,024 |

Each doubling is below the preregistered 2.5x ceiling. This establishes the
counter slope for the directed adversary; it does not substitute for the full
semantic differential or prove good wall-clock performance.

## Semantic and coverage gates

The focused gate covers optional, absent, empty, repeated, nested and 26-way
capture histories; invalid bytes; CRLF line reduction; interior absolute
anchors; and the quadratic restart adversary. It also retains typed refusals
for Unicode capture lowering and unsupported looks. At this checkpoint these
commands pass:

```text
cargo test -p fre-capture-lab --test conformance
cargo test -p fre --test captures
cargo test -p fre --test portable_assertions
cargo test -p rebar-compare fre_capture_reducers_cover_optional_repeated_and_line_models
cargo test -p rebar-compare grep_capture_selector_ledgers_are_cumulative_across_lines
cargo test -p rebar-compare current_fre_compile_constructs_fresh_artifacts_and_keeps_build_many_typed
```

The prior suffix-restarted semantic experiment added ten rows to its then-179
baseline, but it was killed because its aggregate work was quadratic. Those
receipts do not qualify this replacement. Promotion requires, on the current
baseline:

1. two byte-identical full 344-row comparison reports;
2. no removed pass, semantic failure, unresolved result or fault;
3. an exact unique supported-row delta and refusal-reason inventory;
4. focused static and documentation gates; and
5. preservation of the specialized non-capture dispatch identities.

The known capture-gap families must be reported rather than hidden by a total:
Unicode lowering, unsupported looks, ordered build-many, selector construction
limits, selector operation limits, and tagged replay/history limits. In
particular, the seven large rows refused by the rejected replay must be
reclassified using this mechanism's exact selector and exact-span bounds.

## Preregistered pointwise performance matrix

Run no timings before the semantic and counter gates above pass. After they do,
measure the complete public reducer boundary against pinned Rust regex on these
four cells. RE2 is a secondary comparator only: equal expected reductions make
these cells useful comparisons, but do not establish general RE2-profile
capture conformance.

| Regime | Row | Haystack bytes | Expected reduction |
|---|---|---:|---:|
| dense line captures | `curated/07-unicode-character-data/parse-line` | 1,913,704 | 558,784 |
| long sparse line captures | `curated/04-ruff-noqa/real` | 32,514,634 | 84 |
| medium line captures | `opt/onepass/fn-predicate` | 7,384,531 | 916 |
| short whole-haystack captures | `test/model/count-captures` | 37 | 3 |

Report pointwise medians, dispersion, allocations and work counters. Do not
publish a suite geomean from four hand-selected cells, and do not select a
different timing subset after seeing results.
