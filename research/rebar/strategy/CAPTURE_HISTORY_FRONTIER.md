# Capture-history reducer frontier

This checkpoint replaces the rejected suffix-restarted capture reducer with a
whole-operation selector followed by exact-span tagged-history replay. It is a
source, semantic, and counter checkpoint, not a performance result. Exact
source `785cc1eecf05bea484d2be1a54206152c4108685` passed the full authenticated
Rebar differential twice with byte-identical reports. No capture timing has
been run.

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
cargo test -p fre --test captures --test portable_assertions --test aggregate_many_facade
cargo test -p rebar-compare --lib
cargo clippy -p fre-capture-lab --all-targets -- -D warnings
cargo clippy -p fre -p rebar-compare --all-targets --no-deps -- -D warnings
RUSTDOCFLAGS=-Dwarnings cargo doc -p fre-capture-lab -p fre --no-deps
```

The prior suffix-restarted semantic experiment added ten rows to its then-179
baseline, but it was killed because its aggregate work was quadratic. Those
receipts do not qualify this replacement. The replacement satisfies the
semantic promotion gate:

- Two full 344-Rust-row reports are byte-identical at SHA-256
  `fc8a34677a6a7e8e4ae276c24f41339677247887901a98e824506b2fd5be26c8`;
  their sorted-receipts SHA-256 is
  `e108451aeef37bf0dacd3bfded66f0a5cd8a77fde3e832476acd26a1b27c791b`.
- FRE has 197 passes and 147 typed unsupported receipts, with no failure,
  fault, unresolved result, or removed pass relative to the authenticated
  189-pass baseline.
- The exact delta is eight capture rows: three `count-captures` and five
  `grep-captures`.
- The existing 29 exact-literal, 132 continuation, two ordered build-many, 17
  compile-artifact, and nine portable-search dispatch identities are
  preserved. Eight new receipts identify the selector/history capture path.

The eight newly supported IDs are:

- `captures/contiguous-letters@rust/regex`
- `curated/07-unicode-character-data/parse-line@rust/regex`
- `curated/11-unstructured-to-json/extract@rust/regex`
- `opt/onepass/first-three-words-english@rust/regex`
- `test/model/count-captures@rust/regex`
- `test/model/grep-captures@rust/regex`
- `unicode/overlapping-words/ascii@rust/regex`
- `wild/caddy/caddy@rust/regex`

The 29 remaining capture refusals are not hidden by the total: 17 require
Unicode lowering, two require unsupported looks, one requires ordered
build-many capture semantics, and nine exceed selector-work limits. Of the
seven large count-capture probe rows from the rejected experiment,
`captures/contiguous-letters` now passes and the other six remain exact bounded
resource refusals. Cumulative public-job ledger hardening also corrected three
line reducers that a pre-hardening screen admitted by resetting the quota per
line:

- `curated/04-ruff-noqa/real`: 154,000 units required with 87,810 remaining;
- `curated/04-ruff-noqa/tweaked`: 87,138 required with 62,472 remaining; and
- `opt/onepass/fn-predicate`: 43,529 required with 42,796 remaining.

The authenticated reports are
`/tmp/fre-control/results/P34-CAPTURE-785CC1E-85D-FULL344-R{1,2}.json`.
The earlier headline 200 screen reset line budgets and is not promotion
evidence. The separately reverted Unicode-compile experiment is also excluded.

## Preregistered pointwise performance matrix

The semantic and counter gates now permit timing, but no timing has yet run.
Measure the complete public reducer boundary against pinned Rust regex on these
four supported cells. RE2 is a secondary comparator only: equal expected
reductions make these cells useful comparisons, but do not establish general
RE2-profile capture conformance.

| Regime | Row | Haystack bytes | Expected reduction |
|---|---|---:|---:|
| dense line captures | `curated/07-unicode-character-data/parse-line` | 1,913,704 | 558,784 |
| short structured line captures | `curated/11-unstructured-to-json/extract` | 23,952 | 600 |
| medium line captures | `opt/onepass/first-three-words-english` | 613,357 | 35,128 |
| short whole-haystack captures | `test/model/count-captures` | 37 | 3 |

Report pointwise medians, dispersion, allocations and work counters. Do not
publish a suite geomean from four hand-selected cells, and do not select a
different timing subset after seeing results. This matrix was corrected before
any timing because `ruff-noqa/real` and `fn-predicate` became typed unsupported
when the semantic gate made selector ledgers cumulative across lines. Keep
those two rows as refusal/work-counter diagnostics until an implementation
earns admission within the existing limits; do not time them as supported FRE
cells and do not raise their quotas.
