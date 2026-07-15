# Rebar semantic coverage frontier

This is the compact source checkpoint for the latest authenticated per-job
frontier. A full generation from exact source
`509682249461cd16d2d11fbbc98c72f68b1624d6` (tree
`aced3773a7e9278e883315792673ae99ff10ed54`) has SHA-256
`0bda3dcb0cff6fbe5756f148045f413a645ac2017d3dffd111346cc20a1dca2b`.
They used the immutable expanded manifest with SHA-256
`09a7bfe5df8a4d78c21144b4d45f584167a1607f412990a60045878227553e43`,
clean Rebar revision `463d00f31887e84c38467805b9e3122c314b9521`,
and the exact Rust and RE2 runners recorded below. The raw generated report
copy remains outside Git at
`/tmp/fre-control/results/G0-REBAR-PORTABLE-UNICODE-5096822-FRONTIER-001.json`.
The checked-in `report.json` continues to preserve the
preceding 144-pass baseline rather than being silently replaced by generated
evidence.

The authenticated current figure is 237: the 230-row Unicode-boundary and
compile-many frontier plus six variable-width Unicode continuation rows and
one portable Unicode scalar-class row. The malformed-UTF-8 boundary, Nosey
Parker repeat-bound, and all other prior refusals remain typed.

## By operation model

| Rebar model | Rust jobs | FRE pass | FRE unsupported | RE2 jobs | RE2 pass |
|---|---:|---:|---:|---:|---:|
| `compile` | 33 | 22 | 11 | 26 | 26 |
| `count` | 133 | 89 | 44 | 109 | 109 |
| `count-spans` | 129 | 108 | 21 | 110 | 110 |
| `count-captures` | 15 | 3 | 12 | 12 | 12 |
| `grep` | 11 | 10 | 1 | 10 | 10 |
| `grep-captures` | 22 | 5 | 17 | 17 | 17 |
| `regex-redux` | 1 | 0 | 1 | 1 | 1 |
| **Total** | **344** | **237** | **107** | **285** | **285** |

FRE has no `fail`, `fault`, or unresolved receipt. Its 219 aggregate-facade
passes comprise 22 `compile`, 89 `count`, and 108 `count-spans` jobs; another
ten use the portable `grep` path and eight use the linear selector plus
persistent capture-history path. All 285 RE2 jobs execute through the
exact pinned Rebar adapter and pass. The Rust reference executes all 344 Rust
jobs, with 342 pass and two retained failures.

The optional v2 executed-plan field splits those passes into 29 exact-literal
aggregates, 143 continuation-program aggregates, 23 direct Unicode-scalar
aggregates, two ordered build-many literal aggregates, 19 continuation compile
artifacts, two direct Unicode-scalar compile artifacts, one ordered compile-many
artifact, ten portable-search rows, and eight selector/history capture rows. It is
populated only after successful candidate execution and does not infer a plan
for any unsupported receipt.

## Authenticated capture delta

The source adds exactly eight supported jobs to the authenticated 214-pass
baseline, with no removed baseline pass:

- `captures/contiguous-letters@rust/regex`
- `curated/07-unicode-character-data/parse-line@rust/regex`
- `curated/11-unstructured-to-json/extract@rust/regex`
- `opt/onepass/first-three-words-english@rust/regex`
- `test/model/count-captures@rust/regex`
- `test/model/grep-captures@rust/regex`
- `unicode/overlapping-words/ascii@rust/regex`
- `wild/caddy/caddy@rust/regex`

## Authenticated Unicode-boundary and compile-many delta

The current source adds exactly these eight rows to the 222-pass capture
frontier, with no removed pass:

- `curated/12-dictionary/compile-multi@rust/regex`
- `reported/i787-keywords/opt-unicode@rust/regex`
- `reported/i787-keywords/unicode@rust/regex`
- `test/unicode/word-boundary/unicode-alphabetic@rust/regex`
- `test/unicode/word-boundary/unicode-connector-punctuation@rust/regex`
- `test/unicode/word-boundary/unicode-decimal-number@rust/regex`
- `test/unicode/word-boundary/unicode-join-control@rust/regex`
- `test/unicode/word-boundary/unicode-mark@rust/regex`

## Authenticated variable-width Unicode continuation delta

The current source adds exactly these six rows to the 230-pass frontier, with
no removed pass:

- `imported/sherlock/everything-greedy-nl@rust/regex`
- `opt/fixed-length/go33484-3@rust/regex`
- `opt/fixed-length/too-big-unicode@rust/regex`
- `opt/fixed-length/too-small-unicode@rust/regex`
- `unicode/compile/match-every-line@rust/regex`
- `wild/grapheme/compile@rust/regex`

## Authenticated portable Unicode class delta

The current source adds exactly one row to the 236-pass frontier, with no
removed pass:

- `wild/ruff/unnecessary-coding-comment@rust/regex`

## By benchmark/pattern family

| Family | FRE pass | FRE unsupported | RE2 pass |
|---|---:|---:|---:|
| `captures` | 1 | 0 | 1 |
| `curated` | 30 | 22 | 41 |
| `dictionary` | 1 | 6 | 4 |
| `folly` | 4 | 0 | 4 |
| `grep` | 2 | 1 | 2 |
| `hyperscan` | 14 | 1 | 0 |
| `imported` | 85 | 22 | 107 |
| `opt` | 24 | 11 | 26 |
| `reported` | 9 | 10 | 17 |
| `slow` | 4 | 0 | 4 |
| `test` | 50 | 0 | 46 |
| `unicode` | 10 | 12 | 16 |
| `wild` | 3 | 22 | 17 |
| **Total** | **237** | **107** | **285** |

The target job sets differ because Rebar definitions select engines
independently; columns are not intended to be row-wise equivalents.

## Exact FRE refusal split

The 76 aggregate compile/count/span refusals are all bounded resources: 11
`compile`, 44 `count`, and 21 `count-spans`. Unicode-on continuation now lowers
all scalar classes to canonical UTF-8 paths, while the direct plan still
executes canonical nonempty root scalar classes in one UTF-8 pass. Rows that do
not fit retain exact HIR/state/log/work or repeat-bound diagnostics. Resource
refusals are not faults and require a better plan, not a silent quota raise.

The other 31 refusals are operation/surface gaps: 29 capture rows, one portable
`grep` syntax gap, and one `regex-redux`. Capture refusals split exactly into
17 Unicode-lowering gaps, two unsupported look assertions, one ordered
build-many gap, and nine bounded selector-work refusals. The `grep` job remains:

- `grep/long-words-unicode@rust/regex`: Unicode word-boundary assertion.

The cumulative public-job ledger correctly refuses three `grep-captures` rows
that the pre-hardening screen admitted by resetting its budget per line:

- `curated/04-ruff-noqa/real@rust/regex`: requires 154,000 units with 87,810
  remaining at the refusing line.
- `curated/04-ruff-noqa/tweaked@rust/regex`: requires 87,138 units with 62,472
  remaining.
- `opt/onepass/fn-predicate@rust/regex`: requires 43,529 units with 42,796
  remaining.

The other six selector-work refusals are larger count-capture rows:
`opt/prefilter/rust-functions` (2,436,895,560 units),
`wild/dot-star-capture/rust-src-tools` (797,529,456), and four
`wild/rustsec-cargo-audit` rows (`both-alternate` at 8,216,459,160,
`both-slashes` and `original-unix` at 4,124,030,463 each, and
`original-windows` at 3,636,929,295), each against the existing 536,870,912
unit public-job limit. These are typed refusals; the limit was not raised.

## Correctness adversaries now admitted

Every executed candidate receipt passes, including the prior Unicode
exact-literal rows, six newly admitted variable-width Unicode continuation rows,
twelve aggregate ASCII-word/LF assertion rows, the two corresponding portable
ASCII-assertion `grep` rows, the portable Unicode scalar-class row, two ordered
build-many rows, 25 direct Unicode-scalar rows, the
eight capture-history rows, and all selected
`curated/14-quadratic`, `slow/quadratic-*`, `opt/reverse-inner/no-quadratic-*`,
and `opt/reverse-suffix/no-quadratic` jobs. The directed facade suite also locks
nullable/empty iteration, late priority fallback `(?:a+b|a)` over `a^N`,
captures erased only for whole-match output, invalid bytes, case folding, and
full-original-haystack anchor context under both continuation strategies and
forced exact/continuation plan policies. Exact-literal unit differentials cover
empty needles, overlaps, arbitrary invalid bytes, nested captures, canonical
HIR eligibility, and every nonzero build/reducer quota at and one below.
Capture differentials cover optional, absent, empty, repeated, nested and
26-way histories, line reduction, interior anchors, and a retained restart
adversary. For `(?:a.*z|a)` over `a^N`, combined selector/replay state visits
grow 1,740, 3,468, 6,924, and 13,836 at N=64, 128, 256, and 512; each doubling
is below the registered 2.5x counter ceiling. This is a work-counter result,
not a wall-clock performance claim.

The two reverse-suffix unsoundness jobs are intentionally non-bug-compatible:

| Job | Definition | FRE | Pinned Rust 1.12.4 |
|---|---:|---:|---:|
| `opt/reverse-suffix/unsound-leftmost-first@rust/regex` | 1 | 1 pass | 2 fail |
| `opt/reverse-suffix/unsound-start-literal-order-mismatch@rust/regex` | 1 | 1 pass | 2 fail |

A parser-, HIR-, planner-, and executor-independent `fre-reference` hand-AST
interpreter selects the single span `0..4` for both `zabb` inputs. Aggregate
full-table and reverse-row strategies agree with that naive leftmost-first
oracle. Direct upstream KLV differentials retain the pinned Rust `actual=2`
results, so the report exposes rather than copies the optimizer bug.

## Historical admission probe

`admission-frontier.json` is the byte-identical pre-integration diagnostic over
the old portable single-search builder. Its 194 build successes and projected
75 `count`/82 `count-spans` ceilings are historical construction evidence, not
current coverage. `report.json` supersedes it for production semantic outcomes.

## Prioritized exact frontier

1. Extend exact Unicode scalar and word-boundary semantics to the 17 capture
   Unicode refusals and the remaining portable Unicode-word `grep` refusal
   without weakening malformed-input or offset semantics.
2. Introduce faster bounded aggregate plans for the 76 aggregate resource
   refusals. The
   exact-literal reducer advanced `imported/leipzig/twain` without changing a
   quota and preserves the construction-time choice/no-fallback contract; the
   remaining refusals require other semantic shapes.
3. Run the preregistered pointwise capture performance gate on all four
   currently supported regimes before optimizing a favorite subset. Use
   allocations and selector/history counters to choose shared improvements;
   do not publish a four-cell suite geomean.
4. Extend ordered compile-many without raising the frozen repeat cap or
   emulating priority by source concatenation.
5. Qualify cold and allocator-warm construction performance for the twenty
   supported compile rows, keeping construction separate from untimed semantic
   verification. Extend only the reusable Unicode/resource/build-many mechanisms
   to the other fourteen rows.
6. Reduce selector work for the three near-bound cumulative-ledger refusals
   (`ruff-noqa/real`, `ruff-noqa/tweaked`, and `fn-predicate`) and then address
   the six much larger selector shapes with a reusable plan. Each row must earn
   admission within the existing public-job limits; do not raise quotas.
7. Admit the composite `regex-redux` job only after its complete report,
   replacement, and non-empty iteration semantics are implemented.

The current generated report has SHA-256
`0bda3dcb0cff6fbe5756f148045f413a645ac2017d3dffd111346cc20a1dca2b`,
and its sorted-receipts SHA-256 is
`fed904ca1ff5f62dba13345e8327bb7939d1b53ea8dd1758be162f0ed0ec72cc`.
