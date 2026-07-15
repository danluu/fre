# Rebar semantic coverage frontier

This is the compact source checkpoint for the latest authenticated per-job
frontier. Two full generations from exact source
`785cc1eecf05bea484d2be1a54206152c4108685` (tree
`8dd5735985ea087837f73fc0ca882fa2126169a4`) are byte-identical, each with
SHA-256
`fc8a34677a6a7e8e4ae276c24f41339677247887901a98e824506b2fd5be26c8`.
They used the immutable expanded manifest with SHA-256
`09a7bfe5df8a4d78c21144b4d45f584167a1607f412990a60045878227553e43`,
clean Rebar revision `463d00f31887e84c38467805b9e3122c314b9521`,
and the exact Rust and RE2 runners recorded below. The raw generated report
copies remain outside Git at
`/tmp/fre-control/results/P34-CAPTURE-785CC1E-85D-FULL344-R{1,2}.json`.
The checked-in `report.json` continues to preserve the
preceding 144-pass baseline rather than being silently replaced by generated
evidence.

The authenticated current figure is 197. It is not the earlier 200-row capture
screening figure, which incorrectly reset public-job selector budgets for each
line, and it does not include the separately reverted Unicode-compile
experiment. Neither earlier result is current promotion evidence.

## By operation model

| Rebar model | Rust jobs | FRE pass | FRE unsupported | RE2 jobs | RE2 pass |
|---|---:|---:|---:|---:|---:|
| `compile` | 33 | 17 | 16 | 26 | 26 |
| `count` | 133 | 62 | 71 | 109 | 109 |
| `count-spans` | 129 | 101 | 28 | 110 | 110 |
| `count-captures` | 15 | 3 | 12 | 12 | 12 |
| `grep` | 11 | 9 | 2 | 10 | 10 |
| `grep-captures` | 22 | 5 | 17 | 17 | 17 |
| `regex-redux` | 1 | 0 | 1 | 1 | 1 |
| **Total** | **344** | **197** | **147** | **285** | **285** |

FRE has no `fail`, `fault`, or unresolved receipt. Its 180 aggregate-facade
passes comprise 17 `compile`, 62 `count`, and 101 `count-spans` jobs; another
nine use the portable `grep` path and eight use the linear selector plus
persistent capture-history path. All 285 RE2 jobs execute through the
exact pinned Rebar adapter and pass. The Rust reference executes all 344 Rust
jobs, with 342 pass and two retained failures.

The optional v2 executed-plan field splits those passes into 29 exact-literal
aggregate, 132 continuation-program aggregate, two ordered build-many literal
plans, 17 fresh complete compile artifacts using the continuation program, and
nine portable-search rows, plus eight selector/history capture rows. It is
populated only after successful candidate execution and does not infer a plan
for any unsupported receipt.

## Authenticated capture delta

The source adds exactly eight supported jobs to the authenticated 189-pass
baseline, with no removed baseline pass:

- `captures/contiguous-letters@rust/regex`
- `curated/07-unicode-character-data/parse-line@rust/regex`
- `curated/11-unstructured-to-json/extract@rust/regex`
- `opt/onepass/first-three-words-english@rust/regex`
- `test/model/count-captures@rust/regex`
- `test/model/grep-captures@rust/regex`
- `unicode/overlapping-words/ascii@rust/regex`
- `wild/caddy/caddy@rust/regex`

## By benchmark/pattern family

| Family | FRE pass | FRE unsupported | RE2 pass |
|---|---:|---:|---:|
| `captures` | 1 | 0 | 1 |
| `curated` | 29 | 23 | 41 |
| `dictionary` | 1 | 6 | 4 |
| `folly` | 4 | 0 | 4 |
| `grep` | 2 | 1 | 2 |
| `hyperscan` | 14 | 1 | 0 |
| `imported` | 79 | 28 | 107 |
| `opt` | 21 | 14 | 26 |
| `reported` | 7 | 12 | 17 |
| `slow` | 4 | 0 | 4 |
| `test` | 28 | 22 | 46 |
| `unicode` | 6 | 16 | 16 |
| `wild` | 1 | 24 | 17 |
| **Total** | **197** | **147** | **285** |

The target job sets differ because Rebar definitions select engines
independently; columns are not intended to be row-wise equivalents.

## Exact FRE refusal split

The 115 aggregate compile/count/span refusals are fully typed:

- 68 Unicode-feature jobs: 9 `compile`, 42 `count`, and 17 `count-spans`.
  Unicode-on continuation now admits empty/literal/ASCII-range and singleton
  scalar classes, including finite singleton case folds. Non-singleton scalar
  classes and Unicode-word assertions remain typed unsupported.
- 2 ordered build-many `compile` jobs. Pattern cardinality is checked before
  any candidate compilation.
- 45 bounded resource refusals: 5 `compile`, 29 `count`, and 11 `count-spans`.
  These retain exact construction or execution quota diagnostics. Resource
  refusals are not faults and require a better plan, not a silent quota raise.

The other 32 refusals are operation/surface gaps: 29 capture rows, two portable
`grep` syntax gaps, and one `regex-redux`. Capture refusals split exactly into
17 Unicode-lowering gaps, two unsupported look assertions, one ordered
build-many gap, and nine bounded selector-work refusals. The two `grep` jobs
remain:

- `grep/long-words-unicode@rust/regex`: Unicode word-boundary assertion.
- `wild/ruff/unnecessary-coding-comment@rust/regex`: variable-width Unicode
  scalar class lowering.

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
exact-literal rows, eight newly admitted byte-stable Unicode continuation rows,
twelve aggregate ASCII-word/LF assertion rows, the two corresponding portable
`grep` rows, two ordered build-many rows, the eight capture-history rows, and
all selected
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

1. Extend the reusable Unicode-on continuation and capture compiler with
   explicit variable-width
   UTF-8 semantics and independent differential qualification for the remaining
   68 aggregate and 17 capture Unicode-feature refusals. Do not weaken
   singleton-only admission.
2. Introduce faster bounded aggregate plans for the 45 aggregate resource
   refusals. The
   exact-literal reducer advanced `imported/leipzig/twain` without changing a
   quota and preserves the construction-time choice/no-fallback contract; the
   remaining refusals require other semantic shapes.
3. Run the preregistered pointwise capture performance gate on all four
   currently supported regimes before optimizing a favorite subset. Use
   allocations and selector/history counters to choose shared improvements;
   do not publish a four-cell suite geomean.
4. Extend the ordered build-many plan/API to the two remaining compile jobs.
   Never emulate priority by concatenating patterns; retain the named adverse
   performance follow-up for the two admitted execution rows.
5. Qualify cold and allocator-warm construction performance for the seventeen
   supported compile rows, keeping construction separate from untimed semantic
   verification. Extend only the reusable Unicode/resource/build-many mechanisms
   to the other sixteen rows.
6. Reduce selector work for the three near-bound cumulative-ledger refusals
   (`ruff-noqa/real`, `ruff-noqa/tweaked`, and `fn-predicate`) and then address
   the six much larger selector shapes with a reusable plan. Each row must earn
   admission within the existing public-job limits; do not raise quotas.
7. Admit the composite `regex-redux` job only after its complete report,
   replacement, and non-empty iteration semantics are implemented.

Each retained generated report has SHA-256
`fc8a34677a6a7e8e4ae276c24f41339677247887901a98e824506b2fd5be26c8`,
and its sorted-receipts SHA-256 is
`e108451aeef37bf0dacd3bfded66f0a5cd8a77fde3e832476acd26a1b27c791b`.
