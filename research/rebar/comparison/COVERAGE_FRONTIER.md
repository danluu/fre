# Rebar semantic coverage frontier

This is a compact index into the exact per-job receipts in `report.json`.
Counts below are derived from that report; it remains authoritative for every
job ID, expected result, actual result, and refusal reason.

## By operation model

| Rebar model | Rust jobs | FRE pass | FRE unsupported | RE2 jobs | RE2 pass |
|---|---:|---:|---:|---:|---:|
| `compile` | 33 | 0 | 33 | 26 | 26 |
| `count` | 133 | 48 | 85 | 109 | 109 |
| `count-spans` | 129 | 89 | 40 | 110 | 110 |
| `count-captures` | 15 | 0 | 15 | 12 | 12 |
| `grep` | 11 | 7 | 4 | 10 | 10 |
| `grep-captures` | 22 | 0 | 22 | 17 | 17 |
| `regex-redux` | 1 | 0 | 1 | 1 | 1 |
| **Total** | **344** | **144** | **200** | **285** | **285** |

FRE has no `fail` or `fault` receipt. Its 137 aggregate passes comprise 48
`count` and 89 `count-spans` jobs; the other seven passes are the pre-existing
portable `grep` path. All 285 RE2 jobs execute through the exact pinned Rebar
adapter and pass. The Rust reference executes all 344 Rust jobs, with 342 pass
and two retained failures.

The optional v2 executed-plan field splits those passes into 24 exact-literal
aggregate, 113 continuation-program aggregate, and seven portable-search rows.
It is populated only after successful candidate execution and does not infer a
plan for any unsupported receipt.

## By benchmark/pattern family

| Family | FRE pass | FRE unsupported | RE2 pass |
|---|---:|---:|---:|
| `captures` | 0 | 1 | 1 |
| `curated` | 12 | 40 | 41 |
| `dictionary` | 0 | 7 | 4 |
| `folly` | 4 | 0 | 4 |
| `grep` | 1 | 2 | 2 |
| `hyperscan` | 8 | 7 | 0 |
| `imported` | 77 | 30 | 107 |
| `opt` | 15 | 20 | 26 |
| `reported` | 1 | 18 | 17 |
| `slow` | 4 | 0 | 4 |
| `test` | 22 | 28 | 46 |
| `unicode` | 0 | 22 | 16 |
| `wild` | 0 | 25 | 17 |
| **Total** | **144** | **200** | **285** |

The target job sets differ because Rebar definitions select engines
independently; columns are not intended to be row-wise equivalents.

## Exact FRE refusal split

The 125 aggregate refusals are fully typed:

- 78 Unicode-enabled jobs: 55 `count`, 23 `count-spans`. The byte-only
  production boundary refuses Unicode mode before parsing, including empty or
  ASCII-looking patterns.
- 5 ordered build-many jobs: 3 `count`, 2 `count-spans`. Pattern cardinality is
  checked before any candidate compilation.
- 14 unsupported assertion jobs: four `count` ASCII word-boundary jobs and ten
  `count-spans` jobs (nine ASCII word boundaries and one LF-aware end anchor).
- 28 bounded resource refusals. For `count`, 21 exceed the 536,870,912 operation
  work quota and two exceed the 134,217,728-byte row-log quota. For
  `count-spans`, three exceed operation work and two exceed the 4,096-node
  compile quota. These are not faults and must be addressed by a better plan or
  an explicitly re-qualified policy, not by silently retrying with larger
  limits.

The other 75 refusals are operation/surface gaps: 33 `compile`, 22
`grep-captures`, 15 `count-captures`, four portable `grep` syntax gaps, and one
`regex-redux`. The four `grep` jobs remain:

- `grep/long-words-ascii@rust/regex`: ASCII word-boundary assertion.
- `grep/long-words-unicode@rust/regex`: Unicode word-boundary assertion.
- `opt/accelerate/whole-line@rust/regex`: LF-aware start assertion.
- `wild/ruff/unnecessary-coding-comment@rust/regex`: variable-width Unicode
  scalar class lowering.

## Correctness adversaries now admitted

Every newly executed candidate receipt passes, including all selected
`curated/14-quadratic`, `slow/quadratic-*`, `opt/reverse-inner/no-quadratic-*`,
and `opt/reverse-suffix/no-quadratic` jobs. The directed facade suite also locks
nullable/empty iteration, late priority fallback `(?:a+b|a)` over `a^N`,
captures erased only for whole-match output, invalid bytes, case folding, and
full-original-haystack anchor context under both continuation strategies and
forced exact/continuation plan policies. Exact-literal unit differentials cover
empty needles, overlaps, arbitrary invalid bytes, nested captures, canonical
HIR eligibility, and every nonzero build/reducer quota at and one below.

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

1. Add Unicode-enabled Rust-byte lowering with explicit variable-width UTF-8
   semantics and independent differential qualification (78 jobs).
2. Introduce faster bounded aggregate plans for the 28 resource refusals. The
   exact-literal reducer advanced `imported/leipzig/twain` without changing a
   quota and preserves the construction-time choice/no-fallback contract; the
   remaining refusals require other semantic shapes.
3. Implement ASCII word boundaries and LF-aware anchors for the 14 aggregate
   assertion refusals and four portable grep gaps.
4. Add ordered build-many as its own semantic plan/API, beginning with the five
   aggregate jobs. Never emulate priority by concatenating patterns.
5. Add the 33 compile-model receipts without hiding candidate work outside the
   measured/verified contract.
6. Add capture histories for the 37 capture reducer jobs; whole-match capture
   erasure is not a capture API.
7. Admit the composite `regex-redux` job only after its complete report,
   replacement, and non-empty iteration semantics are implemented.

Two consecutive full generations were byte-identical. The report SHA-256 is
`6a9e599ef7b3e2edeeec42dbad208e4a10f206a321f8f36e76bff3871f26b336` and its
sorted-receipts SHA-256 is
`23b072ac9cbcd6798bf76eaa39ffc7d45aea26115036f18dd2c185566f40f3d4`.
