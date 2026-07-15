# Rebar semantic coverage frontier

This is the compact source checkpoint for the latest authenticated per-job
frontier. Two full generations from final candidate source
`ad902c997d5a35c8cf567091fbccbc4a1ffabc66` were byte-identical with SHA-256
`50d87ceabdb147f0900651cb6bf49f5fc894442ac41a9a87a54d28c610fd62e5`.
That exact source tree (`534d0351dceb370df2c8847392a873485a70d753`)
is canonical commit `ad902c997d5a35c8cf567091fbccbc4a1ffabc66`.
Those raw generated reports remain outside Git. The checked-in `report.json`
continues to preserve the preceding 144-pass baseline rather than being
silently replaced by generated evidence.

## By operation model

| Rebar model | Rust jobs | FRE pass | FRE unsupported | RE2 jobs | RE2 pass |
|---|---:|---:|---:|---:|---:|
| `compile` | 33 | 16 | 17 | 26 | 26 |
| `count` | 133 | 54 | 79 | 109 | 109 |
| `count-spans` | 129 | 100 | 29 | 110 | 110 |
| `count-captures` | 15 | 0 | 15 | 12 | 12 |
| `grep` | 11 | 9 | 2 | 10 | 10 |
| `grep-captures` | 22 | 0 | 22 | 17 | 17 |
| `regex-redux` | 1 | 0 | 1 | 1 | 1 |
| **Total** | **344** | **179** | **165** | **285** | **285** |

FRE has no `fail` or `fault` receipt. Its 170 aggregate-facade passes comprise
16 `compile`, 54 `count`, and 100 `count-spans` jobs; the other nine passes are
the portable `grep` path. All 285 RE2 jobs execute through the
exact pinned Rebar adapter and pass. The Rust reference executes all 344 Rust
jobs, with 342 pass and two retained failures.

The optional v2 executed-plan field splits those passes into 29 exact-literal
aggregate, 125 continuation-program aggregate, 16 fresh complete compile
artifacts using the continuation program, and nine portable-search rows. It is
populated only after successful candidate execution and does not infer a plan
for any unsupported receipt.

## By benchmark/pattern family

| Family | FRE pass | FRE unsupported | RE2 pass |
|---|---:|---:|---:|
| `captures` | 0 | 1 | 1 |
| `curated` | 25 | 27 | 41 |
| `dictionary` | 0 | 7 | 4 |
| `folly` | 4 | 0 | 4 |
| `grep` | 2 | 1 | 2 |
| `hyperscan` | 12 | 3 | 0 |
| `imported` | 79 | 28 | 107 |
| `opt` | 17 | 18 | 26 |
| `reported` | 7 | 12 | 17 |
| `slow` | 4 | 0 | 4 |
| `test` | 24 | 26 | 46 |
| `unicode` | 5 | 17 | 16 |
| `wild` | 0 | 25 | 17 |
| **Total** | **179** | **165** | **285** |

The target job sets differ because Rebar definitions select engines
independently; columns are not intended to be row-wise equivalents.

## Exact FRE refusal split

The 108 aggregate refusals are fully typed:

- 73 general Unicode-enabled jobs: 51 `count`, 22 `count-spans`. Five of the
  original 78 Unicode-gated rows now pass through the independently checked
  nonempty exact-UTF-8-literal path; broader Unicode continuation execution
  remains typed unsupported.
- 5 ordered build-many jobs: 3 `count`, 2 `count-spans`. Pattern cardinality is
  checked before any candidate compilation.
- 30 bounded resource refusals. For `count`, 22 exceed the 536,870,912
  operation-work quota, two exceed the 134,217,728-byte row-log quota, and one
  exceeds the 1,000 repeat bound. For `count-spans`, three exceed operation
  work and two exceed the 4,096-node compile quota. Twelve of the fourteen
  former assertion refusals now pass; `imported/leipzig/word-ending-nn` and
  `curated/13-noseyparker/single` reach these later resource gates. Resource
  refusals are not faults and require a better plan, not a silent quota raise.

The other 57 refusals are operation/surface gaps: 17 `compile`, 22
`grep-captures`, 15 `count-captures`, two portable `grep` syntax gaps, and one
`regex-redux`. The remaining compile rows split into twelve Unicode-enabled
inputs, three bounded-resource refusals, and two ordered build-many inputs. The
two `grep` jobs remain:

- `grep/long-words-unicode@rust/regex`: Unicode word-boundary assertion.
- `wild/ruff/unnecessary-coding-comment@rust/regex`: variable-width Unicode
  scalar class lowering.

## Correctness adversaries now admitted

Every executed candidate receipt passes, including five Unicode exact-literal
rows, twelve aggregate ASCII-word/LF assertion rows, the two corresponding
portable `grep` rows, and all selected
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
   semantics and independent differential qualification for the remaining 73
   aggregate and twelve compile-model general-Unicode refusals.
2. Introduce faster bounded aggregate plans for the 30 aggregate and three
   compile-model resource refusals. The
   exact-literal reducer advanced `imported/leipzig/twain` without changing a
   quota and preserves the construction-time choice/no-fallback contract; the
   remaining refusals require other semantic shapes.
3. Apply the stratified pointwise performance gate to the two newly admitted
   portable ASCII-word/LF `grep` rows and two relevant unchanged neighbors.
   Retain typed refusals for Unicode word state and variable-width Unicode
   scalar lowering until their own semantic and performance gates pass.
4. Add ordered build-many as its own semantic plan/API, beginning with the five
   aggregate and two compile-model jobs. Never emulate priority by concatenating
   patterns.
5. Qualify cold and allocator-warm construction performance for the sixteen
   supported compile rows, keeping construction separate from untimed semantic
   verification. Extend only the reusable Unicode/resource/build-many mechanisms
   to the other seventeen rows.
6. Add capture histories for the 37 capture reducer jobs; whole-match capture
   erasure is not a capture API.
7. Admit the composite `regex-redux` job only after its complete report,
   replacement, and non-empty iteration semantics are implemented.

Two consecutive full generations were byte-identical. The retained generated
report SHA-256 is
`50d87ceabdb147f0900651cb6bf49f5fc894442ac41a9a87a54d28c610fd62e5`,
and its sorted-receipts SHA-256 is
`fb175f63514a79075c4ddf696d512097ed53ec74ae1496d1d86cf44cf0fe878d`.
