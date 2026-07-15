# Rebar semantic coverage frontier

This is the compact source checkpoint for the latest authenticated per-job
frontier. A full generation from exact composed source
`35b22acf7db5ebf63992085a4ad3782a9e46f139` (tree
`b63266c7be97e82b565bf2b9ce78d9608536a2a9`) has SHA-256
`132e6c75034fe6ff720af3511eca8779ebb0dd9266c243dbc9061a5157209607`.
It used the immutable expanded manifest with SHA-256
`09a7bfe5df8a4d78c21144b4d45f584167a1607f412990a60045878227553e43`,
clean Rebar revision `463d00f31887e84c38467805b9e3122c314b9521`,
and the exact Rust and RE2 runners recorded below. The raw generated report
remains outside Git. The checked-in `report.json` continues to preserve the
preceding 144-pass baseline rather than being silently replaced by generated
evidence.

## By operation model

| Rebar model | Rust jobs | FRE pass | FRE unsupported | RE2 jobs | RE2 pass |
|---|---:|---:|---:|---:|---:|
| `compile` | 33 | 17 | 16 | 26 | 26 |
| `count` | 133 | 62 | 71 | 109 | 109 |
| `count-spans` | 129 | 101 | 28 | 110 | 110 |
| `count-captures` | 15 | 0 | 15 | 12 | 12 |
| `grep` | 11 | 9 | 2 | 10 | 10 |
| `grep-captures` | 22 | 0 | 22 | 17 | 17 |
| `regex-redux` | 1 | 0 | 1 | 1 | 1 |
| **Total** | **344** | **189** | **155** | **285** | **285** |

FRE has no `fail` or `fault` receipt. Its 180 aggregate-facade passes comprise
17 `compile`, 62 `count`, and 101 `count-spans` jobs; the other nine passes are
the portable `grep` path. All 285 RE2 jobs execute through the
exact pinned Rebar adapter and pass. The Rust reference executes all 344 Rust
jobs, with 342 pass and two retained failures.

### Unvalidated regex-redux source projection

The source composition now layers the complete reusable `regex-redux`
candidate over the direct-scalar, breadth, and bounded capture-history source
union, but has not generated a comparison report. Its exact projected delta is
one row from unsupported to pass: `regex-redux +1`, total pass `+1`, total
unsupported `-1`. The scalar-plus-breadth ceiling is 228 rows, and capture has
at most 22 statically eligible rows before syntax/resource classification, so
the positive Unicode-word boundary contributes exactly one additional projected
`grep` row. The combined arithmetic ceiling is therefore at most 252 pass / 92
unsupported. This is an evaluation bound, not observed coverage and not a
claim that all 22 capture rows pass.

The candidate freshly constructs all fifteen ordered Unicode-off continuation
components, retains the nine report patterns and five substitutions in exact
protocol order, rejects empty replacement matches, and preflights bounded work
and exact-capacity allocation. It does not inspect a job ID, fixture hash, or
expected reducer.

The optional v2 executed-plan field splits those passes into 29 exact-literal
aggregate, 132 continuation-program aggregate, two ordered build-many literal
plans, 17 fresh complete compile artifacts using the continuation program, and
nine portable-search rows. It is
populated only after successful candidate execution and does not infer a plan
for any unsupported receipt.

### Unvalidated scalar-plus-breadth projection

Canonical base `bf53ce82a17df0351d9e7a936271e5ebfa8c9635` has an independently
authenticated direct-scalar frontier of 214 pass / 130 unsupported, recorded
in `../../aggregate/UNICODE_SCALAR_STREAM.md`. The accepted breadth source at
`0b1c15b0792983f42a194ad33a936185d7e5acb7` contributes three separately
qualified mechanisms, but this composition has not generated a report.

The overlap-aware arithmetic ceiling is 228 pass / 116 unsupported. It adds
nine compile-artifact rows after excluding the two compile rows already owned
by the direct scalar plan (`unicode/compile/negated-class-matches-codepoint`
and `unicode/compile/one-letter`), four cardinality-disjoint Unicode-off finite
`count` rows, and one portable Unicode-class `grep` row: `214 + 9 + 4 + 1`.
This is a projected ceiling only. It assumes no lost disposition and is not
observed coverage, semantic qualification of the composition, or benchmark
evidence.

## By benchmark/pattern family

| Family | FRE pass | FRE unsupported | RE2 pass |
|---|---:|---:|---:|
| `captures` | 0 | 1 | 1 |
| `curated` | 27 | 25 | 41 |
| `dictionary` | 1 | 6 | 4 |
| `folly` | 4 | 0 | 4 |
| `grep` | 2 | 1 | 2 |
| `hyperscan` | 14 | 1 | 0 |
| `imported` | 79 | 28 | 107 |
| `opt` | 20 | 15 | 26 |
| `reported` | 7 | 12 | 17 |
| `slow` | 4 | 0 | 4 |
| `test` | 26 | 24 | 46 |
| `unicode` | 5 | 17 | 16 |
| `wild` | 0 | 25 | 17 |
| **Total** | **189** | **155** | **285** |

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

The other 40 refusals are operation/surface gaps: 22 `grep-captures`, 15
`count-captures`, two portable `grep` syntax gaps, and one `regex-redux`. The
two `grep` jobs remain:

- `grep/long-words-unicode@rust/regex`: Unicode word-boundary assertion.
- `wild/ruff/unnecessary-coding-comment@rust/regex`: variable-width Unicode
  scalar class lowering.

## Correctness adversaries now admitted

Every executed candidate receipt passes, including the prior Unicode
exact-literal rows, eight newly admitted byte-stable Unicode continuation rows,
twelve aggregate ASCII-word/LF assertion rows, the two corresponding portable
`grep` rows, two ordered build-many rows, and all selected
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

1. Extend the reusable Unicode-on continuation with explicit variable-width
   UTF-8 semantics and independent differential qualification for the remaining
   68 Unicode-feature refusals. Do not weaken singleton-only admission.
2. Introduce faster bounded aggregate plans for the 45 aggregate resource
   refusals. The
   exact-literal reducer advanced `imported/leipzig/twain` without changing a
   quota and preserves the construction-time choice/no-fallback contract; the
   remaining refusals require other semantic shapes.
3. Apply the stratified pointwise performance gate to the two newly admitted
   portable ASCII-word/LF `grep` rows and two relevant unchanged neighbors.
   Retain typed refusals for Unicode word state and variable-width Unicode
   scalar lowering until their own semantic and performance gates pass.
4. Extend the ordered build-many plan/API to the two remaining compile jobs.
   Never emulate priority by concatenating patterns; retain the named adverse
   performance follow-up for the two admitted execution rows.
5. Qualify cold and allocator-warm construction performance for the seventeen
   supported compile rows, keeping construction separate from untimed semantic
   verification. Extend only the reusable Unicode/resource/build-many mechanisms
   to the other sixteen rows.
6. Add capture histories for the 37 capture reducer jobs; whole-match capture
   erasure is not a capture API.
7. Authenticate the source-complete composite `regex-redux` projection with a
   fresh full comparison, then qualify its whole fresh-build operation rather
   than diagnostic component timings.

The retained generated report SHA-256 is
`132e6c75034fe6ff720af3511eca8779ebb0dd9266c243dbc9061a5157209607`,
and its sorted-receipts SHA-256 is
`106dce03fad55de68e32ef9bdf8be0541918119a8e189b9243fd1f4deec4df48`.

## Source-only combined portable projection

The later mechanisms in `research/portable-unicode-classes/PROOF.md` and
`research/portable-unicode-word-boundary/PROOF.md` are not included in the
authenticated tables above. The exact combined source contains both canonical
valid-UTF-8 Unicode scalar-class lowering and the positive `WordUnicode` look
in portable K0. It retains typed refusals for negated/start/end/half Unicode
looks and CRLF assertions.

Relative to the accepted breadth source, the positive-boundary composition
projects exactly one additional Rebar beneficiary:
`grep/long-words-unicode@rust/regex`. The breadth source separately projects
`wild/ruff/unnecessary-coding-comment@rust/regex` through its scalar-class
mechanism. Neither row changes the authenticated tables above. Both require
fresh combined semantic qualification and a complete authenticated generation
before any coverage statement; this remains a source projection, not coverage
or performance evidence.
