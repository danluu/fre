# Direct Unicode counted continuation

`PORTFOLIO_PROFILE=unicode-continuation-direct-a` uses mechanism
`unicode-continuation`, variant `direct-scalar`. The construction-selected
route now covers a canonical root Unicode scalar class under any non-nullable
counted or lower-bounded repetition. Nullable, asserted, concatenated and
alternating HIR remains on its pre-existing route. Exact literals, finite
languages, K0 plans, root scalar atoms and the existing `CLASS+` specialization
are selected first and retain their identities.

## Invariant and bounds

The reducer decodes each byte-window position once. Invalid, overlong,
surrogate, out-of-range and truncated encodings advance one byte and never
enter a class run. A matching scalar updates only `(run_scalars, run_bytes)`.
Greedy finite repetition emits at its symbolic maximum and emits a terminal
run only at its minimum; greedy lower-bounded repetition emits once at the
first outsider. Lazy repetition emits whenever its minimum is reached. These
are exactly the leftmost-first non-overlapping choices for a root repetition
of one class. No UTF-8 expansion, boundary/state set, suffix restart, pattern
loop or reference-engine execution exists in the operation.

For `N` window bytes and `R` retained canonical non-ASCII ranges, construction
retains `O(R)` bytes and execution uses zero dynamic scratch. The immutable
Unicode scalar domain bounds a membership decision to the ASCII bitmap or a
bounded range lookup; execution performs at most `4N` decode-byte checks, `N`
membership probes, `N+1` reducer transitions and `N` match events. Thus the
production stream is linear in `N` for the fixed Unicode domain, with `O(R)`
one-time construction/storage, and never performs `N * R`, `N * states`, or
`N * patterns` work. Exact counters and preflight limits cover every term.

The focused N-scaling gate uses the hostile mixed unit
`abcd!αβ<invalid>-` at 8, 16 and 32 copies. It requires exact doubling of
input advance, decode checks, range comparisons and match events, exact
doubled reducer transitions after subtracting the single terminal transition,
and zero scratch at all sizes. Focused semantics cover greedy/lazy bounded,
fixed and lower-bounded forms; early, late and absent matches; multibyte
scalars; invalid and truncated bytes; count, span sum and retained compile
artifact verification. Nullable repetitions remain an explicit continuation
neighbor.

## Preregistered pointwise gate

Window 3, not a source worker, runs the following affected/neighbor matrix.
Every row is pointwise against Rust regex and RE2 where the authenticated
inventory marks RE2 available. Each cell runs retained-artifact execution at
three input sizes (`N`, `2N`, `4N`) and early/late/absent placement; compile
rows additionally measure fresh construction and retained verification
separately. No suite geomean may hide a regression.

| Role | Row | Model | Rust | RE2 |
| --- | --- | --- | --- | --- |
| affected | `imported/leipzig/math-symbols@rust/regex` | count | yes | yes |
| affected | `imported/rsc/match-class-unicode@rust/regex` | count-spans | yes | yes |
| affected | `opt/fixed-length/too-big-unicode@rust/regex` | count | yes | no |
| affected | `opt/fixed-length/too-small-unicode@rust/regex` | count | yes | no |
| affected | `opt/nfa-sparse/small-repeated-class-unicode@rust/regex` | count | yes | no |
| affected | `test/unicode/decimal/unicode@rust/regex` | count | yes | yes |
| affected | `test/unicode/letter/pL-matches-bmp-delta@rust/regex` | count | yes | yes |
| affected | `test/unicode/utf8/dot-matches-codepoint@rust/regex` | count | yes | yes |
| affected | `unicode/codepoints/any-all@rust/regex` | count-spans | yes | yes |
| affected | `unicode/codepoints/any-one@rust/regex` | count | yes | yes |
| affected | `unicode/compile/fifty-letters@rust/regex` | compile | yes | yes |
| affected | `unicode/compile/one-letter@rust/regex` | compile | yes | yes |
| neighbor | `curated/01-literal/sherlock-zh@rust/regex` | count | yes | yes |
| neighbor | `unicode/word/boundary-any-russian@rust/regex` | count-spans | yes | no |

This is a performance-debt-open screening plan. The legacy scalar route is
known to be slow, direct scalar pointwise timing is absent, and this source
change makes no speed claim. The expected effect is to replace bounded
continuation construction/execution with one allocation-free operation stream
while leaving whether that improves any pointwise cell to the serialized gate.
