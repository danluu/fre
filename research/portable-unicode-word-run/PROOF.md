# Linear portable Unicode word runs

Status: semantically accepted source at exact head
`639656f256f9a39d0682d47552fa581af2e72cce` (tree
`9aaef07fd9532636a8d246ceead355d0f07cf184`), based on canonical
`60e97792ae69c00b052ae268ba99470cf87bf995`. No benchmark claim is made.

## Construction and execution proof

The facade construction-selects `unicode-word-run-linear-v1` only for the exact
greedy HIR shape `WordUnicode + UnicodePerlWord{m,} + WordUnicode`, with
`m > 0`. The class is compared to the pinned parser's canonical `\w` class;
negated, lazy, bounded, start/end/half, CRLF, and all other shapes retain their
existing plans or typed refusals. Forced K0 remains available for differential
qualification.

Search decodes each canonical scalar at most a constant number of times and
advances one byte on invalid UTF-8. It classifies scalars with the pinned UTS#18
Annex C Perl-word table and observes word context outside a requested search
window while never consuming outside it. Invalid, overlong, truncated,
surrogate, and stray continuation bytes are non-word context. The plan performs
no allocation during search, stores only the minimum scalar count, exposes
checked work and byte/scalar counters, and reuses the native no-workspace
session path. Runtime work is linear in the requested window bytes.

## Qualification

- Red-first exact-plan and all-window specifications: PASS.
- Full portable facade: 11/11 PASS.
- Comparator library: 20/20 PASS.
- Strict affected all-target Clippy: PASS.
- Workspace formatting check: PASS.
- Exact all-window word-run matrix: 0.04 seconds in the debug test harness.
  The preceding generic K0 matrix took about 1.11 seconds on its broader three-
  pattern matrix, and its full generation was stopped after 16:38. This is a
  cheap anti-pathology screen, not a formal cross-engine timing result.

## Authenticated Rebar frontier

The deterministic full generation uses manifest SHA-256
`09a7bfe5df8a4d78c21144b4d45f584167a1607f412990a60045878227553e43`,
Rust runner SHA-256
`8ef7a4a47264c584c02432a70f7e917c1aab2639451f0ba42da0ef04041951fc`,
RE2 runner SHA-256
`42a53794bc7a1a911484b84dd239b625e7241c8aca41b28d677ca76686266d4b`,
and comparator SHA-256
`fcc477903b5b6a91eb140121a789ca1fbff9a7c6d99a317d036bc11c5784f4c0`.

The report
`/tmp/fre-control/results/G0-REBAR-UNICODE-WORD-RUN-639656F-FRONTIER-001.json`
has SHA-256
`f1f40ff23aa316fc69fd32b5bb9c508d7085f0b91b360baea7387dd66c23273e`
and sorted-receipts SHA-256
`6122094efae0d307e458ca8f07243f73bee0a1e31938610b4b386bbebd2d6fca`.
FRE has 238 pass / 106 unsupported, no fail or fault. `grep` is 11/0. The
single delta is `grep/long-words-unicode@rust/regex`: expected and actual are
both 5,075, with `portable-single-search` identity.

Promotion retains a named follow-up: collect pointwise immutable timings for
the exact long-word row plus neighboring ASCII grep and Unicode scalar-class
rows against pinned Rust and valid RE2 targets. Do not publish a suite geomean
from this semantic receipt.

## Candidate aggregate direct extension

The aggregate facade now construction-selects the same allocation-free scalar
stream for canonical positive word runs with a required minimum and an
optional maximum. The admitted HIR is exactly `\w{m,n}`, `\b\w{m,n}`,
`\w{m,n}\b`, or `\b\w{m,n}\b`, modulo transparent captures, with `m > 0`.
The class and boundary must both be canonical ASCII or both canonical Unicode.
All other HIR continues to the existing scalar/continuation selection, and
forced continuation is unchanged. Count, matched-byte sum, and compile-model
verification use the direct reducer; materialized spans remain outside this
route.

Let `N` be input bytes and `Q` be canonical HIR nodes. Construction is `O(Q)`.
Execution is `O(N)`: the forward stream advances after every decoded scalar or
invalid byte; an end-boundary-only bounded run may replay its selected suffix
once, so no input byte participates in more than a constant number of decodes.
There is no boundary/state table, state set, pattern loop, or `N * Q` term.
Persistent storage is `size_of::<Plan>()`, dynamic scratch is zero, and output
is two scalar reducers (`count` and matched bytes). Invalid, truncated,
overlong, surrogate, and stray continuation bytes are non-word separators.
Full-haystack boundary context is consulted without consuming outside the
operation. Because `m > 0`, every emitted match is nonempty and progress is its
exclusive end.

Focused qualification covers ASCII/Unicode modes, zero/one/two boundaries,
bounded and unbounded repetition, hostile invalid bytes, truncated scalars,
outside-window word context, direct compile/count/span-sum identity, exact work
refusal, and an N/2N structural counter. No cross-engine semantic verifier is
part of this candidate.

### Preregistered pointwise matrix

Window 3 should measure each affected cell below against Rust regex and RE2
where the epoch inventory marks a comparator available, at identical compiled
patterns and haystacks. It should retain construction outside Count/SpanSum
samples, separately sample Compile, use N/2N/4N haystacks, and report every
cell rather than a geomean-only result.

| role | row | family | model | Rust | RE2 |
|---|---|---|---|---|---|
| affected | `curated/08-words/all-russian@rust/regex` | curated | count-spans | yes | no |
| affected | `curated/08-words/long-russian@rust/regex` | curated | count-spans | yes | no |
| affected | `hyperscan/fixed-length-words-unicode-nosom@rust/regex` | hyperscan | count | yes | no |
| affected | `unicode/word/boundary-any-russian@rust/regex` | unicode | count-spans | yes | no |
| affected | `unicode/word/boundary-long-russian@rust/regex` | unicode | count-spans | yes | no |
| neighbor | `curated/08-words/all-english@rust/regex` | curated | count-spans | yes | yes |
| neighbor | `hyperscan/fixed-length-words-nosom@rust/regex` | hyperscan | count | yes | no |
| neighbor | `grep/long-words-unicode@rust/regex` | grep | grep | yes | no |
