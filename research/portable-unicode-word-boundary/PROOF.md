# Portable positive Unicode word boundary

Status: source-only composition onto exact accepted breadth head
`f85cdfda7bc3968f6910d122bb4cffe32db47dbd` (tree
`260ab9e1ca6d3e4979e50dcf5deab3a572d57c8b`), replaying the accepted positive
Unicode word-boundary core from
`aca57f7392d80a4150649db829df6dbc7de667f7`. No compiler, formatter, test,
build, assembly, benchmark, or generated Rebar report was run for this
checkpoint.

## Exact predicate

K0 adds one zero-width graph edge for `regex_syntax::hir::Look::WordUnicode`.
At absolute byte boundary `p`, let `L` be the complete Unicode scalar whose
canonical UTF-8 encoding ends exactly at `p`, if one exists, and let `R` be the
complete scalar whose encoding begins exactly at `p`, if one exists. Each
scalar is a word character exactly when the workspace-pinned `regex-syntax`
0.8.11 `unicode-perl` table classifies it under the UTS#18 Annex C definition.
The edge is enabled exactly when `word(L) XOR word(R)`.

A missing, malformed, overlong, surrogate, out-of-range, or truncated side is
non-word. At a position inside a valid multi-byte scalar, neither an encoding
ending there nor one beginning there is complete, so the positive boundary is
false. Conversely, invalid bytes next to a valid word scalar do form a
boundary. This matches the pinned Rust bytes-regex behavior and never treats a
continuation byte as an independent character.

Assertions inspect the full original haystack even for a ranged search. They
may classify context immediately outside the requested window, while consuming
edges remain confined to the window and reported offsets remain absolute.

## Bounded execution

Forward decoding reads at most four bytes beginning at `p`; reverse decoding
examines at most four bytes ending at `p`. Both use fixed local state and
`core::str::from_utf8` over the bounded slice. Word classification performs a
bounded lookup in an immutable, compile-time Unicode table. Search performs no
allocation, recursion, cache initialization, or input-sized side scan.

The existing logical work unit charges every assertion-edge inspection once.
The fixed-width decodes and fixed-table lookup are the bounded predicate for
that edge, analogous to the constant adjacent-byte work already covered by an
ASCII assertion charge. K0's conservative edge/boundary work certificate and
fixed workspace dimensions are therefore unchanged.

If the pinned table feature were unexpectedly unavailable, execution returns
an internal invariant error; it does not classify the scalar as ASCII or
non-word and continue.

## Narrow admission and typed refusals

Only positive `WordUnicode` maps to the new edge. `WordUnicodeNegate`, Unicode
word start/end, both Unicode half assertions, `StartCRLF`, and `EndCRLF` retain
typed `UnsupportedFeature::LookAssertion` errors. This is deliberate: the
negated and half assertions have additional malformed/interior UTF-8 rules and
are not inferred by negating the positive predicate.

The accepted breadth base already supplies canonical valid-UTF-8 Unicode
scalar-class lowering. Thus `\b(?-u:[A-Za-z]{2,})\b` exercises the boundary
mechanism with a locally byte-stable body, while the exact target
`\b\w{25,}\b` exercises the composed boundary and scalar-class mechanisms. No
fallback or pattern-specific route is introduced. Scalar aggregate execution,
Unicode compile fallback, finite-language plans, and other portable-class
routes remain independently selected and unchanged.

## Directed source specifications

Tests are committed before implementation. The automata layer pins boundaries
around one-to-four-byte word scalars, ASCII, combining-mark, join-control,
multi-byte symbols, invalid, overlong, and surrogate byte sequences, including
every interior byte position and the conservative work certificate. Lowering
pins the distinct edge mapping and all remaining typed look refusals. The
facade compares a Unicode-boundary pattern with a locally byte-stable body
against pinned `regex-automata` 0.4.14 over every range of valid and invalid
haystacks.

These specifications have not been executed in this source-only lane.

## Exact Rebar projection

The immutable expanded manifest is `fre.rebar.expanded.v1`, SHA-256
`09a7bfe5df8a4d78c21144b4d45f584167a1607f412990a60045878227553e43`,
from clean Rebar revision `463d00f31887e84c38467805b9e3122c314b9521`.

Relative to the accepted breadth source, this exact composition projects one
additional row:

- `grep/long-words-unicode@rust/regex`, pattern `\b\w{25,}\b`, pattern blob
  SHA-256
  `fc8ac2dd7d0956da04a9837cc773ef39fcc597b02a9baee03733d2bf3ce3d5fd`,
  valid-UTF-8 haystack SHA-256
  `7d43cc8dfd053b083b809bd7ce7d4a074f2fd24a6b7ec38908b3966f3324fa36`,
  authenticated expected grep count 5,075.

The breadth source separately projects
`wild/ruff/unnecessary-coding-comment@rust/regex` through its portable Unicode
scalar-class mechanism. Fresh combined validation and a complete authenticated
generation are required before either projection becomes a coverage statement;
separate measurement is required before any performance statement.
