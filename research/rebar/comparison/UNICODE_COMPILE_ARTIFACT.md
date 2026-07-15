# Unicode compile-artifact checkpoint

The exact source checkpoint is
`16308239f29555890fcf1601ab68b70e33aa0f17` (tree
`ea09793a170546ec64b0f938de3052ef9421bc19`). It extends only the one-pattern
Rebar `compile` surface. It does not add Unicode execution to `count`,
`count-spans`, grep, or capture reducers, and it makes no timing claim.

For the exact pinned Rust bytes/Rebar profile, construction parses canonical
HIR and preflights a deterministic preorder artifact. Literal scalars and both
endpoints of every scalar-class range are retained in their canonical 1–4 byte
UTF-8 encodings. Locally byte-oriented literals that contain invalid UTF-8 and
byte classes extending above ASCII are typed refusals. The full artifact byte
count, scalar count, and construction work are checked before artifact storage
is requested. The returned immutable artifact has no deferred parser,
lowerer, or allocation step and verifies its framing, scalar encodings, count,
and identity before publication.
The Rebar adapter exposes a separate 100 MiB artifact quota aligned with the
pinned upstream Thompson-NFA size boundary instead of silently borrowing the
smaller runtime continuation-program quota.

The comparator constructs and drops a fresh artifact for each candidate call.
Structural verification and a fresh pinned Rust semantic verifier run only
after construction and are explicitly outside any future construction timing
boundary. The verifier is qualification infrastructure, not an FRE Unicode
runtime plan and not warmed state shared by samples.

The exact regenerated 344-row report is
`/tmp/fre-control/results/G0-REBAR-UNICODE-COMPILE-1630823-FRONTIER-002.json`,
SHA-256
`196d9042324e67b98f04aec4897a930e95a32a40143c34c041dba2b8afdfeacd`,
with sorted-receipts SHA-256
`caa7cd09848ca1585f3ac58c129ca3702881087d9976a8a82ace42d0a626da78`.
It records 28/33 compile passes and 200/344 total FRE passes: exactly eleven
new compile rows over the 189-pass build-many frontier, zero lost passes, and
no FRE `fail` or `fault` receipt. Those new rows are:

- `curated/03-date/compile-unicode@rust/regex`
- `dictionary/compile/english-10@rust/regex`
- `dictionary/compile/english@rust/regex`
- `reported/i1095-word-repetition/unicode-compile@rust/regex`
- `unicode/compile/fifty-letters@rust/regex`
- `unicode/compile/huge-character-class@rust/regex`
- `unicode/compile/match-every-line@rust/regex`
- `unicode/compile/negated-class-matches-codepoint@rust/regex`
- `unicode/compile/one-letter@rust/regex`
- `wild/bibleref/compile@rust/regex`
- `wild/grapheme/compile@rust/regex`

Future construction timing must report at least these separate cells:

- `unicode-compile/cold/class`, `unicode-compile/cold/literal`, and
  `unicode-compile/cold/line`: fresh process or allocator-cold construction,
  followed by untimed verification.
- `unicode-compile/allocator-warm-fresh-artifact/class`,
  `unicode-compile/allocator-warm-fresh-artifact/literal`, and
  `unicode-compile/allocator-warm-fresh-artifact/line`: warmed allocator and
  code pages, but a newly parsed, allocated, completed, and dropped artifact on
  every measured iteration. Artifact reuse is prohibited in this cell.

The directed mutation witness is
`one_scalar_mutation_changes_artifact_bytes_and_identity`; it changes one
Unicode scalar and requires both retained bytes and artifact identity to move.
