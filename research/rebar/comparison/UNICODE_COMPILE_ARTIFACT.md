# Unicode compile-artifact source checkpoint

This source-only checkpoint, recomposed on
`78b0c3cd63b0b0cb505ba0d185670a688efef2f2`, extends only the one-pattern Rebar `compile`
surface. It does not add Unicode execution to `count`, `count-spans`, grep, or
capture reducers, and it makes no timing or observed-coverage claim.

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

The older projection covered twelve Unicode-enabled `compile` refusals. One
now passes through the authenticated Unicode v5 continuation artifact, so this
composition has a projected ceiling of eleven new rows: `compile` 17 to 28 and
the full frontier 187 pass / 157 unsupported to 198 / 146 in isolation. The
authoritative table must remain unchanged until exact regenerated receipts and
an independent source/provenance audit accept every disposition.

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
