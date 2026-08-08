# Correlated Unicode folded-root structural gate

This is a source-owned candidate-versus-parent gate for a correlated 2–4 byte
root fingerprint. It is deliberately independent of Rebar, ripgrep, holdout
inputs, Rust-regex timings, and named Unicode examples.

The catalog is derived from the Unicode 16.0.0 simple-fold table shipped by
`regex-syntax` 0.8.11. The complete generated table has SHA-256
`7622c7f7f03ac0dc2f2bcd51c81a217d64de0cc912f62f1add5f676603a02456`.
`catalog.tsv` freezes the mechanically selected equivalence classes, recipe
geometry, semantic boundaries, and timing sizes. The executable refuses a
catalog whose FNV-1a checksum differs from the compiled constant.

Frozen catalog checksums:

- SHA-256: `3bea4b65bce0af5ef9bafe5a710ec9c747c41d118ae79cbce91969aeed3b10fa`
- FNV-1a-64: `58717f6d97c089b2`

The eight recipes cover:

- primary byte cardinalities 1, 2, 3, 4, 8, and greater than 8;
- contiguous tuple widths 2, 3, and 4;
- bucket budgets 1, 2, 4, and 8, including bucket-alias survivors;
- fixed two-, three-, and four-byte UTF-8 classes and mixed-width folds;
- structural columns at the prefix, middle, and suffix;
- explicit independent-guard and no-explicit-guard forms.

Every alternative begins directly with its measured folded Unicode class, as
required by folded-trie admission. The frozen primary is a production-eligible
column: it occurs in every root expansion, is not made entirely of UTF-8 lead
bytes, passes the wide-classifier high-nibble bound, and wins production's
exact structural-lead/frequency/reverse-offset ranking. A mixed-width folded
successor ends fixed-column enumeration before the saturation tail. Guard
recipes place a deliberately lower-ranked branch-tag column before that stop.
Clock-free verification refuses to proceed unless retained build accounting
reports the exact frozen primary offset and cardinality for every recipe.

Clock-free verification builds an independent literal/class oracle from the
frozen scalar equivalence facts. It checks `is_match`, `find`, `find_at`,
windowed find, and non-overlapping iteration across structural size boundaries,
all 16 byte alignments, frame trims, candidate spacings, valid and malformed
cross-product decoys, deep verifier failures, and early/middle/late/dense true
matches. No clock is read on the `catalog` or `verify` path.

The timing path measures one indexed task per process. Construction, catalog
generation, semantic verification, and warm-up occur before `Instant::now()`.
It compares FRE candidates only with their exact parent build; Rust regex is
not linked. Task strata, sizes, iteration counts, and ordering are frozen.

The default feature selects the authenticated static-dispatch profile used by
the zstd evaluation host. A portable source-only check can explicitly use
`--no-default-features --features portable-dispatch`, but candidate and parent
results must never mix dispatch profiles.

Future invocation contract, after source validation is authorized:

```text
cargo run --release --manifest-path gates/unicode-fold-correlated-root-r1/Cargo.toml -- catalog
cargo run --release --manifest-path gates/unicode-fold-correlated-root-r1/Cargo.toml -- verify
cargo run --release --manifest-path gates/unicode-fold-correlated-root-r1/Cargo.toml -- task-count
cargo run --release --manifest-path gates/unicode-fold-correlated-root-r1/Cargo.toml -- time TASK SAMPLE
```

Acceptance must be reported by structural stratum, not only by a global
geometric mean. Zero-primary, true-positive, bucket-alias, and explicit-guard
controls are regression constraints; gains are expected in independently
plausible but tuple-impossible storms. The frozen catalog must not be revised
in response to candidate timings.
