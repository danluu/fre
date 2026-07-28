# Count-v2 final-image evidence

`c3-count-v2/` is a deterministic arm64 macOS evidence bundle for the
row-selector-first Count-v2 final-image path. Recreate it from the workspace
root with:

```console
cargo run -p fre-aot-count-compiler --example emit_c3_evidence -- \
  crates/fre-aot-count-compiler/evidence/c3-count-v2
```

The generator uses the legacy compiler only as a dev-only claim oracle. The
implementation object, expectation, prelink receipt, glue object, and
final-image receipt are emitted by the focused neutral compiler. The retained
driver links and executes the emitted machine code. Its pinned link command
sets `__FRE_CONST` maximum and initial protections to read-only, matching the
runtime verifier, while the duplicate-object link is required to fail.
`SHA256SUMS` pins every retained artifact.

`c5-count-v2-candidate/` retains the exact objects regenerated from the
integrated C5 candidate source. Its raw C driver still reports
`runtime_authority=absent`, because that driver deliberately stubs the adopter.
The adjacent `benchmarks/c5-qualified-vs-portable/` package links both retained
objects with the real `fre-aot-static-runtime`, exercises the literal selector
11 production row and immutable-image verifier, and measures only the resulting
safe authenticated handle. The C5 row is not releasable until that package has
been run in a sealed source-bound qualification and independently verified.
