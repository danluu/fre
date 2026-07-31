# Search V27 native AOT evidence

This source-first harness evaluates Search V27/tag40 independently of Rebar.
Its build script:

1. constructs canonical byte-regex source for 128 literal families (widths
   1–32 crossed with uniform, periodic, clustered, and phase-unique topology);
2. requires `PortableRegex` to authenticate each source as its live exact
   literal plan;
3. builds typed `Exists`, `SelectedEnd`, and `Span` Kernel IR;
4. emits and independently audits V27 machine images; and
5. packages the exact audited bytes into one statically linked Mach-O or ELF
   text object.

The runner checks both the linked native entries and the current portable
value APIs against a scalar oracle before timing. It covers no-match,
early-match, and late-match fixtures, two long window sizes by default, and
additional deterministic randomized windows that are never timed. Regex
compilation, machine-code generation, audit, object assembly, and linking all
happen before the measured steady-state calls.

Run on AArch64 macOS or Linux:

```text
cargo run --release -- \
  --host local-apple-aarch64 \
  --output apple.json
```

For a shorter diagnostic run, retain the complete breadth but reduce sampling:

```text
cargo run --release -- \
  --samples 3 \
  --sample-bytes 1048576 \
  --windows 65536 \
  --host diagnostic \
  --output diagnostic.json
```

The JSON contains every cell plus geomean and tail summaries by output,
topology, selected V27 graph, outcome, width band, and window size. A ratio
greater than one means the linked V27 code is faster than the current portable
path.
