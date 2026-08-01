# General AOT compiler

`compile_general_aot.rs` is the explicit general compiler CLI:

```sh
cargo run -p fre-aot-compiler --example compile_general_aot -- \
  '(?:[A-Za-z_][A-Za-z0-9_]*::)+item' \
  linux-x86_64 item.o optimizing span avx2
```

The final feature argument is optional and comma-separated. Accepted facts are
`sse2`, `avx2`, `avx512f`, `avx512bw`, `avx512vl`, `asimd`, `sve`, and `sve2`;
the target validator rejects cross-architecture or incomplete feature sets.
Current x86-64 instruction selection uses the SSE2 baseline, AVX2, or
AVX-512 when both `avx512f` and `avx512bw` are present. Current `AArch64`
selection uses scalar code or `asimd`. `avx512vl`, `sve`, and `sve2` are
accepted target facts but do not yet select distinct lowering. Empty features
therefore mean SSE2 on x86-64 and scalar code on `AArch64`; the compiler does
not inspect the build host. The command prints the identity-suffixed entry, any
required runtime helper and exported program alias, and the complete receipt.
It does not invoke an assembler or linker.

## Legacy Search Span source-candidate emitter

`emit_search_span_source_candidate.rs` is the source-only first step toward a
real static Search qualification. It compiles the fixed non-Unicode
`0123456789abcdef` exact-literal `Span` through `fre-aot-compiler`, using row
selector `1`.

The example emits this closed bundle:

- `implementation.o`;
- `expectation.bin`;
- selector-1 private-qualification and production glue objects;
- a selector-2 private-qualification control glue object;
- the three canonical unsigned glue-receipt wires;
- the exact canonical compiler-receipt wire and an LF-terminated review
  projection;
- a proposal containing selector `1` plus all twelve qualification fields
  required by `SourceQualifiedStaticSearchSpanRowV1`; and
- `SHA256SUMS` over every other file.

The selector is the row lookup key. The twelve proposal fields are
`live_literal_bytes` plus the manifest, semantic-binding, literal, KIR,
artifact, binding, compile, object, compiler-receipt, expectation, and payload
identities. No field is inferred from a path, environment variable, linker
output, or runtime feature.

`compiler-receipt.bin` is the exact fixed-width stream whose SHA-256 is the
typed compiler receipt identity. The compiler receipt TSV carries that
identity, all row-relevant compiler identities, object/payload/metadata hashes,
and bounded resource observations; it is a deterministic review projection,
not a second authority-bearing receipt format. The glue receipts are the
compiler's exact canonical 256-byte wires.

The requested output directory must not exist. A 128-bit nonce read from
`/dev/urandom` names a same-parent staging directory. That directory is
create-new mode `0700`; its descriptor and named path must retain the same
device, inode, and mode throughout the transaction. Every artifact is
create-new mode `0600`. Reopening compares descriptor and named-path
device/inode/link-count/mode observations before and after the bounded read, so
a followed symlink, hard link, permission change, or path replacement fails
closed.

The implementation is checked both by the generic Mach-O inspector and its
typed compiler receipt. The expectation is checked by the neutral contract and
compiler state. Every glue object is checked by the allocation-free canonical
inspector and its exact source-bound receipt.

Publication does not rename a directory over the requested path. It atomically
creates that final directory as a new mode-`0700` directory, so an existing
path is never replaced. All content artifacts are moved into it, reopened, and
strictly inspected before the directory is synced. `SHA256SUMS` is moved into
the final directory strictly last and is the readiness atom. The final
directory and parent are synced, then the exact complete final bundle is
reopened and verified before success is reported.
Consumers must reject a directory without `SHA256SUMS` and must validate the
manifest and semantic receipts rather than treating marker presence alone as
authority.

On failure, recursive deletion is deliberately absent. A private random stage,
or a private incomplete final directory without `SHA256SUMS`, may remain for
forensics but is not a ready bundle. On success only the identity-revalidated,
exactly empty staging directory is removed with non-recursive `remove_dir`.

After build admission is restored, the command is:

```sh
cargo run -p fre-aot-compiler \
  --example emit_search_span_source_candidate \
  -- /new/output/directory
```

This example does not invoke a linker, map or call generated code, run a
benchmark, or write either static-runtime row table. Its compiler, expectation,
glue, and proposal receipts all retain `runtime_authority=absent`. The emitted
row is private-qualification input only; mapped-image and hardware evidence
must be collected and independently reviewed before any separate source-row
transaction.
