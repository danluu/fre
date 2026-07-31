# C5 qualification transaction

These tools qualify one exact candidate; they do not promote the selector-11
row. Ordinary `linked-count-v2` builds have an empty production table.
Only this standalone benchmark enables the deliberately private C5
qualification feature and calls its explicitly unsafe, separately named
adopter. Its row table and authenticated registry are disjoint from the safe
production adopter. Enabling or transitively unifying the feature cannot change
any safe production lookup. The five authority-bearing runtime identities
remain literal source, and the production promotion atom remains all-zero.

A later promotion decision must separately pin the independently verified
bundle manifest through the Candidate-rooted transaction in `PROMOTION.md`,
replacing that one all-zero
`C5_PROMOTION_BUNDLE_MANIFEST_SHA256_V2` source atom with the exact manifest
SHA-256. Until then, production lookup cannot resolve selector 11.

The measured subject and toolchain identities are external inputs:

- the exact Git commit and tree;
- the benchmark-source SHA-256 computed from the exact ordered v2 source
  manifest embedded by `benchmark_source_id`;
- the byte-identical release executable SHA-256;
- independent SHA-256 pins for the direct Cargo, rustc, and rustdoc
  executables and for the bounded physical toolchain closure.

The build gate requires a clean subject at those identities, a passing
production-inert runtime matrix (no features, `linked-count-v2`,
`linked-hardware-matrix-v2`, and all features), and a feature graph proving the
private candidate capability exists only in the standalone benchmark graph.
The all-features test executes the ordinary safe production adopter and proves
selector 11 still returns `NoQualified`. Symbol inspection proves the private
qualification boundary is absent from the first three production feature
combinations; its all-features presence is recorded as audit-only. The emitted
glue names that separate boundary, and its unsigned final-image receipt
explicitly pins the `qualification-private` adopter code in addition to the
complete object hash. The gate first archives the exact Candidate commit, then
builds from two physically distinct read-only extractions rather than the
mutable subject worktree. Before either extraction becomes a compiler input,
the gate compares its complete bounded directory/file inventory, executable
bits, byte counts, and Git blob identities with the externally pinned
Candidate commit. This rejects committed `.gitattributes` `export-ignore` or
`export-subst` transformations as well as any materialized path outside the
exact Git tree. Both locked/offline release lanes remap their source root to
`/fre-source`; every Cargo invocation runs from a separate private,
configuration-free working directory under an `env -i` allowlist with a
private home, externally pinned private registry snapshot, direct non-rustup
Cargo/rustc/rustdoc binaries, fixed Apple clang, empty wrappers, and no
ambient Rust/Cargo/profile/target overrides. Cargo therefore cannot discover
Candidate-controlled workspace `.cargo` settings; all project inputs still
resolve from explicit absolute manifest paths. The gate
also requires the two release binaries to be byte-identical, byte-identical
regeneration of the complete C5 evidence directory, one immutable
`__FRE_CONST` segment, and dependency graphs with no LLVM, Inkwell, or
Cranelift compiler package. Rustc
itself may use LLVM and Apple clang performs the final Mach-O link; neither is
the Count AOT compiler. Count machine code and Mach-O objects come from FRE's
custom `AArch64` emitter. The benchmark link also disables the otherwise
input-sensitive linker choices with Apple's `-reproducible` mode. The complete
custom-emitter evidence link uses the same mode. The gate requires the
resulting single content-hash Mach-O `LC_UUID`, which macOS needs to execute
the binary. Because source and linker-input path shape can affect native
output, the two source snapshots and targets use distinct fixed
`/private/tmp/fre-aot-c5-build.XXXXXX/source-{a,b}` and `target-{a,b}` shapes
while both source roots are remapped to `/fre-source`. The receipt records
this v2 snapshot/remap contract, and changing `TMPDIR` cannot change it.

```console
export FRE_CARGO_BUILD_JOBS=8

./fingerprint-toolchain.sh \
  /absolute/direct/rust-toolchain-1.93.0 \
  > /independently/published/c5-toolchain-fingerprint.tsv

./fingerprint-cargo-registry.sh \
  /absolute/config-free-offline-cargo-registry \
  > /independently/published/c5-cargo-registry-fingerprint.tsv

./build-qualified-candidate.sh \
  EXPECTED_COMMIT EXPECTED_TREE EXPECTED_SOURCE_SHA256 \
  EXPECTED_BINARY_SHA256 \
  /absolute/direct/rust-toolchain-1.93.0 \
  EXPECTED_CARGO_BINARY_SHA256 EXPECTED_RUSTC_BINARY_SHA256 \
  EXPECTED_RUSTDOC_BINARY_SHA256 EXPECTED_TOOLCHAIN_CLOSURE_SHA256 \
  EXPECTED_TOOLCHAIN_CLOSURE_ENTRIES EXPECTED_TOOLCHAIN_CLOSURE_BYTES \
  /absolute/config-free-offline-cargo-registry \
  EXPECTED_CARGO_REGISTRY_CLOSURE_SHA256 \
  EXPECTED_CARGO_REGISTRY_CLOSURE_ENTRIES \
  EXPECTED_CARGO_REGISTRY_CLOSURE_BYTES \
  /absolute/post-cutover/resource-coordinator \
  EXPECTED_RESOURCE_COORDINATOR_SHA256 \
  /absolute/post-cutover/cutover-receipt \
  EXPECTED_CUTOVER_RECEIPT_SHA256 \
  /private/tmp/fre-aot-c5-build
```

Do not substitute the historical `resource-coordinator-headroom-v1` path.
The concrete helper path, complete externally pinned SHA-256, cutover receipt,
and exact post-GO helper interface/receipt-field interpretation remain
intentionally unspecified until the controller publishes the live-cutover GO.
The scripts already fail closed on a canonical physical helper, its full
external SHA-256, a regular externally hashed cutover receipt, evidence copies
of both, pre/post hashing of the executed canonical path, and absence of any
direct build/timing fallback. They deliberately do not execute the copied
single file: the live helper may resolve sibling support files relative to its
installed directory. Final evidence remains blocked until the generic
`run-build`/`run-timing-wave` calls, receipt fields, and a sealed helper-support
closure (if required) are reconciled with the published GO interface rather
than inventing sibling hashes.

The toolchain root must be the physical directory containing regular
`bin/cargo`, `bin/rustc`, and `bin/rustdoc` files, not `~/.cargo/bin` rustup
proxy symlinks. The three executable digests and closure digest are independent
inputs.
`fingerprint-toolchain.sh` is part of the benchmark source identity and emits
the exact pins in a closed v2 TSV. The v2 closure covers the full physical
toolchain root, including its root record, all directories, and all files; it
permits at most 16,384 physical records and 4 GiB of regular-file payload,
rejects symlink/special/multiply-linked files, reads exactly each charged file
size, caps directory enumeration before sorting, and seals its entry/byte
totals into the digest trailer. The build checks digest, entry count, and byte
count before and after each Rust-tool phase and requires `rustc --print
sysroot` to resolve to that physical root. No pinned Rust executable is invoked
before an expected full-closure check, and each such phase is followed by
another full-closure check. Fingerprint and build receipts retain the
producer-local canonical toolchain path for auditability.

The second fingerprint command covers the complete consumed Cargo `registry/`
subtree under the distinct
`FRE-CARGO-REGISTRY-CLOSURE\0\x01` domain (100,000-entry/4-GiB caps). Both
Candidate lockfiles must contain only registry and path source classes; any Git
source fails closed. The build copies the exact pinned subtree to a private
`CARGO_HOME/registry`, leaves the private Cargo home configuration-free, and
checks both source and private snapshot before and after all Cargo activity.
Cargo.lock and Cargo's `.cargo-checksum.json` checks remain defense in depth;
they are no longer the byte authority for dependency inputs. The producer
receipt likewise retains the canonical registry source path and separately
labels the private snapshot location.

Run the three fresh processes; the runner preserves a coordinator evidence copy
but admits only through the pre/post-hashed canonical installed coordinator:

```console
./run-qualified-candidate.sh \
  EXPECTED_COMMIT EXPECTED_TREE EXPECTED_SOURCE_SHA256 \
  EXPECTED_BINARY_SHA256 \
  EXPECTED_CARGO_BINARY_SHA256 EXPECTED_RUSTC_BINARY_SHA256 \
  EXPECTED_RUSTDOC_BINARY_SHA256 EXPECTED_TOOLCHAIN_CLOSURE_SHA256 \
  EXPECTED_TOOLCHAIN_CLOSURE_ENTRIES EXPECTED_TOOLCHAIN_CLOSURE_BYTES \
  EXPECTED_CARGO_REGISTRY_CLOSURE_SHA256 \
  EXPECTED_CARGO_REGISTRY_CLOSURE_ENTRIES \
  EXPECTED_CARGO_REGISTRY_CLOSURE_BYTES \
  /absolute/post-cutover/resource-coordinator \
  EXPECTED_RESOURCE_COORDINATOR_SHA256 \
  /absolute/post-cutover/cutover-receipt \
  EXPECTED_CUTOVER_RECEIPT_SHA256 \
  /private/tmp/fre-aot-c5-build \
  /private/tmp/fre-aot-c5-bundle
```

The runner verifies the executable before and after every process. The
raw-results gate derives all medians, speedups, and pair wins from bounded
canonical integers; it does not trust reported summaries. The bundle records
first and cached adoption separately, while steady-state AOT samples call only
the authenticated `VerifiedStaticCountV2` handle and include the production
per-call preflight.

The exact workload matrix has 29 cases at each of 64 KiB and 1 MiB: four
baseline sparse/dense/absent/tail cases, sixteen named actual-base/relative-start
alignment cases, and nine binary, natural-text, selected-filter adversarial,
sparse-recovery, first/last-confirmation, and dense-run-transition cases.
Therefore each fresh process has `58 × 16 × 2 = 1,856` raw samples; the complete
transaction has `3 × 58 = 174` process/case cells and
`3 × 58 × 16 = 2,784` paired repetitions. Every sample scans exactly 64 MiB,
and every one of the 174 raw-derived medians must beat portable by at least
1.10× while at least 95% of the 2,784 pairs must be strict AOT wins.

Qualification authorizes only selector 11 and its identity-bound exact
`needle` Count-v2 row. Timing evidence covers cache-resident steady-state safe
handle calls and separately labeled qualification-private first/cached
adoption. Compile/object generation, final linking, process startup, production
adoption latency, general AOT, other selectors/literals, and other operations
or targets are outside this evidence. No lifecycle number may be inferred from
the retained whole-process resource reports.

An independent reviewer pins the manifest SHA-256 printed by the runner and
replays the closed bundle against an object database containing the expected
commit:

```console
./verify-qualification-bundle.sh \
  EXPECTED_COMMIT EXPECTED_TREE EXPECTED_SOURCE_SHA256 \
  EXPECTED_BINARY_SHA256 EXPECTED_MANIFEST_SHA256 \
  EXPECTED_CARGO_BINARY_SHA256 EXPECTED_RUSTC_BINARY_SHA256 \
  EXPECTED_RUSTDOC_BINARY_SHA256 EXPECTED_TOOLCHAIN_CLOSURE_SHA256 \
  EXPECTED_TOOLCHAIN_CLOSURE_ENTRIES EXPECTED_TOOLCHAIN_CLOSURE_BYTES \
  EXPECTED_CARGO_REGISTRY_CLOSURE_SHA256 \
  EXPECTED_CARGO_REGISTRY_CLOSURE_ENTRIES \
  EXPECTED_CARGO_REGISTRY_CLOSURE_BYTES \
  EXPECTED_RESOURCE_COORDINATOR_SHA256 EXPECTED_CUTOVER_RECEIPT_SHA256 \
  /private/tmp/fre-aot-c5-bundle /path/to/fre
```

The closed-bundle verifier validates the retained dependency graph, exact
source archive/lock, and no-LLVM/feature-isolation policy without invoking an
ambient Cargo installation. Rebuilding or replaying `cargo tree` belongs to
the independently controlled review environment; a promotion verifier must
not inherit the reviewing shell's Cargo/Rustup configuration as authority.

`test-results-verifier.sh` requires known-valid raw output and exercises the
numeric and structural tamper matrix. `test-qualification-bundle.sh` requires a
known-valid sealed bundle and exercises manifest, source, binary, binding,
symlink, hardlink, and missing-file tampering.

The source identity covers the benchmark, build/runner/verifier authority,
promotion verifier and trust-root regression, documentation, and the
correctness-only promoted-source harness. A Rust test recomputes the same
domain-separated byte stream from `benchmark-source-files-v2.txt` and proves
that one changed byte or changed file order changes the identity.
