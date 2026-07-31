# Search V26 fresh synthetic runner

This standalone crate materializes the population frozen by
`../preregistration-v1.json`. It has no corpus or result-file input. For every
width, output contract, and accepted slot, it derives SHA-256-domain bytes and
advances the hash ordinal until the public Search V17 emitter admits the exact
literal. The compact population identity binds both the accepted slot and the
source ordinal.

Generate a compact summary without performance timing:

```sh
cargo run --manifest-path \
  research/aot/search-v26-width-cost-rule-r1/synthetic-runner/Cargo.toml \
  --release -- summary
```

Use `population` instead of `summary` to include all 1,296 literal records.
`static` enforces exact V17 graph parity at widths 6 through 8, exact V25
graph parity at widths 9 through 32, tag-39/AOT-magic distinction, and routing
boundaries. `correctness local` and `correctness c9g` publish V26 on their
explicit macOS/Linux AArch64 lanes, record target features, and differentially
check all 7,776 literal/window/output cases against the safe Kernel IR oracle. Unit
tests pin the byte derivation, population identity, uniqueness, determinism,
per-cell counts, geometry, and public-emitter admission.

`emission-timing` is a separate, report-only cold compiler measurement. It
prepares KIR outside the clock, performs two untimed candidate/source warmup
pairs, then records the arithmetic median of eleven paired full-population
emission batches with alternating order. It never publishes or invokes
machine code, refuses non-release builds, and its result is not an acceptance
gate. Search performance execution belongs to a separately sealed one-shot
runner and receipt.

## Correctness receipt

`../run_correctness_lane.py` directly executes one bound release artifact on
each evidence host. The local invocation emits static and native-correctness
reports plus a platform execution manifest; the C9g invocation emits native
correctness plus its own manifest. It accepts no timing command. It verifies a
clean source commit/tree and requires the supplied archive to be byte-for-byte
identical to `git archive --format=tar COMMIT`. It independently checks the
host OS/architecture, requires an operator-supplied host fingerprint, and
requires a thin AArch64 Mach-O artifact locally or an AArch64 ELF artifact on
C9g.

Each evidence runner must be compiled with
`FRE_V26_EVIDENCE_SOURCE_COMMIT`,
`FRE_V26_EVIDENCE_SOURCE_TREE`, and
`FRE_V26_EVIDENCE_SOURCE_ARCHIVE_SHA256` set to the final identities already
verified by the controller. These labels are not trusted as source proof:
`build.rs` independently hashes the complete actual in-repository source set
(sorted paths, Git-compatible modes, and bytes, excluding only `.git`), while
the controller derives the same domain hash
from every blob in the exact bound Git tree. A dirty or stale build therefore
cannot be relabeled with fresh environment values. `build.rs` tracks every
source-set file and all three label variables so a change invalidates Cargo's
cached crate build. An evidence build must set `CARGO_TARGET_DIR` to an
absolute directory outside the source tree, so generated Cargo outputs cannot
be mistaken for inputs and a tracked path named `target` is never excluded.
The controller first invokes the
no-timing `evidence-build-identity` command from the privately staged binary.
It refuses an unset/sentinel identity, debug-assertions build, wrong target
OS/architecture/pointer width/endianness, source mismatch, backend/population
mismatch, noncanonical output, or any timing/performance/production authority.
Both platform manifests bind that exact identity report, and the top-level
sealer requires the two distinct native binaries to name the same final
commit/tree/archive.

On Linux the private staged pathname is unlinked and the held, byte-validated
executable descriptor is launched through `/proc/self/fd` with explicit FD
inheritance. macOS cannot execute a Mach-O image from `/dev/fd`, so its lane
uses a freshly created private directory closed to mutation, a held descriptor
whose bytes and vnode identity are checked before and after every command, and
the sole staged pathname whose vnode must remain identical. The manifests bind
these mechanisms as `validated-open-fd` and `closed-private-inode`.

Before execution, the controller copies the already-hashed artifact to a
private directory and executes that exact byte sequence with a fixed
environment, isolated working directory, bounded output, and a bounded
deadline. It accepts exactly one LF-terminated JSON line and empty stderr.
Only after every lane command and semantic check passes does it create
read-only reports and a canonical manifest at previously nonexistent paths.
The manifest binds the logical argv, report hashes and sizes, source
commit/tree/archive, runner hash and size, host fingerprint and target,
environment, and exact controller and validation-tool hashes.

After both platform invocations, `../seal_correctness_receipt.py` creates the
top-level read-only receipt at a new path. It independently repeats source,
archive, artifact-format, report, and manifest validation. The local and C9g
artifacts must have different paths and hashes, and their operator-supplied
host fingerprints must differ. A Linux/AArch64 self-report alone is therefore
not treated as C9g provenance; the operator remains responsible for supplying
the reviewed C9g host fingerprint.

Both tools strictly reject duplicate JSON keys, duplicate evidence, incomplete
coverage, nonzero mismatches, changed static totals, mutated commands or
hashes, placeholder identities, dirty source, input mutation during reads,
and existing output paths. Their manifests and receipt explicitly carry no
performance, promotion, or deployment authority.

Run its isolated tests without writing bytecode:

```sh
cd research/aot/search-v26-width-cost-rule-r1
python3 -B -m unittest -v test_seal_correctness_receipt.py
```

Use `python3 -B seal_correctness_receipt.py --help` for the exact create-new
top-level sealing arguments. Use
`python3 -B run_correctness_lane.py --help` for the per-host execution
arguments. The same final source commit/tree and deterministic archive must be
used for both lanes, while each lane uses its own native release artifact.
