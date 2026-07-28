# Search V8 source and dependency provenance

This is the source-only Stage A v2 format for closing independently derived
Search V8 source, Cargo dependency, and registry-archive sidecars over exact
bytes. It does not change the benchmark build, grant AOT runtime authority,
populate a Search qualification table, make an unlinked object callable, or
itself prove how Git or Cargo produced an input sidecar.

The existing build receipt's `subject_revision` is caller-supplied and only
syntax checked. Its benchmark source identity covers a local manifest, not the
transitive path dependencies. `Cargo.lock` authenticates registry archives but
does not contain checksums for path packages. Stage A therefore establishes a
strict, independently replayable closure before any build-receipt wiring.

## Exact authority boundary

The producer and reviewer remain separately responsible for deriving the
source and dependency sidecars. Each must receive these values from an
external authority:

- an exact commit and its exact tree;
- the SHA-256 of the Git executable used to read the object database;
- an immutable private archive store;
- the fixed target `aarch64-apple-darwin` and profile `release`; and
- Cargo metadata obtained with an externally pinned Cargo/toolchain,
  `--locked --offline`, the exact target, and only normal/build edges.

`generate_provenance.py` never invokes Git or Cargo and never discovers
`HEAD`. `verify_provenance.py` does not claim that the supplied source snapshot
was enumerated by Git, that `subject_commit` resolves to `subject_tree`, or
that the dependency sidecar came from Cargo. It proves that:

1. the retained sidecars are canonical and byte-identical to separately
   supplied reviewer derivations;
2. the selected package tuples and registry checksums occur in the exact
   canonical Cargo.lock v4 bytes;
3. the exact Search V8 root and lock roles are selected;
4. every registry archive row is backed by a descriptor-bound real `.crate`
   file with the stated byte count and SHA-256; and
5. every retained byte and fixed external assertion is committed by the
   final identity.

A later producer wrapper must authenticate the still-external Git and Cargo
derivations: clean repository, exact commit-to-tree relation, non-shallow
history, no grafts/replacement refs, exact blob/tree identities, no
symlink/submodule/special Git modes, and controlled Cargo metadata. Until that
wrapper and its independent review receipt are bound, a Stage A PASS means
“canonical sidecar closure agrees with the reviewer inputs,” not “Git/Cargo
execution was internally reproduced.”

## Fixed Search identity

The v2 schema admits exactly:

- lock role
  `repo:research/aot/search-v8-bakeoff/Cargo.lock`;
- root manifest role
  `repo:research/aot/search-v8-bakeoff/Cargo.toml`;
- root package `fre-search-v8-bakeoff` version `0.1.0`;
- root source
  `path:repo:research/aot/search-v8-bakeoff`;
- registry source
  `registry+https://github.com/rust-lang/crates.io-index`; and
- normal/build dependency edges only.

The root package key is derived from that exact name, version, and source. It
is not a caller-selectable argument. Every selected path package must occur as
one unique source-less Cargo.lock name/version tuple. Every selected registry
package must occur as the exact Cargo.lock name/version/source/checksum tuple.
The fixed v2 lock parser policy is
`cargo-lock-v4-bare-unique-name-edges-v1`: lock package rows must be ordered,
package names must be globally unique, and every lock dependency must be one
bare package name resolving uniquely inside the lock. Every selected sidecar
edge must occur in that resolved lock graph. Cargo metadata remains the
external authority for dependency aliases, normal/build kind, cfg activation,
and which lock edges are target-active. A lock requiring qualified package-ID
syntax needs a new reviewed parser policy/schema rather than an approximation.
Target-inactive or otherwise unselected lock packages may remain; the
dependency sidecar is the externally derived target-specific normal/build
closure.

## Closed bundle

The generator creates one new permission-sealed directory containing exactly
five singly linked regular files:

| Logical role | Schema or format | Purpose |
| --- | --- | --- |
| `source-snapshot.tsv` | `fre-search-v8-source-snapshot-v2` | Every regular blob in the externally authenticated Git tree |
| `Cargo.lock` | canonical Cargo.lock v4 | Exact Search V8 lock bytes named by the source snapshot |
| `dependency-manifest.tsv` | `fre-search-v8-dependency-manifest-v2` | Closed selected normal/build package graph |
| `registry-archives.tsv` | `fre-search-v8-registry-archives-v2` | One real-archive identity for every selected registry package |
| `source-provenance.tsv` | `fre-search-v8-source-provenance-v2` | Ordered closure receipt |

Each file is mode `0400`; the final directory is mode `0500`. These modes are
a permission seal, not an assertion that a privileged writer cannot replace
the enclosing directory. Every consumer reopens and authenticates a fresh
descriptor-bound snapshot.

No sidecar may store an absolute source, registry, output, or `OUT_DIR` path.
Source snapshot paths are uppercase-percent-encoded repository-relative byte
paths. A NUL, absolute path, empty/dot/dot-dot component, backslash, redundant
escape, or escaped safe byte is rejected.

Path package locators have exactly:

```text
path:repo:PERCENT_ENCODED_PACKAGE_DIRECTORY
```

Their manifest role is derived as:

```text
repo:PERCENT_ENCODED_PACKAGE_DIRECTORY/Cargo.toml
```

Registry manifest and archive roles are derived from the package key:

```text
cargo-registry-manifest:PACKAGE_KEY/Cargo.toml
cargo-registry-archive:PACKAGE_KEY.crate
```

Manifest and archive roles are strictly unique. Physical archive paths are
outer CLI inputs of the form `PACKAGE_KEY=/absolute/file.crate`; no physical
path enters a sidecar or identity.

## Canonical tables

Source snapshot rows are strictly ordered by decoded path bytes:

```text
ordinal  mode  git_object  bytes  sha256  path
```

Only Git modes `100644` and `100755` are accepted. Paths are unique and
ASCII-case-disjoint.

Dependency rows are strictly ordered by package key:

```text
ordinal  package_key  name  version  source_kind  source_locator
manifest_role  package_tree  lock_checksum  target_kinds  features
dependencies
```

The physical row is tab-separated on one line. Edges contain the dependency
alias, `normal` or `build`, `all` or `cfg-sha256:HEX64`, and the target package
key. Every edge stays within the manifest and every package is reachable from
the fixed Search root.

Registry archive rows are strictly ordered by package key:

```text
ordinal  package_key  name  version  source_locator  lock_checksum
archive_bytes  archive_sha256  archive_role
```

The archive SHA-256 must equal the exact Cargo.lock checksum and the digest of
the descriptor-bound real `.crate` bytes. Actual archive inodes must be
singly linked, unique, stable across the bounded hash, and exactly cover the
selected registry packages.

## Framed identities

Every v2 composite uses unsigned little-endian 64-bit role and byte-string
lengths. There are no delimiter-joined composite preimages. Domains are:

- `FRE-SEARCH-V8-SOURCE-SNAPSHOT\0\x02`
- `FRE-SEARCH-V8-DEPENDENCY-CLOSURE\0\x02`
- `FRE-SEARCH-V8-SOURCE-PROVENANCE\0\x02`
- `FRE-SEARCH-V8-PACKAGE-KEY\0\x02`

The dependency closure binds, in order:

1. exact `source-snapshot.tsv` bytes;
2. exact Search V8 `Cargo.lock` bytes;
3. exact `dependency-manifest.tsv` bytes; and
4. exact `registry-archives.tsv` bytes.

`source_snapshot_file_sha256` is the ordinary file digest.
`source_snapshot_identity_sha256` is the framed source-domain identity.
`source_provenance_sha256` is the framed identity of every preceding ordered
receipt row, with each receipt key as its own role; it is not the ordinary
digest of `source-provenance.tsv` and does not contain an intermediate TSV
`receipt-preimage`.

Known-answer tests pin both a standard SHA-256 vector and the exact
little-endian framing preimage. Changing a domain byte or field boundary
requires another schema version.

## Descriptor and durability protocol

All input paths must be canonical absolute physical paths. The implementation
walks every directory component from `/` with `openat`,
`O_DIRECTORY|O_NOFOLLOW`, retains the final directory descriptor, and opens
each leaf relative to that descriptor. A file is read once through its pinned
descriptor with bounded `read`, pre/post `fstat`, stable
device/inode/mode/link-count/size/mtime/ctime, and an exact length check.
Verifier-side rederivations must also have physical `(device, inode)`
identities disjoint from every retained bundle role. This rejects pointing a
review argument back into the retained bundle; authenticated reviewer
independence remains an external requirement.

The output parent must be owned by the effective UID and must not be
group/other writable. The generator records the created directory entry
identity, binds the opened descriptor to it, and rechecks the final name and
parent policy before publication. After both directory fsyncs, it also
re-walks the absolute parent path without following symlinks, requires the
same parent and bundle `(device, inode)` identities, and re-reads the exact
sealed bundle through those final descriptors. This is a check-at-publication
guarantee; consumers must reopen and authenticate the absolute path again.
A process with the same effective UID can still mutate the path after either
check and is outside this permission-seal threat model.

The verifier inventories the retained bundle through its open directory
descriptor and opens every role with `O_NOFOLLOW`; it does not validate a
pathname and reopen it later. Re-derived sidecars and real archives use the
same descriptor-bound rules.

The generator opens the output parent by descriptor, creates one new leaf
directory, retains that directory descriptor, creates every role with
`O_EXCL|O_NOFOLLOW`, completes and verifies every write, `fsync`s each file
and the directory, checks the exact inventory and bytes, changes the directory
to `0500`, rechecks it, and `fsync`s the parent. A failure emits no provenance
identity and may leave an incomplete new `0700` directory for forensic
inspection; it never recursively removes an ambiguous path.

## Intended source-only commands

The producer supplies one real archive binding per registry row:

```sh
python3 generate_provenance.py \
  --expected-commit HEX40 \
  --expected-tree HEX40 \
  --snapshot-git-tool-sha256 HEX64 \
  --source-snapshot /physical/source-snapshot.tsv \
  --cargo-lock /physical/Cargo.lock \
  --dependency-manifest /physical/dependency-manifest.tsv \
  --registry-archives /physical/registry-archives.tsv \
  --registry-archive PACKAGE_KEY=/physical/archive.crate \
  --target aarch64-apple-darwin \
  --profile release \
  --output /physical/new-provenance-directory
```

The independent verifier receives the Git-tool pin explicitly as well as the
opaque closure identity:

```sh
python3 verify_provenance.py \
  --bundle /physical/provenance-directory \
  --expected-commit HEX40 \
  --expected-tree HEX40 \
  --expected-provenance-sha256 HEX64 \
  --expected-snapshot-git-tool-sha256 HEX64 \
  --rederived-source-snapshot /physical/review/source-snapshot.tsv \
  --rederived-cargo-lock /physical/review/Cargo.lock \
  --rederived-dependency-manifest /physical/review/dependency-manifest.tsv \
  --rederived-registry-archives /physical/review/registry-archives.tsv \
  --registry-archive PACKAGE_KEY=/physical/review/archive.crate
```

Multiple `--registry-archive` arguments are supplied when needed.

## Deferred build wiring

Before Stage A can authorize a qualification build, a later change must:

1. implement and independently review the controlled Git/Cargo sidecar
   producers described above;
2. bind complete Rust toolchain, registry-store, Apple linker/SDK, link
   argument, wrapper/environment, and source-remapping closures;
3. carry the exact v2 sidecars and provenance identity into build, linked
   image, timing, and completion receipts;
4. replace absolute embedded build paths with logical bundle roles; and
5. perform two admitted builds in distinct roots and require byte-identical
   implementation objects, compiler receipts, provenance identities, and
   reproducible final-image evidence.

Lifecycle measurement remains separate. Its native route is
`strict-wx-jit-lifecycle`; safe AOT adoption and full-link lifecycle rows stay
deferred until an exact private source-qualified Search row and final-image
evidence exist.
