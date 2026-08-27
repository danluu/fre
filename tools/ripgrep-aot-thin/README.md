# ripgrep AOT thin registry

This package builds a fixed registry of AOT-compiled regular expressions for
the ripgrep comparison adapter. With no environment variables, it reads the
bundled `patterns.tsv` and emits the same four variants for every row as
before: Fast/Exists, Fast/Span, Optimizing/Exists, and Optimizing/Span.

## External pattern manifests

Set `FRE_RIPGREP_AOT_PATTERNS_FILE` at build time to select another TSV file:

```sh
FRE_RIPGREP_AOT_PATTERNS_FILE=/absolute/path/to/patterns.tsv \
  cargo build -p fre-ripgrep-aot-thin
```

Each non-comment row is:

```text
id<TAB>case_insensitive<TAB>pattern
```

`id` contains only ASCII letters, digits, and underscores;
`case_insensitive` is `0` or `1`. Blank lines and lines beginning with `#` are
ignored. The pattern is the remainder of the row, so it may contain tabs and
may be empty. Relative paths are resolved from this package directory.

Cargo tracks both the environment variable and the resolved selected file, so
changing either reruns the build script. `FRE_RIPGREP_AOT_PATTERN_FILTER`
continues to filter IDs after the selected manifest is loaded.

The checked-in `testdata/patterns.tsv` is a generated, shape-only example; it
does not contain production or private query contents.

## Target features

When `FRE_RIPGREP_AOT_FEATURES` is absent, the build inherits only the
features understood by FRE from Cargo's target metadata. In particular,
Cargo's AArch64 `neon` feature maps to FRE's `asimd`, and x86-64 `sse2` maps
to FRE's `sse2`; unrelated Cargo feature names are ignored. This uses the
compilation target's metadata and does not inspect the build host.

`FRE_RIPGREP_AOT_FEATURES` remains an exact comma-separated override. An
explicitly empty value selects the portable scalar target, while an unknown
explicit name is an error. Cargo tracks both the explicit override and its
target-feature metadata for build-script reruns.

## Optional variant pruning

Trace-profile builds that only call optimizing Exists can opt into:

```sh
FRE_RIPGREP_AOT_VARIANTS=optimizing-exists \
  cargo build -p fre-ripgrep-aot-thin
```

This emits only Optimizing/Exists for every selected row. Requests for Fast or
Span then return a runtime error that names the build policy and available
variant. Unset, empty, or `all` retains the default four-variant registry.

## Opt-in aggregate GrepCount endpoint

An integration that needs only ripgrep's whole-haystack matching-line count
can build the additive aggregate-only registry:

```sh
FRE_RIPGREP_AOT_VARIANTS=optimizing-grep-count \
  cargo build -p fre-ripgrep-aot-thin
```

This policy emits no ordinary `AotMatcher` variants. It asks the compiler for
an Optimizing/SelectedEnd native GrepCount reducer only after an independent
`fre-syntax`/`fre-lower` pass proves a non-empty, non-nullable, assertion-free
exact finite byte language whose members contain neither CR nor LF. The build
then authenticates the compiler report, semantic-program identity, exclusive
GrepCount export, and `NativeFused` strategy before linking an entry. A
compiler structural decline simply omits that tuple.

Call `AotGrepCountFactory::select` before acquiring or inspecting a haystack.
`None` is the complete structural decline. `prepare` creates the separate
exclusive `AotGrepCount` handle, and `count_matching_lines` returns the exact
LF/CRLF semantic line count. Preparation and native-call errors are terminal;
the handle never falls back after source access. This aggregate API exposes no
spans or captures, so integrations needing those results must keep their
ordinary matcher authoritative for them.

Unset, empty, and `all` continue to emit exactly the original four variants
and an empty GrepCount registry.

## Exact-singleton first-candidate endpoint

Every emitted Optimizing/Exists row is also considered for a separate
stateless `FIRST_CANDIDATE_SPECS` registry. The build independently parses and
lowers the Rust byte regex and admits only a language containing exactly one
nonempty, assertion-free LF-free literal. A compiler decline simply omits the
row. A present compiler endpoint is linked only after its literal length and
SHA-256 agree with the independent proof and its target, feature, ISA, ABI,
sentinel, position semantics, trusted core, wrapper, code, relocations,
symbols, call-free property, and complete object identity authenticate.
Generated first-candidate registry source contains only domain-separated keys,
digests, lengths, numeric metadata, and identity-derived symbol names; it does
not contain regex sources or literal bytes. Existing matcher and batch
registries are unchanged.

Call `AotExactSingletonFirstCandidateFactory::select` before obtaining a
haystack. Selection takes the ordinary `(mode, output, pattern,
case_insensitive)` tuple plus the exact literal bytes independently recovered
from the configured stock-matcher HIR. Unsupported modes/outputs and a missing
or compiler-declined row return `Ok(None)`. Once a manifest/profile row is
present, a configured-literal, target, feature, symbol, or receipt mismatch is
a raw-free terminal error.

`find(&[u8])` makes one stateless native call and returns
`AotExactSingletonFirstCandidateOutcome::ConfirmedMiss` or
`Candidate { position }`, where `position` is the inclusive final byte of the
earliest-completing possible match. A candidate is never confirmed: stock
ripgrep remains authoritative for the containing line, spans, and captures.
Native status errors and malformed success positions are terminal after the
haystack is supplied. The miss is authoritative only under the authenticated
exact-language receipt.

`testdata/public-first-candidate.tsv` supplies only generated wide singleton
shapes (plus one deliberate finite-alternation decline) for a nonempty linked
registry build check:

```sh
FRE_RIPGREP_AOT_PATTERNS_FILE=testdata/public-first-candidate.tsv \
  FRE_RIPGREP_AOT_VARIANTS=optimizing-exists \
  cargo test -p fre-ripgrep-aot-thin
```

## Opt-in Exact64 set prefilter

The static multi-pattern registry is a separate additive opt-in. With the
environment variable absent, it emits no set objects and does not change any
existing single-pattern registry row or default:

```sh
FRE_RIPGREP_AOT_EXACT64_SETS_FILE=testdata/public-exact64-sets.tsv \
  cargo test -p fre-ripgrep-aot-thin
```

The selected file uses LF record separators and contiguous ordered rows:

```text
set_id<TAB>rust-regex-lf-bytes-v1<TAB>case_insensitive<TAB>raw-regex
```

`set_id` follows the same identifier grammar as the ordinary manifest. A set
has 2 through 64 rows, all with one case value; duplicate regex sources remain
distinct ordered rows. The raw regex is the remainder of the record and may
contain tabs. Actual CR is rejected to avoid CRLF record ambiguity (a regex may
spell a CR escape). Cargo tracks both the opt-in environment variable and the
resolved file. Generated diagnostics and registry source never contain regex
sources.

Each row must pass an independent `fre-syntax`/`fre-lower` proof that its Rust
byte-regex language is exactly one nonempty, assertion-free LF-free literal.
The Exact64 compiler independently repeats the source proof, builds the shared
scan, and the build authenticates the complete first-any receipt and object
before linking it. Safe source, target, or numeric-resource declines omit the
set; allocation, arithmetic, object, and authentication failures remain
terminal. The current first-any object lowering is AArch64-only.

`AotExact64SetFactory::select` must run before obtaining a haystack. It takes
the complete ordered source vector and a `RipgrepAotExact64SetProfileV1`.
Selection is only possible for Optimizing/Exists Rust-regex byte semantics,
Unicode enabled, raw already-decoded input, and no fixed-string, inversion,
multiline/dotall, CRLF, NUL-data, word/whole-line, or PCRE2 transformation.
Unsupported semantics and absent vectors return `Ok(None)`; a found registry
row with invalid authentication is an error. The registry key is
domain-separated and binds the profile, source count, each source length,
ordered raw UTF-8 bytes, and duplicates. Runtime authentication also requires
the receipt's target-feature mask to equal the exact mask selected by this
build; it is not merely reported as metadata.

The selected factory is immutable, `Copy`, `Send`, and `Sync`.
`prefilter(&[u8])` returns `ConfirmedMiss` or `Candidate { position }`, where
the position is the final byte of the earliest-completing possible match. A
candidate is never a confirmed match: stock ripgrep must remain authoritative
for the line decision, matching IDs, spans, and captures. The miss alone may
short-circuit under the authenticated exact-language proof. Every ABI failure
or malformed success after the haystack is supplied is terminal and must not
be retried through a weaker fallback.

This package publishes the registry/runtime primitive; wiring parsed ripgrep
flags, decoded-input evidence, and stock verification into a particular
ripgrep revision remains an explicit integration step.

`verify-default-artifacts.py BASE_OUT_DIR CANDIDATE_OUT_DIR` closes the
env-absent compatibility boundary against a build of the pre-feature base. It
compares `registry.rs` byte-for-byte, ordinary object/program filenames and
payloads byte-for-byte, then compares archive member order and payloads. The
archive comparison deliberately ignores `ar` header timestamps and hashes the
logical ordered member stream instead.

## Exists batching

Exists variants request an optional one-call native batch entry at build time.
Prepared artifacts use their existing exclusive-handle batch API. A
self-contained direct artifact may instead expose the additive, handle-free
`direct-exists-batch-v1` API, which evaluates up to 64 independent haystacks
through one Rust-to-native call. The compiler authenticates a private
full-window Exists core so the native loop does not repeat the ordinary public
entry validation for every haystack; the ordinary scalar entry remains
byte-for-byte unchanged. Runtime-backed and otherwise ineligible artifacts
keep the checked scalar compatibility loop.

The generated registry authenticates the advertised route before publishing
it. The Rust adapter still constructs the bounded descriptor array and
validates the returned status and initialized prefix. The independently
authenticated compiler entry is responsible for writing only the canonical
Boolean bytes 0 and 1 while it owns the per-haystack search loop. A
one-haystack request uses the scalar entry directly. This changes neither match
semantics nor the default compiler API: callers must explicitly request the
additive direct batch entry, and an object-byte-cap decline returns the exact
ordinary artifact.

The `public_direct_exists_batch` example also has benchmark-only timed modes.
Its four-argument form retains the ordinary automatic batch call. An exact
fifth argument of `scalar-loop-v1` or `direct-call-v1` selects a scalar
per-haystack loop or the descriptor-batch API after both haystack views and the
bounded descriptor array have been prepared. The equal-length tokens avoid an
allocator-layout difference between causal arms. Both call paths are
preflighted in the same order, and route formatting happens after timing. The
emitted route includes the selected `timed_mode`; unknown and lookalike values
fail closed.

For a causal wrapper comparison, build one direct-batch-capable example and
pass that same resolved executable as both inputs to
`scripts/benchmark-aot-direct-exists-batch.py --same-binary-causal`. The runner
authenticates binary identity, the per-arm timed mode, output digests, and route
evidence in its append-only log. This is a benchmark endpoint only and does not
change or bypass the production matcher API.
