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
validates the returned status, initialized prefix, and Boolean results; the
native entry owns the per-haystack search loop. A one-haystack request uses the
scalar entry directly. This changes neither match semantics nor the default
compiler API: callers must explicitly request the additive direct batch entry,
and an object-byte-cap decline returns the exact ordinary artifact.
