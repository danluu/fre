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
