# Pinned RE2 syntax evidence

This directory separates two different kinds of evidence:

1. Source evidence defines what the Rust parser is attempting to reproduce.
2. The test-only C++ oracle checks public RE2 construction and matching. An
   oracle constructor success does **not** qualify the Rust AST shape or
   lowering semantics by itself.

Normative checkout: `/tmp/regex-src-re2` at
`972a15cedd008d846f1a39b2e88ce48d7f166cbd`.

| File | SHA-256 |
|---|---|
| `re2/parse.cc` | `11c28b05ed5563dce8a539f0074f94637e82f7fa12137924a175eeb3bd0ab9d1` |
| `re2/re2.cc` | `b0f3cd7c638c4c38adb5ac806f9efc27d6d8ef871a0d166dd0099338a44a0c7e` |
| `re2/re2.h` | `59f4d4b5318fcb6acf0c90f17d17e71903a87ec25d75fcf5d13e738beb29490f` |
| `re2/regexp.h` | `4e6b57b9e0d9185eb30991c16a172be542bb876f2920346c42b3cd4af2e52cbc` |
| `re2/testing/parse_test.cc` | `d24737b890830eb374ac38e6793e2bd7a2c06c430ad8a7544e8a00bf7563295d` |
| `re2/perl_groups.cc` | `9202c5d6bcc10e4b134a331ddfddd4dc6a41d51505126aff25c74a1ed032e243` |
| `re2/unicode_groups.h` | `42fd7852174d43570684f904c5ecd6f086bf81acd89d2d7ab97b15358380b9c5` |
| `re2/unicode_groups.cc` | `e00735cd8ba1f87ea5c0c78c07de7836e9ad02cc84f4ef8cf90e2b0edfd99e68` |
| `re2/unicode_casefold.h` | `d256539dd13c70d6947261fa4cd763b80068ef51e9cf3cf53439ad7601ec6a09` |

The Rust implementation directly follows the manual precedence stack,
`MaybeParseRepetition`, `ParseEscape`, bracket-class loop, `ParsePerlFlags`,
`RE2::Options::ParseFlags`, `QuoteMeta`, and `CheckRewriteString`. All names in
the pinned generated Unicode table and all POSIX named groups are checked in
the parser and retained symbolically; their range payloads are not duplicated
into this syntax-only crate.

## Oracle

`oracle/oracle.cc` accepts hex pattern/haystack bytes (`-` means empty) plus syntax, encoding,
and a comma-separated option list. It emits a versioned tab-separated record
containing constructor status, numeric public error code, error argument and
message bytes, capture metadata, match status, and capture spans.

The oracle requires the pinned checkout and Abseil. Run it with an installed
Abseil CMake package, or set `ABSL_SOURCE` to an existing local Abseil checkout:

```text
RE2_SOURCE=/tmp/regex-src-re2 ABSL_SOURCE=/path/to/abseil-cpp \
  ./research/re2-syntax/oracle/run-oracle.sh PATTERN_HEX HAYSTACK_HEX \
  perl utf8 FLAGS
```

No suitable local Abseil checkout or package was present during the initial
bootstrap. The pinned dependency declared by RE2's own module metadata,
Abseil `20250814.1` at
`d38452e1ee03523a208362186fd42248ff2609f6`, was then fetched and built with a
shared C++17 mode. `oracle/availability.tsv` retains both the initial failure
and the later successful build instead of rewriting history.
`fixtures.tsv` is deterministic input inventory sourced from the pinned tests;
its expectation column is source-derived constructor validity, not an executed
oracle receipt.

With `FRE_RE2_ORACLE` set to the resulting helper, both ignored upstream tests
pass: 11 directed constructor/diagnostic cases, seven independently expected
match-span records, and all 34 source-derived constructor fixtures. The run
also corrected a malformed `core-escapes` fixture before qualification.
`oracle/qualification.tsv` pins the source revisions, binary and fixture
hashes, counts, and result. This is deliberately an oracle-checked slice: it
does not qualify every parser input, internal AST shape, RE2 program admission,
lowering, or production matching.
