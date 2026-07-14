# fre-re2-syntax

This is an incremental, Rust-native parser for RE2 syntax. Its normative source
is RE2 revision `972a15cedd008d846f1a39b2e88ce48d7f166cbd`, especially
`re2/parse.cc`, `re2/regexp.h`, `re2/re2.h`, generated Unicode tables, and the
upstream parse tests. It does not use Rust `regex-syntax`.

The API has three outcomes. `Parsed` means the implemented subset was parsed
under checked limits. `Rejected` carries an RE2 error category and source
argument. `NotYetImplemented` is used wherever exact behavior has not been
implemented and qualified. Nothing in this crate currently claims full RE2
compatibility. Unicode and POSIX named classes are pinned symbolic AST items;
range materialization belongs to lowering/runtime tables.

## Boundaries

- `options` is the full public RE2 option identity, including fields that do
  not alter parsing but do alter constructor or match behavior.
- `parser` is a manual precedence/frame stack. It performs no recursive AST
  traversal, decodes each UTF-8 scalar in constant time after one validation
  pass, and checks source bytes, work, nodes, tokens, nesting, captures, and
  class-item quotas with checked arithmetic.
- `ast` is an arena of stable integer IDs. Every node/token/class item has a
  half-open span into retained original bytes. Latin-1 error arguments also
  retain RE2's post-conversion UTF-8 bytes.
- `unicode` pins all 199 generated group names plus RE2's special `Any`; the
  much larger ranges are symbolic here so lowering can own table layout.
- `quote` and `rewrite` are isolated ports of `QuoteMeta` and
  `CheckRewriteString`. Rewrite application remains explicitly open.
- `capability` distinguishes source-mapped local work from an upstream oracle
  qualification receipt.

The default limits make parser work finite even for hostile input. For inputs
admitted by a caller-selected envelope, storage is linear in retained source,
AST edges, tokens, captures, and class items. Nested counted-repeat validation
is iterative and follows RE2's 1000-product rule.

## Tests and upstream evidence

The normal suite includes source-derived valid/error matrices, option gates,
diagnostic bytes, 10,000 nested captures, a 100,000-byte literal, and exhaustive
patterns through length five over a metacharacter alphabet. The ignored
`upstream_oracle` test compares constructor status, public error code/argument,
capture count, and independently expected RE2 match spans when
`FRE_RE2_ORACLE` points at the separate pinned C++ helper. See
`research/re2-syntax`. The initial pinned oracle run now passes 11 directed
constructor/diagnostic cases, seven directed match-span records, and all 34
source-derived constructor fixtures. This is an oracle-checked slice, not full
RE2 parser or constructor qualification; capability entries label that
distinction explicitly.
